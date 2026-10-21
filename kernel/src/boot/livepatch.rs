// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Signed kernel livepatch, Level 2 of the live update (Kconfig `LIVEPATCH`;
//! the plan's "function redirection for non-sleeping functions, bounded by
//! QSBR"). This file is the half that touches the machine; the blob format,
//! every check that admits it, the relocations and the redirect encoders are
//! in `azos_mm::text_poke::patch` and run on the host.
//!
//! # One apply
//!
//! 1. A `[livepatch.NAME]` row of the signed topology names the blob by the
//!    SHA-256 of its bytes. The blob is verified against the update key
//!    (`SECURE_BOOT_PUBKEY`), this kernel's build-id (`isa::build_id`), the
//!    OTA `sec_epoch` floor, and the allowlist below ([`is_patchable`]) plus
//!    the compiler's entry slots (`.azos_patch`).
//! 2. The bodies go into `.text.patch_pool` through the one text writer, so
//!    the text stays RX. The pool only grows: no byte is handed out twice.
//! 3. The entry of each function becomes a branch to its body: one `B`
//!    (aarch64), one `JAL` at the 4-aligned part of the entry slot (riscv64,
//!    within 1 MiB of the pool), the `int3` sequence (x86_64). A failure
//!    unwinds the entries already redirected.
//! 4. One bounded QSBR grace (`LIVEPATCH_GRACE_MS`): when it ends no CPU is
//!    inside an old body. A miss is recorded, not undone. No CPU is stopped.
//!
//! There is no revert: nothing persists across a reboot, and
//! [`install_livepatch`] applies the rows again from `/fat/PATCH/`, so a cold
//! boot with the volume removed is the image. The boot is the only caller, so
//! applies do not overlap today; the entries of an apply are claimed in
//! [`STATE`] before any byte is written all the same, so that a later caller
//! cannot make two applies write the same entry.
//!
//! Every apply and refusal is a `Rule::Livepatch` record: subject the row (or
//! `u32::MAX` when no row named the blob), numbers `{first 8 bytes of the
//! blob's SHA-256, entry of the first function, reason}` (`patch::Reason`).

use super::isa;
use azos_decision::{Rule, Verdict};
use azos_drv_sys::kprintln;
use azos_mm::text_poke::{self, patch, patch::Reason, patch::Redirect};
use azos_sync::SpinLock;

/// Is the livepatch built in?
const ENABLED: bool = azos_limits::LIVEPATCH;
/// Applied-patch slots (none without the feature).
const SLOTS: usize = if ENABLED { azos_limits::LIVEPATCH_MAX_PATCHES } else { 0 };

const ISA: u8 = if cfg!(target_arch = "riscv64") {
    patch::ISA_RISCV64
} else if cfg!(target_arch = "aarch64") {
    patch::ISA_AARCH64
} else {
    patch::ISA_X86_64
};

// The redirect overwrites one instruction (aarch64: 1 nop; riscv64: a 4-aligned
// pair of c.nop, which a 2-aligned entry has inside three; x86_64: the
// five-byte nopl), so the compiler must leave at least that many entry nops.
const _: () = assert!(!ENABLED || azos_limits::LIVEPATCH_POOL_KIB != 0, "LIVEPATCH needs LIVEPATCH_POOL_KIB");
const _: () = assert!(
    !ENABLED || azos_limits::LIVEPATCH_ENTRY_NOPS >= if cfg!(target_arch = "aarch64") { 1 } else if cfg!(target_arch = "riscv64") { 3 } else { 5 },
    "LIVEPATCH needs LIVEPATCH_ENTRY_NOPS: 1 on aarch64, 3 on riscv64, 5 on x86_64"
);
const _: () = assert!(!ENABLED || azos_sync::qsbr::ON, "LIVEPATCH needs RCU_QSBR for its grace period");

struct State {
    /// Bytes of the pool handed out.
    used: u64,
    /// The entries each patch has claimed, from before its first write.
    slots: [patch::Claim; SLOTS],
}

static STATE: SpinLock<State> = SpinLock::new(State { used: 0, slots: [patch::Claim::EMPTY; SLOTS] });

/// The function S6's in-QEMU demonstrator replaces: a leaf that never
/// sleeps, a real symbol (`#[inline(never)]`, no mangling) with an entry
/// slot. The demonstrator's patch returns another value.
#[no_mangle]
#[inline(never)]
pub(crate) extern "C" fn livepatch_probe_target() -> u32 {
    0x4c50_0001
}

/// The allowlist baked into the image: the entry points a patch may replace.
/// A function belongs here once it is `#[inline(never)]`, non-generic, never
/// sleeps, and is not boot, trap entry, context switch, `text_poke`, the
/// QSBR hooks or this file (plan, "Never patchable"). Below such an entry the
/// whole inlined closure is replaced with it.
fn is_patchable(va: u64) -> bool {
    [livepatch_probe_target as *const () as usize as u64].contains(&va)
}

/// Record and say one outcome. `row` is `u32::MAX` when no row named the blob.
fn record(row: u32, name: u64, va: u64, reason: Reason) {
    let verdict = if reason.admitted() { Verdict::Admit } else { Verdict::Refuse };
    azos_decision::record(Rule::Livepatch, verdict, row, [name, va, reason.code()]);
    if reason.admitted() {
        kprintln!("[LIVEPATCH] {:016x} {} (row {}, entry {:#x})", name, reason.name(), row, va);
    } else {
        azos_drv_sys::kwarn!("[LIVEPATCH] {:016x} refused: {} (row {})", name, reason.name(), row);
    }
}

/// `n` (at most 8) bytes of kernel text at `va`, read through its own RX mapping.
fn read_text(va: u64, n: usize) -> [u8; 8] {
    let mut b = [0u8; 8];
    for (i, o) in b.iter_mut().enumerate().take(n) {
        // SAFETY: `va` is a function entry inside the mapped kernel text
        // (checked against `.azos_patch`), readable; a function is longer than
        // its entry slot.
        *o = unsafe { core::ptr::read_volatile((va as *const u8).add(i)) };
    }
    b
}

/// Put `new` at the entry `va`, which holds `cur`.
fn swap_entry(va: u64, cur: Redirect, new: Redirect) -> Result<(), Reason> {
    let r = match (cur, new) {
        (_, Redirect::Word(w)) => text_poke::write_words(&[(va as usize, w)]).map(|_| ()),
        (Redirect::Bytes5(old), Redirect::Bytes5(new)) => text_poke::write_bp5(va as usize, &old, &new),
        // A Word can only be replaced by a Word, and the encoders give one
        // form per ISA.
        (Redirect::Word(_), Redirect::Bytes5(_)) => return Err(Reason::Format),
    };
    r.map_err(|_| Reason::Poke)
}

/// Put an entry this apply redirected back as it was.
fn restore_entry(s: &patch::Saved) -> Result<(), Reason> {
    let jmp = patch::redirect(ISA, s.va, s.body)?;
    swap_entry(s.va, jmp, s.restore())
}

/// The bounded grace period every apply ends with.
fn grace(done: Reason) -> Reason {
    if azos_sync::qsbr::synchronize_rcu_for(Some(azos_limits::LIVEPATCH_GRACE_MS as u64)) {
        done
    } else {
        Reason::GraceMissed
    }
}

/// What an apply learned about the blob, for its record.
struct Seen {
    row: u32,
    va: u64,
}

fn apply_blob(blob: &mut [u8], floor: u32, seen: &mut Seen) -> Result<Reason, Reason> {
    if !ENABLED {
        return Err(Reason::Profile);
    }
    let build_id = isa::build_id().ok_or(Reason::BuildId)?;
    let topo = azos_topology::get().ok_or(Reason::NotAdmitted)?;
    let mut rows = [patch::Row { isa: 0, build_id: [0; 32], build_id_len: 0, sec_epoch: 0, sha256: [0; 32] };
                    azos_limits::TOPOLOGY_MAX_LIVEPATCHES];
    let mut nrows = 0;
    for (r, o) in topo.livepatches().iter().zip(rows.iter_mut()) {
        *o = patch::Row {
            isa: r.isa as u8,
            build_id: r.build_id.bytes,
            build_id_len: r.build_id.len,
            sec_epoch: r.sec_epoch,
            sha256: r.sha256,
        };
        nrows += 1;
    }
    let key = &azos_ota::SECURE_BOOT_PUBKEY;
    let (ts, te) = isa::text_range();
    let sites = isa::patch_sites();
    let ctx = patch::Ctx {
        isa: ISA,
        build_id: &build_id,
        floor,
        text: (ts as u64, te as u64),
        rows: &rows[..nrows],
        sha256: &|b| azos_crypto::sha256::sha256(b),
        // No update key installed: nothing verifies (as the OTA refuses).
        verify: &|s, digest| {
            key.iter().any(|&b| b != 0) && s.verify(key, digest)
        },
        allowed: &is_patchable,
        has_site: &|va| sites.contains(&va),
    };
    let v = patch::verify(blob, &ctx)?;
    seen.row = v.row as u32;
    seen.va = v.funcs[0].old_va;

    if text_poke::alias().is_none() && text_poke::init(ts, te).is_none() {
        return Err(Reason::NoAlias);
    }
    let pool = isa::patch_pool();
    let (pool, elen) = ((pool.0 as u64, pool.1 as u64), patch::entry_len(ISA));

    // Reserve the pool, a slot and the entries; the pool is given back only
    // if nothing was written (every refusal below until the first body). The
    // entries stay claimed through the write phase, so a second apply naming
    // one of them is refused here instead of passing the entry check against
    // bytes the first is about to overwrite (on x86_64 `write_bp5` takes the
    // old bytes as read), and a patch in force keeps them claimed.
    let mut sites = [0u64; patch::MAX_FUNCS];
    for (o, f) in sites.iter_mut().zip(&v.funcs[..v.nfuncs]) {
        *o = patch::site(ISA, f.old_va);
    }
    let (slot, before, at) = {
        let mut st = STATE.lock_irqsave();
        let slot = st.slots.iter().position(|s| s.state == patch::SLOT_FREE).ok_or(Reason::TableFull)?;
        if st.slots.iter().any(|s| s.holds_any(&sites[..v.nfuncs])) {
            return Err(Reason::Entry);
        }
        let at = patch::place(&v, pool, st.used)?;
        let before = st.used;
        st.used = at.end;
        st.slots[slot] = patch::Claim { state: patch::SLOT_BUSY, n: v.nfuncs as u8, sites };
        (slot, before, at)
    };
    let free = |written: bool| {
        let mut st = STATE.lock_irqsave();
        st.slots[slot] = patch::Claim::EMPTY;
        if !written && st.used == at.end {
            st.used = before;
        }
    };

    // Everything that can be refused before a byte is written.
    let mut rec = [patch::Saved::default(); patch::MAX_FUNCS];
    let mut jumps = [Redirect::Word(0); patch::MAX_FUNCS];
    let prep = (|| {
        patch::relocate(blob, &v, &at)?;
        for i in 0..v.nfuncs {
            let f = &v.funcs[i];
            let span = patch::entry_span(ISA, f.old_va);
            let seen = read_text(f.old_va, span);
            if !patch::entry_is_slot(ISA, f.old_va, &seen[..span]) {
                return Err(Reason::Entry);
            }
            let va = patch::site(ISA, f.old_va);
            let mut bytes = [0u8; 5];
            bytes[..elen].copy_from_slice(&seen[span - elen..span]);
            jumps[i] = patch::redirect(ISA, va, at.body_va[i])?;
            rec[i] = patch::Saved { va, body: at.body_va[i], bytes, len: elen as u8 };
        }
        Ok(())
    })();
    if let Err(e) = prep {
        free(false);
        return Err(e);
    }

    // The bodies, then the entries.
    let mut written = false;
    for i in 0..v.nfuncs {
        let f = &v.funcs[i];
        let body = &blob[f.body_off..f.body_off + f.body_len];
        if text_poke::write_bytes(at.body_va[i] as usize, body).is_err() {
            free(written);
            return Err(Reason::Poke);
        }
        written = true;
    }
    for i in 0..v.nfuncs {
        let s = &rec[i];
        let cur = if elen == 5 { Redirect::Bytes5([s.bytes[0], s.bytes[1], s.bytes[2], s.bytes[3], s.bytes[4]]) } else { Redirect::Word(0) };
        if let Err(e) = swap_entry(s.va, cur, jumps[i]) {
            for j in (0..i).rev() {
                let _ = restore_entry(&rec[j]);
            }
            free(true);
            return Err(e);
        }
    }

    let reason = grace(Reason::Applied);
    STATE.lock_irqsave().slots[slot].state = patch::SLOT_LIVE;
    Ok(reason)
}

/// Verify and apply the blob in `blob` (consumed: its relocations are bound
/// in place). `floor` is the OTA `min_sec_epoch`. Records the outcome.
fn apply(blob: &mut [u8], floor: u32) {
    let name = u64::from_be_bytes(azos_crypto::sha256::sha256(blob)[..8].try_into().unwrap_or([0; 8]));
    let mut seen = Seen { row: u32::MAX, va: 0 };
    let reason = apply_blob(blob, floor, &mut seen).unwrap_or_else(|reason| reason);
    record(seen.row, name, seen.va, reason);
}

/// Boot, after the topology, the volume, the boot record and the text
/// writer, before any other CPU runs: apply what the signed topology
/// admits. A row whose blob is not on the volume decides nothing and says
/// so; with the feature off, each row of this ISA is refused on the record.
pub(crate) fn install_livepatch() {
    let Some(topo) = azos_topology::get() else { return };
    let rows = topo.livepatches();
    if rows.iter().all(|r| r.isa as u8 != ISA) {
        return;
    }
    let floor = if ENABLED { azos_ota::ota_read_boot_meta().min_sec_epoch } else { 0 };
    for (i, row) in rows.iter().enumerate().filter(|(_, r)| r.isa as u8 == ISA) {
        if !ENABLED {
            record(i as u32, u64::from_be_bytes(row.sha256[..8].try_into().unwrap_or([0; 8])), 0, Reason::Profile);
            continue;
        }
        // 8.3 name from the row's own hash: unique per blob, no long names.
        let mut path = *b"/fat/PATCH/00000000.PCH";
        for (k, b) in row.sha256[..4].iter().enumerate() {
            path[11 + 2 * k] = b"0123456789ABCDEF"[(b >> 4) as usize];
            path[12 + 2 * k] = b"0123456789ABCDEF"[(b & 15) as usize];
        }
        match read_blob(&path) {
            Blob::Absent => kprintln!("[LIVEPATCH] row {}: no blob at {}", i, core::str::from_utf8(&path).unwrap_or("?")),
            Blob::TooLarge => {
                record(i as u32, u64::from_be_bytes(row.sha256[..8].try_into().unwrap_or([0; 8])), 0, Reason::Format)
            }
            Blob::Read(mut v) => {
                apply(&mut v, floor);
            }
        }
    }
}

enum Blob {
    Absent,
    TooLarge,
    Read(alloc::vec::Vec<u8>),
}

/// All of `path`, up to `LIVEPATCH_MAX_BLOB_KIB`.
fn read_blob(path: &[u8]) -> Blob {
    let max = azos_limits::LIVEPATCH_MAX_BLOB_KIB * 1024;
    let mut fds = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fds, path, azos_fs::O_RDONLY);
    if fd < 0 {
        return Blob::Absent;
    }
    let mut buf = alloc::vec::Vec::new();
    // One byte past the bound tells "exactly full" from "larger".
    if buf.try_reserve_exact(max + 1).is_err() {
        azos_fs::vfs_close(&mut fds, fd);
        return Blob::TooLarge;
    }
    buf.resize(max + 1, 0);
    let mut n = 0;
    loop {
        let r = azos_fs::vfs_read(&mut fds, fd, buf[n..].as_mut_ptr(), buf.len() - n);
        if r <= 0 {
            break;
        }
        n += r as usize;
        if n == buf.len() {
            break;
        }
    }
    azos_fs::vfs_close(&mut fds, fd);
    if n > max {
        return Blob::TooLarge;
    }
    buf.truncate(n);
    Blob::Read(buf)
}
