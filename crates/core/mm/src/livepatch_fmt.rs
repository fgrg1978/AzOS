// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure half of the signed kernel livepatch (Kconfig `LIVEPATCH`;
//! `kernel/src/boot/livepatch.rs` is the half that touches the machine):
//! the blob format and every check that admits it, the relocations that
//! bind its bodies to where the pool puts them, the entry redirect of each
//! ISA, and the record of what to restore. It reads and writes byte slices
//! and returns values, so the host suite pulls the file in by `#[path]`
//! (`tests/host/mm-tests/src/livepatch.rs`).
//!
//! # The blob
//!
//! One file per ISA: an `RSIG` (`azos_crypto::sig::Rsig`: 48 bytes and the
//! signature, whose length is the configured algorithm's) followed by the
//! payload it signs. The manifest scheme signs
//! `{alg, fw_version, payload_size, sha256(payload)}`; for a patch `fw_version`
//! IS the payload's `sec_epoch`, so the epoch cannot be changed without the
//! signature. All integers are little endian.
//!
//! ```text
//! payload  0  magic "APCH"      4  version = 1     5  isa (1 riscv64, 2 aarch64, 3 x86_64)
//!          6  n_funcs u16       8  sec_epoch u32  12  build_id_len u8 (8..=32), 3 zero bytes
//!         16  build_id[32] (zero after build_id_len)
//!         48  n_relocs u32     52  zero u32                         = HEADER_LEN 56
//!         56  n_funcs x { old_va u64, body_off u32, body_len u32, flags u32, zero u32 }
//!             n_relocs x { func u16, kind u8, zero u8, offset u32, target u64 }
//!             the bodies (4-byte aligned offsets, lengths a multiple of 4)
//! ```
//!
//! `body_off` counts from the start of the payload. A body is a complete
//! replacement function: it is entered at its first byte with the ABI of
//! the function it replaces and returns to that function's caller. It is
//! position-independent except at its relocations, which bind a call to a
//! kernel function: `target` is the absolute address of that function in
//! the running kernel (S + A of the ELF relocation), checked to lie in the
//! kernel text. A reference to data is not supported and is refused by the
//! builder, not here. `flags` is exactly [`F_NOSLEEP`]: the builder
//! asserts the function never sleeps (an offline check against the sleeping
//! APIs plus the image's allowlist), and an unknown bit refuses the blob.
//!
//! # What admits a blob ([`verify`])
//!
//! In this order, each failure one [`Reason`]: the format; a topology row
//! that names the SHA-256 of the whole blob for this ISA
//! ([`Reason::NotAdmitted`]); the RSIG signature and the payload size
//! ([`Reason::Signature`]); the payload's ISA; the build-id, bound to the
//! row and to the running kernel; the `sec_epoch`, equal to the signed one
//! and to the row's and not below the floor; and for each function that it
//! lies in the kernel text, is in the image's allowlist and has an entry
//! slot in `.azos_patch`.

use azos_crypto::sig::{Rsig, RSIG_FIXED_LEN};
use azos_limits::LIVEPATCH_MAX_FUNCS;

// The encoders trace's static keys use, pulled in as source so the one
// definition serves both (the mm crate cannot depend on the trace crate,
// which depends on it).
#[allow(dead_code)]
#[path = "../../trace/src/jump.rs"]
pub(crate) mod jump;

/// Payload magic.
pub const MAGIC: [u8; 4] = *b"APCH";
/// Payload format version.
pub const VERSION: u8 = 1;
/// Fixed part of the payload.
pub const HEADER_LEN: usize = 56;
/// One function entry.
pub const FUNC_LEN: usize = 24;
/// One relocation entry.
pub const RELOC_LEN: usize = 16;
/// Functions one blob may replace (Kconfig `LIVEPATCH_MAX_FUNCS`).
pub const MAX_FUNCS: usize = LIVEPATCH_MAX_FUNCS;
/// The function never sleeps.
pub const F_NOSLEEP: u32 = 1;

/// riscv64, as `azos_topology::PatchIsa`.
pub const ISA_RISCV64: u8 = 1;
/// aarch64.
pub const ISA_AARCH64: u8 = 2;
/// x86_64.
pub const ISA_X86_64: u8 = 3;

/// aarch64 `B`/`BL` imm26 (`R_AARCH64_CALL26`).
pub const R_A64_CALL26: u8 = 1;
/// riscv64 `auipc` + `jalr` pair (`R_RISCV_CALL`), 8 bytes.
pub const R_RV_CALL: u8 = 2;
/// x86_64 32-bit PC-relative field (`R_X86_64_PLT32`/`PC32`).
pub const R_X86_PC32: u8 = 3;

/// Why a patch was applied with a caveat or refused: the third number of the
/// `livepatch` decision record. 0 and [`Reason::GraceMissed`] are the admitted
/// outcomes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Reason {
    /// Applied; the grace period ended: no CPU runs the old bodies.
    Applied = 0,
    /// The build has no livepatch (Kconfig `LIVEPATCH` off).
    Profile = 1,
    /// The blob is malformed.
    Format = 2,
    /// Built for another ISA.
    Isa = 3,
    /// No topology row names this blob for this ISA.
    NotAdmitted = 4,
    /// The signature, the signer, or the signed size is wrong, or the
    /// build has no update key.
    Signature = 5,
    /// Bound to another kernel build.
    BuildId = 6,
    /// The epoch is below the device's floor or disagrees with the row or
    /// the signature.
    Epoch = 7,
    /// A function is not marked as never sleeping.
    NotNosleep = 8,
    /// A function is not in the image's allowlist.
    NotAllowed = 9,
    /// A function has no entry slot in `.azos_patch`.
    NoSite = 10,
    /// The entry of a function is not the slot the redirect expects, or is
    /// misaligned for the ISA.
    Entry = 11,
    /// The redirect or a relocation cannot reach its target.
    Range = 12,
    /// The pool has no room.
    PoolFull = 13,
    /// The text writer refused or failed.
    Poke = 14,
    /// Every slot of the applied table is taken.
    TableFull = 15,
    /// The text writer is not set up.
    NoAlias = 16,
    /// Applied, but the bounded grace period ran out: an old
    /// body may still be running on some CPU.
    GraceMissed = 17,
}

impl Reason {
    /// The number the record carries.
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// The word the console shows.
    pub const fn name(self) -> &'static str {
        match self {
            Reason::Applied => "applied",
            Reason::Profile => "not-built-in",
            Reason::Format => "malformed",
            Reason::Isa => "other-isa",
            Reason::NotAdmitted => "no-topology-row",
            Reason::Signature => "bad-signature",
            Reason::BuildId => "other-build",
            Reason::Epoch => "epoch",
            Reason::NotNosleep => "may-sleep",
            Reason::NotAllowed => "not-allowlisted",
            Reason::NoSite => "no-entry-slot",
            Reason::Entry => "entry-not-a-slot",
            Reason::Range => "out-of-range",
            Reason::PoolFull => "pool-full",
            Reason::Poke => "text-write-refused",
            Reason::TableFull => "table-full",
            Reason::NoAlias => "no-text-writer",
            Reason::GraceMissed => "grace-missed",
        }
    }

    /// Is this an outcome that left the patch in force?
    pub const fn admitted(self) -> bool {
        matches!(self, Reason::Applied | Reason::GraceMissed)
    }
}

/// One `[livepatch.NAME]` row, as the verifier needs it.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    /// `PatchIsa` as a number.
    pub isa: u8,
    /// The kernel build the blob is bound to.
    pub build_id: [u8; 32],
    /// Bytes of `build_id` in use, 8..=32.
    pub build_id_len: u8,
    /// The row's `sec_epoch`.
    pub sec_epoch: u32,
    /// SHA-256 of the whole blob.
    pub sha256: [u8; 32],
}

/// What [`verify`] checks the blob against. Everything the kernel owns is
/// passed in, so the host can stand in for each.
pub struct Ctx<'a> {
    /// The running ISA (`ISA_*`).
    pub isa: u8,
    /// The running kernel's build-id: SHA-256 of its text as linked.
    pub build_id: &'a [u8; 32],
    /// The OTA anti-rollback floor: a blob below it is refused.
    pub floor: u32,
    /// The kernel text, `[start, end)`.
    pub text: (u64, u64),
    /// The topology's `livepatch` rows.
    pub rows: &'a [Row],
    /// SHA-256.
    pub sha256: &'a dyn Fn(&[u8]) -> [u8; 32],
    /// Is this a valid signature by the update key over the manifest of
    /// this payload digest?
    pub verify: &'a dyn Fn(&Rsig, &[u8; 32]) -> bool,
    /// Is the function an entry point the image allows to be replaced?
    pub allowed: &'a dyn Fn(u64) -> bool,
    /// Does `.azos_patch` hold an entry slot at this address?
    pub has_site: &'a dyn Fn(u64) -> bool,
}

/// One function of a verified blob.
#[derive(Clone, Copy, Debug, Default)]
pub struct FuncSpec {
    /// The address of the function entry in the running kernel.
    pub old_va: u64,
    /// Where its body starts in the blob (not in the payload).
    pub body_off: usize,
    /// Its length in bytes.
    pub body_len: usize,
}

/// A blob that passed [`verify`].
#[derive(Clone, Copy, Debug)]
pub struct Verified {
    /// Index of the admitting row.
    pub row: usize,
    /// The signed epoch.
    pub sec_epoch: u32,
    /// First 8 bytes of the blob's SHA-256, big endian: the record's name
    /// for the patch.
    pub name: u64,
    /// Functions in `funcs`.
    pub nfuncs: usize,
    /// The function table.
    pub funcs: [FuncSpec; MAX_FUNCS],
    relocs_off: usize,
    nrelocs: usize,
}

/// One relocation of a verified blob.
#[derive(Clone, Copy, Debug)]
pub struct Reloc {
    /// Index into the function table.
    pub func: usize,
    /// `R_*`.
    pub kind: u8,
    /// Offset in the function's body.
    pub offset: usize,
    /// Absolute address the field must reach.
    pub target: u64,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Is `kind` a relocation `isa` has, and how many bytes of the body does it
/// rewrite?
fn reloc_size(isa: u8, kind: u8) -> Option<usize> {
    match (isa, kind) {
        (ISA_AARCH64, R_A64_CALL26) => Some(4),
        (ISA_RISCV64, R_RV_CALL) => Some(8),
        (ISA_X86_64, R_X86_PC32) => Some(4),
        _ => None,
    }
}

/// The checks of the module doc, in that order.
pub fn verify(blob: &[u8], ctx: &Ctx) -> Result<Verified, Reason> {
    if blob.len() < RSIG_FIXED_LEN + HEADER_LEN {
        return Err(Reason::Format);
    }
    // A row names the blob by the hash of its bytes, for this ISA.
    let whole = (ctx.sha256)(blob);
    let row_idx = ctx
        .rows
        .iter()
        .position(|r| r.isa == ctx.isa && r.sha256 == whole)
        .ok_or(Reason::NotAdmitted)?;
    let row = &ctx.rows[row_idx];

    // The RSIG: its magic, the device's algorithm, a whole signature, then the
    // signature over the manifest of the payload.
    let sig = Rsig::parse(blob).ok_or(Reason::Format)?;
    let sig_len = sig.wire_len();
    if blob.len() < sig_len + HEADER_LEN {
        return Err(Reason::Format);
    }
    let payload = &blob[sig_len..];
    if sig.payload_size as usize != payload.len() {
        return Err(Reason::Signature);
    }
    if !(ctx.verify)(&sig, &(ctx.sha256)(payload)) {
        return Err(Reason::Signature);
    }

    // The payload header.
    if payload[0..4] != MAGIC || payload[4] != VERSION {
        return Err(Reason::Format);
    }
    let (isa, nfuncs, epoch) = (payload[5], le16(payload, 6) as usize, le32(payload, 8));
    let bid_len = payload[12] as usize;
    if payload[13..16] != [0; 3]
        || !(8..=32).contains(&bid_len)
        || payload[16 + bid_len..48].iter().any(|&b| b != 0)
        || le32(payload, 52) != 0
        || nfuncs == 0
        || nfuncs > MAX_FUNCS
    {
        return Err(Reason::Format);
    }
    if isa != ctx.isa {
        return Err(Reason::Isa);
    }
    let bid = &payload[16..16 + bid_len];
    if bid_len != row.build_id_len as usize
        || bid != &row.build_id[..bid_len]
        || bid != &ctx.build_id[..bid_len]
    {
        return Err(Reason::BuildId);
    }
    if epoch == 0 || epoch != sig.fw_version || epoch != row.sec_epoch || epoch < ctx.floor {
        return Err(Reason::Epoch);
    }

    // The tables.
    let nrelocs = le32(payload, 48) as usize;
    let funcs_off = HEADER_LEN;
    let relocs_off = nfuncs.checked_mul(FUNC_LEN).and_then(|n| n.checked_add(funcs_off)).ok_or(Reason::Format)?;
    let bodies_off = nrelocs.checked_mul(RELOC_LEN).and_then(|n| n.checked_add(relocs_off)).ok_or(Reason::Format)?;
    if bodies_off > payload.len() {
        return Err(Reason::Format);
    }
    let mut v = Verified {
        row: row_idx,
        sec_epoch: epoch,
        name: u64::from_be_bytes(whole[..8].try_into().map_err(|_| Reason::Format)?),
        nfuncs,
        funcs: [FuncSpec::default(); MAX_FUNCS],
        relocs_off: sig_len + relocs_off,
        nrelocs,
    };
    for i in 0..nfuncs {
        let o = funcs_off + i * FUNC_LEN;
        let (old_va, boff, blen) = (le64(payload, o), le32(payload, o + 8) as usize, le32(payload, o + 12) as usize);
        let (flags, zero) = (le32(payload, o + 16), le32(payload, o + 20));
        if zero != 0 || flags & !F_NOSLEEP != 0 {
            return Err(Reason::Format);
        }
        if flags & F_NOSLEEP == 0 {
            return Err(Reason::NotNosleep);
        }
        let end = boff.checked_add(blen).ok_or(Reason::Format)?;
        if blen == 0 || blen % 4 != 0 || boff % 4 != 0 || boff < bodies_off || end > payload.len() {
            return Err(Reason::Format);
        }
        if v.funcs[..i].iter().any(|f| f.old_va == old_va) {
            return Err(Reason::Format);
        }
        if old_va < ctx.text.0 || old_va >= ctx.text.1 || !(ctx.allowed)(old_va) {
            return Err(Reason::NotAllowed);
        }
        if !(ctx.has_site)(old_va) {
            return Err(Reason::NoSite);
        }
        v.funcs[i] = FuncSpec { old_va, body_off: sig_len + boff, body_len: blen };
    }
    for i in 0..nrelocs {
        let o = relocs_off + i * RELOC_LEN;
        let (func, kind, offset, target) = (le16(payload, o) as usize, payload[o + 2], le32(payload, o + 4) as usize, le64(payload, o + 8));
        let size = reloc_size(ctx.isa, kind).ok_or(Reason::Format)?;
        if payload[o + 3] != 0
            || func >= nfuncs
            || offset.checked_add(size).is_none_or(|e| e > v.funcs[func].body_len)
            || (ctx.isa != ISA_X86_64 && offset % 4 != 0)
            || target < ctx.text.0
            || target >= ctx.text.1
        {
            return Err(Reason::Format);
        }
    }
    Ok(v)
}

impl Verified {
    /// The relocations, in file order. `blob` is the blob [`verify`] saw.
    pub fn relocs<'a>(&self, blob: &'a [u8]) -> impl Iterator<Item = Reloc> + 'a {
        let base = self.relocs_off;
        (0..self.nrelocs).map(move |i| {
            let o = base + i * RELOC_LEN;
            Reloc { func: le16(blob, o) as usize, kind: blob[o + 2], offset: le32(blob, o + 4) as usize, target: le64(blob, o + 8) }
        })
    }
}

/// Where each body goes in the pool.
#[derive(Clone, Copy, Debug)]
pub struct Placement {
    /// The address of each function's body.
    pub body_va: [u64; MAX_FUNCS],
    /// The pool's fill after this patch.
    pub end: u64,
}

/// Bodies start 16-aligned.
const BODY_ALIGN: u64 = 16;

/// Lay the bodies of `v` out in `pool` (`[start, end)`) after the first
/// `used` bytes. The pool only grows: space a failed apply held is not
/// handed out again, so a CPU still inside an old body never finds new code
/// under it.
pub fn place(v: &Verified, pool: (u64, u64), used: u64) -> Result<Placement, Reason> {
    let mut at = pool.0.checked_add(used).ok_or(Reason::PoolFull)?;
    let mut p = Placement { body_va: [0; MAX_FUNCS], end: 0 };
    for (i, f) in v.funcs[..v.nfuncs].iter().enumerate() {
        at = at.checked_add(BODY_ALIGN - 1).ok_or(Reason::PoolFull)? & !(BODY_ALIGN - 1);
        p.body_va[i] = at;
        at = at.checked_add(f.body_len as u64).ok_or(Reason::PoolFull)?;
        if at > pool.1 {
            return Err(Reason::PoolFull);
        }
    }
    p.end = at - pool.0;
    Ok(p)
}

/// Bind every relocation of `v` to where `place` put the bodies, rewriting
/// the fields in `blob`. The signature and the hash were checked before, on
/// the bytes as signed; this is the only write.
pub fn relocate(blob: &mut [u8], v: &Verified, at: &Placement) -> Result<(), Reason> {
    for i in 0..v.nrelocs {
        let r = {
            let o = v.relocs_off + i * RELOC_LEN;
            Reloc { func: le16(blob, o) as usize, kind: blob[o + 2], offset: le32(blob, o + 4) as usize, target: le64(blob, o + 8) }
        };
        let f = &v.funcs[r.func];
        let pc = at.body_va[r.func] + r.offset as u64;
        let w = &mut blob[f.body_off + r.offset..];
        let rel = r.target.wrapping_sub(pc) as i64;
        match r.kind {
            R_A64_CALL26 => {
                let old = le32(w, 0);
                if old & 0x7c00_0000 != 0x1400_0000 {
                    return Err(Reason::Format); // not B/BL
                }
                if rel % 4 != 0 || !(-(1i64 << 27)..(1i64 << 27)).contains(&rel) {
                    return Err(Reason::Range);
                }
                w[0..4].copy_from_slice(&((old & 0xfc00_0000) | ((rel >> 2) as u32 & 0x03ff_ffff)).to_le_bytes());
            }
            R_RV_CALL => {
                let (a, j) = (le32(w, 0), le32(w, 4));
                if a & 0x7f != 0x17 || j & 0x707f != 0x67 {
                    return Err(Reason::Format); // not auipc + jalr
                }
                let hi = rel.checked_add(0x800).ok_or(Reason::Range)?;
                if !(-(1i64 << 31)..(1i64 << 31)).contains(&hi) {
                    return Err(Reason::Range);
                }
                let lo = rel - ((hi >> 12) << 12);
                w[0..4].copy_from_slice(&((a & 0xfff) | (((hi >> 12) as u32 & 0xfffff) << 12)).to_le_bytes());
                w[4..8].copy_from_slice(&((j & 0x000f_ffff) | ((lo as u32 & 0xfff) << 20)).to_le_bytes());
            }
            R_X86_PC32 => {
                if !(i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
                    return Err(Reason::Range);
                }
                w[0..4].copy_from_slice(&(rel as i32).to_le_bytes());
            }
            _ => return Err(Reason::Format),
        }
    }
    Ok(())
}

// ---- the entry of a replaced function ----------------------------------

/// Bytes at a function entry the redirect overwrites: one instruction on
/// aarch64 and riscv64, five bytes on x86_64.
pub const fn entry_len(isa: u8) -> usize {
    if isa == ISA_X86_64 {
        5
    } else {
        4
    }
}

/// Where the redirect of the function entered at `entry` is written. riscv64
/// functions are 2-aligned (the compressed extension) and a 32-bit store is
/// one whole instruction to fetch only when 4-aligned, so the `jal` goes at
/// the first 4-aligned address of the entry slot and the `c.nop` before it, if
/// any, falls through into it. Everywhere else it is the entry.
pub const fn site(isa: u8, entry: u64) -> u64 {
    if isa == ISA_RISCV64 {
        (entry + 3) & !3
    } else {
        entry
    }
}

/// How many bytes from `entry` [`entry_is_slot`] judges: those up to the end
/// of the redirect.
pub const fn entry_span(isa: u8, entry: u64) -> usize {
    (site(isa, entry) - entry) as usize + entry_len(isa)
}

/// The slot at the redirect itself, [`entry_len`] bytes: riscv64 `addi x0, x0,
/// 0` or two `c.nop`s; aarch64 `nop`; x86_64 the one five-byte `nopl
/// disp8(%rax,%rax)` (LLVM keeps a count in the displacement), never a sled of
/// single-byte nops, which a CPU can sit in the middle of when the redirect
/// lands and then run the middle of the new instruction. Also what an unwind
/// finds once it has put the entry back.
pub fn is_slot(isa: u8, bytes: &[u8]) -> bool {
    match isa {
        ISA_RISCV64 => bytes == [0x13, 0, 0, 0] || bytes == [0x01, 0, 0x01, 0],
        ISA_AARCH64 => bytes == jump::A64_NOP.to_le_bytes(),
        ISA_X86_64 => bytes.len() == 5 && bytes[..4] == [0x0f, 0x1f, 0x44, 0],
        _ => false,
    }
}

/// Is `bytes` (the [`entry_span`] bytes read from `entry`) a function entry the
/// compiler's `-Z patchable-function-entry` left a slot at, with the redirect
/// inside it? On riscv64 an entry at 2 mod 4 needs the `c.nop` before the
/// slot and so three of them in all.
pub fn entry_is_slot(isa: u8, entry: u64, bytes: &[u8]) -> bool {
    if bytes.len() != entry_span(isa, entry) {
        return false;
    }
    let lead = bytes.len() - entry_len(isa);
    (lead == 0 || bytes[..lead] == [0x01, 0]) && is_slot(isa, &bytes[lead..])
}

/// The instruction that sends the entry at `from` to `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redirect {
    /// One naturally aligned 32-bit instruction, written atomically.
    Word(u32),
    /// `jmp rel32`, written with the `int3` sequence.
    Bytes5([u8; 5]),
}

/// `jmp rel32` at `from` to `to`.
pub fn x86_jmp(from: u64, to: u64) -> Option<[u8; 5]> {
    let rel = to.wrapping_sub(from.wrapping_add(5)) as i64;
    let rel = i32::try_from(rel).ok()?;
    let mut b = [0xe9, 0, 0, 0, 0];
    b[1..].copy_from_slice(&rel.to_le_bytes());
    Some(b)
}

/// The redirect of the entry at `from` (a [`site`]) to the body at `to`.
pub fn redirect(isa: u8, from: u64, to: u64) -> Result<Redirect, Reason> {
    match isa {
        ISA_AARCH64 => {
            if from % 4 != 0 {
                return Err(Reason::Entry);
            }
            jump::a64_b(from, to).map(Redirect::Word).ok_or(Reason::Range)
        }
        // A 32-bit store is one whole instruction to fetch only at a
        // 4-aligned address: [`site`] picks one, and any other is refused
        // rather than torn.
        ISA_RISCV64 => {
            if from % 4 != 0 {
                return Err(Reason::Entry);
            }
            jump::rv_jal(from, to).map(Redirect::Word).ok_or(Reason::Range)
        }
        ISA_X86_64 => x86_jmp(from, to).map(Redirect::Bytes5).ok_or(Reason::Range),
        _ => Err(Reason::Isa),
    }
}

/// The `int3` sequence for turning the five bytes `new` in: the trap byte,
/// then the four after the first, then the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpSteps {
    /// Step 1: written at the site.
    pub trap: u8,
    /// Step 2: written at the site + 1.
    pub tail: [u8; 4],
    /// Step 3: written at the site.
    pub head: u8,
}

/// See [`BpSteps`].
pub fn x86_steps(new: &[u8; 5]) -> BpSteps {
    BpSteps { trap: 0xcc, tail: [new[1], new[2], new[3], new[4]], head: new[0] }
}

/// Where a CPU that hit the trap at `site` must resume to behave as if the
/// instruction `new` were already there: the target of a `jmp`, or the next
/// instruction for anything else.
pub fn x86_resume(site: u64, new: &[u8; 5]) -> u64 {
    let next = site.wrapping_add(5);
    if new[0] == 0xe9 {
        next.wrapping_add(i32::from_le_bytes([new[1], new[2], new[3], new[4]]) as i64 as u64)
    } else {
        next
    }
}

// ---- what to restore, what is claimed -----------------------------------

/// One replaced function, as the unwind of a failed apply needs it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Saved {
    /// The redirect: the entry, or on riscv64 the first 4-aligned address
    /// in its slot ([`site`]).
    pub va: u64,
    /// Its body in the pool.
    pub body: u64,
    /// The bytes the redirect overwrote, in `bytes[..len]`.
    pub bytes: [u8; 5],
    /// 4 or 5.
    pub len: u8,
}

impl Saved {
    /// What the unwind writes back.
    pub fn restore(&self) -> Redirect {
        if self.len == 5 {
            Redirect::Bytes5(self.bytes)
        } else {
            Redirect::Word(u32::from_le_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]))
        }
    }
}

/// Slot states of [`Claim`].
pub const SLOT_FREE: u8 = 0;
/// Reserved by an apply in progress, which writes the entries it claimed.
pub const SLOT_BUSY: u8 = 1;
/// In force.
pub const SLOT_LIVE: u8 = 2;

/// The entries one patch has claimed: taken before a byte is written, so two
/// applies that name the same function cannot both pass the entry check and
/// write over each other, and kept while the patch is in force.
#[derive(Clone, Copy, Debug)]
pub struct Claim {
    /// `SLOT_*`.
    pub state: u8,
    /// Functions in `sites`.
    pub n: u8,
    /// The redirect site of each ([`site`]).
    pub sites: [u64; MAX_FUNCS],
}

impl Claim {
    /// An empty slot.
    pub const EMPTY: Claim = Claim { state: SLOT_FREE, n: 0, sites: [0; MAX_FUNCS] };

    /// Does this slot hold any of `sites`?
    pub fn holds_any(&self, sites: &[u64]) -> bool {
        self.state != SLOT_FREE && self.sites[..self.n as usize].iter().any(|s| sites.contains(s))
    }
}

/// How [`x86_bp_sequence`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpOutcome<E> {
    /// The five bytes are `new`.
    Done,
    /// A write was refused and the five bytes are `old` again.
    Undone(E),
    /// A write was refused and so was putting `old` back: the site is left
    /// as the sequence left it, the first byte probably still the trap. The
    /// caller must keep the resume address of `old` armed, so that a CPU that
    /// hits the trap goes on as the old instruction.
    Stuck(E),
}

/// The `int3` sequence of [`x86_steps`] over `write(va, bytes)`, with its
/// undo. `set_resume(addr)` is told where a CPU that hits the trap must
/// continue: the target of `new` first, and, before any byte of `old` is
/// written back, that of `old` (the trap stays in the first byte until the
/// last write, so nothing between the first write and the last ever shows a
/// CPU a half-written instruction, going forward or back). A refusal at the
/// trap write itself puts only the first byte back; a refusal after it puts
/// the tail back first and the head last.
pub fn x86_bp_sequence<E: Copy>(
    site: u64,
    old: &[u8; 5],
    new: &[u8; 5],
    set_resume: &mut dyn FnMut(u64),
    write: &mut dyn FnMut(u64, &[u8]) -> Result<(), E>,
) -> BpOutcome<E> {
    let steps = x86_steps(new);
    set_resume(x86_resume(site, new));
    if let Err(e) = write(site, &[steps.trap]) {
        // Nothing but the first byte can have changed.
        set_resume(x86_resume(site, old));
        return match write(site, &old[..1]) {
            Ok(()) => BpOutcome::Undone(e),
            Err(_) => BpOutcome::Stuck(e),
        };
    }
    let forward = write(site + 1, &steps.tail).and_then(|()| write(site, &[steps.head]));
    let Err(e) = forward else { return BpOutcome::Done };
    set_resume(x86_resume(site, old));
    // The head may hold `new[0]` now (a write that was stored but failed its
    // readback) over the whole new tail, a complete `jmp`; putting the old
    // tail under it first would show a CPU `e9` and old bytes. So the trap
    // goes in again, then the old bytes whole, tail before head.
    match write(site, &[steps.trap])
        .and_then(|()| write(site + 1, &old[1..]))
        .and_then(|()| write(site, &old[..1]))
    {
        Ok(()) => BpOutcome::Undone(e),
        Err(_) => BpOutcome::Stuck(e),
    }
}
