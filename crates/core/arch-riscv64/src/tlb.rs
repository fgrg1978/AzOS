// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-hart TLB shootdown for riscv64.
//!
//! **What it guarantees.** When [`shootdown`] returns, no hart can use a
//! translation for `[va, va + len)` (or for anything, with `len == ALL`) under
//! the address space whose root is `root_phys` that was cached before the PTE
//! change the caller made just before calling it.
//!
//! **Which harts can hold such a translation.** Every `satp` write in this
//! kernel is followed by `sfence.vma zero, zero` (`csr::write_satp`,
//! `context_switch.S`, `context_switch_rvv.S`, `trap_entry.S`,
//! `sret_to_user*`). A hart therefore holds translations for exactly one
//! address space: the one its `satp` currently names. Each hart publishes that
//! value in [`AZOS_HART_SATP`] *before* it writes `satp`, and the set of
//! harts to signal is the set whose published root equals `root_phys`
//! ([`remote_mask`]). This is Linux's `mm_cpumask`, kept exact rather than
//! "set on switch-in, never cleared", because the full flush on every switch
//! makes the exact set cheap to know.
//!
//! **Ordering (store-buffering, fenced on both sides).**
//!   shooter:  store PTE;  fence rw,rw;  load AZOS_HART_SATP[h]
//!   switcher: store AZOS_HART_SATP[h]; fence rw,rw; csrw satp; sfence.vma; walk
//! Either the shooter sees the switcher's publication (and signals it, perhaps
//! needlessly), or the switcher's walk after its own `sfence.vma` sees the
//! cleared PTE. A hart that publishes a *different* root before its switch
//! away is skipped while it may still hold old entries for a few
//! instructions; it is in straight-line kernel code in the switch path, where
//! nothing dereferences a user address, and it flushes them before it runs
//! anything else.
//!
//! **Completion.** The remote part is SBI `remote_sfence_vma`. OpenSBI's
//! implementation waits for every target hart to finish its `sfence.vma`
//! before the ecall returns (`sbi_tlb` sync); the SBI specification alone does
//! not say so. The target runs the fence in M-mode, so it needs no S-mode
//! handler and `sstatus.SIE` does not delay it — which is why the
//! `INT_SOFTWARE_S` arm in `kernel/src/trap/interrupt.rs` stays a pure wake doorbell.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Size of [`AZOS_HART_SATP`]: the CPU ceiling, Kconfig `NR_CPUS`, the same
/// constant `kernel/src/main.rs`'s `MAX_HARTS` and `boot.S`'s range check
/// take. The context-switch assembly takes it as `{tlb_max_harts}` (it was a
/// literal 8 there) and skips the publication for a hart id at or above it.
pub const TLB_MAX_HARTS: usize = azos_limits::NR_CPUS;
// `remote_mask` answers a `usize` bit mask, one bit per hart.
const _: () = assert!(TLB_MAX_HARTS <= usize::BITS as usize);

/// `len` value meaning "the whole address space".
pub const ALL: usize = usize::MAX;

/// Sv39 `satp.PPN` field (bits 43:0).
const SATP_PPN_MASK: usize = (1usize << 44) - 1;

/// The `satp` value each hart has installed, or is about to install. Written
/// by the owning hart only (`csr::write_satp`, `sret_to_user*` in the sched
/// crate, and the two context-switch assembly files, by symbol name;
/// `trap_entry.S`'s exec hand-off only re-writes the root `write_satp`
/// already published); read by any hart in [`shootdown`] and [`holders`].
/// Zero means "never published" and matches no user root.
#[no_mangle]
pub static AZOS_HART_SATP: [AtomicUsize; TLB_MAX_HARTS] =
    [const { AtomicUsize::new(0) }; TLB_MAX_HARTS];

/// One past the highest hart id that has run, or been started to run, this
/// kernel: the bound [`shootdown`] scans [`AZOS_HART_SATP`] up to. Raised by
/// [`note_hart_online`] and never lowered. A hart at or above it has never
/// executed a context switch, so its slot is still 0 and matches no root.
///
/// Why not `TLB_MAX_HARTS`: at `-smp 1` every shootdown scanned 8 slots to
/// find nothing (~65 instructions a call, wave 8). Why not the scheduler's
/// `NUM_ONLINE_CPUS`: that is a prefix COUNT, and the harts this kernel runs
/// on need not be a prefix — the VF2 enumerates its U74s as harts 1..4 and the
/// boot hart can sit outside the online prefix — so a count would leave the
/// highest-numbered hart unscanned.
///
/// Ordering: a hart raises the bound before it can publish a root (the boot
/// hart before it wakes any other; each secondary on entry, before it enables
/// the timer, and its waker before `hart_start`). `shootdown` loads the bound
/// after its `SeqCst` fence, the same fence that orders its PTE store before
/// the root loads, so either it sees the raised bound or the new hart's first
/// walk sees the PTE store.
static TLB_HART_BOUND: AtomicUsize = AtomicUsize::new(0);

/// Record that `hart` runs (or is about to be started to run) this kernel.
/// Ids at or above [`TLB_MAX_HARTS`] are ignored: such a hart never publishes.
#[inline]
pub fn note_hart_online(hart: usize) {
    // Gate canary: no hart is ever noted, the scan covers nobody, and the
    // cross-hart stale-access probe (`tlb-smoke`) must read stale data.
    if cfg!(feature = "tlb-bound-canary") {
        return;
    }
    if hart < TLB_MAX_HARTS {
        TLB_HART_BOUND.fetch_max(hart + 1, Ordering::SeqCst);
    }
}

/// The current scan bound (see [`TLB_HART_BOUND`]).
#[inline]
pub fn hart_bound() -> usize {
    TLB_HART_BOUND.load(Ordering::Relaxed)
}

/// Harts other than `self_hart` whose published `satp` names the table rooted
/// at `root_phys`, as an SBI hart mask with base 0. Pure: `published(h)` is
/// the value hart `h` published. MODE and ASID bits are ignored — only the
/// root PPN identifies an address space.
pub fn remote_mask(
    published: impl Fn(usize) -> usize,
    harts: usize,
    self_hart: usize,
    root_phys: usize,
) -> usize {
    let want = (root_phys >> 12) & SATP_PPN_MASK;
    if want == 0 {
        return 0;
    }
    let mut mask = 0usize;
    let n = if harts < TLB_MAX_HARTS { harts } else { TLB_MAX_HARTS };
    let mut h = 0;
    while h < n {
        if h != self_hart && (published(h) & SATP_PPN_MASK) == want {
            mask |= 1 << h;
        }
        h += 1;
    }
    mask
}

/// [`remote_mask`] split for an ASID-scoped shootdown (Kconfig
/// `TLB_ASID_SCOPED`): `(scoped, full)`. A hart on the root whose published
/// ASID is `asid` (the space's ASID this generation, nonzero) holds the
/// space's entries under `asid` only (one ASID per address space,
/// `azos_sched::asid`), so `sfence.vma ..., asid` covers it; any other hart
/// on the root (still on an older generation's ASID, or `asid` is 0:
/// unknown) gets the all-ASID form. Pure.
pub fn scoped_split(
    published: impl Fn(usize) -> usize,
    harts: usize,
    self_hart: usize,
    root_phys: usize,
    asid: u16,
) -> (usize, usize) {
    let on_root = remote_mask(&published, harts, self_hart, root_phys);
    if asid == 0 {
        return (0, on_root);
    }
    let mut scoped = 0usize;
    let mut h = 0;
    while h < TLB_MAX_HARTS {
        if on_root & (1 << h) != 0 && ((published(h) >> SATP_ASID_SHIFT) & 0xFFFF) as u16 == asid {
            scoped |= 1 << h;
        }
        h += 1;
    }
    (scoped, on_root & !scoped)
}

/// `satp.ASID`'s position.
const SATP_ASID_SHIFT: usize = 44;

/// Kconfig `TLB_ASID_SCOPED` (needs `TLB_RETAIN`).
pub const ASID_SCOPED: bool = azos_limits::TLB_RETAIN && azos_limits::TLB_ASID_SCOPED;

/// Harts, this one included, whose published `satp` names the table rooted at
/// `root_phys` (see [`remote_mask`]; `usize::MAX` excludes nobody). What a
/// page-table free checks before it releases a single frame of that table.
///
/// Sound because the publication is conservative in the direction that
/// matters: a hart publishes a root BEFORE its `csrw satp` installs it, so it
/// is never live and unpublished. The one hart that is live and already
/// published elsewhere is the one in the few instructions between publishing
/// the next root and its `csrw` away from this one — and it is leaving: the
/// table's owner has already stopped naming it (`task_satp`), which is what
/// makes the free legal in the first place.
pub fn holders(root_phys: usize) -> usize {
    // The caller's stores that moved every user off the table, before the
    // loads of the published roots.
    core::sync::atomic::fence(Ordering::SeqCst);
    remote_mask(
        |h| AZOS_HART_SATP[h].load(Ordering::Relaxed),
        hart_bound(), usize::MAX, root_phys,
    )
}

/// Publish `satp` as this hart's translation root. Called before the `csrw`.
#[inline(always)]
pub fn publish(hart: usize, satp: usize) {
    if hart < TLB_MAX_HARTS {
        AZOS_HART_SATP[hart].store(satp, Ordering::Relaxed);
        // Order the publication before the `csrw satp` + walk that follows
        // (see the module doc's ordering argument).
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}

/// Invalidate `[va, va + len)` (or everything, `len == ALL`) for the address
/// space rooted at `root_phys`, on this hart and on every hart that may hold
/// it. Returns the mask of remote harts signalled (0: no IPI was sent).
///
/// The caller has already written the PTE(s). Frames the old PTEs pointed at
/// may be freed only after this returns.
#[cfg(target_arch = "riscv64")]
pub fn shootdown(root_phys: usize, va: usize, len: usize) -> usize {
    // The space's ASID this generation (Kconfig `TLB_ASID_SCOPED`; 0: none
    // recorded, every invalidation below takes the all-ASID form).
    let asid = if ASID_SCOPED {
        azos_arch_api::tlb_gen::SPACES.asid_of((root_phys >> 12) & SATP_PPN_MASK)
    } else {
        0
    };
    // Local part first: this hart may be running the address space. Scoped
    // only when it runs it under the recorded ASID; a hart not on the root
    // may hold the space's entries under any older ASID.
    let live = crate::csr::read_satp();
    let local_asid = if asid != 0
        && (live & SATP_PPN_MASK) == ((root_phys >> 12) & SATP_PPN_MASK)
        && ((live >> SATP_ASID_SHIFT) & 0xFFFF) as u16 == asid
    {
        asid as usize
    } else {
        0
    };
    if len == ALL {
        if local_asid != 0 { crate::csr::sfence_vma_asid(local_asid) } else { crate::csr::sfence_vma() }
    } else {
        let mut a = va & !0xfff;
        let end = va.saturating_add(len);
        while a < end {
            if local_asid != 0 {
                crate::csr::sfence_vma_addr_asid(a, local_asid);
            } else {
                crate::csr::sfence_vma_addr(a);
            }
            a += 0x1000;
        }
    }
    let me = crate::cpu::hart_id();
    // A hart that ran this space and switched away keeps its entries under
    // a retained ASID (Kconfig `TLB_RETAIN`) and is not in the mask below:
    // it flushes at its next user switch (`azos_arch_api::tlb_gen`). Only
    // the harts that ran this space are marked with `TLB_SPACE_MASK`, every
    // hart without. Stored before the fence, so a hart switching in
    // concurrently either sees the mark or is seen in `AZOS_HART_SATP`.
    azos_arch_api::tlb_gen::mark_space_stale(root_phys, me, false);
    // PTE store(s) before the loads of the published roots.
    core::sync::atomic::fence(Ordering::SeqCst);
    let (scoped, full) = scoped_split(
        |h| AZOS_HART_SATP[h].load(Ordering::Relaxed),
        hart_bound(), me, root_phys, asid,
    );
    let mask = scoped | full;
    // `tlb-local-only` is the gate canary: it keeps the mask computation (so
    // the probe can still print who SHOULD have been signalled) and drops the
    // remote fence, which must make the stale-access probe read stale data.
    #[cfg(not(feature = "tlb-local-only"))]
    {
        let (start, size) = if len == ALL { (0, usize::MAX) } else { (va & !0xfff, len) };
        if scoped != 0 {
            let _ = crate::sbi::remote_sfence_vma_asid(scoped, 0, start, size, asid as usize);
        }
        if full != 0 {
            let _ = crate::sbi::remote_sfence_vma(full, 0, start, size);
        }
    }
    mask
}
