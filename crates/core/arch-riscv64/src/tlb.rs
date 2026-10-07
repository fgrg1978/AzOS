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
    // Local part first: this hart may be running the address space.
    if len == ALL {
        crate::csr::sfence_vma();
    } else {
        let mut a = va & !0xfff;
        let end = va.saturating_add(len);
        while a < end {
            crate::csr::sfence_vma_addr(a);
            a += 0x1000;
        }
    }
    // PTE store(s) before the loads of the published roots.
    core::sync::atomic::fence(Ordering::SeqCst);
    let me = crate::cpu::hart_id();
    let mask = remote_mask(
        |h| AZOS_HART_SATP[h].load(Ordering::Relaxed),
        hart_bound(), me, root_phys,
    );
    // `tlb-local-only` is the gate canary: it keeps the mask computation (so
    // the probe can still print who SHOULD have been signalled) and drops the
    // remote fence, which must make the stale-access probe read stale data.
    #[cfg(not(feature = "tlb-local-only"))]
    if mask != 0 {
        let (start, size) = if len == ALL { (0, usize::MAX) } else { (va & !0xfff, len) };
        let _ = crate::sbi::remote_sfence_vma(mask, 0, start, size);
    }
    mask
}
