// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-CPU TLB shootdown for x86_64, in riscv64's shape
//! (`crates/core/arch-riscv64/src/tlb.rs`): the same publication of each
//! CPU's root, the same pure [`remote_mask`], the same guarantee.
//!
//! **What it guarantees.** When [`shootdown`] returns, no CPU can use a
//! translation for `[va, va + len)` (everything, with `len == ALL`) under
//! the address space rooted at `root_phys` that was cached before the PTE
//! change the caller made just before calling it.
//!
//! **Which CPUs can hold one.** The CPUs whose CR3 names the root now: each
//! CPU publishes that word in [`AZOS_HART_CR3`] before it writes CR3
//! ([`switch_root`], `context_switch.S`), and those are the CPUs signalled.
//! With Kconfig `TLB_RETAIN` the context switch sets the CR3 no-flush bit,
//! so a CPU that ran the space earlier keeps its entries under that PCID:
//! [`shootdown`] marks every CPU stale (`azos_arch_api::tlb_gen`), and each
//! flushes every PCID at its next user switch. A per-address-space mask
//! "ran it since its last flush" (VM-DESIGN §2.4) would narrow that.
//!
//! **Ordering (store-buffering, fenced on both sides).**
//!   shooter:  store PTE;  mfence;  load AZOS_HART_CR3[c]
//!   switcher: store AZOS_HART_CR3[c]; mfence; mov cr3; walk
//! (`SeqCst` fences; x86 reorders exactly store-then-load, which they
//! forbid.) Either the shooter sees the publication, or the switcher's
//! first walk after its CR3 write sees the new PTE.
//!
//! **The remote part.** x86 has no broadcast invalidate (AMD's INVLPGB is a
//! later choice): the shooter posts the request ([`Request`]), sets one bit
//! per target in [`PENDING`], asks the interrupt controller to deliver the
//! shootdown vector to them (the sender registered with
//! [`register_ipi_sender`]; the LAPIC front owns the vector and calls
//! [`handle_ipi`] from it), and waits until every bit is clear. A target
//! flushes in its handler. A CPU that is itself waiting to shoot (the
//! request lock) services its own bit while it spins, so two shooters never
//! wait on each other. What it cannot help: a target spinning with
//! interrupts masked on something the shooter holds stalls it, as on Linux
//! (`smp_call_function` with IRQs off); no kernel lock is held across a
//! shootdown wait with interrupts off on a path a target can also take.

use core::sync::atomic::{fence, AtomicBool, AtomicUsize, Ordering};

use super::mmu;

/// Size of [`AZOS_HART_CR3`]: the CPU ceiling, Kconfig `NR_CPUS`.
pub const TLB_MAX_HARTS: usize = azos_limits::NR_CPUS;
// The masks are one `usize` bit per CPU.
const _: () = assert!(TLB_MAX_HARTS <= usize::BITS as usize);

/// `len` meaning "the whole address space".
pub const ALL: usize = usize::MAX;

/// Above this many pages a ranged flush drops the whole PCID instead of
/// one `invlpg` per page (Kconfig `TLB_FLUSH_CEILING_PAGES`; Linux's
/// `tlb_single_page_flush_ceiling`, 33).
pub const FLUSH_CEILING_PAGES: usize = azos_limits::TLB_FLUSH_CEILING_PAGES as usize;

/// `root_phys` for [`shootdown_kernel`]: every CPU, whatever its CR3.
const ANY_ROOT: usize = usize::MAX;

/// The CR3 word each CPU has installed, or is about to install. Written by
/// the owning CPU only ([`publish`]); read by any CPU. Zero means "never
/// published" and matches no user root.
#[no_mangle]
pub static AZOS_HART_CR3: [AtomicUsize; TLB_MAX_HARTS] =
    [const { AtomicUsize::new(0) }; TLB_MAX_HARTS];

/// One past the highest CPU id that has run (or been started to run) this
/// kernel: the bound of the [`AZOS_HART_CR3`] scan. See riscv64's
/// `TLB_HART_BOUND` for why a bound and not a count.
static TLB_HART_BOUND: AtomicUsize = AtomicUsize::new(0);

/// Record that `cpu` runs (or is about to be started to run) this kernel.
#[inline]
pub fn note_hart_online(cpu: usize) {
    if cpu < TLB_MAX_HARTS {
        TLB_HART_BOUND.fetch_max(cpu + 1, Ordering::SeqCst);
    }
}

/// The current scan bound.
#[inline]
pub fn hart_bound() -> usize {
    TLB_HART_BOUND.load(Ordering::Relaxed)
}

/// CPUs other than `self_cpu` whose published CR3 names the table rooted at
/// `root_phys`, as a bit mask. Pure: `published(c)` is CPU `c`'s word. The
/// PCID bits are ignored: only the root identifies an address space.
/// `root_phys == ANY_ROOT` selects every other CPU that has published a
/// root (one that has not cannot hold a translation yet, and may not be
/// taking interrupts to acknowledge one).
pub fn remote_mask(
    published: impl Fn(usize) -> usize,
    cpus: usize,
    self_cpu: usize,
    root_phys: usize,
) -> usize {
    let any = root_phys == ANY_ROOT;
    let want = mmu::cr3_root(root_phys as u64);
    if want == 0 && !any {
        return 0;
    }
    let n = if cpus < TLB_MAX_HARTS { cpus } else { TLB_MAX_HARTS };
    let mut mask = 0usize;
    let mut c = 0;
    while c < n {
        let p = mmu::cr3_root(published(c) as u64);
        if c != self_cpu && p != 0 && (any || p == want) {
            mask |= 1 << c;
        }
        c += 1;
    }
    mask
}

/// CPUs, this one included, whose published CR3 names `root_phys`: what a
/// page-table free checks first (0 = nobody can walk it). Conservative in
/// the right direction, as on riscv64: a CPU publishes before it installs.
pub fn holders(root_phys: usize) -> usize {
    // The caller's stores that moved every user off the table, before the
    // loads of the published roots.
    fence(Ordering::SeqCst);
    remote_mask(|c| AZOS_HART_CR3[c].load(Ordering::Relaxed), hart_bound(), usize::MAX, root_phys)
}

/// Publish `cr3` as `cpu`'s translation root. Called before the CR3 write.
#[inline(always)]
pub fn publish(cpu: usize, cr3: usize) {
    if cpu < TLB_MAX_HARTS {
        AZOS_HART_CR3[cpu].store(cr3, Ordering::Relaxed);
        // The publication before the CR3 write and its walks.
        fence(Ordering::SeqCst);
    }
}

// ── The request a shooter posts ──────────────────────────────────────────

/// One shootdown at a time: root, range.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
struct Request {
    root: AtomicUsize,
    va: AtomicUsize,
    len: AtomicUsize,
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
static REQUEST: Request = Request {
    root: AtomicUsize::new(0),
    va: AtomicUsize::new(0),
    len: AtomicUsize::new(0),
};

/// Targets of the posted request that have not flushed yet.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
static PENDING: AtomicUsize = AtomicUsize::new(0);
/// Held by the CPU whose request is posted.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
static REQUEST_LOCK: AtomicBool = AtomicBool::new(false);
/// The interrupt controller's "deliver the shootdown vector to every CPU in
/// this mask" (a `fn(usize)`, stored as its address; 0 = none yet).
static IPI_SENDER: AtomicUsize = AtomicUsize::new(0);

/// Register the sender of the shootdown vector. The LAPIC code calls it once
/// its ICR works, before any secondary CPU starts; its vector handler calls
/// [`handle_ipi`].
pub fn register_ipi_sender(send: fn(cpu_mask: usize)) {
    IPI_SENDER.store(send as usize, Ordering::Release);
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn ipi_sender() -> Option<fn(usize)> {
    let p = IPI_SENDER.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        // SAFETY: only `register_ipi_sender` stores a non-zero value, and it
        // stores a `fn(usize)`.
        Some(unsafe { core::mem::transmute::<usize, fn(usize)>(p) })
    }
}

/// How a target flushes `[va, va + len)` for the request it was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalFlush {
    /// One `invlpg` per page, `pages` of them from `start`.
    Pages { start: usize, pages: usize },
    /// The current PCID's non-global entries.
    Context,
    /// Everything, global entries included (a kernel-wide request).
    Everything,
}

/// The local flush a request needs. Pure. `kernel` = the request names no
/// root (kernel mappings: global entries must go too).
pub fn local_flush_for(va: usize, len: usize, kernel: bool, ceiling_pages: usize) -> LocalFlush {
    if len == ALL {
        return if kernel { LocalFlush::Everything } else { LocalFlush::Context };
    }
    let start = va & !(mmu::PAGE_SIZE - 1);
    let end = va.saturating_add(len);
    let pages = (end.saturating_sub(start)).div_ceil(mmu::PAGE_SIZE);
    if pages > ceiling_pages {
        // `invlpg` is the only per-VA form that drops a global entry; past
        // the ceiling a kernel request flushes everything instead.
        if kernel { LocalFlush::Everything } else { LocalFlush::Context }
    } else {
        LocalFlush::Pages { start, pages }
    }
}

#[cfg(target_arch = "x86_64")]
fn do_local(f: LocalFlush) {
    match f {
        LocalFlush::Pages { start, pages } => {
            let mut a = start;
            for _ in 0..pages {
                mmu::cpu::invlpg(a);
                a = a.wrapping_add(mmu::PAGE_SIZE);
            }
        }
        LocalFlush::Context => mmu::cpu::flush_current(),
        LocalFlush::Everything => mmu::cpu::flush_all(),
    }
}

/// Serve this CPU's bit of the posted request, if set.
#[cfg(target_arch = "x86_64")]
fn serve(cpu: usize) {
    let bit = 1usize << cpu;
    if PENDING.load(Ordering::Acquire) & bit == 0 {
        return;
    }
    // Ordered after the Acquire above: the shooter wrote the request
    // before it set our bit (Release).
    let root = REQUEST.root.load(Ordering::Relaxed);
    let va = REQUEST.va.load(Ordering::Relaxed);
    let len = REQUEST.len.load(Ordering::Relaxed);
    do_local(local_flush_for(va, len, root == ANY_ROOT, FLUSH_CEILING_PAGES));
    PENDING.fetch_and(!bit, Ordering::AcqRel);
}

/// The shootdown vector's handler body (the LAPIC front's IDT entry calls
/// it with this CPU's id; it sends the EOI itself).
#[cfg(target_arch = "x86_64")]
pub fn handle_ipi(cpu: usize) {
    if cpu < TLB_MAX_HARTS {
        serve(cpu);
    }
}

/// Post `[va, va + len)` of `root` to `mask`, signal, wait for every ack.
#[cfg(target_arch = "x86_64")]
fn remote(me: usize, mask: usize, root: usize, va: usize, len: usize) {
    let Some(send) = ipi_sender() else {
        // A CPU other than this one is online and may hold the entry, and
        // nothing can reach it: returning would let the caller free a frame
        // another CPU still translates.
        panic!("x86_64 tlb: shootdown to CPU mask {mask:#x} with no IPI sender registered");
    };
    while REQUEST_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        // Another shooter's request may name this CPU: serve it, or the
        // two wait on each other.
        if me < TLB_MAX_HARTS {
            serve(me);
        }
        core::hint::spin_loop();
    }
    REQUEST.root.store(root, Ordering::Relaxed);
    REQUEST.va.store(va, Ordering::Relaxed);
    REQUEST.len.store(len, Ordering::Relaxed);
    PENDING.store(mask, Ordering::Release);
    send(mask);
    while PENDING.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    REQUEST_LOCK.store(false, Ordering::Release);
}

/// Invalidate `[va, va + len)` (everything with `len == ALL`) of the address
/// space rooted at `root_phys` on this CPU (`me`) and every CPU that may
/// hold it. Returns the mask of CPUs interrupted (0: none). The caller has
/// written the PTE(s); frames they named may be freed after this returns.
#[cfg(target_arch = "x86_64")]
pub fn shootdown(me: usize, root_phys: usize, va: usize, len: usize) -> usize {
    // Local part: this CPU may be running the address space.
    do_local(local_flush_for(va, len, false, FLUSH_CEILING_PAGES));
    // Retained PCIDs (Kconfig `TLB_RETAIN`): the local flush reaches only
    // the current PCID and the IPIs only the CPUs on the root now, so every
    // CPU, this one included, flushes at its next user switch
    // (`azos_arch_api::tlb_gen`). Before the fence: a CPU switching in
    // concurrently either sees the mark or is seen in `AZOS_HART_CR3`.
    azos_arch_api::tlb_gen::mark_all_stale(usize::MAX);
    // PTE store(s) before the loads of the published roots.
    fence(Ordering::SeqCst);
    let mask = remote_mask(|c| AZOS_HART_CR3[c].load(Ordering::Relaxed), hart_bound(), me, root_phys);
    // `tlb-local-only` (gate canary): the mask is kept, the IPIs are not
    // sent, so a CPU on the root keeps its stale entry.
    #[cfg(not(feature = "tlb-local-only"))]
    if mask != 0 {
        remote(me, mask, root_phys, va, len);
    }
    mask
}

/// Invalidate kernel VA range `[va, va + len)` on every online CPU, global
/// entries included (`ArchPlatform::flush_tlb_page_all`). Returns the mask
/// of CPUs interrupted.
#[cfg(target_arch = "x86_64")]
pub fn shootdown_kernel(me: usize, va: usize, len: usize) -> usize {
    do_local(local_flush_for(va, len, true, FLUSH_CEILING_PAGES));
    azos_arch_api::tlb_gen::mark_all_stale(usize::MAX);
    fence(Ordering::SeqCst);
    let mask = remote_mask(|c| AZOS_HART_CR3[c].load(Ordering::Relaxed), hart_bound(), me, ANY_ROOT);
    if mask != 0 {
        remote(me, mask, ANY_ROOT, va, len);
    }
    mask
}

/// Install `root_phys` with `asid` on this CPU (`me`): publish, then CR3.
/// The write drops the incoming PCID's non-global entries (no-flush clear),
/// which is the "full flush on switch" the shootdown rule above rests on.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn switch_root(me: usize, root_phys: usize, asid: u16) {
    install_word(me, mmu::make_cr3(root_phys, asid, mmu::pcid_on()));
}

/// Publish and install a CR3 word built by [`mmu::make_cr3`].
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn install_word(me: usize, cr3: u64) {
    publish(me, cr3 as usize);
    mmu::cpu::write_cr3(cr3 & !mmu::CR3_NOFLUSH);
}
