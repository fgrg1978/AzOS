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
//! A CPU also publishes the CR3 it runs on when it comes online ([`join`]):
//! one that only ever runs kernel tasks never writes CR3 (the trampoline
//! loaded the kernel root, every kernel task's word), and a kernel-wide
//! request ([`shootdown_kernel`]) must still reach it.
//! With Kconfig `TLB_RETAIN` the context switch sets the CR3 no-flush bit,
//! so a CPU that ran the space earlier keeps its entries under that PCID:
//! [`shootdown`] marks every CPU stale (`azos_arch_api::tlb_gen`), and each
//! flushes every PCID at its next user switch. A per-address-space mask
//! "ran it since its last flush" would narrow that.
//!
//! **Ordering (store-buffering, fenced on both sides).**
//!   shooter:  store PTE;  mfence;  load AZOS_HART_CR3[c]
//!   switcher: store AZOS_HART_CR3[c]; mfence; mov cr3; walk
//! (`SeqCst` fences; x86 reorders exactly store-then-load, which they
//! forbid.) Either the shooter sees the publication, or the switcher's
//! first walk after its CR3 write sees the new PTE.
//!
//! **The remote part, two ways.** Without INVLPGB (Kconfig `X86_INVLPGB`
//! never, or a CPU that lacks it): the shooter posts the request
//! ([`Request`]), sets one bit per target in [`PENDING`], asks the interrupt
//! controller to deliver the shootdown vector to them (the sender registered
//! with [`register_ipi_sender`]; the LAPIC front owns the vector and calls
//! [`handle_ipi`] from it), and waits until every bit is clear. A target
//! flushes in its handler. A CPU that is itself waiting to shoot (the
//! request lock) services its own bit while it spins, so two shooters never
//! wait on each other.
//!
//! **A target that waits for a lock with interrupts masked.** The shooter
//! may hold a lock across the shootdown (the MemObj table across a revoke's
//! unmap, text_poke's lock across its `sync_all`), and a target may be
//! waiting for that lock with interrupts masked (`lock_irqsave`, a fault
//! handler, a lock taken inside an irqsave one): it never takes the vector,
//! and the two would wait on each other. Every kernel lock waits through
//! `SpinWait::wait_while32`, whose wait steps call `wait_service`: on this
//! ISA [`serve_waiting`], which serves the waiter's bit from the lock's wait
//! loop, so a masked waiter acks within one wait step. Linux forbids the
//! shape instead (`smp_call_function_many_cond` warns when called with
//! interrupts off, and a lock taken with interrupts off is never held across
//! a flush); here holding a lock across a shootdown is allowed, and what
//! must not happen is a masked wait for something the shooter holds that is
//! not a lock wait (a raw flag spin).
//!
//! **With INVLPGB (AMD Zen 3 and later).** `INVLPGB` broadcasts the
//! invalidation through the fabric to every logical processor, the issuing
//! one included (AMD APM Vol. 3; Linux's `flush_tlb_kernel_range` issues no
//! separate local flush either), and `TLBSYNC` waits until every processor
//! has finished the INVLPGBs this one issued. No IPI, no handler, no
//! request lock, and no target has to take an interrupt, so the wait does
//! not depend on the targets' interrupt state. Because it reaches every CPU
//! and, with the PCID-valid bit clear, every PCID, the retained-PCID
//! problem the IPI path works around disappears: nothing is marked stale
//! (`azos_arch_api::tlb_gen`), exactly as on aarch64's `TLBI ...IS`. The
//! PCID-valid bit is never set: scoping to the space's PCID
//! (`tlb_gen::broadcast_scope_asid`) is sound on aarch64, where no hart is
//! ever marked stale at run time, but x86_64 marks harts stale
//! (`flush_tlb_page`, `install_user_root_local`, the empty-range IPI), and
//! `harts_scopable` reads a stale hart as "holds nothing", which would leave
//! a hart still running the space under an older generation's PCID with its
//! entries. The final-only bit is never set (a caller may have freed a page
//! table) and `EFER.TCE` stays clear, so every INVLPGB also drops the
//! paging-structure caches, as `invlpg` does. The return value is 0: no CPU was interrupted.
//! The INVLPGB..TLBSYNC pair runs with interrupts off (TLBSYNC covers the
//! INVLPGBs of the CPU it runs on). The AMD documentation leaves the
//! ordering of older stores against INVLPGB to the architecture's general
//! rules, so the PTE store is fenced (`mfence`) before the first INVLPGB.
//! QEMU's TCG has no INVLPGB: the emulated gate runs the IPI path, and the
//! broadcast path is exercised only on Zen 3+ hardware (or a hypervisor
//! that exposes the CPUID bit).

use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::mmu;
#[cfg(target_arch = "x86_64")]
use azos_arch_api::Interrupts as _;

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
/// the owning CPU only ([`publish`]); read by any CPU. Zero means "not
/// online" (never started, or stopped: `azos_sched::smp`'s `tlb_leave`) and
/// matches no root, the kernel's included: every online CPU has published
/// since it joined ([`join`]).
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
/// root, which is every other online CPU: each publishes the CR3 it runs on
/// when it joins ([`join`]), a CPU that has only run kernel tasks included,
/// and it may hold global kernel entries from its first walk on. A zero word
/// is a CPU that is not online (not started yet, or stopped), which takes no
/// interrupt to acknowledge a request and drops what it cached when it joins.
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

/// Join the shootdown's targets as `cpu` comes online (`ArchEntry::
/// secondary_tlb_online`: an AP's first start, a CPU back from a hotplug
/// stop): raise the scan bound, publish the live CR3, then drop everything
/// this CPU cached before, global entries included. The caller runs it with
/// interrupts masked, once the LAPIC accepts the shootdown vector and before
/// it unmasks: a request posted from here on latches in the IRR and is taken
/// at the unmask (or served by a lock wait), so a shooter waits a bounded
/// time; one posted before could be refused by a software-disabled LAPIC and
/// waited for forever. The CPU has cached kernel translations since the
/// trampoline turned paging on; the flush after the publication closes that
/// window as the switch path's fence pair does: either a shooter loads the
/// publication, or its PTE store is visible to this CPU's walks after the flush.
#[cfg(target_arch = "x86_64")]
pub fn join(cpu: usize) {
    note_hart_online(cpu);
    publish(cpu, mmu::cpu::read_cr3() as usize);
    mmu::cpu::flush_all();
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

// ── INVLPGB (Kconfig X86_INVLPGB) ────────────────────────────────────────

/// The most pages one INVLPGB may name when the broadcast path is selected;
/// 0 = not selected (the IPI path). Set once at boot by [`invlpgb_select`].
static INVLPGB_PAGES: AtomicU32 = AtomicU32::new(0);

/// Decide the remote half of a shootdown: INVLPGB when the Kconfig choice
/// allows it (`policy_allows`: not `n`), the CPU reports it (`present`,
/// CPUID.0x80000008:EBX[3]) and its page limit is usable (`max_pages`, the
/// CPUID.0x80000008:EDX[15:0] count plus one, at least 1). Returns the
/// decision. Boot CPU, before any other CPU runs a shootdown.
pub fn invlpgb_select(policy_allows: bool, present: bool, max_pages: u32) -> bool {
    let on = policy_allows && present && max_pages != 0;
    INVLPGB_PAGES.store(if on { max_pages } else { 0 }, Ordering::Release);
    on
}

/// Is the remote half of a shootdown INVLPGB (see [`invlpgb_select`])?
#[inline]
pub fn invlpgb_on() -> bool {
    INVLPGB_PAGES.load(Ordering::Acquire) != 0
}

/// RAX bit 0 of INVLPGB: the address (RAX[63:12]) and the count are valid.
pub const INVLPGB_VALID_VA: u64 = 1 << 0;
/// RAX bit 3: global entries are invalidated too.
pub const INVLPGB_INCLUDE_GLOBAL: u64 = 1 << 3;

/// The three registers one INVLPGB takes (AMD APM Vol. 3, INVLPGB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvlpgbOperands {
    pub rax: u64,
    pub ecx: u32,
    pub edx: u32,
}

/// The operands of one INVLPGB: `pages` consecutive 4 KiB pages from `va`
/// (`va = None`: no address, every page) in every PCID, global entries too
/// when `global`. RAX = address[63:12] | flags, ECX = `pages - 1` (the count
/// of ADDITIONAL pages; stride bit 31 stays clear: 4 KiB steps), EDX = 0
/// (PCID-valid and ASID-valid stay clear: every PCID, and this kernel is no
/// hypervisor). `pages` is at least 1.
pub const fn invlpgb_operands(va: Option<usize>, pages: u32, global: bool) -> InvlpgbOperands {
    let mut rax = 0u64;
    let mut ecx = 0u32;
    if let Some(a) = va {
        rax |= (a as u64 & !0xFFF) | INVLPGB_VALID_VA;
        ecx = pages.saturating_sub(1);
    }
    if global {
        rax |= INVLPGB_INCLUDE_GLOBAL;
    }
    InvlpgbOperands { rax, ecx, edx: 0 }
}

/// The INVLPGBs one [`LocalFlush`] takes, handed to `issue` in order:
/// a page run is cut into chunks of at most `max_pages` (the CPU's limit);
/// the context flush is one INVLPGB without an address (every PCID's
/// non-global entries); everything is one INVLPGB without an address that
/// includes global entries. `global` = the range is kernel mappings (global
/// entries must go too).
pub fn invlpgb_plan(
    f: LocalFlush,
    global: bool,
    max_pages: u32,
    mut issue: impl FnMut(InvlpgbOperands),
) {
    match f {
        LocalFlush::Pages { start, pages } => {
            let max = if max_pages == 0 { 1 } else { max_pages } as usize;
            let (mut va, mut left) = (start, pages);
            while left != 0 {
                let n = if left < max { left } else { max };
                issue(invlpgb_operands(Some(va), n as u32, global));
                va = va.wrapping_add(n * mmu::PAGE_SIZE);
                left -= n;
            }
        }
        LocalFlush::Context => issue(invlpgb_operands(None, 0, global)),
        LocalFlush::Everything => issue(invlpgb_operands(None, 0, true)),
    }
}

/// Does a kernel-range shootdown of `len` bytes take the INVLPGB path
/// (`on` = [`invlpgb_on`])? Not the empty range: that is not an
/// invalidation but `icache_sync_all`'s request that every CPU take an
/// interrupt (its `iretq` serializes the instruction stream after code was
/// patched), which INVLPGB cannot deliver. Pure.
pub const fn kernel_uses_invlpgb(on: bool, len: usize) -> bool {
    on && len != 0
}

/// INVLPGB for `ops`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn invlpgb(ops: InvlpgbOperands) {
    // SAFETY: invalidation only; `invlpgb_select` ran after the CPUID probe.
    // Not `nomem`: it is ordered against the PTE stores around it.
    unsafe {
        core::arch::asm!("invlpgb", in("rax") ops.rax, in("ecx") ops.ecx, in("edx") ops.edx,
                         options(nostack, preserves_flags));
    }
}

/// TLBSYNC: wait for every INVLPGB this CPU issued to finish everywhere.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn tlbsync() {
    // SAFETY: waits only.
    unsafe { core::arch::asm!("tlbsync", options(nostack, preserves_flags)) };
}

/// Issue `f` as INVLPGBs and wait: the whole sequence with interrupts off, so
/// the TLBSYNC runs on the CPU that issued them.
#[cfg(target_arch = "x86_64")]
fn broadcast(f: LocalFlush, global: bool) {
    let max = INVLPGB_PAGES.load(Ordering::Acquire);
    let saved: u64;
    // SAFETY: saves RFLAGS and masks interrupts; restored below.
    unsafe { core::arch::asm!("pushfq", "pop {f}", "cli", f = out(reg) saved, options(preserves_flags)) };
    invlpgb_plan(f, global, max, invlpgb);
    tlbsync();
    if saved & (1 << 9) != 0 {
        // SAFETY: the interrupts were enabled on entry.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }
}

// ── The request a shooter posts ──────────────────────────────────────────

/// One shootdown at a time: root, range.
struct Request {
    root: AtomicUsize,
    va: AtomicUsize,
    len: AtomicUsize,
}

static REQUEST: Request = Request {
    root: AtomicUsize::new(0),
    va: AtomicUsize::new(0),
    len: AtomicUsize::new(0),
};

/// Targets of the posted request that have not flushed yet.
static PENDING: AtomicUsize = AtomicUsize::new(0);
/// Held by the CPU whose request is posted.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
static REQUEST_LOCK: AtomicBool = AtomicBool::new(false);
azos_common::ro_hook! {
    /// The interrupt controller's "deliver the shootdown vector to every CPU in
    /// this mask" (unset = none yet).
    static IPI_SENDER: fn(usize);
}

/// Register the sender of the shootdown vector. The LAPIC code calls it once
/// its ICR works, before any secondary CPU starts; its vector handler calls
/// [`handle_ipi`].
pub fn register_ipi_sender(send: fn(cpu_mask: usize)) {
    IPI_SENDER.set(send);
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn ipi_sender() -> Option<fn(usize)> {
    IPI_SENDER.get()
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

/// [`do_local`] on the PCID `pcid` instead of the live one (`invpcid`
/// type 0 per page, type 1 for the context): reaches the space's entries
/// whether or not this CPU runs it now. Only with PCIDE and INVPCID on.
#[cfg(target_arch = "x86_64")]
fn do_local_pcid(f: LocalFlush, pcid: u16) {
    match f {
        LocalFlush::Pages { start, pages } => {
            let mut a = start;
            for _ in 0..pages {
                mmu::cpu::invpcid(mmu::cpu::INVPCID_ADDR, pcid, a);
                a = a.wrapping_add(mmu::PAGE_SIZE);
            }
        }
        LocalFlush::Context => mmu::cpu::invpcid(mmu::cpu::INVPCID_SINGLE, pcid, 0),
        LocalFlush::Everything => mmu::cpu::flush_all(),
    }
}

/// Post `[va, va + len)` of `root` (`ANY_ROOT`: kernel mappings) to the CPUs
/// in `mask`, for each to flush and ack ([`serve_with`]). The caller holds
/// the request lock (one request at a time) and then signals the targets.
pub fn post(mask: usize, root: usize, va: usize, len: usize) {
    REQUEST.root.store(root, Ordering::Relaxed);
    REQUEST.va.store(va, Ordering::Relaxed);
    REQUEST.len.store(len, Ordering::Relaxed);
    // The request before the bits (the targets' Acquire in `serve_with`).
    PENDING.store(mask, Ordering::Release);
}

/// Targets of the posted request that have not acked yet (0: all done).
#[inline]
pub fn pending() -> usize {
    PENDING.load(Ordering::Acquire)
}

/// Serve CPU `cpu`'s bit of the posted request, if set: `flush` runs the
/// local flush the request needs on that CPU, then the bit is cleared.
/// Returns the flush run, `None` when the bit was clear (served already, or
/// never asked). The caller runs it with interrupts masked on `cpu` itself:
/// read request, flush, ack is not restartable, and a vector taken in the
/// middle could ack this request and let the next be posted, whose bit the
/// interrupted ack would then clear unflushed. Pure apart from the request
/// words (host-tested with a recording `flush`).
pub fn serve_with(cpu: usize, flush: impl FnOnce(LocalFlush)) -> Option<LocalFlush> {
    let bit = 1usize << cpu;
    if PENDING.load(Ordering::Acquire) & bit == 0 {
        return None;
    }
    // Ordered after the Acquire above: the shooter wrote the request
    // before it set our bit (Release).
    let root = REQUEST.root.load(Ordering::Relaxed);
    let va = REQUEST.va.load(Ordering::Relaxed);
    let len = REQUEST.len.load(Ordering::Relaxed);
    let f = local_flush_for(va, len, root == ANY_ROOT, FLUSH_CEILING_PAGES);
    flush(f);
    PENDING.fetch_and(!bit, Ordering::AcqRel);
    Some(f)
}

/// The shootdown vector's handler body (the LAPIC front's IDT entry calls
/// it with this CPU's id; it sends the EOI itself). Interrupts are masked
/// (an interrupt gate); its `iretq` serializes, as `icache_sync_all`'s empty
/// request needs. A bit a lock wait served first is found clear.
#[cfg(target_arch = "x86_64")]
pub fn handle_ipi(cpu: usize) {
    if cpu < TLB_MAX_HARTS {
        serve_with(cpu, do_local);
    }
}

/// Serve this CPU's bit outside the vector: a shooter waiting for the
/// request lock, a lock waiter ([`serve_waiting`]). The CPU id is read in
/// the same masked window as the flush and the ack: the spinning task may
/// have moved since its last step, and `serve_with` flushes THIS CPU. No
/// `iretq` follows, so `icache_sync_all`'s empty request (no flush to run,
/// and every other flush here is a serializing instruction already: `invlpg`,
/// `invpcid`, a CR3 or CR4 write) is answered by a `cpuid`.
#[cfg(target_arch = "x86_64")]
#[cold]
#[inline(never)]
fn serve_here() {
    let irq = crate::X86_64.disable_all();
    let here = crate::cpu::percpu_id();
    if here < TLB_MAX_HARTS {
        if let Some(LocalFlush::Pages { pages: 0, .. }) = serve_with(here, do_local) {
            let _ = crate::platform_impl::cpuid(0, 0);
        }
    }
    crate::X86_64.restore(irq);
}

/// A lock's wait step (`SpinWait::wait_service`): serve this CPU's bit of a
/// posted request. One load of the mask when nothing is posted, which is
/// almost always; the waiter may have interrupts masked, so its bit would
/// otherwise wait for the waiter to get the lock, possibly from the shooter.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn serve_waiting() {
    if PENDING.load(Ordering::Relaxed) != 0 {
        serve_here();
    }
}

/// Post `[va, va + len)` of `root` to `mask`, signal, wait for every ack.
#[cfg(target_arch = "x86_64")]
fn remote(mask: usize, root: usize, va: usize, len: usize) {
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
        // two wait on each other. `serve_here` reads the CPU per iteration:
        // `me` (the CPU that flushed) may not be the one spinning any more.
        serve_waiting();
        core::hint::spin_loop();
    }
    post(mask, root, va, len);
    send(mask);
    while PENDING.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    REQUEST_LOCK.store(false, Ordering::Release);
}

/// Invalidate `[va, va + len)` (everything with `len == ALL`) of the address
/// space rooted at `root_phys` on this CPU and every CPU that may hold it.
/// Returns the mask of CPUs interrupted (0: none). The caller has written the
/// PTE(s); frames they named may be freed after this returns.
///
/// The CPU id (`me`) is read in the same masked window as the local flush: it
/// is the CPU that has flushed, left out of the IPIs and of the stale marks.
/// Read apart from the flush (a task context, interrupts on) a tick would move
/// the task between them and the CPU it now runs on, which never flushed,
/// would be left out. The IPI part runs unmasked and uses that `me` whatever
/// CPU the task is on by then.
#[cfg(target_arch = "x86_64")]
pub fn shootdown(root_phys: usize, va: usize, len: usize) -> usize {
    // `tlb-local-only` (gate canary) keeps the IPI path's local-only shape on
    // a CPU with INVLPGB too, so the stale-access probe still has to fail.
    if invlpgb_on() && !cfg!(feature = "tlb-local-only") {
        // PTE store(s) before the first INVLPGB.
        fence(Ordering::SeqCst);
        broadcast(local_flush_for(va, len, false, FLUSH_CEILING_PAGES), false);
        return 0;
    }
    // Local part: this CPU may be running the address space, or have run
    // it. With PCIDE + INVPCID (Kconfig `X86_INVPCID`, `mmu::invpcid_on`)
    // and `TLB_ASID_SCOPED`, the space's PCID this generation is named
    // directly (`tlb_gen::self_scope_asid`: only when this CPU's TLB is of
    // the record's generation), which reaches its entries whether or not it
    // is live, so this CPU need not be marked stale. Otherwise `invlpg` /
    // CR3 reach only the live PCID.
    let irq = crate::X86_64.disable_all();
    let me = crate::cpu::percpu_id();
    let pcid = if azos_arch_api::tlb_gen::ASID_SCOPED && mmu::pcid_on() && mmu::invpcid_on() {
        azos_arch_api::tlb_gen::self_scope_asid(root_phys >> 12, me) & mmu::CR3_PCID_MASK as u16
    } else {
        0
    };
    let f = local_flush_for(va, len, false, FLUSH_CEILING_PAGES);
    if pcid != 0 { do_local_pcid(f, pcid) } else { do_local(f) }
    crate::X86_64.restore(irq);
    // Retained PCIDs (Kconfig `TLB_RETAIN`): the IPIs reach only the CPUs on
    // the root now, so every CPU that ran the space (`TLB_SPACE_MASK`; every
    // CPU without it), this one included unless its PCID was named above,
    // flushes at its next user switch (`azos_arch_api::tlb_gen`). Before the
    // fence: a CPU switching in concurrently either sees the mark or is seen
    // in `AZOS_HART_CR3`.
    azos_arch_api::tlb_gen::mark_space_stale(root_phys, me, pcid == 0);
    // PTE store(s) before the loads of the published roots.
    fence(Ordering::SeqCst);
    let mask = remote_mask(|c| AZOS_HART_CR3[c].load(Ordering::Relaxed), hart_bound(), me, root_phys);
    // `tlb-local-only` (gate canary): the mask is kept, the IPIs are not
    // sent, so a CPU on the root keeps its stale entry.
    #[cfg(not(feature = "tlb-local-only"))]
    if mask != 0 {
        remote(mask, root_phys, va, len);
    }
    mask
}

/// Invalidate kernel VA range `[va, va + len)` on every online CPU, global
/// entries included (`ArchPlatform::flush_tlb_page_all`). Returns the mask
/// of CPUs interrupted. An empty range (`len == 0`) is the instruction
/// stream serialization of `ArchPlatform::icache_sync_all` and always uses
/// the IPI. The CPU id and the local flush are one masked window, as in
/// [`shootdown`].
#[cfg(target_arch = "x86_64")]
pub fn shootdown_kernel(va: usize, len: usize) -> usize {
    // The empty range stays on the IPI (see [`kernel_uses_invlpgb`]).
    if kernel_uses_invlpgb(invlpgb_on(), len) {
        fence(Ordering::SeqCst);
        broadcast(local_flush_for(va, len, true, FLUSH_CEILING_PAGES), true);
        return 0;
    }
    let irq = crate::X86_64.disable_all();
    let me = crate::cpu::percpu_id();
    do_local(local_flush_for(va, len, true, FLUSH_CEILING_PAGES));
    crate::X86_64.restore(irq);
    azos_arch_api::tlb_gen::mark_all_stale(usize::MAX);
    fence(Ordering::SeqCst);
    let mask = remote_mask(|c| AZOS_HART_CR3[c].load(Ordering::Relaxed), hart_bound(), me, ANY_ROOT);
    if mask != 0 {
        remote(mask, ANY_ROOT, va, len);
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
