// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SMP support for the AzOS scheduler.
//!
//! **RISC-V:** starts secondary harts via SBI HSM `hart_start` (same
//! approach as the C kernel's `sbi_hart_start()` in kernel/core/smp.c).
//! OpenSBI parks secondary harts in M-mode by default; they must be
//! explicitly started via HSM, not via a polling flag.
//!
//! **aarch64:** starts secondary PEs via PSCI `CPU_ON`
//! (`arch-aarch64::smp::start_core`), targeting the MPIDR affinity
//! `azos_percpu::hw_id` maps the logical CPU to (built from the DTB `/cpus`
//! nodes) — see [`wake_hart`]'s own doc for the full sequence and this
//! kernel's own `context_id` convention.
//!
//! A CPU id here is always the dense logical one (boot CPU = 0); the
//! hardware's own id (`mhartid`, MPIDR affinity, APIC ID) appears only at the
//! firmware calls, through `azos_percpu`'s map.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// Pure liveness accounting for [`wake_harts`], in its own file only so the
/// host test runner can compile it (this module cannot leave the target: it
/// reads `tp` with inline assembly and links against `_secondary_start`).
#[path = "hart_set.rs"]
pub mod hart_set;

/// Number of CPUs currently considered online for task distribution.
///
/// Published in two steps by the boot CPU:
/// 1. Before task creation, set to the *expected* CPU count (from the DTB)
///    so that the boot-time `task_create` calls — which run before any
///    secondary hart exists and must pre-populate per-CPU ready queues that
///    can't be touched cross-CPU afterwards — spread across all intended
///    CPUs.
/// 2. After [`wake_harts`] reports how many secondary harts actually started,
///    corrected down to the real count. This is what matters for any task
///    created later (e.g. `fork()`): without the correction, a hart that
///    failed `hart_start` keeps an empty ready queue forever, which
///    `find_best_cpu` reads as the least contended CPU and routes tasks to
///    it forever — see [`hart_set`] for why the published value must be a
///    live *prefix* bound, not a plain headcount.
/// Secondary CPUs do NOT write this: the boot CPU owns it at boot, and after
/// that only the serialised hotplug path ([`cpu_offline`], [`cpu_online`], one
/// at a time under `HOTPLUG_BUSY`) does, always as `online_prefix(ALIVE)`.
pub static NUM_ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);

// ---- External symbols ----

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    /// Secondary CPU entry point defined in kernel/src/asm/boot.S.
    /// OpenSBI will jump to this address (in S-mode) when `firmware::hart_start` is called.
    fn _secondary_start();
}

// ---- Hart wakeup via SBI HSM ----

/// Start secondary hart `hart_id` (a logical CPU id; `firmware::hart_start`
/// maps it to the hardware hart and passes it back as the entry's `opaque`)
/// via SBI HSM `hart_start`.
///
/// Returns the raw SBI error code: `0` (`SBI_SUCCESS`) on success, negative
/// on failure (`SBI_ERR_INVALID_PARAM`, `SBI_ERR_ALREADY_AVAILABLE`, hart not
/// present, ...). Callers MUST check this — a hart that fails to start never
/// runs `_secondary_start`, so its per-CPU ready queue stays empty forever.
#[cfg(target_arch = "riscv64")]
pub unsafe fn wake_hart(hart_id: usize) -> isize {
    // Before the hart can run: the shootdown scan must already cover it.
    azos_arch::tlb::note_hart_online(hart_id);
    let entry = _secondary_start as *const () as usize;
    azos_arch::firmware::hart_start(hart_id, entry, hart_id)
}

// Secondary CPU entry point defined in
// `kernel/src/entry/aarch64/asm/boot.S`. PSCI `CPU_ON` starts the target PE
// here with `x0` = the `context_id` `wake_hart` (below) passes — THIS
// kernel's own convention is `hart_id` (not "the new PE's boot-stack top",
// the generic convention `arch-aarch64::smp::start_core`'s doc describes):
// the asm entry computes its own stack from a `hart_id`-indexed table,
// exactly mirroring `_secondary_start`'s `secondary_stacks[hart_id]` above,
// rather than trusting a stack address handed to it with no range check
// available on this side.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn _aarch64_secondary_entry();
}

/// Unpack the gic/mpidr `affinity_key` shape (Aff3 at bits [31:24]) into
/// PSCI's `target_cpu` shape (Aff3 at bits [39:32] — see
/// `mpidr::Mpidr::pack_for_psci`). Same four bytes, different bit
/// positions; conflating them sends `CPU_ON` a target that silently
/// decodes to a different PE (or none) whenever Aff3 != 0.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn psci_target(affinity: u32) -> u64 {
    let aff0 = (affinity & 0xFF) as u8;
    let aff1 = ((affinity >> 8) & 0xFF) as u8;
    let aff2 = ((affinity >> 16) & 0xFF) as u8;
    let aff3 = ((affinity >> 24) & 0xFF) as u8;
    azos_arch::cpu::Mpidr::pack_for_psci(aff0, aff1, aff2, aff3)
}

/// Start secondary hart `hart_id` via PSCI `CPU_ON`, targeting the MPIDR
/// affinity `azos_percpu::hw_id` maps it to (packed `Aff3<<24 | Aff2<<16 |
/// Aff1<<8 | Aff0`, the shape `gic::find_redistributor` also uses; from the
/// DTB `/cpus` nodes, installed by `boot::discover_cpus` before any
/// secondary starts).
///
/// Returns `0` on `Success`/`AlreadyOn` (an already-on PE is the caller's
/// desired end state, same as the RISC-V arm treating `SBI_ERR_ALREADY_
/// AVAILABLE` as fine would if it checked — it doesn't, PSCI's decoded
/// outcome here does), `-1` otherwise — including "no affinity for this
/// hart_id", which happens when the map has fewer CPUs than `num_cpus`
/// claimed (the `nr-cpus-clamp-canary` build).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn wake_hart(hart_id: usize) -> isize {
    let Some(affinity) = azos_percpu::hw_id(hart_id) else {
        azos_drv_sys::kwarn!(
            "[SMP] hart {} has no MPIDR affinity (the CPU map is shorter than \
             expected) — not starting it", hart_id);
        return -1;
    };

    // A CPU the firmware held in a spin table waits in the kernel's pen
    // (`azos_arch::smp::spin_table_release`): let it out, to the same entry
    // with the same x0 `CPU_ON` would give it.
    if azos_arch::smp::spin_table_parked(hart_id) {
        return if azos_arch::smp::spin_table_start(hart_id, affinity as u32) { 0 } else { -1 };
    }

    let target_cpu = psci_target(affinity as u32);

    // PSCI `CPU_ON` takes a PHYSICAL entry point — `_aarch64_secondary_entry`
    // is the kernel's own symbol address, identical to its PA today
    // (`virt_to_phys` is a no-op until the aarch64 TTBR1 migration links the
    // kernel high — see `azos_mm::addr`'s module doc), but the target PE
    // starts with its MMU off and BOOTS from the value handed here, so this
    // must always be the PA, never whatever VA the kernel happens to see its
    // own code at.
    let entry = azos_mm::addr::virt_to_phys(_aarch64_secondary_entry as *const () as usize);
    match azos_arch::smp::start_core(target_cpu, entry as u64, hart_id as u64) {
        azos_arch::smp::CpuOnOutcome::Success
        | azos_arch::smp::CpuOnOutcome::AlreadyOn => 0,
        outcome => {
            azos_drv_sys::kwarn!(
                "[SMP] hart {} PSCI CPU_ON failed: {:?}", hart_id, outcome);
            -1
        }
    }
}

#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
unsafe extern "C" {
    /// The 64-bit AP entry (kernel/src/entry/x86_64/asm/ap_entry.S): %rdi =
    /// the CPU number, which it also uses for its stack and per-CPU base.
    fn _secondary_start();
}

/// x86_64 (and any further ISA): INIT-SIPI-SIPI to the MADT APIC ID of
/// `hart_id` through `Boot::hart_start`, which returns once the AP has
/// reached 64-bit mode. 0 on success, -1 otherwise (logged).
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub unsafe fn wake_hart(hart_id: usize) -> isize {
    let entry = _secondary_start as *const () as usize;
    match azos_arch::Boot::hart_start(&azos_arch::ARCH, hart_id, entry, hart_id) {
        Ok(()) => 0,
        Err(e) => {
            azos_drv_sys::kwarn!("[SMP] CPU {} INIT-SIPI-SIPI failed: {:?}", hart_id, e);
            -1
        }
    }
}

/// Start every secondary CPU in `0..num_cpus` (boot CPU excluded — it is
/// already running).
///
/// CPU ids are the dense logical ones, so the range is the CPUs and the boot
/// CPU is 0; the hardware id each start call needs (`mhartid`, MPIDR
/// affinity, APIC ID) comes from `azos_percpu`'s map. A board whose harts
/// start above 0 or are sparse needs nothing more than `0..num_cpus`.
///
/// Returns the number of CPUs the caller should publish as
/// [`NUM_ONLINE_CPUS`]. `find_best_cpu` in `scheduler.rs` reads that value as
/// a live *prefix* bound (`for i in 0..num_online`, indexing `PER_CPU[i]`
/// directly), and `rebalance_from_offline_cpus(online, total)` reads
/// `online..total` as the dead harts — not a plain headcount of successes.
/// Every hart is still attempted regardless of earlier failures; only the
/// published prefix shrinks. See [`hart_set`] for the full contract.
///
/// The boot CPU identifies itself through [`current_cpu_id`], which is
/// correct here without help: `wake_harts` runs on the boot CPU inside
/// `kernel_main`, and `boot.S` sets `tp` (riscv64) to 0 before calling it.
pub unsafe fn wake_harts(num_cpus: usize) -> usize {
    // percpu-hint: wake_harts runs on the boot hart in kernel_main, before any task exists
    let boot = current_cpu_id();
    BOOT_CPU.store(boot, Ordering::Relaxed);
    let mut alive = hart_set::mark_alive(0, boot); // boot hart is already running
    // The online mask (`azos_percpu::online`) is the SET of running CPUs,
    // kept apart from the possible mask so a later hotplug is a bit flip;
    // `NUM_ONLINE_CPUS` below stays the prefix the scheduler walks.
    azos_percpu::set_cpu_online(boot, true);
    // The boot hart publishes roots too; other harts' shootdowns must scan it.
    // riscv64 and x86_64 have no broadcast invalidate, so the boot CPU joins
    // the shootdown's IPI scan (aarch64 needs nothing: TLBI ...IS).
    // arch-only: aarch64's broadcast TLBI has no scan to join.
    #[cfg(any(target_arch = "riscv64", all(target_arch = "x86_64", target_os = "none")))]
    azos_arch::tlb::note_hart_online(boot);

    for hart_id in 0..num_cpus {
        if hart_id == boot {
            continue;
        }
        let ret = wake_hart(hart_id);
        if ret == 0 {
            alive = hart_set::mark_alive(alive, hart_id);
            azos_percpu::set_cpu_online(hart_id, true);
        } else {
            azos_drv_sys::kwarn!(
                "[SMP] hart {} failed to start (sbi hart_start error {})",
                hart_id, ret
            );
        }
    }

    ALIVE.store(alive, Ordering::Release);
    let online = hart_set::online_prefix(alive, num_cpus);

    // A hart that came up but sits past the first dead one gets no work at
    // all, because the published value is a prefix. That is the intended
    // conservative outcome, but silently idling a working CPU is exactly the
    // kind of thing that reads as "SMP is just slow" months later.
    let stranded = hart_set::stranded(alive, num_cpus);
    if stranded != 0 {
        azos_drv_sys::kwarn!(
            "[SMP] harts alive past the first dead one (mask {:#x}) will stay idle: \
             NUM_ONLINE_CPUS is a prefix bound, not a set",
            stranded
        );
    }

    online
}

// ---- Current CPU identity ----

/// Returns the current CPU's logical id from the per-CPU register the boot
/// asm parks it in (dense; the boot CPU is 0; the hardware id is
/// `azos_percpu::hw_id` of it).
///
/// **riscv64:** `tp`, set in `boot.S` for every hart, primary (0) and
/// secondary (the `opaque` argument of its `hart_start`). Rust does not use
/// `tp` in `no_std` bare-metal builds. Note `tp`
/// is an ordinary GPR that EL0 (U-mode) can write, which is the whole reason
/// `trap_entry.S` re-establishes it before any Rust runs (K-C16).
///
/// **aarch64:** `TPIDR_EL1`, which is only writable at EL1 — so the K-C16
/// apparatus has no aarch64 counterpart, and the boot asm's `msr TPIDR_EL1` is
/// the only writer. Added 2026-09-19: this function was `mv {}, tp`
/// unconditionally, so the whole scheduler was riscv-only at its most basic
/// call.
#[inline(always)]
pub fn current_cpu_id() -> usize {
    let id: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) id, options(nostack, nomem));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {}, TPIDR_EL1", out(reg) id, options(nostack, nomem));
    }
    // x86_64: the kernel GS base is this CPU's `PerCpu`, whose first word is
    // the id (`azos_arch::cpu`); ring 3 reaches GS only through `swapgs`,
    // which the trap entry undoes before any Rust runs.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        id = azos_arch::cpu::percpu_id();
    }
    // A host build (tests) has no per-hart register and no SMP: everything runs
    // on "CPU 0", which is what the host shims already assume.
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", all(target_arch = "x86_64", target_os = "none"))))]
    {
        id = 0;
    }
    #[cfg(feature = "cpuid-probe")]
    crate::cpuid_probe::observe(id);
    id
}

// ---------------------------------------------------------------------------
// CPU hotplug (Kconfig `CPU_HOTPLUG`)
// ---------------------------------------------------------------------------
//
// The scheduler places work on `0..NUM_ONLINE_CPUS` (a prefix: `find_best_cpu`,
// the balancer, the real-time admission and the wake placement all walk it), so
// a CPU leaves from the top of the prefix and the one right above it joins
// (`hart_set::check_offline`, `check_online`); the rest of the policy (boot
// CPU, last CPU, the caller's, real-time, isolated, pinned) is there too.
//
// Offline, `cpu_offline(t)` on the requester's CPU `r`:
//   1. checks, and `HOTPLUG_BUSY` (one change at a time);
//   2. starts the kernel thread `cpu-down`, pinned to `t` in the real-time
//      band, so it preempts whatever `t` is running (that task goes back on
//      `t`'s queue, which the thread drains);
//   3. the thread, on `t`, interrupts off, first cuts the online prefix to
//      exclude `t` (nothing is placed on it from then on), then moves the
//      ready tasks to other CPUs
//      (`lifecycle::migrate_off_cpu`), the timer sleepers to the takeover CPU's
//      heap (`timer_sleepers::migrate_off`), leaves the TLB shootdown's scan,
//      marks `t` offline in the percpu mask (RCU stops waiting for it) and
//      stops through the firmware keeping its context
//      (`firmware::stop_current`: HSM `hart_stop`, PSCI `CPU_OFF`, a halt loop
//      on x86_64). If the firmware refuses, everything is undone;
//   4. `r` waits for the firmware to report `t` stopped, then drains `t`'s queue
//      once more (a task queued onto it in the window) and records the change.
//
// Online, `cpu_online(t)`: the firmware starts `t` at the secondary entry,
// which finds its saved context and returns into the `cpu-down` thread where
// it stopped; the thread reports back and ends, `t` runs its own idle task
// again (still on its queue), and the requester puts it back in the prefix.
// A CPU that never stopped here has no saved context and no idle task of its
// own (a boot-time failure moved them), so it is refused (`NeverStopped`).
//
// A requester that gives up (a wait times out) leaves the change to finish on
// the CPU's side, so the next request of either kind starts with `reconcile`:
// a CPU that came back after `cpu_online` timed out is put back in the masks
// and the prefix, and a change the thread undid after `cpu_offline` timed out
// gets its prefix published. A change still running (`REQUESTED`, `STARTED`)
// makes the new request wait its turn (`Busy`).

/// The boot CPU, set by [`wake_harts`].
static BOOT_CPU: AtomicUsize = AtomicUsize::new(0);

/// The running CPUs (bit n = CPU n, `hart_set::mark_alive`): `NUM_ONLINE_CPUS`
/// is `online_prefix` of it. Written by [`wake_harts`] and, after that, by the
/// hotplug path alone.
static ALIVE: AtomicU64 = AtomicU64::new(0);

/// CPUs stopped by [`cpu_offline`] and not yet back: they hold a saved context.
static STOPPED: AtomicU64 = AtomicU64::new(0);

/// One hotplug change at a time.
static HOTPLUG_BUSY: AtomicBool = AtomicBool::new(false);

/// Where the `cpu-down` thread of a CPU is. Written by the thread, read by the
/// requester.
mod phase {
    /// No change running.
    pub const NONE: u8 = 0;
    /// The thread was created and has not run yet.
    pub const REQUESTED: u8 = 1;
    /// The thread took the request (the requester can no longer cancel it).
    pub const STARTED: u8 = 5;
    /// The requester gave up before the thread ran; the thread ends at once.
    pub const CANCELLED: u8 = 6;
    /// The thread has moved everything off and is stopping the CPU.
    pub const STOPPING: u8 = 2;
    /// The CPU came back through the saved context; the thread ends.
    pub const BACK: u8 = 3;
    /// The thread undid the change; the reason is in `FAILED`.
    pub const FAILED: u8 = 4;
}

/// Per CPU: the `phase` in the low byte and the request's generation above it.
/// The generation makes the start handshake one compare-exchange: the thread
/// takes `REQUESTED -> STARTED` and the requester's cancel is
/// `REQUESTED -> CANCELLED`, of the same generation; exactly one wins, and a
/// thread left over from a cancelled request cannot take a later one.
static PHASE: [AtomicU32; azos_limits::NR_CPUS] = [const { AtomicU32::new(phase::NONE as u32) }; azos_limits::NR_CPUS];

/// The phase of `cpu`'s request.
fn phase_of(cpu: usize) -> u8 {
    (PHASE[cpu].load(Ordering::Acquire) & 0xFF) as u8
}

/// Move `cpu`'s request to phase `to`, keeping its generation.
fn set_phase(cpu: usize, to: u8) {
    let _ = PHASE[cpu].fetch_update(Ordering::AcqRel, Ordering::Relaxed, |w| Some((w & !0xFF) | to as u32));
}

/// A new request: the next generation, in phase `REQUESTED`. Returns it.
fn new_request(cpu: usize) -> u32 {
    let gen = (PHASE[cpu].load(Ordering::Relaxed) >> 8).wrapping_add(1) & 0x00FF_FFFF;
    PHASE[cpu].store(gen << 8 | phase::REQUESTED as u32, Ordering::Release);
    gen
}

/// Take the request of generation `gen` (the thread), or cancel it (the
/// requester, `to == CANCELLED`): `true` if this call won.
fn claim(cpu: usize, gen: u32, to: u8) -> bool {
    PHASE[cpu]
        .compare_exchange(gen << 8 | phase::REQUESTED as u32, gen << 8 | to as u32, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
}
/// The `HotplugReason` code of a `phase::FAILED`.
static FAILED: [AtomicU8; azos_limits::NR_CPUS] = [const { AtomicU8::new(0) }; azos_limits::NR_CPUS];
/// Tasks the thread moved (for the record).
static MOVED: [AtomicUsize; azos_limits::NR_CPUS] = [const { AtomicUsize::new(0) }; azos_limits::NR_CPUS];

/// The `cpu-down` thread's priority: the lowest of the real-time band, so it
/// preempts every fair task and nothing real-time (which the policy keeps off
/// the CPU anyway).
const HOTPLUG_PRIORITY: u32 = crate::task::RT_PRIORITY_THRESHOLD - 1;

/// How long each wait lasts before the change is given up (milliseconds).
const HOTPLUG_THREAD_MS: u64 = 500;
const HOTPLUG_STOP_MS: u64 = 1000;
const HOTPLUG_START_MS: u64 = 1000;

use crate::scheduler::{migrate_off_cpu, pinned_to};
use hart_set::{HotplugOp, HotplugReason as Why};

struct Busy;
impl Busy {
    fn take() -> Option<Busy> {
        HOTPLUG_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .ok()
            .map(|_| Busy)
    }
}
impl Drop for Busy {
    fn drop(&mut self) {
        HOTPLUG_BUSY.store(false, Ordering::Release);
    }
}

/// Wait up to `ms` milliseconds for `done`, giving the CPU away meanwhile.
fn wait_ms(ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = azos_drv_sys::timebase::now()
        .saturating_add(azos_drv_sys::timebase::TIMER_FREQ.saturating_mul(ms) / 1000);
    while !done() {
        if azos_drv_sys::timebase::now() >= end {
            return false;
        }
        crate::task_yield();
    }
    true
}

/// The machine as the policy sees it for a change of CPU `cpu`.
fn machine(cpu: usize, caller: usize) -> hart_set::Machine {
    let rt = if cpu < hart_set::HART_MASK_BITS && crate::scheduler::cpu_has_rt_state(cpu) { 1u64 << cpu } else { 0 };
    hart_set::Machine {
        alive: ALIVE.load(Ordering::Acquire),
        num_cpus: crate::scheduler::ncpu(),
        boot: BOOT_CPU.load(Ordering::Relaxed),
        caller,
        rt,
        isolated: crate::scheduler::isolated_cpu_mask(),
        stopped: STOPPED.load(Ordering::Acquire),
        firmware: stop_available(cpu),
        busy: false,
    }
}

/// Publish the prefix of `alive` as `NUM_ONLINE_CPUS`.
fn publish_prefix(alive: u64) {
    NUM_ONLINE_CPUS.store(hart_set::online_prefix(alive, crate::scheduler::ncpu()), Ordering::SeqCst);
}

/// One `cpu-hotplug` decision record and its console line.
fn record(op: HotplugOp, cpu: usize, result: Result<usize, Why>) {
    use azos_decision::{Rule, Verdict};
    let name = if op == HotplugOp::Offline { "offline" } else { "online" };
    match result {
        Ok(load) => {
            azos_decision::record(Rule::CpuHotplug, Verdict::Admit, cpu as u32, [op as u64, load as u64, 0]);
            azos_drv_sys::kprintln!("[HOTPLUG] cpu {} {} ({} {})", cpu, name,
                if op == HotplugOp::Offline { "tasks moved" } else { "cpus online" }, load);
        }
        Err(why) => {
            azos_decision::record(Rule::CpuHotplug, Verdict::Refuse, cpu as u32, [op as u64, 0, why.code() as u64]);
            azos_drv_sys::kwarn!("[HOTPLUG] cpu {} {} REFUSED: {} (reason {}, recorded)", cpu, name, why.name(), why.code());
        }
    }
}

/// Take CPU `cpu` offline (see the section comment). Returns the number of
/// tasks moved off it, or the reason it was refused or undone; either way a
/// `cpu-hotplug` record is made. Called from a task, with interrupts on.
pub fn cpu_offline(cpu: usize) -> Result<usize, Why> {
    let r = offline_run(cpu);
    record(HotplugOp::Offline, cpu, r);
    r
}

fn offline_run(cpu: usize) -> Result<usize, Why> {
    let _busy = Busy::take().ok_or(Why::Busy)?;
    reconcile(cpu)?;
    // percpu-hint: a policy input (never take down the CPU the caller runs on): a stale one is checked against the CPU the caller just left, and the work thread is pinned to the target
    let m = machine(cpu, current_cpu_id());
    hart_set::check_offline(&m, cpu, pinned_to(cpu))?;

    // The thread that does the work, on `cpu`. It is created while `cpu` is
    // still in the online prefix and cuts the prefix itself, first thing, once
    // it runs there: so it is never placed by a prefix that already excludes
    // its pin, and what it cuts is what it then drains.
    FAILED[cpu].store(0, Ordering::Relaxed);
    MOVED[cpu].store(0, Ordering::Relaxed);
    let gen = new_request(cpu);
    if crate::try_task_create_affinity("cpu-down", offline_thread, cpu | (gen as usize) << 8, HOTPLUG_PRIORITY, cpu as i8)
        .is_none()
    {
        set_phase(cpu, phase::NONE);
        return Err(Why::Busy);
    }

    // It runs on `cpu`, preempting what is there.
    if !wait_ms(HOTPLUG_THREAD_MS, || phase_of(cpu) != phase::REQUESTED) {
        // Cancel: whichever of this and the thread's own `claim` comes first wins.
        if claim(cpu, gen, phase::CANCELLED) {
            return Err(Why::Timeout);
        }
        // The thread had taken the request just now: go on with it.
    }
    match phase_of(cpu) {
        phase::FAILED => {
            publish_prefix(ALIVE.load(Ordering::Acquire));
            set_phase(cpu, phase::NONE);
            return Err(reason_of(FAILED[cpu].load(Ordering::Relaxed)));
        }
        // STARTED: the thread is draining; wait for it to commit or fail.
        phase::STARTED | phase::STOPPING | phase::BACK => {}
        _ => return Err(Why::Timeout),
    }
    if !wait_ms(HOTPLUG_STOP_MS, || !matches!(phase_of(cpu), phase::STARTED)) {
        return Err(Why::Timeout);
    }
    if phase_of(cpu) == phase::FAILED {
        publish_prefix(ALIVE.load(Ordering::Acquire));
        set_phase(cpu, phase::NONE);
        return Err(reason_of(FAILED[cpu].load(Ordering::Relaxed)));
    }

    // The firmware says it stopped.
    if !wait_ms(HOTPLUG_STOP_MS, || confirm_stopped(cpu)) {
        // The thread has committed (the CPU left the masks); it is as good as
        // gone, but the firmware has not said so. Not undone: report it.
        return Err(Why::Timeout);
    }
    // A task queued onto it in the window between the thread's last drain and
    // the stop would never run: move it. The CPU is stopped, so this is the
    // dead-hart rescue, from another CPU, through the same locked queue ops.
    // SAFETY: `cpu` is outside the prefix.
    let _ = unsafe { migrate_off_cpu(cpu) };
    Ok(MOVED[cpu].load(Ordering::Relaxed))
}

fn reason_of(code: u8) -> Why {
    use Why::*;
    [NotPossible, NoChange, BootCpu, LastCpu, CallerCpu, RealTime, Isolated, Pinned, NotAtPrefixEdge,
     NoFirmware, Busy, Timeout, FirmwareRefused, NeverStopped]
        .into_iter()
        .find(|w| w.code() == code as u32)
        .unwrap_or(FirmwareRefused)
}

/// The `cpu-down` thread, pinned to the CPU it takes down. `arg` is the CPU and
/// the request's generation above it.
fn offline_thread(arg: usize) {
    use azos_arch::Interrupts;
    let (cpu, gen) = (arg & 0xFF, (arg >> 8) as u32);
    // The request was cancelled (or is an older one's): do nothing.
    if !claim(cpu, gen, phase::STARTED) {
        crate::task_exit();
    }
    // Not the CPU the request is for (a pin that did not hold): above all do not
    // stop the CPU we are on. Checked with interrupts already masked, so the
    // CPU read here is the one `offline_here` then stops: a tick between the
    // check and the mask could move a thread whose pin did not hold.
    let irq = azos_arch::ARCH.disable_all();
    if current_cpu_id() != cpu {
        azos_arch::ARCH.restore(irq);
        FAILED[cpu].store(Why::Timeout.code() as u8, Ordering::Relaxed);
        set_phase(cpu, phase::FAILED);
        crate::task_exit();
    }
    // SAFETY: interrupts are off, this is `cpu`, the change is serialised by
    // `HOTPLUG_BUSY` (the requester holds it).
    let out = unsafe { offline_here(cpu) };
    azos_arch::ARCH.restore(irq);
    match out {
        Ok(()) => set_phase(cpu, phase::BACK),
        Err(why) => {
            FAILED[cpu].store(why.code() as u8, Ordering::Relaxed);
            set_phase(cpu, phase::FAILED);
        }
    }
    crate::task_exit();
}

/// The work on the dying CPU. `Ok` when the CPU stopped and came back.
///
/// # Safety
/// Interrupts off on `cpu`; see [`offline_thread`].
unsafe fn offline_here(cpu: usize) -> Result<(), Why> {
    let alive = ALIVE.load(Ordering::Acquire);
    let after = hart_set::alive_after(alive, cpu, false);

    // Nothing is placed on this CPU from here on.
    publish_prefix(after);

    // The ready tasks. A few rounds: a wake that raced the prefix cut may still
    // queue one here.
    let mut moved = 0;
    for _ in 0..4 {
        match unsafe { migrate_off_cpu(cpu) } {
            Ok(n) => moved += n,
            Err(_) => return Err(Why::Pinned),
        }
    }
    MOVED[cpu].store(moved, Ordering::Relaxed);

    // The timer sleepers, to the takeover CPU, which is rung: an idle CPU's
    // comparator may be far past the earliest of them. (Without the per-CPU
    // timer heap, `sched-timer-heap`, a sleeper is not owned by a CPU: there
    // is nothing to move.)
    #[cfg(feature = "sched-timer-heap")]
    if let Some(to) = hart_set::takeover_cpu(after, crate::scheduler::ncpu(), cpu) {
        if crate::scheduler::migrate_timers_off_cpu(cpu, to) != 0 {
            use azos_arch::Interrupts;
            azos_arch::ARCH.send_ipi(to);
        }
    }

    // Leave the shootdown's scan and RCU's wait, then stop. Undone if the
    // firmware refuses.
    let old_root = tlb_leave(cpu);
    azos_percpu::set_cpu_online(cpu, false);
    ALIVE.store(after, Ordering::Release);
    STOPPED.fetch_or(1u64 << cpu, Ordering::AcqRel);
    set_phase(cpu, phase::STOPPING);

    // SAFETY: the caller's contract; queues drained, timers moved.
    let r = unsafe { stop_current() };
    if is_resumed(r) {
        // Back: a `cpu_online` started this CPU at the secondary entry, which
        // restored this context. The requester finishes the accounting.
        return Ok(());
    }

    // Refused: nothing happened to the CPU. Undo.
    STOPPED.fetch_and(!(1u64 << cpu), Ordering::AcqRel);
    ALIVE.store(alive, Ordering::Release);
    azos_percpu::set_cpu_online(cpu, true);
    tlb_return(cpu, old_root);
    azos_drv_sys::kwarn!("[HOTPLUG] cpu {}: the firmware refused the stop (code {})", cpu, r);
    Err(Why::FirmwareRefused)
}

/// Bring CPU `cpu` back online (see the section comment). Returns the number of
/// CPUs online after it, or the reason it was refused; either way a
/// `cpu-hotplug` record is made. Called from a task, with interrupts on.
pub fn cpu_online(cpu: usize) -> Result<usize, Why> {
    let r = online_run(cpu);
    record(HotplugOp::Online, cpu, r);
    r
}

fn online_run(cpu: usize) -> Result<usize, Why> {
    let _busy = Busy::take().ok_or(Why::Busy)?;
    // An earlier request of this CPU may have timed out and the CPU come up
    // since: that is this request's answer.
    if reconcile(cpu)? & 1u64 << cpu != 0 {
        return Ok(ALIVE.load(Ordering::Acquire).count_ones() as usize);
    }
    // percpu-hint: a policy input of the online check: a stale caller CPU only changes which CPU is refused as "the caller's"; the work thread is pinned to the target
    let m = machine(cpu, current_cpu_id());
    hart_set::check_online(&m, cpu)?;

    // The firmware only starts a CPU it has stopped.
    if !wait_ms(HOTPLUG_STOP_MS, || confirm_stopped(cpu)) {
        return Err(Why::Timeout);
    }
    // A task queued onto it after an offline that gave up before its last drain
    // would wait for the CPU to come back: move it now.
    // SAFETY: `cpu` is outside the prefix (`check_online` saw it stopped).
    let _ = unsafe { migrate_off_cpu(cpu) };
    set_phase(cpu, phase::STOPPING);
    // SAFETY: the CPU is stopped and holds its saved context; the entry address
    // and the stack table were published at boot.
    if unsafe { wake_hart(cpu) } != 0 {
        return Err(Why::FirmwareRefused);
    }
    // It resumes inside its `cpu-down` thread, which reports back and ends. If
    // this wait gives up, the CPU can still come up: `reconcile` finishes it.
    if !wait_ms(HOTPLUG_START_MS, || phase_of(cpu) == phase::BACK) {
        return Err(Why::Timeout);
    }
    Ok(finish_online(cpu))
}

/// The accounting of a CPU that came back: out of `STOPPED`, into `ALIVE`, the
/// percpu online mask and the prefix. Returns the CPUs online. Under
/// `HOTPLUG_BUSY`, once the CPU's phase is `BACK`.
fn finish_online(cpu: usize) -> usize {
    set_phase(cpu, phase::NONE);
    STOPPED.fetch_and(!(1u64 << cpu), Ordering::AcqRel);
    let now = hart_set::alive_after(ALIVE.load(Ordering::Acquire), cpu, true);
    ALIVE.store(now, Ordering::Release);
    azos_percpu::set_cpu_online(cpu, true);
    publish_prefix(now);
    now.count_ones() as usize
}

/// Finish what a requester that timed out left behind, before a new request
/// looks at the masks. Under `HOTPLUG_BUSY`. Returns the CPUs it put back
/// online (bit n = CPU n; each but `requested`, whose caller records it, gets
/// its `cpu-hotplug` record here), or `Busy` while a change is still running on some
/// CPU (its thread is between `REQUESTED` and the commit: a second change
/// would race its prefix cut).
fn reconcile(requested: usize) -> Result<u64, Why> {
    let mut came_back = 0u64;
    for cpu in 0..crate::scheduler::ncpu().min(PHASE.len()).min(hart_set::HART_MASK_BITS) {
        match phase_of(cpu) {
            phase::REQUESTED | phase::STARTED => return Err(Why::Busy),
            // `cpu_online` gave up, then the CPU resumed its thread.
            phase::BACK if STOPPED.load(Ordering::Acquire) & 1u64 << cpu != 0 => {
                let online = finish_online(cpu);
                came_back |= 1u64 << cpu;
                // The requested CPU's change is recorded by its caller.
                if cpu != requested {
                    record(HotplugOp::Online, cpu, Ok(online));
                }
            }
            // `cpu_offline` gave up, then the thread undid the change: it
            // restored the masks but could not publish the prefix.
            phase::FAILED => {
                publish_prefix(ALIVE.load(Ordering::Acquire));
                set_phase(cpu, phase::NONE);
            }
            _ => {}
        }
    }
    Ok(came_back)
}

// ---- Per-ISA pieces of the stop ----

/// Can the firmware stop and start CPU `cpu`?
#[cfg(target_arch = "riscv64")]
fn stop_available(_cpu: usize) -> bool {
    azos_arch::firmware::hart_stop_available()
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn stop_available(_cpu: usize) -> bool {
    azos_arch::firmware::cpu_stop_available()
}
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
fn stop_available(cpu: usize) -> bool {
    azos_arch::smp::cpu_stop_available(cpu)
}
/// A host build has no CPUs to stop.
#[cfg(not(target_os = "none"))]
fn stop_available(_cpu: usize) -> bool {
    false
}

/// Stop the calling CPU keeping its context; the return value is the stop's
/// answer ([`is_resumed`] for "came back").
///
/// # Safety
/// Interrupts off, queues drained, timers moved.
#[cfg(target_arch = "riscv64")]
unsafe fn stop_current() -> isize {
    unsafe { azos_arch::firmware::stop_current() }
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn stop_current() -> isize {
    unsafe { azos_arch::firmware::stop_current() }
}
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
unsafe fn stop_current() -> isize {
    unsafe { azos_arch::smp::stop_current() }
}
#[cfg(not(target_os = "none"))]
unsafe fn stop_current() -> isize {
    -1
}

/// Did [`stop_current`] return because the CPU was started again?
fn is_resumed(r: isize) -> bool {
    #[cfg(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none")))]
    {
        r == azos_arch::firmware::RESUMED
    }
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        r == azos_arch::smp::RESUMED
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = r;
        false
    }
}

/// Does the firmware say CPU `cpu` is stopped?
#[cfg(target_arch = "riscv64")]
fn confirm_stopped(cpu: usize) -> bool {
    azos_arch::firmware::hart_is_stopped(cpu)
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn confirm_stopped(cpu: usize) -> bool {
    azos_percpu::hw_id(cpu)
        .is_some_and(|a| azos_arch::firmware::affinity_info(psci_target(a as u32)) == azos_arch::firmware::AFFINITY_OFF)
}
/// x86_64: the CPU said it halted; an INIT then puts it in wait-for-SIPI.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
fn confirm_stopped(cpu: usize) -> bool {
    azos_arch::smp::cpu_parked(cpu) && azos_arch::smp::park_init(cpu)
}
#[cfg(not(target_os = "none"))]
fn confirm_stopped(_cpu: usize) -> bool {
    false
}

/// Take `cpu` out of the TLB shootdown's scan (a stopped CPU would never answer
/// an IPI, and the shooter waits). Returns the root it had published.
fn tlb_leave(cpu: usize) -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        let old = azos_arch::tlb::AZOS_HART_SATP[cpu].load(Ordering::Relaxed);
        azos_arch::tlb::publish(cpu, 0);
        old
    }
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        let old = azos_arch::tlb::AZOS_HART_CR3[cpu].load(Ordering::Relaxed);
        azos_arch::tlb::publish(cpu, 0);
        old
    }
    // aarch64 invalidates with a broadcast TLBI: no scan to leave. Off the target nothing runs.
    #[cfg(not(any(target_arch = "riscv64", all(target_os = "none", not(target_arch = "aarch64")))))]
    {
        let _ = cpu;
        0
    }
}

/// Undo [`tlb_leave`] after a refused stop.
fn tlb_return(cpu: usize, old: usize) {
    #[cfg(any(target_arch = "riscv64", all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64")))))]
    azos_arch::tlb::publish(cpu, old);
    #[cfg(not(any(target_arch = "riscv64", all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))))]
    let _ = (cpu, old);
}
