// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Task lifecycle half of the scheduler: init and start, task creation,
//! exit / stop / wait, the boot-time offline-hart rescue, the exit notes and
//! the switch entry points they end in. Child of `scheduler` (moved out of
//! `scheduler/mod.rs` unchanged).

use super::*;

// ---- Public API ----

/// Initialize the scheduler. Call once before `task_create` / `start`.
pub fn init() {
    // PER_CPU is initialized via EMPTY_CPU const (current_idx = usize::MAX).
    // Static storage is already zero-initialized (BSS).

    // U02-3 measurement (owner order 4-1): decide the timer wheel by a
    // number, not a guess. Runs here — before any real task exists, so
    // filling the pool cannot collide with anything else — self-
    // contained, no `main.rs` edit needed.
    #[cfg(feature = "sched-tick-probe")]
    {
        run_tick_sweep_probe(false);
        run_tick_sweep_probe(true);
    }

    // The placement query's own cost, which `run_tick_sweep_probe` never
    // reaches (nothing there is dispatched). Two fill levels: the scan
    // scales with the resident count, the histogram should not.
    #[cfg(feature = "sched-tick-probe")]
    {
        run_placement_probe(15);
        run_placement_probe(MAX_TASKS);
    }
}

/// U02-3 measurement. Fills the task pool to `MAX_TASKS - 1` with
/// synthetic `Blocked` tasks, runs one `wake_expired_timers` +
/// `reap_stamped_sleepers` pass — the two O(`MAX_TASKS`) sweeps a real
/// timer tick pays — and prints `[SCHED] tick instr=N`.
///
/// **Never dispatched, never enqueued, never visible past this
/// function.** Each synthetic slot is `Blocked` on `WaitReason::WaitQueue`
/// — NOT `Timer`, so `wake_expired_timers`'s predicate (`WaitReason::Timer
/// if expired`) never matches and `try_wake_task` returns at the
/// `Mismatch`/no-op arm for every one of them: the full per-slot cost
/// (`TASK_VALID` check, `task_mut` deref, `context_saving` load, the
/// `wake_transition` CAS attempt, the predicate call) runs exactly as it
/// would for a real tick with many tasks asleep on something else, but
/// nothing is ever transitioned to `Ready` or `cpu_enqueue_locked`'d — a
/// synthetic slot has no valid `TaskContext`, so dispatching one would
/// context-switch into garbage. `reap_stamped_sleepers` short-circuits
/// even faster per slot (no `WAKE_STAMP` bit set), which is the realistic
/// common case for that sweep too.
///
/// Every slot this function marks `TASK_VALID` it restores to invalid
/// before returning, so nothing about the pool's state survives the call
/// — a diagnostic, not a boot-time side effect.
///
/// Meaningful only under `-icount shift=0,sleep=off`: outside that mode
/// `timebase::now()` (`rdtime`, wall-clock ticks) is not an instruction
/// count.
#[cfg(feature = "sched-tick-probe")]
fn run_tick_sweep_probe(on_timer: bool) {
    use crate::task::sched_word;
    unsafe {
        let sstatus = azos_arch::ARCH.disable_all();
        let _pool = PoolGuard::acquire();

        let target = MAX_TASKS.saturating_sub(1);
        let mut filled = [false; MAX_TASKS];
        let mut filled_count = 0usize;
        for i in 0..MAX_TASKS {
            if filled_count >= target {
                break;
            }
            if TASK_VALID[i].load(Ordering::Relaxed) {
                continue;
            }
            let t = task_mut(i);
            t.tid = 0; // never a live TID; `idx_for_tid` never matches 0.
            // `on_timer`: asleep on a timer that is never due in this probe
            // (`u64::MAX - 1`), so the timer path's per-sleeper cost is
            // paid without anything being woken.
            t.wait_reason = if on_timer {
                WaitReason::Timer(u64::MAX - 1)
            } else {
                WaitReason::WaitQueue
            };
            t.context_saving.store(false, Ordering::Relaxed);
            t.state_word.store(sched_word::pack(TaskState::Blocked), Ordering::Relaxed);
            publish_filter_word(i);
            core::sync::atomic::fence(Ordering::Release);
            TASK_VALID[i].store(true, Ordering::Relaxed);
            #[cfg(feature = "sched-timer-heap")]
            if on_timer {
                timer_sleepers::arm(i, u64::MAX - 1);
            }
            filled[i] = true;
            filled_count += 1;
        }

        let before = azos_drv_sys::timebase::now();
        crate::wait::wake_expired_timers(before);
        let mid = azos_drv_sys::timebase::now();
        reap_stamped_sleepers();
        let after = azos_drv_sys::timebase::now();
        let _ = nearest_timer_deadline();
        let near_ticks = azos_drv_sys::timebase::now().saturating_sub(after);

        for i in 0..MAX_TASKS {
            if filled[i] {
                #[cfg(feature = "sched-timer-heap")]
                timer_sleepers::cancel(i);
                TASK_VALID[i].store(false, Ordering::Relaxed);
                TASKS[i].wait_reason = WaitReason::None;
                TASKS[i].tid = 0;
            }
        }
        core::sync::atomic::fence(Ordering::Release);

        azos_arch::ARCH.restore(sstatus);

        let ticks = after.saturating_sub(before);
        // `-icount shift=0` advances the virtual clock one nanosecond per
        // instruction (vsbench's own convention); `TIMER_FREQ` converts
        // this device's ticks to real time. instr ≈ ticks * (1e9 / freq).
        let instr = ticks.saturating_mul(1_000_000_000)
            / (azos_drv_sys::timebase::TIMER_FREQ as u64).max(1);
        let per = |t: u64| t.saturating_mul(1_000_000_000)
            / (azos_drv_sys::timebase::TIMER_FREQ as u64).max(1);
        azos_drv_sys::kprintln!(
            "[SCHED] tick{} instr={} (ticks={} at {} filled slots, TIMER_FREQ={}) \
             wake_expired_timers={} reap_stamped_sleepers={} nearest_timer_deadline={} heap={}",
            if on_timer { "-timer" } else { "" },
            instr, ticks, filled_count, azos_drv_sys::timebase::TIMER_FREQ,
            per(mid.saturating_sub(before)), per(after.saturating_sub(mid)),
            per(near_ticks), cfg!(feature = "sched-timer-heap"),
        );
    }
}

/// U02-3 task 3a measurement, sibling of [`run_tick_sweep_probe`]: the cost
/// of ONE placement query — what every fork (`pick_target_cpu`) and every
/// real wake of an unpinned task (`wake_target_cpu`) pays — with `fill`
/// synthetic `Ready` residents spread across `MAX_CPUS` harts and most
/// priority buckets. Prints `find_best_cpu` (whichever build is active)
/// and, separately, the O(`MAX_TASKS`) scan, so one boot shows both.
///
/// `NUM_ONLINE_CPUS` is 1 this early in boot and `find_best_cpu` returns
/// `0` without looking at anything when it is `<= 1`, so this overrides it
/// to `MAX_CPUS` for the duration. Every slot it fills is freed (and, under
/// `sched-o1-placement`, re-accounted back to `NONE`) before it returns.
///
/// Meaningful only under `-icount shift=0,sleep=off` (one instruction per
/// virtual nanosecond); the resolution is one timer tick (100 instructions
/// at `TIMER_FREQ` = 10 MHz).
#[cfg(feature = "sched-tick-probe")]
fn run_placement_probe(fill: usize) {
    unsafe {
        let sstatus = azos_arch::ARCH.disable_all();
        let _pool = PoolGuard::acquire();

        let saved_online = NUM_ONLINE_CPUS.load(Ordering::Relaxed);
        NUM_ONLINE_CPUS.store(MAX_CPUS, Ordering::Relaxed);

        let target = fill.min(MAX_TASKS.saturating_sub(1));
        let mut filled = [false; MAX_TASKS];
        let mut filled_count = 0usize;
        for i in 0..MAX_TASKS {
            if filled_count >= target {
                break;
            }
            if TASK_VALID[i].load(Ordering::Relaxed) {
                continue;
            }
            let cpu = filled_count % MAX_CPUS;
            let prio = (filled_count * 7) as u32 % NUM_PRIORITIES as u32;
            let t = task_mut(i);
            t.tid = 0; // never a live TID; `idx_for_tid` never matches 0.
            t.cpu_affinity = -1;
            t.context.tp = cpu as CtxReg;
            t.priority.store(prio, Ordering::Relaxed);
            t.state_word.store(
                crate::task::sched_word::pack(TaskState::Ready),
                Ordering::Relaxed,
            );
            publish_filter_word(i);
            core::sync::atomic::fence(Ordering::Release);
            TASK_VALID[i].store(true, Ordering::Relaxed);
            hist_reaccount(i);
            filled[i] = true;
            filled_count += 1;
        }

        // `exclude = MAX_TASKS` matches no slot (a creation-time query);
        // prio 16 so a meaningful share of the residents outrank it.
        let t0 = azos_drv_sys::timebase::now();
        let pick = find_best_cpu(16, MAX_TASKS);
        let t1 = azos_drv_sys::timebase::now();
        let scan = find_best_cpu_scan(16, MAX_TASKS, MAX_CPUS);
        let t2 = azos_drv_sys::timebase::now();
        let scan_pick = pick_cpu_by_load(&scan[..MAX_CPUS]);

        for i in 0..MAX_TASKS {
            if filled[i] {
                TASK_VALID[i].store(false, Ordering::Relaxed);
                hist_reaccount(i);
                TASKS[i].tid = 0;
                TASKS[i].cpu_affinity = -1;
            }
        }
        core::sync::atomic::fence(Ordering::Release);
        NUM_ONLINE_CPUS.store(saved_online, Ordering::Relaxed);

        azos_arch::ARCH.restore(sstatus);

        let per = |ticks: u64| ticks.saturating_mul(1_000_000_000)
            / (azos_drv_sys::timebase::TIMER_FREQ as u64).max(1);
        azos_drv_sys::kprintln!(
            "[SCHED] placement fill={} find_best_cpu instr={} scan-only instr={} pick={} scan_pick={} o1={}",
            filled_count,
            per(t1.saturating_sub(t0)),
            per(t2.saturating_sub(t1)),
            pick,
            scan_pick,
            cfg!(feature = "sched-o1-placement"),
        );
    }
}

/// Create a new kernel task with CPU affinity.
///
/// `affinity`: -1 = auto-assign via `find_best_cpu`, 0..3 = pin to that hart.
/// Returns the task pool index.
///
/// Panics if the task pool is exhausted. Every existing caller of this
/// function is kernel-internal (boot-time or otherwise trusted), so pool
/// exhaustion here is a genuine system misconfiguration worth crashing
/// loudly for. **Any task-creation path reachable by unprivileged
/// userspace (e.g. `fork()`) MUST use [`try_task_create_affinity`]
/// instead** — with `panic = "abort"` in this profile a panic here is a
/// full board reset, so letting a user fork-bomb the pool would be a
/// remote/local DoS. K-A13.
/// Names that survive a `bench-minimal` boot. Everything else is skipped.
///
/// `idle` keeps a hart from falling out of `do_schedule` with nothing to run;
/// `autorun` is the measured program itself. Nothing else is needed to execute
/// a ring-3 ELF.
/// `ipc-census` is in the list even though it is a diagnostic, not something
/// the benchmark needs: gating it behind a cross-crate feature was tried and
/// the feature did not propagate, so the printer stayed parked and the counters
/// it exists to print never reached the console. The task is only *created* in
/// builds that enable `ipc-census` in the kernel, so naming it here costs a
/// string comparison and nothing else in a normal bench-minimal build.
///
/// Numbers taken with the census running are for **hunting**, not for
/// measuring: the printer competes for CPU and is not comparable with a
/// vsbench run.
#[cfg(feature = "bench-minimal")]
/// `fs-wb` (wave 15) is the FAT32 write-back cache's own flusher: parked, a
/// disk lane's writer would do every write-back itself, which is not the
/// file system being measured (Linux's flusher threads run on its side).
const BENCH_MINIMAL_KEEP: [&str; 4] = ["idle", "autorun", "ipc-census", "fs-wb"];

/// Entry point substituted for every non-allowlisted task under
/// `bench-minimal`: block forever and never consume a cycle.
///
/// **WHY substitute the entry instead of skipping the creation.** Skipping was
/// tried first and panicked during boot: the task pool's slots, names and
/// indices are load-bearing for code that runs later (topology install, the
/// driver registry), and refusing to create a task quietly breaks
/// invariants far from the refusal. Creating the task and parking it keeps
/// every one of those intact — the slot exists, the name resolves, the index is
/// valid — while removing the only thing the benchmark cares about: the task
/// competing for CPU while a measurement is running.
///
/// `Timer(u64::MAX)` is a deadline no `wake_expired_timers` sweep will ever
/// reach, so the task is `Blocked` from its first instruction and is never
/// dispatched again.
#[cfg(feature = "bench-minimal")]
static BENCH_MINIMAL_ANNOUNCED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// `Timer(u64::MAX)` is safe against `overflow-checks = true`: every consumer
/// of a `Timer` deadline in this tree either compares it (`now >= deadline`,
/// `wait.rs`) or folds it with `min` (`nearest_timer_deadline`, and
/// `set_next_tick_smart`, where `u64::MAX.min(tick)` yields the ordinary
/// periodic tick). None of them adds to it. Audited 2026-08-28 — a panic here
/// would reset the board.
#[cfg(feature = "bench-minimal")]
fn bench_minimal_park(_: usize) {
    loop {
        crate::task_block(crate::WaitReason::Timer(u64::MAX));
    }
}

pub fn task_create_affinity(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
) -> usize {
    // A pin to a CPU this boot does not have (at or past `nr_cpu_ids`: the
    // DTB named fewer CPUs, or the Kconfig ceiling NR_CPUS cut them) has no
    // ready queue to go to — that CPU has no per-CPU area. Re-pin it, loudly,
    // where `rebalance_from_offline_cpus` used to after the fact, when every
    // CPU of the ceiling still had a static queue. The pin is rewritten, not
    // just clamped at each use: a pin that names another CPU than the one
    // the task runs on refuses the IPC direct switch (`ipc_direct::allowed`),
    // which cost the ipc-roundtrip lane 16 % when only the uses were clamped.
    let affinity = if affinity >= 0 && affinity as usize >= ncpu() {
        // SAFETY: a racy load scan, as at every other call site.
        let to = unsafe { find_best_cpu(priority, MAX_TASKS) }.min(ncpu() - 1);
        azos_drv_sys::kwarn!(
            "[SMP] task '{}' pinned to CPU {}, which this boot does not have (nr_cpu_ids {}) — pinned to CPU {} instead",
            name, affinity, ncpu(), to
        );
        to as i8
    } else {
        affinity
    };
    // `bench-minimal`: boot only what the measurement needs.
    //
    // **WHY this exists.** Comparing this kernel against Linux under the same
    // emulator was measuring two unequal machines: a normal boot brings up
    // ~20 tasks (rt-motor, flight-ctrl, behaviour, net-poll, telemetry,
    // watchdog, the io-ring worker…) that all compete while the benchmark
    // runs, while the Linux guest ran a single process as PID 1. It showed up
    // as noise, not as a slowdown: the syscall floor drifted 22 % between the
    // first and last batch of one run, against 2 % on the Linux side. That
    // spread is not measurement error, it is the rest of the OS working.
    //
    // **WHY the gate is here and not at the 37 call sites.** One place to
    // reason about, one place to audit, and — since the whole thing is
    // `cfg`'d out by default — literally no code in a normal build. Gating
    // each call site would have meant 30-odd edits in `main.rs`, every one of
    // them a chance to skip a task that the kernel actually needs.
    //
    // **Forked children are deliberately NOT parked.** `fork()` builds its
    // child through `try_task_create_affinity` directly (see
    // `process.rs`, where it passes the name "forked"), so it never reaches
    // this gate. That is the semantics we want -- the gate exists to silence
    // boot-time daemons, not to break `fork()` -- and it is load-bearing for
    // the IPC round-trip benchmark, whose client and server are a forked pair.
    // If `fork()` is ever rerouted through `task_create_affinity`, that
    // benchmark will hang with the child parked and the parent blocked on a
    // reply that never comes.
    //
    // This is a measurement aid, never a production configuration: a robot
    // without `rt-motor` is not a robot.
    #[cfg(feature = "bench-minimal")]
    let entry_fn = if BENCH_MINIMAL_KEEP.contains(&name) {
        entry_fn
    } else {
        // Announce once. This banner is not decoration: `vsbench_compare.sh`
        // refuses its bench-minimal (gate) column unless this line is in that
        // boot's log, so a kernel built without the feature cannot put
        // full-boot numbers under the bench-minimal label, where they would
        // read as a 5x regression. The script matches the text exactly
        // (`BENCH_MINIMAL_BANNER`): change both together.
        if !BENCH_MINIMAL_ANNOUNCED.swap(true, Ordering::Relaxed) {
            azos_drv_sys::kwarn!("[BENCH] bench-minimal: only idle+autorun run; all other tasks parked");
        }
        bench_minimal_park as fn(usize)
    };

    try_task_create_affinity(name, entry_fn, arg, priority, affinity)
        .expect("sched: task pool full")
}

/// Task-pool slots not in use right now (a racy snapshot: a creation or exit
/// on another hart can move it by one). For callers that size optional work
/// to what is left, such as the boot's stress workers on a small profile.
pub fn free_task_slots() -> usize {
    // SAFETY: an atomic load per slot, the same unsynchronised probe the
    // census helpers use; the result is advisory.
    (0..MAX_TASKS).filter(|&i| unsafe { !TASK_VALID[i].load(Ordering::Relaxed) }).count()
}

/// Fallible variant of [`task_create_affinity`] — returns `None` instead of
/// panicking when the task pool is exhausted. See that function's doc for
/// when to use this one. K-A13.
pub fn try_task_create_affinity(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
) -> Option<usize> {
    try_task_create_init(name, entry_fn, arg, priority, affinity, TaskInit::default())
}

/// The address-space value (`Task::task_satp`) of a task that has no user
/// address space: the kernel's own root.
///
/// **riscv64**: the `satp` word `vmm::enable_paging` installed
/// (`switch_kernel_pt` = `make_satp(kernel_pagetable(), 0)`), i.e. the value
/// every boot-created kernel task already carries, so `context_switch.S`'s
/// "same satp, skip the switch" test keeps working between kernel tasks.
/// Cached: `kernel_pagetable()` takes a lock, and this runs under `POOL_LOCK`
/// on every task creation. With no kernel root built (before
/// `vmm::init`) it is the live `satp`, what the creator's read gave before.
///
/// **aarch64**: `0`, the sentinel `context_switch.S` resolves to
/// `AARCH64_KERNEL_TTBR0` (the device-only low-half root); the kernel itself
/// lives in `TTBR1_EL1`.
///
/// **x86_64**: the CR3 word of the kernel's PML4 (PCID 0), cached as on
/// riscv64; 0 before `vmm::init` (`context_switch.S` keeps the live root).
#[inline]
pub fn kernel_task_satp() -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        static KERNEL_SATP: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let cached = KERNEL_SATP.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        let kpt = azos_mm::vmm::kernel_pagetable();
        if kpt == 0 {
            return azos_arch::cpu::read_satp() as u64;
        }
        let satp = azos_arch::mmu::make_satp(kpt, 0) as u64;
        KERNEL_SATP.store(satp, Ordering::Relaxed);
        satp
    }
    // x86_64: the kernel's PML4 word, so a kernel task does not keep the
    // last user root live in CR3 (published, that root could never be torn
    // down: `root_holders` would refuse it while this CPU names it).
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use azos_arch::ArchPlatform;
        static KERNEL_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let cached = KERNEL_CR3.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        let kpt = azos_mm::vmm::kernel_pagetable();
        if kpt == 0 {
            return 0;
        }
        let w = azos_arch::ARCH.user_root_word(kpt, 0) as u64;
        KERNEL_CR3.store(w, Ordering::Relaxed);
        w
    }
    #[cfg(not(any(target_arch = "riscv64", all(target_arch = "x86_64", target_os = "none"))))]
    { 0 }
}

/// Create a task with its security and scheduling identity already installed.
///
/// This is the only correct way to create a task that must not be observed
/// in a half-initialised state. Everything in `init` is written inside the
/// same `POOL_LOCK` section that fills the rest of the slot, i.e. strictly
/// before `cpu_enqueue_locked` publishes the task and rings the target
/// hart's doorbell IPI. See [`TaskInit`] for what went wrong when callers
/// patched these fields after creation instead.
pub fn try_task_create_init(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
    init: TaskInit,
) -> Option<usize> {
    // D2: every task has a domain. A thread joins its creator's, any other
    // task gets a fresh one: a task made by another task (a spawn, a fork) is
    // a child of its creator's Domain, so the subtree policy follows it; a
    // kernel task has no creator and is a root. Taken before interrupts go
    // off, under the Domain table's own lock only: a fresh Domain is a scan
    // of the table and a reset of its entries, 2.3 us of the 9.7 us this
    // function held interrupts masked (riscv64 `-icount`, lat smoke,
    // 2026-10-24). A creation refused below gives it back after interrupts
    // are on again (`refused_dom`).
    let dom = if let Some(k) = init.domain {
        crate::domain::join(k).then_some(k)
    } else {
        crate::domain::create_child(idx_for_tid(init.parent).map_or(crate::domain::NONE, task_domain))
    };
    let mut refused_dom = None;

    // Three bounded steps, each with interrupts masked only by its own lock:
    // the slot under POOL_LOCK (`PoolGuard`), the wait-graph reset of the
    // slot (the graph's lock), the enqueue under the target CPU's lock. The
    // whole function ran masked (once for a NEXT_TID race; the TID is
    // allocated under POOL_LOCK): 9.7 us of `-icount` time on riscv64 and
    // 8.6 us on aarch64 in the lat smoke. Between the steps the slot holds a
    // Ready task in no queue that nothing has a TID for yet: a creator
    // preempted there only starts it later.

    // K-C22(B): address spaces the claimed slot's PREVIOUS occupant left
    // behind, captured under POOL_LOCK and destroyed after interrupts are
    // back on (a full teardown walks and frees hundreds of frames — not
    // something to do with SIE off on an RT hart). See the reuse-time
    // comment at the capture site for why destroying here is safe at all.
    let mut stale_user_pt: u64 = 0;
    let mut stale_exec_old_pt: u64 = 0;

    let result = unsafe {
        // --- Allocate and initialize task under pool lock ---
        let alloc = {
            let _pool = PoolGuard::acquire();
            // Gate canary `pool-lock-spin-canary` (the `lat: <isa> irq-off
            // canary` rows): this step, interrupts masked, held twice the RT
            // contract's bound (Kconfig LOCK_MAX_HOLD_US). Never in a real build.
            #[cfg(feature = "pool-lock-spin-canary")]
            {
                use azos_drv_sys::timebase::{now, TIMER_FREQ};
                let end = now() + TIMER_FREQ * 2 * azos_limits::LOCK_MAX_HOLD_US / 1_000_000;
                while now() < end {
                    core::hint::spin_loop();
                }
            }

            // Wave 12 (EXIT2): a child whose exit will be reported needs room
            // for its notice — see `exit_note::admits`. One atomic load when
            // no notice is queued; a slot count only while some are.
            let admitted = init.parent == 0 || {
                let notices = EXIT_NOTICES_QUEUED.load(Ordering::Acquire) as usize;
                notices == 0 || exit_note::admits(free_task_slots(), notices)
            };
            if !admitted {
                EXIT_NOTICE_REFUSALS.fetch_add(1, Ordering::Relaxed);
            }

            match if admitted && dom.is_some() { alloc_slot() } else { None } {
                None => {
                    refused_dom = dom;
                    None
                }
                Some(idx) => {
                    PARENT_TID[idx].store(init.parent, Ordering::Relaxed);
                    let task = task_mut(idx);
                    // Before the TID is published: whoever resolves the TID
                    // (`idx_for_tid`) then finds the domain in place.
                    task.domain.store(dom.unwrap_or(crate::domain::NONE), Ordering::Relaxed);

                    // U02-6 (second half): `alloc_tid` is the old
                    // wrapping-counter dance, now also skipping any
                    // candidate a live task still holds once the counter
                    // has wrapped once — see its doc.
                    let tid = alloc_tid();
                    task.tid = tid;
                    TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].store(idx as u16, Ordering::Relaxed);

                    let name_bytes = name.as_bytes();
                    let len = name_bytes.len().min(31);
                    task.name[..len].copy_from_slice(&name_bytes[..len]);
                    task.name[len] = 0;

                    task.priority.store(priority, Ordering::Relaxed);
                    task.base_priority.store(priority, Ordering::Relaxed);
                    // Pool slots are reused: a stale count from the previous
                    // occupant would keep this task permanently "donated to".
                    task.donation_count.store(0, Ordering::Relaxed);
                    // Same slot-reuse hazard for the other cross-hart flags.
                    // A stale `wake_pending` (a wake that raced the previous
                    // occupant's exit and was never consumed) would hand this
                    // task a phantom wakeup on its first block. A stale
                    // `fork_ctx_ready` (previous occupant was a fork child
                    // that died without consuming its context) is far worse:
                    // a new fork child in this slot would swap it, read the
                    // PREVIOUS process's entry/user_sp/satp, and SRET into a
                    // freed address space. `context_saving` should already be
                    // false on every exit path; clearing it is free insurance
                    // against a future path that Zombifies mid-transition.
                    // (The wake stamp lives in `state_word` now — cleared
                    // together with the state reset below, atomically.)
                    // K-C12: a stale `queued` (previous occupant died while
                    // an entry of its own still sat in a ready queue) would
                    // make this brand-new task permanently un-enqueueable —
                    // `cpu_enqueue` would refuse it forever as a duplicate.
                    // That is the same silent starvation the flag prevents,
                    // inverted.
                    task.queued.store(false, Ordering::Relaxed);
                    task.fork_ctx_ready.store(false, Ordering::Relaxed);
                    task.fork_entry   = 0;
                    task.fork_user_sp = 0;
                    task.fork_satp    = 0;
                    // K-C21: same hygiene for the exec hand-off. A stale
                    // `exec_ctx_ready` (previous occupant published an exec
                    // it never consumed — no such path exists today, but the
                    // flag must not be the thing that assumption hangs on)
                    // would make this task's next ecall SRET into the dead
                    // process's image. If one IS pending, its `exec_old_pt`
                    // is an address space nothing else references any more —
                    // hand it to the same reuse-time reclaim as `user_pt`
                    // below instead of leaking it.
                    if task.exec_ctx_ready.swap(false, Ordering::Relaxed) {
                        EXEC_HANDOFFS.fetch_sub(1, Ordering::Relaxed);
                        stale_exec_old_pt = task.exec_old_pt;
                    }
                    task.exec_entry   = 0;
                    task.exec_user_sp = 0;
                    task.exec_sstatus = 0;
                    task.exec_satp    = 0;
                    task.exec_old_pt  = 0;
                    task.context_saving.store(false, Ordering::Relaxed);
                    task.cpu_affinity  = affinity;
                    // One plain store resets state AND clears any stale wake
                    // stamp from the slot's previous occupant — the only
                    // place a plain (non-CAS) store of the word is correct,
                    // because the slot is not yet visible to any waker.
                    task.state_word.store(
                        crate::task::sched_word::pack(TaskState::Ready),
                        Ordering::Relaxed,
                    );
                    // K-C26 provenance — see `Task::ready_site`.
                    task.ready_site.store(
                        crate::task::ready_site::CREATE
                            | ((current_cpu_id() as u8) << 4),
                        Ordering::Relaxed,
                    );
                    task.wait_reason    = WaitReason::None;
                    // The slot is being reused: a reservation its previous
                    // occupant still held (one that died without passing the
                    // dispatch tail's reap) leaves its hart's set and ledger.
                    rt::release(idx);
                    // N6: the slot's SC starts over in its priority's class.
                    classes::on_slot_reset(idx, priority);
                    // Wave 13: a reused slot is in no thread group.
                    crate::group::slot_reset(idx);
                    // The slot reset installs `disabled()` — which means
                    // ALLOW EVERYTHING. A caller that wants this task
                    // confined must have its filter land here, under
                    // POOL_LOCK, and not after the enqueue below has already
                    // made the task dispatchable on another hart.
                    task.syscall_filter = match init.syscall_filter {
                        Some(f) => f,
                        None => SyscallFilter::disabled(),
                    };
                    task.stack_idx      = idx;
                    task.entry_fn       = entry_fn as usize;
                    task.entry_arg      = arg;

                    // The plain entry points (`task_create`,
                    // `task_create_affinity`) default to `BestEffort`.
                    task.sched_class_raw     = init
                        .class_raw
                        .unwrap_or(crate::task::DEFAULT_SCHED_CLASS_RAW);
                    classes::on_row_class(idx, task.sched_class_raw);
                    crate::fp::reset(idx);
                    // The next task in this slot starts with no I/O port open.
                    crate::ioport::reset(idx);
                    // A stale set of PAC keys must not reach the next task in this slot.
                    crate::pac::clear(idx);
                    // Native unless the creator asked for the Linux
                    // personality; in place before the enqueue publishes the
                    // task (a spawned child is switched to while it waits for
                    // its hand-off, and its filter word is cached then).
                    task.abi = if azos_limits::LINUX_ABI { init.abi } else { crate::task::ABI_NATIVE };
                    publish_filter_word(idx);

                    // Stack grows down; top is the (ABI-aligned) end of the slice.
                    let stack_top = task_stack_top(idx);
                    // x86_64: `context_switch` jumps to the entry, which the
                    // SysV ABI enters with RSP = 8 mod 16, as after a `call`.
                    // arch-only: the other ISAs enter at the slice's aligned end.
                    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
                    let stack_top = stack_top - 8;

                    let entry_addr = task_entry_wrapper as *const () as usize as CtxReg;
                    let target_cpu = pick_target_cpu(affinity, priority, idx);
                    task.context = TaskContext {
                        sp: stack_top as CtxReg,
                        pc: entry_addr,
                        ra: entry_addr,
                        tp: target_cpu as CtxReg,
                        ..Default::default()
                    };
                    // Placement histogram: the slot's home is now known.
                    // Until here its recorded key was `NONE` (freed slots
                    // are re-accounted to `NONE`), which is also what
                    // `pick_target_cpu(.., idx)` above excluded.
                    hist_reaccount(idx);

                    // Phase 7: per-task SATP and user-space fields (requires MMU).
                    //
                    // K-C22(B), now the FALLBACK: `task_exit()` frees the
                    // dying task's address space itself since K-C22(C) — it
                    // first moves its own hart onto the kernel root (see
                    // `release_address_space_at_exit`), which is what the
                    // original deferral to REUSE time, i.e. right here, was
                    // working around: the exiting hart used to stay on that
                    // satp until `do_schedule()` switched away. A `user_pt`
                    // still found here belongs to a task that never ran that
                    // path with it (a fork/spawn child published after it
                    // exited). K-C6 frees the slot only in the
                    // `do_schedule()` call that is about to context-switch
                    // off the dying task's stack. Zeroing without destroying
                    // (the old code) leaked the whole address space. Capture
                    // under POOL_LOCK, destroy after SIE is restored (see
                    // `stale_user_pt` above).
                    //
                    // Residual window, argued exactly: the Zombie arm clears
                    // TASK_VALID a few dozen instructions BEFORE its
                    // `context_switch()` reaches `csrw satp`, so a claim can
                    // land while the freeing hart is still on the dying PT.
                    // In that tail the freeing hart runs straight-line,
                    // IRQ-off kernel code (spin-gate, a handful of stores,
                    // the register restore) touching only kernel text /
                    // stacks / .bss — all of which resolve through the
                    // kernel L1 tables the teardown BORROWS and never frees
                    // (`destroy_user_pagetable_skip_range` skips
                    // `k_l1 == u_l1`). The only frame that hart still needs
                    // is the PT ROOT, which the teardown frees LAST — after
                    // this claim finishes slot init + enqueue under two more
                    // locks, restores SIE, and walks all 512 L2 slots (a
                    // deliberate, load-bearing property; noted on the vmm
                    // fn). "Orders of magnitude" of guest instructions was
                    // the argument, and it does not hold once the host
                    // deschedules the dying hart's vCPU inside those few
                    // instructions: on 5c805b9, where every exit took this
                    // path, 3 of 119 probed abitest boots freed a root
                    // another hart still had published, and one boot of an
                    // earlier run took the kernel page fault (the trap
                    // vector fetched through the freed root, with idle's
                    // registers already restored by `context_switch`).
                    // The teardown now refuses a root any hart still
                    // publishes (`Mmu::root_holders`); here that turns the
                    // race into a leaked address space.
                    {
                        // Every new task starts on the KERNEL's root; a task
                        // that gets a user address space (fork, spawn, exec)
                        // has it installed later by `set_task_user_info` /
                        // `set_current_user_info`. This used to be the
                        // CREATOR's live `satp`: a kernel task created from a
                        // user context (the io_ring SQ poller, created inside
                        // its owner's submit syscall) ran on that user's page
                        // table, which the owner's exit frees. See
                        // `kernel_task_satp`.
                        task.task_satp = kernel_task_satp();
                        stale_user_pt  = task.user_pt;
                        task.user_pt   = 0;
                        task.user_brk  = 0;
                        task.user_mmap_low = 0;
                        // Owner decision 102 / D2 — the frame budget is the
                        // domain's, and a new domain starts from zero (limit
                        // included: every path that gives a task a budget sets
                        // it), so a slot cannot hand its next tenant the
                        // previous one's spent count or ceiling.
                        task.mem = crate::task::TaskMem::new();
                        task.user_window = [[0; 2]; crate::user_window::USER_WINDOW_RANGES];
                        task.reap_on_resume = 0;
                        // Chain E commit 9: a resume point is spent by every
                        // resume, so a slot's last tenant leaves none; reset
                        // anyway, as `reap_on_resume`, so no path that ends a
                        // task without resuming it can hand one on.
                        task.fast_resume_pc = 0;
                    }

                    // Phase 16: write stack canary at the bottom of the stack (lowest
                    // address).  Stack grows downward, so this is the first location
                    // overwritten on overflow.  Checked by `stack_canary_check()`.
                    // Skip when guard pages are active — the bottom page is unmapped
                    // and writing the canary would page fault.
                    if !GUARD_PAGES_ACTIVE.load(Ordering::Acquire) {
                        (TASK_STACKS.0[idx].as_mut_ptr() as *mut u64).write_volatile(stack_canary());
                    }

                    Some((idx, target_cpu))
                }
            }
        }; // pool lock released here

        match alloc {
            None => None,
            Some((idx, target_cpu)) => {
                // --- Enqueue to target CPU under CPU lock ---
                // `target_cpu` may differ from the creating CPU (priority-aware
                // assignment or explicit affinity) — always go through the locked
                // wrapper.
                // K-C12: a brand-new task can never be a duplicate (its
                // `queued` flag was just cleared), so a refusal here can only
                // mean the ring is genuinely full. Fail the creation instead
                // of returning a task index for something that is in no ready
                // queue and will never run: `fork()` reports -1, which its
                // caller already handles, and the pool slot goes back.
                // N7: nothing of the previous occupant's wait-graph state
                // survives (its effective attribute, its boost floor, an
                // object that still names the slot as owner). Before the
                // enqueue, outside POOL_LOCK: a graph reset takes the graph
                // lock three times and looks at every lazy edge (4.6 us of
                // the masked window above, riscv64 `-icount`).
                classes::on_slot_graph_reset(idx);
                if !cpu_enqueue_locked(target_cpu, idx) {
                    {
                        let _pool = PoolGuard::acquire();
                        TASK_VALID[idx].store(false, Ordering::Relaxed);
                        hist_reaccount(idx);
                        crate::domain::leave(TASKS[idx].take_domain());
                        // Mirror of alloc_slot's sentinel protocol: unpublish,
                        // fence, then clear the tid so no unsynchronised scan
                        // can ever again match this task's TID against the
                        // slot's next life.
                        core::sync::atomic::fence(Ordering::Release);
                        TASKS[idx].tid = 0;
                    }
                    // K-C22(B): the claim already zeroed the slot's `user_pt`
                    // — the captured stale address spaces must be destroyed
                    // on THIS exit too, or they become unreachable forever.
                    if (stale_user_pt | stale_exec_old_pt) != 0 {
                        REUSE_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
                        reclaim_stale_user_pts(stale_user_pt, stale_exec_old_pt);
                    }
                    return None;
                }

                Some(idx)
            }
        }
    };

    if let Some(k) = refused_dom {
        crate::domain::leave(k);
    }
    // The task list shows the task before its creator learns its TID.
    if let Some(idx) = result {
        view_note(idx);
    }
    // Wave 15 (TRACE): the proc class's spawn record (every task, kernel or
    // user, fork or spawn, is created here).
    if azos_trace::proc_on() {
        if let Some(idx) = result {
            azos_trace::raw::proc_spawn(unsafe { task_ref(idx).tid }, current_task_tid());
        }
    }
    // K-C22(B): reuse-time reclaim of the previous occupant's address
    // space(s), with interrupts back on. Runs before the caller learns the
    // new index, but after the new task is enqueued — harmless: the new task
    // holds `user_pt = 0` and never references what is being freed. A
    // fallback since K-C22(C): the exit path frees its own, so this finds
    // something only in the cases `release_address_space_at_exit` lists.
    if (stale_user_pt | stale_exec_old_pt) != 0 {
        REUSE_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
        reclaim_stale_user_pts(stale_user_pt, stale_exec_old_pt);
    }
    result
}

/// K-C22(B)/(C): destroy address spaces recovered from an exiting task
/// ([`release_address_space_at_exit`]) or from a reused task slot.
///
/// Callable ONLY with page tables no hart can still hold in satp/TLB: the
/// exit path's switch-then-free argument, or the reuse-time argument in
/// `try_task_create_affinity`.
/// Goes through `process::destroy_user_address_space` — not bare
/// `vmm::destroy_user_pagetable` — so shm/MMIO frames mapped into the dead
/// address space are spared (they are owned by the shm registry / the
/// hardware, not by the page table; see that function).
fn reclaim_stale_user_pts(user_pt: u64, exec_old_pt: u64) {
    if user_pt != 0 {
        crate::process::destroy_user_address_space(user_pt);
    }
    if exec_old_pt != 0 {
        crate::process::destroy_user_address_space(exec_old_pt);
    }
}

/// Create a new kernel task, auto-assigned to the CPU where a task of this
/// priority will actually get dispatched (K-C12 — see [`find_best_cpu`]).
///
/// Returns the task pool index (for debugging; rarely needed by callers).
pub fn task_create(name: &str, entry_fn: fn(usize), arg: usize, priority: u32) -> usize {
    task_create_affinity(name, entry_fn, arg, priority, -1)
}

/// Translate a `tid` to a slot index in the global `TASKS[]` array.
///
/// O(1) on a `TID_SLOT` hint hit (the common case: every publisher of a
/// tid records the hint at the same time), falling back to an
/// O(`MAX_TASKS`) scan only on a hint miss (stale, colliding, or never
/// set) — this doc used to describe only the fallback, before the hint
/// existed. Used by every wake path,
/// `EXIT_NOTE`'s orphan check, and `alloc_tid`'s post-wrap search all
/// depend on the hint-hit case staying cheap.
/// Does slot `idx` hold the live task `tid` (`TASK_VALID` and its TID, the
/// check [`idx_for_tid`]'s hint makes)? For a slot a caller kept as a hint:
/// a read, not a promise, as [`idx_for_tid`]'s answer is not one either.
#[inline(always)]
pub fn slot_holds(idx: usize, tid: u32) -> bool {
    // SAFETY: `idx < MAX_TASKS`; word reads, as `idx_for_tid`'s hint check.
    tid != 0 && idx < MAX_TASKS && unsafe { TASK_VALID[idx].load(Ordering::Relaxed) && TASKS[idx].tid == tid }
}

pub fn idx_for_tid(tid: u32) -> Option<usize> {
    // TID 0 is the sentinel `alloc_slot` parks in a slot before publishing
    // it (and the free sites park after unpublishing) — it never names a
    // task, so it must never match one.
    if tid == 0 {
        return None;
    }
    unsafe {
        // The published slot for this TID, verified exactly as the scan below
        // verifies a match. A hint that is stale, collides with another live
        // TID, or was never set fails the check and falls through to the scan,
        // so it can only cost time.
        let hint = TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].load(Ordering::Relaxed) as usize;
        if hint < MAX_TASKS
            && TASK_VALID[hint].load(Ordering::Relaxed)
            && TASKS[hint].tid == tid
        {
            core::sync::atomic::fence(Ordering::Acquire);
            if TASK_VALID[hint].load(Ordering::Relaxed) && TASKS[hint].tid == tid {
                return Some(hint);
            }
        }
        for i in 0..MAX_TASKS {
            if TASK_VALID[i].load(Ordering::Relaxed) && TASKS[i].tid == tid {
                // Pairs with the Release fences in `alloc_slot` and the free
                // sites: having (tentatively) observed a match, order the
                // re-reads after everything the publisher wrote before its
                // fence. A mid-allocation slot re-reads as tid 0 and is
                // rejected; only a slot whose tid was genuinely published
                // (or a torn first read that the re-read corrects) survives.
                // Fence-per-MATCH, not per-iteration — a resolution walks up
                // to 64 slots and this path is on every cap operation.
                core::sync::atomic::fence(Ordering::Acquire);
                if TASK_VALID[i].load(Ordering::Relaxed) && TASKS[i].tid == tid {
                    // Re-publish the hint (wave 13). A later TID sharing this
                    // bucket overwrote it at its creation, and nothing put it
                    // back when that task exited: every lookup of this TID
                    // then walked the table (measured: +156 instructions on
                    // each typed call of a long-lived task after 256 task
                    // creations, the thread lanes' churn). A stale or racing
                    // hint is verified like any other, so this only saves time.
                    TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].store(i as u16, Ordering::Relaxed);
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Translate a slot index in `TASKS[]` to its `tid`. Inverse of
/// [`idx_for_tid`]. Returns `None` if the slot is not a valid task.
pub fn tid_for_idx(idx: usize) -> Option<u32> {
    if idx >= MAX_TASKS {
        return None;
    }
    unsafe {
        if TASK_VALID[idx].load(Ordering::Relaxed) {
            Some(TASKS[idx].tid)
        } else {
            None
        }
    }
}

/// Create a task with a security profile pre-applied.
///
/// The filter is set before the task ever runs — it cannot call any
/// unauthorized syscall, not even during initialization.
///
/// An unknown `profile_id` FAILS CLOSED to `PROFILE_MINIMAL` (exit/yield/
/// sleep/write/brk only) and logs. This function returns a task index with
/// no error channel, so the old behaviour — `profile_to_filter` handing
/// back a disabled filter for any unrecognised id — created a fully
/// *unrestricted* child while the caller believed it had sandboxed one,
/// with no return code that could have revealed the difference. A child
/// that is too confined to work fails loudly during bring-up; a child that
/// is silently unconfined does not fail at all until it matters.
pub fn task_create_filtered(
    name: &str, entry_fn: fn(usize), arg: usize,
    priority: u32, profile_id: u64,
) -> usize {
    // Resolve the profile BEFORE creating anything: a task must never exist,
    // however briefly, in a state its creator did not ask for.
    let filter = match crate::seccomp::profile_to_filter(profile_id) {
        Some(f) => f,
        None => {
            azos_drv_sys::kwarn!(
                "[SECCOMP] unknown profile {} for task '{}' — failing closed to MINIMAL",
                profile_id, name
            );
            // `PROFILE_MINIMAL` is a known-good id, so the `None` arm is
            // unreachable — but it must not be `unwrap()` (panic = board
            // reset) nor `SyscallFilter::disabled()` (that is the exact
            // silent-unrestricted bug being fixed). Deny-everything is the
            // only fallback that stays fail-closed without panicking.
            crate::seccomp::profile_to_filter(crate::seccomp::PROFILE_MINIMAL)
                .unwrap_or_else(|| {
                    let mut deny_all = crate::task::SyscallFilter::disabled();
                    deny_all.enabled = true;
                    deny_all
                })
        }
    };
    // The filter is installed under POOL_LOCK, before the task is enqueued.
    //
    // It used to be written after `task_create` returned — and `task_create`
    // returns only once `cpu_enqueue_locked` has put the task in a ready
    // queue AND rung the target hart's doorbell IPI. The slot reset leaves
    // `SyscallFilter::disabled()` behind, and `disabled` is allow-everything,
    // so a task created to be sandboxed was dispatchable unconfined for the
    // length of that window — one the kernel actively signals another CPU to
    // come and use. See [`TaskInit`].
    try_task_create_init(
        name, entry_fn, arg, priority, -1,
        TaskInit { syscall_filter: Some(filter), ..TaskInit::default() },
    )
    .unwrap_or(MAX_TASKS)
}

azos_common::ro_hook! {
    /// Called when a task's entry function returns.
    ///
    /// Marks the task as zombie and immediately tries to reschedule. If no tasks
    /// are ready, enters a WFI idle loop (timer interrupts will call
    /// `schedule()` to pick up future tasks).
    ///
    /// K-C6: deliberately does NOT free the task's pool slot (`TASK_VALID`) or
    /// clear `PER_CPU[cpu].current_idx` — this function is still executing ON
    /// the exiting task's own stack, so doing either here would let another
    /// hart's `alloc_slot()` (e.g. via `fork()`) reuse and dispatch a brand new
    /// task onto that same physical stack while this hart is still running on
    /// it. `do_schedule()` frees the slot itself, in the same call that
    /// `context_switch()`s away from it — see its `old.state == Zombie` arm.
    ///
    /// Hook invoked with the dying task's TID from [`task_exit`].
    ///
    /// `crates/core/ipc` depends on `crates/core/sched`, so `sched` cannot call into it
    /// directly without a dependency cycle — hence the same registered-callback
    /// shape already used for the wait-queue callbacks (`wq_set_callbacks`). The
    /// kernel registers `task_release_all_resources` (which calls
    /// `azos_ipc::task_release_all`) here at boot.
    ///
    static TASK_EXIT_HOOK: fn(u32);
}

/// Register the [`TASK_EXIT_HOOK`]. Call once, during boot.
pub fn set_task_exit_hook(f: fn(u32)) {
    TASK_EXIT_HOOK.set(f);
}

azos_common::ro_hook! {
    /// Wave 15 (plan 4a): called when an exec'ing thread takes its process's
    /// identity from the leader (`exec_take_over`) with `(from_idx, to_idx, tid)`:
    /// what other crates keep per pool slot for the process (`azos_ipc`'s
    /// capability table, the seed row `natfork` recorded) moves from the
    /// leader's slot to the thread's, which the TID swap right after names
    /// `tid`. Called with interrupts off, before that swap. Registered by the
    /// kernel at boot, as [`TASK_EXIT_HOOK`].
    static TASK_IDENTITY_HOOK: fn(usize, usize, u32);
}

/// Register the [`TASK_IDENTITY_HOOK`]. Call once, during boot.
pub fn set_task_identity_hook(f: fn(usize, usize, u32)) {
    TASK_IDENTITY_HOOK.set(f);
}

azos_common::ro_hook! {
    /// Called with a pool slot whose row of the task list changed
    /// ([`super::task_row_at`]): a task made in it, the task in it a zombie,
    /// the slot freed, its parent re-linked, its identity swapped at an exec.
    /// The introspection tree's admin task list is written here, before the
    /// change's caller goes on (`kernel/src/boot/inspect_tasks.rs`). Called
    /// with interrupts off and under the pool lock at some sites: the hook
    /// takes no lock and does not wait. Registered by the kernel at boot, as
    /// [`TASK_EXIT_HOOK`].
    static TASK_VIEW_HOOK: fn(usize);
}

/// Register the [`TASK_VIEW_HOOK`]. Call once, during boot.
pub fn set_task_view_hook(f: fn(usize)) {
    TASK_VIEW_HOOK.set(f);
}

/// Slot `idx`'s row of the task list changed ([`TASK_VIEW_HOOK`]).
#[inline]
pub(crate) fn view_note(idx: usize) {
    if let Some(f) = TASK_VIEW_HOOK.get() {
        f(idx);
    }
}

azos_common::ro_hook! {
    /// Called with the exiting task's TID after its address space is torn down
    /// (`release_address_space_at_exit`) and before its exit notice: for what
    /// must not happen while the dying task still holds memory (wave 12: the
    /// driver supervisor's wake). Registered by the kernel at boot, as
    /// [`TASK_EXIT_HOOK`].
    static TASK_EXIT_LATE_HOOK: fn(u32);
}

/// Register the [`TASK_EXIT_LATE_HOOK`]. Call once, during boot.
pub fn set_task_exit_late_hook(f: fn(u32)) {
    TASK_EXIT_LATE_HOOK.set(f);
}

/// Does the live task `tid` still hold a user address space? `false` for a
/// kernel task, for a task whose exit has torn its space down, and for a TID
/// with no slot. For ordering checks on the exit path (wave 12).
pub fn tid_holds_address_space(tid: u32) -> bool {
    match idx_for_tid(tid) {
        // SAFETY: a valid slot index; one word read, as `note_exit` does.
        Some(idx) => unsafe { task_ref(idx).user_pt != 0 },
        None => false,
    }
}

azos_common::ro_hook! {
    /// Fork-time bootstrap capability grant, mirroring
    /// [`TASK_EXIT_HOOK`] above for the same reason: `crates/core/ipc` depends on
    /// `crates/core/sched`, so this crate cannot call `azos_ipc::task_fork_grant`
    /// directly without a dependency cycle. `kernel/src/boot/sched.rs`'s
    /// `install_sched_hooks` registers it alongside `set_task_exit_hook`.
    ///
    /// `fn(u32, u32)` is `(parent_tid, child_tid)` — unlike the exit hook, both
    /// identities are needed, and the caller (`sys_fork_impl`, still running as
    /// the parent) already has both without a lookup, so the signature carries
    /// them rather than making the callee re-derive one.
    ///
    static TASK_FORK_HOOK: fn(u32, u32);
}

/// Register the [`TASK_FORK_HOOK`]. Call once, during boot.
pub fn set_task_fork_hook(f: fn(u32, u32)) {
    TASK_FORK_HOOK.set(f);
}

/// Invoke the registered [`TASK_FORK_HOOK`], if one was registered.
///
/// A no-op before boot registration — same convention as `TASK_EXIT_HOOK`'s
/// call site: a missing hook is a silent no-grant, not a panic, because a
/// host-side unit test or an early-boot fork must not crash for lacking a
/// capability subsystem it never asked for.
pub(crate) fn invoke_task_fork_hook(parent_tid: u32, child_tid: u32) {
    if let Some(f) = TASK_FORK_HOOK.get() {
        f(parent_tid, child_tid);
    }
}

/// K-C22(C): tear down the exiting task's address space on its own exit path.
///
/// Called by [`task_exit_with_code`] for the task running on this hart (slot
/// `idx`), after the exit hook and before the Zombie mark. The order inside is
/// load-bearing, because interrupts are ON here and a tick may switch this
/// task out and back in at any point:
///
///  1. `task_satp` becomes the kernel's root and `user_pt` is taken (zeroed)
///     FIRST. A switch back into this task after that installs the kernel
///     root, never the table being freed.
///  2. This hart leaves the user table: riscv64 `csrw satp` to the kernel root
///     (`cpu::write_satp`: publishes the root for the shootdown scan, full
///     `sfence.vma`); aarch64 `TTBR0_EL1` to the kernel's device-only low-half
///     root (`AARCH64_KERNEL_TTBR0`) plus a local `tlbi vmalle1`. Kernel
///     text, data and stacks resolve through the kernel root on riscv64 and
///     through `TTBR1_EL1` on aarch64, so execution continues unchanged.
///  3. Only then the teardown. No hart holds the table any more: this one
///     just left it, and no thread of the process is left on another hart:
///     a member leaves the root (`member_exit`) before it drops the group's
///     live count, and the leader gets here only once that count is 1
///     (`group_exit`); a switch to a kernel task installs the kernel root on
///     every ISA (no lazy user root). A hart that ran the space earlier may
///     still hold TLB and walk-cache entries for it under Kconfig
///     `TLB_RETAIN`, but tagged with the space's ASID, which is not handed
///     out again before a rollover (`asid::new_root_word` gives a reused
///     root frame a fresh one), and a rollover flushes every hart before it
///     runs a new-generation ASID (`tlb_gen`). So nothing walks the frames
///     the allocator is about to reissue, and no `TLBI ASIDE1IS` is needed
///     (Linux arm64 needs its `flush_tlb_mm` at exit because the exiting
///     CPU keeps the mm in TTBR0 lazily). It runs with interrupts on, like
///     the reuse-time reclaim it replaces.
///     The teardown checks that rather than trusting it
///     (`Mmu::root_holders`): a hart still on the table gets the address
///     space refused and leaked, never freed under it.
///
/// A pending exec hand-off (published, never consumed — no path does that
/// today, see `try_task_create_init`) leaves the replaced table in
/// `exec_old_pt`; it is freed here too.
///
/// K-C22(B)'s reuse-time reclaim stays as the fallback for a table that is
/// published on a slot after its task already passed this point (a fork or
/// spawn child that died before its parent's `set_task_user_info`), and for
/// aarch64 before the kernel root is published (never, after boot): then
/// nothing is switched or freed here and the claim frees it.
unsafe fn release_address_space_at_exit(idx: usize) {
    let task = task_mut(idx);
    if task.user_pt == 0 && !task.exec_ctx_ready.load(Ordering::Relaxed) {
        return; // a kernel task: nothing to release, nothing to switch
    }

    // arch-only: aarch64's device-only low-half root (TTBR0); riscv64 and an
    // x86_64 port keep the kernel in every user table and switch to the
    // kernel task's own root below.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    let kernel_root = {
        unsafe extern "C" {
            // `kernel/src/entry/aarch64/mod.rs`: the device-only low-half root
            // `context_switch.S` installs for `task_satp == 0`.
            static AARCH64_KERNEL_TTBR0: core::sync::atomic::AtomicU64;
        }
        let root = unsafe { AARCH64_KERNEL_TTBR0.load(Ordering::Acquire) };
        if root == 0 {
            return; // not published: leave both tables to the reuse fallback
        }
        root
    };

    // Step 1.
    task.task_satp = kernel_task_satp();
    let user_pt = core::mem::replace(&mut task.user_pt, 0);
    task.user_brk = 0;
    task.user_mmap_low = 0;
    let exec_old_pt = if task.exec_ctx_ready.swap(false, Ordering::Relaxed) {
        EXEC_HANDOFFS.fetch_sub(1, Ordering::Relaxed);
        core::mem::replace(&mut task.exec_old_pt, 0)
    } else {
        0
    };
    // The switch below must not be hoisted above the stores that tell a
    // context switch which root to install for this task.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Step 2. `exit-satp-canary` (gate canary) skips it: the teardown then
    // finds this hart still on the table and must refuse it (see step 3).
    #[cfg(all(target_arch = "riscv64", not(feature = "exit-satp-canary")))]
    azos_arch::cpu::write_satp(task.task_satp as usize);
    #[cfg(all(target_arch = "aarch64", target_os = "none", not(feature = "exit-satp-canary")))]
    azos_arch::sysregs::install_ttbr0_flush_local(kernel_root as usize);
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "exit-satp-canary"))]
    let _ = kernel_root;
    // Any other ISA (the x86_64 skeleton): the contract's local root install
    // (riscv64's arm above is that same call: `write_satp`).
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64")), not(feature = "exit-satp-canary")))]
    azos_arch::ArchPlatform::install_user_root_local(&azos_arch::ARCH, task.task_satp as usize);

    // Step 3.
    EXIT_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
    reclaim_stale_user_pts(user_pt, exec_old_pt);
}

/// Address spaces torn down on the exit path ([`release_address_space_at_exit`]).
pub static EXIT_TEARDOWNS: AtomicU32 = AtomicU32::new(0);

/// Address spaces the slot-reuse fallback (K-C22(B)) found and tore down.
/// Zero on a run where every exit released its own.
pub static REUSE_TEARDOWNS: AtomicU32 = AtomicU32::new(0);

/// Exit notices published while the exiting task still held its address
/// space ([`note_exit`]). Zero while `task_exit_with_code` notifies after
/// the teardown; any other count means a parent could reap a child whose
/// memory was not back yet.
pub static EARLY_EXIT_NOTICES: AtomicU32 = AtomicU32::new(0);

/// `DOMAIN_EXIT_STATS`: the exit-path counter `which` names
/// (`azos_abi::syscall_nr::EXIT_STAT_*`), or `None` for any other value.
/// Totals since boot, for every task.
pub fn exit_stat(which: u64) -> Option<u32> {
    use azos_abi::syscall_nr::{
        EXIT_STAT_EARLY_NOTICES, EXIT_STAT_EXIT_TEARDOWNS, EXIT_STAT_NOTICE_DROPS,
        EXIT_STAT_NOTICE_REFUSALS, EXIT_STAT_REUSE_TEARDOWNS,
    };
    let c = match which {
        EXIT_STAT_EXIT_TEARDOWNS => &EXIT_TEARDOWNS,
        EXIT_STAT_REUSE_TEARDOWNS => &REUSE_TEARDOWNS,
        EXIT_STAT_EARLY_NOTICES => &EARLY_EXIT_NOTICES,
        EXIT_STAT_NOTICE_DROPS => &EXIT_NOTICE_DROPS,
        EXIT_STAT_NOTICE_REFUSALS => &EXIT_NOTICE_REFUSALS,
        _ => return None,
    };
    Some(c.load(Ordering::Relaxed))
}

/// Never returns.
pub fn task_exit() -> ! { task_exit_with_code(0) }

/// Wave 13: end the current task by a signal: exit code `code` (`128 + n`,
/// what native waiters read, unchanged), and the signal recorded so a Linux
/// parent's `wait4` reports the child killed by `n` (`WIFSIGNALED`), as
/// Linux does. A code outside `129..=192` is an ordinary exit.
pub fn task_exit_by_signal(code: i32) -> ! {
    if (129..=192).contains(&code) {
        signal::mark_current_signalled((code - 128) as u32);
    }
    task_exit_with_code(code)
}

/// End only the calling thread (Linux `exit`, the native thread exit; wave
/// 13). For a task in no thread group it is [`task_exit_with_code`]. A group
/// leader waits in its exit path until it is the group's last member.
pub fn thread_exit(code: i32) -> ! {
    if let Some(idx) = current_slot() {
        crate::group::mark_thread_only(idx);
    }
    task_exit_with_code(code)
}

/// Why [`exec_end_other_threads`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExecDethreadError {
    /// The process is ending (`exit_group`, a fault, a forced stop), or
    /// another of its threads is already exec'ing.
    Ending,
}

/// Wave 15 (plan 4a): the first half of an exec's commit from a process with
/// threads, POSIX's "all other threads are terminated" (Linux `de_thread`).
/// Called once the new image is admitted (`process::exec_prepare_*`): an
/// exec that fails before this point leaves every thread running.
///
/// Every other thread of the caller's process is stopped and this waits until
/// it has gone: each ends only itself (`group::begin_exit` refuses while the
/// group is exec'ing), clears and wakes its clear-tid word on the old image,
/// and leaves the shared root before the exec replaces it, so no thread ever
/// returns to user mode on an address space that is about to be torn down.
/// The last one's exit dissolves the group: the caller is a plain process
/// again, and the commit that follows is the single-threaded one.
///
/// A caller that is not the leader takes the process's identity: the
/// leader, stopped like the others, hands it over on its way out
/// ([`exec_take_over`]) and ends as a thread under the caller's old TID.
/// The caller then IS the process (its TID is the process id the parent
/// waits for, the task list shows and signals name), as Linux's PID swap makes it.
///
/// Returns how many threads were ended (0 for a process with none: one
/// load, `group::lead_of_idx`). It waits as the leader's own exit does
/// (`group_exit`): each member's exit wakes the leader's TID, which the
/// caller holds once the hand-over is done, and the 10 ms deadline is the
/// backstop. Members are stopped by slot, under the pool lock, so a stop
/// meant for the leader cannot land on the caller once it holds the
/// leader's TID; each slot once, and the slots are scanned again on every
/// pass, so one a sibling admitted just before the group was marked is
/// stopped too.
pub fn exec_end_other_threads() -> Result<u32, ExecDethreadError> {
    let Some(idx) = current_slot() else { return Ok(0) };
    let lead = crate::group::lead_of_idx(idx);
    if lead == 0 {
        return Ok(0);
    }
    let me = unsafe { TASKS[idx].tid };
    // Gate canaries only: a thread that is not the leader is refused, as
    // before the PID hand-over; or the other threads keep running across
    // the exec.
    if cfg!(feature = "exec-no-pid-swap-canary") && lead != me {
        return Err(ExecDethreadError::Ending);
    }
    if cfg!(feature = "exec-no-dethread-canary") {
        return Ok(0);
    }
    if !crate::group::begin_exec(lead, me) {
        return Err(ExecDethreadError::Ending);
    }
    let ended = crate::group::live_members(lead).saturating_sub(1);
    // Each slot is stopped once. A member that has exited keeps its slot
    // (and its group mark) until the slot is reused, and a second stop on it
    // would count a forced stop nobody consumes (`FORCED_PENDING`), putting
    // every timer tick from user mode, machine-wide, on the slow path.
    let mut stopped = [0u64; MAX_TASKS.div_ceil(64)];
    while crate::group::live_members(lead) > 1 {
        // The caller itself is being stopped: its exec must not run. The
        // members are already asked; their exits dissolve the group. Once
        // the leader has begun handing it the process, it waits for that.
        if current_forced_exit().is_some() && crate::group::abandon_exec(lead, me) {
            return Err(ExecDethreadError::Ending);
        }
        for i in 0..MAX_TASKS {
            let bit = 1u64 << (i % 64);
            if i != idx && stopped[i / 64] & bit == 0 && crate::group::lead_of_idx(i) == lead {
                stopped[i / 64] |= bit;
                stop_slot(i);
            }
        }
        let deadline = azos_drv_sys::timebase::now()
            .saturating_add(azos_drv_sys::timebase::TIMER_FREQ / 100);
        crate::task_block(WaitReason::Timer(deadline));
    }
    Ok(ended)
}

/// Force-stop (signal 9) whatever task holds slot `idx` now, checked and
/// recorded under the pool lock, which [`exec_take_over`] also holds while
/// it swaps two slots' TIDs: the stop lands on the slot it was meant for.
fn stop_slot(idx: usize) {
    let tid = {
        let _pool = PoolGuard::acquire();
        // SAFETY: under the pool lock, a valid index.
        unsafe {
            if !TASK_VALID[idx].load(Ordering::Relaxed) {
                return;
            }
            let tid = TASKS[idx].tid;
            if tid == 0 {
                return;
            }
            record_stop(idx, tid, stop_policy::Stop { force: true, signo: 9 });
            tid
        }
    };
    wake_stopped(tid, true);
}

/// Wave 15 (plan 4a): the leader's half of an exec by another of its
/// threads. Called on the leader's exit path (`group_exit`, slot `idx`,
/// TID `lead`) while its group is exec'ing by thread `by`: the two slots
/// swap TIDs, and the process's state on the leader's slot moves to the
/// exec'ing thread's — the break, the address-space window, the memory row,
/// the name, the parent link, the subreaper and die-with-parent marks, the
/// signal words, and (through [`TASK_IDENTITY_HOOK`]) the seed row. The
/// capability table and the page budget are the process's domain's and stay
/// where they are. Returns
/// the leader slot's new TID (`by`'s old one): it then ends as a thread of
/// the group, whose leader TID is unchanged. `None` when there is nothing to
/// hand over (no exec, or the leader is the one exec'ing).
///
/// It runs only when the two are the group's last live members
/// (`group::claim_handover`), so no other thread of the process runs; the
/// exec'ing thread is in [`exec_end_other_threads`], which touches nothing
/// of its slot but under the pool lock this holds. A stop already recorded
/// on the leader's slot is dropped (the slot is ending).
unsafe fn exec_take_over(idx: usize, lead: u32) -> Option<u32> {
    // Only once every other member has gone: nothing else of the process
    // still runs (a sibling's fault would charge the process while its slots swap identities).
    let by = crate::group::claim_handover(lead)?;
    let to = idx_for_tid(by)?;
    // Interrupts off from the hook to the TID swap, on this hart, so the
    // seed row and the TIDs move as one step.
    let irqs = azos_arch::ARCH.disable_all();
    if let Some(f) = TASK_IDENTITY_HOOK.get() {
        f(idx, to, lead);
    }
    {
        let _pool = PoolGuard::acquire();
        // SAFETY: both slots valid under the pool lock; the thread in `to`
        // is parked, the leader in `idx` is the caller.
        unsafe {
            let (a, b) = (task_mut(idx) as *mut Task, task_mut(to) as *mut Task);
            let (a, b) = (&mut *a, &mut *b);
            core::mem::swap(&mut a.tid, &mut b.tid);
            core::mem::swap(&mut a.name, &mut b.name);
            core::mem::swap(&mut a.user_brk, &mut b.user_brk);
            core::mem::swap(&mut a.user_mmap_low, &mut b.user_mmap_low);
            core::mem::swap(&mut a.user_window, &mut b.user_window);
            core::mem::swap(&mut a.mem, &mut b.mem);
            for arr in [&PARENT_TID, &DWP_TID] {
                let v = arr[idx].swap(arr[to].load(Ordering::Relaxed), Ordering::AcqRel);
                arr[to].store(v, Ordering::Release);
            }
            let v = SUBREAPER[idx].swap(SUBREAPER[to].load(Ordering::Relaxed), Ordering::AcqRel);
            SUBREAPER[to].store(v, Ordering::Release);
            STOP_TID[idx].store(0, Ordering::Release);
            stop_policy::forced_clear(&FORCED_ACCT[idx], &FORCED_PENDING);
            // The two TIDs' lookup hints now name the other slot; the scan
            // in `idx_for_tid` finds and repairs them on first use.
        }
    }
    azos_arch::ARCH.restore(irqs);
    view_note(idx);
    view_note(to);
    signal::hand_over(idx, to);
    Some(by)
}

/// Wave 13 (THREADS): the thread-group half of an exit, run first.
///
/// A whole-process exit (anything but [`thread_exit`]) marks the group ending
/// with `code` and stops every other member. A member (not the leader) then
/// ends here, alone: its clear-tid word cleared and woken while its address
/// space is still installed, its own objects released by the exit hook (the
/// shared tables are skipped there, `group::shares_tables`), its slot moved
/// off the shared root WITHOUT destroying it, and no exit notice (a thread
/// is nobody's child). The leader waits until it is the last member and then
/// returns the code its exit reports (the group's, when the group ended);
/// the rest of its exit releases what the group shared.
unsafe fn group_exit(idx: usize, tid: u32, code: i32) -> i32 {
    let lead = crate::group::lead_of_idx(idx);
    if lead == 0 {
        let _ = crate::group::take_thread_only(idx);
        // A process with no other thread: nobody of its own can wait on its
        // robust words, but they are marked as Linux marks them.
        robust_list_exit(idx, tid, tid);
        return code;
    }
    // The leader's robust words go before it waits to be alone: the
    // siblings it outlives in that wait may be the ones blocked on them
    // (a member walks its own in `member_exit`).
    if lead == tid {
        robust_list_exit(idx, tid, lead);
    }
    if !crate::group::take_thread_only(idx) && crate::group::begin_exit(lead, code) {
        let mut members = [0u32; crate::group::GROUP_THREADS_MAX as usize];
        let n = crate::group::members_of(lead, tid, &mut members).min(members.len());
        for &m in &members[..n] {
            let _ = task_stop(m, true, 9);
        }
    }
    if lead != tid {
        member_exit(idx, tid, lead, code);
    }
    // The leader's own clear-tid word (Linux
    // `set_tid_address`; musl's start code passes its thread-list lock) is
    // cleared and woken as a member's is, while the address space is still
    // installed, and, as Linux `mm_release` does, only while another thread
    // shares that address space (`mm_users > 1`): alone, nobody can observe
    // it. A leader ending by `pthread_exit` while its threads run is the
    // case: musl holds its thread-list lock across that exit and relies on
    // this clear to release it, so without it the next `pthread_create` or
    // `pthread_exit` in the process waits forever.
    if crate::group::live_members(lead) > 1 && !cfg!(feature = "leader-cleartid-canary") {
        clear_tid_word(idx, lead);
    }
    // The leader: wait to be alone. Each member's exit wakes it; the
    // deadline is a backstop against a wake that found it not yet asleep and
    // a stamp already consumed.
    while crate::group::live_members(lead) > 1 {
        // Wave 15 (plan 4a): another thread is exec'ing. The leader hands
        // it the process and ends as a thread under its old TID.
        if let Some(t) = unsafe { exec_take_over(idx, lead) } {
            member_exit(idx, t, lead, code);
        }
        let deadline = azos_drv_sys::timebase::now()
            .saturating_add(azos_drv_sys::timebase::TIMER_FREQ / 100);
        crate::task_block(WaitReason::Timer(deadline));
    }
    let code = crate::group::exiting(lead).unwrap_or(code);
    crate::group::dissolve(lead, idx);
    code
}

/// Clear and wake the clear-tid word of the task in slot `idx` (process
/// `proc_id`), while its address space is installed. Best effort: a word
/// that cannot be written is skipped. A word of a shm region wakes its
/// region's key (owner decision 10-10, Linux `mm_release`; `futex::wake_in`).
unsafe fn clear_tid_word(idx: usize, proc_id: u32) {
    let addr = crate::group::take_clear_tid(idx);
    // Gate canary only: the word is never cleared (a join never returns).
    if cfg!(feature = "threads-no-cleartid-canary") {
        return;
    }
    if addr == 0 || addr & 3 != 0 {
        return;
    }
    if crate::UserPtr::<u32>::new(addr).write(&0).is_ok() {
        let _ = crate::futex::wake_in(proc_id, addr, 1);
    }
}

/// Walk the robust futex list of the task in slot `idx` (thread `tid` of
/// process `proc_id`; Linux `set_robust_list`) while its address space is
/// installed: each lock word it still owns becomes `FUTEX_OWNER_DIED` and
/// one waiter on it is woken (`azos_linux_abi::robust`). Bounded by Kconfig
/// `LINUX_ROBUST_LIST_LIMIT`. Run before the clear-tid wake: a joiner may
/// free the thread's stack, where musl keeps the list head, once that word
/// is cleared.
fn robust_list_exit(idx: usize, tid: u32, proc_id: u32) {
    let head = crate::group::take_robust_list(idx);
    // Gate canary only: the list is never walked (a lock its owner died
    // holding stays held; the next locker sleeps).
    if head == 0 || cfg!(feature = "robust-list-canary") {
        return;
    }
    struct Mem(u32, usize);
    impl azos_linux_abi::robust::RobustMem for Mem {
        fn read_u64(&mut self, addr: u64) -> Option<u64> {
            crate::UserPtr::<u64>::new(addr).read().ok()
        }
        fn read_u32(&mut self, addr: u64) -> Option<u32> {
            crate::UserPtr::<u32>::new(addr).read().ok()
        }
        fn cas_u32(&mut self, addr: u64, old: u32, new: u32) -> Result<(), Option<u32>> {
            crate::UserPtr::<u32>::new(addr).cas(old, new)
        }
        // A shm word wakes its region's key (owner decision 10-10).
        fn wake_one(&mut self, addr: u64) {
            let _ = crate::futex::wake_key(crate::futex::robust_key(self.0, addr), 1);
        }
        // Wave 15 N10: a PI word goes to the PI futex code (Kconfig FUTEX_PI).
        fn pi_owner_died(&mut self, addr: u64) -> Option<bool> {
            azos_sync::pi_futex::robust_owner_died(self.0, addr, self.1 as u32)
        }
    }
    let limit = azos_limits::LINUX_ROBUST_LIST_LIMIT as u32;
    let _ = azos_linux_abi::robust::exit_robust_list(&mut Mem(proc_id, idx), head, tid, limit);
}

/// The exit of a thread-group member that is not the leader (see
/// [`group_exit`]). Never returns.
unsafe fn member_exit(idx: usize, tid: u32, lead: u32, code: i32) -> ! {
    TASK_EXITING[idx].store(true, Ordering::Release);
    robust_list_exit(idx, tid, lead);
    clear_tid_word(idx, lead);
    TASK_EXIT_CODE[idx].store(code, Ordering::Relaxed);
    {
        if let Some(f) = TASK_EXIT_HOOK.get() {
            f(tid);
        }
    }
    // Off the shared root, never destroying it: a slot reused with
    // `user_pt` still set would tear the group's address space down
    // (K-C22(B)).
    {
        let task = task_mut(idx);
        // arch-only: aarch64's device-only low-half root (see
        // release_address_space_at_exit).
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        let kernel_root = {
            unsafe extern "C" {
                static AARCH64_KERNEL_TTBR0: core::sync::atomic::AtomicU64;
            }
            unsafe { AARCH64_KERNEL_TTBR0.load(Ordering::Acquire) }
        };
        task.task_satp = kernel_task_satp();
        task.user_pt = 0;
        task.user_brk = 0;
        task.user_mmap_low = 0;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        #[cfg(target_arch = "riscv64")]
        azos_arch::cpu::write_satp(task.task_satp as usize);
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        if kernel_root != 0 {
            azos_arch::sysregs::install_ttbr0_flush_local(kernel_root as usize);
        }
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        azos_arch::ArchPlatform::install_user_root_local(&azos_arch::ARCH, task.task_satp as usize);
    }
    // D2: out of the domain BEFORE the leader can learn it is alone, so its
    // exit finds the domain unshared and takes the capability table with it.
    crate::domain::leave(task_mut(idx).take_domain());
    let _ = crate::group::member_gone(lead, tid);
    wake_task_by_tid(lead, &|r| matches!(r, WaitReason::Timer(_)));
    // N7b: the wait graph forgets the task here, with interrupts on.
    classes::on_task_exit(idx);
    // N7d: after the graph's owner-died hand-over, the held table forgets
    // the locks this task dies holding (the panic policy's `mutex-held`).
    azos_sync::held::held_forget(tid);
    // Owner decision 10-10: and the claim table (rule F1) the same way.
    azos_sync::claim::held_forget(tid);
    {
        let _pool = PoolGuard::acquire();
        task_mut(idx).set_state(TaskState::Zombie);
        hist_reaccount(idx);
        view_note(idx);
    }
    let _ = azos_arch::ARCH.disable_all();
    do_schedule(SwitchReason::Voluntary);
    loop {
        azos_arch::ARCH.enable_all();
        azos_arch::Cpu::wfi(&azos_arch::ARCH);
    }
}

/// Same as [`task_exit`] but preserving the exit code for the parent.
///
/// **It used to be lost.** `sys_exit(_code)` discarded its argument and called
/// `task_exit()`, which never took one: there was nobody to notify and nothing
/// to notify with.
pub fn task_exit_with_code(code: i32) -> ! {
    // K-C29: exit cannot be refused and cannot be deferred. A task exiting
    // inside a critical section is a bug in that task — it is not coming back
    // to drop its guard — but refusing to switch away from a Zombie strands
    // the hart, which is worse. Force the depth to 0 and continue; the counter
    // is the record that it happened. This is the one caller of
    // `force_zero_depth`, and it can only ever ENABLE preemption, so it can
    // never itself be the cause of a hang.
    if azos_sync::preempt::disabled() {
        preempt_audit::bump(&preempt_audit::EXIT_WHILE_ATOMIC);
        azos_sync::preempt::force_zero_depth();
    }
    let t_exit = crate::prof::t();
    // Wave 15 (TRACE): the proc class's exit record.
    if azos_trace::proc_on() {
        azos_trace::raw::proc_exit(current_task_tid(), code);
    }
    unsafe {
        // Interrupts are on here: the slot and the hart come from one window.
        let (cpu, idx) = here();
        #[cfg(feature = "exit-stale-hart-canary")]
        stale_hart_canary::arm(cpu, idx);
        #[cfg(not(feature = "exit-stale-hart-canary"))]
        let _ = cpu;
        // Wave 13: a thread group's member ends here alone; its leader
        // waits to be the last and exits with the group's code. So the
        // re-parenting below (`note_exit`) runs once, for the whole process,
        // when its last thread is gone: a member never re-parents (it posts
        // no notice and has no children of its own: a fork from it is its
        // process's child, `current_proc_tid`), and is never re-parented (a
        // thread's parent link is 0).
        let code = if idx != usize::MAX { group_exit(idx, TASKS[idx].tid, code) } else { code };
        // U04-2 route (b): publish "exiting" before ANYTHING else below —
        // `note_exit`, the driver-crash notice and
        // especially the `TASK_EXIT_HOOK` (`task_release_all`) all run
        // after this. See `TASK_EXITING`'s doc for why `tid_exists` alone
        // is not a safe "OK to newly target this tid" answer during that
        // window.
        if idx != usize::MAX {
            // Wave 13: whether `note_exit` re-parents this task's children,
            // published with (before) the exiting mark that readers pair it with.
            EXIT_REPARENTS[idx].store(
                task_ref(idx).user_pt != 0 && !cfg!(feature = "orphan-reparent-canary"),
                Ordering::Relaxed,
            );
            TASK_EXITING[idx].store(true, Ordering::Release);
        }
        // Wave 9: give back the row instance this task held,
        // BEFORE the exit notice: a parent woken by `note_exit` may spawn
        // again at once, and must find the count already returned.
        // Taken to 0 first, so it is returned exactly once.
        if idx != usize::MAX {
            let t = task_mut(idx);
            let row = t.mem.row;
            t.mem.row = 0;
            row_release(row);
        }
        if idx != usize::MAX {
            // Read the dying task's identity BEFORE anything else touches it.
            // `exit_tid` — not `idx` — is what the driver manager and the
            // exit hook are keyed on: pool slots are recycled (`alloc_slot`
            // reuses the first free index, `do_schedule` frees this one), so
            // a slot number identifies "whoever sits here now", not the task
            // that is dying.
            let exit_tid = task_mut(idx).tid;
            // AQ2: Notify driver manager — if this task was a registered driver,
            // record the crash so auto-restart can kick in. Keyed on the TID:
            // passing `idx` used to blame the crash on whichever driver last
            // occupied this pool slot.
            crate::driver::driver_on_crash(exit_tid);

            // Release resources keyed by this TID before the slot can be
            // reused: a resource left behind by a dead task is otherwise
            // inherited by the next task that draws the same pool slot.
            //
            // ORDERING — DO NOT MOVE THIS BLOCK (W3-F7). The hook the kernel
            // registers is `azos_ipc::task_release_all`, which calls
            // `cap_store::reset`. That resolves the TID back to a pool slot
            // and only succeeds while `TASK_VALID[idx]` is still true. It
            // therefore MUST run before the `Zombie` marking below and long
            // before `do_schedule()` frees the slot. Move it later and typed
            // capabilities stop being revoked on exit — silently, with no
            // error and no failing test.
            TASK_EXIT_CODE[idx].store(code, Ordering::Relaxed);
            let t_ph = crate::prof::t();
            {
                if let Some(f) = TASK_EXIT_HOOK.get() {
                    f(exit_tid);
                }
            }

            // K-C22(C): the address space goes HERE, in the exiting task's
            // own context — after the exit hook (whose shm/io_ring unmaps walk
            // `current_user_pt()`), before the Zombie mark. It
            // used to wait for the slot's reuse (K-C22(B)), so an unrelated
            // later `fork` paid ~47k instructions to free a dead process's
            // tables and frames, and they stayed allocated until then.
            crate::prof::add(12, t_ph);
            let t_ph = crate::prof::t();
            release_address_space_at_exit(idx);
            crate::prof::add(13, t_ph);
            let t_ph = crate::prof::t();

            // Wave 12 (EXIT2): the post-teardown hook — the kernel wakes the
            // driver supervisor here, not from `TASK_EXIT_HOOK`, so a restart
            // it decides never runs beside the dead driver's address space.
            // Same place in the sequence as the exit notice just below.
            {
                if let Some(f) = TASK_EXIT_LATE_HOOK.get() {
                    f(exit_tid);
                }
            }

            // The exit notice goes out HERE, after the exit hook and the
            // address-space teardown — Linux's order (`exit_mm`/`exit_files`
            // before `exit_notify`): a parent's `wait`/`waitpid` returns only
            // once this task's capabilities, handles and memory are back, so
            // a parent that reaps and at once forks or spawns again never
            // competes with a half-torn-down child for them. Before the Zombie
            // mark: from there on the slot may be freed on any context switch.
            //
            // It used to sit at the top of this function, because a parent
            // polling `wait` with `yield` at a HIGHER priority than this task,
            // on this hart, never lets it run again once a tick preempts it,
            // and every instruction before the notice was a window for that
            // stall (tried in wave 9: abitest's `waitpid(epsrv)` gave up in 5
            // of 9 `-smp 4` boots). The cure is on the waiting side: a poll
            // SLEEPS between looks, so the hart goes to whatever is ready.
            // `note_exit` counts a notice published while this task still
            // holds its address space (`EARLY_EXIT_NOTICES`, syscall 605).
            crate::prof::add(15, t_ph);
            let t_ph = crate::prof::t();
            note_exit(idx, code);
            crate::prof::add(14, t_ph);

            // N7b: the wait graph forgets the task here, with interrupts on.
            classes::on_task_exit(idx);
            // N7d: the held table forgets the locks it dies holding.
            azos_sync::held::held_forget(exit_tid);
            azos_sync::claim::held_forget(exit_tid);
            // K-C6: mark Zombie only — TASK_VALID stays true and
            // PER_CPU[cpu].current_idx keeps pointing at `idx` (see the
            // function doc above) until do_schedule() can safely free it.
            {
                let _pool = PoolGuard::acquire();
                task_mut(idx).set_state(TaskState::Zombie);
                hist_reaccount(idx);
                view_note(idx);
            } // pool lock released
        }

        crate::prof::add(11, t_exit);
        crate::prof::report(11, 40);
        // Disable interrupts and try an immediate reschedule.
        let _ = azos_arch::ARCH.disable_all();
        do_schedule(SwitchReason::Voluntary);
        // do_schedule() only returns when there are no ready tasks on this CPU.
    }

    // No tasks remaining — idle until timer brings more work.
    loop {
        azos_arch::ARCH.enable_all();
        azos_arch::Cpu::wfi(&azos_arch::ARCH);
        // Timer interrupt → schedule() → do_schedule() → may context-switch away.
        // If not, we just loop again.
    }
}

/// Voluntarily yield the CPU to the next ready task.
///
/// K-C29: a yield issued inside a critical section is refused, not deferred.
/// Yielding while holding a spinlock cannot make progress by yielding — the
/// hart is being asked to stop running the only task that can release the
/// lock. Keeping the holder on the hart is what frees it. This is also the
/// function registered as the deferred-reschedule callback, and the refusal is
/// what stops a guard drop nested inside another critical section from
/// switching early.
#[inline]
pub fn task_yield() {
    yield_as(SwitchReason::Voluntary);
}

/// The deferred-reschedule callback (`preempt::set_resched_callback`): a
/// timer tick that found this hart inside a critical section recorded a debt
/// (`tick_admit`'s `Defer` arm, the only caller of `set_need_resched`), and
/// the outermost guard's drop pays it here. That switch is the timer taking
/// the CPU, so it counts as `Preempted`, as Linux counts a preemption taken
/// on the way out of a syscall in `nivcsw`. Wave 13: it was `task_yield` and
/// counted `Voluntary`, so `DOMAIN_TASKINFO`'s preempted count missed every tick
/// that landed in a lock — vsbench's `drvring-batch8` saw an extra round
/// (65+64 / 64+65) with "preempted 0" on both sides.
pub fn task_preempt_deferred() {
    yield_as(SwitchReason::Preempted);
}

#[inline(always)]
fn yield_as(why: SwitchReason) {
    use azos_sync::preempt_core::VoluntaryAdmission;
    if azos_sync::preempt_core::voluntary_admission(azos_sync::preempt::depth())
        == VoluntaryAdmission::RefuseAtomic
    {
        preempt_audit::bump(&preempt_audit::YIELD_WHILE_ATOMIC);
        return;
    }
    crate::swcensus::yield_enter();

    let sstatus = azos_arch::ARCH.disable_all();

    unsafe { do_schedule(why); }

    azos_arch::ARCH.restore(sstatus);
}

/// Called from the timer interrupt handler (interrupts already disabled by hardware).
///
/// RT tasks: never preempted by timer — only by a strictly higher-priority ready task.
/// Fair tasks: EEVDF (`fairq::tick`). The idle task is switched at every tick.
/// On a hart with RT state (`rt::active`: a band task running, an exhausted
/// band window, or reservations), `rt::tick` charges and may preempt first:
/// band budget, CBS budget, EDF order inside a level.
#[wcet(30_us)]
pub fn schedule() {
    let cpu = current_cpu_id();
    // K-C29: the preemption check is NOT here. It sits at each of the two
    // `do_schedule` sites below, *after* the tick bookkeeping — runtime
    // accounting and the RT band / CBS charge all have to
    // happen whether or not this hart is in
    // a critical section. The deleted F03.4 stub returned from right here and
    // lost all of it; see the deletion note further down this file.
    unsafe {
        let current_idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // K-C6: a lingering Zombie — task_exit() found no ready task and is
        // idling in its own WFI loop, still on its own stack — must not be
        // treated as "the task currently running" here. Crediting a dead
        // task's runtime/deadline stats is wrong, and worse: the RT/time-
        // slice preemption-avoidance branches below can `return` without
        // ever calling do_schedule(), which would permanently starve this
        // CPU of new dispatches once its last task happened to be
        // RT-priority. Treat it exactly like the genuinely-idle
        // (current_idx == MAX) case; do_schedule() frees the Zombie's slot
        // once it finds a real next task to switch to (see its `old.state
        // == TaskState::Zombie` arm).
        let current_idx = if current_idx != usize::MAX
            && task_mut(current_idx).state() == TaskState::Zombie
        {
            usize::MAX
        } else {
            current_idx
        };
        // The tick updates the running task's and this CPU's
        // utilisation (an idle tick, the CPU's alone).
        #[cfg(feature = "energy")]
        energy::on_tick(cpu, current_idx);
        if current_idx != usize::MAX {
            let task = task_mut(current_idx);
            task.total_runtime += 1;

            // Wave 11 SCHED-RT: band budget, CBS budget and EDF order. A
            // hart with none of them pays one per-hart load here.
            if rt::active(cpu) && rt::tick(cpu, current_idx) {
                RT_TICK_PREEMPTS.fetch_add(1, Ordering::Relaxed);
                if tick_admit() { do_schedule(SwitchReason::Preempted); }
                return;
            }

            // Hoisted: same reason as `find_best_cpu`'s `t_prio` — an atomic
            // load is not free for the compiler to CSE across these two uses
            // the way the plain field it replaced was, and this runs on
            // every timer tick on every hart.
            let task_prio = task.priority.load(Ordering::Relaxed);
            if is_rt_priority(task_prio) {
                // RT task: only preempt if a higher-priority task is waiting.
                match cpu_peek_highest_prio(cpu) {
                    Some(ready_prio) if ready_prio < task_prio => {
                        // Higher-priority task ready — preempt.
                    }
                    _ => {
                        return; // No higher-priority task — keep running.
                    }
                }
            } else if fairq::is_fair(task_prio) {
                // Fair task (EEVDF): charged by what it ran; preempted when a
                // queued task now beats it (its slice is used, it is ahead of
                // its share, or a woken task has an earlier deadline).
                if !fairq::tick(cpu, current_idx) {
                    return;
                }
            }
        } else if rt::active(cpu) && rt::tick(cpu, usize::MAX) {
            // Nothing real runs (idle-equivalent): a replenished reservation
            // or a rolled band window is dispatched below like any tick.
            RT_TICK_PREEMPTS.fetch_add(1, Ordering::Relaxed);
        }
        if tick_admit() { do_schedule(SwitchReason::Preempted); }
    }
}

/// K-C29 involuntary-preemption admission for the tick / reschedule-IPI path.
///
/// Returns `true` if this tick may enter `do_schedule`. **Call it after the
/// tick bookkeeping and immediately before the switch** — the accounting is
/// not preemption and must run in a critical section too.
///
/// The `Defer` arm records a debt instead of dropping the tick. The debt is
/// paid by the drop of the outermost `PreemptGuard`, which calls the
/// registered resched callback once interrupts are enabled again.
///
/// The `Switch` arm *clears* the debt: a later tick that actually reached the
/// scheduler has served whatever an earlier deferred tick was owed, and
/// leaving the flag set would make the next guard drop fire a redundant
/// reschedule.
#[inline]
fn tick_admit() -> bool {
    use azos_sync::preempt_core::TickDispatch;
    match azos_sync::preempt_core::tick_dispatch(azos_sync::preempt::depth()) {
        TickDispatch::Defer => {
            azos_sync::preempt::set_need_resched();
            false
        }
        TickDispatch::Switch => {
            azos_sync::preempt::clear_need_resched();
            true
        }
    }
}

/// Ticks on which `rt::tick` asked for a preemption (band or CBS budget, EDF
/// order). Read by the SCHED-RT rows.
pub static RT_TICK_PREEMPTS: AtomicU32 = AtomicU32::new(0);

/// Start the scheduler on the calling CPU (boot CPU).
///
/// Picks the first ready task from this CPU's queue and switches to it.
/// Never returns.
pub fn start() -> ! {
    let cpu = current_cpu_id();
    // K-A12: SSTATUS.SIE is already on by the time start() runs (enabled
    // earlier in boot), so a timer tick firing in the window below would
    // enter schedule() → do_schedule() and mutate this same CPU's ready
    // queue / PER_CPU.current_idx concurrently with the dequeue+dispatch
    // this function is doing inline — corrupting the dispatch, or racing
    // `current_idx` between the dequeue and the assignment below. Not
    // restored here: task_entry_wrapper (the entry point of the task we're
    // about to switch to) unconditionally re-enables SIE.
    //
    // Hence `let _`: the saved-state token is deliberately dropped, and
    // saying so is the point — this function never returns, so a token bound
    // to a name would read like a restore that someone forgot to write.
    let _ = azos_arch::ARCH.disable_all();
    unsafe {
        // Locked: another hart may be racing us via `task_create` (least-
        // loaded assignment can still target a CPU that hasn't called
        // `start()` yet) or, in principle, a very early cross-CPU wake.
        let next_idx = match cpu_dequeue_locked(cpu) {
            Some(idx) => idx,
            None => panic!("sched_start: no tasks for CPU {}", cpu),
        };
        let next = task_mut(next_idx);
        next.set_state(TaskState::Running);
        set_current_task(cpu, next_idx);
        core_started(cpu, next_idx);
        // A band task dispatched first is charged from here (SCHED-RT).
        rt::on_switch(cpu, next_idx);
        // And accrues utilisation from here.
        #[cfg(feature = "energy")]
        energy::on_switch(cpu, usize::MAX, next_idx);

        // Lockdep: the boot context hands over holding nothing.
        azos_sync::lockdep::switch(None, next_idx);
        // QSBR (Kconfig RCU_QSBR, N4): a context switch is a quiescent state.
        azos_sync::qsbr::switch();
        // N12: re-tag `next`'s ASID if a rollover took it; set the flush word.
        crate::asid::prepare_switch(next as *mut Task);
        // Switch to first task (no current task to save).
        context_switch(core::ptr::null_mut(), next as *mut Task);
    }
    unreachable!()
}

// ---- Boot-time offline-hart rescue ----

/// Move every ready task stranded on a hart that failed to start during SMP
/// bring-up onto a hart that actually came up.
///
/// Call exactly once, from the boot hart, strictly *after* `wake_harts()` has
/// returned and [`crate::smp::NUM_ONLINE_CPUS`] has been corrected to the
/// real `online` count, and strictly *before* the boot hart calls
/// [`start()`] (or enables its own timer interrupt). Returns the number of
/// tasks moved.
///
/// # Why this needs no extra synchronization on the *source* side
///
/// `task_create`/`task_create_affinity` calls made earlier in boot (before
/// `wake_harts()`) spread tasks across `0..num_cpus` using the *optimistic*
/// pre-boot `NUM_ONLINE_CPUS` estimate — some may have landed on a hart that
/// then failed `hart_start`. Those per-CPU ready queues
/// (`PER_CPU[online..total]`) are, by construction, never touched by anyone
/// but the boot hart: a hart that failed to start never executes a single
/// instruction, so it can never call `schedule()` / `do_schedule()` or
/// enqueue/dequeue anything on its own queue. That is not a narrow timing
/// window — it holds for as long as the kernel runs.
///
/// # Why the *destination* side still goes through the locked wrappers
///
/// A hart that *did* start runs `secondary_main()` immediately and
/// independently of how far the boot hart has gotten through the rest of
/// `kernel_main` — it enables its own local timer right there and will call
/// `schedule()` on its first tick, which can land before the boot hart
/// reaches `start()`. So, unlike the source side, a lock-free enqueue onto
/// an *alive* CPU's queue here would not be provably race-free without also
/// reasoning about exactly how much boot-time code runs in between. Rather
/// than depend on that, every queue touch below — source and destination —
/// goes through `cpu_dequeue_locked` / `cpu_enqueue_locked` (never the raw
/// `cpu_dequeue`/`cpu_enqueue`), same as every other cross-CPU path in this
/// file. The extra lock cost is negligible: boot-time only, at most
/// `MAX_TASKS` operations total.
///
/// # Algorithm
///
/// For each dead hart `online..total`, repeatedly dequeue its
/// highest-priority ready task (this drains every priority level, via the
/// same bitmap dequeue used everywhere else) and hand it to
/// [`find_best_cpu`] — the same priority-aware balancer `task_create`
/// uses, not a bitmap popcount. It is naturally bounded to
/// `0..online` because the caller has already corrected `NUM_ONLINE_CPUS`
/// before calling this function.
///
/// Both the task's saved `tp` (`context.tp`, the CPU it is queued for: the
/// wake and balance paths read it as the task's home; `context_switch` saves
/// it and never loads it into the hart's `tp`, see its field doc) and, if the
/// task was pinned (`cpu_affinity >= 0`), its affinity are rewritten to the
/// new CPU. Skipping this would leave a moved task, once it blocks and is
/// later woken, placed by a dead hart's id (`try_wake_task` / `wq_wake_by_tid`
/// route pinned tasks straight back to `cpu_affinity`): silently re-stranded
/// on the dead hart.
/// Breaking an explicit pin is a decision the operator must see, so it is
/// logged per task.
///
/// No work-stealing is added at runtime — this is a one-shot rescue that
/// only ever runs during this boot-time window.
pub fn rebalance_from_offline_cpus(online: usize, _total: usize) -> usize {
    // **Sweep up to `nr_cpu_ids`, not up to the DTB count.** (Every CPU
    // below it has a queue; a pin past it was cut to it at creation.)
    //
    // This function used to take `total` (the harts the DTB said exist) and
    // drained only `online..total`. That looks reasonable and strands tasks:
    // several are created with **explicit affinity** to a specific hart, and
    // that affinity is not bounded by the DTB count. With `-smp 1`, `total` is
    // 1 and the loop `for dead_cpu in 1..1` never runs a single iteration --
    // while the queues of CPUs 1, 2 and 3 have tasks in them.
    //
    // Measured before this change, with `-smp 1`: `per_cpu_queues = [0, 3, 1, 2]`.
    // Six tasks, `autorun` among them, queued on harts that do not exist.
    // The result is that **the user program never starts** with the kernel
    // apparently healthy: the loops keep running, the daemons talk, and the
    // ring-3 ELF executes not one instruction.
    //
    // Every queue above `online` must be drained, whether the task got there
    // by load balancing or by an explicit pin. `total` is kept in the
    // signature for caller compatibility and is deliberately unused.
    let total = ncpu();
    if online == 0 || online >= total {
        return 0; // Nothing offline, or nothing online to rescue onto.
    }

    let mut moved = 0usize;
    let mut moved_per_dead = [0usize; MAX_CPUS];

    unsafe {
        for dead_cpu in online..total {
            loop {
                let idx = match cpu_dequeue_locked(dead_cpu) {
                    Some(idx) => idx,
                    None => break, // This dead hart's queue is fully drained.
                };

                let task = task_mut(idx);
                let target_cpu = find_best_cpu(task.priority.load(Ordering::Relaxed), idx);

                if task.cpu_affinity >= 0 {
                    // Pinned task stranded on a hart that never came up —
                    // the pin cannot be honored without leaving it stuck
                    // forever, so move it anyway and make that visible.
                    let len = task.name.iter().position(|&b| b == 0).unwrap_or(TASK_NAME_MAX_LEN);
                    let name = core::str::from_utf8(&task.name[..len]).unwrap_or("<?>");
                    azos_drv_sys::kwarn!(
                        "[SMP] task '{}' (tid {}) was pinned to dead hart {} — \
                         reassigning to hart {} (affinity broken: hart never started)",
                        name, task.tid, dead_cpu, target_cpu
                    );
                    task.cpu_affinity = target_cpu as i8;
                }

                // Keep the saved tp consistent with the queue the task now
                // lives on: the wake and balance paths read it as the task's
                // home (context_switch never loads it into the hart's tp).
                task.context.tp = target_cpu as CtxReg;
                hist_reaccount(idx);

                // K-C26 discriminator 2: the task is already `Ready`; a
                // refusal here strands it in no queue. Counted, not ignored.
                task.ready_site.store(
                    crate::task::ready_site::REBALANCE | ((target_cpu as u8) << 4),
                    Ordering::Relaxed,
                );
                if !cpu_enqueue_locked(target_cpu, idx) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                moved_per_dead[dead_cpu] += 1;
                moved += 1;
            }
        }
    }

    if moved > 0 {
        for dead_cpu in online..total {
            if moved_per_dead[dead_cpu] > 0 {
                azos_drv_sys::kprintln!(
                    "[SMP] rebalanced {} boot task(s) off dead hart {}",
                    moved_per_dead[dead_cpu], dead_cpu
                );
            }
        }
        azos_drv_sys::kprintln!(
            "[SMP] rebalance summary: {} task(s) moved off {} dead hart(s) onto {} online hart(s)",
            moved, total - online, online
        );
    }

    moved
}

/// CPU hotplug (Kconfig `CPU_HOTPLUG`): how many tasks other than `cpu`'s own
/// idle task are pinned to it. A pin is a decision the operator or a
/// reservation made; moving the task would break it, so a hotplug request is
/// refused while there is one (`hart_set::HotplugReason::Pinned`). Read
/// unlocked, like `fairq::rt_cpu`: a pin that appears after the answer is caught
/// by [`migrate_off_cpu`].
pub(crate) fn pinned_to(cpu: usize) -> u32 {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        // SAFETY: a static table of atomics, read.
        if !unsafe { TASK_VALID[idx].load(Ordering::Relaxed) } {
            continue;
        }
        // SAFETY: a valid slot; the fields read are plain words a stale read of
        // only makes this count off by a task that is being created or freed.
        let t = unsafe { task_ref(idx) };
        if t.cpu_affinity == cpu as i8
            && t.priority.load(Ordering::Relaxed) != crate::task::IDLE_PRIORITY
            && !matches!(t.state(), TaskState::Zombie | TaskState::Invalid)
        {
            n += 1;
        }
    }
    n
}

/// CPU hotplug: does `cpu` hold real-time state now (`fairq::rt_cpu`: a band
/// task running or queued, an admitted reservation)? Read unlocked.
pub(crate) fn cpu_has_rt_state(cpu: usize) -> bool {
    // SAFETY: reads the CPU's scheduling state, as the balancer does.
    cpu < MAX_CPUS && unsafe { fairq::rt_cpu(cpu) }
}

/// CPU hotplug: the CPUs of `isolcpus` (bit n = CPU n).
pub(crate) fn isolated_cpu_mask() -> u64 {
    fairq::isolated_cpus()
}

/// The profiler (Kconfig `PROFILER_PMU`): is `cpu` a real-time CPU now, one
/// of `isolcpus` or one holding real-time state ([`cpu_has_rt_state`])? Its
/// overflow sampling is refused and its tick samples only the PC. Read
/// unlocked, from the CPU's own tick and PMU interrupt.
pub fn cpu_is_real_time(cpu: usize) -> bool {
    (cpu < 64 && isolated_cpu_mask() >> cpu & 1 != 0) || cpu_has_rt_state(cpu)
}

/// CPU hotplug: move every ready task of `cpu`'s queue to another CPU, so the
/// CPU can stop. Returns the number moved, or `Err(moved)` when it found a task
/// pinned there (other than the CPU's own idle task): that task and the ones
/// behind it stay on the queue, the CPU stays online, and the tasks already
/// moved stay where they went.
///
/// Runs on `cpu` itself (its idle task, interrupts masked, the online prefix
/// already cut to exclude it), or on another CPU once `cpu` has stopped (the
/// rescue drain of a task that was queued onto it in the window): every touch
/// of the queue goes through the locked wrappers either way, as
/// [`rebalance_from_offline_cpus`] does for the harts that never came up.
/// Each task goes where [`find_best_cpu`] puts a new one, which looks only at
/// the online prefix, so none lands on `cpu`; its saved `tp` follows (the
/// task's home for its next wake; `context_switch` never loads it).
///
/// The decision for each entry is `hart_set::disposition`. The CPU's own idle
/// task (pinned, lowest priority) is put back: it is the task `cpu` runs when it
/// comes back, or is running now.
///
/// # Safety
/// `cpu` is a real CPU and not in `0..NUM_ONLINE_CPUS`.
pub(crate) unsafe fn migrate_off_cpu(cpu: usize) -> Result<usize, usize> {
    use crate::smp::hart_set::{disposition, Disposition};
    let mut moved = 0usize;
    // The idle tasks found: put back after the drain (a dequeue pops the
    // highest priority first, so they come last).
    let mut idle = [usize::MAX; 4];
    let mut n_idle = 0;
    let mut pinned_stop = false;
    unsafe {
        while let Some(idx) = cpu_dequeue_locked(cpu) {
            let task = task_mut(idx);
            let is_idle = task.priority.load(Ordering::Relaxed) == crate::task::IDLE_PRIORITY;
            let pinned = task.cpu_affinity >= 0;
            match disposition(is_idle, pinned) {
                Disposition::KeepIdle => {
                    if n_idle < idle.len() {
                        idle[n_idle] = idx;
                        n_idle += 1;
                    } else {
                        // More idle-class tasks than the model has: leave this one
                        // where it is rather than lose it.
                        let _ = cpu_enqueue_locked(cpu, idx);
                        break;
                    }
                }
                Disposition::Pinned => {
                    // Back on its queue, and the drain ends: the change is undone.
                    let _ = cpu_enqueue_locked(cpu, idx);
                    pinned_stop = true;
                    break;
                }
                Disposition::Move => {
                    let target = find_best_cpu(task.priority.load(Ordering::Relaxed), idx);
                    task.context.tp = target as CtxReg;
                    hist_reaccount(idx);
                    task.ready_site.store(
                        crate::task::ready_site::REBALANCE | ((target as u8) << 4),
                        Ordering::Relaxed,
                    );
                    if !cpu_enqueue_locked(target, idx) {
                        SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                    }
                    moved += 1;
                }
            }
        }
        for &idx in idle.iter().take(n_idle) {
            let _ = cpu_enqueue_locked(cpu, idx);
        }
    }
    if pinned_stop { Err(moved) } else { Ok(moved) }
}

/// CPU hotplug: move the timer sleepers of `from`'s heap to `to`'s
/// (`timer_sleepers::migrate_off`), part of taking `from` offline. Returns how
/// many moved; the caller rings `to`. Without `sched-timer-heap` there is no
/// per-CPU timer heap, so there is nothing to move and no function.
#[cfg(feature = "sched-timer-heap")]
pub(crate) fn migrate_timers_off_cpu(from: usize, to: usize) -> usize {
    timer_sleepers::migrate_off(from, to)
}

/// Parent of each pool slot, for `wait`. 0 = no parent.
///
/// **Deliberately outside `Task`.** Adding a field to `Task` shifts the offset
/// of `satp` (`TASK_SATP_OFFSET`, `task.rs`) that `context_switch.S` is fed
/// via `offset_of!` — not hand-copied, but still layout-frozen: a
/// compile-time assertion checks it and the build refuses. Touching the
/// context-switch assembly's injection site to hang a `u32` off it is not
/// worth the risk, so the relation lives here, indexed by slot.
pub(super) static PARENT_TID: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];

/// U04-2 route (b). `true` from the earliest instant of
/// `task_exit_with_code` — BEFORE `note_exit`, the driver-crash notice,
/// and above all before the registered
/// [`TASK_EXIT_HOOK`] (`azos_ipc::task_release_all`) run — until the
/// slot is freed and reused.
///
/// **Why this exists: `tid_exists` alone is not "safe to target".** The
/// caps/ipc front's `sched_seam::tid_exists`
/// is `idx_for_tid(tid).is_some()`, which stays `true` for the entire
/// teardown window — `TASK_VALID` and the tid are not cleared until
/// `do_schedule()` frees the slot, long after `task_release_all` has run.
/// A `fast_ipc_call`/`fast_ipc_accept` on another hart that checks only
/// `tid_exists` can start a NEW interaction with a tid whose capabilities
/// `cap_store::reset` is concurrently revoking — a race between "does a
/// slot exist" and "is anyone allowed to newly rely on it". Publishing
/// this flag first gives the ipc side a cheap second check
/// (`tid_is_exiting`) to refuse that window instead of racing it.
///
/// **Deliberately OUTSIDE `Task`, like [`PARENT_TID`].** Adding a field to
/// `Task` shifts `TASK_SATP_OFFSET`, layout-frozen by a compile-time
/// assertion even though `context_switch.S` gets it via `offset_of!`
/// rather than a hand-copied number. Indexed by slot for the same reason
/// `PARENT_TID` is.
///
/// **A plain `Release` store, not a compare-exchange, is the right
/// primitive.** Exactly one hart — the task exiting itself — ever writes
/// its own slot's entry `true` (and only `alloc_slot`, under
/// `POOL_LOCK`, ever writes it back to `false`), so there is no writer
/// race to arbitrate; a CAS here would cost more and prove nothing a
/// `Release` store does not already give a `tid_is_exiting` reader
/// paired with `Acquire`.
pub(super) static TASK_EXITING: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// The code the task in this slot is exiting with, stored by
/// [`task_exit_with_code`] before the exit hook runs, so the hook (a
/// `fn(u32)`) can tell a clean `exit(0)` from a failure: the supervisor
/// restarts a driver only on the second (owner decision
/// 2026-09-28). Written only by the exiting task, for its own slot.
static TASK_EXIT_CODE: [core::sync::atomic::AtomicI32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicI32::new(0) }; MAX_TASKS];

/// The exit code of the CURRENT task, for the exit hook it runs.
/// Meaningful only from inside that hook (before, it is a stale value).
pub fn current_exit_code() -> i32 {
    let idx = my_idx();
    if idx >= MAX_TASKS { return 0; }
    TASK_EXIT_CODE[idx].load(Ordering::Relaxed)
}

/// [`idx_for_tid`] for a task that is not mid-exit (`TASK_EXITING`): the
/// PI futex owner lookup (owner decision 10-10) never resolves an exiting
/// slot, so a locker cannot make a dying task a word's owner after its
/// exit's handover ran.
pub fn live_idx_for_tid(tid: u32) -> Option<usize> {
    idx_for_tid(tid).filter(|&i| !TASK_EXITING[i].load(Ordering::Acquire))
}

/// Is `tid` mid-exit (or already fully gone)? `false` for a tid with no
/// valid slot at all (nothing to be mid-exit FROM) as well as for one
/// whose slot exists but has not started exiting — i.e. `true` is the
/// answer callers should treat as "do not start a new interaction with
/// this tid", and `false` alone is not yet a promise the tid is alive
/// (pair with `idx_for_tid`/`tid_exists` for that).
/// [`tid_is_exiting`] for a slot the caller already resolved (Chain E): the
/// fast-IPC call has `idx_for_tid(server)` in hand, and asking by TID again
/// repeated the lookup on every call (~30 instructions).
#[inline]
pub fn slot_is_exiting(idx: usize) -> bool {
    idx < MAX_TASKS && TASK_EXITING[idx].load(Ordering::Acquire)
}

pub fn tid_is_exiting(tid: u32) -> bool {
    match idx_for_tid(tid) {
        Some(idx) => TASK_EXITING[idx].load(Ordering::Acquire),
        None => false,
    }
}

/// Exit notices waiting to be reaped: `(parent, child, code)`.
///
/// **Decoupled from the zombie's slot, and that is the design, not a
/// shortcut.** A POSIX `wait` keeps the child's slot alive until the parent
/// reaps it; here `do_schedule` frees them as soon as it switches, and
/// changing that means touching task lifetime — exactly where K-C6 and K-C26
/// lived. The notice outlives the slot, so the parent finds out without
/// anything in the scheduler changing.
///
/// **Kept until reaped, as Linux keeps zombies** (wave 12, EXIT2). One entry
/// per task slot, and the creation of a child with a parent is refused while
/// the queued notices could use up the slots still free
/// (`exit_note::admits`, under `POOL_LOCK`): the notice a child leaves holds
/// the place its slot would have held. So the table never fills with live
/// parents' notices and none is dropped; a parent that never waits makes its
/// own `fork`/`spawn` fail instead. A parent's exit releases its notices
/// (`exit_note::purge_parent` in [`note_exit`]). Until wave 12 this was a
/// 32-entry Kconfig table (`SCHED_EXIT_NOTES`) that evicted the oldest live
/// notice when full.
const EXIT_NOTES: usize = MAX_TASKS;
static EXIT_NOTE: azos_sync::SpinLock<[(u32, u32, i32); EXIT_NOTES]> =
    azos_sync::SpinLock::new([(0, 0, 0); EXIT_NOTES]);
/// Entries of [`EXIT_NOTE`] in use. Written only under its lock; read
/// without it by the creation admission and to skip the scans when 0.
static EXIT_NOTICES_QUEUED: AtomicU32 = AtomicU32::new(0);
/// Notices `exit_note::insert` could not place. Zero unless the admission is
/// broken: the table is sized so it cannot fill (`DOMAIN_EXIT_STATS`).
pub static EXIT_NOTICE_DROPS: AtomicU32 = AtomicU32::new(0);
/// Creations of a child refused because queued notices hold the slots that
/// were free (`DOMAIN_EXIT_STATS`).
pub static EXIT_NOTICE_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// Pure `EXIT_NOTE` insertion/orphan-eviction logic, in its own file only
/// so the host test runner (`tests/host/sched-wake-tests`) can compile it —
/// the rest of this module cannot leave the target. Same pattern as
/// `process::elf_bounds` / `smp::hart_set`.
#[path = "../exit_note.rs"]
pub mod exit_note;

/// Wave 13 (orphans): the slot's task is a child subreaper — Linux's
/// `PR_SET_CHILD_SUBREAPER` — so orphaned descendants are re-parented to it
/// rather than to [`INIT_TID`]. Written only by the task itself
/// ([`task_subreaper`]); cleared when its slot is claimed.
pub(super) static SUBREAPER: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// Wave 13 (orphans): the reaper of last resort, Linux's init — the task the
/// autorun row's image runs as (`set_init_tid`, called by the kernel's
/// autorun loader at its exec; a supervised successor sets its own). 0: none,
/// and an orphan with no subreaper ancestor is left with no parent.
static INIT_TID: AtomicU32 = AtomicU32::new(0);

/// Make `tid` the reaper of last resort ([`INIT_TID`]).
pub fn set_init_tid(tid: u32) {
    INIT_TID.store(tid, Ordering::Release);
}

/// The reaper of last resort, 0 for none.
pub fn init_tid() -> u32 {
    INIT_TID.load(Ordering::Acquire)
}

/// `DOMAIN_SUBREAPER` / Linux `prctl(PR_{SET,GET}_CHILD_SUBREAPER)` for the
/// current task: `Some(on)` sets or clears the mark, `None` only reads it.
/// Returns the mark afterwards; `false` for a context with no task.
pub fn task_subreaper(set: Option<bool>) -> bool {
    let idx = my_idx();
    if idx >= MAX_TASKS {
        return false;
    }
    // Wave 13: the mark is the process's (its group leader's slot), as on
    // Linux, whichever thread sets it: a process's children name the leader.
    let idx = proc_slot(idx);
    if let Some(on) = set {
        // `subreaper-mark-canary`: the mark is never set (the shell's
        // orphan rows must go red: its jobs' orphans get no parent).
        let on = on && !cfg!(feature = "subreaper-mark-canary");
        SUBREAPER[idx].store(on, Ordering::Release);
    }
    SUBREAPER[idx].load(Ordering::Acquire)
}

/// Who adopts the children of the task in `idx` (TID `dying`), which is
/// exiting: `exit_note::reaper_for` over the live slots. Called under
/// `EXIT_NOTE`, which serialises every exiting task's re-parenting.
fn reaper_of(idx: usize, dying: u32) -> u32 {
    let look = |tid: u32| {
        let i = idx_for_tid(tid)?;
        Some(exit_note::Ancestor {
            parent: PARENT_TID[i].load(Ordering::Relaxed),
            subreaper: SUBREAPER[i].load(Ordering::Acquire),
            can_adopt: !TASK_EXITING[i].load(Ordering::Acquire),
        })
    };
    exit_note::reaper_for(
        dying,
        PARENT_TID[idx].load(Ordering::Relaxed),
        INIT_TID.load(Ordering::Acquire),
        look,
        stop_policy::MAX_ANCESTRY,
    )
}

/// Wave 13 (orphans): the slot's task, now exiting, will re-parent its
/// children in [`note_exit`]: it ran a user address space and the canary is
/// off. Written by the exiting task just before it publishes
/// [`TASK_EXITING`] (so a reader that sees the latter sees this); only a
/// user task's children are re-parented. A kernel task's children — the
/// ring-3 drivers and the user shell the boot launcher starts, the
/// supervisor's successors — are the kernel's, as Linux's kthreadd children
/// are, and keep the link they had.
pub(super) static EXIT_REPARENTS: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// Wake `tid` if it is parked waiting for a child's exit notice.
fn wake_child_waiter(tid: u32) {
    // A parent parked in `LOG_CONSOLE_WAIT` is waiting for exactly
    // this. One load when nobody waits; the wake stamps a parent that has
    // not blocked yet, and its loop re-tests `has_exit_note`.
    if let Some(pidx) = idx_for_tid(tid) {
        if WAITS_CHILD[pidx].load(Ordering::Acquire) {
            wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_)));
        }
    }
}

/// Records that the task in `idx` finished with `code`.
pub fn note_exit(idx: usize, code: i32) {
    if idx >= MAX_TASKS { return; }
    let (child, still_mapped) = unsafe {
        let t = task_ref(idx);
        (t.tid, t.user_pt != 0)
    };
    // Called by the exiting task for its own slot, after
    // `release_address_space_at_exit` zeroed `user_pt`: a table still here
    // means the notice is going out ahead of the teardown.
    if still_mapped {
        EARLY_EXIT_NOTICES.fetch_add(1, Ordering::Relaxed);
    }
    // **The lock is taken BEFORE the parent link is cleared, and that ordering
    // is the fix for a real race.** The clear used to happen first, leaving a
    // window in which the link said "no parent" and no notice existed yet.
    // `take_exit_note_for` reads both, and in that window it concluded the
    // caller was not the child's parent — answering `ECHILD`, "this will never
    // resolve", for a child that was in the middle of exiting.
    //
    // Measured, not reasoned: `userspace/bench/vsbench`'s life-cycle lane hit it on
    // the FIRST poll in 2 of 40 iterations, needing the child to exit on
    // another hart at exactly that instant. `DOMAIN_WAIT` never saw it because it
    // does not consult the parent link at all.
    //
    // Holding `EXIT_NOTE` across both makes the transition atomic against
    // `take_exit_note_for`, which does its own parent-link check under the
    // same lock.
    let mut t = EXIT_NOTE.lock();
    // Wave 13 (orphans, Linux's model): this task's children go to the
    // nearest live ancestor marked a child subreaper, else to init
    // (`reaper_of`), and the notices of its children that exited unreaped go
    // with them. With nobody to adopt them they are left with no parent and
    // the notices are dropped, as wave 12 dropped them all: nothing would
    // ever reap them (TIDs are never reused). Under this lock, which every
    // exit takes: after it no live task names this one as its parent, so a
    // child that still reads this task in its link (below, under the same
    // lock) does so before this point, and its notice is moved here.
    // A kernel task's children, and `orphan-reparent-canary`, keep wave 12's
    // purge with no re-link (`EXIT_REPARENTS`).
    let reparent = EXIT_REPARENTS[idx].load(Ordering::Relaxed);
    let reaper = if reparent { reaper_of(idx, child) } else { 0 };
    if reparent {
        for i in 0..MAX_TASKS {
            if i != idx && tid_for_idx(i).is_some() && PARENT_TID[i].load(Ordering::Relaxed) == child {
                PARENT_TID[i].store(reaper, Ordering::Relaxed);
                view_note(i);
                #[cfg(feature = "orphan-late-adopter-canary")]
                LATE_ADOPTER_TID.store(child, Ordering::Relaxed);
            }
        }
    }
    let mut adopted = 0;
    if EXIT_NOTICES_QUEUED.load(Ordering::Relaxed) != 0 {
        adopted = exit_note::readdress(&mut *t, child, reaper);
        if adopted == 0 {
            let purged = exit_note::purge_parent(&mut *t, child);
            if purged > 0 {
                EXIT_NOTICES_QUEUED.fetch_sub(purged as u32, Ordering::Release);
            }
        }
    }
    let parent = PARENT_TID[idx].swap(0, Ordering::Relaxed);
    // Wave 13: how the child ended (a signal, for a Linux parent's `wait4`),
    // recorded BEFORE its notice can be taken: a parent polling `wait4` on
    // another hart takes the notice the instant it is queued below.
    if azos_limits::LINUX_ABI {
        signal::note_child_end(idx, child, parent);
    }
    // U02-6 fix. `PARENT_TID` used to be cleared only when the CHILD
    // exits — nothing ran when the PARENT died — so every child of a
    // parent that already exited (its slot freed, its TID permanently
    // retired: TIDs are never reused, see `NEXT_TID`'s doc) queued a
    // notice addressed to a TID no `wait`/`waitpid` will ever present
    // again, and once 32 such orphans accumulated the FIFO eviction in
    // `exit_note::insert` started discarding a LIVE parent's real notice
    // instead. `exit_note::should_queue`/`insert` hold the fixed
    // decision logic (host-tested in `sched-wake-tests`); `idx_for_tid`
    // — the same O(1)-on-hint-hit lookup every wake path already uses —
    // is the `is_alive` predicate, so the common case (parent alive)
    // costs nothing extra.
    // A parent mid-exit that re-parents (`EXIT_REPARENTS`) has not done so
    // yet, or this task would no longer name it: it will move this notice
    // to its reaper, so it counts as alive. One that does not re-parent
    // counts as gone, as in wave 12: its purge may already have run.
    let parent_alive = |tid: u32| match idx_for_tid(tid) {
        Some(p) => !TASK_EXITING[p].load(Ordering::Acquire) || EXIT_REPARENTS[p].load(Ordering::Relaxed),
        None => false,
    };
    let queued = exit_note::should_queue(parent, parent_alive);
    if queued {
        match exit_note::insert(&mut *t, (parent, child, code), parent_alive) {
            exit_note::Placed::Empty => {
                EXIT_NOTICES_QUEUED.fetch_add(1, Ordering::Release);
            }
            exit_note::Placed::Orphan => {}
            exit_note::Placed::Full => {
                EXIT_NOTICE_DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    drop(t);
    if queued {
        wake_child_waiter(parent);
    }
    if adopted > 0 {
        wake_child_waiter(reaper);
    }
    // Wave 13: `SIGCHLD` to a Linux parent (a native parent has no signal
    // state: `NotLinux`, nothing done). Discarded unless it set a handler.
    if azos_limits::LINUX_ABI && !cfg!(feature = "linux-sigchld-canary") {
        let _ = signal::post(parent, 17, child);
    }
}

/// Take the exit notice for ONE named child of `parent_tid`.
///
/// The targeted form of [`take_exit_note`]. Returns `Some((child_tid, code))`
/// when that child has finished and its notice is still queued;
/// [`WaitpidMiss::NotYet`] when `child_tid` is a live child of this parent, and
/// [`WaitpidMiss::NotOurs`] otherwise.
///
/// # Why the two misses are different answers
///
/// `take_exit_note` cannot express either. It returns the FIRST notice for the
/// parent, so a task with several children learns that *a* child died and never
/// which — and a caller waiting for one particular child must consume, and
/// discard, notices belonging to its siblings. `userspace/bench/vsbench`'s life-cycle
/// lane had to do exactly that, and its first version treated a sibling's
/// notice as an error and failed on a real boot.
///
/// Collapsing the two misses into one would put the caller back in that
/// position: "not finished yet" is a reason to poll again, and "not your child"
/// never becomes true however long you wait.
///
/// # How a live child is distinguished from a stranger
///
/// `PARENT_TID[idx]` holds the parent while the child lives and is cleared by
/// `note_exit` on the way out, so after a successful reap the same query
/// answers `NotOurs` — which is correct: the notice is spent and the child is
/// gone. That also makes a second reap of one child indistinguishable from a
/// TID that was never ours, deliberately: neither is ever going to produce a
/// notice, and telling them apart would need a record of dead children that
/// nothing here keeps.
pub fn take_exit_note_for(parent_tid: u32, child_tid: u32) -> Result<(u32, i32), WaitpidMiss> {
    // Both reads under ONE hold of `EXIT_NOTE`. Releasing between them left a
    // window in which `note_exit` had cleared the parent link and not yet
    // published the notice, so a child in the middle of exiting read as "not
    // yours" — see `note_exit`, which now clears the link under this same lock.
    let mut t = EXIT_NOTE.lock();
    for e in t.iter_mut() {
        if e.0 == parent_tid && e.1 == child_tid {
            let r = (e.1, e.2);
            *e = (0, 0, 0);
            EXIT_NOTICES_QUEUED.fetch_sub(1, Ordering::Release);
            #[cfg(feature = "orphan-late-adopter-canary")]
            {
                drop(t);
                late_adopter_delay(child_tid);
            }
            return Ok(r);
        }
    }
    // No notice. Is it a child of ours that simply has not exited?
    match idx_for_tid(child_tid) {
        Some(idx) if PARENT_TID[idx].load(Ordering::Relaxed) == parent_tid => {
            Err(WaitpidMiss::NotYet)
        }
        _ => Err(WaitpidMiss::NotOurs),
    }
}

/// Why [`take_exit_note_for`] found no notice.
/// Gate canary (`orphan-late-adopter-canary`): the last task whose exit
/// re-parented a child of its own.
#[cfg(feature = "orphan-late-adopter-canary")]
static LATE_ADOPTER_TID: AtomicU32 = AtomicU32::new(0);

/// Gate canary: the reap of that task returns 1.5 s late, as on a loaded
/// host, so its orphan's adopter lists it late.
#[cfg(feature = "orphan-late-adopter-canary")]
fn late_adopter_delay(child_tid: u32) {
    if child_tid == 0 || LATE_ADOPTER_TID.compare_exchange(child_tid, 0, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return;
    }
    let until = azos_drv_sys::timebase::now()
        .saturating_add(azos_drv_sys::timebase::TIMER_FREQ * 3 / 2);
    while azos_drv_sys::timebase::now() < until {
        crate::task_block(WaitReason::Timer(until));
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitpidMiss {
    /// A live child of this parent that has not exited. Poll again.
    NotYet,
    /// Not a child of this parent, or already reaped. Polling will not help.
    NotOurs,
}

/// Take an exit notice for `parent_tid`. Returns the child's TID, or `None`
/// if none has finished.
///
/// **`WNOHANG` semantics, not POSIX `wait`**: it does not block. Blocking
/// would need a wait queue and a wake of the parent from the exit path, and
/// that *does* touch the scheduler. The caller polls, which is what it already
/// does with `recv`.
pub fn take_exit_note(parent_tid: u32) -> Option<(u32, i32)> {
    if parent_tid == 0 || EXIT_NOTICES_QUEUED.load(Ordering::Acquire) == 0 {
        return None;
    }
    let mut t = EXIT_NOTE.lock();
    for e in t.iter_mut() {
        if e.0 == parent_tid {
            let r = (e.1, e.2);
            *e = (0, 0, 0);
            EXIT_NOTICES_QUEUED.fetch_sub(1, Ordering::Release);
            return Some(r);
        }
    }
    None
}

// ── Child-exit waits and stop requests ─────────────────────────────────────
//
// Per slot, beside `PARENT_TID` and for the same reason (not in `Task`, whose
// layout is frozen). Each entry that names a task carries the task's TID, so
// a slot reused by another task never inherits a stale request: no clearing
// on creation is needed, a mismatch reads as "none".

/// Slots whose task blocks in `LOG_CONSOLE_WAIT` and wants a child's exit
/// notice to wake it ([`note_exit`]).
static WAITS_CHILD: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];
/// The TID a pending stop request in [`STOP_WORD`] is for; 0 = none.
static STOP_TID: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// The pending stop request (`stop_policy::Stop::encode`).
static STOP_WORD: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// The TID of a child spawned with `SPAWN_F_DIE_WITH_PARENT` in this slot;
/// 0 = none.
static DWP_TID: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// Forced stops issued that have not ended their task yet, machine-wide:
/// what the timer tick from user mode tests before looking at its own slot.
/// Changed only through `stop_policy::forced_*` on [`FORCED_ACCT`], so it is
/// always the number of slots whose word is `counted`.
pub(super) static FORCED_PENDING: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Per slot: the forced-stop accounting word (`stop_policy::forced_count`).
pub(super) static FORCED_ACCT: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(stop_policy::ACCT_NONE) }; MAX_TASKS];

/// The pure half: the ancestor relation and the request word.
#[path = "../stop_policy.rs"]
pub mod stop_policy;

/// Wave 13: the per-task signal words of Linux tasks.
#[path = "../signal_state.rs"]
pub mod signal;

/// The slot of the task running here, `None` when none is: [`my_idx`] with
/// the bounds test callers want. The slot is the task's own, so it stays
/// valid after a migration.
#[inline(always)]
pub(crate) fn current_slot() -> Option<usize> {
    let idx = my_idx();
    (idx < MAX_TASKS).then_some(idx)
}

/// The current task does (or no longer does) want a child's exit notice to
/// wake it.
pub fn set_current_waits_child(on: bool) {
    if let Some(idx) = current_slot() {
        WAITS_CHILD[idx].store(on, Ordering::Release);
    }
}

/// Is an exit notice queued for `parent_tid`? Does not take it.
pub fn has_exit_note(parent_tid: u32) -> bool {
    parent_tid != 0
        && EXIT_NOTICES_QUEUED.load(Ordering::Acquire) != 0
        && EXIT_NOTE.lock().iter().any(|e| e.0 == parent_tid)
}

/// Has `parent` a child it could still reap: a live one, or an exit notice
/// not taken yet? What a Linux `wait4(-1)` needs to tell `ECHILD` from "not
/// yet"; the native waits answer `-1` for both.
pub fn has_reapable_child(parent: u32) -> bool {
    if parent == 0 {
        return false;
    }
    if has_exit_note(parent) {
        return true;
    }
    (0..MAX_TASKS).any(|idx| {
        tid_for_idx(idx).is_some() && PARENT_TID[idx].load(Ordering::Relaxed) == parent
    })
}

/// The parent of live task `tid`, 0 when it has none or is gone.
pub fn parent_of_tid(tid: u32) -> u32 {
    match idx_for_tid(tid) {
        Some(idx) => PARENT_TID[idx].load(Ordering::Relaxed),
        None => 0,
    }
}

/// Is `caller` an ancestor of live task `target` (at most
/// `stop_policy::MAX_ANCESTRY` steps up)?
pub fn task_is_ancestor(caller: u32, target: u32) -> bool {
    stop_policy::is_ancestor(caller, target, parent_of_tid, stop_policy::MAX_ANCESTRY)
}

/// The live descendants of `root` (within the ancestry bound), into `out`.
/// Returns how many were found (it may exceed `out.len()`; only that many are
/// written). A bounded scan of the task table.
pub fn descendants_of(root: u32, out: &mut [u32]) -> usize {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        let Some(tid) = tid_for_idx(idx) else { continue };
        if task_is_ancestor(root, tid) {
            if n < out.len() {
                out[n] = tid;
            }
            n += 1;
        }
    }
    n
}

/// Ask live task `tid` to stop (`force`: end it), with `signo`. Wakes any
/// `Timer` wait it is parked in (the console, pipe and sleep waits), so a
/// blocked target sees `-EINTR` or dies at the wake. A forced stop also
/// empties the target's syscall filter: its next syscall is refused, and the
/// refusal path (`seccomp_deny_kill`) ends it with `128 + signo` — the exit
/// path a user-mode fault takes, at a syscall boundary, never inside a
/// syscall. Returns `false` for a TID with no live task.
pub fn task_stop(tid: u32, force: bool, signo: u8) -> bool {
    let Some(idx) = idx_for_tid(tid) else { return false };
    // Wave 13: a Linux task is asked by its signal, not by the sticky stop
    // word: its handler (or default action) answers it, and a task that
    // handles `SIGINT` (an interactive shell) must not find every later
    // wait interrupted. A forced stop stays the forced path for both ABIs.
    // A request to a thread of a Linux process is its process's signal,
    // posted once: a subtree stop names the process and each of its threads,
    // and only the process (its leader) posts.
    if !force && azos_limits::LINUX_ABI {
        let p = crate::group::proc_tid(tid);
        if p != tid && signal::post(p, signo as u32, 0) != signal::Posted::NotLinux {
            return true;
        }
        match signal::post(tid, signo as u32, current_proc_tid()) {
            signal::Posted::NotLinux => {}
            _ => return true,
        }
    }
    record_stop(idx, tid, stop_policy::Stop { force, signo });
    wake_stopped(tid, force);
    true
}

/// Wake a task just asked to stop. A request wakes the `Timer` waits that
/// answer `-EINTR` (the console, pipe and sleep waits). A forced stop wakes
/// it out of ANY wait (plan item 7): every wait a task makes in its own
/// syscall blocks through `wait::task_block_killable`, which refuses to block
/// again once the stop is pending, so the task returns and ends; woken from a
/// `Timer` wait only, a task parked on a port or a fast-IPC exchange
/// stayed parked, and its exit hook, which releases everything it held, never
/// ran.
fn wake_stopped(tid: u32, force: bool) {
    #[cfg(not(feature = "kill-wake-timer-only-canary"))]
    wake_task_by_tid(tid, &|r| force || matches!(r, WaitReason::Timer(_)));
    #[cfg(feature = "kill-wake-timer-only-canary")]
    { let _ = force; wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_))); }
}

/// Record stop request `new` for task `tid` in slot `idx` (merged with one
/// already pending): the request word, the machine-wide forced count, and a
/// forced stop's empty filter. The caller wakes the task.
fn record_stop(idx: usize, tid: u32, new: stop_policy::Stop) {
    let old = if STOP_TID[idx].load(Ordering::Acquire) == tid {
        stop_policy::Stop::decode(STOP_WORD[idx].load(Ordering::Acquire))
    } else {
        None
    };
    let merged = stop_policy::Stop::merge(old, new);
    STOP_WORD[idx].store(merged.encode(), Ordering::Release);
    STOP_TID[idx].store(tid, Ordering::Release);
    if merged.force {
        // Counted once per task, never after its exit hook sealed the slot.
        let _ = stop_policy::forced_count(&FORCED_ACCT[idx], &FORCED_PENDING, tid);
    }
    if merged.force && !old.is_some_and(|o| o.force) {
        // SAFETY: the slot holds `tid` (checked above); the filter is plain
        // data read by `current_syscall_verdict` through a pointer into this
        // same slot. A verdict racing these stores reads either filter, and
        // either answer is harmless: the next syscall after them is refused.
        unsafe {
            let t = task_mut(idx);
            if t.tid == tid {
                let f = &mut t.syscall_filter;
                f.count = 0;
                f.audit = false;
                f.bits = [0; crate::filter::SYSCALL_FILTER_BITMAP_BITS / 32];
                f.enabled = true;
            }
        }
    }
}

/// The stop request pending for the current task, if any. Sticky: a task
/// asked to stop stays asked, so every interruptible wait it enters after
/// answers `-EINTR`.
pub fn current_stop_request() -> Option<stop_policy::Stop> {
    let idx = current_slot()?;
    let tid = unsafe { TASKS[idx].tid };
    if STOP_TID[idx].load(Ordering::Acquire) != tid {
        return None;
    }
    stop_policy::Stop::decode(STOP_WORD[idx].load(Ordering::Acquire))
}

/// The exit code the current task must end with now, if a forced stop is
/// pending for it.
pub fn current_forced_exit() -> Option<i32> {
    current_stop_request().filter(|s| s.force).map(|s| s.exit_code())
}

/// Is a forced stop pending anywhere? One load: what the timer tick from
/// user mode asks before [`current_forced_exit`].
#[inline]
pub fn forced_stop_pending() -> bool {
    FORCED_PENDING.load(Ordering::Relaxed) != 0
}

/// End the current task now if a forced stop is pending for it. Call only at
/// a safe point: no lock held, not inside a syscall that holds the console
/// (a return to user mode, a timer interrupt taken from user mode).
pub fn exit_if_forced() {
    if let Some(code) = take_current_forced_exit() {
        // Wave 13: a thread group's member stopped because its group is
        // ending (`exit_group`, a fault) is not news.
        if !crate::group::current_group_ending() {
            azos_drv_sys::kprintln!(
                "[KILL] tid={} stopped by an ancestor: exit {}", current_task_tid(), code,
            );
            task_exit_by_signal(code);
        }
        task_exit_with_code(code);
    }
}

/// Consume the current task's forced stop, if one is pending: it is taken off
/// the machine-wide count and the slot's request is cleared, so a second call
/// (the exit hook after `seccomp_deny_kill`) finds nothing. Returns its exit
/// code. The caller is about to end the task.
pub fn take_current_forced_exit() -> Option<i32> {
    let idx = current_slot()?;
    let code = current_forced_exit()?;
    let tid = STOP_TID[idx].swap(0, Ordering::AcqRel);
    if tid != 0 {
        let _ = stop_policy::forced_uncount(&FORCED_ACCT[idx], &FORCED_PENDING, tid);
    }
    Some(code)
}

/// Task `tid`, in slot `idx`, is exiting (the exit hook, after
/// [`take_current_forced_exit`]):
/// a forced stop still counted for it is settled, and none recorded for it
/// from now on is counted. Without the seal, a stop that lands after the
/// hook — the task stays valid until its slot is freed — kept the
/// machine-wide count up for good, and every user-mode tick on every hart
/// took the slow path ([`forced_stop_pending`]).
pub fn seal_forced_stop(idx: usize, tid: u32) {
    if let Some(w) = FORCED_ACCT.get(idx) {
        stop_policy::forced_seal(w, &FORCED_PENDING, tid);
    }
}

/// Forced stops counted and not consumed, machine-wide (ktest).
pub fn forced_stops_pending() -> u32 {
    FORCED_PENDING.load(Ordering::Relaxed)
}

/// `tid` (a child just spawned, still parked) dies with its parent.
pub fn set_die_with_parent(tid: u32) {
    if let Some(idx) = idx_for_tid(tid) {
        DWP_TID[idx].store(tid, Ordering::Release);
    }
}

/// `dead` is exiting: force-stop (signal 1) every live child of it that was
/// spawned with `SPAWN_F_DIE_WITH_PARENT`. Returns how many. Called from the
/// exit hook, while `dead`'s slot is still valid.
pub fn stop_die_with_parent_children(dead: u32) -> usize {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        let Some(tid) = tid_for_idx(idx) else { continue };
        if DWP_TID[idx].load(Ordering::Acquire) == tid
            && PARENT_TID[idx].load(Ordering::Relaxed) == dead
            && task_stop(tid, true, 1)
        {
            n += 1;
        }
    }
    n
}

/// Core scheduling logic: pick next task for `cpu` and context-switch to it.
///
/// Scheduling order: strict priority over the per-CPU bitmap queues; on a
/// hart with RT state, `rt::pick` (band budget, EDF + CBS inside a level).
///
/// # Safety
/// Should be called with interrupts disabled on the calling CPU (all current
/// callers do, or run inside a trap handler where hardware already disabled
/// them) — but every ready-queue touch below goes through the IRQ-safe
/// `cpu_dequeue_locked` / `cpu_enqueue_locked` wrappers regardless, so this
/// function no longer *depends* on that invariant for correctness against
/// `CPU_LOCKS[cpu]`.
/// No `CPU_LOCKS` guard is held across `context_switch()` — each locked
/// helper acquires and releases `CPU_LOCKS[cpu]` internally, before
/// returning, so nothing is held when `context_switch` (which may not
/// return) is reached further down.

/// Clear the outgoing task's `context_saving` when `do_schedule` is about to
/// return **without switching**.
///
/// `context_saving` means "this task's registers are being saved right now —
/// do not dispatch it yet", and it is normally cleared by the save tail in
/// `context_switch.S`. `block_current` sets it *before* committing to
/// `Blocked`, so every path where `do_schedule` returns instead of switching
/// leaves it set on a task that nothing is saving.
///
/// The consequence is not subtle: `do_schedule` spin-gates on
/// `next.context_saving` before switching to a task, so a stuck flag makes
/// every hart that picks that task spin forever. Observed directly in the
/// census as `blocked tid=21 client=false saving=true` with phase A of
/// `ipctest` stalled — 369 of 1600 calls served and every client stuck.
///
/// Safe on the switching paths too, which is why it is called at the returns
/// rather than being conditional on state: if we are not switching away from
/// this task, nobody is saving it.
#[inline(always)]
pub(super) unsafe fn clear_saving_on_no_switch(cpu: usize) {
    let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
    if idx >= MAX_TASKS { return; }
    let task = unsafe { task_ref(idx) };
    // **Only for a `Running` current, and the restriction is load-bearing.**
    //
    // Clearing it unconditionally was tried and is a far worse bug than the
    // wedge it cures. For a `Blocked` current at a no-switch return the task
    // keeps executing on this hart with live registers; clearing the flag lets
    // a waker take it Blocked -> Ready -> enqueued, another hart dequeue it,
    // pass the spin-gate, and restore a **stale** saved context while this
    // hart is still running the real one. Two harts, one register file.
    //
    // Not hypothetical: the counters measured that path firing **12906 times**
    // in a single `ipctest` run (`self` arm, current Blocked), against 216
    // with the current Running. The dangerous case was the dominant one.
    //
    // A `Blocked` current at a no-switch return keeps the flag set and the
    // hart that picks it spins -- the IPC wedge. That is the lesser evil, and the real fix
    // is to never return to a `Blocked` current at all.
    if task.state() == TaskState::Running {
        task.context_saving.store(false, Ordering::Release);
    }
}



/// Early-return accounting for [`do_schedule`], split by whether the *current*
/// task had already committed to `Blocked`.
///
/// **WHY the split is the whole point.** `do_schedule` returning without
/// switching is perfectly normal when the current task is `Running` — there is
/// simply nothing better to run, so it keeps running. The same return with the
/// current task `Blocked` is a defect: `block_current` has already published
/// `Blocked` and does not idle, so control goes back through the syscall to
/// ring 3 and a task that the whole system believes is asleep keeps executing.
/// Every subsequent `task_block` then takes the "already Blocked, unswitched"
/// arm of `commit_blocked_or_consume_wake`, calls `do_schedule` again, and
/// returns again — which is exactly the signature measured in
/// on the IPC wedge: eight turns, zero wakes, 15 us.
///
/// The three sites are the three early returns, so a single run names the line.
#[path = "../unswitched.rs"]
pub mod unswitched;

/// Wake latency: how long a task sat `Ready` before a hart actually ran it,
/// and **whether the doorbell was rung for it**.
///
/// **The question this exists to answer.** `vsbench` measures an `ipc-rt` worst
/// case of 5–15 ms in 7 runs of 8, against 276–417 us for Linux on the same
/// host (vsbench). Two discriminators localised it: the stall vanishes
/// at `-smp 1`, and it shrinks by 10x when the tick goes from 100 Hz to
/// 1000 Hz. So a task is made runnable, nobody dispatches it, and the timer
/// eventually rescues it.
///
/// That leaves exactly two shapes, and they need opposite fixes:
///   * the bell was **rung and did not help** — the IPI is delivered and
///     something on the target hart swallows it;
///   * the bell was **never rung** — the enqueue path skipped it, e.g.
///     `cpu_enqueue_locked` only rings `if appended`.
///
/// Global wake counters cannot separate them: they are cumulative, and one lost
/// wake among thousands does not move them. This records the delay per task and
/// splits the long ones by whether a doorbell accompanied that enqueue.
///
/// Side arrays, not `Task` fields, deliberately: a compile-time assertion ties
/// `satp`'s offset to `TASK_SATP_OFFSET`, the value `context_switch.S` is fed
/// via `offset_of!` (not hand-copied) — layout-frozen all the same, and
/// adding fields to `Task` has already broken this build once.
#[cfg(feature = "ipc-census")]
#[path = "../wakelat.rs"]
pub mod wakelat;

/// The tasks with the most `total_runtime`, to name whoever is hogging a hart.
///
/// `schedule()` bumps the current task's `total_runtime` on every tick, so the
/// ranking says who is really running — which is the question global switch
/// counters cannot answer.
#[cfg(feature = "ipc-census")]
pub(super) static SCHED_BY_TASK: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];

/// Who ENTERS `do_schedule`, per task. The global counters say how many times
/// a switch happens; only this says **who asks for it**, which is the
/// difference between "the scheduler has gone mad" and "this task yields in a
/// loop".
#[cfg(feature = "ipc-census")]
pub fn top_sched_callers(out: &mut [(u32, u32, [u8; 8])]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let c = SCHED_BY_TASK[i].load(Ordering::Relaxed);
            if c == 0 { continue; }
            let t = task_ref(i);
            let mut nm = [0u8; 8];
            for (k, b) in t.name.iter().take(8).enumerate() { nm[k] = *b; }
            let e = (t.tid, c, nm);
            if n < out.len() { out[n] = e; n += 1; }
            else {
                let mut worst = 0usize;
                for k in 1..out.len() { if out[k].1 < out[worst].1 { worst = k; } }
                if out[worst].1 < e.1 { out[worst] = e; }
            }
        }
    }
    out[..n].sort_unstable_by(|a, b| b.1.cmp(&a.1));
    n
}

pub fn top_runtime(out: &mut [(u32, u64, [u8; 8], u8)]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let t = task_ref(i);
            let mut nm = [0u8; 8];
            for (k, b) in t.name.iter().take(8).enumerate() { nm[k] = *b; }
            let e = (t.tid, t.total_runtime, nm, t.state() as u8);
            if n < out.len() { out[n] = e; n += 1; }
            else {
                let mut worst = 0usize;
                for k in 1..out.len() { if out[k].1 < out[worst].1 { worst = k; } }
                if out[worst].1 < e.1 { out[worst] = e; }
            }
        }
    }
    out[..n].sort_unstable_by(|a, b| b.1.cmp(&a.1));
    n
}

/// Is the task currently on `cpu` already committed to `Blocked`?
#[cfg(feature = "ipc-census")]
#[inline(always)]
pub(super) unsafe fn current_is_blocked(cpu: usize) -> bool {
    let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
    if idx >= MAX_TASKS { return false; }
    unsafe { task_ref(idx).state() == TaskState::Blocked }
}

/// Why a task is giving up the CPU.
///
/// **Travels with the call, not in a per-CPU flag.** The reason is known at
/// the call site and nowhere else; a flag set beside the call is a flag
/// somebody eventually forgets to clear, and it would be wrong in exactly the
/// case that matters — a tick arriving while a voluntary schedule is in
/// flight. As an argument it cannot desynchronise from the call it describes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    /// The task asked: `task_yield`, `task_block`, `task_exit`.
    Voluntary,
    /// The timer took the CPU away.
    Preempted,
}

/// Q3.2 (tickless idle) — the re-arm for an idle hart whose run queue is
/// EMPTY. `do_schedule()` reaches the two "nothing to pick" early returns
/// below in exactly that state (the dequeue → None), and
/// neither carried the re-arm the self-pick path further down does — the
/// idle task is never IN the queue, so an idle hart never self-picks. The
/// timer ISR's `set_next_tick_smart` (periodic 1/sched_hz clamp) therefore
/// stood on every tick: measured 74/74/75 wakeups/s over three 30 s windows
/// (`riscv64: idle wakeups/s (tickless)` row body by hand, -smp 1
/// bench-minimal), with a histogram of `set_next_tick_tickless(.., true)`
/// calls read over GDB showing ONE call per boot. The row's author measured
/// 43.6/s on a tree where the pick path still went through the self-pick
/// arm. Same arming as that arm; only when the current task is idle.
#[inline]
pub(super) unsafe fn tickless_rearm_if_idle(cpu: usize) {
    let ci = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
    if ci < MAX_TASKS
        && task_ref(ci).priority.load(Ordering::Relaxed) == crate::task::IDLE_PRIORITY
    {
        azos_drv_sys::timebase::set_next_tick_tickless(
            cpu as u32, nearest_timer_deadline(), true,
        );
        // A throttled reservation or an exhausted band window on this hart
        // must not be slept past (SCHED-RT).
        rt::rearm(cpu);
    }
}

/// The context-saving gate's wait (see `do_schedule`): spin until `next`'s
/// save has finished, with a wall-clock bound (SCHED_SAVING_GATE_US). `false` when the bound
/// ran out. Out of line: the flag is clear on every switch that finds its
/// task saved, and the deadline needs a clock read only when it is not.
#[inline(never)]
pub(super) fn wait_context_saved(next: &Task) -> bool {
    // Kconfig SCHED_SAVING_GATE_US (1000) and SCHED_SAVING_GATE_CLOCK_EVERY
    // (256): the bound and how often the clock is read while waiting.
    let deadline = azos_drv_sys::timebase::now()
        + (azos_drv_sys::timebase::TIMER_FREQ as u64)
            * azos_limits::SCHED_SAVING_GATE_US as u64 / 1_000_000;
    let every = (azos_limits::SCHED_SAVING_GATE_CLOCK_EVERY as u32).max(1);
    let mut spins: u32 = 0;
    while next.context_saving.load(Ordering::Acquire) {
        core::hint::spin_loop();
        spins = spins.wrapping_add(1);
        if spins % every == 0 && azos_drv_sys::timebase::now() >= deadline {
            return false;
        }
    }
    true
}


/// Gate-only probe (`ctx-probe`, CTXHUNT 2026-10-08): the invariants a
/// switch relies on, checked where they must hold. The first violation is
/// printed (`[CTXPROBE]`, both task ids, the hart, the site) and the kernel
/// panics; a second hart that fails meanwhile spins, so the line is whole.
/// - every `do_schedule` entry and every resume: `tp` is this hart (riscv64:
///   the id under its `stvec` slot) and `sp` is on the current task's stack;
/// - every dispatch: the task's saved `sp` is on its own stack, its `ra` is
///   not 0, its slot is valid, it is current on no other hart, and the
///   switching hart is still on the outgoing task's stack;
/// - every reap: no hart runs on the slot being freed.
///
/// It found the stale hart id of the exit path (see `do_schedule`) on its
/// first loaded boot.
#[cfg(feature = "ctx-probe")]
#[path = "../ctx_probe.rs"]
pub(crate) mod ctx_probe;

/// Gate canary (`exit-stale-hart-canary`): the exit path's stale hart id,
/// made certain. An exiting task first sleeps 1 ms with its affinity on the
/// next hart, so it wakes there, then its next `do_schedule` is handed the
/// hart it entered the exit on, as `task_exit_with_code` used to hand it.
#[cfg(feature = "exit-stale-hart-canary")]
#[path = "../stale_hart_canary.rs"]
pub(super) mod stale_hart_canary;

/// **A Zombie's slot is freed only after the switch away from it**
/// (CTXHUNT, 2026-10-08), by the task switched to, on its own stack: the
/// hart that switches from the Zombie stores the slot in the next task's
/// `reap_on_resume`, and that task frees it first thing when it runs
/// (`finish_switch`, after every `context_switch` that resumes a task and at
/// the top of `task_entry_wrapper`). It used to be freed in `do_schedule`'s
/// Zombie arm, BEFORE `context_switch`, while the hart still ran on the
/// Zombie's kernel stack through the dispatch tail (the context-saving gate's
/// spin of up to SCHED_SAVING_GATE_US, the tickless write, tracing): from
/// `TASK_VALID` false on, another hart could hand the slot, and its stack, to
/// a new fork or thread and run it. Two harts on one stack. With the stale
/// hart id of the exit path fixed (see `do_schedule`), the old order still
/// faulted the kernel in 4 of 8 loaded boots of abitest's thread storm;
/// `reap-window-canary` (the old order plus 2 ms on the freed stack) faults
/// it in the storm's first round. Linux frees a dead task's stack in
/// `finish_task_switch`, on the next task's stack; this is the same rule.
///
/// The store is made after the dispatch gate, so a `do_schedule` that gives
/// its pick back (and stays on the Zombie) leaves nothing to free.
#[inline(always)]
pub(crate) unsafe fn finish_switch(me: *mut Task) {
    #[cfg(feature = "ctx-probe")]
    ctx_probe::check_running(ctx_probe::RESUME);
    let r = unsafe { (*me).reap_on_resume };
    if r != 0 {
        finish_switch_slow(me, r - 1);
    }
}

#[inline(never)]
#[cold]
unsafe fn finish_switch_slow(me: *mut Task, idx: usize) {
    unsafe {
        (*me).reap_on_resume = 0;
        // SAFETY: `idx` is the Zombie the hart switched from to resume
        // `me`; nothing runs on its stack any more and its slot is still
        // valid (`TASK_VALID` true until this reap).
        reap_zombie_on_switch(idx);
    }
}

/// `do_schedule`'s reap of a Zombie it is switching away from, out of line
/// (wave 15, SWITCH): a rare arm with a lock, two prints and a TTBR1 probe,
/// inline it made every switch's prologue save registers only it needs.
/// The slot is free when this returns; the caller must not touch it again.
/// Called from [`finish_switch`], once this hart is off the Zombie's stack
/// (the K-C6 note below predates that: "about to leave" was not left yet).
#[inline(never)]
pub(super) unsafe fn reap_zombie_on_switch(old_idx: usize) {
    #[cfg(feature = "ctx-probe")]
    ctx_probe::check_reap(current_cpu_id(), old_idx);
    let old = task_mut(old_idx);
    // K-C6: `task_exit()` marks the task Zombie but deliberately does
    // NOT free its pool slot (TASK_VALID) or clear
    // PER_CPU[cpu].current_idx itself — at that point it is still
    // executing ON this exact task's own stack (task_exit() calls
    // do_schedule() directly, and if no task was ready yet, idles in
    // its own WFI loop on that same stack). Freeing the slot there
    // would let another hart's alloc_slot() (e.g. via fork()) reuse
    // and dispatch a brand new task onto that same physical stack
    // while this hart is still running on it.
    //
    // This is therefore the correct, and only safe, place to free
    // it: right here, in the SAME do_schedule() call that is about
    // to `context_switch()` away from it below — whether that
    // happens on the very tick task_exit() called us (a ready task
    // was immediately available) or many ticks later (task_exit()
    // idled in WFI until one appeared; schedule() treats a lingering
    // Zombie exactly like "nothing running" in the meantime, see its
    // K-C6 comment, so it keeps calling us every tick until we get
    // here). Either way, by the time this line runs we are
    // unconditionally about to leave `old`'s stack for good via the
    // context_switch() call below — no other hart can have reused
    // this slot in the interim, since TASK_VALID stayed true.
    let _pool = PoolGuard::acquire();
    // aarch64 Phase 6 marker: this is the actual reap — the pool slot
    // is freed right here, immediately (no second task_create needed
    // to trigger it, unlike the lazy claim-time reset in
    // `try_task_create_init`) — so it is the honest place to prove
    // "the kernel reaps it" for the `hello`/`syscall_test` gate row.
    // `#[cfg]`'d to the real aarch64 kernel target only — NOT plain
    // `target_arch = "aarch64"`, which is also this crate's OWN host
    // test target (`aarch64-apple-darwin`, since these tests run on
    // Apple Silicon). That plain form shipped once and broke
    // `tests/host/syscall-tests`' `exec_binding` suite: this arm ran
    // during a host test through the very same `#[path]`-pulled
    // source (`shims/sched`), calling a `kprintln!` that assumes a
    // live UART driver. `target_os = "none"` is what is actually
    // true only for the real bare-metal build. RISC-V's console
    // output must not change either way (this task's own
    // constraint) — riscv64 already proves this same path via its
    // own scenarios' exit-code checks.
    // arch-only: an aarch64 bring-up trace line.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    azos_drv_sys::kprintln!(
        "[SCHED] aarch64 reaped tid={} slot={}", old.tid, old_idx);
    // TTBR1 split proof, second half (aarch64 parity program): the
    // boot-time marker in `kernel_main` (`[AARCH64-TTBR1]`) proves
    // the alias table is configured correctly at boot; this proves
    // it STAYS that way after real user-task activity has forced
    // real `TTBR0_EL1` switches (fork/exec/exit, all upstream of
    // every reap). First reap ON HART 0 only.
    //
    // **Must be hart 0, not merely "the first reap".** `TTBR1_EL1`
    // is a per-CPU banked register, and this wave's
    // `aarch64_early_ttbr1_alias` (`boot.S`) runs on the PRIMARY
    // ONLY — a secondary's own `TTBR1_EL1` was never written and
    // reads back whatever its reset state happens to be (0 on
    // QEMU). Gating on "first reap, any hart" measured this
    // directly on `-smp 2` ipctest: 8 of 10 runs printed FAILED
    // with `now=0x0` whenever hart 1 (not hart 0) reaped first —
    // a false positive from comparing hart 0's boot-time value
    // against hart 1's own never-initialized register, not a real
    // write to anything. Every row this runs in reaps many tasks
    // across the run, so waiting specifically for a hart-0 reap
    // still fires reliably without needing every secondary to
    // also run the alias setup (out of scope for this wave — see
    // `enable_ttbr1_alias`'s own doc).
    // arch-only: the TTBR1 split proof; no other ISA splits its tables so.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    if crate::smp::current_cpu_id() == 0 {
        static CHECKED: AtomicBool = AtomicBool::new(false);
        if !CHECKED.swap(true, Ordering::AcqRel) {
            // What this asserts changed when the kernel moved into the
            // upper half: TTBR1 no longer holds the boot-time alias,
            // it holds the kernel's REAL page table. So the invariant
            // is "TTBR1 still points at the kernel's table after user
            // tasks have been switching TTBR0", which is the property
            // the split exists for — comparing against the boot alias
            // would now fail on a correct kernel.
            let kpt = azos_mm::vmm::kernel_pagetable();
            if kpt != 0 {
                let now = azos_arch::sysregs::read_ttbr1_el1() as usize & !0xFFF;
                if now == kpt {
                    azos_drv_sys::kprintln!(
                        "[AARCH64-TTBR1-POST] after a user task's own TTBR0_EL1 \
                         switches: TTBR1_EL1 still the kernel table on hart 0 ({:#x})", now);
                } else {
                    azos_drv_sys::kerr!(
                        "[AARCH64-TTBR1-POST] FAILED: hart 0's TTBR1_EL1 is not the \
                         kernel table after user activity — kernel PT {:#x}, TTBR1 {:#x}",
                        kpt, now);
                }
            }
        }
    }
    // Its reservation, if any, leaves the hart's set and ledger before
    // the slot can be claimed again.
    rt::release(old_idx);
    TASK_VALID[old_idx].store(false, Ordering::Relaxed);
    hist_reaccount(old_idx);
    view_note(old_idx);
    // D2: the task's place in its domain ends with its slot (a thread left
    // it already, in `member_exit`); the last one out frees the domain.
    crate::domain::leave(old.take_domain());
    // Sentinel protocol (see alloc_slot): unpublish, fence, clear the
    // tid, so a dead TID can never be matched against this slot's
    // next occupant by the lock-free `idx_for_tid` scan.
    core::sync::atomic::fence(Ordering::Release);
    old.tid = 0;
}
