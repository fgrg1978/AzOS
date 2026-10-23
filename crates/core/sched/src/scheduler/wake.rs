// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Block / wake half of the scheduler: `block_current`, the wake paths and
//! their placement, the K-C25 reaper, the TID-directed wake, and the timer
//! sweep. Child of `scheduler` (moved out of `scheduler/mod.rs` unchanged).

use super::*;

mod preempt;
pub mod attrib;

/// Count one wake in the Domain of the task it woke and, if it is one of those
/// the ring keeps (`attrib::logged`: the machine's own wakes all, the wakes
/// tasks make one in `2^WAKE_RING_SAMPLE_LOG2` per Domain), log it with its source. Called
/// by each place that makes a Blocked -> Ready transition, with `reason` read
/// before the wake cleared it and `target_cpu` the CPU the task was queued on.
/// Kconfig `WAKE_RING_ENTRIES` 0: nothing is compiled.
///
/// The IPC hand-off is the hot case and costs the count and one test; the
/// logging is out of line.
#[inline(always)]
fn note_wake(task: &Task, reason: attrib::Reason, via: attrib::Via, target_cpu: usize) {
    if !attrib::ENABLED {
        return;
    }
    let nth = crate::domain::count_wake(task.domain());
    let logged = attrib::logged(via, reason, nth, || azos_sync::isr_depth::in_isr(current_cpu_id()));
    if logged {
        log_wake(task, reason, via, target_cpu);
    }
}

/// The source of the wake and its ring entry (`note_wake` decided to log it).
#[inline(never)]
fn log_wake(task: &Task, reason: attrib::Reason, via: attrib::Via, target_cpu: usize) {
    let here = current_cpu_id();
    // `isr`: the waker is an interrupt handler, not the task it interrupted. The
    // IPC hand-off is made from a syscall.
    let isr = !matches!(via, attrib::Via::Ipc) && azos_sync::isr_depth::in_isr(here);
    // Only a delivery in flight on this CPU has a line, and it runs in interrupt
    // context.
    let line = if isr { attrib::irq_line(here) } else { None };
    let src = attrib::source(via, reason, isr, line.is_some());
    let detail = attrib::detail(src, line, isr, current_task_tid);
    attrib::RING.push(azos_drv_sys::timebase::now(), task.tid, task.domain(), detail, src, here as u8, target_cpu as u8);
}

/// [`note_wake`] for the paths that are not hot (a broadcast sweep, a wait
/// queue, the reaper): out of line.
#[inline(never)]
fn note_wake_cold(task: &Task, reason: attrib::Reason, via: attrib::Via, target_cpu: usize) {
    note_wake(task, reason, via, target_cpu);
}

/// `irq_dispatch` on this CPU is about to deliver the event of interrupt line
/// `line`: the wakes it makes are logged as that line's (`attrib`).
pub fn wake_irq_enter(line: u32) {
    attrib::irq_enter(current_cpu_id(), line);
}

/// The delivery [`wake_irq_enter`] announced is over.
pub fn wake_irq_leave() {
    attrib::irq_leave(current_cpu_id());
}

/// Cross-class wake-up preemption (`preempt.rs` has the rule and the
/// reasoning).
///
/// `wake_enqueue_locked` for the wake paths of this file, then the check that
/// used to be missing: a task woken onto the waking CPU itself, which runs a
/// worse class, waited for that CPU's next tick (an enqueue for oneself rings
/// no doorbell). `check` is false for the synchronous IPC hand-off, whose
/// waker blocks right after; true for the one hand-off outcome whose waker does
/// not (`direct_claim_enqueue`).
///
/// Returns what `wake_enqueue_locked` returned; a refused enqueue queued
/// nothing new, so there is nothing to preempt for.
///
/// SAFETY: as `wake_enqueue_locked`; `idx` is the slot just enqueued on `cpu`.
#[inline]
pub(super) unsafe fn wake_enqueue_preempting(cpu: usize, idx: usize, check: bool) -> bool {
    let appended = wake_enqueue_locked(cpu, idx);
    if appended && check && cpu == current_cpu_id() {
        wake_preempt_check(cpu, idx);
    }
    appended
}

/// The facts of task `idx` for [`preempt::must_preempt`]. A DL task's
/// deadline is the owner hart's state, readable here because `cpu` is the
/// calling hart (a reservation is pinned to the hart that admitted it).
#[inline]
unsafe fn preempt_facts(cpu: usize, idx: usize) -> preempt::Running {
    use crate::sc::Class;
    let class = classes::class_of(idx).unwrap_or(Class::Fair);
    preempt::Running {
        class,
        prio: prio_bucket(task_ref(idx).priority.load(Ordering::Relaxed)) as u32,
        deadline: if class == Class::Dl { rt::dl_deadline(cpu, idx) } else { None },
    }
}

/// Compare the task just queued on the calling hart `cpu` with the one it
/// runs and, if it must preempt, record the debt (`need_resched`).
#[inline]
unsafe fn wake_preempt_check(cpu: usize, idx: usize) {
    let cur_idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
    // A task in `current_idx` that is no longer `Running` (a Zombie, K-C6; a
    // blocker past its commit) is about to leave the CPU on its own: the
    // pick that follows takes the best ready task, so it is not preempted.
    let cur = if cur_idx < MAX_TASKS
        && cur_idx != idx
        && task_ref(cur_idx).state() == TaskState::Running
    {
        Some(preempt_facts(cpu, cur_idx))
    } else {
        None
    };
    if preempt::local_resched(cur, preempt_facts(cpu, idx)) {
        azos_sync::preempt::set_need_resched();
    }
}

// ---- AQ0: Block / Wake API (used by wait.rs) ----

/// Stable one-byte tag for a [`WaitReason`], for packing into the K-C29
/// last-offender word. Only the variant matters there — the payload
/// (handle, deadline, TID) would not fit and is not what identifies the
/// offending call site.
#[inline]
fn wait_reason_tag(r: WaitReason) -> u8 {
    match r {
        WaitReason::None => 0,
        // 1 was `Irq`, removed with the wake-task IRQ binding (`DEVICE_IRQ_BIND`
        // reports through a port): not reused, so a recorded tag keeps its
        // meaning.
        // 2 was `Channel`, removed with the channel pool: not reused, so a
        // recorded tag keeps its meaning.
        WaitReason::Ring(_) => 3,
        WaitReason::Timer(_) => 4,
        WaitReason::Port(_) => 5,
        WaitReason::WaitQueue => 6,
        // 7 was `Rpc`, removed with the synchronous RPC path:
        // not reused, so a recorded tag keeps its meaning.
        WaitReason::FastIpcServer(_) => 8,
        WaitReason::FastIpcClient(_) => 9,
        // 10 was the accept wait of a memory loan, removed: not reused, so a
        // recorded tag keeps its meaning.
    }
}

/// Block the current task on `cpu` with the given reason.
/// Moves it from Running → Blocked, then reschedules.
pub fn block_current(cpu: usize, reason: WaitReason) {
    if cpu >= MAX_CPUS { return; }
    // Lockdep (Kconfig LOCKDEP, N1): every task sleep (timed, WaitQueue,
    // IPC) passes here; a SpinLock held, IRQs off or interrupt context is
    // reported with the lock's class and site. No instruction when off.
    azos_sync::lockdep::might_sleep("scheduler block");

    // K-C29: refuse to park a task that is inside a critical section.
    //
    // CHECKED FIRST, on purpose — before the `sstatus` write below, before
    // `context_saving` is set, before `wait_reason` is published, and before
    // the commit CAS. Every one of those is a step that makes this task
    // visible to wakers as "going to sleep"; a refusal has to happen while
    // none of it has been done, or the task is left half-parked.
    //
    // Refuse, do not defer, and do not switch. Parking a task that holds a
    // spinlock converts a priority-dependent hang into a certain one: nobody
    // can release the lock, and unlike a deferred tick there is no later
    // moment at which sleeping becomes the right answer.
    //
    // ── STEP-2 PREREQUISITE — the caller contract is NOT uniform ──
    //
    // Returning without blocking is the same outcome the `!committed`
    // (wake-already-stamped) arm below already produces, so it is not a new
    // shape of return. But the claim in that arm's comment — "every caller
    // re-checks its condition in a loop" — was checked against the callers and
    // is **only true of the path it names**:
    //
    //   * `dispatch.rs`'s `DOMAIN_IRQ_WAIT` was a bare single `task_block`
    //     followed by `0`: under a refusal it reported "your IRQ fired" when
    //     it did not. An interrupt line reports through a port now, whose
    //     wait re-tests its queue.
    //   * the `WaitReason::Timer` sleeps in `main.rs` are bare calls inside an
    //     outer loop: a refusal turns one timed sleep into a hot spin for that
    //     iteration, not a correctness break.
    //
    // **This branch IS reachable, and the note that used to sit here saying it
    // was not is why that matters.** It read "UNREACHABLE today — nothing
    // takes a `PreemptGuard` … before step 2 makes `SpinLockGuard` carry one".
    // Step 2 landed: `crates/core/sync/src/spinlock.rs:64` takes
    // `critical_section()` and `:66` stores it in the guard, so
    // `preempt::disabled()` is TRUE for the whole of any `SpinLock` hold.
    //
    // What that means for a caller: **blocking while holding a spinlock does
    // not block.** It returns here, having neither slept nor published any
    // state, and the caller sees an ordinary wake. A loop that re-tests a
    // condition only another task can change then spins to its bound and
    // reports failure — which is exactly what a direct
    // hand-off from a client holding `FAST_IPC` to a waiting server would do
    // if it blocked with that lock held. Read this before writing that.
    //
    if azos_sync::preempt::disabled() {
        let depth = azos_sync::preempt::depth();
        preempt_audit::bump(&preempt_audit::BLOCK_WHILE_ATOMIC);
        // SAFETY: `cpu < MAX_CPUS` was just checked; `current_idx` is either
        // `usize::MAX` or a valid pool index, and only read here.
        let tid = unsafe {
            let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
            if idx < MAX_TASKS { task_ref(idx).tid } else { 0 }
        };
        preempt_audit::record_block_offender(tid, depth, wait_reason_tag(reason));
        // Rate-limited: a hart refusing on every IPC round trip must not turn
        // the UART into the bottleneck. The counter keeps rising after the
        // budget runs out.
        let n = preempt_audit::BLOCK_WHILE_ATOMIC.load(Ordering::Relaxed);
        if n <= preempt_audit::BLOCK_LOG_BUDGET {
            azos_drv_sys::kprintln!(
                "[K-C29] block_current refused: tid={} depth={} reason_tag={} (#{}/{})",
                tid, depth, wait_reason_tag(reason), n,
                preempt_audit::BLOCK_LOG_BUDGET
            );
        }
        return;
    }

    // K-A12: do_schedule() is not safe to reenter — a timer tick firing on
    // this hart mid-call would race this call's own queue/PER_CPU mutations
    // (the outer call's dequeued `next_idx` and this task's Blocked state get
    // corrupted by a nested dispatch). This is the exact hazard task_yield()
    // already guards against; block_current() was missing the same guard.
    // Disable SIE before do_schedule() and restore it only after it returns
    // (i.e. once this task has been rescheduled back in) — same pattern as
    // task_yield(), and both the "have a task to block" and early-return
    // paths below converge on the same restore.
    let sstatus = azos_arch::ARCH.disable_all();
    // This hart, read with interrupts off: the caller's `cpu` may predate a
    // block that moved the task (see `do_schedule`).
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // `< MAX_TASKS`, not `!= usize::MAX`: the scheduler only ever writes
        // in-range indices or MAX here, so the two are equivalent — but only
        // this form lets LLVM prove the `TASKS[idx]` index below in range.
        // With the sentinel comparison it emitted a `panic_bounds_check`
        // call, i.e. a board reset under `panic = "abort"` sitting on the
        // block path. Same provable-guard trick as any
        // bounded table walk.
        if idx < MAX_TASKS {
            let task = task_mut(idx);

            // Mark in-transit BEFORE the state change that makes this task
            // visible to wakers — closes the race where a waker sees Blocked
            // and redispatches before context_switch.S has actually saved
            // this task's registers (the save tail in context_switch.S clears
            // it).
            task.context_saving.store(true, Ordering::Relaxed);

            // K-C17: publish the REASON before the state. A waker only reads
            // `wait_reason` after observing `Blocked` with Acquire, and
            // `Blocked` is only ever published by the Release CAS inside
            // `commit_blocked_or_consume_wake` below — that pairing is what
            // guarantees the reason a waker reads is this one, not the stale
            // value from when we were running (the mismatch path drops the
            // wake without stamping, so a torn read here was a permanent
            // sleep). The old explicit fence pair moved into the CAS
            // orderings.
            task.wait_reason = reason;

            // K-C9 + K-C19 — one conditional CAS replaces "consume the stamp,
            // then mark Blocked" (two independently-ordered cells, a measured
            // ~1-in-3 hang):
            //
            //  * If a wake is already stamped, the commit fails, the stamp is
            //    consumed, and we skip blocking entirely — the condition this
            //    caller is about to sleep on is already satisfied, and every
            //    caller re-checks its condition in a loop, so returning is
            //    exactly "wait() returned because we were woken".
            //
            //    That last clause used to say "every caller", and it was not
            //    true. An enumeration of all 22 production call sites (2026-09-04)
            //    found three shapes, not one: eighteen loop on a real condition
            //    or on a deadline and are safe; two re-poll but cannot tell a
            //    spurious wake from an empty queue, so they answer -1 after a
            //    bounded number of turns; and `DOMAIN_IRQ_WAIT` (gone: a line
            //    reports through a port) had nothing to re-test at all and
            //    returned 0 -- "your interrupt fired" -- to a driver whose
            //    interrupt had not.
            //
            //    One of the loops was added for the same reason: `SYS_IPC_CALL`
            //    blocked once and answered -1, while its waker stamps
            //    `wake_pending` -- so a caller that was merely early already
            //    got a failure, before K-C29 existed.
            //  * A waker can no longer stamp *after* we passed the check: its
            //    stamp CAS requires `state != Blocked`, our commit CAS
            //    requires the stamp clear. Whoever loses the CAS retries
            //    against the other's result. The double-check handshake that
            //    was tried and REVERTED (it could enqueue a task that was
            //    still "current", freezing boot) is unnecessary under this
            //    scheme — see `sched_word` in task.rs for the full history.
            #[allow(unused_variables)]
            let committed = crate::task::sched_word::commit_blocked_or_consume_wake(&task.state_word);
            // Placement histogram, on BOTH outcomes: the commit may have
            // taken Running -> Blocked, or consumed a stamp on a task still
            // `Blocked` from an unswitched block (-> Running), or changed
            // nothing (re-entry while already `Blocked`). The key tells.
            hist_reaccount(idx);
            // Timer sleepers are armed only once `Blocked` is committed —
            // see `timer_sleepers` for why never before.
            // The instant it was armed at: its deadline, or (QoS timer
            // tolerance) a wake-up already scheduled inside its slack window.
            #[cfg(feature = "sched-timer-heap")]
            #[cfg_attr(feature = "oneshot-canary", allow(unused_assignments, unused_variables))]
            let mut armed_at = None;
            #[cfg(feature = "sched-timer-heap")]
            #[cfg_attr(feature = "oneshot-canary", allow(unused_assignments))]
            if committed {
                if let WaitReason::Timer(deadline) = reason {
                    armed_at = Some(timer_sleepers::arm(idx, deadline));
                }
            }
            // Wave 11 ONESHOT: a timer sleeper moves this
            // hart's comparator when its deadline is earlier than what is
            // programmed. Without it a hart that switches to another busy
            // task kept the next scheduler tick programmed, and the deadline
            // was seen up to one period late (the `lat:` rows' worst case).
            // After the commit, for the same reason as the heap arm above: a
            // sleeper the interrupt can find. Interrupts are masked here, so
            // the interrupt this programs runs once `do_schedule` has
            // switched away. `oneshot-canary` compiles it out (gate canary).
            // `u64::MAX` is "no deadline" (futex waits, timeout 0):
            // never earlier than anything, so it skips even the record read.
            #[cfg(not(feature = "oneshot-canary"))]
            if committed {
                if let WaitReason::Timer(deadline) = reason {
                    #[cfg(feature = "sched-timer-heap")]
                    let deadline = armed_at.unwrap_or(deadline);
                    if deadline != u64::MAX {
                        azos_drv_sys::timebase::arm_if_earlier(deadline);
                    }
                }
            }
            if !committed {
                #[cfg(feature = "ipc-census")]
                unswitched::bump(&unswitched::BLOCK_SKIPPED);
                // We never became Blocked, so no waker can be dispatching
                // us — undo the in-transit mark and return to the caller's
                // condition re-check.
                task.context_saving.store(false, Ordering::Relaxed);
                azos_arch::ARCH.restore(sstatus);
                return;
            }

            // Don't re-enqueue — blocked tasks leave the ready queue.
            do_schedule(SwitchReason::Voluntary);
            // Returns here when woken and rescheduled.
            #[cfg(feature = "ipc-census")]
            unswitched::bump(&unswitched::BLOCK_SLEPT);
        }
    }
    azos_arch::ARCH.restore(sstatus);
}

/// Try to wake task `idx` if it matches the predicate.
/// Called from wait.rs wake_matching() — reachable from IRQ context (the
/// timer ISR and external-IRQ path in `kernel/src/entry/riscv64/irq.rs` call
/// `wake_expired_timers()`, which fans out here), and the
/// target CPU is frequently *not* the calling CPU (affinity-pinned task, or
/// the `0` fallback for unpinned tasks). Goes through `cpu_enqueue_locked` —
/// IRQ-safe and takes `CPU_LOCKS[target_cpu]`, so it can't race the target
/// CPU's own `do_schedule()`.
/// Which CPU should a task being woken be enqueued on?
///
/// **WHY this is not just `0` (K-C14).** All three wake paths
/// (`try_wake_task`, `wq_wake_by_tid`, `wake_task_by_tid`) used to send every
/// unpinned task to **CPU 0**, unconditionally. `find_least_loaded_cpu()` had
/// existed in this file all along and none of them called it.
///
/// The result is not "slightly unbalanced": it is starvation with a
/// reproducible victim. `cpu_dequeue` picks by `ready_bitmap.trailing_zeros()`,
/// i.e. strictly by priority, and on this kernel's default boot CPU 0 is where
/// the RT tasks live (`rt-motor` and `flight-ctrl` are both created with
/// affinity to hart 0). So every unpinned task that ever blocks and is woken —
/// which is every userspace task doing IPC, I/O or sleeping — is permanently
/// relocated behind two real-time tasks on a single hart, no matter how idle
/// the other three are.
///
/// Measured: a ring-3 fast-IPC round trip (`userspace/tests/ipctest` phase A, 8
/// forked clients under `-smp 4`) completes exactly as many exchanges as there
/// were clients still sitting on their post-fork CPUs — four — and then wedges
/// forever. The kernel stays healthy throughout, RT tasks keep meeting their
/// deadlines, and nothing reports an error: the clients are `Ready`, correctly
/// enqueued, and simply never picked. That is why this reads as a lost wakeup
/// and is not one.
///
/// Pinned tasks (`cpu_affinity >= 0`) keep going exactly where they are
/// pinned; the operator asked for that.
///
/// `idx` is the waking task's own pool slot, so it does not score against its
/// own placement.
///
/// Every wake-up placement goes through the `Placement` seam.
/// The selection is a `const` and `Legacy` is its one variant, so the `match`
/// has no discriminant to test and the code is what it was before the seam
/// existed (the arm holds the body in place: a helper function per variant
/// moved LLVM's inlining of `find_best_cpu` and changed seven functions).
#[inline]
unsafe fn wake_target_cpu(idx: usize, task: &Task) -> usize {
    match azos_energy::seams::PLACEMENT {
        azos_energy::Placement::Legacy => if task.cpu_affinity >= 0 {
            (task.cpu_affinity as usize).min(ncpu() - 1)
        } else {
            // K-C12: "emptiest hart" is not the same question as "hart that will
            // dispatch this task". A woken task parked behind permanently
            // higher-priority work is a lost task, not a slow one — the same
            // defect K-C14 half-fixed by moving off the hardcoded CPU 0.
            // Approximate and unlocked, like the metric it replaces: a stale
            // sample costs one suboptimal placement, never correctness.
            let prio = task.priority.load(Ordering::Relaxed);
            // Energy-aware placement (Kconfig SCHED_EAS): on asymmetric CPUs a fair task
            // goes where the energy model says it costs least, while no CPU
            // is full; otherwise the load decides, below.
            #[cfg(feature = "energy")]
            let cpu = match if azos_limits::SCHED_EAS && energy::eas_active() {
                eas_wake_cpu(idx, task, prio)
            } else {
                None
            } {
                Some(cpu) => cpu.min(ncpu() - 1),
                None => find_best_cpu(prio, idx).min(ncpu() - 1),
            };
            #[cfg(not(feature = "energy"))]
            let cpu = find_best_cpu(prio, idx).min(ncpu() - 1);
            // Kconfig DECISION_RECORDS_DEV: a move off the task's last CPU is
            // explained (the rejected alternative is staying). Off: nothing.
            if azos_decision::ON {
                note_wake_move(task, cpu, prio);
            }
            cpu
        },
    }
}

/// The CPU the energy model picks for the fair task `idx`
/// being woken, `None` where it does not apply and `find_best_cpu` decides.
///
/// Never for a real-time or deadline task (the load-based placement keeps
/// their liveness rule). The candidates are the online CPUs that balancing
/// also treats as general: not isolated, no real-time state. The task's
/// previous CPU is the one it last ran on (`context.tp`, as in
/// [`note_wake_move`]).
#[cfg(feature = "energy")]
#[inline(never)]
unsafe fn eas_wake_cpu(idx: usize, task: &Task, prio: u32) -> Option<usize> {
    if is_rt_priority(prio) || classes::class_of(idx) != Some(crate::sc::Class::Fair) {
        return None;
    }
    // The model names at most 32 CPUs.
    let online = NUM_ONLINE_CPUS.load(Ordering::Acquire).min(MAX_CPUS).min(ncpu()).min(32);
    if online < 2 {
        return None;
    }
    let isolated = fairq::isolated_cpus();
    let mut candidates = 0u32;
    for c in 0..online {
        if isolated >> c & 1 == 0 && !fairq::rt_cpu(c) {
            candidates |= 1 << c;
        }
    }
    let prev = (task.context.tp as usize).min(ncpu() - 1);
    energy::eas_place(idx, prev, candidates)
}

/// The wake-placement record of [`wake_target_cpu`]: only a migration.
#[inline(never)]
fn note_wake_move(task: &Task, cpu: usize, prio: u32) {
    let last = task.context.tp as usize;
    if last != cpu && last < ncpu() {
        azos_decision::record(
            azos_decision::Rule::WakePlacement,
            azos_decision::Verdict::Place,
            task.tid,
            [cpu as u64, last as u64, prio as u64],
        );
    }
}

/// The IPC-affinity exception to `find_best_cpu`'s placement
/// (`sched-ipc-affinity`; without it this is [`wake_target_cpu`]).
///
/// A synchronous IPC hand-off wakes a task whose waker blocks on the answer
/// right after: the call wakes the server and the client waits for the
/// reply; the reply wakes the client and the server goes back to accept.
/// The waker's hart is about to have nothing of the waker's to run, so the
/// woken task goes THERE — the seL4-style co-location that keeps a call/
/// reply pair on one hart (no cross-hart enqueue, no IPI, warm caches) —
/// instead of wherever `find_best_cpu` ranks best.
///
/// Liveness still outranks affinity, the same rule `find_best_cpu` keeps:
/// co-location is taken only if no competing resident of this hart other
/// than the woken task and the waker outranks the woken task (the waker is
/// left out because it is about to block; `pick_cpu_by_load`'s first two
/// keys would be zero). Otherwise, and for a pinned task, the ordinary
/// placement decides.
///
/// Through the `Placement` seam, like [`wake_target_cpu`]; the
/// co-location exception is part of `Legacy`. The irrefutable `let` is the
/// seam: it compiles only while `Legacy` is the one variant, so the stage
/// that adds `EnergyAware` (E5) must decide this path explicitly.
#[inline]
pub(super) unsafe fn ipc_wake_target_cpu(idx: usize, task: &Task) -> usize {
    let azos_energy::Placement::Legacy = azos_energy::seams::PLACEMENT;
    #[cfg(feature = "sched-ipc-affinity")]
    if task.cpu_affinity < 0 {
        let num_online = NUM_ONLINE_CPUS.load(Ordering::Acquire).min(MAX_CPUS);
        if num_online > 1 {
            let here = current_cpu_id();
            if here < num_online {
                let waker = PER_CPU[here].current_idx.load(Ordering::Relaxed);
                // Outranked or not, a server woken by a caller that holds a
                // reservation here goes here: it runs on that reservation
                // (`rt` proxy execution), above what outranks its own
                // priority. Asked only of an outranked wake.
                if !outranked_on(here, task.priority.load(Ordering::Relaxed), idx, waker)
                    || rt::proxy_target(here, waker, idx)
                {
                    return here;
                }
            }
        }
    }
    wake_target_cpu(idx, task)
}

/// Whether any competing resident of `cpu`, other than slots `a` and `b`,
/// outranks a task of priority `prio` (strictly lower bucket) — the
/// `blocking` key of `find_best_cpu`'s score for that one CPU.
#[cfg(all(feature = "sched-ipc-affinity", feature = "sched-o1-placement"))]
#[inline]
unsafe fn outranked_on(cpu: usize, prio: u32, a: usize, b: usize) -> bool {
    let key_of = |s: usize| if s < MAX_TASKS {
        HIST_KEY[s].load(Ordering::Relaxed)
    } else {
        resident_histogram::key::NONE
    };
    let (ka, kb) = (key_of(a), if b == a { resident_histogram::key::NONE } else { key_of(b) });
    RESIDENT_HIST
        .load_excluding(
            cpu,
            prio_bucket(prio),
            crate::task::RT_PRIORITY_THRESHOLD as usize,
            &[ka, kb],
        )
        .blocking
        > 0
}

/// Scan form of the above: stops at the first outranking resident.
#[cfg(all(feature = "sched-ipc-affinity", not(feature = "sched-o1-placement")))]
#[inline]
unsafe fn outranked_on(cpu: usize, prio: u32, a: usize, b: usize) -> bool {
    let bucket = prio_bucket(prio);
    for i in 0..MAX_TASKS {
        if i == a || i == b || !TASK_VALID[i].load(Ordering::Relaxed) {
            continue;
        }
        let t = &*core::ptr::addr_of!(TASKS[i]);
        let home = if t.cpu_affinity >= 0 {
            (t.cpu_affinity as usize).min(ncpu() - 1)
        } else {
            (t.context.tp as usize).min(ncpu() - 1)
        };
        if home != cpu || !crate::task::resident_competes(t.state()) {
            continue;
        }
        if prio_bucket(t.priority.load(Ordering::Relaxed)) < bucket {
            return true;
        }
    }
    false
}

pub fn try_wake_task(idx: usize, pred: &dyn Fn(&WaitReason) -> bool) {
    use crate::task::sched_word::{wake_transition, WakeTransition};
    if idx >= MAX_TASKS { return; }
    unsafe {
        if !TASK_VALID[idx].load(Ordering::Relaxed) { return; }
        let task = task_mut(idx);
        // K-C19: the Blocked→Ready transition is a CAS — exactly one waker
        // can win it, and the Acquire/Release pairing inside guarantees the
        // `wait_reason` the predicate reads is the one the blocker published
        // (K-C17). `stamp_if_unblocked = false`: this is the broadcast path;
        // a sweep cannot tell its addressee from any other task about to
        // sleep, so it must never stamp (see wait.rs).
        // K-C24: `saved` gates dispatch — a Blocked task whose context is
        // not yet saved is still RUNNING (unswitched block) and must be
        // stamped, never enqueued. See `sched_word::wake_transition`.
        // `saved` read after `Blocked` is seen (inside the transition).
        let saved_seen = core::cell::Cell::new(true);
        let wt = wake_transition(&task.state_word, || pred(&task.wait_reason), false, || {
            let s = !task.context_saving.load(Ordering::Acquire);
            saved_seen.set(s);
            s
        });
        let saved = saved_seen.get();
        note_unsaved_stamp(idx, saved, wt);
        if wt != WakeTransition::Dispatched { return; }
        task.ready_site.store(
            crate::task::ready_site::WAKE | ((current_cpu_id() as u8) << 4),
            Ordering::Relaxed,
        );
        #[cfg(feature = "ipc-census")]
        wakelat::arm(idx);

        let reason = attrib::Reason::of(&task.wait_reason);
        task.wait_reason = WaitReason::None;
        let target_cpu = wake_target_cpu(idx, task);
        // K-A11: the saved tp records the CPU this task is enqueued on (mirrors
        // rebalance_from_offline_cpus): the wake and balance paths read it as
        // the task's home. Bookkeeping only: context_switch saves it and never
        // loads it into the hart's tp (K1 M2), so a stale word misplaces a task,
        // it cannot make a hart run as another CPU.
        task.context.tp = target_cpu as CtxReg;
        note_wake_cold(task, reason, attrib::Via::Sweep, target_cpu);
        hist_reaccount(idx);
        wake_enqueue_preempting(target_cpu, idx, true);
    }
}


// ── WaitQueue support ───────────────────────────────────────────────────────

/// Block the current task on a WaitQueue.
/// Called via function pointer from `azos_sync::waitqueue`.
pub fn wq_block_current() {
    let cpu = current_cpu_id();
    block_current(cpu, WaitReason::WaitQueue);
}

/// Wake a blocked task by TID (used by WaitQueue).
/// Scans the task pool for a matching TID in WaitQueue-blocked state.
///
/// Reachable from IRQ context and, like `try_wake_task`, the
/// target CPU is often not the caller's own. See `try_wake_task` doc for the
/// locking rationale — same `cpu_enqueue_locked` wrapper, same guarantees.
pub fn wq_wake_by_tid(tid: u32) {
    use crate::task::sched_word::{wake_transition, WakeTransition};
    unsafe {
        if let Some(i) = idx_for_tid(tid) {
            let task = task_mut(i);
            // K-C9 + K-C19, in one transition:
            //  * Not Blocked yet (the caller — WaitQueue::wait() —
            //    registered itself as wake-able and is
            //    mid-way to wq_block_current()): stamp the wake so its
            //    commit consumes it. The stamp is a CAS conditioned on
            //    `state != Blocked`, so it can no longer land *after* the
            //    task committed (the old lost-wake half-window).
            //  * Blocked on WaitQueue: dispatch (CAS Blocked→Ready; the
            //    Acquire pairing guarantees the reason read is the published
            //    one — K-C17).
            //  * Blocked on something else (e.g. a Timer): genuine mismatch,
            //    not the K-C9 race — no stamp, this is not our task anymore.
            // K-C24: see try_wake_task — an unsaved Blocked target is still
            // running and gets a stamp, not an enqueue.
            let saved_seen = core::cell::Cell::new(true);
            let wt = wake_transition(
                &task.state_word,
                || task.wait_reason == WaitReason::WaitQueue,
                true,
                || {
                    let s = !task.context_saving.load(Ordering::Acquire);
                    saved_seen.set(s);
                    s
                },
            );
            let saved = saved_seen.get();
            note_unsaved_stamp(i, saved, wt);
            if wt != WakeTransition::Dispatched { return; }
            task.ready_site.store(
                crate::task::ready_site::WAKE | ((current_cpu_id() as u8) << 4),
                Ordering::Relaxed,
            );
            #[cfg(feature = "ipc-census")]
            wakelat::arm(i);

            let reason = attrib::Reason::of(&task.wait_reason);
            task.wait_reason = WaitReason::None;
            let target_cpu = wake_target_cpu(i, task);
            // K-A11: keep saved tp consistent with the enqueue CPU (see try_wake_task).
            task.context.tp = target_cpu as CtxReg;
            note_wake_cold(task, reason, attrib::Via::WaitQueue, target_cpu);
            hist_reaccount(i);
            // U02-1 fix: see try_wake_task / wake_enqueue_preempting.
            wake_enqueue_preempting(target_cpu, i, true);
        }
    }
}

// ── K-C10: TID-directed wake with K-C9 pending-wake treatment ───────────────

/// Wake the task whose TID is `tid`, if its `wait_reason` satisfies `pred`.
///
/// Returns `true` **only** when this call actually transitioned the target
/// Blocked → Ready and enqueued it. The "stamped `wake_pending` instead"
/// path returns `false`: nothing was dispatched here, the target will
/// short-circuit its own `block_current()` instead. Callers must not read
/// `false` as "the wake was lost".
///
/// # K-C10: why this exists next to `try_wake_task`
///
/// `try_wake_task` selects tasks by a **predicate over `wait_reason`** and
/// bails out early when `state != Blocked`. That early exit is a lost-wakeup
/// bug for every wake whose target is a specific task that is still *on its
/// way* to `Blocked`. The concrete case is `SYS_IPC_FAST_CALL`
/// (`crates/core/syscall/src/dispatch.rs`), whose sequence is:
///
///   1. reserve a fast-IPC slot (now visible to the server),
///   2. `wake_fast_ipc_server(server_tid)`,
///   3. `task_block(WaitReason::FastIpcClient(slot))`.
///
/// On SMP the server can wake, accept and reply **between 2 and 3**. Its
/// `wake_fast_ipc_client*` then finds the client not yet `Blocked`,
/// `try_wake_task` returns early, and the client proceeds to block on a wake
/// that will never come again — sleeping forever while pinning the slot.
/// `SYS_IPC_FAST_ACCEPT` is symmetric.
///
/// # Why this cannot be fixed inside `try_wake_task`
///
/// Stamping `wake_pending` from `try_wake_task` when the state is not
/// `Blocked` is **wrong** and must never be "simplified" into that. A task
/// that has not blocked yet has `wait_reason == WaitReason::None`, so the
/// predicate cannot possibly identify it: `try_wake_task` is called in a
/// sweep over all `MAX_TASKS` slots, so it would have to stamp *every*
/// not-yet-blocked task in the pool. That would make unrelated tasks skip
/// their next, entirely unrelated block — trading a hang for silent
/// cross-task corruption, which is strictly worse.
///
/// This function is safe to stamp because it selects by **TID**, which is
/// known independently of `state` and `wait_reason`. That is the invariant
/// to preserve: never widen this to a state-dependent selector. It is also
/// exactly why the broadcast wakes (`wake_by_ring`, `wake_by_port`,
/// `wake_expired_timers`) must NOT be
/// routed through here — they have no addressee TID.
///
/// # `pred` is a *cross-check*, not the selector
///
/// For all current callers the predicate is redundant with the TID by
/// construction: `WaitReason::FastIpcServer(t)` carries the blocked task's
/// own TID, and `FastIpcClient(slot)` names a
/// slot whose owner is that TID. `pred` therefore only distinguishes "this
/// task is blocked where I expect" from "this task is blocked on something
/// else entirely", i.e. it detects a genuine mismatch.
///
/// # Genuine mismatch: `break` without stamping (same rule as `wq_wake_by_tid`)
///
/// If the task is `Blocked` but `pred` rejects its `wait_reason`, we leave
/// `wake_pending` untouched. Rationale specific to these callers: between
/// making itself wake-able and calling `task_block`, the target is running
/// a straight-line stretch of its own syscall — it can be preempted to
/// `Ready`, but it cannot become `Blocked` on a *different* reason, because
/// there is no other block in that stretch. So `Blocked` + non-matching
/// reason means this is not the task we are addressing at all (stale TID,
/// TID reuse after exit, or a confused/malicious replier). Stamping there
/// would make an unrelated task skip an unrelated block. Same conclusion as
/// `wq_wake_by_tid`, reached for the same reason.
///
/// # Spurious `wake_pending` — bounded, and audited per call site
///
/// If the target was simply running unrelated work, the stamp survives and
/// makes its *next* `block_current()` return immediately. `block_current`
/// documents this as acceptable because waiters re-check their condition.
/// The caveat:
///   * the fast-IPC syscall path re-checks **once** and returns `-1`
///     rather than looping, so a stale stamp surfaces as a bogus `-1` to
///     userspace, not as a hang or as corruption (see the K-C10 report).
///
/// # First TID match wins — why that is safe
///
/// The scan stops at the first valid slot carrying `tid`. That is only
/// correct because TIDs are unique among valid slots: `NEXT_TID` increments
/// monotonically under `POOL_LOCK` and is never recycled (it wraps only after
/// 2^32 task creations, skipping 0). A `Zombie` slot does keep both
/// `TASK_VALID` and its TID until `do_schedule()` frees it — but its TID is
/// distinct from every live task's, so it can only be hit when the addressee
/// itself has exited. In that case it takes a `StampPending` on a slot that
/// is about to be released, which is inert: the old sweep also skipped
/// Zombies (`state != Blocked`), so this is not a regression.
///
/// # The selector invariant this depends on
///
/// Replacing "task blocked on reason R" with "task whose TID is `tid`" is
/// only sound while every `WaitReason` carrying a TID carries the *blocking
/// task's own* TID. Verified for the construction sites in
/// `crates/core/syscall/src/dispatch.rs`: `FastIpcServer(server_tid)` is
/// `current_task_tid()` of the task that is about to block, and
/// `FastIpcClient(slot)`'s slot was reserved by
/// `fast_ipc_call(caller_tid, ..)` for that same caller. If a future caller
/// blocks a task on another task's TID, it must NOT be woken through here.
///
/// # IRQ context and reentrancy
///
/// Safe to call from IRQ context, like `try_wake_task` and `wq_wake_by_tid`
/// (no IRQ-context caller of this function remains). It is safe there for the same reasons —
/// it never calls `do_schedule()`, it
/// touches the ready queue only via `cpu_enqueue_locked` (IRQ-safe, takes
/// `CPU_LOCKS[target_cpu]`, so it cannot race the target CPU's own
/// `do_schedule()`), and the target CPU is routinely not the caller's. The
/// stamp is a lock-free CAS on the task's own `state_word` (K-C19), so it
/// cannot deadlock against an interrupted critical section.
///
/// The policy lives in `wait::wake_action()` — a pure function with the full
/// truth table next to it — and since K-C19 the *transition* that enforces it
/// is host-tested too: `task::sched_word::wake_transition` is free code over
/// an `AtomicU32`, exercised directly by `sched-wake-tests`. Everything below
/// is the addressee scan plus the dispatch bookkeeping around that verdict.
/// Diagnostic counters for [`wake_task_by_tid`]: `(dispatched, stamped,
/// mismatched, absent)`.
///
/// `mismatched` is the one that matters. That branch drops a wake **without**
/// stamping, on the grounds that a blocked task whose reason does not match
/// is no longer the task the waker meant. If it ever fires for a wake that
/// WAS meant for that task, the result is a permanent sleep — the signature
/// K-C17/K-C19 chased (reply deposited, client blocked, nothing ready). Both
/// are closed; the counter stays because a nonzero value here under a hang is
/// still the fastest way to tell "predicate wrong" from "wake never sent".
///
/// `absent` counts wakes addressed to a TID with no valid task at all.
pub fn wake_counters() -> (u32, u32, u32, u32, u32, u32, u32) {
    (
        // Counted only in `ipc-census` builds (its only readers): 0 otherwise.
        WAKE_DISPATCHED.load(Ordering::Relaxed),
        WAKE_STAMPED.load(Ordering::Relaxed),
        WAKE_MISMATCHED.load(Ordering::Relaxed),
        WAKE_ABSENT.load(Ordering::Relaxed),
        WAKE_ENQ_REFUSED.load(Ordering::Relaxed),
        WAKE_LATE_DISPATCH.load(Ordering::Relaxed),
        SCHED_ENQ_REFUSED.load(Ordering::Relaxed),
    )
}

static WAKE_DISPATCHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_STAMPED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_MISMATCHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_ABSENT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
pub(super) static WAKE_ENQ_REFUSED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_LATE_DISPATCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Enqueues refused at the two `do_schedule`/rebalance sites that historically
/// ignored `cpu_enqueue_locked`'s answer (K-C26 discriminator 2).
///
/// **WHY it is counted rather than handled.** Both sites set the task `Ready`
/// *before* enqueuing it, so a refusal leaves it `Ready` in no queue at all —
/// which is precisely the K-C26 terminal signature (a task Ready, unqueued and
/// current on no hart). Reading the code says it cannot happen: `Full` is
/// unreachable while the `queued` invariant holds and would log `[SCHED] BUG`,
/// and `AlreadyQueued` needs someone to have enqueued a task that is Running,
/// which no path does — `boost_ready_task` checks the state first.
///
/// That argument is exactly the kind K-C26 has already defeated twice. Until a
/// run with the real signature is captured, the honest move is to make the
/// silent case *audible*: if this counter is ever non-zero, discriminator 2 is
/// answered and the genesis is here. Zero cost — one relaxed increment on a
/// path that is supposed never to run.
pub(super) static SCHED_ENQ_REFUSED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostic snapshot of what each hart is running right now: fills
/// `(tid, raw state_word, name)` per CPU (tid 0 = no current). Racy by
/// nature — reads without locks, display-only, same license as the rest of
/// the ipc-census family.
pub fn current_snapshot(out: &mut [(u32, u32, [u8; 8]); MAX_CPUS]) {
    unsafe {
        for cpu in 0..ncpu() {
            let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
            out[cpu] = if idx < MAX_TASKS && TASK_VALID[idx].load(Ordering::Relaxed) {
                let t = task_ref(idx);
                let mut name = [0u8; 8];
                let src = t.name;
                let n = src.iter().position(|&b| b == 0).unwrap_or(src.len()).min(8);
                name[..n].copy_from_slice(&src[..n]);
                (t.tid, t.state_word.load(Ordering::Acquire), name)
            } else {
                (0, 0, [0u8; 8])
            };
        }
    }
}

/// K-C25 reaper: deliver wakes that were stamped onto a task which then
/// parked (see `sched_word::reap_orphaned_stamp` for the full mechanism and
/// the measured wedge). Walks the pool once; called from the timer tick right
/// after `wake_expired_timers`, which already pays the same O(MAX_TASKS) walk
/// every tick — this adds one atomic load per valid task in the common case.
///
/// `Blocked + WAKE_STAMP` with `context_saving == false` is unambiguously an
/// orphaned delivered wake: with the context saved the target cannot consume
/// the stamp itself (it is not executing), `do_schedule`'s switch-away sweep
/// already ran (that is how the context got saved), and `wake_transition`
/// never stamps a saved task — so the stamp can only have landed in the
/// window between the sweep's check and context_switch.S clearing the flag.
/// While the flag is still true the target may be executing an unswitched
/// block and its own `commit_blocked_or_consume_wake` owns the stamp — those
/// are skipped and, if they park, caught on a later tick.
///
/// The walk runs only when [`STAMP_PENDING`] was set (w14 RTMAX). Every
/// `Blocked + WAKE_STAMP` comes from `wake_transition`'s `!saved` arm, and
/// each of its three callers stores the flag right after, in
/// [`note_unsaved_stamp`]. A tick landing between a waker's stamp CAS and its
/// flag store skips that stamp; the store sets the flag and the next tick
/// reaps it: one tick later than an unconditional walk, the same window
/// `sched-reap-event` has between its CAS and its mark. With no stamp
/// anywhere, the tick pays one swap instead of the 64-slot walk.
///
/// Recovery counts as `late_dispatch` in [`wake_counters`] — the counter has
/// been reserved (declared, read, never incremented) since K-C19 for exactly
/// this: a wake delivered later than its waker intended, by a third party.
pub fn reap_stamped_sleepers() {
    // Taken before the walk: a stamp made after this swap sets it again, and
    // one made before is seen by the walk (Release in the waker, AcqRel here).
    let _pending = STAMP_PENDING.swap(false, Ordering::AcqRel);
    // w14 RTMAX: no stamp was flagged since the last pass, so there is
    // nothing to reap; see the doc above for the one-tick window.
    #[cfg(not(feature = "sched-reap-event"))]
    if _pending {
        reap_sweep();
    }
    #[cfg(feature = "sched-reap-event")]
    {
        reap_pending::reap_marked();
        if reap_pending::any() {
            STAMP_PENDING.store(true, Ordering::Release);
        }
    }
    #[cfg(all(feature = "sched-o1-placement", feature = "ipc-census"))]
    hist_check::audit_tick(azos_drv_sys::timebase::now());
}

/// The walk of [`reap_stamped_sleepers`], out of line so the tick's common
/// case (nothing flagged) does not pay its register saves.
#[cfg(not(feature = "sched-reap-event"))]
#[inline(never)]
fn reap_sweep() {
    for i in 0..MAX_TASKS {
        // SAFETY: as `reap_one`'s callers always were: the tick ISR.
        if unsafe { reap_one(i) } == Reap::Again {
            STAMP_PENDING.store(true, Ordering::Release);
        }
    }
}

/// The safety net behind the tick's flag gate (owner decision, w14): a full
/// K-C25 walk run by the idle task, never by the tick, so a stamp whose waker
/// forgot `note_unsaved_stamp` is still delivered once the hart has nothing
/// else to do, and the tick never pays the walk.
///
/// * **Skip:** one load. `sched_word::REAPABLE_STAMPS` counts every
///   `Blocked + WAKE_STAMP` made (inside `wake_transition`, so a caller cannot
///   forget it); unchanged since the last complete walk means nothing new to
///   find. With `STAMP_PENDING` set the tick's walk owns the stamps, and idle
///   leaves them to it.
/// * **Same rules as the tick:** each `reap_one` runs with this hart's
///   interrupts masked, as in the ISR, so the tick's walk on this hart cannot
///   interleave with a slot here; walks on other harts already race each other
///   today and are settled by `reap_orphaned_stamp`'s CAS. Interrupts open
///   between slots, so a wake for a real task preempts the walk (the masked
///   window is one slot, not 64).
/// * **Bounded:** at most `MAX_TASKS` slots, once per change of the count. A
///   slot still switching away (`Reap::Again`) leaves the count unseen, so the
///   next idle pass looks again.
///
/// Returns true when it made a task ready: the idle loop must yield before
/// `wfi`. A hart that is never idle never runs this; another hart's idle does
/// (the walk covers every slot).
pub fn reap_idle_sweep() -> bool {
    let seen = crate::task::sched_word::reapable_stamps();
    if seen == IDLE_SWEPT.load(Ordering::Relaxed) || STAMP_PENDING.load(Ordering::Acquire) {
        return false;
    }
    reap_idle_walk(seen)
}

/// Last `REAPABLE_STAMPS` value a complete idle walk covered.
static IDLE_SWEPT: AtomicU32 = AtomicU32::new(0);

#[inline(never)]
fn reap_idle_walk(seen: u32) -> bool {
    let mut again = false;
    let mut reaped = false;
    for i in 0..MAX_TASKS {
        // Unmasked look first (reap_one's own first test, read-only): most
        // slots end here, and only a stamped one pays the masked window. A
        // stamp made after this look moves the count past `seen`, so the
        // next idle pass walks again.
        if !looks_reapable(i) {
            continue;
        }
        let s = azos_arch::ARCH.disable_all();
        // SAFETY: interrupts masked on this hart, as in the tick ISR.
        let r = unsafe { reap_one(i) };
        azos_arch::ARCH.restore(s);
        match r {
            Reap::Done => {}
            Reap::Again => again = true,
            Reap::Reaped => {
                reaped = true;
                #[cfg(feature = "ipc-census")]
                if REAP_IDLE.fetch_add(1, Ordering::Relaxed) == 0 {
                    azos_drv_sys::kprintln!("[SCHED] REAP_IDLE first: slot={}", i);
                }
            }
        }
    }
    if !again {
        IDLE_SWEPT.store(seen, Ordering::Relaxed);
    }
    reaped
}

/// `Blocked + WAKE_STAMP` on a valid slot: what `reap_one` acts on.
#[inline(always)]
fn looks_reapable(i: usize) -> bool {
    use crate::task::sched_word::{state_of, WAKE_STAMP};
    // SAFETY: atomic loads of the slot's valid flag and state word, the same
    // reads `reap_one` starts with.
    unsafe {
        if !TASK_VALID[i].load(Ordering::Relaxed) {
            return false;
        }
        let w = task_ref(i).state_word.load(Ordering::Acquire);
        w & WAKE_STAMP != 0 && state_of(w) == TaskState::Blocked
    }
}

/// `ipc-census`: wakes delivered by [`reap_idle_sweep`]. Each is a stamp no
/// flagged tick walk had reaped by the time its hart went idle: a stamp site
/// that forgets the flag shows here on every boot that reaches it. A waker
/// caught between its stamp CAS and its flag store also lands here (the
/// window `sched-reap-event`'s `UNMARKED` has).
#[cfg(feature = "ipc-census")]
pub static REAP_IDLE: AtomicU32 = AtomicU32::new(0);

/// `sched-reap-event`: mark `idx` for the reaper if this wake left a stamp
/// on a target that was still switching away. Compiles to nothing without
/// the feature.
#[inline(always)]
#[allow(unused_variables)]
fn note_unsaved_stamp(idx: usize, saved: bool, wt: crate::task::sched_word::WakeTransition) {
    if !saved && wt == crate::task::sched_word::WakeTransition::Stamped {
        #[cfg(feature = "sched-reap-event")]
        reap_pending::mark(idx);
        STAMP_PENDING.store(true, Ordering::Release);
    }
}

/// A wake was stamped onto a task still switching away, and no tick has
/// reaped it yet (K-C25). Only a timer interrupt runs the reaper, so while
/// this is set an idle hart must not sleep to its ceiling: the kernel's
/// idle-poll hook (`timebase::set_idle_poll_hook`) reads [`stamp_pending`].
/// Before wave 13 hart 0's fixed 100 ms keepalive was the reaper's last
/// resort on an idle machine; the keepalive now runs only while a hardware
/// watchdog is armed.
static STAMP_PENDING: AtomicBool = AtomicBool::new(false);

/// See [`STAMP_PENDING`].
#[inline]
pub fn stamp_pending() -> bool {
    STAMP_PENDING.load(Ordering::Acquire)
}

/// What [`reap_one`] did with a slot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Reap {
    /// Nothing to do for this stamp: no stamp, not `Blocked`, or another
    /// waker delivered it first.
    Done,
    /// `Blocked` with the stamp set but still switching away
    /// (`context_saving`) or current on some hart: look again next tick.
    Again,
    /// Recovered here: `Ready` and enqueued.
    Reaped,
}

/// One slot of [`reap_stamped_sleepers`].
pub(super) unsafe fn reap_one(i: usize) -> Reap {
    use crate::task::sched_word::{state_of, WAKE_STAMP};
    unsafe {
        {
            if !TASK_VALID[i].load(Ordering::Relaxed) { return Reap::Done; }
            let task = task_mut(i);
            let w = task.state_word.load(Ordering::Acquire);
            if w & WAKE_STAMP == 0 || state_of(w) != TaskState::Blocked {
                return Reap::Done;
            }
            // K-C24 gate, same read the wakers use. Stale note removed
            // 2026-09-26: this used to claim `rvv` never maintained the
            // flag, from when `context_switch_rvv.S` never cleared
            // `context_saving` — see the fix note a few hundred lines up
            // at the `do_schedule` gate. `Cargo.toml` dropped the `rvv`
            // feature entirely on 2026-09-24, so there is no such build
            // left to describe either way.
            if task.context_saving.load(Ordering::Acquire) {
                return Reap::Again;
            }
            // ABA guard (measured 2026-08-24, first reaper version): the
            // state word has no generation, so "Blocked+STAMP" can be the
            // SAME bit pattern twice with a full consume→run→re-block→
            // re-stamp cycle in between — and `context_saving` sampled in
            // that window reads false. A CAS alone then reaps a task that is
            // EXECUTING its unswitched-block loop, enqueueing a running task
            // (census signature: `READY-UNQUEUED name=autorun`, the exact
            // state K-C24 exists to prevent — the commit's defensive arm
            // then parks it Ready-in-no-queue forever). The discriminator a
            // recycled bit pattern cannot fake: a PARKED task is current on
            // no hart. A parked Blocked task can only become current again
            // by first leaving Blocked (dispatch CAS → our CAS fails), so
            // checking currency before the CAS closes the ABA.
            let mut is_current = false;
            for cpu in 0..ncpu() {
                if PER_CPU[cpu].current_idx.load(Ordering::Relaxed) == i {
                    is_current = true;
                    break;
                }
            }
            if is_current {
                return Reap::Again;
            }
            if crate::task::sched_word::reap_orphaned_stamp(&task.state_word) {
                WAKE_LATE_DISPATCH.fetch_add(1, Ordering::Relaxed);
                task.ready_site.store(
                    crate::task::ready_site::REAP | ((current_cpu_id() as u8) << 4),
                    Ordering::Relaxed,
                );
                // Same dispatch-ownership contract as `wake_task_by_tid`'s
                // Dispatched arm: winner clears the reason and enqueues,
                // keeping tp consistent with the enqueue CPU (K-A11).
                let reason = attrib::Reason::of(&task.wait_reason);
                task.wait_reason = WaitReason::None;
                let target_cpu = wake_target_cpu(i, task);
                task.context.tp = target_cpu as CtxReg;
                note_wake_cold(task, reason, attrib::Via::Reap, target_cpu);
                hist_reaccount(i);
                // U02-1 fix: see try_wake_task / wake_enqueue_preempting.
                if !wake_enqueue_preempting(target_cpu, i, true) {
                    WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                return Reap::Reaped;
            }
        }
    }
    Reap::Done
}

pub fn wake_task_by_tid(tid: u32, pred: &dyn Fn(&WaitReason) -> bool) -> bool {
    wake_task_by_tid_placed(idx_for_tid(tid), pred, false)
}

/// [`wake_task_by_tid`] for a synchronous IPC hand-off — the fast-IPC call
/// waking its server, the reply waking its client — where the waker is about
/// to block on the answer. Placement goes through [`ipc_wake_target_cpu`]
/// (the IPC-affinity exception) instead of [`wake_target_cpu`].
pub fn wake_task_by_tid_ipc(tid: u32, pred: &dyn Fn(&WaitReason) -> bool) -> bool {
    wake_task_by_tid_placed(idx_for_tid(tid), pred, true)
}

/// [`wake_task_by_tid`] for a caller that knows what the wake is (a futex wake,
/// a notify word): the attribution logs `src` instead of guessing it from the
/// task's wait (every timed sleep waits on a timer, whoever ends it). Placement
/// is the ordinary one.
pub fn wake_task_by_tid_as(tid: u32, pred: &dyn Fn(&WaitReason) -> bool, src: attrib::Src) -> bool {
    !matches!(
        wake_by_slot_as(idx_for_tid(tid), pred, false, NO_CLAIM, attrib::Via::As(src)),
        WakeOut::NotWoken
    )
}

/// The body of both: `slot` is `idx_for_tid(tid)`, resolved by the caller
/// so every TID lookup stays visibly in the public entry points.
#[inline(always)]
fn wake_task_by_tid_placed(slot: Option<usize>, pred: &dyn Fn(&WaitReason) -> bool, ipc: bool) -> bool {
    // `NO_CLAIM`: a constant, so the claim branch in `wake_by_slot` folds away
    // and this compiles to the same wake it always was.
    !matches!(wake_by_slot(slot, pred, ipc, NO_CLAIM), WakeOut::NotWoken)
}

/// `claim_cpu` value meaning "never claim, always enqueue".
const NO_CLAIM: usize = usize::MAX;

/// What [`wake_by_slot`] did with the addressee.
pub(super) enum WakeOut {
    /// Stamped, mismatched, or no such task: nothing was dispatched.
    NotWoken,
    /// Dispatched through a run queue, exactly as every wake did before.
    Enqueued,
    /// Dispatched (`Blocked` -> `Ready`, `wait_reason` cleared) but left in
    /// NO queue: the caller owns it and must either switch to it or enqueue it.
    /// Only returned when `claim_cpu != NO_CLAIM` and [`ipc_direct::allowed`]
    /// said yes for that hart. Only `ipc_wake_then_block` asks for a claim,
    /// and only with `sched-ipc-affinity`.
    #[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
    Claimed(usize),
}

/// The body of every TID-directed wake. With `claim_cpu == NO_CLAIM` it is the
/// ordinary wake; otherwise a dispatched addressee that
/// [`ipc_direct::allowed`] clears for `claim_cpu` is handed back as
/// [`WakeOut::Claimed`] instead of being enqueued.
#[inline(always)]
pub(super) fn wake_by_slot(
    slot: Option<usize>,
    pred: &dyn Fn(&WaitReason) -> bool,
    ipc: bool,
    claim_cpu: usize,
) -> WakeOut {
    wake_by_slot_as(slot, pred, ipc, claim_cpu, if ipc { attrib::Via::Ipc } else { attrib::Via::Targeted })
}

/// [`wake_by_slot`] with the way the wake is made told to the attribution
/// ([`attrib::Via`]): the one body of every TID-directed wake.
#[inline(always)]
pub(super) fn wake_by_slot_as(
    slot: Option<usize>,
    pred: &dyn Fn(&WaitReason) -> bool,
    ipc: bool,
    claim_cpu: usize,
    via: attrib::Via,
) -> WakeOut {
    use crate::task::sched_word::{wake_transition, WakeTransition};
    unsafe {
        // `idx_for_tid` answers only for a slot that is valid AND carries this
        // TID, so an invalid slot's stale `Task` is never read and `pred` is
        // never evaluated for a non-addressee. It used to be a 64-slot scan
        // written out here (~490 instructions per wake, two wakes per IPC round
        // trip); TID 0, which never names a task, no longer matches a slot that
        // is mid-allocation.
        if let Some(i) = slot {
            let task = task_mut(i);

            // K-C19: decision and transition are one CAS protocol now —
            // `wake_transition` enforces the `wait::wake_action` truth table
            // (its doc still holds), with the two windows closed:
            // a stamp can no longer land after the addressee committed to
            // Blocked, and a dispatch CAS can be won by exactly one waker.
            // The Acquire pairing inside replaces the old K-C17 fence.
            // K-C24: `saved` keeps an unswitched-block target (Blocked but
            // still executing) out of the ready queues — stamp instead.
            let saved_seen = core::cell::Cell::new(true);
            let wt = wake_transition(&task.state_word, || pred(&task.wait_reason), true, || {
                let s = !task.context_saving.load(Ordering::Acquire);
                saved_seen.set(s);
                s
            });
            let saved = saved_seen.get();
            match wt {
                WakeTransition::Stamped => {
                    note_unsaved_stamp(i, saved, WakeTransition::Stamped);
                    WAKE_STAMPED.fetch_add(1, Ordering::Relaxed);
                    // K-C9/K-C10: the addressee had not committed to Blocked
                    // yet; its commit CAS will now fail, consume the stamp,
                    // and skip the block.
                    return WakeOut::NotWoken;
                }
                // Genuine mismatch: no stamp, and do NOT keep scanning —
                // TIDs are unique among valid tasks.
                WakeTransition::Mismatch => {
                    WAKE_MISMATCHED.fetch_add(1, Ordering::Relaxed);
                    return WakeOut::NotWoken;
                }
                WakeTransition::Dispatched => return dispatched(i, task, ipc, claim_cpu, via),
                // Unreachable with `stamp_if_unblocked = true`; kept so the
                // match stays exhaustive against the transition's contract.
                WakeTransition::NotBlocked => return WakeOut::NotWoken,
            }
        }
        // Every arm above returns, so reaching here means no valid slot
        // carried this TID.
        WAKE_ABSENT.fetch_add(1, Ordering::Relaxed);
    }
    WakeOut::NotWoken
}


/// The `Dispatched` arm of [`wake_by_slot`]: `task` (slot `i`) was just moved
/// `Blocked -> Ready` by this hart's CAS, so its dispatch is ours. Clears its
/// wait, then either hands it back [`WakeOut::Claimed`] (`claim_cpu !=
/// NO_CLAIM` and [`ipc_direct::allowed`] said yes) or enqueues it as every
/// wake does. Shared with the IPC fast path ([`ipc_fast_handoff`]), whose
/// claim is its own CAS.
#[inline(always)]
pub(super) unsafe fn dispatched(i: usize, task: &mut Task, ipc: bool, claim_cpu: usize, via: attrib::Via) -> WakeOut {
    unsafe {
        task.ready_site.store(
            crate::task::ready_site::WAKE | ((current_cpu_id() as u8) << 4),
            Ordering::Relaxed,
        );
        #[cfg(feature = "ipc-census")]
        wakelat::arm(i);
        // Read only by the `ipc-census` reports (`wake_counters`).
        #[cfg(feature = "ipc-census")]
        WAKE_DISPATCHED.fetch_add(1, Ordering::Relaxed);
        // What it waited on, for the attribution: read before the clear.
        let reason = attrib::Reason::of(&task.wait_reason);
        task.wait_reason = WaitReason::None;
        // Direct-switch claim: keep the task out of every queue and
        // hand it to the caller, who switches to it on `claim_cpu`
        // without a trip through `do_schedule`'s pick.
        if claim_cpu != NO_CLAIM {
            let prio = task.priority.load(Ordering::Relaxed);
            let cur = PER_CPU[claim_cpu].current_idx.load(Ordering::Relaxed);
            let cur_idle = cur < MAX_TASKS
                && task_ref(cur).priority.load(Ordering::Relaxed)
                    == crate::task::IDLE_PRIORITY;
            let target_saved = !task.context_saving.load(Ordering::Acquire);
            #[cfg(feature = "ipc-census")]
            if !target_saved {
                IPC_DIRECT_UNSAVED.fetch_add(1, Ordering::Relaxed);
            }
            if cur < MAX_TASKS && core_direct_ok(claim_cpu, cur, i) && ipc_direct::allowed(ipc_direct::DirectSwitch {
                ready_bitmap: PER_CPU[claim_cpu].ready_bitmap.load(Ordering::Relaxed),
                target_bucket: prio_bucket(prio),
                target_affinity: task.cpu_affinity,
                cpu: claim_cpu,
                target_is_idle: prio == crate::task::IDLE_PRIORITY,
                current_is_idle: cur_idle,
                deadline_live: rt::holds_direct_switch(
                    claim_cpu, prio, task_ref(cur).priority.load(Ordering::Relaxed)),
                // Read after the CAS, not the `saved` read before
                // it — see the field's doc.
                target_saved,
            }) {
                task.context.tp = claim_cpu as CtxReg;
                // Wave 15 (TRACE): a claimed wake never queues.
                if azos_trace::sched_on() {
                    azos_trace::raw::sched_wakeup(task.tid, claim_cpu as u32, current_task_tid());
                }
                note_wake(task, reason, via, claim_cpu);
                return WakeOut::Claimed(i);
            }
        }
        let target_cpu = if ipc {
            ipc_wake_target_cpu(i, task)
        } else {
            wake_target_cpu(i, task)
        };
        #[cfg(feature = "ipc-census")]
        if ipc {
            ipc_placement::record(target_cpu);
        }
        // K-A11: the saved tp records the enqueue CPU, the task's
        // home for the next wake and balance (bookkeeping only:
        // context_switch never loads it into the hart's tp).
        task.context.tp = target_cpu as CtxReg;
        note_wake(task, reason, via, target_cpu);
        hist_reaccount(i);
        // The return value matters: a refused enqueue leaves the
        // task `Ready` and in no queue at all, which is worse than
        // the sleep it was meant to end. Counted, not ignored.
        // U02-1 fix: see try_wake_task / wake_enqueue_preempting.
        if !wake_enqueue_preempting(target_cpu, i, !ipc) {
            WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        WakeOut::Enqueued
    }
}

// ── M03: Tickless scheduling helpers ────────────────────────────────────────

/// Return the nearest pending timer deadline across all blocked tasks.
///
/// Used by the tickless scheduler to program mtimecmp at the exact tick needed
/// rather than firing at a fixed periodic rate.  Returns `None` if no tasks
/// are currently sleeping on a timer.
///
/// With `sched-timer-heap` this is the heap's top after dropping stale
/// entries (see [`timer_sleepers`]); without it, the O(`MAX_TASKS`) sweep
/// below. Under `ipc-census` the heap build also runs the sweep and counts
/// disagreements (`timer_sleepers::NEAREST_MISMATCH`).
pub fn nearest_timer_deadline() -> Option<u64> {
    #[cfg(feature = "sched-timer-heap")]
    {
        let got = timer_sleepers::nearest();
        #[cfg(feature = "ipc-census")]
        timer_sleepers::check_nearest(got, nearest_timer_deadline_sweep_where(timer_sleepers::owned_here));
        got
    }
    #[cfg(not(feature = "sched-timer-heap"))]
    nearest_timer_deadline_sweep()
}

/// The O(`MAX_TASKS`) sweep: the whole of `nearest_timer_deadline` without
/// `sched-timer-heap` (its census cross-check sweeps this CPU's slots only).
#[cfg_attr(feature = "sched-timer-heap", allow(dead_code))]
fn nearest_timer_deadline_sweep() -> Option<u64> {
    nearest_timer_deadline_sweep_where(|_| true)
}

/// The sweep over the slots `keep` selects (the census: this CPU's heap's).
#[cfg_attr(
    all(feature = "sched-timer-heap", not(feature = "ipc-census")),
    allow(dead_code)
)]
#[inline(always)]
fn nearest_timer_deadline_sweep_where(keep: impl Fn(usize) -> bool) -> Option<u64> {
    let mut min_deadline: Option<u64> = None;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) || !keep(i) { continue; }
            let task = task_ref(i);
            // Acquire pairs with block_current's Release commit: it publishes
            // the `wait_reason` (and deadline) we read next (K-C17).
            if task.state_acquire() != TaskState::Blocked { continue; }
            if let WaitReason::Timer(deadline) = task.wait_reason {
                // The instant the heap fires it at (QoS timer slack).
                #[cfg(feature = "sched-timer-heap")]
                let deadline = timer_sleepers::fire_of(i, deadline);
                min_deadline = Some(match min_deadline {
                    Some(cur) => cur.min(deadline),
                    None      => deadline,
                });
            }
        }
    }
    min_deadline
}

/// `wait::wake_expired_timers` with `sched-timer-heap`: the pure pass
/// `timer_heap::wake_due` (batches of `SCHED_TIMER_WAKE_BATCH`, the lock
/// never held across a wake, the retry re-armed with a deadline read under
/// the lock) over the live heap, waking each popped slot with the sweep's
/// own predicate. The host runner drives the same pass under a model of
/// another hart (`timer_heap`'s `wake_due_*` tests).
#[cfg(feature = "sched-timer-heap")]
pub(crate) fn wake_expired_timers_heap(now_ticks: u64) {
    let due = timer_sleepers::Due::here();
    if !due.ready() {
        return;
    }
    crate::timer_heap::wake_due::<MAX_TASKS, { azos_limits::SCHED_TIMER_WAKE_BATCH }, _>(
        &due,
        now_ticks,
    );
    #[cfg(feature = "ipc-census")]
    timer_sleepers::check_tick(now_ticks);
}
