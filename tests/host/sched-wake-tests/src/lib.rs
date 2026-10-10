// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for the K-C10 wake logic in `crates/core/sched/src/wait.rs`.
//!
//! # What is real here and what is not — read this before trusting a green run
//!
//! `crates/core/sched/src/scheduler.rs` cannot be compiled for the host: static
//! `TASKS`/`PER_CPU` arrays, RISC-V CSR reads (`read_sstatus`), an assembly
//! context switch, and `current_cpu_id()` reading `tp`. Refactoring it to be
//! host-buildable would mean rewriting the core of a production scheduler,
//! which is far more dangerous than the race K-C10 closes. So it is **not**
//! compiled here.
//!
//! What *is* compiled from the kernel tree, unmodified, via `#[path]`:
//!
//!   * `crates/core/sched/src/task.rs` — the real `WaitReason`, `TaskState`,
//!     `Task`, the real `MAX_TASKS`, and since K-C19 the real `sched_word`
//!     transition protocol (state + wake stamp in one atomic word). It has
//!     no dependency beyond `azos_limits`.
//!   * `crates/core/sched/src/wait.rs` — the real `wake_action()` truth table and
//!     the real wake entry points with their real `WaitReason` predicates.
//!
//! What is stubbed (`smp`, `scheduler` below): only the *mechanism* —
//! scanning the task pool, flipping `state`, and `cpu_enqueue_locked`. The
//! stub records every call so the tests can assert which primitive each wake
//! routed to and exactly which `WaitReason` values its predicate accepts.
//!
//! So these tests prove: (1) the K-C10 decision table is what the kernel
//! executes, because `wake_task_by_tid` matches on `wait::wake_action()`;
//! (2) each targeted wake addresses the right TID with the right predicate;
//! (3) the broadcast wakes still use the sweep and were not swept into the
//! TID path. They do **not** prove the SMP interleaving itself — that needs
//! the ring-3 scenario described at the bottom of this file.

// The real task definitions — no stubs, no copies.
//
// `task.rs` re-exports the syscall filter and the creation-time `TaskInit`
// from `filter.rs` (they are pure policy types with no TCB dependency, kept
// separate so `tests/host/seccomp-tests` can reach them), so that module has to
// be pulled in alongside it.
#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/filter.rs"]
pub mod filter;

#[path = "../../../../crates/core/sched/src/task.rs"]
pub mod task;

/// Stub for `crate::smp`. `wait::task_block()` only needs a CPU id; the real
/// one reads the RISC-V `tp` register.
pub mod smp {
    pub fn current_cpu_id() -> usize { 0 }
}

/// Stub for `crate::scheduler`, recording instead of scheduling.
///
/// Every call is logged together with the result of applying the caller's
/// predicate to a fixed probe set (`probes()`), which is how the tests get at
/// the closures `wait.rs` builds internally.
pub mod scheduler {
    use crate::task::WaitReason;
    use std::sync::Mutex;

    /// Fixed probe set. Index positions are stable and referenced by the
    /// tests via `probe_index()`.
    pub fn probes() -> Vec<WaitReason> {
        vec![
            WaitReason::None,
            WaitReason::WaitQueue,
            WaitReason::Timer(1234),
            WaitReason::Irq(5),
            WaitReason::Channel(5),
            WaitReason::Ring(5),
            WaitReason::Port(5),
            WaitReason::FastIpcServer(7),
            WaitReason::FastIpcServer(8),
            WaitReason::FastIpcClient(3),
            WaitReason::FastIpcClient(4),
            // Appended, so the indices above stay put. Lessee 7 (the same TID
            // as the fast-IPC server probes) accepting from lessor 21 or 22,
            // and lessee 8 accepting from 21.
            WaitReason::LeaseAccept(7, 21),
            WaitReason::LeaseAccept(7, 22),
            WaitReason::LeaseAccept(8, 21),
            // Appended: a second port reference, so a port wake's predicate
            // that ignores the reference accepts both.
            WaitReason::Port(6),
            // Appended: a second IRQ line, so an IRQ-waiter wake's predicate
            // that ignores the line accepts both.
            WaitReason::Irq(6),
        ]
    }

    pub fn probe_index(r: WaitReason) -> usize {
        probes().iter().position(|p| *p == r).expect("probe not in set")
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum Call {
        /// `try_wake_task(idx, pred)` — the sweep path.
        Sweep { idx: usize, accepts: Vec<WaitReason> },
        /// `wake_task_by_tid(tid, pred)` — the K-C10 targeted path.
        ByTid { tid: u32, accepts: Vec<WaitReason> },
        /// `wake_task_by_tid_ipc(tid, pred)` — the same path, placed by the
        /// IPC-affinity rule (fast-IPC call/reply hand-offs only).
        ByTidIpc { tid: u32, accepts: Vec<WaitReason> },
        /// `block_current(cpu, reason)`.
        Block { cpu: usize, reason: WaitReason },
    }

    pub static LOG: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    pub fn reset() { LOG.lock().unwrap().clear(); }
    pub fn log() -> Vec<Call> { LOG.lock().unwrap().clone() }

    fn accepted(pred: &dyn Fn(&WaitReason) -> bool) -> Vec<WaitReason> {
        probes().into_iter().filter(|r| pred(r)).collect()
    }

    pub fn block_current(cpu: usize, reason: WaitReason) {
        LOG.lock().unwrap().push(Call::Block { cpu, reason });
    }

    pub fn try_wake_task(idx: usize, pred: &dyn Fn(&WaitReason) -> bool) {
        let accepts = accepted(pred);
        LOG.lock().unwrap().push(Call::Sweep { idx, accepts });
    }

    /// Kconfig CHAOS stand-in: no injection on the host, the clock as given.
    pub fn chaos_sweep_now(now_ticks: u64) -> u64 { now_ticks }

    /// Plan item 7 stand-ins: no forced stop is ever pending on the host.
    pub fn forced_stop_pending() -> bool { false }
    pub fn current_forced_exit() -> Option<i32> { None }

    pub fn wake_task_by_tid(tid: u32, pred: &dyn Fn(&WaitReason) -> bool) -> bool {
        let accepts = accepted(pred);
        LOG.lock().unwrap().push(Call::ByTid { tid, accepts });
        false
    }

    pub fn wake_task_by_tid_ipc(tid: u32, pred: &dyn Fn(&WaitReason) -> bool) -> bool {
        let accepts = accepted(pred);
        LOG.lock().unwrap().push(Call::ByTidIpc { tid, accepts });
        false
    }
}

// The real wake logic, compiled against the real `task` and the stubs above.
#[path = "../../../../crates/core/sched/src/wait.rs"]
pub mod wait;

#[cfg(test)]
mod tests {
    use super::scheduler::{self, Call};
    use super::task::{TaskState, WaitReason, MAX_TASKS};
    use super::wait::{self, WakeAction};
    use core::sync::atomic::Ordering;

    // The stub log is a process-wide singleton and `cargo test` runs tests in
    // threads, so every test that inspects it must hold this lock.
    static LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_log<R>(f: impl FnOnce() -> R) -> R {
        let _g = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        scheduler::reset();
        f()
    }

    // ── 1. The K-C10 truth table ────────────────────────────────────────────

    #[test]
    fn wake_action_covers_the_full_truth_table() {
        // Not the addressee: nothing else is consulted.
        for &blocked in &[false, true] {
            for &matches in &[false, true] {
                assert_eq!(
                    wait::wake_action(false, blocked, matches),
                    WakeAction::Skip,
                    "non-addressee must always Skip (blocked={blocked}, matches={matches})"
                );
            }
        }
        // Addressee, not yet Blocked: this is the lost-wakeup window.
        assert_eq!(wait::wake_action(true, false, false), WakeAction::StampPending);
        assert_eq!(wait::wake_action(true, false, true), WakeAction::StampPending);
        // Addressee, Blocked on something else: genuine mismatch.
        assert_eq!(wait::wake_action(true, true, false), WakeAction::Mismatch);
        // Addressee, Blocked, reason matches: the ordinary wake.
        assert_eq!(wait::wake_action(true, true, true), WakeAction::Dispatch);
    }

    #[test]
    fn wake_action_is_a_total_function_of_three_bools() {
        // Guards against someone adding a fourth outcome without a rule:
        // all eight input combinations must land in the four known actions.
        let mut seen = [false; 4];
        for &a in &[false, true] {
            for &b in &[false, true] {
                for &c in &[false, true] {
                    match wait::wake_action(a, b, c) {
                        WakeAction::Skip => seen[0] = true,
                        WakeAction::StampPending => seen[1] = true,
                        WakeAction::Mismatch => seen[2] = true,
                        WakeAction::Dispatch => seen[3] = true,
                    }
                }
            }
        }
        assert_eq!(seen, [true; 4], "every action must be reachable");
    }

    #[test]
    fn only_stamp_pending_is_reachable_when_not_blocked() {
        // The property that makes K-C10 correct: a task that has not blocked
        // yet can never be Dispatched (its wait_reason is None, so no
        // targeted predicate accepts it) and must never be judged a Mismatch
        // (that would drop the wake — the original bug).
        for &matches in &[false, true] {
            let a = wait::wake_action(true, false, matches);
            assert_ne!(a, WakeAction::Dispatch);
            assert_ne!(a, WakeAction::Mismatch);
        }
    }

    // ── 2. The K-C9/K-C19 handshake — the REAL protocol, not a model ────────
    //
    // Until K-C19 this section *modelled* block/wake over the removed
    // `wake_pending: AtomicBool`, replicating scheduler.rs by hand — exactly
    // the "test that replicates the logic it guards" trap. The protocol now
    // lives in `task::sched_word` as free functions over an `AtomicU32`, so
    // these tests execute the kernel's own transition code.

    use super::task::sched_word::{
        self, commit_blocked_or_consume_wake, reap_orphaned_stamp,
        wake_transition, WakeTransition, STATE_MASK, WAKE_STAMP,
    };
    use core::sync::atomic::AtomicU32;

    fn word(s: TaskState) -> AtomicU32 { AtomicU32::new(sched_word::pack(s)) }
    fn state_now(w: &AtomicU32) -> TaskState {
        sched_word::state_of(w.load(Ordering::Acquire))
    }
    fn stamped(w: &AtomicU32) -> bool {
        w.load(Ordering::Acquire) & WAKE_STAMP != 0
    }
    /// A targeted wake with a matching reason, as `wake_task_by_tid` issues
    /// it against a PARKED target (context saved — the common case).
    fn wake(w: &AtomicU32, reason_matches: bool) -> WakeTransition {
        wake_transition(w, || reason_matches, true, || true)
    }

    /// The same wake against an UNSAVED target (K-C24: Blocked but still
    /// executing past an unswitched block).
    fn wake_unsaved(w: &AtomicU32, reason_matches: bool) -> WakeTransition {
        wake_transition(w, || reason_matches, true, || false)
    }

    /// Wave 13 (RT7): `saved` is read only once `Blocked` has been seen. The
    /// blocker sets `context_saving` BEFORE its Release commit, so only a read
    /// that follows the Acquire load of `Blocked` is guaranteed to see it; a
    /// read made before (the old `bool` argument) could be `saved` from the
    /// task's previous switch and dispatch a task still running on its hart.
    /// Model: the "flag" flips to unsaved at the commit; a waker that read it
    /// first would see saved.
    #[test]
    fn saved_is_read_after_blocked_is_seen() {
        use core::cell::Cell;
        // Not Blocked: the flag is never consulted.
        let w = word(TaskState::Running);
        let asked = Cell::new(0);
        assert_eq!(wake_transition(&w, || true, true, || { asked.set(asked.get() + 1); true }),
                   WakeTransition::Stamped);
        assert_eq!(asked.get(), 0, "saved() consulted before Blocked was seen");
        // The blocker commits (flag already unsaved): the late read stamps.
        let w = word(TaskState::Blocked);
        let flag_saved = Cell::new(false); // the commit's earlier store: unsaved
        assert_eq!(wake_transition(&w, || true, true, || flag_saved.get()), WakeTransition::Stamped,
                   "an unsaved Blocked task must be stamped, not dispatched");
        assert_eq!(state_now(&w), TaskState::Blocked);
    }

    /// The scheduler's wakers pass the flag read INSIDE the transition, never a
    /// value read before it (source check; the race needs SMP timing to show).
    /// Canary: put back `let saved = !task.context_saving.load(..)` before a
    /// `wake_transition(` call and this fails.
    #[test]
    fn scheduler_wakers_read_saved_late() {
        const SCHED: &str = include_str!("../../../../crates/core/sched/src/scheduler.rs");
        assert!(!SCHED.contains("let saved = !task.context_saving.load("),
                "a waker reads context_saving before the transition sees Blocked");
        assert_eq!(SCHED.matches("wake_transition(").count(), 3, "every waker reviewed");
        assert_eq!(SCHED.matches("saved_seen.set(s);").count(), 3, "every waker reads it late");
    }

    #[test]
    fn wake_before_block_does_not_sleep() {
        // The exact SYS_IPC_FAST_CALL race: server replies between the
        // client's wake_fast_ipc_server() and its task_block().
        let w = word(TaskState::Running);

        assert_eq!(wake(&w, true), WakeTransition::Stamped,
                   "nothing to dispatch — client is still Running");
        assert!(stamped(&w), "the wake must have been stamped");

        assert!(!commit_blocked_or_consume_wake(&w),
                "K-C9: the client must skip blocking, not sleep forever");
        assert_eq!(state_now(&w), TaskState::Running);
        assert!(!stamped(&w), "the stamp must be consumed exactly once");
    }

    #[test]
    fn wake_after_block_dispatches_normally() {
        let w = word(TaskState::Running);

        assert!(commit_blocked_or_consume_wake(&w));
        assert_eq!(state_now(&w), TaskState::Blocked);

        assert_eq!(wake(&w, true), WakeTransition::Dispatched);
        assert_eq!(state_now(&w), TaskState::Ready);
        assert!(!stamped(&w), "an ordinary wake must not stamp");
    }

    #[test]
    fn stamp_is_consumed_once_not_latched() {
        // A latched stamp would make every subsequent block a no-op — the
        // task would spin instead of sleeping.
        let w = word(TaskState::Running);
        wake(&w, true);

        assert!(!commit_blocked_or_consume_wake(&w), "first block consumes the stamp");
        assert!(commit_blocked_or_consume_wake(&w), "second block must actually sleep");
        assert_eq!(state_now(&w), TaskState::Blocked);
    }

    #[test]
    fn two_wakes_before_block_still_consume_once() {
        // The stamp is an idempotent bit (see the truth table): two early
        // wakes skip one block, not two.
        let w = word(TaskState::Running);
        assert_eq!(wake(&w, true), WakeTransition::Stamped);
        assert_eq!(wake(&w, true), WakeTransition::Stamped);

        assert!(!commit_blocked_or_consume_wake(&w));
        assert!(commit_blocked_or_consume_wake(&w), "only one block is skipped");
    }

    #[test]
    fn mismatch_while_blocked_touches_nothing() {
        // The rule that stops K-C10 turning a hang into cross-task
        // corruption: a task blocked on an unrelated reason must not be
        // marked, or it would skip its own next, unrelated wait.
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));

        assert_eq!(wake(&w, /* reason_matches */ false), WakeTransition::Mismatch);
        assert_eq!(state_now(&w), TaskState::Blocked, "must stay asleep");
        assert!(!stamped(&w), "mismatch must never stamp");
    }

    #[test]
    fn broadcast_wake_never_stamps() {
        // `try_wake_task` (the sweep path) passes `stamp_if_unblocked =
        // false`: a sweep cannot tell its addressee from any other task about
        // to sleep, so stamping there would hand random tasks a phantom wake.
        let w = word(TaskState::Running);
        assert_eq!(wake_transition(&w, || true, false, || true), WakeTransition::NotBlocked);
        assert!(!stamped(&w));
        assert_eq!(state_now(&w), TaskState::Running);
    }

    // ── 2b. K-C19: the invariant is structural now ──────────────────────────

    #[test]
    fn a_stamped_word_cannot_commit_to_blocked() {
        // The blocker half of K-C19: committing past a pending wake is not a
        // race that discipline avoids — the CAS refuses it.
        let w = word(TaskState::Running);
        wake(&w, true);
        for _ in 0..3 {
            assert!(!commit_blocked_or_consume_wake(&w) || state_now(&w) == TaskState::Blocked);
            if state_now(&w) == TaskState::Blocked { break; }
        }
        // After the first (consuming) call the state must still be Running —
        // never Blocked-with-a-wake-outstanding.
        assert_ne!(w.load(Ordering::Acquire),
                   sched_word::pack(TaskState::Blocked) | WAKE_STAMP,
                   "Blocked with the stamp set must be unrepresentable");
    }

    #[test]
    fn a_committed_word_cannot_be_stamped() {
        // The waker half of K-C19: once the task is Blocked, a targeted wake
        // must dispatch (or mismatch) — it can never leave a stamp behind for
        // nobody to consume. This was the measured ~1-in-3 permanent sleep.
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));

        assert_eq!(wake(&w, true), WakeTransition::Dispatched,
                   "a wake against a Blocked task must dispatch, never stamp");
        assert!(!stamped(&w));
    }

    #[test]
    fn blocked_with_stamp_is_unreachable_from_every_interleaving() {
        // Exhaustive over every serialized order of one blocker step and up
        // to two wakes: the two rows deliberately absent from the K-C10
        // truth table must be unrepresentable outcomes, whatever the order.
        type Step = u8; // 0 = commit, 1 = matching wake, 2 = mismatched wake
        fn run(steps: &[Step]) -> u32 {
            let w = word(TaskState::Running);
            for s in steps {
                match s {
                    0 => { let _ = commit_blocked_or_consume_wake(&w); }
                    1 => { let _ = wake(&w, true); }
                    _ => { let _ = wake(&w, false); }
                }
            }
            w.load(Ordering::Acquire)
        }
        for a in 0..3u8 {
            for b in 0..3u8 {
                for c in 0..3u8 {
                    let end = run(&[a, b, c]);
                    let is_blocked =
                        end & STATE_MASK == sched_word::pack(TaskState::Blocked);
                    let has_stamp = end & WAKE_STAMP != 0;
                    assert!(!(is_blocked && has_stamp),
                            "steps {a},{b},{c} produced Blocked+stamp");
                }
            }
        }
    }

    // ── 2c. K-C24: Blocked does not mean parked ─────────────────────────────
    //
    // `block_current`'s do_schedule can find nothing to run and RETURN: the
    // task keeps executing with `state == Blocked` and its context unsaved.
    // Dispatching it then enqueues a RUNNING task — measured as the phase-A
    // server sitting `Ready` in no queue forever. The `saved` gate turns
    // those wakes into stamps.

    #[test]
    fn an_unsaved_blocked_target_is_stamped_never_dispatched() {
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w)); // Blocked, still running
        assert_eq!(wake_unsaved(&w, true), WakeTransition::Stamped,
                   "dispatching an unswitched block enqueues a running task");
        assert_eq!(state_now(&w), TaskState::Blocked, "state must not move");
        assert!(stamped(&w));
        // The task loops back into its next block attempt: the commit
        // consumes the stamp AND normalizes to Running in one CAS — leaving
        // Blocked behind on the skip path would re-expose the bug.
        assert!(!commit_blocked_or_consume_wake(&w), "stamp must be consumed");
        assert_eq!(state_now(&w), TaskState::Running,
                   "skip path must normalize the word to the truth");
        assert!(!stamped(&w));
    }

    #[test]
    fn a_mismatched_unsaved_target_is_left_alone() {
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));
        assert_eq!(wake_unsaved(&w, false), WakeTransition::Mismatch);
        assert_eq!(state_now(&w), TaskState::Blocked);
        assert!(!stamped(&w), "a mismatch must not stamp, saved or not");
    }

    #[test]
    fn a_parked_stamp_is_swept_by_the_dispatch_cas() {
        // If the task DOES get parked with a K-C24 stamp set (do_schedule's
        // Blocked-arm conversion races are re-covered kernel-side), a later
        // targeted wake against the now-saved task must deliver: the
        // dispatch CAS replaces the whole word, stamp included.
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));
        assert_eq!(wake_unsaved(&w, true), WakeTransition::Stamped);
        // ...task gets switched out; context saved; a fresh wake arrives:
        assert_eq!(wake(&w, true), WakeTransition::Dispatched);
        assert_eq!(state_now(&w), TaskState::Ready);
        assert!(!stamped(&w), "dispatch must sweep the stamp with the state");
    }

    // ── 2d. K-C25: an orphaned parked stamp needs a reaper ──────────────────
    //
    // The leg 2c's sweep test cannot cover: the stamp lands AFTER
    // do_schedule's switch-away sweep checked and the task parks with it set.
    // A later wake WOULD sweep it (test above) — but the one-shot wakes
    // (fast-IPC reply, RPC) fire exactly once, and at the measured wedge
    // every possible waker was already asleep. `reap_orphaned_stamp`, driven
    // by the timer tick, is that state's designated consumer.

    #[test]
    fn an_orphaned_parked_stamp_is_reaped() {
        // The measured 2026-08-24 wedge, step by step: client committed to
        // Blocked; the reply's one-shot wake stamped it (unsaved — mid
        // switch-out, past the sweep's check); the context save completed;
        // no further wake will ever fire.
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));
        assert_eq!(wake_unsaved(&w, true), WakeTransition::Stamped);
        // ...context_switch.S finishes the save; the task is parked
        // Blocked+stamp+saved. The tick's reaper must deliver the wake:
        assert!(reap_orphaned_stamp(&w), "the reaper must recover the wake");
        assert_eq!(state_now(&w), TaskState::Ready);
        assert!(!stamped(&w), "recovery must consume the stamp");
        // Idempotence: a second reap finds nothing to do.
        assert!(!reap_orphaned_stamp(&w));
    }

    #[test]
    fn reap_refuses_a_stampless_sleeper() {
        // An ordinary parked task is not the reaper's business — waking it
        // with no delivered wake would be a phantom wake.
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));
        assert!(!reap_orphaned_stamp(&w));
        assert_eq!(state_now(&w), TaskState::Blocked, "must stay asleep");
    }

    #[test]
    fn reap_refuses_a_running_stamp() {
        // A stamp on a not-yet-blocked task belongs to block_current's
        // consume path (K-C9); the reaper stealing it would turn the
        // imminent block into a permanent sleep.
        let w = word(TaskState::Running);
        assert_eq!(wake(&w, true), WakeTransition::Stamped);
        assert!(!reap_orphaned_stamp(&w), "Running+stamp is not orphaned");
        assert!(stamped(&w), "the stamp must survive for the commit");
        assert!(!commit_blocked_or_consume_wake(&w), "commit consumes it");
    }

    #[test]
    fn reap_and_a_late_wake_deliver_exactly_once() {
        // If a second wake DOES exist, it races the reaper over the same
        // Blocked+stamp word. Exactly one may win — a double delivery would
        // enqueue the task twice.
        use std::sync::{Arc, Barrier};
        const ROUNDS: usize = 20_000;
        let w = Arc::new(word(TaskState::Running));
        let start = Arc::new(Barrier::new(2));
        let (w2, start2) = (w.clone(), start.clone());

        let reaper = std::thread::spawn(move || {
            let mut wins = 0usize;
            for _ in 0..ROUNDS {
                start2.wait();
                if reap_orphaned_stamp(&w2) { wins += 1; }
                start2.wait();
            }
            wins
        });
        let mut wake_wins = 0usize;
        for _ in 0..ROUNDS {
            assert!(commit_blocked_or_consume_wake(&w));
            assert_eq!(wake_unsaved(&w, true), WakeTransition::Stamped);
            start.wait();
            if wake(&w, true) == WakeTransition::Dispatched { wake_wins += 1; }
            start.wait();
            assert_eq!(state_now(&w), TaskState::Ready,
                       "someone must have delivered the wake");
            // NOTE: the word MAY carry a fresh stamp here — when the reaper
            // wins, the late wake finds Ready and stamps (StampPending),
            // which the task's next block would consume. That is a delivered
            // second wake, not a double delivery of the first.
            // Reset the seat for the next round.
            w.store(sched_word::pack(TaskState::Running), Ordering::Release);
        }
        let reap_wins = reaper.join().unwrap();
        assert_eq!(reap_wins + wake_wins, ROUNDS,
                   "every round must deliver exactly once");
    }

    #[test]
    fn reentry_commit_with_a_standing_blocked_word_proceeds() {
        // Unswitched block loops back in with the word still Blocked and no
        // stamp: the commit must stand (return true) so the task keeps
        // trying to yield the hart — not spin forever failing to re-commit.
        let w = word(TaskState::Running);
        assert!(commit_blocked_or_consume_wake(&w));
        assert!(commit_blocked_or_consume_wake(&w),
                "a standing commit is still a commit");
        assert_eq!(state_now(&w), TaskState::Blocked);
    }

    #[test]
    fn kc19_stress_no_wake_is_ever_lost() {
        // The race itself, run on real threads against the real protocol: a
        // blocker committing while a waker delivers exactly one wake. In
        // every round, either the blocker consumed the stamp (skip) or the
        // waker dispatched (Blocked → Ready). A round ending Blocked is a
        // lost wake — the K-C19 hang. The reverted double-check handshake
        // failed the mirror property (dispatching a task that never
        // committed); both are asserted.
        use std::sync::{Arc, Barrier};
        const ROUNDS: usize = 20_000;

        let w = Arc::new(word(TaskState::Running));
        let start = Arc::new(Barrier::new(2));
        let end = Arc::new(Barrier::new(2));

        let waker = {
            let w = Arc::clone(&w);
            let (start, end) = (Arc::clone(&start), Arc::clone(&end));
            std::thread::spawn(move || {
                for _ in 0..ROUNDS {
                    start.wait();
                    let wt = wake_transition(&w, || true, true, || true);
                    assert_ne!(wt, WakeTransition::Mismatch);
                    assert_ne!(wt, WakeTransition::NotBlocked);
                    end.wait();
                }
            })
        };

        for i in 0..ROUNDS {
            start.wait();
            let committed = commit_blocked_or_consume_wake(&w);
            end.wait(); // both sides done; the word is now quiescent
            let now = w.load(Ordering::Acquire);
            if committed {
                // We really blocked, so the waker must have dispatched us.
                assert_eq!(now, sched_word::pack(TaskState::Ready),
                           "round {i}: committed but never dispatched — lost wake (K-C19)");
            } else {
                // We consumed the stamp and skipped the block.
                assert_eq!(now, sched_word::pack(TaskState::Running),
                           "round {i}: skipped the block but the word moved");
            }
            // Reset for the next round, as the scheduler would (dispatch
            // path: dequeued and set Running; skip path: already Running).
            w.store(sched_word::pack(TaskState::Running), Ordering::Release);
        }
        waker.join().unwrap();
    }

    // ── 3. Routing: which wake uses which primitive ─────────────────────────

    fn only_by_tid(log: &[Call]) -> (u32, Vec<WaitReason>) {
        assert_eq!(log.len(), 1, "a targeted wake must make exactly one call: {log:?}");
        match &log[0] {
            Call::ByTid { tid, accepts } | Call::ByTidIpc { tid, accepts } => {
                (*tid, accepts.clone())
            }
            other => panic!("expected the TID-directed path, got {other:?}"),
        }
    }

    /// The IPC-affinity placement is for the two fast-IPC hand-offs only: a
    /// lease or port wake has no waker about to block on an answer, so it
    /// must keep the ordinary placement.
    #[test]
    fn only_fast_ipc_hand_offs_take_the_ipc_placement() {
        let ipc = |log: Vec<Call>| matches!(log.as_slice(), [Call::ByTidIpc { .. }]);
        assert!(ipc(with_log(|| { wait::wake_fast_ipc_server(7); scheduler::log() })), "server");
        assert!(ipc(with_log(|| { wait::wake_fast_ipc_client_tid(9, 3); scheduler::log() })), "client");
        assert!(!ipc(with_log(|| { wait::wake_lease_acceptor(7, 21); scheduler::log() })), "lease");
    }

    #[test]
    fn wake_fast_ipc_server_is_tid_directed() {
        let log = with_log(|| { wait::wake_fast_ipc_server(7); scheduler::log() });
        let (tid, accepts) = only_by_tid(&log);
        assert_eq!(tid, 7);
        assert_eq!(accepts, vec![WaitReason::FastIpcServer(7)]);
    }

    #[test]
    fn wake_fast_ipc_client_tid_addresses_the_client_and_matches_its_slot() {
        // The point of the new variant: the addressee is the *caller* TID,
        // while the predicate still keys on the slot.
        let log = with_log(|| { wait::wake_fast_ipc_client_tid(9, 3); scheduler::log() });
        let (tid, accepts) = only_by_tid(&log);
        assert_eq!(tid, 9, "must address the client TID, not the slot");
        assert_eq!(accepts, vec![WaitReason::FastIpcClient(3)],
                   "must not accept FastIpcClient(4) — wrong slot is a mismatch");
    }

    #[test]
    fn targeted_predicates_reject_every_unrelated_reason() {
        // A targeted predicate that accepted WaitReason::None would make the
        // Mismatch arm unreachable and re-open the corruption hazard.
        for (label, log) in [
            ("server", with_log(|| { wait::wake_fast_ipc_server(7); scheduler::log() })),
            ("client", with_log(|| { wait::wake_fast_ipc_client_tid(9, 3); scheduler::log() })),
            ("lease", with_log(|| { wait::wake_lease_acceptor(7, 21); scheduler::log() })),
        ] {
            let (_, accepts) = only_by_tid(&log);
            assert_eq!(accepts.len(), 1, "{label}: predicate must be exact");
            assert!(!accepts.contains(&WaitReason::None),
                    "{label}: must never accept WaitReason::None");
            assert!(!accepts.contains(&WaitReason::WaitQueue),
                    "{label}: must never accept WaitQueue");
        }
    }

    #[test]
    fn broadcast_wakes_still_use_the_sweep() {
        // These have no addressee TID. Routing them through the TID path
        // would be the trap K-C10 exists to avoid, so pin them here.
        for (label, log) in [
            ("irq", with_log(|| { wait::wake_by_irq(5); scheduler::log() })),
            ("channel", with_log(|| { wait::wake_by_channel(5); scheduler::log() })),
            ("ring", with_log(|| { wait::wake_by_ring(5); scheduler::log() })),
            ("port", with_log(|| { wait::wake_by_port(5); scheduler::log() })),
            ("timers", with_log(|| { wait::wake_expired_timers(9999); scheduler::log() })),
            // Legacy slot-keyed client wake — still a sweep, still lossy.
            ("client_by_slot", with_log(|| { wait::wake_fast_ipc_client(3); scheduler::log() })),
        ] {
            assert_eq!(log.len(), MAX_TASKS, "{label}: must sweep the whole pool");
            for c in &log {
                assert!(matches!(c, Call::Sweep { .. }),
                        "{label}: must not use the TID-directed path: {c:?}");
            }
        }
    }

    #[test]
    fn legacy_slot_keyed_client_wake_still_matches_the_slot() {
        // Kept only for the un-migrated SYS_IPC_FAST_REPLY call site; its
        // predicate must stay identical to the TID variant's.
        let log = with_log(|| { wait::wake_fast_ipc_client(3); scheduler::log() });
        match &log[0] {
            Call::Sweep { accepts, .. } => {
                assert_eq!(*accepts, vec![WaitReason::FastIpcClient(3)]);
            }
            other => panic!("expected a sweep, got {other:?}"),
        }
    }

    // ── Port waiter: the TID-directed port wake (RFC-0040 gap 1) ───────────
    //
    // `crates/core/ipc/src/port.rs` registers a `SYS_PORT_WAIT` task as a waiter of
    // the port's packed reference in the hold of its empty poll, and wakes each
    // registered waiter through `wait::wake_port_waiter(tid, port_ref)`. The
    // probe `Port(5)` stands for the reference. `wake_by_port` (the broadcast)
    // stays pinned to the sweep above.

    /// Canaries: route `wake_port_waiter` through `wake_matching`; match
    /// `WaitReason::Port(_)` without comparing the reference.
    #[test]
    fn wake_port_waiter_is_tid_directed_and_matches_the_exact_reference() {
        let log = with_log(|| { wait::wake_port_waiter(7, 5); scheduler::log() });
        let (tid, accepts) = only_by_tid(&log);
        assert_eq!(tid, 7, "must address the waiter's TID");
        assert_eq!(accepts, vec![WaitReason::Port(5)], "must accept Port(5) and nothing else");
    }

    /// The lost wakeup the port waiter registry closes: the event lands after
    /// the waiter's empty poll and before its `task_block`, while the waiter is
    /// still Running with no reason published. The real transition stamps it
    /// and its block consumes the stamp.
    ///
    /// Canary: route `wake_port_waiter` through the sweep (`wake_matching`),
    /// which passes `stamp_if_unblocked = false`; `only_by_tid` refuses it.
    #[test]
    fn a_port_event_before_the_waiter_blocks_is_not_lost() {
        let log = with_log(|| { wait::wake_port_waiter(7, 5); scheduler::log() });
        let (_, accepts) = only_by_tid(&log);

        let w = word(TaskState::Running);
        assert_eq!(wake_transition(&w, || accepts.contains(&WaitReason::None), true, || true),
                   WakeTransition::Stamped);
        assert!(!commit_blocked_or_consume_wake(&w),
                "the waiter slept through an event that landed before its block");
        assert_eq!(state_now(&w), TaskState::Running);
        assert!(!stamped(&w));
    }

    // ── IRQ waiter: the wake-task binding's wake (wave 9 IRQ4) ─────────────
    //
    // `crates/core/ipc/src/irq_bind.rs` registers the owner of a wake-task binding
    // in `SYS_DRV_IRQ_WAIT` and wakes it on delivery through
    // `wait::wake_irq_waiter(tid, irq)`. `wake_by_irq` (the broadcast) stays
    // pinned to the sweep above.

    /// Canaries: route `wake_irq_waiter` through `wake_matching`; match
    /// `WaitReason::Irq(_)` without comparing the line.
    #[test]
    fn wake_irq_waiter_is_tid_directed_and_matches_the_exact_line() {
        let log = with_log(|| { wait::wake_irq_waiter(7, 5); scheduler::log() });
        let (tid, accepts) = only_by_tid(&log);
        assert_eq!(tid, 7, "must address the binding owner's TID");
        assert_eq!(accepts, vec![WaitReason::Irq(5)], "must accept Irq(5) and nothing else");
    }

    /// The lost wakeup the pending bit's registration closes: the delivery
    /// lands after the owner registered and before its `task_block`, while it
    /// is still Running. The real transition stamps it and its block
    /// consumes the stamp.
    #[test]
    fn an_irq_before_the_waiter_blocks_is_not_lost() {
        let log = with_log(|| { wait::wake_irq_waiter(7, 5); scheduler::log() });
        let (_, accepts) = only_by_tid(&log);

        let w = word(TaskState::Running);
        assert_eq!(wake_transition(&w, || accepts.contains(&WaitReason::None), true, || true),
                   WakeTransition::Stamped);
        assert!(!commit_blocked_or_consume_wake(&w),
                "the waiter slept through a delivery that landed before its block");
        assert_eq!(state_now(&w), TaskState::Running);
    }

    // ── Lease accept: the grant's wake (owner decision 2026-09-14) ─────────
    //
    // `SYS_IPC_LEASE_GRANT` used to wake the lessee through
    // `wake_fast_ipc_server`, and `SYS_IPC_LEASE_ACCEPT` blocked on
    // `FastIpcServer(lessee)`: a grant dispatched a task blocked as a fast-IPC
    // server on the lessee's TID. The tests below take the predicate the real
    // `wait::wake_lease_acceptor` builds (through the probe set) and run it
    // through the real `sched_word::wake_transition`.

    /// The reasons `wake_lease_acceptor(lessee, lessor)` accepts, and the TID
    /// it addresses.
    fn lease_wake(lessee: u32, lessor: u32) -> (u32, Vec<WaitReason>) {
        let log = with_log(|| { wait::wake_lease_acceptor(lessee, lessor); scheduler::log() });
        only_by_tid(&log)
    }

    /// Canaries: swap the addressee to the lessor; drop `*l == lessor` from
    /// the predicate; match `FastIpcServer(t)` instead.
    #[test]
    fn wake_lease_acceptor_addresses_the_lessee_and_matches_its_lessor() {
        let (tid, accepts) = lease_wake(7, 21);
        assert_eq!(tid, 7, "must address the lessee, not the lessor");
        assert_eq!(accepts, vec![WaitReason::LeaseAccept(7, 21)],
                   "must accept LeaseAccept(7, 21) and nothing else");
    }

    /// Canaries: as above. With `FastIpcServer(t)` matched, the server
    /// below is dispatched; without the lessor, the accept naming 22 is.
    #[test]
    fn a_grant_leaves_a_fast_ipc_server_and_another_lessors_accept_asleep() {
        let (_, accepts) = lease_wake(7, 21);
        let blocked_on = |reason: WaitReason| {
            let w = word(TaskState::Running);
            assert!(commit_blocked_or_consume_wake(&w));
            let t = wake_transition(&w, || accepts.contains(&reason), true, || true);
            (t, state_now(&w), stamped(&w))
        };

        // The same TID blocked as a fast-IPC server: not the grant's task.
        assert_eq!(blocked_on(WaitReason::FastIpcServer(7)),
                   (WakeTransition::Mismatch, TaskState::Blocked, false),
                   "a grant woke (or marked) a fast-IPC server on the lessee's TID");
        // The lessee accepting from another lessor: left asleep, unmarked.
        assert_eq!(blocked_on(WaitReason::LeaseAccept(7, 22)),
                   (WakeTransition::Mismatch, TaskState::Blocked, false),
                   "a grant from 21 woke an accept naming 22");
        // The lessee accepting from this lessor: dispatched.
        assert_eq!(blocked_on(WaitReason::LeaseAccept(7, 21)),
                   (WakeTransition::Dispatched, TaskState::Ready, false));
    }

    /// Canary: route `wake_lease_acceptor` through the sweep
    /// (`wake_matching`) instead of `scheduler::wake_task_by_tid`. A sweep
    /// passes `stamp_if_unblocked = false`, so an early grant would be lost;
    /// here `only_by_tid` refuses the sweep call.
    #[test]
    fn a_grant_before_the_lessee_blocks_is_not_lost() {
        let (_, accepts) = lease_wake(7, 21);
        // The grant lands between the accept's `lease_accept` poll and its
        // `task_block`: the lessee is still Running, its reason still None.
        let w = word(TaskState::Running);
        assert_eq!(wake_transition(&w, || accepts.contains(&WaitReason::None), true, || true),
                   WakeTransition::Stamped);
        // Its block then consumes the stamp instead of sleeping, and the
        // arm's loop polls `lease_accept` again and finds the lease.
        assert!(!commit_blocked_or_consume_wake(&w),
                "the accept slept through a grant that landed before its block");
        assert_eq!(state_now(&w), TaskState::Running);
        assert!(!stamped(&w));
    }

    // ── Lease return: the lessor's wake (owner decision 2026-09-14) ─────────
    //
    // Every lessor-side lease wake (`lease_return`, the lessee-exit sweep in
    // `lease_release_all`, the timer ISR's expiry drain) is now
    // `scheduler::wq_wake_by_tid(lessor)` alone; the `wake_fast_ipc_server`
    // half was removed. `wq_wake_by_tid` lives in scheduler.rs, which this
    // crate does not compile, so its predicate is TRANSCRIBED below from
    // scheduler.rs (`task.wait_reason == WaitReason::WaitQueue`, passed to
    // `wake_transition` with `stamp_if_unblocked = true`). The transition is
    // the real one. This pins what that wake does to each lessor state; it
    // does not detect an edit to scheduler.rs.

    /// Transcribed from `scheduler::wq_wake_by_tid`, not compiled from it.
    fn wq_wake_by_tid_reason_matches(r: WaitReason) -> bool {
        r == WaitReason::WaitQueue
    }

    /// A lessor blocked in `lease_wait_return` is dispatched by a return; the
    /// same TID blocked serving fast IPC is neither dispatched nor stamped.
    /// The removed `wake_fast_ipc_server(lessor)` (predicate taken from the
    /// real `wait.rs`) did dispatch it.
    ///
    /// Canary: have `wait::wake_fast_ipc_server` accept `WaitQueue` too; the
    /// last assertion (the removed wake leaves a lessor in
    /// `lease_wait_return` asleep) then fails.
    #[test]
    fn a_lease_return_dispatches_the_waiting_lessor_and_not_a_fast_ipc_server() {
        let blocked_on = |reason: WaitReason, matches: &dyn Fn(WaitReason) -> bool| {
            let w = word(TaskState::Running);
            assert!(commit_blocked_or_consume_wake(&w));
            let t = wake_transition(&w, || matches(reason), true, || true);
            (t, state_now(&w), stamped(&w))
        };
        let lease_wake = |r: WaitReason| wq_wake_by_tid_reason_matches(r);

        assert_eq!(blocked_on(WaitReason::WaitQueue, &lease_wake),
                   (WakeTransition::Dispatched, TaskState::Ready, false),
                   "a return left the lessor asleep in lease_wait_return");
        assert_eq!(blocked_on(WaitReason::FastIpcServer(7), &lease_wake),
                   (WakeTransition::Mismatch, TaskState::Blocked, false),
                   "a return woke (or marked) a lessor blocked serving fast IPC");

        // The wake the lease paths no longer issue, from the real `wait.rs`.
        let (tid, accepts) = only_by_tid(&with_log(|| {
            wait::wake_fast_ipc_server(7);
            scheduler::log()
        }));
        assert_eq!(tid, 7);
        let removed_wake = |r: WaitReason| accepts.contains(&r);
        assert_eq!(blocked_on(WaitReason::FastIpcServer(7), &removed_wake),
                   (WakeTransition::Dispatched, TaskState::Ready, false),
                   "the removed wake dispatched a lessor blocked serving fast IPC");
        assert_eq!(blocked_on(WaitReason::WaitQueue, &removed_wake),
                   (WakeTransition::Mismatch, TaskState::Blocked, false),
                   "the removed wake never reached lease_wait_return");
    }

    #[test]
    fn task_block_forwards_the_reason_unchanged() {
        let log = with_log(|| {
            wait::task_block(WaitReason::FastIpcClient(3));
            scheduler::log()
        });
        assert_eq!(log, vec![Call::Block { cpu: 0, reason: WaitReason::FastIpcClient(3) }]);
    }

    // ── K-C29: `task_block_outcome` reports a refusal to block ──────────────
    //
    // `block_current` can return without having parked the caller. After
    // K-C29 it does so deliberately whenever preemption is disabled on the
    // hart, because parking a spinlock holder turns a priority-dependent hang
    // into a certain one. Callers that have a condition to re-test are
    // correct under that by looping; `SYS_DRV_IRQ_WAIT` has nothing to
    // re-test, so `task_block_outcome` exists to hand it the fact.
    //
    // WHAT IS REAL HERE: `wait.rs` is pulled unmodified, and the decision it
    // delegates to — `preempt_core::voluntary_admission` — is the kernel's
    // own pure module, also pulled (see `shims/sync`). Only the *source* of
    // the depth is faked, because reading it needs `tp`. So these tests prove
    // the mapping from depth to outcome, not how a depth arises; the
    // mechanism that produces one is `tests/host/sync-tests`' subject.
    //
    // The companion half — what the syscall layer then returns to ring 3 —
    // is `tests/host/syscall-tests`' `irq_wait.rs`. Neither proves the other.

    use azos_sync::preempt;

    /// Run `f` with this "hart" at `depth`, then put the depth back.
    ///
    /// The depth cell is a process-wide singleton like the log, so this runs
    /// inside `with_log`'s lock. Restoring is not politeness: a leaked
    /// non-zero depth would make every later test's `task_block_outcome`
    /// report `Refused`, and `a_block_inside_a_critical_section_reports_
    /// refused` would then pass for the wrong reason.
    ///
    /// **The restore is a `Drop`, not a statement after `f()`, and that is
    /// load-bearing.** A failing assertion panics, and `with_log` deliberately
    /// recovers from the resulting lock poisoning so the remaining tests still
    /// run — so a trailing `set_depth(0)` would be skipped exactly when a test
    /// fails, leaking depth into every test that ran afterwards. Whether the
    /// leak was observed would then depend on thread scheduling, which is the
    /// same class of defect as a canary that samples where the mutant and the
    /// fix agree.
    fn at_depth<R>(depth: u32, f: impl FnOnce() -> R) -> R {
        struct ResetDepth;
        impl Drop for ResetDepth {
            fn drop(&mut self) { preempt::set_depth(0); }
        }
        with_log(|| {
            let _reset = ResetDepth;
            preempt::set_depth(depth);
            f()
        })
    }

    /// **The property.** With a critical section open, the outcome must say
    /// the block did not happen.
    ///
    /// `depth = 1` is where a mutant differs: at depth 0 a broken mapping and
    /// a correct one both answer `Returned`, so asserting there proves
    /// nothing. Every depth above 0 is the same branch of
    /// `voluntary_admission`, so 1 is the whole of the interesting input.
    #[test]
    fn a_block_inside_a_critical_section_reports_refused() {
        let outcome = at_depth(1, || {
            wait::task_block_outcome(WaitReason::Irq(5))
        });
        assert_eq!(outcome, wait::BlockOutcome::Refused);
    }

    /// With no critical section open, the outcome must say the block
    /// happened. This is the control for the test above: without it, a
    /// mapping that answered `Refused` unconditionally would pass.
    #[test]
    fn a_block_outside_a_critical_section_reports_returned() {
        let outcome = at_depth(0, || {
            wait::task_block_outcome(WaitReason::Irq(5))
        });
        assert_eq!(outcome, wait::BlockOutcome::Returned);
    }

    /// The saturating depth counter goes to `u32::MAX`; every value above 0
    /// is a refusal, not just 1.
    #[test]
    fn every_nonzero_depth_refuses() {
        for d in [1u32, 2, 7, u32::MAX] {
            let outcome = at_depth(d, || {
                wait::task_block_outcome(WaitReason::WaitQueue)
            });
            assert_eq!(outcome, wait::BlockOutcome::Refused, "depth {d}");
        }
    }

    /// **`block_current` is still called on the refusal path.**
    ///
    /// This is a separate claim from the mapping and it has its own mutant:
    /// an "optimisation" that returns `Refused` *without* calling
    /// `task_block` would pass both tests above while silently disabling the
    /// K-C29 audit — the `BLOCK_WHILE_ATOMIC` counter, the last-offender
    /// record and the rate-limited console line all live inside
    /// `block_current`, and they are the only evidence that a caller is
    /// blocking under a lock at all. Losing them would hide the very bug the
    /// mechanism was built to surface.
    ///
    /// The reason must arrive unchanged too, since the offender record tags
    /// itself with the wait-reason discriminant.
    #[test]
    fn a_refused_block_still_reaches_block_current_with_its_reason() {
        let log = at_depth(1, || {
            let _ = wait::task_block_outcome(WaitReason::Irq(9));
            scheduler::log()
        });
        assert_eq!(
            log,
            vec![Call::Block { cpu: 0, reason: WaitReason::Irq(9) }],
            "the refusal path must not short-circuit the K-C29 audit in block_current"
        );
    }

    /// `task_block_outcome` must be `task_block` plus a report — the block
    /// itself is identical on both paths, so the non-refused path reaches
    /// `block_current` exactly the same way.
    #[test]
    fn a_returned_block_reaches_block_current_identically() {
        let log = at_depth(0, || {
            let _ = wait::task_block_outcome(WaitReason::Irq(9));
            scheduler::log()
        });
        assert_eq!(log, vec![Call::Block { cpu: 0, reason: WaitReason::Irq(9) }]);
    }

    // ── K-C12: CPU placement policy ─────────────────────────────────────
    //
    // These exercise `task::pick_cpu_by_load`, the real decision the kernel
    // makes in `scheduler::find_best_cpu`. What the kernel does around it —
    // walking `TASKS[]` to build the per-CPU `CpuLoad` — cannot be compiled
    // for the host (static `TASKS`, `context.tp`, CSRs), so the *sampling* is
    // not covered here. That half is covered from ring 3 by
    // `userspace/tests/ipctest`, which is where the defect was found in the first
    // place. Stated plainly so a green run here is not mistaken for proof
    // that placement as a whole is correct.

    use crate::task::{CpuLoad, EnqueueOutcome, TaskState as TS, claim_audit_persistent,
                      enqueue_decision, pick_cpu_by_load, resident_competes,
                      resident_load_contribution, ring_walk_bounds};

    /// Build the `CpuLoad` array exactly as `find_best_cpu` does — by summing
    /// the real rule over residents — so these tests exercise the production
    /// path instead of hand-written numbers.
    fn loads_for(
        residents: &[(usize, TS, usize, bool)], // (home, state, bucket, is_rt)
        target_bucket: usize,
        harts: usize,
    ) -> Vec<CpuLoad> {
        let mut out = vec![CpuLoad { rt_blocking: 0, blocking: 0, total: 0 }; harts];
        for &(home, state, bucket, is_rt) in residents {
            let (rt, blk, tot) =
                resident_load_contribution(state, bucket, is_rt, target_bucket);
            out[home].rt_blocking += rt;
            out[home].blocking    += blk;
            out[home].total       += tot;
        }
        out
    }

    fn load(rt_blocking: u32, blocking: u32, total: u32) -> CpuLoad {
        CpuLoad { rt_blocking, blocking, total }
    }

    #[test]
    fn placement_avoids_a_hart_with_higher_priority_residents() {
        // The K-C12 shape, taken from the measured boot layout: hart 0 hosts
        // rt-motor + flight-ctrl (priority 8) and looks *emptiest* by queued
        // count; hart 2 hosts only same-or-lower priority work. A newcomer at
        // DEFAULT_PRIORITY must go to hart 2 even though hart 0 carries fewer
        // tasks in total, because on hart 0 it would never be dispatched.
        let loads = [
            load(2, 2, 2), // hart 0 — two RT residents, fewest tasks
            load(1, 1, 5), // hart 1
            load(0, 0, 4), // hart 2 — no one outranks the newcomer
            load(1, 1, 5), // hart 3
        ];
        assert_eq!(pick_cpu_by_load(&loads), 2);
    }

    #[test]
    fn placement_ranks_real_time_blockers_ahead_of_everything() {
        // The regression that made the first version of this fix incomplete,
        // taken from the probe: every hart ends up with two outranking
        // residents, so `blocking` ties — and hart 0 has the *fewest* tasks
        // overall because the earlier children all went to hart 2. Ranking on
        // (blocking, total) alone sends the newcomer to hart 0, whose two
        // blockers are `rt-motor` and `flight-ctrl` at priority 8 and which
        // therefore never dispatches it. The real-time count has to win.
        let loads = [
            load(2, 2, 6),  // hart 0 — two RT blockers, lightest overall
            load(1, 2, 9),
            load(0, 2, 20), // hart 2 — no RT blockers, heaviest by far
            load(1, 2, 9),
        ];
        assert_eq!(pick_cpu_by_load(&loads), 2);
    }

    #[test]
    fn placement_still_uses_the_plain_blocker_count_below_the_rt_key() {
        // Non-RT blockers are not harmless — dispatch is strict priority, so
        // a p13 task that never sleeps starves p16 just as thoroughly. With
        // the RT key tied, fewer blockers must still win over fewer tasks.
        let loads = [load(1, 4, 1), load(1, 2, 30)];
        assert_eq!(pick_cpu_by_load(&loads), 1);
    }

    #[test]
    fn placement_falls_back_to_total_only_among_equally_live_harts() {
        // Balance still matters — but only once liveness is settled.
        let loads = [load(0, 0, 9), load(0, 0, 3), load(0, 0, 7)];
        assert_eq!(pick_cpu_by_load(&loads), 1);
    }

    #[test]
    fn placement_never_trades_liveness_for_balance() {
        // A hart with one blocker loses to a hart with none no matter how
        // lopsided the totals are. This is the whole point of the ordering:
        // an unbalanced-but-running task beats a balanced-and-starved one.
        let loads = [load(1, 1, 0), load(0, 0, u32::MAX)];
        assert_eq!(pick_cpu_by_load(&loads), 1);
    }

    #[test]
    fn placement_is_deterministic_on_ties_and_total_ordering() {
        // Ties resolve to the lowest index, so the choice is reproducible.
        assert_eq!(pick_cpu_by_load(&[load(1, 1, 1), load(1, 1, 1), load(1, 1, 1)]), 0);
        // And every non-empty input yields an in-range index.
        for a in 0..3u32 {
            for b in 0..3u32 {
                for c in 0..3u32 {
                    let got = pick_cpu_by_load(&[load(a, a, c), load(b, b, a), load(c, c, b)]);
                    assert!(got < 3, "out-of-range CPU {got}");
                }
            }
        }
    }

    #[test]
    fn placement_handles_a_single_cpu_and_an_empty_list() {
        assert_eq!(pick_cpu_by_load(&[load(9, 9, 9)]), 0);
        assert_eq!(pick_cpu_by_load(&[]), 0);
    }

    // ── K-C12: ready-queue admission ────────────────────────────────────
    //
    // `cpu_enqueue`'s guard used to be a `debug_assert!`, compiled out of the
    // release profile the kernel ships. These pin the replacement policy.
    // The ring manipulation itself lives on `static mut PER_CPU` and is not
    // host-compilable; only the decision is.

    #[test]
    fn enqueue_refuses_a_task_that_is_already_queued() {
        // The duplicate case is safe to refuse precisely because an entry
        // already exists — refusing loses nothing.
        assert_eq!(
            enqueue_decision(true, 0, 64),
            EnqueueOutcome::AlreadyQueued,
            "a queued task must never be appended twice"
        );
        // Even on an empty ring, and even on a full one: being queued wins.
        assert_eq!(enqueue_decision(true, 64, 64), EnqueueOutcome::AlreadyQueued);
    }

    #[test]
    fn enqueue_refuses_instead_of_overwriting_a_full_ring() {
        // The bug: `count == capacity` used to fall through to
        // `q.buf[q.tail] = idx`, clobbering a live entry and pushing `count`
        // past the ring. Refusal is the only non-corrupting answer that is
        // also not a panic (= board reset under `panic = "abort"`).
        assert_eq!(enqueue_decision(false, 64, 64), EnqueueOutcome::Full);
        // And a count that somehow ran past capacity must still refuse, not
        // wrap back into "there is room".
        assert_eq!(enqueue_decision(false, 65, 64), EnqueueOutcome::Full);
        assert_eq!(enqueue_decision(false, usize::MAX, 64), EnqueueOutcome::Full);
    }

    /// The walk that `ring_claim_audit` performs must not be able to panic,
    /// whatever the unsynchronised read hands it.
    ///
    /// This is not hypothetical. The first version seeded its cursor straight
    /// from `head` and did `h = (h + 1) % MAX_TASKS`. Every value the ring ever
    /// *stores* in `head` is below capacity, so the add looked safe — but that
    /// read is a data race, and a racing read has no coherent value to reason
    /// about. Twice in a hundred 8-way-concurrent QEMU runs it overflowed and
    /// reset the board from inside the timer ISR, where `panic = "abort"` makes
    /// an arithmetic check a reboot.
    #[test]
    fn a_racing_ring_read_cannot_produce_an_out_of_range_cursor() {
        const CAP: usize = 64;
        // The value that actually crashed it, plus its neighbours and the
        // ordinary cases, all held to the same contract.
        for &head in &[0, 1, 63, 64, 65, 127, 128, usize::MAX - 1, usize::MAX] {
            for &count in &[0, 1, 63, 64, 65, usize::MAX] {
                let (start, len) = ring_walk_bounds(head, count, CAP);
                assert!(
                    start < CAP,
                    "head={head} count={count} produced start={start},                      which would index outside a {CAP}-entry ring"
                );
                assert!(
                    len <= CAP,
                    "head={head} count={count} produced len={len},                      which would walk past a {CAP}-entry ring"
                );
            }
        }
    }

    /// Walking the bounds must terminate and stay in range at every step —
    /// the property the crash violated, asserted end to end rather than only
    /// at the seed.
    #[test]
    fn the_whole_walk_stays_in_range_for_adversarial_inputs() {
        const CAP: usize = 64;
        for &head in &[usize::MAX, usize::MAX - 1, 0, 63, 64] {
            for &count in &[usize::MAX, 64, 65, 1] {
                let (mut h, mut remaining) = ring_walk_bounds(head, count, CAP);
                let mut steps = 0usize;
                while remaining > 0 {
                    assert!(h < CAP, "step {steps} left the ring at index {h}");
                    // Exactly the arithmetic the audit performs.
                    h = h.wrapping_add(1) % CAP;
                    remaining -= 1;
                    steps += 1;
                    assert!(steps <= CAP, "the walk failed to terminate");
                }
            }
        }
    }

    /// Only a resident that can run right now outranks a newcomer.
    #[test]
    fn a_sleeping_resident_does_not_outrank_anybody() {
        assert!(resident_competes(TaskState::Running), "it holds the hart");
        assert!(resident_competes(TaskState::Ready), "it is queued to hold it");
        assert!(
            !resident_competes(TaskState::Blocked),
            "a task waiting on a timer is not competing for the CPU"
        );
        assert!(
            !resident_competes(TaskState::Zombie),
            "a dead task competes for nothing"
        );
    }

    /// The measured layout that made this change necessary.
    ///
    /// After K-C27 the real-time daemons sleep between activations, so for
    /// almost all of every period harts 0 and 1 are idle. Placement kept
    /// scoring their sleeping residents as full blockers, so every unpinned
    /// child went to hart 2 — the one hart with no real-time residents — and
    /// stayed there. Captured at the moment `ipctest` failed:
    /// `per_cpu_queues = [0, 2, 50, 4]`. Two empty ready queues and fifty
    /// tasks waiting on a third.
    ///
    /// Built through `resident_load_contribution`, not by hand: an earlier
    /// version of this test wrote the `CpuLoad` numbers itself and stayed
    /// green under a deliberately broken rule.
    #[test]
    fn sleeping_real_time_residents_stop_funnelling_work_onto_one_hart() {
        const NEWCOMER: usize = 16; // best-effort bucket
        let mut residents = vec![
            (0, TS::Blocked, 8,  true),  // rt-motor,     asleep on its timer
            (0, TS::Blocked, 8,  true),  // flight-ctrl,  asleep
            (1, TS::Blocked, 8,  true),  // imu,          asleep
            (3, TS::Ready,  10, false),  // autorun
        ];
        // Fifty best-effort peers already piled on hart 2. They do not outrank
        // the newcomer, so they only move `total`.
        for _ in 0..50 { residents.push((2, TS::Ready, 16, false)); }

        let loads = loads_for(&residents, NEWCOMER, 4);
        assert_eq!(
            loads[0].rt_blocking, 0,
            "a daemon asleep on a timer is not blocking anybody"
        );
        assert_eq!(loads[2].total, 50, "the fifty are still residents");
        assert_ne!(
            pick_cpu_by_load(&loads), 2,
            "with its blockers asleep, the fifty-deep hart must stop winning"
        );
        assert_eq!(
            pick_cpu_by_load(&loads), 1,
            "and `total` breaks the tie toward the emptiest idle hart"
        );
    }

    /// A resident that is genuinely running still wins the argument.
    ///
    /// The guard this replaced exists for a measured reason: mid-priority
    /// children placed on a hart whose residents never blocked "sat Ready and
    /// un-dispatched for the rest of the run". Not counting a *Running*
    /// resident would reintroduce exactly that, so the rule must keep telling
    /// the two apart.
    #[test]
    fn a_running_real_time_resident_still_repels_best_effort_work() {
        const NEWCOMER: usize = 16;
        let mut residents = vec![
            (0, TS::Running, 8, true),   // busy, not asleep
            (0, TS::Ready,   8, true),   // queued behind it, also competing
        ];
        for _ in 0..30 { residents.push((1, TS::Ready, 16, false)); }

        let loads = loads_for(&residents, NEWCOMER, 2);
        assert_eq!(
            loads[0].rt_blocking, 2,
            "residents that can run must still be counted"
        );
        assert_eq!(
            pick_cpu_by_load(&loads), 1,
            "thirty peers beat two residents that never yield: liveness outranks balance"
        );
    }

    /// A zero capacity must yield an empty walk, not a division by zero.
    ///
    /// `MAX_TASKS` is never 0, so this input cannot arise today — but the
    /// point of extracting the clamp was to make it a total function, and a
    /// total function that panics on one input is not one.
    #[test]
    fn a_zero_capacity_ring_yields_an_empty_walk_rather_than_dividing_by_zero() {
        assert_eq!(ring_walk_bounds(usize::MAX, usize::MAX, 0), (0, 0));
        assert_eq!(ring_walk_bounds(0, 0, 0), (0, 0));
    }

    // ── The two-sample filter that makes the lock-free audit usable ──────
    //
    // `ring_claim_audit` reads the ready-queue rings from the timer ISR
    // without `CPU_LOCKS`. Making the ring fields `AtomicUsize`/`Relaxed`
    // closed the *undefined behaviour* — a plain load racing a plain store is
    // UB whatever the result is clamped to — but it did not, and could not,
    // give the reader a consistent snapshot: a sample can still catch an
    // enqueue between `buf[tail] = idx` and `count += 1` and see a task whose
    // `queued` flag is set but whose ring entry is not yet counted.
    //
    // This used to add: "Two documented writers
    // (`boost_ready_task`/`restore_ready_task`) do not take the lock at all,
    // so they can lose an update outright." **Fixed 2026-09-20** (scan unit 4)
    // — both now go through `cpu_remove_anywhere`, which takes each CPU's lock
    // in turn. The audit turned up a second, worse half that this note never
    // mentioned: they used the DONOR's hart, so on any other hart the removal
    // silently missed and the task was left queued in another CPU's bucket
    // under its old priority while `priority` said otherwise — a bucket no
    // later removal could find. See `cpu_remove_anywhere`.
    //
    // The torn-snapshot problem the filter defends against is unchanged: the
    // ISR still reads the rings without `CPU_LOCKS`, which is deliberate.
    //
    // `claim_audit_persistent` is the entire defence against printing that
    // torn view as a fault, so it is the piece that has to be proved. What
    // these tests cover and what they do not:
    //
    //   * COVERED: the filter itself, driven through the same
    //     replace-prev-with-current sequence `scheduler.rs` performs.
    //   * NOT COVERED: that `scheduler.rs` really calls it, and really uses
    //     `swap` rather than a sticky accumulate. `scheduler.rs` does not
    //     compile for the host (static `PER_CPU`, CSR reads, `kprintln!`), so
    //     that half is read, not executed. It is one `swap` and one call on
    //     one line each.

    /// Drive a sequence of per-tick `claim_no_entry` masks through the filter
    /// exactly as the audit does: `persistent = f(prev, cur)`, then `prev`
    /// is **replaced** by `cur` (`PREV_CLAIM_NO_ENTRY.swap`).
    fn audit_sequence(samples: &[u64]) -> Vec<u64> {
        let mut prev = 0u64;
        samples
            .iter()
            .map(|&cur| {
                let persistent = claim_audit_persistent(prev, cur);
                prev = cur;
                persistent
            })
            .collect()
    }

    /// Both directions, because either one alone passes against the other's
    /// mutant.
    ///
    /// A filter that reported every sample (`|prev, cur| cur`) turns every
    /// enqueue window into a false CLAIM-NO-ENTRY report from inside the timer
    /// ISR; a filter that reported nothing (`|_, _| 0`) makes the audit — the
    /// only check on the `queued` claim anywhere in this kernel — silently
    /// useless while still printing a clean bill of health. A test asserting
    /// only "a single sample is not reported" is green under the second; one
    /// asserting only "two in a row are reported" is green under the first.
    #[test]
    fn one_anomalous_sample_is_noise_and_two_consecutive_ones_are_evidence() {
        const A: u64 = 1 << 5;

        // Direction 1: a lone transient must not report. Kills `cur`.
        assert_eq!(
            audit_sequence(&[A]),
            vec![0],
            "a single racy sample is noise — reporting it would mean the ISR \
             prints a fault every time it lands mid-enqueue"
        );

        // Direction 2: two in a row must report. Kills `0`, and kills any
        // mutant that never accumulates.
        assert_eq!(
            audit_sequence(&[A, A]),
            vec![0, A],
            "a slot that claims a queue entry it does not have in two \
             consecutive samples is the failure this audit exists to find"
        );
    }

    /// The count must restart, not accumulate — the discriminator for the
    /// sticky mutant, which the two-tick cases above cannot see.
    ///
    /// `|prev, cur| prev | cur` agrees with the real rule on `[A]` (reports
    /// nothing at tick 1 either way, since `prev` starts 0) and on `[A, A]`.
    /// It differs for the first time at tick 3 of `[A, 0, A]`: the real filter
    /// says nothing (tick 2 cleared the slot, so the streak restarted), the
    /// sticky one reports `A` forever after a single transient. That is the
    /// input this asserts at.
    #[test]
    fn a_slot_that_comes_clean_for_one_tick_restarts_its_streak() {
        const A: u64 = 1 << 5;
        assert_eq!(
            audit_sequence(&[A, 0, A]),
            vec![0, 0, 0],
            "ticks 1 and 3 are two separate transients, not a persistent \
             fault — a sticky filter would report at tick 3"
        );
        // And the streak really does resume from scratch afterwards.
        assert_eq!(audit_sequence(&[A, 0, A, A]), vec![0, 0, 0, A]);
    }

    /// Only the slots present in *both* samples are reported — a per-slot
    /// intersection, not a per-tick "something was anomalous" flag.
    ///
    /// Discriminates against `prev | cur` and against any mutant that reports
    /// the whole current mask once anything persists: with `A|B` then `B|C`,
    /// the real rule returns exactly `B`. Both mutants return a superset that
    /// names innocent slots, and the audit prints a task name per bit — a
    /// false CLAIM-NO-ENTRY line for a healthy task is what would send the
    /// next K-C26-style hunt down the wrong hart.
    #[test]
    fn persistence_is_per_slot_not_per_tick() {
        const A: u64 = 1 << 1;
        const B: u64 = 1 << 2;
        const C: u64 = 1 << 3;
        assert_eq!(audit_sequence(&[A | B, B | C]), vec![0, B]);
        // Disjoint sets never intersect, however anomalous each tick looks.
        assert_eq!(audit_sequence(&[A, B]), vec![0, 0]);
    }

    /// The filter is applied to each 64-slot word of the audit's slot bitmap
    /// (`scheduler.rs` through `slot_bitmap::claim_pass`), so the top bit of a
    /// word has to survive. Asserted because a mutant using `u32` arithmetic, or an
    /// off-by-one in the bit index, would pass every test above.
    #[test]
    fn the_top_slot_of_a_word_is_not_lost_from_the_mask() {
        const TOP: u64 = 1 << 63;
        assert_eq!(audit_sequence(&[TOP, TOP]), vec![0, TOP]);
        assert_eq!(audit_sequence(&[u64::MAX, u64::MAX]), vec![0, u64::MAX]);
        assert_eq!(audit_sequence(&[u64::MAX, TOP]), vec![0, TOP]);
    }

    #[test]
    fn enqueue_appends_only_with_room_and_no_duplicate() {
        assert_eq!(enqueue_decision(false, 0, 64), EnqueueOutcome::Append);
        assert_eq!(enqueue_decision(false, 63, 64), EnqueueOutcome::Append);
    }

    #[test]
    fn enqueue_never_appends_past_capacity_for_any_input() {
        // Exhaustive over the ring: Append implies there was a free slot.
        for count in 0..=70usize {
            for &already in &[false, true] {
                if enqueue_decision(already, count, 64) == EnqueueOutcome::Append {
                    assert!(!already && count < 64, "appended with count={count} already={already}");
                }
            }
        }
    }

    #[test]
    fn a_full_ring_of_distinct_tasks_is_unreachable_while_queued_holds() {
        // The safety argument for `Task::queued`, stated as a test: with at
        // most MAX_TASKS tasks and at most one queue entry each, one CPU's
        // queues can never hold more than MAX_TASKS entries — so a
        // MAX_TASKS-deep ring cannot be asked to hold one more.
        let capacity = crate::task::MAX_TASKS;
        for queued_elsewhere in 0..capacity {
            let room_here = capacity - queued_elsewhere;
            assert_eq!(
                enqueue_decision(false, room_here.saturating_sub(1), capacity),
                EnqueueOutcome::Append,
                "a distinct task must always fit while the invariant holds"
            );
        }
    }
}

// ── Ring-3 scenario that would actually demonstrate the race ────────────────
//
// The tests above cannot observe an SMP interleaving; only the kernel can.
// The scenario below is what `userspace/tests/ipctest/` must do under `-smp 4`.
// It is written to be implementable by another lane without reading this
// crate.
//
// Shape:
//   * Parent registers as a fast-IPC server and `fork()`s N ≥ 8 children.
//   * Each child immediately issues SYS_IPC_FAST_CALL(parent_tid, [seq,0,0,0])
//     in a loop of M ≥ 200 iterations.
//   * The parent loops SYS_IPC_FAST_ACCEPT → SYS_IPC_FAST_REPLY(slot,
//     [seq ^ MAGIC, ...]) with NO delay between accept and reply. The tight
//     accept/reply loop is what makes the reply land inside the client's
//     window between wake_fast_ipc_server() and task_block(); adding a sleep
//     there hides the bug.
//   * Children must be pinned across harts (or left unpinned) so client and
//     server genuinely run on different harts — on `-smp 1` the race cannot
//     occur and the test proves nothing. Assert the hart count at startup.
//
// What to assert:
//   1. Every one of the N×M calls returns, and returns `seq ^ MAGIC` for its
//      own `seq`. A wrong value means a reply was collected by the wrong
//      client (slot aliasing), which is a *different* bug from ours.
//   2. Each child prints `IPCTEST child=<i> done=<M>` and the parent prints
//      `IPCTEST all=<N*M> OK` only after all children exited. The harness
//      greps for `IPCTEST all=`.
//   3. A per-child watchdog: before each call the child records `seq` in a
//      known location (a global it also prints on a timer, or simply
//      printing `IPCTEST child=<i> seq=<k>` every 32 iterations). This is
//      what separates the two failure modes.
//
// How to tell "hung on the lost wakeup" from "hung on something else" — this
// is the part that matters, because a bare timeout proves nothing:
//   * Lost wakeup (K-C10) looks like: the run stops making progress, the
//     LAST line for one or more children is a `seq=` line, and the *parent*
//     keeps going or itself blocks in FAST_ACCEPT with no pending call. The
//     signature is that the stuck child is `Blocked` on
//     `WaitReason::FastIpcClient(slot)` while its slot is already replied to
//     — i.e. the reply data is present but nobody collected it. Expose this
//     from the shell: a `ps`-style dump showing state + wait_reason per task
//     plus the fast-IPC slot table (owner TID, replied flag). If a slot is
//     `replied=true` with its owner `Blocked on FastIpcClient(that slot)`,
//     that is K-C10 and nothing else.
//   * Slot exhaustion looks different: FAST_CALL returns -1 immediately
//     rather than hanging. Children must print `IPCTEST child=<i> ENOSLOT`
//     and continue, so exhaustion never masquerades as a hang.
//   * A `-1` from `fast_ipc_collect` after a *successful* wake is the
//     spurious-`wake_pending` signature (see the K-C10 report): the call
//     returns, but with -1 and no reply. Children must count those
//     separately and print `IPCTEST child=<i> spurious=<n>`; a non-zero
//     count is a real finding even if the run completes.
//   * Anything else (fork failure, scheduler deadlock, page fault) shows up
//     as a missing `IPCTEST child=<i> done=` line with no preceding `seq=`
//     progress at all, or as a board reset — distinguishable because the
//     panic handler prints first.
//
// Expected result today: with the K-C10 fix in `wake_fast_ipc_server` the
// FAST_ACCEPT side is closed, but the client side is only closed once
// `SYS_IPC_FAST_REPLY` switches from `wake_fast_ipc_client(slot)` to
// `wake_fast_ipc_client_tid(caller_tid, slot)`. Until that call-site change
// lands, this scenario should still hang — which makes it a genuine
// regression test rather than a formality.

// ═══════════════════════════════════════════════════════════════════════════
// Carril E — ELF loader bounds and hart-liveness accounting
// ═══════════════════════════════════════════════════════════════════════════
//
// Both modules below are compiled from the kernel tree verbatim, exactly like
// `task.rs`/`wait.rs` above: no copies, no stubs, no dependencies to stub.
// They were split out of `process.rs` / `smp.rs` precisely so that they could
// be — the files they came from cannot leave the RISC-V target (PTE flags and
// the physical allocator in one, `mv tp` and `_secondary_start` in the other).
//
// What this does NOT cover, stated rather than papered over:
//   * The page-table half of `load_elf_into` — `vmm::map`,
//     `vmm::translate_user` reuse, `add_user_leaf_perms` and the W^X refusal
//     of EXEC-onto-WRITE. Those need a page table, so they need the target.
//   * `wake_harts` itself: the SBI call and `current_cpu_id()`. Only the
//     accounting it feeds is here — but the accounting *was* the bug.

#[path = "../../../../crates/core/sched/src/elf_bounds.rs"]
pub mod elf_bounds;

#[path = "../../../../crates/core/sched/src/hart_set.rs"]
pub mod hart_set;

// U02-6 (orphaned `EXIT_NOTE` entries poisoning the 32-slot table; a dead
// parent's TID never dropped from a pending notice, so the FIFO eviction
// started discarding LIVE parents' real notices). Pure logic, no
// `unsafe`, no global state — compiles unmodified from the kernel tree.
#[path = "../../../../crates/core/sched/src/exit_note.rs"]
pub mod exit_note;

// RFC-0055 (wave 11): who may stop whom (`SYS_TASK_KILL`), and the stop word.
#[path = "../../../../crates/core/sched/src/stop_policy.rs"]
pub mod stop_policy;

// U02-6, second half (`NEXT_TID` wrap has no liveness check). Same
// pattern: pure logic, compiles unmodified.
#[path = "../../../../crates/core/sched/src/tid_alloc.rs"]
pub mod tid_alloc;

// Task 3a: the O(NUM_PRIORITIES) resident-placement histogram, replacing
// `find_best_cpu`'s O(MAX_TASKS) scan. Pure logic, compiles unmodified;
// its own `#[cfg(test)]` module (the random field-change replay against
// the real `task::resident_load_contribution` full scan) runs here.
#[path = "../../../../crates/core/sched/src/resident_histogram.rs"]
pub mod resident_histogram;

// U02-3: the indexed timer min-heap behind `sched-timer-heap`. Pure logic;
// its `#[cfg(test)]` module (ordering, re-arm, cancel, top-of-range
// comparison, random ops against the sweep model) runs here.
#[path = "../../../../crates/core/sched/src/timer_heap.rs"]
pub mod timer_heap;

#[path = "../../../../crates/core/sched/src/ready_list.rs"]
pub mod ready_list;

// The fast-IPC same-hart direct switch's eligibility rule
// (`scheduler::ipc_wake_then_block`). Pure; its `#[cfg(test)]` module holds
// the priority-inheritance case: a lessee boosted into a better bucket than
// the woken server must refuse the switch.
#[path = "../../../../crates/core/sched/src/ipc_direct.rs"]
pub mod ipc_direct;

// Priority donation (lease priority inheritance and the user-driver proxy
// share it): the rule, the counted boost and return. Pure; its
// `#[cfg(test)]` module (composition of two donors, return order, a wait
// cycle making one edge) runs here.
#[path = "../../../../crates/core/sched/src/donation.rs"]
pub mod donation;

/// The donation-vs-last-restore race (wave 9), forced.
///
/// `donation::boost_locked` / `restore_locked` are the functions the kernel's
/// `boost_ready_task` / `restore_ready_task` (and the PiMutex pair) call, with
/// `scheduler::TaskDonation` as the target. Here the target is `Cell`, whose
/// lock is a real spin lock, and the restore's `between` hook — the window
/// after the count reaches 0 and before the base priority is written — starts
/// a boost on a second thread and gives it up to 300 ms to land.
///
/// With the lock, the boost cannot land there: it waits for the restore to
/// finish, and the target ends at the donated priority with one donation.
/// `NoLock` is the same target with the lock removed: the boost lands inside
/// the window and the restore then writes the base over it — the target ends
/// at base with a donation outstanding, which is the bug.
///
/// **Canary (run by hand, wave-9 PROXY2 report):** delete `c.lock()` /
/// `c.unlock()` from `restore_locked` and `the_last_restore_cannot_swallow_a_racing_boost`
/// goes red with `(24, 1)`.
#[cfg(test)]
mod donation_race_tests {
    use super::donation::{boost_locked, restore_locked, DonationCell};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    const BASE: u32 = 24;
    const DONOR_A: u32 = 14;
    const DONOR_B: u32 = 10;

    struct Cell {
        locked: AtomicBool,
        use_lock: bool,
        count: AtomicU32,
        prio: AtomicU32,
        base: u32,
    }

    impl Cell {
        fn new(use_lock: bool) -> Arc<Self> {
            Arc::new(Cell {
                locked: AtomicBool::new(false),
                use_lock,
                count: AtomicU32::new(0),
                prio: AtomicU32::new(BASE),
                base: BASE,
            })
        }
        fn state(&self) -> (u32, u32) {
            (self.prio.load(Ordering::SeqCst), self.count.load(Ordering::SeqCst))
        }
    }

    impl DonationCell for Cell {
        fn lock(&self) {
            if !self.use_lock {
                return;
            }
            while self.locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                std::thread::yield_now();
            }
        }
        fn unlock(&self) {
            if self.use_lock {
                self.locked.store(false, Ordering::Release);
            }
        }
        fn count(&self) -> u32 { self.count.load(Ordering::SeqCst) }
        fn set_count(&self, c: u32) { self.count.store(c, Ordering::SeqCst) }
        fn prio(&self) -> u32 { self.prio.load(Ordering::SeqCst) }
        fn base(&self) -> u32 { self.base }
        fn apply_prio(&self, p: u32) { self.prio.store(p, Ordering::SeqCst) }
    }

    /// Donor A's last restore races donor B's boost, in the window.
    fn race(use_lock: bool) -> (u32, u32) {
        let c = Cell::new(use_lock);
        boost_locked(&*c, DONOR_A);
        assert_eq!(c.state(), (DONOR_A, 1));
        let (tx, rx) = mpsc::channel();
        let c2 = Arc::clone(&c);
        let mut booster = None;
        restore_locked(&*c, || {
            booster = Some(std::thread::spawn(move || {
                boost_locked(&*c2, DONOR_B);
                let _ = tx.send(());
            }));
            // Unlocked, the boost lands in here; locked, it cannot, and the
            // wait times out.
            let _ = rx.recv_timeout(Duration::from_millis(300));
        });
        booster.unwrap().join().unwrap();
        c.state()
    }

    #[test]
    fn the_last_restore_cannot_swallow_a_racing_boost() {
        assert_eq!(race(true), (DONOR_B, 1),
                   "donor B is waiting (count 1) but the target is not at its priority");
    }

    /// The instrument: without the lock the same interleaving reproduces the
    /// race, so the test above discriminates.
    #[test]
    fn without_the_lock_the_race_is_reproduced() {
        assert_eq!(race(false), (BASE, 1));
    }

    /// Many donors on many threads, each a boost then a restore: every
    /// interleaving ends at base with no donation outstanding, and while a
    /// donor is between its boost and its restore the target is never at base.
    #[test]
    fn concurrent_donors_balance_and_never_expose_base_while_one_waits() {
        let c = Cell::new(true);
        let seen_base_while_waiting = Arc::new(AtomicBool::new(false));
        let mut hs = Vec::new();
        for t in 0..8u32 {
            let c = Arc::clone(&c);
            let seen = Arc::clone(&seen_base_while_waiting);
            hs.push(std::thread::spawn(move || {
                for _ in 0..2000 {
                    boost_locked(&*c, 4 + t);
                    if c.prio() == BASE {
                        seen.store(true, Ordering::SeqCst);
                    }
                    restore_locked(&*c, || {});
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(c.state(), (BASE, 0));
        assert!(!seen_base_while_waiting.load(Ordering::SeqCst),
                "a donor between its boost and its return saw the target at base");
    }
}

/// The ready queues as intrusive lists (`ready_list`, wave 15
/// NRCPUS-FLEET-AREA): FIFO order, removal from anywhere keeping order, one
/// link table shared by several lists, and walks that stay bounded and in
/// range over garbage links (the audit's lockless walk).
///
/// **Canaries.** `push_back` that does not link the old tail: `fifo_order`
/// red. `remove` that leaves `tail` on the removed slot:
/// `removing_the_tail_then_appending_keeps_the_list` red. `iter` without the
/// `count` bound: `a_cycle_in_the_links_ends_the_walk` hangs. A `next[..]`
/// index without `get`: `garbage_links_never_index_out_of_range` panics.
#[cfg(test)]
mod ready_list_tests {
    use super::ready_list::{ReadyList, EMPTY};
    use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

    const CAP: usize = 64;

    fn links() -> Vec<AtomicU32> {
        (0..CAP).map(|_| AtomicU32::new(0)).collect()
    }
    fn push(q: &ReadyList, next: &[AtomicU32], v: &[usize]) {
        for &x in v {
            q.push_back(next, x, q.count());
        }
    }
    fn read(q: &ReadyList, next: &[AtomicU32]) -> Vec<usize> {
        q.iter(next).collect()
    }

    #[test]
    fn fifo_order() {
        let next = links();
        let q = EMPTY;
        push(&q, &next, &[5, 1, 9, 3]);
        assert_eq!(read(&q, &next), vec![5, 1, 9, 3]);
        let mut out = vec![];
        while q.count() > 0 {
            out.push(q.pop_front(&next, q.count()).unwrap());
        }
        assert_eq!(out, vec![5, 1, 9, 3]);
        assert_eq!(read(&q, &next), Vec::<usize>::new());
        push(&q, &next, &[7]);
        assert_eq!(read(&q, &next), vec![7], "an emptied list takes a new head");
    }

    #[test]
    fn removes_from_anywhere_keeping_order() {
        let next = links();
        let q = EMPTY;
        push(&q, &next, &[10, 11, 12, 13, 14]);
        assert_eq!(q.remove(&next, 12), Some(4));
        assert_eq!(read(&q, &next), vec![10, 11, 13, 14]);
        assert_eq!(q.remove(&next, 10), Some(3));
        assert_eq!(read(&q, &next), vec![11, 13, 14]);
        assert_eq!(q.remove(&next, 42), None, "absent: nothing written");
        assert_eq!(read(&q, &next), vec![11, 13, 14]);
    }

    #[test]
    fn removing_the_tail_then_appending_keeps_the_list() {
        let next = links();
        let q = EMPTY;
        push(&q, &next, &[1, 2, 3]);
        assert_eq!(q.remove(&next, 3), Some(2));
        push(&q, &next, &[4]);
        assert_eq!(read(&q, &next), vec![1, 2, 4]);
        assert_eq!(q.remove(&next, 1), Some(2));
        assert_eq!(q.remove(&next, 2), Some(1));
        assert_eq!(q.remove(&next, 4), Some(0));
        push(&q, &next, &[6]);
        assert_eq!(read(&q, &next), vec![6]);
    }

    /// Several lists (the 32 levels of every CPU) share one link table: a
    /// slot moves from one to another as it does on a priority change.
    #[test]
    fn lists_share_one_link_table() {
        let next = links();
        let (a, b) = (EMPTY, EMPTY);
        push(&a, &next, &[1, 2, 3]);
        push(&b, &next, &[4, 5]);
        assert_eq!(a.remove(&next, 2), Some(2));
        push(&b, &next, &[2]);
        assert_eq!(read(&a, &next), vec![1, 3]);
        assert_eq!(read(&b, &next), vec![4, 5, 2]);
    }

    #[test]
    fn a_cycle_in_the_links_ends_the_walk() {
        let next = links();
        let q = EMPTY;
        push(&q, &next, &[1, 2]);
        next[2].store(1, Relaxed); // 2 -> 1 again: a cycle
        assert_eq!(read(&q, &next).len(), 2, "bounded by count");
        assert_eq!(q.remove(&next, 9), None, "a remove over a cycle ends");
    }

    #[test]
    fn garbage_links_never_index_out_of_range() {
        let next = links();
        let q = EMPTY;
        push(&q, &next, &[1, 2, 3]);
        next[2].store(u32::MAX, Relaxed);
        assert_eq!(read(&q, &next), vec![1, 2], "the walk stops at the bad link");
        assert_eq!(q.remove(&next, 3), None);
        next[1].store(CAP as u32 + 7, Relaxed);
        q.pop_front(&next, q.count());
        assert!(read(&q, &next).is_empty() || read(&q, &next).iter().all(|&s| s < CAP));
    }

    /// The per-CPU area relies on this: sixteen bytes a level (a shift away),
    /// all-zero empty.
    #[test]
    fn a_level_is_sixteen_bytes_and_zero_is_empty() {
        assert_eq!(core::mem::size_of::<ReadyList>(), 16);
        let q = ReadyList::default();
        assert_eq!(q.count(), 0);
        assert!(read(&q, &links()).is_empty());
    }
}

// `task.rs` names `crate::user_window::USER_WINDOW_RANGES`, so the per-task
// shm/MMIO window allocator is pulled in too, and tested below.
#[path = "../../../../crates/core/sched/src/user_window.rs"]
pub mod user_window;

#[cfg(test)]
mod user_window_tests {
    use super::user_window::{release, reserve, USER_WINDOW_RANGES};

    const P: usize = 4096;
    const LO: usize = 0x6000_0000;
    const HI: usize = LO + 16 * P;

    fn empty() -> [[usize; 2]; USER_WINDOW_RANGES] {
        [[0; 2]; USER_WINDOW_RANGES]
    }

    /// **A released range is handed out again** — the property the board-wide
    /// cursor this replaced did not have.
    ///
    /// **Canary.** `release` that frees nothing: the third reservation lands at
    /// `LO + 4P`.
    #[test]
    fn a_released_range_is_handed_out_again() {
        let mut w = empty();
        assert_eq!(reserve(&mut w, LO, HI, 2 * P), Some(LO));
        assert_eq!(reserve(&mut w, LO, HI, 2 * P), Some(LO + 2 * P));
        assert!(release(&mut w, LO, 2 * P));
        assert_eq!(reserve(&mut w, LO, HI, 2 * P), Some(LO));
    }

    /// **First fit: the lowest gap wide enough, never an overlap.** A one-page
    /// hole between reservations takes a one-page request and is skipped by a
    /// two-page one.
    ///
    /// **Canary.** Test overlap against `base` instead of `end` (`r[0] < base`):
    /// the two-page request is placed over the hole and the next reservation.
    #[test]
    fn a_reservation_takes_the_lowest_gap_it_fits() {
        let mut w = empty();
        for i in 0..4 {
            assert_eq!(reserve(&mut w, LO, HI, P), Some(LO + i * P));
        }
        assert!(release(&mut w, LO + P, P));
        assert_eq!(reserve(&mut w, LO, HI, 2 * P), Some(LO + 4 * P), "the hole is one page");
        assert_eq!(reserve(&mut w, LO, HI, P), Some(LO + P), "and a page fits it");
    }

    /// **A range may end exactly at the limit, never past it.** Past
    /// `USER_MMIO_LIMIT` lie the user stack and then the kernel's own tables.
    ///
    /// **Canary.** `end >= hi`: the whole-window reservation is refused.
    #[test]
    fn a_range_may_end_at_the_limit_and_not_past_it() {
        let mut w = empty();
        assert_eq!(reserve(&mut w, LO, HI, 17 * P), None);
        assert_eq!(reserve(&mut w, LO, HI, 16 * P), Some(LO));
        assert!(release(&mut w, LO, 16 * P));
        assert_eq!(reserve(&mut w, LO, HI, P), Some(LO));
        assert_eq!(reserve(&mut w, LO, HI, 16 * P), None, "the only gap is 15 pages");
        assert_eq!(reserve(&mut w, LO, HI, 15 * P), Some(LO + P));
    }

    /// **Only the exact pair a reservation returned is released**, once. A
    /// release by base alone would free a mapping's addresses for a different
    /// length than it has.
    ///
    /// **Canary.** Match on the base only: the one-page release of a two-page
    /// reservation succeeds.
    #[test]
    fn only_the_exact_pair_is_released() {
        let mut w = empty();
        assert_eq!(reserve(&mut w, LO, HI, 2 * P), Some(LO));
        assert!(!release(&mut w, LO, P));
        assert!(!release(&mut w, LO + P, P));
        assert!(!release(&mut w, LO, 0));
        assert_eq!(reserve(&mut w, LO, HI, P), Some(LO + 2 * P), "a refused release freed nothing");
        assert!(release(&mut w, LO, 2 * P));
        assert!(!release(&mut w, LO, 2 * P), "a pair is released once");
    }

    /// **A full table refuses with room left in the window, and an empty span
    /// is not a reservation.** A zero span stored would read as a free pair.
    ///
    /// **Canary.** Drop the `span == 0` refusal: the empty request answers
    /// `Some(LO)`.
    #[test]
    fn a_full_table_refuses_and_an_empty_span_reserves_nothing() {
        let mut w = [[0usize; 2]; 3];
        assert_eq!(reserve(&mut w, LO, HI, 0), None);
        for i in 0..3 {
            assert_eq!(reserve(&mut w, LO, HI, P), Some(LO + i * P));
        }
        assert_eq!(reserve(&mut w, LO, HI, P), None, "three pairs, three reservations");
        assert!(release(&mut w, LO + P, P));
        assert_eq!(reserve(&mut w, LO, HI, P), Some(LO + P));
    }
}

#[cfg(test)]
mod elf_bounds_tests {
    use super::elf_bounds::{
        check_exec_headers, check_page_sharing, check_pt_load, page_up, seg_perms, SegCheck, SegLimits,
        SegPerms, SegReject,
    };

    /// The real limits, spelled out because this crate cannot depend on
    /// `azos_mm` (RISC-V CSRs) or `azos_sched` (ditto).
    ///
    /// `guard_limit` is `vmm::USER_GUARD_LIMIT`, `low_max` is
    /// `process::USER_LOW_MAX`, `page_size` is `mmu::PAGE_SIZE`. If any of
    /// those three moves, `real_images_still_load` below is what should fail
    /// first — it replays the segment tables measured off the actual binaries.
    const LIM: SegLimits = SegLimits {
        guard_limit: 0x1_0000,
        low_max: 0x0200_0000,
        page_size: 4096,
    };

    /// A well-formed segment, to be perturbed one field at a time.
    fn ok(p_vaddr: usize, p_memsz: usize) -> SegCheck {
        check_pt_load(0x1000, p_vaddr, p_memsz, p_memsz, 0x10_0000, 0, LIM)
    }

    fn reject_of(c: SegCheck) -> SegReject {
        match c {
            SegCheck::Reject(r) => r,
            other => panic!("expected a rejection, got {:?}", other),
        }
    }

    fn range_of(c: SegCheck) -> (usize, usize) {
        match c {
            SegCheck::Load(r) => (r.va_start, r.va_end),
            other => panic!("expected the segment to load, got {:?}", other),
        }
    }

    // ── The lower bound itself ──────────────────────────────────────────

    #[test]
    fn page_zero_is_refused() {
        // The whole point of the encargo: a legal ELF can name p_vaddr = 0,
        // and before this the loader mapped it, which made the null guard in
        // handle_demand_fault/handle_cow_fault meaningless for that process.
        assert_eq!(reject_of(ok(0, 0x1000)), SegReject::NullGuard);
    }

    #[test]
    fn just_below_the_guard_limit_is_refused() {
        assert_eq!(reject_of(ok(0xFFFF, 1)), SegReject::NullGuard);
        assert_eq!(reject_of(ok(0xF000, 0x1000)), SegReject::NullGuard);
    }

    #[test]
    fn exactly_the_guard_limit_still_loads() {
        // The single most dangerous off-by-one in this change. 0x10000 is
        // both USER_GUARD_LIMIT and the min PT_LOAD p_vaddr of every one of
        // the 12 binaries in build/. A `<=` here bricks all of userspace,
        // and with QEMU off the table this assertion is the only thing
        // standing between that and a commit.
        assert_eq!(range_of(ok(0x1_0000, 0x1000)), (0x1_0000, 0x1_1000));
    }

    #[test]
    fn just_above_the_guard_limit_still_loads() {
        assert_eq!(range_of(ok(0x1_0001, 1)), (0x1_0000, 0x1_1000));
    }

    #[test]
    fn a_segment_ending_inside_the_guard_cannot_exist() {
        // p_vaddr is the only lower bound needed: memsz only ever grows the
        // range upwards, so no accepted segment can reach below the guard.
        for va in [0x1_0000usize, 0x1_0001, 0x2_0000] {
            let (start, _) = range_of(ok(va, 1));
            assert!(start >= LIM.guard_limit, "va_start {:#x} below the guard", start);
        }
    }

    // ── Upper bound and overflow ────────────────────────────────────────

    #[test]
    fn the_low_max_ceiling_is_exclusive_for_the_start() {
        assert_eq!(reject_of(ok(LIM.low_max, 1)), SegReject::StartAboveLowMax);
        assert_eq!(reject_of(ok(LIM.low_max + 1, 1)), SegReject::StartAboveLowMax);
    }

    #[test]
    fn the_low_max_ceiling_is_inclusive_for_the_end() {
        // A segment may end exactly at the ceiling.
        let (_, end) = range_of(ok(LIM.low_max - 0x1000, 0x1000));
        assert_eq!(end, LIM.low_max);
        assert_eq!(
            reject_of(ok(LIM.low_max - 0x1000, 0x1001)),
            SegReject::EndOutOfRange
        );
    }

    #[test]
    fn memsz_overflow_rejects_instead_of_panicking() {
        // overflow-checks = true + panic = abort: an unchecked p_vaddr +
        // p_memsz here is a board reset driven by a file on a FAT volume.
        assert_eq!(reject_of(ok(0x1_0000, usize::MAX)), SegReject::EndOutOfRange);
        assert_eq!(
            reject_of(ok(0x1_0000, usize::MAX - 0x1_0000)),
            SegReject::EndOutOfRange
        );
    }

    #[test]
    fn an_absurd_vaddr_is_caught_by_the_ceiling_not_by_arithmetic() {
        assert_eq!(reject_of(ok(usize::MAX, 1)), SegReject::StartAboveLowMax);
        assert_eq!(reject_of(ok(usize::MAX, usize::MAX)), SegReject::StartAboveLowMax);
    }

    // ── File-range bounds ───────────────────────────────────────────────

    #[test]
    fn filesz_over_memsz_is_refused() {
        let c = check_pt_load(0x1000, 0x1_0000, 0x2000, 0x1000, 0x10_0000, 0, LIM);
        assert_eq!(reject_of(c), SegReject::FileSizeOverMemSize);
    }

    #[test]
    fn a_file_range_past_the_blob_is_refused() {
        let c = check_pt_load(0xF000, 0x1_0000, 0x2000, 0x2000, 0x10_000, 0, LIM);
        assert_eq!(reject_of(c), SegReject::FileRangeOutOfBlob);
    }

    #[test]
    fn an_offset_overflow_rejects_instead_of_panicking() {
        let c = check_pt_load(usize::MAX, 0x1_0000, 0x1000, 0x1000, 0x10_0000, 0, LIM);
        assert_eq!(reject_of(c), SegReject::FileRangeOutOfBlob);
    }

    // ── Segment ordering (the invariant the reuse branch documented) ─────

    #[test]
    fn a_descending_segment_is_refused() {
        // Header order, not vaddr order, drives the loop. An image whose
        // second PT_LOAD sits below the first used to be loaded anyway, and
        // its file bytes rewrote the first segment's already-mapped page.
        let c = check_pt_load(0x1000, 0x1_0000, 0x100, 0x100, 0x10_0000, 0x1_1000, LIM);
        assert_eq!(reject_of(c), SegReject::Descending);
    }

    #[test]
    fn a_segment_starting_exactly_at_the_previous_end_is_allowed() {
        // Not hypothetical: brain_client, gpio_drv, ipctest, reflex and
        // uhello all have .rodata starting at exactly .text's end byte.
        // A `>` here instead of `>=` would reject 5 of the 12 real images.
        let c = check_pt_load(0x1c72, 0x1_0c72, 0x1b3, 0x1b3, 0x10_0000, 0x1_0c72, LIM);
        assert!(matches!(c, SegCheck::Load(_)), "got {:?}", c);
    }

    #[test]
    fn segments_sharing_a_page_but_not_a_byte_are_allowed() {
        let c = check_pt_load(0x1b48, 0x1_0b48, 0x849, 0x849, 0x10_0000, 0x1_0b44, LIM);
        let (start, end) = range_of(c);
        assert_eq!((start, end), (0x1_0000, 0x1_2000));
    }

    // ── Empty segments ──────────────────────────────────────────────────

    #[test]
    fn a_zero_memsz_segment_is_skipped_not_rejected() {
        // Deliberate, and it is why the null-guard check sits after it: a
        // PT_LOAD with p_memsz = 0 maps nothing at all, so even p_vaddr = 0
        // is inert. Rejecting it would refuse images that are merely odd.
        assert_eq!(check_pt_load(0, 0, 0, 0, 0, 0, LIM), SegCheck::Empty);
        assert_eq!(check_pt_load(0, usize::MAX, 0, 0, 0, 0, LIM), SegCheck::Empty);
    }

    // ── Page rounding ───────────────────────────────────────────────────

    #[test]
    fn page_up_saturates_instead_of_wrapping() {
        assert_eq!(page_up(0, 4096), 0);
        assert_eq!(page_up(1, 4096), 4096);
        assert_eq!(page_up(4096, 4096), 4096);
        assert_eq!(page_up(usize::MAX, 4096), usize::MAX & !4095);
    }

    #[test]
    fn an_unaligned_segment_maps_from_its_page_base() {
        let (start, end) = range_of(ok(0x1_0b48, 0x849));
        assert_eq!((start, end), (0x1_0000, 0x1_2000));
    }

    // ── Nothing in this range may panic ─────────────────────────────────

    #[test]
    fn no_input_anywhere_near_the_threshold_panics() {
        // A panic under this profile is a board reset, and `exec` is
        // reachable from ring 3, so "returns something" is the assertion.
        let interesting = [
            0usize, 1, 0xFFF, 0x1000, 0xFFFF, 0x1_0000, 0x1_0001,
            LIM.low_max - 1, LIM.low_max, LIM.low_max + 1,
            usize::MAX / 2, usize::MAX - 1, usize::MAX,
        ];
        let mut loaded = 0;
        let mut rejected = 0;
        for &va in &interesting {
            for &memsz in &interesting {
                for &filesz in &interesting {
                    for &off in &interesting {
                        match check_pt_load(off, va, filesz, memsz, 0x10_0000, 0, LIM) {
                            SegCheck::Load(_) => loaded += 1,
                            _ => rejected += 1,
                        }
                    }
                }
            }
        }
        assert_eq!(loaded + rejected, interesting.len().pow(4));
        assert!(loaded > 0, "the sweep must exercise the accepting path too");
    }

    #[test]
    fn every_prev_seg_end_is_survivable() {
        for &prev in &[0usize, 0x1_0000, LIM.low_max, usize::MAX] {
            let _ = check_pt_load(0x1000, 0x1_0000, 0x100, 0x100, 0x10_0000, prev, LIM);
        }
    }

    // ── Regression: the real images must still load ─────────────────────

    /// Every PT_LOAD of every ELF in `build/`, read off the files with a
    /// program-header parser (`p_offset, p_vaddr, p_filesz, p_memsz`).
    /// Grouped per image so the ordering check sees the real sequence.
    const REAL_IMAGES: &[(&str, &[(usize, usize, usize, usize)])] = &[
        ("abitest",      &[(0x1000, 0x10000, 0xb44, 0xb44), (0x1b48, 0x10b48, 0x849, 0x849), (0x3000, 0x12000, 0x0, 0x8)]),
        ("brain_client", &[(0x1000, 0x10000, 0xc72, 0xc72), (0x1c72, 0x10c72, 0x1b3, 0x1b3)]),
        ("captest",      &[(0x1000, 0x10000, 0x3dc, 0x3dc), (0x13e0, 0x103e0, 0x1a5, 0x1a5), (0x2000, 0x11000, 0x0, 0x4)]),
        ("gpio_drv",     &[(0x1000, 0x10000, 0x15a, 0x15a), (0x115a, 0x1015a, 0x46, 0x46)]),
        ("hello",        &[(0x1000, 0x10000, 0x35, 0x35)]),
        ("ipctest",      &[(0x1000, 0x10000, 0x1cfa, 0x1cfa), (0x2d00, 0x11d00, 0xa2c, 0xa2c), (0x4000, 0x13000, 0x8, 0xd0)]),
        ("ipctest2",     &[(0x1000, 0x10000, 0x1860, 0x1860), (0x2860, 0x11860, 0x827, 0x827), (0x4000, 0x13000, 0x8, 0xc8)]),
        ("latbench",     &[(0x1000, 0x10000, 0x48c, 0x48c), (0x1490, 0x10490, 0x284, 0x284)]),
        ("reflex",       &[(0x1000, 0x10000, 0x1f0, 0x1f0), (0x11f0, 0x101f0, 0xbb, 0xbb)]),
        ("syscall_test", &[(0x1000, 0x10000, 0xe7, 0xe7)]),
        ("uhello",       &[(0x1000, 0x10000, 0x34, 0x34), (0x1034, 0x10034, 0x24, 0x24)]),
    ];

    #[test]
    fn real_images_still_load() {
        // The bound is only as good as the fact that it costs nothing. If a
        // future edit tightens `guard_limit`, moves `low_max`, or turns the
        // ordering check into `>`, this is what says which binaries died.
        for (name, segs) in REAL_IMAGES {
            let mut prev_seg_end = 0usize;
            for &(off, va, filesz, memsz) in *segs {
                let blob_len = off + filesz + 0x1000; // every real p_offset is in range
                match check_pt_load(off, va, filesz, memsz, blob_len, prev_seg_end, LIM) {
                    SegCheck::Load(r) => prev_seg_end = r.seg_end,
                    other => panic!("{}: segment at {:#x} refused: {:?}", name, va, other),
                }
            }
        }
    }

    /// Wave 15 (VI): a page two segments share took the union of their
    /// permissions, so `.rodata` on the last `.text` page was executable.
    /// A segment that starts on the page the previous one ends on, mapped
    /// differently, refuses the image: code then rodata, rodata then data,
    /// code then data. Canary `elf-mixed-page-canary` (gate row): accepted.
    #[test]
    fn a_page_shared_by_segments_mapped_differently_is_refused() {
        use SegPerms::*;
        let p = LIM.page_size;
        // .text 0x10000..0x10100 (RX), .rodata from 0x10100 (R): one page.
        assert_eq!(check_page_sharing(0x10100, Some(ReadExec), 0x10100, ReadOnly, p),
                   Err(SegReject::SharedPageMixedPerms));
        // A gap inside the page is still the same page.
        assert_eq!(check_page_sharing(0x10100, Some(ReadExec), 0x10ff8, ReadOnly, p),
                   Err(SegReject::SharedPageMixedPerms));
        assert_eq!(check_page_sharing(0x11391, Some(ReadOnly), 0x11394, ReadWrite, p),
                   Err(SegReject::SharedPageMixedPerms));
        assert_eq!(check_page_sharing(0x10850, Some(ReadExec), 0x10850, ReadWrite, p),
                   Err(SegReject::SharedPageMixedPerms));
        assert_eq!(check_page_sharing(0x10850, Some(ReadWrite), 0x10900, ReadExec, p),
                   Err(SegReject::SharedPageMixedPerms));
    }

    /// What the refusal leaves alone: the first segment; a segment on the
    /// next page at the same offset (the layout `user*.ld`, lld and GNU ld
    /// produce); a previous segment that ends exactly on a page boundary;
    /// two segments mapped alike sharing a page.
    #[test]
    fn segments_on_pages_of_their_own_or_mapped_alike_load() {
        use SegPerms::*;
        let p = LIM.page_size;
        assert_eq!(check_page_sharing(0, None, 0x10000, ReadExec, p), Ok(()));
        assert_eq!(check_page_sharing(0x10850, Some(ReadExec), 0x11850, ReadOnly, p), Ok(()));
        assert_eq!(check_page_sharing(0x11000, Some(ReadExec), 0x11000, ReadOnly, p), Ok(()));
        assert_eq!(check_page_sharing(0x100e000, Some(ReadWrite), 0x100e090, ReadWrite, p), Ok(()));
        assert_eq!(check_page_sharing(0x10850, Some(ReadOnly), 0x10900, ReadOnly, p), Ok(()));
    }

    /// GR3: an executable segment over the ELF/program headers is the
    /// program-header signature of `.rodata` folded into the text segment.
    /// The 16 KiB `lxhello` linked `--no-rosegment` (one RX segment from
    /// file offset 0, headers end 0x120) is refused; so is GNU ld's default
    /// riscv64/aarch64 text segment (offset 0, R E). Canary: Kconfig
    /// ELF_REFUSE_EXEC_HEADERS off (the loader skips the check).
    #[test]
    fn an_executable_segment_over_the_headers_is_refused() {
        assert_eq!(check_exec_headers(5, 0, 0x96c4, 0x120), Err(SegReject::ExecMapsHeaders));
        // One byte of the program header table is enough.
        assert_eq!(check_exec_headers(5, 0x11f, 0x100, 0x120), Err(SegReject::ExecMapsHeaders));
        // PF_R absent changes nothing: the loader maps it read-execute.
        assert_eq!(check_exec_headers(1, 0, 0x100, 0x40), Err(SegReject::ExecMapsHeaders));
    }

    /// What it leaves alone: lld's default layout (headers and `.rodata` in
    /// the R segment at offset 0, text from 0xd88); the 16/64 KiB native
    /// `user_aarch64.ld` (text from exactly the end of the headers, which
    /// sit in no segment); a read-only or writable segment over the headers;
    /// an executable segment with no file bytes.
    #[test]
    fn segments_clear_of_the_headers_or_not_executable_load() {
        assert_eq!(check_exec_headers(4, 0, 0xd88, 0x120), Ok(()));
        assert_eq!(check_exec_headers(5, 0xd88, 0x8974, 0x120), Ok(()));
        assert_eq!(check_exec_headers(5, 0x120, 0x8000, 0x120), Ok(()));
        assert_eq!(check_exec_headers(5, 0x1000, 0x35, 0x120), Ok(()));
        assert_eq!(check_exec_headers(6, 0, 0x100, 0x120), Ok(()));
        assert_eq!(check_exec_headers(7, 0, 0x100, 0x120), Ok(()));
        assert_eq!(check_exec_headers(5, 0, 0, 0x120), Ok(()));
    }

    /// The mapping class of a header: writable is never executable, and
    /// read-only (with or without PF_R) is never executable.
    #[test]
    fn seg_perms_is_wx_both_ways() {
        assert_eq!(seg_perms(7), SegPerms::ReadWrite);
        assert_eq!(seg_perms(6), SegPerms::ReadWrite);
        assert_eq!(seg_perms(5), SegPerms::ReadExec);
        assert_eq!(seg_perms(1), SegPerms::ReadExec);
        assert_eq!(seg_perms(4), SegPerms::ReadOnly);
        assert_eq!(seg_perms(0), SegPerms::ReadOnly);
    }

    #[test]
    fn every_real_image_starts_exactly_at_the_guard_limit() {
        // The measurement the threshold was chosen from, kept as an
        // assertion instead of a claim in a comment.
        for (name, segs) in REAL_IMAGES {
            let min_va = segs.iter().map(|s| s.1).min().unwrap();
            assert_eq!(min_va, LIM.guard_limit, "{} no longer starts at the guard limit", name);
        }
    }
}

#[cfg(test)]
mod hart_set_tests {
    use super::hart_set::{mark_alive, online_prefix, stranded, HART_MASK_BITS};

    /// The accounting `wake_harts` used before this tanda, reproduced so the
    /// tests can show exactly where it diverges — and where it does not.
    fn legacy_online(num_cpus: usize, boot: usize, started: &[bool]) -> usize {
        let mut online = 1; // "boot hart is already running" — i.e. slot 0
        let mut prefix_intact = true;
        for hart in 0..num_cpus {
            if hart == boot {
                continue;
            }
            if started[hart] {
                if prefix_intact {
                    online += 1;
                }
            } else {
                prefix_intact = false;
            }
        }
        online
    }

    /// What `wake_harts` computes now, from the same inputs.
    fn current_online(num_cpus: usize, boot: usize, started: &[bool]) -> usize {
        let mut alive = mark_alive(0, boot);
        for hart in 0..num_cpus {
            if hart == boot {
                continue;
            }
            if started[hart] {
                alive = mark_alive(alive, hart);
            }
        }
        online_prefix(alive, num_cpus)
    }

    /// True when every hart in `0..online` is actually running — the single
    /// property `find_best_cpu` and `rebalance_from_offline_cpus` rely on.
    fn prefix_is_honest(online: usize, boot: usize, started: &[bool]) -> bool {
        (0..online).all(|h| h == boot || started[h])
    }

    fn all_patterns(num_cpus: usize) -> Vec<Vec<bool>> {
        (0..(1u32 << num_cpus))
            .map(|bits| (0..num_cpus).map(|h| bits & (1 << h) != 0).collect())
            .collect()
    }

    // ── The regression, stated as the concrete measured case ────────────

    #[test]
    fn boot_hart_two_with_hart_zero_dead_used_to_claim_hart_zero_was_alive() {
        // Boot hart 2 was measured in QEMU virt (K-C16 evidence). Harts 1
        // and 3 start, hart 0 does not.
        let started = [false, true, false, true]; // index 2 unused: it is the boot hart
        assert_eq!(legacy_online(4, 2, &started), 1);
        assert!(!prefix_is_honest(1, 2, &started), "legacy published a dead hart 0");

        assert_eq!(current_online(4, 2, &started), 0);
        assert!(prefix_is_honest(0, 2, &started));
    }

    #[test]
    fn boot_hart_two_with_a_hole_used_to_publish_the_dead_hart() {
        // Hart 0 starts, hart 1 fails, hart 3 starts, boot hart is 2.
        let started = [true, false, false, true];
        assert_eq!(legacy_online(4, 2, &started), 2); // claims harts 0 and 1
        assert!(!prefix_is_honest(2, 2, &started), "legacy published dead hart 1");

        assert_eq!(current_online(4, 2, &started), 1); // only hart 0
        assert!(prefix_is_honest(1, 2, &started));
    }

    #[test]
    fn boot_hart_two_with_everything_up_was_already_correct() {
        // The honest half of the answer: with no hart_start failure the old
        // seed happened to land on the right number, which is why this never
        // showed up in a normal boot.
        let started = [true, true, false, true];
        assert_eq!(legacy_online(4, 2, &started), 4);
        assert_eq!(current_online(4, 2, &started), 4);
    }

    #[test]
    fn with_boot_hart_zero_nothing_changed_at_all() {
        // Exhaustive over every start/fail pattern for 1..=4 harts: the fix
        // must not move the value on the configuration the kernel has always
        // actually run.
        for num_cpus in 1..=4 {
            for mut started in all_patterns(num_cpus) {
                started[0] = true; // the boot hart is running by definition
                assert_eq!(
                    legacy_online(num_cpus, 0, &started),
                    current_online(num_cpus, 0, &started),
                    "num_cpus={} started={:?}",
                    num_cpus,
                    started
                );
            }
        }
    }

    #[test]
    fn the_published_prefix_is_honest_for_every_boot_hart_and_pattern() {
        // The property, checked exhaustively rather than argued: for any boot
        // hart and any failure pattern, every hart below the published value
        // is running. The legacy accounting violates this (see below), which
        // is what makes it a bug and not a stale comment.
        let mut legacy_violations = 0;
        for num_cpus in 1..=4 {
            for boot in 0..num_cpus {
                for mut started in all_patterns(num_cpus) {
                    started[boot] = true;
                    let now = current_online(num_cpus, boot, &started);
                    assert!(
                        prefix_is_honest(now, boot, &started),
                        "num_cpus={} boot={} started={:?} online={}",
                        num_cpus, boot, started, now
                    );
                    if !prefix_is_honest(legacy_online(num_cpus, boot, &started), boot, &started) {
                        legacy_violations += 1;
                    }
                }
            }
        }
        assert!(
            legacy_violations > 0,
            "if the legacy accounting never lied, this whole change is cosmetic"
        );
    }

    #[test]
    fn every_legacy_violation_needs_both_a_nonzero_boot_hart_and_a_failure() {
        // The precise scope of the bug, so the report does not overstate it.
        for num_cpus in 1..=4 {
            for boot in 0..num_cpus {
                for mut started in all_patterns(num_cpus) {
                    started[boot] = true;
                    let legacy = legacy_online(num_cpus, boot, &started);
                    if !prefix_is_honest(legacy, boot, &started) {
                        assert_ne!(boot, 0, "a boot hart of 0 never produced a dishonest prefix");
                        assert!(
                            started.iter().any(|&s| !s),
                            "a run with no hart_start failure never produced a dishonest prefix"
                        );
                    }
                }
            }
        }
    }

    // ── Prefix / stranded semantics ─────────────────────────────────────

    #[test]
    fn a_live_hart_past_a_hole_is_excluded_and_reported() {
        let alive = 0b1011u64; // harts 0,1,3 up; hart 2 dead
        assert_eq!(online_prefix(alive, 4), 2);
        assert_eq!(stranded(alive, 4), 0b1000);
    }

    #[test]
    fn nothing_is_stranded_when_the_set_is_already_a_prefix() {
        assert_eq!(stranded(0b1111, 4), 0);
        assert_eq!(stranded(0b0011, 4), 0);
        assert_eq!(stranded(0b0000, 4), 0);
    }

    #[test]
    fn harts_past_num_cpus_are_not_counted() {
        // A boot hart id above the DTB's cpu count sets a bit outside the
        // range; it must not inflate the prefix.
        assert_eq!(online_prefix(0b1111_1111, 4), 4);
        assert_eq!(stranded(0b1111_0011, 4), 0);
    }

    #[test]
    fn a_dead_hart_zero_publishes_zero_rather_than_a_comfortable_one() {
        // Clamping to 1 would assert hart 0 is alive when it is not. Both
        // consumers guard the zero case; a lie has no guard.
        assert_eq!(online_prefix(0b1110, 4), 0);
    }

    // ── Nothing here may panic ──────────────────────────────────────────

    #[test]
    fn out_of_range_hart_ids_do_not_shift_overflow() {
        // `1u64 << 64` is an overflow panic under overflow-checks, i.e. a
        // board reset, and num_cpus comes from the DTB.
        assert_eq!(mark_alive(0, HART_MASK_BITS), 0);
        assert_eq!(mark_alive(0, HART_MASK_BITS + 1), 0);
        assert_eq!(mark_alive(0, usize::MAX), 0);
        assert_eq!(mark_alive(0b101, 12345), 0b101);
    }

    #[test]
    fn an_absurd_cpu_count_saturates_at_the_mask_width() {
        assert_eq!(online_prefix(u64::MAX, usize::MAX), HART_MASK_BITS);
        assert_eq!(online_prefix(u64::MAX, HART_MASK_BITS), HART_MASK_BITS);
        assert_eq!(stranded(u64::MAX, usize::MAX), 0);
        assert_eq!(stranded(u64::MAX - 1, usize::MAX), u64::MAX - 1);
    }

    #[test]
    fn the_boundary_bit_is_representable() {
        let alive = mark_alive(0, HART_MASK_BITS - 1);
        assert_eq!(alive, 1u64 << (HART_MASK_BITS - 1));
        assert_eq!(online_prefix(alive, HART_MASK_BITS), 0);
        assert_eq!(stranded(alive, HART_MASK_BITS), alive);
    }
}

/// The direct switch's WIRING, which `ipc_direct`'s own tests cannot
/// see — `scheduler.rs` does not build on the host, so this reads its source.
/// A variant that claimed the woken task without asking `ipc_direct::allowed`,
/// or asked it about the wrong hart's queue, would pass every predicate test
/// and still dispatch a server ahead of a boosted lessee (RFC-0031). Canary:
/// deleting the `ready_bitmap:` field's source hart, or returning `Claimed`
/// before the rule, or dropping the post-CAS `context_saving` re-read, turns
/// these red.
#[cfg(test)]
mod ipc_direct_wiring {
    const SCHED: &str = include_str!("../../../../crates/core/sched/src/scheduler.rs");

    fn body_of(sig: &str) -> &'static str {
        let start = SCHED.find(sig).unwrap_or_else(|| panic!("`{sig}` not found in scheduler.rs"));
        let rest = &SCHED[start..];
        let end = rest.find("\n}\n").expect("function end");
        &rest[..end]
    }

    #[test]
    fn claim_is_gated_on_the_rule_with_the_switching_harts_queue() {
        let b = body_of("fn wake_by_slot(");
        let rule = b.find("ipc_direct::allowed(").expect("the claim must ask ipc_direct::allowed");
        let claim = b.find("return WakeOut::Claimed(i)").expect("the claim return");
        assert!(rule < claim, "Claimed is returned before the rule is asked");
        let gate = &b[rule..claim];
        let cas = b.find("wake_transition(").expect("the dispatch CAS");
        assert!(cas < rule, "the save re-check must follow the dispatch CAS");
        assert!(
            gate.contains("ready_bitmap: PER_CPU[claim_cpu].ready_bitmap.load("),
            "the rule must read the queue of the hart that will switch (claim_cpu)"
        );
        assert!(gate.contains("target_bucket: prio_bucket(prio)"), "the rule must see the target's live bucket");
        assert!(gate.contains("deadline_live: rt::holds_direct_switch("), "SCHED-RT state must refuse the switch");
        assert!(gate.contains("aps: aps_dispatch_enabled()"), "APS must refuse the switch");
        // The save check must be read inside the claim branch, i.e. after the
        // dispatch CAS — the pre-CAS `saved` read is stale on SMP.
        assert!(
            b[cas..rule].contains("let target_saved = !task.context_saving.load(Ordering::Acquire);")
                && gate.contains("target_saved,"),
            "the claim must re-read context_saving (Acquire) after the CAS"
        );

    }

    #[test]
    fn claimed_is_produced_in_exactly_one_place() {
        assert_eq!(SCHED.matches("WakeOut::Claimed(").count(), 2,
            "one construction (wake_by_slot) and one match arm (ipc_wake_then_block)");
        assert_eq!(SCHED.matches("return WakeOut::Claimed(").count(), 1);
    }

    #[test]
    fn ordinary_wakes_never_claim() {
        let b = body_of("fn wake_task_by_tid_placed(");
        assert!(b.contains("wake_by_slot(slot, pred, ipc, NO_CLAIM)"),
            "every ordinary TID wake must pass NO_CLAIM");
    }
}

#[cfg(test)]
mod stop_policy_tests {
    use crate::stop_policy::*;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    /// The forced-stop count stays balanced on every path: a stop counted
    /// once however often it is repeated; consumed at exit; a stop recorded
    /// AFTER the exit hook (the task is still valid until its slot is freed)
    /// not counted; a slot reused by a new TID counted afresh; a stale
    /// counted word taken over, not stacked. Canary `forced-seal-skip-canary`
    /// (the hook consumes without sealing): the late stop leaks one count.
    #[test]
    fn the_forced_stop_count_is_balanced_on_every_path() {
        let w = AtomicU64::new(ACCT_NONE);
        let p = AtomicU32::new(0);
        let n = || p.load(Ordering::Relaxed);
        assert!(forced_count(&w, &p, 7));
        assert!(!forced_count(&w, &p, 7), "a repeated stop was counted twice");
        assert_eq!(n(), 1);
        // The exit hook: consume, then seal.
        assert!(forced_uncount(&w, &p, 7));
        forced_seal(&w, &p, 7);
        assert_eq!(n(), 0);
        // A stop that lands between the hook and the slot's free.
        let _ = forced_count(&w, &p, 7);
        assert_eq!(n(), 0, "a stop recorded after the exit hook leaked the count");
        // The slot is reused by TID 9, stopped, and exits without consuming
        // (a supervised kill whose code path never took it).
        forced_clear(&w, &p);
        assert!(forced_count(&w, &p, 9));
        assert_eq!(n(), 1);
        forced_seal(&w, &p, 9);
        assert_eq!(n(), 0, "the seal did not settle a counted stop");
        // A stale counted word (TID 11 never reached its hook) taken over by
        // TID 12 in the same slot: still one.
        forced_clear(&w, &p);
        assert!(forced_count(&w, &p, 11));
        assert!(!forced_count(&w, &p, 12));
        assert_eq!(n(), 1);
        assert!(!forced_uncount(&w, &p, 11), "the stale TID's uncount hit the new TID's count");
        assert!(forced_uncount(&w, &p, 12));
        assert_eq!(n(), 0);
    }

    /// Two harts stopping the same task at once count it once (the CAS),
    /// and a racing seal leaves the count at 0.
    #[test]
    fn concurrent_stops_and_a_seal_stay_balanced() {
        use std::sync::Arc;
        for _ in 0..200 {
            let w = Arc::new(AtomicU64::new(ACCT_NONE));
            let p = Arc::new(AtomicU32::new(0));
            let hs: Vec<_> = (0..4).map(|k| {
                let (w, p) = (w.clone(), p.clone());
                std::thread::spawn(move || {
                    if k == 3 { forced_seal(&w, &p, 5) } else { let _ = forced_count(&w, &p, 5); }
                })
            }).collect();
            for h in hs { h.join().unwrap(); }
            forced_seal(&w, &p, 5);
            assert_eq!(p.load(Ordering::Relaxed), 0);
        }
    }

    /// parent links: 10 <- 11 <- 12 <- 13, and 20 (a kernel task) <- 21 (a
    /// supervised driver).
    fn parent(t: u32) -> u32 {
        match t {
            11 => 10,
            12 => 11,
            13 => 12,
            21 => 20,
            _ => 0,
        }
    }

    #[test]
    fn an_ancestor_may_stop_a_descendant_and_nothing_else() {
        assert!(is_ancestor(10, 13, parent, MAX_ANCESTRY));
        assert!(is_ancestor(12, 13, parent, MAX_ANCESTRY));
        assert!(!is_ancestor(13, 10, parent, MAX_ANCESTRY), "a child is not its parent's ancestor");
        assert!(!is_ancestor(13, 13, parent, MAX_ANCESTRY), "nor its own");
        assert!(!is_ancestor(10, 21, parent, MAX_ANCESTRY), "a shell cannot reach a supervised driver");
        assert!(!is_ancestor(10, 99, parent, MAX_ANCESTRY), "absent answers like foreign");
        assert!(!is_ancestor(0, 13, parent, MAX_ANCESTRY));
    }

    /// Wave 12 (owner round 48, Linux `hidepid=2`): without the full view a
    /// task sees itself and its descendants in `/proc`, nothing else — not
    /// its parent, not a sibling subtree, not a supervised driver, not an
    /// absent TID. With it, every task. Nobody (viewer 0) sees anything
    /// filtered, and TID 0 is never a task.
    ///
    /// **Canary.** Make `may_see` return `true` for `!full` (the filter
    /// compiled out, as `proc-hidepid-canary` does in the kernel): red on
    /// "a child sees its parent".
    #[test]
    fn proc_shows_self_and_descendants_unless_the_full_view_is_held() {
        assert!(may_see(10, 10, false, parent, MAX_ANCESTRY), "itself");
        assert!(may_see(10, 11, false, parent, MAX_ANCESTRY), "a child");
        assert!(may_see(10, 13, false, parent, MAX_ANCESTRY), "a great-grandchild");
        assert!(!may_see(13, 12, false, parent, MAX_ANCESTRY), "a child sees its parent");
        assert!(!may_see(11, 21, false, parent, MAX_ANCESTRY), "a foreign subtree");
        assert!(!may_see(10, 20, false, parent, MAX_ANCESTRY), "a kernel task");
        assert!(!may_see(10, 99, false, parent, MAX_ANCESTRY), "an absent TID");
        assert!(!may_see(0, 13, false, parent, MAX_ANCESTRY), "no viewer");
        for t in [10, 11, 12, 13, 20, 21, 99] {
            assert!(may_see(13, t, true, parent, MAX_ANCESTRY), "the full view hides {t}");
        }
        assert!(!may_see(10, 0, true, parent, MAX_ANCESTRY), "TID 0 is never a task");
    }

    /// **Canary.** Drop the step bound: a parent cycle (corrupt links) never
    /// ends.
    #[test]
    fn the_walk_is_bounded() {
        assert!(!is_ancestor(10, 13, parent, 2), "three steps up is past a bound of 2");
        assert!(is_ancestor(11, 13, parent, 2));
        let cyc = |t: u32| if t == 1 { 2 } else { 1 };
        assert!(!is_ancestor(5, 1, cyc, MAX_ANCESTRY));
    }

    #[test]
    fn the_stop_word_round_trips_and_force_sticks() {
        let s = Stop { force: false, signo: 2 };
        assert_eq!(Stop::decode(s.encode()), Some(s));
        assert_eq!(Stop::decode(0), None);
        let f = Stop::merge(Some(s), Stop { force: true, signo: 9 });
        assert_eq!(f, Stop { force: true, signo: 2 }, "force sticks; the first signal stays");
        let r = Stop::merge(Some(f), Stop { force: false, signo: 15 });
        assert!(r.force, "a later request does not undo a force");
        assert_eq!(Stop { force: true, signo: 2 }.exit_code(), 130);
    }
}

/// w14 RTMAX: the tick's K-C25 reaper walks the task pool only when
/// `STAMP_PENDING` was set, and the SCHED-RT set walks are skipped while the
/// hart holds no reservation. `scheduler.rs`/`rt.rs` do not build on the
/// host, so the wiring is read from source; the stamp/reap protocol itself is
/// run through the kernel's own `sched_word` functions.
///
/// Canaries (each turns a test red): delete the `STAMP_PENDING.store(true`
/// line from `note_unsaved_stamp`; call `reap_sweep()` outside the `if
/// _pending`; add a fourth `wake_transition(` caller without
/// `note_unsaved_stamp`; in `rt::reserve`, set `F_RESV` before storing the
/// slot; in `rt::set_iter`, drop the `F_RESV` test.
#[cfg(test)]
mod reap_flag_gate {
    use super::task::sched_word::{self, reap_orphaned_stamp, wake_transition, WakeTransition};
    use super::task::TaskState;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    const SCHED: &str = include_str!("../../../../crates/core/sched/src/scheduler.rs");
    const RT: &str = include_str!("../../../../crates/core/sched/src/rt.rs");

    fn body_of(src: &'static str, sig: &str) -> &'static str {
        let start = src.find(sig).unwrap_or_else(|| panic!("`{sig}` not found"));
        let rest = &src[start..];
        let end = rest.find("\n}\n").expect("function end");
        &rest[..end]
    }

    /// Code lines only: a comment that names a call must not satisfy a check.
    fn code(body: &str) -> String {
        body.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn every_unsaved_stamp_sets_the_flag_unconditionally() {
        let b = code(body_of(SCHED, "fn note_unsaved_stamp("));
        let store = b.find("STAMP_PENDING.store(true").expect("the stamp site must set the flag");
        // The store must not sit under a `#[cfg(...)]` of its own: the line
        // before it is the reap-event mark, which is the only gated line.
        let before = b[..store].trim_end();
        let last = before.lines().last().unwrap_or("");
        assert!(!last.trim_start().starts_with("#[cfg"),
                "the flag store is compiled out in some build: `{last}`");
    }

    #[test]
    fn each_stamping_waker_reports_its_stamp() {
        let src = code(SCHED);
        assert_eq!(src.matches("wake_transition(").count(), 3, "a new waker must be reviewed here");
        // One definition plus one call per waker.
        assert_eq!(src.matches("note_unsaved_stamp(").count(), 4,
                   "every wake_transition caller must call note_unsaved_stamp");
        // And in that order inside each waker.
        let mut from = 0;
        for _ in 0..3 {
            let w = from + src[from..].find("wake_transition(").unwrap();
            let n = w + src[w..].find("note_unsaved_stamp(").expect("note after the transition");
            let next = src[w + 1..].find("wake_transition(").map(|x| x + w + 1);
            if let Some(nx) = next {
                assert!(n < nx, "a waker stamps without reporting it before the next waker");
            }
            from = w + 1;
        }
    }

    #[test]
    fn the_sweep_runs_only_when_flagged_and_reflags_what_it_leaves() {
        let tick = code(body_of(SCHED, "pub fn reap_stamped_sleepers("));
        let swap = tick.find("STAMP_PENDING.swap(false").expect("the flag is taken first");
        let gate = tick.find("if _pending").expect("the walk is gated on the flag");
        let sweep = tick.find("reap_sweep()").expect("the walk");
        assert!(swap < gate && gate < sweep, "swap, then test, then walk");
        assert_eq!(tick.matches("reap_sweep()").count(), 1, "no ungated walk");
        // The safety net is the idle task's, never the tick's.
        assert!(!tick.contains("reap_idle"), "the tick runs the idle walk");
        let walk = code(body_of(SCHED, "fn reap_sweep("));
        let again = walk.find("Reap::Again").expect("a stamp still switching away");
        assert!(walk[again..].contains("STAMP_PENDING.store(true"),
                "a stamp left for later must keep the next tick walking");
    }

    /// The protocol the gate relies on, through the kernel's own transitions:
    /// a tick that lands between a waker's stamp and its flag store misses the
    /// stamp; the store makes the next tick reap it. `flag` stands for
    /// `STAMP_PENDING`, `tick` for `reap_stamped_sleepers`.
    #[test]
    fn a_stamp_flagged_late_is_reaped_one_tick_later() {
        let w = AtomicU32::new(sched_word::pack(TaskState::Blocked));
        let flag = AtomicBool::new(false);
        let tick = |w: &AtomicU32| flag.swap(false, Ordering::AcqRel) && reap_orphaned_stamp(w);

        // The waker stamps a target that is still switching away.
        assert_eq!(wake_transition(&w, || true, false, || false), WakeTransition::Stamped);
        // A tick before the waker's flag store: gated out, nothing delivered.
        assert!(!tick(&w));
        assert_eq!(sched_word::state_of(w.load(Ordering::Acquire)), TaskState::Blocked);
        // The waker's `note_unsaved_stamp`; the target has parked since.
        flag.store(true, Ordering::Release);
        assert!(tick(&w), "the next tick must deliver the wake");
        assert_eq!(sched_word::state_of(w.load(Ordering::Acquire)), TaskState::Ready);
        // Nothing left: the following tick neither walks nor reaps.
        assert!(!tick(&w));
    }

    #[test]
    fn the_rt_set_is_empty_exactly_when_the_flag_is_clear() {
        let it = code(body_of(RT, "fn set_iter("));
        assert!(it.contains("& F_RESV != 0"), "set_iter must test F_RESV");
        // reserve: slot first, flag second (a reader seeing the flag sees the slot).
        let res = code(body_of(RT, "pub fn reserve("));
        let slot = res.find("set_of(cpu)[k].store(idx").expect("the slot store");
        let flag = res.find("fetch_or(F_RESV").expect("the flag set");
        assert!(slot < flag, "F_RESV is set before the slot it announces");
        // release: the flag is cleared only once every slot is empty.
        let rel = code(body_of(RT, "pub(super) fn release("));
        let empty = rel.find(".all(|s| s.load(Ordering::Relaxed) == usize::MAX)").expect("emptiness test");
        let clear = rel.find("fetch_and(!F_RESV").expect("the flag clear");
        assert!(empty < clear, "F_RESV is cleared without checking the set is empty");
        // Nothing else clears the flag.
        assert_eq!(code(RT).matches("!F_RESV").count(), 1, "a second F_RESV clear site");
    }

    const SYSTEM: &str = include_str!("../../../../kernel/src/tasks/system.rs");

    /// The count the idle walk skips on is bumped by the transition itself,
    /// for the `!saved` stamp only (the state the reaper acts on), so a waker
    /// that forgets `note_unsaved_stamp` cannot hide its stamp from it.
    /// Canary: delete the `REAPABLE_STAMPS.fetch_add` in `wake_transition`.
    #[test]
    fn every_reapable_stamp_moves_the_idle_count() {
        let before = sched_word::reapable_stamps();
        let w = AtomicU32::new(sched_word::pack(TaskState::Blocked));
        assert_eq!(wake_transition(&w, || true, false, || false), WakeTransition::Stamped);
        let after = sched_word::reapable_stamps();
        assert!(after != before, "an unswitched-block stamp left the count unchanged");
        // A saved task is dispatched, a running one stamped for its own
        // commit to consume: neither is the reaper's, and other tests running
        // in parallel may bump the count, so only the stamp case is asserted.
        let r = AtomicU32::new(sched_word::pack(TaskState::Running));
        assert_eq!(wake_transition(&r, || true, true, || true), WakeTransition::Stamped);
    }

    /// The idle walk: skipped on one load when the count has not moved or
    /// the tick owns a flagged stamp; each slot reaped with interrupts masked
    /// (the tick's own condition); the count marked swept only when no slot
    /// was left for later; never called from the tick.
    #[test]
    fn the_idle_walk_is_gated_masked_and_bounded() {
        let gate = code(body_of(SCHED, "pub fn reap_idle_sweep("));
        let load = gate.find("reapable_stamps()").expect("the count is read");
        let skip = gate.find("IDLE_SWEPT.load(").expect("compared with the last walk");
        let pend = gate.find("STAMP_PENDING.load(").expect("a flagged stamp is the tick's");
        let walk = gate.find("reap_idle_walk(").expect("the walk");
        assert!(load < walk && skip < walk && pend < walk, "the walk runs before its skip tests");
        let w = code(body_of(SCHED, "fn reap_idle_walk("));
        let lp = w.find("for i in 0..MAX_TASKS").expect("one bounded pass");
        let look = w.find("if !looks_reapable(i)").expect("unstamped slots skipped unmasked");
        let mask = w.find("ARCH.disable_all()").expect("masked like the ISR");
        assert!(lp < look && look < mask, "the read-only look precedes the masked window");
        let lr = code(body_of(SCHED, "fn looks_reapable("));
        assert!(lr.contains("TASK_VALID[i]") && lr.contains("WAKE_STAMP != 0")
                && lr.contains("TaskState::Blocked"), "looks_reapable is not reap_one's own test");
        let reap = w.find("reap_one(i)").expect("the slot");
        let unmask = w.find("ARCH.restore(").expect("unmasked between slots");
        assert!(lp < mask && mask < reap && reap < unmask, "each slot is reaped with interrupts masked");
        let again = w.find("Reap::Again => again = true").expect("a slot left for later");
        let mark = w.find("IDLE_SWEPT.store(").expect("the count marked swept");
        assert!(again < mark && w[..mark].contains("if !again"), "a pass with a slot left marks the count swept");
        assert_eq!(code(SCHED).matches("reap_idle_walk(").count(), 2, "one definition, one caller");
        assert!(!code(body_of(SCHED, "pub fn reap_stamped_sleepers(")).contains("reap_idle"));
    }

    /// The idle loop (one body for every ISA) runs the net and yields to
    /// what it woke before going back to `wfi`. Canary: drop either call.
    #[test]
    fn both_idle_loops_run_the_net_and_yield() {
        let src = code(SYSTEM);
        for f in ["pub(crate) fn idle_task("] {
            let b = code(body_of(SYSTEM, f));
            let call = b.find("if azos_sched::scheduler::reap_idle_sweep() {").unwrap_or_else(|| panic!("{f} does not run the net"));
            assert!(b[call..].trim_start_matches("if azos_sched::scheduler::reap_idle_sweep() {").trim_start().starts_with("azos_sched::task_yield();"),
                    "{f} sleeps on a task the net just woke");
        }
        assert_eq!(src.matches("reap_idle_sweep()").count(), 1);
    }

    /// A forgotten flag: the tick never walks, the idle walk delivers the wake.
    /// `flag` is `STAMP_PENDING`, `swept` is `IDLE_SWEPT`; the transitions and
    /// the count are the kernel's own.
    #[test]
    fn a_stamp_whose_flag_was_forgotten_is_reaped_when_idle() {
        let w = AtomicU32::new(sched_word::pack(TaskState::Blocked));
        let flag = AtomicBool::new(false);
        let swept = AtomicU32::new(sched_word::reapable_stamps());
        assert_eq!(wake_transition(&w, || true, false, || false), WakeTransition::Stamped);
        // No `note_unsaved_stamp`: every tick is gated out.
        for _ in 0..3 {
            assert!(!(flag.swap(false, Ordering::AcqRel) && reap_orphaned_stamp(&w)));
        }
        // The hart goes idle; the target has parked.
        let seen = sched_word::reapable_stamps();
        assert!(seen != swept.load(Ordering::Relaxed) && !flag.load(Ordering::Acquire),
                "the idle skip test hides the stamp");
        assert!(reap_orphaned_stamp(&w), "the idle walk must deliver the wake");
        swept.store(seen, Ordering::Relaxed);
        assert_eq!(sched_word::state_of(w.load(Ordering::Acquire)), TaskState::Ready);
    }

}

// Wave 15 (VW): the per-CPU deferred remote-wake list
// (`SCHED_REMOTE_WAKE_DEFER`): lock-free MPSC push, FIFO drain.
#[path = "../../../../crates/core/sched/src/wake_list.rs"]
pub mod wake_list;

#[cfg(test)]
mod wake_list_tests {
    use super::wake_list::{drain, is_empty, push, NIL};
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    fn links(n: usize) -> Vec<AtomicU32> {
        (0..n).map(|_| AtomicU32::new(NIL)).collect()
    }

    #[test]
    fn drain_returns_push_order() {
        let head = AtomicU32::new(NIL);
        let next = links(8);
        assert!(is_empty(&head));
        for s in [3, 1, 7, 0] {
            push(&head, &next, s);
        }
        let mut got = Vec::new();
        assert_eq!(drain(&head, &next, |s| got.push(s)), 4);
        assert_eq!(got, vec![3, 1, 7, 0]);
        assert!(is_empty(&head));
        assert_eq!(drain(&head, &next, |_| panic!("empty")), 0);
    }

    /// A slot queued by the drain can be woken and pushed again (here: from
    /// inside the callback, the earliest it can happen); the walk must not
    /// follow the rewritten link.
    #[test]
    fn repush_during_drain_is_kept_for_the_next_drain() {
        let head = AtomicU32::new(NIL);
        let next = links(4);
        push(&head, &next, 0);
        push(&head, &next, 1);
        push(&head, &next, 2);
        let mut got = Vec::new();
        drain(&head, &next, |s| {
            got.push(s);
            if s == 0 {
                push(&head, &next, 0);
            }
        });
        assert_eq!(got, vec![0, 1, 2]);
        let mut again = Vec::new();
        drain(&head, &next, |s| again.push(s));
        assert_eq!(again, vec![0]);
    }

    /// Many producers, one consumer draining concurrently: every slot comes
    /// out exactly once, and each producer's slots in its push order.
    #[test]
    fn mpsc_no_loss_no_duplicate_per_producer_fifo() {
        const P: usize = 4;
        const PER: usize = 2000;
        let head = Arc::new(AtomicU32::new(NIL));
        let next: Arc<Vec<AtomicU32>> = Arc::new(links(P * PER));
        let hs: Vec<_> = (0..P)
            .map(|p| {
                let (h, n) = (head.clone(), next.clone());
                std::thread::spawn(move || {
                    for k in 0..PER {
                        push(&h, &n, p * PER + k);
                    }
                })
            })
            .collect();
        let mut got = Vec::new();
        while got.len() < P * PER {
            drain(&head, &next, |s| got.push(s));
            std::hint::spin_loop();
        }
        for h in hs {
            h.join().unwrap();
        }
        drain(&head, &next, |s| got.push(s));
        assert_eq!(got.len(), P * PER);
        let mut seen = vec![false; P * PER];
        let mut last = [None::<usize>; P];
        for &s in &got {
            assert!(!seen[s], "slot {s} drained twice");
            seen[s] = true;
            let p = s / PER;
            if let Some(l) = last[p] {
                assert!(s > l, "producer {p}: {s} after {l}");
            }
            last[p] = Some(s);
        }
    }
}
