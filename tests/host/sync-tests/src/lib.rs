// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for the K-C29 preemption-control mechanism.
//!
//! # What is real here and what is not — read this before trusting a green run
//!
//! Both modules under test are pulled from the kernel tree **unmodified**, via
//! `#[path]`. There is no copy in this crate; a mutation in
//! `crates/core/sync/src/preempt.rs` or `crates/core/sync/src/preempt_core.rs` changes
//! what these tests compile. That is deliberate — a test crate carrying its
//! own copy of the logic passes against unchanged production code, which is
//! the exact failure this repo has been burned by twice.
//!
//! What is substituted: only the two machine reads, `hart_id()` and
//! `read_sstatus()`, through `shims/arch`. The guard, the depth arithmetic,
//! the `need_resched` handling, the underflow policy and the `sstatus.SIE`
//! firing gate are the kernel's own code.
//!
//! What is **not** proved here: nothing about the scheduler. `crates/core/sched`
//! cannot be compiled for the host (static `TASKS`/`PER_CPU`, CSR reads, an
//! assembly context switch), so the wiring in `scheduler.rs` —
//! `tick_admit()`, the `task_yield` / `block_current` refusals, the exit
//! override, the pre-`context_switch` assertion — is *not* executed by these
//! tests. What is proved is that the decisions those call sites delegate to
//! (`tick_dispatch`, `voluntary_admission`, `enable`) are the ones the
//! scheduler will get, and the two-task model at the bottom proves that the
//! `Defer` answer is the one that terminates.

// The real preemption modules — no stubs, no copies.
/// The held-lock table (`held::PI_HELD`) is process-global: every test that
/// takes a `kmutex::Mutex` holds this lock, so the tests that fill or read the
/// table see only their own entries. A test that forgets a guard (a task that
/// "died" holding the mutex) leaves a count for the boot identity; the drop
/// forgets it, as the kernel's exit path does.
#[cfg(test)]
pub(crate) struct HeldTableGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for HeldTableGuard {
    fn drop(&mut self) {
        held::held_forget(u32::MAX);
    }
}

#[cfg(test)]
pub(crate) fn held_table_lock() -> HeldTableGuard {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    HeldTableGuard(L.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner()))
}

#[path = "../../../../crates/core/sync/src/preempt_core.rs"]
pub mod preempt_core;

#[path = "../../../../crates/core/sync/src/preempt.rs"]
pub mod preempt;

// K-C29 fix applied to `WaitQueue`'s hand-rolled internal spin (see that
// file's module doc). Pulled in via `#[path]` for the same reason as
// `preempt`/`preempt_core` above: the guard, the `SpinLock`/`IrqSaveGuard`
// Drop ordering, and `WaitQueue`'s routing through them are the kernel's own
// code, not a copy that could drift from it. `spinlock.rs` needs
// `azos_arch::cpu::{read_sstatus, write_sstatus}`, which is why this
// crate's arch shim grew `write_sstatus` alongside these modules.
// `lock_level` is the kernel's `scope` locks', which this crate does not pull.
#[allow(dead_code)]
#[path = "../../../../crates/core/sync/src/spinlock.rs"]
pub mod spinlock;

// The queued SpinLock's slow half (wave 15, N3), which `spinlock.rs` calls
// and which defines `azos_spin_mcs_slow32` for the trait's portable fast
// path.
#[path = "../../../../crates/core/sync/src/qspinlock.rs"]
pub mod qspinlock;

#[path = "../../../../crates/core/sync/src/held.rs"]
pub mod held;

#[path = "../../../../crates/core/sync/src/waitqueue.rs"]
pub mod waitqueue;

// The counters of bounded sleeps `WaitQueue::wait_if_for` books to.
#[path = "../../../../crates/core/sync/src/waitstat.rs"]
pub mod waitstat;

// Rule F1: ownership of a resource across a device wait. Its exchange mutex
// is the real kernel mutex below.
#[path = "../../../../crates/core/sync/src/claim.rs"]
pub mod claim;

// Lockdep-lite (wave 15, N1). The kernel instance is off here (no `lockdep`
// feature: every table is sized 0 and the lock paths call nothing); the
// tests below drive its `Graph` and `HeldStack` directly.
#[path = "../../../../crates/core/sync/src/lockdep.rs"]
pub mod lockdep;

#[path = "../../../../crates/core/sync/src/isr_depth.rs"]
pub mod isr_depth;

// QSBR (wave 15, N4): the counter transitions and the grace-period decision.
#[path = "../../../../crates/core/sync/src/qsbr_core.rs"]
pub mod qsbr_core;

// Wave 15 IF: the interfaces of the wait graph (N7), the kernel mutex (N8),
// and the PI futex seam (N10). Stubs: only their
// fixed, already-implemented parts are tested here (the attribute order,
// the futex word protocol, the Kconfig-off behaviour).
#[path = "../../../../crates/core/sync/src/pi_attr.rs"]
pub mod pi_attr;
#[path = "../../../../crates/core/sync/src/waitgraph.rs"]
pub mod waitgraph;
#[path = "../../../../crates/core/sync/src/kmutex.rs"]
pub mod kmutex;
#[path = "../../../../crates/core/sync/src/pi_futex.rs"]
pub mod pi_futex;
// pi_futex.rs retires a pi_state through `crate::qsbr::call_rcu`; qsbr.rs
// needs the per-CPU layer, so this stand-in runs the callback at once (the
// kernel's own behaviour with RCU_QSBR n).
pub mod qsbr {
    pub struct RcuHead;
    impl RcuHead {
        pub const fn new() -> Self { RcuHead }
    }
    /// # Safety
    /// As the kernel's `call_rcu`.
    pub unsafe fn call_rcu(head: *mut RcuHead, f: unsafe fn(*mut RcuHead)) { f(head) }
}
#[cfg(test)]
mod interface_tests {
    use super::pi_futex::*;
    use super::waitgraph::{EdgeKind, PiAttr, PiWaiters, WaitError, WaitObj, PI_MAX_DEPTH};

    #[test]
    fn pi_attr_order_is_the_class_precedence() {
        let order = [
            PiAttr::Idle,
            PiAttr::Fair,
            PiAttr::Rt { prio: 50 },
            PiAttr::Rt { prio: 10 },
            PiAttr::Dl { deadline_ns: 2_000 },
            PiAttr::Dl { deadline_ns: 1_000 },
            PiAttr::Stop,
        ];
        for w in order.windows(2) {
            assert!(w[1] > w[0], "{:?} must be more urgent than {:?}", w[1], w[0]);
        }
        // Lower RT number and earlier deadline are more urgent.
        assert!(PiAttr::Rt { prio: 0 } > PiAttr::Rt { prio: 1 });
        assert!(PiAttr::Dl { deadline_ns: 0 } > PiAttr::Rt { prio: 0 });
        // Stage 1: a DL donor's deadline is what the owner inherits.
        let owner = PiAttr::Rt { prio: 20 };
        let donor = PiAttr::Dl { deadline_ns: 5 };
        assert_eq!(owner.max_urgent(donor), donor);
        assert_eq!(donor.max_urgent(owner), donor);
        assert_eq!(PiAttr::Fair.max_urgent(PiAttr::Fair), PiAttr::Fair);
    }

    /// Chain E cut 6: the lock-free quiet test (`quiet_le` over two
    /// `quiet_key`s) is `waiter <= owner` by `PiAttr::cmp` for EVERY pair of
    /// attributes that are not `Dl` (Idle, Fair, Stop and all 256 RT
    /// levels: 259 x 259 pairs), and never quiet when either side is `Dl`,
    /// whatever the deadlines (Dl against each of those 259 on both sides,
    /// and Dl against Dl in every deadline order).
    #[test]
    fn quiet_key_matches_ord() {
        use super::waitgraph::{quiet_le, QUIET_DL};
        let mut all: Vec<PiAttr> = vec![PiAttr::Idle, PiAttr::Fair, PiAttr::Stop];
        all.extend((0..=255u8).map(|prio| PiAttr::Rt { prio }));
        for &w in &all {
            for &o in &all {
                assert_eq!(
                    quiet_le(w.quiet_key(), o.quiet_key()),
                    w <= o,
                    "quiet_le({w:?}, {o:?}) disagrees with PiAttr::cmp",
                );
            }
        }
        let dls = [0u64, 1, 1_000, u64::MAX - 1, u64::MAX].map(|deadline_ns| PiAttr::Dl { deadline_ns });
        for &d in &dls {
            assert_eq!(d.quiet_key(), QUIET_DL);
            for &x in &all {
                assert!(!quiet_le(d.quiet_key(), x.quiet_key()), "a Dl waiter on {x:?} was quiet");
                assert!(!quiet_le(x.quiet_key(), d.quiet_key()), "{x:?} on a Dl owner was quiet");
            }
            for &e in &dls {
                assert!(!quiet_le(d.quiet_key(), e.quiet_key()), "a Dl waiter on a Dl owner was quiet");
            }
        }
    }

    #[test]
    fn graph_contract_constants() {
        assert_eq!(PI_MAX_DEPTH, azos_limits::PI_MAX_DEPTH);
        assert!(PI_MAX_DEPTH >= 1);
        assert_eq!(WaitError::Deadlock.errno(), 35); // EDEADLK
        assert!(core::mem::size_of::<PiWaiters>() <= 32);
        static A: PiWaiters = PiWaiters::new(EdgeKind::Mutex);
        static B: PiWaiters = PiWaiters::new(EdgeKind::FutexPi);
        assert_eq!(A.kind(), EdgeKind::Mutex);
        assert_ne!(WaitObj::of(&A), WaitObj::of(&B));
        assert_eq!(WaitObj::of(&A), WaitObj::of(&A));
    }

    #[test]
    fn futex_word_protocol_is_linux_bit_exact() {
        assert_eq!(FUTEX_TID_MASK, 0x3FFF_FFFF);
        assert_eq!(FUTEX_OWNER_DIED, 0x4000_0000);
        assert_eq!(FUTEX_WAITERS, 0x8000_0000);
        assert_eq!(FUTEX_TID_MASK | FUTEX_OWNER_DIED | FUTEX_WAITERS, u32::MAX);
        assert_eq!(word_owner(0), None);
        assert_eq!(word_owner(FUTEX_WAITERS | FUTEX_OWNER_DIED), None);
        assert_eq!(word_owner(FUTEX_WAITERS | 77), Some(77));
        // A handover always sets FUTEX_WAITERS, even to the last waiter
        // (Linux; owner decision 10-10).
        assert_eq!(handover_word(77, false), 77 | FUTEX_WAITERS);
        assert_eq!(handover_word(77, true), 77 | FUTEX_WAITERS | FUTEX_OWNER_DIED);
        assert_eq!(handover_word(77 | FUTEX_OWNER_DIED, false), 77 | FUTEX_WAITERS);
        // The heir of an exited owner (owner decision 10-10, Linux
        // fixup_pi_state_owner): OWNER_DIED only when the robust walk
        // marked the word; a non-robust owner's word goes over plain.
        assert_eq!(heir_word(549 | FUTEX_WAITERS, 77), 77 | FUTEX_WAITERS);
        assert_eq!(heir_word(549, 77), 77 | FUTEX_WAITERS);
        assert_eq!(heir_word(FUTEX_OWNER_DIED | FUTEX_WAITERS, 77),
                   77 | FUTEX_WAITERS | FUTEX_OWNER_DIED);
        assert_eq!(PiStateId::from_raw(0), None);
        assert_eq!(PiStateId::from_raw(5).map(|p| p.raw()), Some(5));
    }

    #[test]
    fn kconfig_off_paths_are_inert() {
        if !super::pi_futex::ENABLED {
            assert!(super::pi_futex::ops().is_none());
        }
    }
}

// N10: the PI futex word state machine, and every PiFutexOps path that does
// not reach the wait graph (no pi_state: the graph's bodies are N7's).
#[cfg(test)]
mod pi_futex_tests {
    use super::pi_futex::*;
    use super::waitgraph::TaskId;

    /// TIDs are slot + 100 here, so a slot/TID mix-up cannot pass.
    fn tid(t: TaskId) -> Option<u32> {
        (t < 50).then_some(t + 100)
    }

    struct Bucket {
        word: Option<u32>,
        slot: u32,
        /// A TID mid-exit: `task_of_tid` does not resolve it.
        exiting: Option<u32>,
    }
    impl PiBucket for Bucket {
        fn pi_slot(&mut self) -> &mut u32 { &mut self.slot }
        fn read_word(&self) -> Result<u32, UserFault> { self.word.ok_or(UserFault) }
        fn cmpxchg_word(&mut self, expected: u32, new: u32) -> Result<u32, UserFault> {
            let w = self.word.as_mut().ok_or(UserFault)?;
            let seen = *w;
            if seen == expected { *w = new; }
            Ok(seen)
        }
        fn task_of_tid(&self, t: u32) -> Option<TaskId> {
            ((100..150).contains(&t) && self.exiting != Some(t)).then(|| t - 100)
        }
        fn tid_exiting(&self, t: u32) -> bool { self.exiting == Some(t) }
    }
    fn b(w: u32) -> Bucket { Bucket { word: Some(w), slot: 0, exiting: None } }
    /// `lock`'s answer for `LockPiStep::Retry` (no errno has this value).
    const RETRY: i32 = i32::MAX;
    fn lock(bk: &mut Bucket, me: TaskId, try_only: bool) -> Result<(), i32> {
        register_tid_of(tid);
        match PI_FUTEX.lock_pi_prepare(bk, me, try_only) {
            LockPiStep::Acquired => Ok(()),
            LockPiStep::Err(e) => Err(e),
            LockPiStep::Block(_) => panic!("blocked without a pi_state"),
            LockPiStep::Retry => Err(RETRY),
        }
    }

    /// Owner decision 10-10 (Linux handle_exit_race): an owner mid-exit is
    /// never installed as the word's owner; the locker retries, the word
    /// and the table untouched. Once the exit is over, a plain word is
    /// ESRCH and an OWNER_DIED one is taken over.
    #[test]
    fn an_exiting_owner_is_never_installed_the_locker_retries() {
        let mut k = b(149);
        k.exiting = Some(149);
        assert_eq!(lock(&mut k, 1, false), Err(RETRY));
        assert_eq!(lock(&mut k, 1, true), Err(RETRY), "trylock retries too");
        assert_eq!((k.word, k.slot), (Some(149), 0), "no WAITERS bit, no pi_state");
        k.exiting = None;
        k.word = Some(160);
        assert_eq!(lock(&mut k, 1, false), Err(-ESRCH), "a gone owner of a plain word");
        k.exiting = Some(149);
        k.word = Some(149 | FUTEX_OWNER_DIED);
        assert_eq!(lock(&mut k, 1, false), Ok(()), "an OWNER_DIED word is taken over");
        assert_eq!(k.word, Some(101 | FUTEX_OWNER_DIED));
    }

    /// Wave 15 N10d (Linux futex_proxy_trylock_atomic): CMP_REQUEUE_PI
    /// gives a free PI word to the top waiter (OWNER_DIED kept, WAITERS when
    /// more are requeued behind it); an owned word, a word the top already
    /// names, or a fault leaves the word as it was.
    #[test]
    fn requeue_pi_proxy_lock_takes_only_a_free_word_for_the_top_waiter() {
        let mut k = b(0);
        assert_eq!(proxy_lock(&mut k, 101, false), Ok(true));
        assert_eq!(k.word, Some(101));
        let mut k = b(FUTEX_OWNER_DIED);
        assert_eq!(proxy_lock(&mut k, 101, true), Ok(true));
        assert_eq!(k.word, Some(101 | FUTEX_OWNER_DIED | FUTEX_WAITERS));
        let mut k = b(102);
        assert_eq!(proxy_lock(&mut k, 101, true), Ok(false), "owned: the top is requeued");
        assert_eq!((k.word, k.slot), (Some(102), 0));
        let mut k = b(101);
        assert_eq!(proxy_lock(&mut k, 101, false), Ok(false), "its own LOCK_PI answers EDEADLK");
        assert_eq!(k.word, Some(101));
        let mut k = Bucket { word: None, slot: 0, exiting: None };
        assert_eq!(proxy_lock(&mut k, 101, false), Err(-EFAULT));
    }

    /// Owner decision 10-10 (Linux rt_mutex_start_proxy_lock): the proxy
    /// enqueue keeps a requeued waiter asleep only behind a live owner that
    /// is not the waiter; a free word, a word naming the waiter, a gone
    /// owner, an unknown waiter or a fault send it to its own LOCK_PI, the
    /// word untouched.
    #[test]
    fn requeue_pi_proxy_enqueue_refuses_what_its_own_lock_pi_must_answer() {
        register_tid_of(tid);
        for (w, why) in [(0, "a free word"), (FUTEX_OWNER_DIED, "a free OWNER_DIED word"), (101, "the waiter's own word"), (160, "a gone owner")] {
            let mut k = b(w);
            assert!(!proxy_enqueue(&mut k, 101), "{why}");
            assert_eq!((k.word, k.slot), (Some(w), 0), "{why}: untouched");
        }
        let mut k = b(102);
        k.exiting = Some(102);
        assert!(!proxy_enqueue(&mut k, 101), "an owner mid-exit");
        assert_eq!((k.word, k.slot), (Some(102), 0));
        let mut k = b(102);
        assert!(!proxy_enqueue(&mut k, 160), "a waiter with no task");
        assert_eq!(k.word, Some(102));
        let mut k = Bucket { word: None, slot: 0, exiting: None };
        assert!(!proxy_enqueue(&mut k, 101), "a fault");
    }

    #[test]
    fn word_transitions_are_linux_futex_lock_pi_atomic() {
        assert_eq!(lock_word(0, 101), LockWord::Take { new: 101 });
        assert_eq!(lock_word(FUTEX_OWNER_DIED, 101), LockWord::Take { new: 101 | FUTEX_OWNER_DIED });
        assert_eq!(lock_word(FUTEX_WAITERS, 101), LockWord::Take { new: 101 });
        assert_eq!(lock_word(101 | FUTEX_WAITERS, 101), LockWord::SelfOwned);
        assert_eq!(lock_word(102, 101), LockWord::Owned { tid: 102, marked: 102 | FUTEX_WAITERS });
        assert_eq!(takeover_word(102, 101), None);
        assert_eq!(takeover_word(102 | FUTEX_OWNER_DIED | FUTEX_WAITERS, 101),
                   Some(101 | FUTEX_OWNER_DIED | FUTEX_WAITERS));
        assert!(may_unlock(101 | FUTEX_WAITERS | FUTEX_OWNER_DIED, 101));
        assert!(!may_unlock(102, 101));
        assert!(!may_unlock(0, 101));
        assert_eq!(death_word(101 | FUTEX_WAITERS), FUTEX_OWNER_DIED | FUTEX_WAITERS);
        assert_eq!(death_word(101), FUTEX_OWNER_DIED);
    }

    #[test]
    fn uncontended_lock_trylock_unlock() {
        let mut k = b(0);
        assert_eq!(lock(&mut k, 1, false), Ok(()));
        assert_eq!(k.word, Some(101));
        assert_eq!(lock(&mut k, 2, true), Err(-EAGAIN));
        assert_eq!(k.word, Some(101), "a refused trylock leaves the word");
        assert_eq!(lock(&mut k, 1, false), Err(-EDEADLK));
        assert_eq!(PI_FUTEX.unlock_pi(&mut k, 2), Err(-EPERM));
        assert_eq!(PI_FUTEX.unlock_pi(&mut k, 1), Ok(None));
        assert_eq!(k.word, Some(0));
        assert_eq!(PI_FUTEX.unlock_pi(&mut k, 1), Err(-EPERM), "unlocking a free word");
        // A stale WAITERS bit with no pi_state: unlock still frees the word.
        let mut k = b(101 | FUTEX_WAITERS);
        assert_eq!(PI_FUTEX.unlock_pi(&mut k, 1), Ok(None));
        assert_eq!(k.word, Some(0));
    }

    #[test]
    fn owner_died_marks_the_word_and_the_next_locker_keeps_the_bit() {
        register_tid_of(tid);
        let mut k = b(101 | FUTEX_WAITERS);
        assert_eq!(PI_FUTEX.owner_died(&mut k, 2), Ok(None), "not 2's word");
        assert_eq!(PI_FUTEX.owner_died(&mut k, 60), Err(-ESRCH), "no TID: left to the walk");
        assert_eq!(k.word, Some(101 | FUTEX_WAITERS));
        assert_eq!(PI_FUTEX.owner_died(&mut k, 1), Ok(None));
        assert_eq!(k.word, Some(FUTEX_OWNER_DIED | FUTEX_WAITERS));
        assert_eq!(lock(&mut k, 2, false), Ok(()));
        assert_eq!(k.word, Some(102 | FUTEX_OWNER_DIED), "EOWNERDEAD visible to user space");
    }

    #[test]
    fn a_vanished_owner_is_esrch_unless_owner_died() {
        let mut k = b(149 + 400);
        assert_eq!(lock(&mut k, 1, false), Err(-ESRCH));
        let mut k = b(549 | FUTEX_OWNER_DIED);
        assert_eq!(lock(&mut k, 1, true), Ok(()));
        assert_eq!(k.word, Some(101 | FUTEX_OWNER_DIED));
    }

    #[test]
    fn faults_are_efault() {
        let mut k = Bucket { word: None, slot: 0, exiting: None };
        assert_eq!(lock(&mut k, 1, false), Err(-EFAULT));
        assert_eq!(PI_FUTEX.unlock_pi(&mut k, 1), Err(-EFAULT));
        assert_eq!(PI_FUTEX.owner_died(&mut k, 1), Err(-EFAULT));
    }

    #[test]
    fn nothing_registered_is_enosys() {
        if !ENABLED {
            assert_eq!(POOL_LEN, 0);
            assert_eq!(sys_futex_pi(0x1000, PiCmd::Unlock), -(ENOSYS as i64));
            assert_eq!(robust_owner_died(1, 0x1000, 1), None);
        }
        assert_eq!(states_in_use(), 0);
    }
}

#[cfg(test)]
mod nohz;

#[cfg(test)]
mod qsbr_cpuid;

#[cfg(test)]
mod qsbr_tests {
    use super::qsbr_core::*;

    /// A CPU's counter, driven the way the kernel hooks drive it.
    struct Cpu(u64);
    impl Cpu {
        fn kernel() -> Self { Cpu(1) }
        fn trap_in(&mut self) -> bool { enter(self.0).map(|v| self.0 = v).is_some() }
        fn to_user(&mut self) { if let Some(v) = leave(self.0) { self.0 = v } }
        fn idle(&mut self) { if let Some(v) = leave(self.0) { self.0 = v } }
        fn wake(&mut self) { if let Some(v) = enter(self.0) { self.0 = v } }
        fn switch(&mut self) { self.0 = switch(self.0) }
    }

    /// Every CPU of a grace period snapshotted at once, polled later.
    fn done(snaps: &[u64], cpus: &[Cpu]) -> bool {
        snaps.iter().zip(cpus).all(|(&s, c)| passed(s, c.0))
    }

    #[test]
    fn parity_is_the_kernel_and_every_transition_moves_the_counter() {
        let mut c = Cpu::kernel();
        assert!(!quiescent(c.0));
        c.to_user();
        assert!(quiescent(c.0), "user mode is an extended quiescent state");
        assert!(c.trap_in(), "a trap from user leaves it");
        assert!(!quiescent(c.0));
        assert!(!c.trap_in(), "a nested trap changes nothing");
        let v = c.0;
        c.switch();
        assert!(!quiescent(c.0) && c.0 != v, "a switch stays in the kernel and moves");
        c.idle();
        assert!(quiescent(c.0));
        c.wake();
        assert!(!quiescent(c.0));
        // A switch on a CPU wrongly left even puts it back in the kernel.
        let mut w = Cpu(4);
        w.switch();
        assert!(!quiescent(w.0));
    }

    #[test]
    fn a_grace_period_waits_for_the_cpu_inside_a_reader_and_no_other() {
        // CPU 0 is in a read section (kernel, no transition); CPU 1 is in
        // user mode; CPU 2 is idle.
        let mut cpus = [Cpu::kernel(), Cpu::kernel(), Cpu::kernel()];
        cpus[1].to_user();
        cpus[2].idle();
        let snaps: Vec<u64> = cpus.iter().map(|c| snapshot(c.0)).collect();
        assert_eq!(snaps[1], DONE);
        assert_eq!(snaps[2], DONE);
        assert!(!done(&snaps, &cpus), "the reader's CPU holds the grace period");
        // Others moving does not end it.
        cpus[1].trap_in();
        cpus[1].to_user();
        cpus[2].wake();
        assert!(!done(&snaps, &cpus));
        // The reader ends; the CPU's next switch is the quiescent state.
        cpus[0].switch();
        assert!(done(&snaps, &cpus));
    }

    #[test]
    fn a_return_to_user_or_idle_ends_it_too() {
        for leave_by_idle in [false, true] {
            let mut c = [Cpu::kernel()];
            let snaps = [snapshot(c[0].0)];
            assert!(!done(&snaps, &c));
            if leave_by_idle { c[0].idle() } else { c[0].to_user() }
            assert!(done(&snaps, &c));
        }
    }

    #[test]
    fn a_cpu_that_went_to_user_and_came_back_between_polls_has_passed() {
        let mut c = [Cpu::kernel()];
        let snaps = [snapshot(c[0].0)];
        c[0].to_user();
        c[0].trap_in();
        assert!(!quiescent(c[0].0), "back in the kernel at the poll");
        assert!(done(&snaps, &c), "but it was quiescent in between");
    }

    #[test]
    fn an_idle_cpu_that_never_says_so_stalls_the_grace_period() {
        // The `rcu-idle-qs-skip` canary's shape: the CPU switched to idle
        // (odd, moved) and then sleeps without the idle hook.
        let mut c = [Cpu::kernel()];
        c[0].switch();
        let snaps = [snapshot(c[0].0)];
        for _ in 0..1000 {
            assert!(!done(&snaps, &c), "no transition, no quiescent state");
        }
        assert!(!stalled(0, 4000, 4000));
        assert!(stalled(0, 4001, 4000));
        assert!(stalled(u64::MAX - 10, 4000, 100), "wrapping clock");
    }

    #[test]
    fn callbacks_run_on_the_lowest_cpu_outside_the_mask() {
        let all = |_c: usize| true;
        assert_eq!(callback_cpu(4, 0, all), Some(0));
        assert_eq!(callback_cpu(4, 0b0011, all), Some(2));
        assert_eq!(callback_cpu(4, 0b1111, all), None);
        assert_eq!(callback_cpu(4, 0b0001, |c| c != 1), Some(2));
    }

    /// The mask is read by logical CPU id. A machine whose boot hart is 4 and
    /// whose harts are 4, 1, 7 has CPUs 0, 1, 2: the RT test of the CPU the
    /// reclaim task runs on asks with the CPU id, not the hart id.
    ///
    /// Canary (by hand, 2026-10-17): `cpu_in_mask` reading bit `cpu + 1`:
    /// the CPU 2 line red. (A task that asks with the hart id reads the same
    /// wrong bit; that call site is not host-testable.)
    #[test]
    fn the_rt_mask_is_read_by_cpu_id_not_hart_id() {
        let hart_of_cpu = [4usize, 1, 7];
        let rt = 0b100; // CPU 2 is real-time
        for (cpu, &hart) in hart_of_cpu.iter().enumerate() {
            assert_eq!(cpu_in_mask(rt, cpu), cpu == 2, "CPU {cpu}");
            // Hart 7 would read bit 7 (clear): the wrong answer for CPU 2; hart 4
            // would read bit 4 for CPU 0.
            assert_eq!(cpu_in_mask(rt, hart), false, "hart id {hart} is not a CPU id here");
        }
        // The CPU the task is placed on is never in the mask it was chosen against.
        let all = |_c: usize| true;
        assert!(!cpu_in_mask(rt, callback_cpu(3, rt, all).unwrap()));
        assert!(!cpu_in_mask(usize::MAX, usize::BITS as usize), "past the width: in no mask");
        assert!(!cpu_in_mask(usize::MAX, 4096));
    }
}

#[cfg(test)]
mod lockdep_tests {
    use super::lockdep::*;
    use core::panic::Location;

    type G = Graph<64, 64>;

    #[track_caller]
    fn class(kind: Kind) -> LockClass { LockClass::here(kind) }

    #[track_caller]
    fn held(c: &LockClass, addr: usize) -> Held {
        Held::new(c, addr, Kind::Spin, false, false, Location::caller())
    }

    #[test]
    fn class_is_the_declaration_site_and_kind() {
        let (a, b) = (class(Kind::Spin), class(Kind::Spin));
        assert_ne!(a.key(), b.key(), "two sites, two classes");
        let c: Vec<LockClass> = (0..2).map(|_| class(Kind::Spin)).collect();
        assert_eq!(c[0].key(), c[1].key(), "one site, one class");
        let k = |kind| class_key("f.rs", 1, 1, kind as u8);
        assert_ne!(k(Kind::Spin), k(Kind::Mutex));
        assert_ne!(k(Kind::Spin), 0);
    }

    #[test]
    fn abba_is_reported_with_both_sites() {
        let g = G::new();
        let (ca, cb) = (class(Kind::Spin), class(Kind::Spin));
        let (a, b) = (held(&ca, 0x100), held(&cb, 0x200));
        assert!(g.check(&[], &a).is_none());
        assert!(g.check(&[a], &b).is_none(), "A then B is a first order, not a violation");
        assert!(g.edge(ca.key(), cb.key()).is_some());
        assert!(g.check(&[a], &b).is_none(), "the same chain again is cached");
        let r = g.check(&[b], &a).expect("B then A after A then B is an inversion");
        assert_eq!(r.what, What::Inversion);
        assert_eq!(r.held.key, cb.key());
        assert_eq!(r.taken.key, ca.key());
        assert!(r.reverse_site_loc().is_some() && r.reverse_held_site_loc().is_some());
        let line = format!("{}", r);
        assert!(line.starts_with("lockdep: lock order inversion (ABBA)"), "{line}");
        assert!(line.contains("lib.rs"), "{line}");
    }

    #[test]
    fn irq_context_locks_form_no_edge_with_task_locks() {
        let g = G::new();
        let (ca, cb) = (class(Kind::Spin), class(Kind::Spin));
        let a = held(&ca, 1);
        let b_irq = Held { irq_ctx: true, ..held(&cb, 2) };
        assert!(g.check(&[a], &b_irq).is_none());
        assert!(g.edge(ca.key(), cb.key()).is_none());
    }

    #[test]
    fn recursion_and_same_class() {
        let g = G::new();
        let c = class(Kind::Spin);
        let a = held(&c, 1);
        assert_eq!(g.check(&[a], &a).map(|r| r.what), Some(What::Recursive));
        // A wrapper and the SpinLock at its address are two locks.
        let w = Held { kind: Kind::Mutex, key: class_key("w", 1, 1, 2), ..a };
        assert!(g.check(&[w], &a).map_or(true, |r| r.what != What::Recursive));
        let a2 = held(&c, 2);
        let r = g.check(&[a], &a2).expect("same class nested is a note");
        assert!(r.what.is_note());
    }

    #[test]
    fn full_edge_table_is_reported() {
        let g: Graph<2, 64> = Graph::new();
        // Four classes by key (a closure has one call site, one class).
        let k: Vec<Held> = (1..=4u32).map(|i| Held { key: class_key("x", i, 0, 1), addr: i as usize, ..Held::EMPTY }).collect();
        assert!(g.check(&[k[0]], &k[1]).is_none());
        assert!(g.check(&[k[0]], &k[2]).is_none());
        assert_eq!(g.check(&[k[0]], &k[3]).map(|r| r.what), Some(What::TableFull));
    }

    #[test]
    fn held_stack_pops_out_of_order_and_absorbs_overflow() {
        let mut s: HeldStack<2> = HeldStack::new();
        let c = class(Kind::Spin);
        assert!(s.push(held(&c, 1)) && s.push(held(&c, 2)));
        assert!(!s.pop(1, Kind::Mutex), "same address, other kind: not this lock");
        assert!(!s.push(held(&c, 3)), "past the depth: not recorded");
        assert!(s.pop(1, Kind::Spin), "out of order");
        assert!(s.pop(3, Kind::Spin), "the lost push's release is absorbed");
        assert!(!s.pop(9, Kind::Spin), "a release never taken is unmatched");
        assert!(s.pop(2, Kind::Spin) && s.is_empty());
        let mut t: HeldStack<2> = HeldStack::new();
        s.push(held(&c, 7));
        t.copy_from(&s);
        assert_eq!(t.held().len(), 1);
        assert_eq!(t.held()[0].addr, 7);
    }

    #[test]
    fn kernel_instance_is_inert_without_the_feature() {
        assert!(!ON);
        let c = class(Kind::Spin);
        acquire(&c, 1, Kind::Spin, false, Location::caller());
        might_sleep("test");
        user_return();
        assert_eq!(violations(), 0);
        assert_eq!(stats(), Stats::default());
        // N1b's entry points are inert too.
        scope_per_cpu();
        scope_cpu_owned(3);
        contended(&c, 1, Kind::Mutex, 1 << 31 | 2);
        assert_eq!(holder_word(), 0);
        hold_unbounded();
        assert_eq!(stats(), Stats::default());
    }

    type Cl = Classes<64, 8>;

    #[test]
    fn irq_inference_needs_both_contexts() {
        let t = Cl::new();
        let c = class(Kind::Spin);
        let i = t.slot(&held(&c, 1));
        assert_ne!(i, NO_CLASS);
        assert_eq!(t.slot(&held(&c, 2)), i, "one class, one slot, whatever the instance");
        assert!(t.infer(i, false, false, 0x10).is_none(), "task context, interrupts off: neither");
        assert!(t.infer(i, true, false, 0x20).is_none(), "interrupt context alone: IRQ-safe, fine");
        assert!(t.infer(i, true, false, 0x21).is_none());
        assert_eq!(t.infer(i, false, true, 0x30), Some((0x20, 0x30)),
                   "then task context with interrupts on: the inversion, first sites kept");
        let d = class(Kind::Spin);
        let j = t.slot(&held(&d, 3));
        assert!(t.infer(j, false, true, 0x40).is_none(), "interrupts on alone: IRQ-unsafe, fine");
        assert_eq!(t.infer(j, true, false, 0x50), Some((0x50, 0x40)), "either order");
    }

    #[test]
    fn hold_histogram_and_top() {
        assert_eq!(hold_bucket(0, 8), 0);
        assert_eq!(hold_bucket(1, 8), 1);
        assert_eq!(hold_bucket(3, 8), 2);
        assert_eq!(hold_bucket(4, 8), 3);
        assert_eq!(hold_bucket(1 << 40, 8), 7, "the last bucket takes the rest");
        let t = Cl::new();
        let (a, b) = (class(Kind::Spin), class(Kind::Mutex));
        let (ia, ib) = (t.slot(&held(&a, 1)), t.slot(&Held { kind: Kind::Mutex, ..held(&b, 2) }));
        // Site words are `&'static Location`s (printed by `HoldLine`).
        let site = Location::caller() as *const Location<'static> as usize;
        t.hold(ia, 10, 1, site);
        t.hold(ia, 500, 50, site);
        t.hold(ib, 90, 9, site);
        let ca = t.get(ia as usize).unwrap();
        assert_eq!((ca.holds, ca.max_ticks), (2, 500));
        assert_eq!(ca.hist[1] + ca.hist[6], 2);
        assert_eq!(t.get(ib as usize).unwrap().kind, Kind::Mutex);
        let mut order = Vec::new();
        t.top(5, |c| order.push(c.max_ticks));
        assert_eq!(order, vec![500, 90], "longest first, each once");
        let line = format!("{}", HoldLine(&ca));
        assert!(line.starts_with("lockdep: hold SpinLock") && line.contains("holds=2"), "{line}");
    }

    #[test]
    fn full_class_table_is_counted() {
        let t: Classes<2, 4> = Classes::new();
        let k: Vec<Held> = (1..=3u32).map(|i| Held { key: class_key("y", i, 0, 1), ..Held::EMPTY }).collect();
        assert_ne!(t.slot(&k[0]), NO_CLASS);
        assert_ne!(t.slot(&k[1]), NO_CLASS);
        assert_eq!(t.slot(&k[2]), NO_CLASS);
        assert_eq!(t.counts(), (2, 1));
        assert!(t.infer(NO_CLASS, true, false, 1).is_none());
        t.hold(NO_CLASS, 1, 1, 1);
    }

    #[test]
    fn new_reports_print_their_numbers() {
        let c = class(Kind::Spin);
        let h = held(&c, 1);
        let mut r = Report::EMPTY;
        r.what = What::HoldOverLimit;
        r.held = h;
        r.value = 250;
        r.value2 = 100;
        let line = format!("{}", r);
        assert!(line.contains("held 250 us, limit 100 us"), "{line}");
        assert!(What::HoldOverLimitNote.is_note() && !What::HoldOverLimit.is_note());
        // Owner decision 10-10: rule F7 is report-only.
        assert!(What::RtCrossCpu.is_note());
        r.what = What::RtCrossCpu;
        r.taken = Held { kind: Kind::Mutex, ..h };
        r.value = 1;
        r.value2 = 2;
        let line = format!("{}", r);
        assert!(line.contains("RT task on CPU 1") && line.contains("one on CPU 2"), "{line}");
    }
}

/// Wave 15 N8c: a `Mutex` excludes, and `unlocked_for_io` really frees it
/// for the length of the device wait and re-takes it after (rule F1).
#[cfg(test)]
mod mutex_io_tests {
    use super::kmutex::Mutex;

    #[test]
    fn mutex_excludes_and_unlocked_for_io_frees_the_wait() {
        let _held = crate::held_table_lock();
        static L: Mutex<u32> = Mutex::new(0);
        let mut g = L.lock();
        *g = 7;
        assert!(L.try_lock().is_none(), "a held Mutex was taken again");
        let free_in_wait = g.unlocked_for_io("host test wait", || L.try_lock().is_some());
        assert!(free_in_wait, "the Mutex was held across the device wait (F1)");
        assert!(L.try_lock().is_none(), "unlocked_for_io did not re-take the Mutex");
        assert_eq!(*g, 7);
        drop(g);
        assert_eq!(L.try_lock().map(|g| *g), Some(7));
    }
}

#[cfg(test)]
mod donor_node_tests {
    /// N7e: the donor node selector. With `WAIT_GRAPH` n a donor's node is
    /// zero-sized, so embedding it changes no layout; y selects the graph's
    /// `PiWaiters` with the donor's edge kind.
    #[test]
    fn donor_node_is_zero_sized_without_the_graph() {
        use super::waitgraph::{DonorNode, EdgeKind, NodeSel, PiWaiters, SelectNode, ENABLED};
        let want = if ENABLED { core::mem::size_of::<PiWaiters>() } else { 0 };
        assert_eq!(core::mem::size_of::<DonorNode>(), want);
        assert_eq!(core::mem::size_of::<<NodeSel<true> as SelectNode>::Node>(),
                   core::mem::size_of::<PiWaiters>());
        assert_eq!(<NodeSel<true> as SelectNode>::IPC_CALL.kind(), EdgeKind::IpcCall);
        assert_eq!(<NodeSel<true> as SelectNode>::DRIVER_PROXY.kind(), EdgeKind::DriverProxy);
    }
}

/// N8: the kernel mutex without a scheduler (host): the owner-word states,
/// exclusion, the slow unlock a marked word forces, and rule F1's release
/// around a device wait. The graph is off here (`WAIT_GRAPH` n), so no
/// path reaches a `waitgraph` stub.
#[cfg(test)]
mod kmutex_tests {
    use super::kmutex::{word, Mutex};
    use core::sync::atomic::Ordering;

    #[test]
    fn owner_word_states() {
        let _held = crate::held_table_lock();
        assert_eq!(word::owned_by(0), word::BOOT_OWNER);
        assert_eq!(word::owned_by(u32::MAX), word::BOOT_OWNER);
        assert_eq!(word::owned_by(42), 42);
        assert_eq!(word::owner(word::FREE), None);
        assert_eq!(word::owner(word::WAITERS), None);
        assert_eq!(word::owner(42 | word::WAITERS), Some(42));
        // free -> owned: fast unlock applies; owned -> marked: it does not.
        assert!(!word::fast_unlockable(word::FREE));
        assert!(word::fast_unlockable(42));
        assert!(!word::fast_unlockable(42 | word::WAITERS));
        assert!(!word::sleep_on(42));
        assert!(word::sleep_on(42 | word::WAITERS));
        assert!(!word::sleep_on(word::WAITERS));
    }

    #[test]
    fn lock_excludes_and_releases() {
        let _held = crate::held_table_lock();
        static M: Mutex<u32> = Mutex::new(0);
        {
            let mut g = M.lock();
            *g += 1;
            assert!(M.is_locked());
            assert!(M.try_lock().is_none(), "try_lock took a held mutex");
        }
        assert!(!M.is_locked());
        assert_eq!(*M.try_lock().expect("free after drop"), 1);
        assert_eq!(M.owner.load(Ordering::Relaxed), word::FREE);
    }

    #[test]
    fn marked_word_takes_the_slow_unlock_and_frees() {
        let _held = crate::held_table_lock();
        static M: Mutex<u32> = Mutex::new(0);
        let g = M.lock();
        // A sleeper marked the word: the one-CAS unlock must not apply.
        M.owner.fetch_or(word::WAITERS, Ordering::Relaxed);
        drop(g);
        assert_eq!(M.owner.load(Ordering::Relaxed), word::FREE);
        // A lingering mark on a free word is kept by the next owner.
        M.owner.store(word::WAITERS, Ordering::Relaxed);
        let g = M.lock();
        assert!(word::sleep_on(M.owner.load(Ordering::Relaxed)));
        drop(g);
        assert_eq!(M.owner.load(Ordering::Relaxed), word::FREE);
    }

    #[test]
    fn unlocked_for_io_releases_around_the_wait() {
        let _held = crate::held_table_lock();
        static M: Mutex<u32> = Mutex::new(7);
        let mut g = M.lock();
        let free_in_wait = g.unlocked_for_io("host blk wait", || {
            // Another task could take it here: the mutex is free.
            M.try_lock().map(|mut h| { *h += 1; }).is_some()
        });
        assert!(free_in_wait, "F1: the mutex stayed held across the device wait");
        assert!(M.is_locked(), "not re-acquired after the wait");
        assert_eq!(*g, 8);
        let t = g.unlock_for_io();
        assert!(!M.is_locked());
        let g = t.relock();
        assert!(M.is_locked());
        drop(g);
        assert!(!M.is_locked());
    }

    #[test]
    fn threads_exclude() {
        let _held = crate::held_table_lock();
        use std::sync::Arc;
        let m = Arc::new(Mutex::new(0u64));
        let hs: Vec<_> = (0..4).map(|_| {
            let m = m.clone();
            std::thread::spawn(move || for _ in 0..2000 { *m.try_lock_spin() += 1; })
        }).collect();
        for h in hs { h.join().unwrap(); }
        assert_eq!(*m.try_lock().unwrap(), 8000);
    }

    /// N8b steal rule: after a release only the top waiter, or a task
    /// strictly more urgent than it, takes the mutex.
    #[test]
    fn steal_rule_only_a_more_urgent_task_overtakes_the_top_waiter() {
        let _held = crate::held_table_lock();
        use super::kmutex::may_take;
        use super::waitgraph::PiAttr;
        let rt = |p| Some(PiAttr::Rt { prio: p });
        // Nobody queued: anyone takes it.
        assert!(may_take(Some(PiAttr::Fair), None, false));
        assert!(may_take(None, None, false));
        // The top waiter always takes it, whatever the comparison says.
        assert!(may_take(Some(PiAttr::Fair), rt(4), true));
        // Strictly more urgent overtakes; equal or less waits.
        assert!(may_take(rt(2), rt(4), false));
        assert!(!may_take(rt(4), rt(4), false), "equal urgency stole the lock");
        assert!(!may_take(rt(6), rt(4), false));
        assert!(!may_take(Some(PiAttr::Fair), Some(PiAttr::Fair), false), "fair stole from fair");
        assert!(!may_take(Some(PiAttr::Fair), rt(10), false));
        assert!(may_take(Some(PiAttr::Dl { deadline_ns: 1_000 }), rt(0), false));
        assert!(may_take(Some(PiAttr::Dl { deadline_ns: 1_000 }), Some(PiAttr::Dl { deadline_ns: 2_000 }), false));
        assert!(!may_take(Some(PiAttr::Dl { deadline_ns: 2_000 }), Some(PiAttr::Dl { deadline_ns: 1_000 }), false));
        assert!(may_take(Some(PiAttr::Stop), Some(PiAttr::Dl { deadline_ns: 0 }), false));
        // No attribute (no scheduler slot): never overtakes a queued waiter.
        assert!(!may_take(None, Some(PiAttr::Idle), false));
    }

    /// Without the graph (host, `WAIT_GRAPH` n) the slow unlock still
    /// clears the word to FREE: the steal rule's ownerless WAITERS word only
    /// exists while a graph waiter is queued.
    #[test]
    fn slow_unlock_without_graph_waiters_frees_the_word() {
        let _held = crate::held_table_lock();
        static M: Mutex<u32> = Mutex::new(0);
        let g = M.lock();
        M.owner.fetch_or(word::WAITERS, Ordering::Relaxed);
        drop(g);
        assert_eq!(M.owner.load(Ordering::Relaxed), word::FREE);
        assert!(M.try_lock().is_some(), "the fast path could not take a released mutex");
    }

    /// Owner decision 10-10 (N7d): the owner after a dead one learns it
    /// from `MutexGuard::owner_died`; that owner's unlock clears the flag.
    #[test]
    fn owner_died_is_seen_by_the_next_owner_and_cleared_by_its_unlock() {
        let _held = crate::held_table_lock();
        use super::kmutex::{owner_died_count, OWNER_DIED_HOOK};
        use super::waitgraph::OwnerDiedHook;
        static M: Mutex<u32> = Mutex::new(0);
        assert!(!M.lock().owner_died(), "a normal hand-over reads owner-died");
        // The owner exits holding it with a sleeper marked.
        let g = M.lock();
        M.owner.fetch_or(word::WAITERS, Ordering::Relaxed);
        core::mem::forget(g);
        let before = owner_died_count();
        // No probes on the host: the hook takes the word as the dead task's.
        OWNER_DIED_HOOK.owner_died(M.wait_node(), 0);
        assert_eq!(owner_died_count(), before + 1);
        // Marked and ownerless: the next owner's unlock must be the slow one.
        assert_eq!(M.owner.load(Ordering::Relaxed), word::WAITERS);
        let g = M.lock();
        assert!(g.owner_died(), "the next owner was not told its owner died");
        assert!(word::sleep_on(M.owner.load(Ordering::Relaxed)), "the mark was lost");
        drop(g);
        assert_eq!(M.owner.load(Ordering::Relaxed), word::FREE);
        assert!(!M.lock().owner_died(), "the flag survived the next normal unlock");
        assert!(!M.try_lock().expect("free").owner_died());
    }

    trait SpinTry<T> { fn try_lock_spin(&self) -> super::kmutex::MutexGuard<'_, T>; }
    impl<T> SpinTry<T> for Mutex<T> {
        /// `try_lock` in a loop: exclusion across host threads without the
        /// caller identity (host threads share one TID, so `lock`'s debug
        /// recursion check cannot tell them apart).
        fn try_lock_spin(&self) -> super::kmutex::MutexGuard<'_, T> {
            loop {
                if let Some(g) = self.try_lock() { return g; }
                std::hint::spin_loop();
            }
        }
    }
}

/// `PreemptGuard` must be `!Send`.
///
/// The depth it decrements belongs to a *hart*, so a guard released on a hart
/// other than the one that took it would decrement a counter it never
/// incremented — an underflow on one hart and a permanent disable on another.
/// `PhantomData<*mut ()>` makes that a compile error.
///
/// ```compile_fail
/// use azos_sync_tests::preempt::critical_section;
/// fn assert_send<T: Send>(_t: T) {}
/// assert_send(critical_section());
/// ```
///
/// The companion below is the control: it proves the `compile_fail` above
/// fails on the `Send` bound and not on a typo in the path or the import.
///
/// ```
/// use azos_sync_tests::preempt::critical_section;
/// fn assert_not_send<T>(_t: T) {}
/// assert_not_send(critical_section());
/// ```
pub fn preempt_guard_is_not_send() {}

/// `kmutex::MutexGuard` must be `!Send` (N8): the owner word names the task
/// that took the mutex, and only that task releases it.
///
/// ```compile_fail
/// use azos_sync_tests::kmutex::Mutex;
/// static M: Mutex<u32> = Mutex::new(0);
/// fn assert_send<T: Send>(_t: T) {}
/// assert_send(M.lock());
/// ```
///
/// Control (the path and the import are right):
///
/// ```
/// use azos_sync_tests::kmutex::Mutex;
/// static M: Mutex<u32> = Mutex::new(0);
/// fn assert_not_send<T>(_t: T) {}
/// assert_not_send(M.lock());
/// ```
pub fn kmutex_guard_is_not_send() {}

#[cfg(test)]
mod tests {
    use super::preempt;
    use super::preempt_core::{
        self, EnableOutcome, TickDispatch, VoluntaryAdmission,
    };
    use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    // ── Test harness ────────────────────────────────────────────────────
    //
    // `preempt.rs`'s `PREEMPT` slots and its UNDERFLOW/HART_OOR counters are
    // process-global statics, so tests that touch them must not run
    // concurrently. Every test takes this lock and resets the slot it uses.

    fn test_lock() -> &'static Mutex<()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
    }

    /// Serialise, and start from a known slot state on hart 0 with SIE set.
    pub(crate) fn guard() -> MutexGuard<'static, ()> {
        // Ignore poisoning: a failing test leaves the lock poisoned, and the
        // remaining tests should still run (and reset state themselves)
        // rather than all reporting the first failure.
        let g = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        azos_arch::set_hart(0);
        azos_arch::set_sie(true);
        // A test that fails after arming the sstatus hook but before it fires
        // must not leave it armed for whichever test's `read_sstatus()` call
        // comes next on this OS thread.
        azos_arch::clear_sstatus_hook();
        preempt::window_hook::clear();
        preempt::force_zero_depth();
        CALLS.store(0, Ordering::Relaxed);
        NEED_AT_CALL.store(false, Ordering::Relaxed);
        g
    }

    /// How many times the registered resched callback fired.
    static CALLS: AtomicU32 = AtomicU32::new(0);
    /// What `need_resched()` read *inside* the callback.
    static NEED_AT_CALL: AtomicBool = AtomicBool::new(false);

    fn record_resched() {
        NEED_AT_CALL.store(preempt::need_resched(), Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Relaxed);
    }

    fn arm_callback() {
        preempt::set_resched_callback(record_resched);
    }

    // ── Pure decision logic ─────────────────────────────────────────────

    #[test]
    fn tick_dispatch_defers_exactly_when_disabled() {
        assert_eq!(preempt_core::tick_dispatch(0), TickDispatch::Switch);
        for d in [1u32, 2, 7, u32::MAX] {
            assert_eq!(
                preempt_core::tick_dispatch(d),
                TickDispatch::Defer,
                "depth {d} must defer"
            );
        }
    }

    #[test]
    fn voluntary_refuses_exactly_when_disabled() {
        assert_eq!(
            preempt_core::voluntary_admission(0),
            VoluntaryAdmission::Proceed
        );
        for d in [1u32, 2, 7, u32::MAX] {
            assert_eq!(
                preempt_core::voluntary_admission(d),
                VoluntaryAdmission::RefuseAtomic,
                "depth {d} must refuse"
            );
        }
    }

    #[test]
    fn disable_saturates_instead_of_wrapping() {
        assert_eq!(preempt_core::disable(0), 1);
        assert_eq!(preempt_core::disable(1), 2);
        // The whole point: `u32::MAX + 1 == 0` would silently re-enable
        // preemption inside a critical section.
        assert_eq!(preempt_core::disable(u32::MAX), u32::MAX);
    }

    #[test]
    fn enable_at_zero_underflows_without_wrapping() {
        // `enable` takes depth alone now (see `EnableOutcome`'s docs for why
        // `need_resched`/`irqs_enabled` were pulled out into `should_fire`),
        // so there is only one depth-0 case to check, not a (need, irqs)
        // matrix over it.
        let (depth, outcome) = preempt_core::enable(0);
        assert_eq!(depth, 0, "must not wrap to u32::MAX");
        assert_eq!(outcome, EnableOutcome::Underflow);
    }

    #[test]
    fn enable_reports_outermost_only_at_depth_one() {
        assert_eq!(preempt_core::enable(1), (0, EnableOutcome::Enabled));
        // A nested guard is never the outermost, whatever depth it nests at.
        for d in [2u32, 3, 7, u32::MAX] {
            assert_eq!(
                preempt_core::enable(d),
                (d - 1, EnableOutcome::StillDisabled),
                "depth {d} must stay StillDisabled"
            );
        }
    }

    #[test]
    fn should_fire_requires_both_need_and_irqs() {
        // The matrix `enable` used to decide internally now lives here, over
        // (need, irqs) alone — `should_fire` has no depth parameter at all,
        // because by the time it is called the caller has already committed
        // to `Enabled` (outermost guard) and depth is irrelevant to whether
        // the debt is safe to pay.
        assert!(preempt_core::should_fire(true, true));
        assert!(!preempt_core::should_fire(true, false));
        assert!(!preempt_core::should_fire(false, true));
        assert!(!preempt_core::should_fire(false, false));
    }

    // ── The real guard, on the real statics ─────────────────────────────

    #[test]
    fn guard_raises_and_lowers_depth() {
        let _g = guard();
        arm_callback();
        assert_eq!(preempt::depth(), 0);
        assert!(!preempt::disabled());
        {
            let _c = preempt::critical_section();
            assert_eq!(preempt::depth(), 1);
            assert!(preempt::disabled());
        }
        assert_eq!(preempt::depth(), 0);
        assert!(!preempt::disabled());
    }

    /// A context may block only with preemption on and interrupts unmasked:
    /// inside any critical section (a SpinLock's, `cap_store::with_table`'s
    /// closure among them) or with the interrupt flag clear it may not.
    /// **Canary.** Make `may_block` ignore the depth: the first inside
    /// assertion goes red.
    #[test]
    fn may_block_is_false_under_a_lock_and_with_interrupts_masked() {
        let _g = guard();
        arm_callback();
        assert!(preempt::may_block());
        {
            let _c = preempt::critical_section();
            assert!(!preempt::may_block(), "a spinlock is held");
            let _d = preempt::critical_section();
            assert!(!preempt::may_block());
        }
        assert!(preempt::may_block(), "released");
        azos_arch::set_sie(false);
        assert!(!preempt::may_block(), "interrupts masked");
        azos_arch::set_sie(true);
        assert!(preempt::may_block());
    }

    #[test]
    fn nested_inner_drop_does_not_fire_and_leaves_depth_one() {
        let _g = guard();
        arm_callback();

        // `deferred`/`fired` are process-global (like `PREEMPT` itself), so
        // this reads deltas rather than resetting them — see
        // `unbalanced_release_counts_an_underflow_and_does_not_wrap` for the
        // same pattern with `UNDERFLOW`.
        let d0 = preempt::deferred();
        let f0 = preempt::fired();

        let outer = preempt::critical_section();
        assert_eq!(preempt::depth(), 1);
        {
            let _inner = preempt::critical_section();
            assert_eq!(preempt::depth(), 2);
            // A tick lands while nested, and interrupts are on. The inner drop
            // must still not fire: an outer critical section is open.
            preempt::set_need_resched();
        }
        assert_eq!(preempt::depth(), 1, "inner drop must leave depth 1");
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "inner drop must not fire");
        assert!(preempt::need_resched(), "the debt must survive the inner drop");
        assert_eq!(preempt::deferred(), d0 + 1, "the tick was recorded once");
        assert_eq!(
            preempt::fired(), f0,
            "an inner drop must pay nothing — `depth` staying at 1 is not by \
             itself proof of that; the counter must not move either"
        );

        drop(outer);
        assert_eq!(preempt::depth(), 0);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1, "outer drop fires exactly once");
        assert!(!preempt::need_resched(), "the debt is discharged");
        assert_eq!(
            preempt::fired(), f0 + 1,
            "the outer drop pays the debt exactly once, not once per nesting level"
        );
        assert_eq!(
            preempt::deferred(), d0 + 1,
            "paying the debt must not re-record the tick that created it"
        );
    }

    #[test]
    fn need_resched_is_cleared_before_the_callback_runs() {
        let _g = guard();
        arm_callback();

        let c = preempt::critical_section();
        preempt::set_need_resched();
        drop(c);

        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        // The callback re-enters the scheduler, which may take and drop a
        // guard of its own. Seeing the flag still set there would make that
        // inner drop fire a second, duplicate reschedule for a debt already
        // being paid.
        assert!(
            !NEED_AT_CALL.load(Ordering::Relaxed),
            "need_resched must be cleared BEFORE the callback is invoked"
        );
    }

    #[test]
    fn no_fire_without_a_pending_tick() {
        let _g = guard();
        arm_callback();
        let c = preempt::critical_section();
        drop(c);
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fire_requires_interrupts_enabled_and_the_debt_survives() {
        let _g = guard();
        arm_callback();

        let c = preempt::critical_section();
        preempt::set_need_resched();
        // Stand in for "this guard is being dropped inside the scheduler or
        // inside an ISR" — every such context runs with SSTATUS_SIE clear.
        azos_arch::set_sie(false);
        drop(c);

        assert_eq!(preempt::depth(), 0, "the depth still drops");
        assert_eq!(
            CALLS.load(Ordering::Relaxed), 0,
            "must not re-enter the scheduler with interrupts off"
        );
        assert!(
            preempt::need_resched(),
            "the debt must SURVIVE a drop that could not pay it"
        );

        // Back in ordinary task context, the surviving debt is paid.
        azos_arch::set_sie(true);
        let c2 = preempt::critical_section();
        drop(c2);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1, "the deferred tick is paid later");
        assert!(!preempt::need_resched());
    }

    // ── The `deferred`/`fired` counter pair ─────────────────────────────
    //
    // These pin the two counters directly, on top of what the tests above
    // already establish via `CALLS`. They matter separately: `CALLS` proves
    // the callback ran; these prove the *accounting* of that event is
    // correct. A mutant that fires the callback without bumping `FIRED`, or
    // bumps `FIRED` without the callback running, passes every `CALLS`-only
    // assertion above and must still fail one of these.

    #[test]
    fn deferred_tick_later_paid_increments_both_counters_exactly_once() {
        let _g = guard();
        arm_callback();

        let d0 = preempt::deferred();
        let f0 = preempt::fired();

        let c = preempt::critical_section();
        preempt::set_need_resched();
        assert_eq!(
            preempt::deferred(), d0 + 1,
            "recording the debt must bump `deferred` exactly once"
        );
        assert_eq!(
            preempt::fired(), f0,
            "recording a debt must not itself pay it"
        );

        // Interrupts are on (guard()'s default) — ordinary task context, so
        // this drop is legally allowed to re-enter the scheduler.
        drop(c);

        assert_eq!(
            preempt::fired(), f0 + 1,
            "a debt that gets paid must bump `fired` exactly once"
        );
        assert_eq!(
            preempt::deferred(), d0 + 1,
            "paying a debt must not retroactively double-count the tick \
             that created it — `deferred` counts ticks, not payments"
        );
        assert_eq!(CALLS.load(Ordering::Relaxed), 1, "the callback itself still ran once");
    }

    #[test]
    fn deferred_tick_not_paid_increments_deferred_not_fired_and_debt_survives() {
        let _g = guard();
        arm_callback();

        let d0 = preempt::deferred();
        let f0 = preempt::fired();

        let c = preempt::critical_section();
        preempt::set_need_resched();
        // Stand in for "this guard is being dropped inside the scheduler or
        // inside an ISR" — every such context runs with SSTATUS_SIE clear
        // (see `irqs_enabled`'s doc in `preempt.rs`).
        azos_arch::set_sie(false);
        drop(c);

        assert_eq!(preempt::deferred(), d0 + 1, "the tick was still deferred");
        assert_eq!(
            preempt::fired(), f0,
            "a drop that could not legally re-enter the scheduler must not \
             be counted as a fire, whatever `need_resched` said"
        );
        assert!(preempt::need_resched(), "the debt must survive this drop");
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "no callback ran either");
    }

    #[test]
    fn a_tick_landing_between_the_decrement_and_the_decision_is_not_lost() {
        // THE RACE THIS FIX EXISTS FOR (K-C29-adjacent lost wakeup). This must
        // pin `PreemptGuard::drop` itself, not just the pure `enable`/
        // `should_fire` split called correctly by a hand-written test caller
        // — that would prove the arithmetic is right while leaving open
        // whether `drop` actually calls it in the fixed order.
        //
        // No host thread can deliver a same-hart RISC-V interrupt, so this
        // drives the injection point `shims/arch::arm_on_sstatus_read` exists
        // for. `drop`'s fixed ordering reads `irqs_enabled()` (which calls
        // `cpu::read_sstatus()`) BEFORE it reads `need_resched` — both AFTER
        // the depth has already committed to 0. Arming a hook on
        // `read_sstatus()` to set `need_resched` right there stands in for "a
        // tick's `need_resched = true` becomes visible in exactly the window
        // between the decrement and the decision".
        //
        // Discriminator check (why this is not decorative): under the OLD
        // ordering — `need`/`irqs` read BEFORE the `fetch_update` that
        // decrements — `need` is already loaded (as `false`) by the time this
        // hook could run, so the hook's write is invisible to that stale
        // copy and the guard decides `fire: false`. Reapplying the old
        // ordering must make this assertion fail; see the report for the
        // canary run that confirms it.
        let _g = guard();
        arm_callback();

        let c = preempt::critical_section();
        assert!(!preempt::need_resched(), "starts with nothing owed");
        // Fires when `drop`'s FIRST read of `cpu::read_sstatus()` happens —
        // i.e. inside `irqs_enabled()`, which the fixed `drop` calls only
        // after the depth has already gone from 1 to 0 (this is the only,
        // hence outermost, guard).
        azos_arch::arm_on_sstatus_read(|| preempt::set_need_resched());
        drop(c);

        assert_eq!(
            CALLS.load(Ordering::Relaxed), 1,
            "a need_resched set between the decrement committing and the fire \
             decision must still be seen and paid — reading 0 here means the \
             decision was made from a value staler than the decrement"
        );
        assert!(
            !preempt::need_resched(),
            "a debt that fired must also be cleared, not just fired once and left set"
        );
    }

    #[test]
    fn the_sstatus_hook_itself_fires_nothing_without_a_pending_tick() {
        // Negative control for the test above. Without this, a harness bug
        // that reports CALLS == 1 regardless of what the hook's body does
        // would make the previous test pass for the wrong reason — it would
        // no longer be measuring "the write became visible", only "a hook
        // ran". An inert hook (armed, but touching nothing) must still result
        // in no fire, because nothing is owed.
        let _g = guard();
        arm_callback();

        let c = preempt::critical_section();
        azos_arch::arm_on_sstatus_read(|| {});
        drop(c);

        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "an inert hook must not fire");
        assert!(!preempt::need_resched());
    }

    #[test]
    fn a_tick_that_reaches_the_scheduler_discharges_the_debt() {
        let _g = guard();
        arm_callback();

        let d0 = preempt::deferred();
        let f0 = preempt::fired();

        // A tick arrived while preemption was disabled and recorded a debt.
        preempt::set_need_resched();
        assert!(preempt::need_resched());
        assert_eq!(preempt::deferred(), d0 + 1, "the tick was recorded");

        // A later tick found preemption enabled and went on to `do_schedule`.
        // That is `tick_admit`'s Switch arm, and it clears the debt: the
        // reschedule the earlier tick wanted is happening now.
        preempt::clear_need_resched();
        assert!(
            !preempt::need_resched(),
            "a served tick must discharge the debt"
        );
        // THE POINT OF THIS TEST for the counter pair, not just the flag: the
        // debt is gone, but it was never paid through `PreemptGuard::drop`,
        // so `fired` must NOT move. This is one of the growth sources
        // documented on `FIRED` in `preempt.rs` — the reason `deferred -
        // fired` is a floor on tick-defer traffic, not a live count of debts
        // still owed: this debt closes and the gap it leaves behind never
        // does.
        assert_eq!(
            preempt::fired(), f0,
            "a debt discharged by `clear_need_resched` was not paid by a \
             guard drop and must not be counted as if it were"
        );

        // The consequence, and the reason it matters: the next guard drop must
        // not fire a redundant reschedule for a tick that was already served.
        let c = preempt::critical_section();
        drop(c);
        assert_eq!(
            CALLS.load(Ordering::Relaxed), 0,
            "a discharged debt must not fire on the next guard drop"
        );
        assert_eq!(preempt::fired(), f0, "no fire happened, so the counter must not move");
        assert_eq!(
            preempt::deferred(), d0 + 1,
            "an uneventful guard drop must not bump `deferred` either — only \
             `set_need_resched` does that"
        );
    }

    #[test]
    fn unbalanced_release_counts_an_underflow_and_does_not_wrap() {
        let _g = guard();
        arm_callback();

        let (before, _) = preempt::audit_counters();

        // `force_zero_depth` is what `task_exit_with_code` does: exit cannot
        // be refused, so an exiting task's open guard is discarded. Dropping
        // that guard afterwards is the underflow this counter exists for.
        let c = preempt::critical_section();
        assert_eq!(preempt::depth(), 1);
        preempt::force_zero_depth();
        drop(c);

        assert_eq!(preempt::depth(), 0, "must stay 0, never u32::MAX");
        assert!(!preempt::disabled(), "a wrapped depth would read as disabled");
        let (after, _) = preempt::audit_counters();
        assert_eq!(after, before + 1, "the underflow must be counted");
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "an underflow fires nothing");
    }

    #[test]
    fn slots_are_per_hart_and_never_merged() {
        let _g = guard();
        arm_callback();

        // The deleted stub clamped `hart.min(MAX_CPUS - 1)` with MAX_CPUS = 4
        // and MAX_HARTS = 8, so a critical section on hart 5 disabled
        // preemption on hart 3. Every slot must be independent.
        // One slot per CPU of the Kconfig ceiling; this test needs hart 5, so
        // it runs against a `.config` with NR_CPUS of at least 6 (qemu: 64).
        assert_eq!(preempt::SLOTS, azos_limits::NR_CPUS);
        assert!(preempt::SLOTS > 5, "this test needs NR_CPUS >= 6 in the host .config");
        for h in 0..preempt::SLOTS {
            azos_arch::set_hart(h);
            preempt::force_zero_depth();
        }
        azos_arch::set_hart(5);
        let c = preempt::critical_section();
        assert!(preempt::disabled(), "hart 5 is in a critical section");
        for other in 0..preempt::SLOTS {
            if other == 5 { continue; }
            azos_arch::set_hart(other);
            assert_eq!(
                preempt::depth(), 0,
                "hart {other} must not share hart 5's depth"
            );
        }
        azos_arch::set_hart(5);
        drop(c);
        assert_eq!(preempt::depth(), 0);
        azos_arch::set_hart(0);
    }

    // ── The load-to-store window (Chain E commit 7) ─────────────────────
    //
    // The depth moves by a Relaxed load and a Relaxed store, not an RMW.
    // `preempt::window_hook` runs a function between the two, standing for
    // an interrupt on this hart landing there.

    /// What the in-window "interrupt" saw: the depth before its own guard,
    /// and inside it.
    static SEEN_BEFORE: AtomicU32 = AtomicU32::new(u32::MAX);
    static SEEN_INSIDE: AtomicU32 = AtomicU32::new(u32::MAX);

    /// A depth-balanced interrupt handler: one guard, taken and dropped.
    fn balanced_irq() {
        SEEN_BEFORE.store(preempt::depth(), Ordering::Relaxed);
        let g = preempt::critical_section();
        SEEN_INSIDE.store(preempt::depth(), Ordering::Relaxed);
        drop(g);
    }

    #[test]
    fn an_interrupt_between_the_load_and_the_store_of_a_take_leaves_the_count_right() {
        let _g = guard();
        arm_callback();
        let (u0, _) = preempt::audit_counters();
        // Outermost (0 -> 1) and nested (1 -> 2): the store after the window
        // writes `d + 1` from a `d` loaded before the interrupt, which is
        // right only because the interrupt left the slot at `d`.
        for outer in 0..2u32 {
            let held: Vec<_> = (0..outer).map(|_| preempt::critical_section()).collect();
            preempt::window_hook::arm(balanced_irq);
            let c = preempt::critical_section();
            assert_eq!(SEEN_BEFORE.load(Ordering::Relaxed), outer,
                "the interrupt landed before the store: the slot still read d");
            assert_eq!(SEEN_INSIDE.load(Ordering::Relaxed), outer + 1,
                "the interrupt's own guard nested on d");
            assert_eq!(preempt::depth(), outer + 1,
                "after the window the count must be d + 1, not d + 2 or d");
            drop(c);
            assert_eq!(preempt::depth(), outer);
            drop(held);
            assert_eq!(preempt::depth(), 0);
        }
        let (underflow, _) = preempt::audit_counters();
        assert_eq!(underflow, u0, "a balanced interrupt must not unbalance anything");
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "nothing was owed");
    }

    /// A tick that lands while the slot still reads `d >= 1`: it defers
    /// (`tick_admit`'s `Defer` arm) after its own spinlocks, as the real one.
    fn deferring_tick() {
        balanced_irq();
        assert!(preempt::disabled(), "the slot still holds d >= 1 before the store");
        preempt::set_need_resched();
    }

    #[test]
    fn a_tick_between_the_load_and_the_store_of_a_drop_is_paid_by_that_drop() {
        let _g = guard();
        arm_callback();
        let c = preempt::critical_section();
        preempt::window_hook::arm(deferring_tick);
        drop(c);
        assert_eq!(SEEN_INSIDE.load(Ordering::Relaxed), 2, "the tick nested on depth 1");
        assert_eq!(preempt::depth(), 0, "the store after the window still lands 0");
        assert_eq!(CALLS.load(Ordering::Relaxed), 1,
            "the debt the tick recorded before the store must be read after it and paid");
        assert!(!preempt::need_resched(), "and cleared");
    }

    /// An interrupt that switches the task away and resumes it on another
    /// hart (the tick's exit, then an idle hart pulling the queued task):
    /// it can only land while interrupts are on.
    fn migrating_irq() {
        use azos_arch::Interrupts;
        if azos_arch::ARCH.interrupts_enabled() {
            azos_arch::set_hart(1);
        }
    }

    #[test]
    fn a_take_never_lands_on_a_hart_the_task_has_left() {
        // The load-to-store window of a take is the one place the task can be
        // moved between reading its hart and writing that hart's slot. If an
        // interrupt can land there, the 1 goes into the slot of the hart the
        // task LEFT (a depth nothing will ever drop: its ticks defer for good
        // and its blocks are refused), while the hart it resumed on sees the
        // matching drop at depth 0 (`UNDERFLOW`). Seen as a hart that never
        // rescheduled again on an x86_64 boot. The take must therefore leave
        // the task on the hart whose slot it wrote.
        let _g = guard();
        arm_callback();
        let (u0, _) = preempt::audit_counters();
        preempt::window_hook::arm(migrating_irq);
        let c = preempt::critical_section();
        assert_eq!(preempt::depth(), 1,
            "the hart the task runs on must show its critical section");
        drop(c);
        assert_eq!(preempt::depth(), 0);
        azos_arch::set_hart(0);
        assert_eq!(preempt::depth(), 0, "and the hart it started on must not keep a depth");
        let (underflow, _) = preempt::audit_counters();
        assert_eq!(underflow, u0, "no drop may find its slot at 0");
    }

    #[test]
    fn guards_dropped_out_of_order_keep_the_count() {
        // Rust lets an outer guard die first (`drop(a)` before `b`). The
        // count is a count, not a saved-and-restored previous value: a
        // guard that restored the depth it found would leave 1 here.
        let _g = guard();
        arm_callback();
        let (u0, _) = preempt::audit_counters();
        let a = preempt::critical_section();
        let b = preempt::critical_section();
        preempt::set_need_resched();
        drop(a);
        assert_eq!(preempt::depth(), 1, "one guard is still live");
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "not the outermost drop yet");
        drop(b);
        assert_eq!(preempt::depth(), 0);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1, "the last drop pays the debt");
        let (underflow, _) = preempt::audit_counters();
        assert_eq!(underflow, u0);
    }

    #[test]
    fn each_unbalanced_release_counts_once_and_the_count_stays_zero() {
        // Task exit inside two nested sections: both guards' drops are
        // underflows, each counted, neither wrapping nor firing a debt.
        let _g = guard();
        arm_callback();
        let (before, _) = preempt::audit_counters();
        let outer = preempt::critical_section();
        let inner = preempt::critical_section();
        preempt::set_need_resched();
        preempt::force_zero_depth();
        drop(inner);
        assert_eq!(preempt::depth(), 0, "must stay 0, never u32::MAX");
        drop(outer);
        assert_eq!(preempt::depth(), 0);
        let (after, _) = preempt::audit_counters();
        assert_eq!(after, before + 2, "each unbalanced drop is counted");
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "an underflow fires nothing");
        let c = preempt::critical_section();
        assert_eq!(preempt::depth(), 1, "the next section starts from 0 again");
        drop(c);
    }

    #[test]
    fn out_of_range_hart_is_counted_and_degrades_to_no_control() {
        let _g = guard();
        arm_callback();
        let (_, before) = preempt::audit_counters();

        azos_arch::set_hart(preempt::SLOTS);
        // Unreachable on a real board (boot.S range-checks against
        // MAX_HARTS = SLOTS). If it ever happened, it must not merge into
        // another hart's slot: everything degrades to today's behaviour, which
        // is no preemption control at all.
        let c = preempt::critical_section();
        assert_eq!(preempt::depth(), 0, "must not borrow another hart's slot");
        assert!(!preempt::disabled());
        drop(c);

        let (_, after) = preempt::audit_counters();
        assert!(after > before, "the out-of-range read must be counted");

        azos_arch::set_hart(0);
        assert_eq!(preempt::depth(), 0, "hart 0 was not touched");
    }

    // ── The test that can fail: one hart, two tasks, one lock ───────────

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Running { L, H }

    /// Steps before the model gives up and reports non-termination.
    const BOUND: usize = 1_000;

    /// A discrete one-hart model of the K-C29 hang, driven entirely by the
    /// production predicates.
    ///
    /// Task L (low priority) is running and takes a spinlock. Task H (high
    /// priority) becomes ready and spins on that same lock. Dispatch is
    /// strict-priority with no aging — the property this kernel actually has
    /// (`task.rs` placement + priority-ordered `cpu_dequeue`), and the reason
    /// K-C26 starves. So once H is picked, L is never picked again while H is
    /// runnable.
    ///
    /// Returns `Some(step)` when H finally acquires the lock, `None` if the
    /// model ran to `BOUND` without progress.
    fn run_model(dispatch: fn(u32) -> TickDispatch) -> Option<usize> {
        let mut depth = 0u32;
        let mut lock_held = false;
        let mut running = Running::L;
        let mut need_resched = false;
        // Ticks of work L still has to do inside its critical section.
        let mut l_work = 3usize;

        for step in 0..BOUND {
            match running {
                Running::L => {
                    if !lock_held {
                        // L takes the lock; the guard opens the critical section.
                        lock_held = true;
                        depth = preempt_core::disable(depth);
                    } else if l_work > 0 {
                        l_work -= 1;
                    } else {
                        // Critical section finished: release the lock and drop
                        // the guard. Interrupts are on — this is task context.
                        // Mirror the real `drop`'s order: decrement via
                        // `enable(depth)` alone, THEN consult `need_resched`
                        // and decide via `should_fire`. Consulting
                        // `need_resched` before calling `enable` here would
                        // silently go back to testing the shape production no
                        // longer has.
                        lock_held = false;
                        let (d, out) = preempt_core::enable(depth);
                        depth = d;
                        if out == EnableOutcome::Enabled
                            && preempt_core::should_fire(need_resched, true)
                        {
                            need_resched = false;
                            running = Running::H;
                        }
                        continue;
                    }
                    // A timer tick lands, with H ready and higher priority.
                    match dispatch(depth) {
                        TickDispatch::Switch => running = Running::H,
                        TickDispatch::Defer => need_resched = true,
                    }
                }
                Running::H => {
                    if !lock_held {
                        return Some(step);
                    }
                    // H spins. Strict priority, no aging: nothing else can be
                    // picked, so the state does not change. This is the hang.
                }
            }
        }
        None
    }

    #[test]
    fn deferring_the_tick_is_what_makes_the_system_terminate() {
        // Both directions are asserted, so the test cannot go vacuous if the
        // model drifts — one of the two would break.
        //
        // Preempting the lock holder: H is picked, spins on a lock only L can
        // release, and L is never picked again.
        fn always_switch(_depth: u32) -> TickDispatch { TickDispatch::Switch }
        assert_eq!(
            run_model(always_switch), None,
            "preempting the lock holder must NOT terminate — if this passes, \
             the model no longer reproduces K-C29 and proves nothing"
        );

        // The production decision: the tick is recorded and paid when L drops
        // its guard, so L finishes the critical section, releases the lock,
        // and the deferred reschedule hands the hart to H.
        let steps = run_model(preempt_core::tick_dispatch)
            .expect("with tick_dispatch the model must terminate");
        assert!(steps < BOUND);
    }

    // ── WaitQueue's internal lock (K-C29 applied to a second hand-rolled
    // spin) ──────────────────────────────────────────────────────────────
    //
    // `WaitQueue` used to protect its waiters array with a bare `AtomicBool`
    // plus `compare_exchange_weak` plus `core::hint::spin_loop()` — no
    // `PreemptGuard`, no `critical_section()`, nothing. That is the exact
    // defect `SpinLock` was fixed for, just never carried over to this
    // second, independent implementation. The fix routes `WaitQueue`'s
    // internal lock through `crate::spinlock::SpinLock` instead, so these
    // tests check the property at the instant that actually matters: is
    // `preempt::depth()` raised for the ENTIRE time the internal lock is
    // held, not merely before or after `lock_irqsave()` returns (a test that
    // only checked before/after would pass just as well against the old,
    // unguarded `AtomicBool` — the depth would simply stay 0 the whole time
    // and the assertion would never notice).

    #[test]
    fn waitqueue_internal_lock_disables_preemption_for_its_whole_hold() {
        let _g = guard();
        arm_callback();

        let wq = super::waitqueue::WaitQueue::new();
        assert_eq!(preempt::depth(), 0, "starts enabled");

        // Acquire exactly the way `wait()`/`wake_one()`/`wake_all()`/`len()`
        // do internally, and hold it open across the assertion — the
        // observation has to land DURING the hold, which is the window
        // where a same-hart tick could otherwise preempt the holder.
        let held = wq.inner.lock_irqsave();
        assert_eq!(
            preempt::depth(), 1,
            "WaitQueue's internal lock must hold a PreemptGuard for as long \
             as it is held — otherwise a tick landing right here could \
             preempt the holder, and a higher-priority task spinning on the \
             same lock on the same hart would never see it released"
        );
        drop(held);
        assert_eq!(preempt::depth(), 0, "preemption re-enabled once the lock is released");
    }

    /// `wait_if` does NOT enqueue when the predicate is already false.
    ///
    /// This is the lost wakeup, expressed as the only half a host test can
    /// reach. The race is: a waiter reads its condition as "still waiting",
    /// and a waker runs `store(true)` + `wake_all()` entirely before the
    /// waiter enqueues — so the wake finds an empty queue and the waiter
    /// sleeps forever with the condition already met. a one-shot completion
    /// flag had exactly that shape.
    ///
    /// `wait_if` re-checks under the queue's own lock, the one `wake_all`
    /// also takes, so the check and the enqueue are one critical section.
    /// Observable here as: predicate false at the lock -> the queue stays
    /// empty and this returns without blocking.
    ///
    /// **Canary.** Make `wait_if` ignore its predicate (enqueue
    /// unconditionally, i.e. behave like `wait`): `len()` becomes 1 and this
    /// goes red. Note that under the current callbacks it would also BLOCK,
    /// which is the failure in miniature.
    /// Give `waitqueue::caller_tid()` a real answer.
    ///
    /// It is `u32::MAX` in this harness until a per-CPU accessor is
    /// registered — and `wait`/`wait_if` treat that as "no scheduler
    /// running" and return via a spin fallback BEFORE touching the queue.
    ///
    /// **Without this, a test of `wait_if` passes without reaching it.** The
    /// first version of the test below did exactly that, and the companion
    /// test caught it by counting predicate calls: zero.
    fn with_a_current_tid<R>(f: impl FnOnce() -> R) -> R {
        as_tid(7, f)
    }

    #[test]
    fn wait_if_does_not_enqueue_when_the_condition_is_already_false() {
        let _g = guard();
        arm_callback();

        let wq = super::waitqueue::WaitQueue::new();
        with_a_current_tid(|| wq.wait_if(|| false));
        assert_eq!(wq.len(), 0, "a satisfied condition must not enqueue anyone");
        assert!(wq.is_empty());
        assert_eq!(preempt::depth(), 0, "the early return must drop the lock guard");
    }

    /// And the predicate is consulted exactly once, under the lock.
    ///
    /// Without this, `wait_if` could satisfy the test above by never calling
    /// the predicate at all in some path — which would make it `wait()` with
    /// extra steps for any caller whose condition starts true.
    #[test]
    fn wait_if_consults_its_predicate_under_the_lock() {
        use core::sync::atomic::{AtomicU32, Ordering};
        let _g = guard();
        arm_callback();

        static CALLS: AtomicU32 = AtomicU32::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let wq = super::waitqueue::WaitQueue::new();
        with_a_current_tid(|| wq.wait_if(|| {
            CALLS.fetch_add(1, Ordering::SeqCst);
            // Preemption is off for the whole hold, and the predicate runs
            // inside it — which is why its doc forbids anything that blocks.
            assert_eq!(preempt::depth(), 1, "the predicate must run UNDER the lock");
            false
        }));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "consulted exactly once");
    }

    #[test]
    fn waitqueue_wake_one_on_empty_queue_still_drops_the_guard() {
        // Companion to the test above: `wake_one()` returns `false` from
        // INSIDE the locked block on an empty queue. An early `return` still
        // has to run the guard's `Drop` — Rust guarantees this structurally,
        // but the property under test here is `WaitQueue`'s, not the
        // language's: a hand-rolled version of this same early-return path
        // could easily forget to unlock on the empty branch (the pre-fix
        // code had exactly this shape: an explicit `spin_unlock()` call
        // duplicated on every return path, one of them easy to miss).
        let _g = guard();
        arm_callback();

        let wq = super::waitqueue::WaitQueue::new();
        assert!(!wq.wake_one(), "empty queue: nothing to wake");
        assert_eq!(preempt::depth(), 0, "the early return must still drop the guard");
    }

    // ── WaitQueue: a wake must reach the sleeper it popped ──────────────
    //
    // The block layer lost a wake once (an OTA receive, 20-10) and its cause
    // was never found. These are the ways this file could drop one that a
    // host test can reach; each has a canary noted on it.

    /// `as_tid` without resetting the callbacks the test registered.
    fn as_task<R>(tid: u32, f: impl FnOnce() -> R) -> R {
        use core::sync::atomic::Ordering;
        let prev = TEST_TID.load(Ordering::SeqCst);
        TEST_TID.store(tid, Ordering::SeqCst);
        let r = f();
        TEST_TID.store(prev, Ordering::SeqCst);
        r
    }

    static WQ_STALE: super::waitqueue::WaitQueue = super::waitqueue::WaitQueue::new();
    static WOKEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    static BLOCKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    fn record_wake(tid: u32) {
        WOKEN.store(tid, core::sync::atomic::Ordering::SeqCst);
    }

    /// Task 8's block is where the waker runs (after 8 is listed, before it
    /// sleeps); every other task's block returns at once, as a block does
    /// when a stamp is pending or the scheduler refuses it.
    fn block_then_wake_one() {
        BLOCKS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        if test_tid() == 8 {
            WQ_STALE.wake_one();
        }
    }

    fn count_block() {
        BLOCKS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }

    /// A task whose block returned without a wake popping it (a stamp
    /// pending, a refused block) must not stay listed: a later `wake_one`
    /// would pop IT, deliver the wake to a task that is not asleep here, and
    /// leave the real sleeper asleep.
    ///
    /// **Canary.** Delete the removal in `WaitQueue::block_and_leave`: task 7
    /// stays listed, `wake_one` pops 7 first and `WOKEN` is 7, not 8.
    #[test]
    fn a_stale_entry_does_not_swallow_a_wake_meant_for_a_sleeper() {
        use core::sync::atomic::Ordering;
        let _g = guard();
        super::waitqueue::wq_set_callbacks(block_then_wake_one, record_wake, test_tid);
        WOKEN.store(0, Ordering::SeqCst);
        as_task(7, || WQ_STALE.wait_if(|| true));
        assert_eq!(WQ_STALE.len(), 0, "task 7's block returned unwoken: it must not stay listed");
        as_task(8, || WQ_STALE.wait_if(|| true));
        assert_eq!(WOKEN.load(Ordering::SeqCst), 8, "the wake went to the task that sleeps, not to a stale entry");
        assert_eq!(WQ_STALE.len(), 0);
    }

    /// A woken task is already off the list; leaving removes nothing else.
    #[test]
    fn leaving_the_list_removes_only_the_callers_own_entries() {
        use core::sync::atomic::Ordering;
        let _g = guard();
        super::waitqueue::wq_set_callbacks(count_block, record_wake, test_tid);
        let wq = super::waitqueue::WaitQueue::new();
        {
            // Two other sleepers listed around a stale entry of task 7.
            let mut inner = wq.inner.lock_irqsave();
            inner.waiters[0] = 21;
            inner.waiters[1] = 7;
            inner.waiters[2] = 22;
            inner.count = 3;
        }
        BLOCKS.store(0, Ordering::SeqCst);
        as_task(7, || wq.wait_if(|| true));
        assert_eq!(BLOCKS.load(Ordering::SeqCst), 1, "it blocked");
        let inner = wq.inner.lock_irqsave();
        // Task 7 was listed twice (a stale entry and the new one): both go.
        assert_eq!(&inner.waiters[..inner.count], &[21, 22], "only task 7's own entries leave, in order");
    }

    /// A full list used to be skipped by `wait()` and then blocked anyway:
    /// the 17th sleeper had no entry and no wake could reach it.
    ///
    /// **Canary.** Restore the old `wait()` (no `count >= CAPACITY` return):
    /// `BLOCKS` becomes 1.
    #[test]
    fn wait_on_a_full_list_does_not_block_without_an_entry() {
        use core::sync::atomic::Ordering;
        let _g = guard();
        super::waitqueue::wq_set_callbacks(count_block, record_wake, test_tid);
        let wq = super::waitqueue::WaitQueue::new();
        {
            let mut inner = wq.inner.lock_irqsave();
            for i in 0..16 {
                inner.waiters[i] = 100 + i as u32;
            }
            inner.count = 16;
        }
        BLOCKS.store(0, Ordering::SeqCst);
        as_task(7, || wq.wait());
        assert_eq!(BLOCKS.load(Ordering::SeqCst), 0, "no entry, so no block");
        assert_eq!(wq.len(), 16);
    }

    /// TID 0 is what a CPU with no current task answers; `idx_for_tid(0)`
    /// matches nothing, so a wake popped under it is dropped.
    ///
    /// **Canary.** Make `is_task` accept 0: the list gets an entry and the
    /// block runs.
    #[test]
    fn no_task_tid_neither_lists_nor_blocks() {
        use core::sync::atomic::Ordering;
        let _g = guard();
        super::waitqueue::wq_set_callbacks(count_block, record_wake, test_tid);
        let wq = super::waitqueue::WaitQueue::new();
        BLOCKS.store(0, Ordering::SeqCst);
        as_task(0, || {
            wq.wait_if(|| true);
            wq.wait();
        });
        assert_eq!(BLOCKS.load(Ordering::SeqCst), 0);
        assert_eq!(wq.len(), 0);
    }

    // ── WaitQueue::wait_if_for: a sleep with a deadline, and its evidence ──
    //
    // A sleep that ends at its deadline with nobody having popped the sleeper
    // is the signature of a wake that did not come; with the condition already
    // true by then it is a lost wake. A board boot reads the counters; these
    // tests pin what is counted and what is not.

    use super::waitqueue::Slept;
    use super::waitstat::{self, Site};
    use core::sync::atomic::AtomicU64;

    static WQ_TIMED: super::waitqueue::WaitQueue = super::waitqueue::WaitQueue::new();
    /// What the timed block does, and answers.
    static BLOCK_DOES: AtomicU32 = AtomicU32::new(0);
    static BLOCK_ANSWERS: AtomicU32 = AtomicU32::new(0);
    static BLOCK_SLICE_NS: AtomicU64 = AtomicU64::new(0);
    static COND_SLEEP: AtomicBool = AtomicBool::new(true);
    static TIMED_WOKEN: AtomicU32 = AtomicU32::new(0);
    static PLAIN_WOKEN: AtomicU32 = AtomicU32::new(0);

    const DOES_NOTHING: u32 = 0;
    /// The event happens while the task sleeps, and nobody wakes it.
    const DOES_EVENT: u32 = 1;
    /// A waker pops the sleeper (and its wake arrives, late).
    const DOES_WAKE: u32 = 2;

    fn timed_block(slice_ns: u64) -> Slept {
        BLOCK_SLICE_NS.store(slice_ns, Ordering::SeqCst);
        match BLOCK_DOES.load(Ordering::SeqCst) {
            DOES_EVENT => COND_SLEEP.store(false, Ordering::SeqCst),
            DOES_WAKE => {
                COND_SLEEP.store(false, Ordering::SeqCst);
                WQ_TIMED.wake_all();
            }
            _ => {}
        }
        match BLOCK_ANSWERS.load(Ordering::SeqCst) {
            0 => Slept::Woken,
            1 => Slept::Expired,
            _ => Slept::Refused,
        }
    }

    fn timed_wake(tid: u32) {
        TIMED_WOKEN.store(tid, Ordering::SeqCst);
    }

    fn plain_wake(tid: u32) {
        PLAIN_WOKEN.store(tid, Ordering::SeqCst);
    }

    /// Run one `wait_if_for` as task 9 on `WQ_TIMED` under `Site::Claim` and
    /// return how much `(expired, lost)` grew.
    fn timed_sleep(does: u32, answers: u32) -> (u64, u64) {
        super::waitqueue::wq_set_callbacks(count_block, plain_wake, test_tid);
        super::waitqueue::wq_set_timed_callbacks(timed_block, timed_wake);
        BLOCK_DOES.store(does, Ordering::SeqCst);
        BLOCK_ANSWERS.store(answers, Ordering::SeqCst);
        COND_SLEEP.store(true, Ordering::SeqCst);
        let (e0, l0) = waitstat::stats(Site::Claim);
        as_task(9, || WQ_TIMED.wait_if_for(Site::Claim, || COND_SLEEP.load(Ordering::SeqCst)));
        let (e1, l1) = waitstat::stats(Site::Claim);
        assert_eq!(WQ_TIMED.len(), 0, "the sleeper is off the list when it returns");
        (e1 - e0, l1 - l0)
    }

    /// The sleep is bounded by the slice, and a slice that ends with the event
    /// already true and no wake popped is a LOST wake.
    ///
    /// **Canary.** Delete the `waitstat::note_expiry` call in `wait_if_for`
    /// (or drop `lost` from it): `(1, 1)` reads `(0, 0)` / `(1, 0)`.
    #[test]
    fn a_slice_that_ends_with_the_event_true_and_no_wake_is_lost() {
        let _g = guard();
        assert_eq!(timed_sleep(DOES_EVENT, 1), (1, 1));
        assert_eq!(BLOCK_SLICE_NS.load(Ordering::SeqCst), waitstat::SLICE_NS, "bounded by the slice, not longer");
    }

    /// A slice that ends with the event still to come is an expiry, not a
    /// loss: a long wait for a slow event ends this way again and again.
    #[test]
    fn a_slice_that_ends_with_the_event_pending_is_expired_not_lost() {
        let _g = guard();
        assert_eq!(timed_sleep(DOES_NOTHING, 1), (1, 0));
    }

    /// A sleeper that came back before its deadline was woken (or consumed a
    /// pending wake): nothing to count.
    #[test]
    fn a_sleeper_woken_before_its_deadline_is_not_counted() {
        let _g = guard();
        assert_eq!(timed_sleep(DOES_EVENT, 0), (0, 0));
    }

    /// A sleeper a waker already popped was sent its wake; it is only late. It
    /// is not a drop, and the wake went through the TIMED callback (the
    /// sleeper is blocked on a timer, which the plain wake does not reach).
    ///
    /// **Canary.** Count regardless of `listed`: `(1, 1)`. Route a timed
    /// entry through `WQ_WAKE_FN`: `PLAIN_WOKEN` is 9 and `TIMED_WOKEN` 0.
    #[test]
    fn a_popped_sleeper_is_not_a_dropped_wake_and_is_woken_by_the_timed_callback() {
        let _g = guard();
        TIMED_WOKEN.store(0, Ordering::SeqCst);
        PLAIN_WOKEN.store(0, Ordering::SeqCst);
        assert_eq!(timed_sleep(DOES_WAKE, 1), (0, 0));
        assert_eq!(TIMED_WOKEN.load(Ordering::SeqCst), 9);
        assert_eq!(PLAIN_WOKEN.load(Ordering::SeqCst), 0);
    }

    /// A block the scheduler refused (a critical section is open) slept for
    /// nothing: not an expiry.
    #[test]
    fn a_refused_block_is_not_counted() {
        let _g = guard();
        assert_eq!(timed_sleep(DOES_EVENT, 2), (0, 0));
    }

    /// The condition is re-checked once the sleeper is listed: an event that
    /// came first means no block at all.
    #[test]
    fn wait_if_for_does_not_block_when_the_condition_is_already_false() {
        let _g = guard();
        super::waitqueue::wq_set_callbacks(count_block, plain_wake, test_tid);
        super::waitqueue::wq_set_timed_callbacks(timed_block, timed_wake);
        BLOCK_SLICE_NS.store(0, Ordering::SeqCst);
        as_task(9, || WQ_TIMED.wait_if_for(Site::Claim, || false));
        assert_eq!(BLOCK_SLICE_NS.load(Ordering::SeqCst), 0, "no block");
        assert_eq!(WQ_TIMED.len(), 0);
    }

    /// Before the timed callbacks exist (early boot, a host shim) it is
    /// `wait_if`: the plain block runs and the entry is plain.
    #[test]
    fn without_timed_callbacks_wait_if_for_is_wait_if() {
        let _g = guard();
        super::waitqueue::wq_set_callbacks(count_block, plain_wake, test_tid);
        super::waitqueue::wq_clear_timed_callbacks();
        BLOCKS.store(0, Ordering::SeqCst);
        as_task(9, || WQ_TIMED.wait_if_for(Site::Claim, || true));
        assert_eq!(BLOCKS.load(Ordering::SeqCst), 1);
        assert_eq!(WQ_TIMED.len(), 0);
    }

    /// The counters are named for the introspection tree: one name per site,
    /// in `Site::ALL` order, each a valid node name.
    #[test]
    fn every_site_has_its_own_node_name() {
        let mut names: Vec<&str> = Site::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(names.len(), waitstat::SITES);
        for (i, s) in Site::ALL.iter().enumerate() {
            assert_eq!(*s as usize, i, "ALL is in counter order");
            assert!(!s.name().is_empty() && !s.name().contains('/'));
        }
        names.sort();
        names.dedup();
        assert_eq!(names.len(), waitstat::SITES, "no name twice");
    }

    // ── Mutex held count (RT7: the panic policy's check 4) ──────────────

    /// The identity `as_tid` hands the accessor (`u32::MAX`: none).
    static TEST_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

    fn test_tid() -> u32 {
        TEST_TID.load(core::sync::atomic::Ordering::SeqCst)
    }

    fn no_block() {}
    fn no_wake(_tid: u32) {}

    /// Run `f` as task `tid`: the per-CPU accessor `waitqueue::caller_tid`
    /// reads answers `tid` for the length of `f`.
    fn as_tid<R>(tid: u32, f: impl FnOnce() -> R) -> R {
        use core::sync::atomic::Ordering;
        super::waitqueue::wq_set_callbacks(no_block, no_wake, test_tid);
        let prev = TEST_TID.load(Ordering::SeqCst);
        TEST_TID.store(tid, Ordering::SeqCst);
        let r = f();
        TEST_TID.store(prev, Ordering::SeqCst);
        r
    }

    /// Every acquisition counts until its guard drops: nested `lock`s, a
    /// `try_lock`, and back to zero. A refused `try_lock` counts nothing.
    #[test]
    fn held_count_tracks_every_acquisition_until_release() {
        use super::held::held_by;
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let a = Mutex::new(1u32);
        let b = Mutex::new(2u32);
        let c = Mutex::new(3u32);
        as_tid(41, || {
            assert_eq!(held_by(41), 0);
            let ga = a.lock();
            assert_eq!(held_by(41), 1, "lock() counts");
            {
                let _gb = b.lock();
                assert_eq!(held_by(41), 2, "a nested lock() counts");
                let gc = c.try_lock().expect("c is free");
                assert_eq!(held_by(41), 3, "try_lock() counts");
                assert!(c.try_lock().is_none(), "c is held");
                assert_eq!(held_by(41), 3, "a refused try_lock() counts nothing");
                drop(gc);
                assert_eq!(held_by(41), 2);
            }
            assert_eq!(held_by(41), 1);
            drop(ga);
            assert_eq!(held_by(41), 0, "every release balances its acquisition");
        });
    }

    /// N7d: a task that exits holding Mutexes leaves the held table: the
    /// exit path's `held_forget` drops all its entries, and only its own.
    #[test]
    fn held_forget_drops_a_dead_holder_only() {
        use super::held::{held_by, held_forget};
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let a = Mutex::new(1u32);
        let b = Mutex::new(2u32);
        let c = Mutex::new(3u32);
        as_tid(43, || {
            a.lock().leak();
            b.lock().leak();
        });
        let gc = as_tid(44, || c.lock());
        assert_eq!(held_by(43), 2, "the dead holder's count");
        held_forget(43);
        assert_eq!(held_by(43), 0, "a dead holder still counted in the held table");
        assert_eq!(held_by(44), 1, "held_forget dropped another task's entry");
        as_tid(44, || drop(gc));
        assert_eq!(held_by(44), 0);
    }

    /// The release lowers the slot of the TID that ACQUIRED (the owner word
    /// names it), even when a different task is current at release time.
    #[test]
    fn held_count_is_lowered_for_the_owner_not_the_releaser() {
        use super::held::held_by;
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let a = Mutex::new(0u32);
        let ga = as_tid(42, || a.lock());
        assert_eq!(held_by(42), 1);
        as_tid(43, || drop(ga));
        assert_eq!(held_by(42), 0, "the owner's slot is the one lowered");
        assert_eq!(held_by(43), 0, "the releaser's slot is untouched");
    }

    /// The table is keyed by the exact TID (wave 13): a TID whose home entry
    /// is another task's reads as holding nothing, and both count their own.
    /// Before wave 13 (`count[tid % 64]`) `held_by(44 + 64)` read 1 here.
    #[test]
    fn held_count_is_exact_per_tid() {
        use super::held::held_by;
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let a = Mutex::new(0u32);
        let b = Mutex::new(0u32);
        let ga = as_tid(44, || a.lock());
        assert_eq!(held_by(44 + 64), 0, "a TID sharing the home entry holds nothing");
        assert_eq!(held_by(44), 1);
        let gb = as_tid(44 + 64, || b.lock());
        assert_eq!(held_by(44 + 64), 1, "the colliding TID probes to an entry of its own");
        assert_eq!(held_by(44), 1, "and leaves the first one's count alone");
        drop(ga);
        assert_eq!(held_by(44), 0);
        assert_eq!(held_by(44 + 64), 1);
        drop(gb);
        assert_eq!(held_by(44 + 64), 0);
    }

    /// A task can own two entries: its second lock probed past a home entry
    /// that was taken, and a third lock re-claims that home entry once it is
    /// freed. The sum stays exact and every release finds an entry.
    #[test]
    fn held_count_sums_a_task_spread_over_two_entries() {
        use super::held::held_by;
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let (l1, l2, l3) = (Mutex::new(0u32), Mutex::new(0u32), Mutex::new(0u32));
        let (a, b) = (45u32, 45u32 + 64);
        let g1 = as_tid(a, || l1.lock());          // a: home entry
        let g2 = as_tid(b, || l2.lock());          // b: the next one
        drop(g1);                                  // home entry free again
        let g3 = as_tid(b, || l3.lock());          // b: claims the home entry
        assert_eq!(held_by(a), 0);
        assert_eq!(held_by(b), 2, "both of b's entries count");
        drop(g2);
        assert_eq!(held_by(b), 1);
        drop(g3);
        assert_eq!(held_by(b), 0, "every release found one of b's entries");
    }

    /// A full first level: the acquisition that finds no entry spills into
    /// the second level, still keyed by TID, so it reads as that task's own
    /// and nobody else's, and its release balances it.
    ///
    /// **Canary.** Count the spill in `overflow` (skip `slots_raise(&self.spill)`
    /// in `raise`): `held_by(7)` reads 1, red.
    #[test]
    fn held_count_first_level_overflow_is_per_tid() {
        use super::held::held_by;
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let locks: Vec<Mutex<u32>> = (0..65).map(Mutex::new).collect();
        let held: Vec<_> = (0..64u32).map(|i| as_tid(1000 + i, || locks[i as usize].lock())).collect();
        assert_eq!(held_by(7), 0, "a full table alone is no over-count");
        let extra = as_tid(5000, || locks[64].lock());
        assert_eq!(held_by(5000), 1, "the spilled holder still reads as holding");
        assert_eq!(held_by(7), 0, "a spill is the holder's own count, not everyone's");
        drop(extra);
        assert_eq!(held_by(5000), 0);
        drop(held);
        assert_eq!(held_by(1000), 0);
        assert_eq!(held_by(1063), 0);
    }

    /// Both levels full: the acquisition that finds no entry is counted for
    /// EVERY TID (an over-count: the reset path), and its release balances it.
    #[test]
    fn held_count_overflow_only_overcounts() {
        use super::held::held_by;
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let locks: Vec<Mutex<u32>> = (0..64 + 16 + 1).map(Mutex::new).collect();
        let held: Vec<_> = (0..64 + 16u32).map(|i| as_tid(1000 + i, || locks[i as usize].lock())).collect();
        assert_eq!(held_by(7), 0, "two full levels alone are no over-count");
        let extra = as_tid(5000, || locks[80].lock());
        assert_eq!(held_by(5000), 1, "the overflowed holder still reads as holding");
        assert_eq!(held_by(7), 1, "and so does everyone else: over-count only");
        drop(extra);
        assert_eq!(held_by(5000), 0);
        assert_eq!(held_by(7), 0, "the release took the overflow back");
        drop(held);
        assert_eq!(held_by(1000), 0);
        assert_eq!(held_by(1079), 0);
    }

    /// A holder whose acquisitions overflowed the first level dies holding
    /// them (`forget`, the scheduler's exit path): it must read as holding
    /// nothing. Before the second level `forget` left them in the global
    /// `overflow` counter, and a dead holder looked alive for every TID
    /// (ktest `kmutex_dead_holder_leaves_the_held_table`).
    ///
    /// **Canary.** Chain `self.spill` out of the iterator in `forget`:
    /// `held_by(5000)` stays at 3, red. Count a spill in `overflow` instead
    /// (see the test above): `held_by(7)` is 3 after the forget, red.
    #[test]
    fn held_count_a_forgotten_overflowed_holder_holds_nothing() {
        use super::held::{held_by, held_forget};
        use super::kmutex::Mutex;
        let _g = guard();
        let _held = crate::held_table_lock();
        let locks: Vec<Mutex<u32>> = (0..67).map(Mutex::new).collect();
        let held: Vec<_> = (0..64u32).map(|i| as_tid(1000 + i, || locks[i as usize].lock())).collect();
        let dead: Vec<_> = (64..67usize).map(|i| as_tid(5000, || locks[i].lock())).collect();
        assert_eq!(held_by(5000), 3, "the three overflowed acquisitions count");
        // The task dies with its guards still out, as a panicking holder does.
        for g in dead { core::mem::forget(g); }
        held_forget(5000);
        assert_eq!(held_by(5000), 0, "a dead holder still reads as holding: forget kept its overflow");
        assert_eq!(held_by(7), 0, "and so does everyone else");
        drop(held);
        assert_eq!(held_by(1000), 0);
    }
}

// ── SpinWait + SpinLock over it (wave 15, N2) ───────────────────────────────
//
// The shim's `SpinWait` is the trait's provided bodies: the fallback every
// ISA keeps (`compare_exchange`, `spin_loop`). These run the SpinLock's
// real source over it, threads standing in for harts.
#[cfg(test)]
mod spin_tests {
    use crate::spinlock::SpinLock;
    use azos_arch::{CasOrder, SpinWait as _, ARCH};
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn cas_and_wait_while_contract() {
        let w = AtomicU32::new(0xFFFF_FFFF);
        assert_eq!(ARCH.cas32(&w, 0xFFFF_FFFF, 0x8000_0000, CasOrder::Acquire), Ok(0xFFFF_FFFF));
        assert_eq!(ARCH.cas32(&w, 0xFFFF_FFFF, 1, CasOrder::AcqRel), Err(0x8000_0000));
        let d = AtomicU64::new(0xFFFF_FFFF_0000_0001);
        assert!(ARCH.cas64(&d, 1, 2, CasOrder::Release).is_err(), "cas64 compared the low half only");
        assert_eq!(ARCH.swap32(&AtomicU32::new(3), 4, CasOrder::Acquire), 3);
        assert_eq!(ARCH.wait_while32(&w, 0), 0x8000_0000);
        // A second thread changes the word; the waiter returns the new value.
        let flag = Arc::new(AtomicU32::new(7));
        let f2 = flag.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            f2.store(8, Ordering::Release);
        });
        assert_eq!(ARCH.wait_while32(&flag, 7), 8);
        t.join().unwrap();
    }

    #[test]
    fn spinlock_excludes_across_threads() {
        // The preemption slots are process-global: serialise with the
        // `tests` module, which resets and asserts on them.
        let _g = crate::tests::guard();
        static L: SpinLock<u64> = SpinLock::new(0);
        const ROUNDS: u64 = 50_000;
        let ts: Vec<_> = (1..=4)
            .map(|h| {
                std::thread::spawn(move || {
                    azos_arch::set_hart(h);
                    for _ in 0..ROUNDS {
                        let mut g = L.lock();
                        let v = *g;
                        std::hint::black_box(());
                        *g = v + 1;
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(*L.lock(), 4 * ROUNDS, "an increment was lost under the SpinLock");
        assert!(L.try_lock().is_some(), "the lock stayed held");
    }

    /// N3: after contention under the queued lock no CPU still holds a node
    /// (the waiter frees its own on acquire).
    #[test]
    fn qspinlock_nodes_freed_after_contention() {
        let _g = crate::tests::guard();
        if !crate::qspinlock::ON {
            return;
        }
        static L: SpinLock<u64> = SpinLock::new(0);
        let ts: Vec<_> = (1..=4)
            .map(|h| std::thread::spawn(move || {
                azos_arch::set_hart(h);
                for _ in 0..20_000 {
                    *L.lock() += 1;
                }
            }))
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(*L.lock(), 80_000);
        for h in 1..=4 {
            assert_eq!(crate::qspinlock::depth(h), 0, "CPU {h} still holds a queue node");
        }
    }

    /// N3: a fast path that lands on a free word with a pending waiter gives
    /// the lock back and waits its turn: the pending waiter goes first. A
    /// trylock never takes a word with a waiter on it.
    #[test]
    fn qspinlock_give_back_keeps_fifo() {
        use crate::qspinlock::{try_acquire, LOCKED, PENDING};
        let _g = crate::tests::guard();
        let w = Arc::new(AtomicU32::new(PENDING));
        assert!(!try_acquire(&w), "a trylock passed a pending waiter");
        let order = Arc::new(AtomicU32::new(0));
        let (w2, o2) = (w.clone(), order.clone());
        // The pending waiter: takes the lock once `locked` is clear.
        let p = std::thread::spawn(move || {
            azos_arch::set_hart(2);
            std::thread::sleep(std::time::Duration::from_millis(30));
            loop {
                let v = w2.load(Ordering::Relaxed);
                if v & 0xff == 0 && w2.compare_exchange(v, (v & !PENDING) | LOCKED, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    break;
                }
                std::hint::spin_loop();
            }
            o2.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Relaxed).ok();
            std::thread::sleep(std::time::Duration::from_millis(10));
            ARCH.unlock_low_byte32(&w2);
        });
        azos_arch::set_hart(1);
        ARCH.qlock_acquire32(&w);
        order.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).ok();
        ARCH.unlock_low_byte32(&w);
        p.join().unwrap();
        assert_eq!(order.load(Ordering::Acquire), 2, "the fast path kept a lock a pending waiter was owed");
        assert_eq!(w.load(Ordering::Relaxed), 0, "the queue tail or pending bit was left set");
        assert_eq!(crate::qspinlock::depth(1), 0);
    }
}

/// Rule F1: a claim keeps a resource across a device wait without holding a
/// `Mutex` (host: no scheduler, so a contender spins instead of sleeping; the
/// exchange, the count and the exclusion are the kernel's own code).
#[cfg(test)]
mod claim_tests {
    use super::{claim, held};
    use claim::Claim;

    /// The boot identity both tables key the host's only "task" by.
    const ME: u32 = u32::MAX;

    #[test]
    fn owner_counts_for_panic_and_not_as_a_held_mutex() {
        let _held = crate::held_table_lock();
        static C: Claim<u32> = Claim::new(0);
        assert_eq!(claim::held_by(ME), 0);
        let mut g = C.acquire();
        *g += 1;
        assert_eq!(claim::held_by(ME), 1, "the owner is counted for the panic path");
        assert_eq!(held::held_by(ME), 0, "F1: the owner holds no Mutex across its work");
        drop(g);
        assert_eq!(claim::held_by(ME), 0, "a release balances the acquisition");
        assert_eq!(*C.acquire(), 1);
        claim::held_forget(ME);
    }

    #[test]
    fn exchange_mutex_is_free_while_the_claim_is_owned() {
        let _held = crate::held_table_lock();
        static C: Claim<u32> = Claim::new(0);
        let g = C.acquire();
        // The claim's address is its exchange mutex's: free, so a canary
        // that holds it is visible as a `Mutex` held.
        // SAFETY: `repr(C)`, the mutex is the first field.
        let m = unsafe { &*(&C as *const Claim<u32> as *const super::kmutex::Mutex<()>) };
        assert!(!m.is_locked(), "the exchange mutex stayed held by the owner");
        drop(g);
        claim::held_forget(ME);
    }

    #[test]
    fn exclusion_across_threads() {
        let _held = crate::held_table_lock();
        static C: Claim<u64> = Claim::new(0);
        const ROUNDS: u64 = 2_000;
        let ts: Vec<_> = (0..4)
            .map(|_| std::thread::spawn(|| {
                for _ in 0..ROUNDS {
                    let mut g = C.acquire();
                    // A read-modify-write with a yield in the middle: lost
                    // updates show if two threads own the claim at once.
                    let v = *g;
                    std::thread::yield_now();
                    *g = v + 1;
                }
            }))
            .collect();
        for t in ts { t.join().unwrap(); }
        assert_eq!(*C.acquire(), 4 * ROUNDS, "two owners at once lost an update");
        claim::held_forget(ME);
    }

    /// `try_acquire` refuses an owned claim at once, without waiting, and
    /// takes a free one as `acquire` does (counted for the panic path).
    #[test]
    fn try_acquire_refuses_an_owned_claim_and_takes_a_free_one() {
        let _held = crate::held_table_lock();
        static C: Claim<u32> = Claim::new(0);
        let g = C.acquire();
        let t = std::thread::spawn(|| C.try_acquire().is_none());
        assert!(t.join().unwrap(), "try_acquire took a claim that was owned");
        drop(g);
        let mut g = C.try_acquire().expect("try_acquire refused a free claim");
        *g += 1;
        assert_eq!(claim::held_by(ME), 1, "a try_acquire owner is counted for the panic path");
        assert!(C.try_acquire().is_none(), "a second owner while the first holds it");
        drop(g);
        assert_eq!(claim::held_by(ME), 0);
        assert_eq!(*C.acquire(), 1);
        claim::held_forget(ME);
    }

    #[test]
    fn contender_gets_the_claim_after_the_owner_gives_it_back() {
        use core::sync::atomic::{AtomicBool, Ordering};
        let _held = crate::held_table_lock();
        static C: Claim<()> = Claim::new(());
        static GOT: AtomicBool = AtomicBool::new(false);
        let g = C.acquire();
        let t = std::thread::spawn(|| {
            let _g = C.acquire();
            GOT.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!GOT.load(Ordering::SeqCst), "a contender took a claim that was owned");
        drop(g);
        t.join().unwrap();
        assert!(GOT.load(Ordering::SeqCst));
        claim::held_forget(ME);
    }

    /// Owner decision 10-10: an owner that exits leaves the table (the exit
    /// path's `claim::held_forget`), only its own entries; `0` is no task.
    #[test]
    fn held_forget_drops_a_dead_owner() {
        let _held = crate::held_table_lock();
        static C: Claim<()> = Claim::new(());
        core::mem::forget(C.acquire());
        assert_eq!(claim::held_by(ME), 1);
        claim::held_forget(0);
        assert_eq!(claim::held_by(ME), 1, "tid 0 forgot a real entry");
        claim::held_forget(ME);
        assert_eq!(claim::held_by(ME), 0, "a dead owner is still counted in the claim table");
    }
}
