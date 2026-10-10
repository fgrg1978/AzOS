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
#[path = "../../../../crates/core/sync/src/preempt_core.rs"]
pub mod preempt_core;

#[path = "../../../../crates/core/sync/src/preempt.rs"]
pub mod preempt;

// K-C29 fix applied to `WaitQueue`'s hand-rolled internal spin (see that
// file's module doc). Pulled in via `#[path]` for the same reason as
// `preempt`/`preempt_core` above: the guard, the `SpinLock`/`IrqSaveGuard`
// Drop ordering, and `WaitQueue`'s routing through them are the kernel's own
// code, not a copy that could drift from it. `spinlock.rs` needs
// `azos_arch::csr::{read_sstatus, write_sstatus}`, which is why this
// crate's arch shim grew `write_sstatus` alongside these modules.
// `waitqueue.rs` names `crate::pi_mutex::CURRENT_TID`, so `pi_mutex` comes
// along too even though nothing here tests PI directly.
#[path = "../../../../crates/core/sync/src/spinlock.rs"]
pub mod spinlock;

// The queued SpinLock's slow half (wave 15, N3), which `spinlock.rs` calls
// and which defines `azos_spin_mcs_slow32` for the trait's portable fast
// path.
#[path = "../../../../crates/core/sync/src/qspinlock.rs"]
pub mod qspinlock;

#[path = "../../../../crates/core/sync/src/pi_mutex.rs"]
pub mod pi_mutex;

#[path = "../../../../crates/core/sync/src/waitqueue.rs"]
pub mod waitqueue;

#[path = "../../../../crates/core/sync/src/sleep_lock.rs"]
pub mod sleep_lock;

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
        assert_ne!(k(Kind::Spin), k(Kind::PiMutex));
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
        let w = Held { kind: Kind::PiMutex, key: class_key("w", 1, 1, 2), ..a };
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
        assert!(!s.pop(1, Kind::PiMutex), "same address, other kind: not this lock");
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
        contended(&c, 1, Kind::PiMutex, 1 << 31 | 2);
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
        let (a, b) = (class(Kind::Spin), class(Kind::PiMutex));
        let (ia, ib) = (t.slot(&held(&a, 1)), t.slot(&Held { kind: Kind::PiMutex, ..held(&b, 2) }));
        // Site words are `&'static Location`s (printed by `HoldLine`).
        let site = Location::caller() as *const Location<'static> as usize;
        t.hold(ia, 10, 1, site);
        t.hold(ia, 500, 50, site);
        t.hold(ib, 90, 9, site);
        let ca = t.get(ia as usize).unwrap();
        assert_eq!((ca.holds, ca.max_ticks), (2, 500));
        assert_eq!(ca.hist[1] + ca.hist[6], 2);
        assert_eq!(t.get(ib as usize).unwrap().kind, Kind::PiMutex);
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
        r.what = What::RtCrossCpu;
        r.taken = Held { kind: Kind::PiMutex, ..h };
        r.value = 1;
        r.value2 = 2;
        let line = format!("{}", r);
        assert!(line.contains("RT task on CPU 1") && line.contains("one on CPU 2"), "{line}");
    }
}

/// Wave 15 (PI), owner rule F1: a sleeping lock (or claim) a task holds is
/// counted for the panic path, and NOT as a held `PiMutex` (the `lat-fat`
/// smoke's F1 probe reads `pi_mutex::held_by`: a `SleepLock` held across a
/// device wait is the allowed shape).
#[cfg(test)]
mod sleep_lock_tests {
    use super::{pi_mutex, sleep_lock};

    #[test]
    fn sleep_holds_count_for_panic_not_as_pi() {
        let tid = 0x5eed;
        assert_eq!(sleep_lock::held_by(tid), 0);
        sleep_lock::note_acquired(tid);
        sleep_lock::note_acquired(tid);
        assert_eq!(sleep_lock::held_by(tid), 2);
        assert_eq!(pi_mutex::held_by(tid), 0);
        sleep_lock::note_released(tid);
        sleep_lock::note_released(tid);
        assert_eq!(sleep_lock::held_by(tid), 0);
    }

    #[test]
    fn sleep_lock_excludes_and_releases() {
        static L: sleep_lock::SleepLock<u32> = sleep_lock::SleepLock::new(0);
        {
            let mut g = L.lock();
            *g += 1;
        }
        // Released: a second take does not wait.
        assert_eq!(*L.lock(), 1);
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
        // `csr::read_sstatus()`) BEFORE it reads `need_resched` — both AFTER
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
        // Fires when `drop`'s FIRST read of `csr::read_sstatus()` happens —
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
    /// sleeps forever with the condition already met. `Completion::wait` had
    /// exactly that shape.
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
    /// Give `waitqueue`'s `current_task_tid()` a real answer.
    ///
    /// It reads `pi_mutex::CURRENT_TID`, which is `NO_OWNER` (`u32::MAX`) in
    /// this harness — and `wait`/`wait_if` treat that as "no scheduler
    /// running" and return via a spin fallback BEFORE touching the queue.
    ///
    /// **Without this, a test of `wait_if` passes without reaching it.** The
    /// first version of the test below did exactly that, and the companion
    /// test caught it by counting predicate calls: zero.
    fn with_a_current_tid<R>(f: impl FnOnce() -> R) -> R {
        use core::sync::atomic::Ordering;
        let prev = super::pi_mutex::CURRENT_TID.load(Ordering::SeqCst);
        super::pi_mutex::CURRENT_TID.store(7, Ordering::SeqCst);
        let r = f();
        super::pi_mutex::CURRENT_TID.store(prev, Ordering::SeqCst);
        r
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

    // ── PiMutex held count (RT7: the panic policy's check 4) ────────────

    /// Run `f` as task `tid` (the pre-registration identity `pi_mutex` reads).
    fn as_tid<R>(tid: u32, f: impl FnOnce() -> R) -> R {
        use core::sync::atomic::Ordering;
        let prev = super::pi_mutex::CURRENT_TID.load(Ordering::SeqCst);
        super::pi_mutex::CURRENT_TID.store(tid, Ordering::SeqCst);
        let r = f();
        super::pi_mutex::CURRENT_TID.store(prev, Ordering::SeqCst);
        r
    }

    /// Every acquisition counts until its guard drops: nested `lock`s, a
    /// `try_lock`, and back to zero. A refused `try_lock` counts nothing.
    #[test]
    fn pi_held_count_tracks_every_acquisition_until_release() {
        use super::pi_mutex::{held_by, PiMutex};
        let _g = guard();
        let a = PiMutex::new(1u32);
        let b = PiMutex::new(2u32);
        let c = PiMutex::new(3u32);
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

    /// The release lowers the slot of the TID that ACQUIRED, even when a
    /// different task is current at release time (the guard dropped after a
    /// switch would read another identity).
    #[test]
    fn pi_held_count_is_lowered_for_the_owner_not_the_releaser() {
        use super::pi_mutex::{held_by, PiMutex};
        let _g = guard();
        let a = PiMutex::new(0u32);
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
    fn pi_held_count_is_exact_per_tid() {
        use super::pi_mutex::{held_by, PiMutex};
        let _g = guard();
        let a = PiMutex::new(0u32);
        let b = PiMutex::new(0u32);
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
    fn pi_held_count_sums_a_task_spread_over_two_entries() {
        use super::pi_mutex::{held_by, PiMutex};
        let _g = guard();
        let (l1, l2, l3) = (PiMutex::new(0u32), PiMutex::new(0u32), PiMutex::new(0u32));
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

    /// A full table: the acquisition that finds no entry is counted for EVERY
    /// TID (an over-count: the reset path), and its release balances it.
    #[test]
    fn pi_held_count_overflow_only_overcounts() {
        use super::pi_mutex::{held_by, PiMutex};
        let _g = guard();
        let locks: Vec<PiMutex<u32>> = (0..65).map(PiMutex::new).collect();
        let held: Vec<_> = (0..64u32).map(|i| as_tid(1000 + i, || locks[i as usize].lock())).collect();
        assert_eq!(held_by(7), 0, "a full table alone is no over-count");
        let extra = as_tid(5000, || locks[64].lock());
        assert_eq!(held_by(5000), 1, "the overflowed holder still reads as holding");
        assert_eq!(held_by(7), 1, "and so does everyone else: over-count only");
        drop(extra);
        assert_eq!(held_by(5000), 0);
        assert_eq!(held_by(7), 0, "the release took the overflow back");
        drop(held);
        assert_eq!(held_by(1000), 0);
        assert_eq!(held_by(1063), 0);
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
