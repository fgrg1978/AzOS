// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! How long interrupts stay masked with an input a user sizes: a storm of
//! sleepers due at one instant on one CPU, and the wait graph at the size of
//! the largest task table (`MAX_TASKS` 4096, the server profile). The numbers
//! mean instructions only under `-icount shift=0` (the `ktest hold bound`
//! rows): 1 ns of the printed time is one instruction there.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use azos_sched::WaitReason;

fn ticks_to_ns(t: u64) -> u64 {
    t.saturating_mul(1_000_000_000) / azos_drv_sys::timebase::TIMER_FREQ
}

static STORM_AT: AtomicU64 = AtomicU64::new(0);
static STORM_READY: AtomicUsize = AtomicUsize::new(0);
static STORM_WOKEN: AtomicUsize = AtomicUsize::new(0);
static URGENT_WOKEN: AtomicUsize = AtomicUsize::new(0);
static STORM_LATE: AtomicBool = AtomicBool::new(false);
const URGENT: usize = 2;
/// Which slots hold a fair sleeper of the storm, and which an urgent one.
static FAIR_SLOT: [AtomicBool; azos_limits::MAX_TASKS] = [const { AtomicBool::new(false) }; azos_limits::MAX_TASKS];
static URGENT_SLOT: [AtomicBool; azos_limits::MAX_TASKS] = [const { AtomicBool::new(false) }; azos_limits::MAX_TASKS];

fn slot() -> usize {
    azos_sched::current_task_slot().map_or(0, |(i, _)| i)
}

/// The first and the last place in the wake order of the sleepers `flags` marks.
fn wake_places(flags: &[AtomicBool]) -> (u32, u32) {
    let mut places = (0..flags.len()).filter(|&i| flags[i].load(Ordering::Acquire)).map(azos_sched::ktest_wake_order);
    let first = places.next().unwrap_or(0);
    places.fold((first, first), |(lo, hi), p| (lo.min(p), hi.max(p)))
}

/// A sleeper that arms after the instant (a stalled host) is not due with the others.
fn block_until(at: u64) {
    if azos_drv_sys::timebase::now() >= at {
        STORM_LATE.store(true, Ordering::Release);
    }
    azos_sched::task_block(WaitReason::Timer(at));
}

fn storm_sleeper(_: usize) {
    FAIR_SLOT[slot()].store(true, Ordering::Release);
    STORM_READY.fetch_add(1, Ordering::AcqRel);
    let mut at = STORM_AT.load(Ordering::Acquire);
    while at == 0 {
        azos_sched::task_yield();
        at = STORM_AT.load(Ordering::Acquire);
    }
    block_until(at);
    STORM_WOKEN.fetch_add(1, Ordering::AcqRel);
}

/// A sleeper of the real-time band, due at the storm's instant like the rest.
fn urgent_sleeper(_: usize) {
    URGENT_SLOT[slot()].store(true, Ordering::Release);
    STORM_READY.fetch_add(1, Ordering::AcqRel);
    let mut at = STORM_AT.load(Ordering::Acquire);
    while at == 0 {
        // Sleeps instead of yielding: nothing below its band runs on a yield.
        azos_sched::task_block(WaitReason::Timer(azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 1000));
        at = STORM_AT.load(Ordering::Acquire);
    }
    block_until(at);
    URGENT_WOKEN.fetch_add(1, Ordering::AcqRel);
}

/// One storm of `k` sleepers pinned to this CPU, due at one instant: its
/// longest timer pass in timer counts, and the most sleepers a pass popped.
fn storm(k: usize) -> Result<(u64, usize), &'static str> {
    let cpu = azos_sched::smp::current_cpu_id() as i8;
    STORM_AT.store(0, Ordering::Release);
    STORM_READY.store(0, Ordering::Release);
    STORM_WOKEN.store(0, Ordering::Release);
    URGENT_WOKEN.store(0, Ordering::Release);
    STORM_LATE.store(false, Ordering::Release);
    for (f, u) in FAIR_SLOT.iter().zip(&URGENT_SLOT) {
        f.store(false, Ordering::Release);
        u.store(false, Ordering::Release);
    }
    for _ in 0..k {
        if azos_sched::try_task_create_affinity("irqoff-storm", storm_sleeper, 0, azos_sched::DEFAULT_PRIORITY, cpu).is_none() {
            return Err("no free task slot for a sleeper");
        }
    }
    // Last: the highest slots, so a pop by slot index puts them behind the storm.
    for _ in 0..URGENT {
        if azos_sched::try_task_create_affinity("irqoff-urgent", urgent_sleeper, 0, azos_sched::RT_PRIORITY_THRESHOLD - 2, cpu).is_none() {
            return Err("no free task slot for an urgent sleeper");
        }
    }
    crate::ktest::wait("the sleepers did not start", || STORM_READY.load(Ordering::Acquire) == k + URGENT)?;
    let _ = azos_sched::ktest_take_tick_pass_max();
    azos_sched::ktest_wake_order_reset();
    // Far enough for every sleeper to commit its block first, on any host.
    let at = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 5;
    STORM_AT.store(at, Ordering::Release);
    crate::ktest::wait("the sleepers did not all wake", || {
        STORM_WOKEN.load(Ordering::Acquire) == k && URGENT_WOKEN.load(Ordering::Acquire) == URGENT
    })?;
    Ok(azos_sched::ktest_take_tick_pass_max())
}

azos_ktest::ktest_late! {
    fn irqoff_timer_storm() {
        // Every slot left but a few, as a user with a thread limit of the table does.
        let most = azos_sched::free_task_slots().saturating_sub(8);
        // A storm no larger than the bounds cannot show them, and a small task table
        // with the daemons of a volume (the soak and disk rows) leaves too few slots.
        if most <= azos_limits::SCHED_TIMER_WAKES_PER_IRQ.max(azos_limits::FAIR_PLACE_SAMPLE as usize) {
            return azos_ktest::skip!("the free task slots do not outnumber the bounds under test");
        }
        for k in [most / 4, most / 2, most] {
            let _ = azos_sched::scheduler::fairq::ktest_take_place_read_max();
            let (ticks, popped) = storm(k)?;
            let read = azos_sched::scheduler::fairq::ktest_take_place_read_max();
            let ns = ticks_to_ns(ticks);
            let (urgent_last, fair_first) = (wake_places(&URGENT_SLOT).1, wake_places(&FAIR_SLOT).0);
            azos_drv_sys::kprintln!("# irqoff timer-storm: sleepers={} popped_one_pass={} longest_pass_ns={} place_read_max={} urgent_last_wake={} fair_first_wake={}",
                k, popped, ns, read, urgent_last, fair_first);
            if popped > azos_limits::SCHED_TIMER_WAKES_PER_IRQ {
                return Err("one masked pass woke past SCHED_TIMER_WAKES_PER_IRQ");
            }
            if read > azos_limits::FAIR_PLACE_SAMPLE as u64 {
                return Err("a placement read past FAIR_PLACE_SAMPLE");
            }
            // Due at one instant: the order is the class's, not the slot's. The urgent ones
            // took the highest slots.
            if azos_limits::SCHED_CLASS_RT && !STORM_LATE.load(Ordering::Acquire) && urgent_last > fair_first {
                return Err("an urgent sleeper woke behind a fair one of the same instant");
            }
            // Instructions only under -icount, which this option's rows run.
            if azos_sync::lockdep::HOLD_ENFORCE && ns > azos_sync::lockdep::MAX_HOLD_US * 1_000 {
                return Err("one masked timer pass took past LOCK_MAX_HOLD_US");
            }
            // The slots come back when the sleepers have left.
            crate::ktest::wait("the sleepers' slots did not come back", || azos_sched::free_task_slots() >= most)?;
        }
        Ok(())
    }
}

mod graph {
    use super::*;
    use azos_sync::waitgraph::{EdgeKind, Graph, PiAttr, PiWaiters, SchedPi, TaskId, UnblockReason, WaitObj, PI_MAX_DEPTH};

    const N: usize = 4096;

    struct Sched {
        base: [AtomicUsize; N],
        on: [AtomicUsize; N],
    }

    fn attr(raw: usize) -> PiAttr {
        if raw == 0 { PiAttr::Fair } else { PiAttr::Rt { prio: (raw - 1) as u8 } }
    }

    impl SchedPi for Sched {
        fn base_attr(&self, t: TaskId) -> PiAttr { attr(self.base[t as usize].load(Ordering::Relaxed)) }
        fn boost(&self, _t: TaskId, _to: PiAttr) {}
        fn unboost(&self, _t: TaskId, _to: PiAttr) {}
        fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
            self.on[t as usize].store(on.map_or(0, WaitObj::addr), Ordering::Relaxed);
        }
        fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
            WaitObj::from_addr(self.on[t as usize].load(Ordering::Relaxed))
        }
        fn on_cpu(&self, _t: TaskId) -> bool { false }
    }

    static S: Sched = Sched {
        base: [const { AtomicUsize::new(0) }; N],
        on: [const { AtomicUsize::new(0) }; N],
    };
    static G: Graph<N> = Graph::new();
    static O: [PiWaiters; N] = [const { PiWaiters::new(EdgeKind::Mutex) }; N];
    /// A kind that takes lazy edges, whose owner change scans the task table.
    static LAZY: PiWaiters = PiWaiters::new(EdgeKind::IpcCall);

    fn timed<R>(max: &mut u64, f: impl FnOnce() -> R) -> R {
        // Masked, so the time is the hold's and not a preemption's.
        use azos_arch::Interrupts as _;
        let irq = azos_arch::ARCH.disable_all();
        let t0 = azos_drv_sys::timebase::now();
        let r = f();
        *max = (*max).max(azos_drv_sys::timebase::now().wrapping_sub(t0));
        azos_arch::ARCH.restore(irq);
        r
    }

    /// Every waiter at one attribute, so each enqueue walks to the tail. Owner: 0.
    fn one_object(n: usize) -> Result<u64, &'static str> {
        let obj = &O[0];
        G.set_owner(obj, Some(0));
        let mut m = 0;
        for w in 1..=n as u32 {
            timed(&mut m, || G.block_on(w, obj)).map_err(|_| "a block on one object failed")?;
        }
        for w in (1..=n as u32).rev() {
            timed(&mut m, || G.unblock(w, obj, UnblockReason::Timeout));
        }
        G.set_owner(obj, None);
        Ok(m)
    }

    /// Owner 0 owns `n` objects with one waiter each.
    fn many_owned(n: usize) -> Result<u64, &'static str> {
        let mut m = 0;
        for i in 0..n {
            G.set_owner(&O[i], Some(0));
        }
        for i in 0..n {
            timed(&mut m, || G.block_on(i as TaskId + 1, &O[i])).map_err(|_| "a block on an owned object failed")?;
        }
        for i in 0..n {
            timed(&mut m, || G.unblock(i as TaskId + 1, &O[i], UnblockReason::Timeout));
            timed(&mut m, || G.set_owner(&O[i], None));
        }
        Ok(m)
    }

    /// `n` lazy waiters on one object, then its owner changes: each is joined to
    /// the list in a hold of the graph lock, none of them all.
    fn lazy_owner_change(n: usize) -> Result<u64, &'static str> {
        G.set_owner(&LAZY, Some(0));
        for w in 1..=n as u32 {
            G.block_on_lazy(&S, w, &LAZY).map_err(|_| "a lazy block failed")?;
        }
        let mut m = 0;
        timed(&mut m, || G.set_owner(&LAZY, Some(n as u32 + 1)));
        if G.top_waiter(&LAZY).is_none() {
            return Err("the owner change left the lazy waiters out of the list");
        }
        for w in (1..=n as u32).rev() {
            G.unblock(w, &LAZY, UnblockReason::Timeout);
        }
        G.set_owner(&LAZY, None);
        Ok(m)
    }

    /// A chain `PI_MAX_DEPTH` long with the tasks left as waiters on its
    /// objects, and an urgent task at the end of it: the walk re-sorts every level.
    fn chain(n: usize) -> Result<u64, &'static str> {
        let d = PI_MAX_DEPTH.min(n / 2);
        let per = (n - 2 * d) / d;
        let mut next = d as u32 + 1;
        // Task i owns O[i] and waits on O[i - 1]; task 0 owns O[0].
        for i in 0..d {
            G.set_owner(&O[i], Some(i as u32));
            for _ in 0..per {
                G.block_on(next, &O[i]).map_err(|_| "a waiter on the chain failed")?;
                next += 1;
            }
        }
        for i in 1..d {
            G.block_on(i as u32, &O[i - 1]).map_err(|_| "a chain link failed")?;
        }
        let urgent = next;
        S.base[urgent as usize].store(1, Ordering::Relaxed);
        let mut m = 0;
        timed(&mut m, || G.block_on(urgent, &O[d - 1])).map_err(|_| "the urgent block failed")?;
        timed(&mut m, || G.unblock(urgent, &O[d - 1], UnblockReason::Timeout));
        S.base[urgent as usize].store(0, Ordering::Relaxed);
        for i in 1..d {
            G.unblock(i as u32, &O[i - 1], UnblockReason::Timeout);
        }
        let mut w = d as u32 + 1;
        for i in 0..d {
            for _ in 0..per {
                G.unblock(w, &O[i], UnblockReason::Timeout);
                w += 1;
            }
            G.set_owner(&O[i], None);
        }
        Ok(m)
    }

    azos_ktest::ktest_late! {
        fn irqoff_wait_graph_user_sized() {
            G.register_sched(&S);
            for n in [62, N - 2] {
                let a = one_object(n)?;
                let b = many_owned(n)?;
                let c = chain(n)?;
                let d = lazy_owner_change(n)?;
                azos_drv_sys::kprintln!("# irqoff wait-graph: tasks={} one_object_ns={} many_owned_ns={} chain_ns={} lazy_owner_ns={}",
                    n, ticks_to_ns(a), ticks_to_ns(b), ticks_to_ns(c), ticks_to_ns(d));
            }
            Ok(())
        }
    }
}
