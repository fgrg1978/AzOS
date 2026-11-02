// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! How long interrupts stay masked with an input a user sizes: a storm of
//! sleepers due at one instant on one CPU, and the wait graph at the size of
//! the largest task table (`MAX_TASKS` 4096, the server profile). The numbers
//! mean instructions only under `-icount shift=0` (the `ktest hold bound`
//! rows): 1 ns of the printed time is one instruction there.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use azos_sched::WaitReason;

fn ticks_to_ns(t: u64) -> u64 {
    t.saturating_mul(1_000_000_000) / azos_drv_sys::timebase::TIMER_FREQ
}

static STORM_AT: AtomicU64 = AtomicU64::new(0);
static STORM_READY: AtomicUsize = AtomicUsize::new(0);
static STORM_WOKEN: AtomicUsize = AtomicUsize::new(0);

fn storm_sleeper(_: usize) {
    STORM_READY.fetch_add(1, Ordering::AcqRel);
    let mut at = STORM_AT.load(Ordering::Acquire);
    while at == 0 {
        azos_sched::task_yield();
        at = STORM_AT.load(Ordering::Acquire);
    }
    azos_sched::task_block(WaitReason::Timer(at));
    STORM_WOKEN.fetch_add(1, Ordering::AcqRel);
}

/// One storm of `k` sleepers pinned to this CPU, due at one instant: its
/// longest timer pass in timer counts, and the most sleepers a pass popped.
fn storm(k: usize) -> Result<(u64, usize), &'static str> {
    storm_with(k, || Ok(()))
}

/// [`storm`], running `mid` once every sleeper is up and none is due.
fn storm_with(k: usize, mid: impl FnOnce() -> Result<(), &'static str>) -> Result<(u64, usize), &'static str> {
    let cpu = azos_sched::smp::current_cpu_id() as i8;
    STORM_AT.store(0, Ordering::Release);
    STORM_READY.store(0, Ordering::Release);
    STORM_WOKEN.store(0, Ordering::Release);
    for _ in 0..k {
        if azos_sched::try_task_create_affinity("irqoff-storm", storm_sleeper, 0, azos_sched::DEFAULT_PRIORITY, cpu).is_none() {
            return Err("no free task slot for a sleeper");
        }
    }
    crate::ktest::wait("the sleepers did not start", || STORM_READY.load(Ordering::Acquire) == k)?;
    mid()?;
    let _ = azos_sched::ktest_take_tick_pass_max();
    // Far enough for every sleeper to commit its block first, on any host.
    let at = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 5;
    STORM_AT.store(at, Ordering::Release);
    crate::ktest::wait("the sleepers did not all wake", || STORM_WOKEN.load(Ordering::Acquire) == k)?;
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
            azos_drv_sys::kprintln!("# irqoff timer-storm: sleepers={} popped_one_pass={} longest_pass_ns={} place_read_max={}", k, popped, ns, read);
            if popped > azos_limits::SCHED_TIMER_WAKES_PER_IRQ {
                return Err("one masked pass woke past SCHED_TIMER_WAKES_PER_IRQ");
            }
            if read > azos_limits::FAIR_PLACE_SAMPLE as u64 {
                return Err("a placement read past FAIR_PLACE_SAMPLE");
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

azos_ktest::ktest_late! {
    // The fair queue's tree holds what the ready lists hold, with a queue a
    // user sized: every sleeper of the storm yields in a loop, queued on this CPU.
    fn fair_tree_follows_the_lists() {
        let k = azos_sched::free_task_slots().saturating_sub(8).min(48);
        if k < 8 {
            return azos_ktest::skip!("too few free task slots for a queue");
        }
        let cpu = azos_sched::smp::current_cpu_id();
        let mut queued = 0;
        storm_with(k, || {
            queued = azos_sched::scheduler::fairq::ktest_check(cpu)?;
            Ok(())
        })?;
        if queued < k / 2 {
            return Err("the sleepers were not queued when the tree was checked");
        }
        crate::ktest::wait("the sleepers' slots did not come back", || azos_sched::free_task_slots() >= k)?;
        azos_sched::scheduler::fairq::ktest_check(cpu).map(|_| ())
    }
}

azos_ktest::ktest! {
    // The tree's pick is the definition's, on this ISA: random links, unlinks
    // and picks against a scan of the same entities.
    fn fair_tree_pick_is_the_scan() {
        use azos_sched::eevdf_core::{Avg, Choice, Ent, WEIGHTS};
        use azos_sched::eevdf_tree::{AtomicNodes, Tree};

        const N: usize = 48;
        static NODES: AtomicNodes<N> = AtomicNodes::new();
        let mut rng = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move |n: u64| {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng.wrapping_mul(0x2545_F491_4F6C_DD1D) % n
        };
        let mut tree = Tree::new();
        // Entity, level and arrival of each linked task.
        let mut m: [Option<(Ent, u32, u64)>; N] = [None; N];
        let mut seq = 0u64;
        let mut cur: Option<(usize, Ent)> = None;
        let mut cur_level = 0;
        for _ in 0..600 {
            let i = next(N as u64) as usize;
            match (next(3), m[i]) {
                (0, None) if cur.map(|c| c.0) != Some(i) => {
                    let mut e = Ent::new(WEIGHTS[next(40) as usize], 1000 + next(3000));
                    e.vruntime = next(60) as i64 - 30;
                    e.deadline = next(20) as i64;
                    let level = next(3) as u32;
                    tree.insert(&NODES, i, &e, level);
                    m[i] = Some((e, level, seq));
                    seq += 1;
                }
                (1, Some(_)) => {
                    if !tree.remove(&NODES, i) {
                        return Err("a linked task was not found");
                    }
                    m[i] = None;
                }
                _ => {}
            }
            let mut order: [Option<(usize, Ent)>; N] = [None; N];
            let mut n = 0;
            let mut avg = Avg::new();
            for lvl in 0..3u32 {
                let mut by_seq = [(u64::MAX, 0usize); N];
                let mut k = 0;
                for (j, x) in m.iter().enumerate() {
                    if let Some((_, l, s)) = x {
                        if *l == lvl {
                            by_seq[k] = (*s, j);
                            k += 1;
                        }
                    }
                }
                by_seq[..k].sort_unstable();
                for &(_, j) in &by_seq[..k] {
                    let e = m[j].unwrap().0;
                    avg.add(&e);
                    order[n] = Some((j, e));
                    n += 1;
                }
            }
            let want = if n == 0 {
                if cur.is_some() { Choice::Cur } else { Choice::Empty }
            } else {
                if let Some((_, c)) = &cur {
                    avg.add(c);
                }
                let mut best: Option<(usize, i64)> = None;
                for &(j, e) in order[..n].iter().flatten() {
                    if avg.eligible(&e) && best.is_none_or(|(_, d)| e.deadline < d) {
                        best = Some((j, e.deadline));
                    }
                }
                match (best, cur) {
                    (None, _) => Choice::Cur,
                    (Some((j, _)), None) => Choice::Task(j),
                    (Some((j, d)), Some((_, c))) => {
                        if avg.eligible(&c) && c.deadline <= d { Choice::Cur } else { Choice::Task(j) }
                    }
                }
            };
            if tree.pick(&NODES, cur) != want {
                return Err("the tree and the scan pick differently");
            }
            tree.check(&NODES)?;
            if let Choice::Task(j) = want {
                if !tree.remove(&NODES, j) {
                    return Err("the picked task was not linked");
                }
                let (e, l, _) = m[j].take().unwrap();
                if let Some((o, oe)) = cur.take() {
                    tree.insert(&NODES, o, &oe, cur_level);
                    m[o] = Some((oe, cur_level, seq));
                    seq += 1;
                }
                cur = Some((j, e));
                cur_level = l;
            }
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
                azos_drv_sys::kprintln!("# irqoff wait-graph: tasks={} one_object_ns={} many_owned_ns={} chain_ns={}",
                    n, ticks_to_ns(a), ticks_to_ns(b), ticks_to_ns(c));
            }
            Ok(())
        }
    }
}
