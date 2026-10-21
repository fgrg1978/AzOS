// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Load balancing of the fair class between CPUs: the policy, pure and
//! host-tested (`tests/host/sched-policy-tests/src/balance.rs`).
//!
//! A child module of `scheduler.rs` (declared with `mod balance;`), but with no
//! `super::` and no state, so the host runner can compile it. The queue side is
//! `fairq.rs` (`impl Rq for Queues`): it reads the loads, detaches a queued
//! task under the sender's lock, and queues it on the receiver. This file
//! decides *who* gives to *whom*, *which* task may go, and *when to stop*.
//!
//! # Two moves
//!
//! * [`pull`]: a CPU that is about to idle takes work. It walks the topology
//!   levels nearest first (the caller passes the last-level cache, then the
//!   node, then the package, each a superset of the one before), takes from
//!   the busiest CPU of the first level that has a gap, and stops at the
//!   first level that gave a task. Cache-warm work is the cheapest to move,
//!   and a far level is touched only when the near ones have nothing.
//! * [`push`]: a CPU with fair work queued hands one task to the least loaded
//!   CPU, with the same walk. The pull cannot do this job: an idle CPU is
//!   tickless and asleep, so only a busy CPU's tick can see the imbalance. The
//!   push's enqueue rings the receiver's doorbell, which wakes it.
//!
//! # What may move
//!
//! The queue side only offers queued, ready fair tasks that are not pinned,
//! not a reservation and not mid-switch. The rest is here:
//!
//! * `eligible` is the set of CPUs that take part, as sender or receiver.
//!   The caller leaves out the offline CPUs and every CPU with real-time
//!   state; a pass for a CPU outside it does nothing. So nothing moves onto
//!   or off an isolated CPU, whichever side starts the pass.
//! * A move must leave the receiver strictly below where the sender was
//!   ([`improves`]): `scaled(dst) + w * (1 + hop) < scaled(src)`, with `w` the
//!   task's weight, `scaled` the load over the CPU's capacity and `hop` the
//!   topology level the move crosses (0 = within the cache). Two
//!   consequences: the scaled loads, sorted largest first, fall in lexicographic order with
//!   every move (the sender drops, the receiver stays below the sender's old
//!   load), so passes reach a fixed point and never loop; and the reverse
//!   move of a task just moved never qualifies, so nothing bounces. A CPU is
//!   never emptied of its last runnable task for a peer that is idle
//!   (`w + 0 < w` is false).
//! * At most [`Params::moves`] tasks and [`Params::scan`] queue entries per
//!   call, whatever the number of CPUs and tasks: the time in the tick and on
//!   the way to idle is bounded.
//!
//! # Load
//!
//! [`Load::weight`] is the sum of the EEVDF weights (`eevdf_core::weight_of_prio`)
//! of the CPU's runnable fair tasks, the running one included; it is read
//! without a lock and may be stale, which costs one suboptimal move at worst:
//! the sender's lock decides at `take` whether the task can go.

/// A set of CPUs, bit `n` is CPU `n` (`topo::Mask`).
pub type Mask = u64;

/// The capacity of the largest CPU (`topo::CAPACITY_SCALE`).
pub const CAPACITY_SCALE: u64 = 1024;

#[inline]
const fn bit(cpu: usize) -> Mask {
    1u64 << cpu
}

/// What the policy knows of one CPU, read unlocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Load {
    /// Sum of the weights of the runnable fair tasks (queued and running).
    pub weight: u32,
    /// `topo::capacity`: the CPU's performance, [`CAPACITY_SCALE`] for the
    /// largest. 0 is read as 1.
    pub capacity: u16,
}

impl Load {
    /// The load over the capacity, in units of [`CAPACITY_SCALE`] per weight
    /// unit, with `extra` weight added.
    #[inline]
    pub fn scaled(&self, extra: u32) -> u64 {
        (self.weight as u64 + extra as u64) * CAPACITY_SCALE / self.capacity.max(1) as u64
    }
}

/// Would moving a task of weight `w` from `src` to `dst` improve the balance?
/// `hop`: the topology level the move crosses ([`Ring::level`]); a farther
/// level costs more.
#[inline]
pub fn improves(src: &Load, dst: &Load, w: u32, hop: u32) -> bool {
    dst.scaled(w.saturating_mul(1 + hop)) < src.scaled(0)
}

/// How much one call may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Tasks moved.
    pub moves: u32,
    /// Queue entries examined, over all the queues visited.
    pub scan: u32,
}

/// What `take` found.
pub enum Take<T> {
    /// A task detached from its queue.
    Got(T),
    /// The sender's queue had no task that may go (all pinned, or none that
    /// improves the balance), or the scan budget ran out.
    Nothing,
    /// The sender's queue lock was held: not waited for.
    Busy,
}

/// The queue side of a balancing pass.
pub trait Rq {
    /// A task detached from a queue and not yet on another.
    type Task;

    /// The load of `cpu`.
    fn load(&mut self, cpu: usize) -> Load;

    /// Detach the first queued task of `src` that may run on `dst` and whose
    /// weight satisfies `want`, looking at no more than `*scan` entries and
    /// subtracting those it looked at from `*scan`. Never waits for a lock
    /// another CPU holds.
    fn take(
        &mut self,
        src: usize,
        dst: usize,
        scan: &mut u32,
        want: &mut dyn FnMut(u32) -> bool,
    ) -> Take<Self::Task>;

    /// Queue a task [`take`](Rq::take) detached on `dst`.
    fn give(&mut self, dst: usize, t: Self::Task);
}

/// One ring of a walk: the CPUs at a topology level and that level's true
/// index (0 = the last-level cache, 1 = the node, 2 = the package), which
/// stays the same when an equal level before it was dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ring {
    pub mask: Mask,
    pub level: u32,
}

/// What a pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Moved {
    /// Tasks moved.
    pub moved: u32,
    /// The farthest topology level a task crossed ([`Ring::level`]).
    pub hop: u32,
    /// Senders whose lock was busy.
    pub busy: u32,
    /// Queue entries examined.
    pub scanned: u32,
}

/// The CPU of `ring` that `better(a, b)` ranks first, `tried` left out.
fn pick(
    rq: &mut impl Rq,
    mut ring: Mask,
    tried: Mask,
    better: impl Fn(&Load, &Load) -> bool,
) -> Option<(usize, Load)> {
    ring &= !tried;
    let mut best: Option<(usize, Load)> = None;
    while ring != 0 {
        let c = ring.trailing_zeros() as usize;
        ring &= ring - 1;
        let l = rq.load(c);
        if best.as_ref().is_none_or(|(_, b)| better(&l, b)) {
            best = Some((c, l));
        }
    }
    best
}

/// `me` is about to idle: take work from the busiest CPU of the nearest level
/// that has some. `levels`: the CPUs at each level around `me`, nearest first,
/// each a superset of the one before.
pub fn pull<R: Rq>(rq: &mut R, me: usize, levels: &[Ring], eligible: Mask, p: &Params) -> Moved {
    let mut out = Moved::default();
    if eligible & bit(me) == 0 {
        return out;
    }
    let mut seen = bit(me);
    let mut scan = p.scan;
    for &Ring { mask, level } in levels {
        let ring = mask & eligible & !seen;
        seen |= mask;
        let mut tried: Mask = 0;
        while out.moved < p.moves && scan > 0 {
            let mine = rq.load(me);
            let Some((src, sl)) = pick(rq, ring, tried, |a, b| a.scaled(0) > b.scaled(0)) else { break };
            // The busiest of the ring is not busier than `me`: no task of it
            // can improve anything, and none of the others can either.
            if sl.scaled(0) <= mine.scaled(0) {
                break;
            }
            let before = scan;
            let r = rq.take(src, me, &mut scan, &mut |w| improves(&sl, &mine, w, level));
            out.scanned += before - scan;
            match r {
                Take::Got(t) => {
                    rq.give(me, t);
                    out.moved += 1;
                    out.hop = out.hop.max(level);
                }
                Take::Nothing => tried |= bit(src),
                Take::Busy => {
                    out.busy += 1;
                    tried |= bit(src);
                }
            }
        }
        // Stop at the nearest level that gave.
        if out.moved > 0 {
            break;
        }
    }
    out
}

/// `me` has fair tasks queued: hand some to the least loaded CPU of the
/// nearest level where it helps.
pub fn push<R: Rq>(rq: &mut R, me: usize, levels: &[Ring], eligible: Mask, p: &Params) -> Moved {
    let mut out = Moved::default();
    if eligible & bit(me) == 0 {
        return out;
    }
    let mut seen = bit(me);
    let mut scan = p.scan;
    for &Ring { mask, level } in levels {
        let ring = mask & eligible & !seen;
        seen |= mask;
        let mut tried: Mask = 0;
        while out.moved < p.moves && scan > 0 {
            let mine = rq.load(me);
            let Some((dst, dl)) = pick(rq, ring, tried, |a, b| a.scaled(0) < b.scaled(0)) else { break };
            // The least loaded of the ring is not less loaded than `me`.
            if dl.scaled(0) >= mine.scaled(0) {
                break;
            }
            let before = scan;
            let r = rq.take(me, dst, &mut scan, &mut |w| improves(&mine, &dl, w, level));
            out.scanned += before - scan;
            match r {
                Take::Got(t) => {
                    rq.give(dst, t);
                    out.moved += 1;
                    out.hop = out.hop.max(level);
                }
                Take::Nothing => tried |= bit(dst),
                Take::Busy => {
                    out.busy += 1;
                    tried |= bit(dst);
                }
            }
        }
        if out.moved > 0 {
            break;
        }
    }
    out
}

/// The distinct levels around a CPU, nearest first: `masks` is the CPU's mask
/// at each topology level from the last-level cache out, `online` the CPUs
/// that run. A level equal to the one before it is dropped (a machine with
/// one node has `node == package`), each result is clipped to `online`, and
/// each keeps its index in `masks`, so a move is charged and counted at the
/// level it crosses whatever was dropped before it. Returns how many entries
/// of `out` are set.
pub fn distinct_levels(masks: &[Mask], online: Mask, out: &mut [Ring]) -> usize {
    let mut n = 0;
    let mut last: Mask = 0;
    for (level, &m) in masks.iter().enumerate() {
        let m = m & online;
        if m != last && n < out.len() {
            out[n] = Ring { mask: m, level: level as u32 };
            n += 1;
            last = m;
        }
    }
    n
}
