// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Priority donation: the rule every waiting donor applies, and the counted
//! return that lets several donors share one target.
//!
//! Two donors use it today, through `scheduler::donate_priority` /
//! `scheduler::return_donation`:
//!
//!  * lease priority inheritance (RFC-0031): a lessor blocked in
//!    `lease_wait_return` donates to the lessee holding its buffer;
//!  * the user-driver proxy (`crates/drivers/sys/src/user_driver_proxy.rs`): a
//!    kernel client blocked on a ring-3 driver's reply donates to the driver.
//!
//! A third, fast IPC (wave 11 PIFAST), enters through
//! `scheduler::donate_priority_for_call` with the rule [`donation_for_call`]
//! and shares the same counted return.
//!
//! Pure: no scheduler state and no locks, so the host suite
//! (`tests/host/sched-wake-tests`) runs the tests at the bottom of this file
//! against the same code the kernel compiles.
//!
//! # One edge, made once, never walked
//!
//! A donation is one write: the donor's live priority onto one target, made
//! when the donor starts to wait and undone once when the wait ends (reply,
//! return, expiry or timeout). Nothing follows the target's own waits to pass
//! the boost further, so there is no chain to walk and no cycle to loop on. If
//! A waits on B and B then waits on A, B's donation finds A already at least
//! as urgent (it is A's own priority B was boosted to) and is not made.
//!
//! The cost of that choice: donation is not transitive. A target that is
//! itself blocked on a third task passes the boost on only by donating when
//! it starts that wait, with the priority it has then.
//!
//! Lower number = more urgent, as everywhere in the scheduler.

/// "No task" in the TID-valued fields donors pass (`lease.rs`'s `NO_TID`,
/// the proxy's absent driver). TID 0 is reserved by the allocator
/// (`tid_alloc::next_after`), so it is never a target either.
pub const NO_TID: u32 = u32::MAX;

/// The priority `donor` gives `target`, or `None` when no donation is due.
///
/// `donor_prio`/`target_prio` are the LIVE priorities (`task_priority`), so
/// a donor that is itself boosted passes on what it currently runs at.
/// `None` for a priority means that task no longer exists.
///
/// `target_floor` is the most urgent priority the target may be given: `0`
/// for a kernel task, `RT_PRIORITY_THRESHOLD` (12) for a ring-3 task — the
/// same floor the topology applies to a ring-3 row (wave 9, owner default):
/// below it the tick never preempts, so a donation must not put a ring-3
/// driver or lessee where a topology row may not. The donated priority is
/// raised to the floor first, and the returned `bool` says it was.
///
/// Refused: a donor donating to itself; a sentinel target; a target already
/// as urgent as the (floored) donation (strictly less urgent only — equal
/// priority gains nothing, and it is what stops the A→B→A case in the module
/// doc).
#[inline]
pub const fn donation_for(
    donor_tid: u32,
    donor_prio: Option<u32>,
    target_tid: u32,
    target_prio: Option<u32>,
    target_floor: u32,
) -> Option<(u32, bool)> {
    if donor_tid == target_tid || target_tid == NO_TID || target_tid == 0 {
        return None;
    }
    match (donor_prio, target_prio) {
        (Some(d), Some(t)) => {
            let (d, floored) = if d < target_floor { (target_floor, true) } else { (d, false) };
            if d < t { Some((d, floored)) } else { None }
        }
        _ => None,
    }
}

/// The fast-IPC call's rule (wave 11 PIFAST): [`donation_for`] judged against
/// the target's BASE priority, not its live one.
///
/// Why base: a server already boosted by a more urgent caller A must still
/// count caller B's donation. Judged against the live priority, B's is refused
/// ("already as urgent"), A's reply then brings the base back — the count was
/// A's alone — and B waits behind whatever sits between B and the base: the
/// inversion the donation exists to remove, re-opened by the second client.
/// Judged against the base, B's donation is counted ([`boost_step`] moves the
/// priority only towards more urgent), so the base returns only after B's
/// return too. The cost is an over-boost: between A's return and B's, the
/// server keeps A's priority.
///
/// The lease and proxy donors keep [`donation_for`]: each has one donor per
/// target at a time.
///
/// `#[inline]` (both): the call runs on every fast call from
/// `azos_ipc`, another crate, and without it the decision was an
/// out-of-line call there (seen in the riscv64 disassembly).
#[inline]
pub const fn donation_for_call(
    donor_tid: u32,
    donor_prio: Option<u32>,
    target_tid: u32,
    target_base: Option<u32>,
    target_floor: u32,
) -> Option<(u32, bool)> {
    donation_for(donor_tid, donor_prio, target_tid, target_base, target_floor)
}

/// A boost: the donation count always rises (the matching return always
/// lowers it), and the priority moves only towards more urgent. Returns the
/// new count and the priority to write, if any.
pub const fn boost_step(count: u32, current: u32, donated: u32) -> (u32, Option<u32>) {
    let prio = if donated < current { Some(donated) } else { None };
    (count.saturating_add(1), prio)
}

/// A return: one donation leaves. Returns the remaining count and whether
/// the base priority comes back — only when the LAST donation has left, so a
/// donor that returns early cannot drop the target below a donor still
/// waiting. Saturating: an unmatched return must not wrap the count and pin
/// the target at a donated priority forever.
pub const fn return_step(count: u32) -> (u32, bool) {
    let remaining = count.saturating_sub(1);
    (remaining, remaining == 0)
}

/// One donation target as the locked protocol sees it: its donation count,
/// its live and base priority, and its donation lock. The scheduler's
/// implementation is one task slot (`scheduler::TaskDonation`); the host suite
/// (`tests/host/sched-wake-tests`) drives the same two functions below through its
/// own, with threads.
///
/// # Why a lock (wave 9)
///
/// The count and the priority used to be two separate atomics, and the last
/// restore did two steps: count to 0, then store the base priority. A boost
/// landing between them (count 0→1, priority lowered) was overwritten by the
/// base: the new donor waited without its boost. Both functions now run the
/// whole read-modify-write of count AND priority — including the run-queue
/// re-bucketing and the IPI it sends — under the target's lock, so a boost
/// and a restore on one target are serialised and neither can split the
/// other.
pub trait DonationCell {
    /// Take the target's donation lock (the scheduler also masks interrupts:
    /// the holder must not be switched out while another donor spins).
    fn lock(&self);
    fn unlock(&self);
    fn count(&self) -> u32;
    fn set_count(&self, c: u32);
    /// The live priority.
    fn prio(&self) -> u32;
    fn base(&self) -> u32;
    /// Write the live priority, moving the task between ready buckets if it
    /// is queued (and waking the hart it is queued on).
    fn apply_prio(&self, p: u32);
}

/// A boost of `c` to `donated`, under the target's lock. Counted even when
/// the priority does not move (see [`boost_step`]).
pub fn boost_locked<C: DonationCell>(c: &C, donated: u32) {
    c.lock();
    let (n, p) = boost_step(c.count(), c.prio(), donated);
    c.set_count(n);
    if let Some(p) = p {
        c.apply_prio(p);
    }
    c.unlock();
}

/// One return on `c`, under the target's lock: the base priority comes back
/// only when this was the last donation (see [`return_step`]).
///
/// `between` runs after the count is written and before the base priority is
/// — the exact window the lock closes. The kernel passes a no-op; the host
/// test passes a closure that starts a concurrent boost there and gives it
/// time to land.
pub fn restore_locked<C: DonationCell>(c: &C, between: impl FnOnce()) {
    c.lock();
    let (n, back) = return_step(c.count());
    c.set_count(n);
    between();
    if back && c.prio() != c.base() {
        c.apply_prio(c.base());
    }
    c.unlock();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One target task as the scheduler keeps it: base priority, live
    /// priority, donation count — driven only through the functions above.
    struct Target { base: u32, prio: u32, count: u32 }

    impl Target {
        fn new(base: u32) -> Self { Target { base, prio: base, count: 0 } }
        fn boost(&mut self, donated: u32) {
            let (c, p) = boost_step(self.count, self.prio, donated);
            self.count = c;
            if let Some(p) = p { self.prio = p; }
        }
        fn ret(&mut self) {
            let (c, back) = return_step(self.count);
            self.count = c;
            if back { self.prio = self.base; }
        }
    }

    #[test]
    fn a_more_urgent_donor_donates_its_live_priority() {
        assert_eq!(donation_for(10, Some(14), 20, Some(24), 0), Some((14, false)));
    }

    #[test]
    fn no_donation_to_an_equal_or_more_urgent_target() {
        assert_eq!(donation_for(10, Some(24), 20, Some(24), 0), None);
        assert_eq!(donation_for(10, Some(24), 20, Some(14), 0), None);
    }

    #[test]
    fn no_donation_to_self_a_sentinel_or_a_task_that_is_gone() {
        assert_eq!(donation_for(7, Some(1), 7, Some(24), 0), None);
        assert_eq!(donation_for(7, Some(1), NO_TID, Some(24), 0), None);
        assert_eq!(donation_for(7, Some(1), 0, Some(24), 0), None);
        assert_eq!(donation_for(7, Some(1), 9, None, 0), None);
        assert_eq!(donation_for(7, None, 9, Some(24), 0), None);
    }

    /// Wave 9: a donation to a ring-3 target stops at the ring-3 floor (12).
    #[test]
    fn a_donation_to_a_ring3_target_is_raised_to_the_floor() {
        const FLOOR: u32 = 12;
        // A kernel RT client at 8 onto a ring-3 driver at 24: the driver runs
        // at 12, and the clamp is reported.
        assert_eq!(donation_for(3, Some(8), 9, Some(24), FLOOR), Some((12, true)));
        // At or above the floor nothing moves.
        assert_eq!(donation_for(3, Some(12), 9, Some(24), FLOOR), Some((12, false)));
        assert_eq!(donation_for(3, Some(14), 9, Some(24), FLOOR), Some((14, false)));
        // A kernel target has no floor.
        assert_eq!(donation_for(3, Some(8), 9, Some(24), 0), Some((8, false)));
        // Floored to a priority the target already has: no donation at all.
        assert_eq!(donation_for(3, Some(4), 9, Some(12), FLOOR), None);
    }

    #[test]
    fn a_donation_is_undone_by_its_return() {
        let mut t = Target::new(24);
        t.boost(14);
        assert_eq!((t.prio, t.count), (14, 1));
        t.ret();
        assert_eq!((t.prio, t.count), (24, 0));
    }

    /// The two donors compose: a lessor at 8 and a proxy client at 14 both
    /// wait on the same task. Whichever returns first, the target stays
    /// boosted until the other has returned too, and then is back at base.
    #[test]
    fn two_donors_compose_whatever_the_return_order() {
        for lessor_first in [true, false] {
            let mut t = Target::new(24);
            t.boost(14); // proxy client
            t.boost(8);  // lessor
            assert_eq!(t.prio, 8);
            t.ret();
            assert_ne!(t.prio, 24, "base came back while a donor still waits \
                                   (lessor_first={})", lessor_first);
            t.ret();
            assert_eq!((t.prio, t.count), (24, 0));
        }
    }

    /// A donation that did not lower the priority is still counted, so its
    /// return is balanced: the target does not drop back while the more
    /// urgent donor still waits.
    #[test]
    fn a_donation_that_moves_nothing_is_still_counted() {
        let mut t = Target::new(24);
        t.boost(8);
        t.boost(14); // already at 8: priority unchanged, count 2
        assert_eq!((t.prio, t.count), (8, 2));
        t.ret();
        assert_eq!(t.prio, 8);
        t.ret();
        assert_eq!(t.prio, 24);
    }

    #[test]
    fn an_unmatched_return_saturates() {
        let mut t = Target::new(24);
        t.ret();
        assert_eq!((t.prio, t.count), (24, 0));
        t.boost(14);
        t.ret();
        assert_eq!((t.prio, t.count), (24, 0));
    }

    /// A waits on B (A donates), then B waits on A: B's donation is refused,
    /// because A is exactly as urgent as the priority B was boosted to. No
    /// cycle, and each wait's return leaves both at base.
    #[test]
    fn a_wait_cycle_makes_one_donation_not_a_loop() {
        let (a_tid, b_tid) = (3u32, 4u32);
        let mut a = Target::new(10);
        let mut b = Target::new(20);
        let d1 = donation_for(a_tid, Some(a.prio), b_tid, Some(b.prio), 0);
        assert_eq!(d1, Some((10, false)));
        b.boost(10);
        let d2 = donation_for(b_tid, Some(b.prio), a_tid, Some(a.prio), 0);
        assert_eq!(d2, None, "the reverse edge must not be made");
        b.ret();
        assert_eq!((a.prio, a.count, b.prio, b.count), (10, 0, 20, 0));
        a.ret(); // an unmatched return on A is harmless
        assert_eq!(a.prio, 10);
    }


    /// Wave 11 PIFAST: two fast-IPC callers on one server of base 24, A at 10
    /// then B at 14, A answered first. The live-priority rule refuses B
    /// (the server already runs at 10) and A's return brings back 24 while B
    /// still waits; the base rule counts B, and the server stays at least as
    /// urgent as 14 until B's return.
    #[test]
    fn a_second_caller_judged_against_the_base_keeps_the_server_boosted() {
        const BASE: u32 = 24;
        // The live rule, for contrast: B's donation is refused...
        let mut live = Target::new(BASE);
        if let Some((p, _)) = donation_for(1, Some(10), 9, Some(live.prio), 0) { live.boost(p); }
        assert_eq!(donation_for(2, Some(14), 9, Some(live.prio), 0), None);
        // ...and A's return re-opens the inversion for B.
        live.ret();
        assert_eq!(live.prio, BASE);

        let mut t = Target::new(BASE);
        if let Some((p, _)) = donation_for_call(1, Some(10), 9, Some(t.base), 0) { t.boost(p); }
        let b = donation_for_call(2, Some(14), 9, Some(t.base), 0);
        assert_eq!(b, Some((14, false)));
        if let Some((p, _)) = b { t.boost(p); }
        assert_eq!((t.prio, t.count), (10, 2));
        t.ret(); // A answered
        assert!(t.prio <= 14, "B still waiting, the server fell to {}", t.prio);
        t.ret(); // B answered
        assert_eq!((t.prio, t.count), (BASE, 0));
    }

    /// The base rule keeps the other refusals of `donation_for`: no donation
    /// to a server whose base is as urgent as the caller, to self, to a gone
    /// task, and the ring-3 floor.
    #[test]
    fn the_call_rule_keeps_the_refusals_and_the_floor() {
        assert_eq!(donation_for_call(1, Some(14), 9, Some(14), 0), None);
        assert_eq!(donation_for_call(1, Some(14), 9, Some(10), 0), None);
        assert_eq!(donation_for_call(9, Some(1), 9, Some(24), 0), None);
        assert_eq!(donation_for_call(1, Some(1), 9, None, 0), None);
        assert_eq!(donation_for_call(1, Some(8), 9, Some(24), 12), Some((12, true)));
    }
}
