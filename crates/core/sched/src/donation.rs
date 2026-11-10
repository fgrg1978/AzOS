// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The counted boost cell under the wait graph: where the graph's floor lands
//! on a task's live priority (`classes::ClassPi::write_floor`), the ring-3
//! floor, and the boost and return steps the ktests drive.
//!
//! Pure: no scheduler state and no locks, so the host suite
//! (`tests/host/sched-wake-tests`) runs the tests at the bottom of this file
//! against the same code the kernel compiles.
//!
//! Lower number = more urgent, as everywhere in the scheduler.

/// "No task" in the TID-valued fields donors pass (the proxy's absent
/// driver). TID 0 is reserved by the allocator
/// (`tid_alloc::next_after`), so it is never a target either.
pub const NO_TID: u32 = u32::MAX;

/// A priority `p` held at `floor` (0: none): never more urgent (a lower
/// number) than the floor. `u32::MAX` (no boost) stays. The wait graph's
/// ring-3 floor (`classes::graph_floored`).
pub const fn floored(p: u32, floor: u32) -> u32 {
    if p < floor { floor } else { p }
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
/// # Why a lock
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
    /// Does the cell still belong to the target the caller resolved? Asked
    /// under the lock; a cell handed to another target is left untouched.
    fn holds(&self) -> bool {
        true
    }
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
    if !c.holds() {
        c.unlock();
        return;
    }
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
    if !c.holds() {
        c.unlock();
        return;
    }
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
    fn a_graph_boost_of_a_ring3_target_is_held_at_the_floor() {
        const FLOOR: u32 = 12;
        // A kernel RT waiter at 4 (or a DL / stop donor, 0) onto a ring-3
        // owner: the owner runs at 12.
        assert_eq!(floored(4, FLOOR), FLOOR);
        assert_eq!(floored(0, FLOOR), FLOOR);
        // At or past the floor, and no boost at all, nothing moves.
        assert_eq!(floored(12, FLOOR), 12);
        assert_eq!(floored(14, FLOOR), 14);
        assert_eq!(floored(u32::MAX, FLOOR), u32::MAX);
        // A kernel owner has no floor.
        assert_eq!(floored(4, 0), 4);
        assert_eq!(floored(0, 0), 0);
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
}
