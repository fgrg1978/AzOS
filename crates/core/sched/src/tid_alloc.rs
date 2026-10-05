// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure TID-allocation candidate search (U02-6, second half: `NEXT_TID`
//! wrap has no liveness check).
//!
//! No `unsafe`, no global state: `scheduler::alloc_tid` holds the real
//! `NEXT_TID`/`TID_HAS_WRAPPED` and calls the real `idx_for_tid` as the
//! `is_live` predicate; everything here is free code the host test
//! runner (`tests/host/sched-wake-tests`) can exercise directly, the way
//! `elf_bounds.rs` / `hart_set.rs` / `exit_note.rs` are.

/// The next candidate after `tid`, skipping the reserved sentinel `0`.
///
/// Byte-identical to the original inline dance
/// (`NEXT_TID.wrapping_add(1); if NEXT_TID == 0 { NEXT_TID = 1; }`) — its
/// own function only so `first_free` can call it without duplicating the
/// skip-zero rule.
#[inline]
pub const fn next_after(tid: u32) -> u32 {
    let n = tid.wrapping_add(1);
    if n == 0 { 1 } else { n }
}

/// Search starting at `start` for a candidate `is_live` says is free,
/// trying at most `bound` candidates (including `start` itself).
///
/// Returns the first free candidate found, or `start` unchanged if every
/// candidate in the bound was live — which cannot happen when `bound` is
/// `MAX_TASKS + 1` and at most `MAX_TASKS` TIDs are ever live at once
/// (pigeonhole): returning `start` in that case is a defensive fallback,
/// not a path a correct caller reaches.
pub fn first_free(start: u32, bound: usize, is_live: impl Fn(u32) -> bool) -> u32 {
    let mut candidate = start;
    for _ in 0..bound {
        if !is_live(candidate) {
            return candidate;
        }
        candidate = next_after(candidate);
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_after_skips_zero() {
        assert_eq!(next_after(u32::MAX), 1);
        assert_eq!(next_after(5), 6);
    }

    #[test]
    fn first_free_returns_start_when_it_is_already_free() {
        assert_eq!(first_free(7, 10, |_| false), 7);
    }

    #[test]
    fn first_free_skips_live_candidates() {
        // 7 and 8 are live (a wrapped counter landed on an ancient,
        // still-running task's TID); 9 is free.
        let live = [7u32, 8u32];
        assert_eq!(first_free(7, 10, |t| live.contains(&t)), 9);
    }

    #[test]
    fn first_free_wraps_past_zero_during_the_search() {
        // Start right at the top of the range; 0 must never be
        // returned (it is the sentinel), and the search must continue
        // into 1, 2, ... exactly like the unbounded counter does.
        let live = [u32::MAX, 1u32];
        assert_eq!(first_free(u32::MAX, 5, |t| live.contains(&t)), 2);
    }

    #[test]
    fn first_free_gives_up_at_the_bound_without_looping_forever() {
        // U02-6's own regression, made concrete: if every candidate in
        // the bound is (pathologically) live, the search must still
        // terminate — this is the proof it is bounded, not the
        // expected outcome of a correct `MAX_TASKS + 1` call.
        assert_eq!(first_free(1, 3, |_| true), 1);
    }

    #[test]
    fn a_burst_of_wrap_allocations_never_collides_with_a_still_live_tid() {
        // Simulates `alloc_tid` over several allocations after a wrap,
        // with a handful of ancient tasks still alive right where the
        // counter lands. No two allocations may ever collide with each
        // other OR with the live set — U02-6's actual failure mode was
        // exactly this: a wrapped counter handing out a TID a live task
        // already held.
        let live_ancient = [100u32, 101, 105];
        let mut issued: Vec<u32> = Vec::new();
        let mut next = 99u32;
        for _ in 0..10 {
            let is_live = |t: u32| live_ancient.contains(&t) || issued.contains(&t);
            let tid = first_free(next, 200, is_live);
            assert!(
                !live_ancient.contains(&tid),
                "issued a TID still held by a live task: {tid}"
            );
            assert!(!issued.contains(&tid), "issued the same TID twice: {tid}");
            issued.push(tid);
            next = next_after(tid);
        }
    }
}
