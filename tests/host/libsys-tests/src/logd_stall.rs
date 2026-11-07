// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! When `logd` gives up on a record nobody finished (`userspace/services/logd/src/stall.rs`).

use crate::stall::{Stall, STUCK_POLLS};

/// A record still unfinished, with the ring barely past it, is waited for
/// [`STUCK_POLLS`] polls and then given up on.
#[test]
fn a_record_is_waited_for_a_few_polls_then_given_up() {
    let mut s = Stall::new();
    for _ in 1..STUCK_POLLS {
        assert!(!s.give_up(1, 40, 2, 256));
    }
    assert!(s.give_up(1, 40, 2, 256), "the last poll gives up");
    assert!(!s.give_up(1, 40, 2, 256), "and the count starts again");
}

/// A producer the ring has moved half a lap past is gone: the reader gives up
/// on the first poll and the other rings are not held back for seconds.
/// **Canary** `canary-logd-stall-polls-only`: only the polls count, red.
#[test]
fn a_record_the_ring_left_behind_is_given_up_at_once() {
    let mut s = Stall::new();
    assert!(!s.give_up(0, 7, 128, 256), "exactly half a lap is still waited for");
    let mut s = Stall::new();
    assert!(s.give_up(0, 7, 129, 256), "past half a lap is not");
}

/// Another record, or another ring, restarts the count.
#[test]
fn a_different_record_restarts_the_wait() {
    let mut s = Stall::new();
    for _ in 1..STUCK_POLLS {
        assert!(!s.give_up(1, 40, 2, 256));
    }
    assert!(!s.give_up(1, 41, 2, 256), "the cursor moved");
    assert!(!s.give_up(0, 41, 2, 256), "another ring");
    s.clear();
    for _ in 1..STUCK_POLLS {
        assert!(!s.give_up(0, 41, 2, 256));
    }
}
