// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/actuation/src/liveness.rs`: the hardware watchdog is fed only
//! while both safety heartbeats advance.

use crate::liveness::Feed;

const LIMIT: u32 = 4;
const GRACE: u64 = 400;

/// **A stalled enforcer stops the feed**, as a stalled control loop does, once
/// past both grace bounds; a heartbeat that never ran does not stall it, and
/// one that advances again resumes it.
///
/// **Canary.** Feed on the control heartbeat alone: the enforcer's stall feeds.
#[test]
fn a_stalled_enforcer_stops_the_watchdog_feed() {
    let f = Feed::new();
    assert!(f.kick(0, 0, 0, LIMIT, GRACE), "nothing has run yet: the boot must not reset");
    let mut t = 0;
    for beat in 1..=10u32 {
        t += 100;
        assert!(f.kick(beat, beat, t, LIMIT, GRACE), "both advancing at {t}");
    }
    let (control, enforce) = (10u32, 10u32);
    let mut fed = true;
    let mut c = control;
    for _ in 0..20 {
        t += 100;
        c += 1;
        fed = f.kick(c, enforce, t, LIMIT, GRACE);
    }
    assert!(!fed, "the enforcer stood still 2 s and the watchdog was still fed");
    t += 100;
    assert!(f.kick(c + 1, enforce + 1, t, LIMIT, GRACE), "the enforcer advanced again and the feed did not resume");
    for _ in 0..20 {
        t += 100;
        fed = f.kick(c + 1, enforce + 1 + (t as u32), t, LIMIT, GRACE);
    }
    assert!(!fed, "the control loop stood still 2 s and the watchdog was still fed");
    let quiet = Feed::new();
    for i in 1..=30u32 {
        assert!(quiet.kick(i, 0, i as u64 * 100, LIMIT, GRACE), "an image without an enforcer stalled the feed");
    }
}

/// Within the grace window a pause is not a stall: four calls or 400 ticks.
#[test]
fn a_pause_inside_the_grace_feeds() {
    let f = Feed::new();
    assert!(f.kick(1, 1, 100, LIMIT, GRACE));
    for i in 1..=LIMIT {
        assert!(f.kick(1 + i, 1, 100 + i as u64, LIMIT, GRACE), "call {i} of the tick bound");
    }
    assert!(f.kick(1 + LIMIT + 1, 1, 500, LIMIT, GRACE), "inside the time bound");
    assert!(!f.kick(1 + LIMIT + 2, 1, 501, LIMIT, GRACE), "past both bounds");
}
