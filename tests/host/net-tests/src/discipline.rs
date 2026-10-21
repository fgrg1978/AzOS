// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the SNTP client hands the clock discipline: the four timestamps of an
//! exchange (`ntp::Exchange`), the offset and delay they give, and the
//! discipline fed from a real `ntp_sync_with_yield`.
//!
//! The loops themselves are tested in `drivers-tests/src/discipline.rs`; this
//! file is the join: a sample that goes in with the wrong sign, the wrong
//! stamp or the wrong unit steps the wall clock to the wrong time.
//!
//! Wired by `mod discipline;` (`#[cfg(test)]`) in `lib.rs`.

use crate::conformance_ntp::{begin, reply_with, UNIX_2026_09_13};
use crate::ntp::{self, Exchange};
use std::sync::Mutex;

#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/clockdisc.rs"]
mod clockdisc;
use clockdisc::{source, Discipline, Params, Verdict};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;

/// An exchange on a clock that is `behind_ns` behind the server's, over a
/// path of `out_ns` there and `back_ns` back, the server holding the request
/// `hold_ns`; the client's counter reads `t1` when it sends. The wall clock
/// reads the counter plus `real` (the offset the vDSO publishes).
fn exchange(t1: u64, real: u64, behind_ns: u64, out_ns: u64, hold_ns: u64, back_ns: u64) -> Exchange {
    // The server's clock at T1 is our wall clock then plus how far we are behind.
    let server_at_t1 = t1 + real + behind_ns;
    Exchange {
        t1_mono_ns: t1,
        t2_unix_ns: server_at_t1 + out_ns,
        t3_unix_ns: server_at_t1 + out_ns + hold_ns,
        t4_mono_ns: t1 + out_ns + hold_ns + back_ns,
    }
}

/// **The offset is the server's time minus ours, positive when we are behind,
/// and the delay is the path, not the server's holding time.** 20 ms each
/// way, 1 ms held, a clock 3 s behind: offset 3 s exactly, delay 40 ms.
/// **Canary:** swapping the subtraction gives -3 s; using T3 - T1 for the
/// delay gives 41 ms.
#[test]
fn offset_is_server_minus_client_and_delay_excludes_the_hold() {
    let ex = exchange(100 * SEC, 0, 3 * SEC, 20 * MS, MS, 20 * MS);
    assert_eq!(ex.measure(0), (3 * SEC as i64, 40 * MS));
    // Ahead by 3 s: the same exchange, the server's clock 3 s behind ours.
    let ahead = Exchange { t2_unix_ns: ex.t2_unix_ns - 6 * SEC, t3_unix_ns: ex.t3_unix_ns - 6 * SEC, ..ex };
    assert_eq!(ahead.measure(0), (-(3 * SEC as i64), 40 * MS));
}

/// **The wall clock is the counter plus the published real offset.** The same
/// exchange measured against a clock already 3 s ahead of the counter finds
/// it right: offset 0.
#[test]
fn the_real_offset_is_part_of_our_clock() {
    let ex = exchange(100 * SEC, 3 * SEC, 0, 20 * MS, MS, 20 * MS);
    assert_eq!(ex.measure(3 * SEC), (0, 40 * MS));
    assert_eq!(ex.measure(0), (3 * SEC as i64, 40 * MS), "against the bare counter it is 3 s ahead of us");
}

/// A path longer one way than the other puts half the difference into the
/// offset (the error SNTP cannot see): 30 ms out and 10 ms back reads 10 ms
/// late; the delay is still the total.
#[test]
fn path_asymmetry_is_half_in_the_offset() {
    let ex = exchange(100 * SEC, 0, 0, 30 * MS, 0, 10 * MS);
    assert_eq!(ex.measure(0), (10 * MS as i64, 40 * MS));
}

/// A server whose holding time exceeds the round trip (a stepped clock under
/// the exchange, or stamps out of order) has no negative path: the delay is 0.
#[test]
fn a_negative_delay_is_zero() {
    let ex = Exchange { t1_mono_ns: 5 * SEC, t4_mono_ns: 5 * SEC + MS, t2_unix_ns: 9 * SEC, t3_unix_ns: 9 * SEC + 10 * MS };
    assert_eq!(ex.measure(0).1, 0);
}

/// The Unix times of 2026 are 1.8e18 ns against a counter near zero: the
/// subtractions run in 128 bits and the offset still fits.
#[test]
fn a_boot_exchange_measures_the_whole_unix_time() {
    let unix = UNIX_2026_09_13 as u64 * SEC;
    let ex = Exchange { t1_mono_ns: SEC, t4_mono_ns: SEC + 2 * MS, t2_unix_ns: unix, t3_unix_ns: unix };
    let (off, delay) = ex.measure(0);
    assert_eq!(off, unix as i64 - SEC as i64 - MS as i64, "midpoint of the exchange");
    assert_eq!(delay, 2 * MS);
}

static FED: Mutex<Option<Discipline>> = Mutex::new(None);
static MEASURED: Mutex<Vec<(Exchange, i64, u64, Verdict)>> = Mutex::new(Vec::new());

/// The kernel's sink, reduced to its two steps: measure against the real
/// offset the page holds (0: nothing has set it), feed the discipline. It stays
/// installed for the rest of the run, so it only records.
fn feed(ex: &Exchange) {
    let (off, delay) = ex.measure(0);
    let mut d = FED.lock().unwrap_or_else(|e| e.into_inner());
    let d = d.get_or_insert_with(|| Discipline::new(Params::DEFAULT));
    let v = d.sample(ex.t4_mono_ns, off, delay, source::NTP);
    MEASURED.lock().unwrap_or_else(|e| e.into_inner()).push((*ex, off, delay, v));
}

/// **A real `ntp_sync_with_yield` feeds the discipline with the time the server told.**
/// The canned reply is for 2026-09-13T00:00:00.5Z, received 1 s before it was
/// sent (the derivation in `conformance_ntp.rs`). The offset is the midpoint
/// of the server's two stamps (0.5 s before T3) minus the midpoint of ours,
/// and the first sample from an unset clock is the boot step by that offset.
/// A client that read the Transmit Timestamp for both stamps would step by
/// 0.5 s more.
/// **Canary:** `measure` with T2 = T3 fails the equality.
#[test]
fn an_ntp_sync_steps_the_clock_by_the_servers_midpoint() {
    let _g = begin();
    *FED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    MEASURED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ntp::set_exchange_sink(feed);
    reply_with([0xEE, 0x50, 0x66, 0x00, 0x80, 0x00, 0x00, 0x00]);
    assert_eq!(ntp::ntp_sync_with_yield(core::hint::spin_loop), UNIX_2026_09_13);

    let m = MEASURED.lock().unwrap();
    assert_eq!(m.len(), 1);
    let (ex, off, delay, verdict) = m[0];
    let t3 = UNIX_2026_09_13 as u64 * SEC + SEC / 2;
    assert_eq!(ex.t3_unix_ns, t3);
    assert_eq!(ex.t2_unix_ns, t3 - SEC);
    let ours_mid = (ex.t1_mono_ns + ex.t4_mono_ns) / 2;
    assert_eq!(off, (t3 - SEC / 2) as i64 - ours_mid as i64, "server midpoint minus our midpoint");
    assert_eq!(delay, 0, "the 1 s hold exceeds the instant exchange: no negative path");
    assert_eq!(verdict, Verdict::Stepped { delta_ns: off, limit_ns: 0 }, "the boot step");
    let snap = FED.lock().unwrap().unwrap().snapshot();
    assert_eq!(snap.steps, 1);
    assert_eq!(snap.source, source::NTP);
}
