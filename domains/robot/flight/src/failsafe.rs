// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The failsafe priority chain, and the one decision upstream of it.
//!
//! Split into its own file for a reason that is not tidiness: `lib.rs` names
//! `azos_drv_*`, whose acquire paths carry RV64 assembly, so nothing in
//! it can be compiled for the host. This module names NO external crate, which
//! is what lets `tests/host/flight-tests` pull it in with `#[path]` and run it —
//! the same arrangement `path3d.rs` already uses.
//!
//! Until 2026-09-06 `check_failsafe` and `FailsafeAction` had **no test of any
//! kind**, on the host or in QEMU, and no reference anywhere in the tree
//! outside `lib.rs` and the one kernel call site. The failsafe chain of a
//! flying machine was carried entirely by review.

// ── Failsafe ────────────────────────────────────────────────────────────────

/// Failsafe priority chain result.
#[derive(Clone, Copy, PartialEq)]
pub enum FailsafeAction {
    /// No failsafe active — continue normal operation.
    None,
    /// Switch to position hold (server link lost).
    PosHold,
    /// Return to launch (RC link lost).
    RTL,
    /// Level and descend (attitude estimation failure).
    Land,
    /// Immediate motor shutoff (HW watchdog / critical failure).
    Disarm,
}

/// Check failsafe conditions.
///
/// - `attitude_age_us`: age of last attitude estimate in microseconds
/// - `rc_age_us`: age of last RC input in microseconds
/// - `server_age_us`: age of last server command in microseconds
/// Should a just-decoded RC frame be published as fresh input?
///
/// # Why this is a function and not one `if` at the call site
///
/// It is the decision that makes [`check_failsafe`]'s RC branch reachable at
/// all, and the call site is inside `domains/robot/safety-core/src/flight_ctrl.rs`'s flight task, which
/// no host test can enter. Same split, and the same reason, as
/// `irq_wait_ret` and `wake_action`.
///
/// # The failure it closes
///
/// `check_failsafe` detects RC link loss by AGE — the RC channel going stale.
/// The flight task published every frame `rc_read()` returned, including
/// frames whose failsafe flag was set, which is the receiver saying *"I have
/// lost the transmitter"*. Publishing one refreshes the channel, so the age
/// never grows, so `FailsafeAction::RTL` could not fire — and the sticks in
/// that frame are what `FlightMode::Stabilize` then flies on.
///
/// The flag itself was read in exactly one place in the tree: a telemetry
/// `rssi` of 0 versus 100, and an info print. Nothing acted on it.
///
/// This was invisible in the tree as it stands because the only `rc_init`
/// caller selects `RcMode::Simulated`, which never raises the flag. It would
/// have become a flying drone's problem on the first real SBUS decoder, and
/// it would have looked like the failsafe was broken rather than the publish.
///
/// A failsafe frame is therefore **not** fresh input: it is the absence of
/// input, and the age is how this design says so.
#[inline]
pub const fn rc_frame_is_fresh_input(failsafe: bool) -> bool {
    !failsafe
}

pub fn check_failsafe(attitude_age_us: u64, rc_age_us: u64, server_age_us: u64) -> FailsafeAction {
    // Priority 1: attitude estimation failure (>50 ms old).
    if attitude_age_us > 50_000 {
        return FailsafeAction::Land;
    }

    // Priority 2: RC link loss (>1 second).
    if rc_age_us > 1_000_000 {
        return FailsafeAction::RTL;
    }

    // Priority 3: server link loss (>3 seconds) — switch to PosHold.
    if server_age_us > 3_000_000 {
        return FailsafeAction::PosHold;
    }

    FailsafeAction::None
}

