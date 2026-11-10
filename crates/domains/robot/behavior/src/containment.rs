// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a lost companion session (or verdict) arms, per robot profile. Pure
//! and dependency-free: the kernel (`azos_safety_core::frames`) and the ring-3
//! behaviour engine (`companion_client`) both compile this file, so they cannot
//! disagree on what each profile does.
//!
//! * Wheeled and Ackermann: stop. The drivetrain coasts at duty 0 and the
//!   kernel's degraded mode refuses every motor write until the operator's
//!   signed clear.
//! * Drone: motors are never cut in the air. The engine starts no manoeuvre and
//!   the kernel hands control to the flight failsafe (`azos_flight::failsafe`:
//!   hold position, then a controlled landing). Motors stop only on the
//!   ground (disarmed) or on an e-stop.
//! * Humanoid: hold a safe posture. There is no posture code in the tree, so the
//!   hold is the stop: every joint drive is halted through the motor gate, the
//!   same as the ground profiles, and the posture hold is the one place a
//!   posture controller attaches.

/// The engine's report of the companion link to the kernel (`PKT_LINK_STATE`
/// payload byte). The session is up: also sent as a beat while it stays up.
pub const LINK_UP: u8 = 1;
/// An established session ended.
pub const LINK_LOST: u8 = 0;
/// The inference verdict has been missing for [`VERDICT_LOSS_MS`].
pub const LINK_VERDICT_LOST: u8 = 2;
/// The engine reports a live session this often (ms).
pub const LINK_BEAT_MS: u64 = 250;
/// The kernel arms containment when a session reported up has gone this long
/// without a report (ms): the engine stopped.
pub const LINK_SILENCE_MS: u64 = 1_000;
/// A session whose companion sends no frame for this long is lost (ms).
pub const LINK_RX_SILENCE_MS: u64 = 3_000;
/// A verdict missing continuously for this long counts as lost (ms).
pub const VERDICT_LOSS_MS: u64 = 2_000;

/// The robot types `ROBOT_TYPE_ID` numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Wheeled,
    Drone,
    Humanoid,
    Ackermann,
}

/// What losing the session does under a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effects {
    /// Drives are stopped: duty 0 now and every motor write refused after.
    pub stop_drive: bool,
    /// The posture hold runs.
    pub posture_hold: bool,
    /// Control goes to the flight failsafe.
    pub flight_handoff: bool,
}

impl Profile {
    pub const fn from_id(id: u8) -> Option<Profile> {
        match id {
            0 => Some(Profile::Wheeled),
            1 => Some(Profile::Drone),
            2 => Some(Profile::Humanoid),
            3 => Some(Profile::Ackermann),
            _ => None,
        }
    }

    pub const fn effects(self) -> Effects {
        if cfg!(feature = "drone-cut-canary") && matches!(self, Profile::Drone) {
            return Effects { stop_drive: true, posture_hold: false, flight_handoff: true };
        }
        if cfg!(feature = "ground-drives-canary") && matches!(self, Profile::Wheeled) {
            return Effects { stop_drive: false, posture_hold: false, flight_handoff: false };
        }
        match self {
            Profile::Wheeled | Profile::Ackermann => Effects { stop_drive: true, posture_hold: false, flight_handoff: false },
            Profile::Drone => Effects { stop_drive: false, posture_hold: false, flight_handoff: true },
            Profile::Humanoid => Effects { stop_drive: true, posture_hold: true, flight_handoff: false },
        }
    }
}
