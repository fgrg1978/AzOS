// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behaviour engine's choice: which layer drives, and at what speed.
//! Pure (no syscalls), so the host suite includes it by path.
//!
//! The safety layer is not here: the kernel caps every command with its
//! verdict on the sensor bus, the e-stop and the envelope, and the operator's
//! RC override replaces the command outright. What is left to choose, in
//! order: L1 avoids an obstacle the rangefinders see, L2 follows the brain's
//! latest command while it is fresh, L3 explores while the brain's session is
//! up. A cycle no layer wins publishes nothing, so the drivetrain's watchdog
//! stops the wheels.

/// A rangefinder reading closer than this stops the robot (mm).
pub const OBSTACLE_STOP_MM: u16 = 150;
/// Closer than this, the robot turns away to the right (mm).
pub const OBSTACLE_TURN_MM: u16 = 400;
/// The turn: left wheel forward, right wheel slow.
pub const TURN: (i32, i32) = (60, 20);
/// Exploring: slow and straight.
pub const EXPLORE: (i32, i32) = (30, 30);
/// The brain's command drives for this long after it arrives (ms).
pub const REMOTE_MAX_AGE_MS: u64 = 2_000;

/// The layers CONFIG.INI enables (`behavior_l1_enabled` .. `_l3_`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layers {
    pub avoid: bool,
    pub remote: bool,
    pub explore: bool,
}

impl Layers {
    /// Every layer on (the host tests' default).
    #[cfg(test)]
    pub const ALL: Layers = Layers { avoid: true, remote: true, explore: true };
    /// What an engine that cannot read the kernel's switches runs: the layer
    /// that only stops or turns away.
    pub const AVOID_ONLY: Layers = Layers { avoid: true, remote: false, explore: false };
}

/// The brain's latest drive command and when it arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remote {
    pub left: i32,
    pub right: i32,
    pub at_ms: u64,
}

impl Remote {
    /// The brain's command after an e-stop: a stop, as of `now_ms`. Once the
    /// operator clears the latch, the command that preceded the e-stop does
    /// not resume; the brain has to send a new one.
    pub const fn stop(now_ms: u64) -> Remote {
        Remote { left: 0, right: 0, at_ms: now_ms }
    }
}

/// What one cycle sees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    pub now_ms: u64,
    /// Front and right rangefinders; `None` for no reading.
    pub front_mm: Option<u16>,
    pub right_mm: Option<u16>,
    pub remote: Option<Remote>,
    /// The brain's session is up.
    pub session_up: bool,
}

/// The layer that won.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Winner {
    Avoid,
    Remote,
    Explore,
}

/// The command to publish this cycle, percent per wheel, and the layer that
/// chose it; `None` when no layer drives.
pub fn arbitrate(layers: Layers, i: &Inputs) -> Option<((i32, i32), Winner)> {
    if layers.avoid {
        let near = [i.front_mm, i.right_mm].into_iter().flatten().min();
        match (i.front_mm, near) {
            (_, Some(d)) if d < OBSTACLE_STOP_MM => return Some(((0, 0), Winner::Avoid)),
            (Some(f), _) if f < OBSTACLE_TURN_MM => return Some((TURN, Winner::Avoid)),
            _ => {}
        }
    }
    if layers.remote {
        if let Some(r) = i.remote {
            if i.now_ms.saturating_sub(r.at_ms) <= REMOTE_MAX_AGE_MS {
                return Some(((r.left.clamp(-100, 100), r.right.clamp(-100, 100)), Winner::Remote));
            }
        }
    }
    if layers.explore && i.session_up {
        return Some((EXPLORE, Winner::Explore));
    }
    None
}
