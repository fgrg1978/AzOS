// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behaviour engine's choice: which layer drives, and at what speed.
//! Pure (no syscalls), so the host suite includes it by path.
//!
//! The safety layer is not here: the kernel caps every command with its
//! verdict on the sensor bus, the e-stop and the envelope, and the operator's
//! RC override replaces the command outright. What is left to choose, in
//! order: L2 follows the companion's latest command while it is fresh, L3
//! explores while the companion's session is up, and L1 bounds whichever of the
//! two asked (the rangefinders are the floor, the model's verdict sits on top
//! and a missing verdict is a stop). L1 only brakes or limits: it never starts
//! motion from standstill and never raises a wheel above what was asked. A cycle
//! with nothing asked publishes nothing, so the drivetrain's watchdog stops the
//! wheels. The companion's prediction only ever makes L1 more cautious.
//!
//! What a lost session does is the profile's (`containment.rs`), not this file's.

/// A rangefinder reading closer than this stops the robot (mm).
pub const OBSTACLE_STOP_MM: u16 = 150;
/// Closer than this, the robot turns away to the right (mm).
pub const OBSTACLE_TURN_MM: u16 = 400;
/// The turn L1 limits a command to: left wheel forward, right wheel slow.
pub const TURN: (i32, i32) = (60, 20);
/// Exploring: slow and straight.
pub const EXPLORE: (i32, i32) = (30, 30);
/// The companion's command drives for this long after it arrives (ms).
pub const REMOTE_MAX_AGE_MS: u64 = 2_000;
/// The actuator type of a differential drive (`companion_protocol::ACT_DIFF_DRIVE`).
pub const ACTUATOR_DIFF_DRIVE: u8 = 0;
/// A prediction is of the next command: it biases L1 for this long (ms).
pub const PREDICT_MAX_AGE_MS: u64 = 500;
/// A prediction the companion is less sure of than this is ignored.
pub const PREDICT_MIN_CONFIDENCE: u8 = 128;
/// A predicted stop or reverse widens the turn-away distance by this (mm).
pub const PREDICT_OBSTACLE_MARGIN_MM: u16 = 300;
/// A predicted turn (the wheels differ by at least [`PREDICT_TURN_DELTA`])
/// widens it by this (mm).
pub const PREDICT_TURN_MARGIN_MM: u16 = 150;
/// Percent between the predicted wheels that makes the prediction a turn.
pub const PREDICT_TURN_DELTA: i32 = 30;

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
    /// that only brakes or limits, so nothing drives.
    pub const AVOID_ONLY: Layers = Layers { avoid: true, remote: false, explore: false };
}

/// The verdict's loss as the engine reports it: a verdict that had been
/// coming is missing without a break for [`crate::containment::VERDICT_LOSS_MS`].
/// A model that never answered (still starting, or refused at boot) is held at
/// a stop by L1 but is not a loss. Fires once per stretch.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerdictWatch {
    had: bool,
    missing_since: Option<u64>,
    reported: bool,
}

impl VerdictWatch {
    pub const fn new() -> Self {
        Self { had: false, missing_since: None, reported: false }
    }

    /// One cycle: `true` the moment the verdict has been missing long enough.
    pub fn step(&mut self, ml: Ml, now_ms: u64) -> bool {
        if ml != Ml::Missing {
            self.had |= matches!(ml, Ml::Go | Ml::Turn | Ml::Stop);
            self.missing_since = None;
            self.reported = false;
            return false;
        }
        if !self.had {
            return false;
        }
        let since = *self.missing_since.get_or_insert(now_ms);
        let lost = !self.reported && now_ms.saturating_sub(since) >= crate::containment::VERDICT_LOSS_MS;
        self.reported |= lost;
        lost
    }
}

/// A session whose companion has sent nothing since `last_rx_ms` is lost: an
/// open socket is not a session.
pub fn rx_silent(now_ms: u64, last_rx_ms: u64) -> bool {
    if cfg!(feature = "rx-silence-canary") {
        return false;
    }
    now_ms.saturating_sub(last_rx_ms) > crate::containment::LINK_RX_SILENCE_MS
}

/// The companion's latest drive command and when it arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remote {
    pub left: i32,
    pub right: i32,
    pub at_ms: u64,
}

impl Remote {
    /// The companion's command after an e-stop: a stop, as of `now_ms`. Once the
    /// operator clears the latch, the command that preceded the e-stop does
    /// not resume; the companion has to send a new one.
    pub const fn stop(now_ms: u64) -> Remote {
        Remote { left: 0, right: 0, at_ms: now_ms }
    }
}

/// The inference service's verdict for this cycle, as L1 acts on it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ml {
    /// No model is asked: the topology grants no inference endpoint, or a
    /// rangefinder gave no reading to build the input from.
    #[default]
    Off,
    Go,
    Turn,
    Stop,
    /// A verdict was due and none came (late, refused, unsigned model, a
    /// reply that is not a class): L1 stops.
    Missing,
}

/// The companion's prediction of its next command and how sure it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Predict {
    pub left: i32,
    pub right: i32,
    pub confidence: u8,
    pub at_ms: u64,
}

/// What a prediction asks of L1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bias {
    None,
    Obstacle,
    Turn,
}

impl Predict {
    /// A `PKT_PREDICT` payload: an actuator command (type, channels, flags,
    /// one signed 16-bit percent per channel) and one confidence byte. `None`
    /// for anything else, and for an emergency, which has its own frame.
    pub fn decode(payload: &[u8], now_ms: u64) -> Option<Predict> {
        let n = *payload.get(1)? as usize;
        let flags = *payload.get(2)?;
        if payload[0] != ACTUATOR_DIFF_DRIVE || n < 2 || payload.len() != 3 + 2 * n + 1 || flags & 0x01 != 0 {
            return None;
        }
        let wheel = |k: usize| i16::from_le_bytes([payload[3 + 2 * k], payload[4 + 2 * k]]) as i32;
        Some(Predict { left: wheel(0), right: wheel(1), confidence: payload[payload.len() - 1], at_ms: now_ms })
    }

    fn bias(&self, now_ms: u64) -> Bias {
        if self.confidence < PREDICT_MIN_CONFIDENCE || now_ms.saturating_sub(self.at_ms) > PREDICT_MAX_AGE_MS {
            return Bias::None;
        }
        if self.left <= 0 && self.right <= 0 {
            Bias::Obstacle
        } else if self.left > 0 && self.right > 0 && (self.left - self.right).abs() >= PREDICT_TURN_DELTA {
            Bias::Turn
        } else {
            Bias::None
        }
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
    /// The companion's session is up.
    pub session_up: bool,
    pub ml: Ml,
    pub predict: Option<Predict>,
}

/// The layer that won.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Winner {
    Avoid,
    Remote,
    Explore,
}

/// The command to publish this cycle, percent per wheel, and the layer that
/// chose it; `None` when no layer drives. Only an upstream command (the
/// companion's, or L3 exploring under a session) starts motion; L1 only bounds
/// it, wheel by wheel: a stop, or a turn that is no faster and never the other
/// way than what was asked. A cycle with nothing upstream publishes nothing,
/// whatever the rangefinders say, and the drivetrain's watchdog holds the wheels
/// at standstill.
pub fn arbitrate(layers: Layers, i: &Inputs) -> Option<((i32, i32), Winner)> {
    if cfg!(feature = "l1-start-canary") && upstream(layers, i).is_none() {
        return layers.avoid.then(|| avoid(i, Bias::None)).flatten().map(|c| (c, Winner::Avoid));
    }
    let (asked, winner) = upstream(layers, i)?;
    let bias = if layers.avoid { i.predict.map_or(Bias::None, |p| p.bias(i.now_ms)) } else { Bias::None };
    let cmd = match layers.avoid.then(|| avoid(i, bias)).flatten() {
        Some(limit) if cfg!(feature = "l1-raise-canary") => limit,
        Some(limit) => bounded(limit, asked),
        None => asked,
    };
    Some((cmd, if cmd == asked { winner } else { Winner::Avoid }))
}

/// `limit` bounded by `asked`, wheel by wheel. A wheel that would turn the other
/// way stops the whole command: a spin must not become motion forward.
fn bounded(limit: (i32, i32), asked: (i32, i32)) -> (i32, i32) {
    let reverses = |f: i32, b: i32| f != 0 && b != 0 && (f > 0) != (b > 0);
    if reverses(limit.0, asked.0) || reverses(limit.1, asked.1) {
        return (0, 0);
    }
    (under(limit.0, asked.0), under(limit.1, asked.1))
}

/// `limit` bounded by `asked`: the same direction and no faster.
fn under(limit: i32, asked: i32) -> i32 {
    if limit == 0 || asked == 0 || (limit > 0) != (asked > 0) {
        0
    } else {
        limit.signum() * limit.abs().min(asked.abs())
    }
}

/// What the layers above L1 ask: the companion's fresh command, else exploring
/// while the session is up.
fn upstream(layers: Layers, i: &Inputs) -> Option<((i32, i32), Winner)> {
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

/// L1: the rangefinders are the floor and the model's verdict sits on top; the
/// more cautious of the two wins. A stop beats a turn. The result is a bound on
/// what the layers above ask, never a command of its own.
fn avoid(i: &Inputs, bias: Bias) -> Option<(i32, i32)> {
    let near = [i.front_mm, i.right_mm].into_iter().flatten().min();
    let margin = match bias {
        Bias::None => 0,
        Bias::Obstacle => PREDICT_OBSTACLE_MARGIN_MM,
        Bias::Turn => PREDICT_TURN_MARGIN_MM,
    };
    let turn_below = OBSTACLE_TURN_MM.saturating_add(margin);
    if matches!(i.ml, Ml::Stop | Ml::Missing) || near.is_some_and(|d| d < OBSTACLE_STOP_MM) {
        return Some((0, 0));
    }
    if i.ml == Ml::Turn || i.front_mm.is_some_and(|f| f < turn_below) {
        return Some(TURN);
    }
    None
}

/// A rangefinder reading the engine may act on: this cycle's read succeeded
/// (a failed read leaves the last distance in place, which is not a reading)
/// and the sensor gave a distance (0 is none).
pub fn range_reading(raw: u16, fresh: bool) -> Option<u16> {
    if cfg!(feature = "range-stale-canary") {
        return (raw != 0).then_some(raw);
    }
    (fresh && raw != 0).then_some(raw)
}
