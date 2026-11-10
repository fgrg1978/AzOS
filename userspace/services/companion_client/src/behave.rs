// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behaviour engine's choice: which layer drives, and at what speed.
//! Pure (no syscalls), so the host suite includes it by path.
//!
//! The safety layer is not here: the kernel caps every command with its
//! verdict on the sensor bus, the e-stop and the envelope, and the operator's
//! RC override replaces the command outright. What is left to choose, in
//! order: L1 avoids an obstacle (the rangefinders are the floor, the model's
//! verdict sits on top and a missing verdict is a stop), L2 follows the
//! companion's latest command while it is fresh, L3 explores while the companion's
//! session is up. A cycle no layer wins publishes nothing, so the drivetrain's
//! watchdog stops the wheels. The companion's prediction only ever makes L1 more
//! cautious: it can narrow what the layers chose, never widen it.

/// A rangefinder reading closer than this stops the robot (mm).
pub const OBSTACLE_STOP_MM: u16 = 150;
/// Closer than this, the robot turns away to the right (mm).
pub const OBSTACLE_TURN_MM: u16 = 400;
/// The turn: left wheel forward, right wheel slow.
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
    /// that only stops or turns away.
    pub const AVOID_ONLY: Layers = Layers { avoid: true, remote: false, explore: false };
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
/// chose it; `None` when no layer drives. A prediction can only lower what the
/// layers chose, wheel by wheel: it never makes a cycle drive that would not
/// have, and never raises a wheel.
pub fn arbitrate(layers: Layers, i: &Inputs) -> Option<((i32, i32), Winner)> {
    // What the layers choose without the model's turn: the verdict may brake
    // or limit that choice, never start motion or raise a wheel.
    let floor = Inputs { ml: if i.ml == Ml::Turn { Ml::Go } else { i.ml }, predict: None, ..*i };
    let (base, base_winner) = choose(layers, &floor, Bias::None)?;
    let bias = if layers.avoid { i.predict.map_or(Bias::None, |p| p.bias(i.now_ms)) } else { Bias::None };
    let (full, full_winner) = choose(layers, i, bias).unwrap_or((base, base_winner));
    let cmd = bounded(full, base);
    Some((cmd, if cmd == base { base_winner } else { full_winner }))
}

/// `full` bounded by `base`, wheel by wheel. A wheel that would turn the other
/// way stops the whole command: a spin must not become motion forward.
fn bounded(full: (i32, i32), base: (i32, i32)) -> (i32, i32) {
    let reverses = |f: i32, b: i32| f != 0 && b != 0 && (f > 0) != (b > 0);
    if reverses(full.0, base.0) || reverses(full.1, base.1) {
        return (0, 0);
    }
    (under(full.0, base.0), under(full.1, base.1))
}

/// `hinted` bounded by `plain`: the same direction and no faster.
fn under(hinted: i32, plain: i32) -> i32 {
    if hinted == 0 || plain == 0 || (hinted > 0) != (plain > 0) {
        0
    } else {
        hinted.signum() * hinted.abs().min(plain.abs())
    }
}

fn choose(layers: Layers, i: &Inputs, bias: Bias) -> Option<((i32, i32), Winner)> {
    if layers.avoid {
        if let Some(cmd) = avoid(i, bias) {
            return Some((cmd, Winner::Avoid));
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

/// L1: the rangefinders are the floor and the model's verdict sits on top; the
/// more cautious of the two wins. A stop beats a turn.
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
