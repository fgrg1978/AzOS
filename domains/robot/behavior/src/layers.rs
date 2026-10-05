// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Behavior layers — pure functions, no side effects.
//!
//! Each layer receives `SensorState` (and optionally `MlpResult`) and returns
//! a `BehaviorOutput`.  The arbiter calls them in priority order L0→L3;
//! the first `valid` output wins.

use crate::types::*;

// ── L0: Emergency stop ────────────────────────────────────────────────────────
// Invariant + evidence (always-runs / always-applied / cannot-be-disabled):
// canonical statement is the comment on the `layer_emergency_stop` call
// inside `arbitrate()` in `domains/robot/behavior/src/arbiter.rs`.

/// Emergency stop: runs full safety profile for the current robot type.
/// Checks: fall, spin, battery, tilt, obstacle, GPS (drone), comms timeout.
/// Uses `crate::safety::safety_check()` for type-aware checks.
pub fn layer_emergency_stop(state: &SensorState) -> BehaviorOutput {
    use crate::safety::{safety_check, SafetyAction};

    let result = safety_check(state);

    match result.action {
        SafetyAction::None => {
            BehaviorOutput { cmd: MotorOutput::none(), layer: 0 }
        }
        SafetyAction::EmergencyStop | SafetyAction::LandNow => {
            BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 0 }
        }
        SafetyAction::ReturnToLaunch => {
            // For RTL: stop motors here, behavior_task handles RTL navigation
            BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 0 }
        }
        SafetyAction::SpeedLimit(max_speed) => {
            // Clamp current command speed — let higher layers run but limited
            BehaviorOutput { cmd: MotorOutput::some(max_speed, max_speed), layer: 0 }
        }
    }
}

// ── L1: Avoid obstacle (local MLP) ──────────────────────────────────────────

/// Obstacle avoidance using local MLP inference result.
/// Maps predicted class to motor speeds.
/// Gated by `#[cfg(not(feature = "no-ml"))]` at call site.
#[cfg(not(feature = "no-ml"))]
pub fn layer_avoid_obstacle(_state: &SensorState, mlp: &MlpResult) -> BehaviorOutput {
    if !mlp.valid {
        return BehaviorOutput { cmd: MotorOutput::none(), layer: 1 };
    }

    let cmd = match mlp.class {
        0 => MotorOutput::some(70, 70),   // go_forward
        1 => MotorOutput::some(80, 30),   // turn_right
        2 => MotorOutput::some(0, 0),     // stop (obstacle)
        _ => MotorOutput::none(),
    };
    BehaviorOutput { cmd, layer: 1 }
}

// ── L2: Remote VLA ──────────────────────────────────────────────────────────

/// How stale a remote action may be and still drive the wheels, in seconds.
///
/// Stated in SECONDS, not ticks, on purpose: the tick rate is a per-board
/// property (`timebase::TIMER_FREQ` — 10 MHz under QEMU, 4 MHz on VisionFive 2,
/// 24 MHz on K1) and a tick count hardcoded for one board silently means a
/// different timeout on the others. See the conversion at the use site.
pub const REMOTE_ACTION_MAX_AGE_S: u64 = 2;

/// Remote VLA: uses the last action from the external VLA server.
/// Timeout: if the action is older than [`REMOTE_ACTION_MAX_AGE_S`] seconds,
/// invalidate it.
pub fn layer_remote_vla(state: &SensorState) -> BehaviorOutput {
    let act = &state.remote_action;
    if !act.valid || act.cmd == CMD_NONE {
        return BehaviorOutput { cmd: MotorOutput::none(), layer: 2 };
    }

    // Age in mtime ticks, converted through the BOARD's CLINT frequency.
    //
    // **This was `age > 20_000_000` with a comment reading "2 seconds at
    // 10 MHz CLINT" until 2026-09-18.** 10 MHz is QEMU's rate
    // (`platform.rs`, qemu block); the VisionFive 2 — the board that has the
    // motors — runs its mtime at 4 MHz, which `platform.rs:80` marks "←
    // critical difference", and the K1 at 24 MHz. So the gate that decides
    // whether a stale command from the brain still drives the wheels was
    // **5 seconds on real hardware** instead of 2, and 0.83 s on K1. A dead
    // brain link kept commanding the motors two and a half times longer than
    // designed, on the only target where that moves anything.
    let age = state.timestamp.saturating_sub(act.received_at);
    if age > REMOTE_ACTION_MAX_AGE_S * azos_drv_sys::timebase::TIMER_FREQ {
        return BehaviorOutput { cmd: MotorOutput::none(), layer: 2 };
    }

    match act.cmd {
        CMD_STOP => {
            BehaviorOutput { cmd: MotorOutput::some(0, 0), layer: 2 }
        }
        CMD_MOTOR => {
            // actions[0] = speed_l milli-units (-1000..+1000), divide by 10 → -100..+100
            let speed_l = (act.actions[0] as i32) / 10;
            let speed_r = (act.actions[1] as i32) / 10;
            BehaviorOutput { cmd: MotorOutput::some(speed_l, speed_r), layer: 2 }
        }
        _ => BehaviorOutput { cmd: MotorOutput::none(), layer: 2 },
    }
}

// ── L3: Explore (placeholder) ───────────────────────────────────────────────

/// Default exploration: drive forward slowly.
pub fn layer_explore(_state: &SensorState) -> BehaviorOutput {
    BehaviorOutput { cmd: MotorOutput::some(30, 30), layer: 3 }
}
