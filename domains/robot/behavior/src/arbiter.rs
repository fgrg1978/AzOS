// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Subsumption arbiter — iterates layers L0→L3, first `valid` output wins.
//!
//! **L0 (emergency stop) is the canonical statement of the "always runs /
//! always applied / cannot be disabled" invariant** — see the comment on the
//! `layer_emergency_stop` call inside `arbitrate()` below for the evidence.
//! `domains/robot/behavior/src/safety.rs` and `domains/robot/behavior/src/layers.rs` state
//! the same guarantee but point back here rather than re-deriving it, so the
//! claim has one place to go stale instead of three.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use crate::types::*;
use crate::layers;
use wcet_macro::wcet;

/// Per-layer enable flags.  Index 0 is always true.
static LAYER_ENABLED: [AtomicBool; NUM_LAYERS] = [
    AtomicBool::new(true),  // L0: emergency-stop — always on
    AtomicBool::new(true),  // L1: avoid-obstacle
    AtomicBool::new(true),  // L2: remote-vla
    AtomicBool::new(true),  // L3: explore
];

/// Last winning layer (for status display).
static LAST_WINNER: AtomicU8 = AtomicU8::new(0xFF);

/// Layer names for display.
pub const LAYER_NAMES: [&str; NUM_LAYERS] = [
    "emergency-stop",
    "avoid-obstacle",
    "remote-vla",
    "explore",
];

/// Run the subsumption arbiter.  Iterates L0→L3; first layer that produces
/// a valid output wins.
#[wcet(80_us)]
pub fn arbitrate(state: &SensorState, _mlp: &MlpResult) -> BehaviorOutput {
    // ── L0: emergency stop — canonical invariant statement ─────────────────
    //
    // RUNS unconditionally: unlike L1-L3 below, this call has no
    // `LAYER_ENABLED[..]` check and no `#[cfg]` gate. `layer_set_enabled`
    // explicitly no-ops for index 0 (see below), there is no
    // `behavior_l0_enabled` key in CONFIG.INI (unlike l1/l2/l3, wired in
    // `crates/core/config`), and the `behavior disable`/`enable` shell command
    // refuses layer 0 by name. `LAYER_ENABLED[0]` itself is read by nothing
    // except the status display (`layer_statuses`) — nothing in this crate
    // ever gates the call on it.
    //
    // APPLIED whenever it should be, not just called: `layer_emergency_stop`
    // delegates to `safety::safety_check`, whose only `SafetyAction::None`
    // path maps to `MotorOutput::none()` (`valid == false`) — that is the
    // "no violation fired" case. Every other action
    // (EmergencyStop/LandNow/ReturnToLaunch/SpeedLimit) maps to
    // `MotorOutput::some(..)` (`valid == true`). So `out.cmd.valid` is
    // exactly "a real violation fired," and `if out.cmd.valid { return }`
    // is not a fail-open window: it is what makes L0 *subsume* the layers
    // below rather than replace them permanently. Falling through here
    // means "L0 found nothing to override this tick," never "L0 skipped a
    // violation." Exercised by `tests/host/behavior-tests`, module
    // `arbitration` (`arbitrate_returns_l0_output_on_a_real_violation` /
    // `arbitrate_falls_through_to_lower_layers_when_l0_is_clean`).
    {
        let out = layers::layer_emergency_stop(state);
        if out.cmd.valid {
            LAST_WINNER.store(0, Ordering::Relaxed);
            return out;
        }
    }

    // L1: avoid obstacle (MLP-based, only if no-ml is not set)
    // ── RC manual override (wave 15, Kconfig `RC_INPUT`) ─────────────────
    //
    // The operator's sticks outrank autonomy but not safety: L0 above
    // returned already if it had anything to say, and L1's STOP (an
    // obstacle, or a cycle with no ML verdict, which fails closed) still
    // stops a manually driven robot. L1's steering, L2 (the brain) and L3 do
    // not override the operator. The command then reaches the wheels only
    // through `rt_motor`'s motor envelope and the actuation gate.
    #[cfg(feature = "rc-input")]
    if state.rc_manual.valid {
        #[cfg(not(feature = "no-ml"))]
        if LAYER_ENABLED[1].load(Ordering::Relaxed) {
            let out = layers::layer_avoid_obstacle(state, _mlp);
            if out.cmd.valid && out.cmd.speed_l == 0 && out.cmd.speed_r == 0 {
                LAST_WINNER.store(1, Ordering::Relaxed);
                return out;
            }
        }
        LAST_WINNER.store(2, Ordering::Relaxed);
        return BehaviorOutput { cmd: state.rc_manual, layer: 2 };
    }

    #[cfg(not(feature = "no-ml"))]
    if LAYER_ENABLED[1].load(Ordering::Relaxed) {
        let out = layers::layer_avoid_obstacle(state, _mlp);
        if out.cmd.valid {
            LAST_WINNER.store(1, Ordering::Relaxed);
            return out;
        }
    }

    // L2: remote VLA
    if LAYER_ENABLED[2].load(Ordering::Relaxed) {
        let out = layers::layer_remote_vla(state);
        if out.cmd.valid {
            LAST_WINNER.store(2, Ordering::Relaxed);
            return out;
        }
    }

    // L3: explore / offline patrol
    // When offline mode is active, use waypoint patrol instead of default wander.
    //
    // **Owner decision, 2026-09-26 (V1.5 / U08-2): no brain, no exploration.**
    // Before this decision `layer_explore` returned `some(30, 30)`
    // unconditionally — a robot that has NEVER had a brain connected drove
    // forward from the moment it booted, uncommanded and (until Q1.3) with
    // no record of it. Gated here, not by disabling the layer, on
    // `camera_tx::control_session().up`: the SAME flag the camera task
    // already reads to decide whether the brain's control connection is up,
    // written by the behavior task's own connection lifecycle
    // (`control_session_ready`/`control_session_ended`) — not a new signal
    // invented for this. `offline_is_active()`'s waypoint patrol is
    // deliberately NOT gated the same way: that path exists FOR the
    // brain-was-connected-then-lost case (`kernel/src/tasks/behavior.rs`'s `offline_activate`),
    // and with no waypoints it already answers `(0, 0)`
    // (`offline::layer_offline_patrol`) — gating it on `control_session().up`
    // would be redundant with what it already does and would also block the
    // one case it exists to serve (session down, patrol the last plan).
    if LAYER_ENABLED[3].load(Ordering::Relaxed)
        && (crate::offline::offline_is_active() || crate::camera_tx::control_session().up)
    {
        let out = if crate::offline::offline_is_active() {
            crate::offline::layer_offline_patrol(state)
        } else {
            layers::layer_explore(state)
        };
        if out.cmd.valid {
            LAST_WINNER.store(3, Ordering::Relaxed);
            return out;
        }
    }

    // No layer produced output — return invalid
    BehaviorOutput {
        cmd: MotorOutput::none(),
        layer: 0xFF,
    }
}

/// Enable or disable a layer.  Layer 0 cannot be disabled.
pub fn layer_set_enabled(layer: usize, enabled: bool) {
    if layer == 0 || layer >= NUM_LAYERS { return; }
    LAYER_ENABLED[layer].store(enabled, Ordering::Relaxed);
}

/// Check if a layer is enabled.
pub fn layer_is_enabled(layer: usize) -> bool {
    if layer >= NUM_LAYERS { return false; }
    LAYER_ENABLED[layer].load(Ordering::Relaxed)
}

/// Return the index of the last winning layer (0xFF if none).
pub fn last_winner() -> u8 {
    LAST_WINNER.load(Ordering::Relaxed)
}

/// Return status of all layers.
pub fn layer_statuses() -> [LayerStatus; NUM_LAYERS] {
    let winner = LAST_WINNER.load(Ordering::Relaxed);
    let mut out = [LayerStatus { layer: 0, name: "", enabled: false, winning: false }; NUM_LAYERS];
    for i in 0..NUM_LAYERS {
        out[i] = LayerStatus {
            layer:   i as u8,
            name:    LAYER_NAMES[i],
            enabled: LAYER_ENABLED[i].load(Ordering::Relaxed),
            winning: winner == i as u8,
        };
    }
    out
}
