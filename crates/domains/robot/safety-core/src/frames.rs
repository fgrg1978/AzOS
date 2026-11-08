// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's answer to the brain-protocol frames that ask for authority:
//! an e-stop, degraded mode and the semantic level, a mode change (the
//! operator's signed e-stop release and device-hold release), a payload or
//! configuration effect, and the low-confidence flag of an actuator command.
//! The behaviour engine parses the link and hands each such frame's payload
//! here; the checks, the effects and their records are the kernel's. A frame
//! of a type the protocol does not define is recorded here too.

use azos_behavior::brain_protocol::*;
use azos_behavior::logger;
use azos_behavior::safety;
use azos_drv_sys::kprintln;

/// What the kernel did with a frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    /// It was an authority frame and is answered.
    Handled,
    /// An actuator command: its confidence is noted, the motion is the
    /// engine's to choose.
    Actuator,
    /// A frame the engine reads itself (`PKT_PREDICT`).
    NotAuthority,
}

azos_common::ro_hook! {
    /// The board's buzzer as a configuration frame drives it: beep, siren,
    /// off. Set by the kernel at boot.
    static BUZZER: [fn() -> bool; 3];
}

/// Install the buzzer's three calls (the kernel, at boot, once).
pub fn set_buzzer(beep: fn() -> bool, siren: fn() -> bool, off: fn() -> bool) {
    BUZZER.set([beep, siren, off]);
}

/// The `Authority` interface's handler: a frame the ring-3 behaviour engine
/// submits (`azos_syscall::authority_host`).
pub fn submitted(kind: u8, payload: &[u8], _tid: u32) {
    let _ = authority_frame(kind, payload, "");
}

/// Answer frame `pkt_type` with `payload`, which came over `link` (`""` for
/// the network link, `" (UART)"` for the bridge: appended to each line).
pub fn authority_frame(pkt_type: u8, payload: &[u8], link: &str) -> Answer {
    match pkt_type {
        PKT_ACTUATOR => {
            if let Some(cmd) = decode_actuator_cmd(payload) {
                safety::cmd_set_low_confidence(cmd.is_low_confidence());
                #[cfg(feature = "actuation-smoke")]
                if cmd.is_emergency() {
                    kprintln!("[ACTSMOKE] brainlink emergency{}", if link.is_empty() { " (tcp)" } else { link });
                }
            }
            Answer::Actuator
        }
        PKT_PREDICT => Answer::NotAuthority,
        PKT_CONFIG => {
            if let Some(cfg) = decode_config_cmd(payload) {
                config(cfg);
            }
            Answer::Handled
        }
        PKT_PAYLOAD => {
            if let Some(cmd) = decode_payload_cmd(payload) {
                azos_behavior::payload::payload_exec(cmd);
            }
            Answer::Handled
        }
        PKT_ESTOP => {
            if !safety::estop_is_active() {
                crate::actuation::latch_and_stop();
                azos_drv_sys::kwarn!("[BRAIN] ESTOP received{} — motors stopped", link);
                let _ = logger::log_safety_violation_durable(logger::SAFETY_ESTOP, 0, 0);
            }
            Answer::Handled
        }
        PKT_DEGRADE => {
            degrade(payload, link);
            Answer::Handled
        }
        PKT_SEMANTIC_LEVEL => {
            let malformed = payload.is_empty();
            let level = payload.first().copied().unwrap_or(azos_ipc::cap::DEGRADE_LEVEL_CONTAINED);
            let previous = azos_ipc::cap::degrade_level();
            azos_ipc::cap::degrade_level_set(level);
            let effective = azos_ipc::cap::degrade_level();
            kprintln!("[BRAIN] semantic level set to {}{}", effective, link);
            if let Some((v, a, d)) = logger::semantic_level_record(malformed, effective, previous) {
                logger::log_safety_violation(v, a, d);
            }
            Answer::Handled
        }
        PKT_MODE => {
            if !hold_release_frame(payload, link) {
                if let Some(m) = decode_mode_cmd(payload) {
                    mode(m, payload, link);
                }
            }
            Answer::Handled
        }
        _ => {
            logger::log_safety_violation(logger::SAFETY_UNKNOWN_PKT, pkt_type, payload.len() as u32);
            Answer::Handled
        }
    }
}

fn config(cfg: ConfigCmd) {
    match cfg.config_key {
        CFG_KEY_BUZZER => {
            let Some(b) = BUZZER.get() else { return };
            match cfg.value {
                BUZZER_BEEP => { let _ = b[0](); }
                BUZZER_SIREN => { let _ = b[1](); }
                BUZZER_OFF => { let _ = b[2](); }
                _ => {}
            }
        }
        CFG_KEY_CAMERA => {
            if cfg.value == CAMERA_PWR_ON {
                azos_drv_sensor::csi::csi_power_on();
            } else if cfg.value == CAMERA_PWR_OFF {
                azos_drv_sensor::csi::csi_power_off();
            }
        }
        _ => {}
    }
}

/// Brain-triggered degraded mode: any reason arms it (a missing reason byte
/// arms it as malformed), `DEGRADE_CLEAR` lifts it.
fn degrade(payload: &[u8], link: &str) {
    let malformed = payload.is_empty();
    let reason = payload.first().copied().unwrap_or(DEGRADE_REASON_MALFORMED);
    if reason == DEGRADE_CLEAR {
        azos_ipc::cap::degraded_set(false);
        azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared{}", link);
        logger::log_safety_violation(logger::SAFETY_DEGRADE, 0, 0);
    } else {
        azos_ipc::cap::degraded_set(true);
        if malformed {
            azos_drv_sys::kwarn!("[BRAIN] degraded mode armed{} — reason byte missing", link);
        } else {
            azos_drv_sys::kwarn!("[BRAIN] degraded mode armed{} — reason {}", link, reason);
        }
        logger::log_safety_violation(logger::SAFETY_DEGRADE, 1, reason as u32);
    }
}

/// A mode change: the e-stop clears only with the operator's verified
/// release proof, and the reset id also lifts degraded mode.
fn mode(m: ModeCmd, payload: &[u8], link: &str) {
    if let Some((should_clear, action_code)) = mode_estop_record(m.mode_id, safety::estop_is_active()) {
        if should_clear {
            let proof = if payload.len() >= 1 + safety::RELEASE_PROOF_BYTES {
                let mut nonce = [0u8; 8];
                nonce.copy_from_slice(&payload[1..9]);
                let mut sig = [0u8; safety::RELEASE_SIG_BYTES];
                sig.copy_from_slice(&payload[9..9 + safety::RELEASE_SIG_BYTES]);
                safety::verify_operator_release(u64::from_be_bytes(nonce), &sig).ok()
            } else {
                None
            };
            if let Some(proof) = proof {
                safety::estop_release(proof);
                azos_drv_sys::kwarn!("[BRAIN] ESTOP cleared by verified operator authority{}", link);
                let _ = logger::log_safety_violation_durable(logger::SAFETY_ESTOP, action_code, m.mode_id as u32);
            } else if let Some(n) = safety::note_refused_estop_clear() {
                azos_drv_sys::kwarn!("[BRAIN] ESTOP_RESET recorded as a REQUEST — no verified operator authority, \
                    ESTOP stays armed{} (refusal #{})", link, n);
                let _ = logger::log_safety_violation_durable(
                    logger::SAFETY_ESTOP, safety::ESTOP_ACTION_REFUSED_MIRROR, (n << 8) | m.mode_id as u32);
            }
        } else if let Some(n) = safety::note_refused_estop_clear() {
            azos_drv_sys::kwarn!("[BRAIN] MODE mode_id={} is not the reset id — ESTOP stays armed{} (refusal #{})",
                m.mode_id, link, n);
            let _ = logger::log_safety_violation_durable(logger::SAFETY_ESTOP, action_code, (n << 8) | m.mode_id as u32);
        }
    }
    if let Some((should_clear, action_code, detail)) = mode_degrade_record(m.mode_id, azos_ipc::cap::degraded_active()) {
        if should_clear {
            azos_ipc::cap::degraded_set(false);
            azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared by MODE command{}", link);
        }
        logger::log_safety_violation(logger::SAFETY_DEGRADE, action_code, detail);
    }
}

/// A `PKT_MODE` frame that releases a device the kernel holds in its safe
/// state: the reserved reset mode id, then the operator's release proof and
/// the device (`safe_state::release_from_frame`). `true` when the frame was
/// one; it then touches neither the e-stop latch nor degraded mode. The
/// release and each refusal are `Rule::SafeState` records; this only prints
/// the outcome, a refusal metered like a refused e-stop clear.
#[cfg(feature = "effect-gate")]
fn hold_release_frame(payload: &[u8], link: &str) -> bool {
    use azos_actuation::safe_state::ReleaseError;
    let Some((&mode_id, body)) = payload.split_first() else { return false };
    if !mode_clears_containment(mode_id) {
        return false;
    }
    match azos_actuation::safe_state::release_from_frame(body) {
        None => false,
        Some(Ok(())) => {
            azos_drv_sys::kwarn!("[BRAIN] device hold released by verified operator authority ({})", link_name(link));
            true
        }
        Some(Err(e)) => {
            if let Some(n) = safety::note_refused_estop_clear() {
                let why = match e {
                    ReleaseError::NotHeld => "not held",
                    ReleaseError::TooEarly { .. } => "inside the minimum hold",
                    ReleaseError::NoWarrant(_) => "no valid warrant",
                };
                azos_drv_sys::kwarn!("[BRAIN] device hold release refused: {} ({}, refusal #{})", why, link_name(link), n);
            }
            true
        }
    }
}

#[cfg(not(feature = "effect-gate"))]
fn hold_release_frame(_payload: &[u8], _link: &str) -> bool {
    false
}

#[cfg(feature = "effect-gate")]
fn link_name(link: &str) -> &str {
    if link.is_empty() { "TCP" } else { "UART" }
}
