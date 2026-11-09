// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's answer to the brain-protocol frames that ask for authority:
//! an e-stop, degraded mode and the semantic level, a mode change (the
//! operator's signed e-stop release and device-hold release), a payload or
//! configuration effect, and the low-confidence flag of an actuator command.
//! The ring-3 behaviour engine parses the link and hands each such frame's
//! payload here (`Authority`); the UART bridge's e-stop comes here directly.
//! The checks, the effects and their records are the kernel's.
//!
//! **Tightening is always admitted, relaxing needs the operator.** An e-stop,
//! arming degraded mode, raising the semantic level and setting the
//! low-confidence cap can only stop or slow the machine. Clearing degraded
//! mode (which also lifts the low-confidence cap), lowering the level, and a
//! payload or configuration effect while contained need the operator's
//! warrant in the frame (`brain_protocol::relax_body_len`: the body, a nonce,
//! the signature), verified like an e-stop release
//! (`estop::verify_operator_relax`); without one the frame is refused with a
//! decision record. A frame of a type the protocol does not define is
//! recorded.

use azos_behavior::brain_protocol::*;
use azos_behavior::logger;
use azos_behavior::safety;
use azos_drv_sys::kprintln;

azos_common::ro_hook! {
    /// The board's buzzer as a configuration frame drives it, set by the
    /// kernel at boot: a beep.
    static BUZZER_BEEP_FN: fn() -> bool;
}
azos_common::ro_hook! {
    /// The siren.
    static BUZZER_SIREN_FN: fn() -> bool;
}
azos_common::ro_hook! {
    /// Silence.
    static BUZZER_OFF_FN: fn() -> bool;
}

/// Install the buzzer's three calls (the kernel, at boot, once).
pub fn set_buzzer(beep: fn() -> bool, siren: fn() -> bool, off: fn() -> bool) {
    BUZZER_BEEP_FN.set(beep);
    BUZZER_SIREN_FN.set(siren);
    BUZZER_OFF_FN.set(off);
}

/// The `Authority` interface's handler: a frame the ring-3 behaviour engine
/// submits (`azos_syscall::authority_host`).
pub fn submitted(kind: u8, payload: &[u8], _tid: u32) {
    authority_frame(kind, payload);
}

/// Answer frame `kind` with `payload`.
pub fn authority_frame(kind: u8, payload: &[u8]) {
    let contained = azos_ipc::cap::degraded_active();
    let body = match relax_body_len(kind, payload, contained, azos_ipc::cap::degrade_level()) {
        None => payload,
        Some(n) => match warranted(kind, payload, n) {
            Some(body) => body,
            None => {
                safety::record_unsigned_relax(kind, payload.first().copied().unwrap_or(0));
                azos_drv_sys::kwarn!("[BRAIN] frame 0x{:02x} refused: relaxing needs the operator's warrant", kind);
                return;
            }
        },
    };
    match kind {
        PKT_ACTUATOR => {
            // The brain's own doubt only ever tightens: it sets the cap, and
            // only the operator's degrade clear lifts it.
            if decode_actuator_cmd(body).is_some_and(|c| c.is_low_confidence()) {
                safety::cmd_set_low_confidence(true);
            }
        }
        PKT_CONFIG => {
            if let Some(cfg) = decode_config_cmd(body) {
                config(cfg);
            }
        }
        PKT_PAYLOAD => {
            if let Some(cmd) = decode_payload_cmd(body) {
                azos_behavior::payload::payload_exec(cmd);
            }
        }
        PKT_ESTOP => {
            if !safety::estop_is_active() {
                crate::actuation::latch_and_stop();
                azos_drv_sys::kwarn!("[BRAIN] ESTOP received — motors stopped");
                let _ = logger::log_safety_violation_durable(logger::SAFETY_ESTOP, 0, 0);
            }
        }
        PKT_DEGRADE => degrade(body),
        PKT_SEMANTIC_LEVEL => {
            let malformed = body.is_empty();
            let level = body.first().copied().unwrap_or(azos_ipc::cap::DEGRADE_LEVEL_CONTAINED);
            let previous = azos_ipc::cap::degrade_level();
            azos_ipc::cap::degrade_level_set(level);
            let effective = azos_ipc::cap::degrade_level();
            kprintln!("[BRAIN] semantic level set to {}", effective);
            if let Some((v, a, d)) = logger::semantic_level_record(malformed, effective, previous) {
                logger::log_safety_violation(v, a, d);
            }
        }
        PKT_MODE => {
            if !hold_release_frame(body) {
                if let Some(m) = decode_mode_cmd(body) {
                    mode(m, body);
                }
            }
        }
        _ => logger::log_safety_violation(logger::SAFETY_UNKNOWN_PKT, kind, payload.len() as u32),
    }
}

/// The first `n` bytes of `payload` when the operator's warrant that follows
/// them (nonce, signature) verifies for `kind` and exactly those bytes.
fn warranted(kind: u8, payload: &[u8], n: usize) -> Option<&[u8]> {
    if payload.len() < n + safety::RELEASE_PROOF_BYTES {
        return None;
    }
    let (body, proof) = payload.split_at(n);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&proof[..8]);
    let mut sig = [0u8; safety::RELEASE_SIG_BYTES];
    sig.copy_from_slice(&proof[8..8 + safety::RELEASE_SIG_BYTES]);
    safety::verify_operator_relax(kind, body, u64::from_be_bytes(nonce), &sig).ok().map(|_| body)
}

fn config(cfg: ConfigCmd) {
    match cfg.config_key {
        CFG_KEY_BUZZER => {
            let call = match cfg.value {
                BUZZER_BEEP => BUZZER_BEEP_FN.get(),
                BUZZER_SIREN => BUZZER_SIREN_FN.get(),
                BUZZER_OFF => BUZZER_OFF_FN.get(),
                _ => None,
            };
            if let Some(f) = call {
                let _ = f();
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

/// Degraded mode: any reason arms it (a missing reason byte arms it as
/// malformed); `DEGRADE_CLEAR`, which reaches here only with the operator's
/// warrant, lifts it and the low-confidence cap.
fn degrade(body: &[u8]) {
    let malformed = body.is_empty();
    let reason = body.first().copied().unwrap_or(DEGRADE_REASON_MALFORMED);
    if reason == DEGRADE_CLEAR {
        azos_ipc::cap::degraded_set(false);
        safety::cmd_set_low_confidence(false);
        azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared by verified operator authority");
        logger::log_safety_violation(logger::SAFETY_DEGRADE, 0, 0);
    } else {
        azos_ipc::cap::degraded_set(true);
        if malformed {
            azos_drv_sys::kwarn!("[BRAIN] degraded mode armed — reason byte missing");
        } else {
            azos_drv_sys::kwarn!("[BRAIN] degraded mode armed — reason {}", reason);
        }
        logger::log_safety_violation(logger::SAFETY_DEGRADE, 1, reason as u32);
    }
}

/// A mode change: the e-stop clears only with the operator's verified
/// release proof. A mode change never lifts degraded mode: that is the signed
/// `PKT_DEGRADE` clear's alone, and the attempt is refused and recorded.
fn mode(m: ModeCmd, payload: &[u8]) {
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
                azos_drv_sys::kwarn!("[BRAIN] ESTOP cleared by verified operator authority");
                let _ = logger::log_safety_violation_durable(logger::SAFETY_ESTOP, action_code, m.mode_id as u32);
            } else if let Some(n) = safety::note_refused_estop_clear() {
                azos_drv_sys::kwarn!("[BRAIN] ESTOP_RESET recorded as a REQUEST — no verified operator authority, \
                    ESTOP stays armed (refusal #{})", n);
                let _ = logger::log_safety_violation_durable(
                    logger::SAFETY_ESTOP, safety::ESTOP_ACTION_REFUSED_MIRROR, (n << 8) | m.mode_id as u32);
            }
        } else if let Some(n) = safety::note_refused_estop_clear() {
            azos_drv_sys::kwarn!("[BRAIN] MODE mode_id={} is not the reset id — ESTOP stays armed (refusal #{})",
                m.mode_id, n);
            let _ = logger::log_safety_violation_durable(logger::SAFETY_ESTOP, action_code, (n << 8) | m.mode_id as u32);
        }
    }
    if let Some((should_clear, action_code, detail)) = mode_degrade_record(m.mode_id, azos_ipc::cap::degraded_active()) {
        if should_clear {
            safety::record_unsigned_relax(PKT_MODE, m.mode_id);
            azos_drv_sys::kwarn!("[BRAIN] MODE does not clear degraded mode: the operator's signed degrade clear does");
        } else {
            logger::log_safety_violation(logger::SAFETY_DEGRADE, action_code, detail);
        }
    }
}

/// A `PKT_MODE` frame that releases a device the kernel holds in its safe
/// state: the reserved reset mode id, then the operator's release proof and
/// the device (`safe_state::release_from_frame`). `true` when the frame was
/// one; it then touches neither the e-stop latch nor degraded mode. The
/// release and each refusal are `Rule::SafeState` records; this only prints
/// the outcome, a refusal metered like a refused e-stop clear.
#[cfg(feature = "effect-gate")]
fn hold_release_frame(payload: &[u8]) -> bool {
    use azos_actuation::safe_state::ReleaseError;
    let Some((&mode_id, body)) = payload.split_first() else { return false };
    if !mode_clears_containment(mode_id) {
        return false;
    }
    match azos_actuation::safe_state::release_from_frame(body) {
        None => false,
        Some(Ok(())) => {
            azos_drv_sys::kwarn!("[BRAIN] device hold released by verified operator authority");
            true
        }
        Some(Err(e)) => {
            if let Some(n) = safety::note_refused_estop_clear() {
                let why = match e {
                    ReleaseError::NotHeld => "not held",
                    ReleaseError::TooEarly { .. } => "inside the minimum hold",
                    ReleaseError::NoWarrant(_) => "no valid warrant",
                };
                azos_drv_sys::kwarn!("[BRAIN] device hold release refused: {} (refusal #{})", why, n);
            }
            true
        }
    }
}

#[cfg(not(feature = "effect-gate"))]
fn hold_release_frame(_payload: &[u8]) -> bool {
    false
}
