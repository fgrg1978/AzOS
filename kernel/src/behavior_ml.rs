// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behavior loop's side of the ring-3 ML service.
//!
//! The loop's MLP runs in `userspace/services/mlsrv` (`MLSRV.ELF`), which the loop
//! starts itself and then reaches through the driver-server queue for
//! `DRV_KIND_ML`: one request per cycle carrying the two range readings, one
//! reply carrying the class. The call blocks the loop for at most
//! [`ML_REPLY_TIMEOUT_US`] and donates the loop's priority to the service for
//! that span (`UserDriverProxy::call_timeout_us`). What a missing reply turns
//! into is `azos_behavior::ml_link`'s policy, not this file's.
//!
//! The kernel no longer does any f32 work for this loop: it packs two `u16`s
//! and reads back one byte.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_abi::ml_srv;
use azos_behavior::ml_link::{MlAbsence, MlLinkStats, MlOutcome};
use azos_behavior::types::MlpResult;
use azos_drv_sys::kprintln;
use azos_drv_sys::user_driver_proxy::{ProxyError, UserDriverProxy};

/// The service image on the FAT32 volume.
const MLSRV_PATH: &[u8] = b"/fat/MLSRV.ELF";

/// How long one cycle waits for the service's verdict.
///
/// 10 % of the loop's 100 ms period. The service's own work is a few thousand
/// instructions and the round trip a few thousand more (`[BSTEP]` measures
/// both), so a reply that has not come after 10 ms is a service that is not
/// running, not one that is slow; waiting longer only eats into the period
/// the rest of the loop (the brain link, arbitration, the motor publish)
/// needs.
///
/// Wave 11: Kconfig `ML_REPLY_TIMEOUT_US` (Robot menu, default 10000).
pub const ML_REPLY_TIMEOUT_US: u64 = azos_limits::ML_REPLY_TIMEOUT_US;

/// TID of the service the loop started; 0 = not started on this boot.
static ML_SERVICE_TID: AtomicU32 = AtomicU32::new(0);

/// Start the ML service. Called once, by the behavior task, before its loop.
///
/// Refused, like autorun, while the actuation gate is not installed (Q1.4:
/// no ring-3 program starts before it). A boot that cannot start it gets no
/// ML verdicts (`MlOutcome::NotLaunched`) and L1 holds STOP for as long as
/// ML is enabled (owner decision 2026-09-28, fail closed); it says so once,
/// here.
pub fn launch() {
    if !azos_robot::motor::motor_gate_installed() {
        azos_drv_sys::kwarn!("[ML] ring-3 ML service NOT started: the actuation gate is not installed");
        return;
    }
    if azos_behavior::safety::safe_mode_active() {
        azos_drv_sys::kwarn!("[ML] ring-3 ML service NOT started: safe mode");
        return;
    }
    // Supervised (wave 11): a service that dies is restarted from the same
    // image under the supervisor's policy, and L1 holds STOP for every cycle
    // without a verdict meanwhile (`ml_link`), so a restart lets nothing
    // through before the new service answers.
    let rc = crate::drv_supervisor::spawn_supervised(MLSRV_PATH);
    if rc > 0 {
        ML_SERVICE_TID.store(rc as u32, Ordering::Release);
        kprintln!("[ML] ring-3 ML service /fat/MLSRV.ELF started, tid={} (reply budget {} us)",
            rc, ML_REPLY_TIMEOUT_US);
    } else {
        azos_drv_sys::kwarn!("[ML] ring-3 ML service NOT started (spawn /fat/MLSRV.ELF rc={}): no ML \
                   verdicts this boot, L1 holds STOP (ml_enabled=0 turns ML off)", rc);
    }
}

/// The service's TID, 0 when it was never started. After a restart, the
/// successor's (the supervisor's entry for `MLSRV_PATH`); while a successor
/// is due, the one that died.
pub fn service_tid() -> u32 {
    let launched = ML_SERVICE_TID.load(Ordering::Acquire);
    if launched == 0 {
        return 0;
    }
    match crate::drv_supervisor::current_tid(MLSRV_PATH) {
        Some(tid) if tid != 0 => tid,
        _ => launched,
    }
}

fn proxy() -> UserDriverProxy {
    use azos_abi::cap::CapPerms;
    use azos_drv_api::{DriverIsolation, DriverManifest};
    // Routing is by kind; the TID in the manifest is informational.
    UserDriverProxy::new(DriverManifest::new(
        azos_driver_server::DRV_KIND_ML,
        "ml-user",
        DriverIsolation::UserProcess { tid: 0 },
        CapPerms::RW,
    ))
}

/// One request to the service. `logits` receives the three logit bit
/// patterns of a verdict.
fn call(op: u32, payload: &[u8], logits: &mut [u32; 3]) -> MlOutcome {
    if service_tid() == 0 {
        return MlOutcome::NotLaunched;
    }
    let mut out = [0u8; ml_srv::INFER_REPLY_LEN];
    match proxy().call_timeout_us(op, payload, &mut out, ML_REPLY_TIMEOUT_US) {
        Ok(n) if n >= ml_srv::INFER_REPLY_LEN => {
            for (k, l) in logits.iter_mut().enumerate() {
                *l = u32::from_le_bytes([out[4 + 4 * k], out[5 + 4 * k], out[6 + 4 * k], out[7 + 4 * k]]);
            }
            MlOutcome::Verdict(out[0])
        }
        Ok(_) | Err(ProxyError::OutputTooLarge) => MlOutcome::Malformed,
        Err(ProxyError::Timeout) | Err(ProxyError::CannotBlock) => MlOutcome::Late,
        Err(ProxyError::SubmitFailed) => MlOutcome::Unavailable,
    }
}

fn infer_payload(front_mm: u16, right_mm: u16) -> [u8; 4] {
    let f = front_mm.to_le_bytes();
    let r = right_mm.to_le_bytes();
    [f[0], f[1], r[0], r[1]]
}

/// The loop's per-cycle state: outcome counts and the one-shot lines.
pub struct MlLink {
    pub stats: MlLinkStats,
    absence: MlAbsence,
    said_verdict: bool,
    said_missing: bool,
}

impl MlLink {
    pub const fn new() -> Self {
        MlLink {
            stats: MlLinkStats::new(),
            absence: MlAbsence::new(),
            said_verdict: false,
            said_missing: false,
        }
    }

    /// This cycle's request: the MLP on the two range readings.
    pub fn cycle(&mut self, front_mm: u16, right_mm: u16) -> MlOutcome {
        let mut logits = [0u32; 3];
        let outcome = call(ml_srv::OP_INFER, &infer_payload(front_mm, right_mm), &mut logits);
        self.stats.note(outcome);
        match outcome {
            MlOutcome::Verdict(c) if !self.said_verdict => {
                self.said_verdict = true;
                kprintln!("[BEHAVIOR][ML] first ring-3 verdict: class={} from mlsrv tid={} \
                           (front={} right={} logits {:#010x} {:#010x} {:#010x})",
                    c, service_tid(), front_mm, right_mm, logits[0], logits[1], logits[2]);
            }
            MlOutcome::Late | MlOutcome::Unavailable | MlOutcome::Malformed | MlOutcome::NotLaunched
                if !self.said_missing =>
            {
                self.said_missing = true;
                azos_drv_sys::kwarn!("[BEHAVIOR][ML] no verdict ({:?}) -- L1 holds STOP {}", outcome,
                    if outcome == MlOutcome::NotLaunched { "while ML is enabled" }
                    else { "until mlsrv answers" });
            }
            _ => {}
        }
        outcome
    }

    /// The verdict L1 acts on for this cycle's `outcome`
    /// (`ml_link::mlp_result_for`), and the absence record when this cycle
    /// completes a run of missing verdicts (`ml_link::MlAbsence`).
    pub fn verdict(&mut self, outcome: MlOutcome) -> MlpResult {
        let r = azos_behavior::ml_link::mlp_result_for(outcome);
        if let Some(action) = self.absence.note(outcome, &r) {
            azos_behavior::logger::log_safety_violation(
                azos_behavior::logger::SAFETY_ML_ABSENT, action, service_tid());
            azos_drv_sys::kwarn!("[SAFETY] no ML verdict for {} cycles ({:?}): L1 holds STOP -- recorded \
                       (SAFETY_ML_ABSENT action={} tid={})",
                azos_behavior::ml_link::ABSENT_RECORD_CYCLES, outcome, action, service_tid());
        }
        r
    }

    #[cfg_attr(not(feature = "qemu"), allow(dead_code))]
    pub fn report(&self) {
        let s = &self.stats;
        kprintln!("[BEHAVIOR][ML] mlsrv tid={} verdicts={} late={} unavailable={} malformed={} \
                   not_launched={} (fallback STOP on {})",
            service_tid(), s.verdicts, s.late, s.unavailable, s.malformed, s.not_launched,
            s.fallbacks());
    }
}
