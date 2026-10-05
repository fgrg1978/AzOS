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
/// needs. Measured under QEMU TCG in the ML service row: see
/// `tools/ci_check.sh`.
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
    /// The action code of the last `SAFETY_ML_ABSENT` record this loop wrote.
    #[cfg_attr(not(feature = "ml-kill-smoke"), allow(dead_code))]
    recorded: Option<u8>,
    said_verdict: bool,
    said_missing: bool,
    #[cfg(feature = "ml-kill-smoke")]
    smoke: smoke::Smoke,
}

impl MlLink {
    pub const fn new() -> Self {
        MlLink {
            stats: MlLinkStats::new(),
            absence: MlAbsence::new(),
            recorded: None,
            said_verdict: false,
            said_missing: false,
            #[cfg(feature = "ml-kill-smoke")]
            smoke: smoke::Smoke::new(),
        }
    }

    /// This cycle's request: the MLP on the two range readings.
    pub fn cycle(&mut self, front_mm: u16, right_mm: u16) -> MlOutcome {
        #[cfg(feature = "ml-kill-smoke")]
        let op = self.smoke.op_for_this_cycle(front_mm, right_mm);
        #[cfg(not(feature = "ml-kill-smoke"))]
        let op = (ml_srv::OP_INFER, infer_payload(front_mm, right_mm));
        let mut logits = [0u32; 3];
        let outcome = call(op.0, &op.1, &mut logits);
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
            self.recorded = Some(action);
            azos_behavior::logger::log_safety_violation(
                azos_behavior::logger::SAFETY_ML_ABSENT, action, service_tid());
            azos_drv_sys::kwarn!("[SAFETY] no ML verdict for {} cycles ({:?}): L1 holds STOP -- recorded \
                       (SAFETY_ML_ABSENT action={} tid={})",
                azos_behavior::ml_link::ABSENT_RECORD_CYCLES, outcome, action, service_tid());
        }
        r
    }

    /// Called after arbitration, with what the cycle decided.
    #[cfg_attr(not(feature = "ml-kill-smoke"), allow(unused_variables))]
    pub fn observe(&mut self, outcome: MlOutcome, output: &azos_behavior::BehaviorOutput,
                   work_ticks: u64, period_ticks: u64) {
        #[cfg(feature = "ml-kill-smoke")]
        self.smoke.observe(outcome, output, work_ticks, period_ticks, self.recorded);
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

/// The ML service rows' scenario (`ml-kill-smoke`): parity, then late, then
/// killed and restarted by the supervisor (wave 11), each checked against what
/// the loop actually decided. On a boot that
/// never started the service (the absent row deletes `MLSRV.ELF` from its
/// disk) it checks instead that L1 held STOP and that the absence reached the
/// flight recorder on disk.
#[cfg(feature = "ml-kill-smoke")]
mod smoke {
    use super::*;

    /// Verdicts before the parity sweep and the stall.
    const WARMUP: u32 = 10;
    /// How long the stalled service sleeps: three loop periods.
    const STALL_MS: u16 = 300;
    /// Cycles the supervisor has to bring a killed service back: 20 s of
    /// loop periods, a bound only a service that is not restarted reaches.
    const RESTART_WITHIN: u32 = 200;
    /// Verdicts the restarted service must give before the verdict.
    const AFTER_RESTART: u32 = 5;
    /// Cycles checked on a boot that never started the service: twice the
    /// run that writes the absence record.
    const AFTER_ABSENT: u32 = 2 * azos_behavior::ml_link::ABSENT_RECORD_CYCLES;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Phase {
        Warmup,
        Stall,
        Recover,
        Kill,
        Dead,
        Back,
        Done,
    }

    pub struct Smoke {
        phase: Phase,
        verdicts: u32,
        late_seen: u32,
        /// The service the kill was sent to.
        killed_tid: u32,
        /// Cycles from the kill up to the first verdict after it, and how
        /// many of them L1 decided STOP.
        gap_cycles: u32,
        gap_stop_by_l1: u32,
        /// Who answered the first verdict after the kill, and verdicts since.
        back_tid: u32,
        back_verdicts: u32,
        /// Which kill this is: 1, then 2. The first restart is immediate,
        /// the second waits for the supervisor's cooldown (1 s, ~10 cycles),
        /// so the second gap is the long one.
        round: u8,
        /// The first round's `(killed, back, gap, gap STOP by L1)`.
        first: (u32, u32, u32, u32),
        worst_work: u64,
        overruns: u32,
        absent_cycles: u32,
        absent_stop_by_l1: u32,
    }

    /// Flush the recorder and look for this boot's `SAFETY_ML_ABSENT` record
    /// with `action` on disk: `(found, records on disk)`.
    fn absence_on_disk(action: Option<u8>) -> (bool, u32) {
        let Some(action) = action else { return (false, 0) };
        let _ = azos_behavior::logger::logger_flush();
        crate::find_safety_record_on_disk(azos_behavior::logger::SAFETY_ML_ABSENT, action)
    }

    impl Smoke {
        pub const fn new() -> Self {
            Smoke { phase: Phase::Warmup, verdicts: 0, late_seen: 0, killed_tid: 0, gap_cycles: 0,
                    gap_stop_by_l1: 0, back_tid: 0, back_verdicts: 0, round: 1,
                    first: (0, 0, 0, 0), worst_work: 0,
                    overruns: 0, absent_cycles: 0, absent_stop_by_l1: 0 }
        }

        pub fn op_for_this_cycle(&mut self, front: u16, right: u16) -> (u32, [u8; 4]) {
            match self.phase {
                Phase::Stall => {
                    kprintln!("[MLKILL] stalling mlsrv for {} ms (reply budget {} us)",
                        STALL_MS, ML_REPLY_TIMEOUT_US);
                    let ms = STALL_MS.to_le_bytes();
                    (ml_srv::OP_STALL, [ms[0], ms[1], 0, 0])
                }
                Phase::Kill => {
                    // Read before the fault: once it has died, the service's
                    // TID is the next one's.
                    self.killed_tid = service_tid();
                    kprintln!("[MLKILL] OP_FAULT sent to mlsrv tid={}", self.killed_tid);
                    (ml_srv::OP_FAULT, [0; 4])
                }
                _ => (ml_srv::OP_INFER, infer_payload(front, right)),
            }
        }

        /// Class and logits of the service against the kernel-side reference
        /// MLP (`azos_ml`, linked into this smoke build only) over an
        /// 11 x 11 grid.
        /// A point the service did not answer in time is counted apart: it
        /// says nothing about the arithmetic.
        fn parity_sweep() {
            let (mut same, mut answered, mut n) = (0u32, 0u32, 0u32);
            for fi in 0..=10u16 {
                for ri in 0..=10u16 {
                    let (front, right) = (fi * 100, ri * 100);
                    let mut logits = [0u32; 3];
                    let got = call(ml_srv::OP_INFER, &infer_payload(front, right), &mut logits);
                    let input = [front as f32 / 1000.0, right as f32 / 1000.0, 0.5, 0.9];
                    let want = azos_ml::mlp_infer(&input);
                    let want_class = azos_ml::argmax3(&want) as u8;
                    n += 1;
                    if got == MlOutcome::Late {
                        continue;
                    }
                    answered += 1;
                    if got == MlOutcome::Verdict(want_class)
                        && logits == [want[0].to_bits(), want[1].to_bits(), want[2].to_bits()]
                    {
                        same += 1;
                    }
                }
            }
            kprintln!("[MLKILL] parity: {}/{} answered grid points bit-identical to the reference \
                       MLP, class and logits ({} of {} late)", same, answered, n - answered, n);
        }

        /// Round-trip cost, in `timebase` ticks: an empty request (the
        /// service answers it without computing) against a full inference.
        fn round_trips() {
            const N: u64 = 64;
            let mut logits = [0u32; 3];
            let t0 = azos_drv_sys::timebase::now();
            for _ in 0..N {
                let _ = call(ml_srv::OP_INFER, &[], &mut logits);
            }
            let t1 = azos_drv_sys::timebase::now();
            for i in 0..N {
                let _ = call(ml_srv::OP_INFER, &infer_payload(600 + i as u16, 300), &mut logits);
            }
            let t2 = azos_drv_sys::timebase::now();
            kprintln!("[MLKILL] round trip over {} calls: empty {} ticks, inference {} ticks \
                       (x1000 per call, freq {})",
                N, (t1 - t0) * 1000 / N, (t2 - t1) * 1000 / N, crate::behavior_step::freq());
        }

        pub fn observe(&mut self, outcome: MlOutcome, out: &azos_behavior::BehaviorOutput,
                       work: u64, period: u64, recorded: Option<u8>) {
            if self.phase != Phase::Warmup && self.phase != Phase::Done {
                self.worst_work = self.worst_work.max(work);
                if work > period {
                    self.overruns += 1;
                }
            }
            let stop_by_l1 = out.layer == 1 && out.cmd.valid
                && out.cmd.speed_l == 0 && out.cmd.speed_r == 0;
            match self.phase {
                // The absent row. No overrun check: the readback below does a
                // flush and a FAT read inside the loop.
                Phase::Warmup if outcome == MlOutcome::NotLaunched => {
                    self.absent_cycles += 1;
                    if stop_by_l1 {
                        self.absent_stop_by_l1 += 1;
                    }
                    if self.absent_cycles == AFTER_ABSENT {
                        let (found, records) = absence_on_disk(recorded);
                        let pass = self.absent_stop_by_l1 == AFTER_ABSENT
                            && recorded == Some(azos_behavior::ml_link::ABSENT_NOT_LAUNCHED)
                            && found;
                        kprintln!("[MLABSENT] {}: service never started | {} cycles, {} decided STOP \
                                   by L1 | SAFETY_ML_ABSENT {} (action {:?}, {} records on disk)",
                            if pass { "PASS" } else { "FAIL" }, self.absent_cycles,
                            self.absent_stop_by_l1, if found { "RECORDED" } else { "NOT RECORDED" },
                            recorded, records);
                        self.phase = Phase::Done;
                    }
                }
                Phase::Warmup => {
                    if matches!(outcome, MlOutcome::Verdict(_)) {
                        self.verdicts += 1;
                        if self.verdicts == WARMUP {
                            Self::parity_sweep();
                            Self::round_trips();
                            self.phase = Phase::Stall;
                        }
                    }
                }
                Phase::Stall => {
                    if outcome == MlOutcome::Late {
                        self.late_seen += 1;
                        kprintln!("[MLKILL] stalled cycle: {:?}, decided layer={} ({},{})",
                            outcome, out.layer, out.cmd.speed_l, out.cmd.speed_r);
                    }
                    self.phase = Phase::Recover;
                }
                Phase::Recover => {
                    if outcome == MlOutcome::Late {
                        self.late_seen += 1;
                    } else if matches!(outcome, MlOutcome::Verdict(_)) {
                        kprintln!("[MLKILL] mlsrv answering again after {} late cycle(s)",
                            self.late_seen);
                        self.phase = Phase::Kill;
                    }
                }
                // The cycle that sent OP_FAULT: no verdict on it, so it is
                // the first cycle of the gap the restart must cover.
                Phase::Kill => {
                    self.gap_cycles = 1;
                    self.gap_stop_by_l1 = stop_by_l1 as u32;
                    self.phase = Phase::Dead;
                }
                // Every cycle until the restarted service's first verdict must
                // be STOP decided by L1: the restart lets nothing through
                // before the service is back.
                Phase::Dead => {
                    if matches!(outcome, MlOutcome::Verdict(_)) {
                        self.back_tid = azos_driver_server::driver_owner_tid(
                            azos_driver_server::DRV_KIND_ML).unwrap_or(0);
                        kprintln!("[MLKILL] restarted: tid={} killed, tid={} answering after {} \
                                   cycle(s) without a verdict, {} decided STOP by L1",
                            self.killed_tid, self.back_tid, self.gap_cycles, self.gap_stop_by_l1);
                        self.back_verdicts = 1;
                        self.phase = Phase::Back;
                    } else {
                        self.gap_cycles += 1;
                        if stop_by_l1 {
                            self.gap_stop_by_l1 += 1;
                        }
                        if self.gap_cycles == RESTART_WITHIN {
                            kprintln!("[MLKILL] FAIL: not restarted: no verdict for {} cycles after \
                                       the kill of tid={} ({} decided STOP by L1, last outcome {:?})",
                                self.gap_cycles, self.killed_tid, self.gap_stop_by_l1, outcome);
                            self.phase = Phase::Done;
                        }
                    }
                }
                Phase::Back => {
                    if matches!(outcome, MlOutcome::Verdict(_)) {
                        self.back_verdicts += 1;
                    }
                    if self.back_verdicts == AFTER_RESTART && self.round == 1 {
                        // Kill it again: the second restart waits out the
                        // cooldown, so L1 must hold STOP over a longer gap.
                        self.first = (self.killed_tid, self.back_tid, self.gap_cycles,
                                      self.gap_stop_by_l1);
                        self.round = 2;
                        self.phase = Phase::Kill;
                    } else if self.back_verdicts == AFTER_RESTART {
                        // The overrun verdict is taken before the readbacks,
                        // which flush and read the disk inside the loop.
                        let timely = self.overruns == 0;
                        // `SAFETY_ML_ABSENT` is written on the
                        // `ABSENT_RECORD_CYCLES`-th cycle in a row without a
                        // verdict: required only when the gap was that long.
                        let absent_due = self.gap_cycles.max(self.first.2)
                            >= azos_behavior::ml_link::ABSENT_RECORD_CYCLES;
                        let (absent_found, records) = if absent_due {
                            absence_on_disk(recorded)
                        } else {
                            (false, 0)
                        };
                        let _ = azos_behavior::logger::logger_flush();
                        // Restarts 1 and 2 of the ML kind, as the supervisor
                        // recorded them (`sup_record_detail(kind, restarts)`).
                        let restart_found = |n: u8| crate::find_safety_record_detail_on_disk(
                            azos_behavior::logger::SAFETY_DRIVER_SUPERVISOR,
                            azos_behavior::logger::SUP_ACTION_RESTART,
                            Some(azos_behavior::logger::sup_record_detail(
                                azos_driver_server::DRV_KIND_ML, n))).0;
                        let restarts_found = restart_found(1) && restart_found(2);
                        let (k1, b1, g1, s1) = self.first;
                        let pass = self.late_seen >= 1
                            && s1 == g1 && b1 != 0 && b1 != k1
                            && self.gap_stop_by_l1 == self.gap_cycles
                            && self.back_tid != 0
                            && self.back_tid != self.killed_tid
                            && self.killed_tid == b1
                            && timely
                            && (!absent_due || absent_found)
                            && restarts_found;
                        kprintln!("[MLKILL] {}: late cycles={} | kill 1: tid={} -> tid={} after {} \
                                   cycle(s), {} STOP by L1 | kill 2: tid={} -> tid={} after {} \
                                   cycle(s), {} STOP by L1, then {} verdicts | worst step {} ticks of \
                                   a {}-tick period, overruns={} | SAFETY_ML_ABSENT {} (action {:?}, \
                                   {} records on disk) | restarts 1+2 {}",
                            if pass { "PASS" } else { "FAIL" },
                            self.late_seen, k1, b1, g1, s1, self.killed_tid, self.back_tid,
                            self.gap_cycles, self.gap_stop_by_l1, self.back_verdicts,
                            self.worst_work, period, self.overruns,
                            if !absent_due { "not due (gap shorter than its run)" }
                            else if absent_found { "RECORDED" } else { "NOT RECORDED" },
                            recorded, records,
                            if restarts_found { "RECORDED" } else { "NOT RECORDED" });
                        self.phase = Phase::Done;
                    }
                }
                Phase::Done => {}
            }
        }
    }
}
