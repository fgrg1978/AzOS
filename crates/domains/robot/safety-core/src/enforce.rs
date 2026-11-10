// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The robot's enforcer (`azos_ext_api::Enforcer`), run by the base's
//! enforcement task: the safety layer's verdict on the sensor bus (L0: a fall,
//! a spin, a flat battery, a latched e-stop), which the drivetrain loop applies
//! as a cap on every motor write whoever issued it ([`l0_cap`]; a stale
//! verdict is a stop), the UART bridge's e-stop frames, the payload
//! pulse's deadline, the RC receiver's link loss
//! and kill switch (Kconfig `RC_INPUT`), and the geofence's home arm and
//! breach latch (Kconfig `GEOFENCE`). Each latches the e-stop and records
//! why; none chooses a motion.

use core::sync::atomic::{AtomicU32, Ordering};
use azos_actuation::verdict::Stamped;
use azos_behavior::safety::SafetyAction;
use azos_behavior::types::SensorState;

/// Its period: the rate the sensor bus and the RC link are judged at.
const PERIOD_MS: u32 = 100;

pub static ROBOT_ENFORCER: azos_ext_api::Enforcer = azos_ext_api::Enforcer {
    name: "robot",
    period_ms: PERIOD_MS,
    tick,
};

/// No cap: the safety layer found nothing.
const NO_CAP: i32 = i32::MAX;

/// How long a published verdict holds: two enforcer periods. Past it the
/// enforcer has stalled, and what it guards is stopped.
fn fresh_ticks() -> u64 {
    2 * PERIOD_MS as u64 * azos_drv_sys::timebase::freq() / 1000
}

/// The safety layer's latest cap on a wheel's command, in percent: 0 stops,
/// [`NO_CAP`] leaves the command alone.
static L0: Stamped = Stamped::new();

/// The cap every motor write gets at tick `now`, whoever issued it: the
/// safety layer's verdict while it is fresh, 0 (stop) before the first one and
/// once the enforcer has stalled.
pub fn l0_cap(now: u64) -> i32 {
    L0.fresh(now, fresh_ticks()).unwrap_or(0)
}

/// `action` as a cap: a stop, a landing and a return all stop the wheels, a
/// speed limit bounds them.
pub fn cap_of(action: SafetyAction) -> i32 {
    match action {
        SafetyAction::None => NO_CAP,
        SafetyAction::EmergencyStop | SafetyAction::LandNow | SafetyAction::ReturnToLaunch => 0,
        SafetyAction::SpeedLimit(n) => n.clamp(0, 100),
    }
}

/// The operator's sticks while the RC receiver is in manual override, packed
/// `(left << 16) | right` as two `i16`.
static RC_OVERRIDE: Stamped = Stamped::new();

/// The operator's override, while the RC receiver says so and the reading is
/// fresh: the drive the sticks ask, which the drivetrain loop applies in place
/// of the behaviour engine's command and without its command watchdog, so the
/// operator keeps control when the engine dies. A human override is
/// enforcement, like the e-stop; the safety layer's cap and the envelope still
/// bound it.
pub fn rc_override(now: u64) -> Option<(i32, i32)> {
    let v = RC_OVERRIDE.fresh(now, fresh_ticks())? as u32;
    Some(((v >> 16) as u16 as i16 as i32, v as u16 as i16 as i32))
}

/// Completed checks, for the smokes that wait for some to pass.
static PASSES: AtomicU32 = AtomicU32::new(0);

/// How many checks have completed.
pub fn passes() -> u32 {
    PASSES.load(Ordering::Acquire)
}

fn tick(now: u64) {
    azos_behavior::payload::payload_tick();
    bridge_estop();
    let mut state = SensorState::new();
    azos_behavior::sensor_bus::SENSOR_BUS.snapshot(&mut state);
    state.timestamp = now;
    L0.publish(cap_of(azos_behavior::safety::safety_check(&state).action), now);
    azos_robot::motor::motor_recap();
    #[cfg(feature = "rc-input")]
    {
        rc_enforce(now);
        static MANUAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        let mut manual = MANUAL.load(Ordering::Relaxed);
        match rc_sticks(now, &mut manual) {
            Some((l, r)) => {
                RC_OVERRIDE.publish((((l as i16 as u16 as u32) << 16) | r as i16 as u16 as u32) as i32, now);
            }
            None => RC_OVERRIDE.withdraw(),
        }
        MANUAL.store(manual, Ordering::Relaxed);
    }
    #[cfg(feature = "geofence")]
    fence_tick(&state);
    let _ = PASSES.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_add(1)));
}

/// The receiver's verdict at `now`.
#[cfg(feature = "rc-input")]
fn rc_verdict(now: u64) -> azos_behavior::rc_link::RcVerdict {
    use azos_behavior::rc_link::{rc_evaluate, RcPolicy};
    use azos_robot_drivers::rc;
    const POLICY: RcPolicy = RcPolicy::from_limits(azos_drv_sys::timebase::TIMER_FREQ as u64);
    let verdict = rc_evaluate(&POLICY, rc::rc_frames_seen(), rc::rc_read(), rc::rc_last_update(), now);
    #[cfg(feature = "rc-failsafe-canary")]
    let verdict = match verdict {
        azos_behavior::rc_link::RcVerdict::LinkLoss { .. } => azos_behavior::rc_link::RcVerdict::Passive,
        v => v,
    };
    verdict
}

#[cfg(feature = "rc-input")]
fn rc_latch(action: u8, detail: u32, what: &str) {
    if azos_behavior::safety::estop_is_active() {
        return;
    }
    crate::actuation::latch_and_stop();
    let _ = azos_behavior::logger::log_safety_violation_durable(
        azos_behavior::logger::SAFETY_ESTOP, action, detail);
    azos_drv_sys::kwarn!("[RC] {} — e-stop latched (SAFETY_ESTOP action {} detail {})", what, action, detail);
}

/// A lost link (Kconfig `RC_FAILSAFE_ESTOP`) and the kill switch latch the
/// e-stop.
#[cfg(feature = "rc-input")]
fn rc_enforce(now: u64) {
    use azos_behavior::rc_link::{link_loss_detail, RcVerdict};
    match rc_verdict(now) {
        RcVerdict::LinkLoss { age_ms } => {
            if azos_limits::RC_FAILSAFE_ESTOP {
                rc_latch(azos_behavior::safety::ESTOP_ACTION_RC_LINK_LOSS, link_loss_detail(age_ms),
                         if age_ms.is_none() { "link lost (receiver failsafe)" }
                         else { "link lost (no frame within RC_LINK_TIMEOUT_MS)" });
            }
        }
        RcVerdict::Kill { pulse_us } => {
            rc_latch(azos_behavior::safety::ESTOP_ACTION_RC_KILL, pulse_us as u32, "kill switch");
        }
        _ => {}
    }
}

/// The operator's sticks while the receiver is in manual override: the
/// drive they ask, `None` otherwise. `manual` carries the override's state
/// between calls, for its console lines.
#[cfg(feature = "rc-input")]
fn rc_sticks(now: u64, manual: &mut bool) -> Option<(i32, i32)> {
    use azos_behavior::rc_link::RcVerdict;
    let sticks = match rc_verdict(now) {
        RcVerdict::Manual { left, right } => Some((left, right)),
        _ => None,
    };
    match (*manual, sticks) {
        (true, None) => azos_drv_sys::kwarn!("[RC] manual override off"),
        (false, Some((l, r))) => azos_drv_sys::kwarn!("[RC] manual override on: sticks ask ({},{})", l, r),
        _ => {}
    }
    *manual = sticks.is_some();
    if cfg!(feature = "rc-stick-canary") { None } else { sticks }
}

/// The fence arms at the first good fix, and a breach latches the e-stop
/// with one durable record (the latch is the guard against a second).
#[cfg(feature = "geofence")]
fn fence_tick(state: &SensorState) {
    #[cfg(not(feature = "fence-arm-canary"))]
    if let Some((lat, lon, radius)) = azos_behavior::safety::geofence_arm_home(state) {
        azos_drv_sys::kprintln!("[GEOFENCE] armed at home fix ({},{}) udeg, radius {} m", lat, lon, radius);
    }
    if let Some(overshoot_m) = azos_behavior::safety::geofence_breach_latch(state) {
        let _ = azos_behavior::logger::log_safety_violation_durable(
            azos_behavior::logger::SAFETY_ESTOP, azos_behavior::safety::ESTOP_ACTION_GEOFENCE, overshoot_m);
        azos_drv_sys::kwarn!("[SAFETY] geofence breach — motors stopped, envelope latched ({} m beyond the fence)",
                             overshoot_m);
    }
}

/// The UART bridge's e-stop: every `PKT_ESTOP` frame on the line latches,
/// straight in the kernel, with no ring-3 program and no TCP in the path. The
/// line is the kernel's from `actuation::install` on and carries nothing else
/// on a robot: polled at the enforcer's period, its receive ring holds many
/// e-stop frames between two reads, and each read drains it.
fn bridge_estop() {
    use azos_drv_bus::uart_bridge as bridge;
    use azos_behavior::companion_protocol::take_estop_frames;
    static LINE: azos_sync::SpinLock<([u8; 256], usize)> = azos_sync::SpinLock::new(([0; 256], 0));
    if !bridge::bridge_is_ready() {
        return;
    }
    let estops = {
        let mut g = LINE.lock();
        let (buf, len) = &mut *g;
        let mut estops = 0;
        // A read that leaves room has emptied the ring; the bound keeps a
        // babbling line from holding the enforcer.
        for _ in 0..16 {
            let room = buf.len() - *len;
            let n = (bridge::bridge_recv(&mut buf[*len..]).max(0) as usize).min(room);
            let (found, keep) = take_estop_frames(buf, *len + n);
            estops += found;
            *len = keep;
            if n < room {
                break;
            }
        }
        estops
    };
    if estops > 0 {
        crate::frames::authority_frame(azos_behavior::companion_protocol::PKT_ESTOP, &[]);
    }
}
