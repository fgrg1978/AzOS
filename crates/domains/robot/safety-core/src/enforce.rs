// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The robot's enforcer (`azos_ext_api::Enforcer`), run by the base's
//! enforcement task: the payload pulse's deadline, the RC receiver's link loss
//! and kill switch (Kconfig `RC_INPUT`), and the geofence's home arm and
//! breach latch (Kconfig `GEOFENCE`). Each latches the e-stop and records
//! why; none chooses a motion.

use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(any(feature = "rc-input", feature = "geofence"))]
use azos_behavior::types::SensorState;

/// Its period: the rate the sensor bus and the RC link are judged at.
const PERIOD_MS: u32 = 100;

pub static ROBOT_ENFORCER: azos_ext_api::Enforcer = azos_ext_api::Enforcer {
    name: "robot",
    period_ms: PERIOD_MS,
    tick,
};

/// Completed checks, for the smokes that wait for some to pass.
static PASSES: AtomicU32 = AtomicU32::new(0);

/// How many checks have completed.
pub fn passes() -> u32 {
    PASSES.load(Ordering::Acquire)
}

fn tick(now: u64) {
    azos_behavior::payload::payload_tick();
    #[cfg(feature = "rc-input")]
    rc_enforce(now);
    #[cfg(feature = "geofence")]
    {
        let mut state = SensorState::new();
        azos_behavior::sensor_bus::SENSOR_BUS.snapshot(&mut state);
        state.timestamp = now;
        fence_tick(&state);
    }
    #[cfg(not(any(feature = "rc-input", feature = "geofence")))]
    let _ = now;
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
pub fn rc_sticks(now: u64, manual: &mut bool) -> Option<(i32, i32)> {
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
