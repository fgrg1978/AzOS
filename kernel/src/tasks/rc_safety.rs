// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The RC receiver and the geofence in the behavior loop (wave 15, owner
//! decision: wire both; Kconfig `RC_INPUT` / `GEOFENCE`, robot domain default
//! y, off = compiled out).
//!
//! Called once per behavior tick, after the brain's action is injected and
//! before arbitration, from `behavior.rs`:
//!
//! * [`rc_tick`] asks `azos_behavior::rc_link` what the receiver means. Link
//!   loss (with `RC_FAILSAFE_ESTOP`) and the kill switch latch the e-stop and
//!   write a durable `SAFETY_ESTOP` record, once per latch; manual mode puts
//!   the sticks in `state.rc_manual`, which the arbiter ranks below L0 and
//!   L1's stop and above autonomy; they reach the wheels only through
//!   `rt_motor`'s motor envelope and the actuation gate — the same
//!   chokepoints as the brain's commands.
//! * [`fence_tick`] arms the geofence at the boot's first trusted fix. The
//!   breach latch and its record stay where they were (`behavior.rs` step 3b).

use azos_behavior::types::SensorState;
use core::sync::atomic::{AtomicU32, Ordering};

/// Behavior-loop passes through this module (saturating). The wave-15 smokes
/// wait on it: the loop runs its in-kernel bench sweep before its first pass,
/// for several seconds of a QEMU boot, and a probe that fed the receiver
/// before then would be timing the sweep.
static LOOP_PASSES: AtomicU32 = AtomicU32::new(0);

/// Count one behavior-loop pass.
pub(crate) fn note_pass() {
    let _ = LOOP_PASSES.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                                     |n| Some(n.saturating_add(1)));
}

/// Behavior-loop passes so far.
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke", feature = "fence-refuse-smoke"))]
pub(crate) fn loop_passes() -> u32 {
    LOOP_PASSES.load(Ordering::Acquire)
}

/// Edge state of [`rc_tick`]'s console lines (one line per transition, not
/// one per tick).
#[cfg(feature = "rc-input")]
pub(crate) struct RcTickState {
    manual: bool,
}

#[cfg(feature = "rc-input")]
impl RcTickState {
    pub(crate) const fn new() -> Self { RcTickState { manual: false } }
}

/// Latch the e-stop for an RC source and record why, once per latch.
#[cfg(feature = "rc-input")]
fn rc_latch(action: u8, detail: u32, what: &str) {
    if azos_behavior::safety::estop_is_active() { return; }
    azos_behavior::safety::estop_activate();
    let _ = azos_behavior::logger::log_safety_violation_durable(
        azos_behavior::logger::SAFETY_ESTOP, action, detail);
    azos_drv_sys::kwarn!("[RC] {} — e-stop latched (SAFETY_ESTOP action {} detail {})",
                         what, action, detail);
}

/// The receiver's say this tick. See the module doc.
#[cfg(feature = "rc-input")]
pub(crate) fn rc_tick(state: &mut SensorState, now: u64, mem: &mut RcTickState) {
    use azos_behavior::rc_link::{rc_evaluate, link_loss_detail, RcPolicy, RcVerdict};
    use azos_robot_drivers::rc;
    const POLICY: RcPolicy = RcPolicy::from_limits(azos_drv_sys::timebase::TIMER_FREQ as u64);

    let verdict = rc_evaluate(&POLICY, rc::rc_frames_seen(), rc::rc_read(),
                              rc::rc_last_update(), now);
    // `rc-failsafe-canary`: the verdict is computed and then ignored, so the
    // row that proves link loss latches the e-stop must go red.
    #[cfg(feature = "rc-failsafe-canary")]
    let verdict = match verdict { RcVerdict::LinkLoss { .. } => RcVerdict::Passive, v => v };

    let manual = matches!(verdict, RcVerdict::Manual { .. });
    if mem.manual && !manual {
        azos_drv_sys::kwarn!("[RC] manual override off");
    }
    match verdict {
        RcVerdict::NoLink | RcVerdict::Passive => {}
        RcVerdict::LinkLoss { age_ms } => {
            if azos_limits::RC_FAILSAFE_ESTOP {
                rc_latch(azos_behavior::safety::ESTOP_ACTION_RC_LINK_LOSS,
                         link_loss_detail(age_ms),
                         if age_ms.is_none() { "link lost (receiver failsafe)" }
                         else { "link lost (no frame within RC_LINK_TIMEOUT_MS)" });
            }
        }
        RcVerdict::Kill { pulse_us } => {
            rc_latch(azos_behavior::safety::ESTOP_ACTION_RC_KILL, pulse_us as u32,
                     "kill switch");
        }
        RcVerdict::Manual { left, right } => {
            if !mem.manual {
                azos_drv_sys::kwarn!("[RC] manual override on: sticks ask ({},{})", left, right);
            }
            // `rc-stick-canary`: the sticks never reach arbitration.
            #[cfg(feature = "rc-stick-canary")]
            let _ = &state;
            #[cfg(not(feature = "rc-stick-canary"))]
            {
                state.rc_manual = azos_behavior::types::MotorOutput::some(left, right);
            }
        }
    }
    mem.manual = manual;
}

/// Arm the geofence at the boot's first trusted fix (once).
#[cfg(feature = "geofence")]
pub(crate) fn fence_tick(state: &SensorState) {
    // `fence-arm-canary`: the boot never arms the fence, as before wave 15.
    #[cfg(feature = "fence-arm-canary")]
    { let _ = state; return; }
    #[cfg(not(feature = "fence-arm-canary"))]
    if let Some((lat, lon, radius)) = azos_behavior::safety::geofence_arm_home(state) {
        azos_drv_sys::kwarn!("[GEOFENCE] armed at home fix ({},{}) udeg, radius {} m",
                             lat, lon, radius);
    }
}
