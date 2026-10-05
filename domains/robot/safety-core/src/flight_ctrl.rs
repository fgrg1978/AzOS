// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The flight controller task (Phase J+K).

use core::sync::atomic::{AtomicU32, Ordering};

use azos_drv_sys::kprintln;

/// Completed flight-control iterations, every path through the loop
/// included (armed or not). For measurement: the RT7 rows read whether the
/// loop kept its period across a contained kernel panic.
pub static FLIGHT_TICKS: AtomicU32 = AtomicU32::new(0);

/// Read-only view of [`FLIGHT_TICKS`].
#[inline]
pub fn flight_ticks() -> u32 {
    FLIGHT_TICKS.load(Ordering::Relaxed)
}

/// The flight controller's own reaction to a CONTAINED kernel panic (Kconfig
/// `PANIC_POLICY_CONTAIN`, RFC-0052 §5): the kernel parked the culprit and
/// keeps running; this loop then flies `Land` for `PANIC_CONTAIN_LAND_MS`
/// and disarms. Never a reset. Task-local state, polled once per tick.
struct ContainedPanicLanding {
    /// `panic_policy::contained_count()` already acted on.
    seen: u32,
    /// `timebase::now()` when the Land started; `None` when not landing.
    since: Option<u64>,
}

impl ContainedPanicLanding {
    const LAND_TICKS: u64 = azos_limits::PANIC_CONTAIN_LAND_MS as u64
        * (azos_drv_sys::timebase::TIMER_FREQ / 1000);

    fn new() -> Self {
        Self { seen: azos_common::panic_policy::contained_count(), since: None }
    }

    /// One tick. Runs before the armed / e-stop early exits, so a landing
    /// in progress is finished (or abandoned, if something else disarmed)
    /// whatever else this tick does.
    fn tick(&mut self, now: u64) {
        use azos_flight::{flight_disarm, flight_mode, is_armed, set_flight_mode, FlightMode};
        if !azos_limits::PANIC_POLICY_CONTAIN {
            return;
        }
        let count = azos_common::panic_policy::contained_count();
        if count != self.seen {
            self.seen = count;
            if !is_armed() {
                azos_drv_sys::kerr!("[FLIGHT] contained kernel panic #{}: not armed, nothing to land", count);
            } else if self.since.is_none() {
                azos_drv_sys::kerr!("[FLIGHT] contained kernel panic #{}: Land", count);
                set_flight_mode(FlightMode::Land);
                self.since = Some(now);
            } else {
                azos_drv_sys::kerr!("[FLIGHT] contained kernel panic #{}: already landing", count);
            }
        }
        let Some(t0) = self.since else { return };
        if !is_armed() {
            // Disarmed by something else meanwhile (a failsafe, the shell).
            azos_drv_sys::kerr!("[FLIGHT] contained kernel panic: disarmed during Land");
            self.since = None;
        } else if now.wrapping_sub(t0) >= Self::LAND_TICKS {
            azos_drv_sys::kerr!("[FLIGHT] contained kernel panic: Land done after {} ms, Disarm",
                azos_limits::PANIC_CONTAIN_LAND_MS);
            flight_disarm();
            azos_robot_drivers::esc::esc_disarm();
            self.since = None;
        } else if flight_mode() != FlightMode::Land {
            // The landing is sticky: no mode change ends it early.
            set_flight_mode(FlightMode::Land);
        }
    }
}

/// Phase J+K: flight controller task.
///
/// Reads attitude, RC/target, runs cascaded PID, computes mixer output,
/// and drives ESC channels.  Checks failsafes each iteration.
///
/// K-C27: runs at a nominal 1 kHz on a timer block, not at yield speed.
/// The loop already computes `dt_us` from real CLINT time precisely because
/// its iteration rate was never a constant; sleeping between ticks changes
/// only how often it samples, not any control mathematics. See
/// `RT_MOTOR_TICK_INTERVAL` for the tick-grid quantisation note.
pub fn flight_control_task(_: usize) {
    use azos_flight::*;
    use azos_ahrs::{CH_ATTITUDE, CH_IMU};

    /// Nominal flight-control period: 1 kHz (the documented upper design
    /// rate; the tickless grid bounds the effective rate below it).
    const FLIGHT_TICK_INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 1000;
    #[inline]
    fn flight_tick_sleep() {
        let dl = azos_drv_sys::timebase::now() + FLIGHT_TICK_INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }

    kprintln!("[FLIGHT] Phase J+K: flight controller starting (QuadX, cascaded PID)");

    let mut pid = FlightPid::new();
    let frame = FrameType::QuadX;
    let mut last_time = azos_drv_sys::timebase::now();
    let mut contained = ContainedPanicLanding::new();

    loop {
        FLIGHT_TICKS.fetch_add(1, Ordering::Relaxed);
        let now = azos_drv_sys::timebase::now();
        contained.tick(now);
        let dt_ticks = now.wrapping_sub(last_time);
        let dt_us = (dt_ticks * 1_000_000 / azos_drv_sys::timebase::TIMER_FREQ) as u32;
        last_time = now;

        // Skip unreasonable dt.
        if dt_us == 0 || dt_us > 1_000_000 {
            flight_tick_sleep();
            continue;
        }

        // Read RC input and publish to channel.
        if let Some((channels, failsafe)) = azos_robot_drivers::rc::rc_read() {
            // A failsafe frame is the receiver reporting it has LOST the
            // transmitter. Publishing it refreshed the channel, so the age
            // `check_failsafe` measures never grew and `FailsafeAction::RTL`
            // could not fire — while the sticks in that same frame were what
            // `Stabilize` flew on. See `rc_frame_is_fresh_input`.
            if rc_frame_is_fresh_input(failsafe) {
                let rc = RcInput {
                    channels,
                    rssi: 100,
                    failsafe,
                };
                CH_RC_INPUT.publish(rc, now);
            }
        }

        if !is_armed() {
            // Not armed — ensure ESC outputs are zero.
            for i in 0..4u8 {
                azos_robot_drivers::esc::esc_set_throttle(i, 0);
            }
            flight_tick_sleep();
            continue;
        }

        // U08-6 / H22, owner fix 2026-09-26: the e-stop latch reaches every
        // OTHER actuator through `motor_envelope`'s `estop_is_active()`
        // check, but this loop had none — `flight_arm()`/`esc_arm()` could
        // (and still can, from the shell) re-energise while the latch
        // holds, and this loop would keep computing and applying mixer
        // output regardless of `ARMED`. Checked every tick, not just once
        // at arm time: the latch can engage AFTER this task is already
        // running armed. `azos_behavior` is already a real dependency
        // of this crate (`boot_latch.rs`, `actuation.rs`), so this reads
        // the SAME state `motor_envelope` reads — not a second copy of it.
        if azos_behavior::safety::estop_is_active() {
            for i in 0..4u8 {
                azos_robot_drivers::esc::esc_set_throttle(i, 0);
            }
            flight_tick_sleep();
            continue;
        }

        // Check failsafes.
        // `age_us`, not `age(now) * 1_000_000`. `age` returns `u64::MAX` for a
        // channel nobody has published to, and this kernel has
        // `overflow-checks = true` with `panic = "abort"` — so that multiply
        // was a board reset, reachable on real hardware and invisible here:
        // `CH_RC_INPUT` is published only when `rc_read()` returns `Some`, and
        // `RcMode::Sbus` fails closed and returns `None`. See
        // `Channel::age_us`.
        let att_age = CH_ATTITUDE.age_us(now, azos_drv_sys::timebase::TIMER_FREQ);
        let rc_age = CH_RC_INPUT.age_us(now, azos_drv_sys::timebase::TIMER_FREQ);
        // Server age: use flight target channel.
        let srv_age = CH_FLIGHT_TARGET.age_us(now, azos_drv_sys::timebase::TIMER_FREQ);

        let fs = check_failsafe(att_age, rc_age, srv_age);
        match fs {
            FailsafeAction::Disarm => {
                azos_drv_sys::kerr!("[FLIGHT] FAILSAFE: Disarm (critical failure)");
                flight_disarm();
                azos_robot_drivers::esc::esc_disarm();
                flight_tick_sleep();
                continue;
            }
            FailsafeAction::Land => {
                if flight_mode() != FlightMode::Land {
                    azos_drv_sys::kerr!("[FLIGHT] FAILSAFE: Land (attitude loss)");
                    set_flight_mode(FlightMode::Land);
                }
            }
            FailsafeAction::RTL => {
                if flight_mode() != FlightMode::RTL && flight_mode() != FlightMode::Land {
                    azos_drv_sys::kerr!("[FLIGHT] FAILSAFE: RTL (RC link loss)");
                    set_flight_mode(FlightMode::RTL);
                }
            }
            FailsafeAction::PosHold => {
                if flight_mode() == FlightMode::Auto {
                    set_flight_mode(FlightMode::PosHold);
                }
            }
            FailsafeAction::None => {}
        }

        // Get flight target (from RC or server depending on mode).
        let target = match flight_mode() {
            FlightMode::Manual | FlightMode::Stabilize | FlightMode::AltHold => {
                // RC-driven.
                let rc = CH_RC_INPUT.read().val;
                rc_to_target(&rc)
            }
            FlightMode::Auto | FlightMode::PosHold => {
                // Server-driven (or last published target).
                CH_FLIGHT_TARGET.read().val
            }
            FlightMode::RTL | FlightMode::Land => {
                // Auto-generated: level, descend slowly.
                FlightTarget {
                    roll_cdeg: 0,
                    pitch_cdeg: 0,
                    yaw_rate_mdps: 0,
                    throttle: if flight_mode() == FlightMode::Land { 300 } else { 400 },
                    alt_mm: 0,
                }
            }
            FlightMode::Disarmed => {
                FlightTarget::new()
            }
        };

        // Read attitude and gyro.
        let att = CH_ATTITUDE.read().val;
        let imu = CH_IMU.read().val;

        // Cascaded PID per axis.
        let roll_corr = pid.update_axis(
            target.roll_cdeg - att.roll_cdeg,
            imu.gyro_mdps[0],
            0, dt_us);
        let pitch_corr = pid.update_axis(
            target.pitch_cdeg - att.pitch_cdeg,
            imu.gyro_mdps[1],
            1, dt_us);
        // Yaw: in Manual/Stabilize, use rate control directly.
        let yaw_corr = pid.rate_pid[2].update(
            (target.yaw_rate_mdps as i64 - imu.gyro_mdps[2] as i64)
                .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            dt_us);

        // Compute mixer output.
        let mix = mixer_compute(frame, target.throttle as i32, roll_corr, pitch_corr, yaw_corr);

        // Apply to ESCs.
        for i in 0..mix.count as u8 {
            azos_robot_drivers::esc::esc_set_throttle(i, mix.motors[i as usize]);
        }

        flight_tick_sleep();
    }
}
