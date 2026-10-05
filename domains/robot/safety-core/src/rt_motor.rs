// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's RT motor control task and its wheel-write wrapper.

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;

use crate::txn::{txn_arm, txn_note_tick_complete};
use crate::watchdog::CONTROL_HEARTBEAT;

/// Nominal control-tick period for `rt_motor_task`: 1 kHz. The effective
/// rate is bounded below by the tickless timer grid (see the block at the
/// loop tail); on QEMU with `SCHED_HZ = 100` and four staggered harts it
/// lands in the hundreds of Hz. The PID, watchdog and envelope all compute
/// from real CLINT time, so the rate change does not touch them. The
/// simulated encoder (`encoder_tick`, speed × iteration) does scale with
/// this rate — and becomes *better*: ticks now accrue at a timer-driven
/// cadence instead of at whatever speed the host happened to emulate the
/// yield loop, which made every derived odometry figure host-dependent.
const RT_MOTOR_TICK_INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 1000;

/// One wheel write from the kernel's own control loop.
///
/// Wraps `motor_set` so the `actuation-smoke` marker can report what the
/// KERNEL applied, on exactly the terms the ring-3 marker uses: the value
/// comes out of the write itself (`motor_set_reporting`), never from a later
/// read of the channel — these two channels have two writers and a read taken
/// afterwards can be handed the other one's duty.
///
/// Why the kernel side needs a marker at all: `[ACTSMOKE] ring3 ...` proves a
/// ring-3 call actuated, and proves nothing about whether the wheel STAYED
/// there. This loop rewrites both wheels from `CH_MOTOR_CMD` every control
/// tick, so any claim of the form "the robot stopped" is a claim about this
/// writer, not about the syscall.
#[inline]
fn control_apply_wheel(id: u32, dir: azos_robot::MotorDir, speed_pct: u32) {
    let (_rc, _applied) = azos_robot::motor_set_reporting(id, dir, speed_pct);
    #[cfg(feature = "actuation-smoke")]
    actsmoke_kernel_apply(id, _applied);
}

/// Print the kernel control loop's applied duty, **on transitions only**.
///
/// This loop writes both wheels on every tick, so a line per write would be
/// thousands of UART frames a boot on the actuation path — the measurement
/// would change what it measures (see the i3 probe). A duty that holds for a
/// minute is one event, same edge-triggered rule the envelope marker uses.
#[cfg(feature = "actuation-smoke")]
fn actsmoke_kernel_apply(id: u32, applied: Option<u32>) {
    use core::sync::atomic::{AtomicI32, Ordering as O};
    // -1 is "nothing applied yet", and is also what a refused write reports,
    // so the two are deliberately the same observable: neither drove a wheel.
    static LAST: [AtomicI32; 2] = [AtomicI32::new(-2), AtomicI32::new(-2)];
    let v = applied.map(|d| d as i32).unwrap_or(-1);
    if let Some(slot) = LAST.get(id as usize) {
        if slot.swap(v, O::Relaxed) != v {
            kprintln!("[ACTSMOKE] kernel motor id={} duty={}", id, v);
        }
    }
}

/// Set by [`request_canary_panic`]: `rt_motor_task` panics on its next tick.
#[cfg(feature = "rt-panic-canary-safety")]
static CANARY_PANIC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// RT7 canary (`rt-panic-canary-safety`): make rt-motor panic on its next tick.
#[cfg(feature = "rt-panic-canary-safety")]
pub fn request_canary_panic() {
    CANARY_PANIC.store(true, Ordering::Release);
}

/// Phase 13/G1: RT motor task — apply MotorCmd to motors; fire safe-stop on watchdog.
///
/// Reads `motor_cmd_read()` each tick, checks the watchdog, and drives
/// motors 0 and 1 according to the published command.  Runs forever.
/// The motor-command watchdog's report window: one `SAFETY_RT_WATCHDOG`
/// repeats record (and console line) at most per window. 5 s under
/// `rtwd-window-smoke`, so the gate row sees a window close in a short boot.
const RT_WD_WINDOW_S: u64 = if cfg!(feature = "rtwd-window-smoke") { 5 } else { 60 };

/// One reported watchdog transition (`azos_behavior::logger::
/// RtWatchdogReports` decides which): the console line and the
/// `SAFETY_RT_WATCHDOG` record. The SAFE STOP record is durable (flushed
/// before returning): the motors are already stopped, and it is the event
/// most likely to be followed by a reset. The clear and the repeats count
/// go through the ring and the watchdog task's periodic flush, so a running
/// control loop never waits on the block device.
/// `rtwd-record-canary` (gate canary) prints and does not record.
fn rt_watchdog_report(action: u8, detail: u32) {
    use azos_behavior::logger as log;
    match action {
        log::RTWD_ACTION_STOP =>
            azos_drv_sys::kwarn!("[RT-MOTOR] Watchdog! No command >500 ms → SAFE STOP"),
        log::RTWD_ACTION_CLEAR =>
            azos_drv_sys::kwarn!("[RT-MOTOR] Watchdog cleared — resuming"),
        _ => {
            let (n, stopped) = log::rtwd_repeats_from_detail(detail);
            azos_drv_sys::kwarn!(
                "[RT-MOTOR] Watchdog: {} repeat(s) in the last {} s (SAFE STOP / cleared transitions); now {}",
                n, RT_WD_WINDOW_S, if stopped { "SAFE STOP" } else { "running" });
        }
    }
    if cfg!(feature = "rtwd-record-canary") {
        return;
    }
    if action == log::RTWD_ACTION_STOP {
        let _ = log::log_safety_violation_durable(log::SAFETY_RT_WATCHDOG, action, detail);
    } else {
        log::log_safety_violation(log::SAFETY_RT_WATCHDOG, action, detail);
    }
}

pub fn rt_motor_task(_: usize) {
    // I-13: arm the transactional checkpoint so a recoverable (misaligned)
    // fault mid-tick restarts here — safe-stop + continue — instead of halting
    // the kernel. The reset SP is the task's CLEAN stack top (pre-prologue),
    // not a mid-function SP, so each restart runs the entry prologue exactly
    // once and the stack does not leak a frame per rollback. Re-runs on every
    // (re)entry; the abort budget (MAX_TXN_RESTARTS) bounds deterministic faults.
    txn_arm(
        azos_sched::current_task_stack_top(),
        rt_motor_task as fn(usize) as usize,
    );
    kprintln!("[RT-MOTOR] Starting (watchdog timeout=500 ms, PID velocity control)");
    let mut safe_mode = false;
    let mut wd_reports = azos_behavior::logger::RtWatchdogReports::new(
        azos_drv_sys::timebase::now(), RT_WD_WINDOW_S * azos_drv_sys::timebase::TIMER_FREQ);
    // RFC-0033 observability: edge-triggered, so a command that stays over the
    // cap logs once rather than every tick of this loop. Until the flight
    // recorder is wired, the console IS the audit trail, and a safety
    // intervention that leaves no trace at all cannot be audited or tested.
    let mut envelope_clamping = false;

    /// Left motor hardware ID.
    const MOTOR_ID_LEFT: u32 = 0;
    /// Right motor hardware ID.
    const MOTOR_ID_RIGHT: u32 = 1;

    loop {
        let fired = azos_robot::motor_watchdog_fired();

        if fired && !safe_mode {
            azos_robot::motor_stop(MOTOR_ID_LEFT);
            azos_robot::motor_stop(MOTOR_ID_RIGHT);
            azos_drv_actuator::motor_pid::motor_pid_reset();
            // Reported after the stop: its record is durable, and the flush
            // must not stand between the watchdog and the motors.
            if let Some((action, detail)) = wd_reports.stop() {
                rt_watchdog_report(action, detail);
            }
            safe_mode = true;
        } else if !fired {
            if safe_mode {
                if let Some((action, detail)) = wd_reports.clear() {
                    rt_watchdog_report(action, detail);
                }
                safe_mode = false;
            }
            let mut cmd = azos_robot::motor_cmd_read();
            if azos_robot::CH_MOTOR_CMD.is_valid() {
                // RFC-0033: bounded runtime safety monitor — the LAST line of
                // defence at the single MotorCmd→PWM chokepoint. Enforces hard
                // ESTOP + per-robot-type speed cap on the command MAGNITUDE
                // (the sensor-reactive L0 upstream does not). Structurally
                // NOT unbypassable — this is one caller of `motor_set` among
                // several, and the syscall path does not come through here.
                // The gate inside `motor_set` is what makes it unavoidable.
                let (env_l, env_r) = azos_behavior::safety::motor_envelope(
                    cmd.speed_l, cmd.speed_r);

                // Report the intervention on its edges. The comparison is
                // against what was ASKED for, so this fires whenever the
                // envelope actually changed the command — estop, per-type cap,
                // low-confidence cap or degrade level, whichever bound bit.
                let clamped = env_l != cmd.speed_l || env_r != cmd.speed_r;
                if clamped && !envelope_clamping {
                    azos_drv_sys::kwarn!(
                        "[ENVELOPE] refused: asked ({},{}) applied ({},{})",
                        cmd.speed_l, cmd.speed_r, env_l, env_r
                    );
                    // The thesis sentence ends "and without a record". This is
                    // that record. The console line above is lost on reboot,
                    // and a safety intervention nobody can audit afterwards
                    // may as well not have been made. Edge-triggered like the
                    // print: a clamp that holds for a minute is one event, not
                    // six thousand.
                    azos_behavior::logger::log_safety_violation(
                        azos_behavior::logger::SAFETY_ENVELOPE_REFUSED, 0,
                        ((cmd.speed_l as u16 as u32) << 16) | (env_l as u16 as u32));
                    envelope_clamping = true;
                } else if !clamped && envelope_clamping {
                    azos_drv_sys::kwarn!("[ENVELOPE] within bounds again");
                    azos_behavior::logger::log_safety_violation(
                        azos_behavior::logger::SAFETY_ENVELOPE_REFUSED, 1,
                        ((cmd.speed_l as u16 as u32) << 16) | (env_l as u16 as u32));
                    envelope_clamping = false;
                }

                cmd.speed_l = env_l;
                cmd.speed_r = env_r;

                // Phase 17: accumulate simulated encoder ticks.
                azos_robot::encoder_tick(cmd.speed_l, cmd.speed_r);

                if azos_drv_actuator::motor_pid::motor_pid_enabled() {
                    // Closed-loop PID velocity control.
                    // Set target from the motor command (speed as ticks/s).
                    azos_drv_actuator::motor_pid::motor_pid_set_target(
                        cmd.speed_l as i16,
                        cmd.speed_r as i16,
                    );

                    // Read encoders and run PID tick.
                    let (ticks_l, ticks_r) = azos_robot::encoder_read();
                    let now = azos_drv_sys::timebase::now();
                    let (pwm_l, pwm_r) =
                        azos_drv_actuator::motor_pid::motor_pid_tick(ticks_l, ticks_r, now);

                    // Apply PID output to motors.
                    let (dir_l, spd_l) = if pwm_l >= 0 {
                        (azos_robot::MotorDir::Forward,  pwm_l as u32)
                    } else {
                        (azos_robot::MotorDir::Backward, (-pwm_l) as u32)
                    };
                    let (dir_r, spd_r) = if pwm_r >= 0 {
                        (azos_robot::MotorDir::Forward,  pwm_r as u32)
                    } else {
                        (azos_robot::MotorDir::Backward, (-pwm_r) as u32)
                    };
                    control_apply_wheel(MOTOR_ID_LEFT, dir_l, spd_l);
                    control_apply_wheel(MOTOR_ID_RIGHT, dir_r, spd_r);
                } else {
                    // Open-loop: direct PWM from motor command (legacy behavior).
                    let (dir_l, spd_l) = if cmd.speed_l >= 0 {
                        (azos_robot::MotorDir::Forward,  cmd.speed_l as u32)
                    } else {
                        (azos_robot::MotorDir::Backward, (-cmd.speed_l) as u32)
                    };
                    let (dir_r, spd_r) = if cmd.speed_r >= 0 {
                        (azos_robot::MotorDir::Forward,  cmd.speed_r as u32)
                    } else {
                        (azos_robot::MotorDir::Backward, (-cmd.speed_r) as u32)
                    };
                    control_apply_wheel(MOTOR_ID_LEFT, dir_l, spd_l);
                    control_apply_wheel(MOTOR_ID_RIGHT, dir_r, spd_r);
                }
            }
        }

        // K-A1: a completed iteration proves the control task is alive; the
        // timer ISR feeds the hardware WDT only while this advances.
        CONTROL_HEARTBEAT.fetch_add(1, Ordering::Relaxed);

        // RT7 canary: a panic in a safety task, at a point that holds no lock
        // (no SpinLock, no PiMutex, interrupts on), so the only check of the
        // containment predicate it fails is "a safety task".
        #[cfg(feature = "rt-panic-canary-safety")]
        if CANARY_PANIC.load(Ordering::Acquire) {
            panic!("rt-panic-canary: deliberate panic in rt-motor (a safety task)");
        }

        // I-13: a completed tick proves forward progress — clear the restart
        // streak so the abort budget only counts consecutive no-progress
        // restarts (a deterministic fault), not lifetime one-off transients.
        txn_note_tick_complete();

        // K-C27: sleep until the next control tick instead of yield-polling.
        // The old `task_yield()` here made this loop run ~215,000 iterations
        // per second under QEMU TCG (32M scheduler entries in a 150 s run),
        // which monopolised hart 0 for the whole boot: under strict priority
        // with no aging, nothing below RT priority ever dispatched there.
        // Timer-blocking is the same idiom `imu_task` (also RT band) has
        // used all along; the wake path (timer ISR → `wake_expired_timers`
        // → home-hart enqueue + IPI) is the proven one. The period is 1 ms:
        // the block programs the hart's timer for this deadline when it is
        // earlier than what is programmed (wave 11 ONESHOT; before that a
        // busy hart saw it at the next tick, up to 10 ms later).
        // CONTROL_HEARTBEAT still advances every iteration, far inside the
        // feeder's stall grace (40 ticks and 400 ms, `watchdog.rs`).
        let now = azos_drv_sys::timebase::now();
        if let Some((action, detail)) = wd_reports.tick(now, safe_mode) {
            rt_watchdog_report(action, detail);
        }
        let dl = now + RT_MOTOR_TICK_INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
}
