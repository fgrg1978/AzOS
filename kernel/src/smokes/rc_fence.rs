// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 15 smokes: the RC receiver and the geofence wired into the safety
//! path, one property per boot (a latched e-stop would mask the next one).
//!
//! The receiver and the GPS are board-blocked, so the test feeders push bytes
//! through the same functions a board's UART receive interrupts call:
//! `azos_robot_drivers::rc::rc_feed_byte` (SBUS frames built with
//! `sbus_encode`) and `azos_gps::gps_feed_byte` (an NMEA GGA sentence). Every
//! verdict line is `[RCSMOKE] PASS|FAIL <property>: ...`; the gate rows
//! (`tools/ci_check.sh`, "RC input and geofence") anchor on them and on the
//! kernel's own lines (`[RC] ...`, `[ENVELOPE] refused: ...`, `[SAFETY]
//! geofence breach`).

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

fn sleep_ms(ms: u64) {
    azos_sched::task_block(azos_sched::WaitReason::Timer(now() + ms * (TIMER_FREQ / 1000).max(1)));
}

/// How long the boot's tasks get to reach their loops first.
const SETTLE_MS: u64 = 2_000;

/// Poll the flight recorder (up to 5 s) for the record `find` looks for. The
/// latch is taken BEFORE its durable record is written (the stop is the urgent
/// half), so a probe that sees the e-stop can still be ahead of the write.
#[cfg(any(feature = "rc-failsafe-smoke", feature = "fence-refuse-smoke"))]
fn poll_record(find: impl Fn() -> (bool, u32)) -> (bool, u32) {
    let t0 = now();
    loop {
        let r = find();
        if r.0 || now() - t0 > 5 * TIMER_FREQ { return r; }
        sleep_ms(200);
    }
}

/// Wait (up to 60 s) until the behavior loop has made a few passes: it runs a
/// bench sweep before its first one. `false` if it never did.
fn wait_behavior_loop() -> bool {
    sleep_ms(SETTLE_MS);
    let start = crate::tasks::rc_safety::loop_passes();
    let t0 = now();
    while crate::tasks::rc_safety::loop_passes() < start.saturating_add(3) {
        if now() - t0 > 60 * TIMER_FREQ {
            kprintln!("[RCSMOKE] FAIL setup: the behavior loop made no pass in 60 s");
            return false;
        }
        sleep_ms(50);
    }
    true
}
/// Gap between two fed SBUS frames (a receiver sends one every 7-14 ms).
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke"))]
const FRAME_GAP_MS: u64 = 10;

/// One SBUS frame with every channel centred except the ones given, as
/// (1-based channel, pulse us); channel 0 entries are skipped.
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke"))]
fn frame(set: &[(usize, u16)], failsafe: bool) -> [u8; azos_robot_drivers::rc::SBUS_FRAME_LEN] {
    use azos_robot_drivers::rc::{sbus_encode, sbus_us_to_raw, SbusFrame};
    let mut channels = [sbus_us_to_raw(1500); 16];
    for &(ch, us) in set {
        if (1..=16).contains(&ch) { channels[ch - 1] = sbus_us_to_raw(us); }
    }
    sbus_encode(&SbusFrame { channels, failsafe, frame_lost: false, ch17: false, ch18: false })
}

/// Feed `f` every [`FRAME_GAP_MS`] for `ms`; the number of frames the byte
/// source decoded and applied.
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke"))]
fn feed_for(f: &[u8; azos_robot_drivers::rc::SBUS_FRAME_LEN], ms: u64) -> u32 {
    let end = now() + ms * (TIMER_FREQ / 1000).max(1);
    let mut applied = 0;
    while now() < end {
        for &b in f.iter() {
            if azos_robot_drivers::rc::rc_feed_byte(b) { applied += 1; }
        }
        sleep_ms(FRAME_GAP_MS);
    }
    applied
}

/// Switch channels at "off": the mode and kill switches low.
#[cfg(feature = "rc-failsafe-smoke")]
const SWITCHES_OFF: [(usize, u16); 2] = [
    (azos_limits::RC_MODE_CHANNEL, 1000),
    (azos_limits::RC_KILL_CHANNEL, 1000),
];

/// RC link loss latches the e-stop and is recorded.
///
/// 1. one second of good frames (switches off) — the link is up, the e-stop
///    clear; 2. frames carrying the receiver's failsafe bit — the behavior
///    loop must latch the e-stop and write SAFETY_ESTOP / RC_LINK_LOSS with
///    detail 0 (the receiver's verdict), read back off the disk.
#[cfg(feature = "rc-failsafe-smoke")]
pub(crate) fn rc_failsafe_smoke_task(_arg: usize) {
    use azos_behavior::logger::SAFETY_ESTOP;
    use azos_behavior::safety::{estop_is_active, ESTOP_ACTION_RC_LINK_LOSS};
    if !wait_behavior_loop() { return; }
    let good = feed_for(&frame(&SWITCHES_OFF, false), 1_000);
    if good == 0 || !azos_robot_drivers::rc::rc_frames_seen() {
        kprintln!("[RCSMOKE] FAIL failsafe: the byte source applied no frame");
        return;
    }
    if estop_is_active() {
        kprintln!("[RCSMOKE] FAIL failsafe: the e-stop was latched before the link was lost");
        return;
    }
    kprintln!("[RCSMOKE] link up: {} frames applied, e-stop clear", good);
    let _ = feed_for(&frame(&SWITCHES_OFF, true), 500);
    let t0 = now();
    while !estop_is_active() && now() - t0 < 10 * TIMER_FREQ { sleep_ms(20); }
    let latched = estop_is_active();
    let (recorded, records) = poll_record(|| super::find_safety_record_detail_on_disk(
        SAFETY_ESTOP, ESTOP_ACTION_RC_LINK_LOSS, Some(0)));
    if latched && recorded {
        kprintln!("[RCSMOKE] PASS failsafe: receiver failsafe latched the e-stop; \
                   SAFETY_ESTOP action {} detail 0 on disk ({} records)",
                  ESTOP_ACTION_RC_LINK_LOSS, records);
    } else {
        kprintln!("[RCSMOKE] FAIL failsafe: latched={} recorded={} ({} records)",
                  latched, recorded, records);
    }
}

/// A stick command reaches the motors only through the motor envelope.
///
/// Mode switch on, drive stick fully forward: the behavior loop must publish
/// MotorCmd (full scale, full scale) — the sticks' ask, through L0 — and
/// `rt_motor` prints the clamp it applies (`[ENVELOPE] refused: asked
/// (100,100) applied (80,80)` on a wheeled robot), which the row reads.
#[cfg(feature = "rc-stick-smoke")]
pub(crate) fn rc_stick_smoke_task(_arg: usize) {
    if !wait_behavior_loop() { return; }
    let full = azos_limits::RC_STICK_FULL_SCALE_PCT as i32;
    let f = frame(&[
        (azos_limits::RC_MODE_CHANNEL, 2000),
        (azos_limits::RC_KILL_CHANNEL, 1000),
        (azos_limits::RC_DRIVE_CHANNEL, 2000),
        (azos_limits::RC_STEER_CHANNEL, 1500),
    ], false);
    // Feed for up to 3 s and watch MotorCmd between frames.
    let end = now() + 3 * TIMER_FREQ;
    let mut seen = false;
    let mut last = (0, 0);
    while now() < end && !seen {
        let _ = feed_for(&f, 100);
        let c = azos_robot::motor_cmd_read();
        last = (c.speed_l, c.speed_r);
        seen = last == (full, full);
    }
    // Keep the sticks on a little longer so rt_motor's clamp line lands
    // while the command still stands.
    let _ = feed_for(&f, 500);
    let (env_l, env_r) = azos_behavior::safety::motor_envelope(full, full);
    if seen && !azos_behavior::safety::estop_is_active() {
        kprintln!("[RCSMOKE] PASS stick: MotorCmd asked ({},{}) from the sticks; envelope bound ({},{})",
                  full, full, env_l, env_r);
    } else {
        kprintln!("[RCSMOKE] FAIL stick: MotorCmd never carried the sticks (last ({},{}), estop={})",
                  last.0, last.1, azos_behavior::safety::estop_is_active());
    }
}

/// A position outside the fence the BOOT armed refuses a motor write, with a
/// recorded reason.
///
/// Never calls `geofence_set`: it waits for the behavior loop to arm the fence
/// at the home fix, checks a motor write is admitted inside it, feeds a fix
/// outside, and then requires the same write to be refused at the actuation
/// gate and SAFETY_ESTOP / GEOFENCE to be on the disk.
#[cfg(feature = "fence-refuse-smoke")]
pub(crate) fn fence_refuse_smoke_task(_arg: usize) {
    use azos_behavior::logger::SAFETY_ESTOP;
    use azos_behavior::safety::{estop_is_active, geofence_armed, ESTOP_ACTION_GEOFENCE};
    use azos_robot::motor::{motor_set_reporting, motor_state, MotorDir, MOTOR_REFUSED_HALTED};
    if !wait_behavior_loop() { return; }
    let t0 = now();
    while !geofence_armed() && now() - t0 < 10 * TIMER_FREQ { sleep_ms(100); }
    if !geofence_armed() {
        kprintln!("[RCSMOKE] FAIL fence: the boot never armed the geofence");
        return;
    }
    while motor_state(0).is_none() && now() - t0 < 20 * TIMER_FREQ { sleep_ms(50); }
    if estop_is_active() {
        kprintln!("[RCSMOKE] FAIL fence: the e-stop was latched while inside the fence");
        return;
    }
    let (rc_in, applied_in) = motor_set_reporting(0, MotorDir::Forward, 40);
    if rc_in != 0 || applied_in.unwrap_or(0) == 0 {
        kprintln!("[RCSMOKE] FAIL fence: inside the fence motor 0 forward 40% answered rc={} applied={:?}",
                  rc_in, applied_in);
        return;
    }
    let mut accepted = false;
    for &b in super::OUTSIDE_GGA { accepted |= azos_gps::gps_feed_byte(b); }
    if !accepted {
        kprintln!("[RCSMOKE] FAIL fence: the GPS driver rejected the outside fix");
        return;
    }
    // The fix reaches the bus on `sensor-ahrs`'s next GPS publish and the
    // breach on the behavior loop's next pass; a loaded host stretches both.
    let t1 = now();
    while !estop_is_active() && now() - t1 < 20 * TIMER_FREQ { sleep_ms(20); }
    let latched = estop_is_active();
    if !latched {
        kprintln!("[RCSMOKE] FAIL fence: no e-stop within 20 s of the outside fix");
        return;
    }
    let (rc_out, applied_out) = motor_set_reporting(0, MotorDir::Forward, 40);
    let (recorded, records) = poll_record(|| super::find_safety_record_on_disk(
        SAFETY_ESTOP, ESTOP_ACTION_GEOFENCE));
    if rc_out == MOTOR_REFUSED_HALTED && applied_out == Some(0) && recorded {
        kprintln!("[RCSMOKE] PASS fence: inside admitted 40% (applied {:?}); outside refused \
                   (rc={}, applied 0%); SAFETY_ESTOP action {} on disk ({} records)",
                  applied_in, rc_out, ESTOP_ACTION_GEOFENCE, records);
    } else {
        kprintln!("[RCSMOKE] FAIL fence: outside, e-stop latched: rc={} applied={:?} recorded={}",
                  rc_out, applied_out, recorded);
    }
}
