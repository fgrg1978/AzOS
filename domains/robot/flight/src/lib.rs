// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Flight controller — mixer, PID, modes (Phases J + K) + drone phases D01-D06.
//!
//! Provides the core flight control components for multirotor drones:
//! - **Mixer**: converts roll/pitch/yaw/throttle commands into per-motor throttle
//! - **Flight PID**: cascaded angle → rate PID for 3 axes + altitude hold
//! - **Flight modes**: Disarmed, Manual, Stabilize, AltHold, PosHold, Auto, RTL, Land
//! - **Failsafe**: automatic mode transitions on link/sensor loss
//!
//! All arithmetic is integer (no `f32`).  PID gains are stored × 1000.
//!
//! # Channels
//!
//! - `CH_FLIGHT_TARGET` — desired attitude/throttle (from RC or server)
//! - `CH_RC_INPUT`      — raw RC receiver channels

// D01-D06: drone-critical modules
pub mod ekf;
pub mod sitl;
pub mod path3d;
pub mod terrain;
pub mod slam;
// D04: pure drone math (integer trig + wind estimator) lives in the
// dependency-free `azos_flight_math` leaf crate so it is host-testable.
// Re-exported here so existing `azos_flight::{trig,wind}` / `crate::trig`
// paths keep resolving.
pub use azos_flight_math::{position, trig, wind};

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use azos_channel::Channel;
use azos_robot_drivers::rc::{RC_PULSE_MAX_US, RC_PULSE_MIN_US};

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum number of motors supported.
pub const MAX_MOTORS: usize = 8;

/// Centre of the RC pulse-width range, in microseconds.
///
/// `RcInput::channels` holds exactly what `azos_robot_drivers::rc::rc_read`
/// returns — pulse widths in `RC_PULSE_MIN_US`..=`RC_PULSE_MAX_US` — so the
/// neutral stick is the midpoint of that range. Its home is beside the two
/// bounds in `domains/robot/drivers/src/rc.rs`.
pub const RC_PULSE_CENTER_US: u16 = (RC_PULSE_MIN_US + RC_PULSE_MAX_US) / 2;

// `rc_to_target` scales `channel_signed` by 9 and by 60 to reach ±4500 cdeg
// and ±30000 mdps. Both multipliers are correct only for a half-span of
// exactly 500 µs: a wider driver pulse range would carry a stick command past
// the attitude limits those conversions declare.
const _: () = assert!(
    RC_PULSE_CENTER_US - RC_PULSE_MIN_US == 500,
    "RC half-span moved: the ×9 and ×60 scalings in rc_to_target no longer land on ±4500 cdeg / ±30000 mdps"
);

/// Throttle range: 0 = off, 1000 = full power.
pub const THROTTLE_MAX: u16 = 1000;

// `rc_to_target` feeds `channel_unsigned(RC_CH_THROTTLE)` — whose top is the
// RC pulse span — straight into `FlightTarget::throttle`, whose top is
// `THROTTLE_MAX`. The two are equal by numeric coincidence, not by
// derivation: they are a pulse width in microseconds and a per-motor throttle
// unit. Nothing converts between them, so hold the coincidence here.
const _: () = assert!(
    RC_PULSE_MAX_US - RC_PULSE_MIN_US == THROTTLE_MAX,
    "RC pulse span no longer equals THROTTLE_MAX: rc_to_target needs a scaling step"
);

/// Minimum throttle when armed (keeps propellers spinning for response).
pub const THROTTLE_IDLE: u16 = 50;

// ── Channels ────────────────────────────────────────────────────────────────

/// Channel for flight target (from RC input, autopilot, or server).
pub static CH_FLIGHT_TARGET: Channel<FlightTarget> = Channel::new(FlightTarget::new());

/// Channel for RC receiver input.
pub static CH_RC_INPUT: Channel<RcInput> = Channel::new(RcInput::new());

// ── Types ───────────────────────────────────────────────────────────────────

/// Desired flight state (from pilot or autopilot).
#[derive(Clone, Copy)]
pub struct FlightTarget {
    /// Target roll angle in centi-degrees (-18000..+18000).
    pub roll_cdeg: i32,
    /// Target pitch angle in centi-degrees (-9000..+9000).
    pub pitch_cdeg: i32,
    /// Target yaw rate in milli-degrees/sec.
    pub yaw_rate_mdps: i32,
    /// Throttle 0-1000 (0.0%-100.0%).
    pub throttle: u16,
    /// Target altitude in mm (for AltHold/PosHold modes).
    pub alt_mm: i32,
}

impl FlightTarget {
    pub const fn new() -> Self {
        FlightTarget {
            roll_cdeg: 0,
            pitch_cdeg: 0,
            yaw_rate_mdps: 0,
            throttle: 0,
            alt_mm: 0,
        }
    }
}

/// RC receiver input (SBUS / PPM).
#[derive(Clone, Copy)]
pub struct RcInput {
    /// Channel values in microseconds, in RC_PULSE_MIN_US..=RC_PULSE_MAX_US
    /// with RC_PULSE_CENTER_US as the neutral stick.
    pub channels: [u16; 16],
    /// RSSI (0-100%).
    pub rssi: u8,
    /// True if receiver has lost signal.
    pub failsafe: bool,
}

impl RcInput {
    pub const fn new() -> Self {
        RcInput {
            channels: [RC_PULSE_CENTER_US; 16],
            rssi: 0,
            failsafe: true,
        }
    }

    /// Map a channel pulse width to a signed value, centred on
    /// RC_PULSE_CENTER_US and spanning ±half the driver's pulse range.
    pub fn channel_signed(&self, ch: usize) -> i32 {
        if ch >= 16 { return 0; }
        self.channels[ch] as i32 - RC_PULSE_CENTER_US as i32
    }

    /// Map a channel pulse width to 0..=(RC_PULSE_MAX_US - RC_PULSE_MIN_US).
    pub fn channel_unsigned(&self, ch: usize) -> u16 {
        if ch >= 16 { return 0; }
        let v = self.channels[ch];
        if v <= RC_PULSE_MIN_US { 0 }
        else if v >= RC_PULSE_MAX_US { RC_PULSE_MAX_US - RC_PULSE_MIN_US }
        else { v - RC_PULSE_MIN_US }
    }
}

/// Mixer output per motor.
#[derive(Clone, Copy)]
pub struct MixerOutput {
    /// Throttle per motor (0-1000).
    pub motors: [u16; MAX_MOTORS],
    /// Number of active motors.
    pub count: u8,
}

impl MixerOutput {
    pub const fn new() -> Self {
        MixerOutput { motors: [0; MAX_MOTORS], count: 0 }
    }
}

/// Frame type (multirotor geometry).
#[derive(Clone, Copy, PartialEq)]
pub enum FrameType {
    QuadX,
    QuadPlus,
    Hex,
    Octo,
    // D04: extended configurations
    /// Tricopter: 2 front motors + 1 rear with servo yaw.
    Tri,
    /// Y6: 6-motor Y layout (3 arms, co-axial pairs — top CW, bottom CCW).
    Y6,
    /// Hex-X (60° arm offsets, alternating CW/CCW).
    HexX,
    /// Co-axial quad (4 arms, 2 motors each: top CW, bottom CCW).
    Coax,
}

/// Flight mode.
#[derive(Clone, Copy, PartialEq)]
pub enum FlightMode {
    /// Motors off, cannot fly.
    Disarmed,
    /// RC direct to mixer (only rate PID).
    Manual,
    /// RC = target angle, angle + rate PID.
    Stabilize,
    /// **PLANNED**: Stabilize + altitude PID. The `FlightPid::update_alt`
    /// method exists but is NOT wired into `flight_control_task` yet —
    /// AltHold currently behaves identically to Stabilize. Wiring requires
    /// closed-loop SITL/HIL validation of the altitude controller (same
    /// discipline as the D04 position controller); deferred until a real
    /// SITL exercises it.
    AltHold,
    /// **PLANNED**: AltHold + position PID. Same status as `AltHold` —
    /// the position controller exists in `crate::position::PositionController`
    /// (D04, host-tested in flight-math-tests) but is NOT wired into
    /// `flight_control_task`; PosHold currently forwards whatever
    /// roll/pitch/throttle the server publishes via `CH_FLIGHT_TARGET`.
    /// Deferred until SITL/HIL.
    PosHold,
    /// Follow waypoints from server.
    Auto,
    /// Return To Launch (failsafe).
    RTL,
    /// Controlled descent.
    Land,
}

impl FlightMode {
    pub fn name(&self) -> &'static str {
        match self {
            FlightMode::Disarmed  => "Disarmed",
            FlightMode::Manual    => "Manual",
            FlightMode::Stabilize => "Stabilize",
            FlightMode::AltHold   => "AltHold",
            FlightMode::PosHold   => "PosHold",
            FlightMode::Auto      => "Auto",
            FlightMode::RTL       => "RTL",
            FlightMode::Land      => "Land",
        }
    }

    pub fn from_str(s: &[u8]) -> Option<FlightMode> {
        match s {
            b"disarmed"  | b"off"  => Some(FlightMode::Disarmed),
            b"manual"              => Some(FlightMode::Manual),
            b"stabilize" | b"stab" => Some(FlightMode::Stabilize),
            b"althold"   | b"alt"  => Some(FlightMode::AltHold),
            b"poshold"   | b"pos"  => Some(FlightMode::PosHold),
            b"auto"                => Some(FlightMode::Auto),
            b"rtl"                 => Some(FlightMode::RTL),
            b"land"                => Some(FlightMode::Land),
            _ => None,
        }
    }
}

// ── Global flight state ─────────────────────────────────────────────────────

static ARMED: AtomicBool = AtomicBool::new(false);
static FLIGHT_MODE: AtomicU8 = AtomicU8::new(0); // 0 = Disarmed

/// Whether the e-stop latch holds, queried before arming. `None` until
/// installed (`set_arm_gate`), in which case arming is unconditionally
/// permitted — the pre-2026-09-26 behaviour, for a build with no safety
/// layer wired at all.
///
/// This crate cannot depend on `domains/robot/behavior`/`domains/robot/safety-core`
/// directly: `safety-core` already depends on THIS crate
/// (`flight_ctrl.rs`), so the reverse edge would be a cycle. Same seam
/// shape as `domains/robot/robot::motor::MOTOR_GATE` — the consumer (this crate)
/// hosts the hook, and `domains/robot/safety-core::actuation::install()` (which
/// already depends on both `azos_flight` and `azos_behavior`)
/// installs it at boot.
static ARM_GATE: azos_sync::SpinLock<Option<fn() -> bool>> =
    azos_sync::SpinLock::new(None);

/// Install the e-stop query `flight_arm` consults. Called once at boot from
/// `domains/robot/safety-core::actuation::install`.
pub fn set_arm_gate(f: fn() -> bool) {
    *ARM_GATE.lock() = Some(f);
}

/// Whether the e-stop latch currently holds, per the installed gate.
fn estop_latched() -> bool {
    let g = *ARM_GATE.lock();
    match g { Some(f) => f(), None => false }
}

/// Check if motors are armed.
pub fn is_armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

/// Arm the motors (enable flight).
///
/// Refuses while the e-stop latch holds (owner/coordinator decision,
/// 2026-09-26, H22/U08-6) — before this, `flight_arm`/`esc_arm` (the shell
/// command wrapping it) re-energised the ESC while the latch held; the
/// ACTUATION half of that gap is closed independently in
/// `domains/robot/safety-core/src/flight_ctrl.rs` (throttle zeroed every tick while
/// latched, regardless of `ARMED`), and this closes the STATE half so
/// arming itself visibly fails rather than silently doing nothing useful.
pub fn flight_arm() -> bool {
    if estop_latched() {
        azos_drv_sys::kwarn!("[FLIGHT] ARM refused — e-stop latch holds");
        return false;
    }
    if flight_mode() != FlightMode::Disarmed {
        // Already in a flying mode — just set armed flag.
        ARMED.store(true, Ordering::Release);
        return true;
    }
    // Transition from Disarmed → Stabilize by default.
    ARMED.store(true, Ordering::Release);
    set_flight_mode(FlightMode::Stabilize);
    azos_drv_sys::kprintln!("[FLIGHT] ARMED — Stabilize mode");
    true
}

/// Disarm the motors (stop flight).
pub fn flight_disarm() {
    ARMED.store(false, Ordering::Release);
    set_flight_mode(FlightMode::Disarmed);
    azos_drv_sys::kprintln!("[FLIGHT] DISARMED");
}

/// Get current flight mode.
pub fn flight_mode() -> FlightMode {
    match FLIGHT_MODE.load(Ordering::Acquire) {
        1 => FlightMode::Manual,
        2 => FlightMode::Stabilize,
        3 => FlightMode::AltHold,
        4 => FlightMode::PosHold,
        5 => FlightMode::Auto,
        6 => FlightMode::RTL,
        7 => FlightMode::Land,
        _ => FlightMode::Disarmed,
    }
}

/// Set flight mode.
pub fn set_flight_mode(mode: FlightMode) {
    let val = match mode {
        FlightMode::Disarmed  => 0,
        FlightMode::Manual    => 1,
        FlightMode::Stabilize => 2,
        FlightMode::AltHold   => 3,
        FlightMode::PosHold   => 4,
        FlightMode::Auto      => 5,
        FlightMode::RTL       => 6,
        FlightMode::Land      => 7,
    };
    FLIGHT_MODE.store(val, Ordering::Release);
}

// ── Mixer ───────────────────────────────────────────────────────────────────

/// Compute per-motor throttle from control inputs.
///
/// - `frame`: multirotor geometry
/// - `throttle`: base throttle (0-1000)
/// - `roll`: roll correction (-1000..+1000)
/// - `pitch`: pitch correction (-1000..+1000)
/// - `yaw`: yaw correction (-1000..+1000)
///
/// Returns per-motor throttle values (0-1000).
pub fn mixer_compute(
    frame: FrameType,
    throttle: i32,
    roll: i32,
    pitch: i32,
    yaw: i32,
) -> MixerOutput {
    let mut out = MixerOutput::new();

    match frame {
        FrameType::QuadX => {
            out.count = 4;
            // QuadX layout (looking down, front is up):
            //   M1(CW)  M2(CCW)     front-right / front-left
            //   M3(CCW) M4(CW)      rear-left   / rear-right
            //
            // Motor 1 (front-right): +T -R +P -Y
            // Motor 2 (front-left):  +T +R +P +Y
            // Motor 3 (rear-left):   +T +R -P -Y
            // Motor 4 (rear-right):  +T -R -P +Y
            let m1 = throttle - roll + pitch - yaw;
            let m2 = throttle + roll + pitch + yaw;
            let m3 = throttle + roll - pitch - yaw;
            let m4 = throttle - roll - pitch + yaw;

            out.motors[0] = clamp_throttle(m1);
            out.motors[1] = clamp_throttle(m2);
            out.motors[2] = clamp_throttle(m3);
            out.motors[3] = clamp_throttle(m4);
        }
        FrameType::QuadPlus => {
            out.count = 4;
            // Quad+ layout:
            //       M1(CW)        front
            //   M2(CCW)  M3(CCW)  left / right
            //       M4(CW)        rear
            let m1 = throttle + pitch - yaw;
            let m2 = throttle + roll  + yaw;
            let m3 = throttle - roll  + yaw;
            let m4 = throttle - pitch - yaw;

            out.motors[0] = clamp_throttle(m1);
            out.motors[1] = clamp_throttle(m2);
            out.motors[2] = clamp_throttle(m3);
            out.motors[3] = clamp_throttle(m4);
        }
        FrameType::Hex => {
            out.count = 6;
            // Hex layout (simplified — equal 60° spacing):
            let m1 = throttle + pitch - yaw;
            let m2 = throttle + roll / 2 + pitch / 2 + yaw;
            let m3 = throttle + roll / 2 - pitch / 2 - yaw;
            let m4 = throttle - pitch + yaw;
            let m5 = throttle - roll / 2 - pitch / 2 - yaw;
            let m6 = throttle - roll / 2 + pitch / 2 + yaw;

            out.motors[0] = clamp_throttle(m1);
            out.motors[1] = clamp_throttle(m2);
            out.motors[2] = clamp_throttle(m3);
            out.motors[3] = clamp_throttle(m4);
            out.motors[4] = clamp_throttle(m5);
            out.motors[5] = clamp_throttle(m6);
        }
        FrameType::Octo => {
            out.count = 8;
            // Octo (simplified — 8 equal spacing):
            for i in 0..8 {
                out.motors[i] = clamp_throttle(throttle);
            }
            // Apply roll/pitch/yaw with 45° mixing ratios.
            // sin(0)=0, sin(45)=707/1000, sin(90)=1000/1000
            let s45: i32 = 707; // sin(45°) × 1000
            let corrections: [(i32, i32, i32); 8] = [
                ( 0,     1000,  -1), // front       : +P -Y
                ( s45,   s45,    1), // front-left  : +R +P +Y
                ( 1000,  0,     -1), // left        : +R -Y
                ( s45,  -s45,    1), // rear-left   : +R -P +Y
                ( 0,    -1000,  -1), // rear        : -P -Y
                (-s45,  -s45,    1), // rear-right  : -R -P +Y
                (-1000,  0,     -1), // right       : -R -Y
                (-s45,   s45,    1), // front-right : -R +P +Y
            ];
            for (i, &(cr, cp, cy)) in corrections.iter().enumerate() {
                let m = throttle + roll * cr / 1000 + pitch * cp / 1000 + yaw * cy;
                out.motors[i] = clamp_throttle(m);
            }
        }
        // D04: Tricopter (2 front + 1 rear; yaw via rear servo — approximated here
        // as yaw authority split across front motors with opposite signs).
        FrameType::Tri => {
            out.count = 3;
            // Motor 1 (front-right, CW): +T -R +P
            // Motor 2 (front-left, CCW): +T +R +P
            // Motor 3 (rear, CW/servo): +T -P ; yaw via tilt servo (not modeled)
            out.motors[0] = clamp_throttle(throttle - roll + pitch - yaw / 2);
            out.motors[1] = clamp_throttle(throttle + roll + pitch + yaw / 2);
            out.motors[2] = clamp_throttle(throttle - pitch);
        }

        // D04: Y6 — 3-arm Y, co-axial pairs.
        // Arms at 0°(front), 120°(rear-left), 240°(rear-right).
        // Top motors (CW): M1, M3, M5.  Bottom motors (CCW): M2, M4, M6.
        // sin(120°)=866/1000, cos(120°)=-500/1000.
        FrameType::Y6 => {
            out.count = 6;
            const S120: i32 = 866;
            const C120: i32 = -500;
            // Arm force contributions (×1000 normalized):
            // Front arm:     roll_factor=0,     pitch_factor=1000
            // Rear-left arm: roll_factor=-S120, pitch_factor=C120
            // Rear-right arm:roll_factor=+S120, pitch_factor=C120
            let t = throttle / 2; // split evenly across top+bottom per arm
            // Front top/bottom:
            out.motors[0] = clamp_throttle(t + pitch - yaw); // front top
            out.motors[1] = clamp_throttle(t + pitch + yaw); // front bottom
            // Rear-left top/bottom:
            out.motors[2] = clamp_throttle(t - roll * S120/1000 + pitch * C120/1000 - yaw);
            out.motors[3] = clamp_throttle(t - roll * S120/1000 + pitch * C120/1000 + yaw);
            // Rear-right top/bottom:
            out.motors[4] = clamp_throttle(t + roll * S120/1000 + pitch * C120/1000 - yaw);
            out.motors[5] = clamp_throttle(t + roll * S120/1000 + pitch * C120/1000 + yaw);
        }

        // D04: HexX — 6 motors at 30/90/150/210/270/330° (hex-X layout).
        // Motors alternate CW/CCW starting with CW at 30°.
        // sin/cos values for 30° multiples (×1000):
        // 30°: s=500 c=866; 90°: s=1000 c=0; 150°: s=500 c=-866
        FrameType::HexX => {
            out.count = 6;
            // Arm angles (cdeg) for hex-X: 30, 90, 150, 210, 270, 330
            // Roll contribution: sin(angle), Pitch: cos(angle), Yaw: alternating ±1
            const ARMS: [(i32, i32, i32); 6] = [
                ( 500,  866, -1), //  30°: right-front   CW
                ( 1000, 0,    1), //  90°: right          CCW
                ( 500, -866, -1), // 150°: right-rear    CW
                (-500, -866,  1), // 210°: left-rear     CCW
                (-1000, 0,   -1), // 270°: left           CW
                (-500,  866,  1), // 330°: left-front    CCW
            ];
            for (i, &(sr, cp, cy)) in ARMS.iter().enumerate() {
                let m = throttle
                    + roll  * sr / 1000
                    + pitch * cp / 1000
                    + yaw   * cy;
                out.motors[i] = clamp_throttle(m);
            }
        }

        // D04: Co-axial quad (X layout, each arm has top CW + bottom CCW).
        // 4 arms (45°/135°/225°/315°), 2 motors per arm = 8 motors total.
        FrameType::Coax => {
            out.count = 8;
            let s45: i32 = 707;
            // Arms: FR, FL, RL, RR
            let arms: [(i32, i32); 4] = [
                (-s45,  s45), // front-right: -R +P
                ( s45,  s45), // front-left:  +R +P
                ( s45, -s45), // rear-left:   +R -P
                (-s45, -s45), // rear-right:  -R -P
            ];
            for (i, &(ar, ap)) in arms.iter().enumerate() {
                let t = throttle / 2;
                let m_top = t + roll * ar / 1000 + pitch * ap / 1000 - yaw;
                let m_bot = t + roll * ar / 1000 + pitch * ap / 1000 + yaw;
                out.motors[i * 2]     = clamp_throttle(m_top);
                out.motors[i * 2 + 1] = clamp_throttle(m_bot);
            }
        }
    }

    out
}

fn clamp_throttle(v: i32) -> u16 {
    // When armed, floor at THROTTLE_IDLE so an aggressive mix correction can
    // never stop a prop mid-flight (0 µs = motor off, risks ESC desync).
    // Disarmed floors at 0 (motors off).
    let floor = if is_armed() { THROTTLE_IDLE as i32 } else { 0 };
    if v <= floor { floor as u16 }
    else if v >= THROTTLE_MAX as i32 { THROTTLE_MAX }
    else { v as u16 }
}

// ── PID controller ──────────────────────────────────────────────────────────
//
// Extracted to its own file 2026-09-26 (`pid.rs`) so it can be `#[path]`-
// pulled into `tests/host/flight-tests` without the rest of this file's AHRS/
// GPS/driver dependencies — see that module's doc for why the file as a
// whole cannot be.
mod pid;
pub use pid::Pid;

// ── Cascaded flight PID ─────────────────────────────────────────────────────

/// Cascaded PID for flight control: outer loop (angle) → inner loop (rate).
pub struct FlightPid {
    /// Angle PID: roll, pitch, yaw (outer loop, ~250 Hz).
    pub angle_pid: [Pid; 3],
    /// Rate PID: roll, pitch, yaw (inner loop, ~1000 Hz).
    pub rate_pid: [Pid; 3],
    /// Altitude hold PID (~50 Hz).
    pub alt_pid: Pid,
}

impl FlightPid {
    /// Create with default tuning values.
    pub const fn new() -> Self {
        // Angle PID: moderate gains, output is target rate in mdps.
        let angle = Pid::new(4500, 500, 0, -30000, 30000); // ±30000 mdps max rate
        // Rate PID: faster response, output is mixer correction (0-500).
        let rate = Pid::new(1200, 300, 100, -500, 500);
        // Alt PID: slow, output is throttle offset.
        let alt = Pid::new(2000, 200, 500, -300, 300);

        FlightPid {
            angle_pid: [angle, angle, angle],
            rate_pid: [rate, rate, rate],
            alt_pid: alt,
        }
    }

    /// Run cascaded PID for one axis.
    ///
    /// - `angle_error`: target_angle - measured_angle (centi-degrees)
    /// - `gyro_rate`: measured angular rate (milli-degrees/sec)
    /// - `axis`: 0=roll, 1=pitch, 2=yaw
    /// - `dt_us`: time delta in microseconds
    ///
    /// Returns mixer correction value (-500..+500).
    pub fn update_axis(&mut self, angle_error: i32, gyro_rate: i32, axis: usize, dt_us: u32) -> i32 {
        if axis >= 3 { return 0; }

        // Outer loop: angle error → target rate.
        let target_rate = self.angle_pid[axis].update(angle_error, dt_us);

        // Inner loop: rate error → control output. Subtract in i64 and
        // saturate: a toxic/sentinel gyro sample (e.g. i32::MIN) must not
        // overflow this subtraction and abort the flight loop.
        let rate_error =
            (target_rate as i64 - gyro_rate as i64).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        self.rate_pid[axis].update(rate_error, dt_us)
    }

    /// Run altitude hold PID.
    ///
    /// - `alt_error`: target_alt - measured_alt (millimetres)
    /// - `dt_us`: time delta
    ///
    /// Returns throttle offset (-300..+300).
    pub fn update_alt(&mut self, alt_error: i32, dt_us: u32) -> i32 {
        self.alt_pid.update(alt_error, dt_us)
    }

    /// Reset all PID state.
    pub fn reset(&mut self) {
        for pid in &mut self.angle_pid { pid.reset(); }
        for pid in &mut self.rate_pid { pid.reset(); }
        self.alt_pid.reset();
    }
}

pub mod failsafe;
pub use failsafe::{check_failsafe, rc_frame_is_fresh_input, FailsafeAction};

// ── RC mapping ──────────────────────────────────────────────────────────────

/// Standard RC channel mapping.
pub const RC_CH_ROLL:     usize = 0;
pub const RC_CH_PITCH:    usize = 1;
pub const RC_CH_THROTTLE: usize = 2;
pub const RC_CH_YAW:      usize = 3;
pub const RC_CH_MODE:     usize = 4;
pub const RC_CH_AUX1:     usize = 5;

/// Convert RC input to flight target (Stabilize mode).
///
/// Roll/pitch: map ±500us to ±4500 cdeg (±45°).
/// Yaw: map ±500us to ±30000 mdps (±30°/s).
/// Throttle: map 0-1000 directly.
pub fn rc_to_target(rc: &RcInput) -> FlightTarget {
    FlightTarget {
        roll_cdeg:     rc.channel_signed(RC_CH_ROLL) * 9,     // ±500 → ±4500 cdeg
        pitch_cdeg:    rc.channel_signed(RC_CH_PITCH) * 9,    // ±500 → ±4500 cdeg
        yaw_rate_mdps: rc.channel_signed(RC_CH_YAW) * 60,     // ±500 → ±30000 mdps
        throttle:      rc.channel_unsigned(RC_CH_THROTTLE),
        alt_mm:        0,
    }
}

// ── Info ─────────────────────────────────────────────────────────────────────

/// Print flight controller status.
pub fn flight_info() {
    let mode = flight_mode();
    let armed = is_armed();
    azos_drv_sys::kconsoleln!("[FLIGHT] Mode: {} | Armed: {}", mode.name(), armed);

    let target_snap = CH_FLIGHT_TARGET.read();
    if target_snap.seq > 0 {
        let t = target_snap.val;
        azos_drv_sys::kconsoleln!("[FLIGHT] Target: roll={} pitch={} yaw_rate={} thr={}",
            t.roll_cdeg, t.pitch_cdeg, t.yaw_rate_mdps, t.throttle);
    }

    let rc_snap = CH_RC_INPUT.read();
    if rc_snap.seq > 0 {
        let rc = rc_snap.val;
        azos_drv_sys::kconsoleln!("[FLIGHT] RC: ch1={} ch2={} ch3={} ch4={} rssi={} fs={}",
            rc.channels[0], rc.channels[1], rc.channels[2], rc.channels[3],
            rc.rssi, rc.failsafe);
    } else {
        azos_drv_sys::kconsoleln!("[FLIGHT] RC: no data");
    }
}
