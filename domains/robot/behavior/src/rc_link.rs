// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The RC receiver's say in the safety path (wave 15, owner decision: wire the
//! RC input; Kconfig `RC_INPUT`).
//!
//! Pure policy: it is handed what `azos_robot_drivers::rc` reports (the
//! channels, the receiver's failsafe bit, when the last frame arrived, whether
//! any frame ever did) and answers with one [`RcVerdict`]. The kernel's
//! behavior loop (`kernel/src/tasks/rc_safety.rs`) acts on it:
//!
//! * [`RcVerdict::LinkLoss`] — latch the e-stop (unless Kconfig
//!   `RC_FAILSAFE_ESTOP` is n, the drone default, whose flight controller
//!   returns to launch instead) and write a durable record.
//! * [`RcVerdict::Kill`] — latch the e-stop on every robot type.
//! * [`RcVerdict::Manual`] — the sticks replace the brain's command for that
//!   tick, so they reach the motors only through L0 and the motor envelope.
//!
//! **Nothing acts before the first frame.** A link that never existed cannot
//! be lost: a robot without a transmitter (or whose receiver is still bound
//! to nothing) is not held stopped. The receiver's driver counts frames that
//! arrived through its byte source, never the QEMU `Simulated` stand-in, so a
//! plain QEMU boot sees [`RcVerdict::NoLink`] forever.
//!
//! No clock, no globals, no I/O: the host suite (`tests/host/behavior-tests`)
//! pulls this file in with `#[path]` and drives it directly.

/// Pulse width of a centred stick, in microseconds.
pub const RC_CENTER_US: i32 = 1500;
/// Pulse width of a stick at either end, as a deflection from centre.
pub const RC_HALF_TRAVEL_US: i32 = 500;

/// The receiver policy, from Kconfig (see `config/Kconfig.robot`, "RC input
/// and geofence"). Channels are 1-based as on a transmitter; 0 means "none".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcPolicy {
    /// No fresh frame for this many timer ticks is link loss.
    pub link_timeout_ticks: u64,
    /// Ticks per millisecond, for the age reported in a record.
    pub ticks_per_ms: u64,
    pub mode_channel: u8,
    pub kill_channel: u8,
    pub switch_high_us: u16,
    pub drive_channel: u8,
    pub steer_channel: u8,
    pub deadband_us: u16,
    pub full_scale_pct: i32,
}

impl RcPolicy {
    /// The policy the .config selected, on a board whose timer runs at
    /// `timer_freq` Hz.
    pub const fn from_limits(timer_freq: u64) -> Self {
        let ticks_per_ms = if timer_freq / 1000 == 0 { 1 } else { timer_freq / 1000 };
        RcPolicy {
            link_timeout_ticks: azos_limits::RC_LINK_TIMEOUT_MS * ticks_per_ms,
            ticks_per_ms,
            mode_channel: azos_limits::RC_MODE_CHANNEL as u8,
            kill_channel: azos_limits::RC_KILL_CHANNEL as u8,
            switch_high_us: azos_limits::RC_SWITCH_HIGH_US as u16,
            drive_channel: azos_limits::RC_DRIVE_CHANNEL as u8,
            steer_channel: azos_limits::RC_STEER_CHANNEL as u8,
            deadband_us: azos_limits::RC_STICK_DEADBAND_US as u16,
            full_scale_pct: azos_limits::RC_STICK_FULL_SCALE_PCT as i32,
        }
    }
}

/// What the receiver says this tick, most urgent first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcVerdict {
    /// No frame has arrived this boot: the receiver has no say.
    NoLink,
    /// The link is gone: the receiver raised its failsafe bit
    /// (`age_ms == None`), or no fresh frame for the timeout (`Some(age)`).
    LinkLoss { age_ms: Option<u32> },
    /// The kill switch is on; `pulse_us` is its channel's pulse width.
    Kill { pulse_us: u16 },
    /// Link fresh, mode switch off: the brain drives.
    Passive,
    /// Link fresh, mode switch on: the sticks ask for `(left, right)` percent.
    Manual { left: i32, right: i32 },
}

/// The pulse on 1-based channel `ch`, or `None` for channel 0 ("none") or
/// one beyond the frame.
fn channel(channels: &[u16; 16], ch: u8) -> Option<u16> {
    if ch == 0 { return None; }
    channels.get(ch as usize - 1).copied()
}

/// A stick's pulse as a percentage of `full_scale` (signed, deadband applied).
pub fn stick_pct(pulse_us: u16, deadband_us: u16, full_scale: i32) -> i32 {
    let d = pulse_us as i32 - RC_CENTER_US;
    if d.abs() <= deadband_us as i32 { return 0; }
    (d * full_scale / RC_HALF_TRAVEL_US).clamp(-full_scale, full_scale)
}

/// Differential mixing: left = drive + steer, right = drive - steer, each
/// clamped to `full_scale`.
pub fn mix(drive: i32, steer: i32, full_scale: i32) -> (i32, i32) {
    ((drive + steer).clamp(-full_scale, full_scale),
     (drive - steer).clamp(-full_scale, full_scale))
}

/// Decide what the receiver means this tick.
///
/// `frames_seen`: a frame has arrived through the byte source this boot.
/// `read`: `rc_read()` (`None` while the driver is not ready). `last_frame`
/// and `now` are timer ticks. Order: no link, link loss, kill switch, mode.
pub fn rc_evaluate(p: &RcPolicy, frames_seen: bool, read: Option<([u16; 16], bool)>,
                   last_frame: u64, now: u64) -> RcVerdict {
    if !frames_seen { return RcVerdict::NoLink; }
    let Some((channels, failsafe)) = read else {
        // A link existed and the driver stopped handing out data.
        return RcVerdict::LinkLoss { age_ms: None };
    };
    if failsafe { return RcVerdict::LinkLoss { age_ms: None }; }
    let age = now.saturating_sub(last_frame);
    if age > p.link_timeout_ticks {
        let ms = age / p.ticks_per_ms;
        return RcVerdict::LinkLoss { age_ms: Some(ms.min(u32::MAX as u64) as u32) };
    }
    if let Some(k) = channel(&channels, p.kill_channel) {
        if k > p.switch_high_us { return RcVerdict::Kill { pulse_us: k }; }
    }
    match channel(&channels, p.mode_channel) {
        Some(m) if m > p.switch_high_us => {
            let drive = channel(&channels, p.drive_channel)
                .map_or(0, |v| stick_pct(v, p.deadband_us, p.full_scale_pct));
            let steer = channel(&channels, p.steer_channel)
                .map_or(0, |v| stick_pct(v, p.deadband_us, p.full_scale_pct));
            let (left, right) = mix(drive, steer, p.full_scale_pct);
            RcVerdict::Manual { left, right }
        }
        _ => RcVerdict::Passive,
    }
}

/// The record `detail` of a [`RcVerdict::LinkLoss`]: 0 for the receiver's
/// failsafe bit, else the frame age in ms (at least 1).
pub const fn link_loss_detail(age_ms: Option<u32>) -> u32 {
    match age_ms {
        None => 0,
        Some(0) => 1,
        Some(ms) => ms,
    }
}
