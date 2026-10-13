// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The five RFC-0004 class names a signed topology (`SCHED.TOML`) may use,
//! and their wire bytes. Dispatch is the class model in `sc.rs`/`classes.rs`.

/// The five AZOS scheduling classes.
///
/// Wire-format `repr(u8)` so this can be packed into per-task control
/// blocks and topology files.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SchedClass {
    /// Hard-deadline safety code (geofence check, ESTOP, watchdog).
    SafetyCritical = 0,
    /// Hard real-time tasks (motor PID, IMU sample).
    HardRT = 1,
    /// Soft real-time (telemetry, network stack).
    SoftRT = 2,
    /// Best-effort fair-share (AI inference, logging).
    BestEffort = 3,
    /// Idle / opportunistic.
    Idle = 4,
}

impl SchedClass {
    /// All classes in priority order (highest urgency first).
    pub const ALL: [Self; 5] = [
        Self::SafetyCritical,
        Self::HardRT,
        Self::SoftRT,
        Self::BestEffort,
        Self::Idle,
    ];

    /// Try to construct from a raw `u8`. Returns `None` for unknown
    /// discriminants.
    #[inline]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::SafetyCritical),
            1 => Some(Self::HardRT),
            2 => Some(Self::SoftRT),
            3 => Some(Self::BestEffort),
            4 => Some(Self::Idle),
            _ => None,
        }
    }

    /// The class a signed topology names, by its RFC-0004 name
    /// (`[class.<name>]` in `SCHED.TOML`).
    ///
    /// `None` is a class this build does not schedule. The kernel refuses to
    /// apply such a topology row (the task keeps the priority it was created
    /// with) and records the refusal; it never guesses the nearest class.
    pub fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"safety_critical" => Some(Self::SafetyCritical),
            b"hard_rt" => Some(Self::HardRT),
            b"soft_rt" => Some(Self::SoftRT),
            b"best_effort" => Some(Self::BestEffort),
            b"idle" => Some(Self::Idle),
            _ => None,
        }
    }

    /// The RFC-0004 name [`from_name`](Self::from_name) accepts.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SafetyCritical => "safety_critical",
            Self::HardRT => "hard_rt",
            Self::SoftRT => "soft_rt",
            Self::BestEffort => "best_effort",
            Self::Idle => "idle",
        }
    }
}
