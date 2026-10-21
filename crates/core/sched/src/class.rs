// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The five budget class names a signed topology (`SCHED.TOML`) may use, the
//! interactive session class, and their wire bytes. Dispatch is the class model in `sc.rs`/`classes.rs`.

/// The AZOS scheduling classes: the five budget classes and the interactive one.
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
    /// The interactive session (the shell's row): scheduled fair-share like
    /// [`BestEffort`](Self::BestEffort) but run at the latency QoS tier
    /// ([`qos_hint`](Self::qos_hint)), and the class that carries
    /// `principal = "user"`. Its topology name is `session`. Appended after
    /// `Idle` so no wire byte moves; `ALL` orders it by urgency.
    Interactive = 5,
}

impl SchedClass {
    /// All classes in priority order (highest urgency first).
    pub const ALL: [Self; 6] = [
        Self::SafetyCritical,
        Self::HardRT,
        Self::SoftRT,
        Self::Interactive,
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
            5 => Some(Self::Interactive),
            _ => None,
        }
    }

    /// The class a signed topology names, by its name
    /// (`[class.<name>]` in `SCHED.TOML`).
    ///
    /// `None` is a class this build does not schedule. The kernel refuses to
    /// apply such a topology row (the task keeps the priority it was created
    /// with) and records the refusal; it never guesses the nearest class.
    ///
    /// `session` is the class the topology gives an interactive shell's row, so
    /// the kernel can label the task as a user principal (`principal =
    /// "user"`, a property of a class). It is [`Interactive`](Self::Interactive):
    /// fair-share like `best_effort`, at the latency QoS tier, and reported as
    /// `interactive` ([`name`](Self::name)), never as `best_effort`.
    pub fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"safety_critical" => Some(Self::SafetyCritical),
            b"hard_rt" => Some(Self::HardRT),
            b"soft_rt" => Some(Self::SoftRT),
            b"best_effort" => Some(Self::BestEffort),
            b"session" => Some(Self::Interactive),
            b"idle" => Some(Self::Idle),
            _ => None,
        }
    }

    /// The name the class is reported by (log lines, `task_class_raw`): the
    /// Name [`from_name`](Self::from_name) accepts, except that the
    /// interactive class is reported as `interactive` and declared as
    /// `session`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SafetyCritical => "safety_critical",
            Self::HardRT => "hard_rt",
            Self::SoftRT => "soft_rt",
            Self::BestEffort => "best_effort",
            Self::Idle => "idle",
            Self::Interactive => "interactive",
        }
    }

    /// The QoS hint a task of this class starts with (`SYS_SCHEDCTL`'s
    /// `HINT_QOS` values): the latency tier for the interactive class, the
    /// default for every other. Applied where the row's class is applied
    /// (`classes::on_row_class`); the task may say otherwise afterwards.
    pub const fn qos_hint(self) -> u32 {
        match self {
            Self::Interactive => azos_abi::syscall_nr::QOS_LATENCY,
            _ => azos_abi::syscall_nr::QOS_DEFAULT,
        }
    }
}
