// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS scheduler classes — RFC-0004.
//!
//! Five classes, each with its own scheduling policy and budget. The
//! Adaptive Partitioning combinator (`partitions.rs`) hands the CPU to
//! the class whose budget is the most under-served at any tick.
//!
//! | Class            | Default policy | Budget (RFC-0004 default) |
//! |------------------|----------------|----------------------------|
//! | SafetyCritical   | EDF + CBS      | 20 %                       |
//! | HardRT           | EDF + CBS      | 30 %                       |
//! | SoftRT           | RR             | 25 %                       |
//! | BestEffort       | CFS            | 20 %                       |
//! | Idle             | Sporadic       |  5 %                       |
//!
//! Bookkeeping is integer-only (no floats, no allocator) so this code
//! is safe to call from the timer ISR.

use core::sync::atomic::{AtomicU32, Ordering};

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

    /// Number of distinct classes.
    pub const COUNT: usize = 5;

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

    /// Numeric urgency rank — `0` is most urgent. Mirrors the
    /// discriminant.
    #[inline]
    pub const fn urgency(self) -> u8 {
        self as u8
    }

    /// Slot index for use in fixed-size per-class arrays.
    #[inline]
    pub const fn slot(self) -> usize {
        self as usize
    }

    /// `true` for classes whose deadline budget is hard real-time.
    /// These classes drive admission control (Liu-Layland).
    #[inline]
    pub const fn is_hard_rt(self) -> bool {
        matches!(self, Self::SafetyCritical | Self::HardRT)
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

/// Default scheduler-class budgets matching RFC-0004's reference
/// configuration. Sums to exactly 100 %.
pub const DEFAULT_BUDGETS_PCT: [u8; SchedClass::COUNT] = [20, 30, 25, 20, 5];

/// Per-class CPU budget bookkeeping for one Adaptive Partitioning
/// window.
///
/// Stored in `AtomicU32` so the timer ISR can decrement the consumed
/// counter without taking a lock.
pub struct ClassBudget {
    /// Configured minimum percentage of CPU per partition window.
    pub min_pct: u8,
    /// Configured maximum percentage (cap; 100 = unbounded).
    pub max_pct: u8,
    /// CPU time consumed in the current window, in microseconds.
    pub consumed_us: AtomicU32,
}

impl ClassBudget {
    /// Construct a fresh budget bookkeeper.
    pub const fn new(min_pct: u8, max_pct: u8) -> Self {
        Self {
            min_pct,
            max_pct,
            consumed_us: AtomicU32::new(0),
        }
    }

    /// Default-budget shorthand.
    pub const fn default_for(class: SchedClass) -> Self {
        let min = DEFAULT_BUDGETS_PCT[class.slot()];
        Self::new(min, 100)
    }

    /// Reset the consumed counter to zero. Called at the start of each
    /// window.
    #[inline]
    pub fn reset_window(&self) {
        self.consumed_us.store(0, Ordering::Relaxed);
    }

    /// Account for `dt_us` microseconds of elapsed runtime.
    #[inline]
    pub fn consume(&self, dt_us: u32) {
        self.consumed_us.fetch_add(dt_us, Ordering::Relaxed);
    }

    /// CPU consumed so far in the current window, microseconds.
    #[inline]
    pub fn consumed_us(&self) -> u32 {
        self.consumed_us.load(Ordering::Relaxed)
    }

    /// Compute the budget cap for this class given the partition
    /// window length, as a microsecond quota.
    #[inline]
    pub fn quota_us(&self, window_us: u32) -> u32 {
        ((window_us as u64 * self.max_pct as u64) / 100) as u32
    }

    /// Compute the guaranteed minimum for this class given the window.
    #[inline]
    pub fn min_quota_us(&self, window_us: u32) -> u32 {
        ((window_us as u64 * self.min_pct as u64) / 100) as u32
    }

    /// True iff this class has consumed more than its `max_pct` quota
    /// in the current window — should yield until the next window.
    #[inline]
    pub fn over_quota(&self, window_us: u32) -> bool {
        self.consumed_us() >= self.quota_us(window_us)
    }

    /// True iff this class has yet to receive its guaranteed minimum
    /// in the current window. The APS combinator prefers under-served
    /// classes.
    #[inline]
    pub fn under_min(&self, window_us: u32) -> bool {
        self.consumed_us() < self.min_quota_us(window_us)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests live in the host crate `tests/host/sched-policy-tests` because this
// crate is no_std and bound to RV64. The tests there exercise the full
// public API of class.rs including atomic semantics.
// ──────────────────────────────────────────────────────────────────────────
