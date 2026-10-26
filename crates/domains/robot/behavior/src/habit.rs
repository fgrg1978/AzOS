// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Habit Formation — L1→L0 promotion (R04).
///
/// Repeatedly successful skill sequences get "compiled" into a fast-path
/// L0-level reflex that bypasses the deliberative planner.
///
/// ## Concept
/// Inspired by the neuroscience model of skill automatization:
/// - **L2/L1 (deliberative/reactive)**: first execution — full planner path,
///   VLM perception, context lookup.
/// - **L0 (reflex/habit)**: after `HABIT_PROMOTE_THRESHOLD` successes — the
///   kernel remembers the skill sequence and its triggering condition, and
///   fires it directly from the arbiter without going through the planner.
///
/// ## Data model
/// A `Habit` stores:
/// - `trigger`: a compact sensor condition (obstacle distance, battery level,
///   attitude thresholds) that activates the habit.
/// - `sequence`: a fixed sequence of up to `HABIT_MAX_SEQ` skill IDs.
/// - `success_count`: number of times this sequence has been executed
///   successfully since the habit was recorded.
/// - `promote_count`: number of times it has been promoted to L0.
///
/// ## Lifecycle
/// 1. `habit_record(trigger, sequence)` — called by L2 when a skill plan
///    executes successfully.
/// 2. `habit_tick()` — increments success counts on active habits.
/// 3. `habit_promoted()` — returns habits whose success_count ≥ threshold.
/// 4. The arbiter checks `habit_match(sensor_state)` before calling the
///    deliberative planner; on match, it returns the habit's motor output
///    directly (effectively L0 speed, L1 capability).

use azos_sync::SpinLock;
use crate::skill_profile::SkillId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of successful executions before a habit is promoted to L0.
pub const HABIT_PROMOTE_THRESHOLD: u32 = 10;

/// Maximum number of habits stored simultaneously.
pub const MAX_HABITS: usize = 16;

/// Maximum skill IDs per habit sequence.
pub const HABIT_MAX_SEQ: usize = 8;

// ---------------------------------------------------------------------------
// Trigger condition
// ---------------------------------------------------------------------------

/// A compact sensor condition that activates a habit.
///
/// The trigger fires when ALL specified thresholds are satisfied.
/// Fields set to sentinel values (u16::MAX, i16::MIN) are ignored.
#[derive(Clone, Copy)]
pub struct HabitTrigger {
    /// Minimum range reading (mm) to front sensor that fires this habit.
    /// e.g., 0 = always, 300 = fire when something is < 300mm in front.
    pub obstacle_lt_mm: u16,   // trigger if front range < this (u16::MAX = ignore)
    /// Minimum battery % required (0 = no requirement).
    pub min_battery_pct: u8,
    /// Maximum absolute roll (millidegrees) before triggering.
    /// u32::MAX = ignore.
    pub max_roll_abs_mdeg: u32,
    /// Maximum absolute pitch.
    pub max_pitch_abs_mdeg: u32,
}

impl HabitTrigger {
    /// A trigger that never fires spontaneously (all conditions disabled).
    pub const fn never() -> Self {
        HabitTrigger {
            obstacle_lt_mm: u16::MAX,
            min_battery_pct: 0,
            max_roll_abs_mdeg: u32::MAX,
            max_pitch_abs_mdeg: u32::MAX,
        }
    }

    /// Check if this trigger matches the given sensor state.
    pub fn matches(&self, front_mm: u16, battery_pct: u8, roll_mdeg: i32, pitch_mdeg: i32) -> bool {
        if self.obstacle_lt_mm != u16::MAX && front_mm >= self.obstacle_lt_mm {
            return false;
        }
        if battery_pct < self.min_battery_pct {
            return false;
        }
        if self.max_roll_abs_mdeg != u32::MAX && (roll_mdeg.unsigned_abs()) > self.max_roll_abs_mdeg {
            return false;
        }
        if self.max_pitch_abs_mdeg != u32::MAX && (pitch_mdeg.unsigned_abs()) > self.max_pitch_abs_mdeg {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Habit entry
// ---------------------------------------------------------------------------

/// A recorded habit — a trigger + skill sequence that may be promoted to L0.
pub struct Habit {
    /// Condition that activates this habit.
    pub trigger: HabitTrigger,
    /// Skill sequence to execute when triggered.
    pub sequence: [SkillId; HABIT_MAX_SEQ],
    /// Number of skills in the sequence.
    pub seq_len: u8,
    /// Number of successful executions recorded.
    pub success_count: u32,
    /// Number of times promoted to L0 level.
    pub promote_count: u32,
    /// Whether this slot is occupied.
    pub active: bool,
    /// Whether this habit has been promoted to L0.
    pub promoted: bool,
}

impl Habit {
    const fn empty() -> Self {
        Habit {
            trigger: HabitTrigger::never(),
            sequence: [SkillId::Idle; HABIT_MAX_SEQ],
            seq_len: 0,
            success_count: 0,
            promote_count: 0,
            active: false,
            promoted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

struct HabitTable {
    habits: [Habit; MAX_HABITS],
}

impl HabitTable {
    const fn new() -> Self {
        const E: Habit = Habit::empty();
        HabitTable { habits: [E; MAX_HABITS] }
    }
}

static HABITS: SpinLock<HabitTable> = SpinLock::new(HabitTable::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Record a successful skill sequence execution.
///
/// If a habit with the same trigger already exists, increment its success
/// count.  Otherwise, if there is a free slot, create a new habit entry.
///
/// Returns the habit index on success, or `None` if the table is full.
pub fn habit_record(trigger: HabitTrigger, skills: &[SkillId]) -> Option<usize> {
    let mut table = HABITS.lock();
    let seq_len = skills.len().min(HABIT_MAX_SEQ) as u8;

    // Look for matching existing habit (same sequence)
    for (i, h) in table.habits.iter_mut().enumerate() {
        if !h.active { continue; }
        if h.seq_len != seq_len { continue; }
        let mut same = true;
        for j in 0..seq_len as usize {
            if h.sequence[j] != skills[j] { same = false; break; }
        }
        if same {
            h.success_count += 1;
            if h.success_count >= HABIT_PROMOTE_THRESHOLD && !h.promoted {
                h.promoted = true;
                h.promote_count += 1;
            }
            return Some(i);
        }
    }

    // New habit
    for (i, h) in table.habits.iter_mut().enumerate() {
        if !h.active {
            h.trigger = trigger;
            h.seq_len = seq_len;
            for j in 0..seq_len as usize {
                h.sequence[j] = skills[j];
            }
            h.success_count = 1;
            h.promote_count = 0;
            h.promoted = false;
            h.active = true;
            return Some(i);
        }
    }
    None
}

/// Check if any promoted habit matches the current sensor state.
///
/// Returns the first matching habit's skill sequence, or `None`.
/// Called from the arbiter at L0 priority before the deliberative planner.
pub fn habit_match(front_mm: u16, battery_pct: u8, roll_mdeg: i32, pitch_mdeg: i32)
    -> Option<([SkillId; HABIT_MAX_SEQ], u8)>
{
    let table = HABITS.lock();
    for h in table.habits.iter() {
        if !h.active || !h.promoted { continue; }
        if h.trigger.matches(front_mm, battery_pct, roll_mdeg, pitch_mdeg) {
            return Some((h.sequence, h.seq_len));
        }
    }
    None
}

/// Evict habits that have not fired in a long time (called periodically).
///
/// `min_successes`: habits with fewer successes than this threshold are removed.
/// This prevents stale habits from interfering with new behavior.
pub fn habit_prune(min_successes: u32) {
    let mut table = HABITS.lock();
    for h in table.habits.iter_mut() {
        if h.active && h.success_count < min_successes {
            *h = Habit::empty();
        }
    }
}

/// Count active / promoted habits.
pub fn habit_stats() -> (usize, usize) {
    let table = HABITS.lock();
    let active = table.habits.iter().filter(|h| h.active).count();
    let promoted = table.habits.iter().filter(|h| h.active && h.promoted).count();
    (active, promoted)
}
