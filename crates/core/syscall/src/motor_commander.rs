// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which ring-3 task last left each wheel turning, so its death can stop the
//! wheel (wave 15, COHERENCE-AUDIT; owner decision: a dead commander's
//! motors go to a SAFE STOP, recorded with its reason).
//!
//! The typed motor calls (`SYS_MOTOR_SPEED_TYPED` 560,
//! `SYS_MOTOR_DIRECTION_TYPED` 576, `SYS_MOTOR_MOVE_TYPED` 584) write a duty
//! that stays on the channel until something writes another. `rt_motor_task`
//! rewrites both wheels every control tick only while its command channel is
//! live and its watchdog has not fired; in SAFE STOP it writes once and then
//! leaves the wheels alone, so a ring-3 write after that persists. A task that
//! dies after commanding a wheel at speed (a fault, a kill, a crash of
//! `reflex` mid-backup) left it turning with nobody in charge.
//!
//! Each successful write is noted against its wheel: a non-zero applied duty
//! names the caller, a zero one clears the wheel (it is stopped, by whoever).
//! At exit, [`release`] takes every wheel the dying task still names; the
//! kernel's exit hook stops those wheels (duty 0, coast) and records the
//! event (`SAFETY_ESTOP`, action `ESTOP_ACTION_COMMANDER_LOST`, which does
//! NOT latch: the machine is stopped, not locked, and a restarted commander
//! drives again — the same contract as rt_motor's own SAFE STOP).
//!
//! Lock-free: one `AtomicU32` per wheel, compare-and-swap on release, so a
//! wheel another task has taken over meanwhile is never stopped on the dead
//! task's account.

use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(feature = "domain-robot"))]
use crate::no_robot::robot as azos_robot;

/// Per wheel: the TID that last left it at a non-zero duty, 0 for none.
pub struct Commanders<const N: usize> {
    by_wheel: [AtomicU32; N],
}

impl<const N: usize> Commanders<N> {
    pub const fn new() -> Self {
        Self { by_wheel: [const { AtomicU32::new(0) }; N] }
    }

    /// A write to `wheel` by `tid` left `applied` on the channel (`None`:
    /// the write was refused and changed nothing).
    pub fn note(&self, wheel: u32, tid: u32, applied: Option<u32>) {
        let Some(w) = self.by_wheel.get(wheel as usize) else { return };
        match applied {
            Some(0) => w.store(0, Ordering::Release),
            Some(_) => w.store(tid, Ordering::Release),
            None => {}
        }
    }

    /// `tid` is exiting: take every wheel it still commands. Bit `i` of the
    /// result is wheel `i`.
    pub fn release(&self, tid: u32) -> u32 {
        if tid == 0 {
            return 0;
        }
        let mut mask = 0u32;
        for (i, w) in self.by_wheel.iter().enumerate().take(32) {
            // A plain load first: on almost every exit no wheel names the
            // task, and the exit then costs one load per wheel.
            if w.load(Ordering::Relaxed) == tid
                && w.compare_exchange(tid, 0, Ordering::AcqRel, Ordering::Acquire).is_ok()
            {
                mask |= 1 << i;
            }
        }
        mask
    }

    /// The task commanding `wheel`, 0 for none.
    pub fn commander(&self, wheel: u32) -> u32 {
        self.by_wheel.get(wheel as usize).map_or(0, |w| w.load(Ordering::Acquire))
    }
}

static COMMANDERS: Commanders<{ azos_robot::MAX_MOTORS }> = Commanders::new();

/// The current task's write to `wheel` left `applied`: note it. Called by the
/// typed motor handlers after `motor_set_reporting`.
#[inline]
pub fn note_current(wheel: u32, applied: Option<u32>) {
    if azos_limits::MOTOR_COMMANDER_EXIT_STOP {
        COMMANDERS.note(wheel, azos_sched::current_task_tid(), applied);
    }
}

/// [`note_current`] for a caller that already has the TID (the speed and
/// move handlers; the ktest that stands in for a ring-3 commander).
#[inline]
pub fn note(wheel: u32, tid: u32, applied: Option<u32>) {
    if azos_limits::MOTOR_COMMANDER_EXIT_STOP {
        COMMANDERS.note(wheel, tid, applied);
    }
}

/// The task commanding `wheel`, 0 for none.
pub fn commander(wheel: u32) -> u32 {
    COMMANDERS.commander(wheel)
}

/// The last [`exit_stop`] that stopped something: `(tid << 32) | mask` of
/// the wheels the motor layer reported at duty 0 after the stop. Read by the
/// ktest; 0 before any.
static LAST_EXIT_STOP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `(tid, wheels confirmed at duty 0)` of the last [`exit_stop`] that took a
/// wheel.
pub fn last_exit_stop() -> (u32, u32) {
    let v = LAST_EXIT_STOP.load(Ordering::Acquire);
    ((v >> 32) as u32, v as u32)
}

/// Task `tid` is exiting: stop (duty 0, coast) every wheel it still
/// commands. Returns `(taken, stopped)`: the wheels it commanded, and those
/// the motor layer confirmed at duty 0 (bit `i` = wheel `i`); the caller
/// records the event. Nothing is taken with Kconfig
/// `MOTOR_COMMANDER_EXIT_STOP` off.
pub fn exit_stop(tid: u32) -> (u32, u32) {
    if !azos_limits::MOTOR_COMMANDER_EXIT_STOP {
        return (0, 0);
    }
    let taken = COMMANDERS.release(tid);
    if taken == 0 {
        return (0, 0);
    }
    let mut stopped = 0u32;
    // Gate canary: the wheels are taken and never stopped.
    if !cfg!(feature = "commander-exit-nostop-canary") {
        for i in 0..32 {
            if taken & (1 << i) != 0
                && matches!(azos_robot::motor_stop_reporting(i), (0, Some(0)))
            {
                stopped |= 1 << i;
            }
        }
    }
    LAST_EXIT_STOP.store(((tid as u64) << 32) | stopped as u64, Ordering::Release);
    (taken, stopped)
}
