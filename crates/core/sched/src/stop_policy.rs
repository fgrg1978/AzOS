// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure half of `SYS_TASK_KILL` (RFC-0055 §5.5): who may stop whom, and
//! how a stop request is packed into a word.
//!
//! **Authority is a relation, not a name.** A caller may stop a task only if
//! it is that task's ANCESTOR: the target's parent, its parent's parent, and
//! so on, at most [`MAX_ANCESTRY`] steps up. Kernel tasks are the parents of
//! every supervised ring-3 driver, so no ring-3 caller is ever an ancestor of
//! one. Pure, with the parent lookup a closure, so `tests/host/sched-wake-tests`
//! pulls it in with `#[path]`.

/// Steps up the parent chain an ancestor is looked for.
pub const MAX_ANCESTRY: usize = 8;

/// Highest signal number a stop may carry (its exit code is `128 + signo`).
pub const SIGNO_MAX: u32 = 31;

/// Is `caller` an ancestor of `target`, within `max` steps, by `parent_of`
/// (0 = no parent)? A task is not its own ancestor.
pub fn is_ancestor(caller: u32, target: u32, parent_of: impl Fn(u32) -> u32, max: usize) -> bool {
    if caller == 0 || target == 0 || caller == target {
        return false;
    }
    let mut p = parent_of(target);
    for _ in 0..max {
        if p == 0 {
            return false;
        }
        if p == caller {
            return true;
        }
        p = parent_of(p);
    }
    false
}

/// May `viewer` see `target` in `/proc` (wave 12, owner round 48: Linux
/// `hidepid=2`)? With `full` (the viewer holds `Cap<Task>` `READ` on
/// `"tasks"`) every task; otherwise only itself and its descendants — the
/// relation [`is_ancestor`] already decides for `SYS_TASK_KILL`, with the same
/// step bound, so a task listed is a task its viewer may also stop. A task
/// with no viewer (0, no task) sees nothing, and TID 0 is never a task.
///
/// The parent link is cleared when a task exits, so a descendant of an
/// intermediate task that has exited is no longer reachable from the
/// viewer: there is no re-parenting, and that subtree drops out of a
/// filtered view.
pub fn may_see(viewer: u32, target: u32, full: bool, parent_of: impl Fn(u32) -> u32, max: usize) -> bool {
    if target == 0 {
        return false;
    }
    full || (viewer != 0 && (viewer == target || is_ancestor(viewer, target, parent_of, max)))
}

/// A stop request, as one word: bit 9 force, bit 8 requested, low byte signo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop {
    /// End the task at its next return to user mode.
    pub force: bool,
    /// The signal number: its exit code is `128 + signo`.
    pub signo: u8,
}

const REQUESTED: u32 = 1 << 8;
const FORCE: u32 = 1 << 9;

impl Stop {
    /// Pack into a word that is never 0.
    pub const fn encode(self) -> u32 {
        REQUESTED | if self.force { FORCE } else { 0 } | self.signo as u32
    }

    /// Unpack; `None` for 0 (no request).
    pub const fn decode(w: u32) -> Option<Stop> {
        if w & REQUESTED == 0 {
            return None;
        }
        Some(Stop { force: w & FORCE != 0, signo: (w & 0xff) as u8 })
    }

    /// Combine with a request already pending: force sticks, and the first
    /// signal number stays.
    pub const fn merge(old: Option<Stop>, new: Stop) -> Stop {
        match old {
            Some(o) => Stop { force: o.force || new.force, signo: o.signo },
            None => new,
        }
    }

    /// The exit code a forced stop ends the task with.
    pub const fn exit_code(self) -> i32 {
        128 + self.signo as i32
    }
}
