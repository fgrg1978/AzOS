// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The live-instance count of each topology row: a gate, not a statistic.
//! Every claim is a compare-exchange against the cap, so two harts cannot both
//! take the last instance. Rows are identified by index + 1, as
//! `TaskMem::row` stores them; row 0 is "no row" and counts nothing.
//!
//! Kept free of the scheduler so the host suite pulls it in unchanged
//! (`tests/host/sched-policy-tests`).

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

const ROW_SLOTS: usize = azos_limits::MAX_TASKS;

static ROW_LIVE: [AtomicU32; ROW_SLOTS] = [const { AtomicU32::new(0) }; ROW_SLOTS];
/// The `instances` each row last claimed with (topology-constant per row), so
/// a fork, which has no topology to ask, claims against the same cap.
static ROW_CAP: [AtomicU16; ROW_SLOTS] = [const { AtomicU16::new(0) }; ROW_SLOTS];

/// Take one live-instance count of `row` (index + 1) whose `instances` is
/// `cap`. `true` for row 0 (no row: nothing is counted). `false`, and
/// nothing taken, when `cap` instances are already live.
pub fn row_claim(row: u16, cap: u16) -> bool {
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return true;
    }
    let live = &ROW_LIVE[i - 1];
    let mut cur = live.load(Ordering::Relaxed);
    loop {
        if cur >= cap as u32 {
            return false;
        }
        match live.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => {
                ROW_CAP[i - 1].store(cap, Ordering::Relaxed);
                return true;
            }
            Err(now) => cur = now,
        }
    }
}

/// [`row_claim`] for a fork child of a task that holds a count of `row`, with
/// the cap that count was claimed under. `false` when the row is full.
///
/// Canary `fork-row-instance-canary`: a fork child is never refused.
pub fn row_claim_for_fork(row: u16) -> bool {
    if cfg!(feature = "fork-row-instance-canary") {
        return true;
    }
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return true;
    }
    row_claim(row, ROW_CAP[i - 1].load(Ordering::Relaxed))
}

/// The `instances` cap [`row_claim`] last saw for `row`; 0 when never claimed.
pub fn row_cap(row: u16) -> u16 {
    ROW_CAP.get((row as usize).wrapping_sub(1)).map_or(0, |c| c.load(Ordering::Relaxed))
}

/// Give back a count taken by [`row_claim`]. Saturates at 0.
pub fn row_release(row: u16) {
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return;
    }
    let _ = ROW_LIVE[i - 1].fetch_update(Ordering::AcqRel, Ordering::Relaxed, |v| v.checked_sub(1));
}

/// Instances of `row` (index + 1) live now.
pub fn row_live(row: u16) -> u32 {
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return 0;
    }
    ROW_LIVE[i - 1].load(Ordering::Relaxed)
}
