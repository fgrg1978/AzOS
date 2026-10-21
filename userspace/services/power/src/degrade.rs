// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The low-battery degrade rows and the level the charge selects. Pure: the
//! rows are the signed topology's `[degrade.NAME]` rows, read back from the
//! kernel (`POLICY_STATE_BATTERY_ROW_BASE`), and the host suite
//! (`tests/host/power-tests`) drives [`select`] with scripted charges.
//!
//! A row is entered at or below its `battery_pct` and left above its
//! `clear_pct` (the hysteresis the topology declares, so a charge that
//! jitters on a threshold does not toggle the level). What a level asks of the
//! machine is `policy::degrade`; what the kernel allows of it is the kernel's.

use azos_power::*;

use super::battery::{Estimator, Sample};

/// Most rows a topology declares.
pub const MAX_ROWS: usize = POLICY_DEGRADE_ROWS_MAX;

/// One `[degrade.NAME]` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The level the row enters (1 cautious, 2 slow, 3 contained).
    pub level: u8,
    /// Entered at or below this charge, percent.
    pub battery_pct: u8,
    /// Left above this charge, percent.
    pub clear_pct: u8,
}

impl Row {
    /// Unpack the kernel's state word.
    pub const fn of(w: u64) -> Row {
        Row { level: w as u8, battery_pct: (w >> 8) as u8, clear_pct: (w >> 16) as u8 }
    }
}

/// The topology's rows, in file order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rows {
    rows: [Row; MAX_ROWS],
    n: usize,
}

impl Rows {
    /// No rows: the machine declares no battery, and nothing degrades.
    pub const NONE: Rows = Rows { rows: [Row { level: 0, battery_pct: 0, clear_pct: 0 }; MAX_ROWS], n: 0 };

    /// A set of rows (at most [`MAX_ROWS`]; the rest are dropped).
    pub fn new(rows: &[Row]) -> Rows {
        let mut r = Rows::NONE;
        for (slot, row) in r.rows.iter_mut().zip(rows) {
            *slot = *row;
            r.n += 1;
        }
        r
    }

    /// The rows.
    pub fn rows(&self) -> &[Row] {
        &self.rows[..self.n]
    }

    /// The rows the kernel holds. `None` when a read failed.
    pub fn load<P: PowerPolicy + ?Sized>(p: &P) -> Option<Rows> {
        let head = p.state(POLICY_STATE_BATTERY as u32);
        if head == WORD_ERR {
            return None;
        }
        let n = ((head >> 24 & 0xFF) as usize).min(MAX_ROWS);
        let mut rows = [Row { level: 0, battery_pct: 0, clear_pct: 0 }; MAX_ROWS];
        for (i, slot) in rows.iter_mut().enumerate().take(n) {
            match p.state(POLICY_STATE_BATTERY_ROW_BASE as u32 + i as u32) {
                WORD_ERR => return None,
                w => *slot = Row::of(w),
            }
        }
        Some(Rows::new(&rows[..n]))
    }
}

/// The kernel's battery reserve, percent (`ENERGY_BATTERY_RESERVE_PCT`):
/// the charge at and below which it holds the clocks at their lowest legal
/// OPP, whatever this server asks. `None` when the read failed.
pub fn reserve_pct<P: PowerPolicy + ?Sized>(p: &P) -> Option<u8> {
    match p.state(POLICY_STATE_BATTERY as u32) {
        WORD_ERR => None,
        w => Some((w >> 40) as u8),
    }
}

/// The level to hold at charge `soc_pct` when `current` is held now: the most
/// restrictive row that is entered (the charge is at or below its threshold)
/// or still held (it is not above its `clear_pct` and the level it enters is
/// not past the current one). 0 when no row applies.
pub fn select(rows: &Rows, soc_pct: u8, current: u8) -> u8 {
    rows.rows()
        .iter()
        .filter(|r| {
            soc_pct <= r.battery_pct
                || (r.level <= current && soc_pct <= r.clear_pct && !cfg!(feature = "pw-degrade-canary"))
        })
        .map(|r| r.level)
        .max()
        .unwrap_or(0)
}

/// What one look at the battery came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch {
    /// The level to hold from now on.
    pub level: u8,
    /// The charge estimated, percent; `None` when there was no sample.
    pub soc: Option<u8>,
    /// The kernel's answer to the report; `None` when nothing was reported.
    pub verdict: Option<Verdict>,
}

/// One look at the battery: a sample (or none) becomes a charge, the rows
/// choose the level for it, and both go to the kernel. The level to hold is
/// the new one, or `level` again when there is nothing to look at (no rows,
/// no sample) or the kernel did not take the report.
pub fn watch<P: PowerPolicy + ?Sized>(
    p: &mut P,
    rows: &Rows,
    est: &mut Estimator,
    level: u8,
    sample: Option<Sample>,
) -> Watch {
    let (false, Some(sample)) = (rows.rows().is_empty(), sample) else {
        return Watch { level, soc: None, verdict: None };
    };
    let soc = est.update(sample);
    let next = select(rows, soc, level);
    let verdict = Verdict::of(p.report_battery(soc as u32, next as u32));
    let level = if verdict == Verdict::Applied { next } else { level };
    Watch { level, soc: Some(soc), verdict: Some(verdict) }
}
