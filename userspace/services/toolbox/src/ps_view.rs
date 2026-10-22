// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The task list `ps` prints, read from the introspection tree.
//!
//! The admin region holds a fixed set of rows,
//! `sched/tasks/<row>/{tid, name, state, priority, parent}`, a row a task and
//! TID 0 for a free one, written by the kernel where a task changes
//! (`kernel/src/boot/inspect_tasks.rs`). A walk visits a directory before its
//! children and gives each node a path ([`crate::metrics_view::PathStack`]);
//! [`Table::feed`] files the leaves of those paths into rows, and
//! [`Table::render`] prints the rows that hold a task as `ps` always did: a
//! header, then TID, parent, priority, state and name a line.
//!
//! Plain Rust over `core::fmt`, compiled by the host tests
//! (`tests/host/sh-tests/src/lib.rs`) through a `#[path]` include.

use core::fmt::{self, Write};

/// The first line of the listing.
pub const HEADER: &str = "  TID  PPID PRI S NAME\n";

/// Rows kept; a task past them is counted in the closing `... N more` line.
pub const ROWS_MAX: usize = 128;

/// Longest task name the kernel publishes.
const NAME_MAX: usize = 16;

/// The prefix every task node's path carries.
const TASKS: &str = "sched/tasks/";

/// One row of the list: the task it holds (TID 0: none).
#[derive(Clone, Copy)]
pub struct Row {
    row: u64,
    tid: u64,
    parent: u64,
    priority: u64,
    state: u8,
    name: [u8; NAME_MAX],
    name_len: u8,
}

const ROW0: Row = Row { row: 0, tid: 0, parent: 0, priority: 0, state: b'?', name: [0; NAME_MAX], name_len: 0 };

/// What a leaf of a task's directory holds.
pub enum Leaf<'a> {
    U64(u64),
    Str(&'a str),
}

/// The rows a walk met.
pub struct Table {
    rows: [Row; ROWS_MAX],
    n: usize,
    /// Rows past [`ROWS_MAX`] that hold a task, and the last row past it (its
    /// leaves arrive together).
    over: usize,
    over_row: Option<u64>,
}

impl Table {
    pub const fn new() -> Self {
        Table { rows: [ROW0; ROWS_MAX], n: 0, over: 0, over_row: None }
    }

    /// Forget every row: a walk that is retried starts again from its root.
    /// In place: only `rows[..n]` is ever read, so the rows need no rewrite, and
    /// `*self = Table::new()` built a second table (6 KiB) in the stack frame of
    /// the walk's closure, which `ps` runs on top of its own.
    pub fn clear(&mut self) {
        self.n = 0;
        self.over = 0;
        self.over_row = None;
    }

    /// Tasks held.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.rows[..self.n].iter().filter(|r| r.tid != 0).count()
    }

    /// File the leaf at `path` (`sched/tasks/<row>/<field>`) under its row.
    /// Anything else, a field this listing does not print, or a leaf of the
    /// wrong kind, is ignored. A walk is pre-order, so a row's leaves arrive
    /// together: only the latest row is looked at.
    pub fn feed(&mut self, path: &str, leaf: Leaf<'_>) {
        let Some(rest) = path.strip_prefix(TASKS) else { return };
        let Some((row, field)) = rest.split_once('/') else { return };
        let Some(row) = parse_num(row) else { return };
        let Some(row) = self.row_of(row, matches!((field, &leaf), ("tid", Leaf::U64(t)) if *t != 0)) else { return };
        match (field, leaf) {
            ("tid", Leaf::U64(v)) => row.tid = v,
            ("parent", Leaf::U64(v)) => row.parent = v,
            ("priority", Leaf::U64(v)) => row.priority = v,
            ("state", Leaf::Str(s)) => row.state = s.as_bytes().first().copied().unwrap_or(b'?'),
            ("name", Leaf::Str(s)) => {
                let n = s.len().min(NAME_MAX);
                row.name[..n].copy_from_slice(&s.as_bytes()[..n]);
                row.name_len = n as u8;
            }
            _ => {}
        }
    }

    /// Row `row`: the latest one, or a new one. `None` once the table is
    /// full (a row past it that holds a task, `holds`, is counted in `over`,
    /// once: a row's TID is its first leaf).
    fn row_of(&mut self, row: u64, holds: bool) -> Option<&mut Row> {
        if self.n > 0 && self.rows[self.n - 1].row == row {
            return Some(&mut self.rows[self.n - 1]);
        }
        if self.n == ROWS_MAX {
            if holds && self.over_row != Some(row) {
                self.over += 1;
                self.over_row = Some(row);
            }
            return None;
        }
        self.rows[self.n] = Row { row, ..ROW0 };
        self.n += 1;
        self.rows.get_mut(self.n - 1)
    }

    /// The header and a line a task, then `... N more` when some did not fit.
    pub fn render(&self, w: &mut dyn Write) -> fmt::Result {
        w.write_str(HEADER)?;
        for r in self.rows[..self.n].iter().filter(|r| r.tid != 0) {
            let name = core::str::from_utf8(&r.name[..r.name_len as usize]).unwrap_or("?");
            writeln!(w, "{:5} {:5} {:3} {} {}", r.tid, r.parent, r.priority, r.state as char, name)?;
        }
        if self.over > 0 {
            writeln!(w, "... {} more", self.over)?;
        }
        Ok(())
    }
}

fn parse_num(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    s.bytes().try_fold(0u64, |v, c| if c.is_ascii_digit() { Some(v * 10 + (c - b'0') as u64) } else { None })
}
