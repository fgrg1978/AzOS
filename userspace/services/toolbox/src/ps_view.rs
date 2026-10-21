// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The task list `ps` prints, read from the introspection tree.
//!
//! The admin region holds one directory per live task,
//! `sched/tasks/<tid>/{name, state, priority, parent}`, rebuilt at every
//! refresh (`kernel/src/boot/inspect.rs`). A walk visits a directory before
//! its children and gives each node a path ([`crate::metrics_view::PathStack`]);
//! [`Table::feed`] files the leaves of those paths into rows, and
//! [`Table::render`] prints them as `ps` always did: a header, then TID,
//! parent, priority, state and name a line.
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

/// One task.
#[derive(Clone, Copy)]
pub struct Row {
    tid: u64,
    parent: u64,
    priority: u64,
    state: u8,
    name: [u8; NAME_MAX],
    name_len: u8,
}

const ROW0: Row = Row { tid: 0, parent: 0, priority: 0, state: b'?', name: [0; NAME_MAX], name_len: 0 };

/// What a leaf of a task's directory holds.
pub enum Leaf<'a> {
    U64(u64),
    Str(&'a str),
}

/// The tasks a walk met.
pub struct Table {
    rows: [Row; ROWS_MAX],
    n: usize,
    /// Tasks past [`ROWS_MAX`], and the last of them (its leaves arrive together).
    over: usize,
    over_tid: Option<u64>,
}

impl Table {
    pub const fn new() -> Self {
        Table { rows: [ROW0; ROWS_MAX], n: 0, over: 0, over_tid: None }
    }

    /// Forget every task: a walk of a rebuilt region starts again from its root.
    /// In place: only `rows[..n]` is ever read, so the rows need no rewrite, and
    /// `*self = Table::new()` built a second table (6 KiB) in the stack frame of
    /// the walk's closure, which `ps` runs on top of its own.
    pub fn clear(&mut self) {
        self.n = 0;
        self.over = 0;
        self.over_tid = None;
    }

    /// Tasks held.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.n
    }

    /// File the leaf at `path` (`sched/tasks/<tid>/<field>`) under its task.
    /// Anything else, a field this listing does not print, or a leaf of the
    /// wrong kind, is ignored. A walk is pre-order, so a task's leaves arrive
    /// together: only the latest row is looked at.
    pub fn feed(&mut self, path: &str, leaf: Leaf<'_>) {
        let Some(rest) = path.strip_prefix(TASKS) else { return };
        let Some((tid, field)) = rest.split_once('/') else { return };
        let Some(tid) = parse_tid(tid) else { return };
        let Some(row) = self.row_of(tid) else { return };
        match (field, leaf) {
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

    /// The row of `tid`: the latest one, or a new one. `None` once the table
    /// is full (the task is counted in `over`, once).
    fn row_of(&mut self, tid: u64) -> Option<&mut Row> {
        if self.n > 0 && self.rows[self.n - 1].tid == tid {
            return Some(&mut self.rows[self.n - 1]);
        }
        if self.n == ROWS_MAX {
            // A task's leaves arrive together: count it on the first.
            if self.over_tid != Some(tid) {
                self.over += 1;
                self.over_tid = Some(tid);
            }
            return None;
        }
        self.rows[self.n] = Row { tid, ..ROW0 };
        self.n += 1;
        self.rows.get_mut(self.n - 1)
    }

    /// The header and a line a task, then `... N more` when some did not fit.
    pub fn render(&self, w: &mut dyn Write) -> fmt::Result {
        w.write_str(HEADER)?;
        for r in &self.rows[..self.n] {
            let name = core::str::from_utf8(&r.name[..r.name_len as usize]).unwrap_or("?");
            writeln!(w, "{:5} {:5} {:3} {} {}", r.tid, r.parent, r.priority, r.state as char, name)?;
        }
        if self.over > 0 {
            writeln!(w, "... {} more", self.over)?;
        }
        Ok(())
    }
}

fn parse_tid(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    s.bytes().try_fold(0u64, |v, c| if c.is_ascii_digit() { Some(v * 10 + (c - b'0') as u64) } else { None })
}
