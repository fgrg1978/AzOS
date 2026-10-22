// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The admin region's task list, written where a task changes.
//!
//! ```text
//! sched/tasks/<row>/{tid, name, state, priority, parent}     tid 0: a free row
//! ```
//!
//! The shape is built once, at boot, with one row per task the list can show
//! ([`ROWS`], or `MAX_TASKS` when it is smaller); it is never rebuilt, so a
//! value can be written from any context with the writer's per-node seqlock
//! and no other lock. The scheduler calls [`TaskList::note`] with the task
//! slot that changed (a task made, a task that became a zombie, a slot freed,
//! a parent re-linked, two slots that swapped identities at an exec), and the
//! note writes the slot's row before the change's caller goes on: a reader
//! that sees the change done (the TID a spawn returned, a reaped child) finds
//! it in the list, with no wait. Ready or blocked and the effective priority
//! move at every switch and every donation; those two are sampled with the
//! counters ([`TaskList::resample`]), as `sched/tasks_*` are.
//!
//! One writer a slot: a note that finds the slot's row being written marks it
//! changed again and returns, and the writer that holds it reads the slot once
//! more before it lets go ([`coalesce`]). So a note made from an interrupt on
//! the CPU that is writing the same slot cannot deadlock, and the last state
//! of the slot is the one written.
//!
//! Plain Rust over `azos_inspect`: the host suite (`tests/host/inspect-tests`)
//! pulls this file in with `#[path]`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use azos_inspect::{Builder, Error, NodeId, Writer};

/// Rows the list holds at most: the tasks it shows. A task made while every
/// row is held is not listed (the refresh says so, once:
/// [`TaskList::cut_unsaid`]).
pub(crate) const ROWS: usize = 64;
/// Bytes of a task's name the list shows.
pub(crate) const NAME: usize = 16;

const _: () = assert!(ROWS < u8::MAX as usize && ROWS <= 1000);

/// One task as the list shows it. `state`: `R` ready or running, `S` blocked,
/// `Z` exited and not yet freed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Task {
    pub tid: u32,
    pub parent: u32,
    pub priority: u32,
    pub state: u8,
    pub name: [u8; NAME],
}

#[derive(Clone, Copy)]
struct Nodes {
    tid: NodeId,
    name: NodeId,
    state: NodeId,
    priority: NodeId,
    parent: NodeId,
}

const NO_NODES: Nodes =
    Nodes { tid: NodeId::ROOT, name: NodeId::ROOT, state: NodeId::ROOT, priority: NodeId::ROOT, parent: NodeId::ROOT };

/// The rows' nodes, as [`build`] made them.
#[derive(Clone, Copy)]
pub(crate) struct Shape {
    rows: [Nodes; ROWS],
    n: usize,
}

impl Shape {
    pub(crate) const EMPTY: Shape = Shape { rows: [NO_NODES; ROWS], n: 0 };

    /// Rows built.
    pub(crate) fn rows(&self) -> usize {
        self.n
    }
}

/// Add `sched/tasks/<row>` for `rows` rows (at most [`ROWS`]) to the tree
/// being built, into `out`. What fit is kept when the region is short.
pub(crate) fn build(b: &mut Builder<'_, '_>, rows: usize, out: &mut Shape) -> Result<(), Error> {
    *out = Shape::EMPTY;
    let sched = b.dir(NodeId::ROOT, "sched")?;
    let tasks = b.dir(sched, "tasks")?;
    let mut name = [0u8; 3];
    for r in 0..rows.min(ROWS) {
        let d = b.dir(tasks, decimal(r, &mut name))?;
        out.rows[r] = Nodes {
            tid: b.u64(d, "tid", 0)?,
            name: b.string(d, "name", NAME, "")?,
            state: b.string(d, "state", 1, "")?,
            priority: b.u64(d, "priority", 0)?,
            parent: b.u64(d, "parent", 0)?,
        };
        out.n = r + 1;
    }
    Ok(())
}

/// `v` (below 1000) in decimal.
fn decimal(v: usize, buf: &mut [u8; 3]) -> &str {
    let digits = if v >= 100 { 3 } else if v >= 10 { 2 } else { 1 };
    let mut x = v;
    for i in (0..digits).rev() {
        buf[i] = b'0' + (x % 10) as u8;
        x /= 10;
    }
    core::str::from_utf8(&buf[..digits]).unwrap_or("0")
}

/// Run `f` now, or, when another caller is running it for the same `flag`,
/// have that caller run it once more and return. `flag`: 0 idle, 1 running,
/// 2 running and asked again. Never waits.
pub(crate) fn coalesce(flag: &AtomicU8, mut f: impl FnMut()) {
    loop {
        match flag.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => break,
            // Running: ask again, unless it finished meanwhile (then retry).
            Err(1) => {
                if flag.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    loop {
        f();
        if flag.compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed).is_ok() {
            return;
        }
        // Asked again while `f` ran.
        flag.store(1, Ordering::Relaxed);
    }
}

/// The list: the region's writer, the rows' nodes, which slot holds each row
/// and which row each slot holds.
pub(crate) struct TaskList<'a> {
    w: Writer<'a>,
    shape: Shape,
    /// Per row: the task slot holding it, plus one; 0 for a free row.
    holder: [AtomicU32; ROWS],
    /// Per row: the TID it shows, for its writer.
    shown: [AtomicU32; ROWS],
    /// Per task slot: its row plus one, 0 for none. Written only by the
    /// slot's one writer ([`coalesce`] over `busy`).
    row_of: &'a [AtomicU8],
    /// Per task slot: [`coalesce`]'s flag.
    busy: &'a [AtomicU8],
    /// A task found no free row; and the refresh said so.
    cut: AtomicBool,
    said: AtomicBool,
}

impl<'a> TaskList<'a> {
    /// The list over `w`, whose tree [`build`] made `shape` in; one `row_of`
    /// and one `busy` word per task slot, all 0.
    pub(crate) fn new(w: Writer<'a>, shape: Shape, row_of: &'a [AtomicU8], busy: &'a [AtomicU8]) -> Self {
        TaskList {
            w,
            shape,
            holder: [const { AtomicU32::new(0) }; ROWS],
            shown: [const { AtomicU32::new(0) }; ROWS],
            row_of,
            busy,
            cut: AtomicBool::new(false),
            said: AtomicBool::new(false),
        }
    }

    /// Task slot `slot` changed: write its row from `read(slot)` (`None`, or a
    /// TID of 0, for a slot no task holds). Any context; no lock, no wait.
    ///
    /// **Gate canary `task-view-stale-canary`:** a note writes nothing and the
    /// refresh rewrites every slot ([`TaskList::resample`]), as the list was
    /// before it was written on change: a task is listed up to a refresh
    /// period after it is made, and a reaped one stays as long. The host
    /// suite's `a_change_is_listed_before_the_note_returns` and the
    /// `inspect: views` rows' task-list checks must fail.
    pub(crate) fn note(&self, slot: usize, read: &dyn Fn(usize) -> Option<Task>) {
        if !cfg!(feature = "task-view-stale-canary") {
            self.write(slot, read);
        }
    }

    fn write(&self, slot: usize, read: &dyn Fn(usize) -> Option<Task>) {
        let (Some(busy), Some(row_of)) = (self.busy.get(slot), self.row_of.get(slot)) else { return };
        coalesce(busy, || self.sync(slot, row_of, read(slot).filter(|t| t.tid != 0)));
    }

    /// `true` once, after a task found every row held: for the refresh to say
    /// so (a note may run where nothing can be printed).
    pub(crate) fn cut_unsaid(&self) -> bool {
        self.cut.load(Ordering::Relaxed) && !self.said.swap(true, Ordering::Relaxed)
    }

    /// Read again every listed task: what moves at every switch (the state,
    /// the effective priority). From the refresh, with the counters.
    pub(crate) fn resample(&self, read: &dyn Fn(usize) -> Option<Task>) {
        if cfg!(feature = "task-view-stale-canary") {
            for slot in 0..self.busy.len() {
                self.write(slot, read);
            }
            return;
        }
        for h in &self.holder[..self.shape.n] {
            let s = h.load(Ordering::Acquire);
            if s != 0 {
                self.write(s as usize - 1, read);
            }
        }
    }

    /// The writer of `slot`'s row (`row_of` its word): make the row show `t`.
    fn sync(&self, slot: usize, row_of: &AtomicU8, t: Option<Task>) {
        let mut row = (row_of.load(Ordering::Relaxed) as usize).checked_sub(1);
        let Some(t) = t else {
            if let Some(r) = row {
                self.clear(r);
                row_of.store(0, Ordering::Relaxed);
                self.holder[r].store(0, Ordering::Release);
            }
            return;
        };
        if row.is_none() {
            row = self.claim(slot);
        }
        let Some(r) = row else {
            self.cut.store(true, Ordering::Relaxed);
            return;
        };
        row_of.store(r as u8 + 1, Ordering::Relaxed);
        self.put(r, &t);
    }

    fn claim(&self, slot: usize) -> Option<usize> {
        let me = slot as u32 + 1;
        (0..self.shape.n)
            .find(|&r| self.holder[r].compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok())
    }

    /// Write `t` into row `r`. A row that showed another task (or none) is
    /// taken off the list first (TID 0) and given its TID last, so a reader
    /// never pairs one task's TID with another's fields. A write cannot fail
    /// on a node of the shape that has one writer, so none is checked.
    fn put(&self, r: usize, t: &Task) {
        let n = &self.shape.rows[r];
        let fresh = self.shown[r].load(Ordering::Relaxed) != t.tid;
        if fresh {
            let _ = self.w.set_u64(n.tid, 0);
        }
        let len = t.name.iter().position(|c| *c == 0).unwrap_or(NAME);
        let _ = self.w.set_str(n.name, core::str::from_utf8(&t.name[..len]).unwrap_or("?"));
        let _ = self.w.set_str(n.state, core::str::from_utf8(&[t.state]).unwrap_or("?"));
        let _ = self.w.set_u64(n.priority, t.priority as u64);
        let _ = self.w.set_u64(n.parent, t.parent as u64);
        if fresh {
            let _ = self.w.set_u64(n.tid, t.tid as u64);
            self.shown[r].store(t.tid, Ordering::Relaxed);
        }
    }

    /// Take row `r` off the list.
    fn clear(&self, r: usize) {
        let n = &self.shape.rows[r];
        let _ = self.w.set_u64(n.tid, 0);
        self.shown[r].store(0, Ordering::Relaxed);
        let _ = self.w.set_str(n.name, "");
        let _ = self.w.set_str(n.state, "");
        let _ = self.w.set_u64(n.priority, 0);
        let _ = self.w.set_u64(n.parent, 0);
    }
}
