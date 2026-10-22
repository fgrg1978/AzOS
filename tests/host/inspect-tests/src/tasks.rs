// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the admin region's task list
//! (`kernel/src/boot/inspect_tasks.rs`, included by path): a change in a task
//! slot is in the list when its note returns, read the way ring 3 reads it
//! (`Reader` over the words, the TID leaf of each row), with no refresh in
//! between; a row is reused once its task is freed; a full list is said once;
//! notes of one slot from two threads (or from an interrupt on the CPU that
//! is writing it) leave the slot's last state; and the admin tree's whole
//! shape fits the region Kconfig gives it, on the embedded profile too.
//!
//! **Canary** `--features task-view-stale-canary`: a note writes nothing and
//! the refresh rewrites every slot, as before the list was written on change;
//! `a_change_is_listed_before_the_note_returns` must fail.

#[path = "../../../../kernel/src/boot/inspect_tasks.rs"]
pub(crate) mod kt;

use azos_inspect::{Class, Reader, Region, Value, Writer};
use kt::{coalesce, Shape, Task, TaskList, NAME, ROWS};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering::*};
use std::sync::Mutex;

fn words(pages: usize) -> Vec<AtomicU64> {
    (0..pages * 512).map(|_| AtomicU64::new(0)).collect()
}

fn task(tid: u32, parent: u32, state: u8, name: &str) -> Task {
    let mut n = [0u8; NAME];
    n[..name.len()].copy_from_slice(name.as_bytes());
    Task { tid, parent, priority: 24, state, name: n }
}

/// A scheduler's slots, as `azos_sched::task_row_at` reads them.
struct Slots(Mutex<Vec<Option<Task>>>);

impl Slots {
    fn new(n: usize) -> Slots {
        Slots(Mutex::new(vec![None; n]))
    }
    fn set(&self, i: usize, t: Option<Task>) {
        self.0.lock().unwrap()[i] = t;
    }
    fn read(&self) -> impl Fn(usize) -> Option<Task> + '_ {
        move |i| self.0.lock().unwrap()[i]
    }
}

/// The list over a region of `pages` pages with `rows` rows and `slots` task
/// slots.
struct Fixture {
    region: &'static [AtomicU64],
    list: TaskList<'static>,
}

fn fixture(pages: usize, rows: usize, slots: usize) -> Fixture {
    let region: &'static [AtomicU64] = Box::leak(words(pages).into_boxed_slice());
    let w = Writer::init(Region::from_atomics(region), Class::Admin).unwrap();
    let mut shape = Shape::EMPTY;
    w.rebuild(|b| kt::build(b, rows, &mut shape)).unwrap();
    assert_eq!(shape.rows(), rows.min(ROWS));
    let row_of: &'static [AtomicU8] = Box::leak((0..slots).map(|_| AtomicU8::new(0)).collect::<Vec<_>>().into_boxed_slice());
    let busy: &'static [AtomicU8] = Box::leak((0..slots).map(|_| AtomicU8::new(0)).collect::<Vec<_>>().into_boxed_slice());
    Fixture { region, list: TaskList::new(w, shape, row_of, busy) }
}

/// The list as ring 3 reads it: (TID, parent, state, name) of each row whose
/// TID is not 0, in row order.
fn listed(region: &[AtomicU64]) -> Vec<(u32, u32, u8, String)> {
    let r = Reader::open(Region::from_atomics(region), Class::Admin).unwrap();
    let dir = r.lookup("sched/tasks").unwrap().expect("sched/tasks");
    let mut out = Vec::new();
    r.children(dir, &mut |info, _| {
        let leaf = |name: &str| r.lookup_in(info.id, name).unwrap().map(|id| r.read(id).unwrap());
        let Some(Value::U64(tid)) = leaf("tid") else { panic!("a row without a TID") };
        if tid == 0 {
            return;
        }
        let Some(Value::U64(parent)) = leaf("parent") else { panic!("no parent") };
        let Some(Value::Str(state)) = leaf("state") else { panic!("no state") };
        let Some(Value::Str(name)) = leaf("name") else { panic!("no name") };
        out.push((tid as u32, parent as u32, state.as_bytes().first().copied().unwrap_or(b'?'), name.as_str().to_string()));
    })
    .unwrap();
    out
}

fn tids(region: &[AtomicU64]) -> Vec<u32> {
    listed(region).iter().map(|t| t.0).collect()
}

/// Every change of a task's life is in the list when the note made at the
/// change returns: made, a zombie, freed, its slot reused by another task.
/// **Canary:** `task-view-stale-canary` (the note writes nothing; only the
/// refresh does): the first check fails, red.
#[test]
fn a_change_is_listed_before_the_note_returns() {
    let f = fixture(16, ROWS, 128);
    let s = Slots::new(128);
    let read = s.read();
    s.set(5, Some(task(40, 1, b'R', "SH.ELF")));
    f.list.note(5, &read);
    assert_eq!(listed(f.region), vec![(40, 1, b'R', "SH.ELF".to_string())], "a task made is listed at once");
    s.set(5, Some(task(40, 1, b'Z', "SH.ELF")));
    f.list.note(5, &read);
    assert_eq!(listed(f.region)[0].2, b'Z', "a task that exited is a zombie at once");
    s.set(5, None);
    f.list.note(5, &read);
    assert_eq!(tids(f.region), Vec::<u32>::new(), "a freed task is gone at once");
    s.set(5, Some(task(41, 40, b'R', "ABICHILD.ELF")));
    f.list.note(5, &read);
    assert_eq!(listed(f.region), vec![(41, 40, b'R', "ABICHILD.ELF".to_string())], "a reused slot shows its new task");
}

/// The refresh does not list a task no note told of (a slot a probe fills
/// with TID 0 is not a task), and keeps the state and priority it samples.
#[test]
fn the_refresh_resamples_the_listed_tasks_only() {
    let f = fixture(16, ROWS, 16);
    let s = Slots::new(16);
    let read = s.read();
    s.set(0, Some(task(1, 0, b'R', "kernel")));
    s.set(1, Some(task(0, 0, b'S', "probe")));
    f.list.note(0, &read);
    f.list.note(1, &read);
    assert_eq!(tids(f.region), vec![1], "TID 0 is no task");
    s.set(0, Some(task(1, 0, b'S', "kernel")));
    f.list.resample(&read);
    assert_eq!(listed(f.region)[0].2, b'S', "the state is sampled at the refresh");
}

/// More tasks than rows: the newest are not listed and the refresh is told
/// once; a freed row is taken by the next task.
#[test]
fn a_full_list_is_said_once_and_a_freed_row_is_reused() {
    let f = fixture(16, 4, 8);
    let s = Slots::new(8);
    let read = s.read();
    for i in 0..5 {
        s.set(i, Some(task(10 + i as u32, 1, b'R', "t")));
        f.list.note(i, &read);
    }
    assert_eq!(tids(f.region), vec![10, 11, 12, 13]);
    assert!(f.list.cut_unsaid(), "the full list is said");
    assert!(!f.list.cut_unsaid(), "once");
    s.set(1, None);
    f.list.note(1, &read);
    s.set(5, Some(task(20, 1, b'R', "late")));
    f.list.note(5, &read);
    assert_eq!(tids(f.region), vec![10, 20, 12, 13], "row 1 is reused");
}

/// A note made while the same slot is being written (an interrupt on that
/// CPU, or another CPU) does not wait: the writer writes once more, with the
/// slot's last state.
#[test]
fn a_note_during_a_write_of_its_slot_is_written_by_the_writer() {
    let flag = AtomicU8::new(0);
    let runs = AtomicU64::new(0);
    coalesce(&flag, || {
        if runs.fetch_add(1, Relaxed) == 0 {
            // The nested note: returns at once, asks for one more run.
            let inner = AtomicU64::new(0);
            coalesce(&flag, || {
                inner.fetch_add(1, Relaxed);
            });
            assert_eq!(inner.load(Relaxed), 0, "the nested note did not run its own write");
        }
    });
    assert_eq!(runs.load(Relaxed), 2, "the writer ran once more");
    assert_eq!(flag.load(Relaxed), 0, "and let go");
}

/// Two threads note one slot while it changes under them: when both are
/// done, the row shows the slot's last state, and no other row is taken.
#[test]
fn notes_of_one_slot_from_two_threads_leave_its_last_state() {
    let f: &'static Fixture = Box::leak(Box::new(fixture(16, ROWS, 4)));
    let s: &'static Slots = Box::leak(Box::new(Slots::new(4)));
    for round in 0..200u32 {
        let h: Vec<_> = (0..2)
            .map(|k| {
                std::thread::spawn(move || {
                    let read = s.read();
                    for j in 0..20u32 {
                        let tid = 100 + round * 40 + k * 20 + j;
                        s.set(2, Some(task(tid, 1, b'R', "racer")));
                        f.list.note(2, &read);
                    }
                })
            })
            .collect();
        for t in h {
            t.join().unwrap();
        }
        let last = s.read()(2).unwrap().tid;
        f.list.note(2, &s.read());
        assert_eq!(tids(f.region), vec![last], "round {round}");
    }
}

/// The admin tree's whole shape (the task rows, the default wake ring and the
/// decision records, as `install_inspect` builds it) fits Kconfig's default
/// INSPECT_ADMIN_PAGES (16), for the default MAX_TASKS and the embedded
/// profile's (32).
#[test]
fn the_admin_tree_fits_its_region_on_every_profile() {
    const ADMIN_PAGES: usize = 16;
    const WAKE_RING_ENTRIES: usize = 32;
    const DECISION_ROWS: usize = 24;
    for max_tasks in [32, 256, 4096] {
        let a = words(ADMIN_PAGES);
        let w = Writer::init(Region::from_atomics(&a), Class::Admin).unwrap();
        let mut shape = Shape::EMPTY;
        let r = w.rebuild(|b| {
            kt::build(b, max_tasks, &mut shape)?;
            crate::metrics::km::build_admin_wake(b, WAKE_RING_ENTRIES)?;
            let dec = b.dir(azos_inspect::NodeId::ROOT, "decisions")?;
            let dir = b.dir(dec, "records")?;
            for k in 0..DECISION_ROWS {
                b.bytes(dir, &k.to_string(), azos_decision::PROVENANCE_SIZE, &[])?;
            }
            Ok(())
        });
        assert!(r.is_ok(), "MAX_TASKS {max_tasks}: {r:?}");
        assert_eq!(shape.rows(), max_tasks.min(ROWS));
    }
}
