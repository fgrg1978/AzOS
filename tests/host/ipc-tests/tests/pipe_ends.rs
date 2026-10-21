// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's half of the POSIX pipe (`memobj.rs`, "The ends of a POSIX pipe
//! region"): who holds which end of a pipe region, kept per holding task, and
//! the counts and wakes that follow from it.
//!
//! A pipe is a byte ring in a `Cap<Shm>` region (`azos_bytepipe`); the kernel
//! alone writes its two end counts, so these tests drive the same functions
//! the syscalls and the task-exit hook run (`memobj_pipe_hold` for a spawn's
//! move list, `memobj_pipe_inherit` for a fork, `memobj_pipe_drop` for
//! `MEMOBJ_END_DROP`, `memobj_release_all` for a death) and read the counts,
//! the lock words and the futex wakes they leave on the region's first page.
//!
//! **A binary of its own**: real regions take pages from
//! `shims/mm`, and the futex wakes are read from `shims/sched`.
//!
//! **Canaries (by hand).** In `pipe_drop_all`, skip the `drop_bits_locked`
//! call: `a_death_gives_up_every_end_the_task_held` and its siblings fail on
//! the counts. In `Header::recover_locks` (azos_bytepipe) compare the owner
//! with `owner + 1`: `a_death_opens_the_lock_it_owned` fails.

use azos_bytepipe::{BytePipe, Header};
use azos_ipc_tests::cap::{objref, CapPerms};
use azos_ipc_tests::cap_store;
use azos_ipc_tests::memobj::{
    memobj_acquire_ref, memobj_create_cap, memobj_move, memobj_page_phys_ref, memobj_pipe_drop,
    memobj_pipe_drop_all_ref, memobj_pipe_hold, memobj_pipe_inherit, memobj_release_all, memobj_frames_pin,
    memobj_frames_unpin, MemObjError, MemPerms, MemSpec, PIPE_END_READ, PIPE_END_WRITE,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

const A: u32 = 31;
const B: u32 = 32;
const C: u32 = 33;

// Header offsets of `azos_bytepipe`'s words (its private constants): a test
// that reads a count or a wake by offset states them once here.
const WRITERS: usize = 12;
const READERS: usize = 16;
const RD_EVENT: u32 = 20;
const WR_EVENT: u32 = 24;
const WLOCK: usize = 32;
const RLOCK: usize = 36;

fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    azos_sched::shim_reset();
    azos_mm::shim_reset();
    for t in [A, B, C] {
        memobj_release_all(t);
        cap_store::reset(t);
    }
    azos_sched::shim_take_futex_wakes();
    g
}

/// A region `A` created, started as a pipe, and its packed reference.
struct Pipe {
    r: u32,
    base: usize,
}

impl Pipe {
    /// A region of `pages` pages that is a pipe: `BytePipe::init` ran on it
    /// (one reader, one writer: `A`'s).
    fn new() -> Pipe {
        let p = Pipe::bare();
        // SAFETY: the first page of a live region, page aligned; `init` writes
        // the header only, which lies in that page.
        unsafe { BytePipe::init(p.base, 4096) }.expect("a pipe header");
        p
    }

    /// A region that is no pipe (nothing written to it).
    fn bare() -> Pipe {
        let cap = memobj_create_cap(A, 5, &MemSpec::anon(MemPerms::ReadWrite)).expect("a region");
        let r = cap_store::get(A, cap, CapPerms::READ).expect("the creator holds it");
        let base = memobj_page_phys_ref(r, 0).unwrap().expect("a first page");
        Pipe { r, base }
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        // SAFETY: a word of the live first page.
        unsafe { &*((self.base + off) as *const AtomicU32) }
    }
    fn readers(&self) -> u32 {
        self.word(READERS).load(Ordering::SeqCst)
    }
    fn writers(&self) -> u32 {
        self.word(WRITERS).load(Ordering::SeqCst)
    }
    fn counts(&self) -> (u32, u32) {
        (self.readers(), self.writers())
    }
    /// `tid` takes a reference on the region, as a spawn's child or a fork's.
    fn give(&self, tid: u32) {
        memobj_acquire_ref(tid, self.r).expect("a reference for the receiver");
    }
}

fn wakes() -> Vec<(u32, u32)> {
    azos_sched::shim_take_futex_wakes()
}

#[test]
fn the_creator_starts_holding_both_ends_and_its_death_gives_them_up() {
    let _g = serial();
    let p = Pipe::new();
    assert_eq!(p.counts(), (1, 1));
    memobj_release_all(A);
    assert_eq!(p.counts(), (0, 0), "a creator that dies without closing leaves no end counted");
    let w = wakes();
    assert!(w.contains(&(p.r, RD_EVENT)), "the readers are woken to see end of file: {w:?}");
    assert!(w.contains(&(p.r, WR_EVENT)), "the writers are woken to see EPIPE: {w:?}");
}

#[test]
fn a_death_gives_up_every_end_the_task_held() {
    let _g = serial();
    let p = Pipe::new();
    // B is the stage that reads (fd 0), C the one that writes (fd 1).
    p.give(B);
    p.give(C);
    memobj_pipe_hold(B, p.r, PIPE_END_READ).unwrap();
    memobj_pipe_hold(C, p.r, PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (2, 2));
    wakes();
    // C is killed: the writer count drops to the creator's one; not the last.
    memobj_release_all(C);
    assert_eq!(p.counts(), (2, 1));
    assert!(wakes().is_empty(), "not the last writer: nobody is told");
    // The creator closes its write end the ordinary way; C is gone, so that
    // was the last writer: the reader stage sees end of file.
    memobj_pipe_drop(A, p.r, PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (2, 0));
    assert_eq!(wakes(), vec![(p.r, RD_EVENT)]);
    // B is killed too, and A gives up its read end by dying: the last reader.
    memobj_release_all(B);
    assert_eq!(p.counts(), (1, 0));
    memobj_release_all(A);
    assert_eq!(p.counts(), (0, 0));
    assert!(wakes().contains(&(p.r, WR_EVENT)), "the last reader's death tells the writers");
}

#[test]
fn a_hold_counts_only_the_ends_the_task_did_not_hold() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    // `> f 2>&1`: one region at fd 1 and fd 2 is one write end, asked twice.
    memobj_pipe_hold(B, p.r, PIPE_END_WRITE).unwrap();
    memobj_pipe_hold(B, p.r, PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (1, 2));
    memobj_pipe_hold(B, p.r, PIPE_END_READ | PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (2, 2), "only the read end was new");
    memobj_release_all(B);
    assert_eq!(p.counts(), (1, 1), "and the death gives each back once");
}

#[test]
fn a_fork_child_holds_what_its_parent_holds() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    // The parent keeps only its read end.
    memobj_pipe_drop(A, p.r, PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (1, 0));
    wakes();
    memobj_pipe_inherit(A, B, p.r).unwrap();
    assert_eq!(p.counts(), (2, 0), "the child inherited the read end and no write end");
    memobj_release_all(B);
    assert_eq!(p.counts(), (1, 0));
    assert!(wakes().is_empty());
}

#[test]
fn a_hold_or_inherit_without_a_reference_is_refused_and_counts_nothing() {
    let _g = serial();
    let p = Pipe::new();
    assert_eq!(memobj_pipe_hold(B, p.r, PIPE_END_READ), Err(MemObjError::Closed));
    assert_eq!(memobj_pipe_inherit(A, B, p.r), Err(MemObjError::Closed));
    assert_eq!(p.counts(), (1, 1));
}

#[test]
fn a_count_with_no_room_refuses_the_hand_over_whole() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    p.word(WRITERS).store(u32::MAX, Ordering::SeqCst);
    assert_eq!(memobj_pipe_hold(B, p.r, PIPE_END_READ | PIPE_END_WRITE), Err(MemObjError::Full));
    assert_eq!(p.counts(), (1, u32::MAX), "the read end counted before the refusal was given back");
    // And B holds nothing: its death changes nothing.
    memobj_release_all(B);
    assert_eq!(p.counts(), (1, u32::MAX));
}

#[test]
fn an_end_drop_names_ends_the_task_holds() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    assert_eq!(memobj_pipe_drop(B, p.r, PIPE_END_READ), Err(MemObjError::BadArg), "B holds nothing yet");
    assert_eq!(memobj_pipe_drop(A, p.r, 0), Err(MemObjError::BadArg), "no end named");
    assert_eq!(memobj_pipe_drop(A, p.r, 4), Err(MemObjError::BadArg), "no such end");
    assert_eq!(memobj_pipe_drop(A, p.r, PIPE_END_READ), Ok(()));
    assert_eq!(memobj_pipe_drop(A, p.r, PIPE_END_READ), Err(MemObjError::BadArg), "an end is given up once");
    assert_eq!(memobj_pipe_drop(C, p.r, PIPE_END_READ), Err(MemObjError::Closed), "C holds no reference");
    assert_eq!(p.counts(), (0, 1));
}

#[test]
fn a_death_opens_the_lock_it_owned() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    p.give(C);
    memobj_pipe_hold(B, p.r, PIPE_END_WRITE).unwrap();
    memobj_pipe_hold(C, p.r, PIPE_END_READ).unwrap();
    // B died inside the writer lock, C holds the reader lock and lives.
    p.word(WLOCK).store((B << 2) | 1, Ordering::SeqCst);
    p.word(RLOCK).store((C << 2) | 1, Ordering::SeqCst);
    wakes();
    memobj_release_all(B);
    assert_eq!(p.word(WLOCK).load(Ordering::SeqCst), 0, "the dead owner's lock is open");
    assert_eq!(p.word(RLOCK).load(Ordering::SeqCst), (C << 2) | 1, "a live owner's lock is not touched");
    assert!(wakes().contains(&(p.r, WLOCK as u32)), "and its sleepers are woken");
}

#[test]
fn a_lock_is_opened_even_when_the_task_had_already_given_its_ends_up() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    memobj_pipe_hold(B, p.r, PIPE_END_WRITE).unwrap();
    // B closed its write end while a thread of it was still inside a write.
    memobj_pipe_drop(B, p.r, PIPE_END_WRITE).unwrap();
    p.word(WLOCK).store((B << 2) | 1, Ordering::SeqCst);
    wakes();
    memobj_release_all(B);
    assert_eq!(p.word(WLOCK).load(Ordering::SeqCst), 0);
    assert!(wakes().contains(&(p.r, WLOCK as u32)));
}

#[test]
fn a_release_of_the_region_gives_up_what_the_task_still_held() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    memobj_pipe_hold(B, p.r, PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (1, 2));
    // The typed release (`SYS_MO_UNMAP`) and the undo of a refused hand-over
    // let go of the region: the ends go first.
    memobj_pipe_drop_all_ref(B, p.r);
    assert_eq!(p.counts(), (1, 1));
    memobj_pipe_drop_all_ref(B, p.r);
    assert_eq!(p.counts(), (1, 1), "and a second time gives nothing more");
}

#[test]
fn a_region_that_is_no_pipe_is_left_alone() {
    let _g = serial();
    let p = Pipe::bare();
    p.word(WRITERS).store(5, Ordering::SeqCst);
    p.word(READERS).store(6, Ordering::SeqCst);
    p.give(B);
    assert_eq!(memobj_pipe_hold(B, p.r, PIPE_END_WRITE), Ok(()));
    memobj_release_all(B);
    memobj_release_all(A);
    assert_eq!(p.counts(), (6, 5), "no magic word: the data of the region is its owner's");
    assert!(wakes().is_empty());
}

#[test]
fn a_moved_reference_carries_its_ends() {
    let _g = serial();
    let p = Pipe::new();
    p.give(B);
    memobj_pipe_hold(B, p.r, PIPE_END_WRITE).unwrap();
    assert_eq!(p.counts(), (1, 2));
    // A's references move to B: B held a write end already, A's read and write
    // ends become B's. A was one holder of the write end and so is B: counted
    // once now.
    let m = memobj_move(A, B, p.r).expect("a move");
    assert!(m.transferred);
    assert_eq!(p.counts(), (1, 1), "two write holders became one");
    memobj_release_all(A);
    assert_eq!(p.counts(), (1, 1), "A holds nothing any more");
    memobj_release_all(B);
    assert_eq!(p.counts(), (0, 0));
}

#[test]
fn a_region_is_a_pipe_for_the_header_view_only_with_its_magic() {
    let _g = serial();
    let p = Pipe::bare();
    // SAFETY: the first page of a live region.
    assert!(unsafe { Header::at(p.base) }.is_none());
    let q = Pipe::new();
    // SAFETY: as above.
    assert!(unsafe { Header::at(q.base) }.is_some());
    let _ = objref::SHM;
}

/// The kernel's own calls on a pipe (`azos_ipc::kpipe`) reach the region one
/// frame at a time, whatever the frames are (a ring-3 region is one per
/// page); the kernel's reference keeps them when every holder has let go
/// during a call.
///
/// **Canary.** Make `memobj_frames_unpin` a no-op: the frames are never freed
/// and the last assertion fails.
#[test]
fn the_pin_lists_every_frame_and_keeps_them() {
    let _g = serial();
    let pages = 5;
    let cap = memobj_create_cap(A, pages, &MemSpec::anon(MemPerms::ReadWrite)).expect("a region");
    let r = cap_store::get(A, cap, CapPerms::RW).unwrap();
    let mut out = [0usize; 16];
    let n = memobj_frames_pin(r, &mut out).expect("a read-write region");
    assert_eq!(n, pages);
    for (k, &va) in out[..n].iter().enumerate() {
        assert_eq!(Some(va), memobj_page_phys_ref(r, k).unwrap(), "page {k}'s direct-map address");
    }
    // (`serial` frees what the test before left, after the shim's reset, so
    // a page may already count one free: compare against the count now.)
    let first = out[0];
    let freed = azos_mm::shim_free_count(first);
    // The only holder lets go in the middle of a call: the frames stay.
    memobj_release_all(A);
    assert_eq!(azos_mm::shim_free_count(first), freed, "the pin keeps the frames");
    memobj_frames_unpin(r);
    assert_eq!(azos_mm::shim_free_count(first), freed + 1, "the last reference frees them");
}

/// The kernel writes the ring (head, tail, end counts, data), so it views only
/// a region a ring-3 task could write through its mapping, and takes no
/// reference of a region it refuses. A read-only region, and the capability a
/// read-only region mints (the kernel's callers ask `READ | WRITE`), are
/// refused; so is a region longer than the caller's frame list.
///
/// **Canary.** Drop the `perms` test in `memobj_frames_pin`: the read-only
/// region is viewed and the first assertion fails.
#[test]
fn a_region_the_task_could_not_write_is_no_pipe_view() {
    let _g = serial();
    let ro = memobj_create_cap(A, 5, &MemSpec::anon(MemPerms::ReadOnly)).expect("a read-only region");
    assert!(cap_store::get(A, ro, CapPerms::RW).is_err(), "its capability has no WRITE right");
    let r = cap_store::get(A, ro, CapPerms::READ).unwrap();
    let first = memobj_page_phys_ref(r, 0).unwrap().unwrap();
    let mut out = [0usize; 16];
    assert_eq!(memobj_frames_pin(r, &mut out), Err(MemObjError::BadArg), "a read-only region");
    let rw = memobj_create_cap(A, 5, &MemSpec::anon(MemPerms::ReadWrite)).expect("a region");
    let r = cap_store::get(A, rw, CapPerms::RW).unwrap();
    assert_eq!(memobj_frames_pin(r, &mut out[..4]), Err(MemObjError::BadArg), "five pages, room for four");
    let freed = azos_mm::shim_free_count(first);
    memobj_release_all(A);
    assert_eq!(azos_mm::shim_free_count(first), freed + 1, "a refused pin took no reference");
}
