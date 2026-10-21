// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the swap file (Kconfig `MM_SWAP_BACKEND_FILE`): the real
//! `swap.rs` over the real `zpool.rs`, with an area that changes size
//! (`SwapDev::resize`) in place of a partition. The area grows when a storm
//! finds no free slot, by whole segments and as far as the medium allows;
//! its free tail is given back after the idle passes; the map from the
//! file's sectors to the medium cuts a request along the runs.
//!
//! Not here: the kernel half (`kernel/src/boot/swap.rs`: the lock around the
//! map, the filesystem calls), and the filesystems' side of `swap_runs` and
//! `swap_resize` (`tests/host/fs-tests/src/swap_file.rs`).
//!
//! Canaries (discriminate / do not / did not compile):
//! * `swap_out_step` not asking `swap_grow` on `Full`: `a_storm_with_no_free_slot_grows_the_area` red.
//! * `swap_grow` not halving its step: `a_medium_with_less_room_gives_a_shorter_step_then_stops` red.
//! * `swap_in`'s room-making passing `grow = true`: `a_restore_never_grows_the_area` red.
//! * `swap_grow` raising the slot count before the medium has the sectors:
//!   `the_area_is_never_asked_for_a_slot_the_medium_lacks` red (the device asserts every request is inside it).
//! * `Pool::swap_set_cap` without its parked-slot test: `a_slot_with_a_parked_segment_is_not_cut_off` red
//!   (`swap_trim`'s own arithmetic keeps `a_parked_segment_in_the_tail_keeps_the_tail` green).
//! * `swap_trim` without its two `trimming` checks (both removed): `a_discard_still_on_a_tail_slot_keeps_the_tail` red. Either one
//!   alone keeps it green: the second (after the cut) covers a discard that starts between the first and the cut,
//!   a race one thread cannot make.
//! * `swap_trim` without the idle count: `the_tail_is_given_back_only_after_the_idle_passes` red.
//! * `RunMap::piece` not stopping at the end of a run: `a_request_is_cut_along_the_runs` red.
//! * Does not discriminate: the halving loop's last step (`add == 1`); the pool refuses a shrink below
//!   one slot first.

use super::swap::{
    slots_for, swap_grow, swap_in, swap_out_storm, swap_trim, Policy, Run, RunMap, Stop, Swap, SwapDev, SwapError,
    SwapRecord, GROW_SLOTS, SECTOR, SHRINK_POLLS,
};
use super::zpool::{Backing, Codec, Error, Packed, Pool};
use azos_arch_api::PAGE_SIZE;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::{Cell, RefCell};
use std::ptr::NonNull;
use std::rc::Rc;

const SEG: usize = 4 * PAGE_SIZE;
/// Three growth steps: room to grow twice and to shrink.
const SWF: usize = 3 * GROW_SLOTS;
const SEG_SECTORS: u64 = (SEG / SECTOR) as u64;

type PF = Pool<Heap, 1024, 2048, 4, 8, SEG, 0, SWF, 8, 0>;
/// Two resident segments, to run into the ceiling.
type PT = Pool<Heap, 1024, 2048, 2, 8, SEG, 0, SWF, 8, 0>;
type SF = Swap<'static, SWF, SEG>;

struct Heap;

impl Backing for Heap {
    fn alloc(&self, bytes: usize) -> Option<NonNull<u8>> {
        // SAFETY: a non-zero size.
        NonNull::new(unsafe { alloc(Layout::from_size_align(bytes, 4096).unwrap()) })
    }
    fn free(&self, p: NonNull<u8>, bytes: usize) {
        // SAFETY: `p` came from `alloc` above with this layout.
        unsafe { dealloc(p.as_ptr(), Layout::from_size_align(bytes, 4096).unwrap()) }
    }
}

/// A swap file: `limit` sectors of medium, `len` of them the area now; every
/// request asserts it lies inside the area.
struct Flex {
    bytes: RefCell<Vec<u8>>,
    len: Cell<u64>,
    limit: Cell<u64>,
    elastic: bool,
    /// The length of every resize taken, in sectors; and the refused ones.
    resizes: RefCell<Vec<u64>>,
    refused: Cell<u32>,
    writes: Cell<u32>,
    on_discard: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl Flex {
    fn new(elastic: bool, slots: usize, limit_slots: usize) -> &'static Flex {
        Box::leak(Box::new(Flex {
            bytes: RefCell::new(vec![0; SWF * SEG]),
            len: Cell::new(slots as u64 * SEG_SECTORS),
            limit: Cell::new(limit_slots as u64 * SEG_SECTORS),
            elastic,
            resizes: RefCell::new(Vec::new()),
            refused: Cell::new(0),
            writes: Cell::new(0),
            on_discard: RefCell::new(None),
        }))
    }

    fn check(&self, sector: u64, bytes: usize) {
        let end = sector + (bytes / SECTOR) as u64;
        assert!(end <= self.len.get(), "I/O to sector {end}, the area has {}", self.len.get());
    }
}

impl SwapDev for Flex {
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), ()> {
        self.check(sector, buf.len());
        self.writes.set(self.writes.get() + 1);
        let at = sector as usize * SECTOR;
        self.bytes.borrow_mut()[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), ()> {
        self.check(sector, buf.len());
        let at = sector as usize * SECTOR;
        buf.copy_from_slice(&self.bytes.borrow()[at..at + buf.len()]);
        Ok(())
    }
    fn discard(&self, sector: u64, sectors: u32) -> Result<(), ()> {
        self.check(sector, sectors as usize * SECTOR);
        let hook = self.on_discard.borrow_mut().take();
        if let Some(h) = hook {
            h();
        }
        let at = sector as usize * SECTOR;
        self.bytes.borrow_mut()[at..at + sectors as usize * SECTOR].fill(0);
        Ok(())
    }
    fn resizable(&self) -> bool {
        self.elastic
    }
    fn resize(&self, sectors: u64) -> Result<(), ()> {
        if sectors > self.limit.get() {
            self.refused.set(self.refused.get() + 1);
            return Err(());
        }
        self.resizes.borrow_mut().push(sectors);
        self.len.set(sectors);
        Ok(())
    }
}

fn pinned(_: usize) -> bool {
    false
}
fn record(_: &SwapRecord) {}
fn tamper(_: usize) {}

const KEY: [u8; 16] = *b"zpool test key 1";
const SKEY: [u8; 32] = *b"swap test boot key, 32 bytes....";

fn page(seed: u32) -> Vec<u8> {
    let mut p = vec![0u8; PAGE_SIZE];
    for (i, c) in p.chunks_exact_mut(4).enumerate() {
        let w: u32 = match i % 8 {
            0 => 0x4000_0000 + (i as u32 / 8 % 4) * 8 + seed * 0x1_0000,
            3 => (i as u32 / 8 % 3) + seed,
            _ => 0,
        };
        c.copy_from_slice(&w.to_le_bytes());
    }
    p
}

/// The pool, the swap state and the area, with the locks the swap loops want.
struct Rig<T> {
    pool: Rc<RefCell<T>>,
    swap: Rc<RefCell<SF>>,
    dev: &'static Flex,
}

macro_rules! rig_impl {
    ($t:ty) => {
        #[allow(dead_code)]
        impl Rig<$t> {
            /// An area of `slots` slots to start with, on a medium of `limit` slots.
            fn new(slots: usize, limit: usize) -> Self {
                let dev = Flex::new(true, slots, limit);
                Self::on(dev)
            }

            fn on(dev: &'static Flex) -> Self {
                let mut pool = <$t>::new(Heap);
                // The slots are the area's length: what the file holds now.
                assert!(pool.swap_attach(slots_for(dev.len.get(), SEG, SWF)));
                let swap = Swap::new(dev, Policy { pinned, record, tamper }, &SKEY);
                Rig { pool: Rc::new(RefCell::new(pool)), swap: Rc::new(RefCell::new(swap)), dev }
            }

            fn store(&self, obj: u64, pg: u64, seed: u32) {
                let p = page(seed);
                let mut scratch = vec![0u8; PAGE_SIZE];
                let codec = Codec::new(&KEY, 75);
                match codec.pack(&p, &mut scratch).unwrap() {
                    Packed::Blob { len, nonce } => {
                        self.pool.borrow_mut().insert_blob(1, obj, pg, nonce, &scratch[..len]).unwrap()
                    }
                    other => panic!("test page did not compress: {other:?}"),
                }
            }

            fn segments(&self) -> usize {
                self.pool.borrow().stats().segments
            }

            /// Add one full segment of `obj`'s pages: the first page is 0.
            fn fill_one_segment(&self, obj: u64) {
                self.store(obj, 0, 0);
                let start = self.segments();
                let mut n = 1u64;
                loop {
                    self.store(obj, n, n as u32);
                    if self.segments() > start {
                        assert!(self.pool.borrow_mut().remove(obj, n));
                        return;
                    }
                    n += 1;
                }
            }

            fn storm(&self, max: u32) -> Result<SwapRecord, SwapError> {
                swap_out_storm(&*self.pool, &*self.swap, &Heap, false, max, &|| false)
            }

            fn restore(&self, obj: u64) -> Result<(), SwapError> {
                let sw = self.pool.borrow().swapped(obj, 0).expect("the segment is on swap");
                swap_in(&*self.pool, &*self.swap, &Heap, &sw)
            }

            fn slots(&self) -> super::zpool::SwapSlots {
                self.pool.borrow().swap_slots()
            }

            fn trim(&self) -> Option<usize> {
                swap_trim(&*self.pool, &*self.swap)
            }

            /// Passes with nothing moving, up to the one before the area may shrink.
            fn idle(&self) {
                for _ in 1..SHRINK_POLLS {
                    assert_eq!(self.trim(), None);
                }
            }
        }
    };
}
rig_impl!(PF);
rig_impl!(PT);

// ── the map from the file to the medium ──────────────────────────────────────

fn run(lba: u64, sectors: u32) -> Run {
    Run { lba, sectors }
}

#[test]
fn a_request_is_cut_along_the_runs() {
    let mut m = RunMap::<4>::new();
    assert!(m.set_iter([run(1000, 8), run(5000, 4), run(200, 16)].into_iter()));
    assert_eq!(m.sectors(), 28);
    // Inside the first run, a request that would cross: cut at the end of the run.
    assert_eq!(m.piece(0, 100), Some(run(1000, 8)));
    assert_eq!(m.piece(6, 5), Some(run(1006, 2)));
    // Starting on a boundary.
    assert_eq!(m.piece(8, 4), Some(run(5000, 4)));
    assert_eq!(m.piece(12, 100), Some(run(200, 16)));
    // Short of the end of the run: the request's own length.
    assert_eq!(m.piece(13, 3), Some(run(201, 3)));
    // Past the map.
    assert_eq!(m.piece(28, 1), None);
    // Walking a segment-sized request piece by piece covers it once, in order.
    let (mut at, mut seen) = (3u64, Vec::new());
    while at < 25 {
        let p = m.piece(at, (25 - at) as u32).unwrap();
        seen.push(p);
        at += p.sectors as u64;
    }
    assert_eq!(seen, [run(1003, 5), run(5000, 4), run(200, 13)]);
}

#[test]
fn a_map_that_does_not_fit_or_has_an_empty_run_keeps_what_it_had() {
    let mut m = RunMap::<2>::new();
    assert!(m.set_iter([run(10, 4)].into_iter()));
    assert!(!m.set_iter([run(1, 1), run(2, 1), run(3, 1)].into_iter()), "three runs in a map of two");
    assert!(!m.set_iter([run(1, 1), run(2, 0)].into_iter()), "an empty run");
    assert_eq!(m.sectors(), 4);
    assert_eq!(m.piece(0, 4), Some(run(10, 4)));
    // A shorter file replaces it whole.
    assert!(m.set_iter([run(30, 2)].into_iter()));
    assert_eq!(m.sectors(), 2);
    assert_eq!(m.piece(2, 1), None);
}

// ── growing ──────────────────────────────────────────────────────────────────

#[test]
fn a_storm_with_no_free_slot_grows_the_area() {
    let rig = Rig::<PF>::new(1, SWF);
    rig.fill_one_segment(10);
    rig.fill_one_segment(11);
    let rec = rig.storm(2).unwrap();
    assert_eq!(rec.segments, 2, "{rec:?}");
    let want = (1 + GROW_SLOTS).min(SWF);
    assert_eq!(rig.slots().cap, want, "one step, whole segments");
    assert_eq!(rig.dev.resizes.borrow().as_slice(), &[want as u64 * SEG_SECTORS], "the medium grew once, to match");
    assert_eq!(rig.swap.borrow().stats().grown, 1);
    // What was written to the grown part comes back.
    rig.restore(11).unwrap();
    rig.restore(10).unwrap();
}

#[test]
fn the_area_is_never_asked_for_a_slot_the_medium_lacks() {
    // The device asserts every request lies inside the area it was resized to;
    // slot 1 is only written because the medium grew first.
    let rig = Rig::<PF>::new(1, SWF);
    rig.fill_one_segment(10);
    rig.fill_one_segment(11);
    rig.storm(2).unwrap();
    assert!(rig.dev.len.get() >= 2 * SEG_SECTORS);
    assert_eq!(rig.dev.writes.get(), 2);
}

#[test]
fn a_medium_with_less_room_gives_a_shorter_step_then_stops() {
    // Room for three slots: a step of GROW_SLOTS is refused, halved until it fits.
    let rig = Rig::<PF>::new(1, 3);
    for obj in 10..13 {
        rig.fill_one_segment(obj);
    }
    let rec = rig.storm(3).unwrap();
    assert_eq!(rec.segments, 3, "{rec:?}");
    assert_eq!(rig.slots().cap, 3);
    assert_eq!(rig.dev.len.get(), 3 * SEG_SECTORS);
    // A fourth: no slot, and the medium has no room for one more.
    rig.fill_one_segment(13);
    let refused = rig.dev.refused.get();
    let rec = rig.storm(1).unwrap();
    assert_eq!((rec.segments, rec.stop), (0, Stop::AreaFull));
    assert!(rig.dev.refused.get() > refused, "the medium was asked and said no");
    assert_eq!(rig.slots().cap, 3, "the slots did not move");
    // And space that comes back is used on the next storm.
    rig.dev.limit.set(SWF as u64 * SEG_SECTORS);
    let rec = rig.storm(1).unwrap();
    assert_eq!(rec.segments, 1, "{rec:?}");
}

#[test]
fn a_partition_does_not_grow() {
    let dev = Flex::new(false, 1, SWF);
    let rig = Rig::<PF>::on(dev);
    rig.fill_one_segment(10);
    rig.fill_one_segment(11);
    let rec = rig.storm(2).unwrap();
    assert_eq!((rec.segments, rec.stop), (1, Stop::AreaFull));
    assert!(dev.resizes.borrow().is_empty());
    assert_eq!(swap_grow::<PF, _, _, SWF, SEG>(&*rig.pool, &*rig.swap), Err(SwapError::Pool(Error::Full)));
    assert_eq!(rig.trim(), None);
}

#[test]
fn a_restore_never_grows_the_area() {
    // The medium can give more, but the restore that meets the ceiling is
    // not the place to ask the filesystem for it (it may hold its locks).
    let dev = Flex::new(true, 1, 1);
    let rig = Rig::<PT>::on(dev);
    rig.fill_one_segment(10);
    rig.storm(1).unwrap();
    assert_eq!(rig.slots().free, 0, "one slot, used; the medium had no room to grow after it");
    // Two resident segments fill the ceiling.
    rig.fill_one_segment(11);
    rig.store(12, 0, 12);
    assert_eq!(rig.segments(), 2);
    dev.limit.set(SWF as u64 * SEG_SECTORS);
    assert_eq!(rig.restore(10), Err(SwapError::Pool(Error::Full)), "no slot to write the segment in the way to");
    assert!(dev.resizes.borrow().is_empty(), "and nothing was asked of the medium");
    // The storm does grow it, and then the restore finds its room.
    let rec = rig.storm(1).unwrap();
    assert_eq!(rec.segments, 1, "{rec:?}");
    assert!(rig.slots().cap > 1);
    rig.restore(10).unwrap();
}

#[test]
fn a_storm_leaves_a_free_slot_for_the_restore_that_needs_one() {
    let rig = Rig::<PF>::new(1, SWF);
    rig.fill_one_segment(10);
    let rec = rig.storm(1).unwrap();
    assert_eq!(rec.segments, 1);
    assert!(rig.slots().free >= 1, "the slot just filled was the last: the area grew after the write");
}

// ── shrinking ────────────────────────────────────────────────────────────────

/// `GROW_SLOTS + 1` segments swapped out, in slots `0..=GROW_SLOTS`: the area
/// has grown to two steps. The object of the segment in slot `i` is `100 + i`.
fn grown_area() -> Rig<PF> {
    let rig = Rig::<PF>::new(GROW_SLOTS, SWF);
    for i in 0..=GROW_SLOTS as u64 {
        rig.fill_one_segment(100 + i);
        assert_eq!(rig.storm(1).unwrap().segments, 1);
    }
    assert_eq!(rig.slots().cap, 2 * GROW_SLOTS);
    assert_eq!(rig.slots().top, GROW_SLOTS + 1);
    rig
}

#[test]
fn a_parked_segment_in_the_tail_keeps_the_tail() {
    let rig = grown_area();
    // Everything but the segment in slot GROW_SLOTS comes back (its pages leave).
    for i in 0..GROW_SLOTS as u64 {
        assert!(rig.pool.borrow_mut().remove_obj(100 + i) > 0);
    }
    assert_eq!(rig.slots().top, GROW_SLOTS + 1);
    rig.idle();
    assert_eq!(rig.trim(), None, "the highest parked slot is in the second step");
    assert_eq!(rig.slots().cap, 2 * GROW_SLOTS);
    assert_eq!(rig.dev.len.get(), 2 * GROW_SLOTS as u64 * SEG_SECTORS);
    // It is still readable after the refused shrink.
    rig.restore(100 + GROW_SLOTS as u64).unwrap();
}

#[test]
fn the_tail_is_given_back_only_after_the_idle_passes() {
    let rig = grown_area();
    for i in 0..=GROW_SLOTS as u64 {
        assert!(rig.pool.borrow_mut().remove_obj(100 + i) > 0);
    }
    assert_eq!(rig.slots().top, 0);
    rig.idle();
    assert_eq!(rig.dev.len.get(), 2 * GROW_SLOTS as u64 * SEG_SECTORS, "not yet");
    // The pass that makes it SHRINK_POLLS in a row.
    assert_eq!(rig.trim(), Some(GROW_SLOTS), "down to one step, not to nothing");
    assert_eq!(rig.slots().cap, GROW_SLOTS);
    assert_eq!(rig.dev.len.get(), GROW_SLOTS as u64 * SEG_SECTORS);
    assert_eq!(rig.swap.borrow().stats().shrunk, 1);
    // One step is the least it keeps.
    assert_eq!(rig.trim(), None);
    // And a storm uses the shorter area as before (and grows it again when it must).
    for i in 0..=GROW_SLOTS as u64 {
        rig.fill_one_segment(200 + i);
        assert_eq!(rig.storm(1).unwrap().segments, 1);
    }
    assert_eq!(rig.slots().cap, 2 * GROW_SLOTS);
}

#[test]
fn traffic_restarts_the_idle_count() {
    let rig = grown_area();
    for i in 0..GROW_SLOTS as u64 {
        assert!(rig.pool.borrow_mut().remove_obj(100 + i) > 0);
    }
    rig.idle();
    // A restore of the segment in the tail is traffic (and empties the tail).
    rig.restore(100 + GROW_SLOTS as u64).unwrap();
    assert!(rig.pool.borrow_mut().remove_obj(100 + GROW_SLOTS as u64) > 0);
    rig.idle();
    assert_eq!(rig.trim(), Some(GROW_SLOTS));
}

#[test]
fn a_discard_still_on_a_tail_slot_keeps_the_tail() {
    let rig = grown_area();
    for i in 0..GROW_SLOTS as u64 {
        assert!(rig.pool.borrow_mut().remove_obj(100 + i) > 0);
    }
    // During the discard of the tail slot the restore freed, the area may not
    // be cut: the medium would be told about sectors the filesystem has taken back.
    let (pool, swap) = (rig.pool.clone(), rig.swap.clone());
    let answers = Rc::new(RefCell::new(Vec::new()));
    let a = answers.clone();
    *rig.dev.on_discard.borrow_mut() = Some(Box::new(move || {
        for _ in 0..SHRINK_POLLS {
            a.borrow_mut().push(swap_trim(&*pool, &*swap));
        }
    }));
    rig.restore(100 + GROW_SLOTS as u64).unwrap();
    assert_eq!(rig.slots().top, 0, "its pages are in the pool again: the slot is free");
    assert_eq!(answers.borrow().len(), SHRINK_POLLS as usize, "the discard ran");
    assert!(answers.borrow().iter().all(|r| r.is_none()), "{:?}", answers.borrow());
    assert_eq!(rig.dev.len.get(), 2 * GROW_SLOTS as u64 * SEG_SECTORS);
    // The discard is over: the tail goes.
    assert_eq!(rig.trim(), Some(GROW_SLOTS));
}

#[test]
fn a_slot_with_a_parked_segment_is_not_cut_off() {
    // The books refuse on their own, whatever the caller computed.
    let rig = grown_area();
    assert!(!rig.pool.borrow_mut().swap_set_cap(GROW_SLOTS), "a segment is parked in slot {GROW_SLOTS}");
    assert!(rig.pool.borrow_mut().swap_set_cap(GROW_SLOTS + 1), "down to just past it is fine");
    assert_eq!(rig.slots().cap, GROW_SLOTS + 1);
    assert!(rig.pool.borrow_mut().swap_set_cap(SWF + 5), "a grow past the table is clamped to it");
    assert_eq!(rig.slots().cap, SWF);
    rig.restore(100 + GROW_SLOTS as u64).unwrap();
}

#[test]
fn a_segment_leaving_keeps_the_area_as_it_is() {
    // The pool refuses a shrink while a segment is between its pick and its commit.
    let rig = grown_area();
    for i in 0..=GROW_SLOTS as u64 {
        assert!(rig.pool.borrow_mut().remove_obj(100 + i) > 0);
    }
    rig.fill_one_segment(300);
    let pick = rig.pool.borrow_mut().swap_pick(&|_| false).unwrap();
    assert!(!rig.pool.borrow_mut().swap_set_cap(GROW_SLOTS), "a segment is leaving");
    rig.pool.borrow_mut().swap_abort(&pick);
    assert!(rig.pool.borrow_mut().swap_set_cap(GROW_SLOTS));
    assert!(!rig.pool.borrow_mut().swap_set_cap(0), "never none");
}
