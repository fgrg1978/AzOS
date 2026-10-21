// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for owner rule F1 in swap (`swap.rs`: no lock is held across the
//! device wait) and for the system watermark the reclaim task tests
//! (`budget::used_at_least`). The real `zpool.rs` and `swap.rs`; the kernel half
//! (`pager.rs`'s locks) needs the boot gate.
//!
//! Canaries (by hand, 2026-10-16; discriminate / do not / did not compile):
//! * `swap_out_one` holding the swap lock across `dev.write` (the old shape), or
//!   `swap_in` across `dev.read`: `no_lock_is_held_across_the_device_wait` red (the
//!   disk asserts both lock depths are zero).
//! * `swap_in` treating a failed tag as tamper without asking the pool
//!   (`in_current`): `a_slot_sealed_again_during_a_read_is_not_tamper` red.
//! * `Pool::swap_pick` answering `Gone` instead of `Busy` while a segment is leaving:
//!   `a_second_storm_during_a_write_is_told_busy` red (the storm reports `Stop::Io`).
//! * `used_at_least` comparing with `>` : `the_system_watermark_has_the_arithmetic_of_a_domains` red.
//! * Does not discriminate: `Locked::step_end` for the pool (a no-op there).

use super::budget::used_at_least;
use super::swap::{slots_for, swap_in, swap_out_storm, Locked, Policy, Stop, Swap, SwapDev, SwapError, SwapRecord, SECTOR};
use super::zpool::{Backing, Codec, Packed, Pool};
use azos_arch_api::PAGE_SIZE;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::{Cell, RefCell};
use std::ptr::NonNull;
use std::rc::Rc;

// ── the system watermark ─────────────────────────────────────────────────────

/// The system watermark: `pct` percent or more of the frames in use.
#[test]
fn the_system_watermark_has_the_arithmetic_of_a_domains() {
    assert!(!used_at_least(100, 0, 85), "no frames, no pressure");
    assert!(used_at_least(15, 100, 85), "85 of 100 in use");
    assert!(!used_at_least(16, 100, 85), "84 of 100");
    assert!(used_at_least(0, 100, 100));
    assert!(!used_at_least(1000, 100, 1), "more free than frames cannot underflow");
}

// ── owner rule F1 in swap ────────────────────────────────────────────────────

/// A segment is four frames.
const SEG: usize = 4 * PAGE_SIZE;
const SW: usize = 6;
type P = Pool<Heap, 256, 512, 4, 8, SEG, 0, SW, 8, 0>;
type S = Swap<'static, SW, SEG>;

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

/// A value behind a lock the rows can see: how many closures are inside it
/// now, and how many swap steps ended.
struct Gate<T> {
    v: RefCell<T>,
    depth: Rc<Cell<u32>>,
    steps: Cell<u32>,
}

impl<T> Gate<T> {
    fn new(v: T) -> Self {
        Gate { v: RefCell::new(v), depth: Rc::new(Cell::new(0)), steps: Cell::new(0) }
    }
}

impl<T> Locked<T> for Gate<T> {
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.depth.set(self.depth.get() + 1);
        let r = f(&mut self.v.borrow_mut());
        self.depth.set(self.depth.get() - 1);
        r
    }
    fn step_end(&self) {
        self.steps.set(self.steps.get() + 1);
    }
}

/// The swap partition. Every device call first asserts that neither lock is
/// held (the pool's, the swap state's), then runs the hook a row set: what
/// happens elsewhere during the device wait.
struct Disk {
    bytes: RefCell<Vec<u8>>,
    locks: RefCell<Vec<Rc<Cell<u32>>>>,
    waits: Cell<u32>,
    on_write: RefCell<Option<Box<dyn FnOnce()>>>,
    on_read: RefCell<Option<Box<dyn FnOnce()>>>,
    on_discard: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl Disk {
    fn new() -> Self {
        Disk {
            bytes: RefCell::new(vec![0; SW * SEG]),
            locks: RefCell::new(Vec::new()),
            waits: Cell::new(0),
            on_write: RefCell::new(None),
            on_read: RefCell::new(None),
            on_discard: RefCell::new(None),
        }
    }

    fn wait(&self, hook: &RefCell<Option<Box<dyn FnOnce()>>>) {
        for d in self.locks.borrow().iter() {
            assert_eq!(d.get(), 0, "a lock is held across the device wait (owner rule F1)");
        }
        self.waits.set(self.waits.get() + 1);
        let h = hook.borrow_mut().take();
        if let Some(h) = h {
            h();
        }
    }
}

impl SwapDev for Disk {
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), ()> {
        self.wait(&self.on_write);
        let at = sector as usize * SECTOR;
        self.bytes.borrow_mut()[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), ()> {
        self.wait(&self.on_read);
        let at = sector as usize * SECTOR;
        buf.copy_from_slice(&self.bytes.borrow()[at..at + buf.len()]);
        Ok(())
    }
    /// A TRIM'd flash block reads zeros afterwards: a discard that lands on a
    /// segment written since makes its tag fail.
    fn discard(&self, sector: u64, sectors: u32) -> Result<(), ()> {
        self.wait(&self.on_discard);
        let at = sector as usize * SECTOR;
        self.bytes.borrow_mut()[at..at + sectors as usize * SECTOR].fill(0);
        Ok(())
    }
}

thread_local! {
    static TAMPERED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    static RECORDS: RefCell<Vec<SwapRecord>> = const { RefCell::new(Vec::new()) };
}

fn pinned(_: usize) -> bool {
    false
}
fn record(r: &SwapRecord) {
    RECORDS.with(|v| v.borrow_mut().push(*r));
}
fn tamper(slot: usize) {
    TAMPERED.with(|v| v.borrow_mut().push(slot));
}
fn tampered() -> Vec<usize> {
    TAMPERED.with(|v| v.borrow().clone())
}

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

/// The pool and the swap state behind visible locks, over one disk whose
/// every call checks them. The disk is leaked: the hooks a row sets capture
/// the locks, and the locks hold the disk.
#[derive(Clone)]
struct Rig {
    pool: Rc<Gate<P>>,
    swap: Rc<Gate<S>>,
}

fn disk() -> &'static Disk {
    Box::leak(Box::new(Disk::new()))
}

impl Rig {
    fn new(disk: &'static Disk) -> Self {
        let mut pool = P::new(Heap);
        assert!(pool.swap_attach(slots_for((SW * SEG / SECTOR) as u64, SEG, SW)));
        let pool = Rc::new(Gate::new(pool));
        let swap = Rc::new(Gate::new(Swap::new(disk, Policy { pinned, record, tamper }, &SKEY)));
        disk.locks.borrow_mut().push(pool.depth.clone());
        disk.locks.borrow_mut().push(swap.depth.clone());
        Rig { pool, swap }
    }

    fn store(&self, owner: usize, obj: u64, pg: u64, seed: u32) {
        let mut scratch = vec![0u8; PAGE_SIZE];
        let Packed::Blob { len, nonce } = Codec::new(&KEY, 75).pack(&page(seed), &mut scratch).unwrap() else {
            panic!("test page did not compress")
        };
        self.pool.v.borrow_mut().insert_blob(owner, obj, pg, nonce, &scratch[..len]).unwrap();
    }

    fn segments(&self) -> usize {
        self.pool.v.borrow().stats().segments
    }

    /// Add one full segment of `(owner, obj)` pages: stored until one spills
    /// into a new segment, and that one removed again. The pages in it.
    fn fill_one_segment(&self, owner: usize, obj: u64, first_pg: u64) -> Vec<u64> {
        self.store(owner, obj, first_pg, first_pg as u32);
        let start = self.segments();
        let mut pgs = vec![first_pg];
        loop {
            let pg = first_pg + pgs.len() as u64;
            self.store(owner, obj, pg, pg as u32);
            if self.segments() > start {
                assert!(self.pool.v.borrow_mut().remove(obj, pg));
                return pgs;
            }
            pgs.push(pg);
        }
    }

    fn storm(&self, max: u32) -> Result<SwapRecord, SwapError> {
        swap_out_storm(&*self.pool, &*self.swap, &Heap, false, max, &|| false)
    }

    fn bring_in(&self, obj: u64, pg: u64) -> Result<(), SwapError> {
        let sw = self.pool.v.borrow().swapped(obj, pg).expect("the page is swapped");
        swap_in(&*self.pool, &*self.swap, &Heap, &sw)
    }
}

/// Owner rule F1: no lock, the pool's or the swap state's, is held while the
/// device works, in either direction, and every step ends by ringing.
#[test]
fn no_lock_is_held_across_the_device_wait() {
    let disk = disk();
    let rig = Rig::new(disk);
    let a = rig.fill_one_segment(1, 7, 0);
    assert_eq!(rig.storm(1).unwrap().segments, 1);
    assert_eq!(disk.waits.get(), 1, "one write, and the disk checked both locks before it");
    rig.bring_in(7, a[0]).unwrap();
    // One read, and with Kconfig `BLK_DISCARD` on the discard of the slot it
    // freed: each checked the same way.
    let discards = if azos_limits::BLK_DISCARD_OFF { 0 } else { 1 };
    assert_eq!(disk.waits.get(), 2 + discards, "one read and the slot's discard, checked the same way");
    assert_eq!(rig.swap.steps.get(), 2, "each step ended by ringing the waiters");
    assert_eq!(rig.pool.depth.get() + rig.swap.depth.get(), 0);
}

/// While a segment is out, a second storm is told `Busy`, writes nothing and
/// leaves no record (nothing was done); the first completes.
#[test]
fn a_second_storm_during_a_write_is_told_busy() {
    let disk = disk();
    let rig = Rig::new(disk);
    rig.fill_one_segment(1, 7, 0);
    rig.fill_one_segment(1, 8, 0);
    let inner = rig.clone();
    let seen = Rc::new(RefCell::new(None));
    let s2 = seen.clone();
    let records = RECORDS.with(|v| v.borrow().len());
    *disk.on_write.borrow_mut() = Some(Box::new(move || {
        *s2.borrow_mut() = Some(inner.storm(4));
    }));
    let rec = rig.storm(1).unwrap();
    assert_eq!((rec.segments, rec.stop), (1, Stop::Max));
    assert_eq!(*seen.borrow(), Some(Err(SwapError::Busy)), "the second storm walked in while a segment was leaving");
    assert_eq!(disk.waits.get(), 1, "and wrote nothing");
    assert_eq!(RECORDS.with(|v| v.borrow().len()), records + 1, "only the first storm left a record");
    // The pool is whole: the next storm takes the other segment.
    assert_eq!(rig.storm(1).unwrap().segments, 1);
}

/// While a segment is being read back, a restore of another is told `Busy`
/// (the fault waits for the step to end); after it, both come back.
#[test]
fn a_restore_during_a_read_is_told_busy() {
    let disk = disk();
    let rig = Rig::new(disk);
    let a = rig.fill_one_segment(1, 7, 0);
    let b = rig.fill_one_segment(1, 8, 0);
    assert_eq!(rig.storm(2).unwrap().segments, 2);
    let inner = rig.clone();
    let b0 = b[0];
    let seen = Rc::new(RefCell::new(None));
    let s2 = seen.clone();
    *disk.on_read.borrow_mut() = Some(Box::new(move || {
        *s2.borrow_mut() = Some(inner.bring_in(8, b0));
    }));
    rig.bring_in(7, a[0]).unwrap();
    assert_eq!(*seen.borrow(), Some(Err(SwapError::Busy)), "two segments were coming back at once");
    assert!(tampered().is_empty());
    rig.bring_in(8, b[0]).unwrap();
    assert!(rig.pool.v.borrow().swapped(7, a[0]).is_none() && rig.pool.v.borrow().swapped(8, b[0]).is_none());
}

/// A slot freed and sealed again while a reader reads it is not tamper: the
/// block fails the tag it started with, the pool no longer has that segment, so
/// nothing is attached and nothing is reported. The new segment restores right.
#[test]
fn a_slot_sealed_again_during_a_read_is_not_tamper() {
    let disk = disk();
    let rig = Rig::new(disk);
    let a = rig.fill_one_segment(1, 7, 0);
    assert_eq!(rig.storm(1).unwrap().segments, 1);
    let inner = rig.clone();
    let n = a.len();
    let fresh = Rc::new(RefCell::new(Vec::new()));
    let f2 = fresh.clone();
    *disk.on_read.borrow_mut() = Some(Box::new(move || {
        // Every page of the segment leaves, its slot is free, and a new segment
        // is sealed into it (the lowest free slot) before the read lands.
        assert_eq!(inner.pool.v.borrow_mut().remove_obj(7), n);
        *f2.borrow_mut() = inner.fill_one_segment(1, 9, 0);
        assert_eq!(inner.storm(1).unwrap().segments, 1);
    }));
    let before = rig.swap.v.borrow().stats();
    // The reader that started on the old segment finds it gone.
    let sw = rig.pool.v.borrow().swapped(7, a[0]).unwrap();
    assert_eq!(swap_in(&*rig.pool, &*rig.swap, &Heap, &sw), Ok(()), "a slot sealed again was taken for tamper");
    assert!(tampered().is_empty(), "the tamper hook fired for a segment that was freed: {:?}", tampered());
    let st = rig.swap.v.borrow().stats();
    assert_eq!((st.tampered, st.read), (before.tampered, before.read), "nothing was attached or counted");
    // The segment sealed meanwhile is intact.
    let pg = fresh.borrow()[0];
    rig.bring_in(9, pg).unwrap();
    assert!(rig.pool.v.borrow().fetch(9, pg, &mut vec![0u8; PAGE_SIZE]).is_some());
}

/// A block that really changed on the medium, with the segment still the
/// pool's, is tamper.
#[test]
fn a_changed_block_is_still_tamper() {
    let disk = disk();
    let rig = Rig::new(disk);
    let a = rig.fill_one_segment(1, 7, 0);
    assert_eq!(rig.storm(1).unwrap().segments, 1);
    disk.bytes.borrow_mut()[3] ^= 1;
    assert_eq!(rig.bring_in(7, a[0]), Err(SwapError::Tamper));
    assert_eq!(tampered().len(), 1);
    assert_eq!(rig.swap.v.borrow().stats().tampered, 1);
}
