// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for swap after compression (Kconfig `MM_SWAP_BACKEND`): the real
//! `crates/core/mm/src/swap.rs` over the real `zpool.rs`, with a byte map for
//! a swap partition, and the swap partition type of the block crate's
//! `partition.rs`. Evict and restore, the Domain's swap quota, a tampered,
//! moved or replayed block, pinned memory, a real-time hart, the record per
//! storm, a write that fails, and the books when pages leave, or other stores
//! and a compaction run, while a segment is out of the lock (the disk's write
//! runs a hook, with the pool's `RefCell` free: a swap step that held the pool
//! across the device would panic on the hook's borrow).
//!
//! Not here: the kernel half (`pager.rs`'s restore arm and statics,
//! `kernel/src/boot/swap.rs`'s block-queue device and decision record), which
//! needs the boot gate.
//!
//! Canaries (discriminate / do not / did not compile):
//! * feature `swap-pinned-canary` (the storm asks `Pool::swap_pick` as if no Domain
//!   were pinned): `swap_out_storm_refuses_pinned_memory_and_records_it` red.
//!   (`a_pinned_domains_segment_is_never_written` calls the pool directly, so it
//!   stays green: it pins the pool's own test, the storm row pins the wiring.)
//! * feature `swap-verify-canary` (`Swap::open` attaches without the tag):
//!   `a_changed_block_is_refused_and_nothing_is_attached`,
//!   `a_block_moved_to_another_slot_is_refused` and `a_replayed_block_is_refused` red.
//! * `seal` skipping `ctr_encrypt`: `the_medium_never_holds_the_staged_image` red.
//! * Does not discriminate: `tag_of` leaving the slot out of the HMAC input. A block
//!   moved to another slot already fails against that slot's own record (the tag is
//!   over the ciphertext as well); the slot in the input is depth, not a test.
//! * `swap_out_storm` without the `rt_hart` test: `a_real_time_hart_never_swaps` red.
//! * `swap_commit` not moving the charge: `a_full_segment_is_written_whole_and_every_page_comes_back` red.
//! * `swap_pick` without the `leaving` mark, or `compact` ignoring it:
//!   `stores_and_a_compaction_during_the_write_do_not_move_the_segment` red.
//! * `release_blob` not freeing a parked slot at `live == 0`:
//!   `pages_that_leave_a_swapped_segment_free_its_slot` red.
//! * `swap_out_one` not aborting after a failed write: `a_failed_write_leaves_the_segment_where_it_was` red.
//! * `swap_in` not writing a segment out first at the ceiling:
//!   `a_restore_at_the_ceiling_writes_another_segment_out` red.
//! * `swap_commit` parking a segment whose pages all left: `pages_that_leave_during_the_write_park_nothing` red.
//! * `swap_out_one` taking a `Gone` stage for an error (`Stop::Io`), or not aborting the pick:
//!   `a_segment_gone_at_the_copy_is_skipped_not_an_io_error` red.
//! * `swap_out_storm` skipping `abort` after a failure: `a_failed_write_leaves_the_segment_where_it_was` red.

use super::partition as part;
use super::swap::{
    slots_for, swap_in, swap_out_storm, Locked, Parkable, Policy, Stop, Swap, SwapDev, SwapError, SwapRecord, SECTOR,
};
use super::zpool::{fill_page, Backing, Codec, Error, Fetched, Packed, Pool, SwapPick, SwapSlots, Swapped};
use azos_arch_api::PAGE_SIZE;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::{Cell, RefCell};
use std::ptr::NonNull;
use std::rc::Rc;

/// Segments (and the staging segment) from the heap, counting those outstanding.
#[derive(Clone)]
struct Heap {
    out: Rc<Cell<isize>>,
}

impl Heap {
    fn new() -> Self {
        Heap { out: Rc::new(Cell::new(0)) }
    }
}

impl Backing for Heap {
    fn alloc(&self, bytes: usize) -> Option<NonNull<u8>> {
        self.out.set(self.out.get() + 1);
        // SAFETY: a non-zero size.
        NonNull::new(unsafe { alloc(Layout::from_size_align(bytes, 4096).unwrap()) })
    }
    fn free(&self, p: NonNull<u8>, bytes: usize) {
        self.out.set(self.out.get() - 1);
        // SAFETY: `p` came from `alloc` above with this layout.
        unsafe { dealloc(p.as_ptr(), Layout::from_size_align(bytes, 4096).unwrap()) }
    }
}

/// A segment is four frames: about twenty of the test pages.
const SEG: usize = 4 * PAGE_SIZE;
const SW: usize = 6;
/// 256 pages, 4 resident segments, 8 Domains; 6 swap slots, 8 swap Domains, no default quotas.
type P = Pool<Heap, 256, 512, 4, 8, SEG, 0, SW, 8, 0>;
/// Two resident segments only, to make a restore run into the ceiling.
type Tight = Pool<Heap, 256, 512, 2, 8, SEG, 0, SW, 8, 0>;
type S<'d> = Swap<'d, SW, SEG>;

impl<T> Locked<T> for RefCell<T> {
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.borrow_mut())
    }
}

impl<T> Locked<T> for Rc<RefCell<T>> {
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.borrow_mut())
    }
}

/// The swap partition: a byte map, with the counters and the faults a row sets.
struct Disk {
    bytes: RefCell<Vec<u8>>,
    writes: Cell<u32>,
    reads: Cell<u32>,
    fail_write: Cell<bool>,
    fail_read: Cell<bool>,
    /// Run once inside the next write: what happens during the device wait.
    during_write: RefCell<Option<Box<dyn FnOnce()>>>,
    /// Run once inside the next discard.
    during_discard: RefCell<Option<Box<dyn FnOnce()>>>,
    /// Every discard taken: `(sector, sectors)`.
    discards: RefCell<Vec<(u64, u32)>>,
}

impl Disk {
    fn new(slots: usize) -> Self {
        Disk {
            bytes: RefCell::new(vec![0; slots * SEG]),
            writes: Cell::new(0),
            reads: Cell::new(0),
            fail_write: Cell::new(false),
            fail_read: Cell::new(false),
            during_write: RefCell::new(None),
            during_discard: RefCell::new(None),
            discards: RefCell::new(Vec::new()),
        }
    }
    fn slot(&self, n: usize) -> Vec<u8> {
        self.bytes.borrow()[n * SEG..(n + 1) * SEG].to_vec()
    }
    fn put_slot(&self, n: usize, data: &[u8]) {
        self.bytes.borrow_mut()[n * SEG..(n + 1) * SEG].copy_from_slice(data);
    }
    fn flip(&self, off: usize) {
        self.bytes.borrow_mut()[off] ^= 0x01;
    }
}

impl SwapDev for Disk {
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), ()> {
        assert_eq!(buf.len() % SECTOR, 0);
        if let Some(f) = self.during_write.borrow_mut().take() {
            f();
        }
        if self.fail_write.get() {
            return Err(());
        }
        self.writes.set(self.writes.get() + 1);
        let at = sector as usize * SECTOR;
        self.bytes.borrow_mut()[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), ()> {
        assert_eq!(buf.len() % SECTOR, 0);
        if self.fail_read.get() {
            return Err(());
        }
        self.reads.set(self.reads.get() + 1);
        let at = sector as usize * SECTOR;
        buf.copy_from_slice(&self.bytes.borrow()[at..at + buf.len()]);
        Ok(())
    }
    fn discard(&self, sector: u64, sectors: u32) -> Result<(), ()> {
        if let Some(f) = self.during_discard.borrow_mut().take() {
            f();
        }
        self.discards.borrow_mut().push((sector, sectors));
        // A TRIM'd flash block reads zeros afterwards.
        let at = sector as usize * SECTOR;
        self.bytes.borrow_mut()[at..at + sectors as usize * SECTOR].fill(0);
        Ok(())
    }
}

thread_local! {
    /// Bit `n`: Domain slot `n` is pinned.
    static PINNED: Cell<u64> = const { Cell::new(0) };
    static RECORDS: RefCell<Vec<SwapRecord>> = const { RefCell::new(Vec::new()) };
    static TAMPERED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

fn pinned(owner: usize) -> bool {
    PINNED.with(|p| p.get() >> owner & 1 == 1)
}
fn record(r: &SwapRecord) {
    RECORDS.with(|v| v.borrow_mut().push(*r));
}
fn records() -> Vec<SwapRecord> {
    RECORDS.with(|v| v.borrow().clone())
}
fn pin(owners: &[usize]) {
    PINNED.with(|p| p.set(owners.iter().fold(0, |a, o| a | 1 << o)));
}

const KEY: [u8; 16] = *b"zpool test key 1";
const SKEY: [u8; 32] = *b"swap test boot key, 32 bytes....";

fn codec() -> Codec {
    Codec::new(&KEY, 75)
}

fn tamper(slot: usize) {
    TAMPERED.with(|v| v.borrow_mut().push(slot));
}

fn policy() -> Policy {
    Policy { pinned, record, tamper }
}

/// A compressible page: small integers beside a few pointers, as memory is.
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

/// Everything a row needs: the pool behind its lock, the heap it counts, the
/// disk, and the swap keys.
struct Rig<'d, T> {
    pool: Rc<RefCell<T>>,
    heap: Heap,
    disk: &'d Disk,
}

macro_rules! rig_impl {
    ($t:ty) => {
        impl<'d> Rig<'d, $t> {
            fn new(disk: &'d Disk) -> Self {
                let heap = Heap::new();
                let mut pool = <$t>::new(heap.clone());
                assert!(pool.swap_attach(slots_for((SW * SEG / SECTOR) as u64, SEG, SW)));
                Rig { pool: Rc::new(RefCell::new(pool)), heap, disk }
            }

            fn swap(&self) -> RefCell<S<'d>> {
                RefCell::new(Swap::new(self.disk, policy(), &SKEY))
            }

            fn store(&self, owner: usize, obj: u64, pg: u64, seed: u32) {
                let p = page(seed);
                let mut scratch = vec![0u8; PAGE_SIZE];
                match codec().pack(&p, &mut scratch).unwrap() {
                    Packed::Blob { len, nonce } => {
                        self.pool.borrow_mut().insert_blob(owner, obj, pg, nonce, &scratch[..len]).unwrap()
                    }
                    other => panic!("test page did not compress: {other:?}"),
                }
            }

            fn segments(&self) -> usize {
                self.pool.borrow().stats().segments
            }

            /// Add one full segment of `(owner, obj)` pages to the pool: pages
            /// are stored from `first_pg` until one spills into a new segment,
            /// and that one is removed again. The pages in the full segment.
            fn fill_one_segment(&self, owner: usize, obj: u64, first_pg: u64) -> Vec<u64> {
                self.store(owner, obj, first_pg, first_pg as u32);
                let start = self.segments();
                let mut pgs = vec![first_pg];
                loop {
                    let pg = first_pg + pgs.len() as u64;
                    self.store(owner, obj, pg, pg as u32);
                    if self.segments() > start {
                        assert!(self.pool.borrow_mut().remove(obj, pg));
                        assert_eq!(self.segments(), start);
                        return pgs;
                    }
                    pgs.push(pg);
                }
            }

            /// The fault's restore: bring the segment in if it is out, then
            /// fetch and decode.
            fn restore(&self, swap: &RefCell<S<'d>>, obj: u64, pg: u64) -> Result<Vec<u8>, SwapError> {
                let sw = self.pool.borrow().swapped(obj, pg);
                if let Some(sw) = sw {
                    swap_in(&self.pool, swap, &self.heap, &sw)?;
                }
                let mut scratch = vec![0u8; PAGE_SIZE];
                let mut out = vec![0u8; PAGE_SIZE];
                let got = self.pool.borrow().fetch(obj, pg, &mut scratch).expect("the page is in the pool");
                match got.0 {
                    Fetched::Fill(w) => fill_page(w, &mut out),
                    Fetched::Blob { len, nonce } => codec().unpack(nonce, len, &mut scratch, &mut out).unwrap(),
                }
                Ok(out)
            }

            fn storm(&self, swap: &RefCell<S<'d>>, max: u32) -> Result<SwapRecord, SwapError> {
                swap_out_storm(&self.pool, swap, &self.heap, false, max, &|| false)
            }

            #[allow(dead_code)]
            /// Segments the rig's heap holds: the resident ones, nothing else
            /// once a swap step is over.
            fn outstanding(&self) -> isize {
                self.heap.out.get()
            }
        }
    };
}
rig_impl!(P);
rig_impl!(Tight);

#[test]
fn a_full_segment_is_written_whole_and_every_page_comes_back() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let pgs = rig.fill_one_segment(1, 7, 0);
    assert!(pgs.len() > 10, "{} pages in a segment", pgs.len());
    assert_eq!(rig.outstanding(), 1);
    let charged = rig.pool.borrow().charged(1);

    let rec = rig.storm(&swap, 8).unwrap();
    assert_eq!(rec.segments, 1, "{rec:?}");
    assert_eq!(rec.stop, Stop::NoSegment);
    assert!(rec.paid());
    assert_eq!(disk.writes.get(), 1, "one request for the whole segment, not one per page");
    assert!(rec.written_bytes as usize > SEG * 87 / 100 && rec.written_bytes as usize <= SEG);
    assert_eq!(rig.outstanding(), 0, "its frames went back");
    let st = rig.pool.borrow().stats();
    assert_eq!((st.segments, st.swapped), (0, 1));
    // Charged to the swap quota instead of the pool's.
    assert_eq!(rig.pool.borrow().charged(1), 0);
    assert_eq!(rig.pool.borrow().swap_charged(1), charged);

    // The page is in the index but not in memory; a restore brings the lot back.
    for &pg in &pgs {
        assert!(rig.pool.borrow().gen_of(7, pg).is_some());
        assert!(rig.pool.borrow().swapped(7, pg).is_some());
        assert!(rig.pool.borrow().fetch(7, pg, &mut vec![0u8; PAGE_SIZE]).is_none());
    }
    for &pg in &pgs {
        assert_eq!(rig.restore(&swap, 7, pg).unwrap(), page(pg as u32), "page {pg}");
    }
    assert_eq!(disk.reads.get(), 1, "one read brought every page of the segment");
    assert_eq!(rig.outstanding(), 1);
    assert_eq!(rig.pool.borrow().swap_charged(1), 0);
    assert_eq!(rig.pool.borrow().charged(1), charged, "the pool's charge is back, to the byte");
    assert_eq!(rig.pool.borrow().stats().swapped, 0);
}

#[test]
fn the_medium_never_holds_the_staged_image() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    rig.fill_one_segment(1, 7, 0);
    // What would have been written without the cipher: the segment as staged.
    let pick = rig.pool.borrow_mut().swap_pick(&|_| false).unwrap();
    let mut plain = vec![0u8; SEG];
    rig.pool.borrow().swap_stage(&pick, &mut plain).unwrap();
    rig.pool.borrow_mut().swap_abort(&pick);
    assert!(plain[..pick.fill].iter().any(|&b| b != 0));

    rig.storm(&swap, 1).unwrap();
    let on_disk = disk.slot(pick.slot);
    let same = plain.iter().zip(&on_disk).filter(|(a, b)| a == b).count();
    // A cipher agrees with the plaintext on 1 byte in 256 by chance, the zero
    // tail of the image included.
    assert!(same < SEG / 50, "{same} of {SEG} bytes are the staged image's");
    assert!(disk.bytes.borrow()[SEG * (pick.slot + 1)..].iter().all(|&b| b == 0), "only its own slot was written");
}

#[test]
fn a_changed_block_is_refused_and_nothing_is_attached() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let pgs = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    disk.flip(1234);
    assert_eq!(rig.restore(&swap, 7, pgs[0]), Err(SwapError::Tamper));
    assert_eq!(swap.borrow().stats().tampered, 1);
    assert_eq!(TAMPERED.with(|v| v.borrow().clone()), vec![rig.pool.borrow().swapped(7, pgs[0]).unwrap().slot], "reported");
    let st = rig.pool.borrow().stats();
    assert_eq!((st.segments, st.swapped), (0, 1), "the segment stays out");
    assert_eq!(rig.outstanding(), 0, "the buffer that was read into is freed");
    assert!(rig.pool.borrow().swapped(7, pgs[0]).is_some(), "and its pages are not silently replaced by zeros");
    // Put the byte back: the same block verifies, and the pages are intact.
    disk.flip(1234);
    assert_eq!(rig.restore(&swap, 7, pgs[0]).unwrap(), page(pgs[0] as u32));
}

#[test]
fn a_block_moved_to_another_slot_is_refused() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    let b = rig.fill_one_segment(1, 8, 0);
    rig.storm(&swap, 1).unwrap();
    let (sa, sb) = (rig.pool.borrow().swapped(7, a[0]).unwrap(), rig.pool.borrow().swapped(8, b[0]).unwrap());
    assert_ne!(sa.slot, sb.slot);
    // The medium's owner swaps the two blocks.
    let (s0, s1) = (disk.slot(sa.slot), disk.slot(sb.slot));
    disk.put_slot(sa.slot, &s1);
    disk.put_slot(sb.slot, &s0);
    assert_eq!(rig.restore(&swap, 7, a[0]), Err(SwapError::Tamper));
    assert_eq!(rig.restore(&swap, 8, b[0]), Err(SwapError::Tamper));
}

#[test]
fn a_replayed_block_is_refused() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    let slot = rig.pool.borrow().swapped(7, a[0]).unwrap().slot;
    let old = disk.slot(slot);
    // Back in, then out again to the same slot: a new nonce, a new block.
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap(), page(a[0] as u32));
    rig.storm(&swap, 1).unwrap();
    assert_eq!(rig.pool.borrow().swapped(7, a[0]).unwrap().slot, slot);
    assert!(disk.slot(slot) != old, "a fresh nonce: the same plaintext, other bytes");
    disk.put_slot(slot, &old);
    assert_eq!(rig.restore(&swap, 7, a[0]), Err(SwapError::Tamper));
}

#[test]
fn a_read_that_fails_leaves_the_segment_out() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    disk.fail_read.set(true);
    assert_eq!(rig.restore(&swap, 7, a[0]), Err(SwapError::Io));
    assert_eq!(rig.outstanding(), 0);
    disk.fail_read.set(false);
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap(), page(a[0] as u32), "the next fault tries again");
}

#[test]
fn a_failed_write_leaves_the_segment_where_it_was() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    disk.fail_write.set(true);
    let rec = rig.storm(&swap, 4).unwrap();
    assert_eq!((rec.segments, rec.stop), (0, Stop::Io));
    assert!(!rec.paid());
    assert_eq!(rig.outstanding(), 1, "nothing freed, the staging segment returned");
    assert_eq!(rig.pool.borrow().stats().swapped, 0);
    // Not stuck "leaving": the next storm writes it.
    disk.fail_write.set(false);
    assert_eq!(rig.storm(&swap, 4).unwrap().segments, 1);
    assert_eq!(rig.restore(&swap, 7, a[3]).unwrap(), page(a[3] as u32));
}

#[test]
fn the_swap_quota_refuses_before_the_medium_is_touched() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(2, 7, 0);
    // Domain 2 may swap 1000 bytes: a segment of its pages is more.
    rig.pool.borrow_mut().set_swap_quota(2, 1000);
    let rec = rig.storm(&swap, 4).unwrap();
    assert_eq!((rec.segments, rec.stop), (0, Stop::Quota));
    assert_eq!(disk.writes.get(), 0, "refused before the medium is touched");
    assert_eq!(rig.pool.borrow().swap_charged(2), 0);
    assert_eq!(rig.outstanding(), 1);
    // Room for it: it goes, and is charged to the swap ledger.
    rig.pool.borrow_mut().set_swap_quota(2, 1 << 20);
    assert_eq!(rig.storm(&swap, 4).unwrap().segments, 1);
    let held = rig.pool.borrow().swap_charged(2);
    assert!(held as usize > SEG * 80 / 100, "{held}");
    // A page removed while out gives its share back.
    assert!(rig.pool.borrow_mut().remove(7, a[0]));
    assert!(rig.pool.borrow().swap_charged(2) < held);
}

#[test]
fn a_domain_over_its_quota_does_not_hold_up_the_others() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(2, 7, 0);
    rig.fill_one_segment(3, 8, 0);
    rig.pool.borrow_mut().set_swap_quota(2, 1000);
    let rec = rig.storm(&swap, 4).unwrap();
    assert_eq!((rec.segments, rec.stop), (1, Stop::Quota), "Domain 3's segment went, Domain 2's was refused");
    assert!(rig.pool.borrow().swapped(7, a[0]).is_none(), "Domain 2's stayed");
    assert!(rig.pool.borrow().swap_charged(3) > 0);
    assert_eq!(rig.pool.borrow().swap_charged(2), 0);
}

#[test]
fn a_pinned_domains_segment_is_never_written() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    rig.fill_one_segment(3, 7, 0);
    assert_eq!(rig.pool.borrow_mut().swap_pick(&|o| o == 3), Err(Error::Pinned));
    assert!(rig.pool.borrow_mut().swap_pick(&|o| o == 4).is_ok(), "another Domain's pin is not this one's");
}

#[test]
fn swap_out_storm_refuses_pinned_memory_and_records_it() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(3, 7, 0);
    pin(&[3]);
    let rec = rig.storm(&swap, 4).unwrap();
    assert_eq!((rec.segments, rec.stop), (0, Stop::Pinned));
    assert_eq!(disk.writes.get(), 0, "the pinned pages never reached the medium");
    assert_eq!(rig.outstanding(), 1);
    assert!(rig.pool.borrow().swapped(7, a[0]).is_none());
    assert_eq!(records(), vec![rec], "the storm that wrote nothing is still one record");
    assert!(!rec.paid(), "and it is a refusal");
    // Unpinned (the row changed): it goes.
    pin(&[]);
    assert_eq!(rig.storm(&swap, 4).unwrap().segments, 1);
}

#[test]
fn a_real_time_hart_never_swaps() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    rig.fill_one_segment(1, 7, 0);
    let r = swap_out_storm(&rig.pool, &swap, &rig.heap, true, 4, &|| false);
    assert_eq!(r, Err(SwapError::RtHart));
    assert_eq!((disk.writes.get(), disk.reads.get()), (0, 0));
    assert_eq!(rig.outstanding(), 1, "not even the staging segment was taken");
    assert!(records().is_empty(), "refused before a storm began: no record");
    assert_eq!(rig.pool.borrow().stats().swapped, 0);
}

#[test]
fn one_storm_is_one_record() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    for obj in 1..=3u64 {
        rig.fill_one_segment(1, obj, 0);
    }
    assert_eq!(rig.segments(), 3);
    let rec = rig.storm(&swap, 8).unwrap();
    assert_eq!(rec.segments, 3, "{rec:?}");
    assert_eq!(disk.writes.get(), 3);
    assert_eq!(records(), vec![rec], "one record, not one per segment");
    let [segs, live, written] = rec.fields();
    assert_eq!(segs, 3);
    assert!(live > 0 && written >= live);
    // The cap on a storm is honoured.
    for obj in 4..=6u64 {
        rig.fill_one_segment(1, obj, 0);
    }
    let rec = rig.storm(&swap, 2).unwrap();
    assert_eq!((rec.segments, rec.stop), (2, Stop::Max));
    assert_eq!(records().len(), 2);
}

#[test]
fn done_ends_a_storm_before_it_writes() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    rig.fill_one_segment(1, 7, 0);
    let rec = swap_out_storm(&rig.pool, &swap, &rig.heap, false, 4, &|| true).unwrap();
    assert_eq!((rec.segments, rec.stop), (0, Stop::Done));
    assert_eq!(disk.writes.get(), 0);
}

#[test]
fn stores_and_a_compaction_during_the_write_do_not_move_the_segment() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    // While the device works: more pages arrive, one of the segment's goes,
    // and the compactor runs. The pool is free (not borrowed) meanwhile.
    let pool = rig.pool.clone();
    let rig2 = (rig.pool.clone(), a[1]);
    *disk.during_write.borrow_mut() = Some(Box::new(move || {
        for i in 0..30u64 {
            let p = page(900 + i as u32);
            let mut scratch = vec![0u8; PAGE_SIZE];
            let Packed::Blob { len, nonce } = codec().pack(&p, &mut scratch).unwrap() else { unreachable!() };
            pool.borrow_mut().insert_blob(1, 9, i, nonce, &scratch[..len]).unwrap();
        }
        assert!(rig2.0.borrow_mut().remove(7, rig2.1));
        rig2.0.borrow_mut().compact();
    }));
    let rec = rig.storm(&swap, 1).unwrap();
    assert_eq!(rec.segments, 1);
    // Every page but the removed one restores: compaction moving a blob under
    // the staged copy would leave the medium's image with the old offsets.
    for &pg in &a {
        if pg != a[1] {
            assert_eq!(rig.restore(&swap, 7, pg).unwrap(), page(pg as u32), "page {pg}");
        }
    }
    // The pages stored meanwhile were never in it.
    assert!(rig.pool.borrow().swapped(9, 0).is_none() || rig.pool.borrow().swapped(9, 0) != rig.pool.borrow().swapped(7, a[0]));
    for i in 0..30u64 {
        assert_eq!(rig.restore(&swap, 9, i).unwrap(), page(900 + i as u32));
    }
    assert!(rig.pool.borrow().gen_of(7, a[1]).is_none());
}

#[test]
fn pages_that_leave_during_the_write_park_nothing() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    let pool = rig.pool.clone();
    let pgs = a.clone();
    *disk.during_write.borrow_mut() = Some(Box::new(move || {
        assert_eq!(pool.borrow_mut().remove_obj(7), pgs.len());
    }));
    let rec = rig.storm(&swap, 1).unwrap();
    assert_eq!(rec.segments, 0, "the segment had no live page left: {rec:?}");
    let st = rig.pool.borrow().stats();
    assert_eq!((st.swapped, st.entries), (0, 0));
    assert_eq!(rig.pool.borrow().swap_charged(1), 0);
    assert_eq!(rig.pool.borrow().charged(1), 0);
    // The pool is whole: a new segment is taken and swaps normally.
    let b = rig.fill_one_segment(1, 8, 0);
    assert_eq!(rig.storm(&swap, 1).unwrap().segments, 1);
    assert_eq!(rig.restore(&swap, 8, b[0]).unwrap(), page(b[0] as u32));
}

/// A pool whose one segment is gone by the time it is copied (the real pool
/// never reaches this on its own: a picked segment stays mapped until commit).
/// It counts how the pick is given up.
struct VanishingPool {
    picked: bool,
    aborts: u32,
}

impl Parkable for VanishingPool {
    fn pick(&mut self, _: &dyn Fn(usize) -> bool) -> Result<SwapPick, Error> {
        if std::mem::replace(&mut self.picked, true) {
            return Err(Error::NoSegment);
        }
        Ok(SwapPick { seg: 0, slot: 0, fill: 64, live: 32 })
    }
    fn stage(&self, _: &SwapPick, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Gone)
    }
    fn commit(&mut self, _: &SwapPick) -> Result<(), Error> {
        panic!("nothing was staged, so nothing is committed");
    }
    fn abort(&mut self, _: &SwapPick) {
        self.aborts += 1;
    }
    fn in_begin(&mut self, _: &Swapped) -> Result<NonNull<u8>, Error> {
        unreachable!()
    }
    fn in_commit(&mut self, _: &Swapped, _: NonNull<u8>) -> Result<(), Error> {
        unreachable!()
    }
    fn in_current(&self, _: &Swapped) -> bool {
        unreachable!()
    }
    fn in_abort(&mut self, _: NonNull<u8>) {
        unreachable!()
    }
    fn slots(&self) -> SwapSlots {
        unreachable!("a storm that wrote nothing does not ask")
    }
    fn set_cap(&mut self, _: usize) -> bool {
        unreachable!()
    }
}

#[test]
fn a_segment_gone_at_the_copy_is_skipped_not_an_io_error() {
    let disk = Disk::new(SW);
    let heap = Heap::new();
    let swap: RefCell<S<'_>> = RefCell::new(Swap::new(&disk, policy(), &SKEY));
    let pool = RefCell::new(VanishingPool { picked: false, aborts: 0 });
    let rec = swap_out_storm(&pool, &swap, &heap, false, 2, &|| false).unwrap();
    assert_eq!(rec.segments, 0, "{rec:?}");
    assert_eq!(rec.stop, Stop::NoSegment, "the storm moved on to the next pick, found none, and said so: {rec:?}");
    assert_eq!(pool.borrow().aborts, 1, "the pick was given up, so the segment is not left leaving");
    assert_eq!(disk.writes.get(), 0, "nothing was sealed onto the medium");
    assert_eq!(heap.out.get(), 0, "the staging segment is back");
}

#[test]
fn pages_that_leave_a_swapped_segment_free_its_slot() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    let sw = rig.pool.borrow().swapped(7, a[0]).unwrap();
    assert_eq!(rig.pool.borrow().stats().swapped, 1);
    for &pg in &a {
        assert!(rig.pool.borrow_mut().remove(7, pg));
    }
    assert_eq!(rig.pool.borrow().stats().swapped, 0, "the last page freed the slot");
    assert_eq!(rig.pool.borrow().swap_charged(1), 0);
    assert_eq!(rig.pool.borrow().stats().swapped, 0);
    // A restorer that read the slot's incarnation before the pages left
    // finds it gone, and attaches nothing.
    assert_eq!(swap_in(&rig.pool, &swap, &rig.heap, &sw), Ok(()));
    assert_eq!(disk.reads.get(), 0, "nothing to read");
    assert_eq!(rig.outstanding(), 0);
    // And the slot can be taken by the next segment out.
    rig.fill_one_segment(1, 8, 0);
    assert_eq!(rig.storm(&swap, 1).unwrap().segments, 1);
}

#[test]
fn a_second_restorer_finds_the_segment_back_already() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    let sw = rig.pool.borrow().swapped(7, a[0]).unwrap();
    // Two faults saw the same swapped page; the first one brought it back.
    swap_in(&rig.pool, &swap, &rig.heap, &sw).unwrap();
    swap_in(&rig.pool, &swap, &rig.heap, &sw).unwrap();
    assert_eq!(disk.reads.get(), 1, "attached once");
    assert_eq!(rig.outstanding(), 1);
    assert_eq!(rig.pool.borrow().stats().segments, 1);
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap(), page(a[0] as u32));
}

#[test]
fn a_restore_at_the_ceiling_writes_another_segment_out() {
    let disk = Disk::new(SW);
    let rig = Rig::<Tight>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    // Two resident segments: a full one and a part-full one fill the ceiling.
    let b = rig.fill_one_segment(1, 8, 0);
    rig.store(1, 9, 0, 9);
    assert_eq!(rig.segments(), 2);
    assert!(!rig.pool.borrow().swap_has_room());
    // Fault on the swapped segment: the full one in the way is written out.
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap(), page(a[0] as u32));
    assert_eq!(disk.writes.get(), 2);
    assert!(rig.pool.borrow().swapped(8, b[0]).is_some(), "the segment that was in the way is out now");
    assert_eq!(rig.restore(&swap, 8, b[0]).unwrap(), page(b[0] as u32), "and it comes back in turn");
    assert_eq!(rig.restore(&swap, 7, a[5]).unwrap(), page(a[5] as u32), "the others are still right");
}

#[test]
fn a_forked_page_in_a_swapped_segment_is_charged_to_swap() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    let held = rig.pool.borrow().swap_charged(1);
    assert_eq!(rig.pool.borrow_mut().dup_obj(7, 70), Ok(a.len()));
    assert!(rig.pool.borrow().swap_charged(1) > held, "the child's entries are swap bytes too");
    let (p, c) = (rig.pool.borrow().swapped(7, a[0]).unwrap(), rig.pool.borrow().swapped(70, a[0]).unwrap());
    assert_eq!(p, c, "one blob, one slot");
    // Both come back from the one read.
    assert_eq!(rig.restore(&swap, 70, a[2]).unwrap(), page(a[2] as u32));
    assert_eq!(rig.restore(&swap, 7, a[2]).unwrap(), page(a[2] as u32));
    assert_eq!(rig.pool.borrow().swap_charged(1), 0);
    assert_eq!(disk.reads.get(), 1);
    // A child that exits: the parent's page stays.
    assert_eq!(rig.pool.borrow_mut().remove_obj(70), a.len());
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap(), page(a[0] as u32));
}

#[test]
fn a_pool_without_a_swap_area_picks_nothing() {
    let mut pool = P::new(Heap::new());
    assert_eq!(pool.swap_pick(&|_| false), Err(Error::NoSwap));
    assert!(!pool.swap_attach(0));
    // A partition of one and a half segments holds one slot.
    assert_eq!(slots_for((SEG / SECTOR * 3 / 2) as u64, SEG, SW), 1);
    assert_eq!(slots_for(u64::MAX, SEG, SW), SW);
    assert_eq!(slots_for(0, SEG, SW), 0);
}

// ── the swap partition type ──────────────────────────────────────────────────

const LINUX_DATA: [u8; 16] =
    [0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4];

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// A GPT medium of `cap` sectors with the given `(type GUID, first, last)` entries.
fn gpt(cap: u64, ents: &[([u8; 16], u64, u64)]) -> Vec<u8> {
    let mut d = vec![0u8; cap as usize * SECTOR];
    d[510] = 0x55;
    d[511] = 0xAA;
    d[446 + 4] = 0xEE;
    let mut arr = vec![0u8; 128 * 128];
    for (i, (g, first, last)) in ents.iter().enumerate() {
        arr[i * 128..i * 128 + 16].copy_from_slice(g);
        arr[i * 128 + 16] = i as u8 + 1; // a unique GUID, which the parser does not read
        put64(&mut arr, i * 128 + 32, *first);
        put64(&mut arr, i * 128 + 40, *last);
    }
    d[2 * SECTOR..2 * SECTOR + arr.len()].copy_from_slice(&arr);
    let h = &mut d[SECTOR..2 * SECTOR];
    h[..8].copy_from_slice(b"EFI PART");
    put32(h, 8, 0x0001_0000);
    put32(h, 12, 92);
    put64(h, 24, 1);
    put64(h, 32, cap - 1);
    put64(h, 40, 34);
    put64(h, 48, cap - 34);
    put64(h, 72, 2);
    put32(h, 80, 128);
    put32(h, 84, 128);
    put32(h, 88, part::crc32_update(0, &arr));
    let crc = part::crc32_update(0, &h[..92]);
    put32(h, 16, crc);
    d
}

fn parse(d: &[u8]) -> Result<part::Table, part::PartError> {
    part::parse((d.len() / SECTOR) as u64, &mut |lba, buf| {
        buf.copy_from_slice(&d[lba as usize * SECTOR..(lba as usize + 1) * SECTOR]);
        Ok(())
    })
}

#[test]
fn the_swap_partition_is_found_claimed_and_hidden() {
    part::reset_for_tests();
    // GPT: a data partition and a swap partition.
    let d = gpt(4096, &[(LINUX_DATA, 100, 999), (part::GPT_SWAP_GUID, 1000, 1999)]);
    let t = parse(&d).unwrap();
    assert_eq!(t.count, 2);
    assert!(!t.parts[0].is_swap() && t.parts[1].is_swap());
    assert_eq!(t.parts[1].mbr_type, part::MBR_SWAP);
    assert_eq!(t.parts[0].mbr_type, 0, "a GPT data entry still reads 0");
    assert_eq!(t.swap_index(), Some(1));

    // MBR: type 0x82 is swap, 0x83 is not.
    let mut m = vec![0u8; 4096 * SECTOR];
    m[510] = 0x55;
    m[511] = 0xAA;
    for (i, (ty, start, len)) in [(0x83u8, 100u32, 900u32), (0x82, 1000, 1000)].iter().enumerate() {
        let e = 446 + 16 * i;
        m[e + 4] = *ty;
        put32(&mut m, e + 8, *start);
        put32(&mut m, e + 12, *len);
    }
    let tm = parse(&m).unwrap();
    assert_eq!(tm.swap_index(), Some(1));

    // No swap partition: none to claim.
    let none = parse(&gpt(4096, &[(LINUX_DATA, 100, 999)])).unwrap();
    assert_eq!(none.swap_index(), None);
    assert!(part::publish(&none));
    assert_eq!(part::claim_swap(), None);
    part::reset_for_tests();

    // Published: visible until claimed; claimed once; hidden afterwards, and
    // the numbers of the others do not move.
    assert!(part::publish(&t));
    assert_eq!(part::partition(1), Some((1000, 1000)));
    assert!(part::contains(1, 1000, 1));
    assert_eq!(part::claim_swap(), Some((1000, 1000)));
    assert_eq!(part::claim_swap(), None, "the kernel takes it once");
    assert_eq!(part::count(), 2, "its index stays reserved");
    assert_eq!(part::partition(1), None, "no capability can name it");
    assert!(!part::contains(1, 1000, 1));
    assert_eq!(part::resolve(1, 0, 1), None);
    assert_eq!(part::partition(0), Some((100, 900)), "the others keep their numbers");
    assert_eq!(part::extent(1), Some((1000, 1000)), "the kernel's own accounting still sees it");
    part::reset_for_tests();
}

// ── Discard of a slot a segment left (Kconfig `BLK_DISCARD`) ────────────

/// A segment brought back gives its slot up; the slot is discarded once the
/// commit has freed it, and the discard is the one of that slot.
#[test]
fn a_restored_segments_slot_is_discarded_after_the_commit() {
    if azos_limits::BLK_DISCARD_OFF {
        return;
    }
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    assert!(disk.discards.borrow().is_empty(), "writing a segment out discards nothing");
    let sw = rig.pool.borrow().swapped(7, a[0]).unwrap();
    // While the discard runs the segment is back in memory and its slot is
    // free: the commit came first.
    let pool = rig.pool.clone();
    *disk.during_discard.borrow_mut() = Some(Box::new(move || {
        let st = pool.borrow().stats();
        assert_eq!((st.swapped, st.segments), (0, 1), "the slot is free when it is discarded");
    }));
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap(), page(a[0] as u32));
    assert_eq!(*disk.discards.borrow(), vec![(sector_of_slot(sw.slot), (SEG / SECTOR) as u32)]);
    // The medium reads zeros there now.
    assert!(disk.slot(sw.slot).iter().all(|&b| b == 0));
    // A second restorer finds the segment back already: no commit, no discard.
    swap_in(&rig.pool, &swap, &rig.heap, &sw).unwrap();
    assert_eq!(disk.discards.borrow().len(), 1);
}

fn sector_of_slot(slot: usize) -> u64 {
    (slot * (SEG / SECTOR)) as u64
}

/// A restore that fails reads or verifies nothing it may throw away: the
/// segment is still out, so its slot still holds the only copy.
#[test]
fn a_restore_that_fails_discards_nothing() {
    let disk = Disk::new(SW);
    let rig = Rig::<P>::new(&disk);
    let swap = rig.swap();
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(&swap, 1).unwrap();
    disk.fail_read.set(true);
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap_err(), SwapError::Io);
    disk.fail_read.set(false);
    let sw = rig.pool.borrow().swapped(7, a[0]).unwrap();
    disk.flip(sw.slot * SEG + 9);
    assert_eq!(rig.restore(&swap, 7, a[0]).unwrap_err(), SwapError::Tamper);
    assert!(disk.discards.borrow().is_empty(), "the segment is still out: its slot is not free");
}

/// **A discard never lands on a segment written after it started.** A storm
/// that runs while the slot is being discarded picks that very slot (the
/// first free one); it gives the pick up and asks again later, and the slot is
/// written only once the discard is over. The medium orders a discard against
/// nothing, so a write let through would be erased and fail its tag.
///
/// **Canary.** Dropping the `trimming` test in `swap_out_step` lets the storm
/// write the slot during its discard: the write count moves, and this row
/// goes red.
#[test]
fn a_storm_cannot_write_the_slot_being_discarded() {
    if azos_limits::BLK_DISCARD_OFF {
        return;
    }
    let disk: &'static Disk = Box::leak(Box::new(Disk::new(SW)));
    let rig = Rig::<P>::new(disk);
    let swap: &'static RefCell<S<'static>> = Box::leak(Box::new(rig.swap()));
    let a = rig.fill_one_segment(1, 7, 0);
    rig.storm(swap, 1).unwrap();
    // Another full segment waits in memory to be written out.
    let b = rig.fill_one_segment(1, 8, 0);
    let writes = disk.writes.get();
    let (pool, heap) = (rig.pool.clone(), rig.heap.clone());
    *disk.during_discard.borrow_mut() = Some(Box::new(move || {
        let r = swap_out_storm(&pool, swap, &heap, false, 1, &|| false);
        assert!(matches!(r, Err(SwapError::Busy)), "a storm during the discard: {r:?}");
    }));
    assert_eq!(rig.restore(swap, 7, a[0]).unwrap(), page(a[0] as u32));
    assert_eq!(disk.writes.get(), writes, "nothing was written into the slot during its discard");
    // The discard is over: the slot is writable, and what is written there is whole.
    let rec = rig.storm(swap, 1).unwrap();
    assert_eq!(rec.segments, 1);
    assert_eq!(disk.writes.get(), writes + 1);
    assert_eq!(rig.restore(swap, 8, b[0]).unwrap(), page(b[0] as u32));
}
