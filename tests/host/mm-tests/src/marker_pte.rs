// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the page markers the reclaimer leaves in an anonymous page's
//! slot (Kconfig `MM_RECLAIM_COMPRESS`): the protocol of `zpool.rs`
//! ([`take_out`], [`publish`], [`put_back`], [`clear`]) over the real slot
//! words of `slot.rs` ([`SlotWords`]), the fault's decision over the slot
//! ([`resolve`]: the slot decides, the leaf is a cache of it), the real pool
//! and codec, the generation checks of `Pool::fetch_named`, the stage order of
//! `reclaim_pass`, and the Domain watermarks `PageBudget::set_limit_marked`
//! derives from a row's limit.
//!
//! **What is real and what is a model.** The protocol functions, the slot
//! words, the decision, the pool, the codec, the pass and the budget are the
//! shipping code. The fault and the reclaimer below are the order `pager.rs`
//! runs them in (`fault_once`, `DomainReclaim::unmap`), written out over a page
//! that is a slot word and a leaf word (`AtomicU64`s, the leaf in the RISC-V
//! encoding of the shim's real `mmu.rs`) and frames that are `Vec`s:
//! `pager.rs` itself needs the page allocator, the scheduler's wait queue and
//! a live MMU, and runs in `tests/host/syscall-tests` (`pte_truth.rs`) and
//! the boot gate.
//!
//! Canaries (by hand; discriminates / does not / did not compile):
//! * `resolve` answering `Supply` for an `InTransit` slot:
//!   `a_fault_racing_a_store_waits_and_restores_the_page` red (it zero-fills,
//!   the stored copy is orphaned).
//! * `take_out` taking a slot that is not a `Frame` (a marker):
//!   `only_a_resident_slot_is_taken_out` red.
//! * `publish` / `put_back` not comparing the ticket (swapping from whatever
//!   marker is there): `a_store_ends_only_its_own_marker` red.
//! * `Pool::fetch_named` not comparing the generation:
//!   `a_marker_never_restores_another_stores_copy` red.
//! * `Pool::dup_obj` giving the child a new generation:
//!   `a_forks_child_restores_through_the_parents_marker_word` red.
//! * `clear` leaving an `InTransit` marker: `munmap_clears_every_kind_of_marker` red.
//! * Feature `keep-leaf-first-canary` (the put-back writes the leaf first):
//!   `a_failed_store_writes_no_leaf_for_a_slot_that_is_not_its_own` red.
//! * Feature `mm-pte-truth-canary` (the leaf believed over the slot):
//!   `a_leaf_the_slot_does_not_name_is_not_believed`,
//!   `a_resident_slot_whose_leaf_is_gone_is_installed_again` and
//!   `a_fault_on_a_compressed_marker_restores_the_page` red.
//! * `reclaim_pass` swapping before compressing, or without a `full` round:
//!   `the_pass_runs_purge_then_cache_then_compression_then_swap_only_when_full` red.
//! * `reclaim_pass` not running `purge` first (or at all): the same row red (2026-10-20).
//! * `reclaim_pass` ignoring `max_rounds`: `a_pass_is_bounded` red.
//! * `PageBudget::set_limit` leaving the old marks: `a_limit_without_marks_has_none` red.
//! * `set_limit_marked` taking the percentages the wrong way round:
//!   `a_rows_limit_sets_the_domains_watermarks` red.
//!
//! The test the reclaimer makes on the leaf (`pager::victim_leaf`) is mirrored
//! by `Rv` below.

use super::budget::PageBudget;
use super::slot::{self, put_back_page, resolve, PageMarker, PutBack, Resolve, SlotWords};
use super::zpool::{
    clear, fill_page, publish, put_back, reclaim_pass, take_out, Backing, Codec, Fetched, Lookup, Packed, PageWords,
    Pool, Refusal, Round, Stages,
};
use azos_arch::mmu::{Pte, PteFlags};
use azos_arch_api::PAGE_SIZE;
use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

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

const SEG: usize = 4 * PAGE_SIZE;
type P = Pool<Heap, 16, 32, 2, 2, SEG, 0>;

const KEY: [u8; 16] = *b"marker test key.";
const OWN: usize = 1;
const OBJ: u64 = 0x0100_0007;
const PG: u64 = 3;
/// The frame of the page's first install.
const FRAME: usize = 0x8020_0000;

fn codec() -> Codec {
    Codec::new(&KEY, 75)
}

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

/// The reclaimer's test on the leaf (`pager::victim_leaf`), on the RISC-V words
/// of the shim's real `mmu.rs`.
struct Rv;

impl Rv {
    fn is_victim_leaf(&self, w: u64) -> bool {
        let p = Pte(w);
        p.is_valid() && p.is_leaf() && p.flags().contains(PteFlags::USER) && !p.flags().contains(PteFlags::COW)
    }
}

/// A resident user page's leaf on `frame`.
fn leaf_on(frame: usize) -> u64 {
    Pte::new(frame, PteFlags::USER_RW | PteFlags::ACCESSED | PteFlags::DIRTY).0
}

/// One page of an anonymous object: its slot (the truth) and its leaf (the
/// cache), and the frames of the model's memory.
struct Page {
    slot: AtomicU64,
    leaf: AtomicU64,
    mem: Mutex<HashMap<usize, Vec<u8>>>,
    next: AtomicUsize,
}

impl Page {
    /// Resident in `FRAME`, holding `bytes`.
    fn resident(bytes: Vec<u8>) -> Self {
        let p = Page::empty();
        p.slot.store(slot::frame(FRAME), Ordering::Release);
        p.leaf.store(leaf_on(FRAME), Ordering::Release);
        p.mem.lock().unwrap().insert(FRAME, bytes);
        p
    }

    fn empty() -> Self {
        Page { slot: AtomicU64::new(slot::EMPTY), leaf: AtomicU64::new(0), mem: Mutex::new(HashMap::new()), next: AtomicUsize::new(FRAME + PAGE_SIZE) }
    }

    /// A frame of the allocator, holding `bytes`.
    fn frame(&self, bytes: Vec<u8>) -> usize {
        let f = self.next.fetch_add(PAGE_SIZE, Ordering::Relaxed);
        self.mem.lock().unwrap().insert(f, bytes);
        f
    }

    /// What a load through the leaf reads (the hardware walks the leaf only).
    fn read(&self) -> Option<Vec<u8>> {
        let p = Pte(self.leaf.load(Ordering::Acquire));
        p.is_valid().then(|| self.mem.lock().unwrap()[&p.phys_addr()].clone())
    }

    fn bytes_of(&self, frame: usize) -> Vec<u8> {
        self.mem.lock().unwrap()[&frame].clone()
    }
}

/// The reclaimer's store of `page`, in the order `DomainReclaim` runs it: the
/// slot becomes `InTransit`, the leaf is cleared, the frame's bytes are packed
/// and inserted, the marker is published. The leaf word that was cleared and
/// the entry's generation.
fn reclaim(pool: &Mutex<P>, pg: &Page, ticket: u32) -> (u64, u32) {
    let original = out(pg, ticket);
    let gen = store(pool, &pg.bytes_of(Pte(original).phys_addr()));
    assert!(publish(&SlotWords, &pg.slot, ticket, PageMarker::Compressed, gen), "the store's own marker");
    (original, gen)
}

/// The take-out half of a store: the slot first, then the leaf.
fn out(pg: &Page, ticket: u32) -> u64 {
    let w = pg.leaf.load(Ordering::Acquire);
    assert!(Rv.is_victim_leaf(w), "a plain user leaf");
    take_out(&SlotWords, &pg.slot, ticket).expect("a resident slot");
    pg.leaf.compare_exchange(w, 0, Ordering::AcqRel, Ordering::Acquire).expect("the leaf it read");
    w
}

fn store(pool: &Mutex<P>, frame: &[u8]) -> u32 {
    let mut scratch = vec![0u8; PAGE_SIZE];
    let mut p = pool.lock().unwrap();
    match codec().pack(frame, &mut scratch).unwrap() {
        Packed::Fill(w) => p.insert_fill(OWN, OBJ, PG, w).unwrap(),
        Packed::Blob { len, nonce } => p.insert_blob(OWN, OBJ, PG, nonce, &scratch[..len]).unwrap(),
        Packed::Skip => panic!("the test page compresses"),
    }
    p.gen_of(OBJ, PG).unwrap()
}

/// What a fault did.
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    Zero,
    Restored(Vec<u8>),
    /// Nothing to do: the access retries on the leaf.
    Present,
}

/// One fault on `pg` as `fault_once` runs it: decide from the slot (the leaf
/// only says whether it already maps the slot's frame), wait while a store is
/// in flight (`waits` counts the looks), supply a zero page or restore the
/// marked one, and install it over exactly the slot and leaf words it read,
/// then drop the pool's copy by generation.
fn fault(pool: &Mutex<P>, pg: &Page, waits: &AtomicBool) -> Fate {
    loop {
        let seen = pg.slot.load(Ordering::Acquire);
        let seen_leaf = pg.leaf.load(Ordering::Acquire);
        let leaf = Pte(seen_leaf).is_valid().then(|| Pte(seen_leaf).phys_addr());
        let (bytes, gen) = match resolve(seen, leaf).expect("a word an encoder made") {
            Resolve::Present => return Fate::Present,
            Resolve::Wait => {
                waits.store(true, Ordering::Release);
                std::thread::yield_now();
                continue;
            }
            Resolve::Supply => (vec![0u8; PAGE_SIZE], None),
            Resolve::Install(f) => (pg.bytes_of(f), Some(u32::MAX)),
            Resolve::Foreign => return Fate::Present,
            Resolve::Restore(_, gen) => {
                let mut scratch = vec![0u8; PAGE_SIZE];
                let mut out = vec![0u8; PAGE_SIZE];
                let got = pool.lock().unwrap().fetch_named(OBJ, PG, gen, &mut scratch);
                let Lookup::Page(what, g, _) = got else { panic!("the marker's entry: {got:?}") };
                match what {
                    Fetched::Fill(w) => fill_page(w, &mut out),
                    Fetched::Blob { len, nonce } => codec().unpack(nonce, len, &mut scratch, &mut out).unwrap(),
                }
                (out, Some(g))
            }
        };
        let f = pg.frame(bytes.clone());
        // Install over the words read; a changed one starts over.
        if pg.slot.load(Ordering::Acquire) == seen
            && pg.leaf.compare_exchange(seen_leaf, leaf_on(f), Ordering::AcqRel, Ordering::Acquire).is_ok()
        {
            pg.slot.store(slot::frame(f), Ordering::Release);
            return match gen {
                Some(u32::MAX) => Fate::Restored(bytes),
                Some(g) => {
                    pool.lock().unwrap().remove_if(OBJ, PG, g);
                    Fate::Restored(bytes)
                }
                None => Fate::Zero,
            };
        }
    }
}

fn pool() -> Mutex<P> {
    Mutex::new(P::new(Heap))
}

#[test]
fn a_fault_on_a_compressed_marker_restores_the_page() {
    let pool = pool();
    let pg = Page::resident(page(3));
    let (_, gen) = reclaim(&pool, &pg, 1);
    assert_eq!(pg.leaf.load(Ordering::Acquire), 0, "the page is out of the table");
    assert_eq!(SlotWords.marker(pg.slot.load(Ordering::Acquire)), Some((PageMarker::Compressed, gen)));

    assert_eq!(fault(&pool, &pg, &AtomicBool::new(false)), Fate::Restored(page(3)));
    assert_eq!(pg.read(), Some(page(3)), "the leaf maps the restored copy");
    assert!(slot::frame_of(pg.slot.load(Ordering::Acquire)).is_some(), "the slot names its frame");
    assert!(pool.lock().unwrap().is_empty(), "the copy goes with the install");
}

/// **The slot decides.** A leaf the slot does not name (over an `Empty` slot,
/// or naming another frame than the slot's) is no page of the object: the
/// fault does not take it as resident and does not replace it (its frame is
/// nobody's the fault could free).
/// Canary `mm-pte-truth-canary`: the leaf is believed (`Present`).
#[test]
fn a_leaf_the_slot_does_not_name_is_not_believed() {
    let stale = FRAME + 7 * PAGE_SIZE;
    assert_eq!(resolve(slot::EMPTY, Some(stale)), Some(Resolve::Foreign));
    assert_eq!(resolve(slot::frame(FRAME), Some(stale)), Some(Resolve::Foreign));
    assert_eq!(resolve(slot::marker(PageMarker::Compressed, 3), Some(stale)), Some(Resolve::Foreign));
    assert_eq!(resolve(slot::frame(FRAME), Some(FRAME)), Some(Resolve::Present));
}

#[test]
fn a_resident_slot_whose_leaf_is_gone_is_installed_again() {
    let pool = pool();
    let pg = Page::resident(page(2));
    pg.leaf.store(0, Ordering::Release);
    assert_eq!(resolve(pg.slot.load(Ordering::Acquire), None), Some(Resolve::Install(FRAME)));
    // The model installs a copy; the kernel installs the slot's own frame.
    assert_eq!(fault(&pool, &pg, &AtomicBool::new(false)), Fate::Restored(page(2)));
    assert_eq!(pg.read(), Some(page(2)), "the page, not a zero one");
}

#[test]
fn a_zero_page_is_restored_from_a_single_entry() {
    let pool = pool();
    let pg = Page::resident(vec![0u8; PAGE_SIZE]);
    reclaim(&pool, &pg, 1);
    assert_eq!(pool.lock().unwrap().stats().live_bytes, 0, "a same-filled page keeps no bytes");
    assert_eq!(fault(&pool, &pg, &AtomicBool::new(false)), Fate::Restored(vec![0u8; PAGE_SIZE]));
}

#[test]
fn an_empty_slot_is_a_zero_page_and_the_pool_is_not_asked() {
    let pool = pool();
    // A stale entry under the key, as a reclaimer that lost its race leaves for
    // a moment: no marker, so no restore.
    store(&pool, &page(9));
    let pg = Page::empty();
    assert_eq!(fault(&pool, &pg, &AtomicBool::new(false)), Fate::Zero);
    assert_eq!(pool.lock().unwrap().len(), 1, "and the entry is not touched");
}

#[test]
fn a_fault_racing_a_store_waits_and_restores_the_page() {
    let pool = pool();
    let pg = Page::resident(page(5));
    let waits = AtomicBool::new(false);
    // The reclaimer has the page out and has not stored it.
    let original = out(&pg, 7);
    let fate = std::thread::scope(|s| {
        let faulting = s.spawn(|| fault(&pool, &pg, &waits));
        // The fault is in its wait before the store goes on.
        wait_for(&waits);
        let gen = store(&pool, &pg.bytes_of(Pte(original).phys_addr()));
        assert!(publish(&SlotWords, &pg.slot, 7, PageMarker::Compressed, gen));
        faulting.join().unwrap()
    });
    assert!(waits.load(Ordering::Acquire), "the fault waited for the store");
    assert_eq!(fate, Fate::Restored(page(5)), "and then restored the page, not a zero one");
}

#[test]
fn a_fault_racing_a_store_that_gives_up_finds_the_page_where_it_was() {
    let pool = pool();
    let pg = Page::resident(page(6));
    let waits = AtomicBool::new(false);
    let original = out(&pg, 2);
    std::thread::scope(|s| {
        let faulting = s.spawn(|| fault(&pool, &pg, &waits));
        wait_for(&waits);
        // The pool refused: the page goes back (`DomainReclaim::keep`).
        let put = put_back_page(&pg.slot, 2, FRAME, || pg.leaf.compare_exchange(0, original, Ordering::AcqRel, Ordering::Acquire).is_ok());
        assert_eq!(put, PutBack::Back);
        assert_eq!(faulting.join().unwrap(), Fate::Present, "the fault retries on the page");
    });
    assert_eq!(pg.read(), Some(page(6)));
}

/// **A failed store writes no leaf for a slot that is not its own.** The range
/// was unmapped while the store ran (the slot emptied), maybe mapped again and
/// touched (another frame in the slot): the put-back looks at the slot first
/// and writes nothing, so no translation of the frame it then frees exists.
/// Canary `keep-leaf-first-canary`: the leaf is written first.
#[test]
fn a_failed_store_writes_no_leaf_for_a_slot_that_is_not_its_own() {
    for now in [slot::EMPTY, slot::frame(FRAME + PAGE_SIZE), slot::marker(PageMarker::InTransit, 8)] {
        let s = AtomicU64::new(now);
        let mut wrote = false;
        assert_eq!(put_back_page(&s, 7, FRAME, || { wrote = true; true }), PutBack::NotMine);
        assert!(!wrote, "a leaf was written for a slot that is {now:#x}");
        assert_eq!(s.load(Ordering::Acquire), now);
    }
}

#[test]
fn a_failed_store_puts_its_page_back_or_empties_the_slot() {
    let s = AtomicU64::new(slot::marker(PageMarker::InTransit, 7));
    assert_eq!(put_back_page(&s, 7, FRAME, || true), PutBack::Back);
    assert_eq!(s.load(Ordering::Acquire), slot::frame(FRAME));
    // The leaf could not be written: the slot is not left in transit for good.
    let s = AtomicU64::new(slot::marker(PageMarker::InTransit, 7));
    assert_eq!(put_back_page(&s, 7, FRAME, || false), PutBack::Emptied);
    assert_eq!(s.load(Ordering::Acquire), slot::EMPTY);
}

/// Spin until the fault has been seen waiting; a fault that never waits (it
/// zero-filled, or restored an empty copy) fails the row instead of hanging it.
fn wait_for(waits: &AtomicBool) {
    for _ in 0..50_000_000u32 {
        if waits.load(Ordering::Acquire) {
            return;
        }
        std::thread::yield_now();
    }
    panic!("the fault never waited for the store");
}

#[test]
fn only_a_resident_slot_is_taken_out() {
    for w in [slot::EMPTY, slot::marker(PageMarker::Compressed, 4), slot::marker(PageMarker::Swapped, 4), slot::marker(PageMarker::InTransit, 4)] {
        let s = AtomicU64::new(w);
        assert_eq!(take_out(&SlotWords, &s, 1), Err(Refusal::NotVictim), "{w:#x}");
        assert_eq!(s.load(Ordering::Acquire), w, "{w:#x} is left as it was");
    }
    let s = AtomicU64::new(slot::frame(FRAME));
    assert_eq!(take_out(&SlotWords, &s, 1), Ok(slot::frame(FRAME)));
    assert_eq!(resolve(s.load(Ordering::Acquire), None), Some(Resolve::Wait));
}

#[test]
fn only_a_plain_user_leaf_is_a_victim() {
    let cow = leaf_on(FRAME) | PteFlags::COW.bits();
    let kernel = Pte::new(FRAME, PteFlags::KERNEL_RW).0;
    let table = Pte::new(0x8030_0000, PteFlags::VALID).0;
    let invalid = PteFlags::USER.bits() | PteFlags::READ.bits();
    for (w, what) in [(0, "empty"), (cow, "a COW leaf"), (kernel, "a kernel leaf"), (table, "a table"), (invalid, "an invalid word")] {
        assert!(!Rv.is_victim_leaf(w), "{what}");
    }
    assert!(Rv.is_victim_leaf(leaf_on(FRAME)));
}

#[test]
fn slot_words_round_trip() {
    assert_eq!(slot::decode(slot::EMPTY), Some(slot::Slot::Empty));
    assert_eq!(slot::decode(slot::frame(FRAME)), Some(slot::Slot::Frame(FRAME)));
    for kind in [PageMarker::Compressed, PageMarker::Swapped, PageMarker::InTransit] {
        let w = slot::marker(kind, u32::MAX);
        assert_eq!(slot::decode(w), Some(slot::Slot::Marker(kind, u32::MAX)));
        assert_eq!(slot::frame_of(w), None, "a marker names no frame");
    }
    assert_eq!(slot::decode(0b11 << 3), None, "no encoder makes a word with no kind");
}

#[test]
fn a_store_ends_only_its_own_marker() {
    let s = AtomicU64::new(slot::frame(FRAME));
    take_out(&SlotWords, &s, 10).unwrap();
    let mine = s.load(Ordering::Acquire);
    // Another store's ticket: the slot is not touched.
    assert!(!publish(&SlotWords, &s, 11, PageMarker::Compressed, 5));
    assert!(!put_back(&SlotWords, &s, 11, slot::frame(FRAME)));
    assert_eq!(s.load(Ordering::Acquire), mine);
    // The page went (unmapped) and came back to be taken out by a later store:
    // the first store's end must not finish the second's marker.
    assert!(clear(&SlotWords, &s).is_some());
    assert_eq!(s.load(Ordering::Acquire), slot::EMPTY);
    s.store(slot::frame(FRAME), Ordering::Release);
    take_out(&SlotWords, &s, 12).unwrap();
    assert!(!publish(&SlotWords, &s, 10, PageMarker::Compressed, 5), "the first store's late end");
    assert!(publish(&SlotWords, &s, 12, PageMarker::Compressed, 5));
}

#[test]
fn munmap_clears_every_kind_of_marker() {
    for kind in [PageMarker::Compressed, PageMarker::Swapped, PageMarker::InTransit] {
        let s = AtomicU64::new(slot::marker(kind, 77));
        assert_eq!(clear(&SlotWords, &s), Some((kind, 77)));
        assert_eq!(s.load(Ordering::Acquire), slot::EMPTY, "{kind:?}: the page is empty again");
    }
    // And nothing else: a resident page and an empty slot stay.
    for w in [slot::frame(FRAME), slot::EMPTY] {
        let s = AtomicU64::new(w);
        assert_eq!(clear(&SlotWords, &s), None);
        assert_eq!(s.load(Ordering::Acquire), w);
    }
}

#[test]
fn a_store_whose_range_was_unmapped_cannot_publish_or_put_back() {
    let s = AtomicU64::new(slot::frame(FRAME));
    let original = take_out(&SlotWords, &s, 3).unwrap();
    assert_eq!(clear(&SlotWords, &s), Some((PageMarker::InTransit, 3)), "munmap while the store runs");
    assert!(!publish(&SlotWords, &s, 3, PageMarker::Compressed, 1));
    assert!(!put_back(&SlotWords, &s, 3, original), "the frame is the store's to free");
    assert_eq!(s.load(Ordering::Acquire), slot::EMPTY);
}

#[test]
fn a_marker_never_restores_another_stores_copy() {
    let pool = pool();
    let pg = Page::resident(page(1));
    let (_, first) = reclaim(&pool, &pg, 1);
    // The first copy is restored and dropped; the page is written and stored
    // again: a second entry, a second generation, the same key.
    assert_eq!(fault(&pool, &pg, &AtomicBool::new(false)), Fate::Restored(page(1)));
    let f = Pte(pg.leaf.load(Ordering::Acquire)).phys_addr();
    pg.mem.lock().unwrap().insert(f, page(2));
    let (_, second) = reclaim(&pool, &pg, 2);
    assert_ne!(first, second);
    let mut scratch = vec![0u8; PAGE_SIZE];
    // A fault that read the first marker and is late with its fetch is told so,
    // and does not take the page's newer contents for its own.
    assert_eq!(pool.lock().unwrap().fetch_named(OBJ, PG, first, &mut scratch), Lookup::Wrong);
    // The entry names the Domain slot it was stored for: the restore's charge.
    assert!(matches!(pool.lock().unwrap().fetch_named(OBJ, PG, second, &mut scratch), Lookup::Page(_, _, o) if usize::from(o) == OWN));
    assert_eq!(pool.lock().unwrap().fetch_named(OBJ, PG + 1, second, &mut scratch), Lookup::Gone);
}

#[test]
fn a_forks_child_restores_through_the_parents_marker_word() {
    let pool = pool();
    let parent = Page::resident(page(4));
    let (_, gen) = reclaim(&pool, &parent, 1);
    let child_obj = OBJ + 1;
    {
        let mut p = pool.lock().unwrap();
        assert_eq!(p.dup_obj(OBJ, child_obj), Ok(1));
        // The parent's marker word names the child's entry too.
        let mut scratch = vec![0u8; PAGE_SIZE];
        // ...and the entry is charged to the Domain the parent's is: the one a
        // restore in the child charges back.
        assert!(matches!(p.fetch_named(child_obj, PG, gen, &mut scratch), Lookup::Page(_, _, o) if usize::from(o) == OWN));
        assert_eq!(p.gen_of(child_obj, PG), Some(gen));
    }
    // The child restores; the parent's copy is untouched.
    {
        let mut p = pool.lock().unwrap();
        assert!(p.remove_if(child_obj, PG, gen));
        assert!(p.gen_of(OBJ, PG).is_some());
    }
    assert_eq!(fault(&pool, &parent, &AtomicBool::new(false)), Fate::Restored(page(4)));
}

#[test]
fn a_page_in_a_swapped_segment_is_told_from_one_that_is_not() {
    // The pool answers `Parked` for a page whose segment is on the swap area;
    // `Swapped` markers are the fast path to that answer, and `parked_from` is
    // how the pager finds the pages whose markers to change.
    type S = Pool<Heap, 64, 128, 2, 2, SEG, 0, 2, 2, 0>;
    let mut pool = S::new(Heap);
    assert!(pool.swap_attach(2));
    let mut scratch = vec![0u8; PAGE_SIZE];
    // About twenty-one of the test pages fill a segment; thirty spill into the second.
    let mut gens = Vec::new();
    for pg in 0..30u64 {
        match codec().pack(&page(pg as u32), &mut scratch).unwrap() {
            Packed::Blob { len, nonce } => pool.insert_blob(OWN, OBJ, pg, nonce, &scratch[..len]).unwrap(),
            other => panic!("{other:?}"),
        }
        gens.push(pool.gen_of(OBJ, pg).unwrap());
    }
    let pick = pool.swap_pick(&|_| false).expect("the first segment is full");
    let mut image = vec![0u8; SEG];
    pool.swap_stage(&pick, &mut image).unwrap();
    pool.swap_commit(&pick).unwrap();

    let mut listed = [super::zpool::Stored { obj: 0, page: 0, gen: 0 }; 4];
    let mut parked = Vec::new();
    let mut at = 0;
    loop {
        let (n, next) = pool.parked_from(at, &mut listed);
        parked.extend(listed[..n].iter().map(|s| (s.page, s.gen)));
        match next {
            Some(i) => at = i,
            None => break,
        }
    }
    assert!(parked.len() > 4, "the listing is longer than its buffer: it went on in pieces");
    assert!(parked.len() < 30, "the second segment is still in memory");
    for &(pg, gen) in &parked {
        assert_eq!(gens[pg as usize], gen, "the listing carries the entry's generation");
        assert_eq!(pool.fetch_named(OBJ, pg, gen, &mut scratch), Lookup::Parked);
    }
    let mut resident = 0;
    for pg in (0..30u64).filter(|pg| !parked.iter().any(|p| p.0 == *pg)) {
        assert!(matches!(pool.fetch_named(OBJ, pg, gens[pg as usize], &mut scratch), Lookup::Page(..)));
        resident += 1;
    }
    assert_eq!(resident + parked.len(), 30);
}

// ── The pass ─────────────────────────────────────────────────────────────────

/// Stages that log what they were asked and answer from a script.
struct Script {
    log: Vec<&'static str>,
    compress: Vec<Round>,
    swap: Vec<bool>,
    low: bool,
}

impl Stages for Script {
    fn purge(&mut self) {
        self.log.push("purge");
    }
    fn page_cache(&mut self) {
        self.log.push("cache");
    }
    fn compress(&mut self) -> Round {
        self.log.push("compress");
        if self.compress.is_empty() { Round::default() } else { self.compress.remove(0) }
    }
    fn swap(&mut self) -> bool {
        self.log.push("swap");
        if self.swap.is_empty() { false } else { self.swap.remove(0) }
    }
    fn still_low(&mut self) -> bool {
        self.log.push("low?");
        self.low
    }
}

fn round(stored: u32, full: bool) -> Round {
    Round { stored, full }
}

#[test]
fn the_pass_runs_purge_then_cache_then_compression_then_swap_only_when_full() {
    // Compression does the job: no swap.
    let mut s = Script { log: vec![], compress: vec![round(8, false)], swap: vec![], low: false };
    reclaim_pass(&mut s, 8);
    assert_eq!(s.log, ["purge", "cache", "compress", "low?"]);

    // The pool fills: one segment goes to swap, compression is asked again.
    let mut s = Script { log: vec![], compress: vec![round(4, true), round(6, false)], swap: vec![true], low: false };
    reclaim_pass(&mut s, 8);
    assert_eq!(s.log, ["purge", "cache", "compress", "swap", "compress", "low?"]);

    // Nothing to swap: the pass ends at the full pool.
    let mut s = Script { log: vec![], compress: vec![round(2, true)], swap: vec![false], low: true };
    reclaim_pass(&mut s, 8);
    assert_eq!(s.log, ["purge", "cache", "compress", "swap"]);

    // Still low after a round that stored pages: another round, and not before.
    let mut s = Script { log: vec![], compress: vec![round(3, false), round(3, false)], swap: vec![], low: true };
    s.low = true;
    reclaim_pass(&mut s, 2);
    assert_eq!(s.log, ["purge", "cache", "compress", "low?", "compress", "low?"]);

    // A round that stored nothing and is not full ends it.
    let mut s = Script { log: vec![], compress: vec![round(0, false)], swap: vec![true], low: true };
    reclaim_pass(&mut s, 8);
    assert_eq!(s.log, ["purge", "cache", "compress"]);
}

#[test]
fn a_pass_is_bounded() {
    let mut s = Script { log: vec![], compress: vec![round(1, false); 50], swap: vec![], low: true };
    assert_eq!(reclaim_pass(&mut s, 5), 5);
    assert_eq!(s.log.iter().filter(|e| **e == "compress").count(), 5);
    // Swap rounds count against the bound too.
    let mut s = Script { log: vec![], compress: vec![round(1, true); 50], swap: vec![true; 50], low: true };
    assert_eq!(reclaim_pass(&mut s, 3), 3);
}

// ── The Domain's watermarks ──────────────────────────────────────────────────

#[test]
fn a_rows_limit_sets_the_domains_watermarks() {
    let b = PageBudget::new();
    b.set_limit_marked(1000, 85, 65);
    assert_eq!((b.low(), b.high(), b.limit()), (650, 850, 1000));
    // A charge crossing the high mark is over; below it is not.
    b.charge(849);
    assert!(!b.over_high());
    b.charge(1);
    assert!(b.over_high(), "850 pages of 1000 is the high watermark");
    // The kernel's percentages: the marks are `watermarks_for` of the limit.
    let k = PageBudget::new();
    let (hi, lo) = (azos_limits::MM_RECLAIM_HIGH_PCT as u32, azos_limits::MM_RECLAIM_LOW_PCT as u32);
    k.set_limit_marked(4096, hi, lo);
    assert_eq!((k.low(), k.high()), super::budget::watermarks_for(4096, hi, lo));
    // Reclaim off (percentages 0): no marks, and no storm ever starts.
    let off = PageBudget::new();
    off.set_limit_marked(1000, 0, 0);
    assert_eq!((off.low(), off.high()), (0, 0));
    // A limit too small to take a percentage of still has a watermark.
    let tiny = PageBudget::new();
    tiny.set_limit_marked(3, 85, 65);
    assert!(tiny.high() >= 1 && tiny.low() < tiny.high());
}

#[test]
fn a_limit_without_marks_has_none() {
    let b = PageBudget::new();
    b.set_limit_marked(1000, 85, 65);
    b.set_limit(1000);
    assert_eq!((b.low(), b.high()), (0, 0), "a limit declared without marks keeps none of the old ones");
    b.set_limit_marked(1000, 85, 65);
    b.set_limit(0);
    assert_eq!((b.low(), b.high(), b.limit()), (0, 0, 0), "no limit, no marks: a reused slot never reclaims");
    b.set_limit_marked(0, 85, 65);
    assert_eq!((b.low(), b.high()), (0, 0));
    assert!(!b.over_high());
}
