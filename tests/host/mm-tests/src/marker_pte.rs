// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the page markers the reclaimer leaves in a page's slot
//! (Kconfig `MM_RECLAIM_COMPRESS`): the protocol of `zpool.rs`
//! ([`take_out`], [`publish`], [`put_back`], [`clear`], [`classify`]) over the
//! real pool and codec, with the RISC-V encoding of the shim's real `mmu.rs` for
//! the words, the generation checks of `Pool::fetch_named`, the stage order of
//! `reclaim_pass`, and the Domain watermarks `PageBudget::set_limit_marked`
//! derives from a row's limit.
//!
//! **What is real and what is a model.** The protocol functions, the pool, the
//! codec, the pass and the budget are the shipping code. The fault and the
//! reclaimer below are the order `pager.rs` runs them in (`resolve_fault`,
//! `AnonReclaim`), written out over a slot that is an `AtomicU64` and a
//! "frame" that is a `Vec`: `pager.rs` itself needs the page allocator, the
//! scheduler's wait queue and a live MMU, and is exercised by the boot gate
//! (not run in this front: no QEMU).
//!
//! Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
//! * `classify` answering `Zero` for an `InTransit` marker:
//!   `a_fault_racing_a_store_waits_and_restores_the_page` red (it zero-fills,
//!   the stored copy is orphaned).
//! * `take_out` not checking `is_victim_leaf` (a COW leaf, a marker):
//!   `only_a_plain_user_leaf_is_taken_out` red.
//! * `publish` / `put_back` not comparing the ticket (swapping from whatever
//!   marker is there): `a_store_ends_only_its_own_marker` red.
//! * `Pool::fetch_named` not comparing the generation:
//!   `a_marker_never_restores_another_stores_copy` red.
//! * `Pool::dup_obj` giving the child a new generation:
//!   `a_forks_child_restores_through_the_parents_marker_word` red.
//! * `clear` leaving an `InTransit` marker: `munmap_clears_every_kind_of_marker` red.
//! * `reclaim_pass` swapping before compressing, or without a `full` round:
//!   `the_pass_runs_purge_then_cache_then_compression_then_swap_only_when_full` red.
//! * `reclaim_pass` not running `purge` first (or at all): the same row red (2026-10-20).
//! * `reclaim_pass` ignoring `max_rounds`: `a_pass_is_bounded` red.
//! * `PageBudget::set_limit` leaving the old marks: `a_limit_without_marks_has_none` red.
//! * `set_limit_marked` taking the percentages the wrong way round:
//!   `a_rows_limit_sets_the_domains_watermarks` red.
//!
//! The one arch seam not run here is the x86_64 and aarch64 word encoding: it
//! has its rows in `tests/host/arch-tests/src/marker_pte.rs`.

use super::budget::PageBudget;
use super::zpool::{
    classify, clear, fill_page, publish, put_back, reclaim_pass, take_out, Backing, Codec, Fault, Fetched,
    Lookup, Packed, PageWords, Pool, Refusal, Round, Stages,
};
use azos_arch::mmu::{self as rv, Pte, PteFlags};
use azos_arch_api::{PageMarker, PAGE_SIZE};
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// The words of the RISC-V encoding the shim's real `mmu.rs` builds. The
/// kernel's blanket impl over `Mmu` is the same four functions on the real
/// trait.
struct Rv;

impl PageWords for Rv {
    fn is_valid(&self, w: u64) -> bool {
        Pte(w).is_valid()
    }
    fn is_victim_leaf(&self, w: u64) -> bool {
        let p = Pte(w);
        p.is_valid() && p.is_leaf() && p.flags().contains(PteFlags::USER) && !p.flags().contains(PteFlags::COW)
    }
    fn make_marker(&self, kind: PageMarker, payload: u32) -> u64 {
        rv::make_marker(kind.code(), payload)
    }
    fn marker(&self, w: u64) -> Option<(PageMarker, u32)> {
        let (code, payload) = rv::marker_of(w)?;
        Some((PageMarker::from_code(code)?, payload))
    }
}

/// A resident user page's leaf.
fn leaf() -> u64 {
    Pte::new(0x8020_0000, PteFlags::USER_RW | PteFlags::ACCESSED | PteFlags::DIRTY).0
}

/// The reclaimer's store of the page in `frame` whose slot is `slot`, in the
/// order `AnonReclaim` runs it: take it out, pack and insert, publish. The
/// leaf that was replaced and the entry's generation.
fn reclaim(pool: &Mutex<P>, slot: &AtomicU64, frame: &[u8], ticket: u32) -> (u64, u32) {
    let original = take_out(&Rv, slot, ticket).expect("a plain user leaf");
    let gen = store(pool, frame);
    assert!(publish(&Rv, slot, ticket, PageMarker::Compressed, gen), "the store's own marker");
    (original, gen)
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
}

/// One fault on `slot` as `resolve_fault` runs it: decide from the word, wait
/// while a store is in flight (`waits` counts the looks), restore the marked
/// page and install it over exactly the word it read, then drop the pool's copy
/// by generation.
fn fault(pool: &Mutex<P>, slot: &AtomicU64, waits: &AtomicBool) -> Fate {
    loop {
        let seen = slot.load(Ordering::Acquire);
        match classify(&Rv, seen) {
            Fault::Zero => return Fate::Zero,
            Fault::Wait => {
                waits.store(true, Ordering::Release);
                std::thread::yield_now();
            }
            Fault::Restore(_, gen) => {
                let mut scratch = vec![0u8; PAGE_SIZE];
                let mut out = vec![0u8; PAGE_SIZE];
                let got = pool.lock().unwrap().fetch_named(OBJ, PG, gen, &mut scratch);
                let Lookup::Page(what, g, _) = got else { panic!("the marker's entry: {got:?}") };
                match what {
                    Fetched::Fill(w) => fill_page(w, &mut out),
                    Fetched::Blob { len, nonce } => codec().unpack(nonce, len, &mut scratch, &mut out).unwrap(),
                }
                // Install over the word read; a changed slot starts over.
                if slot.compare_exchange(seen, leaf(), Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    pool.lock().unwrap().remove_if(OBJ, PG, g);
                    return Fate::Restored(out);
                }
            }
            other => panic!("not a fault of this row: {other:?}"),
        }
    }
}

fn pool() -> Mutex<P> {
    Mutex::new(P::new(Heap))
}

#[test]
fn a_fault_on_a_compressed_marker_restores_the_page() {
    let pool = pool();
    let slot = AtomicU64::new(leaf());
    let data = page(3);
    let (_, gen) = reclaim(&pool, &slot, &data, 1);
    let word = slot.load(Ordering::Acquire);
    assert!(!Pte(word).is_valid(), "the page is out of the table");
    assert_eq!(Rv.marker(word), Some((PageMarker::Compressed, gen)));

    assert_eq!(fault(&pool, &slot, &AtomicBool::new(false)), Fate::Restored(data));
    assert_eq!(slot.load(Ordering::Acquire), leaf(), "installed over the marker");
    assert!(pool.lock().unwrap().is_empty(), "the copy goes with the install");
}

#[test]
fn a_zero_page_is_restored_from_a_single_entry() {
    let pool = pool();
    let slot = AtomicU64::new(leaf());
    let zeros = vec![0u8; PAGE_SIZE];
    reclaim(&pool, &slot, &zeros, 1);
    assert_eq!(pool.lock().unwrap().stats().live_bytes, 0, "a same-filled page keeps no bytes");
    assert_eq!(fault(&pool, &slot, &AtomicBool::new(false)), Fate::Restored(zeros));
}

#[test]
fn an_empty_slot_is_a_zero_page_and_the_pool_is_not_asked() {
    let pool = pool();
    // A stale entry under the key, as a reclaimer that lost its race leaves for
    // a moment: no marker, so no restore.
    store(&pool, &page(9));
    let slot = AtomicU64::new(0);
    assert_eq!(fault(&pool, &slot, &AtomicBool::new(false)), Fate::Zero);
    assert_eq!(pool.lock().unwrap().len(), 1, "and the entry is not touched");
}

#[test]
fn a_fault_racing_a_store_waits_and_restores_the_page() {
    let pool = pool();
    let slot = AtomicU64::new(leaf());
    let data = page(5);
    let waits = AtomicBool::new(false);
    // The reclaimer has the page out and has not stored it.
    take_out(&Rv, &slot, 7).unwrap();
    let fate = std::thread::scope(|s| {
        let faulting = s.spawn(|| fault(&pool, &slot, &waits));
        // The fault is in its wait before the store goes on.
        wait_for(&waits);
        let gen = store(&pool, &data);
        assert!(publish(&Rv, &slot, 7, PageMarker::Compressed, gen));
        faulting.join().unwrap()
    });
    assert!(waits.load(Ordering::Acquire), "the fault waited for the store");
    assert_eq!(fate, Fate::Restored(data), "and then restored the page, not a zero one");
}

#[test]
fn a_fault_racing_a_store_that_gives_up_finds_the_page_where_it_was() {
    let slot = AtomicU64::new(leaf());
    let waits = AtomicBool::new(false);
    let original = take_out(&Rv, &slot, 2).unwrap();
    std::thread::scope(|s| {
        let faulting = s.spawn(|| classify_until_not_wait(&slot, &waits));
        wait_for(&waits);
        // The pool refused: the page goes back.
        assert!(put_back(&Rv, &slot, 2, original));
        assert_eq!(faulting.join().unwrap(), Fault::Present, "the fault retries on the page");
    });
    assert_eq!(slot.load(Ordering::Acquire), original);
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

fn classify_until_not_wait(slot: &AtomicU64, waits: &AtomicBool) -> Fault {
    loop {
        match classify(&Rv, slot.load(Ordering::Acquire)) {
            Fault::Wait => {
                waits.store(true, Ordering::Release);
                std::thread::yield_now();
            }
            f => return f,
        }
    }
}

#[test]
fn only_a_plain_user_leaf_is_taken_out() {
    let marker = rv::make_marker(PageMarker::Compressed.code(), 4);
    let cow = leaf() | PteFlags::COW.bits();
    let kernel = Pte::new(0x8020_0000, PteFlags::KERNEL_RW).0;
    let table = Pte::new(0x8030_0000, PteFlags::VALID).0;
    let demand = PteFlags::DEMAND.bits() | PteFlags::USER.bits() | PteFlags::READ.bits();
    for (w, what) in [(0, "empty"), (marker, "a marker"), (cow, "a COW leaf"), (kernel, "a kernel leaf"), (table, "a table"), (demand, "a demand word")] {
        let slot = AtomicU64::new(w);
        assert_eq!(take_out(&Rv, &slot, 1), Err(Refusal::NotVictim), "{what}");
        assert_eq!(slot.load(Ordering::Acquire), w, "{what} is left as it was");
    }
    let slot = AtomicU64::new(leaf());
    assert_eq!(take_out(&Rv, &slot, 1), Ok(leaf()));
    assert_eq!(classify(&Rv, slot.load(Ordering::Acquire)), Fault::Wait);
}

#[test]
fn a_store_ends_only_its_own_marker() {
    let slot = AtomicU64::new(leaf());
    take_out(&Rv, &slot, 10).unwrap();
    let mine = slot.load(Ordering::Acquire);
    // Another store's ticket: the slot is not touched.
    assert!(!publish(&Rv, &slot, 11, PageMarker::Compressed, 5));
    assert!(!put_back(&Rv, &slot, 11, leaf()));
    assert_eq!(slot.load(Ordering::Acquire), mine);
    // The page went (unmapped) and came back to be taken out by a later store:
    // the first store's end must not finish the second's marker.
    assert!(clear(&Rv, &slot).is_some());
    assert_eq!(slot.load(Ordering::Acquire), 0);
    slot.store(leaf(), Ordering::Release);
    take_out(&Rv, &slot, 12).unwrap();
    assert!(!publish(&Rv, &slot, 10, PageMarker::Compressed, 5), "the first store's late end");
    assert!(publish(&Rv, &slot, 12, PageMarker::Compressed, 5));
}

#[test]
fn munmap_clears_every_kind_of_marker() {
    for kind in [PageMarker::Compressed, PageMarker::Swapped, PageMarker::InTransit] {
        let slot = AtomicU64::new(rv::make_marker(kind.code(), 77));
        assert_eq!(clear(&Rv, &slot), Some((kind, 77)));
        assert_eq!(slot.load(Ordering::Acquire), 0, "{kind:?}: the range is vacant again");
    }
    // And nothing else: a resident page and a demand reservation stay.
    for w in [leaf(), PteFlags::DEMAND.bits(), 0] {
        let slot = AtomicU64::new(w);
        assert_eq!(clear(&Rv, &slot), None);
        assert_eq!(slot.load(Ordering::Acquire), w);
    }
}

#[test]
fn a_store_whose_range_was_unmapped_cannot_publish_or_put_back() {
    let slot = AtomicU64::new(leaf());
    let original = take_out(&Rv, &slot, 3).unwrap();
    assert_eq!(clear(&Rv, &slot), Some((PageMarker::InTransit, 3)), "munmap while the store runs");
    assert!(!publish(&Rv, &slot, 3, PageMarker::Compressed, 1));
    assert!(!put_back(&Rv, &slot, 3, original), "the frame is the store's to free");
    assert_eq!(slot.load(Ordering::Acquire), 0);
}

#[test]
fn a_marker_never_restores_another_stores_copy() {
    let pool = pool();
    let slot = AtomicU64::new(leaf());
    let (_, first) = reclaim(&pool, &slot, &page(1), 1);
    // The first copy is restored and dropped; the page is written and stored
    // again: a second entry, a second generation, the same key.
    assert_eq!(fault(&pool, &slot, &AtomicBool::new(false)), Fate::Restored(page(1)));
    let (_, second) = reclaim(&pool, &slot, &page(2), 2);
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
    let parent = AtomicU64::new(leaf());
    let (_, gen) = reclaim(&pool, &parent, &page(4), 1);
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
