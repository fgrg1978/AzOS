// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the reclaimer's page generations (`crates/core/mm/src/aging.rs`,
//! Kconfig `MM_RECLAIM_COMPRESS`): the table the shipping code keeps, and the
//! storm loop (`zpool::run_storm`) over the real `Pool` and `Codec` taking its
//! victims from it.
//!
//! **What is real and what is a model.** `AgeTable`, the pool, the codec, the
//! budget and the loop are the shipping code. The address space is a model: a
//! `Vec` of pages with an Accessed flag each, standing for what
//! `pager::age_space` reads through `Mmu::harvest_accessed` (the walk of the
//! page tables behind it needs a live MMU; the harvest itself has its rows in
//! `tests/host/arch-api-tests/src/aging.rs`) and for what
//! `pager::AnonReclaim` does with a victim (`AgedSpace` below mirrors its
//! `next` / `store` / `free`: it takes the order from the table, marks a page
//! the coder gave up on, and forgets a page that left).
//!
//! Canaries (by hand, 2026-10-20; discriminates / does not / did not compile;
//! all five variants compiled and went red on the rows named, nothing else):
//! * `pick` walking the generations youngest first (`age = cur.level`):
//!   `reclaim_takes_the_oldest_generation_first_and_address_order_inside_it`,
//!   `a_hot_page_outlives_cold_ones_through_a_storm`,
//!   `an_incompressible_page_is_offered_once`, `pages_that_leave_are_forgotten`.
//! * `pick` ignoring the skip mask: `an_incompressible_page_is_offered_once`,
//!   `the_coder_runs_on_an_incompressible_page_once_until_it_is_touched`.
//! * `begin` / `end` treating every Domain's chunks as the pass's own:
//!   `a_pass_sweeps_only_its_own_domains_chunks`.
//! * `observe` leaving the skip flag on an accessed page:
//!   `a_touched_incompressible_page_is_offered_again`,
//!   `the_coder_runs_on_an_incompressible_page_once_until_it_is_touched`.
//! * the saturating step `older1 = a1 | a0` as an XOR (a plain increment that
//!   wraps 3 to 0): `an_idle_page_stops_at_the_oldest_generation`,
//!   `a_page_used_goes_back_to_the_youngest_generation`,
//!   `pages_that_leave_are_forgotten`.
//! * `retain_owners` keeping every chunk (or dropping the kept ones):
//!   `chunks_of_a_domain_no_longer_aged_are_released`.

use super::aging::{AgeTable, Cursor, FIRST_IDLE, OLDEST};
use super::budget::PageBudget;
use super::zpool::{run_storm, Backing, Codec, Error, Packed, Pool, Reclaimee};
use azos_arch_api::PAGE_SIZE;
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;

const SP: usize = 0x8000_0000;
const OWN: usize = 1;

type T = AgeTable<8>;

/// One pass over chunk `chunk` of `SP` with every page in scope.
fn pass(t: &mut T, chunk: u32, resident: u64, accessed: u64) {
    t.begin(OWN);
    assert!(t.observe(OWN, SP, chunk, u64::MAX, resident, accessed));
    t.end(OWN);
}

fn picks(t: &T, spaces: &[usize]) -> Vec<usize> {
    let mut cur = Cursor::default();
    let mut v = vec![];
    while let Some((_, page)) = t.pick(&mut cur, spaces) {
        v.push(page);
    }
    v
}

/// A page first seen untouched starts one short of the oldest; one first seen
/// used starts youngest.
#[test]
fn a_new_page_starts_young_if_used_and_one_short_of_oldest_if_not() {
    let mut t = T::new();
    pass(&mut t, 0, 0b11, 0b01);
    assert_eq!(t.age_of(SP, 0), Some(0));
    assert_eq!(t.age_of(SP, 1), Some(FIRST_IDLE));
    assert_eq!(t.age_of(SP, 2), None, "a page that was not resident is not tracked");
}

/// Each pass without a use makes a page one generation older, and it stops at
/// the oldest instead of wrapping to the youngest.
#[test]
fn an_idle_page_stops_at_the_oldest_generation() {
    let mut t = T::new();
    pass(&mut t, 0, 1, 0);
    assert_eq!(t.age_of(SP, 0), Some(2));
    for _ in 0..5 {
        pass(&mut t, 0, 1, 0);
        assert_eq!(t.age_of(SP, 0), Some(OLDEST));
    }
}

#[test]
fn a_page_used_goes_back_to_the_youngest_generation() {
    let mut t = T::new();
    for _ in 0..3 {
        pass(&mut t, 0, 0b111, 0);
    }
    assert_eq!(t.age_of(SP, 1), Some(OLDEST));
    pass(&mut t, 0, 0b111, 0b010);
    assert_eq!((t.age_of(SP, 0), t.age_of(SP, 1), t.age_of(SP, 2)), (Some(3), Some(0), Some(3)));
    pass(&mut t, 0, 0b111, 0);
    assert_eq!(t.age_of(SP, 1), Some(1), "and ages again from there");
}

/// Pages 0..5: 1 is used in the first pass, 3 in the second.
fn five() -> T {
    let mut t = T::new();
    pass(&mut t, 0, 0b11111, 0b00010);
    pass(&mut t, 0, 0b11111, 0b01000);
    t
}

#[test]
fn reclaim_takes_the_oldest_generation_first_and_address_order_inside_it() {
    let t = five();
    assert_eq!(
        (0..5).map(|p| t.age_of(SP, p).unwrap()).collect::<Vec<_>>(),
        vec![3, 1, 3, 0, 3],
        "page 1 aged once since its use, page 3 not at all, the rest are idle"
    );
    assert_eq!(picks(&t, &[SP]), vec![0, 2, 4, 1, 3], "age 3 by address, then 1, then 0");
}

/// A page is answered once per walk, so a storm that keeps it (busy, or it did
/// not compress) does not spin on it.
#[test]
fn the_cursor_never_hands_a_page_back() {
    let t = five();
    let mut cur = Cursor::default();
    let mut seen = vec![];
    while let Some((_, p)) = t.pick(&mut cur, &[SP]) {
        assert!(!seen.contains(&p));
        seen.push(p);
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(t.pick(&mut cur, &[SP]), None, "and the end stays the end");
}

/// Only the spaces the storm names: another Domain's pages are not its victims.
#[test]
fn only_the_named_spaces_are_offered() {
    let mut t = T::new();
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, u64::MAX, 0b1, 0));
    assert!(t.observe(2, SP + 0x1000_0000, 0, u64::MAX, 0b11, 0));
    assert_eq!(picks(&t, &[SP]), vec![0]);
    assert_eq!(picks(&t, &[SP + 0x1000_0000]), vec![0, 1]);
    assert_eq!(picks(&t, &[]), Vec::<usize>::new());
}

/// Chunks are met in address order whatever order they were first seen in.
#[test]
fn chunks_come_out_in_address_order() {
    let mut t = T::new();
    t.begin(OWN);
    for chunk in [5u32, 1, 3] {
        assert!(t.observe(OWN, SP, chunk, u64::MAX, 1 << 2, 0));
    }
    assert_eq!(picks(&t, &[SP]), vec![64 + 2, 3 * 64 + 2, 5 * 64 + 2]);
    assert_eq!(t.chunks(), 3);
}

/// A page the coder gave up on is not offered again, and a pass that sees it
/// used (so possibly written) offers it again.
#[test]
fn an_incompressible_page_is_offered_once() {
    let mut t = five();
    t.mark_incompressible(SP, 2);
    assert!(t.is_incompressible(SP, 2));
    assert_eq!(picks(&t, &[SP]), vec![0, 4, 1, 3]);
    // Idle passes keep the flag.
    pass(&mut t, 0, 0b11111, 0);
    assert!(t.is_incompressible(SP, 2));
    assert!(!picks(&t, &[SP]).contains(&2));
}

#[test]
fn a_touched_incompressible_page_is_offered_again() {
    let mut t = five();
    t.mark_incompressible(SP, 2);
    pass(&mut t, 0, 0b11111, 0b00100);
    assert!(!t.is_incompressible(SP, 2));
    assert_eq!(t.age_of(SP, 2), Some(0));
    assert!(picks(&t, &[SP]).contains(&2));
    // An untracked page cannot be flagged.
    t.mark_incompressible(SP, 40);
    assert!(!t.is_incompressible(SP, 40));
}

/// A page that left (compressed, unmapped) is forgotten at once, and one that
/// the next pass finds no longer resident is forgotten there.
#[test]
fn pages_that_leave_are_forgotten() {
    let mut t = five();
    t.evicted(SP, 0);
    assert_eq!(t.age_of(SP, 0), None);
    assert_eq!(picks(&t, &[SP]), vec![2, 4, 1, 3]);
    pass(&mut t, 0, 0b10101, 0);
    assert_eq!(t.age_of(SP, 1), None);
    assert_eq!(t.age_of(SP, 3), None);
    assert_eq!(picks(&t, &[SP]), vec![2, 4, 0], "2 and 4 stayed and are oldest; page 0 came back as a new page, one short");
}

/// A pass over part of a chunk (one region of a window two regions share)
/// leaves the other part as it was.
#[test]
fn a_scope_keeps_to_its_own_pages() {
    let mut t = T::new();
    pass(&mut t, 0, 0b1111, 0);
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, 0b0011, 0b0001, 0b0001));
    assert_eq!(t.age_of(SP, 0), Some(0), "in scope and used");
    assert_eq!(t.age_of(SP, 1), None, "in scope and gone");
    assert_eq!(t.age_of(SP, 2), Some(FIRST_IDLE), "out of scope: untouched");
    assert_eq!(t.age_of(SP, 3), Some(FIRST_IDLE));
}

/// A pass drops what it did not see (a region that went away), empty chunks,
/// and only for its own Domain.
#[test]
fn a_pass_sweeps_only_its_own_domains_chunks() {
    let mut t = T::new();
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, u64::MAX, 1, 0));
    assert!(t.observe(OWN, SP, 1, u64::MAX, 1, 0));
    assert!(t.observe(2, SP + 0x1000_0000, 0, u64::MAX, 1, 0));
    assert_eq!(t.end(OWN).chunks, 2);
    assert_eq!(t.end(2).chunks, 1);
    // OWN's next pass sees chunk 0 only; chunk 1 goes, the other Domain's stays.
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, u64::MAX, 1, 0));
    let tally = t.end(OWN);
    assert_eq!((tally.chunks, tally.pages), (1, 1));
    assert_eq!(t.chunks(), 2);
    assert_eq!(t.age_of(SP, 64), None);
    assert!(t.age_of(SP + 0x1000_0000, 0).is_some());
    // A chunk whose last page is gone is dropped too.
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, u64::MAX, 0, 0));
    assert_eq!(t.end(OWN), super::aging::Tally { pages: 0, chunks: 0, overflow: 0 });
    assert_eq!(t.chunks(), 1);
}

/// The chunks of a Domain nobody ages any more (it exited, is locked, or went
/// under its low watermark) leave the table, so they stop counting against
/// the chunk limit; the Domains still aged keep theirs.
#[test]
fn chunks_of_a_domain_no_longer_aged_are_released() {
    let mut t = AgeTable::<2>::new();
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, u64::MAX, 1, 0));
    assert_eq!(t.end(OWN).chunks, 1);
    t.begin(2);
    assert!(t.observe(2, SP + 0x1000_0000, 0, u64::MAX, 1, 0));
    assert_eq!(t.end(2).chunks, 1);
    // Table full: a third Domain's chunk is left out.
    t.begin(3);
    assert!(!t.observe(3, SP + 0x2000_0000, 0, u64::MAX, 1, 0));
    // Slot OWN has no live Domain any more; nothing closes its pass.
    assert_eq!(t.retain_owners(|slot| slot != OWN), 1);
    assert_eq!(t.chunks(), 1);
    assert_eq!(t.age_of(SP, 0), None);
    assert!(t.age_of(SP + 0x1000_0000, 0).is_some());
    // Room again for the newcomer.
    t.begin(3);
    assert!(t.observe(3, SP + 0x2000_0000, 0, u64::MAX, 1, 0));
    assert_eq!(t.end(3).overflow, 0);
    // Nothing to drop: nothing changes.
    assert_eq!(t.retain_owners(|_| true), 0);
    assert_eq!(t.chunks(), 2);
}

/// A full table does not track a new chunk and says so; the chunks it has are
/// as they were, and a chunk with nothing resident costs no record.
#[test]
fn a_full_table_leaves_new_chunks_out_and_says_so() {
    let mut t = AgeTable::<2>::new();
    t.begin(OWN);
    assert!(t.observe(OWN, SP, 0, u64::MAX, 1, 0));
    assert!(t.observe(OWN, SP, 1, u64::MAX, 1, 0));
    assert!(!t.observe(OWN, SP, 2, u64::MAX, 1, 0), "no room");
    assert!(t.observe(OWN, SP, 3, u64::MAX, 0, 0), "nothing resident: nothing to track");
    assert!(t.observe(OWN, SP, 1, u64::MAX, 0b11, 0), "a chunk it has is always updated");
    let tally = t.end(OWN);
    assert_eq!((tally.chunks, tally.pages, tally.overflow), (2, 3, 1));
    // The next pass starts the count again.
    t.begin(OWN);
    assert_eq!(t.end(OWN).overflow, 0);
}

/// The table costs what Kconfig says: 48 bytes per chunk.
#[test]
fn a_chunk_costs_48_bytes() {
    assert_eq!(core::mem::size_of::<AgeTable<256>>() - core::mem::size_of::<AgeTable<0>>(), 256 * 48);
}

// ── The storm loop over the table ───────────────────────────────────────────

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
type Roomy = Pool<Heap, 64, 128, 4, 2, SEG, 0>;
const KEY: [u8; 16] = *b"reclaim test key";
const OBJ: u64 = 0x0100_0007;
const P: u32 = PAGE_SIZE as u32;

fn compressible(seed: u32) -> Vec<u8> {
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

fn noise(seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..PAGE_SIZE)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// An address space of pages, as `pager::AnonReclaim` sees one: what the
/// table says is the order, `store` asks the real codec and pool, a page the
/// coder gave up on is marked, a page stored is forgotten.
struct AgedSpace {
    pool: Roomy,
    codec: Codec,
    pages: Vec<Option<Vec<u8>>>,
    /// The Accessed flags, cleared by `age`.
    used: Vec<bool>,
    table: AgeTable<4>,
    cursor: Cursor,
    /// Pages the coder was asked about, in order.
    packed: Vec<usize>,
}

impl AgedSpace {
    fn new(pages: Vec<Vec<u8>>) -> Self {
        let n = pages.len();
        AgedSpace {
            pool: Roomy::new(Heap),
            codec: Codec::new(&KEY, 75),
            pages: pages.into_iter().map(Some).collect(),
            used: vec![false; n],
            table: AgeTable::new(),
            cursor: Cursor::default(),
            packed: vec![],
        }
    }

    /// `pager::age_space` over the model: one chunk, the resident pages and the
    /// flags harvested (and cleared).
    fn age(&mut self) {
        let (mut resident, mut accessed) = (0u64, 0u64);
        for (i, p) in self.pages.iter().enumerate() {
            if p.is_some() {
                resident |= 1 << i;
                if self.used[i] {
                    accessed |= 1 << i;
                }
            }
        }
        self.used.iter_mut().for_each(|u| *u = false);
        self.table.begin(OWN);
        assert!(self.table.observe(OWN, SP, 0, u64::MAX, resident, accessed));
        self.table.end(OWN);
    }

    fn touch(&mut self, i: usize) {
        self.used[i] = true;
    }

    fn storm(&mut self, b: &PageBudget) -> Vec<usize> {
        self.cursor = Cursor::default();
        let before: Vec<usize> = (0..self.pages.len()).filter(|&i| self.pages[i].is_none()).collect();
        run_storm(b, self, false, false, 1000, P).unwrap();
        (0..self.pages.len()).filter(|&i| self.pages[i].is_none() && !before.contains(&i)).collect()
    }
}

impl Reclaimee for AgedSpace {
    type Victim = usize;
    fn next(&mut self) -> Option<usize> {
        self.table.pick(&mut self.cursor, &[SP]).map(|(_, p)| p)
    }
    fn unmap(&mut self, _: usize) -> bool {
        true
    }
    fn store(&mut self, v: usize) -> Result<u32, Error> {
        self.packed.push(v);
        let mut scratch = vec![0u8; PAGE_SIZE];
        let r = self.codec.pack(self.pages[v].as_ref().unwrap(), &mut scratch).and_then(|packed| match packed {
            Packed::Fill(w) => self.pool.insert_fill(OWN, OBJ, v as u64, w).map(|()| 0),
            Packed::Blob { len, nonce } => {
                self.pool.insert_blob(OWN, OBJ, v as u64, nonce, &scratch[..len]).map(|()| len as u32 + 8)
            }
            Packed::Skip => Err(Error::Incompressible),
        });
        if r == Err(Error::Incompressible) {
            self.table.mark_incompressible(SP, v);
        }
        r
    }
    fn free(&mut self, v: usize) {
        self.pages[v] = None;
        self.table.evicted(SP, v);
    }
    fn keep(&mut self, _: usize) {}
}

fn budget(limit: u32, low: u32, high: u32, used: u32) -> PageBudget {
    let b = PageBudget::new();
    b.set_limit(limit);
    b.set_watermarks(low, high);
    assert!(b.charge(used));
    b
}

/// Ten compressible pages; a storm needing four takes the four that went
/// longest unused, not pages 0..4.
#[test]
fn a_hot_page_outlives_cold_ones_through_a_storm() {
    let mut s = AgedSpace::new((0..10).map(compressible).collect());
    s.age();
    // Pages 0..4 are used between passes, 4..10 are not.
    for _ in 0..3 {
        (0..4).for_each(|i| s.touch(i));
        s.age();
    }
    let b = budget(20, 6, 8, 10);
    let out = s.storm(&b);
    assert_eq!(out, vec![4, 5, 6, 7], "the idle pages, not the low addresses");
    assert_eq!(b.used(), 6);
    assert!((0..4).all(|i| s.pages[i].is_some()));
}

/// Noise stays resident, the coder sees it in the first storm only, and the
/// next storm goes to the pages that do compress; touching it makes the coder
/// look again.
#[test]
fn the_coder_runs_on_an_incompressible_page_once_until_it_is_touched() {
    let mut pages: Vec<Vec<u8>> = (0..6).map(compressible).collect();
    pages[0] = noise(1);
    pages[1] = noise(2);
    let mut s = AgedSpace::new(pages);
    s.age();
    s.age();
    // 8 pages' worth over high; down to low takes 2.
    let b = budget(20, 4, 5, 6);
    let first = s.storm(&b);
    assert_eq!(first, vec![2, 3], "0 and 1 are the lowest, noise, and kept");
    assert_eq!(s.packed, vec![0, 1, 2, 3], "the coder was asked about the noise pages once");
    assert!(s.table.is_incompressible(SP, 0) && s.table.is_incompressible(SP, 1));

    // Charge back over the mark (the program grew): a second storm.
    assert!(b.charge(1) && b.charge(1) && b.charge(1));
    s.age();
    let second = s.storm(&b);
    assert_eq!(second, vec![4, 5]);
    assert_eq!(s.packed, vec![0, 1, 2, 3, 4, 5], "the noise pages were not packed again");

    // Page 0 is used: it may have changed, so it is offered again.
    s.touch(0);
    s.age();
    assert!(!s.table.is_incompressible(SP, 0));
    assert!(b.charge(3));
    let third = s.storm(&b);
    assert!(third.is_empty(), "noise again: nothing stored");
    assert_eq!(s.packed.iter().filter(|&&p| p == 0).count(), 2, "page 0 was asked once more, page 1 not");
    assert_eq!(s.packed.iter().filter(|&&p| p == 1).count(), 1);
}

/// Zero and same-filled pages are index entries: no compression, no bytes.
/// The one-word test comes before the coder, so a page that would also
/// compress is a fill, and a page one word off is a blob.
#[test]
fn a_same_filled_page_is_deduped_before_the_coder_sees_it() {
    let codec = Codec::new(&KEY, 75);
    let mut scratch = vec![0u8; PAGE_SIZE];
    assert_eq!(codec.pack(&vec![0u8; PAGE_SIZE], &mut scratch), Ok(Packed::Fill(0)));
    let mut page = vec![0u8; PAGE_SIZE];
    super::zpool::fill_page(0xDEAD_BEEF_0000_0001, &mut page);
    assert_eq!(codec.pack(&page, &mut scratch), Ok(Packed::Fill(0xDEAD_BEEF_0000_0001)));
    page[PAGE_SIZE - 1] ^= 1;
    assert!(matches!(codec.pack(&page, &mut scratch), Ok(Packed::Blob { .. })));

    // Through a storm: three zero pages cost no bytes at all.
    let mut s = AgedSpace::new(vec![vec![0u8; PAGE_SIZE]; 3]);
    s.age();
    let b = budget(10, 1, 2, 3);
    let out = s.storm(&b);
    assert_eq!(out, vec![0, 1]);
    assert_eq!(s.pool.charged(OWN), 0);
}

/// A model with no Accessed bit reports nothing as used: every page ages to
/// the oldest and the walk is address order, as it was.
#[test]
fn without_an_accessed_bit_the_walk_is_address_order() {
    let mut t = T::new();
    for _ in 0..4 {
        pass(&mut t, 0, 0b1111_0000, 0);
    }
    assert_eq!(picks(&t, &[SP]), vec![4, 5, 6, 7]);
}

/// The Domain's aging clock (`PageBudget::aging_due`): never aged is due at
/// once, then once per interval; below the low watermark or with no marks it
/// is never due, and a slot's new occupant starts over.
#[test]
fn a_domain_is_aged_once_per_interval_and_only_above_low() {
    let b = budget(100, 60, 80, 70);
    assert!(b.aging_due(1, 1000), "never aged: due at once, whatever the clock says");
    b.note_aged(500);
    assert!(!b.aging_due(1499, 1000));
    assert!(b.aging_due(1500, 1000));
    b.note_aged(0);
    assert!(!b.aging_due(0, 1000), "a clock at 0 is recorded as 1, not as never");
    // Below low: nothing can be asked of it soon.
    let quiet = budget(100, 60, 80, 60);
    assert!(!quiet.aging_due(10_000, 1000));
    // No watermarks: no aging.
    let free = PageBudget::new();
    assert!(free.charge(50));
    assert!(!free.aging_due(10_000, 1000));
    assert!(b.wants_aging(), "the clock does not enter");
    assert!(!quiet.wants_aging() && !free.wants_aging());
    // A slot reused for a new Domain.
    b.note_aged(9_000);
    b.set_limit_marked(100, 80, 60);
    assert!(b.aging_due(9_001, 100_000));
}
