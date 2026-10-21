// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for reclaim into the compressed pool (Kconfig `MM_RECLAIM_COMPRESS`):
//! the Domain's watermarks and the storm bookkeeping of the
//! real `budget.rs`, and the storm loop (`zpool::run_storm`) over the real
//! `Pool` and `Codec`.
//!
//! **What is real and what is a model.** The budget, the pool, the codec and
//! the loop are the shipping code. The victim source is a model: a `Vec` of
//! pages standing for one address space (`Model` below implements
//! [`Reclaimee`](super::zpool::Reclaimee)). The kernel's source is
//! `pager::AnonReclaim` (`crates/core/mm/src/pager.rs`): the generation order
//! of the Domain's anonymous region pages (`aging.rs`, whose rows are in
//! `aging.rs` next to this file), the shoot-down and the page allocator;
//! those need page tables and a live MMU, and the candidate walk has no host
//! row here (`marker_pte.rs` covers the page markers). The
//! `mem_locked` rule IS tested at the shipping seam (`storm_begin`), the page
//! level of it ("the walk never offers a locked page") is not.
//!
//! Canaries (by hand, 2026-10-16; discriminates / does not / did not compile):
//! * `reclaim_target` measuring from `high` instead of `low`:
//!   `crossing_high_reclaims_down_to_low_and_no_further` red.
//! * `storm_begin` not testing `locked` (or `rt_hart`):
//!   `a_locked_domain_and_an_rt_hart_are_never_reclaimed` red.
//! * `storm_end` clearing the flag with a store, not a compare-and-swap:
//!   `a_storm_answers_one_record_and_one_storm_runs_at_a_time` red.
//! * `run_storm` breaking on `Incompressible`:
//!   `incompressible_pages_are_kept_and_the_storm_goes_on` red.
//! * `run_storm` not breaking on `Full`: `a_full_pool_ends_the_storm_early` red.
//! * `run_storm` ignoring `max_steps`: `max_steps_bounds_a_storm` red.
//! * `storm_note_stored` not discharging: `crossing_high_...` and
//!   `a_restore_charges_the_page_again_and_may_overshoot` red.
//! * `storm_end` releasing the flag before it drains the counters:
//!   `a_new_storm_never_takes_the_closing_storms_counters` red.
//! * `storm_begin` opening with a store, not a compare-and-swap, and
//!   `charge_restore` not charging: the same rows as above red.
//!
//! All twelve variants of these went red on exactly the rows named (several
//! on more); nothing here depends on the host's `.config`: the rows set the
//! watermarks themselves, and `watermarks_follow_the_limit` has a branch for
//! reclaim on and one for off (both run: `KCONFIG_CONFIG` with
//! `MM_RECLAIM_COMPRESS=y` and the default `MM_RECLAIM_OFF`).

use super::budget::{watermarks_for, NoStorm, PageBudget};
use super::zpool::{fill_page, run_storm, Backing, Codec, Error, Fetched, Packed, Pool, Reclaimee};
use azos_arch_api::PAGE_SIZE;

/// The percentages the rows here use (the kernel's come from Kconfig).
const HIGH: u32 = 85;
const LOW: u32 = 65;
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;

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
/// 64 pages, 4 segments of 4 frames, one Domain slot.
type Roomy = Pool<Heap, 64, 128, 4, 2, SEG, 0>;
/// Four pages: the fifth store finds no room.
type Four = Pool<Heap, 4, 8, 4, 2, SEG, 0>;

const KEY: [u8; 16] = *b"reclaim test key";
const OWN: usize = 1;
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

/// A Domain's frame budget with `used` pages charged and the watermarks
/// `(low, high)` under `limit`.
fn budget(limit: u32, low: u32, high: u32, used: u32) -> PageBudget {
    let b = PageBudget::new();
    b.set_limit(limit);
    b.set_watermarks(low, high);
    assert!(b.charge(used));
    b
}

/// One MemObj's pages, as the reclaimer sees them: resident contents (`None`:
/// out in the pool), and what the storm did to each.
struct Model<Z: PoolOps> {
    pool: Z,
    codec: Codec,
    pages: Vec<Option<Vec<u8>>>,
    /// A page whose mapping cannot be removed (pinned or sealed).
    busy: Vec<bool>,
    hand: usize,
    unmapped: Vec<usize>,
    freed: Vec<usize>,
    kept: Vec<usize>,
}

/// The two pool sizes the rows use, behind one interface.
trait PoolOps {
    fn put(&mut self, pg: u64, packed: Packed, ct: &[u8]) -> Result<u32, Error>;
    fn get(&self, pg: u64, out: &mut [u8]) -> Option<(Fetched, u32)>;
    fn drop_copy(&mut self, pg: u64, gen: u32) -> bool;
    fn held(&self) -> usize;
}

macro_rules! pool_ops {
    ($t:ty) => {
        impl PoolOps for $t {
            fn put(&mut self, pg: u64, packed: Packed, ct: &[u8]) -> Result<u32, Error> {
                match packed {
                    Packed::Fill(w) => self.insert_fill(OWN, OBJ, pg, w).map(|()| 0),
                    Packed::Blob { len, nonce } => {
                        self.insert_blob(OWN, OBJ, pg, nonce, &ct[..len]).map(|()| len as u32 + 8)
                    }
                    Packed::Skip => Err(Error::Incompressible),
                }
            }
            fn get(&self, pg: u64, out: &mut [u8]) -> Option<(Fetched, u32)> {
                self.fetch(OBJ, pg, out)
            }
            fn drop_copy(&mut self, pg: u64, gen: u32) -> bool {
                self.remove_if(OBJ, pg, gen)
            }
            fn held(&self) -> usize {
                self.len()
            }
        }
    };
}
pool_ops!(Roomy);
pool_ops!(Four);

impl<Z: PoolOps> Model<Z> {
    fn new(pool: Z, pages: Vec<Vec<u8>>) -> Self {
        let n = pages.len();
        Model {
            pool,
            codec: Codec::new(&KEY, 75),
            pages: pages.into_iter().map(Some).collect(),
            busy: vec![false; n],
            hand: 0,
            unmapped: vec![],
            freed: vec![],
            kept: vec![],
        }
    }

    fn resident(&self) -> u32 {
        self.pages.iter().filter(|p| p.is_some()).count() as u32
    }

    /// The fault: restore page `i` from the pool as the pager does (fetch,
    /// unpack, install, drop the copy that was restored), charging the frame.
    fn fault(&mut self, b: &PageBudget, i: usize) -> Vec<u8> {
        let mut ct = vec![0u8; PAGE_SIZE];
        let mut page = vec![0u8; PAGE_SIZE];
        let (what, gen) = self.pool.get(i as u64, &mut ct).expect("the page is in the pool");
        match what {
            Fetched::Fill(w) => fill_page(w, &mut page),
            Fetched::Blob { len, nonce } => self.codec.unpack(nonce, len, &mut ct, &mut page).unwrap(),
        }
        assert!(self.pool.drop_copy(i as u64, gen));
        b.charge_restore(1);
        self.pages[i] = Some(page.clone());
        page
    }
}

impl<Z: PoolOps> Reclaimee for Model<Z> {
    type Victim = usize;

    /// One pass, as `AnonReclaim::next` makes: a page is offered once, and
    /// the hand is back at the start when the pass ends.
    fn next(&mut self) -> Option<usize> {
        while self.hand < self.pages.len() {
            let i = self.hand;
            self.hand += 1;
            if self.pages[i].is_some() {
                return Some(i);
            }
        }
        self.hand = 0;
        None
    }

    fn unmap(&mut self, v: usize) -> bool {
        if self.busy[v] {
            return false;
        }
        self.unmapped.push(v);
        true
    }

    fn store(&mut self, v: usize) -> Result<u32, Error> {
        let mut scratch = vec![0u8; PAGE_SIZE];
        let packed = self.codec.pack(self.pages[v].as_ref().unwrap(), &mut scratch)?;
        self.pool.put(v as u64, packed, &scratch)
    }

    fn free(&mut self, v: usize) {
        self.pages[v] = None;
        self.freed.push(v);
    }

    fn keep(&mut self, v: usize) {
        self.kept.push(v);
    }
}

fn roomy(n: usize) -> Model<Roomy> {
    Model::new(Roomy::new(Heap), (0..n).map(|i| compressible(i as u32)).collect())
}

/// Over `high`, the storm frees pages until the charge is at `low`: exactly,
/// not to zero and not short; the record says how many and how much.
#[test]
fn crossing_high_reclaims_down_to_low_and_no_further() {
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    assert!(b.over_high());
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(b.used(), 10, "down to low");
    assert_eq!(rec.pages, 7);
    assert_eq!(rec.bytes_in, 7 * PAGE_SIZE as u64);
    assert!(rec.bytes_out > 0 && rec.bytes_out < rec.bytes_in, "the pool holds them smaller: {}", rec.bytes_out);
    assert!(rec.paid());
    assert_eq!(rec.fields(), [7, 7 * PAGE_SIZE as u64, rec.bytes_out]);
    assert_eq!(m.resident(), 10);
    assert_eq!(m.pool.held(), 7);
    assert_eq!(m.freed.len(), 7);
    assert!(!b.over_high());
    // Below high now: the next trigger finds nothing to do.
    assert_eq!(run_storm(&b, &mut m, false, false, 1000, P), Err(NoStorm::BelowHigh));
}

/// The loop takes victims in the order the source offers them (this model's is
/// by index; the kernel's is the oldest generation first, `aging.rs`).
#[test]
fn victims_go_in_the_order_the_source_offers_them() {
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(m.freed, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(m.unmapped, m.freed, "each stored page was unmapped first, and only those");
}

/// A Domain with no frame limit has no watermark and never reclaims, however
/// much it holds; one under `high` is left alone and nothing is touched.
#[test]
fn a_domain_below_high_or_without_a_limit_is_left_alone() {
    let unlimited = PageBudget::new();
    assert!(unlimited.charge(1_000_000));
    assert!(!unlimited.over_high());
    let mut m = roomy(8);
    assert_eq!(run_storm(&unlimited, &mut m, false, false, 1000, P), Err(NoStorm::BelowHigh));
    let below = budget(20, 10, 16, 15);
    assert_eq!(run_storm(&below, &mut m, false, false, 1000, P), Err(NoStorm::BelowHigh));
    assert!(m.unmapped.is_empty() && m.pool.held() == 0);
    assert_eq!(watermarks_for(0, HIGH, LOW), (0, 0));
}

/// `mem = "locked"` rows and real-time harts are never reclaimed: the storm
/// does not start, nothing is unmapped, the charge does not move. The same
/// Domain, once the gate is open, does reclaim (so the refusal was the gate).
#[test]
fn a_locked_domain_and_an_rt_hart_are_never_reclaimed() {
    let b = budget(20, 10, 16, 18);
    let mut m = roomy(18);
    assert_eq!(run_storm(&b, &mut m, true, false, 1000, P), Err(NoStorm::Locked));
    assert_eq!(run_storm(&b, &mut m, false, true, 1000, P), Err(NoStorm::RtHart));
    assert_eq!(run_storm(&b, &mut m, true, true, 1000, P), Err(NoStorm::Locked));
    assert_eq!(b.used(), 18);
    assert!(m.unmapped.is_empty() && m.freed.is_empty() && m.pool.held() == 0);
    // A refusal opens no storm: the gate being open later is not `Busy`.
    assert_eq!(run_storm(&b, &mut m, false, false, 1000, P).unwrap().pages, 8);
}

/// One record per storm, however many pages it took; a second storm is a
/// second record with its own numbers. A storm is closed exactly once and
/// only one runs at a time.
#[test]
fn a_storm_answers_one_record_and_one_storm_runs_at_a_time() {
    let b = budget(20, 10, 16, 17);
    assert_eq!(b.storm_end(P), None, "no storm open");
    assert_eq!(b.storm_begin(false, false), Ok(()));
    assert_eq!(b.storm_begin(false, false), Err(NoStorm::Busy));
    assert_eq!(b.reclaim_target(), 7);
    b.storm_note_stored(100);
    b.storm_note_stored(0);
    b.storm_note_stored(50);
    let rec = b.storm_end(P).unwrap();
    assert_eq!((rec.pages, rec.bytes_out), (3, 150));
    assert_eq!(b.storm_end(P), None, "the record is answered once");
    assert_eq!(b.reclaim_target(), 0, "no storm, no target");
    assert_eq!(b.used(), 14);

    // Two storms through the loop, two records, the second not including the first.
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    let first = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    for _ in 0..8 {
        assert!(b.charge(1));
    }
    let more = (0..8).map(|i| compressible(100 + i)).collect::<Vec<_>>();
    let base = m.pages.len();
    m.pages.extend(more.into_iter().map(Some));
    m.busy.resize(base + 8, false);
    let second = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(first.pages, 7);
    assert_eq!(second.pages, 8, "18 down to 10: the first storm's seven are not counted again");
    assert_ne!(first.bytes_out, 0);
    assert_eq!(b.used(), 10);
}

/// A storm's record holds that storm's pages and nothing of the next one's,
/// even when another hart opens the next storm the instant this one closes:
/// `storm_end` drains the counters BEFORE it releases the flag. Every thread
/// that wins `storm_begin` notes exactly three pages of 10 bytes, so any
/// record that is not (3, 30) took a page that was not its own (or lost one).
#[test]
fn a_new_storm_never_takes_the_closing_storms_counters() {
    use std::sync::atomic::{AtomicU32, Ordering};
    const ROUNDS: u32 = 200_000;
    let b = budget(1000, 10, 16, 17);
    let bad = AtomicU32::new(0);
    let done = AtomicU32::new(0);
    let start = std::sync::Barrier::new(4);
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                start.wait();
                let mut mine = 0;
                while mine < ROUNDS {
                    if b.storm_begin(false, false).is_err() {
                        std::hint::spin_loop();
                        continue;
                    }
                    for _ in 0..3 {
                        b.storm_note_stored(10);
                    }
                    // The charge goes back BEFORE the close, so the Domain is over
                    // `high` the instant the flag drops and the next storm can open
                    // inside the closing call's window.
                    b.charge_restore(3);
                    let rec = b.storm_end(P).unwrap();
                    if rec.fields() != [3, 3 * u64::from(P), 30] {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                    mine += 1;
                    done.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(done.load(Ordering::Relaxed), 4 * ROUNDS);
    assert_eq!(bad.load(Ordering::Relaxed), 0, "a record took another storm's pages");
    assert_eq!(b.storm_end(P), None);
    assert_eq!(b.used(), 17);
}

/// Pages that do not compress stay resident: every one is kept (mapped
/// again), the storm still tries the rest, and it answers a record with no
/// pages (the rule's "compression did not pay").
#[test]
fn incompressible_pages_are_kept_and_the_storm_goes_on() {
    let b = budget(20, 10, 16, 17);
    let mut m = Model::new(Roomy::new(Heap), (0..17).map(|i| noise(i as u64 + 1)).collect());
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(rec.pages, 0);
    assert!(!rec.paid());
    assert_eq!(rec.fields(), [0, 0, 0]);
    assert_eq!(b.used(), 17, "nothing was freed, nothing is owed back");
    assert_eq!(m.kept.len(), 17, "it went through every page before giving up");
    assert_eq!(m.unmapped.len(), 17);
    assert!(m.freed.is_empty() && m.pool.held() == 0);
    assert_eq!(m.resident(), 17);
}

/// A mix: the incompressible ones are skipped and the compressible ones still
/// bring the charge down to low.
#[test]
fn skipping_an_incompressible_page_does_not_cost_the_target() {
    let b = budget(20, 10, 16, 17);
    let mut pages: Vec<Vec<u8>> = (0..17).map(|i| compressible(i)).collect();
    for i in [1, 4, 5] {
        pages[i] = noise(i as u64 + 9);
    }
    let mut m = Model::new(Roomy::new(Heap), pages);
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(b.used(), 10);
    assert_eq!(rec.pages, 7);
    assert_eq!(m.kept, vec![1, 4, 5]);
    assert_eq!(m.freed, vec![0, 2, 3, 6, 7, 8, 9]);
}

/// When the pool has no room the storm stops: every later page would be
/// unmapped (a shoot-down on every hart) for the same answer.
#[test]
fn a_full_pool_ends_the_storm_early() {
    let b = budget(20, 5, 16, 17);
    let mut m = Model::new(Four::new(Heap), (0..17).map(|i| compressible(i)).collect());
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(rec.pages, 4, "the pool holds four");
    assert_eq!(b.used(), 13);
    assert_eq!(m.unmapped.len(), 5, "the fifth was unmapped, refused, kept: and the storm stopped there");
    assert_eq!(m.kept, vec![4]);
}

/// A page whose mapping cannot be removed is passed over; the storm moves to
/// the next one.
#[test]
fn a_busy_page_is_passed_over() {
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    m.busy[0] = true;
    m.busy[2] = true;
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(rec.pages, 7);
    assert_eq!(m.freed, vec![1, 3, 4, 5, 6, 7, 8]);
    assert!(m.pages[0].is_some() && m.pages[2].is_some());
    assert!(m.kept.is_empty(), "never unmapped, so nothing to map again");
}

/// With fewer victims than the target the storm takes what there is and says
/// so; the charge stays over `low`.
#[test]
fn a_source_with_nothing_left_ends_the_storm_short_of_low() {
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    for i in 0..13 {
        m.busy[i] = true;
    }
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(rec.pages, 4);
    assert_eq!(b.used(), 13);
}

/// A storm holds its hart for a bounded number of candidates.
#[test]
fn max_steps_bounds_a_storm() {
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    let rec = run_storm(&b, &mut m, false, false, 3, P).unwrap();
    assert_eq!(rec.pages, 3);
    assert_eq!(b.used(), 14);
    // 14 is below high: the bounded storm left the Domain out of pressure.
    assert_eq!(run_storm(&b, &mut m, false, false, 3, P), Err(NoStorm::BelowHigh));
}

/// The fault after a reclaim gets the page back byte for byte, drops the
/// pool's copy, and the page is charged again. Same-filled pages (zero) are
/// among them and cost the pool nothing.
#[test]
fn restore_on_fault_after_reclaim_returns_the_page() {
    let b = budget(20, 10, 16, 17);
    let mut originals: Vec<Vec<u8>> = (0..17).map(|i| compressible(i)).collect();
    originals[2] = vec![0u8; PAGE_SIZE];
    originals[5] = vec![0xA5u8; PAGE_SIZE];
    let mut m = Model::new(Roomy::new(Heap), originals.clone());
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(rec.pages, 7);
    assert_eq!(m.pool.held(), 7);
    for i in 0..7 {
        assert!(m.pages[i].is_none());
    }
    let used = b.used();
    for i in 0..7 {
        let back = m.fault(&b, i);
        assert!(back == originals[i], "page {i} comes back as it was");
    }
    assert_eq!(m.pool.held(), 0, "each restore dropped its copy");
    assert_eq!(b.used(), used + 7, "and charged its frame");
    assert_eq!(m.resident(), 17);
}

/// A restore cannot be refused: the Domain used the headroom the storm made,
/// so the page's frame takes it past its limit. The charge says so (Critical),
/// the peak follows, an ordinary charge is refused, and the next storm brings
/// the Domain back down.
#[test]
fn a_restore_charges_the_page_again_and_may_overshoot() {
    let b = budget(20, 10, 16, 17);
    let mut m = roomy(17);
    run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(b.used(), 10);
    assert!(b.charge(10), "the headroom the storm made");
    assert_eq!(b.used(), 20);
    assert!(!b.charge(1));
    m.fault(&b, 0);
    m.fault(&b, 1);
    assert_eq!(b.used(), 22, "over the limit by the two restored frames");
    assert_eq!(b.peak(), 22);
    assert!(b.used() > b.limit());
    assert!(!b.charge(1));
    // Over high: the next storm runs. The hand is at page 7, so its pass takes
    // the ten pages from there on and ends; 12 is under high, and the two
    // restored pages behind the hand wait for the pass after the next trigger.
    let rec = run_storm(&b, &mut m, false, false, 1000, P).unwrap();
    assert_eq!(rec.pages, 10);
    assert_eq!(b.used(), 12);
    assert!(!b.over_high());
    b.charge_restore(0);
    assert_eq!(b.used(), 12, "zero pages is a no-op");
}

/// `over_high` is the high watermark and nothing below it: a charge one page
/// short is not over, the charge at `high` is, and discharging below it is not.
/// A Domain with no marks is never over, whatever it charges.
#[test]
fn over_high_is_exactly_the_high_watermark() {
    let b = budget(20, 10, 16, 0);
    assert!(!b.over_high(), "nothing charged");
    assert!(b.charge(15));
    assert!(!b.over_high());
    assert!(b.charge(1));
    assert!(b.over_high(), "at high, not past it");
    assert!(b.charge(4));
    assert!(b.over_high(), "at the limit");
    b.discharge(20);
    assert!(!b.over_high());
}

/// The watermarks follow the percentages of the limit (the kernel's are
/// Kconfig `MM_RECLAIM_HIGH_PCT` / `MM_RECLAIM_LOW_PCT`, declared by
/// `PageBudget::set_limit_marked`), `low < high` always, and with reclaim off
/// (`high_pct == 0`) there are none.
#[test]
fn watermarks_follow_the_limit() {
    for limit in 1..=2048u32 {
        let (low, high) = watermarks_for(limit, HIGH, LOW);
        assert!(low < high, "limit {limit}: {low} < {high}");
        assert!(high >= 1 && high <= limit);
        assert_eq!(watermarks_for(limit, 0, 0), (0, 0), "reclaim off: no watermark");
    }
    assert_eq!(watermarks_for(1000, HIGH, LOW), (10 * LOW, 10 * HIGH));
}
