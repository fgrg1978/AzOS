// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the compressed-page pool (Kconfig `MM_RECLAIM_COMPRESS`), the
//! real `crates/core/mm/src/zpool.rs`: store and restore, same-filled pages,
//! the incompressible skip, segment compaction, the per-Domain quota, fork
//! sharing, and the index under collisions.
//!
//! Not here: the kernel half (`pager.rs`: the fault path's restore, the
//! munmap/fork/exit hooks, the segments from the page allocator), which needs
//! a live MMU and runs in the boot gate.
//!
//! Canaries (discriminate / do not / did not compile), each by editing
//! `zpool.rs`:
//! * `slide` not updating `Blob::off` after a move: `compaction_keeps_every_survivor_restorable` red.
//! * `compact` skipped in `reserve`: `a_fragmented_pool_at_its_ceiling_takes_a_page_after_compaction` red.
//! * `remove_slot` not discharging: `the_quota_is_given_back_when_a_page_goes` and
//!   `a_refused_store_changes_nothing` red.
//! * `erase` without the home test (moves every follower): `the_index_survives_collisions_and_removals` red.
//! * `release_blob` freeing on the first release of a shared blob: `a_forked_page_outlives_its_parents_entry` red.
//! * `NONCE` returning a constant: `two_stores_of_one_page_do_not_share_a_keystream` red.
//! * `pack` skipping `ctr_encrypt`: `a_segment_holds_ciphertext_only` red.
//! * `remove_if` ignoring the generation (`remove`): `a_release_names_the_copy_it_restored` red.
//! * `put` not bumping `gen`: `a_release_names_the_copy_it_restored` red.

use super::zpool::{fill_page, same_filled, Backing, Codec, Error, Fetched, Packed, Pool};
use azos_arch_api::PAGE_SIZE;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::Cell;
use std::collections::HashMap;
use std::ptr::NonNull;

/// Segments from the heap, counting the ones outstanding.
struct Heap {
    out: Cell<usize>,
}

impl Heap {
    const fn new() -> Self {
        Heap { out: Cell::new(0) }
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

/// One frame a segment: the test page compresses to about 750 bytes, so five
/// blobs fill one and two segments hold ten pages, short of the 16 entries.
const SEG: usize = PAGE_SIZE;
/// 16 pages, 2 segments, 4 Domains, no default quota.
type Small = Pool<Heap, 16, 32, 2, 4, SEG, 0>;
/// The same with 3000 bytes of quota per Domain by default (about four pages).
type Quota = Pool<Heap, 16, 32, 2, 4, SEG, 3000>;
/// Four entries and nothing else to run out of first.
type Tiny = Pool<Heap, 4, 8, 1, 2, SEG, 0>;
/// Many entries in few slots, for the index rows.
type Dense = Pool<Heap, 32, 64, 4, 2, { 8 * PAGE_SIZE }, 0>;

const KEY: [u8; 16] = *b"zpool test key 1";
const OWN: usize = 1;

fn codec() -> Codec {
    Codec::new(&KEY, 75)
}

/// A compressible page: small integers beside a few pointers, as memory is.
fn page(seed: u32) -> Vec<u8> {
    let mut p = vec![0u8; PAGE_SIZE];
    for (i, c) in p.chunks_exact_mut(4).enumerate() {
        // Mostly zero words and repeats of a few pointers, as a heap page is.
        let w: u32 = match i % 8 {
            0 => 0x4000_0000 + (i as u32 / 8 % 4) * 8 + seed * 0x1_0000,
            3 => (i as u32 / 8 % 3) + seed,
            _ => 0,
        };
        c.copy_from_slice(&w.to_le_bytes());
    }
    p
}

/// Bytes of a counter-mode generator: nothing a coder can use.
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

/// Compress and store `p` under `(obj, page)`; the bytes it was charged.
fn store<const E: usize, const S: usize, const G: usize, const O: usize, const Z: usize, const Q: u32>(
    pool: &mut Pool<Heap, E, S, G, O, Z, Q>,
    owner: usize,
    obj: u64,
    pg: u64,
    p: &[u8],
) -> Result<usize, Error> {
    let mut scratch = vec![0u8; PAGE_SIZE];
    match codec().pack(p, &mut scratch)? {
        Packed::Fill(w) => pool.insert_fill(owner, obj, pg, w).map(|_| 0),
        Packed::Blob { len, nonce } => pool.insert_blob(owner, obj, pg, nonce, &scratch[..len]).map(|_| len + 8),
        Packed::Skip => Err(Error::Incompressible),
    }
}

/// Restore `(obj, page)` as the fault path does: fetch, then unpack.
fn restore<const E: usize, const S: usize, const G: usize, const O: usize, const Z: usize, const Q: u32>(
    pool: &Pool<Heap, E, S, G, O, Z, Q>,
    obj: u64,
    pg: u64,
) -> Option<Vec<u8>> {
    let mut scratch = vec![0u8; PAGE_SIZE];
    let mut out = vec![0u8; PAGE_SIZE];
    match pool.fetch(obj, pg, &mut scratch)?.0 {
        Fetched::Fill(w) => fill_page(w, &mut out),
        Fetched::Blob { len, nonce } => codec().unpack(nonce, len, &mut scratch, &mut out).ok()?,
    }
    Some(out)
}

#[test]
fn a_page_round_trips_and_is_charged_its_footprint() {
    let mut pool = Small::new(Heap::new());
    let p = page(1);
    let foot = store(&mut pool, OWN, 7, 100, &p).unwrap();
    assert!(foot > 8 && foot < PAGE_SIZE * 75 / 100 + 8, "compressed to {foot}");
    assert_eq!(pool.charged(OWN), foot as u32);
    assert_eq!(restore(&pool, 7, 100).unwrap(), p);
    // Fetching does not remove it: two threads can both restore.
    assert_eq!(restore(&pool, 7, 100).unwrap(), p);
    assert!(pool.remove(7, 100));
    assert_eq!(pool.charged(OWN), 0);
    assert!(restore(&pool, 7, 100).is_none());
    assert!(!pool.remove(7, 100));
}

#[test]
fn zero_and_same_filled_pages_are_one_entry_and_no_bytes() {
    let mut pool = Small::new(Heap::new());
    assert_eq!(store(&mut pool, OWN, 1, 0, &vec![0u8; PAGE_SIZE]), Ok(0));
    let mut filled = vec![0u8; PAGE_SIZE];
    fill_page(0xdead_beef_0bad_f00d, &mut filled);
    assert_eq!(same_filled(&filled), Some(0xdead_beef_0bad_f00d));
    assert_eq!(store(&mut pool, OWN, 1, 1, &filled), Ok(0));
    let s = pool.stats();
    assert_eq!((s.entries, s.blobs, s.segments, s.live_bytes), (2, 0, 0, 0), "no segment was even taken");
    assert_eq!(pool.charged(OWN), 0);
    assert_eq!(restore(&pool, 1, 0).unwrap(), vec![0u8; PAGE_SIZE]);
    assert_eq!(restore(&pool, 1, 1).unwrap(), filled);
    // One odd word and it is no longer same-filled.
    filled[PAGE_SIZE - 1] ^= 1;
    assert_eq!(same_filled(&filled), None);
}

#[test]
fn an_incompressible_page_is_skipped_and_leaves_no_trace() {
    let mut pool = Small::new(Heap::new());
    let n = noise(0x1234_5678);
    let mut scratch = vec![0u8; PAGE_SIZE];
    assert_eq!(codec().pack(&n, &mut scratch), Ok(Packed::Skip));
    assert_eq!(store(&mut pool, OWN, 1, 0, &n), Err(Error::Incompressible));
    assert_eq!(pool.stats().entries, 0);
    assert_eq!(pool.charged(OWN), 0);
    // The threshold decides: the same page that fits 75% does not fit 5%.
    let p = page(3);
    assert!(matches!(Codec::new(&KEY, 75).pack(&p, &mut scratch), Ok(Packed::Blob { .. })));
    assert_eq!(Codec::new(&KEY, 5).pack(&p, &mut scratch), Ok(Packed::Skip));
    // Not a page.
    assert_eq!(codec().pack(&p[..100], &mut scratch), Err(Error::BadPageSize));
}

#[test]
fn a_segment_holds_ciphertext_only() {
    let mut pool = Small::new(Heap::new());
    let p = page(2);
    // What the plaintext stream would be.
    let mut plain = vec![0u8; PAGE_SIZE];
    let len = azos_crypto::wkdm::compress(&p, &mut plain).unwrap();
    store(&mut pool, OWN, 1, 0, &p).unwrap();
    let mut ct = vec![0u8; PAGE_SIZE];
    let Some((Fetched::Blob { len: l, .. }, _)) = pool.fetch(1, 0, &mut ct) else { panic!("a blob") };
    assert_eq!(l, len);
    assert_ne!(&ct[..l], &plain[..len], "the stored stream is the plaintext stream");
    // A wrong key does not give the page back.
    let other = Codec::new(b"another key 0000", 75);
    let Some((Fetched::Blob { len, nonce }, _)) = pool.fetch(1, 0, &mut ct) else { panic!("a blob") };
    let mut out = vec![0u8; PAGE_SIZE];
    let r = other.unpack(nonce, len, &mut ct, &mut out);
    assert!(r.is_err() || out != p, "a wrong key restored the page");
}

#[test]
fn two_stores_of_one_page_do_not_share_a_keystream() {
    let mut pool = Small::new(Heap::new());
    let p = page(4);
    store(&mut pool, OWN, 1, 0, &p).unwrap();
    store(&mut pool, OWN, 1, 1, &p).unwrap();
    let (mut a, mut b) = (vec![0u8; PAGE_SIZE], vec![0u8; PAGE_SIZE]);
    let Some((Fetched::Blob { len: la, nonce: na }, _)) = pool.fetch(1, 0, &mut a) else { panic!() };
    let Some((Fetched::Blob { len: lb, nonce: nb }, _)) = pool.fetch(1, 1, &mut b) else { panic!() };
    assert_ne!(na, nb, "one nonce twice");
    assert_eq!(la, lb);
    assert_ne!(&a[..la], &b[..lb], "equal plaintext gave equal ciphertext");
}

#[test]
fn storing_a_key_again_replaces_it() {
    let mut pool = Small::new(Heap::new());
    store(&mut pool, OWN, 1, 5, &page(1)).unwrap();
    let second = store(&mut pool, OWN, 1, 5, &page(2)).unwrap();
    assert_eq!(pool.stats().entries, 1);
    assert_eq!(pool.charged(OWN), second as u32, "the old copy is still charged");
    assert_eq!(restore(&pool, 1, 5).unwrap(), page(2));
    // A blob replaced by a same-filled page gives its bytes back.
    store(&mut pool, OWN, 1, 5, &vec![0u8; PAGE_SIZE]).unwrap();
    assert_eq!((pool.charged(OWN), pool.stats().blobs, pool.stats().live_bytes), (0, 0, 0));
}

#[test]
fn compaction_keeps_every_survivor_restorable() {
    let mut pool = Small::new(Heap::new());
    // Enough blobs to need both segments, then remove every other one.
    for i in 0..8u32 {
        store(&mut pool, OWN, 1, i as u64, &page(i)).unwrap();
    }
    let before = pool.stats();
    assert!(before.segments >= 2, "{before:?}");
    for i in (0..8).step_by(2) {
        assert!(pool.remove(1, i));
    }
    pool.compact();
    let after = pool.stats();
    assert_eq!(after.entries, 4);
    assert_eq!(after.live_bytes, pool.charged(OWN) as usize, "the ledger sums to the live bytes");
    assert!(after.resident_bytes < before.resident_bytes, "{before:?} -> {after:?}");
    for i in (1..8u32).step_by(2) {
        assert_eq!(restore(&pool, 1, i as u64).unwrap(), page(i), "page {i} after compaction");
    }
    // Compacting a compact pool changes nothing.
    pool.compact();
    assert_eq!(pool.stats(), after);
}

#[test]
fn a_fragmented_pool_at_its_ceiling_takes_a_page_after_compaction() {
    let mut pool = Small::new(Heap::new());
    // Fill both segments until the ceiling refuses, then punch holes.
    let mut n = 0u64;
    while store(&mut pool, OWN, 1, n, &page(n as u32)).is_ok() {
        n += 1;
    }
    assert_eq!(pool.stats().entries as u64, n);
    // The segments are what ran out (ten pages of sixteen entries); keep
    // every third page and try again: only compaction makes room.
    assert!(n < 16, "{n}");
    let keep: Vec<u64> = (0..n).filter(|i| i % 3 == 0).collect();
    for i in 0..n {
        if !keep.contains(&i) {
            pool.remove(1, i);
        }
    }
    let r = store(&mut pool, OWN, 2, 0, &page(40));
    assert!(r.is_ok(), "{r:?}");
    for &i in &keep {
        assert_eq!(restore(&pool, 1, i).unwrap(), page(i as u32));
    }
    assert_eq!(restore(&pool, 2, 0).unwrap(), page(40));
}

#[test]
fn segments_come_and_go_with_their_blobs() {
    let heap_out = |p: &Small| p.stats().segments;
    let mut pool = Small::new(Heap::new());
    assert_eq!(heap_out(&pool), 0);
    // Blobs of ~ 1 KiB: a few fill a segment (8 KiB); store until a second opens.
    let mut n = 0u64;
    while pool.stats().segments < 2 {
        store(&mut pool, OWN, 1, n, &page(n as u32)).unwrap();
        n += 1;
    }
    for i in 0..n {
        pool.remove(1, i);
    }
    // Every blob gone: one empty segment is kept, the rest returned.
    assert_eq!(pool.stats().segments, 1);
    assert_eq!(pool.stats().live_bytes, 0);
    assert_eq!(pool.charged(OWN), 0);
    // And it is reused, not a new one taken.
    store(&mut pool, OWN, 1, 0, &page(1)).unwrap();
    assert_eq!(pool.stats().segments, 1);
}

#[test]
fn a_domain_past_its_quota_is_refused_and_nothing_changes() {
    let mut pool = Quota::new(Heap::new());
    let a = store(&mut pool, 0, 1, 0, &page(1)).unwrap();
    assert!(a < 3000);
    // The default quota is 3000: a second page of ~ a few hundred bytes fits
    // until it does not.
    let mut n = 1u64;
    let refused = loop {
        match store(&mut pool, 0, 1, n, &page(n as u32 + 1)) {
            Ok(_) => n += 1,
            Err(e) => break e,
        }
        assert!(n < 8);
    };
    assert_eq!(refused, Error::Quota);
    let (charged, stats) = (pool.charged(0), pool.stats());
    assert!(charged <= 3000);
    // The refused store changed nothing, including the pool's entries.
    assert_eq!(stats.entries as u64, n);
    assert_eq!(pool.charged(0), charged);
    assert!(pool.gen_of(1, n).is_none());
    // Another Domain has its own.
    assert!(store(&mut pool, 1, 2, 0, &page(9)).is_ok());
    // Same-filled pages cost nothing and are never refused.
    assert_eq!(store(&mut pool, 0, 3, 0, &vec![0u8; PAGE_SIZE]), Ok(0));
    // A quota set for the Domain replaces the default, both ways.
    pool.set_quota(0, 100);
    assert_eq!(store(&mut pool, 0, 4, 0, &page(5)), Err(Error::Quota));
    pool.set_quota(0, 100_000);
    assert!(store(&mut pool, 0, 4, 0, &page(5)).is_ok());
    pool.set_quota(0, 0);
    assert_eq!(store(&mut pool, 0, 4, 1, &page(6)), Err(Error::Quota), "back to the default: over it");
    // A number that is not a Domain.
    assert_eq!(store(&mut pool, 4, 5, 0, &page(1)), Err(Error::BadOwner));
    assert_eq!(pool.stats().entries as u64, n + 3, "n pages, the other Domain's, the zero page, page (4,0)");
}

#[test]
fn a_refused_store_changes_nothing() {
    let mut pool = Quota::new(Heap::new());
    pool.set_quota(0, 1);
    let before = pool.stats();
    assert_eq!(store(&mut pool, 0, 1, 0, &page(1)), Err(Error::Quota));
    assert_eq!(pool.stats(), before);
    assert_eq!(pool.charged(0), 0);
    assert_eq!(before.segments, 0, "refused before a segment was taken");
}

#[test]
fn the_quota_is_given_back_when_a_page_goes() {
    let mut pool = Quota::new(Heap::new());
    let a = store(&mut pool, 0, 1, 0, &page(1)).unwrap();
    let b = store(&mut pool, 0, 1, 1, &page(2)).unwrap();
    assert_eq!(pool.charged(0), (a + b) as u32);
    pool.remove(1, 0);
    assert_eq!(pool.charged(0), b as u32);
    assert_eq!(pool.remove_obj(1), 1);
    assert_eq!(pool.charged(0), 0);
}

#[test]
fn the_pool_refuses_when_every_entry_is_taken() {
    let mut pool = Tiny::new(Heap::new());
    for i in 0..4u64 {
        store(&mut pool, OWN, 1, i, &vec![i as u8; PAGE_SIZE]).unwrap();
    }
    assert_eq!(store(&mut pool, OWN, 1, 4, &page(1)), Err(Error::Full));
    assert_eq!(pool.stats().segments, 0, "refused before a segment was taken");
    // A key already stored can still be replaced when the table is full.
    assert!(store(&mut pool, OWN, 1, 3, &page(1)).is_ok());
    // Dup into a full table is refused too, and leaves it as it was.
    let before = pool.stats();
    assert_eq!(pool.dup_obj(1, 2), Err(Error::Full));
    assert_eq!(pool.stats(), before);
}

#[test]
fn a_forked_page_outlives_its_parents_entry() {
    let mut pool = Small::new(Heap::new());
    store(&mut pool, 0, 10, 1, &page(1)).unwrap();
    store(&mut pool, 0, 10, 2, &vec![7u8; PAGE_SIZE]).unwrap();
    assert_eq!(pool.dup_obj(10, 20), Ok(2));
    assert_eq!(pool.stats().entries, 4);
    assert_eq!(pool.stats().blobs, 1, "the child shares the parent's blob");
    assert_eq!(restore(&pool, 20, 1).unwrap(), page(1));
    assert_eq!(restore(&pool, 20, 2).unwrap(), vec![7u8; PAGE_SIZE]);
    // The parent exits: the child's copy stays whole.
    assert_eq!(pool.remove_obj(10), 2);
    assert_eq!(pool.stats().blobs, 1);
    assert_eq!(restore(&pool, 20, 1).unwrap(), page(1));
    assert_eq!(pool.remove_obj(20), 2);
    let s = pool.stats();
    assert_eq!((s.entries, s.blobs, s.live_bytes), (0, 0, 0));
    assert_eq!(pool.charged(0), 0, "both entries were charged and both were given back");
}

#[test]
fn a_fork_that_the_quota_refuses_leaves_the_pool_as_it_was() {
    let mut pool = Quota::new(Heap::new());
    let mut held = 0;
    for i in 1..=3u64 {
        held += store(&mut pool, 0, 10, i, &page(i as u32)).unwrap();
    }
    // Room for the first page of the child's copy, not for all three.
    pool.set_quota(0, held as u32 + 1000);
    let before = pool.stats();
    assert_eq!(pool.dup_obj(10, 20), Err(Error::Quota));
    assert_eq!(pool.stats(), before, "the entries the fork had already made are gone");
    assert_eq!(pool.charged(0), held as u32);
    assert!((1..=3).all(|i| pool.gen_of(20, i).is_none() && pool.gen_of(10, i).is_some()));
}

#[test]
fn removing_a_range_takes_only_that_object_and_that_range() {
    let mut pool = Dense::new(Heap::new());
    for i in 0..10u64 {
        store(&mut pool, 0, 1, 100 + i, &vec![i as u8 + 1; PAGE_SIZE]).unwrap();
        store(&mut pool, 0, 2, 100 + i, &vec![i as u8 + 50; PAGE_SIZE]).unwrap();
    }
    assert_eq!(pool.remove_range(1, 103, 107), 4);
    for i in 0..10u64 {
        assert_eq!(pool.gen_of(1, 100 + i).is_some(), !(3..7).contains(&i), "obj 1 page {i}");
        assert!(pool.gen_of(2, 100 + i).is_some(), "obj 2 lost page {i}");
    }
    assert_eq!(pool.remove_range(1, 0, 50), 0);
}

#[test]
fn the_index_survives_collisions_and_removals() {
    // 32 entries in 64 slots, removals in an order that shuffles clusters,
    // against a model.
    let mut pool = Dense::new(Heap::new());
    let mut model: HashMap<(u64, u64), u8> = HashMap::new();
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for step in 0..4000u32 {
        let key = (next() % 3, next() % 40);
        if next() % 5 < 3 && model.len() < 32 {
            let v = (step % 250) as u8 + 1;
            pool.insert_fill(0, key.0, key.1, v as u64).unwrap();
            model.insert(key, v);
        } else {
            assert_eq!(pool.remove(key.0, key.1), model.remove(&key).is_some(), "step {step}");
        }
        assert_eq!(pool.len(), model.len());
        if step % 50 == 0 {
            let mut buf = [0u8; 8];
            for o in 0..3u64 {
                for p in 0..40u64 {
                    let want = model.get(&(o, p)).copied();
                    let got = pool.fetch(o, p, &mut buf).map(|(f, _)| match f {
                        Fetched::Fill(w) => w as u8,
                        _ => panic!("a blob"),
                    });
                    assert_eq!(got, want, "({o},{p}) at step {step}");
                }
            }
        }
    }
}

#[test]
fn compaction_under_churn_never_loses_or_mixes_a_page() {
    // Random store/remove/compact against a model of what each page holds.
    let mut pool = Small::new(Heap::new());
    let mut model: HashMap<u64, u32> = HashMap::new();
    let mut x = 0xD1B5_4A32_D192_ED03u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for step in 0..600u32 {
        let pg = next() % 12;
        match next() % 4 {
            0 | 1 => {
                let seed = (next() % 90) as u32;
                match store(&mut pool, OWN, 1, pg, &page(seed)) {
                    Ok(_) => {
                        model.insert(pg, seed);
                    }
                    Err(Error::Full) => {
                        // The replaced entry is gone either way.
                        model.remove(&pg);
                    }
                    Err(e) => panic!("{e:?} at step {step}"),
                }
            }
            2 => {
                assert_eq!(pool.remove(1, pg), model.remove(&pg).is_some());
            }
            _ => pool.compact(),
        }
        let s = pool.stats();
        assert_eq!(s.entries, model.len(), "step {step}");
        assert_eq!(s.live_bytes, pool.charged(OWN) as usize, "step {step}");
        if step % 25 == 0 {
            for (&pg, &seed) in &model {
                assert_eq!(restore(&pool, 1, pg).unwrap(), page(seed), "page {pg} at step {step}");
            }
        }
    }
}

#[test]
fn a_release_names_the_copy_it_restored() {
    // A fault restores the page (generation g1); before it drops its copy the
    // reclaimer stores the freshly installed frame again (g2). The late
    // release must leave the new copy, the page's only one.
    let mut pool = Small::new(Heap::new());
    let mut buf = vec![0u8; PAGE_SIZE];
    store(&mut pool, OWN, 1, 0, &page(3)).unwrap();
    let (_, g1) = pool.fetch(1, 0, &mut buf).unwrap();
    assert!(pool.remove(1, 0), "the first release of a fault that installed");
    store(&mut pool, OWN, 1, 0, &page(4)).unwrap();
    let (_, g2) = pool.fetch(1, 0, &mut buf).unwrap();
    assert_ne!(g1, g2);
    assert!(!pool.remove_if(1, 0, g1), "a stale release removed the new copy");
    assert_eq!(restore(&pool, 1, 0).unwrap(), page(4));
    // The same incarnation is released by its own generation.
    assert!(pool.remove_if(1, 0, g2));
    assert!(pool.gen_of(1, 0).is_none());
    assert!(!pool.remove_if(1, 0, g2), "nothing left to release");
    assert_eq!(pool.charged(OWN), 0);
}

#[test]
fn a_replaced_entry_has_a_new_generation_and_a_fork_keeps_its_sources() {
    let mut pool = Small::new(Heap::new());
    let mut buf = vec![0u8; PAGE_SIZE];
    store(&mut pool, OWN, 1, 0, &page(5)).unwrap();
    let (_, a) = pool.fetch(1, 0, &mut buf).unwrap();
    store(&mut pool, OWN, 1, 0, &page(5)).unwrap();
    let (_, b) = pool.fetch(1, 0, &mut buf).unwrap();
    assert_ne!(a, b, "a store over a key reused the generation");
    pool.dup_obj(1, 2).unwrap();
    let (_, c) = pool.fetch(2, 0, &mut buf).unwrap();
    // The child's entry has its source's generation: the page marker in the
    // parent's slot, which a fork copies word for word, names the child's copy.
    assert_eq!(c, b, "a fork's entry took a generation of its own");
    // A release is keyed by the object as well: the child's does not touch the
    // parent's, and a second one finds nothing.
    assert!(pool.remove_if(2, 0, c));
    assert!(!pool.remove_if(2, 0, c));
    assert!(pool.gen_of(1, 0).is_some());
}

#[test]
fn the_kconfig_cost_lines_are_the_size_of_the_tables() {
    // MM_ZPOOL_ENTRIES says 88 B per entry (a 32 B entry in twice as many
    // slots, a 24 B blob record), MM_ZPOOL_SEGMENTS 16 B per segment and
    // MM_ZPOOL_DOMAIN_KIB 8 B per Domain slot; what is left is a few counters.
    type Edge = Pool<Heap, 2048, 4096, 64, 64, SEG, 0>;
    let fixed = std::mem::size_of::<Edge>() - (88 * 2048 + 16 * 64 + 8 * 64);
    assert!(fixed < 128, "{fixed} bytes of fixed state");
    type Embedded = Pool<Heap, 256, 512, 16, 32, SEG, 0>;
    assert_eq!(std::mem::size_of::<Embedded>() - fixed, 88 * 256 + 16 * 16 + 8 * 32);
}
