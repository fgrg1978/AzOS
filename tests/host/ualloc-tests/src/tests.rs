// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::model::*;
use azos_ualloc::engine::{Config, Fault, Heap, HDR, SLOT};
use std::collections::BTreeMap;

fn fill(p: *mut u8, n: usize, v: u8) {
    // SAFETY: the tests only touch memory they allocated.
    unsafe { core::ptr::write_bytes(p, v, n) }
}

fn all_eq(p: *mut u8, n: usize, v: u8) -> bool {
    // SAFETY: as `fill`.
    unsafe { core::slice::from_raw_parts(p, n).iter().all(|&b| b == v) }
}

fn poke(a: usize, v: u8) {
    // SAFETY: the tests poke inside memory the model mapped.
    unsafe { (a as *mut u8).write(v) }
}

fn free(h: &mut H, p: *mut u8) {
    h.free(p, None)
}

fn is(f: Option<Faulted>, kind: Fault) -> bool {
    matches!(f, Some(Faulted(k, _)) if k == kind)
}

// ── ordinary behaviour ──────────────────────────────────────────────────────

#[test]
fn every_size_roundtrips_and_chunks_are_disjoint() {
    for cfg in [plain(), hardened()] {
        let mut h = heap(cfg, Some(7));
        let mut live = vec![];
        for size in (0..=2100).step_by(7).chain([4095, 4096, 4097, 9000, 70000]) {
            let p = h.alloc(size, 8);
            assert!(!p.is_null(), "size {size}");
            assert_eq!(p as usize % HDR, 0, "16-aligned: the header sits 16 bytes before");
            fill(p, size, (size % 251) as u8);
            live.push((p, size));
        }
        for &(p, size) in &live {
            assert!(all_eq(p, size, (size % 251) as u8), "size {size} was overwritten by a neighbour");
        }
        for (p, _) in live {
            free(&mut h, p);
        }
        assert_eq!(h.stats().allocs, h.stats().frees);
    }
}

#[test]
fn alignment_up_to_a_page() {
    for cfg in [plain(), hardened()] {
        let mut h = heap(cfg, Some(1));
        for align in [1, 8, 16, 32, 64, 256, 1024, 4096] {
            for size in [0, 1, 17, 100, 2000, 2500, 5000] {
                let p = h.alloc(size, align);
                assert!(!p.is_null());
                assert_eq!(p as usize % align.max(16), 0, "align {align} size {size}");
                fill(p, size, 0x11);
                free(&mut h, p);
            }
        }
        assert!(h.alloc(8, 8192).is_null(), "alignment above a page is refused");
        assert!(h.alloc(8, 3).is_null(), "not a power of two");
        assert!(h.alloc(usize::MAX - 8, 8).is_null(), "overflowing size");
        assert!(h.alloc(1 << 47, 8).is_null());
    }
}

#[test]
fn free_of_null_is_a_noop() {
    let mut h = heap(plain(), None);
    assert!(fault_of(|| h.free(core::ptr::null_mut(), None)).is_none());
    assert_eq!(h.stats().frees, 0);
}

// ── double free ─────────────────────────────────────────────────────────────

#[test]
fn double_free_of_a_quarantined_chunk() {
    let cfg = Config { randomize: false, ..hardened() };
    let mut h = heap(cfg, Some(3));
    let p = h.alloc(40, 8);
    // Control: the first free is fine.
    assert!(fault_of(|| free(&mut h, p)).is_none());
    assert!(is(fault_of(|| free(&mut h, p)), Fault::DoubleFree));
}

#[test]
fn double_free_without_quarantine_is_caught_until_the_slot_is_reused() {
    let mut h = heap(plain(), Some(3));
    let p = h.alloc(40, 8);
    free(&mut h, p);
    assert!(is(fault_of(|| free(&mut h, p)), Fault::DoubleFree), "slot is on the free list");
    // The documented limit: once the slot is handed out again, a stale free
    // of the old pointer frees the NEW owner's chunk. Same as Scudo.
    let q = h.alloc(40, 8);
    assert_eq!(p, q, "no quarantine: LIFO reuse");
    assert!(fault_of(|| free(&mut h, p)).is_none());
    assert!(is(fault_of(|| free(&mut h, q)), Fault::DoubleFree));
}

#[test]
fn double_free_of_an_aligned_chunk_without_quarantine() {
    // The live header of an aligned chunk is not at the slot start.
    let big_chunk = Config { quarantine_bytes: 64, ..plain() };
    for cfg in [plain(), big_chunk, Config { poison: true, ..plain() }] {
        for align in [32, 64, 256] {
            let mut h = heap(cfg, Some(3));
            let p = h.alloc(40, align);
            assert_eq!(p as usize % align, 0);
            assert!(fault_of(|| free(&mut h, p)).is_none());
            let f = fault_of(|| free(&mut h, p));
            // DoubleFree, or HeaderCorrupt where the free-list link (front 16)
            // or the poison fill landed on the stale header.
            let ok = matches!(&f, Some(Faulted(Fault::DoubleFree | Fault::HeaderCorrupt, _)));
            assert!(ok, "align {align}: {f:?}");
            // The slot is on the list once: two allocations differ.
            let (x, y) = (h.alloc(40, align), h.alloc(40, align));
            assert_ne!(x, y, "align {align}: duplicate allocation");
        }
    }
}

#[test]
fn double_free_of_a_large_allocation() {
    let mut h = heap(plain(), Some(3));
    let p = h.alloc(10000, 8);
    free(&mut h, p);
    // Unmapped and never mapped again: not a chunk of this heap any more.
    assert!(is(fault_of(|| free(&mut h, p)), Fault::InvalidFree));
}

// ── overflow, underflow, forged headers ─────────────────────────────────────

#[test]
fn overflow_into_the_next_chunk_header_is_caught_when_that_chunk_is_freed() {
    let mut h = heap(plain(), Some(5));
    let (a, b) = (h.alloc(48, 8), h.alloc(48, 8));
    assert_eq!(b as usize, a as usize + SLOT[2], "fresh slots are consecutive (class 64)");
    // Control: writing exactly the 48 bytes does nothing.
    fill(a, 48, 0xaa);
    assert!(fault_of(|| free(&mut h, b)).is_none());
    let b = h.alloc(48, 8);
    assert_eq!(b as usize, a as usize + 64);
    // One byte past a's chunk is the first byte of b's header.
    poke(a as usize + 48, 0xff);
    assert!(is(fault_of(|| free(&mut h, b)), Fault::HeaderCorrupt));
    // The overflowing chunk itself is still consistent.
    assert!(fault_of(|| free(&mut h, a)).is_none());
}

#[test]
fn an_overflow_that_reaches_only_the_checksum_field_is_caught() {
    // Offset 12 of the next header is the low byte of the 32-bit checksum:
    // every field the structure checks (size, class, state, front) is intact,
    // so only the keyed checksum can see it.
    let mut h = heap(plain(), Some(5));
    let (a, b) = (h.alloc(48, 8), h.alloc(48, 8));
    assert_eq!(b as usize, a as usize + 64);
    // SAFETY: inside the model's block.
    let old = unsafe { *((b as usize - 4) as *const u8) };
    poke(b as usize - 4, old ^ 1);
    assert!(is(fault_of(|| free(&mut h, b)), Fault::HeaderCorrupt));
    poke(b as usize - 4, old);
    assert!(fault_of(|| free(&mut h, b)).is_none(), "restored: no fault");
}

#[test]
fn underflow_into_own_header() {
    let mut h = heap(plain(), Some(5));
    let a = h.alloc(48, 8);
    poke(a as usize - 1, 0);
    assert!(is(fault_of(|| free(&mut h, a)), Fault::HeaderCorrupt));
    let b = h.alloc(10000, 8);
    poke(b as usize - 16, 0xee);
    assert!(is(fault_of(|| free(&mut h, b)), Fault::HeaderCorrupt), "large chunks too");
}

#[test]
fn a_header_copied_from_another_chunk_does_not_verify() {
    let mut h = heap(plain(), Some(5));
    let (a, b) = (h.alloc(48, 8), h.alloc(48, 8));
    // Same size, same class, same state: only the address differs.
    // SAFETY: both headers are inside the model's block.
    unsafe { core::ptr::copy_nonoverlapping((a as usize - 16) as *const u8, (b as usize - 16) as *mut u8, 16) };
    assert!(is(fault_of(|| free(&mut h, b)), Fault::HeaderCorrupt));
    // Control: a header copied onto itself is fine.
    // SAFETY: as above.
    unsafe { core::ptr::copy((a as usize - 16) as *const u8, (a as usize - 16) as *mut u8, 16) };
    assert!(fault_of(|| free(&mut h, a)).is_none());
}

#[test]
fn the_key_is_the_kernels_entropy() {
    // A header forged with another heap's cookie does not verify.
    let (mut h1, mut h2) = (heap(plain(), Some(1)), heap(plain(), Some(2)));
    let (a, b) = (h1.alloc(48, 8), h2.alloc(48, 8));
    // SAFETY: both headers are inside the models' blocks.
    unsafe { core::ptr::copy_nonoverlapping((b as usize - 16) as *const u8, (a as usize - 16) as *mut u8, 16) };
    assert!(is(fault_of(|| free(&mut h1, a)), Fault::HeaderCorrupt));
    assert!(fault_of(|| free(&mut h2, b)).is_none());
}

// ── invalid frees ───────────────────────────────────────────────────────────

#[test]
fn pointers_that_are_not_chunks() {
    let mut h = heap(plain(), Some(5));
    let a = h.alloc(100, 8);
    let x = 0u64;
    assert!(is(fault_of(|| free(&mut h, &x as *const u64 as *mut u8)), Fault::InvalidFree), "stack");
    assert!(is(fault_of(|| free(&mut h, (a as usize + 1) as *mut u8)), Fault::InvalidFree), "misaligned");
    let f = fault_of(|| free(&mut h, (a as usize + 16) as *mut u8));
    assert!(matches!(f, Some(Faulted(Fault::HeaderCorrupt | Fault::InvalidFree, _))), "interior: {f:?}");
    let guard = h.sys().guard_pages[0];
    assert!(is(fault_of(|| free(&mut h, (guard + 64) as *mut u8)), Fault::InvalidFree), "guard page");
    let (base, ..) = h.sys().mapped[0];
    assert!(is(fault_of(|| free(&mut h, base as *mut u8)), Fault::InvalidFree), "block start has no header");
    // A slot never handed out is not a chunk either (its header is zero).
    let f = fault_of(|| free(&mut h, (a as usize + 160) as *mut u8));
    assert!(matches!(f, Some(Faulted(Fault::HeaderCorrupt, _))), "{f:?}");
    assert!(fault_of(|| free(&mut h, a)).is_none(), "the real chunk still frees");
}

#[test]
fn size_mismatch() {
    let mut h = heap(plain(), Some(5));
    let a = h.alloc(100, 8);
    assert!(is(fault_of(|| h.free(a, Some(99))), Fault::SizeMismatch));
    assert!(fault_of(|| h.free(a, Some(100))).is_none());
    let b = h.alloc(9000, 8);
    assert!(is(fault_of(|| h.free(b, Some(1))), Fault::SizeMismatch));
}

// ── use after free ──────────────────────────────────────────────────────────

/// Frees and reallocates until the chunk `p` has left quarantine (random
/// order, 16 entries: 1 in 16 per eviction), or `rounds` pass.
fn churn(h: &mut H, rounds: usize) -> Option<Faulted> {
    fault_of(|| {
        for _ in 0..rounds {
            let q = h.alloc(64, 8);
            h.free(q, None);
        }
    })
}

#[test]
fn write_after_free_is_caught_when_the_chunk_leaves_quarantine() {
    let mut h = heap(hardened(), Some(11));
    let p = h.alloc(64, 8);
    free(&mut h, p);
    poke(p as usize + 8, 1); // inside the poisoned span
    assert!(is(churn(&mut h, 2000), Fault::UseAfterFree));
}

#[test]
fn write_after_free_control_cases() {
    // No write: no fault in the same churn.
    let mut h = heap(hardened(), Some(11));
    let p = h.alloc(64, 8);
    free(&mut h, p);
    assert!(churn(&mut h, 2000).is_none());
    // Poison off: the same write is not detected (the knob is what detects).
    let mut h = heap(Config { poison: false, ..hardened() }, Some(11));
    let p = h.alloc(64, 8);
    free(&mut h, p);
    poke(p as usize + 8, 1);
    assert!(churn(&mut h, 2000).is_none());
    // Beyond the poisoned span: not detected either (documented limit).
    let mut h = heap(hardened(), Some(11));
    let p = h.alloc(1000, 8);
    free(&mut h, p);
    poke(p as usize + 600, 1);
    let f = fault_of(|| {
        for _ in 0..2000 {
            let q = h.alloc(1000, 8);
            h.free(q, None);
        }
    });
    assert!(f.is_none());
}

#[test]
fn write_after_free_without_quarantine_is_caught_at_reuse() {
    let mut h = heap(Config { poison: true, ..plain() }, Some(11));
    let p = h.alloc(64, 8);
    free(&mut h, p);
    poke(p as usize + 24, 9);
    assert!(is(fault_of(|| h.alloc(64, 8)), Fault::UseAfterFree));
}

#[test]
fn free_list_links_and_headers_are_checked() {
    let mut h = heap(plain(), Some(11));
    let (a, b) = (h.alloc(64, 8), h.alloc(64, 8));
    free(&mut h, a);
    free(&mut h, b);
    // Control: untouched, the head is b.
    let c = h.alloc(64, 8);
    assert_eq!(c, b);
    free(&mut h, c);
    // A write through the stale b clobbers its link.
    // SAFETY: inside the model's block.
    unsafe { (b as *mut u64).write(0x4141_4141_4141_4141) };
    assert!(is(fault_of(|| h.alloc(64, 8)), Fault::FreelistCorrupt));
    // And its header.
    let mut h = heap(plain(), Some(11));
    let a = h.alloc(64, 8);
    free(&mut h, a);
    poke(a as usize - 8, 0x55);
    assert!(is(fault_of(|| h.alloc(64, 8)), Fault::FreelistCorrupt));
}

// ── quarantine ──────────────────────────────────────────────────────────────

#[test]
fn quarantine_delays_reuse_in_fifo_order_and_is_bounded() {
    // 5 slots of class 80 fit the budget.
    let cfg = Config { quarantine_bytes: 5 * 80, randomize: false, ..hardened() };
    let mut h = heap(cfg, Some(1));
    let c: Vec<_> = (0..7).map(|_| h.alloc(64, 8)).collect();
    for &p in &c[..5] {
        free(&mut h, p);
    }
    assert_eq!((h.stats().quarantined, h.stats().evictions), (5, 0));
    let d = h.alloc(64, 8);
    assert!(!c[..5].contains(&d), "a quarantined chunk is not handed out");
    free(&mut h, c[5]); // over budget: the oldest leaves
    assert_eq!((h.stats().quarantined, h.stats().evictions), (5, 1));
    assert_eq!(h.alloc(64, 8), c[0], "oldest first, then LIFO from the free list");
    // Control: no quarantine, immediate reuse.
    let mut h = heap(plain(), Some(1));
    let p = h.alloc(64, 8);
    free(&mut h, p);
    assert_eq!(h.alloc(64, 8), p);
}

#[test]
fn quarantine_never_exceeds_its_budget_or_table() {
    let mut h = heap(hardened(), Some(2));
    let budget = h.config().quarantine_bytes;
    let mut live = vec![];
    for i in 0..3000usize {
        live.push(h.alloc(1 + i * 37 % 1500, 8));
        if live.len() > 40 {
            free(&mut h, live.remove(i % 40));
        }
        let s = h.stats();
        assert!(s.quarantined_bytes <= budget && s.quarantined <= 16, "{s:?}");
    }
}

#[test]
fn a_chunk_bigger_than_the_budget_is_not_quarantined() {
    let cfg = Config { quarantine_bytes: 64, ..plain() };
    let mut h = heap(cfg, Some(1));
    let p = h.alloc(500, 8); // slot 512 > budget 64
    free(&mut h, p);
    assert_eq!(h.stats().quarantined, 0);
}

// ── randomization ───────────────────────────────────────────────────────────

fn fresh_order(cfg: Config, seed: Option<u64>) -> Vec<usize> {
    let mut h = heap(cfg, seed);
    (0..16).map(|_| h.alloc(48, 8) as usize).collect()
}

#[test]
fn fresh_chunks_are_shuffled_by_the_kernel_entropy() {
    let asc = fresh_order(plain(), Some(1));
    assert!(asc.windows(2).all(|w| w[1] == w[0] + 64), "deterministic: address order");
    let orders: Vec<_> = (1..=8).map(|s| fresh_order(hardened(), Some(s))).collect();
    let distinct: std::collections::BTreeSet<_> =
        orders.iter().map(|o| o.iter().map(|a| (a - o.iter().min().unwrap()) / 64).collect::<Vec<_>>()).collect();
    assert!(distinct.len() >= 7, "{} distinct placements in 8 seeds", distinct.len());
    assert!(orders.iter().any(|o| !o.windows(2).all(|w| w[1] > w[0])), "not address order");
    // Same entropy, same placement (relative to the block).
    let rel = |o: &Vec<usize>| o.iter().map(|a| (a - o.iter().min().unwrap()) / 64).collect::<Vec<_>>();
    assert_eq!(rel(&fresh_order(hardened(), Some(4))), rel(&fresh_order(hardened(), Some(4))));
}

#[test]
fn reuse_picks_among_the_free_list() {
    // 16 chunks (a whole fresh window), freed, then 16 allocations: the
    // free list alone serves them, LIFO would give the exact reverse.
    let mut orders = std::collections::BTreeSet::new();
    for seed in 1..=6 {
        let cfg = Config { quarantine_bytes: 0, ..hardened() };
        let mut h = heap(cfg, Some(seed));
        let c: Vec<_> = (0..16).map(|_| h.alloc(48, 8)).collect();
        for &p in &c {
            free(&mut h, p);
        }
        let again: Vec<_> = (0..16).map(|_| h.alloc(48, 8)).collect();
        let mut s = again.clone();
        s.sort();
        let mut e = c.clone();
        e.sort();
        assert_eq!(s, e, "the same sixteen chunks");
        orders.insert(again.iter().map(|a| c.iter().position(|x| x == a).unwrap()).collect::<Vec<_>>());
    }
    assert!(orders.len() >= 4, "{orders:?}");
}

#[test]
fn without_entropy_placement_is_deterministic_and_says_so() {
    let mut h = heap(hardened(), None);
    let v: Vec<_> = (0..8).map(|_| h.alloc(48, 8) as usize).collect();
    assert!(v.windows(2).all(|w| w[1] == w[0] + 64));
    assert_eq!(h.sys().notes.len(), 1, "one line, not one per allocation");
    assert!(h.sys().notes[0].contains("not randomized"));
    assert!(!h.stats().seeded);
    // Checksums still work.
    let p = h.alloc(48, 8);
    free(&mut h, p);
    assert!(is(fault_of(|| free(&mut h, p)), Fault::DoubleFree));
    // Plain config: nothing to say.
    let mut h = heap(plain(), None);
    h.alloc(8, 8);
    assert!(h.sys().notes.is_empty());
}

#[test]
fn seed_required_faults_without_entropy() {
    let mut h = heap(Config { seed_required: true, ..hardened() }, None);
    assert!(is(fault_of(|| h.alloc(8, 8)), Fault::SeedMissing));
    let mut h = heap(Config { seed_required: true, ..hardened() }, Some(1));
    assert!(fault_of(|| h.alloc(8, 8)).is_none());
    assert!(h.stats().seeded);
}

// ── large allocations and guard pages ───────────────────────────────────────

#[test]
fn large_allocations_sit_between_guard_pages() {
    let mut h = heap(plain(), Some(1));
    for size in [2100usize, 3000, 4080, 4081, 5000, 8176, 8192, 100_000] {
        let p = h.alloc(size, 8) as usize;
        let &(base, len, guards) = h.sys().mapped.last().unwrap();
        assert!(guards);
        assert!(h.sys().guard_pages.contains(&(base - PAGE)) && h.sys().guard_pages.contains(&(base + len)));
        assert!(p - 16 >= base && p + size <= base + len);
        // Deterministic: the payload ends within 16 bytes of the guard, so an
        // overflow of 16 bytes or more touches it.
        assert!(base + len - (p + size) < 16, "size {size}: {} bytes of slack", base + len - (p + size));
    }
}

#[test]
fn large_placement_is_random_inside_the_pages() {
    let mut offs = std::collections::BTreeSet::new();
    for seed in 1..=8 {
        let mut h = heap(hardened(), Some(seed));
        let p = h.alloc(5000, 64) as usize;
        let &(base, len, _) = h.sys().mapped.last().unwrap();
        assert_eq!(p % 64, 0);
        assert!(p - 16 >= base && p + 5000 <= base + len);
        offs.insert(p - base);
    }
    assert!(offs.len() >= 4, "{offs:?}");
}

#[test]
fn guards_off_maps_without_guard_pages() {
    let mut h = heap(Config { guard: false, ..plain() }, Some(1));
    h.alloc(5000, 8);
    h.alloc(8, 8);
    assert!(h.sys().guard_pages.is_empty());
    assert!(h.sys().mapped.iter().all(|m| !m.2));
}

#[test]
fn blocks_have_guards_and_the_class_table_is_checked() {
    let mut h = heap(plain(), Some(1));
    let p = h.alloc(8, 8);
    let &(base, len, guards) = h.sys().mapped.last().unwrap();
    assert!(guards && len == 16 * 1024 && p as usize >= base && (p as usize) < base + len);
    assert!(h.sys().guard_pages.contains(&(base + len)));
}

#[test]
fn freeing_a_large_allocation_unmaps_exactly_what_was_mapped() {
    let mut h = heap(plain(), Some(1));
    let p = h.alloc(50_000, 8);
    let m = *h.sys().mapped.last().unwrap();
    free(&mut h, p);
    assert_eq!(h.sys().unmapped, vec![m]);
    let s = h.stats();
    assert_eq!((s.large_maps, s.large_unmaps), (1, 1));
}

// ── limits ──────────────────────────────────────────────────────────────────

#[test]
fn full_table_and_refused_maps_fail_the_allocation() {
    let mut h: Heap<Model, 2, 4> = Heap::new(Model::new(Some(1)), plain());
    assert!(!h.alloc(8, 8).is_null());
    assert!(!h.alloc(100, 8).is_null());
    assert!(h.alloc(500, 8).is_null(), "a third class needs a third mapping");
    assert!(h.alloc(5000, 8).is_null());
    assert_eq!(h.sys().mapped.len(), h.sys().unmapped.len() + 2, "the refused ones were given back");
    // Existing classes still work.
    assert!(!h.alloc(8, 8).is_null());

    let mut h = heap(plain(), Some(1));
    h.sys().map_budget = 0;
    assert!(h.alloc(8, 8).is_null() && h.alloc(8000, 8).is_null());
    h.sys().map_budget = usize::MAX;
    assert!(!h.alloc(8, 8).is_null());
}

// ── a long random workload against a shadow ─────────────────────────────────

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn workload(cfg: Config, seed: u64) {
    let mut h: Big = Heap::new(Model::new(Some(seed)), cfg);
    let mut rng = Rng(seed | 1);
    let mut live: Vec<(usize, usize, u8)> = vec![];
    let mut spans: BTreeMap<usize, usize> = BTreeMap::new();
    for step in 0..40_000usize {
        if live.len() < 400 && (live.is_empty() || rng.below(100) < 55) {
            let size = match rng.below(20) {
                0 => 2000 + rng.below(20_000),
                1..=3 => 200 + rng.below(1800),
                _ => rng.below(200),
            };
            let align = [8, 16, 32, 64][rng.below(4)];
            let p = h.alloc(size, align) as usize;
            assert_ne!(p, 0, "step {step}");
            assert_eq!(p % align.max(16), 0);
            let v = (rng.next() & 0xff) as u8;
            fill(p as *mut u8, size, v);
            if let Some((&q, &qs)) = spans.range(..=p).next_back() {
                assert!(q < p && q + qs <= p, "chunk {p:#x} overlaps {q:#x}+{qs}");
            }
            if let Some((&q, _)) = spans.range(p..).next() {
                assert!(p < q && p + size <= q, "chunk {p:#x}+{size} overlaps {q:#x}");
            }
            spans.insert(p, size);
            live.push((p, size, v));
        } else {
            let i = rng.below(live.len());
            let (p, size, v) = live.swap_remove(i);
            assert!(all_eq(p as *mut u8, size, v), "step {step}: chunk {p:#x} changed");
            spans.remove(&p);
            h.free(p as *mut u8, Some(size));
        }
    }
    for (p, size, v) in live {
        assert!(all_eq(p as *mut u8, size, v));
        h.free(p as *mut u8, Some(size));
    }
    let s = h.stats();
    assert_eq!(s.allocs, s.frees);
    assert_eq!(s.large_maps, s.large_unmaps);
}

#[test]
fn random_workload_plain() {
    workload(plain(), 1);
}

#[test]
fn random_workload_hardened() {
    workload(Config { quarantine_bytes: 64 * 1024, ..hardened() }, 2);
}

#[test]
fn random_workload_quarantine_without_poison_or_guards() {
    workload(Config { quarantine_bytes: 16 * 1024, poison: false, guard: false, ..hardened() }, 3);
}

#[test]
fn random_workload_poison_without_quarantine() {
    workload(Config { quarantine_bytes: 0, ..hardened() }, 4);
}
