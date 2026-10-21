// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for `frame.rs` (the descriptor table) and `buddy.rs` (the free
//! lists and the per-hart caches), the real files, over a private descriptor
//! table each: no singleton, no arena, so these run in parallel.
//!
//! Each row names the canary that turns it red (Cargo features of this crate
//! and of `azos_mm`, run by hand: `cargo test --release --features <canary>`;
//! the rows named are the ones each is aimed at, others go red with them):
//!
//! | canary               | red rows                                        |
//! |----------------------|-------------------------------------------------|
//! | `buddy-merge-canary` | `a_freed_block_merges_back_to_the_block_it_came_from`, `fragmentation_*` |
//! | `buddy-split-canary` | `a_split_keeps_every_frame_it_does_not_hand_out`, the alignment row |
//! | `pcp-refill-canary`  | `a_cache_refills_exactly_one_batch`             |
//! | `pcp-drain-canary`   | `a_cache_drained_gives_everything_back`         |
//! | `frame-index-canary` | `every_frame_has_its_own_descriptor`            |

use super::buddy::{order_for, Buddy, Pcp, MAX_ORDER};

/// What `pmm::alloc` does on a cache miss: a batch off the lists as a chain,
/// spliced onto the cache. Returns the frames it got.
fn refill(pcp: &Pcp, f: &Fx, b: &mut Buddy, n: usize) -> usize {
    let c = b.take_chain(&f.t, n);
    let got = c.len();
    pcp.splice(&f.t, c);
    got
}

/// What `pmm::free` does when the cache is full: the newest `n` frames cut
/// off as a chain and released to the lists.
fn drain(pcp: &Pcp, f: &Fx, b: &mut Buddy, n: usize) -> usize {
    let c = pcp.detach(&f.t, n);
    let gave = c.len();
    b.release_chain(&f.t, c);
    gave
}
use super::frame::*;
use core::sync::atomic::Ordering::Relaxed;

/// A private descriptor table and the vector it points into.
struct Fx {
    _descs: Vec<FrameDesc>,
    t: FrameTable,
}

fn fx(first: usize, n: usize, flags: u32) -> Fx {
    let descs: Vec<FrameDesc> = (0..n).map(|_| FrameDesc::new(flags)).collect();
    // SAFETY: the vector's buffer is not moved or dropped while `Fx` lives.
    let t = unsafe { FrameTable::new(descs.as_ptr(), Pfn(first), n) };
    Fx { _descs: descs, t }
}

/// A table of `n` frames from frame number `first`, all of it free and in the
/// lists as the fewest aligned blocks.
fn seeded(first: usize, n: usize) -> (Fx, Buddy) {
    let f = fx(first, n, F_FREE);
    let mut b = Buddy::new();
    b.release_range(&f.t, Pfn(first), Pfn(first + n));
    (f, b)
}

/// What `pmm::free` does to a block before it releases it.
fn give_back(f: &Fx, b: &mut Buddy, pfn: Pfn, order: usize) {
    for i in 0..1usize << order {
        f.t.get(Pfn(pfn.0 + i)).unwrap().flags.store(F_FREE, Relaxed);
    }
    b.release(&f.t, pfn, order);
}

fn count(f: &Fx, flags: u32) -> usize {
    (0..f.t.len()).filter(|&i| f.t.at(i).state() == flags).count()
}

/// The lists and the descriptors agree: every free frame is in a block.
fn assert_consistent(f: &Fx, b: &Buddy) {
    let listed: usize = (0..=MAX_ORDER).map(|o| b.blocks(o) << o).sum();
    assert_eq!(listed, b.free_frames(), "block counts and the free total disagree");
    assert_eq!(count(f, F_FREE), b.free_frames(), "F_FREE frames and the lists disagree");
}

// ── frame.rs ──────────────────────────────────────────────────────────────

#[test]
fn a_descriptor_is_32_bytes_and_has_no_colour_or_node_field() {
    assert_eq!(core::mem::size_of::<FrameDesc>(), 32);
    // Colour is the low bits of the frame number, nothing stored.
    assert_eq!(Pfn(0b1011).colour(4), 0b11);
    assert_eq!(Pfn(0b1011).colour(1), 0);
    assert_eq!(Pfn::from_phys(0x8020_1000), Pfn(0x80201));
    assert_eq!(Pfn(0x80201).phys(), 0x8020_1000);
}

#[test]
fn the_state_bits_are_distinct_single_bits() {
    let bits = [F_FREE, F_ALLOCATED, F_RESERVED, F_PINNED, F_COMPRESSED, F_SWAPPED, F_CACHED];
    for (i, a) in bits.iter().enumerate() {
        assert_eq!(a.count_ones(), 1, "bit {i}");
        for b in &bits[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// The descriptor of a frame comes from its frame number alone: first and
/// last are the ends of the array, and just outside either end there is none.
#[test]
fn descriptors_are_indexed_from_the_frame_number() {
    let f = fx(0x8_0000, 100, 0);
    let t = &f.t;
    assert_eq!(t.index(Pfn(0x8_0000)), Some(0));
    assert_eq!(t.index(Pfn(0x8_0000 + 99)), Some(99));
    assert_eq!(t.index(Pfn(0x8_0000 + 100)), None, "one past the end");
    assert_eq!(t.index(Pfn(0x8_0000 - 1)), None, "one before the start");
    assert_eq!(t.index(Pfn(0)), None);
    assert_eq!(t.pfn(37), Pfn(0x8_0000 + 37));
    assert_eq!(t.end(), Pfn(0x8_0000 + 100));
    assert!(t.of_phys(0x8_0000 << 12).is_some());
    assert!(t.of_phys((0x8_0000 << 12) + 1).is_none(), "unaligned");
    assert!(t.of_phys((0x8_0000 + 100) << 12).is_none());
}

/// **Canary `frame-index-canary`.** Two frames sharing a descriptor would
/// share a state, a link and a COW count.
#[test]
fn every_frame_has_its_own_descriptor() {
    let f = fx(0x8_0000, 64, 0);
    for i in 0..64 {
        f.t.get(Pfn(0x8_0000 + i)).unwrap().refcount.store(1000 + i as u32, Relaxed);
    }
    for i in 0..64 {
        assert_eq!(f.t.get(Pfn(0x8_0000 + i)).unwrap().refcount(), 1000 + i as u32,
                   "frame {i} lost its count to another frame's descriptor");
    }
}

// ── buddy.rs ──────────────────────────────────────────────────────────────

#[test]
fn order_for_is_the_smallest_block_that_holds_n_frames() {
    for (n, o) in [(0, 0), (1, 0), (2, 1), (3, 2), (4, 2), (5, 3), (512, 9), (513, 10)] {
        assert_eq!(order_for(n), o, "{n} frames");
    }
}

/// RAM that does not start on a block boundary is seeded as the fewest
/// aligned blocks: a lone frame, then growing blocks up to the end.
#[test]
fn seeding_makes_the_fewest_aligned_blocks() {
    let (f, b) = seeded(3, 61); // frames 3..64
    for (order, want) in [(0, 1), (1, 0), (2, 1), (3, 1), (4, 1), (5, 1), (6, 0)] {
        assert_eq!(b.blocks(order), want, "order {order}");
    }
    assert_eq!(b.free_frames(), 61);
    assert_consistent(&f, &b);
}

/// **Canary `buddy-split-canary`, `buddy-merge-canary`.** One frame out of a
/// 64-frame block leaves one free block of every smaller order (the upper
/// halves); freeing it merges them all back into the one block.
#[test]
fn a_split_keeps_every_frame_it_does_not_hand_out() {
    let (f, mut b) = seeded(0, 64);
    assert_eq!(b.blocks(6), 1);
    let p = b.alloc(&f.t, 0).expect("a free block");
    assert_eq!(p, Pfn(0), "the lowest frame of the block");
    assert_eq!(f.t.get(p).unwrap().state(), F_ALLOCATED);
    assert_eq!(b.free_frames(), 63);
    for order in 0..6 {
        assert_eq!(b.blocks(order), 1, "upper half of order {order}");
    }
    assert_eq!(b.blocks(6), 0);
    assert_consistent(&f, &b);
}

#[test]
fn a_freed_block_merges_back_to_the_block_it_came_from() {
    let (f, mut b) = seeded(0, 64);
    let p = b.alloc(&f.t, 0).unwrap();
    give_back(&f, &mut b, p, 0);
    assert_eq!(b.blocks(6), 1, "the 64-frame block is whole again");
    assert_eq!(b.free_frames(), 64);
    for order in 0..6 {
        assert_eq!(b.blocks(order), 0, "order {order} left over");
    }
    assert_consistent(&f, &b);
}

/// Every block is aligned to its own size (in absolute frame numbers, so
/// also in the physical address space), the blocks do not overlap, and
/// returning them all rebuilds the one big block.
#[test]
fn blocks_are_naturally_aligned_disjoint_and_come_back_whole() {
    let (f, mut b) = seeded(0, 512);
    let mut taken: Vec<(Pfn, usize)> = Vec::new();
    for order in [3, 0, 5, 1, 2, 4, 0, 6, 1, 3] {
        let p = b.alloc(&f.t, order).expect("room");
        assert_eq!(p.0 % (1 << order), 0, "order {order} block at {p:?}");
        for i in 0..1usize << order {
            let st = f.t.get(Pfn(p.0 + i)).unwrap().state();
            assert_eq!(st, F_ALLOCATED, "frame {i} of the order-{order} block");
        }
        for &(q, qo) in &taken {
            let (a0, a1, b0, b1) = (p.0, p.0 + (1 << order), q.0, q.0 + (1 << qo));
            assert!(a1 <= b0 || b1 <= a0, "{p:?}/{order} overlaps {q:?}/{qo}");
        }
        taken.push((p, order));
    }
    assert_consistent(&f, &b);
    for (p, order) in taken {
        give_back(&f, &mut b, p, order);
    }
    assert_eq!(b.blocks(9), 1, "all 512 frames are one block again");
    assert_eq!(b.free_frames(), 512);
}

/// A block only ever merges with its OWN buddy: four free frames that
/// straddle an alignment boundary do not make an order-2 block.
///
/// **Canary `buddy-merge-canary`.**
#[test]
fn fragmentation_free_frames_merge_only_with_their_buddy() {
    let (f, mut b) = seeded(0, 64);
    let all: Vec<Pfn> = (0..64).map(|_| b.alloc(&f.t, 0).unwrap()).collect();
    assert_eq!(b.free_frames(), 0);
    assert!(b.alloc(&f.t, 0).is_none(), "exhausted");

    // Every other frame: 32 free frames and not one pair.
    for p in all.iter().filter(|p| p.0 % 2 == 0) {
        give_back(&f, &mut b, *p, 0);
    }
    assert_eq!(b.free_frames(), 32);
    assert_eq!(b.blocks(0), 32, "no two free frames are buddies");
    assert!(b.alloc(&f.t, 1).is_none(), "32 frames free, none contiguous: no order-1 block");
    assert_consistent(&f, &b);

    // Fill the gaps: they pair up, and the pairs pair up, to the whole.
    for p in all.iter().filter(|p| p.0 % 2 == 1) {
        give_back(&f, &mut b, *p, 0);
    }
    assert_eq!(b.blocks(6), 1, "fully merged");
    assert_eq!(b.free_frames(), 64);
}

#[test]
fn four_free_frames_across_an_alignment_boundary_are_not_an_order_two_block() {
    let (f, mut b) = seeded(0, 64);
    let all: Vec<Pfn> = (0..64).map(|_| b.alloc(&f.t, 0).unwrap()).collect();
    for p in &all[2..6] {
        give_back(&f, &mut b, *p, 0);
    }
    // 2,3 are buddies and 4,5 are buddies; 2..4 and 4..6 are not.
    assert_eq!(b.blocks(1), 2);
    assert_eq!(b.blocks(2), 0, "frames 2..6 straddle the order-2 boundary at 4");
    assert!(b.alloc(&f.t, 2).is_none());
    for p in [&all[0], &all[1], &all[6], &all[7]] {
        give_back(&f, &mut b, *p, 0);
    }
    assert_eq!(b.blocks(3), 1, "0..8 is one block once its ends are back");
}

/// Reserving a range in the middle of a block splits the block around it:
/// what is outside stays allocatable, nothing inside is ever handed out.
#[test]
fn carving_a_range_out_of_a_free_block_leaves_the_rest_usable() {
    let (f, mut b) = seeded(0, 64);
    b.carve(&f.t, Pfn(10), Pfn(20));
    assert_eq!(b.free_frames(), 54);
    for i in 0..64 {
        let st = f.t.get(Pfn(i)).unwrap().state();
        assert_eq!(st, if (10..20).contains(&i) { F_RESERVED } else { F_FREE }, "frame {i}");
    }
    assert_consistent(&f, &b);
    let mut seen = std::collections::HashSet::new();
    while let Some(p) = b.alloc(&f.t, 0) {
        assert!(!(10..20).contains(&p.0), "{p:?} is reserved");
        assert!(seen.insert(p.0), "{p:?} handed out twice");
    }
    assert_eq!(seen.len(), 54);
}

#[test]
fn carving_leaves_frames_in_use_and_already_reserved_alone() {
    let (f, mut b) = seeded(0, 64);
    let used = b.alloc(&f.t, 0).unwrap(); // frame 0
    b.carve(&f.t, Pfn(0), Pfn(8));
    assert_eq!(f.t.get(used).unwrap().state(), F_ALLOCATED, "in use: not reserved");
    for i in 1..8 {
        assert_eq!(f.t.get(Pfn(i)).unwrap().state(), F_RESERVED);
    }
    assert_eq!(b.free_frames(), 56);
    let before = b.free_frames();
    b.carve(&f.t, Pfn(4), Pfn(12)); // overlaps the reserved ones
    assert_eq!(b.free_frames(), before - 4, "only 8..12 were still free");
    b.carve(&f.t, Pfn(60), Pfn(1000)); // runs past the table
    assert_eq!(b.free_frames(), before - 8);
    assert_consistent(&f, &b);
}

/// An exact-size run takes the block that holds it and gives the tail back
/// at once, so the surplus is neither lost nor left allocated.
#[test]
fn a_run_takes_exactly_its_frames_and_returns_the_tail() {
    let (f, mut b) = seeded(0, 64);
    let p = b.alloc_run(&f.t, 5, 0).expect("room");
    assert_eq!(p, Pfn(0));
    assert_eq!(b.free_frames(), 59);
    assert_eq!(count(&f, F_ALLOCATED), 5);
    // 5..8 went back as 5 (order 0) and 6..8 (order 1), then merge no further.
    assert_eq!((b.blocks(0), b.blocks(1)), (1, 1));
    assert_consistent(&f, &b);
    for i in 0..5 {
        give_back(&f, &mut b, Pfn(i), 0);
    }
    assert_eq!(b.blocks(6), 1, "frame by frame, as the callers free a run");

    let q = b.alloc_run(&f.t, 3, 4).expect("room");
    assert_eq!(q.0 % 16, 0, "min_order 4 starts on a multiple of 16 frames");
    assert!(b.alloc_run(&f.t, 65, 0).is_none(), "more than the table has");
    assert_eq!(b.free_frames(), 61, "a refused run claims nothing");
}

// ── the per-hart cache ────────────────────────────────────────────────────

/// **Canary `pcp-refill-canary`.**
#[test]
fn a_cache_refills_exactly_one_batch() {
    let (f, mut b) = seeded(0, 64);
    let pcp = Pcp::new();
    assert_eq!(refill(&pcp, &f, &mut b, 8), 8);
    assert_eq!(pcp.len(), 8);
    assert_eq!(b.free_frames(), 56, "the batch left the lists");
    assert_eq!(count(&f, F_CACHED), 8, "and is marked cached, not allocated");
    assert_eq!(count(&f, F_ALLOCATED), 0);
}

#[test]
fn a_cache_hands_out_its_newest_frame_and_marks_it_allocated() {
    let (f, mut b) = seeded(0, 64);
    let pcp = Pcp::new();
    refill(&pcp, &f, &mut b, 4);
    let a = pcp.pop(&f.t).unwrap();
    let c = pcp.pop(&f.t).unwrap();
    assert_ne!(a, c);
    assert_eq!(f.t.get(a).unwrap().state(), F_ALLOCATED);
    assert_eq!(pcp.len(), 2);
    // A frame freed now is the next one handed out (cache-hot reuse).
    f.t.get(a).unwrap().flags.store(F_CACHED, Relaxed);
    pcp.push(&f.t, f.t.index(a).unwrap());
    assert_eq!(pcp.pop(&f.t), Some(a));
    pcp.pop(&f.t).unwrap();
    pcp.pop(&f.t).unwrap();
    assert!(pcp.pop(&f.t).is_none(), "empty");
    assert_eq!(pcp.len(), 0);
}

#[test]
fn a_cache_refill_stops_where_the_lists_run_dry() {
    let (f, mut b) = seeded(0, 4);
    let pcp = Pcp::new();
    assert_eq!(refill(&pcp, &f, &mut b, 8), 4);
    assert_eq!(b.free_frames(), 0);
}

/// **Canary `pcp-drain-canary`.** Frames drained from a cache rejoin the
/// lists, merge with their neighbours, and nothing is left behind.
#[test]
fn a_cache_drained_gives_everything_back() {
    let (f, mut b) = seeded(0, 64);
    let pcp = Pcp::new();
    refill(&pcp, &f, &mut b, 10);
    let out = pcp.pop(&f.t).unwrap(); // one in use
    assert_eq!(drain(&pcp, &f, &mut b, 4), 4);
    assert_eq!(pcp.len(), 5);
    assert_eq!(b.free_frames(), 54 + 4);
    assert_eq!(drain(&pcp, &f, &mut b, 100), 5, "asked for more than it holds");
    assert_eq!(pcp.len(), 0);
    assert_eq!(b.free_frames(), 63);
    assert_consistent(&f, &b);
    give_back(&f, &mut b, out, 0);
    assert_eq!(b.blocks(6), 1, "every frame came back and merged");
    assert_eq!(count(&f, F_CACHED), 0);
}

/// The cache driven the way `pmm::alloc` and `pmm::free` drive it (refill a
/// batch on a miss, cut a batch plus the new frame off when full): over
/// thousands of random steps no frame is lost, duplicated or handed out
/// twice, the cache never exceeds its ceiling, and everything given back
/// merges to the one block it came from.
#[test]
fn a_cache_driven_like_pmm_never_loses_or_duplicates_a_frame() {
    const BATCH: usize = 4;
    const HIGH: usize = 8;
    let (f, mut b) = seeded(0, 256);
    let pcp = Pcp::new();
    let mut held: Vec<Pfn> = Vec::new();
    let mut live = std::collections::HashSet::new();
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let free_one = |p: Pfn, pcp: &Pcp, b: &mut Buddy| {
        f.t.get(p).unwrap().flags.store(F_CACHED, Relaxed);
        let idx = f.t.index(p).unwrap();
        if pcp.len() < HIGH {
            pcp.push(&f.t, idx);
        } else {
            let mut c = pcp.detach(&f.t, BATCH);
            c.push_front(&f.t, idx);
            b.release_chain(&f.t, c);
        }
    };
    for step in 0..6000 {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        if s % 5 < 3 || held.is_empty() {
            let p = pcp.pop(&f.t).or_else(|| {
                refill(&pcp, &f, &mut b, BATCH);
                pcp.pop(&f.t)
            });
            if let Some(p) = p {
                assert!(live.insert(p.0), "frame {p:?} handed out twice at step {step}");
                assert_eq!(f.t.get(p).unwrap().state(), F_ALLOCATED);
                held.push(p);
            }
        } else {
            let p = held.swap_remove((s >> 20) as usize % held.len());
            live.remove(&p.0);
            free_one(p, &pcp, &mut b);
        }
        assert!(pcp.len() <= HIGH, "cache over its ceiling at step {step}");
        assert_eq!(b.free_frames() + pcp.len() + held.len(), 256, "a frame was lost at step {step}");
    }
    for p in held.drain(..) {
        free_one(p, &pcp, &mut b);
    }
    drain(&pcp, &f, &mut b, HIGH);
    assert_eq!(b.blocks(8), 1, "everything merged back into the one block");
    assert_eq!(b.free_frames(), 256);
    assert_consistent(&f, &b);
}
