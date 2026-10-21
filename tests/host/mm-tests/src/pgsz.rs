// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the plan `vmm::map_contig_range` follows, the real
//! `azos_arch_api::contig`: which stretch of a region's frames and addresses
//! is a run (virtual and physical start aligned to the run, the frames
//! consecutive).
//!
//! What is NOT here: the page-table half (the CAS install of a run, the
//! break-before-make of a break), which needs a live MMU and runs in the boot
//! gate on the Raspberry Pi boards (QEMU does not model the TLB conflict
//! abort). The words themselves are pinned in `tests/host/arch-tests`.
//!
//! Canaries (by hand, red then green):
//! * `is_run` ignoring the physical alignment: `a_run_needs_both_addresses_aligned` goes red.
//! * `is_run` comparing the first and last frame only: `a_gap_inside_the_run_is_not_a_run` goes red.
//! * `step_pages` always returning `run_pages`: `the_plan_splits_a_region_into_head_runs_and_tail` goes red.

use azos_arch_api::contig::{is_run, step_pages};

const P: usize = 4096;
const R: usize = 16; // pages in a run (riscv64 Svnapot, aarch64 4 KiB granule)
const VA: usize = 0x6001_0000; // aligned to 16 pages

fn frames(first: usize, n: usize) -> Vec<usize> {
    (0..n).map(|i| first + i * P).collect()
}

/// The steps the mapper takes over a region: `(pages, is_run)` per step.
fn plan(run_pages: usize, mut va: usize, phys: &[usize]) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < phys.len() {
        let n = step_pages(P, run_pages, va, &phys[i..]);
        out.push((n, n > 1));
        va += n * P;
        i += n;
    }
    out
}

#[test]
fn an_aligned_consecutive_stretch_is_a_run() {
    assert!(is_run(P, R, VA, &frames(0x8000_0000, R)));
    assert!(is_run(P, R, VA, &frames(0x8000_0000, R + 5)), "a longer slice: the first run");
}

#[test]
fn a_run_needs_both_addresses_aligned() {
    assert!(!is_run(P, R, VA + P, &frames(0x8000_0000, R)), "virtual start inside a run");
    assert!(!is_run(P, R, VA, &frames(0x8000_0000 + P, R)), "physical start inside a run");
    assert!(!is_run(P, R, VA, &frames(0x8000_0000 + 8 * P, R)), "half a run off");
}

#[test]
fn a_gap_inside_the_run_is_not_a_run() {
    let mut f = frames(0x8000_0000, R);
    f[R / 2] += P; // one frame out of place; first and last still line up with a gap-free guess
    assert!(!is_run(P, R, VA, &f));
    let mut g = frames(0x8000_0000, R);
    g.swap(3, 4);
    assert!(!is_run(P, R, VA, &g), "out of order");
    assert!(!is_run(P, R, VA, &frames(0x8000_0000, R - 1)), "one frame short");
    assert!(!is_run(P, R, VA, &[]));
}

#[test]
fn an_isa_without_runs_never_plans_one() {
    for run_pages in [0, 1] {
        assert!(!is_run(P, run_pages, VA, &frames(0x8000_0000, R)));
        assert_eq!(step_pages(P, run_pages, VA, &frames(0x8000_0000, R)), 1);
    }
}

#[test]
fn the_plan_splits_a_region_into_head_runs_and_tail() {
    // 3 head pages (virtual start 3 pages before a run boundary, frames
    // consecutive and aligned only from the 4th), two runs, 5 tail pages.
    let head = 3;
    let n = head + 2 * R + 5;
    let mut f = frames(0x8000_0000 - head * P, n);
    // The frames after the head are one aligned stretch.
    assert!(is_run(P, R, VA, &f[head..]));
    let steps = plan(R, VA - head * P, &f);
    let mut want = vec![(1, false); head];
    want.extend([(R, true), (R, true)]);
    want.extend(vec![(1, false); 5]);
    assert_eq!(steps, want);
    assert_eq!(steps.iter().map(|s| s.0).sum::<usize>(), n, "every page is covered once");
    // The same frames on an ISA without runs: all pages.
    assert!(plan(0, VA - head * P, &f).iter().all(|s| *s == (1, false)));
    // A frame swapped inside the second run: it falls back to pages.
    f.swap(head + R + 2, head + R + 3);
    let steps = plan(R, VA - head * P, &f);
    assert_eq!(steps.iter().filter(|s| s.1).count(), 1, "only the first run survives");
}

#[test]
fn a_region_with_frames_in_buddy_order_gets_the_runs_that_line_up() {
    // Two 16-frame blocks of the page allocator, then a lone frame: the
    // region's first 32 pages at an aligned address are two runs.
    let mut f = frames(0x8010_0000, R);
    f.extend(frames(0x8030_0000, R));
    f.push(0x8002_0000);
    assert_eq!(plan(R, VA, &f), vec![(R, true), (R, true), (1, false)]);
    // The second block is not aligned to 16 frames: it is pages.
    let mut g = frames(0x8010_0000, R);
    g.extend(frames(0x8030_1000, R));
    assert_eq!(plan(R, VA, &g)[0], (R, true));
    assert!(plan(R, VA, &g)[1..].iter().all(|s| *s == (1, false)));
}
