// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// A Linux task's mmap placement (`handlers::mmap_place`): the hint, exact
// no-replace placement, the area apart from the break. Against the real
// `handlers.rs`, `vmm.rs`, `pager.rs` and `region.rs` on the shim arena.
//
// What each row pins, and its canary (a feature of this crate mirroring
// azos_syscall's):
//
// * zig's `PageAllocator` (BusyBox's libc) grows its heap by 64 KiB slabs,
//   each a 124 KiB `mmap` at a hint just below the last slab, trimmed by
//   `munmap` to the aligned 64 KiB. The slabs make one contiguous run in one
//   region record. Canary `mmap-brk-apart-canary` (placed at the break, as
//   before): every slab lands past the last trim, nine records then eager
//   commits. `mmap-hint-canary` does NOT turn it red, and that is a finding,
//   not a gap: the head trim gives the cursor back, so the top-down placement
//   lands exactly where zig's hint points.
// * A free hint is honoured, a taken one falls back. Canary
//   `mmap-hint-canary` (the hint is not read).
// * `MAP_FIXED_NOREPLACE`: the exact address or `-EEXIST`, never over a
//   mapping. Canary `mmap-noreplace-canary` (it falls back like a hint).
// * The break and the mappings stay apart: a Linux task's mappings start at
//   the area's floor, which is the break's ceiling, and leave the break
//   where it was. Canary `mmap-brk-apart-canary` (mappings at the break again).
// * A hint outside the area (the break's zone, the vDSO page, the shm
//   window, across the ceiling) is not honoured. Canary
//   `mmap-hint-window-canary` (any vacant range is taken).
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;

const ANON: u64 = u64::MAX;
const RW: u64 = 3;
const NONE: u64 = 0;
/// A break that is not 64 KiB-aligned, as an image's end is not.
const BRK: u64 = 0x4_6000;
const SLAB: usize = 64 * 1024;
/// zig's `PageAllocator.map(64 KiB, align 64 KiB)`: the length plus the
/// alignment less a page, so an aligned slab lies somewhere inside.
const OVER: usize = 2 * SLAB - PAGE_SIZE;
const EEXIST: i64 = -17;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;
const EPERM: i64 = -1;

/// A fresh, empty address space of a Linux task with no budget, its break at
/// [`BRK`] and its mmap cursor where a new address space has it (nothing
/// handed out).
fn linux_space() -> usize {
    let old = azos_sched::current_user_pt();
    if old != 0 {
        azos_mm::pager::forget(old);
    }
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_sched_class(3);
    azos_sched::shim_set_brk(BRK);
    azos_sched::shim_set_linux(true);
    pt
}

fn map_at(hint: usize, pages: usize, prot: u64, flags: u64) -> i64 {
    sys_mmap(hint as u64, (pages * PAGE_SIZE) as u64, prot, flags, ANON, 0)
}

fn map(pages: usize) -> usize {
    let r = map_at(0, pages, RW, 0);
    assert!(r > 0, "mmap failed: {r}");
    r as usize
}

/// One growth of zig's allocator: map [`OVER`] bytes at the hint it computes
/// from the last slab (`None` on the first), trim to the aligned slab.
/// Returns the slab and the pages charged at the peak (between the map and
/// the trims).
fn zig_grow(last: Option<usize>) -> (usize, u32) {
    let hint = last.map_or(0, |a| ((a - SLAB) & !(SLAB - 1)) - (SLAB - PAGE_SIZE));
    let before = azos_sched::shim_user_pages();
    let s = sys_mmap(hint as u64, OVER as u64, RW, 0, ANON, 0);
    assert!(s > 0, "mmap {hint:#x}: {s}");
    let s = s as usize;
    let peak = azos_sched::shim_user_pages() - before;
    let slab = (s + SLAB - 1) & !(SLAB - 1);
    if slab != s {
        assert_eq!(sys_munmap(s as u64, (slab - s) as u64), 0);
    }
    let rest = OVER - (slab - s);
    if rest > SLAB {
        assert_eq!(sys_munmap((slab + SLAB) as u64, (rest - SLAB) as u64), 0);
    }
    (slab, peak)
}

#[test]
fn zig_heap_growth_is_one_contiguous_run() {
    let _g = serial();
    let pt = linux_space();
    let frames = azos_mm::shim_pages_in_use();
    const SLABS: usize = 12;
    let mut last = None;
    for i in 0..SLABS {
        let (slab, peak) = zig_grow(last);
        let net = azos_sched::shim_user_pages() as usize;
        eprintln!("slab {i:2}: {slab:#x} peak {peak} total {net} region {:?}", azos_mm::pager::space_pages(pt));
        assert_eq!(peak as usize, OVER / PAGE_SIZE, "the whole request is charged at map time");
        assert_eq!(net, (i + 1) * SLAB / PAGE_SIZE, "the trims give back all but the slab");
        if let Some(prev) = last {
            assert_eq!(slab + SLAB, prev, "slab {i} lies right below the last one");
        }
        last = Some(slab);
    }
    // One run of reserved, uncommitted pages: one region record, so the
    // space never runs out of records and never falls back to committing
    // every page at map time (the baseline did from the ninth slab on).
    assert_eq!(azos_mm::pager::space_pages(pt), (SLABS * SLAB / PAGE_SIZE, 0));
    assert_eq!(azos_mm::shim_pages_in_use(), frames, "nothing committed, no table built");
    let (floor, ceiling) = azos_sched::user_mmap_area();
    assert_eq!(last.unwrap() + SLABS * SLAB, ceiling, "the run ends at the ceiling");
    assert!(last.unwrap() >= floor);
}

#[test]
fn a_free_hint_is_honoured_a_taken_one_falls_back() {
    let _g = serial();
    let pt = linux_space();
    let (_, ceiling) = azos_sched::user_mmap_area();
    let first = map(4);
    assert_eq!(first, ceiling - 4 * PAGE_SIZE, "top-down from the ceiling");
    let want = ceiling - 64 * PAGE_SIZE;
    assert_eq!(map_at(want, 4, RW, 0), want as i64, "a vacant range below the cursor");
    // Over the mapping just made: placed elsewhere, the mapping untouched.
    let reserved = azos_mm::pager::space_pages(pt);
    let charged = azos_sched::shim_user_pages();
    let other = map_at(want, 4, RW, 0);
    assert!(other > 0 && other as usize != want, "a taken hint falls back: {other:#x}");
    assert!(other as usize + 4 * PAGE_SIZE <= want || other as usize >= want + 4 * PAGE_SIZE);
    assert_eq!(azos_mm::pager::space_pages(pt).0, reserved.0 + 4);
    assert_eq!(azos_sched::shim_user_pages(), charged + 4);
    // An unaligned hint rounds up to its page, as Linux's does.
    let up = ceiling - 128 * PAGE_SIZE;
    assert_eq!(map_at(up - PAGE_SIZE + 1, 2, RW, 0), up as i64);
}

#[test]
fn noreplace_places_exactly_or_answers_eexist() {
    let _g = serial();
    let pt = linux_space();
    let (floor, ceiling) = azos_sched::user_mmap_area();
    let nr = MMAP_MAP_FIXED_NOREPLACE;
    let at = ceiling - 256 * PAGE_SIZE;
    assert_eq!(map_at(at, 8, RW, nr), at as i64);
    let reserved = azos_mm::pager::space_pages(pt);
    let charged = azos_sched::shim_user_pages();
    // Over it, whole or in part: refused, nothing changes.
    assert_eq!(map_at(at, 8, RW, nr), EEXIST);
    assert_eq!(map_at(at + 4 * PAGE_SIZE, 8, RW, nr), EEXIST);
    assert_eq!(map_at(at - 4 * PAGE_SIZE, 8, RW, nr), EEXIST);
    assert_eq!(azos_mm::pager::space_pages(pt), reserved);
    assert_eq!(azos_sched::shim_user_pages(), charged);
    // Above the cursor nothing is presumed free: a PROT_NONE mapping there
    // leaves no record of itself.
    let none = map_at(0, 2, NONE, 0);
    assert!(none > 0);
    assert_eq!(map_at(none as usize, 2, RW, nr), EEXIST, "over a PROT_NONE mapping");
    // Unaligned, outside the area, or across its edge.
    assert_eq!(map_at(at - 64 * PAGE_SIZE + 1, 1, RW, nr), EINVAL);
    assert_eq!(map_at(floor - PAGE_SIZE, 2, RW, nr), ENOMEM, "into the break's zone");
    assert_eq!(map_at(ceiling - PAGE_SIZE, 2, RW, nr), ENOMEM, "across the ceiling");
    assert_eq!(map_at(ceiling, 1, RW, nr), ENOMEM, "the vDSO page");
    // A native task's exact placement is the module window
    // (module_window_tests.rs): without a live module token, EPERM.
    azos_sched::shim_set_linux(false);
    assert_eq!(map_at(at - 64 * PAGE_SIZE, 1, RW, nr), EPERM);
}

#[test]
fn the_break_and_the_mappings_stay_apart() {
    let _g = serial();
    let _pt = linux_space();
    let (floor, ceiling) = azos_sched::user_mmap_area();
    // `sys_brk_impl` grows the break up to `USER_LOW_MAX` and no further: that
    // is the floor here, so no mapping can lie where the break grows.
    assert_eq!(floor, 0x0200_0000, "the floor is the break's ceiling");
    for (pages, prot) in [(4, RW), (2, NONE), (OVER / PAGE_SIZE, RW)] {
        let m = map_at(0, pages, prot, 0);
        assert!(m as usize >= floor && m as usize + pages * PAGE_SIZE <= ceiling, "{m:#x}");
        assert_eq!(azos_sched::update_user_brk(0), BRK, "a mapping leaves the break alone");
    }
    // A hint into the break's zone is not taken either.
    let m = map_at(BRK as usize + 16 * PAGE_SIZE, 4, RW, 0);
    assert!(m as usize >= floor, "{m:#x}");
    assert_eq!(azos_sched::update_user_brk(0), BRK);
    // A native task still maps at its break and moves it (ualloc's guards).
    azos_sched::shim_set_linux(false);
    assert_eq!(map_at(0, 2, RW, 0), BRK as i64);
    assert_eq!(azos_sched::update_user_brk(0), BRK + 2 * PAGE_SIZE as u64);
}

#[test]
fn a_hint_outside_the_area_is_ignored() {
    let _g = serial();
    let _pt = linux_space();
    let (floor, ceiling) = azos_sched::user_mmap_area();
    let (shm_lo, _) = azos_sched::user_shm_window();
    let mut cursor = ceiling;
    for hint in [
        0x1000,                     // the null guard
        BRK as usize,               // the break
        floor - 4 * PAGE_SIZE,      // the break's zone, up to the floor
        ceiling,                    // the vDSO page
        ceiling - 2 * PAGE_SIZE,    // across the ceiling
        shm_lo,                     // the shm/MMIO window
    ] {
        let m = map_at(hint, 4, RW, 0);
        assert_eq!(m, (cursor - 4 * PAGE_SIZE) as i64, "hint {hint:#x}: the default placement");
        cursor = m as usize;
    }
}

#[test]
fn mprotect_opens_a_prot_none_mapping_in_the_area() {
    let _g = serial();
    let pt = linux_space();
    // musl reserves a thread stack PROT_NONE and opens it with mprotect: the
    // area above the cursor is handed out, like the pages below the break.
    let m = map_at(0, 4, NONE, 0);
    assert!(m > 0);
    assert_eq!(sys_mprotect(m as u64, (4 * PAGE_SIZE) as u64, RW), 0);
    assert!(matches!(azos_mm::vmm::user_page(pt, m as usize), azos_mm::vmm::UserPage::Leaf { .. }));
    // Below the cursor nothing was handed out: still refused.
    assert_eq!(sys_mprotect((m as usize - 16 * PAGE_SIZE) as u64, PAGE_SIZE as u64, RW), ENOMEM);
}
