// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The W^X planner with the `.data.ro_after_init` span carved out of the data
//! range (`wx::plan_with_ro`, security audit 2026-10-17 finding D).
//!
//! Before the seal the span is RW like the rest of `.data` (the boot installs
//! the hooks into it); after it, RO. `vmm::enforce_wx`, the seal and every
//! readback (`verify_wx`, the `mm_wx_image` ktest) read the SAME plan, so the
//! readback that follows the seal expects exactly what the seal wrote.

use super::wx::{self, RoAfterInit};
use azos_arch_api::{PagePerms, PAGE_SIZE};

const BASE: usize = 0x8020_0000;
const TEXT_END: usize = BASE + 0x3_0800;
const RO_END: usize = BASE + 0x4_0400;
const DATA_START: usize = RO_END;
const KERNEL_END: usize = BASE + 0x8_0000;
/// Two pages of hooks, page-aligned at both ends, after the rodata's last
/// page, as the linker scripts place them.
const HOOKS_START: usize = (RO_END + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
const HOOKS_END: usize = HOOKS_START + 2 * PAGE_SIZE;

fn plan(sealed: bool) -> [wx::WxRange; 5] {
    wx::plan_with_ro(BASE, TEXT_END, TEXT_END, RO_END, DATA_START, KERNEL_END,
        RoAfterInit { start: HOOKS_START, end: HOOKS_END, sealed })
}

fn flags_at(p: &[wx::WxRange; 5], addr: usize) -> Option<PagePerms> {
    p.iter().filter(|r| !r.is_empty() && addr >= r.start && addr < r.end).map(|r| r.flags).last()
}

#[test]
fn before_the_seal_the_hooks_are_writable_like_the_rest_of_data() {
    let p = plan(false);
    for a in (HOOKS_START..HOOKS_END).step_by(PAGE_SIZE) {
        assert_eq!(flags_at(&p, a), Some(PagePerms::KERNEL_RW), "{a:#x}");
    }
}

/// The discriminating pair: the same page is RW before and RO after. If the
/// planner ignored `sealed`, the readback after the seal would call the
/// freshly sealed pages wrong.
#[test]
fn after_the_seal_exactly_the_hook_pages_are_read_only() {
    let p = plan(true);
    for a in (HOOKS_START..HOOKS_END).step_by(PAGE_SIZE) {
        assert_eq!(flags_at(&p, a), Some(PagePerms::KERNEL_RO), "{a:#x}");
    }
    // The page after (ordinary .data) is not sealed; the one before is the
    // rodata's, RO for its own reason (`sealing_changes_no_other_page`).
    assert_eq!(flags_at(&p, HOOKS_END), Some(PagePerms::KERNEL_RW));
    assert_eq!(flags_at(&p, KERNEL_END - PAGE_SIZE), Some(PagePerms::KERNEL_RW));
}

#[test]
fn sealing_changes_no_other_page_of_the_image() {
    let (a, b) = (plan(false), plan(true));
    let mut addr = BASE;
    while addr < KERNEL_END {
        let in_hooks = (HOOKS_START..HOOKS_END).contains(&addr);
        if !in_hooks {
            assert_eq!(flags_at(&a, addr), flags_at(&b, addr), "{addr:#x}");
        }
        addr += PAGE_SIZE;
    }
}

/// An empty or absent span (the image-alias pass, a build without hooks)
/// leaves the three-range plan untouched.
#[test]
fn no_span_is_the_plain_plan() {
    let plain = wx::plan(BASE, TEXT_END, TEXT_END, RO_END, DATA_START, KERNEL_END);
    let none = wx::plan_with_ro(BASE, TEXT_END, TEXT_END, RO_END, DATA_START, KERNEL_END,
        RoAfterInit::default());
    assert_eq!(&none[..3], &plain[..]);
    assert!(none[3].is_empty() && none[4].is_empty());
}

/// A span outside the data range (the alias pass asks about other VAs) is
/// not carved: nothing of the data range changes.
#[test]
fn a_span_outside_the_data_range_is_ignored() {
    let plain = wx::plan(BASE, TEXT_END, TEXT_END, RO_END, DATA_START, KERNEL_END);
    let far = wx::plan_with_ro(BASE, TEXT_END, TEXT_END, RO_END, DATA_START, KERNEL_END,
        RoAfterInit { start: KERNEL_END + 0x10_0000, end: KERNEL_END + 0x12_0000, sealed: true });
    assert_eq!(&far[..3], &plain[..]);
    assert!(far[3].is_empty() && far[4].is_empty());
}

#[test]
fn the_carved_ranges_tile_the_data_range_exactly() {
    for sealed in [false, true] {
        let p = plan(sealed);
        let data = wx::plan(BASE, TEXT_END, TEXT_END, RO_END, DATA_START, KERNEL_END)[2];
        let (before, ro, after) = (p[2], p[3], p[4]);
        assert_eq!(before.start, data.start);
        assert_eq!(before.end, ro.start);
        assert_eq!(ro.end, after.start);
        assert_eq!(after.end, data.end);
        assert!(!wx::is_write_exec(ro.flags));
    }
}
