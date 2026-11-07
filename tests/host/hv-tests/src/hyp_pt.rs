// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the monitor checks before it writes a word into the kernel half's
//! tables (crates/core/hyp-mon/src/arch/ptcheck.rs), and the pool calls'
//! address checks (hyp-api).
//!
//! WHY. The checks are the whole of I3: a word they let through is a word the
//! kernel, once compromised, can use to map memory it must not reach. Each
//! rule has a case here that fails when the rule goes, and `hyp-pt-check-skip`
//! style regressions show as the accepting cases below turning into refusals
//! or the refusing ones into acceptances.

#[allow(dead_code)]
#[path = "../../../../crates/core/hyp-mon/src/arch/ptcheck.rs"]
mod ptcheck;

use azos_hyp_api::{pt_entry_error, pt_pool_error, Guarded};
use ptcheck::pte_fmt::*;
use ptcheck::*;
use std::collections::HashMap;

const SHIFT: u32 = 12;
const POOL: u64 = 0x8100_0000;
const PAGES: u64 = 16;
const END: u64 = POOL + PAGES * 4096;
const TEXT: [u64; 2] = [0x8008_0000, 0x8040_0000];
const RAM: [[u64; 2]; 1] = [[0x8000_0000, 0x9000_0000]];

fn leaf(pa: u64, flags: u64) -> u64 {
    (pa & OA_MASK) | VALID | TYPE_TABLE_OR_PAGE | AF | flags
}

fn block(pa: u64, flags: u64) -> u64 {
    (pa & OA_MASK) | VALID | AF | flags
}

fn in_pool(pa: u64) -> bool {
    pa >= POOL && pa < END && pa % 4096 == 0
}

fn tag_none(_: u64) -> u8 {
    0
}

fn write(expected: u64, new: u64, level: usize, entry_tag: u8, tag: impl Fn(u64) -> u8) -> Result<Claims, &'static str> {
    write_error(expected, new, level, entry_tag, SHIFT, &[TEXT], in_pool, tag)
}

#[test]
fn a_read_only_executable_leaf_and_a_writable_data_leaf_are_accepted() {
    let rx = leaf(0x9000_0000, AP_RO | UXN);
    let rw = leaf(0x9000_1000, PXN | UXN);
    assert!(write(0, rx, 0, 0, tag_none).is_ok());
    assert!(write(0, rw, 0, 0, tag_none).is_ok());
}

#[test]
fn a_leaf_writable_and_executable_is_refused() {
    let wx = leaf(0x9000_0000, UXN);
    assert_eq!(write(0, wx, 0, 0, tag_none), Err("leaf writable and executable"));
}

#[test]
fn a_leaf_without_af_is_refused() {
    let w = leaf(0x9000_0000, PXN | UXN) & !AF;
    assert_eq!(write(0, w, 0, 0, tag_none), Err("leaf without AF"));
}

#[test]
fn a_leaf_with_dbm_is_refused() {
    assert_eq!(write(0, leaf(0x9000_0000, PXN | UXN | DBM), 0, 0, tag_none), Err("leaf with DBM"));
}

#[test]
fn an_invalid_word_is_always_accepted() {
    assert!(write(leaf(0x9000_0000, PXN | UXN), 0, 0, 0, tag_none).is_ok());
    // A break-before-make marker: not valid, so the walker ignores it.
    assert!(write(leaf(0x9000_0000, PXN | UXN), 0xdead_0000_0000_0000, 0, 0, tag_none).is_ok());
}

#[test]
fn a_table_must_lie_in_the_pool_and_serve_the_level_below() {
    assert_eq!(write(0, make_table(0x9000_0000), 1, 0, tag_none), Err("table outside the pool"));
    let c = write(0, make_table(POOL as usize + 0x1000), 1, 0, tag_none).unwrap();
    assert_eq!(c.target, Some((POOL + 0x1000, 0)));
    // The target already serves level 1: it cannot be linked as a level-0 table.
    let tag = |pa: u64| if pa == POOL + 0x1000 { tag_of(1) } else { 0 };
    assert_eq!(write(0, make_table(POOL as usize + 0x1000), 1, 0, tag), Err("page serves another level"));
}

#[test]
fn a_table_descriptor_that_carries_attributes_is_refused() {
    let t = make_table(POOL as usize + 0x1000) | PXN;
    assert_eq!(write(0, t, 1, 0, tag_none), Err("table descriptor with attributes"));
}

#[test]
fn a_page_serves_one_level_for_good() {
    assert!(write(0, 0, 0, tag_of(0), tag_none).is_ok());
    assert_eq!(write(0, 0, 1, tag_of(0), tag_none), Err("page serves another level"));
    assert_eq!(claim(0, 2), Ok(tag_of(2)));
    assert_eq!(tag_level(tag_of(2) | TAG_IMAGE), Some(2));
    assert_eq!(claim(tag_of(2) | TAG_IMAGE, 2), Ok(tag_of(2) | TAG_IMAGE));
}

#[test]
fn a_leaf_is_aligned_to_its_size_and_the_level_decides_what_a_word_is() {
    assert_eq!(block_size(0, 12), 4096);
    assert_eq!(block_size(1, 12), 2 << 20);
    assert_eq!(block_size(2, 12), 1 << 30);
    assert_eq!(block_size(0, 14), 16 << 10);
    assert_eq!(block_size(1, 14), 32 << 20);
    assert_eq!(block_size(0, 16), 64 << 10);
    assert_eq!(block_size(1, 16), 512 << 20);
    assert_eq!(classify(block(0x9020_0000, PXN | UXN), 1, 12), Ok(Word::Leaf { pa: 0x9020_0000, size: 2 << 20 }));
    assert_eq!(classify(block(0x9010_0000, PXN | UXN), 1, 12), Err("leaf not aligned to its size"));
    // Bit 1 clear at the last level is reserved, not a block.
    assert_eq!(classify(VALID | AF | 0x9000_0000, 0, 12), Err("reserved descriptor"));
    assert_eq!(classify(0, 2, 12), Ok(Word::Invalid));
}

#[test]
fn a_slot_that_maps_the_image_is_never_rewritten() {
    let text_leaf = leaf(TEXT[0] + 0x1000, AP_RO | UXN);
    assert_eq!(write(text_leaf, 0, 0, 0, tag_none), Err("slot maps the image"));
    assert_eq!(write(text_leaf, leaf(0x9000_0000, PXN | UXN), 0, 0, tag_none), Err("slot maps the image"));
    // A block that merely overlaps the image counts.
    let blk = block(TEXT[0] & !((2 << 20) - 1), AP_RO | UXN);
    assert_eq!(write(blk, 0, 1, 0, tag_none), Err("slot maps the image"));
}

#[test]
fn a_slot_that_leads_to_a_table_that_maps_the_image_is_never_rewritten() {
    let link = make_table(POOL as usize + 0x2000);
    let tag = |pa: u64| if pa == POOL + 0x2000 { tag_of(0) | TAG_IMAGE } else { 0 };
    assert_eq!(write(link, 0, 1, 0, tag), Err("slot leads to the image"));
    // The same table without the mark is an ordinary one.
    assert!(write(link, 0, 1, 0, |pa| if pa == POOL + 0x2000 { tag_of(0) } else { 0 }).is_ok());
}

#[test]
fn a_new_read_only_alias_of_the_image_is_not_a_slot_that_maps_it() {
    assert!(write(0, leaf(TEXT[0], AP_RO | UXN), 0, 0, tag_none).is_ok());
}

#[test]
fn the_pool_call_checks_the_range_the_granule_and_the_root() {
    let g = Guarded::new();
    let ok = |pa, pages, shift, root| pt_pool_error(pa, pages, shift, root, &RAM, &[TEXT], 0x8200_0000, 0x8300_0000, &g);
    assert_eq!(ok(POOL, PAGES, 12, POOL), None);
    assert_eq!(ok(POOL, 0, 12, POOL), Some("page count"));
    assert_eq!(ok(POOL, 2000, 12, POOL), Some("page count"));
    assert_eq!(ok(POOL, PAGES, 13, POOL), Some("granule"));
    assert_eq!(ok(POOL + 8, PAGES, 12, POOL + 8), Some("not page-aligned"));
    assert_eq!(ok(0x9000_0000, PAGES, 12, 0x9000_0000), Some("outside RAM"));
    assert_eq!(ok(TEXT[0], PAGES, 12, TEXT[0]), Some("overlaps the image"));
    assert_eq!(ok(0x81ff_f000, PAGES, 12, 0x81ff_f000), Some("overlaps the monitor"));
    assert_eq!(ok(POOL, PAGES, 12, END), Some("root outside the pool"));
    let mut guarded = Guarded::new();
    assert!(guarded.add(POOL + 0x1000, POOL + 0x2000));
    assert_eq!(pt_pool_error(POOL, PAGES, 12, POOL, &RAM, &[TEXT], 0, 0, &guarded), Some("overlaps a guarded page"));
}

#[test]
fn the_entry_call_checks_the_slot_and_the_level() {
    assert_eq!(pt_entry_error(POOL + 8, 0, POOL, PAGES, 12, 3), None);
    assert_eq!(pt_entry_error(POOL + 4, 0, POOL, PAGES, 12, 3), Some("entry not 8-aligned"));
    assert_eq!(pt_entry_error(END, 0, POOL, PAGES, 12, 3), Some("entry outside the pool"));
    assert_eq!(pt_entry_error(POOL - 8, 0, POOL, PAGES, 12, 3), Some("entry outside the pool"));
    assert_eq!(pt_entry_error(POOL, 3, POOL, PAGES, 12, 3), Some("level"));
}

#[test]
fn a_leaf_with_the_contiguous_hint_is_refused() {
    let l0 = leaf(0x9000_0000, PXN | UXN | CONT);
    assert_eq!(write(0, l0, 0, 0, tag_none), Err("leaf with the contiguous hint"));
    assert_eq!(write(0, block(0x9020_0000, PXN | UXN | CONT), 1, 0, tag_none), Err("leaf with the contiguous hint"));
}

#[test]
fn rewriting_a_slot_with_the_word_it_holds_is_not_a_change() {
    let text_leaf = leaf(TEXT[0] + 0x1000, AP_RO | UXN);
    assert!(write(text_leaf, text_leaf, 0, 0, tag_none).is_ok());
    let link = make_table(POOL as usize + 0x2000);
    let tag = |pa: u64| if pa == POOL + 0x2000 { tag_of(0) | TAG_IMAGE } else { 0 };
    assert!(write(link, link, 1, 0, tag).is_ok());
}

/// A three-level tree in a map: the root at POOL, one table per level, and the
/// pages of an image at `VA` leading to frames from `PA`.
fn tree(frame: impl Fn(u64) -> u64, flags: u64) -> HashMap<u64, u64> {
    const VA: u64 = 0xffff_0000_0000_0000;
    let mut m = HashMap::new();
    let (root, mid, last) = (POOL, POOL + 0x1000, POOL + 0x2000);
    let idx = |l: u32| (VA >> (12 + 9 * l)) & 511;
    m.insert(root + idx(2) * 8, make_table(mid as usize));
    m.insert(mid + idx(1) * 8, make_table(last as usize));
    for i in 0..4u64 {
        m.insert(last + (idx(0) + i) * 8, leaf(frame(i), flags));
    }
    m
}

const VA: u64 = 0xffff_0000_0000_0000;
const FRAMES: u64 = 0x8008_0000;

fn image(m: &HashMap<u64, u64>, text: bool) -> Option<&'static str> {
    image_error(|pa| *m.get(&pa).unwrap_or(&0), POOL, VA, FRAMES, 4 * 4096, text, 12)
}

#[test]
fn the_image_pages_must_resolve_to_the_image_frames_read_only() {
    let ok = tree(|i| FRAMES + i * 4096, AP_RO | UXN);
    assert_eq!(image(&ok, true), None);
    assert_eq!(image(&tree(|i| FRAMES + i * 4096, AP_RO | PXN | UXN), false), None);
    assert_eq!(image(&tree(|i| if i == 2 { 0x9000_0000 } else { FRAMES + i * 4096 }, AP_RO | UXN), true), Some("image page maps another frame"));
    assert_eq!(image(&tree(|i| FRAMES + i * 4096, PXN | UXN), false), Some("image page writable"));
    assert_eq!(image(&ok, false), Some("data page executable"));
    assert_eq!(image(&tree(|i| FRAMES + i * 4096, AP_RO | PXN | UXN), true), Some("text page not executable"));
    let mut hole = ok.clone();
    hole.remove(&(POOL + 0x2000 + ((VA >> 12) & 511) * 8 + 16));
    assert_eq!(image(&hole, true), Some("image page not mapped"));
}

#[test]
fn a_block_resolves_to_the_frame_at_its_offset() {
    let mut m = HashMap::new();
    let (root, mid) = (POOL, POOL + 0x1000);
    m.insert(root + ((VA >> 30) & 511) * 8, make_table(mid as usize));
    m.insert(mid + ((VA >> 21) & 511) * 8, block(0x8000_0000, AP_RO | UXN));
    assert_eq!(resolve(|pa| *m.get(&pa).unwrap_or(&0), root, VA + 0x1234, 12).map(|r| r.0), Some(0x8000_1234));
}

#[test]
fn a_pe_runs_the_kernel_half_only_on_the_locked_root_and_walk() {
    assert_eq!(ttbr1_error(POOL, POOL), None);
    // CnP is not part of the root.
    assert_eq!(ttbr1_error(POOL | 1, POOL), None);
    assert_eq!(ttbr1_error(POOL + 0x1000, POOL), Some("TTBR1 is not the locked root"));
    assert_eq!(ttbr1_error(POOL | 1 << 48, POOL), Some("TTBR1 carries an ASID"));
    let tcr = 25 << 16 | 2 << 30 | 3 << 28;
    assert_eq!(tcr_error(tcr, tcr), None);
    // HA is a per-core feature, not a walk field.
    assert_eq!(tcr_error(tcr | 1 << 39, tcr), None);
    assert_eq!(tcr_error(tcr ^ 1 << 16, tcr), Some("TCR walks the kernel half differently"));
    assert_eq!(tcr_error(tcr ^ 1 << 30, tcr), Some("TCR walks the kernel half differently"));
}

#[test]
fn the_lock_refuses_a_block_over_the_image_and_a_pool_page_nothing_checked() {
    let blk = block(TEXT[0] & !((2 << 20) - 1), AP_RO | UXN);
    assert_eq!(lock_word_error(classify(blk, 1, 12).unwrap(), blk, 1, &[TEXT]), Some("a block leaf over the image"));
    // The same words as 4 KiB leaves, and a block elsewhere, are the boot's own.
    let page = leaf(TEXT[0], AP_RO | UXN);
    assert_eq!(lock_word_error(classify(page, 0, 12).unwrap(), page, 0, &[TEXT]), None);
    let far = block(0x9020_0000, PXN | UXN);
    assert_eq!(lock_word_error(classify(far, 1, 12).unwrap(), far, 1, &[TEXT]), None);
    assert_eq!(unreached_error(0, [0u64, 0, 7].into_iter()), Some("a pool page nothing links has words in it"));
    assert_eq!(unreached_error(0, [0u64; 512].into_iter()), None);
    assert_eq!(unreached_error(tag_of(0), [1u64].into_iter()), None);
}
