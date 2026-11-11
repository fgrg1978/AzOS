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
fn a_pe_runs_the_kernel_half_only_on_the_locked_root() {
    assert_eq!(ttbr1_error(POOL, POOL), None);
    // CnP is not part of the root.
    assert_eq!(ttbr1_error(POOL | 1, POOL), None);
    assert_eq!(ttbr1_error(POOL + 0x1000, POOL), Some("TTBR1 is not the locked root"));
    assert_eq!(ttbr1_error(POOL | 1 << 48, POOL), Some("TTBR1 carries an ASID"));
}

#[test]
fn each_field_that_decides_how_the_half_is_walked_is_compared_and_no_other() {
    let tcr = 25 << 16 | 2 << 30 | 3 << 28 | 1 << 24 | 1 << 26;
    assert_eq!(tcr_error(tcr, tcr), None);
    // One assert per field: T1SZ, IRGN1, ORGN1, SH1, TG1, DS.
    for (name, bit) in [("T1SZ", 16), ("IRGN1", 24), ("ORGN1", 26), ("SH1", 28), ("TG1", 30), ("DS", 59)] {
        assert_eq!(tcr_error(tcr ^ 1 << bit, tcr), Some("TCR walks the kernel half differently"), "{name}");
    }
    // HA, TBI1, IPS and A1 are not the monitor's to compare.
    for bit in [39, 38, 32, 22] {
        assert_eq!(tcr_error(tcr ^ 1 << bit, tcr), None, "bit {bit}");
    }
}

#[test]
fn a_tcr_with_the_half_off_is_the_boots_identity_map_form_and_is_written() {
    let tcr = 25 << 16 | 2 << 30 | 3 << 28;
    // T0 fields only, EPD1 set, the T1 fields zero: what every secondary's first write is.
    let early = 25 | 1 << 23 | 2 << 14 | 3 << 12;
    assert_eq!(tcr_write_error(early, tcr), None);
    assert_eq!(tcr_error(early, tcr), Some("TCR walks the kernel half differently"), "the live register is not excused");
    // With the half on, the locked fields are needed.
    assert_eq!(tcr_write_error(early & !(1 << 23), tcr), Some("TCR walks the kernel half differently"));
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

const ROOT_REG: u64 = POOL | 1;
const LOCKED_TCR: u64 = 25 << 16 | 2 << 30 | 3 << 28 | 1 << 39;
const LOCKED_SCTLR: u64 = 1 | 1 << 2 | 1 << 12;
const LOCKED: Locked = Locked { ttbr1: ROOT_REG, tcr: LOCKED_TCR, sctlr: LOCKED_SCTLR };

#[test]
fn a_core_that_differs_from_the_locked_registers_is_found() {
    assert_eq!(pe_regs_error(LOCKED, LOCKED), None);
    assert_eq!(pe_regs_error(Locked { ttbr1: POOL + 0x1000, ..LOCKED }, LOCKED), Some("TTBR1 is not the locked root"));
    assert_eq!(pe_regs_error(Locked { tcr: LOCKED_TCR ^ 1 << 30, ..LOCKED }, LOCKED), Some("TCR walks the kernel half differently"));
    assert_eq!(pe_regs_error(Locked { sctlr: LOCKED_SCTLR & !1, ..LOCKED }, LOCKED), Some("SCTLR turns the MMU off"));
    assert_eq!(pe_regs_error(Locked { sctlr: LOCKED_SCTLR | 1 << 25, ..LOCKED }, LOCKED), Some("SCTLR changes the byte order or WXN"));
}

#[test]
fn the_lock_wants_a_pinned_core_on_the_root_it_names() {
    assert_eq!(lock_regs_error(true, ROOT_REG, POOL), None);
    assert_eq!(lock_regs_error(false, ROOT_REG, POOL), Some("the calling core has not pinned"));
    assert_eq!(lock_regs_error(true, ROOT_REG + 0x1000, POOL), Some("TTBR1 is not the locked root"));
    assert_eq!(lock_regs_error(true, ROOT_REG | 1 << 48, POOL), Some("TTBR1 carries an ASID"));
}

#[test]
fn a_core_enters_on_the_locked_registers_once_the_pool_is_locked_and_not_before() {
    assert_eq!(entry_plan(None), None);
    assert_eq!(entry_plan(Some(LOCKED)), Some(EntryPlan { ttbr1: ROOT_REG, tcr: LOCKED_TCR }));
}

#[test]
fn a_trapped_write_to_the_walk_registers_is_carried_out_only_when_it_is_the_locked_one() {
    let locked = Some(LOCKED);
    // Before the lock none is.
    for r in [Vm::Sctlr, Vm::Tcr, Vm::Ttbr1] {
        assert!(!write_allowed(r, LOCKED_SCTLR, None));
    }
    assert!(write_allowed(Vm::Ttbr1, POOL, locked));
    assert!(write_allowed(Vm::Ttbr1, ROOT_REG, locked));
    assert!(!write_allowed(Vm::Ttbr1, 0x9000_0000, locked), "a forged root");
    assert!(!write_allowed(Vm::Ttbr1, POOL | 1 << 48, locked), "an ASID");
    assert!(write_allowed(Vm::Tcr, LOCKED_TCR | 1 << 37, locked));
    assert!(!write_allowed(Vm::Tcr, LOCKED_TCR ^ 1 << 16, locked), "another T1SZ");
    // The MMU is turned on with the locked byte order, by a core pinned or not; never off.
    assert!(write_allowed(Vm::Sctlr, LOCKED_SCTLR | 1 << 15, locked));
    assert!(!write_allowed(Vm::Sctlr, LOCKED_SCTLR & !1, locked), "MMU off");
    assert!(!write_allowed(Vm::Sctlr, LOCKED_SCTLR | 1 << 25, locked), "EE");
    assert!(!write_allowed(Vm::Sctlr, LOCKED_SCTLR | 1 << 24, locked), "E0E");
    assert!(!write_allowed(Vm::Sctlr, LOCKED_SCTLR | 1 << 19, locked), "WXN");
}

/// MPIDR of a Cortex-A76 in a DynamIQ cluster: the core number is in Aff1, Aff0 is 0, MT is set.
fn a76(core: u64) -> u64 {
    1 << 31 | 1 << 24 | core << 8
}

#[test]
fn cores_whose_aff0_is_zero_are_told_apart() {
    let t: PinTable<8> = PinTable::new();
    assert!(t.insert(affinity(a76(0))));
    assert!(!t.contains(affinity(a76(1))), "core 1 is not pinned because core 0 is");
    assert!(t.insert(affinity(a76(1))) && t.insert(affinity(a76(2))) && t.insert(affinity(a76(3))));
    assert_eq!(t.count(), 4);
    assert!(t.contains(affinity(a76(2))));
    // Aff2 and Aff3 count as well.
    assert!(!t.contains(affinity(a76(0) | 1 << 16)) && !t.contains(affinity(a76(0) | 1 << 32)));
    // Core 0 (affinity 0) is a core: its slot is not "empty".
    assert!(t.contains(affinity(0)));
}

#[test]
fn a_core_that_goes_off_pins_again_when_it_is_back() {
    let t: PinTable<8> = PinTable::new();
    for c in 0..4 { assert!(t.insert(affinity(a76(c)))); }
    t.remove(affinity(a76(2)));
    assert!(!t.contains(affinity(a76(2))));
    assert!(t.contains(affinity(a76(1))) && t.contains(affinity(a76(3))));
    assert_eq!(t.count(), 3);
    assert!(t.insert(affinity(a76(2))) && t.contains(affinity(a76(2))));
    // The table holds as many cores as the monitor has stacks, and says so when it is full.
    let full: PinTable<2> = PinTable::new();
    assert!(full.insert(1) && full.insert(2) && !full.insert(3));
}

#[test]
fn the_extensions_that_reread_a_descriptor_are_trapped_or_the_lock_is_refused() {
    let hcx = 1 << 40;
    assert_eq!(extensions(0, 0), Extensions::None);
    assert_eq!(extensions(hcx, 0), Extensions::None, "HCX alone changes nothing");
    for mmfr3 in [1, 1 << 8, 1 << 16] {
        assert_eq!(extensions(hcx, mmfr3), Extensions::Trap);
        assert_eq!(extensions(0, mmfr3), Extensions::Unenforceable);
    }
}

// ── the EL2 stack and resume-context slots (power cycles, DynamIQ, resume of the boot PE) ──

const PRIMARY: u64 = 0x8000_0000;

#[test]
fn a_core_that_cycles_power_keeps_its_slot() {
    let t: PeSlots<8> = PeSlots::new();
    assert_eq!(t.claim(PRIMARY), Some(0));
    let cpu1 = 0x8000_0001;
    assert_eq!(t.claim(cpu1), Some(1));
    // CPU_OFF/CPU_ON and power-down resumes, far more than the table holds.
    for _ in 0..1000 {
        assert_eq!(t.claim(cpu1), Some(1), "the same core finds its slot again");
        assert_eq!(t.claim(PRIMARY), Some(0));
    }
    assert_eq!(t.claim(0x8000_0002), Some(2), "the next core takes the next slot, not a power-cycle's");
}

#[test]
fn more_cores_than_slots_are_refused_not_aliased() {
    let t: PeSlots<4> = PeSlots::new();
    for i in 0..4 {
        assert_eq!(t.claim(0x8000_0000 + i), Some(i as usize));
    }
    assert_eq!(t.claim(0x8000_0004), None);
    assert_eq!(t.claim(0x8000_0003), Some(3));
}

#[test]
fn a_dynamiq_core_is_told_apart_by_its_whole_affinity() {
    // Every Aff0 is 0 here: the core number is in Aff1, which an Aff0 key cannot see.
    let t: PeSlots<8> = PeSlots::new();
    let (a, b, c) = (0x8000_0000, 0x8000_0100, 0x8000_0200);
    assert_ne!(PeSlots::<8>::key(a), PeSlots::<8>::key(b));
    assert_eq!(t.record(a, 0xA).unwrap(), 0);
    assert_eq!(t.record(b, 0xB).unwrap(), 1);
    assert_eq!(t.record(c, 0xC).unwrap(), 2);
    assert_eq!((t.ctx_of(0), t.ctx_of(1), t.ctx_of(2)), (0xA, 0xB, 0xC), "no core gets another's context");
    // Aff3 counts too, and the bits above the affinity (MT, U, the RES1 bit) do not.
    assert_ne!(PeSlots::<8>::key(0x1_0000_0000 | a), PeSlots::<8>::key(a));
    assert_eq!(PeSlots::<8>::key(0x8000_0000 | 1 << 24 | 1 << 30), PeSlots::<8>::key(0x8000_0000));
}

#[test]
fn the_boot_core_resumes_with_the_context_it_suspended_with() {
    // The boot core is never CPU_ON'd: its slot and context come from its own suspend.
    let t: PeSlots<8> = PeSlots::new();
    assert_eq!(t.claim(PRIMARY), Some(0));
    let slot = t.record(PRIMARY, 0x77).expect("a slot for the suspending core");
    assert_eq!(slot, 0);
    assert_eq!(t.ctx_of(slot), 0x77);
    // A second suspend replaces the context; a slot past the table has none.
    t.record(PRIMARY, 0x78);
    assert_eq!(t.ctx_of(0), 0x78);
    assert_eq!(t.ctx_of(99), 0);
}
