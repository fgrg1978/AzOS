// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Stage2::split_to_page` (aarch64): the break-before-make split the monitor's
//! `guard_pages` takes to unmap one page out of a block.

use crate::glue::arm::stage2::*;
use std::cell::RefCell;
use std::rc::Rc;

const BASE: u64 = 0x1_0000_0000;

struct Arena {
    words: Vec<u64>,
    next: u64,
    cap: u64,
    /// The stores to the two root tables, in order: `0` is an invalidate.
    root_stores: Rc<RefCell<Vec<&'static str>>>,
}

impl Arena {
    fn new(cap: u64) -> Arena {
        Arena { words: vec![0; (cap * 512) as usize], next: 0, cap, root_stores: Rc::default() }
    }
}

impl TableMem for Arena {
    fn alloc_tables(&mut self, tables: u64) -> Option<u64> {
        let at = self.next.div_ceil(tables) * tables;
        if at + tables > self.cap {
            return None;
        }
        self.next = at + tables;
        Some(BASE + at * 4096)
    }
    fn read(&self, pa: u64) -> u64 {
        self.words[((pa - BASE) / 8) as usize]
    }
    fn write(&mut self, pa: u64, d: u64) {
        if pa < BASE + 2 * 4096 {
            self.root_stores.borrow_mut().push(if d == 0 { "invalidate" } else { "write" });
        }
        self.words[((pa - BASE) / 8) as usize] = d;
    }
}

fn user_ram() -> S2Attrs {
    S2Attrs { read: true, write: true, exec: true, mem: MemType::NormalWb, only: ExecOnly::El0 }
}

fn cfg() -> VtcrConfig {
    VtcrConfig::new(40, 2).unwrap()
}

#[test]
fn a_block_splits_to_pages_and_keeps_every_other_page_as_it_was() {
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg(), &mut m).unwrap();
    s2.map_leaf(0x4000_0000, 0x4000_0000, 1, user_ram()).unwrap();
    let mut breaks = Vec::new();
    s2.split_to_page(0x4012_3000, &mut |ipa| breaks.push(ipa)).unwrap();
    assert_eq!(breaks, vec![0x4000_0000, 0x4000_0000], "the 1 GiB block, then the 2 MiB one inside it");
    for ipa in [0x4000_0000u64, 0x4000_1000, 0x4012_3456, 0x401f_f000, 0x4020_0000, 0x7fff_f000] {
        assert_eq!(s2.translate(ipa), Some((ipa, user_ram())), "{ipa:#x}");
    }
    assert_eq!(s2.unmap_page(0x4012_3000), Ok(0x4012_3000));
    assert_eq!(s2.translate(0x4012_3000), None);
    assert_eq!(s2.translate(0x4012_2fff).map(|t| t.0), Some(0x4012_2fff));
    assert_eq!(s2.translate(0x4012_4000).map(|t| t.0), Some(0x4012_4000));
}

#[test]
fn a_page_already_is_a_page_and_an_unmapped_address_is_refused() {
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg(), &mut m).unwrap();
    s2.map_page(0x4000_0000, 0x9000_0000, S2Attrs::RAM).unwrap();
    s2.split_to_page(0x4000_0000, &mut |_| panic!("nothing to break")).unwrap();
    assert_eq!(s2.translate(0x4000_0000), Some((0x9000_0000, S2Attrs::RAM)));
    assert_eq!(s2.split_to_page(0x2_0000_0000, &mut |_| ()), Err(S2Error::NotMapped));
    assert_eq!(s2.split_to_page(1 << 40, &mut |_| ()), Err(S2Error::IpaOutOfRange));
}

#[test]
fn the_table_replaces_the_block_only_after_the_break() {
    let mut m = Arena::new(32);
    let log = m.root_stores.clone();
    let mut s2 = Stage2::new(cfg(), &mut m).unwrap();
    s2.map_leaf(0x4000_0000, 0x4000_0000, 1, S2Attrs::RAM).unwrap();
    log.borrow_mut().clear();
    let seen = log.clone();
    s2.split_to_page(0x4000_0000, &mut |_| seen.borrow_mut().push("flush")).unwrap();
    // The root entry: invalid, the flush, then the table. The 2 MiB split
    // below it flushes once more, in a table outside the root.
    assert_eq!(*log.borrow(), vec!["invalidate", "flush", "write", "flush"]);
}

#[test]
fn a_split_without_a_table_to_spare_leaves_the_block_alone() {
    let mut m = Arena::new(2); // the root, nothing else
    let mut s2 = Stage2::new(cfg(), &mut m).unwrap();
    s2.map_leaf(0x4000_0000, 0x4000_0000, 1, S2Attrs::RAM).unwrap();
    assert_eq!(s2.split_to_page(0x4000_0000, &mut |_| panic!("no break without a table")), Err(S2Error::NoMemory));
    assert_eq!(s2.translate(0x4000_0000), Some((0x4000_0000, S2Attrs::RAM)));
}

/// **A run capped at 2 MiB blocks breaks one block, not a gigabyte, when a page
/// of it is taken out.** The monitor builds the boot map this way around itself.
///
/// **Canary.** `map_run_max` ignores its cap: the first assertion sees a 1 GiB
/// block and the break count is 2.
#[test]
fn a_run_capped_at_two_mib_breaks_one_two_mib_block_to_take_a_page_out() {
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg(), &mut m).unwrap();
    s2.map_run_max(0x4000_0000, 0x4000_0000, 0x4000_0000, user_ram(), 2 << 20).unwrap();
    // Beyond the cap the run still uses a gigabyte block.
    s2.map_run_max(0x8000_0000, 0x8000_0000, 0x4000_0000, user_ram(), u64::MAX).unwrap();
    let mut breaks = Vec::new();
    s2.split_to_page(0x4012_3000, &mut |ipa| breaks.push(ipa)).unwrap();
    assert_eq!(breaks, vec![0x4000_0000], "one 2 MiB block");
    let mut again = Vec::new();
    s2.split_to_page(0x8012_3000, &mut |ipa| again.push(ipa)).unwrap();
    assert_eq!(again.len(), 2, "the uncapped run breaks its gigabyte, then a 2 MiB block");
    // Every page of both is still where it was.
    for ipa in [0x4000_0000u64, 0x401f_f000, 0x7fff_f000, 0x8000_0000, 0xbfff_f000] {
        assert_eq!(s2.translate(ipa), Some((ipa, user_ram())), "{ipa:#x}");
    }
}
