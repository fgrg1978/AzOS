// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Svnapot: 64 KiB naturally aligned leaves (Kconfig `RV_SVNAPOT`).
//!
//! A level-0 leaf with the N bit (PTE bit 63) and PPN[3:0] = `0b1000` maps
//! the 64 KiB around it: the other fifteen slots of its aligned group hold
//! the SAME word, and the hart may cache the group as one TLB entry. Unlike
//! the aarch64 contiguous hint, no member names its own frame: the PPN is the
//! run's base with the size marker in its low four bits, so a reader that
//! wants the frame of one page adds the offset inside the run itself
//! (`Mmu::pte_leaf0_span`, `Pte::phys_addr` returning the base).
//!
//! The rules the encoders keep, from the privileged spec (Svnapot):
//! * the run is 16 slots of one level-0 table, aligned to 16 slots, virtual
//!   and physical;
//! * all sixteen words equal: same PPN field, same permissions, A and D;
//! * a hart that finds them unequal may use any of them. A break (this file's
//!   [`member`]) therefore changes no translation: the sixteen plain words
//!   name the same frames the run did, and the order they are stored in does
//!   not matter. RISC-V defines no TLB conflict abort for it, so no
//!   break-before-make (`Mmu::block_change_needs_bbm` is false here).
//!
//! Svnapot has no enable bit (Svpbmt has `menvcfg.PBMTE`): the device tree's
//! `riscv,isa` token is the whole probe, as for `svpbmt_select`.

use crate::mmu::{Pte, PteFlags, PAGE_SIZE, PTE_N};
use core::sync::atomic::{AtomicBool, Ordering};

/// Pages in one NAPOT run.
pub const NAPOT_PAGES: usize = 16;

/// Bytes in one NAPOT run: 64 KiB.
pub const NAPOT_SIZE: usize = NAPOT_PAGES * PAGE_SIZE;

/// PPN[3:0] = `0b1000` in place (PPN starts at word bit 10).
const SIZE_MARKER: u64 = 0b1000 << 10;

/// The four PPN bits the size marker occupies, in place.
const SIZE_FIELD: u64 = 0xF << 10;

static ON: AtomicBool = AtomicBool::new(false);

/// Settle Svnapot: on only when the Kconfig policy allows it and cpu@0's
/// `riscv,isa` lists it. Returns the decision.
pub fn select(policy_allows: bool, dt_present: bool) -> bool {
    let on = policy_allows && dt_present;
    ON.store(on, Ordering::Release);
    on
}

/// Are NAPOT leaves in use?
#[inline]
pub fn on() -> bool {
    ON.load(Ordering::Acquire)
}

/// The word every slot of the run at `run_pa` holds. `run_pa` must be aligned
/// to [`NAPOT_SIZE`] (the caller checks; the low bits would be lost into the
/// size marker otherwise).
#[inline]
pub fn make_64k(run_pa: usize, flags: PteFlags) -> u64 {
    debug_assert!(run_pa & (NAPOT_SIZE - 1) == 0);
    Pte::new(run_pa, flags).0 | SIZE_MARKER | PTE_N
}

/// Is `word` a NAPOT leaf: N set and the size marker `0b1000` in PPN[3:0]?
/// N with any other low PPN bits is a reserved encoding (a page fault); it is
/// not a run.
#[inline]
pub fn is_napot(word: u64) -> bool {
    word & PTE_N != 0 && word & SIZE_FIELD == SIZE_MARKER
}

/// The plain 4 KiB word for member `index` (0..16) of the run `word` heads:
/// N and the marker gone, the PPN the member's own frame. Every other bit
/// (permissions, A, D, software bits, Svpbmt) is carried over.
#[inline]
pub fn member(word: u64, index: usize) -> u64 {
    debug_assert!(index < NAPOT_PAGES);
    if !is_napot(word) {
        return word;
    }
    let base_ppn = word & !SIZE_FIELD & !PTE_N;
    base_ppn + ((index as u64) << 10)
}
