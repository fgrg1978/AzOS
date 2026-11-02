// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The roots the PEs translate through, for the page-table free check
//! (`Mmu::root_holders`). Invalidation needs none of it here (TLBI ...IS
//! broadcasts); the free does: a PE that still names a root walks frames the
//! allocator is about to reissue.
//!
//! Each PE stores its `TTBR0_EL1` base in [`AZOS_HART_TTBR0`] BEFORE it writes
//! the register, fenced, the order riscv64 keeps for `satp` and x86_64 for
//! CR3:
//!
//! ```text
//!   freer:    stores that moved every user off the table;  fence;  load AZOS_HART_TTBR0[h]
//!   switcher: store AZOS_HART_TTBR0[h];  fence;  msr TTBR0_EL1;  walk
//! ```
//!
//! so a PE is never on a root it has not published. The writers are
//! [`publish`] (the Rust installs: `Mmu::switch_pt`, the exit path's
//! `install_ttbr0_flush_local`) and, by symbol name, `context_switch.S` and
//! `trap_entry.S`'s exec and native-return installs.

use core::sync::atomic::{fence, AtomicUsize, Ordering};

/// Length of [`AZOS_HART_TTBR0`]: the CPU ceiling, Kconfig `NR_CPUS`. The
/// assembly takes it as `{tlb_max_harts}` and skips the publication for a PE
/// at or above it.
pub const TLB_MAX_HARTS: usize = azos_arch_api::tlb_gen::HARTS;
// `mask_of` answers a `usize` bit mask, one bit per PE.
const _: () = assert!(TLB_MAX_HARTS <= usize::BITS as usize);

/// `TTBR0_EL1`'s table base (BADDR, bits 47:1): the ASID in 63:48 and the CnP
/// bit are not part of a root's identity.
pub const BADDR_MASK: usize = 0x0000_ffff_ffff_fffe;

/// The `TTBR0_EL1` base each PE has installed, or is about to install. Written
/// by the owning PE only; read by any PE in [`holders`]. Zero means "never
/// published" and matches no root.
#[no_mangle]
pub static AZOS_HART_TTBR0: [AtomicUsize; TLB_MAX_HARTS] =
    [const { AtomicUsize::new(0) }; TLB_MAX_HARTS];

/// PEs among the first `harts` whose published base is `root_phys`, as a bit
/// mask. Pure: `published(h)` is what PE `h` published.
pub fn mask_of(published: impl Fn(usize) -> usize, harts: usize, root_phys: usize) -> usize {
    let want = root_phys & BADDR_MASK;
    if want == 0 {
        return 0;
    }
    let n = if harts < TLB_MAX_HARTS { harts } else { TLB_MAX_HARTS };
    let mut mask = 0usize;
    let mut h = 0;
    while h < n {
        if published(h) & BADDR_MASK == want {
            mask |= 1 << h;
        }
        h += 1;
    }
    mask
}

/// PEs, this one included, whose published base names the table at
/// `root_phys`. What a page-table free checks first (0 = nobody can walk it).
pub fn holders(root_phys: usize) -> usize {
    // The caller's stores that moved every user off the table, before the
    // loads of the published roots.
    fence(Ordering::SeqCst);
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if azos_limits::CANARY_RUNTIME && CANARY_HOLDERS_SELF.load(Ordering::Relaxed) {
            let me = crate::cpu::hart_id();
            return mask_of(|h| if h == me { AZOS_HART_TTBR0[h].load(Ordering::Relaxed) } else { 0 }, TLB_MAX_HARTS, root_phys);
        }
    }
    mask_of(|h| AZOS_HART_TTBR0[h].load(Ordering::Relaxed), TLB_MAX_HARTS, root_phys)
}

/// Runtime canary `ttbr0-holders-self` (`kernel/src/canary_rt.rs`): [`holders`]
/// sees only the executing PE's base (ktest `tlb_shootdown_cross_cpu`).
static CANARY_HOLDERS_SELF: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// See [`CANARY_HOLDERS_SELF`].
pub fn canary_holders_self() {
    CANARY_HOLDERS_SELF.store(true, Ordering::Relaxed);
}

/// Publish `word` (a `TTBR0_EL1` value; ASID and CnP are dropped) as `hart`'s
/// root. Called before the register write.
#[inline(always)]
pub fn publish(hart: usize, word: usize) {
    if hart < TLB_MAX_HARTS {
        AZOS_HART_TTBR0[hart].store(word & BADDR_MASK, Ordering::Relaxed);
        // The publication before the `msr TTBR0_EL1` and the walks that follow.
        fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mask_names_every_pe_on_the_root_and_no_other() {
        let pub_ = [0x8000_0000usize | (7 << 48), 0x9000_0000, 0x8000_0001, 0];
        let m = mask_of(|h| pub_[h], 4, 0x8000_0000);
        assert_eq!(m, 0b0101, "ASID and CnP bits do not tell roots apart");
        assert_eq!(mask_of(|h| pub_[h], 4, 0xa000_0000), 0);
        assert_eq!(mask_of(|h| pub_[h], 4, 0), 0, "root 0 matches the never-published slots");
    }

    #[test]
    fn the_scan_stops_at_the_bound() {
        assert_eq!(mask_of(|_| 0x8000_0000, 2, 0x8000_0000), 0b11);
    }
}
