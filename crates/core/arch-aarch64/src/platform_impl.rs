// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`ArchPlatform`] for aarch64: thin `#[inline]` wrappers over this crate's
//! own modules, so a shared crate calls `ARCH.<method>` instead of naming
//! `cache`/`sysregs`/`cbo` (which a new ISA would not have).

use crate::api_impl::Aarch64;
use azos_arch_api::{ArchPlatform, Mmu};

impl ArchPlatform for Aarch64 {
    /// Arm's instruction fetch does not snoop the data cache: written lines
    /// must be cleaned to the PoU (`DC CVAU`) before the I-cache invalidate.
    #[inline]
    fn icache_needs_dcache_clean(&self) -> bool {
        true
    }

    #[inline]
    unsafe fn dcache_clean(&self, va: usize, len: usize) {
        // SAFETY: forwarded caller contract.
        unsafe { crate::cache::dcache_clean(va, len) }
    }

    /// `IC IALLUIS` (broadcast to the inner-shareable domain) with its
    /// barriers.
    #[inline]
    fn icache_sync_all(&self) {
        crate::cache::icache_invalidate_all();
    }

    /// `flush_tlb_page` is already `TLBI VAAE1IS`, broadcast on this ISA.
    #[inline]
    fn flush_tlb_page_all(&self, va: usize) {
        Mmu::flush_tlb_page(self, va);
    }

    #[inline]
    unsafe fn zero_memory(&self, va: usize, len: usize) {
        // SAFETY: forwarded caller contract.
        unsafe { crate::cbo::zero_memory(va, len) }
    }

    /// `TTBR0_EL1`: ASID in bits 63:48 (`TCR_EL1.A1` = 0 takes it from
    /// TTBR0), the table PA below. User leaves carry nG, so their TLB
    /// entries are tagged with it (N12, Kconfig `TLB_RETAIN`).
    #[inline]
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize {
        ((asid as usize) << 48) | (root_phys & 0x0000_ffff_ffff_fffe)
    }

    #[inline]
    fn user_root_asid(&self, word: usize) -> u16 {
        (word >> 48) as u16
    }

    #[inline]
    fn user_root_with_asid(&self, word: usize, asid: u16) -> usize {
        (word & 0x0000_ffff_ffff_ffff) | ((asid as usize) << 48)
    }

    /// Zero means "keep the kernel's own table" on this ISA (no root lives at
    /// PA 0), so it leaves `TTBR0_EL1` alone.
    #[inline]
    fn install_user_root_local(&self, word: usize) {
        if word != 0 {
            crate::sysregs::install_ttbr0_flush_local(word);
            // Outside the generation scheme: the next user switch flushes
            // (Kconfig `TLB_RETAIN`).
            azos_arch_api::tlb_gen::mark_stale(crate::cpu::hart_id());
        }
    }

    type UserAccess = crate::sysregs::UserAccess;

    #[inline]
    fn user_access(&self) -> Self::UserAccess {
        crate::sysregs::UserAccess::enable()
    }
}
