// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`ArchPlatform`] for riscv64: thin `#[inline]` wrappers over this crate's
//! own modules, so a shared crate calls `ARCH.<method>` instead of naming
//! `sbi`/`csr`/`cbo` (which a new ISA would not have).

use crate::api_impl::Riscv64;
use azos_arch_api::{ArchPlatform, Mmu};

impl ArchPlatform for Riscv64 {
    /// RISC-V instruction fetch is made coherent by `fence.i` (Zifencei), not
    /// by data-cache maintenance.
    #[inline]
    fn icache_needs_dcache_clean(&self) -> bool {
        false
    }

    #[inline]
    unsafe fn dcache_clean(&self, _va: usize, _len: usize) {}

    /// Local `fence rw, rw` + `fence.i`, then SBI RFENCE `remote_fence_i` to
    /// every hart (`hart_mask_base == -1`).
    #[inline]
    fn icache_sync_all(&self) {
        // SAFETY: memory and instruction-fetch fences only.
        unsafe { core::arch::asm!("fence rw, rw", "fence.i", options(nostack, preserves_flags)) };
        let _ = crate::sbi::remote_fence_i(0, usize::MAX);
    }

    /// Local `sfence.vma va`, then SBI `remote_sfence_vma` of that page to
    /// every hart.
    #[inline]
    fn flush_tlb_page_all(&self, va: usize) {
        Mmu::flush_tlb_page(self, va);
        let _ = crate::sbi::remote_sfence_vma(0, usize::MAX, va, crate::mmu::PAGE_SIZE);
    }

    #[inline]
    unsafe fn zero_memory(&self, va: usize, len: usize) {
        // SAFETY: forwarded caller contract.
        unsafe { crate::cbo::zero_memory(va, len) }
    }

    #[inline]
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize {
        crate::mmu::make_satp(root_phys, asid)
    }

    /// `csrw satp` + `sfence.vma` (and the TLB-holder publish `write_satp`
    /// does). Written unconditionally, as before.
    #[inline]
    fn install_user_root_local(&self, word: usize) {
        crate::csr::write_satp(word);
    }

    type UserAccess = crate::csr::UserAccess;

    #[inline]
    fn user_access(&self) -> Self::UserAccess {
        crate::csr::UserAccess::enable()
    }
}
