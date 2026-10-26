// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`ArchPlatform`] for riscv64: thin `#[inline]` wrappers over this crate's
//! own modules, so a shared crate calls `ARCH.<method>` instead of naming
//! `firmware`/`cpu`/`cache` (which a new ISA would not have).

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
        let _ = crate::firmware::remote_fence_i(0, usize::MAX);
    }

    /// Local `sfence.vma va`, then SBI `remote_sfence_vma` of that page to
    /// every hart.
    #[inline]
    fn flush_tlb_page_all(&self, va: usize) {
        Mmu::flush_tlb_page(self, va);
        let _ = crate::firmware::remote_sfence_vma(0, usize::MAX, va, crate::mmu::PAGE_SIZE);
    }

    #[inline]
    unsafe fn zero_memory(&self, va: usize, len: usize) {
        // SAFETY: forwarded caller contract.
        unsafe { crate::cache::zero_memory(va, len) }
    }

    /// Zkr `seed`, when the boot selected it (`seed::select`).
    fn cpu_seed(&self, out: &mut [u8]) -> azos_arch_api::entropy::CpuSeed {
        crate::seed::fill(out)
    }

    #[inline]
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize {
        crate::mmu::make_satp(root_phys, asid)
    }

    /// `satp.ASID`, bits 59:44.
    #[inline]
    fn user_root_asid(&self, word: usize) -> u16 {
        (word >> 44) as u16
    }

    #[inline]
    fn user_root_with_asid(&self, word: usize, asid: u16) -> usize {
        (word & !(0xFFFF << 44)) | ((asid as usize) << 44)
    }

    /// `satp.PPN`, bits 43:0: the root frame number `tlb::shootdown` keys on.
    #[inline]
    fn tlb_space_key(&self, word: usize) -> usize {
        word & ((1usize << 44) - 1)
    }

    /// `AZOS_HART_SATP[hart]` (`tlb::publish`), what `tlb::shootdown` scans.
    #[inline]
    fn publish_user_root(&self, word: usize) {
        // percpu-hint: the arch contract: called on the switch and exec paths with interrupts off; the record and the install are one hart
        crate::tlb::publish(crate::cpu::hart_id(), word);
    }

    /// `csrw satp` + `sfence.vma` (and the TLB-holder publish `write_satp`
    /// does). Written unconditionally, as before.
    #[inline]
    fn install_user_root_local(&self, word: usize) {
        crate::cpu::write_satp(word);
    }

    type UserAccess = crate::cpu::UserAccess;

    #[inline]
    fn user_access(&self) -> Self::UserAccess {
        crate::cpu::UserAccess::enable()
    }
}
