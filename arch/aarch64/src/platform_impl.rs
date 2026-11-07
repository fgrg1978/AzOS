// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`ArchPlatform`] for aarch64: thin `#[inline]` wrappers over this crate's
//! own modules, so a shared crate calls `ARCH.<method>` instead of naming
//! `cache`/`sysregs` (which a new ISA would not have).

use crate::api_impl::Aarch64;
use azos_arch_api::{ArchPlatform, Mmu};

impl ArchPlatform for Aarch64 {
    fn pt_tag_leaf(&self, word: u64) -> u64 {
        crate::mmu::ptwin::tag(word)
    }
    fn pt_key_present(&self) -> bool {
        let regs = crate::cpu::features::read_id_regs();
        azos_arch_api::isa::aarch64::POE.gate(regs.s1poe() && regs.tcr2())
    }
    fn pt_lock_this_cpu(&self) -> bool {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            crate::mmu::ptwin::lock_this_cpu()
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        unreachable!("aarch64: pt_lock_this_cpu on a host build")
    }
    fn pt_locked_this_cpu(&self) -> bool {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            crate::mmu::ptwin::locked_this_cpu()
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        unreachable!("aarch64: pt_locked_this_cpu on a host build")
    }
    #[inline(always)]
    fn pt_window_open(&self) -> u64 {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            crate::mmu::ptwin::open()
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        unreachable!("aarch64: pt_window_open on a host build")
    }
    #[inline(always)]
    fn pt_window_close(&self, _saved: u64) {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        crate::mmu::ptwin::close(_saved);
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        unreachable!("aarch64: pt_window_close on a host build")
    }

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

    fn tlb_remote_flush_masked_ok(&self) -> bool { true }

    /// `flush_tlb_page` is already `TLBI VAAE1IS`, broadcast on this ISA.
    #[inline]
    fn flush_tlb_page_all(&self, va: usize) {
        Mmu::flush_tlb_page(self, va);
    }

    #[inline]
    unsafe fn zero_memory(&self, va: usize, len: usize) {
        // SAFETY: forwarded caller contract.
        unsafe { crate::cache::zero_memory(va, len) }
    }

    /// FEAT_RNG `RNDRRS`, when the boot selected it (`seed::select`).
    fn cpu_seed(&self, out: &mut [u8]) -> azos_arch_api::entropy::CpuSeed {
        crate::seed::fill(out)
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

    /// The table PA's frame number (BADDR, bits 47:1, without the CnP bit):
    /// the key of the space's ASID record. `tlb_space_key` stays 0 (broadcast
    /// TLBI, no hart mask).
    #[inline]
    fn user_root_frame(&self, word: usize) -> usize {
        (word & 0x0000_ffff_ffff_fffe) >> 12
    }

    /// Zero means "keep the kernel's own table" on this ISA (no root lives at
    /// PA 0), so it leaves `TTBR0_EL1` alone.
    #[inline]
    fn install_user_root_local(&self, word: usize) {
        if word != 0 {
            // percpu-hint: the arch contract: called on the switch and exec paths with interrupts off
            crate::tlb::publish(crate::cpu::hart_id(), word);
            crate::sysregs::install_ttbr0_flush_local(word);
            // Outside the generation scheme: the next user switch flushes
            // (Kconfig `TLB_RETAIN`), and until then this PE may run the
            // space under an ASID that is not its record, so no ASID-scoped
            // shootdown counts on it (`tlb_gen::UNTRACKED`).
            // percpu-hint: the arch contract: called on the switch and exec paths with interrupts off
            azos_arch_api::tlb_gen::mark_untracked(crate::cpu::hart_id());
        }
    }

    type UserAccess = crate::sysregs::UserAccess;

    #[inline]
    fn user_access(&self) -> Self::UserAccess {
        crate::sysregs::UserAccess::enable()
    }
}
