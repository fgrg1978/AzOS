// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_arch`.
//!
//! **It re-exports the real module rather than stubbing it.** The facade crate
//! is `target_arch`-gated and its CSR/PLIC halves cannot compile on a host,
//! but `arch-riscv64/src/mmu.rs` is pure arithmetic — the same file
//! `tests/host/arch-tests` already covers. Pulling it in with `#[path]` means the
//! memory manager under test computes page numbers with the kernel's own
//! definitions of `PAGE_SIZE` and the Sv39 layout, not with a copy that can
//! drift from them.
//!
//! A stub here would be the failure `tests/host/regression-tests/src/sched_tests.rs`
//! documents at length: a test asserting against a hand-written duplicate of
//! the logic it claims to watch.

#[path = "../../../../../../crates/core/arch-riscv64/src/mmu.rs"]
pub mod mmu;

/// Host stand-in for `azos_arch::cbo` (RFC-0045 Tier 0 item 3).
///
/// The real module emits `cbo.zero` when a boot-time probe found Zicboz,
/// and `write_bytes` when it did not. It cannot compile here — it is
/// inline assembly and a `global_asm!` trap probe — but this is **not** a
/// fabricated answer: a host has no Zicboz to probe, so the scalar branch
/// is the real module's own behavior on this target, byte for byte. The
/// allocator under test therefore zeroes pages exactly as it would on a
/// board whose device tree does not declare the extension, which is one of
/// the two paths that has to keep working.
pub mod cbo {
    /// See the module doc: the real dispatcher's fallback branch.
    ///
    /// # Safety
    /// Same contract as `core::ptr::write_bytes(addr, 0, len)`.
    pub unsafe fn zero_memory(addr: usize, len: usize) {
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len) };
    }
}

pub use azos_arch_api::ArchPlatform;
pub use mmu::{PAGE_SHIFT, PAGE_SIZE};

/// Stand-in singleton for `azos_arch::ARCH`.
pub struct Arch;
pub static ARCH: Arch = Arch;

/// The arch contract's `ArchPlatform`, host bodies: plain stores for zeroing,
/// no caches or TLBs to maintain. Shared files call these through `ARCH`
/// rather than an ISA module, so this stand-in implements the contract.
impl azos_arch_api::ArchPlatform for Arch {
    fn icache_needs_dcache_clean(&self) -> bool { false }
    unsafe fn dcache_clean(&self, _va: usize, _len: usize) {}
    fn icache_sync_all(&self) {}
    fn flush_tlb_page_all(&self, _va: usize) {}
    unsafe fn zero_memory(&self, va: usize, len: usize) {
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, len) };
    }
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize { mmu::make_satp(root_phys, asid) }
    fn install_user_root_local(&self, _word: usize) {}
    type UserAccess = ();
    fn user_access(&self) {}
}
