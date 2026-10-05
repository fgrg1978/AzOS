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
