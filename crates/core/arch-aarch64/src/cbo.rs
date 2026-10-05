// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Bulk page zeroing — the aarch64 side of `azos_arch::cbo`.
//!
//! RISC-V's `crates/core/arch-riscv64/src/cbo.rs` dispatches to `cbo.zero`
//! (Zicboz) behind a DTB-driven, trap-verified probe, with a scalar
//! `core::ptr::write_bytes` fallback whenever the extension is absent or
//! unproven. `crates/core/mm` (`pmm::alloc_page`, `demand::handle_demand_fault`,
//! `vdso::vdso_init`) calls `azos_arch::cbo::zero_memory` expecting
//! that same signature on every ISA — this module gives aarch64 the
//! fallback half of that contract.
//!
//! **What this is not, honestly.** VMSAv8-A's answer to the same problem
//! is `DC ZVA` (Data Cache Zero by Virtual Address), gated by `DCZID_EL0`
//! for whether it is permitted and at what block size. That fast path is
//! not implemented here — this always takes the scalar route. Per the
//! project's rule for an ISA-specific fast path with no arch-api
//! equivalent yet ("route through arch-api if an equivalent exists;
//! otherwise an honest aarch64 side that never fakes success"): a plain
//! `write_bytes` genuinely zeroes the memory, correctly, every time — it is
//! slower than `DC ZVA` would be, never wrong. Wiring up `DC ZVA` (with the
//! same "probe it, don't just trust the ID register" discipline
//! `zicboz_select` uses) is a follow-up, not a correctness gap.

/// Zero `len` bytes at `addr`. See the module doc for why this is always
/// the scalar path on aarch64 today.
///
/// # Safety
/// `addr` must be a valid, writable address for `len` bytes, with no
/// other live reference to that memory — the same contract
/// `core::ptr::write_bytes` has, since that is exactly what this calls.
#[inline]
pub unsafe fn zero_memory(addr: usize, len: usize) {
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len) };
}

/// aarch64 side of `azos_arch::cbo::zicboz_select`
/// (`kernel/src/entry/riscv64/boot_hooks.rs` calls it, unconditionally, once at boot).
///
/// Zicboz is a RISC-V extension name — there is nothing to select on this
/// ISA, so this always answers `false` (no fast path taken) rather than
/// reusing the RISC-V name for a probe that would be meaningless here.
/// [`zero_memory`] above is always the scalar path regardless of this
/// return value; see the module doc for why `DC ZVA` (the real aarch64
/// fast path) isn't wired up yet. Arguments are accepted and ignored so a
/// caller written against the RISC-V signature (DTB-declared extension +
/// block size) compiles unchanged on this ISA.
#[inline]
pub fn zicboz_select(_dt_zicboz: bool, _dt_block_size: u32) -> bool {
    false
}
