// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PT_PROTECTION on aarch64: the kernel half's page-table pool carries
//! permission-overlay index [`POINDEX`], `POR_EL1` takes write away from that
//! index, and `pt_set` gives it back for the one store (Kconfig `A64_POE`,
//! FEAT_S1POE).
//!
//! With `TCR2_EL1.POE` set the CPU intersects every EL1 data access's page
//! permissions with the 4-bit overlay `POR_EL1` holds for the leaf's
//! `POIndex` (bits 62:60). Index 0 is every other kernel page and stays
//! read-write-execute. The window is one `POR_EL1` write and an `isb` before
//! the store and the same after, with every PSTATE.DAIF mask set between (an
//! SError or a debug exception inside it would run with the pool writable); it
//! restores what it found, so windows nest. The asm is not `nomem`: it is the
//! compiler barrier that keeps the store between the two writes.
//!
//! EL2 must let EL1 at the registers: `HCRX_EL2.TCR2En` for `TCR2_EL1` and the
//! `HFGRTR_EL2` / `HFGWTR_EL2` n-bit `nPOR_EL1` for `POR_EL1`
//! (`_azos_drop_to_el1` programs them, `mmu/boot.rs`). Without them the first
//! write traps to EL2. The encodings below are the Arm ARM's; the arm-phase
//! rows are what check them on a core.

/// The overlay index the pool carries. Index 0 is every other kernel page.
pub const POINDEX: u64 = 1;
/// First bit of the overlay index of a leaf.
pub const PTE_POINDEX_SHIFT: u32 = 60;
/// The overlay index field of a leaf (bits 62:60).
pub const PTE_POINDEX_MASK: u64 = 0b111 << PTE_POINDEX_SHIFT;
/// `TCR2_EL1.POE` (bit 3): stage-1 overlays apply to EL1 data accesses.
pub const TCR2_EL1_POE: u64 = 1 << 3;
/// Overlay permission bits of one index (four bits each in `POR_EL1`).
pub const OVL_R: u64 = 0b001;
pub const OVL_X: u64 = 0b010;
pub const OVL_W: u64 = 0b100;
/// `POR_EL1` while the pool is locked: index 0 read-write-execute, index 1 read only.
pub const POR_LOCKED: u64 = (OVL_R | OVL_X | OVL_W) | OVL_R << (4 * POINDEX);
/// `HCRX_EL2.TCR2En` (bit 14): EL1 may access `TCR2_EL1`.
pub const HCRX_TCR2EN: u64 = 1 << 14;
/// `HFGRTR_EL2` / `HFGWTR_EL2` `nPOR_EL1` (bit 60): 1 lets EL1 access `POR_EL1`.
/// Bit 59 is `nPOR_EL0`, EL0's. The boot trampoline builds its immediate from
/// this constant, so the number exists once.
pub const HFGXTR_NPOR_EL1: u64 = 1 << 60;
const DAIF_SHIFT: u32 = 32;

/// The leaf `word` tagged with the pool's overlay index (any other index cleared).
pub const fn tag(word: u64) -> u64 {
    (word & !PTE_POINDEX_MASK) | POINDEX << PTE_POINDEX_SHIFT
}

/// The `POR_EL1` value of an open window over `por`: write allowed on [`POINDEX`].
pub const fn opened(por: u64) -> u64 {
    por | OVL_W << (4 * POINDEX)
}

/// What a window open returns: the `POR_EL1` found (32 bits are defined) and
/// the `DAIF` value, for the close.
pub const fn pack(por: u64, daif: u64) -> u64 {
    (por & 0xFFFF_FFFF) | daif << DAIF_SHIFT
}

/// Inverse of [`pack`].
pub const fn unpack(token: u64) -> (u64, u64) {
    (token & 0xFFFF_FFFF, token >> DAIF_SHIFT)
}

/// Does this `TCR2_EL1` / `POR_EL1` pair deny writes to the pool?
pub const fn denies_writes(tcr2: u64, por: u64) -> bool {
    tcr2 & TCR2_EL1_POE != 0 && por & 0xFFFF_FFFF == POR_LOCKED
}

/// `TCR2_EL1.POE` on and `POR_EL1` denying writes to the pool, on this CPU.
/// Only after `ArchPlatform::pt_key_present` said yes, and with EL2's grants in
/// place. Whether it took is read back.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn lock_this_cpu() -> bool {
    // SAFETY: EL1; FEAT_S1POE and FEAT_TCR2 are present (the caller's probe) and
    // EL2 let EL1 at the registers, so these accesses do not trap.
    unsafe {
        core::arch::asm!(
            // Absolute: TCR2_EL1's other fields (PnCH, PIE, E0POE, D128, ...) are
            // UNKNOWN out of reset and change what a descriptor means.
            "msr S3_0_C2_C0_3, {poe}",
            "msr S3_0_C10_C2_4, {por}",
            "isb",
            poe = in(reg) TCR2_EL1_POE, por = in(reg) POR_LOCKED,
            options(nostack),
        );
    }
    locked_this_cpu()
}

/// Is this CPU denying writes to the pool now?
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn locked_this_cpu() -> bool {
    let (tcr2, por): (u64, u64);
    // SAFETY: reads of registers the lock programmed.
    unsafe {
        core::arch::asm!("mrs {0}, S3_0_C2_C0_3", "mrs {1}, S3_0_C10_C2_4",
            out(reg) tcr2, out(reg) por, options(nomem, nostack, preserves_flags));
    }
    denies_writes(tcr2, por)
}

/// Every DAIF mask set, the pool's write-deny lifted; the token for [`close`].
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline(always)]
pub fn open() -> u64 {
    let (daif, por): (u64, u64);
    // SAFETY: `DAIFSet #0xf` masks D, A, I and F; `close` writes DAIF back. POR_EL1
    // exists (the lock ran).
    unsafe {
        core::arch::asm!("mrs {d}, DAIF", "msr DAIFSet, #0xf", "mrs {p}, S3_0_C10_C2_4",
            d = out(reg) daif, p = out(reg) por, options(nostack));
        core::arch::asm!("msr S3_0_C10_C2_4, {o}", "isb", o = in(reg) opened(por), options(nostack));
    }
    pack(por, daif)
}

/// Restore `POR_EL1` and the interrupt masks a window found.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline(always)]
pub fn close(token: u64) {
    let (por, daif) = unpack(token);
    // SAFETY: puts back what `open` read.
    unsafe {
        core::arch::asm!("msr S3_0_C10_C2_4, {p}", "isb", "msr DAIF, {d}",
            p = in(reg) por, d = in(reg) daif, options(nostack));
    }
}
