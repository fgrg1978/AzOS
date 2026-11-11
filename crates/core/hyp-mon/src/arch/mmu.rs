// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! EL2 stage-1 state and the per-PE EL1 grant.
//!
//! The identity map is one level-1 table of 512 × 1 GiB blocks, baked into the
//! image as a `const`: a 1:1 map's descriptors do not depend on the load
//! address, so no PE has to build it and no pre-MMU atomic is needed. Index 0
//! (the device gigabyte on QEMU virt and the SBC SoCs) is Device, the rest
//! Normal write-back inner-shareable. The entry stub (`entry.rs`) loads it and
//! turns the MMU on; this module grants EL1 back to the kernel.

use super::ptcheck::PeSlots;
use super::{MAX_PES, STACK_SIZE};
use azos_hyp_api::{INV_EL2_MMU, INV_HOST_S2, INV_PSCI};

/// 4 KiB TG0, 39-bit (T0SZ=25), inner WB cacheable + inner-shareable,
/// PS = 40-bit, EL2 RES1 at bits 23 and 31.
pub const TCR_EL2: u64 =
    25 | (1 << 8) | (1 << 10) | (3 << 12) | (0 << 14) | (2 << 16) | (1 << 23) | (1 << 31);

const fn identity() -> [u64; 512] {
    let mut t = [0u64; 512];
    let mut i = 0usize;
    while i < 512 {
        let pa = (i as u64) << 30;
        t[i] = if i == 0 {
            pa | (1 << 10) | 0b01 // AF, AttrIndx0 (Device), block
        } else {
            pa | (1 << 10) | (3 << 8) | (1 << 2) | 0b01 // AF, SH inner, AttrIndx1 (Normal), block
        };
        i += 1;
    }
    t
}

#[repr(align(4096))]
#[allow(dead_code)] // reason: read by the table walker through TTBR0_EL2, never by Rust
struct L1([u64; 512]);

#[no_mangle]
static IDENTITY_L1: L1 = L1(identity());

/// EL2 stacks, one per PE. In `.bss`, zero-filled into the blob. A stable
/// symbol: the entry stub forms each PE's stack top from it.
#[no_mangle]
pub static mut HYP_STACKS: [[u8; STACK_SIZE]; MAX_PES] = [[0; STACK_SIZE]; MAX_PES];

/// Which core owns which EL2 stack slot, by full affinity (`keys` first, read by
/// the entry stub), and the context each gets back when it resumes.
#[no_mangle]
static HYP_PE_SLOTS: PeSlots<MAX_PES> = PeSlots::new();

/// The slot table, addressed PC-relative. The symbol is global (the entry stub
/// names it), and rustc reaches a global through the GOT, which the flat image
/// never relocates: a plain `HYP_PE_SLOTS` in Rust would read and write the
/// link address, not the table.
pub fn pe_slots() -> &'static PeSlots<MAX_PES> {
    let p: *const PeSlots<MAX_PES>;
    // SAFETY: the address of a static of this image.
    unsafe {
        core::arch::asm!(
            "adrp {t}, HYP_PE_SLOTS",
            "add {t}, {t}, :lo12:HYP_PE_SLOTS",
            t = out(reg) p,
            options(nomem, nostack, pure),
        );
        &*p
    }
}

/// Run after the entry stub has turned EL2 stage-1 on. Sets the vectors, HCR,
/// the EL1 grants, builds host stage-2 on the primary (F2) or attaches it on any
/// other entry, and accounts the PE. `slot` is this PE's stack index;
/// `primary` is set only for the first entry of the boot PE (a PE back from a
/// power-down, the boot PE included, enters as a secondary). Returns to the
/// stub, which `eret`s the caller into EL1.
///
/// # Safety
/// Called on every entry of a PE, from the entry stub, at EL2 with the MMU on.
#[no_mangle]
pub unsafe extern "C" fn hyp_el2_init(slot: u64, primary: u64) {
    let primary = primary != 0;

    if cfg!(feature = "hyp-no-secondary-init-canary") && !primary {
        // R1 red: a secondary never finishes init, so `probe` sees fewer PEs.
        return;
    }

    unsafe {
        // VBAR_EL2 = the monitor's vectors (PC-relative → the PA).
        core::arch::asm!(
            "adrp {t}, _hyp_vectors",
            "add {t}, {t}, :lo12:_hyp_vectors",
            "msr VBAR_EL2, {t}",
            "isb",
            t = out(reg) _,
        );
        // HCR_EL2: EL1 AArch64, pointer-auth usable at EL1, and TSC so every
        // SMC traps to the monitor (F3). VM is added by the stage-2 build (F2).
        // The `hyp-tsc-off-canary` drops TSC so SMCs pass through and R3 fails.
        let tsc: u64 = if cfg!(feature = "hyp-tsc-off-canary") { 0 } else { 1 << 19 };
        core::arch::asm!(
            "msr HCR_EL2, {v}",
            v = in(reg) (1u64 << 31) | (1u64 << 41) | (1u64 << 40) | tsc,
        );
        grant_el1();
    }
    // Stage 2 is per PE: every PE that runs the host takes the live map before EL1 runs on it.
    if !primary {
        super::s2::attach_host_s2();
    }
    super::pin::init_pe();

    if primary {
        if !cfg!(feature = "hyp-mmu-off-canary") {
            crate::state::HYP.set_invariant(INV_EL2_MMU);
        }
        if !cfg!(feature = "hyp-tsc-off-canary") {
            crate::state::HYP.set_invariant(INV_PSCI);
        }
        // F2: permissive host stage-2 with the monitor image a hole.
        let (hole, len, top) = crate::arch::s2_hole();
        unsafe { super::s2::build_and_enable(hole, len, top) };
        let _ = INV_HOST_S2;
    }

    crate::hyp_cpu_up(slot, primary as u64);
}

/// The EL1 grants, matching `arch/aarch64/src/mmu/boot.rs::_azos_drop_to_el1`:
/// FP/SIMD untrapped, debug/PMU untrapped, the physical counter and (where
/// present) the GICv3 system registers reachable, and a safe `SCTLR_EL1`
/// (MMU off; `boot.S` rewrites it before any EL1 compiled code) / `CPACR_EL1`.
unsafe fn grant_el1() {
    unsafe {
        core::arch::asm!(
            "movz {t}, #0x22FF",
            "msr CPTR_EL2, {t}",
            "mov {t}, #0",
            "mrs {d}, ID_AA64DFR0_EL1",
            "sbfx {d}, {d}, #8, #4",
            "cmp {d}, #0",
            "b.le 2f",
            "mrs {t}, PMCR_EL0",
            "ubfx {t}, {t}, #11, #5",
            "2:",
            "msr MDCR_EL2, {t}",
            "mrs {t}, CNTHCTL_EL2",
            "orr {t}, {t}, #3",
            "msr CNTHCTL_EL2, {t}",
            "msr CNTVOFF_EL2, xzr",
            t = out(reg) _,
            d = out(reg) _,
        );
        core::arch::asm!(
            "mrs {t}, ID_AA64PFR0_EL1",
            "ubfx {t}, {t}, #24, #4",
            "cbz {t}, 1f",
            "mov {t}, #0x9",          // ICC_SRE_EL2: SRE | Enable
            "msr S3_4_C12_C9_5, {t}",
            "isb",
            "1:",
            t = out(reg) _,
        );
        core::arch::asm!(
            "movz {t}, #0x0800",
            "movk {t}, #0x30d0, lsl #16", // SCTLR_EL1: MMU off, RES1, SPAN
            "msr SCTLR_EL1, {t}",
            "movz {t}, #0x30, lsl #16",   // CPACR_EL1.FPEN = 0b11
            "msr CPACR_EL1, {t}",
            t = out(reg) _,
        );
    }
}
