// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Zkr `seed` CSR (0x015) as the boot entropy pool's CPU seed source
//! (`azos_arch_api::entropy`, `ArchPlatform::cpu_seed`).
//!
//! Two steps, the Zicboz/Sstc shape (`cache.rs`, `clint::timer_select`):
//!
//! 1. cpu@0's device tree declares `zkr` (`DtbInfo::isa_zkr`), masked by
//!    Kconfig RV_ZKR — the kernel passes the result to [`select`].
//! 2. [`select`] reads the CSR once under a private `stvec`. The device tree
//!    saying the hart implements Zkr is not enough: S-mode reaches `seed`
//!    only when M-mode firmware set `mseccfg.SSEED`, otherwise the access
//!    is an illegal instruction, and the kernel's own trap path for an
//!    S-mode illegal instruction stops the board (see `cache.rs`'s probe).
//!
//! Every later read goes through the same trap-safe routine (the boot draws
//! 24 words once; a few instructions each are nothing next to that), so a
//! firmware that changes its mind cannot take the boot down either.
//!
//! The CSR must be accessed with a read-write instruction (`csrrw rd,
//! seed, x0`); `csrr` (`csrrs` with x0) is illegal by the spec. Only status
//! ES16 carries entropy (bits 15:0); BIST/WAIT are retried within
//! `ENTROPY_CPU_RETRIES`, DEAD gives the source up
//! (`azos_arch_api::entropy::rv_seed_decode`).

use azos_arch_api::entropy::{self, CpuSeed, Draw};
use core::sync::atomic::{AtomicBool, Ordering};

static SELECTED: AtomicBool = AtomicBool::new(false);

/// Decide, once on the boot hart, whether `seed` is usable: `dt_zkr` is
/// cpu@0's claim masked by Kconfig RV_ZKR. Executes the CSR read only when
/// the claim holds; a trap or a DEAD status refutes it. Returns the
/// decision, which [`available`] repeats.
pub fn select(dt_zkr: bool) -> bool {
    let ok = dt_zkr && !matches!(read(), Draw::Dead);
    SELECTED.store(ok, Ordering::Release);
    ok
}

/// What [`select`] decided (the `[ISA]` line's `zkr` row).
pub fn available() -> bool {
    SELECTED.load(Ordering::Acquire)
}

/// Fill `out` from `seed`, or [`CpuSeed::NONE`] when [`select`] did not
/// choose it.
pub fn fill(out: &mut [u8]) -> CpuSeed {
    if !available() {
        return CpuSeed::NONE;
    }
    let bytes = entropy::fill(out, entropy::RETRIES, read, core::hint::spin_loop);
    CpuSeed { bytes, source: "zkr-seed" }
}

/// One trap-safe `csrrw rd, seed, x0`, decoded; a trap reads as DEAD. Also the
/// KASLR boot's draw (`mmu::kaslr_boot`), which runs before [`select`].
pub(crate) fn read() -> Draw {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: the routine installs its own stvec with interrupts off and
        // restores both; it touches no memory.
        let r = unsafe { azos_zkr_seed_read() };
        if r.ok == 0 { Draw::Dead } else { entropy::rv_seed_decode(r.value as u64) }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        Draw::Dead
    }
}

/// `azos_zkr_seed_read`'s two return registers (a0, a1).
#[repr(C)]
struct SeedRead {
    ok: usize,
    value: usize,
}

// `azos_zkr_seed_read() -> (a0 = 1 read / 0 trapped, a1 = CSR value)`.
// The `cache.rs` probe's shape: sstatus.SIE cleared, a private stvec whose
// handler zeroes a0 and resumes after the access, stvec and SIE restored.
// Clobbers t0, t1, t3 (caller-saved).
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_zkr_seed_read, \"ax\"",
    ".globl azos_zkr_seed_read",
    ".p2align 2",
    "azos_zkr_seed_read:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a0, 1",
    "    li     a1, 0",
    "    csrrw  a1, 0x015, zero",
    "2:",
    "    csrw   stvec, t1",
    "    andi   t3, t3, 2",
    "    csrs   sstatus, t3",
    "    ret",
    ".p2align 2",
    "1:",
    "    li     a0, 0",
    "    la     t0, 2b",
    "    csrw   sepc, t0",
    "    sret",
    ".popsection",
);

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_zkr_seed_read() -> SeedRead;
}
