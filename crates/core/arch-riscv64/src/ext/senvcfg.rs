// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `senvcfg`: what U-mode may do of the hart's environment (Kconfig
//! `RV_SENVCFG`).
//!
//! The CSR (0x10A, privileged spec 1.12) gates U-mode's cache-block
//! instructions (CBZE bit 7 `cbo.zero`, CBCFE bit 6 `cbo.clean`/`cbo.flush`,
//! CBIE bits 5:4 `cbo.inval`), pointer masking (PMM bits 33:32, Ssnpm), the
//! U-mode landing pads and shadow stack (LPE bit 2, SSE bit 3) and FIOM (bit
//! 0). Its reset value is not defined, and the firmware's `menvcfg` opens the
//! cache-block instructions to S-mode where the hart has them, so what U-mode
//! may run was whatever the reset left: no task owns that state. Every hart
//! writes [`USER_ENV`] before ring 3 runs on it ([`init_this_hart`]: the boot
//! hart at [`select`], each secondary from `secondary_irq_init`, a resumed
//! hart through the same path).
//!
//! [`USER_ENV`] is 0: no ring-3 program uses a cache-block instruction or
//! pointer masking (relibc, stdrt and the Linux servers have none), so U-mode
//! gets none and each traps as an illegal instruction. Linux sets CBZE where
//! Zicboz is (user space's `cbo.zero`); the day a ring-3 user exists, its bit
//! goes here.
//!
//! A hart before Priv 1.12 has no `senvcfg` (the access traps), and no device
//! tree token names it: the probe is one trap-safe read under a private
//! `stvec` on the boot hart (`seed.rs`'s shape), the harts of one machine
//! taken to be uniform, as for Ssqosid.

use core::sync::atomic::{AtomicBool, Ordering};

/// The CSR number.
pub const SENVCFG: u16 = 0x10A;

/// `senvcfg.CBZE` (bit 7): U-mode `cbo.zero`.
pub const CBZE: usize = 1 << 7;
/// `senvcfg.CBCFE` (bit 6): U-mode `cbo.clean` and `cbo.flush`.
pub const CBCFE: usize = 1 << 6;
/// `senvcfg.CBIE` (bits 5:4) = 01: U-mode `cbo.inval` runs as a flush.
pub const CBIE_FLUSH: usize = 0b01 << 4;
/// `senvcfg.FIOM` (bit 0): fence on I/O implies memory.
pub const FIOM: usize = 1 << 0;

/// The `senvcfg` every hart runs with: U-mode gets nothing (see the module
/// doc).
pub const USER_ENV: usize = 0;

/// What [`init_this_hart`] writes: [`USER_ENV`]. Gate canary
/// `el0-state-canary`: a stand-in for a reset value that opens every
/// cache-block instruction (ktest `user_visible_state_is_set_on_every_cpu`
/// is `not ok`; QEMU resets the CSR to 0, the right value, so only the
/// canary shows the check can fail).
const WRITTEN: usize = if cfg!(feature = "el0-state-canary") { CBZE | CBCFE | CBIE_FLUSH | FIOM } else { USER_ENV };

/// The boot found the CSR ([`select`]).
static PRESENT: AtomicBool = AtomicBool::new(false);

/// Decide on the boot hart: the Kconfig policy allows it and the probe reads
/// the CSR without a trap (run only then, so `n` executes nothing). Writes
/// [`USER_ENV`] on this hart when present. Returns the decision.
pub fn select(policy_allows: bool, probe: impl FnOnce() -> bool) -> bool {
    let present = policy_allows && probe();
    PRESENT.store(present, Ordering::Release);
    init_this_hart();
    present
}

/// Does this boot have `senvcfg` ([`select`])?
#[inline]
pub fn available() -> bool {
    PRESENT.load(Ordering::Acquire)
}

/// Write [`USER_ENV`] to this hart's `senvcfg`; nothing where the boot found
/// none. Every hart, before ring 3 runs on it.
pub fn init_this_hart() {
    if available() {
        write(WRITTEN);
    }
}

/// This hart's `senvcfg`, or `None` where the boot found none.
pub fn read() -> Option<usize> {
    if !available() {
        return None;
    }
    #[cfg(target_arch = "riscv64")]
    {
        let v: usize;
        // SAFETY: the boot probe read `senvcfg` without a trap; no memory.
        unsafe { core::arch::asm!("csrr {v}, {csr}", csr = const SENVCFG, v = out(reg) v, options(nomem, nostack)) };
        Some(v)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        None
    }
}

#[inline(always)]
fn write(v: usize) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: only reached after the boot probe read `senvcfg` without a
    // trap; the CSR gates U-mode only and touches no memory.
    unsafe {
        core::arch::asm!("csrw {csr}, {v}", csr = const SENVCFG, v = in(reg) v, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "riscv64"))]
    let _ = v;
}

/// One trap-safe read of `senvcfg`: `false` when the access trapped.
pub fn trap_probe() -> bool {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: the routine installs its own stvec with interrupts off and
        // restores both; the read changes nothing; no memory.
        unsafe { azos_senvcfg_probe() != 0 }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        false
    }
}

// `azos_senvcfg_probe() -> a0` (1 read, 0 trapped). The `seed.rs` probe's
// shape: sstatus.SIE cleared, a private stvec whose handler zeroes a0 and
// resumes after the access, stvec and SIE restored. Clobbers t0-t3.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_senvcfg_probe, \"ax\"",
    ".globl azos_senvcfg_probe",
    ".p2align 2",
    "azos_senvcfg_probe:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a0, 1",
    "    csrr   t2, {csr}",
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
    csr = const SENVCFG,
);

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_senvcfg_probe() -> usize;
}
