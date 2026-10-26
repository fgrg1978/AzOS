// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! How a RISC-V S-mode hart programs its timer: SBI `set_timer` or the Sstc
//! `stimecmp` CSR, chosen once at boot.
//!
//! The name is historical: the writes are the SBI call or a CSR, none of
//! them the CLINT's MMIO. The tick rate, the tick
//! arithmetic and the per-hart record of what is programmed are ISA-neutral
//! and live in `azos_drv_sys::timebase`, which calls [`set_timer`] here on
//! riscv64 and `Interrupts::set_timer_deadline` elsewhere.
//!
//! Ported from kernel/core/irq.c (CLINT parts)

use core::sync::atomic::{AtomicU8, Ordering};

// ── Timer programming mechanism ─────────────────────────────────────────────

/// How the next timer interrupt is programmed.
///
/// RISC-V has a real choice — SBI `set_timer` vs the Sstc `stimecmp` CSR —
/// selected once at boot by [`timer_select`] from the device tree plus a
/// hardware probe (see that function's doc). The other ISAs have exactly one
/// mechanism (the ARMv8 generic timer, the x86 TSC deadline), reached through
/// `arch-api`'s `Interrupts::set_timer_deadline`, so they have nothing to
/// select and no equivalent of this module.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimerMode {
    /// SBI `set_timer`: an ecall into the firmware per tick.
    Sbi,
    /// Sstc: a direct write to the `stimecmp` CSR, no trap.
    Sstc,
}

const MODE_UNSET: u8 = 0;
const MODE_SBI: u8 = 1;
const MODE_SSTC: u8 = 2;

/// Selected once by [`timer_select`]. Until then every write goes through SBI,
/// which works on every S-mode platform.
static TIMER_MODE: AtomicU8 = AtomicU8::new(MODE_UNSET);

/// Choose the timer mechanism, once. `dt_sstc` is `DtbInfo::isa_sstc` — and
/// `false` from a build that forces SBI.
///
/// Sstc only when the device tree declares it AND S-mode can actually read
/// `stimecmp`. The device tree says the hart implements the CSR; whether
/// S-mode may touch it is `menvcfg.STCE` (and `mcounteren.TM`), which only
/// M-mode can read. With either clear, an S-mode access is an illegal
/// instruction, and an illegal instruction from S-mode shuts the board down.
/// So the answer is taken from the hart: [`smode_timer::stimecmp_readable`]
/// reads the CSR once under a private trap vector. OpenSBI sets STCE when it
/// finds Sstc; firmware that does not is seen here and gets SBI.
///
/// Probed on the calling hart only (the boot hart). A SoC whose harts differ
/// in Sstc or in firmware setup would be mis-selected on the others.
///
/// The first call decides; later calls return that decision without probing.
pub fn timer_select(dt_sstc: bool) -> TimerMode {
    let current = TIMER_MODE.load(Ordering::Acquire);
    if current != MODE_UNSET {
        return decode(current);
    }
    let want = if dt_sstc && smode_timer::stimecmp_readable() { MODE_SSTC } else { MODE_SBI };
    match TIMER_MODE.compare_exchange(MODE_UNSET, want, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => decode(want),
        Err(already) => decode(already),
    }
}

/// Run the `stimecmp` access probe on the calling hart, outside any selection.
///
/// For the boot log of an emulated build: `-cpu rv64,sstc=off` makes the read
/// trap, which is the one way to take the probe's own trap path and see the
/// boot carry on after it.
pub fn stimecmp_probe() -> bool {
    smode_timer::stimecmp_readable()
}

#[inline(always)]
fn decode(mode: u8) -> TimerMode {
    if mode == MODE_SSTC { TimerMode::Sstc } else { TimerMode::Sbi }
}

// ============================================================
// RISC-V S-mode platforms (QEMU / VF2 / K1): SBI set_timer / stimecmp
// ============================================================

mod smode_timer {
    use crate::firmware;

    /// Schedule the next timer interrupt via SBI set_timer.
    #[inline(always)]
    pub fn set_timer_sbi(time: u64) {
        firmware::set_timer(time);
    }

    /// Schedule the next timer interrupt by writing `stimecmp` (CSR 0x14D).
    ///
    /// Numeric, not the CSR name: the name assembles only when the target
    /// enables the Sstc feature, and none of the kernel targets do.
    #[inline(always)]
    pub fn set_timer_stimecmp(time: u64) {
        unsafe {
            core::arch::asm!("csrw 0x14d, {}", in(reg) time, options(nostack, preserves_flags));
        }
    }

    // `azos_stimecmp_probe() -> usize`: 1 if reading `stimecmp` does not
    // trap on this hart, 0 if it does.
    //
    // Self-contained, so it needs no fixup table and no change to the kernel's
    // trap handler: interrupts off, `stvec` pointed at a four-instruction
    // handler of its own, one CSR read, `stvec` and `sstatus.SIE` restored.
    // The handler resumes at label 2 with a0 = 0. Only an illegal-instruction
    // exception can reach it — SIE is clear and nothing else in the window can
    // fault. Clobbers t0-t3 and a0, all caller-saved.
    //
    // `sret` leaves SIE = SPIE, which the trap set from the cleared SIE, so
    // interrupts stay off until the saved bit is written back at label 2.
    core::arch::global_asm!(
        ".pushsection .text.azos_stimecmp_probe, \"ax\"",
        ".globl azos_stimecmp_probe",
        ".p2align 2",
        "azos_stimecmp_probe:",
        "    csrrci t3, sstatus, 2",
        "    csrr   t1, stvec",
        "    la     t0, 1f",
        "    csrw   stvec, t0",
        "    li     a0, 1",
        "    csrr   t2, 0x14d",
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

    unsafe extern "C" {
        fn azos_stimecmp_probe() -> usize;
    }

    /// Can S-mode read `stimecmp` on this hart? See `azos_stimecmp_probe`.
    pub fn stimecmp_readable() -> bool {
        unsafe { azos_stimecmp_probe() != 0 }
    }
}

// ============================================================
// Public API
// ============================================================

/// Schedule the next timer interrupt at an absolute time value, on the
/// calling hart (`stimecmp` and SBI `set_timer` are both per-hart; `_hart` is
/// not used by either).
///
/// Called only by `timebase`'s recorded writers (`program`, `arm_if_earlier`):
/// a write from anywhere else leaves the hart's record of its comparator wrong,
/// and a task blocking on a timer deadline then skips a write it needed.
#[inline(always)]
pub fn set_timer(_hart: u32, time: u64) {
    if TIMER_MODE.load(Ordering::Relaxed) == MODE_SSTC {
        smode_timer::set_timer_stimecmp(time);
    } else {
        smode_timer::set_timer_sbi(time);
    }
}
