// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// CLINT (Core-Local Interruptor) / SYSTIMER driver.
///
/// RISC-V S-mode platforms: timer via SBI calls or the Sstc `stimecmp` CSR,
/// and the `rdtime` instruction. aarch64 has one mechanism instead — the
/// ARMv8 generic timer, programmed through `arch-api`'s
/// `Interrupts::set_timer_deadline` — see [`TimerMode`]'s doc for why the
/// two ISAs don't share the selection dance below.
///
/// Ported from kernel/core/irq.c (CLINT parts)

use core::sync::atomic::{AtomicU32, Ordering};
// arch-only: the riscv64 SBI/Sstc mode word.
#[cfg(target_arch = "riscv64")]
use core::sync::atomic::AtomicU8;

/// Timer frequency — platform-specific. `mtime` on RISC-V (`TIMER_FREQ`
/// per board in `platform::hw`); the ARMv8 generic timer's `CNTFRQ_EL0` on
/// aarch64, where `platform::hw::TIMER_FREQ` carries the same provisional
/// caveat as this module's RISC-V board constants — see its doc comment.
pub const TIMER_FREQ: u64 = azos_drv_base::platform::hw::TIMER_FREQ;

// ── Configurable scheduler rate (Phase E1) ──────────────────────────────────

// Stored as AtomicU32: the 10-10000 range fits in u32; API still returns u64.
static SCHED_HZ: AtomicU32 = AtomicU32::new(100);

/// Set the scheduler tick rate (10..=10_000 Hz).  Out-of-range values are ignored.
pub fn sched_hz_set(hz: u64) {
    if hz >= 10 && hz <= 10_000 {
        SCHED_HZ.store(hz as u32, Ordering::Relaxed);
    }
}

/// Get the current scheduler tick rate in Hz.
pub fn sched_hz_get() -> u64 {
    SCHED_HZ.load(Ordering::Relaxed) as u64
}

// ── Timer programming mechanism (RFC-0041 §B) ───────────────────────────────

/// How the next timer interrupt is programmed.
///
/// **RISC-V has a real choice** — SBI `set_timer` vs the Sstc `stimecmp`
/// CSR — selected once at boot by [`timer_select`] from the device tree
/// plus a hardware probe (see that function's doc). **aarch64 has exactly
/// one mechanism**, the ARMv8 generic timer (`CNTV_CVAL_EL0`, reached
/// through `arch-api`'s `Interrupts::set_timer_deadline`), so its variant
/// is fixed: [`timer_select`]/[`timer_mode`] report `Generic`
/// unconditionally on this ISA rather than picking one of the two RISC-V
/// labels above — an aarch64 build must never claim to be running SBI or
/// Sstc, neither of which exists on this hardware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimerMode {
    /// SBI `set_timer`: an ecall into the firmware per tick.
    #[cfg(target_arch = "riscv64")]
    Sbi,
    /// Sstc: a direct write to the `stimecmp` CSR, no trap.
    #[cfg(target_arch = "riscv64")]
    Sstc,
    /// ARMv8 generic timer (`CNTV_CVAL_EL0`) — the only mechanism aarch64
    /// has. Not a placeholder: this is the honest, permanent answer on
    /// this ISA, not a stand-in for a selection that hasn't landed yet.
    // aarch64 and any ISA without a mechanism choice (the x86_64 skeleton):
    // the one deadline write the arch contract offers.
    #[cfg(any(all(target_arch = "aarch64", target_os = "none"), not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    Generic,
}

#[cfg(target_arch = "riscv64")]
const MODE_UNSET: u8 = 0;
#[cfg(target_arch = "riscv64")]
const MODE_SBI: u8 = 1;
#[cfg(target_arch = "riscv64")]
const MODE_SSTC: u8 = 2;

/// Selected once by [`timer_select`]. Until then every write goes through SBI,
/// which works on every S-mode platform.
#[cfg(target_arch = "riscv64")]
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
#[cfg(target_arch = "riscv64")]
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

/// The mechanism in use: SBI until [`timer_select`] has chosen.
#[cfg(target_arch = "riscv64")]
pub fn timer_mode() -> TimerMode {
    decode(TIMER_MODE.load(Ordering::Acquire))
}

/// Run the `stimecmp` access probe on the calling hart, outside any selection.
///
/// For the boot log of an emulated build: `-cpu rv64,sstc=off` makes the read
/// trap, which is the one way to take the probe's own trap path and see the
/// boot carry on after it.
///
/// RISC-V only — there is nothing to probe on aarch64 (see [`TimerMode`]).
/// `kernel/src/entry/riscv64/boot_hooks.rs` currently calls this unconditionally under
/// `#[cfg(feature = "qemu")]`; an aarch64 boot path must not call it.
#[cfg(target_arch = "riscv64")]
pub fn stimecmp_probe() -> bool {
    smode_timer::stimecmp_readable()
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn decode(mode: u8) -> TimerMode {
    if mode == MODE_SSTC { TimerMode::Sstc } else { TimerMode::Sbi }
}

/// aarch64 (and the x86_64 skeleton, whose deadline is the contract's
/// `set_timer_deadline`: TSC-deadline): one mechanism only, so there is
/// nothing to select. `_dt_sstc` is
/// accepted (not `#[cfg]`d away) so a caller written against the RISC-V
/// signature — a device-tree Sstc flag — still compiles unchanged on this
/// ISA; the value is always ignored, since Sstc is a RISC-V CSR extension
/// with no aarch64 equivalent to turn on or off.
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub fn timer_select(_dt_sstc: bool) -> TimerMode {
    TimerMode::Generic
}

/// aarch64: always [`TimerMode::Generic`] — see [`TimerMode`]'s doc.
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub fn timer_mode() -> TimerMode {
    TimerMode::Generic
}

// ============================================================
// RISC-V S-mode platforms (QEMU / VF2 / K1): rdtime + SBI set_timer / stimecmp
// ============================================================

#[cfg(target_arch = "riscv64")]
mod smode_timer {
    use azos_arch::sbi;

    /// Read the current time counter (`rdtime` instruction).
    #[inline(always)]
    pub fn get_time() -> u64 {
        let time: u64;
        unsafe { core::arch::asm!("rdtime {}", out(reg) time) };
        time
    }

    /// Schedule the next timer interrupt via SBI set_timer.
    #[inline(always)]
    pub fn set_timer_sbi(time: u64) {
        sbi::set_timer(time);
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

/// Read the current time counter.
///
/// **Prefer [`azos_drv_sys::timebase::now`]** — this name says CLINT and the read is
/// `rdtime`, a CSR, not the CLINT's MMIO. Kept because the timer-control
/// functions below legitimately belong to this module and read the same
/// counter to compute their deadlines.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn get_time() -> u64 {
    smode_timer::get_time()
}

/// aarch64: `CNTVCT_EL0`, through the same free function `timebase::now()`
/// and `Cpu::now_ticks` already use — see `azos_drv_sys::timebase`'s module doc
/// for why this crate stopped naming the clock after a RISC-V device.
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
#[inline(always)]
pub fn get_time() -> u64 {
    azos_arch::Cpu::now_ticks(&azos_arch::ARCH)
}

/// Schedule the next timer interrupt at an absolute time value, on the
/// calling hart (`stimecmp` and SBI `set_timer` are both per-hart; `_hart` is
/// not used by either).
///
/// Called only by `timebase`'s recorded writers (`program`, `arm_if_earlier`):
/// a write from anywhere else leaves the hart's record of its comparator wrong,
/// and a task blocking on a timer deadline then skips a write it needed.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn set_timer(_hart: u32, time: u64) {
    if TIMER_MODE.load(Ordering::Relaxed) == MODE_SSTC {
        smode_timer::set_timer_stimecmp(time);
    } else {
        smode_timer::set_timer_sbi(time);
    }
}

/// aarch64: the deadline write goes straight through `arch-api`'s
/// [`azos_arch::Interrupts::set_timer_deadline`] (`CNTV_CVAL_EL0` write +
/// enable) — there is no mechanism choice to make here, so unlike the
/// RISC-V arm above this needs no `TIMER_MODE` dispatch at all. `_hart` is
/// unused for the same reason the RISC-V arm ignores it: the generic
/// timer's `CVAL` register is per-PE, not addressed by hart id.
///
/// **Not routed through `ARCH` on RISC-V.** `arch-riscv64`'s own
/// `Interrupts::set_timer_deadline` is SBI-only — it has no visibility into
/// this module's `TIMER_MODE` — so doing the same thing there would
/// silently drop the Sstc fast path this file exists to provide.
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
#[inline(always)]
pub fn set_timer(_hart: u32, time: u64) {
    use azos_arch::Interrupts;
    azos_arch::ARCH.set_timer_deadline(time);
}

