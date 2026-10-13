// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Time: the vDSO clock, the absolute sleep and the yield. No syscall for a
//! read of the clock where the hardware counter is readable in ring 3.
//!
//! The only clock the kernel serves is the monotonic one
//! (`azos_abi::time::ClockId::MONO`); there is no wall clock in the ABI, so
//! `std::time::SystemTime` is not provided.

#[cfg(not(target_arch = "aarch64"))]
use crate::pure::rdtime_is_native;
use crate::sys::syscall6;
#[cfg(not(target_arch = "aarch64"))]
use crate::sys::invoke;
#[cfg(not(target_arch = "aarch64"))]
use azos_abi::invoke as inv;
use azos_abi::syscall_nr::{SYS_SLEEP_UNTIL, SYS_YIELD};
use azos_abi::vdso::VDSO_USER_BASE;

/// A word of the vDSO page published once at init (no seqlock needed).
#[cfg(not(target_arch = "aarch64"))]
fn page_u32(off: usize) -> u32 {
    // SAFETY: the page is mapped at VDSO_USER_BASE for every user task.
    unsafe { core::ptr::read_volatile((VDSO_USER_BASE + off) as *const u32) }
}

/// A seqlock-protected word of the vDSO page.
fn page_u64(off: usize) -> u64 {
    let seq = (VDSO_USER_BASE + 8) as *const u32;
    let data = (VDSO_USER_BASE + off) as *const u64;
    loop {
        // SAFETY: the page is mapped at VDSO_USER_BASE for every user task.
        let s1 = unsafe { core::ptr::read_volatile(seq) };
        if s1 & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let v = unsafe { core::ptr::read_volatile(data) };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        if s1 == unsafe { core::ptr::read_volatile(seq) } {
            return v;
        }
        core::hint::spin_loop();
    }
}

/// The free-running hardware counter, read in ring 3: the RISC-V `time` CSR,
/// the AArch64 virtual counter, or the x86_64 TSC converted with the factors
/// the kernel published.
#[inline(always)]
fn counter() -> u64 {
    let t: u64;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack));
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (lo, hi): (u32, u32);
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
        let tsc = ((hi as u64) << 32) | lo as u64;
        let rd = |off: usize| unsafe { core::ptr::read_volatile((VDSO_USER_BASE + off) as *const u64) };
        let (base, ticks, mult) = (
            rd(azos_abi::vdso::VDSO_COUNTER_BASE_OFFSET),
            rd(azos_abi::vdso::VDSO_TICKS_BASE_OFFSET),
            rd(azos_abi::vdso::VDSO_COUNTER_MULT_OFFSET),
        );
        t = ticks.wrapping_add(((tsc.wrapping_sub(base) as u128 * mult as u128) >> 32) as u64);
    }
    t
}

/// `DOMAIN_UPTIME` as a trap: the counter, where ring 3 may not read it.
#[cfg(not(target_arch = "aarch64"))]
fn counter_trap() -> u64 {
    invoke(inv::DOMAIN_SELF.as_raw(), inv::DOMAIN_UPTIME, [0; 4]).0 as u64
}

/// Exact monotonic nanoseconds since boot, 0 if the page publishes no
/// timebase (no vDSO mapped). AArch64 reads the virtual counter always (the
/// vDSO flag is a RISC-V statement); the others read it only where the kernel
/// says it is native.
pub fn now_ns() -> u64 {
    let hz = page_u64(32);
    if hz == 0 {
        return 0;
    }
    #[cfg(target_arch = "aarch64")]
    let ticks = counter();
    #[cfg(not(target_arch = "aarch64"))]
    let ticks = if rdtime_is_native(page_u32(0), page_u32(12)) { counter() } else { counter_trap() };
    azos_abi::time::ticks_to_ns(ticks, hz)
}

/// Block until the monotonic clock reads `deadline_ns` (returns at once if it
/// already does).
pub fn sleep_until(deadline_ns: u64) {
    // SAFETY: a plain call; the result (slept, overrun, refused) changes
    // nothing the caller can do.
    unsafe { syscall6(SYS_SLEEP_UNTIL, deadline_ns, 0, 0, 0, 0, 0) };
}

/// Give the CPU up.
pub fn yield_now() {
    // SAFETY: a plain call.
    unsafe { syscall6(SYS_YIELD, 0, 0, 0, 0, 0, 0) };
}
