// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 [`SpinWait`]: LSE `CAS`/`CASA`/`CASL`/`CASAL` for the CAS
//! (Kconfig A64_LSE), `SEVL`; `WFE`; `LDAXR`; `WFE` for the wait hint
//! (Armv8.0, every core), `ISB` for `cpu_relax` (the trait's default,
//! `core::hint::spin_loop`). The CAS fallback is the trait's provided
//! body: the compiler's LDAXR/STLXR loop at Armv8.0 (this kernel has no
//! outlined atomics), CAS itself when A64_LSE is `require` (+lse).
//!
//! Probe: ID_AA64ISAR0_EL1.Atomic (`features::read_id_regs`), which the
//! architecture defines, so there is no execution probe: a wrong claim
//! (the `spin-ext-claim` canary on a Cortex-A53) is an Undefined
//! Instruction exception at the first lock after [`select`]. Until
//! [`select`] runs every CAS takes LL/SC; the two may meet on one word.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use azos_arch_api::isa::{aarch64 as policy, ExtPolicy};
use azos_arch_api::{CasOrder, SpinWait};

/// The probe's verdict (`probe` only; `n`/`require` never read it).
static LSE_ON: AtomicBool = AtomicBool::new(false);

/// LSE CAS in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn lse_on() -> bool {
    match policy::LSE {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => LSE_ON.load(Ordering::Relaxed),
    }
}

/// Boot, the boot CPU, before the secondaries: `lse` is the ID register's
/// answer (or a canary's forced claim). Returns what the lock paths use.
pub fn select(lse: bool) -> bool {
    let on = policy::LSE.gate(lse);
    LSE_ON.store(on, Ordering::Relaxed);
    lse_on()
}

/// `cas{,a,l,al}` (32-bit `w` registers, or 64-bit `x`): the first
/// register holds the compare value in and the old value out. The asm is
/// `cfg(target_arch = "aarch64")` (the crate's rule, lib.rs): on the
/// workspace's other targets every method is the trait's fallback.
#[cfg(target_arch = "aarch64")]
macro_rules! cas {
    ($insn:literal, $ty:ty, $a:expr, $cur:expr, $new:expr) => {{
        let mut old: $ty = $cur;
        // SAFETY: `$a` is a valid, aligned atomic word (a reference); the
        // instruction is only reached when LSE is in use (`lse_on`).
        unsafe {
            core::arch::asm!(
                ".arch_extension lse",
                $insn,
                old = inout(reg) old,
                new = in(reg) $new,
                addr = in(reg) $a,
                options(nostack, preserves_flags),
            );
        }
        old
    }};
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn cas_w(a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> u32 {
    let p = a.as_ptr();
    match order {
        CasOrder::Relaxed => cas!("cas {old:w}, {new:w}, [{addr}]", u32, p, current, new),
        CasOrder::Acquire => cas!("casa {old:w}, {new:w}, [{addr}]", u32, p, current, new),
        CasOrder::Release => cas!("casl {old:w}, {new:w}, [{addr}]", u32, p, current, new),
        CasOrder::AcqRel => cas!("casal {old:w}, {new:w}, [{addr}]", u32, p, current, new),
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn cas_x(a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> u64 {
    let p = a.as_ptr();
    match order {
        CasOrder::Relaxed => cas!("cas {old:x}, {new:x}, [{addr}]", u64, p, current, new),
        CasOrder::Acquire => cas!("casa {old:x}, {new:x}, [{addr}]", u64, p, current, new),
        CasOrder::Release => cas!("casl {old:x}, {new:x}, [{addr}]", u64, p, current, new),
        CasOrder::AcqRel => cas!("casal {old:x}, {new:x}, [{addr}]", u64, p, current, new),
    }
}

impl SpinWait for crate::api_impl::Aarch64 {
    #[inline(always)]
    fn cas32(&self, a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> Result<u32, u32> {
        #[cfg(target_arch = "aarch64")]
        if lse_on() {
            let old = cas_w(a, current, new, order);
            return if old == current { Ok(old) } else { Err(old) };
        }
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    #[inline(always)]
    fn cas64(&self, a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> Result<u64, u64> {
        #[cfg(target_arch = "aarch64")]
        if lse_on() {
            let old = cas_x(a, current, new, order);
            return if old == current { Ok(old) } else { Err(old) };
        }
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    /// `SEVL; WFE` empties the event register, `LDAXR` arms the exclusive
    /// monitor on the word, and the second `WFE` sleeps until another
    /// observer's store clears the monitor (an event) or an interrupt is
    /// pending, masked or not. Linux arm64's `__cmpwait`.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn wait_hint32(&self, a: &AtomicU32, expected: u32) {
        // SAFETY: `a` is a valid, aligned word; the monitor left armed is
        // harmless (the next exclusive or exception clears it).
        unsafe {
            core::arch::asm!(
                "sevl",
                "wfe",
                "ldaxr {t:w}, [{addr}]",
                "eor {t:w}, {t:w}, {e:w}",
                "cbnz {t:w}, 2f",
                "wfe",
                "2:",
                addr = in(reg) a.as_ptr(),
                e = in(reg) expected,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn wait_hint64(&self, a: &AtomicU64, expected: u64) {
        // SAFETY: as `wait_hint32`.
        unsafe {
            core::arch::asm!(
                "sevl",
                "wfe",
                "ldaxr {t:x}, [{addr}]",
                "eor {t:x}, {t:x}, {e:x}",
                "cbnz {t:x}, 2f",
                "wfe",
                "2:",
                addr = in(reg) a.as_ptr(),
                e = in(reg) expected,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
}
