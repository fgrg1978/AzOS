// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Machine check (#MC): CR4.MCE on every CPU, and the record the handler
//! leaves. With CR4.MCE clear a machine check is a shutdown, so the handler
//! (`kernel/src/entry/x86_64/trap.rs`) would never run.
//!
//! The record is a handful of atomics: the handler runs on its own IST stack
//! with IF and NMIs in whatever state the interrupted code had, so it can
//! take no lock and allocate nothing (Linux's `do_machine_check` is
//! NMI-like for the same reason). Bank decoding, CMCI and page retirement are
//! not here; the handler stops the actuators, records and halts.

use core::sync::atomic::{AtomicU64, Ordering};

/// CR4 bit 6.
pub const CR4_MCE: u64 = 1 << 6;
/// IA32_MCG_STATUS: RIPV (bit 0), EIPV (bit 1), MCIP (bit 2).
pub const MSR_MCG_STATUS: u32 = 0x17a;
/// CPUID.1:EDX bit 7 (MCE) and bit 14 (MCA).
const CPUID_MCE: u32 = 1 << 7;
const CPUID_MCA: u32 = 1 << 14;

/// Does the CPU report machine checks (CPUID.1:EDX.MCE)?
pub const fn has_mce(edx: u32) -> bool {
    edx & CPUID_MCE != 0
}

/// Does it have the MCG_STATUS register (both MCE and MCA)?
pub const fn has_mcg_status(edx: u32) -> bool {
    edx & (CPUID_MCE | CPUID_MCA) == CPUID_MCE | CPUID_MCA
}

/// What the last machine check was, as the handler saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Seen {
    pub count: u64,
    pub cpu: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub mcg_status: u64,
}

/// The lock-free record. Written by the handler of whichever CPU takes the
/// check; a second check on another CPU overwrites the fields, `count` says
/// how many came.
pub struct Record {
    count: AtomicU64,
    cpu: AtomicU64,
    rip: AtomicU64,
    cs: AtomicU64,
    rflags: AtomicU64,
    mcg_status: AtomicU64,
}

impl Record {
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            cpu: AtomicU64::new(0),
            rip: AtomicU64::new(0),
            cs: AtomicU64::new(0),
            rflags: AtomicU64::new(0),
            mcg_status: AtomicU64::new(0),
        }
    }

    /// Leave a check: the fields first, the count last (the reader of a
    /// non-zero count sees the fields of that check or of a later one).
    /// Returns the new count.
    pub fn note(&self, cpu: u64, rip: u64, cs: u64, rflags: u64, mcg_status: u64) -> u64 {
        self.cpu.store(cpu, Ordering::Relaxed);
        self.rip.store(rip, Ordering::Relaxed);
        self.cs.store(cs, Ordering::Relaxed);
        self.rflags.store(rflags, Ordering::Relaxed);
        self.mcg_status.store(mcg_status, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn seen(&self) -> Seen {
        let count = self.count.load(Ordering::Acquire);
        Seen {
            count,
            cpu: self.cpu.load(Ordering::Relaxed),
            rip: self.rip.load(Ordering::Relaxed),
            cs: self.cs.load(Ordering::Relaxed),
            rflags: self.rflags.load(Ordering::Relaxed),
            mcg_status: self.mcg_status.load(Ordering::Relaxed),
        }
    }
}

impl Default for Record {
    fn default() -> Self {
        Self::new()
    }
}

/// The machine checks this kernel has taken.
pub static RECORD: Record = Record::new();

/// Set CR4.MCE on this CPU when it has the feature; whether it is set after.
/// Every CPU runs it once its IDT (with the #MC gate on its own IST stack) is
/// loaded, whichever boot protocol brought it up.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn enable_this_cpu() -> bool {
    if !has_mce(crate::platform_impl::cpuid(1, 0).3) {
        return false;
    }
    let cr4 = crate::mmu::cpu::read_cr4();
    if cr4 & CR4_MCE == 0 {
        // SAFETY: CPL 0; CR4.MCE is architectural when CPUID.1:EDX.MCE.
        unsafe { core::arch::asm!("mov cr4, {}", in(reg) cr4 | CR4_MCE, options(nostack, preserves_flags)) };
    }
    crate::mmu::cpu::read_cr4() & CR4_MCE != 0
}

/// IA32_MCG_STATUS, or 0 on a CPU without it (a read of an absent MSR is a
/// #GP, which must not happen inside the #MC handler).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn mcg_status() -> u64 {
    if has_mcg_status(crate::platform_impl::cpuid(1, 0).3) {
        crate::cpu::rdmsr(MSR_MCG_STATUS)
    } else {
        0
    }
}
