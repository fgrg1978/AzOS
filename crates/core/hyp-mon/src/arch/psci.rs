// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PSCI and SMC through the monitor (F3).
//!
//! With `HCR_EL2.TSC` set, every SMC from EL1 traps here; an HVC on a PSCI
//! function id lands here too (QEMU virt's conduit is HVC). The monitor runs
//! an allow list, substitutes the entry point of `CPU_ON`/`CPU_SUSPEND`/
//! `SYSTEM_SUSPEND` with its own so a powered-on or resumed PE re-enters the
//! monitor before EL1, and refuses a spin-table board and a no-conduit SMP
//! image. Anything off the list is refused and recorded.
//!
//! The forwarding conduit below the monitor is `smc #0`. On a machine with no
//! EL3 firmware (QEMU virt without `secure=on`) the provider of PSCI below EL2
//! is the open question flagged in the design; it is where the rows, when they
//! run, prove or disprove the path.

use crate::state::HYP;
use azos_hyp_api::{Kind, DENIED, NOT_SUPPORTED};
use core::sync::atomic::{AtomicU64, Ordering};

// PSCI / SMCCC function ids (the 32- and 64-bit forms the kernel issues).
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_CPU_OFF: u64 = 0x8400_0002;
const PSCI_CPU_ON_64: u64 = 0xC400_0003;
const PSCI_AFFINITY_INFO_64: u64 = 0xC400_0004;
const PSCI_CPU_SUSPEND_64: u64 = 0xC400_0001;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_SYSTEM_SUSPEND_64: u64 = 0xC400_000E;
const PSCI_FEATURES: u64 = 0x8400_000A;
const SMCCC_VERSION: u64 = 0x8000_0000;
const SMCCC_ARCH_FEATURES: u64 = 0x8000_0001;
const SMCCC_ARCH_WORKAROUND_1: u64 = 0x8000_8000;
const SMCCC_ARCH_WORKAROUND_2: u64 = 0x8000_7FFF;
const SMCCC_ARCH_WORKAROUND_3: u64 = 0x8000_3FFF;

/// Per-target kernel entry/context, stored on `CPU_ON` so the substituted
/// secondary entry can resume the kernel where it asked.
static TARGET_ENTRY: [AtomicU64; super::MAX_PES] = [const { AtomicU64::new(0) }; super::MAX_PES];
static TARGET_CTX: [AtomicU64; super::MAX_PES] = [const { AtomicU64::new(0) }; super::MAX_PES];

#[inline]
fn reg(regs: *mut u64, n: usize) -> u64 {
    unsafe { *regs.add(n) }
}
#[inline]
fn set(regs: *mut u64, n: usize, v: u64) {
    unsafe { *regs.add(n) = v };
}

fn this_pe() -> u32 {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr) };
    (mpidr & 0xff) as u32
}

fn allowed(id: u64) -> bool {
    matches!(
        id,
        PSCI_VERSION
            | PSCI_FEATURES
            | PSCI_CPU_OFF
            | PSCI_AFFINITY_INFO_64
            | PSCI_SYSTEM_OFF
            | PSCI_SYSTEM_RESET
            | SMCCC_VERSION
            | SMCCC_ARCH_FEATURES
            | SMCCC_ARCH_WORKAROUND_1
            | SMCCC_ARCH_WORKAROUND_2
            | SMCCC_ARCH_WORKAROUND_3
    )
}

/// A trapped SMC (EC 0x17). `HCR_EL2.TSC` makes this the only SMC path; the
/// `hyp-tsc-off-canary` clears TSC in F3's init, so no SMC traps and R3 goes
/// red. The handler advances ELR past the `smc` after it services it.
pub fn smc(regs: *mut u64, _esr: u64) {
    dispatch(regs, true);
    // Skip the trapped `smc #0` so EL1 resumes after it.
    let elr: u64;
    unsafe { core::arch::asm!("mrs {}, ELR_EL2", out(reg) elr) };
    unsafe { core::arch::asm!("msr ELR_EL2, {}", in(reg) elr + 4) };
}

/// A PSCI call arriving as an HVC (the non-monitor HVC from `sync::hvc`): the
/// ELR already points past the `hvc`, so no adjustment.
pub fn hvc_call(regs: *mut u64) {
    dispatch(regs, false);
}

fn dispatch(regs: *mut u64, _trapped_smc: bool) {
    let id = reg(regs, 0);
    match id {
        PSCI_CPU_ON_64 => cpu_on(regs),
        PSCI_CPU_SUSPEND_64 | PSCI_SYSTEM_SUSPEND_64 => suspend(regs),
        _ if allowed(id) => forward(regs),
        _ => {
            crate::record(Kind::CallRefused, this_pe(), id, id, 0);
            set(regs, 0, NOT_SUPPORTED as u64);
        }
    }
}

/// `CPU_ON(target, entry, context)`: substitute the entry with the monitor's
/// secondary entry and store the kernel's own entry/context, so the PE comes
/// up at EL2 and the monitor resumes it at the one legal EL1 entry (F4 locks
/// that entry; before the lock the first requested entry is taken as legal).
fn cpu_on(regs: *mut u64) {
    let target = reg(regs, 1);
    let entry = reg(regs, 2);
    let ctx = reg(regs, 3);
    let legal = HYP.legal_entry_or_set(entry);
    if entry != legal {
        crate::record(Kind::EntryRefused, this_pe(), entry, target, 0);
        set(regs, 0, DENIED as u64);
        return;
    }
    let idx = (target & 0xff) as usize;
    if idx >= super::MAX_PES {
        set(regs, 0, DENIED as u64);
        return;
    }
    TARGET_ENTRY[idx].store(entry, Ordering::Release);
    TARGET_CTX[idx].store(ctx, Ordering::Release);
    // Substitute: the PE powers on at the monitor's secondary entry with the
    // target index as its context, and the monitor resumes it at `entry`.
    let sec = secondary_entry_pa();
    set(regs, 2, sec);
    set(regs, 3, idx as u64);
    forward(regs);
}

fn suspend(regs: *mut u64) {
    // Same entry substitution as CPU_ON: a resumed PE must re-enter the monitor.
    let entry = reg(regs, 2);
    if entry != 0 {
        let legal = HYP.legal_entry_or_set(entry);
        if entry != legal {
            crate::record(Kind::EntryRefused, this_pe(), entry, 0, 0);
            set(regs, 0, DENIED as u64);
            return;
        }
        set(regs, 2, secondary_entry_pa());
    }
    forward(regs);
}

/// Forward the (possibly rewritten) call to the conduit below via `smc #0`.
fn forward(regs: *mut u64) {
    let mut x0 = reg(regs, 0);
    let x1 = reg(regs, 1);
    let x2 = reg(regs, 2);
    let x3 = reg(regs, 3);
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") x0,
            inout("x1") x1 => _,
            inout("x2") x2 => _,
            inout("x3") x3 => _,
        );
    }
    set(regs, 0, x0);
}

fn secondary_entry_pa() -> u64 {
    extern "C" {
        fn _hyp_secondary_entry();
    }
    _hyp_secondary_entry as *const () as usize as u64
}

/// Resolve the kernel entry/context for a secondary that entered the monitor
/// via the substituted `CPU_ON`. Called from `_hyp_secondary_entry`.
#[no_mangle]
pub extern "C" fn hyp_secondary_resume(idx: u64) -> u64 {
    let i = (idx as usize).min(super::MAX_PES - 1);
    // Before the core runs the kernel: the locked kernel-half registers, writes to them trapped.
    super::pt::enter_pe();
    // The stub reads x0 back from here as the kernel entry; context is placed
    // into the saved frame by the stub.
    TARGET_ENTRY[i].load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn hyp_secondary_ctx(idx: u64) -> u64 {
    let i = (idx as usize).min(super::MAX_PES - 1);
    TARGET_CTX[i].load(Ordering::Acquire)
}
