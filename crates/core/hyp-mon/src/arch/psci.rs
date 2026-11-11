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
use super::mmu::HYP_PE_SLOTS;
use super::ptcheck::affinity;

// PSCI / SMCCC function ids (the 32- and 64-bit forms the kernel issues).
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_CPU_OFF: u64 = 0x8400_0002;
/// `power_state.StateType` (bit 16) of `CPU_SUSPEND`: a power-down state.
const POWER_DOWN: u64 = 1 << 16;
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


#[inline]
fn reg(regs: *mut u64, n: usize) -> u64 {
    unsafe { *regs.add(n) }
}
#[inline]
fn set(regs: *mut u64, n: usize, v: u64) {
    unsafe { *regs.add(n) = v };
}

fn mpidr() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) v) };
    v
}

fn this_pe() -> u32 {
    (mpidr() & 0xff) as u32
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
        PSCI_CPU_SUSPEND_64 | PSCI_SYSTEM_SUSPEND_64 => {
            // A power-down loses the core's state and brings it back through the entry: it pins again.
            if id == PSCI_SYSTEM_SUSPEND_64 || reg(regs, 1) & POWER_DOWN != 0 {
                super::pin::unpin_this_pe();
            }
            suspend(regs, id == PSCI_SYSTEM_SUSPEND_64)
        }
        PSCI_CPU_OFF => {
            super::pin::unpin_this_pe();
            forward(regs)
        }
        _ if allowed(id) => forward(regs),
        _ => {
            crate::record(Kind::CallRefused, this_pe(), id, id, 0);
            set(regs, 0, NOT_SUPPORTED as u64);
        }
    }
}

/// `CPU_ON(target, entry, context)`: substitute the entry with the monitor's
/// secondary entry and keep the kernel's context for the target's slot (keyed
/// by its full affinity), so the PE comes up at EL2 and the monitor resumes it
/// at the one legal EL1 entry (F4 locks that entry; before the lock the first
/// requested entry is taken as legal).
fn cpu_on(regs: *mut u64) {
    let target = reg(regs, 1);
    let entry = reg(regs, 2);
    let ctx = reg(regs, 3);
    let legal = HYP.legal_entry_or_set(entry);
    if entry != legal || entry == 0 {
        crate::record(Kind::EntryRefused, this_pe(), entry, target, 0);
        set(regs, 0, DENIED as u64);
        return;
    }
    let Some(slot) = HYP_PE_SLOTS.record(affinity(target), ctx) else {
        crate::record(Kind::CallRefused, this_pe(), PSCI_CPU_ON_64, target, 0);
        set(regs, 0, DENIED as u64);
        return;
    };
    // Substitute: the PE powers on at the monitor's secondary entry with its
    // slot as the context, and the monitor resumes it at the legal entry.
    set(regs, 2, secondary_entry_pa());
    set(regs, 3, slot as u64);
    forward(regs);
}

/// `CPU_SUSPEND(state, entry, ctx)` / `SYSTEM_SUSPEND(entry, ctx)`: a
/// power-down comes back through the monitor, so the entry is substituted and
/// the kernel's context is kept under this PE's own slot (the slot, not the
/// kernel's context, is what firmware hands back in x0). The two calls carry
/// the entry one register apart.
fn suspend(regs: *mut u64, system: bool) {
    let (ei, ci) = if system { (1, 2) } else { (2, 3) };
    let entry = reg(regs, ei);
    if entry != 0 {
        let legal = HYP.legal_entry_or_set(entry);
        if entry != legal {
            crate::record(Kind::EntryRefused, this_pe(), entry, 0, 0);
            set(regs, 0, DENIED as u64);
            return;
        }
        let Some(slot) = HYP_PE_SLOTS.record(affinity(mpidr()), reg(regs, ci)) else {
            set(regs, 0, DENIED as u64);
            return;
        };
        set(regs, ei, secondary_entry_pa());
        set(regs, ci, slot as u64);
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

/// The kernel entry a PE that entered through the substituted `CPU_ON` or
/// resume path continues at: always the one legal entry, whatever was asked.
/// Called from `_hyp_secondary_entry`.
#[no_mangle]
pub extern "C" fn hyp_secondary_resume(_slot: u64) -> u64 {
    // Before the core runs the kernel: the locked kernel-half registers, writes to them trapped.
    super::pin::unpin_this_pe();
    super::pt::enter_pe();
    HYP.legal_entry()
}

/// The context the kernel asked to find in x0 (its hart id), by slot.
#[no_mangle]
pub extern "C" fn hyp_secondary_ctx(slot: u64) -> u64 {
    HYP_PE_SLOTS.ctx_of(slot as usize)
}
