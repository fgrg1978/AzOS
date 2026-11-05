// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The synchronous-trap dispatch for traps taken from EL1: the monitor calls
//! (HVC on the ABI's id range), the trapped SMC/PSCI path (F3), and the host
//! stage-2 fault path (F2). `regs` is x0..x30 as the vector stub saved them.

use crate::state::HYP;
use azos_hyp_api::{
    is_monitor_call, Kind, ABI_VERSION, CALL_PROBE, CALL_VIOLATION_READ, EMPTY, INVALID, OK,
};

const EC_HVC64: u64 = 0x16;
const EC_SMC64: u64 = 0x17;
const EC_SYSREG: u64 = 0x18;
const EC_IABORT_LOWER: u64 = 0x20;
const EC_DABORT_LOWER: u64 = 0x24;

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

pub fn handle(regs: *mut u64) {
    let esr: u64;
    unsafe { core::arch::asm!("mrs {}, ESR_EL2", out(reg) esr) };
    let ec = (esr >> 26) & 0x3f;
    match ec {
        EC_HVC64 => hvc(regs),
        EC_SMC64 => super::psci::smc(regs, esr),
        EC_SYSREG => super::pin::trap(regs, esr),
        EC_IABORT_LOWER | EC_DABORT_LOWER => super::s2::fault(regs, esr, ec == EC_IABORT_LOWER),
        _ => {
            let elr: u64;
            unsafe { core::arch::asm!("mrs {}, ELR_EL2", out(reg) elr) };
            crate::record(Kind::UnexpectedTrap, this_pe(), esr, elr, 0);
        }
    }
}

fn hvc(regs: *mut u64) {
    let id = reg(regs, 0);
    if !is_monitor_call(id) {
        // Not a monitor call: QEMU virt's PSCI conduit is HVC, so a PSCI or
        // SMCCC function id is filtered and forwarded like a trapped SMC.
        super::psci::hvc_call(regs);
        return;
    }
    match id {
        CALL_PROBE => {
            set(regs, 0, OK as u64);
            set(regs, 1, ABI_VERSION);
            set(regs, 2, HYP.invariants());
            set(regs, 3, crate::PES_UP.load(core::sync::atomic::Ordering::Acquire) as u64);
        }
        CALL_VIOLATION_READ => {
            let cursor = reg(regs, 1);
            match HYP.ring_read(cursor) {
                Some((next, v)) => {
                    set(regs, 0, OK as u64);
                    set(regs, 1, next);
                    set(regs, 2, v.word1());
                    set(regs, 3, v.syndrome);
                    set(regs, 4, v.addr);
                    set(regs, 5, v.aux);
                }
                None => set(regs, 0, EMPTY as u64),
            }
        }
        azos_hyp_api::CALL_LOCK_KERNEL_IMAGE => set(regs, 0, super::s2::lock_kernel_image(reg(regs, 1)) as u64),
        azos_hyp_api::CALL_LOCK_RO_DATA => set(regs, 0, super::s2::lock_ro_data() as u64),
        azos_hyp_api::CALL_TEXT_PATCH => {
            let r = super::s2::text_patch(reg(regs, 1), reg(regs, 2));
            if r != OK { crate::record(Kind::CallRefused, this_pe(), azos_hyp_api::CALL_TEXT_PATCH, reg(regs, 1), reg(regs, 2)); }
            set(regs, 0, r as u64)
        }
        azos_hyp_api::CALL_PIN => {
            let (r, mode, pinned) = super::pin::pin();
            if r != OK { crate::record(Kind::CallRefused, this_pe(), azos_hyp_api::CALL_PIN, 0, 0); }
            set(regs, 0, r as u64);
            set(regs, 1, mode);
            set(regs, 2, pinned);
        }
        azos_hyp_api::CALL_GUARD_PAGES => {
            let r = super::s2::guard_pages(reg(regs, 1), reg(regs, 2));
            if r != OK { crate::record(Kind::CallRefused, this_pe(), azos_hyp_api::CALL_GUARD_PAGES, reg(regs, 1), reg(regs, 2)); }
            set(regs, 0, r as u64)
        }
        _ => set(regs, 0, INVALID as u64),
    }
}
