// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The AzOS resident monitor on aarch64 (VIRT_SPLIT).
//!
//! It is entered at EL2 from the kernel's boot trampoline, on every PE, before
//! EL1 runs (`arch/aarch64/src/mmu/boot.rs`). It brings up its own EL2 stage-1
//! (an identity map), host stage-2 (F2), and the PSCI/SMC filter (F3), then
//! `eret`s the caller into EL1. It runs on its own stack and table, never
//! dereferences a kernel VA, and links against nothing but the ISA-neutral
//! ABI (`azos_hyp_api`): a reference to a kernel symbol is a link error.
//!
//! Position-independent (built `-C relocation-model=pic`): the kernel's `.hyp`
//! section chooses the physical address and the monitor forms every address
//! PC-relative, so EL2 stage-1 is a 1:1 identity map and the running VA equals
//! that PA.
#![no_std]
#![no_main]
#![allow(dead_code)]

use azos_hyp_api::{Kind, Ring, Violation};
use core::sync::atomic::{AtomicU32, Ordering};

mod arch;
mod state;

use state::HYP;

/// A monitor panic parks every PE: it fails closed.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// How many PEs have completed `_hyp_entry`. Reported by `probe`.
pub(crate) static PES_UP: AtomicU32 = AtomicU32::new(0);

/// Called from `_hyp_entry` once EL2 stage-1 is on, before the `eret` to EL1.
/// `primary` is set for the PE that built the shared tables.
#[no_mangle]
pub extern "C" fn hyp_cpu_up(_hart: u64, primary: u64) {
    if primary != 0 {
        HYP.init_once();
    }
    PES_UP.fetch_add(1, Ordering::AcqRel);
}

/// The synchronous-exception handler for traps from EL1 (and the monitor's own
/// faults). `regs` points at x0..x17 saved by the vector stub; the handler may
/// rewrite x0..x3 for the return values. Returns to the trapping PC via `eret`.
#[no_mangle]
pub extern "C" fn hyp_sync_from_el1(regs: *mut u64) {
    arch::sync::handle(regs);
}

pub(crate) fn record(kind: Kind, pe: u32, syndrome: u64, addr: u64, aux: u64) {
    HYP.ring_push(Violation { kind: kind as u32, pe, syndrome, addr, aux });
}

// Pull the ring type into the binary so a monitor with no violations still
// links the ABI's ring (and the host tests cover its cursor rules).
const _: fn() = || {
    let _r: Ring<1> = Ring::new();
};
