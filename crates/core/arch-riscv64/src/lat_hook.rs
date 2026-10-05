// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V hooks of the masked-window tracer (`azos_arch_api::lat`).
//!
//! Compiled only with `lat-trace`. Every function here reads the hart id
//! (`tp`) and the `time` CSR itself and passes them to the ISA-neutral
//! bookkeeping, so a site is the only thing a caller supplies.
//!
//! Interrupt masking inside this module is raw `sstatus` access, never
//! `Interrupts::disable_all`: the latter is hooked, and the tracer must not
//! open windows on its own behalf.

use core::panic::Location;

/// The ISA-neutral bookkeeping, reachable through the `azos_arch` facade.
pub use azos_arch_api::lat;
use azos_arch_api::lat::Kind;

use crate::csr::{read_sstatus, write_sstatus, SSTATUS_SIE, SSTATUS_SPIE};

/// The site value the bookkeeping stores for a `Location`.
#[inline(always)]
pub fn site(loc: &'static Location<'static>) -> usize {
    loc as *const Location<'static> as usize
}

#[inline(always)]
fn now() -> u64 {
    crate::cpu::now_ticks()
}

#[inline(always)]
fn hart() -> usize {
    crate::cpu::hart_id()
}

/// Interrupts just went from enabled to masked at `loc`.
#[inline(never)]
pub fn irq_off(loc: &'static Location<'static>) {
    lat::open(Kind::Irq, hart(), now(), site(loc));
}

/// Interrupts are about to go from masked to enabled at `loc`. Called while
/// still masked, so the bookkeeping is not interruptible.
#[inline(never)]
pub fn irq_on(loc: &'static Location<'static>) {
    lat::close(Kind::Irq, hart(), now(), site(loc));
}

/// `Interrupts::restore(prev)` is about to run from a guard taken at `loc`:
/// close the window now, with `loc` as its end, if the restore re-enables.
#[inline]
pub fn irq_restore_at(prev: u64, loc: &'static Location<'static>) {
    if (prev as usize) & SSTATUS_SIE != 0 && read_sstatus() & SSTATUS_SIE == 0 {
        irq_on(loc);
    }
}

/// Trap entry. `frame_sstatus` is the `sstatus` the trap saved: `SPIE` says
/// whether the interrupted context had interrupts enabled. If it did, the
/// trap itself opened a window (the hardware cleared `SIE`).
#[inline(never)]
pub fn trap_enter(frame_sstatus: usize, loc: &'static Location<'static>) {
    if frame_sstatus & SSTATUS_SPIE != 0 {
        lat::open(Kind::Irq, hart(), now(), site(loc));
    }
}

/// Trap exit towards a context whose `sstatus` is `frame_sstatus`: if it
/// runs with interrupts enabled, the window ends here (the `sret` is a few
/// instructions away).
#[inline(never)]
pub fn trap_exit(frame_sstatus: usize, loc: &'static Location<'static>) {
    if frame_sstatus & SSTATUS_SPIE != 0 {
        lat::close(Kind::Irq, hart(), now(), site(loc));
    }
}

/// Interrupt-path exit (`trap_resched`): an interrupt is only ever taken from
/// a context with interrupts enabled, so the return always re-enables.
#[inline(never)]
pub fn irq_exit(loc: &'static Location<'static>) {
    lat::close(Kind::Irq, hart(), now(), site(loc));
}

/// Preemption just went from enabled to disabled at `loc`.
#[inline(never)]
pub fn preempt_off(loc: &'static Location<'static>) {
    let s = read_sstatus();
    write_sstatus(s & !SSTATUS_SIE);
    lat::open(Kind::Preempt, hart(), now(), site(loc));
    write_sstatus((read_sstatus() & !SSTATUS_SIE) | (s & SSTATUS_SIE));
}

/// Preemption just went from disabled to enabled; the guard that ended the
/// window was taken at `loc`.
#[inline(never)]
pub fn preempt_on(loc: &'static Location<'static>) {
    let s = read_sstatus();
    write_sstatus(s & !SSTATUS_SIE);
    lat::close(Kind::Preempt, hart(), now(), site(loc));
    write_sstatus((read_sstatus() & !SSTATUS_SIE) | (s & SSTATUS_SIE));
}
