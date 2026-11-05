// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 hooks of the masked-window tracer (`azos_arch_api::lat`).
//!
//! Compiled only with `lat-trace`. Same contract as the RISC-V and aarch64
//! modules of the same name: the CPU id (`%gs:0`) and the clock
//! (`timer::now_ticks`, the TSC in `TIMER_FREQ` ticks) are read here, the
//! caller supplies only a site. Masking inside this module is raw `cli`/`sti`,
//! never the hooked `Interrupts::disable_all`.
//!
//! Polarity: `RFLAGS.IF` SET means interrupts are enabled, and an interrupt
//! or exception frame carries the interrupted context's `RFLAGS` at the same
//! bit position (bit 9).

use core::panic::Location;

/// The ISA-neutral bookkeeping, reachable through the `azos_arch` facade.
pub use azos_arch_api::lat;
use azos_arch_api::lat::Kind;

use crate::cpu::{cli, rflags, sti, RFLAGS_IF};

/// The site value the bookkeeping stores for a `Location`.
#[inline(always)]
pub fn site(loc: &'static Location<'static>) -> usize {
    loc as *const Location<'static> as usize
}

#[inline(always)]
fn now() -> u64 {
    crate::timer::now_ticks()
}

#[inline(always)]
fn hart() -> usize {
    crate::cpu::percpu_id()
}

/// Back to the interrupt state `flags` holds, without closing a window.
#[inline(always)]
fn put_if(flags: u64) {
    if flags & RFLAGS_IF != 0 {
        sti();
    }
}

/// Interrupts just went from enabled to masked at `loc`.
#[inline(never)]
pub fn irq_off(loc: &'static Location<'static>) {
    lat::open(Kind::Irq, hart(), now(), site(loc));
}

/// Interrupts are about to go from masked to enabled at `loc`. Called while
/// still masked.
#[inline(never)]
pub fn irq_on(loc: &'static Location<'static>) {
    lat::close(Kind::Irq, hart(), now(), site(loc));
}

/// `Interrupts::restore(prev)` is about to run from a guard taken at `loc`:
/// close the window now, with `loc` as its end, if the restore re-enables.
#[inline]
pub fn irq_restore_at(prev: u64, loc: &'static Location<'static>) {
    if prev & RFLAGS_IF != 0 && rflags() & RFLAGS_IF == 0 {
        irq_on(loc);
    }
}

/// Exception or interrupt entry. `frame_rflags` is the `RFLAGS` the trap
/// saved: with `IF` set the interrupted context had interrupts enabled, so
/// the gate (which cleared `IF`) opened a window.
#[inline(never)]
pub fn trap_enter(frame_rflags: u64, loc: &'static Location<'static>) {
    if frame_rflags & RFLAGS_IF != 0 {
        lat::open(Kind::Irq, hart(), now(), site(loc));
    }
}

/// Trap exit towards a context whose `RFLAGS` is `frame_rflags`: if it runs
/// with interrupts enabled, the window ends here (the `iretq` is a few
/// instructions away).
#[inline(never)]
pub fn trap_exit(frame_rflags: u64, loc: &'static Location<'static>) {
    if frame_rflags & RFLAGS_IF != 0 {
        lat::close(Kind::Irq, hart(), now(), site(loc));
    }
}

/// Interrupt-path exit: an interrupt is only taken from a context with
/// interrupts enabled, so the `iretq` always re-enables.
#[inline(never)]
pub fn irq_exit(loc: &'static Location<'static>) {
    lat::close(Kind::Irq, hart(), now(), site(loc));
}

/// Preemption just went from enabled to disabled at `loc`.
#[inline(never)]
pub fn preempt_off(loc: &'static Location<'static>) {
    let f = rflags();
    cli();
    lat::open(Kind::Preempt, hart(), now(), site(loc));
    put_if(f);
}

/// Preemption just went from disabled to enabled; the guard that ended the
/// window was taken at `loc`.
#[inline(never)]
pub fn preempt_on(loc: &'static Location<'static>) {
    let f = rflags();
    cli();
    lat::close(Kind::Preempt, hart(), now(), site(loc));
    put_if(f);
}
