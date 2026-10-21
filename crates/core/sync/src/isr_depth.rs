// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-hart "am I inside an interrupt handler?" depth.
//!
//! Owner decision 2026-09-20 (security scan, unit 4): **detect** a lock taken
//! from interrupt context rather than mask interrupts against it.
//!
//! # Why this exists and not `sstatus.SIE`
//!
//! The obvious probe is wrong, and it was tried: RISC-V hardware clears
//! `sstatus.SIE` on **every** trap entry, exception as well as interrupt. So
//! "SIE is clear" is the normal state of every syscall handler in this kernel,
//! and a detector built on it reported 149, 16 and 162 "violations" on a clean
//! boot — one per IPC call, none of them an interrupt. It measured the
//! instrument, not the hazard.
//!
//! Only the trap handler knows which arm it took, so only the trap handler can
//! answer the question. `enter()`/`exit()` bracket the interrupt arm; anything
//! that wants to know asks [`in_isr`].
//!
//! # Why a plain per-hart cell and not an atomic counter
//!
//! Only the hart itself writes its own slot, and only between trap entry and
//! trap exit on that same hart. There is no cross-hart access to order, so
//! `Relaxed` on a per-hart `AtomicU32` is as strong as this needs to be — the
//! same argument `PerCpuSched::current_filter` makes in the scheduler.
//!
//! A depth rather than a flag: nested interrupts are not enabled today, but a
//! flag that someone later clears on the inner return would report "not in an
//! ISR" while still inside the outer one, and that failure is silent.

use core::sync::atomic::{AtomicU32, Ordering};

/// Upper bound on harts, matched to `kernel/src/main.rs`'s own `MAX_HARTS`
/// (not the scheduler's `MAX_CPUS` — a prior version of this comment named
/// the wrong constant; `MAX_HARTS` and `MAX_CPUS` have been allowed to
/// differ before, see `kernel/src/main.rs`'s own comment on why `PER_CPU`
/// and the boot-hart range check use different bounds). A hart id past this
/// is ignored rather than indexed — an out-of-range write here would be a
/// memory-safety bug reported as a scheduling one.
pub const MAX_HARTS: usize = azos_limits::NR_CPUS;

const ZERO: AtomicU32 = AtomicU32::new(0);
static DEPTH: [AtomicU32; MAX_HARTS] = [ZERO; MAX_HARTS];

/// Called by the trap handler's INTERRUPT arm on entry.
#[inline]
pub fn enter(hart: usize) {
    if hart < MAX_HARTS {
        DEPTH[hart].fetch_add(1, Ordering::Relaxed);
    }
}

/// Called by the trap handler's INTERRUPT arm on exit.
///
/// Saturating: an unbalanced `exit` must not wrap to `u32::MAX` and leave the
/// hart permanently claiming to be in an ISR, which would turn this detector
/// into a source of false reports instead of a silent one.
#[inline]
pub fn exit(hart: usize) {
    if hart < MAX_HARTS {
        let _ = DEPTH[hart].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| {
            Some(d.saturating_sub(1))
        });
    }
}

/// Is this hart currently inside an interrupt handler?
#[inline]
#[must_use]
pub fn in_isr(hart: usize) -> bool {
    hart < MAX_HARTS && DEPTH[hart].load(Ordering::Relaxed) != 0
}
