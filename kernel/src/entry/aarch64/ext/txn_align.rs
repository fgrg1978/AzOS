// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I-13 on aarch64 (ktest `txn_rolls_back_an_el1_alignment_fault`): the
//! control task (`rt-motor`) takes an EL1 Alignment fault in its loop, an
//! exclusive load one byte off its natural alignment, which faults whatever
//! `SCTLR_EL1.A` says. The trap entry must hand it to the rollback
//! (`TrapFrame::arch_page_fault`), which restarts the task at its entry; the
//! loop must run on after it (its heartbeat advances), and the restart must be
//! reported: a `SAFETY_TXN_ROLLBACK` record the flight recorder admitted when
//! it is active (the `ktest disk` rows), the report itself otherwise.
//!
//! Canary `txn-align-route-canary` (cargo feature): the old routing, so the
//! fault is the fatal kernel page fault and the run ends with no summary.

use azos_safety_core::txn::{txn_counts, txn_inject_once};

/// Sixteen aligned bytes; the injected load reads at offset 1.
#[repr(align(16))]
struct Aligned([u8; 16]);
static TARGET: Aligned = Aligned([0; 16]);

/// The control task's injected fault. Never returns when the rollback takes
/// it: the task restarts at its entry.
fn misaligned_exclusive() {
    let at = core::ptr::addr_of!(TARGET) as usize + 1;
    // SAFETY: `at` is inside `TARGET`, a static; an exclusive load off its
    // natural alignment takes an Alignment fault before it reads, and the
    // `clrex` only runs (dropping the monitor) if it ever did not.
    unsafe {
        core::arch::asm!("ldxr {v}, [{a}]", "clrex", a = in(reg) at, v = out(reg) _, options(nostack));
    }
}

azos_ktest::ktest_late! {
    fn txn_rolls_back_an_el1_alignment_fault() {
        if !azos_limits::CONTROL_TXN_TICKS {
            return Err("Kconfig CONTROL_TXN_TICKS is off in this build");
        }
        let (aborts, reported, recorded) = txn_counts();
        txn_inject_once(misaligned_exclusive);
        crate::ktest::wait("the control task's alignment fault was not rolled back", || {
            txn_counts().0 > aborts
        })?;
        let beat = azos_safety_core::watchdog::control_heartbeat();
        crate::ktest::wait("the control loop did not run on after the rollback", || {
            azos_safety_core::watchdog::control_heartbeat().wrapping_sub(beat) >= 3
        })?;
        crate::ktest::wait("the restarted control task never reported the rollback", || {
            txn_counts().1 > reported
        })?;
        if azos_actuation::logger::logger_active() && txn_counts().2 == recorded {
            return Err("the flight recorder did not admit the rollback's record");
        }
        Ok(())
    }
}
