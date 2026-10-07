// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `current_cpu_id()` cross-check (feature `cpuid-probe`; gate only).
//!
//! `current_cpu_id()` reads a register the boot code parks the hart id in:
//! `tp` on riscv64 (an ordinary GPR) and `TPIDR_EL1` on aarch64. This module
//! re-derives the id from a source that register cannot reach and counts
//! every disagreement, at EVERY call of `current_cpu_id()` once [`arm`] ran:
//!
//! - riscv64: the id word 4 bytes below this hart's `stvec` slot (a per-hart
//!   CSR U-mode cannot write), `boot_hart_id` for the boot hart's generic
//!   vector — the very derivation `trap_entry.S` uses for K-C16;
//! - aarch64: `MPIDR_EL1` Aff2:Aff1:Aff0, the value `boot.S` copies into
//!   `TPIDR_EL1` (logical id = affinity on every board the tree supports).
//!
//! It also counts `current_user_pt()` calls that loaded a slot other than
//! their own hart's (a lie, or a migration between the id read and the
//! load: the one the 2026-09-25 reading needed). Nothing here
//! prints from the hot path: a mismatch only bumps counters and keeps its
//! first sample, read back by [`snapshot`].

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ARMED: AtomicBool = AtomicBool::new(false);
static READS: AtomicU64 = AtomicU64::new(0);
static MISMATCHES: AtomicU64 = AtomicU64::new(0);
/// First mismatch: `register id << 32 | hardware id`, `u64::MAX` = none.
static FIRST: AtomicU64 = AtomicU64::new(u64::MAX);
static FOREIGN: AtomicU64 = AtomicU64::new(0);

/// Start checking. Called on the boot hart once its trap vector is installed
/// (riscv64 reads `stvec`) and before any secondary hart is woken.
pub fn arm() {
    ARMED.store(true, Ordering::Release);
}

/// The hart id from a source `tp` / `TPIDR_EL1` cannot reach.
#[inline(always)]
pub fn hw_cpu_id() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        unsafe extern "C" {
            static boot_hart_id: u64;
        }
        let stvec: usize;
        // SAFETY: reading a CSR has no side effect.
        unsafe { core::arch::asm!("csrr {}, stvec", out(reg) stvec, options(nostack, nomem)) };
        // SAFETY: `arm()` runs after the boot hart installs `trap_vector` and
        // every secondary installs its `trap_hart_vectors` slot in boot.S
        // before any Rust; both carry their id word at -4, mapped readable.
        let word = unsafe { core::ptr::read_volatile(((stvec & !3) - 4) as *const i32) };
        if word >= 0 {
            word as usize
        } else {
            // SAFETY: a .data word boot.S writes once before kernel_main.
            unsafe { core::ptr::read_volatile(&raw const boot_hart_id) as usize }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mpidr: usize;
        // SAFETY: reading a system register has no side effect.
        unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nostack, nomem)) };
        mpidr & 0x00ff_ffff
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Called by `current_cpu_id()` with the id it is about to return.
#[inline(always)]
pub fn observe(id: usize) {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    READS.fetch_add(1, Ordering::Relaxed);
    let hw = hw_cpu_id();
    if hw != id {
        mismatch(id, hw);
    }
}

#[cold]
#[inline(never)]
fn mismatch(id: usize, hw: usize) {
    MISMATCHES.fetch_add(1, Ordering::Relaxed);
    let sample = ((id as u64 & 0xffff_ffff) << 32) | (hw as u64 & 0xffff_ffff);
    let _ = FIRST.compare_exchange(u64::MAX, sample, Ordering::Relaxed, Ordering::Relaxed);
}

/// `current_user_pt()` read `cpu`, then that hart's slot: counts the calls
/// that are no longer on hart `cpu` once the load is done.
#[inline(always)]
pub fn note_accessor(cpu: usize) {
    if ARMED.load(Ordering::Relaxed) && hw_cpu_id() != cpu {
        FOREIGN.fetch_add(1, Ordering::Relaxed);
    }
}

/// `(reads, mismatches, first mismatch as (register id, hardware id), foreign)`.
pub fn snapshot() -> (u64, u64, Option<(u32, u32)>, u64) {
    let first = FIRST.load(Ordering::Relaxed);
    (
        READS.load(Ordering::Relaxed),
        MISMATCHES.load(Ordering::Relaxed),
        (first != u64::MAX).then(|| ((first >> 32) as u32, first as u32)),
        FOREIGN.load(Ordering::Relaxed),
    )
}

/// The boot hart at the old fork-probe position: secondaries are running
/// tasks, this hart has never scheduled. Reads `current_cpu_id()` and
/// `current_user_pt()` `iters` times; returns `(wrong id, nonzero user_pt)`.
/// Either count above zero is the anomaly.
pub fn boot_hart_hammer(boot_id: usize, iters: u32) -> (u32, u32) {
    let (mut wrong, mut pt) = (0u32, 0u32);
    for _ in 0..iters {
        if crate::smp::current_cpu_id() != boot_id {
            wrong += 1;
        }
        if crate::scheduler::current_user_pt() != 0 {
            pt += 1;
        }
    }
    (wrong, pt)
}

/// Canary (`cpuid-probe-canary`; gate only): make the id register lie on
/// purpose. For each other hart `c`, with interrupts off: `tp` /
/// `TPIDR_EL1` := `c`, read `current_user_pt()`, and when that finds a user
/// page table, call fork exactly as the old fork probe did (kernel context,
/// zeroed `sepc`/`user_sp`/registers). Restores the register before
/// interrupts come back on. Run on the boot hart at the old fork-probe
/// position and from a kernel task once user tasks exist.
///
/// What it proves: if `current_cpu_id()` lied, the probe observes the
/// mismatch, and the old fork probe would have printed the CHILD'S TID
/// (>= 1) — never `rc=0`, which `fork` cannot return to its caller.
/// Returns `(c, user_pt, fork rc)` for the first hart whose slot had one.
#[cfg(feature = "cpuid-probe-canary")]
pub fn poison_and_fork(ncpu: usize) -> Option<(usize, usize, i64)> {
    use azos_arch::Interrupts;
    #[inline(always)]
    fn set_id(v: usize) {
        // SAFETY: interrupts are off for the whole poisoned window, and the
        // register is restored before they come back on.
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("mv tp, {}", in(reg) v, options(nostack, nomem)) };
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("msr TPIDR_EL1, {}", in(reg) v, options(nostack, nomem)) };
        #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
        let _ = v;
    }
    for c in 0..ncpu {
        let prev = azos_arch::ARCH.disable_all();
        let own = hw_cpu_id();
        if c == own {
            azos_arch::ARCH.restore(prev);
            continue;
        }
        set_id(c);
        let pt = crate::scheduler::current_user_pt();
        let rc = if pt != 0 {
            crate::process::sys_fork_impl(0, 0, &crate::task::UserRegs::default())
        } else {
            0
        };
        set_id(own);
        azos_arch::ARCH.restore(prev);
        if pt != 0 {
            return Some((c, pt, rc));
        }
    }
    None
}
