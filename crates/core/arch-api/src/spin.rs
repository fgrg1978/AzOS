// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Spin-wait and compare-and-swap (wave 15, N2): the only way a kernel
//! spinner (SpinLock today; the MCS lock, seqlock, adaptive mutex and RCU
//! later) touches the CPU's wait hints and its CAS instruction.
//!
//! [`SpinWait`]'s provided bodies ARE the fallback every ISA has without an
//! extension: `core::sync::atomic` (an LR/SC loop on riscv64, LDAXR/STLXR
//! at Armv8.0, LOCK CMPXCHG on x86_64) and a relax loop. An ISA overrides
//! the methods it has a better instruction for, each behind its
//! config/Kconfig.arch choice ([`crate::isa::ExtPolicy`]):
//!
//! | ISA     | `cas32/cas64`                 | `wait_hint32/64`            | `cpu_relax` |
//! |---------|-------------------------------|-----------------------------|-------------|
//! | riscv64 | Zacas `amocas.w/.d` (RV_ZACAS)| Zawrs `lr`+`wrs.nto` (RV_ZAWRS) | `pause` |
//! | aarch64 | LSE `CAS{A,L,AL}` (A64_LSE)   | `SEVL`;`WFE`;`LDAXR`;`WFE`  | `isb`       |
//! | x86_64  | `LOCK CMPXCHG` (baseline)     | WAITPKG `UMONITOR`/`UMWAIT` (X86_WAITPKG) | `pause` |
//!
//! `n` compiles the fallback only; `require` inlines the extension with no
//! branch; `probe` reads one flag the boot sets from the CPU's report and
//! branches. Nothing in a caller names an ISA.
//!
//! Orderings are explicit and never SeqCst (rfcs/survey/MUTEX.md §5.2):
//! [`CasOrder`] says what the success path publishes or observes.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The ordering of a [`SpinWait::cas32`] / [`SpinWait::cas64`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CasOrder {
    /// No ordering (a counter).
    Relaxed,
    /// Acquire on success (taking a lock); Acquire on the failed read.
    Acquire,
    /// Release on success (publishing); Relaxed on the failed read.
    Release,
    /// Both (a hand-off that observes and publishes).
    AcqRel,
}

impl CasOrder {
    /// The success ordering, as `compare_exchange` takes it.
    #[inline(always)]
    pub const fn success(self) -> Ordering {
        match self {
            CasOrder::Relaxed => Ordering::Relaxed,
            CasOrder::Acquire => Ordering::Acquire,
            CasOrder::Release => Ordering::Release,
            CasOrder::AcqRel => Ordering::AcqRel,
        }
    }

    /// The failure ordering (no store happened, so no Release half).
    #[inline(always)]
    pub const fn failure(self) -> Ordering {
        match self {
            CasOrder::Relaxed | CasOrder::Release => Ordering::Relaxed,
            CasOrder::Acquire | CasOrder::AcqRel => Ordering::Acquire,
        }
    }
}

/// Polls with [`SpinWait::cpu_relax`] before [`SpinWait::wait_while32`]
/// takes the wait hint (Kconfig `SPIN_WAIT_RELAX_SPINS`).
pub const RELAX_SPINS: u32 = azos_limits::SPIN_WAIT_RELAX_SPINS as u32;

/// Spin-wait and CAS primitives. Every method is `#[inline(always)]` and
/// takes `&self` on the ISA's zero-sized `ARCH`, so a call costs exactly
/// the instructions it emits.
pub trait SpinWait {
    /// One pause in a polling loop: a hint that this hart is spinning
    /// (frees the sibling thread, saves power). No ordering.
    #[inline(always)]
    fn cpu_relax(&self) {
        core::hint::spin_loop();
    }

    /// Strong compare-and-swap: `Ok(current)` and `*a = new` when `*a ==
    /// current`, else `Err(observed)`. Never fails spuriously (the same
    /// contract as `AtomicU32::compare_exchange`).
    #[inline(always)]
    fn cas32(&self, a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> Result<u32, u32> {
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    /// [`cas32`](Self::cas32) on a 64-bit word.
    #[inline(always)]
    fn cas64(&self, a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> Result<u64, u64> {
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    /// One wait step: return once `*a` may differ from `expected`. May
    /// return early (an interrupt, a timeout, a store of the same value);
    /// never stalls past a store that changes the word or a pending
    /// interrupt, masked or not. The fallback is one `cpu_relax`.
    #[inline(always)]
    fn wait_hint32(&self, a: &AtomicU32, expected: u32) {
        let _ = (a, expected);
        self.cpu_relax();
    }

    /// [`wait_hint32`](Self::wait_hint32) on a 64-bit word.
    #[inline(always)]
    fn wait_hint64(&self, a: &AtomicU64, expected: u64) {
        let _ = (a, expected);
        self.cpu_relax();
    }

    /// Wait until `*a != expected` and return the value read: up to
    /// [`RELAX_SPINS`] relaxed polls with `cpu_relax`, then a
    /// [`wait_hint32`](Self::wait_hint32) per poll. The reads are Relaxed
    /// (Linux's `smp_cond_load_relaxed`): the caller orders what follows,
    /// with a CAS or an Acquire fence.
    #[inline(always)]
    fn wait_while32(&self, a: &AtomicU32, expected: u32) -> u32 {
        let mut spins = 0u32;
        loop {
            let v = a.load(Ordering::Relaxed);
            if v != expected {
                return v;
            }
            if spins < RELAX_SPINS {
                spins += 1;
                self.cpu_relax();
            } else {
                self.wait_hint32(a, expected);
            }
        }
    }

    /// [`wait_while32`](Self::wait_while32) on a 64-bit word.
    #[inline(always)]
    fn wait_while64(&self, a: &AtomicU64, expected: u64) -> u64 {
        let mut spins = 0u32;
        loop {
            let v = a.load(Ordering::Relaxed);
            if v != expected {
                return v;
            }
            if spins < RELAX_SPINS {
                spins += 1;
                self.cpu_relax();
            } else {
                self.wait_hint64(a, expected);
            }
        }
    }
}
