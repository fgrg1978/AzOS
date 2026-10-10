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
//! branch. `probe` (riscv64, aarch64) is Linux's ALTERNATIVE: each use is a
//! boot-once site in `.azos_keys`, linked as the safe form (a branch to the
//! out-of-line fallback, or a nop) and rewritten once, on the boot CPU
//! before the secondaries start, to the extension's instruction when the
//! probe found it ([`SITE_KEY_CAS`]; the kernel's `boot/spin_patch.rs`).
//! After boot a probe site costs what `require` costs. x86_64's WAITPKG
//! (the contended wait only) still tests a boot-set flag. Nothing in a
//! caller names an ISA.
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

/// The `.azos_keys` key of the atomic-instruction sites
/// (`azos_trace::jump::KEY_SPIN_CAS`; the kernel asserts the mirrors
/// agree): Zacas `amocas` on riscv64, LSE `CAS*`/`SWP*` on aarch64.
pub const SITE_KEY_CAS: u32 = 65;
/// The wait-hint sites (Zawrs `wrs.nto`).
pub const SITE_KEY_WAIT: u32 = 66;
/// The relax sites (Zihintpause `pause`).
pub const SITE_KEY_RELAX: u32 = 67;
/// The site kinds (`azos_trace::jump::KIND_RV_ALT` / `KIND_A64_ALT`).
pub const SITE_KIND_RV_ALT: u32 = 5;
pub const SITE_KIND_A64_ALT: u32 = 6;

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

    /// Atomic exchange: `*a = new`, returning the old value. The
    /// test-and-set of a lock whose word holds only free/held, and the
    /// queue-tail swap of an MCS lock (rfcs/survey/MUTEX.md §5.2). Every ISA
    /// has it in its base: `amoswap` (riscv64 A), `XCHG` (x86_64), an
    /// LDAXR/STXR loop at Armv8.0, LSE `SWP*` on aarch64 when present.
    #[inline(always)]
    fn swap32(&self, a: &AtomicU32, new: u32, order: CasOrder) -> u32 {
        a.swap(new, order.success())
    }

    /// [`swap32`](Self::swap32) on a 64-bit word.
    #[inline(always)]
    fn swap64(&self, a: &AtomicU64, new: u64, order: CasOrder) -> u64 {
        a.swap(new, order.success())
    }

    /// Test-and-set acquire of a lock word that holds only 0 (free) and 1
    /// (held): [`swap32`](Self::swap32) to 1 (Acquire) until it returns 0,
    /// waiting with [`wait_while32`](Self::wait_while32) between attempts.
    /// The `SpinLock` acquire. An ISA keeps the swap and its branch inline
    /// and the waiting out of line WITHOUT a function call's clobbers: a
    /// trampoline that saves every caller-saved register calls
    /// [`tas_slow32`], so the inline site costs the caller only the swap,
    /// the branch and one link register.
    #[inline(always)]
    fn tas_acquire32(&self, a: &AtomicU32) {
        if self.swap32(a, 1, CasOrder::Acquire) != 0 {
            tas_slow32(self, a);
        }
    }

    /// [`cas32`](Self::cas32) on a 64-bit word.
    #[inline(always)]
    fn cas64(&self, a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> Result<u64, u64> {
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    /// One wait step: return once `*a` may differ from `expected`. May
    /// return early (an interrupt, a timeout, a store of the same value);
    /// never stalls past another CPU's store to the word. What else ends
    /// the stall is the ISA's: Zawrs any pending interrupt, enabled or
    /// not; WFE an unmasked interrupt or an event; UMWAIT its TSC deadline
    /// or an interrupt. The fallback is one `cpu_relax`.
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

    /// Boot: should the sites of `key` ([`SITE_KEY_CAS`], ...) be rewritten
    /// to the extension's instruction? The probe's verdict, read once by the
    /// boot patcher. Default: no site of this ISA is ever rewritten.
    fn boot_site_wanted(&self, key: u32) -> bool {
        let _ = key;
        false
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

/// The contended half of [`SpinWait::tas_acquire32`], after a swap found
/// the word held: wait (reading only) until it is no longer 1, swap again.
/// Each ISA's `azos_spin_tas_slow32` (reached through its register-saving
/// trampoline) is this, for its `ARCH`.
#[inline(never)]
pub fn tas_slow32<S: SpinWait + ?Sized>(s: &S, a: &AtomicU32) {
    loop {
        s.wait_while32(a, 1);
        if s.swap32(a, 1, CasOrder::Acquire) == 0 {
            return;
        }
    }
}
