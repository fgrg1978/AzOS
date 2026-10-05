// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_arch`, used only by `tests/host/sync-tests`.
//! **Not part of the kernel.**
//!
//! `crates/core/sync/src/preempt.rs` reaches the machine through exactly two arch
//! calls — `cpu::hart_id()` (a `mv rd, tp`) and `csr::read_sstatus()` (a
//! `csrr`). Both are RISC-V inline asm and cannot execute on the developer
//! host. This crate replaces the two *inputs* with settable cells and nothing
//! else, so `preempt.rs` itself is compiled unmodified: the guard, the
//! saturating counter arithmetic, the `need_resched` handling and the
//! `sstatus.SIE` firing gate under test are the kernel's own code, not a copy.
//!
//! `csr::write_sstatus()` was added alongside these two once `sync-tests`
//! started pulling in `spinlock.rs` and `waitqueue.rs` as well (the WaitQueue
//! K-C29 fix, which uses `SpinLock::lock_irqsave()`): that function is the
//! other half of the `read_sstatus`/`write_sstatus` pair `lock_irqsave()`
//! uses to save and restore `SSTATUS_SIE`, and `spinlock.rs` does not compile
//! without it. Only the `SIE` bit is modelled, same as `read_sstatus()`.
//!
//! The cells are thread-local because `cargo test` runs tests in parallel
//! threads; `sync-tests` additionally serialises everything that touches the
//! shared `PREEMPT` slots (see its `guard()`).
//!
//! # `arm_on_sstatus_read` — the same-hart-interrupt injection point
//!
//! `PreemptGuard::drop` (K-C29-adjacent lost-wakeup fix) commits its depth
//! decrement, then reads `need_resched` and `csr::read_sstatus()` to decide
//! whether to fire. The property under test is about a *same-hart interrupt*
//! landing inside that post-decrement window — something no host thread can
//! do to another, since a host OS never delivers a RISC-V timer trap. What it
//! can do is splice code into the one call `drop` makes that sits inside that
//! window: `read_sstatus()` itself. `arm_on_sstatus_read` runs a one-shot
//! callback immediately before `read_sstatus()` returns its value, so a test
//! can make "a tick sets `need_resched` right there" concrete without any
//! real concurrency.
//!
//! This is a real but narrow discriminator: it proves the fix reads
//! `need_resched` after the point where `sstatus` is read, which is exactly
//! where production reads it today. It stops discriminating the instant a
//! future refactor reorders `drop` to read `sstatus` before `need_resched` (a
//! behaviour-preserving reorder, since both reads happen post-decrement) —
//! see the test's own doc comment in `sync-tests`.
//!
//! # `arm_on_hart_id_read` — "what has already happened by the time
//! `critical_section()` starts?"
//!
//! `critical_section()`'s very first action is `cpu::hart_id()` (inside
//! `preempt::slot()`), before it touches the depth counter. That makes
//! `hart_id()` a synchronous injection point for a different class of
//! question than `arm_on_sstatus_read` answers: not "what happens between
//! two points inside one function" but "was `critical_section()` called
//! BEFORE or AFTER some other, unrelated piece of state changed" — e.g.
//! `tests/host/world-state-tests` uses this to check whether `WORLD_STATE.seq`
//! is still even at the instant `critical_section()` begins, which is
//! exactly the K-C29 property `world_state_write_begin()`'s ordering has to
//! hold and which cannot be observed from outside a single synchronous
//! function call by checking state only before/after it returns.

use std::cell::Cell;

thread_local! {
    /// What `cpu::hart_id()` reports on this thread.
    static HART: Cell<usize> = const { Cell::new(0) };
    /// Whether `csr::read_sstatus()` reports `SSTATUS_SIE` set on this thread.
    static SIE: Cell<bool> = const { Cell::new(true) };
    /// One-shot callback fired by the next `csr::read_sstatus()` call, before
    /// it returns. `None` most of the time — armed only by the race test.
    static ON_SSTATUS_READ: Cell<Option<fn()>> = const { Cell::new(None) };
    /// One-shot callback fired by the next `cpu::hart_id()` call, before it
    /// returns. `None` most of the time — see `arm_on_hart_id_read`'s doc.
    static ON_HART_ID_READ: Cell<Option<fn()>> = const { Cell::new(None) };
}

/// Set the hart id this thread's `hart_id()` will report.
pub fn set_hart(h: usize) {
    HART.with(|c| c.set(h));
}

/// Set whether S-mode interrupts read as enabled on this thread.
pub fn set_sie(on: bool) {
    SIE.with(|c| c.set(on));
}

/// Arm a one-shot hook that runs the next time `csr::read_sstatus()` is
/// called, just before it returns. Consumed on read via `Cell::take`, so it
/// is re-entrancy safe: if the hook itself causes another `read_sstatus()`
/// call, that nested call sees no hook armed and just reads `SIE`.
pub fn arm_on_sstatus_read(f: fn()) {
    ON_SSTATUS_READ.with(|c| c.set(Some(f)));
}

/// Clear any armed hook without waiting for it to fire. Tests must call this
/// in their shared reset (`guard()`), the same way `set_hart`/`set_sie` reset
/// their cells — otherwise a test that fails before its hook fires leaves it
/// armed for whichever test's `read_sstatus()` call comes next on this
/// thread.
pub fn clear_sstatus_hook() {
    ON_SSTATUS_READ.with(|c| c.set(None));
}

/// Arm a one-shot hook that runs the next time `cpu::hart_id()` is called,
/// just before it returns. Consumed on read via `Cell::take`, same
/// re-entrancy handling as `arm_on_sstatus_read`.
pub fn arm_on_hart_id_read(f: fn()) {
    ON_HART_ID_READ.with(|c| c.set(Some(f)));
}

/// Clear any armed `hart_id()` hook without waiting for it to fire. Same
/// reset obligation as `clear_sstatus_hook`.
pub fn clear_hart_id_hook() {
    ON_HART_ID_READ.with(|c| c.set(None));
}

pub mod cpu {
    /// Stands in for `mv {}, tp`.
    #[inline]
    pub fn hart_id() -> usize {
        if let Some(f) = super::ON_HART_ID_READ.with(|c| c.take()) {
            f();
        }
        super::HART.with(|c| c.get())
    }
}

pub mod csr {
    /// Same bit position as the kernel's `crates/core/arch-riscv64/src/csr.rs`.
    pub const SSTATUS_SIE: usize = 1 << 1;

    /// Stands in for `csrr {}, sstatus`. Only the SIE bit is modelled — it is
    /// the only bit `preempt.rs` looks at.
    #[inline]
    pub fn read_sstatus() -> usize {
        // Fire (and consume) any armed hook BEFORE computing the return
        // value, so a hook that flips `need_resched` is visible to whatever
        // in `preempt.rs` reads it right after this call returns.
        if let Some(f) = super::ON_SSTATUS_READ.with(|c| c.take()) {
            f();
        }
        if super::SIE.with(|c| c.get()) { SSTATUS_SIE } else { 0 }
    }

    /// Stands in for `csrw sstatus, {}` (as used via `csrrc`/`csrrs` in the
    /// real `lock_irqsave()`/`IrqSaveGuard::drop`). Only the SIE bit is
    /// modelled, matching `read_sstatus()`: this thread's simulated SIE
    /// becomes whatever bit 1 of `v` says.
    #[inline]
    pub fn write_sstatus(v: usize) {
        super::SIE.with(|c| c.set(v & SSTATUS_SIE != 0));
    }
}

// ──────────────────────────────────────────────────────────────────────────
// The cross-ISA contract, modelled on top of this shim's own `csr` cells.
//
// Added 2026-09-21, when `spinlock.rs` and `preempt.rs` stopped reaching
// `sstatus` directly and started going through `arch-api`. Without it those
// two files — which this crate compiles UNMODIFIED via `#[path]`, which is
// the whole point — would not build here.
//
// **Every method routes through `csr::read_sstatus()` / `csr::write_sstatus()`
// rather than touching `SIE` itself.** That is not indirection for its own
// sake: `read_sstatus()` is where `arm_on_sstatus_read` fires its one-shot
// hook, and that hook is the only way this suite can make "a tick lands
// inside `PreemptGuard::drop`'s post-decrement window" concrete on a host
// with no RISC-V traps. A shim that set the cell directly would compile,
// pass, and quietly retire that test's discriminator.
// ──────────────────────────────────────────────────────────────────────────

pub use azos_arch_api::{InterruptState, Interrupts};

/// Host stand-in for the ISA singleton the kernel calls `ARCH`.
pub struct HostArch;

/// Same name the facade exports, so the call sites read identically.
pub static ARCH: HostArch = HostArch;

impl Interrupts for HostArch {
    fn disable_all(&self) -> InterruptState {
        let prev = csr::read_sstatus();
        csr::write_sstatus(prev & !csr::SSTATUS_SIE);
        InterruptState(prev as u64)
    }

    /// Read-modify-write of `SIE` alone — the same correction the RISC-V
    /// impl took. Modelling the blanket write here instead would make this
    /// suite agree with a kernel that no longer exists.
    fn restore(&self, prev: InterruptState) {
        let current = csr::read_sstatus();
        csr::write_sstatus(
            (current & !csr::SSTATUS_SIE) | ((prev.0 as usize) & csr::SSTATUS_SIE),
        );
    }

    fn enable_all(&self) {
        csr::write_sstatus(csr::read_sstatus() | csr::SSTATUS_SIE);
    }

    fn interrupts_enabled(&self) -> bool {
        csr::read_sstatus() & csr::SSTATUS_SIE != 0
    }

    /// No timer on the host. `preempt.rs` and `spinlock.rs` never call it;
    /// it exists because the trait requires it, and it panics rather than
    /// silently doing nothing so a future caller finds out here.
    fn set_timer_deadline(&self, _deadline_ticks: u64) {
        unimplemented!("sync-tests has no timer; nothing under test programs one")
    }

    /// Same reasoning as `set_timer_deadline`: `cargo test` has no harts to
    /// signal, so answering "sent" would be modelling a lie.
    fn send_ipi(&self, _target_hart: usize) {
        unimplemented!("sync-tests has no second hart to signal")
    }
}
