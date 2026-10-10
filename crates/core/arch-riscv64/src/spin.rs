// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 [`SpinWait`]: Zacas `amocas.w/.d` for the CAS (Kconfig
//! RV_ZACAS), Zawrs `lr` + `wrs.nto` for the wait hint (RV_ZAWRS),
//! Zihintpause `pause` for `cpu_relax`. The fallbacks are the trait's
//! provided bodies: the compiler's `lr`/`sc` loop and a `pause` loop.
//!
//! Probe, the Zicboz/Sstc shape: cpu@0's device tree claims the extension,
//! then [`select`] executes it once under a private `stvec` (a trap-safe
//! probe that also checks the result), so a device tree that lies costs
//! the fast path, never an illegal-instruction trap in a lock. Until
//! [`select`] runs every CAS takes `lr`/`sc`, which every RV64A hart has;
//! the two may meet on one word (both are atomic on it).
//!
//! The instructions are emitted with `.option arch` inside each asm block,
//! so no codegen flag changes: the kernel's other atomics keep LR/SC.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use azos_arch_api::isa::{riscv64 as policy, ExtPolicy};
use azos_arch_api::{CasOrder, SpinWait};

/// The probe's verdicts (`probe` only; `n`/`require` never read them).
static ZACAS_ON: AtomicBool = AtomicBool::new(false);
static ZAWRS_ON: AtomicBool = AtomicBool::new(false);

/// `amocas` in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn zacas_on() -> bool {
    match policy::ZACAS {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => ZACAS_ON.load(Ordering::Relaxed),
    }
}

/// `wrs.nto` in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn zawrs_on() -> bool {
    match policy::ZAWRS {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => ZAWRS_ON.load(Ordering::Relaxed),
    }
}

/// The boot's verdicts as [`select`] left them (the `[ISA]` line's input
/// under every policy; under `require` the lock paths do not read them).
pub fn verdict() -> (bool, bool) {
    (ZACAS_ON.load(Ordering::Relaxed), ZAWRS_ON.load(Ordering::Relaxed))
}

/// What [`select`] found: the claim, and whether executing it worked.
#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    pub zacas: bool,
    pub zawrs: bool,
    /// A claimed extension whose execution probe trapped or misbehaved.
    pub zacas_refuted: bool,
    pub zawrs_refuted: bool,
}

/// Boot, cpu@0, before the secondaries: `dt_*` are the device tree's
/// claims (already masked by the Kconfig policy, or forced by a canary).
/// Each claim is executed once under a private trap vector; the flags the
/// lock paths read are set only for a claim that executed correctly.
pub fn select(dt_zacas: bool, dt_zawrs: bool) -> Verdict {
    let zacas = dt_zacas && probe::zacas_works();
    let zawrs = dt_zawrs && probe::zawrs_works();
    ZACAS_ON.store(zacas, Ordering::Relaxed);
    ZAWRS_ON.store(zawrs, Ordering::Relaxed);
    Verdict { zacas, zawrs, zacas_refuted: dt_zacas && !zacas, zawrs_refuted: dt_zawrs && !zawrs }
}

/// `amocas.w{,.aq,.rl,.aqrl}` / `amocas.d...`: `rd` holds the compare
/// value in and the old value out. `.w` compares the low 32 bits and
/// sign-extends the result, which `as u32` drops.
macro_rules! amocas {
    ($insn:literal, $ty:ty, $a:expr, $cur:expr, $new:expr) => {{
        let mut rd: $ty = $cur;
        // SAFETY: `$a` is a valid, aligned atomic word (a reference); the
        // instruction is only reached when Zacas is in use (`zacas_on`).
        unsafe {
            core::arch::asm!(
                ".option push",
                ".option arch, +zacas",
                concat!($insn, " {rd}, {new}, ({addr})"),
                ".option pop",
                rd = inout(reg) rd,
                new = in(reg) $new,
                addr = in(reg) $a,
                options(nostack, preserves_flags),
            );
        }
        rd
    }};
}

#[inline(always)]
fn amocas_w(a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> u32 {
    let p = a.as_ptr();
    match order {
        CasOrder::Relaxed => amocas!("amocas.w", u32, p, current, new),
        CasOrder::Acquire => amocas!("amocas.w.aq", u32, p, current, new),
        CasOrder::Release => amocas!("amocas.w.rl", u32, p, current, new),
        CasOrder::AcqRel => amocas!("amocas.w.aqrl", u32, p, current, new),
    }
}

#[inline(always)]
fn amocas_d(a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> u64 {
    let p = a.as_ptr();
    match order {
        CasOrder::Relaxed => amocas!("amocas.d", u64, p, current, new),
        CasOrder::Acquire => amocas!("amocas.d.aq", u64, p, current, new),
        CasOrder::Release => amocas!("amocas.d.rl", u64, p, current, new),
        CasOrder::AcqRel => amocas!("amocas.d.aqrl", u64, p, current, new),
    }
}

/// `lr` the word, and stall in `wrs.nto` while it still holds `expected`
/// and the reservation stands (Linux's `__cmpwait`). Another hart's store
/// breaks the reservation; a pending interrupt, masked or not, ends the
/// stall too.
macro_rules! lr_wrs {
    ($lr:literal, $a:expr, $expected:expr) => {{
        // SAFETY: `$a` is a valid, aligned word; only reached when Zawrs is
        // in use (`zawrs_on`). The reservation left behind is harmless.
        unsafe {
            core::arch::asm!(
                concat!($lr, " {t}, ({addr})"),
                "bne {t}, {e}, 2f",
                ".option push",
                ".option arch, +zawrs",
                "wrs.nto",
                ".option pop",
                "2:",
                addr = in(reg) $a,
                e = in(reg) $expected,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }};
}

impl SpinWait for crate::api_impl::Riscv64 {
    /// Zihintpause `pause`: a HINT encoding (`fence w,0`), a no-op on a
    /// hart without it, so it needs no probe.
    #[inline(always)]
    fn cpu_relax(&self) {
        // SAFETY: a hint; no memory, register or flag effect.
        unsafe {
            core::arch::asm!(".option push", ".option arch, +zihintpause", "pause", ".option pop",
                             options(nomem, nostack, preserves_flags));
        }
    }

    #[inline(always)]
    fn cas32(&self, a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> Result<u32, u32> {
        if zacas_on() {
            let old = amocas_w(a, current, new, order);
            if old == current { Ok(old) } else { Err(old) }
        } else {
            a.compare_exchange(current, new, order.success(), order.failure())
        }
    }

    #[inline(always)]
    fn cas64(&self, a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> Result<u64, u64> {
        if zacas_on() {
            let old = amocas_d(a, current, new, order);
            if old == current { Ok(old) } else { Err(old) }
        } else {
            a.compare_exchange(current, new, order.success(), order.failure())
        }
    }

    #[inline(always)]
    fn wait_hint32(&self, a: &AtomicU32, expected: u32) {
        if zawrs_on() {
            // `lr.w` sign-extends: compare against the sign-extended value.
            lr_wrs!("lr.w", a.as_ptr(), expected as i32 as i64);
        } else {
            self.cpu_relax();
        }
    }

    #[inline(always)]
    fn wait_hint64(&self, a: &AtomicU64, expected: u64) {
        if zawrs_on() {
            lr_wrs!("lr.d", a.as_ptr(), expected);
        } else {
            self.cpu_relax();
        }
    }
}

/// The trap-safe execution probes (the `cbo::probe` shape: interrupts off,
/// a private `stvec` that turns the trap into a 0 result, both restored).
mod probe {
    // `azos_zacas_probe(addr) -> usize`: `amocas.w` then `amocas.d` on the
    // two words at `addr` (compare 5, swap in 9). 1: no trap; 0: trapped.
    // `azos_zawrs_probe() -> usize`: `wrs.nto` with no reservation (no
    // stall). 1: no trap; 0: trapped (absent, or mstatus.TW set).
    // Clobbers t0-t4, a1 (caller-saved); a0 carries the result out.
    core::arch::global_asm!(
        ".pushsection .text.azos_spin_probe, \"ax\"",
        ".globl azos_zacas_probe",
        ".p2align 2",
        "azos_zacas_probe:",
        "    csrrci t3, sstatus, 2",
        "    csrr   t1, stvec",
        "    la     t0, 1f",
        "    csrw   stvec, t0",
        "    li     a1, 1",
        "    li     t2, 5",
        "    li     t4, 9",
        ".option push",
        ".option arch, +zacas",
        "    amocas.w.aqrl t2, t4, (a0)",
        "    li     t2, 5",
        "    addi   a0, a0, 8",
        "    amocas.d.aqrl t2, t4, (a0)",
        ".option pop",
        "2:",
        "    csrw   stvec, t1",
        "    andi   t3, t3, 2",
        "    csrs   sstatus, t3",
        "    mv     a0, a1",
        "    ret",
        ".p2align 2",
        "1:",
        "    li     a1, 0",
        "    la     t0, 2b",
        "    csrw   sepc, t0",
        "    sret",
        "",
        ".globl azos_zawrs_probe",
        ".p2align 2",
        "azos_zawrs_probe:",
        "    csrrci t3, sstatus, 2",
        "    csrr   t1, stvec",
        "    la     t0, 3f",
        "    csrw   stvec, t0",
        "    li     a1, 1",
        ".option push",
        ".option arch, +zawrs",
        "    wrs.nto",
        ".option pop",
        "4:",
        "    csrw   stvec, t1",
        "    andi   t3, t3, 2",
        "    csrs   sstatus, t3",
        "    mv     a0, a1",
        "    ret",
        ".p2align 2",
        "3:",
        "    li     a1, 0",
        "    la     t0, 4b",
        "    csrw   sepc, t0",
        "    sret",
        ".popsection",
    );

    unsafe extern "C" {
        fn azos_zacas_probe(addr: *mut u64) -> usize;
        fn azos_zawrs_probe() -> usize;
    }

    /// `amocas` executes AND swaps: a TCG or a core that accepts the
    /// encoding as a no-op would pass a trap-only check.
    pub(super) fn zacas_works() -> bool {
        let mut words: [u64; 2] = [5, 5];
        // SAFETY: two aligned, writable words on this stack frame; the
        // probe restores stvec and sstatus.SIE before returning.
        let ran = unsafe { azos_zacas_probe(words.as_mut_ptr()) } == 1;
        // SAFETY: the probe has returned; plain reads of our own words.
        let (w, d) = unsafe {
            (core::ptr::read_volatile(words.as_ptr() as *const u32),
             core::ptr::read_volatile(words.as_ptr().add(1)))
        };
        ran && w == 9 && d == 9
    }

    pub(super) fn zawrs_works() -> bool {
        // SAFETY: no memory operand; stvec and sstatus.SIE restored.
        unsafe { azos_zawrs_probe() == 1 }
    }
}
