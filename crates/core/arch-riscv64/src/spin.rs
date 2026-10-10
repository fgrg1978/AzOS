// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 [`SpinWait`]: Zacas `amocas.w/.d` for the CAS (Kconfig
//! RV_ZACAS), Zawrs `lr` + `wrs.nto` for the wait hint (RV_ZAWRS),
//! Zihintpause `pause` for `cpu_relax` (RV_ZIHINTPAUSE).
//!
//! `n` compiles the fallback (the compiler's `lr`/`sc` loop; no wait hint;
//! no instruction for `cpu_relax`) and `require` the extension, inline.
//!
//! `probe`, the Zicboz/Sstc shape for the decision: cpu@0's device tree
//! claims the extension, then [`select`] executes it once under a private
//! `stvec` (a trap-safe probe that also checks the result), so a device
//! tree that lies costs the fast path, never an illegal-instruction trap in
//! a lock. Then Linux's ALTERNATIVE for the cost: every probe use is a
//! 4-byte site (`.option norvc`, 2-byte aligned like any instruction in
//! compressed code: no alignment padding on the path; the boot writes a
//! 2 mod 4 site in halves) in `.azos_keys` (`SITE_KEY_*`, `SITE_KIND_RV_ALT`), linked as
//! the safe form and rewritten once by the kernel's boot patcher, on the
//! boot hart before any secondary starts, to the extension's instruction
//! when [`select`] confirmed it ([`SpinWait::boot_site_wanted`]).
//!
//! * CAS: linked `j` to an LR/SC loop placed after the function
//!   (`.subsection 1`, so the branch stays short); rewritten to the
//!   `amocas` the assembler encoded with the site's own registers.
//! * wait hint: `lr`; `bne`; a 4-byte nop, rewritten to `wrs.nto`.
//! * `cpu_relax`: a 4-byte nop, rewritten to `pause`.
//!
//! Before the patch, or on a kernel that cannot patch, every site runs its
//! linked form, correct on every RV64A hart (an LR/SC and an AMOCAS may meet
//! on one word: both are atomic on it). The instructions are emitted with
//! `.option arch` inside each asm block, so no codegen flag changes.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use azos_arch_api::isa::{riscv64 as policy, ExtPolicy};
use azos_arch_api::spin::{SITE_KEY_CAS, SITE_KEY_RELAX, SITE_KEY_WAIT, SITE_KIND_RV_ALT};
use azos_arch_api::{CasOrder, SpinWait};

/// The boot's verdicts ([`select`]): the input of the boot patcher and the
/// `[ISA]` line. No lock path reads them.
static ZACAS_OK: AtomicBool = AtomicBool::new(false);
static ZAWRS_OK: AtomicBool = AtomicBool::new(false);
static PAUSE_OK: AtomicBool = AtomicBool::new(false);

/// `amocas` in use on this boot once the boot patch has run.
pub fn zacas_on() -> bool {
    match policy::ZACAS {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => ZACAS_OK.load(Ordering::Relaxed),
    }
}

/// `wrs.nto` in use on this boot once the boot patch has run.
pub fn zawrs_on() -> bool {
    match policy::ZAWRS {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => ZAWRS_OK.load(Ordering::Relaxed),
    }
}

/// `pause` in use on this boot once the boot patch has run.
pub fn pause_on() -> bool {
    match policy::ZIHINTPAUSE {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => PAUSE_OK.load(Ordering::Relaxed),
    }
}

/// The boot's verdicts as [`select`] left them: (zacas, zawrs, zihintpause).
pub fn verdict() -> (bool, bool, bool) {
    (ZACAS_OK.load(Ordering::Relaxed), ZAWRS_OK.load(Ordering::Relaxed), PAUSE_OK.load(Ordering::Relaxed))
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
/// Zacas and Zawrs are executed once under a private trap vector; a verdict
/// is set only for a claim that executed correctly. `pause` is a HINT (a
/// fence with no successor where absent): the claim is the verdict.
pub fn select(dt_zacas: bool, dt_zawrs: bool, dt_pause: bool) -> Verdict {
    let zacas = dt_zacas && probe::zacas_works();
    let zawrs = dt_zawrs && probe::zawrs_works();
    ZACAS_OK.store(zacas, Ordering::Relaxed);
    ZAWRS_OK.store(zawrs, Ordering::Relaxed);
    PAUSE_OK.store(dt_pause, Ordering::Relaxed);
    Verdict { zacas, zawrs, zacas_refuted: dt_zacas && !zacas, zawrs_refuted: dt_zawrs && !zawrs }
}

/// `require`: `amocas.w{,.aq,.rl,.aqrl}` / `amocas.d...` inline. `rd`
/// holds the compare value in and the old value out.
macro_rules! amocas {
    ($insn:expr, $a:expr, $rd:expr, $new:expr) => {{
        let mut rd: u64 = $rd;
        // SAFETY: `$a` is a valid, aligned atomic word (a reference); Zacas
        // is `require` (a hart without it is refused at boot).
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

/// `probe`: one boot-once CAS site. Linked `jal zero` to the LR/SC loop
/// after the function (`.subsection 1`); the table entry carries the
/// `amocas` the assembler encoded with this site's registers and 0 (the
/// linked word is a branch). `rd` in: the compare value (sign-extended for
/// `.w`, as `lr.w` loads); out: the old value.
macro_rules! cas_site {
    ($lr:expr, $sc:expr, $amocas:expr, $a:expr, $rd:expr, $new:expr) => {{
        let mut rd: u64 = $rd;
        // SAFETY: `$a` is a valid, aligned atomic word (a reference). The
        // linked form is the LR/SC loop, correct on every RV64A hart; the
        // boot writes the `amocas` only on a hart whose probe executed it.
        unsafe {
            core::arch::asm!(
                ".option push",
                ".option norvc",
                ".option norelax",
                "2: jal zero, 4f",
                ".option pop",
                "5:",
                ".subsection 1",
                concat!("4: ", $lr, " {t}, ({addr})"),
                "bne {t}, {rd}, 6f",
                concat!($sc, " {t2}, {new}, ({addr})"),
                "bnez {t2}, 4b",
                "6: mv {rd}, {t}",
                "j 5b",
                ".subsection 0",
                ".pushsection .azos_keys, \"a\"",
                ".balign 8",
                ".8byte 2b",
                ".option push",
                ".option norvc",
                ".option arch, +zacas",
                concat!($amocas, " {rd}, {new}, ({addr})"),
                ".option pop",
                ".4byte 0",
                ".4byte {key}",
                ".4byte {kind}",
                ".popsection",
                rd = inout(reg) rd,
                new = in(reg) $new,
                addr = in(reg) $a,
                t = out(reg) _,
                t2 = out(reg) _,
                key = const SITE_KEY_CAS,
                kind = const SITE_KIND_RV_ALT,
                options(nostack),
            );
        }
        rd
    }};
}

/// One CAS of `width` ("w"/"d") and `order`, by policy. `rd` is the
/// compare value as the register holds it.
macro_rules! cas_by_policy {
    ($w:literal, $a:expr, $rd:expr, $new:expr, $order:expr) => {
        match ($order, policy::ZACAS) {
            (CasOrder::Relaxed, ExtPolicy::Require) => Some(amocas!(concat!("amocas.", $w), $a, $rd, $new)),
            (CasOrder::Acquire, ExtPolicy::Require) => Some(amocas!(concat!("amocas.", $w, ".aq"), $a, $rd, $new)),
            (CasOrder::Release, ExtPolicy::Require) => Some(amocas!(concat!("amocas.", $w, ".rl"), $a, $rd, $new)),
            (CasOrder::AcqRel, ExtPolicy::Require) => Some(amocas!(concat!("amocas.", $w, ".aqrl"), $a, $rd, $new)),
            (CasOrder::Relaxed, ExtPolicy::Probe) => Some(cas_site!(concat!("lr.", $w), concat!("sc.", $w),
                concat!("amocas.", $w), $a, $rd, $new)),
            (CasOrder::Acquire, ExtPolicy::Probe) => Some(cas_site!(concat!("lr.", $w, ".aq"), concat!("sc.", $w),
                concat!("amocas.", $w, ".aq"), $a, $rd, $new)),
            (CasOrder::Release, ExtPolicy::Probe) => Some(cas_site!(concat!("lr.", $w), concat!("sc.", $w, ".rl"),
                concat!("amocas.", $w, ".rl"), $a, $rd, $new)),
            (CasOrder::AcqRel, ExtPolicy::Probe) => Some(cas_site!(concat!("lr.", $w, ".aq"), concat!("sc.", $w, ".rl"),
                concat!("amocas.", $w, ".aqrl"), $a, $rd, $new)),
            (_, ExtPolicy::Never) => None,
        }
    };
}

/// `require`: `lr` the word, and stall in `wrs.nto` while it still holds
/// `expected` and the reservation stands (Linux's `__cmpwait`). Another
/// hart's store breaks the reservation; a pending interrupt, enabled or
/// not, ends the stall too. `probe`: the same with the `wrs.nto` a
/// boot-once site, linked as the 4-byte nop.
macro_rules! lr_wrs {
    ($lr:literal, $a:expr, $expected:expr) => {{
        match policy::ZAWRS {
            // SAFETY: `$a` is a valid, aligned word; Zawrs is `require`.
            // The reservation left behind is harmless.
            ExtPolicy::Require => unsafe {
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
            },
            // SAFETY: as above; the site is a nop until the boot writes the
            // `wrs.nto` on a hart whose probe executed it.
            ExtPolicy::Probe => unsafe {
                core::arch::asm!(
                    concat!($lr, " {t}, ({addr})"),
                    "bne {t}, {e}, 3f",
                    ".option push",
                    ".option norvc",
                    ".option norelax",
                    "2: addi zero, zero, 0",
                    ".option pop",
                    "3:",
                    ".pushsection .azos_keys, \"a\"",
                    ".balign 8",
                    ".8byte 2b",
                    ".option push",
                    ".option arch, +zawrs",
                    "wrs.nto",
                    ".option pop",
                    ".4byte 0x00000013",
                    ".4byte {key}",
                    ".4byte {kind}",
                    ".popsection",
                    addr = in(reg) $a,
                    e = in(reg) $expected,
                    t = out(reg) _,
                    key = const SITE_KEY_WAIT,
                    kind = const SITE_KIND_RV_ALT,
                    options(nostack, preserves_flags),
                );
            },
            ExtPolicy::Never => {}
        }
    }};
}

impl SpinWait for crate::api_impl::Riscv64 {
    /// Zihintpause `pause` (Kconfig RV_ZIHINTPAUSE): nothing under `n`,
    /// inline under `require`, a boot-once site (a nop until the boot
    /// writes the `pause`) under `probe`.
    #[inline(always)]
    fn cpu_relax(&self) {
        match policy::ZIHINTPAUSE {
            ExtPolicy::Never => {}
            // SAFETY: a hint; no memory, register or flag effect.
            ExtPolicy::Require => unsafe {
                core::arch::asm!(".option push", ".option arch, +zihintpause", "pause", ".option pop",
                                 options(nomem, nostack, preserves_flags));
            },
            // SAFETY: a nop or a hint, and a table entry.
            ExtPolicy::Probe => unsafe {
                core::arch::asm!(
                    ".option push",
                    ".option norvc",
                    ".option norelax",
                    "2: addi zero, zero, 0",
                    ".option pop",
                    ".pushsection .azos_keys, \"a\"",
                    ".balign 8",
                    ".8byte 2b",
                    ".option push",
                    ".option arch, +zihintpause",
                    "pause",
                    ".option pop",
                    ".4byte 0x00000013",
                    ".4byte {key}",
                    ".4byte {kind}",
                    ".popsection",
                    key = const SITE_KEY_RELAX,
                    kind = const SITE_KIND_RV_ALT,
                    options(nomem, nostack, preserves_flags),
                );
            },
        }
    }

    #[inline(always)]
    fn cas32(&self, a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> Result<u32, u32> {
        // `.w` compares the low 32 bits; `lr.w` and `amocas.w` sign-extend
        // what they load, so the compare value goes in sign-extended.
        match cas_by_policy!("w", a.as_ptr(), current as i32 as i64 as u64, new, order) {
            Some(old) => {
                let old = old as u32;
                if old == current { Ok(old) } else { Err(old) }
            }
            None => a.compare_exchange(current, new, order.success(), order.failure()),
        }
    }

    #[inline(always)]
    fn cas64(&self, a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> Result<u64, u64> {
        match cas_by_policy!("d", a.as_ptr(), current, new, order) {
            Some(old) => if old == current { Ok(old) } else { Err(old) },
            None => a.compare_exchange(current, new, order.success(), order.failure()),
        }
    }

    #[inline(always)]
    fn wait_hint32(&self, a: &AtomicU32, expected: u32) {
        // `lr.w` sign-extends: compare against the sign-extended value.
        lr_wrs!("lr.w", a.as_ptr(), expected as i32 as i64);
        if !matches!(policy::ZAWRS, ExtPolicy::Require) {
            self.cpu_relax();
        }
    }

    #[inline(always)]
    fn wait_hint64(&self, a: &AtomicU64, expected: u64) {
        lr_wrs!("lr.d", a.as_ptr(), expected);
        if !matches!(policy::ZAWRS, ExtPolicy::Require) {
            self.cpu_relax();
        }
    }

    /// `li`; `amoswap.w.aq` (base A: every hart, no probe); `bnez` to a
    /// `call t0, azos_spin_tas_tramp32` placed after the function. The
    /// trampoline saves every caller-saved register, so the site clobbers
    /// only `t0` (the link) and the swap's result register.
    #[inline(always)]
    fn tas_acquire32(&self, a: &AtomicU32) {
        // SAFETY: `a` is a valid, aligned atomic word (a reference, in t1).
        // The slow path's trampoline preserves every register but t0 and
        // keeps sp 16-aligned; it uses the stack (no `nostack`).
        unsafe {
            core::arch::asm!(
                "amoswap.w.aq {t}, {one}, (t1)",
                "bnez {t}, 3f",
                "2:",
                ".subsection 1",
                "3: call t0, azos_spin_tas_tramp32",
                "j 2b",
                ".subsection 0",
                in("t1") a.as_ptr(),
                one = in(reg) 1u32,
                t = out(reg) _,
                out("t0") _,
            );
        }
    }

    /// `li`; `amoor.w.aq t2` (base A: every hart, no probe); `bnez` to the
    /// same `call t0, azos_spin_tas_tramp32` as `tas_acquire32`, which hands
    /// the old word (t2) to the queued lock's slow half. The cost of the
    /// test-and-set site, instruction for instruction.
    #[inline(always)]
    fn qlock_acquire32(&self, a: &AtomicU32) {
        // SAFETY: as `tas_acquire32`; the trampoline reads t1 and t2.
        unsafe {
            core::arch::asm!(
                "amoor.w.aq t2, {one}, (t1)",
                "bnez t2, 3f",
                "2:",
                ".subsection 1",
                "3: call t0, azos_spin_tas_tramp32",
                "j 2b",
                ".subsection 0",
                in("t1") a.as_ptr(),
                one = in(reg) 1u32,
                out("t2") _,
                out("t0") _,
            );
        }
    }

    /// `fence rw,w; sb zero`: a release store of the low byte, no sub-word
    /// AMO (no Zabha).
    #[inline(always)]
    fn unlock_low_byte32(&self, a: &AtomicU32) {
        // SAFETY: `a` is a valid, aligned word; byte 0 is its low byte
        // (little-endian). Not `nomem`: a compiler barrier as well.
        unsafe {
            core::arch::asm!(
                "fence rw, w",
                "sb zero, 0({p})",
                p = in(reg) a.as_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }

    fn boot_site_wanted(&self, key: u32) -> bool {
        let (zacas, zawrs, pause) = verdict();
        match key {
            SITE_KEY_CAS => matches!(policy::ZACAS, ExtPolicy::Probe) && zacas,
            SITE_KEY_WAIT => matches!(policy::ZAWRS, ExtPolicy::Probe) && zawrs,
            SITE_KEY_RELAX => matches!(policy::ZIHINTPAUSE, ExtPolicy::Probe) && pause,
            _ => false,
        }
    }
}

/// [`SpinWait::tas_acquire32`]'s (or, under Kconfig `SPINLOCK_IMPL` = mcs,
/// [`SpinWait::qlock_acquire32`]'s) contended half for this ISA, called by
/// the trampoline below with the word in a0 and the RMW's old value in a1.
#[no_mangle]
extern "C" fn azos_spin_tas_slow32(a: &AtomicU32, old: u32) {
    azos_arch_api::spin::lock_slow32(&crate::api_impl::RISCV64, a, old)
}

// `azos_spin_tas_tramp32`: entered by `call t0, ...` with the word in t1;
// saves ra, t0-t6 and a0-a7 (every caller-saved integer register; the
// kernel is soft-float), calls `azos_spin_tas_slow32(t1, t2)` (t2: the
// queued lock's old word; unused by the test-and-set), restores them
// and returns through t0. 128 bytes of stack, 16-aligned.
core::arch::global_asm!(
    ".pushsection .text.azos_spin_tas_tramp32, \"ax\"",
    ".globl azos_spin_tas_tramp32",
    ".p2align 2",
    "azos_spin_tas_tramp32:",
    "    addi sp, sp, -128",
    "    sd   ra, 0(sp)",
    "    sd   t0, 8(sp)",
    "    sd   t1, 16(sp)",
    "    sd   t2, 24(sp)",
    "    sd   t3, 32(sp)",
    "    sd   t4, 40(sp)",
    "    sd   t5, 48(sp)",
    "    sd   t6, 56(sp)",
    "    sd   a0, 64(sp)",
    "    sd   a1, 72(sp)",
    "    sd   a2, 80(sp)",
    "    sd   a3, 88(sp)",
    "    sd   a4, 96(sp)",
    "    sd   a5, 104(sp)",
    "    sd   a6, 112(sp)",
    "    sd   a7, 120(sp)",
    "    mv   a0, t1",
    "    mv   a1, t2",
    "    call azos_spin_tas_slow32",
    "    ld   ra, 0(sp)",
    "    ld   t0, 8(sp)",
    "    ld   t1, 16(sp)",
    "    ld   t2, 24(sp)",
    "    ld   t3, 32(sp)",
    "    ld   t4, 40(sp)",
    "    ld   t5, 48(sp)",
    "    ld   t6, 56(sp)",
    "    ld   a0, 64(sp)",
    "    ld   a1, 72(sp)",
    "    ld   a2, 80(sp)",
    "    ld   a3, 88(sp)",
    "    ld   a4, 96(sp)",
    "    ld   a5, 104(sp)",
    "    ld   a6, 112(sp)",
    "    ld   a7, 120(sp)",
    "    addi sp, sp, 128",
    "    jr   t0",
    ".popsection",
);

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
