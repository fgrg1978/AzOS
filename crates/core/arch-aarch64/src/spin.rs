// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 [`SpinWait`]: LSE `CAS`/`CASA`/`CASL`/`CASAL` for the CAS and
//! `SWP*` for the exchange
//! (Kconfig A64_LSE), `SEVL`; `WFE`; `LDAXR`; `WFE` for the wait hint
//! (Armv8.0, every core), `ISB` for `cpu_relax` (the trait's default,
//! `core::hint::spin_loop`). The CAS fallback is the trait's provided
//! body: the compiler's LDAXR/STLXR loop at Armv8.0 (this kernel has no
//! outlined atomics), CAS itself when A64_LSE is `require` (+lse).
//!
//! Probe: ID_AA64ISAR0_EL1.Atomic (`features::read_id_regs`), which the
//! architecture defines, so there is no execution probe. Each probe CAS is
//! a boot-once site (Linux's ALTERNATIVE): linked as a `b` to an LDAXR/STXR
//! loop placed after the function (`.subsection 1`), correct on every core,
//! and rewritten once by the kernel's boot patcher, on the boot CPU before
//! any secondary starts, to the `cas*` the assembler encoded with the
//! site's own registers (B and CAS are both single 32-bit instructions;
//! the patch runs before any other PE executes the text). After boot a
//! probe CAS costs what `require` does. A wrong claim (the
//! `spin-ext-claim` canary on a Cortex-A53) is an Undefined Instruction
//! exception at the first lock after the patch.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use azos_arch_api::isa::{aarch64 as policy, ExtPolicy};
use azos_arch_api::spin::SITE_KEY_CAS;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use azos_arch_api::spin::SITE_KIND_A64_ALT;
use azos_arch_api::{CasOrder, SpinWait};

/// The probe's verdict: the boot patcher's input (no lock path reads it).
static LSE_ON: AtomicBool = AtomicBool::new(false);

/// LSE CAS in use on this boot once the boot patch has run.
pub fn lse_on() -> bool {
    match policy::LSE {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => LSE_ON.load(Ordering::Relaxed),
    }
}

/// Boot, the boot CPU, before the secondaries: `lse` is the ID register's
/// answer (or a canary's forced claim). Returns what the boot patch makes
/// the lock paths use.
pub fn select(lse: bool) -> bool {
    let on = policy::LSE.gate(lse);
    LSE_ON.store(on, Ordering::Relaxed);
    lse_on()
}

/// `require`: `cas{,a,l,al}` inline (32-bit `w` or 64-bit `x` registers);
/// the first register holds the compare value in and the old value out.
/// The asm is `cfg(target_arch = "aarch64")` (the crate's rule, lib.rs):
/// on the workspace's other targets every method is the trait's fallback.
#[cfg(target_arch = "aarch64")]
macro_rules! cas {
    ($insn:expr, $r:literal, $ty:ty, $a:expr, $cur:expr, $new:expr) => {{
        let mut old: $ty = $cur;
        // SAFETY: `$a` is a valid, aligned atomic word (a reference); LSE
        // is `require` (+lse codegen; a core without it is refused).
        unsafe {
            core::arch::asm!(
                ".arch_extension lse",
                concat!($insn, " {old:", $r, "}, {new:", $r, "}, [{addr}]"),
                old = inout(reg) old,
                new = in(reg) $new,
                addr = in(reg) $a,
                options(nostack, preserves_flags),
            );
        }
        old
    }};
}

/// `probe`: one boot-once CAS site. Linked `b` to the LL/SC loop after the
/// function; the table entry carries the `cas*` the assembler encoded with
/// this site's registers and 0 (the linked word is a branch).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
macro_rules! cas_site {
    ($ld:expr, $st:expr, $insn:expr, $r:literal, $ty:ty, $a:expr, $cur:expr, $new:expr) => {{
        let mut old: $ty = $cur;
        // SAFETY: `$a` is a valid, aligned atomic word (a reference). The
        // linked form is the LL/SC loop, correct on every core; the boot
        // writes the `cas*` only when ID_AA64ISAR0_EL1 reports LSE.
        unsafe {
            core::arch::asm!(
                "2: b 4f",
                "5:",
                ".subsection 1",
                concat!("4: ", $ld, " {t:", $r, "}, [{addr}]"),
                concat!("cmp {t:", $r, "}, {old:", $r, "}"),
                "b.ne 6f",
                concat!($st, " {t2:w}, {new:", $r, "}, [{addr}]"),
                "cbnz {t2:w}, 4b",
                "b 7f",
                "6: clrex",
                concat!("7: mov {old:", $r, "}, {t:", $r, "}"),
                "b 5b",
                ".subsection 0",
                ".pushsection .azos_keys, \"a\"",
                ".balign 8",
                ".8byte 2b",
                ".arch_extension lse",
                concat!($insn, " {old:", $r, "}, {new:", $r, "}, [{addr}]"),
                ".4byte 0",
                ".4byte {key}",
                ".4byte {kind}",
                ".popsection",
                old = inout(reg) old,
                new = in(reg) $new,
                addr = in(reg) $a,
                t = out(reg) _,
                t2 = out(reg) _,
                key = const SITE_KEY_CAS,
                kind = const SITE_KIND_A64_ALT,
                options(nostack),
            );
        }
        old
    }};
}

/// `require`: `swp{,a,l,al}` inline (`SWP Rs, Rt, [Xn]`: stores `new`,
/// loads the old value).
#[cfg(target_arch = "aarch64")]
macro_rules! swp {
    ($insn:expr, $r:literal, $ty:ty, $a:expr, $new:expr) => {{
        let old: $ty;
        // SAFETY: `$a` is a valid, aligned atomic word; LSE is `require`.
        unsafe {
            core::arch::asm!(
                ".arch_extension lse",
                concat!($insn, " {new:", $r, "}, {old:", $r, "}, [{addr}]"),
                old = out(reg) old,
                new = in(reg) $new,
                addr = in(reg) $a,
                options(nostack, preserves_flags),
            );
        }
        old
    }};
}

/// `probe`: one boot-once SWP site, linked `b` to an LL/SC exchange loop
/// after the function; the table entry carries the `swp*` the assembler
/// encoded with this site's registers.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
macro_rules! swp_site {
    ($ld:expr, $st:expr, $insn:expr, $r:literal, $ty:ty, $a:expr, $new:expr) => {{
        let old: $ty;
        // SAFETY: `$a` is a valid, aligned atomic word. The linked form is
        // the LL/SC loop, correct on every core; the boot writes the `swp*`
        // only when ID_AA64ISAR0_EL1 reports LSE.
        unsafe {
            core::arch::asm!(
                "2: b 4f",
                "5:",
                ".subsection 1",
                concat!("4: ", $ld, " {old:", $r, "}, [{addr}]"),
                concat!($st, " {t2:w}, {new:", $r, "}, [{addr}]"),
                "cbnz {t2:w}, 4b",
                "b 5b",
                ".subsection 0",
                ".pushsection .azos_keys, \"a\"",
                ".balign 8",
                ".8byte 2b",
                ".arch_extension lse",
                concat!($insn, " {new:", $r, "}, {old:", $r, "}, [{addr}]"),
                ".4byte 0",
                ".4byte {key}",
                ".4byte {kind}",
                ".popsection",
                old = out(reg) old,
                new = in(reg) $new,
                addr = in(reg) $a,
                t2 = out(reg) _,
                key = const SITE_KEY_CAS,
                kind = const SITE_KIND_A64_ALT,
                options(nostack, preserves_flags),
            );
        }
        old
    }};
}

/// One exchange by policy and order: `Some(old)` from the LSE paths,
/// `None` for the compiler's LL/SC.
#[cfg(target_arch = "aarch64")]
macro_rules! swp_by_policy {
    ($r:literal, $ty:ty, $a:expr, $new:expr, $order:expr) => {{
        let p = $a;
        match ($order, policy::LSE) {
            (CasOrder::Relaxed, ExtPolicy::Require) => Some(swp!("swp", $r, $ty, p, $new)),
            (CasOrder::Acquire, ExtPolicy::Require) => Some(swp!("swpa", $r, $ty, p, $new)),
            (CasOrder::Release, ExtPolicy::Require) => Some(swp!("swpl", $r, $ty, p, $new)),
            (CasOrder::AcqRel, ExtPolicy::Require) => Some(swp!("swpal", $r, $ty, p, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::Relaxed, ExtPolicy::Probe) => Some(swp_site!("ldxr", "stxr", "swp", $r, $ty, p, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::Acquire, ExtPolicy::Probe) => Some(swp_site!("ldaxr", "stxr", "swpa", $r, $ty, p, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::Release, ExtPolicy::Probe) => Some(swp_site!("ldxr", "stlxr", "swpl", $r, $ty, p, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::AcqRel, ExtPolicy::Probe) => Some(swp_site!("ldaxr", "stlxr", "swpal", $r, $ty, p, $new)),
            _ => None,
        }
    }};
}

/// One CAS by policy and order: `Some(old)` from the LSE paths, `None` for
/// the compiler's LL/SC.
#[cfg(target_arch = "aarch64")]
macro_rules! cas_by_policy {
    ($r:literal, $ty:ty, $a:expr, $cur:expr, $new:expr, $order:expr) => {{
        let p = $a;
        match ($order, policy::LSE) {
            (CasOrder::Relaxed, ExtPolicy::Require) => Some(cas!("cas", $r, $ty, p, $cur, $new)),
            (CasOrder::Acquire, ExtPolicy::Require) => Some(cas!("casa", $r, $ty, p, $cur, $new)),
            (CasOrder::Release, ExtPolicy::Require) => Some(cas!("casl", $r, $ty, p, $cur, $new)),
            (CasOrder::AcqRel, ExtPolicy::Require) => Some(cas!("casal", $r, $ty, p, $cur, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::Relaxed, ExtPolicy::Probe) => Some(cas_site!("ldxr", "stxr", "cas", $r, $ty, p, $cur, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::Acquire, ExtPolicy::Probe) => Some(cas_site!("ldaxr", "stxr", "casa", $r, $ty, p, $cur, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::Release, ExtPolicy::Probe) => Some(cas_site!("ldxr", "stlxr", "casl", $r, $ty, p, $cur, $new)),
            #[cfg(target_os = "none")]
            (CasOrder::AcqRel, ExtPolicy::Probe) => Some(cas_site!("ldaxr", "stlxr", "casal", $r, $ty, p, $cur, $new)),
            _ => None,
        }
    }};
}

impl SpinWait for crate::api_impl::Aarch64 {
    #[inline(always)]
    fn cas32(&self, a: &AtomicU32, current: u32, new: u32, order: CasOrder) -> Result<u32, u32> {
        #[cfg(target_arch = "aarch64")]
        if let Some(old) = cas_by_policy!("w", u32, a.as_ptr(), current, new, order) {
            return if old == current { Ok(old) } else { Err(old) };
        }
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    #[inline(always)]
    fn cas64(&self, a: &AtomicU64, current: u64, new: u64, order: CasOrder) -> Result<u64, u64> {
        #[cfg(target_arch = "aarch64")]
        if let Some(old) = cas_by_policy!("x", u64, a.as_ptr(), current, new, order) {
            return if old == current { Ok(old) } else { Err(old) };
        }
        a.compare_exchange(current, new, order.success(), order.failure())
    }

    #[inline(always)]
    fn swap32(&self, a: &AtomicU32, new: u32, order: CasOrder) -> u32 {
        #[cfg(target_arch = "aarch64")]
        if let Some(old) = swp_by_policy!("w", u32, a.as_ptr(), new, order) {
            return old;
        }
        a.swap(new, order.success())
    }

    #[inline(always)]
    fn swap64(&self, a: &AtomicU64, new: u64, order: CasOrder) -> u64 {
        #[cfg(target_arch = "aarch64")]
        if let Some(old) = swp_by_policy!("x", u64, a.as_ptr(), new, order) {
            return old;
        }
        a.swap(new, order.success())
    }

    /// The swap (an LSE probe site, `SWPA` inline under `require`, an
    /// LDAXR/STXR loop under `n`) and `cbnz` to a `bl
    /// azos_spin_tas_tramp32` placed after the function. The trampoline
    /// saves every caller-saved register, so the site clobbers only x30,
    /// the swap's result and the store-exclusive status.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    #[inline(always)]
    fn tas_acquire32(&self, a: &AtomicU32) {
        // SAFETY (all three): `a` is a valid, aligned atomic word (in x9).
        // The slow path's trampoline preserves every register but x30 and
        // keeps sp 16-aligned; it uses the stack (no `nostack`).
        match policy::LSE {
            ExtPolicy::Require => unsafe {
                core::arch::asm!(
                    ".arch_extension lse",
                    "swpa {one:w}, {t:w}, [x9]",
                    "cbnz {t:w}, 3f",
                    "2:",
                    ".subsection 1",
                    "3: bl azos_spin_tas_tramp32",
                    "b 2b",
                    ".subsection 0",
                    in("x9") a.as_ptr(),
                    one = in(reg) 1u32,
                    t = out(reg) _,
                    out("x30") _,
                );
            },
            // The swap is a boot-once site: linked `bl` to the one shared
            // LL/SC exchange (`azos_spin_swpa_llsc32`: x9 in, w10 out,
            // x16/x17 scratch), rewritten to `swpa ..., w10, [x9]` when
            // ID_AA64ISAR0_EL1 reports LSE. One word per site: no per-site
            // fallback loop in the text.
            ExtPolicy::Probe => unsafe {
                core::arch::asm!(
                    "2: bl azos_spin_swpa_llsc32",
                    "cbnz w10, 3f",
                    "6:",
                    ".subsection 1",
                    "3: bl azos_spin_tas_tramp32",
                    "b 6b",
                    ".subsection 0",
                    ".pushsection .azos_keys, \"a\"",
                    ".balign 8",
                    ".8byte 2b",
                    ".arch_extension lse",
                    "swpa {one:w}, w10, [x9]",
                    ".4byte 0",
                    ".4byte {key}",
                    ".4byte {kind}",
                    ".popsection",
                    in("x9") a.as_ptr(),
                    one = in(reg) 1u32,
                    out("x10") _,
                    out("x16") _,
                    out("x17") _,
                    out("x30") _,
                    key = const SITE_KEY_CAS,
                    kind = const SITE_KIND_A64_ALT,
                );
            },
            ExtPolicy::Never => unsafe {
                core::arch::asm!(
                    "4: ldaxr {t:w}, [x9]",
                    "stxr {t2:w}, {one:w}, [x9]",
                    "cbnz {t2:w}, 4b",
                    "cbnz {t:w}, 3f",
                    "2:",
                    ".subsection 1",
                    "3: bl azos_spin_tas_tramp32",
                    "b 2b",
                    ".subsection 0",
                    in("x9") a.as_ptr(),
                    one = in(reg) 1u32,
                    t = out(reg) _,
                    t2 = out(reg) _,
                    out("x30") _,
                );
            },
        }
    }

    /// The queued lock's fast path: `fetch_or(1)` (Acquire), w10 the old
    /// word. LSE `LDSETA` inline under `require`; an LSE probe site under
    /// `probe`, linked `bl` to the one shared LL/SC form
    /// (`azos_spin_ldseta_llsc32`) and rewritten to `ldseta` at boot; an
    /// inline LDAXR/ORR/STXR loop under `n`. Then `cbnz` to the same `bl
    /// azos_spin_tas_tramp32` as `tas_acquire32`, which hands x9 and w10 to
    /// the slow half.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    #[inline(always)]
    fn qlock_acquire32(&self, a: &AtomicU32) {
        // SAFETY (all three): as `tas_acquire32`; the trampoline reads x9
        // and x10.
        match policy::LSE {
            ExtPolicy::Require => unsafe {
                core::arch::asm!(
                    ".arch_extension lse",
                    "ldseta {one:w}, w10, [x9]",
                    "cbnz w10, 3f",
                    "2:",
                    ".subsection 1",
                    "3: bl azos_spin_tas_tramp32",
                    "b 2b",
                    ".subsection 0",
                    in("x9") a.as_ptr(),
                    one = in(reg) 1u32,
                    out("x10") _,
                    out("x30") _,
                );
            },
            ExtPolicy::Probe => unsafe {
                core::arch::asm!(
                    "2: bl azos_spin_ldseta_llsc32",
                    "cbnz w10, 3f",
                    "6:",
                    ".subsection 1",
                    "3: bl azos_spin_tas_tramp32",
                    "b 6b",
                    ".subsection 0",
                    ".pushsection .azos_keys, \"a\"",
                    ".balign 8",
                    ".8byte 2b",
                    ".arch_extension lse",
                    "ldseta {one:w}, w10, [x9]",
                    ".4byte 0",
                    ".4byte {key}",
                    ".4byte {kind}",
                    ".popsection",
                    in("x9") a.as_ptr(),
                    one = in(reg) 1u32,
                    out("x10") _,
                    out("x16") _,
                    out("x17") _,
                    out("x30") _,
                    key = const SITE_KEY_CAS,
                    kind = const SITE_KIND_A64_ALT,
                );
            },
            ExtPolicy::Never => unsafe {
                core::arch::asm!(
                    "4: ldaxr w10, [x9]",
                    "orr {t:w}, w10, #1",
                    "stxr {t2:w}, {t:w}, [x9]",
                    "cbnz {t2:w}, 4b",
                    "cbnz w10, 3f",
                    "2:",
                    ".subsection 1",
                    "3: bl azos_spin_tas_tramp32",
                    "b 2b",
                    ".subsection 0",
                    in("x9") a.as_ptr(),
                    t = out(reg) _,
                    t2 = out(reg) _,
                    out("x10") _,
                    out("x30") _,
                );
            },
        }
    }

    /// `STLRB wzr`: a release store of the low byte, no sub-word RMW.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn unlock_low_byte32(&self, a: &AtomicU32) {
        // SAFETY: `a` is a valid, aligned word; byte 0 is its low byte
        // (little-endian). Not `nomem`: a compiler barrier as well.
        unsafe {
            core::arch::asm!(
                "stlrb wzr, [{p}]",
                p = in(reg) a.as_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }

    fn boot_site_wanted(&self, key: u32) -> bool {
        key == SITE_KEY_CAS && matches!(policy::LSE, ExtPolicy::Probe) && LSE_ON.load(Ordering::Relaxed)
    }

    /// `SEVL; WFE` empties the event register, `LDAXR` arms the exclusive
    /// monitor on the word, and the second `WFE` sleeps until a wake-up
    /// event: another observer's store clearing the monitor, a SEV, the
    /// generic timer's event stream if enabled, or an interrupt PSTATE does
    /// not mask (under `lock_irqsave` only the store wakes it, which is the
    /// release this waits for). Linux arm64's `__cmpwait`.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn wait_hint32(&self, a: &AtomicU32, expected: u32) {
        // SAFETY: `a` is a valid, aligned word; the monitor left armed is
        // harmless (the next exclusive or exception clears it).
        unsafe {
            core::arch::asm!(
                "sevl",
                "wfe",
                "ldaxr {t:w}, [{addr}]",
                "eor {t:w}, {t:w}, {e:w}",
                "cbnz {t:w}, 2f",
                "wfe",
                "2:",
                addr = in(reg) a.as_ptr(),
                e = in(reg) expected,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn wait_hint64(&self, a: &AtomicU64, expected: u64) {
        // SAFETY: as `wait_hint32`.
        unsafe {
            core::arch::asm!(
                "sevl",
                "wfe",
                "ldaxr {t:x}, [{addr}]",
                "eor {t:x}, {t:x}, {e:x}",
                "cbnz {t:x}, 2f",
                "wfe",
                "2:",
                addr = in(reg) a.as_ptr(),
                e = in(reg) expected,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// [`SpinWait::tas_acquire32`]'s contended half for this ISA, called by the
/// trampoline below with the word in x0 and, for
/// [`SpinWait::qlock_acquire32`] (Kconfig `SPINLOCK_IMPL` = mcs), the old
/// word in w1.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
extern "C" fn azos_spin_tas_slow32(a: &AtomicU32, old: u32) {
    azos_arch_api::spin::lock_slow32(&crate::api_impl::AARCH64, a, old)
}

// `azos_spin_swpa_llsc32`: the linked form of every `tas_acquire32` probe
// site, `swpa 1, w10, [x9]` on any core: an LDAXR/STXR loop. Clobbers only
// w10 (the old value), x16, x17.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
core::arch::global_asm!(
    ".pushsection .text.azos_spin_swpa_llsc32, \"ax\"",
    ".globl azos_spin_swpa_llsc32",
    ".p2align 2",
    "azos_spin_swpa_llsc32:",
    "    mov  w17, #1",
    "1:  ldaxr w10, [x9]",
    "    stxr w16, w17, [x9]",
    "    cbnz w16, 1b",
    "    ret",
    ".popsection",
);

// `azos_spin_ldseta_llsc32`: the linked form of every `qlock_acquire32`
// probe site, `ldseta 1, w10, [x9]` on any core: an LDAXR/ORR/STXR loop.
// Clobbers only w10 (the old value), x16, x17.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
core::arch::global_asm!(
    ".pushsection .text.azos_spin_ldseta_llsc32, \"ax\"",
    ".globl azos_spin_ldseta_llsc32",
    ".p2align 2",
    "azos_spin_ldseta_llsc32:",
    "1:  ldaxr w10, [x9]",
    "    orr  w17, w10, #1",
    "    stxr w16, w17, [x9]",
    "    cbnz w16, 1b",
    "    ret",
    ".popsection",
);

// `azos_spin_tas_tramp32`: entered by `bl` with the word in x9; saves x0-x18
// and x30 (every caller-saved integer register; the kernel is soft-float),
// calls `azos_spin_tas_slow32(x9, w10)` (w10: the queued lock's old
// word), restores them and returns. 160 bytes of
// stack, 16-aligned.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
core::arch::global_asm!(
    ".pushsection .text.azos_spin_tas_tramp32, \"ax\"",
    ".globl azos_spin_tas_tramp32",
    ".p2align 2",
    "azos_spin_tas_tramp32:",
    "    stp x0, x1, [sp, #-160]!",
    "    stp x2, x3, [sp, #16]",
    "    stp x4, x5, [sp, #32]",
    "    stp x6, x7, [sp, #48]",
    "    stp x8, x9, [sp, #64]",
    "    stp x10, x11, [sp, #80]",
    "    stp x12, x13, [sp, #96]",
    "    stp x14, x15, [sp, #112]",
    "    stp x16, x17, [sp, #128]",
    "    stp x18, x30, [sp, #144]",
    "    mov x0, x9",
    "    mov w1, w10",
    "    bl  azos_spin_tas_slow32",
    "    ldp x2, x3, [sp, #16]",
    "    ldp x4, x5, [sp, #32]",
    "    ldp x6, x7, [sp, #48]",
    "    ldp x8, x9, [sp, #64]",
    "    ldp x10, x11, [sp, #80]",
    "    ldp x12, x13, [sp, #96]",
    "    ldp x14, x15, [sp, #112]",
    "    ldp x16, x17, [sp, #128]",
    "    ldp x18, x30, [sp, #144]",
    "    ldp x0, x1, [sp], #160",
    "    ret",
    ".popsection",
);
