// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot helpers for early aarch64 init.
//!
//! Today this module exposes a single helper, [`drop_to_el1`], the
//! EL2→EL1 trampoline that's needed before any GICv3 sysreg /
//! generic-timer / MMU programming runs at EL1 on QEMU virt and
//! similar bare-metal entry environments where firmware (or QEMU
//! itself) drops the kernel at EL2 by default.
//!
//! Lifted out of `tests/qemu/aarch64-smoke/src/main.rs` so the kernel
//! and any future bare-metal binary that links against
//! `arch-aarch64` can share the same one-shot trampoline instead of
//! reimplementing it. The asm body is the same as the one that the
//! aarch64-smoke demo has been booting through since B1.gic.smp.real.

#[cfg(target_arch = "aarch64")]
use core::arch::global_asm;

// EL2→EL1 trampoline. Called via `bl _azos_drop_to_el1` from EL2
// code; the asm preserves the caller's LR, programs the minimum
// set of sysregs EL1 needs to run safely, then ERETs into EL1 at
// the saved LR. Clobbers x10 only — AAPCS-clean.
//
// Sysreg setup, in order:
//   HCR_EL2.RW=1               EL1 runs in AArch64
//   HCR_EL2 other bits = 0     defends vs stale TGE / E2H
//   CPTR_EL2 = 0x22FF          RES1 bits set, every trap bit clear:
//                              FP/SIMD, SVE and SME not trapped to
//                              EL2 (B2-07 — see comment below)
//   CNTHCTL_EL2 EL1PCEN+PCTEN  EL1 may use the physical counter/timer (the
//                              kernel itself runs on the VIRTUAL ones, which
//                              EL1 reaches without any grant; kept so a
//                              parked or foreign EL1 payload is unaffected)
//   CNTVOFF_EL2 = CNTVOFF_INIT 0 — virtual count == physical count. The
//                              kernel does not depend on it (it reads
//                              CNTVCT_EL0, as ring 3 does); only the
//                              `cntvoff-canary` feature sets it nonzero
//   ICC_SRE_EL2 SRE+Enable=1   EL1 may use GICv3 sysregs
//   SCTLR_EL1 = 0x30450838     reserved-bits mask, MMU off, SPAN=0 (O3.2)
//   CPACR_EL1.FPEN = 0b11      EL0/EL1 may use FP/SIMD/NEON
//   SPSR_EL2 = 0x3C5           EL1h, DAIF masked
//   ELR_EL2 = LR               return into caller at EL1
//   eret
/// `CNTVOFF_EL2` as `_azos_drop_to_el1` leaves it: 0 — and a large nonzero
/// offset under `cntvoff-canary`, the stand-in for firmware or a hypervisor
/// that set one. A kernel stamping with the physical count while ring 3's
/// vDSO reads the virtual one then disagrees with itself by this much,
/// which the captest sensor-stamp row and the tick row both see.
#[cfg(target_arch = "aarch64")]
const CNTVOFF_INIT: u64 = if cfg!(feature = "cntvoff-canary") { 2_000_000 } else { 0 };

#[cfg(target_arch = "aarch64")]
global_asm!(r#"
.section .text.azos_boot, "ax"
.globl _azos_drop_to_el1
_azos_drop_to_el1:
    // HCR_EL2 = 0x8000_0000 exactly (RW=1, everything else 0).
    movz    x10, #0x8000, lsl #16
    msr     HCR_EL2, x10

    // CPTR_EL2 — B2-07. This target is hard-float
    // (aarch64-unknown-none, owner decision 97: NEON is mandatory
    // at the ARMv8.5 baseline), so the compiler emits FP/SIMD
    // instructions anywhere — memcpy included. CPTR_EL2 resets with
    // TFP=1 on some implementations; if it did, the very first FP
    // instruction at EL1 would trap straight back into an EL2 that
    // has no VBAR_EL2 set (nothing runs here after this trampoline
    // returns), and hang exactly like the HVC-from-EL1 case this
    // wave also fixes in psci.rs.
    //
    // 0x22FF is exactly Linux's RES1 mask for non-VHE (HCR_EL2.E2H=0,
    // our case), quoted from arch/arm64/include/asm/kvm_arm.h:
    //
    //     #define CPTR_NVHE_EL2_RES1  (BIT(13) | BIT(9) | GENMASK(7, 0))
    //
    // i.e. bits 13, 9 and 7:0 are RES1 and must be written as 1. Every
    // trap bit is outside that mask and therefore written 0:
    // TCPAC[31], TAM[30], TTA[20], TSM[12] (SME), TFP[10], TZ[8] (SVE).
    // SVE and SME are then governed at EL1 by CPACR_EL1.ZEN/SMEN, which
    // the write below leaves at 0b00 — so a stray SVE or SME instruction
    // traps to OUR EL1 vector, where it can be reported, not to an EL2
    // with no vector, where it would hang.
    //
    // **This was 0x30FF for one revision (2026-09-21) and it was wrong
    // twice:** bit 9 is RES1 and was written 0, and bit 12 is TSM, so
    // SME WAS trapped to EL2 — the opposite of what the comment then
    // claimed. The comment also misquoted the Linux line above (BIT(12)
    // in place of BIT(9)) and cited a `CPTR_EL2_DEFAULT` that does not
    // exist in current Linux. QEMU passed it anyway: it neither enforces
    // RES1 bits nor, with `-cpu max`, reaches an SME instruction here.
    //
    // QEMU resets CPTR_EL2 benignly, so no QEMU run can make this fix
    // fail without it. The evidence is the architectural mask above.
    movz    x10, #0x22FF
    msr     CPTR_EL2, x10

    mrs     x10, CNTHCTL_EL2
    orr     x10, x10, #3            // EL1PCTEN | EL1PCEN
    msr     CNTHCTL_EL2, x10
    movz    x10, #{off2}, lsl #32
    movk    x10, #{off1}, lsl #16
    movk    x10, #{off0}
    msr     CNTVOFF_EL2, x10

    mov     x10, #1                 // ICC_SRE_EL2.SRE
    orr     x10, x10, #(1 << 3)     // ICC_SRE_EL2.Enable
    msr     S3_4_C12_C9_5, x10      // ICC_SRE_EL2
    isb

    // O3.2 (owner decision, PAN): SPAN (bit 23) cleared — 0x30C5 -> 0x3045
    // — so PSTATE.PAN is SET automatically on every EL0->EL1 exception,
    // matching riscv64's SUM starting clear. See sysregs::SCTLR_EL1_SPAN
    // and sysregs::UserAccess for the read/write side of this.
    //
    // Only when PAN is in use: Kconfig `A64_PAN` not `n` and the core has
    // FEAT_PAN (ID_AA64MMFR1_EL1.PAN != 0). Otherwise SPAN stays 1 (it is
    // RES1 on an Armv8.0 core, and under `n` a cleared SPAN would set PAN on
    // every exception with no UserAccess window ever clearing it) and the
    // SPSR_EL2.PAN bit below stays 0 (RES0 without FEAT_PAN). x11 carries
    // the decision to that write.
    mov     x10, #0x0838            // SCTLR_EL1 reserved-bits mask
    movk    x10, #0x30C5, lsl #16   // SPAN=1
    mov     x11, #0
.if {pan_allowed}
    mrs     x12, ID_AA64MMFR1_EL1
    ubfx    x12, x12, #20, #4
    cbz     x12, 1f
    bic     x10, x10, #(1 << 23)    // SPAN=0
    mov     x11, #(1 << 22)         // SPSR_EL2.PAN=1
1:
.endif
    msr     SCTLR_EL1, x10

    // CPACR_EL1.FPEN = 0b11 (bits [21:20]). Explicit movz with
    // `lsl #16` because `mov #(0b11 << 20)` has no single-immediate
    // encoding and assemblers can silently emit the wrong value.
    movz    x10, #0x30, lsl #16     // 0x30 << 16 = 0x300000 = 0b11 << 20
    msr     CPACR_EL1, x10

    // O3.2: PAN (bit 22) set too, so PAN is ACTIVE from the very first
    // instruction at EL1 — SPAN=0 above only sets PAN on a LATER EL0->EL1
    // exception, which does not help before the first one has ever
    // happened (measured: the pan-probe feature run during early boot,
    // before any task exists, did NOT fault without this — PSTATE.PAN's
    // reset value is not "protected" on its own).
    mov     x10, #0x3C5             // SPSR_EL2 = EL1h, DAIF masked
    orr     x10, x10, x11           // + PAN=1 when PAN is in use (above)
    msr     SPSR_EL2, x10

    msr     ELR_EL2, lr
    eret
"#,
    off0 = const (CNTVOFF_INIT & 0xFFFF) as u16,
    off1 = const ((CNTVOFF_INIT >> 16) & 0xFFFF) as u16,
    off2 = const ((CNTVOFF_INIT >> 32) & 0xFFFF) as u16,
    pan_allowed = const azos_arch_api::isa::aarch64::PAN.allowed() as u8,
);

/// Drop the calling thread from EL2 to EL1.
///
/// On return, the caller is running at EL1h with DAIF masked and a
/// minimal sysreg setup suitable for the existing aarch64 boot
/// path: GICv3 sysregs and the physical timer are accessible,
/// MMU is still off, FP/SIMD trap is cleared. The caller is
/// responsible for checking `CurrentEL` first — calling this from
/// EL1 will either undef-trap or behave undefined-ly.
///
/// # Safety
///
/// - The caller must be running at EL2.
/// - The trampoline reads the link register (LR) on entry and
///   uses it as the EL1 entry point. Any code that wraps this call
///   in inline asm or otherwise mutates LR before the asm body
///   runs will return to the wrong address — call it from a plain
///   Rust callsite that uses the standard AAPCS `bl` lowering.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe fn drop_to_el1() {
    extern "C" {
        fn _azos_drop_to_el1();
    }
    unsafe { _azos_drop_to_el1() }
}

/// Host-build stub so the trait surface compiles cross-target. A
/// non-aarch64 target should never reach this; the panic catches
/// any accidental call (e.g. from a test that forgot to gate the
/// arch crate).
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn drop_to_el1() {
    unreachable!("drop_to_el1() is aarch64-only")
}

/// SPSR_EL1 value used by [`eret_to_el0`]: mode bits = `EL0t`
/// (0b0000), DAIF = 1111 (all four exception classes masked).
/// EL0 may unmask them later if it wants; the kernel side doesn't
/// want to take an unexpected IRQ during the transition itself.
pub const SPSR_EL0T_DAIF_MASKED: u64 = 0x3C0;

/// ERET from EL1 to EL0 with the given user PC + SP. Never
/// returns — execution resumes at `user_pc` in EL0 with
/// `SP_EL0 = user_sp`, `SPSR_EL1 = `[`SPSR_EL0T_DAIF_MASKED`].
///
/// Pure shim around the four-instruction `msr…msr…isb;eret`
/// sequence so any future kernel transitioning to user mode for
/// the first time can call one function instead of re-coding the
/// asm. The caller is responsible for having a valid EL0 mapping
/// at `user_pc` (AP[2:1]=01 for the code page, AP[2:1]=01 for the
/// stack page) — see the L1→L2→L3 split landed by B1.user.split
/// for the canonical setup.
///
/// # Safety
///
/// - Caller must be at EL1.
/// - `user_pc` must be a virtual address mapped EL0-readable +
///   EL0-executable.
/// - `user_sp` must be a 16-byte-aligned virtual address mapped
///   EL0-readable + EL0-writable; AAPCS requires alignment.
/// - There is no way back — any return from `user_pc` to EL1 must
///   go through a trap (SVC, abort, IRQ).
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe fn eret_to_el0(user_pc: u64, user_sp: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "msr SP_EL0, {sp}",
            "msr ELR_EL1, {pc}",
            "msr SPSR_EL1, {spsr}",
            "isb",
            "eret",
            sp = in(reg) user_sp,
            pc = in(reg) user_pc,
            spsr = in(reg) SPSR_EL0T_DAIF_MASKED,
            options(noreturn, nomem, nostack),
        )
    }
}

/// Host-build stub mirroring [`eret_to_el0`].
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn eret_to_el0(_user_pc: u64, _user_sp: u64) -> ! {
    unreachable!("eret_to_el0() is aarch64-only")
}
