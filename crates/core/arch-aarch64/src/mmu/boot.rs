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
//! It lives in the arch crate so the kernel and any other bare-metal
//! binary that links against `arch-aarch64` share the same one-shot
//! trampoline instead of reimplementing it.

#[cfg(target_arch = "aarch64")]
use core::arch::global_asm;

// EL2→EL1 trampoline. Called via `bl _azos_drop_to_el1` from EL2
// code; the asm preserves the caller's LR, programs the minimum
// set of sysregs EL1 needs to run safely, then ERETs into EL1 at
// the saved LR. Clobbers x10-x12 — AAPCS-clean.
//
// With the hypervisor built in (cargo feature `hv`, Kconfig HV, derived from
// VIRT) EL2 is kept, not given up: VBAR_EL2 points at the resident stub's
// vector table (`ext/hv/stub.rs`), so an HVC from EL1 returns and any other
// trap to EL2 parks with its syndrome recorded, instead of hanging on a vector
// table that did not exist. `azos_hv_state` records that EL2 was kept, and
// SP_EL2 is zeroed (the stub reads it to tell the host's HVC from a trap of a
// guest). Every PE that enters at EL2 takes this trampoline (the primary, and
// each PSCI CPU_ON secondary), so every PE gets the vectors. Without the
// hypervisor none of that is done: VIRT none drops to EL1 as it always did,
// and the stub's code is not in the image.
//
// Sysreg setup, in order:
//   VBAR_EL2 = _azos_hv_vectors the resident stub (above; hypervisor builds only)
//   SP_EL2 = 0                 no guest runs (hypervisor builds only)
//   HCR_EL2.RW=1               EL1 runs in AArch64
//   HCR_EL2.API=APK=1          EL1 may use pointer-authentication keys/insns
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
//   MDCR_EL2 = HPMN            EL1 sees every PMU counter, no debug or PMU
//                              access trapped to EL2 (Linux's __init_el2_debug)
//   ICC_SRE_EL2 SRE+Enable=1   EL1 may use GICv3 sysregs (only where
//                              ID_AA64PFR0_EL1.GIC says they exist)
//   SCTLR_EL1 = SCTLR_EL1_BOOT the boot word (sysregs), MMU off; boot.S
//                              writes it again, with SPAN, on both paths
//   CPACR_EL1.FPEN = 0b11      EL0/EL1 may use FP/SIMD/NEON
//   SPSR_EL2 = 0x3C5           EL1h, DAIF masked (boot.S sets PAN)
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
    // HCR_EL2 = RW | API | APK, everything else 0. API and APK (bits 41, 40)
    // stop EL1's pointer-authentication key writes and PAC instructions from
    // trapping to EL2: with them clear, `azos_cfi_prepare`'s first
    // `msr APIAKeyLo_EL1` took EC=0x18 into the stub and the kernel never
    // printed (QEMU `-cpu max,pauth=on` at EL2). Linux sets the same two bits
    // unconditionally (HCR_HOST_NVHE_FLAGS); both are RES0 without FEAT_PAuth,
    // where the write is ignored.
    movz    x10, #0x300, lsl #32
    movk    x10, #0x8000, lsl #16
    msr     HCR_EL2, x10

.if {hv}
    // Keep EL2: vectors first, so no later instruction here can trap into the
    // void; then the record. MMU off, so a plain byte store (no exclusives).
    adrp    x10, _azos_hv_vectors
    add     x10, x10, :lo12:_azos_hv_vectors
    msr     VBAR_EL2, x10
    adrp    x10, azos_hv_state
    add     x10, x10, :lo12:azos_hv_state
    mov     w11, #1
    strb    w11, [x10]
    // SP_EL2 is "no guest runs" (reset leaves it undefined, and the stub tells
    // a guest's trap from the host's HVC by whether it is zero). The caller
    // returns to EL1 below and sets the SP_EL1 it runs on itself, so this
    // loses nothing. SPSel first: a PE that enters EL2 with SPSel=0 (EL2t,
    // e.g. a PSCI CPU_ON secondary) would otherwise have the write below land
    // in SP_EL0 and leave SP_EL2 undefined, so the host's first HVC would take
    // the guest-exit path through a garbage stack. Nothing below uses the
    // stack, and the eret returns to EL1h.
    msr     SPSel, #1
    mov     x10, #0
    mov     sp, x10
.endif

    // CPTR_EL2 — B2-07. This target is hard-float
    // (aarch64-unknown-none, owner decision 97: NEON is mandatory
    // at the ARMv8.5 baseline), so the compiler emits FP/SIMD
    // instructions anywhere — memcpy included. CPTR_EL2 resets with
    // TFP=1 on some implementations; if it did, the very first FP
    // instruction at EL1 would trap straight back into an EL2 that
    // has no VBAR_EL2 set, and hang exactly like the HVC-from-EL1 case
    // (VBAR_EL2 is set above since step H1, so such a trap would now park
    // with its syndrome recorded instead; still not what we want).
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

    // MDCR_EL2 resets UNKNOWN but for HPMN: TDE would route EL1's debug
    // exceptions to an EL2 with no handler for them, TDA/TDOSA trap the
    // debug registers (`MDSCR_EL1`, written per PE by `init_el0_state`), TPM
    // and TPMCR the PMU (`pmu::start_this_cpu`), and a small HPMN hides
    // counters from EL1. So, as Linux's `__init_el2_debug`: HPMN =
    // PMCR_EL0.N, every trap and every other field 0. PMCR_EL0 exists only
    // with PMUv3: ID_AA64DFR0_EL1.PMUVer [11:8] read signed, so 0 (none)
    // and 0xF (IMPLEMENTATION DEFINED) both skip the read and leave HPMN 0.
    mov     x10, #0
    mrs     x11, ID_AA64DFR0_EL1
    sbfx    x11, x11, #8, #4
    cmp     x11, #0
    b.le    2f
    mrs     x10, PMCR_EL0
    ubfx    x10, x10, #11, #5       // PMCR_EL0.N
2:  msr     MDCR_EL2, x10

    mrs     x10, CNTHCTL_EL2
    orr     x10, x10, #3            // EL1PCTEN | EL1PCEN
    msr     CNTHCTL_EL2, x10
    movz    x10, #{off2}, lsl #32
    movk    x10, #{off1}, lsl #16
    movk    x10, #{off0}
    msr     CNTVOFF_EL2, x10

    // Only where the GICv3 system-register interface exists
    // (ID_AA64PFR0_EL1.GIC [27:24] non-zero): without it ICC_SRE_EL2 is
    // UNDEFINED, and with VBAR_EL2 unset that is a silent hang at EL2. A
    // GICv2 machine or one with no GIC at all (the Raspberry Pi 3's BCM2836
    // local controller) has none; QEMU raspi3b enters here at EL2.
    mrs     x10, ID_AA64PFR0_EL1
    ubfx    x10, x10, #24, #4
    cbz     x10, 1f
    mov     x10, #1                 // ICC_SRE_EL2.SRE
    orr     x10, x10, #(1 << 3)     // ICC_SRE_EL2.Enable
    msr     S3_4_C12_C9_5, x10      // ICC_SRE_EL2
    isb
1:

    // SCTLR_EL1 before the eret: its reset value is UNKNOWN, and an M or A
    // bit set in it would fault the first instruction at EL1. The boot word
    // (sysregs::SCTLR_EL1_BOOT, SPAN 1); boot.S writes it again on both entry
    // paths, with SPAN cleared where PAN is in use, before any compiled code.
    movz    x10, #{sctlr_lo}
    movk    x10, #{sctlr_hi}, lsl #16
    msr     SCTLR_EL1, x10

    // CPACR_EL1.FPEN = 0b11 (bits [21:20]). Explicit movz with
    // `lsl #16` because `mov #(0b11 << 20)` has no single-immediate
    // encoding and assemblers can silently emit the wrong value.
    movz    x10, #0x30, lsl #16     // 0x30 << 16 = 0x300000 = 0b11 << 20
    msr     CPACR_EL1, x10

    // PSTATE.PAN is set by boot.S after the eret, on both entry paths, under
    // the same probe as SPAN (O3.2).
    mov     x10, #0x3C5             // SPSR_EL2 = EL1h, DAIF masked
    msr     SPSR_EL2, x10

    msr     ELR_EL2, lr
    eret
"#,
    off0 = const (CNTVOFF_INIT & 0xFFFF) as u16,
    off1 = const ((CNTVOFF_INIT >> 16) & 0xFFFF) as u16,
    off2 = const ((CNTVOFF_INIT >> 32) & 0xFFFF) as u16,
    sctlr_lo = const (crate::sysregs::SCTLR_EL1_BOOT & 0xFFFF) as u16,
    sctlr_hi = const ((crate::sysregs::SCTLR_EL1_BOOT >> 16) & 0xFFFF) as u16,
    hv = const cfg!(all(feature = "hv", target_os = "none")) as u8,
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
