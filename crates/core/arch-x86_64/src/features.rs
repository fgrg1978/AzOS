// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 CPU features — SKELETON, in riscv64's three tiers
//! (`crates/core/arch-riscv64/src/cbo.rs`):
//!
//! 1. **Baseline** — Kconfig `X86_64_LEVEL` (`-C target-cpu=x86-64[-vN]`),
//!    the only thing codegen assumes. [`check_baseline`] runs first on the
//!    boot CPU and refuses to boot below it, with a message.
//! 2. **Optional extensions** — [`detect`] probes CPUID once; each user
//!    tests its bit and falls back. Instructions above the baseline are
//!    emitted only inside gated `asm!` (or `#[target_feature]` functions
//!    reached only after the probe), never as a global target-feature.
//! 3. **Per-extension `X86_*` choice** (config/Kconfig.arch: n / probe /
//!    require, `azos_arch_api::isa::x86_64`): n never selects the path,
//!    probe takes this module's answer, require refuses a CPU without it
//!    (the kernel's `[ISA]` boot line, `boot::isa`).

/// What [`detect`] found. One bit per optional extension, with its CPUID
/// source and the fallback its user takes when clear.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86Features {
    /// CPUID.(7,0):EBX[7]. Clear: CR4.SMEP stays off.
    pub smep: bool,
    /// CPUID.(7,0):EBX[20]. Clear: no stac/clac window.
    pub smap: bool,
    /// CPUID.1:ECX[17]. Clear: full TLB flush on every CR3 write.
    pub pcid: bool,
    /// CPUID.(7,0):EBX[10]. Clear: CR4.PGE toggle / CR3 reload.
    pub invpcid: bool,
    /// CPUID.(7,0):EBX[0]. Clear: rdmsr/wrmsr IA32_GS_BASE.
    pub fsgsbase: bool,
    /// CPUID.1:ECX[24]. Clear: LAPIC one-shot count.
    pub tsc_deadline: bool,
    /// CPUID.1:ECX[21]. Clear: xAPIC MMIO.
    pub x2apic: bool,
    /// CPUID.(0xD,1):EAX[0]. Clear: XSAVE.
    pub xsaveopt: bool,
    /// CPUID.(0xD,1):EAX[3]. Clear: XSAVEOPT / XSAVE.
    pub xsaves: bool,
    /// CPUID.(7,0):EBX[5] and XCR0[2:1]. Clear: SSE2 in the Vector impl.
    pub avx2: bool,
    /// CPUID.(7,0):EBX[29]. Clear: portable SHA-256.
    pub sha_ni: bool,
}

/// Probe every optional extension once (boot CPU; APs must match).
pub fn detect() -> X86Features {
    todo!("x86_64: features::detect: CPUID leaves 1, 7/0, 0xD/1 and XGETBV")
}

/// The Kconfig baseline level's CPUID bits (v2: SSE4.2, POPCNT, CMPXCHG16B,
/// LAHF/SAHF; v3: + AVX2, BMI1/2, FMA, MOVBE, LZCNT, XSAVE+OSXSAVE). `Err`
/// names the missing bit; the boot path prints it and halts before any code
/// compiled for the level runs.
pub fn check_baseline() -> Result<(), &'static str> {
    todo!("x86_64: features::check_baseline: CPUID bits of X86_64_LEVEL, refuse to boot below it")
}
