// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 CPU features, in riscv64's three tiers
//! (`crates/core/arch-riscv64/src/cache.rs`):
//!
//! 1. **Baseline** — Kconfig `X86_64_LEVEL` (`-C target-cpu=x86-64[-vN]`),
//!    the only thing codegen assumes. `boot.S` checks the level's CPUID bits
//!    before long mode (no Rust compiled for the level has run yet);
//!    [`check_baseline`] repeats the check from Rust and names the first
//!    missing feature, and the boot powers off.
//! 2. **Optional extensions** — [`detect`] reads CPUID once; each user tests
//!    its bit and falls back. Instructions above the baseline are emitted
//!    only inside gated `asm!` (or `#[target_feature]` functions reached only
//!    after the probe), never as a global target-feature.
//! 3. **Per-extension `X86_*` choice** (config/arch/Kconfig.isa: n / probe /
//!    require, `azos_arch_api::isa::x86_64`): n never selects the path,
//!    probe takes this module's answer, require refuses a CPU without it
//!    (the kernel's `[ISA]` boot line, `boot::isa`).
//!
//! The decoding ([`decode`], [`level_missing`]) is pure arithmetic over a
//! [`CpuidLeaves`] snapshot, so a wrong bit index is a host test failure
//! (`tests/host/arch-tests`, which `#[path]`-includes this file: it must
//! name no other crate). Only [`read_cpuid`] executes `cpuid`.
//!
//! # XCR0
//!
//! AVX and AVX-512 also need their register state in XCR0. The probe asks
//! CPUID leaf 0xD sub-leaf 0 which XCR0 bits the CPU can enable
//! ([`CpuidLeaves::xcr0_supported`]), not XGETBV: the kernel programs XCR0
//! itself (the eager FP switch, `fp.rs`), XGETBV raises #UD until
//! CR4.OSXSAVE is set, and this probe runs before either. A CPU that
//! reports AVX2 but cannot enable the YMM state reads as having no AVX2.
//!
//! Leaf 7 sub-leaf 1 carries none of the extensions below (its first users
//! would be AVX-VNNI and LAM), so it is not read.

/// The CPUID words the decoding reads. A leaf above the CPU's maximum reads
/// as zero (Intel returns the highest basic leaf's data for an out-of-range
/// leaf, which must not be decoded as leaf 7).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CpuidLeaves {
    /// CPUID.0:EBX, EDX, ECX — the vendor string's twelve bytes in that order.
    pub l0_vendor: [u32; 3],
    /// CPUID.1:EAX — stepping, model and family.
    pub l1_eax: u32,
    /// CPUID.1:ECX.
    pub l1_ecx: u32,
    /// CPUID.1:EDX.
    pub l1_edx: u32,
    /// CPUID.(7,0):EBX.
    pub l7_ebx: u32,
    /// CPUID.(7,0):ECX.
    pub l7_ecx: u32,
    /// CPUID.(7,0):EDX.
    pub l7_edx: u32,
    /// CPUID.(7,2):EDX — the Intel mitigation-control bits (BHI_CTRL). Zero
    /// where the CPU has fewer than three sub-leaves.
    pub l7_2_edx: u32,
    /// CPUID.(0xD,0):EDX:EAX — the XCR0 bits the CPU can enable.
    pub xcr0_supported: u64,
    /// CPUID.(0xD,1):EAX.
    pub ld1_eax: u32,
    /// CPUID.0x80000001:ECX.
    pub e1_ecx: u32,
    /// CPUID.0x80000001:EDX.
    pub e1_edx: u32,
    /// CPUID.0x80000007:EDX.
    pub e7_edx: u32,
    /// CPUID.0x80000008:EBX — AMD's branch-prediction control bits and
    /// INVLPGB (bit 3).
    pub e8_ebx: u32,
    /// CPUID.0x80000008:EDX — AMD's INVLPGB page-count limit in bits 15:0.
    pub e8_edx: u32,
    /// CPUID.0x80000021:EAX — AMD's AutoIBRS, SBPB and SRSO bits.
    pub e21_eax: u32,
}

impl CpuidLeaves {
    /// Every word zero (`Default`, as a constant).
    pub const ZERO: Self = Self {
        l0_vendor: [0; 3], l1_eax: 0, l1_ecx: 0, l1_edx: 0, l7_ebx: 0, l7_ecx: 0, l7_edx: 0,
        l7_2_edx: 0, xcr0_supported: 0, ld1_eax: 0, e1_ecx: 0, e1_edx: 0, e7_edx: 0, e8_ebx: 0,
        e8_edx: 0, e21_eax: 0,
    };
}

// CPUID bit positions (Intel SDM Vol. 2A, CPUID; Linux cpufeatures.h).
mod bit {
    // CPUID.1:ECX
    pub const SSE3: u32 = 0;
    pub const PCLMULQDQ: u32 = 1;
    pub const SSSE3: u32 = 9;
    pub const FMA: u32 = 12;
    pub const CX16: u32 = 13;
    pub const PCID: u32 = 17;
    pub const SSE4_1: u32 = 19;
    pub const SSE4_2: u32 = 20;
    pub const X2APIC: u32 = 21;
    pub const MOVBE: u32 = 22;
    pub const POPCNT: u32 = 23;
    pub const TSC_DEADLINE: u32 = 24;
    pub const AES: u32 = 25;
    pub const XSAVE: u32 = 26;
    pub const AVX: u32 = 28;
    pub const F16C: u32 = 29;
    pub const RDRAND: u32 = 30;
    // CPUID.1:EDX
    pub const SSE2: u32 = 26;
    // CPUID.(7,0):EBX
    pub const FSGSBASE: u32 = 0;
    pub const BMI1: u32 = 3;
    pub const AVX2: u32 = 5;
    pub const SMEP: u32 = 7;
    pub const BMI2: u32 = 8;
    pub const INVPCID: u32 = 10;
    pub const AVX512F: u32 = 16;
    pub const AVX512DQ: u32 = 17;
    pub const RDSEED: u32 = 18;
    pub const ADX: u32 = 19;
    pub const SMAP: u32 = 20;
    pub const AVX512CD: u32 = 28;
    pub const SHA: u32 = 29;
    pub const AVX512BW: u32 = 30;
    pub const AVX512VL: u32 = 31;
    // CPUID.(7,0):ECX
    pub const UMIP: u32 = 2;
    pub const PKU: u32 = 3;
    pub const WAITPKG: u32 = 5;
    pub const CET_SS: u32 = 7;
    pub const LA57: u32 = 16;
    pub const RDPID: u32 = 22;
    // CPUID.(7,0):EDX
    pub const CET_IBT: u32 = 20;
    pub const CORE_CAPABILITIES: u32 = 30;
    // CPUID.(0xD,1):EAX
    pub const XSAVEOPT: u32 = 0;
    pub const XSAVES: u32 = 3;
    // CPUID.0x80000001:ECX
    pub const LAHF_LM: u32 = 0;
    pub const LZCNT: u32 = 5;
    // CPUID.0x80000001:EDX
    pub const PDPE1GB: u32 = 26;
    pub const RDTSCP: u32 = 27;
    // CPUID.0x80000007:EDX
    pub const INVARIANT_TSC: u32 = 8;
    // CPUID.0x80000008:EBX (AMD APM Vol. 3, Appendix E; Linux word 13 bit 3)
    pub const INVLPGB: u32 = 3;
}

/// XCR0 components: SSE (1) and AVX/YMM_Hi128 (2).
pub const XCR0_YMM: u64 = 0b110;
/// XCR0 components: opmask (5), ZMM_Hi256 (6), Hi16_ZMM (7).
pub const XCR0_ZMM: u64 = 0b1110_0000;

const fn has(word: u32, b: u32) -> bool {
    word & (1 << b) != 0
}

/// Who made the CPU, from the CPUID vendor string. Only the vendors whose
/// documented microarchitecture bugs and controls this tree knows are named.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Vendor {
    /// Not read (a host build), or a vendor string the tree does not know.
    #[default]
    Unknown,
    Intel,
    Amd,
    /// Hygon's Zen derivative: AMD's bugs and controls, its own string.
    Hygon,
}

impl Vendor {
    pub const fn name(self) -> &'static str {
        match self {
            Vendor::Unknown => "unknown",
            Vendor::Intel => "Intel",
            Vendor::Amd => "AMD",
            Vendor::Hygon => "Hygon",
        }
    }
}

/// The CPU's identity as the SDM and the AMD APM display it: the
/// family/model/stepping of CPUID.1:EAX with the extended fields folded in.
/// It is the last resort of a decision: a mitigation is chosen from the
/// capability bits (CPUID, `IA32_ARCH_CAPABILITIES`) and consults this only
/// for a bug the architecture publishes no bit for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CpuIdent {
    pub vendor: Vendor,
    /// Display family: base, plus the extended family when the base is 0xF.
    pub family: u16,
    /// Display model: the model nibble, with the extended model above it
    /// for family 6 and 0xF and above (the SDM's DisplayModel).
    pub model: u16,
    pub stepping: u8,
}

const fn le_word(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}

/// Decode the vendor string and CPUID.1:EAX.
pub const fn decode_ident(r: &CpuidLeaves) -> CpuIdent {
    let v = r.l0_vendor; // EBX, EDX, ECX
    let vendor = if v[0] == le_word(b"Genu") && v[1] == le_word(b"ineI") && v[2] == le_word(b"ntel") {
        Vendor::Intel
    } else if v[0] == le_word(b"Auth") && v[1] == le_word(b"enti") && v[2] == le_word(b"cAMD") {
        Vendor::Amd
    } else if v[0] == le_word(b"Hygo") && v[1] == le_word(b"nGen") && v[2] == le_word(b"uine") {
        Vendor::Hygon
    } else {
        Vendor::Unknown
    };
    let a = r.l1_eax;
    let base_family = (a >> 8) & 0xF;
    let base_model = (a >> 4) & 0xF;
    let family = if base_family == 0xF { base_family + ((a >> 20) & 0xFF) } else { base_family };
    let model = if base_family == 0x6 || base_family == 0xF { base_model | ((a >> 16) & 0xF) << 4 } else { base_model };
    CpuIdent { vendor, family: family as u16, model: model as u16, stepping: (a & 0xF) as u8 }
}

/// What [`detect`] found. One bit per optional extension, with its CPUID
/// source and the fallback its user takes when clear.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct X86Features {
    /// Vendor, family, model and stepping (CPUID.0, CPUID.1:EAX).
    pub ident: CpuIdent,
    /// CPUID.1:ECX[20] (with SSE3/SSSE3/SSE4.1 below it). User codegen only.
    pub sse4_2: bool,
    /// CPUID.1:ECX[23].
    pub popcnt: bool,
    /// CPUID.1:ECX[28] and XCR0 YMM state. Clear: SSE2.
    pub avx: bool,
    /// CPUID.(7,0):EBX[5] and AVX. Clear: SSE2 in the Vector impl.
    pub avx2: bool,
    /// CPUID.(7,0):EBX[3].
    pub bmi1: bool,
    /// CPUID.(7,0):EBX[8].
    pub bmi2: bool,
    /// CPUID.1:ECX[12] and AVX.
    pub fma: bool,
    /// CPUID.1:ECX[22].
    pub movbe: bool,
    /// CPUID.(7,0):EBX[16] and XCR0 opmask/ZMM state.
    pub avx512f: bool,
    /// CPUID.(7,0):EBX[30] and AVX-512F.
    pub avx512bw: bool,
    /// CPUID.(7,0):EBX[28] and AVX-512F.
    pub avx512cd: bool,
    /// CPUID.(7,0):EBX[17] and AVX-512F.
    pub avx512dq: bool,
    /// CPUID.(7,0):EBX[31] and AVX-512F.
    pub avx512vl: bool,
    /// CPUID.1:ECX[25]. Clear: portable AES.
    pub aes: bool,
    /// CPUID.1:ECX[1]. Clear: table-driven GF(2) multiply.
    pub pclmulqdq: bool,
    /// CPUID.(7,0):EBX[29]. Clear: portable SHA-256.
    pub sha_ni: bool,
    /// CPUID.1:ECX[30]. Clear: the entropy pool's other sources.
    pub rdrand: bool,
    /// CPUID.(7,0):EBX[18].
    pub rdseed: bool,
    /// CPUID.(7,0):EBX[19].
    pub adx: bool,
    /// CPUID.(7,0):EBX[0]. Clear: rdmsr/wrmsr IA32_GS_BASE.
    pub fsgsbase: bool,
    /// CPUID.1:ECX[17]. Clear: full TLB flush on every CR3 write.
    pub pcid: bool,
    /// CPUID.(7,0):EBX[10]. Clear: CR4.PGE toggle / CR3 reload.
    pub invpcid: bool,
    /// CPUID.(7,0):EBX[7]. Clear: CR4.SMEP stays off.
    pub smep: bool,
    /// CPUID.(7,0):EBX[20]. Clear: no stac/clac window.
    pub smap: bool,
    /// CPUID.(7,0):ECX[2]. Clear: SGDT/SIDT/SLDT/SMSW/STR stay legal in ring 3.
    pub umip: bool,
    /// CPUID.(7,0):ECX[3]. Clear: no protection keys.
    pub pku: bool,
    /// CPUID.(7,0):ECX[16]. Clear: 4-level paging (48-bit VA).
    pub la57: bool,
    /// CPUID.(7,0):ECX[5]. Clear: PAUSE loops in `SpinWait` (`spin`).
    pub waitpkg: bool,
    /// CPUID.0x80000001:EDX[26]. Clear: no 1 GiB leaves (2 MiB ones only).
    pub gbpages: bool,
    /// CPUID.(7,0):EDX[20]. Clear: no ENDBR64 enforcement.
    pub cet_ibt: bool,
    /// CPUID.(7,0):ECX[7]. Clear: no shadow stack.
    pub cet_shstk: bool,
    /// CPUID.(7,0):EDX[30]: IA32_CORE_CAPABILITIES (MSR 0xCF) exists. Only the
    /// MSR's bit 5 says split-lock detection does ([`split_lock_supported`]).
    pub core_capabilities: bool,
    /// CPUID.1:ECX[26]. Clear: FXSAVE.
    pub xsave: bool,
    /// CPUID.(0xD,1):EAX[0] and XSAVE. Clear: XSAVE.
    pub xsaveopt: bool,
    /// CPUID.(0xD,1):EAX[3] and XSAVE. Clear: XSAVEOPT / XSAVE.
    pub xsaves: bool,
    /// CPUID.1:ECX[21]. Clear: xAPIC MMIO.
    pub x2apic: bool,
    /// CPUID.1:ECX[24]. Clear: LAPIC one-shot count.
    pub tsc_deadline: bool,
    /// CPUID.0x80000001:EDX[27] (RDTSCP) or CPUID.(7,0):ECX[22] (RDPID):
    /// IA32_TSC_AUX exists, and ring 3 reads it with either instruction.
    /// Clear: the MSR is a #GP.
    pub tsc_aux: bool,
    /// CPUID.0x80000007:EDX[8]. Clear: the TSC may stop or change rate in
    /// deep C/P-states; the clock source must be recalibrated (HPET).
    pub invariant_tsc: bool,
    /// CPUID.0x80000008:EBX[3]: INVLPGB and TLBSYNC (AMD Zen 3 and later).
    /// Clear: TLB shootdowns are IPIs (`tlb`).
    pub invlpgb: bool,
    /// CPUID.0x80000008:EDX[15:0] + 1: the most pages one INVLPGB names
    /// (the field is the count of ADDITIONAL pages). 0 when `invlpgb` is clear.
    pub invlpgb_max_pages: u32,
}

impl X86Features {
    /// Nothing detected: what a host build reads.
    pub const NONE: Self = decode(&CpuidLeaves::ZERO);
}

/// The extensions a CPUID snapshot reports. The vector extensions also need
/// their register state in [`CpuidLeaves::xcr0_supported`], and each one
/// the extension it builds on (AVX2 and FMA on AVX, every AVX-512 subset on
/// AVX-512F): a CPU reporting a bit the OS can never enable reads as absent.
pub const fn decode(r: &CpuidLeaves) -> X86Features {
    let (c1, b7, c7, d7) = (r.l1_ecx, r.l7_ebx, r.l7_ecx, r.l7_edx);
    let xsave = has(c1, bit::XSAVE);
    // Canary (`x86-cpuid-canary`): forget the XCR0 YMM state check, so a
    // CPU that cannot enable YMM still reads as having AVX.
    let ymm = cfg!(feature = "x86-cpuid-canary") || r.xcr0_supported & XCR0_YMM == XCR0_YMM;
    let avx = xsave && ymm && has(c1, bit::AVX);
    let avx512f = avx && r.xcr0_supported & XCR0_ZMM == XCR0_ZMM && has(b7, bit::AVX512F);
    let invlpgb = has(r.e8_ebx, bit::INVLPGB);
    X86Features {
        ident: decode_ident(r),
        sse4_2: has(c1, bit::SSE4_2),
        popcnt: has(c1, bit::POPCNT),
        avx,
        avx2: avx && has(b7, bit::AVX2),
        bmi1: has(b7, bit::BMI1),
        bmi2: has(b7, bit::BMI2),
        fma: avx && has(c1, bit::FMA),
        movbe: has(c1, bit::MOVBE),
        avx512f,
        avx512bw: avx512f && has(b7, bit::AVX512BW),
        avx512cd: avx512f && has(b7, bit::AVX512CD),
        avx512dq: avx512f && has(b7, bit::AVX512DQ),
        avx512vl: avx512f && has(b7, bit::AVX512VL),
        aes: has(c1, bit::AES),
        pclmulqdq: has(c1, bit::PCLMULQDQ),
        sha_ni: has(b7, bit::SHA),
        rdrand: has(c1, bit::RDRAND),
        rdseed: has(b7, bit::RDSEED),
        adx: has(b7, bit::ADX),
        fsgsbase: has(b7, bit::FSGSBASE),
        pcid: has(c1, bit::PCID),
        invpcid: has(b7, bit::INVPCID),
        smep: has(b7, bit::SMEP),
        smap: has(b7, bit::SMAP),
        umip: has(c7, bit::UMIP),
        pku: has(c7, bit::PKU),
        la57: has(c7, bit::LA57),
        waitpkg: has(c7, bit::WAITPKG),
        gbpages: has(r.e1_edx, bit::PDPE1GB),
        cet_ibt: has(d7, bit::CET_IBT),
        cet_shstk: has(c7, bit::CET_SS),
        core_capabilities: has(d7, bit::CORE_CAPABILITIES),
        xsave,
        xsaveopt: xsave && has(r.ld1_eax, bit::XSAVEOPT),
        xsaves: xsave && has(r.ld1_eax, bit::XSAVES),
        x2apic: has(c1, bit::X2APIC),
        tsc_deadline: has(c1, bit::TSC_DEADLINE),
        tsc_aux: has(r.e1_edx, bit::RDTSCP) || has(c7, bit::RDPID),
        invariant_tsc: has(r.e7_edx, bit::INVARIANT_TSC),
        invlpgb,
        invlpgb_max_pages: if invlpgb { (r.e8_edx & 0xFFFF) + 1 } else { 0 },
    }
}

/// IA32_CORE_CAPABILITIES (Intel SDM Vol. 4; Linux `MSR_IA32_CORE_CAPS`).
/// Read only when CPUID.(7,0):EDX[30] says it exists: elsewhere it is #GP.
pub const MSR_IA32_CORE_CAPABILITIES: u32 = 0xCF;
/// IA32_CORE_CAPABILITIES bit 5: the CPU can raise #AC on a split lock.
pub const CORE_CAPS_SPLIT_LOCK_DETECT: u64 = 1 << 5;
/// MSR_TEST_CTRL (Linux `MSR_TEST_CTRL`), present when the bit above is.
pub const MSR_TEST_CTRL: u32 = 0x33;
/// MSR_TEST_CTRL bit 29: a split-locked atomic raises #AC (Kconfig `X86_SPLIT_LOCK`).
pub const TEST_CTRL_SPLIT_LOCK_DETECT: u64 = 1 << 29;
/// CR0.AM (alignment mask): with RFLAGS.AC it enables the ordinary ring-3 #AC.
pub const CR0_AM: u64 = 1 << 18;
/// RFLAGS.AC.
pub const RFLAGS_AC: u64 = 1 << 18;

/// Does this CPU have split-lock detection: the CPUID bit for the MSR, then
/// the MSR's bit 5. `core_caps_msr` is read only when `cpuid_bit` is set (the
/// caller's guard), so an absent MSR never reaches here as a value.
pub const fn split_lock_supported(cpuid_bit: bool, core_caps_msr: u64) -> bool {
    cpuid_bit && core_caps_msr & CORE_CAPS_SPLIT_LOCK_DETECT != 0
}

/// `MSR_TEST_CTRL` with split-lock detection on or off, every other bit as it was.
pub const fn test_ctrl_with_split_lock(v: u64, on: bool) -> u64 {
    if on { v | TEST_CTRL_SPLIT_LOCK_DETECT } else { v & !TEST_CTRL_SPLIT_LOCK_DETECT }
}

/// What an #AC (vector 17) is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcKind {
    /// An atomic that crosses a cache line, caught by `MSR_TEST_CTRL`.
    SplitLock,
    /// The ordinary alignment check (CR0.AM with RFLAGS.AC), or any #AC when
    /// detection is off.
    Alignment,
}

/// Classify an #AC. With detection off it is the ordinary check. With it on
/// it is a split lock unless the interrupted code had the ordinary check
/// armed (CR0.AM and RFLAGS.AC both set), where the two cannot be told apart
/// and the architecture's own meaning wins (Linux's rule). The kernel keeps
/// CR0.AM clear, so there every #AC with detection on is a split lock, even
/// inside a stac/clac window (RFLAGS.AC set).
pub const fn classify_ac(detect_on: bool, cr0: u64, rflags: u64) -> AcKind {
    if detect_on && !(cr0 & CR0_AM != 0 && rflags & RFLAGS_AC != 0) {
        AcKind::SplitLock
    } else {
        AcKind::Alignment
    }
}

/// The first entry of `list` whose feature is absent.
const fn first_absent(list: &[(bool, &'static str)]) -> Option<&'static str> {
    let mut i = 0;
    while i < list.len() {
        if !list[i].0 {
            return Some(list[i].1);
        }
        i += 1;
    }
    None
}

/// The first feature of psABI level `level` (1..=4) the snapshot lacks, as
/// the refusal names it; `None` when the CPU meets the level. v1 is every
/// x86_64 CPU (SSE2 is part of long mode); v2 adds CMPXCHG16B, LAHF/SAHF,
/// POPCNT, SSE3, SSSE3, SSE4.1, SSE4.2; v3 adds XSAVE, AVX, AVX2, BMI1, BMI2,
/// F16C, FMA, LZCNT, MOVBE; v4 adds AVX-512 F, BW, CD, DQ, VL. The same bits
/// `boot.S` tests before long mode.
pub const fn level_missing(r: &CpuidLeaves, level: u8) -> Option<&'static str> {
    let f = decode(r);
    let c1 = r.l1_ecx;
    if !has(r.l1_edx, bit::SSE2) {
        return Some("SSE2");
    }
    if level >= 2 {
        let m = first_absent(&[
            (has(c1, bit::CX16), "CMPXCHG16B"),
            (has(r.e1_ecx, bit::LAHF_LM), "LAHF/SAHF"),
            (f.popcnt, "POPCNT"),
            (has(c1, bit::SSE3), "SSE3"),
            (has(c1, bit::SSSE3), "SSSE3"),
            (has(c1, bit::SSE4_1), "SSE4.1"),
            (f.sse4_2, "SSE4.2"),
        ]);
        if m.is_some() {
            return m;
        }
    }
    if level >= 3 {
        let m = first_absent(&[
            (f.xsave, "XSAVE"),
            (f.avx, "AVX (or its XCR0 YMM state)"),
            (f.avx2, "AVX2"),
            (f.bmi1, "BMI1"),
            (f.bmi2, "BMI2"),
            (has(c1, bit::F16C), "F16C"),
            (f.fma, "FMA"),
            (has(r.e1_ecx, bit::LZCNT), "LZCNT"),
            (f.movbe, "MOVBE"),
        ]);
        if m.is_some() {
            return m;
        }
    }
    if level >= 4 {
        return first_absent(&[
            (f.avx512f, "AVX-512F (or its XCR0 opmask/ZMM state)"),
            (f.avx512bw, "AVX-512BW"),
            (f.avx512cd, "AVX-512CD"),
            (f.avx512dq, "AVX-512DQ"),
            (f.avx512vl, "AVX-512VL"),
        ]);
    }
    None
}

/// Execute `cpuid` for every leaf [`CpuidLeaves`] holds, each guarded by the
/// CPU's maximum basic / extended leaf. Zero everywhere on a host build
/// (`target_os = "none"` is what means "we are the kernel"; a host x86_64
/// test process must not mistake its own CPU for the target's).
pub fn read_cpuid() -> CpuidLeaves {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use core::arch::x86_64::__cpuid_count;
        // CPUID is unprivileged, has no side effects and exists on every
        // x86_64 CPU (a safe intrinsic); leaves above the reported maximum
        // are skipped.
        let q = |leaf: u32, sub: u32| __cpuid_count(leaf, sub);
        let l0 = q(0, 0);
        let max = l0.eax;
        let max_ext = q(0x8000_0000, 0).eax;
        let mut r = CpuidLeaves::default();
        r.l0_vendor = [l0.ebx, l0.edx, l0.ecx];
        let l1 = q(1, 0);
        (r.l1_eax, r.l1_ecx, r.l1_edx) = (l1.eax, l1.ecx, l1.edx);
        if max >= 7 {
            let l7 = q(7, 0);
            (r.l7_ebx, r.l7_ecx, r.l7_edx) = (l7.ebx, l7.ecx, l7.edx);
            // Sub-leaf 2 exists when sub-leaf 0 reports a maximum of 2 or more.
            if l7.eax >= 2 {
                r.l7_2_edx = q(7, 2).edx;
            }
        }
        if max >= 0xD {
            let d0 = q(0xD, 0);
            r.xcr0_supported = (d0.edx as u64) << 32 | d0.eax as u64;
            r.ld1_eax = q(0xD, 1).eax;
        }
        if max_ext >= 0x8000_0001 {
            let e1 = q(0x8000_0001, 0);
            (r.e1_ecx, r.e1_edx) = (e1.ecx, e1.edx);
        }
        if max_ext >= 0x8000_0007 {
            r.e7_edx = q(0x8000_0007, 0).edx;
        }
        if max_ext >= 0x8000_0008 {
            let e8 = q(0x8000_0008, 0);
            (r.e8_ebx, r.e8_edx) = (e8.ebx, e8.edx);
        }
        if max_ext >= 0x8000_0021 {
            r.e21_eax = q(0x8000_0021, 0).eax;
        }
        r
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        CpuidLeaves::default()
    }
}

/// Probe every optional extension once (boot CPU; APs must match).
pub fn detect() -> X86Features {
    decode(&read_cpuid())
}

/// The psABI level the kernel was configured for (Kconfig `X86_64_LEVEL`,
/// passed in by the caller so this file names no other crate), checked on
/// this CPU. `Err` names the first missing feature; the boot path prints it
/// and powers off.
pub fn check_baseline(level: u8) -> Result<(), &'static str> {
    match level_missing(&read_cpuid(), level) {
        None => Ok(()),
        Some(m) => Err(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CPUID.(7,0):EDX[30] only says the MSR exists; bit 5 of the MSR is the
    /// capability, and an absent MSR (cpuid bit clear) never counts.
    #[test]
    fn split_lock_needs_the_cpuid_bit_and_the_msr_bit() {
        let mut r = CpuidLeaves::default();
        assert!(!decode(&r).core_capabilities);
        r.l7_edx = 1 << 30;
        assert!(decode(&r).core_capabilities);
        r.l7_edx = !(1 << 30);
        assert!(!decode(&r).core_capabilities, "a neighbour bit leaked into CORE_CAPABILITIES");
        assert!(split_lock_supported(true, 1 << 5));
        assert!(split_lock_supported(true, u64::MAX));
        assert!(!split_lock_supported(true, !(1 << 5)), "another MSR bit leaked into split-lock");
        assert!(!split_lock_supported(true, 0));
        assert!(!split_lock_supported(false, 1 << 5), "the MSR was believed without its CPUID bit");
    }

    /// MSR_TEST_CTRL bit 29 only; the rest of the register is preserved.
    #[test]
    fn test_ctrl_split_lock_is_bit_29_and_touches_nothing_else() {
        assert_eq!(TEST_CTRL_SPLIT_LOCK_DETECT, 1 << 29);
        assert_eq!(MSR_TEST_CTRL, 0x33);
        assert_eq!(MSR_IA32_CORE_CAPABILITIES, 0xCF);
        let v = (1u64 << 31) | 1;
        let on = test_ctrl_with_split_lock(v, true);
        assert_eq!(on ^ v, 1 << 29);
        assert_eq!(test_ctrl_with_split_lock(on, false), v);
        assert_eq!(test_ctrl_with_split_lock(on, true), on, "idempotent");
        assert_eq!(test_ctrl_with_split_lock(u64::MAX, false), u64::MAX & !(1 << 29));
    }

    /// The #AC decision: off is always the ordinary check; on is a split lock
    /// unless the ordinary check was armed (both CR0.AM and RFLAGS.AC).
    #[test]
    fn an_ac_is_a_split_lock_only_with_detection_on_and_no_armed_alignment_check() {
        use AcKind::*;
        // detection, cr0, rflags
        assert_eq!(classify_ac(false, 0, 0), Alignment);
        assert_eq!(classify_ac(false, CR0_AM, RFLAGS_AC), Alignment);
        assert_eq!(classify_ac(true, 0, 0), SplitLock, "the kernel's usual state");
        assert_eq!(classify_ac(true, 0, RFLAGS_AC), SplitLock, "a stac window with CR0.AM clear");
        assert_eq!(classify_ac(true, CR0_AM, 0), SplitLock);
        assert_eq!(classify_ac(true, CR0_AM, RFLAGS_AC), Alignment, "ring 3 armed the ordinary check");
        // Other bits of either register change nothing.
        assert_eq!(classify_ac(true, !CR0_AM, !RFLAGS_AC), SplitLock);
        assert_eq!(classify_ac(true, u64::MAX, u64::MAX), Alignment);
    }

    /// A v2 CPU: Nehalem-class leaf 1, nothing in leaf 7.
    fn nehalem() -> CpuidLeaves {
        CpuidLeaves {
            l1_ecx: (1 << bit::SSE3) | (1 << bit::SSSE3) | (1 << bit::CX16) | (1 << bit::SSE4_1)
                | (1 << bit::SSE4_2) | (1 << bit::POPCNT),
            l1_edx: 1 << bit::SSE2,
            e1_ecx: 1 << bit::LAHF_LM,
            ..CpuidLeaves::default()
        }
    }

    /// A v3 CPU (Haswell-class) with YMM state.
    fn haswell() -> CpuidLeaves {
        let mut r = nehalem();
        r.l1_ecx |= (1 << bit::FMA) | (1 << bit::MOVBE) | (1 << bit::XSAVE) | (1 << bit::AVX)
            | (1 << bit::F16C);
        r.l7_ebx |= (1 << bit::BMI1) | (1 << bit::AVX2) | (1 << bit::BMI2);
        r.e1_ecx |= 1 << bit::LZCNT;
        r.xcr0_supported = 0b111;
        r
    }

    /// A v4 CPU (Skylake-SP-class) with opmask/ZMM state.
    fn skylake_sp() -> CpuidLeaves {
        let mut r = haswell();
        r.l7_ebx |= (1 << bit::AVX512F) | (1 << bit::AVX512DQ) | (1 << bit::AVX512CD)
            | (1 << bit::AVX512BW) | (1 << bit::AVX512VL);
        r.xcr0_supported = 0b1110_0111;
        r
    }

    fn count(f: X86Features) -> usize {
        [f.sse4_2, f.popcnt, f.avx, f.avx2, f.bmi1, f.bmi2, f.fma, f.movbe, f.avx512f,
         f.avx512bw, f.avx512cd, f.avx512dq, f.avx512vl, f.aes, f.pclmulqdq, f.sha_ni,
         f.rdrand, f.rdseed, f.adx, f.fsgsbase, f.pcid, f.invpcid, f.smep, f.smap, f.umip,
         f.pku, f.la57, f.waitpkg, f.gbpages, f.cet_ibt, f.cet_shstk, f.xsave, f.xsaveopt, f.xsaves, f.x2apic,
         f.tsc_deadline, f.tsc_aux, f.invariant_tsc, f.invlpgb].iter().filter(|&&b| b).count()
    }

    #[test]
    fn each_extension_reads_its_own_bit_and_no_other() {
        // The bit indices are written as literals from the SDM here, not
        // through `bit::`: one bit set at a time turns on exactly one field,
        // so an index off by one names the neighbour and fails.
        let one = |set: fn(&mut CpuidLeaves), get: fn(&X86Features) -> bool, name: &str| {
            let mut r = CpuidLeaves { xcr0_supported: 0b1110_0111, ..CpuidLeaves::default() };
            set(&mut r);
            let f = decode(&r);
            assert!(get(&f), "{name} not read from its bit");
            assert_eq!(count(f), 1, "{name}'s bit turned on another field: {f:?}");
        };
        one(|r| r.l1_ecx = 1 << 20, |f| f.sse4_2, "sse4.2");
        one(|r| r.l1_ecx = 1 << 23, |f| f.popcnt, "popcnt");
        one(|r| r.l7_ebx = 1 << 3, |f| f.bmi1, "bmi1");
        one(|r| r.l7_ebx = 1 << 8, |f| f.bmi2, "bmi2");
        one(|r| r.l1_ecx = 1 << 22, |f| f.movbe, "movbe");
        one(|r| r.l1_ecx = 1 << 25, |f| f.aes, "aes");
        one(|r| r.l1_ecx = 1 << 1, |f| f.pclmulqdq, "pclmulqdq");
        one(|r| r.l7_ebx = 1 << 29, |f| f.sha_ni, "sha");
        one(|r| r.l1_ecx = 1 << 30, |f| f.rdrand, "rdrand");
        one(|r| r.l7_ebx = 1 << 18, |f| f.rdseed, "rdseed");
        one(|r| r.l7_ebx = 1 << 19, |f| f.adx, "adx");
        one(|r| r.l7_ebx = 1 << 0, |f| f.fsgsbase, "fsgsbase");
        one(|r| r.l1_ecx = 1 << 17, |f| f.pcid, "pcid");
        one(|r| r.l7_ebx = 1 << 10, |f| f.invpcid, "invpcid");
        one(|r| r.l7_ebx = 1 << 7, |f| f.smep, "smep");
        one(|r| r.l7_ebx = 1 << 20, |f| f.smap, "smap");
        one(|r| r.l7_ecx = 1 << 2, |f| f.umip, "umip");
        one(|r| r.l7_ecx = 1 << 3, |f| f.pku, "pku");
        one(|r| r.l7_ecx = 1 << 16, |f| f.la57, "la57");
        one(|r| r.l7_ecx = 1 << 5, |f| f.waitpkg, "waitpkg");
        one(|r| r.e1_edx = 1 << 26, |f| f.gbpages, "pdpe1gb");
        one(|r| r.l7_edx = 1 << 20, |f| f.cet_ibt, "cet-ibt");
        one(|r| r.l7_ecx = 1 << 7, |f| f.cet_shstk, "cet-shstk");
        one(|r| r.l1_ecx = 1 << 26, |f| f.xsave, "xsave");
        one(|r| r.l1_ecx = 1 << 21, |f| f.x2apic, "x2apic");
        one(|r| r.l1_ecx = 1 << 24, |f| f.tsc_deadline, "tsc-deadline");
        one(|r| r.e7_edx = 1 << 8, |f| f.invariant_tsc, "invariant-tsc");
        one(|r| r.e8_ebx = 1 << 3, |f| f.invlpgb, "invlpgb");
        one(|r| r.e1_edx = 1 << 27, |f| f.tsc_aux, "rdtscp");
        one(|r| r.l7_ecx = 1 << 22, |f| f.tsc_aux, "rdpid");
    }

    /// INVLPGB is CPUID.0x80000008:EBX[3]. EDX[15:0] is the page-count limit
    /// (additional pages, so +1), never the feature flag: a CPU whose EDX
    /// has bit 3 set but whose EBX does not has no INVLPGB.
    #[test]
    fn invlpgb_is_read_from_ebx_and_its_limit_from_edx() {
        let f = decode(&CpuidLeaves { e8_edx: 1 << 3, ..CpuidLeaves::default() });
        assert!(!f.invlpgb, "EDX[3] was taken for the feature bit");
        assert_eq!(f.invlpgb_max_pages, 0);
        let f = decode(&CpuidLeaves { e8_ebx: 1 << 3, e8_edx: 0x0007 | 0xABCD_0000, ..CpuidLeaves::default() });
        assert!(f.invlpgb);
        assert_eq!(f.invlpgb_max_pages, 8, "limit is EDX[15:0] + 1, upper half ignored");
        let f = decode(&CpuidLeaves { e8_ebx: 1 << 3, e8_edx: 0xFFFF, ..CpuidLeaves::default() });
        assert_eq!(f.invlpgb_max_pages, 65536);
        let f = decode(&CpuidLeaves { e8_ebx: 1 << 3, ..CpuidLeaves::default() });
        assert_eq!(f.invlpgb_max_pages, 1, "a limit field of 0 still names one page");
    }

    #[test]
    fn the_vector_extensions_need_their_xsave_state() {
        let h = haswell();
        assert!(decode(&h).avx && decode(&h).avx2 && decode(&h).fma);
        assert_eq!(decode(&h).avx512f, false);
        // AVX2 reported, but the YMM component cannot be enabled in XCR0:
        // an OS cannot run AVX code, so AVX, AVX2 and FMA read absent.
        let f = decode(&CpuidLeaves { xcr0_supported: 0b011, ..h });
        assert!(!f.avx && !f.avx2 && !f.fma, "AVX without its XCR0 state: {f:?}");
        assert!(f.bmi1 && f.bmi2 && f.movbe, "the integer v3 extensions do not need XCR0");
        // No XSAVE at all: no AVX either, and XSAVEOPT/XSAVES read absent.
        let f = decode(&CpuidLeaves { l1_ecx: h.l1_ecx & !(1 << bit::XSAVE), ld1_eax: 0b1001, ..h });
        assert!(!f.avx && !f.xsaveopt && !f.xsaves, "{f:?}");
        let f = decode(&CpuidLeaves { ld1_eax: 0b1001, ..h });
        assert!(f.xsaveopt && f.xsaves);
        // AVX-512 needs the opmask and both ZMM components.
        let s = skylake_sp();
        assert!(decode(&s).avx512vl);
        let f = decode(&CpuidLeaves { xcr0_supported: 0b0110_0111, ..s });
        assert!(!f.avx512f && !f.avx512bw && !f.avx512vl && f.avx2, "{f:?}");
    }

    #[test]
    fn the_level_check_names_the_first_missing_feature() {
        assert_eq!(level_missing(&CpuidLeaves::default(), 1), Some("SSE2"));
        let n = nehalem();
        assert_eq!(level_missing(&n, 1), None);
        assert_eq!(level_missing(&n, 2), None);
        assert_eq!(level_missing(&n, 3), Some("XSAVE"));
        let no_popcnt = CpuidLeaves { l1_ecx: n.l1_ecx & !(1 << bit::POPCNT), ..n };
        assert_eq!(level_missing(&no_popcnt, 2), Some("POPCNT"));
        assert_eq!(level_missing(&no_popcnt, 1), None, "v1 needs no POPCNT");
        assert_eq!(level_missing(&CpuidLeaves { e1_ecx: 0, ..n }, 2), Some("LAHF/SAHF"));
        let h = haswell();
        assert_eq!(level_missing(&h, 3), None);
        assert_eq!(level_missing(&h, 4), Some("AVX-512F (or its XCR0 opmask/ZMM state)"));
        let no_lzcnt = CpuidLeaves { e1_ecx: h.e1_ecx & !(1 << bit::LZCNT), ..h };
        assert_eq!(level_missing(&no_lzcnt, 3), Some("LZCNT"));
        assert_eq!(level_missing(&CpuidLeaves { xcr0_supported: 1, ..h }, 3),
                   Some("AVX (or its XCR0 YMM state)"));
        let s = skylake_sp();
        assert_eq!(level_missing(&s, 4), None);
        let no_vl = CpuidLeaves { l7_ebx: s.l7_ebx & !(1 << bit::AVX512VL), ..s };
        assert_eq!(level_missing(&no_vl, 4), Some("AVX-512VL"));
    }

    /// The vendor string is EBX, EDX, ECX (in that order) and CPUID.1:EAX packs
    /// stepping, model and family with the extended fields: the extended
    /// family adds only when the base family is 0xF, the extended model joins
    /// only for family 6 and 0xF. The EAX values are those of the CPU models
    /// the q35 gate boots.
    #[test]
    fn the_identity_decodes_vendor_family_model_and_stepping() {
        const INTEL: [u32; 3] = [0x756e_6547, 0x4965_6e69, 0x6c65_746e]; // "Genu" "ineI" "ntel"
        const AMD: [u32; 3] = [0x6874_7541, 0x6974_6e65, 0x444d_4163]; // "Auth" "enti" "cAMD"
        const HYGON: [u32; 3] = [0x6f67_7948, 0x6e65_476e, 0x656e_6975]; // "Hygo" "nGen" "uine"
        let id = |vendor: [u32; 3], eax: u32| {
            decode_ident(&CpuidLeaves { l0_vendor: vendor, l1_eax: eax, ..CpuidLeaves::default() })
        };
        let who = |vendor, family, model, stepping| CpuIdent { vendor, family, model, stepping };
        assert_eq!(id(INTEL, 0x0001_06A3), who(Vendor::Intel, 6, 0x1A, 3), "Nehalem");
        assert_eq!(id(INTEL, 0x0003_06C1), who(Vendor::Intel, 6, 0x3C, 1), "Haswell");
        assert_eq!(id(INTEL, 0x0005_06E3), who(Vendor::Intel, 6, 0x5E, 3), "Skylake-Client");
        assert_eq!(id(INTEL, 0x0008_06F4), who(Vendor::Intel, 6, 0x8F, 4), "Sapphire Rapids");
        assert_eq!(id(AMD, 0x0083_0F10), who(Vendor::Amd, 0x17, 0x31, 0), "EPYC Rome");
        assert_eq!(id(AMD, 0x00A0_0F11), who(Vendor::Amd, 0x19, 0x01, 1), "EPYC Milan");
        assert_eq!(id(AMD, 0x00A1_0F11), who(Vendor::Amd, 0x19, 0x11, 1), "EPYC Genoa");
        assert_eq!(id(HYGON, 0x0090_0F11).vendor, Vendor::Hygon);
        // No extended model below family 6, and no extended family below 0xF.
        assert_eq!(id(INTEL, 0x000F_0540), who(Vendor::Intel, 5, 4, 0));
        assert_eq!(id(INTEL, 0x00F0_0640), who(Vendor::Intel, 6, 4, 0));
        // Anything else, or nothing read, is Unknown (and a swapped string too).
        assert_eq!(id([0; 3], 0).vendor, Vendor::Unknown);
        assert_eq!(id([INTEL[0], INTEL[2], INTEL[1]], 0x0005_06E3).vendor, Vendor::Unknown);
        assert_eq!(decode(&CpuidLeaves::ZERO).ident, CpuIdent::default());
        assert_eq!(X86Features::NONE.ident.vendor.name(), "unknown");
    }

    #[test]
    fn a_host_build_reads_nothing_without_executing_cpuid() {
        assert_eq!(read_cpuid(), CpuidLeaves::default());
        assert_eq!(detect(), X86Features::NONE);
        assert_eq!(X86Features::NONE, X86Features::default());
        assert_eq!(check_baseline(1), Err("SSE2"));
    }
}
