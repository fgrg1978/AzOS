// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a guest sees of the CPU: the answer to its `CPUID`.
//!
//! The monitor intercepts `CPUID` (SVM `icpt::CPUID`) and answers from here,
//! never with the host's words as they are. The rule is an **allow list**:
//! a feature bit the guest sees is a bit this file names, and a leaf this file
//! does not know reads as zero. A deny list would hand a guest every feature a
//! newer CPU adds, with the MSRs, XCR0 bits and exits that come with it that
//! the monitor does not serve.
//!
//! * The guest is told it runs under a hypervisor (`CPUID.1:ECX[31]`) and
//!   leaf `0x4000_0000` names it. Leaf `0x4000_0010` carries the TSC rate in
//!   kHz (the convention of KVM and VMware that `timer.rs` reads): the guest
//!   has no PIT, HPET or ACPI timer to calibrate against, and
//!   `X86_TSC_FREQ_CPUID` makes it trust this leaf when the TSC is invariant
//!   (`CPUID.80000007:EDX[8]`, passed through here).
//! * What the guest probes at boot stays: the `X86_64_LEVEL` baseline bits
//!   (`boot.S` tests them before long mode), `x2APIC` and `TSC-deadline`
//!   (served by the vLAPIC), `XSAVE` and leaf `0xD` (`fp.rs`), `PAT`.
//! * What the guest must not use is hidden: `VMX` and `SVM` (no nested
//!   virtualization), `MONITOR`/`MWAIT` (an idle guest takes `HLT`, which the
//!   vCPU thread sleeps on), `MTRR`, machine check, the performance counters,
//!   thermal and power leaves, `TSC_ADJUST`, `RDTSCP`/`RDPID` (`TSC_AUX` is not
//!   in the VMCB), `CET`, `PKU`, `LA57` (the nested tables are 47 bits wide),
//!   every speculation-control MSR (`SPEC_CTRL`, `ARCH_CAPABILITIES`, the AMD
//!   `AutoIBRS` bit): a guest that sees none of them never writes the MSR.
//! * Per vCPU: the initial APIC ID (`CPUID.1:EBX[31:24]`) and the x2APIC ID
//!   (`CPUID.B:EDX`) are the vCPU index, the same ID the vLAPIC answers in
//!   its ID register and the guest's MADT lists.
//!
//! Pure: the host's `CPUID` is a parameter, so the host tests feed real CPUs'
//! words (an AMD Zen 3 and an Intel Ice Lake) through it.

/// The four registers `CPUID` returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Leaf {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl Leaf {
    pub const ZERO: Leaf = Leaf { eax: 0, ebx: 0, ecx: 0, edx: 0 };
}

/// The guest a `CPUID` is answered for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guest {
    /// This vCPU's index: its APIC ID.
    pub vcpu: u32,
    /// vCPUs in the VM (at least 1).
    pub vcpus: u32,
    /// The guest's TSC rate in kHz (what `RDTSC` counts at, host rate): leaf
    /// `0x4000_0010`. Zero when unknown: the guest then calibrates by itself.
    pub tsc_khz: u32,
    /// The rate of the vLAPIC timer's undivided clock in kHz (leaf
    /// `0x4000_0010`, `EBX`). Zero when unknown.
    pub apic_khz: u32,
    /// The guest's `XCR0` (it is not in the VMCB; the monitor keeps it).
    pub xcr0: u64,
    /// The guest's `CR4.OSXSAVE` (mirrored in `CPUID.1:ECX[27]`).
    pub osxsave: bool,
}

/// The highest basic leaf answered: `0xD` (XSAVE). Leaves above read zero, so
/// `0x15` and `0x16` are absent and the guest does not take its TSC rate
/// from them.
pub const MAX_BASIC: u32 = 0xD;
/// The highest extended leaf answered.
pub const MAX_EXTENDED: u32 = 0x8000_0008;
/// The hypervisor leaf range's top.
pub const HV_MAX: u32 = 0x4000_0010;
/// `"AzOS"`, three times: the signature of leaf `0x4000_0000`.
pub const HV_SIGNATURE: [u32; 3] = [u32::from_le_bytes(*b"AzOS"); 3];

/// `CPUID.1:ECX` bits the guest sees if the host has them.
pub const L1_ECX_ALLOW: u32 = 1 << 0 // SSE3
    | 1 << 1 // PCLMULQDQ
    | 1 << 9 // SSSE3
    | 1 << 12 // FMA
    | 1 << 13 // CMPXCHG16B
    | 1 << 17 // PCID
    | 1 << 19 // SSE4.1
    | 1 << 20 // SSE4.2
    | 1 << 22 // MOVBE
    | 1 << 23 // POPCNT
    | 1 << 25 // AES
    | 1 << 26 // XSAVE
    | 1 << 28 // AVX
    | 1 << 29 // F16C
    | 1 << 30; // RDRAND
/// `CPUID.1:ECX` bits the guest sees whatever the host has: the vLAPIC serves
/// the x2APIC MSR window and the TSC-deadline MSR (AMD CPUs have no
/// TSC-deadline timer; the guest gets one all the same).
pub const L1_ECX_EMULATED: u32 = 1 << 21 // x2APIC
    | 1 << 24; // TSC-deadline
/// `CPUID.1:ECX[27]`: OSXSAVE, the guest's own `CR4.OSXSAVE`.
pub const L1_ECX_OSXSAVE: u32 = 1 << 27;
/// `CPUID.1:ECX[31]`: running under a hypervisor.
pub const L1_ECX_HYPERVISOR: u32 = 1 << 31;
/// `CPUID.1:EDX` bits the guest sees if the host has them (not HTT).
pub const L1_EDX_ALLOW: u32 = 1 << 0 // FPU
    | 1 << 1 // VME
    | 1 << 2 // DE
    | 1 << 3 // PSE
    | 1 << 4 // TSC
    | 1 << 5 // MSR
    | 1 << 6 // PAE
    | 1 << 8 // CMPXCHG8B
    | 1 << 11 // SEP
    | 1 << 13 // PGE
    | 1 << 15 // CMOV
    | 1 << 16 // PAT
    | 1 << 17 // PSE-36
    | 1 << 19 // CLFSH
    | 1 << 23 // MMX
    | 1 << 24 // FXSR
    | 1 << 25 // SSE
    | 1 << 26; // SSE2
/// `CPUID.1:EDX[9]`: an on-chip APIC (the vLAPIC).
pub const L1_EDX_APIC: u32 = 1 << 9;
/// `CPUID.1:EDX[28]`: more than one logical processor.
pub const L1_EDX_HTT: u32 = 1 << 28;
/// `CPUID.(7,0):EBX` bits the guest sees if the host has them.
pub const L7_EBX_ALLOW: u32 = 1 << 0 // FSGSBASE
    | 1 << 3 // BMI1
    | 1 << 5 // AVX2
    | 1 << 7 // SMEP
    | 1 << 8 // BMI2
    | 1 << 9 // ERMS
    | 1 << 10 // INVPCID
    | 1 << 16 // AVX512F
    | 1 << 17 // AVX512DQ
    | 1 << 18 // RDSEED
    | 1 << 19 // ADX
    | 1 << 20 // SMAP
    | 1 << 21 // AVX512_IFMA
    | 1 << 23 // CLFLUSHOPT
    | 1 << 24 // CLWB
    | 1 << 28 // AVX512CD
    | 1 << 29 // SHA
    | 1 << 30 // AVX512BW
    | 1 << 31; // AVX512VL
/// `CPUID.(7,0):ECX` bits the guest sees if the host has them.
pub const L7_ECX_ALLOW: u32 = 1 << 1 // AVX512_VBMI
    | 1 << 2 // UMIP
    | 1 << 6 // AVX512_VBMI2
    | 1 << 8 // GFNI
    | 1 << 9 // VAES
    | 1 << 10 // VPCLMULQDQ
    | 1 << 11 // AVX512_VNNI
    | 1 << 12 // AVX512_BITALG
    | 1 << 14; // AVX512_VPOPCNTDQ
/// `CPUID.80000001:ECX` bits the guest sees if the host has them.
pub const E1_ECX_ALLOW: u32 = 1 << 0 // LAHF/SAHF in long mode
    | 1 << 4 // CR8 in legacy mode
    | 1 << 5 // LZCNT / ABM
    | 1 << 6 // SSE4A
    | 1 << 7 // misaligned SSE
    | 1 << 8; // PREFETCHW
/// `CPUID.80000001:EDX` bits the guest sees if the host has them.
pub const E1_EDX_ALLOW: u32 = 1 << 0
    | 1 << 1
    | 1 << 2
    | 1 << 3
    | 1 << 4
    | 1 << 5
    | 1 << 6
    | 1 << 8
    | 1 << 9
    | 1 << 11 // SYSCALL
    | 1 << 13
    | 1 << 15
    | 1 << 16
    | 1 << 17
    | 1 << 20 // NX
    | 1 << 22 // AMD MMX extensions
    | 1 << 23
    | 1 << 24
    | 1 << 26 // 1 GiB pages
    | 1 << 29; // long mode
/// `CPUID.80000007:EDX[8]`: the TSC is invariant.
pub const E7_EDX_INVARIANT_TSC: u32 = 1 << 8;

/// `XCR0` state components a guest may enable: x87, SSE, AVX and the three
/// AVX-512 components. (`XSAVES` supervisor state, `PKRU`, `AMX` and `CET`
/// are not offered.)
pub const XCR0_ALLOW: u64 = 0xE7;
/// The state the `XSAVE` area always holds: the legacy region plus the header.
pub const XSAVE_BASE_BYTES: u32 = 576;

/// Highest basic leaf the host has.
fn host_max(host: &dyn Fn(u32, u32) -> Leaf) -> u32 {
    host(0, 0).eax
}

fn host_max_ext(host: &dyn Fn(u32, u32) -> Leaf) -> u32 {
    host(0x8000_0000, 0).eax
}

/// `ceil(log2(n))`: the bit width that names `n` APIC IDs.
const fn id_bits(n: u32) -> u32 {
    if n <= 1 { 0 } else { 32 - (n - 1).leading_zeros() }
}

/// Bytes the standard (non-compacted) `XSAVE` area takes for the components
/// in `xcr0`: the end of the highest enabled component, from the host's
/// sub-leaves (their size and offset are a property of the CPU, not of any
/// `XCR0`).
pub fn xsave_bytes(host: &dyn Fn(u32, u32) -> Leaf, xcr0: u64) -> u32 {
    let mut end = XSAVE_BASE_BYTES;
    for c in 2..8u32 {
        if xcr0 >> c & 1 != 0 {
            let l = host(0xD, c);
            end = end.max(l.ebx.saturating_add(l.eax));
        }
    }
    end
}

/// The components of `XCR0` the host supports and the guest may enable.
pub fn xcr0_supported(host: &dyn Fn(u32, u32) -> Leaf) -> u64 {
    if host_max(host) < 0xD {
        return 0x3 & XCR0_ALLOW;
    }
    let l = host(0xD, 0);
    ((l.edx as u64) << 32 | l.eax as u64) & XCR0_ALLOW
}

/// Would a guest write of `xcr0` to `XCR0` be accepted (SDM vol. 1, 13.3)?
/// x87 must stay on, AVX needs SSE, the AVX-512 components come together and
/// need AVX, and nothing but supported components.
pub fn xcr0_valid(host: &dyn Fn(u32, u32) -> Leaf, xcr0: u64) -> bool {
    let supported = xcr0_supported(host);
    let avx512 = 0xE0;
    xcr0 & !supported == 0
        && xcr0 & 1 != 0
        && (xcr0 & 4 == 0 || xcr0 & 2 != 0)
        && (xcr0 & avx512 == 0 || (xcr0 & avx512 == avx512 && xcr0 & 4 != 0))
}

/// Answer `CPUID` leaf `leaf`, sub-leaf `sub`, for `g`.
pub fn answer(host: &dyn Fn(u32, u32) -> Leaf, g: &Guest, leaf: u32, sub: u32) -> Leaf {
    match leaf {
        0x4000_0000 => Leaf { eax: HV_MAX, ebx: HV_SIGNATURE[0], ecx: HV_SIGNATURE[1], edx: HV_SIGNATURE[2] },
        0x4000_0010 => Leaf { eax: g.tsc_khz, ebx: g.apic_khz, ecx: 0, edx: 0 },
        0x4000_0001..=0x4000_000F => Leaf::ZERO,
        0..=MAX_BASIC => basic(host, g, leaf, sub),
        0x8000_0000..=MAX_EXTENDED => extended(host, g, leaf),
        _ => Leaf::ZERO,
    }
}

fn basic(host: &dyn Fn(u32, u32) -> Leaf, g: &Guest, leaf: u32, sub: u32) -> Leaf {
    // A leaf the host lacks reads as zero from it; leaf 0xB is the VM's own.
    let h = if leaf <= host_max(host) { host(leaf, sub) } else { Leaf::ZERO };
    match leaf {
        0 => Leaf { eax: host_max(host).min(MAX_BASIC), ..h },
        1 => {
            let multi = g.vcpus > 1;
            Leaf {
                eax: h.eax,
                // Brand index and CLFLUSH size as the host has them; the
                // logical processor count and the initial APIC ID are the VM's.
                ebx: h.ebx & 0xFFFF | (g.vcpus.min(255) << 16) | ((g.vcpu & 0xFF) << 24),
                ecx: h.ecx & L1_ECX_ALLOW
                    | L1_ECX_EMULATED
                    | L1_ECX_HYPERVISOR
                    | if g.osxsave && h.ecx & (1 << 26) != 0 { L1_ECX_OSXSAVE } else { 0 },
                edx: h.edx & L1_EDX_ALLOW | L1_EDX_APIC | if multi { L1_EDX_HTT } else { 0 },
            }
        }
        7 => {
            if sub != 0 {
                return Leaf::ZERO;
            }
            // Sub-leaf 0 is the only one: the speculation-control word in
            // EDX and the sub-leaves 1 and 2 are not offered.
            Leaf { eax: 0, ebx: h.ebx & L7_EBX_ALLOW, ecx: h.ecx & L7_ECX_ALLOW, edx: 0 }
        }
        0xB => {
            // One thread per core, `vcpus` cores: the topology is flat.
            let (shift, count, kind) = match sub {
                0 => (0, 1, 1),
                1 => (id_bits(g.vcpus), g.vcpus, 2),
                _ => (0, 0, 0),
            };
            Leaf { eax: shift, ebx: count, ecx: sub & 0xFF | kind << 8, edx: g.vcpu }
        }
        0xD => xsave_leaf(host, g, sub, h),
        // 2 (cache descriptors), 3, 4 (cache parameters), 5 (MONITOR), 6
        // (thermal and power), 9, 0xA (performance counters) and the rest.
        _ => Leaf::ZERO,
    }
}

fn xsave_leaf(host: &dyn Fn(u32, u32) -> Leaf, g: &Guest, sub: u32, h: Leaf) -> Leaf {
    let supported = xcr0_supported(host);
    match sub {
        0 => Leaf {
            eax: supported as u32,
            // The area the guest's current XCR0 needs, and the one for everything.
            ebx: xsave_bytes(host, g.xcr0 & supported),
            ecx: xsave_bytes(host, supported),
            edx: 0,
        },
        // XSAVEOPT only: no XSAVEC, XGETBV(1) or XSAVES, so no supervisor state.
        1 => Leaf { eax: h.eax & 1, ..Leaf::ZERO },
        2..=7 if supported >> sub & 1 != 0 => Leaf { eax: h.eax, ebx: h.ebx, ecx: h.ecx & 2, edx: 0 },
        _ => Leaf::ZERO,
    }
}

fn extended(host: &dyn Fn(u32, u32) -> Leaf, g: &Guest, leaf: u32) -> Leaf {
    let max = host_max_ext(host);
    if leaf > max {
        return Leaf::ZERO;
    }
    let h = host(leaf, 0);
    match leaf {
        0x8000_0000 => Leaf { eax: max.min(MAX_EXTENDED), ..Leaf::ZERO },
        0x8000_0001 => Leaf { eax: h.eax, ebx: 0, ecx: h.ecx & E1_ECX_ALLOW, edx: h.edx & E1_EDX_ALLOW },
        // The brand string, as the host has it.
        0x8000_0002..=0x8000_0004 => h,
        // Invariant TSC only: no power-management or RAS bits.
        0x8000_0007 => Leaf { edx: h.edx & E7_EDX_INVARIANT_TSC, ..Leaf::ZERO },
        0x8000_0008 => Leaf {
            // Physical bits as the host, at most 46 (the nested tables take
            // 47); linear bits 48 (LA57 is not offered). AMD's ECX[7:0] is the
            // thread count minus one.
            eax: (h.eax & 0xFF).min(46) | 48 << 8,
            ebx: 0,
            ecx: g.vcpus.saturating_sub(1) & 0xFF,
            edx: 0,
        },
        // 5, 6 (cache), 9, 0xA (SVM), 0x19 and 0x1F (SEV) etc.
        _ => Leaf::ZERO,
    }
}
