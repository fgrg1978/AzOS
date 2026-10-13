// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86 speculative-execution mitigations, chosen by probe (Kconfig
//! `X86_MIT_*`, config/Kconfig.mitigations): the decision is a pure function
//! of what the CPU reports, so a wrong bit or a wrong table row is a host
//! test failure (`tests/host/arch-tests`, which includes this file after
//! `features.rs` under one parent module: it names no crate but `core` and
//! `azos_arch_api`). Only [`crate::mitigate`] executes `rdmsr`/`wrmsr`.
//!
//! **Probe, not vendor name.** A verdict is read from the architectural
//! capability bits first: `IA32_ARCH_CAPABILITIES` (RDCL_NO, IBRS_ALL,
//! MDS_NO, TAA_NO, GDS_NO, RFDS_NO, BHI_NO, RSBA, the *_CLEAR and *_CTRL
//! bits), the CPUID words of Intel's leaf 7 and AMD's 0x80000008 /
//! 0x80000021 (SPEC_CTRL, MD_CLEAR, BHI_CTRL, AutoIBRS, BTC_NO, SBPB,
//! SRSO_NO). The family/model table is the last resort, consulted only for
//! a bug the architecture publishes no bit for: which parts are affected
//! at all (GDS, RFDS, Retbleed on Intel), AMD's Zen generations, Zenbleed's
//! model ranges. The rows are the ones Linux's `cpu_vuln_blacklist` and
//! `cpu_vuln_whitelist` carry (arch/x86/kernel/cpu/common.c).
//!
//! **What is mitigated here, and what is only reported.** A choice is
//! `n` (look at nothing, do nothing: [`Verdict::Off`]), `probe` (mitigate
//! when the CPU is affected and the tree has the mechanism, else say
//! [`Verdict::Vulnerable`] and why), or `require` (the boot refuses a CPU
//! left `Vulnerable`: [`Report::refusal`]). The mechanisms in the tree:
//!
//! * Spectre v2: eIBRS (`IA32_SPEC_CTRL.IBRS` once per CPU), AutoIBRS
//!   (`EFER.AIBRS`), else retpoline: the kernel is built with the external
//!   indirect-branch thunk (`-Zretpoline-external-thunk`) exactly when the
//!   choice is `probe`; the thunk ([`crate::retpoline`]) is the retpoline
//!   sequence, and the boot patches it once to a plain `jmp` ([`ThunkMode`],
//!   [`thunk_patch`]) when the hardware protects indirect branches. Under
//!   `require` the kernel is built without thunks and the CPU must have
//!   eIBRS/AutoIBRS.
//! * BHI: `BHI_DIS_S` (`IA32_SPEC_CTRL` bit 10); retpoline covers a CPU with
//!   no eIBRS. The software clearing loop is not in the tree.
//! * MDS / TAA / RFDS: `verw` on the way back to ring 3 (`trap_entry.S`),
//!   when the CPU's microcode makes it clear the buffers.
//! * GDS: the microcode mitigation, kept enabled (`IA32_MCU_OPT_CTRL`).
//! * Zenbleed: the `DE_CFG` chicken bit, unless the microcode is fixed.
//! * L1TF: PTE inversion by construction. A not-present PTE this kernel
//!   writes holds no frame address (`mmu::empty`, `mmu::make_demand`), and
//!   frame 0, which such an entry names, is never allocated.
//! * Not in the tree, so `Vulnerable` on an affected CPU: KPTI (Meltdown),
//!   the return thunk / IBRS-on-entry (Retbleed), safe-RET / IBPB-on-entry
//!   (SRSO), the BHB clearing loop.

use azos_arch_api::isa::ExtPolicy;

use super::features::{decode_ident, CpuIdent, CpuidLeaves, Vendor};

// ── MSRs and register bits ──────────────────────────────────────────────────

/// IA32_SPEC_CTRL (Intel SDM Vol. 4; AMD APM 3 §3.2.9). Exists behind
/// CPUID.(7,0):EDX[26] (Intel) or CPUID.80000008H:EBX[14] (AMD).
pub const MSR_IA32_SPEC_CTRL: u32 = 0x48;
pub const SPEC_CTRL_IBRS: u64 = 1 << 0;
/// Intel's BHI_DIS_S, behind CPUID.(7,2):EDX[4].
pub const SPEC_CTRL_BHI_DIS_S: u64 = 1 << 10;
/// IA32_ARCH_CAPABILITIES, behind CPUID.(7,0):EDX[29].
pub const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x10A;
/// IA32_MCU_OPT_CTRL, behind ARCH_CAPABILITIES.GDS_CTRL.
pub const MSR_IA32_MCU_OPT_CTRL: u32 = 0x123;
/// MCU_OPT_CTRL bit 4: GDS mitigation disable.
pub const MCU_OPT_GDS_MITG_DIS: u64 = 1 << 4;
/// MCU_OPT_CTRL bit 5: GDS mitigation lock (the disable bit is then fixed).
pub const MCU_OPT_GDS_MITG_LOCK: u64 = 1 << 5;
/// IA32_BIOS_SIGN_ID, the microcode revision in its high half (Intel: write
/// 0, execute CPUID.1, read); AMD's MSR_AMD64_PATCH_LEVEL is the same number
/// and holds the revision in its low half.
pub const MSR_AMD64_PATCH_LEVEL: u32 = 0x8B;
/// MSR_AMD64_DE_CFG.
pub const MSR_AMD64_DE_CFG: u32 = 0xC001_1029;
/// DE_CFG bit 9: the Zen 2 FP-backup fix (Zenbleed).
pub const DE_CFG_ZEN2_FP_BACKUP_FIX: u64 = 1 << 9;
/// EFER bit 21: AutoIBRS.
pub const EFER_AIBRS: u64 = 1 << 21;

/// IA32_ARCH_CAPABILITIES bits (Linux msr-index.h).
pub mod arch_cap {
    pub const RDCL_NO: u64 = 1 << 0;
    pub const IBRS_ALL: u64 = 1 << 1;
    pub const RSBA: u64 = 1 << 2;
    pub const MDS_NO: u64 = 1 << 5;
    pub const TSX_CTRL: u64 = 1 << 7;
    pub const TAA_NO: u64 = 1 << 8;
    pub const RRSBA: u64 = 1 << 19;
    pub const BHI_NO: u64 = 1 << 20;
    pub const GDS_CTRL: u64 = 1 << 25;
    pub const GDS_NO: u64 = 1 << 26;
    pub const RFDS_NO: u64 = 1 << 27;
    pub const RFDS_CLEAR: u64 = 1 << 28;
}

// CPUID bit positions.
mod bit {
    // CPUID.1:ECX
    pub const HYPERVISOR: u32 = 31;
    // CPUID.1:ECX
    pub const AVX: u32 = 28;
    // CPUID.(7,0):EBX
    pub const RTM: u32 = 11;
    // CPUID.(7,0):EDX
    pub const MD_CLEAR: u32 = 10;
    pub const SPEC_CTRL: u32 = 26;
    pub const ARCH_CAPABILITIES: u32 = 29;
    // CPUID.(7,2):EDX
    pub const BHI_CTRL: u32 = 4;
    // CPUID.80000008H:EBX
    pub const AMD_IBRS: u32 = 14;
    pub const BTC_NO: u32 = 29;
    // CPUID.80000021H:EAX
    pub const AUTO_IBRS: u32 = 8;
    pub const SRSO_NO: u32 = 29;
    pub const SRSO_USER_KERNEL_NO: u32 = 30;
}

const fn has(word: u32, b: u32) -> bool {
    word & (1 << b) != 0
}

// ── The probe ───────────────────────────────────────────────────────────────

/// Everything the decision reads, as plain values: one snapshot per boot CPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Probe {
    pub ident: CpuIdent,
    /// CPUID.1:ECX[31]: running under a hypervisor.
    pub hypervisor: bool,
    /// CPUID.1:ECX[28]: AVX (Zenbleed is a vector-register bug).
    pub avx: bool,
    /// CPUID.(7,0):EBX[11]: TSX (RTM), the TAA precondition.
    pub rtm: bool,
    /// CPUID.(7,0):EDX[10]: `verw` clears the CPU's buffers.
    pub md_clear: bool,
    /// IA32_SPEC_CTRL exists: CPUID.(7,0):EDX[26], or AMD's
    /// CPUID.80000008H:EBX[14].
    pub spec_ctrl: bool,
    /// CPUID.(7,2):EDX[4]: SPEC_CTRL bit 10 (BHI_DIS_S) exists.
    pub bhi_ctrl: bool,
    /// CPUID.80000021H:EAX[8]: EFER.AIBRS exists.
    pub auto_ibrs: bool,
    /// CPUID.80000008H:EBX[29]: not affected by branch type confusion.
    pub btc_no: bool,
    /// CPUID.80000021H:EAX[29]: not affected by SRSO.
    pub srso_no: bool,
    /// CPUID.80000021H:EAX[30]: not affected by SRSO between user and kernel.
    pub srso_user_kernel_no: bool,
    /// CPUID.(7,0):EDX[29] was set, so [`Probe::arch_caps`] was read.
    pub has_arch_caps: bool,
    /// IA32_ARCH_CAPABILITIES (0 when the MSR is absent).
    pub arch_caps: u64,
    /// IA32_MCU_OPT_CTRL (0 unless ARCH_CAPABILITIES.GDS_CTRL).
    pub mcu_opt_ctrl: u64,
    /// The microcode revision (0 when not read).
    pub ucode_rev: u32,
}

impl Probe {
    /// From the CPUID snapshot and the MSR values the caller read behind the
    /// bits [`needs_arch_caps`], [`needs_mcu_opt_ctrl`] and
    /// [`needs_ucode_rev`] say are safe to read.
    pub const fn new(r: &CpuidLeaves, arch_caps: Option<u64>, mcu_opt_ctrl: u64, ucode_rev: u32) -> Self {
        let has_arch_caps = arch_caps.is_some();
        Probe {
            ident: decode_ident(r),
            hypervisor: has(r.l1_ecx, bit::HYPERVISOR),
            avx: has(r.l1_ecx, bit::AVX),
            rtm: has(r.l7_ebx, bit::RTM),
            md_clear: has(r.l7_edx, bit::MD_CLEAR),
            spec_ctrl: has(r.l7_edx, bit::SPEC_CTRL) || has(r.e8_ebx, bit::AMD_IBRS),
            bhi_ctrl: has(r.l7_2_edx, bit::BHI_CTRL),
            auto_ibrs: has(r.e21_eax, bit::AUTO_IBRS),
            btc_no: has(r.e8_ebx, bit::BTC_NO),
            srso_no: has(r.e21_eax, bit::SRSO_NO),
            srso_user_kernel_no: has(r.e21_eax, bit::SRSO_USER_KERNEL_NO),
            has_arch_caps,
            arch_caps: match arch_caps {
                Some(v) => v,
                None => 0,
            },
            mcu_opt_ctrl,
            ucode_rev,
        }
    }

    fn cap(&self, bit: u64) -> bool {
        self.arch_caps & bit != 0
    }
    fn intel(&self) -> bool {
        self.ident.vendor == Vendor::Intel
    }
    /// AMD, or Hygon's Zen derivative.
    fn amd_like(&self) -> bool {
        matches!(self.ident.vendor, Vendor::Amd | Vendor::Hygon)
    }
    fn model(&self) -> u16 {
        self.ident.model
    }
    /// An Intel family 6 part whose display model is in `list`.
    fn intel_model_in(&self, list: &[u16]) -> bool {
        self.intel() && self.ident.family == 6 && list.contains(&self.model())
    }
    /// Intel's eIBRS: ARCH_CAPABILITIES says IBRS_ALL and SPEC_CTRL exists.
    pub fn eibrs(&self) -> bool {
        self.intel() && self.spec_ctrl && self.cap(arch_cap::IBRS_ALL)
    }
}

/// Is IA32_ARCH_CAPABILITIES readable (CPUID.(7,0):EDX[29])?
pub const fn needs_arch_caps(r: &CpuidLeaves) -> bool {
    has(r.l7_edx, bit::ARCH_CAPABILITIES)
}

/// Is IA32_MCU_OPT_CTRL readable (ARCH_CAPABILITIES.GDS_CTRL)?
pub const fn needs_mcu_opt_ctrl(arch_caps: u64) -> bool {
    arch_caps & arch_cap::GDS_CTRL != 0
}

/// Does the decision read the microcode revision (a Zen 2 part, where the
/// Zenbleed fix depends on it)?
pub const fn needs_ucode_rev(ident: &CpuIdent) -> bool {
    matches!(ident.vendor, Vendor::Amd) && zen2_zenbleed_range(ident)
}

// ── Model tables (display family 6 for Intel; Linux's rows) ─────────────────

/// Bonnell / Saltwell Atoms: in order, no speculation to attack.
const INTEL_NO_SPECULATION: &[u16] = &[0x1C, 0x26, 0x27, 0x35, 0x36];
/// Goldmont Atoms: not affected by MDS.
const INTEL_NO_MDS: &[u16] = &[0x5C, 0x5F, 0x7A];
/// Silvermont/Airmont/Goldmont Atoms and Knights Landing/Mill: not affected
/// by L1TF.
const INTEL_NO_L1TF: &[u16] = &[0x37, 0x4A, 0x4C, 0x4D, 0x5A, 0x5D, 0x5C, 0x5F, 0x7A, 0x57, 0x85];
/// Parts affected by Gather Data Sampling (Skylake through Rocket Lake).
const INTEL_GDS: &[u16] = &[
    0x55, 0x4E, 0x5E, 0x8E, 0x9E, 0x7E, 0x6C, 0x6A, 0xA5, 0xA6, 0x8C, 0x8D, 0xA7,
];
/// Parts affected by Register File Data Sampling (Atom cores).
const INTEL_RFDS: &[u16] = &[
    0x97, 0x9A, 0xB7, 0xBA, 0xBF, 0xBE, 0x96, 0x86, 0x9C, 0x5C, 0x5F, 0x7A,
];
/// Parts affected by Retbleed (Skylake through Rocket Lake without eIBRS
/// protection of returns, Cannon Lake, Lakefield).
const INTEL_RETBLEED: &[u16] = &[0x55, 0x4E, 0x5E, 0x8E, 0x9E, 0x66, 0x7E, 0xA5, 0xA6, 0x8A, 0xA7];

/// Zen 2 parts the Zenbleed erratum covers (AMD family 17h).
const fn zen2_zenbleed_range(i: &CpuIdent) -> bool {
    i.family == 0x17
        && matches!(i.model, 0x30..=0x4F | 0x60..=0x7F | 0x90..=0x91 | 0xA0..=0xAF)
}

/// The microcode revision that fixes Zenbleed, per model (exact match); a
/// part not listed has no known fixed microcode.
const ZENBLEED_FIXED_UCODE: &[(u16, u32)] = &[
    (0x30, 0x0830_107A),
    (0x60, 0x0860_010B),
    (0x68, 0x0860_8105),
    (0x70, 0x0870_1032),
    (0xA0, 0x08A0_0008),
];

// ── Policies, verdicts ──────────────────────────────────────────────────────

/// The ten `X86_MIT_*` choices.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policies {
    pub meltdown: ExtPolicy,
    pub l1tf: ExtPolicy,
    pub mds_taa: ExtPolicy,
    pub rfds: ExtPolicy,
    pub gds: ExtPolicy,
    pub spectre_v2: ExtPolicy,
    pub bhi: ExtPolicy,
    pub retbleed: ExtPolicy,
    pub srso: ExtPolicy,
    pub zenbleed: ExtPolicy,
}

impl Policies {
    pub const fn all(p: ExtPolicy) -> Self {
        Policies {
            meltdown: p, l1tf: p, mds_taa: p, rfds: p, gds: p, spectre_v2: p, bhi: p, retbleed: p,
            srso: p, zenbleed: p,
        }
    }
}

/// How a bug is mitigated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// IA32_SPEC_CTRL.IBRS, set once (Intel eIBRS).
    Eibrs,
    /// EFER.AIBRS (AMD).
    AutoIbrs,
    /// The retpoline thunk (the kernel is built with it).
    Retpoline,
    /// IA32_SPEC_CTRL.BHI_DIS_S.
    BhiDisS,
    /// `verw` before ring 3 (clears the CPU's buffers).
    Verw,
    /// The microcode mitigation, kept enabled.
    Microcode,
    /// The DE_CFG chicken bit.
    DeCfg,
    /// L1TF: no not-present PTE holds a frame address.
    NoStaleFrame,
}

impl Method {
    pub const fn label(self) -> &'static str {
        match self {
            Method::Eibrs => "eibrs",
            Method::AutoIbrs => "autoibrs",
            Method::Retpoline => "retpoline",
            Method::BhiDisS => "bhi-dis-s",
            Method::Verw => "verw",
            Method::Microcode => "microcode",
            Method::DeCfg => "de-cfg",
            Method::NoStaleFrame => "pte-inversion",
        }
    }
}

/// One bug's outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Choice `n`: not looked at, nothing done.
    Off,
    /// The CPU is not affected, and why.
    NotAffected(&'static str),
    Mitigated(Method),
    /// Affected, and the tree has no (working) mechanism for it: why.
    Vulnerable(&'static str),
}

impl Verdict {
    /// The word the boot line prints.
    pub const fn label(self) -> &'static str {
        match self {
            Verdict::Off => "off",
            Verdict::NotAffected(_) => "not-affected",
            Verdict::Mitigated(m) => m.label(),
            Verdict::Vulnerable(_) => "vulnerable",
        }
    }
    /// The reason, for the verdicts that carry one.
    pub const fn why(self) -> Option<&'static str> {
        match self {
            Verdict::NotAffected(w) | Verdict::Vulnerable(w) => Some(w),
            _ => None,
        }
    }
}

/// All the verdicts, in the order the boot line prints them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub meltdown: Verdict,
    pub l1tf: Verdict,
    pub mds: Verdict,
    pub taa: Verdict,
    pub rfds: Verdict,
    pub gds: Verdict,
    pub spectre_v2: Verdict,
    pub bhi: Verdict,
    pub retbleed: Verdict,
    pub srso: Verdict,
    pub zenbleed: Verdict,
}

/// The indirect-branch thunk's body (`crate::retpoline`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThunkMode {
    /// A plain `jmp *%r11`: hardware protects indirect branches.
    Direct = 0,
    /// The retpoline sequence: what the thunk is as assembled, so what it is
    /// until the decision.
    Retpoline = 1,
}

/// The thunk's reserved length: the retpoline sequence padded with `int3`.
pub const THUNK_BYTES: usize = 32;

/// The bytes the thunk is patched to for `mode`, or `None` where the
/// assembled retpoline already is the body. `jmp *%r11` is `41 FF E3` (REX.B,
/// FF /4); the rest is `int3`, so nothing after the jump executes, even
/// speculatively.
pub fn thunk_patch(mode: ThunkMode) -> Option<[u8; THUNK_BYTES]> {
    match mode {
        ThunkMode::Retpoline => None,
        ThunkMode::Direct => {
            let mut b = [0xCC; THUNK_BYTES];
            b[..3].copy_from_slice(&[0x41, 0xFF, 0xE3]);
            Some(b)
        }
    }
}

/// What to do on every CPU once the decision is taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    /// Bits to OR into IA32_SPEC_CTRL (0: leave the MSR alone).
    pub spec_ctrl: u64,
    /// Set EFER.AIBRS.
    pub efer_aibrs: bool,
    pub thunk: ThunkMode,
    /// Execute `verw` on every return to ring 3.
    pub verw_on_exit: bool,
    /// Set DE_CFG bit 9.
    pub de_cfg_zenbleed: bool,
    /// Clear IA32_MCU_OPT_CTRL.GDS_MITG_DIS.
    pub gds_enable: bool,
}

impl Plan {
    /// Nothing done (every choice `n`, or nothing affected).
    pub const NONE: Plan = Plan {
        spec_ctrl: 0,
        efer_aibrs: false,
        thunk: ThunkMode::Retpoline,
        verw_on_exit: false,
        de_cfg_zenbleed: false,
        gds_enable: false,
    };
}

/// The first `require`d choice whose verdict is `Vulnerable`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    /// The bug as the boot line names it.
    pub name: &'static str,
    /// The Kconfig choice.
    pub symbol: &'static str,
    pub why: &'static str,
}

impl Report {
    /// The verdicts with their boot-line names, in print order.
    pub fn rows(&self) -> [(&'static str, Verdict); 11] {
        [
            ("meltdown", self.meltdown),
            ("l1tf", self.l1tf),
            ("mds", self.mds),
            ("taa", self.taa),
            ("rfds", self.rfds),
            ("gds", self.gds),
            ("spectre_v2", self.spectre_v2),
            ("bhi", self.bhi),
            ("retbleed", self.retbleed),
            ("srso", self.srso),
            ("zenbleed", self.zenbleed),
        ]
    }

    /// A `require`d choice the CPU leaves vulnerable.
    pub fn refusal(&self, p: &Policies) -> Option<Refusal> {
        let checks: [(&'static str, &'static str, ExtPolicy, Verdict); 11] = [
            ("meltdown", "X86_MIT_MELTDOWN", p.meltdown, self.meltdown),
            ("l1tf", "X86_MIT_L1TF", p.l1tf, self.l1tf),
            ("mds", "X86_MIT_MDS_TAA", p.mds_taa, self.mds),
            ("taa", "X86_MIT_MDS_TAA", p.mds_taa, self.taa),
            ("rfds", "X86_MIT_RFDS", p.rfds, self.rfds),
            ("gds", "X86_MIT_GDS", p.gds, self.gds),
            ("spectre_v2", "X86_MIT_SPECTRE_V2", p.spectre_v2, self.spectre_v2),
            ("bhi", "X86_MIT_BHI", p.bhi, self.bhi),
            ("retbleed", "X86_MIT_RETBLEED", p.retbleed, self.retbleed),
            ("srso", "X86_MIT_SRSO", p.srso, self.srso),
            ("zenbleed", "X86_MIT_ZENBLEED", p.zenbleed, self.zenbleed),
        ];
        checks.into_iter().find_map(|(name, symbol, pol, v)| match v {
            Verdict::Vulnerable(why) if pol == ExtPolicy::Require => Some(Refusal { name, symbol, why }),
            _ => None,
        })
    }
}

// ── The decision ────────────────────────────────────────────────────────────

/// Take the decision for `pr` under `pol`.
pub fn decide(pr: &Probe, pol: &Policies) -> (Report, Plan) {
    let mut plan = Plan::NONE;

    let meltdown = gate(pol.meltdown, || meltdown(pr));
    let l1tf = gate(pol.l1tf, || l1tf(pr));
    let (mds, taa) = if pol.mds_taa == ExtPolicy::Never {
        (Verdict::Off, Verdict::Off)
    } else {
        (mds(pr), taa(pr))
    };
    let rfds = gate(pol.rfds, || rfds(pr));
    let gds = gate(pol.gds, || gds(pr));
    let spectre_v2 = gate(pol.spectre_v2, || spectre_v2(pr, pol.spectre_v2));
    let bhi = gate(pol.bhi, || bhi(pr, spectre_v2));
    let retbleed = gate(pol.retbleed, || retbleed(pr, spectre_v2));
    let srso = gate(pol.srso, || srso(pr));
    let zenbleed = gate(pol.zenbleed, || zenbleed(pr));

    // The actions the verdicts imply.
    match spectre_v2 {
        Verdict::Mitigated(Method::Eibrs) => {
            plan.spec_ctrl |= SPEC_CTRL_IBRS;
            plan.thunk = ThunkMode::Direct;
        }
        Verdict::Mitigated(Method::AutoIbrs) => {
            plan.efer_aibrs = true;
            plan.thunk = ThunkMode::Direct;
        }
        _ => {}
    }
    if bhi == Verdict::Mitigated(Method::BhiDisS) {
        plan.spec_ctrl |= SPEC_CTRL_BHI_DIS_S;
    }
    plan.verw_on_exit = [mds, taa, rfds].contains(&Verdict::Mitigated(Method::Verw));
    plan.de_cfg_zenbleed = zenbleed == Verdict::Mitigated(Method::DeCfg);
    plan.gds_enable = gds == Verdict::Mitigated(Method::Microcode) && pr.mcu_opt_ctrl & MCU_OPT_GDS_MITG_DIS != 0;

    (Report { meltdown, l1tf, mds, taa, rfds, gds, spectre_v2, bhi, retbleed, srso, zenbleed }, plan)
}

fn gate(p: ExtPolicy, f: impl FnOnce() -> Verdict) -> Verdict {
    if p == ExtPolicy::Never { Verdict::Off } else { f() }
}

/// A vendor the tables do not describe: nothing can be said, so nothing is
/// claimed.
const UNKNOWN_VENDOR: Verdict = Verdict::Vulnerable("unknown CPU vendor: no documented mitigation state");

fn meltdown(pr: &Probe) -> Verdict {
    if pr.amd_like() {
        return Verdict::NotAffected("AMD and Hygon cores do not speculate past the privilege check");
    }
    if !pr.intel() {
        return UNKNOWN_VENDOR;
    }
    if pr.cap(arch_cap::RDCL_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.RDCL_NO");
    }
    if pr.intel_model_in(INTEL_NO_SPECULATION) {
        return Verdict::NotAffected("in-order core");
    }
    Verdict::Vulnerable("KPTI is not in the tree")
}

fn l1tf(pr: &Probe) -> Verdict {
    if pr.amd_like() {
        return Verdict::NotAffected("not an Intel core");
    }
    if !pr.intel() {
        return UNKNOWN_VENDOR;
    }
    if pr.cap(arch_cap::RDCL_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.RDCL_NO");
    }
    if pr.intel_model_in(INTEL_NO_SPECULATION) || pr.intel_model_in(INTEL_NO_L1TF) {
        return Verdict::NotAffected("core not affected");
    }
    Verdict::Mitigated(Method::NoStaleFrame)
}

fn mds(pr: &Probe) -> Verdict {
    if pr.amd_like() {
        return Verdict::NotAffected("not an Intel core");
    }
    if !pr.intel() {
        return UNKNOWN_VENDOR;
    }
    if pr.cap(arch_cap::MDS_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.MDS_NO");
    }
    if pr.intel_model_in(INTEL_NO_SPECULATION) || pr.intel_model_in(INTEL_NO_MDS) {
        return Verdict::NotAffected("core not affected");
    }
    if pr.md_clear {
        Verdict::Mitigated(Method::Verw)
    } else {
        Verdict::Vulnerable("no MD_CLEAR: microcode that makes verw clear the buffers is not loaded")
    }
}

fn taa(pr: &Probe) -> Verdict {
    if pr.amd_like() {
        return Verdict::NotAffected("not an Intel core");
    }
    if !pr.intel() {
        return UNKNOWN_VENDOR;
    }
    if !(pr.rtm || pr.cap(arch_cap::TSX_CTRL)) {
        return Verdict::NotAffected("no TSX");
    }
    if pr.cap(arch_cap::TAA_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.TAA_NO");
    }
    if pr.md_clear {
        Verdict::Mitigated(Method::Verw)
    } else {
        Verdict::Vulnerable("no MD_CLEAR: microcode that makes verw clear the buffers is not loaded")
    }
}

fn rfds(pr: &Probe) -> Verdict {
    if !pr.intel() {
        return if pr.amd_like() { Verdict::NotAffected("not an Intel core") } else { UNKNOWN_VENDOR };
    }
    if pr.cap(arch_cap::RFDS_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.RFDS_NO");
    }
    if !pr.intel_model_in(INTEL_RFDS) {
        return Verdict::NotAffected("core not in the affected list");
    }
    if pr.cap(arch_cap::RFDS_CLEAR) {
        Verdict::Mitigated(Method::Verw)
    } else {
        Verdict::Vulnerable("no RFDS_CLEAR: microcode that makes verw clear the register file is not loaded")
    }
}

fn gds(pr: &Probe) -> Verdict {
    if !pr.intel() {
        return if pr.amd_like() { Verdict::NotAffected("not an Intel core") } else { UNKNOWN_VENDOR };
    }
    if pr.cap(arch_cap::GDS_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.GDS_NO");
    }
    if !pr.intel_model_in(INTEL_GDS) {
        return Verdict::NotAffected("core not in the affected list");
    }
    if !pr.cap(arch_cap::GDS_CTRL) {
        return Verdict::Vulnerable("no GDS_CTRL: the microcode mitigation is not loaded");
    }
    if pr.mcu_opt_ctrl & MCU_OPT_GDS_MITG_LOCK != 0 && pr.mcu_opt_ctrl & MCU_OPT_GDS_MITG_DIS != 0 {
        return Verdict::Vulnerable("the firmware disabled the microcode mitigation and locked it");
    }
    Verdict::Mitigated(Method::Microcode)
}

fn spectre_v2(pr: &Probe, pol: ExtPolicy) -> Verdict {
    if pr.intel_model_in(INTEL_NO_SPECULATION) {
        return Verdict::NotAffected("in-order core");
    }
    if pr.eibrs() {
        return Verdict::Mitigated(Method::Eibrs);
    }
    if pr.amd_like() && pr.auto_ibrs {
        return Verdict::Mitigated(Method::AutoIbrs);
    }
    // The build carries the thunk only under `probe`.
    if pol == ExtPolicy::Probe {
        Verdict::Mitigated(Method::Retpoline)
    } else {
        Verdict::Vulnerable("neither eIBRS nor AutoIBRS, and the build has no retpoline thunk (require)")
    }
}

fn bhi(pr: &Probe, v2: Verdict) -> Verdict {
    if !pr.intel() {
        return if pr.amd_like() { Verdict::NotAffected("not an Intel core") } else { UNKNOWN_VENDOR };
    }
    if pr.cap(arch_cap::BHI_NO) {
        return Verdict::NotAffected("ARCH_CAPABILITIES.BHI_NO");
    }
    if pr.intel_model_in(INTEL_NO_SPECULATION) {
        return Verdict::NotAffected("in-order core");
    }
    match v2 {
        Verdict::Mitigated(Method::Eibrs) => {
            if pr.bhi_ctrl {
                Verdict::Mitigated(Method::BhiDisS)
            } else {
                Verdict::Vulnerable("no BHI_DIS_S, and the BHB clearing loop is not in the tree")
            }
        }
        // Retpoline takes every indirect branch off the predictor.
        Verdict::Mitigated(Method::Retpoline) => Verdict::Mitigated(Method::Retpoline),
        _ => Verdict::Vulnerable("indirect branches are not protected (Spectre v2 choice)"),
    }
}

fn retbleed(pr: &Probe, v2: Verdict) -> Verdict {
    if pr.intel() {
        if !(pr.intel_model_in(INTEL_RETBLEED) || pr.cap(arch_cap::RSBA)) {
            return Verdict::NotAffected("core not in the affected list");
        }
        if v2 == Verdict::Mitigated(Method::Eibrs) {
            return Verdict::Mitigated(Method::Eibrs);
        }
        return Verdict::Vulnerable("needs IBRS on every kernel entry, which is not in the tree");
    }
    if pr.amd_like() {
        // Zen 1 and Zen 2 (and Hygon's family 18h).
        let zen12 = matches!((pr.ident.vendor, pr.ident.family), (Vendor::Amd, 0x17) | (Vendor::Hygon, 0x18));
        if !zen12 || pr.btc_no {
            return Verdict::NotAffected("CPUID BTC_NO or a core without branch type confusion");
        }
        return Verdict::Vulnerable("needs the untrained return thunk, which is not in the tree");
    }
    UNKNOWN_VENDOR
}

fn srso(pr: &Probe) -> Verdict {
    if !pr.amd_like() {
        return if pr.intel() { Verdict::NotAffected("not an AMD core") } else { UNKNOWN_VENDOR };
    }
    // Zen 1 through Zen 5.
    if !matches!(pr.ident.family, 0x17..=0x1A) {
        return Verdict::NotAffected("core predates Zen");
    }
    if pr.srso_no {
        return Verdict::NotAffected("CPUID SRSO_NO");
    }
    if pr.srso_user_kernel_no {
        return Verdict::NotAffected("CPUID SRSO_USER_KERNEL_NO (no guests are hosted)");
    }
    Verdict::Vulnerable("needs safe-RET or IBPB on entry, which are not in the tree")
}

fn zenbleed(pr: &Probe) -> Verdict {
    if pr.ident.vendor != Vendor::Amd || !zen2_zenbleed_range(&pr.ident) {
        return Verdict::NotAffected("not a Zen 2 core");
    }
    if !pr.avx {
        return Verdict::NotAffected("no AVX");
    }
    let fixed = ZENBLEED_FIXED_UCODE.iter().find(|&&(m, _)| m == pr.ident.model);
    match fixed {
        Some(&(_, rev)) if pr.ucode_rev >= rev => Verdict::NotAffected("fixed microcode"),
        _ => Verdict::Mitigated(Method::DeCfg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE: Policies = Policies::all(ExtPolicy::Probe);

    /// A probe for one of the CPUs the gate boots, as the architecture
    /// documents it (`display family`, `model`), with the capability words
    /// those parts carry. The assertions below are the discriminators: each
    /// names the bit or the table row that makes the verdict.
    fn cpu(vendor: Vendor, family: u16, model: u16) -> Probe {
        Probe {
            ident: CpuIdent { vendor, family, model, stepping: 0 },
            hypervisor: true,
            avx: true,
            ..Probe::default()
        }
    }

    fn intel(model: u16) -> Probe {
        cpu(Vendor::Intel, 6, model)
    }

    /// Nehalem: no ARCH_CAPABILITIES, no SPEC_CTRL, no MD_CLEAR.
    fn nehalem() -> Probe {
        intel(0x1A)
    }

    /// Skylake-Client, with the 2019 microcode: SPEC_CTRL, MD_CLEAR, no
    /// ARCH_CAPABILITIES.
    fn skylake() -> Probe {
        Probe { spec_ctrl: true, md_clear: true, ..intel(0x5E) }
    }

    /// Ice Lake server class: eIBRS, RDCL_NO, MDS_NO, TAA_NO.
    fn icelake_server() -> Probe {
        Probe {
            spec_ctrl: true,
            md_clear: true,
            has_arch_caps: true,
            arch_caps: arch_cap::RDCL_NO | arch_cap::IBRS_ALL | arch_cap::MDS_NO | arch_cap::TAA_NO,
            ..intel(0x6A)
        }
    }

    /// Sapphire Rapids: Ice Lake's bits plus GDS_NO, RFDS_NO, and BHI_CTRL
    /// with no BHI_NO.
    fn sapphire_rapids() -> Probe {
        Probe {
            bhi_ctrl: true,
            arch_caps: icelake_server().arch_caps | arch_cap::GDS_NO | arch_cap::RFDS_NO,
            ..icelake_server()
        }
    }

    fn epyc(family: u16, model: u16) -> Probe {
        Probe { spec_ctrl: true, ..cpu(Vendor::Amd, family, model) }
    }

    fn rome() -> Probe {
        epyc(0x17, 0x31)
    }
    fn milan() -> Probe {
        Probe { btc_no: true, ..epyc(0x19, 0x01) }
    }
    fn genoa() -> Probe {
        Probe { btc_no: true, auto_ibrs: true, srso_user_kernel_no: true, ..epyc(0x19, 0x11) }
    }

    #[test]
    fn the_probe_reads_each_cpuid_bit_from_its_own_word() {
        let l = |f: fn(&mut CpuidLeaves)| {
            let mut r = CpuidLeaves::default();
            f(&mut r);
            Probe::new(&r, None, 0, 0)
        };
        assert!(l(|r| r.l1_ecx = 1 << 31).hypervisor);
        assert!(l(|r| r.l1_ecx = 1 << 28).avx);
        assert!(l(|r| r.l7_ebx = 1 << 11).rtm);
        assert!(l(|r| r.l7_edx = 1 << 10).md_clear);
        assert!(l(|r| r.l7_edx = 1 << 26).spec_ctrl);
        assert!(l(|r| r.e8_ebx = 1 << 14).spec_ctrl, "AMD's IBRS bit");
        assert!(l(|r| r.l7_2_edx = 1 << 4).bhi_ctrl);
        assert!(l(|r| r.e21_eax = 1 << 8).auto_ibrs);
        assert!(l(|r| r.e8_ebx = 1 << 29).btc_no);
        assert!(l(|r| r.e21_eax = 1 << 29).srso_no);
        assert!(l(|r| r.e21_eax = 1 << 30).srso_user_kernel_no);
        // A neighbour bit turns on nothing.
        let none = l(|r| {
            r.l1_ecx = !((1 << 31) | (1 << 28));
            r.l7_ebx = !(1 << 11);
            r.l7_edx = !((1 << 10) | (1 << 26) | (1 << 29));
            r.l7_2_edx = !(1 << 4);
            r.e8_ebx = !((1 << 14) | (1 << 29));
            r.e21_eax = !((1 << 8) | (1 << 29) | (1 << 30));
        });
        assert!(!none.hypervisor && !none.avx && !none.rtm && !none.md_clear && !none.spec_ctrl);
        assert!(!none.bhi_ctrl && !none.auto_ibrs && !none.btc_no && !none.srso_no && !none.srso_user_kernel_no);
        // The MSR reads are gated on the CPUID bits.
        assert!(needs_arch_caps(&CpuidLeaves { l7_edx: 1 << 29, ..CpuidLeaves::default() }));
        assert!(!needs_arch_caps(&CpuidLeaves { l7_edx: !(1 << 29), ..CpuidLeaves::default() }));
        assert!(needs_mcu_opt_ctrl(arch_cap::GDS_CTRL) && !needs_mcu_opt_ctrl(!arch_cap::GDS_CTRL));
        assert_eq!(Probe::new(&CpuidLeaves::default(), Some(5), 0, 0).arch_caps, 5);
        assert!(Probe::new(&CpuidLeaves::default(), Some(0), 0, 0).has_arch_caps);
        assert!(!Probe::new(&CpuidLeaves::default(), None, 0, 0).has_arch_caps);
    }

    #[test]
    fn the_arch_capabilities_bit_numbers_are_the_documented_ones() {
        // Literal bit numbers, not through `arch_cap::`: a constant off by
        // one reads the neighbouring capability.
        assert_eq!(arch_cap::RDCL_NO, 1 << 0);
        assert_eq!(arch_cap::IBRS_ALL, 1 << 1);
        assert_eq!(arch_cap::RSBA, 1 << 2);
        assert_eq!(arch_cap::MDS_NO, 1 << 5);
        assert_eq!(arch_cap::TSX_CTRL, 1 << 7);
        assert_eq!(arch_cap::TAA_NO, 1 << 8);
        assert_eq!(arch_cap::RRSBA, 1 << 19);
        assert_eq!(arch_cap::BHI_NO, 1 << 20);
        assert_eq!(arch_cap::GDS_CTRL, 1 << 25);
        assert_eq!(arch_cap::GDS_NO, 1 << 26);
        assert_eq!(arch_cap::RFDS_NO, 1 << 27);
        assert_eq!(arch_cap::RFDS_CLEAR, 1 << 28);
        assert_eq!(MSR_IA32_SPEC_CTRL, 0x48);
        assert_eq!(MSR_IA32_ARCH_CAPABILITIES, 0x10A);
        assert_eq!(MSR_IA32_MCU_OPT_CTRL, 0x123);
        assert_eq!(MSR_AMD64_DE_CFG, 0xC001_1029);
        assert_eq!(SPEC_CTRL_IBRS, 1);
        assert_eq!(SPEC_CTRL_BHI_DIS_S, 1 << 10);
        assert_eq!(EFER_AIBRS, 1 << 21);
        assert_eq!(DE_CFG_ZEN2_FP_BACKUP_FIX, 1 << 9);
    }

    // ── the CPU-model matrix (the host half of the q35 gate rows) ───────────

    #[test]
    fn nehalem_haswell_skylake_take_retpoline_and_are_meltdown_vulnerable() {
        for (name, p) in [("nehalem", nehalem()), ("haswell", intel(0x3C)), ("skylake", skylake())] {
            let (r, plan) = decide(&p, &PROBE);
            assert_eq!(r.spectre_v2, Verdict::Mitigated(Method::Retpoline), "{name}: no eIBRS without IBRS_ALL");
            assert_eq!(plan.thunk, ThunkMode::Retpoline, "{name}");
            assert_eq!(plan.spec_ctrl, 0, "{name}: legacy IBRS is not written");
            assert_eq!(r.meltdown.label(), "vulnerable", "{name}: no RDCL_NO");
            assert_eq!(r.l1tf, Verdict::Mitigated(Method::NoStaleFrame), "{name}");
            assert_eq!(r.srso.label(), "not-affected", "{name}");
            assert_eq!(r.zenbleed.label(), "not-affected", "{name}");
        }
        // MD_CLEAR decides MDS: Nehalem's microcode has none, Skylake's does.
        assert_eq!(decide(&nehalem(), &PROBE).0.mds.label(), "vulnerable");
        let (r, plan) = decide(&skylake(), &PROBE);
        assert_eq!(r.mds, Verdict::Mitigated(Method::Verw));
        assert!(plan.verw_on_exit);
        // Skylake is on the Retbleed list; Haswell is not.
        assert_eq!(r.retbleed.label(), "vulnerable");
        assert_eq!(decide(&intel(0x3C), &PROBE).0.retbleed.label(), "not-affected");
        // And on the GDS list, with no GDS_CTRL: the microcode is missing.
        assert_eq!(r.gds.label(), "vulnerable");
        // BHI: retpoline covers a CPU with no eIBRS.
        assert_eq!(r.bhi, Verdict::Mitigated(Method::Retpoline));
    }

    #[test]
    fn icelake_and_sapphire_rapids_take_eibrs_and_are_not_meltdown_vulnerable() {
        let (r, plan) = decide(&icelake_server(), &PROBE);
        assert_eq!(r.spectre_v2, Verdict::Mitigated(Method::Eibrs));
        assert_eq!(plan.spec_ctrl & SPEC_CTRL_IBRS, SPEC_CTRL_IBRS);
        assert_eq!(plan.thunk, ThunkMode::Direct);
        assert_eq!(r.meltdown.label(), "not-affected");
        assert_eq!(r.l1tf.label(), "not-affected");
        assert_eq!(r.mds.label(), "not-affected");
        assert_eq!(r.taa.label(), "not-affected", "TAA_NO, whatever RTM says");
        assert!(!plan.verw_on_exit);
        // No BHI_NO and no BHI_CTRL: eIBRS alone leaves BHI open.
        assert_eq!(r.bhi.label(), "vulnerable");
        let (r, plan) = decide(&sapphire_rapids(), &PROBE);
        assert_eq!(r.spectre_v2, Verdict::Mitigated(Method::Eibrs));
        assert_eq!(r.bhi, Verdict::Mitigated(Method::BhiDisS));
        assert_eq!(plan.spec_ctrl, SPEC_CTRL_IBRS | SPEC_CTRL_BHI_DIS_S);
        assert_eq!(r.gds.label(), "not-affected");
        assert_eq!(r.rfds.label(), "not-affected");
        // eIBRS also covers Retbleed on a part that would be listed.
        let listed = Probe { ident: CpuIdent { model: 0x7E, ..icelake_server().ident }, ..icelake_server() };
        assert_eq!(decide(&listed, &PROBE).0.retbleed, Verdict::Mitigated(Method::Eibrs));
    }

    #[test]
    fn the_epyc_generations_pick_their_own_paths() {
        let (r, plan) = decide(&rome(), &PROBE);
        assert_eq!(r.spectre_v2, Verdict::Mitigated(Method::Retpoline), "Zen 2 has no AutoIBRS");
        assert_eq!(r.meltdown.label(), "not-affected");
        assert_eq!(r.retbleed.label(), "vulnerable", "Zen 2 without BTC_NO");
        assert_eq!(r.srso.label(), "vulnerable");
        assert_eq!(r.zenbleed, Verdict::Mitigated(Method::DeCfg));
        assert!(plan.de_cfg_zenbleed);
        assert_eq!(r.bhi.label(), "not-affected");
        assert_eq!(r.mds.label(), "not-affected");

        let (r, plan) = decide(&milan(), &PROBE);
        assert_eq!(r.spectre_v2, Verdict::Mitigated(Method::Retpoline));
        assert_eq!(r.retbleed.label(), "not-affected");
        assert_eq!(r.zenbleed.label(), "not-affected");
        assert_eq!(r.srso.label(), "vulnerable", "Zen 3 has no user/kernel exemption");
        assert!(!plan.de_cfg_zenbleed && plan.thunk == ThunkMode::Retpoline);

        let (r, plan) = decide(&genoa(), &PROBE);
        assert_eq!(r.spectre_v2, Verdict::Mitigated(Method::AutoIbrs));
        assert!(plan.efer_aibrs && plan.thunk == ThunkMode::Direct && plan.spec_ctrl == 0);
        assert_eq!(r.srso.label(), "not-affected");
    }

    #[test]
    fn the_amd_bits_beat_the_family_table() {
        // BTC_NO clears Retbleed on a Zen 2 part; SRSO_NO clears SRSO.
        let p = Probe { btc_no: true, srso_no: true, ..rome() };
        let r = decide(&p, &PROBE).0;
        assert_eq!(r.retbleed.label(), "not-affected");
        assert_eq!(r.srso.label(), "not-affected");
        // Hygon's Zen derivative (family 18h) is Retbleed/SRSO material like Zen 2.
        let hygon = Probe { spec_ctrl: true, ..cpu(Vendor::Hygon, 0x18, 0x00) };
        let r = decide(&hygon, &PROBE).0;
        assert_eq!((r.retbleed.label(), r.srso.label(), r.meltdown.label()), ("vulnerable", "vulnerable", "not-affected"));
        assert_eq!(decide(&Probe { btc_no: true, ..hygon }, &PROBE).0.retbleed.label(), "not-affected");
        // AutoIBRS on an Intel part is ignored (the bit is AMD's).
        let p = Probe { auto_ibrs: true, ..nehalem() };
        assert_eq!(decide(&p, &PROBE).0.spectre_v2, Verdict::Mitigated(Method::Retpoline));
        // IBRS_ALL without SPEC_CTRL is not eIBRS: nothing to write.
        let p = Probe { spec_ctrl: false, ..icelake_server() };
        assert_eq!(decide(&p, &PROBE).0.spectre_v2, Verdict::Mitigated(Method::Retpoline));
    }

    #[test]
    fn zenbleed_follows_the_microcode_revision_and_avx() {
        let mut p = epyc(0x17, 0x30);
        p.ucode_rev = 0x0830_1000;
        assert_eq!(decide(&p, &PROBE).0.zenbleed, Verdict::Mitigated(Method::DeCfg));
        p.ucode_rev = 0x0830_107A;
        assert_eq!(decide(&p, &PROBE).0.zenbleed.label(), "not-affected");
        assert!(!decide(&p, &PROBE).1.de_cfg_zenbleed);
        // Rome's model 0x31 has no entry: the bit is set whatever the revision.
        let p = Probe { ucode_rev: u32::MAX, ..rome() };
        assert_eq!(decide(&p, &PROBE).0.zenbleed, Verdict::Mitigated(Method::DeCfg));
        // Outside the ranges, or without AVX, nothing is affected.
        assert_eq!(decide(&epyc(0x17, 0x01), &PROBE).0.zenbleed.label(), "not-affected");
        assert_eq!(decide(&Probe { avx: false, ..rome() }, &PROBE).0.zenbleed.label(), "not-affected");
        assert_eq!(decide(&epyc(0x19, 0x30), &PROBE).0.zenbleed.label(), "not-affected");
        // Only a Zen 2 AMD part reads the microcode revision.
        assert!(needs_ucode_rev(&rome().ident));
        assert!(!needs_ucode_rev(&milan().ident) && !needs_ucode_rev(&skylake().ident));
    }

    #[test]
    fn verw_needs_microcode_that_clears_the_buffers() {
        // RFDS: an Alder Lake part with RFDS_CLEAR is mitigated, without it vulnerable.
        let adl = Probe { has_arch_caps: true, arch_caps: arch_cap::RDCL_NO | arch_cap::IBRS_ALL | arch_cap::MDS_NO
            | arch_cap::TAA_NO | arch_cap::GDS_NO, spec_ctrl: true, md_clear: true, ..intel(0x97) };
        assert_eq!(decide(&adl, &PROBE).0.rfds.label(), "vulnerable");
        let with = Probe { arch_caps: adl.arch_caps | arch_cap::RFDS_CLEAR, ..adl };
        let (r, plan) = decide(&with, &PROBE);
        assert_eq!(r.rfds, Verdict::Mitigated(Method::Verw));
        assert!(plan.verw_on_exit);
        assert_eq!(decide(&Probe { arch_caps: adl.arch_caps | arch_cap::RFDS_NO, ..adl }, &PROBE).0.rfds.label(),
                   "not-affected");
        // TAA: only with TSX.
        let tsx = Probe { rtm: true, ..skylake() };
        assert_eq!(decide(&tsx, &PROBE).0.taa, Verdict::Mitigated(Method::Verw));
        assert_eq!(decide(&skylake(), &PROBE).0.taa.label(), "not-affected");
        assert_eq!(decide(&Probe { md_clear: false, ..tsx }, &PROBE).0.taa.label(), "vulnerable");
    }

    #[test]
    fn gds_needs_the_control_and_respects_a_firmware_lock() {
        let base = Probe { has_arch_caps: true, arch_caps: arch_cap::GDS_CTRL, ..skylake() };
        assert_eq!(decide(&base, &PROBE).0.gds, Verdict::Mitigated(Method::Microcode));
        assert!(!decide(&base, &PROBE).1.gds_enable, "already enabled: nothing to write");
        let off = Probe { mcu_opt_ctrl: MCU_OPT_GDS_MITG_DIS, ..base };
        let (r, plan) = decide(&off, &PROBE);
        assert_eq!(r.gds, Verdict::Mitigated(Method::Microcode));
        assert!(plan.gds_enable, "disabled but unlocked: turn it on");
        let locked = Probe { mcu_opt_ctrl: MCU_OPT_GDS_MITG_DIS | MCU_OPT_GDS_MITG_LOCK, ..base };
        assert_eq!(decide(&locked, &PROBE).0.gds.label(), "vulnerable");
        assert_eq!(decide(&Probe { arch_caps: arch_cap::GDS_CTRL | arch_cap::GDS_NO, ..base }, &PROBE).0.gds.label(),
                   "not-affected");
    }

    #[test]
    fn the_policies_are_n_probe_require() {
        // n: nothing is looked at, nothing is done.
        let (r, plan) = decide(&skylake(), &Policies::all(ExtPolicy::Never));
        assert!(r.rows().iter().all(|(_, v)| *v == Verdict::Off));
        assert_eq!(plan, Plan::NONE);
        // One choice at a time.
        let p = Policies { spectre_v2: ExtPolicy::Never, ..PROBE };
        let (r, _) = decide(&skylake(), &p);
        assert_eq!(r.spectre_v2, Verdict::Off);
        assert_eq!(r.bhi.label(), "vulnerable", "BHI depends on the Spectre v2 choice");
        // require: refuses a CPU left vulnerable, names the symbol.
        let req = Policies { meltdown: ExtPolicy::Require, ..PROBE };
        let (r, _) = decide(&skylake(), &req);
        let f = r.refusal(&req).expect("Skylake is Meltdown-vulnerable");
        assert_eq!((f.name, f.symbol), ("meltdown", "X86_MIT_MELTDOWN"));
        // ... and passes one that is not.
        assert_eq!(decide(&icelake_server(), &req).0.refusal(&req), None);
        // probe never refuses.
        assert_eq!(decide(&skylake(), &PROBE).0.refusal(&PROBE), None);
        // require on Spectre v2 means the hardware modes: no thunk is built.
        let req = Policies { spectre_v2: ExtPolicy::Require, ..PROBE };
        let (r, _) = decide(&skylake(), &req);
        assert_eq!(r.spectre_v2.label(), "vulnerable");
        assert_eq!(r.refusal(&req).map(|f| f.symbol), Some("X86_MIT_SPECTRE_V2"));
        assert_eq!(decide(&icelake_server(), &req).0.spectre_v2, Verdict::Mitigated(Method::Eibrs));
        assert_eq!(decide(&genoa(), &req).0.spectre_v2, Verdict::Mitigated(Method::AutoIbrs));
        // MDS and TAA share one choice.
        let req = Policies { mds_taa: ExtPolicy::Require, ..PROBE };
        assert_eq!(decide(&nehalem(), &req).0.refusal(&req).map(|f| f.name), Some("mds"));
    }

    #[test]
    fn an_unknown_vendor_is_not_declared_safe() {
        let (r, _) = decide(&cpu(Vendor::Unknown, 6, 1), &PROBE);
        assert_eq!(r.meltdown.label(), "vulnerable");
        assert_eq!(r.mds.label(), "vulnerable");
        let none = Policies { zenbleed: ExtPolicy::Require, ..PROBE };
        // Zenbleed is an AMD erratum: another vendor simply is not in range.
        assert_eq!(decide(&cpu(Vendor::Unknown, 0x17, 0x31), &none).0.zenbleed.label(), "not-affected");
    }

    #[test]
    fn an_in_order_atom_has_nothing_to_mitigate() {
        let (r, plan) = decide(&intel(0x1C), &PROBE);
        for (name, v) in r.rows() {
            assert!(matches!(v, Verdict::NotAffected(_)), "{name}: {v:?}");
        }
        assert_eq!(plan, Plan::NONE);
    }

    #[test]
    fn the_thunk_patch_is_a_bare_indirect_jump_and_int3s() {
        // The assembled retpoline needs no write; the hardware-protected body
        // is `jmp *%r11` (41 FF E3) followed by int3 to the end of the thunk.
        assert_eq!(thunk_patch(ThunkMode::Retpoline), None);
        let b = thunk_patch(ThunkMode::Direct).unwrap();
        assert_eq!(&b[..3], &[0x41, 0xFF, 0xE3]);
        assert!(b[3..].iter().all(|&x| x == 0xCC), "nothing after the jump may execute");
        assert_eq!(b.len(), THUNK_BYTES);
        // The decision picks Direct exactly where hardware protects the branches.
        for (p, direct) in [(skylake(), false), (icelake_server(), true), (rome(), false), (genoa(), true)] {
            let (_, plan) = decide(&p, &PROBE);
            assert_eq!(thunk_patch(plan.thunk).is_some(), direct);
        }
    }

    #[test]
    fn the_boot_line_names_are_stable() {
        let (r, _) = decide(&skylake(), &PROBE);
        let names: Vec<&str> = r.rows().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["meltdown", "l1tf", "mds", "taa", "rfds", "gds", "spectre_v2", "bhi", "retbleed",
                           "srso", "zenbleed"]);
        for m in [Method::Eibrs, Method::AutoIbrs, Method::Retpoline, Method::BhiDisS, Method::Verw,
                  Method::Microcode, Method::DeCfg, Method::NoStaleFrame] {
            assert!(!m.label().is_empty() && !m.label().contains(' '));
        }
    }
}
