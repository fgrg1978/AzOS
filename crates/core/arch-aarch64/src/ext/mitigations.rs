// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Arm speculation mitigations (config/Kconfig.mitigations, `A64_MIT_*`):
//! what this core is exposed to, from its ID registers first and the MIDR
//! tables only for what has no register bit, what the firmware offers for the
//! rest, and what the kernel does about it. The aarch64 twin of
//! `arch-x86_64/src/ext/mitigations.rs`.
//!
//! Everything is decided PER CORE: `boot.S` runs it on every CPU, the
//! secondaries included, so a big.LITTLE part gets the verdict of each core
//! type from that core's own MIDR and ID registers.
//!
//! | bug (Kconfig)               | the CPU / firmware says                 | the kernel                  |
//! |-----------------------------|-----------------------------------------|-----------------------------|
//! | Spectre v2 (`SPECTRE_V2`)   | `ID_AA64PFR0_EL1.CSV2` >= 1: isolated   | nothing to do               |
//! |                             | no CSV2, in-order core (A35/53/55/510)  | not affected                |
//! |                             | no CSV2, firmware: WORKAROUND_1 = 1     | not affected                |
//! |                             | no CSV2, any other                      | firmware call at entry: OPEN|
//! | Spectre v4 (`SSB`)          | in-order core (A35/53/55/510)           | not affected                |
//! |                             | `ID_AA64PFR1_EL1.SSBS` >= 1             | `PSTATE.SSBS` = 0: MITIGATED|
//! |                             | firmware: WORKAROUND_2 = 0              | call once per CPU: MITIGATED|
//! |                             | firmware: WORKAROUND_2 = 1 / -2         | not affected                |
//! |                             | no SSBS, no firmware workaround         | OPEN                        |
//! | Spectre-BHB (`BHB`)         | `ID_AA64MMFR1_EL1.ECBHB` >= 1           | hardware clears it          |
//! |                             | `ID_AA64ISAR2_EL1.CLRBHB` >= 1          | `clrbhb` at entry: OPEN     |
//! |                             | MIDR in the k-loop table                | k branches at entry: OPEN   |
//! |                             | unlisted, firmware: WORKAROUND_3 = 0    | firmware call at entry: OPEN|
//! |                             | unlisted, WORKAROUND_3 = -2 / absent    | not affected                |
//! |                             | anything else                           | not affected                |
//!
//! OPEN means the tree has no mitigation for it yet: probe prints it as
//! vulnerable, `require` refuses the boot (on a secondary, the power-off).
//! The three OPEN rows are mitigations that run on EVERY entry from EL0: the
//! SMCCC `ARCH_WORKAROUND_1` call (Spectre v2), `clrbhb` and the branch
//! history clearing loop (Spectre-BHB, or `ARCH_WORKAROUND_3`). They belong in
//! the lower-EL vector slots of `kernel/src/entry/aarch64/asm/trap_entry.S`
//! and cost a few instructions (a firmware call for WORKAROUND_1/3) per EL0
//! entry; they are not written. The firmware column only decides what the
//! reason line says: "the firmware offers it" is a different gap from "nothing
//! to call".
//!
//! What the kernel does once per CPU, [`apply_this_cpu`]: `PSTATE.SSBS` = 0 on
//! a core with FEAT_SSBS, so a load never bypasses an older store to the same
//! address, kernel and ring 3 alike (EL0 starts with SSBS = 0 as well; the
//! user-controlled bit is not exposed); or, on a core without it, the firmware
//! call `SMCCC_ARCH_WORKAROUND_2(1)`, which keeps the firmware's mitigation on
//! for this PE until it is turned off (it never is).
//!
//! The firmware is asked only when the answer matters (a core that needs a
//! workaround and has no bit for it) and only through `PSCI_FEATURES` first:
//! QEMU's PSCI shim answers PSCI function ids only, and an `HVC` or `SMC` with
//! any other id would be an undefined instruction there.
//!
//! The MIDR lists are Linux's (arch/arm64/kernel/proton-pack.c:
//! `spectre_v2_safe_list`, `spectre_v4_safe_list`, `spectre_bhb_loop_affected`)
//! as remembered, Arm cores only, not machine-checked against Arm's Cache
//! Speculation Issues update; a core on no list reads as unaffected by BHB.
//! The host tests pin what the tables say, not what Arm says. Audit them
//! before relying on a verdict for a core this table has never seen.

use azos_arch_api::isa::ExtPolicy;

/// `ID_AA64*` field at `shift` (4 bits).
const fn field(reg: u64, shift: u32) -> u64 {
    (reg >> shift) & 0xf
}

/// Arm Limited, the implementer of the cores below.
pub const IMPL_ARM: u8 = 0x41;

pub const A35: u16 = 0xD04;
pub const A53: u16 = 0xD03;
pub const A55: u16 = 0xD05;
pub const A510: u16 = 0xD46;
pub const A57: u16 = 0xD07;
pub const A72: u16 = 0xD08;
pub const A76: u16 = 0xD0B;
pub const A76AE: u16 = 0xD0E;
pub const A77: u16 = 0xD0D;
pub const A78: u16 = 0xD41;
pub const A78AE: u16 = 0xD42;
pub const A78C: u16 = 0xD4B;
pub const A710: u16 = 0xD47;
pub const X1: u16 = 0xD44;
pub const X1C: u16 = 0xD4C;
pub const X2: u16 = 0xD48;
pub const N1: u16 = 0xD0C;
pub const N2: u16 = 0xD49;
pub const V1: u16 = 0xD40;

/// In-order Arm cores that are affected by neither Spectre v2 nor v4.
const IN_ORDER: [u16; 4] = [A35, A53, A55, A510];

/// The branches of the Spectre-BHB clearing loop for an Arm core (`k`), 0 for
/// a core that needs none. Linux's `spectre_bhb_{k8,k24,k32}_list`.
pub const fn bhb_loop(implementer: u8, part: u16) -> u8 {
    if implementer != IMPL_ARM {
        return 0;
    }
    match part {
        A72 | A57 => 8,
        A76 | A76AE | A77 | N1 => 24,
        A78 | A78AE | A78C | X1 | X1C | A710 | X2 | N2 | V1 => 32,
        _ => 0,
    }
}

const fn in_order(implementer: u8, part: u16) -> bool {
    if implementer != IMPL_ARM {
        return false;
    }
    let mut i = 0;
    while i < IN_ORDER.len() {
        if IN_ORDER[i] == part {
            return true;
        }
        i += 1;
    }
    false
}

/// `SMCCC_VERSION`.
pub const SMCCC_VERSION: u32 = 0x8000_0000;
/// `SMCCC_ARCH_FEATURES`.
pub const SMCCC_ARCH_FEATURES: u32 = 0x8000_0001;
/// `SMCCC_ARCH_WORKAROUND_1`: invalidate the branch predictor (Spectre v2).
pub const SMCCC_ARCH_WORKAROUND_1: u32 = 0x8000_8000;
/// `SMCCC_ARCH_WORKAROUND_2`: switch the speculative-store-bypass mitigation.
pub const SMCCC_ARCH_WORKAROUND_2: u32 = 0x8000_7FFF;
/// `SMCCC_ARCH_WORKAROUND_3`: the Spectre-BHB mitigation.
pub const SMCCC_ARCH_WORKAROUND_3: u32 = 0x8000_3FFF;
/// `SMCCC_VERSION` 1.1: the first with `SMCCC_ARCH_FEATURES`.
pub const SMCCC_1_1: i32 = 0x1_0001;

/// What the firmware says about one workaround.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FwState {
    /// Not asked: this core needs no workaround, or has a register bit for it.
    #[default]
    Unasked,
    /// Asked, and the firmware does not implement it (or has no SMCCC 1.1).
    Absent,
    /// Implemented, and this PE needs it.
    Offered,
    /// Implemented, and this PE does not need it.
    NotRequired,
}

impl FwState {
    pub const fn label(self) -> &'static str {
        match self {
            FwState::Unasked => "-",
            FwState::Absent => "absent",
            FwState::Offered => "offered",
            FwState::NotRequired => "not-required",
        }
    }
}

/// The three workarounds [`FwState`] is asked about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Workaround {
    /// `ARCH_WORKAROUND_1`.
    Wa1,
    /// `ARCH_WORKAROUND_2`.
    Wa2,
    /// `ARCH_WORKAROUND_3`.
    Wa3,
}

impl Workaround {
    pub const fn fn_id(self) -> u32 {
        match self {
            Workaround::Wa1 => SMCCC_ARCH_WORKAROUND_1,
            Workaround::Wa2 => SMCCC_ARCH_WORKAROUND_2,
            Workaround::Wa3 => SMCCC_ARCH_WORKAROUND_3,
        }
    }
}

/// `SMCCC_ARCH_FEATURES(workaround)`'s return value `ret` (w0), as Linux reads
/// it: 0 implemented and required; WORKAROUND_1 and 2 return 1 for "implemented,
/// this PE is not affected"; WORKAROUND_2 and 3 return -2 (`NOT_REQUIRED`);
/// everything else, -1 (`NOT_SUPPORTED`) included, is absent. A value the
/// specification does not define for that workaround reads as absent, never as
/// "not affected".
pub const fn fw_state(w: Workaround, ret: i32) -> FwState {
    match (w, ret) {
        (_, 0) => FwState::Offered,
        (Workaround::Wa1 | Workaround::Wa2, 1) => FwState::NotRequired,
        (Workaround::Wa2 | Workaround::Wa3, -2) => FwState::NotRequired,
        _ => FwState::Absent,
    }
}

/// The answers of [`query_firmware`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Firmware {
    pub wa1: FwState,
    pub wa2: FwState,
    pub wa3: FwState,
}

/// What the boot reads: the MIDR's two identifying fields, the four ID
/// registers that carry the bits, and what the firmware said.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Probe {
    pub implementer: u8,
    pub part: u16,
    /// ID_AA64PFR0_EL1.
    pub pfr0: u64,
    /// ID_AA64PFR1_EL1.
    pub pfr1: u64,
    /// ID_AA64MMFR1_EL1.
    pub mmfr1: u64,
    /// ID_AA64ISAR2_EL1 (reads 0 on a core that predates it).
    pub isar2: u64,
    /// SMCCC answers; [`FwState::Unasked`] everywhere until [`query_firmware`] ran.
    pub fw: Firmware,
}

impl Probe {
    /// CSV2 [59:56]: this PE's branch predictor does not let one context steer another's.
    pub const fn csv2(&self) -> bool {
        field(self.pfr0, 56) >= 1
    }

    /// FEAT_SSBS (PFR1.SSBS [7:4]).
    pub const fn ssbs(&self) -> bool {
        field(self.pfr1, 4) >= 1
    }

    /// FEAT_ECBHB (MMFR1.ECBHB [63:60]): the hardware clears the branch history on exception entry.
    pub const fn ecbhb(&self) -> bool {
        field(self.mmfr1, 60) >= 1
    }

    /// FEAT_CLRBHB (ISAR2.CLRBHB [31:28]): the `clrbhb` instruction exists.
    pub const fn clrbhb(&self) -> bool {
        field(self.isar2, 28) >= 1
    }

    const fn in_order(&self) -> bool {
        in_order(self.implementer, self.part)
    }
}

/// The three choices.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policies {
    pub spectre_v2: ExtPolicy,
    pub ssb: ExtPolicy,
    pub bhb: ExtPolicy,
}

/// The workarounds whose firmware answer would change a verdict for `pr` under
/// `pol`, in [`Workaround`] order (1, 2, 3). Pure: [`query_firmware`] asks
/// exactly these, and a core with every bit it needs asks none.
pub const fn wants(pr: &Probe, pol: &Policies) -> [bool; 3] {
    let wa1 = !matches!(pol.spectre_v2, ExtPolicy::Never) && !pr.csv2() && !pr.in_order();
    let wa2 = !matches!(pol.ssb, ExtPolicy::Never) && !pr.in_order() && !pr.ssbs();
    // Only a core on no loop list: a listed core is affected whatever the
    // firmware says (Linux asks the firmware only after the lists), and the
    // firmware may know a core the table has never seen.
    let wa3 = !matches!(pol.bhb, ExtPolicy::Never)
        && !pr.ecbhb()
        && !pr.clrbhb()
        && bhb_loop(pr.implementer, pr.part) == 0;
    [wa1, wa2, wa3]
}

/// One bug's outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Choice `n`: not looked at, nothing done.
    Off,
    /// The core is not exposed (a register bit, the in-order list or the firmware says so).
    NotAffected,
    /// The core protects itself (CSV2, ECBHB).
    Hardware,
    /// The kernel closed it ([`apply_this_cpu`]).
    Mitigated,
    /// Exposed, and the tree has no mitigation for it yet.
    Vulnerable(&'static str),
}

impl Verdict {
    pub const fn label(self) -> &'static str {
        match self {
            Verdict::Off => "n",
            Verdict::NotAffected => "not-affected",
            Verdict::Hardware => "hardware",
            Verdict::Mitigated => "mitigated",
            Verdict::Vulnerable(_) => "vulnerable",
        }
    }
}

/// The verdicts, and what [`apply_this_cpu`] does about them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub spectre_v2: Verdict,
    pub ssb: Verdict,
    pub bhb: Verdict,
    /// The BHB-clearing loop this core would need (0: none), for the line.
    pub bhb_k: u8,
    /// Clear `PSTATE.SSBS` on this CPU.
    pub clear_ssbs: bool,
    /// Call `SMCCC_ARCH_WORKAROUND_2(1)` on this CPU.
    pub fw_ssbd: bool,
}

/// The first `require`d choice whose verdict is `Vulnerable`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    pub name: &'static str,
    pub symbol: &'static str,
    pub why: &'static str,
}

impl Report {
    /// The verdicts with their boot-line names, in print order.
    pub fn rows(&self) -> [(&'static str, Verdict); 3] {
        [("spectre_v2", self.spectre_v2), ("ssb", self.ssb), ("bhb", self.bhb)]
    }

    /// A `require`d choice the core leaves vulnerable.
    pub fn refusal(&self, p: &Policies) -> Option<Refusal> {
        let checks: [(&'static str, &'static str, ExtPolicy, Verdict); 3] = [
            ("spectre_v2", "A64_MIT_SPECTRE_V2", p.spectre_v2, self.spectre_v2),
            ("ssb", "A64_MIT_SSB", p.ssb, self.ssb),
            ("bhb", "A64_MIT_BHB", p.bhb, self.bhb),
        ];
        checks.into_iter().find_map(|(name, symbol, pol, v)| match v {
            Verdict::Vulnerable(why) if pol == ExtPolicy::Require => Some(Refusal { name, symbol, why }),
            _ => None,
        })
    }
}

/// Take the decision for `pr` under `pol`. Pure.
pub const fn decide(pr: &Probe, pol: &Policies) -> Report {
    let ordered = pr.in_order();
    let spectre_v2 = match pol.spectre_v2 {
        ExtPolicy::Never => Verdict::Off,
        _ => {
            if pr.csv2() {
                Verdict::Hardware
            } else if ordered || matches!(pr.fw.wa1, FwState::NotRequired) {
                Verdict::NotAffected
            } else if matches!(pr.fw.wa1, FwState::Offered) {
                Verdict::Vulnerable("no CSV2; the firmware offers ARCH_WORKAROUND_1 but the call at EL0 entry is not wired")
            } else {
                Verdict::Vulnerable("no CSV2 and no ARCH_WORKAROUND_1 from the firmware")
            }
        }
    };
    let mut clear_ssbs = false;
    let mut fw_ssbd = false;
    let ssb = match pol.ssb {
        ExtPolicy::Never => Verdict::Off,
        _ => {
            if ordered {
                Verdict::NotAffected
            } else if pr.ssbs() {
                clear_ssbs = true;
                Verdict::Mitigated
            } else if matches!(pr.fw.wa2, FwState::Offered) {
                fw_ssbd = true;
                Verdict::Mitigated
            } else if matches!(pr.fw.wa2, FwState::NotRequired) {
                Verdict::NotAffected
            } else {
                Verdict::Vulnerable("no FEAT_SSBS and no ARCH_WORKAROUND_2 from the firmware")
            }
        }
    };
    let k = bhb_loop(pr.implementer, pr.part);
    let bhb = match pol.bhb {
        ExtPolicy::Never => Verdict::Off,
        _ => {
            if pr.ecbhb() {
                Verdict::Hardware
            } else if pr.clrbhb() {
                Verdict::Vulnerable("clrbhb exists; the instruction is not issued at EL0 entry")
            } else if k != 0 {
                // A listed core is affected; the firmware is not consulted for it.
                Verdict::Vulnerable("the branch-history clearing loop at EL0 entry is not written")
            } else if matches!(pr.fw.wa3, FwState::Offered) {
                Verdict::Vulnerable("the firmware offers ARCH_WORKAROUND_3; neither it nor the clearing loop is issued at EL0 entry")
            } else {
                Verdict::NotAffected
            }
        }
    };
    Report { spectre_v2, ssb, bhb, bhb_k: k, clear_ssbs, fw_ssbd }
}

/// `SCTLR_EL1.DSSBS` (bit 44): the `PSTATE.SSBS` an exception to EL1 starts with.
pub const SCTLR_EL1_DSSBS: u64 = 1 << 44;

/// Read what [`decide`] needs from this core's own registers (no firmware call).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn probe() -> Probe {
    let m = crate::cpu::read_midr();
    let r = crate::cpu::features::read_id_regs();
    Probe {
        implementer: m.implementer,
        part: m.part_num,
        pfr0: r.pfr0,
        pfr1: r.pfr1,
        mmfr1: r.mmfr1,
        isar2: r.isar2,
        fw: Firmware::default(),
    }
}

/// [`probe`], then the firmware's answers for what [`wants`] says matters.
/// Needs the PSCI conduit ([`crate::firmware::conduit`]) to be the right one:
/// on the boot CPU only after `smp_probe` selected it.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn probe_with_firmware(pol: &Policies) -> Probe {
    let mut pr = probe();
    pr.fw = query_firmware(wants(&pr, pol));
    pr
}

/// Ask the firmware about the workarounds in `want` (see [`wants`]). Nothing
/// is sent when `want` is all false. `PSCI_FEATURES(SMCCC_VERSION)` goes
/// first, the one discovery call a PSCI-only shim (QEMU) understands: without
/// an answer there, or a version below 1.1, every asked workaround is absent.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn query_firmware(want: [bool; 3]) -> Firmware {
    use crate::firmware::{features, psci_call};
    if !(want[0] || want[1] || want[2]) {
        return Firmware::default();
    }
    let absent = |asked: bool| if asked { FwState::Absent } else { FwState::Unasked };
    let none = Firmware { wa1: absent(want[0]), wa2: absent(want[1]), wa3: absent(want[2]) };
    if features(SMCCC_VERSION) < 0 {
        return none;
    }
    if (psci_call(SMCCC_VERSION, 0, 0, 0) as i32) < SMCCC_1_1 {
        return none;
    }
    let ask = |asked: bool, w: Workaround| {
        if asked {
            fw_state(w, psci_call(SMCCC_ARCH_FEATURES, w.fn_id() as u64, 0, 0) as i32)
        } else {
            FwState::Unasked
        }
    };
    Firmware {
        wa1: ask(want[0], Workaround::Wa1),
        wa2: ask(want[1], Workaround::Wa2),
        wa3: ask(want[2], Workaround::Wa3),
    }
}

/// Write this CPU's controls for the verdicts in `r`: `PSTATE.SSBS` = 0 now and
/// for every exception entry (`SCTLR_EL1.DSSBS` = 0) where the core has
/// FEAT_SSBS, or `ARCH_WORKAROUND_2(1)` where the firmware does it. Idempotent,
/// so the boot CPU runs it twice: from boot.S with the register-only report
/// (no conduit yet), and from the boot hooks with the firmware's answers.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn apply_this_cpu(r: &Report) {
    if r.clear_ssbs {
        // SAFETY: only reached when ID_AA64PFR1_EL1.SSBS said FEAT_SSBS, so the
        // PSTATE form `MSR SSBS, #imm` exists (the register form is FEAT_SSBS2,
        // SSBS == 2, and is UNDEFINED at 1) and DSSBS is not RES0.
        unsafe {
            core::arch::asm!(
                ".arch_extension ssbs",
                "msr ssbs, #0",
                "mrs {t}, SCTLR_EL1",
                "bic {t}, {t}, {dssbs}",
                "msr SCTLR_EL1, {t}",
                "isb",
                t = out(reg) _, dssbs = in(reg) SCTLR_EL1_DSSBS,
                options(nomem, nostack),
            );
        }
    }
    if r.fw_ssbd {
        // Reached only on the firmware's own "implemented and required" for
        // this PE, through the conduit the boot selected.
        crate::firmware::psci_call(SMCCC_ARCH_WORKAROUND_2, 1, 0, 0);
    }
}

/// The Kconfig policies (`azos_arch_api::isa::aarch64::MIT_*`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn policies() -> Policies {
    use azos_arch_api::isa::aarch64 as p;
    Policies { spectre_v2: p::MIT_SPECTRE_V2, ssb: p::MIT_SSB, bhb: p::MIT_BHB }
}
