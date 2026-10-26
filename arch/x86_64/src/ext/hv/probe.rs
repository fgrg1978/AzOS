// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Is hardware virtualization usable on this CPU? (Kconfig `X86_SVM`,
//! `X86_VMX`.)
//!
//! Two questions per vendor, asked in this order so no MSR is read on a CPU
//! that lacks it (a `rdmsr` of an absent MSR is a #GP, which on a boot path
//! is a crash):
//!
//! 1. CPUID says the extension exists (`CPUID.80000001:ECX[2]` SVM,
//!    `CPUID.1:ECX[5]` VMX).
//! 2. Firmware has not locked it off (`VM_CR.SVMDIS`; `IA32_FEATURE_CONTROL`
//!    locked without "VMXON outside SMX"), and the second-level translation
//!    the monitor needs exists (NPT; EPT with a 4-level walk and write-back,
//!    `INVEPT`, and unrestricted guest: the AzOS guest starts with paging off
//!    and its other CPUs in real mode, which VMX refuses without it).
//!
//! The decision is [`probe_with`], pure over the CPUID words and a closure
//! that reads an MSR, so the host tests drive every combination. [`probe`]
//! is the same on the real CPU. The verdict is [`Choice`]; [`record`] keeps
//! the last one for whoever prints it after the console is up.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::cpu::features::CpuidLeaves;

/// `VM_CR` (AMD APM vol. 2, 15.30.1): `LOCK` bit 3, `SVMDIS` bit 4.
pub const MSR_VM_CR: u32 = 0xC001_0114;
/// `VM_CR.LOCK`: writes to `SVMDIS` are ignored until reset.
pub const VM_CR_LOCK: u64 = 1 << 3;
/// `VM_CR.SVMDIS`: firmware turned SVM off (`EFER.SVME` writes #GP).
pub const VM_CR_SVMDIS: u64 = 1 << 4;
/// `VM_HSAVE_PA`: the physical page `VMRUN` saves the host state into.
pub const MSR_VM_HSAVE_PA: u32 = 0xC001_0117;
/// `EFER.SVME`: SVM instructions enabled.
pub const EFER_SVME: u64 = 1 << 12;

/// `CPUID.80000001:ECX[2]`: SVM.
pub const CPUID_E1_ECX_SVM: u32 = 1 << 2;
/// `CPUID.1:ECX[5]`: VMX.
pub const CPUID_L1_ECX_VMX: u32 = 1 << 5;

/// `IA32_FEATURE_CONTROL` (Intel SDM vol. 3, 23.7).
pub const MSR_IA32_FEATURE_CONTROL: u32 = 0x3A;
/// Locked: the MSR is read-only until reset.
pub const FC_LOCK: u64 = 1 << 0;
/// VMXON is allowed inside SMX operation.
pub const FC_VMXON_INSIDE_SMX: u64 = 1 << 1;
/// VMXON is allowed outside SMX operation (what an OS without TXT needs).
pub const FC_VMXON_OUTSIDE_SMX: u64 = 1 << 2;

/// The capability MSRs (Intel SDM vol. 4, appendix A).
pub const MSR_VMX_BASIC: u32 = 0x480;
/// Primary processor-based controls (allowed-0 in the low word, allowed-1 in
/// the high).
pub const MSR_VMX_PROCBASED_CTLS: u32 = 0x482;
/// Secondary processor-based controls.
pub const MSR_VMX_PROCBASED_CTLS2: u32 = 0x48B;
/// EPT and VPID capabilities.
pub const MSR_VMX_EPT_VPID_CAP: u32 = 0x48C;
/// What a probe found for one vendor's extension.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Kconfig `n`: not even asked.
    Off,
    /// The CPU does not have it.
    Absent,
    /// The CPU has it and firmware locked it off (BIOS setting).
    FirmwareDisabled,
    /// Enabled, but without the second-level translation the monitor needs.
    NoNestedPaging,
    /// Usable.
    Usable,
}

impl Status {
    /// May a guest run?
    pub const fn usable(self) -> bool {
        matches!(self, Status::Usable)
    }

    /// The word the boot line prints.
    pub const fn name(self) -> &'static str {
        match self {
            Status::Off => "off",
            Status::Absent => "absent",
            Status::FirmwareDisabled => "disabled by firmware",
            Status::NoNestedPaging => "no nested paging",
            Status::Usable => "usable",
        }
    }

    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(c: u8) -> Self {
        match c {
            1 => Status::Absent,
            2 => Status::FirmwareDisabled,
            3 => Status::NoNestedPaging,
            4 => Status::Usable,
            _ => Status::Off,
        }
    }
}

/// `CPUID.8000000A` decoded (AMD APM vol. 3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SvmCaps {
    /// SVM revision (EAX[7:0]).
    pub revision: u8,
    /// Number of address space ids (EBX), ASID 0 being the host's.
    pub nasid: u32,
    /// Nested paging (EDX[0]).
    pub npt: bool,
    /// `SVML`: the SVM lock and key (EDX[2]).
    pub svm_lock: bool,
    /// Next-RIP save on #VMEXIT (EDX[3]).
    pub nrips: bool,
    /// VMCB clean bits (EDX[5]).
    pub vmcb_clean: bool,
    /// Flush by ASID (EDX[6]).
    pub flush_by_asid: bool,
    /// Decode assists (EDX[7]).
    pub decode_assists: bool,
    /// Pause filter (EDX[10]).
    pub pause_filter: bool,
    /// Virtual GIF (EDX[16]).
    pub vgif: bool,
}

/// Decode `CPUID.8000000A` EAX, EBX, EDX.
pub const fn decode_svm_leaf(eax: u32, ebx: u32, edx: u32) -> SvmCaps {
    SvmCaps {
        revision: (eax & 0xFF) as u8,
        nasid: ebx,
        npt: edx & 1 != 0,
        svm_lock: edx & (1 << 2) != 0,
        nrips: edx & (1 << 3) != 0,
        vmcb_clean: edx & (1 << 5) != 0,
        flush_by_asid: edx & (1 << 6) != 0,
        decode_assists: edx & (1 << 7) != 0,
        pause_filter: edx & (1 << 10) != 0,
        vgif: edx & (1 << 16) != 0,
    }
}

/// The SVM verdict. `vm_cr` is read only after CPUID said SVM exists.
pub const fn svm_status(allowed: bool, cpuid_svm: bool, vm_cr: u64, caps: &SvmCaps) -> Status {
    if !allowed {
        Status::Off
    } else if !cpuid_svm {
        Status::Absent
    } else if vm_cr & VM_CR_SVMDIS != 0 {
        Status::FirmwareDisabled
    } else if !caps.npt || caps.nasid < 2 {
        Status::NoNestedPaging
    } else {
        Status::Usable
    }
}

/// The VMX capability MSRs the monitor depends on, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct VmxCaps {
    /// VMCS / VMXON revision identifier (`IA32_VMX_BASIC[30:0]`).
    pub revision: u32,
    /// The VMCS may be accessed write-back (`[53:50]` = 6).
    pub wb_vmcs: bool,
    /// Secondary controls exist (`PROCBASED_CTLS[63]`).
    pub secondary: bool,
    /// "Enable EPT" can be set (`PROCBASED_CTLS2[33]`).
    pub ept: bool,
    /// "Unrestricted guest" can be set (`PROCBASED_CTLS2[39]`): a real-mode guest.
    pub unrestricted_guest: bool,
    /// 4-level EPT walk (`EPT_VPID_CAP[6]`).
    pub ept_4level: bool,
    /// Write-back EPT paging structures and leaves (`[14]`).
    pub ept_wb: bool,
    /// 2 MiB EPT leaves (`[16]`).
    pub ept_2m: bool,
    /// 1 GiB EPT leaves (`[17]`).
    pub ept_1g: bool,
    /// `INVEPT` (`[20]`).
    pub invept: bool,
}

/// Decode `IA32_VMX_BASIC`, `PROCBASED_CTLS`, `PROCBASED_CTLS2` and
/// `EPT_VPID_CAP`. The secondary controls' allowed-1 half is the high word.
pub const fn decode_vmx_caps(basic: u64, proc: u64, proc2: u64, ept_vpid: u64) -> VmxCaps {
    let secondary = proc & (1 << 63) != 0;
    VmxCaps {
        revision: (basic & 0x7FFF_FFFF) as u32,
        wb_vmcs: (basic >> 50) & 0xF == 6,
        secondary,
        ept: secondary && proc2 & (1 << 33) != 0,
        unrestricted_guest: secondary && proc2 & (1 << 39) != 0,
        ept_4level: ept_vpid & (1 << 6) != 0,
        ept_wb: ept_vpid & (1 << 14) != 0,
        ept_2m: ept_vpid & (1 << 16) != 0,
        ept_1g: ept_vpid & (1 << 17) != 0,
        invept: ept_vpid & (1 << 20) != 0,
    }
}

/// Can VMXON run outside SMX with this `IA32_FEATURE_CONTROL`?
///
/// Locked without the "outside SMX" bit is the BIOS setting that disables
/// VMX: only a reset changes it. Unlocked means the OS may set the bits and
/// lock.
pub const fn feature_control_allows(fc: u64) -> bool {
    fc & FC_LOCK == 0 || fc & FC_VMXON_OUTSIDE_SMX != 0
}

/// The VMX verdict. `fc` and `caps` are read only after CPUID said VMX exists.
pub const fn vmx_status(allowed: bool, cpuid_vmx: bool, fc: u64, caps: &VmxCaps) -> Status {
    if !allowed {
        Status::Off
    } else if !cpuid_vmx {
        Status::Absent
    } else if !feature_control_allows(fc) {
        Status::FirmwareDisabled
    } else if !(caps.ept && caps.ept_4level && caps.ept_wb && caps.wb_vmcs && caps.unrestricted_guest && caps.invept) {
        Status::NoNestedPaging
    } else {
        Status::Usable
    }
}

/// Which hypervisor backend, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// No hardware virtualization is usable.
    None,
    /// AMD SVM with nested paging.
    Svm,
    /// Intel VMX with EPT.
    Vmx,
}

impl Kind {
    /// The word the boot line prints.
    pub const fn name(self) -> &'static str {
        match self {
            Kind::None => "none",
            Kind::Svm => "svm",
            Kind::Vmx => "vmx",
        }
    }
}

/// The outcome of the probe: the backend, and when there is none, why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Choice {
    pub kind: Kind,
    /// The status that decided it: `Usable` for a backend, the most
    /// informative refusal for [`Kind::None`].
    pub why: Status,
}

const fn rank(s: Status) -> u8 {
    match s {
        Status::FirmwareDisabled => 4,
        Status::NoNestedPaging => 3,
        Status::Absent => 2,
        _ => 1,
    }
}

/// Pick the backend. No backend reports the most informative refusal:
/// firmware-disabled, then no nested paging, then absent, then off. (A CPU
/// with SVM disabled in firmware is "disabled by firmware", not "VMX
/// absent".)
pub const fn choose(svm: Status, vmx: Status) -> Choice {
    if svm.usable() {
        return Choice { kind: Kind::Svm, why: Status::Usable };
    }
    if vmx.usable() {
        return Choice { kind: Kind::Vmx, why: Status::Usable };
    }
    let why = if rank(svm) >= rank(vmx) { svm } else { vmx };
    Choice { kind: Kind::None, why }
}

/// Everything the probe found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Probe {
    pub svm: Status,
    pub svm_caps: SvmCaps,
    pub vmx: Status,
    pub vmx_caps: VmxCaps,
}

impl Probe {
    /// The backend this probe selects.
    pub const fn choice(&self) -> Choice {
        choose(self.svm, self.vmx)
    }
}

/// The probe over given CPUID words and an MSR reader. `svm_leaf` is
/// `CPUID.8000000A` as `(eax, ebx, edx)`. `rdmsr` is called only for an MSR
/// the CPUID words say exists, and only when the extension is `allowed`
/// (the Kconfig choice is not `n`).
pub fn probe_with(
    allow_svm: bool,
    allow_vmx: bool,
    leaves: &CpuidLeaves,
    svm_leaf: (u32, u32, u32),
    mut rdmsr: impl FnMut(u32) -> u64,
) -> Probe {
    let cpuid_svm = leaves.e1_ecx & CPUID_E1_ECX_SVM != 0;
    let svm_caps = if allow_svm && cpuid_svm {
        decode_svm_leaf(svm_leaf.0, svm_leaf.1, svm_leaf.2)
    } else {
        SvmCaps::default()
    };
    let vm_cr = if allow_svm && cpuid_svm { rdmsr(MSR_VM_CR) } else { 0 };
    let svm = svm_status(allow_svm, cpuid_svm, vm_cr, &svm_caps);

    let cpuid_vmx = leaves.l1_ecx & CPUID_L1_ECX_VMX != 0;
    let (fc, vmx_caps) = if allow_vmx && cpuid_vmx {
        let fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
        // The capability MSRs exist whenever CPUID says VMX does; reading them
        // before the firmware verdict is what lets the boot line say why.
        let basic = rdmsr(MSR_VMX_BASIC);
        let proc = rdmsr(MSR_VMX_PROCBASED_CTLS);
        let proc2 = if proc & (1 << 63) != 0 { rdmsr(MSR_VMX_PROCBASED_CTLS2) } else { 0 };
        let ept = if proc2 & (1 << 33) != 0 { rdmsr(MSR_VMX_EPT_VPID_CAP) } else { 0 };
        (fc, decode_vmx_caps(basic, proc, proc2, ept))
    } else {
        (0, VmxCaps::default())
    };
    let vmx = vmx_status(allow_vmx, cpuid_vmx, fc, &vmx_caps);
    Probe { svm, svm_caps, vmx, vmx_caps }
}

/// The probe on this CPU: [`probe_with`] over the real CPUID and MSRs. Off
/// bare-metal x86_64 (the host stub) every word reads zero: nothing present.
pub fn probe(allow_svm: bool, allow_vmx: bool) -> Probe {
    let leaves = crate::cpu::features::read_cpuid();
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let svm_leaf = if allow_svm && leaves.e1_ecx & CPUID_E1_ECX_SVM != 0 { read_svm_leaf() } else { (0, 0, 0) };
        probe_with(allow_svm, allow_vmx, &leaves, svm_leaf, crate::cpu::rdmsr)
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        probe_with(allow_svm, allow_vmx, &leaves, (0, 0, 0), |_| 0)
    }
}

/// `CPUID.8000000A` (EAX, EBX, EDX), guarded by the maximum extended leaf.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn read_svm_leaf() -> (u32, u32, u32) {
    use core::arch::x86_64::__cpuid_count;
    if __cpuid_count(0x8000_0000, 0).eax < 0x8000_000A {
        return (0, 0, 0);
    }
    let r = __cpuid_count(0x8000_000A, 0);
    (r.eax, r.ebx, r.edx)
}

/// `CPUID.8000000A` of this CPU, decoded.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn svm_caps_now() -> SvmCaps {
    let (a, b, d) = read_svm_leaf();
    decode_svm_leaf(a, b, d)
}

static RECORD: AtomicU8 = AtomicU8::new(0);

/// Keep `c` as the boot's verdict (the boot CPU, once).
pub fn record_set(c: Choice) {
    let k = match c.kind {
        Kind::None => 0u8,
        Kind::Svm => 1,
        Kind::Vmx => 2,
    };
    RECORD.store(k << 4 | c.why.code(), Ordering::Release);
}

/// The verdict [`record_set`] kept; `None`/`Off` before the probe ran.
pub fn record() -> Choice {
    let b = RECORD.load(Ordering::Acquire);
    let kind = match b >> 4 {
        1 => Kind::Svm,
        2 => Kind::Vmx,
        _ => Kind::None,
    };
    Choice { kind, why: Status::from_code(b & 0xF) }
}
