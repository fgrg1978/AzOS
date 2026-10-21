// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Intel VMX: the VMCS and the entry loop, as a second backend of the same
//! guest entry ([`super::vcpu`]) that SVM runs.
//!
//! # Shape: the VMCB stays the vCPU's state
//!
//! A VMCS is opaque (software reads and writes fields by encoding, with
//! `VMREAD` / `VMWRITE`, and cannot keep it in memory), and the CPU holds it
//! while a CPU runs it. Everything above the CPU in [`super::vcpu`], [`super::serve`], [`super::msr`],
//! [`super::mmio`] and [`super::inject`] (the guest's CPUID and MSRs, the
//! virtual APIC, event injection, the interrupt window, NMI blocking, INIT and
//! startup, the decode of a device access) is written against the [`Vmcb`]
//! image and the general registers. This backend keeps that image as the
//! vCPU's architectural state and translates it at the edge of each entry:
//!
//! 1. [`load`]: the image, the controls and the host state go into the VMCS
//!    (the VMCS is `VMCLEAR`ed at the end of every entry, so a vCPU that moves
//!    to another CPU needs nothing: it is `VMPTRLD`ed and `VMLAUNCH`ed again
//!    from the image);
//! 2. the entry (`VMLAUNCH`, [`VmxCpu::enter`]);
//! 3. [`store`]: the guest state comes back into the image, and the exit
//!    becomes the SVM exit code and information words the service already
//!    decodes ([`to_svm`], then [`super::exit::svm`]).
//!
//! The price is paid per exit (about a hundred `VMREAD`/`VMWRITE`s and a
//! `VMCLEAR`): the VMX path is the Intel fallback of a hypervisor whose
//! primary backend is SVM, and it buys the whole guest service (the same
//! CPUID, MSRs, APIC, MMIO emulation and INIT/SIPI the SVM guest has)
//! without a second copy of it. A dirty-field cache and a lazy `VMCLEAR` are
//! a follow-up for when measurements on an Intel machine ask for them.
//!
//! # What the translation decides
//!
//! * **Controls** ([`Controls::resolve`]): the `TRUE_*` capability MSRs, each
//!   wanted bit checked against allowed-1 and the allowed-0 bits forced on.
//!   Required: external-interrupt, NMI and virtual-NMI exiting; HLT, MONITOR,
//!   MWAIT, CR8 and unconditional I/O exiting; MSR bitmaps; secondary controls
//!   with EPT, **unrestricted guest** (the PVH boot CPU starts with paging off
//!   and every other CPU in real mode: VMX refuses both without it) and
//!   WBINVD exiting; the 64-bit host, PAT and EFER save/load controls.
//!   Optional: VPID, INVPCID.
//! * **I/O**: every port exits (unconditional I/O exiting, no bitmaps), the
//!   service answers an empty bus. **MSRs**: [`build_msr_bitmap`] is the SVM
//!   permission map's twin (a host test pins that they agree on every MSR);
//!   what the VMCS does not hold (`STAR`, `LSTAR`, `CSTAR`, `SFMASK`,
//!   `KernelGSBase`) is swapped by the CPU through the entry/exit MSR lists
//!   ([`Extra`]).
//! * **CR0 / CR4**: the bits VMX forces on (`NE`, `VMXE`) are the host's; the
//!   guest-host masks and read shadows hide `VMXE`, and a guest write that
//!   would clear a forced bit is an exit nothing serves (the vCPU stops,
//!   visibly). `CR8` is the vLAPIC's business, not the CPU's TPR: the access
//!   is emulated against the image's virtual TPR without leaving the entry.
//! * **Events**: SVM's `EVENT_INJ` and `EXITINTINFO` share VMX's bit layout
//!   for external interrupts, NMIs and hardware exceptions; the interrupt
//!   window is interrupt-window exiting; the end of an NMI handler (SVM's
//!   `IRET` intercept) is NMI-window exiting, which fires once the CPU's
//!   virtual-NMI blocking ends (one instruction after the `IRET`: the service
//!   lets the block end at the next exit, as SVM does after the `IRET`).
//! * **No decode assist**: VMX records no instruction bytes, so the entry reads
//!   them from guest memory right after the exit ([`record_insn`], through the
//!   EPT) into the image's decode-assist words, for the one exit that needs
//!   them (a device access faulting in the EPT). The service itself reads guest
//!   memory only in a one-vCPU VM, because another vCPU can rewrite the bytes
//!   between the fault and the decode; the same window exists here, inside the
//!   interrupts-off section, and it can only make the emulation act on the
//!   faulting address the EPT reported (the access size and register come from
//!   the bytes, the address does not).
//!
//! QEMU's TCG has no VMX, so the instruction layer ([`super::vmx_hw`]) is not
//! exercised by the host tests. Everything pure here (field encodings,
//! control resolution, the image translation, exit decode, the MSR bitmap,
//! the loop over a scripted CPU) is host-tested against numbers from the SDM.

use super::ept;
use super::exit::{self, Exit};
use super::inject::{EXITINTINFO_VALID, RFLAGS_IF};
use super::mmio::{self, Mode, OFF_INSN_BYTES, OFF_INSN_LEN};
use super::msr;
use super::probe::SvmCaps;
use super::svm::{code, ctl, efer, icpt, off, GuestRegs, Vmcb};
use super::vcpu::{Claim, VcpuMem, PAGE};

// ── VMCS field encodings (SDM vol. 3, appendix B) ───────────────────────

/// VMCS field encodings. Bits 14:13 are the width (0 = 16, 1 = 64, 2 = 32,
/// 3 = natural), bits 11:10 the type (0 control, 1 read-only data, 2 guest
/// state, 3 host state); a host test checks every constant against that rule.
pub mod field {
    pub const VPID: u32 = 0x0000;

    pub const GUEST_ES_SEL: u32 = 0x0800;
    pub const GUEST_CS_SEL: u32 = 0x0802;
    pub const GUEST_SS_SEL: u32 = 0x0804;
    pub const GUEST_DS_SEL: u32 = 0x0806;
    pub const GUEST_FS_SEL: u32 = 0x0808;
    pub const GUEST_GS_SEL: u32 = 0x080A;
    pub const GUEST_LDTR_SEL: u32 = 0x080C;
    pub const GUEST_TR_SEL: u32 = 0x080E;

    pub const HOST_ES_SEL: u32 = 0x0C00;
    pub const HOST_CS_SEL: u32 = 0x0C02;
    pub const HOST_SS_SEL: u32 = 0x0C04;
    pub const HOST_DS_SEL: u32 = 0x0C06;
    pub const HOST_FS_SEL: u32 = 0x0C08;
    pub const HOST_GS_SEL: u32 = 0x0C0A;
    pub const HOST_TR_SEL: u32 = 0x0C0C;

    pub const MSR_BITMAP: u32 = 0x2004;
    pub const EXIT_MSR_STORE_ADDR: u32 = 0x2006;
    pub const EXIT_MSR_LOAD_ADDR: u32 = 0x2008;
    pub const ENTRY_MSR_LOAD_ADDR: u32 = 0x200A;
    pub const TSC_OFFSET: u32 = 0x2010;
    pub const EPT_POINTER: u32 = 0x201A;
    pub const GUEST_PHYS_ADDR: u32 = 0x2400;
    pub const VMCS_LINK_POINTER: u32 = 0x2800;
    pub const GUEST_DEBUGCTL: u32 = 0x2802;
    pub const GUEST_PAT: u32 = 0x2804;
    pub const GUEST_EFER: u32 = 0x2806;
    pub const GUEST_PDPTE0: u32 = 0x280A;
    pub const GUEST_PDPTE1: u32 = 0x280C;
    pub const GUEST_PDPTE2: u32 = 0x280E;
    pub const GUEST_PDPTE3: u32 = 0x2810;
    pub const HOST_PAT: u32 = 0x2C00;
    pub const HOST_EFER: u32 = 0x2C02;

    pub const PIN_BASED: u32 = 0x4000;
    pub const PROC_BASED: u32 = 0x4002;
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    pub const PF_ERROR_MASK: u32 = 0x4006;
    pub const PF_ERROR_MATCH: u32 = 0x4008;
    pub const CR3_TARGET_COUNT: u32 = 0x400A;
    pub const EXIT_CTLS: u32 = 0x400C;
    pub const EXIT_MSR_STORE_COUNT: u32 = 0x400E;
    pub const EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
    pub const ENTRY_CTLS: u32 = 0x4012;
    pub const ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
    pub const ENTRY_INT_INFO: u32 = 0x4016;
    pub const ENTRY_ERROR_CODE: u32 = 0x4018;
    pub const ENTRY_INSN_LEN: u32 = 0x401A;
    pub const PROC_BASED2: u32 = 0x401E;

    pub const INSN_ERROR: u32 = 0x4400;
    pub const EXIT_REASON: u32 = 0x4402;
    pub const EXIT_INT_INFO: u32 = 0x4404;
    pub const EXIT_INT_ERROR: u32 = 0x4406;
    pub const IDT_VECTORING_INFO: u32 = 0x4408;
    pub const IDT_VECTORING_ERROR: u32 = 0x440A;
    pub const EXIT_INSN_LEN: u32 = 0x440C;

    pub const GUEST_ES_LIMIT: u32 = 0x4800;
    pub const GUEST_CS_LIMIT: u32 = 0x4802;
    pub const GUEST_SS_LIMIT: u32 = 0x4804;
    pub const GUEST_DS_LIMIT: u32 = 0x4806;
    pub const GUEST_FS_LIMIT: u32 = 0x4808;
    pub const GUEST_GS_LIMIT: u32 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
    pub const GUEST_TR_LIMIT: u32 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;
    pub const GUEST_ES_AR: u32 = 0x4814;
    pub const GUEST_CS_AR: u32 = 0x4816;
    pub const GUEST_SS_AR: u32 = 0x4818;
    pub const GUEST_DS_AR: u32 = 0x481A;
    pub const GUEST_FS_AR: u32 = 0x481C;
    pub const GUEST_GS_AR: u32 = 0x481E;
    pub const GUEST_LDTR_AR: u32 = 0x4820;
    pub const GUEST_TR_AR: u32 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY: u32 = 0x4824;
    pub const GUEST_ACTIVITY: u32 = 0x4826;
    pub const GUEST_SYSENTER_CS: u32 = 0x482A;
    pub const HOST_SYSENTER_CS: u32 = 0x4C00;

    pub const CR0_GUEST_HOST_MASK: u32 = 0x6000;
    pub const CR4_GUEST_HOST_MASK: u32 = 0x6002;
    pub const CR0_READ_SHADOW: u32 = 0x6004;
    pub const CR4_READ_SHADOW: u32 = 0x6006;
    pub const EXIT_QUALIFICATION: u32 = 0x6400;

    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_ES_BASE: u32 = 0x6806;
    pub const GUEST_CS_BASE: u32 = 0x6808;
    pub const GUEST_SS_BASE: u32 = 0x680A;
    pub const GUEST_DS_BASE: u32 = 0x680C;
    pub const GUEST_FS_BASE: u32 = 0x680E;
    pub const GUEST_GS_BASE: u32 = 0x6810;
    pub const GUEST_LDTR_BASE: u32 = 0x6812;
    pub const GUEST_TR_BASE: u32 = 0x6814;
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    pub const GUEST_DR7: u32 = 0x681A;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;
    pub const GUEST_PENDING_DBG: u32 = 0x6822;
    pub const GUEST_SYSENTER_ESP: u32 = 0x6824;
    pub const GUEST_SYSENTER_EIP: u32 = 0x6826;

    pub const HOST_CR0: u32 = 0x6C00;
    pub const HOST_CR3: u32 = 0x6C02;
    pub const HOST_CR4: u32 = 0x6C04;
    pub const HOST_FS_BASE: u32 = 0x6C06;
    pub const HOST_GS_BASE: u32 = 0x6C08;
    pub const HOST_TR_BASE: u32 = 0x6C0A;
    pub const HOST_GDTR_BASE: u32 = 0x6C0C;
    pub const HOST_IDTR_BASE: u32 = 0x6C0E;
    pub const HOST_SYSENTER_ESP: u32 = 0x6C10;
    pub const HOST_SYSENTER_EIP: u32 = 0x6C12;
    pub const HOST_RSP: u32 = 0x6C14;
    pub const HOST_RIP: u32 = 0x6C16;
}

/// Basic exit reasons (`VM_EXIT_REASON[15:0]`).
pub mod reason {
    /// Exception or NMI.
    pub const EXCEPTION_NMI: u32 = 0;
    pub const EXTERNAL_INTERRUPT: u32 = 1;
    pub const TRIPLE_FAULT: u32 = 2;
    pub const INIT_SIGNAL: u32 = 3;
    pub const STARTUP_IPI: u32 = 4;
    pub const INTERRUPT_WINDOW: u32 = 7;
    pub const NMI_WINDOW: u32 = 8;
    pub const CPUID: u32 = 10;
    pub const HLT: u32 = 12;
    pub const INVD: u32 = 13;
    pub const VMCALL: u32 = 18;
    /// `VMCLEAR`, `VMLAUNCH`, `VMPTRLD`, `VMPTRST`, `VMREAD`, `VMRESUME`,
    /// `VMWRITE`, `VMXOFF`, `VMXON`: every one exits unconditionally.
    pub const VMX_INSN_FIRST: u32 = 19;
    pub const VMX_INSN_LAST: u32 = 27;
    pub const CR_ACCESS: u32 = 28;
    pub const IO_INSTRUCTION: u32 = 30;
    pub const RDMSR: u32 = 31;
    pub const WRMSR: u32 = 32;
    pub const INVALID_GUEST_STATE: u32 = 33;
    pub const MSR_LOAD_FAILURE: u32 = 34;
    pub const MWAIT: u32 = 36;
    pub const MONITOR: u32 = 39;
    pub const MACHINE_CHECK_ENTRY: u32 = 41;
    pub const EPT_VIOLATION: u32 = 48;
    pub const EPT_MISCONFIG: u32 = 49;
    pub const WBINVD: u32 = 54;
    pub const XSETBV: u32 = 55;
    /// `VM_EXIT_REASON` bit 31: the entry failed (the guest state or the MSR list).
    pub const ENTRY_FAILURE: u32 = 1 << 31;
}

/// Control bits (SDM vol. 3, 24.6 - 24.8).
pub mod bits {
    /// Pin-based: external interrupts exit.
    pub const PIN_EXTERNAL_INTERRUPT: u32 = 1 << 0;
    /// Pin-based: NMIs exit.
    pub const PIN_NMI: u32 = 1 << 3;
    /// Pin-based: virtual NMIs (NMI blocking is tracked for the guest).
    pub const PIN_VIRTUAL_NMI: u32 = 1 << 5;

    /// Primary: exit when the guest can take an interrupt.
    pub const PROC_INTERRUPT_WINDOW: u32 = 1 << 2;
    /// Primary: the TSC offset applies to `RDTSC`.
    pub const PROC_TSC_OFFSET: u32 = 1 << 3;
    pub const PROC_HLT: u32 = 1 << 7;
    pub const PROC_MWAIT: u32 = 1 << 10;
    /// Primary: `MOV CR8` from the guest exits.
    pub const PROC_CR8_LOAD: u32 = 1 << 19;
    /// Primary: `MOV CR8` to the guest exits.
    pub const PROC_CR8_STORE: u32 = 1 << 20;
    /// Primary: exit when NMI blocking is off.
    pub const PROC_NMI_WINDOW: u32 = 1 << 22;
    /// Primary: every I/O instruction exits.
    pub const PROC_UNCOND_IO: u32 = 1 << 24;
    pub const PROC_MSR_BITMAPS: u32 = 1 << 28;
    pub const PROC_MONITOR: u32 = 1 << 29;
    pub const PROC_SECONDARY: u32 = 1 << 31;

    /// Secondary: EPT.
    pub const PROC2_EPT: u32 = 1 << 1;
    pub const PROC2_VPID: u32 = 1 << 5;
    pub const PROC2_WBINVD: u32 = 1 << 6;
    /// Secondary: the guest may run with paging off and in real mode.
    pub const PROC2_UNRESTRICTED_GUEST: u32 = 1 << 7;
    pub const PROC2_INVPCID: u32 = 1 << 12;

    /// Exit: save the debug controls (`DR7`, `IA32_DEBUGCTL`).
    pub const EXIT_SAVE_DEBUG: u32 = 1 << 2;
    /// Exit: the host runs in 64-bit mode.
    pub const EXIT_HOST_64: u32 = 1 << 9;
    pub const EXIT_SAVE_PAT: u32 = 1 << 18;
    pub const EXIT_LOAD_PAT: u32 = 1 << 19;
    pub const EXIT_SAVE_EFER: u32 = 1 << 20;
    pub const EXIT_LOAD_EFER: u32 = 1 << 21;

    /// Entry: load the debug controls.
    pub const ENTRY_LOAD_DEBUG: u32 = 1 << 2;
    /// Entry: the guest is in IA-32e mode (`EFER.LMA`).
    pub const ENTRY_IA32E: u32 = 1 << 9;
    pub const ENTRY_LOAD_PAT: u32 = 1 << 14;
    pub const ENTRY_LOAD_EFER: u32 = 1 << 15;
}

/// The capability MSRs (SDM vol. 4, appendix A).
pub mod cap_msr {
    pub const BASIC: u32 = 0x480;
    pub const PIN: u32 = 0x481;
    pub const PROC: u32 = 0x482;
    pub const EXIT: u32 = 0x483;
    pub const ENTRY: u32 = 0x484;
    pub const CR0_FIXED0: u32 = 0x486;
    pub const CR0_FIXED1: u32 = 0x487;
    pub const CR4_FIXED0: u32 = 0x488;
    pub const CR4_FIXED1: u32 = 0x489;
    pub const PROC2: u32 = 0x48B;
    pub const EPT_VPID: u32 = 0x48C;
    pub const TRUE_PIN: u32 = 0x48D;
    pub const TRUE_PROC: u32 = 0x48E;
    pub const TRUE_EXIT: u32 = 0x48F;
    pub const TRUE_ENTRY: u32 = 0x490;
}

const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;

// ── the capability MSRs, and the controls they allow ────────────────────

/// The capability MSRs, as read.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Caps {
    pub basic: u64,
    pub pin: u64,
    pub proc: u64,
    pub proc2: u64,
    pub exit: u64,
    pub entry: u64,
    pub ept_vpid: u64,
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
}

impl Caps {
    /// Read them through `rd` (`RDMSR`). The `TRUE_*` control MSRs are the
    /// ones consulted when `IA32_VMX_BASIC[55]` says they exist; the legacy
    /// ones would force the CR3 and CR8 exits on, which the backend refuses
    /// ([`Missing::TrueControls`]). The secondary and EPT/VPID MSRs are read
    /// only when the bits that announce them are set.
    pub fn read(mut rd: impl FnMut(u32) -> u64) -> Caps {
        let basic = rd(cap_msr::BASIC);
        let t = basic & (1 << 55) != 0;
        let proc = rd(if t { cap_msr::TRUE_PROC } else { cap_msr::PROC });
        let proc2 = if proc >> 32 & bits::PROC_SECONDARY as u64 != 0 { rd(cap_msr::PROC2) } else { 0 };
        let ept_vpid = if proc2 >> 32 & (bits::PROC2_EPT | bits::PROC2_VPID) as u64 != 0 { rd(cap_msr::EPT_VPID) } else { 0 };
        Caps {
            basic,
            pin: rd(if t { cap_msr::TRUE_PIN } else { cap_msr::PIN }),
            proc,
            proc2,
            exit: rd(if t { cap_msr::TRUE_EXIT } else { cap_msr::EXIT }),
            entry: rd(if t { cap_msr::TRUE_ENTRY } else { cap_msr::ENTRY }),
            ept_vpid,
            cr0_fixed0: rd(cap_msr::CR0_FIXED0),
            cr0_fixed1: rd(cap_msr::CR0_FIXED1),
            cr4_fixed0: rd(cap_msr::CR4_FIXED0),
            cr4_fixed1: rd(cap_msr::CR4_FIXED1),
        }
    }
}

/// What this CPU lacks that the backend needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Missing {
    /// `IA32_VMX_BASIC[55]`: no `TRUE_*` control MSRs.
    TrueControls,
    /// Pin-based controls (the bits).
    Pin(u32),
    /// Primary processor-based controls.
    Proc(u32),
    /// Secondary processor-based controls.
    Proc2(u32),
    /// VM-exit controls.
    Exit(u32),
    /// VM-entry controls.
    Entry(u32),
    /// `EPT_VPID_CAP`: a 4-level write-back walk.
    Ept,
    /// `EPT_VPID_CAP`: `INVEPT`.
    Invept,
}

/// The controls and the fixed-bit masks the entries use, resolved once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Controls {
    /// VMCS revision identifier (`IA32_VMX_BASIC[30:0]`): first word of the
    /// VMXON region and of every VMCS.
    pub revision: u32,
    pub pin: u32,
    /// Without the dynamic bits (interrupt window, NMI window).
    pub proc: u32,
    pub proc2: u32,
    pub exit: u32,
    /// Without the dynamic bit (IA-32e guest).
    pub entry: u32,
    /// VPIDs tag the guest's translations (the VM's id).
    pub vpid: bool,
    /// `INVVPID` single-context exists (otherwise all-context is used).
    pub invvpid_single: bool,
    /// `INVEPT` single-context exists (otherwise all-context is used).
    pub invept_single: bool,
    /// The EPTP asks for accessed/dirty flags (never: the monitor does not read them).
    pub ept_ad: bool,
    /// `CR0` bits VMX forces on that a guest may not clear (`NE`).
    pub cr0_forced: u64,
    pub cr0_fixed1: u64,
    /// `CR4` bits VMX forces on (`VMXE`): hidden from the guest.
    pub cr4_forced: u64,
    pub cr4_fixed1: u64,
}

/// `(want | optional-that-exists | allowed-0)`, or the wanted bits the CPU
/// cannot set (SDM vol. 3, 31.5.1): bits 31:0 of the MSR are the ones that
/// must be 1, bits 63:32 the ones that may be.
const fn adjust(msr: u64, want: u32, optional: u32) -> Result<u32, u32> {
    let (must, may) = (msr as u32, (msr >> 32) as u32);
    if want & !may != 0 {
        return Err(want & !may);
    }
    Ok(want | (optional & may) | must)
}

impl Controls {
    /// The controls the guest entry runs with, or what is missing.
    pub fn resolve(c: &Caps) -> Result<Controls, Missing> {
        use bits::*;
        if c.basic & (1 << 55) == 0 {
            return Err(Missing::TrueControls);
        }
        let pin = adjust(c.pin, PIN_EXTERNAL_INTERRUPT | PIN_NMI | PIN_VIRTUAL_NMI, 0).map_err(Missing::Pin)?;
        let proc = adjust(
            c.proc,
            PROC_HLT | PROC_MWAIT | PROC_MONITOR | PROC_TSC_OFFSET | PROC_CR8_LOAD | PROC_CR8_STORE | PROC_UNCOND_IO
                | PROC_MSR_BITMAPS | PROC_SECONDARY,
            0,
        )
        .map_err(Missing::Proc)?;
        let proc2 = adjust(
            c.proc2,
            PROC2_EPT | PROC2_UNRESTRICTED_GUEST | PROC2_WBINVD,
            PROC2_VPID | PROC2_INVPCID,
        )
        .map_err(Missing::Proc2)?;
        let exit = adjust(
            c.exit,
            EXIT_HOST_64 | EXIT_SAVE_DEBUG | EXIT_SAVE_PAT | EXIT_LOAD_PAT | EXIT_SAVE_EFER | EXIT_LOAD_EFER,
            0,
        )
        .map_err(Missing::Exit)?;
        let entry = adjust(c.entry, ENTRY_LOAD_DEBUG | ENTRY_LOAD_PAT | ENTRY_LOAD_EFER, 0).map_err(Missing::Entry)?;
        // The walk we build, and a way to invalidate it.
        if c.ept_vpid & (1 << 6) == 0 || c.ept_vpid & (1 << 14) == 0 {
            return Err(Missing::Ept);
        }
        if c.ept_vpid & (1 << 20) == 0 || c.ept_vpid & (1 << 25 | 1 << 26) == 0 {
            return Err(Missing::Invept);
        }
        // VPIDs need INVVPID (single- or all-context) to be flushed.
        let vpid = proc2 & PROC2_VPID != 0 && c.ept_vpid & (1 << 32) != 0 && c.ept_vpid & (1 << 41 | 1 << 42) != 0;
        let proc2 = if vpid { proc2 } else { proc2 & !PROC2_VPID };
        Ok(Controls {
            revision: (c.basic & 0x7FFF_FFFF) as u32,
            pin,
            proc,
            proc2,
            exit,
            entry,
            vpid,
            invvpid_single: c.ept_vpid & (1 << 41) != 0,
            invept_single: c.ept_vpid & (1 << 25) != 0,
            ept_ad: false,
            // Unrestricted guest lifts PE and PG; what is left forced is the guest's to keep set.
            cr0_forced: c.cr0_fixed0 & !(CR0_PE | CR0_PG),
            cr0_fixed1: c.cr0_fixed1,
            cr4_forced: c.cr4_fixed0,
            cr4_fixed1: c.cr4_fixed1,
        })
    }
}

// ── the CPU as the entry sees it ────────────────────────────────────────

/// `VMREAD` / `VMWRITE` of the current VMCS.
pub trait VmcsIo {
    fn read(&mut self, field: u32) -> u64;
    fn write(&mut self, field: u32, value: u64);
}

/// The guest general registers VMX does not hold: RAX too (the VMCB image
/// keeps RAX; here the stub swaps it with the rest). The order is the run
/// stub's offsets (`rax` 0, `rbx` 8, ..., `r15` 120).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct VmxRegs {
    pub rax: u64,
    pub g: GuestRegs,
}

/// The host state the VM exit restores. The CPU's own at the moment of the
/// entry: a vCPU moves between CPUs, and the per-CPU bases differ.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HostState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub tr: u16,
    pub fs_base: u64,
    pub gs_base: u64,
    pub tr_base: u64,
    pub gdtr_base: u64,
    pub idtr_base: u64,
    pub sysenter_cs: u32,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub pat: u64,
    pub efer: u64,
    /// Where the exit lands (the stub's label).
    pub rip: u64,
}

/// The instructions an entry needs, on this CPU, in VMX operation, with
/// interrupts off. [`super::vmx_hw`] is the real one; a script in the host
/// tests plays the CPU.
pub trait VmxCpu: VmcsIo {
    fn host_state(&mut self) -> HostState;
    fn rdmsr(&mut self, msr: u32) -> u64;
    fn cr2(&mut self) -> u64;
    fn set_cr2(&mut self, v: u64);
    /// `VMCLEAR`: the VMCS is flushed to memory, inactive, launch state clear.
    fn vmclear(&mut self, pa: u64) -> bool;
    /// `VMPTRLD`: make it the current VMCS.
    fn vmptrld(&mut self, pa: u64) -> bool;
    /// `INVEPT` of the tree `eptp` names (`single`), or of all trees.
    fn invept(&mut self, single: bool, eptp: u64);
    /// `INVVPID` of one VPID's translations (`single`), or of all of them.
    fn invvpid(&mut self, single: bool, vpid: u16);
    /// `VMLAUNCH` (`launched` false) or `VMRESUME`, with the guest registers
    /// in and out. `false`: the instruction itself failed (`INSN_ERROR`).
    fn enter(&mut self, regs: &mut VmxRegs, launched: bool) -> bool;
    /// Right after an exit: the host's `GDTR`/`IDTR` limits (the exit sets
    /// them to 0xFFFF), the segments the exit loads.
    fn after_exit(&mut self);
    /// The exit was a physical NMI (taken by the exit, not delivered): run
    /// the host's handler.
    fn take_nmi(&mut self);
    /// Did a `VMREAD`/`VMWRITE` since the last call fail?
    fn io_failed(&mut self) -> bool;
}

// ── the MSR bitmap and the MSR lists ────────────────────────────────────

/// The MSR bitmap: one page, four 1 KiB regions (read low, read high, write
/// low, write high), one bit per MSR; a set bit exits.
pub const MSR_BITMAP_BYTES: usize = PAGE;

const fn bitmap_bit(msr: u32, write: bool) -> Option<(usize, u32)> {
    let (base, first) = match msr {
        0..=0x1FFF => (0, 0),
        0xC000_0000..=0xC000_1FFF => (1024, 0xC000_0000),
        _ => return None,
    };
    let n = (msr - first) as usize;
    Some((base + if write { 2048 } else { 0 } + n / 8, (n % 8) as u32))
}

/// Allow the guest to read and/or write `msr` without an exit.
fn allow(bm: &mut [u8; MSR_BITMAP_BYTES], msr: u32, rd: bool, wr: bool) {
    if rd {
        if let Some((b, bit)) = bitmap_bit(msr, false) {
            bm[b] &= !(1 << bit);
        }
    }
    if wr {
        if let Some((b, bit)) = bitmap_bit(msr, true) {
            bm[b] &= !(1 << bit);
        }
    }
}

/// Fill `bm` with the guest's MSR bitmap: the twin of [`msr::build_msrpm`]
/// (everything exits, [`msr::PASSTHROUGH`] open both ways, the TSC open for
/// reads). Every passthrough MSR is in the VMCS or in the lists below.
pub fn build_msr_bitmap(bm: &mut [u8; MSR_BITMAP_BYTES]) {
    bm.fill(0xFF);
    for m in msr::PASSTHROUGH {
        allow(bm, m, true, true);
    }
    allow(bm, msr::MSR_TSC, true, false);
}

/// Is the read or write of `msr` intercepted by `bm`?
pub fn msr_intercepted(bm: &[u8; MSR_BITMAP_BYTES], msr: u32, write: bool) -> bool {
    match bitmap_bit(msr, write) {
        Some((b, bit)) => bm[b] >> bit & 1 != 0,
        None => true,
    }
}

/// An entry of an entry/exit MSR list (SDM vol. 3, 24.7.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct MsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub value: u64,
}

/// The passthrough MSRs the VMCS has no field for: the CPU swaps them
/// through the lists, and the image keeps them at these offsets.
pub const LISTED: [(u32, usize); 5] = [
    (msr::MSR_STAR, off::STAR),
    (msr::MSR_LSTAR, off::LSTAR),
    (msr::MSR_CSTAR, off::CSTAR),
    (msr::MSR_SFMASK, off::SFMASK),
    (msr::MSR_KERNEL_GS_BASE, off::KERNEL_GS_BASE),
];

/// What an entry keeps besides the VMCS and the VMCB image: one page, 4 KiB
/// aligned, the second of the two extra pages of a VMX vCPU.
#[repr(C, align(4096))]
pub struct Extra {
    /// The guest's values: loaded at entry, stored back at exit (the same list).
    pub guest: [MsrEntry; LISTED.len()],
    /// The host's values: loaded at exit.
    pub host: [MsrEntry; LISTED.len()],
    /// The PAE guest's four page-directory-pointer entries: the CPU loads
    /// them when the guest sets `CR3` and keeps them in the VMCS, which does
    /// not outlive an entry.
    pub pdpte: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<Extra>() == PAGE);
const _: () = assert!(core::mem::offset_of!(Extra, host) % 16 == 0);

/// Pages a VMX vCPU needs beyond a SVM one: the VMCS, then [`Extra`].
pub const EXTRA_PAGES: usize = 2;

/// Physical addresses an entry names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Site {
    pub vmcs_pa: u64,
    pub extra_pa: u64,
    pub msr_bitmap_pa: u64,
}

// ── guest state: image <-> VMCS ─────────────────────────────────────────

/// A segment register: the image offset and its four VMCS fields.
struct Seg {
    img: usize,
    sel: u32,
    limit: u32,
    ar: u32,
    base: u32,
}

const SEGS: [Seg; 8] = [
    Seg { img: off::ES, sel: field::GUEST_ES_SEL, limit: field::GUEST_ES_LIMIT, ar: field::GUEST_ES_AR, base: field::GUEST_ES_BASE },
    Seg { img: off::CS, sel: field::GUEST_CS_SEL, limit: field::GUEST_CS_LIMIT, ar: field::GUEST_CS_AR, base: field::GUEST_CS_BASE },
    Seg { img: off::SS, sel: field::GUEST_SS_SEL, limit: field::GUEST_SS_LIMIT, ar: field::GUEST_SS_AR, base: field::GUEST_SS_BASE },
    Seg { img: off::DS, sel: field::GUEST_DS_SEL, limit: field::GUEST_DS_LIMIT, ar: field::GUEST_DS_AR, base: field::GUEST_DS_BASE },
    Seg { img: off::FS, sel: field::GUEST_FS_SEL, limit: field::GUEST_FS_LIMIT, ar: field::GUEST_FS_AR, base: field::GUEST_FS_BASE },
    Seg { img: off::GS, sel: field::GUEST_GS_SEL, limit: field::GUEST_GS_LIMIT, ar: field::GUEST_GS_AR, base: field::GUEST_GS_BASE },
    Seg { img: off::LDTR, sel: field::GUEST_LDTR_SEL, limit: field::GUEST_LDTR_LIMIT, ar: field::GUEST_LDTR_AR, base: field::GUEST_LDTR_BASE },
    Seg { img: off::TR, sel: field::GUEST_TR_SEL, limit: field::GUEST_TR_LIMIT, ar: field::GUEST_TR_AR, base: field::GUEST_TR_BASE },
];

/// "Segment unusable" in a VMX access-rights word.
pub const AR_UNUSABLE: u32 = 1 << 16;

/// A VMCB segment attribute word (type, S, DPL, P in 7:0; AVL, L, D/B, G in
/// 11:8) as VMX access rights (the flags nibble sits in 15:12). `usable`
/// false sets the unusable bit.
pub const fn ar_from_attrib(attrib: u16, usable: bool) -> u32 {
    (attrib as u32 & 0xFF) | (attrib as u32 & 0xF00) << 4 | if usable { 0 } else { AR_UNUSABLE }
}

/// The reverse: an unusable segment is attribute 0 (not present).
pub const fn attrib_from_ar(ar: u32) -> u16 {
    if ar & AR_UNUSABLE != 0 { 0 } else { ((ar & 0xFF) | (ar >> 4 & 0xF00)) as u16 }
}

/// Is the segment at image offset `img` usable as the image has it? Data
/// segments and the LDT are unusable when not present (the null selector in
/// a mode that does not need one); the LDT also when its selector is 0; CS
/// and TR are always usable.
fn usable(img: usize, selector: u16, attrib: u16) -> bool {
    match img {
        off::CS | off::TR => true,
        off::LDTR => selector != 0 && attrib & 0x80 != 0,
        _ => attrib & 0x80 != 0,
    }
}

/// The VMX interruptibility word the image's `INT_STATE` stands for. The
/// image keeps the VMX word with bit 0 raised for "any shadow" (what
/// [`Vmcb::in_shadow`] reads): bit 0 only is `STI` blocking, bits 1 and 0
/// together `MOV SS` blocking, bit 3 NMI blocking (virtual NMIs). A reset
/// (`init_real_mode`) zeroes it all, which is the state a start must have.
fn interruptibility_of(state: u32, rflags: u64, injecting_nmi: bool) -> u32 {
    let movss = state & 2;
    let sti = if state & 1 != 0 && movss == 0 && rflags & RFLAGS_IF != 0 { 1 } else { 0 };
    // The service decides an NMI may go in; the CPU's view must agree, or the
    // entry fails its consistency check.
    let nmi = if injecting_nmi { 0 } else { state & 8 };
    sti | movss | nmi | (state & 4)
}

/// The image's `INT_STATE` for a VMX interruptibility word.
fn state_of(interruptibility: u32) -> u32 {
    let w = interruptibility & 0xF;
    if w & 3 != 0 { w | 1 } else { w }
}

/// `CR8` is the low four bits of the vLAPIC's task priority, kept in the
/// image's `INT_CTL[7:0]` (SVM's `V_TPR`).
const TPR_MASK: u32 = 0xFF;

const EVENT_TYPE_SHIFT: u32 = 8;
const EVENT_TYPE_MASK: u32 = 7 << EVENT_TYPE_SHIFT;
const EVENT_TYPE_SOFT_INTR: u32 = 4 << EVENT_TYPE_SHIFT;
const EVENT_TYPE_SOFT_EXC: u32 = 6 << EVENT_TYPE_SHIFT;
const EVENT_TYPE_NMI: u32 = 2 << EVENT_TYPE_SHIFT;
/// Bits of an interruption-information word that SVM's `EVENT_INJ` shares:
/// vector 7:0, type 10:8, error code valid 11, valid 31.
const EVENT_SHARED: u32 = 0xFFF | 1 << 31;

/// Write the VMCS from the image, the resolved controls and the host state.
/// Every field is written, every time: the VMCS was `VMCLEAR`ed.
pub fn load<I: VmcsIo + ?Sized>(io: &mut I, k: &Controls, site: &Site, host: &HostState, img: &Vmcb, x: &Extra) {
    use field::*;
    fn w<I: VmcsIo + ?Sized>(io: &mut I, f: u32, v: u64) {
        io.write(f, v);
    }

    // The guest's long-mode state decides one entry control.
    let efer_img = img.rd64(off::EFER);
    let ia32e = efer_img & efer::LMA != 0;
    let mut proc = k.proc;
    if img.window_requested() {
        proc |= bits::PROC_INTERRUPT_WINDOW;
    }
    if img.rd32(off::INTERCEPT_W3) & icpt::IRET != 0 {
        proc |= bits::PROC_NMI_WINDOW;
    }
    w(io, PIN_BASED, k.pin as u64);
    w(io, PROC_BASED, proc as u64);
    w(io, PROC_BASED2, k.proc2 as u64);
    w(io, EXIT_CTLS, k.exit as u64);
    w(io, ENTRY_CTLS, (k.entry | if ia32e { bits::ENTRY_IA32E } else { 0 }) as u64);
    w(io, EXCEPTION_BITMAP, 0);
    w(io, PF_ERROR_MASK, 0);
    w(io, PF_ERROR_MATCH, 0);
    w(io, CR3_TARGET_COUNT, 0);
    w(io, MSR_BITMAP, site.msr_bitmap_pa);
    w(io, VMCS_LINK_POINTER, u64::MAX);
    w(io, TSC_OFFSET, img.rd64(off::TSC_OFFSET));
    w(io, EPT_POINTER, ept::eptp(img.rd64(off::NESTED_CR3), k.ept_ad));
    if k.vpid {
        w(io, VPID, img.rd32(off::GUEST_ASID) as u16 as u64);
    }

    // The MSR lists: guest values in and out through one list, the host's out.
    let (g, h) = (site.extra_pa + core::mem::offset_of!(Extra, guest) as u64, site.extra_pa + core::mem::offset_of!(Extra, host) as u64);
    w(io, ENTRY_MSR_LOAD_ADDR, g);
    w(io, ENTRY_MSR_LOAD_COUNT, LISTED.len() as u64);
    w(io, EXIT_MSR_STORE_ADDR, g);
    w(io, EXIT_MSR_STORE_COUNT, LISTED.len() as u64);
    w(io, EXIT_MSR_LOAD_ADDR, h);
    w(io, EXIT_MSR_LOAD_COUNT, LISTED.len() as u64);

    // Guest state.
    for s in &SEGS {
        let (sel, attrib, limit, base) = img.segment(s.img);
        w(io, s.sel, sel as u64);
        w(io, s.limit, limit as u64);
        w(io, s.ar, ar_from_attrib(attrib, usable(s.img, sel, attrib)) as u64);
        w(io, s.base, base);
    }
    let (_, _, gl, gb) = img.segment(off::GDTR);
    w(io, GUEST_GDTR_LIMIT, gl as u64);
    w(io, GUEST_GDTR_BASE, gb);
    let (_, _, il, ib) = img.segment(off::IDTR);
    w(io, GUEST_IDTR_LIMIT, il as u64);
    w(io, GUEST_IDTR_BASE, ib);

    let cr0 = img.rd64(off::CR0);
    let cr4 = img.rd64(off::CR4);
    let (real0, real4) = ((cr0 | k.cr0_forced) & k.cr0_fixed1, (cr4 | k.cr4_forced) & k.cr4_fixed1);
    w(io, GUEST_CR0, real0);
    w(io, GUEST_CR3, img.rd64(off::CR3));
    w(io, GUEST_CR4, real4);
    w(io, CR0_GUEST_HOST_MASK, k.cr0_forced);
    w(io, CR4_GUEST_HOST_MASK, k.cr4_forced);
    // The guest reads the forced CR0 bits as they are (a write that clears one
    // is the exit); the forced CR4 bits (VMXE) read as the guest set them.
    w(io, CR0_READ_SHADOW, real0 & k.cr0_forced);
    w(io, CR4_READ_SHADOW, cr4 & k.cr4_forced);
    w(io, GUEST_DR7, img.rd64(off::DR7));
    w(io, GUEST_RSP, img.rd64(off::RSP));
    w(io, GUEST_RIP, img.rd64(off::RIP));
    w(io, GUEST_RFLAGS, img.rd64(off::RFLAGS));
    w(io, GUEST_SYSENTER_CS, img.rd64(off::SYSENTER_CS) & 0xFFFF_FFFF);
    w(io, GUEST_SYSENTER_ESP, img.rd64(off::SYSENTER_ESP));
    w(io, GUEST_SYSENTER_EIP, img.rd64(off::SYSENTER_EIP));
    w(io, GUEST_PAT, img.rd64(off::G_PAT));
    // `SVME` is the image's (the service keeps it set); VMX reserves the bit.
    w(io, GUEST_EFER, efer_img & !efer::SVME);
    w(io, GUEST_DEBUGCTL, 0);
    w(io, GUEST_ACTIVITY, 0);
    w(io, GUEST_PENDING_DBG, 0);
    let ev = img.rd32(off::EVENT_INJ);
    let injecting = ev & ctl::EVENT_VALID != 0;
    w(
        io,
        GUEST_INTERRUPTIBILITY,
        interruptibility_of(img.rd32(off::INT_STATE), img.rd64(off::RFLAGS), injecting && ev & EVENT_TYPE_MASK == EVENT_TYPE_NMI) as u64,
    );
    let pae_paging = cr0 & CR0_PG != 0 && cr4 & CR4_PAE != 0 && !ia32e;
    if pae_paging {
        for (f, v) in [GUEST_PDPTE0, GUEST_PDPTE1, GUEST_PDPTE2, GUEST_PDPTE3].into_iter().zip(x.pdpte) {
            w(io, f, v);
        }
    }

    // The event to inject: same layout; a software event takes its length.
    if injecting {
        let t = ev & EVENT_TYPE_MASK;
        w(io, ENTRY_INT_INFO, (ev & EVENT_SHARED) as u64);
        w(io, ENTRY_ERROR_CODE, img.rd32(off::EVENT_INJ_ERR) as u64);
        let soft = (EVENT_TYPE_SOFT_INTR..=EVENT_TYPE_SOFT_EXC).contains(&t);
        w(io, ENTRY_INSN_LEN, if soft { img.rd32(off::EVENT_INJ_ERR) as u64 } else { 0 });
    } else {
        w(io, ENTRY_INT_INFO, 0);
        w(io, ENTRY_ERROR_CODE, 0);
        w(io, ENTRY_INSN_LEN, 0);
    }

    // Host state.
    w(io, HOST_CR0, host.cr0);
    w(io, HOST_CR3, host.cr3);
    w(io, HOST_CR4, host.cr4);
    w(io, HOST_CS_SEL, host.cs as u64);
    w(io, HOST_SS_SEL, host.ss as u64);
    w(io, HOST_DS_SEL, host.ds as u64);
    w(io, HOST_ES_SEL, host.es as u64);
    w(io, HOST_FS_SEL, host.fs as u64);
    w(io, HOST_GS_SEL, host.gs as u64);
    w(io, HOST_TR_SEL, host.tr as u64);
    w(io, HOST_FS_BASE, host.fs_base);
    w(io, HOST_GS_BASE, host.gs_base);
    w(io, HOST_TR_BASE, host.tr_base);
    w(io, HOST_GDTR_BASE, host.gdtr_base);
    w(io, HOST_IDTR_BASE, host.idtr_base);
    w(io, HOST_SYSENTER_CS, host.sysenter_cs as u64);
    w(io, HOST_SYSENTER_ESP, host.sysenter_esp);
    w(io, HOST_SYSENTER_EIP, host.sysenter_eip);
    w(io, HOST_PAT, host.pat);
    w(io, HOST_EFER, host.efer);
    w(io, HOST_RIP, host.rip);
}

/// The raw words an exit leaves in the VMCS, for [`to_svm`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RawExit {
    /// `VM_EXIT_REASON` as read (bit 31: the entry failed).
    pub reason: u32,
    pub qualification: u64,
    pub gpa: u64,
    /// `VM_EXIT_INTERRUPTION_INFORMATION`.
    pub intr_info: u32,
    pub rip: u64,
    pub insn_len: u32,
}

/// Exit codes for reasons SVM has no code for: far from every SVM code, so
/// the service's table never mistakes one (it ends the vCPU).
pub const OTHER_BASE: u64 = 0x10_0000;

/// The SVM `(EXITCODE, EXITINFO1, EXITINFO2)` a VMX exit stands for.
pub fn to_svm(e: &RawExit) -> (u64, u64, u64) {
    let q = e.qualification;
    if e.reason & reason::ENTRY_FAILURE != 0 {
        return (code::INVALID, q, 0);
    }
    match e.reason {
        reason::EXCEPTION_NMI if e.intr_info & ctl::EVENT_VALID != 0 && e.intr_info & EVENT_TYPE_MASK == EVENT_TYPE_NMI => {
            (code::NMI, 0, 0)
        }
        reason::EXTERNAL_INTERRUPT => (code::INTR, 0, 0),
        reason::TRIPLE_FAULT => (code::SHUTDOWN, 0, 0),
        reason::INIT_SIGNAL | reason::STARTUP_IPI => (code::INIT, 0, 0),
        reason::INTERRUPT_WINDOW => (code::VINTR, 0, 0),
        // The end of NMI blocking: the SVM service's "the handler's IRET".
        reason::NMI_WINDOW => (code::IRET, 0, 0),
        reason::CPUID => (code::CPUID, 0, 0),
        reason::HLT => (code::HLT, 0, 0),
        reason::INVD => (code::INVD, 0, 0),
        reason::VMCALL => (code::VMMCALL, 0, 0),
        // The guest executed a VMX instruction: it is a CPU without VMX (`#UD`,
        // the service's answer to SVM's `VMRUN`).
        r if (reason::VMX_INSN_FIRST..=reason::VMX_INSN_LAST).contains(&r) => (code::VMRUN, 0, 0),
        reason::IO_INSTRUCTION => {
            // Size 1 / 2 / 4 bytes in bits 2:0 as 0 / 1 / 3; direction 3 (1 = IN);
            // string 4; rep 5; port 31:16. SVM: IN in bit 0, string 2, rep 3,
            // the size as a one-hot at 4 / 5 / 6, the port at 31:16.
            let size = match q & 7 {
                0 => 1 << 4,
                1 => 1 << 5,
                _ => 1 << 6,
            };
            let info1 = (q >> 3 & 1) | (q >> 4 & 1) << 2 | (q >> 5 & 1) << 3 | size | (q >> 16 & 0xFFFF) << 16;
            (code::IOIO, info1, e.rip.wrapping_add(e.insn_len as u64))
        }
        reason::RDMSR => (code::MSR, 0, 0),
        reason::WRMSR => (code::MSR, 1, 0),
        reason::MWAIT => (code::MWAIT, 0, 0),
        reason::MONITOR => (code::MONITOR, 0, 0),
        reason::WBINVD => (code::WBINVD, 0, 0),
        reason::XSETBV => (code::XSETBV, 0, 0),
        reason::INVALID_GUEST_STATE | reason::MSR_LOAD_FAILURE | reason::MACHINE_CHECK_ENTRY => (code::INVALID, q, 0),
        reason::EPT_VIOLATION => {
            // Qualification: bit 1 write, bit 2 instruction fetch, bits 5:3
            // the entry's own read/write/execute (any: the page is mapped),
            // bit 7 the guest linear address is valid, bit 8 the access was to
            // the final address and not to a paging structure. SVM: P bit 0,
            // W bit 1, ID bit 4, "final translation" bit 32.
            let present = (q >> 3 & 7 != 0) as u64;
            let final_translation = (q >> 7 & 1 != 0 && q >> 8 & 1 != 0) as u64;
            (code::NPF, present | (q >> 1 & 1) << 1 | (q >> 2 & 1) << 4 | final_translation << 32, e.gpa)
        }
        other => (OTHER_BASE + other as u64, q, 0),
    }
}

/// Decode a VMX exit to what the service switches on.
pub fn decode(e: &RawExit) -> Exit {
    let (c, i1, i2) = to_svm(e);
    exit::svm(c, i1, i2)
}

/// Read the guest state and the exit back into the image. `entered` is false
/// when the entry failed (the exit information then says why, and the guest
/// state is not reliable: it is left as it was).
pub fn store<I: VmcsIo + ?Sized>(io: &mut I, img: &mut Vmcb, regs: &VmxRegs, k: &Controls, x: &mut Extra) {
    use field::*;
    let r = RawExit {
        reason: io.read(EXIT_REASON) as u32,
        qualification: io.read(EXIT_QUALIFICATION),
        gpa: io.read(GUEST_PHYS_ADDR),
        intr_info: io.read(EXIT_INT_INFO) as u32,
        rip: io.read(GUEST_RIP),
        insn_len: io.read(EXIT_INSN_LEN) as u32,
    };
    let (c, i1, i2) = to_svm(&r);
    img.wr64(off::EXIT_CODE, c);
    img.wr64(off::EXIT_INFO_1, i1);
    img.wr64(off::EXIT_INFO_2, i2);
    if r.reason & reason::ENTRY_FAILURE != 0 {
        // The event stays queued; nothing ran.
        return;
    }
    // The event went in with this entry (the CPU clears the valid bit).
    img.wr32(off::EVENT_INJ, img.rd32(off::EVENT_INJ) & !ctl::EVENT_VALID);

    for s in &SEGS {
        let sel = io.read(s.sel) as u16;
        let attrib = attrib_from_ar(io.read(s.ar) as u32);
        img.set_segment(s.img, sel, attrib, io.read(s.limit) as u32, io.read(s.base));
    }
    img.set_segment(off::GDTR, 0, 0, io.read(GUEST_GDTR_LIMIT) as u32, io.read(GUEST_GDTR_BASE));
    img.set_segment(off::IDTR, 0, 0, io.read(GUEST_IDTR_LIMIT) as u32, io.read(GUEST_IDTR_BASE));
    let ss_ar = io.read(GUEST_SS_AR) as u32;
    img.wr8(off::CPL, (ss_ar >> 5 & 3) as u8);

    let real0 = io.read(GUEST_CR0);
    let real4 = io.read(GUEST_CR4);
    img.wr64(off::CR0, real0);
    img.wr64(off::CR3, io.read(GUEST_CR3));
    // The guest sees VMXE as it wrote it (never set), the rest as it is.
    img.wr64(off::CR4, real4 & !k.cr4_forced | io.read(CR4_READ_SHADOW) & k.cr4_forced);
    img.wr64(off::DR7, io.read(GUEST_DR7));
    img.wr64(off::RSP, io.read(GUEST_RSP));
    img.wr64(off::RIP, r.rip);
    img.wr64(off::RFLAGS, io.read(GUEST_RFLAGS));
    img.wr64(off::RAX, regs.rax);
    img.wr64(off::SYSENTER_CS, io.read(GUEST_SYSENTER_CS));
    img.wr64(off::SYSENTER_ESP, io.read(GUEST_SYSENTER_ESP));
    img.wr64(off::SYSENTER_EIP, io.read(GUEST_SYSENTER_EIP));
    img.wr64(off::G_PAT, io.read(GUEST_PAT));
    let efer_now = io.read(GUEST_EFER);
    img.wr64(off::EFER, efer_now | efer::SVME);
    img.wr32(off::INT_STATE, state_of(io.read(GUEST_INTERRUPTIBILITY) as u32));
    // The CPU stored the guest's listed MSRs at the exit.
    for (i, (_, o)) in LISTED.into_iter().enumerate() {
        // SAFETY: `i` is in range; the CPU wrote the entry at the exit.
        let e = unsafe { core::ptr::read_volatile(&x.guest[i]) };
        img.wr64(o, e.value);
    }
    img.wr64(off::NEXT_RIP, r.rip.wrapping_add(r.insn_len as u64));
    if real0 & CR0_PG != 0 && real4 & CR4_PAE != 0 && efer_now & efer::LMA == 0 {
        for (slot, f) in x.pdpte.iter_mut().zip([GUEST_PDPTE0, GUEST_PDPTE1, GUEST_PDPTE2, GUEST_PDPTE3]) {
            *slot = io.read(f);
        }
    }

    // An event the exit interrupted while it was being delivered: the same
    // layout as SVM's `EXITINTINFO`. A software event has no error code, and
    // needs the instruction's length to be delivered again: it rides in the
    // error-code word.
    let idt = io.read(IDT_VECTORING_INFO) as u32;
    if idt & EXITINTINFO_VALID != 0 {
        let t = idt & EVENT_TYPE_MASK;
        let err = if (EVENT_TYPE_SOFT_INTR..=EVENT_TYPE_SOFT_EXC).contains(&t) {
            r.insn_len
        } else {
            io.read(IDT_VECTORING_ERROR) as u32
        };
        img.wr32(off::EXIT_INT_INFO, idt & EVENT_SHARED);
        img.wr32(off::EXIT_INT_INFO_ERR, err);
    } else {
        img.wr32(off::EXIT_INT_INFO, 0);
        img.wr32(off::EXIT_INT_INFO_ERR, 0);
    }
}

/// The general register `n` in the `MOV CR` encoding (0 = RAX, 1 = RCX, 2 =
/// RDX, 3 = RBX, 5 = RBP, 6 = RSI, 7 = RDI, 8..15). RSP (4) lives in the VMCS.
fn gpr(regs: &mut VmxRegs, n: u32) -> Option<&mut u64> {
    let g = &mut regs.g;
    Some(match n {
        0 => &mut regs.rax,
        1 => &mut g.rcx,
        2 => &mut g.rdx,
        3 => &mut g.rbx,
        5 => &mut g.rbp,
        6 => &mut g.rsi,
        7 => &mut g.rdi,
        8 => &mut g.r8,
        9 => &mut g.r9,
        10 => &mut g.r10,
        11 => &mut g.r11,
        12 => &mut g.r12,
        13 => &mut g.r13,
        14 => &mut g.r14,
        15 => &mut g.r15,
        _ => return None,
    })
}

/// Most `CR8` accesses emulated without leaving the entry before it hands
/// the exit to the loop above (a guest that does nothing else must still let
/// the thread see a stop request; a physical interrupt ends the entry anyway).
const MAX_INLINE: u32 = 64;

/// `MOV` to or from `CR8` (qualification: control register 3:0, access type
/// 5:4 where 0 is `MOV to CR` and 1 `MOV from CR`, register 11:8) against
/// the image's virtual TPR. `false`: not an access this emulates.
fn emulate_cr8<I: VmcsIo + ?Sized>(io: &mut I, img: &mut Vmcb, regs: &mut VmxRegs) -> bool {
    let q = io.read(field::EXIT_QUALIFICATION);
    let (cr, ty, reg) = ((q & 0xF) as u32, (q >> 4 & 3) as u32, (q >> 8 & 0xF) as u32);
    if cr != 8 || ty > 1 {
        return false;
    }
    let tpr = img.rd32(off::INT_CTL);
    if ty == 0 {
        let v = if reg == 4 { io.read(field::GUEST_RSP) } else { gpr(regs, reg).map_or(0, |r| *r) };
        img.wr32(off::INT_CTL, tpr & !TPR_MASK | (v as u32 & 0xF));
    } else if reg == 4 {
        io.write(field::GUEST_RSP, (tpr & 0xF) as u64);
    } else if let Some(r) = gpr(regs, reg) {
        *r = (tpr & 0xF) as u64;
    }
    let rip = io.read(field::GUEST_RIP).wrapping_add(io.read(field::EXIT_INSN_LEN));
    io.write(field::GUEST_RIP, rip);
    true
}

/// Fill the image's decode-assist words for the exit in it: the bytes of the
/// instruction that touched a device register (a read or write of an
/// unmapped guest-physical address by a data access), read from guest memory
/// through `mem`. Anything else leaves the length 0, as a CPU with decode
/// assists leaves it for a fault it recorded nothing for. The conditions are
/// the ones [`super::serve`] applies before it decodes.
fn record_insn(img: &mut Vmcb, mem: &dyn mmio::GuestMem) {
    img.wr8(OFF_INSN_LEN, 0);
    let (c, i1) = (img.rd64(off::EXIT_CODE), img.rd64(off::EXIT_INFO_1));
    let present = i1 & 1 != 0;
    let fetch = i1 & 1 << 4 != 0;
    let final_translation = i1 & 1 << 32 != 0;
    if c != code::NPF || present || fetch || !final_translation {
        return;
    }
    let Some(mode) = Mode::of(img) else { return };
    let Some((bytes, n)) = mmio::fetch(img, mem, mode, true) else { return };
    for (k, b) in bytes[..n].iter().enumerate() {
        img.wr8(OFF_INSN_BYTES + k, *b);
    }
    img.wr8(OFF_INSN_LEN, n as u8);
}

/// Make the entry fail the way the service already understands.
fn failed(img: &mut Vmcb, why: u64) {
    img.wr64(off::EXIT_CODE, code::INVALID);
    img.wr64(off::EXIT_INFO_1, why);
    img.wr64(off::EXIT_INFO_2, 0);
}

/// One guest entry of the vCPU `v`, from the image to the image: everything
/// [`super::vcpu::Machine::vmrun`] does on VMX after "interrupts off, in VMX
/// operation, thread on `cpu`". `claim` is published for exactly the time the
/// guest can run, as for SVM. A refusal by the hardware is an `INVALID` exit
/// in the image (`EXITINFO1` = the VMCS instruction error, or 0xFFFF_0000 + a
/// code of ours when a VMCS access failed), which the service reports as
/// `Exit::InvalidState`. `read_phys` reads host-physical memory (the EPT
/// tree's words, the guest's instruction bytes: [`record_insn`]).
pub fn run(
    c: &mut dyn VmxCpu,
    k: &Controls,
    site: &Site,
    v: &mut VcpuMem,
    x: &mut Extra,
    claim: &Claim,
    cpu: usize,
    read_phys: ept::ReadPhys<'_>,
) {
    claim.enter(v, cpu);
    let VcpuMem { vmcb: img, run, .. } = v;
    let flush = img.rd8(off::TLB_CTL) != 0;

    // The CPU reads and writes the two lists behind the compiler's back, around
    // an opaque call: volatile, so the stores are not sunk past it and the
    // loads after it are not forwarded from them.
    for (i, (m, o)) in LISTED.into_iter().enumerate() {
        // SAFETY: `i` is in range; a plain store to memory this entry owns.
        unsafe { core::ptr::write_volatile(&mut x.guest[i], MsrEntry { index: m, reserved: 0, value: img.rd64(o) }) };
        let host_value = c.rdmsr(m);
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(&mut x.host[i], MsrEntry { index: m, reserved: 0, value: host_value }) };
    }
    let host = c.host_state();
    let host_cr2 = c.cr2();
    c.set_cr2(img.rd64(off::CR2));
    let mut regs = VmxRegs { rax: img.rd64(off::RAX), g: run.regs };

    let mut outcome = Outcome::Refused(REFUSED_SETUP);
    if c.vmclear(site.vmcs_pa) && c.vmptrld(site.vmcs_pa) {
        load(c, k, site, &host, img, x);
        if !c.io_failed() {
            if flush {
                c.invept(k.invept_single, ept::eptp(img.rd64(off::NESTED_CR3), k.ept_ad));
                if k.vpid {
                    c.invvpid(k.invvpid_single, img.rd32(off::GUEST_ASID) as u16);
                }
            }
            outcome = enter_loop(c, img, &mut regs);
        }
    }
    claim.leave(cpu);

    img.wr64(off::CR2, c.cr2());
    c.set_cr2(host_cr2);
    match outcome {
        Outcome::Refused(why) => failed(img, why),
        Outcome::Exited { yielded } => {
            run.regs = regs.g;
            store(c, img, &regs, k, x);
            if c.io_failed() {
                failed(img, REFUSED_READ);
            } else {
                record_insn(img, &ept::GuestRam { root: img.rd64(off::NESTED_CR3), read_phys });
                if yielded {
                    // Many `CR8` accesses in a row: hand the hart back as if a
                    // physical interrupt had ended the entry.
                    img.wr64(off::EXIT_CODE, code::INTR);
                    img.wr64(off::EXIT_INFO_1, 0);
                    img.wr64(off::EXIT_INFO_2, 0);
                }
            }
        }
    }
    // Inactive on this CPU: the thread may be on another one next time.
    c.vmclear(site.vmcs_pa);
}

/// `EXITINFO1` of an `INVALID` exit that is ours: the VMCS could not be made current or written.
pub const REFUSED_SETUP: u64 = 0xFFFF_0000;
/// ... or could not be read back after the exit.
pub const REFUSED_READ: u64 = 0xFFFF_0001;

enum Outcome {
    /// An exit to report. `yielded`: the cap on inline exits was reached.
    Exited { yielded: bool },
    /// The hardware refused the entry (`EXITINFO1` = why).
    Refused(u64),
}

/// `VMLAUNCH`, then `VMRESUME` while the exit is one this module serves
/// itself (a `CR8` access). The exits of a physical NMI are handed to the host.
fn enter_loop(c: &mut dyn VmxCpu, img: &mut Vmcb, regs: &mut VmxRegs) -> Outcome {
    let mut launched = false;
    for n in 0..MAX_INLINE {
        if !c.enter(regs, launched) {
            return Outcome::Refused(c.read(field::INSN_ERROR));
        }
        launched = true;
        c.after_exit();
        let r = c.read(field::EXIT_REASON) as u32;
        if r == reason::EXCEPTION_NMI {
            let info = c.read(field::EXIT_INT_INFO) as u32;
            if info & ctl::EVENT_VALID != 0 && info & EVENT_TYPE_MASK == EVENT_TYPE_NMI {
                c.take_nmi();
            }
        }
        if r == reason::CR_ACCESS && emulate_cr8(c, img, regs) {
            if n + 1 == MAX_INLINE {
                return Outcome::Exited { yielded: true };
            }
            continue;
        }
        return Outcome::Exited { yielded: false };
    }
    Outcome::Exited { yielded: true }
}

/// The synthetic [`SvmCaps`] the shared entry sees: VPIDs for ASIDs (16
/// bits), the next instruction's address on every instruction exit, flush by
/// VPID.
pub const fn svm_caps() -> SvmCaps {
    SvmCaps {
        revision: 0,
        nasid: 1 << 16,
        npt: true,
        svm_lock: false,
        nrips: true,
        vmcb_clean: false,
        flush_by_asid: true,
        decode_assists: false,
        pause_filter: false,
        vgif: false,
    }
}

/// `TSS` descriptor base from its two descriptor words (the 16-byte system
/// descriptor): base 15:0 at bits 31:16, 23:16 at 39:32, 31:24 at 63:56 of
/// the low word, 63:32 in the low half of the high word.
pub const fn tss_base(lo: u64, hi: u64) -> u64 {
    (lo >> 16 & 0xFF_FFFF) | (lo >> 56 & 0xFF) << 24 | (hi & 0xFFFF_FFFF) << 32
}
