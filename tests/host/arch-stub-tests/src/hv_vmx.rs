// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Intel half of the x86_64 hypervisor primitives
//! (`arch/x86_64/src/ext/hv/{vmx,ept}.rs`), checked on the host.
//!
//! QEMU's TCG has no VMX and there is no Intel machine in the lab yet, so
//! nothing here can be proven by running a guest. What is proven instead is
//! everything that does not need the instructions, against numbers from the
//! Intel SDM (vol. 3 appendices B and C, chapters 24-27 and 29; vol. 4
//! appendix A), not from the code under test: a VMCS field encoding that is
//! wrong by one is a `VMfail` or a silently different field on hardware, an
//! EPT entry in the x86 PTE format is an EPT misconfiguration, a control bit
//! that is wrong is an exit the service never sees.
//!
//! The last module runs the real guest entry (`vcpu::enter`) over a scripted
//! CPU (`Cpu`: each `VMLAUNCH` plays the next step of the guest and leaves the
//! exit the hardware would) and the real translation between the VMCB image
//! and the VMCS.

use azos_arch::hv::vmx::{self, field, reason, VmcsIo};
use std::collections::HashMap;

/// A VMCS: fields by encoding, 0 until written.
#[derive(Default, Clone)]
struct Vmcs {
    f: HashMap<u32, u64>,
    writes: Vec<u32>,
}

impl VmcsIo for Vmcs {
    fn read(&mut self, field: u32) -> u64 {
        *self.f.get(&field).unwrap_or(&0)
    }
    fn write(&mut self, field: u32, value: u64) {
        self.writes.push(field);
        self.f.insert(field, value);
    }
}

impl Vmcs {
    fn get(&self, field: u32) -> u64 {
        *self.f.get(&field).unwrap_or(&0)
    }
}

mod encodings {
    use super::*;

    // Width (bits 14:13) and type (bits 11:10) of a field, SDM vol. 3 B.
    const W16: u32 = 0;
    const W64: u32 = 1;
    const W32: u32 = 2;
    const WNAT: u32 = 3;
    const CTL: u32 = 0;
    const RO: u32 = 1;
    const GUEST: u32 = 2;
    const HOST: u32 = 3;

    #[test]
    fn every_field_has_the_width_and_type_the_sdm_gives_it() {
        use field::*;
        let t: &[(&str, u32, u32, u32)] = &[
            ("VPID", VPID, W16, CTL),
            ("GUEST_ES_SEL", GUEST_ES_SEL, W16, GUEST),
            ("GUEST_CS_SEL", GUEST_CS_SEL, W16, GUEST),
            ("GUEST_SS_SEL", GUEST_SS_SEL, W16, GUEST),
            ("GUEST_DS_SEL", GUEST_DS_SEL, W16, GUEST),
            ("GUEST_FS_SEL", GUEST_FS_SEL, W16, GUEST),
            ("GUEST_GS_SEL", GUEST_GS_SEL, W16, GUEST),
            ("GUEST_LDTR_SEL", GUEST_LDTR_SEL, W16, GUEST),
            ("GUEST_TR_SEL", GUEST_TR_SEL, W16, GUEST),
            ("HOST_ES_SEL", HOST_ES_SEL, W16, HOST),
            ("HOST_CS_SEL", HOST_CS_SEL, W16, HOST),
            ("HOST_SS_SEL", HOST_SS_SEL, W16, HOST),
            ("HOST_DS_SEL", HOST_DS_SEL, W16, HOST),
            ("HOST_FS_SEL", HOST_FS_SEL, W16, HOST),
            ("HOST_GS_SEL", HOST_GS_SEL, W16, HOST),
            ("HOST_TR_SEL", HOST_TR_SEL, W16, HOST),
            ("MSR_BITMAP", MSR_BITMAP, W64, CTL),
            ("EXIT_MSR_STORE_ADDR", EXIT_MSR_STORE_ADDR, W64, CTL),
            ("EXIT_MSR_LOAD_ADDR", EXIT_MSR_LOAD_ADDR, W64, CTL),
            ("ENTRY_MSR_LOAD_ADDR", ENTRY_MSR_LOAD_ADDR, W64, CTL),
            ("TSC_OFFSET", TSC_OFFSET, W64, CTL),
            ("EPT_POINTER", EPT_POINTER, W64, CTL),
            ("GUEST_PHYS_ADDR", GUEST_PHYS_ADDR, W64, RO),
            ("VMCS_LINK_POINTER", VMCS_LINK_POINTER, W64, GUEST),
            ("GUEST_DEBUGCTL", GUEST_DEBUGCTL, W64, GUEST),
            ("GUEST_PAT", GUEST_PAT, W64, GUEST),
            ("GUEST_EFER", GUEST_EFER, W64, GUEST),
            ("GUEST_PDPTE0", GUEST_PDPTE0, W64, GUEST),
            ("GUEST_PDPTE1", GUEST_PDPTE1, W64, GUEST),
            ("GUEST_PDPTE2", GUEST_PDPTE2, W64, GUEST),
            ("GUEST_PDPTE3", GUEST_PDPTE3, W64, GUEST),
            ("HOST_PAT", HOST_PAT, W64, HOST),
            ("HOST_EFER", HOST_EFER, W64, HOST),
            ("PIN_BASED", PIN_BASED, W32, CTL),
            ("PROC_BASED", PROC_BASED, W32, CTL),
            ("EXCEPTION_BITMAP", EXCEPTION_BITMAP, W32, CTL),
            ("PF_ERROR_MASK", PF_ERROR_MASK, W32, CTL),
            ("PF_ERROR_MATCH", PF_ERROR_MATCH, W32, CTL),
            ("CR3_TARGET_COUNT", CR3_TARGET_COUNT, W32, CTL),
            ("EXIT_CTLS", EXIT_CTLS, W32, CTL),
            ("EXIT_MSR_STORE_COUNT", EXIT_MSR_STORE_COUNT, W32, CTL),
            ("EXIT_MSR_LOAD_COUNT", EXIT_MSR_LOAD_COUNT, W32, CTL),
            ("ENTRY_CTLS", ENTRY_CTLS, W32, CTL),
            ("ENTRY_MSR_LOAD_COUNT", ENTRY_MSR_LOAD_COUNT, W32, CTL),
            ("ENTRY_INT_INFO", ENTRY_INT_INFO, W32, CTL),
            ("ENTRY_ERROR_CODE", ENTRY_ERROR_CODE, W32, CTL),
            ("ENTRY_INSN_LEN", ENTRY_INSN_LEN, W32, CTL),
            ("PROC_BASED2", PROC_BASED2, W32, CTL),
            ("INSN_ERROR", INSN_ERROR, W32, RO),
            ("EXIT_REASON", EXIT_REASON, W32, RO),
            ("EXIT_INT_INFO", EXIT_INT_INFO, W32, RO),
            ("EXIT_INT_ERROR", EXIT_INT_ERROR, W32, RO),
            ("IDT_VECTORING_INFO", IDT_VECTORING_INFO, W32, RO),
            ("IDT_VECTORING_ERROR", IDT_VECTORING_ERROR, W32, RO),
            ("EXIT_INSN_LEN", EXIT_INSN_LEN, W32, RO),
            ("GUEST_ES_LIMIT", GUEST_ES_LIMIT, W32, GUEST),
            ("GUEST_CS_LIMIT", GUEST_CS_LIMIT, W32, GUEST),
            ("GUEST_SS_LIMIT", GUEST_SS_LIMIT, W32, GUEST),
            ("GUEST_DS_LIMIT", GUEST_DS_LIMIT, W32, GUEST),
            ("GUEST_FS_LIMIT", GUEST_FS_LIMIT, W32, GUEST),
            ("GUEST_GS_LIMIT", GUEST_GS_LIMIT, W32, GUEST),
            ("GUEST_LDTR_LIMIT", GUEST_LDTR_LIMIT, W32, GUEST),
            ("GUEST_TR_LIMIT", GUEST_TR_LIMIT, W32, GUEST),
            ("GUEST_GDTR_LIMIT", GUEST_GDTR_LIMIT, W32, GUEST),
            ("GUEST_IDTR_LIMIT", GUEST_IDTR_LIMIT, W32, GUEST),
            ("GUEST_ES_AR", GUEST_ES_AR, W32, GUEST),
            ("GUEST_CS_AR", GUEST_CS_AR, W32, GUEST),
            ("GUEST_SS_AR", GUEST_SS_AR, W32, GUEST),
            ("GUEST_DS_AR", GUEST_DS_AR, W32, GUEST),
            ("GUEST_FS_AR", GUEST_FS_AR, W32, GUEST),
            ("GUEST_GS_AR", GUEST_GS_AR, W32, GUEST),
            ("GUEST_LDTR_AR", GUEST_LDTR_AR, W32, GUEST),
            ("GUEST_TR_AR", GUEST_TR_AR, W32, GUEST),
            ("GUEST_INTERRUPTIBILITY", GUEST_INTERRUPTIBILITY, W32, GUEST),
            ("GUEST_ACTIVITY", GUEST_ACTIVITY, W32, GUEST),
            ("GUEST_SYSENTER_CS", GUEST_SYSENTER_CS, W32, GUEST),
            ("HOST_SYSENTER_CS", HOST_SYSENTER_CS, W32, HOST),
            ("CR0_GUEST_HOST_MASK", CR0_GUEST_HOST_MASK, WNAT, CTL),
            ("CR4_GUEST_HOST_MASK", CR4_GUEST_HOST_MASK, WNAT, CTL),
            ("CR0_READ_SHADOW", CR0_READ_SHADOW, WNAT, CTL),
            ("CR4_READ_SHADOW", CR4_READ_SHADOW, WNAT, CTL),
            ("EXIT_QUALIFICATION", EXIT_QUALIFICATION, WNAT, RO),
            ("GUEST_CR0", GUEST_CR0, WNAT, GUEST),
            ("GUEST_CR3", GUEST_CR3, WNAT, GUEST),
            ("GUEST_CR4", GUEST_CR4, WNAT, GUEST),
            ("GUEST_ES_BASE", GUEST_ES_BASE, WNAT, GUEST),
            ("GUEST_CS_BASE", GUEST_CS_BASE, WNAT, GUEST),
            ("GUEST_SS_BASE", GUEST_SS_BASE, WNAT, GUEST),
            ("GUEST_DS_BASE", GUEST_DS_BASE, WNAT, GUEST),
            ("GUEST_FS_BASE", GUEST_FS_BASE, WNAT, GUEST),
            ("GUEST_GS_BASE", GUEST_GS_BASE, WNAT, GUEST),
            ("GUEST_LDTR_BASE", GUEST_LDTR_BASE, WNAT, GUEST),
            ("GUEST_TR_BASE", GUEST_TR_BASE, WNAT, GUEST),
            ("GUEST_GDTR_BASE", GUEST_GDTR_BASE, WNAT, GUEST),
            ("GUEST_IDTR_BASE", GUEST_IDTR_BASE, WNAT, GUEST),
            ("GUEST_DR7", GUEST_DR7, WNAT, GUEST),
            ("GUEST_RSP", GUEST_RSP, WNAT, GUEST),
            ("GUEST_RIP", GUEST_RIP, WNAT, GUEST),
            ("GUEST_RFLAGS", GUEST_RFLAGS, WNAT, GUEST),
            ("GUEST_PENDING_DBG", GUEST_PENDING_DBG, WNAT, GUEST),
            ("GUEST_SYSENTER_ESP", GUEST_SYSENTER_ESP, WNAT, GUEST),
            ("GUEST_SYSENTER_EIP", GUEST_SYSENTER_EIP, WNAT, GUEST),
            ("HOST_CR0", HOST_CR0, WNAT, HOST),
            ("HOST_CR3", HOST_CR3, WNAT, HOST),
            ("HOST_CR4", HOST_CR4, WNAT, HOST),
            ("HOST_FS_BASE", HOST_FS_BASE, WNAT, HOST),
            ("HOST_GS_BASE", HOST_GS_BASE, WNAT, HOST),
            ("HOST_TR_BASE", HOST_TR_BASE, WNAT, HOST),
            ("HOST_GDTR_BASE", HOST_GDTR_BASE, WNAT, HOST),
            ("HOST_IDTR_BASE", HOST_IDTR_BASE, WNAT, HOST),
            ("HOST_SYSENTER_ESP", HOST_SYSENTER_ESP, WNAT, HOST),
            ("HOST_SYSENTER_EIP", HOST_SYSENTER_EIP, WNAT, HOST),
            ("HOST_RSP", HOST_RSP, WNAT, HOST),
            ("HOST_RIP", HOST_RIP, WNAT, HOST),
        ];
        let mut seen = std::collections::HashSet::new();
        for (name, enc, w, ty) in t {
            assert_eq!(enc >> 13 & 3, *w, "{name}: width bits of {enc:#x}");
            assert_eq!(enc >> 10 & 3, *ty, "{name}: type bits of {enc:#x}");
            assert_eq!(enc & 0xF000_0000, 0, "{name}: reserved bits");
            assert_eq!(enc & 1, 0, "{name}: access type bit (full)");
            assert!(seen.insert(*enc), "{name}: two fields share {enc:#x}");
        }
    }

    #[test]
    fn well_known_fields_have_their_published_encodings() {
        // Linux arch/x86/include/asm/vmx.h, the numbers KVM runs on.
        let t: &[(u32, u32)] = &[
            (field::GUEST_RIP, 0x681E),
            (field::GUEST_RSP, 0x681C),
            (field::GUEST_RFLAGS, 0x6820),
            (field::GUEST_CR0, 0x6800),
            (field::GUEST_CS_SEL, 0x0802),
            (field::GUEST_CS_AR, 0x4816),
            (field::GUEST_TR_AR, 0x4822),
            (field::GUEST_INTERRUPTIBILITY, 0x4824),
            (field::EPT_POINTER, 0x201A),
            (field::EXIT_REASON, 0x4402),
            (field::EXIT_QUALIFICATION, 0x6400),
            (field::GUEST_PHYS_ADDR, 0x2400),
            (field::PIN_BASED, 0x4000),
            (field::PROC_BASED, 0x4002),
            (field::PROC_BASED2, 0x401E),
            (field::EXIT_CTLS, 0x400C),
            (field::ENTRY_CTLS, 0x4012),
            (field::ENTRY_INT_INFO, 0x4016),
            (field::IDT_VECTORING_INFO, 0x4408),
            (field::TSC_OFFSET, 0x2010),
            (field::MSR_BITMAP, 0x2004),
            (field::HOST_RIP, 0x6C16),
            (field::HOST_RSP, 0x6C14),
            (field::HOST_CR3, 0x6C02),
            (field::VMCS_LINK_POINTER, 0x2800),
            (field::INSN_ERROR, 0x4400),
        ];
        for (got, want) in t {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn the_eight_segments_are_spaced_by_two_in_every_family() {
        use field::*;
        let sel = [GUEST_ES_SEL, GUEST_CS_SEL, GUEST_SS_SEL, GUEST_DS_SEL, GUEST_FS_SEL, GUEST_GS_SEL, GUEST_LDTR_SEL, GUEST_TR_SEL];
        let lim = [GUEST_ES_LIMIT, GUEST_CS_LIMIT, GUEST_SS_LIMIT, GUEST_DS_LIMIT, GUEST_FS_LIMIT, GUEST_GS_LIMIT, GUEST_LDTR_LIMIT, GUEST_TR_LIMIT];
        let ar = [GUEST_ES_AR, GUEST_CS_AR, GUEST_SS_AR, GUEST_DS_AR, GUEST_FS_AR, GUEST_GS_AR, GUEST_LDTR_AR, GUEST_TR_AR];
        let base = [GUEST_ES_BASE, GUEST_CS_BASE, GUEST_SS_BASE, GUEST_DS_BASE, GUEST_FS_BASE, GUEST_GS_BASE, GUEST_LDTR_BASE, GUEST_TR_BASE];
        for (i, fam) in [sel, lim, ar, base].iter().enumerate() {
            for k in 1..8 {
                assert_eq!(fam[k], fam[0] + 2 * k as u32, "family {i} segment {k}");
            }
        }
        // SDM order: ES, CS, SS, DS, FS, GS, LDTR, TR.
        assert_eq!([sel[0], lim[0], ar[0], base[0]], [0x800, 0x4800, 0x4814, 0x6806]);
    }

    #[test]
    fn exit_reasons_and_control_bits_are_the_sdms() {
        use vmx::bits::*;
        // SDM vol. 3 appendix C.
        let r: &[(u32, u32)] = &[
            (reason::EXCEPTION_NMI, 0),
            (reason::EXTERNAL_INTERRUPT, 1),
            (reason::TRIPLE_FAULT, 2),
            (reason::INIT_SIGNAL, 3),
            (reason::STARTUP_IPI, 4),
            (reason::INTERRUPT_WINDOW, 7),
            (reason::NMI_WINDOW, 8),
            (reason::CPUID, 10),
            (reason::HLT, 12),
            (reason::INVD, 13),
            (reason::VMCALL, 18),
            (reason::VMX_INSN_FIRST, 19),
            (reason::VMX_INSN_LAST, 27),
            (reason::CR_ACCESS, 28),
            (reason::IO_INSTRUCTION, 30),
            (reason::RDMSR, 31),
            (reason::WRMSR, 32),
            (reason::INVALID_GUEST_STATE, 33),
            (reason::MSR_LOAD_FAILURE, 34),
            (reason::MWAIT, 36),
            (reason::MONITOR, 39),
            (reason::MACHINE_CHECK_ENTRY, 41),
            (reason::EPT_VIOLATION, 48),
            (reason::EPT_MISCONFIG, 49),
            (reason::WBINVD, 54),
            (reason::XSETBV, 55),
        ];
        for (got, want) in r {
            assert_eq!(got, want);
        }
        assert_eq!(reason::ENTRY_FAILURE, 1 << 31);
        // Vol. 3 24.6.1 - 24.6.2: bit positions of the controls.
        assert_eq!([PIN_EXTERNAL_INTERRUPT, PIN_NMI, PIN_VIRTUAL_NMI], [1, 1 << 3, 1 << 5]);
        assert_eq!(
            [PROC_INTERRUPT_WINDOW, PROC_TSC_OFFSET, PROC_HLT, PROC_MWAIT, PROC_CR8_LOAD, PROC_CR8_STORE, PROC_NMI_WINDOW],
            [1 << 2, 1 << 3, 1 << 7, 1 << 10, 1 << 19, 1 << 20, 1 << 22]
        );
        assert_eq!([PROC_UNCOND_IO, PROC_MSR_BITMAPS, PROC_MONITOR, PROC_SECONDARY], [1 << 24, 1 << 28, 1 << 29, 1 << 31]);
        assert_eq!([PROC2_EPT, PROC2_VPID, PROC2_WBINVD, PROC2_UNRESTRICTED_GUEST, PROC2_INVPCID], [1 << 1, 1 << 5, 1 << 6, 1 << 7, 1 << 12]);
        assert_eq!([EXIT_SAVE_DEBUG, EXIT_HOST_64, EXIT_SAVE_PAT, EXIT_LOAD_PAT, EXIT_SAVE_EFER, EXIT_LOAD_EFER], [1 << 2, 1 << 9, 1 << 18, 1 << 19, 1 << 20, 1 << 21]);
        assert_eq!([ENTRY_LOAD_DEBUG, ENTRY_IA32E, ENTRY_LOAD_PAT, ENTRY_LOAD_EFER], [1 << 2, 1 << 9, 1 << 14, 1 << 15]);
    }

    #[test]
    fn capability_msr_numbers_are_the_sdms() {
        use vmx::cap_msr::*;
        assert_eq!([BASIC, PIN, PROC, EXIT, ENTRY], [0x480, 0x481, 0x482, 0x483, 0x484]);
        assert_eq!([CR0_FIXED0, CR0_FIXED1, CR4_FIXED0, CR4_FIXED1], [0x486, 0x487, 0x488, 0x489]);
        assert_eq!([PROC2, EPT_VPID, TRUE_PIN, TRUE_PROC, TRUE_EXIT, TRUE_ENTRY], [0x48B, 0x48C, 0x48D, 0x48E, 0x48F, 0x490]);
    }
}

mod controls {
    use super::*;
    use vmx::bits::*;
    use vmx::cap_msr as m;
    use vmx::{Caps, Controls, Missing};

    /// A capability MSR: bits that must be 1 in the low word, that may be 1 in the high.
    const fn cap(must: u32, may: u32) -> u64 {
        (may as u64) << 32 | must as u64
    }

    /// An Intel part with everything the backend wants, the legacy reserved-1
    /// bits in the allowed-0 halves.
    fn sky() -> HashMap<u32, u64> {
        let mut t = HashMap::new();
        t.insert(m::BASIC, 0x00DA_0400_0000_0001 | 1 << 55 | 6 << 50);
        t.insert(m::TRUE_PIN, cap(0x16 & !(1 << 3), 0xFF));
        t.insert(m::TRUE_PROC, cap(0x0401_E172 & !(1 << 15 | 1 << 16), 0xFFF9_FFFE | 1 << 31));
        t.insert(m::PROC2, cap(0, 0x00FF_FFFF));
        t.insert(m::TRUE_EXIT, cap(0x36DFF & !(1 << 2), 0x00FF_FFFF));
        t.insert(m::TRUE_ENTRY, cap(0x11FF & !(1 << 2), 0x0007_FFFF));
        t.insert(m::EPT_VPID, 1 << 6 | 1 << 14 | 1 << 16 | 1 << 17 | 1 << 20 | 1 << 25 | 1 << 26 | 1 << 32 | 1 << 41 | 1 << 42);
        t.insert(m::CR0_FIXED0, 0x8000_0021);
        t.insert(m::CR0_FIXED1, 0xFFFF_FFFF);
        t.insert(m::CR4_FIXED0, 0x2000);
        t.insert(m::CR4_FIXED1, 0x0037_77FF);
        t
    }

    fn caps(t: &HashMap<u32, u64>) -> Caps {
        Caps::read(|msr| *t.get(&msr).unwrap_or_else(|| panic!("unexpected rdmsr {msr:#x}")))
    }

    #[test]
    fn a_capable_cpu_resolves_every_control() {
        let c = caps(&sky());
        let k = Controls::resolve(&c).expect("resolves");
        assert_eq!(k.revision, 1);
        // Wanted bits are in, forced-1 bits are in.
        assert_eq!(k.pin & (PIN_EXTERNAL_INTERRUPT | PIN_NMI | PIN_VIRTUAL_NMI), PIN_EXTERNAL_INTERRUPT | PIN_NMI | PIN_VIRTUAL_NMI);
        assert_eq!(k.pin & 0x16 & !(1 << 3), 0x16 & !(1 << 3), "the allowed-0 bits are forced on");
        for b in [PROC_HLT, PROC_MWAIT, PROC_MONITOR, PROC_TSC_OFFSET, PROC_CR8_LOAD, PROC_CR8_STORE, PROC_UNCOND_IO, PROC_MSR_BITMAPS, PROC_SECONDARY] {
            assert_ne!(k.proc & b, 0, "primary {b:#x}");
        }
        // The dynamic ones are not baked in.
        assert_eq!(k.proc & (PROC_INTERRUPT_WINDOW | PROC_NMI_WINDOW), 0);
        // CR3 exiting is off: the TRUE msr let us clear it.
        assert_eq!(k.proc & (1 << 15 | 1 << 16), 0);
        // I/O bitmaps are not used, unconditional I/O exiting is.
        assert_eq!(k.proc & (1 << 25), 0);
        for b in [PROC2_EPT, PROC2_UNRESTRICTED_GUEST, PROC2_WBINVD, PROC2_VPID, PROC2_INVPCID] {
            assert_ne!(k.proc2 & b, 0, "secondary {b:#x}");
        }
        assert!(k.vpid && k.invept_single && k.invvpid_single && !k.ept_ad);
        for b in [EXIT_HOST_64, EXIT_SAVE_DEBUG, EXIT_SAVE_PAT, EXIT_LOAD_PAT, EXIT_SAVE_EFER, EXIT_LOAD_EFER] {
            assert_ne!(k.exit & b, 0, "exit {b:#x}");
        }
        for b in [ENTRY_LOAD_DEBUG, ENTRY_LOAD_PAT, ENTRY_LOAD_EFER] {
            assert_ne!(k.entry & b, 0, "entry {b:#x}");
        }
        assert_eq!(k.entry & ENTRY_IA32E, 0, "IA-32e is per entry");
        // Unrestricted guest lifts PE and PG; NE stays forced. VMXE is the host's.
        assert_eq!(k.cr0_forced, 1 << 5);
        assert_eq!(k.cr4_forced, 1 << 13);
    }

    #[test]
    fn each_missing_capability_is_named() {
        let miss = |f: &dyn Fn(&mut HashMap<u32, u64>)| {
            let mut t = sky();
            f(&mut t);
            Controls::resolve(&caps(&t)).unwrap_err()
        };
        // No TRUE controls: the legacy MSRs would force CR3 exiting on.
        assert_eq!(miss(&|t| { t.insert(m::BASIC, 1); t.insert(m::PIN, 0xFF << 32); t.insert(m::PROC, 0); t.insert(m::EXIT, 0); t.insert(m::ENTRY, 0); }), Missing::TrueControls);
        // The wanted external-interrupt bit cannot be set.
        assert_eq!(miss(&|t| { t.insert(m::TRUE_PIN, cap(0, 0xFF & !1)); }), Missing::Pin(PIN_EXTERNAL_INTERRUPT));
        // Virtual NMIs and NMI exiting both missing: both reported.
        assert_eq!(miss(&|t| { t.insert(m::TRUE_PIN, cap(0, 1)); }), Missing::Pin(PIN_NMI | PIN_VIRTUAL_NMI));
        assert_eq!(miss(&|t| { t.insert(m::TRUE_PROC, cap(0, 0xFFFF_FFFF & !PROC_HLT)); }), Missing::Proc(PROC_HLT));
        // No secondary controls at all.
        assert!(matches!(miss(&|t| { t.insert(m::TRUE_PROC, cap(0, 0x7FFF_FFFF)); }), Missing::Proc(PROC_SECONDARY)));
        // Unrestricted guest missing.
        assert_eq!(miss(&|t| { t.insert(m::PROC2, cap(0, 0xFF & !PROC2_UNRESTRICTED_GUEST)); }), Missing::Proc2(PROC2_UNRESTRICTED_GUEST));
        assert_eq!(miss(&|t| { t.insert(m::TRUE_EXIT, cap(0, 0x00FF_FFFF & !EXIT_LOAD_EFER)); }), Missing::Exit(EXIT_LOAD_EFER));
        assert_eq!(miss(&|t| { t.insert(m::TRUE_ENTRY, cap(0, 0x0007_FFFF & !ENTRY_LOAD_PAT)); }), Missing::Entry(ENTRY_LOAD_PAT));
        // EPT: the walk or write-back missing; INVEPT missing or without either type.
        assert_eq!(miss(&|t| { t.insert(m::EPT_VPID, 1 << 14 | 1 << 20 | 1 << 25); }), Missing::Ept);
        assert_eq!(miss(&|t| { t.insert(m::EPT_VPID, 1 << 6 | 1 << 14 | 1 << 25); }), Missing::Invept);
        assert_eq!(miss(&|t| { t.insert(m::EPT_VPID, 1 << 6 | 1 << 14 | 1 << 20); }), Missing::Invept);
    }

    #[test]
    fn optional_controls_are_dropped_when_the_cpu_lacks_them() {
        let mut t = sky();
        // No VPID, no INVPCID, INVEPT all-context only.
        t.insert(m::PROC2, cap(0, 0x00FF_FFFF & !(PROC2_VPID | PROC2_INVPCID)));
        t.insert(m::EPT_VPID, 1 << 6 | 1 << 14 | 1 << 20 | 1 << 26);
        let k = Controls::resolve(&caps(&t)).unwrap();
        assert_eq!(k.proc2 & (PROC2_VPID | PROC2_INVPCID), 0);
        assert!(!k.vpid && !k.invept_single);
        // VPID offered but INVVPID is not: unusable, so off.
        let mut t = sky();
        t.insert(m::EPT_VPID, 1 << 6 | 1 << 14 | 1 << 20 | 1 << 25);
        let k = Controls::resolve(&caps(&t)).unwrap();
        assert!(!k.vpid);
        assert_eq!(k.proc2 & PROC2_VPID, 0, "the control follows the flag");
        // A bit the CPU forces on that we did not ask for is on.
        let mut t = sky();
        t.insert(m::PROC2, cap(1 << 3, 0x00FF_FFFF));
        assert_ne!(Controls::resolve(&caps(&t)).unwrap().proc2 & (1 << 3), 0);
    }

    #[test]
    fn secondary_and_ept_msrs_are_read_only_when_announced() {
        // No secondary controls: PROC2 and EPT_VPID are never read.
        let mut reads = vec![];
        let c = Caps::read(|msr| {
            reads.push(msr);
            match msr {
                m::BASIC => 1 << 55,
                m::TRUE_PROC => 0,
                _ => 0,
            }
        });
        assert!(!reads.contains(&m::PROC2) && !reads.contains(&m::EPT_VPID));
        assert_eq!(c.proc2, 0);
        // Legacy MSRs when BASIC[55] is clear.
        let mut reads = vec![];
        Caps::read(|msr| {
            reads.push(msr);
            0
        });
        for legacy in [m::PIN, m::PROC, m::EXIT, m::ENTRY] {
            assert!(reads.contains(&legacy));
        }
        for t in [m::TRUE_PIN, m::TRUE_PROC, m::TRUE_EXIT, m::TRUE_ENTRY] {
            assert!(!reads.contains(&t));
        }
    }
}

mod msr_bitmap {
    use super::*;
    use azos_arch::hv::msr::{self, PASSTHROUGH};
    use azos_arch::hv::svm::MSRPM_BYTES;

    fn vmx_map() -> Box<[u8; vmx::MSR_BITMAP_BYTES]> {
        let mut b = Box::new([0u8; vmx::MSR_BITMAP_BYTES]);
        vmx::build_msr_bitmap(&mut b);
        b
    }

    #[test]
    fn the_layout_is_four_quarter_page_regions() {
        // SDM vol. 3 24.6.9: read-low 0, read-high 1 KiB, write-low 2 KiB, write-high 3 KiB.
        let mut b = Box::new([0xFFu8; vmx::MSR_BITMAP_BYTES]);
        // Open the read of 0x10 (TSC): byte 2, bit 0 of the first region.
        b[2] &= !1;
        assert!(!vmx::msr_intercepted(&b, 0x10, false));
        assert!(vmx::msr_intercepted(&b, 0x10, true));
        let mut b = Box::new([0xFFu8; vmx::MSR_BITMAP_BYTES]);
        // Open the write of 0xC0000082 (LSTAR): write-high region, byte 0x82 / 8, bit 2.
        b[3072 + 0x82 / 8] &= !(1 << (0x82 % 8));
        assert!(!vmx::msr_intercepted(&b, 0xC000_0082, true));
        assert!(vmx::msr_intercepted(&b, 0xC000_0082, false));
        // Outside the two ranges: always an exit.
        assert!(vmx::msr_intercepted(&b, 0x2000, false) && vmx::msr_intercepted(&b, 0xC001_0000, true));
    }

    #[test]
    fn it_agrees_with_the_svm_permission_map_on_every_msr() {
        let v = vmx_map();
        let mut s = Box::new([0u8; MSRPM_BYTES]);
        msr::build_msrpm(&mut s);
        let ranges = [0u32..0x2000, 0xC000_0000..0xC000_2000, 0xC001_0000..0xC001_2000];
        let mut open = 0;
        for r in ranges {
            for m in r {
                for w in [false, true] {
                    // The SVM map covers C001_0000.. and the VMX bitmap does not;
                    // nothing passthrough sits there.
                    let want = msr::intercepted(&s, m, w);
                    let got = vmx::msr_intercepted(&v, m, w);
                    if m < 0xC001_0000 {
                        assert_eq!(got, want, "msr {m:#x} write={w}");
                    } else {
                        assert!(got && want, "msr {m:#x}");
                    }
                    open += !got as u32;
                }
            }
        }
        // 10 passthrough MSRs both ways, plus the TSC read.
        assert_eq!(open, 2 * PASSTHROUGH.len() as u32 + 1);
    }

    #[test]
    fn every_passthrough_msr_has_somewhere_to_live() {
        // In the VMCS (SYSENTER, FS/GS base) or in the entry/exit MSR lists.
        let in_vmcs = [msr::MSR_SYSENTER_CS, msr::MSR_SYSENTER_ESP, msr::MSR_SYSENTER_EIP, msr::MSR_FS_BASE, msr::MSR_GS_BASE];
        for m in PASSTHROUGH {
            let listed = vmx::LISTED.iter().any(|(l, _)| *l == m);
            assert!(listed ^ in_vmcs.contains(&m), "msr {m:#x} must be in exactly one place");
        }
        // And the lists hold nothing that is not passthrough (the guest would never touch it).
        for (l, o) in vmx::LISTED {
            assert!(PASSTHROUGH.contains(&l));
            assert!(o >= azos_arch::hv::svm::off::SAVE);
        }
    }

    #[test]
    fn the_msr_list_entries_are_16_bytes_and_16_aligned() {
        assert_eq!(core::mem::size_of::<vmx::MsrEntry>(), 16);
        assert_eq!(core::mem::size_of::<vmx::Extra>(), 4096);
        assert_eq!(core::mem::align_of::<vmx::Extra>(), 4096);
        assert_eq!(core::mem::offset_of!(vmx::Extra, guest) % 16, 0);
        assert_eq!(core::mem::offset_of!(vmx::Extra, host) % 16, 0);
        assert_eq!(core::mem::offset_of!(vmx::MsrEntry, index), 0);
        assert_eq!(core::mem::offset_of!(vmx::MsrEntry, value), 8);
    }
}

mod exits {
    use super::*;
    use azos_arch::hv::exit::{Exit, IoAccess, NestedFault};

    fn raw(reason: u32, q: u64) -> vmx::RawExit {
        vmx::RawExit { reason, qualification: q, ..Default::default() }
    }

    #[test]
    fn ept_violations_decode_the_gpa_and_the_access() {
        // SDM vol. 3 table 27-7: bit 0 data read, 1 data write, 2 instruction
        // fetch, 3/4/5 the entry was readable/writable/executable, 7 the
        // linear address is valid, 8 the access was to the final address.
        let gpa = 0x1000_1000;
        let v = |q| vmx::RawExit { gpa, ..raw(reason::EPT_VIOLATION, q) };
        // A load from an unmapped page (nothing present): the device-register case.
        assert_eq!(
            vmx::decode(&v(1 | 1 << 7 | 1 << 8)),
            Exit::NestedFault(NestedFault { gpa, write: false, exec: false, present: false, final_translation: true })
        );
        // A store.
        assert_eq!(
            vmx::decode(&v(1 << 1 | 1 << 7 | 1 << 8)),
            Exit::NestedFault(NestedFault { gpa, write: true, exec: false, present: false, final_translation: true })
        );
        // A fetch from a no-execute page: mapped (readable and writable), permission fault.
        assert_eq!(
            vmx::decode(&v(1 << 2 | 1 << 3 | 1 << 4 | 1 << 7 | 1 << 8)),
            Exit::NestedFault(NestedFault { gpa, write: false, exec: true, present: true, final_translation: true })
        );
        // The walk of the guest's own page tables faulted: not the final address.
        assert_eq!(
            vmx::decode(&v(1 << 1 | 1 << 7)),
            Exit::NestedFault(NestedFault { gpa, write: true, exec: false, present: false, final_translation: false })
        );
        // Execute-only entry present: bit 5 alone is "present".
        match vmx::decode(&v(1 | 1 << 5 | 1 << 7 | 1 << 8)) {
            Exit::NestedFault(f) => assert!(f.present),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn io_instructions_decode_port_direction_size_and_the_next_rip() {
        // SDM table 27-5: size-1 in 2:0 (0, 1, 3), direction 3 (1 = IN), string 4, rep 5, port 31:16.
        let e = |q| vmx::RawExit { rip: 0x8000, insn_len: 2, ..raw(reason::IO_INSTRUCTION, q) };
        assert_eq!(vmx::decode(&e(0x3F8 << 16)), Exit::Io(IoAccess { port: 0x3F8, write: true, size: 1, string: false, rep: false, next_rip: 0x8002 }));
        assert_eq!(vmx::decode(&e(1 << 3 | 0x60 << 16)), Exit::Io(IoAccess { port: 0x60, write: false, size: 1, string: false, rep: false, next_rip: 0x8002 }));
        assert_eq!(vmx::decode(&e(1 | 0xCF8 << 16)), Exit::Io(IoAccess { port: 0xCF8, write: true, size: 2, string: false, rep: false, next_rip: 0x8002 }));
        assert_eq!(vmx::decode(&e(3 | 1 << 3 | 0xCFC << 16)), Exit::Io(IoAccess { port: 0xCFC, write: false, size: 4, string: false, rep: false, next_rip: 0x8002 }));
        assert_eq!(
            vmx::decode(&e(3 | 1 << 4 | 1 << 5 | 0x10 << 16)),
            Exit::Io(IoAccess { port: 0x10, write: true, size: 4, string: true, rep: true, next_rip: 0x8002 })
        );
    }

    #[test]
    fn the_instruction_exits_decode() {
        assert_eq!(vmx::decode(&raw(reason::CPUID, 0)), Exit::Cpuid);
        assert_eq!(vmx::decode(&raw(reason::RDMSR, 0)), Exit::Msr { write: false });
        assert_eq!(vmx::decode(&raw(reason::WRMSR, 0)), Exit::Msr { write: true });
        assert_eq!(vmx::decode(&raw(reason::HLT, 0)), Exit::Halt);
        assert_eq!(vmx::decode(&raw(reason::XSETBV, 0)), Exit::Xsetbv);
        assert_eq!(vmx::decode(&raw(reason::VMCALL, 0)), Exit::Hypercall);
        assert_eq!(vmx::decode(&raw(reason::TRIPLE_FAULT, 0)), Exit::Shutdown);
        assert_eq!(vmx::decode(&raw(reason::EXTERNAL_INTERRUPT, 0)), Exit::Interrupt);
        assert_eq!(vmx::decode(&raw(reason::INTERRUPT_WINDOW, 0)), Exit::IntWindow);
    }

    #[test]
    fn an_nmi_is_an_exception_exit_whose_type_is_nmi() {
        // Interruption information: valid 31, type 10:8 (2 = NMI), vector 7:0.
        let nmi = vmx::RawExit { intr_info: 1 << 31 | 2 << 8 | 2, ..raw(reason::EXCEPTION_NMI, 0) };
        assert_eq!(vmx::decode(&nmi), Exit::Nmi);
        // A hardware exception (type 3, #PF): nothing we intercept.
        let pf = vmx::RawExit { intr_info: 1 << 31 | 3 << 8 | 14, ..raw(reason::EXCEPTION_NMI, 0) };
        assert!(matches!(vmx::decode(&pf), Exit::Other(c) if c == vmx::OTHER_BASE));
        // Not valid: not an NMI whatever the type bits say.
        let junk = vmx::RawExit { intr_info: 2 << 8, ..raw(reason::EXCEPTION_NMI, 0) };
        assert!(matches!(vmx::decode(&junk), Exit::Other(_)));
    }

    #[test]
    fn vmx_instructions_in_the_guest_are_the_ud_of_a_cpu_without_vmx() {
        use azos_arch::hv::svm::code;
        for r in reason::VMX_INSN_FIRST..=reason::VMX_INSN_LAST {
            assert_eq!(vmx::to_svm(&raw(r, 0)).0, code::VMRUN, "reason {r}");
        }
        // MONITOR / MWAIT / WBINVD / INVD map to the codes the service already serves.
        assert_eq!(vmx::to_svm(&raw(reason::MONITOR, 0)).0, code::MONITOR);
        assert_eq!(vmx::to_svm(&raw(reason::MWAIT, 0)).0, code::MWAIT);
        assert_eq!(vmx::to_svm(&raw(reason::WBINVD, 0)).0, code::WBINVD);
        assert_eq!(vmx::to_svm(&raw(reason::INVD, 0)).0, code::INVD);
        assert_eq!(vmx::to_svm(&raw(reason::NMI_WINDOW, 0)).0, code::IRET);
    }

    #[test]
    fn a_failed_entry_is_invalid_and_unknown_reasons_cannot_alias_an_svm_code() {
        use azos_arch::hv::svm::code;
        for r in [reason::INVALID_GUEST_STATE, reason::MSR_LOAD_FAILURE, reason::MACHINE_CHECK_ENTRY] {
            assert_eq!(vmx::decode(&raw(r | reason::ENTRY_FAILURE, 7)), Exit::InvalidState);
            assert_eq!(vmx::decode(&raw(r, 7)), Exit::InvalidState);
        }
        // Reason 28 (a CR access nothing serves) and 49 (EPT misconfiguration).
        for r in [reason::CR_ACCESS, reason::EPT_MISCONFIG, 9, 11, 16, 44, 63] {
            let (c, _, _) = vmx::to_svm(&raw(r, 0));
            assert_eq!(c, vmx::OTHER_BASE + r as u64);
            assert!(c > code::NPF, "{c:#x} must be above every SVM code");
            assert!(matches!(vmx::decode(&raw(r, 0)), Exit::Other(x) if x == c));
        }
    }
}

mod state {
    use super::*;
    use azos_arch::hv::entry::{ATTR_CODE32, ATTR_DATA32};
    use azos_arch::hv::svm::{efer, icpt, off, GuestRegs, Vmcb, ATTR_REAL_CODE, ATTR_REAL_DATA, ATTR_TSS_BUSY};
    use vmx::{Controls, Extra, HostState, Site, VmxRegs};

    fn extra() -> Box<Extra> {
        // SAFETY: all-zero is a valid `Extra` (integers only).
        unsafe { Box::new_zeroed().assume_init() }
    }

    fn ctls() -> Controls {
        Controls {
            revision: 1,
            pin: 0x1_0001 | vmx::bits::PIN_EXTERNAL_INTERRUPT | vmx::bits::PIN_NMI | vmx::bits::PIN_VIRTUAL_NMI,
            proc: 0x0400_0000 | vmx::bits::PROC_HLT | vmx::bits::PROC_SECONDARY | vmx::bits::PROC_MSR_BITMAPS,
            proc2: vmx::bits::PROC2_EPT | vmx::bits::PROC2_UNRESTRICTED_GUEST | vmx::bits::PROC2_VPID,
            exit: 0x36DFE,
            entry: 0x11FB,
            vpid: true,
            invvpid_single: true,
            invept_single: true,
            ept_ad: false,
            cr0_forced: 1 << 5,
            cr0_fixed1: 0xFFFF_FFFF,
            cr4_forced: 1 << 13,
            cr4_fixed1: 0x0037_77FF,
        }
    }

    fn site() -> Site {
        Site { vmcs_pa: 0x5000, extra_pa: 0x6000, msr_bitmap_pa: 0x7000 }
    }

    fn host() -> HostState {
        HostState {
            cr0: 0x8005_0033,
            cr3: 0x1234_5000,
            cr4: 0x0000_26A0,
            cs: 0x08,
            ss: 0x10,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            tr: 0x28,
            fs_base: 0x1111,
            gs_base: 0xFFFF_8000_0000_1000,
            tr_base: 0xFFFF_8000_0000_2000,
            gdtr_base: 0xFFFF_8000_0000_3000,
            idtr_base: 0xFFFF_8000_0000_4000,
            sysenter_cs: 8,
            sysenter_esp: 0,
            sysenter_eip: 0,
            pat: 0x0007_0406_0007_0406,
            efer: 0xD01,
            rip: 0xFFFF_8000_dead_0000,
        }
    }

    /// The PVH boot CPU, ready to enter.
    fn pvh() -> Vmcb {
        let mut v = Vmcb::new();
        let mut regs = GuestRegs::default();
        v.init_pvh(&mut regs, 0x20_0000, 0x6000, 3).unwrap();
        v.enable_nested_paging(0xABC000);
        v
    }

    fn loaded(v: &Vmcb) -> Vmcs {
        let mut io = Vmcs::default();
        vmx::load(&mut io, &ctls(), &site(), &host(), v, &extra());
        io
    }

    #[test]
    fn access_rights_move_the_flags_nibble_up_and_mark_unusable() {
        // VMCB attrib: type/S/DPL/P in 7:0, AVL/L/D/G in 11:8. VMX AR: the same
        // low byte, AVL/L/D/G in 15:12, unusable in 16.
        assert_eq!(vmx::ar_from_attrib(ATTR_CODE32, true), 0xC09B);
        assert_eq!(vmx::ar_from_attrib(ATTR_DATA32, true), 0xC093);
        assert_eq!(vmx::ar_from_attrib(ATTR_REAL_CODE, true), 0x9B);
        assert_eq!(vmx::ar_from_attrib(ATTR_TSS_BUSY, true), 0x8B);
        assert_eq!(vmx::ar_from_attrib(0xA9B, true), 0xA09B, "64-bit code: L and G");
        assert_eq!(vmx::ar_from_attrib(0, false), 1 << 16);
        for a in [ATTR_CODE32, ATTR_DATA32, ATTR_REAL_CODE, ATTR_REAL_DATA, ATTR_TSS_BUSY, 0xA9B, 0x82] {
            assert_eq!(vmx::attrib_from_ar(vmx::ar_from_attrib(a, true)), a);
        }
        assert_eq!(vmx::attrib_from_ar(0x1_C093), 0, "an unusable segment is not present");
    }

    #[test]
    fn the_pvh_boot_cpu_is_loaded_with_the_state_the_protocol_names() {
        let v = pvh();
        let io = loaded(&v);
        assert_eq!(io.get(field::GUEST_RIP), 0x20_0000);
        // 32-bit flat code: selector 0x10, base 0, limit 4 GiB, AR 0xC09B.
        assert_eq!(io.get(field::GUEST_CS_SEL), 0x10);
        assert_eq!(io.get(field::GUEST_CS_BASE), 0);
        assert_eq!(io.get(field::GUEST_CS_LIMIT), 0xFFFF_FFFF);
        assert_eq!(io.get(field::GUEST_CS_AR), 0xC09B);
        assert_eq!(io.get(field::GUEST_DS_AR), 0xC093);
        assert_eq!(io.get(field::GUEST_TR_AR), 0x8B);
        assert_eq!(io.get(field::GUEST_TR_LIMIT), 0x67);
        // The LDT is not there: unusable. FS and GS are flat data, usable.
        assert_eq!(io.get(field::GUEST_LDTR_AR) & vmx::AR_UNUSABLE as u64, vmx::AR_UNUSABLE as u64);
        assert_eq!(io.get(field::GUEST_FS_AR) & vmx::AR_UNUSABLE as u64, 0);
        // Protected mode, paging off: CR0 = PE | ET, plus the NE VMX forces.
        assert_eq!(io.get(field::GUEST_CR0), 1 | 1 << 4 | 1 << 5);
        assert_eq!(io.get(field::GUEST_CR4), 1 << 13, "VMXE is forced on");
        assert_eq!(io.get(field::GUEST_RFLAGS), 2);
        // EFER without SVME (reserved on Intel); no IA-32e entry.
        assert_eq!(io.get(field::GUEST_EFER), 0);
        assert_eq!(io.get(field::ENTRY_CTLS) & vmx::bits::ENTRY_IA32E as u64, 0);
        assert_eq!(io.get(field::GUEST_PAT), 0x0007_0406_0007_0406);
        assert_eq!(io.get(field::VMCS_LINK_POINTER), u64::MAX);
        // EBX = start_info is a register, not a VMCS field: nothing wrote it.
        assert_eq!(io.get(field::GUEST_DR7), 0x400);
    }

    #[test]
    fn controls_ept_msr_lists_and_host_state_are_written() {
        let v = pvh();
        let io = loaded(&v);
        let k = ctls();
        assert_eq!(io.get(field::PIN_BASED), k.pin as u64);
        assert_eq!(io.get(field::PROC_BASED2), k.proc2 as u64);
        assert_eq!(io.get(field::EXIT_CTLS), k.exit as u64);
        // EPTP: write-back (6), 4-level walk (3 << 3), the image's nested root.
        assert_eq!(io.get(field::EPT_POINTER), 0xABC000 | 3 << 3 | 6);
        assert_eq!(io.get(field::VPID), 3, "the VM's id");
        assert_eq!(io.get(field::MSR_BITMAP), 0x7000);
        assert_eq!(io.get(field::EXCEPTION_BITMAP), 0);
        assert_eq!(io.get(field::CR3_TARGET_COUNT), 0);
        // Guest MSR list is both the entry load and the exit store; the host list loads at exit.
        let guest = 0x6000 + core::mem::offset_of!(Extra, guest) as u64;
        let host_l = 0x6000 + core::mem::offset_of!(Extra, host) as u64;
        assert_eq!(io.get(field::ENTRY_MSR_LOAD_ADDR), guest);
        assert_eq!(io.get(field::EXIT_MSR_STORE_ADDR), guest);
        assert_eq!(io.get(field::EXIT_MSR_LOAD_ADDR), host_l);
        for f in [field::ENTRY_MSR_LOAD_COUNT, field::EXIT_MSR_STORE_COUNT, field::EXIT_MSR_LOAD_COUNT] {
            assert_eq!(io.get(f), 5);
        }
        // The host.
        let h = host();
        assert_eq!(io.get(field::HOST_CR3), h.cr3);
        assert_eq!(io.get(field::HOST_RIP), h.rip);
        assert_eq!(io.get(field::HOST_GS_BASE), h.gs_base);
        assert_eq!(io.get(field::HOST_TR_SEL), 0x28);
        assert_eq!(io.get(field::HOST_EFER), 0xD01);
        // Host RSP is the stub's to write (it knows its own stack).
        assert!(!io.writes.contains(&field::HOST_RSP));
    }

    #[test]
    fn every_field_of_a_clean_vmcs_is_written_each_time() {
        // The VMCS is VMCLEARed at the end of every entry: nothing may be left to a previous one.
        let io = loaded(&pvh());
        let mut w = io.writes.clone();
        w.sort();
        let n = w.len();
        w.dedup();
        assert_eq!(w.len(), n, "no field is written twice");
        for f in [
            field::PIN_BASED, field::PROC_BASED, field::PROC_BASED2, field::EXIT_CTLS, field::ENTRY_CTLS,
            field::GUEST_CR0, field::GUEST_CR3, field::GUEST_CR4, field::GUEST_RIP, field::GUEST_RSP, field::GUEST_RFLAGS,
            field::GUEST_INTERRUPTIBILITY, field::GUEST_ACTIVITY, field::GUEST_PENDING_DBG, field::GUEST_GDTR_BASE,
            field::GUEST_IDTR_LIMIT, field::GUEST_SYSENTER_CS, field::GUEST_DEBUGCTL, field::HOST_CR0, field::HOST_IDTR_BASE,
            field::ENTRY_INT_INFO, field::TSC_OFFSET, field::EPT_POINTER, field::CR0_GUEST_HOST_MASK, field::CR4_READ_SHADOW,
        ] {
            assert!(w.contains(&f), "field {f:#x} not written");
        }
    }

    #[test]
    fn cr0_and_cr4_follow_the_guest_with_the_forced_bits_hidden_or_pinned() {
        let k = ctls();
        let mut v = pvh();
        v.wr64(off::CR0, 1 | 1 << 31 | 1 << 16 | 1 << 4);
        v.wr64(off::CR4, 1 << 5 | 1 << 9);
        let io = loaded(&v);
        assert_eq!(io.get(field::GUEST_CR0), 1 | 1 << 31 | 1 << 16 | 1 << 4 | 1 << 5, "NE forced");
        assert_eq!(io.get(field::GUEST_CR4), 1 << 5 | 1 << 9 | 1 << 13, "VMXE forced");
        assert_eq!(io.get(field::CR0_GUEST_HOST_MASK), k.cr0_forced);
        assert_eq!(io.get(field::CR4_GUEST_HOST_MASK), k.cr4_forced);
        // The guest reads NE as set (a write that clears it exits), VMXE as clear.
        assert_eq!(io.get(field::CR0_READ_SHADOW), 1 << 5);
        assert_eq!(io.get(field::CR4_READ_SHADOW), 0);
    }

    #[test]
    fn a_guest_in_long_mode_enters_in_ia32e_with_its_efer() {
        let mut v = pvh();
        v.wr64(off::EFER, efer::SVME | efer::LME | efer::LMA | 1 << 11);
        let io = loaded(&v);
        assert_ne!(io.get(field::ENTRY_CTLS) & vmx::bits::ENTRY_IA32E as u64, 0);
        assert_eq!(io.get(field::GUEST_EFER), efer::LME | efer::LMA | 1 << 11, "SVME stripped");
    }

    #[test]
    fn the_window_and_the_iret_intercept_are_the_two_exiting_controls() {
        let mut v = pvh();
        let base = loaded(&v).get(field::PROC_BASED);
        assert_eq!(base & (vmx::bits::PROC_INTERRUPT_WINDOW | vmx::bits::PROC_NMI_WINDOW) as u64, 0);
        v.request_window();
        let w = loaded(&v).get(field::PROC_BASED);
        assert_eq!(w, base | vmx::bits::PROC_INTERRUPT_WINDOW as u64);
        v.clear_window();
        v.set_iret_intercept(true);
        let n = loaded(&v).get(field::PROC_BASED);
        assert_eq!(n, base | vmx::bits::PROC_NMI_WINDOW as u64);
        v.set_iret_intercept(false);
        assert_eq!(loaded(&v).get(field::PROC_BASED), base);
        // Whatever else SVM intercepts is not a VMX control: unchanged.
        v.or32(off::INTERCEPT_W3, icpt::CPUID | icpt::HLT);
        assert_eq!(loaded(&v).get(field::PROC_BASED), base);
    }

    #[test]
    fn events_go_in_with_the_same_layout() {
        // Interruption information: vector 7:0, type 10:8 (0 external, 2 NMI, 3
        // hardware exception), error code valid 11, valid 31: SVM's EVENT_INJ.
        let mut v = pvh();
        v.inject_interrupt(0x41);
        let io = loaded(&v);
        assert_eq!(io.get(field::ENTRY_INT_INFO), 1 << 31 | 0x41);
        assert_eq!(io.get(field::ENTRY_INSN_LEN), 0);
        let mut v = pvh();
        v.inject_nmi();
        assert_eq!(loaded(&v).get(field::ENTRY_INT_INFO), 1 << 31 | 2 << 8 | 2);
        let mut v = pvh();
        v.inject_exception(13, Some(0x18));
        let io = loaded(&v);
        assert_eq!(io.get(field::ENTRY_INT_INFO), 1 << 31 | 1 << 11 | 3 << 8 | 13);
        assert_eq!(io.get(field::ENTRY_ERROR_CODE), 0x18);
        let mut v = pvh();
        v.inject_exception(6, None);
        assert_eq!(loaded(&v).get(field::ENTRY_INT_INFO), 1 << 31 | 3 << 8 | 6);
        // Nothing queued: nothing injected.
        assert_eq!(loaded(&pvh()).get(field::ENTRY_INT_INFO), 0);
    }

    #[test]
    fn a_software_event_that_an_exit_interrupted_is_reinjected_with_its_length() {
        // The image carries the length in the error-code word (a software event has no error code).
        let mut v = pvh();
        v.wr32(off::EVENT_INJ, 1 << 31 | 4 << 8 | 0x80);
        v.wr32(off::EVENT_INJ_ERR, 2);
        let io = loaded(&v);
        assert_eq!(io.get(field::ENTRY_INT_INFO), 1 << 31 | 4 << 8 | 0x80);
        assert_eq!(io.get(field::ENTRY_INSN_LEN), 2);
        // And back: an IDT-vectoring event of that type stores the length.
        let mut io = Vmcs::default();
        io.f.insert(field::EXIT_REASON, reason::EPT_VIOLATION as u64);
        io.f.insert(field::IDT_VECTORING_INFO, 1 << 31 | 4 << 8 | 0x80);
        io.f.insert(field::EXIT_INSN_LEN, 2);
        let mut img = pvh();
        vmx::store(&mut io, &mut img, &VmxRegs::default(), &ctls(), &mut extra());
        assert_eq!(img.rd32(off::EXIT_INT_INFO), 1 << 31 | 4 << 8 | 0x80);
        assert_eq!(img.rd32(off::EXIT_INT_INFO_ERR), 2);
        assert!(img.requeue_exit_event());
        assert_eq!(img.rd32(off::EVENT_INJ), 1 << 31 | 4 << 8 | 0x80);
        assert_eq!(img.rd32(off::EVENT_INJ_ERR), 2);
    }

    #[test]
    fn interruptibility_keeps_the_nmi_block_and_the_two_shadows_apart() {
        let mut img = pvh();
        let mut io = Vmcs::default();
        let rflags_if = 1 << 9 | 2;
        let k = ctls();
        let read = |io: &mut Vmcs, img: &mut Vmcb, word: u32| {
            io.f.insert(field::EXIT_REASON, reason::HLT as u64);
            io.f.insert(field::GUEST_INTERRUPTIBILITY, word as u64);
            io.f.insert(field::GUEST_RFLAGS, rflags_if);
            vmx::store(io, img, &VmxRegs::default(), &k, &mut extra());
            img.rd32(off::INT_STATE)
        };
        // Bit 0 STI, bit 1 MOV SS, bit 3 NMI. The image raises bit 0 for "any shadow".
        assert_eq!(read(&mut io, &mut img, 0), 0);
        assert_eq!(read(&mut io, &mut img, 1), 1);
        assert!(img.in_shadow());
        assert_eq!(read(&mut io, &mut img, 2), 3);
        assert!(img.in_shadow());
        assert_eq!(read(&mut io, &mut img, 8), 8);
        assert!(!img.in_shadow(), "NMI blocking is not an interrupt shadow");
        // And back: the entry sets exactly what the CPU reported.
        for (word, want) in [(0u32, 0u64), (1, 1), (2, 2), (8, 8), (9, 9)] {
            let mut v = pvh();
            v.wr64(off::RFLAGS, rflags_if);
            let _ = read(&mut io, &mut v, word);
            assert_eq!(loaded(&v).get(field::GUEST_INTERRUPTIBILITY), want, "word {word}");
        }
        // A shadow the service raised on its own (bit 0 only) is STI blocking, which needs IF=1.
        let mut v = pvh();
        v.wr32(off::INT_STATE, 1);
        v.wr64(off::RFLAGS, 2);
        assert_eq!(loaded(&v).get(field::GUEST_INTERRUPTIBILITY), 0, "STI blocking with IF clear would fail the entry");
        v.wr64(off::RFLAGS, 2 | 1 << 9);
        assert_eq!(loaded(&v).get(field::GUEST_INTERRUPTIBILITY), 1);
        // An NMI the service injects means it is not blocked: the CPU must agree.
        let mut v = pvh();
        v.wr32(off::INT_STATE, 8);
        v.inject_nmi();
        assert_eq!(loaded(&v).get(field::GUEST_INTERRUPTIBILITY), 0);
    }

    #[test]
    fn store_brings_the_guest_back_into_the_image() {
        let k = ctls();
        let mut io = Vmcs::default();
        let f = &mut io.f;
        f.insert(field::EXIT_REASON, reason::CPUID as u64);
        f.insert(field::EXIT_INSN_LEN, 2);
        f.insert(field::GUEST_RIP, 0x1000);
        f.insert(field::GUEST_RSP, 0x7FF0);
        f.insert(field::GUEST_RFLAGS, 0x202);
        f.insert(field::GUEST_CR0, 0x8000_0033);
        f.insert(field::GUEST_CR3, 0x4000);
        f.insert(field::GUEST_CR4, 1 << 5 | 1 << 13);
        f.insert(field::CR4_READ_SHADOW, 0);
        f.insert(field::GUEST_EFER, efer::LME | efer::LMA | 1 << 11);
        f.insert(field::GUEST_PAT, 0x0007_0406_0007_0406);
        f.insert(field::GUEST_CS_SEL, 0x10);
        f.insert(field::GUEST_CS_AR, 0xA09B);
        f.insert(field::GUEST_CS_LIMIT, 0xFFFF_FFFF);
        f.insert(field::GUEST_SS_AR, 0xC093 | 3 << 5);
        f.insert(field::GUEST_FS_BASE, 0xFFFF_8000_0000_0000);
        f.insert(field::GUEST_LDTR_AR, vmx::AR_UNUSABLE as u64);
        f.insert(field::GUEST_GDTR_BASE, 0x9000);
        f.insert(field::GUEST_GDTR_LIMIT, 0x2F);
        f.insert(field::GUEST_SYSENTER_CS, 8);
        let mut img = pvh();
        let regs = VmxRegs { rax: 0x1234, ..Default::default() };
        vmx::store(&mut io, &mut img, &regs, &k, &mut extra());
        assert_eq!(img.rd64(off::RIP), 0x1000);
        assert_eq!(img.rd64(off::NEXT_RIP), 0x1002);
        assert_eq!(img.rd64(off::RSP), 0x7FF0);
        assert_eq!(img.rd64(off::RAX), 0x1234);
        assert_eq!(img.rd64(off::RFLAGS), 0x202);
        assert_eq!(img.rd64(off::CR0), 0x8000_0033);
        assert_eq!(img.rd64(off::CR3), 0x4000);
        assert_eq!(img.rd64(off::CR4), 1 << 5, "the guest does not see VMXE");
        assert_eq!(img.rd64(off::EFER), efer::SVME | efer::LME | efer::LMA | 1 << 11, "the image keeps SVME set");
        assert_eq!(img.segment(off::CS), (0x10, 0xA9B, 0xFFFF_FFFF, 0));
        assert_eq!(img.segment(off::LDTR).1, 0, "unusable reads back as not present");
        assert_eq!(img.segment(off::FS).3, 0xFFFF_8000_0000_0000);
        assert_eq!(img.segment(off::GDTR), (0, 0, 0x2F, 0x9000));
        assert_eq!(img.rd8(off::CPL), 3, "CPL is SS.DPL");
        assert_eq!(img.rd64(off::SYSENTER_CS), 8);
        assert_eq!(img.rd64(off::EXIT_CODE), azos_arch::hv::svm::code::CPUID);
        // The event that was queued went in: the valid bit is gone, as SVM clears it.
        let mut img = pvh();
        img.inject_interrupt(0x30);
        let mut io = Vmcs::default();
        io.f.insert(field::EXIT_REASON, reason::HLT as u64);
        vmx::store(&mut io, &mut img, &VmxRegs::default(), &k, &mut extra());
        assert!(!img.event_queued());
        // A failed entry keeps it, and leaves the guest state alone.
        let mut img = pvh();
        img.inject_interrupt(0x30);
        let before = img.rd64(off::RIP);
        let mut io = Vmcs::default();
        io.f.insert(field::EXIT_REASON, (reason::INVALID_GUEST_STATE | reason::ENTRY_FAILURE) as u64);
        io.f.insert(field::GUEST_RIP, 0xBAD);
        io.f.insert(field::EXIT_QUALIFICATION, 2);
        vmx::store(&mut io, &mut img, &VmxRegs::default(), &k, &mut extra());
        assert!(img.event_queued());
        assert_eq!(img.rd64(off::RIP), before);
        assert_eq!(img.rd64(off::EXIT_CODE), azos_arch::hv::svm::code::INVALID);
        assert_eq!(img.rd64(off::EXIT_INFO_1), 2);
    }

    #[test]
    fn pae_paging_keeps_its_page_directory_pointers_across_the_vmclear() {
        let k = ctls();
        let mut x = extra();
        let mut io = Vmcs::default();
        io.f.insert(field::EXIT_REASON, reason::HLT as u64);
        io.f.insert(field::GUEST_CR0, 0x8000_0033);
        io.f.insert(field::GUEST_CR4, 1 << 5 | 1 << 13);
        io.f.insert(field::GUEST_EFER, 0);
        for (i, f) in [field::GUEST_PDPTE0, field::GUEST_PDPTE1, field::GUEST_PDPTE2, field::GUEST_PDPTE3].iter().enumerate() {
            io.f.insert(*f, 0x1000 * (i as u64 + 1) | 1);
        }
        let mut img = pvh();
        vmx::store(&mut io, &mut img, &VmxRegs::default(), &k, &mut x);
        assert_eq!(x.pdpte, [0x1001, 0x2001, 0x3001, 0x4001]);
        // Loaded again for a PAE guest (paging on, PAE on, not long mode).
        img.wr64(off::CR0, 0x8000_0033);
        img.wr64(off::CR4, 1 << 5);
        let mut io2 = Vmcs::default();
        vmx::load(&mut io2, &k, &site(), &host(), &img, &x);
        assert_eq!(io2.get(field::GUEST_PDPTE2), 0x3001);
        // Not for a real-mode guest: the fields are not touched.
        let io3 = loaded(&pvh());
        assert!(!io3.writes.contains(&field::GUEST_PDPTE0));
    }

    #[test]
    fn the_run_stub_offsets_are_the_field_order() {
        use core::mem::offset_of;
        // `azos_vmx_run` loads and stores by these offsets.
        assert_eq!(offset_of!(VmxRegs, rax), 0);
        let g = offset_of!(VmxRegs, g);
        assert_eq!(g, 8);
        let expect = [
            ("rbx", offset_of!(GuestRegs, rbx), 8),
            ("rcx", offset_of!(GuestRegs, rcx), 16),
            ("rdx", offset_of!(GuestRegs, rdx), 24),
            ("rsi", offset_of!(GuestRegs, rsi), 32),
            ("rdi", offset_of!(GuestRegs, rdi), 40),
            ("rbp", offset_of!(GuestRegs, rbp), 48),
            ("r8", offset_of!(GuestRegs, r8), 56),
            ("r9", offset_of!(GuestRegs, r9), 64),
            ("r10", offset_of!(GuestRegs, r10), 72),
            ("r11", offset_of!(GuestRegs, r11), 80),
            ("r12", offset_of!(GuestRegs, r12), 88),
            ("r13", offset_of!(GuestRegs, r13), 96),
            ("r14", offset_of!(GuestRegs, r14), 104),
            ("r15", offset_of!(GuestRegs, r15), 112),
        ];
        for (n, o, want) in expect {
            assert_eq!(g + o, want, "{n}");
        }
        assert_eq!(core::mem::size_of::<VmxRegs>(), 120);
    }

    #[test]
    fn the_tss_base_is_scattered_over_the_two_descriptor_words() {
        // Base 0x1234_5678_9ABC_DEF0 split as the system descriptor does:
        // low word base 15:0 at 31:16, 23:16 at 39:32, 31:24 at 63:56; high word base 63:32.
        let base = 0x1234_5678_9ABC_DEF0u64;
        let lo = (base & 0xFFFF) << 16 | (base >> 16 & 0xFF) << 32 | (base >> 24 & 0xFF) << 56 | 0x67 | 0x8B << 40;
        let hi = base >> 32;
        assert_eq!(vmx::tss_base(lo, hi), base);
    }

    #[test]
    fn the_synthetic_svm_caps_have_what_the_shared_entry_reads() {
        let c = vmx::svm_caps();
        assert!(c.nrips && c.flush_by_asid);
        assert!(c.nasid > u16::MAX as u32, "a VPID is 16 bits");
    }
}

mod ept_tests {
    use azos_arch::hv::ept::{self, *};
    use azos_arch::hv::npt::GuestAccess;
    use azos_arch::mmu::{self, TableMem, WalkError};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Mem {
        words: HashMap<(usize, usize), u64>,
        next: usize,
        refuse: bool,
    }

    impl Mem {
        fn new() -> Mem {
            Mem { next: 0x10_0000, ..Default::default() }
        }
    }

    impl TableMem for Mem {
        fn read(&self, table: usize, idx: usize) -> u64 {
            *self.words.get(&(table, idx)).unwrap_or(&0)
        }
        fn write(&mut self, table: usize, idx: usize, word: u64) {
            self.words.insert((table, idx), word);
        }
        fn alloc_table(&mut self) -> Option<usize> {
            if self.refuse {
                return None;
            }
            let t = self.next;
            self.next += 0x1000;
            Some(t)
        }
    }

    fn tree() -> (Mem, usize) {
        let mut m = Mem::new();
        let root = m.alloc_table().unwrap();
        (m, root)
    }

    #[test]
    fn entries_are_in_the_ept_format_not_the_x86_one() {
        // SDM vol. 3 table 29-1 / 29-3: R 0, W 1, X 2, memory type 5:3, IPAT 6,
        // large page 7, accessed 8, dirty 9, address 51:12.
        assert_eq!([READ, WRITE, EXEC], [1, 2, 4]);
        assert_eq!((MT_SHIFT, MT_WB, IGNORE_PAT, LARGE, ACCESSED, DIRTY), (3, 6, 1 << 6, 1 << 7, 1 << 8, 1 << 9));
        assert_eq!(ADDR_MASK, 0x000F_FFFF_FFFF_F000);
        // A table pointer is read+write+execute and nothing else.
        assert_eq!(table_entry(0x1234_5000), 0x1234_5000 | 7);
        // Leaves: read always; write-back; the guest's PAT applies; no A/D (the EPTP does not enable them).
        assert_eq!(leaf_entry(0xABC000, GuestAccess::RW), 0xABC000 | 1 | 2 | 6 << 3);
        assert_eq!(leaf_entry(0xABC000, GuestAccess::RX), 0xABC000 | 1 | 4 | 6 << 3);
        assert_eq!(leaf_entry(0xABC000, GuestAccess { write: false, exec: false }), 0xABC000 | 1 | 6 << 3);
        for a in [GuestAccess::RW, GuestAccess::RX] {
            let w = leaf_entry(0x1000, a);
            assert_eq!(w & (ACCESSED | DIRTY | IGNORE_PAT | LARGE), 0);
            assert_eq!(w >> 52, 0, "no bit above the address: suppress-#VE and the reserved ones are clear");
            assert_eq!(access_of(w), a);
        }
        // The one word the two formats share: a table pointer (x86 P|RW|US is R|W|X).
        // Leaves are not (accessed and dirty are EPT's memory-type bits), which is why
        // `npt::map` cannot build them.
        assert_eq!(mmu::make_table(0x2000), table_entry(0x2000));
        assert_ne!(mmu::make_table(0x2000) | 1 << 5 | 1 << 6, leaf_entry(0x2000, GuestAccess::RW));
        // Execute-only is representable and is not "not present".
        assert!(present(EXEC) && present(WRITE) && !present(0));
    }

    #[test]
    fn eptp_is_memory_type_walk_length_and_root() {
        // SDM vol. 3 table 24-8: bits 2:0 memory type (6 = WB), 5:3 walk length - 1, 6 A/D, 51:12 root.
        assert_eq!(eptp(0xABC000, false), 0xABC000 | 3 << 3 | 6);
        assert_eq!(eptp(0xABC000, true), 0xABC000 | 3 << 3 | 6 | 1 << 6);
        assert_eq!(eptp_root(eptp(0xABC000, true)), 0xABC000);
        // A root with garbage in the low bits does not leak into the control fields.
        assert_eq!(eptp(0xABCFFF, false), 0xABC000 | 3 << 3 | 6);
    }

    #[test]
    fn mapping_translating_and_unmapping_a_page() {
        let (mut m, root) = tree();
        map(&mut m, root, 0x2000_1000, 0xABC000, GuestAccess::RW).unwrap();
        let l = translate(&m, root, 0x2000_1234).unwrap();
        assert_eq!((l.level, l.phys), (0, 0xABC234));
        assert_eq!(access_of(l.word), GuestAccess::RW);
        assert!(translate(&m, root, 0x2000_2000).is_none());
        assert!(translate(&m, root, 0x2000_0000).is_none());
        // Four levels were built, each pointing to the next with RWX.
        let mut table = root;
        for level in (1..4).rev() {
            let w = m.read(table, (0x2000_1000usize >> (12 + 9 * level)) & 511);
            assert_eq!(w & 7, 7, "level {level}");
            assert_eq!(w & LARGE, 0);
            table = (w & ADDR_MASK) as usize;
        }
        assert_eq!(unmap(&mut m, root, 0x2000_1000), Ok(0xABC000));
        assert!(translate(&m, root, 0x2000_1000).is_none());
        assert_eq!(unmap(&mut m, root, 0x2000_1000), Err(WalkError::NotMapped));
    }

    #[test]
    fn the_refusals() {
        let (mut m, root) = tree();
        map(&mut m, root, 0x1000, 0x5000, GuestAccess::RX).unwrap();
        assert_eq!(map(&mut m, root, 0x1000, 0x6000, GuestAccess::RX), Err(WalkError::AlreadyMapped));
        assert_eq!(map(&mut m, root, 0x1001, 0x6000, GuestAccess::RX), Err(WalkError::Misaligned));
        assert_eq!(map(&mut m, root, 0x2000, 0x6001, GuestAccess::RX), Err(WalkError::Misaligned));
        assert_eq!(map(&mut m, root, 1 << 48, 0x6000, GuestAccess::RX), Err(WalkError::NotCanonical));
        assert_eq!(map(&mut m, root, 0x2000, 1 << 52, GuestAccess::RX), Err(WalkError::Misaligned), "no bits above 51");
        assert!(translate(&m, root, 1 << 48).is_none());
        assert_eq!(unmap(&mut m, root, 1 << 48), Err(WalkError::NotCanonical));
        // Out of table memory.
        m.refuse = true;
        assert_eq!(map(&mut m, root, 0x4000_0000_0000, 0x6000, GuestAccess::RX), Err(WalkError::NoMemory));
    }

    #[test]
    fn a_large_leaf_in_the_way_is_not_split_or_overwritten() {
        let (mut m, root) = tree();
        // Hand-build a 2 MiB leaf at gpa 0x40_0000: PML4 -> PDPT -> PD entry with the large bit.
        let pdpt = m.alloc_table().unwrap();
        let pd = m.alloc_table().unwrap();
        m.write(root, 0, table_entry(pdpt as u64));
        m.write(pdpt, 0, table_entry(pd as u64));
        m.write(pd, 2, 0x80_0000 | READ | WRITE | EXEC | MT_WB << MT_SHIFT | LARGE);
        let l = translate(&m, root, 0x40_1234).unwrap();
        assert_eq!((l.level, l.phys), (1, 0x80_1234));
        assert_eq!(map(&mut m, root, 0x40_1000, 0x9000, GuestAccess::RW), Err(WalkError::HugeLeafInTheWay));
        assert_eq!(unmap(&mut m, root, 0x40_1000), Err(WalkError::HugeLeafInTheWay));
    }

    #[test]
    fn the_guest_memory_walk_of_the_x86_builder_reads_an_ept_tree() {
        // `vcpu`'s read of guest memory (instruction bytes of a device access)
        // goes through `mmu::translate`, which knows nothing of EPT: it reads
        // "present" from bit 0, "large" from bit 7 and the address from 51:12,
        // which this module's entries satisfy. Pin it, for 4 KiB and large leaves.
        let (mut m, root) = tree();
        for (gpa, hpa) in [(0x1000usize, 0x7000usize), (0x7FFF_F000, 0x1234_5000), (0x80_0000_0000, 0xABC_D000)] {
            map(&mut m, root, gpa, hpa, GuestAccess::RX).unwrap();
            let theirs = mmu::translate(&m, root, 4, gpa + 0x123).unwrap();
            let ours = translate(&m, root, gpa + 0x123).unwrap();
            assert_eq!((theirs.level, theirs.phys as u64), (ours.level, ours.phys), "gpa {gpa:#x}");
        }
        let pdpt = m.alloc_table().unwrap();
        let pd = m.alloc_table().unwrap();
        m.write(root, 5, table_entry(pdpt as u64));
        m.write(pdpt, 0, table_entry(pd as u64));
        m.write(pd, 1, 0x60_0000 | READ | WRITE | MT_WB << MT_SHIFT | LARGE);
        let gpa = (5usize << 39) + (1 << 21) + 0x321;
        let theirs = mmu::translate(&m, root, 4, gpa).unwrap();
        let ours = translate(&m, root, gpa).unwrap();
        assert_eq!((theirs.level, theirs.phys as u64), (ours.level, ours.phys));
        let _ = ept::LEVELS;
    }
}

mod guest_ram {
    use azos_arch::hv::ept::{self, GuestRam};
    use azos_arch::hv::mmio::GuestMem;
    use azos_arch::hv::npt::GuestAccess;
    use azos_arch::mmu::TableMem;
    use std::cell::RefCell;

    /// Physical memory as bytes: frames at 0x1000 up are tables, the rest data.
    struct Ram {
        b: RefCell<Vec<u8>>,
        next: usize,
    }

    impl TableMem for Ram {
        fn read(&self, table: usize, idx: usize) -> u64 {
            let b = self.b.borrow();
            u64::from_le_bytes(b[table + idx * 8..table + idx * 8 + 8].try_into().unwrap())
        }
        fn write(&mut self, table: usize, idx: usize, word: u64) {
            self.b.borrow_mut()[table + idx * 8..table + idx * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        fn alloc_table(&mut self) -> Option<usize> {
            let t = self.next;
            self.next += 0x1000;
            Some(t)
        }
    }

    #[test]
    fn guest_memory_is_read_through_the_tree_across_non_contiguous_frames() {
        let mut ram = Ram { b: RefCell::new(vec![0; 0x10_0000]), next: 0x1000 };
        let root = ram.alloc_table().unwrap();
        ept::map(&mut ram, root, 0x1000, 0x8_0000, GuestAccess::RX).unwrap();
        ept::map(&mut ram, root, 0x2000, 0x4_0000, GuestAccess::RX).unwrap();
        for i in 0..0x1000 {
            ram.b.borrow_mut()[0x8_0000 + i] = 0xA0 | (i % 16) as u8;
            ram.b.borrow_mut()[0x4_0000 + i] = 0xB0 | (i % 16) as u8;
        }
        let read = |pa: u64, buf: &mut [u8]| {
            let b = ram.b.borrow();
            match b.get(pa as usize..pa as usize + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    true
                }
                None => false,
            }
        };
        let g = GuestRam { root: root as u64, read_phys: &read };
        // Eight bytes at the end of the first page, eight at the start of the second.
        let mut buf = [0u8; 16];
        assert!(g.read(0x1FF8, &mut buf));
        assert_eq!(buf[..8], [0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF]);
        assert_eq!(buf[8..12], [0xB0, 0xB1, 0xB2, 0xB3]);
        // Unmapped anywhere in the range: the whole read fails.
        assert!(!g.read(0x2FF8, &mut buf));
        assert!(!g.read(0x3000, &mut buf));
        // A tree that points outside RAM fails the read and does not panic.
        assert!(!GuestRam { root: 0x200_0000, read_phys: &read }.read(0x1000, &mut buf));
    }
}

mod format {
    use azos_arch::hv::{ept, Format};
    use azos_arch_api::{StageError, StagePerms, StageTableMem};
    use std::collections::HashMap;

    /// Frames from 0x10_0000 up, a flat word store.
    #[derive(Default)]
    struct Frames {
        w: HashMap<u64, u64>,
        next: u64,
        live: Vec<u64>,
    }

    impl Frames {
        fn new() -> Frames {
            Frames { next: 0x10_0000, ..Default::default() }
        }
    }

    impl StageTableMem for Frames {
        fn alloc(&mut self, pages: usize) -> Option<u64> {
            let pa = self.next;
            self.next += pages as u64 * 0x1000;
            self.live.push(pa);
            Some(pa)
        }
        fn free(&mut self, pa: u64, _pages: usize) {
            self.live.retain(|p| *p != pa);
        }
        fn read(&self, pa: u64) -> u64 {
            *self.w.get(&pa).unwrap_or(&0)
        }
        fn write(&mut self, pa: u64, word: u64) {
            self.w.insert(pa, word);
        }
    }

    const RW: StagePerms = StagePerms { write: true, exec: false };
    const RX: StagePerms = StagePerms { write: false, exec: true };

    #[test]
    fn the_two_formats_build_their_own_entries_through_the_same_calls() {
        for f in [Format::Npt, Format::Ept] {
            let mut mem = Frames::new();
            let s2 = f.create(&mut mem).unwrap();
            f.map(&s2, &mut mem, 0x3000_0000, 0xA000, RW).unwrap();
            f.map(&s2, &mut mem, 0x3000_1000, 0xB000, RX).unwrap();
            assert_eq!(f.translate(&s2, &mem, 0x3000_0abc), Some((0xAABC, RW)), "{f:?}");
            assert_eq!(f.translate(&s2, &mem, 0x3000_1000), Some((0xB000, RX)), "{f:?}");
            assert_eq!(f.translate(&s2, &mem, 0x3000_2000), None);
            assert_eq!(f.map(&s2, &mut mem, 0x3000_0000, 0xC000, RW), Err(StageError::Overlap));
            assert_eq!(f.map(&s2, &mut mem, 1 << 47, 0xC000, RW), Err(StageError::OutOfRange));
            assert_eq!(f.map(&s2, &mut mem, 0x3000_2001, 0xC000, RW), Err(StageError::Misaligned));
            assert_eq!(f.unmap(&s2, &mut mem, 0x3000_0000), Ok(0xA000));
            assert_eq!(f.unmap(&s2, &mut mem, 0x3000_0000), Err(StageError::NotMapped));
            assert_eq!(f.translate(&s2, &mem, 0x3000_0000), None);
            assert_eq!(f.gpa_bits(), 47);
        }
    }

    #[test]
    fn ept_leaves_in_the_frames_are_ept_words() {
        let mut mem = Frames::new();
        let s2 = Format::Ept.create(&mut mem).unwrap();
        assert_eq!(s2.aux, 4, "the guest memory walk reads the depth from aux");
        Format::Ept.map(&s2, &mut mem, 0x1000, 0xA000, RX).unwrap();
        // Walk by hand: the leaf is read | execute | write-back, at the bottom of four levels.
        let mut t = s2.root;
        for lvl in (0..4).rev() {
            let w = mem.read(t + 8 * ((0x1000u64 >> (12 + 9 * lvl)) & 511));
            assert_eq!(w & 1, 1, "level {lvl}");
            if lvl == 0 {
                assert_eq!(w, 0xA000 | ept::READ | ept::EXEC | ept::MT_WB << ept::MT_SHIFT);
            } else {
                assert_eq!(w & 7, 7);
                t = w & ept::ADDR_MASK;
            }
        }
        // The x86 format keeps its own: user and accessed, no write-back type field.
        let mut mem = Frames::new();
        let s2 = Format::Npt.create(&mut mem).unwrap();
        Format::Npt.map(&s2, &mut mem, 0x1000, 0xA000, RX).unwrap();
        let mut t = s2.root;
        let mut leaf = 0;
        for lvl in (0..s2.aux).rev() {
            let w = mem.read(t + 8 * ((0x1000u64 >> (12 + 9 * lvl)) & 511));
            t = w & ept::ADDR_MASK;
            leaf = w;
        }
        assert_ne!(leaf & (1 << 2), 0, "x86 bit 2 is user");
        assert_eq!(leaf & (1 << 6 | 1 << 5), 1 << 6 | 1 << 5, "accessed and dirty preset");
    }

    #[test]
    fn a_larger_leaf_is_not_a_4k_unmap_in_either_format() {
        let mut mem = Frames::new();
        let s2 = Format::Ept.create(&mut mem).unwrap();
        // A 2 MiB leaf at gpa 0, hand-made.
        let (pdpt, pd) = (mem.alloc(1).unwrap(), mem.alloc(1).unwrap());
        mem.write(s2.root, ept::table_entry(pdpt));
        mem.write(pdpt, ept::table_entry(pd));
        mem.write(pd, 0x20_0000 | ept::READ | ept::WRITE | ept::LARGE);
        assert_eq!(Format::Ept.unmap(&s2, &mut mem, 0x1000), Err(StageError::Overlap));
        assert_eq!(Format::Ept.translate(&s2, &mem, 0x1234), Some((0x20_1234, RW)));
    }
}

/// The real guest entry (`vcpu::enter`) and the real VMX translation over a
/// scripted CPU: each `VMLAUNCH` plays the next step of the guest.
mod enter {
    use super::*;
    use azos_arch::hv::apic::{ApicEvent, Gp, LocalApic};
    use azos_arch::hv::cpuid::Leaf;
    use azos_arch::hv::ept;
    use azos_arch::hv::npt::GuestAccess;
    use azos_arch::hv::probe::SvmCaps;
    use azos_arch::hv::svm::off;
    use azos_arch::hv::vcpu::{self, Claim, Machine, Ran, VcpuMem, VmHost, VmInfo, PAGE};
    use azos_arch::hv::vmx::{Controls, Extra, HostState, MsrEntry, Site, VmxCpu, VmxRegs};
    use azos_arch::mmu::TableMem;
    use azos_arch_api::{Exit, GuestCtx, MmioAccess, MmioDone, Stage2Root};
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    use std::collections::VecDeque;
    use std::sync::{Mutex, MutexGuard};

    const FP_BYTES: usize = 832;
    const ENTRY: u64 = 0x20_0000;
    const DEVICE: u64 = 0x1000_1000;
    /// The entry keeps its slots and per-CPU records in statics.
    static LOCK: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── the kernel ──────────────────────────────────────────────────────

    #[derive(Default)]
    struct Apic {
        pending: Option<u8>,
        acked: Vec<u8>,
        events: VecDeque<ApicEvent>,
    }

    impl LocalApic for Apic {
        fn msr_read(&mut self, _msr: u32, _tsc: u64) -> Result<u64, Gp> {
            Err(Gp)
        }
        fn msr_write(&mut self, _msr: u32, _val: u64, _tsc: u64) -> Result<(), Gp> {
            Err(Gp)
        }
        fn tick(&mut self, _tsc: u64) {}
        fn pending(&self) -> Option<u8> {
            self.pending
        }
        fn ack(&mut self) -> Option<u8> {
            let v = self.pending.take();
            self.acked.extend(v);
            v
        }
        fn take_event(&mut self) -> Option<ApicEvent> {
            self.events.pop_front()
        }
        fn has_work(&self) -> bool {
            self.pending.is_some()
        }
        fn next_deadline(&self) -> Option<u64> {
            None
        }
        fn init_reset(&mut self) {}
        fn owns_mmio(&self, _gpa: u64) -> bool {
            false
        }
        fn mmio_read(&mut self, _gpa: u64, _size: u8, _tsc: u64) -> u32 {
            0
        }
        fn mmio_write(&mut self, _gpa: u64, _size: u8, _val: u32, _tsc: u64) {}
    }

    struct Host {
        apic: Mutex<Apic>,
        pages: Mutex<Vec<(u64, usize)>>,
        vcpus: u8,
    }

    impl Host {
        fn new(vcpus: u8) -> Host {
            Host { apic: Mutex::new(Apic::default()), pages: Mutex::new(Vec::new()), vcpus }
        }
    }

    fn layout(pages: usize) -> Layout {
        Layout::from_size_align(pages * PAGE, PAGE).unwrap()
    }

    impl Drop for Host {
        fn drop(&mut self) {
            for (pa, n) in self.pages.get_mut().unwrap().drain(..) {
                // SAFETY: allocated by `alloc_pages` with the same layout, not freed since.
                unsafe { dealloc(pa as *mut u8, layout(n)) };
            }
        }
    }

    impl VmHost for Host {
        fn alloc_pages(&self, pages: usize) -> Option<u64> {
            // SAFETY: a non-zero, page-aligned layout.
            let pa = unsafe { alloc_zeroed(layout(pages)) } as u64;
            self.pages.lock().unwrap().push((pa, pages));
            Some(pa)
        }
        fn free_pages(&self, pa: u64, pages: usize) {
            self.pages.lock().unwrap().retain(|(p, _)| *p != pa);
            // SAFETY: as in `Drop`.
            unsafe { dealloc(pa as *mut u8, layout(pages)) };
        }
        fn vm_info(&self, _vmid: u16) -> Option<VmInfo> {
            Some(VmInfo { vcpus: self.vcpus, tsc_khz: 2_000_000, apic_khz: 100_000 })
        }
        fn reset_vm(&self, vmid: u16) -> Option<VmInfo> {
            self.vm_info(vmid)
        }
        fn with_apic(&self, _vmid: u16, _vcpu: u8, f: &mut dyn FnMut(&mut dyn LocalApic)) -> bool {
            f(&mut *self.apic.lock().unwrap());
            true
        }
        fn raise_lines(&self, _vmid: u16, _lines: u64) {}
        fn release_vm(&self, _vmid: u16) {}
    }

    /// Guest-physical tables in host memory (pa = host address).
    struct Tables(Vec<u64>);

    impl Tables {
        fn frame(&mut self) -> usize {
            // SAFETY: a non-zero, page-aligned layout; freed in `Drop`.
            let p = unsafe { alloc_zeroed(layout(1)) } as u64;
            self.0.push(p);
            p as usize
        }
    }

    impl Drop for Tables {
        fn drop(&mut self) {
            for p in self.0.drain(..) {
                // SAFETY: allocated by `frame`, freed once.
                unsafe { dealloc(p as *mut u8, layout(1)) };
            }
        }
    }

    impl TableMem for Tables {
        fn read(&self, table: usize, idx: usize) -> u64 {
            // SAFETY: `table` is a frame of this set.
            unsafe { *(table as *const u64).add(idx) }
        }
        fn write(&mut self, table: usize, idx: usize, word: u64) {
            // SAFETY: as `read`.
            unsafe { *(table as *mut u64).add(idx) = word }
        }
        fn alloc_table(&mut self) -> Option<usize> {
            Some(self.frame())
        }
    }

    // ── the CPU ─────────────────────────────────────────────────────────

    /// A step of the guest: it runs when the entry does, sees and changes the
    /// VMCS the entry filled and the registers, and says whether the
    /// instruction worked.
    type Step = Box<dyn FnOnce(&mut Vmcs, &mut VmxRegs) -> bool>;

    struct Cpu {
        vmcs: Vmcs,
        steps: VecDeque<Step>,
        log: Vec<String>,
        launched: Vec<bool>,
        cr2: u64,
        extra: *mut Extra,
        lists: Vec<([MsrEntry; 5], [MsrEntry; 5])>,
        refuse_load: bool,
        /// What the hardware does to the entry's side page during the next run.
        hook: Option<Box<dyn FnOnce(&mut Extra)>>,
    }

    impl Cpu {
        fn new() -> Cpu {
            Cpu {
                vmcs: Vmcs::default(),
                steps: VecDeque::new(),
                log: Vec::new(),
                launched: Vec::new(),
                cr2: 0xC0DE,
                extra: core::ptr::null_mut(),
                lists: Vec::new(),
                refuse_load: false,
                hook: None,
            }
        }
        fn hook(&mut self, f: impl FnOnce(&mut Extra) + 'static) {
            self.hook = Some(Box::new(f));
        }
        fn then(&mut self, f: impl FnOnce(&mut Vmcs, &mut VmxRegs) -> bool + 'static) -> &mut Cpu {
            self.steps.push_back(Box::new(f));
            self
        }
    }

    impl VmcsIo for Cpu {
        fn read(&mut self, field: u32) -> u64 {
            self.vmcs.read(field)
        }
        fn write(&mut self, field: u32, value: u64) {
            self.vmcs.write(field, value)
        }
    }

    impl VmxCpu for Cpu {
        fn host_state(&mut self) -> HostState {
            HostState { rip: 0xFFFF_8000_0000_1234, cr3: 0x1000, ..HostState::default() }
        }
        fn rdmsr(&mut self, msr: u32) -> u64 {
            0xAA00_0000_0000 | msr as u64
        }
        fn cr2(&mut self) -> u64 {
            self.cr2
        }
        fn set_cr2(&mut self, v: u64) {
            self.log.push(format!("cr2={v:#x}"));
            self.cr2 = v;
        }
        fn vmclear(&mut self, pa: u64) -> bool {
            self.log.push(format!("vmclear {}", pa != 0));
            self.vmcs = Vmcs::default();
            true
        }
        fn vmptrld(&mut self, _pa: u64) -> bool {
            self.log.push("vmptrld".into());
            !self.refuse_load
        }
        fn invept(&mut self, single: bool, eptp: u64) {
            self.log.push(format!("invept {} {eptp:#x}", if single { "single" } else { "all" }));
        }
        fn invvpid(&mut self, single: bool, vpid: u16) {
            self.log.push(format!("invvpid {} {vpid}", if single { "single" } else { "all" }));
        }
        fn enter(&mut self, regs: &mut VmxRegs, launched: bool) -> bool {
            self.log.push(format!("enter {launched}"));
            self.launched.push(launched);
            // SAFETY: the test machine set it to the vCPU's `Extra` before the run;
            // this plays the hardware, which reads and writes it behind the entry's back.
            let x = unsafe { &mut *self.extra };
            self.lists.push((x.guest, x.host));
            if let Some(h) = self.hook.take() {
                h(x);
            }
            let step = self.steps.pop_front().expect("the guest ran out of script");
            let ok = step(&mut self.vmcs, regs);
            if !ok {
                self.vmcs.f.insert(field::INSN_ERROR, 7);
            }
            ok
        }
        fn after_exit(&mut self) {
            self.log.push("after_exit".into());
        }
        fn take_nmi(&mut self) {
            self.log.push("nmi".into());
        }
        fn io_failed(&mut self) -> bool {
            false
        }
    }

    fn intel(leaf: u32, _sub: u32) -> Leaf {
        match leaf {
            0 => Leaf { eax: 0x1B, ebx: 0x756E_6547, ecx: 0x6C65_746E, edx: 0x4965_6E69 },
            1 => Leaf { eax: 0x000606A6, ebx: 0x0010_0800, ecx: 0x7FFE_FBFF, edx: 0xBFEB_FBFF },
            _ => Leaf { eax: 0, ebx: 0, ecx: 0, edx: 0 },
        }
    }

    /// Host memory at its own address, as the tests lay out guest frames.
    fn read_raw(pa: u64, buf: &mut [u8]) -> bool {
        // SAFETY: the tests only name addresses of their own frames.
        unsafe { core::ptr::copy_nonoverlapping(pa as *const u8, buf.as_mut_ptr(), buf.len()) };
        true
    }

    struct M {
        cpu: Cpu,
        k: Controls,
    }

    impl Machine for M {
        fn cpu(&self) -> usize {
            0
        }
        fn host_tsc(&self) -> u64 {
            1_000_000
        }
        fn ticks_to_tsc(&self, ticks: u64) -> u64 {
            ticks
        }
        fn host_cpuid(&self, leaf: u32, sub: u32) -> Leaf {
            intel(leaf, sub)
        }
        fn svm_caps(&self) -> SvmCaps {
            vmx::svm_caps()
        }
        fn fp_bytes(&self) -> usize {
            FP_BYTES
        }
        fn extra_pages(&self) -> usize {
            vmx::EXTRA_PAGES
        }
        fn read_phys(&self, pa: u64, buf: &mut [u8]) -> bool {
            read_raw(pa, buf)
        }
        fn map(&self, pa: u64) -> *mut u8 {
            pa as *mut u8
        }
        fn vmrun(&mut self, v: &mut VcpuMem, fp: *mut u8, _xcr0: u64, cpu: usize, claim: &Claim) -> Ran {
            let extra = vcpu::extra_offset(FP_BYTES) - vcpu::fp_offset();
            let pa = v.run.pa + (vcpu::fp_offset() + extra) as u64;
            let site = Site { vmcs_pa: pa, extra_pa: pa + PAGE as u64, msr_bitmap_pa: 0x7000 };
            // SAFETY: the vCPU's pages end with the two extra pages (`extra_pages`).
            let x = unsafe { &mut *(fp.add(extra + PAGE) as *mut Extra) };
            self.cpu.extra = x;
            vmx::run(&mut self.cpu, &self.k, &site, v, x, claim, cpu, &read_raw);
            Ran::Done
        }
    }

    fn ctls() -> Controls {
        Controls {
            revision: 1,
            pin: 0x1_0001 | vmx::bits::PIN_EXTERNAL_INTERRUPT | vmx::bits::PIN_NMI | vmx::bits::PIN_VIRTUAL_NMI,
            proc: vmx::bits::PROC_HLT | vmx::bits::PROC_SECONDARY | vmx::bits::PROC_MSR_BITMAPS,
            proc2: vmx::bits::PROC2_EPT | vmx::bits::PROC2_UNRESTRICTED_GUEST | vmx::bits::PROC2_VPID,
            exit: 0x36DFE,
            entry: 0x11FB,
            vpid: true,
            invvpid_single: true,
            invept_single: true,
            ept_ad: false,
            cr0_forced: 1 << 5,
            cr0_fixed1: 0xFFFF_FFFF,
            cr4_forced: 1 << 13,
            cr4_fixed1: 0x0037_77FF,
        }
    }

    /// A one-vCPU VM: EPT with the code page at `ENTRY`, a machine with the
    /// script, a context starting at `ENTRY` with `DEVICE` in EBX.
    struct Rig {
        host: Host,
        m: M,
        ctx: GuestCtx,
        _mem: Tables,
        vmid: u16,
    }

    impl Rig {
        fn new(vmid: u16, code: &[u8]) -> Rig {
            Rig::with_vcpus(vmid, 1, code)
        }

        fn with_vcpus(vmid: u16, vcpus: u8, code: &[u8]) -> Rig {
            let mut mem = Tables(vec![]);
            let root = mem.frame();
            let page = mem.frame();
            // SAFETY: `page` is a fresh frame of PAGE bytes.
            unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len()) };
            ept::map(&mut mem, root, ENTRY as usize, page, GuestAccess::RX).unwrap();
            let s2 = Stage2Root { root: root as u64, aux: ept::LEVELS as u64 };
            Rig {
                host: Host::new(vcpus),
                m: M { cpu: Cpu::new(), k: ctls() },
                ctx: GuestCtx::new(s2, vmid, 0, ENTRY, DEVICE),
                _mem: mem,
                vmid,
            }
        }

        fn enter(&mut self) -> Exit {
            vcpu::enter(&mut self.m, &self.host, &mut self.ctx)
        }

        /// The vCPU's state image, after at least one entry.
        fn img(&self) -> &VcpuMem {
            // SAFETY: `frame[0]` is the address of the vCPU's `VcpuMem`, set on the first entry.
            unsafe { &*(self.ctx.frame[0] as *const VcpuMem) }
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            azos_arch::hv::vcpu::slots_release(&self.host, self.ctx.s2.root);
            let _ = self.vmid;
        }
    }

    fn exit_with(v: &mut Vmcs, reason: u32, q: u64, ilen: u64) {
        v.f.insert(field::EXIT_REASON, reason as u64);
        v.f.insert(field::EXIT_QUALIFICATION, q);
        v.f.insert(field::EXIT_INSN_LEN, ilen);
    }

    #[test]
    fn the_boot_cpu_starts_in_pvh_state_and_its_cpuid_is_answered_without_leaving() {
        let _g = serial();
        let mut r = Rig::new(1, &[0x0F, 0xA2, 0xF4]);
        r.m.cpu
            .then(|v, regs| {
                // First entry: the protocol's state, EBX = the start info (our DEVICE value here).
                assert_eq!(v.get(field::GUEST_RIP), ENTRY);
                assert_eq!(regs.g.rbx, DEVICE);
                assert_eq!(v.get(field::GUEST_CS_AR), 0xC09B);
                assert_eq!(v.get(field::EPT_POINTER) & 0x3F, 3 << 3 | 6, "4-level write-back");
                exit_with(v, reason::CPUID, 0, 2);
                true
            })
            .then(|v, regs| {
                // The service answered CPUID(0) and stepped past it, no exit to the monitor.
                assert_eq!(v.get(field::GUEST_RIP), ENTRY + 2);
                assert_ne!(regs.rax, 0, "CPUID leaf 0 has a maximum leaf");
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        assert_eq!(r.enter(), Exit::Wait);
        // Two entries, both launches of a freshly cleared VMCS, the VMCS cleared after each.
        assert_eq!(r.m.cpu.launched, vec![false, false]);
        let l = &r.m.cpu.log;
        assert_eq!(l.iter().filter(|s| s.starts_with("vmclear")).count(), 4, "before and after each entry: {l:?}");
        assert_eq!(l.last().unwrap(), "vmclear true", "inactive before the thread can move");
        // The first entry flushes (a start asks for it), with the VM's EPT root and VPID.
        let eptp = r.m.cpu.log.iter().find(|s| s.starts_with("invept")).unwrap().clone();
        assert!(eptp.starts_with("invept single 0x"), "{eptp}");
        assert!(r.m.cpu.log.contains(&format!("invvpid single {}", r.vmid)));
        // Only the first: the second entry has nothing stale to flush.
        assert_eq!(r.m.cpu.log.iter().filter(|s| s.starts_with("invept")).count(), 1);
    }

    #[test]
    fn a_device_access_in_the_ept_is_decoded_from_guest_memory_and_completed() {
        let _g = serial();
        // mov eax, [ebx] (32-bit protected mode); hlt.
        let mut r = Rig::new(1, &[0x8B, 0x03, 0xF4]);
        r.m.cpu
            .then(|v, _| {
                // A read of an unmapped page: EPT violation, final address, nothing present.
                exit_with(v, reason::EPT_VIOLATION, 1 | 1 << 7 | 1 << 8, 0);
                v.f.insert(field::GUEST_PHYS_ADDR, DEVICE);
                true
            })
            .then(|v, regs| {
                // The monitor's answer reached EAX and the guest is past the instruction.
                assert_eq!(regs.rax, 0xCAFE);
                assert_eq!(v.get(field::GUEST_RIP), ENTRY + 2);
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        let access = MmioAccess { gpa: DEVICE, size: 4, write: false, reg: 0, insn_len: 2 };
        assert_eq!(r.enter(), Exit::Mmio(access));
        r.ctx.completed = Some(MmioDone { access, value: 0xCAFE });
        assert_eq!(r.enter(), Exit::Wait);
    }

    #[test]
    fn a_device_access_in_a_larger_vm_is_decoded_from_the_bytes_the_entry_recorded() {
        let _g = serial();
        // SVM's decode assist hands the service the instruction; VMX has none, so the
        // entry reads the bytes itself: without them a VM of two vCPUs cannot
        // emulate a device access at all (the service reads memory only for one vCPU).
        // mov [ebx], eax (store EAX); hlt.
        let mut r = Rig::with_vcpus(1, 2, &[0x89, 0x03, 0xF4]);
        r.m.cpu
            .then(|v, regs| {
                regs.rax = 0x1122_3344;
                exit_with(v, reason::EPT_VIOLATION, 1 << 1 | 1 << 7 | 1 << 8, 0);
                v.f.insert(field::GUEST_PHYS_ADDR, DEVICE);
                true
            })
            .then(|v, _| {
                assert_eq!(v.get(field::GUEST_RIP), ENTRY + 2);
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        let access = MmioAccess { gpa: DEVICE, size: 4, write: true, reg: 0, insn_len: 2 };
        // The store's value is the register's, delivered with the exit.
        assert_eq!(r.enter(), Exit::Mmio(access));
        assert_eq!(r.ctx.mmio_value, 0x1122_3344);
        r.ctx.completed = Some(MmioDone { access, value: 0 });
        assert_eq!(r.enter(), Exit::Wait);
    }

    #[test]
    fn only_a_data_access_to_unmapped_memory_has_its_bytes_recorded() {
        let _g = serial();
        let mut r = Rig::with_vcpus(1, 2, &[0x89, 0x03, 0xF4]);
        let insn_len = |r: &Rig| r.img().vmcb.rd8(azos_arch::hv::mmio::OFF_INSN_LEN);
        r.m.cpu
            .then(|v, _| {
                // A permission fault on mapped memory: nothing to decode.
                exit_with(v, reason::EPT_VIOLATION, 1 << 1 | 1 << 3 | 1 << 5 | 1 << 7 | 1 << 8, 0);
                v.f.insert(field::GUEST_PHYS_ADDR, ENTRY);
                true
            })
            .then(|v, _| {
                // A fetch from unmapped memory.
                exit_with(v, reason::EPT_VIOLATION, 1 << 2 | 1 << 7 | 1 << 8, 0);
                v.f.insert(field::GUEST_PHYS_ADDR, DEVICE);
                true
            })
            .then(|v, _| {
                // The guest's own page-table walk faulted.
                exit_with(v, reason::EPT_VIOLATION, 1 << 1 | 1 << 7, 0);
                v.f.insert(field::GUEST_PHYS_ADDR, DEVICE);
                true
            });
        for _ in 0..3 {
            assert!(matches!(r.enter(), Exit::Fault { .. }));
            assert_eq!(insn_len(&r), 0);
        }
    }

    #[test]
    fn a_fault_on_mapped_memory_is_the_monitors() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        r.m.cpu.then(|v, _| {
            // A write to the read-only code page: present (readable and executable entry).
            exit_with(v, reason::EPT_VIOLATION, 1 << 1 | 1 << 3 | 1 << 5 | 1 << 7 | 1 << 8, 0);
            v.f.insert(field::GUEST_PHYS_ADDR, ENTRY);
            true
        });
        assert_eq!(r.enter(), Exit::Fault { gpa: ENTRY, access: azos_arch_api::StageAccess::Write });
    }

    #[test]
    fn a_port_nobody_serves_is_an_empty_bus() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xEC, 0xF4]);
        r.m.cpu
            .then(|v, _| {
                // `in al, dx` on port 0x3F8: size 1, IN.
                exit_with(v, reason::IO_INSTRUCTION, 1 << 3 | 0x3F8 << 16, 1);
                true
            })
            .then(|v, regs| {
                assert_eq!(v.get(field::GUEST_RIP), ENTRY + 1);
                assert_eq!(regs.rax & 0xFF, 0xFF, "an IN from nothing reads all ones");
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        assert_eq!(r.enter(), Exit::Wait);
    }

    #[test]
    fn an_interrupt_waits_for_the_window_then_goes_in() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        r.host.apic.lock().unwrap().pending = Some(0x41);
        r.m.cpu
            .then(|v, _| {
                // IF is clear in the PVH state: the vector cannot go in, the window is asked for.
                assert_eq!(v.get(field::ENTRY_INT_INFO), 0);
                assert_ne!(v.get(field::PROC_BASED) & vmx::bits::PROC_INTERRUPT_WINDOW as u64, 0);
                // The guest enables interrupts, and the window opens.
                v.f.insert(field::GUEST_RFLAGS, 0x202);
                exit_with(v, reason::INTERRUPT_WINDOW, 0, 0);
                true
            })
            .then(|v, _| {
                assert_eq!(v.get(field::ENTRY_INT_INFO), 1 << 31 | 0x41);
                assert_eq!(v.get(field::PROC_BASED) & vmx::bits::PROC_INTERRUPT_WINDOW as u64, 0, "withdrawn");
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        assert_eq!(r.enter(), Exit::Wait);
        assert_eq!(r.host.apic.lock().unwrap().acked, vec![0x41]);
        assert!(!r.img().vmcb.event_queued(), "the injected event went in with the entry");
    }

    #[test]
    fn an_exit_that_interrupts_event_delivery_does_not_lose_the_event() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        r.host.apic.lock().unwrap().pending = Some(0x50);
        r.m.cpu
            .then(|v, _| {
                v.f.insert(field::GUEST_RFLAGS, 0x202);
                exit_with(v, reason::INTERRUPT_WINDOW, 0, 0);
                true
            })
            .then(|v, _| {
                // The vector went in, and delivering it faulted in the EPT (the stack page).
                assert_eq!(v.get(field::ENTRY_INT_INFO), 1 << 31 | 0x50);
                v.f.insert(field::IDT_VECTORING_INFO, 1 << 31 | 0x50);
                exit_with(v, reason::EPT_VIOLATION, 1 << 1 | 1 << 7 | 1 << 8, 0);
                v.f.insert(field::GUEST_PHYS_ADDR, 0x7000);
                true
            });
        // A write to unmapped memory by an instruction that is not a store: the monitor gets the fault.
        assert_eq!(r.enter(), Exit::Fault { gpa: 0x7000, access: azos_arch_api::StageAccess::Write });
        // The event is queued for the next entry.
        assert_eq!(r.img().vmcb.rd32(off::EVENT_INJ), 1 << 31 | 0x50);
    }

    #[test]
    fn a_physical_nmi_is_run_by_the_host_and_an_interrupt_is_left_for_it() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        r.m.cpu
            .then(|v, _| {
                exit_with(v, reason::EXCEPTION_NMI, 0, 0);
                v.f.insert(field::EXIT_INT_INFO, 1 << 31 | 2 << 8 | 2);
                true
            })
            .then(|v, _| {
                exit_with(v, reason::EXTERNAL_INTERRUPT, 0, 0);
                true
            });
        assert_eq!(r.enter(), Exit::HostInterrupt);
        assert_eq!(r.m.cpu.log.iter().filter(|s| *s == "nmi").count(), 1);
        let n = r.m.cpu.log.iter().position(|s| s == "nmi").unwrap();
        assert_eq!(r.m.cpu.log[n - 1], "after_exit", "the descriptor tables are back before the handler runs");
        assert_eq!(r.enter(), Exit::HostInterrupt);
        assert_eq!(r.m.cpu.log.iter().filter(|s| *s == "nmi").count(), 1, "an external interrupt is not an NMI");
    }

    #[test]
    fn cr8_is_emulated_without_leaving_the_entry() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        r.m.cpu
            .then(|v, regs| {
                // mov cr8, rcx with rcx = 0x35: the vLAPIC's task priority class is the low four bits.
                regs.g.rcx = 0x35;
                v.f.insert(field::GUEST_RIP, ENTRY + 0x10);
                exit_with(v, reason::CR_ACCESS, 8 | 1 << 8, 3);
                true
            })
            .then(|v, regs| {
                // Still the same VMCS, resumed past the instruction; now mov rdx, cr8.
                assert_eq!(v.get(field::GUEST_RIP), ENTRY + 0x13);
                assert_eq!(regs.g.rdx, 0);
                exit_with(v, reason::CR_ACCESS, 8 | 1 << 4 | 2 << 8, 3);
                true
            })
            .then(|v, regs| {
                assert_eq!(v.get(field::GUEST_RIP), ENTRY + 0x16);
                assert_eq!(regs.g.rdx, 5);
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        assert_eq!(r.enter(), Exit::Wait);
        assert_eq!(r.m.cpu.launched, vec![false, true, true], "one VMLAUNCH, then VMRESUME on the same VMCS");
        assert_eq!(r.m.cpu.log.iter().filter(|s| s.starts_with("vmptrld")).count(), 1);
    }

    #[test]
    fn a_cr_access_nothing_serves_ends_the_vcpu_visibly() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        // mov cr0, rax clearing a forced bit: control register 0, MOV to CR.
        r.m.cpu.then(|v, _| {
            exit_with(v, reason::CR_ACCESS, 0, 3);
            true
        });
        assert_eq!(r.enter(), Exit::Other(vmx::OTHER_BASE + reason::CR_ACCESS as u64));
    }

    #[test]
    fn a_refusal_by_the_cpu_is_an_invalid_state_and_leaves_the_vmcs_clear() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        r.m.cpu.then(|_, _| false);
        assert_eq!(r.enter(), Exit::InvalidState);
        assert_eq!(r.m.cpu.log.last().unwrap(), "vmclear true");
        // The entry failure with an exit reason (invalid guest state) is the same.
        let mut r = Rig::new(1, &[0xF4]);
        r.m.cpu.then(|v, _| {
            exit_with(v, reason::INVALID_GUEST_STATE | reason::ENTRY_FAILURE, 2, 0);
            true
        });
        assert_eq!(r.enter(), Exit::InvalidState);
        // A VMCS that cannot be made current: nothing runs.
        let mut r = Rig::new(1, &[0xF4]);
        r.m.cpu.refuse_load = true;
        assert_eq!(r.enter(), Exit::InvalidState);
        assert!(r.m.cpu.launched.is_empty());
        assert_eq!(r.m.cpu.log.last().unwrap(), "vmclear true");
    }

    #[test]
    fn the_ept_is_invalidated_only_when_the_tables_change() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        for _ in 0..3 {
            r.m.cpu.then(|v, _| {
                exit_with(v, reason::EXTERNAL_INTERRUPT, 0, 0);
                true
            });
        }
        let count = |r: &Rig| r.m.cpu.log.iter().filter(|s| s.starts_with("invept")).count();
        assert_eq!(r.enter(), Exit::HostInterrupt);
        assert_eq!(count(&r), 1, "the start");
        assert_eq!(r.enter(), Exit::HostInterrupt);
        assert_eq!(count(&r), 1, "nothing changed");
        // The monitor unmapped a page: the epoch moves, the next entry invalidates.
        vcpu::flush(r.vmid, usize::MAX, &mut |_| {});
        assert_eq!(r.enter(), Exit::HostInterrupt);
        assert_eq!(count(&r), 2);
        assert_eq!(r.m.cpu.log.iter().filter(|s| s.starts_with("invvpid")).count(), 2);
    }

    #[test]
    fn the_syscall_msrs_cr2_and_the_registers_round_trip_through_an_entry() {
        let _g = serial();
        let mut r = Rig::new(1, &[0xF4]);
        // The CPU stores the guest's listed MSRs at the exit; here the guest changed two.
        r.m.cpu.hook(|x| {
            x.guest[4].value = 0x55;
            x.guest[1].value = 0xFFFF_8000_0000_0100;
        });
        r.m.cpu
            .then(|v, regs| {
                regs.g.r12 = 0x1212;
                regs.rax = 0xAAAA;
                v.f.insert(field::GUEST_FS_BASE, 0x2000);
                exit_with(v, reason::EXTERNAL_INTERRUPT, 0, 0);
                true
            })
            .then(|v, regs| {
                assert_eq!((regs.g.r12, regs.rax), (0x1212, 0xAAAA), "the registers survive the exit and the next entry");
                exit_with(v, reason::HLT, 0, 1);
                true
            });
        assert_eq!(r.enter(), Exit::HostInterrupt);
        let img = &r.img().vmcb;
        assert_eq!(img.rd64(off::KERNEL_GS_BASE), 0x55);
        assert_eq!(img.rd64(off::LSTAR), 0xFFFF_8000_0000_0100);
        assert_eq!(img.segment(off::FS).3, 0x2000);
        assert_eq!(img.rd64(off::RAX), 0xAAAA);
        // The guest's CR2 (the image's, zero) went in, the host's came back.
        let l = &r.m.cpu.log;
        let enter = l.iter().position(|s| s == "enter false").unwrap();
        assert!(l[..enter].contains(&"cr2=0x0".to_string()));
        assert_eq!(l[l.len() - 2], "cr2=0xc0de", "{l:?}");
        // The next entry loads what the exit stored, and the host's values for the exit.
        assert_eq!(r.enter(), Exit::Wait);
        let (guest, host) = r.m.cpu.lists[1];
        assert_eq!(guest.map(|e| e.index), [0xC000_0081, 0xC000_0082, 0xC000_0083, 0xC000_0084, 0xC000_0102]);
        assert_eq!(guest[4].value, 0x55);
        assert_eq!(guest[1].value, 0xFFFF_8000_0000_0100);
        assert_eq!(host.map(|e| e.index), guest.map(|e| e.index));
        assert_eq!(host[0].value, 0xAA00_0000_0000 | 0xC000_0081);
    }
}
