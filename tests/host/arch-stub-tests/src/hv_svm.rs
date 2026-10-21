// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 hypervisor primitives (`crates/core/arch-x86_64/src/ext/hv`),
//! checked on the host against independent oracles: the AMD APM / Linux
//! `svm.h` offsets and exit codes, and the kernel's own x86 PTE builder.
//!
//! A wrong constant here is a silent `VMEXIT_INVALID` on hardware, with no
//! message: each property below has a number from the manual, not one
//! computed by the code under test. The AMD half (`svm`, `npt`) and the
//! probe of both vendors (`probe_tests`); the Intel half is probe-only.

use azos_arch::hv::probe::{self, Choice, Kind, Status};
use azos_arch::mmu::TableMem;
use std::collections::HashMap;

/// Table memory for the walker tests: frames numbered from 0x1000 up.
#[derive(Default)]
struct Mem {
    words: HashMap<(usize, usize), u64>,
    next: usize,
}

impl Mem {
    fn new() -> Self {
        Mem { words: HashMap::new(), next: 0x10_0000 }
    }
    fn root(&mut self) -> usize {
        self.alloc_table().unwrap()
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
        let t = self.next;
        self.next += 0x1000;
        Some(t)
    }
}

mod svm {
    use azos_arch::hv::exit::{self, Exit, IoAccess, NestedFault};
    use azos_arch::hv::svm::*;
    use azos_arch::trap::gdt;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn vmcb_offsets_are_the_apms() {
        // AMD APM vol. 2 appendix B / Linux arch/x86/include/asm/svm.h.
        let table: &[(&str, usize, usize)] = &[
            ("intercept cr", off::INTERCEPT_CR, 0x00),
            ("intercept dr", off::INTERCEPT_DR, 0x04),
            ("intercept exceptions", off::INTERCEPT_EXCEPTIONS, 0x08),
            ("intercept word 3", off::INTERCEPT_W3, 0x0C),
            ("intercept word 4", off::INTERCEPT_W4, 0x10),
            ("pause filter count", off::PAUSE_FILTER_COUNT, 0x3E),
            ("iopm", off::IOPM_BASE_PA, 0x40),
            ("msrpm", off::MSRPM_BASE_PA, 0x48),
            ("tsc offset", off::TSC_OFFSET, 0x50),
            ("asid", off::GUEST_ASID, 0x58),
            ("tlb ctl", off::TLB_CTL, 0x5C),
            ("int ctl", off::INT_CTL, 0x60),
            ("exit code", off::EXIT_CODE, 0x70),
            ("exit info 1", off::EXIT_INFO_1, 0x78),
            ("exit info 2", off::EXIT_INFO_2, 0x80),
            ("exit int info", off::EXIT_INT_INFO, 0x88),
            ("nested ctl", off::NESTED_CTL, 0x90),
            ("event inj", off::EVENT_INJ, 0xA8),
            ("nested cr3", off::NESTED_CR3, 0xB0),
            ("clean", off::CLEAN, 0xC0),
            ("next rip", off::NEXT_RIP, 0xC8),
            ("es", off::ES, 0x400),
            ("cs", off::CS, 0x410),
            ("ss", off::SS, 0x420),
            ("ds", off::DS, 0x430),
            ("fs", off::FS, 0x440),
            ("gs", off::GS, 0x450),
            ("gdtr", off::GDTR, 0x460),
            ("ldtr", off::LDTR, 0x470),
            ("idtr", off::IDTR, 0x480),
            ("tr", off::TR, 0x490),
            ("cpl", off::CPL, 0x4CB),
            ("efer", off::EFER, 0x4D0),
            ("cr4", off::CR4, 0x548),
            ("cr3", off::CR3, 0x550),
            ("cr0", off::CR0, 0x558),
            ("dr7", off::DR7, 0x560),
            ("dr6", off::DR6, 0x568),
            ("rflags", off::RFLAGS, 0x570),
            ("rip", off::RIP, 0x578),
            ("rsp", off::RSP, 0x5D8),
            ("rax", off::RAX, 0x5F8),
            ("star", off::STAR, 0x600),
            ("kernel gs base", off::KERNEL_GS_BASE, 0x620),
            ("cr2", off::CR2, 0x640),
            ("g_pat", off::G_PAT, 0x668),
        ];
        for (name, got, want) in table {
            assert_eq!(got, want, "{name}");
        }
        assert_eq!((size_of::<Vmcb>(), align_of::<Vmcb>()), (4096, 4096), "one page, page-aligned");
    }

    #[test]
    fn intercept_bits_and_exit_codes_are_the_apms() {
        assert_eq!((icpt::INTR, icpt::NMI, icpt::CPUID, icpt::HLT), (1, 2, 1 << 18, 1 << 24));
        assert_eq!((icpt::IOIO_PROT, icpt::MSR_PROT, icpt::SHUTDOWN), (1 << 27, 1 << 28, 1 << 31));
        assert_eq!((icpt::VMRUN, icpt::VMMCALL, icpt::VMLOAD, icpt::VMSAVE), (1, 2, 4, 8));
        assert_eq!((icpt::STGI, icpt::CLGI, icpt::WBINVD), (16, 32, 1 << 9));
        assert_eq!((icpt::SMI, icpt::INIT, icpt::INVD), (1 << 2, 1 << 3, 1 << 22));
        assert_eq!((code::SMI, code::INIT, code::INVD, code::WBINVD), (0x62, 0x63, 0x76, 0x89));
        assert_eq!((code::INTR, code::CPUID, code::HLT, code::IOIO, code::MSR), (0x60, 0x72, 0x78, 0x7B, 0x7C));
        assert_eq!((code::SHUTDOWN, code::VMRUN, code::VMMCALL, code::NPF), (0x7F, 0x80, 0x81, 0x400));
        assert_eq!(code::INVALID, u64::MAX);
        assert_eq!(ctl::V_INTR_MASKING, 1 << 24);
    }

    #[test]
    fn guest_regs_offsets_are_what_the_run_stub_uses() {
        // hw.rs's azos_svm_run indexes by these numbers.
        let want = [
            (offset_of!(GuestRegs, rbx), 0), (offset_of!(GuestRegs, rcx), 8),
            (offset_of!(GuestRegs, rdx), 16), (offset_of!(GuestRegs, rsi), 24),
            (offset_of!(GuestRegs, rdi), 32), (offset_of!(GuestRegs, rbp), 40),
            (offset_of!(GuestRegs, r8), 48), (offset_of!(GuestRegs, r9), 56),
            (offset_of!(GuestRegs, r10), 64), (offset_of!(GuestRegs, r11), 72),
            (offset_of!(GuestRegs, r12), 80), (offset_of!(GuestRegs, r13), 88),
            (offset_of!(GuestRegs, r14), 96), (offset_of!(GuestRegs, r15), 104),
        ];
        for (got, w) in want {
            assert_eq!(got, w);
        }
        assert_eq!(size_of::<GuestRegs>(), 112);
    }

    #[test]
    fn fields_are_little_endian_at_their_offset_and_touch_nothing_else() {
        let mut v = Vmcb::new();
        v.wr64(off::RIP, 0x1122_3344_5566_7788);
        assert_eq!(&v.as_bytes()[off::RIP..off::RIP + 8], &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
        assert_eq!(v.rd32(off::RIP), 0x5566_7788);
        assert_eq!(v.rd16(off::RIP + 2), 0x5566);
        let others = v.as_bytes().iter().enumerate().filter(|&(i, b)| *b != 0 && !(off::RIP..off::RIP + 8).contains(&i)).count();
        assert_eq!(others, 0, "a write spilled outside its field");
        v.wr32(off::GUEST_ASID, 7);
        v.or32(off::INTERCEPT_W3, icpt::HLT);
        v.or32(off::INTERCEPT_W3, icpt::CPUID);
        assert_eq!(v.rd32(off::INTERCEPT_W3), icpt::HLT | icpt::CPUID, "or32 keeps what was there");
    }

    #[test]
    fn a_segment_is_selector_attrib_limit_base() {
        let mut v = Vmcb::new();
        v.set_segment(off::CS, 0x1234, 0x0A9B, 0xFFFF_FFFF, 0xFFFF_8000_0000_0000);
        assert_eq!(&v.as_bytes()[off::CS..off::CS + 16],
            &[0x34, 0x12, 0x9B, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0x80, 0xFF, 0xFF]);
        assert_eq!(v.segment(off::CS), (0x1234, 0x0A9B, 0xFFFF_FFFF, 0xFFFF_8000_0000_0000));
    }

    #[test]
    fn attributes_pack_the_access_byte_and_the_flags_nibble() {
        // The kernel's own GDT descriptors, run through the VMCB packing.
        assert_eq!(attrib_from_descriptor(gdt::segment(true, 0)), 0x0A9B, "kernel code64: P, S, code, L, G");
        assert_eq!(attrib_from_descriptor(gdt::segment(false, 0)), 0x0C93, "kernel data: P, S, data, D/B, G");
        assert_eq!(attrib_from_descriptor(gdt::segment(false, 3)), 0x0CF3, "user data: DPL 3");
        assert_eq!(attrib_from_descriptor(gdt::segment(true, 3)), 0x0AFB, "user code64: DPL 3");
        // Bits the packing must not leak: limit 19:16 (descriptor bits 51:48).
        assert_eq!(attrib_from_descriptor(0x000F_0000_0000_0000), 0);
        assert_eq!(attrib_from_descriptor(0x0100_0000_0000_0000), 0, "base 31:24 is not an attribute");
    }

    fn good() -> Vmcb {
        let mut v = Vmcb::new();
        v.init_real_mode(0x1000, 1);
        v.enable_nested_paging(0x20_0000);
        v.set_iopm(0x10_0000);
        v.set_msrpm(0x10_4000);
        v
    }

    /// The ASID count of the CPU the host tests pretend to run on.
    const NASID: u32 = 8;

    #[test]
    fn a_real_mode_guest_passes_the_vmrun_checks_and_has_the_reset_state() {
        let v = good();
        assert_eq!(v.check(NASID), Ok(()));
        assert_eq!(v.rd64(off::RIP), 0x1000);
        assert_eq!(v.rd64(off::EFER), efer::SVME);
        assert_eq!(v.rd64(off::NESTED_CTL), 1);
        assert_eq!(v.rd64(off::NESTED_CR3), 0x20_0000);
        assert_eq!(v.rd32(off::GUEST_ASID), 1);
        assert_eq!(v.segment(off::CS), (0, 0x9B, 0xFFFF, 0));
        assert_eq!(v.segment(off::DS), (0, 0x93, 0xFFFF, 0));
        assert_ne!(v.rd32(off::INTERCEPT_W4) & icpt::VMRUN, 0, "VMRUN intercept");
        assert_ne!(v.rd32(off::INTERCEPT_W3) & icpt::INTR, 0, "physical interrupts exit");
        let (w3, w4) = (v.rd32(off::INTERCEPT_W3), v.rd32(off::INTERCEPT_W4));
        for (bit, what) in [(icpt::IOIO_PROT, "I/O ports"), (icpt::MSR_PROT, "MSRs"), (icpt::INVD, "INVD"),
                            (icpt::SMI, "SMI"), (icpt::INIT, "INIT")] {
            assert_ne!(w3 & bit, 0, "{what} exit by default");
        }
        assert_ne!(w4 & icpt::WBINVD, 0, "WBINVD exits by default");
        assert_ne!(v.rd32(off::INT_CTL) & ctl::V_INTR_MASKING, 0, "the host's IF masks physical interrupts");
        assert_eq!(v.rd64(off::RFLAGS) & 2, 2, "RFLAGS bit 1");
    }

    #[test]
    fn each_vmrun_check_has_its_own_verdict() {
        let mut v = good();
        v.wr64(off::EFER, 0);
        assert_eq!(v.check(NASID), Err(Invalid::GuestEferSvme));

        let mut v = good();
        v.wr32(off::INTERCEPT_W4, 0);
        assert_eq!(v.check(NASID), Err(Invalid::NoVmrunIntercept));

        let mut v = good();
        v.wr32(off::GUEST_ASID, 0);
        assert_eq!(v.check(NASID), Err(Invalid::AsidZero));

        let mut v = good();
        v.wr64(off::CR0, cr0::NW);
        assert_eq!(v.check(NASID), Err(Invalid::Cr0CdNw), "NW without CD");
        v.wr64(off::CR0, cr0::NW | cr0::CD);
        assert_eq!(v.check(NASID), Ok(()), "NW with CD is legal");

        let mut v = good();
        v.wr64(off::CR0, 1 << 32);
        assert_eq!(v.check(NASID), Err(Invalid::Cr0High));

        let mut v = good();
        v.wr64(off::EFER, efer::SVME | efer::LME);
        v.wr64(off::CR0, cr0::PG | cr0::PE);
        assert_eq!(v.check(NASID), Err(Invalid::LongModeWithoutPae));
        v.wr64(off::CR4, cr4::PAE);
        assert_eq!(v.check(NASID), Ok(()));

        let mut v = good();
        v.wr64(off::EFER, efer::SVME | efer::LMA);
        assert_eq!(v.check(NASID), Err(Invalid::EferReserved), "LMA without LME");
        v.wr64(off::EFER, efer::SVME | 1 << 40);
        assert_eq!(v.check(NASID), Err(Invalid::EferReserved), "a reserved bit");

        let mut v = good();
        v.wr64(off::DR7, 1 << 40);
        assert_eq!(v.check(NASID), Err(Invalid::DrHigh));

        let mut v = good();
        v.wr32(off::GUEST_ASID, NASID);
        assert_eq!(v.check(NASID), Err(Invalid::AsidAboveCount), "ASID == the count");
        v.wr32(off::GUEST_ASID, NASID - 1);
        assert_eq!(v.check(NASID), Ok(()), "the last ASID is legal");
        v.wr32(off::GUEST_ASID, 1);
        assert_eq!(v.check(1), Err(Invalid::AsidAboveCount), "a CPU with one ASID has none for a guest");

        let mut v = good();
        v.set_iopm(0);
        assert_eq!(v.check(NASID), Err(Invalid::BadPermissionMap), "unset map");
        v.set_iopm(0x3000);
        assert_eq!(v.check(NASID), Ok(()));
        v.set_msrpm(0x3800);
        assert_eq!(v.check(NASID), Err(Invalid::BadPermissionMap), "unaligned map");

        // Policy: a guest without the I/O or MSR intercept owns the host's ports
        // and MSRs, so the VMCB is refused however good the maps look.
        for bit in [icpt::IOIO_PROT, icpt::MSR_PROT] {
            let mut v = good();
            v.wr32(off::INTERCEPT_W3, v.rd32(off::INTERCEPT_W3) & !bit);
            assert_eq!(v.check(NASID), Err(Invalid::NoProtIntercepts), "intercept {bit:#x} cleared");
        }
        // A fresh guest has the intercepts but not the maps: the unset map is
        // the verdict, never a silent pass-through.
        let mut v = Vmcb::new();
        v.init_real_mode(0x1000, 1);
        assert_eq!(v.check(NASID), Err(Invalid::BadPermissionMap), "init_real_mode alone is not runnable");

        let mut v = good();
        v.wr64(off::NESTED_CR3, 0x20_0800);
        assert_eq!(v.check(NASID), Err(Invalid::BadNestedCr3));
    }

    #[test]
    fn io_exits_decode_port_direction_size_and_next_rip() {
        // OUT dx, al to port 0x3F8: TYPE 0, SZ8.
        let out8 = exit::svm(code::IOIO, 0x3F8 << 16 | 1 << 4, 0x1005);
        assert_eq!(out8, Exit::Io(IoAccess { port: 0x3F8, write: true, size: 1, string: false, rep: false, next_rip: 0x1005 }));
        // REP INSD from port 0x1F0: TYPE 1, STR, REP, SZ32.
        let ins32 = exit::svm(code::IOIO, 0x1F0 << 16 | 1 | 1 << 2 | 1 << 3 | 1 << 6, 0x2000);
        assert_eq!(ins32, Exit::Io(IoAccess { port: 0x1F0, write: false, size: 4, string: true, rep: true, next_rip: 0x2000 }));
        // OUT dx, ax: SZ16.
        let Exit::Io(a) = exit::svm(code::IOIO, 0x80 << 16 | 1 << 5, 0) else { panic!() };
        assert_eq!((a.port, a.size, a.write), (0x80, 2, true));
    }

    #[test]
    fn nested_faults_decode_the_gpa_and_the_access() {
        // A write to an absent page: W set, P clear, final translation.
        let e = exit::svm(code::NPF, 1 << 1 | 1 << 32, 0x5000);
        assert_eq!(e, Exit::NestedFault(NestedFault { gpa: 0x5000, write: true, exec: false, present: false, final_translation: true }));
        // A fetch from a present non-executable page: ID and P set.
        let e = exit::svm(code::NPF, 1 | 1 << 4 | 1 << 32, 0x6000);
        assert_eq!(e, Exit::NestedFault(NestedFault { gpa: 0x6000, write: false, exec: true, present: true, final_translation: true }));
        // A fault in the guest's own page-table walk: bit 33, not 32.
        let Exit::NestedFault(f) = exit::svm(code::NPF, 1 << 33, 0x7000) else { panic!() };
        assert!(!f.final_translation);
    }

    #[test]
    fn the_other_exits_decode() {
        assert_eq!(exit::svm(code::HLT, 0, 0), Exit::Halt);
        assert_eq!(exit::svm(code::CPUID, 0, 0), Exit::Cpuid);
        assert_eq!(exit::svm(code::MSR, 0, 0), Exit::Msr { write: false });
        assert_eq!(exit::svm(code::MSR, 1, 0), Exit::Msr { write: true });
        assert_eq!(exit::svm(code::INTR, 0, 0), Exit::Interrupt);
        assert_eq!(exit::svm(code::NMI, 0, 0), Exit::Nmi);
        assert_eq!(exit::svm(code::VMMCALL, 0, 0), Exit::Hypercall);
        assert_eq!(exit::svm(code::SHUTDOWN, 0, 0), Exit::Shutdown);
        assert_eq!(exit::svm(code::INVALID, 0, 0), Exit::InvalidState);
        // The policy intercepts have no dedicated exit: the monitor kills the guest.
        for c in [code::SMI, code::INIT, code::INVD, code::WBINVD] {
            assert_eq!(exit::svm(c, 0, 0), Exit::Other(c));
        }
        assert_eq!(exit::svm(0x7A, 0, 0), Exit::Other(0x7A));
    }
}

mod npt {
    use super::Mem;
    use azos_arch::hv::npt::*;
    use azos_arch::mmu::{self, TableMem, WalkError, G, NX, P, PS, RW, US};

    const LEVELS: usize = 4;

    /// Every table entry and leaf reachable from `root`, as `(level, word)`.
    fn all_entries(mem: &Mem, root: usize) -> Vec<(usize, u64)> {
        fn walk(mem: &Mem, table: usize, level: usize, out: &mut Vec<(usize, u64)>) {
            for i in 0..512 {
                let w = mem.read(table, i);
                if w == 0 {
                    continue;
                }
                out.push((level, w));
                if mmu::is_table(w, level) {
                    walk(mem, mmu::phys_addr(w), level - 1, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(mem, root, LEVELS - 1, &mut out);
        out
    }

    #[test]
    fn every_entry_at_every_level_is_user_accessible() {
        let mut mem = Mem::new();
        let root = mem.root();
        for i in 0..3 {
            map(&mut mem, root, LEVELS, 0x1000 + i * 0x1000, 0x40_0000 + i * 0x1000, 0, GuestAccess::RW, false).unwrap();
        }
        map(&mut mem, root, LEVELS, 0x20_0000, 0x80_0000, 1, GuestAccess::RX, false).unwrap();
        let entries = all_entries(&mem, root);
        // PML4, PDPT and PD pointers, three 4 KiB leaves and one 2 MiB leaf.
        assert_eq!(entries.len(), 3 + 3 + 1, "{entries:x?}");
        for (level, w) in entries {
            assert_ne!(w & US, 0, "level {level} entry {w:#x} lacks U/S: the nested walk would fault");
            assert_ne!(w & P, 0);
            assert_eq!(w & G, 0, "an NPT entry is not a kernel mapping");
        }
    }

    #[test]
    fn leaves_are_the_x86_builders_with_user_set() {
        let mut mem = Mem::new();
        let root = mem.root();
        map(&mut mem, root, LEVELS, 0x1000, 0x40_0000, 0, GuestAccess::RW, false).unwrap();
        map(&mut mem, root, LEVELS, 0x2000, 0x40_1000, 0, GuestAccess::RX, false).unwrap();
        let word = |gpa| mmu::translate(&mem, root, LEVELS, gpa).unwrap().word;
        assert_eq!(word(0x1000) & (RW | NX | US), RW | NX | US, "data: writable, never executable");
        assert_eq!(word(0x2000) & (RW | NX | US), US, "code: executable, not writable");
        // Same word as the host builder with the user flag: no private encoding.
        let host = mmu::make_leaf_with(0x40_0000, leaf_perms(GuestAccess::RW), 0, false).unwrap();
        assert_eq!(host, word(0x1000));
    }

    #[test]
    fn translation_follows_the_map_and_offsets_within_the_page() {
        let mut mem = Mem::new();
        let root = mem.root();
        map(&mut mem, root, LEVELS, 0x1000, 0x40_0000, 0, GuestAccess::RW, false).unwrap();
        map(&mut mem, root, LEVELS, 0x2000, 0x40_1000, 0, GuestAccess::RW, false).unwrap();
        let tr = |gpa| mmu::translate(&mem, root, LEVELS, gpa).map(|l| l.phys);
        assert_eq!(tr(0x1234), Some(0x40_0234));
        assert_eq!(tr(0x2FFF), Some(0x40_1FFF));
        assert_eq!(tr(0x3000), None);
        assert_eq!(tr(0x0), None);
    }

    #[test]
    fn large_leaves_and_the_one_gig_capability() {
        let mut mem = Mem::new();
        let root = mem.root();
        map(&mut mem, root, LEVELS, 0x20_0000, 0x60_0000, 1, GuestAccess::RW, false).unwrap();
        let w = mmu::translate(&mem, root, LEVELS, 0x20_0000).unwrap();
        assert_eq!((w.level, w.phys), (1, 0x60_0000));
        assert_ne!(w.word & PS, 0);
        assert_eq!(mmu::translate(&mem, root, LEVELS, 0x2F_FFFF).map(|l| l.phys), Some(0x6F_FFFF));
        // 1 GiB only when the CPU has it.
        assert!(map(&mut mem, root, LEVELS, 0x4000_0000, 0x4000_0000, 2, GuestAccess::RW, false).is_err());
        map(&mut mem, root, LEVELS, 0x4000_0000, 0x4000_0000, 2, GuestAccess::RW, true).unwrap();
        // A misaligned 2 MiB request is refused, not rounded.
        assert_eq!(map(&mut mem, root, LEVELS, 0x20_1000, 0x80_0000, 1, GuestAccess::RW, false), Err(WalkError::Misaligned));
    }

    #[test]
    fn remapping_is_refused() {
        let mut mem = Mem::new();
        let root = mem.root();
        map(&mut mem, root, LEVELS, 0x1000, 0x40_0000, 0, GuestAccess::RW, false).unwrap();
        assert_eq!(map(&mut mem, root, LEVELS, 0x1000, 0x50_0000, 0, GuestAccess::RW, false), Err(WalkError::AlreadyMapped));
        assert_eq!(mmu::translate(&mem, root, LEVELS, 0x1000).map(|l| l.phys), Some(0x40_0000), "the first mapping stands");
    }

    #[test]
    fn five_level_hosts_build_five_level_nested_tables() {
        let mut mem = Mem::new();
        let root = mem.root();
        map(&mut mem, root, 5, 0x1000, 0x40_0000, 0, GuestAccess::RW, false).unwrap();
        assert_eq!(mmu::translate(&mem, root, 5, 0x1000).map(|l| l.phys), Some(0x40_0000));
        let depth = all_entries_depth(&mem, root, 5);
        assert_eq!(depth, 5, "PML5, PML4, PDPT, PD, PT");
    }

    fn all_entries_depth(mem: &Mem, root: usize, levels: usize) -> usize {
        let mut table = root;
        let mut depth = 0;
        for level in (0..levels).rev() {
            let w = mem.read(table, mmu::vpn(0x1000, level));
            assert_ne!(w, 0);
            depth += 1;
            if level == 0 { break; }
            table = mmu::phys_addr(w);
        }
        depth
    }
}

mod probe_tests {
    use super::*;
    use azos_arch::cpu::features::CpuidLeaves;
    use azos_arch::hv::probe::*;

    const SVM_LEAF: (u32, u32, u32) = (1, 64, 1 | 1 << 3 | 1 << 5 | 1 << 6 | 1 << 7);

    fn amd() -> CpuidLeaves {
        CpuidLeaves { e1_ecx: CPUID_E1_ECX_SVM, ..CpuidLeaves::default() }
    }
    fn intel() -> CpuidLeaves {
        CpuidLeaves { l1_ecx: CPUID_L1_ECX_VMX, ..CpuidLeaves::default() }
    }

    #[test]
    fn msr_numbers_are_the_manuals() {
        assert_eq!((MSR_VM_CR, MSR_VM_HSAVE_PA), (0xC001_0114, 0xC001_0117));
        assert_eq!((VM_CR_LOCK, VM_CR_SVMDIS, EFER_SVME), (1 << 3, 1 << 4, 1 << 12));
        assert_eq!(MSR_IA32_FEATURE_CONTROL, 0x3A);
        assert_eq!((FC_LOCK, FC_VMXON_INSIDE_SMX, FC_VMXON_OUTSIDE_SMX), (1, 2, 4));
        assert_eq!([MSR_VMX_BASIC, MSR_VMX_PROCBASED_CTLS], [0x480, 0x482]);
        assert_eq!([MSR_VMX_PROCBASED_CTLS2, MSR_VMX_EPT_VPID_CAP], [0x48B, 0x48C]);
        assert_eq!((CPUID_E1_ECX_SVM, CPUID_L1_ECX_VMX), (1 << 2, 1 << 5));
    }

    #[test]
    fn the_svm_leaf_decodes_its_feature_bits() {
        let c = decode_svm_leaf(0x01, 0x8000, 1 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 10 | 1 << 16);
        assert_eq!((c.revision, c.nasid), (1, 0x8000));
        assert!(c.npt && c.svm_lock && c.nrips && c.vmcb_clean && c.flush_by_asid && c.decode_assists && c.pause_filter && c.vgif);
        let n = decode_svm_leaf(0, 0, 0);
        assert!(!n.npt && !n.nrips && !n.vmcb_clean && !n.flush_by_asid && !n.decode_assists && !n.svm_lock);
        // One bit at a time lands on one field: no neighbour reads another's bit.
        assert!(decode_svm_leaf(0, 0, 1 << 3).nrips && !decode_svm_leaf(0, 0, 1 << 3).vmcb_clean);
        assert!(decode_svm_leaf(0, 0, 1 << 5).vmcb_clean && !decode_svm_leaf(0, 0, 1 << 5).flush_by_asid);
    }

    #[test]
    fn svm_is_usable_only_with_cpuid_firmware_and_nested_paging() {
        let rd = |m| { assert_eq!(m, MSR_VM_CR, "only VM_CR is read for SVM"); 0 };
        let p = probe_with(true, true, &amd(), SVM_LEAF, rd);
        assert_eq!(p.svm, Status::Usable);
        assert_eq!(p.vmx, Status::Absent);
        assert_eq!(p.choice(), Choice { kind: Kind::Svm, why: Status::Usable });

        // Firmware set SVMDIS (with or without the lock): disabled, with a reason.
        for cr in [VM_CR_SVMDIS, VM_CR_SVMDIS | VM_CR_LOCK] {
            let p = probe_with(true, true, &amd(), SVM_LEAF, |_| cr);
            assert_eq!(p.svm, Status::FirmwareDisabled, "VM_CR {cr:#x}");
            assert_eq!(p.choice(), Choice { kind: Kind::None, why: Status::FirmwareDisabled });
        }
        // The lock alone is not a refusal.
        assert_eq!(probe_with(true, true, &amd(), SVM_LEAF, |_| VM_CR_LOCK).svm, Status::Usable);

        // No nested paging, or a single ASID (the host's): no guest can run.
        assert_eq!(probe_with(true, true, &amd(), (1, 64, 0), |_| 0).svm, Status::NoNestedPaging);
        assert_eq!(probe_with(true, true, &amd(), (1, 1, 1), |_| 0).svm, Status::NoNestedPaging);
    }

    #[test]
    fn no_msr_is_read_on_a_cpu_that_lacks_the_extension_or_when_the_choice_is_n() {
        let never = |m| -> u64 { panic!("rdmsr({m:#x}) on a CPU without the extension would #GP") };
        let p = probe_with(true, true, &CpuidLeaves::default(), SVM_LEAF, never);
        assert_eq!((p.svm, p.vmx), (Status::Absent, Status::Absent));
        assert_eq!(p.choice(), Choice { kind: Kind::None, why: Status::Absent });
        // `n`: not touched even where present.
        let p = probe_with(false, false, &amd(), SVM_LEAF, never);
        assert_eq!((p.svm, p.vmx), (Status::Off, Status::Off));
        let p = probe_with(false, false, &intel(), SVM_LEAF, never);
        assert_eq!((p.svm, p.vmx), (Status::Off, Status::Off));
        assert_eq!(p.choice(), Choice { kind: Kind::None, why: Status::Off });
        // SVM `n` with an AMD CPU never reads VM_CR; VMX stays independent.
        let p = probe_with(false, true, &amd(), SVM_LEAF, never);
        assert_eq!((p.svm, p.vmx), (Status::Off, Status::Absent));
    }

    /// An Intel part: write-back VMCS, secondary controls with EPT and
    /// unrestricted guest, 4-level write-back EPT with 2M and 1G.
    fn vmx_msrs(fc: u64) -> impl FnMut(u32) -> u64 {
        move |m| match m {
            MSR_IA32_FEATURE_CONTROL => fc,
            MSR_VMX_BASIC => 0x1234 | 0x1000 << 32 | 6 << 50 | 1 << 55,
            MSR_VMX_PROCBASED_CTLS => 1 << 63,
            MSR_VMX_PROCBASED_CTLS2 => 1 << 33 | 1 << 39,
            MSR_VMX_EPT_VPID_CAP => 1 << 6 | 1 << 14 | 1 << 16 | 1 << 17 | 1 << 20 | 1 << 21,
            other => panic!("unexpected rdmsr {other:#x}"),
        }
    }

    #[test]
    fn vmx_follows_feature_control_and_needs_ept() {
        // Firmware locked it off: the BIOS setting. VIRT none, with the reason.
        let p = probe_with(true, true, &intel(), (0, 0, 0), vmx_msrs(FC_LOCK));
        assert_eq!(p.vmx, Status::FirmwareDisabled);
        assert_eq!(p.choice(), Choice { kind: Kind::None, why: Status::FirmwareDisabled });
        // Locked with VMXON outside SMX: on. Unlocked: the OS may set and lock.
        for fc in [FC_LOCK | FC_VMXON_OUTSIDE_SMX, 0, FC_VMXON_OUTSIDE_SMX] {
            let p = probe_with(true, true, &intel(), (0, 0, 0), vmx_msrs(fc));
            assert_eq!(p.vmx, Status::Usable, "FEATURE_CONTROL {fc:#x}");
            assert_eq!(p.choice().kind, Kind::Vmx);
        }
        // Locked with only the inside-SMX bit is still off for an OS without TXT.
        let p = probe_with(true, true, &intel(), (0, 0, 0), vmx_msrs(FC_LOCK | FC_VMXON_INSIDE_SMX));
        assert_eq!(p.vmx, Status::FirmwareDisabled);

        assert!(feature_control_allows(0) && !feature_control_allows(FC_LOCK));
        let c = probe_with(true, true, &intel(), (0, 0, 0), vmx_msrs(0)).vmx_caps;
        assert_eq!(c.revision, 0x1234);
        assert!(c.wb_vmcs && c.secondary && c.ept && c.unrestricted_guest);
        assert!(c.ept_4level && c.ept_wb && c.ept_2m && c.ept_1g && c.invept);
    }

    #[test]
    fn vmx_without_ept_or_the_walk_we_build_is_not_usable() {
        let base = vmx_msrs(0);
        // No secondary controls: no EPT, and the EPT MSRs are never read.
        let no_secondary = |m| if m == MSR_VMX_PROCBASED_CTLS { 0 } else { base_for(m) };
        fn base_for(m: u32) -> u64 { vmx_msrs(0)(m) }
        let _ = base;
        let p = probe_with(true, true, &intel(), (0, 0, 0), no_secondary);
        assert_eq!(p.vmx, Status::NoNestedPaging);
        // EPT but no write-back / 4-level walk.
        let weak = |m| if m == MSR_VMX_EPT_VPID_CAP { 1 << 6 } else { base_for(m) };
        assert_eq!(probe_with(true, true, &intel(), (0, 0, 0), weak).vmx, Status::NoNestedPaging);
        let weak = |m| if m == MSR_VMX_EPT_VPID_CAP { 1 << 14 } else { base_for(m) };
        assert_eq!(probe_with(true, true, &intel(), (0, 0, 0), weak).vmx, Status::NoNestedPaging);
    }

    #[test]
    fn the_refusal_reported_is_the_most_informative() {
        use Status::*;
        let c = |s, v| choose(s, v);
        assert_eq!(c(Usable, FirmwareDisabled).kind, Kind::Svm);
        assert_eq!(c(Absent, Usable).kind, Kind::Vmx);
        assert_eq!(c(FirmwareDisabled, Absent).why, FirmwareDisabled, "an AMD CPU with SVM off is not 'VMX absent'");
        assert_eq!(c(Absent, FirmwareDisabled).why, FirmwareDisabled);
        assert_eq!(c(NoNestedPaging, Absent).why, NoNestedPaging);
        assert_eq!(c(Off, Absent).why, Absent);
        assert_eq!(c(Off, Off).why, Off);
        assert_eq!(c(Absent, Absent).kind, Kind::None);
    }

    #[test]
    fn the_record_round_trips_every_verdict() {
        assert_eq!(record(), Choice { kind: Kind::None, why: Status::Off }, "before the probe ran");
        for c in [
            Choice { kind: Kind::Svm, why: Status::Usable },
            Choice { kind: Kind::Vmx, why: Status::Usable },
            Choice { kind: Kind::None, why: Status::FirmwareDisabled },
            Choice { kind: Kind::None, why: Status::NoNestedPaging },
            Choice { kind: Kind::None, why: Status::Absent },
        ] {
            record_set(c);
            assert_eq!(record(), c);
        }
        assert_eq!((Kind::None.name(), Kind::Svm.name(), Kind::Vmx.name()), ("none", "svm", "vmx"));
        assert_eq!(Status::FirmwareDisabled.name(), "disabled by firmware");
    }

    #[test]
    fn the_host_stub_reads_nothing_present() {
        // Off bare-metal x86_64 the CPUID words are zero: nothing to probe.
        let p = probe::probe(true, true);
        assert_eq!(p.choice(), Choice { kind: Kind::None, why: Status::Absent });
    }
}
