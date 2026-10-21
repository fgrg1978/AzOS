// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! An AzOS guest on x86_64 under SVM: the state its vCPUs start in, what its
//! `CPUID` and MSR accesses get, the INIT / startup-IPI sequence that brings
//! up the other vCPUs, and the delivery of the vLAPIC timer and the
//! IOAPIC-routed device interrupts.
//!
//! The pieces under test are `azos_arch_x86_64::hv::{entry, cpuid, msr,
//! inject, serve}` (the VMCB side) and `azos_hv::{vlapic, vioapic}` (the APIC
//! models), joined here by the one adapter ([`Port`]) the monitor's end will
//! also be. WHY: a wrong bit in a guest's start state or in a CPUID word is
//! a guest that dies in its first instructions or that takes a path nobody
//! tested, with no message; no guest runs on this ISA before the guest-boot
//! step (QEMU `-cpu ...,+svm`), so these are the only check until then.
//!
//! The expected values come from the manuals (AMD APM vol. 2 and 3, Intel SDM
//! vol. 2 CPUID, the Xen PVH protocol) and from what AzOS's own boot reads
//! (`boot.S`, `timer.rs`, `fp.rs`), written out by hand. The "hosts" are
//! shaped like an AMD Zen 3 and an Intel Ice Lake: their words are modelled
//! on those CPUs' feature sets, so the filter is checked against more than
//! one vendor's layout.

use azos_arch_x86_64::hv::apic::{ApicEvent, Gp, LocalApic};
use azos_arch_x86_64::hv::cpuid::{self, Guest, Leaf};
use azos_arch_x86_64::hv::entry::{Power, Start};
use azos_arch_x86_64::hv::exit::{self, Exit};
use azos_arch_x86_64::hv::mmio::{self, Extend, GuestMem, Insn, Mode};
use azos_arch_x86_64::hv::msr;
use azos_arch_x86_64::hv::serve::{Entry, Env, Served, VcpuState};
use azos_arch_x86_64::hv::svm::{code, ctl, efer, icpt, off, GuestRegs, Vmcb, MSRPM_BYTES};
use azos_arch_api::MmioAccess;
use azos_hv::vioapic::{deliver_effect, pulse_lines, Vioapic, IOAPIC_DEFAULT_BASE, IOAPIC_WINDOW};
use azos_hv::vlapic::{timer_clock, Event, Mode as ApicMode, Vlapic, APIC_DEFAULT_BASE, APIC_PAGE, MSR_APIC_BASE, MSR_TSC_DEADLINE};

// ── the hosts ───────────────────────────────────────────────────────────

fn leaf(eax: u32, ebx: u32, ecx: u32, edx: u32) -> Leaf {
    Leaf { eax, ebx, ecx, edx }
}

/// An AMD Zen 3-shaped host: SVM, MONITOR, MTRR, MCE, RDTSCP, PKU, RDPID,
/// SEV leaves, XSAVE with AVX and PKRU, no AVX-512.
pub(crate) fn zen3(l: u32, s: u32) -> Leaf {
    match (l, s) {
        (0, _) => leaf(0x10, 0x6874_7541, 0x444D_4163, 0x6974_6E65),
        (1, _) => leaf(0x00A0_0F11, 0x0010_0800, 0x7EF8_320B, 0x178B_FBFF),
        (5, _) => leaf(0x40, 0x40, 0x3, 0x11),
        (6, _) => leaf(0x4, 0, 0x1, 0),
        (7, 0) => leaf(0, 0x219C_97A9, 0x0040_061C | 1 << 9 | 1 << 10, 0),
        (0xB, _) => leaf(1, 2, 0x100 | s, 0),
        (0xD, 0) => leaf(0x207, 0x340, 0x380, 0),
        (0xD, 1) => leaf(0xF, 0x340, 0, 0),
        (0xD, 2) => leaf(0x100, 0x240, 0, 0),
        (0xD, 9) => leaf(0x8, 0x980, 0x1, 0),
        (0x8000_0000, _) => leaf(0x8000_0023, 0, 0, 0),
        (0x8000_0001, _) => leaf(0x00A0_0F11, 0, 0x75C2_37FF, 0x2FD3_FBFF),
        (0x8000_0002, _) => leaf(0x2044_4D41, 0x5859_4543, 0x3535_3720, 0x2033_5420),
        (0x8000_0007, _) => leaf(0, 0x3, 0, 0x6799),
        (0x8000_0008, _) => leaf(0x3030, 0x791E_F257, 0x400F, 0x1_0000),
        (0x8000_000A, _) => leaf(1, 0x8000, 0, 0x119B_9CFF),
        (0x8000_001F, _) => leaf(0x1, 0x1_00B3, 0x1F, 0),
        _ => Leaf::ZERO,
    }
}

/// An Intel Ice Lake-shaped host: VMX, SMX, MTRR, AVX-512 with PKRU, CET,
/// LA57, RDPID, TSC_ADJUST, the speculation-control word, leaf 0x15/0x16.
fn icelake(l: u32, s: u32) -> Leaf {
    match (l, s) {
        (0, _) => leaf(0x1B, 0x756E_6547, 0x6C65_746E, 0x4965_6E69),
        (1, _) => leaf(0x000606A6, 0x0010_0800, 0x7FFE_FBFF, 0xBFEB_FBFF),
        (7, 0) => leaf(
            2,
            // FSGSBASE TSC_ADJUST SGX BMI1 AVX2 FDP_EXCPTN SMEP BMI2 ERMS INVPCID AVX512F DQ RDSEED ADX SMAP
            // IFMA PT CLFLUSHOPT CLWB CD SHA BW VL
            1 | 1 << 1 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 16 | 1 << 17
                | 1 << 18 | 1 << 19 | 1 << 20 | 1 << 21 | 1 << 25 | 1 << 23 | 1 << 24 | 1 << 28 | 1 << 29 | 1 << 30 | 1 << 31,
            // VBMI UMIP PKU OSPKE VBMI2 CET_SS GFNI VAES VPCLMULQDQ VNNI BITALG VPOPCNTDQ LA57 RDPID
            1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 6 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 14
                | 1 << 16 | 1 << 22,
            // IBRS STIBP L1D_FLUSH ARCH_CAPABILITIES CORE_CAPABILITIES SSBD
            1 << 26 | 1 << 27 | 1 << 28 | 1 << 29 | 1 << 30 | 1 << 31,
        ),
        (7, 2) => leaf(0, 0, 0, 0x7),
        (0xB, _) => leaf(1, 2, 0x100 | s, 0),
        (0xD, 0) => leaf(0x2E7, 0xA88, 0xA88, 0),
        (0xD, 1) => leaf(0xF, 0xA88, 0x1800, 0),
        (0xD, 2) => leaf(0x100, 0x240, 0, 0),
        (0xD, 5) => leaf(0x40, 0x440, 0, 0),
        (0xD, 6) => leaf(0x200, 0x480, 0, 0),
        (0xD, 7) => leaf(0x400, 0x680, 0, 0),
        (0xD, 9) => leaf(0x8, 0xA80, 0x1, 0),
        (0x15, _) => leaf(2, 0xB4, 25_000_000, 0),
        (0x16, _) => leaf(2000, 3500, 100, 0),
        (0x8000_0000, _) => leaf(0x8000_0008, 0, 0, 0),
        (0x8000_0001, _) => leaf(0, 0, 0x121, 0x2C10_0800),
        (0x8000_0007, _) => leaf(0, 0, 0, 0x100),
        (0x8000_0008, _) => leaf(0x3027, 0, 0, 0),
        _ => Leaf::ZERO,
    }
}

pub(crate) const TSC_KHZ: u32 = 2_995_200;
pub(crate) const APIC_KHZ: u32 = 100_000;

fn guest(vcpu: u32, vcpus: u32) -> Guest {
    Guest { vcpu, vcpus, tsc_khz: TSC_KHZ, apic_khz: APIC_KHZ, xcr0: 1, osxsave: false }
}

fn ask(host: &dyn Fn(u32, u32) -> Leaf, g: &Guest, l: u32, s: u32) -> Leaf {
    cpuid::answer(host, g, l, s)
}

// ── CPUID ───────────────────────────────────────────────────────────────

#[test]
fn cpuid_tells_the_guest_it_runs_under_a_hypervisor_and_names_it() {
    for host in [&zen3 as &dyn Fn(u32, u32) -> Leaf, &icelake] {
        let g = guest(0, 1);
        assert_ne!(ask(host, &g, 1, 0).ecx & 1 << 31, 0, "CPUID.1:ECX[31], the bit timer.rs tests");
        let h = ask(host, &g, 0x4000_0000, 0);
        assert_eq!(h.eax, 0x4000_0010, "max hypervisor leaf: timer.rs needs 0x40000010");
        let sig = [h.ebx.to_le_bytes(), h.ecx.to_le_bytes(), h.edx.to_le_bytes()].concat();
        assert_eq!(&sig, b"AzOSAzOSAzOS");
        // The TSC rate in kHz in EAX; the vLAPIC timer clock in EBX.
        let t = ask(host, &g, 0x4000_0010, 0);
        assert_eq!((t.eax, t.ebx, t.ecx, t.edx), (TSC_KHZ, APIC_KHZ, 0, 0));
        // Nothing else in the range.
        for l in 0x4000_0001..=0x4000_000F {
            assert_eq!(ask(host, &g, l, 0), Leaf::ZERO, "leaf {l:#x}");
        }
        assert_eq!(ask(host, &g, 0x4000_0011, 0), Leaf::ZERO);
    }
}

#[test]
fn the_tsc_is_trusted_only_as_far_as_the_host_says_it_is_invariant() {
    // timer.rs `calibrate`: leaf 0x40000010 only counts with CPUID.80000007:EDX[8].
    for (host, invariant) in [(&zen3 as &dyn Fn(u32, u32) -> Leaf, true), (&icelake, true)] {
        let e7 = ask(host, &guest(0, 1), 0x8000_0007, 0);
        assert_eq!(e7.edx, if invariant { 1 << 8 } else { 0 });
        assert_eq!((e7.eax, e7.ebx, e7.ecx), (0, 0, 0), "no power-management or RAS word");
    }
    // A host without the bit gives the guest none: it measures its TSC itself.
    let no_inv = |l: u32, s: u32| if l == 0x8000_0007 { leaf(0, 0, 0, 0x99) } else { zen3(l, s) };
    assert_eq!(ask(&no_inv, &guest(0, 1), 0x8000_0007, 0).edx, 0);
}

#[test]
fn cpuid_keeps_what_the_boot_checks_for_each_baseline_level() {
    // boot.S, the X86_64_LEVEL ladder, bit masks as the assembly writes them.
    for (name, host) in [("zen3", &zen3 as &dyn Fn(u32, u32) -> Leaf), ("icelake", &icelake)] {
        let g = guest(0, 1);
        let l1 = ask(host, &g, 1, 0);
        let l7 = ask(host, &g, 7, 0);
        let e1 = ask(host, &g, 0x8000_0001, 0);
        // v2: SSE3 SSSE3 CX16 SSE4.1 SSE4.2 POPCNT, LAHF/SAHF.
        assert_eq!(l1.ecx & 0x0098_2201, 0x0098_2201, "{name} v2 ecx");
        assert_ne!(e1.ecx & 1, 0, "{name} LAHF");
        // v3: FMA MOVBE XSAVE AVX F16C; BMI1 AVX2 BMI2; LZCNT.
        assert_eq!(l1.ecx & 0x3440_1000, 0x3440_1000, "{name} v3 ecx");
        assert_eq!(l7.ebx & 0x0000_0128, 0x0000_0128, "{name} v3 ebx");
        assert_ne!(e1.ecx & 0x20, 0, "{name} LZCNT");
        // x2APIC and the TSC deadline timer: the vLAPIC serves both.
        assert_eq!(l1.ecx & (1 << 21 | 1 << 24), 1 << 21 | 1 << 24, "{name} x2APIC, TSC-deadline");
        // PAT, the page-attribute table mmu.rs programs; CMPXCHG8B, FXSR, SSE2, APIC.
        for b in [16, 8, 24, 26, 9, 5, 4, 0] {
            assert_ne!(l1.edx & 1 << b, 0, "{name} CPUID.1:EDX[{b}]");
        }
        // Long mode, NX, SYSCALL, 1 GiB pages.
        for b in [29, 20, 11, 26] {
            assert_ne!(e1.edx & 1 << b, 0, "{name} CPUID.80000001:EDX[{b}]");
        }
    }
    // v4: AVX512 F DQ CD BW VL (Ice Lake only).
    let l7 = ask(&icelake, &guest(0, 1), 7, 0);
    assert_eq!(l7.ebx & 0xD003_0000, 0xD003_0000);
}

#[test]
fn cpuid_hides_what_the_guest_must_not_use() {
    for (name, host) in [("zen3", &zen3 as &dyn Fn(u32, u32) -> Leaf), ("icelake", &icelake)] {
        let g = guest(0, 1);
        let l1 = ask(host, &g, 1, 0);
        // Intel: VMX 5, SMX 6, EIST 7, TM2 8, DS-CPL 4, xTPR 14, PDCM 15, DCA 18, SDBG 11.
        // AMD and Intel: MONITOR 3.
        for b in [3, 4, 5, 6, 7, 8, 11, 14, 15, 18] {
            assert_eq!(l1.ecx & 1 << b, 0, "{name} CPUID.1:ECX[{b}] hidden");
        }
        // MCE 7, MTRR 12, MCA 14, PSN 18, DS 21, ACPI 22, SS 27, TM 29, PBE 31.
        for b in [7, 12, 14, 18, 21, 22, 27, 29, 31] {
            assert_eq!(l1.edx & 1 << b, 0, "{name} CPUID.1:EDX[{b}] hidden");
        }
        // One vCPU: no HTT.
        assert_eq!(l1.edx & 1 << 28, 0);
        let e1 = ask(host, &g, 0x8000_0001, 0);
        // AMD: SVM 2, EXTAPIC 3, OSVW 9, IBS 10, SKINIT 12, WDT 13, TOPOEXT 22, PERFCTR 23/24, MWAITX 29.
        for b in [2, 3, 9, 10, 12, 13, 22, 23, 24, 29] {
            assert_eq!(e1.ecx & 1 << b, 0, "{name} CPUID.80000001:ECX[{b}] hidden");
        }
        // RDTSCP 27 (TSC_AUX is not in the VMCB), FFXSR 25, MTRR 12, MCE 7, MCA 14.
        for b in [7, 12, 14, 25, 27] {
            assert_eq!(e1.edx & 1 << b, 0, "{name} CPUID.80000001:EDX[{b}] hidden");
        }
        let l7 = ask(host, &g, 7, 0);
        // TSC_ADJUST 1, SGX 2, HLE 4, RTM 11, MPX 14, PT 25, FDP_EXCPTN_ONLY 6.
        for b in [1, 2, 4, 6, 11, 14, 25] {
            assert_eq!(l7.ebx & 1 << b, 0, "{name} CPUID.7:EBX[{b}] hidden");
        }
        // PKU 3, OSPKE 4, CET_SS 7, LA57 16, RDPID 22.
        for b in [3, 4, 7, 16, 22] {
            assert_eq!(l7.ecx & 1 << b, 0, "{name} CPUID.7:ECX[{b}] hidden");
        }
        // The whole speculation-control word, and no sub-leaf 1 or 2.
        assert_eq!(l7.edx, 0, "{name} no IBRS / ARCH_CAPABILITIES / CORE_CAPABILITIES");
        assert_eq!(l7.eax, 0, "{name} no sub-leaf past 0");
        assert_eq!(ask(host, &g, 7, 1), Leaf::ZERO);
        assert_eq!(ask(host, &g, 7, 2), Leaf::ZERO);
        // MONITOR/MWAIT parameters, thermal and power, performance counters, cache parameters.
        for l in [2, 3, 4, 5, 6, 9, 0xA] {
            assert_eq!(ask(host, &g, l, 0), Leaf::ZERO, "{name} leaf {l:#x}");
        }
        // Nested virtualization, SEV, the extended topology of AMD.
        for l in [0x8000_000A, 0x8000_001E, 0x8000_001F, 0x8000_0021] {
            assert_eq!(ask(host, &g, l, 0), Leaf::ZERO, "{name} leaf {l:#x}");
        }
        // 0x15 and 0x16 are above the highest basic leaf: the guest takes its
        // TSC rate from the hypervisor leaf.
        let max = ask(host, &g, 0, 0).eax;
        assert_eq!(max, 0xD);
        assert_eq!(ask(host, &g, 0x15, 0), Leaf::ZERO);
        assert_eq!(ask(host, &g, 0x16, 0), Leaf::ZERO);
        assert_eq!(ask(host, &g, 0x8000_0000, 0).eax, 0x8000_0008);
    }
}

#[test]
fn the_guest_sees_the_hosts_vendor_signature_and_brand() {
    let g = guest(0, 1);
    let z = ask(&zen3, &g, 0, 0);
    assert_eq!((z.ebx, z.ecx, z.edx), (0x6874_7541, 0x444D_4163, 0x6974_6E65), "AuthenticAMD");
    let i = ask(&icelake, &g, 0, 0);
    assert_eq!((i.ebx, i.edx, i.ecx), (0x756E_6547, 0x4965_6E69, 0x6C65_746E), "GenuineIntel");
    assert_eq!(ask(&zen3, &g, 0x8000_0002, 0), zen3(0x8000_0002, 0));
    assert_eq!(ask(&zen3, &g, 1, 0).eax, 0x00A0_0F11, "the family / model / stepping the host has");
}

#[test]
fn each_vcpu_has_its_own_apic_id_and_the_topology_is_flat() {
    for v in 0..4u32 {
        let g = guest(v, 4);
        let l1 = ask(&zen3, &g, 1, 0);
        assert_eq!(l1.ebx >> 24, v, "initial APIC ID");
        assert_eq!(l1.ebx >> 16 & 0xFF, 4, "logical processors");
        assert_ne!(l1.edx & 1 << 28, 0, "HTT: the count above is valid");
        assert_eq!(l1.ebx & 0xFFFF, 0x0800, "brand index and CLFLUSH line as the host");
        // Leaf 0xB: level 0 is one thread (SMT), level 1 is `vcpus` cores.
        let t0 = ask(&zen3, &g, 0xB, 0);
        assert_eq!((t0.eax, t0.ebx, t0.ecx, t0.edx), (0, 1, 1 << 8, v));
        let t1 = ask(&zen3, &g, 0xB, 1);
        assert_eq!((t1.eax, t1.ebx, t1.ecx, t1.edx), (2, 4, 1 | 2 << 8, v), "2 bits name 4 cores");
        let t2 = ask(&zen3, &g, 0xB, 2);
        assert_eq!((t2.eax, t2.ebx, t2.ecx, t2.edx), (0, 0, 2, v), "no level 2: type 0, level number echoed");
        assert_eq!(ask(&zen3, &g, 0x8000_0008, 0).ecx & 0xFF, 3, "AMD: threads - 1");
    }
    // The shift is ceil(log2(n)).
    for (n, bits) in [(1, 0), (2, 1), (3, 2), (4, 2), (5, 3), (8, 3), (9, 4)] {
        assert_eq!(ask(&zen3, &guest(0, n), 0xB, 1).eax, bits, "{n} vCPUs");
    }
}

#[test]
fn the_physical_address_width_leaves_room_in_the_nested_tables() {
    let g = guest(0, 1);
    // Zen 3 reports 48; the nested tables are 47 bits wide: the guest sees 46.
    assert_eq!(ask(&zen3, &g, 0x8000_0008, 0).eax, 46 | 48 << 8);
    // A host with fewer bits keeps them; linear width is 48 (no LA57).
    assert_eq!(ask(&icelake, &g, 0x8000_0008, 0).eax, 0x27 | 48 << 8);
}

#[test]
fn osxsave_follows_the_guests_cr4_and_leaf_d_follows_its_xcr0() {
    let mut g = guest(0, 1);
    assert_eq!(ask(&icelake, &g, 1, 0).ecx & 1 << 27, 0, "CR4.OSXSAVE clear");
    g.osxsave = true;
    assert_ne!(ask(&icelake, &g, 1, 0).ecx & 1 << 27, 0, "CR4.OSXSAVE set");
    // Supported components: x87 SSE AVX and the three AVX-512 ones; PKRU (bit 9) is not offered.
    let d0 = ask(&icelake, &g, 0xD, 0);
    assert_eq!(d0.eax, 0xE7);
    assert_eq!(d0.ecx, 0xA80, "the area for everything offered: up to the end of Hi16_ZMM (0x680 + 0x400)");
    // EBX is the area for what the guest has enabled in XCR0.
    for (xcr0, bytes) in [(1, 576), (3, 576), (7, 0x340), (0xE7, 0xA80)] {
        g.xcr0 = xcr0;
        assert_eq!(ask(&icelake, &g, 0xD, 0).ebx, bytes, "XCR0 = {xcr0:#x}");
    }
    // The host's PKRU is not the guest's: Zen 3 has AVX and PKRU, the guest gets AVX.
    let z = ask(&zen3, &g, 0xD, 0);
    assert_eq!((z.eax, z.ecx), (0x7, 0x340));
    // Sub-leaf 1: XSAVEOPT only (bit 0): no XSAVEC (1), XGETBV(1) (2), XSAVES (3).
    assert_eq!(ask(&icelake, &g, 0xD, 1), leaf(1, 0, 0, 0));
    // Offered components carry the host's size and offset; PKRU (9) and unknown ones read zero.
    assert_eq!(ask(&icelake, &g, 0xD, 2), leaf(0x100, 0x240, 0, 0));
    assert_eq!(ask(&icelake, &g, 0xD, 6), leaf(0x200, 0x480, 0, 0));
    assert_eq!(ask(&icelake, &g, 0xD, 9), Leaf::ZERO);
    assert_eq!(ask(&icelake, &g, 0xD, 3), Leaf::ZERO, "MPX is not offered");
    assert_eq!(ask(&zen3, &g, 0xD, 5), Leaf::ZERO, "Zen 3 has no opmask state");
}

#[test]
fn xcr0_writes_are_checked_against_the_rules_of_the_manual() {
    // SDM vol. 1 13.3: x87 always, AVX needs SSE, AVX-512 is all three components and needs AVX.
    let ok = |host: &dyn Fn(u32, u32) -> Leaf, v: u64| cpuid::xcr0_valid(host, v);
    assert!(ok(&icelake, 1) && ok(&icelake, 3) && ok(&icelake, 7) && ok(&icelake, 0xE7));
    assert!(!ok(&icelake, 0), "x87 cannot be disabled");
    assert!(!ok(&icelake, 2), "SSE without x87");
    assert!(!ok(&icelake, 5), "AVX without SSE");
    assert!(!ok(&icelake, 0x67), "ZMM_Hi256 without the other two AVX-512 components");
    assert!(!ok(&icelake, 0xE3), "AVX-512 without AVX");
    assert!(!ok(&icelake, 0x207), "PKRU is not offered");
    assert!(!ok(&icelake, 1 << 17), "AMX is not offered");
    // The host decides what exists: Zen 3 has no AVX-512.
    assert!(ok(&zen3, 7));
    assert!(!ok(&zen3, 0xE7));
}

// ── a guest vCPU's state ────────────────────────────────────────────────

const NASID: u32 = 8;
const IOPM: u64 = 0x10_0000;
const MSRPM: u64 = 0x14_0000;
const NCR3: u64 = 0x20_0000;

/// A VMCB with the parts only the caller sets, as the entry path does.
fn wired(mut v: Vmcb) -> Vmcb {
    v.set_iopm(IOPM);
    v.set_msrpm(MSRPM);
    v.enable_nested_paging(NCR3);
    v
}

fn pvh() -> (Vmcb, GuestRegs) {
    let mut v = Vmcb::new();
    let mut r = GuestRegs { rbx: 0xDEAD, rcx: 0xBEEF, r15: 7, ..GuestRegs::default() };
    v.init_pvh(&mut r, 0x0100_0000, 0x7000, 1).unwrap();
    (wired(v), r)
}

#[test]
fn the_boot_cpu_starts_the_way_the_pvh_protocol_says() {
    let (v, r) = pvh();
    // Xen PVH: 32-bit protected mode, paging off, flat 4 GiB segments, EBX = start_info, EFLAGS.IF clear.
    assert_eq!(v.rd64(off::CR0), 0x11, "PE and the reset ET bit; PG, CD, NW clear");
    assert_eq!(v.rd64(off::CR4), 0);
    assert_eq!(v.rd64(off::CR3), 0);
    assert_eq!(v.rd64(off::EFER), efer::SVME, "no LME: the guest enables long mode itself");
    assert_eq!(v.rd64(off::RIP), 0x0100_0000);
    assert_eq!(v.rd64(off::RFLAGS), 2, "IF clear, VM clear, bit 1");
    assert_eq!(r.rbx, 0x7000, "EBX = hvm_start_info");
    assert_eq!((r.rcx, r.r15, r.rdx), (0, 0, 0), "the rest of the registers are cleared");
    // Segment attributes in the VMCB format: access byte | flags nibble << 8.
    // Code: P S type 0xB (execute/read, accessed) = 0x9B, D/B and G = 0xC.
    assert_eq!(v.segment(off::CS), (0x10, 0xC9B, 0xFFFF_FFFF, 0));
    for seg in [off::DS, off::ES, off::SS, off::FS, off::GS] {
        // Data: P S type 3 (read/write, accessed) = 0x93, D/B and G = 0xC.
        assert_eq!(v.segment(seg), (0x18, 0xC93, 0xFFFF_FFFF, 0));
    }
    assert_eq!(v.segment(off::TR), (0x20, 0x8B, 0x67, 0), "a busy 32-bit TSS");
    assert_eq!(v.rd8(off::CPL), 0);
    // No interrupt queued, no shadow, the window closed, translations flushed.
    assert_eq!((v.rd32(off::EVENT_INJ), v.rd32(off::INT_STATE)), (0, 0));
    assert_eq!(v.rd32(off::INT_CTL), ctl::V_INTR_MASKING);
    assert_eq!(v.rd32(off::INTERCEPT_W3) & icpt::VINTR, 0);
    assert_eq!(v.rd32(off::TLB_CTL), ctl::TLB_FLUSH_ALL as u32);
    // It passes what VMRUN checks and the intercepts the guest needs.
    assert_eq!(v.check(NASID), Ok(()));
    let (w3, w4) = (v.rd32(off::INTERCEPT_W3), v.rd32(off::INTERCEPT_W4));
    assert_ne!(w3 & icpt::HLT, 0, "an idle guest sleeps the vCPU thread, not the CPU");
    for (bit, what) in [(icpt::XSETBV, "XSETBV"), (icpt::MONITOR, "MONITOR"), (icpt::MWAIT, "MWAIT"),
                        (icpt::RDTSCP, "RDTSCP"), (icpt::SKINIT, "SKINIT")] {
        assert_ne!(w4 & bit, 0, "{what} exits");
    }
}

#[test]
fn a_pvh_entry_that_does_not_fit_32_bits_is_refused() {
    let mut v = Vmcb::new();
    let mut r = GuestRegs::default();
    assert!(v.init_pvh(&mut r, 1 << 32, 0x7000, 1).is_err());
    assert!(v.init_pvh(&mut r, 0x100000, 1 << 32, 1).is_err());
    assert!(v.init_pvh(&mut r, 0xFFFF_FFFF, 0xFFFF_F000, 1).is_ok(), "the top of the 32-bit space is fine");
}

#[test]
fn a_started_ap_is_in_real_mode_at_vector_times_4096() {
    let mut v = wired(Vmcb::new());
    let mut r = GuestRegs { rbx: 5, ..GuestRegs::default() };
    v.init_startup(&mut r, 0x9A, 3, 0x00A0_0F11);
    // Intel SDM vol. 3 8.4.3 / the INIT-SIPI protocol: CS.selector = vector << 8, CS.base = vector << 12, IP = 0.
    assert_eq!(v.segment(off::CS), (0x9A00, 0x9B, 0xFFFF, 0x9A000));
    assert_eq!(v.rd64(off::RIP), 0);
    assert_eq!(v.rd64(off::CR0), 0x10, "real mode");
    assert_eq!(v.rd64(off::RFLAGS), 2);
    assert_eq!(v.rd32(off::GUEST_ASID), 3);
    assert_eq!(v.rd64(off::EFER), efer::SVME);
    assert_eq!((r.rdx, r.rbx), (0x00A0_0F11, 0), "EDX = the CPU signature after reset, the rest 0");
    assert_eq!(v.segment(off::DS), (0, 0x93, 0xFFFF, 0), "data segments flat at 0");
    assert_eq!(v.check(NASID), Ok(()));
}

#[test]
fn an_init_leaves_no_trace_of_the_life_before() {
    let (mut v, mut r) = pvh();
    // The guest got to a state worth forgetting: paging, a queued event, a shadow, a window.
    v.wr64(off::CR3, 0x1000);
    v.wr64(off::CR4, 1 << 5);
    v.wr64(off::CR2, 0x55);
    v.wr64(off::EFER, efer::SVME | efer::LME | efer::LMA);
    v.inject_interrupt(0x41);
    v.wr32(off::INT_STATE, 1);
    v.request_window();
    v.wr32(off::EXIT_INT_INFO, 1 << 31 | 0x20);
    r.rcx = 1;
    v.init_startup(&mut r, 0, 1, 0x600);
    assert_eq!((v.rd64(off::CR3), v.rd64(off::CR4), v.rd64(off::CR2)), (0, 0, 0));
    assert_eq!(v.rd64(off::EFER), efer::SVME);
    assert_eq!((v.rd32(off::EVENT_INJ), v.rd32(off::INT_STATE), v.rd32(off::EXIT_INT_INFO)), (0, 0, 0));
    assert!(!v.window_requested());
    assert_eq!(v.rd32(off::INTERCEPT_W3) & icpt::VINTR, 0);
    assert_eq!(v.check(NASID), Ok(()));
    // Intercepts, maps and nested paging are the caller's and stay.
    assert_eq!(v.rd64(off::NESTED_CR3), NCR3);
    assert_eq!(v.rd64(off::IOPM_BASE_PA), IOPM);
}

#[test]
fn init_then_startup_starts_a_cpu_once() {
    let mut p = Power::WaitSipi;
    // A SIPI before any INIT of a CPU that was never started still starts it
    // (the first life of an AP is the wait state), and the second does not.
    assert_eq!(p.sipi(0x9A), Start::Run(0x9A));
    assert_eq!(p.sipi(0x9A), Start::Nothing, "the second SIPI of the sequence finds it running");
    assert_eq!(p, Power::Running);
    // An INIT sends even a running CPU back to waiting.
    assert_eq!(p.init(), Start::Reset);
    assert_eq!(p, Power::WaitSipi);
    assert_eq!(p.init(), Start::Reset, "a second INIT is the same");
    assert_eq!(p.sipi(0x10), Start::Run(0x10));
}

// ── the MSR permission map and the MSRs ─────────────────────────────────

fn msrpm() -> [u8; MSRPM_BYTES] {
    let mut pm = [0u8; MSRPM_BYTES];
    msr::build_msrpm(&mut pm);
    pm
}

#[test]
fn the_msr_map_is_laid_out_as_the_manual_says() {
    let pm = msrpm();
    // AMD APM vol. 2 15.11: 2 bits per MSR (read, then write); 0x0000_0000 at byte 0, 0xC000_0000 at 0x800,
    // 0xC001_0000 at 0x1000. EFER 0xC0000080: bit 0x100 of the second range = byte 0x800 + 0x20, bit 0.
    assert!(msr::intercepted(&pm, msr::MSR_EFER, false) && msr::intercepted(&pm, msr::MSR_EFER, true));
    assert_eq!(pm[0x820] & 0b11, 0b11);
    // LSTAR 0xC0000082: bit 0x104: byte 0x820, bit 4.
    assert_eq!(pm[0x820] >> 4 & 0b11, 0, "LSTAR passes through both ways");
    // SYSENTER_CS 0x174: bit 0x2E8 of the first range = byte 0x5D, bit 0.
    assert_eq!(pm[0x5D] & 0b11, 0);
    // A byte nothing passes through is all ones.
    assert_eq!(pm[0x5C], 0xFF);
    // The spare bytes after the third range stay set.
    assert!(pm[0x1800..].iter().all(|&b| b == 0xFF));
    // An MSR outside the three ranges is always intercepted.
    assert!(msr::intercepted(&pm, 0x4000_0000, false));
    assert!(msr::intercepted(&pm, 0xC002_0000, true));
}

#[test]
fn only_what_the_vmcb_holds_passes_through() {
    let pm = msrpm();
    let open: Vec<u32> = (0..0x2000u32)
        .chain(0xC000_0000..0xC000_2000)
        .chain(0xC001_0000..0xC001_2000)
        .filter(|&m| !msr::intercepted(&pm, m, false) || !msr::intercepted(&pm, m, true))
        .collect();
    let mut want: Vec<u32> = msr::PASSTHROUGH.to_vec();
    want.push(msr::MSR_TSC);
    want.sort();
    assert_eq!(open, want, "every MSR that is open for a read or a write");
    for m in msr::PASSTHROUGH {
        assert!(!msr::intercepted(&pm, m, false) && !msr::intercepted(&pm, m, true), "{m:#x}");
    }
    // FS/GS/KernelGSBase 0xC0000100-2, STAR/LSTAR/CSTAR/SFMASK 0xC0000081-4, SYSENTER 0x174-6.
    assert_eq!(msr::PASSTHROUGH, [0x174, 0x175, 0x176, 0xC000_0081, 0xC000_0082, 0xC000_0083, 0xC000_0084,
                                  0xC000_0100, 0xC000_0101, 0xC000_0102]);
    // The TSC reads at full speed (the hardware adds the offset) and a write exits to move the offset.
    assert!(!msr::intercepted(&pm, msr::MSR_TSC, false) && msr::intercepted(&pm, msr::MSR_TSC, true));
    // What the monitor emulates exits both ways: EFER, PAT, APIC base, TSC deadline, x2APIC, SPEC_CTRL, TSC_AUX, VM_HSAVE_PA.
    for m in [0xC000_0080, 0x277, 0x1B, 0x6E0, 0x802, 0x830, 0x48, 0xC000_0103, 0xC001_0117, 0x1A0, 0xC001_0114] {
        assert!(msr::intercepted(&pm, m, false) && msr::intercepted(&pm, m, true), "{m:#x}");
    }
}

/// A guest at the `EFER` state of a booting kernel before paging.
fn efer_vmcb(cur: u64, cr0: u64) -> Vmcb {
    let mut v = wired(Vmcb::new());
    v.wr64(off::EFER, cur | efer::SVME);
    v.wr64(off::CR0, cr0);
    v
}

/// An APIC that must not be reached.
struct NoApic;

impl LocalApic for NoApic {
    fn msr_read(&mut self, _: u32, _: u64) -> Result<u64, Gp> {
        panic!("not an APIC MSR")
    }
    fn msr_write(&mut self, _: u32, _: u64, _: u64) -> Result<(), Gp> {
        panic!("not an APIC MSR")
    }
    fn tick(&mut self, _: u64) {}
    fn pending(&self) -> Option<u8> {
        None
    }
    fn ack(&mut self) -> Option<u8> {
        None
    }
    fn take_event(&mut self) -> Option<ApicEvent> {
        None
    }
    fn has_work(&self) -> bool {
        false
    }
    fn next_deadline(&self) -> Option<u64> {
        None
    }
    fn init_reset(&mut self) {}
    fn owns_mmio(&self, _: u64) -> bool {
        false
    }
    fn mmio_read(&mut self, _: u64, _: u8, _: u64) -> u32 {
        panic!("no MMIO")
    }
    fn mmio_write(&mut self, _: u64, _: u8, _: u32, _: u64) {
        panic!("no MMIO")
    }
}

const SCE: u64 = 1;
const LME: u64 = 1 << 8;
const LMA: u64 = 1 << 10;
const NXE: u64 = 1 << 11;
const SVME: u64 = 1 << 12;

#[test]
fn efer_hides_svm_and_never_lets_the_guest_clear_it_underneath() {
    let mut v = efer_vmcb(0, 0x11);
    // What boot.S does with the PVH state: set LME and NXE (CR4.PAE and CR3 first), then CR0.PG.
    assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_EFER, LME | NXE, 0), Ok(()));
    assert_eq!(v.rd64(off::EFER), LME | NXE | SVME, "SVME stays set underneath: VMRUN needs it");
    assert_eq!(msr::read(&v, &mut NoApic, msr::MSR_EFER, 0), Ok(LME | NXE), "the guest reads no SVME");
    // The kernel's own wrmsr after long mode is on (cpu_init sets SCE), with LMA as the hardware set it.
    v.wr64(off::EFER, LME | LMA | NXE | SVME);
    v.wr64(off::CR0, 0x8001_0011);
    let seen = msr::read(&v, &mut NoApic, msr::MSR_EFER, 0).unwrap();
    assert_eq!(seen, LME | LMA | NXE);
    assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_EFER, seen | SCE, 0), Ok(()));
    assert_eq!(v.rd64(off::EFER), SCE | LME | LMA | NXE | SVME);
    // The AP trampoline writes back what the boot CPU read, LMA included, before it has paging: LMA is
    // the hardware's, so the write is accepted and sets nothing.
    let mut ap = efer_vmcb(0, 0x11);
    assert_eq!(msr::write(&mut ap, &mut NoApic, msr::MSR_EFER, SCE | LME | LMA | NXE, 0), Ok(()));
    assert_eq!(ap.rd64(off::EFER), SCE | LME | NXE | SVME, "LMA is not set by a write");
    // A write that clears SVME is not a way out: the VMCB keeps it.
    assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_EFER, SCE | LME | NXE, 0), Ok(()));
    assert_ne!(v.rd64(off::EFER) & SVME, 0);
}

#[test]
fn efer_refuses_what_cpuid_does_not_offer_and_a_mode_switch_under_paging() {
    let mut v = efer_vmcb(0, 0x11);
    // SVME (12), LMSLE (13), FFXSR (14), TCE (15), AutoIBRS (21), and a reserved bit.
    for b in [12, 13, 14, 15, 21, 40, 63] {
        assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_EFER, 1 << b, 0), Err(Gp), "bit {b}");
    }
    assert_eq!(v.rd64(off::EFER), SVME, "a refused write changes nothing");
    // Under paging LME cannot change.
    let mut p = efer_vmcb(LME | LMA | NXE, 0x8001_0011);
    assert_eq!(msr::write(&mut p, &mut NoApic, msr::MSR_EFER, NXE, 0), Err(Gp), "clearing LME with PG");
    assert_eq!(msr::write(&mut p, &mut NoApic, msr::MSR_EFER, LME | NXE | SCE, 0), Ok(()), "same LME is fine");
    let mut q = efer_vmcb(NXE, 0x8001_0011);
    assert_eq!(msr::write(&mut q, &mut NoApic, msr::MSR_EFER, NXE | LME, 0), Err(Gp), "setting LME with PG");
}

#[test]
fn pat_takes_valid_memory_types_only() {
    let mut v = wired(Vmcb::new());
    // The PAT AzOS programs (mmu.rs PAT_VALUE shape): WB WT UC- UC WB WT UC- UC is the architectural reset value.
    let reset = 0x0007_0406_0007_0406u64;
    assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_PAT, reset, 0), Ok(()));
    assert_eq!(v.rd64(off::G_PAT), reset);
    assert_eq!(msr::read(&v, &mut NoApic, msr::MSR_PAT, 0), Ok(reset));
    // Valid types: 0 UC, 1 WC, 4 WT, 5 WP, 6 WB, 7 UC-. Invalid: 2, 3, 8.
    let all_valid = 0x0001_0405_0607_0001u64;
    assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_PAT, all_valid, 0), Ok(()));
    for bad in [2u64, 3, 8, 0xFF] {
        for byte in 0..8 {
            let w = reset & !(0xFF << (byte * 8)) | bad << (byte * 8);
            assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_PAT, w, 0), Err(Gp), "type {bad:#x} in byte {byte}");
        }
    }
    assert_eq!(v.rd64(off::G_PAT), all_valid, "a refused write changes nothing");
}

#[test]
fn the_tsc_the_guest_reads_is_the_hosts_plus_its_offset() {
    let mut v = wired(Vmcb::new());
    v.wr64(off::TSC_OFFSET, 1_000);
    assert_eq!(msr::read(&v, &mut NoApic, msr::MSR_TSC, 5_000), Ok(6_000));
    // A write moves the offset so that the guest's TSC reads the value now.
    assert_eq!(msr::write(&mut v, &mut NoApic, msr::MSR_TSC, 10, 5_000), Ok(()));
    assert_eq!(v.rd64(off::TSC_OFFSET), 10u64.wrapping_sub(5_000));
    assert_eq!(msr::read(&v, &mut NoApic, msr::MSR_TSC, 5_000), Ok(10));
    assert_eq!(msr::read(&v, &mut NoApic, msr::MSR_TSC, 5_100), Ok(110));
}

#[test]
fn what_a_cpu_without_the_msr_would_refuse_is_a_gp() {
    let mut v = wired(Vmcb::new());
    // SPEC_CTRL, ARCH_CAPABILITIES, TSC_AUX, VM_HSAVE_PA, VM_CR, MISC_ENABLE, TSC_ADJUST, CET, MTRRcap, machine check.
    for m in [0x48, 0x10A, 0xC000_0103, 0xC001_0117, 0xC001_0114, 0x1A0, 0x3B, 0x6A2, 0xFE, 0x179, 0x4000_0000] {
        assert_eq!(msr::read(&v, &mut NoApic, m, 0), Err(Gp), "rdmsr {m:#x}");
        assert_eq!(msr::write(&mut v, &mut NoApic, m, 0, 0), Err(Gp), "wrmsr {m:#x}");
    }
    // The two the mitigation code of an AMD guest reads and writes: zero, dropped.
    for m in [0x8B, 0xC001_1029] {
        assert_eq!(msr::read(&v, &mut NoApic, m, 0), Ok(0));
        assert_eq!(msr::write(&mut v, &mut NoApic, m, 0xFFFF, 0), Ok(()));
        assert_eq!(msr::read(&v, &mut NoApic, m, 0), Ok(0), "a dropped write is not remembered");
    }
}

// ── the exits ───────────────────────────────────────────────────────────

/// The monitor's side of a VM: the vCPUs' APICs and the IOAPIC.
pub(crate) struct Vm {
    pub(crate) apics: Vec<Vlapic>,
    pub(crate) io: Vioapic,
    /// The vCPUs that received a message since the monitor last looked.
    pub(crate) kicked: u64,
}

/// vCPU `idx`'s window onto the VM's APICs.
pub(crate) struct Port<'a> {
    pub(crate) vm: &'a mut Vm,
    pub(crate) idx: usize,
}

impl LocalApic for Port<'_> {
    fn msr_read(&mut self, m: u32, tsc: u64) -> Result<u64, Gp> {
        self.vm.apics[self.idx].msr_read(m, tsc).map_err(|_| Gp)
    }
    fn msr_write(&mut self, m: u32, v: u64, tsc: u64) -> Result<(), Gp> {
        let e = self.vm.apics[self.idx].msr_write(m, v, tsc).map_err(|_| Gp)?;
        let vm = &mut *self.vm;
        vm.kicked |= deliver_effect(&mut vm.apics, &mut vm.io, self.idx, e);
        Ok(())
    }
    fn tick(&mut self, tsc: u64) {
        self.vm.apics[self.idx].tick(tsc)
    }
    fn pending(&self) -> Option<u8> {
        self.vm.apics[self.idx].pending()
    }
    fn ack(&mut self) -> Option<u8> {
        self.vm.apics[self.idx].ack()
    }
    fn take_event(&mut self) -> Option<ApicEvent> {
        self.vm.apics[self.idx].take_event().map(|e| match e {
            Event::Init => ApicEvent::Init,
            Event::Startup(v) => ApicEvent::Startup(v),
            Event::Smi => ApicEvent::Smi,
            Event::Nmi => ApicEvent::Nmi,
            Event::ExtInt => ApicEvent::ExtInt,
        })
    }
    fn has_work(&self) -> bool {
        self.vm.apics[self.idx].has_work()
    }
    fn next_deadline(&self) -> Option<u64> {
        self.vm.apics[self.idx].next_deadline()
    }
    fn init_reset(&mut self) {
        self.vm.apics[self.idx].init_reset()
    }
    fn owns_mmio(&self, gpa: u64) -> bool {
        let a = &self.vm.apics[self.idx];
        let io = self.vm.io.mmio_base();
        (a.mode() == ApicMode::XApic && gpa >= a.mmio_base() && gpa < a.mmio_base() + APIC_PAGE)
            || (gpa >= io && gpa < io + IOAPIC_WINDOW)
    }
    fn mmio_read(&mut self, gpa: u64, size: u8, tsc: u64) -> u32 {
        let io = self.vm.io.mmio_base();
        if gpa >= io && gpa < io + IOAPIC_WINDOW {
            self.vm.io.mmio_read(gpa, size).unwrap_or(0)
        } else {
            self.vm.apics[self.idx].mmio_read(gpa, size, tsc).unwrap_or(0)
        }
    }
    fn mmio_write(&mut self, gpa: u64, size: u8, val: u32, tsc: u64) {
        let vm = &mut *self.vm;
        let io = vm.io.mmio_base();
        if gpa >= io && gpa < io + IOAPIC_WINDOW {
            if let Ok(msgs) = vm.io.mmio_write(gpa, size, val) {
                vm.kicked |= azos_hv::vioapic::deliver_all(&mut vm.apics, &msgs);
            }
        } else if let Ok(e) = vm.apics[self.idx].mmio_write(gpa, size, val, tsc) {
            vm.kicked |= deliver_effect(&mut vm.apics, &mut vm.io, self.idx, e);
        }
    }
}

/// Guest RAM for the instruction fetch: 2 MiB, identity-mapped by `long_mode`.
struct Ram(Vec<u8>);

impl Ram {
    fn new() -> Ram {
        Ram(vec![0; 2 << 20])
    }

    fn put(&mut self, at: u64, bytes: &[u8]) {
        self.0[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    }

    fn put64(&mut self, at: u64, v: u64) {
        self.put(at, &v.to_le_bytes());
    }
}

impl GuestMem for Ram {
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool {
        match self.0.get(gpa as usize..gpa as usize + buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

/// Guest TSC cycles per timer tick: 3 GHz over a 100 MHz bus.
fn tpt() -> u64 {
    timer_clock(TSC_KHZ, APIC_KHZ).0
}

pub(crate) fn vm(n: u32) -> Vm {
    Vm {
        apics: (0..n).map(|i| Vlapic::new(i, i == 0, tpt())).collect(),
        io: Vioapic::new(0, IOAPIC_DEFAULT_BASE),
        kicked: 0,
    }
}

/// One vCPU with its VMCB, registers, state and the host it runs on.
struct Cpu {
    s: VcpuState,
    v: Vmcb,
    r: GuestRegs,
    ram: Ram,
}

fn cpu(id: u32, vcpus: u32) -> Cpu {
    let mut s = VcpuState::new(id, vcpus, 1);
    s.tsc_khz = TSC_KHZ;
    s.apic_khz = APIC_KHZ;
    s.signature = 0x00A0_0F11;
    s.nrips = true;
    let (v, r) = if id == 0 {
        pvh()
    } else {
        let mut v = wired(Vmcb::new());
        let mut r = GuestRegs::default();
        v.init_startup(&mut r, 0, 1, 0);
        (v, r)
    };
    Cpu { s, v, r, ram: Ram::new() }
}

impl Cpu {
    /// The guest executed an instruction that exits at `rip` and the CPU says the next one is `next`.
    fn exits(&mut self, code: u64, info1: u64, rip: u64, next: u64, vm: &mut Vm) -> Served {
        self.v.wr64(off::RIP, rip);
        self.v.wr64(off::NEXT_RIP, next);
        let e = exit::svm(code, info1, 0);
        let mut port = Port { vm, idx: self.s.id as usize };
        let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &self.ram, host_tsc: 1_000_000 };
        self.s.serve(e, &mut self.v, &mut self.r, &mut env)
    }

    fn enters(&mut self, vm: &mut Vm, host_tsc: u64) -> Entry {
        let mut port = Port { vm, idx: self.s.id as usize };
        let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &self.ram, host_tsc };
        self.s.before_entry(&mut self.v, &mut self.r, &mut env)
    }

    fn rdmsr(&mut self, m: u32, vm: &mut Vm) -> Option<u64> {
        self.r.rcx = m as u64;
        let at = self.v.rd64(off::RIP);
        let s = self.exits(code::MSR, 0, at, at + 2, vm);
        assert_eq!(s, Served::Resume);
        (self.v.rd64(off::RIP) == at + 2).then(|| (self.r.rdx << 32) | (self.v.rd64(off::RAX) & 0xFFFF_FFFF))
    }

    fn wrmsr(&mut self, m: u32, val: u64, vm: &mut Vm) -> bool {
        self.r.rcx = m as u64;
        self.r.rdx = val >> 32;
        self.v.wr64(off::RAX, val & 0xFFFF_FFFF);
        let at = self.v.rd64(off::RIP);
        assert_eq!(self.exits(code::MSR, 1, at, at + 2, vm), Served::Resume);
        self.v.rd64(off::RIP) == at + 2
    }
}

fn injected(v: &Vmcb) -> Option<(u8, u32)> {
    let w = v.rd32(off::EVENT_INJ);
    (w & ctl::EVENT_VALID != 0).then_some((w as u8, w & 0x700))
}

#[test]
fn a_cpuid_exit_fills_the_registers_and_steps_past_the_instruction() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    c.v.wr64(off::RAX, 0x4000_0000);
    c.r.rcx = 0;
    c.r.rbx = 0x1111;
    assert_eq!(c.exits(code::CPUID, 0, 0x1000, 0x1002, &mut vm), Served::Resume);
    assert_eq!(c.v.rd64(off::RAX), 0x4000_0010);
    assert_eq!((c.r.rbx, c.r.rcx, c.r.rdx), (0x534F_7A41, 0x534F_7A41, 0x534F_7A41), "\"AzOS\" three times");
    assert_eq!(c.v.rd64(off::RIP), 0x1002);
    // Sub-leaf comes from ECX; upper halves of RAX are ignored on input and cleared on output.
    c.v.wr64(off::RAX, 0xFFFF_FFFF_0000_000B);
    c.r.rcx = 0xFFFF_FFFF_0000_0001;
    c.exits(code::CPUID, 0, 0x1002, 0x1004, &mut vm);
    assert_eq!(c.r.rbx, 1, "leaf 0xB sub-leaf 1 for vCPU 0 of 1: one core");
    assert_eq!(c.v.rd64(off::RAX), 0);
    // After CR4.OSXSAVE the same CPUID shows OSXSAVE.
    c.v.wr64(off::CR4, 1 << 18);
    c.v.wr64(off::RAX, 1);
    c.r.rcx = 0;
    c.exits(code::CPUID, 0, 0x1004, 0x1006, &mut vm);
    assert_ne!(c.r.rcx & 1 << 27, 0);
}

#[test]
fn without_next_rip_the_instruction_lengths_are_used() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    c.s.nrips = false;
    // CPUID, RDMSR, WRMSR are 0F A2 / 0F 32 / 0F 30; HLT is F4; XSETBV is 0F 01 D1.
    c.v.wr64(off::RAX, 0);
    c.exits(code::CPUID, 0, 0x2000, 0xBAD, &mut vm);
    assert_eq!(c.v.rd64(off::RIP), 0x2002);
    c.r.rcx = 0x277;
    c.exits(code::MSR, 0, 0x2002, 0xBAD, &mut vm);
    assert_eq!(c.v.rd64(off::RIP), 0x2004);
    c.exits(code::HLT, 0, 0x2004, 0xBAD, &mut vm);
    assert_eq!(c.v.rd64(off::RIP), 0x2005);
    c.exits(code::WBINVD, 0, 0x2005, 0xBAD, &mut vm);
    assert_eq!(c.v.rd64(off::RIP), 0x2007);
    c.v.wr64(off::CR4, 1 << 18);
    c.v.wr64(off::RAX, 7);
    c.r.rcx = 0;
    c.r.rdx = 0;
    c.exits(code::XSETBV, 0, 0x2007, 0xBAD, &mut vm);
    assert_eq!(c.v.rd64(off::RIP), 0x200A);
}

#[test]
fn rdmsr_and_wrmsr_move_edx_eax_and_a_refusal_is_a_gp_at_the_same_instruction() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    let pat = 0x0001_0405_0607_0001u64;
    assert!(c.wrmsr(0x277, pat, &mut vm));
    assert_eq!(c.v.rd64(off::G_PAT), pat);
    c.r.rdx = 0xAAAA;
    c.v.wr64(off::RAX, 0xBBBB_BBBB_BBBB_BBBB);
    assert_eq!(c.rdmsr(0x277, &mut vm), Some(pat));
    assert_eq!((c.r.rdx, c.v.rd64(off::RAX)), (pat >> 32, pat & 0xFFFF_FFFF), "EDX:EAX, upper halves cleared");
    // The high half of RAX and RDX on a write are ignored.
    c.r.rcx = 0x277;
    c.r.rdx = 0xFFFF_FFFF_0001_0405;
    c.v.wr64(off::RAX, 0xFFFF_FFFF_0607_0001);
    let at = c.v.rd64(off::RIP);
    c.exits(code::MSR, 1, at, at + 2, &mut vm);
    assert_eq!(c.v.rd64(off::G_PAT), pat);
    // An unknown MSR: #GP(0), RIP stays at the instruction.
    let at = c.v.rd64(off::RIP);
    assert_eq!(c.rdmsr(0x48, &mut vm), None);
    assert_eq!(c.v.rd64(off::RIP), at, "the GP is taken at the instruction");
    assert_eq!(c.v.rd32(off::EVENT_INJ), ctl::EVENT_VALID | ctl::EVENT_EXCEPTION | ctl::EVENT_ERR | 13);
    assert_eq!(c.v.rd32(off::EVENT_INJ_ERR), 0);
    // Writing an invalid PAT too.
    let mut d = cpu(0, 1);
    assert!(!d.wrmsr(0x277, 2, &mut vm));
    assert_eq!(injected(&d.v), Some((13, 3 << 8)));
}

#[test]
fn xsetbv_keeps_the_guests_xcr0_and_checks_it() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    let run = |c: &mut Cpu, vm: &mut Vm, idx: u64, val: u64| {
        c.r.rcx = idx;
        c.r.rdx = val >> 32;
        c.v.wr64(off::RAX, val & 0xFFFF_FFFF);
        let at = c.v.rd64(off::RIP);
        assert_eq!(c.exits(code::XSETBV, 0, at, at + 3, vm), Served::Resume);
        c.v.rd64(off::RIP) == at + 3
    };
    // Without CR4.OSXSAVE the instruction is #UD (SDM vol. 2).
    assert!(!run(&mut c, &mut vm, 0, 7));
    assert_eq!(injected(&c.v), Some((6, 3 << 8)));
    assert_eq!(c.s.xcr0(), 1);
    c.v.wr32(off::EVENT_INJ, 0);
    c.v.wr64(off::CR4, 1 << 18);
    assert!(run(&mut c, &mut vm, 0, 7));
    assert_eq!(c.s.xcr0(), 7);
    // #GP(0): an XCR other than 0, a value Zen 3 does not have (AVX-512), x87 off, SSE off under AVX.
    for (idx, val) in [(1u64, 7u64), (0, 0xE7), (0, 6), (0, 5), (0, 1 << 63)] {
        c.v.wr32(off::EVENT_INJ, 0);
        assert!(!run(&mut c, &mut vm, idx, val), "XCR{idx} = {val:#x}");
        assert_eq!(injected(&c.v), Some((13, 3 << 8)));
        assert_eq!(c.s.xcr0(), 7, "a refused write changes nothing");
    }
    // Not in ring 0.
    c.v.wr32(off::EVENT_INJ, 0);
    c.v.wr8(off::CPL, 3);
    assert!(!run(&mut c, &mut vm, 0, 3));
    assert_eq!(injected(&c.v), Some((13, 3 << 8)));
    assert_eq!(c.s.xcr0(), 7);
}

#[test]
fn hlt_sleeps_only_when_the_apic_has_nothing_for_the_vcpu() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    assert_eq!(c.exits(code::HLT, 0, 0x3000, 0x3001, &mut vm), Served::Wait);
    assert_eq!(c.v.rd64(off::RIP), 0x3001, "the guest wakes after the HLT");
    // A request in the IRR (even one the guest cannot take yet) keeps it from sleeping.
    x2apic_up(&mut vm, 0);
    vm.apics[0].msr_write(0x83F, 0x41, 0).unwrap();
    assert_eq!(c.exits(code::HLT, 0, 0x3001, 0x3002, &mut vm), Served::Resume);
}

#[test]
fn the_instructions_cpuid_does_not_offer_are_ud_and_the_cache_flushes_are_skipped() {
    let mut vm = vm(1);
    for c in [code::RDTSCP, code::MONITOR, code::MWAIT, code::SKINIT, code::VMRUN, code::VMLOAD, code::VMSAVE,
              code::STGI, code::CLGI] {
        let mut cpu = cpu(0, 1);
        assert_eq!(cpu.exits(c, 0, 0x4000, 0x4003, &mut vm), Served::Resume, "{c:#x}");
        assert_eq!(injected(&cpu.v), Some((6, 3 << 8)), "{c:#x} is #UD");
        assert_eq!(cpu.v.rd32(off::EVENT_INJ) & ctl::EVENT_ERR, 0, "#UD has no error code");
        assert_eq!(cpu.v.rd64(off::RIP), 0x4000, "the UD is taken at the instruction");
    }
    for c in [code::WBINVD, code::INVD] {
        let mut cpu = cpu(0, 1);
        assert_eq!(cpu.exits(c, 0, 0x4000, 0x4002, &mut vm), Served::Resume);
        assert_eq!((injected(&cpu.v), cpu.v.rd64(off::RIP)), (None, 0x4002));
    }
}

#[test]
fn the_exits_it_does_not_answer_go_back_to_the_loop() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    assert_eq!(c.exits(code::INTR, 0, 0, 0, &mut vm), Served::HostInterrupt);
    assert_eq!(c.exits(code::NMI, 0, 0, 0, &mut vm), Served::HostInterrupt);
    assert_eq!(c.exits(code::SHUTDOWN, 0, 0, 0, &mut vm), Served::Shutdown);
    assert_eq!(c.exits(code::INVALID, 0, 0, 0, &mut vm), Served::InvalidState);
    for (code, info) in [(code::NPF, 0x100u64), (code::IOIO, 3 << 16 | 1), (code::VMMCALL, 0), (code::SMI, 0), (code::INIT, 0),
                         (code::PAUSE, 0)] {
        let e = exit::svm(code, info, 0);
        let mut port = Port { vm: &mut vm, idx: 0 };
        let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &c.ram, host_tsc: 0 };
        assert_eq!(c.s.serve(e, &mut c.v, &mut c.r, &mut env), Served::Unserved(e), "{code:#x}");
    }
}

// ── interrupts ──────────────────────────────────────────────────────────

/// A vCPU's APIC in x2APIC mode, software-enabled, as AzOS's `apic::init_local` leaves it.
pub(crate) fn x2apic_up(vm: &mut Vm, i: usize) {
    let a = &mut vm.apics[i];
    let bsp = if i == 0 { 1 << 8 } else { 0 };
    a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | bsp | 1 << 11, 0).unwrap();
    a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | bsp | 1 << 11 | 1 << 10, 0).unwrap();
    a.msr_write(0x80F, 0x1FF, 0).unwrap();
}

/// vCPU `src` writes `icr` to its x2APIC ICR and what that asks of the VM is applied.
pub(crate) fn icr_send(vm: &mut Vm, src: usize, icr: u64) {
    let e = vm.apics[src].msr_write(0x830, icr, 0).unwrap();
    vm.kicked |= deliver_effect(&mut vm.apics, &mut vm.io, src, e);
}

const LVT_TIMER: u32 = 0x832;
const TIMER_VECTOR: u64 = 0xEC;

#[test]
fn the_tsc_deadline_timer_fires_in_the_guest_and_the_vector_is_injected() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    // TSC-deadline mode, vector 0xEC, unmasked; the guest arms a deadline 5000 guest cycles away.
    assert!(c.wrmsr(LVT_TIMER, TIMER_VECTOR | 2 << 17, &mut vm));
    let now = 1_000_000 + c.v.rd64(off::TSC_OFFSET);
    assert!(c.wrmsr(MSR_TSC_DEADLINE, now + 5_000, &mut vm));
    assert_eq!(c.rdmsr(MSR_TSC_DEADLINE, &mut vm), Some(now + 5_000));
    assert_eq!(vm.apics[0].next_deadline(), Some(now + 5_000), "the monitor arms a host timer for this");
    // Before the deadline: nothing to inject.
    assert_eq!(c.enters(&mut vm, 1_000_000 + 4_999), Entry::Run);
    assert_eq!(injected(&c.v), None);
    assert!(!c.v.window_requested());
    // At the deadline: the timer fires and the vector goes in; the APIC moves it to in-service.
    assert_eq!(c.enters(&mut vm, 1_000_000 + 5_000), Entry::Run);
    assert_eq!(injected(&c.v), Some((TIMER_VECTOR as u8, 0)), "an external interrupt, vector 0xEC");
    assert_eq!(vm.apics[0].pending(), None);
    assert_eq!(vm.apics[0].msr_read(0x817, 0), Ok(1 << (TIMER_VECTOR % 32)), "ISR[0xE0..0x100)");
    assert_eq!(vm.apics[0].next_deadline(), None, "one-shot");
    assert!(!c.v.window_requested());
}

#[test]
fn a_one_shot_timer_counts_in_the_clock_cpuid_reported() {
    let (per_tick, khz) = timer_clock(TSC_KHZ, APIC_KHZ);
    assert_eq!((per_tick, khz), (30, 99_840), "2 995 200 kHz / 30 cycles per tick; CPUID must say the second");
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    // The guest programs divide-by-1 (encoding 0xB) and an initial count of 1000 ticks of the clock it
    // calibrated from leaf 0x40000010.
    assert!(c.wrmsr(0x83E, 0xB, &mut vm));
    assert!(c.wrmsr(LVT_TIMER, TIMER_VECTOR, &mut vm));
    let t0 = 1_000_000 + c.v.rd64(off::TSC_OFFSET);
    assert!(c.wrmsr(0x838, 1000, &mut vm));
    let due = t0 + 1000 * per_tick;
    assert_eq!(vm.apics[0].next_deadline(), Some(due));
    assert_eq!(c.enters(&mut vm, 1_000_000 + 1000 * per_tick - 1), Entry::Run);
    assert_eq!(injected(&c.v), None);
    assert_eq!(c.enters(&mut vm, 1_000_000 + 1000 * per_tick), Entry::Run);
    assert_eq!(injected(&c.v), Some((TIMER_VECTOR as u8, 0)));
    // A zero input is zero out: the guest then calibrates by itself.
    assert_eq!(timer_clock(0, APIC_KHZ), (1, 0));
    assert_eq!(timer_clock(TSC_KHZ, 0), (1, 0));
    // The undivided clock never runs faster than the TSC.
    assert_eq!(timer_clock(1000, 5000), (1, 1000));
}

#[test]
fn an_interrupt_waits_for_if_the_shadow_and_a_free_event_slot() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    vm.apics[0].msr_write(0x83F, 0x41, 0).unwrap(); // self IPI
    // IF clear (the PVH state): the interrupt window opens instead.
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None);
    assert!(c.v.window_requested());
    assert_ne!(c.v.rd32(off::INTERCEPT_W3) & icpt::VINTR, 0, "the guest exits when it can take it");
    assert_ne!(c.v.rd32(off::INT_CTL) & ctl::V_IGN_TPR, 0);
    assert_eq!(vm.apics[0].pending(), Some(0x41), "not acknowledged");
    // sti: IF set but in the shadow of the instruction after it.
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    c.v.wr32(off::INT_STATE, ctl::INT_SHADOW);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None);
    assert!(c.v.window_requested());
    // The window exit once the shadow is gone: the intercept is withdrawn and the next entry injects.
    c.v.wr32(off::INT_STATE, 0);
    assert_eq!(c.exits(code::VINTR, 0, 0x5000, 0x5000, &mut vm), Served::Resume);
    assert!(!c.v.window_requested());
    assert_eq!(c.v.rd32(off::INTERCEPT_W3) & icpt::VINTR, 0);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x41, 0)));
    assert!(!c.v.window_requested(), "nothing else pending: no window");
    // An event already queued for the entry (a #GP) goes first.
    let mut d = cpu(0, 1);
    d.v.wr64(off::RFLAGS, 2 | 1 << 9);
    vm.apics[0].msr_write(0x83F, 0x52, 0).unwrap();
    d.v.inject_exception(13, Some(0));
    assert_eq!(d.enters(&mut vm, 0), Entry::Run);
    assert_eq!(d.v.rd32(off::EVENT_INJ) & 0xFF, 13, "the exception stays queued");
    assert!(d.v.window_requested());
    assert_eq!(vm.apics[0].pending(), Some(0x52));
}

#[test]
fn the_highest_priority_class_goes_first_and_the_eoi_releases_the_next() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    vm.apics[0].msr_write(0x83F, 0x41, 0).unwrap();
    vm.apics[0].msr_write(0x83F, 0x91, 0).unwrap();
    // 0x91 is the higher priority class and goes first; one event per entry.
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x91, 0)));
    // 0x41 does not beat the in-service 0x91: no window either, the EOI is what releases it.
    c.v.wr32(off::EVENT_INJ, 0);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None);
    assert!(!c.v.window_requested());
    assert!(c.wrmsr(0x80B, 0, &mut vm), "EOI");
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x41, 0)));
}

#[test]
fn an_event_cut_short_by_an_exit_is_injected_again() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    // The CPU was delivering vector 0x41 (type 0, valid) when a nested page fault exited.
    c.v.wr32(off::EXIT_INT_INFO, 1 << 31 | 0x41);
    c.v.wr32(off::EXIT_INT_INFO_ERR, 0);
    let e = exit::svm(code::NPF, 2, 0xFEC0_0000);
    let mut port = Port { vm: &mut vm, idx: 0 };
    let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &c.ram, host_tsc: 0 };
    c.s.serve(e, &mut c.v, &mut c.r, &mut env);
    assert_eq!(injected(&c.v), Some((0x41, 0)), "queued for the retry");
    assert_eq!(c.v.rd32(off::EXIT_INT_INFO), 0, "and not repeated by the next exit");
    // An exception with an error code keeps it.
    c.v.wr32(off::EXIT_INT_INFO, 1 << 31 | 1 << 11 | 3 << 8 | 14);
    c.v.wr32(off::EXIT_INT_INFO_ERR, 0x6);
    let mut port = Port { vm: &mut vm, idx: 0 };
    let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &c.ram, host_tsc: 0 };
    c.s.serve(e, &mut c.v, &mut c.r, &mut env);
    assert_eq!(c.v.rd32(off::EVENT_INJ), 1 << 31 | 1 << 11 | 3 << 8 | 14);
    assert_eq!(c.v.rd32(off::EVENT_INJ_ERR), 6);
}

#[test]
fn an_nmi_is_injected_once() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    // ICR: NMI (delivery mode 4), to itself via the shorthand.
    icr_send(&mut vm, 0, 4 << 8 | 1 << 18);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((2, 2 << 8)), "vector 2, type NMI");
    c.v.wr32(off::EVENT_INJ, 0);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None, "once");
}

/// Send the vCPU an NMI (ICR: NMI delivery, to itself).
fn nmi_to_self(vm: &mut Vm) {
    icr_send(vm, 0, 4 << 8 | 1 << 18);
}

#[test]
fn a_second_nmi_waits_for_the_iret_of_the_first_handler() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    nmi_to_self(&mut vm);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((2, 2 << 8)));
    assert_ne!(c.v.rd32(off::INTERCEPT_W3) & icpt::IRET, 0, "the end of the handler is watched");
    // The handler sends itself another NMI (an ICR write in the handler): it is latched, not injected.
    c.v.wr32(off::EVENT_INJ, 0);
    nmi_to_self(&mut vm);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None, "NMIs are blocked until the handler returns");
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None, "and stay blocked on later entries");
    // HLT with a blocked NMI latched sleeps: only an interrupt can wake it.
    assert_eq!(c.exits(code::HLT, 0, 0x1000, 0x1001, &mut vm), Served::Wait);
    // The handler reaches its IRET: the exit comes before it runs.
    assert_eq!(c.exits(code::IRET, 0, 0x7000, 0x7001, &mut vm), Served::Resume);
    assert_eq!(c.v.rd32(off::INTERCEPT_W3) & icpt::IRET, 0, "the intercept is withdrawn");
    assert_eq!(c.v.rd64(off::RIP), 0x7000, "the IRET is not stepped over: it runs");
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None, "still on the IRET: the block has not ended");
    // The IRET ran: the guest is elsewhere. The latched NMI is injected, and blocks again.
    c.v.wr64(off::RIP, 0x1234);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((2, 2 << 8)));
    assert_ne!(c.v.rd32(off::INTERCEPT_W3) & icpt::IRET, 0);
}

#[test]
fn an_nmi_is_not_injected_in_the_shadow_of_sti_or_mov_ss() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    c.v.wr32(off::INT_STATE, ctl::INT_SHADOW);
    nmi_to_self(&mut vm);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None, "held back");
    assert!(c.v.window_requested(), "and the guest exits when the shadow is over");
    assert_eq!(c.v.rd32(off::INTERCEPT_W3) & icpt::IRET, 0, "no handler is running");
    c.v.wr32(off::INT_STATE, 0);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((2, 2 << 8)));
}

#[test]
fn an_init_ends_the_nmi_block() {
    let mut vm = vm(2);
    x2apic_up(&mut vm, 0);
    x2apic_up(&mut vm, 1);
    let mut bsp = cpu(0, 2);
    let mut ap = cpu(1, 2);
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    // An NMI to the AP: injected, and its handler is watched.
    assert!(bsp.wrmsr(ICR, 1 << 32 | 4 << 8 | 1 << 14, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&ap.v), Some((2, 2 << 8)));
    assert_ne!(ap.v.rd32(off::INTERCEPT_W3) & icpt::IRET, 0);
    // INIT + SIPI again: a new life, in no handler.
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(ap.v.rd32(off::INTERCEPT_W3) & icpt::IRET, 0);
    assert!(bsp.wrmsr(ICR, 1 << 32 | 4 << 8 | 1 << 14, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&ap.v), Some((2, 2 << 8)), "not held back by the first life's handler");
}

#[test]
fn with_other_vcpus_running_only_the_cpus_own_copy_of_the_instruction_is_decoded() {
    let mut vm = vm(2);
    // The same fault, read from guest memory: served in a VM of one vCPU, refused in a VM of two (the
    // other vCPU could have rewritten the bytes after the exit).
    for (vcpus, served) in [(1, true), (2, false)] {
        let mut c = cpu(0, vcpus);
        long_mode(&mut c);
        code_at(&mut c, 0x4000, &[0x8B, 0x07]);
        let s = c.fault(VIRTIO, false, &mut vm);
        assert_eq!(matches!(s, Served::Mmio { .. }), served, "{vcpus} vCPUs: {s:?}");
        // With the CPU's bytes (which no vCPU can change) the memory is not looked at at all.
        let mut c = cpu(0, vcpus);
        long_mode(&mut c);
        code_at(&mut c, 0x4000, &[0x89, 0x07]);
        c.v.wr8(0xD0, 2);
        c.v.wr8(0xD1, 0x8B);
        c.v.wr8(0xD2, 0x07);
        let s = c.fault(VIRTIO, false, &mut vm);
        assert!(matches!(s, Served::Mmio { access: MmioAccess { write: false, .. }, .. }), "{vcpus} vCPUs, assisted: {s:?}");
    }
}

// ── device interrupts through the IOAPIC ────────────────────────────────

/// The IOAPIC window register pair for pin `n`'s redirection entry.
fn rte_lo(n: u32) -> u32 {
    0x10 + 2 * n
}

fn io_write(vm: &mut Vm, reg: u32, val: u32) {
    vm.io.mmio_write(IOAPIC_DEFAULT_BASE, 4, reg).unwrap();
    let m = vm.io.mmio_write(IOAPIC_DEFAULT_BASE + 0x10, 4, val).unwrap();
    vm.kicked |= azos_hv::vioapic::deliver_all(&mut vm.apics, &m);
}

/// AzOS's `ioapic::route` for a virtio-mmio line: level, active high, fixed delivery to `dest`.
pub(crate) fn route(vm: &mut Vm, pin: u32, vector: u8, dest: u32) {
    io_write(vm, rte_lo(pin), 1 << 16);
    io_write(vm, rte_lo(pin) + 1, dest << 24);
    io_write(vm, rte_lo(pin), vector as u32 | 1 << 15);
}

#[test]
fn a_virtio_mmio_line_reaches_the_guest_through_the_ioapic_and_is_released_by_the_eoi() {
    let mut vm = vm(2);
    x2apic_up(&mut vm, 0);
    x2apic_up(&mut vm, 1);
    let mut c = cpu(0, 2);
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    route(&mut vm, 5, 0x35, 0);
    // The device model raises line 5 (`GuestCtx::irqs` bit 5): the vector is requested at vCPU 0.
    let hit = pulse_lines(&mut vm.apics, &mut vm.io, 1 << 5);
    assert_eq!(hit, 1, "vCPU 0 is kicked");
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x35, 0)));
    // A second event before the guest's EOI is not lost: it is released by the EOI (x2APIC EOI MSR 0x80B).
    c.v.wr32(off::EVENT_INJ, 0);
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, 1 << 5), 0, "level entry still outstanding");
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None);
    assert!(c.wrmsr(0x80B, 0, &mut vm), "EOI");
    assert_eq!(vm.kicked & 1, 1, "the EOI released the second message");
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x35, 0)));
    c.v.wr32(off::EVENT_INJ, 0);
    assert!(c.wrmsr(0x80B, 0, &mut vm));
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None, "two events, two interrupts, no more");
}

#[test]
fn a_masked_line_waits_for_the_guest_to_unmask_it_and_lines_past_the_ioapic_are_ignored() {
    let mut vm = vm(1);
    x2apic_up(&mut vm, 0);
    let mut c = cpu(0, 1);
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    // Level, masked: the line is raised and nothing is sent.
    io_write(&mut vm, rte_lo(7), 0x37 | 1 << 15 | 1 << 16);
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, 1 << 7), 0);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), None);
    // The guest unmasks it: the line that was held is delivered now.
    io_write(&mut vm, rte_lo(7), 0x37 | 1 << 15);
    assert_eq!(vm.kicked & 1, 1);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x37, 0)), "the level line was held until the guest unmasked it");
    // An edge entry sees one edge per raise; lines 24..64 reach nothing.
    let mut vm = self::vm(1);
    x2apic_up(&mut vm, 0);
    io_write(&mut vm, rte_lo(9), 0x39); // edge, unmasked, fixed, dest 0
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, 1 << 9), 1);
    vm.apics[0].ack();
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, 1 << 9), 1, "an edge entry takes every edge");
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, u64::MAX << 24), 0);
}

// ── INIT and startup IPIs ───────────────────────────────────────────────

const ICR: u32 = 0x830;
const ICR_INIT: u64 = 5 << 8 | 1 << 14;
const ICR_SIPI: u64 = 6 << 8 | 1 << 14;

#[test]
fn the_boot_cpu_brings_up_an_ap_with_init_sipi_sipi() {
    let mut vm = vm(2);
    x2apic_up(&mut vm, 0);
    x2apic_up(&mut vm, 1);
    let mut bsp = cpu(0, 2);
    let mut ap = cpu(1, 2);
    // The AP is not run before its SIPI.
    assert_eq!(ap.s.power(), Power::WaitSipi);
    assert_eq!(ap.enters(&mut vm, 0), Entry::WaitSipi);
    // The BSP's INIT, as AzOS's smp.rs sends it: x2APIC ICR, destination APIC ID 1 in the high half.
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert_eq!(vm.kicked, 1 << 1, "vCPU 1 is the one to kick");
    assert_eq!(ap.enters(&mut vm, 0), Entry::WaitSipi, "INIT alone starts nothing");
    assert_eq!(ap.s.power(), Power::WaitSipi);
    // The first SIPI, vector 0x9A (the trampoline page 0x9A000).
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(ap.s.power(), Power::Running);
    assert_eq!(ap.v.segment(off::CS), (0x9A00, 0x9B, 0xFFFF, 0x9A000));
    assert_eq!(ap.v.rd64(off::RIP), 0);
    assert_eq!(ap.r.rdx, 0x00A0_0F11);
    assert_eq!(ap.v.check(NASID), Ok(()));
    // The second SIPI finds it running. Mark the state to see that nothing resets it.
    ap.v.wr64(off::RIP, 0x1234);
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(ap.v.rd64(off::RIP), 0x1234, "ignored");
}

#[test]
fn an_init_and_a_sipi_sent_before_the_ap_runs_both_count() {
    // The AP's thread may not run between the BSP's INIT and its SIPI (the
    // guest waits 10 ms in between): the INIT's reset must not eat the SIPI.
    let mut vm = vm(2);
    x2apic_up(&mut vm, 0);
    x2apic_up(&mut vm, 1);
    let mut bsp = cpu(0, 2);
    let mut ap = cpu(1, 2);
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(ap.v.segment(off::CS), (0x9A00, 0x9B, 0xFFFF, 0x9A000));
    assert_eq!(ap.s.power(), Power::Running);
}

#[test]
fn an_init_resets_the_ap_and_its_apic_and_sends_it_back_to_waiting() {
    let mut vm = vm(2);
    x2apic_up(&mut vm, 0);
    x2apic_up(&mut vm, 1);
    let mut bsp = cpu(0, 2);
    let mut ap = cpu(1, 2);
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x10, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    // The AP got going: its APIC enabled, a timer, a pending interrupt, paging.
    vm.apics[1].msr_write(0x80F, 0x1FF, 0).unwrap();
    ap.v.wr64(off::CR0, 0x8000_0011);
    ap.v.wr64(off::CR3, 0x5000);
    vm.apics[1].msr_write(LVT_TIMER, TIMER_VECTOR | 2 << 17, 0).unwrap();
    vm.apics[1].msr_write(MSR_TSC_DEADLINE, 1 << 40, 0).unwrap();
    vm.apics[1].msr_write(0x83F, 0x77, 0).unwrap();
    assert!(vm.apics[1].has_work() && vm.apics[1].next_deadline().is_some(), "something to forget");
    // A new INIT: back to waiting, the state wiped, the APIC reset.
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::WaitSipi);
    assert_eq!(ap.s.power(), Power::WaitSipi);
    assert_eq!(ap.v.rd64(off::CR3), 0);
    assert_eq!(ap.v.rd64(off::CR0), 0x10);
    assert_eq!(vm.apics[1].next_deadline(), None, "the timer is gone");
    assert_eq!(vm.apics[1].msr_read(0x80F, 0), Ok(0xFF), "and the APIC is software-disabled again");
    assert!(!vm.apics[1].has_work(), "and the interrupt that was pending");
    // And it can be started again, elsewhere.
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x20, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(ap.v.segment(off::CS).3, 0x20000);
}

#[test]
fn a_started_ap_takes_the_timer_and_the_device_interrupts_like_the_boot_cpu() {
    let mut vm = vm(2);
    x2apic_up(&mut vm, 0);
    x2apic_up(&mut vm, 1);
    let mut bsp = cpu(0, 2);
    let mut ap = cpu(1, 2);
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_INIT, &mut vm));
    assert!(bsp.wrmsr(ICR, 1 << 32 | ICR_SIPI | 0x9A, &mut vm));
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    ap.v.wr64(off::RFLAGS, 2 | 1 << 9);
    // The INIT reset the AP's APIC (software-disabled); its startup code enables it again.
    vm.apics[1].msr_write(0x80F, 0x1FF, 0).unwrap();
    // A device line routed to the AP (destination APIC ID 1).
    route(&mut vm, 6, 0x36, 1);
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, 1 << 6), 1 << 1);
    assert_eq!(ap.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&ap.v), Some((0x36, 0)));
    // The BSP does not see it.
    bsp.v.wr64(off::RFLAGS, 2 | 1 << 9);
    assert_eq!(bsp.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&bsp.v), None);
}

#[test]
fn the_boot_cpu_is_never_made_to_wait() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    assert_eq!(c.s.power(), Power::Running);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
}

// ── memory-mapped I/O ───────────────────────────────────────────────────

/// A decoded instruction without the parts a test does not care about.
fn insn(len: u8, write: bool, size: u8, reg: u8, dest: u8, extend: Extend) -> Insn {
    Insn { len, write, size, reg, high8: false, dest, extend, imm: None }
}

#[test]
fn the_mov_family_decodes_as_the_manual_encodes_it() {
    use Extend::*;
    let l = |b: &[u8]| mmio::decode(b, Mode::Long);
    // Encodings from the SDM (vol. 2, MOV, MOVZX, MOVSX, MOVSXD) and the ModRM / SIB tables.
    // mov eax, [rdi+0x50]; mov [rdi+0x50], eax: ModRM mod=01 rm=111 reg=000, disp8.
    assert_eq!(l(&[0x8B, 0x47, 0x50]), Some(insn(3, false, 4, 0, 4, Move)));
    assert_eq!(l(&[0x89, 0x47, 0x50]), Some(insn(3, true, 4, 0, 4, Move)));
    // mov [rax+rcx*4], r9d: REX.R, ModRM mod=00 rm=100, SIB scale=2 index=rcx base=rax.
    assert_eq!(l(&[0x44, 0x89, 0x0C, 0x88]), Some(insn(4, true, 4, 9, 4, Move)));
    // mov rax, [rip+0x1234]: REX.W, ModRM mod=00 rm=101, disp32.
    assert_eq!(l(&[0x48, 0x8B, 0x05, 0x34, 0x12, 0x00, 0x00]), Some(insn(7, false, 8, 0, 8, Move)));
    // mov eax, [rax*4+0x1000]: SIB with no base (base=101, mod=00): disp32.
    assert_eq!(l(&[0x8B, 0x04, 0x85, 0x00, 0x10, 0x00, 0x00]), Some(insn(7, false, 4, 0, 4, Move)));
    // mov r12d, [r13]: ModRM mod=01 (r13 needs a disp8), REX.R + REX.B.
    assert_eq!(l(&[0x45, 0x8B, 0x65, 0x00]), Some(insn(4, false, 4, 12, 4, Move)));
    // mov eax, fs:[0x10]: segment override and a SIB absolute address; the override is ignored.
    assert_eq!(l(&[0x64, 0x8B, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00]), Some(insn(8, false, 4, 0, 4, Move)));
    // 67 (address size) changes nothing about the layout in 64-bit mode.
    assert_eq!(l(&[0x67, 0x8B, 0x07]), Some(insn(3, false, 4, 0, 4, Move)));
    // mov ax, [rdi]; mov [rdi], ax.
    assert_eq!(l(&[0x66, 0x8B, 0x07]), Some(insn(3, false, 2, 0, 2, Move)));
    assert_eq!(l(&[0x66, 0x89, 0x07]), Some(insn(3, true, 2, 0, 2, Move)));
    // mov al, [rdi]; mov [rdi], dl; mov [rdi], sil (REX: SIL, not DH).
    assert_eq!(l(&[0x8A, 0x07]), Some(insn(2, false, 1, 0, 1, Move)));
    assert_eq!(l(&[0x88, 0x17]), Some(insn(2, true, 1, 2, 1, Move)));
    assert_eq!(l(&[0x40, 0x88, 0x37]), Some(insn(3, true, 1, 6, 1, Move)));
    // mov [rdi], ah: without REX the byte registers 4..7 are AH, CH, DH, BH.
    assert_eq!(l(&[0x88, 0x27]), Some(Insn { high8: true, ..insn(2, true, 1, 0, 1, Move) }));
    // mov dword [rdi], 0x12345678; mov word [rdi], 0x1234; mov byte [rdi], 0x7F.
    assert_eq!(l(&[0xC7, 0x07, 0x78, 0x56, 0x34, 0x12]),
               Some(Insn { imm: Some(0x1234_5678), ..insn(6, true, 4, 0, 4, Move) }));
    assert_eq!(l(&[0x66, 0xC7, 0x07, 0x34, 0x12]), Some(Insn { imm: Some(0x1234), ..insn(5, true, 2, 0, 2, Move) }));
    assert_eq!(l(&[0xC6, 0x07, 0x7F]), Some(Insn { imm: Some(0x7F), ..insn(3, true, 1, 0, 1, Move) }));
    // mov qword [rdi], -1: imm32 sign-extended to 64 bits.
    assert_eq!(l(&[0x48, 0xC7, 0x07, 0xFF, 0xFF, 0xFF, 0xFF]),
               Some(Insn { imm: Some(u64::MAX), ..insn(7, true, 8, 0, 8, Move) }));
    // movzx eax, byte [rdi]; movzx eax, word [rdi]; movsx rax, byte [rdi]; movsx eax, word [rdi]; movsxd rax, dword [rdi].
    assert_eq!(l(&[0x0F, 0xB6, 0x07]), Some(insn(3, false, 1, 0, 4, Zero)));
    assert_eq!(l(&[0x0F, 0xB7, 0x07]), Some(insn(3, false, 2, 0, 4, Zero)));
    assert_eq!(l(&[0x48, 0x0F, 0xBE, 0x07]), Some(insn(4, false, 1, 0, 8, Sign)));
    assert_eq!(l(&[0x0F, 0xBF, 0x07]), Some(insn(3, false, 2, 0, 4, Sign)));
    assert_eq!(l(&[0x48, 0x63, 0x07]), Some(insn(3, false, 4, 0, 8, Sign)));
    // 32-bit protected mode, where AzOS's PVH entry runs: no REX, a bare disp32.
    assert_eq!(mmio::decode(&[0x89, 0x05, 0x00, 0x00, 0x00, 0xFE], Mode::Prot32), Some(insn(6, true, 4, 0, 4, Move)));
    // In 32-bit mode 0x40..0x4F are INC / DEC, not REX: not a MOV.
    assert_eq!(mmio::decode(&[0x44, 0x89, 0x0C, 0x88], Mode::Prot32), None);
}

#[test]
fn what_is_not_a_plain_mov_to_memory_is_not_decoded() {
    let l = |b: &[u8]| mmio::decode(b, Mode::Long);
    assert_eq!(l(&[0x8B, 0xC3]), None, "mov eax, ebx: a register operand");
    assert_eq!(l(&[0x09, 0x07]), None, "or [rdi], eax: a read-modify-write");
    assert_eq!(l(&[0x01, 0x07]), None, "add [rdi], eax");
    assert_eq!(l(&[0xF3, 0xA5]), None, "rep movsd");
    assert_eq!(l(&[0xA5]), None, "movsd");
    assert_eq!(l(&[0xF0, 0x89, 0x07]), None, "lock");
    assert_eq!(l(&[0xC7, 0x0F, 0, 0, 0, 0]), None, "C7 /1 is not a MOV");
    assert_eq!(l(&[0x0F, 0x10, 0x07]), None, "movups");
    assert_eq!(l(&[0x0F, 0x1F, 0x07]), None, "nop");
    assert_eq!(l(&[0x63, 0x07]), None, "movsxd without REX.W is a plain move of a 32-bit pointer");
    assert_eq!(l(&[0x89]), None, "truncated");
    assert_eq!(l(&[0x89, 0x47]), None, "truncated disp8");
    assert_eq!(l(&[0xC7, 0x07, 0x78, 0x56]), None, "truncated immediate");
    assert_eq!(l(&[]), None);
    assert_eq!(mmio::decode(&[0x67, 0x8B, 0x07], Mode::Prot32), None, "16-bit addressing");
    // A REX followed by another prefix is not an instruction the decoder knows.
    assert_eq!(l(&[0x48, 0x66, 0x89, 0x07]), None);
    // Longer than 15 bytes of prefixes.
    let mut long = vec![0x66; 15];
    long.extend_from_slice(&[0x89, 0x07]);
    assert_eq!(l(&long), None);
}

#[test]
fn a_load_writes_the_register_the_way_the_instruction_does() {
    let run = |i: Insn, old: u64, value: u64| -> (u64, u64) {
        let mut v = Vmcb::new();
        v.wr64(off::RIP, 0x1000);
        let mut r = GuestRegs { rbx: old, ..GuestRegs::default() };
        let i = Insn { reg: 3, ..i };
        mmio::complete_load(&i, &mut v, &mut r, value);
        (r.rbx, v.rd64(off::RIP))
    };
    let all = 0xAAAA_BBBB_CCCC_DDDDu64;
    // mov r64: all of it. mov r32: the upper half is cleared. mov r16, mov r8: the rest stays.
    assert_eq!(run(insn(3, false, 8, 0, 8, Extend::Move), all, 0x1122_3344_5566_7788), (0x1122_3344_5566_7788, 0x1003));
    assert_eq!(run(insn(3, false, 4, 0, 4, Extend::Move), all, 0x1122_3344), (0x1122_3344, 0x1003));
    assert_eq!(run(insn(3, false, 2, 0, 2, Extend::Move), all, 0x1122), (0xAAAA_BBBB_CCCC_1122, 0x1003));
    assert_eq!(run(insn(2, false, 1, 0, 1, Extend::Move), all, 0x11), (0xAAAA_BBBB_CCCC_DD11, 0x1002));
    // AH, CH, DH, BH are bits 15:8.
    assert_eq!(run(Insn { high8: true, ..insn(2, false, 1, 0, 1, Extend::Move) }, all, 0x11), (0xAAAA_BBBB_CCCC_11DD, 0x1002));
    // movzx / movsx into a 32-bit register clear the upper half; a sign bit extends.
    assert_eq!(run(insn(3, false, 1, 0, 4, Extend::Zero), all, 0x80), (0x80, 0x1003));
    assert_eq!(run(insn(3, false, 1, 0, 4, Extend::Sign), all, 0x80), (0xFFFF_FF80, 0x1003));
    assert_eq!(run(insn(4, false, 1, 0, 8, Extend::Sign), all, 0x80), (0xFFFF_FFFF_FFFF_FF80, 0x1004));
    assert_eq!(run(insn(3, false, 2, 0, 4, Extend::Sign), all, 0x7FFF), (0x7FFF, 0x1003));
    assert_eq!(run(insn(3, false, 2, 0, 4, Extend::Sign), all, 0x8000), (0xFFFF_8000, 0x1003));
    assert_eq!(run(insn(3, false, 4, 0, 8, Extend::Sign), all, 0x8000_0000), (0xFFFF_FFFF_8000_0000, 0x1003));
    // movsx into a 16-bit register merges.
    assert_eq!(run(insn(4, false, 1, 0, 2, Extend::Sign), all, 0xFF), (0xAAAA_BBBB_CCCC_FFFF, 0x1004));
    // A value wider than the access is cut to it.
    assert_eq!(run(insn(3, false, 1, 0, 4, Extend::Zero), all, 0x1FF), (0xFF, 0x1003));
    // rax and rsp live in the VMCB.
    let mut v = Vmcb::new();
    let mut r = GuestRegs::default();
    v.wr64(off::RAX, u64::MAX);
    mmio::complete_load(&insn(3, false, 4, 0, 4, Extend::Move), &mut v, &mut r, 5);
    assert_eq!(v.rd64(off::RAX), 5);
    mmio::complete_load(&insn(3, false, 8, 4, 8, Extend::Move), &mut v, &mut r, 0x7000);
    assert_eq!(v.rd64(off::RSP), 0x7000);
}

#[test]
fn a_store_reads_the_register_or_the_immediate() {
    let mut v = Vmcb::new();
    v.wr64(off::RAX, 0x1122_3344_5566_7788);
    let r = GuestRegs { rdx: 0xAABB_CCDD_EEFF_0011, r9: 0x99, ..GuestRegs::default() };
    let st = |reg, size, high8| Insn { high8, ..insn(2, true, size, reg, size, Extend::Move) };
    assert_eq!(mmio::store_value(&st(0, 8, false), &v, &r), 0x1122_3344_5566_7788);
    assert_eq!(mmio::store_value(&st(0, 4, false), &v, &r), 0x5566_7788);
    assert_eq!(mmio::store_value(&st(0, 2, false), &v, &r), 0x7788);
    assert_eq!(mmio::store_value(&st(0, 1, false), &v, &r), 0x88);
    assert_eq!(mmio::store_value(&st(0, 1, true), &v, &r), 0x77, "AH");
    assert_eq!(mmio::store_value(&st(2, 1, true), &v, &r), 0x00, "DH");
    assert_eq!(mmio::store_value(&st(9, 4, false), &v, &r), 0x99);
    assert_eq!(mmio::store_value(&Insn { imm: Some(0x42), ..st(0, 4, false) }, &v, &r), 0x42);
}

/// 64-bit mode with the first 2 MiB identity-mapped by the guest's own tables
/// (PML4 at 0x1000, PDPT at 0x2000, PD at 0x3000 with one 2 MiB leaf).
fn long_mode(c: &mut Cpu) {
    c.ram.put64(0x1000, 0x2000 | 3);
    c.ram.put64(0x2000, 0x3000 | 3);
    c.ram.put64(0x3000, 0x83);
    c.v.wr64(off::CR3, 0x1000);
    c.v.wr64(off::CR4, 1 << 5);
    c.v.wr64(off::CR0, 0x8001_0011);
    c.v.wr64(off::EFER, efer::SVME | LME | LMA | NXE);
    // CS: P S code, accessed, L (bit 9 of the attribute word).
    c.v.set_segment(off::CS, 0x8, 0x29B, 0xFFFF_FFFF, 0);
}

/// The guest is about to run `code` at `rip`.
fn code_at(c: &mut Cpu, rip: u64, code: &[u8]) {
    c.ram.put(rip, code);
    c.v.wr64(off::RIP, rip);
}

impl Cpu {
    /// A nested page fault on `gpa`: not present, the final translation (EXITINFO1 bit 32), a write or a read.
    fn fault(&mut self, gpa: u64, write: bool, vm: &mut Vm) -> Served {
        let info1 = (write as u64) << 1 | 1 << 32;
        let e = exit::svm(code::NPF, info1, gpa);
        let mut port = Port { vm, idx: self.s.id as usize };
        let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &self.ram, host_tsc: 1_000_000 };
        self.s.serve(e, &mut self.v, &mut self.r, &mut env)
    }
}

const VIRTIO: u64 = 0x1000_1000;

#[test]
fn the_guests_page_tables_are_walked_to_fetch_the_instruction() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // mov eax, [rdi]: the fault is a read at a virtio-mmio register.
    code_at(&mut c, 0x4000, &[0x8B, 0x07]);
    c.r.rdi = VIRTIO;
    let s = c.fault(VIRTIO, false, &mut vm);
    let access = MmioAccess { gpa: VIRTIO, size: 4, write: false, reg: 0, insn_len: 2 };
    assert_eq!(s, Served::Mmio { access, value: 0 });
    // The monitor hands the device's answer back: the register is written and RIP steps past.
    assert!(c.s.finish_mmio(&mut c.v, &mut c.r, 0x7472_6976), "the magic value 'virt'");
    assert_eq!(c.v.rd64(off::RAX), 0x7472_6976);
    assert_eq!(c.v.rd64(off::RIP), 0x4002);
    assert!(!c.s.finish_mmio(&mut c.v, &mut c.r, 0), "nothing was waiting");
}

#[test]
fn a_store_to_a_device_register_carries_its_value_and_is_stepped_over_at_the_answer() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // mov [rdi+0x70], edx (VIRTIO_MMIO_STATUS = 0x70).
    code_at(&mut c, 0x4000, &[0x89, 0x57, 0x70]);
    c.r.rdx = 0xFFFF_FFFF_0000_000F;
    let s = c.fault(VIRTIO + 0x70, true, &mut vm);
    assert_eq!(s, Served::Mmio {
        access: MmioAccess { gpa: VIRTIO + 0x70, size: 4, write: true, reg: 2, insn_len: 3 },
        value: 0xF,
    });
    assert_eq!(c.v.rd64(off::RIP), 0x4000, "not stepped over until the device model has it");
    assert!(c.s.finish_mmio(&mut c.v, &mut c.r, 0));
    assert_eq!(c.v.rd64(off::RIP), 0x4003);
    // A store of an immediate: mov dword [rdi+0x50], 3 (QUEUE_NOTIFY).
    code_at(&mut c, 0x4010, &[0xC7, 0x47, 0x50, 3, 0, 0, 0]);
    let s = c.fault(VIRTIO + 0x50, true, &mut vm);
    assert!(matches!(s, Served::Mmio { value: 3, access: MmioAccess { size: 4, write: true, insn_len: 7, .. } }), "{s:?}");
}

#[test]
fn the_cpus_own_copy_of_the_instruction_is_used_when_it_is_there() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // Nothing in RAM at RIP (the page walk would fetch zeros: not an instruction), but the VMCB has the bytes.
    c.v.wr64(off::RIP, 0x5000);
    c.v.wr8(0xD0, 2);
    c.v.wr8(0xD1, 0x8B);
    c.v.wr8(0xD2, 0x07);
    let s = c.fault(VIRTIO, false, &mut vm);
    assert!(matches!(s, Served::Mmio { access: MmioAccess { size: 4, insn_len: 2, .. }, .. }), "{s:?}");
}

#[test]
fn a_fault_that_is_not_a_device_access_goes_back_to_the_loop() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    code_at(&mut c, 0x4000, &[0x8B, 0x07]);
    let e = |info1: u64| exit::svm(code::NPF, info1, VIRTIO);
    let serve = |c: &mut Cpu, vm: &mut Vm, e: Exit| {
        let mut port = Port { vm, idx: 0 };
        let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &c.ram, host_tsc: 0 };
        c.s.serve(e, &mut c.v, &mut c.r, &mut env)
    };
    // Present (a permission fault on mapped memory), an instruction fetch, a fault on the guest's page tables.
    for (what, info1) in [("present", 1 | 1 << 32), ("fetch", 1 << 4 | 1 << 32), ("page table", 1 << 33)] {
        let x = e(info1);
        assert_eq!(serve(&mut c, &mut vm, x), Served::Unserved(x), "{what}");
    }
    // The instruction is a load but the fault was a write: the bytes are not the instruction that faulted.
    let x = e(1 << 1 | 1 << 32);
    assert_eq!(serve(&mut c, &mut vm, x), Served::Unserved(x));
    // An instruction the decoder does not know (rep movsd).
    code_at(&mut c, 0x4000, &[0xF3, 0xA5]);
    let x = e(1 << 32);
    assert_eq!(serve(&mut c, &mut vm, x), Served::Unserved(x));
    // Real mode (an AP before it enabled protected mode): not decoded.
    let mut ap = cpu(1, 2);
    ap.ram.put(0x4000, &[0x8B, 0x07]);
    ap.v.wr64(off::RIP, 0x4000);
    let x = e(1 << 32);
    let mut port = Port { vm: &mut vm, idx: 1 };
    let mut env = Env { host_cpuid: &zen3, apic: &mut port, mem: &ap.ram, host_tsc: 0 };
    assert_eq!(ap.s.serve(x, &mut ap.v, &mut ap.r, &mut env), Served::Unserved(x));
    // No instruction could be read (RIP unmapped, no CPU copy).
    let mut d = cpu(0, 1);
    long_mode(&mut d);
    d.v.wr64(off::RIP, 0x40_0000);
    assert_eq!(serve(&mut d, &mut vm, x), Served::Unserved(x));
}

#[test]
fn the_page_walk_follows_the_guests_tables() {
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // A 4 KiB mapping: VA 0x7000_0000_0000 -> PA 0x5000 through PML4[0xE0] ... a fresh chain at 0x10000.
    let va = 0x0000_7000_0000_0000u64;
    let (pdpt, pd, pt) = (0x10000, 0x11000, 0x12000);
    let idx = |l: u32| (va >> (12 + 9 * l)) & 0x1FF;
    c.ram.put64(0x1000 + idx(3) * 8, pdpt | 3);
    c.ram.put64(pdpt + idx(2) * 8, pd | 3);
    c.ram.put64(pd + idx(1) * 8, pt | 3);
    c.ram.put64(pt + idx(0) * 8, 0x5000 | 3);
    assert_eq!(mmio::translate(&c.v, &c.ram, va + 0x123), Some(0x5123));
    // Not present at any level.
    assert_eq!(mmio::translate(&c.v, &c.ram, va + 0x1000), None);
    assert_eq!(mmio::translate(&c.v, &c.ram, 0x0000_6000_0000_0000), None);
    // The 2 MiB leaf the fixture maps.
    assert_eq!(mmio::translate(&c.v, &c.ram, 0x1_2345), Some(0x1_2345));
    // A 1 GiB leaf.
    c.ram.put64(0x2000 + 8, 0x4000_0000 | 0x83);
    assert_eq!(mmio::translate(&c.v, &c.ram, 0x4000_0000 + 0x12_3456), Some(0x4000_0000 + 0x12_3456));
    // Not canonical.
    assert_eq!(mmio::translate(&c.v, &c.ram, 0x0001_0000_0000_0000), None);
    // Paging off is the identity; 32-bit paging is not walked.
    let mut p = cpu(0, 1);
    assert_eq!(mmio::translate(&p.v, &p.ram, 0xFEC0_0000), Some(0xFEC0_0000));
    p.v.wr64(off::CR0, 0x8000_0011);
    assert_eq!(mmio::translate(&p.v, &p.ram, 0x1000), None);
}

#[test]
fn an_instruction_across_a_page_is_read_from_both_pages_or_as_far_as_the_first() {
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // Map VA 0x7F000 -> PA 0x20000 and 0x80000 -> PA 0x30000 with 4 KiB pages, replacing the 2 MiB leaf.
    c.ram.put64(0x3000, 0x4000 | 3);
    c.ram.put64(0x4000 + 0x7F * 8, 0x20000 | 3);
    c.ram.put64(0x4000 + 0x80 * 8, 0x30000 | 3);
    c.ram.put(0x20000 + 0xFFE, &[0x8B, 0x47]);
    c.ram.put(0x30000, &[0x10]);
    c.v.wr64(off::RIP, 0x7F000 + 0xFFE);
    let (code, n) = mmio::fetch(&c.v, &c.ram, Mode::Long, true).unwrap();
    assert_eq!(n, 15);
    assert_eq!(&code[..3], &[0x8B, 0x47, 0x10]);
    assert_eq!(mmio::decode(&code[..n], Mode::Long), Some(insn(3, false, 4, 0, 4, Extend::Move)));
    // The next page unmapped: only what the first holds.
    c.ram.put64(0x4000 + 0x80 * 8, 0);
    let (_, n) = mmio::fetch(&c.v, &c.ram, Mode::Long, true).unwrap();
    assert_eq!(n, 2);
    assert_eq!(mmio::decode(&[0x8B, 0x47], Mode::Long), None, "which is not the whole instruction");
}

#[test]
fn the_ioapic_window_and_the_xapic_page_are_answered_without_a_device_model() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // The guest programs pin 5 as AzOS's ioapic::route does: IOREGSEL <- 0x10 + 2*5, IOWIN <- value; twice.
    // mov [rdi], eax (IOREGSEL at +0x00) and mov [rdi+0x10], edx (IOWIN) are both 32-bit stores.
    let store_sel = [0x89, 0x07];
    let store_win = [0x89, 0x57, 0x10];
    let mut at = 0x4000;
    let mut program = |c: &mut Cpu, vm: &mut Vm, reg: u32, val: u32| {
        c.v.wr64(off::RAX, reg as u64);
        c.r.rdx = val as u64;
        code_at(c, at, &store_sel);
        assert_eq!(c.fault(IOAPIC_DEFAULT_BASE, true, vm), Served::Resume);
        assert_eq!(c.v.rd64(off::RIP), at + 2, "stepped over");
        code_at(c, at + 2, &store_win);
        assert_eq!(c.fault(IOAPIC_DEFAULT_BASE + 0x10, true, vm), Served::Resume);
        assert_eq!(c.v.rd64(off::RIP), at + 5);
        at += 8;
    };
    program(&mut c, &mut vm, rte_lo(5), 1 << 16);
    program(&mut c, &mut vm, rte_lo(5) + 1, 0);
    program(&mut c, &mut vm, rte_lo(5), 0x35 | 1 << 15);
    // A read back: mov ecx, [rdi+0x10] after selecting the entry.
    c.v.wr64(off::RAX, rte_lo(5) as u64);
    code_at(&mut c, at, &store_sel);
    c.fault(IOAPIC_DEFAULT_BASE, true, &mut vm);
    code_at(&mut c, at + 2, &[0x8B, 0x4F, 0x10]);
    assert_eq!(c.fault(IOAPIC_DEFAULT_BASE + 0x10, false, &mut vm), Served::Resume);
    assert_eq!(c.r.rcx, 0x35 | 1 << 15, "the redirection entry reads back");
    // The device model raises line 5: the vector reaches the vCPU.
    x2apic_up(&mut vm, 0);
    c.v.wr64(off::RFLAGS, 2 | 1 << 9);
    assert_eq!(pulse_lines(&mut vm.apics, &mut vm.io, 1 << 5), 1);
    assert_eq!(c.enters(&mut vm, 0), Entry::Run);
    assert_eq!(injected(&c.v), Some((0x35, 0)));
}

#[test]
fn the_xapic_page_is_served_while_the_guest_has_the_apic_in_xapic_mode() {
    let mut vm = vm(1);
    let mut c = cpu(0, 1);
    long_mode(&mut c);
    // xAPIC mode (the reset state): the version register reads 0x0006_0014; the page is at 0xFEE00000.
    code_at(&mut c, 0x4000, &[0x8B, 0x07]);
    assert_eq!(c.fault(APIC_DEFAULT_BASE + 0x30, false, &mut vm), Served::Resume);
    assert_eq!(c.v.rd64(off::RAX), 0x0006_0014);
    // Software-enable (SVR at +0xF0) and program the TPR through mov [rdi+0x80], eax.
    c.v.wr64(off::RAX, 0x1FF);
    code_at(&mut c, 0x4010, &[0x89, 0x87, 0xF0, 0, 0, 0]);
    assert_eq!(c.fault(APIC_DEFAULT_BASE + 0xF0, true, &mut vm), Served::Resume);
    assert_eq!(vm.apics[0].mmio_read(APIC_DEFAULT_BASE + 0xF0, 4, 0), Ok(0x1FF), "the store reached the SVR");
    assert_eq!(vm.apics[0].msr_read(0x80F, 0), Err(azos_hv::vlapic::Fault), "x2APIC MSRs are not served in xAPIC mode");
    // Once the guest moves to x2APIC the page no longer is: the access goes back to the loop.
    vm.apics[0].msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | 1 << 8 | 1 << 11 | 1 << 10, 0).unwrap();
    code_at(&mut c, 0x4020, &[0x8B, 0x07]);
    assert!(matches!(c.fault(APIC_DEFAULT_BASE + 0x30, false, &mut vm), Served::Mmio { .. }));
}
