// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the pure half of the x86_64 platform.
//!
//! **WHY.** None of this can be checked in QEMU yet, and its mistakes are
//! silent: a MADT walk that drops a CPU leaves it parked forever, a wrong
//! redirection-entry bit routes a line to another CPU or the wrong trigger,
//! a wrong clock scale stretches every TIMER_FREQ timeout in the tree. The
//! tables here are synthetic, built byte by byte to the ACPI 6.x layouts,
//! with real checksums; a test that corrupts one checks it is refused.

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/acpi.rs"]
mod acpi;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/bootinfo.rs"]
mod bootinfo;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/encode.rs"]
mod encode;

#[cfg(test)]
mod tests {
    use super::acpi::{self, AcpiError, AcpiInfo, Madt, PhysMem};
    use super::bootinfo::{self, MemEntry, VirtioMmio};
    use super::encode::{self, Scale, TimerMode};

    // ── synthetic physical memory ───────────────────────────────────────

    #[derive(Default)]
    struct Mem(Vec<(u64, Vec<u8>)>);

    impl Mem {
        fn put(&mut self, pa: u64, bytes: Vec<u8>) {
            self.0.push((pa, bytes));
        }
    }

    impl PhysMem for Mem {
        fn read(&self, pa: u64, len: usize) -> Option<&[u8]> {
            self.0.iter().find_map(|(base, b)| {
                let off = pa.checked_sub(*base)? as usize;
                b.get(off..off.checked_add(len)?)
            })
        }
    }

    fn fix_checksum(b: &mut [u8], at: usize) {
        b[at] = 0;
        let sum = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[at] = 0u8.wrapping_sub(sum);
    }

    /// An SDT: 36-byte header + `body`, length and checksum filled in.
    fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(sig);
        t.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
        t.push(1); // revision
        t.push(0); // checksum
        t.extend_from_slice(b"AZOSTS");
        t.extend_from_slice(b"SYNTHTBL");
        t.extend_from_slice(&1u32.to_le_bytes());
        t.extend_from_slice(b"AZOS");
        t.extend_from_slice(&1u32.to_le_bytes());
        t.extend_from_slice(body);
        fix_checksum(&mut t, 9);
        t
    }

    fn rsdp_v2(xsdt: u64, rsdt: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"RSD PTR ");
        r.push(0);
        r.extend_from_slice(b"AZOSTS");
        r.push(2);
        r.extend_from_slice(&rsdt.to_le_bytes());
        r.extend_from_slice(&36u32.to_le_bytes());
        r.extend_from_slice(&xsdt.to_le_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        fix_checksum(&mut r[..20], 8);
        fix_checksum(&mut r, 32);
        r
    }

    fn rsdp_v1(rsdt: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"RSD PTR ");
        r.push(0);
        r.extend_from_slice(b"AZOSTS");
        r.push(0);
        r.extend_from_slice(&rsdt.to_le_bytes());
        fix_checksum(&mut r, 8);
        r
    }

    fn lapic(uid: u8, id: u8, flags: u32) -> Vec<u8> {
        let mut e = vec![0, 8, uid, id];
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }
    fn x2apic(id: u32, uid: u32, flags: u32) -> Vec<u8> {
        let mut e = vec![9, 16, 0, 0];
        e.extend_from_slice(&id.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e.extend_from_slice(&uid.to_le_bytes());
        e
    }
    fn ioapic(id: u8, addr: u32, gsi_base: u32) -> Vec<u8> {
        let mut e = vec![1, 12, id, 0];
        e.extend_from_slice(&addr.to_le_bytes());
        e.extend_from_slice(&gsi_base.to_le_bytes());
        e
    }
    fn iso(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut e = vec![2, 10, 0, source];
        e.extend_from_slice(&gsi.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }
    fn lapic_nmi(uid: u8, flags: u16, lint: u8) -> Vec<u8> {
        let mut e = vec![4, 6, uid];
        e.extend_from_slice(&flags.to_le_bytes());
        e.push(lint);
        e
    }

    fn madt_body(lapic_addr: u32, flags: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&lapic_addr.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        for e in entries {
            b.extend_from_slice(e);
        }
        b
    }

    fn hpet_body(addr: u64) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0..4].copy_from_slice(&0x8086_A201u32.to_le_bytes());
        b[4] = 0; // GAS: system memory
        b[5] = 64;
        b[8..16].copy_from_slice(&addr.to_le_bytes());
        b[16] = 0; // HPET number
        b[17..19].copy_from_slice(&0x80u16.to_le_bytes());
        b
    }

    fn mcfg_body(base: u64, seg: u16, b0: u8, b1: u8) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&base.to_le_bytes());
        b.extend_from_slice(&seg.to_le_bytes());
        b.push(b0);
        b.push(b1);
        b.extend_from_slice(&[0; 4]);
        b
    }

    const RSDP: u64 = 0xF_0000;
    const ROOT: u64 = 0x7FE_0000;
    const MADT_PA: u64 = 0x7FE_1000;
    const HPET_PA: u64 = 0x7FE_2000;
    const MCFG_PA: u64 = 0x7FE_3000;

    /// A two-CPU microvm-like machine: LAPICs 0 and 1, two IOAPICs (GSI 0
    /// and 24), the ISA IRQ 0 -> GSI 2 override, a LINT1 NMI, HPET, MCFG.
    fn machine(xsdt: bool) -> Mem {
        let mut m = Mem::default();
        let madt = sdt(b"APIC", &madt_body(0xFEE0_0000, 1, &[
            lapic(0, 0, 1),
            lapic(1, 1, 1),
            ioapic(0, 0xFEC0_0000, 0),
            ioapic(1, 0xFEC1_0000, 24),
            iso(0, 2, 0),
            iso(9, 9, 0b1111),
            lapic_nmi(0xFF, 0, 1),
        ]));
        let ptrs = [MADT_PA, HPET_PA, MCFG_PA];
        let root = if xsdt {
            let mut b = Vec::new();
            ptrs.iter().for_each(|p| b.extend_from_slice(&p.to_le_bytes()));
            sdt(b"XSDT", &b)
        } else {
            let mut b = Vec::new();
            ptrs.iter().for_each(|p| b.extend_from_slice(&(*p as u32).to_le_bytes()));
            sdt(b"RSDT", &b)
        };
        m.put(RSDP, if xsdt { rsdp_v2(ROOT, 0) } else { rsdp_v1(ROOT as u32) });
        m.put(ROOT, root);
        m.put(MADT_PA, madt);
        m.put(HPET_PA, sdt(b"HPET", &hpet_body(0xFED0_0000)));
        m.put(MCFG_PA, sdt(b"MCFG", &mcfg_body(0xB000_0000, 0, 0, 255)));
        m
    }

    fn parse(m: &Mem) -> Result<Box<AcpiInfo>, AcpiError> {
        let mut info = Box::new(AcpiInfo::EMPTY);
        acpi::parse(m, RSDP, &mut info).map(|()| info)
    }

    // ── ACPI ────────────────────────────────────────────────────────────

    #[test]
    fn xsdt_machine_parses_every_table() {
        let info = parse(&machine(true)).unwrap();
        assert!(info.xsdt);
        assert_eq!(info.revision, 2);
        assert_eq!(info.bad_tables, 0);
        let madt = info.madt.as_ref().unwrap();
        assert_eq!(madt.lapic_addr, 0xFEE0_0000);
        assert_eq!(madt.flags & 1, 1);
        assert_eq!(madt.cpus().iter().map(|c| c.apic_id).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(madt.ioapics().len(), 2);
        assert_eq!(madt.ioapics()[1].addr, 0xFEC1_0000);
        assert_eq!(madt.ioapics()[1].gsi_base, 24);
        assert_eq!(madt.nmis()[0].lint, 1);
        assert_eq!(madt.nmis()[0].uid, u32::MAX);
        assert_eq!(info.hpet.unwrap().addr, 0xFED0_0000);
        assert_eq!(info.mcfg()[0].base, 0xB000_0000);
        assert_eq!(info.mcfg()[0].size(), 256 << 20);
        // RSDP, XSDT, MADT, HPET, MCFG: each one's pages are reserved.
        assert_eq!(info.n_tables, 5);
    }

    #[test]
    fn rsdt_machine_parses_the_same() {
        let info = parse(&machine(false)).unwrap();
        assert!(!info.xsdt);
        assert_eq!(info.madt.as_ref().unwrap().n_cpus, 2);
        assert!(info.hpet.is_some());
    }

    #[test]
    fn overrides_carry_trigger_and_polarity() {
        let info = parse(&machine(true)).unwrap();
        let madt = info.madt.as_ref().unwrap();
        let timer = madt.iso_for(0).unwrap();
        assert_eq!((timer.gsi, timer.level(), timer.active_low()), (2, None, None));
        let sci = madt.iso_for(9).unwrap();
        assert_eq!((sci.level(), sci.active_low()), (Some(true), Some(true)));
        assert!(madt.iso_for(4).is_none());
    }

    #[test]
    fn a_bad_rsdp_checksum_is_refused() {
        let mut m = machine(true);
        m.0[0].1[8] ^= 1;
        assert_eq!(parse(&m).err(), Some(AcpiError::BadRsdp));
        // Canary: the same machine untouched parses.
        assert!(parse(&machine(true)).is_ok());
    }

    #[test]
    fn a_bad_table_checksum_is_skipped_not_trusted() {
        let mut m = machine(true);
        let madt = m.0.iter_mut().find(|(pa, _)| *pa == MADT_PA).unwrap();
        madt.1[40] ^= 0x40; // a flags bit, checksum now wrong
        let info = parse(&m).unwrap();
        assert!(info.madt.is_none());
        assert_eq!(info.bad_tables, 1);
        assert!(info.hpet.is_some());
    }

    #[test]
    fn a_truncated_table_is_skipped() {
        let mut m = machine(true);
        let madt = m.0.iter_mut().find(|(pa, _)| *pa == MADT_PA).unwrap();
        let n = madt.1.len();
        madt.1.truncate(n - 4); // header length now runs past readable memory
        let info = parse(&m).unwrap();
        assert!(info.madt.is_none());
        assert_eq!(info.bad_tables, 1);
    }

    #[test]
    fn no_rsdp_is_reported() {
        let m = Mem::default();
        assert_eq!(parse(&m).err(), Some(AcpiError::NoRsdp));
    }

    #[test]
    fn rsdp_scan_finds_the_bios_area_copy() {
        let mut m = Mem::default();
        m.put(0x40E, vec![0, 0]); // no EBDA
        let mut area = vec![0u8; 0x2_0000];
        let at = 0x0_5A30; // 16-byte aligned, inside 0xE0000..0x100000
        let r = rsdp_v1(0x1234);
        area[at..at + r.len()].copy_from_slice(&r);
        m.put(0xE_0000, area);
        assert_eq!(acpi::find_rsdp(&m), Some(0xE_0000 + at as u64));
    }

    #[test]
    fn madt_entry_with_short_length_stops_the_walk() {
        let body = madt_body(0xFEE0_0000, 0, &[lapic(0, 0, 1), vec![0, 1], lapic(1, 1, 1)]);
        let t = sdt(b"APIC", &body);
        let mut m = Box::new(Madt::EMPTY);
        acpi::parse_madt(&t, &mut m);
        assert_eq!(m.n_cpus, 1);
        assert_eq!(m.malformed, 1);
    }

    #[test]
    fn disabled_cpus_are_left_out_and_x2apic_duplicates_merge() {
        let body = madt_body(0xFEE0_0000, 0, &[
            lapic(0, 0, 1),
            lapic(1, 1, 0),          // disabled
            lapic(2, 2, 0b10),       // online-capable (hot-plug), not present
            x2apic(0, 0, 1),         // the same CPU as LAPIC 0
            x2apic(300, 3, 1),       // beyond 8-bit IDs
        ]);
        let t = sdt(b"APIC", &body);
        let mut m = Box::new(Madt::EMPTY);
        acpi::parse_madt(&t, &mut m);
        assert_eq!(m.cpus().iter().map(|c| c.apic_id).collect::<Vec<_>>(), [0, 300]);
    }

    #[test]
    fn the_boot_cpu_becomes_cpu_zero() {
        let body = madt_body(0, 0, &[lapic(0, 4, 1), lapic(1, 7, 1), lapic(2, 2, 1)]);
        let t = sdt(b"APIC", &body);
        let mut m = Box::new(Madt::EMPTY);
        acpi::parse_madt(&t, &mut m);
        assert!(m.boot_cpu_first(2));
        assert_eq!(m.cpus().iter().map(|c| c.apic_id).collect::<Vec<_>>(), [2, 4, 7]);
        assert!(!m.boot_cpu_first(9));
    }

    #[test]
    fn lapic_address_override_wins() {
        let mut ovr = vec![5, 12, 0, 0];
        ovr.extend_from_slice(&0x1_FEE0_0000u64.to_le_bytes());
        let t = sdt(b"APIC", &madt_body(0xFEE0_0000, 0, &[ovr]));
        let mut m = Box::new(Madt::EMPTY);
        acpi::parse_madt(&t, &mut m);
        assert_eq!(m.lapic_addr, 0x1_FEE0_0000);
    }

    // ── PVH memory map, command line, trampoline ────────────────────────

    fn e(addr: u64, size: u64, kind: u32) -> MemEntry {
        MemEntry { addr, size, kind, reserved: 0 }
    }

    /// QEMU microvm, -m 128M.
    fn microvm_map() -> Vec<MemEntry> {
        vec![
            e(0, 0x9_FC00, 1),
            e(0x9_FC00, 0x400, 2),
            e(0xF_0000, 0x1_0000, 2),
            e(0x10_0000, 0x7F0_0000, 1),
            e(0xFEFF_C000, 0x4000, 2),
        ]
    }

    #[test]
    fn ram_span_ends_at_the_top_of_ram() {
        assert_eq!(bootinfo::ram_span(&microvm_map(), u64::MAX), Some((0, 0x800_0000)));
        assert_eq!(bootinfo::ram_span(&microvm_map(), 0x400_0000), Some((0, 0x400_0000)));
        assert_eq!(bootinfo::ram_span(&[e(0, 0, 1), e(0x1000, 0x1000, 2)], u64::MAX), None);
    }

    #[test]
    fn holes_cover_everything_that_is_not_ram() {
        let mut holes = Vec::new();
        bootinfo::for_each_hole(&microvm_map(), 0x800_0000, |s, l| holes.push((s, l)));
        // The partial page at 0x9F000 is not RAM; 0x9F000..0x100000 is one hole.
        assert_eq!(holes, [(0x9_F000, 0x6_1000)]);
    }

    #[test]
    fn holes_handle_unsorted_overlapping_and_absent_ranges() {
        let map = [e(0x20_0000, 0x10_0000, 1), e(0, 0x8_0000, 1), e(0x4_0000, 0x8_0000, 1), e(0x50_0000, 0x1000, 3)];
        let mut holes = Vec::new();
        bootinfo::for_each_hole(&map, 0x60_0000, |s, l| holes.push((s, l)));
        assert_eq!(holes, [(0xC_0000, 0x14_0000), (0x30_0000, 0x30_0000)]);
    }

    #[test]
    fn trampoline_avoids_boot_information() {
        let map = microvm_map();
        // The highest free page under 640 KiB.
        assert_eq!(bootinfo::pick_trampoline(&map, &[], 0), Some(0x9_E000));
        // ...unless the start_info sits there.
        assert_eq!(bootinfo::pick_trampoline(&map, &[(0x9_E000, 0x1000)], 0), Some(0x9_D000));
        // A forced page is checked like any other.
        assert_eq!(bootinfo::pick_trampoline(&map, &[], 0x8000), Some(0x8000));
        assert_eq!(bootinfo::pick_trampoline(&map, &[(0x8000, 0x10)], 0x8000), None);
        assert_eq!(bootinfo::pick_trampoline(&map, &[], 0xF_0000), None); // reserved BIOS
        assert_eq!(bootinfo::pick_trampoline(&map, &[], 0x8100), None); // unaligned
        assert_eq!(bootinfo::pick_trampoline(&map, &[], 0x10_0000), None); // above 1 MiB
    }

    #[test]
    fn virtio_mmio_cmdline_entries_parse() {
        let line = b"console=ttyS0 virtio_mmio.device=512@0xfeb00e00:12 virtio_mmio.device=4K@0xfeb01000:13:3 root=/dev/vda\0junk";
        let mut out = [VirtioMmio::default(); 4];
        assert_eq!(bootinfo::parse_virtio_mmio(line, &mut out), (2, 0));
        assert_eq!(out[0], VirtioMmio { base: 0xFEB0_0E00, size: 512, gsi: 12 });
        assert_eq!(out[1], VirtioMmio { base: 0xFEB0_1000, size: 4096, gsi: 13 });
    }

    #[test]
    fn malformed_virtio_mmio_entries_are_counted_not_used() {
        let line = b"virtio_mmio.device=512 virtio_mmio.device=512@zz:5 virtio_mmio.device=0@0x1000:5 virtio_mmio.device=1M@4096:7";
        let mut out = [VirtioMmio::default(); 4];
        assert_eq!(bootinfo::parse_virtio_mmio(line, &mut out), (1, 3));
        assert_eq!(out[0], VirtioMmio { base: 4096, size: 1 << 20, gsi: 7 });
        let mut one = [VirtioMmio::default(); 1];
        let two = b"virtio_mmio.device=512@0x1000:5 virtio_mmio.device=512@0x2000:6";
        assert_eq!(bootinfo::parse_virtio_mmio(two, &mut one), (1, 0));
    }

    #[test]
    fn microvm_layout_follows_qemu() {
        assert_eq!(bootinfo::microvm_virtio_layout(true, true), (24, 24));
        assert_eq!(bootinfo::microvm_virtio_layout(true, false), (16, 8));
        assert_eq!(bootinfo::microvm_virtio_layout(false, false), (5, 8));
    }

    // ── register words ──────────────────────────────────────────────────

    #[test]
    fn x2apic_msrs() {
        assert_eq!(encode::x2apic_msr(encode::LAPIC_ID), 0x802);
        assert_eq!(encode::x2apic_msr(encode::LAPIC_EOI), 0x80B);
        assert_eq!(encode::x2apic_msr(encode::LAPIC_ICR_LOW), 0x830);
        assert_eq!(encode::x2apic_msr(encode::LAPIC_LVT_TIMER), 0x832);
        assert_eq!(encode::x2apic_msr(encode::LAPIC_TIMER_DIVIDE), 0x83E);
    }

    #[test]
    fn icr_words() {
        assert_eq!(encode::icr_init(), 0x0000_C500);
        assert_eq!(encode::icr_init_deassert(), 0x0000_8500);
        assert_eq!(encode::icr_sipi(0x9E000), Some(0x0000_469E));
        assert_eq!(encode::icr_sipi(0x9E800), None);
        assert_eq!(encode::icr_sipi(0x10_0000), None);
        assert_eq!(encode::icr_fixed(0xFD), 0x0000_40FD);
        assert_eq!(encode::icr_x2apic(300, 0x40FD), (300u64 << 32) | 0x40FD);
        assert_eq!(encode::icr_xapic_high(3), Some(3 << 24));
        assert_eq!(encode::icr_xapic_high(256), None);
        assert_eq!(encode::icr_fixed(0xFC) | encode::ICR_ALL_BUT_SELF, 0x000C_40FC);
    }

    #[test]
    fn lvt_and_divide() {
        assert_eq!(encode::lvt_timer(0xEF, TimerMode::TscDeadline, false), 0x0004_00EF);
        assert_eq!(encode::lvt_timer(0xEF, TimerMode::Periodic, false), 0x0002_00EF);
        assert_eq!(encode::lvt_timer(0xEF, TimerMode::OneShot, true), 0x0001_00EF);
        assert_eq!(encode::tdcr(1), Some(0b1011));
        assert_eq!(encode::tdcr(16), Some(0b0011));
        assert_eq!(encode::tdcr(128), Some(0b1010));
        assert_eq!(encode::tdcr(3), None);
        assert_eq!(encode::svr(0xFF), 0x1FF);
    }

    #[test]
    fn redirection_entries() {
        // GSI 24 -> vector 72, CPU APIC 1, level, active-high, unmasked.
        let w = encode::rte(72, 1, true, false, false).unwrap();
        assert_eq!(w, (1u64 << 56) | (1 << 15) | 72);
        let m = encode::rte(52, 0, false, true, true).unwrap();
        assert_eq!(m, (1 << 16) | (1 << 13) | 52);
        assert_eq!(encode::rte(52, 256, false, false, false), None);
        assert_eq!(encode::ioapic_rte_reg(0), 0x10);
        assert_eq!(encode::ioapic_rte_reg(23), 0x3E);
        assert_eq!(encode::ioapic_pins(0x0017_0020), 24);
    }

    #[test]
    fn vector_map_is_disjoint() {
        let base = 48u8;
        assert!(base >= encode::PIC_VECTOR_BASE + 16);
        assert_eq!(encode::gsi_vector(base, 0), Some(48));
        assert_eq!(encode::gsi_vector(base, 47), Some(95));
        assert_eq!(encode::gsi_vector(base, 176), None); // would be 0xE0
        assert_eq!(encode::vector_gsi(base, 95), Some(47));
        assert_eq!(encode::vector_gsi(base, 47), None);
        for v in [encode::TIMER_VECTOR, encode::CALL_VECTOR, encode::TLB_VECTOR,
                  encode::RESCHED_VECTOR, encode::ERROR_VECTOR, encode::SPURIOUS_VECTOR] {
            assert!(v >= encode::SYSTEM_VECTOR_FLOOR);
            assert_eq!(encode::vector_gsi(base, v), None);
        }
        assert_eq!(encode::SPURIOUS_VECTOR & 0xF, 0xF);
    }

    #[test]
    fn msi_words() {
        assert_eq!(encode::msi_address(2), Some(0xFEE0_2000));
        assert_eq!(encode::msi_address(256), None);
        assert_eq!(encode::msi_data(0x41), 0x41);
    }

    #[test]
    fn pic_remap_sequence() {
        let s = encode::pic_remap(0x20);
        assert_eq!(s[0], (0x20, 0x11));
        assert_eq!(s[2], (0x21, 0x20));
        assert_eq!(s[3], (0xA1, 0x28));
    }

    // ── clock ───────────────────────────────────────────────────────────

    #[test]
    fn tsc_scaling_to_timer_freq() {
        // 3 GHz TSC -> 1 GHz ticks.
        let s = Scale::new(3_000_000_000, 1_000_000_000).unwrap();
        assert_eq!(s.apply(3_000_000_000), 999_999_999); // floor of 2^-32 error
        assert!((s.apply(3_000_000_000_000) as i64 - 1_000_000_000_000).abs() <= 1000);
        // ...and back, rounded up: the deadline is never early.
        let back = Scale::new(1_000_000_000, 3_000_000_000).unwrap();
        assert_eq!(back.apply_ceil(1), 3);
        let t = 123_456_789u64;
        assert!(s.apply(back.apply_ceil(t)) >= t - 1);
        assert_eq!(Scale::IDENTITY.apply(42), 42);
        assert_eq!(Scale::new(0, 1), None);
        assert_eq!(Scale::new(1, 1 << 33), None); // ratio past 2^32
        // mult is rounded down: at most 2^-32 relative low, never high.
        assert!(s.apply(u64::MAX) <= u64::MAX / 3 && u64::MAX / 3 - s.apply(u64::MAX) < u64::MAX >> 31);
        assert_eq!(Scale::new(1, u32::MAX as u64).unwrap().apply(u64::MAX), u64::MAX);
    }

    #[test]
    fn tsc_rate_sources() {
        // 25 MHz crystal x 168 / 2 = 2.1 GHz.
        assert_eq!(encode::tsc_hz_from_leaf15(2, 168, 25_000_000), Some(2_100_000_000));
        assert_eq!(encode::tsc_hz_from_leaf15(2, 168, 0), None);
        assert_eq!(encode::tsc_hz_from_leaf16(2100), Some(2_100_000_000));
        assert_eq!(encode::tsc_hz_from_hv_leaf(2_100_000), Some(2_100_000_000));
        assert_eq!(encode::pit_count_for_ms(20), Some(23_863));
        assert_eq!(encode::pit_count_for_ms(55), None);
        assert_eq!(encode::rate_from_window(42_000_000, 23_863, encode::PIT_HZ), Some(2_100_056_321));
        assert_eq!(encode::hpet_hz(10_000_000), Some(100_000_000)); // 10 ns period
        assert_eq!(encode::hpet_hz(0x05F5_E101), None);
    }
}
