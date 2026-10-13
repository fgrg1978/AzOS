// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ACPI tables the PC port reads beyond the MADT: the FADT's PM timer
//! fields, the DMAR (Intel VT-d) and IVRS (AMD-Vi) IOMMU descriptions, and
//! the PM timer's counter arithmetic. Tables are built byte by byte to the
//! ACPI 6.x / VT-d / AMD IOMMU specification layouts, with real checksums;
//! a test that corrupts one checks it is refused.

use super::acpi::{self, Dmar, Ivrs, PhysMem};
use super::encode;

fn fix_checksum(b: &mut [u8]) {
    b[9] = 0;
    let sum = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
    b[9] = 0u8.wrapping_sub(sum);
}

/// An SDT: the 36-byte header + `body`, length and checksum filled in.
fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(sig);
    t.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
    t.push(1);
    t.push(0);
    t.extend_from_slice(b"AZOSTS");
    t.extend_from_slice(b"SYNTHTBL");
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(b"AZOS");
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(body);
    fix_checksum(&mut t);
    t
}

// ── FADT ────────────────────────────────────────────────────────────────────

/// A FADT of `len` bytes with the PM timer fields set. Absolute offsets from
/// the table start: PM_TMR_BLK 76, PM_TMR_LEN 91, Flags 112, X_PM_TMR_BLK 208.
fn fadt(len: usize, blk: u32, tmr_len: u8, flags: u32, x_gas: Option<(u8, u64)>) -> Vec<u8> {
    let mut t = sdt(b"FACP", &vec![0; len - 36]);
    t[76..80].copy_from_slice(&blk.to_le_bytes());
    t[91] = tmr_len;
    t[112..116].copy_from_slice(&flags.to_le_bytes());
    if let Some((space, addr)) = x_gas {
        t[208] = space;
        t[212..220].copy_from_slice(&addr.to_le_bytes());
    }
    fix_checksum(&mut t);
    t
}

#[test]
fn the_fadt_names_the_pm_timer_port_and_width() {
    // The legacy fields alone (a 116-byte, ACPI 1.0-sized table).
    let f = acpi::parse_fadt(&fadt(116, 0x608, 4, 0, None)).unwrap();
    assert_eq!((f.pm_tmr_port, f.pm_tmr_wide), (0x608, false));
    // TMR_VAL_EXT (flags bit 8) is the 32-bit counter; a neighbour bit is not.
    assert!(acpi::parse_fadt(&fadt(116, 0x608, 4, 1 << 8, None)).unwrap().pm_tmr_wide);
    assert!(!acpi::parse_fadt(&fadt(116, 0x608, 4, !(1 << 8), None)).unwrap().pm_tmr_wide);
    // A length other than 4 means no timer; so does a port past 16 bits.
    assert_eq!(acpi::parse_fadt(&fadt(116, 0x608, 0, 0, None)).unwrap().pm_tmr_port, 0);
    assert_eq!(acpi::parse_fadt(&fadt(116, 0x1_0608, 4, 0, None)).unwrap().pm_tmr_port, 0);
    assert_eq!(acpi::parse_fadt(&fadt(116, 0, 4, 0, None)).unwrap().pm_tmr_port, 0);
    // X_PM_TMR_BLK, when it is system I/O, wins over the legacy field...
    let f = acpi::parse_fadt(&fadt(276, 0x608, 4, 0, Some((1, 0x1808)))).unwrap();
    assert_eq!(f.pm_tmr_port, 0x1808);
    // ... a memory-space one means a timer this does not read, and the legacy
    // port is not trusted past it ...
    assert_eq!(acpi::parse_fadt(&fadt(276, 0x608, 4, 0, Some((0, 0xFED0_8000)))).unwrap().pm_tmr_port, 0);
    // ... a zero one falls back to the legacy field, and a short table has no GAS.
    assert_eq!(acpi::parse_fadt(&fadt(276, 0x608, 4, 0, Some((1, 0)))).unwrap().pm_tmr_port, 0x608);
    assert_eq!(acpi::parse_fadt(&fadt(116, 0x608, 4, 0, None)).unwrap().pm_tmr_port, 0x608);
    // Too short to hold the flags: not a FADT.
    assert!(acpi::parse_fadt(&sdt(b"FACP", &[0; 60])).is_none());
}

// ── DMAR ────────────────────────────────────────────────────────────────────

fn drhd(flags: u8, size: u8, segment: u16, base: u64) -> Vec<u8> {
    let mut e = vec![0, 0, 16, 0, flags, size];
    e.extend_from_slice(&segment.to_le_bytes());
    e.extend_from_slice(&base.to_le_bytes());
    e
}
fn rmrr(segment: u16, base: u64, limit: u64) -> Vec<u8> {
    let mut e = vec![1, 0, 24, 0, 0, 0];
    e.extend_from_slice(&segment.to_le_bytes());
    e.extend_from_slice(&base.to_le_bytes());
    e.extend_from_slice(&limit.to_le_bytes());
    e
}
fn dmar_table(width: u8, flags: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![width, flags];
    b.extend_from_slice(&[0; 10]);
    for e in entries {
        b.extend_from_slice(e);
    }
    sdt(b"DMAR", &b)
}

#[test]
fn the_dmar_lists_units_and_reserved_regions() {
    let t = dmar_table(
        38,
        0b101,
        &[
            drhd(0, 0, 0, 0xFED9_0000),
            drhd(1, 1, 0, 0xFED9_1000),
            rmrr(0, 0x6F00_0000, 0x6F0F_FFFF),
            // An ATSR (type 2), which is not read.
            vec![2, 0, 8, 0, 0, 0, 0, 0],
        ],
    );
    let mut d = Dmar::EMPTY;
    acpi::parse_dmar(&t, &mut d);
    assert_eq!((d.host_addr_width, d.flags), (38, 0b101));
    assert!(d.intr_remap());
    assert_eq!(d.units().len(), 2);
    assert_eq!((d.units()[0].base, d.units()[0].size, d.units()[0].include_all), (0xFED9_0000, 4096, false));
    assert_eq!((d.units()[1].base, d.units()[1].size, d.units()[1].include_all), (0xFED9_1000, 8192, true));
    assert_eq!(d.rmrr().len(), 1);
    assert_eq!((d.rmrr()[0].base, d.rmrr()[0].len), (0x6F00_0000, 0x10_0000), "the limit is inclusive");
    assert_eq!(d.malformed + d.skipped, 0);
    assert!(!Dmar { flags: 0b110, ..d }.intr_remap(), "INTR_REMAP is bit 0, not a neighbour");
}

#[test]
fn a_bad_dmar_structure_is_counted_and_never_trusted() {
    // A DRHD cut short (length 8), an RMRR whose limit is below its base, and
    // a structure that runs past the table end.
    let mut short = drhd(0, 0, 0, 0xFED9_0000);
    short.truncate(8);
    short[2] = 8;
    let t = dmar_table(38, 0, &[short, rmrr(0, 0x2000, 0x1000)]);
    let mut d = Dmar::EMPTY;
    acpi::parse_dmar(&t, &mut d);
    assert_eq!((d.n_units, d.n_rmrr, d.malformed), (0, 0, 2));
    let mut t = dmar_table(38, 0, &[drhd(0, 0, 0, 0xFED9_0000)]);
    let n = t.len();
    t[n - 14] = 200; // the DRHD's length now exceeds the table
    fix_checksum(&mut t);
    acpi::parse_dmar(&t, &mut d);
    assert_eq!((d.n_units, d.malformed), (0, 1));
    // A table without its fixed fields.
    acpi::parse_dmar(&sdt(b"DMAR", &[0; 4]), &mut d);
    assert_eq!((d.n_units, d.malformed), (0, 1));
    // More units than the capacity: counted, not stored.
    let many: Vec<Vec<u8>> = (0..acpi::MAX_IOMMUS + 2).map(|i| drhd(0, 0, 0, 0xFED9_0000 + 0x1000 * i as u64)).collect();
    acpi::parse_dmar(&dmar_table(38, 0, &many), &mut d);
    assert_eq!((d.n_units, d.skipped), (acpi::MAX_IOMMUS, 2));
}

// ── IVRS ────────────────────────────────────────────────────────────────────

fn ivhd(kind: u8, device_id: u16, base: u64, segment: u16, efr: u64) -> Vec<u8> {
    let len: u16 = if kind == 0x10 { 24 } else { 40 };
    let mut e = vec![kind, 0x90];
    e.extend_from_slice(&len.to_le_bytes());
    e.extend_from_slice(&device_id.to_le_bytes());
    e.extend_from_slice(&0x40u16.to_le_bytes()); // capability offset
    e.extend_from_slice(&base.to_le_bytes());
    e.extend_from_slice(&segment.to_le_bytes());
    e.extend_from_slice(&[0; 6]);
    if kind != 0x10 {
        e.extend_from_slice(&efr.to_le_bytes());
        e.extend_from_slice(&[0; 8]);
    }
    assert_eq!(e.len(), len as usize);
    e
}
fn ivmd(kind: u8, start: u64, len: u64) -> Vec<u8> {
    let mut e = vec![kind, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    e.extend_from_slice(&start.to_le_bytes());
    e.extend_from_slice(&len.to_le_bytes());
    e
}
fn ivrs_table(info: u32, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut b = info.to_le_bytes().to_vec();
    b.extend_from_slice(&[0; 8]);
    for e in blocks {
        b.extend_from_slice(e);
    }
    sdt(b"IVRS", &b)
}

#[test]
fn the_ivrs_lists_units_and_unity_regions() {
    let t = ivrs_table(
        0x0025_8001,
        &[
            ivhd(0x10, 0x0002, 0xFEB8_0000, 0, 0),
            ivhd(0x11, 0x0402, 0xFEB9_0000, 1, 0x0000_1234_5678_9ABC),
            ivmd(0x20, 0x7000_0000, 0x4000),
            ivmd(0x22, 0x7100_0000, 0x8000),
            // An unknown block type is skipped by length.
            vec![0x99, 0, 8, 0, 0, 0, 0, 0],
        ],
    );
    let mut v = Ivrs::EMPTY;
    acpi::parse_ivrs(&t, &mut v);
    assert_eq!(v.info, 0x0025_8001);
    assert_eq!(v.units().len(), 2);
    assert_eq!((v.units()[0].kind, v.units()[0].device_id, v.units()[0].base, v.units()[0].efr),
               (0x10, 2, 0xFEB8_0000, 0), "type 0x10 has no EFR image");
    assert_eq!((v.units()[1].kind, v.units()[1].segment, v.units()[1].base, v.units()[1].efr),
               (0x11, 1, 0xFEB9_0000, 0x0000_1234_5678_9ABC));
    assert_eq!(v.ivmd().len(), 2);
    assert_eq!((v.ivmd()[0].base, v.ivmd()[0].len, v.ivmd()[1].base, v.ivmd()[1].len),
               (0x7000_0000, 0x4000, 0x7100_0000, 0x8000));
    assert_eq!(v.malformed + v.skipped, 0);
    // A short IVHD (0x11 declared 24 bytes long) is malformed, not read as 0x10.
    let mut short = ivhd(0x11, 1, 0xFEB9_0000, 0, 7);
    short.truncate(24);
    short[2] = 24;
    acpi::parse_ivrs(&ivrs_table(0, &[short]), &mut v);
    assert_eq!((v.n_units, v.malformed), (0, 1));
}

// ── the walk, end to end ────────────────────────────────────────────────────

struct Mem(Vec<(u64, Vec<u8>)>);
impl PhysMem for Mem {
    fn read(&self, pa: u64, len: usize) -> Option<&[u8]> {
        self.0.iter().find_map(|(base, b)| {
            let off = pa.checked_sub(*base)? as usize;
            b.get(off..off.checked_add(len)?)
        })
    }
}

fn machine(tables: &[(u64, Vec<u8>)]) -> Mem {
    let mut xsdt_body = Vec::new();
    for (pa, _) in tables {
        xsdt_body.extend_from_slice(&pa.to_le_bytes());
    }
    let xsdt = sdt(b"XSDT", &xsdt_body);
    let mut rsdp = Vec::new();
    rsdp.extend_from_slice(b"RSD PTR ");
    rsdp.push(0);
    rsdp.extend_from_slice(b"AZOSTS");
    rsdp.push(2);
    rsdp.extend_from_slice(&0u32.to_le_bytes());
    rsdp.extend_from_slice(&36u32.to_le_bytes());
    rsdp.extend_from_slice(&0x2000u64.to_le_bytes());
    rsdp.extend_from_slice(&[0, 0, 0, 0]);
    let sum = rsdp[..20].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    rsdp[8] = 0u8.wrapping_sub(sum);
    let sum = rsdp.iter().fold(0u8, |a, &x| a.wrapping_add(x));
    rsdp[32] = 0u8.wrapping_sub(sum);
    let mut m = vec![(0x1000u64, rsdp), (0x2000u64, xsdt)];
    m.extend(tables.iter().cloned());
    Mem(m)
}

#[test]
fn the_walk_reads_the_fadt_and_the_iommu_tables_and_names_the_dma_regions() {
    let m = machine(&[
        (0x3000, fadt(276, 0x608, 4, 1 << 8, None)),
        (0x4000, dmar_table(38, 1, &[drhd(1, 0, 0, 0xFED9_0000), rmrr(0, 0x6F00_0000, 0x6F00_FFFF)])),
    ]);
    let mut a = acpi::AcpiInfo::EMPTY;
    acpi::parse(&m, 0x1000, &mut a).unwrap();
    let f = a.fadt.expect("FACP");
    assert_eq!((f.pm_tmr_port, f.pm_tmr_wide), (0x608, true));
    assert_eq!(a.iommu(), Some(("Intel VT-d", 1)));
    assert!(a.ivrs.is_none());
    let mut regions = Vec::new();
    a.for_each_dma_region(|b, l| regions.push((b, l)));
    assert_eq!(regions, [(0x6F00_0000, 0x1_0000)]);
    assert!(a.tables().iter().any(|t| &t.0 == b"DMAR"), "its pages are reserved with the other tables");

    // An AMD machine: IVRS instead.
    let m = machine(&[(0x3000, ivrs_table(0, &[ivhd(0x10, 2, 0xFEB8_0000, 0, 0), ivmd(0x20, 0x7000_0000, 0x4000)]))]);
    let mut a = acpi::AcpiInfo::EMPTY;
    acpi::parse(&m, 0x1000, &mut a).unwrap();
    assert_eq!(a.iommu(), Some(("AMD-Vi", 1)));
    let mut regions = Vec::new();
    a.for_each_dma_region(|b, l| regions.push((b, l)));
    assert_eq!(regions, [(0x7000_0000, 0x4000)]);

    // A table with a bad checksum is skipped whole.
    let mut bad = dmar_table(38, 0, &[drhd(0, 0, 0, 0xFED9_0000)]);
    bad[10] ^= 0xFF;
    let m = machine(&[(0x3000, bad)]);
    let mut a = acpi::AcpiInfo::EMPTY;
    acpi::parse(&m, 0x1000, &mut a).unwrap();
    assert!(a.dmar.is_none() && a.iommu().is_none());
    assert_eq!(a.bad_tables, 1);
}

// ── the PM timer's arithmetic ───────────────────────────────────────────────

#[test]
fn the_pm_timer_counts_across_a_wrap_in_its_own_width() {
    assert_eq!(encode::PMTMR_HZ, 3_579_545);
    assert_eq!(encode::pmtmr_mask(false), 0x00FF_FFFF);
    assert_eq!(encode::pmtmr_mask(true), 0xFFFF_FFFF);
    assert_eq!(encode::pmtmr_elapsed(100, 350, false), 250);
    // 24-bit wrap: 0xFFFFF0 -> 0x10 is 0x20 ticks; the 32-bit counter has not wrapped there.
    assert_eq!(encode::pmtmr_elapsed(0x00FF_FFF0, 0x10, false), 0x20);
    assert_eq!(encode::pmtmr_elapsed(0x00FF_FFF0, 0x0100_0010, true), 0x20);
    // A 24-bit counter's upper byte is not part of the count.
    assert_eq!(encode::pmtmr_elapsed(0x0100_0000 | 5, 9, false), 4);
    // 32-bit wrap.
    assert_eq!(encode::pmtmr_elapsed(0xFFFF_FFF0, 0x10, true), 0x20);
}

#[test]
fn the_pm_timer_window_and_the_rate_it_gives() {
    assert_eq!(encode::pmtmr_ticks_for_ms(20), Some(71_590));
    assert_eq!(encode::pmtmr_ticks_for_ms(0), None);
    assert_eq!(encode::pmtmr_ticks_for_ms(1), Some(3_579));
    // Past half of the 24-bit counter's 4.69 s span a wrap could hide.
    assert!(encode::pmtmr_ticks_for_ms(2_000).is_some());
    assert_eq!(encode::pmtmr_ticks_for_ms(3_000), None);
    // A 3 GHz TSC over a 20 ms window reads 3 GHz within the tick quantum.
    let hz = encode::rate_from_window(60_000_000, 71_590, encode::PMTMR_HZ).unwrap();
    assert!((2_999_000_000..=3_001_000_000).contains(&hz), "{hz}");
    assert_eq!(encode::rate_from_window(60_000_000, 0, encode::PMTMR_HZ), None, "a counter that did not move");
}

// ── x2APIC or xAPIC ─────────────────────────────────────────────────────────

#[test]
fn the_lapic_mode_follows_policy_cpu_ids_and_the_dmar_opt_out() {
    use encode::{apic_mode, ApicWhy::*};
    //                 never  require x2apic opt_out max_id
    assert_eq!(apic_mode(false, false, true, false, 3), (true, Preferred));
    assert_eq!(apic_mode(false, false, false, false, 3), (false, NotPresent), "the xAPIC fallback");
    assert_eq!(apic_mode(true, false, true, false, 3), (false, PolicyNever));
    assert_eq!(apic_mode(true, true, true, false, 3), (false, PolicyNever), "n wins over a stale require");
    assert_eq!(apic_mode(false, true, true, true, 3), (true, Required), "require beats the firmware's opt-out");
    assert_eq!(apic_mode(false, true, false, false, 3), (false, NotPresent), "the ISA report refuses this one");
    // The DMAR asks for xAPIC when every ID fits...
    assert_eq!(apic_mode(false, false, true, true, 254), (false, FirmwareOptOut));
    // ... but an ID of 255 or more is out of an xAPIC's reach (255 is the broadcast).
    assert_eq!(apic_mode(false, false, true, true, 255), (true, IdsNeedIt));
    assert_eq!(apic_mode(false, false, true, false, 300), (true, IdsNeedIt));
    // Without CPU support there is no choice, whatever the IDs.
    assert_eq!(apic_mode(false, false, false, true, 300), (false, NotPresent));
    for w in [Preferred, Required, IdsNeedIt, NotPresent, PolicyNever, FirmwareOptOut] {
        assert!(!w.label().is_empty());
    }
}

#[test]
fn segment_0_unit_is_the_catch_all_drhd_else_the_first_and_the_first_ivhd() {
    let unit = |entries: &[Vec<u8>]| {
        let mut d = Dmar::EMPTY;
        acpi::parse_dmar(&dmar_table(38, 0, entries), &mut d);
        d.segment0_unit()
    };
    // QEMU q35: one DRHD, INCLUDE_PCI_ALL.
    assert_eq!(unit(&[drhd(1, 0, 0, 0xFED9_0000)]), Some(0xFED9_0000));
    // A scoped unit first, the catch-all last: the catch-all wins.
    assert_eq!(unit(&[drhd(0, 0, 0, 0xFED9_0000), drhd(1, 1, 0, 0xFED9_1000)]), Some(0xFED9_1000));
    // No catch-all: the first unit of segment 0, not another segment's.
    assert_eq!(unit(&[drhd(0, 0, 1, 0xFED8_0000), drhd(0, 0, 0, 0xFED9_0000)]), Some(0xFED9_0000));
    // Nothing usable.
    assert_eq!(unit(&[drhd(1, 0, 3, 0xFED9_0000)]), None);
    assert_eq!(unit(&[drhd(1, 0, 0, 0)]), None);
    assert_eq!(unit(&[]), None);

    let mut v = Ivrs::EMPTY;
    let ivrs = |v: &mut Ivrs, blocks: &[Vec<u8>]| {
        acpi::parse_ivrs(&ivrs_table(0, blocks), v);
        v.segment0_unit()
    };
    assert_eq!(ivrs(&mut v, &[ivhd(0x11, 8, 0xFED8_0000, 0, 0)]), Some(0xFED8_0000));
    assert_eq!(ivrs(&mut v, &[ivhd(0x40, 8, 0xFED7_0000, 2, 0), ivhd(0x40, 8, 0xFED8_0000, 0, 0)]), Some(0xFED8_0000));
    assert_eq!(ivrs(&mut v, &[ivmd(0x20, 0x7000_0000, 0x4000)]), None);
    assert_eq!(ivrs(&mut v, &[]), None);
}
