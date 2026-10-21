// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/core/arch-aarch64/src/ext/hv` (hypervisor step H1):
//! the stage-2 descriptor and `VTCR_EL2` / `VTTBR_EL2` encoders and the table
//! mapper, the vGICv3 list-register model, the virtual timer arithmetic and
//! the EL2 stub's `HVC` dispatch.
//!
//! WHY. Every one of these is arithmetic whose mistakes are silent until a
//! guest runs: a descriptor bit one place off maps the right page with the
//! wrong permissions, a `VTCR_EL2` start level that disagrees with the table
//! depth walks garbage, a list register encoded with the wrong shift injects
//! the wrong interrupt. QEMU with `virtualization=on` is the testing week's
//! (S6); until then the encoders are pinned here against the architecture's
//! field positions, written out by hand and not derived from the code.

#![cfg(test)]

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/ext/hv/mod.rs"]
mod hv;

use hv::stage2::*;
use hv::vgic::*;
use hv::vtimer::*;
use hv::{availability, availability_from_state, classify_hvc, Availability, HvcClass, Reason};

// ── the EL2 stub's dispatch ─────────────────────────────────────────────

#[test]
fn the_stub_answers_the_probe_and_forwards_exactly_the_psci_calls() {
    // The assembly tests the same bits in the same order; this table is the
    // one place the dispatch is written down independently.
    for (fid, want) in [
        (0x8600_0000u32, HvcClass::Probe),
        // PSCI_VERSION, CPU_SUSPEND_32, CPU_OFF, CPU_ON_32, SYSTEM_OFF, SYSTEM_RESET, the last number.
        (0x8400_0000, HvcClass::Psci),
        (0x8400_0001, HvcClass::Psci),
        (0x8400_0002, HvcClass::Psci),
        (0x8400_0003, HvcClass::Psci),
        (0x8400_0008, HvcClass::Psci),
        (0x8400_0009, HvcClass::Psci),
        (0x8400_001F, HvcClass::Psci),
        // The SMC64 forms: CPU_ON_64, CPU_SUSPEND_64, AFFINITY_INFO_64.
        (0xC400_0003, HvcClass::Psci),
        (0xC400_0001, HvcClass::Psci),
        (0xC400_0004, HvcClass::Psci),
        // Number 32 and beyond, a set bit in 23:16, a yielding (not fast) call,
        // another owner, the vendor service's other functions, noise.
        (0x8400_0020, HvcClass::Unsupported),
        (0x8401_0000, HvcClass::Unsupported),
        (0x8480_0000, HvcClass::Unsupported),
        (0x0400_0003, HvcClass::Unsupported),
        (0xC300_0000, HvcClass::Unsupported),
        (0x8300_0000, HvcClass::Unsupported),
        (0xC600_0000, HvcClass::Unsupported),
        (0x8600_0001, HvcClass::Unsupported),
        (0x0000_0000, HvcClass::Unsupported),
        (0xFFFF_FFFF, HvcClass::Unsupported),
        (0xC800_0003, HvcClass::Unsupported),
    ] {
        assert_eq!(classify_hvc(fid), want, "fid {:#x}", fid);
    }
}

#[test]
fn the_boot_record_decides_availability() {
    assert_eq!(availability_from_state(1), Availability::Resident);
    // Never written (entered at EL1) is absent with its reason; so is any
    // other value, which nothing writes.
    assert_eq!(availability_from_state(0), Availability::Absent(Reason::EntryEl1));
    assert_eq!(availability_from_state(2), Availability::Absent(Reason::EntryEl1));
    // Off bare metal there is no trampoline.
    assert_eq!(availability(), Availability::Absent(Reason::EntryEl1));
    assert_eq!(hv::probe(), None, "no HVC is issued without a resident stub");
}

// ── VTCR_EL2 / VTTBR_EL2 ────────────────────────────────────────────────

#[test]
fn vtcr_fields_sit_where_the_architecture_puts_them() {
    // 40-bit IPA on a 40-bit CPU (PARange 2): T0SZ 24, start level 1 (SL0 1),
    // two concatenated root tables. IRGN0 = ORGN0 = 01, SH0 = 11, TG0 = 00,
    // PS = 010, bit 31 RES1; VS, HA, HD clear.
    let c = VtcrConfig::new(40, 2).unwrap();
    assert_eq!(c.start_level(), 1);
    assert_eq!(c.root_tables(), 2);
    assert_eq!(c.root_align(), 8192);
    let v = c.value();
    assert_eq!(v & 0x3F, 24, "T0SZ");
    assert_eq!((v >> 6) & 3, 1, "SL0");
    assert_eq!((v >> 8) & 3, 1, "IRGN0");
    assert_eq!((v >> 10) & 3, 1, "ORGN0");
    assert_eq!((v >> 12) & 3, 3, "SH0");
    assert_eq!((v >> 14) & 3, 0, "TG0 = 4 KiB");
    assert_eq!((v >> 16) & 7, 2, "PS");
    assert_eq!((v >> 19) & 1, 0, "VS: 8-bit VMID");
    assert_eq!((v >> 21) & 3, 0, "HA, HD");
    assert_eq!((v >> 31) & 1, 1, "RES1");
    assert_eq!(v, 24 | 1 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | 2 << 16 | 1 << 31);
}

#[test]
fn the_ipa_width_picks_start_level_and_root_size() {
    // (ipa bits, start level, SL0, root tables)
    for (bits, level, sl0, tables) in [
        (32u8, 2u8, 0u64, 4u64),
        (34, 2, 0, 16),
        (35, 1, 1, 1),
        (39, 1, 1, 1),
        (40, 1, 1, 2),
        (43, 1, 1, 16),
        (44, 0, 2, 1),
        (48, 0, 2, 1),
    ] {
        let c = VtcrConfig::new(bits, 5).unwrap();
        assert_eq!(c.start_level(), level, "{} bits", bits);
        assert_eq!(c.root_tables(), tables, "{} bits", bits);
        assert_eq!((c.value() >> 6) & 3, sl0, "{} bits SL0", bits);
        assert_eq!(c.value() & 0x3F, 64 - bits as u64, "{} bits T0SZ", bits);
        // The walk must resolve exactly the configured input size: the start
        // level covers `12 + 9 * (4 - level)` bits per table, `tables` of them.
        let covered = 12 + 9 * (4 - level as u32) + tables.trailing_zeros();
        assert!(covered >= bits as u32 && covered <= bits as u32 + 8, "{} bits: covered {}", bits, covered);
    }
}

#[test]
fn vtcr_refuses_widths_the_cpu_or_the_encoding_cannot_do() {
    assert_eq!(VtcrConfig::new(31, 5), Err(S2Error::BadIpaBits));
    assert_eq!(VtcrConfig::new(49, 6), Err(S2Error::BadIpaBits));
    // An IPA wider than the CPU's output size.
    assert_eq!(VtcrConfig::new(44, 2), Err(S2Error::BadIpaBits));
    assert!(VtcrConfig::new(40, 2).is_ok());
    // A PARange this code does not know.
    assert_eq!(VtcrConfig::new(40, 7), Err(S2Error::BadParange));
    // 52-bit CPUs: PS encodes the 48 bits this code can.
    assert_eq!((VtcrConfig::new(48, 6).unwrap().value() >> 16) & 7, 5);
    // PS follows the PARange encoding one to one below that.
    for (field, ps) in [(0u8, 0u64), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)] {
        assert_eq!((VtcrConfig::new(32, field).unwrap().value() >> 16) & 7, ps);
    }
}

#[test]
fn vttbr_carries_the_root_and_the_vmid_and_checks_alignment() {
    let c = VtcrConfig::new(40, 2).unwrap();
    assert_eq!(c.vttbr(0x4000_2000, 0x5A), Ok(0x4000_2000 | 0x5Au64 << 48));
    // Two concatenated tables: the root is aligned to its 8 KiB size.
    assert_eq!(c.vttbr(0x4000_1000, 1), Err(S2Error::Misaligned));
    assert_eq!(c.vttbr(0x4000_2000, 0x100), Err(S2Error::VmidTooWide));
    assert_eq!(c.vttbr(1 << 48, 1), Err(S2Error::PaTooWide));
    // One table: page alignment is enough.
    let one = VtcrConfig::new(39, 2).unwrap();
    assert_eq!(one.vttbr(0x4000_1000, 0xFF), Ok(0x4000_1000 | 0xFFu64 << 48));
}

// ── stage-2 descriptors ─────────────────────────────────────────────────

#[test]
fn a_ram_page_descriptor_has_every_field_in_place() {
    let pa = 0x8123_4000u64;
    let d = leaf_desc(pa, 3, S2Attrs::RAM).unwrap();
    // valid, page (bit 1), MemAttr 1111 at [5:2], S2AP 11 at [7:6], SH 11 at
    // [9:8], AF bit 10, output address [47:12], XN (bit 54) clear.
    assert_eq!(d, 1 | 1 << 1 | 0xF << 2 | 3 << 6 | 3 << 8 | 1 << 10 | pa);
    assert!(desc_valid(d));
    assert!(!desc_is_table(d, 3), "a level-3 descriptor with bit 1 set is a page, not a table");
    assert_eq!(desc_pa(d), pa);
}

#[test]
fn blocks_have_bit_one_clear_and_need_their_own_alignment() {
    let d2 = leaf_desc(0x4020_0000, 2, S2Attrs::RAM).unwrap();
    assert_eq!(d2 & 3, 1, "block descriptor");
    assert!(!desc_is_table(d2, 2));
    let d1 = leaf_desc(0x4000_0000, 1, S2Attrs::RAM).unwrap();
    assert_eq!(d1 & 3, 1);
    assert_eq!(leaf_desc(0x4010_0000, 2, S2Attrs::RAM), Err(S2Error::Misaligned));
    assert_eq!(leaf_desc(0x4020_0000, 1, S2Attrs::RAM), Err(S2Error::Misaligned));
    assert_eq!(leaf_desc(0x4000_0800, 3, S2Attrs::RAM), Err(S2Error::Misaligned));
    assert_eq!(leaf_desc(0x4000_0000, 0, S2Attrs::RAM), Err(S2Error::BadLevel));
    assert_eq!(leaf_desc(0x4000_0000, 4, S2Attrs::RAM), Err(S2Error::BadLevel));
    assert_eq!(leaf_desc(1 << 48, 3, S2Attrs::RAM), Err(S2Error::PaTooWide));
}

#[test]
fn permissions_land_in_s2ap_and_xn_and_decode_back() {
    let pa = 0x4000_0000;
    let rom = leaf_desc(pa, 3, S2Attrs::ROM).unwrap();
    assert_eq!((rom >> 6) & 3, 0b01, "read-only");
    assert_eq!(rom >> 54 & 1, 0, "ROM executes");
    let mmio = leaf_desc(pa, 3, S2Attrs::MMIO).unwrap();
    assert_eq!((mmio >> 6) & 3, 0b11);
    assert_eq!(mmio >> 54 & 1, 1, "MMIO is never executed");
    assert_eq!((mmio >> 2) & 0xF, 0b0001, "Device-nGnRE");
    assert_eq!((mmio >> 8) & 3, 0, "SH is ignored for Device memory");
    assert_eq!(
        leaf_desc(pa, 3, S2Attrs { read: false, write: false, exec: true, mem: MemType::NormalWb }),
        Err(S2Error::ExecWithoutRead)
    );
    // Every permission and memory-type combination decodes to what built it.
    for mem in [MemType::Device, MemType::DeviceNgnre, MemType::NormalNc, MemType::NormalWt, MemType::NormalWb] {
        for bits in 0..8u8 {
            let a = S2Attrs { read: bits & 1 != 0, write: bits & 2 != 0, exec: bits & 4 != 0, mem };
            match leaf_desc(pa, 3, a) {
                Ok(d) => assert_eq!(leaf_attrs(d), Some(a), "{:?}", a),
                Err(e) => {
                    assert_eq!(e, S2Error::ExecWithoutRead);
                    assert!(a.exec && !a.read);
                }
            }
        }
    }
}

#[test]
fn memory_types_use_the_architected_memattr_values() {
    let at = |m| (leaf_desc(0x4000_0000, 3, S2Attrs { read: true, write: true, exec: false, mem: m }).unwrap() >> 2) & 0xF;
    assert_eq!(at(MemType::Device), 0b0000);
    assert_eq!(at(MemType::DeviceNgnre), 0b0001);
    assert_eq!(at(MemType::NormalNc), 0b0101);
    assert_eq!(at(MemType::NormalWt), 0b1010);
    assert_eq!(at(MemType::NormalWb), 0b1111);
}

#[test]
fn a_table_descriptor_is_valid_with_bit_one_and_the_next_table() {
    let d = table_desc(0x4000_3000).unwrap();
    assert_eq!(d, 0b11 | 0x4000_3000);
    assert!(desc_is_table(d, 0) && desc_is_table(d, 1) && desc_is_table(d, 2));
    assert!(!desc_is_table(d, 3));
    assert_eq!(desc_pa(d), 0x4000_3000);
    assert_eq!(table_desc(0x4000_3010), Err(S2Error::Misaligned));
    assert_eq!(table_desc(1 << 48), Err(S2Error::PaTooWide));
}

// ── the mapper, over an arena of tables ─────────────────────────────────

const ARENA_BASE: u64 = 0x1_0000_0000;

struct Arena {
    words: Vec<u64>,
    /// Next free table, in 4 KiB units from `ARENA_BASE`.
    next: u64,
    /// Capacity in tables.
    cap: u64,
}

impl Arena {
    fn new(cap_tables: u64) -> Arena {
        Arena { words: vec![0; (cap_tables * 512) as usize], next: 0, cap: cap_tables }
    }
    fn used(&self) -> u64 {
        self.next
    }
}

impl TableMem for Arena {
    fn alloc_tables(&mut self, tables: u64) -> Option<u64> {
        // Aligned to its own size, as the trait promises.
        let at = self.next.div_ceil(tables) * tables;
        if at + tables > self.cap {
            return None;
        }
        self.next = at + tables;
        Some(ARENA_BASE + at * 4096)
    }
    fn read(&self, pa: u64) -> u64 {
        assert_eq!(pa % 8, 0);
        self.words[((pa - ARENA_BASE) / 8) as usize]
    }
    fn write(&mut self, pa: u64, d: u64) {
        assert_eq!(pa % 8, 0);
        self.words[((pa - ARENA_BASE) / 8) as usize] = d;
    }
}

#[test]
fn a_page_maps_and_translates_with_its_offset_and_attributes() {
    let cfg = VtcrConfig::new(40, 2).unwrap();
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_page(0x4000_1000, 0x9000_5000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.translate(0x4000_1000), Some((0x9000_5000, S2Attrs::RAM)));
    assert_eq!(s2.translate(0x4000_1ABC), Some((0x9000_5ABC, S2Attrs::RAM)));
    assert_eq!(s2.translate(0x4000_2000), None, "the next page is not mapped");
    assert_eq!(s2.translate(1 << 40), None, "outside the IPA space");
    // Root (2 tables) + level 2 + level 3.
    assert_eq!(m.used(), 4);
}

#[test]
fn the_second_concatenated_root_table_holds_the_upper_half() {
    let cfg = VtcrConfig::new(40, 2).unwrap();
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    let root = s2.root();
    assert_eq!(root % 8192, 0);
    // Level-1 index 512 (IPA 512 GiB) is entry 0 of the SECOND table.
    s2.map_page(1 << 39, 0x9000_0000, S2Attrs::RAM).unwrap();
    s2.map_page(0x4000_0000, 0x9000_1000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.translate(1 << 39).unwrap().0, 0x9000_0000);
    let (vtcr, vttbr) = s2.registers(7).unwrap();
    assert_eq!(vtcr, cfg.value());
    assert_eq!(vttbr, root | 7u64 << 48);
    assert_ne!(m.read(root + 4096), 0, "entry 512 lives in the second root table");
    assert_ne!(m.read(root + 8), 0, "IPA 1 GiB is entry 1 of the first");
}

#[test]
fn memobj_frames_larger_than_a_stage2_page_map_as_consecutive_pages() {
    // A 16 KiB kernel frame is four stage-2 pages; the frames themselves need
    // not be adjacent in memory.
    let cfg = VtcrConfig::new(39, 2).unwrap();
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_frames(0x8000_0000, [0x9000_0000u64, 0xA000_4000, 0x9000_8000], 0x4000, S2Attrs::RAM).unwrap();
    for (ipa, pa) in [(0x8000_0000u64, 0x9000_0000u64), (0x8000_3000, 0x9000_3000), (0x8000_4000, 0xA000_4000), (0x8000_B000, 0x9000_B000)] {
        assert_eq!(s2.translate(ipa).unwrap().0, pa, "ipa {:#x}", ipa);
    }
    assert_eq!(s2.translate(0x8000_C000), None, "three frames, no fourth");
    // A frame not aligned to its size, and a size that is not a page multiple.
    assert_eq!(s2.map_frames(0x9000_0000, [0xB000_1000u64], 0x4000, S2Attrs::RAM), Err(S2Error::Misaligned));
    assert_eq!(s2.map_frames(0x9000_0000, [0xB000_0000u64], 0x1800, S2Attrs::RAM), Err(S2Error::Misaligned));
}

#[test]
fn remapping_and_mapping_through_a_block_are_refused() {
    let cfg = VtcrConfig::new(40, 2).unwrap();
    let mut m = Arena::new(32);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_page(0x4000_0000, 0x9000_0000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.map_page(0x4000_0000, 0x9000_1000, S2Attrs::RAM), Err(S2Error::Overlap));
    // The old mapping survived the refusal.
    assert_eq!(s2.translate(0x4000_0000).unwrap().0, 0x9000_0000);
    // A 2 MiB block over a range that already holds a table of pages.
    assert_eq!(s2.map_leaf(0x4000_0000, 0xA000_0000, 2, S2Attrs::RAM), Err(S2Error::Overlap));
    // A page inside an existing block.
    s2.map_leaf(0x6000_0000, 0xA020_0000, 2, S2Attrs::RAM).unwrap();
    assert_eq!(s2.map_page(0x6000_1000, 0xB000_0000, S2Attrs::RAM), Err(S2Error::Overlap));
    assert_eq!(s2.translate(0x6012_3456).unwrap().0, 0xA032_3456, "a block translates with its offset");
    // Unmapping one page of a block is refused: the block goes whole or not at all.
    assert_eq!(s2.unmap_page(0x6000_1000), Err(S2Error::Overlap));
}

#[test]
fn unmap_returns_the_frame_and_leaves_the_neighbours() {
    let cfg = VtcrConfig::new(39, 2).unwrap();
    let mut m = Arena::new(16);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_page(0x1000, 0x9000_0000, S2Attrs::RAM).unwrap();
    s2.map_page(0x2000, 0x9000_1000, S2Attrs::ROM).unwrap();
    assert_eq!(s2.unmap_page(0x1000), Ok(0x9000_0000));
    assert_eq!(s2.translate(0x1000), None);
    assert_eq!(s2.translate(0x2000), Some((0x9000_1000, S2Attrs::ROM)));
    assert_eq!(s2.unmap_page(0x1000), Err(S2Error::NotMapped));
    assert_eq!(s2.unmap_page(0x7000_0000), Err(S2Error::NotMapped));
    // The slot is reusable.
    s2.map_page(0x1000, 0x9000_2000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.translate(0x1000).unwrap().0, 0x9000_2000);
}

#[test]
fn a_run_uses_blocks_only_where_alignment_and_length_allow() {
    // 2 MiB blocks: start 2 MiB aligned, 4 MiB + 8 KiB long, so two blocks
    // and two pages; no level-3 table for the blocks.
    let cfg = VtcrConfig::new(39, 2).unwrap();
    let mut m = Arena::new(64);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_run(0x4000_0000, 0x8000_0000, 0x40_2000, S2Attrs::RAM).unwrap();
    for off in [0u64, 0x1000, 0x20_0000, 0x3F_F000, 0x40_0000, 0x40_1000] {
        assert_eq!(s2.translate(0x4000_0000 + off).unwrap().0, 0x8000_0000 + off, "off {:#x}", off);
    }
    assert_eq!(s2.translate(0x4040_2000), None);
    // root + L2 + one L3 table for the two tail pages.
    assert_eq!(m.used(), 3);

    // Misaligned relative to each other: the physical side is 4 KiB off a
    // 2 MiB boundary, so pages all the way.
    let mut m = Arena::new(64);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_run(0x4000_0000, 0x8000_1000, 0x20_0000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.translate(0x4000_0000).unwrap().0, 0x8000_1000);
    assert_eq!(s2.translate(0x401F_F000).unwrap().0, 0x8020_0000);
    // 512 pages: root + L2 + one L3 table only.
    assert_eq!(m.used(), 3);

    // A 1 GiB block at a start level that has one (level 1 for 39 bits).
    let mut m = Arena::new(8);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    s2.map_run(0x4000_0000, 0xC000_0000, 0x4000_0000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.translate(0x7FFF_F000).unwrap().0, 0xFFFF_F000);
    assert_eq!(m.used(), 1, "just the root: the GiB is one block descriptor");

    // At a 34-bit IPA the walk starts at level 2: there is no level-1 block.
    let c34 = VtcrConfig::new(34, 2).unwrap();
    let mut m = Arena::new(64);
    let mut s2 = Stage2::new(c34, &mut m).unwrap();
    s2.map_run(0x4000_0000, 0xC000_0000, 0x4000_0000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.translate(0x7FFF_F000).unwrap().0, 0xFFFF_F000);
    assert_eq!(s2.map_leaf(0x8000_0000, 0xC000_0000, 1, S2Attrs::RAM), Err(S2Error::BadLevel));
    assert_eq!(m.used(), 16, "only the 16 concatenated root tables: 512 two-MiB blocks, no more tables");
}

#[test]
fn the_mapper_refuses_what_it_cannot_place() {
    let cfg = VtcrConfig::new(39, 2).unwrap();
    let mut m = Arena::new(3);
    let mut s2 = Stage2::new(cfg, &mut m).unwrap();
    assert_eq!(s2.map_page(1 << 39, 0x9000_0000, S2Attrs::RAM), Err(S2Error::IpaOutOfRange));
    assert_eq!(s2.map_page(0x1800, 0x9000_0000, S2Attrs::RAM), Err(S2Error::Misaligned));
    assert_eq!(s2.map_leaf(0x1000, 0x9000_0000, 2, S2Attrs::RAM), Err(S2Error::Misaligned));
    // root + L2 + L3 fill the arena; a page in another 1 GiB needs more.
    s2.map_page(0x1000, 0x9000_0000, S2Attrs::RAM).unwrap();
    assert_eq!(s2.map_page(0x4000_0000, 0x9000_1000, S2Attrs::RAM), Err(S2Error::NoMemory));
    // A root that cannot be allocated.
    let mut tiny = Arena::new(1);
    assert!(matches!(Stage2::new(VtcrConfig::new(40, 2).unwrap(), &mut tiny), Err(S2Error::NoMemory)));
}

// ── the vGICv3 list registers ───────────────────────────────────────────

#[test]
fn an_lr_has_every_field_at_its_architected_bit() {
    let lr = lr_value(LrState::Pending, 0x1234, 0xA0, true, None, false);
    assert_eq!(lr, 1u64 << 62 | 1u64 << 60 | 0xA0u64 << 48 | 0x1234);
    assert_eq!(lr_state(lr), LrState::Pending);
    assert_eq!(lr_vintid(lr), 0x1234);
    assert_eq!(lr_priority(lr), 0xA0);
    assert!(lr_group1(lr));
    assert_eq!(lr_hw(lr), None);

    // HW = 1: bit 61, pINTID in [41:32]; EOI is not available.
    let hwlr = lr_value(LrState::Active, 27, 0x40, false, Some(0x3FF), true);
    assert_eq!(hwlr, 2u64 << 62 | 1u64 << 61 | 0x3FFu64 << 32 | 0x40u64 << 48 | 27);
    assert_eq!(lr_hw(hwlr), Some(0x3FF));
    assert!(!lr_eoi_maint(hwlr), "EOI shares bit 41 with pINTID: only without HW");
    assert_eq!(lr_state(hwlr), LrState::Active);
    assert!(!lr_group1(hwlr));

    // A software interrupt asking for the EOI maintenance interrupt.
    let eoi = lr_value(LrState::Pending, 5, 0, false, None, true);
    assert_eq!(eoi, 1u64 << 62 | 1u64 << 41 | 5);
    assert!(lr_eoi_maint(eoi));
    assert_eq!(lr_state(lr_value(LrState::PendingActive, 1, 0, false, None, false)), LrState::PendingActive);
    assert_eq!(lr_state(0), LrState::Invalid);
}

#[test]
fn the_lr_count_is_listregs_plus_one() {
    assert_eq!(nr_lrs_from_vtr(0), 1);
    assert_eq!(nr_lrs_from_vtr(3), 4);
    assert_eq!(nr_lrs_from_vtr(15), 16);
    // Bits above ListRegs (PREbits, PRIbits, ...) do not count.
    assert_eq!(nr_lrs_from_vtr(0xFFFF_FFE3), 4);
}

#[test]
fn injections_take_free_lrs_then_queue_by_priority() {
    let mut v = VgicCpu::new(2);
    assert_eq!(v.inject(30, 0x80, true, None), Ok(Injected::Listed(0)));
    assert_eq!(v.inject(31, 0x80, true, None), Ok(Injected::Listed(1)));
    assert_eq!(v.elrsr(), 0);
    assert_eq!(v.hcr(), ICH_HCR_EN, "no queue, no maintenance interrupt");
    // Every LR busy: the rest queue, most urgent (lowest number) first, FIFO
    // within a priority.
    assert_eq!(v.inject(40, 0x90, true, None), Ok(Injected::Queued));
    assert_eq!(v.inject(41, 0x20, true, None), Ok(Injected::Queued));
    assert_eq!(v.inject(42, 0x90, true, None), Ok(Injected::Queued));
    assert_eq!(v.inject(43, 0x20, true, None), Ok(Injected::Queued));
    assert_eq!(v.queued(), 4);
    assert_eq!(v.hcr(), ICH_HCR_EN | ICH_HCR_UIE);

    // The guest acknowledges and ends LR0 and LR1: both become Invalid.
    let after_guest = [0u64, 0u64];
    v.absorb(&after_guest);
    let lrs = v.lrs();
    assert_eq!((lr_vintid(lrs[0]), lr_priority(lrs[0])), (41, 0x20));
    assert_eq!((lr_vintid(lrs[1]), lr_priority(lrs[1])), (43, 0x20));
    assert_eq!(lr_state(lrs[0]), LrState::Pending);
    assert_eq!(v.queued(), 2);

    // Next round: LR0 only is freed; 40 (0x90) arrived before 42 (0x90).
    let lr1 = v.lrs()[1];
    v.absorb(&[0, lr1]);
    assert_eq!(lr_vintid(v.lrs()[0]), 40);
    v.absorb(&[0, lr1]);
    assert_eq!(lr_vintid(v.lrs()[0]), 42);
    assert_eq!(v.queued(), 0);
    assert_eq!(v.hcr(), ICH_HCR_EN);
}

#[test]
fn a_raised_interrupt_merges_while_pending_and_repends_while_active() {
    let mut v = VgicCpu::new(4);
    assert_eq!(v.inject(27, 0x40, true, None), Ok(Injected::Listed(0)));
    assert_eq!(v.inject(27, 0x40, true, None), Ok(Injected::Merged));
    assert_eq!(lr_state(v.lrs()[0]), LrState::Pending);
    assert_eq!(v.lrs().iter().filter(|&&l| lr_state(l) != LrState::Invalid).count(), 1, "still one");

    // The guest acknowledged it (Active) and the device raised it again.
    let active = lr_value(LrState::Active, 27, 0x40, true, None, false);
    v.absorb(&[active, 0, 0, 0]);
    assert_eq!(v.inject(27, 0x40, true, None), Ok(Injected::Merged));
    assert_eq!(lr_state(v.lrs()[0]), LrState::PendingActive);
    assert_eq!(lr_vintid(v.lrs()[0]), 27, "the other fields are kept");
    assert_eq!(lr_priority(v.lrs()[0]), 0x40);

    // Queued ones merge too.
    let mut q = VgicCpu::new(1);
    q.inject(1, 0, false, None).unwrap();
    assert_eq!(q.inject(2, 0, false, None), Ok(Injected::Queued));
    assert_eq!(q.inject(2, 0, false, None), Ok(Injected::Merged));
    assert_eq!(q.queued(), 1);
}

#[test]
fn a_hardware_linked_interrupt_keeps_its_physical_id_through_the_queue() {
    let mut v = VgicCpu::new(1);
    v.inject(48, 0x10, true, None).unwrap();
    assert_eq!(v.inject(49, 0x10, true, Some(77)), Ok(Injected::Queued));
    v.absorb(&[0]);
    assert_eq!(lr_hw(v.lrs()[0]), Some(77));
    assert_eq!(lr_vintid(v.lrs()[0]), 49);
    assert_eq!(v.inject(50, 0, true, Some(1024)), Err(VgicError::BadPhysicalIntid));
}

#[test]
fn the_queue_is_bounded_and_the_lr_count_is_clamped() {
    let mut v = VgicCpu::new(1);
    v.inject(0, 0, false, None).unwrap();
    for i in 0..QUEUE_CAP as u32 {
        assert_eq!(v.inject(100 + i, 0, false, None), Ok(Injected::Queued));
    }
    assert_eq!(v.inject(999, 0, false, None), Err(VgicError::QueueFull));
    assert_eq!(v.queued(), QUEUE_CAP);
    assert_eq!(VgicCpu::new(0).lrs().len(), 1);
    assert_eq!(VgicCpu::new(99).lrs().len(), MAX_LRS);
    // ELRSR for 16 free LRs.
    assert_eq!(VgicCpu::new(16).elrsr(), 0xFFFF);
    // Reading back fewer registers than there are leaves the rest alone.
    let mut w = VgicCpu::new(4);
    w.inject(7, 0, false, None).unwrap();
    w.absorb(&[0]);
    assert_eq!(w.elrsr(), 0b1111);
}

// ── the virtual timer ───────────────────────────────────────────────────

#[test]
fn cnthctl_grants_the_host_the_physical_timer_and_traps_it_for_a_guest() {
    assert_eq!(Cnthctl::HOST.bits(), 0b11);
    assert_eq!(Cnthctl::GUEST.bits(), 0);
    assert!(Cnthctl::HOST.guest_has_physical_timer() && !Cnthctl::GUEST.guest_has_physical_timer());
    // The other bits (event stream, ECV controls) are kept.
    let base = 0xFFFF_FFFF_FFFF_FFFFu64;
    assert_eq!(Cnthctl::GUEST.apply(base), base & !0b11);
    assert_eq!(Cnthctl::HOST.apply(0b1_0100), 0b1_0111);
    assert_eq!(Cnthctl::HOST.apply(Cnthctl::GUEST.apply(0x5555)), 0x5555 | 0b11);
}

#[test]
fn a_guest_clock_stops_while_it_is_off_the_cpu() {
    // Left at virtual count 1000 when the physical count was 5000 (offset
    // 4000); resumes at physical 9000: the offset must make it read 1000 again.
    let off = cntvoff_on_resume(9000, 1000);
    assert_eq!(off, 8000);
    assert_eq!(virtual_count(9000, off), 1000);
    assert_eq!(virtual_count(9500, off), 1500, "and it counts on from there");
    // A guest that has never run starts at 0.
    assert_eq!(virtual_count(123, cntvoff_on_resume(123, 0)), 0);
    // The subtraction wraps as the hardware's does.
    let off = cntvoff_on_resume(10, 50);
    assert_eq!(virtual_count(10, off), 50);
    assert_eq!(virtual_count(15, off), 55);
}

#[test]
fn the_virtual_timer_fires_only_enabled_unmasked_and_due() {
    let t = |ctl, cval| Vtimer { ctl, cval };
    // ENABLE = 1, IMASK = 2.
    assert!(t(1, 100).asserted(100), "due exactly at cval");
    assert!(t(1, 100).asserted(101));
    assert!(!t(1, 100).asserted(99));
    assert!(!t(0, 100).asserted(500), "disabled");
    assert!(!t(3, 100).asserted(500), "masked: the condition holds but the line does not");
    assert!(t(3, 100).condition_met(500));
    // ISTATUS (bit 2) follows the condition in what the guest reads, not in what is stored.
    assert_eq!(t(1, 100).ctl_as_read(99), 1);
    assert_eq!(t(1, 100).ctl_as_read(100), 1 | 4);
    assert_eq!(t(3 | 4, 100).ctl_as_read(99), 3, "a stale ISTATUS is cleared");
    assert_eq!(t(0, 100).ctl_as_read(500), 0, "disabled never reports");
}

#[test]
fn the_host_wakes_at_the_physical_count_the_guest_deadline_maps_to() {
    // vcnt = pcnt - off, so the deadline cval in virtual time is cval + off in physical time.
    assert_eq!(Vtimer { ctl: 1, cval: 1500 }.expiry_physical_count(8000), Some(9500));
    assert_eq!(Vtimer { ctl: 0, cval: 1500 }.expiry_physical_count(8000), None);
    assert_eq!(Vtimer { ctl: 3, cval: 1500 }.expiry_physical_count(8000), None);
    // Consistent with the clock: at that physical count the guest reads cval.
    let off = cntvoff_on_resume(9000, 1000);
    let at = Vtimer { ctl: 1, cval: 1500 }.expiry_physical_count(off).unwrap();
    assert!(Vtimer { ctl: 1, cval: 1500 }.asserted(virtual_count(at, off)));
    assert!(!Vtimer { ctl: 1, cval: 1500 }.asserted(virtual_count(at - 1, off)));
    assert_eq!(VTIMER_PPI, 27);
}
