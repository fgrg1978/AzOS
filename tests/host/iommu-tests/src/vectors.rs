// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Spec vectors: entries, commands and records, as the specifications lay
//! them out.

use azos_dma::Direction;
use azos_iommu::pgtable::{Perm, PtFormat, PtKind};
use azos_iommu::{amdvi, riscv, smmuv3, vtd, DomainMode, FaultKind};

const RW: Perm = Perm { read: true, write: true };
const RO: Perm = Perm { read: true, write: false };
const WO: Perm = Perm { read: false, write: true };

// ---------------------------------------------------------------------
// I/O page-table entries
// ---------------------------------------------------------------------

#[test]
fn riscv_pte_vectors() {
    let f = PtFormat::new(PtKind::RiscvSv, 3);
    // PPN = 0x80001000 >> 12 = 0x80001, at bits 53:10 -> 0x80001 << 10 = 0x2000_0400.
    // Flags: V 0x01, R 0x02, W 0x04, U 0x10, A 0x40, D 0x80.
    assert_eq!(f.leaf_entry(0x8000_1000, RW), 0x2000_0400 | 0x01 | 0x02 | 0x04 | 0x10 | 0x40 | 0x80);
    assert_eq!(f.leaf_entry(0x8000_1000, RW), 0x2000_04D7);
    assert_eq!(f.leaf_entry(0x8000_1000, RO), 0x2000_04D3);
    // W without R is a reserved encoding: write-only is granted read-write.
    assert_eq!(f.leaf_entry(0x8000_1000, WO), 0x2000_04D7);
    // A pointer to a table: PPN and V, no R/W/X.
    assert_eq!(f.table_entry(0x8020_0000, 1), (0x80200 << 10) | 1);
    assert_eq!(f.table_entry(0x8020_0000, 1), 0x2008_0001);
    assert!(f.is_present(0x2008_0001));
    assert!(!f.is_upper_leaf(0x2008_0001));
    assert!(f.is_upper_leaf(0x2000_04D3), "R set: a leaf");
    assert_eq!(f.entry_pa(0x2000_04D7), 0x8000_1000);
    assert_eq!(f.leaf_perm(0x2000_04D3), RO);
}

#[test]
fn arm_lpae_descriptor_vectors() {
    let f = PtFormat::new(PtKind::ArmLpae, 4);
    // Page descriptor: bits 1:0 = 0b11 (3); AttrIndx 4:2 = 0; AP[1] (bit 6,
    // 0x40) lets unprivileged transactions in; SH 9:8 = 0b11 (0x300); AF
    // bit 10 (0x400); nG bit 11 (0x800); PXN bit 53 and UXN bit 54.
    let xn = (1u64 << 53) | (1 << 54);
    assert_eq!(xn, 0x0060_0000_0000_0000);
    assert_eq!(f.leaf_entry(0x8000_1000, RW), 0x8000_1000 | 0x3 | 0x40 | 0x300 | 0x400 | 0x800 | xn);
    assert_eq!(f.leaf_entry(0x8000_1000, RW), 0x0060_0000_8000_1F43);
    // AP[2] (bit 7, 0x80) makes it read-only.
    assert_eq!(f.leaf_entry(0x8000_1000, RO), 0x0060_0000_8000_1FC3);
    assert_eq!(f.leaf_entry(0x8000_1000, WO), 0x0060_0000_8000_1F43);
    // Table descriptor: address and 0b11.
    assert_eq!(f.table_entry(0x8020_0000, 2), 0x8020_0003);
    assert!(f.is_present(0x8020_0003));
    assert!(!f.is_upper_leaf(0x8020_0003));
    assert!(f.is_upper_leaf(0x8020_0001), "bit 1 clear: a block");
    assert_eq!(f.leaf_perm(0x0060_0000_8000_1FC3), RO);
}

#[test]
fn vtd_second_level_entry_vectors() {
    let f = PtFormat::new(PtKind::Vtd, 4);
    // R bit 0, W bit 1, address bits 51:12; no other bit set.
    assert_eq!(f.leaf_entry(0x8000_1000, RW), 0x8000_1003);
    assert_eq!(f.leaf_entry(0x8000_1000, RO), 0x8000_1001);
    assert_eq!(f.leaf_entry(0x8000_1000, WO), 0x8000_1002);
    assert_eq!(f.table_entry(0x8020_0000, 1), 0x8020_0003);
    // Present means R or W; bit 7 (SP) in an upper table is a superpage.
    assert!(f.is_present(0x8000_1002));
    assert!(!f.is_present(0x8000_1000));
    assert!(f.is_upper_leaf(0x8020_0083));
    assert_eq!(f.leaf_perm(0x8000_1002), WO);
}

#[test]
fn amd_vi_entry_vectors() {
    let f = PtFormat::new(PtKind::AmdVi, 4);
    // PR bit 0, IR bit 61 (0x2000_0000_0000_0000), IW bit 62 (0x4000_...).
    assert_eq!(f.leaf_entry(0x8000_1000, RW), 0x6000_0000_8000_1001);
    assert_eq!(f.leaf_entry(0x8000_1000, RO), 0x2000_0000_8000_1001);
    assert_eq!(f.leaf_entry(0x8000_1000, WO), 0x4000_0000_8000_1001);
    // A table entry carries PR, IR, IW and NextLevel (bits 11:9) = the AMD
    // level of the table it points at (leaf table = 1): child_level 0 -> 1.
    assert_eq!(f.table_entry(0x8020_0000, 0), 0x6000_0000_8020_0201);
    assert_eq!(f.table_entry(0x8020_0000, 2), 0x6000_0000_8020_0601);
    // NextLevel 0 or 7 in an upper table is a leaf / default-size page.
    assert!(f.is_upper_leaf(0x6000_0000_8020_0001));
    assert!(f.is_upper_leaf(0x6000_0000_8020_0E01));
    assert!(!f.is_upper_leaf(0x6000_0000_8020_0601));
}

#[test]
fn directions_ask_for_the_permission_the_device_needs() {
    assert_eq!(Perm::of(Direction::ToDevice), RO, "the device reads");
    assert_eq!(Perm::of(Direction::FromDevice), WO, "the device writes");
    assert_eq!(Perm::of(Direction::Bidirectional), RW);
}

// ---------------------------------------------------------------------
// RISC-V IOMMU
// ---------------------------------------------------------------------

#[test]
fn riscv_device_context_vectors() {
    // fsc = MODE[63:60] | PPN[43:0]; Sv39 = 8, Sv48 = 9; PPN = 0x80200000 >> 12 = 0x80200.
    let sv39 = riscv::DeviceContext::encode(DomainMode::Translate { root_pa: 0x8020_0000 }, 3, 5);
    // ta: PSCID 5 at 31:12 = 0x5000.
    assert_eq!((sv39.tc, sv39.iohgatp, sv39.ta), (1, 0, 0x5000));
    assert_eq!(sv39.fsc, 0x8000_0000_0008_0200);
    let sv48 = riscv::DeviceContext::encode(DomainMode::Translate { root_pa: 0x8020_0000 }, 4, 5);
    assert_eq!(sv48.fsc, 0x9000_0000_0008_0200);
    // Bypass: valid, first stage Bare.
    let bypass = riscv::DeviceContext::encode(DomainMode::Bypass, 3, 0);
    assert_eq!((bypass.tc, bypass.ta, bypass.fsc), (1, 0, 0));
    // Block: not valid.
    let block = riscv::DeviceContext::encode(DomainMode::Block, 3, 0);
    assert!(!block.is_valid());
    assert_eq!(block.decode_mode(), Some(DomainMode::Block));
    // Round trips.
    assert_eq!(sv39.decode_mode(), Some(DomainMode::Translate { root_pa: 0x8020_0000 }));
    assert_eq!(bypass.decode_mode(), Some(DomainMode::Bypass));
    // The base format is four dwords, the extended one eight.
    assert_eq!(sv39.to_dwords(false).1, 4);
    assert_eq!(sv39.to_dwords(true).1, 8);
    assert_eq!(sv39.to_dwords(true).0[3], sv39.fsc);
}

#[test]
fn riscv_ddt_index_vectors() {
    // Extended format (64-byte DC): 6 bits at the leaf, 9 above.
    assert_eq!(riscv::ddt_index(0x18, true), Some((0, 0x18)));
    assert_eq!(riscv::ddt_index(0x1c5, true), Some((7, 5))); // 0x1c5 = 0b111_000101
    assert_eq!(riscv::ddt_index(1 << 15, true), None);
    // Base format (32-byte DC): 7 and 9.
    assert_eq!(riscv::ddt_index(0x1c5, false), Some((3, 0x45)));
    assert_eq!(riscv::ddt_index(1 << 16, false), None);
    // A non-leaf entry: PPN at bit 10, V at bit 0.
    assert_eq!(riscv::ddt_nonleaf(0x8030_0000), (0x80300 << 10) | 1);
}

#[test]
fn riscv_command_vectors() {
    // IODIR: opcode 3 (6:0), func INVAL_DDT 0 (9:7), DV bit 33, DID 63:40.
    assert_eq!(riscv::cmd_iodir_inval_ddt(0x18), [0x0000_1802_0000_0003, 0]);
    // IOFENCE.C: opcode 2, PR bit 12 (0x1000), PW bit 13 (0x2000).
    assert_eq!(riscv::cmd_iofence(), [0x3002, 0]);
    // IOTINVAL.VMA: opcode 1, func 0, PSCV bit 32, PSCID 31:12; no address
    // or guest scope.
    assert_eq!(riscv::cmd_iotinval_vma_pscid(0x18), [0x1_0001_8001, 0]);
}

#[test]
fn riscv_fault_record_vector() {
    // hdr: CAUSE[11:0] = 13 (load page fault), DID[63:40] = 0x18; iotval at +16.
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&0x0000_1800_0000_000du64.to_le_bytes());
    raw[16..24].copy_from_slice(&0x8000_1000u64.to_le_bytes());
    let rec = riscv::FaultRecord::decode(&raw);
    assert_eq!((rec.cause, rec.device_id, rec.iotval), (13, 0x18, 0x8000_1000));
    assert_eq!(rec.encode(), raw);
    let f = riscv::classify(&rec);
    assert_eq!((f.device_id, f.fault_addr, f.kind), (0x18, 0x8000_1000, FaultKind::UnmappedIova));
}

#[test]
fn riscv_fault_causes_classify() {
    let k = |cause| riscv::classify(&riscv::FaultRecord { cause, device_id: 1, iotval: 0 }).kind;
    assert_eq!(k(12), FaultKind::UnmappedIova);
    assert_eq!(k(13), FaultKind::UnmappedIova);
    assert_eq!(k(15), FaultKind::UnmappedIova);
    for c in [256, 257, 258, 259, 260, 268] {
        assert_eq!(k(c), FaultKind::BadDeviceEntry, "cause {c}");
    }
    assert_eq!(k(5), FaultKind::Other(5), "a plain access fault is not a page-table fault");
}

// ---------------------------------------------------------------------
// SMMUv3
// ---------------------------------------------------------------------

#[test]
fn smmu_ste_vectors() {
    // Bypass: V bit 0, Config bits 3:1 = 0b100 -> 1 | 4<<1 = 9; dword 1 SHCFG
    // bits 45:44 = 0b01 (use incoming attributes) -> 1<<44.
    let b = smmuv3::encode_ste(DomainMode::Bypass, 0);
    assert_eq!(b[0], 0x9);
    assert_eq!(b[1], 0x0000_1000_0000_0000);
    assert!(b[2..].iter().all(|w| *w == 0));
    // Stage 1 translate: Config = 0b101 -> 1 | 5<<1 = 0xb, S1ContextPtr 51:6
    // = the CD's address; dword 1: S1DSS 1:0 = 2, S1CIR 3:2 = 1 (0x4), S1COR
    // 5:4 = 1 (0x10), S1CSH 7:6 = 3 (0xc0), SHCFG 1<<44.
    let t = smmuv3::encode_ste(DomainMode::Translate { root_pa: 0x8020_0000 }, 0x8010_0000);
    assert_eq!(t[0], 0x8010_000b);
    assert_eq!(t[1], 0x0000_1000_0000_00d6);
    // Block: all zero (V clear).
    assert_eq!(smmuv3::encode_ste(DomainMode::Block, 0), [0; 8]);
}

#[test]
fn smmu_cd_vector() {
    // 4 levels from a 48-bit input: T0SZ = 64 - 48 = 16 (0x10); IRGN0 = 1
    // (<<8 = 0x100); ORGN0 = 1 (<<10 = 0x400); SH0 = 3 (<<12 = 0x3000);
    // EPD1 bit 30; V bit 31; IPS = 5 (48-bit) at 34:32; AA64 bit 41; R 45;
    // A 46; ASET 47; ASID = 1 at 63:48.
    let cd = smmuv3::encode_cd(0x8020_0000, 4, 5, 1);
    assert_eq!(cd[0], 0x0001_E205_C000_3510);
    assert_eq!(cd[1], 0x8020_0000, "TTB0");
    assert_eq!(cd[2], 0, "TTB1 unused");
    assert_eq!(cd[3], 0xff, "MAIR attribute 0: normal write-back");
    // Three levels: T0SZ = 64 - 39 = 25 (0x19).
    assert_eq!(smmuv3::encode_cd(0x8020_0000, 3, 5, 1)[0] & 0x3f, 25);
}

#[test]
fn smmu_command_vectors() {
    // CFGI_STE: opcode 0x03 in 7:0, StreamID in 63:32; dword 2 bit 0 = Leaf.
    assert_eq!(smmuv3::cmd_cfgi_ste(0x18), [0x18_0000_0003, 1]);
    assert_eq!(smmuv3::cmd_cfgi_all(), [0x04, 31]);
    // CFGI_CD_ALL: opcode 0x06, StreamID in 63:32.
    assert_eq!(smmuv3::cmd_cfgi_cd_all(0x18), [0x18_0000_0006, 0]);
    assert_eq!(smmuv3::cmd_tlbi_nsnh_all(), [0x30, 0]);
    assert_eq!(smmuv3::cmd_tlbi_nh_asid(1), [0x0001_0000_0000_0011, 0]);
    // CMD_SYNC: opcode 0x46, CS bits 13:12 = 2 (SEV).
    assert_eq!(smmuv3::cmd_sync(), [0x2046, 0]);
}

#[test]
fn smmu_event_record_vector() {
    // dword 0: event 0x10 (F_TRANSLATION) in 7:0, StreamID 0x18 in 63:32;
    // the input address is dword 2 (byte 16).
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&0x0000_0018_0000_0010u64.to_le_bytes());
    raw[16..24].copy_from_slice(&0x8000_1000u64.to_le_bytes());
    let rec = smmuv3::EventRecord::decode(&raw);
    assert_eq!((rec.event_type, rec.stream_id, rec.input_addr), (0x10, 0x18, 0x8000_1000));
    assert_eq!(rec.encode(), raw);
    let f = smmuv3::classify(&rec);
    assert_eq!((f.device_id, f.fault_addr, f.kind), (0x18, 0x8000_1000, FaultKind::UnmappedIova));
}

#[test]
fn smmu_events_classify() {
    let k = |t| smmuv3::classify(&smmuv3::EventRecord { event_type: t, stream_id: 1, input_addr: 0 }).kind;
    assert_eq!(k(0x10), FaultKind::UnmappedIova); // F_TRANSLATION
    assert_eq!(k(0x13), FaultKind::UnmappedIova); // F_PERMISSION
    for t in [0x02, 0x03, 0x04, 0x06, 0x09, 0x0a] {
        assert_eq!(k(t), FaultKind::BadDeviceEntry, "event {t:#x}");
    }
    assert_eq!(k(0x11), FaultKind::Other(0x11), "F_ADDR_SIZE is not an unmapped access");
    assert_eq!(k(0x12), FaultKind::Other(0x12), "F_ACCESS");
}

// ---------------------------------------------------------------------
// VT-d
// ---------------------------------------------------------------------

#[test]
fn vtd_table_entry_vectors() {
    // Root entry: P bit 0, context-table pointer 63:12.
    assert_eq!(vtd::root_entry(0x8030_0000), [0x8030_0001, 0]);
    // Context entry, translate: P, TT (3:2) = 0, SLPTPTR 63:12; high: AW (2:0)
    // = 2 (48-bit), DID (23:8) = 2 -> 2 | 2<<8 = 0x202.
    assert_eq!(
        vtd::context_entry(DomainMode::Translate { root_pa: 0x8020_0000 }, 2, 2),
        [0x8020_0001, 0x202]
    );
    // Pass-through: TT = 2 -> 2<<2 = 8, plus P; no page-table pointer.
    assert_eq!(vtd::context_entry(DomainMode::Bypass, 2, 1), [0x9, 0x102]);
    // Block: not present.
    assert_eq!(vtd::context_entry(DomainMode::Block, 2, 1), [0, 0]);
}

#[test]
fn vtd_capability_decoding() {
    // IRO (ECAP 17:8) = 0x100 -> IOTLB registers at 0x100*16, the IOTLB
    // invalidate register 8 bytes in.
    assert_eq!(vtd::iotlb_reg(0x100 << 8), 0x1008);
    // FRO (CAP 33:24) = 0x20 -> fault recording at 0x200; NFR (CAP 47:40) = 0 -> 1 register.
    assert_eq!(vtd::frcd_base(0x20 << 24), 0x200);
    assert_eq!(vtd::frcd_count(0), 1);
    assert_eq!(vtd::frcd_count(3 << 40), 4);
    // SAGAW (CAP 12:8); ND (CAP 2:0) = 6 -> 16 << 12 = 65536 domains.
    assert_eq!(vtd::sagaw(0b100 << 8), 0b100);
    assert_eq!(vtd::ndoms(6), 65536);
    assert_eq!(vtd::ndoms(0), 16);
}

#[test]
fn vtd_fault_record_vector() {
    // Low qword: FI 63:12 = the page address. High qword: SID 15:0, FR
    // 39:32, F bit 63.
    let rec = vtd::FaultRecord::decode(0x8000_1000, 0x8000_0005_0000_0018).unwrap();
    assert_eq!((rec.reason, rec.source_id, rec.page_addr), (5, 0x18, 0x8000_1000));
    assert_eq!(rec.encode(), (0x8000_1000, 0x8000_0005_0000_0018));
    assert_eq!(vtd::FaultRecord::decode(0x8000_1000, 0x0000_0005_0000_0018), None, "F clear: empty");
    let f = vtd::classify(&rec);
    assert_eq!((f.device_id, f.fault_addr, f.kind), (0x18, 0x8000_1000, FaultKind::UnmappedIova));
}

#[test]
fn vtd_reasons_classify() {
    let k = |r| vtd::classify(&vtd::FaultRecord { reason: r, source_id: 1, page_addr: 0 }).kind;
    for r in [4, 5, 6] {
        assert_eq!(k(r), FaultKind::UnmappedIova, "reason {r}");
    }
    for r in [1, 2, 3, 8, 9, 10, 11, 13] {
        assert_eq!(k(r), FaultKind::BadDeviceEntry, "reason {r}");
    }
    assert_eq!(k(7), FaultKind::Other(7));
}

// ---------------------------------------------------------------------
// AMD-Vi
// ---------------------------------------------------------------------

#[test]
fn amd_dte_vectors() {
    // Translate, 4 levels: V bit 0, TV bit 1, Mode (11:9) = 4 -> 0x800, root
    // 51:12, IR bit 61, IW bit 62; qword 1 DomainID; qword 2 IntCtl (61:60)
    // = 01b -> bit 60.
    let t = amdvi::encode_dte(DomainMode::Translate { root_pa: 0x8020_0000 }, 4, 2);
    assert_eq!(t, [0x6000_0000_8020_0803, 2, 1 << 60, 0]);
    // Pass-through: translation valid, Mode 0.
    assert_eq!(amdvi::encode_dte(DomainMode::Bypass, 4, 1), [0x6000_0000_0000_0003, 1, 1 << 60, 0]);
    assert_eq!(amdvi::encode_dte(DomainMode::Block, 4, 1), [0; 4]);
}

#[test]
fn amd_command_vectors() {
    // Each command is four dwords; here as two qwords. The opcode is bits
    // 31:28 of dword 1 = bits 63:60 of the first qword.
    assert_eq!(amdvi::cmd_inv_dev_entry(0x18), [0x2000_0000_0000_0018, 0]);
    assert_eq!(amdvi::cmd_inv_all(), [0x8000_0000_0000_0000, 0]);
    // COMPLETION_WAIT, store 5 at 0x8000_1000: dword 0 = address 31:3 | S;
    // dword 1 = address 51:32 | opcode 1 << 28; dwords 2-3 = the data.
    assert_eq!(amdvi::cmd_completion_wait(0x8000_1000, 5), [0x1000_0000_8000_1001, 5]);
    // INVALIDATE_IOMMU_PAGES for domain 2: dword 1 = domain | opcode 3 << 28;
    // dwords 2-3 = address 0x7fff_ffff_ffff_f000 with S (bit 0) and PDE (bit 1).
    assert_eq!(amdvi::cmd_inv_pages_all(2), [0x3000_0002_0000_0000, 0x7fff_ffff_ffff_f003]);
}

#[test]
fn amd_event_vector() {
    // Dword 0: DeviceID 15:0; dword 1 bits 31:28: event type 2 (IO_PAGE_FAULT);
    // dwords 2-3: the address.
    let rec = amdvi::EventRecord::decode(0x2000_0000_0000_0018, 0x8000_1000);
    assert_eq!((rec.event_type, rec.device_id, rec.address), (2, 0x18, 0x8000_1000));
    assert_eq!(rec.encode(), (0x2000_0000_0000_0018, 0x8000_1000));
    let f = amdvi::classify(&rec);
    assert_eq!((f.device_id, f.fault_addr, f.kind), (0x18, 0x8000_1000, FaultKind::UnmappedIova));
    let bad = amdvi::classify(&amdvi::EventRecord { event_type: 1, device_id: 1, address: 0 });
    assert_eq!(bad.kind, FaultKind::BadDeviceEntry);
}

// ---------------------------------------------------------------------
// Register offsets, as the specifications and the Linux headers list them
// ---------------------------------------------------------------------

#[test]
fn register_offsets_and_bits_match_the_specifications() {
    // RISC-V IOMMU (riscv-iommu spec, register layout).
    assert_eq!(
        [riscv::REG_CAP, riscv::REG_FCTL, riscv::REG_DDTP, riscv::REG_CQB, riscv::REG_CQH, riscv::REG_CQT],
        [0x00, 0x08, 0x10, 0x18, 0x20, 0x24]
    );
    assert_eq!(
        [riscv::REG_FQB, riscv::REG_FQH, riscv::REG_FQT, riscv::REG_CQCSR, riscv::REG_FQCSR],
        [0x28, 0x30, 0x34, 0x48, 0x4c]
    );
    // capabilities: Sv39 bit 9, Sv48 bit 10, MSI_FLAT bit 22; ddtp.BUSY bit 4.
    assert_eq!((riscv::CAP_SV39, riscv::CAP_SV48, riscv::CAP_MSI_FLAT), (1 << 9, 1 << 10, 1 << 22));
    assert_eq!(riscv::DDTP_BUSY, 0x10);
    // queue CSR: enable bit 0, active bit 16, busy bit 17.
    assert_eq!((riscv::QCSR_EN, riscv::QCSR_ON, riscv::QCSR_BUSY), (1, 1 << 16, 1 << 17));

    // SMMUv3 (IHI 0070, register map).
    assert_eq!(
        [smmuv3::REG_IDR0, smmuv3::REG_IDR1, smmuv3::REG_IDR5, smmuv3::REG_CR0, smmuv3::REG_CR0ACK],
        [0x00, 0x04, 0x14, 0x20, 0x24]
    );
    assert_eq!(
        [smmuv3::REG_STRTAB_BASE, smmuv3::REG_STRTAB_BASE_CFG, smmuv3::REG_CMDQ_BASE, smmuv3::REG_CMDQ_PROD],
        [0x80, 0x88, 0x90, 0x98]
    );
    assert_eq!([smmuv3::REG_CMDQ_CONS, smmuv3::REG_EVTQ_BASE], [0x9c, 0xa0]);
    // The event queue's PROD and CONS are in register page 1 (+0x10000).
    assert_eq!([smmuv3::REG_EVTQ_PROD, smmuv3::REG_EVTQ_CONS], [0x100a8, 0x100ac]);
    assert_eq!((smmuv3::CR0_SMMUEN, smmuv3::CR0_EVTQEN, smmuv3::CR0_CMDQEN), (1, 4, 8));

    // VT-d (spec ch. 10).
    assert_eq!(
        [vtd::REG_CAP, vtd::REG_ECAP, vtd::REG_GCMD, vtd::REG_GSTS, vtd::REG_RTADDR, vtd::REG_CCMD],
        [0x08, 0x10, 0x18, 0x1c, 0x20, 0x28]
    );
    assert_eq!([vtd::REG_FSTS, vtd::REG_FECTL], [0x34, 0x38]);
    assert_eq!((vtd::GCMD_TE, vtd::GCMD_SRTP, vtd::GSTS_TES, vtd::GSTS_RTPS), (1 << 31, 1 << 30, 1 << 31, 1 << 30));
    assert_eq!((vtd::CCMD_ICC, vtd::CCMD_GLOBAL), (1 << 63, 1 << 61));
    assert_eq!((vtd::IOTLB_IVT, vtd::IOTLB_GLOBAL), (1 << 63, 1 << 60));
    assert_eq!(vtd::ECAP_PT, 1 << 6);

    // AMD-Vi (spec ch. 3, MMIO registers).
    assert_eq!(
        [amdvi::REG_DEV_TABLE, amdvi::REG_CMD_BUF, amdvi::REG_EVT_LOG, amdvi::REG_CONTROL],
        [0x0000, 0x0008, 0x0010, 0x0018]
    );
    assert_eq!(
        [amdvi::REG_CMD_HEAD, amdvi::REG_CMD_TAIL, amdvi::REG_EVT_HEAD, amdvi::REG_EVT_TAIL, amdvi::REG_STATUS],
        [0x2000, 0x2008, 0x2010, 0x2018, 0x2020]
    );
    assert_eq!((amdvi::CTRL_IOMMU_EN, amdvi::CTRL_EVT_LOG_EN, amdvi::CTRL_CMD_BUF_EN), (1, 4, 0x1000));
}
