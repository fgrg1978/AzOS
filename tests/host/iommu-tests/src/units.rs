// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The four units brought up against models of their registers: what they
//! write, in which order, and what they leave in memory.

use crate::common::{read64, write64, FakeMmio, TestMem};
use azos_iommu::pgtable::PtKind;
use azos_iommu::riscv::RiscvIommu;
use azos_iommu::smmuv3::Smmuv3;
use azos_iommu::vtd::Vtd;
use azos_iommu::amdvi::AmdVi;
use azos_iommu::{amdvi, riscv, smmuv3, vtd};
use azos_iommu::{DmaFault, DomainMode, FaultKind, Flavour, IommuError, IommuUnit};

fn faults(unit: &mut dyn IommuUnit) -> Vec<DmaFault> {
    let mut v = Vec::new();
    let n = unit.poll_faults(&mut |f| v.push(f));
    assert_eq!(n, v.len());
    v
}

// =====================================================================
// RISC-V IOMMU
// =====================================================================

fn riscv_model(cap: u64) -> FakeMmio {
    FakeMmio::new(
        &[(riscv::REG_CAP, cap)],
        Box::new(|regs, off, val| match off {
            // Enabling a queue turns its "active" bit on.
            riscv::REG_CQCSR | riscv::REG_FQCSR if val & 1 != 0 => {
                regs.r.insert(off, val | (1 << 16));
            }
            // The unit executes commands as they are queued.
            riscv::REG_CQT => {
                regs.r.insert(riscv::REG_CQH, val);
            }
            _ => {}
        }),
    )
}

fn cmds(page: u64, n: usize) -> Vec<[u64; 2]> {
    (0..n).map(|i| [read64(page, 2 * i), read64(page, 2 * i + 1)]).collect()
}

const RV_CAP_EXT: u64 = riscv::CAP_SV39 | riscv::CAP_SV48 | riscv::CAP_MSI_FLAT;

#[test]
fn riscv_bring_up_programs_queues_then_the_device_directory() {
    let mem = TestMem::leak();
    let mmio = riscv_model(RV_CAP_EXT);
    let unit = RiscvIommu::new(mmio.clone(), mem).unwrap();
    let (cq, fq, ddt) = (mem.page(0), mem.page(1), mem.page(2));
    // CQB: PPN at 10, LOG2SZ-1 in the low bits: 256 entries -> 7.
    assert_eq!(mmio.get(riscv::REG_CQB), ((cq >> 12) << 10) | 7);
    assert_eq!(mmio.get(riscv::REG_FQB), ((fq >> 12) << 10) | 6, "128 entries");
    // DDTP: mode 2LVL (3) in the low nibble, PPN at 10.
    assert_eq!(mmio.get(riscv::REG_DDTP), 3 | ((ddt >> 12) << 10));
    // Queues were enabled before the directory was installed.
    let log = mmio.regs.lock().unwrap().log.clone();
    let pos = |off| log.iter().position(|(o, _)| *o == off).unwrap();
    assert!(pos(riscv::REG_CQCSR) < pos(riscv::REG_DDTP));
    assert!(pos(riscv::REG_FQCSR) < pos(riscv::REG_DDTP));
    assert_eq!(unit.flavour(), Flavour::Riscv);
    assert_eq!(unit.pt_format().kind, PtKind::RiscvSv);
    assert_eq!(unit.pt_format().levels, 3, "Sv39 preferred");
    assert!(unit.extended_dc());
}

#[test]
fn riscv_without_sv39_falls_to_sv48_and_without_both_is_refused() {
    let mem = TestMem::leak();
    let unit = RiscvIommu::new(riscv_model(riscv::CAP_SV48), mem).unwrap();
    assert_eq!(unit.pt_format().levels, 4);
    assert!(!unit.extended_dc(), "no MSI_FLAT: base format");
    let err = RiscvIommu::new(riscv_model(0), TestMem::leak()).err().unwrap();
    assert!(matches!(err, IommuError::Unsupported(_)));
}

#[test]
fn riscv_attach_writes_the_context_body_then_valid_then_invalidates() {
    let mem = TestMem::leak();
    let mmio = riscv_model(RV_CAP_EXT);
    let mut unit = RiscvIommu::new(mmio.clone(), mem).unwrap();
    let (cq, ddt) = (mem.page(0), mem.page(2));

    unit.attach(0x18, DomainMode::Bypass).unwrap();
    let leaf = mem.page(3);
    assert_eq!(read64(ddt, 0), ((leaf >> 12) << 10) | 1, "DDT root[0] -> new leaf");
    let dc = leaf + 0x18 * 64; // extended: 64-byte contexts
    assert_eq!([read64(dc, 0), read64(dc, 3)], [1, 0], "tc.V, fsc Bare");
    assert_eq!(cmds(cq, 2), vec![riscv::cmd_iodir_inval_ddt(0x18), riscv::cmd_iofence()]);

    // Re-attach to a page table: the valid context is torn down first.
    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    assert_eq!([read64(dc, 0), read64(dc, 3)], [1, 0x8000_0000_0008_0200]);
    // ... and the device's PSCID (1) is invalidated with the new context.
    assert_eq!(cmds(cq, 7)[2..], [
        riscv::cmd_iodir_inval_ddt(0x18), riscv::cmd_iofence(),
        riscv::cmd_iodir_inval_ddt(0x18), riscv::cmd_iotinval_vma_pscid(1), riscv::cmd_iofence(),
    ]);
    // Another device in the same leaf shares the leaf page.
    unit.attach(0x19, DomainMode::Bypass).unwrap();
    assert_eq!(mem.count(), 4);
    // Block clears the valid bit.
    unit.attach(0x19, DomainMode::Block).unwrap();
    assert_eq!(read64(leaf + 0x19 * 64, 0), 0);
}

#[test]
fn riscv_base_format_packs_contexts_at_32_bytes() {
    let mem = TestMem::leak();
    let mut unit = RiscvIommu::new(riscv_model(riscv::CAP_SV39), mem).unwrap();
    unit.attach(0x18, DomainMode::Bypass).unwrap();
    assert_eq!(read64(mem.page(3) + 0x18 * 32, 0), 1);
}

#[test]
fn riscv_refuses_a_device_id_beyond_the_directory_and_reports_a_rejected_command() {
    let mem = TestMem::leak();
    let mut unit = RiscvIommu::new(riscv_model(RV_CAP_EXT), mem).unwrap();
    assert_eq!(unit.attach(1 << 15, DomainMode::Bypass), Err(IommuError::DeviceOutOfRange));

    // A unit that flags every command illegal.
    let bad = FakeMmio::new(
        &[(riscv::REG_CAP, RV_CAP_EXT)],
        Box::new(|regs, off, val| match off {
            riscv::REG_CQCSR | riscv::REG_FQCSR if val & 1 != 0 => {
                regs.r.insert(off, val | (1 << 16));
            }
            riscv::REG_CQT => {
                regs.r.insert(riscv::REG_CQCSR, (1 << 16) | (1 << 10) | 1);
            }
            _ => {}
        }),
    );
    let mut unit = RiscvIommu::new(bad, TestMem::leak()).unwrap();
    assert!(matches!(unit.attach(0x18, DomainMode::Bypass), Err(IommuError::Hardware(_))));
}

/// The PSCID in the device context of `dev` (`ta` is dword 2, PSCID its
/// bits 31:12), extended format with every device in the first leaf.
fn rv_pscid(leaf: u64, dev: u32) -> u64 {
    (read64(leaf + dev as u64 * 64, 2) >> 12) & 0xf_ffff
}

#[test]
fn riscv_gives_each_translating_device_its_own_pscid_and_flushes_only_it() {
    let mem = TestMem::leak();
    let mmio = riscv_model(RV_CAP_EXT);
    let mut unit = RiscvIommu::new(mmio.clone(), mem).unwrap();
    let cq = mem.page(0);
    let queued = || mmio.get(riscv::REG_CQT) as usize;

    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    unit.attach(0x19, DomainMode::Translate { root_pa: 0x8030_0000 }).unwrap();
    let leaf = mem.page(3);
    // Two devices, two tables: two PSCIDs (1 and 2; 0 is never handed out).
    assert_eq!((rv_pscid(leaf, 0x18), rv_pscid(leaf, 0x19)), (1, 2));

    // A flush names the device's PSCID only: IOTINVAL.VMA (opcode 1) with
    // PSCV (bit 32) and PSCID 2 at 31:12 = 0x1_0000_2001, then IOFENCE.C.
    let n = queued();
    unit.flush(0x19).unwrap();
    assert_eq!(cmds(cq, queued())[n..], [[0x1_0000_2001, 0], [0x3002, 0]]);

    // Device 0x18 stops translating: its PSCID's translations go before the
    // PSCID is free, and the next translating device gets it.
    let n = queued();
    unit.attach(0x18, DomainMode::Bypass).unwrap();
    assert!(cmds(cq, queued())[n..].contains(&[0x1_0000_1001, 0]), "IOTINVAL.VMA of PSCID 1");
    assert_eq!(rv_pscid(leaf, 0x18), 0, "a bypassed device carries no PSCID");
    unit.attach(0x1a, DomainMode::Translate { root_pa: 0x8040_0000 }).unwrap();
    assert_eq!(rv_pscid(leaf, 0x1a), 1);

    // A device in bypass caches no translation: nothing to flush.
    let n = queued();
    unit.flush(0x18).unwrap();
    assert_eq!(queued(), n);
}

#[test]
fn riscv_poll_faults_decodes_the_queue_and_advances_the_head() {
    let mem = TestMem::leak();
    let mmio = riscv_model(RV_CAP_EXT);
    let mut unit = RiscvIommu::new(mmio.clone(), mem).unwrap();
    let fq = mem.page(1);
    assert!(faults(&mut unit).is_empty());
    // Record 0: S-stage write page fault (15) from device 0x18 at 0x8000_1000.
    write64(fq, 0, 15 | (0x18 << 40));
    write64(fq, 2, 0x8000_1000);
    mmio.set(riscv::REG_FQT, 1);
    assert_eq!(
        faults(&mut unit),
        vec![DmaFault { device_id: 0x18, fault_addr: 0x8000_1000, kind: FaultKind::UnmappedIova }]
    );
    assert_eq!(mmio.get(riscv::REG_FQH), 1);
    assert!(faults(&mut unit).is_empty(), "consumed");
    // The queue is memory the unit writes: clean once before it can, and
    // the CPU's copy of a record dropped before the record is read.
    assert!(mem.cleaned_all(fq, 4096), "the queue is clean in the cache before the unit writes it");
    assert!(mem.invalidated_in(fq, 32), "record 0 was invalidated before it was read");
}

// =====================================================================
// SMMUv3
// =====================================================================

const SMMU_IDR0: u64 = (smmuv3::IDR0_S1P as u64) | (2 << 2);
const SMMU_IDR1: u64 = (8 << 21) | (7 << 16) | 16; // CMDQS 8, EVTQS 7, SIDSIZE 16
const SMMU_IDR5: u64 = 5; // 48-bit output

fn smmu_model(idr0: u64, idr1: u64) -> FakeMmio {
    FakeMmio::new(
        &[(smmuv3::REG_IDR0, idr0), (smmuv3::REG_IDR1, idr1), (smmuv3::REG_IDR5, SMMU_IDR5)],
        Box::new(|regs, off, val| match off {
            smmuv3::REG_CR0 => {
                regs.r.insert(smmuv3::REG_CR0ACK, val);
            }
            // The unit consumes commands as they are queued.
            smmuv3::REG_CMDQ_PROD => {
                regs.r.insert(smmuv3::REG_CMDQ_CONS, val);
            }
            _ => {}
        }),
    )
}

#[test]
fn smmu_bring_up_order_and_values() {
    let mem = TestMem::leak();
    let mmio = smmu_model(SMMU_IDR0, SMMU_IDR1);
    let unit = Smmuv3::new(mmio.clone(), mem, 0xff).unwrap();
    let (strtab, cmdq, evtq) = (mem.page(0), mem.page(1), mem.page(2));
    // 256 streams: LOG2SIZE 8, linear format.
    assert_eq!(mmio.get(smmuv3::REG_STRTAB_BASE_CFG), 8);
    assert_eq!(mmio.get(smmuv3::REG_STRTAB_BASE), strtab);
    // Queues: base | log2size (command 8, event 7).
    assert_eq!(mmio.get(smmuv3::REG_CMDQ_BASE), cmdq | 8);
    assert_eq!(mmio.get(smmuv3::REG_EVTQ_BASE), evtq | 7);
    // CR0 walked 0 -> CMDQEN -> +EVTQEN -> +SMMUEN.
    assert_eq!(mmio.writes_to(smmuv3::REG_CR0), vec![0, 0x8, 0xc, 0xd]);
    // Boot invalidation: all configuration, all TLBs, then a sync.
    assert_eq!(
        crate::units::cmds(cmdq, 3),
        vec![smmuv3::cmd_cfgi_all(), smmuv3::cmd_tlbi_nsnh_all(), smmuv3::cmd_sync()]
    );
    assert_eq!(unit.pt_format().kind, PtKind::ArmLpae);
    assert_eq!(unit.pt_format().levels, 4);
}

#[test]
fn smmu_refuses_a_unit_it_cannot_drive() {
    let mem = TestMem::leak();
    assert!(matches!(Smmuv3::new(smmu_model(0, SMMU_IDR1), mem, 0xff).err(), Some(IommuError::Unsupported(_))));
    // Stream-id space of 4 bits cannot hold device 0xff.
    assert!(matches!(
        Smmuv3::new(smmu_model(SMMU_IDR0, (8 << 21) | (7 << 16) | 4), TestMem::leak(), 0xff).err(),
        Some(IommuError::Unsupported(_))
    ));
}

#[test]
fn smmu_attach_writes_the_cd_then_the_ste_and_syncs() {
    let mem = TestMem::leak();
    let mmio = smmu_model(SMMU_IDR0, SMMU_IDR1);
    let mut unit = Smmuv3::new(mmio.clone(), mem, 0xff).unwrap();
    let (strtab, cmdq, cd_page) = (mem.page(0), mem.page(1), mem.page(3));
    let ste = strtab + 0x18 * 64;

    unit.attach(0x18, DomainMode::Bypass).unwrap();
    assert_eq!(read64(ste, 0), 0x9);
    assert_eq!(read64(ste, 1), 1 << 44);
    assert_eq!(cmds(cmdq, 5)[3..], [smmuv3::cmd_cfgi_ste(0x18), smmuv3::cmd_sync()]);

    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    assert_eq!(read64(ste, 0), cd_page | 0xb, "translate, pointing at the first CD slot");
    assert_eq!(read64(cd_page, 0), 0x0001_E205_C000_3510);
    assert_eq!(read64(cd_page, 1), 0x8020_0000);
    // The live STE was invalidated first (CFGI+SYNC); then the new STE, the
    // stream's cached CDs and the ASID's translations go, and one SYNC.
    assert_eq!(cmds(cmdq, 11)[5..], [
        smmuv3::cmd_cfgi_ste(0x18), smmuv3::cmd_sync(),
        smmuv3::cmd_cfgi_ste(0x18), smmuv3::cmd_cfgi_cd_all(0x18), smmuv3::cmd_tlbi_nh_asid(1), smmuv3::cmd_sync(),
    ]);
    // A second translating device takes the next CD slot.
    unit.attach(0x19, DomainMode::Translate { root_pa: 0x8030_0000 }).unwrap();
    assert_eq!(read64(strtab + 0x19 * 64, 0), (cd_page + 64) | 0xb);

    assert_eq!(unit.attach(0x100, DomainMode::Bypass), Err(IommuError::DeviceOutOfRange));
    unit.flush(0x18).unwrap();
}

/// The ASID in the CD the STE of `dev` points at: STE dword 0 bits 51:6 are
/// the CD address, CD dword 0 bits 63:48 the ASID.
fn smmu_asid(strtab: u64, dev: u32) -> u64 {
    let cd = read64(strtab + dev as u64 * 64, 0) & 0x000f_ffff_ffff_ffc0;
    read64(cd, 0) >> 48
}

/// Commands `from..to` of the queue at `cmdq`, as the unit read them.
fn smmu_cmds(cmdq: u64, from: usize, to: usize) -> Vec<[u64; 2]> {
    cmds(cmdq, to)[from..].to_vec()
}

#[test]
fn smmu_gives_each_translating_device_its_own_asid_and_flushes_only_it() {
    let mem = TestMem::leak();
    let mmio = smmu_model(SMMU_IDR0, SMMU_IDR1);
    let mut unit = Smmuv3::new(mmio.clone(), mem, 0xff).unwrap();
    let (strtab, cmdq) = (mem.page(0), mem.page(1));
    // CMDQ_PROD counts the commands queued (the wrap bit stays clear below 256).
    let queued = || mmio.get(smmuv3::REG_CMDQ_PROD) as usize;

    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    unit.attach(0x19, DomainMode::Translate { root_pa: 0x8030_0000 }).unwrap();
    // Two devices, two tables: two ASIDs (1 and 2; 0 is never handed out).
    assert_eq!((smmu_asid(strtab, 0x18), smmu_asid(strtab, 0x19)), (1, 2));

    // A flush names the device's ASID only: TLBI_NH_ASID (0x11) with ASID 2
    // at 63:48, then CMD_SYNC (0x46, CS = SEV at 13:12 = 0x2046).
    let n = queued();
    unit.flush(0x19).unwrap();
    assert_eq!(smmu_cmds(cmdq, n, queued()), [[0x0002_0000_0000_0011, 0], [0x2046, 0]]);

    // Device 0x18 stops translating: its ASID's translations go before the
    // ASID is free, and the next translating device gets it, in the same CD.
    let cd0 = read64(strtab + 0x18 * 64, 0) & 0x000f_ffff_ffff_ffc0;
    let n = queued();
    unit.attach(0x18, DomainMode::Bypass).unwrap();
    assert!(smmu_cmds(cmdq, n, queued()).contains(&[0x0001_0000_0000_0011, 0]), "TLBI of ASID 1");
    unit.attach(0x20, DomainMode::Translate { root_pa: 0x8040_0000 }).unwrap();
    assert_eq!(smmu_asid(strtab, 0x20), 1);
    assert_eq!(read64(strtab + 0x20 * 64, 0) & 0x000f_ffff_ffff_ffc0, cd0);
    assert_eq!(read64(cd0, 1), 0x8040_0000, "the CD now holds the new device's table");

    // A device in bypass caches no translation: nothing to flush.
    let n = queued();
    unit.flush(0x18).unwrap();
    assert_eq!(queued(), n);
}

#[test]
fn smmu_poll_faults_walks_the_event_queue_with_wrap_bits() {
    let mem = TestMem::leak();
    let mmio = smmu_model(SMMU_IDR0, SMMU_IDR1);
    let mut unit = Smmuv3::new(mmio.clone(), mem, 0xff).unwrap();
    let evtq = mem.page(2);
    assert!(faults(&mut unit).is_empty());
    // Two records: F_TRANSLATION from stream 0x18 and C_BAD_STE from 0x19.
    write64(evtq, 0, 0x10 | (0x18 << 32));
    write64(evtq, 2, 0x8000_1000);
    write64(evtq, 4, 0x04 | (0x19 << 32));
    mmio.set(smmuv3::REG_EVTQ_PROD, 2);
    assert_eq!(
        faults(&mut unit),
        vec![
            DmaFault { device_id: 0x18, fault_addr: 0x8000_1000, kind: FaultKind::UnmappedIova },
            DmaFault { device_id: 0x19, fault_addr: 0, kind: FaultKind::BadDeviceEntry },
        ]
    );
    assert_eq!(mmio.get(smmuv3::REG_EVTQ_CONS), 2);
    assert!(mem.cleaned_all(evtq, 4096), "the queue is clean in the cache before the unit writes it");
    assert!(mem.invalidated_in(evtq, 64), "both records were invalidated before they were read");
    // An overflow flag in PROD is echoed back to CONS to acknowledge it.
    mmio.set(smmuv3::REG_EVTQ_PROD, 2 | (1 << 31));
    faults(&mut unit);
    assert_eq!(mmio.get(smmuv3::REG_EVTQ_CONS), 2 | (1 << 31));
}

// =====================================================================
// VT-d
// =====================================================================

const VTD_CAP: u64 = (0b100 << 8) | (0x20 << 24) | (1 << 40) | 6; // 4-level, FRO 0x20, 2 FRCD, ND 6
const VTD_ECAP: u64 = vtd::ECAP_PT | (0x100 << 8); // pass-through, IRO 0x100

fn vtd_model(cap: u64, ecap: u64) -> FakeMmio {
    let iotlb = vtd::iotlb_reg(ecap);
    FakeMmio::new(
        &[(vtd::REG_CAP, cap), (vtd::REG_ECAP, ecap)],
        Box::new(move |regs, off, val| {
            if off == vtd::REG_GCMD {
                // Status bits sit where the command bits do.
                regs.r.insert(vtd::REG_GSTS, val);
            } else if off == vtd::REG_CCMD {
                regs.r.insert(off, val & !vtd::CCMD_ICC);
            } else if off == iotlb {
                regs.r.insert(off, val & !vtd::IOTLB_IVT);
            }
        }),
    )
}

#[test]
fn vtd_bring_up_sets_the_root_then_invalidates_then_enables() {
    let mem = TestMem::leak();
    let mmio = vtd_model(VTD_CAP, VTD_ECAP);
    let unit = Vtd::new(mmio.clone(), mem).unwrap();
    assert_eq!(mmio.get(vtd::REG_RTADDR), mem.page(0));
    assert_eq!(mmio.get(vtd::REG_FECTL), vtd::FECTL_IM as u64, "fault interrupt masked");
    // SRTP, then (after the invalidations) TE.
    assert_eq!(mmio.writes_to(vtd::REG_GCMD), vec![vtd::GCMD_SRTP as u64, vtd::GCMD_TE as u64]);
    assert_eq!(mmio.writes_to(vtd::REG_CCMD), vec![vtd::CCMD_ICC | vtd::CCMD_GLOBAL]);
    assert_eq!(
        mmio.writes_to(0x1008),
        vec![vtd::IOTLB_IVT | vtd::IOTLB_GLOBAL | vtd::IOTLB_DRAIN_R | vtd::IOTLB_DRAIN_W]
    );
    assert_eq!(unit.pt_format().kind, PtKind::Vtd);
    assert_eq!(unit.pt_format().levels, 4, "SAGAW 48-bit only");
}

#[test]
fn vtd_prefers_three_levels_and_refuses_what_it_cannot_drive() {
    let mem = TestMem::leak();
    let both = (0b110 << 8) | (0x20 << 24) | 6;
    assert_eq!(Vtd::new(vtd_model(both, VTD_ECAP), mem).unwrap().pt_format().levels, 3);
    assert!(matches!(Vtd::new(vtd_model(VTD_CAP, 0x100 << 8), TestMem::leak()).err(), Some(IommuError::Unsupported(_))));
    assert!(matches!(Vtd::new(vtd_model(6, VTD_ECAP), TestMem::leak()).err(), Some(IommuError::Unsupported(_))));
}

#[test]
fn vtd_attach_builds_root_and_context_entries() {
    let mem = TestMem::leak();
    let mmio = vtd_model(VTD_CAP, VTD_ECAP);
    let mut unit = Vtd::new(mmio.clone(), mem).unwrap();
    let root = mem.page(0);

    // Device 00:03.0 = 0x18, bus 0.
    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    let ctx = mem.page(1);
    assert_eq!([read64(root, 0), read64(root, 1)], [ctx | 1, 0]);
    let ce = ctx + 0x18 * 16;
    // 4-level (AW 2), first translating domain id 2.
    assert_eq!([read64(ce, 0), read64(ce, 1)], [0x8020_0001, 0x202]);

    // Device on bus 1 gets its own context table.
    unit.attach(0x0108, DomainMode::Bypass).unwrap();
    let ctx1 = mem.page(2);
    assert_eq!(read64(root, 2), ctx1 | 1);
    assert_eq!([read64(ctx1 + 8 * 16, 0), read64(ctx1 + 8 * 16, 1)], [0x9, 0x102]);

    // A second translating device takes domain id 3.
    unit.attach(0x20, DomainMode::Translate { root_pa: 0x8030_0000 }).unwrap();
    assert_eq!(read64(ctx + 0x20 * 16, 1), 0x302);

    // Every attach invalidated the context cache and the IOTLB.
    assert_eq!(mmio.writes_to(vtd::REG_CCMD).len(), 4);
    unit.flush(0x18).unwrap();
    assert_eq!(mmio.writes_to(vtd::REG_CCMD).len(), 5);
}

/// The domain id the context entry of `dev` carries.
fn vtd_did(ctx: u64, dev: u32) -> u64 {
    (read64(ctx + (dev as u64 & 0xff) * 16, 1) >> 8) & 0xffff
}

#[test]
fn vtd_keeps_one_domain_id_per_device_and_frees_it_when_the_device_stops_translating() {
    let mem = TestMem::leak();
    let tr = |pa| DomainMode::Translate { root_pa: pa };
    // ND = 0: 16 domain ids, 2 of them the crate's own: 14 translating devices.
    let mut unit = Vtd::new(vtd_model(VTD_CAP & !7, VTD_ECAP), mem).unwrap();
    let ctx = {
        unit.attach(0x10, tr(0x8000_0000)).unwrap();
        mem.page(1)
    };
    assert_eq!(vtd_did(ctx, 0x10), 2);
    // The same device again, many times over: the same id, no exhaustion.
    for _ in 0..40 {
        unit.attach(0x10, tr(0x8010_0000)).unwrap();
    }
    assert_eq!(vtd_did(ctx, 0x10), 2, "re-attach reuses the device's id");
    // Detach and attach again: still the same id (it was freed, and is the lowest).
    unit.attach(0x10, DomainMode::Block).unwrap();
    unit.attach(0x10, tr(0x8010_0000)).unwrap();
    assert_eq!(vtd_did(ctx, 0x10), 2);
    // Fill the remaining 13 ids; the 15th device finds none.
    for dev in 0x11..0x1e {
        unit.attach(dev, tr(0x8020_0000)).unwrap();
    }
    assert_eq!(vtd_did(ctx, 0x1d), 15, "the last of ids 2..=15");
    assert_eq!(unit.attach(0x1e, tr(0x8030_0000)), Err(IommuError::Unsupported("vt-d: out of domain ids")));
    // A device that stops translating gives its id to the next one.
    unit.attach(0x12, DomainMode::Bypass).unwrap();
    unit.attach(0x1e, tr(0x8030_0000)).unwrap();
    assert_eq!(vtd_did(ctx, 0x1e), 4, "the id device 0x12 gave up");
    assert_eq!(vtd_did(ctx, 0x12), 1, "pass-through uses the bypass id");
}

#[test]
fn vtd_poll_faults_reads_and_frees_the_recording_registers() {
    let mem = TestMem::leak();
    let mmio = vtd_model(VTD_CAP, VTD_ECAP);
    let mut unit = Vtd::new(mmio.clone(), mem).unwrap();
    assert!(faults(&mut unit).is_empty());
    // Register 1 (at FRO*16 + 16 = 0x210) holds a fault: write to 0x8000_1000
    // from 00:03.0, reason 5 (write permission).
    mmio.set(0x210, 0x8000_1000);
    mmio.set(0x218, 0x8000_0005_0000_0018);
    assert_eq!(
        faults(&mut unit),
        vec![DmaFault { device_id: 0x18, fault_addr: 0x8000_1000, kind: FaultKind::UnmappedIova }]
    );
    assert_eq!(mmio.writes_to(0x218), vec![vtd::FRCD_F], "F written back as 1 to free it");
}

// =====================================================================
// AMD-Vi
// =====================================================================

fn amd_model() -> FakeMmio {
    amd_model_with_efr(amdvi::EFR_IASUP)
}

/// A unit whose Extended Feature Register reads `efr`; it executes
/// commands and stores the completion-wait data, and (like the real thing)
/// stops on an opcode it does not implement.
fn amd_model_with_efr(efr: u64) -> FakeMmio {
    FakeMmio::new(
        &[(amdvi::REG_EFR, efr)],
        Box::new(|regs, off, val| match off {
            amdvi::REG_CONTROL => {
                let mut s = 0;
                if val & amdvi::CTRL_CMD_BUF_EN != 0 {
                    s |= amdvi::STATUS_CMD_BUF_RUN;
                }
                if val & amdvi::CTRL_EVT_LOG_EN != 0 {
                    s |= amdvi::STATUS_EVT_LOG_RUN;
                }
                regs.r.insert(amdvi::REG_STATUS, s);
            }
            // The unit executes the commands between head and tail; a
            // COMPLETION_WAIT stores its data at its address.
            amdvi::REG_CMD_TAIL => {
                let buf = regs.r[&amdvi::REG_CMD_BUF] & 0x000f_ffff_ffff_f000;
                let mut head = regs.r.get(&amdvi::REG_CMD_HEAD).copied().unwrap_or(0);
                while head != val {
                    let q0 = read64(buf + head, 0);
                    let q1 = read64(buf + head, 1);
                    if (q0 >> 60) & 0xf == 1 {
                        let addr = (q0 & 0xffff_fff8) | (((q0 >> 32) & 0xf_ffff) << 32);
                        write64(addr, 0, q1);
                    }
                    head = (head + 16) % 4096;
                }
                regs.r.insert(amdvi::REG_CMD_HEAD, head);
            }
            _ => {}
        }),
    )
}

#[test]
fn amd_bring_up_programs_the_tables_then_enables() {
    let mem = TestMem::leak();
    let mmio = amd_model();
    let unit = AmdVi::new(mmio.clone(), mem, 0xff).unwrap();
    let (devtab, cmd, evt) = (mem.page(0), mem.page(1), mem.page(2));
    // 256 entries of 32 bytes = 8 KiB = 2 pages: Size field 1.
    assert_eq!(mmio.get(amdvi::REG_DEV_TABLE), devtab | 1);
    // Length code 8 (256 entries) at bits 59:56.
    assert_eq!(mmio.get(amdvi::REG_CMD_BUF), cmd | (8 << 56));
    assert_eq!(mmio.get(amdvi::REG_EVT_LOG), evt | (8 << 56));
    // Buffers on first, translation on last.
    assert_eq!(mmio.writes_to(amdvi::REG_CONTROL), vec![0x1004, 0x1005]);
    // Boot invalidation is INVALIDATE_IOMMU_ALL, then a completion wait.
    assert_eq!(cmds(cmd, 2)[0], amdvi::cmd_inv_all());
    assert_eq!(unit.pt_format().kind, PtKind::AmdVi);
    // The event log and the semaphore are written by the unit: clean first.
    assert!(mem.cleaned_all(evt, 4096));
    assert!(mem.cleaned_all(mem.page(3), 4096));
}

#[test]
fn amd_without_ia_sup_never_issues_invalidate_all() {
    // INVALIDATE_IOMMU_ALL exists only with EFR.IASup: elsewhere it is an
    // ILLEGAL_COMMAND. The bring-up invalidates entry by entry instead.
    let mem = TestMem::leak();
    let mmio = amd_model_with_efr(0);
    let unit = AmdVi::new(mmio.clone(), mem, 0x3f).unwrap();
    let c = cmds(mem.page(1), 256);
    assert!(c.iter().all(|cmd| (cmd[0] >> 60) & 0xf != 8), "no INVALIDATE_IOMMU_ALL in the buffer");
    // 64 device entries, a wait, then the domain ids 1..=17 and a wait.
    assert_eq!(c[0], amdvi::cmd_inv_dev_entry(0));
    assert_eq!(c[63], amdvi::cmd_inv_dev_entry(0x3f));
    assert_eq!((c[64][0] >> 60) & 0xf, 1, "a completion wait");
    assert_eq!(c[65], amdvi::cmd_inv_pages_all(1));
    assert_eq!(c[81], amdvi::cmd_inv_pages_all(17));
    assert_eq!((c[82][0] >> 60) & 0xf, 1);
    assert_eq!(mmio.writes_to(amdvi::REG_CONTROL).last(), Some(&0x1005), "and translation is on");
    assert_eq!(unit.pt_format().kind, PtKind::AmdVi);
    // With the bit set it is the single command.
    let mem = TestMem::leak();
    AmdVi::new(amd_model_with_efr(amdvi::EFR_IASUP), mem, 0x3f).unwrap();
    assert_eq!(cmds(mem.page(1), 2)[0], amdvi::cmd_inv_all());
}

#[test]
fn amd_keeps_one_domain_id_per_device_and_frees_it_when_the_device_stops_translating() {
    let mem = TestMem::leak();
    let tr = |pa| DomainMode::Translate { root_pa: pa };
    let mut unit = AmdVi::new(amd_model(), mem, 0xff).unwrap();
    let devtab = mem.page(0);
    let did = |dev: u64| read64(devtab + dev * 32, 1);
    unit.attach(0x10, tr(0x8000_0000)).unwrap();
    assert_eq!(did(0x10), 2);
    for _ in 0..40 {
        unit.attach(0x10, tr(0x8010_0000)).unwrap();
    }
    assert_eq!(did(0x10), 2, "re-attach reuses the device's id");
    // The 16 ids 2..=17; the 17th device finds none.
    for dev in 0x11..0x20 {
        unit.attach(dev, tr(0x8020_0000)).unwrap();
    }
    assert_eq!(did(0x1f), 17);
    assert_eq!(unit.attach(0x30, tr(0x8030_0000)), Err(IommuError::Unsupported("amd-vi: out of domains")));
    // Stopping drops the domain's cached translations, then frees the id.
    let inv4 = amdvi::cmd_inv_pages_all(4);
    assert!(!cmds(mem.page(1), 256).contains(&inv4));
    unit.attach(0x12, DomainMode::Block).unwrap();
    assert!(cmds(mem.page(1), 256).contains(&inv4), "its cached translations were dropped");
    unit.attach(0x30, tr(0x8030_0000)).unwrap();
    assert_eq!(did(0x30), 4, "the id device 0x12 gave up");
}

#[test]
fn amd_attach_writes_the_device_table_entry_and_invalidates() {
    let mem = TestMem::leak();
    let mmio = amd_model();
    let mut unit = AmdVi::new(mmio.clone(), mem, 0xff).unwrap();
    let (devtab, cmd) = (mem.page(0), mem.page(1));
    let dte = devtab + 0x18 * 32;

    unit.attach(0x18, DomainMode::Bypass).unwrap();
    assert_eq!([read64(dte, 0), read64(dte, 1), read64(dte, 2)], [0x6000_0000_0000_0003, 1, 1 << 60]);
    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    assert_eq!([read64(dte, 0), read64(dte, 1)], [0x6000_0000_8020_0803, 2]);
    // The command stream: INV_ALL, WAIT, INV_DEV, WAIT, INV_DEV, WAIT.
    let c = cmds(cmd, 6);
    assert_eq!(c[2], amdvi::cmd_inv_dev_entry(0x18));
    assert_eq!(c[4], amdvi::cmd_inv_dev_entry(0x18));
    assert_eq!(c[5], amdvi::cmd_completion_wait(mem.page(3), 3), "third wait, sequence 3");

    // Flushing a translating device invalidates its domain; a bypass one has none.
    unit.flush(0x18).unwrap();
    assert_eq!(cmds(cmd, 8)[6], amdvi::cmd_inv_pages_all(2));
    let before = mmio.writes_to(amdvi::REG_CMD_TAIL).len();
    unit.flush(0x40).unwrap();
    assert_eq!(mmio.writes_to(amdvi::REG_CMD_TAIL).len(), before);

    assert_eq!(unit.attach(0x100, DomainMode::Bypass), Err(IommuError::DeviceOutOfRange));
}

#[test]
fn amd_blocks_every_device_it_was_not_told_about_and_never_passes_through_zero() {
    // A blocking DTE's qword 0: V (bit 0) | TV (bit 1), Mode 0, IR/IW clear.
    const BLOCK: u64 = 0x3;
    let mem = TestMem::leak();
    let mut unit = AmdVi::new(amd_model(), mem, 0x3f).unwrap();
    let devtab = mem.page(0);
    // 64 entries need one page, which holds 128: all of them block, those
    // past the highest requester id included, and the unit sees them.
    assert!((0..128).all(|dev| read64(devtab + dev * 32, 0) == BLOCK), "a fresh table blocks");
    assert!(mem.cleaned_all(devtab, 4096));

    // Rewriting an entry passes through blocking, never through zero (V clear
    // = untranslated DMA), whatever the unit reads mid-update.
    let dte = devtab + 0x18 * 32;
    unit.attach(0x18, DomainMode::Bypass).unwrap();
    unit.attach(0x18, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    unit.attach(0x18, DomainMode::Block).unwrap();
    let seen = mem.cleaned_values(dte);
    assert!(seen.contains(&BLOCK), "the update went through a blocking entry");
    assert!(seen.iter().all(|&q0| q0 & 1 == 1), "never an invalid (pass-through) entry: {seen:x?}");
    assert_eq!(read64(dte, 0), BLOCK);
}

#[test]
fn amd_poll_faults_reads_the_event_log() {
    let mem = TestMem::leak();
    let mmio = amd_model();
    let mut unit = AmdVi::new(mmio.clone(), mem, 0xff).unwrap();
    let evt = mem.page(2);
    assert!(faults(&mut unit).is_empty());
    assert!(mem.invalidated_in(mem.page(3), 8), "the completion semaphore is invalidated before it is read");
    write64(evt, 0, 0x2000_0000_0000_0018);
    write64(evt, 1, 0x8000_1000);
    mmio.set(amdvi::REG_EVT_TAIL, 16);
    assert_eq!(
        faults(&mut unit),
        vec![DmaFault { device_id: 0x18, fault_addr: 0x8000_1000, kind: FaultKind::UnmappedIova }]
    );
    assert_eq!(mmio.get(amdvi::REG_EVT_HEAD), 16);
    assert!(mem.invalidated_in(evt, 16), "the record was invalidated before it was read");
}
