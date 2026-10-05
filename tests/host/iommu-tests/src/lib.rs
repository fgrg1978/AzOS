// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![cfg(test)]

use azos_iommu::riscv::{cause, classify as riscv_classify, DeviceContext, FaultRecord};
use azos_iommu::smmuv3::{classify as smmuv3_classify, event, EventRecord, Ste, SteConfig};
use azos_iommu::{DomainMode, FaultKind};

// -----------------------------------------------------------------------
// RISC-V IOMMU: Device Context round trip
// -----------------------------------------------------------------------

#[test]
fn riscv_dc_bypass_round_trips_and_is_valid() {
    let dc = DeviceContext::encode(DomainMode::Bypass);
    assert!(dc.is_valid());
    assert_eq!(dc.decode_mode(), Some(DomainMode::Bypass));
}

#[test]
fn riscv_dc_single_stage_round_trips_root_ppn() {
    let dc = DeviceContext::encode(DomainMode::SingleStage { root_ppn: 0x1234 });
    assert!(dc.is_valid());
    assert_eq!(dc.decode_mode(), Some(DomainMode::SingleStage { root_ppn: 0x1234 }));
}

#[test]
fn riscv_dc_single_stage_masks_root_ppn_to_44_bits() {
    // A PPN with bits set above the 44-bit field must not corrupt the
    // MODE field it's packed next to.
    let huge_ppn = 0xffff_ffff_ffff_ffffu64;
    let dc = DeviceContext::encode(DomainMode::SingleStage { root_ppn: huge_ppn });
    match dc.decode_mode() {
        Some(DomainMode::SingleStage { root_ppn }) => assert_eq!(root_ppn, huge_ppn & ((1u64 << 44) - 1)),
        other => panic!("expected SingleStage, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// RISC-V IOMMU: fault record — this is gate 3's decode path
// -----------------------------------------------------------------------

#[test]
fn riscv_fault_record_round_trips() {
    let rec = FaultRecord { cause: cause::LOAD_PAGE_FAULT, device_id: 7, iotval: 0xdead_beef_1000 };
    let buf = rec.encode();
    let decoded = FaultRecord::decode(&buf);
    assert_eq!(decoded, rec);
}

#[test]
fn unmapped_iova_load_fault_classifies_as_unmapped_iova() {
    let rec = FaultRecord { cause: cause::LOAD_PAGE_FAULT, device_id: 3, iotval: 0x9000_0000 };
    let fault = riscv_classify(&rec);
    assert_eq!(fault.kind, FaultKind::UnmappedIova);
    assert_eq!(fault.device_id, 3);
    assert_eq!(fault.fault_addr, 0x9000_0000);
}

#[test]
fn unmapped_iova_store_fault_also_classifies_as_unmapped_iova() {
    let rec = FaultRecord { cause: cause::STORE_AMO_PAGE_FAULT, device_id: 3, iotval: 0x9000_1000 };
    assert_eq!(riscv_classify(&rec).kind, FaultKind::UnmappedIova);
}

#[test]
fn ddt_entry_not_valid_classifies_as_bad_device_entry_not_unmapped_iova() {
    let rec = FaultRecord { cause: cause::DDT_ENTRY_NOT_VALID, device_id: 9, iotval: 0 };
    assert_eq!(riscv_classify(&rec).kind, FaultKind::BadDeviceEntry);
}

#[test]
fn unrecognised_cause_is_recorded_not_dropped() {
    let rec = FaultRecord { cause: 0xdead, device_id: 1, iotval: 0 };
    assert_eq!(riscv_classify(&rec).kind, FaultKind::Other(0xdead));
}

// -----------------------------------------------------------------------
// SMMUv3: STE round trip
// -----------------------------------------------------------------------

#[test]
fn smmuv3_ste_bypass_round_trips() {
    let ste = Ste::encode(DomainMode::Bypass);
    let raw = ste.to_raw();
    let back = Ste::from_raw(raw).expect("valid STE must decode");
    assert_eq!(back, ste);
    assert_eq!(back.decode_mode(), Some(DomainMode::Bypass));
}

#[test]
fn smmuv3_ste_stage1_round_trips_cd_ptr() {
    let ste = Ste::encode(DomainMode::SingleStage { root_ppn: 0x5_5555 });
    let back = Ste::from_raw(ste.to_raw()).unwrap();
    assert_eq!(back.decode_mode(), Some(DomainMode::SingleStage { root_ppn: 0x5_5555 }));
}

#[test]
fn smmuv3_ste_abort_config_has_no_domain_mode() {
    let ste = Ste { valid: true, config: SteConfig::Abort, cd_ptr: 0 };
    assert_eq!(ste.decode_mode(), None, "Abort must not be reported as any usable domain mode");
}

#[test]
fn smmuv3_ste_from_raw_rejects_an_unrecognised_config_value() {
    // Config field 0b11 is not one of this crate's three states —
    // from_raw must say so, not silently pick one.
    let raw = 0b11 << 1;
    assert_eq!(Ste::from_raw(raw), None);
}

// -----------------------------------------------------------------------
// SMMUv3: event record classification — the aarch64 half of gate 3
// -----------------------------------------------------------------------

#[test]
fn smmuv3_translation_fault_classifies_as_unmapped_iova() {
    let rec = EventRecord { event_type: event::F_TRANSLATION, stream_id: 0x42, input_addr: 0x8000_0000 };
    let fault = smmuv3_classify(&rec);
    assert_eq!(fault.kind, FaultKind::UnmappedIova);
    assert_eq!(fault.device_id, 0x42);
    assert_eq!(fault.fault_addr, 0x8000_0000);
}

#[test]
fn smmuv3_event_record_round_trips() {
    let rec = EventRecord { event_type: event::C_BAD_STE, stream_id: 5, input_addr: 0x1234 };
    let decoded = EventRecord::decode(&rec.encode());
    assert_eq!(decoded, rec);
}
