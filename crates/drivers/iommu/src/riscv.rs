// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V IOMMU: Device Context (base format) encode/decode, and fault
//! record decode. Layouts are best-effort — see the crate-level doc.

use crate::{DmaFault, DomainMode, FaultKind};

// -----------------------------------------------------------------------
// Device Context (DC) — base format, second-stage bypassed, first-stage
// either Bare (bypass) or Sv39 (single-stage, this crate's only mode)
// -----------------------------------------------------------------------

/// `tc` (translation control) bit positions this crate sets. Every other
/// bit (ATS, PRI, PDT validity, …) stays 0 — off — matching "no ATS, no
/// PASID" in the module scope.
const TC_V: u64 = 1 << 0;

/// `iohgatp`/`fsc`.MODE field values this crate uses. `BARE` means "no
/// translation at this stage"; `SV39` selects the standard 3-level RISC-V
/// page-table walk for the first stage.
const MODE_BARE: u64 = 0;
const MODE_SV39: u64 = 8;

const MODE_SHIFT: u32 = 60;
const PPN_MASK: u64 = (1u64 << 44) - 1;

/// One device's translation state, base-format DC (32 bytes: `tc`,
/// `iohgatp`, `ta`, `fsc`). `iohgatp` (second stage / G-stage) is always
/// programmed Bare by this crate — the scope is one stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceContext {
    pub tc: u64,
    pub iohgatp: u64,
    pub ta: u64,
    pub fsc: u64,
}

impl DeviceContext {
    /// Build the DC for `mode`. `device_id` only affects `ta` (PSCID
    /// field would go here in a fuller implementation; this crate leaves
    /// it 0 — no PASID means no per-process ASID to carry).
    pub fn encode(mode: DomainMode) -> Self {
        let iohgatp = MODE_BARE << MODE_SHIFT; // second stage always bypassed
        let fsc = match mode {
            DomainMode::Bypass => MODE_BARE << MODE_SHIFT,
            DomainMode::SingleStage { root_ppn } => (MODE_SV39 << MODE_SHIFT) | (root_ppn & PPN_MASK),
        };
        DeviceContext { tc: TC_V, iohgatp, ta: 0, fsc }
    }

    pub fn is_valid(&self) -> bool {
        self.tc & TC_V != 0
    }

    /// Recover the [`DomainMode`] this context encodes. `None` if `fsc`
    /// carries a MODE this crate doesn't emit (a context this crate
    /// didn't build, or spec drift) — a decoder that guessed here would
    /// misreport a fault's context instead of saying "unrecognised".
    pub fn decode_mode(&self) -> Option<DomainMode> {
        let mode = self.fsc >> MODE_SHIFT;
        if mode == MODE_BARE {
            Some(DomainMode::Bypass)
        } else if mode == MODE_SV39 {
            Some(DomainMode::SingleStage { root_ppn: self.fsc & PPN_MASK })
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------
// Fault queue record
// -----------------------------------------------------------------------

/// Cause codes this crate distinguishes. Values are the ones the RISC-V
/// IOMMU spec's fault-cause table assigns (from training knowledge, NOT
/// verified this session — crate-level doc). Only the codes gate-3 and
/// gate-4 care about are named; everything else falls through to
/// [`FaultKind::Other`] in [`classify`].
pub mod cause {
    pub const LOAD_PAGE_FAULT: u32 = 13;
    pub const STORE_AMO_PAGE_FAULT: u32 = 15;
    pub const DDT_ENTRY_LOAD_ACCESS_FAULT: u32 = 257;
    pub const DDT_ENTRY_NOT_VALID: u32 = 258;
    pub const DDT_ENTRY_MISCONFIGURED: u32 = 259;
    pub const TRANSACTION_TYPE_DISALLOWED: u32 = 260;
}

/// Fault-queue record. Base-format layout (32 bytes): `cause` in the low
/// 12 bits of word 0, `pid`/`did` packed per spec into the remaining
/// words, `iotval`/`iotval2` as two 64-bit trailing words. This crate
/// only decodes the three fields the DMA-fault gate needs: cause, the
/// device id that faulted, and the faulting address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultRecord {
    pub cause: u32,
    pub device_id: u32,
    pub iotval: u64,
}

impl FaultRecord {
    /// Encode a 32-byte fault-queue entry the way this crate's own
    /// `decode` expects it (round-trip pair — see the crate doc for why
    /// that is what's actually verified here, not a real spec match).
    pub fn encode(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&self.cause.to_le_bytes());
        buf[4..8].copy_from_slice(&self.device_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.iotval.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; 32]) -> Self {
        let cause = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let device_id = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let iotval = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        FaultRecord { cause, device_id, iotval }
    }
}

/// Classify a decoded fault record into the flavour-independent
/// [`DmaFault`] `crates/drivers/iommu`'s caller records.
pub fn classify(record: &FaultRecord) -> DmaFault {
    let kind = match record.cause {
        cause::LOAD_PAGE_FAULT | cause::STORE_AMO_PAGE_FAULT => FaultKind::UnmappedIova,
        cause::DDT_ENTRY_LOAD_ACCESS_FAULT | cause::DDT_ENTRY_NOT_VALID | cause::DDT_ENTRY_MISCONFIGURED => {
            FaultKind::BadDeviceEntry
        }
        other => FaultKind::Other(other),
    };
    DmaFault { device_id: record.device_id, fault_addr: record.iotval, kind }
}
