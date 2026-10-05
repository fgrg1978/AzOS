// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Arm SMMUv3: a reduced Stream Table Entry (STE) + Context Descriptor
//! (CD) encode/decode, and event-record decode. Layouts are best-effort
//! — see the crate-level doc. Scope matches `riscv.rs`: one stage,
//! per-device Bypass or SingleStage, no PASID/ATS.

use crate::{DmaFault, DomainMode, FaultKind};

// -----------------------------------------------------------------------
// Stream Table Entry (reduced) — this crate only ever needs "abort",
// "bypass" or "translate stage 1", so `Config` is a 2-bit enum here
// rather than the full 3-bit field the real STE reserves for stage-2 and
// nested combinations this crate does not implement.
// -----------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SteConfig {
    Abort,
    Bypass,
    Stage1,
}

impl SteConfig {
    fn to_bits(self) -> u64 {
        match self {
            SteConfig::Abort => 0,
            SteConfig::Bypass => 1,
            SteConfig::Stage1 => 2,
        }
    }

    fn from_bits(bits: u64) -> Option<Self> {
        match bits {
            0 => Some(SteConfig::Abort),
            1 => Some(SteConfig::Bypass),
            2 => Some(SteConfig::Stage1),
            _ => None,
        }
    }
}

/// Reduced STE: valid bit, config, and (for `Stage1`) the physical
/// address of the Context Descriptor this stream uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ste {
    pub valid: bool,
    pub config: SteConfig,
    pub cd_ptr: u64,
}

const STE_VALID: u64 = 1 << 0;
const STE_CONFIG_SHIFT: u32 = 1;
const STE_CONFIG_MASK: u64 = 0x3;
const STE_CD_PTR_SHIFT: u32 = 8;
const STE_CD_PTR_MASK: u64 = (1u64 << 44) - 1;

impl Ste {
    pub fn encode(mode: DomainMode) -> Self {
        match mode {
            DomainMode::Bypass => Ste { valid: true, config: SteConfig::Bypass, cd_ptr: 0 },
            DomainMode::SingleStage { root_ppn } => {
                Ste { valid: true, config: SteConfig::Stage1, cd_ptr: root_ppn }
            }
        }
    }

    /// Pack into one 64-bit word (the real STE is 64 bytes across 8
    /// words; this crate's reduced model only needs the fields above, so
    /// they fit in one word — a fuller implementation would split this
    /// across the real word layout).
    pub fn to_raw(&self) -> u64 {
        let mut raw = 0u64;
        if self.valid {
            raw |= STE_VALID;
        }
        raw |= self.config.to_bits() << STE_CONFIG_SHIFT;
        raw |= (self.cd_ptr & STE_CD_PTR_MASK) << STE_CD_PTR_SHIFT;
        raw
    }

    pub fn from_raw(raw: u64) -> Option<Self> {
        let valid = raw & STE_VALID != 0;
        let config = SteConfig::from_bits((raw >> STE_CONFIG_SHIFT) & STE_CONFIG_MASK)?;
        let cd_ptr = (raw >> STE_CD_PTR_SHIFT) & STE_CD_PTR_MASK;
        Some(Ste { valid, config, cd_ptr })
    }

    pub fn decode_mode(&self) -> Option<DomainMode> {
        match self.config {
            SteConfig::Bypass => Some(DomainMode::Bypass),
            SteConfig::Stage1 => Some(DomainMode::SingleStage { root_ppn: self.cd_ptr }),
            SteConfig::Abort => None,
        }
    }
}

// -----------------------------------------------------------------------
// Event record (reduced)
// -----------------------------------------------------------------------

/// Event IDs this crate distinguishes (from training knowledge of the
/// SMMUv3 event-record type field, NOT verified this session).
pub mod event {
    /// Stage-1 translation fault — no valid leaf mapping for the IOVA.
    pub const F_TRANSLATION: u8 = 0x10;
    /// Stream table entry fetch/format fault — a configuration problem,
    /// not a rogue access.
    pub const F_STE_FETCH: u8 = 0x11;
    pub const C_BAD_STE: u8 = 0x12;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub event_type: u8,
    pub stream_id: u32,
    pub input_addr: u64,
}

impl EventRecord {
    /// Encode/decode round trip only (see crate doc) — 16 bytes, not the
    /// real 32-byte SMMUv3 event-queue entry, since this crate models
    /// only the three fields above.
    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = self.event_type;
        buf[4..8].copy_from_slice(&self.stream_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.input_addr.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; 16]) -> Self {
        EventRecord {
            event_type: buf[0],
            stream_id: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            input_addr: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        }
    }
}

pub fn classify(record: &EventRecord) -> DmaFault {
    let kind = match record.event_type {
        event::F_TRANSLATION => FaultKind::UnmappedIova,
        event::F_STE_FETCH | event::C_BAD_STE => FaultKind::BadDeviceEntry,
        other => FaultKind::Other(other as u32),
    };
    DmaFault { device_id: record.stream_id, fault_addr: record.input_addr, kind }
}
