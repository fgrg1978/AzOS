// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! USB MSC Bulk-Only Transport (BBB) wire-format types.
//!
//! Two 13/15-byte wrappers frame every transfer:
//!
//!   Host → Device: CBW (Command Block Wrapper, 31 bytes)
//!   Device → Host: data (optional, length encoded in CBW)
//!   Device → Host: CSW (Command Status Wrapper, 13 bytes)
//!
//! The CBW's `bCBWCBLength` field bounds the actual SCSI CDB to
//! 1–16 bytes; the rest of the 16-byte block is reserved.

/// CBW signature: ASCII "USBC", little-endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// CSW signature: ASCII "USBS", little-endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;

/// bCBWFlags bit 7 — 0 = data-OUT (host→device), 1 = data-IN.
pub const CBW_DIR_OUT: u8 = 0x00;
pub const CBW_DIR_IN:  u8 = 0x80;

/// bCSWStatus values (USB MSC BBB §5.2 Table 5.3).
pub const CSW_STATUS_OK:          u8 = 0x00;
pub const CSW_STATUS_FAIL:        u8 = 0x01;
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

/// Maximum CDB length per BBB spec.
pub const CBW_CDB_MAX_LEN: usize = 16;
/// Total wire length of a CBW.
pub const CBW_TOTAL_LEN:   usize = 31;
/// Total wire length of a CSW.
pub const CSW_TOTAL_LEN:   usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cbw {
    pub tag:               u32,
    pub data_transfer_len: u32,
    pub flags:             u8,     // CBW_DIR_*
    pub lun:               u8,     // logical unit (0 for single-LUN)
    pub cdb_len:           u8,     // 1..=CBW_CDB_MAX_LEN
    pub cdb:               [u8; CBW_CDB_MAX_LEN],
}

impl Cbw {
    /// Parse a 31-byte CBW. Returns `None` on signature mismatch
    /// or buffer too short; caller should STALL endpoints + wait
    /// for reset recovery (BBB §6.6.1).
    ///
    /// The `.try_into().unwrap()` calls below are unreachable
    /// panics: each one indexes a 4-byte slice of `buf`, and the
    /// `buf.len() < CBW_TOTAL_LEN` guard above proves
    /// `buf.len() >= 31` — so `buf[0..4]`, `buf[4..8]`, `buf[8..12]`
    /// are all in-bounds 4-byte slices, and the conversion to
    /// `[u8; 4]` cannot fail.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < CBW_TOTAL_LEN {
            return None;
        }
        let sig = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if sig != CBW_SIGNATURE {
            return None;
        }
        let cdb_len_raw = buf[14];
        if cdb_len_raw == 0 || (cdb_len_raw as usize) > CBW_CDB_MAX_LEN {
            return None;
        }
        let mut cdb = [0u8; CBW_CDB_MAX_LEN];
        cdb[..CBW_CDB_MAX_LEN].copy_from_slice(&buf[15..15 + CBW_CDB_MAX_LEN]);
        Some(Cbw {
            tag:               u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            data_transfer_len: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            flags:             buf[12],
            lun:               buf[13] & 0x0F,
            cdb_len:           cdb_len_raw,
            cdb,
        })
    }

    pub const fn direction_is_in(&self) -> bool {
        self.flags & 0x80 != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Csw {
    pub tag:          u32,
    pub data_residue: u32,
    pub status:       u8,
}

impl Csw {
    pub const fn new(tag: u32, data_residue: u32, status: u8) -> Self {
        Self { tag, data_residue, status }
    }

    /// Encode as the 13-byte wire-format CSW.
    pub const fn encode(self) -> [u8; CSW_TOTAL_LEN] {
        let sig = CSW_SIGNATURE;
        let tag = self.tag;
        let res = self.data_residue;
        [
            (sig      & 0xFF) as u8, (sig >>  8 & 0xFF) as u8,
            (sig >>16 & 0xFF) as u8, (sig >>24 & 0xFF) as u8,
            (tag      & 0xFF) as u8, (tag >>  8 & 0xFF) as u8,
            (tag >>16 & 0xFF) as u8, (tag >>24 & 0xFF) as u8,
            (res      & 0xFF) as u8, (res >>  8 & 0xFF) as u8,
            (res >>16 & 0xFF) as u8, (res >>24 & 0xFF) as u8,
            self.status,
        ]
    }
}
