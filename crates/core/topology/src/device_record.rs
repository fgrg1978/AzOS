// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device record: this device's id and the lowest `CONFIG.SIG` counter it
//! still accepts (RFC-0054 finding 7, wave 11).
//!
//! One sector in the reserved tail past the FAT32 volume
//! (`kernel/src/msc_gadget.rs` `RESERVED_SECTOR_DEVICE`), which the USB
//! mass-storage export cannot address. Written from the host by
//! `tools/device_provision.py` (floor 0) and by the kernel each time it accepts
//! a `CONFIG.INI` whose signed counter is above the floor.
//!
//! ```text
//!   0   4   magic "KDEV"
//!   4   1   version 1
//!   5  16   device id
//!   21  8   floor, u64 little-endian (0: no signed CONFIG.INI accepted yet)
//!   29  4   first 4 bytes of SHA-256(bytes 0..29)
//! ```
//!
//! The tag catches a torn or foreign sector, not an attacker: anyone who can
//! write this sector can write a matching tag. What keeps the USB-port
//! attacker out is the sector's position; a card-reader attacker can rewrite
//! it (RFC-0054 §6.3: only a hardware counter closes that).

use azos_crypto::sha256::sha256;

/// Bytes of a device id.
pub const DEVICE_ID_LEN: usize = 16;
/// Meaningful bytes of a record; the rest of the sector is zero.
pub const DEVICE_RECORD_LEN: usize = 4 + 1 + DEVICE_ID_LEN + 8 + 4;
const MAGIC: [u8; 4] = *b"KDEV";
const VERSION: u8 = 1;
const BODY: usize = DEVICE_RECORD_LEN - 4;

/// A decoded device record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The id a `CONFIG.SIG` v2 must name.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The lowest counter accepted. 0: no signed `CONFIG.INI` was ever
    /// accepted on this device.
    pub floor: u64,
}

impl DeviceRecord {
    /// The record as it goes on the medium.
    pub fn encode(&self) -> [u8; DEVICE_RECORD_LEN] {
        let mut out = [0u8; DEVICE_RECORD_LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5..5 + DEVICE_ID_LEN].copy_from_slice(&self.device_id);
        out[5 + DEVICE_ID_LEN..BODY].copy_from_slice(&self.floor.to_le_bytes());
        let tag = sha256(&out[..BODY]);
        out[BODY..].copy_from_slice(&tag[..4]);
        out
    }

    /// Decode a sector: `None` for a wrong magic or version, a short buffer,
    /// or a tag that does not match. An absent record is never read as a
    /// zero id or a zero floor.
    pub fn decode(sector: &[u8]) -> Option<Self> {
        if sector.len() < DEVICE_RECORD_LEN || sector[..4] != MAGIC || sector[4] != VERSION {
            return None;
        }
        let tag = sha256(&sector[..BODY]);
        if sector[BODY..DEVICE_RECORD_LEN] != tag[..4] {
            return None;
        }
        let mut device_id = [0u8; DEVICE_ID_LEN];
        device_id.copy_from_slice(&sector[5..5 + DEVICE_ID_LEN]);
        let mut f = [0u8; 8];
        f.copy_from_slice(&sector[5 + DEVICE_ID_LEN..BODY]);
        Some(Self { device_id, floor: u64::from_le_bytes(f) })
    }
}

// ── The signed topology's counter floor (wave 15, TOPOSIGN) ─────────────────
//
// A second record, in its own reserved-tail sector (Kconfig
// `TOPOLOGY_FLOOR_SECTOR`, default 3), so the CONFIG.SIG floor above and this
// one move independently and neither format changes:
//
//   0   4   magic "KTPF"
//   4   1   version 1
//   5   8   floor, u64 little-endian (0: no counter-bound topology accepted)
//   13  4   first 4 bytes of SHA-256(bytes 0..13)
//
// Same trust as the device record: the sector is out of the USB export's
// reach; a card-reader attacker can rewrite it (RFC-0054 §6.3).

/// Meaningful bytes of a topology floor record; the rest of the sector is 0.
pub const TOPO_FLOOR_LEN: usize = 4 + 1 + 8 + 4;
const TOPO_MAGIC: [u8; 4] = *b"KTPF";
const TOPO_VERSION: u8 = 1;
const TOPO_BODY: usize = TOPO_FLOOR_LEN - 4;

/// Encode the topology counter floor as it goes on the medium.
pub fn topo_floor_encode(floor: u64) -> [u8; TOPO_FLOOR_LEN] {
    let mut out = [0u8; TOPO_FLOOR_LEN];
    out[..4].copy_from_slice(&TOPO_MAGIC);
    out[4] = TOPO_VERSION;
    out[5..TOPO_BODY].copy_from_slice(&floor.to_le_bytes());
    let tag = sha256(&out[..TOPO_BODY]);
    out[TOPO_BODY..].copy_from_slice(&tag[..4]);
    out
}

/// Decode a topology floor sector: `None` for anything that is not a valid
/// record (an all-zero sector of a fresh image included), which the loader
/// reads as floor 0.
pub fn topo_floor_decode(sector: &[u8]) -> Option<u64> {
    if sector.len() < TOPO_FLOOR_LEN || sector[..4] != TOPO_MAGIC || sector[4] != TOPO_VERSION {
        return None;
    }
    if sector[TOPO_BODY..TOPO_FLOOR_LEN] != sha256(&sector[..TOPO_BODY])[..4] {
        return None;
    }
    let mut f = [0u8; 8];
    f.copy_from_slice(&sector[5..TOPO_BODY]);
    Some(u64::from_le_bytes(f))
}
