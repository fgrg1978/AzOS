// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-blk on the wire (virtio 1.2, section 5.2): request types, status
//! bytes, feature bits, the configuration offsets and the discard segment.

/// Bytes of a sector, the unit of `sector` in a request and of capacity.
pub const SECTOR_SIZE: usize = 512;
/// Bytes of the request header: type, reserved, sector.
pub const REQ_HDR_BYTES: usize = 16;

/// Read from the device.
pub const T_IN: u32 = 0;
/// Write to the device.
pub const T_OUT: u32 = 1;
/// Commit the device's volatile write cache.
pub const T_FLUSH: u32 = 4;
pub const T_GET_ID: u32 = 8;
/// Deallocate the sectors of the discard segments.
pub const T_DISCARD: u32 = 11;

pub const S_OK: u8 = 0;
pub const S_IOERR: u8 = 1;
/// The device does not implement the request type.
pub const S_UNSUPP: u8 = 2;

pub const F_SEG_MAX: u64 = 1 << 2;
pub const F_RO: u64 = 1 << 5;
pub const F_FLUSH: u64 = 1 << 9;
/// Several request queues; `num_queues` is valid.
pub const F_MQ: u64 = 1 << 12;
/// `T_DISCARD` is implemented; the discard limits are valid.
pub const F_DISCARD: u64 = 1 << 13;

/// Offsets from the start of the configuration space: the 32-bit word holding
/// `num_queues` in its upper half (`le16` at 34), `le32 max_discard_sectors`
/// and `le32 max_discard_seg`.
pub const CFG_NUM_QUEUES_WORD: u32 = 32;
pub const CFG_MAX_DISCARD_SECTORS: u32 = 36;
pub const CFG_MAX_DISCARD_SEG: u32 = 40;

/// Bytes of one discard segment (`virtio_blk_discard_write_zeroes`).
pub const DISCARD_SEG_BYTES: usize = 16;

/// One discard segment: the first sector, the sector count and the flags,
/// little endian. The flags are 0: `unmap` is a WRITE_ZEROES flag, and section
/// 5.2.6.2 makes the device answer `S_UNSUPP` to a DISCARD that sets it (QEMU does), which would switch the
/// file system's discard off at its first use.
pub fn discard_segment(sector: u64, sectors: u32) -> [u8; DISCARD_SEG_BYTES] {
    let mut s = [0u8; DISCARD_SEG_BYTES];
    s[0..8].copy_from_slice(&sector.to_le_bytes());
    s[8..12].copy_from_slice(&sectors.to_le_bytes());
    s
}
