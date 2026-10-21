// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The initiator side of the SCSI command set: what a USB mass-storage host
//! driver sends and reads back.
//!
//! The commands are the ones the target side ([`crate::target`]) answers, so a
//! stick that serves them can be driven, and the gadget decodes what this
//! builds (`tests/host/scsi-tests` round-trips every CDB through
//! [`crate::target::parse_scsi_command`]):
//! TEST UNIT READY, REQUEST SENSE, INQUIRY, READ CAPACITY(10), READ(10),
//! WRITE(10) and SYNCHRONIZE CACHE(10). No 16-byte CDB exists here either: a
//! medium over 2^32 blocks answers READ CAPACITY(10) with `0xFFFFFFFF` and is
//! refused ([`CapacityError::TooLarge`]), not driven by its first 2 TiB.
//!
//! Nothing here moves data or waits: a [`Cdb`] goes into a CBW
//! ([`Cdb::cbw`]) and the bytes that come back are parsed by the functions
//! below.

use crate::bbb::{Cbw, CBW_CDB_MAX_LEN, CBW_DIR_IN, CBW_DIR_OUT};
use crate::target::{
    Sense, BLOCK_SIZE, SCSI_OP_INQUIRY, SCSI_OP_READ_10, SCSI_OP_READ_CAPACITY_10, SCSI_OP_REQUEST_SENSE,
    SCSI_OP_SYNCHRONIZE_CACHE_10, SCSI_OP_TEST_UNIT_READY, SCSI_OP_WRITE_10,
};

/// Bytes of the standard INQUIRY data this side reads.
pub const INQUIRY_LEN: usize = 36;
/// Bytes of the READ CAPACITY(10) parameter data.
pub const READ_CAPACITY_10_LEN: usize = 8;
/// Bytes of fixed-format sense data this side asks for.
pub const SENSE_LEN: usize = 18;

/// A command descriptor block: up to [`CBW_CDB_MAX_LEN`] bytes, the rest zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cdb {
    pub bytes: [u8; CBW_CDB_MAX_LEN],
    pub len: u8,
}

impl Cdb {
    const fn of(len: u8, bytes: [u8; CBW_CDB_MAX_LEN]) -> Cdb {
        Cdb { bytes, len }
    }

    pub const fn test_unit_ready() -> Cdb {
        let mut b = [0u8; CBW_CDB_MAX_LEN];
        b[0] = SCSI_OP_TEST_UNIT_READY;
        Cdb::of(6, b)
    }

    /// REQUEST SENSE, asking for `alloc` bytes of fixed-format sense data.
    pub const fn request_sense(alloc: u8) -> Cdb {
        let mut b = [0u8; CBW_CDB_MAX_LEN];
        b[0] = SCSI_OP_REQUEST_SENSE;
        b[4] = alloc;
        Cdb::of(6, b)
    }

    /// Standard INQUIRY (no EVPD), asking for `alloc` bytes.
    pub const fn inquiry(alloc: u8) -> Cdb {
        let mut b = [0u8; CBW_CDB_MAX_LEN];
        b[0] = SCSI_OP_INQUIRY;
        b[4] = alloc;
        Cdb::of(6, b)
    }

    pub const fn read_capacity_10() -> Cdb {
        let mut b = [0u8; CBW_CDB_MAX_LEN];
        b[0] = SCSI_OP_READ_CAPACITY_10;
        Cdb::of(10, b)
    }

    pub const fn read_10(lba: u32, blocks: u16) -> Cdb {
        Cdb::rw_10(SCSI_OP_READ_10, lba, blocks)
    }

    pub const fn write_10(lba: u32, blocks: u16) -> Cdb {
        Cdb::rw_10(SCSI_OP_WRITE_10, lba, blocks)
    }

    const fn rw_10(op: u8, lba: u32, blocks: u16) -> Cdb {
        let mut b = [0u8; CBW_CDB_MAX_LEN];
        b[0] = op;
        let l = lba.to_be_bytes();
        b[2] = l[0];
        b[3] = l[1];
        b[4] = l[2];
        b[5] = l[3];
        let n = blocks.to_be_bytes();
        b[7] = n[0];
        b[8] = n[1];
        Cdb::of(10, b)
    }

    /// SYNCHRONIZE CACHE(10) of the whole medium (LBA 0, 0 blocks = to the
    /// end), not IMMED: the status comes when the cache is on the medium.
    pub const fn synchronize_cache_10() -> Cdb {
        let mut b = [0u8; CBW_CDB_MAX_LEN];
        b[0] = SCSI_OP_SYNCHRONIZE_CACHE_10;
        Cdb::of(10, b)
    }

    /// The CBW that carries this command: `data_len` bytes of data stage, from
    /// the device when `dir_in`, to it otherwise (`data_len` 0: none), on LUN
    /// 0 (this side drives LUN 0 only).
    pub fn cbw(&self, tag: u32, data_len: u32, dir_in: bool) -> Cbw {
        Cbw {
            tag,
            data_transfer_len: data_len,
            flags: if dir_in && data_len != 0 { CBW_DIR_IN } else { CBW_DIR_OUT },
            lun: 0,
            cdb_len: self.len,
            cdb: self.bytes,
        }
    }
}

/// The fields of the standard INQUIRY data a driver acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inquiry {
    /// Peripheral qualifier (0: a device is connected to the logical unit).
    pub qualifier: u8,
    /// Peripheral device type (0 direct access block, 5 CD/DVD, 0x0E RBC, ...).
    pub device_type: u8,
    pub removable: bool,
    pub vendor: [u8; 8],
    pub product: [u8; 16],
    pub revision: [u8; 4],
}

/// Peripheral device type: direct-access block device (SBC).
pub const DEVICE_TYPE_DIRECT_ACCESS: u8 = 0x00;
/// Peripheral device type: simplified direct-access device (RBC).
pub const DEVICE_TYPE_RBC: u8 = 0x0E;

impl Inquiry {
    /// A block device a file system can sit on: connected, SBC or RBC.
    pub fn is_block_device(&self) -> bool {
        self.qualifier == 0 && matches!(self.device_type, DEVICE_TYPE_DIRECT_ACCESS | DEVICE_TYPE_RBC)
    }
}

/// Parse standard INQUIRY data. `None` when it is shorter than the 36 bytes
/// that carry the identification strings.
pub fn parse_inquiry(data: &[u8]) -> Option<Inquiry> {
    if data.len() < INQUIRY_LEN {
        return None;
    }
    let mut i = Inquiry {
        qualifier: data[0] >> 5,
        device_type: data[0] & 0x1F,
        removable: data[1] & 0x80 != 0,
        vendor: [0; 8],
        product: [0; 16],
        revision: [0; 4],
    };
    i.vendor.copy_from_slice(&data[8..16]);
    i.product.copy_from_slice(&data[16..32]);
    i.revision.copy_from_slice(&data[32..36]);
    Some(i)
}

/// A medium of `sectors` blocks of [`BLOCK_SIZE`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    pub sectors: u64,
}

/// Why READ CAPACITY(10) data is not a medium this side drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityError {
    /// Fewer than 8 bytes.
    Short,
    /// The last LBA is `0xFFFFFFFF`: the medium is larger than a 10-byte CDB
    /// addresses and only READ CAPACITY(16) says how much.
    TooLarge,
    /// A block size other than 512 (a 4Kn bridge): the block layer's sector
    /// is 512 bytes.
    BlockLen(u32),
}

/// Parse READ CAPACITY(10) data.
pub fn parse_read_capacity_10(data: &[u8]) -> Result<Capacity, CapacityError> {
    if data.len() < READ_CAPACITY_10_LEN {
        return Err(CapacityError::Short);
    }
    let last = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let block = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if last == u32::MAX {
        return Err(CapacityError::TooLarge);
    }
    if block != BLOCK_SIZE as u32 {
        return Err(CapacityError::BlockLen(block));
    }
    Ok(Capacity { sectors: last as u64 + 1 })
}

/// Parse sense data, fixed format (response code 0x70 / 0x71) or descriptor
/// format (0x72 / 0x73). `None` for anything else or when too short to hold
/// the key, ASC and ASCQ.
pub fn parse_sense(data: &[u8]) -> Option<Sense> {
    match *data.first()? & 0x7F {
        0x70 | 0x71 if data.len() >= 14 => Some(Sense { key: data[2] & 0x0F, asc: data[12], ascq: data[13] }),
        0x72 | 0x73 if data.len() >= 4 => Some(Sense { key: data[1] & 0x0F, asc: data[2], ascq: data[3] }),
        _ => None,
    }
}

impl Sense {
    /// NOT READY (the unit is becoming ready, or has no medium).
    pub const fn is_not_ready(&self) -> bool {
        self.key == 0x02
    }
    /// UNIT ATTENTION (a reset, a medium change: reported once, then cleared).
    pub const fn is_unit_attention(&self) -> bool {
        self.key == 0x06
    }
    /// ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE: the device does not
    /// implement the command.
    pub const fn is_invalid_opcode(&self) -> bool {
        self.key == 0x05 && self.asc == 0x20
    }
}
