// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal SCSI command set for the USB MSC gadget.
//!
//! Decodes the 8 commands a standard PC / Mac / Linux OS issues
//! when mounting a USB drive, and dispatches to a [`BlockDevice`]
//! impl that abstracts the backing store. Sufficient to make the
//! board appear as a read/write USB stick to the host operating
//! system without going near a real on-disk filesystem driver.
//!
//! Reference: SBC-3 (block commands) + SPC-4 (primary cmd set).

/// 6/10-byte SCSI opcodes we implement.
pub const SCSI_OP_TEST_UNIT_READY:   u8 = 0x00;
pub const SCSI_OP_REQUEST_SENSE:     u8 = 0x03;
pub const SCSI_OP_INQUIRY:           u8 = 0x12;
pub const SCSI_OP_MODE_SENSE_6:      u8 = 0x1A;
pub const SCSI_OP_READ_CAPACITY_10:  u8 = 0x25;
pub const SCSI_OP_READ_10:           u8 = 0x28;
pub const SCSI_OP_WRITE_10:          u8 = 0x2A;
/// SBC-3 SYNCHRONIZE CACHE(10). The 16-byte form (0x91) is not decoded:
/// this device implements no 16-byte CDB (no READ/WRITE(16), no READ
/// CAPACITY(16), capacity capped at 2^32 blocks), so a host never needs it.
pub const SCSI_OP_SYNCHRONIZE_CACHE_10: u8 = 0x35;

/// SPC-4 sense data the next REQUEST SENSE reports: sense key, additional
/// sense code, qualifier. A command that fails with CSW status FAIL (BBB's
/// CHECK CONDITION) leaves one here; REQUEST SENSE reports it and clears
/// it; any other command clears it on entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sense {
    pub key:  u8,
    pub asc:  u8,
    pub ascq: u8,
}

impl Sense {
    /// NO SENSE.
    pub const NONE: Sense = Sense { key: 0x00, asc: 0x00, ascq: 0x00 };
    /// MEDIUM ERROR / WRITE ERROR — a write, or the flush that makes writes
    /// durable, did not succeed.
    pub const WRITE_ERROR: Sense = Sense { key: 0x03, asc: 0x0C, ascq: 0x00 };
    /// MEDIUM ERROR / UNRECOVERED READ ERROR.
    pub const READ_ERROR: Sense = Sense { key: 0x03, asc: 0x11, ascq: 0x00 };
    /// ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE.
    pub const INVALID_OPCODE: Sense = Sense { key: 0x05, asc: 0x20, ascq: 0x00 };
}

/// 512-byte block; the SBC standard size.
pub const BLOCK_SIZE: usize = 512;

/// Inquiry vendor / product / revision strings — fixed 8/16/4
/// padded ASCII per SPC-4. Tweak per deployment if needed.
pub const INQUIRY_VENDOR_ID:   &[u8; 8]  = b"AZOS    ";
pub const INQUIRY_PRODUCT_ID:  &[u8; 16] = b"AzOS Recovery   ";
pub const INQUIRY_REVISION:    &[u8; 4]  = b"0001";

/// Block backing-store trait.  The kernel impl wraps the FAT32
/// SD-card driver; host tests use an in-memory `Vec`.
pub trait BlockDevice {
    /// Total number of 512-byte blocks. Used by READ_CAPACITY.
    fn block_count(&self) -> u32;

    /// Read one block into `out` (which must be ≥ 512 bytes).
    fn read_block(&self, lba: u32, out: &mut [u8]) -> Result<(), ()>;

    /// Write one block from `data` (which must be ≥ 512 bytes).
    fn write_block(&mut self, lba: u32, data: &[u8]) -> Result<(), ()>;

    /// Make every completed `write_block` durable on the medium
    /// (SYNCHRONIZE CACHE). `Ok` only when the backing store confirmed it.
    /// No default: an implementation that cannot confirm durability must
    /// say `Err`, not inherit an `Ok`.
    fn sync_cache(&self) -> Result<(), ()>;
}

/// MODE SENSE(6) mode parameter header length (no block descriptor).
pub const MODE_HEADER6_LEN: usize = 4;
/// SBC-3 Caching mode page code and length (bytes including its header).
pub const MODE_PAGE_CACHING: u8 = 0x08;
pub const CACHING_PAGE_LEN: usize = 20;
/// "Return all pages".
pub const MODE_PAGE_ALL: u8 = 0x3F;
/// Caching page byte 2, WCE bit: the device has a volatile write cache.
///
/// Set because it does: every WRITE_10 goes to `blkdev::write`, whose
/// devices (virtio-blk with FLUSH, an SD card) complete a write before it
/// is durable. Linux `sd` (v6.6 `sd_read_cache_type`) sets its WCE from
/// this bit and otherwise prints "Assuming drive cache: write through" and
/// never sends SYNCHRONIZE CACHE; usb-storage makes it ask for page 3Fh.
pub const CACHING_WCE: u8 = 0x04;
/// Largest MODE SENSE(6) response this device builds.
pub const MODE_SENSE6_MAX_LEN: usize = MODE_HEADER6_LEN + CACHING_PAGE_LEN;

/// Full (untruncated) MODE SENSE(6) response length for `page_code`.
pub fn mode_sense6_full_len(page_code: u8) -> usize {
    match page_code {
        MODE_PAGE_CACHING | MODE_PAGE_ALL => MODE_SENSE6_MAX_LEN,
        _ => MODE_HEADER6_LEN,
    }
}

/// Decoded SCSI command — the SCSI handler matches on this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScsiCommand {
    TestUnitReady,
    RequestSense   { allocation_length: u8 },
    Inquiry        { allocation_length: u8 },
    /// `page_code` is CDB byte 2 bits 5:0, `page_control` bits 7:6
    /// (0 current, 1 changeable, 2 default, 3 saved).
    ModeSense6     { allocation_length: u8, page_code: u8, page_control: u8 },
    ReadCapacity10,
    Read10  { lba: u32, blocks: u16 },
    Write10 { lba: u32, blocks: u16 },
    /// The CDB's LBA / block-count range and IMMED bit are not decoded: the
    /// whole device is flushed, before the status is returned, which
    /// satisfies every range and both IMMED settings.
    SynchronizeCache10,
}

/// Parse the CDB into a typed command.  Returns `None` on
/// unknown opcode — the caller stalls the bulk endpoint and
/// reports `STATUS_FAIL` in the CSW.
pub fn parse_scsi_command(cdb: &[u8]) -> Option<ScsiCommand> {
    if cdb.is_empty() {
        return None;
    }
    Some(match cdb[0] {
        SCSI_OP_TEST_UNIT_READY => ScsiCommand::TestUnitReady,
        SCSI_OP_REQUEST_SENSE if cdb.len() >= 6 =>
            ScsiCommand::RequestSense { allocation_length: cdb[4] },
        SCSI_OP_INQUIRY if cdb.len() >= 6 =>
            ScsiCommand::Inquiry { allocation_length: cdb[4] },
        SCSI_OP_MODE_SENSE_6 if cdb.len() >= 6 => ScsiCommand::ModeSense6 {
            allocation_length: cdb[4],
            page_code:    cdb[2] & 0x3F,
            page_control: cdb[2] >> 6,
        },
        SCSI_OP_READ_CAPACITY_10 if cdb.len() >= 10 =>
            ScsiCommand::ReadCapacity10,
        SCSI_OP_READ_10 if cdb.len() >= 10 => ScsiCommand::Read10 {
            lba:    u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]),
            blocks: u16::from_be_bytes([cdb[7], cdb[8]]),
        },
        SCSI_OP_WRITE_10 if cdb.len() >= 10 => ScsiCommand::Write10 {
            lba:    u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]),
            blocks: u16::from_be_bytes([cdb[7], cdb[8]]),
        },
        SCSI_OP_SYNCHRONIZE_CACHE_10 if cdb.len() >= 10 => ScsiCommand::SynchronizeCache10,
        _ => return None,
    })
}

/// Result of executing a SCSI command — what to do with the bulk
/// endpoints next. `data_in` carries the device→host bytes for
/// IN commands (INQUIRY, READ_CAPACITY, etc); `expected_data_out`
/// is the number of host→device bytes the WRITE will receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScsiResponse {
    /// Command done immediately. CSW reports `OK`. `data_in`
    /// slice (if any) goes out on the bulk-IN endpoint before
    /// the CSW.
    Done { data_in_len: usize },
    /// Caller should drain `expected_data_out` bytes from
    /// bulk-OUT into the backing store via `write_block` calls.
    WriteData { expected_data_out: u32 },
    /// Bulk-IN read continues with `expected_data_in` more
    /// bytes (handled by the caller's READ loop).
    ReadData  { expected_data_in: u32 },
    /// Command failed — CSW reports `FAIL`; host will issue
    /// REQUEST_SENSE next.
    Failed,
}

/// Execute a parsed SCSI command. Writes any immediate IN
/// response into `data_in_buf` (returns the number of bytes
/// produced in `Done.data_in_len`).
///
/// `sense` is the device's pending sense data (see [`Sense`]): REQUEST
/// SENSE reports and clears it, every other command clears it on entry
/// and sets it when it fails.
pub fn execute_scsi(
    cmd: ScsiCommand,
    blk: &dyn BlockDevice,
    data_in_buf: &mut [u8],
    sense: &mut Sense,
) -> ScsiResponse {
    if !matches!(cmd, ScsiCommand::RequestSense { .. }) {
        *sense = Sense::NONE;
    }
    match cmd {
        ScsiCommand::TestUnitReady => ScsiResponse::Done { data_in_len: 0 },

        ScsiCommand::RequestSense { allocation_length } => {
            // 18-byte fixed sense format carrying the pending sense.
            let need = (allocation_length as usize).min(18);
            if data_in_buf.len() < need {
                return ScsiResponse::Failed;
            }
            for b in &mut data_in_buf[..need] {
                *b = 0;
            }
            // Guard each field write: a host may request fewer than 8 bytes,
            // and `need - 8` would underflow (usize) → abort. Mirrors Inquiry.
            if need >= 1 { data_in_buf[0] = 0x70; }          // response code
            if need >= 3 { data_in_buf[2] = sense.key; }     // sense key
            if need >= 8 { data_in_buf[7] = (need - 8) as u8; } // additional length
            if need >= 13 { data_in_buf[12] = sense.asc; }   // additional sense code
            if need >= 14 { data_in_buf[13] = sense.ascq; }  // qualifier
            *sense = Sense::NONE;
            ScsiResponse::Done { data_in_len: need }
        }

        ScsiCommand::SynchronizeCache10 => match blk.sync_cache() {
            Ok(()) => ScsiResponse::Done { data_in_len: 0 },
            Err(()) => {
                *sense = Sense::WRITE_ERROR;
                ScsiResponse::Failed
            }
        },

        ScsiCommand::Inquiry { allocation_length } => {
            // 36-byte standard inquiry response.
            let need = (allocation_length as usize).min(36);
            if data_in_buf.len() < need {
                return ScsiResponse::Failed;
            }
            for b in &mut data_in_buf[..need] {
                *b = 0;
            }
            // Guard each field write against `need`, exactly as RequestSense
            // above does. `need` is `min(allocation_length, 36)` and
            // `allocation_length` is byte 4 of a host-supplied CDB — the host
            // is free to send 0. The `data_in_buf.len() < need` check above
            // does NOT cover these five stores: with `allocation_length = 0`
            // it reduces to `len < 0`, which passes for every buffer
            // including an empty one, and then `data_in_buf[0] = 0x00` is an
            // out-of-bounds index. With `panic = "abort"` that is not a bad
            // INQUIRY response, it is a board reset — a physical-safety event
            // on a robot, reachable from one USB control transfer.
            //
            // Not reachable through `dispatch_cbw` today (it hands in a
            // 64-byte scratch buffer, and the §6.7 check now rejects the
            // mismatched CBW anyway), but `execute_scsi` is `pub` and takes
            // the buffer from its caller, so the guard belongs with the
            // stores rather than with any one call site.
            //
            // The `>= 16 / >= 32 / >= 36` thresholds below are left as they
            // are: they are wire-format decisions about when to include the
            // vendor / product / revision strings, not the missing
            // bounds check.
            if need >= 1 { data_in_buf[0] = 0x00; } // peripheral type = direct access
            if need >= 2 { data_in_buf[1] = 0x80; } // RMB=1 (removable)
            if need >= 3 { data_in_buf[2] = 0x06; } // version = SPC-4
            if need >= 4 { data_in_buf[3] = 0x02; } // response data format
            if need >= 5 { data_in_buf[4] = 0x1F; } // additional length = 31
            if need >= 16 {
                let n = (need - 8).min(8);
                data_in_buf[8..8 + n].copy_from_slice(&INQUIRY_VENDOR_ID[..n]);
            }
            if need >= 32 {
                let n = (need - 16).min(16);
                data_in_buf[16..16 + n].copy_from_slice(&INQUIRY_PRODUCT_ID[..n]);
            }
            if need >= 36 {
                data_in_buf[32..36].copy_from_slice(INQUIRY_REVISION);
            }
            ScsiResponse::Done { data_in_len: need }
        }

        ScsiCommand::ModeSense6 { allocation_length, page_code, page_control } => {
            // 4-byte mode parameter header (medium type 0, device-specific
            // 0 = not write-protected / no DPOFUA, no block descriptor),
            // then the Caching page when page 08h or "all pages" (3Fh) is
            // asked for. Any other page: the header alone, as before.
            let full = mode_sense6_full_len(page_code);
            let need = (allocation_length as usize).min(full);
            if data_in_buf.len() < need {
                return ScsiResponse::Failed;
            }
            let mut out = [0u8; MODE_SENSE6_MAX_LEN];
            out[0] = (full - 1) as u8; // mode data length excludes itself
            if full > MODE_HEADER6_LEN {
                let page = &mut out[MODE_HEADER6_LEN..full];
                page[0] = MODE_PAGE_CACHING;
                page[1] = (CACHING_PAGE_LEN - 2) as u8;
                // Changeable values (PC=01): nothing is (no MODE SELECT).
                if page_control != 1 {
                    page[2] = CACHING_WCE; // WCE=1, RCD=0
                }
            }
            data_in_buf[..need].copy_from_slice(&out[..need]);
            ScsiResponse::Done { data_in_len: need }
        }

        ScsiCommand::ReadCapacity10 => {
            // 8 bytes: last LBA (big-endian u32) + block size.
            if data_in_buf.len() < 8 {
                return ScsiResponse::Failed;
            }
            let last_lba = blk.block_count().saturating_sub(1);
            data_in_buf[0..4].copy_from_slice(&last_lba.to_be_bytes());
            data_in_buf[4..8].copy_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
            ScsiResponse::Done { data_in_len: 8 }
        }

        ScsiCommand::Read10  { blocks, .. } => ScsiResponse::ReadData {
            expected_data_in: (blocks as u32) * (BLOCK_SIZE as u32),
        },

        ScsiCommand::Write10 { blocks, .. } => ScsiResponse::WriteData {
            expected_data_out: (blocks as u32) * (BLOCK_SIZE as u32),
        },
    }
}
