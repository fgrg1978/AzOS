// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CBW → SCSI → CSW dispatcher.
//!
//! Pure helper that ties the three pre-existing layers together
//! into a single one-shot call:
//!
//!   1. Parse the 31-byte CBW arriving on bulk-OUT.
//!   2. Decode the SCSI CDB.
//!   3. Execute the command against a `BlockDevice` (immediate
//!      INQUIRY / READ_CAPACITY responses; multi-block READ_10
//!      and WRITE_10 still need the caller to pump bulk endpoints
//!      block-by-block).
//!   4. Encode the 13-byte CSW with the correct residue + status.
//!
//! Lives in the msc crate (rather than in the kernel `msc_gadget`
//! glue module) so that host tests in `tests/host/msc-tests` can
//! exercise the SCSI→LBA mapping without pulling in the kernel.

use crate::bbb::{Cbw, Csw, CBW_TOTAL_LEN, CSW_STATUS_FAIL, CSW_STATUS_OK, CSW_TOTAL_LEN};
use crate::scsi::{
    execute_scsi, mode_sense6_full_len, parse_scsi_command, BlockDevice, ScsiCommand,
    ScsiResponse, Sense, BLOCK_SIZE,
};

/// Max bytes the dispatcher will buffer for an immediate IN
/// response (INQUIRY 36 + slack). Multi-block READ_10 streams via
/// `Action::ReadBlocks` and does NOT use this scratch space.
pub const DISPATCH_IN_BUF_LEN: usize = 64;

/// Tag carried over from CBW into the final CSW. Re-exposed so
/// kernel glue can echo it back to the host without re-parsing.
pub type CbwTag = u32;

/// Highest Logical Unit Number this gadget implements.
///
/// Must stay in step with `descriptors::MscDescriptorBuilder::max_lun`, which
/// is what GET_MAX_LUN reports to the host on EP0. We export exactly one LUN
/// (the FAT32 volume), so the only addressable value is 0.
///
/// BBB §6.2.2 makes a CBW naming a LUN the device does not support "not
/// meaningful", and §6.6.1 requires the device to stall and report Phase
/// Error for one. Before this was checked, `bCBWLUN` was parsed, masked, and
/// then never looked at: a CBW addressed to LUN 3 was executed against LUN 0
/// regardless. On this device every LUN is the boot volume, so that is a
/// command the host believes went to a device that does not exist, silently
/// applied to the one holding the kernel images — a write in that state hits
/// real blocks while the host's own model of what it just did is wrong.
pub const MSC_MAX_LUN: u8 = 0;

/// The device's own data-transfer intent for a decoded command — the "Dn /
/// Di / Do" side of the BBB §6.7 host/device comparison (Table 6.1).
///
/// A zero-length IN or OUT is normalised to [`DeviceIntent::None`]: §6.7
/// classifies by whether data moves, not by which opcode was used, so an
/// INQUIRY with `allocation_length = 0` is a `Dn` case and must not be
/// compared against the host's direction bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceIntent {
    /// `Dn` — the device will transfer no data.
    None,
    /// `Di` — the device will send this many bytes to the host.
    In(u32),
    /// `Do` — the device expects this many bytes from the host.
    Out(u32),
}

/// Device-side transfer intent for `cmd`, without executing it.
///
/// Deliberately derived from the *parsed command* rather than from
/// `execute_scsi`'s result, so the §6.7 comparison can run before anything
/// touches the block device or the scratch buffer. A CBW that fails the
/// comparison must not have executed.
fn device_intent(cmd: ScsiCommand) -> DeviceIntent {
    // Lengths here must match what `execute_scsi` actually produces for the
    // same command, or the check would reject legal transfers. Each `min`
    // mirrors the corresponding cap in `scsi.rs`.
    let len: u32 = match cmd {
        ScsiCommand::TestUnitReady | ScsiCommand::SynchronizeCache10 => 0,
        ScsiCommand::RequestSense { allocation_length } =>
            u32::from(allocation_length).min(18),
        ScsiCommand::Inquiry { allocation_length } =>
            u32::from(allocation_length).min(36),
        ScsiCommand::ModeSense6 { allocation_length, page_code, .. } =>
            u32::from(allocation_length).min(mode_sense6_full_len(page_code) as u32),
        ScsiCommand::ReadCapacity10 => 8,
        // `blocks` is u16 and BLOCK_SIZE is 512, so the product is at most
        // 65535 * 512 = 33_553_920 — comfortably inside u32, no overflow.
        ScsiCommand::Read10  { blocks, .. } |
        ScsiCommand::Write10 { blocks, .. } =>
            u32::from(blocks) * (BLOCK_SIZE as u32),
    };

    if len == 0 {
        return DeviceIntent::None;
    }
    match cmd {
        ScsiCommand::Write10 { .. } => DeviceIntent::Out(len),
        _                           => DeviceIntent::In(len),
    }
}

/// BBB §6.7 host/device data-transfer comparison (Table 6.1, cases 1-13).
///
/// Returns `true` when the host's `dCBWDataTransferLength` + direction bit
/// are compatible with what the device intends to do, `false` for the cases
/// the spec marks Phase Error.
///
/// This existed nowhere before: `data_transfer_len` was read only to compute
/// the CSW residue, and `direction_is_in()` was never called at all. A host
/// that asked for a 512-byte READ while the CDB named 8 blocks got the CSW's
/// residue field quietly saturated to 0 and the device streaming 4096 bytes
/// into a 512-byte expectation — the endpoint desynchronises mid-transfer,
/// and because no case produced `PhaseError`, the host was never told to run
/// the reset-recovery that resynchronises it. Direction was worse: a CBW
/// flagged data-OUT for a READ_10 had the device pushing data onto an
/// endpoint the host was driving in the opposite direction.
///
/// The mapping to Table 6.1, by arm:
/// * `Dn`   — cases 1 / 4 / 9: host may expect nothing or more than nothing;
///            either way it is `OK` with the full length as residue, and the
///            direction bit is not consulted.
/// * `Di`   — case 2 (`Hn < Di`), case 10 (`Ho <> Di`), case 7 (`Hi < Di`)
///            are Phase Error; cases 5 / 6 (`Hi >= Di`) are OK.
/// * `Do`   — case 3 (`Hn < Do`), case 8 (`Hi <> Do`), case 13 (`Ho < Do`)
///            are Phase Error; cases 11 / 12 (`Ho >= Do`) are OK.
fn bbb_transfer_compatible(cbw: &Cbw, intent: DeviceIntent) -> bool {
    let host_len = cbw.data_transfer_len;
    let host_in  = cbw.direction_is_in();

    match intent {
        // Cases 1, 4, 9 — device moves no data. Per §6.7 the direction bit
        // is "don't care" when the device transfers nothing, and any host
        // length is satisfied by an all-residue CSW.
        DeviceIntent::None => true,

        // Case 2 (Hn) / case 10 (Ho) / case 7 (Hi too short).
        DeviceIntent::In(want)  => host_len != 0 && host_in  && host_len >= want,

        // Case 3 (Hn) / case 8 (Hi) / case 13 (Ho too short).
        DeviceIntent::Out(want) => host_len != 0 && !host_in && host_len >= want,
    }
}

/// Outcome of dispatching one CBW.  The caller (kernel msc_gadget
/// or a host test) decides what to do next on the bulk endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Command completed inline. Send `in_len` bytes from the
    /// scratch buffer on bulk-IN (if non-zero) then send `csw`.
    InlineDone {
        in_len: usize,
        csw: [u8; CSW_TOTAL_LEN],
    },
    /// READ_10: stream `blocks` × 512 bytes from `start_lba` on
    /// bulk-IN, then send `csw`.
    ReadBlocks {
        start_lba: u32,
        blocks: u16,
        csw: [u8; CSW_TOTAL_LEN],
    },
    /// WRITE_10: drain `blocks` × 512 bytes from bulk-OUT into
    /// `start_lba` onwards, then send `csw`.
    WriteBlocks {
        start_lba: u32,
        blocks: u16,
        csw: [u8; CSW_TOTAL_LEN],
    },
    /// CBW parse failed or unsupported opcode. Caller should stall
    /// the bulk endpoints and wait for MASS_STORAGE_RESET.
    PhaseError,
}

/// Parse + execute one CBW and produce the next action.
///
/// `in_buf` is the scratch destination for inline IN responses
/// (INQUIRY, READ_CAPACITY, REQUEST_SENSE, MODE_SENSE). It must
/// be at least `DISPATCH_IN_BUF_LEN` bytes.
///
/// `sense` is the device's pending sense data, kept by the caller across
/// CBWs: a CSW(FAIL) produced here leaves the reason in it for the host's
/// REQUEST SENSE (see `scsi::Sense`). A failure the caller detects later —
/// in the READ_10/WRITE_10 data phase — is the caller's to record.
pub fn dispatch_cbw(
    cbw_bytes: &[u8],
    blk: &dyn BlockDevice,
    in_buf: &mut [u8],
    sense: &mut Sense,
) -> Action {
    if cbw_bytes.len() < CBW_TOTAL_LEN || in_buf.len() < DISPATCH_IN_BUF_LEN {
        return Action::PhaseError;
    }
    let cbw = match Cbw::parse(cbw_bytes) {
        Some(c) => c,
        None => return Action::PhaseError,
    };

    // BBB §6.2.2 — a CBW naming an unsupported LUN is "not meaningful", and
    // §6.6.1 answers those with a stall + Phase Error, not a CSW. See
    // `MSC_MAX_LUN`.
    if cbw.lun > MSC_MAX_LUN {
        return Action::PhaseError;
    }

    // An unknown opcode is a *meaningful* CBW carrying a command we do not
    // implement: the host expects a normal CSW(FAIL) and will follow with
    // REQUEST_SENSE. Collapsing it into PhaseError would send the host into
    // reset recovery for something as ordinary as an OS probing for an
    // optional command, so this stays ahead of the §6.7 check (which needs a
    // decoded command to know the device's intent anyway).
    let cmd = match parse_scsi_command(&cbw.cdb[..cbw.cdb_len as usize]) {
        Some(c) => c,
        None => {
            *sense = Sense::INVALID_OPCODE;
            return Action::InlineDone {
                in_len: 0,
                csw: Csw::new(cbw.tag, cbw.data_transfer_len, CSW_STATUS_FAIL).encode(),
            };
        }
    };

    // BBB §6.7 — reconcile what the host announced in the CBW against what
    // this command will actually transfer. Runs BEFORE `execute_scsi` so a
    // mismatched CBW never reaches the block device or the scratch buffer.
    if !bbb_transfer_compatible(&cbw, device_intent(cmd)) {
        return Action::PhaseError;
    }

    let resp = execute_scsi(cmd, blk, in_buf, sense);
    match (cmd, resp) {
        (_, ScsiResponse::Done { data_in_len }) => {
            let residue = cbw
                .data_transfer_len
                .saturating_sub(data_in_len as u32);
            Action::InlineDone {
                in_len: data_in_len,
                csw: Csw::new(cbw.tag, residue, CSW_STATUS_OK).encode(),
            }
        }
        (ScsiCommand::Read10 { lba, blocks }, ScsiResponse::ReadData { expected_data_in }) => {
            // Bounds-check before streaming. Out-of-range LBA reports FAIL;
            // host will then issue REQUEST_SENSE.
            if !lba_range_in_bounds(blk, lba, blocks) {
                return Action::InlineDone {
                    in_len: 0,
                    csw: Csw::new(cbw.tag, cbw.data_transfer_len, CSW_STATUS_FAIL).encode(),
                };
            }
            let residue = cbw.data_transfer_len.saturating_sub(expected_data_in);
            Action::ReadBlocks {
                start_lba: lba,
                blocks,
                csw: Csw::new(cbw.tag, residue, CSW_STATUS_OK).encode(),
            }
        }
        (ScsiCommand::Write10 { lba, blocks }, ScsiResponse::WriteData { expected_data_out }) => {
            if !lba_range_in_bounds(blk, lba, blocks) {
                return Action::InlineDone {
                    in_len: 0,
                    csw: Csw::new(cbw.tag, cbw.data_transfer_len, CSW_STATUS_FAIL).encode(),
                };
            }
            let residue = cbw.data_transfer_len.saturating_sub(expected_data_out);
            Action::WriteBlocks {
                start_lba: lba,
                blocks,
                csw: Csw::new(cbw.tag, residue, CSW_STATUS_OK).encode(),
            }
        }
        _ => Action::InlineDone {
            in_len: 0,
            csw: Csw::new(cbw.tag, cbw.data_transfer_len, CSW_STATUS_FAIL).encode(),
        },
    }
}

/// `true` if `[lba, lba+blocks)` lies fully inside the device.
/// Used to short-circuit READ_10/WRITE_10 with FAIL on out-of-
/// range LBA — otherwise the per-block loop would surface the
/// error mid-transfer which is harder to recover from.
pub fn lba_range_in_bounds(blk: &dyn BlockDevice, lba: u32, blocks: u16) -> bool {
    let cnt = blk.block_count() as u64;
    let end = (lba as u64) + (blocks as u64);
    end <= cnt
}

/// Convenience: bytes consumed/produced by `blocks` of READ/WRITE.
/// Inline `pub const fn` so callers can use it in array sizes.
pub const fn block_bytes(blocks: u16) -> usize {
    (blocks as usize) * BLOCK_SIZE
}
