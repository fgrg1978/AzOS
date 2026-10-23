// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What virtio-blk says on the wire and the arithmetic around it: request
//! types, feature bits, the device-config offsets of the queue count and the
//! discard limits, the discard segment, how many queues and slots a device
//! gets and which queue a slot belongs to. Pure functions with no device
//! behind them, so `tests/host/drivers-tests` runs this exact file; `blk.rs`
//! is the driver that puts it on a virtqueue.
//!
//! virtio 1.2, section 5.2.

use azos_drv_api::block::HwStatus;

// ── Command budgets ─────────────────────────────────────────────────────

/// What a slot runs, for the status mapping and its budget.
pub const OP_DATA: u8 = 0;
pub const OP_FLUSH: u8 = 1;
pub const OP_DISCARD: u8 = 2;

/// **A wall-clock budget, not a spin count.** 500 ms is deliberately
/// generous: a virtio-blk request completes in microseconds here and in low
/// milliseconds on real storage. The budget exists to bound a *dead* device,
/// not to police a slow one: a timeout resets the device (once per boot,
/// `azos_drv_api::recovery`) and the next one latches the driver dead until
/// reboot, and being late is survivable where being wrong is not.
pub const BLK_TIMEOUT_US: u64 = 500_000;

/// Budget for a command whose completion time scales with device state
/// rather than with one request: four times the per-request one.
pub const BLK_LONG_TIMEOUT_US: u64 = 4 * BLK_TIMEOUT_US;

/// The budget of a command. A flush writes out the device's whole volatile
/// cache; a discard (up to `max_discard_sectors` in one command) makes a flash
/// device erase or remap blocks, which can take far longer than a read of the
/// same size. A discard is only a hint, so it must never be the command that
/// kills the driver: it gets the long budget too.
pub const fn budget_us(op: u8) -> u64 {
    match op {
        OP_FLUSH | OP_DISCARD => BLK_LONG_TIMEOUT_US,
        _ => BLK_TIMEOUT_US,
    }
}

// ── Request types and status ────────────────────────────────────────────

/// Read from the device.
pub const T_IN: u32 = 0;
/// Write to the device.
pub const T_OUT: u32 = 1;
/// Commit the device's volatile write cache.
pub const T_FLUSH: u32 = 4;
/// Deallocate the sectors of the discard segments.
pub const T_DISCARD: u32 = 11;

pub const S_OK: u8 = 0;
/// The device does not implement the request type.
pub const S_UNSUPP: u8 = 2;
/// The status byte before the device writes it.
pub const S_PENDING: u8 = 0xFF;
/// Driver-side only, never written by a device: the command's budget ran out
/// and the device was reset or latched dead for it.
pub const S_TIMEOUT: u8 = 0xFE;
/// Driver-side only: the device was reset with the command in it (another
/// command's budget ran out).
pub const S_RESET: u8 = 0xFD;

// ── Feature bits (word 0) ───────────────────────────────────────────────

pub const F_RO: u32 = 1 << 5;
pub const F_FLUSH: u32 = 1 << 9;
/// Several request queues; `num_queues` is valid.
pub const F_MQ: u32 = 1 << 12;
/// `T_DISCARD` is implemented; the discard limits are valid.
pub const F_DISCARD: u32 = 1 << 13;

// ── Device config (byte offsets from the start of the config space) ─────

/// The 32-bit word holding `num_queues` in its upper half (`le16` at 34).
pub const CFG_NUM_QUEUES_WORD: u32 = 32;
/// `le32 max_discard_sectors`.
pub const CFG_MAX_DISCARD_SECTORS: u32 = 36;
/// `le32 max_discard_seg`.
pub const CFG_MAX_DISCARD_SEG: u32 = 40;

/// `num_queues` out of the config word at [`CFG_NUM_QUEUES_WORD`].
pub const fn num_queues_of(word: u32) -> u16 {
    (word >> 16) as u16
}

// ── Descriptors ─────────────────────────────────────────────────────────

/// Descriptors a request chain takes at most: header, data (or the discard
/// segment), status.
pub const DESCS_PER_REQUEST: usize = 3;

/// Bytes of one discard segment.
pub const DISCARD_SEG_BYTES: usize = 16;

/// One discard segment (`virtio_blk_discard_write_zeroes`): the first sector,
/// the sector count and the flags, little endian. The flags are 0: `unmap` is
/// a WRITE_ZEROES flag, and virtio 1.2 section 5.2.6.2 makes the device answer
/// `S_UNSUPP` to a DISCARD that sets it (QEMU does), which would switch the
/// file system's discard off at its first use.
pub fn discard_segment(sector: u64, sectors: u32) -> [u8; DISCARD_SEG_BYTES] {
    let mut s = [0u8; DISCARD_SEG_BYTES];
    s[0..8].copy_from_slice(&sector.to_le_bytes());
    s[8..12].copy_from_slice(&sectors.to_le_bytes());
    s
}

// ── Queues and slots ────────────────────────────────────────────────────

/// Request queues to set up: the device's `num_queues` when it offers
/// `F_MQ` (else one), no more than `wanted` (Kconfig `VIRTIO_BLK_QUEUES`) or
/// `cpus`, and at least one: a device that offers `F_MQ` and says 0 queues is
/// driven through queue 0, which every device has.
pub fn queues_used(mq: bool, num_queues: u16, wanted: usize, cpus: usize) -> usize {
    if !mq {
        return 1;
    }
    (num_queues as usize).min(wanted).min(cpus).max(1)
}

/// The slots that can be in flight: the configured number, and no more than
/// the descriptors of the queues hold (`queue_size` entries per queue,
/// [`DESCS_PER_REQUEST`] each).
pub fn slots_usable(configured: usize, queues: usize, queue_size: usize) -> usize {
    configured.min(queues * (queue_size / DESCS_PER_REQUEST)).max(1)
}

/// The queue slot `tag` is submitted to.
pub const fn queue_of(tag: usize, queues: usize) -> usize {
    tag % queues
}

/// Is `tag` in the preferred pass for a task on queue `pref`? Slots of the
/// task's own queue come first, so two CPUs on two queues do not share a ring
/// while a slot of their own is free.
pub const fn tag_preferred(tag: usize, queues: usize, pref: usize) -> bool {
    queue_of(tag, queues) == pref
}

/// The largest discard the device takes in one request: 0 (none) unless it
/// offers `F_DISCARD` and takes at least one segment per request.
pub fn max_discard(offered: bool, max_sectors: u32, max_segments: u32) -> u32 {
    if offered && max_segments >= 1 { max_sectors } else { 0 }
}

// ── Completion ──────────────────────────────────────────────────────────

/// What a status byte means for a request. `data`: a read or a write, for
/// which `S_UNSUPP` is a failure; for a flush or a discard it is the device
/// saying it has no such command. `S_TIMEOUT` and `S_RESET` are the driver's
/// own marks for a command a timeout ended.
pub fn status_of(data: bool, status: u8) -> HwStatus {
    match status {
        S_OK => HwStatus::Ok,
        S_UNSUPP if !data => HwStatus::Unsupported,
        S_TIMEOUT => HwStatus::Timeout,
        S_RESET => HwStatus::Reset,
        _ => HwStatus::Io,
    }
}
