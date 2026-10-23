// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block device class: what every block backend implements.

/// Backend-agnostic block device operations, selected once at bring-up (see
/// `azos_drv_block::blkdev`). One implementation per board: `blkdev::Queued`
/// (virtio-blk on QEMU, NVMe) over the request layer, `Mmc` on VF2/K1.
///
/// `#[inline]` on every method: with `lto = false` workspace-wide, a
/// cross-crate call (this crate to `crates/fs/fs`) is not inlined without the
/// hint, and the FAT32 read path (`fat32_read_chain` → `fat32_next_cluster`
/// → `read_sector` → `blkdev::read`) runs on every file read and every
/// exec. Each method here is a one-line forward to the existing
/// `virtio::blk`/`mmc` functions, so with the hint LLVM collapses this
/// trait dispatch back down to the same call the old `#[cfg]` free function
/// made — measured in the write-path audit's report, not assumed.
pub trait BlockDevice: Sync {
    fn init(&self) -> Result<(), ()>;
    fn capacity_sectors(&self) -> u64;
    fn read(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()>;
    fn write(&self, sector: u64, count: u32, buf: &[u8]) -> Result<(), ()>;

    /// Make every write that has completed so far durable on the medium.
    ///
    /// A completed `write` means the device accepted the data, which on a
    /// device with a volatile write cache is not the same as the data
    /// surviving a power cut. `Ok` means the device confirmed the flush.
    ///
    /// The default is `Err(Unsupported)`, never `Ok`: a backend that has no
    /// way to confirm durability must say so, and a caller that claims
    /// durability passes that on instead of claiming it.
    fn flush(&self) -> Result<(), FlushError> {
        Err(FlushError::Unsupported)
    }
}

/// Why [`BlockDevice::flush`] could not confirm durability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushError {
    /// The backend cannot flush: the device offered no flush command, or
    /// the driver cannot issue or verify one. Writes are as durable as the
    /// device makes them when it completes them, which this kernel cannot
    /// confirm.
    Unsupported,
    /// A flush was issued and did not complete successfully, or the device
    /// is not usable.
    Io,
}

/// What a record that must survive a power cut came to: its write, then the
/// device's flush (owner decision 2026-10-23, Q2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Written, and the device confirmed the flush.
    Durable,
    /// Written, but the device has no cache control ([`FlushError::Unsupported`]):
    /// the kernel cannot confirm the record survives a power cut, so it does
    /// not claim it did. Fails closed: a caller treats it as not committed.
    Unconfirmed,
    /// The write or the flush failed.
    Failed,
}

impl Durability {
    /// The verdict for a write that `wrote` (or did not) followed by `flush`.
    /// Only a confirmed flush is durable.
    pub fn of(wrote: bool, flush: Result<(), FlushError>) -> Durability {
        match (wrote, flush) {
            (false, _) | (true, Err(FlushError::Io)) => Durability::Failed,
            (true, Err(FlushError::Unsupported)) => Durability::Unconfirmed,
            (true, Ok(())) => Durability::Durable,
        }
    }
}

// ── What a queued device offers ─────────────────────────────────────────
//
// The request layer (`azos_drv_block::queue`) drives a device through
// [`HwQueue`]. The types are here, not in that crate, because the drivers
// that implement it live on both sides of it: NVMe in the block crate and
// virtio-blk in the virtio crate, which the block crate depends on.

/// Most commands a device may hold at once through [`HwQueue`].
pub const HW_TAGS_MAX: usize = 8;

/// What a [`HwQueue`] command does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwOp {
    Read,
    Write,
    /// Make every completed write durable.
    Flush,
    /// Deallocate (TRIM) the sectors.
    Discard,
}

/// One command for the device. The sectors of a read or write are the
/// concatenation of `segs`, in order; a flush or a discard has none.
pub struct HwCmd<'a> {
    pub op: HwOp,
    pub lba: u64,
    pub sectors: u32,
    /// Force unit access: the data is on stable media when the command
    /// completes. Writes only; the layer sends it only to a device whose
    /// [`HwCaps::fua`] is set.
    pub fua: bool,
    /// Where a write's data is read from (the lender is blocked until the
    /// command is done, so the slices stay valid and unchanged).
    pub segs: &'a [&'a [u8]],
}

/// How the device finished a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwStatus {
    Ok,
    /// The device does not implement the command (a flush with no volatile
    /// cache to flush, a discard it cannot do).
    Unsupported,
    /// The command failed, or the device is dead.
    Io,
    /// The command did not complete within the driver's budget for it (the
    /// driver then reset the device and latched it dead). Only the commands
    /// whose own budget ran out say this; the others the dead device held
    /// are [`HwStatus::Io`]. The request layer fails the request like `Io`
    /// and reports the timeout (`azos_drv_block::queue::set_timeout_sink`).
    Timeout,
}

/// One finished command.
#[derive(Clone, Copy, Debug)]
pub struct HwDone {
    pub tag: u8,
    pub status: HwStatus,
}

/// The answer of [`HwQueue::claim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// A free command slot, `< HW_TAGS_MAX`; the claimer must `start` it or
    /// `release` it.
    Tag(u8),
    /// Every slot is in use: try again after a completion.
    Busy,
    /// The device is gone for good: nothing will ever be started.
    Dead,
}

/// What the device is, once.
#[derive(Clone, Copy, Debug)]
pub struct HwCaps {
    /// Sectors on the medium.
    pub sectors: u64,
    /// Sectors one read or write command carries at most.
    pub max_sectors: u32,
    /// Sectors one [`HwOp::Discard`] command covers at most; 0: the device
    /// has no discard and the layer refuses the request.
    pub max_discard_sectors: u32,
    /// The device honours [`HwCmd::fua`] natively: the write is stable when
    /// it completes, with no flush behind it. A device without it (virtio-blk
    /// has no per-request FUA) sets `false` and the layer refuses a request
    /// that asks for it.
    pub fua: bool,
}

/// A device's hardware queue, as the request layer drives it. Implemented by
/// the NVMe driver and by virtio-blk.
///
/// A command is `claim`ed (a slot with its staging memory), `start`ed, and
/// later reported by `reap`; the data of a read is then `copy_out`, and the
/// slot `release`d. The device never sees a caller's memory: `start` copies a
/// write's data into memory the device may DMA from, and `copy_out` copies a
/// read's out of it.
///
/// A device that has failed reports every command it holds as
/// [`HwStatus::Io`] (or [`HwStatus::Timeout`], for one whose budget ran out)
/// from `reap` (without touching their data), answers
/// [`Claim::Dead`], and keeps the staging memory of those commands for good:
/// a command it could not recall may still be writing to it.
pub trait HwQueue: Sync {
    fn caps(&self) -> HwCaps;
    /// Which per-hart queue the calling task submits to (its CPU).
    fn cpu(&self) -> usize;
    fn claim(&self) -> Claim;
    /// Start the command on a claimed slot. `Err` only when the device died
    /// meanwhile; the slot is then the caller's to `release`.
    fn start(&self, tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()>;
    /// Move the commands the device finished since the last call into `out`;
    /// returns how many. Never blocks.
    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize;
    /// Copy `dst.len()` bytes of a finished read's data, from byte `off` of
    /// the command's data.
    fn copy_out(&self, tag: u8, off: usize, dst: &mut [u8]);
    /// The command is retired: its slot is free again.
    fn release(&self, tag: u8);
    /// Sleep until the device may have completed something or `until_ns` on
    /// the monotonic clock; `false` when it cannot sleep (polled, or no
    /// scheduler yet) and the caller should spin. At most one task is ever in
    /// here.
    fn wait(&self, until_ns: u64) -> bool;
}

// ── Command budgets that survive a guest that did not run ───────────────

use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

/// Two looks at a device further apart than this are a guest that did not run
/// in between (a hypervisor paused it, a host starved it), not a device that
/// is slow. A task waiting for the disk looks at least once per millisecond
/// (the request layer's slice); 50 ms is far past any scheduling delay a
/// running guest sees and far below a command budget (500 ms).
pub const STALL_GAP_US: u64 = 50_000;

/// What a block driver's command budget is measured in: time the guest ran.
///
/// A command's budget (`virtio::blk_proto::BLK_TIMEOUT_US`, NVMe's `IO_TIMEOUT_US`)
/// is wall-clock, and it exists to catch a DEAD device. A guest whose host
/// stopped it for a second wakes up with the clock a second ahead and every
/// command in flight out of budget, though the device never had a chance to
/// answer: the driver then reset it and latched it dead for good.
///
/// So the driver tells this clock each time it looks at the device (a submit,
/// a reap). A gap between two looks above [`STALL_GAP_US`] is time the device
/// was not asked and could not be heard: it is added to a credit, and a
/// command is out of budget only when its deadline plus the credit gained
/// since it was submitted has passed. A device that really died is still found:
/// the credit is the unwatched time, once, and the next look sees a short gap.
///
/// Rejected: "retry once before latching" (a second budget after the first
/// expiry): it forgives one stall of any length but only one, and a guest
/// stopped twice during one command still killed its disk; the credit asks
/// the question that matters, how long the device was left to answer.
///
/// Lock-free. Two harts that observe the same gap both credit it, which only
/// ever delays the verdict (by at most the gap, once per observing hart).
pub struct StallClock {
    last: AtomicU64,
    credit: AtomicU64,
}

impl StallClock {
    pub const fn new() -> Self {
        StallClock { last: AtomicU64::new(0), credit: AtomicU64::new(0) }
    }

    /// The driver looks at the device at timebase tick `now`; gaps above
    /// `stall_ticks` are credited. Returns the ticks credited by this look
    /// (0: the guest ran).
    ///
    /// The credit is published before the look is, so a hart that sees this
    /// look as the previous one also sees its credit.
    pub fn observe(&self, now: u64, stall_ticks: u64) -> u64 {
        let prev = self.last.load(Ordering::Acquire);
        let gap = if prev == 0 { 0 } else { now.saturating_sub(prev) };
        let credited = if gap > stall_ticks {
            self.credit.fetch_add(gap, Ordering::AcqRel);
            gap
        } else {
            0
        };
        self.last.fetch_max(now, Ordering::AcqRel);
        credited
    }

    /// The credit so far: record it when a command is submitted
    /// (`credit_at_submit` of [`expired`](Self::expired)).
    pub fn credit(&self) -> u64 {
        self.credit.load(Ordering::Acquire)
    }

    /// Has the command, due at `deadline` and submitted when the credit was
    /// `credit_at_submit`, run out of budget at tick `now`? Call
    /// [`observe`](Self::observe) with the same `now` first.
    pub fn expired(&self, now: u64, deadline: u64, credit_at_submit: u64) -> bool {
        now >= deadline.saturating_add(self.credit().saturating_sub(credit_at_submit))
    }
}

// ── The task asleep in the device ───────────────────────────────────────

/// The task asleep in [`HwQueue::wait`], and the handshake with the interrupt
/// (or the task) that wakes it: a wake sent before the sleeper listed itself
/// reaches nobody, so the sleeper looks again after it is listed.
///
/// **The two halves are a pair of store-then-load, and need a full fence.**
///
/// ```text
///   sleeper                          waker
///   tid.store(me)                    event is visible (a completion posted,
///   fence                                a progress flag set)
///   if ready() { skip the sleep }    fence
///   else { block }                   tid.load()  -> wake it if listed
/// ```
///
/// Each side stores and then loads what the other stored. With no fence
/// between a side's store and its load, both loads may read the old value (a
/// store sits in the store buffer past a later load): the waker sees nobody
/// listed, the sleeper sees no event, and the sleeper blocks until its
/// deadline with its event already posted. With the fences one of the two
/// loads sees the other side's store, so the sleeper either skips the sleep or
/// is found by the waker. Virtio-blk and NVMe had the store/load pair without
/// the fence; the USB disk had no `ready` at all: a wake that came between the
/// reaper's last look and its listing was lost for the whole slice.
pub struct DeviceWait {
    tid: AtomicU32,
}

impl DeviceWait {
    pub const fn new() -> Self {
        DeviceWait { tid: AtomicU32::new(0) }
    }

    /// The sleeping half of [`HwQueue::wait`]: list `tid`, then ask `ready`
    /// whether the event has already happened, and only if it has not call
    /// `block`. Answers what `block` answered (`true` when `ready` held: the
    /// caller looks again at once, as after any sleep).
    pub fn park(&self, tid: u32, ready: impl FnOnce() -> bool, block: impl FnOnce() -> bool) -> bool {
        self.tid.store(tid, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        let slept = if ready() { true } else { block() };
        self.tid.store(0, Ordering::SeqCst);
        slept
    }

    /// The waking half: the task to wake, `0` when none is listed. Call it
    /// after the event is visible (the completion posted, the flag set).
    pub fn sleeper(&self) -> u32 {
        fence(Ordering::SeqCst);
        self.tid.load(Ordering::SeqCst)
    }
}

impl Default for DeviceWait {
    fn default() -> Self {
        Self::new()
    }
}
