// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block device class: the one request every block role speaks, and the
//! device that takes it.

/// Why [`BlockDev::flush`] could not confirm durability.
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
/// device's flush.
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

// ── The one block request ───────────────────────────────────────────────
//
// Every role speaks this: the consumers above the device (the FAT32 cache,
// azvol, the SCSI target), a partition stacked on a device, and the device
// itself. A request is made for a caller and answered when it is done.

// The flag bits and op codes are the wire definitions of `azos_devif::block`:
// `FLAG_FUA`: the write is stable on the medium when it completes (force unit
// access), not only accepted by a volatile cache; writes only, and it orders
// nothing before it. `FLAG_PREFLUSH`: every write that completed before the
// request is made durable before it starts (a flush ahead of it); writes only;
// the epoch rule of a write-back cache rides on it. If the flush ahead
// answers [`BlockError::Unsupported`] the device declares it has no volatile
// cache to flush and the write proceeds; any other flush failure fails the
// request with [`BlockError::PreFlush`] and the write is not made. A device
// with a volatile cache and no flush command must answer `PreFlush`, never
// skip the order. (A plain [`BlockDev::flush`] does not tolerate
// `Unsupported`: it is an `Err`, and its caller fails closed.)
pub use azos_devif::block::{FLAGS_ALL, FLAG_FUA, FLAG_PREFLUSH};
use azos_devif::block::{REQ_DISCARD, REQ_FLUSH, REQ_READ, REQ_WRITE};

/// What a [`BlockReq`] does. The numbers are the wire codes of
/// `azos_devif::block` (`REQ_READ`..`REQ_DISCARD`), the one definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BlockOp {
    Read = REQ_READ,
    Write = REQ_WRITE,
    /// Make every write that completed before this request durable.
    Flush = REQ_FLUSH,
    /// Tell the device the sectors hold nothing worth keeping (a hint).
    Discard = REQ_DISCARD,
}

/// The memory a request moves, matching its op.
pub enum BlockData<'a> {
    /// A flush.
    None,
    /// A read's destination: `count * 512` bytes.
    Read(&'a mut [u8]),
    /// A write's source: `count * 512` bytes.
    Write(&'a [u8]),
    /// A discard's runs, `(first sector, sectors)` relative to
    /// [`BlockReq::sector`], handed to the device together.
    Runs(&'a [(u64, u32)]),
}

/// One request: an op over sector runs, its ordering flags, and the buffers.
/// Sectors are 512 bytes. The answer is the `Result` of [`BlockDev::submit`],
/// which returns once the request is done.
pub struct BlockReq<'a> {
    pub op: BlockOp,
    /// [`FLAG_FUA`] | [`FLAG_PREFLUSH`]; writes only.
    pub flags: u32,
    /// First sector of a read or write; the base a discard's runs are
    /// relative to; 0 for a flush.
    pub sector: u64,
    /// Sectors of a read or write; the sum of a discard's runs; 0 for a flush.
    pub count: u32,
    pub data: BlockData<'a>,
}

impl<'a> BlockReq<'a> {
    pub fn read(sector: u64, buf: &'a mut [u8]) -> Self {
        BlockReq { op: BlockOp::Read, flags: 0, sector, count: (buf.len() / SECTOR) as u32, data: BlockData::Read(buf) }
    }

    pub fn write(sector: u64, buf: &'a [u8]) -> Self {
        BlockReq { op: BlockOp::Write, flags: 0, sector, count: (buf.len() / SECTOR) as u32, data: BlockData::Write(buf) }
    }

    pub fn flush() -> Self {
        BlockReq { op: BlockOp::Flush, flags: 0, sector: 0, count: 0, data: BlockData::None }
    }

    /// A discard of `runs`, relative to `sector 0` of the device it is made to.
    pub fn discard(runs: &'a [(u64, u32)]) -> Self {
        let count = runs.iter().fold(0u64, |a, r| a.saturating_add(r.1 as u64)).min(u32::MAX as u64) as u32;
        BlockReq { op: BlockOp::Discard, flags: 0, sector: 0, count, data: BlockData::Runs(runs) }
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Is the request well formed for a device of `sectors`? Buffers match
    /// the count, the flags only ride on a write, the range lies inside the
    /// device. [`BlockError::Invalid`] for a shape that means nothing,
    /// [`BlockError::Range`] for one that leaves the device.
    pub fn check(&self, sectors: u64) -> Result<(), BlockError> {
        if self.flags & !FLAGS_ALL != 0 || (self.flags != 0 && self.op != BlockOp::Write) {
            return Err(BlockError::Invalid);
        }
        let bytes = (self.count as usize).checked_mul(SECTOR).ok_or(BlockError::Invalid)?;
        match (&self.op, &self.data) {
            (BlockOp::Read, BlockData::Read(b)) if b.len() == bytes && self.count != 0 => {}
            (BlockOp::Write, BlockData::Write(b)) if b.len() == bytes && self.count != 0 => return self.within(sectors),
            (BlockOp::Flush, BlockData::None) if self.count == 0 && self.sector == 0 => return Ok(()),
            (BlockOp::Discard, BlockData::Runs(runs)) if !runs.is_empty() => {
                for &(first, n) in runs.iter() {
                    let end = self.sector.checked_add(first).and_then(|s| s.checked_add(n as u64)).ok_or(BlockError::Range)?;
                    if n == 0 || end > sectors {
                        return Err(BlockError::Range);
                    }
                }
                return Ok(());
            }
            _ => return Err(BlockError::Invalid),
        }
        self.within(sectors)
    }

    fn within(&self, sectors: u64) -> Result<(), BlockError> {
        match self.sector.checked_add(self.count as u64) {
            Some(end) if end <= sectors => Ok(()),
            _ => Err(BlockError::Range),
        }
    }
}

/// Bytes per sector: every block device in the tree speaks 512 B.
pub const SECTOR: usize = 512;

/// Why a request did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// The device does not implement the op (a flush it cannot confirm, a
    /// discard it lacks, FUA without native support). Never an `Ok`: a
    /// caller that claims durability passes it on.
    Unsupported,
    /// The device failed the request, or is not usable.
    Io,
    /// The flush ahead of a [`FLAG_PREFLUSH`] write failed, and the write was
    /// not made. A device that cannot tell which half failed says `Io`.
    PreFlush,
    /// The run leaves the device.
    Range,
    /// The request means nothing (unknown flag, buffer not `count` sectors).
    Invalid,
}

impl From<BlockError> for FlushError {
    fn from(e: BlockError) -> FlushError {
        match e {
            BlockError::Unsupported => FlushError::Unsupported,
            _ => FlushError::Io,
        }
    }
}

/// What a device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Sectors on the device.
    pub sectors: u64,
    /// A [`FLAG_FUA`] write is stable when it completes, natively, and the
    /// build allows relying on it (Kconfig `BLK_FUA`).
    pub fua: bool,
}

/// A block device: the boot disk, a stick, a partition of either, a verity
/// view. Requests complete before `submit` returns.
pub trait BlockDev {
    fn geometry(&self) -> Geometry;

    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError>;

    /// The sector of the medium where sector 0 of this device lies, when the
    /// device is a plain window onto it (the bytes written are the bytes on
    /// the sectors). A device that transforms them says `None`.
    fn medium_start(&self) -> Option<u64> {
        None
    }

    #[inline]
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.submit(BlockReq::read(sector, buf))
    }

    #[inline]
    fn write(&mut self, sector: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.submit(BlockReq::write(sector, buf))
    }

    /// A write with `flags`: [`FLAG_PREFLUSH`] makes every completed write
    /// durable before it starts; [`FLAG_FUA`] makes this one durable when it
    /// completes. Together they commit without a flush behind.
    #[inline]
    fn write_flagged(&mut self, sector: u64, buf: &[u8], flags: u32) -> Result<(), BlockError> {
        self.submit(BlockReq::write(sector, buf).with_flags(flags))
    }

    /// Make every write that completed so far durable. `Err(Unsupported)`
    /// where the device cannot confirm it, never `Ok`.
    #[inline]
    fn flush(&mut self) -> Result<(), BlockError> {
        self.submit(BlockReq::flush())
    }

    #[inline]
    fn discard(&mut self, runs: &[(u64, u32)]) -> Result<(), BlockError> {
        self.submit(BlockReq::discard(runs))
    }
}

/// A window onto `[start, start + sectors)` of the device under it: the
/// stacked device a partition is. Everything it forwards is shifted by
/// `start`, and a request that leaves the window is refused before the
/// device sees it.
pub struct Part<D: BlockDev> {
    inner: D,
    start: u64,
    sectors: u64,
}

impl<D: BlockDev> Part<D> {
    /// `None` when the window leaves `inner`.
    pub fn new(inner: D, start: u64, sectors: u64) -> Option<Self> {
        if start.checked_add(sectors)? > inner.geometry().sectors {
            return None;
        }
        Some(Part { inner, start, sectors })
    }

    /// The device under the window.
    pub fn device(&self) -> &D {
        &self.inner
    }
}

impl<D: BlockDev> BlockDev for Part<D> {
    fn geometry(&self) -> Geometry {
        Geometry { sectors: self.sectors, ..self.inner.geometry() }
    }

    #[inline]
    fn submit(&mut self, mut req: BlockReq<'_>) -> Result<(), BlockError> {
        req.check(self.sectors)?;
        if req.op != BlockOp::Flush {
            req.sector += self.start;
        }
        self.inner.submit(req)
    }

    fn medium_start(&self) -> Option<u64> {
        Some(self.inner.medium_start()? + self.start)
    }
}

// ── What a queued device offers ─────────────────────────────────────────
//
// The request layer (`azos_drv_block::queue`) drives a device through
// [`HwQueue`]. The types are here, not in that crate, because the drivers
// that implement it live on both sides of it: NVMe in the block crate and
// virtio-blk in the virtio crate, which the block crate depends on.

/// Most commands a device may hold at once through [`HwQueue`]: 32, the
/// tags of SATA native command queuing (the AHCI driver's Kconfig
/// `AHCI_NCQ_DEPTH`); NVMe and virtio-blk use fewer.
pub const HW_TAGS_MAX: usize = 32;

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
    /// driver then reset the device, or latched it dead once its resets were
    /// spent: [`crate::recovery`]). Only the commands whose own budget ran
    /// out say this; the others a reset abandoned are [`HwStatus::Reset`],
    /// those a dead device held [`HwStatus::Io`]. The request layer fails
    /// the request like `Io` and reports the timeout
    /// (`azos_drv_block::queue::set_timeout_sink`).
    Timeout,
    /// The device was reset (another command's budget ran out) with this
    /// command in it: not done, and whether a write reached the medium is
    /// unknown. Not retried: the request layer fails the request like `Io`.
    Reset,
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
    /// Every slot is in use, or the device is being reset: try again after
    /// a completion.
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
/// a command it could not recall may still be writing to it. A device being
/// reset ([`crate::recovery`]) answers [`Claim::Busy`], never `Dead`; once
/// its stop is confirmed it reports the commands it held as
/// [`HwStatus::Reset`] (the one whose budget ran out as `Timeout`), and their
/// slots are reused: the stopped device writes to none of them.
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
    /// The device is out of service for a while (a suspend or an unbind in
    /// progress): a `start` it refuses is given back to the queue, not failed.
    fn parked(&self) -> bool {
        false
    }
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

/// A driver says it credited a stall at most this often; the others are
/// counted ([`StallNote::held`]).
pub const STALL_SAY_EVERY_US: u64 = 10_000_000;

/// What a block driver's command budget is measured in: time the guest ran.
///
/// A command's budget (`virtio::blk_proto::BLK_TIMEOUT_US`, NVMe's `IO_TIMEOUT_US`)
/// is wall-clock, and it exists to catch a DEAD device. A guest whose host
/// stopped it for a second wakes up with the clock a second ahead and every
/// command in flight out of budget, though the device never had a chance to
/// answer: the driver then reset it, or latched it dead for good.
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
    said: AtomicU64,
    held: AtomicU32,
}

/// What [`StallClock::look`] asks its driver to say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StallNote {
    /// The stall this look credited, in timebase ticks.
    pub ticks: u64,
    /// Stalls credited since the last line and not said.
    pub held: u32,
}

impl StallClock {
    pub const fn new() -> Self {
        StallClock { last: AtomicU64::new(0), credit: AtomicU64::new(0), said: AtomicU64::new(0), held: AtomicU32::new(0) }
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

    /// The driver looks at an idle device at `now`: nothing was waiting on
    /// it, so the gap since the last look is no stall, whatever its length (a
    /// tickless idle guest looks once per client I/O, seconds apart). Only
    /// the look is recorded; the next [`observe`](Self::observe) measures from
    /// here.
    pub fn touch(&self, now: u64) {
        self.last.fetch_max(now, Ordering::AcqRel);
    }

    /// The driver's look at the device at `now`. A gap is credited only when
    /// `busy` (a command is in the device and its budget runs): an idle disk
    /// looked at seconds apart is no stall, and saying so fed the log sink a
    /// line per period, whose write was the next look.
    ///
    /// Answers what the driver says, at most once per `say_every` ticks:
    /// `None` when nothing was credited or the line is held back.
    pub fn look(&self, now: u64, stall_ticks: u64, say_every: u64, busy: bool) -> Option<StallNote> {
        if !busy {
            self.touch(now);
            return None;
        }
        let ticks = self.observe(now, stall_ticks);
        if ticks == 0 {
            return None;
        }
        let said = self.said.load(Ordering::Relaxed);
        if said != 0 && now.saturating_sub(said) < say_every {
            self.held.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.said.store(now, Ordering::Relaxed);
        Some(StallNote { ticks, held: self.held.swap(0, Ordering::Relaxed) })
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
