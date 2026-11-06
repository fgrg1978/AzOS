// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Block device abstraction — Phase A/B (VF2 + K1 boot).
//!
//! Routes sector I/O to the appropriate backend:
//! - QEMU (`default`):        the NVMe controller or the AHCI SATA disk the PCI
//!                            bring-up attached first (Kconfig `DRV_NVME`,
//!                            `DRV_AHCI`), else the VirtIO block device; all
//!                            are driven through the request layer
//!                            ([`crate::queue`]).
//!                            A USB mass-storage disk (Kconfig `USB_STORAGE`,
//!                            `usb_msc`) is driven through the same
//!                            layer but is never bound here: it has a request
//!                            queue of its own, so a stick that comes and goes
//!                            cannot take the boot disk's place.
//! - VisionFive 2 (`vf2`):   the microSD socket's DesignWare MSHC
//!                            (`starfive,jh7110-mmc`), bound from the device
//!                            tree node by the hardware bus ([`crate::dwmshc`]).
//! - SpacemiT K1  (`k1`):    MMC slot 0 — SD socket (0xD428_0000), an SDHCI
//!                            controller ([`crate::mmc`]).
//!
//! The FAT32 layer and kernel boot use this module exclusively so that
//! no storage-related code needs to be gated on platform features outside
//! this file.
//!
//! ── One request type ────────────────────────────────────────────────────
//!
//! Each backend is a zero-sized [`BlockDev`] (`azos_drv_api::block`) selected
//! once, at compile time, by the board's feature: a request is an op over a
//! sector run with its ordering flags, and `submit` returns when it is done.
//! [`Boot`] is the backend behind this module's checks (real-time rule, the
//! write-back observers, the chaos point); the free functions below are its
//! synchronous helpers, and a partition is a [`Part`](azos_drv_api::block::Part)
//! stacked on it.

use azos_devif::block::{OWNER_KERNEL, OWNER_NONE};
use azos_drv_api::block::{
    BlockData, BlockDev, BlockError, BlockOp, BlockReq, FlushError, Geometry, FLAG_FUA, FLAG_PREFLUSH,
};

// ── Queued backend: virtio-blk, NVMe, AHCI ─────────────────────────────────────────

/// The devices behind the block request layer ([`crate::queue`]): the NVMe
/// controller or the AHCI SATA disk the PCI bring-up attached first (Kconfig
/// `DRV_NVME`, `DRV_AHCI`), else the virtio-blk device the hardware bus bound.
/// Zero-sized: the device is the one `queue::bind` was given, and every
/// method is a request for the caller's Domain that waits for its outcome.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub struct Queued;

#[cfg(not(any(feature = "vf2", feature = "k1")))]
impl Queued {
    #[inline]
    fn init(&self) -> Result<(), ()> {
        if crate::queue::bound().is_some() {
            return Ok(());
        }
        // No controller attached before this: virtio-blk, if the bus bound one.
        azos_drv_virtio::virtio::blk::init()?;
        crate::queue::bind(&azos_drv_virtio::virtio::blk::VIRTIO_BLK);
        Ok(())
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
impl BlockDev for Queued {
    #[inline]
    fn geometry(&self) -> Geometry {
        match crate::queue::bound() {
            None => Geometry { sectors: 0, fua: false, discard: false },
            Some(hw) => {
                let c = hw.caps();
                Geometry { sectors: c.sectors, fua: c.fua, discard: c.max_discard_sectors != 0 }
            }
        }
    }

    #[inline]
    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError> {
        let Some(hw) = crate::queue::bound() else {
            return Err(if req.op == BlockOp::Discard { BlockError::Unsupported } else { BlockError::Io });
        };
        let owner = if req.owner == 0 { owner_now() } else { req.owner };
        let done = match (req.op, req.data) {
            (BlockOp::Read, BlockData::Read(buf)) => crate::queue::read(hw, owner, req.sector, req.count, buf),
            (BlockOp::Write, BlockData::Write(buf)) => {
                crate::queue::write(hw, owner, req.sector, req.count, req.flags, buf)
            }
            (BlockOp::Flush, _) => crate::queue::flush(hw, owner),
            (BlockOp::Discard, BlockData::Runs(runs)) => {
                crate::queue::discard(hw, owner, req.sector, runs, azos_limits::BLK_DISCARD_BATCHED)
            }
            _ => return Err(BlockError::Invalid),
        };
        match done {
            Ok(()) => Ok(()),
            Err(crate::queue::Failure::Refused(azos_devif::outcome::UNSUPPORTED))
            | Err(crate::queue::Failure::Ended(crate::queue::Outcome::Unsupported)) => Err(BlockError::Unsupported),
            Err(_) => Err(BlockError::Io),
        }
    }

    #[inline]
    fn medium_start(&self) -> Option<u64> {
        Some(0)
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
type Backend = Queued;

// ── Real-hardware SD backends (VisionFive 2, SpacemiT K1) ────────────────────

/// DesignWare MSHC backend (VisionFive 2): the microSD controller the hardware
/// bus bound from its device-tree node (`dwmshc::attach`). Zero-sized: the
/// state lives in `dwmshc`.
#[cfg(feature = "vf2")]
pub struct DwMshc;

#[cfg(feature = "vf2")]
impl DwMshc {
    #[inline]
    fn init(&self) -> Result<(), ()> {
        if crate::dwmshc::init() { Ok(()) } else { Err(()) }
    }
}

#[cfg(feature = "vf2")]
impl BlockDev for DwMshc {
    #[inline]
    fn geometry(&self) -> Geometry {
        Geometry { sectors: crate::dwmshc::capacity(), fua: false, discard: false }
    }

    #[inline]
    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError> {
        match (req.op, req.data) {
            (BlockOp::Read, BlockData::Read(buf)) => {
                crate::dwmshc::read(req.sector, req.count, buf).map_err(|()| BlockError::Io)
            }
            (BlockOp::Write, BlockData::Write(buf)) => {
                ordered_write(req.flags, || flush_state(crate::dwmshc::flush()), || {
                    crate::dwmshc::write(req.sector, req.count, buf).map_err(|()| BlockError::Io)?;
                    // This backend has no request layer to complete the write: the write
                    // ledger is fed here (`write_observer::account`).
                    crate::write_observer::account(owner_now(), req.count as u64 * crate::queue::SECTOR as u64);
                    Ok(())
                })
            }
            // `dwmshc::flush`: CMD13 until the card is back in `tran` with
            // READY_FOR_DATA (error bits checked, bounded). `Ok` only on a
            // confirmed card status, `Err(Io)` otherwise.
            (BlockOp::Flush, _) => flush_state(crate::dwmshc::flush()),
            (BlockOp::Discard, _) => Err(BlockError::Unsupported),
            _ => Err(BlockError::Invalid),
        }
    }

    #[inline]
    fn medium_start(&self) -> Option<u64> {
        Some(0)
    }
}

#[cfg(feature = "vf2")]
type Backend = DwMshc;

/// Boot storage slot on K1: the SD card socket (K1 naming: "Emmc" slot 0
/// physically wires to the removable SD socket).
#[cfg(feature = "k1")]
const BOOT_SLOT: crate::mmc::MmcSlot = crate::mmc::MmcSlot::Emmc;

/// SDHCI MMC backend (K1). Zero-sized: state lives in `mmc::SLOT_STATE`,
/// keyed by `BOOT_SLOT`.
#[cfg(feature = "k1")]
pub struct Mmc;

#[cfg(feature = "k1")]
impl Mmc {
    #[inline]
    fn init(&self) -> Result<(), ()> {
        if crate::mmc::mmc_init(BOOT_SLOT) { Ok(()) } else { Err(()) }
    }
}

#[cfg(feature = "k1")]
impl BlockDev for Mmc {
    #[inline]
    fn geometry(&self) -> Geometry {
        Geometry { sectors: crate::mmc::mmc_capacity(BOOT_SLOT), fua: false, discard: false }
    }

    #[inline]
    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError> {
        match (req.op, req.data) {
            (BlockOp::Read, BlockData::Read(buf)) => {
                crate::mmc::mmc_read(BOOT_SLOT, req.sector, req.count, buf).map_err(|()| BlockError::Io)
            }
            (BlockOp::Write, BlockData::Write(buf)) => {
                ordered_write(req.flags, || flush_state(crate::mmc::mmc_flush(BOOT_SLOT)), || {
                    crate::mmc::mmc_write(BOOT_SLOT, req.sector, req.count, buf).map_err(|()| BlockError::Io)?;
                    // This backend has no request layer to complete the write: the write
                    // ledger is fed here (`write_observer::account`).
                    crate::write_observer::account(owner_now(), req.count as u64 * crate::queue::SECTOR as u64);
                    Ok(())
                })
            }
            // `mmc::mmc_flush`: CMD13 until the card is back in `tran` with
            // READY_FOR_DATA (error bits checked, bounded), plus CMD6
            // FLUSH_CACHE if an eMMC cache was ever enabled; `mmc.rs` never
            // enables one. `Ok` only on a confirmed card status, `Err(Io)`
            // otherwise; never `Unsupported`.
            (BlockOp::Flush, _) => flush_state(crate::mmc::mmc_flush(BOOT_SLOT)),
            (BlockOp::Discard, _) => Err(BlockError::Unsupported),
            _ => Err(BlockError::Invalid),
        }
    }

    #[inline]
    fn medium_start(&self) -> Option<u64> {
        Some(0)
    }
}

#[cfg(feature = "k1")]
type Backend = Mmc;

/// The two SD backends have no request layer and no native FUA: a write that
/// asks for the flush ahead of it (`FLAG_PREFLUSH`) is ordered by the card's
/// own status poll, a device with nothing to flush has nothing to order, a
/// flush that failed fails the write before it is made, and one that asks for
/// FUA gets the refusal `fua_commit` says it would.
#[cfg(any(feature = "vf2", feature = "k1"))]
#[inline]
fn ordered_write(
    flags: u32,
    flush: impl FnOnce() -> Result<(), BlockError>,
    write: impl FnOnce() -> Result<(), BlockError>,
) -> Result<(), BlockError> {
    if flags & FLAG_FUA != 0 {
        return Err(BlockError::Unsupported);
    }
    if flags & FLAG_PREFLUSH != 0 {
        match flush() {
            Ok(()) | Err(BlockError::Unsupported) => {}
            Err(_) => return Err(BlockError::PreFlush),
        }
    }
    write()
}

#[cfg(any(feature = "vf2", feature = "k1"))]
#[inline]
fn flush_state(r: Result<(), FlushError>) -> Result<(), BlockError> {
    r.map_err(|e| match e {
        FlushError::Unsupported => BlockError::Unsupported,
        FlushError::Io => BlockError::Io,
    })
}

/// The board's backend: zero-sized, so a fresh value per call is the device.
#[inline(always)]
fn backend() -> Backend {
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    return Queued;
    #[cfg(feature = "vf2")]
    return DwMshc;
    #[cfg(feature = "k1")]
    return Mmc;
}

// ── Public API — unchanged names/signatures, now forwarding to the board's backend ──

#[inline]
pub fn init() -> Result<(), ()> {
    backend().init()
}

#[inline]
pub fn capacity_sectors() -> u64 {
    backend().geometry().sectors
}

/// Block reads and writes that answered an error since boot, the device's
/// and injected ones alike (Kconfig CHAOS, point `disk-io`). Counted only
/// with CHAOS built in; off, nothing is counted and [`io`] is the device call.
static IO_ERRORS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// See [`IO_ERRORS`].
pub fn io_errors() -> u32 {
    IO_ERRORS.load(core::sync::atomic::Ordering::Relaxed)
}

#[cold]
fn note_io_error() {
    IO_ERRORS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// The device's answer, or an injected I/O error (point `disk-io`, before
/// the device is touched), counted in [`IO_ERRORS`] either way (CHAOS on).
#[inline(always)]
fn io(r: impl FnOnce() -> Result<(), BlockError>) -> Result<(), BlockError> {
    if !azos_chaos::ON {
        return r();
    }
    let r = if azos_chaos::fire(azos_chaos::Point::DiskIo) { Err(BlockError::Io) } else { r() };
    if r.is_err() {
        note_io_error();
    }
    r
}

azos_common::ro_hook! {
    /// The kernel's "which Domain is calling" source: its key
    /// (`azos_sched::domain::Key`), or 0 for a context that belongs to none.
    /// Unset until the kernel registers it (boot, before the first task).
    static OWNER_SRC: fn() -> u32;
}

/// Register the source of the Domain a request is made for. This crate cannot
/// name the scheduler, hence the pointer (as for [`set_rt_io_check`]).
pub fn set_owner_source(f: fn() -> u32) {
    OWNER_SRC.set(f);
}

/// The owner this layer stamps on the requests it builds for its callers: the
/// calling task's Domain, or [`OWNER_KERNEL`] where there is none (boot,
/// before the scheduler; an idle or interrupt context). The refusal of a
/// request with no owner therefore bites the direct users of the request
/// layer, which name their owner themselves; this facade never makes one.
fn owner_now() -> u32 {
    match OWNER_SRC.get() {
        None => OWNER_KERNEL,
        Some(f) => match f() {
            OWNER_NONE => OWNER_KERNEL,
            key => key,
        },
    }
}

azos_common::ro_hook! {
    /// Kconfig `RT_BLOCK_IO_CHECK`: the kernel's "a real-time task is calling"
    /// check, run at every entry into this layer. Owner rule: an RT task never
    /// does block I/O; the kernel's check panics naming the task. Unset until the
    /// kernel registers it (boot, before the first task), and never registered
    /// with the option off, where [`rt_io_check`] compiles to nothing.
    static RT_IO_CHECK: fn();
}

/// Register the check [`RT_IO_CHECK`] runs. A no-op with `RT_BLOCK_IO_CHECK` off.
pub fn set_rt_io_check(f: fn()) {
    if azos_limits::RT_BLOCK_IO_CHECK {
        RT_IO_CHECK.set(f);
    }
}

/// Run the registered check. Called by every entry below.
///
/// Also the block layer's lockdep point (Kconfig LOCKDEP, N1): a request
/// may wait for the device, so entering here with a SpinLock held, with
/// interrupts off or in an interrupt is reported (`might_sleep`), whatever
/// RT_BLOCK_IO_CHECK says. No instruction with lockdep off.
#[inline(always)]
pub fn rt_io_check() {
    azos_sync::lockdep::might_wait_device("block I/O");
    if azos_limits::RT_BLOCK_IO_CHECK {
        if let Some(f) = RT_IO_CHECK.get() {
            f();
        }
    }
}

/// The boot medium with this module's rules: the real-time check, the
/// write-back observers and the chaos point around the backend. `observed`
/// tells the block-cache owner which sectors moved and first makes it write
/// back what it holds for a range read ([`crate::write_observer`]); `quiet`
/// is for that owner itself, which updates its cache on its own and may hold
/// the cache's lock while it calls. Zero-sized: the device is the board's
/// backend.
///
#[derive(Clone, Copy)]
pub struct Boot {
    observed: bool,
}

impl Boot {
    pub const fn observed() -> Boot {
        Boot { observed: true }
    }

    pub const fn quiet() -> Boot {
        Boot { observed: false }
    }
}

impl BlockDev for Boot {
    #[inline]
    fn geometry(&self) -> Geometry {
        backend().geometry()
    }

    #[inline]
    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError> {
        rt_io_check();
        let (op, sector, count) = (req.op, req.sector, req.count);
        match op {
            BlockOp::Read => {
                if self.observed {
                    crate::write_observer::before_read(sector, count);
                }
                io(|| backend().submit(req))
            }
            BlockOp::Write => {
                let r = io(|| backend().submit(req));
                if self.observed {
                    crate::write_observer::notify(sector, count);
                }
                r
            }
            BlockOp::Flush | BlockOp::Discard => backend().submit(req),
        }
    }

    #[inline]
    fn medium_start(&self) -> Option<u64> {
        backend().medium_start()
    }
}

/// Read the medium. A block-cache owner that keeps writes back
/// ([`crate::write_observer::before_read`], FAT32 under Kconfig
/// `FS_WRITEBACK`) first writes any it holds for these sectors, so this
/// reader never sees a sector older than a write that already returned.
#[inline]
pub fn read(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    Boot::observed().submit(BlockReq { count, ..BlockReq::read(sector, buf) }).map_err(|_| ())
}

/// [`read`] without the read observer: for the cache owner itself, whose
/// reads already look in its cache first.
#[inline]
pub fn read_quiet(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    Boot::quiet().submit(BlockReq { count, ..BlockReq::read(sector, buf) }).map_err(|_| ())
}

/// For a reader of the boot medium that does not go through [`read`]
/// (the ring-3 block path, `block_io`, which reads raw sectors): call
/// before reading.
#[inline]
pub fn note_external_read(sector: u64, count: u32) {
    crate::write_observer::before_read(sector, count);
}

/// Install the observer every [`read`] calls first (the FAT32 block cache
/// in write-back mode), and `held`, which answers whether that call would have
/// something to write back for a range ([`read_would_wait`]).
#[inline]
pub fn set_read_observer(f: fn(u64, u32), held: fn(u64, u32) -> bool) {
    crate::write_observer::set_read(f, held);
}

/// Would [`note_external_read`] of the range wait for the device? For a caller
/// that may not (an io_ring submit): when this is true it leaves the read to
/// one that may, and calls [`note_external_read`] there.
#[inline]
pub fn read_would_wait(sector: u64, count: u32) -> bool {
    crate::write_observer::read_would_wait(sector, count)
}

/// Write the medium, then tell the block-cache owner which sectors moved
/// ([`crate::write_observer::notify`]), whether the write succeeded or not:
/// a failed multi-sector write may have landed in part.
#[inline]
pub fn write(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    Boot::observed().submit(BlockReq { count, ..BlockReq::write(sector, buf) }).map_err(|_| ())
}

/// [`write`] without telling the observer: for the one caller that updates
/// the block cache itself (FAT32's write-through path), which may hold the
/// cache's lock while it writes. `tests/host/fs-tests` keeps its callers to
/// `crates/fs/src/fat32.rs`.
#[inline]
pub fn write_quiet(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    Boot::quiet().submit(BlockReq { count, ..BlockReq::write(sector, buf) }).map_err(|_| ())
}

/// Write `count` sectors for the write-back cache's owner, with the ordering
/// it asks for. `preflush`: the write starts only after every write that
/// completed before this call is durable (the cache's epoch rule, folded into
/// the request so a device behind the request layer starts the data right
/// after one flush, with no round trip to the caller between). `fua`: the
/// data is on stable media when the call returns, so with `preflush` it also
/// makes every earlier write durable: a commit that needs no flush behind
/// it. A caller sets `fua` only where [`fua_commit`] says the device has one.
///
/// Like [`write_quiet`] it does not tell the write observer: the caller is the
/// cache owner. A device with nothing to flush (`FlushError::Unsupported`) has
/// nothing to order, so the write goes; a flush that failed fails the call and
/// the write is not made.
#[inline]
pub fn write_run(sector: u64, count: u32, buf: &[u8], preflush: bool, fua: bool) -> Result<(), ()> {
    let flags = if preflush { FLAG_PREFLUSH } else { 0 } | if fua { FLAG_FUA } else { 0 };
    Boot::quiet().submit(BlockReq { count, ..BlockReq::write(sector, buf) }.with_flags(flags)).map_err(|_| ())
}

/// Does a [`write_run`] with `fua` commit natively (Kconfig `BLK_FUA`, and a
/// device behind the request layer whose Force Unit Access is a bit of its
/// write command)? Where it does not, durability is the explicit
/// [`flush`] that follows the writes.
#[inline]
pub fn fua_commit() -> bool {
    azos_limits::BLK_FUA && backend().geometry().fua
}

/// Discard is compiled in (Kconfig `BLK_DISCARD` is not `off`).
pub const DISCARD: bool = !azos_limits::BLK_DISCARD_OFF;

/// Why [`discard`] did not discard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscardError {
    /// No device behind the request layer, or one without the command: the
    /// caller stops asking.
    Unsupported,
    /// The device failed the command.
    Io,
}

/// Tell the device that the sectors of `runs` (`(first sector, sectors)`)
/// hold nothing worth keeping (Kconfig `BLK_DISCARD`: `online` discards one
/// request at a time, `batched` keeps the whole batch in the device at once).
/// A hint: the device may keep the data, and a read of a discarded sector
/// answers whatever it chooses. The caller owns the sectors and does not
/// reuse them until this returns. Every request is waited for.
///
/// Does not tell the write observer: it moves no bytes the cache owner holds.
pub fn discard(runs: &[(u64, u32)]) -> Result<(), DiscardError> {
    if !DISCARD || runs.is_empty() {
        return Ok(());
    }
    match Boot::quiet().submit(BlockReq::discard(runs)) {
        Ok(()) => Ok(()),
        Err(BlockError::Unsupported) => Err(DiscardError::Unsupported),
        Err(_) => Err(DiscardError::Io),
    }
}

/// For a writer of the boot medium that does not go through [`write`]
/// (the ring-3 block path, `block_io`, which writes raw sectors): report the
/// sectors after the device answered.
#[inline]
pub fn note_external_write(sector: u64, count: u32) {
    crate::write_observer::notify(sector, count);
}

/// Install the observer every [`write`] reports to (the FAT32 block cache).
#[inline]
pub fn set_write_observer(f: fn(u64, u32)) {
    crate::write_observer::set(f);
}

/// The device's read, with none of [`read`]'s layers: no chaos point, no
/// real-time check, no write-back observer. For the ring-3 disk syscalls,
/// which do those themselves (`note_external_read`) and used to call
/// `virtio::blk` directly, which is the wrong device on a board whose block
/// device is not virtio-blk (an NVMe boot disk, the VF2's SD card).
#[inline]
pub fn read_raw(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    backend().submit(BlockReq { count, ..BlockReq::read(sector, buf) }).map_err(|_| ())
}

/// See [`read_raw`]; the write twin (`note_external_write` reports it).
#[inline]
pub fn write_raw(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    backend().submit(BlockReq { count, ..BlockReq::write(sector, buf) }).map_err(|_| ())
}

// ── Queued raw transfers (the io_ring block entries) ──────────────────────

/// A raw transfer [`submit_raw`] queued: [`wait_raw`] takes it, and its slot of
/// the request layer is held until then.
#[derive(Clone, Copy, Debug)]
pub struct RawTicket(crate::queue::Ticket);

/// Sectors one [`submit_raw`] request carries at most; `None` when the boot
/// disk is not behind the request layer (an SD/eMMC board), where a raw
/// transfer is [`read_raw`] / [`write_raw`] and waits.
#[inline]
pub fn raw_max_sectors() -> Option<u32> {
    crate::queue::bound().map(|hw| hw.caps().max_sectors)
}

/// Queue a raw read (`write` false) or write of `count` sectors at the absolute
/// `sector` for the Domain `owner` (`azos_devif::block::OWNER_KERNEL` for the
/// kernel's own), and return at once: no device register is touched and no
/// task sleeps. [`wait_raw`] starts it (and everything else queued) and collects it. `Err` when
/// the request layer cannot take it now (no queue bound, the hart's queue is
/// full, more sectors than one command): the caller falls back to
/// [`read_raw`] / [`write_raw`].
///
/// # Safety
///
/// `buf` is `count * 512` bytes that stay valid, and for a read untouched,
/// until [`wait_raw`] returns for the ticket. The device never sees it: the
/// queue copies through the device's own staging memory.
#[inline]
pub unsafe fn submit_raw(owner: u32, write: bool, sector: u64, count: u32, buf: *mut u8) -> Result<RawTicket, ()> {
    let hw = crate::queue::bound().ok_or(())?;
    crate::queue::enqueue(hw, owner, write, sector, count, buf).map(RawTicket).map_err(|_| ())
}

/// Collect `t`, running the device meanwhile and sleeping until the request is
/// over; frees its slot. `Err` when the device failed it (a CHAOS `disk-io`
/// point counts here as it does for [`read_raw`]).
pub fn wait_raw(t: RawTicket) -> Result<(), ()> {
    rt_io_check();
    let Some(hw) = crate::queue::bound() else { return Err(()) };
    io(|| match crate::queue::wait(hw, t.0) {
        crate::queue::Outcome::Ok => Ok(()),
        _ => Err(BlockError::Io),
    })
    .map_err(|_| ())
}

/// Make every write that completed so far durable ([`BlockDev::flush`]).
#[inline]
pub fn flush() -> Result<(), FlushError> {
    Boot::quiet().flush().map_err(FlushError::from)
}

/// Orderly power-off or reboot (`azos_syscall::handlers`, after every
/// filesystem was synced): flush the boot disk once more, so a write that
/// went around the filesystems (the reserved tail, a raw partition) is
/// durable too, then tell its controller to shut down where it has a
/// shutdown of its own (NVMe `CC.SHN`). One `[ORDERLY] disk:` line says what
/// each answered. Bounded: the flush by the backend's command budget, the
/// shutdown wait by Kconfig `POWER_OFF_STEP_TIMEOUT_MS` (or the controller's
/// RTD3E); the power-off goes on whatever they answered.
pub fn shutdown() {
    let flush = match flush() {
        Ok(()) => "ok",
        Err(FlushError::Unsupported) => "unsupported (no cache control)",
        Err(FlushError::Io) => "FAILED",
    };
    #[cfg(feature = "nvme")]
    let ctl = match crate::nvme::shutdown(azos_limits::POWER_OFF_STEP_TIMEOUT_MS as u64) {
        None => "none",
        Some(true) => "nvme complete",
        Some(false) => "nvme NOT confirmed",
    };
    #[cfg(not(feature = "nvme"))]
    let ctl = "none";
    azos_drv_sys::kprintln!("[ORDERLY] disk: flush {}, controller shutdown {}", flush, ctl);
}
