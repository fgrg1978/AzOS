// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Block device abstraction — Phase A/B (VF2 + K1 boot).
//!
//! Routes sector I/O to the appropriate backend:
//! - QEMU (`default`):        VirtIO block device.
//! - VisionFive 2 (`vf2`):   MMC slot 1 — microSD, `MMC1_BASE` = 0x1602_0000.
//! - SpacemiT K1  (`k1`):    MMC slot 0 — SD socket (0xD428_0000).
//!
//! The FAT32 layer and kernel boot use this module exclusively so that
//! no storage-related code needs to be gated on platform features outside
//! this file.
//!
//! NOTE (2026-09-18): the address above was previously written as
//! `0x1603_0000` in this file's docs, which is actually `ETH0_BASE` (a
//! stale copy-paste, not a logic bug — the code below always used the
//! correctly named `MMC1_BASE` constant). See `platform.rs` and `mmc.rs`
//! for the more important open finding: real JH7110 SDIO silicon is a
//! DesignWare MSHC (`snps,dw-mshc`), not the SDHCI-v3 IP `mmc.rs` currently
//! models — `mmc.rs`'s module doc has the details and the source citation.
//!
//! ── `BlockDevice` trait (2026-09-23) ─────────────────────────────────────
//!
//! Previously this module was four free functions, each forked in two by
//! `#[cfg(vf2/k1)]` vs `#[cfg(not(vf2/k1))]` — a per-function `if/else` at
//! the source level rather than a value. That made the two backends
//! (VirtIO-blk, SDHCI-modeled MMC) harder to tell apart at a glance and gave
//! no seam a third backend (e.g. a ring-3 forwarder, RFC-0040 gap P) could
//! plug into without adding a third `#[cfg]` arm to every function.
//!
//! Now there is one [`BlockDevice`] trait, one zero-sized implementation per
//! backend, and a single `BACKEND` static selected once at bring-up (still
//! by `#[cfg]` — each board is its own kernel binary, so the "selection" is
//! at compile time, not a runtime branch). The four public functions below
//! are unchanged in name, signature and behaviour; they now forward to
//! `BACKEND` instead of directly to `virtio::blk`/`mmc`. A fifth, `flush`,
//! was added with the trait method of the same name; it has no free-function
//! predecessor.
//!
//! **Kept deliberately close to the old free-function surface, not
//! redesigned toward gap P.** `Result<(), ()>` and borrowed `&[u8]`/`&mut
//! [u8]` buffers are exactly what FAT32 already called through. A ring-3
//! forwarder implementing this trait would still need, beyond what is here:
//!   - **Typed errors.** `Result<(), ()>` cannot tell a caller "device not
//!     ready" from "sector out of range" from "read to a ring-3 IPC peer
//!     timed out" — a forwarder would have to fold all of those into `Err`,
//!     losing exactly the distinction FAT32's own callers (e.g. journal
//!     recovery) might need to react differently to a transient IPC failure
//!     versus a real disk error.
//!   - **Fixed-size buffers.** `&mut [u8]` of caller-chosen length crosses
//!     an in-process function call for free; crossing a ring-3 IPC boundary
//!     it does not — a forwarder needs a bounded, fixed-size message buffer
//!     (mirroring the DMA staging area `virtio::blk` already keeps for the
//!     same reason: the device must never be handed a pointer into caller
//!     memory) and would have to chunk any request larger than that buffer
//!     itself, the way `virtio::blk::read`/`write` already chunk against
//!     `BLK_DMA_SECTORS`.
//!   - **A bounded-wait guarantee in the trait signature, not just in one
//!     implementation.** `virtio::blk` already bounds its wait with a
//!     500 ms wall-clock deadline (see that file), but the trait itself
//!     promises nothing: a future implementation could block on an
//!     unbounded IPC `recv()`. A ring-3 forwarder's `read`/`write` would
//!     need the same wall-clock discipline, and ideally the trait would say
//!     so instead of leaving it to each `impl` to remember.

use azos_drv_api::block::{BlockDevice, FlushError};

// ── QEMU / VirtIO backend ─────────────────────────────────────────────────────

/// VirtIO-blk backend (QEMU / `default`). Zero-sized: all state lives in
/// `virtio::blk`'s own statics, exactly as before this trait existed.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub struct VirtioBlk;

#[cfg(not(any(feature = "vf2", feature = "k1")))]
impl BlockDevice for VirtioBlk {
    #[inline]
    fn init(&self) -> Result<(), ()> {
        azos_drv_virtio::virtio::blk::init()
    }

    #[inline]
    fn capacity_sectors(&self) -> u64 {
        azos_drv_virtio::virtio::blk::capacity_sectors()
    }

    #[inline]
    fn read(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        azos_drv_virtio::virtio::blk::read(sector, count, buf)
    }

    #[inline]
    fn write(&self, sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        azos_drv_virtio::virtio::blk::write(sector, count, buf)
    }

    #[inline]
    fn flush(&self) -> Result<(), FlushError> {
        azos_drv_virtio::virtio::blk::flush()
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
static BACKEND: VirtioBlk = VirtioBlk;

// ── Real-hardware MMC backend (VisionFive 2 + SpacemiT K1) ───────────────────
//
// `mmc.rs` models an SDHCI-v3 register set for both boards; only the boot
// slot differs here:
//   VF2: microSD = SDIO1 (MmcSlot::Sd  = MMC1_BASE 0x1602_0000)
//   K1:  SD card = SDHCI0 (MmcSlot::Emmc = MMC0_BASE 0xD428_0000)
//        (K1 naming: "Emmc" slot 0 physically wires to the removable SD socket)
// VF2's real SDIO1 IP is NOT SDHCI (see `mmc.rs` module doc) — K1's has not
// been re-checked in this pass.

/// Boot storage slot: microSD on VF2, SD card socket on K1.
#[cfg(feature = "vf2")]
const BOOT_SLOT: crate::mmc::MmcSlot = crate::mmc::MmcSlot::Sd;
#[cfg(feature = "k1")]
const BOOT_SLOT: crate::mmc::MmcSlot = crate::mmc::MmcSlot::Emmc;

/// SDHCI-modeled MMC backend (VF2 / K1). Zero-sized: state lives in
/// `mmc::SLOT_STATE`, keyed by `BOOT_SLOT`, exactly as before this trait
/// existed.
#[cfg(any(feature = "vf2", feature = "k1"))]
pub struct Mmc;

#[cfg(any(feature = "vf2", feature = "k1"))]
impl BlockDevice for Mmc {
    #[inline]
    fn init(&self) -> Result<(), ()> {
        if crate::mmc::mmc_init(BOOT_SLOT) { Ok(()) } else { Err(()) }
    }

    #[inline]
    fn capacity_sectors(&self) -> u64 {
        crate::mmc::mmc_capacity(BOOT_SLOT)
    }

    #[inline]
    fn read(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        crate::mmc::mmc_read(BOOT_SLOT, sector, count, buf)
    }

    #[inline]
    fn write(&self, sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        crate::mmc::mmc_write(BOOT_SLOT, sector, count, buf)
    }

    /// `mmc::mmc_flush`: CMD13 until the card is back in `tran` with
    /// READY_FOR_DATA (error bits checked, bounded), plus CMD6 FLUSH_CACHE
    /// if an eMMC cache was ever enabled — `mmc.rs` never enables one. `Ok`
    /// only on a confirmed card status, `Err(Io)` otherwise; never
    /// `Unsupported` any more. Run only against QEMU's `sdhci-pci` model
    /// (`mmc-pci`); on the VF2 this file still models the wrong controller
    /// IP (see `mmc.rs`), so a VF2 flush answers `Io` until that is fixed,
    /// because nothing before it can succeed either.
    #[inline]
    fn flush(&self) -> Result<(), FlushError> {
        crate::mmc::mmc_flush(BOOT_SLOT)
    }
}

#[cfg(any(feature = "vf2", feature = "k1"))]
static BACKEND: Mmc = Mmc;

// ── Public API — unchanged names/signatures, now forwarding to `BACKEND` ────

#[inline]
pub fn init() -> Result<(), ()> {
    BACKEND.init()
}

#[inline]
pub fn capacity_sectors() -> u64 {
    BACKEND.capacity_sectors()
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
fn io(r: impl FnOnce() -> Result<(), ()>) -> Result<(), ()> {
    if !azos_chaos::ON {
        return r();
    }
    let r = if azos_chaos::fire(azos_chaos::Point::DiskIo) { Err(()) } else { r() };
    if r.is_err() {
        note_io_error();
    }
    r
}

/// Kconfig `RT_BLOCK_IO_CHECK`: the kernel's "a real-time task is calling"
/// check, run at every entry into this layer. Owner rule: an RT task never
/// does block I/O; the kernel's check panics naming the task. `0` until the
/// kernel registers it (boot, before the first task), and never registered
/// with the option off, where [`rt_io_check`] compiles to nothing.
static RT_IO_CHECK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Register the check [`RT_IO_CHECK`] runs. A no-op with `RT_BLOCK_IO_CHECK` off.
pub fn set_rt_io_check(f: fn()) {
    if azos_limits::RT_BLOCK_IO_CHECK {
        RT_IO_CHECK.store(f as usize, core::sync::atomic::Ordering::Release);
    }
}

/// Run the registered check. Called by every entry below, and by the one
/// path to the device that does not come through here (ring-3
/// `SYS_DISK_READ`/`SYS_DISK_WRITE`, which call `virtio::blk` directly).
#[inline(always)]
pub fn rt_io_check() {
    if azos_limits::RT_BLOCK_IO_CHECK {
        let f = RT_IO_CHECK.load(core::sync::atomic::Ordering::Acquire);
        if f != 0 {
            // SAFETY: only `set_rt_io_check` stores here, and it stores a `fn()`.
            let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(f) };
            f();
        }
    }
}

#[inline]
pub fn read(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    rt_io_check();
    io(|| BACKEND.read(sector, count, buf))
}

/// Write the medium, then tell the block-cache owner which sectors moved
/// ([`crate::write_observer::notify`]), whether the write succeeded or not:
/// a failed multi-sector write may have landed in part.
#[inline]
pub fn write(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    rt_io_check();
    let r = io(|| BACKEND.write(sector, count, buf));
    crate::write_observer::notify(sector, count);
    r
}

/// [`write`] without telling the observer: for the one caller that updates
/// the block cache itself (FAT32's write-through path), which may hold the
/// cache's lock while it writes. `tests/host/fs-tests` keeps its callers to
/// `crates/fs/fs/src/fat32.rs`.
#[inline]
pub fn write_quiet(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    rt_io_check();
    io(|| BACKEND.write(sector, count, buf))
}

/// For a writer of the boot medium that does not go through [`write`]
/// (ring-3 `SYS_DISK_WRITE`, which calls `virtio::blk` directly): report the
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

/// See [`BlockDevice::flush`].
#[inline]
pub fn flush() -> Result<(), FlushError> {
    rt_io_check();
    BACKEND.flush()
}
