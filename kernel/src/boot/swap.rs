// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Swap after compression (Kconfig `MM_SWAP_BACKEND`): the boot step.
//!
//! Runs once, before any task exists, on every ISA (`kernel_main` is one),
//! and draws the boot secret the swap keys come from out of the entropy pool,
//! then attaches the area to the compressed-page pool (`azos_mm::pager`). The
//! pool and the loops are `crates/core/mm/src/{zpool,swap}.rs`. Two areas, one
//! of which the Kconfig choice picks:
//!
//! * `MM_SWAP_BACKEND_PARTITION`: [`install_swap`], right after the partition
//!   table is published (before any filesystem is mounted), takes the swap
//!   partition for the kernel (`partition::claim_swap`; from then on no
//!   capability names it). Fixed size.
//! * `MM_SWAP_BACKEND_FILE`: [`install_swap_file`], right after the mounts,
//!   makes `MM_SWAP_FILE_PATH` (on FAT32 or azvol) the swap file. The VFS
//!   pins it (nothing else opens, truncates, renames or removes it), starts
//!   it empty and resizes it by whole segments: the storm grows it when no
//!   slot is free, the reclaim task gives the unused tail back
//!   (`pager::swap_trim`). The filesystem hands over the sector runs under the
//!   file once per resize and every request below is cut along them, so a
//!   segment never goes through the filesystem. FAT32 files end below 4 GiB
//!   and are never sparse (a grow writes the zeros); azvol's copy on write is
//!   why the blocks are fixed first and written only directly afterwards.
//!
//! The device is the block layer's queue: every segment is one request
//! through `blkdev::{write,read}_quiet` (the layer splits it to the
//! controller's DMA size and takes its own queue and real-time check). The
//! quiet variants because the partition belongs to no filesystem, and no
//! path reads or writes the file's sectors through the filesystem's cache (the
//! grow flushed its zeros; clean copies may stay cached and go stale, which
//! nothing can observe while the file is pinned).
//!
//! One `Rule::SwapOut` decision per eviction storm, written here (the loop
//! calls [`record`] when a storm ends): `[segments, live bytes, bytes
//! written]`, subject 0 (the system), `Admit` when a segment went out and
//! `Refuse` when the storm wrote none.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_decision::{Rule, Verdict};
use azos_drv_sys::kwarn;
use azos_mm::swap::{Policy, Run, RunMap, SwapDev, SwapRecord, SECTOR};
use azos_sync::SpinLock;

use crate::kprintln;

/// First sector of the swap partition on the medium.
static AREA_START: AtomicU64 = AtomicU64::new(0);

/// The swap area on the block layer's queue.
struct BlockQueue;

impl SwapDev for BlockQueue {
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), ()> {
        azos_drv_block::blkdev::write_quiet(AREA_START.load(Ordering::Relaxed) + sector, (buf.len() / SECTOR) as u32, buf)
    }

    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), ()> {
        azos_drv_block::blkdev::read_quiet(AREA_START.load(Ordering::Relaxed) + sector, (buf.len() / SECTOR) as u32, buf)
    }

    /// Kconfig `BLK_DISCARD`: a device behind the request layer takes it, any
    /// other (SD/eMMC) has none and the segment is simply overwritten later.
    fn discard(&self, sector: u64, sectors: u32) -> Result<(), ()> {
        azos_drv_block::blkdev::discard(&[(AREA_START.load(Ordering::Relaxed) + sector, sectors)]).map_err(|_| ())
    }
}

static DEV: BlockQueue = BlockQueue;

/// A Domain on a `mem = "locked"` row is pinned: none of its pages is ever in
/// a segment that is written out. Called under the pool's lock; takes none.
fn pinned(owner: usize) -> bool {
    azos_sched::domain::slot_mem_locked(owner)
}

fn record(r: &SwapRecord) {
    let verdict = if r.refused() { Verdict::Refuse } else { Verdict::Admit };
    azos_decision::record(Rule::SwapOut, verdict, 0, r.fields());
}

fn tamper(slot: usize) {
    kwarn!("[SWAP] slot {} failed its tag: changed, moved or replayed on the medium; its pages are lost to the tasks that touch them", slot);
}

/// The boot secret the swap keys come from, or `None` while the entropy pool
/// is unseeded (no key, so nothing may be written).
fn boot_key() -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    // The entropy pool's own lock does not keep preemption off (its crate
    // cannot use `azos_sync`), so the caller does.
    let seeded = {
        let _cs = azos_sync::critical_section();
        azos_crypto::entropy::fill(&mut key)
    };
    if seeded {
        Some(key)
    } else {
        kprintln!("[SWAP] entropy pool not seeded: swap stays off");
        None
    }
}

/// Take the swap partition and turn swap on. A no-op unless the backend is
/// the partition; without a swap partition, or while the entropy pool is
/// unseeded, swap stays off for the boot.
pub(crate) fn install_swap() {
    if !azos_limits::MM_SWAP_BACKEND_PARTITION {
        return;
    }
    let Some((start, sectors)) = azos_drv_block::partition::claim_swap() else {
        kprintln!("[SWAP] no swap partition");
        return;
    };
    let Some(mut key) = boot_key() else { return };
    AREA_START.store(start, Ordering::Relaxed);
    let slots = azos_mm::pager::swap_attach(&DEV, sectors, &key, Policy { pinned, record, tamper });
    azos_crypto::ct::secure_zero(&mut key);
    kprintln!("[SWAP] partition LBA {} + {}: {} segment slots, encrypted", start, sectors, slots);
}

/// Bytes of one pool segment, the unit the file grows by.
const SEGMENT: usize = azos_mm::zpool::SEGMENT_BYTES;

/// Runs the swap file may be scattered in (Kconfig `MM_SWAP_FILE_RUNS`; none
/// without the file backend, so the table below is not in the image).
const RUNS: usize = if azos_limits::MM_SWAP_BACKEND_FILE { azos_limits::MM_SWAP_FILE_RUNS } else { 0 };

const _: () = assert!(
    !azos_limits::MM_SWAP_BACKEND_FILE || azos_mm::swap::GROW_SLOTS <= azos_mm::zpool::SWAP_SEGMENTS,
    "MM_SWAP_FILE_GROW_SEGMENTS is more than MM_SWAP_SEGMENTS: the file starts longer than it can be used"
);

/// Where the swap file's sectors are on the medium (rebuilt at each resize),
/// behind a leaf lock held for a lookup only.
static FILE_RUNS: SpinLock<RunMap<RUNS>> = SpinLock::new(RunMap::new());

/// The swap file as the swap layer's device.
struct FileArea;

impl FileArea {
    /// Run `f(medium sector, sectors, sectors already done)` over the pieces
    /// of the `count` sectors that start at area sector `sector`, each piece
    /// inside one run of the file. The lock is dropped before `f` waits.
    fn each(sector: u64, count: u32, mut f: impl FnMut(u64, u32, u32) -> Result<(), ()>) -> Result<(), ()> {
        let mut done = 0u32;
        while done < count {
            let piece = FILE_RUNS.lock().piece(sector + done as u64, count - done).ok_or(())?;
            f(piece.lba, piece.sectors, done)?;
            done += piece.sectors;
        }
        Ok(())
    }
}

impl SwapDev for FileArea {
    fn write(&self, sector: u64, buf: &[u8]) -> Result<(), ()> {
        Self::each(sector, (buf.len() / SECTOR) as u32, |lba, n, done| {
            let at = done as usize * SECTOR;
            azos_drv_block::blkdev::write_quiet(lba, n, &buf[at..at + n as usize * SECTOR])
        })
    }

    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<(), ()> {
        Self::each(sector, (buf.len() / SECTOR) as u32, |lba, n, done| {
            let at = done as usize * SECTOR;
            azos_drv_block::blkdev::read_quiet(lba, n, &mut buf[at..at + n as usize * SECTOR])
        })
    }

    fn discard(&self, sector: u64, sectors: u32) -> Result<(), ()> {
        Self::each(sector, sectors, |lba, n, _| azos_drv_block::blkdev::discard(&[(lba, n)]).map_err(|_| ()))
    }

    fn resizable(&self) -> bool {
        true
    }

    /// Make the file `sectors` long and have the map follow. A grow whose
    /// file the filesystem cannot describe in `MM_SWAP_FILE_RUNS` runs (too
    /// fragmented) is undone: the file goes back to the length the map covers.
    /// The map is the only thing that names the file's sectors, so it is
    /// replaced whole, after the file changed.
    fn resize(&self, sectors: u64) -> Result<(), ()> {
        let before = FILE_RUNS.lock().sectors();
        let len = sectors * SECTOR as u64;
        if azos_fs::vfs_swapfile_resize(len).is_err() {
            // A grow that ran out of room part way leaves the blocks it got;
            // they go back, so a refused step does not hold the volume.
            if sectors > before {
                let _ = azos_fs::vfs_swapfile_resize(before * SECTOR as u64);
            }
            return Err(());
        }
        let mut found = [azos_fs::SectorRun::default(); RUNS];
        let loaded = azos_fs::vfs_swapfile_runs(len, &mut found).ok().and_then(|n| {
            let runs = found[..n].iter().map(|f| Run { lba: f.lba, sectors: f.sectors });
            FILE_RUNS.lock().set_iter(runs).then_some(())
        });
        if loaded.is_none() {
            // A grow the map cannot follow is undone. A shrink needs no
            // undoing: the slots of the tail are gone already (the pool's
            // count went down first), so the stale map is never asked for them.
            if sectors > before {
                let _ = azos_fs::vfs_swapfile_resize(before * SECTOR as u64);
            }
            return Err(());
        }
        Ok(())
    }
}

static FILE_DEV: FileArea = FileArea;

/// Make `MM_SWAP_FILE_PATH` the swap file and turn swap on. A no-op unless
/// the backend is the file. Call after the filesystems are mounted and before
/// the first task. Swap stays off for the boot when the entropy pool is
/// unseeded, the file cannot be made, or the filesystem cannot name its
/// sectors (tmpfs, a verity-wrapped azvol volume); the file, once made, stays
/// pinned and empty.
pub(crate) fn install_swap_file() {
    if !azos_limits::MM_SWAP_BACKEND_FILE {
        return;
    }
    let path = azos_limits::MM_SWAP_FILE_PATH.as_bytes();
    let Some(mut key) = boot_key() else { return };
    if let Err(e) = azos_fs::vfs_swapfile_open(path) {
        kprintln!("[SWAP] swap file {}: {:?}: swap stays off", azos_limits::MM_SWAP_FILE_PATH, e);
        azos_crypto::ct::secure_zero(&mut key);
        return;
    }
    let first = (azos_mm::swap::GROW_SLOTS * SEGMENT / SECTOR) as u64;
    let slots = if FILE_DEV.resize(first).is_ok() {
        azos_mm::pager::swap_attach(&FILE_DEV, first, &key, Policy { pinned, record, tamper })
    } else {
        0
    };
    azos_crypto::ct::secure_zero(&mut key);
    if slots == 0 {
        kprintln!("[SWAP] swap file {}: no room for its first {} segments: swap stays off", azos_limits::MM_SWAP_FILE_PATH, azos_mm::swap::GROW_SLOTS);
    } else {
        kprintln!("[SWAP] file {}: {} segment slots to start, grows and shrinks by {}, encrypted", azos_limits::MM_SWAP_FILE_PATH, slots, azos_mm::swap::GROW_SLOTS);
    }
}
