// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block device class: what every block backend implements.

/// Backend-agnostic block device operations, selected once at bring-up (see
/// `azos_drv_block::blkdev`). One implementation per board: `VirtioBlk` on QEMU,
/// `Mmc` on VF2/K1.
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
