// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block device an azvol volume sits on: any
//! [`BlockDev`](azos_drv_api::block::BlockDev), addressed in azvol blocks.
//!
//! The unit is the azvol block (4096 bytes), eight 512-byte sectors; [`Blocks`]
//! is the thin helper that turns a block run into one request. A multi-block
//! call is one request, so the format layer never asks the device for more
//! round trips than it has runs.

pub use azos_drv_api::block::{BlockDev, BlockError};
use azos_drv_api::block::BlockReq;

use alloc::vec::Vec;

/// Bytes per azvol block.
const BLOCK: usize = super::layout::BLOCK_SIZE;
/// Sectors per azvol block.
const SECTORS: u64 = (BLOCK / azos_drv_api::block::SECTOR) as u64;

/// A device-level failure (I/O error, range error). The volume maps it to
/// [`super::Error::Io`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevError;

impl From<BlockError> for DevError {
    fn from(_: BlockError) -> DevError {
        DevError
    }
}

pub trait Blocks: BlockDev {
    /// Size of the device in azvol blocks (a trailing partial block is not used).
    fn block_count(&self) -> u64 {
        self.geometry().sectors / SECTORS
    }

    /// Read `buf.len() / BLOCK_SIZE` consecutive blocks starting at `first`.
    /// `buf.len()` is a non-zero multiple of the block size.
    fn read_blocks(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let sector = first.checked_mul(SECTORS).ok_or(DevError)?;
        Ok(self.submit(BlockReq::read(sector, buf))?)
    }

    /// Write `buf.len() / BLOCK_SIZE` consecutive blocks starting at `first`.
    fn write_blocks(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        let sector = first.checked_mul(SECTORS).ok_or(DevError)?;
        Ok(self.submit(BlockReq::write(sector, buf))?)
    }

    /// Barrier: everything written before this call is durable before
    /// anything written after it. The commit protocol's whole ordering
    /// argument rests on this one call: a request that is a flush, never a
    /// write that is only FUA. A device that cannot confirm it fails (the
    /// volume fails closed).
    fn barrier(&mut self) -> Result<(), DevError> {
        Ok(self.flush()?)
    }

    /// The medium sector where block `block` starts, when the blocks are a
    /// plain window onto the medium (a partition): the bytes the volume writes
    /// are the bytes on the sectors, nothing between. A wrapper that
    /// transforms them (the verity tree) says `None`. Only the swap file uses
    /// it: it writes the file's blocks by sector.
    fn raw_sector(&self, block: u64) -> Option<u64> {
        if block >= self.block_count() {
            return None;
        }
        Some(self.medium_start()? + block * SECTORS)
    }

    /// Tell the device that the blocks of `runs` (`(first block, blocks)`)
    /// hold nothing worth keeping (TRIM; a hint, Kconfig `BLK_DISCARD`). The
    /// volume asks only for blocks no tree on the medium names any more,
    /// after the superblock that stopped naming them is durable and before
    /// any of them can be allocated again, and it ignores the answer.
    fn discard_blocks(&mut self, runs: &[(u64, u32)]) -> Result<(), DevError> {
        let mut sectors = Vec::with_capacity(runs.len());
        for &(first, n) in runs {
            let n = u32::try_from(n as u64 * SECTORS).map_err(|_| DevError)?;
            sectors.push((first.checked_mul(SECTORS).ok_or(DevError)?, n));
        }
        Ok(self.discard(&sectors)?)
    }
}

impl<T: BlockDev + ?Sized> Blocks for T {}
