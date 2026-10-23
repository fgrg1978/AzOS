// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block device an azvol volume sits on.
//!
//! The unit is the azvol block (4096 bytes), not the device sector: the
//! kernel adapter turns one block into eight 512-byte sectors (or one 4 KiB
//! page) and batches a multi-block call into one queue submission. Every
//! call that can move more than one block does, so the format layer never
//! asks the device for more round trips than it has runs.

/// A device-level failure (I/O error, range error). The volume maps it to
/// [`super::Error::Io`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevError;

pub trait BlockDev {
    /// Size of the device in azvol blocks.
    fn block_count(&self) -> u64;

    /// Read `buf.len() / BLOCK_SIZE` consecutive blocks starting at `first`.
    /// `buf.len()` is a non-zero multiple of the block size.
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError>;

    /// Write `buf.len() / BLOCK_SIZE` consecutive blocks starting at `first`.
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError>;

    /// Barrier: everything written before this call is durable before
    /// anything written after it. The commit protocol's whole ordering
    /// argument rests on this one call.
    fn flush(&mut self) -> Result<(), DevError>;

    /// The medium sector where block `block` starts, when the blocks are a
    /// plain window onto the medium (a partition): the bytes the volume writes
    /// are the bytes on the sectors, nothing between. A wrapper that
    /// transforms them (the verity tree) says `None`. Only the swap file uses
    /// it: it writes the file's blocks by sector.
    fn raw_sector(&self, _block: u64) -> Option<u64> {
        None
    }

    /// Tell the device that the blocks of `runs` (`(first block, blocks)`)
    /// hold nothing worth keeping (TRIM; a hint, Kconfig `BLK_DISCARD`). The
    /// volume asks only for blocks no tree on the medium names any more,
    /// after the superblock that stopped naming them is durable and before
    /// any of them can be allocated again, and it ignores the answer. A
    /// wrapper that transforms the blocks (the verity tree) keeps this
    /// default: nothing is discarded.
    fn discard(&mut self, _runs: &[(u64, u32)]) -> Result<(), DevError> {
        Ok(())
    }
}
