// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Chunk accumulator — pure (no I/O) helper for buffering DFU
//! DNLOAD payload chunks into a caller-owned staging buffer.
//!
//! The DFU state machine in [`crate::state`] only tracks byte
//! counts; the actual bytes need to land somewhere the kernel can
//! later flush to disk. This helper does that, validating each
//! chunk against the transfer-size negotiated in the functional
//! descriptor and the staging buffer's capacity.
//!
//! Kept here (not in the kernel module) so it is host-testable
//! from `tests/host/dfu-tests`.

#![allow(dead_code)]

/// Error variants from [`ChunkAccumulator::push`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccumulatorError {
    /// Single chunk exceeded the negotiated `wTransferSize`.
    ChunkTooLarge,
    /// Cumulative bytes would exceed the staging buffer capacity.
    Overflow,
}

/// Buffers incoming DNLOAD chunks into a caller-owned slice.
///
/// The accumulator owns no memory itself — the staging slice is
/// passed in for each [`Self::push`] call. This matches the kernel
/// pattern where the staging buffer is a `static mut [u8; N]` and
/// the accumulator lives next to it as a `static` counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkAccumulator {
    /// Bytes already written into the staging buffer.
    pub bytes_written: usize,
    /// Max chunk size from the DFU functional descriptor.
    pub transfer_size: u16,
}

impl ChunkAccumulator {
    /// New empty accumulator with the given transfer size.
    #[must_use]
    pub const fn new(transfer_size: u16) -> Self {
        Self { bytes_written: 0, transfer_size }
    }

    /// Reset to empty (e.g. on DFU_ABORT or CLR_STATUS).
    pub fn reset(&mut self) {
        self.bytes_written = 0;
    }

    /// Append `chunk` to `staging`. Returns the new total on success.
    pub fn push(
        &mut self,
        chunk: &[u8],
        staging: &mut [u8],
    ) -> Result<usize, AccumulatorError> {
        if chunk.len() > self.transfer_size as usize {
            return Err(AccumulatorError::ChunkTooLarge);
        }
        let end = self.bytes_written
            .checked_add(chunk.len())
            .ok_or(AccumulatorError::Overflow)?;
        if end > staging.len() {
            return Err(AccumulatorError::Overflow);
        }
        staging[self.bytes_written..end].copy_from_slice(chunk);
        self.bytes_written = end;
        Ok(self.bytes_written)
    }
}
