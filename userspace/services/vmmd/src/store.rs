// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A disk over a file that can only be read and written in order.
//!
//! A `Cap<File>` has a position and no seek (the typed seek call is retired),
//! so a guest's random sector access is made by moving the position: forward
//! by reading and discarding, backward by reopening the file at its start.
//! That is correct and slow for a guest that jumps about; a file that can be
//! addressed (a mapping, a positional read) replaces [`SeqFile`] and nothing
//! above it changes.
//!
//! # Work budget
//!
//! Moving the position costs one 4 KiB call per 4 KiB skipped, so a jump deep
//! into the image is long work, and vmmd serves every trap, the console and
//! the NIC from one loop. The store therefore works on a budget
//! ([`WORK_BYTES`], renewed by [`BlockStore::refill`] at each call of the
//! device): when it runs out the call answers [`IoError::Again`] with the
//! position kept where the work got to, and the same call made again goes on
//! from there. A guest's seek is paid for over as many passes as it needs,
//! and nothing else waits for more than one budget.

use crate::blk::{BlockStore, IoError, SECTOR};

/// Bytes skipped per read when moving forward.
const SKIP: usize = 4096;
/// Bytes of file work (skipped or transferred) one renewal allows: 16 calls.
pub const WORK_BYTES: usize = 16 * SKIP;

/// A file as the typed calls give it.
pub trait SeqFile {
    /// Read at the position; 0 at the end of the file.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError>;
    /// Write at the position; the count written.
    fn write(&mut self, data: &[u8]) -> Result<usize, IoError>;
    /// Reopen the file with the position at its start.
    fn rewind(&mut self) -> Result<(), IoError>;
    /// Make the writes so far durable.
    fn sync(&mut self) -> Result<(), IoError>;
}

/// The store.
pub struct SeqStore<F: SeqFile> {
    file: F,
    /// Where the file's position is; `None` after an error left it unknown.
    pos: Option<u64>,
    sectors: u64,
    ro: bool,
    /// Work left before the next [`BlockStore::refill`].
    left: usize,
    /// Times the file was reopened to go backward.
    pub rewinds: u32,
}

impl<F: SeqFile> SeqStore<F> {
    /// A disk of `bytes` (a partial last sector is not part of it) over
    /// `file`, open at its start.
    pub fn new(file: F, bytes: u64, ro: bool) -> Self {
        SeqStore { file, pos: Some(0), sectors: bytes / SECTOR as u64, ro, left: WORK_BYTES, rewinds: 0 }
    }

    /// The file, for the tests to look at.
    #[cfg(test)]
    pub fn file_mut(&mut self) -> &mut F {
        &mut self.file
    }

    /// Move the position to `off`. `Again`: the budget ran out first, the
    /// position is where it got to (nearer `off`, never past it).
    fn seek(&mut self, off: u64) -> Result<(), IoError> {
        let mut pos = match self.pos {
            Some(p) if p <= off => p,
            _ => {
                // The file is closed and reopened: unknown until it is open.
                self.pos = None;
                self.file.rewind()?;
                self.rewinds += 1;
                0
            }
        };
        self.pos = None;
        let mut skip = [0u8; SKIP];
        while pos < off {
            #[cfg(not(feature = "canary-store-unbounded"))]
            if self.left == 0 {
                self.pos = Some(pos);
                return Err(IoError::Again);
            }
            let n = (off - pos).min(SKIP as u64) as usize;
            match self.file.read(&mut skip[..n])? {
                0 => return Err(IoError::Device),
                got => {
                    pos += got as u64;
                    self.left = self.left.saturating_sub(got);
                }
            }
        }
        self.pos = Some(pos);
        Ok(())
    }

    /// Spend `bytes` of the budget on a transfer; `Again` when none is left.
    fn spend(&mut self, bytes: usize) -> Result<(), IoError> {
        #[cfg(not(feature = "canary-store-unbounded"))]
        if self.left == 0 {
            return Err(IoError::Again);
        }
        self.left = self.left.saturating_sub(bytes);
        Ok(())
    }
}

impl<F: SeqFile> BlockStore for SeqStore<F> {
    fn capacity(&self) -> u64 {
        self.sectors
    }

    fn read_only(&self) -> bool {
        self.ro
    }

    fn refill(&mut self) {
        self.left = WORK_BYTES;
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let off = sector * SECTOR as u64;
        self.seek(off)?;
        self.spend(buf.len())?;
        self.pos = None;
        let mut done = 0;
        while done < buf.len() {
            match self.file.read(&mut buf[done..])? {
                0 => return Err(IoError::Device),
                n => done += n,
            }
        }
        self.pos = Some(off + done as u64);
        Ok(())
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), IoError> {
        let off = sector * SECTOR as u64;
        self.seek(off)?;
        self.spend(data.len())?;
        self.pos = None;
        let mut done = 0;
        while done < data.len() {
            match self.file.write(&data[done..])? {
                0 => return Err(IoError::Device),
                n => done += n,
            }
        }
        self.pos = Some(off + done as u64);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.file.sync()
    }
}
