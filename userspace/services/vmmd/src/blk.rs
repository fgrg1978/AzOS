// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio-blk backend (device id 2): a guest's disk is a file vmmd holds.
//!
//! The device keeps no authority of its own. Every request becomes a read, a
//! write or a flush on a [`BlockStore`], and the store is a file opened
//! through the `Cap<Dir>` of vmmd's row, so what a guest's disk can do is
//! what that capability allows and every effect passes the kernel's gate and
//! its record like a native task's. A store that is refused answers an
//! error; the device turns it into `VIRTIO_BLK_S_IOERR` and goes on. The
//! guest never learns more than "that request failed".
//!
//! The guest picks sector numbers and lengths, so each request is checked
//! against the capacity before the store sees it (a write past the end must
//! not grow the file), against the read-only flag (offered as `F_RO`; a
//! write is refused regardless of what the driver negotiated), and for whole
//! sectors.

use crate::guest::GuestMem;
use crate::mmio::{Device, F_VERSION_1, MAX_QUEUES};
use crate::virtq::{Chain, Virtq, VqError, MAX_CHAIN};

/// Bytes of a sector.
pub const SECTOR: usize = 512;
/// Bytes moved between the store and guest memory at a time.
const CHUNK: usize = 4096;

const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const T_GET_ID: u32 = 8;

const S_OK: u8 = 0;
const S_IOERR: u8 = 1;
const S_UNSUPP: u8 = 2;
/// Not on the wire: a request refused while degraded mode is armed, which the
/// guest sees as `S_IOERR` and the device counts apart.
const S_CONTAINED: u8 = 0xFE;

const F_SEG_MAX: u64 = 1 << 2;
const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;

/// What the device reports for `GET_ID` (20 bytes, zero padded).
const ID: &[u8] = b"azos-vmmd";

/// Why the store did not do what was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// The authority behind the store does not allow it.
    Denied,
    /// Degraded mode is armed and refuses writes for now. The authority is
    /// fine and the medium is fine, so it is neither of the others; the guest
    /// still sees `IOERR` (virtio has no "try later"), but it is counted on
    /// its own.
    Contained,
    /// The medium failed.
    Device,
    /// The store spent its work budget before it finished and did nothing the
    /// caller must undo: make the same call again after the next
    /// [`BlockStore::refill`].
    Again,
}

impl IoError {
    /// What a failed file call (its negative result `rc`) means for the disk.
    pub fn from_errno(rc: isize) -> IoError {
        // -EPERM, -EACCES and the capability errors (`-ECAPPERMS` and the
        // like, all below -200) are the authority saying no; -EAGAIN is what a
        // write answers while degraded mode (containment) is armed; the rest
        // is the medium.
        if rc == -1 || rc == -13 || rc <= -200 {
            IoError::Denied
        } else if rc == -11 {
            IoError::Contained
        } else {
            IoError::Device
        }
    }
}

/// The medium behind a disk: sector-addressed, bounded.
pub trait BlockStore {
    /// Sectors the disk has.
    fn capacity(&self) -> u64;
    /// Writes are refused.
    fn read_only(&self) -> bool;
    /// Read whole sectors starting at `sector` into `buf`.
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), IoError>;
    /// Write whole sectors starting at `sector`.
    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), IoError>;
    /// Make the writes so far durable.
    fn flush(&mut self) -> Result<(), IoError>;
    /// A new budget of work begins (a store that never answers
    /// [`IoError::Again`] has nothing to renew).
    fn refill(&mut self) {}
}

/// A read or a write the store has not finished: the chain stays with the
/// device, and the guest sees nothing until the status byte is written.
#[derive(Clone, Copy)]
struct Job {
    chain: Chain,
    write: bool,
    sector: u64,
    bytes: u64,
    done: u64,
}

/// The device.
pub struct Blk<S: BlockStore> {
    pub store: S,
    /// Requests answered with an error status (`Contained` ones apart).
    pub errors: u32,
    /// Writes the store refused because degraded mode is armed.
    pub contained: u32,
    /// The request being worked on across passes, if any.
    job: Option<Job>,
}

impl<S: BlockStore> Blk<S> {
    pub fn new(store: S) -> Self {
        Blk { store, errors: 0, contained: 0, job: None }
    }

    /// Run the data phase of `j` as far as the store's budget allows: the
    /// status when it is over, `None` when the store asked to be called again.
    fn advance(&mut self, j: &mut Job, mem: &mut dyn GuestMem) -> Option<u8> {
        let mut buf = [0u8; CHUNK];
        while j.done < j.bytes {
            let n = (j.bytes - j.done).min(CHUNK as u64) as usize;
            let at = j.sector + j.done / SECTOR as u64;
            let r = if j.write {
                // The data follows the 16-byte header in the readable run.
                if j.chain.read_at(mem, HEADER as u64 + j.done, &mut buf[..n]).is_err() {
                    return Some(S_IOERR);
                }
                self.store.write(at, &buf[..n])
            } else {
                match self.store.read(at, &mut buf[..n]) {
                    Ok(()) if j.chain.write_at(mem, j.done, &buf[..n]).is_err() => return Some(S_IOERR),
                    r => r,
                }
            };
            match r {
                Ok(()) => j.done += n as u64,
                Err(IoError::Again) => return None,
                Err(IoError::Contained) => {
                    self.contained += 1;
                    return Some(S_CONTAINED);
                }
                Err(_) => return Some(S_IOERR),
            }
        }
        Some(S_OK)
    }

    /// Check a read or write the guest asked for before the store sees it.
    fn start(&mut self, chain: Chain, write: bool, sector: u64, bytes: u64) -> Result<Job, u8> {
        if bytes % SECTOR as u64 != 0 {
            return Err(S_IOERR);
        }
        let sectors = bytes / SECTOR as u64;
        #[cfg(not(feature = "canary-blk-no-capacity-check"))]
        if sector.checked_add(sectors).map_or(true, |end| end > self.store.capacity()) {
            return Err(S_IOERR);
        }
        #[cfg(not(feature = "canary-blk-ro-ignored"))]
        if write && self.store.read_only() {
            return Err(S_IOERR);
        }
        Ok(Job { chain, write, sector, bytes, done: 0 })
    }

    /// Write the status byte; the length the used entry reports (the status
    /// and, when the request succeeded, the `data` bytes before it). `0` when
    /// there is no way to answer.
    fn finish(&mut self, c: &Chain, mem: &mut dyn GuestMem, status: u8, data: u64) -> u32 {
        if status == S_IOERR {
            self.errors += 1;
        }
        // An error leaves the data buffer untouched; only the status counts.
        let written = if status == S_OK { data } else { 0 };
        let wire = if status == S_CONTAINED { S_IOERR } else { status };
        if c.write_at(mem, c.writable() - 1, &[wire]).is_err() {
            return 0;
        }
        (written + 1) as u32
    }

    /// Answer a request, or park it: the used length when it is over.
    fn request(&mut self, c: Chain, mem: &mut dyn GuestMem) -> Option<u32> {
        let wlen = c.writable();
        // The status byte is the last writable byte; without one there is no
        // way to answer and the request is dropped.
        if wlen == 0 {
            return Some(0);
        }
        let mut h = [0u8; HEADER];
        if c.readable() < HEADER as u64 || c.read_at(mem, 0, &mut h).is_err() {
            return Some(self.finish(&c, mem, S_IOERR, 0));
        }
        let ty = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let sector = u64::from_le_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
        let (write, bytes) = match ty {
            T_IN => (false, wlen - 1),
            T_OUT => (true, c.readable() - HEADER as u64),
            T_FLUSH => {
                let st = match self.store.flush() {
                    Ok(()) => S_OK,
                    Err(IoError::Contained) => {
                        self.contained += 1;
                        S_CONTAINED
                    }
                    Err(_) => S_IOERR,
                };
                return Some(self.finish(&c, mem, st, 0));
            }
            T_GET_ID => {
                let mut id = [0u8; 20];
                id[..ID.len()].copy_from_slice(ID);
                let n = (wlen - 1).min(20) as usize;
                let st = if c.write_at(mem, 0, &id[..n]).is_ok() { S_OK } else { S_IOERR };
                return Some(self.finish(&c, mem, st, n as u64));
            }
            _ => return Some(self.finish(&c, mem, S_UNSUPP, 0)),
        };
        match self.start(c, write, sector, bytes) {
            Ok(j) => self.run(j, mem),
            Err(st) => Some(self.finish(&c, mem, st, 0)),
        }
    }

    /// Work on `j`; park it if the store asked for another pass.
    fn run(&mut self, mut j: Job, mem: &mut dyn GuestMem) -> Option<u32> {
        match self.advance(&mut j, mem) {
            Some(st) => Some(self.finish(&j.chain, mem, st, if j.write { 0 } else { j.bytes })),
            None => {
                self.job = Some(j);
                None
            }
        }
    }

    /// One pass: the parked request first, then the ones the driver has made
    /// available, until the budget parks one or the queue is empty.
    fn serve(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        self.store.refill();
        let mut any = false;
        // A queue the driver turned off took its parked request with it.
        if !vqs[0].ready {
            self.job = None;
        }
        if let Some(j) = self.job.take() {
            match self.run(j, mem) {
                Some(n) => {
                    vqs[0].push_used(mem, &j.chain, n)?;
                    any = true;
                }
                None => return Ok(false),
            }
        }
        loop {
            let Some(chain) = vqs[0].pop(mem)? else { break };
            match self.request(chain, mem) {
                Some(n) => {
                    vqs[0].push_used(mem, &chain, n)?;
                    any = true;
                }
                None => break,
            }
        }
        Ok(any)
    }
}

const HEADER: usize = 16;
// A request is the header, data in at most this many descriptors and a status.
const _: () = assert!(MAX_CHAIN >= 3);

impl<S: BlockStore> Device for Blk<S> {
    fn id(&self) -> u32 {
        2
    }

    fn features(&self) -> u64 {
        F_VERSION_1 | F_SEG_MAX | F_FLUSH | if self.store.read_only() { F_RO } else { 0 }
    }

    fn queues(&self) -> usize {
        1
    }

    /// `capacity` (u64) at 0, `size_max` (u32) at 8, `seg_max` (u32) at 12.
    fn read_config(&self, off: usize, out: &mut [u8]) {
        let mut cfg = [0u8; 16];
        cfg[..8].copy_from_slice(&self.store.capacity().to_le_bytes());
        cfg[12..16].copy_from_slice(&((MAX_CHAIN - 2) as u32).to_le_bytes());
        for (i, b) in out.iter_mut().enumerate() {
            *b = cfg.get(off + i).copied().unwrap_or(0);
        }
    }

    fn notify(&mut self, q: usize, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        debug_assert_eq!(q, 0);
        self.serve(vqs, mem)
    }

    /// Goes on with the parked request, and with the ones queued behind it
    /// (the driver kicked once for all of them).
    fn poll(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        if self.job.is_none() {
            return Ok(false);
        }
        self.serve(vqs, mem)
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    fn reset(&mut self) {
        self.job = None;
    }
}
