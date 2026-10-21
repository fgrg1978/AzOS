// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The split virtqueue (virtio 1.x, section 2.7), device side.
//!
//! Everything in guest memory is the guest's to forge, so [`Virtq::pop`]
//! trusts none of it: the avail index may claim more entries than the queue
//! holds, a head or `next` may name a descriptor past the table, a chain may
//! loop, a descriptor may point (or, by wrapping, claim to point) outside RAM,
//! and a device-readable buffer may follow a device-writable one. Each is
//! refused with a [`VqError`], and the transport answers by flagging the
//! device as needing a reset, never by following the data any further. A
//! chain is collected whole (at most [`MAX_CHAIN`] descriptors) before a
//! device sees any of it.

use crate::guest::{read_u16, read_u32, read_u64, write_u16, write_u32, GuestMem, OutOfRam};

/// Most entries a queue may have (a power of two, spec 2.7: at most 32768).
pub const QUEUE_MAX: u16 = 128;
/// Most descriptors in one chain the models accept.
pub const MAX_CHAIN: usize = 16;

const DESC_BYTES: u64 = 16;
const F_NEXT: u16 = 1;
const F_WRITE: u16 = 2;
const F_INDIRECT: u16 = 4;

/// Why a queue cannot be served; the device is then flagged `NEEDS_RESET`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VqError {
    /// A ring or table address is not inside RAM.
    Ram,
    /// The avail index runs ahead of the queue by more than its size.
    Overrun,
    /// A head or `next` index is not in the descriptor table.
    BadIndex,
    /// The chain is longer than [`MAX_CHAIN`] (or loops).
    TooLong,
    /// An indirect descriptor (not offered).
    Indirect,
    /// A device-readable descriptor after a device-writable one.
    Order,
}

impl From<OutOfRam> for VqError {
    fn from(_: OutOfRam) -> Self {
        VqError::Ram
    }
}

/// One descriptor of a chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    /// The device writes this buffer (else it only reads it).
    pub write: bool,
}

/// One buffer chain taken off the avail ring.
#[derive(Clone, Copy, Debug)]
pub struct Chain {
    /// The head index: what the used ring answers with.
    pub head: u16,
    n: usize,
    descs: [Desc; MAX_CHAIN],
}

impl Chain {
    pub fn descs(&self) -> &[Desc] {
        &self.descs[..self.n]
    }

    /// Bytes the device may read.
    pub fn readable(&self) -> u64 {
        self.descs().iter().filter(|d| !d.write).map(|d| d.len as u64).sum()
    }

    /// Bytes the device may write.
    pub fn writable(&self) -> u64 {
        self.descs().iter().filter(|d| d.write).map(|d| d.len as u64).sum()
    }

    /// Copy device-readable bytes `[off, off + out.len())` (counting the
    /// readable descriptors as one run) into `out`. `Err` when the run is
    /// shorter.
    pub fn read_at(&self, mem: &dyn GuestMem, off: u64, out: &mut [u8]) -> Result<(), VqError> {
        self.walk(false, off, out.len(), |d_addr, range| {
            mem.read(d_addr, &mut out[range]).map_err(VqError::from)
        })
    }

    /// Copy `data` into the device-writable run at `off`.
    pub fn write_at(&self, mem: &mut dyn GuestMem, off: u64, data: &[u8]) -> Result<(), VqError> {
        self.walk(true, off, data.len(), |d_addr, range| {
            mem.write(d_addr, &data[range]).map_err(VqError::from)
        })
    }

    /// Visit the pieces of the `want`-byte span at `off` of the readable
    /// (`write == false`) or writable run: `f(address, range of the span)`.
    fn walk(
        &self,
        write: bool,
        mut off: u64,
        want: usize,
        mut f: impl FnMut(u64, core::ops::Range<usize>) -> Result<(), VqError>,
    ) -> Result<(), VqError> {
        let mut done = 0usize;
        for d in self.descs().iter().filter(|d| d.write == write) {
            if done == want {
                break;
            }
            let len = d.len as u64;
            if off >= len {
                off -= len;
                continue;
            }
            let take = (len - off).min((want - done) as u64) as usize;
            // The descriptor was range-checked when the chain was taken.
            f(d.addr.wrapping_add(off), done..done + take)?;
            done += take;
            off = 0;
        }
        if done == want {
            Ok(())
        } else {
            Err(VqError::BadIndex)
        }
    }
}

/// One virtqueue's device-side state.
#[derive(Clone, Copy, Debug)]
pub struct Virtq {
    /// Entries the driver set (`QueueNum`), 0 until it does.
    pub num: u16,
    pub ready: bool,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    last_avail: u16,
    used_idx: u16,
}

impl Virtq {
    pub const EMPTY: Virtq = Virtq { num: 0, ready: false, desc: 0, avail: 0, used: 0, last_avail: 0, used_idx: 0 };

    /// Back to the state after a device reset.
    pub fn reset(&mut self) {
        *self = Virtq::EMPTY;
    }

    /// May the driver turn this queue on? A power-of-two size within
    /// [`QUEUE_MAX`] and the three areas aligned (16, 2, 4) and wholly in RAM.
    pub fn valid(&self, mem: &dyn GuestMem) -> bool {
        let n = self.num as u64;
        self.num != 0
            && self.num <= QUEUE_MAX
            && self.num.is_power_of_two()
            && self.desc % 16 == 0
            && self.avail % 2 == 0
            && self.used % 4 == 0
            && mem.contains(self.desc, DESC_BYTES * n)
            && mem.contains(self.avail, 6 + 2 * n)
            && mem.contains(self.used, 6 + 8 * n)
    }

    /// Take the next chain the driver made available, if any.
    pub fn pop(&mut self, mem: &dyn GuestMem) -> Result<Option<Chain>, VqError> {
        if !self.ready || self.num == 0 {
            return Ok(None);
        }
        let idx = read_u16(mem, self.avail + 2)?;
        if idx == self.last_avail {
            return Ok(None);
        }
        // Entries the driver published cannot exceed the queue's size.
        if idx.wrapping_sub(self.last_avail) > self.num {
            return Err(VqError::Overrun);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let slot = (self.last_avail % self.num) as u64;
        let head = read_u16(mem, self.avail + 4 + 2 * slot)?;
        let chain = self.collect(mem, head)?;
        self.last_avail = self.last_avail.wrapping_add(1);
        Ok(Some(chain))
    }

    fn collect(&self, mem: &dyn GuestMem, head: u16) -> Result<Chain, VqError> {
        let mut chain = Chain { head, n: 0, descs: [Desc::default(); MAX_CHAIN] };
        let mut i = head;
        let mut seen_write = false;
        loop {
            if i >= self.num {
                return Err(VqError::BadIndex);
            }
            if chain.n == MAX_CHAIN {
                return Err(VqError::TooLong);
            }
            let at = self.desc + DESC_BYTES * i as u64;
            let addr = read_u64(mem, at)?;
            let len = read_u32(mem, at + 8)?;
            let flags = read_u16(mem, at + 12)?;
            let next = read_u16(mem, at + 14)?;
            if flags & F_INDIRECT != 0 {
                return Err(VqError::Indirect);
            }
            let write = flags & F_WRITE != 0;
            if seen_write && !write {
                return Err(VqError::Order);
            }
            seen_write |= write;
            // The guest chose `addr` and `len`; the sum may wrap.
            #[cfg(not(feature = "canary-vq-no-bounds"))]
            if !mem.contains(addr, len as u64) {
                return Err(VqError::Ram);
            }
            chain.descs[chain.n] = Desc { addr, len, write };
            chain.n += 1;
            if flags & F_NEXT == 0 {
                return Ok(chain);
            }
            i = next;
        }
    }

    /// Return `chain` to the driver with `written` bytes put in its writable
    /// buffers.
    pub fn push_used(&mut self, mem: &mut dyn GuestMem, chain: &Chain, written: u32) -> Result<(), VqError> {
        if self.num == 0 {
            return Err(VqError::BadIndex);
        }
        let slot = (self.used_idx % self.num) as u64;
        let e = self.used + 4 + 8 * slot;
        write_u32(mem, e, chain.head as u32)?;
        write_u32(mem, e + 4, written)?;
        // The entry is visible before the index that publishes it.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.used_idx = self.used_idx.wrapping_add(1);
        write_u16(mem, self.used + 2, self.used_idx)?;
        Ok(())
    }
}
