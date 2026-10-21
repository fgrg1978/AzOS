// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Block` interface: raw sector access to ONE partition of the medium
//! the kernel found at boot.
//!
//! The endpoint's badge is the partition (`endpoint = "block.part.<n>"`, badge
//! `n + 1`; badge 0, the whole medium, is not a partition and no row names it).
//! The holder names sectors RELATIVE to its partition: the kernel adds the
//! partition's start, so a sector outside it cannot even be spelled, and a run
//! past the partition's end is refused and recorded.
//!
//! The kernel's own block traffic (the FAT32 write-back, the block cache's
//! flushes) is made of [`BlockRequest`]s, queued per hart and merged by
//! `azos_drv_block::queue`; the descriptor is defined here so that the same
//! request can cross an endpoint, and the same refusal ([`BlockRequest::check`])
//! applies on either side.
//!
//! **The data path is the io_ring** (`OP_BLOCK_READ`, `OP_BLOCK_WRITE`), not the
//! call: a sector is 512 bytes and a reply carries 64. The endpoint carries the
//! authority (`READ` reads, `WRITE` writes) and the one question a client asks
//! before it submits, how long its partition is. The ring's data window holds
//! four sectors at most, and a ring entry names a sector below 2^32 (the
//! entry's `addr` and `reg` fields, low half first).

//!
//! # Failure contract
//!
//! `sectors` degrades on failure (the client is told `NOT_READY` or gets a
//! transport error and keeps its ring) and is bounded like any reader. The
//! data path's own bounds belong to the io_ring, not to this interface.

use crate::outcome::{self, Out};
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "BLK ").
pub const BLOCK_ID: u32 = 0x424C_4B20;
/// Bytes per sector.
pub const SECTOR_BYTES: usize = 512;
/// Partitions the interface names: the kernel's table size.
pub const PARTS: u32 = 16;

// ── The request ─────────────────────────────────────────────────────────

/// [`BlockRequest::op`]: read `count` sectors into the request's buffer.
pub const REQ_READ: u32 = 0;
/// [`BlockRequest::op`]: write `count` sectors from the request's buffer.
pub const REQ_WRITE: u32 = 1;
/// [`BlockRequest::op`]: make every write that completed before this request
/// durable. No sectors, no buffer.
pub const REQ_FLUSH: u32 = 2;
/// [`BlockRequest::op`]: tell the device the `count` sectors hold nothing
/// worth keeping (TRIM / deallocate). A hint: the device may keep the data,
/// and a read of a discarded sector answers whatever the device chooses. No
/// buffer.
pub const REQ_DISCARD: u32 = 3;

/// [`BlockRequest::flags`]: the write is durable when it completes (force
/// unit access), not only accepted by the device's volatile cache. Writes
/// only.
pub const FLAG_FUA: u32 = 1 << 0;
/// [`BlockRequest::flags`]: every write that completed before this request is
/// made durable BEFORE this request starts (a flush ahead of it). Writes
/// only. This is the epoch rule of a write-back cache: a block of epoch `e`
/// may not reach the device before the blocks of the epochs before it are
/// stable.
pub const FLAG_PREFLUSH: u32 = 1 << 1;
/// Every flag bit a request may carry.
pub const FLAGS_ALL: u32 = FLAG_FUA | FLAG_PREFLUSH;

/// [`BlockRequest::owner`]: no Domain. A request that names it is refused.
pub const OWNER_NONE: u32 = 0;
/// [`BlockRequest::owner`]: the kernel itself, before the scheduler has a
/// Domain to name (boot reads) or from a context that belongs to none.
pub const OWNER_KERNEL: u32 = u32::MAX;

/// One block request: what to move, where, how urgent, and whose it is.
///
/// This is the descriptor the block layer queues (`azos_drv_block::queue`)
/// and the form it takes across an endpoint ([`Wire`]). The data itself is
/// not in it: a request names a buffer either as a kernel buffer that
/// travels beside the descriptor (`mem == 0`) or as a range of a MemObj the
/// owner Domain holds (`mem` is the handle in the owner's table, `mem_off`
/// the byte offset of the range). `count * 512` bytes for a read or a write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockRequest {
    /// [`REQ_READ`], [`REQ_WRITE`], [`REQ_FLUSH`] or [`REQ_DISCARD`].
    pub op: u32,
    /// [`FLAG_FUA`] | [`FLAG_PREFLUSH`].
    pub flags: u32,
    /// First sector, in 512-byte sectors of the medium.
    pub sector: u64,
    /// Sectors. 0 for a flush; at least 1 otherwise.
    pub count: u32,
    /// Nanoseconds from submission within which the request must have been
    /// started; one that waited longer is not started and answers a deadline
    /// miss. 0: no deadline of its own (the device's command timeout still
    /// bounds it). Earlier deadlines are started first, except under
    /// Kconfig `BLK_IOSCHED` `none` (arrival order).
    pub deadline_ns: u64,
    /// The Domain the request is made for (its key, `azos_sched::domain::Key`),
    /// or [`OWNER_KERNEL`]. [`OWNER_NONE`] is refused: every request is
    /// someone's, and only requests of one owner are merged.
    pub owner: u32,
    /// 0: the buffer is a kernel buffer beside the descriptor. Else a handle
    /// to a MemObj in the owner's capability table.
    pub mem: u32,
    /// Byte offset of the range in the MemObj; 0 when `mem == 0`.
    pub mem_off: u64,
}

impl BlockRequest {
    /// A read or write of `count` sectors at `sector` into/from a kernel
    /// buffer, for `owner`, with no deadline and no flags.
    pub const fn rw(write: bool, sector: u64, count: u32, owner: u32) -> BlockRequest {
        BlockRequest {
            op: if write { REQ_WRITE } else { REQ_READ },
            flags: 0,
            sector,
            count,
            deadline_ns: 0,
            owner,
            mem: 0,
            mem_off: 0,
        }
    }

    /// A flush for `owner`.
    pub const fn flush(owner: u32) -> BlockRequest {
        BlockRequest { op: REQ_FLUSH, flags: 0, sector: 0, count: 0, deadline_ns: 0, owner, mem: 0, mem_off: 0 }
    }

    /// Does the request carry a buffer (a read or a write)?
    pub const fn has_data(&self) -> bool {
        self.op == REQ_READ || self.op == REQ_WRITE
    }

    /// Is the request well formed? The outcome code the layer answers a
    /// malformed one with: [`outcome::REFUSED`] for a request with no owner
    /// (nobody to charge it to), [`outcome::BAD_ARGUMENT`] for a shape that
    /// means nothing (an unknown op or flag, flags on a read, a flush with
    /// sectors, a data request with none or whose last sector overflows,
    /// a MemObj offset with no MemObj).
    pub fn check(&self) -> Result<(), u32> {
        if self.owner == OWNER_NONE {
            return Err(outcome::REFUSED);
        }
        if self.flags & !FLAGS_ALL != 0 || (self.mem == 0 && self.mem_off != 0) {
            return Err(outcome::BAD_ARGUMENT);
        }
        let shaped = match self.op {
            REQ_READ => self.flags == 0 && self.count != 0,
            REQ_WRITE => self.count != 0,
            REQ_FLUSH => self.flags == 0 && self.count == 0 && self.sector == 0,
            REQ_DISCARD => self.flags == 0 && self.count != 0,
            _ => false,
        };
        if !shaped || (self.mem != 0 && !self.has_data()) {
            return Err(outcome::BAD_ARGUMENT);
        }
        if self.sector.checked_add(self.count as u64).is_none() {
            return Err(outcome::BAD_ARGUMENT);
        }
        Ok(())
    }
}

impl Wire for BlockRequest {
    const WORDS: usize = 8;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.op.put(w);
        self.flags.put(w);
        self.sector.put(w);
        self.count.put(w);
        self.deadline_ns.put(w);
        self.owner.put(w);
        self.mem.put(w);
        self.mem_off.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let op = u32::get(r);
        let flags = u32::get(r);
        let sector = u64::get(r);
        let count = u32::get(r);
        let deadline_ns = u64::get(r);
        let owner = u32::get(r);
        let mem = u32::get(r);
        BlockRequest { op, flags, sector, count, deadline_ns, owner, mem, mem_off: u64::get(r) }
    }
}

#[azos_interface(id = 0x424C_4B20, level = 1)]
pub trait Block {
    /// The partition's length in sectors. `NOT_READY` when the kernel has not
    /// published the partition. Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn sectors(&self) -> Out<u64>;
}
