// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Block` interface: raw sector access to ONE partition of the medium
//! the kernel found at boot (RFC-0048 P3).
//!
//! The endpoint's badge is the partition (`endpoint = "block.part.<n>"`, badge
//! `n + 1`; badge 0, the whole medium, is not a partition and no row names it).
//! The holder names sectors RELATIVE to its partition: the kernel adds the
//! partition's start, so a sector outside it cannot even be spelled, and a run
//! past the partition's end is refused and recorded.
//!
//! **The data path is the io_ring** (`OP_BLOCK_READ`, `OP_BLOCK_WRITE`), not the
//! call: a sector is 512 bytes and a reply carries 64. The endpoint carries the
//! authority (`READ` reads, `WRITE` writes) and the one question a client asks
//! before it submits, how long its partition is. The ring's data window holds
//! four sectors at most, and a ring entry names a sector below 2^32 (the
//! entry's `addr` and `reg` fields, low half first).

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "BLK ").
pub const BLOCK_ID: u32 = 0x424C_4B20;
/// Bytes per sector.
pub const SECTOR_BYTES: usize = 512;
/// Partitions the interface names: the kernel's table size.
pub const PARTS: u32 = 16;

#[azos_interface(id = 0x424C_4B20, level = 1)]
pub trait Block {
    /// The partition's length in sectors. `NOT_READY` when the kernel has not
    /// published the partition. Needs `READ`.
    #[idempotent]
    fn sectors(&self) -> Out<u64>;
}
