// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Region domains: what a task's PMP entries admit.
//!
//! A task's domain is a short list of regions, each one a range of physical
//! addresses with rights, of three kinds:
//!
//! * [`Kind::Anon`]: the task's own memory, carved eagerly from the pool at
//!   boot (nothing is faulted in on a machine with no MMU). The task sees
//!   its stack and data in the lower part; the upper part is its grant
//!   (`grant.rs`) and no entry covers it.
//! * [`Kind::Phys`]: a window of device registers a `mmio` capability names
//!   (`chip::MMIO`), at the chip's own address.
//! * [`Kind::Contig`]: a physically contiguous block of the contiguous pool,
//!   the DMA memory of a `[pipeline.NAME]` section, shared by every task that
//!   holds a `shm` capability naming the pipeline. A power-of-two block
//!   aligned to its size, so it is one PMP entry and a device can be pointed
//!   at it.
//!
//! The list is checked against the entries the hart gives one task
//! (`MICRO_TASK_PMP_ENTRIES`) when a region is added, so a domain that does
//! not fit is refused at boot, not discovered at the first switch.

use crate::pmp_core::{self, PmpEntry};

/// Where a region's memory comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// The task's own memory, from the pool.
    Anon,
    /// A window of device registers.
    Phys,
    /// A physically contiguous block, shared.
    Contig,
}

/// One range with rights.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    /// First byte.
    pub base: usize,
    /// Length in bytes.
    pub size: usize,
    /// `pmp_core::{R, W, X}` bits.
    pub perm: u8,
    /// Where it comes from.
    pub kind: Kind,
}

impl Region {
    /// One past the last byte.
    pub const fn end(&self) -> usize {
        self.base.wrapping_add(self.size)
    }

    /// Whether `[addr, addr + len)` lies inside the region and `need` is a
    /// subset of its rights. An empty range is inside only when its start is.
    pub fn admits(&self, addr: usize, len: usize, need: u8) -> bool {
        let (Some(end), Some(region_end)) = (addr.checked_add(len), self.base.checked_add(self.size)) else {
            return false;
        };
        self.perm & need == need && addr >= self.base && end <= region_end
    }
}

/// Why a region was not added to a domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DomainError {
    /// The hart cannot express the range exactly (unaligned, empty, wrapped).
    Unencodable,
    /// The domain would use more PMP entries than a task is given.
    NoEntries,
    /// More regions than the domain's table.
    TooMany,
}

/// Most regions one domain lists. Eight regions at one entry each is the
/// most `MICRO_TASK_PMP_ENTRIES` allows.
pub const MAX_REGIONS: usize = 16;

/// A task's regions and the entries they use.
#[derive(Clone, Copy, Debug)]
pub struct Domain {
    regions: [Option<Region>; MAX_REGIONS],
    n: usize,
    used: usize,
    budget: usize,
    grain_log2: u32,
}

impl Domain {
    /// An empty domain that may use `budget` PMP entries on a hart of
    /// granularity `1 << grain_log2`.
    pub const fn new(budget: usize, grain_log2: u32) -> Self {
        Self { regions: [None; MAX_REGIONS], n: 0, used: 0, budget, grain_log2 }
    }

    /// Add `region`, or say why not. A refusal changes nothing.
    pub fn add(&mut self, region: Region) -> Result<(), DomainError> {
        if self.n >= MAX_REGIONS {
            return Err(DomainError::TooMany);
        }
        let cost = pmp_core::entries_needed(region.base, region.size, self.grain_log2)
            .ok_or(DomainError::Unencodable)?;
        if self.used + cost > self.budget {
            return Err(DomainError::NoEntries);
        }
        self.regions[self.n] = Some(region);
        self.n += 1;
        self.used += cost;
        Ok(())
    }

    /// The regions, in the order they were added.
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions[..self.n].iter().flatten()
    }

    /// PMP entries the regions use.
    pub fn entries_used(&self) -> usize {
        self.used
    }

    /// Whether the domain admits `[addr, addr + len)` with rights `need`:
    /// the whole range lies in ONE region (two adjacent regions are two
    /// grants, and a copy across the seam is not covered by either).
    pub fn admits(&self, addr: usize, len: usize, need: u8) -> bool {
        self.regions().any(|r| r.admits(addr, len, need))
    }

    /// Write the domain's entries to `out` from index 0; returns how many.
    /// `out` must hold `entries_used()`.
    pub fn encode(&self, out: &mut [PmpEntry]) -> usize {
        let mut i = 0;
        for r in self.regions() {
            // `add` accepted this region, so it encodes.
            if let Some(c) = pmp_core::region(r.base, r.size, r.perm, self.grain_log2) {
                for e in c.entries() {
                    out[i] = *e;
                    i += 1;
                }
            }
        }
        i
    }
}

/// A bump allocator over a fixed window: how the pool and the contiguous
/// pool hand out memory at boot. Nothing is freed (the topology is static;
/// a task that ends has its region cleared and kept).
#[derive(Clone, Copy, Debug)]
pub struct Pool {
    next: usize,
    end: usize,
}

impl Pool {
    /// A pool over `[start, end)`.
    pub const fn new(start: usize, end: usize) -> Self {
        Self { next: start, end }
    }

    /// `size` bytes aligned to `align` (a power of two), or `None` when the
    /// pool is exhausted. Nothing is consumed on `None`.
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<usize> {
        let base = self.next.checked_add(align - 1)? & !(align - 1);
        let end = base.checked_add(size)?;
        if end > self.end {
            return None;
        }
        self.next = end;
        Some(base)
    }

    /// Bytes left (before alignment).
    pub fn left(&self) -> usize {
        self.end - self.next
    }
}

/// `n` rounded up to a multiple of `1 << grain_log2`.
pub const fn round_up(n: usize, grain_log2: u32) -> usize {
    let g = 1usize << grain_log2;
    (n + g - 1) & !(g - 1)
}

/// A contiguous region's size for a request of `kb` KiB: the next power of
/// two (at least one granule), so the block is a NAPOT entry.
pub const fn contig_size(kb: usize, grain_log2: u32) -> usize {
    let want = kb * 1024;
    let want = if want < (1 << grain_log2) { 1 << grain_log2 } else { want };
    want.next_power_of_two()
}
