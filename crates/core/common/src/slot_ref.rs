// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! How a packed `(index, generation)` reference splits, and the per-slot generation a pool stamps.
//! `ipc::cap::objref` re-exports it; `mm::memobj` packs its `Cap<Shm>` references with it.

/// The fewest generation bits a packed kind may have.
pub const MIN_GEN_BITS: u32 = 16;

/// How one kind splits a packed resource into index and generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    idx_bits: u32,
}

impl Layout {
    /// The smallest index width that holds the indices `0..slots`.
    ///
    /// `slots <= 1` needs no index bits. Otherwise the width is that of
    /// `slots - 1`, the largest index: 16 slots take 4 bits, 17 take 5.
    pub const fn for_slots(slots: usize) -> Layout {
        let idx_bits = if slots <= 1 {
            0
        } else {
            usize::BITS - (slots - 1).leading_zeros()
        };
        Layout { idx_bits }
    }

    /// A fixed index width.
    pub const fn fixed(idx_bits: u32) -> Layout {
        assert!(idx_bits < u32::BITS, "a layout needs at least one generation bit");
        Layout { idx_bits }
    }

    #[inline]
    pub const fn idx_bits(self) -> u32 {
        self.idx_bits
    }

    #[inline]
    pub const fn gen_bits(self) -> u32 {
        u32::BITS - self.idx_bits
    }

    /// Mask of the index half.
    #[inline]
    pub const fn idx_mask(self) -> u32 {
        ((1u64 << self.idx_bits) - 1) as u32
    }

    /// Largest generation a counter of this layout hands out. The smallest is 1.
    #[inline]
    pub const fn gen_max(self) -> u32 {
        ((1u64 << self.gen_bits()) - 1) as u32
    }

    // REQ-018
    /// Pack an index and a generation. Both are masked to their widths; the
    /// pools pass an index below their size (each asserts it fits) and a
    /// generation from [`take_slot_gen`].
    #[inline]
    pub const fn pack(self, idx: u32, gen: u32) -> u32 {
        (((gen & self.gen_max()) as u64) << self.idx_bits) as u32 | (idx & self.idx_mask())
    }

    /// The pool index of a packed resource.
    #[inline]
    pub const fn idx(self, r: u32) -> u32 {
        r & self.idx_mask()
    }

    /// The generation of a packed resource. 0 never names a live object.
    #[inline]
    pub const fn gen(self, r: u32) -> u32 {
        ((r as u64) >> self.idx_bits) as u32
    }
}

/// `Cap<Shm>`: 8 index bits (the pool asserts its 16 slots fit).
pub const SHM: Layout = Layout::fixed(8);
/// What [`take_slot_gen`] answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotGen {
    /// Stamp the carried generation into the slot, and store one past it back
    /// into `next_gen[i]`.
    Gen(u32),
    /// `next_gen[i]` has passed `layout.gen_max()`. The caller must: mark the
    /// slot mid-sweep (pools use `next_gen[i] = 0`, which this function never
    /// returns and which the free-slot scan already treats as unavailable, so
    /// no concurrent create can select the same index while the lock below is
    /// dropped), release the pool lock, call [`sweep_index`] for this index,
    /// re-take the lock, reset `next_gen[i]` to `1`, and retry — which then
    /// always answers `Gen(1)`.
    Wrap,
}

// REQ-018
/// The generation a create should stamp into the slot whose `next_gen` entry
/// is `next_gen`, or [`SlotGen::Wrap`] if that slot's generation is exhausted.
///
/// A pool keeps its own `next_gen: [u32; N]` (one entry per object slot,
/// initialised to `1`, never reset by a destroy) under the same lock as the
/// objects themselves — no separate counter type, no atomics, no lock of its
/// own. Having already found a free slot `i`, the create calls this with
/// `next_gen[i]`. See the module doc ("Per-slot generations...") for the full
/// wrap protocol.
#[inline]
pub const fn take_slot_gen(next_gen: u32, layout: Layout) -> SlotGen {
    if next_gen == 0 || next_gen > layout.gen_max() {
        SlotGen::Wrap
    } else {
        SlotGen::Gen(next_gen)
    }
}

