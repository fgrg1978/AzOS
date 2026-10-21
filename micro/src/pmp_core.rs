// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V PMP entry encoding. Pure: no CSR is touched here (`hw.rs` writes
//! the words this file computes), so the host suite checks every encoding
//! against the privileged spec's.
//!
//! One `pmpcfg` byte per entry (`R`, `W`, `X`, the address-matching mode `A`
//! in bits 3..4, `L` in bit 7) and one `pmpaddr` word holding the address
//! shifted right by two. A region is one NAPOT entry when it is a
//! power-of-two block aligned to its size, else a TOR pair: the entry below
//! holds the base (switched off, it only supplies the lower bound) and the
//! TOR entry the end. M-mode ignores unlocked entries, so no entry here
//! sets `L`: the kernel validates the pointers it dereferences itself.

/// Read.
pub const R: u8 = 1;
/// Write.
pub const W: u8 = 2;
/// Execute.
pub const X: u8 = 4;

const A_OFF: u8 = 0;
const A_TOR: u8 = 1 << 3;
const A_NA4: u8 = 2 << 3;
const A_NAPOT: u8 = 3 << 3;

/// One PMP entry as the CSRs hold it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PmpEntry {
    /// The `pmpcfg` byte.
    pub cfg: u8,
    /// The `pmpaddr` word: the address shifted right by two.
    pub addr: usize,
}

impl PmpEntry {
    /// A switched-off entry: matches nothing.
    pub const OFF: Self = Self { cfg: A_OFF, addr: 0 };
}

/// The entries one region costs: one (NAPOT, or NA4 for four bytes) or two
/// (a TOR pair, base entry first).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cost {
    entries: [PmpEntry; 2],
    n: u8,
}

impl Cost {
    /// The entries, lowest index first.
    pub fn entries(&self) -> &[PmpEntry] {
        &self.entries[..self.n as usize]
    }

    /// How many entries.
    pub fn count(&self) -> usize {
        self.n as usize
    }
}

/// Whether `[base, base + size)` is a NAPOT block: a power of two of at
/// least eight bytes (four is NA4) aligned to its own size.
pub const fn napot_fits(base: usize, size: usize) -> bool {
    size >= 4 && size.is_power_of_two() && base & (size - 1) == 0
}

/// The entries for `[base, base + size)` with rights `perm` (`R|W|X` bits):
/// NA4 for four bytes, NAPOT for an aligned power of two, else a TOR pair.
/// `None` when the region is empty, wraps the address space, or `base` or
/// `size` is not a multiple of the granularity (`1 << grain_log2`): the
/// hart could not express it exactly, and a region wider than asked is
/// authority nobody granted.
pub fn region(base: usize, size: usize, perm: u8, grain_log2: u32) -> Option<Cost> {
    let grain = 1usize << grain_log2;
    if size == 0 || base & (grain - 1) != 0 || size & (grain - 1) != 0 {
        return None;
    }
    let end = base.checked_add(size)?;
    let perm = perm & (R | W | X);
    let mut entries = [PmpEntry::OFF; 2];
    // NA4 and the smallest NAPOT block need a granularity of four bytes: a
    // coarser PMP has neither (the spec makes NA4 unavailable when G > 2).
    if grain_log2 == 2 && size == 4 {
        entries[0] = PmpEntry { cfg: A_NA4 | perm, addr: base >> 2 };
        return Some(Cost { entries, n: 1 });
    }
    if size >= 8 && napot_fits(base, size) {
        entries[0] = PmpEntry { cfg: A_NAPOT | perm, addr: (base >> 2) | ((size >> 3) - 1) };
        return Some(Cost { entries, n: 1 });
    }
    entries[0] = PmpEntry { cfg: A_OFF, addr: base >> 2 };
    entries[1] = PmpEntry { cfg: A_TOR | perm, addr: end >> 2 };
    Some(Cost { entries, n: 2 })
}

/// What one region costs in entries, without encoding it.
pub fn entries_needed(base: usize, size: usize, grain_log2: u32) -> Option<usize> {
    region(base, size, R, grain_log2).map(|c| c.count())
}

/// The `pmpcfg` CSR word number `word` holds, from the per-entry bytes:
/// entry `i` is byte `i % per_word` of CSR `i / per_word` (little-endian
/// within the word). `per_word` is the entries one CSR holds: the XLEN in
/// bytes (4 on rv32, 8 on rv64, whose odd-numbered CSRs do not exist).
pub fn pack_cfg(cfgs: &[u8], word: usize, per_word: usize) -> usize {
    let mut v = 0usize;
    for k in 0..per_word {
        let b = cfgs.get(word * per_word + k).copied().unwrap_or(0);
        v |= (b as usize) << (8 * k);
    }
    v
}

/// How many `pmpcfg` CSRs `entries` PMP entries take.
pub const fn cfg_words(entries: usize, per_word: usize) -> usize {
    entries.div_ceil(per_word)
}
