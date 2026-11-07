// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the monitor checks in a stage-1 word before it writes one into the
//! kernel half's tables: the descriptor must be well formed at its level, a
//! leaf must carry AF (the walker's hardware update would need a stage-2 write
//! the read-only pool refuses), no DBM and never be writable and executable at
//! EL1,
//! and the level a pool page serves is fixed by its first use. Pure, so the
//! host suite checks it.

#[path = "../../../../../arch/aarch64/src/mmu/pte_fmt.rs"]
#[allow(dead_code)] // reason: shared by source with the kernel's page-table code, which uses the rest
pub mod pte_fmt;

use pte_fmt::*;

/// A pool page's tag: set once the page has a level, `TAG_IMAGE` when it maps,
/// or leads to a table that maps, the locked image.
pub const TAG_SET: u8 = 0x80;
pub const TAG_IMAGE: u8 = 0x40;
const TAG_LEVEL: u8 = 0x3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Word {
    Invalid,
    Table(u64),
    Leaf { pa: u64, size: u64 },
}

pub const fn block_size(level: usize, page_shift: u32) -> u64 {
    1 << (page_shift + (page_shift - 3) * level as u32)
}

pub fn classify(word: u64, level: usize, page_shift: u32) -> Result<Word, &'static str> {
    if !is_valid(word) {
        return Ok(Word::Invalid);
    }
    let pa = phys_addr(word) as u64;
    if is_table(word, level) {
        if word != make_table(pa as usize) { return Err("table descriptor with attributes"); }
        if pa % (1 << page_shift) != 0 { return Err("table not page-aligned"); }
        return Ok(Word::Table(pa));
    }
    if is_leaf(word, level) {
        let size = block_size(level, page_shift);
        if pa % size != 0 { return Err("leaf not aligned to its size"); }
        return Ok(Word::Leaf { pa, size });
    }
    Err("reserved descriptor")
}

fn overlaps(lo: u64, hi: u64, r: [u64; 2]) -> bool {
    lo < r[1] && r[0] < hi
}

/// Why a well-formed word may not be written; `None`: it may.
pub fn word_error(w: Word, word: u64) -> Option<&'static str> {
    if !matches!(w, Word::Leaf { .. }) { return None; }
    if word & AF == 0 { return Some("leaf without AF"); }
    if word & DBM != 0 { return Some("leaf with DBM"); }
    if el1_writable(word) && el1_executable(word) { return Some("leaf writable and executable"); }
    None
}

/// Does a leaf map the locked image? Such a word, and the table that holds
/// the way to it, never change.
pub fn maps_image(w: Word, image: &[[u64; 2]]) -> bool {
    matches!(w, Word::Leaf { pa, size } if image.iter().any(|i| overlaps(pa, pa + size, *i)))
}

pub const fn tag_of(level: usize) -> u8 {
    TAG_SET | level as u8
}

pub const fn tag_level(tag: u8) -> Option<usize> {
    if tag & TAG_SET != 0 { Some((tag & TAG_LEVEL) as usize) } else { None }
}

/// The tag after a page is used at `level`: a page with none takes it, one
/// with a level keeps it only if it is the same.
pub fn claim(tag: u8, level: usize) -> Result<u8, &'static str> {
    match tag_level(tag) {
        None => Ok(tag_of(level)),
        Some(l) if l == level => Ok(tag),
        Some(_) => Err("page serves another level"),
    }
}

/// The pages a checked write fixes the level of: the one it writes into
/// (`entry`) and the table it links, with the level that table serves.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub entry: usize,
    pub target: Option<(u64, usize)>,
}

/// Why replacing `expected` by `new` in a table of `level` is refused; the
/// claims it makes otherwise. `in_pool` says whether a table address is a pool
/// page, `tag` gives a pool page's tag.
pub fn write_error(
    expected: u64,
    new: u64,
    level: usize,
    entry_tag: u8,
    page_shift: u32,
    image: &[[u64; 2]],
    in_pool: impl Fn(u64) -> bool,
    tag: impl Fn(u64) -> u8,
) -> Result<Claims, &'static str> {
    claim(entry_tag, level)?;
    let now = classify(expected, level, page_shift)?;
    if maps_image(now, image) { return Err("slot maps the image"); }
    if let Word::Table(t) = now {
        if in_pool(t) && tag(t) & TAG_IMAGE != 0 { return Err("slot leads to the image"); }
    }
    let w = classify(new, level, page_shift)?;
    if let Some(e) = word_error(w, new) { return Err(e); }
    let target = match w {
        Word::Table(t) if !in_pool(t) => return Err("table outside the pool"),
        Word::Table(t) => {
            claim(tag(t), level - 1)?;
            Some((t, level - 1))
        }
        _ => None,
    };
    Ok(Claims { entry: level, target })
}
