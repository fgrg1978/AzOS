// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the monitor checks in a stage-1 word before it writes one into the
//! kernel half's tables: the descriptor must be well formed at its level, a
//! leaf must carry AF (the walker's hardware update would need a stage-2 write
//! the read-only pool refuses), no DBM, no contiguous hint (a run's TLB entry
//! could stand in for a frozen neighbour) and never be writable and executable
//! at EL1,
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
    if word & CONT != 0 { return Some("leaf with the contiguous hint"); }
    if el1_writable(word) && el1_executable(word) { return Some("leaf writable and executable"); }
    None
}

/// Why a word already in the tables at the lock is refused: it breaks the
/// rules of any word, or it is a block over the image (a later split of it would
/// have to rewrite a frozen slot, so the lock fails where it is reported).
pub fn lock_word_error(w: Word, word: u64, level: usize, image: &[[u64; 2]]) -> Option<&'static str> {
    if level > 0 && maps_image(w, image) { return Some("a block leaf over the image"); }
    word_error(w, word)
}

/// Why a pool page the lock's walk did not reach is refused: it has words that
/// nothing checked.
pub fn unreached_error(tag: u8, mut words: impl Iterator<Item = u64>) -> Option<&'static str> {
    if tag & TAG_SET == 0 && words.any(|w| w != 0) { Some("a pool page nothing links has words in it") } else { None }
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
    if expected != new {
        if maps_image(now, image) { return Err("slot maps the image"); }
        if let Word::Table(t) = now {
            if in_pool(t) && tag(t) & TAG_IMAGE != 0 { return Err("slot leads to the image"); }
        }
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

/// The leaf `va` resolves to from `root`, with its physical address: `read`
/// gives the word at a physical address. `None` when the walk meets an
/// invalid word, a reserved one, or a table where the levels run out.
pub fn resolve(read: impl Fn(u64) -> u64, root: u64, va: u64, page_shift: u32) -> Option<(u64, u64)> {
    let bits = page_shift - 3;
    let mut table = root;
    for level in (0..LEVELS).rev() {
        let idx = (va >> (page_shift + bits * level as u32)) & ((1 << bits) - 1);
        let word = read(table + idx * 8);
        match classify(word, level, page_shift).ok()? {
            Word::Invalid => return None,
            Word::Table(t) => table = t,
            Word::Leaf { pa, size } => return Some((pa + (va & (size - 1)), word)),
        }
    }
    None
}

/// Why the image does not live where the kernel says: every page of
/// `[va, va + len)` must resolve to the matching page of `pa`, read-only, and
/// executable only for text.
pub fn image_error(read: impl Fn(u64) -> u64, root: u64, va: u64, pa: u64, len: u64, text: bool, page_shift: u32) -> Option<&'static str> {
    let page = 1u64 << page_shift;
    let mut off = 0;
    while off < len {
        let Some((got, word)) = resolve(&read, root, va + off, page_shift) else { return Some("image page not mapped") };
        if got != pa + off { return Some("image page maps another frame"); }
        if el1_writable(word) { return Some("image page writable"); }
        if el1_executable(word) != text { return Some(if text { "text page not executable" } else { "data page executable" }); }
        off += page;
    }
    None
}

/// `TTBR1_EL1.BADDR` (bits 47:1; bit 0 is CnP) and the ASID field.
const TTBR1_BADDR: u64 = 0x0000_FFFF_FFFF_FFFE;
const TTBR1_ASID: u64 = 0xFFFF << 48;
/// The `TCR_EL1` fields that decide how a `TTBR1_EL1` walk reads the tables:
/// T1SZ, A1, EPD1, IRGN1, ORGN1, SH1 and TG1. The rest (HA, TBI, IPS) is not
/// the monitor's to compare.
pub const TCR_WALK: u64 = 0xFFFF_0000;

/// Why a PE's `TTBR1_EL1` is not the locked root.
pub fn ttbr1_error(ttbr1: u64, root: u64) -> Option<&'static str> {
    if ttbr1 & TTBR1_ASID != 0 { return Some("TTBR1 carries an ASID"); }
    if ttbr1 & TTBR1_BADDR != root { return Some("TTBR1 is not the locked root"); }
    None
}

/// Why a PE's `TCR_EL1` reads the kernel half differently from the one the
/// pool was locked under.
pub fn tcr_error(tcr: u64, locked: u64) -> Option<&'static str> {
    if (tcr ^ locked) & TCR_WALK != 0 { Some("TCR walks the kernel half differently") } else { None }
}
