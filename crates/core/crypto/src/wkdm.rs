// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! WKdm page compression (Wilson, Kaplan, Smaragdakis: "The Case for
//! Compressed Caching in Virtual Memory Systems", USENIX 1999).
//!
//! WKdm exploits what memory pages actually hold: zero words, repeated
//! words, and words that differ from a recent one only in the low bits
//! (pointers into one region, small integers beside large ones). Each
//! 32-bit word is looked up in a 16-entry direct-mapped dictionary indexed
//! by a hash of its upper 22 bits and coded as one of four classes:
//!
//! | tag | class   | payload                                        |
//! |-----|---------|------------------------------------------------|
//! | 0   | zero    | none                                           |
//! | 1   | partial | 4-bit dictionary index + the low 10 bits       |
//! | 2   | miss    | the full 32-bit word (dictionary slot replaced) |
//! | 3   | exact   | 4-bit dictionary index                         |
//!
//! A partial hit also replaces the slot. The encoder and decoder run the
//! same dictionary, so nothing but the tags and payloads is stored. The
//! algorithm is size-independent: 4 KiB, 16 KiB and 64 KiB pages differ only
//! in word count. The slot hash is ours (the paper fixes the structure, not
//! the hash), so this stream is not bit-compatible with other WKdm
//! implementations.
//!
//! ## Stream layout (little-endian words)
//!
//! ```text
//! [0] word count n     [1] index section (word offset)
//! [2] low-bits section [3] end (total words)
//! tags:   n/16 words, 2 bits per word, 16 per word
//! misses: full words, in page order
//! index:  4-bit dictionary indices, 8 per word (partial + exact, page order)
//! low:    10-bit low parts, 3 per word (partial, page order)
//! ```
//!
//! An all-zero page compresses to zero bytes (`compress` returns `Ok(0)`,
//! `decompress` of an empty stream zero-fills): the fast path costs one
//! pass of OR over the page and no output. No allocation: the encoder keeps
//! a 64-byte dictionary and writes straight into the caller's buffer in two
//! passes (tags and misses, then indices and low bits, whose section sizes
//! are only known after the first), so a page never needs a staging copy.

const HEADER_WORDS: usize = 4;
const TAG_ZERO: u32 = 0;
const TAG_PARTIAL: u32 = 1;
const TAG_MISS: u32 = 2;
const TAG_EXACT: u32 = 3;
const LOW_MASK: u32 = 0x3ff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Page length is not 4096, 16384 or 65536.
    BadPageSize,
    /// The page does not compress to fewer bytes than the page itself, or
    /// than the output buffer holds. Store it raw.
    Incompressible,
    /// The stream is not a well-formed WKdm stream for this page size.
    Malformed,
}

/// Supported page sizes: 4 KiB, 16 KiB, 64 KiB.
pub const fn is_page_size(len: usize) -> bool {
    len == 4096 || len == 16384 || len == 65536
}

#[inline(always)]
fn slot(w: u32) -> usize {
    ((w >> 10).wrapping_mul(0x9E37_79B1) >> 28) as usize
}

#[inline(always)]
fn word_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]])
}

#[inline(always)]
fn put_word(b: &mut [u8], i: usize, w: u32) {
    b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
}

fn is_zero_page(page: &[u8]) -> bool {
    let mut acc = 0u64;
    for c in page.chunks_exact(8) {
        acc |= u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    acc == 0
}

/// Compress `page` into `out`; returns the stream length. `Ok(0)` means the
/// page is all zeros. The result is always shorter than `page.len()` and
/// fits `out`, else `Err(Incompressible)`.
pub fn compress(page: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !is_page_size(page.len()) {
        return Err(Error::BadPageSize);
    }
    if is_zero_page(page) {
        return Ok(0);
    }
    let n = page.len() / 4;
    let tag_words = n / 16;
    let limit = out.len().min(page.len() - 1);
    let miss_start = HEADER_WORDS + tag_words;
    if limit < miss_start * 4 {
        return Err(Error::Incompressible);
    }

    // Pass 1: classify every word; tags and miss words go straight out.
    let mut dict = [0u32; 16];
    let (mut n_miss, mut n_idx, mut n_low) = (0usize, 0usize, 0usize);
    let mut tag_acc = 0u32;
    for i in 0..n {
        let w = word_at(page, i);
        let tag = if w == 0 {
            TAG_ZERO
        } else {
            let s = slot(w);
            let d = dict[s];
            if d == w {
                n_idx += 1;
                TAG_EXACT
            } else if (d ^ w) >> 10 == 0 {
                dict[s] = w;
                n_idx += 1;
                n_low += 1;
                TAG_PARTIAL
            } else {
                dict[s] = w;
                if (miss_start + n_miss + 1) * 4 > limit {
                    return Err(Error::Incompressible);
                }
                put_word(out, miss_start + n_miss, w);
                n_miss += 1;
                TAG_MISS
            }
        };
        tag_acc |= tag << (2 * (i % 16));
        if i % 16 == 15 {
            put_word(out, HEADER_WORDS + i / 16, tag_acc);
            tag_acc = 0;
        }
    }

    let idx_start = miss_start + n_miss;
    let low_start = idx_start + n_idx.div_ceil(8);
    let end = low_start + n_low.div_ceil(3);
    if end * 4 > limit {
        return Err(Error::Incompressible);
    }

    // Pass 2: indices and low bits. The slot of a partial/exact word is its
    // own hash, so the dictionary contents are not needed again.
    let (mut ip, mut lp) = (0usize, 0usize);
    let (mut idx_acc, mut low_acc) = (0u32, 0u32);
    for i in 0..n {
        let tag = (word_at(out, HEADER_WORDS + i / 16) >> (2 * (i % 16))) & 3;
        if tag == TAG_PARTIAL || tag == TAG_EXACT {
            let w = word_at(page, i);
            idx_acc |= (slot(w) as u32) << (4 * (ip % 8));
            ip += 1;
            if ip % 8 == 0 {
                put_word(out, idx_start + ip / 8 - 1, idx_acc);
                idx_acc = 0;
            }
            if tag == TAG_PARTIAL {
                low_acc |= (w & LOW_MASK) << (10 * (lp % 3));
                lp += 1;
                if lp % 3 == 0 {
                    put_word(out, low_start + lp / 3 - 1, low_acc);
                    low_acc = 0;
                }
            }
        }
    }
    if ip % 8 != 0 {
        put_word(out, idx_start + ip / 8, idx_acc);
    }
    if lp % 3 != 0 {
        put_word(out, low_start + lp / 3, low_acc);
    }

    put_word(out, 0, n as u32);
    put_word(out, 1, idx_start as u32);
    put_word(out, 2, low_start as u32);
    put_word(out, 3, end as u32);
    Ok(end * 4)
}

/// Decompress `src` (from [`compress`]) into `page`, whose length selects
/// the page size. An empty `src` is the zero page. Every offset is checked
/// against the stream, so a corrupted stream yields `Err(Malformed)`, never
/// an out-of-bounds access.
pub fn decompress(src: &[u8], page: &mut [u8]) -> Result<(), Error> {
    if !is_page_size(page.len()) {
        return Err(Error::BadPageSize);
    }
    if src.is_empty() {
        page.fill(0);
        return Ok(());
    }
    let n = page.len() / 4;
    let miss_start = HEADER_WORDS + n / 16;
    if src.len() % 4 != 0 || src.len() < miss_start * 4 {
        return Err(Error::Malformed);
    }
    let total = src.len() / 4;
    let (idx_start, low_start, end) =
        (word_at(src, 1) as usize, word_at(src, 2) as usize, word_at(src, 3) as usize);
    if word_at(src, 0) as usize != n
        || end != total
        || !(miss_start <= idx_start && idx_start <= low_start && low_start <= end)
    {
        return Err(Error::Malformed);
    }

    let mut dict = [0u32; 16];
    let (mut mp, mut ip, mut lp) = (miss_start, 0usize, 0usize);
    for i in 0..n {
        let tag = (word_at(src, HEADER_WORDS + i / 16) >> (2 * (i % 16))) & 3;
        let w = match tag {
            TAG_ZERO => 0,
            TAG_MISS => {
                if mp >= idx_start {
                    return Err(Error::Malformed);
                }
                let w = word_at(src, mp);
                mp += 1;
                dict[slot(w)] = w;
                w
            }
            _ => {
                let iw = idx_start + ip / 8;
                if iw >= low_start {
                    return Err(Error::Malformed);
                }
                let s = ((word_at(src, iw) >> (4 * (ip % 8))) & 0xf) as usize;
                ip += 1;
                if tag == TAG_EXACT {
                    dict[s]
                } else {
                    let lw = low_start + lp / 3;
                    if lw >= end {
                        return Err(Error::Malformed);
                    }
                    let low = (word_at(src, lw) >> (10 * (lp % 3))) & LOW_MASK;
                    lp += 1;
                    let w = (dict[s] & !LOW_MASK) | low;
                    dict[s] = w;
                    w
                }
            }
        };
        put_word(page, i, w);
    }
    // Sections must be consumed exactly: no trailing or missing payload.
    if mp != idx_start || idx_start + ip.div_ceil(8) != low_start || low_start + lp.div_ceil(3) != end {
        return Err(Error::Malformed);
    }
    Ok(())
}
