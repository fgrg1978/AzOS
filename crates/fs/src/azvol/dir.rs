// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Directory blocks. A directory is a file whose data is a sequence of
//! records, each within one block:
//!
//! ```text
//!   0 ino u64 (0 = deleted)   8 rec_len u16   10 name_len u8   11 kind u8
//!  12 reserved u32            16 name bytes, record padded to 8
//! ```
//!
//! `rec_len == 0` ends the block's records (a fresh block is all zero). A
//! lookup is a linear scan; a hashed or tree-shaped directory is a later
//! format revision (the inode `flags` field is where it will be declared).
//! Pure functions over a block image, no I/O.

use alloc::vec::Vec;

use super::layout::{rd16, rd64, wr16, wr64, BLOCK_SIZE, MAX_NAME};
use super::Error;

pub const REC_HDR: usize = 16;
pub const MIN_REC: usize = 24;

#[derive(Clone, Copy, Debug)]
pub struct Rec {
    pub off: usize,
    pub rec_len: usize,
    pub ino: u64,
    pub kind: u8,
    pub name_len: usize,
}

/// Bytes a record for a name of `name_len` bytes occupies.
pub fn rec_need(name_len: usize) -> usize {
    (REC_HDR + name_len + 7) & !7
}

pub fn name_ok(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name != b"."
        && name != b".."
        && !name.iter().any(|&c| c == 0 || c == b'/')
}

/// The record at `off`, or `None` at the end of the block's records.
fn rec_at(b: &[u8], off: usize) -> Result<Option<Rec>, Error> {
    if off + REC_HDR > BLOCK_SIZE {
        return Ok(None);
    }
    let rec_len = rd16(b, off + 8) as usize;
    if rec_len == 0 {
        return Ok(None);
    }
    if rec_len % 8 != 0 || rec_len < MIN_REC || off + rec_len > BLOCK_SIZE {
        return Err(Error::Corrupt("directory record length"));
    }
    let ino = rd64(b, off);
    let name_len = b[off + 10] as usize;
    if ino != 0 && (name_len == 0 || REC_HDR + name_len > rec_len) {
        return Err(Error::Corrupt("directory name length"));
    }
    Ok(Some(Rec { off, rec_len, ino, kind: b[off + 11], name_len }))
}

pub fn name_of<'a>(b: &'a [u8], r: &Rec) -> &'a [u8] {
    &b[r.off + REC_HDR..r.off + REC_HDR + r.name_len]
}

pub fn find(b: &[u8], name: &[u8]) -> Result<Option<Rec>, Error> {
    let mut off = 0;
    while let Some(r) = rec_at(b, off)? {
        if r.ino != 0 && name_of(b, &r) == name {
            return Ok(Some(r));
        }
        off += r.rec_len;
    }
    Ok(None)
}

fn write_rec(b: &mut [u8], off: usize, rec_len: usize, ino: u64, kind: u8, name: &[u8]) {
    wr64(b, off, ino);
    wr16(b, off + 8, rec_len as u16);
    b[off + 10] = name.len() as u8;
    b[off + 11] = kind;
    for x in b[off + 12..off + 16].iter_mut() {
        *x = 0;
    }
    b[off + REC_HDR..off + REC_HDR + name.len()].copy_from_slice(name);
}

/// Place a record in this block; false if it does not fit.
pub fn insert(b: &mut [u8], name: &[u8], ino: u64, kind: u8) -> Result<bool, Error> {
    let need = rec_need(name.len());
    let mut off = 0;
    loop {
        match rec_at(b, off)? {
            Some(r) => {
                if r.ino == 0 && r.rec_len >= need {
                    let rest = r.rec_len - need;
                    if rest >= MIN_REC {
                        write_rec(b, off, need, ino, kind, name);
                        // the remainder is a deleted record of its own
                        wr64(b, off + need, 0);
                        wr16(b, off + need + 8, rest as u16);
                        b[off + need + 10] = 0;
                    } else {
                        write_rec(b, off, r.rec_len, ino, kind, name);
                    }
                    return Ok(true);
                }
                off += r.rec_len;
            }
            None => {
                if off + need <= BLOCK_SIZE {
                    write_rec(b, off, need, ino, kind, name);
                    return Ok(true);
                }
                return Ok(false);
            }
        }
    }
}

/// Mark the record deleted (its bytes stay; the slot is reusable).
pub fn remove(b: &mut [u8], r: &Rec) {
    wr64(b, r.off, 0);
}

pub fn has_entries(b: &[u8]) -> Result<bool, Error> {
    let mut off = 0;
    while let Some(r) = rec_at(b, off)? {
        if r.ino != 0 {
            return Ok(true);
        }
        off += r.rec_len;
    }
    Ok(false)
}

/// Every live record of the block, as `(name, ino, kind)`.
pub fn list(b: &[u8], out: &mut Vec<(Vec<u8>, u64, u8)>) -> Result<(), Error> {
    let mut off = 0;
    while let Some(r) = rec_at(b, off)? {
        if r.ino != 0 {
            out.push((name_of(b, &r).to_vec(), r.ino, r.kind));
        }
        off += r.rec_len;
    }
    Ok(())
}
