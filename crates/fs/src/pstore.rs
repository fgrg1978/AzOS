// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Panic record kept in a reserved RAM region across a warm reboot
//! (pstore/ramoops-like).
//!
//! The panic handler cannot always write `/fat/CRASH.LOG`: it skips the
//! write when the VFS or FAT32 locks are held, so a panic inside the
//! filesystem used to leave no record. The handler now also writes the same
//! entry line into a RAM region that the kernel never hands to the page
//! allocator (`kernel/src/pstore.rs` reserves it). Main memory keeps its
//! contents across a warm reset, so the next boot finds the record, checks
//! it, appends it to `/fat/CRASH.LOG` through the normal file path and
//! clears it.
//!
//! This file is the record format only: plain functions over a byte slice,
//! no lock, no allocation, no `cfg(feature)` (it is `#[path]`-pulled into
//! `tests/host/fs-tests`, which runs with warnings as errors).
//!
//! Layout, little-endian:
//!
//! ```text
//!   0   8  magic        b"KPSTORE1"
//!   8   4  version      1
//!  12   4  payload_len  bytes of payload stored
//!  16   4  crc32        IEEE CRC-32 of bytes [8, 16) followed by the payload
//!  20   4  reserved     0
//!  24   n  payload
//! ```
//!
//! The magic is written last, after a release fence, so a record torn by a
//! reset in the middle of the write has no magic and reads as empty. A
//! region that holds the magic but fails the length or CRC check is a
//! record that was damaged after it was written (or a bit flip in RAM): it
//! is reported, never copied.

use core::sync::atomic::{fence, Ordering};

/// First eight bytes of a written record.
pub const PSTORE_MAGIC: [u8; 8] = *b"KPSTORE1";
/// Format version this file writes and accepts.
pub const PSTORE_VERSION: u32 = 1;
/// Bytes before the payload.
pub const PSTORE_HEADER_LEN: usize = 24;
/// Prefix of every line the recovery path appends to `/fat/CRASH.LOG`.
pub const PSTORE_LOG_PREFIX: &[u8] = b"[pstore] ";

/// Why a region holding the magic was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The version field names a format this build does not read.
    Version(u32),
    /// The length field does not fit the region.
    Length { len: u32, cap: usize },
    /// The CRC over version, length and payload does not match.
    Checksum { stored: u32, computed: u32 },
}

/// What a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record<'a> {
    /// No magic: nothing was written, the record was cleared, or a write
    /// was cut short before its last step.
    Empty,
    /// A complete record; the slice is its payload.
    Valid(&'a [u8]),
    /// The magic is present but the rest does not check out.
    Rejected(Reject),
}

/// IEEE CRC-32 (reflected, polynomial 0xEDB88320), bitwise: no table, so
/// nothing to initialise and nothing in `.rodata` for the panic path to
/// depend on. Pass `0` as `crc` to start; feed the result back to continue.
pub fn crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            let mask = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !c
}

/// Payload bytes a region of `region_len` bytes can hold.
pub fn capacity(region_len: usize) -> usize {
    region_len.saturating_sub(PSTORE_HEADER_LEN)
}

fn record_crc(version_and_len: &[u8], payload: &[u8]) -> u32 {
    crc32(crc32(0, version_and_len), payload)
}

/// Write `payload` as a record into `region`, truncated to the region's
/// capacity. Returns the payload bytes stored, or 0 if the region is too
/// small to hold a header (nothing is written then).
///
/// Order: clear the magic, payload, header, CRC, release fence, magic. A
/// reset at any point before the last store leaves no magic.
pub fn encode(region: &mut [u8], payload: &[u8]) -> usize {
    if region.len() < PSTORE_HEADER_LEN {
        return 0;
    }
    region[..8].copy_from_slice(&[0u8; 8]);
    fence(Ordering::Release);
    let n = payload.len().min(capacity(region.len()));
    region[PSTORE_HEADER_LEN..PSTORE_HEADER_LEN + n].copy_from_slice(&payload[..n]);
    region[8..12].copy_from_slice(&PSTORE_VERSION.to_le_bytes());
    region[12..16].copy_from_slice(&(n as u32).to_le_bytes());
    region[20..24].copy_from_slice(&[0u8; 4]);
    let crc = record_crc(&region[8..16], &region[PSTORE_HEADER_LEN..PSTORE_HEADER_LEN + n]);
    region[16..20].copy_from_slice(&crc.to_le_bytes());
    fence(Ordering::Release);
    region[..8].copy_from_slice(&PSTORE_MAGIC);
    fence(Ordering::Release);
    n
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Read what `region` holds. Never writes.
pub fn decode(region: &[u8]) -> Record<'_> {
    if region.len() < PSTORE_HEADER_LEN || region[..8] != PSTORE_MAGIC {
        return Record::Empty;
    }
    let version = le_u32(&region[8..12]);
    if version != PSTORE_VERSION {
        return Record::Rejected(Reject::Version(version));
    }
    let len = le_u32(&region[12..16]);
    let cap = capacity(region.len());
    if len as usize > cap {
        return Record::Rejected(Reject::Length { len, cap });
    }
    let payload = &region[PSTORE_HEADER_LEN..PSTORE_HEADER_LEN + len as usize];
    let stored = le_u32(&region[16..20]);
    let computed = record_crc(&region[8..16], payload);
    if stored != computed {
        return Record::Rejected(Reject::Checksum { stored, computed });
    }
    Record::Valid(payload)
}

/// Forget the record: magic first (so a reset mid-clear reads as empty),
/// then the rest of the header. The payload bytes are left as they are.
pub fn clear(region: &mut [u8]) {
    let h = region.len().min(PSTORE_HEADER_LEN);
    let m = h.min(8);
    region[..m].copy_from_slice(&[0u8; 8][..m]);
    fence(Ordering::Release);
    for b in &mut region[m..h] {
        *b = 0;
    }
    fence(Ordering::Release);
}

fn put(out: &mut [u8], pos: usize, s: &[u8]) -> usize {
    let n = s.len().min(out.len().saturating_sub(pos));
    out[pos..pos + n].copy_from_slice(&s[..n]);
    pos + n
}

fn put_hex32(out: &mut [u8], pos: usize, v: u32) -> usize {
    let mut tmp = [0u8; 10];
    tmp[0] = b'0';
    tmp[1] = b'x';
    for i in 0..8 {
        let nib = ((v >> (28 - 4 * i)) & 0xF) as u8;
        tmp[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    put(out, pos, &tmp)
}

fn put_dec(out: &mut [u8], pos: usize, mut v: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    put(out, pos, &tmp[i..])
}

/// The line the recovery path appends to `/fat/CRASH.LOG` for `rec`, built
/// into `out`; returns its length (0 for `Empty`). Always ends in `\n` when
/// `out` has room for one.
///
/// A valid record becomes `[pstore] <payload>`. A rejected one becomes a
/// note that a record was found and discarded, with the reason: random RAM
/// at power-on does not carry the 8-byte magic, so a rejected record means
/// a panic did happen and its text was lost.
pub fn recovery_line(rec: &Record<'_>, out: &mut [u8]) -> usize {
    let mut p = 0;
    match *rec {
        Record::Empty => return 0,
        Record::Valid(payload) => {
            p = put(out, p, PSTORE_LOG_PREFIX);
            p = put(out, p, payload);
        }
        Record::Rejected(why) => {
            p = put(out, p, PSTORE_LOG_PREFIX);
            p = put(out, p, b"corrupt record discarded: ");
            match why {
                Reject::Version(v) => {
                    p = put(out, p, b"version ");
                    p = put_dec(out, p, v as u64);
                }
                Reject::Length { len, cap } => {
                    p = put(out, p, b"length ");
                    p = put_dec(out, p, len as u64);
                    p = put(out, p, b" > capacity ");
                    p = put_dec(out, p, cap as u64);
                }
                Reject::Checksum { stored, computed } => {
                    p = put(out, p, b"checksum stored ");
                    p = put_hex32(out, p, stored);
                    p = put(out, p, b" computed ");
                    p = put_hex32(out, p, computed);
                }
            }
        }
    }
    if p > 0 && out[p - 1] != b'\n' {
        if p < out.len() {
            out[p] = b'\n';
            p += 1;
        } else {
            out[p - 1] = b'\n';
        }
    }
    p
}
