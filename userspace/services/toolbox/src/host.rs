// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `host NAME`: the addresses of a name, from the stack's resolver.
//!
//! This file is the text of the answer, with no system call in it, so a host
//! test can pull it in with `#[path]` (`tests/host/net-tests`). The two
//! lookups (A, then AAAA) are `main.rs`'s `host()`, through the `net`
//! endpoint's `resolve` op.

use azos_devif::Address;
use core::fmt::{self, Write};

/// `a.b.c.d`.
pub fn write_v4(w: &mut dyn Write, a: &[u8]) -> fmt::Result {
    write!(w, "{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// An IPv6 address in the form of RFC 5952: lowercase, no leading zeros in a
/// group, and the longest run of two or more zero groups (the first, on a
/// tie) written `::`.
pub fn write_v6(w: &mut dyn Write, a: &[u8]) -> fmt::Result {
    let g: [u16; 8] = core::array::from_fn(|i| u16::from_be_bytes([a[2 * i], a[2 * i + 1]]));
    // The longest run of zero groups.
    let (mut best_at, mut best_len) = (0usize, 0usize);
    let mut i = 0;
    while i < 8 {
        if g[i] != 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < 8 && g[i] == 0 {
            i += 1;
        }
        if i - start > best_len {
            (best_at, best_len) = (start, i - start);
        }
    }
    if best_len < 2 {
        best_len = 0;
    }
    let mut i = 0;
    while i < 8 {
        if best_len != 0 && i == best_at {
            w.write_str("::")?;
            i += best_len;
            continue;
        }
        if i != 0 && !(best_len != 0 && i == best_at + best_len) {
            w.write_char(':')?;
        }
        write!(w, "{:x}", g[i])?;
        i += 1;
    }
    Ok(())
}

/// One line of the answer: `NAME has address A` or `NAME has IPv6 address A`,
/// by the length of the address. Nothing is written for an empty one.
pub fn write_line(w: &mut dyn Write, name: &str, a: &Address) -> fmt::Result {
    let mut b = [0u8; 16];
    match a.bytes(&mut b) {
        4 => {
            write!(w, "{} has address ", name)?;
            write_v4(w, &b)?;
        }
        16 => {
            write!(w, "{} has IPv6 address ", name)?;
            write_v6(w, &b)?;
        }
        _ => return Ok(()),
    }
    w.write_char('\n')
}
