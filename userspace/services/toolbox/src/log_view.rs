// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What `log` prints: the kernel log `logd` keeps (Kconfig KLOG), filtered and
//! laid out like a kernel ring buffer dump.
//!
//! ```text
//! [    1.234567] W ipc::trace: [TRACE] op 0x8407 REFUSED
//! ```
//!
//! Pure (no system call): the files are read by `main.rs`, the line grammar is
//! `wire.rs`'s (`crates/drivers/sys/src/klog/wire.rs`, the source `logd` writes
//! them with), and the host tests run this file as it ships
//! (`tests/host/libsys-tests`).

use crate::wire::{self, Line};

/// Which lines `log` shows.
pub struct Filter<'a> {
    /// Lines at or below this level (Linux numbering: 3 err .. 7 debug).
    pub max_level: u8,
    /// Lines whose module starts with this (empty: all).
    pub module: &'a [u8],
}

impl Filter<'_> {
    /// Does `l` pass? The files' own opening lines (`file N`) never do.
    pub fn accepts(&self, l: &Line<'_>) -> bool {
        if wire::head_serial(l).is_some() {
            return false;
        }
        // An unknown level (`?`) is shown: it is not a level to drop.
        (l.level == 0 || l.level <= self.max_level) && l.module.starts_with(self.module)
    }
}

/// A level argument: `e`, `w`, `i`, `d` (or the words `err`, `warn`, `info`,
/// `debug`), or a Linux level 3 to 7.
pub fn parse_level(a: &[u8]) -> Option<u8> {
    match a {
        b"e" | b"err" => Some(wire::LEVEL_ERR),
        b"w" | b"warn" => Some(wire::LEVEL_WARN),
        b"i" | b"info" => Some(wire::LEVEL_INFO),
        b"d" | b"debug" => Some(wire::LEVEL_DEBUG),
        [d @ b'3'..=b'7'] => Some(d - b'0'),
        _ => None,
    }
}

/// Bytes `render` can write at most.
pub const RENDER_MAX: usize = 40 + 4 + wire::MODULE_BYTES + 2 + wire::MSG_BYTES + 1;

fn dec(v: u64, width: usize, out: &mut [u8], n: &mut usize) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    let mut v = v;
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for _ in (d.len() - i)..width {
        out[*n] = b'0';
        *n += 1;
    }
    out[*n..*n + d.len() - i].copy_from_slice(&d[i..]);
    *n += d.len() - i;
}

/// One line, laid out; returns its length (at most [`RENDER_MAX`], `out` at
/// least that long). The message is unescaped; a fragment (`I+`) is marked.
pub fn render(l: &Line<'_>, out: &mut [u8]) -> usize {
    let mut n = 0;
    out[n] = b'[';
    n += 1;
    // Seconds, right-aligned in five columns, as a kernel ring buffer dump.
    let secs = l.ts_us / 1_000_000;
    let mut digits = 1;
    let mut t = secs;
    while t >= 10 {
        t /= 10;
        digits += 1;
    }
    for _ in digits..5 {
        out[n] = b' ';
        n += 1;
    }
    dec(secs, 0, out, &mut n);
    out[n] = b'.';
    n += 1;
    dec(l.ts_us % 1_000_000, 6, out, &mut n);
    out[n..n + 2].copy_from_slice(b"] ");
    n += 2;
    out[n] = wire::level_letter(l.level);
    n += 1;
    if l.partial {
        out[n] = b'+';
        n += 1;
    }
    out[n] = b' ';
    n += 1;
    let module = if l.module == b"-" { &b""[..] } else { &l.module[..l.module.len().min(wire::MODULE_BYTES)] };
    out[n..n + module.len()].copy_from_slice(module);
    n += module.len();
    if !module.is_empty() {
        out[n..n + 2].copy_from_slice(b": ");
        n += 2;
    }
    n += wire::unescape(l.msg, &mut out[n..n + wire::MSG_BYTES]);
    out[n] = b'\n';
    n + 1
}

/// The slots of the files in reading order: ascending serial. `files` holds
/// `(serial, slot)` for each file that opened with a serial.
pub fn reading_order(files: &mut [(u64, u8)]) -> impl Iterator<Item = u8> + '_ {
    files.sort_unstable();
    files.iter().map(|f| f.1)
}
