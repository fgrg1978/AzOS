// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the four family tools share: output, a decimal parser, the refusal
//! line. Calls only what every tool's profile lists (`write`, `exit`).
//! Pulled into each binary with `#[path]`, so each image compiles only its
//! own family's syscall (`tests/host/seccomp-tests` derives each profile
//! from its binary's files).

#![allow(dead_code)]

use azos_libsys as sys;

pub fn put(fd: u64, b: &[u8]) {
    let mut done = 0usize;
    while done < b.len() {
        let r = sys::write(fd, &b[done..]);
        if r <= 0 {
            return;
        }
        done += r as usize;
    }
}

pub fn put_num(fd: u64, neg: bool, mut v: u64) {
    let mut d = [0u8; 21];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        d[i] = b'-';
    }
    put(fd, &d[i..]);
}

pub fn parse(a: &[u8]) -> Option<u64> {
    if a.is_empty() || a.len() > 10 {
        return None;
    }
    let mut v = 0u64;
    for &b in a {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Some(v)
}

/// `<tool>: <what> refused: <errno>` on stderr; exit code 1.
pub fn refused(tool: &[u8], what: &[u8], r: isize) -> i32 {
    put(2, tool);
    put(2, b": ");
    put(2, what);
    put(2, b" refused: ");
    put_num(2, r < 0, r.unsigned_abs() as u64);
    put(2, b"\n");
    1
}

/// The usage line on stderr; exit code 2.
pub fn usage(line: &[u8]) -> i32 {
    put(2, b"usage: ");
    put(2, line);
    put(2, b"\n");
    2
}
