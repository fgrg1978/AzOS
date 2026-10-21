// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Console lines with numbers (libsys prints bytes only), and the whole-file
//! read the start-up uses.

use azos_libsys as sys;

pub struct Line {
    buf: [u8; 160],
    len: usize,
}

impl Line {
    pub fn new(s: &[u8]) -> Self {
        let mut l = Line { buf: [0; 160], len: 0 };
        l.push(s);
        l
    }
    pub fn push(&mut self, s: &[u8]) -> &mut Self {
        for &b in s {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        self
    }
    pub fn num(&mut self, mut v: u64) -> &mut Self {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(&d[i..])
    }
    pub fn hex(&mut self, v: u32) -> &mut Self {
        let mut d = [0u8; 10];
        d[0] = b'0';
        d[1] = b'x';
        for k in 0..8 {
            let nib = ((v >> (28 - 4 * k)) & 0xF) as u8;
            d[2 + k] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        }
        self.push(&d)
    }
    pub fn hex64(&mut self, v: u64) -> &mut Self {
        self.push(b"0x");
        for k in 0..16 {
            let nib = ((v >> (60 - 4 * k)) & 0xF) as u8;
            self.push(&[if nib < 10 { b'0' + nib } else { b'a' + nib - 10 }]);
        }
        self
    }
    pub fn print(&self) {
        sys::println(&self.buf[..self.len]);
    }
}

/// Read a whole (small) file into `buf`. `None` when it cannot be opened or
/// read; otherwise the bytes read, up to `buf.len()`.
pub fn read_file(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    let h = sys::open_root(path, 0);
    if h < 0 {
        return None;
    }
    let mut n = 0usize;
    while n < buf.len() {
        let r = sys::file_read_typed(h as u32, &mut buf[n..]);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    let _ = sys::close_typed(h as u32);
    if n == 0 { None } else { Some(n) }
}
