// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A console line built on the stack. The tasks hold no static data (U-mode
//! reaches only its own region), so the buffer is the caller's.

use azos_libsys::print;

/// One console line built in a buffer and written with one call.
pub struct Line {
    buf: [u8; 128],
    n: usize,
}

impl Line {
    /// An empty line.
    pub fn new() -> Self {
        Line { buf: [0; 128], n: 0 }
    }

    /// Append bytes (truncated at the buffer's end).
    pub fn s(&mut self, b: &[u8]) -> &mut Self {
        let take = b.len().min(self.buf.len() - self.n);
        self.buf[self.n..self.n + take].copy_from_slice(&b[..take]);
        self.n += take;
        self
    }

    /// Append a signed decimal.
    pub fn i(&mut self, v: isize) -> &mut Self {
        if v < 0 {
            self.s(b"-");
        }
        let mut n = v.unsigned_abs();
        let mut tmp = [0u8; 12];
        let mut i = tmp.len();
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        }
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        self.s(&tmp[i..])
    }

    /// End the line and write it.
    pub fn flush(&mut self) {
        self.s(b"\n");
        print(&self.buf[..self.n]);
        self.n = 0;
    }
}
