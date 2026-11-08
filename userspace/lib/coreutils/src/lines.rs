// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lines out of a source through a caller-given buffer. A line longer than the
//! buffer comes back in pieces of the buffer's size.

use crate::host::{Error, Host};
use crate::util::{read_src, Src};

pub struct LineReader<'b> {
    buf: &'b mut [u8],
    start: usize,
    end: usize,
    /// Bytes of the line last returned, taken off at the next call.
    taken: usize,
    eof: bool,
}

impl<'b> LineReader<'b> {
    pub fn new(buf: &'b mut [u8]) -> Self {
        LineReader { buf, start: 0, end: 0, taken: 0, eof: false }
    }

    /// The next line without its `\n`; `None` at the end.
    pub fn next<H: Host>(&mut self, h: &mut H, src: Src<H::File>) -> Result<Option<&[u8]>, Error> {
        self.start += self.taken;
        self.taken = 0;
        loop {
            let nl = self.buf[self.start..self.end].iter().position(|&c| c == b'\n');
            if let Some(p) = nl {
                self.taken = p + 1;
                return Ok(Some(&self.buf[self.start..self.start + p]));
            }
            if self.eof {
                if self.start == self.end {
                    return Ok(None);
                }
                self.taken = self.end - self.start;
                return Ok(Some(&self.buf[self.start..self.end]));
            }
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            if self.end == self.buf.len() {
                self.taken = self.end;
                return Ok(Some(&self.buf[..self.end]));
            }
            let n = read_src(h, src, &mut self.buf[self.end..])?;
            if n == 0 {
                self.eof = true;
            } else {
                self.end += n;
            }
        }
    }
}
