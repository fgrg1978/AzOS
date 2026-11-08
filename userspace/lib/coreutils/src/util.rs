// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What every tool shares: messages, numbers, the input a tool reads, the
//! exit statuses.

use crate::argp::ArgError;
use crate::host::{Error, Host};
use crate::path::PathBuf;

pub const OK: i32 = 0;
pub const FAILED: i32 = 1;
pub const USAGE: i32 = 2;
pub const STOPPED: i32 = 130;

/// `tool: subject: why` on standard error, in one write.
pub fn say<H: Host>(h: &mut H, tool: &[u8], subject: &[u8], why: &[u8]) {
    let mut line = [0u8; 256];
    let mut n = 0;
    for part in [tool, b": ", subject, if subject.is_empty() { b"" } else { b": " }, why, b"\n"] {
        let k = part.len().min(line.len() - n);
        line[n..n + k].copy_from_slice(&part[..k]);
        n += k;
    }
    if n == line.len() {
        line[n - 1] = b'\n';
    }
    h.err(&line[..n]);
}

pub fn say_err<H: Host>(h: &mut H, tool: &[u8], subject: &[u8], e: Error) {
    // A closed output is the reader being done: the tool just stops.
    if e != Error::Closed {
        say(h, tool, subject, e.text());
    }
}

/// The status a failed operation ends the tool with.
pub fn status_of(e: Error) -> i32 {
    match e {
        Error::Interrupted => STOPPED,
        Error::Closed => OK,
        _ => FAILED,
    }
}

pub fn usage<H: Host>(h: &mut H, tool: &[u8], text: &[u8]) -> i32 {
    say(h, tool, b"usage", text);
    USAGE
}

pub fn bad_arg<H: Host>(h: &mut H, tool: &[u8], e: ArgError) -> i32 {
    let (c, why): (u8, &[u8]) = match e {
        ArgError::Unknown(c) => (c, b"unknown option"),
        ArgError::MissingValue(c) => (c, b"option needs a value"),
    };
    let sub = [b'-', c];
    say(h, tool, &sub, why);
    USAGE
}

pub fn put<H: Host>(h: &mut H, b: &[u8]) -> Result<(), Error> {
    h.out(b)
}

/// `v` in decimal.
pub fn fmt_u64(mut v: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &out[i..]
}

pub fn put_u64<H: Host>(h: &mut H, v: u64) -> Result<(), Error> {
    let mut d = [0u8; 20];
    h.out(fmt_u64(v, &mut d))
}

pub fn put_i64<H: Host>(h: &mut H, v: i64) -> Result<(), Error> {
    if v < 0 {
        h.out(b"-")?;
    }
    put_u64(h, v.unsigned_abs())
}

/// `v` zero-padded to `width` digits.
pub fn put_padded<H: Host>(h: &mut H, v: u64, width: usize) -> Result<(), Error> {
    let mut d = [0u8; 20];
    let s = fmt_u64(v, &mut d);
    for _ in s.len()..width {
        h.out(b"0")?;
    }
    h.out(s)
}

/// `path` made absolute against the working directory.
pub fn abs<H: Host>(h: &H, a: &[u8]) -> Result<PathBuf, Error> {
    PathBuf::resolve(h.cwd(), a)
}

/// Where a tool reads from.
#[derive(Clone, Copy)]
pub enum Src<F> {
    Stdin,
    File(F),
}

pub fn read_src<H: Host>(h: &mut H, src: Src<H::File>, buf: &mut [u8]) -> Result<usize, Error> {
    match src {
        Src::Stdin => h.stdin(buf),
        Src::File(f) => h.read(f, buf),
    }
}

/// Run `f` on each input of a tool: its operands as files, or standard input
/// with none (and for `-`). A file that cannot be opened is said and skipped;
/// the status is the worst. `f` gets the operand's name and the source.
pub fn each_input<H: Host>(
    h: &mut H,
    tool: &[u8],
    names: &[&[u8]],
    f: &mut dyn FnMut(&mut H, &[u8], Src<H::File>) -> Result<(), Error>,
) -> i32 {
    let mut status = OK;
    if names.is_empty() {
        return match f(h, b"-", Src::Stdin) {
            Ok(()) => OK,
            Err(e) => {
                say_err(h, tool, b"", e);
                status_of(e)
            }
        };
    }
    for &n in names {
        let r = if n == b"-" {
            f(h, n, Src::Stdin)
        } else {
            match abs(h, n).and_then(|p| h.open(p.as_bytes(), crate::host::Open::Read)) {
                Ok(file) => {
                    let r = f(h, n, Src::File(file));
                    h.close(file);
                    r
                }
                Err(e) => Err(e),
            }
        };
        if let Err(e) = r {
            say_err(h, tool, n, e);
            status = status.max(status_of(e));
            if e == Error::Interrupted {
                break;
            }
        }
    }
    status
}

/// Case-insensitive ASCII equality when `fold`.
pub fn same(a: u8, b: u8, fold: bool) -> bool {
    if fold { a.eq_ignore_ascii_case(&b) } else { a == b }
}
