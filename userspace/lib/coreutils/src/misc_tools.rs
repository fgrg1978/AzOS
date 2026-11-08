// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The small tools: date env pwd basename dirname seq printf.

use crate::argp::{parse_i64, parse_u64, Argp, Item};
use crate::date::format;
use crate::host::{Error, Host};
use crate::path::{base_name, dir_name};
use crate::util::*;

pub fn date<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"date [-u] [+FORMAT]";
    let mut fmt: &[u8] = b"%Y-%m-%d %H:%M:%S UTC";
    let mut p = Argp::new(args, b"u");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(_)) => {}
            Ok(Item::Operand(a)) if a.starts_with(b"+") => fmt = &a[1..],
            Ok(Item::Operand(_)) => {
                say(h, b"date", b"", b"the clock is set by the time sources (ntp, ptp), not by hand");
                return USAGE;
            }
            Ok(_) => return usage(h, b"date", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"date", e),
        }
    }
    let Some(ns) = h.wall_ns() else {
        say(h, b"date", b"", b"the wall clock is not set yet (no time source has answered; see ntp)");
        return FAILED;
    };
    if format(h, fmt, ns / 1_000_000_000).and_then(|_| put(h, b"\n")).is_err() {
        return FAILED;
    }
    OK
}

pub fn env<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    if !args.is_empty() {
        return usage(h, b"env", b"env (prints the environment; it starts no program)");
    }
    let mut i = 0;
    while let Some(kv) = h.env(i) {
        // The borrow of `h` ends with the copy: the line goes out whole.
        let mut line = [0u8; 256];
        let k = kv.len().min(line.len() - 1);
        line[..k].copy_from_slice(&kv[..k]);
        line[k] = b'\n';
        if h.out(&line[..k + 1]).is_err() {
            return FAILED;
        }
        i += 1;
    }
    OK
}

pub fn pwd<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    if !args.is_empty() {
        return usage(h, b"pwd", b"pwd");
    }
    let mut line = [0u8; crate::path::PATH_MAX + 1];
    let c = h.cwd();
    let k = c.len().min(crate::path::PATH_MAX);
    line[..k].copy_from_slice(&c[..k]);
    line[k] = b'\n';
    if h.out(&line[..k + 1]).is_err() { FAILED } else { OK }
}

pub fn basename<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    let (Some(&name), suffix) = (args.first(), args.get(1)) else {
        return usage(h, b"basename", b"basename NAME [SUFFIX]");
    };
    if args.len() > 2 {
        return usage(h, b"basename", b"basename NAME [SUFFIX]");
    }
    let mut b = base_name(name);
    if let Some(s) = suffix {
        if b.len() > s.len() && b.ends_with(s) {
            b = &b[..b.len() - s.len()];
        }
    }
    if put(h, b).and_then(|_| put(h, b"\n")).is_err() { FAILED } else { OK }
}

pub fn dirname<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    if args.is_empty() {
        return usage(h, b"dirname", b"dirname NAME...");
    }
    for &a in args {
        if put(h, dir_name(a)).and_then(|_| put(h, b"\n")).is_err() {
            return FAILED;
        }
    }
    OK
}

pub fn seq<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"seq [-s SEP] [FIRST [STEP]] LAST";
    let mut sep: &[u8] = b"\n";
    let mut nums = [0i64; 3];
    let mut n = 0;
    let mut p = Argp::new(args, b"s:");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Val(_, v)) => sep = v,
            Ok(Item::Operand(a)) if n < 3 => match parse_i64(a) {
                Some(v) => {
                    nums[n] = v;
                    n += 1;
                }
                None => {
                    say(h, b"seq", a, b"not an integer");
                    return USAGE;
                }
            },
            Ok(_) => return usage(h, b"seq", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"seq", e),
        }
    }
    let (first, step, last) = match n {
        1 => (1, 1, nums[0]),
        2 => (nums[0], 1, nums[1]),
        3 => (nums[0], nums[1], nums[2]),
        _ => return usage(h, b"seq", USAGE_TEXT),
    };
    if step == 0 {
        say(h, b"seq", b"", b"the step is zero");
        return USAGE;
    }
    let mut v = first;
    let mut started = false;
    while if step > 0 { v <= last } else { v >= last } {
        let r = (|| -> Result<(), Error> {
            if started {
                put(h, sep)?;
            }
            put_i64(h, v)
        })();
        if r.is_err() {
            return OK;
        }
        started = true;
        match v.checked_add(step) {
            Some(x) => v = x,
            None => break,
        }
    }
    if started && put(h, b"\n").is_err() {
        return FAILED;
    }
    OK
}

fn radix(mut v: u64, base: u64, upper: bool, out: &mut [u8; 64]) -> &[u8] {
    let digits: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = digits[(v % base) as usize];
        v /= base;
        if v == 0 {
            break;
        }
    }
    &out[i..]
}

/// `body` in a field of `width`, left- or right-aligned, padded with spaces
/// or zeros.
fn field<H: Host>(h: &mut H, body: &[u8], width: usize, left: bool, zero: bool) -> Result<(), Error> {
    let pad = width.saturating_sub(body.len());
    if !left {
        for _ in 0..pad {
            put(h, if zero { b"0" } else { b" " })?;
        }
    }
    put(h, body)?;
    if left {
        for _ in 0..pad {
            put(h, b" ")?;
        }
    }
    Ok(())
}

/// The format once; `next` is the index of the next argument to use.
fn printf_once<H: Host>(h: &mut H, fmt: &[u8], args: &[&[u8]], next: &mut usize, status: &mut i32) -> Result<(), Error> {
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c == b'\\' {
            let e = fmt.get(i).copied().unwrap_or(b'\\');
            i += 1;
            let out = match e {
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'a' => 7,
                b'0' => 0,
                other => other,
            };
            put(h, &[out])?;
            continue;
        }
        if c != b'%' {
            put(h, &[c])?;
            continue;
        }
        let (mut left, mut zero, mut width) = (false, false, 0usize);
        while let Some(&f) = fmt.get(i) {
            match f {
                b'-' => left = true,
                b'0' => zero = true,
                _ => break,
            }
            i += 1;
        }
        while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
            width = width * 10 + (d - b'0') as usize;
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else { return put(h, b"%") };
        i += 1;
        if conv == b'%' {
            put(h, b"%")?;
            continue;
        }
        let arg: &[u8] = args.get(*next).copied().unwrap_or(b"");
        *next += 1;
        let mut buf = [0u8; 64];
        match conv {
            b's' => field(h, arg, width, left, false)?,
            b'c' => field(h, &arg[..arg.len().min(1)], width, left, false)?,
            b'd' | b'i' => {
                let v = if arg.is_empty() { Some(0) } else { parse_i64(arg) };
                let v = v.unwrap_or_else(|| {
                    *status = FAILED;
                    0
                });
                let mut d = [0u8; 64];
                let digits = radix(v.unsigned_abs(), 10, false, &mut d);
                let mut body = [0u8; 65];
                let neg = v < 0;
                body[0] = b'-';
                body[neg as usize..neg as usize + digits.len()].copy_from_slice(digits);
                field(h, &body[..neg as usize + digits.len()], width, left, zero)?
            }
            b'u' | b'x' | b'X' | b'o' => {
                let v = if arg.is_empty() { Some(0) } else { parse_u64(arg) };
                let v = v.unwrap_or_else(|| {
                    *status = FAILED;
                    0
                });
                let base = match conv {
                    b'o' => 8,
                    b'u' => 10,
                    _ => 16,
                };
                field(h, radix(v, base, conv == b'X', &mut buf), width, left, zero)?
            }
            _ => {
                *status = USAGE;
                put(h, &[b'%', conv])?
            }
        }
    }
    Ok(())
}

pub fn printf<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    let Some((&fmt, rest)) = args.split_first() else {
        return usage(h, b"printf", b"printf FORMAT [ARGUMENT...]");
    };
    let mut status = OK;
    let mut next = 0;
    // The format is used again while arguments remain.
    loop {
        let before = next;
        if printf_once(h, fmt, rest, &mut next, &mut status).is_err() {
            return FAILED;
        }
        if next >= rest.len() || next == before {
            break;
        }
    }
    if status == FAILED {
        say(h, b"printf", b"", b"an argument is not a number");
    }
    status
}
