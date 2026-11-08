// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The one argument parser of every tool: short flags, bundled (`-rf`), flags
//! with a value (`-n5`, `-n 5`), `-NUM` for the tools that take a count that
//! way, operands in any position, and `--` to end the flags. No long options.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item<'a> {
    Flag(u8),
    Val(u8, &'a [u8]),
    Operand(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgError {
    Unknown(u8),
    MissingValue(u8),
}

/// The value item `-NUM` yields, when the spec holds [`NUM`].
pub const NUM: u8 = b'#';

pub struct Argp<'a> {
    args: &'a [&'a [u8]],
    i: usize,
    /// What is left of the bundle being read.
    bundle: &'a [u8],
    no_more_flags: bool,
    /// `x` flag, `x:` flag with a value, `#` for `-NUM`.
    spec: &'static [u8],
}

impl<'a> Argp<'a> {
    pub fn new(args: &'a [&'a [u8]], spec: &'static [u8]) -> Self {
        Argp { args, i: 0, bundle: b"", no_more_flags: false, spec }
    }

    fn takes_value(&self, c: u8) -> Option<bool> {
        let k = self.spec.iter().position(|&s| s == c && c != b':')?;
        Some(self.spec.get(k + 1) == Some(&b':'))
    }

    pub fn next(&mut self) -> Option<Result<Item<'a>, ArgError>> {
        if let Some((&c, rest)) = self.bundle.split_first() {
            return Some(self.flag(c, rest));
        }
        let a = *self.args.get(self.i)?;
        self.i += 1;
        if self.no_more_flags || a.len() < 2 || a[0] != b'-' {
            return Some(Ok(Item::Operand(a)));
        }
        if a == b"--" {
            self.no_more_flags = true;
            return self.next();
        }
        if a[1].is_ascii_digit() {
            // `-5` is a count where the tool takes one, else a negative number.
            if self.spec.contains(&NUM) && a[1..].iter().all(|c| c.is_ascii_digit()) {
                return Some(Ok(Item::Val(NUM, &a[1..])));
            }
            return Some(Ok(Item::Operand(a)));
        }
        Some(self.flag(a[1], &a[2..]))
    }

    fn flag(&mut self, c: u8, rest: &'a [u8]) -> Result<Item<'a>, ArgError> {
        self.bundle = b"";
        match self.takes_value(c) {
            None => Err(ArgError::Unknown(c)),
            Some(false) => {
                #[cfg(not(feature = "args-bundle-canary"))]
                {
                    self.bundle = rest;
                }
                #[cfg(feature = "args-bundle-canary")]
                let _ = rest;
                Ok(Item::Flag(c))
            }
            Some(true) => {
                if !rest.is_empty() {
                    return Ok(Item::Val(c, rest));
                }
                match self.args.get(self.i) {
                    Some(v) => {
                        self.i += 1;
                        Ok(Item::Val(c, v))
                    }
                    None => Err(ArgError::MissingValue(c)),
                }
            }
        }
    }
}

/// A decimal `u64`, `None` for anything else.
pub fn parse_u64(a: &[u8]) -> Option<u64> {
    if a.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &c in a {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

/// A decimal `i64` with an optional sign.
pub fn parse_i64(a: &[u8]) -> Option<i64> {
    let (neg, d) = match a.split_first() {
        Some((b'-', d)) => (true, d),
        Some((b'+', d)) => (false, d),
        _ => (false, a),
    };
    let v = parse_u64(d)?;
    if neg { 0i64.checked_sub_unsigned(v) } else { i64::try_from(v).ok() }
}
