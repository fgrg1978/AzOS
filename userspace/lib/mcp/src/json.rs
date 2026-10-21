// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! JSON (RFC 8259), strict: the value tree, a parser and a writer.
//!
//! Strict means: the grammar and nothing else (no comments, no trailing commas,
//! no leading zeros, no control characters in strings, no lone surrogates in
//! `\u` escapes); one value and then end of input; an object with a repeated
//! key is refused (JSON-RPC and MCP have no use for "last one wins", and two
//! readers that pick differently are a confusion attack); nesting is limited
//! to [`MAX_DEPTH`] so a hostile document cannot exhaust the stack; the text
//! is limited to [`MAX_LEN`] bytes and an object to [`MAX_MEMBERS`] members,
//! so the quadratic repeated-key check has a small constant bound.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// The deepest nesting of arrays and objects the parser accepts.
pub const MAX_DEPTH: usize = 32;

/// The longest text [`Value::parse`] accepts, in bytes.
pub const MAX_LEN: usize = 1 << 20;

/// The most members one object may have. The repeated-key check compares each
/// new key with the earlier ones, so this caps it at `MAX_MEMBERS^2 / 2`
/// comparisons per object (and `MAX_LEN` bounds how many objects there are).
pub const MAX_MEMBERS: usize = 256;

/// A JSON value. Numbers without a fraction or exponent that fit an `i64` are
/// `Int`; every other number is `Float`. Objects keep their members in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// Why a text is not JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The text ends inside a value, or is empty.
    Eof,
    /// A byte that the grammar does not allow here (the offset).
    Unexpected(usize),
    /// A number that is malformed or not finite.
    BadNumber(usize),
    /// A bad escape, or a lone surrogate, or a control character in a string.
    BadString(usize),
    /// An object repeats a key.
    DuplicateKey(usize),
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A text longer than [`MAX_LEN`] bytes.
    TooLong,
    /// An object with more than [`MAX_MEMBERS`] members.
    TooManyMembers,
    /// Something after the value.
    Trailing(usize),
}

impl Value {
    /// Parse one JSON document.
    pub fn parse(text: &str) -> Result<Value, ParseError> {
        if text.len() > MAX_LEN {
            return Err(ParseError::TooLong);
        }
        let mut p = Parser { b: text.as_bytes(), i: 0 };
        p.ws();
        let v = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            return Err(ParseError::Trailing(p.i));
        }
        Ok(v)
    }

    pub fn str(s: &str) -> Value {
        Value::Str(String::from(s))
    }

    /// An object from `(key, value)` pairs, in the order given.
    pub fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
        Value::Object(members.into_iter().map(|(k, v)| (String::from(k), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(_))
    }

    /// The compact JSON text of the value. A `Float` that is not finite has no
    /// JSON form and is written as `null`.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    pub fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Value::Float(f) if f.is_finite() => {
                let _ = write!(out, "{f}");
            }
            Value::Float(_) => out.push_str("null"),
            Value::Str(s) => write_str(out, s),
            Value::Array(a) => {
                out.push('[');
                for (n, v) in a.iter().enumerate() {
                    if n != 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Value::Object(m) => {
                out.push('{');
                for (n, (k, v)) in m.iter().enumerate() {
                    if n != 0 {
                        out.push(',');
                    }
                    write_str(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// A JSON string literal: `"`, `\` and the control characters escaped,
/// everything else (UTF-8 included) as it is.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<u8, ParseError> {
        self.b.get(self.i).copied().ok_or(ParseError::Eof)
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, ParseError> {
        let w = word.as_bytes();
        match self.b.get(self.i..self.i + w.len()) {
            Some(s) if s == w => {
                self.i += w.len();
                Ok(v)
            }
            Some(_) => Err(ParseError::Unexpected(self.i)),
            None => Err(ParseError::Eof),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek()? {
            b'n' => self.lit("null", Value::Null),
            b't' => self.lit("true", Value::Bool(true)),
            b'f' => self.lit("false", Value::Bool(false)),
            b'"' => Ok(Value::Str(self.string()?)),
            b'[' => {
                if depth >= MAX_DEPTH {
                    return Err(ParseError::TooDeep);
                }
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek()? == b']' {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                loop {
                    self.ws();
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Ok(Value::Array(a));
                        }
                        _ => return Err(ParseError::Unexpected(self.i)),
                    }
                }
            }
            b'{' => {
                if depth >= MAX_DEPTH {
                    return Err(ParseError::TooDeep);
                }
                self.i += 1;
                let mut m: Vec<(String, Value)> = Vec::new();
                self.ws();
                if self.peek()? == b'}' {
                    self.i += 1;
                    return Ok(Value::Object(m));
                }
                loop {
                    self.ws();
                    if self.peek()? != b'"' {
                        return Err(ParseError::Unexpected(self.i));
                    }
                    if m.len() >= MAX_MEMBERS {
                        return Err(ParseError::TooManyMembers);
                    }
                    let at = self.i;
                    let k = self.string()?;
                    if m.iter().any(|(e, _)| *e == k) {
                        return Err(ParseError::DuplicateKey(at));
                    }
                    self.ws();
                    if self.peek()? != b':' {
                        return Err(ParseError::Unexpected(self.i));
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Ok(Value::Object(m));
                        }
                        _ => return Err(ParseError::Unexpected(self.i)),
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseError::Unexpected(self.i)),
        }
    }

    fn digits(&mut self) -> usize {
        let s = self.i;
        while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - s
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        let bad = ParseError::BadNumber(start);
        if self.peek()? == b'-' {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(bad),
        }
        let mut integral = true;
        if self.b.get(self.i) == Some(&b'.') {
            integral = false;
            self.i += 1;
            if self.digits() == 0 {
                return Err(bad);
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            integral = false;
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(bad);
            }
        }
        // The slice is ASCII digits, sign, '.', 'e': valid UTF-8.
        let text = core::str::from_utf8(&self.b[start..self.i]).map_err(|_| bad)?;
        if integral {
            if let Ok(i) = text.parse::<i64>() {
                return Ok(Value::Int(i));
            }
        }
        match text.parse::<f64>() {
            Ok(f) if f.is_finite() => Ok(Value::Float(f)),
            _ => Err(bad),
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let at = self.i;
        let h = self.b.get(self.i..self.i + 4).ok_or(ParseError::Eof)?;
        let mut v = 0u32;
        for &c in h {
            let d = (c as char).to_digit(16).ok_or(ParseError::BadString(at))?;
            v = v << 4 | d;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        // Opening quote.
        self.i += 1;
        let mut out = String::new();
        loop {
            let at = self.i;
            let c = self.peek()?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                // A high surrogate must be followed by \u + a low one.
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(ParseError::BadString(at));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(ParseError::BadString(at));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or(ParseError::BadString(at))?);
                        }
                        _ => return Err(ParseError::BadString(at)),
                    }
                }
                0x00..=0x1F => return Err(ParseError::BadString(at)),
                _ => {
                    // The input is a &str: copy one whole UTF-8 sequence.
                    let len = match c {
                        0x00..=0x7F => 1,
                        0xC0..=0xDF => 2,
                        0xE0..=0xEF => 3,
                        _ => 4,
                    };
                    let s = self.b.get(self.i..self.i + len).ok_or(ParseError::Eof)?;
                    out.push_str(core::str::from_utf8(s).map_err(|_| ParseError::BadString(at))?);
                    self.i += len;
                }
            }
        }
    }
}
