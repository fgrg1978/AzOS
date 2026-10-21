// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Key expressions: what a subscriber or a queryable declares and what a
//! PUSH or a REQUEST names.
//!
//! A key expression is chunks separated by `/`. A chunk is:
//!
//! * `*`: exactly one non-empty chunk;
//! * `**`: zero or more whole chunks;
//! * text, in which `$*` stands for any run of bytes (empty too): `a$*`,
//!   `$*b$*`. `$` is allowed only as part of `$*`, and a chunk that is just
//!   `$*` must be written `*`;
//! * **verbatim** when it starts with `@`: no wildcard of any kind (`*`, `**`
//!   or `$*`) matches it or is part of it; only the identical chunk does.
//!   (`@` chunks carry administrative names such as `@/router/...`.)
//!
//! Well-formed means canonical, as zenoh-rust checks it: no empty chunk (no
//! leading, trailing or doubled `/`), no `#` or `?`, `*` only as a whole
//! chunk, and no `**/**` or `**/*` (the second is written `*/**`).
//!
//! The two questions a router asks are [`intersects`] (does a PUSH on `key`
//! reach a subscriber on `sub`: some concrete key matches both) and
//! [`includes`] (is everything `b` matches also matched by `a`). Both are
//! `false` for a malformed argument, and a key longer than [`MAX_KEY_LEN`] is
//! malformed.

use alloc::vec;
use alloc::vec::Vec;

/// Longest key expression accepted, in bytes. Keys arrive from remote peers
/// and the matchers keep a table of (length x length) cells, so the bound is
/// what keeps a hostile key from asking for gigabytes: at most 1 MiB for one
/// `$*` text chunk pair and 512 chunks (257 K cells) for a whole key.
pub const MAX_KEY_LEN: usize = 1024;

/// Is `s` a well-formed (canonical) key expression no longer than
/// [`MAX_KEY_LEN`]?
pub fn is_valid(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_KEY_LEN {
        return false;
    }
    let mut prev: Option<&str> = None;
    for chunk in s.split('/') {
        if !chunk_valid(chunk) {
            return false;
        }
        if let Some(p) = prev {
            if p == "**" && (chunk == "**" || chunk == "*") {
                return false;
            }
        }
        prev = Some(chunk);
    }
    true
}

fn chunk_valid(c: &str) -> bool {
    if c.is_empty() {
        return false;
    }
    if c == "*" || c == "**" {
        return true;
    }
    if c == "$*" {
        return false;
    }
    let b = c.as_bytes();
    let verbatim = b[0] == b'@';
    let mut i = 0;
    let mut prev_star = false;
    while i < b.len() {
        match b[i] {
            b'#' | b'?' => return false,
            b'*' => return false,
            b'$' => {
                if verbatim || i + 1 >= b.len() || b[i + 1] != b'*' || prev_star {
                    return false;
                }
                prev_star = true;
                i += 2;
                continue;
            }
            _ => prev_star = false,
        }
        i += 1;
    }
    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    Star,
}

fn tokens(c: &str) -> Vec<Tok> {
    let b = c.as_bytes();
    let mut v = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' {
            v.push(Tok::Star);
            i += 2;
        } else {
            v.push(Tok::Lit(b[i]));
            i += 1;
        }
    }
    v
}

fn verbatim(c: &str) -> bool {
    c.as_bytes().first() == Some(&b'@')
}

/// Do two text chunks (with `$*`) match a common string?
fn glob_intersects(a: &[Tok], b: &[Tok]) -> bool {
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    let mut t = vec![false; (n + 1) * w];
    t[n * w + m] = true;
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            if i == n && j == m {
                continue;
            }
            let v = if i == n {
                b[j] == Tok::Star && t[i * w + j + 1]
            } else if j == m {
                a[i] == Tok::Star && t[(i + 1) * w + j]
            } else {
                match (a[i], b[j]) {
                    (Tok::Star, Tok::Star) => t[(i + 1) * w + j] || t[i * w + j + 1],
                    (Tok::Star, Tok::Lit(_)) => t[(i + 1) * w + j] || t[i * w + j + 1],
                    (Tok::Lit(_), Tok::Star) => t[i * w + j + 1] || t[(i + 1) * w + j],
                    (Tok::Lit(x), Tok::Lit(y)) => x == y && t[(i + 1) * w + j + 1],
                }
            };
            t[i * w + j] = v;
        }
    }
    t[0]
}

/// Does every string `b` matches also match `a`? (`b`'s stars stand for
/// arbitrary strings, so only a star of `a` can cover one.)
fn glob_includes(a: &[Tok], b: &[Tok]) -> bool {
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    let mut t = vec![false; (n + 1) * w];
    t[n * w + m] = true;
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            if i == n && j == m {
                continue;
            }
            let v = if i == n {
                false
            } else if a[i] == Tok::Star {
                t[(i + 1) * w + j] || (j < m && t[i * w + j + 1])
            } else if j == m {
                false
            } else {
                match (a[i], b[j]) {
                    (Tok::Lit(x), Tok::Lit(y)) => x == y && t[(i + 1) * w + j + 1],
                    _ => false,
                }
            };
            t[i * w + j] = v;
        }
    }
    t[0]
}

fn chunk_intersects(a: &str, b: &str) -> bool {
    if verbatim(a) || verbatim(b) {
        return a == b;
    }
    if a == "*" || b == "*" {
        return true;
    }
    glob_intersects(&tokens(a), &tokens(b))
}

fn chunk_includes(a: &str, b: &str) -> bool {
    if verbatim(a) || verbatim(b) {
        return a == b;
    }
    if a == "*" {
        return true;
    }
    if b == "*" {
        return false;
    }
    glob_includes(&tokens(a), &tokens(b))
}

/// Does some concrete key match both `a` and `b`?
pub fn intersects(a: &str, b: &str) -> bool {
    if !is_valid(a) || !is_valid(b) {
        return false;
    }
    let a: Vec<&str> = a.split('/').collect();
    let b: Vec<&str> = b.split('/').collect();
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    let mut t = vec![false; (n + 1) * w];
    t[n * w + m] = true;
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            if i == n && j == m {
                continue;
            }
            let v = if i == n {
                b[j] == "**" && t[i * w + j + 1]
            } else if a[i] == "**" {
                t[(i + 1) * w + j] || (j < m && !verbatim(b[j]) && t[i * w + j + 1])
            } else if j == m {
                false
            } else if b[j] == "**" {
                t[i * w + j + 1] || (!verbatim(a[i]) && t[(i + 1) * w + j])
            } else {
                chunk_intersects(a[i], b[j]) && t[(i + 1) * w + j + 1]
            };
            t[i * w + j] = v;
        }
    }
    t[0]
}

/// Is everything `b` matches also matched by `a`? For a concrete `b` (no
/// wildcard) this is "does the pattern `a` match the key `b`".
pub fn includes(a: &str, b: &str) -> bool {
    if !is_valid(a) || !is_valid(b) {
        return false;
    }
    let a: Vec<&str> = a.split('/').collect();
    let b: Vec<&str> = b.split('/').collect();
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    let mut t = vec![false; (n + 1) * w];
    t[n * w + m] = true;
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            if i == n && j == m {
                continue;
            }
            let v = if i == n {
                false
            } else if a[i] == "**" {
                t[(i + 1) * w + j] || (j < m && !verbatim(b[j]) && t[i * w + j + 1])
            } else if j == m || b[j] == "**" {
                false
            } else {
                chunk_includes(a[i], b[j]) && t[(i + 1) * w + j + 1]
            };
            t[i * w + j] = v;
        }
    }
    t[0]
}
