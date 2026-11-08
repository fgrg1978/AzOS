// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Name patterns: `*`, `?`, `[abc]`, `[a-z]`, `[!a-z]`. No recursion: a `*`
//! remembers where to resume.

use crate::util::same;

pub fn glob_match(pat: &[u8], name: &[u8], fold: bool) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        let step = match pat.get(p) {
            Some(b'*') => {
                star = Some((p, n));
                p += 1;
                continue;
            }
            Some(b'?') => Some(1),
            Some(b'[') => class(pat, p, name[n], fold).map(|(ok, len)| if ok { len } else { 0 }).filter(|&l| l > 0),
            Some(&c) => if same(c, name[n], fold) { Some(1) } else { None },
            None => None,
        };
        match step {
            Some(len) => {
                p += len;
                n += 1;
            }
            None => match star {
                Some((sp, sn)) => {
                    p = sp + 1;
                    n = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
    while pat.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pat.len()
}

/// Does the class at `pat[p]` (`[`) take `c`; and how many pattern bytes it
/// spans. `None` for a class that never closes (taken as a literal `[`).
fn class(pat: &[u8], p: usize, c: u8, fold: bool) -> Option<(bool, usize)> {
    let mut i = p + 1;
    let neg = matches!(pat.get(i), Some(b'!') | Some(b'^'));
    if neg {
        i += 1;
    }
    let first = i;
    let mut hit = false;
    loop {
        let lo = *pat.get(i)?;
        if lo == b']' && i > first {
            return Some((hit != neg, i + 1 - p));
        }
        if pat.get(i + 1) == Some(&b'-') && pat.get(i + 2).is_some_and(|&h| h != b']') {
            let hi = pat[i + 2];
            let (cl, cu) = if fold { (c.to_ascii_lowercase(), c.to_ascii_uppercase()) } else { (c, c) };
            hit |= (lo <= cl && cl <= hi) || (lo <= cu && cu <= hi);
            i += 3;
        } else {
            hit |= same(lo, c, fold);
            i += 1;
        }
    }
}
