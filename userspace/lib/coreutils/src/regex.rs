// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The regular expressions of `grep`: a literal byte, `.`, a class (`[abc]`,
//! `[a-z]`, `[^a-z]`, `\d` `\w` `\s`), each optionally followed by `*`, `+`
//! or `?`, and `^` / `$` at the ends. No groups, no alternation, no counted
//! repeats, no back-references: those are refused when the pattern compiles
//! (the full syntax is ripgrep's).
//!
//! A pattern is a line of atoms, so it runs as an NFA over a bit set of
//! positions: one pass over the text, no backtracking, no recursion.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegexError {
    TooLong,
    /// `( ) | { }` or `\1`-style references.
    Unsupported(u8),
    NothingToRepeat,
    BadClass,
    TrailingBackslash,
}

impl RegexError {
    pub fn text(self) -> &'static [u8] {
        match self {
            RegexError::TooLong => b"pattern too long (at most 60 atoms, 4 classes)",
            RegexError::Unsupported(_) => b"groups, alternation and counted repeats are not in this grep; use rg",
            RegexError::NothingToRepeat => b"nothing to repeat",
            RegexError::BadClass => b"unterminated [ class",
            RegexError::TrailingBackslash => b"trailing backslash",
        }
    }
}

const MAX_ATOMS: usize = 60;
const MAX_CLASSES: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Atom {
    Lit(u8),
    Any,
    Class(u8),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rep {
    One,
    Opt,
    Star,
    Plus,
}

pub struct Regex {
    atoms: [Atom; MAX_ATOMS],
    reps: [Rep; MAX_ATOMS],
    n: usize,
    classes: [[u8; 32]; MAX_CLASSES],
    nclasses: usize,
    bol: bool,
    eol: bool,
    fold: bool,
}

fn set(cls: &mut [u8; 32], c: u8) {
    cls[(c >> 3) as usize] |= 1 << (c & 7);
}

fn has(cls: &[u8; 32], c: u8) -> bool {
    cls[(c >> 3) as usize] & (1 << (c & 7)) != 0
}

fn shorthand(cls: &mut [u8; 32], k: u8) -> bool {
    for c in 0..=255u8 {
        let hit = match k {
            b'd' => c.is_ascii_digit(),
            b'w' => c.is_ascii_alphanumeric() || c == b'_',
            b's' => c == b' ' || (b'\t'..=b'\r').contains(&c),
            _ => return false,
        };
        if hit {
            set(cls, c);
        }
    }
    true
}

impl Regex {
    pub fn compile(pat: &[u8], fold: bool) -> Result<Regex, RegexError> {
        let mut r = Regex {
            atoms: [Atom::Any; MAX_ATOMS],
            reps: [Rep::One; MAX_ATOMS],
            n: 0,
            classes: [[0; 32]; MAX_CLASSES],
            nclasses: 0,
            bol: false,
            eol: false,
            fold,
        };
        let mut i = 0;
        if pat.first() == Some(&b'^') {
            r.bol = true;
            i = 1;
        }
        while i < pat.len() {
            let c = pat[i];
            i += 1;
            let atom = match c {
                b'(' | b')' | b'|' | b'{' | b'}' => return Err(RegexError::Unsupported(c)),
                b'*' | b'+' | b'?' => {
                    if r.n == 0 || r.reps[r.n - 1] != Rep::One {
                        return Err(RegexError::NothingToRepeat);
                    }
                    r.reps[r.n - 1] = match c {
                        b'*' => Rep::Star,
                        b'+' => Rep::Plus,
                        _ => Rep::Opt,
                    };
                    continue;
                }
                b'$' if i == pat.len() => {
                    r.eol = true;
                    continue;
                }
                b'.' => Atom::Any,
                b'[' => {
                    let (cls, used) = r.parse_class(&pat[i..])?;
                    i += used;
                    cls
                }
                b'\\' => {
                    let Some(&e) = pat.get(i) else { return Err(RegexError::TrailingBackslash) };
                    i += 1;
                    match e {
                        b'd' | b'w' | b's' => {
                            let k = r.new_class()?;
                            shorthand(&mut r.classes[k as usize], e);
                            Atom::Class(k)
                        }
                        b'1'..=b'9' => return Err(RegexError::Unsupported(e)),
                        b'n' => Atom::Lit(b'\n'),
                        b't' => Atom::Lit(b'\t'),
                        _ => r.lit(e),
                    }
                }
                _ => r.lit(c),
            };
            if r.n == MAX_ATOMS {
                return Err(RegexError::TooLong);
            }
            r.atoms[r.n] = atom;
            r.n += 1;
        }
        Ok(r)
    }

    fn lit(&self, c: u8) -> Atom {
        Atom::Lit(if self.fold { c.to_ascii_lowercase() } else { c })
    }

    fn new_class(&mut self) -> Result<u8, RegexError> {
        if self.nclasses == MAX_CLASSES {
            return Err(RegexError::TooLong);
        }
        self.nclasses += 1;
        Ok((self.nclasses - 1) as u8)
    }

    /// The class after a `[`: its atom and the bytes used, `]` included.
    fn parse_class(&mut self, p: &[u8]) -> Result<(Atom, usize), RegexError> {
        let k = self.new_class()?;
        let mut cls = [0u8; 32];
        let mut i = 0;
        let neg = p.first() == Some(&b'^');
        if neg {
            i = 1;
        }
        let first = i;
        loop {
            let Some(&lo) = p.get(i) else { return Err(RegexError::BadClass) };
            if lo == b']' && i > first {
                i += 1;
                break;
            }
            if lo == b'\\' && p.get(i + 1).is_some_and(|c| matches!(c, b'd' | b'w' | b's')) {
                shorthand(&mut cls, p[i + 1]);
                i += 2;
            } else if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|&h| h != b']') {
                let hi = p[i + 2];
                for c in lo..=hi {
                    set(&mut cls, c);
                }
                i += 3;
            } else {
                set(&mut cls, lo);
                i += 1;
            }
        }
        if self.fold {
            for c in 0..=255u8 {
                if has(&cls, c) {
                    set(&mut cls, c.to_ascii_lowercase());
                    set(&mut cls, c.to_ascii_uppercase());
                }
            }
        }
        if neg {
            for b in cls.iter_mut() {
                *b = !*b;
            }
        }
        self.classes[k as usize] = cls;
        Ok((Atom::Class(k), i))
    }

    fn takes(&self, a: usize, c: u8) -> bool {
        match self.atoms[a] {
            Atom::Any => true,
            Atom::Lit(l) => l == if self.fold { c.to_ascii_lowercase() } else { c },
            Atom::Class(k) => has(&self.classes[k as usize], c),
        }
    }

    /// Add the positions reachable by skipping atoms that may match nothing.
    fn close(&self, mut s: u64) -> u64 {
        for a in 0..self.n {
            if s >> a & 1 == 1 && matches!(self.reps[a], Rep::Star | Rep::Opt) {
                s |= 1 << (a + 1);
            }
        }
        s
    }

    /// Does the pattern match somewhere in `text`.
    pub fn is_match(&self, text: &[u8]) -> bool {
        let done = 1u64 << self.n;
        let mut s = self.close(1);
        if self.accepts(s & done != 0, 0, text.len()) {
            return true;
        }
        for (p, &c) in text.iter().enumerate() {
            let mut next = 0u64;
            for a in 0..self.n {
                if s >> a & 1 == 0 || !self.takes(a, c) {
                    continue;
                }
                next |= match self.reps[a] {
                    Rep::One | Rep::Opt => 1 << (a + 1),
                    Rep::Star => 1 << a,
                    Rep::Plus => 1 << a | 1 << (a + 1),
                };
            }
            if !self.bol {
                next |= 1;
            }
            s = self.close(next);
            if self.accepts(s & done != 0, p + 1, text.len()) {
                return true;
            }
            if s == 0 {
                return false;
            }
        }
        false
    }

    fn accepts(&self, reached: bool, at: usize, len: usize) -> bool {
        reached && (!self.eol || at == len)
    }
}

/// Is `needle` inside `text`.
pub fn contains(text: &[u8], needle: &[u8], fold: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    text.len() >= needle.len()
        && text.windows(needle.len()).any(|w| if fold { w.eq_ignore_ascii_case(needle) } else { w == needle })
}
