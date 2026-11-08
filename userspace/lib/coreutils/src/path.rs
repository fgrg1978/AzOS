// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Absolute, normalised paths in a fixed buffer, and the name helpers.

use crate::host::Error;

/// Longest absolute path.
pub const PATH_MAX: usize = 128;

#[derive(Clone, Copy)]
pub struct PathBuf {
    b: [u8; PATH_MAX],
    n: usize,
}

impl PathBuf {
    pub const fn root() -> Self {
        let mut b = [0u8; PATH_MAX];
        b[0] = b'/';
        PathBuf { b, n: 1 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_root(&self) -> bool {
        self.n == 1
    }

    /// `p` against the working directory `cwd`: `.` and empty parts dropped,
    /// `..` taking off the last part (never above the root).
    pub fn resolve(cwd: &[u8], p: &[u8]) -> Result<PathBuf, Error> {
        let mut out = PathBuf::root();
        if p.first() != Some(&b'/') {
            out.append(cwd)?;
        }
        out.append(p)?;
        Ok(out)
    }

    /// The relative path `rel` below this one (`a/b`, no leading `/`).
    pub fn join(&mut self, rel: &[u8]) -> Result<(), Error> {
        self.append(rel)
    }

    /// Is `self` the directory `dir` or somewhere below it.
    pub fn is_within(&self, dir: &PathBuf) -> bool {
        let (a, d) = (self.as_bytes(), dir.as_bytes());
        a.starts_with(d) && (d.len() == 1 || a.len() == d.len() || a[d.len()] == b'/')
    }

    fn append(&mut self, part: &[u8]) -> Result<(), Error> {
        for comp in part.split(|&c| c == b'/') {
            match comp {
                b"" | b"." => {}
                #[cfg(not(feature = "path-dotdot-canary"))]
                b".." => self.pop(),
                #[cfg(feature = "path-dotdot-canary")]
                b".." => self.push(b"..")?,
                c => self.push(c)?,
            }
        }
        Ok(())
    }

    /// `name` as a new last part.
    pub fn push(&mut self, name: &[u8]) -> Result<(), Error> {
        let sep = if self.n == 1 { 0 } else { 1 };
        if self.n + sep + name.len() > PATH_MAX {
            return Err(Error::TooLong);
        }
        if sep == 1 {
            self.b[self.n] = b'/';
        }
        self.b[self.n + sep..self.n + sep + name.len()].copy_from_slice(name);
        self.n += sep + name.len();
        Ok(())
    }

    /// Take off the last part (the root stays).
    pub fn pop(&mut self) {
        while self.n > 1 && self.b[self.n - 1] != b'/' {
            self.n -= 1;
        }
        if self.n > 1 {
            self.n -= 1;
        }
    }

    pub fn truncate(&mut self, n: usize) {
        self.n = n.clamp(1, self.n);
    }

    /// The last part, empty for the root.
    pub fn name(&self) -> &[u8] {
        if self.is_root() { b"" } else { base_name(self.as_bytes()) }
    }
}

/// The last part of `p`, trailing `/` ignored (`/` is `/`).
pub fn base_name(p: &[u8]) -> &[u8] {
    let mut e = p.len();
    while e > 1 && p[e - 1] == b'/' {
        e -= 1;
    }
    let p = &p[..e];
    if p == b"/" {
        return p;
    }
    match p.iter().rposition(|&c| c == b'/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// Everything but the last part of `p`: `.` for a bare name, `/` at the top.
pub fn dir_name(p: &[u8]) -> &[u8] {
    let mut e = p.len();
    while e > 1 && p[e - 1] == b'/' {
        e -= 1;
    }
    let p = &p[..e];
    match p.iter().rposition(|&c| c == b'/') {
        None => b".",
        Some(0) => b"/",
        Some(i) => {
            let mut d = i;
            while d > 1 && p[d - 1] == b'/' {
                d -= 1;
            }
            &p[..d]
        }
    }
}
