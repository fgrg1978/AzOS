// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Command names and paths for the user shell (RFC-0055 §5.6).
//!
//! Resolution order: a builtin (decided by the caller), then an applet of
//! `TOOLBOX.ELF`, then each `PATH` directory as `<dir>/<NAME>.ELF`. FAT32
//! holds 8.3 names only, upper-cased, so a name longer than 8 characters is
//! refused with a message naming the limit instead of being looked up. Which
//! file a name finds does not decide what it may do: the child runs under the
//! profile and topology row of its BYTES.
//!
//! Pure: the one filesystem question (does this path exist?) is a closure.
//! `tests/host/sh-tests` pulls this file in with `#[path]`.

/// Longest absolute path the shell builds.
pub const PATH_MAX: usize = 128;
/// The multicall tool image.
pub const TOOLBOX: &[u8] = b"/fat/TOOLBOX.ELF";
/// The search path when `PATH` is unset.
pub const DEFAULT_PATH: &[u8] = b"/fat";

/// Names `TOOLBOX.ELF` answers to (its `argv[0]` dispatch).
pub const APPLETS: &[&[u8]] = &[
    b"args", b"cat", b"echo", b"false", b"ls", b"ps", b"sleep", b"spin", b"true", b"wc", b"yes",
];

/// Is `name` an applet of `TOOLBOX.ELF`?
pub fn is_applet(name: &[u8]) -> bool {
    APPLETS.iter().any(|a| *a == name)
}

/// Why a name or path did not resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// No file by that name in any `PATH` directory.
    NotFound,
    /// The name has more than 8 characters before `.ELF` (FAT 8.3).
    NameTooLong,
    /// A character FAT does not take, or an empty name.
    BadName,
    /// The joined path exceeds [`PATH_MAX`].
    TooLong,
}

impl PathError {
    /// A message for the user.
    pub fn message(self) -> &'static [u8] {
        match self {
            PathError::NotFound => b"command not found",
            PathError::NameTooLong => b"name longer than 8 characters (FAT 8.3 names, no long names)",
            PathError::BadName => b"not a valid 8.3 name",
            PathError::TooLong => b"path too long",
        }
    }
}

/// Copy `name` upper-cased into `out` as an 8.3 base and add `.ELF`. A name
/// that already ends in `.elf`/`.ELF` keeps it. Returns the length.
pub fn elf_name(name: &[u8], out: &mut [u8; 12]) -> Result<usize, PathError> {
    let base = if name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(b".elf") {
        &name[..name.len() - 4]
    } else {
        name
    };
    if base.is_empty() {
        return Err(PathError::BadName);
    }
    if base.len() > 8 {
        return Err(PathError::NameTooLong);
    }
    for (i, &b) in base.iter().enumerate() {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(PathError::BadName);
        }
        out[i] = b.to_ascii_uppercase();
    }
    out[base.len()..base.len() + 4].copy_from_slice(b".ELF");
    Ok(base.len() + 4)
}

/// Make `path` absolute against `cwd` and remove `.` and `..` components
/// (`..` at the root stays at the root). Repeated slashes collapse; a
/// trailing slash is dropped except for `/` itself. Returns the length.
pub fn join(cwd: &[u8], path: &[u8], out: &mut [u8; PATH_MAX]) -> Result<usize, PathError> {
    let mut n = 0usize;
    // Component start offsets, to pop on `..`.
    let mut starts = [0usize; PATH_MAX / 2];
    let mut depth = 0usize;
    let mut add = |part: &[u8], n: &mut usize, depth: &mut usize, out: &mut [u8; PATH_MAX]| {
        for comp in part.split(|&b| b == b'/') {
            match comp {
                b"" | b"." => {}
                b".." => {
                    if *depth > 0 {
                        *depth -= 1;
                        *n = starts[*depth];
                    }
                }
                c => {
                    if *n + 1 + c.len() > PATH_MAX || *depth == starts.len() {
                        return Err(PathError::TooLong);
                    }
                    starts[*depth] = *n;
                    *depth += 1;
                    out[*n] = b'/';
                    out[*n + 1..*n + 1 + c.len()].copy_from_slice(c);
                    *n += 1 + c.len();
                }
            }
        }
        Ok(())
    };
    if path.first() != Some(&b'/') {
        add(cwd, &mut n, &mut depth, out)?;
    }
    add(path, &mut n, &mut depth, out)?;
    if n == 0 {
        out[0] = b'/';
        n = 1;
    }
    Ok(n)
}

/// Resolve a command `name` that is not a builtin or an applet into an
/// absolute image path in `out`.
///
/// A name with a `/` is a path (relative to `cwd`) and is used as given. A bare
/// name is looked up as `<dir>/<NAME>.ELF` in each `:`-separated directory of
/// `path_var`, in order, with `exists`.
pub fn resolve(
    name: &[u8],
    cwd: &[u8],
    path_var: &[u8],
    exists: &mut dyn FnMut(&[u8]) -> bool,
    out: &mut [u8; PATH_MAX],
) -> Result<usize, PathError> {
    if name.contains(&b'/') {
        let n = join(cwd, name, out)?;
        return if exists(&out[..n]) { Ok(n) } else { Err(PathError::NotFound) };
    }
    let mut file = [0u8; 12];
    let flen = elf_name(name, &mut file)?;
    for dir in path_var.split(|&b| b == b':') {
        if dir.is_empty() {
            continue;
        }
        let mut cand = [0u8; PATH_MAX];
        let mut tail = [0u8; 13];
        tail[0] = b'/';
        tail[1..1 + flen].copy_from_slice(&file[..flen]);
        let d = join(cwd, dir, &mut cand)?;
        let mut full = [0u8; PATH_MAX];
        full[..d].copy_from_slice(&cand[..d]);
        let start = if d == 1 { 0 } else { d };
        if start + 1 + flen > PATH_MAX {
            return Err(PathError::TooLong);
        }
        full[start..start + 1 + flen].copy_from_slice(&tail[..1 + flen]);
        let len = start + 1 + flen;
        if exists(&full[..len]) {
            out[..len].copy_from_slice(&full[..len]);
            return Ok(len);
        }
    }
    Err(PathError::NotFound)
}
