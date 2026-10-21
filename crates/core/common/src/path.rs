// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Opening a name beneath a directory: the one join, shared by the
//! filesystem (which opens the result) and the syscall layer (which checks
//! the authority the result needs before it asks the filesystem).
//!
//! Two layers that each joined a root and a name on their own would be two
//! definitions of "beneath"; a name the check read as `/tmp/x` and the
//! filesystem opened as `/fat/y` would be an escape. There is one join.

/// The root of the namespace: the directory the kernel opens its own files
/// from (boot files, the crash log, an image to spawn). A ring-3 caller never
/// holds it unless its signed row grants a tree on `/`.
pub const ROOT_DIR: &[u8] = b"/";

/// Longest joined path, in bytes.
pub const MAX_PATH: usize = 512;

/// Why a join failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum JoinError {
    /// An escape or a malformed input: the caller cannot tell which.
    Invalid,
    /// The result does not fit [`MAX_PATH`].
    TooLong,
}

/// Join `rel` onto the directory `root` into `out` without leaving `root`.
///
/// * `root` is absolute (`/`, `/fat`, `/fat/LOGS`); `.` and `..` components in
///   it are refused (a directory is named once, canonically).
/// * `rel` is relative and non-empty. A leading `/` is refused (an absolute
///   path names no directory to be beneath), as is a NUL byte. `//` collapses
///   and `.` is skipped; `..` pops the component before it and is refused when
///   there is none, so `a/../..` and `..` escape and `a/../b` does not.
/// * The result is `root` plus the normalised components (`/` alone for the
///   root itself, which `a/..` names), and fits `out` or the join is
///   [`JoinError::TooLong`].
///
/// Returns the length written. `Invalid` for every escape and malformed input.
pub fn join_beneath(root: &[u8], rel: &[u8], out: &mut [u8; MAX_PATH]) -> Result<usize, JoinError> {
    if root.first() != Some(&b'/') || rel.is_empty() || rel[0] == b'/' || rel.contains(&0) {
        return Err(JoinError::Invalid);
    }
    let mut n = 0usize;
    let push = |out: &mut [u8; MAX_PATH], n: &mut usize, c: &[u8]| -> Result<(), JoinError> {
        let end = n.checked_add(1).and_then(|e| e.checked_add(c.len())).ok_or(JoinError::TooLong)?;
        if end > MAX_PATH { return Err(JoinError::TooLong); }
        out[*n] = b'/';
        out[*n + 1..end].copy_from_slice(c);
        *n = end;
        Ok(())
    };
    let root = match root.iter().position(|&b| b == 0) { Some(z) => &root[..z], None => root };
    for c in root.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
        if c == b"." || c == b".." { return Err(JoinError::Invalid); }
        push(out, &mut n, c)?;
    }
    let floor = n;
    for c in rel.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                if n == floor { return Err(JoinError::Invalid); }
                // Components above the floor are `/name` runs: drop the last.
                n = floor + out[floor..n].iter().rposition(|&b| b == b'/').unwrap_or(0);
            }
            _ => push(out, &mut n, c)?,
        }
    }
    if n == 0 {
        out[0] = b'/';
        n = 1;
    }
    Ok(n)
}
