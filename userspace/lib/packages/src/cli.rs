// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `pkg`'s command line and what it prints: pure, over any [`PackagesCall`],
//! any [`Opener`] and any [`core::fmt::Write`], so the host suite drives the
//! whole tool through the generated stubs and a loopback, with the installer
//! beyond it.
//!
//! ```text
//! pkg admit FILE     would the device take the package in FILE? changes nothing
//! pkg install FILE   admit it, stage it and journal the decision
//! pkg list           the staged packages, by id
//! pkg remove ID      unstage the package whose id is ID (64 hex digits)
//! ```

use crate::{id_words, step_name, words_id, IdlError, PackagesCall, PkgMem, Cap};
use core::fmt::Write;

/// Usage line.
pub const USAGE: &str = "usage: pkg admit FILE | install FILE | list | remove ID\n";

/// Staged packages one `list` prints at most.
pub const LIST_MAX: u32 = 64;

/// What the command line asks.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd<'a> {
    /// `admit FILE`.
    Admit(&'a [u8]),
    /// `install FILE`.
    Install(&'a [u8]),
    /// `list`.
    List,
    /// `remove ID`.
    Remove([u8; 32]),
}

fn hex_id(a: &[u8]) -> Option<[u8; 32]> {
    if a.len() != 64 {
        return None;
    }
    let nib = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut id = [0u8; 32];
    for (i, o) in id.iter_mut().enumerate() {
        *o = nib(a[2 * i])? << 4 | nib(a[2 * i + 1])?;
    }
    Some(id)
}

/// The command `args` (the program's arguments, not its name) ask for.
pub fn parse<'a>(args: &[&'a [u8]]) -> Result<Cmd<'a>, &'static str> {
    match args {
        [b"admit", f] => Ok(Cmd::Admit(f)),
        [b"install", f] => Ok(Cmd::Install(f)),
        [b"list"] => Ok(Cmd::List),
        [b"remove", id] => Ok(Cmd::Remove(hex_id(id).ok_or("an id is 64 hex digits")?)),
        _ => Err("unknown command"),
    }
}

/// Reads the package file a command names into a memory object the installer
/// can be given: the capability, and how many bytes of the object are the
/// file.
pub trait Opener {
    /// The file at `path` (no NUL) in a new object, or `None` (no such file,
    /// empty, too large for a message's length word, or no memory).
    fn open(&mut self, path: &[u8]) -> Option<(Cap<PkgMem>, u32)>;
}

/// Why `run` stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// The installer or the transport failed.
    Call(IdlError),
    /// The package file could not be opened.
    Open,
    /// The output could not be written.
    Out,
}

impl From<core::fmt::Error> for Fail {
    fn from(_: core::fmt::Error) -> Self {
        Fail::Out
    }
}

fn hex(out: &mut impl Write, id: &[u8; 32]) -> core::fmt::Result {
    for b in id {
        write!(out, "{b:02x}")?;
    }
    Ok(())
}

/// Run `cmd`; the exit code: 0 done, 1 refused.
pub fn run<C: PackagesCall, O: Opener>(
    cmd: &Cmd<'_>,
    client: &mut C,
    files: &mut O,
    out: &mut impl Write,
) -> Result<i32, Fail> {
    match cmd {
        Cmd::Admit(f) | Cmd::Install(f) => {
            let install = matches!(cmd, Cmd::Install(_));
            let (cap, len) = files.open(f).ok_or(Fail::Open)?;
            let r = if install { client.install(cap, len) } else { client.admit(cap, len) }.map_err(Fail::Call)?;
            if r[0] != 0 {
                writeln!(out, "refused: {} (status {:#x}, package {:016x})", step_name(r[0]), r[0], r[1])?;
                return Ok(1);
            }
            let verb = if install { "installed" } else { "would install" };
            writeln!(out, "{verb}: package {:016x}, {} row(s) from row {}", r[1], r[2], r[3])?;
            Ok(0)
        }
        Cmd::List => {
            for i in 0..LIST_MAX {
                let w = client.installed(i).map_err(Fail::Call)?;
                if w == [0; 4] {
                    break;
                }
                hex(out, &words_id(&w))?;
                writeln!(out)?;
            }
            Ok(0)
        }
        Cmd::Remove(id) => {
            let r = client.remove(id_words(id)).map_err(Fail::Call)?;
            if r[0] != 0 {
                writeln!(out, "refused: {} (status {:#x})", step_name(r[0]), r[0])?;
                return Ok(1);
            }
            writeln!(out, "removed: package {:016x}", r[1])?;
            Ok(0)
        }
    }
}
