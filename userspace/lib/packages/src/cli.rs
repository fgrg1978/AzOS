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
//! pkg fetch          get the package from the source SOURCE.CFG describes and
//!                    install it, as install does
//! pkg update FILE    stage the whole-system update in FILE (a bundle, or a delta
//!                    against the running slot's set) into the inactive slot
//! pkg fetch-update   the same for a bundle the installer gets from the source
//!                    SOURCE.CFG describes
//! pkg outdated       ask the source for its signed index and print, per staged
//!                    package, the installed and the available version and
//!                    where it stands (behind, below its security floor)
//! pkg upgrade [NAME | --all]
//!                    the same, then install the newer version the index lists
//!                    for NAME (or for every package that is behind) through the
//!                    signed install path, in place of the staged one
//! ```

use crate::{id_words, name_words, standing, step, step_name, step_of, words_id, write_version, words_name, IdlError, PackagesCall, PkgMem, Cap};
use core::fmt::Write;

/// Usage line.
pub const USAGE: &str =
    "usage: pkg admit FILE | install FILE | fetch | list | remove ID | update FILE | fetch-update | outdated | upgrade [NAME | --all]\n";

/// Staged packages one `list` prints at most.
pub const LIST_MAX: u32 = 64;

/// What the command line asks.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd<'a> {
    /// `admit FILE`.
    Admit(&'a [u8]),
    /// `install FILE`.
    Install(&'a [u8]),
    /// `fetch`.
    Fetch,
    /// `list`.
    List,
    /// `remove ID`.
    Remove([u8; 32]),
    /// `update FILE`.
    Update(&'a [u8]),
    /// `fetch-update`.
    FetchUpdate,
    /// `outdated`.
    Outdated,
    /// `upgrade [NAME | --all]`.
    Upgrade(Upgrade<'a>),
}

/// What `upgrade` is asked to upgrade.
#[derive(Debug, PartialEq, Eq)]
pub enum Upgrade<'a> {
    /// The package with this name.
    Name(&'a [u8]),
    /// Every package that is behind.
    All,
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
        [b"fetch"] => Ok(Cmd::Fetch),
        [b"list"] => Ok(Cmd::List),
        [b"remove", id] => Ok(Cmd::Remove(hex_id(id).ok_or("an id is 64 hex digits")?)),
        [b"update", f] => Ok(Cmd::Update(f)),
        [b"fetch-update"] => Ok(Cmd::FetchUpdate),
        [b"outdated"] => Ok(Cmd::Outdated),
        [b"upgrade"] | [b"upgrade", b"--all"] => Ok(Cmd::Upgrade(Upgrade::All)),
        [b"upgrade", name] if name.len() > 32 => Err("a package name is at most 32 characters"),
        [b"upgrade", name] => Ok(Cmd::Upgrade(Upgrade::Name(name))),
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

/// One row of the report: a package's name and how it stands.
struct Row {
    name: [u8; 32],
    len: usize,
    standing: u64,
    installed: u64,
    offered: u64,
    floor: u64,
}

impl Row {
    fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }

    fn installed(&self) -> Option<u64> {
        (self.standing & standing::HAS_INSTALLED != 0).then_some(self.installed)
    }

    fn offered(&self) -> Option<u64> {
        (self.standing & standing::HAS_OFFERED != 0).then_some(self.offered)
    }

    fn behind(&self) -> bool {
        self.standing & standing::AVAILABILITY == standing::BEHIND
    }

    fn below_floor(&self) -> bool {
        self.standing & standing::BELOW != 0
    }
}

fn row<C: PackagesCall>(client: &mut C, i: u32) -> Result<Option<Row>, Fail> {
    let n = client.outdated(i, 0).map_err(Fail::Call)?;
    if n == [0; 4] {
        return Ok(None);
    }
    let f = client.outdated(i, 1).map_err(Fail::Call)?;
    let (name, len) = words_name(&n);
    let standing = if step_of(f[0]) == step::ROW as usize { f[0] & 0xFF_FFFF } else { 0 };
    Ok(Some(Row { name, len, standing, installed: f[1], offered: f[2], floor: f[3] }))
}

fn text(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?")
}

/// Ask the source for its index and make the report. `Some(1)` when the
/// installer said no (already printed).
fn refresh<C: PackagesCall>(client: &mut C, out: &mut impl Write) -> Result<Option<i32>, Fail> {
    let r = client.refresh().map_err(Fail::Call)?;
    if r[0] != 0 {
        writeln!(out, "refused: {} (status {:#x})", step_name(r[0]), r[0])?;
        return Ok(Some(1));
    }
    Ok(None)
}

fn state(out: &mut impl Write, r: &Row) -> core::fmt::Result {
    let what = match r.standing & standing::AVAILABILITY {
        standing::NOT_LISTED => "not in the index",
        standing::OTHER_SIGNER => "index is signed by another signer",
        standing::CURRENT => "up to date",
        standing::BEHIND => "behind",
        standing::AHEAD => "newer than the index",
        _ => "version has no order",
    };
    write!(out, "{what}")?;
    match r.standing & standing::FLOOR {
        standing::FLOOR_BELOW => {
            write!(out, "; below security floor ")?;
            write_version(out, r.floor)
        }
        standing::FLOOR_UNORDERED => {
            write!(out, "; cannot be shown to meet security floor ")?;
            write_version(out, r.floor)
        }
        _ => Ok(()),
    }
}

fn pad(out: &mut impl Write, used: usize, to: usize) -> core::fmt::Result {
    for _ in used..to {
        out.write_char(' ')?;
    }
    Ok(())
}

struct Count(usize);

impl Write for Count {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

fn version_cell(out: &mut impl Write, v: Option<u64>) -> core::fmt::Result {
    let mut c = Count(0);
    match v {
        None => {
            c.0 = 1;
            out.write_char('-')?;
        }
        Some(v) => {
            write_version(&mut c, v)?;
            write_version(out, v)?;
        }
    }
    pad(out, c.0, 11)
}

/// Install the newer version of package `name`; `from`/`to` are the versions
/// the report showed, when it did.
fn upgrade_one<C: PackagesCall>(client: &mut C, out: &mut impl Write, name: &[u8], to: Option<(u64, u64)>) -> Result<bool, Fail> {
    let Some(w) = name_words(name) else { return Ok(false) };
    let r = client.upgrade(w).map_err(Fail::Call)?;
    if r[0] != 0 {
        writeln!(out, "refused {}: {} (status {:#x})", text(name), step_name(r[0]), r[0])?;
        return Ok(false);
    }
    write!(out, "upgraded {}", text(name))?;
    if let Some((from, to)) = to {
        write!(out, " ")?;
        write_version(out, from)?;
        write!(out, " -> ")?;
        write_version(out, to)?;
    }
    writeln!(out, " (package {:016x})", r[1])?;
    Ok(true)
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
        Cmd::Fetch => {
            let r = client.fetch().map_err(Fail::Call)?;
            if r[0] != 0 {
                writeln!(out, "refused: {} (status {:#x}, package {:016x})", step_name(r[0]), r[0], r[1])?;
                return Ok(1);
            }
            writeln!(out, "installed: package {:016x}, {} row(s) from row {}", r[1], r[2], r[3])?;
            Ok(0)
        }
        Cmd::Update(_) | Cmd::FetchUpdate => {
            let r = match cmd {
                Cmd::Update(f) => {
                    let (cap, len) = files.open(f).ok_or(Fail::Open)?;
                    client.update(cap, len)
                }
                _ => client.fetch_update(),
            }
            .map_err(Fail::Call)?;
            if r[0] != 0 {
                writeln!(out, "refused: {} (status {:#x}, update {:016x})", step_name(r[0]), r[0], r[1])?;
                return Ok(1);
            }
            let slot = if r[3] == 0 { 'A' } else { 'B' };
            writeln!(out, "staged: update {:016x}, epoch {}, into slot {slot}; the switch is the boot record's", r[1], r[2])?;
            Ok(0)
        }
        Cmd::Outdated => {
            if let Some(code) = refresh(client, out)? {
                return Ok(code);
            }
            writeln!(out, "PACKAGE                           INSTALLED  AVAILABLE  STATE")?;
            let (mut behind, mut below) = (0, 0);
            for i in 0..LIST_MAX {
                let Some(r) = row(client, i)? else { break };
                write!(out, "{}", text(r.name()))?;
                pad(out, r.len, 34)?;
                version_cell(out, r.installed())?;
                write!(out, " ")?;
                version_cell(out, r.offered())?;
                write!(out, " ")?;
                state(out, &r)?;
                writeln!(out)?;
                behind += r.behind() as u32;
                below += r.below_floor() as u32;
            }
            writeln!(out, "{behind} behind, {below} below their security floor")?;
            Ok(0)
        }
        Cmd::Upgrade(which) => {
            if let Some(code) = refresh(client, out)? {
                return Ok(code);
            }
            let mut refused = 0u32;
            match which {
                Upgrade::Name(name) => {
                    let mut shown = None;
                    for i in 0..LIST_MAX {
                        let Some(r) = row(client, i)? else { break };
                        if r.name() == *name {
                            shown = r.installed().zip(r.offered());
                        }
                    }
                    refused += !upgrade_one(client, out, name, shown)? as u32;
                }
                Upgrade::All => {
                    let mut done = 0u32;
                    for i in 0..LIST_MAX {
                        let Some(r) = row(client, i)? else { break };
                        if !r.behind() {
                            continue;
                        }
                        if upgrade_one(client, out, r.name(), r.installed().zip(r.offered()))? {
                            done += 1;
                        } else {
                            refused += 1;
                        }
                    }
                    if done + refused == 0 {
                        writeln!(out, "nothing to upgrade")?;
                    }
                }
            }
            Ok((refused != 0) as i32)
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
