// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The introspection tree, read from ring 3.
//!
//! [`Inspector`] holds the public region and, for a task that was handed the
//! admin one against an admin warrant, the admin region too, and answers
//! paths over both as one namespace. It only loads from the regions, so they
//! may be read-only mappings of the kernel's MemObjs, and a read costs no
//! system call. How a task obtains the MemObjs (the handle, the warrant) is
//! the kernel's grant, not this library's: it takes memory already mapped.
//!
//! A tree can be rebuilt while a task reads it: the library refreshes its
//! view and repeats the read ([`RETRIES`] times) before it reports
//! [`Error::Restructured`] or [`Error::Contended`].
#![no_std]

use core::fmt::{self, Write};

pub use azos_inspect::{Class, Error, Hist, Kind, Name, NodeId, NodeInfo, Region, Str, Value, FORMAT_VERSION};
use azos_inspect::Reader;

/// How many times a read that met a rebuild or a writer is repeated.
pub const RETRIES: usize = 8;

/// Which region a node came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Public,
    Admin,
}

/// The tree a task may read.
pub struct Inspector<'a> {
    public: Reader<'a>,
    admin: Option<Reader<'a>>,
}

/// A failed [`Inspector::render`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderError {
    Tree(Error),
    Write,
}

impl<'a> Inspector<'a> {
    /// Open the regions. `public` must be of class public and `admin` of class
    /// admin: handing one as the other is [`Error::WrongClass`].
    pub fn new(public: Region<'a>, admin: Option<Region<'a>>) -> Result<Inspector<'a>, Error> {
        let public = Reader::open(public, Class::Public)?;
        let admin = admin.map(|r| Reader::open(r, Class::Admin)).transpose()?;
        Ok(Inspector { public, admin })
    }

    /// Open the regions at `(address, bytes)` of mappings the caller made.
    ///
    /// # Safety
    /// As [`Region::from_raw`], for both.
    pub unsafe fn from_mapped(public: (*const u8, usize), admin: Option<(*const u8, usize)>) -> Result<Inspector<'a>, Error> {
        // SAFETY: the caller's contract.
        let public = unsafe { Region::from_raw(public.0, public.1)? };
        let admin = match admin {
            // SAFETY: as above.
            Some((p, n)) => Some(unsafe { Region::from_raw(p, n)? }),
            None => None,
        };
        Inspector::new(public, admin)
    }

    /// Whether the admin region is open.
    pub fn has_admin(&self) -> bool {
        self.admin.is_some()
    }

    /// The reader of one region, if open.
    pub fn reader(&mut self, src: Source) -> Option<&mut Reader<'a>> {
        match src {
            Source::Public => Some(&mut self.public),
            Source::Admin => self.admin.as_mut(),
        }
    }

    /// The value at `path`, from the public region, else from the admin one.
    pub fn read(&mut self, path: &str) -> Result<Option<(Source, Value)>, Error> {
        for src in [Source::Public, Source::Admin] {
            let Some(r) = self.reader(src) else { continue };
            if let Some(v) = retry(r, |r| match r.lookup(path)? {
                Some(id) => r.read(id).map(Some),
                None => Ok(None),
            })? {
                return Ok(Some((src, v)));
            }
        }
        Ok(None)
    }

    /// The `u64` at `path`; `None` when there is no such node or it holds
    /// another kind.
    pub fn read_u64(&mut self, path: &str) -> Result<Option<u64>, Error> {
        Ok(match self.read(path)? {
            Some((_, Value::U64(v))) => Some(v),
            _ => None,
        })
    }

    /// Visit every node of the public region, then every node of the admin
    /// one. A region rebuilt meanwhile is walked again from its root, so the
    /// callback can see the nodes of the old tree first.
    pub fn walk(&mut self, f: &mut dyn FnMut(Source, &NodeInfo, &Value)) -> Result<(), Error> {
        for src in [Source::Public, Source::Admin] {
            if let Some(r) = self.reader(src) {
                retry(r, |r| r.walk(&mut |i, v| f(src, i, v)))?;
            }
        }
        Ok(())
    }

    /// Write the tree as text, one node a line, indented by depth: `name/`
    /// for a directory, `name = value` otherwise. Admin nodes follow the
    /// public ones under a `# admin` line.
    pub fn render(&mut self, out: &mut dyn Write) -> Result<(), RenderError> {
        let mut failed = false;
        let mut last = None;
        let r = self.walk(&mut |src, info, v| {
            if failed {
                return;
            }
            if last != Some(src) {
                last = Some(src);
                if src == Source::Admin {
                    failed = writeln!(out, "# admin").is_err();
                }
            }
            if info.depth > 0 {
                failed = failed || line(out, info, v).is_err();
            }
        });
        r.map_err(RenderError::Tree)?;
        if failed { Err(RenderError::Write) } else { Ok(()) }
    }
}

/// Run `f` on `r`, refreshing it and repeating while the tree moves.
fn retry<T>(r: &mut Reader<'_>, mut f: impl FnMut(&Reader<'_>) -> Result<T, Error>) -> Result<T, Error> {
    let mut last = Error::Contended;
    for _ in 0..RETRIES {
        match f(r) {
            Err(e @ (Error::Restructured | Error::Contended)) => {
                last = e;
                // A rebuild in progress makes the refresh itself contended:
                // the next pass tries again.
                if let Err(e) = r.refresh() {
                    last = e;
                }
            }
            other => return other,
        }
    }
    Err(last)
}

fn line(out: &mut dyn Write, info: &NodeInfo, v: &Value) -> fmt::Result {
    for _ in 1..info.depth {
        out.write_str("  ")?;
    }
    let name = info.name.as_str();
    match v {
        Value::Dir => writeln!(out, "{name}/"),
        Value::U64(x) => writeln!(out, "{name} = {x}"),
        Value::I64(x) => writeln!(out, "{name} = {x}"),
        Value::Str(s) => writeln!(out, "{name} = \"{}\"", s.as_str()),
        Value::Hist(h) => {
            write!(out, "{name} = [")?;
            for (i, b) in h.buckets().iter().enumerate() {
                if i > 0 {
                    out.write_str(", ")?;
                }
                write!(out, "{b}")?;
            }
            writeln!(out, "]")
        }
    }
}
