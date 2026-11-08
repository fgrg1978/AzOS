// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A walk over a tree without recursion: the path buffer is the stack and one
//! directory index per level is the rest. `cp -r`, `rm -r`, `find`, `du` and
//! `grep -r` share it.

use crate::host::{Error, Host, Kind, NAME_MAX};
use crate::path::PathBuf;

/// Directories nested below the root of a walk, at most.
pub const DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ev {
    File,
    /// A directory, before its entries.
    DirPre,
    /// A directory, after its entries.
    DirPost,
}

pub struct Walk {
    path: PathBuf,
    /// Index of the next entry of each open directory (`idx[1]` is the root).
    idx: [u32; DEPTH + 2],
    /// Open directories.
    depth: usize,
    /// The name of the last child yielded is still on the path.
    child_on_path: bool,
    root: Option<Kind>,
    finished: bool,
    last: Ev,
}

impl Walk {
    pub fn new(root: PathBuf, kind: Kind) -> Walk {
        Walk { path: root, idx: [0; DEPTH + 2], depth: 0, child_on_path: false, root: Some(kind), finished: false, last: Ev::File }
    }

    /// The entry the last event is about.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Directories above the entry of the last event (0 for the root).
    pub fn level(&self) -> usize {
        match self.last {
            Ev::DirPre => self.depth - 1,
            _ => self.depth,
        }
    }

    fn enter(&mut self) {
        self.depth += 1;
        self.idx[self.depth] = 0;
    }

    fn leave(&mut self) {
        self.depth -= 1;
        if self.depth > 0 {
            self.child_on_path = true;
        }
    }

    /// After a `DirPre`: do not visit its entries (no `DirPost` follows).
    pub fn skip_dir(&mut self) {
        self.leave();
        if self.depth == 0 {
            self.finished = true;
        }
    }

    /// After the entry of the last event was removed: the next read of its
    /// directory is at the same index.
    pub fn removed(&mut self) {
        let d = self.depth;
        if d > 0 && self.idx[d] > 0 {
            self.idx[d] -= 1;
        }
    }

    pub fn next<H: Host>(&mut self, h: &mut H) -> Option<Result<Ev, Error>> {
        let ev = self.step(h)?;
        if let Ok(e) = ev {
            self.last = e;
        }
        Some(ev)
    }

    fn step<H: Host>(&mut self, h: &mut H) -> Option<Result<Ev, Error>> {
        if self.finished {
            return None;
        }
        if let Some(kind) = self.root.take() {
            return Some(Ok(match kind {
                Kind::File => {
                    self.finished = true;
                    Ev::File
                }
                Kind::Dir => {
                    self.enter();
                    Ev::DirPre
                }
            }));
        }
        if self.child_on_path {
            self.path.pop();
            self.child_on_path = false;
        }
        let mut name = [0u8; NAME_MAX];
        let (entry, l) = loop {
            let entry = match h.readdir(self.path.as_bytes(), self.idx[self.depth], &mut name) {
                Ok(e) => e,
                Err(e) => {
                    self.finished = true;
                    return Some(Err(e));
                }
            };
            let l = name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
            // A FAT directory lists its own `.` and `..`.
            #[cfg(not(feature = "walk-dots-canary"))]
            if entry.is_some() && matches!(&name[..l], b"." | b"..") {
                self.idx[self.depth] += 1;
                continue;
            }
            break (entry, l);
        };
        let Some(entry) = entry else {
            self.leave();
            if self.depth == 0 {
                self.finished = true;
            }
            return Some(Ok(Ev::DirPost));
        };
        self.idx[self.depth] += 1;
        if let Err(e) = self.path.push(&name[..l]) {
            self.finished = true;
            return Some(Err(e));
        }
        match entry.kind {
            Kind::File => {
                self.child_on_path = true;
                Some(Ok(Ev::File))
            }
            Kind::Dir => {
                if self.depth > DEPTH {
                    self.finished = true;
                    return Some(Err(Error::TooLong));
                }
                self.enter();
                Some(Ok(Ev::DirPre))
            }
        }
    }
}
