// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the native basic utilities. `Mem` is a `Host` over an
//! in-memory tree, so a tool runs here exactly as it does in `TOOLBOX.ELF`.

use azos_coreutils::host::*;
use std::collections::BTreeMap;

#[derive(Clone)]
enum Node {
    File { data: Vec<u8>, mtime: u64 },
    Dir,
}

struct Handle {
    path: Vec<u8>,
    pos: usize,
    write: bool,
}

pub struct Mem {
    tree: BTreeMap<Vec<u8>, Node>,
    handles: Vec<Option<Handle>>,
    pub stdin: Vec<u8>,
    stdin_pos: usize,
    /// Bytes `stdin` gives per read, to cross the tools' buffer boundaries.
    pub stdin_chunk: usize,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub cwd: Vec<u8>,
    pub env: Vec<Vec<u8>>,
    pub wall: Option<u64>,
    pub fold: bool,
    pub block: u32,
    /// Paths under this prefix are another volume (a rename across fails).
    pub other_volume: Option<Vec<u8>>,
    /// Paths under this prefix refuse every change.
    pub read_only: Option<Vec<u8>>,
}

impl Mem {
    pub fn new() -> Mem {
        Mem {
            tree: BTreeMap::new(),
            handles: Vec::new(),
            stdin: Vec::new(),
            stdin_pos: 0,
            stdin_chunk: usize::MAX,
            stdout: Vec::new(),
            stderr: Vec::new(),
            cwd: b"/".to_vec(),
            env: Vec::new(),
            wall: None,
            fold: false,
            block: 512,
            other_volume: None,
            read_only: None,
        }
    }

    pub fn dir(&mut self, p: &str) -> &mut Mem {
        let mut acc = Vec::new();
        for part in p.split('/').filter(|s| !s.is_empty()) {
            acc.push(b'/');
            acc.extend_from_slice(part.as_bytes());
            self.tree.entry(acc.clone()).or_insert(Node::Dir);
        }
        self
    }

    pub fn file(&mut self, p: &str, data: &str) -> &mut Mem {
        let parent = p.rsplit_once('/').map_or("", |x| x.0);
        self.dir(parent);
        self.tree.insert(p.as_bytes().to_vec(), Node::File { data: data.as_bytes().to_vec(), mtime: 0 });
        self
    }

    pub fn file_mtime(&mut self, p: &str, data: &str, mtime: u64) -> &mut Mem {
        self.file(p, data);
        self.tree.insert(p.as_bytes().to_vec(), Node::File { data: data.as_bytes().to_vec(), mtime });
        self
    }

    pub fn set_stdin(&mut self, s: &str) -> &mut Mem {
        self.stdin = s.as_bytes().to_vec();
        self.stdin_pos = 0;
        self
    }

    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn read(&self, p: &str) -> Option<String> {
        match self.tree.get(p.as_bytes())? {
            Node::File { data, .. } => Some(String::from_utf8_lossy(data).into_owned()),
            Node::Dir => None,
        }
    }

    pub fn is_dir(&self, p: &str) -> bool {
        matches!(self.tree.get(p.as_bytes()), Some(Node::Dir))
    }

    pub fn exists(&self, p: &str) -> bool {
        p == "/" || self.tree.contains_key(p.as_bytes())
    }

    /// Every path in the tree, sorted.
    pub fn paths(&self) -> Vec<String> {
        self.tree.keys().map(|k| String::from_utf8_lossy(k).into_owned()).collect()
    }

    fn parent_ok(&self, p: &[u8]) -> Result<(), Error> {
        let i = p.iter().rposition(|&c| c == b'/').ok_or(Error::NotFound)?;
        if i == 0 {
            return Ok(());
        }
        match self.tree.get(&p[..i]) {
            Some(Node::Dir) => Ok(()),
            Some(_) => Err(Error::NotDir),
            None => Err(Error::NotFound),
        }
    }

    fn writable(&self, p: &[u8]) -> Result<(), Error> {
        match &self.read_only {
            Some(pre) if p.starts_with(pre) => Err(Error::Denied),
            _ => Ok(()),
        }
    }

    fn children(&self, p: &[u8]) -> Vec<(Vec<u8>, Node)> {
        let pre: Vec<u8> = if p == b"/" { b"/".to_vec() } else { [p, b"/"].concat() };
        self.tree
            .iter()
            .filter(|(k, _)| k.starts_with(&pre) && k.len() > pre.len() && !k[pre.len()..].contains(&b'/'))
            .map(|(k, v)| (k[pre.len()..].to_vec(), v.clone()))
            .collect()
    }
}

impl Host for Mem {
    type File = usize;

    fn cwd(&self) -> &[u8] {
        &self.cwd
    }

    fn env(&self, i: usize) -> Option<&[u8]> {
        self.env.get(i).map(|v| v.as_slice())
    }

    fn wall_ns(&self) -> Option<u64> {
        self.wall
    }

    fn stdin(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = buf.len().min(self.stdin_chunk).min(self.stdin.len() - self.stdin_pos);
        buf[..n].copy_from_slice(&self.stdin[self.stdin_pos..self.stdin_pos + n]);
        self.stdin_pos += n;
        Ok(n)
    }

    fn out(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.stdout.extend_from_slice(bytes);
        Ok(())
    }

    fn err(&mut self, bytes: &[u8]) {
        self.stderr.extend_from_slice(bytes);
    }

    fn stat(&mut self, p: &[u8]) -> Result<Stat, Error> {
        if p == b"/" {
            return Ok(Stat { kind: Kind::Dir, size: 0, mtime: 0 });
        }
        match self.tree.get(p).ok_or(Error::NotFound)? {
            Node::Dir => Ok(Stat { kind: Kind::Dir, size: 0, mtime: 0 }),
            Node::File { data, mtime } => Ok(Stat { kind: Kind::File, size: data.len() as u64, mtime: *mtime }),
        }
    }

    fn readdir(&mut self, p: &[u8], index: u32, name: &mut [u8; NAME_MAX]) -> Result<Option<Entry>, Error> {
        if p != b"/" {
            match self.tree.get(p) {
                Some(Node::Dir) => {}
                Some(_) => return Err(Error::NotDir),
                None => return Err(Error::NotFound),
            }
        }
        let kids = self.children(p);
        let Some((n, node)) = kids.get(index as usize) else { return Ok(None) };
        name.fill(0);
        name[..n.len()].copy_from_slice(n);
        Ok(Some(match node {
            Node::Dir => Entry { kind: Kind::Dir, size: 0 },
            Node::File { data, .. } => Entry { kind: Kind::File, size: data.len() as u32 },
        }))
    }

    fn open(&mut self, p: &[u8], mode: Open) -> Result<usize, Error> {
        let exists = self.tree.get(p);
        if let Some(Node::Dir) = exists {
            return Err(Error::IsDir);
        }
        let write = mode != Open::Read;
        if write {
            self.writable(p)?;
        }
        match (mode, exists.is_some()) {
            (Open::Read, false) => return Err(Error::NotFound),
            (Open::Read, true) => {}
            (_, false) => {
                self.parent_ok(p)?;
                self.tree.insert(p.to_vec(), Node::File { data: Vec::new(), mtime: 0 });
            }
            (Open::Truncate, true) => {
                self.tree.insert(p.to_vec(), Node::File { data: Vec::new(), mtime: 0 });
            }
            _ => {}
        }
        let pos = match (mode, self.tree.get(p)) {
            (Open::Append, Some(Node::File { data, .. })) => data.len(),
            _ => 0,
        };
        self.handles.push(Some(Handle { path: p.to_vec(), pos, write }));
        Ok(self.handles.len() - 1)
    }

    fn read(&mut self, f: usize, buf: &mut [u8]) -> Result<usize, Error> {
        let h = self.handles[f].as_mut().unwrap();
        let Some(Node::File { data, .. }) = self.tree.get(&h.path) else { return Err(Error::Io) };
        let n = buf.len().min(data.len().saturating_sub(h.pos)).min(7);
        buf[..n].copy_from_slice(&data[h.pos..h.pos + n]);
        h.pos += n;
        Ok(n)
    }

    fn write(&mut self, f: usize, buf: &[u8]) -> Result<usize, Error> {
        let h = self.handles[f].as_mut().unwrap();
        assert!(h.write, "write through a read handle");
        let Some(Node::File { data, .. }) = self.tree.get_mut(&h.path) else { return Err(Error::Io) };
        let n = buf.len().min(5);
        if data.len() < h.pos + n {
            data.resize(h.pos + n, 0);
        }
        data[h.pos..h.pos + n].copy_from_slice(&buf[..n]);
        h.pos += n;
        Ok(n)
    }

    fn close(&mut self, f: usize) {
        assert!(self.handles[f].take().is_some(), "closed twice");
    }

    fn mkdir(&mut self, p: &[u8]) -> Result<(), Error> {
        self.writable(p)?;
        if p == b"/" || self.tree.contains_key(p) {
            return Err(Error::Exists);
        }
        self.parent_ok(p)?;
        self.tree.insert(p.to_vec(), Node::Dir);
        Ok(())
    }

    fn unlink(&mut self, p: &[u8]) -> Result<(), Error> {
        self.writable(p)?;
        match self.tree.get(p) {
            None => Err(Error::NotFound),
            Some(Node::Dir) => Err(Error::IsDir),
            Some(_) => {
                self.tree.remove(p);
                Ok(())
            }
        }
    }

    fn rmdir(&mut self, p: &[u8]) -> Result<(), Error> {
        self.writable(p)?;
        match self.tree.get(p) {
            None => Err(Error::NotFound),
            Some(Node::File { .. }) => Err(Error::NotDir),
            Some(Node::Dir) if !self.children(p).is_empty() => Err(Error::NotEmpty),
            Some(Node::Dir) => {
                self.tree.remove(p);
                Ok(())
            }
        }
    }

    fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), Error> {
        self.writable(from)?;
        self.writable(to)?;
        if let Some(v) = &self.other_volume {
            if from.starts_with(v) != to.starts_with(v) {
                return Err(Error::OtherVolume);
            }
        }
        if !self.tree.contains_key(from) {
            return Err(Error::NotFound);
        }
        if self.tree.contains_key(to) {
            return Err(Error::Exists);
        }
        self.parent_ok(to)?;
        let moved: Vec<(Vec<u8>, Node)> = self
            .tree
            .iter()
            .filter(|(k, _)| k.as_slice() == from || (k.starts_with(from) && k[from.len()] == b'/'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in moved {
            self.tree.remove(&k);
            self.tree.insert([to, &k[from.len()..]].concat(), v);
        }
        Ok(())
    }

    fn fs_info(&mut self, _p: &[u8]) -> Result<FsInfo, Error> {
        Ok(FsInfo {
            kind: if self.fold { FsKind::Fat32 } else { FsKind::Tmpfs },
            block: self.block,
            blocks: 1000,
            free: 400,
        })
    }
}

/// Run `name` with `args` on `m` with the default scratch; the status.
pub fn run(m: &mut Mem, name: &str, args: &[&str]) -> i32 {
    run_with(m, name, args, azos_coreutils::SCRATCH_BYTES)
}

pub fn run_with(m: &mut Mem, name: &str, args: &[&str], scratch: usize) -> i32 {
    let a: Vec<&[u8]> = args.iter().map(|s| s.as_bytes()).collect();
    let mut s = vec![0u8; scratch];
    azos_coreutils::run(m, name.as_bytes(), &a, &mut s).expect("not a tool")
}

#[cfg(test)]
mod args_and_paths;
#[cfg(test)]
mod fs_tools;
#[cfg(test)]
mod misc_tools;
#[cfg(test)]
mod text_tools;
