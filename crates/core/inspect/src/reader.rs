// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The reading side: open a mapped region, look nodes up, read values, walk.
//! Loads only, so the mapping may be read-only.

use crate::format::*;
use crate::region::Region;
use core::sync::atomic::{fence, AtomicU64, Ordering};

/// A node's name.
#[derive(Clone, Copy)]
pub struct Name {
    len: u8,
    buf: [u8; NAME_MAX],
}

impl Name {
    pub fn as_str(&self) -> &str {
        // Validated as UTF-8 when the name was read.
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

/// A string value.
#[derive(Clone, Copy)]
pub struct Str {
    len: u8,
    buf: [u8; STR_MAX],
}

impl Str {
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

/// A histogram value.
#[derive(Clone, Copy)]
pub struct Hist {
    n: u8,
    b: [u64; HIST_MAX],
}

impl Hist {
    pub fn buckets(&self) -> &[u64] {
        &self.b[..self.n as usize]
    }
}

/// A node's value, read whole.
#[derive(Clone, Copy)]
pub enum Value {
    Dir,
    U64(u64),
    I64(i64),
    Str(Str),
    Hist(Hist),
}

/// What a node is, apart from its value.
#[derive(Clone, Copy)]
pub struct NodeInfo {
    pub id: NodeId,
    pub kind: Kind,
    pub name: Name,
    /// Below the root: the root's children are at 1.
    pub depth: u32,
    pub parent: NodeId,
}

/// An open region. Ids it hands out belong to the epoch it holds.
pub struct Reader<'a> {
    w: &'a [AtomicU64],
    lay: Layout,
    class: Class,
    epoch: u64,
}

impl<'a> Reader<'a> {
    /// Open `region`, which must be of class `expect`.
    ///
    /// Refused, in this order: a region too small ([`Error::BadRegion`]), a
    /// wrong magic, a layout version other than [`FORMAT_VERSION`]
    /// ([`Error::VersionMismatch`]), a class other than `expect`
    /// ([`Error::WrongClass`]: the admin region is not readable as a public
    /// one, nor the reverse), a header that contradicts itself. A rebuild in
    /// progress is [`Error::Contended`].
    pub fn open(region: Region<'a>, expect: Class) -> Result<Reader<'a>, Error> {
        let w = region.w;
        if w.len() < HEADER_WORDS {
            return Err(Error::BadRegion);
        }
        if w[H_MAGIC].load(Ordering::Acquire) != MAGIC {
            return Err(Error::BadMagic);
        }
        let vc = w[H_VERSION_CLASS].load(Ordering::Relaxed);
        if lo(vc) != FORMAT_VERSION {
            return Err(Error::VersionMismatch { found: lo(vc) });
        }
        let class = Class::from_raw(hi(vc)).ok_or(Error::Corrupt)?;
        if class != expect {
            return Err(Error::WrongClass { found: hi(vc) });
        }
        let lc = w[H_LEN_NODECAP].load(Ordering::Relaxed);
        let cw = w[H_COUNT_WORDCAP].load(Ordering::Relaxed);
        let (len, node_cap, word_cap) = (lo(lc) as usize, hi(lc), hi(cw));
        let need = HEADER_WORDS + node_cap as usize * NODE_WORDS + word_cap as usize;
        if len % 8 != 0 || len > w.len() * 8 || node_cap == 0 || need > len / 8 {
            return Err(Error::Corrupt);
        }
        for _ in 0..SPIN_MAX {
            let epoch = w[H_EPOCH].load(Ordering::Acquire);
            if epoch & 1 == 0 {
                return Ok(Reader { w, lay: Layout { node_cap, word_cap }, class, epoch });
            }
            core::hint::spin_loop();
        }
        Err(Error::Contended)
    }

    /// Open the same region again, after [`Error::Restructured`].
    pub fn refresh(&mut self) -> Result<(), Error> {
        *self = Reader::open(Region { w: self.w }, self.class)?;
        Ok(())
    }

    pub fn class(&self) -> Class {
        self.class
    }

    /// The epoch ids belong to; it grows by two at every rebuild.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The writer's stamp (the kernel's refresh count).
    pub fn stamp(&self) -> u64 {
        self.w[H_STAMP].load(Ordering::Acquire)
    }

    /// Run `f`, then check the epoch did not move under it. A moved epoch
    /// wins over whatever `f` made of a tree that was being rebuilt.
    fn op<T>(&self, f: impl FnOnce(&Self) -> Result<T, Error>) -> Result<T, Error> {
        let r = f(self);
        fence(Ordering::Acquire);
        if self.w[H_EPOCH].load(Ordering::Relaxed) != self.epoch {
            return Err(Error::Restructured);
        }
        r
    }

    fn count(&self) -> Result<u32, Error> {
        let c = lo(self.w[H_COUNT_WORDCAP].load(Ordering::Relaxed));
        if c == 0 || c > self.lay.node_cap {
            return Err(Error::Corrupt);
        }
        Ok(c)
    }

    fn word(&self, id: NodeId, field: usize) -> Result<u64, Error> {
        if id.0 >= self.count()? {
            return Err(Error::BadNode);
        }
        Ok(self.w[self.lay.node_word(id.0, field)].load(Ordering::Relaxed))
    }

    fn info_raw(&self, id: NodeId) -> Result<NodeInfo, Error> {
        let k = self.word(id, N_KIND)?;
        let kind = Kind::from_raw(k as u8).ok_or(Error::Corrupt)?;
        let len = (k >> 8) as u8 as usize;
        let p = self.word(id, N_PARENT)?;
        if len > NAME_MAX || hi(p) > DEPTH_MAX || lo(p) >= self.count()? {
            return Err(Error::Corrupt);
        }
        let mut buf = [0u8; NAME_MAX];
        for i in 0..NAME_MAX / 8 {
            buf[i * 8..i * 8 + 8].copy_from_slice(&self.word(id, N_NAME + i)?.to_le_bytes());
        }
        if core::str::from_utf8(&buf[..len]).is_err() {
            return Err(Error::Corrupt);
        }
        Ok(NodeInfo { id, kind, name: Name { len: len as u8, buf }, depth: hi(p), parent: NodeId(lo(p)) })
    }

    /// A node's kind, name, depth and parent.
    pub fn info(&self, id: NodeId) -> Result<NodeInfo, Error> {
        self.op(|s| s.info_raw(id))
    }

    fn link(&self, id: NodeId, next: bool) -> Result<Option<NodeId>, Error> {
        let l = self.word(id, N_LINKS)?;
        let n = if next { hi(l) } else { lo(l) };
        if n >= self.count()? {
            return Err(Error::Corrupt);
        }
        Ok((n != 0).then_some(NodeId(n)))
    }

    fn find_raw(&self, parent: NodeId, name: &str) -> Result<Option<NodeId>, Error> {
        let mut cur = self.link(parent, false)?;
        // A chain longer than the table is a cycle.
        for _ in 0..self.count()? {
            let Some(id) = cur else { return Ok(None) };
            if self.info_raw(id)?.name.as_str() == name {
                return Ok(Some(id));
            }
            cur = self.link(id, true)?;
        }
        Err(Error::Corrupt)
    }

    /// The node at `path`: names separated by `/`, empty segments ignored,
    /// from the root. `None` when a segment is missing.
    pub fn lookup(&self, path: &str) -> Result<Option<NodeId>, Error> {
        self.op(|s| {
            let mut cur = NodeId::ROOT;
            for seg in path.split('/').filter(|p| !p.is_empty()) {
                match s.find_raw(cur, seg)? {
                    Some(n) => cur = n,
                    None => return Ok(None),
                }
            }
            Ok(Some(cur))
        })
    }

    fn read_raw(&self, id: NodeId) -> Result<Value, Error> {
        let k = self.word(id, N_KIND)?;
        let kind = Kind::from_raw(k as u8).ok_or(Error::Corrupt)?;
        let words = ((k >> 16) & 0xffff) as usize;
        let off = hi(k) as usize;
        if off + words > self.lay.word_cap as usize {
            return Err(Error::Corrupt);
        }
        if kind == Kind::Dir {
            return Ok(Value::Dir);
        }
        let seq = &self.w[self.lay.node_word(id.0, N_SEQ)];
        let vw = |i: usize| self.w[self.lay.value_word((off + i) as u32)].load(Ordering::Relaxed);
        for _ in 0..SPIN_MAX {
            let s1 = seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            // Copy out; nothing is trusted until the seq is checked.
            let mut val = match kind {
                Kind::U64 => Value::U64(vw(0)),
                Kind::I64 => Value::I64(vw(0) as i64),
                Kind::Str => {
                    let mut st = Str { len: vw(0).min(((words - 1) * 8).min(STR_MAX) as u64) as u8, buf: [0; STR_MAX] };
                    for i in 0..(st.len as usize).div_ceil(8) {
                        st.buf[i * 8..i * 8 + 8].copy_from_slice(&vw(1 + i).to_le_bytes());
                    }
                    Value::Str(st)
                }
                Kind::Hist => {
                    let mut h = Hist { n: words.min(HIST_MAX) as u8, b: [0; HIST_MAX] };
                    for i in 0..h.n as usize {
                        h.b[i] = vw(i);
                    }
                    Value::Hist(h)
                }
                Kind::Dir => Value::Dir,
            };
            fence(Ordering::Acquire);
            if seq.load(Ordering::Relaxed) == s1 {
                if let Value::Str(st) = &mut val {
                    if core::str::from_utf8(&st.buf[..st.len as usize]).is_err() {
                        return Err(Error::Corrupt);
                    }
                }
                return Ok(val);
            }
        }
        Err(Error::Contended)
    }

    /// A node's value, read whole: a histogram or a string is one instant's.
    pub fn read(&self, id: NodeId) -> Result<Value, Error> {
        self.op(|s| s.read_raw(id))
    }

    /// Visit every node in depth-first order, parents before children, with
    /// its value (`Value::Dir` for a directory). [`Error::Restructured`]
    /// leaves the callback having seen part of the old tree: refresh and
    /// walk again.
    pub fn walk(&self, f: &mut dyn FnMut(&NodeInfo, &Value)) -> Result<(), Error> {
        self.op(|s| {
            let n = s.count()?;
            let mut cur = NodeId::ROOT;
            // Each node is entered once and left once.
            for _ in 0..=(2 * n) {
                let info = s.info_raw(cur)?;
                f(&info, &s.read_raw(cur)?);
                let mut next = s.link(cur, false)?;
                let mut at = cur;
                while next.is_none() {
                    if at == NodeId::ROOT {
                        return Ok(());
                    }
                    next = s.link(at, true)?;
                    if next.is_none() {
                        at = s.info_raw(at)?.parent;
                    }
                }
                cur = next.unwrap_or(NodeId::ROOT);
            }
            Err(Error::Corrupt)
        })
    }
}
