// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's side: build the tree's shape, then keep its values current.

use crate::format::*;
use crate::region::Region;
use core::sync::atomic::{fence, Ordering};

/// Writes one region. Every method takes `&self`: the claims below make the
/// calls safe to race, so the kernel can keep the writer in a static.
pub struct Writer<'a> {
    w: &'a [core::sync::atomic::AtomicU64],
    lay: Layout,
}

impl<'a> Writer<'a> {
    /// Format `region` as an empty tree (the root only) of the given class.
    ///
    /// The magic goes last, so a reader that sees it sees the whole header;
    /// it goes to zero first, so a region being formatted again is refused
    /// meanwhile. Nothing else may touch the region while this runs.
    pub fn init(region: Region<'a>, class: Class) -> Result<Writer<'a>, Error> {
        let w = region.w;
        let lay = Layout::for_words(w.len()).ok_or(Error::BadRegion)?;
        w[H_MAGIC].store(0, Ordering::Relaxed);
        fence(Ordering::Release);
        w[H_VERSION_CLASS].store(pack(FORMAT_VERSION, class as u32), Ordering::Relaxed);
        w[H_EPOCH].store(0, Ordering::Relaxed);
        w[H_LEN_NODECAP].store(pack((w.len() * 8) as u32, lay.node_cap), Ordering::Relaxed);
        w[H_COUNT_WORDCAP].store(pack(1, lay.word_cap), Ordering::Relaxed);
        w[H_WORDS_USED].store(0, Ordering::Relaxed);
        w[H_STAMP].store(0, Ordering::Relaxed);
        let wr = Writer { w, lay };
        wr.write_node(0, Kind::Dir, "", 0, 0, 0, 0);
        w[H_MAGIC].store(MAGIC, Ordering::Release);
        Ok(wr)
    }

    /// Rebuild the tree's shape: the root is emptied and `f` adds the nodes.
    /// The epoch is odd meanwhile, so a reader that opened earlier gets
    /// [`Error::Restructured`] and one that opens now retries. A rebuild
    /// that fails leaves the nodes added so far, whole, and returns the
    /// error. Values set before are gone with their nodes.
    ///
    /// One rebuild at a time ([`Error::Contended`] otherwise), and no value
    /// setter may run meanwhile on ids of the old epoch: the kernel has one
    /// task that does both.
    pub fn rebuild(&self, f: impl FnOnce(&mut Builder<'_, 'a>) -> Result<(), Error>) -> Result<(), Error> {
        let e = self.w[H_EPOCH].load(Ordering::Relaxed);
        if e & 1 != 0
            || self.w[H_EPOCH].compare_exchange(e, e.wrapping_add(1), Ordering::Relaxed, Ordering::Relaxed).is_err()
        {
            return Err(Error::Contended);
        }
        fence(Ordering::Release);
        self.w[self.lay.node_word(0, N_LINKS)].store(0, Ordering::Relaxed);
        let mut b = Builder { wr: self, count: 1, used: 0 };
        let r = f(&mut b);
        self.w[H_COUNT_WORDCAP].store(pack(b.count, self.lay.word_cap), Ordering::Relaxed);
        self.w[H_WORDS_USED].store(b.used as u64, Ordering::Relaxed);
        self.w[H_EPOCH].store(e.wrapping_add(2), Ordering::Release);
        r
    }

    /// Set the stamp: an opaque number readers see next to the tree (the
    /// kernel puts the refresh counter here).
    pub fn stamp(&self, v: u64) {
        self.w[H_STAMP].store(v, Ordering::Release);
    }

    /// Set a `u64` node.
    pub fn set_u64(&self, id: NodeId, v: u64) -> Result<(), Error> {
        let (kind, _, off) = self.meta(id)?;
        if kind != Kind::U64 {
            return Err(Error::WrongKind);
        }
        self.with_seq(id, || self.put_u64(off, v))
    }

    /// Set an `i64` node.
    pub fn set_i64(&self, id: NodeId, v: i64) -> Result<(), Error> {
        let (kind, _, off) = self.meta(id)?;
        if kind != Kind::I64 {
            return Err(Error::WrongKind);
        }
        self.with_seq(id, || self.put_u64(off, v as u64))
    }

    /// Set a string node; text past its capacity is cut at a character.
    pub fn set_str(&self, id: NodeId, s: &str) -> Result<(), Error> {
        let (kind, words, off) = self.meta(id)?;
        if kind != Kind::Str {
            return Err(Error::WrongKind);
        }
        let s = cut(s, (words - 1) * 8);
        self.with_seq(id, || self.put_str(off, words, s))
    }

    /// Set a histogram node: `b` is the first buckets, the rest are zeroed.
    pub fn set_hist(&self, id: NodeId, b: &[u64]) -> Result<(), Error> {
        let (kind, words, off) = self.meta(id)?;
        if kind != Kind::Hist {
            return Err(Error::WrongKind);
        }
        if b.len() > words {
            return Err(Error::BadSize);
        }
        self.with_seq(id, || self.put_hist(off, words, b))
    }

    /// The kind, value words and value offset of a node of the current shape.
    fn meta(&self, id: NodeId) -> Result<(Kind, usize, u32), Error> {
        if id.0 >= lo(self.w[H_COUNT_WORDCAP].load(Ordering::Relaxed)) {
            return Err(Error::BadNode);
        }
        let k = self.w[self.lay.node_word(id.0, N_KIND)].load(Ordering::Relaxed);
        let kind = Kind::from_raw(k as u8).ok_or(Error::Corrupt)?;
        Ok((kind, ((k >> 16) & 0xffff) as usize, hi(k)))
    }

    /// Claim the node's seq (even to odd), run `store`, release it (odd to
    /// even). A claim that finds it odd waits [`SPIN_MAX`] reads.
    fn with_seq(&self, id: NodeId, store: impl FnOnce()) -> Result<(), Error> {
        let seq = &self.w[self.lay.node_word(id.0, N_SEQ)];
        for _ in 0..SPIN_MAX {
            let s = seq.load(Ordering::Relaxed);
            if s & 1 == 0 && seq.compare_exchange(s, s.wrapping_add(1), Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                // The odd seq must be seen before any value store.
                fence(Ordering::Release);
                store();
                seq.store(s.wrapping_add(2), Ordering::Release);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::Contended)
    }

    fn put_u64(&self, off: u32, v: u64) {
        self.w[self.lay.value_word(off)].store(v, Ordering::Relaxed);
    }

    fn put_hist(&self, off: u32, words: usize, b: &[u64]) {
        for i in 0..words {
            self.put_u64(off + i as u32, b.get(i).copied().unwrap_or(0));
        }
    }

    fn put_str(&self, off: u32, words: usize, s: &str) {
        self.w[self.lay.value_word(off)].store(s.len() as u64, Ordering::Relaxed);
        let b = s.as_bytes();
        for i in 0..words - 1 {
            let mut chunk = [0u8; 8];
            let from = i * 8;
            if from < b.len() {
                let n = (b.len() - from).min(8);
                chunk[..n].copy_from_slice(&b[from..from + n]);
            }
            self.w[self.lay.value_word(off + 1 + i as u32)].store(u64::from_le_bytes(chunk), Ordering::Relaxed);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_node(&self, id: u32, kind: Kind, name: &str, words: usize, off: u32, parent: u32, depth: u32) {
        let base = self.lay.node_word(id, 0);
        self.w[base + N_SEQ].store(0, Ordering::Relaxed);
        self.w[base + N_KIND]
            .store(kind as u64 | (name.len() as u64) << 8 | (words as u64) << 16 | (off as u64) << 32, Ordering::Relaxed);
        self.w[base + N_LINKS].store(0, Ordering::Relaxed);
        self.w[base + N_PARENT].store(pack(parent, depth), Ordering::Relaxed);
        let b = name.as_bytes();
        for i in 0..NAME_MAX / 8 {
            let mut chunk = [0u8; 8];
            let from = i * 8;
            if from < b.len() {
                let n = (b.len() - from).min(8);
                chunk[..n].copy_from_slice(&b[from..from + n]);
            }
            self.w[base + N_NAME + i].store(u64::from_le_bytes(chunk), Ordering::Relaxed);
        }
    }
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn cut(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// Adds nodes during [`Writer::rebuild`].
pub struct Builder<'w, 'a> {
    wr: &'w Writer<'a>,
    count: u32,
    used: usize,
}

impl Builder<'_, '_> {
    /// A directory under `parent`.
    pub fn dir(&mut self, parent: NodeId, name: &str) -> Result<NodeId, Error> {
        self.add(parent, name, Kind::Dir, 0).map(|(id, _)| id)
    }

    /// A `u64` under `parent`, starting at `init`.
    pub fn u64(&mut self, parent: NodeId, name: &str, init: u64) -> Result<NodeId, Error> {
        let (id, off) = self.add(parent, name, Kind::U64, 0)?;
        self.wr.put_u64(off, init);
        Ok(id)
    }

    /// An `i64` under `parent`, starting at `init`.
    pub fn i64(&mut self, parent: NodeId, name: &str, init: i64) -> Result<NodeId, Error> {
        let (id, off) = self.add(parent, name, Kind::I64, 0)?;
        self.wr.put_u64(off, init as u64);
        Ok(id)
    }

    /// A string of up to `cap` bytes under `parent`, starting at `init`.
    pub fn string(&mut self, parent: NodeId, name: &str, cap: usize, init: &str) -> Result<NodeId, Error> {
        if cap == 0 || cap > STR_MAX {
            return Err(Error::BadSize);
        }
        let (id, off) = self.add(parent, name, Kind::Str, cap)?;
        self.wr.put_str(off, 1 + cap.div_ceil(8), cut(init, cap));
        Ok(id)
    }

    /// A histogram of `buckets` counters under `parent`, all zero.
    pub fn hist(&mut self, parent: NodeId, name: &str, buckets: usize) -> Result<NodeId, Error> {
        if buckets == 0 || buckets > HIST_MAX {
            return Err(Error::BadSize);
        }
        let (id, off) = self.add(parent, name, Kind::Hist, buckets)?;
        self.wr.put_hist(off, buckets, &[]);
        Ok(id)
    }

    /// A histogram with the counters `init` under `parent`, written with the
    /// node: a rebuilt tree that is seen again holds these values, not zeros.
    pub fn hist_with(&mut self, parent: NodeId, name: &str, init: &[u64]) -> Result<NodeId, Error> {
        if init.is_empty() || init.len() > HIST_MAX {
            return Err(Error::BadSize);
        }
        let (id, off) = self.add(parent, name, Kind::Hist, init.len())?;
        self.wr.put_hist(off, init.len(), init);
        Ok(id)
    }

    /// The new node and the offset of its value words.
    fn add(&mut self, parent: NodeId, name: &str, kind: Kind, size: usize) -> Result<(NodeId, u32), Error> {
        let wr = self.wr;
        if name.is_empty() || name.len() > NAME_MAX || name.bytes().any(|c| c == b'/' || c == 0) {
            return Err(Error::BadName);
        }
        if parent.0 >= self.count {
            return Err(Error::BadNode);
        }
        let pw = wr.lay.node_word(parent.0, 0);
        if wr.w[pw + N_KIND].load(Ordering::Relaxed) as u8 != Kind::Dir as u8 {
            return Err(Error::WrongKind);
        }
        let depth = hi(wr.w[pw + N_PARENT].load(Ordering::Relaxed)) + 1;
        if depth > DEPTH_MAX {
            return Err(Error::TooDeep);
        }
        // Siblings, to refuse a duplicate and to find the last one.
        let mut last = 0u32;
        let mut cur = lo(wr.w[pw + N_LINKS].load(Ordering::Relaxed));
        while cur != 0 {
            if self.name_is(cur, name) {
                return Err(Error::Duplicate);
            }
            last = cur;
            cur = hi(wr.w[wr.lay.node_word(cur, N_LINKS)].load(Ordering::Relaxed));
        }
        let words = value_words(kind, size);
        if self.count >= wr.lay.node_cap || self.used + words > wr.lay.word_cap as usize {
            return Err(Error::NoSpace);
        }
        let id = self.count;
        let off = self.used as u32;
        wr.write_node(id, kind, name, words, off, parent.0, depth);
        self.count += 1;
        self.used += words;
        // Link last: the node is whole before the tree reaches it.
        let link = if last == 0 { pw + N_LINKS } else { wr.lay.node_word(last, N_LINKS) };
        let old = wr.w[link].load(Ordering::Relaxed);
        let new = if last == 0 { pack(id, hi(old)) } else { pack(lo(old), id) };
        wr.w[link].store(new, Ordering::Relaxed);
        Ok((NodeId(id), off))
    }

    fn name_is(&self, id: u32, name: &str) -> bool {
        let base = self.wr.lay.node_word(id, 0);
        let len = (self.wr.w[base + N_KIND].load(Ordering::Relaxed) >> 8) as u8 as usize;
        if len != name.len() {
            return false;
        }
        let b = name.as_bytes();
        (0..len).all(|i| {
            let word = self.wr.w[base + N_NAME + i / 8].load(Ordering::Relaxed).to_le_bytes();
            word[i % 8] == b[i]
        })
    }
}
