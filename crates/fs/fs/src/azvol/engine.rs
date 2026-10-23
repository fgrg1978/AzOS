// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block-level engine under [`super::Volume`]: verified reads, checksummed
//! writes, the allocator with its deferred frees, and the file operations
//! (read, write, truncate, extent-tree load and store) on one [`Inode`].
//!
//! Every file operation takes the inode as an explicit `&mut` next to `&mut
//! Core`, so the volume can hold the inode cache and the engine as disjoint
//! fields without removing an inode from the cache while it works on it.
//!
//! **Copy on write.** A committed block is never overwritten: a write to a
//! block whose extent carries an older generation allocates new blocks,
//! writes them, and swaps the mapping. A block whose extent carries the
//! open transaction's generation is named by no committed tree and is
//! overwritten in place. The blocks a swap gives up are returned to the
//! allocator only after the commit that stops naming them is durable, and
//! only if no retained snapshot still names them ([`super::snap`]): those
//! go to the dead list instead.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::crc32c::crc32c;
use super::dev::BlockDev;
use super::extent;
use super::freemap::FreeMap;
use super::seal::{self, Sealer};
use super::snap::{self, DeadEnt, SnapRec};
use super::layout::{
    rd32, wr32, Extent, Geometry, IndexEnt, InodeDisk, Kind, NodeHdr, BLOCK_SIZE, BS, ENTRY_SIZE, INLINE_CAP,
    MAX_FILE_BYTES, MAX_LEVEL, NODE_CAP, NODE_HDR,
};
use super::Error;

/// Longest run the allocator hands out at once (64 MiB).
const MAX_RUN: u32 = 1 << 14;
/// Blocks read per device call when filling a caller's buffer.
const READ_CHUNK: u64 = 64;

/// A file, directory or the inode table in memory: the record's fields and
/// the whole extent list. The extent tree is rebuilt from the list when the
/// inode is committed with `ext_dirty` set.
#[derive(Clone, Debug)]
pub struct Inode {
    pub ino: u64,
    pub kind: Kind,
    pub mode: u16,
    pub igen: u32,
    pub size: u64,
    pub gen: u64,
    pub ctime_ns: u64,
    pub mtime_ns: u64,
    /// Directory: parent inode. Free slot: next free inode.
    pub link: u64,
    pub extents: Vec<Extent>,
    /// `(block, generation)` of the tree nodes currently holding `extents`.
    pub nodes: Vec<(u64, u64)>,
    pub dirty: bool,
    pub ext_dirty: bool,
    /// Blocks this file gives up may be named by a snapshot (every file and
    /// the inode table). The snapshot table and the dead list are not
    /// versioned: no snapshot holds them, their old blocks are simply freed.
    pub versioned: bool,
    root_level: u8,
    root: [u8; INLINE_CAP * ENTRY_SIZE],
    root_count: u16,
}

impl Inode {
    pub fn blank(ino: u64, kind: Kind) -> Inode {
        Inode {
            ino,
            kind,
            mode: 0,
            igen: 0,
            size: 0,
            gen: 0,
            ctime_ns: 0,
            mtime_ns: 0,
            link: 0,
            extents: Vec::new(),
            nodes: Vec::new(),
            dirty: true,
            ext_dirty: true,
            versioned: true,
            root_level: 0,
            root: [0; INLINE_CAP * ENTRY_SIZE],
            root_count: 0,
        }
    }

    /// Header fields from a record; the extents are filled by `load_tree`.
    pub fn from_disk(ino: u64, d: &InodeDisk) -> Inode {
        Inode {
            ino,
            kind: d.kind,
            mode: d.mode,
            igen: d.igen,
            size: d.size,
            gen: d.gen,
            ctime_ns: d.ctime_ns,
            mtime_ns: d.mtime_ns,
            link: d.link,
            extents: Vec::new(),
            nodes: Vec::new(),
            dirty: false,
            ext_dirty: false,
            versioned: true,
            root_level: d.level,
            root: d.root,
            root_count: d.count,
        }
    }

    /// The record as it will be stored; the root is the one `store_tree` set.
    pub fn to_disk(&self) -> InodeDisk {
        InodeDisk {
            ino: self.ino,
            size: self.size,
            gen: self.gen,
            ctime_ns: self.ctime_ns,
            mtime_ns: self.mtime_ns,
            link: self.link,
            igen: self.igen,
            kind: self.kind,
            level: self.root_level,
            count: self.root_count,
            mode: self.mode,
            root: self.root,
        }
    }
}

pub struct Core<D: BlockDev> {
    pub dev: D,
    pub geo: Geometry,
    /// Last committed generation; the open transaction is `gen + 1`.
    pub gen: u64,
    pub bitmap: FreeMap,
    /// Set bits in `bitmap` (blocks allocated, including ones whose free is
    /// still deferred).
    pub used: u64,
    /// Blocks given up by committed trees, free once the commit is durable.
    pub pending: Vec<(u64, u32)>,
    pub pending_total: u64,
    csum: BTreeMap<u64, (Vec<u8>, bool)>,
    /// Retained generations, ascending (the snapshot table in memory).
    pub snaps: Vec<SnapRec>,
    /// First `snaps` index changed since the last commit (`usize::MAX` = none).
    pub snaps_from: usize,
    /// Runs the live tree gave up that a snapshot still names, each with the
    /// generations between which the live tree held it.
    pub dead: Vec<DeadEnt>,
    /// Length of `dead` at the start of the open transaction: entries below
    /// it are committed and never merged into or dropped by a rollback.
    pub dead_base: usize,
    /// First `dead` index changed since the last commit (`usize::MAX` = none).
    pub dead_from: usize,
    /// Runs allocated in the open transaction, kept while a change group is
    /// open so an abort can give them back.
    pub undo: Option<Vec<(u64, u32)>>,
    pub time_ns: u64,
    /// The key of a sealed volume ([`super::seal`]); `None` on a plain one.
    pub seal: Option<Sealer>,
    /// Unlink, truncate and commit may dip into the reserve that ordinary
    /// writes leave free (a copy-on-write volume needs space to delete).
    pub privileged: bool,
    reserve: u64,
}

impl<D: BlockDev> Core<D> {
    pub fn new(dev: D, geo: Geometry, gen: u64, bitmap: FreeMap, used: u64) -> Core<D> {
        Core {
            dev,
            geo,
            gen,
            bitmap,
            used,
            pending: Vec::new(),
            pending_total: 0,
            csum: BTreeMap::new(),
            snaps: Vec::new(),
            snaps_from: usize::MAX,
            dead: Vec::new(),
            dead_base: 0,
            dead_from: usize::MAX,
            undo: None,
            time_ns: 0,
            seal: None,
            privileged: false,
            reserve: 8 + geo.block_count / 256,
        }
    }

    pub fn txn_gen(&self) -> u64 {
        self.gen + 1
    }

    // ---- checksum table ------------------------------------------------

    fn csum_block(&mut self, idx: u64) -> Result<&mut (Vec<u8>, bool), Error> {
        if !self.csum.contains_key(&idx) {
            let mut v = vec![0u8; BLOCK_SIZE];
            self.dev.read(self.geo.csum_start + idx, &mut v).map_err(|_| Error::Io)?;
            self.csum.insert(idx, (v, false));
        }
        Ok(self.csum.get_mut(&idx).unwrap())
    }

    fn csum_get(&mut self, blk: u64) -> Result<u32, Error> {
        let (idx, off) = self.geo.table_loc(blk);
        let e = self.csum_block(idx)?;
        Ok(rd32(&e.0, off))
    }

    fn csum_set(&mut self, blk: u64, v: u32) -> Result<(), Error> {
        let (idx, off) = self.geo.table_loc(blk);
        let e = self.csum_block(idx)?;
        wr32(&mut e.0, off, v);
        e.1 = true;
        Ok(())
    }

    /// A sealed volume's table entry for `blk`: tag and sequence number.
    fn entry_get(&mut self, blk: u64) -> Result<([u8; 16], u64), Error> {
        let (idx, off) = self.geo.table_loc(blk);
        let e = self.csum_block(idx)?;
        Ok(seal::decode_entry(&e.0[off..]))
    }

    fn entry_set(&mut self, blk: u64, tag: &[u8; 16], seq: u64) -> Result<(), Error> {
        let (idx, off) = self.geo.table_loc(blk);
        let e = self.csum_block(idx)?;
        seal::encode_entry(tag, seq, &mut e.0[off..]);
        e.1 = true;
        Ok(())
    }

    /// Write the checksum-table blocks changed since the last call.
    pub fn flush_csums(&mut self) -> Result<(), Error> {
        let idxs: Vec<u64> = self.csum.iter().filter(|(_, v)| v.1).map(|(k, _)| *k).collect();
        let mut i = 0;
        while i < idxs.len() {
            let mut j = i + 1;
            while j < idxs.len() && idxs[j] == idxs[j - 1] + 1 {
                j += 1;
            }
            let mut buf = Vec::with_capacity((j - i) * BLOCK_SIZE);
            for k in &idxs[i..j] {
                buf.extend_from_slice(&self.csum[k].0);
            }
            self.dev.write(self.geo.csum_start + idxs[i], &buf).map_err(|_| Error::Io)?;
            for k in &idxs[i..j] {
                self.csum.get_mut(k).unwrap().1 = false;
            }
            i = j;
        }
        Ok(())
    }

    /// Write the bitmap blocks changed since the last call.
    pub fn flush_bitmap(&mut self) -> Result<(), Error> {
        let idxs = self.bitmap.take_dirty();
        let mut i = 0;
        while i < idxs.len() {
            let mut j = i + 1;
            while j < idxs.len() && idxs[j] == idxs[j - 1] + 1 {
                j += 1;
            }
            let mut buf = vec![0u8; (j - i) * BLOCK_SIZE];
            for (n, k) in idxs[i..j].iter().enumerate() {
                self.bitmap.encode_block(*k, &mut buf[n * BLOCK_SIZE..(n + 1) * BLOCK_SIZE]);
            }
            if self.dev.write(self.geo.bitmap_start + idxs[i], &buf).is_err() {
                self.bitmap.mark_all_dirty(&self.geo);
                return Err(Error::Io);
            }
            i = j;
        }
        Ok(())
    }

    // ---- verified block I/O ---------------------------------------------

    fn check_range(&self, first: u64, n: u64) -> Result<(), Error> {
        match first.checked_add(n) {
            Some(end) if first >= self.geo.data_start && end <= self.geo.block_count && n > 0 => Ok(()),
            _ => Err(Error::Corrupt("block outside data area")),
        }
    }

    /// Read `out.len() / BLOCK_SIZE` data-area blocks and verify each: against
    /// the checksum table, or on a sealed volume by opening it
    /// ([`Error::Auth`]; `out` is wiped, no byte of a failed block is
    /// returned).
    pub fn read_run(&mut self, first: u64, out: &mut [u8]) -> Result<(), Error> {
        let n = (out.len() / BLOCK_SIZE) as u64;
        self.check_range(first, n)?;
        self.dev.read(first, out).map_err(|_| Error::Io)?;
        if self.geo.sealed {
            for i in 0..n {
                let blk = first + i;
                let (tag, seq) = self.entry_get(blk)?;
                let key = self.seal.as_ref().ok_or(Error::KeyRequired)?;
                if !key.open(blk, seq, &tag, &mut out[i as usize * BLOCK_SIZE..(i as usize + 1) * BLOCK_SIZE]) {
                    out.fill(0);
                    return Err(Error::Auth(blk));
                }
            }
            return Ok(());
        }
        for i in 0..n {
            let blk = &out[i as usize * BLOCK_SIZE..(i as usize + 1) * BLOCK_SIZE];
            if crc32c(blk) != self.csum_get(first + i)? {
                return Err(Error::Checksum(first + i));
            }
        }
        Ok(())
    }

    /// Write data-area blocks and record their checksums, or on a sealed
    /// volume seal each under a fresh sequence number and record tag and
    /// sequence number.
    pub fn write_run(&mut self, first: u64, data: &[u8]) -> Result<(), Error> {
        let n = (data.len() / BLOCK_SIZE) as u64;
        self.check_range(first, n)?;
        if self.geo.sealed {
            let txn = self.txn_gen();
            let mut ct = data.to_vec();
            let mut tags = Vec::with_capacity(n as usize);
            for i in 0..n {
                let blk = first + i;
                let key = self.seal.as_mut().ok_or(Error::KeyRequired)?;
                let seq = key.next_seq(txn)?;
                tags.push((key.seal(blk, seq, &mut ct[i as usize * BLOCK_SIZE..(i as usize + 1) * BLOCK_SIZE]), seq));
            }
            self.dev.write(first, &ct).map_err(|_| Error::Io)?;
            for (i, (tag, seq)) in tags.iter().enumerate() {
                self.entry_set(first + i as u64, tag, *seq)?;
            }
            return Ok(());
        }
        self.dev.write(first, data).map_err(|_| Error::Io)?;
        for i in 0..n {
            let c = crc32c(&data[i as usize * BLOCK_SIZE..(i as usize + 1) * BLOCK_SIZE]);
            self.csum_set(first + i, c)?;
        }
        Ok(())
    }

    // ---- allocator -------------------------------------------------------

    /// A free run of at most `want` blocks (next-fit), marked used.
    pub fn alloc(&mut self, want: u32) -> Result<(u64, u32), Error> {
        let free = self.geo.block_count - self.used;
        let reserve = if self.privileged { 0 } else { self.reserve };
        if free <= reserve {
            return Err(Error::NoSpace);
        }
        let cap = (free - reserve).min(MAX_RUN as u64) as u32;
        let want = want.min(cap).max(1);
        let (s, l) = self.bitmap.find_run(want, self.geo.data_start).ok_or(Error::NoSpace)?;
        for b in s..s + l as u64 {
            self.bitmap.set(b);
        }
        self.used += l as u64;
        if let Some(u) = self.undo.as_mut() {
            u.push((s, l));
        }
        Ok((s, l))
    }

    /// Give a run back; `born` is the generation that wrote it. A block
    /// written in the open transaction is named by no committed tree and is
    /// free at once. A committed one that a retained snapshot names
    /// (`versioned` files only, see [`Inode::versioned`]) moves to the dead
    /// list; any other waits for the commit that stops naming it.
    pub fn release(&mut self, start: u64, n: u32, born: u64, versioned: bool) {
        if n == 0 {
            return;
        }
        let txn = self.txn_gen();
        if born == txn {
            for b in start..start + n as u64 {
                self.bitmap.clear(b);
            }
            self.used -= n as u64;
        } else if versioned && snap::held(&self.snaps, born, txn) {
            self.push_dead(DeadEnt { disk_blk: start, nblocks: n, born, died: txn });
        } else {
            self.pending.push((start, n));
            self.pending_total += n as u64;
        }
    }

    fn push_dead(&mut self, e: DeadEnt) {
        if self.dead.len() > self.dead_base {
            let last = self.dead.len() - 1;
            if self.dead[last].continues_with(&e) {
                self.dead[last].nblocks += e.nblocks;
                self.dead_from = self.dead_from.min(last);
                return;
            }
        }
        self.dead_from = self.dead_from.min(self.dead.len());
        self.dead.push(e);
    }

    /// Forget the open transaction: give back every block it allocated and
    /// drop what it queued. Nothing of it reached the disk's bitmap or
    /// the superblock, and every committed block is still named, so the
    /// in-memory map goes back to exactly the committed one.
    pub fn rollback_txn(&mut self) {
        if let Some(runs) = self.undo.as_mut() {
            for (s, l) in core::mem::take(runs) {
                for b in s..s + l as u64 {
                    if self.bitmap.clear(b) {
                        self.used -= 1;
                    }
                }
            }
        }
        self.pending.clear();
        self.pending_total = 0;
        self.dead.truncate(self.dead_base);
        self.dead_from = usize::MAX;
    }

    /// Apply the deferred frees (after the superblock that stops naming
    /// those blocks is durable). Returns them, sorted, adjacent runs merged
    /// up to `MAX_RUN` blocks: what the commit tells the device to discard.
    pub fn apply_pending(&mut self) -> Vec<(u64, u32)> {
        let mut p = core::mem::take(&mut self.pending);
        for &(s, n) in &p {
            for b in s..s + n as u64 {
                self.bitmap.clear(b);
            }
            self.used -= n as u64;
        }
        self.pending_total = 0;
        p.sort_unstable();
        let mut runs: Vec<(u64, u32)> = Vec::with_capacity(p.len());
        for (s, n) in p {
            match runs.last_mut() {
                Some(r) if r.0 + r.1 as u64 == s && r.1 + n <= MAX_RUN => r.1 += n,
                _ => runs.push((s, n)),
            }
        }
        runs
    }

    // ---- extent tree -----------------------------------------------------

    /// Read an inode's whole extent list from its record's root, verifying
    /// every node (checksum, magic, level, owner, generation, self block).
    pub fn load_tree(&mut self, d: &InodeDisk, owner: u64) -> Result<(Vec<Extent>, Vec<(u64, u64)>), Error> {
        let mut exts = Vec::new();
        let mut nodes = Vec::new();
        if d.level == 0 {
            for i in 0..d.count as usize {
                exts.push(Extent::decode(&d.root[i * ENTRY_SIZE..]));
            }
        } else {
            let mut budget = self.geo.block_count;
            for i in 0..d.count as usize {
                let ie = IndexEnt::decode(&d.root[i * ENTRY_SIZE..]);
                self.read_subtree(ie, d.level - 1, owner, &mut exts, &mut nodes, &mut budget)?;
            }
        }
        // a committed tree never carries the open transaction's generation
        extent::validate(&exts, &self.geo, self.gen)?;
        Ok((exts, nodes))
    }

    fn read_subtree(
        &mut self,
        ie: IndexEnt,
        level: u8,
        owner: u64,
        exts: &mut Vec<Extent>,
        nodes: &mut Vec<(u64, u64)>,
        budget: &mut u64,
    ) -> Result<(), Error> {
        if *budget == 0 {
            return Err(Error::Corrupt("extent tree larger than the volume"));
        }
        *budget -= 1;
        let mut buf = vec![0u8; BLOCK_SIZE];
        self.read_run(ie.child, &mut buf)?;
        let h = NodeHdr::decode(&buf)?;
        if h.level != level as u16
            || h.count == 0
            || h.count as usize > NODE_CAP
            || h.self_blk != ie.child
            || h.owner != owner
            || h.gen != ie.child_gen
            || h.gen > self.gen
        {
            return Err(Error::Corrupt("tree node header"));
        }
        nodes.push((ie.child, h.gen));
        for i in 0..h.count as usize {
            let ent = &buf[NODE_HDR + i * ENTRY_SIZE..NODE_HDR + (i + 1) * ENTRY_SIZE];
            if level == 0 {
                exts.push(Extent::decode(ent));
            } else {
                self.read_subtree(IndexEnt::decode(ent), level - 1, owner, exts, nodes, budget)?;
            }
        }
        Ok(())
    }

    /// Write an inode's extent list as a tree (inline when it fits the
    /// record, else leaf and index node blocks) and release the nodes of
    /// the previous tree. Sets the record's root.
    pub fn store_tree(&mut self, inode: &mut Inode) -> Result<(), Error> {
        let txn = self.txn_gen();
        for (b, g) in core::mem::take(&mut inode.nodes) {
            self.release(b, 1, g, inode.versioned);
        }
        let mut cur: Vec<(u64, [u8; ENTRY_SIZE])> = inode.extents.iter().map(|e| (e.file_blk, e.encode())).collect();
        let mut level = 0u8;
        loop {
            if cur.len() <= INLINE_CAP {
                break;
            }
            if level >= MAX_LEVEL {
                return Err(Error::TooBig);
            }
            let mut next = Vec::new();
            for chunk in cur.chunks(NODE_CAP) {
                let (blk, got) = self.alloc(1)?;
                debug_assert_eq!(got, 1);
                let mut buf = vec![0u8; BLOCK_SIZE];
                NodeHdr { level: level as u16, count: chunk.len() as u16, self_blk: blk, gen: txn, owner: inode.ino }
                    .encode(&mut buf[..NODE_HDR]);
                for (i, (_, ent)) in chunk.iter().enumerate() {
                    buf[NODE_HDR + i * ENTRY_SIZE..NODE_HDR + (i + 1) * ENTRY_SIZE].copy_from_slice(ent);
                }
                self.write_run(blk, &buf)?;
                inode.nodes.push((blk, txn));
                next.push((chunk[0].0, IndexEnt { key: chunk[0].0, child: blk, child_gen: txn }.encode()));
            }
            cur = next;
            level += 1;
        }
        inode.root = [0; INLINE_CAP * ENTRY_SIZE];
        for (i, (_, ent)) in cur.iter().enumerate() {
            inode.root[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(ent);
        }
        inode.root_level = level;
        inode.root_count = cur.len() as u16;
        inode.ext_dirty = false;
        Ok(())
    }

    // ---- file data -------------------------------------------------------

    /// Fill `buf` from file offset `off` through `exts`, holes as zeros. No
    /// size clamp: the caller bounds the range.
    pub fn read_range(&mut self, exts: &[Extent], off: u64, buf: &mut [u8]) -> Result<(), Error> {
        for x in buf.iter_mut() {
            *x = 0;
        }
        if buf.is_empty() {
            return Ok(());
        }
        let end = off + buf.len() as u64;
        let (fb0, fb1) = (off / BS, (end - 1) / BS + 1);
        let mut tmp: Vec<u8> = Vec::new();
        let mut i = extent::first_after(exts, fb0);
        while i < exts.len() && exts[i].file_blk < fb1 {
            let e = exts[i];
            let t = e.file_end().min(fb1);
            let mut b = e.file_blk.max(fb0);
            while b < t {
                let c = (t - b).min(READ_CHUNK);
                tmp.resize(c as usize * BLOCK_SIZE, 0);
                self.read_run(e.disk_blk + (b - e.file_blk), &mut tmp)?;
                let lo = (b * BS).max(off);
                let hi = ((b + c) * BS).min(end);
                buf[(lo - off) as usize..(hi - off) as usize]
                    .copy_from_slice(&tmp[(lo - b * BS) as usize..(hi - b * BS) as usize]);
                b += c;
            }
            i += 1;
        }
        Ok(())
    }

    /// Read file bytes, clamped to the file size; returns the count.
    pub fn file_read(&mut self, inode: &Inode, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if off >= inode.size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(inode.size - off) as usize;
        self.read_range(&inode.extents, off, &mut buf[..n])?;
        Ok(n)
    }

    /// The blocks `[fb0, fb1)` as the write of `data` at `off` leaves them,
    /// reading the old content only of a block the write covers partly.
    fn assemble(&mut self, exts: &[Extent], fb0: u64, fb1: u64, off: u64, data: &[u8]) -> Result<Vec<u8>, Error> {
        let n = (fb1 - fb0) as usize;
        let mut buf = vec![0u8; n * BLOCK_SIZE];
        let base = fb0 * BS;
        let end = off + data.len() as u64;
        for k in 0..n {
            let (bs, be) = (base + k as u64 * BS, base + (k as u64 + 1) * BS);
            if !(off <= bs && end >= be) {
                self.read_range(exts, bs, &mut buf[k * BLOCK_SIZE..(k + 1) * BLOCK_SIZE])?;
            }
        }
        let lo = off.max(base);
        let hi = end.min(base + n as u64 * BS);
        buf[(lo - base) as usize..(hi - base) as usize].copy_from_slice(&data[(lo - off) as usize..(hi - off) as usize]);
        Ok(buf)
    }

    /// Write `data` at `off` without touching the size. Blocks of the open
    /// transaction are overwritten in place; everything else goes to new
    /// blocks and the mapping is swapped once they are written.
    pub fn write_range(&mut self, inode: &mut Inode, off: u64, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        let end = off.checked_add(data.len() as u64).filter(|e| *e <= MAX_FILE_BYTES).ok_or(Error::TooBig)?;
        let fb1 = (end - 1) / BS + 1;
        let txn = self.txn_gen();
        let mut fb = off / BS;
        while fb < fb1 {
            match extent::containing(&inode.extents, fb) {
                Some(i) if inode.extents[i].gen == txn => {
                    let e = inode.extents[i];
                    let t = e.file_end().min(fb1);
                    let buf = self.assemble(&inode.extents, fb, t, off, data)?;
                    self.write_run(e.disk_blk + (fb - e.file_blk), &buf)?;
                    fb = t;
                }
                _ => {
                    // up to the next extent of this transaction (or the end)
                    let mut seg_end = fb1;
                    let mut j = extent::first_after(&inode.extents, fb);
                    while j < inode.extents.len() && inode.extents[j].file_blk < seg_end {
                        if inode.extents[j].gen == txn && inode.extents[j].file_blk > fb {
                            seg_end = inode.extents[j].file_blk;
                            break;
                        }
                        j += 1;
                    }
                    let buf = self.assemble(&inode.extents, fb, seg_end, off, data)?;
                    let mut runs: Vec<(u64, u64, u32)> = Vec::new();
                    let mut at = fb;
                    let mut failure = None;
                    while at < seg_end {
                        let want = (seg_end - at).min(MAX_RUN as u64) as u32;
                        match self.alloc(want) {
                            Ok((s, l)) => {
                                runs.push((at, s, l));
                                at += l as u64;
                            }
                            Err(e) => {
                                failure = Some(e);
                                break;
                            }
                        }
                    }
                    if failure.is_none() {
                        for (f, d, n) in &runs {
                            let o = ((f - fb) * BS) as usize;
                            if let Err(e) = self.write_run(*d, &buf[o..o + *n as usize * BLOCK_SIZE]) {
                                failure = Some(e);
                                break;
                            }
                        }
                    }
                    if let Some(e) = failure {
                        for (_, d, n) in &runs {
                            self.release(*d, *n, txn, true);
                        }
                        return Err(e);
                    }
                    self.punch(inode, fb, seg_end);
                    for (f, d, n) in runs {
                        extent::insert(&mut inode.extents, Extent { file_blk: f, disk_blk: d, nblocks: n, flags: 0, gen: txn });
                    }
                    inode.ext_dirty = true;
                    inode.dirty = true;
                    fb = seg_end;
                }
            }
        }
        Ok(())
    }

    /// Unmap file blocks `[start, end)` and release their volume blocks.
    pub fn punch(&mut self, inode: &mut Inode, start: u64, end: u64) {
        let mut freed = Vec::new();
        extent::punch(&mut inode.extents, start, end, &mut freed);
        if !freed.is_empty() {
            inode.ext_dirty = true;
            inode.dirty = true;
        }
        for f in freed {
            self.release(f.disk_blk, f.nblocks, f.gen, inode.versioned);
        }
    }

    /// Set the size, zeroing the tail of the last block and releasing the
    /// blocks past it when shrinking (bytes past the size inside a mapped
    /// block are always zero, so growing again exposes zeros, not old data).
    pub fn set_size(&mut self, inode: &mut Inode, size: u64) -> Result<(), Error> {
        if size > MAX_FILE_BYTES {
            return Err(Error::TooBig);
        }
        if size < inode.size {
            if size % BS != 0 && extent::containing(&inode.extents, size / BS).is_some() {
                let zeros = vec![0u8; (BS - size % BS) as usize];
                self.write_range(inode, size, &zeros)?;
            }
            self.punch(inode, size.div_ceil(BS), u64::MAX);
        }
        inode.size = size;
        inode.dirty = true;
        Ok(())
    }

    /// Undo what a failed write left past `size` (the size the file keeps):
    /// zero the tail of the block holding `size` and unmap the blocks after
    /// it, so a later grow exposes zeros. A block the failed write touched is
    /// one of the open transaction, so the zeroing is in place and allocates
    /// nothing; a committed block was never touched and already holds zeros
    /// there.
    pub fn discard_past(&mut self, inode: &mut Inode, size: u64) -> Result<(), Error> {
        if size % BS != 0 {
            if let Some(i) = extent::containing(&inode.extents, size / BS) {
                if inode.extents[i].gen == self.txn_gen() {
                    let zeros = vec![0u8; (BS - size % BS) as usize];
                    self.write_range(inode, size, &zeros)?;
                }
            }
        }
        self.punch(inode, size.div_ceil(BS), u64::MAX);
        Ok(())
    }

    /// Release everything an inode holds (data and tree nodes).
    pub fn drop_contents(&mut self, inode: &mut Inode) {
        self.punch(inode, 0, u64::MAX);
        for (b, g) in core::mem::take(&mut inode.nodes) {
            self.release(b, 1, g, inode.versioned);
        }
        inode.size = 0;
        inode.ext_dirty = true;
        inode.dirty = true;
    }
}
