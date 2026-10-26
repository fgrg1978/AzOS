// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Snapshots: retained generations of the volume.
//!
//! A commit already leaves the previous tree intact until the new
//! superblock is durable; a snapshot is that old tree kept past the commit
//! that would have let it go. The snapshot table (a file, record in the
//! superblock) holds one 512-byte record per retained generation `s`: the
//! inode table's record as of `s`, the slot count, the time and a label.
//! Nothing else is copied: the tree of `s` is the tree the volume had at `s`.
//!
//! **Which blocks a snapshot keeps.** Every extent and tree node carries
//! the generation `born` that wrote it, and it stays in the live tree from
//! `born` until a commit `died` drops it. The tree of a retained generation
//! `s` names the block exactly when `born <= s < died`. So the number of
//! snapshot references to a block is the number of retained generations in
//! `[born, died)`, a pure function of the table: nothing is counted per
//! block on the disk. When the live tree drops a committed run, the engine
//! asks [`held`]; if some snapshot still names the run it goes to the **dead
//! list** (a file of `{run, born, died}`, record in the superblock) instead
//! of the free list. Deleting snapshot `s` removes its record and frees
//! every dead run that no remaining snapshot names, by the same commit
//! protocol as any other free (after the superblock without `s` is
//! durable).
//!
//! Both files are written inside the commit that changes them, so a power
//! cut shows the old superblock (old table, old dead list) or the new one.
//! They are not themselves versioned: no snapshot holds them, and their old
//! blocks are freed like any other. A volume with neither file is
//! byte-identical to one that never heard of snapshots (the records are
//! zeros and the incompat bit is clear).
//!
//! **Reading a snapshot.** [`SnapView`] is the snapshot's inode table and
//! inode cache, swapped into the volume for the duration of one read
//! operation; it offers the read half of the volume API and nothing that
//! writes. A view of a deleted snapshot fails with `NoSnapshot`.
//!
//! Limits of this revision: the table and the dead list are held whole in
//! memory, and rewriting a record rewrites its file from the first changed
//! entry on; `check` and the bitmap rebuild walk every retained tree.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::dev::BlockDev;
use super::engine::{Core, Inode};
use super::layout::{
    rd32, rd64, wr32, wr64, InodeDisk, Kind, Superblock, BLOCK_SIZE, DEAD_OWNER, INODE_SIZE, LABEL_LEN, SNAP_OWNER,
};
use super::volume::{DirEntry, Stat, Volume};
use super::Error;

pub const SNAP_REC_SIZE: usize = 512;
pub const DEAD_REC_SIZE: usize = 32;
/// Offset of the inode-table record inside a snapshot record.
const SNAP_ITABLE: usize = 256;

/// One retained generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapRec {
    /// The generation retained; also the snapshot's id.
    pub gen: u64,
    pub created_ns: u64,
    pub inode_slots: u64,
    pub label: [u8; LABEL_LEN],
    /// The inode table's record as of `gen`.
    pub itable: InodeDisk,
}

impl SnapRec {
    /// ```text
    ///   0 gen u64   8 created_ns u64   16 inode_slots u64   24 reserved (0)
    ///  32 label[32]   64 reserved (0)   256 itable: 256-byte inode record
    /// ```
    pub fn encode(&self, out: &mut [u8]) {
        for x in out[..SNAP_REC_SIZE].iter_mut() {
            *x = 0;
        }
        wr64(out, 0, self.gen);
        wr64(out, 8, self.created_ns);
        wr64(out, 16, self.inode_slots);
        out[32..32 + LABEL_LEN].copy_from_slice(&self.label);
        self.itable.encode(&mut out[SNAP_ITABLE..SNAP_ITABLE + INODE_SIZE]);
    }

    pub fn decode(b: &[u8]) -> Result<SnapRec, Error> {
        let reserved_zero = b[24..32].iter().all(|&x| x == 0) && b[64..SNAP_ITABLE].iter().all(|&x| x == 0);
        if !reserved_zero {
            return Err(Error::Unsupported("snapshot record"));
        }
        let gen = rd64(b, 0);
        let inode_slots = rd64(b, 16);
        let itable = InodeDisk::decode(&b[SNAP_ITABLE..SNAP_ITABLE + INODE_SIZE])?;
        if gen == 0
            || inode_slots < 2
            || inode_slots > (1 << 40)
            || itable.kind != Kind::Table
            || itable.ino != 0
            || itable.size != inode_slots * INODE_SIZE as u64
        {
            return Err(Error::Corrupt("snapshot record"));
        }
        let mut label = [0u8; LABEL_LEN];
        label.copy_from_slice(&b[32..32 + LABEL_LEN]);
        Ok(SnapRec { gen, created_ns: rd64(b, 8), inode_slots, label, itable })
    }
}

/// A run the live tree gave up while a snapshot still names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadEnt {
    pub disk_blk: u64,
    pub nblocks: u32,
    /// Generation that wrote the run.
    pub born: u64,
    /// Generation of the commit that dropped it from the live tree.
    pub died: u64,
}

impl DeadEnt {
    /// `0 disk_blk u64   8 nblocks u32   12 flags u32 (0)   16 born u64   24 died u64`
    pub fn encode(&self, out: &mut [u8]) {
        wr64(out, 0, self.disk_blk);
        wr32(out, 8, self.nblocks);
        wr32(out, 12, 0);
        wr64(out, 16, self.born);
        wr64(out, 24, self.died);
    }

    pub fn decode(b: &[u8]) -> DeadEnt {
        DeadEnt { disk_blk: rd64(b, 0), nblocks: rd32(b, 8), born: rd64(b, 16), died: rd64(b, 24) }
    }

    /// `next` is the run right after this one on disk, dropped by the same
    /// commit, written by the same one.
    pub fn continues_with(&self, next: &DeadEnt) -> bool {
        self.born == next.born
            && self.died == next.died
            && self.disk_blk + self.nblocks as u64 == next.disk_blk
            && (self.nblocks as u64 + next.nblocks as u64) <= u32::MAX as u64
    }
}

/// Number of retained generations `s` with `born <= s < died`: how many
/// snapshots name a run the live tree held over `[born, died)`.
pub fn refs(snaps: &[SnapRec], born: u64, died: u64) -> usize {
    let lo = snaps.partition_point(|r| r.gen < born);
    let hi = snaps.partition_point(|r| r.gen < died);
    hi.saturating_sub(lo)
}

/// Does any retained generation name a run held over `[born, died)`?
pub fn held(snaps: &[SnapRec], born: u64, died: u64) -> bool {
    refs(snaps, born, died) > 0
}

/// Read a whole auxiliary file into a byte vector.
fn read_file<D: BlockDev>(core: &mut Core<D>, f: &Inode) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; f.size as usize];
    let mut done = 0;
    while done < buf.len() {
        let n = core.file_read(f, done as u64, &mut buf[done..])?;
        if n == 0 {
            return Err(Error::Corrupt("auxiliary file shorter than its size"));
        }
        done += n;
    }
    Ok(buf)
}

/// Load the snapshot table and the dead list named by the superblock into
/// the engine and return their files. Validates the table (ascending
/// generations, none newer than the volume) and the list (inside the data
/// area, a lifetime that some retained generation falls into).
pub(super) fn load_aux<D: BlockDev>(core: &mut Core<D>, sb: &Superblock) -> Result<(Inode, Inode), Error> {
    let mut tab = Inode::from_disk(SNAP_OWNER, &sb.snaptab);
    let mut dead = Inode::from_disk(DEAD_OWNER, &sb.deadlist);
    tab.versioned = false;
    dead.versioned = false;
    if !sb.snaptab.is_empty_aux() {
        let (e, n) = core.load_tree(&sb.snaptab, SNAP_OWNER)?;
        tab.extents = e;
        tab.nodes = n;
        let raw = read_file(core, &tab)?;
        if raw.len() % SNAP_REC_SIZE != 0 {
            return Err(Error::Corrupt("snapshot table size"));
        }
        let mut prev = 0;
        for c in raw.chunks(SNAP_REC_SIZE) {
            let r = SnapRec::decode(c)?;
            if r.gen <= prev || r.gen > sb.generation {
                return Err(Error::Corrupt("snapshot generations"));
            }
            prev = r.gen;
            core.snaps.push(r);
        }
    }
    if !sb.deadlist.is_empty_aux() {
        let (e, n) = core.load_tree(&sb.deadlist, DEAD_OWNER)?;
        dead.extents = e;
        dead.nodes = n;
        let raw = read_file(core, &dead)?;
        if raw.len() % DEAD_REC_SIZE != 0 {
            return Err(Error::Corrupt("dead list size"));
        }
        for c in raw.chunks(DEAD_REC_SIZE) {
            let e = DeadEnt::decode(c);
            let end = e.disk_blk.checked_add(e.nblocks as u64).ok_or(Error::Corrupt("dead run"))?;
            if rd32(c, 12) != 0
                || e.nblocks == 0
                || e.disk_blk < core.geo.data_start
                || end > core.geo.block_count
                || e.born == 0
                || e.born >= e.died
                || e.died > sb.generation
            {
                return Err(Error::Corrupt("dead run"));
            }
            if !held(&core.snaps, e.born, e.died) {
                return Err(Error::Corrupt("dead run no snapshot names"));
            }
            core.dead.push(e);
        }
    }
    core.dead_base = core.dead.len();
    Ok((tab, dead))
}

/// Rewrite `f` from byte `from` on with `bytes` and set its size to `total`
/// (shrinking releases what is past it). The file is not versioned, so this
/// adds nothing to the dead list.
fn rewrite_tail<D: BlockDev>(core: &mut Core<D>, f: &mut Inode, from: u64, bytes: &[u8], total: u64) -> Result<(), Error> {
    core.write_range(f, from, bytes)?;
    core.set_size(f, total)?;
    f.gen = core.txn_gen();
    if f.ext_dirty {
        core.store_tree(f)?;
    }
    Ok(())
}

impl<D: BlockDev> Volume<D> {
    /// Write the snapshot table and the dead list if they changed. Called by
    /// the commit after every tree that can add to the dead list is stored.
    pub(super) fn store_aux(&mut self) -> Result<(), Error> {
        let Volume { core, snaptab, deadf, .. } = self;
        if core.snaps_from != usize::MAX {
            let from = core.snaps_from.min(core.snaps.len());
            let mut bytes = vec![0u8; (core.snaps.len() - from) * SNAP_REC_SIZE];
            for (i, r) in core.snaps[from..].iter().enumerate() {
                r.encode(&mut bytes[i * SNAP_REC_SIZE..(i + 1) * SNAP_REC_SIZE]);
            }
            let total = (core.snaps.len() * SNAP_REC_SIZE) as u64;
            rewrite_tail(core, snaptab, (from * SNAP_REC_SIZE) as u64, &bytes, total)?;
        }
        if core.dead_from != usize::MAX {
            let from = core.dead_from.min(core.dead.len());
            let mut bytes = vec![0u8; (core.dead.len() - from) * DEAD_REC_SIZE];
            for (i, e) in core.dead[from..].iter().enumerate() {
                e.encode(&mut bytes[i * DEAD_REC_SIZE..(i + 1) * DEAD_REC_SIZE]);
            }
            let total = (core.dead.len() * DEAD_REC_SIZE) as u64;
            rewrite_tail(core, deadf, (from * DEAD_REC_SIZE) as u64, &bytes, total)?;
        }
        Ok(())
    }

    /// The commit went through: the table and the list are what the disk has.
    pub(super) fn aux_committed(&mut self) {
        self.core.snaps_from = usize::MAX;
        self.core.dead_from = usize::MAX;
        self.core.dead_base = self.core.dead.len();
        self.snaptab.dirty = false;
        self.snaptab.ext_dirty = false;
        self.deadf.dirty = false;
        self.deadf.ext_dirty = false;
    }

    /// The retained generations, oldest first.
    pub fn snapshots(&self) -> Vec<SnapInfo> {
        self.core
            .snaps
            .iter()
            .map(|r| {
                let n = r.label.iter().position(|&c| c == 0).unwrap_or(LABEL_LEN);
                SnapInfo { id: r.gen, created_ns: r.created_ns, label: r.label[..n].to_vec(), inode_slots: r.inode_slots }
            })
            .collect()
    }

    /// Retain the current state. The open transaction is committed first (the
    /// snapshot is of what has been written, durable), then the record is
    /// added by a second commit. Returns the snapshot's id, the generation
    /// it retains. Refused while a change group is open.
    pub fn snapshot_create(&mut self, label: &[u8]) -> Result<u64, Error> {
        self.begin()?;
        if self.in_group() {
            return Err(Error::GroupOpen);
        }
        self.commit()?;
        let id = self.core.gen;
        if self.core.snaps.last().is_some_and(|r| r.gen >= id) {
            return Err(Error::Exists);
        }
        let mut l = [0u8; LABEL_LEN];
        let n = label.len().min(LABEL_LEN);
        l[..n].copy_from_slice(&label[..n]);
        let at = self.core.snaps.len();
        self.core.snaps.push(SnapRec {
            gen: id,
            created_ns: self.core.time_ns,
            inode_slots: self.sb.inode_slots,
            label: l,
            itable: self.sb.itable,
        });
        self.core.snaps_from = self.core.snaps_from.min(at);
        self.commit()?;
        Ok(id)
    }

    /// Hand the volume the gate it asks before it drops a snapshot (the
    /// mount installs `azos_fs::delete_admitted`). Without one every drop goes
    /// ahead.
    pub fn set_delete_gate(&mut self, gate: super::DeleteGate) {
        self.delete_gate = Some(gate);
    }

    /// Drop a snapshot. Every dead run that no remaining snapshot names is
    /// freed once the superblock without this snapshot is durable.
    ///
    /// The delete gate (`storage_delete`, op `SnapshotDrop`) is asked first,
    /// before the open transaction is touched; `Error::Denied` changes nothing.
    pub fn snapshot_delete(&mut self, id: u64) -> Result<(), Error> {
        #[cfg(not(feature = "envelope-delete-canary"))]
        if let Some(gate) = self.delete_gate {
            let uuid = &self.sb.uuid;
            let volume = u64::from_le_bytes([uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7]]);
            if !gate(azos_common::envelope::DeleteOp::SnapshotDrop, volume) {
                return Err(Error::Denied);
            }
        }
        self.begin()?;
        if self.in_group() {
            return Err(Error::GroupOpen);
        }
        self.commit()?;
        let at = self.core.snaps.binary_search_by_key(&id, |r| r.gen).map_err(|_| Error::NoSnapshot)?;
        let core = &mut self.core;
        core.snaps.remove(at);
        core.snaps_from = core.snaps_from.min(at);
        let mut first = usize::MAX;
        let mut kept = Vec::with_capacity(core.dead.len());
        for (i, e) in core.dead.iter().enumerate() {
            if held(&core.snaps, e.born, e.died) {
                kept.push(*e);
            } else {
                first = first.min(i);
                core.pending.push((e.disk_blk, e.nblocks));
                core.pending_total += e.nblocks as u64;
            }
        }
        if first != usize::MAX {
            core.dead = kept;
            core.dead_from = core.dead_from.min(first);
        }
        self.commit()
    }

    /// Open a read-only view of snapshot `id`.
    pub fn snapshot_open(&mut self, id: u64) -> Result<SnapView, Error> {
        self.begin()?;
        let rec = *self.core.snaps.iter().find(|r| r.gen == id).ok_or(Error::NoSnapshot)?;
        let mut itable = Inode::from_disk(0, &rec.itable);
        let (e, n) = self.core.load_tree(&rec.itable, 0)?;
        itable.extents = e;
        itable.nodes = n;
        Ok(SnapView { id, itable, slots: rec.inode_slots, inodes: BTreeMap::new() })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapInfo {
    pub id: u64,
    pub created_ns: u64,
    pub label: Vec<u8>,
    pub inode_slots: u64,
}

/// A snapshot opened for reading. It holds the snapshot's inode table and
/// the inodes read so far; each call lends them to the volume for that one
/// operation, so the volume stays usable (and writable) between calls. The
/// view's content never changes: the blocks it names are retained.
pub struct SnapView {
    id: u64,
    itable: Inode,
    slots: u64,
    inodes: BTreeMap<u64, Inode>,
}

impl SnapView {
    pub fn id(&self) -> u64 {
        self.id
    }

    fn run<D: BlockDev, R>(
        &mut self,
        v: &mut Volume<D>,
        f: impl FnOnce(&mut Volume<D>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if v.core.snaps.binary_search_by_key(&self.id, |r| r.gen).is_err() {
            return Err(Error::NoSnapshot);
        }
        core::mem::swap(&mut v.itable, &mut self.itable);
        core::mem::swap(&mut v.inodes, &mut self.inodes);
        core::mem::swap(&mut v.sb.inode_slots, &mut self.slots);
        let r = f(v);
        core::mem::swap(&mut v.itable, &mut self.itable);
        core::mem::swap(&mut v.inodes, &mut self.inodes);
        core::mem::swap(&mut v.sb.inode_slots, &mut self.slots);
        r
    }

    pub fn lookup<D: BlockDev>(&mut self, v: &mut Volume<D>, dir: u64, name: &[u8]) -> Result<DirEntry, Error> {
        self.run(v, |v| v.lookup(dir, name))
    }

    pub fn lookup_path<D: BlockDev>(&mut self, v: &mut Volume<D>, path: &[u8]) -> Result<u64, Error> {
        self.run(v, |v| v.lookup_path(path))
    }

    pub fn readdir<D: BlockDev>(&mut self, v: &mut Volume<D>, dir: u64) -> Result<Vec<DirEntry>, Error> {
        self.run(v, |v| v.readdir(dir))
    }

    pub fn stat<D: BlockDev>(&mut self, v: &mut Volume<D>, ino: u64) -> Result<Stat, Error> {
        self.run(v, |v| v.stat(ino))
    }

    pub fn read<D: BlockDev>(&mut self, v: &mut Volume<D>, ino: u64, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        self.run(v, |v| v.read(ino, off, buf))
    }
}

const _: () = assert!(SNAP_REC_SIZE <= BLOCK_SIZE && BLOCK_SIZE % SNAP_REC_SIZE == 0);
