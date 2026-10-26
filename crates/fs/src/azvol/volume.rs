// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A mounted azvol volume: format, mount, the file and directory operations,
//! and the commit protocol.
//!
//! **Transactions.** Everything between two commits is one transaction. The
//! operations change the in-memory state and write new (never committed)
//! blocks; `commit` makes the transaction durable in this order:
//!
//! 1. each changed inode's extent tree and record (the records are written
//!    into the inode table, itself a file, through the same copy-on-write
//!    path), then the inode table's own tree;
//! 2. the checksum-table blocks and the bitmap blocks changed so far (the
//!    bitmap still lists every block the OLD tree names: a superset);
//! 3. **flush**, then the superblock into the copy slot that does not hold
//!    the newest generation, then **flush**;
//! 4. only now are the blocks the old tree gave up freed in the bitmap
//!    (the ones a retained snapshot still names went to the dead list in 1
//!    instead, see [`super::snap`]), and the device is told they hold
//!    nothing ([`BlockDev::discard`], a hint whose answer changes nothing).
//!
//! The snapshot table and the dead list are written between 1 and 2, after
//! the last tree that can add to the dead list. [`super::group`] scopes a
//! transaction to a caller-chosen set of operations.
//!
//! A cut at any point leaves either the old superblock or the new one
//! valid, and every block either of them names intact. A cut between 3 and
//! 4 leaves blocks marked used that nothing names; the population count of
//! the stored bitmap then differs from the superblock's `used_blocks` and
//! the next mount rebuilds the map from the trees.
//!
//! A failed commit poisons the handle (the in-memory state no longer
//! matches any state the disk can show); remount to continue.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::engine::{Core, Inode};
use super::group::GroupSaved;
use super::seal::{self, VolumeKey};
use super::snap;
use super::dev::BlockDev;
use super::dir;
use super::freemap::FreeMap;
use super::layout::{
    Geometry, InodeDisk, Kind, Superblock, BLOCK_SIZE, BS, DEAD_OWNER, INODES_PER_BLOCK, INODE_SIZE, LABEL_LEN,
    MAX_FILE_BYTES, ROOT_INO, SB_SLOTS, SNAP_OWNER,
};
use super::Error;

/// Clean inodes kept cached; above this a public operation drops them.
const INODE_CACHE_MAX: usize = 1024;
/// Largest piece of one `write` handled at a time (keeps buffers bounded).
const WRITE_CHUNK: u64 = 1 << 20;
/// Directory blocks read per device call during a scan.
const DIR_BATCH: u64 = 16;

pub struct FormatOptions<'a> {
    /// Volume size in blocks; `None` = the whole device.
    pub block_count: Option<u64>,
    pub label: &'a [u8],
    pub uuid: [u8; 16],
    /// Creation time, also stamped on the root directory.
    pub time_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountReport {
    /// Generation mounted.
    pub generation: u64,
    /// Superblock copy that was newest (0 or 1).
    pub slot: u8,
    /// The other copy held a valid superblock too.
    pub other_valid: bool,
    /// The stored free-space map did not match the trees and was rebuilt.
    pub bitmap_rebuilt: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ino: u64,
    pub kind: Kind,
    pub size: u64,
    pub mode: u16,
    pub ctime_ns: u64,
    pub mtime_ns: u64,
    pub gen: u64,
    pub igen: u32,
    /// Volume blocks the file's data occupies.
    pub blocks: u64,
    /// Extents and tree-node blocks holding the extent list.
    pub extents: u64,
    pub tree_nodes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: u64,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatFs {
    pub block_size: u32,
    pub blocks_total: u64,
    /// Blocks allocated (including ones whose free waits for the commit).
    pub blocks_used: u64,
    pub blocks_pending_free: u64,
    /// Blocks the live tree no longer names but a snapshot does.
    pub blocks_retained: u64,
    pub snapshots: u64,
    pub inode_slots: u64,
}

pub struct Volume<D: BlockDev> {
    pub(super) core: Core<D>,
    pub(super) sb: Superblock,
    pub(super) itable: Inode,
    pub(super) inodes: BTreeMap<u64, Inode>,
    /// The snapshot-table and dead-list files ([`super::snap`]).
    pub(super) snaptab: Inode,
    pub(super) deadf: Inode,
    pub(super) group: Option<GroupSaved>,
    pub(super) poisoned: bool,
    /// Asked before a snapshot is dropped; `None`: every drop goes ahead.
    pub(super) delete_gate: Option<super::DeleteGate>,
    report: MountReport,
}

fn zero_blocks<D: BlockDev>(dev: &mut D, first: u64, n: u64) -> Result<(), Error> {
    let chunk = 128u64;
    let z = vec![0u8; (chunk as usize) * BLOCK_SIZE];
    let mut at = 0;
    while at < n {
        let c = (n - at).min(chunk);
        dev.write(first + at, &z[..c as usize * BLOCK_SIZE]).map_err(|_| Error::Io)?;
        at += c;
    }
    Ok(())
}

impl<D: BlockDev> Volume<D> {
    // ---- format / mount ---------------------------------------------------

    /// Lay out an empty volume on `dev` and return it mounted (the root
    /// directory committed as generation 2).
    pub fn format(dev: D, opts: &FormatOptions) -> Result<Volume<D>, Error> {
        Volume::format_inner(dev, opts, None)
    }

    /// Like [`Volume::format`], for a sealed volume: every block of the data
    /// area is ChaCha20-Poly1305 under a key derived from `key` and the
    /// volume's uuid ([`super::seal`]). `opts.uuid` must be fresh for every
    /// format. The volume holds fewer than 2^32 blocks.
    pub fn format_sealed(dev: D, opts: &FormatOptions, key: &VolumeKey) -> Result<Volume<D>, Error> {
        Volume::format_inner(dev, opts, Some(key))
    }

    fn format_inner(mut dev: D, opts: &FormatOptions, key: Option<&VolumeKey>) -> Result<Volume<D>, Error> {
        let n = opts.block_count.unwrap_or_else(|| dev.block_count());
        if n > dev.block_count() {
            return Err(Error::TooSmall);
        }
        let geo = Geometry::for_volume(n, key.is_some()).ok_or(Error::TooSmall)?;
        zero_blocks(&mut dev, 0, super::layout::RESERVED_BLOCKS)?;
        zero_blocks(&mut dev, geo.csum_start, geo.csum_blocks)?;
        let mut map = FreeMap::new(&geo);
        map.set_static(&geo);
        let mut buf = vec![0u8; BLOCK_SIZE];
        for i in 0..geo.bitmap_blocks {
            map.encode_block(i, &mut buf);
            dev.write(geo.bitmap_start + i, &buf).map_err(|_| Error::Io)?;
        }
        let mut label = [0u8; LABEL_LEN];
        let l = opts.label.len().min(LABEL_LEN);
        label[..l].copy_from_slice(&opts.label[..l]);
        let mut sbi = Inode::blank(0, Kind::Table);
        sbi.size = INODE_SIZE as u64;
        let sb = Superblock {
            generation: 1,
            geo,
            uuid: opts.uuid,
            label,
            free_head: 0,
            inode_slots: 1,
            used_blocks: geo.data_start,
            created_ns: opts.time_ns,
            key_alg: if key.is_some() { seal::ALG_CHACHA20_POLY1305 } else { 0 },
            key_id: key.map_or([0; 16], |k| k.key_id(&opts.uuid)),
            wrapped_key: [0; 40],
            itable: sbi.to_disk(),
            snaptab: InodeDisk::empty_aux(SNAP_OWNER),
            deadlist: InodeDisk::empty_aux(DEAD_OWNER),
        };
        sb.encode(&mut buf);
        for s in SB_SLOTS {
            dev.write(s, &buf).map_err(|_| Error::Io)?;
        }
        dev.flush().map_err(|_| Error::Io)?;
        let mut v = Volume::mount_inner(dev, false, key)?;
        v.core.time_ns = opts.time_ns;
        let mut root = Inode::blank(ROOT_INO, Kind::Dir);
        root.mode = 0o755;
        root.igen = 1;
        root.link = ROOT_INO;
        root.ctime_ns = opts.time_ns;
        root.mtime_ns = opts.time_ns;
        root.gen = v.core.txn_gen();
        v.sb.inode_slots = ROOT_INO + 1;
        v.inodes.insert(ROOT_INO, root);
        v.commit()?;
        Ok(v)
    }

    pub fn mount(dev: D) -> Result<Volume<D>, Error> {
        Volume::mount_inner(dev, true, None)
    }

    /// Mount a sealed volume. [`Error::WrongKey`] when `key` is not the one
    /// it was formatted with (nothing of the data is read), [`Error::Unsupported`]
    /// when the volume is not sealed. The mount commits a new generation
    /// before it returns, so the generation a sealed write is made in was
    /// never used by an earlier mount, whatever that mount's cut left on the
    /// medium (see [`super::seal`]).
    pub fn mount_sealed(dev: D, key: &VolumeKey) -> Result<Volume<D>, Error> {
        let mut v = Volume::mount_inner(dev, true, Some(key))?;
        v.open_generation()?;
        Ok(v)
    }

    /// Commit a superblock that names the same trees one generation later.
    fn open_generation(&mut self) -> Result<(), Error> {
        let txn = self.core.txn_gen();
        let mut next = self.sb;
        next.generation = txn;
        let mut buf = vec![0u8; BLOCK_SIZE];
        next.encode(&mut buf);
        self.core.dev.write(SB_SLOTS[(txn & 1) as usize], &buf).map_err(|_| Error::Io)?;
        self.core.dev.flush().map_err(|_| Error::Io)?;
        self.sb = next;
        self.core.gen = txn;
        Ok(())
    }

    fn mount_inner(mut dev: D, need_root: bool, key: Option<&VolumeKey>) -> Result<Volume<D>, Error> {
        let dev_blocks = dev.block_count();
        let mut found: [Option<Superblock>; 2] = [None, None];
        let mut magic_seen = false;
        let mut buf = vec![0u8; BLOCK_SIZE];
        for (i, slot) in SB_SLOTS.iter().enumerate() {
            if *slot >= dev_blocks || dev.read(*slot, &mut buf).is_err() {
                continue;
            }
            match Superblock::decode(&buf) {
                Ok(sb) if sb.geo.block_count <= dev_blocks => found[i] = Some(sb),
                Ok(_) => magic_seen = true,
                Err(Error::BadMagic) => {}
                Err(_) => magic_seen = true,
            }
        }
        let (slot, sb) = match (found[0], found[1]) {
            (Some(a), Some(b)) => {
                if b.generation >= a.generation { (1u8, b) } else { (0u8, a) }
            }
            (Some(a), None) => (0, a),
            (None, Some(b)) => (1, b),
            (None, None) => return Err(if magic_seen { Error::NoSuperblock } else { Error::BadMagic }),
        };
        let geo = sb.geo;
        let sealer = match (sb.key_alg, key) {
            (0, None) => None,
            (0, Some(_)) => return Err(Error::Unsupported("volume is not sealed")),
            (_, None) => return Err(Error::KeyRequired),
            (_, Some(k)) => {
                if !seal::ids_match(&sb.key_id, &k.key_id(&sb.uuid)) {
                    return Err(Error::WrongKey);
                }
                Some(k.sealer(&sb.uuid))
            }
        };
        let mut bitmap = FreeMap::new(&geo);
        let mut damaged = false;
        let mut i = 0;
        while i < geo.bitmap_blocks {
            let c = (geo.bitmap_blocks - i).min(64);
            let mut bb = vec![0u8; c as usize * BLOCK_SIZE];
            if dev.read(geo.bitmap_start + i, &mut bb).is_err() {
                damaged = true;
            } else {
                for k in 0..c {
                    if !bitmap.decode_block(i + k, &bb[k as usize * BLOCK_SIZE..(k as usize + 1) * BLOCK_SIZE]) {
                        damaged = true;
                    }
                }
            }
            i += c;
        }
        let static_ok = (0..geo.data_start).all(|b| bitmap.is_set(b));
        if damaged || !static_ok || !bitmap.padding_clean() || bitmap.count() != sb.used_blocks {
            damaged = true;
        }
        let used = if damaged { geo.data_start } else { sb.used_blocks };
        let mut itable = Inode::from_disk(0, &sb.itable);
        let mut core = Core::new(dev, geo, sb.generation, bitmap, used);
        core.seal = sealer;
        let (exts, nodes) = core.load_tree(&sb.itable, 0)?;
        itable.extents = exts;
        itable.nodes = nodes;
        let (snaptab, deadf) = snap::load_aux(&mut core, &sb)?;
        let mut v = Volume {
            core,
            sb,
            itable,
            inodes: BTreeMap::new(),
            snaptab,
            deadf,
            group: None,
            poisoned: false,
            delete_gate: None,
            report: MountReport { generation: sb.generation, slot, other_valid: found[1 - slot as usize].is_some(), bitmap_rebuilt: false },
        };
        if damaged {
            let map = v.collect_used()?.all;
            v.core.used = map.count();
            v.core.bitmap = map;
            v.core.bitmap.mark_all_dirty(&geo);
            v.report.bitmap_rebuilt = true;
        }
        if need_root {
            v.load(ROOT_INO)?;
            if v.inodes[&ROOT_INO].kind != Kind::Dir {
                return Err(Error::Corrupt("root is not a directory"));
            }
        }
        Ok(v)
    }

    pub fn report(&self) -> MountReport {
        self.report
    }

    pub fn generation(&self) -> u64 {
        self.core.gen
    }

    pub fn uuid(&self) -> [u8; 16] {
        self.sb.uuid
    }

    pub fn label(&self) -> &[u8] {
        let l = &self.sb.label;
        let n = l.iter().position(|&c| c == 0).unwrap_or(l.len());
        &l[..n]
    }

    pub fn device(&self) -> &D {
        &self.core.dev
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.core.dev
    }

    /// Give the device back WITHOUT committing; uncommitted changes are lost.
    pub fn into_device(self) -> D {
        self.core.dev
    }

    /// Wall-clock source for ctime/mtime: the caller supplies the time, the
    /// format layer has no clock.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.core.time_ns = ns;
    }

    pub fn statfs(&self) -> StatFs {
        StatFs {
            block_size: BLOCK_SIZE as u32,
            blocks_total: self.core.geo.block_count,
            blocks_used: self.core.used,
            blocks_pending_free: self.core.pending_total,
            blocks_retained: self.core.dead.iter().map(|e| e.nblocks as u64).sum(),
            snapshots: self.core.snaps.len() as u64,
            inode_slots: self.sb.inode_slots,
        }
    }

    // ---- inode cache -------------------------------------------------------

    pub(super) fn begin(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.inodes.len() > INODE_CACHE_MAX {
            self.inodes.retain(|_, i| i.dirty);
        }
        Ok(())
    }

    pub(super) fn read_slot(&mut self, ino: u64) -> Result<InodeDisk, Error> {
        let mut b = [0u8; INODE_SIZE];
        let n = self.core.file_read(&self.itable, ino * INODE_SIZE as u64, &mut b)?;
        if n != INODE_SIZE {
            return Err(Error::Corrupt("inode slot outside the table"));
        }
        let d = InodeDisk::decode(&b)?;
        if d.kind == Kind::Table || d.ino != ino {
            return Err(Error::Corrupt("inode record"));
        }
        Ok(d)
    }

    pub(super) fn load(&mut self, ino: u64) -> Result<(), Error> {
        if self.inodes.contains_key(&ino) {
            return Ok(());
        }
        if ino == 0 || ino >= self.sb.inode_slots {
            return Err(Error::NotFound);
        }
        let d = self.read_slot(ino)?;
        let mut inode = Inode::from_disk(ino, &d);
        if d.kind != Kind::Free {
            let (e, n) = self.core.load_tree(&d, ino)?;
            inode.extents = e;
            inode.nodes = n;
            let end = inode.extents.last().map_or(0, |e| e.file_end());
            if end.checked_mul(BS).map_or(true, |b| b > MAX_FILE_BYTES) {
                return Err(Error::Corrupt("file too large"));
            }
        }
        self.inodes.insert(ino, inode);
        Ok(())
    }

    /// Load an in-use inode of the given kind (`None` = any in-use kind).
    fn live(&mut self, ino: u64, want: Option<Kind>) -> Result<(), Error> {
        self.load(ino)?;
        let k = self.inodes[&ino].kind;
        if k == Kind::Free {
            return Err(Error::NotFound);
        }
        match want {
            Some(Kind::Dir) if k != Kind::Dir => Err(Error::NotDir),
            Some(Kind::File) if k != Kind::File => Err(Error::IsDir),
            _ => Ok(()),
        }
    }

    fn touch(core: &Core<D>, inode: &mut Inode) {
        inode.mtime_ns = core.time_ns;
        inode.gen = core.txn_gen();
        inode.dirty = true;
    }

    // ---- directories ---------------------------------------------------------

    /// Run `f(file_block, block)` over a directory's blocks until it
    /// returns `true`.
    pub(super) fn dir_scan<F: FnMut(u64, &[u8]) -> Result<bool, Error>>(&mut self, dir: u64, mut f: F) -> Result<(), Error> {
        let Volume { core, inodes, .. } = self;
        let d = inodes.get(&dir).ok_or(Error::NotFound)?;
        let nb = d.size / BS;
        let mut fb = 0;
        let mut buf = Vec::new();
        while fb < nb {
            let c = (nb - fb).min(DIR_BATCH);
            buf.resize(c as usize * BLOCK_SIZE, 0);
            core.read_range(&d.extents, fb * BS, &mut buf)?;
            for k in 0..c as usize {
                if f(fb + k as u64, &buf[k * BLOCK_SIZE..(k + 1) * BLOCK_SIZE])? {
                    return Ok(());
                }
            }
            fb += c;
        }
        Ok(())
    }

    fn dir_find(&mut self, dir: u64, name: &[u8]) -> Result<Option<(u64, dir::Rec, Vec<u8>)>, Error> {
        let mut hit = None;
        self.dir_scan(dir, |fb, blk| {
            if let Some(r) = dir::find(blk, name)? {
                hit = Some((fb, r, blk.to_vec()));
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(hit)
    }

    fn dir_write_block(&mut self, dir: u64, fb: u64, blk: &[u8]) -> Result<(), Error> {
        let Volume { core, inodes, .. } = self;
        let d = inodes.get_mut(&dir).ok_or(Error::NotFound)?;
        core.write_range(d, fb * BS, blk)?;
        if (fb + 1) * BS > d.size {
            d.size = (fb + 1) * BS;
        }
        Self::touch(core, d);
        Ok(())
    }

    fn dir_add(&mut self, dir: u64, name: &[u8], ino: u64, kind: u8) -> Result<(), Error> {
        let mut slot: Option<(u64, Vec<u8>)> = None;
        self.dir_scan(dir, |fb, blk| {
            let mut copy = blk.to_vec();
            if dir::insert(&mut copy, name, ino, kind)? {
                slot = Some((fb, copy));
                return Ok(true);
            }
            Ok(false)
        })?;
        let (fb, blk) = match slot {
            Some(s) => s,
            None => {
                let mut blk = vec![0u8; BLOCK_SIZE];
                dir::insert(&mut blk, name, ino, kind)?;
                (self.inodes[&dir].size / BS, blk)
            }
        };
        self.dir_write_block(dir, fb, &blk)
    }

    fn dir_is_empty(&mut self, dir: u64) -> Result<bool, Error> {
        let mut empty = true;
        self.dir_scan(dir, |_, blk| {
            if dir::has_entries(blk)? {
                empty = false;
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(empty)
    }

    // ---- public operations ------------------------------------------------------

    pub fn root(&self) -> u64 {
        ROOT_INO
    }

    pub fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<DirEntry, Error> {
        self.begin()?;
        self.live(dir, Some(Kind::Dir))?;
        match self.dir_find(dir, name)? {
            Some((_, r, _)) => Ok(DirEntry {
                name: name.to_vec(),
                ino: r.ino,
                kind: Kind::from_u8(r.kind).ok_or(Error::Corrupt("directory entry kind"))?,
            }),
            None => Err(Error::NotFound),
        }
    }

    /// Resolve a `/`-separated path from the root (empty components skipped).
    pub fn lookup_path(&mut self, path: &[u8]) -> Result<u64, Error> {
        let mut cur = ROOT_INO;
        for comp in path.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
            cur = self.lookup(cur, comp)?.ino;
        }
        Ok(cur)
    }

    pub fn readdir(&mut self, dir: u64) -> Result<Vec<DirEntry>, Error> {
        self.begin()?;
        self.live(dir, Some(Kind::Dir))?;
        let mut raw = Vec::new();
        self.dir_scan(dir, |_, blk| {
            dir::list(blk, &mut raw)?;
            Ok(false)
        })?;
        raw.into_iter()
            .map(|(name, ino, k)| {
                Ok(DirEntry { name, ino, kind: Kind::from_u8(k).ok_or(Error::Corrupt("directory entry kind"))? })
            })
            .collect()
    }

    pub fn stat(&mut self, ino: u64) -> Result<Stat, Error> {
        self.begin()?;
        self.live(ino, None)?;
        let i = &self.inodes[&ino];
        Ok(Stat {
            ino,
            kind: i.kind,
            size: i.size,
            mode: i.mode,
            ctime_ns: i.ctime_ns,
            mtime_ns: i.mtime_ns,
            gen: i.gen,
            igen: i.igen,
            blocks: i.extents.iter().map(|e| e.nblocks as u64).sum(),
            extents: i.extents.len() as u64,
            tree_nodes: i.nodes.len() as u64,
        })
    }

    /// Create a file or directory `name` in `dir`.
    pub fn create(&mut self, dir: u64, name: &[u8], kind: Kind, mode: u16) -> Result<u64, Error> {
        self.begin()?;
        if !matches!(kind, Kind::File | Kind::Dir) {
            return Err(Error::NameInvalid);
        }
        if !dir::name_ok(name) {
            return Err(Error::NameInvalid);
        }
        self.live(dir, Some(Kind::Dir))?;
        if self.dir_find(dir, name)?.is_some() {
            return Err(Error::Exists);
        }
        // Which slot would the new inode take (free list first)?
        let (ino, next_free, igen, from_free) = if self.sb.free_head != 0 {
            let f = self.sb.free_head;
            self.load(f)?;
            let fi = &self.inodes[&f];
            if fi.kind != Kind::Free || fi.link >= self.sb.inode_slots {
                return Err(Error::Corrupt("free inode list"));
            }
            (f, fi.link, fi.igen.wrapping_add(1), true)
        } else {
            (self.sb.inode_slots, 0, 1, false)
        };
        self.dir_add(dir, name, ino, kind as u8)?;
        if from_free {
            self.sb.free_head = next_free;
        } else {
            self.sb.inode_slots += 1;
        }
        let mut inode = Inode::blank(ino, kind);
        inode.mode = mode;
        inode.igen = igen;
        inode.ctime_ns = self.core.time_ns;
        inode.mtime_ns = self.core.time_ns;
        inode.gen = self.core.txn_gen();
        inode.link = if kind == Kind::Dir { dir } else { 0 };
        self.inodes.insert(ino, inode);
        Ok(ino)
    }

    /// Remove `name` from `dir`; a directory must be empty.
    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), Error> {
        self.begin()?;
        self.live(dir, Some(Kind::Dir))?;
        let (fb, rec, mut blk) = self.dir_find(dir, name)?.ok_or(Error::NotFound)?;
        let child = rec.ino;
        self.live(child, None)?;
        if self.inodes[&child].kind == Kind::Dir && !self.dir_is_empty(child)? {
            return Err(Error::NotEmpty);
        }
        self.core.privileged = true;
        let r = (|| {
            dir::remove(&mut blk, &rec);
            self.dir_write_block(dir, fb, &blk)?;
            let Volume { core, inodes, sb, .. } = self;
            let c = inodes.get_mut(&child).ok_or(Error::NotFound)?;
            core.drop_contents(c);
            c.kind = Kind::Free;
            c.mode = 0;
            c.link = sb.free_head;
            c.gen = core.txn_gen();
            sb.free_head = child;
            Ok(())
        })();
        self.core.privileged = false;
        r
    }

    pub fn read(&mut self, ino: u64, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        self.begin()?;
        self.live(ino, Some(Kind::File))?;
        let Volume { core, inodes, .. } = self;
        core.file_read(&inodes[&ino], off, buf)
    }

    /// Write at `off`, extending the file (a gap reads as zeros).
    pub fn write(&mut self, ino: u64, off: u64, data: &[u8]) -> Result<usize, Error> {
        self.begin()?;
        self.live(ino, Some(Kind::File))?;
        off.checked_add(data.len() as u64).filter(|e| *e <= MAX_FILE_BYTES).ok_or(Error::TooBig)?;
        let Volume { core, inodes, .. } = self;
        let f = inodes.get_mut(&ino).ok_or(Error::NotFound)?;
        let mut done = 0usize;
        while done < data.len() {
            let at = off + done as u64;
            let take = (data.len() - done).min((WRITE_CHUNK - at % WRITE_CHUNK) as usize);
            if let Err(e) = core.write_range(f, at, &data[done..done + take]) {
                // a failed chunk may have mapped blocks past the size the
                // file keeps: unmap them and zero the tail (the bytes below
                // that size that were written stay written)
                let keep = f.size.max(off + done as u64);
                if core.discard_past(f, keep).is_err() {
                    // the file's tail can no longer be vouched for
                    self.poisoned = true;
                    return Err(Error::Io);
                }
                if done == 0 {
                    return Err(e);
                }
                f.size = keep;
                Self::touch(core, f);
                return Ok(done);
            }
            done += take;
        }
        f.size = f.size.max(off + data.len() as u64);
        Self::touch(core, f);
        Ok(done)
    }

    pub fn truncate(&mut self, ino: u64, size: u64) -> Result<(), Error> {
        self.begin()?;
        self.live(ino, Some(Kind::File))?;
        self.core.privileged = true;
        let Volume { core, inodes, .. } = self;
        let f = inodes.get_mut(&ino).ok_or(Error::NotFound)?;
        let r = core.set_size(f, size);
        core.privileged = false;
        if r.is_ok() {
            Self::touch(core, f);
        }
        r
    }

    /// The volume block runs `(first block, blocks)` under the first `len`
    /// bytes of file `ino`, in file order, runs that follow each other joined.
    /// For the swap file, whose blocks the caller writes directly: the file
    /// must be fully allocated (a hole is `Unsupported`), longer than `len`,
    /// and never written through the engine again, which would move its
    /// blocks (copy on write). The checksum table and a sealed volume's tags
    /// do not know about the direct writes, so the file must also be empty
    /// when the swap area starts (the swap layer truncates it first). More
    /// than `out.len()` runs is `NoSpace`.
    pub fn file_runs(&mut self, ino: u64, len: u64, out: &mut [(u64, u64)]) -> Result<usize, Error> {
        self.begin()?;
        self.live(ino, Some(Kind::File))?;
        let f = &self.inodes[&ino];
        let want = len.div_ceil(BS);
        if len > f.size {
            return Err(Error::TooBig);
        }
        let (mut n, mut at) = (0usize, 0u64);
        for e in &f.extents {
            if at >= want {
                break;
            }
            if e.file_blk != at {
                return Err(Error::Unsupported("swap file with a hole"));
            }
            let take = (e.nblocks as u64).min(want - at);
            match n.checked_sub(1).map(|i| out[i]) {
                Some((b, c)) if b + c == e.disk_blk => out[n - 1].1 += take,
                _ => {
                    if n == out.len() {
                        return Err(Error::NoSpace);
                    }
                    out[n] = (e.disk_blk, take);
                    n += 1;
                }
            }
            at += take;
        }
        if at < want {
            return Err(Error::Unsupported("swap file with a hole"));
        }
        Ok(n)
    }

    // ---- commit ---------------------------------------------------------------------

    fn is_dirty(&self) -> bool {
        self.itable.dirty
            || self.inodes.values().any(|i| i.dirty)
            || self.core.snaps_from != usize::MAX
            || self.core.dead_from != usize::MAX
    }

    /// Make the open transaction durable (see the module doc for the order).
    /// Refused while a change group is open: `commit_group` ends it.
    pub fn commit(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.group.is_some() {
            return Err(Error::GroupOpen);
        }
        if !self.is_dirty() {
            return Ok(());
        }
        self.core.privileged = true;
        let r = self.commit_inner();
        self.core.privileged = false;
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    fn commit_inner(&mut self) -> Result<(), Error> {
        let Volume { core, sb, itable, inodes, .. } = self;
        let txn = core.txn_gen();
        // 1. trees and records of the changed inodes
        let mut recs: Vec<(u64, [u8; INODE_SIZE])> = Vec::new();
        for (ino, inode) in inodes.iter_mut() {
            if !inode.dirty {
                continue;
            }
            if inode.ext_dirty {
                core.store_tree(inode)?;
            }
            let mut b = [0u8; INODE_SIZE];
            inode.to_disk().encode(&mut b);
            recs.push((*ino, b));
        }
        let mut i = 0;
        while i < recs.len() {
            let fb = recs[i].0 / INODES_PER_BLOCK;
            let mut blk = vec![0u8; BLOCK_SIZE];
            core.read_range(&itable.extents, fb * BS, &mut blk)?;
            while i < recs.len() && recs[i].0 / INODES_PER_BLOCK == fb {
                let o = (recs[i].0 % INODES_PER_BLOCK) as usize * INODE_SIZE;
                blk[o..o + INODE_SIZE].copy_from_slice(&recs[i].1);
                i += 1;
            }
            core.write_range(itable, fb * BS, &blk)?;
        }
        itable.size = sb.inode_slots * INODE_SIZE as u64;
        itable.gen = txn;
        if itable.ext_dirty {
            core.store_tree(itable)?;
        }
        // 1b. the snapshot table and the dead list: every release that can
        // add to the list has happened (these two files are not versioned)
        self.store_aux()?;
        let Volume { core, sb, itable, inodes, snaptab, deadf, .. } = self;
        // 2. checksum table and bitmap (still a superset of the old tree)
        core.flush_csums()?;
        core.flush_bitmap()?;
        core.dev.flush().map_err(|_| Error::Io)?;
        // 3. the superblock, into the copy that is not the newest
        let mut new_sb = *sb;
        new_sb.generation = txn;
        new_sb.used_blocks = core.used - core.pending_total;
        new_sb.itable = itable.to_disk();
        new_sb.snaptab = snaptab.to_disk();
        new_sb.deadlist = deadf.to_disk();
        let mut buf = vec![0u8; BLOCK_SIZE];
        new_sb.encode(&mut buf);
        core.dev.write(SB_SLOTS[(txn & 1) as usize], &buf).map_err(|_| Error::Io)?;
        core.dev.flush().map_err(|_| Error::Io)?;
        // 4. durable: the old tree's blocks may be reused, and the device may
        // deallocate them (nothing is allocated before this returns)
        *sb = new_sb;
        core.gen = txn;
        let freed = core.apply_pending();
        if !freed.is_empty() {
            let _ = core.dev.discard(&freed);
        }
        core.flush_bitmap()?;
        for inode in inodes.values_mut() {
            inode.dirty = false;
            inode.ext_dirty = false;
        }
        itable.dirty = false;
        self.aux_committed();
        Ok(())
    }
}
