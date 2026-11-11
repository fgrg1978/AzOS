// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The file protocol (`azos_devif::fs`) over a read-only ext4 volume.
//!
//! The kernel's capability on the endpoint, which carries [`DIR_BADGE`], is
//! the volume's root [`Dir`]; no other caller is answered as a directory. An
//! open file is a [`Node`]: a capability on the same endpoint derived with a
//! badge of its own ([`Host::derive`]) and lent to the opener. The badge is
//! the slot in its low bits and an open sequence above, which starts at the
//! server's incarnation ([`Host::incarnation`]): a badge an earlier server or
//! an earlier open of the slot lent reaches nothing. Names and data
//! are in the region the server shares with its client: an [`Extent`] is an
//! offset and a length in it, checked before it is touched.
//!
//! Every change of the tree is refused [`READ_ONLY`]: this is the read-only
//! stage of the format. Symlinks are followed beneath the volume's root, so a
//! client sees the file a link names, as on a file system without links; an
//! open or a stat that names a `floor` is rooted at the directory its first
//! components make, and a link that leads out of it, or that is one of those
//! components, is refused `DENIED`.
//!
//! The slots are few ([`NODES`]); an open past them takes the slot used
//! longest ago and revokes what was lent from it, so a client that kept a
//! capability it no longer uses finds it stale and opens again. A slot whose
//! revoke failed keeps serving its badge and is never used again: its copy
//! may still be out there.

use azos_abi::syscall_nr::{
    READDIR_NAME_BYTES, STATFS_BYTES, STATFS_OFF_BFREE, STATFS_OFF_BLOCKS, STATFS_OFF_BSIZE, STATFS_OFF_FFREE,
    STATFS_OFF_FILES, STATFS_OFF_TYPE, STAT_BYTES, STAT_OFF_ATIME, STAT_OFF_CTIME, STAT_OFF_GID, STAT_OFF_MODE,
    STAT_OFF_MTIME, STAT_OFF_NLINK, STAT_OFF_SIZE, STAT_OFF_UID,
};
use azos_devif::fs::{
    Dir, Entry, Extent, Node, OpenNode, ReadDone, DIR_BADGE, IS_DIR, NAME_TOO_LONG, NOT_DIR, NOT_FOUND, READ_MAX,
    READ_ONLY,
};
use azos_devif::{outcome, Out};
use azos_ext4::{BlockSource, DirEntry, Error, Inode, Volume, PATH_MAX};
use azos_idl::Lent;

/// Open files served at once.
pub const NODES: usize = 32;
/// The badge bits that name the slot (`NODES` slots).
const SLOT_BITS: u32 = 5;
const _: () = assert!(NODES == 1 << SLOT_BITS);
/// The `statfs` type of an ext4 volume (`azos_abi::syscall_nr::STATFS_BYTES`).
/// Directory steps (blocks walked, holes skipped) one request may spend before
/// it answers busy: one request cannot hold the single-threaded server.
pub const CALL_STEPS: u32 = 1 << 16;

pub const STATFS_TYPE_EXT4: u32 = 6;
/// What an opener is lent: the call right on the endpoint (`CapPerms::WRITE`).
pub const NODE_RIGHTS: u16 = azos_abi::cap::CapPerms::WRITE.bits() as u16;
/// The access-mode and change bits of an open's flags (`O_WRONLY`, `O_RDWR`,
/// `O_CREAT`, `O_TRUNC`, `O_APPEND`).
const WRITE_FLAGS: u32 = 0x1 | 0x2 | 0x40 | 0x200 | 0x400;

/// What the service needs of the system it runs in.
pub trait Host {
    /// The region shared with the client.
    fn region(&mut self) -> &mut [u8];
    /// A capability on this server's endpoint carrying `badge`, to lend.
    fn derive(&mut self, badge: u32) -> Option<u32>;
    /// Withdraw a capability [`Host::derive`] made, and what was lent of it:
    /// `false` when the copies could not be revoked.
    fn revoke(&mut self, handle: u32) -> bool;
    /// A number this run of the server has and the previous one had not:
    /// where its open sequence starts.
    fn incarnation(&mut self) -> u32;
}

#[derive(Clone, Copy)]
struct Open {
    ino: Inode,
    pos: u64,
    handle: u32,
    badge: u32,
    used: u64,
    /// Its revoke failed: it keeps serving its badge, and the slot is never
    /// handed out again.
    pinned: bool,
}

#[derive(Clone, Copy)]
enum Slot {
    Free,
    Open(Open),
}

/// What a block completion popped while waiting for entry `want` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// The entry's own: its result.
    Mine(i32),
    /// An earlier entry's, which came after its waiter gave up: dropped.
    Stale,
    /// A tag no entry of this ring was given: the ring is not this server's.
    Stray,
}

/// Classify the completion `(tag, result)` popped while waiting for `want`
/// (tags are handed out increasing, one entry in flight at a time).
pub fn completion(want: u64, tag: u64, result: i32) -> Completion {
    if tag == want {
        Completion::Mine(result)
    } else if tag < want && !cfg!(feature = "stale-completion-canary") {
        Completion::Stale
    } else {
        Completion::Stray
    }
}

/// The service: the volume, the open files, the call being served.
pub struct Service<S: BlockSource, H: Host> {
    pub vol: Volume<S>,
    pub host: H,
    nodes: [Slot; NODES],
    /// The badge of the call being served: [`DIR_BADGE`] the root
    /// directory, else an open file's.
    pub badge: u32,
    /// The open sequence: the high bits of the next badge.
    seq: u32,
    clock: u64,
    /// Where the last listing stopped: directory, index of the next entry,
    /// its position.
    cursor: Option<(u32, u32, u64)>,
}

/// The parser's refusal as the protocol's code.
pub fn code(e: Error) -> u32 {
    match e {
        Error::NotFound => NOT_FOUND,
        Error::NotDir => NOT_DIR,
        Error::NameTooLong => NAME_TOO_LONG,
        Error::NotFile => IS_DIR,
        Error::Loop | Error::BadName => outcome::BAD_ARGUMENT,
        Error::Escape => outcome::DENIED,
        Error::Busy => outcome::BUSY,
        Error::Unread(_) => outcome::UNSUPPORTED,
        Error::Io | Error::Corrupt(_) => outcome::FAULT,
    }
}

/// The bytes of `e` in `region`, or `None` when it reaches outside.
fn span(region: &[u8], e: Extent) -> Option<core::ops::Range<usize>> {
    let off = usize::try_from(e.off).ok()?;
    let end = off.checked_add(e.len as usize)?;
    (end <= region.len()).then_some(off..end)
}

/// The name `e` holds (up to its first NUL), copied out of the region and
/// checked: relative, and never above the directory it names from.
fn name_of(region: &[u8], e: Extent, out: &mut [u8; PATH_MAX]) -> Result<usize, u32> {
    let r = span(region, e).ok_or(outcome::BAD_ARGUMENT)?;
    let raw = &region[r];
    let n = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    if n > PATH_MAX {
        return Err(NAME_TOO_LONG);
    }
    let name = &raw[..n];
    if name.first() == Some(&b'/') {
        return Err(outcome::BAD_ARGUMENT);
    }
    let mut depth = 0i32;
    for c in name.split(|&c| c == b'/').filter(|c| !c.is_empty() && *c != b".") {
        depth += if c == b".." { -1 } else { 1 };
        if depth < 0 {
            return Err(outcome::BAD_ARGUMENT);
        }
    }
    out[..n].copy_from_slice(name);
    Ok(n)
}

/// Where the `n`th component of `name` ends (empty components do not count),
/// `None` when it has fewer.
fn components_end(name: &[u8], n: usize) -> Option<usize> {
    let mut seen = 0;
    let mut start = 0;
    for c in name.split(|&b| b == b'/') {
        if !c.is_empty() {
            seen += 1;
            if seen == n {
                return Some(start + c.len());
            }
        }
        start += c.len() + 1;
    }
    None
}

impl<S: BlockSource, H: Host> Service<S, H> {
    pub fn new(vol: Volume<S>, mut host: H) -> Self {
        let seq = host.incarnation();
        Service { vol, host, nodes: [Slot::Free; NODES], badge: 0, seq, clock: 0, cursor: None }
    }

    /// The next badge for `slot`: never [`DIR_BADGE`], never 0.
    fn next_badge(&mut self, slot: usize) -> u32 {
        if cfg!(feature = "badge-slot-canary") {
            return slot as u32 + 1;
        }
        loop {
            self.seq = self.seq.wrapping_add(1) & (u32::MAX >> SLOT_BITS);
            if self.seq != 0 {
                return self.seq << SLOT_BITS | slot as u32;
            }
        }
    }

    /// The inode `e` names, symlinks followed, with the first `floor` components
    /// of the name as the directory the caller is rooted at: what is below it is
    /// resolved beneath it, and no symlink leads out. A symlink among the
    /// floor's own components is refused too, so a grant made through a link
    /// (`lib` -> `usr/lib`) is refused rather than followed.
    fn resolve_beneath(&mut self, e: Extent, floor: u32) -> Result<Inode, u32> {
        if self.badge != DIR_BADGE {
            return Err(outcome::DENIED);
        }
        let mut buf = [0u8; PATH_MAX];
        let n = name_of(self.host.region(), e, &mut buf)?;
        self.resolve_path(&buf[..n], floor, true).map_err(code)
    }

    /// The inode `name` names, rooted at the directory its first `floor`
    /// components make (the volume's root for 0).
    fn resolve_path(&mut self, name: &[u8], floor: u32, follow_last: bool) -> Result<Inode, Error> {
        self.vol.begin_call(CALL_STEPS);
        if floor == 0 {
            return self.vol.resolve(name, follow_last);
        }
        let end = components_end(name, floor as usize).ok_or(Error::BadName)?;
        let base = self.vol.resolve_plain(&name[..end])?;
        self.vol.resolve_beneath(&base, &name[end..], follow_last)
    }

    /// The open file of the call's badge.
    fn node(&mut self) -> Result<&mut Open, u32> {
        if self.badge == DIR_BADGE || self.badge == 0 {
            return Err(outcome::DENIED);
        }
        let slot = if cfg!(feature = "badge-slot-canary") {
            (self.badge as usize).wrapping_sub(1)
        } else {
            (self.badge & ((1 << SLOT_BITS) - 1)) as usize
        };
        self.clock += 1;
        let now = self.clock;
        let badge = self.badge;
        match self.nodes.get_mut(slot) {
            Some(Slot::Open(o)) if o.badge == badge => {
                o.used = now;
                Ok(o)
            }
            _ => Err(outcome::NO_RESOURCE),
        }
    }

    /// Write `bytes` to the region at `e`, which must hold them.
    fn put(&mut self, e: Extent, bytes: &[u8]) -> Result<(), u32> {
        let region = self.host.region();
        let r = span(region, e).ok_or(outcome::BAD_ARGUMENT)?;
        if r.len() < bytes.len() {
            return Err(outcome::BAD_ARGUMENT);
        }
        region[r.start..r.start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// The entry `index` of directory `dir`, from the cursor when it stopped
    /// right before it.
    fn entry(&mut self, dir: &Inode, index: u32, e: &mut DirEntry) -> Result<bool, u32> {
        let (mut i, mut pos) = match self.cursor {
            Some((d, ci, cp)) if d == dir.ino && ci <= index => (ci, cp),
            _ => (0, 0),
        };
        loop {
            match self.vol.readdir(dir, pos, e).map_err(code)? {
                None => {
                    self.cursor = None;
                    return Ok(false);
                }
                Some(next) => {
                    pos = next;
                    if i == index {
                        self.cursor = Some((dir.ino, i + 1, pos));
                        return Ok(true);
                    }
                    i += 1;
                }
            }
        }
    }

    /// What a client sees of entry `e` of the directory `dir` names: the
    /// file a symlink names, or the link itself when it names nothing.
    fn seen(&mut self, dir: &[u8], floor: u32, e: &DirEntry) -> Result<Inode, Error> {
        let own = self.vol.inode(e.ino)?;
        if !own.is_symlink() && !cfg!(feature = "seen-resolve-canary") {
            return Ok(own);
        }
        let mut p = [0u8; PATH_MAX];
        let n = dir.len() + 1 + e.name().len();
        if n <= PATH_MAX {
            p[..dir.len()].copy_from_slice(dir);
            p[dir.len()] = b'/';
            p[dir.len() + 1..n].copy_from_slice(e.name());
            if let Ok(i) = self.resolve_path(&p[..n], floor, true) {
                return Ok(i);
            }
        }
        Ok(own)
    }
}

fn stat_bytes(i: &Inode) -> [u8; STAT_BYTES] {
    let mut b = [0u8; STAT_BYTES];
    b[STAT_OFF_SIZE..STAT_OFF_SIZE + 8].copy_from_slice(&i.size.to_le_bytes());
    b[STAT_OFF_MODE..STAT_OFF_MODE + 4].copy_from_slice(&(i.mode as u32).to_le_bytes());
    b[STAT_OFF_NLINK..STAT_OFF_NLINK + 4].copy_from_slice(&(i.links as u32).to_le_bytes());
    b[STAT_OFF_UID..STAT_OFF_UID + 4].copy_from_slice(&i.uid.to_le_bytes());
    b[STAT_OFF_GID..STAT_OFF_GID + 4].copy_from_slice(&i.gid.to_le_bytes());
    b[STAT_OFF_ATIME..STAT_OFF_ATIME + 8].copy_from_slice(&(i.atime as u64).to_le_bytes());
    b[STAT_OFF_MTIME..STAT_OFF_MTIME + 8].copy_from_slice(&(i.mtime as u64).to_le_bytes());
    b[STAT_OFF_CTIME..STAT_OFF_CTIME + 8].copy_from_slice(&(i.ctime as u64).to_le_bytes());
    b
}

fn done<T: Default>(r: Result<T, u32>) -> Out<T> {
    match r {
        Ok(v) => Out::ok(v),
        Err(c) => Out::err(c),
    }
}

impl<S: BlockSource, H: Host> Dir for Service<S, H> {
    fn openat(&mut self, name: Extent, flags: u32, floor: u32) -> Out<Lent<OpenNode>> {
        if flags & WRITE_FLAGS != 0 {
            return Out::new(READ_ONLY, Lent::none());
        }
        let ino = match self.resolve_beneath(name, floor) {
            Ok(i) if i.is_dir() => return Out::new(IS_DIR, Lent::none()),
            Ok(i) => i,
            Err(c) => return Out::new(c, Lent::none()),
        };
        // A free slot, else the one used longest ago, whose lent copy goes; a
        // slot whose copy could not be revoked is dead, and the next oldest is
        // tried.
        let slot = loop {
            if let Some(s) = self.nodes.iter().position(|o| matches!(o, Slot::Free)) {
                break s;
            }
            let oldest = self
                .nodes
                .iter()
                .enumerate()
                .filter_map(|(s, o)| match o {
                    Slot::Open(o) if !o.pinned => Some((s, *o)),
                    _ => None,
                })
                .min_by_key(|(_, o)| o.used);
            let Some((s, mut old)) = oldest else { return Out::new(outcome::BUSY, Lent::none()) };
            if self.host.revoke(old.handle) || cfg!(feature = "badge-slot-canary") {
                self.nodes[s] = Slot::Free;
            } else {
                old.pinned = true;
                self.nodes[s] = Slot::Open(old);
            }
        };
        let badge = self.next_badge(slot);
        let Some(handle) = self.host.derive(badge) else {
            return Out::new(outcome::BUSY, Lent::none());
        };
        self.clock += 1;
        self.nodes[slot] = Slot::Open(Open { ino, pos: 0, handle, badge, used: self.clock, pinned: false });
        Out::ok(Lent::dup(handle, NODE_RIGHTS))
    }

    fn statat(&mut self, name: Extent, floor: u32, out: Extent) -> Out<()> {
        let r = self.resolve_beneath(name, floor).and_then(|i| self.put(out, &stat_bytes(&i)));
        done(r)
    }

    fn readdir(&mut self, name: Extent, floor: u32, index: u32, out: Extent) -> Out<Entry> {
        let r = (|| {
            if self.badge != DIR_BADGE {
                return Err(outcome::DENIED);
            }
            let mut path = [0u8; PATH_MAX];
            let pn = name_of(self.host.region(), name, &mut path)?;
            let dir = self.resolve_path(&path[..pn], floor, true).map_err(code)?;
            if !dir.is_dir() {
                return Err(NOT_DIR);
            }
            let mut e = DirEntry::new();
            if !self.entry(&dir, index, &mut e)? {
                return Ok(Entry::default());
            }
            let i = self.seen(&path[..pn], floor, &e).map_err(code)?;
            let mut rec = [0u8; READDIR_NAME_BYTES];
            let room = (out.len as usize).min(READDIR_NAME_BYTES);
            let n = e.name().len().min(room.saturating_sub(1));
            rec[..n].copy_from_slice(&e.name()[..n]);
            self.put(out, &rec[..room])?;
            Ok(Entry {
                present: true,
                size: u32::try_from(i.size).unwrap_or(u32::MAX),
                is_dir: i.is_dir(),
                cut: n < e.name().len(),
            })
        })();
        done(r)
    }

    fn statfs(&mut self, name: Extent, floor: u32, out: Extent) -> Out<()> {
        let r = self.resolve_beneath(name, floor).and_then(|_| {
            let s = *self.vol.info();
            let mut b = [0u8; STATFS_BYTES];
            b[STATFS_OFF_TYPE..STATFS_OFF_TYPE + 4].copy_from_slice(&STATFS_TYPE_EXT4.to_le_bytes());
            b[STATFS_OFF_BSIZE..STATFS_OFF_BSIZE + 4].copy_from_slice(&s.block_size.to_le_bytes());
            b[STATFS_OFF_BLOCKS..STATFS_OFF_BLOCKS + 8].copy_from_slice(&s.blocks_count.to_le_bytes());
            b[STATFS_OFF_BFREE..STATFS_OFF_BFREE + 8].copy_from_slice(&s.free_blocks.to_le_bytes());
            b[STATFS_OFF_FILES..STATFS_OFF_FILES + 8].copy_from_slice(&(s.inodes_count as u64).to_le_bytes());
            b[STATFS_OFF_FFREE..STATFS_OFF_FFREE + 8].copy_from_slice(&(s.free_inodes as u64).to_le_bytes());
            b[40..44].copy_from_slice(&(azos_ext4::NAME_MAX as u32).to_le_bytes());
            self.put(out, &b)
        });
        done(r)
    }

    fn mkdirat(&mut self, _name: Extent) -> Out<()> {
        Out::err(READ_ONLY)
    }
    fn unlinkat(&mut self, _name: Extent, _flags: u32) -> Out<()> {
        Out::err(READ_ONLY)
    }
    fn renameat(&mut self, _from: Extent, _to: Extent) -> Out<()> {
        Out::err(READ_ONLY)
    }
    fn truncateat(&mut self, _name: Extent, _len: u64) -> Out<()> {
        Out::err(READ_ONLY)
    }
}

impl<S: BlockSource, H: Host> Node for Service<S, H> {
    fn read(&mut self, buf: Extent) -> Out<ReadDone> {
        let r = (|| {
            let o = *self.node()?;
            let want = buf.len.min(READ_MAX) as usize;
            // Host canary: half of what was asked, and no word of the end.
            let want = if cfg!(feature = "short-read-canary") { want / 2 } else { want };
            let region = self.host.region();
            let at = span(region, Extent { off: buf.off, len: want as u32 }).ok_or(outcome::BAD_ARGUMENT)?;
            let n = self.vol.read(&o.ino, o.pos, &mut region[at]).map_err(code)?;
            let pos = o.pos + n as u64;
            self.node()?.pos = pos;
            let end = pos >= o.ino.size && !cfg!(feature = "short-read-canary");
            Ok(ReadDone { count: n as u32, end })
        })();
        done(r)
    }

    fn write(&mut self, _buf: Extent) -> Out<u32> {
        Out::err(READ_ONLY)
    }

    fn fsync(&mut self) -> Out<()> {
        done(self.node().map(|_| ()))
    }

    fn seek(&mut self, offset: i64, whence: u32) -> Out<u64> {
        let r = (|| {
            let o = self.node()?;
            let base = match whence {
                0 => 0i128,
                1 => o.pos as i128,
                2 => o.ino.size as i128,
                _ => return Err(outcome::BAD_ARGUMENT),
            };
            let to = u64::try_from(base + offset as i128).map_err(|_| outcome::BAD_ARGUMENT)?;
            o.pos = to;
            Ok(to)
        })();
        done(r)
    }
}
