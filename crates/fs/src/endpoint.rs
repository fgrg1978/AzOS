// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A file system served from ring 3: a [`FileSystem`] that forwards every
//! operation to a server on an endpoint, in the file protocol
//! (`azos_devif::fs`: `Dir` on the server's endpoint, `Node` on the
//! capability the server lends for each open file).
//!
//! The VFS routes a path under the mount here like under any other; the
//! client of the mount opens, reads, lists and stats as it would on FAT32 and
//! cannot tell that a ring-3 program answered. What the kernel gives the
//! mount is a [`Link`]: the call to the server (made from a kernel task that
//! holds the server's capabilities, never from the client's table) and the
//! region the two share, where names go out and data comes back. Nothing the
//! server writes there is believed before it is copied out and checked: a
//! read that is shorter than asked without saying the file ended is refused
//! ([`read_checked`]), so a truncated file is never served as the whole one.
//!
//! One operation at a time per mount ([`Claim`]): the region holds one
//! request. Read-only for now: every change is refused before it reaches the
//! server.
//!
//! Not page-cached: a backing read cannot fail through `read_at` (it answers
//! a count), so a page the cache filled from a refused read would hold zeros
//! where the file has bytes. Every read crosses to the server, which keeps
//! only metadata; the supply-pages pager, where the server's pages are the
//! cache's, is what lets the mount be cached without a second copy.
//!
//! [`Claim`]: azos_sync::claim::Claim

use crate::vfs::{
    DirEnt, FileStat, FileSystem, FsErr, InodeKey, StatFs, INODE_KEY_LEN, S_IFDIR,
};
use azos_abi::syscall_nr::{
    READDIR_NAME_BYTES, STATFS_BYTES, STATFS_OFF_BFREE, STATFS_OFF_BLOCKS, STATFS_OFF_BSIZE, STATFS_OFF_FFREE,
    STATFS_OFF_FILES, STATFS_OFF_TYPE, STAT_BYTES, STAT_OFF_ATIME, STAT_OFF_CTIME, STAT_OFF_GID, STAT_OFF_MODE,
    STAT_OFF_MTIME, STAT_OFF_NLINK, STAT_OFF_SIZE, STAT_OFF_UID,
};
use azos_devif::fs::{
    read_checked, DirCall, DirClient, Extent, NodeCall, NodeClient, IS_DIR, NAME_TOO_LONG, NOT_DIR, NOT_FOUND,
    READ_MAX, READ_ONLY,
};
use azos_devif::outcome;
use azos_idl::{MsgDesc, Result as IdlResult, Transport};
use azos_sync::claim::Claim;
use azos_sync::SpinLock;

/// Where a name goes in the shared region (NUL-terminated).
pub const NAME_OFF: usize = 0;
/// Room for a name: a key's bytes and the NUL.
const NAME_ROOM: usize = 512;
/// Where a record comes back (stat, statfs, a listed name).
pub const OUT_OFF: usize = NAME_OFF + NAME_ROOM;
const OUT_ROOM: usize = 512;
/// Where data comes back: [`READ_MAX`] bytes.
pub const DATA_OFF: usize = OUT_OFF + OUT_ROOM;
/// The bytes the shared region must hold.
pub const REGION_BYTES: usize = DATA_OFF + READ_MAX as usize;
const _: () = assert!(INODE_KEY_LEN < NAME_ROOM && READDIR_NAME_BYTES <= OUT_ROOM && STAT_BYTES <= OUT_ROOM);

/// Open files a mount keeps a server capability for.
const NODES: usize = 8;

/// What the kernel provides an endpoint mount.
pub trait Link: Sync {
    /// One call of the file protocol to the server: on its endpoint (the
    /// root directory) when `node` is `None`, else through the open file's
    /// capability the server lent (`node`, as an earlier call answered it).
    /// The answer replaces `msg`. A lent capability arrives in the answer's
    /// first capability entry and is the caller's to keep.
    fn call(&self, node: Option<u32>, msg: &mut MsgDesc) -> IdlResult;
    /// Give back a capability the server lent.
    fn close(&self, node: u32);
    /// Copy `bytes` into the shared region at `off`; `false` when they do
    /// not fit.
    fn put(&self, off: usize, bytes: &[u8]) -> bool;
    /// Copy the shared region at `off` into `out`; `false` when it does not
    /// hold that many.
    fn get(&self, off: usize, out: &mut [u8]) -> bool;
}

/// The protocol's calls through a [`Link`].
struct Via<'a>(&'a dyn Link, Option<u32>);

impl Transport for Via<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        self.0.call(self.1, msg)
    }
}

#[derive(Clone, Copy)]
struct Open {
    key: InodeKey,
    node: u32,
    pos: u64,
    used: u64,
}

struct State {
    nodes: [Option<Open>; NODES],
    clock: u64,
}

/// A mount served from ring 3.
pub struct EndpointFs {
    fs_type: u32,
    link: SpinLock<Option<&'static dyn Link>>,
    state: Claim<State>,
}

/// The protocol's refusal as the VFS's.
fn fs_err(code: u32) -> FsErr {
    match code {
        NOT_FOUND => FsErr::NotFound,
        NOT_DIR => FsErr::NotDir,
        IS_DIR => FsErr::IsDir,
        READ_ONLY => FsErr::ReadOnly,
        NAME_TOO_LONG => FsErr::NameTooLong,
        outcome::BAD_ARGUMENT => FsErr::Invalid,
        outcome::BUSY => FsErr::Busy,
        outcome::DENIED => FsErr::Denied,
        outcome::UNSUPPORTED => FsErr::Unsupported,
        _ => FsErr::Io,
    }
}

/// The name a key carries (the path beneath the mount, zero-padded).
fn name_of(key: &InodeKey) -> &[u8] {
    let n = key.bytes.iter().position(|&c| c == 0).unwrap_or(INODE_KEY_LEN);
    &key.bytes[..n]
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(w)
}

impl EndpointFs {
    /// A mount answering to `fs_type`, with no server until
    /// [`EndpointFs::attach`].
    pub const fn new(fs_type: u32) -> Self {
        EndpointFs {
            fs_type,
            link: SpinLock::new(None),
            state: Claim::new(State { nodes: [None; NODES], clock: 0 }),
        }
    }

    /// Give the mount its server.
    pub fn attach(&self, link: &'static dyn Link) {
        *self.link.lock() = Some(link);
    }

    fn link(&self) -> Result<&'static dyn Link, FsErr> {
        (*self.link.lock()).ok_or(FsErr::Io)
    }

    /// Put `name` in the region: its extent.
    fn name(link: &dyn Link, name: &[u8]) -> Result<Extent, FsErr> {
        if name.len() >= NAME_ROOM || name.contains(&0) {
            return Err(FsErr::NameTooLong);
        }
        let mut b = [0u8; NAME_ROOM];
        b[..name.len()].copy_from_slice(name);
        if !link.put(NAME_OFF, &b[..name.len() + 1]) {
            return Err(FsErr::Io);
        }
        Ok(Extent { off: NAME_OFF as u64, len: name.len() as u32 + 1 })
    }

    fn served<T>(r: azos_idl::Result<azos_devif::Out<T>>) -> Result<T, FsErr> {
        outcome::served(r).map_err(fs_err)
    }

    /// Open `key` on the server: the capability it lent.
    fn open(link: &dyn Link, key: &InodeKey) -> Result<u32, FsErr> {
        let n = Self::name(link, name_of(key))?;
        let lent = Self::served(DirClient::new(Via(link, None)).openat(n, 0))?;
        lent.get().map(|c| c.raw()).ok_or(FsErr::Io)
    }

    /// The slot of `key`'s open file, opened (and the oldest given back)
    /// when the mount holds none.
    fn node(link: &dyn Link, st: &mut State, key: &InodeKey) -> Result<usize, FsErr> {
        st.clock += 1;
        if let Some(i) = st.nodes.iter().position(|o| o.is_some_and(|o| o.key == *key)) {
            if let Some(o) = st.nodes[i].as_mut() {
                o.used = st.clock;
            }
            return Ok(i);
        }
        let node = Self::open(link, key)?;
        let i = match st.nodes.iter().position(|o| o.is_none()) {
            Some(i) => i,
            None => {
                let mut i = 0;
                for (j, o) in st.nodes.iter().enumerate() {
                    if o.map_or(0, |o| o.used) < st.nodes[i].map_or(0, |o| o.used) {
                        i = j;
                    }
                }
                if let Some(old) = st.nodes[i].take() {
                    link.close(old.node);
                }
                i
            }
        };
        st.nodes[i] = Some(Open { key: *key, node, pos: 0, used: st.clock });
        Ok(i)
    }

    /// Read into `dst` from `offset` through slot `i`'s capability.
    fn read_node(link: &dyn Link, st: &mut State, i: usize, offset: u64, dst: &mut [u8]) -> Result<usize, FsErr> {
        let Some(mut o) = st.nodes[i] else { return Err(FsErr::Io) };
        let mut node = NodeClient::new(Via(link, Some(o.node)));
        let mut done = 0usize;
        let r = (|| {
            if o.pos != offset {
                o.pos = Self::served(node.seek(i64::try_from(offset).map_err(|_| FsErr::Invalid)?, 0))?;
            }
            while done < dst.len() {
                let want = (dst.len() - done).min(READ_MAX as usize);
                let buf = Extent { off: DATA_OFF as u64, len: want as u32 };
                // Gate canary `endpoint-short-read-canary`: the count as the
                // server gave it, short or not.
                let n = if cfg!(feature = "endpoint-short-read-canary") {
                    (Self::served(node.read(buf))?.count as usize).min(want)
                } else {
                    read_checked(&mut node, buf).map_err(fs_err)? as usize
                };
                if !link.get(DATA_OFF, &mut dst[done..done + n]) {
                    return Err(FsErr::Io);
                }
                done += n;
                o.pos += n as u64;
                if n < want {
                    break;
                }
            }
            Ok(())
        })();
        // After a refused read the server's offset is not known: the next
        // read seeks first.
        if r.is_err() {
            o.pos = u64::MAX;
        }
        st.nodes[i] = Some(o);
        r.map(|()| done)
    }

    fn read(&self, key: &InodeKey, offset: u64, dst: &mut [u8]) -> Result<usize, FsErr> {
        let link = self.link()?;
        let mut st = self.state.acquire();
        let i = Self::node(link, &mut st, key)?;
        match Self::read_node(link, &mut st, i, offset, dst) {
            Ok(n) => Ok(n),
            // A capability the server took back (its slots ran out) or that
            // lapsed: open once more and read again.
            Err(FsErr::Io) => {
                if let Some(old) = st.nodes[i].take() {
                    link.close(old.node);
                }
                let i = Self::node(link, &mut st, key)?;
                Self::read_node(link, &mut st, i, offset, dst)
            }
            Err(e) => Err(e),
        }
    }

    fn stat_of(&self, key: &InodeKey) -> Result<FileStat, FsErr> {
        let link = self.link()?;
        let _one = self.state.acquire();
        let n = Self::name(link, name_of(key))?;
        Self::served(DirClient::new(Via(link, None)).statat(n, Extent { off: OUT_OFF as u64, len: STAT_BYTES as u32 }))?;
        let mut b = [0u8; STAT_BYTES];
        if !link.get(OUT_OFF, &mut b) {
            return Err(FsErr::Io);
        }
        let mode = u32_at(&b, STAT_OFF_MODE);
        Ok(FileStat {
            size: u64_at(&b, STAT_OFF_SIZE),
            is_dir: mode & 0o170000 == S_IFDIR,
            cookie: 0,
            mode,
            uid: u32_at(&b, STAT_OFF_UID),
            gid: u32_at(&b, STAT_OFF_GID),
            nlink: u32_at(&b, STAT_OFF_NLINK),
            atime: u64_at(&b, STAT_OFF_ATIME),
            mtime: u64_at(&b, STAT_OFF_MTIME),
            ctime: u64_at(&b, STAT_OFF_CTIME),
        })
    }
}

impl FileSystem for EndpointFs {
    fn fs_type(&self) -> u32 {
        self.fs_type
    }

    fn mount(&self) -> Result<(), ()> {
        Ok(())
    }

    fn sync(&self) -> Result<(), ()> {
        Ok(())
    }

    fn key_for(&self, name: &[u8]) -> Option<InodeKey> {
        if name.len() > INODE_KEY_LEN || name.contains(&0) {
            return None;
        }
        let mut k = InodeKey { bytes: [0; INODE_KEY_LEN] };
        k.bytes[..name.len()].copy_from_slice(name);
        Some(k)
    }

    fn stat(&self, key: &InodeKey) -> Option<FileStat> {
        self.stat_of(key).ok()
    }

    fn read_all(&self, key: &InodeKey, _st: &FileStat, dst: &mut [u8]) -> usize {
        self.read(key, 0, dst).unwrap_or(0)
    }

    fn write_all(&self, _key: &InodeKey, _src: &[u8]) -> Result<(), ()> {
        Err(())
    }

    fn unlink(&self, _key: &InodeKey) -> Result<(), ()> {
        Err(())
    }

    fn read_at(&self, key: &InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        self.read(key, offset, dst).unwrap_or(0)
    }

    fn write_at(&self, _key: &InodeKey, _offset: u64, _src: &[u8]) -> Result<usize, ()> {
        Err(())
    }

    fn streaming(&self) -> bool {
        true
    }

    fn create(&self, _key: &InodeKey) -> Result<(), FsErr> {
        Err(FsErr::ReadOnly)
    }

    fn truncate(&self, _key: &InodeKey, _len: u64) -> Result<(), FsErr> {
        Err(FsErr::ReadOnly)
    }

    fn fsync(&self, _key: &InodeKey) -> Result<(), FsErr> {
        Ok(())
    }

    fn mkdir(&self, _name: &[u8]) -> Result<(), FsErr> {
        Err(FsErr::ReadOnly)
    }

    fn rmdir(&self, _name: &[u8]) -> Result<(), FsErr> {
        Err(FsErr::ReadOnly)
    }

    fn rename(&self, _from: &[u8], _to: &[u8]) -> Result<(), FsErr> {
        Err(FsErr::ReadOnly)
    }

    fn read_only(&self) -> bool {
        true
    }

    fn statfs(&self) -> Result<StatFs, FsErr> {
        let link = self.link()?;
        let _one = self.state.acquire();
        let n = Self::name(link, b"")?;
        Self::served(DirClient::new(Via(link, None)).statfs(n, Extent { off: OUT_OFF as u64, len: STATFS_BYTES as u32 }))?;
        let mut b = [0u8; STATFS_BYTES];
        if !link.get(OUT_OFF, &mut b) {
            return Err(FsErr::Io);
        }
        Ok(StatFs {
            fs_type: u32_at(&b, STATFS_OFF_TYPE),
            block_size: u32_at(&b, STATFS_OFF_BSIZE),
            blocks: u64_at(&b, STATFS_OFF_BLOCKS),
            blocks_free: u64_at(&b, STATFS_OFF_BFREE),
            files: u64_at(&b, STATFS_OFF_FILES),
            files_free: u64_at(&b, STATFS_OFF_FFREE),
            name_max: u32_at(&b, 40),
        })
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
        let index = u32::try_from(cookie).map_err(|_| FsErr::Invalid)?;
        let link = self.link()?;
        let _one = self.state.acquire();
        let n = Self::name(link, dir)?;
        let e = Self::served(DirClient::new(Via(link, None)).readdir(
            n,
            index,
            Extent { off: OUT_OFF as u64, len: READDIR_NAME_BYTES as u32 },
        ))?;
        if !e.present {
            return Ok(None);
        }
        let mut b = [0u8; READDIR_NAME_BYTES];
        if !link.get(OUT_OFF, &mut b) {
            return Err(FsErr::Io);
        }
        let len = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        if e.cut || !out.set(&b[..len], e.is_dir, e.size as u64) {
            return Err(FsErr::NameTooLong);
        }
        Ok(Some(cookie + 1))
    }
}
