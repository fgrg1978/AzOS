// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A mount served from ring 3 (`crates/fs/src/endpoint.rs`) behind the real
//! VFS: a client opens, reads, stats and lists it as any volume, and what
//! the server answers out of contract is refused, not served.
//!
//! The server here is a small in-memory one that answers the file protocol
//! (`azos_devif::fs`) through its generated dispatchers; the real one, over
//! ext4, is `tests/host/ext4-tests` (`protocol`).

use super::{endpoint, serial, vfs};
use azos_abi::syscall_nr::{READDIR_NAME_BYTES, STAT_BYTES};
use azos_devif::fs::{Dir, DirIdl, Entry, Extent, Node, NodeIdl, OpenNode, ReadDone, DIR_ID, NOT_FOUND, READ_MAX};
use azos_devif::{outcome, Out};
use azos_idl::{IdlError, Lent, MsgDesc, Result as IdlResult};
use endpoint::{EndpointFs, Link, REGION_BYTES};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, Once};

const AT: &str = "/ep";
/// Handles the server lends: `BASE + slot`.
const BASE: u32 = 100;

fn big() -> Vec<u8> {
    (0..10_000u32).map(|i| (i * 13 % 251) as u8).collect()
}

const FILES: &[(&str, &[u8])] = &[("hello.txt", b"hello from ring 3\n"), ("dir/a.txt", b"a\n")];

fn file(name: &str) -> Option<Vec<u8>> {
    if name == "big.bin" {
        return Some(big());
    }
    FILES.iter().find(|f| f.0 == name).map(|f| f.1.to_vec())
}

struct Server {
    region: Vec<u8>,
    badge: u32,
    open: Vec<Option<(Vec<u8>, u64)>>,
    calls: u32,
}

impl Server {
    fn name(&self, e: Extent) -> String {
        let r = &self.region[e.off as usize..(e.off + e.len as u64) as usize];
        let n = r.iter().position(|&c| c == 0).unwrap_or(r.len());
        String::from_utf8(r[..n].to_vec()).unwrap()
    }
}

impl Dir for Server {
    fn openat(&mut self, name: Extent, _flags: u32) -> Out<Lent<OpenNode>> {
        let Some(data) = file(&self.name(name)) else { return Out::new(NOT_FOUND, Lent::none()) };
        self.open.push(Some((data, 0)));
        Out::ok(Lent::dup(BASE + self.open.len() as u32 - 1, 2))
    }
    fn statat(&mut self, name: Extent, out: Extent) -> Out<()> {
        let n = self.name(name);
        let (size, mode) = match file(&n) {
            Some(d) => (d.len() as u64, 0o100644u32),
            None if n.is_empty() || n == "dir" => (0, 0o040755),
            None => return Out::err(NOT_FOUND),
        };
        let mut b = [0u8; STAT_BYTES];
        b[..8].copy_from_slice(&size.to_le_bytes());
        b[8..12].copy_from_slice(&mode.to_le_bytes());
        self.region[out.off as usize..out.off as usize + STAT_BYTES].copy_from_slice(&b);
        Out::ok(())
    }
    fn readdir(&mut self, name: Extent, index: u32, out: Extent) -> Out<Entry> {
        let list: &[(&str, bool, u32)] = match self.name(name).as_str() {
            "" => &[("hello.txt", false, 18), ("big.bin", false, 10_000), ("dir", true, 0)],
            "dir" => &[("a.txt", false, 2)],
            _ => return Out::err(NOT_FOUND),
        };
        let Some(&(n, is_dir, size)) = list.get(index as usize) else { return Out::ok(Entry::default()) };
        let r = &mut self.region[out.off as usize..out.off as usize + READDIR_NAME_BYTES];
        r.fill(0);
        r[..n.len()].copy_from_slice(n.as_bytes());
        Out::ok(Entry { present: true, size, is_dir, cut: false })
    }
    fn statfs(&mut self, _name: Extent, _out: Extent) -> Out<()> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn mkdirat(&mut self, _name: Extent) -> Out<()> {
        CHANGES.fetch_add(1, Ordering::SeqCst);
        Out::err(outcome::UNSUPPORTED)
    }
    fn unlinkat(&mut self, _name: Extent, _flags: u32) -> Out<()> {
        CHANGES.fetch_add(1, Ordering::SeqCst);
        Out::err(outcome::UNSUPPORTED)
    }
    fn renameat(&mut self, _from: Extent, _to: Extent) -> Out<()> {
        CHANGES.fetch_add(1, Ordering::SeqCst);
        Out::err(outcome::UNSUPPORTED)
    }
    fn truncateat(&mut self, _name: Extent, _len: u64) -> Out<()> {
        CHANGES.fetch_add(1, Ordering::SeqCst);
        Out::err(outcome::UNSUPPORTED)
    }
}

impl Node for Server {
    fn read(&mut self, buf: Extent) -> Out<ReadDone> {
        let slot = self.badge.wrapping_sub(BASE) as usize;
        let Some(Some((data, pos))) = self.open.get_mut(slot) else { return Out::err(outcome::NO_RESOURCE) };
        let mut want = (buf.len.min(READ_MAX) as usize).min(data.len() - *pos as usize);
        let lie = LIAR.load(Ordering::SeqCst);
        if lie {
            want /= 2;
        }
        let at = buf.off as usize;
        let from = *pos as usize;
        let chunk = data[from..from + want].to_vec();
        *pos += want as u64;
        let end = *pos as usize >= data.len() && !lie;
        self.region[at..at + want].copy_from_slice(&chunk);
        Out::ok(ReadDone { count: want as u32, end })
    }
    fn write(&mut self, _buf: Extent) -> Out<u32> {
        CHANGES.fetch_add(1, Ordering::SeqCst);
        Out::err(outcome::UNSUPPORTED)
    }
    fn fsync(&mut self) -> Out<()> {
        Out::ok(())
    }
    fn seek(&mut self, offset: i64, whence: u32) -> Out<u64> {
        let slot = self.badge.wrapping_sub(BASE) as usize;
        let Some(Some((_, pos))) = self.open.get_mut(slot) else { return Out::err(outcome::NO_RESOURCE) };
        if whence != 0 || offset < 0 {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        *pos = offset as u64;
        Out::ok(*pos)
    }
}

/// The server answers half of each read and never says the file ended.
static LIAR: AtomicBool = AtomicBool::new(false);
/// Ops that would change the tree, as the server saw them.
static CHANGES: AtomicU32 = AtomicU32::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);

struct TestLink(Mutex<Server>);

impl Link for TestLink {
    fn call(&self, node: Option<u32>, msg: &mut MsgDesc) -> IdlResult {
        let mut s = self.0.lock().unwrap();
        s.calls += 1;
        s.badge = node.unwrap_or(0);
        if node.is_some_and(|n| s.open.get(n.wrapping_sub(BASE) as usize).is_none_or(|o| o.is_none())) {
            // A capability the server took back: the kernel refuses the call.
            return Err(IdlError::Transport(-1));
        }
        let req = *msg;
        if (req.words[0] >> 32) as u32 == DIR_ID {
            let _ = DirIdl::dispatch(&mut *s, &req, msg);
        } else {
            let _ = NodeIdl::dispatch(&mut *s, &req, msg);
        }
        Ok(())
    }
    fn close(&self, _node: u32) {
        CLOSED.fetch_add(1, Ordering::SeqCst);
    }
    fn put(&self, off: usize, bytes: &[u8]) -> bool {
        let mut s = self.0.lock().unwrap();
        match s.region.get_mut(off..off + bytes.len()) {
            Some(d) => {
                d.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
    fn get(&self, off: usize, out: &mut [u8]) -> bool {
        let s = self.0.lock().unwrap();
        match s.region.get(off..off + out.len()) {
            Some(d) => {
                out.copy_from_slice(d);
                true
            }
            None => false,
        }
    }
}

fn link() -> &'static TestLink {
    static LINK: std::sync::OnceLock<&'static TestLink> = std::sync::OnceLock::new();
    LINK.get_or_init(|| {
        Box::leak(Box::new(TestLink(Mutex::new(Server { region: vec![0; REGION_BYTES], badge: 0, open: vec![], calls: 0 }))))
    })
}

fn mounted() {
    super::vfs_root_once();
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let fs: &'static EndpointFs = Box::leak(Box::new(EndpointFs::new(vfs::FS_TYPE_EXT4)));
        fs.attach(link());
        vfs::vfs_mount_fs(AT.as_bytes(), fs).expect("the mount table has room");
    });
}

fn read_path(path: &str, chunk: usize) -> Option<Vec<u8>> {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path.as_bytes(), vfs::O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut b = vec![0u8; chunk];
    loop {
        let n = vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), chunk);
        assert!(n >= 0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[..n as usize]);
    }
    vfs::vfs_close(&mut t, fd);
    Some(out)
}

/// **A client reads the mount as it reads any volume**: whole files at any
/// read size, sizes and types by stat, entries by listing.
#[test]
fn a_client_reads_the_mount_as_any_volume() {
    let _g = serial();
    mounted();
    LIAR.store(false, Ordering::SeqCst);
    assert_eq!(read_path("/ep/hello.txt", 64).unwrap(), b"hello from ring 3\n");
    for chunk in [1, 1000, 4096, 9000] {
        assert_eq!(read_path("/ep/big.bin", chunk).unwrap(), big(), "chunk {chunk}");
    }
    assert_eq!(read_path("/ep/dir/a.txt", 16).unwrap(), b"a\n");
    assert!(read_path("/ep/nope", 16).is_none());
    let st = vfs::vfs_stat(b"/ep/big.bin").unwrap();
    assert_eq!((st.size, st.is_dir), (10_000, false));
    assert!(vfs::vfs_stat(b"/ep/dir").unwrap().is_dir);
    let mut names = Vec::new();
    let mut e = vfs::DirEnt::new();
    let mut c = 0;
    while let Some(next) = vfs::vfs_readdir(b"/ep", c, &mut e).unwrap() {
        names.push((String::from_utf8(e.name().to_vec()).unwrap(), e.is_dir, e.size));
        c = next;
    }
    assert_eq!(
        names,
        [("hello.txt".to_string(), false, 18), ("big.bin".to_string(), false, 10_000), ("dir".to_string(), true, 0)]
    );
}

/// **A change is refused before it reaches the server**: the mount is
/// read-only, so neither a writable open nor a tree change asks it.
#[test]
fn changes_are_refused_before_the_server() {
    let _g = serial();
    mounted();
    let before = CHANGES.load(Ordering::SeqCst);
    let mut t = vfs::ScratchFds::new();
    assert!(vfs::vfs_open(&mut t, b"/ep/new.txt", vfs::O_WRONLY | vfs::O_CREAT) < 0);
    assert!(vfs::vfs_open(&mut t, b"/ep/hello.txt", vfs::O_RDWR) < 0);
    assert!(vfs::vfs_mkdir(b"/ep/d").is_err());
    assert!(vfs::vfs_unlink(b"/ep/hello.txt").is_err());
    assert!(vfs::vfs_rename(b"/ep/hello.txt", b"/ep/x").is_err());
    assert_eq!(CHANGES.load(Ordering::SeqCst), before);
}

/// **A short read the server does not call the end is not served as the
/// file**: the client gets nothing rather than a truncated file it would
/// take for the whole one, and its size from stat says it is missing bytes.
///
/// **Canary.** `endpoint-short-read-canary`: the mount takes the server's
/// count as it comes, and the client reads a prefix of the file.
#[test]
fn a_short_read_is_never_served_as_the_file() {
    let _g = serial();
    mounted();
    LIAR.store(true, Ordering::SeqCst);
    let got = read_path("/ep/hello.txt", 64).unwrap();
    LIAR.store(false, Ordering::SeqCst);
    let size = vfs::vfs_stat(b"/ep/hello.txt").unwrap().size as usize;
    assert!(got.is_empty(), "a short read was served: {} of {size} bytes", got.len());
    // The server moved its offset while it lied: the next read seeks.
    assert_eq!(read_path("/ep/hello.txt", 64).unwrap(), b"hello from ring 3\n");
}

/// **A capability the server took back is opened again**: the read after
/// it still answers the file.
#[test]
fn a_node_the_server_dropped_is_opened_again() {
    let _g = serial();
    mounted();
    LIAR.store(false, Ordering::SeqCst);
    assert_eq!(read_path("/ep/hello.txt", 64).unwrap(), b"hello from ring 3\n");
    for o in link().0.lock().unwrap().open.iter_mut() {
        *o = None;
    }
    assert_eq!(read_path("/ep/hello.txt", 64).unwrap(), b"hello from ring 3\n");
}
