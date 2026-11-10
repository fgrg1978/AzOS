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

const FILES: &[(&str, &[u8])] = &[("hello.txt", b"hello from ring 3\n"), ("dir/a.txt", b"a\n"), ("dir/link", b"outside\n")];

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
    fn openat(&mut self, name: Extent, _flags: u32, floor: u32) -> Out<Lent<OpenNode>> {
        FLOORS.lock().unwrap().push(floor);
        if floor > 0 && self.name(name).ends_with("link") {
            return Out::new(outcome::DENIED, Lent::none());
        }
        let Some(data) = file(&self.name(name)) else { return Out::new(NOT_FOUND, Lent::none()) };
        self.open.push(Some((data, 0)));
        Out::ok(Lent::dup(BASE + self.open.len() as u32 - 1, 2))
    }
    fn statat(&mut self, name: Extent, floor: u32, out: Extent) -> Out<()> {
        FLOORS.lock().unwrap().push(floor);
        let n = self.name(name);
        if floor > 0 && n.ends_with("link") {
            return Out::err(outcome::DENIED);
        }
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
    fn readdir(&mut self, name: Extent, floor: u32, index: u32, out: Extent) -> Out<Entry> {
        if floor > 0 && self.name(name).ends_with("link") {
            return Out::err(outcome::DENIED);
        }
        let list: &[(&str, bool, u32)] = match self.name(name).as_str() {
            "" => &[("hello.txt", false, 18), ("big.bin", false, 10_000), ("dir", true, 0)],
            "dir" | "dir/link" => &[("a.txt", false, 2)],
            _ => return Out::err(NOT_FOUND),
        };
        let Some(&(n, is_dir, size)) = list.get(index as usize) else { return Out::ok(Entry::default()) };
        let bad = BAD_NAME.lock().unwrap().clone();
        let n: &[u8] = match &bad {
            Some(b) => b,
            None => n.as_bytes(),
        };
        let r = &mut self.region[out.off as usize..out.off as usize + READDIR_NAME_BYTES];
        r.fill(0);
        r[..n.len()].copy_from_slice(n);
        Out::ok(Entry { present: true, size, is_dir, cut: false })
    }
    fn statfs(&mut self, name: Extent, floor: u32, _out: Extent) -> Out<()> {
        match self.name(name).as_str() {
            n if floor > 0 && n.ends_with("link") => Out::err(outcome::DENIED),
            "" | "dir/link" => Out::ok(()),
            _ => Out::err(outcome::UNSUPPORTED),
        }
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
        let reads = READS.fetch_add(1, Ordering::SeqCst);
        let lie = LIAR.load(Ordering::SeqCst) || reads >= LIE_FROM.load(Ordering::SeqCst);
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
/// Reads the server answered; from `LIE_FROM` on it lies as `LIAR` does.
static READS: AtomicU32 = AtomicU32::new(0);
static LIE_FROM: AtomicU32 = AtomicU32::new(u32::MAX);
/// A name the server lists in place of every entry's.
static BAD_NAME: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// The server's incarnation, as the kernel's link reports it.
static EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
/// Ops that would change the tree, as the server saw them.
static CHANGES: AtomicU32 = AtomicU32::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);
/// The floor of every open and stat the server saw (an open whose file the mount
/// already holds open reaches it as a stat only).
static FLOORS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

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
    fn epoch(&self) -> u64 {
        EPOCH.load(Ordering::SeqCst)
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
        // An error ends the read as the end of the file does; what was read
        // is what the caller compares.
        if n <= 0 {
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

/// **A read that fails in the middle of a file is an error, not the end of
/// it**: the client's `vfs_read` answers -1 (EIO), so `cat` or `cp` never
/// end cleanly with a truncated file.
///
/// **Canary.** `endpoint-eof-canary`: the failure reads as 0 bytes again.
#[test]
fn a_read_that_fails_mid_file_is_an_error_not_the_end() {
    let _g = serial();
    mounted();
    LIAR.store(false, Ordering::SeqCst);
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/ep/big.bin", vfs::O_RDONLY);
    assert!(fd >= 0);
    let mut b = vec![0u8; 4096];
    assert_eq!(vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 4096), 4096);
    // From the next read on, the server lies.
    LIE_FROM.store(READS.load(Ordering::SeqCst), Ordering::SeqCst);
    let n = vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 4096);
    LIE_FROM.store(u32::MAX, Ordering::SeqCst);
    vfs::vfs_close(&mut t, fd);
    assert!(n < 0, "a read refused after 4096 of 10000 bytes answered {n}, which a client takes for the end");
}

/// **A listed name is one component**: an empty name, `.` or `..`, a `/` or
/// a NUL with bytes after it is refused, whatever the server says (Linux's
/// `verify_dirent_name`).
///
/// **Canary.** `endpoint-name-canary`.
#[test]
fn a_listed_name_that_is_not_one_component_is_refused() {
    let _g = serial();
    mounted();
    for bad in [&b"a/b"[..], b"", b".", b"..", b"a\0b"] {
        *BAD_NAME.lock().unwrap() = Some(bad.to_vec());
        let mut e = vfs::DirEnt::new();
        let r = vfs::vfs_readdir(b"/ep", 0, &mut e);
        *BAD_NAME.lock().unwrap() = None;
        assert!(r.is_err(), "{:?} was listed as {:?}", String::from_utf8_lossy(bad), r.map(|_| String::from_utf8_lossy(e.name()).to_string()));
    }
    let mut e = vfs::DirEnt::new();
    assert!(vfs::vfs_readdir(b"/ep", 0, &mut e).is_ok());
}

/// **A server that restarted is asked again**: the opens the mount kept from
/// the earlier one are dropped, even where the new server has the same
/// handle in use for another file.
///
/// **Canary.** `endpoint-epoch-canary`: the cached open is kept.
#[test]
fn a_restarted_server_is_opened_again() {
    let _g = serial();
    mounted();
    LIAR.store(false, Ordering::SeqCst);
    assert_eq!(read_path("/ep/hello.txt", 64).unwrap(), b"hello from ring 3\n");
    {
        let mut s = link().0.lock().unwrap();
        s.open.clear();
        // Other clients' opens take the new server's handles, whichever the
        // mount kept from the earlier one.
        let n = s.open.capacity().max(64);
        s.open.clear();
        s.open.resize(n, Some((big(), 0)));
    }
    EPOCH.fetch_add(1, Ordering::SeqCst);
    assert_eq!(read_path("/ep/hello.txt", 64).unwrap(), b"hello from ring 3\n");
}

/// **An open through a directory capability tells the server where the
/// caller is rooted**: the components of the path that the capability's
/// directory covers, so the server can refuse a link that leads out of it.
///
/// **Canary.** `endpoint-floor-canary`: every key is rooted at the mount, and
/// both opens below say 0.
#[test]
fn an_open_beneath_a_directory_names_its_floor_to_the_server() {
    let _g = serial();
    mounted();
    let mut t = vfs::ScratchFds::new();
    FLOORS.lock().unwrap().clear();
    let mut b = [0u8; 8];
    let fd = vfs::vfs_open_at(&mut t, b"/ep/dir", b"a.txt", vfs::O_RDONLY);
    assert!(fd >= 0);
    assert!(vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 8) > 0);
    vfs::vfs_close(&mut t, fd);
    let fd = vfs::vfs_open_at(&mut t, b"/ep", b"hello.txt", vfs::O_RDONLY);
    assert!(fd >= 0);
    assert!(vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 8) > 0);
    vfs::vfs_close(&mut t, fd);
    let fd = vfs::vfs_open_at(&mut t, b"/", b"ep/dir/a.txt", vfs::O_RDONLY);
    assert!(fd >= 0);
    assert!(vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), 8) > 0);
    vfs::vfs_close(&mut t, fd);
    let seen = FLOORS.lock().unwrap().clone();
    assert!(seen.contains(&1), "an open beneath /ep/dir is rooted one component down: {seen:?}");
    assert!(seen.contains(&0), "an open beneath the mount or above it is rooted at the mount: {seen:?}");
}

/// **A server's refusal of a link that leaves the caller's directory is an
/// open that fails, with the refusal's own code from the mount**: no
/// descriptor, and nothing of the target's size. The same link opened by a
/// caller rooted at the mount is the file it names.
///
/// **Canary.** `endpoint-floor-canary`: the server is never told the floor, and
/// the first open succeeds.
#[test]
fn a_link_out_of_the_callers_directory_is_not_opened() {
    let _g = serial();
    mounted();
    let mut t = vfs::ScratchFds::new();
    assert!(vfs::vfs_open_at(&mut t, b"/ep/dir", b"link", vfs::O_RDONLY) < 0);
    let fd = vfs::vfs_open_at(&mut t, b"/ep", b"dir/link", vfs::O_RDONLY);
    assert!(fd >= 0);
    vfs::vfs_close(&mut t, fd);
}

/// **A link out of the caller's directory is refused by stat, listing and
/// statfs as it is by open**: the three tell the server the floor, and what
/// it refuses (`DENIED`) is the mount's `Denied`, not an absent file or an
/// empty listing. The same link from a caller rooted at the mount is the
/// directory it names.
///
/// **Canary.** `endpoint-floor-canary`: none of the three says it, and each
/// refusal below becomes an answer.
#[test]
fn stat_listing_and_statfs_refuse_a_link_out_of_the_callers_directory() {
    let _g = serial();
    mounted();
    let mut e = vfs::DirEnt::new();
    assert_eq!(vfs::vfs_stat_beneath(b"/ep/dir", b"/ep/dir/link").err(), Some(vfs::FsErr::Denied));
    assert!(vfs::vfs_stat_beneath(b"/ep", b"/ep/dir/link").is_ok());
    assert_eq!(vfs::vfs_readdir_beneath(b"/ep/dir", b"/ep/dir/link", 0, &mut e).err(), Some(vfs::FsErr::Denied));
    assert!(vfs::vfs_readdir_beneath(b"/ep", b"/ep/dir/link", 0, &mut e).unwrap().is_some());
    assert_eq!(vfs::vfs_statfs_beneath(b"/ep/dir", b"/ep/dir/link").err(), Some(vfs::FsErr::Denied));
    assert!(vfs::vfs_statfs_beneath(b"/ep", b"/ep/dir/link").is_ok());
}

/// **An op that changes the tree beneath a directory is refused by the
/// read-only mount before the server is asked anything**: an unlink, a
/// truncate, a rename, a mkdir and an rmdir of the link that leaves the
/// caller's directory answer `ReadOnly`, and no stat reaches the server
/// (nothing is learnt about what the link names). Rooted at the mount the
/// answer is the same: the floor is not what refuses, the volume is.
///
/// **Canary.** `mutate-floor-canary`: the stat before the refusal reaches the
/// server through a key rooted at the mount, and the unlink answers for what
/// the link names (`Io`, the server's own refusal, not `ReadOnly`).
#[test]
fn a_change_beneath_a_directory_is_refused_before_the_server_is_asked() {
    let _g = serial();
    mounted();
    FLOORS.lock().unwrap().clear();
    let before = link().0.lock().unwrap().calls;
    assert_eq!(vfs::vfs_unlink_beneath(b"/ep/dir", b"/ep/dir/link"), Err(vfs::FsErr::ReadOnly));
    assert_eq!(vfs::vfs_truncate_beneath(b"/ep/dir", b"/ep/dir/link", 0), Err(vfs::FsErr::ReadOnly));
    assert_eq!(vfs::vfs_rename_beneath(b"/ep/dir", b"/ep/dir/link", b"/ep/dir/moved"), Err(vfs::FsErr::ReadOnly));
    assert_eq!(vfs::vfs_mkdir_beneath(b"/ep/dir", b"/ep/dir/new"), Err(vfs::FsErr::ReadOnly));
    assert_eq!(vfs::vfs_rmdir_beneath(b"/ep/dir", b"/ep/dir/link"), Err(vfs::FsErr::ReadOnly));
    assert_eq!(vfs::vfs_unlink_beneath(b"/ep", b"/ep/dir/link"), Err(vfs::FsErr::ReadOnly));
    assert_eq!(link().0.lock().unwrap().calls, before, "the server was asked about a change the volume refuses");
    assert!(FLOORS.lock().unwrap().is_empty(), "a stat reached the server: {:?}", FLOORS.lock().unwrap());
}
