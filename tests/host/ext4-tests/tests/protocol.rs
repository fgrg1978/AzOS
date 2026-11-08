// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 server's file protocol (`userspace/services/ext4d/src/service.rs`)
//! through the generated `Dir` and `Node` clients, in process: what the
//! kernel's `EndpointFs` asks, over a real image.

#[path = "../../../../userspace/services/ext4d/src/service.rs"]
mod service;

use azos_abi::syscall_nr::{READDIR_NAME_BYTES, STATFS_BYTES, STAT_BYTES};
use azos_devif::fs::{
    read_checked, DirCall, DirClient, DirIdl, Extent, NodeCall, NodeClient, NodeIdl, IS_DIR, NOT_FOUND, READ_MAX,
    READ_ONLY,
};
use azos_devif::outcome;
use azos_ext4_tests::{big, image, Mem, Spec, EXT4};
use azos_idl::{MsgDesc, Result as IdlResult, Transport};
use service::{Host, Service, NODES};
use std::cell::RefCell;
use std::path::Path;

/// Handles the test host derives: `BASE + badge`.
const BASE: u32 = 1000;
const NAME: u64 = 0;
const OUT: u64 = 1024;
const DATA: u64 = 4096;

struct TestHost {
    region: Vec<u8>,
    revoked: Vec<u32>,
}

impl Host for TestHost {
    fn region(&mut self) -> &mut [u8] {
        &mut self.region
    }
    fn derive(&mut self, badge: u32) -> Option<u32> {
        Some(BASE + badge)
    }
    fn revoke(&mut self, handle: u32) {
        self.revoked.push(handle);
    }
}

type Svc = Service<Mem, TestHost>;

/// A call into the service as the server's handler makes it: the badge of
/// the capability the call came through, then the interface's dispatch.
struct Loop<'a>(&'a RefCell<Svc>, u32);

impl Transport for Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let req = *msg;
        let mut s = self.0.borrow_mut();
        s.badge = self.1;
        if (req.words[0] >> 32) as u32 == azos_devif::fs::DIR_ID {
            let _ = DirIdl::dispatch(&mut *s, &req, msg);
        } else {
            let _ = NodeIdl::dispatch(&mut *s, &req, msg);
        }
        Ok(())
    }
}

fn service() -> RefCell<Svc> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("protocol");
    std::fs::create_dir_all(&dir).unwrap();
    let spec = Spec { name: "proto-1k", block: 1024, inode: 256, features: EXT4, extended: "", mib: 8, htree: true };
    let vol = azos_ext4::Volume::mount(Mem(image(&dir, &spec))).unwrap();
    RefCell::new(Service::new(vol, TestHost { region: vec![0; 2 * 4096 + READ_MAX as usize], revoked: vec![] }))
}

/// Put `name` (NUL-terminated) at the region's name slot.
fn name(s: &RefCell<Svc>, n: &str) -> Extent {
    let r = &mut s.borrow_mut().host.region;
    r[..n.len()].copy_from_slice(n.as_bytes());
    r[n.len()] = 0;
    Extent { off: NAME, len: n.len() as u32 + 1 }
}

fn open(s: &RefCell<Svc>, path: &str) -> Result<u32, u32> {
    let n = name(s, path);
    let lent = outcome::served(DirClient::new(Loop(s, 0)).openat(n, 0))?;
    Ok(lent.get().expect("a served open lends a node").raw())
}

/// Read the whole file at `path` the way the kernel does: `read_checked` in
/// `READ_MAX` pieces until a read says the file ended.
fn read_file(s: &RefCell<Svc>, path: &str) -> Result<Vec<u8>, u32> {
    let h = open(s, path)?;
    let mut node = NodeClient::new(Loop(s, h - BASE));
    let mut out = Vec::new();
    loop {
        let n = read_checked(&mut node, Extent { off: DATA, len: READ_MAX })?;
        out.extend_from_slice(&s.borrow().host.region[DATA as usize..DATA as usize + n as usize]);
        if n < READ_MAX {
            return Ok(out);
        }
    }
}

#[test]
fn a_file_reads_whole_through_the_protocol() {
    let s = service();
    assert_eq!(read_file(&s, "hello.txt").unwrap(), b"hello ext4\n");
    assert_eq!(read_file(&s, "big.bin").unwrap(), big());
    assert_eq!(read_file(&s, "slow").unwrap(), b"slow target\n", "a symlink reads as what it names");
    assert_eq!(read_file(&s, "deep/a/b/c/leaf.txt").unwrap(), b"leaf\n");
    assert_eq!(read_file(&s, "empty.txt").unwrap(), b"");
}

#[test]
fn seek_moves_the_offset() {
    let s = service();
    let h = open(&s, "big.bin").unwrap();
    let mut node = NodeClient::new(Loop(&s, h - BASE));
    assert_eq!(outcome::served(node.seek(5000, 0)), Ok(5000));
    assert_eq!(outcome::served(node.seek(-1000, 1)), Ok(4000));
    let n = read_checked(&mut node, Extent { off: DATA, len: 16 }).unwrap();
    assert_eq!(&s.borrow().host.region[DATA as usize..DATA as usize + n as usize], &big()[4000..4016]);
    let end = big().len() as u64;
    assert_eq!(outcome::served(node.seek(0, 2)), Ok(end));
    assert_eq!(outcome::served(node.seek(-1, 0)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(outcome::served(node.seek(0, 9)), Err(outcome::BAD_ARGUMENT));
}

#[test]
fn stat_list_and_statfs_answer_the_records() {
    let s = service();
    let mut dir = DirClient::new(Loop(&s, 0));
    let out = Extent { off: OUT, len: STAT_BYTES as u32 };
    let n = name(&s, "big.bin");
    assert_eq!(outcome::served(dir.statat(n, out)), Ok(()));
    let r = s.borrow().host.region[OUT as usize..OUT as usize + 16].to_vec();
    assert_eq!(u64::from_le_bytes(r[..8].try_into().unwrap()), big().len() as u64);
    assert_eq!(u32::from_le_bytes(r[8..12].try_into().unwrap()) & 0o170000, 0o100000);

    let mut names = Vec::new();
    let out = Extent { off: OUT, len: READDIR_NAME_BYTES as u32 };
    for i in 0.. {
        let n = name(&s, "");
        let e = outcome::served(dir.readdir(n, i, out)).unwrap();
        if !e.present {
            break;
        }
        let r = &s.borrow().host.region[OUT as usize..OUT as usize + READDIR_NAME_BYTES];
        let len = r.iter().position(|&c| c == 0).unwrap();
        names.push((String::from_utf8(r[..len].to_vec()).unwrap(), e.is_dir, e.size));
    }
    names.sort();
    let want = ["abs", "big.bin", "deep", "dirlink", "empty.txt", "esc", "fast", "hello.txt", "loop1", "loop2", "lost+found", "many", "slow", "sparse.bin"];
    assert_eq!(names.iter().map(|n| n.0.as_str()).collect::<Vec<_>>(), want);
    let get = |n: &str| names.iter().find(|e| e.0 == n).unwrap().clone();
    assert!(get("deep").1 && get("dirlink").1, "a link to a directory lists as one");
    assert_eq!(get("fast").2, 11, "a link to a file lists its size");

    // Many entries, in order of index, each once.
    let mut count = 0;
    for i in 0.. {
        let n = name(&s, "many");
        if !outcome::served(dir.readdir(n, i, out)).unwrap().present {
            break;
        }
        count += 1;
    }
    assert_eq!(count, 300);

    let out = Extent { off: OUT, len: STATFS_BYTES as u32 };
    let n = name(&s, "");
    assert_eq!(outcome::served(dir.statfs(n, out)), Ok(()));
    let r = &s.borrow().host.region[OUT as usize..OUT as usize + 16];
    assert_eq!(u32::from_le_bytes(r[..4].try_into().unwrap()), service::STATFS_TYPE_EXT4);
    assert_eq!(u32::from_le_bytes(r[4..8].try_into().unwrap()), 1024);
}

#[test]
fn every_change_is_refused_read_only() {
    let s = service();
    let mut dir = DirClient::new(Loop(&s, 0));
    let n = name(&s, "hello.txt");
    assert_eq!(outcome::served(dir.openat(n, 0x1)).map(|_| ()), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.openat(n, 0x40)).map(|_| ()), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.mkdirat(n)), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.unlinkat(n, 0)), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.renameat(n, n)), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.truncateat(n, 0)), Err(READ_ONLY));
    let h = open(&s, "hello.txt").unwrap();
    let mut node = NodeClient::new(Loop(&s, h - BASE));
    assert_eq!(outcome::served(node.write(Extent { off: DATA, len: 1 })), Err(READ_ONLY));
    assert_eq!(outcome::served(node.fsync()), Ok(()));
}

#[test]
fn names_outside_the_directory_and_extents_outside_the_region_are_refused() {
    let s = service();
    let mut dir = DirClient::new(Loop(&s, 0));
    let out = Extent { off: OUT, len: STAT_BYTES as u32 };
    for bad in ["/hello.txt", "../hello.txt", "deep/../../hello.txt"] {
        let n = name(&s, bad);
        assert_eq!(outcome::served(dir.statat(n, out)), Err(outcome::BAD_ARGUMENT), "{bad}");
    }
    let n = name(&s, "deep/a/../a/b/c/leaf.txt");
    assert_eq!(outcome::served(dir.statat(n, out)), Ok(()), "a .. that stays beneath");
    let n = name(&s, "nope");
    assert_eq!(outcome::served(dir.statat(n, out)), Err(NOT_FOUND));
    let n = name(&s, "deep");
    assert_eq!(outcome::served(dir.openat(n, 0)).map(|_| ()), Err(IS_DIR));
    let region = s.borrow().host.region.len() as u64;
    let n = name(&s, "hello.txt");
    assert_eq!(outcome::served(dir.statat(Extent { off: region - 2, len: 8 }, out)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(outcome::served(dir.statat(n, Extent { off: region - 8, len: 64 })), Err(outcome::BAD_ARGUMENT));
    assert_eq!(outcome::served(dir.statat(n, Extent { off: u64::MAX, len: 64 })), Err(outcome::BAD_ARGUMENT));
    let h = open(&s, "hello.txt").unwrap();
    let mut node = NodeClient::new(Loop(&s, h - BASE));
    assert_eq!(outcome::served(node.read(Extent { off: region, len: 1 })), Err(outcome::BAD_ARGUMENT));
    // A node's capability is no directory, and the directory is no node.
    let mut as_dir = DirClient::new(Loop(&s, h - BASE));
    assert_eq!(outcome::served(as_dir.statat(n, out)), Err(outcome::DENIED));
    let mut as_node = NodeClient::new(Loop(&s, 0));
    assert_eq!(outcome::served(as_node.fsync()), Err(outcome::DENIED));
}

#[test]
fn an_open_past_the_slots_revokes_the_oldest() {
    let s = service();
    let first = open(&s, "hello.txt").unwrap();
    for _ in 1..NODES {
        open(&s, "fast").unwrap();
    }
    assert!(s.borrow().host.revoked.is_empty());
    let mut node = NodeClient::new(Loop(&s, first - BASE));
    assert_eq!(outcome::served(node.fsync()), Ok(()), "the oldest is touched, so another one goes");
    let again = open(&s, "hello.txt").unwrap();
    assert_eq!(s.borrow().host.revoked.len(), 1);
    assert_ne!(s.borrow().host.revoked[0], first);
    assert_eq!(read_file(&s, "hello.txt").unwrap(), b"hello ext4\n");
    let _ = again;
}
