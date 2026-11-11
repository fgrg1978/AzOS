// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 server's file protocol (`userspace/services/ext4d/src/service.rs`)
//! through the generated `Dir` and `Node` clients, in process: what the
//! kernel's `EndpointFs` asks, over a real image.

#[path = "../../../../userspace/services/ext4d/src/service.rs"]
mod service;

use azos_abi::syscall_nr::{READDIR_NAME_BYTES, STATFS_BYTES, STAT_BYTES};
use azos_devif::fs::{
    DIR_BADGE, read_checked, DirCall, DirClient, DirIdl, Extent, NodeCall, NodeClient, NodeIdl, IS_DIR, NOT_FOUND, READ_MAX,
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
    /// The badge of each handle derived: handle `BASE + i` carries `lent[i]`.
    lent: Vec<u32>,
    /// Whether a revoke succeeds.
    revoke_ok: bool,
    incarnation: u32,
}

impl TestHost {
    fn new(incarnation: u32) -> Self {
        TestHost { region: vec![0; 2 * 4096 + READ_MAX as usize], revoked: vec![], lent: vec![], revoke_ok: true, incarnation }
    }
}

impl Host for TestHost {
    fn region(&mut self) -> &mut [u8] {
        &mut self.region
    }
    fn derive(&mut self, badge: u32) -> Option<u32> {
        self.lent.push(badge);
        Some(BASE + self.lent.len() as u32 - 1)
    }
    fn revoke(&mut self, handle: u32) -> bool {
        self.revoked.push(handle);
        self.revoke_ok
    }
    fn incarnation(&mut self) -> u32 {
        self.incarnation
    }
}

/// The badge a handle the service lent carries.
fn badge(s: &RefCell<Svc>, h: u32) -> u32 {
    s.borrow().host.lent[(h - BASE) as usize]
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

fn service_as(incarnation: u32) -> RefCell<Svc> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("protocol");
    std::fs::create_dir_all(&dir).unwrap();
    let spec = Spec { name: "proto-1k", block: 1024, inode: 256, features: EXT4, extended: "", mib: 8, htree: true };
    let vol = azos_ext4::Volume::mount(Mem(image(&dir, &spec))).unwrap();
    RefCell::new(Service::new(vol, TestHost::new(incarnation)))
}

fn service() -> RefCell<Svc> {
    service_as(1)
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
    let lent = outcome::served(DirClient::new(Loop(s, DIR_BADGE)).openat(n, 0, 0))?;
    Ok(lent.get().expect("a served open lends a node").raw())
}

/// Read the whole file at `path` the way the kernel does: `read_checked` in
/// `READ_MAX` pieces until a read says the file ended.
fn read_file(s: &RefCell<Svc>, path: &str) -> Result<Vec<u8>, u32> {
    let h = open(s, path)?;
    let mut node = NodeClient::new(Loop(s, badge(s, h)));
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
    let mut node = NodeClient::new(Loop(&s, badge(&s, h)));
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
    let mut dir = DirClient::new(Loop(&s, DIR_BADGE));
    let out = Extent { off: OUT, len: STAT_BYTES as u32 };
    let n = name(&s, "big.bin");
    assert_eq!(outcome::served(dir.statat(n, 0, out)), Ok(()));
    let r = s.borrow().host.region[OUT as usize..OUT as usize + 16].to_vec();
    assert_eq!(u64::from_le_bytes(r[..8].try_into().unwrap()), big().len() as u64);
    assert_eq!(u32::from_le_bytes(r[8..12].try_into().unwrap()) & 0o170000, 0o100000);

    let mut names = Vec::new();
    let out = Extent { off: OUT, len: READDIR_NAME_BYTES as u32 };
    for i in 0.. {
        let n = name(&s, "");
        let e = outcome::served(dir.readdir(n, 0, i, out)).unwrap();
        if !e.present {
            break;
        }
        let r = &s.borrow().host.region[OUT as usize..OUT as usize + READDIR_NAME_BYTES];
        let len = r.iter().position(|&c| c == 0).unwrap();
        names.push((String::from_utf8(r[..len].to_vec()).unwrap(), e.is_dir, e.size));
    }
    names.sort();
    let want = ["abs", "big.bin", "deep", "dirlink", "empty.txt", "esc", "fast", "grant", "hello.txt", "jail", "loop1", "loop2", "lost+found", "many", "private", "slow", "sparse.bin"];
    assert_eq!(names.iter().map(|n| n.0.as_str()).collect::<Vec<_>>(), want);
    let get = |n: &str| names.iter().find(|e| e.0 == n).unwrap().clone();
    assert!(get("deep").1 && get("dirlink").1, "a link to a directory lists as one");
    assert_eq!(get("fast").2, 11, "a link to a file lists its size");

    // Many entries, in order of index, each once.
    let mut count = 0;
    for i in 0.. {
        let n = name(&s, "many");
        if !outcome::served(dir.readdir(n, 0, i, out)).unwrap().present {
            break;
        }
        count += 1;
    }
    assert_eq!(count, 300);

    let out = Extent { off: OUT, len: STATFS_BYTES as u32 };
    let n = name(&s, "");
    assert_eq!(outcome::served(dir.statfs(n, 0, out)), Ok(()));
    let r = &s.borrow().host.region[OUT as usize..OUT as usize + 16];
    assert_eq!(u32::from_le_bytes(r[..4].try_into().unwrap()), service::STATFS_TYPE_EXT4);
    assert_eq!(u32::from_le_bytes(r[4..8].try_into().unwrap()), 1024);
}

#[test]
fn every_change_is_refused_read_only() {
    let s = service();
    let mut dir = DirClient::new(Loop(&s, DIR_BADGE));
    let n = name(&s, "hello.txt");
    assert_eq!(outcome::served(dir.openat(n, 0x1, 0)).map(|_| ()), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.openat(n, 0x40, 0)).map(|_| ()), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.mkdirat(n)), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.unlinkat(n, 0)), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.renameat(n, n)), Err(READ_ONLY));
    assert_eq!(outcome::served(dir.truncateat(n, 0)), Err(READ_ONLY));
    let h = open(&s, "hello.txt").unwrap();
    let mut node = NodeClient::new(Loop(&s, badge(&s, h)));
    assert_eq!(outcome::served(node.write(Extent { off: DATA, len: 1 })), Err(READ_ONLY));
    assert_eq!(outcome::served(node.fsync()), Ok(()));
}

#[test]
fn names_outside_the_directory_and_extents_outside_the_region_are_refused() {
    let s = service();
    let mut dir = DirClient::new(Loop(&s, DIR_BADGE));
    let out = Extent { off: OUT, len: STAT_BYTES as u32 };
    for bad in ["/hello.txt", "../hello.txt", "deep/../../hello.txt"] {
        let n = name(&s, bad);
        assert_eq!(outcome::served(dir.statat(n, 0, out)), Err(outcome::BAD_ARGUMENT), "{bad}");
    }
    let n = name(&s, "deep/a/../a/b/c/leaf.txt");
    assert_eq!(outcome::served(dir.statat(n, 0, out)), Ok(()), "a .. that stays beneath");
    let n = name(&s, "nope");
    assert_eq!(outcome::served(dir.statat(n, 0, out)), Err(NOT_FOUND));
    let n = name(&s, "deep");
    assert_eq!(outcome::served(dir.openat(n, 0, 0)).map(|_| ()), Err(IS_DIR));
    let region = s.borrow().host.region.len() as u64;
    let n = name(&s, "hello.txt");
    assert_eq!(outcome::served(dir.statat(Extent { off: region - 2, len: 8 }, 0, out)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(outcome::served(dir.statat(n, 0, Extent { off: region - 8, len: 64 })), Err(outcome::BAD_ARGUMENT));
    assert_eq!(outcome::served(dir.statat(n, 0, Extent { off: u64::MAX, len: 64 })), Err(outcome::BAD_ARGUMENT));
    let h = open(&s, "hello.txt").unwrap();
    let mut node = NodeClient::new(Loop(&s, badge(&s, h)));
    assert_eq!(outcome::served(node.read(Extent { off: region, len: 1 })), Err(outcome::BAD_ARGUMENT));
    // A node's capability is no directory, and the directory is no node.
    let mut as_dir = DirClient::new(Loop(&s, badge(&s, h)));
    assert_eq!(outcome::served(as_dir.statat(n, 0, out)), Err(outcome::DENIED));
    let mut as_node = NodeClient::new(Loop(&s, DIR_BADGE));
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
    let mut node = NodeClient::new(Loop(&s, badge(&s, first)));
    assert_eq!(outcome::served(node.fsync()), Ok(()), "the oldest is touched, so another one goes");
    let again = open(&s, "hello.txt").unwrap();
    assert_eq!(s.borrow().host.revoked.len(), 1);
    assert_ne!(s.borrow().host.revoked[0], first);
    assert_eq!(read_file(&s, "hello.txt").unwrap(), b"hello ext4\n");
    let _ = again;
}

/// **An open's capability names that open and no other, across a restart
/// of the server**: a badge an earlier server lent reaches nothing in the
/// next one, even when the next one has the slot in use for another file.
/// The two runs here have different incarnations; two with the same one
/// number their opens alike, and what stops a stale badge then is the kernel's
/// epoch (the owner of the endpoint), not this server.
///
/// **Canary.** `badge-slot-canary`: the badge is the slot, as before.
#[test]
fn a_badge_from_an_earlier_server_reaches_nothing() {
    let old = service_as(1000);
    let h = open(&old, "hello.txt").unwrap();
    let stale = badge(&old, h);
    // The server dies; the next one opens another file into the same slot.
    let new = service_as(7);
    open(&new, "big.bin").unwrap();
    let mut node = NodeClient::new(Loop(&new, stale));
    assert_eq!(outcome::served(node.read(Extent { off: DATA, len: 16 })).map(|d| d.count), Err(outcome::NO_RESOURCE));
    // Within one server, a slot used again carries another badge.
    let s = service();
    let first = open(&s, "hello.txt").unwrap();
    for _ in 0..NODES {
        open(&s, "fast").unwrap();
    }
    assert!(s.borrow().host.revoked.contains(&first));
    let mut node = NodeClient::new(Loop(&s, badge(&s, first)));
    assert_eq!(outcome::served(node.fsync()), Err(outcome::NO_RESOURCE), "the revoked badge reaches the slot's new file");
}

/// **A slot whose capability could not be revoked is never used again**: the
/// copy that was lent from it may still be out there.
#[test]
fn a_slot_whose_revoke_failed_is_not_reused() {
    let s = service();
    s.borrow_mut().host.revoke_ok = false;
    let first = open(&s, "hello.txt").unwrap();
    for _ in 1..NODES {
        open(&s, "fast").unwrap();
    }
    let n = DirClient::new(Loop(&s, DIR_BADGE)).openat(name(&s, "big.bin"), 0, 0);
    assert_eq!(outcome::served(n).map(|_| ()), Err(outcome::BUSY), "no slot can be freed");
    let mut node = NodeClient::new(Loop(&s, badge(&s, first)));
    let got = read_checked(&mut node, Extent { off: DATA, len: READ_MAX }).unwrap();
    assert_eq!(&s.borrow().host.region[DATA as usize..DATA as usize + got as usize], b"hello ext4\n");
}

/// **The directory answers only the kernel's capability** (its badge,
/// `DIR_BADGE`): another holder of the endpoint cannot drive writes into
/// the shared region.
#[test]
fn a_dir_call_without_the_kernels_badge_is_denied() {
    let s = service();
    let out = Extent { off: OUT, len: STAT_BYTES as u32 };
    let n = name(&s, "hello.txt");
    assert_eq!(outcome::served(DirClient::new(Loop(&s, 0)).statat(n, 0, out)), Err(outcome::DENIED));
    assert_eq!(outcome::served(DirClient::new(Loop(&s, DIR_BADGE)).statat(n, 0, out)), Ok(()));
}

/// **A completion that comes after its waiter gave up is dropped, not taken
/// for the next entry's**: the server's ring would otherwise answer every
/// later read with the one before it.
///
/// **Canary.** `stale-completion-canary`.
#[test]
fn a_late_completion_is_dropped() {
    use service::{completion, Completion};
    // Entry 7 timed out; its completion, then entry 8's, are in the ring.
    let ring = [(7u64, 512i32), (8, 1024)];
    let mut got = None;
    for &(tag, r) in &ring {
        match completion(8, tag, r) {
            Completion::Mine(r) => {
                got = Some(r);
                break;
            }
            Completion::Stale => continue,
            Completion::Stray => break,
        }
    }
    assert_eq!(got, Some(1024));
    assert_eq!(completion(8, 9, 0), Completion::Stray, "a tag not yet given");
}

fn open_beneath(s: &RefCell<Svc>, path: &str, floor: u32) -> Result<Vec<u8>, u32> {
    let n = name(s, path);
    let lent = outcome::served(DirClient::new(Loop(s, DIR_BADGE)).openat(n, 0, floor))?;
    let h = lent.get().expect("a served open lends a node").raw();
    let mut node = NodeClient::new(Loop(s, badge(s, h)));
    let got = read_checked(&mut node, Extent { off: DATA, len: READ_MAX })?;
    Ok(s.borrow().host.region[DATA as usize..DATA as usize + got as usize].to_vec())
}

/// **A link cannot take the caller out of the directory its authority is
/// rooted at**: `floor` components of the name are that directory, and a `..`
/// past it or an absolute target is refused (`DENIED`, EACCES), where the
/// same names from the mount's root are the files they name. A link that stays
/// inside still works, and a deeper floor shrinks what is inside.
///
/// **Canary.** `escape-canary`: the resolution may leave the directory, and the
/// refusals below turn into reads of `hello.txt`.
#[test]
fn a_link_out_of_the_callers_directory_is_refused() {
    let s = service();
    assert_eq!(open_beneath(&s, "jail/in", 1).unwrap(), b"jail data\n");
    assert_eq!(open_beneath(&s, "jail/sub/up_in", 1).unwrap(), b"jail data\n");
    assert_eq!(open_beneath(&s, "jail/data.txt", 1).unwrap(), b"jail data\n");
    for out in ["jail/out", "jail/sub/out2", "jail/abs", "jail/../hello.txt"] {
        assert_eq!(open_beneath(&s, out, 1), Err(outcome::DENIED), "{out}");
        assert_eq!(open_beneath(&s, out, 0).unwrap(), b"hello ext4\n", "{out} from the root");
    }
    assert_eq!(open_beneath(&s, "jail/sub/up_in", 2), Err(outcome::DENIED), "rooted at jail/sub, ../data.txt is outside");
    let n = name(&s, "jail/out");
    let out = Extent { off: OUT, len: STAT_BYTES as u32 };
    assert_eq!(outcome::served(DirClient::new(Loop(&s, DIR_BADGE)).statat(n, 1, out)), Err(outcome::DENIED));
    assert_eq!(outcome::served(DirClient::new(Loop(&s, DIR_BADGE)).statat(n, 0, out)), Ok(()));
}

/// **Stat, listing and statfs keep to the caller's directory as an open
/// does**: a link that leads out of it is refused (`DENIED`), and in a listing
/// of the directory itself such an entry is shown as the link it is, not as
/// the file or directory it points at outside.
///
/// **Canary.** `escape-canary`: the same names are resolved out of the
/// directory.
#[test]
fn stat_listing_and_statfs_refuse_a_link_out_of_the_callers_directory() {
    let s = service();
    let dir = || DirClient::new(Loop(&s, DIR_BADGE));
    let out = Extent { off: OUT, len: READDIR_NAME_BYTES as u32 };
    let st = Extent { off: OUT, len: STATFS_BYTES as u32 };
    let n = name(&s, "jail/outdir");
    assert_eq!(outcome::served(dir().readdir(n, 1, 0, out)).map(|_| ()), Err(outcome::DENIED));
    assert_eq!(outcome::served(dir().statfs(n, 1, st)), Err(outcome::DENIED));
    assert_eq!(outcome::served(dir().statat(n, 1, Extent { off: OUT, len: STAT_BYTES as u32 })), Err(outcome::DENIED));
    assert!(outcome::served(dir().readdir(n, 0, 0, out)).unwrap().present, "from the root it is deep/a");
    assert_eq!(outcome::served(dir().statfs(n, 0, st)), Ok(()));
    let n = name(&s, "jail/indir");
    assert!(outcome::served(dir().readdir(n, 1, 0, out)).unwrap().present);
    assert_eq!(outcome::served(dir().statfs(n, 1, st)), Ok(()));

    let list = |floor: u32| {
        let mut seen = Vec::new();
        for i in 0.. {
            let n = name(&s, "jail");
            let e = outcome::served(dir().readdir(n, floor, i, out)).unwrap();
            if !e.present {
                break;
            }
            let r = &s.borrow().host.region[OUT as usize..OUT as usize + READDIR_NAME_BYTES];
            let len = r.iter().position(|&c| c == 0).unwrap();
            seen.push((String::from_utf8(r[..len].to_vec()).unwrap(), e.is_dir, e.size));
        }
        seen
    };
    let get = |l: &[(String, bool, u32)], n: &str| l.iter().find(|e| e.0 == n).unwrap().clone();
    let rooted = list(1);
    assert!(!get(&rooted, "outdir").1 && get(&rooted, "out").2 == 12, "a link out of the directory lists as the link: {rooted:?}");
    assert!(get(&rooted, "indir").1 && get(&rooted, "in").2 == 10, "a link inside lists as its target");
    let whole = list(0);
    assert!(get(&whole, "outdir").1 && get(&whole, "out").2 == 11, "from the root the same links list as their targets");
}

/// **A link in the granted directory's own path does not move the grant**:
/// rooted at `grant`, which the image makes a link to `private`, open, stat,
/// listing and statfs are all refused, where from the root the link is the
/// directory it names.
///
/// **Canary.** `escape-canary`: the grant's components are followed through
/// links, and the refusals below become answers.
#[test]
fn a_link_in_the_granted_directorys_path_is_refused() {
    let s = service();
    assert_eq!(open_beneath(&s, "grant/secret.txt", 1), Err(outcome::DENIED));
    assert_eq!(open_beneath(&s, "grant/secret.txt", 0).unwrap(), b"private\n");
    let dir = || DirClient::new(Loop(&s, DIR_BADGE));
    let n = name(&s, "grant/secret.txt");
    assert_eq!(outcome::served(dir().statat(n, 1, Extent { off: OUT, len: STAT_BYTES as u32 })), Err(outcome::DENIED));
    let n = name(&s, "grant");
    assert_eq!(outcome::served(dir().readdir(n, 1, 0, Extent { off: OUT, len: READDIR_NAME_BYTES as u32 })).map(|_| ()), Err(outcome::DENIED));
    assert_eq!(outcome::served(dir().statfs(n, 1, Extent { off: OUT, len: STATFS_BYTES as u32 })), Err(outcome::DENIED));
    assert!(outcome::served(dir().readdir(n, 0, 0, Extent { off: OUT, len: READDIR_NAME_BYTES as u32 })).unwrap().present);
}

/// **Listing a directory is linear:** one entry per call, each answered from
/// the cursor and its own inode, not by another scan of the directory.
///
/// **Canary.** `seen-resolve-canary`: every entry is resolved by path.
#[test]
fn listing_a_directory_costs_steps_linear_in_its_entries() {
    let s = service();
    let mut dir = DirClient::new(Loop(&s, DIR_BADGE));
    let out = Extent { off: OUT, len: READDIR_NAME_BYTES as u32 };
    let before = s.borrow().vol.work();
    let mut count = 0u64;
    for i in 0.. {
        let n = name(&s, "many");
        if !outcome::served(dir.readdir(n, 0, i, out)).unwrap().present {
            break;
        }
        count += 1;
    }
    assert_eq!(count, 300);
    let steps = s.borrow().vol.work() - before;
    assert!(steps <= 20 * (count + 1), "{steps} directory steps for {count} entries");
}
