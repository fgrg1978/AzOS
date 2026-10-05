// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `Cap<File>` (563-566): a file as a capability.
//
// What these pin, each one because getting it wrong is silent on a booted
// machine:
//
//   * the permissions an open mints follow the access mode, in both
//     directions — a read-only open that could write is the obvious failure,
//     one that could not read is the one nothing else would notice;
//   * a refused grant closes the descriptor it just opened (the shape of the
//     port leak `crates/core/ipc/src/port.rs` had);
//   * `SYS_CLOSE_TYPED` revokes before it releases, so a second close of the
//     same handle is stale rather than a close of whatever reused the number;
//   * the untyped `close` and `dup2` refuse a descriptor a capability still
//     names, and still close one nothing names;
//   * every refusal reaches the typed flight-recorder hook as a File denial.
//
// The filesystem is a stand-in that tracks which descriptors are open, so a
// test asks whether a close actually happened instead of trusting a return
// code, and it hands out the lowest free number from 3 the way `vfs_open`
// does — which is what makes a reused number, the hazard itself, observable.

use super::harness::serial;
use azos_abi::cap::CapKind;
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use azos_ipc::cap::targets::{File, Port};
use azos_ipc::cap::{Cap, CapError, CapHandle, CapPerms};
use std::sync::Mutex;

// ── The stand-in filesystem ───────────────────────────────────────────────

/// Descriptors currently open.
static OPEN: Mutex<Vec<i32>> = Mutex::new(Vec::new());
/// Every close the filesystem was asked for, refused or not.
static CLOSES: Mutex<Vec<i32>> = Mutex::new(Vec::new());

fn open_fds() -> Vec<i32> {
    OPEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn closes() -> Vec<i32> {
    CLOSES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

struct Disk;

impl crate::file_ops::FileOps for Disk {
    fn open(&self, _path: &[u8], _flags: u32) -> i64 {
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        let fd = (3..).find(|fd| !open.contains(fd)).unwrap();
        open.push(fd);
        fd as i64
    }
    fn close(&self, fd: i32) -> i64 {
        CLOSES.lock().unwrap_or_else(|e| e.into_inner()).push(fd);
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        match open.iter().position(|&f| f == fd) {
            Some(i) => { open.remove(i); 0 }
            None => -1,
        }
    }
    fn read(&self, fd: i32, dst: &mut [u8]) -> i64 {
        if !open_fds().contains(&fd) { return -1; }
        for b in dst.iter_mut() { *b = b'R'; }
        dst.len() as i64
    }
    fn write(&self, fd: i32, src: &[u8]) -> i64 {
        if !open_fds().contains(&fd) { return -1; }
        src.len() as i64
    }
    fn lseek(&self, _fd: i32, _offset: i64, _whence: i32) -> i64 { -1 }
    fn dup(&self, _fd: i32) -> i64 { -1 }
    fn dup2(&self, _oldfd: i32, newfd: i32) -> i64 {
        // Like the real one: an open `newfd` is closed first.
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = open.iter().position(|&f| f == newfd) { open.remove(i); }
        open.push(newfd);
        newfd as i64
    }
    fn mkdir(&self, _path: &[u8]) -> i64 { -1 }
    fn unlink(&self, _path: &[u8]) -> i64 { -1 }
    fn readdir(&self, _path: &[u8], _index: u32) -> Option<([u8; 64], u32, bool)> { None }
    fn release_all(&self, _tid: u32) -> usize { 0 }
    fn read_whole(&self, _path: &[u8], _dst: &mut [u8]) -> usize { 0 }
}

static DISK: Disk = Disk;

// ── The typed flight-recorder hook ────────────────────────────────────────

static SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, reason_code: u32) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn seen() -> Vec<(u8, u32)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn denial(e: CapError) -> (u8, u32) {
    (CapKind::File.denial_code(), e.code())
}

// ── The caller ────────────────────────────────────────────────────────────

/// A user VA clear of the one `file_ops_seam.rs` maps.
const SCRATCH: usize = 0x0070_0000;
/// Where a read lands and a write is taken from, inside the scratch page.
const BUF: u64 = (SCRATCH + 64) as u64;
/// The cap-store pool slot the caller is bound to.
const SLOT: usize = 51;

/// A ring-3 caller with one mapped scratch page holding a path. Dropping it
/// uninstalls the stand-in filesystem, panic or not: `file_ops_seam.rs`
/// asserts the uninstalled half, and the installed `FileOps` is a static.
struct Scene {
    mem: *mut u8,
}

impl Drop for Scene {
    fn drop(&mut self) {
        crate::file_ops::__file_ops_clear_for_tests();
    }
}

fn ring3_caller(tid: u32) -> Scene {
    // Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
    // handlers ask this crate's `shims/sched`. See `gpio_typed_lock.rs`.
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, phys, PagePerms::USER_RW).expect("map");
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);

    OPEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    CLOSES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(recorder);
    crate::file_ops::set_file_ops(&DISK);

    // Opening for writing needs a tree capability covering the file since
    // 2026-09-29 (`open_tree_gate`); the topology mints it, so the scene does.
    azos_ipc::file_cap::reset_for_tests();
    azos_ipc::file_cap::file_tree_grant_cap(tid, "/fat", CapPerms::RW).expect("tree grant");

    let path = b"/fat/F.TXT\0";
    unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), phys as *mut u8, path.len()); }
    Scene { mem: phys as *mut u8 }
}

fn open(flags: u64) -> i64 {
    super::sys_file_open_typed(SCRATCH as u64, flags)
}

fn err(e: Errno) -> i64 {
    e.to_syscall_ret()
}

fn file_cap(raw: i64) -> Cap<File> {
    Cap::from_raw(CapHandle::from_raw(raw as u32))
}

/// The descriptor a live `Cap<File>` names.
fn fd_of(tid: u32, raw: i64) -> i32 {
    azos_ipc::cap_store::with_table(tid, |t| t.get(file_cap(raw), CapPerms::NONE))
        .expect("tid does not resolve")
        .expect("not a live Cap<File>") as i32
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Each access mode mints exactly its own permission, and the capability names
/// the descriptor the filesystem actually opened.
#[test]
fn the_capability_an_open_mints_follows_the_access_mode() {
    const TID: u32 = 6401;
    let _g = serial();
    let _s = ring3_caller(TID);

    for (flags, read, write) in [(0u64, true, false), (1, false, true), (2, true, true)] {
        let raw = open(flags);
        assert!(raw >= 0, "open with access mode {flags} returned {raw}");
        let cap = file_cap(raw);
        let (r, w) = azos_ipc::cap_store::with_table(TID, |t| {
            (t.get(cap, CapPerms::READ).is_ok(), t.get(cap, CapPerms::WRITE).is_ok())
        })
        .unwrap();
        assert_eq!((r, w), (read, write), "access mode {flags} minted read={r} write={w}");
        let fd = fd_of(TID, raw);
        assert!(open_fds().contains(&fd), "the cap names fd {fd}, which the filesystem never opened");
    }

    // Mode 3 means nothing, and is refused before the filesystem is asked.
    let before = open_fds().len();
    assert_eq!(open(3), err(Errno::EINVAL));
    assert_eq!(open_fds().len(), before, "access mode 3 opened a descriptor");
}

/// Reads and writes reach the named descriptor only with their permission, and
/// a refusal is recorded as a File denial.
#[test]
fn reads_and_writes_need_their_permission_and_a_refusal_is_recorded() {
    const TID: u32 = 6402;
    let _g = serial();
    let s = ring3_caller(TID);

    let ro = open(0);
    assert!(ro >= 0);
    assert_eq!(super::sys_file_read_typed(ro as u64, BUF, 8), 8);
    let landed = unsafe { core::slice::from_raw_parts(s.mem.add(64), 8) };
    assert_eq!(landed, b"RRRRRRRR", "the read did not reach the filesystem, or did not land in the caller's buffer");
    assert_eq!(super::sys_file_write_typed(ro as u64, BUF, 8), err(Errno::ECAPPERMS));
    assert_eq!(seen(), vec![denial(CapError::MissingPerms)]);

    let wo = open(1);
    assert!(wo >= 0);
    assert_eq!(super::sys_file_write_typed(wo as u64, BUF, 4), 4);
    assert_eq!(super::sys_file_read_typed(wo as u64, BUF, 4), err(Errno::ECAPPERMS));
    assert_eq!(seen(), vec![denial(CapError::MissingPerms); 2]);
}

/// A close revokes, releases, and cannot be repeated against the file that
/// takes the freed number next.
#[test]
fn close_typed_revokes_then_releases_and_a_second_close_is_stale() {
    const TID: u32 = 6403;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = open(0);
    let fd = fd_of(TID, raw);
    assert_eq!(super::sys_close_typed(raw as u64), 0);
    assert!(!open_fds().contains(&fd), "close_typed returned 0 and fd {fd} is still open");

    // The number is free, so the next open takes it. The old handle must not
    // reach the file that now owns it.
    let again = open(0);
    assert_eq!(fd_of(TID, again), fd, "the stand-in did not reuse the number; the test proves nothing");
    assert_eq!(super::sys_file_read_typed(raw as u64, BUF, 4), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_close_typed(raw as u64), err(Errno::ECAPSTALE));
    assert!(open_fds().contains(&fd), "a second close of a revoked handle closed the file now using its number");
    assert_eq!(seen(), vec![denial(CapError::Stale); 2]);
}

/// The descriptor calls leave a descriptor a capability names alone, and
/// still close one nothing names.
#[test]
fn the_untyped_close_and_dup2_leave_a_named_descriptor_alone() {
    const TID: u32 = 6404;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = open(0);
    let fd = fd_of(TID, raw);
    let plain = super::sys_open(SCRATCH as u64, 0);
    assert!(plain >= 3, "the untyped open failed: {plain}");

    assert_eq!(super::sys_close(fd as u64), -1, "close of a capability-named descriptor was not refused");
    assert_eq!(super::sys_dup2(plain as u64, fd as u64), -1, "dup2 onto a capability-named descriptor was not refused");
    assert!(closes().is_empty(), "the filesystem was asked to close {:?}", closes());
    assert!(open_fds().contains(&fd));
    assert_eq!(super::sys_file_read_typed(raw as u64, BUF, 4), 4, "the capability stopped working");

    // Positive control: the guard is about the capability, not about closing.
    assert_eq!(super::sys_close(plain as u64), 0, "a descriptor nothing names did not close");
    assert!(!open_fds().contains(&(plain as i32)));
}

/// A full capability table refuses the grant, and the descriptor opened for it
/// does not stay behind holding one of the task's slots.
#[test]
fn a_refused_grant_closes_the_descriptor_it_just_opened() {
    const TID: u32 = 6405;
    let _g = serial();
    let _s = ring3_caller(TID);

    let mut n = 0u32;
    while azos_ipc::cap_store::grant::<Port>(TID, CapPerms::RW, 9000 + n).is_some() {
        n += 1;
        assert!(n as usize <= azos_ipc::cap::MAX_CAPS_PER_TASK, "the cap table never filled");
    }
    assert_eq!(open(0), err(Errno::EMFILE));
    assert!(open_fds().is_empty(), "the descriptor opened for an ungranted capability was left open: {:?}", open_fds());
    assert_eq!(closes().len(), 1);
}

/// A kind with no close here is refused and left valid. The caller holds it;
/// that is not a capability denial, so nothing is recorded.
#[test]
fn close_typed_refuses_a_kind_it_has_no_close_for_and_leaves_it_valid() {
    const TID: u32 = 6406;
    let _g = serial();
    let _s = ring3_caller(TID);

    let port = azos_ipc::cap_store::grant::<Port>(TID, CapPerms::RW, 77).unwrap();
    assert_eq!(super::sys_close_typed(port.raw().as_raw() as u64), err(Errno::ECAPKIND));
    assert!(
        azos_ipc::cap_store::with_table(TID, |t| t.get(port, CapPerms::READ).is_ok()).unwrap(),
        "a refused close revoked the port capability",
    );
    assert!(seen().is_empty(), "recorded {:?}", seen());
}

/// Handle 0, the forgery an uninitialised variable sends, is stale on every
/// call of the family, recorded each time, and closes nothing.
#[test]
fn a_forged_handle_is_stale_on_every_call_and_recorded() {
    const TID: u32 = 6407;
    let _g = serial();
    let _s = ring3_caller(TID);

    assert_eq!(super::sys_file_read_typed(0, BUF, 4), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_file_write_typed(0, BUF, 4), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_close_typed(0), err(Errno::ECAPSTALE));
    assert_eq!(seen(), vec![denial(CapError::Stale); 3]);
    assert!(closes().is_empty());
}
