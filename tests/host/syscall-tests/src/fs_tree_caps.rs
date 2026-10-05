// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Wave 10 (owner decision): the calls that change the tree — mkdir, unlink,
// rmdir, rename, truncate — need a `Cap<File>` with WRITE naming a directory
// tree that covers the path (`azos_ipc::file_cap`, minted only by the
// topology). Driven from ring 3 (a user page table installed, the paths in
// mapped user memory) against a recording `FileOps`: "admitted" is the call
// reaching the filesystem, whose sentinel answer (-77) comes back; "refused"
// is `-EACCES` with the filesystem never called and a `File` denial recorded.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use std::sync::Mutex;

const SLOT: usize = 58;
const SCRATCH: usize = 0x0068_0000;
/// What the recording filesystem answers: no handler produces it itself.
const FS_ANSWER: i64 = -77;
/// The `File` denial code (`CapKind::denial_code`, frozen in the recording).
const FILE_CODE: u8 = 18;

static CALLS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static SEEN: Mutex<Vec<(u8, u32, bool)>> = Mutex::new(Vec::new());

fn calls() -> Vec<String> {
    std::mem::take(&mut *CALLS.lock().unwrap_or_else(|e| e.into_inner()))
}
fn note(s: String) {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).push(s);
}
fn recorder(kind_code: u8, target: u32, need_write: bool) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, target, need_write));
}
fn seen() -> Vec<(u8, u32, bool)> {
    std::mem::take(&mut *SEEN.lock().unwrap_or_else(|e| e.into_inner()))
}

struct Tree;

fn s(p: &[u8]) -> String { String::from_utf8_lossy(p).into_owned() }

impl crate::file_ops::FileOps for Tree {
    fn open(&self, p: &[u8], f: u32) -> i64 { note(format!("open {} {:#x}", s(p), f)); FS_ANSWER }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn dup2(&self, _: i32, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, p: &[u8]) -> i64 { note(format!("mkdir {}", s(p))); FS_ANSWER }
    fn unlink(&self, p: &[u8]) -> i64 { note(format!("unlink {}", s(p))); FS_ANSWER }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; 64], u32, bool)> { unreachable!() }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
    fn rmdir(&self, p: &[u8]) -> i64 { note(format!("rmdir {}", s(p))); FS_ANSWER }
    fn rename(&self, a: &[u8], b: &[u8]) -> i64 { note(format!("rename {} {}", s(a), s(b))); FS_ANSWER }
    fn truncate(&self, p: &[u8], _: u64) -> i64 { note(format!("truncate {}", s(p))); FS_ANSWER }
}

static TREE: Tree = Tree;

struct Uninstall;
impl Drop for Uninstall {
    fn drop(&mut self) {
        crate::file_ops::__file_ops_clear_for_tests();
        azos_ipc::cap::degraded_set(false);
        azos_sched::set_current_user_pt(0);
    }
}

/// Ring 3, task `tid` bound to an empty capability table, the recording
/// filesystem installed, the tree table empty. Returns the page the paths
/// are written to (user VA `SCRATCH`).
fn ring3(tid: u32) -> *mut u8 {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_ipc::file_cap::reset_for_tests();
    set_cap_deny_recorder(recorder);
    let _ = seen();
    let _ = calls();
    crate::file_ops::set_file_ops(&TREE);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, phys, PagePerms::USER_RW).expect("map");
    phys as *mut u8
}

/// Write two NUL-terminated paths into the user page: `a` at `SCRATCH`, `b`
/// at `SCRATCH + 0x800`.
fn paths(page: *mut u8, a: &[u8], b: &[u8]) -> (u64, u64) {
    unsafe {
        core::ptr::write_bytes(page, 0, 4096);
        core::ptr::copy_nonoverlapping(a.as_ptr(), page, a.len());
        core::ptr::copy_nonoverlapping(b.as_ptr(), page.add(0x800), b.len());
    }
    (SCRATCH as u64, (SCRATCH + 0x800) as u64)
}

fn grant(tid: u32, root: &str, perms: CapPerms) {
    azos_ipc::file_cap::file_tree_grant_cap(tid, root, perms).expect("tree grant");
}

fn eacces() -> i64 { Errno::EACCES.to_syscall_ret() }

/// **No capability: all five are refused before the filesystem sees them**,
/// each refusal recorded as a `File` denial with the write bit.
///
/// **Canary.** Make `fs_tree_gate` return `Ok(())` for ring 3: every call
/// reaches the filesystem and answers -77.
#[test]
fn without_a_tree_capability_every_tree_call_is_refused_and_recorded() {
    let _g = serial();
    let _u = Uninstall;
    let page = ring3(0x7A00_0001);
    let (a, b) = paths(page, b"/fat/A.TXT", b"/fat/B.TXT");
    assert_eq!(sys_mkdir(a), eacces());
    assert_eq!(sys_unlink(a), eacces());
    assert_eq!(sys_rmdir(a), eacces());
    assert_eq!(sys_rename(a, b), eacces());
    assert_eq!(sys_truncate(a, 0), eacces());
    assert_eq!(calls(), Vec::<String>::new(), "a refused call reached the filesystem");
    assert_eq!(seen(), vec![(FILE_CODE, 0, true); 5]);
}

/// **A WRITE tree on `/fat` admits entries under it and nothing else.**
/// `/fat/A.TXT` reaches the filesystem for all five; `/fatx/A` (a byte
/// prefix, not a component prefix), `/A.TXT` and `/fat` itself (not an entry
/// of the tree) are refused for the entry calls; truncate may name the root.
///
/// **Canary.** Compare the tree with a byte `starts_with` instead of
/// component-wise in `tree_covers_path`: `/fatx/A` is admitted.
#[test]
fn a_write_tree_admits_its_entries_and_nothing_outside() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0002;
    let page = ring3(tid);
    grant(tid, "/fat", CapPerms::RW);

    let (a, b) = paths(page, b"/fat/A.TXT", b"/fat/sub/B.TXT");
    assert_eq!(sys_mkdir(a), FS_ANSWER);
    assert_eq!(sys_unlink(a), FS_ANSWER);
    assert_eq!(sys_rmdir(a), FS_ANSWER);
    assert_eq!(sys_rename(a, b), FS_ANSWER);
    assert_eq!(sys_truncate(b, 0), FS_ANSWER);
    assert_eq!(calls(), vec![
        "mkdir /fat/A.TXT", "unlink /fat/A.TXT", "rmdir /fat/A.TXT",
        "rename /fat/A.TXT /fat/sub/B.TXT", "truncate /fat/sub/B.TXT",
    ]);
    assert_eq!(seen(), vec![], "an admitted call was recorded");

    let (x, _) = paths(page, b"/fatx/A", b"");
    assert_eq!(sys_mkdir(x), eacces(), "/fatx is not under /fat");
    let (x, _) = paths(page, b"/A.TXT", b"");
    assert_eq!(sys_unlink(x), eacces());
    let (x, _) = paths(page, b"/fat", b"");
    assert_eq!(sys_rmdir(x), eacces(), "the tree's root is not an entry of it");
    assert_eq!(sys_truncate(x, 0), FS_ANSWER, "truncate may name the root itself");
    let (x, y) = paths(page, b"/fat/A.TXT", b"/nomount/X");
    assert_eq!(sys_rename(x, y), eacces(), "one uncovered end refuses the rename");
    let (x, y) = paths(page, b"/nomount/X", b"/fat/A.TXT");
    assert_eq!(sys_rename(x, y), eacces());
    assert_eq!(calls(), vec!["truncate /fat"]);
}

/// **READ is not enough, and `.`/`..` and relative paths are refused with
/// `-EINVAL`** — the check does not resolve them, so it does not accept them.
///
/// **Canary.** Drop the `path_is_plain` check in `fs_tree_gate`:
/// `/fat/../x` answers `-EACCES` (the tree check refuses it too), not
/// `-EINVAL` — the distinct errno is what the canary moves.
#[test]
fn a_read_tree_is_refused_and_dot_paths_are_invalid() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0003;
    let page = ring3(tid);
    grant(tid, "/fat", CapPerms::READ);
    let (a, _) = paths(page, b"/fat/A.TXT", b"");
    assert_eq!(sys_mkdir(a), eacces(), "a READ tree admitted a mkdir");
    grant(tid, "/", CapPerms::RW);
    let einval = Errno::EINVAL.to_syscall_ret();
    for p in [&b"/fat/../x"[..], b"/fat/./x", b"fat/x", b"/fat/sub/.."] {
        let (a, _) = paths(page, p, b"");
        assert_eq!(sys_unlink(a), einval, "{}", s(p));
    }
    assert_eq!(calls(), Vec::<String>::new());
    let (a, _) = paths(page, b"//fat//A.TXT", b"");
    assert_eq!(sys_unlink(a), FS_ANSWER, "a `/` tree covers every plain path");
}

/// **A holder is contained while degraded mode is armed** (`-EAGAIN`, not
/// recorded); a caller without the tree still gets `-EACCES`.
///
/// **Canary.** Delete the `untyped_write_contained()` check in
/// `fs_tree_gate`: the holder's mkdir reaches the filesystem (-77).
#[test]
fn a_tree_holder_is_contained_while_degraded() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0004;
    let page = ring3(tid);
    grant(tid, "/fat", CapPerms::RW);
    let (a, b) = paths(page, b"/fat/A.TXT", b"/other/B");
    azos_ipc::cap::degraded_set(true);
    let held = sys_mkdir(a);
    let not_held = sys_mkdir(b);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(held, Errno::EAGAIN.to_syscall_ret());
    assert_eq!(not_held, eacces());
    assert_eq!(seen(), vec![(FILE_CODE, 0, true)], "only the non-holder is recorded");
}

/// **Kernel tasks pass**, as they pass `cap_check`: the shell, OTA and the
/// panic writer call these with no capability table.
#[test]
fn kernel_tasks_need_no_tree_capability() {
    let _g = serial();
    let _u = Uninstall;
    let _ = ring3(0x7A00_0005);
    azos_sched::set_current_user_pt(0);
    let p = b"/anywhere/X\0".as_ptr() as u64;
    assert_eq!(sys_mkdir(p), FS_ANSWER);
    assert_eq!(sys_truncate(p, 1), FS_ANSWER);
    assert_eq!(seen(), vec![]);
}

/// **A tree capability names no descriptor.** Handed to the typed file
/// calls it is refused as the wrong kind (`-ECAPKIND`), and `close_typed`
/// leaves the grant in place instead of closing descriptor `0x4000_0000`.
///
/// **Canary.** Delete the `is_tree_resource` arm in `file_fd_for`: the read
/// reaches `FileOps::read`, whose `unreachable!()` panics.
#[test]
fn a_tree_capability_is_not_a_descriptor() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0006;
    let _ = ring3(tid);
    let cap = azos_ipc::file_cap::file_tree_grant_cap(tid, "/fat", CapPerms::RW)
        .expect("tree grant")
        .raw()
        .as_raw() as u64;
    let ecapkind = Errno::ECAPKIND.to_syscall_ret();
    assert_eq!(sys_file_read_typed(cap, SCRATCH as u64, 1), ecapkind);
    assert_eq!(sys_file_write_typed(cap, SCRATCH as u64, 1), ecapkind);
    assert_eq!(sys_fsync_typed(cap), ecapkind);
    assert_eq!(sys_close_typed(cap), ecapkind);
    assert!(azos_ipc::cap_store::with_table(tid, |t| {
        t.holds_kind_where(CapKind::File, CapPerms::WRITE, azos_ipc::file_cap::is_tree_resource)
    }).unwrap_or(false), "close_typed revoked the tree grant");
}

/// **The topology target is refused, not guessed at**: relative, `..`, too
/// long, or asking for DUP. Two spellings of one tree are one entry.
#[test]
fn tree_targets_are_validated_and_interned_once() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0007;
    let _ = ring3(tid);
    use azos_ipc::file_cap::{file_tree_grant_cap as g, tree_resource, TREE_PATH_MAX};
    assert!(g(tid, "fat", CapPerms::RW).is_none(), "relative");
    assert!(g(tid, "/fat/../etc", CapPerms::RW).is_none(), "..");
    assert!(g(tid, "/fat/./x", CapPerms::RW).is_none(), ".");
    assert!(g(tid, "/fat", CapPerms::RW_DUP).is_none(), "DUP");
    assert!(g(tid, "/fat", CapPerms::NONE).is_none(), "no permission");
    let long = format!("/{}", "x".repeat(TREE_PATH_MAX));
    assert!(g(tid, &long, CapPerms::RW).is_none(), "too long");
    assert_eq!(tree_resource(b"/fat/"), tree_resource(b"//fat"));
    assert_ne!(tree_resource(b"/fat"), tree_resource(b"/tmp"));
}

// ── `open` is a tree call when it creates, truncates or writes ──────────────
// (security survey, 2026-09-29: `vfs_open` creates on O_CREAT and truncates on
// O_TRUNC inside the open, and a write descriptor rewrites the file, so all
// three bypassed the five named calls' capability.)

const O_WRONLY: u64 = 0x1;
const O_RDWR: u64 = 0x2;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;

/// **No tree capability: a read-only open still works, every open that
/// could change a file is refused before the filesystem sees it.**
///
/// **Canary.** Drop the `open_tree_gate` call from `sys_open`: the four
/// changing opens reach the filesystem and answer -77.
#[test]
fn without_a_tree_capability_only_a_read_only_open_reaches_the_filesystem() {
    let _g = serial();
    let _u = Uninstall;
    let page = ring3(0x7A00_0101);
    let (a, _) = paths(page, b"/fat/CAPS.SIG", b"");
    assert_eq!(super::sys_open(a, 0), FS_ANSWER, "a read-only open needs no tree capability");
    assert_eq!(calls(), vec!["open /fat/CAPS.SIG 0x0".to_string()]);
    for flags in [O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_WRONLY | O_CREAT | O_TRUNC] {
        assert_eq!(super::sys_open(a, flags), eacces(), "open flags {flags:#x} was not refused");
    }
    assert_eq!(calls(), Vec::<String>::new(), "a refused open reached the filesystem");
    assert_eq!(seen(), vec![(FILE_CODE, 0, true); 5]);
}

/// **The typed open is the same call**: `SYS_FILE_OPEN_TYPED` goes through
/// `sys_open`, so a write-mode typed open without the tree is refused too.
///
/// **Canary.** Call `ops.open` directly in `sys_file_open_typed`: -77.
#[test]
fn a_typed_open_for_writing_needs_the_tree_too() {
    let _g = serial();
    let _u = Uninstall;
    let page = ring3(0x7A00_0102);
    let (a, _) = paths(page, b"/fat/MLP.RML", b"");
    assert_eq!(super::sys_file_open_typed(a, O_WRONLY | O_TRUNC), eacces());
    assert_eq!(calls(), Vec::<String>::new());
}

/// **A WRITE tree on `/fat` admits creating, truncating and writing under
/// it, and nothing outside.** `O_CREAT` asks for the entry's directory, so
/// `/fat` itself cannot be created through it; a write open of the root is
/// the file itself and is admitted, as truncate is.
///
/// **Canary.** Pass `false` for `O_CREAT` in `open_tree_gate`: the create
/// of `/fat` itself is admitted.
#[test]
fn a_write_tree_admits_changing_opens_under_it_only() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0103;
    let page = ring3(tid);
    grant(tid, "/fat", CapPerms::RW);
    let (a, x) = paths(page, b"/fat/LOG.TXT", b"/fatx/LOG.TXT");
    assert_eq!(super::sys_open(a, O_WRONLY | O_CREAT | O_TRUNC), FS_ANSWER);
    assert_eq!(super::sys_open(x, O_WRONLY), eacces(), "/fatx is not under /fat");
    let (root, _) = paths(page, b"/fat", b"");
    assert_eq!(super::sys_open(root, O_CREAT), eacces(), "O_CREAT of the tree root itself");
    let _ = calls();
    let _ = seen();
}

/// **A READ tree does not let an open write.**
#[test]
fn a_read_tree_does_not_admit_a_write_open() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0104;
    let page = ring3(tid);
    grant(tid, "/fat", CapPerms::READ);
    let (a, _) = paths(page, b"/fat/CAPS.SIG", b"");
    assert_eq!(super::sys_open(a, O_RDWR), eacces());
    assert_eq!(super::sys_open(a, 0), FS_ANSWER);
    let _ = calls();
    let _ = seen();
}
