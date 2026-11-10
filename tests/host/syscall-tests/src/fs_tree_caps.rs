// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The ops that change the tree — mkdirat, unlinkat (and its rmdir form),
// renameat, truncateat — name an entry beneath a directory handle and need a
// `Cap<File>` with WRITE naming a directory tree that covers the path the
// name joins to (`azos_ipc::file_cap`, minted only by the topology). Driven from ring 3 (a user page table installed, the paths in
// mapped user memory) against a recording `FileOps`: "admitted" is the call
// reaching the filesystem, whose sentinel answer (-77) comes back; "refused"
// is `-EACCES` with the filesystem never called and a `File` denial recorded.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms, ty};
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use std::sync::Mutex;

const SLOT: usize = 58;
const SCRATCH: usize = 0x0068_0000;
/// What the recording filesystem answers: no handler produces it itself.
const FS_ANSWER: i64 = -77;
/// The `Node` denial code (`CapKind::denial_code`): a file is a Node.
const FILE_CODE: u8 = 6;

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
    fn open_at(&self, r: &[u8], p: &[u8], f: u32) -> i64 { note(format!("open {} {} {:#x}", s(r), s(p), f)); FS_ANSWER }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, r: &[u8], p: &[u8]) -> i64 { note(format!("mkdir {} {}", s(r), s(p))); FS_ANSWER }
    fn unlink(&self, r: &[u8], p: &[u8]) -> i64 { note(format!("unlink {} {}", s(r), s(p))); FS_ANSWER }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; azos_abi::syscall_nr::READDIR_NAME_BYTES], u32, bool)> { unreachable!() }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
    fn rmdir(&self, r: &[u8], p: &[u8]) -> i64 { note(format!("rmdir {} {}", s(r), s(p))); FS_ANSWER }
    fn rename(&self, r: &[u8], a: &[u8], b: &[u8]) -> i64 { note(format!("rename {} {} {}", s(r), s(a), s(b))); FS_ANSWER }
    fn truncate(&self, r: &[u8], p: &[u8], _: u64) -> i64 { note(format!("truncate {} {}", s(r), s(p))); FS_ANSWER }
    fn stat_beneath(&self, r: &[u8], p: &[u8]) -> Result<crate::file_ops::StatOut, i64> { note(format!("stat {} {}", s(r), s(p))); Err(FS_ANSWER) }
    fn readdir_beneath(&self, r: &[u8], p: &[u8], i: u32) -> Result<Option<([u8; azos_abi::syscall_nr::READDIR_NAME_BYTES], u32, bool)>, i64> {
        note(format!("readdir {} {} {i}", s(r), s(p)));
        Err(FS_ANSWER)
    }
    fn statfs_beneath(&self, r: &[u8], p: &[u8]) -> Result<crate::file_ops::StatFsOut, i64> { note(format!("statfs {} {}", s(r), s(p))); Err(FS_ANSWER) }
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

/// The `*at` ops through the directory handle `d`.
fn mkdirat(d: u64, n: u64) -> i64 { sys_mkdirat(d, n) }
fn unlinkat(d: u64, n: u64) -> i64 { sys_unlinkat(d, n, 0) }
fn rmdirat(d: u64, n: u64) -> i64 { sys_unlinkat(d, n, azos_abi::invoke::UNLINK_DIR) }
fn renameat(d: u64, a: u64, b: u64) -> i64 { sys_renameat(d, a, b) }
fn truncateat(d: u64, n: u64) -> i64 { sys_truncateat(d, n, 0) }

/// **No write tree: all five are refused before the filesystem sees them**,
/// each refusal recorded as a `File` denial with the write bit. The names
/// are beneath a read-only root directory, which names but does not write.
///
/// **Canary.** Make `fs_tree_gate` return `Ok(())` for ring 3: every call
/// reaches the filesystem and answers -77.
#[test]
fn without_a_tree_capability_every_tree_call_is_refused_and_recorded() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0001;
    let page = ring3(tid);
    let root = dir(tid, "/", CapPerms::READ);
    let (a, b) = paths(page, b"fat/A.TXT", b"fat/B.TXT");
    assert_eq!(mkdirat(root, a), eacces());
    assert_eq!(unlinkat(root, a), eacces());
    assert_eq!(rmdirat(root, a), eacces());
    assert_eq!(renameat(root, a, b), eacces());
    assert_eq!(truncateat(root, a), eacces());
    assert_eq!(calls(), Vec::<String>::new(), "a refused call reached the filesystem");
    assert_eq!(seen(), vec![(FILE_CODE, 0, true); 5]);
}

/// **A WRITE tree on `/fat` admits entries under it and nothing else.**
/// `fat/A.TXT` reaches the filesystem for all five, as `/fat/A.TXT`;
/// `fatx/A` (a byte prefix, not a component prefix), `A.TXT` and `fat`
/// itself (not an entry of the tree) are refused for the entry calls;
/// truncate may name the root.
///
/// **Canary.** Compare the tree with a byte `starts_with` instead of
/// component-wise in `tree_covers_path`: `fatx/A` is admitted.
#[test]
fn a_write_tree_admits_its_entries_and_nothing_outside() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0002;
    let page = ring3(tid);
    let root = dir(tid, "/", CapPerms::READ);
    grant(tid, "/fat", CapPerms::RW);

    let (a, b) = paths(page, b"fat/A.TXT", b"fat/sub/B.TXT");
    assert_eq!(mkdirat(root, a), FS_ANSWER);
    assert_eq!(unlinkat(root, a), FS_ANSWER);
    assert_eq!(rmdirat(root, a), FS_ANSWER);
    assert_eq!(renameat(root, a, b), FS_ANSWER);
    assert_eq!(truncateat(root, b), FS_ANSWER);
    assert_eq!(calls(), vec![
        "mkdir / /fat/A.TXT", "unlink / /fat/A.TXT", "rmdir / /fat/A.TXT",
        "rename / /fat/A.TXT /fat/sub/B.TXT", "truncate / /fat/sub/B.TXT",
    ]);
    assert_eq!(seen(), vec![], "an admitted call was recorded");

    let (x, _) = paths(page, b"fatx/A", b"");
    assert_eq!(mkdirat(root, x), eacces(), "/fatx is not under /fat");
    let (x, _) = paths(page, b"A.TXT", b"");
    assert_eq!(unlinkat(root, x), eacces());
    let (x, _) = paths(page, b"fat", b"");
    assert_eq!(rmdirat(root, x), eacces(), "the tree's root is not an entry of it");
    assert_eq!(truncateat(root, x), FS_ANSWER, "truncate may name the root itself");
    let (x, y) = paths(page, b"fat/A.TXT", b"nomount/X");
    assert_eq!(renameat(root, x, y), eacces(), "one uncovered end refuses the rename");
    let (x, y) = paths(page, b"nomount/X", b"fat/A.TXT");
    assert_eq!(renameat(root, x, y), eacces());
    assert_eq!(calls(), vec!["truncate / /fat"]);
}

/// **The tree check and the filesystem see one spelling**: the name joined
/// beneath the directory, `//` collapsed and `.` taken out, so `tmp//a` is
/// handed to the filesystem as `/tmp/a`, the path the check judged. A `..`
/// that stays beneath the directory is resolved there: `fat/../tmp/a` is
/// `/tmp/a`, and `tmp/../fat/a` is judged as `/fat/a` (no tree).
///
/// **Canary.** In `join_beneath`, push an empty component instead of
/// skipping it: the filesystem is handed `/tmp//a`.
#[test]
fn a_tree_holder_reaches_the_filesystem_by_the_spelling_the_check_judged() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_00A1;
    let page = ring3(tid);
    let root = dir(tid, "/", CapPerms::READ);
    grant(tid, "/tmp", CapPerms::RW);

    let (a, b) = paths(page, b"tmp//a", b"./tmp///b");
    assert_eq!(mkdirat(root, a), FS_ANSWER);
    assert_eq!(unlinkat(root, a), FS_ANSWER);
    assert_eq!(renameat(root, a, b), FS_ANSWER);
    let (x, _) = paths(page, b"fat/../tmp/a", b"");
    assert_eq!(mkdirat(root, x), FS_ANSWER);
    assert_eq!(calls(), vec!["mkdir / /tmp/a", "unlink / /tmp/a", "rename / /tmp/a /tmp/b", "mkdir / /tmp/a"]);

    let (x, _) = paths(page, b"tmp/../fat/a", b"");
    assert_eq!(mkdirat(root, x), eacces(), "a `..` does not carry the /tmp tree along");
    assert_eq!(calls(), Vec::<String>::new());
}

/// **A name stays beneath its directory** (`RESOLVE_BENEATH`). Through a
/// directory on `/tmp/a`, with a WRITE tree on all of `/tmp`: a `..` that
/// climbs above the directory and an absolute name are `-EINVAL`, and the
/// filesystem is never asked, though `/tmp/b` would be covered; a `..` that
/// stays beneath is resolved there. A READ tree is not a write tree.
///
/// **Canary.** In `azos_common::path::join_beneath`, let a `..` at the
/// directory's floor climb into the root's own components (pop below
/// `floor`): `../b` is handed to the filesystem as `/tmp/b`.
#[test]
fn a_name_cannot_climb_above_its_directory() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0003;
    let page = ring3(tid);
    let d = dir(tid, "/tmp/a", CapPerms::RW);
    grant(tid, "/tmp", CapPerms::RW);
    let einval = Errno::EINVAL.to_syscall_ret();
    for p in [&b"../b"[..], b"x/../../b", b"/tmp/b", b"..", b"./../b"] {
        let (n, _) = paths(page, p, b"");
        assert_eq!(mkdirat(d, n), einval, "mkdirat {}", s(p));
        assert_eq!(unlinkat(d, n), einval, "unlinkat {}", s(p));
    }
    let (n, m) = paths(page, b"x", b"../b");
    assert_eq!(renameat(d, n, m), einval, "a rename whose target climbs out");
    assert_eq!(renameat(d, m, n), einval, "a rename whose source climbs out");
    assert_eq!(calls(), Vec::<String>::new(), "an escape reached the filesystem");
    assert_eq!(seen(), vec![], "an escape is malformed, not a denial");

    let (n, _) = paths(page, b"x/../y", b"");
    assert_eq!(mkdirat(d, n), FS_ANSWER);
    assert_eq!(calls(), vec!["mkdir /tmp/a /tmp/a/y"]);

    let r = dir(tid, "/fat", CapPerms::READ);
    let (n, _) = paths(page, b"A.TXT", b"");
    assert_eq!(mkdirat(r, n), eacces(), "a READ tree admitted a mkdir");
}

/// **A write tree's caveats hold against the op that changes the tree.** The
/// only write tree on `/tmp` carries an op mask naming `FS_OPEN` alone: a
/// creating open beneath it is admitted, mkdirat, unlinkat, renameat and
/// truncateat are refused with the mask's refusal (`-ECAPPERMS`) and never
/// reach the filesystem. An unmasked tree held beside it admits them again: every
/// covering tree is tried, a masked one does not hide another.
///
/// **Canary.** Resolve the covering tree with the held probe again in
/// `fs_tree_gate` (`holds_kind_where(ty::FILE, WRITE, ..)` instead of
/// `held_tree_for`): the masked tree admits the unlink.
#[test]
fn a_write_trees_op_mask_holds_against_the_tree_ops() {
    use super::harness::{classes, op_masked};
    use azos_abi::invoke::CLASS_FS_OPEN;
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0008;
    let page = ring3(tid);
    let root = dir(tid, "/", CapPerms::READ);
    let full = dir(tid, "/tmp", CapPerms::RW);
    op_masked(tid, full, classes(&[CLASS_FS_OPEN]));
    let gone = azos_ipc::cap_store::with_table(tid, |t| t.revoke_raw(azos_abi::cap::CapHandle::from_raw(full as u32)));
    assert_eq!(gone, Some(true), "the unmasked tree was not revoked");
    let (a, b) = paths(page, b"tmp/A", b"tmp/B");
    assert_eq!(super::sys_file_openat_typed(root, a, O_WRONLY | O_CREAT), FS_ANSWER, "the mask names FS_OPEN");
    let refused = ecapperms();
    assert_eq!(mkdirat(root, a), refused);
    assert_eq!(unlinkat(root, a), refused);
    assert_eq!(renameat(root, a, b), refused);
    assert_eq!(truncateat(root, a), refused);
    assert_eq!(calls(), vec!["open / tmp/A 0x41"], "a masked tree op reached the filesystem");

    dir(tid, "/tmp", CapPerms::RW);
    assert_eq!(unlinkat(root, a), FS_ANSWER, "an unmasked tree beside the masked one");
    assert_eq!(calls(), vec!["unlink / /tmp/A"]);
}

/// **An entry to change is never `.` or `..`.** `unlinkat(d, ".")` would
/// remove the directory the handle names, and `x/..` resolves lexically
/// whatever `x` is; both are `-EINVAL` for every op that creates, removes,
/// renames or truncates, though a write tree covers the result, and the
/// filesystem is never asked. A `..` inside the name stays legal.
///
/// **Canary.** Pass `entry: false` from `mutate_at` to `name_beneath`: the
/// `.` unlink reaches the filesystem as `rmdir /tmp/a`.
#[test]
fn a_dot_or_dot_dot_entry_is_refused_for_the_tree_ops() {
    use azos_abi::invoke::UNLINK_DIR;
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0009;
    let page = ring3(tid);
    let d = dir(tid, "/tmp/a", CapPerms::RW);
    grant(tid, "/", CapPerms::RW);
    let einval = Errno::EINVAL.to_syscall_ret();
    for p in [&b"."[..], b"..", b"x/..", b"x/.", b"./", b"x/../"] {
        let (n, ok) = paths(page, p, b"y");
        assert_eq!(sys_unlinkat(d, n, UNLINK_DIR), einval, "rmdir {}", s(p));
        assert_eq!(unlinkat(d, n), einval, "unlink {}", s(p));
        assert_eq!(mkdirat(d, n), einval, "mkdir {}", s(p));
        assert_eq!(truncateat(d, n), einval, "truncate {}", s(p));
        assert_eq!(renameat(d, n, ok), einval, "rename from {}", s(p));
        assert_eq!(renameat(d, ok, n), einval, "rename to {}", s(p));
    }
    assert_eq!(calls(), Vec::<String>::new(), "a dot entry reached the filesystem");
    let (n, _) = paths(page, b"x/../y", b"");
    assert_eq!(unlinkat(d, n), FS_ANSWER);
    assert_eq!(calls(), vec!["unlink /tmp/a /tmp/a/y"]);
}

/// **A name longer than the copy is `-ENAMETOOLONG`, not a fault**: a page of
/// readable bytes with no NUL in the first `PATH_MAX_BYTES`, for a name op and
/// an open alike; nothing reaches the filesystem.
///
/// **Canary.** Answer `-EFAULT` for every failed copy in
/// `copy_path_from_user`: the mkdirat reads -14.
#[test]
fn a_name_longer_than_the_copy_is_too_long() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_000A;
    let page = ring3(tid);
    let root = dir(tid, "/", CapPerms::RW);
    unsafe { core::ptr::write_bytes(page, b'a', 4096) };
    let toolong = Errno::ENAMETOOLONG.to_syscall_ret();
    assert_eq!(mkdirat(root, SCRATCH as u64), toolong);
    assert_eq!(super::sys_file_openat_typed(root, SCRATCH as u64, 0), toolong);
    assert_eq!(calls(), Vec::<String>::new());
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
    let root = dir(tid, "/", CapPerms::READ);
    grant(tid, "/fat", CapPerms::RW);
    let (a, b) = paths(page, b"fat/A.TXT", b"other/B");
    azos_ipc::cap::degraded_set(true);
    let held = mkdirat(root, a);
    let not_held = mkdirat(root, b);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(held, Errno::EAGAIN.to_syscall_ret());
    assert_eq!(not_held, eacces());
    assert_eq!(seen(), vec![(FILE_CODE, 0, true)], "only the non-holder is recorded");
}

/// **Kernel tasks need no write tree**, as they pass `cap_check`: the
/// directory still names where the name is (a kernel task acts beneath a
/// directory it holds, as any other).
#[test]
fn kernel_tasks_need_no_tree_capability() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0005;
    let _ = ring3(tid);
    let root = dir(tid, "/", CapPerms::READ);
    azos_sched::set_current_user_pt(0);
    let p = b"anywhere/X\0".as_ptr() as u64;
    assert_eq!(mkdirat(root, p), FS_ANSWER);
    assert_eq!(sys_truncateat(root, p, 1), FS_ANSWER);
    assert_eq!(calls(), vec!["mkdir / /anywhere/X", "truncate / /anywhere/X"]);
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
        t.holds_kind_where(ty::FILE, CapPerms::WRITE, azos_ipc::file_cap::is_tree_resource)
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
    assert!(g(tid, "/fat", CapPerms::RW_DELEGATE).is_none(), "DUP");
    assert!(g(tid, "/fat", CapPerms::NONE).is_none(), "no permission");
    let long = format!("/{}", "x".repeat(TREE_PATH_MAX));
    assert!(g(tid, &long, CapPerms::RW).is_none(), "too long");
    assert_eq!(tree_resource(b"/fat/"), tree_resource(b"//fat"));
    assert_ne!(tree_resource(b"/fat"), tree_resource(b"/tmp"));
}

// ── `open` is made beneath a directory capability (Storage L12) ─────────────
// Every open names a directory the caller holds (a tree `Cap<File>`, the
// `Cap<Dir>`) and a name relative to it. The directory's root is what the
// filesystem is handed; creating, truncating or writing needs a held tree with
// `WRITE` that covers the file (security survey: `vfs_open`
// creates on O_CREAT and truncates on O_TRUNC inside the open, and a write
// descriptor rewrites the file, so all three bypassed the five named calls'
// capability). The directory itself is that tree when it has `WRITE`; a
// read-only root directory is not, so it writes only where the row also holds
// a write tree.

const O_WRONLY: u64 = 0x1;
const O_RDWR: u64 = 0x2;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;

/// The raw handle of a tree capability, granted as the topology grants it.
fn dir(tid: u32, root: &str, perms: CapPerms) -> u64 {
    azos_ipc::file_cap::file_tree_grant_cap(tid, root, perms).expect("tree grant").raw().as_raw() as u64
}

fn ecapperms() -> i64 { Errno::ECAPPERMS.to_syscall_ret() }

/// **A READ directory opens read-only; every open that could change a file is
/// refused before the filesystem sees it.**
///
/// **Canary.** Make `open_changes_tree` answer `false` for every flag: the
/// changing opens reach the filesystem and answer -77.
#[test]
fn a_read_directory_admits_only_a_read_only_open() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0101;
    let page = ring3(tid);
    let d = dir(tid, "/fat", CapPerms::READ);
    let (a, _) = paths(page, b"CAPS.SIG", b"");
    assert_eq!(super::sys_file_openat_typed(d, a, 0), FS_ANSWER);
    assert_eq!(calls(), vec!["open /fat CAPS.SIG 0x0".to_string()]);
    for flags in [O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_WRONLY | O_CREAT | O_TRUNC] {
        assert_eq!(super::sys_file_openat_typed(d, a, flags), ecapperms(), "open flags {flags:#x} was not refused");
    }
    assert_eq!(calls(), Vec::<String>::new(), "a refused open reached the filesystem");
}

/// **A read-only root directory writes exactly where the row holds a write
/// tree.** The row holds `/` READ, `/fat` RW and `/tmp` READ: through the root
/// a changing open of `fat/X` reaches the filesystem (with the root, never the
/// tree, as the directory), the same open of `tmp/X`, `dev/X`, or a name that
/// climbs out of `fat` and back into `dev` is refused before the filesystem is
/// asked, and reads work everywhere.
///
/// **Canary.** Skip `write_tree_covers_open` in `sys_file_openat_typed`: the
/// three refused opens reach the filesystem.
#[test]
fn a_read_only_root_writes_only_beneath_a_write_tree() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0107;
    let page = ring3(tid);
    let root = dir(tid, "/", CapPerms::READ);
    dir(tid, "/fat", CapPerms::RW);
    dir(tid, "/tmp", CapPerms::READ);
    let open = |name: &[u8], flags: u64| {
        let (n, _) = paths(page, name, b"");
        super::sys_file_openat_typed(root, n, flags)
    };
    assert_eq!(open(b"fat/X.TXT", O_WRONLY | O_CREAT), FS_ANSWER);
    assert_eq!(open(b"tmp/X.TXT", O_WRONLY), ecapperms(), "/tmp is read-only");
    assert_eq!(open(b"dev/X", O_RDWR), ecapperms(), "no tree on /dev");
    assert_eq!(open(b"fat/../dev/X", O_TRUNC), ecapperms(), "a name that climbs back out");
    for name in [&b"fat/X.TXT"[..], b"tmp/X.TXT", b"dev/X", b"fat/../dev/X"] {
        assert_eq!(open(name, 0), FS_ANSWER, "a read-only open works anywhere");
    }
    assert_eq!(calls(), vec![
        "open / fat/X.TXT 0x41".to_string(),
        "open / fat/X.TXT 0x0".to_string(),
        "open / tmp/X.TXT 0x0".to_string(),
        "open / dev/X 0x0".to_string(),
        "open / fat/../dev/X 0x0".to_string(),
    ]);
}

/// **A WRITE directory admits creating, truncating and writing; the
/// filesystem is handed the capability's root and the name as given.** The
/// join that keeps the name beneath the root is the filesystem's
/// (`vfs::join_beneath`, `tests/host/fs-tests/src/capdir.rs`); what this layer
/// owns is that the root is the capability's, never the caller's.
///
/// **Canary.** Pass the caller's name as the root too (swap the arguments of
/// `open_at` in `open_beneath`): the recorded root is the name.
#[test]
fn a_write_directory_admits_changing_opens_with_its_own_root() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0102;
    let page = ring3(tid);
    let d = dir(tid, "/fat//LOGS/", CapPerms::RW);
    let (a, x) = paths(page, b"LOG.TXT", b"../ESCAPE");
    assert_eq!(super::sys_file_openat_typed(d, a, O_WRONLY | O_CREAT | O_TRUNC), FS_ANSWER);
    assert_eq!(super::sys_file_openat_typed(d, x, O_RDWR), FS_ANSWER);
    assert_eq!(calls(), vec![
        "open /fat/LOGS LOG.TXT 0x241".to_string(),
        "open /fat/LOGS ../ESCAPE 0x2".to_string(),
    ]);
}

/// **Only a directory is a directory.** No capability, a stale handle, and a
/// `Cap<File>` that names a descriptor each fail before the filesystem is
/// asked; the last is the wrong kind of object.
///
/// **Canary.** Accept any `Cap<File>` in `dir_root_for` (drop the
/// `is_tree_resource` arm): the descriptor cap answers from the filesystem.
#[test]
fn only_a_tree_capability_is_a_directory() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0103;
    let page = ring3(tid);
    let (a, _) = paths(page, b"X", b"");
    assert!(super::sys_file_openat_typed(0x1234_5678, a, 0) < 0, "forged handle");
    // A capability that names descriptor 5 (what DOMAIN_OPEN used to mint).
    let fd_cap = azos_ipc::cap_store::grant::<azos_ipc::cap::targets::File>(tid, CapPerms::READ, 5)
        .expect("grant").raw().as_raw() as u64;
    assert_eq!(super::sys_file_openat_typed(fd_cap, a, 0), Errno::ECAPKIND.to_syscall_ret());
    assert_eq!(calls(), Vec::<String>::new());
}

/// **A holder is contained while degraded mode is armed** for a changing open
/// (`-EAGAIN`); a read-only open through the same directory still works.
#[test]
fn a_writing_open_is_contained_while_degraded() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0104;
    let page = ring3(tid);
    let d = dir(tid, "/fat", CapPerms::RW);
    let (a, _) = paths(page, b"LOG.TXT", b"");
    azos_ipc::cap::degraded_set(true);
    let w = super::sys_file_openat_typed(d, a, O_WRONLY);
    let r = super::sys_file_openat_typed(d, a, 0);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(w, Errno::EAGAIN.to_syscall_ret());
    assert_eq!(r, FS_ANSWER);
}

/// **The Linux personality opens beneath the held tree that covers the path.**
/// A tree on `/fat` serves `/fat/F.TXT` as the name `F.TXT` beneath `/fat`
/// (the doubled slashes and the root's depth do not shift the name); a path no
/// held tree covers, or a tree that cannot write for a writing open, is
/// refused.
///
/// **Canary.** Cut the name by the root's byte length instead of its
/// components (`rel_below`): `//fat//F.TXT` opens the name `t//F.TXT`.
#[test]
fn the_personality_opens_beneath_the_covering_tree() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0105;
    let _ = ring3(tid);
    dir(tid, "/fat", CapPerms::RW);
    dir(tid, "/tmp", CapPerms::READ);
    assert_eq!(super::file_open_typed_kpath(b"/fat/F.TXT", O_RDWR), FS_ANSWER);
    assert_eq!(super::file_open_typed_kpath(b"//fat//SUB///F.TXT", 0), FS_ANSWER);
    assert_eq!(super::file_open_typed_kpath(b"/tmp/T.TXT", 0), FS_ANSWER);
    assert_eq!(calls(), vec![
        "open /fat F.TXT 0x2", "open /fat SUB///F.TXT 0x0", "open /tmp T.TXT 0x0",
    ]);
    assert_eq!(super::file_open_typed_kpath(b"/tmp/T.TXT", O_WRONLY), eacces(), "/tmp is READ");
    assert_eq!(super::file_open_typed_kpath(b"/fatx/F.TXT", 0), eacces(), "/fatx is not under /fat");
    assert_eq!(super::file_open_typed_kpath(b"/fat", 0), eacces(), "the root is not an entry of the tree");
    assert_eq!(super::file_open_typed_kpath(b"/etc/passwd", 0), eacces());
    assert_eq!(super::file_open_typed_kpath(b"/fat/../etc", 0), Errno::EINVAL.to_syscall_ret());
    assert_eq!(calls(), Vec::<String>::new());
}

/// **The root `Cap<Dir>` is found by a constant resource.** The tree on `/`
/// is interned first, so a task whose row grants it finds it with
/// `SYS_CAP_INFO` by type and `ROOT_DIR_RESOURCE`, however many trees were
/// interned before its row was seeded; a task whose row grants no `/` finds
/// nothing.
///
/// **Canary.** Intern `/` lazily (start the table empty): after another
/// tree, `/` lands on index 1 and the lookup finds nothing.
#[test]
fn the_root_directory_is_the_tree_on_slash() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0106;
    let page = ring3(tid);
    assert_eq!(azos_ipc::file_cap::tree_resource(b"/fat"), Some(azos_abi::invoke::ROOT_DIR_RESOURCE + 1),
        "another tree was interned first");
    let none = super::sys_cap_lookup(ty::FILE.raw() as u64, azos_abi::invoke::ROOT_DIR_RESOURCE as u64);
    assert!(none < 0, "a row with no `/` grant found a root: {none}");
    let root = dir(tid, "/", CapPerms::READ);
    let found = super::sys_cap_lookup(ty::FILE.raw() as u64, azos_abi::invoke::ROOT_DIR_RESOURCE as u64);
    assert_eq!(found as u64, root);
    let mut buf = [0u8; azos_ipc::file_cap::TREE_PATH_MAX];
    let n = azos_ipc::file_cap::tree_path(azos_abi::invoke::ROOT_DIR_RESOURCE, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"/");
    let (a, _) = paths(page, b"fat/X\0", b"");
    assert_eq!(super::sys_file_openat_typed(root, a, 0), FS_ANSWER);
    assert_eq!(calls(), vec!["open / fat/X 0x0".to_string()]);
}

/// **Stat, listing and statfs through a directory capability tell the
/// filesystem the directory they are rooted at**, as an open does, so a
/// backend that follows links can keep a link inside it.
///
/// **Canary.** Make `sys_statat`, `sys_readdirat` or `sys_statfsat` call the
/// seam's rootless `stat`, `readdir` or `statfs`: nothing is noted.
#[test]
fn stat_listing_and_statfs_name_the_directory_they_are_rooted_at() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0107;
    let page = ring3(tid);
    let d = dir(tid, "/fat/x", CapPerms::READ);
    let (a, _) = paths(page, b"f/g\0", b"");
    let out = (SCRATCH + 0x1000) as u64;
    assert_eq!(sys_statat(d, a, out), FS_ANSWER);
    assert_eq!(sys_statfsat(d, a, out, azos_abi::syscall_nr::STATFS_BYTES as u64), FS_ANSWER);
    assert_eq!(sys_readdirat(d, a, 2, out, azos_abi::syscall_nr::READDIR_NAME_BYTES as u64), Err(FS_ANSWER));
    assert_eq!(
        calls(),
        vec!["stat /fat/x /fat/x/f/g".to_string(), "statfs /fat/x /fat/x/f/g".to_string(), "readdir /fat/x /fat/x/f/g 2".to_string()]
    );
}

/// **The ops that change the tree tell the filesystem the directory they
/// are rooted at**, as a stat does: through a directory on `/fat/x`, each
/// of the five reaches the filesystem with `/fat/x` and the joined path, so
/// a backend that follows links keeps the change (and the stat before it)
/// beneath it.
///
/// **Canary.** `beneath-root-canary`: every op says `/`.
#[test]
fn the_ops_that_change_the_tree_name_the_directory_they_are_rooted_at() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0109;
    let page = ring3(tid);
    let d = dir(tid, "/fat/x", CapPerms::RW);
    let (a, b) = paths(page, b"f\0", b"g\0");
    assert_eq!(mkdirat(d, a), FS_ANSWER);
    assert_eq!(unlinkat(d, a), FS_ANSWER);
    assert_eq!(rmdirat(d, a), FS_ANSWER);
    assert_eq!(renameat(d, a, b), FS_ANSWER);
    assert_eq!(truncateat(d, b), FS_ANSWER);
    assert_eq!(calls(), vec![
        "mkdir /fat/x /fat/x/f", "unlink /fat/x /fat/x/f", "rmdir /fat/x /fat/x/f",
        "rename /fat/x /fat/x/f /fat/x/g", "truncate /fat/x /fat/x/g",
    ]);
}

/// A filesystem that implements only the rootless `stat`, `readdir` and
/// `statfs`: every `*_beneath` of it is the seam's default.
struct Plain;

impl crate::file_ops::FileOps for Plain {
    fn open_at(&self, _: &[u8], _: &[u8], _: u32) -> i64 { unreachable!() }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, _: &[u8], _: &[u8]) -> i64 { unreachable!() }
    fn unlink(&self, _: &[u8], _: &[u8]) -> i64 { unreachable!() }
    fn readdir(&self, p: &[u8], i: u32) -> Option<([u8; azos_abi::syscall_nr::READDIR_NAME_BYTES], u32, bool)> {
        note(format!("readdir {} {i}", s(p)));
        None
    }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
    fn stat(&self, p: &[u8]) -> Result<crate::file_ops::StatOut, i64> { note(format!("stat {}", s(p))); Err(FS_ANSWER) }
    fn statfs(&self, p: &[u8]) -> Result<crate::file_ops::StatFsOut, i64> { note(format!("statfs {}", s(p))); Err(FS_ANSWER) }
}

static PLAIN: Plain = Plain;

/// **A seam that has not taken the root serves only a caller rooted at `/`.**
/// Through a directory on `/fat/x`, the stat, listing and statfs of a name
/// beneath it are refused (`-EACCES`) by the seam's own defaults, and the
/// rootless methods are never reached; through the root directory, the
/// same three reach them with the joined path.
///
/// **Canary.** `beneath-default-open-canary`: the defaults drop the root,
/// and the three calls beneath `/fat/x` reach the rootless methods.
#[test]
fn a_seam_without_the_root_serves_only_a_caller_rooted_at_slash() {
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_0108;
    let page = ring3(tid);
    crate::file_ops::set_file_ops(&PLAIN);
    let sub = dir(tid, "/fat/x", CapPerms::READ);
    let root = dir(tid, "/", CapPerms::READ);
    let (a, b) = paths(page, b"f\0", b"fat/x/f\0");
    let out = (SCRATCH + 0x1000) as u64;
    assert_eq!(sys_statat(sub, a, out), eacces());
    assert_eq!(sys_statfsat(sub, a, out, azos_abi::syscall_nr::STATFS_BYTES as u64), eacces());
    assert_eq!(sys_readdirat(sub, a, 0, out, azos_abi::syscall_nr::READDIR_NAME_BYTES as u64), Err(eacces()));
    assert_eq!(calls(), Vec::<String>::new(), "a refused call reached the rootless seam");
    assert_eq!(sys_statat(root, b, out), FS_ANSWER);
    assert_eq!(sys_statfsat(root, b, out, azos_abi::syscall_nr::STATFS_BYTES as u64), FS_ANSWER);
    assert_eq!(sys_readdirat(root, b, 0, out, azos_abi::syscall_nr::READDIR_NAME_BYTES as u64), Ok(None));
    assert_eq!(calls(), vec!["stat /fat/x/f".to_string(), "statfs /fat/x/f".to_string(), "readdir /fat/x/f 0".to_string()]);
}

/// **The Linux personality stats and lists beneath the held tree that covers
/// the path**, as it opens: a tree on `/fat` serves `/fat/F.TXT` and `/fat`
/// itself (the root of a tree is stat'ed and listed, where an open of it is
/// not) with `/fat` as the root the filesystem is told; a path no held tree
/// covers is refused (`-EACCES`, recorded as a `File` denial) before the
/// filesystem sees it, and a path with a `..` is malformed.
///
/// **Canary.** `linux-path-unfloored-canary`: no tree is asked, every path
/// is rooted at `/`, and `/etc/passwd` reaches the filesystem.
#[test]
fn the_personality_stats_and_lists_beneath_the_covering_tree() {
    use azos_abi::invoke::{NODE_READDIR, NODE_STATAT};
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7A00_010A;
    let _ = ring3(tid);
    dir(tid, "/fat", CapPerms::READ);
    let root = super::KpathRoot::covering(b"/fat/F.TXT", NODE_STATAT).expect("the tree covers its entry");
    assert_eq!(root.stat(b"/fat/F.TXT"), Err(FS_ANSWER));
    let root = super::KpathRoot::covering(b"/fat", NODE_READDIR).expect("the tree covers its own root");
    assert_eq!(root.readdir(b"/fat", 3), Err(FS_ANSWER));
    assert_eq!(calls(), vec!["stat /fat /fat/F.TXT".to_string(), "readdir /fat /fat 3".to_string()]);
    assert_eq!(seen(), vec![]);
    assert_eq!(super::KpathRoot::covering(b"/etc/passwd", NODE_STATAT).err(), Some(eacces()));
    assert_eq!(super::KpathRoot::covering(b"/fatx/F.TXT", NODE_READDIR).err(), Some(eacces()), "/fatx is not under /fat");
    assert_eq!(seen(), vec![(FILE_CODE, 0, true); 2], "each refusal is recorded");
    assert_eq!(super::KpathRoot::covering(b"/fat/../etc", NODE_STATAT).err(), Some(Errno::EINVAL.to_syscall_ret()));
    assert_eq!(calls(), Vec::<String>::new(), "a refused path reached the filesystem");
}
