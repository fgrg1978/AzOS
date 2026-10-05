// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_UMOUNT` and the shared `sys_stub` are constant `-1`, and what is worth
// pinning is that they answer it WITHOUT reading their arguments: the calls
// are made in kernel context, where a path is read through the raw pointer
// and a dereference of these addresses faults the test process instead of
// passing.
//
// `SYS_MOUNT` and `SYS_STAT` were in that list until RFC-0048 P2 wired them
// (this test encoded the stub behaviour and was updated with the decision).
// `mount` is now gated BEFORE it reads anything, so the no-read property
// still holds for a caller without the whole-disk capability; `stat` reads
// its path like `open` does, so its argument handling is pinned from ring 3
// below, where a wild pointer is a refused copy, not a fault.
//
// `sync` goes through the `FileOps` seam: `-1` with nothing installed, and
// otherwise exactly what the installed filesystem answers.

use super::harness::serial;
use std::sync::atomic::{AtomicU32, Ordering};

const WILD: [u64; 3] = [1, 0xDEAD_0000_0000, u64::MAX];

#[test]
fn umount_and_the_stub_answer_minus_one_without_reading_arguments() {
    let _g = serial();
    for p in WILD {
        assert_eq!(super::sys_umount(p), -1, "umount {p:#x}");
    }
    assert_eq!(super::sys_stub(), -1);
}

/// **Mount is refused to a ring-3 caller before a byte is read**, whatever
/// the pointers: the gate is the whole-disk `Cap<Disk>` WRITE, which ring 3
/// is never minted.
///
/// **Canary.** Move the `cap_check` below the three copies in `sys_mount`:
/// the wild pointers answer `-EFAULT`, not `E_PERM`.
#[test]
fn mount_is_refused_to_ring_three_before_reading_anything() {
    let _g = serial();
    ipc_task_pool::shim_bind(0x7700_0001, 57);
    azos_ipc::cap_store::reset(0x7700_0001);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(0x7700_0001);
    for p in WILD {
        assert_eq!(super::sys_mount(p, p, p), E_PERM, "mount {p:#x}");
    }
    azos_sched::set_current_user_pt(0);
}

/// **stat from ring 3 copies its path and its result through the checked
/// copies**: an unmapped path or buffer is `-EFAULT`, never a dereference.
#[test]
fn stat_from_ring_three_refuses_unmapped_pointers() {
    use azos_abi::error::Errno;
    let _g = serial();
    // A real (empty) page table: the checked copy walks it and finds nothing
    // mapped. The `0xBAD0_0000` sentinel other tests use is never walked.
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(0x7700_0002);
    for p in WILD {
        assert_eq!(super::sys_stat(p, p), Errno::EFAULT.to_syscall_ret(), "stat {p:#x}");
    }
    assert_eq!(super::sys_stat(0, 0x1000), Errno::EFAULT.to_syscall_ret());
    azos_sched::set_current_user_pt(0);
}

static SYNCS: AtomicU32 = AtomicU32::new(0);

struct Flusher;

impl crate::file_ops::FileOps for Flusher {
    fn open(&self, _: &[u8], _: u32) -> i64 { unreachable!() }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn dup2(&self, _: i32, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, _: &[u8]) -> i64 { unreachable!() }
    fn unlink(&self, _: &[u8]) -> i64 { unreachable!() }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; 64], u32, bool)> { unreachable!() }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
    /// A value no default and no stub produces: `-EIO` from errno 5.
    fn sync(&self) -> i64 {
        SYNCS.fetch_add(1, Ordering::SeqCst);
        -5
    }
}

static FLUSHER: Flusher = Flusher;

/// Uninstalls on the way out, panic or not: `file_ops_seam.rs` asserts the
/// uninstalled seam and must not inherit this one.
struct Uninstall;

impl Drop for Uninstall {
    fn drop(&mut self) {
        crate::file_ops::__file_ops_clear_for_tests();
    }
}

#[test]
fn sync_is_minus_one_uninstalled_and_the_filesystems_answer_installed() {
    let _g = serial();
    let _u = Uninstall;
    crate::file_ops::__file_ops_clear_for_tests();
    assert_eq!(super::sys_sync(), -1, "sync answered with no filesystem installed");

    SYNCS.store(0, Ordering::SeqCst);
    crate::file_ops::set_file_ops(&FLUSHER);
    assert_eq!(super::sys_sync(), -5, "sync did not return the filesystem's answer");
    assert_eq!(SYNCS.load(Ordering::SeqCst), 1, "sync did not flush exactly once");
}

struct Statter;

impl crate::file_ops::FileOps for Statter {
    fn open(&self, _: &[u8], _: u32) -> i64 { unreachable!() }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn dup2(&self, _: i32, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, _: &[u8]) -> i64 { unreachable!() }
    fn unlink(&self, _: &[u8]) -> i64 { unreachable!() }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; 64], u32, bool)> { unreachable!() }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
    fn stat(&self, path: &[u8]) -> Result<crate::file_ops::StatOut, i64> {
        if path != b"/x/y" { return Err(-2); }
        Ok(crate::file_ops::StatOut {
            size: 0x1_2345_6789, mode: 0o100640, nlink: 3, uid: 7, gid: 8,
            atime: 0xA1, mtime: 0xB2, ctime: 0xC3,
        })
    }
}

static STATTER: Statter = Statter;

/// **`SYS_STAT` writes the documented layout** (`STAT_BYTES`'s table) with
/// the path the caller named, and passes the filesystem's errno on.
///
/// **Canary.** Swap `STAT_OFF_UID` and `STAT_OFF_GID` in `azos_abi`: the
/// uid/gid assertions fail.
#[test]
fn stat_writes_the_documented_layout() {
    use azos_abi::syscall_nr::*;
    let _g = serial();
    let _u = Uninstall;
    azos_sched::set_current_user_pt(0);
    crate::file_ops::set_file_ops(&STATTER);
    let path = b"/x/y\0";
    let mut out = [0xEEu8; STAT_BYTES];
    assert_eq!(super::sys_stat(path.as_ptr() as u64, out.as_mut_ptr() as u64), 0);
    let u64_at = |o: usize| u64::from_le_bytes(out[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(out[o..o + 4].try_into().unwrap());
    assert_eq!(u64_at(0), 0x1_2345_6789, "size is the full 64 bits at offset 0");
    assert_eq!(u32_at(8), 0o100640);
    assert_eq!(u32_at(12), 3);
    assert_eq!(u32_at(16), 7, "uid");
    assert_eq!(u32_at(20), 8, "gid");
    assert_eq!((u64_at(24), u64_at(32), u64_at(40)), (0xA1, 0xB2, 0xC3));
    assert_eq!((u64_at(48), u64_at(56)), (0, 0), "reserved words are zero");
    let other = b"/nope\0";
    assert_eq!(super::sys_stat(other.as_ptr() as u64, out.as_mut_ptr() as u64), -2);
}

// ── Owner round 23: rmdir, rename, truncate, fsync, statfs ───────────────────

static CALLS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn calls() -> Vec<String> {
    std::mem::take(&mut *CALLS.lock().unwrap_or_else(|e| e.into_inner()))
}

fn note(s: String) {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).push(s);
}

/// Records what each new entry point was handed and answers a value no
/// default produces, so a handler that returned its own constant is caught.
struct Round23;

impl crate::file_ops::FileOps for Round23 {
    fn open(&self, _: &[u8], _: u32) -> i64 { unreachable!() }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn dup2(&self, _: i32, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, _: &[u8]) -> i64 { unreachable!() }
    fn unlink(&self, _: &[u8]) -> i64 { unreachable!() }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; 64], u32, bool)> { unreachable!() }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
    fn rmdir(&self, path: &[u8]) -> i64 {
        note(format!("rmdir {}", String::from_utf8_lossy(path)));
        -39
    }
    fn rename(&self, from: &[u8], to: &[u8]) -> i64 {
        note(format!("rename {} -> {}", String::from_utf8_lossy(from), String::from_utf8_lossy(to)));
        -22
    }
    fn truncate(&self, path: &[u8], len: u64) -> i64 {
        note(format!("truncate {} {:#x}", String::from_utf8_lossy(path), len));
        -38
    }
    fn fsync(&self, fd: i32) -> i64 {
        note(format!("fsync {fd}"));
        -5
    }
    fn statfs(&self, path: &[u8]) -> Result<crate::file_ops::StatFsOut, i64> {
        note(format!("statfs {}", String::from_utf8_lossy(path)));
        if path != b"/fat" { return Err(-2); }
        Ok(crate::file_ops::StatFsOut {
            fs_type: 1, block_size: 4096, blocks: 0x1_0000_0001, blocks_free: 0x2_0000_0002,
            files: 7, files_free: 6, name_max: 12,
        })
    }
}

static ROUND23: Round23 = Round23;

/// **Nothing installed: each of the five answers `-1`**, as every file call
/// does, and a null path is `-EFAULT` before the seam is consulted.
#[test]
fn the_round_23_calls_answer_minus_one_uninstalled_and_efault_for_null() {
    use azos_abi::error::Errno;
    let _g = serial();
    let _u = Uninstall;
    azos_sched::set_current_user_pt(0);
    crate::file_ops::__file_ops_clear_for_tests();
    let p = b"/fat/X\0".as_ptr() as u64;
    let mut out = [0u8; azos_abi::syscall_nr::STATFS_BYTES];
    assert_eq!(super::sys_rmdir(p), -1);
    assert_eq!(super::sys_rename(p, p), -1);
    assert_eq!(super::sys_truncate(p, 0), -1);
    assert_eq!(super::sys_statfs(p, out.as_mut_ptr() as u64, out.len() as u64), -1);
    let efault = Errno::EFAULT.to_syscall_ret();
    assert_eq!(super::sys_rmdir(0), efault);
    assert_eq!(super::sys_rename(0, p), efault);
    assert_eq!(super::sys_rename(p, 0), efault);
    assert_eq!(super::sys_truncate(0, 1), efault);
    assert_eq!(super::sys_statfs(0, out.as_mut_ptr() as u64, 48), efault);
    assert_eq!(super::sys_statfs(p, 0, 48), efault);
}

/// **The paths and the length reach the filesystem as the caller wrote
/// them**, in order and in full, and its errno comes back unchanged.
///
/// **Canary.** Pass `(to, from)` to `o.rename` in `sys_rename`: the rename
/// line reads `/b -> /a`. **Canary.** Truncate `len` to `u32` in
/// `sys_truncate`: the length reads `0x1`.
#[test]
fn the_round_23_calls_pass_their_arguments_and_the_errno_through() {
    let _g = serial();
    let _u = Uninstall;
    azos_sched::set_current_user_pt(0);
    crate::file_ops::set_file_ops(&ROUND23);
    calls();
    assert_eq!(super::sys_rmdir(b"/fat/D\0".as_ptr() as u64), -39);
    assert_eq!(super::sys_rename(b"/a\0".as_ptr() as u64, b"/b\0".as_ptr() as u64), -22);
    assert_eq!(super::sys_truncate(b"/fat/F\0".as_ptr() as u64, 0x1_0000_0001), -38);
    assert_eq!(calls(), vec![
        "rmdir /fat/D".to_string(),
        "rename /a -> /b".to_string(),
        "truncate /fat/F 0x100000001".to_string(),
    ]);
}

/// **`SYS_STATFS` writes the documented layout**, refuses a buffer shorter
/// than `STATFS_BYTES` without writing a byte (and without asking the
/// filesystem), and passes the filesystem's errno on.
///
/// **Canary.** Swap `STATFS_OFF_BLOCKS` and `STATFS_OFF_BFREE` in
/// `azos_abi`: the block assertions fail. **Canary.** Delete the length
/// check in `sys_statfs`: the short buffer answers `0`.
#[test]
fn statfs_writes_the_documented_layout_and_refuses_a_short_buffer() {
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::STATFS_BYTES;
    let _g = serial();
    let _u = Uninstall;
    azos_sched::set_current_user_pt(0);
    crate::file_ops::set_file_ops(&ROUND23);
    calls();
    let path = b"/fat\0".as_ptr() as u64;
    let mut out = [0xEEu8; STATFS_BYTES + 8];
    assert_eq!(super::sys_statfs(path, out.as_mut_ptr() as u64, (STATFS_BYTES - 1) as u64),
               Errno::EINVAL.to_syscall_ret(), "a short buffer was accepted");
    assert!(out.iter().all(|&b| b == 0xEE), "a refused call wrote to the buffer");
    assert!(calls().is_empty(), "a refused call asked the filesystem");

    assert_eq!(super::sys_statfs(path, out.as_mut_ptr() as u64, out.len() as u64), 0);
    let u64_at = |o: usize| u64::from_le_bytes(out[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(out[o..o + 4].try_into().unwrap());
    assert_eq!((u32_at(0), u32_at(4)), (1, 4096), "type and block size");
    assert_eq!(u64_at(8), 0x1_0000_0001, "blocks, all 64 bits");
    assert_eq!(u64_at(16), 0x2_0000_0002, "free blocks, all 64 bits");
    assert_eq!((u64_at(24), u64_at(32)), (7, 6), "files and free files");
    assert_eq!((u32_at(40), u32_at(44)), (12, 0), "name_max and the reserved word");
    assert!(out[STATFS_BYTES..].iter().all(|&b| b == 0xEE), "wrote past STATFS_BYTES");

    let other = b"/nope\0".as_ptr() as u64;
    assert_eq!(super::sys_statfs(other, out.as_mut_ptr() as u64, out.len() as u64), -2);
}

/// **`SYS_FSYNC_TYPED` syncs the descriptor its `Cap<File>` names**, with
/// any permission (a READ-only handle included), and refuses a forged or a
/// wrong-kind handle as every typed file call does — without reaching the
/// filesystem.
///
/// **Canary.** Resolve with `CapPerms::WRITE` in `sys_fsync_typed`: the
/// READ-only handle is refused with `-ECAPPERMS` instead of syncing fd 5.
#[test]
fn fsync_typed_syncs_the_descriptor_its_capability_names() {
    use azos_abi::cap::CapPerms;
    use azos_abi::error::Errno;
    use azos_ipc::cap::targets::File;
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7700_0023;
    ipc_task_pool::shim_bind(tid, 57);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    crate::file_ops::set_file_ops(&ROUND23);
    calls();
    let rd = azos_ipc::cap_store::grant::<File>(tid, CapPerms::READ, 5)
        .expect("grant").raw().as_raw() as u64;
    assert_eq!(super::sys_fsync_typed(rd), -5, "the filesystem's answer was not returned");
    assert_eq!(calls(), vec!["fsync 5".to_string()]);
    assert_eq!(super::sys_fsync_typed(0), Errno::ECAPSTALE.to_syscall_ret(), "the null handle");
    assert!(calls().is_empty(), "a refused handle reached the filesystem");
    azos_sched::set_current_user_pt(0);
}
