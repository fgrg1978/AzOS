// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

extern crate alloc;

pub mod bcache;
pub mod census;
pub mod vfs;
pub mod fat32;
pub mod tmpfs;
pub mod procfs;
pub mod crash_log;
pub mod pstore;
pub mod probe;

// `inode_leak_probe` exists under both cfgs (see `probe.rs`) — a no-op when
// `fs-inode-probe` is off, the real U09-1 proof when it is on — so a caller
// in `kernel/src/main.rs` can call it unconditionally and the feature alone
// decides whether anything happens, exactly like `vfs_mount`/`crash-log-smoke`
// below.
pub use probe::inode_leak_probe;

pub use fat32::{
    fat32_mount, fat32_lookup_root, fat32_read_chain, fat32_mounted, fat32_ls_root,
    fat32_write_file, fat32_unlink_root, fat32_unlink_path, fat32_rename,
    fat32_alloc_cluster, fat32_free_chain, fat32_sync,
    fat32_journal_idle, fat32_check_root_chain,
    fat32_locks_available, fat32_write_epoch,
    // Write-back (wave 15): the `fs-wb` task's pass, its hooks and gauges.
    fat32_writeback_tick, fat32_writeback_hooks, fat32_writeback_period_ms,
    fat32_writeback_dirty, fat32_set_writeback, fat32_writeback_now, fat32_write_file_queued,
    // File-level API (phase AS).
    fat32_mount_volume, fat32_unmount,
    fat32_open, fat32_read, fat32_write, fat32_seek, fat32_fsync, fat32_close,
    fat32_file_stat,
    fat32_opendir, fat32_mkdir,
    Volume, Fat32File, Fat32DirIter, DirEntryInfo,
    FsError, SeekFrom, open_flags,
    FAT32_MAX_OPEN_FILES,
    // The `vfs::FileSystem` backend.
    Fat32Fs,
};

pub use tmpfs::{
    tmpfs_write, tmpfs_read, tmpfs_size, tmpfs_unlink, tmpfs_ls, tmpfs_stats,
    tmpfs_truncate, tmpfs_rename,
    TmpfsError, TMPFS_MAX_FILES, TMPFS_MAX_BYTES, TMPFS_NAME_LEN,
    // The `vfs::FileSystem` backend. Not mounted by `init()`.
    TmpFs, TMPFS_FS, FS_TYPE_TMPFS,
};

pub use procfs::{
    procfs_init, procfs_register, procfs_register_tid, procfs_read, procfs_ls, procfs_count,
    ProcTidGen,
    ProcNs, PROCFS_MAX_ENTRIES,
    // The `vfs::FileSystem` backends. Not mounted by `init()`.
    ProcFs, PROCFS_FS, SYSFS_FS, FS_TYPE_PROCFS,
};

pub use vfs::{
    FdTable, FdTableN, ScratchFds, SCRATCH_FDS, FileDesc, Inode, DentryEntry,
    MAX_FILES, MAX_FDS, MAX_FILENAME, MAX_PATH,
    INODE_FILE, INODE_DIR, INODE_DEVICE,
    PERM_READ, PERM_WRITE, PERM_EXEC,
    O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND,
    SEEK_SET, SEEK_CUR, SEEK_END,
    FS_TYPE_FAT32,
    NO_IDX,
    cstr_to_bytes,
    init, inode_alloc, inode_free, inode_resize,
    dir_add_entry, dir_lookup, dir_remove_entry, dir_list, dir_entry_at,
    path_lookup, path_parent,
    vfs_mount_fs,
    // The filesystem abstraction: one interface for the three filesystems
    // this crate ships, and the opaque backing the generic inode now carries
    // in place of three FAT32-named fields.
    FileSystem, InodeKey, InodeBacking, FileStat, StatFs, DirEnt, FsErr,
    NAME_MAX, S_IFREG, S_IFDIR, S_IFCHR,
    vfs_stat, vfs_statfs, vfs_readdir, vfs_mkdir, vfs_rmdir, vfs_rename, vfs_unlink, vfs_on_mount,
    vfs_truncate, vfs_fsync,
    INODE_KEY_LEN, ZEROED_KEY, NO_BACKING, FAT32_FS,
    fd_alloc, fd_free, fd_get, fd_dup, fd_dup2,
    // Wave 15 (PI), owner rule F1: descriptor I/O without the table's lock.
    LoneFd, fd_streams, fd_lend, fd_settle, fd_adopt, fd_detach, fd_stream_transfer,
    FsyncWork, fd_fsync_begin, fd_fsync_finish,
    fd_set_owner, fd_owner, fd_count_owned, fd_release_owned,
    FD_NO_OWNER, MAX_FDS_PER_TASK,
    vfs_open, vfs_close, vfs_read, vfs_write, vfs_lseek,
    vfs_fs_lock_available, vfs_file_size,
    // Wave 14 (SPAWNCACHE): what a verified-image cache keys by.
    ContentStamp, STAMP_FS_FAT32, vfs_content_stamp,
};

pub use crash_log::{
    CRASH_LOG_PATH, CRASH_LOG_OLD_PATH, CRASH_LOG_CAP,
    RotationPlan, WriteResult, RecordOutcome,
    plan_rotation, record_entry, record_entry_with_cap,
};

pub use pstore::{
    PSTORE_MAGIC, PSTORE_VERSION, PSTORE_HEADER_LEN, PSTORE_LOG_PREFIX,
    Record as PstoreRecord, Reject as PstoreReject,
};

/// Gate-row trigger (`pstore-smoke`): take the VFS `FS` lock and panic while
/// holding it, so the panic handler finds the lock busy and skips its own
/// `/fat/CRASH.LOG` write. Only the RAM record (`kernel/src/pstore.rs`) can
/// carry this panic to the next boot. Lives here, not in `vfs.rs`, for the
/// `#[path]` reason the `crash-log-smoke` wrapper below gives.
#[cfg(feature = "pstore-smoke")]
pub fn pstore_smoke_panic_holding_fs_lock() -> ! {
    vfs::with_fs_lock_held(|| {
        panic!("pstore-smoke: deliberate panic with the VFS FS lock held");
    });
    // `with_fs_lock_held` returns only if its closure does; this one panics.
    loop { core::hint::spin_loop(); }
}

// `vfs_mount` itself is re-exported conditionally, right below — see the
// doc on the `crash-log-smoke` arm for why it is a wrapper instead of a
// third name in the block above.

/// `vfs::vfs_mount`, wrapped in an opt-in end-to-end proof for
/// `/fat/CRASH.LOG` rotation. `tools/ci_check.sh`'s crash-log gate row is
/// the only caller of this feature.
///
/// **Why the trigger lives here and nowhere else.** `vfs.rs`, `fat32.rs` and
/// `crash_log.rs` are all `#[path]`-pulled WHOLE into `tests/host/fs-tests`,
/// which runs with `unexpected_cfgs = "warn"` and declares no
/// `crash-log-smoke` cfg of its own — a `#[cfg(feature = ...)]` inside any
/// of those three files would warn there, and that host suite's own
/// "warnings are failures" rule would turn it red. `lib.rs` is not pulled,
/// so this is the one place the feature can gate anything.
///
/// **Self-detecting, so ONE kernel image serves both halves of the row's
/// two-boot proof.** If `/fat/CRASH.LOG` does not exist yet, this is "boot
/// 1": the wrapper panics on purpose, right after the real `vfs_mount`
/// returned — so `/fat` is already live and the panic handler's own write
/// actually lands, the same as any other panic after boot. If the file is
/// already there, this is "boot 2" — replaying the exact record boot 1
/// left — and the wrapper prints its tail and lets boot continue normally.
#[cfg(feature = "crash-log-smoke")]
pub fn vfs_mount(path: &[u8], fs_type: u32) -> Result<(), ()> {
    let result = vfs::vfs_mount(path, fs_type);
    if result.is_ok() && fs_type == vfs::FS_TYPE_FAT32 {
        match vfs::vfs_file_size(crash_log::CRASH_LOG_PATH) {
            None => panic!(
                "crash-log-smoke: deliberate panic after /fat mount, \
                 no /fat/CRASH.LOG yet"
            ),
            Some(size) => {
                // Read back up to COPY-chunk-sized tail via the smallest
                // buffer that still shows the message text the gate row
                // greps for; the entry itself is capped at 512 B, so one
                // read covers the whole thing.
                let mut fd_table = vfs::ScratchFds::new();
                let fd = vfs::vfs_open(&mut fd_table, crash_log::CRASH_LOG_PATH, vfs::O_RDONLY);
                let mut buf = [0u8; 512];
                let mut n = 0usize;
                if fd >= 0 {
                    let off = (size as usize).saturating_sub(buf.len());
                    if off > 0 {
                        vfs::vfs_lseek(&mut fd_table, fd, off as i64, vfs::SEEK_SET);
                    }
                    let r = vfs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), buf.len());
                    if r > 0 { n = r as usize; }
                    vfs::vfs_close(&mut fd_table, fd);
                }
                let tail = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                azos_drv_sys::kprintln!(
                    "[CRASH-SMOKE] /fat/CRASH.LOG holds {} bytes; tail: {}", size, tail
                );
            }
        }
    }
    result
}

#[cfg(not(feature = "crash-log-smoke"))]
pub use vfs::vfs_mount;
