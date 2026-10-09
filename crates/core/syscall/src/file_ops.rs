// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The seam between the syscall layer and whatever provides files.
//!
//! `crates/core/syscall` is core: it is the gate ring 3 passes through to reach the
//! motors. `crates/fs/fs` is scaffolding — FAT32, a block device, a descriptor
//! table. The file syscalls sit in the same dispatch table as `SYS_MOTOR_*`,
//! so the core crate linked the entire filesystem, and `tools/tcb_check.sh`
//! counted that as the last of three TCB violations.
//!
//! This module is the same inversion that closed the other two (`net -> tftp`
//! via `UdpTransport`, `behavior -> fs` via `LogStorage`): the trait is
//! declared here, the kernel implements it over the VFS, and the kernel — the
//! composition root, which is allowed to know about everything — installs it
//! at boot.
//!
//! ## What the trait is shaped by
//!
//! By the operations the handlers perform, not by `azos_fs`'s API. A trait
//! that mirrored the thirteen items `handlers.rs` used to import would leave
//! the filesystem's model embedded in core behind an interface, which makes
//! the checker quiet without making the partition true. In particular the
//! descriptor table itself is gone from this crate: `FdTable` appears in no
//! signature here, and the implementation is free to number descriptors and
//! lock them however it likes.
//!
//! What stays in core is the ring-3 boundary work — bouncing user pointers,
//! copying paths, capping lengths — which is what a syscall layer is for.
//!
//! ## When nothing is installed
//!
//! Every entry point returns `-1`, which is exactly what ring 3 already gets
//! for a missing file or an unmounted `/fat`, so no caller learns a new
//! failure mode. That is not a degraded mode to be papered over — it is the
//! property roadmap step 3 is after: a kernel built without a filesystem has
//! file syscalls that are genuinely absent, while `print` still works, because
//! `sys_write` to fd 1 and 2 never consults this seam.

use azos_sync::SpinLock;

/// What the syscall layer needs from a filesystem.
///
/// Descriptors are plain `i32`, allocated and interpreted entirely by the
/// implementation. Every method returns the value the syscall returns to ring
/// 3: a non-negative result on success, `-1` on failure.
pub trait FileOps: Sync {
    /// Open `path` (already copied out of user space and trimmed at its NUL).
    fn open(&self, path: &[u8], flags: u32) -> i64;

    /// Close `fd`.
    fn close(&self, fd: i32) -> i64;

    /// Read into `dst`, returning the byte count.
    fn read(&self, fd: i32, dst: &mut [u8]) -> i64;

    /// Write `src`, returning the byte count.
    fn write(&self, fd: i32, src: &[u8]) -> i64;

    /// [`FileOps::read`] on behalf of `tid`: `-1` unless `fd` is owned by
    /// `tid` ([`fd_owned_by`]), whoever is running. For a caller that acts
    /// for another task from a kernel context — the io_ring SQ poller — where
    /// the running task's identity (a kernel task, which every descriptor
    /// admits) is not the authority (OVSwrap review F1). The check and the
    /// read are one critical section in the implementation, so a descriptor
    /// closed and reopened by another task in between cannot be reached.
    ///
    /// The default refuses: an implementation that cannot tell owners apart
    /// must not be read through on someone else's behalf.
    fn read_as(&self, _tid: u32, _fd: i32, _dst: &mut [u8]) -> i64 { -1 }

    /// [`FileOps::write`] on behalf of `tid`, as [`FileOps::read_as`].
    fn write_as(&self, _tid: u32, _fd: i32, _src: &[u8]) -> i64 { -1 }

    /// Reposition `fd`, returning the new offset.
    fn lseek(&self, fd: i32, offset: i64, whence: i32) -> i64;

    /// Duplicate `fd` onto the lowest free descriptor.
    fn dup(&self, fd: i32) -> i64;

    /// Duplicate `oldfd` onto `newfd`.
    fn dup2(&self, oldfd: i32, newfd: i32) -> i64;

    /// Create a directory at `path`.
    fn mkdir(&self, path: &[u8]) -> i64;

    /// Remove the entry at `path`.
    fn unlink(&self, path: &[u8]) -> i64;

    /// Entry `index` of the directory at `path`, as
    /// `(name, size, is_dir)`. The name is NUL-padded to 64 bytes because
    /// that is the buffer `SYS_READDIR` promises its caller.
    fn readdir(&self, path: &[u8], index: u32) -> Option<([u8; 64], u32, bool)>;

    /// Close every descriptor the task `tid` still holds, and report how many
    /// there were.
    ///
    /// Called from the kernel's task-exit path. It is part of this trait, and
    /// not a function the kernel calls on itself, because the descriptor table
    /// lives on the far side of this seam and nothing on this side is allowed
    /// to know it exists.
    ///
    /// Every other kernel object table stamps an owner and is reclaimed on
    /// exit; this one was not, so a task killed by the watchdog leaked its
    /// descriptors permanently against a machine-wide budget. An
    /// implementation that cannot attribute descriptors to tasks should return
    /// 0 rather than guess.
    fn release_all(&self, tid: u32) -> usize;

    /// Read the whole file at `path` into `dst`, returning the byte count.
    ///
    /// One method rather than open/read/close because its callers,
    /// `sys_execpath` and `sys_spawn`, need the whole file or nothing: a partial read there
    /// would be exec'd as a truncated ELF and misreported as a corrupt one. A
    /// file that does not fit in `dst` must return 0, not a prefix.
    fn read_whole(&self, path: &[u8], dst: &mut [u8]) -> usize;

    /// [`read_whole`](Self::read_whole), handing each run of bytes to `sink`
    /// as it lands in `dst` (wave 14, SPAWNCACHE: the image is hashed in the
    /// same pass that reads it, while the run is still in the data cache).
    /// `sink` sees every byte of `dst[..n]` once, in order. On a refusal (0)
    /// it may have seen a prefix. The default reads, then hands over the
    /// whole.
    fn read_whole_with(&self, path: &[u8], dst: &mut [u8], sink: &mut dyn FnMut(&[u8])) -> usize {
        let n = self.read_whole(path, dst);
        if n != 0 { sink(&dst[..n]); }
        n
    }

    /// The identity of the bytes at `path` now (wave 14, SPAWNCACHE): two
    /// equal stamps mean the same bytes, so what was verified about the first
    /// holds for the second. `None` (the default) when the file system cannot
    /// promise that; nothing is then cached.
    fn content_stamp(&self, _path: &[u8]) -> Option<ContentStamp> { None }

    /// `SYS_SYNC`: make every write completed so far durable on the medium,
    /// and return `0` only when the device confirmed it; otherwise a negative
    /// errno. The default, `-1`, is what an implementation that cannot sync
    /// answers, the same as every entry point with nothing installed.
    fn sync(&self) -> i64 { -1 }

    /// Size, type and metadata of `path` (RFC-0048 P2, `SYS_STAT`), or a
    /// negative errno. The default answers `-1`, as every entry point does
    /// with nothing installed.
    fn stat(&self, _path: &[u8]) -> Result<StatOut, i64> { Err(-1) }

    /// Mount a filesystem of type `fstype` at `target` (`SYS_MOUNT`). `src`
    /// names the device; there is one block device, so today it is only
    /// passed on. `0` or a negative errno.
    fn mount(&self, _src: &[u8], _target: &[u8], _fstype: &[u8]) -> i64 { -1 }

    /// RFC-0055 (`SYS_SPAWN_EX` move list): descriptor `fd`, owned by `from`,
    /// now belongs to `to`, whose per-task share of the table it is charged
    /// to. `0`, or `-1` when `from` does not own it or `to` has no room —
    /// checked under the table's lock, so the descriptor changes owner whole
    /// or not at all. The default refuses, as every entry point does with
    /// nothing installed.
    fn set_owner(&self, _fd: i32, _from: u32, _to: u32) -> i64 { -1 }

    // ── Owner round 23: the rest of the RFC-0048 P2 surface ───────────────
    //
    // Each answers `0` or a negative errno; the default, `-1`, is what an
    // implementation that has no such operation answers, as above.

    /// `SYS_RMDIR`: remove the empty directory at `path`.
    fn rmdir(&self, _path: &[u8]) -> i64 { -1 }

    /// `SYS_RENAME`: rename `from` to `to`.
    fn rename(&self, _from: &[u8], _to: &[u8]) -> i64 { -1 }

    /// `SYS_TRUNCATE`: set the size of the file at `path` to `len`.
    fn truncate(&self, _path: &[u8], _len: u64) -> i64 { -1 }

    /// `SYS_FSYNC_TYPED`: make the writes through descriptor `fd` durable.
    /// The descriptor comes from the caller's own `Cap<File>`; the
    /// implementation still applies its owner check.
    fn fsync(&self, _fd: i32) -> i64 { -1 }

    /// io_ring `OP_FSYNC` (K1): for descriptor `fd` of task `tid`, ASK for a
    /// flush of every write queued so far and answer its ticket, without
    /// waiting on the device (the flusher task does the I/O). `Err` with a
    /// negative errno for a descriptor `tid` does not own. The default runs
    /// [`FileOps::fsync`] inline and answers ticket 0 (always done): a seam
    /// with no flusher stays correct, synchronously.
    fn fsync_request_as(&self, _tid: u32, fd: i32) -> Result<u64, i64> {
        match self.fsync(fd) { 0 => Ok(0), e => Err(e) }
    }

    /// Has flush `ticket` completed? `None` while it runs, `Some(0)` once
    /// durable, `Some(-errno)` when it failed.
    fn fsync_done(&self, _ticket: u64) -> Option<i64> { Some(0) }

    /// `SYS_STATFS`: capacity and free space of the filesystem `path` is on.
    fn statfs(&self, _path: &[u8]) -> Result<StatFsOut, i64> { Err(-1) }
}

/// What [`FileOps::statfs`] reports; `sys_statfs` lays it out as
/// `azos_abi::syscall_nr::STATFS_BYTES` bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatFsOut {
    pub fs_type:     u32,
    pub block_size:  u32,
    pub blocks:      u64,
    pub blocks_free: u64,
    pub files:       u64,
    pub files_free:  u64,
    pub name_max:    u32,
}

impl StatFsOut {
    /// The `SYS_STATFS` wire layout (see `STATFS_BYTES`'s table).
    pub fn to_bytes(&self) -> [u8; azos_abi::syscall_nr::STATFS_BYTES] {
        use azos_abi::syscall_nr::*;
        let mut b = [0u8; STATFS_BYTES];
        b[STATFS_OFF_TYPE..STATFS_OFF_TYPE + 4].copy_from_slice(&self.fs_type.to_le_bytes());
        b[STATFS_OFF_BSIZE..STATFS_OFF_BSIZE + 4].copy_from_slice(&self.block_size.to_le_bytes());
        b[STATFS_OFF_BLOCKS..STATFS_OFF_BLOCKS + 8].copy_from_slice(&self.blocks.to_le_bytes());
        b[STATFS_OFF_BFREE..STATFS_OFF_BFREE + 8].copy_from_slice(&self.blocks_free.to_le_bytes());
        b[STATFS_OFF_FILES..STATFS_OFF_FILES + 8].copy_from_slice(&self.files.to_le_bytes());
        b[STATFS_OFF_FFREE..STATFS_OFF_FFREE + 8].copy_from_slice(&self.files_free.to_le_bytes());
        b[STATFS_OFF_NAMEMAX..STATFS_OFF_NAMEMAX + 4].copy_from_slice(&self.name_max.to_le_bytes());
        b
    }
}

/// What [`FileOps::content_stamp`] answers: the backend, its write epoch at
/// the lookup (never repeats), the file's identity there and its size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContentStamp {
    pub fs:    u32,
    pub epoch: u64,
    pub id:    u64,
    pub size:  u64,
}

/// What [`FileOps::stat`] reports; `sys_stat` lays it out as
/// `azos_abi::syscall_nr::STAT_BYTES` bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatOut {
    pub size:  u64,
    pub mode:  u32,
    pub nlink: u32,
    pub uid:   u32,
    pub gid:   u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

impl StatOut {
    /// The `SYS_STAT` wire layout (see `STAT_BYTES`'s table).
    pub fn to_bytes(&self) -> [u8; azos_abi::syscall_nr::STAT_BYTES] {
        use azos_abi::syscall_nr::*;
        let mut b = [0u8; STAT_BYTES];
        b[STAT_OFF_SIZE..STAT_OFF_SIZE + 8].copy_from_slice(&self.size.to_le_bytes());
        b[STAT_OFF_MODE..STAT_OFF_MODE + 4].copy_from_slice(&self.mode.to_le_bytes());
        b[STAT_OFF_NLINK..STAT_OFF_NLINK + 4].copy_from_slice(&self.nlink.to_le_bytes());
        b[STAT_OFF_UID..STAT_OFF_UID + 4].copy_from_slice(&self.uid.to_le_bytes());
        b[STAT_OFF_GID..STAT_OFF_GID + 4].copy_from_slice(&self.gid.to_le_bytes());
        b[STAT_OFF_ATIME..STAT_OFF_ATIME + 8].copy_from_slice(&self.atime.to_le_bytes());
        b[STAT_OFF_MTIME..STAT_OFF_MTIME + 8].copy_from_slice(&self.mtime.to_le_bytes());
        b[STAT_OFF_CTIME..STAT_OFF_CTIME + 8].copy_from_slice(&self.ctime.to_le_bytes());
        b
    }
}

/// The registered implementation. `None` until [`set_file_ops`] runs, normally
/// once at boot from the kernel, next to `logger_set_storage`.
///
/// A `SpinLock`, not a `PiMutex`, for the reason `LOG_STORAGE` is one: this
/// guards a pointer copy and nothing else. The implementation's own lock — the
/// one held across a real FAT32 read — lives on the kernel side of the seam
/// and stays a `PiMutex` there.
static FILE_OPS: SpinLock<Option<&'static dyn FileOps>> = SpinLock::new(None);

/// Install the filesystem the file syscalls run through.
pub fn set_file_ops(ops: &'static dyn FileOps) {
    *FILE_OPS.lock() = Some(ops);
}

/// Put the seam back to "nothing installed". Test-only: the kernel never
/// uninstalls its filesystem, and host tests that install a stand-in must not
/// leave it behind for a test that asserts the uninstalled half.
#[cfg(test)]
pub fn __file_ops_clear_for_tests() {
    *FILE_OPS.lock() = None;
}

/// The installed implementation, or `None` before boot installs one.
///
/// The lock is released before the returned reference is used, so nothing is
/// ever held across the disk I/O behind it.
pub fn file_ops() -> Option<&'static dyn FileOps> {
    *FILE_OPS.lock()
}

/// Copy a NUL-terminated string out of a raw kernel pointer.
///
/// A local copy of what `azos_fs::cstr_to_bytes` did, kept here so the
/// crate owes the filesystem nothing at all. It is reached only from the
/// kernel-context branches of the handlers — where the pointer is a kernel
/// pointer and `copy_cstr_from_user` would be wrong — and it is as unbounded
/// as the function it replaces: a string with no NUL walks until it finds one.
/// That is preserved rather than fixed, so this change's behaviour diff stays
/// readable; it is worth revisiting separately.
///
/// # Safety
/// `ptr` must point at a NUL-terminated byte string that stays valid for the
/// lifetime of the returned slice.
pub unsafe fn cstr_to_bytes<'a>(ptr: *const u8) -> &'a [u8] {
    if ptr.is_null() { return &[]; }
    let mut len = 0usize;
    while *ptr.add(len) != 0 { len += 1; }
    core::slice::from_raw_parts(ptr, len)
}

/// May a caller use a descriptor, given who owns it?
///
/// # Why this pure predicate exists, and why it lives on this side of the seam
///
/// The check itself has to run in the kernel: `crates/core/syscall` is forbidden
/// from knowing a descriptor is an index into a table, and the owner is
/// stamped on the far side of [`FileOps`]. But the *decision* is three
/// integers and a bool, so it can live here where a host suite already
/// compiles this file — and the kernel's `KernelFileOps` calls it rather than
/// re-deriving the rule at six call sites.
///
/// # What it is for
///
/// Nothing consulted the owner. It was stamped at `open` and read at task
/// death, and in between `read`, `write`, `close`, `lseek`, `dup` and `dup2`
/// tested only that the descriptor was in range and in use. The kernel's
/// descriptor table is ONE machine-wide array and the syscall filter is
/// opt-in, so any ring-3 task could operate on any descriptor any other task
/// had open, and the table is small enough to enumerate by guessing. The
/// socket table's `socket_access_ok` closed exactly this for sockets; this is
/// the same rule on the table that never got it.
///
/// # The three answers, and why each is what it is
///
/// * **A kernel caller passes.** `current_user_pt() == 0` is how the rest of
///   this kernel recognises one, and kernel descriptors are deliberately
///   unowned so that ring 3 cannot reach them by matching.
/// * **An unowned descriptor is refused to ring 3**, not granted. `None` here
///   means out of range, unused, or opened by the kernel — every one of those
///   is a descriptor a user task has no business touching, so the absence of
///   an owner must fail closed.
/// * **A caller whose own tid is the vacant marker is refused**, because that
///   value is what an unowned slot carries: allowing it would make "no owner"
///   match "no caller".
#[inline]
pub const fn fd_access_allowed(
    owner: Option<u32>,
    caller_tid: u32,
    caller_is_kernel: bool,
    no_owner_marker: u32,
) -> bool {
    if caller_is_kernel {
        return true;
    }
    if caller_tid == no_owner_marker {
        return false;
    }
    match owner {
        Some(o) => o == caller_tid,
        None => false,
    }
}

/// May `fd`, stamped `owner`, be used on behalf of task `tid`? Only by its
/// owner: unlike [`fd_access_allowed`] there is no kernel-caller pass, because
/// the caller is acting for `tid`, not for itself, and a kernel descriptor
/// (unowned) is never reachable this way. `no_owner_marker` as `tid` is
/// refused, as there.
///
/// For [`FileOps::read_as`]/[`FileOps::write_as`] (OVSwrap review F1): a
/// `Cap<File>` carries a bare descriptor number, a move copies it into
/// another table without re-stamping the owner, and the number is reused
/// once the opener closes it or exits. From the SQ poller — a kernel task —
/// the old path asked [`fd_access_allowed`] about the POLLER, which admits
/// every descriptor, so a gifted or stale capability read whatever file now
/// held the number.
#[inline]
pub const fn fd_owned_by(owner: Option<u32>, tid: u32, no_owner_marker: u32) -> bool {
    if tid == no_owner_marker {
        return false;
    }
    match owner {
        Some(o) => o == tid,
        None => false,
    }
}
