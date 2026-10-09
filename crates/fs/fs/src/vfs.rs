// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VFS — Virtual Filesystem
//!
//! Direct port of kernel/fs/fs.c + kernel/include/fs.h.
//! Implements a simple in-memory ramfs with VFS abstraction.
//! Inode data and directory entries are heap-allocated; the inode pool is a
//! fixed static array protected by a global spinlock.

use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;
use azos_sync::SpinLock;
pub use azos_limits::MAX_FDS_PER_PROC as MAX_FDS;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Kconfig `VFS_MAX_FILES` (default 128).
pub const MAX_FILES:    usize = azos_limits::VFS_MAX_FILES;
/// Longest name a mounted filesystem's entry can carry through the trait
/// ([`DirEnt`], the path given to `key_for`/`mkdir`/`rename`), in bytes:
/// 255, ext4's `EXT4_NAME_LEN` and POSIX's usual `NAME_MAX` (RFC-0048 P2).
pub const NAME_MAX:     usize = 255;
/// A RAMFS directory entry's name buffer, NUL included: names up to 63
/// bytes. Deliberately not `NAME_MAX + 1`: the ramfs is what `SYS_READDIR`
/// lists, and that ABI hands out exactly `READDIR_NAME_BYTES` (64) bytes
/// and refuses rather than truncates; a longer ramfs name would be a file
/// the listing could not name. It would also quadruple every dentry on the
/// kernel heap for names the kernel's own directories never use.
pub const MAX_FILENAME: usize = 64;
/// Longest path, NUL included. 512 so that a `NAME_MAX` name still fits
/// under a mount point and a few directories (was 256, which a single
/// 255-byte name under `/fat/` already overflowed).
pub const MAX_PATH:     usize = 512;
/// Kconfig `VFS_MAX_MOUNTS` (default 4).
pub const MAX_MOUNTS:   usize = azos_limits::VFS_MAX_MOUNTS;

/// Largest FAT32 file the whole-file proxy path will load into a kernel inode.
///
/// `try_fat32_open` reads the entire file into the kernel heap so the VFS can
/// serve it as an ordinary inode. That makes the on-disk size field an
/// allocation request from a volume anyone with USB access can write, so it
/// needs a ceiling. 8 MiB comfortably covers every image the tree ships (the
/// largest, `captest.elf`, is 27 KiB, and `POLICY.GGF` is read through a 4 KiB
/// buffer).
///
/// **Not "far below the heap" — the opposite.** `config/Kconfig.limits`'
/// `KERNEL_HEAP_SIZE` is 32 KiB on the default profile (512 KiB on the
/// largest documented one); this ceiling is 8 MiB either way, 16×-256×
/// LARGER than the heap it allocates from. The allocation simply fails
/// (`alloc_raw` returns null, `try_backend_open`/`inode_resize` propagate
/// `Err`) long before 8 MiB is reached — this constant bounds what a
/// crafted directory entry can ASK for, not what the heap can grant. Both
/// still matter: without this ceiling, a ~4 GiB claimed size (the only
/// larger cap that exists, `u32::MAX`) is the request the allocator sees;
/// with it, the request is at most 8 MiB, which fails faster and leaves a
/// clearer error than a multi-gigabyte one would.
///
/// This is a limit of the PROXY, not of the filesystem: `fat32_read` streams
/// with its own clamp and is not bounded by this.
pub const MAX_FAT32_PROXY_BYTES: usize = 8 * 1024 * 1024;

pub const INODE_FILE:   u8 = 1;
pub const INODE_DIR:    u8 = 2;
pub const INODE_DEVICE: u8 = 3;

pub const PERM_READ:  u32 = 0x4;
pub const PERM_WRITE: u32 = 0x2;
pub const PERM_EXEC:  u32 = 0x1;

pub const O_RDONLY: u32 = 0x0;
pub const O_WRONLY: u32 = 0x1;
pub const O_RDWR:   u32 = 0x2;
pub const O_CREAT:  u32 = 0x40;
pub const O_TRUNC:  u32 = 0x200;
pub const O_APPEND: u32 = 0x400;

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub const FS_TYPE_RAMFS: u32 = 0;
pub const FS_TYPE_FAT32: u32 = 1;

/// Null sentinel for inode indices (equivalent to C's NULL pointer).
pub const NO_IDX: u32 = u32::MAX;

// ─── The filesystem abstraction ───────────────────────────────────────────────
//
// `crates/core/sched` puts five policy backends behind one `Policy`. This crate had
// three filesystems — FAT32, tmpfs, procfs — behind nothing at all, and the
// generic inode carried three fields named after one of them
// (`fat32_backed`, `fat32_dirty`, `fat32_name`). The VFS therefore could not
// be told about a filesystem; it could only be told about FAT32.
//
// [`FileSystem`] is the interface those three already share **in the code**,
// not the one a filesystem is supposed to have: name a file, ask its size,
// read it whole, write it whole, remove it, enumerate, flush, mount. Nothing
// here mentions clusters, sectors, generators or the heap.
//
// Per RFC-0040, the operations are named by what they do, not by where they
// run. A backend that answered these eight calls over IPC instead of over a
// block device would be a different value passed to [`vfs_mount_fs`] — a
// configuration change — and no code in this file would move. This commit does
// not do that; it only stops the code from making it impossible.

/// Bytes of opaque, backend-defined identity the generic inode carries for a
/// file that lives on a mounted filesystem.
///
/// The VFS never looks inside: it is produced by [`FileSystem::key_for`] and
/// handed back to `stat` / `write_all` / `unlink` unchanged. 64 bytes is
/// tmpfs's `TMPFS_NAME_LEN`, the longest name any backend compiled into this
/// crate stores (owner decision, wave 10; was 11, FAT32's 8.3 name, which
/// made every tmpfs name longer than 11 bytes unreachable through a mount).
/// FAT32 still uses the first 11 bytes and checks that they fit at compile
/// time (the `const _` in `fat32.rs`); procfs caps its keys at what its own
/// path buffer holds (`ProcFs::key_for`).
pub const INODE_KEY_LEN: usize = 64;

/// A backend's private name for a file, carried by the generic inode.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct InodeKey {
    pub bytes: [u8; INODE_KEY_LEN],
}

/// [`FileSystem::content_stamp`]: which backend, its write epoch when the
/// file was looked up (it never repeats: any write, mount or unmount moves
/// it), the file's identity on the backend and its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentStamp {
    pub fs: u32,
    pub epoch: u64,
    pub id: u64,
    pub size: u64,
}

/// [`ContentStamp::fs`] of the FAT32 volume.
pub const STAMP_FS_FAT32: u32 = 1;

/// The key of an inode that has no backing filesystem.
pub const ZEROED_KEY: InodeKey = InodeKey { bytes: [0u8; INODE_KEY_LEN] };

/// What [`FileSystem::stat`] reports, and what [`FileSystem::read_all`]
/// consumes.
///
/// `cookie` exists so an open costs ONE directory scan, exactly as it did
/// before this trait: FAT32's lookup already returns the start cluster next to
/// the size, and re-deriving it inside `read_all` would be a second scan of the
/// same directory. Its meaning is the backend's business; the VFS only carries
/// it from one call to the next.
///
/// Sizes are `u64` since RFC-0048 P2 (a file of 4 GiB or more is a normal
/// ext4 file). `mode` carries the POSIX type and permission bits (`S_IF*`
/// and `0o7777`); `uid`/`gid`/`nlink` and the three times (seconds since
/// the Unix epoch, 0 when the backend does not keep one) are metadata only:
/// capabilities stay the authority, nothing in the kernel checks `mode`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FileStat {
    pub size:   u64,
    pub is_dir: bool,
    pub cookie: u32,
    pub mode:   u32,
    pub uid:    u32,
    pub gid:    u32,
    pub nlink:  u32,
    pub atime:  u64,
    pub mtime:  u64,
    pub ctime:  u64,
}

/// `S_IFMT` type bits, as POSIX numbers them.
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;

impl FileStat {
    /// A regular file of `size` bytes, `0644`, one link, no times.
    pub const fn file(size: u64, cookie: u32) -> Self {
        FileStat {
            size, is_dir: false, cookie, mode: S_IFREG | 0o644,
            uid: 0, gid: 0, nlink: 1, atime: 0, mtime: 0, ctime: 0,
        }
    }
    /// A directory, `0755`, one link, no times.
    pub const fn dir(size: u64) -> Self {
        FileStat {
            size, is_dir: true, cookie: 0, mode: S_IFDIR | 0o755,
            uid: 0, gid: 0, nlink: 1, atime: 0, mtime: 0, ctime: 0,
        }
    }
}

/// What [`FileSystem::statfs`] reports. Counts of 0 in `files`/`files_free`
/// mean the backend has no inode table to count.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StatFs {
    pub fs_type:     u32,
    pub block_size:  u32,
    pub blocks:      u64,
    pub blocks_free: u64,
    pub files:       u64,
    pub files_free:  u64,
    pub name_max:    u32,
}

/// One entry [`FileSystem::readdir`] yields.
#[derive(Copy, Clone)]
pub struct DirEnt {
    pub name:     [u8; NAME_MAX],
    pub name_len: usize,
    pub is_dir:   bool,
    pub size:     u64,
}

impl DirEnt {
    pub const fn new() -> Self {
        DirEnt { name: [0u8; NAME_MAX], name_len: 0, is_dir: false, size: 0 }
    }
    pub fn name(&self) -> &[u8] { &self.name[..self.name_len.min(NAME_MAX)] }
    /// Fill in `name`; `false` (and nothing written) when it exceeds
    /// `NAME_MAX`.
    pub fn set(&mut self, name: &[u8], is_dir: bool, size: u64) -> bool {
        if name.len() > NAME_MAX { return false; }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        self.is_dir = is_dir;
        self.size = size;
        true
    }
}

/// Why a filesystem operation failed. The syscall layer maps these to
/// errno values; the VFS itself only passes them on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FsErr {
    /// This backend does not implement the operation (the default of every
    /// optional trait method).
    Unsupported,
    NotFound,
    Exists,
    NotEmpty,
    NotDir,
    /// The operation does not apply to a directory (POSIX `EISDIR`): an
    /// `unlink` of one, or a rename of a file onto one.
    IsDir,
    NoSpace,
    Io,
    Invalid,
    NameTooLong,
    Busy,
}

/// One mountable filesystem.
///
/// `Sync` because implementations are `&'static` values shared by every hart;
/// they are stateless handles, and whatever state they stand for is behind
/// their own lock.
pub trait FileSystem: Sync {
    /// The `FS_TYPE_*` tag this backend answers to.
    fn fs_type(&self) -> u32;

    /// Bring the volume online. **Not called by [`vfs_mount`]** — the kernel
    /// still calls `fat32_mount()` itself before registering the mount point,
    /// and calling it here as well would mount twice. It is part of the trait
    /// because a mount is one of the eight things a filesystem does; folding
    /// the kernel's two calls into one is a separate change.
    fn mount(&self) -> Result<(), ()>;

    /// Flush anything this backend is holding back.
    fn sync(&self) -> Result<(), ()>;

    /// Turn a path relative to the mount point into this backend's own name
    /// for it, or `None` if the backend cannot name that file at all.
    ///
    /// This is where a backend's naming rules live — 8.3 conversion, length
    /// limits, "root directory only". They used to live in this file.
    fn key_for(&self, name: &[u8]) -> Option<InodeKey>;

    /// Size and locator for an existing file, or `None` if it does not exist.
    fn stat(&self, key: &InodeKey) -> Option<FileStat>;

    /// Read the whole file named by `key` and described by `st` into `dst`;
    /// returns bytes copied.
    ///
    /// Both are passed because backends locate a file differently: FAT32 uses
    /// the cookie `stat` produced (so the open costs one directory scan, as it
    /// did before this trait existed), while a backend that only knows names
    /// uses the key.
    fn read_all(&self, key: &InodeKey, st: &FileStat, dst: &mut [u8]) -> usize;

    /// Replace the whole file named by `key` with `src`.
    fn write_all(&self, key: &InodeKey, src: &[u8]) -> Result<(), ()>;

    /// Remove the file named by `key`.
    fn unlink(&self, key: &InodeKey) -> Result<(), ()>;

    /// Read up to `dst.len()` bytes starting `offset` bytes into the file
    /// named by `key`. Returns bytes actually copied (0 at or past EOF).
    ///
    /// The streaming half [`read_all`] could not be. `read_all`'s whole-file
    /// contract is what forced `vfs.rs`'s FAT32 proxy (`try_backend_open`) to
    /// load an entire file into the heap on every open and, through
    /// [`write_all`], rewrite it whole on every close: a 64 KiB CRASH.LOG
    /// append reads 64 KiB, allocates up to 128 clusters, writes 64 KiB,
    /// frees 128 — for one append (U09-5c). A caller ported to `read_at` /
    /// `write_at` pays for the bytes it touches, not the whole file.
    fn read_at(&self, key: &InodeKey, offset: u64, dst: &mut [u8]) -> usize;

    /// Write `src` at `offset` bytes into the file named by `key`, growing
    /// it if `offset + src.len()` exceeds the current size. Returns bytes
    /// written. `Err(())` for a backend that cannot write at all (procfs)
    /// or on an underlying I/O failure — never for "unsupported", since
    /// every mounted backend implements this.
    fn write_at(&self, key: &InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()>;

    // ── RFC-0048 P2: the operations a general filesystem needs ────────────
    //
    // Every one has a default, so a backend states only what it can do. The
    // price is the one the `list` note below names: `dyn` keeps the whole
    // vtable alive, so each method costs one entry and one function (the
    // default, a two-instruction `Err`, when not overridden) per backend
    // whose vtable is live. Only FAT32's is live in a default kernel; tmpfs's
    // becomes live because `SYS_MOUNT` can mount it.

    /// `true` for a backend the VFS reads and writes in place through
    /// `read_at`/`write_at`, with no whole-file load on open and no
    /// whole-file rewrite on close. `false` (the default, and FAT32's answer)
    /// keeps the proxy path: `read_all` on open, `write_all` on a dirty close.
    fn streaming(&self) -> bool { false }

    /// `true` when this backend's reads and writes wait on a device (the
    /// default); `false` for a RAM-resident one (tmpfs, procfs). A streaming
    /// file of a device-backed backend transfers with the descriptor table
    /// released and under its description's position lock (owner rule F1,
    /// `fd_stream_transfer`); a RAM-resident one keeps the table's lock.
    fn device_backed(&self) -> bool { true }

    /// `true` for a backend whose READ-ONLY opens may stream through
    /// [`read_at_handle`](Self::read_at_handle) even though it is not
    /// [`streaming`](Self::streaming): no whole-file load to serve a few
    /// bytes. Writes keep the backend's own path (a writable open still takes
    /// the proxy). Defaults to `streaming()`.
    fn stream_reads(&self) -> bool { self.streaming() }

    /// What a read-only stream keeps from its open's `stat`, handed back to
    /// every [`read_at_handle`](Self::read_at_handle) (FAT32: the start
    /// cluster and the volume's write generation).
    fn read_handle(&self, _cookie: u32) -> u64 { 0 }

    /// The identity of the bytes `key` names now, for a cache of what was
    /// verified about them (wave 14, SPAWNCACHE: the exec image digest and
    /// frames). Two equal stamps mean the same bytes. `None` (the default)
    /// for a backend that cannot promise that: nothing is cached for it.
    fn content_stamp(&self, _key: &InodeKey) -> Option<ContentStamp> { None }

    /// What an open needs from [`stat`](Self::stat) — size, directory or not,
    /// cookie — and nothing else. Defaults to `stat`.
    fn stat_brief(&self, key: &InodeKey) -> Option<(u64, bool, u32)> {
        self.stat(key).map(|st| (st.size, st.is_dir, st.cookie))
    }

    /// Read up to `dst.len()` bytes at `offset` of the file `key` names,
    /// opened with handle `handle` and size `size`. Bytes copied, 0 at EOF.
    /// The default ignores the handle: [`read_at`](Self::read_at).
    fn read_at_handle(&self, key: &InodeKey, _handle: u64, _size: u64, offset: u64, dst: &mut [u8]) -> usize {
        self.read_at(key, offset, dst)
    }

    /// Create an empty file named by `key` if none exists; an existing file
    /// is left as it is.
    fn create(&self, _key: &InodeKey) -> Result<(), FsErr> { Err(FsErr::Unsupported) }

    /// Set the file's size to `len`, dropping or zero-filling the tail.
    fn truncate(&self, _key: &InodeKey, _len: u64) -> Result<(), FsErr> { Err(FsErr::Unsupported) }

    /// Make this file's completed writes durable. Defaults to the whole
    /// volume's `sync`.
    fn fsync(&self, _key: &InodeKey) -> Result<(), FsErr> {
        self.sync().map_err(|()| FsErr::Io)
    }

    /// Create a directory at `name` (relative to the mount point).
    fn mkdir(&self, _name: &[u8]) -> Result<(), FsErr> { Err(FsErr::Unsupported) }

    /// Remove the empty directory at `name`.
    fn rmdir(&self, _name: &[u8]) -> Result<(), FsErr> { Err(FsErr::Unsupported) }

    /// Rename `from` to `to`, both relative to the mount point.
    fn rename(&self, _from: &[u8], _to: &[u8]) -> Result<(), FsErr> { Err(FsErr::Unsupported) }

    /// Capacity and free space of the volume.
    fn statfs(&self) -> Result<StatFs, FsErr> { Err(FsErr::Unsupported) }

    /// The first entry of directory `dir` (relative to the mount point, `""`
    /// for its root) at or after position `cookie`, written to `out`.
    /// `Ok(Some(next))` hands back the cookie to continue from, `Ok(None)`
    /// means the directory has no more entries.
    ///
    /// A cookie, not an index, because a hashed directory (ext4 htree) is
    /// not walked in index order; its meaning is the backend's business and
    /// the caller only passes it back. 0 always means "from the start".
    fn readdir(&self, _dir: &[u8], _cookie: u64, _out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
        Err(FsErr::Unsupported)
    }

    // NO `list` (`readdir` above is the cookie-based replacement RFC-0048
    // asked for, with callers). `list` was written, had no caller, and was
    // NOT free:
    // `dyn` keeps the whole vtable alive, so an uncalled method drags its
    // implementations in with it — `fat32`'s cost 2,356 of the 2,516 `.text`
    // bytes this abstraction added, for a second monomorphisation of
    // `fat32_ls_root` that nothing ever entered. The free functions
    // (`fat32_ls_root`, `tmpfs_ls`, `procfs_ls`) are still there for whoever
    // needs enumeration; put it back on the trait when something calls it,
    // and pay the bytes then.
}

/// What the generic inode knows about the filesystem underneath it: that there
/// is one, whether it is behind, and an opaque name for the file.
///
/// The whole of the FAT32-shaped hole this refactor filled. It replaced
/// `fat32_backed: bool`, `fat32_dirty: bool`, `fat32_name: [u8; 11]`.
#[derive(Copy, Clone)]
pub struct InodeBacking {
    /// The filesystem this inode proxies, or `None` for a plain ramfs inode.
    pub fs:    Option<&'static dyn FileSystem>,
    /// Set by `vfs_write` / `O_TRUNC`, cleared by a SUCCESSFUL flush in
    /// `vfs_close`. A flush that failed leaves it set, so another descriptor
    /// on the same inode retries rather than assuming the write landed.
    pub dirty: bool,
    /// Opaque, backend-defined; meaningless when `fs` is `None`.
    pub key:   InodeKey,
    /// The backend is [`FileSystem::streaming`]: this inode holds no data,
    /// reads and writes go to the backend at the descriptor's offset, and
    /// `dirty` is never set.
    pub streaming: bool,
    /// For a streaming inode, the file's size as last learned from the
    /// backend or grown by a write through this inode (`u64`: the inode's
    /// own `size` is the ramfs buffer's and stays `u32`).
    pub size:  u64,
    /// A read-only stream over a backend that is NOT [`FileSystem::streaming`]
    /// ([`FileSystem::stream_reads`], wave 14): the descriptor reads in
    /// place, and every write path refuses it, so what the backend's writes
    /// do (FAT32's whole-file proxy rewrite) is unchanged.
    pub ro_stream: bool,
    /// For a read-only stream, what [`FileSystem::read_handle`] returned at
    /// open; handed back to [`FileSystem::read_at_handle`] on every read.
    pub handle: u64,
}

/// An inode that lives only in the ramfs.
pub const NO_BACKING: InodeBacking = InodeBacking {
    fs: None, dirty: false, key: ZEROED_KEY, streaming: false, size: 0,
    ro_stream: false, handle: 0,
};

// ─── Inode ────────────────────────────────────────────────────────────────────

/// In-kernel inode — direct port of `inode_t` in kernel/include/fs.h.
///
/// Uses raw pointers so it can live in a `static` array and be `Copy`.
/// All access is protected by `FS` spinlock.
#[derive(Copy, Clone)]
pub struct Inode {
    pub ino:         u32,
    pub itype:       u8,       // INODE_FILE / INODE_DIR / INODE_DEVICE
    pub size:        u32,
    pub permissions: u32,
    // File data (heap-allocated; INODE_FILE only)
    pub data:        *mut u8,
    pub capacity:    u32,
    // Directory entries (heap-allocated; INODE_DIR only)
    pub entries:     *mut DentryEntry,
    pub entry_count: u32,
    // Device callbacks (INODE_DEVICE only)
    pub dev_read:    Option<unsafe fn(*mut u8, usize) -> i32>,
    pub dev_write:   Option<unsafe fn(*const u8, usize) -> i32>,
    // Metadata
    pub ref_count:   u32,
    pub link_count:  u32,
    /// Which filesystem, if any, this inode is a proxy for — and that
    /// filesystem's own name for the file. Flushed on close when dirty.
    ///
    /// Was three fields called `fat32_backed`, `fat32_dirty` and
    /// `fat32_name`, so the generic inode named one concrete filesystem's
    /// internals (an 8.3 name) and no other filesystem could be proxied at
    /// all. Nothing outside this file ever read them.
    pub backing:     InodeBacking,
}

const ZEROED_INODE: Inode = Inode {
    ino: 0, itype: 0, size: 0, permissions: 0,
    data: ptr::null_mut(), capacity: 0,
    entries: ptr::null_mut(), entry_count: 0,
    dev_read: None, dev_write: None,
    ref_count: 0, link_count: 0,
    backing: NO_BACKING,
};

// Safety: all Inode access is serialised by the FS spinlock.
unsafe impl Send for Inode {}

// ─── DentryEntry ──────────────────────────────────────────────────────────────

/// Directory entry — port of `dentry_t`, but stores a pool index instead of a
/// raw pointer (avoids dangling-pointer UB after inode pool compaction).
#[derive(Copy, Clone)]
pub struct DentryEntry {
    pub name:      [u8; MAX_FILENAME],
    pub inode_idx: u32,   // Index into FsGlobal::inodes
}

const ZEROED_DENTRY: DentryEntry = DentryEntry {
    name: [0u8; MAX_FILENAME],
    inode_idx: NO_IDX,
};

// ─── FileDesc ─────────────────────────────────────────────────────────────────

/// Open file descriptor — port of `file_desc_t`.
#[derive(Copy, Clone)]
pub struct FileDesc {
    pub inode_idx: u32,   // NO_IDX = no inode (or pipe — future)
    /// The open file description this descriptor names, an index into
    /// [`FdTableN::descs`] (round 48: descriptors made by `dup`/`dup2`, and a
    /// forked Linux child's inherited ones, share one description and so
    /// one offset, as in Linux).
    pub desc:      u16,
    pub flags:     u32,
    pub in_use:    bool,
    /// TID of the task this descriptor was opened for, or `FD_NO_OWNER`.
    ///
    /// Every other kernel object table — handles, ports, io_rings, sockets —
    /// stamps its owner and is reclaimed when that task dies. This one did
    /// not, and so was not: a ring-3 task that opened a file and was then
    /// killed by the watchdog left its slot marked in use forever, with no
    /// field for anything to even attribute the leak to. Against a table of
    /// `MAX_FDS` for the entire machine, that is a handful of kills from an
    /// unrecoverable denial — and the thing denied is whatever opens a file
    /// next, including the flight recorder.
    pub owner_task: u32,
}

/// `owner_task` for a descriptor that no task owns: the stdio entries opened
/// by `fd_table_init`, and anything the kernel opens for itself. Never
/// reclaimed by [`fd_release_owned`] — a kernel task's descriptors are not
/// this mechanism's business, and 0 is not a usable TID.
pub const FD_NO_OWNER: u32 = 0;

const ZEROED_FD: FileDesc = FileDesc {
    inode_idx: NO_IDX, desc: 0, flags: 0, in_use: false, owner_task: FD_NO_OWNER,
};

// ─── OpenDesc ─────────────────────────────────────────────────────────────────

/// An open file description (round 48, owner decision): what descriptors
/// made from one `open` share — the offset — and how many descriptors name
/// it. A descriptor keeps its own owner (one task per slot, so every access
/// check stays per slot); several slots, owned by one task or by a parent
/// and its forked child, name one description. Pipes already work this way:
/// a typed pipe counts its read and write handles (`crates/core/ipc/src/pipe.rs`).
///
/// **Lock order.** Descriptions live inside their [`FdTableN`], so they are
/// guarded by the same lock as the slots (`KERNEL_FD_TABLE` for the
/// machine-wide table): nothing new is locked. The order stays
/// `KERNEL_FD_TABLE` → `FS` (the inode pool, taken inside `fd_free`,
/// `vfs_read`, `vfs_write`, `vfs_lseek`) → the backend's own lock (taken by
/// `vfs_close`/streaming I/O with `FS` released). No capability table is held
/// while the descriptor table is taken: callers resolve a `Cap<File>` to its
/// descriptor and release the cap table first.
#[derive(Copy, Clone)]
pub struct OpenDesc {
    /// `u64` since RFC-0048 P2: a streaming backend's file may pass 4 GiB.
    pub offset: u64,
    /// Descriptors naming this description; 0 = free.
    pub refs:   u16,
}

const ZEROED_DESC: OpenDesc = OpenDesc { offset: 0, refs: 0 };

// ─── FdTable ──────────────────────────────────────────────────────────────────

/// File descriptor table of `N` slots — port of `fd_table_t`.
///
/// Every descriptor function is generic over `N`, so one table type serves
/// both uses: the kernel's machine-wide table ([`FdTable`]) and the throwaway
/// table a kernel-internal operation opens a file through ([`ScratchFds`]).
#[derive(Copy, Clone)]
pub struct FdTableN<const N: usize> {
    pub fds: [FileDesc; N],
    /// Open file descriptions ([`OpenDesc`]): at most one per descriptor.
    pub descs: [OpenDesc; N],
}

impl<const N: usize> FdTableN<N> {
    pub const fn new() -> Self {
        FdTableN { fds: [ZEROED_FD; N], descs: [ZEROED_DESC; N] }
    }

    /// The offset of the description open descriptor `fd` names.
    #[inline]
    pub fn off(&self, fd: i32) -> u64 {
        let d = self.fds[fd as usize].desc as usize;
        if d < N { self.descs[d].offset } else { 0 }
    }

    #[inline]
    fn set_off(&mut self, fd: i32, v: u64) {
        let d = self.fds[fd as usize].desc as usize;
        if d < N {
            self.descs[d].offset = v;
        }
    }

    /// A free description, claimed with one reference at `offset`.
    fn desc_alloc(&mut self, offset: u64) -> Option<u16> {
        let i = self.descs.iter().position(|d| d.refs == 0)?;
        self.descs[i] = OpenDesc { offset, refs: 1 };
        Some(i as u16)
    }

    /// Descriptors naming the description `fd` names (0 if `fd` is not open).
    pub fn desc_refs(&self, fd: i32) -> u16 {
        if fd < 0 || fd as usize >= N || !self.fds[fd as usize].in_use {
            return 0;
        }
        let d = self.fds[fd as usize].desc as usize;
        if d < N { self.descs[d].refs } else { 0 }
    }

    /// The description a new descriptor for `entry` names: `entry`'s own,
    /// shared (round 48), or under the gate canary `fd-private-offset-canary`
    /// a private copy of its offset (what `dup` did before).
    fn desc_for_dup(&mut self, entry: &FileDesc) -> Option<u16> {
        if cfg!(feature = "fd-private-offset-canary") {
            let off = self.descs.get(entry.desc as usize).map_or(0, |d| d.offset);
            return self.desc_alloc(off);
        }
        let d = entry.desc as usize;
        if d >= N || self.descs[d].refs == 0 {
            return None;
        }
        self.descs[d].refs += 1;
        Some(entry.desc)
    }
}

/// The machine-wide descriptor table: `MAX_FDS` slots.
pub type FdTable = FdTableN<MAX_FDS>;

/// Slots in a [`ScratchFds`]: fds 0-2 stay reserved, as in every table, which
/// leaves five for one operation.
pub const SCRATCH_FDS: usize = 8;

/// The table a kernel-internal operation (the shell, OTA, the panic record,
/// boot-time readers) opens its files through and drops on return.
///
/// It lives on that task's kernel stack, so its size must not follow the
/// machine-wide `MAX_FDS`: at 256 slots a table is ~5 KiB, two of them fill a
/// 16 KiB kernel stack, and on the fleet profile the shell overflowed into its
/// guard page.
pub type ScratchFds = FdTableN<SCRATCH_FDS>;

// ─── MountPoint ───────────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct MountPoint {
    pub path:    [u8; 64],
    pub fs_type: u32,
    pub active:  bool,
    pub fs_idx:  u32,   // Backend-defined sub-volume index; always 0 today.
    /// The backend serving this mount, or `None` for a mount the VFS serves
    /// out of its own ramfs.
    ///
    /// This is the field that makes "which filesystem" a value rather than a
    /// branch: `path_lookup` and the proxy-open path used to test
    /// `fs_type == FS_TYPE_FAT32` and then call `fat32_*` directly.
    pub fs:      Option<&'static dyn FileSystem>,
}

const ZEROED_MOUNT: MountPoint = MountPoint {
    path: [0u8; 64], fs_type: 0, active: false, fs_idx: 0, fs: None,
};

/// The FAT32 backend, as a value. Zero-sized: it is a handle to the module's
/// own global volume state, not a second copy of it.
pub static FAT32_FS: crate::fat32::Fat32Fs = crate::fat32::Fat32Fs;

/// The backend registered for a `FS_TYPE_*` tag, or `None`.
///
/// Exists so [`vfs_mount`] keeps the signature its two callers in
/// `kernel/src/main.rs` already use. A caller that has the backend itself
/// should use [`vfs_mount_fs`] instead.
fn backend_for_type(fs_type: u32) -> Option<&'static dyn FileSystem> {
    match fs_type {
        FS_TYPE_FAT32 => Some(&FAT32_FS),
        _             => None,
    }
}

// ─── Global FS state ──────────────────────────────────────────────────────────

struct FsGlobal {
    inodes:      [Inode; MAX_FILES],
    root_idx:    u32,
    next_ino:    u32,
    mounts:      [MountPoint; MAX_MOUNTS],
    mount_count: usize,
}

const ZEROED_FS: FsGlobal = FsGlobal {
    inodes:      [ZEROED_INODE; MAX_FILES],
    root_idx:    NO_IDX,
    next_ino:    1,
    mounts:      [ZEROED_MOUNT; MAX_MOUNTS],
    mount_count: 0,
};

// Safety: all access is serialised by the SpinLock.
unsafe impl Send for FsGlobal {}

static FS: SpinLock<FsGlobal> = SpinLock::new(ZEROED_FS);

/// Non-blocking check for whether the global `FS` lock is currently free.
///
/// Intended for callers that must never block (e.g. the panic handler),
/// which cannot afford to spin on `FS` if some hart is holding it — for
/// instance because that hart is itself stuck inside a panic, or panicked
/// while the lock was held and `panic = abort` means it will never be
/// released.
///
/// This is inherently racy: another hart may acquire `FS` immediately
/// after this returns `true`, and `vfs_open`/`vfs_write`/`vfs_close` each
/// take and release `FS` multiple times internally, so a caller can still
/// end up spinning on a later acquisition even after observing `true`
/// here. This function only rules out the common, most dangerous case
/// where the lock is already held at the time of the check — it is not a
/// full non-blocking guarantee for the VFS call that follows.
pub fn vfs_fs_lock_available() -> bool {
    FS.try_lock().is_some()
}

/// Run `f` with the global `FS` lock held. One caller: the `pstore-smoke`
/// gate trigger in `lib.rs`, which panics inside `f` so the panic handler
/// meets a held `FS` lock.
pub fn with_fs_lock_held<R>(f: impl FnOnce() -> R) -> R {
    let _held = FS.lock();
    f()
}

// ─── String / path helpers ────────────────────────────────────────────────────

/// Compare a byte slice with a fixed-size null-terminated name array.
fn name_eq(a: &[u8], b: &[u8; MAX_FILENAME]) -> bool {
    let b_len = b.iter().position(|&c| c == 0).unwrap_or(MAX_FILENAME);
    a.len() == b_len && &a[..] == &b[..b_len]
}

/// Copy a byte slice into a null-terminated fixed-size name array.
fn name_copy(dst: &mut [u8; MAX_FILENAME], src: &[u8]) {
    let n = src.len().min(MAX_FILENAME - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

/// Trim a byte slice at the first NUL byte.
fn trim_nul(s: &[u8]) -> &[u8] {
    if let Some(n) = s.iter().position(|&c| c == 0) { &s[..n] } else { s }
}

/// Convert a C-string pointer to a Rust byte slice (without NUL terminator).
/// # Safety
/// `ptr` must be a valid, non-null, NUL-terminated byte string.
pub unsafe fn cstr_to_bytes<'a>(ptr: *const u8) -> &'a [u8] {
    if ptr.is_null() { return &[]; }
    let mut len = 0usize;
    while *ptr.add(len) != 0 { len += 1; }
    core::slice::from_raw_parts(ptr, len)
}

/// Return true if `path` starts with `prefix` followed by '/' or NUL.
fn path_starts_with(path: &[u8], prefix: &[u8]) -> bool {
    if path.len() < prefix.len() || &path[..prefix.len()] != prefix {
        return false;
    }
    matches!(path.get(prefix.len()), None | Some(&b'/') | Some(&0))
}

/// Iterate path components split by '/'.
struct PathComponents<'a> {
    rest: &'a [u8],
}

impl<'a> PathComponents<'a> {
    fn new(path: &'a [u8]) -> Self {
        // Skip leading '/' and trim NUL
        let rest = path.strip_prefix(b"/").unwrap_or(path);
        PathComponents { rest: trim_nul(rest) }
    }
}

impl<'a> Iterator for PathComponents<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        while self.rest.first() == Some(&b'/') {
            self.rest = &self.rest[1..];
        }
        if self.rest.is_empty() { return None; }

        let end = self.rest.iter()
            .position(|&c| c == b'/')
            .unwrap_or(self.rest.len());
        let component = &self.rest[..end];
        self.rest = if end < self.rest.len() { &self.rest[end + 1..] } else { &[] };
        Some(component)
    }
}

// ─── Allocator helpers ────────────────────────────────────────────────────────

/// Allocate `size` bytes with alignment 1.  Returns null on failure or size==0.
unsafe fn alloc_raw(size: usize) -> *mut u8 {
    if size == 0 { return ptr::null_mut(); }
    alloc(Layout::from_size_align(size, 1).unwrap())
}

/// Deallocate a byte buffer allocated with `alloc_raw`.
unsafe fn dealloc_raw(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        dealloc(ptr, Layout::from_size_align(size, 1).unwrap());
    }
}

/// Allocate an array of `count` `DentryEntry` values.
unsafe fn alloc_dentries(count: usize) -> *mut DentryEntry {
    if count == 0 { return ptr::null_mut(); }
    let layout = Layout::array::<DentryEntry>(count).unwrap();
    alloc(layout) as *mut DentryEntry
}

/// Deallocate a `DentryEntry` array allocated with `alloc_dentries`.
unsafe fn dealloc_dentries(ptr: *mut DentryEntry, count: usize) {
    if !ptr.is_null() && count > 0 {
        dealloc(ptr as *mut u8, Layout::array::<DentryEntry>(count).unwrap());
    }
}

// ─── Inode operations — port of `inode_alloc / inode_free / inode_resize` ─────

/// Allocate a new inode from the pool.
/// Returns index into the pool, or `NO_IDX` on failure.
///
/// `link_count` starts at 0, not 1. A freshly allocated inode has no
/// directory entry yet — the one and only source of a link is
/// [`dir_add_entry`], which adds it. Pre-counting a link here (as the
/// previous version did) double-counted the dentry the caller was about
/// to add: `alloc` -> 1, then `dir_add_entry` -> 2, so `dir_remove_entry`'s
/// single decrement on unlink could only ever bring it back to 1, and
/// `fd_free`'s `rc == 0 && lc == 0` test never fired — every `unlink` leaked
/// the inode (U09-1). A caller with no directory entry at all (the FAT32
/// proxy paths, `try_backend_open`/`try_backend_create`) already zeroes
/// `link_count` itself right after alloc for exactly this reason; that
/// explicit zero is now redundant but harmless. The root inode, which also
/// has no parent dentry but must never be auto-freed, pins its own count
/// explicitly in [`init`] instead of relying on this default.
/// [`inode_alloc`] with `backing` installed under the same lock hold.
fn inode_alloc_backed(itype: u8, permissions: u32, backing: InodeBacking) -> u32 {
    let mut fs = FS.lock();
    for i in 0..MAX_FILES {
        if fs.inodes[i].ino == 0 {
            let ino = fs.next_ino;
            fs.next_ino += 1;
            fs.inodes[i] = ZEROED_INODE;
            fs.inodes[i].ino         = ino;
            fs.inodes[i].itype       = itype;
            fs.inodes[i].permissions = permissions;
            fs.inodes[i].link_count  = 0;
            fs.inodes[i].backing     = backing;
            return i as u32;
        }
    }
    NO_IDX
}

pub fn inode_alloc(itype: u8, permissions: u32) -> u32 {
    let mut fs = FS.lock();
    for i in 0..MAX_FILES {
        if fs.inodes[i].ino == 0 {
            let ino = fs.next_ino;
            fs.next_ino += 1;
            fs.inodes[i] = ZEROED_INODE;
            fs.inodes[i].ino         = ino;
            fs.inodes[i].itype       = itype;
            fs.inodes[i].permissions = permissions;
            fs.inodes[i].link_count  = 0;
            return i as u32;
        }
    }
    NO_IDX
}

/// Free an inode and release its heap memory.
pub fn inode_free(idx: u32) {
    if idx == NO_IDX || idx as usize >= MAX_FILES { return; }

    // Atomically zero the inode slot and capture the pointers to free.
    let (data, cap, entries, entry_count) = {
        let mut fs = FS.lock();
        let n = &mut fs.inodes[idx as usize];
        if n.ino == 0 { return; }   // Already free
        let ptrs = (n.data, n.capacity, n.entries, n.entry_count);
        *n = ZEROED_INODE;
        ptrs
    };

    // Free heap memory after releasing the lock.
    unsafe {
        dealloc_raw(data, cap as usize);
        dealloc_dentries(entries, entry_count as usize);
    }
}

/// Resize a file inode's data buffer.
/// Only grows the allocation; shrinking is only done when `new_size == 0`.
/// Port of `inode_resize()` in fs.c.
pub fn inode_resize(idx: u32, new_size: u32) -> Result<(), ()> {
    if idx == NO_IDX || idx as usize >= MAX_FILES { return Err(()); }

    let (old_data, old_cap, old_size) = {
        let fs = FS.lock();
        let n = &fs.inodes[idx as usize];
        (n.data, n.capacity, n.size)
    };

    if new_size == 0 {
        unsafe { dealloc_raw(old_data, old_cap as usize); }
        let mut fs = FS.lock();
        let n = &mut fs.inodes[idx as usize];
        n.data = ptr::null_mut();
        n.size = 0;
        n.capacity = 0;
        return Ok(());
    }

    if new_size <= old_cap {
        // Buffer already large enough — just update the logical size.
        FS.lock().inodes[idx as usize].size = new_size;
        return Ok(());
    }

    // Need to grow: allocate a new buffer.
    let new_data = unsafe { alloc_raw(new_size as usize) };
    if new_data.is_null() { return Err(()); }

    unsafe {
        // Copy existing content.
        if !old_data.is_null() && old_size > 0 {
            ptr::copy_nonoverlapping(old_data, new_data, old_size as usize);
        }
        // Zero the newly added region.
        if new_size > old_size {
            ptr::write_bytes(
                new_data.add(old_size as usize),
                0,
                (new_size - old_size) as usize,
            );
        }
        dealloc_raw(old_data, old_cap as usize);
    }

    let mut fs = FS.lock();
    let n = &mut fs.inodes[idx as usize];
    n.data     = new_data;
    n.size     = new_size;
    n.capacity = new_size;
    Ok(())
}

// ─── Directory operations — port of `dir_add/lookup/remove_entry` in fs.c ─────

/// Add a directory entry.  Mirrors `dir_add_entry()` in fs.c.
pub fn dir_add_entry(dir_idx: u32, name: &[u8], inode_idx: u32) -> Result<(), ()> {
    if dir_idx == NO_IDX || inode_idx == NO_IDX { return Err(()); }
    if name.is_empty() || name.len() >= MAX_FILENAME { return Err(()); }

    // Validate and snapshot the current entry list under the lock.
    let (old_entries, old_count) = {
        let fs = FS.lock();
        let dir = &fs.inodes[dir_idx as usize];
        if dir.itype != INODE_DIR { return Err(()); }
        // Duplicate check
        for i in 0..dir.entry_count as usize {
            let ent = unsafe { &*dir.entries.add(i) };
            if name_eq(name, &ent.name) { return Err(()); }
        }
        (dir.entries, dir.entry_count)
    };

    let new_count = old_count + 1;

    // Allocate the new (larger) entry array outside the lock.
    let new_entries = unsafe { alloc_dentries(new_count as usize) };
    if new_entries.is_null() { return Err(()); }

    unsafe {
        // Copy existing entries.
        if !old_entries.is_null() && old_count > 0 {
            ptr::copy_nonoverlapping(old_entries, new_entries, old_count as usize);
        }
        // Append the new entry.
        let slot = &mut *new_entries.add(old_count as usize);
        *slot = ZEROED_DENTRY;
        name_copy(&mut slot.name, name);
        slot.inode_idx = inode_idx;
    }

    // Update the directory inode and bump link count under the lock.
    let old_to_free = {
        let mut fs = FS.lock();
        let dir = &mut fs.inodes[dir_idx as usize];
        // Guard against a concurrent modification (should not happen in Phase 6).
        if dir.entry_count != old_count {
            unsafe { dealloc_dentries(new_entries, new_count as usize); }
            return Err(());
        }
        let old = dir.entries;
        dir.entries     = new_entries;
        dir.entry_count = new_count;
        if (inode_idx as usize) < MAX_FILES {
            fs.inodes[inode_idx as usize].link_count += 1;
        }
        old
    };

    unsafe { dealloc_dentries(old_to_free, old_count as usize); }
    Ok(())
}

/// Find a directory entry by name.  Returns inode index or `NO_IDX`.
pub fn dir_lookup(dir_idx: u32, name: &[u8]) -> u32 {
    if dir_idx == NO_IDX || dir_idx as usize >= MAX_FILES { return NO_IDX; }

    let fs = FS.lock();
    let dir = &fs.inodes[dir_idx as usize];
    if dir.itype != INODE_DIR || dir.entries.is_null() { return NO_IDX; }

    for i in 0..dir.entry_count as usize {
        let ent = unsafe { &*dir.entries.add(i) };
        if name_eq(name, &ent.name) {
            return ent.inode_idx;
        }
    }
    NO_IDX
}

/// Remove a directory entry.  Port of `dir_remove_entry()` in fs.c.
pub fn dir_remove_entry(dir_idx: u32, name: &[u8]) -> Result<(), ()> {
    if dir_idx == NO_IDX || dir_idx as usize >= MAX_FILES { return Err(()); }

    // Find the entry and snapshot list info.
    let (target_idx, old_entries, old_count) = {
        let fs = FS.lock();
        let dir = &fs.inodes[dir_idx as usize];
        if dir.itype != INODE_DIR { return Err(()); }
        let mut found = NO_IDX;
        for i in 0..dir.entry_count as usize {
            let ent = unsafe { &*dir.entries.add(i) };
            if name_eq(name, &ent.name) { found = ent.inode_idx; break; }
        }
        if found == NO_IDX { return Err(()); }
        (found, dir.entries, dir.entry_count)
    };

    let new_count = old_count - 1;
    let new_entries = if new_count > 0 {
        let p = unsafe { alloc_dentries(new_count as usize) };
        if p.is_null() { return Err(()); }
        // Copy all entries except the removed one.
        unsafe {
            let mut out = 0usize;
            for i in 0..old_count as usize {
                let ent = &*old_entries.add(i);
                if !name_eq(name, &ent.name) {
                    *p.add(out) = *ent;
                    out += 1;
                }
            }
        }
        p
    } else {
        ptr::null_mut()
    };

    // Swap entries and update link count.
    let old_to_free = {
        let mut fs = FS.lock();
        let dir = &mut fs.inodes[dir_idx as usize];
        // Guard against a concurrent modification, exactly as `dir_add_entry`
        // does. It was missing here, so a `dir_add_entry` that completed while
        // this call was copying (the lock is dropped for the copy) had its new
        // entry silently dropped: `new_entries` was built from a snapshot that
        // predates it, and installing it threw the addition away.
        //
        // **What this does NOT close, stated rather than implied.** The copy
        // loop above reads `old_entries` with the lock released, and a
        // concurrent add frees that buffer when it installs its own. This
        // guard refuses to INSTALL a stale result; it cannot un-read a freed
        // one. Closing that needs the copy to hold the lock, or the buffers to
        // be reference-counted, and both are bigger than this fix — so the
        // window is recorded here rather than papered over.
        if dir.entry_count != old_count {
            unsafe { dealloc_dentries(new_entries, new_count as usize); }
            return Err(());
        }
        let old = dir.entries;
        dir.entries     = new_entries;
        dir.entry_count = new_count;
        if (target_idx as usize) < MAX_FILES {
            let t = &mut fs.inodes[target_idx as usize];
            if t.link_count > 0 { t.link_count -= 1; }
        }
        old
    };

    unsafe { dealloc_dentries(old_to_free, old_count as usize); }

    // Free the inode here if this was its last link and nobody has it open.
    // Relying on a future `fd_free` to notice `lc == 0` is not enough: a file
    // unlinked after every fd on it was already closed (`rc == 0` at this
    // point) gets no further `fd_free` call, so nothing would ever observe
    // `lc == 0` and free it — the other half of the U09-1 fix (see
    // `inode_alloc`'s doc comment for the first half: why `lc` could not
    // reach 0 at all before this).
    if (target_idx as usize) < MAX_FILES {
        let (lc, rc) = {
            let fs = FS.lock();
            let t = &fs.inodes[target_idx as usize];
            (t.link_count, t.ref_count)
        };
        if lc == 0 && rc == 0 {
            inode_free(target_idx);
        }
    }

    Ok(())
}

// ─── Path resolution — port of `path_lookup / path_parent` in fs.c ───────────

/// Resolve an absolute path to an inode index.
/// Returns `NO_IDX` if the path does not exist.
pub fn path_lookup(path: &[u8]) -> u32 {
    let path = trim_nul(path);
    if path.is_empty() || path[0] != b'/' { return NO_IDX; }

    // Root.
    if path == b"/" {
        return FS.lock().root_idx;
    }

    // Check mount points first, in place under the lock (wave 14: the table
    // used to be copied out whole for this compare-only loop).
    {
        let fs = FS.lock();
        for i in 0..fs.mount_count.min(MAX_MOUNTS) {
            let mp = &fs.mounts[i];
            if !mp.active { continue; }
            if mp.fs.is_some() && path_starts_with(path, trim_nul(&mp.path)) {
                // A mounted backend's files are opened via `try_backend_open`
                // in `vfs_open`. `path_lookup` does not create proxy inodes;
                // return NO_IDX.
                return NO_IDX;
            }
        }
    }

    // Walk ramfs.
    let root_idx = FS.lock().root_idx;
    let mut current = root_idx;
    for component in PathComponents::new(path) {
        current = dir_lookup(current, component);
        if current == NO_IDX { return NO_IDX; }
    }
    current
}

/// Register a filesystem mount point by type tag.
///
/// Unchanged in behaviour: an unknown `fs_type` still registers an active
/// mount and returns `Ok`, exactly as before — it simply has no backend, and
/// so behaves as it always did (nothing was ever served through it).
pub fn vfs_mount(path: &[u8], fs_type: u32) -> Result<(), ()> {
    vfs_mount_inner(path, fs_type, backend_for_type(fs_type))
}

/// Register a mount point served by `fs`.
///
/// The RFC-0040 entry point: which filesystem answers for a path becomes an
/// argument. A backend that reached its storage over IPC rather than over the
/// block driver would be mounted through this call and nothing else in this
/// file would change.
///
/// Wave 12: the kernel mounts `procfs` at `/proc` with it (read-only by
/// construction: its backend refuses every write), so ring 3 reads
/// `/proc/tasks` and the rest through the ordinary file calls. `tmpfs`
/// implements [`FileSystem`] too and stays unmounted here.
pub fn vfs_mount_fs(path: &[u8], fs: &'static dyn FileSystem) -> Result<(), ()> {
    let fs_type = fs.fs_type();
    vfs_mount_inner(path, fs_type, Some(fs))
}

fn vfs_mount_inner(
    path: &[u8],
    fs_type: u32,
    backend: Option<&'static dyn FileSystem>,
) -> Result<(), ()> {
    let mut fs = FS.lock();
    if fs.mount_count >= MAX_MOUNTS { return Err(()); }
    let idx = fs.mount_count;   // snapshot before mutable borrow
    // A path that does not fit used to be truncated into a DIFFERENT mount
    // point; refused now. So is a second mount on a path already mounted:
    // `backend_for_path` answers with the first match, so the second would
    // be unreachable while counting against `MAX_MOUNTS`.
    let path = trim_nul(path);
    if path.is_empty() || path.len() > 63 { return Err(()); }
    for m in &fs.mounts[..idx] {
        if m.active && trim_nul(&m.path) == path { return Err(()); }
    }
    let mp = &mut fs.mounts[idx];
    let n = path.len();
    mp.path[..n].copy_from_slice(&path[..n]);
    mp.path[n] = 0;
    mp.fs_type = fs_type;
    mp.active  = true;
    mp.fs_idx  = 0;
    mp.fs      = backend;
    fs.mount_count += 1;
    Ok(())
}

/// Get a single directory entry by index.
///
/// Returns `Some((name_bytes, size, is_dir))` for the entry at `index`,
/// or `None` if the index is out of range or the inode is not a directory.
pub fn dir_entry_at(dir_idx: u32, index: u32) -> Option<([u8; MAX_FILENAME], u32, bool)> {
    if dir_idx == NO_IDX || dir_idx as usize >= MAX_FILES { return None; }
    let fs = FS.lock();
    let dir = &fs.inodes[dir_idx as usize];
    if dir.itype != INODE_DIR || dir.entries.is_null() { return None; }
    if index >= dir.entry_count { return None; }
    // `index` is SYS_READDIR's a1: masked after the check (Spectre v1).
    let index = azos_limits::nospec::array_index_nospec(index as usize, dir.entry_count as usize);
    let ent = unsafe { &*dir.entries.add(index) };
    let (size, is_dir) = if (ent.inode_idx as usize) < MAX_FILES {
        let child = &fs.inodes[ent.inode_idx as usize];
        (child.size, child.itype == INODE_DIR)
    } else {
        (0, false)
    };
    Some((ent.name, size, is_dir))
}

/// Iterate all entries in a directory inode, calling `cb(name, inode_type)`.
///
/// # Note
/// Holds the FS lock during iteration. The callback must not acquire
/// the FS lock itself to avoid deadlock.
pub fn dir_list(dir_idx: u32, mut cb: impl FnMut(&[u8], u8)) {
    if dir_idx == NO_IDX || dir_idx as usize >= MAX_FILES { return; }
    let fs = FS.lock();
    let dir = &fs.inodes[dir_idx as usize];
    if dir.itype != INODE_DIR || dir.entries.is_null() { return; }
    for i in 0..dir.entry_count as usize {
        let ent   = unsafe { &*dir.entries.add(i) };
        let itype = if (ent.inode_idx as usize) < MAX_FILES {
            fs.inodes[ent.inode_idx as usize].itype
        } else { 0 };
        let name_len = ent.name.iter().position(|&b| b == 0).unwrap_or(MAX_FILENAME);
        cb(&ent.name[..name_len], itype);
    }
}

/// [`FileSystem::content_stamp`] of the file at `path`, through the same
/// mount match an open uses (a backend path is never in the ramfs tree).
/// `None` for a ramfs path or a backend with no stamps.
pub fn vfs_content_stamp(path: &[u8]) -> Option<ContentStamp> {
    if cfg!(feature = "content-stamp-off-canary") { return None; }
    let (backend, sub) = backend_for_path(path)?;
    let key = backend.key_for(sub)?;
    backend.content_stamp(&key)
}

/// Find the mounted backend serving `path`, and the backend's own name for the
/// file: `path` with the mount prefix and its slash removed.
///
/// One function where there were two identical copies of the same scan, one
/// inside the open path and one inside the create path — with the FAT32 tag
/// hard-coded in both.
fn backend_for_path(path: &[u8]) -> Option<(&'static dyn FileSystem, &[u8])> {
    let path = trim_nul(path);

    // Scanned in place under the lock (wave 14): the loop only compares
    // paths and never calls into a backend, and copying the whole mount
    // table out first was most of what matching a mount cost. The result
    // borrows `path` and a `'static` backend, never the table.
    let fs = FS.lock();
    for i in 0..fs.mount_count.min(MAX_MOUNTS) {
        let mp = &fs.mounts[i];
        if !mp.active { continue; }
        let backend = match mp.fs {
            Some(b) => b,
            None    => continue,
        };
        let mp_path = trim_nul(&mp.path);
        if path_starts_with(path, mp_path) {
            let after = &path[mp_path.len()..];
            return Some((backend, after.strip_prefix(b"/").unwrap_or(after)));
        }
    }
    None
}

/// Try to open a file from a mounted backend as a proxy inode.
///
/// Creates a temporary INODE_FILE with the file content loaded from the
/// backend. link_count is set to 0 so the inode is freed automatically when
/// closed.
fn try_backend_open(path: &[u8]) -> u32 {
    let (backend, sub) = match backend_for_path(path) {
        Some(v) => v,
        None    => return NO_IDX,
    };

    // The backend's naming rules — 8.3 conversion, "root directory only" —
    // used to be open-coded here. They are now the backend's own business.
    let key = match backend.key_for(sub) {
        Some(k) => k,
        None    => return NO_IDX,
    };

    let t_stat = crate::census::now();
    let st = match backend.stat(&key) {
        Some(s) => s,
        None    => return NO_IDX,
    };
    let t_alloc = crate::census::now();
    crate::census::add(crate::census::STAT, t_stat, t_alloc);
    let file_size = st.size;

    // The size comes from the backend's directory entry, which for FAT32 is
    // attacker-writable (the volume is exposed over the USB MSC gadget), and
    // it reaches `alloc_raw` below with nothing between. A single ring-3
    // `open("/fat/NAME.EXT")` on an entry claiming ~4 GiB asked the kernel
    // heap for ~4 GiB — the allocator returns null and the open fails, so it
    // is not a reset, but every other subsystem's allocations fail while it is
    // attempted. Refusing an impossible size costs one comparison.
    //
    // The bound is the proxy-inode cap, not a filesystem limit: a larger file
    // is simply not loadable through this whole-file proxy path, which is what
    // `MAX_FAT32_PROXY_BYTES`'s own doc says. It stays on this side of the
    // seam because it bounds the VFS's allocation, not the backend's file.
    if file_size > MAX_FAT32_PROXY_BYTES as u64 {
        return NO_IDX;
    }
    // Fits: the ceiling is 8 MiB.
    let file_size = file_size as u32;

    // Allocate proxy inode.
    let inode_idx = inode_alloc(INODE_FILE, PERM_READ);
    if inode_idx == NO_IDX { return NO_IDX; }

    if file_size > 0 {
        if inode_resize(inode_idx, file_size).is_err() {
            inode_free(inode_idx);
            return NO_IDX;
        }
        let data_ptr = FS.lock().inodes[inode_idx as usize].data;
        // Safety: inode_resize guarantees data != null and capacity >= file_size.
        let buf = unsafe { core::slice::from_raw_parts_mut(data_ptr, file_size as usize) };
        let t_fill = crate::census::now();
        crate::census::add(crate::census::ALLOC, t_alloc, t_fill);
        let got = backend.read_all(&key, &st, buf);
        crate::census::add(crate::census::FILL, t_fill, crate::census::now());
        // A synthetic file (procfs) is generated again here, after `stat`
        // sized it, and can come out shorter (wave 12: `/proc/tasks` with a
        // task gone meanwhile): the proxy is cut to what was generated,
        // not padded with NULs. A disk file keeps its stat size.
        if backend.fs_type() == crate::procfs::FS_TYPE_PROCFS && got < file_size as usize {
            let _ = inode_resize(inode_idx, got as u32);
        }
    }

    // link_count = 0: freed when last FD releases it (rc==0 && lc==0).
    // Tag with the backing filesystem so writes are flushed to it on close.
    {
        let mut fs = FS.lock();
        let inode = &mut fs.inodes[inode_idx as usize];
        inode.link_count = 0;
        inode.backing    = InodeBacking {
            fs: Some(backend), dirty: false, key, streaming: false, size: 0,
            ro_stream: false, handle: 0,
        };
    }
    inode_idx
}

/// Does a mounted backend already hold a file at `path`?
///
/// One directory scan, and the only thing that separates "there is no such
/// file" from "there is one, and the proxy could not load it" — a distinction
/// [`vfs_open`]'s `O_CREAT|O_APPEND` path has to make before it is allowed to
/// create anything. Deliberately does NOT allocate: it is called on the paths
/// where the allocation is what failed.
fn backend_file_exists(path: &[u8]) -> bool {
    match backend_for_path(path) {
        Some((backend, sub)) => {
            backend.key_for(sub).and_then(|k| backend.stat(&k)).is_some()
        }
        None => false,
    }
}

/// The size of the file at `path` under a mounted backend, or `None` if it
/// does not exist (or the path is not under any mount).
///
/// The other half of [`backend_file_exists`]'s reason to exist: a caller that
/// needs a SIZE, not a boolean, and must not pay for [`try_backend_open`]'s
/// whole-file proxy load to get it. `FileSystem::stat` is one directory scan
/// with no allocation — `crates/fs/fs/src/crash_log.rs` calls this on every
/// panic to decide whether `/fat/CRASH.LOG` needs to rotate before an
/// `O_APPEND` open would load the file it is about to decide NOT to load.
pub fn vfs_file_size(path: &[u8]) -> Option<u64> {
    let (backend, sub) = backend_for_path(path)?;
    let key = backend.key_for(sub)?;
    backend.stat(&key).map(|st| st.size)
}

/// Try to create a new empty backend-backed proxy inode for a file under a
/// mounted backend.  Used by `vfs_open` when `O_CREAT` is set.
///
/// Returns `Some(inode_idx)` if the path falls under a mounted backend and
/// that backend can name the file; `None` otherwise.
fn try_backend_create(path: &[u8]) -> Option<u32> {
    let (backend, sub) = backend_for_path(path)?;
    let key = backend.key_for(sub)?;

    let inode_idx = inode_alloc(INODE_FILE, PERM_READ | PERM_WRITE);
    if inode_idx == NO_IDX { return None; }

    {
        let mut fs = FS.lock();
        let inode = &mut fs.inodes[inode_idx as usize];
        inode.link_count = 0;   // auto-freed when last FD closes
        inode.backing    = InodeBacking {
            fs: Some(backend), dirty: false, key, streaming: false, size: 0,
            ro_stream: false, handle: 0,
        };
    }
    Some(inode_idx)
}

/// Open `path` on a [`FileSystem::streaming`] backend: an inode that holds no
/// data, whose reads and writes go to the backend at the descriptor's offset
/// (RFC-0048 P2). Nothing is loaded on open and nothing is rewritten on
/// close — the property the proxy path cannot have.
///
/// `None` when `path` is not under a streaming backend (the caller goes on
/// to the proxy path); `Some(NO_IDX)` when it is and the open failed.
fn try_backend_stream_open_at(
    (backend, sub): (&'static dyn FileSystem, &[u8]),
    flags: u32,
) -> Option<u32> {
    if !backend.streaming() {
        return try_backend_ro_stream_open(backend, sub, flags);
    }
    let key = match backend.key_for(sub) {
        Some(k) => k,
        None => return Some(NO_IDX),
    };
    let size = match backend.stat(&key) {
        Some(st) if st.is_dir => return Some(NO_IDX),
        Some(st) => st.size,
        None => {
            if flags & O_CREAT == 0 { return Some(NO_IDX); }
            if backend.create(&key).is_err() { return Some(NO_IDX); }
            0
        }
    };
    let size = if flags & O_TRUNC != 0 && size != 0 {
        if backend.truncate(&key, 0).is_err() { return Some(NO_IDX); }
        0
    } else {
        size
    };
    let perms = if flags & (O_WRONLY | O_RDWR) != 0 { PERM_READ | PERM_WRITE } else { PERM_READ };
    let inode_idx = inode_alloc(INODE_FILE, perms);
    if inode_idx == NO_IDX { return Some(NO_IDX); }
    let mut fs = FS.lock();
    let inode = &mut fs.inodes[inode_idx as usize];
    inode.link_count = 0;   // auto-freed when last FD closes
    inode.backing = InodeBacking {
        fs: Some(backend), dirty: false, key, streaming: true, size, ro_stream: false, handle: 0,
    };
    Some(inode_idx)
}

/// A read-only open on a [`FileSystem::stream_reads`] backend (wave 14): an
/// inode that holds no data and serves reads in place, so `open` + `read 64 B`
/// costs the directory lookup and the bytes read, not a load of the whole
/// file into the heap. `None` (the proxy path, as before) for any flag that
/// may write, a directory, or a name the backend does not have.
fn try_backend_ro_stream_open(backend: &'static dyn FileSystem, sub: &[u8], flags: u32) -> Option<u32> {
    if cfg!(feature = "ro-stream-off-canary") { return None; }
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND) != 0 || !backend.stream_reads() {
        return None;
    }
    let t_k = crate::census::now();
    let key = backend.key_for(sub)?;
    let t_stat = crate::census::now();
    crate::census::add(crate::census::KEY, t_k, t_stat);
    let (size, is_dir, cookie) = backend.stat_brief(&key)?;
    crate::census::add(crate::census::STAT, t_stat, crate::census::now());
    if is_dir { return None; }
    let handle = backend.read_handle(cookie);
    let t_inode = crate::census::now();
    // `inode_alloc` and the backing in one hold of `FS` (link_count 0: freed
    // when the last descriptor closes).
    let backing = InodeBacking {
        fs: Some(backend), dirty: false, key, streaming: true, size, ro_stream: true, handle,
    };
    let inode_idx = inode_alloc_backed(INODE_FILE, PERM_READ, backing);
    crate::census::add(crate::census::INODE, t_inode, crate::census::now());
    Some(inode_idx)
}

/// Return the parent directory index and filename for an absolute path.
/// Equivalent to `path_parent()` in fs.c.
pub fn path_parent(path: &[u8]) -> (u32, &[u8]) {
    let path = trim_nul(path);
    if path.is_empty() || path[0] != b'/' { return (NO_IDX, &[]); }

    // Find the last '/'.
    let last_slash = match path.iter().rposition(|&c| c == b'/') {
        Some(i) => i,
        None    => return (NO_IDX, &[]),
    };
    let filename = &path[last_slash + 1..];
    if filename.is_empty() { return (NO_IDX, &[]); }

    let parent_idx = if last_slash == 0 {
        FS.lock().root_idx          // "/filename" → parent is "/"
    } else {
        path_lookup(&path[..last_slash])
    };
    (parent_idx, filename)
}

// ─── FD table operations — port of `fd_table_init / fd_alloc / fd_free / fd_get` ──

/// Allocate a file descriptor in a table. Returns the fd, or -1 on failure.
///
/// **Descriptors 0, 1 and 2 are skipped, and the reason is not the one the
/// old comment gave.** It said "std streams", implying this table holds them.
/// It does not, and never did: `fd_table_init` — the function that opened
/// `/dev/stdin`, `/dev/stdout` and `/dev/stderr` into slots 0-2 — had zero
/// callers anywhere in the tree, and those three files are not created
/// anywhere either. It has been deleted along with this comment's claim.
///
/// The real reason is one level up. `sys_write` intercepts fd 1 and 2 before
/// it consults the filesystem at all and writes them straight to the UART,
/// because that path is `libsys::print` and `PROFILE_MOTOR` grants it. So a
/// real file handed out on fd 1 would have its writes silently go to the
/// console instead of to the file — a data-loss bug with no error anywhere.
/// The reservation is load-bearing; only its justification was wrong.
///
/// fd 0 has no such interception — `sys_read` has no stdin case, so `read(0)`
/// simply fails — and is skipped only to keep the three consecutive, which
/// costs one slot of `MAX_FDS` for the whole machine. Unifying descriptors
/// under `Cap<T>` (RFC-0003/RFC-0038) removes the question entirely, since a
/// typed handle carries its kind in its top bits and can never collide with a
/// console number.
pub fn fd_alloc<const N: usize>(table: &mut FdTableN<N>, inode_idx: u32, flags: u32) -> i32 {
    for fd in 3..N {
        if !table.fds[fd].in_use {
            let Some(desc) = table.desc_alloc(0) else { return -1 };
            table.fds[fd] = FileDesc {
                inode_idx, desc, flags, in_use: true, owner_task: FD_NO_OWNER,
            };
            if inode_idx != NO_IDX && (inode_idx as usize) < MAX_FILES {
                FS.lock().inodes[inode_idx as usize].ref_count += 1;
            }
            return fd as i32;
        }
    }
    -1
}

/// Release a file descriptor.
pub fn fd_free<const N: usize>(table: &mut FdTableN<N>, fd: i32) {
    if fd < 0 || fd as usize >= N { return; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return; }

    let inode_idx = table.fds[fd as usize].inode_idx;
    table.fds[fd as usize].in_use = false;
    // One reference fewer on the description; the last one frees it.
    let d = table.fds[fd as usize].desc as usize;
    if d < N && table.descs[d].refs > 0 {
        table.descs[d].refs -= 1;
    }

    if inode_idx != NO_IDX && (inode_idx as usize) < MAX_FILES {
        let (rc, lc) = {
            let mut fs = FS.lock();
            let n = &mut fs.inodes[inode_idx as usize];
            if n.ref_count > 0 { n.ref_count -= 1; }
            (n.ref_count, n.link_count)
        };
        if rc == 0 && lc == 0 {
            inode_free(inode_idx);
        }
    }
}


// ─── Descriptor I/O without the table's lock (owner rule F1, wave 15) ───────
//
// The machine-wide table is a `PiMutex` (kernel/src/boot/seams.rs
// `KERNEL_FD_TABLE`): real-time tasks use it for ramfs and device files, so
// it keeps priority inheritance, and so it must not be held across a device
// wait. The helpers below let its owner do the device part of an operation
// on a copy of ONE descriptor, outside the lock, and publish the result
// under it:
//
// * `open`: every device access (the backend lookup, the proxy load, the
//   create) happens before `fd_alloc`, so the seam opens into a
//   `ScratchFds` and [`fd_adopt`] moves the descriptor into the table.
// * `read`/`write` on a device-backed streaming file ([`fd_streams`],
//   [`fd_stream_transfer`]): under the description's position lock
//   ([`DESC_POS`], Linux's `f_pos_lock`) the descriptor is lent
//   ([`fd_lend`]: a one-slot table holding its own inode reference, so a
//   concurrent close cannot free the inode under the I/O) and its offset is
//   published back by [`fd_settle`].
// * `close` of the last descriptor naming an inode ([`fd_detach`]): the
//   flush of a dirty proxy runs on the detached copy. A close that leaves
//   other descriptors on the inode does not flush: the last close does
//   (another descriptor may be writing into the proxy's buffer, which a
//   flush outside the lock could see reallocated).

/// A table of one descriptor (slot 0) taken out of a table for the device
/// part of an operation.
pub type LoneFd = FdTableN<1>;

/// Does descriptor `fd` name a streaming file of a device-backed backend
/// (whose reads and writes wait on the device)?
pub fn fd_streams<const N: usize>(table: &FdTableN<N>, fd: i32) -> bool {
    if fd < 0 || fd as usize >= N { return false; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N);
    let e = &table.fds[fd];
    if !e.in_use || e.inode_idx == NO_IDX || e.inode_idx as usize >= MAX_FILES { return false; }
    let fs = FS.lock();
    let n = &fs.inodes[e.inode_idx as usize];
    n.itype == INODE_FILE && n.backing.streaming
        && n.backing.fs.map_or(false, |b| b.device_backed())
}

/// A copy of open descriptor `fd` as slot 0 of a [`LoneFd`], with its
/// description's offset and a reference of its own on the inode (dropped by
/// `fd_free(&mut lone, 0)`). Also the description index, for [`fd_settle`].
pub fn fd_lend<const N: usize>(table: &FdTableN<N>, fd: i32) -> Option<(LoneFd, u16)> {
    if fd < 0 || fd as usize >= N { return None; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N);
    let e = table.fds[fd];
    if !e.in_use { return None; }
    let mut lone = LoneFd::new();
    lone.fds[0] = FileDesc { desc: 0, ..e };
    lone.descs[0] = OpenDesc { offset: table.off(fd as i32), refs: 1 };
    if e.inode_idx != NO_IDX && (e.inode_idx as usize) < MAX_FILES {
        FS.lock().inodes[e.inode_idx as usize].ref_count += 1;
    }
    Some((lone, e.desc))
}

/// Publish a lent descriptor's offset to `fd`'s description, if `fd` still
/// names the same description and inode (a close or `dup2` in between
/// moved it: then the offset belongs to nobody).
pub fn fd_settle<const N: usize>(table: &mut FdTableN<N>, fd: i32, desc: u16, lone: &LoneFd) {
    if fd < 0 || fd as usize >= N { return; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N);
    let e = table.fds[fd];
    let d = desc as usize;
    if e.in_use && e.desc == desc && e.inode_idx == lone.fds[0].inode_idx
        && d < N && table.descs[d].refs > 0
    {
        table.descs[d].offset = lone.descs[0].offset;
    }
}

/// Position locks, one per open file description index (Linux `f_pos_lock`,
/// 3.14): a read or write of a device-backed streaming file holds its
/// description's lock from taking the offset to publishing the new one, so
/// two threads sharing one description never transfer at the same offset.
/// A `SleepLock` (no priority inheritance: it is held across the device
/// wait, owner rule F1); only non-RT tasks take it, since real-time tasks do
/// no block I/O. Never held while waiting for the descriptor table, and the
/// table is never held while waiting for it. Indexed by description slot;
/// a slot reused while a transfer holds its lock only waits for it.
static DESC_POS: [azos_sync::SleepLock<()>; MAX_FDS] =
    [const { azos_sync::SleepLock::new(()) }; MAX_FDS];

/// Read (`write` false) or write `len` bytes at `buf` through descriptor
/// `fd` of a device-backed streaming file ([`fd_streams`]) without holding
/// the table's lock across the device: `with_table` runs a closure under
/// that lock. Under the description's position lock ([`DESC_POS`]) the
/// descriptor is lent ([`fd_lend`]), transferred with `around_io()`'s value
/// alive (a gate canary's hook; `|| ()` otherwise) and settled
/// ([`fd_settle`]). -1 when `fd` is not open.
pub fn fd_stream_transfer<const N: usize, G>(
    with_table: &dyn Fn(&mut dyn FnMut(&mut FdTableN<N>)),
    around_io: impl Fn() -> G,
    fd: i32, write: bool, buf: *mut u8, len: usize,
) -> i64 {
    if fd < 0 || fd as usize >= N { return -1; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    let mut desc = None;
    with_table(&mut |t| {
        if t.fds[fd as usize].in_use { desc = Some(t.fds[fd as usize].desc); }
    });
    let Some(desc) = desc else { return -1 };
    // Gate canary `fd-pos-lock-canary`: no position lock (two sharers may
    // transfer at one offset).
    let _pos = if cfg!(feature = "fd-pos-lock-canary") {
        None
    } else {
        Some(DESC_POS[desc as usize % MAX_FDS].lock())
    };
    let mut lent = None;
    with_table(&mut |t| {
        let e = &t.fds[fd as usize];
        if e.in_use && e.desc == desc { lent = fd_lend(t, fd); }
    });
    let Some((mut lone, desc)) = lent else { return -1 };
    let n = {
        let _io = around_io();
        if write {
            vfs_write(&mut lone, 0, buf as *const u8, len)
        } else {
            vfs_read(&mut lone, 0, buf, len)
        }
    };
    with_table(&mut |t| {
        fd_settle(t, fd, desc, &lone);
        // The lent inode reference (no device access).
        fd_free(&mut lone, 0);
    });
    n as i64
}

/// Move descriptor `sfd` of `from` into a free slot of `table` (with a new
/// description at its offset, owner `FD_NO_OWNER`). The inode reference
/// moves with it. -1 (and `from` untouched) when `table` has no free slot
/// or description.
pub fn fd_adopt<const N: usize, const M: usize>(table: &mut FdTableN<N>, from: &mut FdTableN<M>, sfd: i32) -> i32 {
    if sfd < 0 || sfd as usize >= M || !from.fds[sfd as usize].in_use { return -1; }
    let e = from.fds[sfd as usize];
    let off = from.off(sfd);
    for fd in 3..N {
        if !table.fds[fd].in_use {
            let Some(desc) = table.desc_alloc(off) else { return -1 };
            table.fds[fd] = FileDesc { desc, owner_task: FD_NO_OWNER, ..e };
            from.fds[sfd as usize].in_use = false;
            let d = e.desc as usize;
            if d < M && from.descs[d].refs > 0 { from.descs[d].refs -= 1; }
            return fd as i32;
        }
    }
    -1
}

/// Close `fd` in `table` and hand back what must still happen outside the
/// lock: `Some(lone)` when this was the last descriptor on its inode (the
/// caller runs `vfs_close(&mut lone, 0)`: the flush of a dirty proxy, then
/// the inode reference); `None` when it is already done (other
/// descriptors still name the inode; no flush — see above).
pub fn fd_detach<const N: usize>(table: &mut FdTableN<N>, fd: i32) -> Option<LoneFd> {
    if fd < 0 || fd as usize >= N { return None; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    let e = table.fds[fd as usize];
    if !e.in_use { return None; }
    let last = e.inode_idx != NO_IDX && (e.inode_idx as usize) < MAX_FILES
        && FS.lock().inodes[e.inode_idx as usize].ref_count <= 1;
    if !last {
        fd_free(table, fd);
        return None;
    }
    let mut lone = LoneFd::new();
    lone.fds[0] = FileDesc { desc: 0, ..e };
    lone.descs[0] = OpenDesc { offset: table.off(fd), refs: 1 };
    // The slot and its description share, without the inode reference
    // (it moved to `lone`).
    table.fds[fd as usize].in_use = false;
    let d = e.desc as usize;
    if d < N && table.descs[d].refs > 0 { table.descs[d].refs -= 1; }
    Some(lone)
}

/// Most descriptors ONE ring-3 task may hold at once.
///
/// `MAX_FDS` is the size of the table for the ENTIRE MACHINE, not per task —
/// despite its Kconfig name, `MAX_FDS_PER_PROC`, and despite that option's
/// help text saying "Maximum open FDs a single process can hold
/// simultaneously". No such ceiling existed: one userspace program opening
/// files in a loop could take all sixteen and deny them to everyone.
///
/// That is not a fairness question here. Sockets got this ceiling because the
/// e-stop arrives over TCP and "another program used up the sockets" is a
/// crash; descriptors are what the flight recorder's rotation and the ELF
/// loader need, so the shape of the failure is the same.
///
/// Half the table, mirroring `MAX_SOCKETS_PER_TASK`: enough for a program that
/// holds a config file, a log and a couple of data files, and never enough for
/// one task to lock everyone else out.
pub const MAX_FDS_PER_TASK: usize = MAX_FDS / 2;

/// How many descriptors `tid` currently holds.
///
/// The counting half of the quota. It must be called under the same lock that
/// allocates — checking the count and then taking the lock would let two of a
/// task's own threads both pass and both allocate, which is the bug this is
/// meant to stop one level down.
pub fn fd_count_owned<const N: usize>(table: &FdTableN<N>, tid: u32) -> usize {
    if tid == FD_NO_OWNER { return 0; }
    table.fds.iter().filter(|e| e.in_use && e.owner_task == tid).count()
}

/// Who owns descriptor `fd`, or `None` if it is out of range or unused.
///
/// The read half of [`fd_set_owner`]. It existed only as a write: the owner
/// was stamped at `open` and read at task death, and **nothing consulted it in
/// between** — so every other syscall on the descriptor path (`read`, `write`,
/// `close`, `lseek`, `dup`, `dup2`) operated on any of the machine-wide slots
/// regardless of who opened it. `crates/fs/fs` cannot make the comparison itself
/// (it deliberately knows nothing about the scheduler), so this hands the
/// value to the kernel, which does.
pub fn fd_owner<const N: usize>(table: &FdTableN<N>, fd: i32) -> Option<u32> {
    if fd < 0 || fd as usize >= N { return None; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    let e = &table.fds[fd as usize];
    if e.in_use { Some(e.owner_task) } else { None }
}

/// Stamp `fd` as belonging to `tid`, so it is reclaimed when that task dies.
///
/// Separate from `fd_alloc` deliberately: this crate has no dependency on the
/// scheduler and must not grow one just to learn who is running. The caller —
/// the kernel, the only place that both holds the table and knows the current
/// TID — stamps it immediately after the open.
pub fn fd_set_owner<const N: usize>(table: &mut FdTableN<N>, fd: i32, tid: u32) {
    if fd < 0 || fd as usize >= N { return; }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return; }
    table.fds[fd as usize].owner_task = tid;
}

/// Close every descriptor owned by `tid`. Returns how many were reclaimed.
///
/// Called when a task exits by ANY route — including the routes that are not a
/// clean `exit`: killed by the watchdog, aborted on a fault, reaped as a
/// zombie. Those are exactly the paths on which the task never got to call
/// `close` itself, and exactly the paths a leak accumulates on.
///
/// Goes through `fd_free` rather than clearing the slot, so the inode's
/// reference count drops exactly as an explicit `close` would drop it. Zeroing
/// the entry directly would reclaim the descriptor and leak the inode instead —
/// trading a bounded table for an unbounded one.
pub fn fd_release_owned<const N: usize>(table: &mut FdTableN<N>, tid: u32) -> usize {
    if tid == FD_NO_OWNER { return 0; }
    let mut freed = 0usize;
    for fd in 0..N {
        if table.fds[fd].in_use && table.fds[fd].owner_task == tid {
            fd_free(table, fd as i32);
            freed += 1;
        }
    }
    freed
}

/// Get a reference to a file descriptor entry.
pub fn fd_get<const N: usize>(table: &FdTableN<N>, fd: i32) -> Option<&FileDesc> {
    if fd < 0 || fd as usize >= N {
        return None;
    }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use {
        return None;
    }
    Some(&table.fds[fd as usize])
}

/// Duplicate a file descriptor.  Returns the new fd (lowest available), or -1.
pub fn fd_dup<const N: usize>(table: &mut FdTableN<N>, old_fd: i32) -> i32 {
    if old_fd < 0 || old_fd as usize >= N {
        return -1;
    }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let old_fd = azos_limits::nospec::array_index_nospec(old_fd as usize, N) as i32;
    if !table.fds[old_fd as usize].in_use {
        return -1;
    }
    let entry = table.fds[old_fd as usize];
    // Find the lowest free fd (starting from 0)
    for fd in 0..N {
        if !table.fds[fd].in_use {
            // Round 48: the duplicate names the SAME description (one offset).
            let Some(desc) = table.desc_for_dup(&entry) else { return -1 };
            table.fds[fd] = FileDesc {
                inode_idx: entry.inode_idx, desc,
                flags: entry.flags, in_use: true,
                // A duplicate inherits the original's owner, so both are
                // reclaimed together. Leaving it unowned would make `dup` a
                // way to launder a descriptor out of its own task's reach.
                owner_task: entry.owner_task,
            };
            if entry.inode_idx != NO_IDX && (entry.inode_idx as usize) < MAX_FILES {
                FS.lock().inodes[entry.inode_idx as usize].ref_count += 1;
            }
            return fd as i32;
        }
    }
    -1
}

/// Duplicate a file descriptor to a specific fd number.
/// Closes new_fd if already open.  Returns new_fd on success, -1 on error.
pub fn fd_dup2<const N: usize>(table: &mut FdTableN<N>, old_fd: i32, new_fd: i32) -> i32 {
    if old_fd < 0 || old_fd as usize >= N {
        return -1;
    }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let old_fd = azos_limits::nospec::array_index_nospec(old_fd as usize, N) as i32;
    if !table.fds[old_fd as usize].in_use {
        return -1;
    }
    if new_fd < 0 || new_fd as usize >= N { return -1; }
    let new_fd = azos_limits::nospec::array_index_nospec(new_fd as usize, N) as i32;
    if old_fd == new_fd { return new_fd; }

    let entry = table.fds[old_fd as usize];
    // Close new_fd if it's open
    if table.fds[new_fd as usize].in_use {
        fd_free(table, new_fd);
    }
    // Round 48: `newfd` names the SAME description as `oldfd` (one offset).
    let Some(desc) = table.desc_for_dup(&entry) else { return -1 };
    table.fds[new_fd as usize] = FileDesc {
        inode_idx: entry.inode_idx, desc,
        flags: entry.flags, in_use: true,
        owner_task: entry.owner_task,
    };
    if entry.inode_idx != NO_IDX && (entry.inode_idx as usize) < MAX_FILES {
        FS.lock().inodes[entry.inode_idx as usize].ref_count += 1;
    }
    new_fd
}

// ─── VFS I/O — accepts explicit FdTable (C used task_current() which is Phase 7) ─

/// Open a file.  Returns fd on success, -1 on error.
pub fn vfs_open<const N: usize>(table: &mut FdTableN<N>, path: &[u8], flags: u32) -> i32 {
    if !cfg!(feature = "file-census") {
        return vfs_open_inner(table, path, flags);
    }
    let t0 = crate::census::now();
    let fd = vfs_open_inner(table, path, flags);
    if census_backend_fd(table, fd) {
        crate::census::add(crate::census::OPEN, t0, crate::census::now());
        crate::census::open_done();
    }
    fd
}

/// `file-census` only: does `fd` name an inode a mounted backend owns?
fn census_backend_fd<const N: usize>(table: &FdTableN<N>, fd: i32) -> bool {
    if fd < 0 || fd as usize >= N || !table.fds[fd as usize].in_use { return false; }
    let idx = table.fds[fd as usize].inode_idx;
    idx != NO_IDX && FS.lock().inodes[idx as usize].backing.fs.is_some()
}

fn vfs_open_inner<const N: usize>(table: &mut FdTableN<N>, path: &[u8], flags: u32) -> i32 {
    let t_path = crate::census::now();
    // A path under a backend mount is never in the ramfs tree (`path_lookup`
    // answers NO_IDX for it after the same mount scan), so the mount is
    // resolved once and the ramfs walk skipped (wave 14).
    let mounted = backend_for_path(path);
    let mut inode_idx = if mounted.is_some() { NO_IDX } else { path_lookup(path) };
    crate::census::add(crate::census::PATH, t_path, crate::census::now());

    if inode_idx == NO_IDX {
        // A streaming backend is opened in place, whatever the flags: no
        // proxy load, and `O_CREAT`/`O_TRUNC` are the backend's own
        // `create`/`truncate`, so none of the proxy-path hazards below apply.
        if let Some(idx) = mounted.and_then(|m| try_backend_stream_open_at(m, flags)) {
            if idx == NO_IDX { return -1; }
            let t_fd = crate::census::now();
            let fd = fd_alloc(table, idx, flags);
            crate::census::add(crate::census::FD, t_fd, crate::census::now());
            if fd < 0 { inode_free(idx); }
            return fd;
        }
        if flags & O_CREAT == 0 {
            // Try a mounted backend's proxy before giving up.
            inode_idx = try_backend_open(path);
            if inode_idx == NO_IDX { return -1; }
        } else {
            // **`O_CREAT` on a backend path must not destroy an existing
            // file.**
            //
            // `path_lookup` returns `NO_IDX` for EVERY path under a mounted
            // backend — it does not create proxy inodes — so "not found"
            // above says nothing about whether the file exists. Taking the
            // create branch unconditionally therefore built an EMPTY proxy
            // for a file that was already there, and `vfs_close` wrote that
            // proxy over the whole file. Every `O_CREAT` open of an existing
            // backend-mounted file lost its contents.
            //
            // For `O_APPEND` that is not a corner case, it is the entire
            // point of the flag: `kernel/src/panic.rs` opens
            // `/fat/CRASH.LOG` with `O_WRONLY|O_CREAT|O_APPEND` on every
            // panic, so the log held exactly one record — the most recent —
            // and the one that explains a cascade is the first.
            //
            // `O_TRUNC` still wins: a caller asking for a truncation gets
            // one. Only a non-truncating append reuses the existing file,
            // which is why the shell's redirect, `cp`, the OTA writer and
            // DFU recovery (all `O_WRONLY|O_CREAT|O_TRUNC`) are untouched.
            // The proxy `try_backend_open` returns carries the file's bytes
            // and its real size, and `vfs_write`'s own `O_APPEND` case seeks
            // to that size — so the write lands at the end rather than at 0.
            if flags & O_APPEND != 0 && flags & O_TRUNC == 0 {
                let existing = try_backend_open(path);
                if existing != NO_IDX {
                    return fd_alloc(table, existing, flags);
                }
                // `try_backend_open` answers `NO_IDX` for three different
                // reasons, and only ONE of them may fall through to the
                // create path: the file is not there. The other two — the
                // file is larger than `MAX_FAT32_PROXY_BYTES`, or the heap
                // could not hold it — describe a file that EXISTS, and
                // creating an empty proxy for it is the same destruction
                // this branch exists to prevent, on the path where the
                // history is worth most. Refuse the open instead: a panic
                // that is not recorded is recoverable, a panic log that is
                // erased is not.
                if backend_file_exists(path) { return -1; }
            }

            // Try backend-backed creation first (path under a mount).
            if let Some(proxy_idx) = try_backend_create(path) {
                // O_TRUNC on a freshly created inode is a no-op (size==0),
                // but mark it dirty so vfs_close flushes an explicit truncate.
                if flags & O_TRUNC != 0 {
                    FS.lock().inodes[proxy_idx as usize].backing.dirty = true;
                }
                return fd_alloc(table, proxy_idx, flags);
            }

            // Fallback: create the file in ramfs.
            let (parent_idx, filename) = path_parent(path);
            if parent_idx == NO_IDX || filename.is_empty() { return -1; }

            inode_idx = inode_alloc(INODE_FILE, PERM_READ | PERM_WRITE);
            if inode_idx == NO_IDX { return -1; }

            if dir_add_entry(parent_idx, filename, inode_idx).is_err() {
                inode_free(inode_idx);
                return -1;
            }
        }
    }

    // Truncate on O_TRUNC.
    if flags & O_TRUNC != 0 {
        let itype = FS.lock().inodes[inode_idx as usize].itype;
        if itype == INODE_FILE {
            let _ = inode_resize(inode_idx, 0);
            // Mark dirty if this is an existing backend-backed inode.
            {
                let mut fs = FS.lock();
                if fs.inodes[inode_idx as usize].backing.fs.is_some() {
                    fs.inodes[inode_idx as usize].backing.dirty = true;
                }
            }
        }
    }

    fd_alloc(table, inode_idx, flags)
}

/// Close a file descriptor.
///
/// If the underlying inode is backed by a mounted filesystem and dirty, the
/// inode data is flushed to that filesystem before the descriptor is released.
///
/// Returns `0`, or **`-1` if that flush failed**.
///
/// **A failed flush used to be silent.** The `write_all` result was dropped
/// with `let _ =`, so a write that never reached the device was
/// indistinguishable from one that did: `close()` answered 0 either way. The
/// return value is the observable, and it reaches ring 3 unchanged —
/// `sys_close` in `kernel/src/boot/seams.rs` already returns whatever this
/// function returns, so a program that writes a file and closes it now learns
/// that its data is gone. A counter was the alternative and is worse here:
/// nothing would read it without adding a poller, and the task that lost the
/// data is the one that needs to know.
///
/// **What -1 means, and what it does not.** It means the bytes did not reach
/// the filesystem. It is not a retry signal: the descriptor is released either
/// way (reporting an error by leaking a slot out of a table this small would
/// trade data loss for a denial of service), and a proxy inode with no other
/// reference is freed with it, so the data is no longer anywhere to resend.
/// `backing.dirty` is left SET on failure, so if another descriptor still
/// holds the same inode its own close retries the write rather than assuming
/// the first one succeeded.
///
/// A close with nothing to flush — a read-only descriptor, a ramfs file, a
/// clean inode — still returns 0.
pub fn vfs_close<const N: usize>(table: &mut FdTableN<N>, fd: i32) -> i32 {
    if !cfg!(feature = "file-census") || !census_backend_fd(table, fd) {
        return vfs_close_inner(table, fd);
    }
    let t0 = crate::census::now();
    let r = vfs_close_inner(table, fd);
    crate::census::add(crate::census::CLOSE, t0, crate::census::now());
    r
}

fn vfs_close_inner<const N: usize>(table: &mut FdTableN<N>, fd: i32) -> i32 {
    if fd < 0 || fd as usize >= N { return 0; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return 0; }

    let inode_idx = table.fds[fd as usize].inode_idx;
    let mut flush_failed = false;

    // Flush dirty backend-backed inodes.
    if inode_idx != NO_IDX && (inode_idx as usize) < MAX_FILES {
        // Snapshot backing state + data pointer under the lock, then release
        // before doing slow I/O — the backend takes its own lock.
        let (backing, data_ptr, size) = {
            let fs = FS.lock();
            let n  = &fs.inodes[inode_idx as usize];
            (n.backing, n.data, n.size)
        };

        if let (Some(backend), true) = (backing.fs, backing.dirty) {
            // Safety: data_ptr is heap-allocated and the inode is kept alive
            // until fd_free() below.  The backend does not acquire FS lock.
            let slice: &[u8] = if size > 0 && !data_ptr.is_null() {
                unsafe { core::slice::from_raw_parts(data_ptr, size as usize) }
            } else {
                &[]
            };
            match backend.write_all(&backing.key, slice) {
                Ok(())  => { FS.lock().inodes[inode_idx as usize].backing.dirty = false; }
                // Leave `dirty` set: if another descriptor still references
                // this inode, its close retries instead of assuming this one
                // wrote the file.
                Err(()) => { flush_failed = true; }
            }
        }
    }

    fd_free(table, fd);
    if flush_failed { -1 } else { 0 }
}

/// Read from a file descriptor.
/// Returns bytes read on success, -1 on error.
pub fn vfs_read<const N: usize>(table: &mut FdTableN<N>, fd: i32, buf: *mut u8, count: usize) -> i32 {
    if !cfg!(feature = "file-census") || !census_backend_fd(table, fd) {
        return vfs_read_inner(table, fd, buf, count);
    }
    let t0 = crate::census::now();
    let r = vfs_read_inner(table, fd, buf, count);
    crate::census::add(crate::census::READ, t0, crate::census::now());
    r
}

fn vfs_read_inner<const N: usize>(table: &mut FdTableN<N>, fd: i32, buf: *mut u8, count: usize) -> i32 {
    if fd < 0 || fd as usize >= N { return -1; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return -1; }

    let fd_ent  = table.fds[fd as usize];
    let inode_idx = fd_ent.inode_idx;
    if inode_idx == NO_IDX { return -1; }

    // Extract inode type and device callback while lock is held.
    let (itype, dev_read_fn) = {
        let fs = FS.lock();
        let n  = &fs.inodes[inode_idx as usize];
        (n.itype, n.dev_read)
    };

    if itype == INODE_DEVICE {
        return if let Some(f) = dev_read_fn {
            unsafe { f(buf, count) }
        } else {
            -1
        };
    }
    if itype != INODE_FILE { return -1; }

    let (data_ptr, size, backing) = {
        let fs = FS.lock();
        let n  = &fs.inodes[inode_idx as usize];
        (n.data, n.size, n.backing)
    };

    let offset = table.off(fd);

    // Streaming backend: read in place at the descriptor's offset. The
    // count is clamped to `i32::MAX` so the return value cannot wrap.
    if let (Some(backend), true) = (backing.fs, backing.streaming) {
        let want = count.min(i32::MAX as usize);
        // Safety: the caller hands a buffer of `count` writable bytes, the
        // same contract the ramfs copy below relies on.
        let dst = unsafe { core::slice::from_raw_parts_mut(buf, want) };
        let n = if backing.ro_stream {
            backend.read_at_handle(&backing.key, backing.handle, backing.size, offset, dst)
        } else {
            backend.read_at(&backing.key, offset, dst)
        }.min(want);
        table.set_off(fd, offset.saturating_add(n as u64));
        return n as i32;
    }

    let available = (size as u64).saturating_sub(offset) as usize;
    let to_read   = count.min(available);

    if to_read > 0 {
        unsafe { ptr::copy_nonoverlapping(data_ptr.add(offset as usize), buf, to_read); }
    }
    table.set_off(fd, offset + to_read as u64);
    to_read as i32
}

/// Write to a file descriptor.
/// Returns bytes written on success, -1 on error.
pub fn vfs_write<const N: usize>(table: &mut FdTableN<N>, fd: i32, buf: *const u8, count: usize) -> i32 {
    if fd < 0 || fd as usize >= N { return -1; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return -1; }

    let fd_ent    = table.fds[fd as usize];
    let inode_idx = fd_ent.inode_idx;
    if inode_idx == NO_IDX { return -1; }

    let (itype, dev_write_fn) = {
        let fs = FS.lock();
        let n  = &fs.inodes[inode_idx as usize];
        (n.itype, n.dev_write)
    };

    if itype == INODE_DEVICE {
        return if let Some(f) = dev_write_fn {
            unsafe { f(buf, count) }
        } else {
            -1
        };
    }
    if itype != INODE_FILE { return -1; }

    // Streaming backend: write in place; nothing is marked dirty because
    // nothing is held back.
    let backing = FS.lock().inodes[inode_idx as usize].backing;
    if backing.ro_stream { return -1; }
    if let (Some(backend), true) = (backing.fs, backing.streaming) {
        let offset = if fd_ent.flags & O_APPEND != 0 {
            // The size the backend reports now, not the cached one: another
            // descriptor may have grown the file.
            backend.stat(&backing.key).map(|st| st.size).unwrap_or(backing.size)
        } else {
            table.off(fd)
        };
        let want = count.min(i32::MAX as usize);
        // Safety: the caller hands `count` readable bytes.
        let src = unsafe { core::slice::from_raw_parts(buf, want) };
        let n = match backend.write_at(&backing.key, offset, src) {
            Ok(n) => n.min(want),
            Err(()) => return -1,
        };
        let end = offset.saturating_add(n as u64);
        table.set_off(fd, end);
        let mut fs = FS.lock();
        let b = &mut fs.inodes[inode_idx as usize].backing;
        if end > b.size { b.size = end; }
        return n as i32;
    }

    // Append mode: seek to end.
    if fd_ent.flags & O_APPEND != 0 {
        let size = FS.lock().inodes[inode_idx as usize].size;
        table.set_off(fd, size as u64);
    }

    // The ramfs/proxy buffer is `u32`-sized; an offset past it (reachable
    // only by seeking a streaming file, which does not come here) is refused.
    let offset = match u32::try_from(table.off(fd)) {
        Ok(o) => o,
        Err(_) => return -1,
    };

    // `count` is a usize but every size/offset in the inode table is a u32.
    // `count as u32` silently truncated: a 4 GiB + 1 write sized the buffer
    // for 1 byte and then `copy_nonoverlapping` below copied the full usize,
    // smashing the heap past the allocation. The `offset + count` addition was
    // also unchecked, so with `overflow-checks = true` a large offset aborted
    // the kernel instead. `sys_write` clamps to 4096 so ring 3 cannot reach
    // this, but in-kernel callers pass their own lengths.
    let count_u32 = match u32::try_from(count) {
        Ok(c)  => c,
        Err(_) => return -1,
    };
    let new_size = match offset.checked_add(count_u32) {
        Some(v) => v,
        None    => return -1,
    };

    // Grow data buffer if necessary.
    let cap = FS.lock().inodes[inode_idx as usize].capacity;
    if new_size > cap {
        if inode_resize(inode_idx, new_size).is_err() { return -1; }
    } else {
        // Just update the logical size if needed.
        let mut fs = FS.lock();
        if new_size > fs.inodes[inode_idx as usize].size {
            fs.inodes[inode_idx as usize].size = new_size;
        }
    }

    // Re-read the capacity after the (possible) resize and clamp the copy to
    // what the allocation actually holds, so a resize that returned Ok with a
    // smaller-than-requested buffer still cannot be overrun.
    let (data_ptr, cap_now) = {
        let fs = FS.lock();
        let n  = &fs.inodes[inode_idx as usize];
        (n.data, n.capacity)
    };
    let writable = cap_now.saturating_sub(offset) as usize;
    let to_write = count.min(writable);
    if to_write > 0 {
        unsafe { ptr::copy_nonoverlapping(buf, data_ptr.add(offset as usize), to_write); }
    }
    // `offset + to_write <= offset + count == new_size`, already checked above.
    table.set_off(fd, (offset + to_write as u32) as u64);

    // Mark backend-backed inodes dirty so vfs_close flushes them.
    //
    // This is the whole of the write path's contact with the abstraction: a
    // field test and a field store, no call through the trait. `vfs_read` does
    // not touch it at all.
    {
        let mut fs = FS.lock();
        if fs.inodes[inode_idx as usize].backing.fs.is_some() {
            fs.inodes[inode_idx as usize].backing.dirty = true;
        }
    }

    // Report what was actually copied, not what was asked for.
    to_write as i32
}

/// Seek within a file. Returns the new offset, or -1 on error.
///
/// `i64` offsets since RFC-0048 P2. A ramfs/proxy file cannot be seeked past
/// its end; a streaming file can (a later write there grows it, as POSIX
/// allows), up to `i64::MAX`.
pub fn vfs_lseek<const N: usize>(table: &mut FdTableN<N>, fd: i32, offset: i64, whence: i32) -> i64 {
    if fd < 0 || fd as usize >= N { return -1; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return -1; }

    let inode_idx = table.fds[fd as usize].inode_idx;
    if inode_idx == NO_IDX { return -1; }

    let (size, streaming) = {
        let fs = FS.lock();
        let n = &fs.inodes[inode_idx as usize];
        if n.backing.streaming { (n.backing.size, true) } else { (n.size as u64, false) }
    };
    let cur = table.off(fd);

    let base = match whence {
        SEEK_SET => 0i64,
        SEEK_CUR => cur as i64,
        SEEK_END => size as i64,
        _        => return -1,
    };
    let new_offset = match base.checked_add(offset) {
        Some(v) if v >= 0 => v as u64,
        _ => return -1,
    };
    if !streaming && new_offset > size { return -1; }

    table.set_off(fd, new_offset);
    new_offset as i64
}

// ─── Path operations over the trait (RFC-0048 P2) ──────────────────────────
//
// Each routes a path to the backend mounted under it, or to the ramfs. They
// are the VFS half of the trait methods above: `SYS_STAT` reaches
// `vfs_stat`; the rest have no syscall number in the ABI yet and are the
// entry points a future one (or an in-kernel caller) uses.

/// `S_IFCHR`, for the ramfs device inodes.
pub const S_IFCHR: u32 = 0o020000;

/// A ramfs inode's `PERM_*` bits as a POSIX mode for owner, group and other.
const fn perm_mode(p: u32) -> u32 {
    let p = p & 0o7;
    p | (p << 3) | (p << 6)
}

/// Size, type and metadata of the file or directory at `path`.
pub fn vfs_stat(path: &[u8]) -> Option<FileStat> {
    let idx = path_lookup(path);
    if idx != NO_IDX {
        let fs = FS.lock();
        let n = &fs.inodes[idx as usize];
        let (ty, is_dir, size) = match n.itype {
            INODE_DIR    => (S_IFDIR, true, n.entry_count as u64),
            INODE_DEVICE => (S_IFCHR, false, 0),
            _            => (S_IFREG, false, n.size as u64),
        };
        return Some(FileStat {
            size, is_dir, cookie: 0, mode: ty | perm_mode(n.permissions),
            uid: 0, gid: 0, nlink: n.link_count.max(1),
            atime: 0, mtime: 0, ctime: 0,
        });
    }
    let (backend, sub) = backend_for_path(path)?;
    if sub.is_empty() {
        // The mount point itself: the backend's root directory.
        return Some(FileStat::dir(0));
    }
    backend.stat(&backend.key_for(sub)?)
}

/// Capacity and free space of the filesystem `path` is on. The ramfs
/// answers in inodes (`MAX_FILES`) and has no block count.
pub fn vfs_statfs(path: &[u8]) -> Result<StatFs, FsErr> {
    if let Some((backend, _)) = backend_for_path(path) {
        return backend.statfs();
    }
    let fs = FS.lock();
    let used = fs.inodes.iter().filter(|n| n.itype != 0).count() as u64;
    Ok(StatFs {
        fs_type: FS_TYPE_RAMFS, block_size: 1, blocks: 0, blocks_free: 0,
        files: MAX_FILES as u64, files_free: (MAX_FILES as u64).saturating_sub(used),
        name_max: NAME_MAX as u32,
    })
}

/// The entry of directory `path` at or after `cookie`; see
/// [`FileSystem::readdir`]. For a ramfs directory the cookie is the entry
/// index.
pub fn vfs_readdir(path: &[u8], cookie: u64, out: &mut DirEnt) -> Result<Option<u64>, FsErr> {
    let idx = path_lookup(path);
    if idx == NO_IDX {
        let (backend, sub) = backend_for_path(path).ok_or(FsErr::NotFound)?;
        return backend.readdir(sub, cookie, out);
    }
    let index = match u32::try_from(cookie) {
        Ok(i) => i,
        Err(_) => return Ok(None),
    };
    match dir_entry_at(idx, index) {
        Some((name, size, is_dir)) => {
            let len = name.iter().position(|&b| b == 0).unwrap_or(MAX_FILENAME);
            if !out.set(&name[..len], is_dir, size as u64) { return Err(FsErr::NameTooLong); }
            Ok(Some(cookie + 1))
        }
        None => {
            let fs = FS.lock();
            if fs.inodes[idx as usize].itype != INODE_DIR { Err(FsErr::NotDir) } else { Ok(None) }
        }
    }
}

/// The backend and in-mount path for `path`, or `NotFound` for a ramfs path
/// (the ramfs has no rename/truncate of its own).
fn backend_or_not_found(path: &[u8]) -> Result<(&'static dyn FileSystem, &[u8]), FsErr> {
    match backend_for_path(path) {
        Some((b, sub)) if !sub.is_empty() => Ok((b, sub)),
        Some(_) => Err(FsErr::Invalid),
        None => Err(FsErr::NotFound),
    }
}

/// Create a directory. Under a mount, the backend's `mkdir`; elsewhere a
/// ramfs directory, as `SYS_MKDIR` has always made.
pub fn vfs_mkdir(path: &[u8]) -> Result<(), FsErr> {
    if let Some((b, sub)) = backend_for_path(path) {
        // The mount point itself already exists.
        if sub.is_empty() { return Err(FsErr::Exists); }
        return b.mkdir(sub);
    }
    let (parent, name) = path_parent(path);
    if parent == NO_IDX || name.is_empty() { return Err(FsErr::NotFound); }
    if name.len() >= MAX_FILENAME { return Err(FsErr::NameTooLong); }
    let d = inode_alloc(INODE_DIR, PERM_READ | PERM_WRITE | PERM_EXEC);
    if d == NO_IDX { return Err(FsErr::NoSpace); }
    dir_add_entry(parent, name, d).map_err(|()| { inode_free(d); FsErr::Exists })
}

/// Whether `path` is on a mounted filesystem (the mount point itself
/// included). `SYS_MKDIR`/`SYS_UNLINK` use it to choose between the backend
/// (`vfs_mkdir`, `vfs_unlink`) and the ramfs tree.
pub fn vfs_on_mount(path: &[u8]) -> bool {
    backend_for_path(path).is_some()
}

/// Remove the file at `path` under a mount: the backend's `unlink`, after a
/// stat so a missing entry answers `NotFound` and a directory `IsDir` (the
/// backend's `unlink` takes either; FAT32's would free a directory's chain
/// with its contents still listed). `Invalid` for a path no backend can name,
/// a failed removal `Io`.
pub fn vfs_unlink(path: &[u8]) -> Result<(), FsErr> {
    let (b, sub) = backend_or_not_found(path)?;
    let key = b.key_for(sub).ok_or(FsErr::Invalid)?;
    match b.stat(&key) {
        None => Err(FsErr::NotFound),
        Some(st) if st.is_dir => Err(FsErr::IsDir),
        Some(_) => b.unlink(&key).map_err(|()| FsErr::Io),
    }
}

/// Remove an empty directory under a mount.
pub fn vfs_rmdir(path: &[u8]) -> Result<(), FsErr> {
    let (b, sub) = backend_or_not_found(path)?;
    b.rmdir(sub)
}

/// Rename within one mounted filesystem. Across mounts: `Invalid` (no
/// cross-device rename, as POSIX's `EXDEV`).
pub fn vfs_rename(from: &[u8], to: &[u8]) -> Result<(), FsErr> {
    let (bf, sf) = backend_or_not_found(from)?;
    let (bt, st) = backend_or_not_found(to)?;
    if !core::ptr::addr_eq(bf as *const dyn FileSystem, bt as *const dyn FileSystem) {
        return Err(FsErr::Invalid);
    }
    bf.rename(sf, st)
}

/// Set the size of the file at `path` under a mount.
pub fn vfs_truncate(path: &[u8], len: u64) -> Result<(), FsErr> {
    let (b, sub) = backend_or_not_found(path)?;
    let key = b.key_for(sub).ok_or(FsErr::Invalid)?;
    b.truncate(&key, len)
}

/// Make the writes through descriptor `fd` durable. A proxy inode's dirty
/// buffer is written first (as a close would), then the backend's `fsync`.
/// A ramfs file has nothing to make durable: `Ok`.
pub fn vfs_fsync<const N: usize>(table: &mut FdTableN<N>, fd: i32) -> Result<(), FsErr> {
    if fd < 0 || fd as usize >= N { return Err(FsErr::Invalid); }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return Err(FsErr::Invalid); }
    let idx = table.fds[fd as usize].inode_idx;
    if idx == NO_IDX || idx as usize >= MAX_FILES { return Err(FsErr::Invalid); }
    let (backing, data_ptr, size) = {
        let fs = FS.lock();
        let n = &fs.inodes[idx as usize];
        (n.backing, n.data, n.size)
    };
    let backend = match backing.fs { Some(b) => b, None => return Ok(()) };
    if backing.dirty {
        let slice: &[u8] = if size > 0 && !data_ptr.is_null() {
            // Safety: as in `vfs_close`, the descriptor keeps the inode alive.
            unsafe { core::slice::from_raw_parts(data_ptr, size as usize) }
        } else {
            &[]
        };
        backend.write_all(&backing.key, slice).map_err(|()| FsErr::Io)?;
        FS.lock().inodes[idx as usize].backing.dirty = false;
    }
    backend.fsync(&backing.key)
}


/// [`vfs_fsync`] in two halves, for a table whose lock must not be held
/// across the device (owner rule F1). Under the lock, [`fd_fsync_begin`]
/// lends the descriptor (its inode stays alive) and, when the proxy is
/// dirty, copies its bytes and marks it clean (a write after this marks it
/// dirty again). Outside it, [`fd_fsync_finish`] writes the copy and syncs
/// the file; a failed write marks the proxy dirty again.
pub struct FsyncWork {
    lone: LoneFd,
    copy: Option<alloc::vec::Vec<u8>>,
}

/// First half of [`vfs_fsync`] (see [`FsyncWork`]): `Err` when there is
/// nothing to lend, or the copy of a dirty proxy found no memory.
pub fn fd_fsync_begin<const N: usize>(table: &FdTableN<N>, fd: i32) -> Result<FsyncWork, FsErr> {
    if fd < 0 || fd as usize >= N { return Err(FsErr::Invalid); }
    let fd = azos_limits::nospec::array_index_nospec(fd as usize, N) as i32;
    if !table.fds[fd as usize].in_use { return Err(FsErr::Invalid); }
    let idx = table.fds[fd as usize].inode_idx;
    if idx == NO_IDX || idx as usize >= MAX_FILES { return Err(FsErr::Invalid); }
    let (lone, _) = fd_lend(table, fd).ok_or(FsErr::Invalid)?;
    let mut work = FsyncWork { lone, copy: None };
    let (backing, data_ptr, size) = {
        let fs = FS.lock();
        let n = &fs.inodes[idx as usize];
        (n.backing, n.data, n.size)
    };
    if backing.fs.is_some() && backing.dirty {
        let mut v = alloc::vec::Vec::new();
        if v.try_reserve_exact(size as usize).is_err() {
            fd_free(&mut work.lone, 0);
            return Err(FsErr::NoSpace);
        }
        if size > 0 && !data_ptr.is_null() {
            // Safety: the descriptor keeps the inode alive, and the table's
            // lock (held by the caller) excludes every write to its bytes.
            v.extend_from_slice(unsafe { core::slice::from_raw_parts(data_ptr, size as usize) });
        }
        FS.lock().inodes[idx as usize].backing.dirty = false;
        work.copy = Some(v);
    }
    Ok(work)
}

/// Second half of [`vfs_fsync`], with the table's lock released.
pub fn fd_fsync_finish(mut work: FsyncWork) -> Result<(), FsErr> {
    let idx = work.lone.fds[0].inode_idx;
    let backing = FS.lock().inodes[idx as usize].backing;
    let r = match backing.fs {
        None => Ok(()),
        Some(backend) => {
            let w = match &work.copy {
                Some(bytes) => backend.write_all(&backing.key, bytes).map_err(|()| FsErr::Io),
                None => Ok(()),
            };
            if w.is_err() {
                FS.lock().inodes[idx as usize].backing.dirty = true;
            }
            w.and_then(|()| backend.fsync(&backing.key))
        }
    };
    // The lent reference. If it is the last one (the descriptor was closed
    // during the sync: that close saw this reference and did not flush), a
    // write that landed after the copy is flushed here; nobody else can
    // reach the inode any more, so the flush needs no lock.
    let last = FS.lock().inodes[idx as usize].ref_count <= 1;
    if last {
        let _ = vfs_close(&mut work.lone, 0);
    } else {
        fd_free(&mut work.lone, 0);
    }
    r
}

// ─── Device callbacks ─────────────────────────────────────────────────────────

unsafe fn device_stdin_read(_buf: *mut u8, _count: usize) -> i32 {
    0   // No keyboard input in Phase 6
}

/// `/dev/stdout` and `/dev/stderr`: the same console path as `sys_write`
/// to fd 1/2 (one write is one piece on the wire, never spliced), not the
/// lock-free byte loop it used to be. Reached from `vfs_write` with the
/// caller's FD table locked (task context), so the ring-3 writer's
/// preemptible line lock is fine here.
unsafe fn device_stdout_write(buf: *const u8, count: usize) -> i32 {
    if count > 0 {
        azos_drv_sys::uart::console_write_ring3(core::slice::from_raw_parts(buf, count));
    }
    count as i32
}

// ─── Filesystem initialisation — port of `fs_init()` in fs.c ─────────────────

/// Initialise the ramfs.  Creates root "/", "/dev", the three std device
/// files, and "/tmp".  Must be called after the heap is initialised.
pub fn init() {
    // Root inode "/". It has no parent directory entry to hold a link for
    // it (there is nothing to `dir_add_entry` it into), so unlike every
    // other inode its link_count is not earned through a dentry — it is
    // pinned here explicitly so a stray open("/")+close() can never run it
    // through fd_free's `rc == 0 && lc == 0` auto-free.
    let root_idx = inode_alloc(INODE_DIR, PERM_READ | PERM_WRITE | PERM_EXEC);
    assert!(root_idx != NO_IDX, "[FS] inode pool exhausted for root");
    FS.lock().inodes[root_idx as usize].link_count = 1;
    FS.lock().root_idx = root_idx;

    // /dev
    let dev_idx = inode_alloc(INODE_DIR, PERM_READ | PERM_EXEC);
    dir_add_entry(root_idx, b"dev", dev_idx)
        .expect("[FS] Failed to create /dev");

    // /dev/stdin
    let stdin_idx = inode_alloc(INODE_DEVICE, PERM_READ);
    FS.lock().inodes[stdin_idx as usize].dev_read = Some(device_stdin_read);
    dir_add_entry(dev_idx, b"stdin", stdin_idx)
        .expect("[FS] Failed to create /dev/stdin");

    // /dev/stdout
    let stdout_idx = inode_alloc(INODE_DEVICE, PERM_WRITE);
    FS.lock().inodes[stdout_idx as usize].dev_write = Some(device_stdout_write);
    dir_add_entry(dev_idx, b"stdout", stdout_idx)
        .expect("[FS] Failed to create /dev/stdout");

    // /dev/stderr (same write callback as stdout)
    let stderr_idx = inode_alloc(INODE_DEVICE, PERM_WRITE);
    FS.lock().inodes[stderr_idx as usize].dev_write = Some(device_stdout_write);
    dir_add_entry(dev_idx, b"stderr", stderr_idx)
        .expect("[FS] Failed to create /dev/stderr");

    // /tmp — a ramfs directory a topology can grant ring 3 a tree on (wave
    // 10: creating and removing entries needs a `Cap<File>` naming a tree
    // that covers the entry's directory, and `/` is the only other writable
    // ramfs directory). A tmpfs mounted at `/tmp` shadows it, as any mount
    // shadows what is under its path.
    let tmp_idx = inode_alloc(INODE_DIR, PERM_READ | PERM_WRITE | PERM_EXEC);
    dir_add_entry(root_idx, b"tmp", tmp_idx)
        .expect("[FS] Failed to create /tmp");
}
