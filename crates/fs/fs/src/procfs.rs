// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Procfs + Sysfs — virtual read-only filesystems (F21).
//!
//! Exposes kernel internals as synthetic text files, following the Linux
//! `/proc` and `/sys` conventions.  Files are generated on-the-fly by
//! registered providers; no persistent storage is needed.
//!
//! ## `/proc` entries
//!
//! | Path            | Content                                          |
//! |-----------------|--------------------------------------------------|
//! | `/proc/uptime`  | Seconds.milliseconds since boot                 |
//! | `/proc/meminfo` | PMM total/free/used pages in kB                 |
//! | `/proc/fs`      | TmpFS file count, used/max bytes                |
//! | `/proc/<tid>`   | One task's line, through [`procfs_register_tid`] (wave 12) |
//!
//! ## `/sys` entries
//!
//! | Path             | Content                                         |
//! |------------------|-------------------------------------------------|
//! | `/sys/version`   | Kernel version string + platform name           |
//! | `/sys/platform`  | Short platform name (QEMU / VF2 / K1)          |
//!
//! ## Usage
//! ```rust
//! procfs_init();                       // register built-in providers
//! let mut buf = [0u8; 512];
//! let n = procfs_read(b"/proc/uptime", &mut buf);
//! ```

extern crate alloc;

use azos_sync::SpinLock;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of registered virtual files (procfs + sysfs combined).
pub const PROCFS_MAX_ENTRIES: usize = 32;
/// Maximum path length for a virtual file path component (no leading slash).
pub const PROCFS_PATH_LEN:    usize = 48;

// ── Entry type ────────────────────────────────────────────────────────────────

/// Virtual-filesystem namespace.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcNs {
    Proc,
    Sys,
}

struct ProcEntry {
    path:     [u8; PROCFS_PATH_LEN],
    path_len: u8,
    ns:       ProcNs,
    gen:      fn(&mut [u8]) -> usize,
    active:   bool,
}

const EMPTY_ENTRY: ProcEntry = ProcEntry {
    path: [0; PROCFS_PATH_LEN],
    path_len: 0,
    ns: ProcNs::Proc,
    gen: |_| 0,
    active: false,
};

// ── Global table ──────────────────────────────────────────────────────────────

struct ProcfsState {
    entries: [ProcEntry; PROCFS_MAX_ENTRIES],
    count:   usize,
}

impl ProcfsState {
    const fn new() -> Self {
        ProcfsState { entries: [EMPTY_ENTRY; PROCFS_MAX_ENTRIES], count: 0 }
    }
}

static PROCFS: SpinLock<ProcfsState> = SpinLock::new(ProcfsState::new());

// ── Public API ────────────────────────────────────────────────────────────────

/// Register a virtual file.
///
/// `path` is relative to the namespace root (e.g. `b"uptime"` for `/proc/uptime`).
/// `gen` is called each time the file is read; it must fill `buf` and return bytes written.
/// Returns `false` if the table is full or `path` is too long.
pub fn procfs_register(ns: ProcNs, path: &[u8], gen: fn(&mut [u8]) -> usize) -> bool {
    if path.len() >= PROCFS_PATH_LEN { return false; }
    let mut state = PROCFS.lock();
    if state.count >= PROCFS_MAX_ENTRIES { return false; }
    let slot = match state.entries.iter().position(|e| !e.active) {
        Some(s) => s,
        None    => return false,
    };
    let e = &mut state.entries[slot];
    e.path[..path.len()].copy_from_slice(path);
    e.path_len = path.len() as u8;
    e.ns       = ns;
    e.gen      = gen;
    e.active   = true;
    state.count += 1;
    true
}

/// Read a virtual file into `buf`.
///
/// `full_path` must include the namespace prefix (`/proc/` or `/sys/`).
/// Returns bytes written to `buf`, or 0 if the path is not found.
pub fn procfs_read(full_path: &[u8], buf: &mut [u8]) -> usize {
    let (ns, rel) = if full_path.starts_with(b"/proc/") {
        (ProcNs::Proc, &full_path[6..])
    } else if full_path.starts_with(b"/sys/") {
        (ProcNs::Sys, &full_path[5..])
    } else {
        return 0;
    };

    // Look up the generator without holding the lock during generation.
    let gen_fn = {
        let state = PROCFS.lock();
        let mut found = None;
        for e in state.entries.iter() {
            if !e.active || e.ns != ns { continue; }
            let plen = e.path_len as usize;
            if &e.path[..plen] == rel { found = Some(e.gen); break; }
        }
        found
    };

    match gen_fn {
        Some(f) => f(buf),
        None if ns == ProcNs::Proc => match parse_tid_name(rel) {
            Some(tid) => {
                let p = TID_GEN.load(core::sync::atomic::Ordering::Acquire);
                if p == 0 {
                    return 0;
                }
                // SAFETY: the only non-zero value ever stored is a
                // `ProcTidGen` (`procfs_register_tid`); fn pointers are
                // `usize`-sized.
                let f: ProcTidGen = unsafe { core::mem::transmute::<usize, ProcTidGen>(p) };
                f(tid, buf)
            }
            None => 0,
        },
        None    => 0,
    }
}

/// The `/proc/<tid>` provider (wave 12), as a function address; 0 = none.
static TID_GEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// What [`procfs_register_tid`] installs: the file for one TID into the
/// buffer, its length, or 0 for "no such file". The kernel's returns 0 for a
/// TID the reader may not see as for one that does not exist (owner round 48,
/// Linux `hidepid=2`), so a hidden task is not even visible by path.
pub type ProcTidGen = fn(u32, &mut [u8]) -> usize;

/// Install the `/proc/<tid>` provider. A name registered with
/// [`procfs_register`] wins over it, so `/proc/tasks` is never a TID.
pub fn procfs_register_tid(gen: ProcTidGen) {
    TID_GEN.store(gen as usize, core::sync::atomic::Ordering::Release);
}

/// The TID a `/proc` name spells, if it spells one: decimal digits only, no
/// sign, no leading zero (`007` is not `7`: one task, one path), nonzero,
/// and inside `u32`.
pub fn parse_tid_name(name: &[u8]) -> Option<u32> {
    if name.is_empty() || name.len() > 10 || name[0] == b'0' {
        return None;
    }
    let mut v: u64 = 0;
    for &c in name {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    u32::try_from(v).ok()
}

/// List all registered paths by calling `cb(full_path_str)` for each entry.
///
/// Each entry is copied out under its own PROCFS hold and `cb` runs with the
/// lock released: `cb` prints (the shell's `ls`), and a SpinLock is never
/// held across a caller's code. An entry registered or removed meanwhile may
/// or may not be listed, as with any directory read.
pub fn procfs_ls(mut cb: impl FnMut(&str)) {
    const PREFIX_MAX: usize = 6; // "/proc/"
    for i in 0..PROCFS_MAX_ENTRIES {
        let (path, plen, ns) = {
            let state = PROCFS.lock();
            let e = &state.entries[i];
            if !e.active { continue; }
            (e.path, (e.path_len as usize).min(PROCFS_PATH_LEN), e.ns)
        };
        let prefix: &[u8] = match ns { ProcNs::Proc => b"/proc/", ProcNs::Sys => b"/sys/" };
        let mut full = [0u8; PREFIX_MAX + PROCFS_PATH_LEN];
        full[..prefix.len()].copy_from_slice(prefix);
        full[prefix.len()..prefix.len() + plen].copy_from_slice(&path[..plen]);
        if let Ok(s) = core::str::from_utf8(&full[..prefix.len() + plen]) {
            cb(s);
        }
    }
}

/// Number of registered virtual-file entries.
pub fn procfs_count() -> usize { PROCFS.lock().count }

// ── Built-in provider registration ───────────────────────────────────────────

/// Register all built-in `/proc` and `/sys` providers.
/// Call once from `kernel_main` after all subsystems are initialized.
pub fn procfs_init() {
    procfs_register(ProcNs::Proc, b"uptime",  gen_uptime);
    procfs_register(ProcNs::Proc, b"meminfo", gen_meminfo);
    procfs_register(ProcNs::Proc, b"fs",      gen_fs);
    procfs_register(ProcNs::Sys,  b"version", gen_version);
    procfs_register(ProcNs::Sys,  b"platform",gen_platform);
}

// ── Generator functions ───────────────────────────────────────────────────────

fn write_str(buf: &mut [u8], s: &str) -> usize {
    let b = s.as_bytes();
    let n = b.len().min(buf.len());
    buf[..n].copy_from_slice(&b[..n]);
    n
}

fn gen_uptime(buf: &mut [u8]) -> usize {
    // Read RISC-V `time` CSR (rdtime pseudo-instruction, S-mode readable).
    // Non-riscv64 builds (host unit tests) have no rdtime; substitute 0.
    #[cfg(target_arch = "riscv64")]
    let ticks: u64 = { let t: u64; unsafe { core::arch::asm!("rdtime {}", out(reg) t); } t };
    #[cfg(not(target_arch = "riscv64"))]
    let ticks: u64 = 0;

    let freq = azos_drv_base::platform::hw::TIMER_FREQ;
    let secs  = ticks / freq;
    let msecs = (ticks % freq) * 1000 / freq;
    let s = alloc::format!("{}.{:03}\n", secs, msecs);
    write_str(buf, &s)
}

fn gen_meminfo(buf: &mut [u8]) -> usize {
    // The PMM counts base pages: 4 KiB, or the aarch64 granule
    // (config/Kconfig.arch PAGE_SHIFT).
    const PAGE_KIB: usize = (1usize << azos_limits::PAGE_SHIFT) / 1024;
    let total_kib = azos_mm::pmm::total_pages() * PAGE_KIB;
    let free_kib  = azos_mm::pmm::free_pages()  * PAGE_KIB;
    let used_kib  = azos_mm::pmm::used_pages()  * PAGE_KIB;
    let s = alloc::format!(
        "MemTotal: {} kB\nMemFree:  {} kB\nMemUsed:  {} kB\n",
        total_kib, free_kib, used_kib
    );
    write_str(buf, &s)
}

fn gen_fs(buf: &mut [u8]) -> usize {
    let (files, used, max) = crate::tmpfs::tmpfs_stats();
    let s = alloc::format!(
        "tmpfs_files: {}\ntmpfs_used:  {} B\ntmpfs_max:   {} B\n",
        files, used, max
    );
    write_str(buf, &s)
}

fn gen_version(buf: &mut [u8]) -> usize {
    let s = alloc::format!(
        "AzOS 0.1.0 ({})\n",
        azos_drv_base::platform::hw::PLATFORM_NAME
    );
    write_str(buf, &s)
}

fn gen_platform(buf: &mut [u8]) -> usize {
    let s = alloc::format!("{}\n", azos_drv_base::platform::hw::PLATFORM_NAME);
    write_str(buf, &s)
}

// ── The VFS backend ───────────────────────────────────────────────────────────

/// `FS_TYPE_*` tag for the synthetic namespaces.
pub const FS_TYPE_PROCFS: u32 = 3;

/// procfs/sysfs as a value the VFS can be handed.
///
/// Unlike the other two backends this one is **not** zero-sized: it carries
/// which namespace it serves. That is the point of making the filesystem a
/// value — `/proc` and `/sys` are the same code with different configuration,
/// and they mount as two values rather than as two branches.
///
/// **Not mounted by `vfs::init()`**: `open("/proc/uptime")` returns -1 today
/// and this change does not alter that. Mounting is
/// `vfs_mount_fs(b"/proc", &PROCFS_FS)`.
pub struct ProcFs {
    ns: ProcNs,
}

/// The `/proc` backend, as a value.
pub static PROCFS_FS: ProcFs = ProcFs { ns: ProcNs::Proc };
/// The `/sys` backend, as a value.
pub static SYSFS_FS:  ProcFs = ProcFs { ns: ProcNs::Sys };

/// Largest synthetic file this backend will materialise for the VFS.
///
/// The built-in generators format a handful of numbers; the longest file is
/// the kernel's `/proc/tasks` (wave 12, one ~30-byte line per task), which
/// cuts its list to fit and says so. It bounds a stack buffer, so it is a
/// kernel-stack cost: 2 KiB of the task's kernel stack while a procfs file
/// is stat'd or read, about 60 task lines.
pub const PROCFS_MAX_FILE: usize = 2048;

impl ProcFs {
    /// Rebuild the full path `procfs_read` expects from a relative key.
    ///
    /// `key_for` never makes a key of `PROCFS_PATH_LEN` bytes or more; a
    /// longer key (only a caller building one by hand can make one) yields
    /// the empty path, which names no provider, rather than being written
    /// past `out` or cut into some other file's name.
    fn full_path(&self, key: &crate::vfs::InodeKey, out: &mut [u8; 64]) -> usize {
        let prefix: &[u8] = match self.ns {
            ProcNs::Proc => b"/proc/",
            ProcNs::Sys  => b"/sys/",
        };
        let name = {
            let n = key.bytes.iter().position(|&b| b == 0)
                .unwrap_or(crate::vfs::INODE_KEY_LEN);
            &key.bytes[..n]
        };
        if prefix.len() + name.len() > out.len() { return 0; }
        out[..prefix.len()].copy_from_slice(prefix);
        out[prefix.len()..prefix.len() + name.len()].copy_from_slice(name);
        prefix.len() + name.len()
    }
}

/// `full_path`'s 64-byte buffer holds the longer prefix (`/proc/`) and the
/// longest name `key_for` accepts.
const _: () = assert!(6 + PROCFS_PATH_LEN - 1 <= 64);
/// The generic key holds the longest name `key_for` accepts.
const _: () = assert!(PROCFS_PATH_LEN - 1 <= crate::vfs::INODE_KEY_LEN);

impl crate::vfs::FileSystem for ProcFs {
    /// RAM-resident: no device wait (owner rule F1 does not apply).
    fn device_backed(&self) -> bool { false }

    #[inline]
    fn fs_type(&self) -> u32 { FS_TYPE_PROCFS }

    /// The providers register themselves through `procfs_init`, which the
    /// kernel already calls. Nothing to do here, and calling `procfs_init`
    /// would register them a second time.
    #[inline]
    fn mount(&self) -> Result<(), ()> { Ok(()) }

    /// Synthetic files are generated on read; there is nothing held back.
    #[inline]
    fn sync(&self) -> Result<(), ()> { Ok(()) }

    #[inline]
    fn key_for(&self, name: &[u8]) -> Option<crate::vfs::InodeKey> {
        // Bounded by what can be registered, not by the generic key (64
        // bytes since wave 10): `procfs_register` refuses a relative path of
        // `PROCFS_PATH_LEN` (48) or more, so a longer name names nothing. It
        // is also what keeps `full_path`'s prefix + name inside its 64-byte
        // buffer (6 + 47 = 53).
        if name.is_empty() || name.len() >= PROCFS_PATH_LEN { return None; }
        if name.contains(&b'/') { return None; }
        let mut bytes = [0u8; crate::vfs::INODE_KEY_LEN];
        bytes[..name.len()].copy_from_slice(name);
        Some(crate::vfs::InodeKey { bytes })
    }

    /// **A procfs `stat` has to generate the file to know its size.** There is
    /// no stored length: the content is produced by a function each time it is
    /// read. `cookie` is unused; the VFS calls `read_all` straight after and
    /// the generator runs twice, which is the honest cost of `stat` on a
    /// synthetic filesystem, not an artefact of this trait.
    #[inline]
    fn stat(&self, key: &crate::vfs::InodeKey) -> Option<crate::vfs::FileStat> {
        let mut path = [0u8; 64];
        let n = self.full_path(key, &mut path);
        let mut scratch = [0u8; PROCFS_MAX_FILE];
        let len = procfs_read(&path[..n], &mut scratch);
        if len == 0 { return None; }
        Some(crate::vfs::FileStat::file(len as u64, 0))
    }

    #[inline]
    fn read_all(
        &self,
        key: &crate::vfs::InodeKey,
        _st: &crate::vfs::FileStat,
        dst: &mut [u8],
    ) -> usize {
        let mut path = [0u8; 64];
        let n = self.full_path(key, &mut path);
        procfs_read(&path[..n], dst)
    }

    /// Read-only, as `/proc` and `/sys` are here: there is no registered
    /// setter and no storage to write to.
    #[inline]
    fn write_all(&self, _key: &crate::vfs::InodeKey, _src: &[u8]) -> Result<(), ()> {
        Err(())
    }

    /// A synthetic entry is unregistered, not unlinked, and nothing exposes
    /// unregistration.
    #[inline]
    fn unlink(&self, _key: &crate::vfs::InodeKey) -> Result<(), ()> { Err(()) }

    /// There is no stored buffer to slice: the generator runs into a
    /// `PROCFS_MAX_FILE` scratch buffer (the same one `stat` uses) and this
    /// copies the `[offset, offset + dst.len())` window out of it. Every
    /// built-in provider's whole output already fits `PROCFS_MAX_FILE`, so
    /// this is not a second `read_all`-sized allocation on top of a first —
    /// it is the same one `read_all` already paid, with `stat` still paying
    /// its own (documented on `stat` above: the generator runs twice, once
    /// there, once here).
    #[inline]
    fn read_at(&self, key: &crate::vfs::InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        let mut path = [0u8; 64];
        let n = self.full_path(key, &mut path);
        let mut scratch = [0u8; PROCFS_MAX_FILE];
        let len = procfs_read(&path[..n], &mut scratch);
        if offset >= len as u64 { return 0; }
        let offset = offset as usize;
        let n_copy = dst.len().min(len - offset);
        dst[..n_copy].copy_from_slice(&scratch[offset..offset + n_copy]);
        n_copy
    }

    /// Read-only, same as `write_all`.
    #[inline]
    fn write_at(&self, _key: &crate::vfs::InodeKey, _offset: u64, _src: &[u8]) -> Result<usize, ()> {
        Err(())
    }
}
