// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_SPAWN` (17): start a new process from the image at a path (RFC-0043).
//!
//! In order:
//!
//! 1. The path is copied from user memory and the file read into
//!    `EXEC_BOUNCE`, as `sys_execpath` does. A file that does not fit is not
//!    read at all.
//! 2. The bytes' SHA-256 picks the plan (`azos_sched::spawn_policy`): the
//!    image's own filter and the topology task named after the image. An
//!    image no profile is bound to is refused with `EACCES` and recorded as a
//!    ring-3 exec refusal, before any address space exists.
//! 3. The child is created parked, under that filter, with the caller as its
//!    parent (`azos_sched::spawn::spawn_prepare`). `EXEC_BOUNCE` is
//!    released here.
//! 3a. An image the signed topology has no row for is refused with `EACCES`
//!    (owner decision 2026-09-28), with a console line and a
//!    `SAFETY_EXEC_REFUSED` record (action [`SPAWN_REFUSED_ACTION_NO_ROW`]),
//!    before any address space exists. A spawned process is admitted, budgeted,
//!    counted and granted by its row; one without a row used to start with no
//!    capabilities, the default budget and no instance count.
//! 4. Its capabilities are seeded from that row, by the child's TID.
//! 5. It is released (`spawn_release`), and its TID returned. The parent reaps
//!    it with `wait`, `wait_status` or `waitpid`.

use crate::file_ops::file_ops;
use crate::handlers::EXEC_BOUNCE;

/// A spawn that succeeds prints nothing unless this is on (owner: kernel
/// console output only in debug modes): `[SPAWN] tid=...` and a
/// `[SPAWN][PRIO]` line that applied the row's priority as declared.
/// Refusals, priority floors and aborts always print. Cargo feature
/// `spawn-log` (kernel `spawn-log`) until a kernel-wide log level replaces
/// it.
const SPAWN_LOG: bool = cfg!(feature = "spawn-log");

/// `SAFETY_EXEC_REFUSED` action code for a `SYS_SPAWN` refused because the
/// topology has no row named after the image. 0 = autorun, 1 = shell `exec`,
/// 2 = ring-3 `SYS_EXEC`/`SYS_EXECPATH`, 3 = shell `spawn`.
pub const SPAWN_REFUSED_ACTION_NO_ROW: u8 = 4;
/// RFC-0047 stage 3: a streamed image's bytes at load did not hash to the
/// digest it was planned by (the file changed between the two reads).
pub const SPAWN_REFUSED_ACTION_STREAM_DIGEST: u8 = 6;

/// `SYS_SPAWN`: a0 = pointer to a NUL-terminated path. Returns the child's
/// TID; `-EACCES` for a file bound to no image profile, or for an image the
/// topology has no row for; `-1` for a bad
/// pointer, a file that cannot be read whole, an image the loader refuses, or
/// a full task pool.
pub fn sys_spawn(path_ptr: u64) -> i64 {
    if path_ptr == 0 { return -1; }

    let mut path_buf = [0u8; 256];
    if azos_sched::copy_cstr_from_user(&mut path_buf, path_ptr as usize).is_none() {
        return -1;
    }
    let path_len = path_buf.iter().position(|&b| b == 0).unwrap_or(0);
    if path_len == 0 { return -1; }
    spawn_path(&path_buf[..path_len])
}

/// Steps 1 (after the path copy) to 5 of [`sys_spawn`], for a path already in
/// kernel memory. The kernel's own callers are the boot-time ring-3 driver
/// launcher (`ring3_driver_launch_task`) and the behavior task starting its ML
/// service (`kernel/src/behavior_ml.rs`): the child is exactly what a ring-3
/// `SYS_SPAWN` of the same file would start — its image's digest-bound filter,
/// row, class, frame budget and capabilities — with the calling kernel task as
/// its parent. Returns the child's TID, or what `SYS_SPAWN` returns.
pub fn spawn_path(path: &[u8]) -> i64 {
    spawn_path_hooked(path, &mut |_| {})
}

/// [`spawn_path`], with `before_release` called with the child's TID once its
/// capabilities are seeded and BEFORE it is released: the child has run no
/// user instruction yet, so whatever the hook records about it (the kernel's
/// supervisor, `kernel/src/drv_supervisor.rs`) is in place before the child
/// can register anything, fault or exit. Not called when no child was
/// created.
pub fn spawn_path_hooked(path: &[u8], before_release: &mut dyn FnMut(u32)) -> i64 {
    match spawn_path_ex(path, &mut |_| true, &mut |child| {
        before_release(child.tid());
        true
    }) {
        SpawnEx::Started(tid) => tid as i64,
        SpawnEx::Failed(rc) => rc,
        // Neither hook above says no.
        SpawnEx::Refused | SpawnEx::Aborted => -1,
    }
}

/// An image read for a spawn or an exec: its length and digest, and, when it
/// is larger than the bounce buffer, the descriptor it is streamed through
/// again ([`with_elf`]).
pub(crate) struct ImageRead {
    pub total: usize,
    pub digest: [u8; 32],
    /// Wave 14 (SPAWNCACHE): the digest came from the verified-image cache.
    pub hit: bool,
    /// The content stamp the bytes were read under, when it held across the
    /// read: what a kept image of them is keyed by.
    pub stamp: Option<crate::file_ops::ContentStamp>,
    streamed: bool,
    file: ImageFile,
}

/// Read the image at `path` into `buf` (the exec bounce buffer), or, when it
/// is larger (RFC-0047 stage 3), hash it through a descriptor and keep its
/// first [`STREAM_HDR_BYTES`] at the start of `buf`.
///
/// Wave 14 (SPAWNCACHE): an image that fits is read by
/// `image_cache::read_verified` (cached digest, or hashed in the same pass).
/// A streamed image whose digest is cached is not hashed here: its load
/// hashes every byte it copies and refuses unless they hash to that digest.
pub(crate) fn read_image(ops: &dyn crate::file_ops::FileOps, path: &[u8], buf: &mut [u8]) -> Result<ImageRead, i64> {
    let size = ops.stat(path).map(|st| st.size as usize).unwrap_or(0);
    let mut file = ImageFile { fd: -1 };
    if size <= buf.len() {
        let v = crate::image_cache::read_verified(ops, path, buf)?;
        return Ok(ImageRead { total: v.total, digest: v.digest, hit: v.hit, stamp: v.stamp, streamed: false, file });
    }
    if size > STREAM_MAX_BYTES {
        azos_drv_sys::kwarn!("[SPAWN] REFUSED: image of {} bytes exceeds {}", size, STREAM_MAX_BYTES);
        return Err(azos_abi::error::Errno::ENOMEM.to_syscall_ret());
    }
    let stamp = ops.content_stamp(path).filter(|s| s.size == size as u64);
    let known = stamp.as_ref().and_then(crate::image_cache::digest_for);
    file.fd = ops.open(path, 0) as i32;
    if file.fd < 0 { return Err(-1); }
    let (hdr, chunk) = buf.split_at_mut(STREAM_HDR_BYTES);
    if let Some(digest) = known {
        if file.read_full(ops, hdr) != hdr.len() { return Err(-1); }
        return Ok(ImageRead { total: size, digest, hit: true, stamp, streamed: true, file });
    }
    let mut h = azos_sched::seccomp::ImageHasher::new();
    let mut off = 0usize;
    while off < size {
        let want = chunk.len().min(size - off);
        if file.read_full(ops, &mut chunk[..want]) != want { return Err(-1); }
        if off == 0 {
            let n = want.min(hdr.len());
            hdr[..n].copy_from_slice(&chunk[..n]);
        }
        h.update(&chunk[..want]);
        off += want;
    }
    let digest = h.finalize();
    // Remembered only if no write of the volume overlapped the pass.
    let held = stamp.filter(|s| ops.content_stamp(path) == Some(*s));
    if let Some(s) = held.as_ref() { crate::image_cache::remember(s, &digest); }
    Ok(ImageRead { total: size, digest, hit: false, stamp: held, streamed: true, file })
}

/// Hand `f` the image [`read_image`] read: the bytes in `buf`, or the header
/// and a filler that streams the segments in again and checks that what it
/// copied hashes to `img.digest`.
pub(crate) fn with_elf<R>(
    ops: &dyn crate::file_ops::FileOps,
    img: &ImageRead,
    path: &[u8],
    buf: &mut [u8],
    f: &mut dyn FnMut(azos_sched::spawn::ElfImage<'_>) -> R,
) -> R {
    if !img.streamed {
        return f(azos_sched::spawn::ElfImage::Bytes(&buf[..img.total]));
    }
    let (hdr, chunk) = buf.split_at_mut(STREAM_HDR_BYTES);
    let mut fill = |user_pt: usize| -> bool {
        if ops.lseek(img.file.fd, 0, 0) != 0 { return false; }
        let mut h = azos_sched::seccomp::ImageHasher::new();
        let mut first = true;
        let mut rd = |_off: usize, dst: &mut [u8]| {
            let n = img.file.read_full(ops, dst);
            // Gate canary only (`stream-hash-flip-canary`): the file changes
            // between the two reads; one byte of the copy differs from what
            // was hashed to plan the image.
            if cfg!(feature = "stream-hash-flip-canary") && first && n > 0 {
                dst[n - 1] ^= 0x01;
            }
            first = false;
            n
        };
        if !azos_sched::process::fill_elf_segments(user_pt, hdr, img.total, chunk, &mut rd, &mut h) {
            return false;
        }
        // The bytes now in memory must be the bytes the image was planned
        // (and its profile and row chosen) by. Compiled out only by the gate
        // canary that proves this check is what refuses.
        if cfg!(feature = "stream-hash-nocheck-canary") || h.finalize() == img.digest {
            return true;
        }
        let head = u32::from_be_bytes([img.digest[0], img.digest[1], img.digest[2], img.digest[3]]);
        let recorded = crate::handlers::record_exec_refused_recorded(SPAWN_REFUSED_ACTION_STREAM_DIGEST, head);
        azos_drv_sys::kwarn!(
            "[SPAWN] REFUSED: {} changed between its hash and its load (digest mismatch){}",
            core::str::from_utf8(path).unwrap_or("?"),
            if recorded { " (recorded)" } else { "" },
        );
        false
    };
    f(azos_sched::spawn::ElfImage::Streamed { hdr: &hdr[..], len: img.total, fill: &mut fill })
}

/// RFC-0047 stage 3: the first bytes of a streamed image kept for its ELF and
/// program headers. Its program header table must lie inside them.
const STREAM_HDR_BYTES: usize = 4096;
/// The largest image a spawn streams (a static BusyBox is about 1 MiB).
const STREAM_MAX_BYTES: usize = 8 * 1024 * 1024;

/// A descriptor a streamed spawn reads its image through, closed on every
/// exit.
struct ImageFile {
    fd: i32,
}

impl ImageFile {
    /// Read until `dst` is full or the file ends; the bytes read.
    fn read_full(&self, ops: &dyn crate::file_ops::FileOps, dst: &mut [u8]) -> usize {
        let mut n = 0;
        while n < dst.len() {
            let r = ops.read(self.fd, &mut dst[n..]);
            if r <= 0 { break; }
            n += r as usize;
        }
        n
    }
}

impl Drop for ImageFile {
    fn drop(&mut self) {
        if self.fd >= 0 {
            if let Some(o) = file_ops() { let _ = o.close(self.fd); }
        }
    }
}

/// Where a spawn's image comes from (wave 14, SPAWNCACHE).
enum Source {
    /// Frames an earlier spawn of the same, unchanged bytes kept.
    Kept(crate::image_cache::Pinned),
    /// The file, read now.
    Read(ImageRead),
}

/// What [`spawn_path_ex`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnEx {
    /// The child was released; its TID.
    Started(u32),
    /// `authorize` said no: no child was created.
    Refused,
    /// `before_release` said no: the child was released into an immediate
    /// exit (`spawn_abort`) and runs no user instruction.
    Aborted,
    /// What `SYS_SPAWN` returns on its own refusals.
    Failed(i64),
}

/// [`spawn_path_hooked`] with two more hooks, for `SYS_SPAWN_EX` (RFC-0055):
/// `authorize(image)` after the digest and the topology row are known and
/// before any address space exists (the launch grant), and a
/// `before_release` that may write into the parked child (its startup block,
/// its moved handles) and may refuse, which aborts it.
pub fn spawn_path_ex(
    path: &[u8],
    authorize: &mut dyn FnMut(&str) -> bool,
    before_release: &mut dyn FnMut(&mut azos_sched::spawn::SpawnPrepared) -> bool,
) -> SpawnEx {
    if path.is_empty() { return SpawnEx::Failed(-1); }
    let ops = match file_ops() { Some(o) => o, None => return SpawnEx::Failed(-1) };
    let t_entry = census::now();
    let mut cs = census::Local::default();

    // The bytes hashed are the bytes loaded: both happen under one hold of
    // the buffer. The hold ends with the block, before any capability table is
    // touched.
    // Wave 14 (SPAWNCACHE): bytes a spawn already verified and loaded,
    // unchanged since (same stamp), start from the frames that spawn kept:
    // nothing is read or hashed.
    let stamp = if crate::image_cache::FRAME_BUDGET != 0 { ops.content_stamp(path) } else { None };
    let (child, plan, sched, hit) = {
        let mut buf = EXEC_BOUNCE.lock();
        // RFC-0047 stage 3: an image larger than the bounce buffer is read
        // twice through a descriptor: once to hash it (the plan is made by
        // the digest), once to copy its segments in while hashing again; the
        // spawn goes ahead only if the second digest is the first.
        let src = match stamp.as_ref().and_then(crate::image_cache::frames_for) {
            Some(pin) => Source::Kept(pin),
            None => match read_image(ops, path, &mut buf[..]) {
                Ok(i) => Source::Read(i),
                Err(e) => return SpawnEx::Failed(e),
            },
        };
        let (digest, hit) = match &src {
            Source::Kept(p) => (p.digest, true),
            Source::Read(i) => (i.digest, i.hit),
        };
        let t_policy = census::now();
        cs.add(census::READ, t_entry, t_policy);

        let plan = match azos_sched::spawn_policy::plan_spawn(&digest) {
            Ok(plan) => plan,
            Err(errno) => {
                // Recorded by the exec handlers' own check, on the same bytes:
                // it answers no again and writes the record under the per-task
                // bound. A refusal pays a second hash; a spawn pays one.
                let _ = crate::handlers::exec_image_is_bound_by_digest(&digest);
                return SpawnEx::Failed(errno.to_syscall_ret());
            }
        };
        // Owner decision 2026-09-28: no row, no process. Checked before any
        // address space exists, on the key the caps, class and budget below
        // are all looked up by.
        if !has_row(plan.topology_key) {
            let head = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
            azos_drv_sys::kwarn!(
                "[SPAWN] REFUSED: {} has no topology row -- a spawned image must have one",
                plan.topology_key,
            );
            crate::handlers::record_exec_refused(SPAWN_REFUSED_ACTION_NO_ROW, head);
            return SpawnEx::Failed(azos_abi::error::Errno::EACCES.to_syscall_ret());
        }
        // RFC-0055: the caller's authority over THIS image (`SYS_SPAWN_EX`'s
        // launch grant), on the image the bytes resolve to.
        if !authorize(plan.profile.image) {
            return SpawnEx::Refused;
        }
        // Wave 7: the child is CREATED in its row's class and priority, so it
        // is never runnable at the default first. Same key as its caps.
        // Wave 11 SCHED-RT (owner decision): a row in the real-time band with
        // a reservation must also be `mem = "locked"`. Refused before any
        // child exists.
        if crate::topo_sched::row_band_entry(plan.topology_key.as_bytes())
            == Some(azos_topology::BandEntry::NotLocked)
        {
            azos_drv_sys::kwarn!(
                "[SPAWN][SCHED-RT] REFUSED {}: a real-time band row must be mem = \"locked\" -- errno -{}",
                plan.topology_key, azos_abi::error::Errno::EACCES as i32,
            );
            crate::topo_sched::record_refusal(crate::topo_sched::SITE_SPAWN_RT, 0);
            return SpawnEx::Failed(azos_abi::error::Errno::EACCES.to_syscall_ret());
        }
        let sched = crate::topo_sched::resolve(plan.topology_key.as_bytes());
        // Wave 11 SCHED-RT: a row with a real-time profile needs its EDF + CBS
        // reservation admitted. Decided before any child exists, so a refusal
        // is an errno and not a half-made task; the child is created at the
        // ring-3 floor and enters the band only once the reservation is its.
        if let crate::topo_sched::TopoSched::Apply { rt: Some(r), .. } = sched {
            if let Err(why) = azos_sched::rt::check(&r) {
                azos_drv_sys::kwarn!(
                    "[SPAWN][SCHED-RT] REFUSED {}: reservation runtime_us={} period_us={} \
                     deadline_us={} band={} does not fit ({}) -- errno -{}",
                    plan.topology_key, r.runtime_us, r.period_us, r.deadline_us, r.band,
                    why.name(), why.errno(),
                );
                crate::topo_sched::record_refusal(crate::topo_sched::SITE_SPAWN_RT, 0);
                return SpawnEx::Failed(if why.errno() == azos_abi::error::Errno::EINVAL as i32 {
                    azos_abi::error::Errno::EINVAL.to_syscall_ret()
                } else {
                    azos_abi::error::Errno::EBUSY.to_syscall_ret()
                });
            }
        }
        let params = match sched {
            crate::topo_sched::TopoSched::Apply { priority, class, rt: Some(_), .. } =>
                Some((crate::topo_sched::band_refused_priority(priority), class as u8)),
            crate::topo_sched::TopoSched::Apply { priority, class, .. } => Some((priority, class as u8)),
            _ => None,
        };
        // RFC-0049 M1: the child's frame budget, from the same row. A locked
        // row whose image could fork or demand-page is refused (P2).
        let (mem, _) = crate::topo_sched::resolve_mem(plan.profile.image, None);
        if !crate::topo_sched::mem_row_admissible(mem, plan.profile) {
            azos_drv_sys::kwarn!(
                "[SPAWN][MEM] REFUSED {}: a locked row, but its profile can fork or demand-page",
                plan.profile.image,
            );
            return SpawnEx::Failed(azos_abi::error::Errno::EACCES.to_syscall_ret());
        }
        // RFC-0047: a row with `abi = "linux"` makes the child a Linux task,
        // decided here so it is in the slot before the child is runnable.
        // Without Kconfig `LINUX_ABI` such a row is refused, never run native.
        let linux_row = azos_topology::get()
            .is_some_and(|t| t.abi_of(plan.topology_key.as_bytes()) == azos_topology::TaskAbi::Linux);
        if linux_row && !azos_limits::LINUX_ABI {
            azos_drv_sys::kwarn!(
                "[SPAWN] REFUSED: {} is a Linux row and this kernel has no Linux personality (LINUX_ABI=n)",
                plan.profile.image,
            );
            return SpawnEx::Failed(azos_abi::error::Errno::EACCES.to_syscall_ret());
        }
        let t_elf = census::now();
        cs.add(census::POLICY, t_policy, t_elf);
        let prepare = |elf: azos_sched::spawn::ElfImage<'_>| {
            azos_sched::spawn::spawn_prepare(elf, plan.filter, plan.profile.image, params, mem, linux_row)
        };
        let prepared = match &src {
            Source::Kept(p) => prepare(azos_sched::spawn::ElfImage::Cached { pages: &p.pages, kept: p.kept }),
            Source::Read(img) => with_elf(ops, img, path, &mut buf[..], &mut |elf| prepare(elf)),
        };
        cs.add(census::ELF_AS, t_elf, census::now());
        let child = match prepared {
            Ok(child) => child,
            Err(_) => return SpawnEx::Failed(-1),
        };
        // Keep what was just loaded from bytes verified under a stamp that
        // held, before anything writes into the child.
        if let Source::Read(img) = &src {
            if let Some(st) = img.stamp.filter(|_| crate::image_cache::FRAME_BUDGET != 0) {
                let hdr = &buf[..if img.streamed { STREAM_HDR_BYTES } else { img.total }];
                if let Some((pages, kept)) =
                    azos_sched::spawn::capture_image(&child, hdr, crate::image_cache::FRAME_BUDGET)
                {
                    crate::image_cache::keep_frames(&st, &img.digest, pages, kept);
                }
            }
        }
        (child, plan, sched, hit)
    };

    let t_post = census::now();
    let mut child = child;
    let tid = child.tid();
    // The reservation, then the band: never the band without it.
    let sched = match sched {
        crate::topo_sched::TopoSched::Apply { priority, class, declared, floored, rt: Some(r) } => {
            let idx = azos_sched::idx_for_tid(tid).unwrap_or(usize::MAX);
            match azos_sched::rt::reserve(idx, r) {
                Ok(_) => {
                    azos_sched::rt::set_base_priority(idx, priority);
                    crate::topo_sched::TopoSched::Apply { priority, class, declared, floored, rt: Some(r) }
                }
                Err(_) => {
                    // Lost a race with another reservation since `check`:
                    // the child runs at the floor, without one (the refusal
                    // line is `reserve`'s).
                    crate::topo_sched::record_refusal(crate::topo_sched::SITE_SPAWN_RT, tid);
                    crate::topo_sched::TopoSched::Apply {
                        priority: crate::topo_sched::band_refused_priority(priority),
                        class, declared, floored: true, rt: None,
                    }
                }
            }
        }
        other => other,
    };
    match sched {
        crate::topo_sched::TopoSched::Apply { priority, class, declared, floored, .. } => {
            if floored {
                crate::topo_sched::record_refusal(crate::topo_sched::SITE_SPAWN_FLOOR, tid);
            }
            if SPAWN_LOG || floored {
                let t_p = census::now();
                azos_drv_sys::kprintln!(
                    "[SPAWN][PRIO] tid={} row={} class={} declared={} applied={}{}",
                    tid, plan.topology_key, class.name(), declared, priority,
                    if floored { " RAISED to the ring-3 floor" } else { "" },
                );
                cs.add(census::PRINT, t_p, census::now());
            }
        }
        crate::topo_sched::TopoSched::Refused => {
            crate::topo_sched::record_refusal(crate::topo_sched::SITE_SPAWN, tid);
            azos_drv_sys::kwarn!(
                "[SPAWN][PRIO] REFUSED tid={} row={} names a class this build does not schedule \
                 — runs at the default priority",
                tid, plan.topology_key,
            );
        }
        crate::topo_sched::TopoSched::NoRow => {}
    }
    let seeded = seed_caps(tid, plan.topology_key);
    // RFC-0047: the personality's entry, before the caller's hook lays out
    // the stack and the descriptors.
    if child.is_linux() {
        if !crate::linux::proc_init(tid, plan.topology_key, path) {
            azos_drv_sys::kwarn!(
                "[SPAWN] REFUSED: {} -- every Linux personality slot is in use",
                plan.profile.image,
            );
            let _ = azos_sched::spawn::spawn_abort(child);
            return SpawnEx::Failed(azos_abi::error::Errno::ENOMEM.to_syscall_ret());
        }
    }
    if !before_release(&mut child) {
        let _ = azos_sched::spawn::spawn_abort(child);
        azos_drv_sys::kprintln!("[SPAWN] tid={} {} aborted before its first instruction",
            tid, plan.profile.image);
        return SpawnEx::Aborted;
    }
    // A Linux child the hook gave no stack (a plain `SYS_SPAWN`): argv is
    // the image's name, no environment, the console on 0, 1 and 2.
    if child.is_linux() && !child.linux_stack_written() {
        let mut argv = [0u8; 16];
        let name = plan.profile.image.as_bytes();
        let n = name.len().min(argv.len() - 1);
        argv[..n].copy_from_slice(&name[..n]);
        if !child.write_linux_stack(&argv[..n + 1], 1, &[], 0, &crate::linux::random16()) {
            let _ = azos_sched::spawn::spawn_abort(child);
            return SpawnEx::Failed(azos_abi::error::Errno::ENOMEM.to_syscall_ret());
        }
    }
    if !azos_sched::spawn::spawn_release(child) {
        return SpawnEx::Failed(-1);
    }
    let t_p = census::now();
    match seeded {
        Seeded::Caps { minted, skipped } => if SPAWN_LOG {
            azos_drv_sys::kprintln!(
                "[SPAWN] tid={} {} profile, caps minted={} (skipped {})",
                tid, plan.profile.image, minted, skipped,
            )
        },
        // Unreachable since the row check above (the topology is installed
        // once at boot and never removed); said out loud if it ever is.
        Seeded::NoRow | Seeded::NoTopology => azos_drv_sys::kprintln!(
            "[SPAWN] tid={} {} profile, its topology row vanished after the check — \
             starts with no capabilities",
            tid, plan.profile.image,
        ),
    }
    let t_end = census::now();
    cs.add(census::PRINT, t_p, t_end);
    cs.add(census::POST, t_post, t_end);
    cs.done(t_entry, hit);
    SpawnEx::Started(tid)
}

/// `spawn-census` (vsbench diagnostic, off in every build that ships): the
/// cost of each phase of [`spawn_path_ex`], summed over spawns and printed as
/// a per-spawn average, separately for spawns the verified-image cache served
/// (`kind=hit`, every [`census::EVERY`]) and spawns it did not (`kind=miss`,
/// each one). Read under `-icount shift=0`, where a nanosecond of guest time
/// is one guest instruction (riscv64's 10 MHz timer counts in steps of 100).
/// On a miss the image is hashed in the same pass that reads it, so `read`
/// holds both and `sha256` is 0. Without the feature every call below is an
/// empty inline function.
pub mod census {
    pub const READ: usize = 0;
    pub const SHA256: usize = 1;
    pub const POLICY: usize = 2;
    pub const ELF_AS: usize = 3;
    pub const POST: usize = 4;
    pub const PRINT: usize = 5;
    pub const TOTAL: usize = 6;
    pub const EVERY: u64 = 32;

    #[cfg(feature = "spawn-census")]
    mod imp {
        use core::sync::atomic::{AtomicU64, Ordering};
        static ACC: [[AtomicU64; 7]; 2] = [const { [const { AtomicU64::new(0) }; 7] }; 2];
        static N: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
        const NAMES: [&str; 7] = ["read", "sha256", "policy", "elf+as", "post", "print", "total"];
        pub fn now() -> u64 { azos_drv_sys::timebase::now() }
        /// One spawn's phases, committed by [`Local::done`] under its kind.
        #[derive(Default)]
        pub struct Local([u64; 7]);
        impl Local {
            pub fn add(&mut self, i: usize, t0: u64, t1: u64) { self.0[i] += t1.wrapping_sub(t0); }
            pub fn done(mut self, t_entry: u64, hit: bool) {
                self.add(super::TOTAL, t_entry, now());
                let k = hit as usize;
                for (a, v) in ACC[k].iter().zip(self.0.iter()) { a.fetch_add(*v, Ordering::Relaxed); }
                let n = N[k].fetch_add(1, Ordering::Relaxed) + 1;
                let every = if hit { super::EVERY } else { 1 };
                if n % every != 0 { return; }
                let f = azos_drv_sys::timebase::TIMER_FREQ;
                let mut line = [0u64; 7];
                for (j, a) in ACC[k].iter().enumerate() {
                    line[j] = a.swap(0, Ordering::Relaxed).saturating_mul(1_000_000_000 / f) / every;
                }
                azos_drv_sys::kprintln!(
                    "[SPAWN-CENSUS] kind={} spawns={} hits={} misses={} avg_ns {}={} {}={} {}={} {}={} {}={} {}={} {}={}",
                    if hit { "hit" } else { "miss" }, n,
                    N[1].load(Ordering::Relaxed), N[0].load(Ordering::Relaxed),
                    NAMES[0], line[0], NAMES[1], line[1], NAMES[2], line[2], NAMES[3], line[3],
                    NAMES[4], line[4], NAMES[5], line[5], NAMES[6], line[6],
                );
            }
        }
    }
    #[cfg(feature = "spawn-census")]
    pub use imp::{now, Local};

    #[cfg(not(feature = "spawn-census"))]
    #[inline(always)]
    pub fn now() -> u64 { 0 }
    /// One spawn's phases (nothing without `spawn-census`).
    #[cfg(not(feature = "spawn-census"))]
    #[derive(Default)]
    pub struct Local;
    #[cfg(not(feature = "spawn-census"))]
    impl Local {
        #[inline(always)]
        pub fn add(&mut self, _: usize, _: u64, _: u64) {}
        #[inline(always)]
        pub fn done(self, _: u64, _: bool) {}
    }
}

/// What seeding a spawned child's capabilities found.
///
/// Three answers, because `(0, 0)` used to mean all three and a reader could
/// not tell "this image is granted nothing on purpose" from "the topology has
/// no row for this image at all".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seeded {
    /// A row was found and walked.
    Caps {
        /// Capabilities minted into the child's table.
        minted: u32,
        /// Declared capabilities that produced nothing.
        skipped: u32,
    },
    /// No topology task is named after this image. `spawn_policy` sets the
    /// lookup key to `profile.image` (`"UHELLO.ELF"`); [`spawn_path`] refuses
    /// such an image before it gets here.
    NoRow,
    /// No topology is installed at all.
    NoTopology,
}

/// Does the installed topology have a row named `key`? `false` with no
/// topology installed: nothing then admits the image.
fn has_row(key: &str) -> bool {
    azos_topology::get().is_some_and(|topo| {
        topo.find_task(&azos_topology::MaybeStr::from_bytes(key.as_bytes())).is_some()
    })
}

/// Mint the capabilities of the topology task named `key` into `tid`'s table.
///
/// The child is parked and its slot claimed, so these are the first
/// `cap_store` operations for its TID (the ordering `cap_seed` requires).
/// The row is remembered for the task (`natfork::record_row`): a native fork
/// child is seeded from it again.
pub(crate) fn seed_caps(tid: u32, key: &str) -> Seeded {
    if azos_topology::get().is_none() {
        return Seeded::NoTopology;
    }
    let Some(row) = crate::natfork::row_index(key.as_bytes()) else { return Seeded::NoRow };
    crate::natfork::record_row(tid, row);
    seed_row(tid, row)
}

/// Is a capability of `kind` withheld under filter `f`? The brain-link key
/// and the entropy pool go only to a task whose filter LISTS the one call
/// that uses each (the autorun loader's rule, `kernel/src/tasks/loader.rs`);
/// a native fork child is seeded under its parent's filter by it.
pub(crate) fn withheld(kind: azos_abi::cap::CapKind, f: &azos_sched::filter::SyscallFilter) -> bool {
    use azos_abi::syscall_nr::{SYS_ENTROPY_READ_TYPED, SYS_LINK_KEY_READ_TYPED};
    let nr = match kind {
        azos_abi::cap::CapKind::LinkKey => SYS_LINK_KEY_READ_TYPED as u16,
        azos_abi::cap::CapKind::Entropy => SYS_ENTROPY_READ_TYPED as u16,
        _ => return false,
    };
    !f.enabled || !f.allowed[..f.count as usize].contains(&nr)
}

/// Mint row `row`'s capabilities into `tid`'s table. (A native fork child is
/// seeded by `natfork`, from the row's template or these same minters.)
pub(crate) fn seed_row(tid: u32, row: usize) -> Seeded {
    let Some(topo) = azos_topology::get() else { return Seeded::NoTopology };
    let Some(task) = topo.tasks().get(row) else { return Seeded::NoRow };
    use azos_ipc::cap_seed::SeedOutcome;
    let mut minted = 0u32;
    let mut skipped = 0u32;
    for cap in topo.caps_of(task) {
        // O3.4: `transfer = true` in the topology row is the only way a
        // SEEDED (not self-created) capability carries `DUP` — `cap_seed.rs`
        // itself never adds it, so a row that says nothing stays
        // non-transferable, same as a fork-minted endpoint capability.
        let perms = if cap.transfer { cap.perms.union(azos_abi::cap::CapPerms::DUP) } else { cap.perms };
        match azos_ipc::cap_seed::seed_one_cap_outcome(
            tid, cap.kind, perms, cap.target.as_str(),
        ) {
            SeedOutcome::Minted(_) => minted = minted.saturating_add(1),
            // A documented gap, not this topology's fault. Counted, quiet.
            SeedOutcome::NoMinter => skipped = skipped.saturating_add(1),
            // The kind HAS a minter and it said no, so the task is about to
            // run with less authority than its topology declares — a second
            // server on one endpoint name, a full pool, a target that does not
            // parse. Counted as skipped too, but said out loud: this used to
            // be indistinguishable from the line above, and the message blamed
            // "no typed minter yet", which was not true.
            SeedOutcome::Refused => {
                skipped = skipped.saturating_add(1);
                azos_drv_sys::kwarn!(
                    "[SPAWN][CAP-SEED] REFUSED kind={:?} target={} perms={:?} tid={} \
                     — the task runs without a capability its topology declares",
                    cap.kind, cap.target.as_str(), cap.perms, tid,
                );
            }
        }
    }
    Seeded::Caps { minted, skipped }
}
