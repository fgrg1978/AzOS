// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The vDSO and the seams the ring-3 syscall layer calls back into the kernel
//! through, plus the IPC plumbing init.

use crate::*;

/// Allocate and publish the vDSO page (M01): the shared timing page every
/// user process maps read-only at `VDSO_USER_BASE` so ring 3 can read
/// kernel time data without an ecall/svc.
///
/// Shared between both `kernel_main`s (riscv64 called this in place until
/// 2026-09-22; aarch64 never called it at all — `azos_mm::vdso::
/// vdso_phys()` stayed 0 there, so `crates/core/sched/src/process.rs`'s exec
/// path found `vdso_phys != 0` false and silently skipped the map on every
/// aarch64 process; `abitest` then took a page fault the moment it read
/// `VDSO_USER_BASE`, since nothing — not even the ecall fallback the
/// module doc describes — was mapped there at all). `timebase_hz` is the
/// counter frequency, board-specific and read differently per ISA (a
/// compile-time constant on riscv64's OpenSBI-fixed `mtime`; a live
/// `CNTFRQ_EL0` read on aarch64, since QEMU's default has changed across
/// machine versions — see that kernel_main's own `live_hz` comment).
///
/// The `VDSO_FLAG_RDTIME_NATIVE` flag (riscv64's `rdtime`-from-U-mode
/// optimisation, RFC-0041 §A) is NOT set here for aarch64: it is a
/// RISC-V-specific ABI promise about a RISC-V-specific instruction, and
/// aarch64 has no equivalent wired yet. Ring 3 there still gets the vDSO's
/// cooked `uptime_ms`/`uptime_ticks` fields; only the sub-tick-granularity
/// `rdtime` fast path is riscv64-only.
pub(crate) fn install_vdso(timebase_hz: u64) {
    #[cfg(not(feature = "no-mmu"))]
    {
        azos_mm::vdso::vdso_init();
        // Wave 13: the riscv64 sigreturn trampoline Linux handlers return to
        // (a no-op on aarch64 and without the personality).
        if azos_limits::LINUX_ABI {
            azos_mm::vdso::sigtramp_init(&azos_linux_abi::signal::RV_SIGRETURN_CODE);
        }
        azos_mm::vdso::vdso_set_timebase(timebase_hz);
        #[cfg(all(feature = "qemu", not(feature = "vdso-force-syscall"), target_arch = "riscv64"))]
        azos_mm::vdso::vdso_set_flags(azos_mm::vdso::VDSO_FLAG_RDTIME_NATIVE);
        let hwcap = detect_hwcap();
        azos_mm::vdso::vdso_set_hwcap(hwcap);
        kprintln!("[VDSO] Shared timing page ready at user VA {:#x}", azos_mm::vdso::VDSO_USER_BASE);
        print_hwcap(hwcap);
        select_sha256(hwcap);
    }
    #[cfg(feature = "no-mmu")]
    {
        let _ = timebase_hz;
    }
}

/// riscv64: the vDSO `hwcap` bits cpu@0's device-tree ISA declares
/// (`boot_hooks` stores them right after the DTB walk, before
/// [`install_vdso`]). aarch64 reads its ID registers instead.
#[cfg(target_arch = "riscv64")]
pub(crate) static DTB_HWCAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The vDSO `hwcap` word (wave 13; the AT_HWCAP analogue): what this CPU
/// implements, from the ID registers (aarch64) or the device tree (riscv64),
/// never from build flags. The only build-dependent part is V, which also
/// needs a kernel that saves the vector state (`rvv`), as Linux's HWCAP
/// does. Under `hwcap-clear-canary` the bits lxbase.ko keys its CRC path on
/// are cleared, so the gate can prove the fallback is taken.
#[cfg(not(feature = "no-mmu"))]
pub(crate) fn detect_hwcap() -> u64 {
    use azos_abi::vdso::*;
    #[cfg(target_arch = "aarch64")]
    let h = {
        // Kconfig `n` (azos_arch_api::isa::aarch64) hides an extension
        // from ring 3 and from the kernel's own SHA-256 selection below.
        use azos_arch_api::isa::aarch64 as p;
        let f = azos_arch::features::detect();
        [(p::CRC32.gate(f.crc32), HWCAP_A64_CRC32), (p::AES.gate(f.aes), HWCAP_A64_AES),
         (p::PMULL.gate(f.pmull), HWCAP_A64_PMULL), (p::SHA2.gate(f.sha2), HWCAP_A64_SHA2),
         (p::LSE.gate(f.lse), HWCAP_A64_ATOMICS)]
            .iter()
            .fold(0u64, |h, &(on, bit)| if on { h | bit } else { h })
    };
    #[cfg(target_arch = "riscv64")]
    let h = {
        let h = DTB_HWCAP.load(core::sync::atomic::Ordering::Acquire);
        if cfg!(feature = "rvv") { h } else { h & !HWCAP_RV_V }
    };
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    let h = 0u64;
    #[cfg(feature = "hwcap-clear-canary")]
    let h = h & !(HWCAP_A64_CRC32 | HWCAP_RV_ZBC);
    h
}

/// riscv64 boot: record cpu@0's device-tree ISA for [`detect_hwcap`].
#[cfg(target_arch = "riscv64")]
pub(crate) fn note_dtb_isa(zbb: bool, zbc: bool, zknh: bool, v: bool) {
    use azos_abi::vdso::*;
    let mut h = 0u64;
    for (on, bit) in [(zbb, HWCAP_RV_ZBB), (zbc, HWCAP_RV_ZBC), (zknh, HWCAP_RV_ZKNH), (v, HWCAP_RV_V)] {
        if on {
            h |= bit;
        }
    }
    DTB_HWCAP.store(h, core::sync::atomic::Ordering::Release);
}

/// The kernel's SHA-256 (module verify, image digests) on the CPU's SHA-2
/// instructions when the hwcap word says it has them (wave 13): aarch64
/// FEAT_SHA256, riscv64 Zknh, else riscv64 Zbb rotates, else generic. Each
/// path is kept only after its self-test (`azos_crypto::sha256`). Runs
/// once, at boot, before anything else hashes.
#[cfg(not(feature = "no-mmu"))]
fn select_sha256(h: u64) {
    use azos_abi::vdso::*;
    #[cfg(target_arch = "aarch64")]
    let name = if h & HWCAP_A64_SHA2 != 0 && azos_crypto::sha256::select_hook(sha256_ce) {
        "armv8-ce"
    } else {
        "generic"
    };
    #[cfg(target_arch = "riscv64")]
    let name = azos_crypto::sha256::select_riscv(h & HWCAP_RV_ZBB != 0, h & HWCAP_RV_ZKNH != 0);
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    let name = { let _ = h; "generic" };
    kprintln!("[CRYPTO] sha256 blocks: {}", name);
}

/// aarch64: FEAT_SHA256 blocks with the SIMD registers taken from ring 3
/// for at most 16 blocks (1 KiB) at a time, IRQs masked meanwhile.
#[cfg(all(target_arch = "aarch64", not(feature = "no-mmu")))]
fn sha256_ce(state: &mut [u32; 8], blocks: &[u8]) {
    for run in blocks.chunks(16 * 64) {
        // SAFETY: selected only when ID_AA64ISAR0_EL1 reports FEAT_SHA256;
        // `with_kernel_simd` frees the SIMD registers and masks IRQs.
        crate::entry::aarch64::fp_lazy::with_kernel_simd(|| unsafe {
            azos_arch::sha2_ce::sha256_blocks(state, run)
        });
    }
}

#[cfg(not(feature = "no-mmu"))]
fn print_hwcap(h: u64) {
    use azos_abi::vdso::*;
    let names: [(u64, &str); 9] = [
        (HWCAP_A64_CRC32, "crc32"), (HWCAP_A64_AES, "aes"), (HWCAP_A64_PMULL, "pmull"),
        (HWCAP_A64_SHA2, "sha2"), (HWCAP_A64_ATOMICS, "atomics"), (HWCAP_RV_ZBB, "zbb"),
        (HWCAP_RV_ZBC, "zbc"), (HWCAP_RV_V, "v"), (HWCAP_RV_ZKNH, "zknh"),
    ];
    let mut buf = [0u8; 64];
    let mut n = 0;
    for (bit, name) in names {
        if h & bit != 0 && n + name.len() + 1 <= buf.len() {
            buf[n] = b' ';
            buf[n + 1..n + 1 + name.len()].copy_from_slice(name.as_bytes());
            n += 1 + name.len();
        }
    }
    kprintln!("[VDSO] hwcap={:#x}:{}", h, core::str::from_utf8(&buf[..n]).unwrap_or(""));
}

/// Ring-3-facing seams every board installs once, at the same relative
/// point in boot, on either ISA: the ramfs root, the `FileOps` seam behind
/// `SYS_OPEN`/`SYS_SPAWN`/`SYS_FILE_OPEN_TYPED` (`crates/core/syscall`'s
/// `file_ops` module), the actuation gate, and the io_ring motor/PWM ops.
///
/// **Why this exists.** riscv64's `kernel_main` used to inline all of this
/// directly in its own body; aarch64's never called any of it — not a
/// deliberate omission, just code nobody ported. `crates/core/syscall::file_ops`
/// returns `-1` from every entry point until [`azos_syscall::file_ops::
/// set_file_ops`] runs (see that module's doc), which is exactly the
/// failure this task found: `SYS_OPEN` (and `SYS_SPAWN`, which reads the
/// child image through the same seam) failing on aarch64 with a FAT32
/// volume correctly mounted underneath it. `azos_safety_core::actuation
/// ::install()` was the same story for the e-stop gate. Hoisted here, once,
/// so both ISAs call the identical code rather than growing a second copy —
/// the seams this touches are core (`crates/core/syscall`, `domains/robot/safety-core`,
/// `crates/core/ipc`), never per-ISA.
///
/// `#[inline(always)]`: riscv64's `kernel_main` used to have this inlined
/// directly, and every function body inside (`KernelFileOps`'s methods,
/// `fd_caller_may_use`, `fd_quota_available`) is unchanged byte-for-byte —
/// only their enclosing scope moved. Forcing the inline keeps riscv64's
/// codegen at that call site the same as before this hoist; without it the
/// compiler is free to leave a real call there instead.
/// `lat-fat`: where `KERNEL_FD_TABLE` lives, so the F1 report names it.
#[cfg(feature = "lat-fat")]
pub(crate) static FD_TABLE_ADDR: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[inline(always)]
pub(crate) fn install_ring3_seams() {
    azos_fs::init();
    kprintln!("[FS] ramfs initialized");

    // The filesystem behind the file syscalls.
    //
    // `crates/core/syscall` is core — it is the gate ring 3 passes through to reach
    // the motors — and `crates/fs/fs` is scaffolding, so the syscall crate names a
    // `FileOps` trait and the kernel, the composition root, supplies the VFS
    // behind it. Same shape as `KernelUdp` for the TFTP fetch loop and
    // `KernelLogStorage` for the flight recorder; this one closed the last of
    // the three TCB violations.
    //
    // Installed HERE, above the FAT32 block and not inside it: `/fat` is one
    // filesystem among several, and ramfs, tmpfs and procfs all answer file
    // syscalls on a board with no disk at all. Installing on mount success
    // would have made `open` return -1 in every scenario that boots without a
    // drive.
    {
        struct KernelFileOps;

        /// **A `PiMutex`, and for the same reason `BLK_LOCK` is one.**
        ///
        /// `open` holds this across `vfs_open`, which loads the ENTIRE file
        /// from FAT32 — a real, synchronous disk read that descends into the
        /// block driver's hardware poll. `close` holds it across `vfs_close`,
        /// which writes a dirty file back. So the two most ordinary filesystem
        /// syscalls in the system hold a global lock for as long as the disk
        /// takes.
        ///
        /// Under a `SpinLock` that section became non-preemptible with K-C29
        /// step 2, and it inherits the block driver's worst case transitively:
        /// fixing the driver's own lock does nothing for this one.
        ///
        /// Copying the table out and writing it back — what `read_whole` does
        /// below — does NOT work for `open`. That path opens on a throwaway
        /// copy and never persists the descriptor; a real `open` has to, and
        /// two concurrent opens would each copy, each pick the same slot, and
        /// one would silently clobber the other. The lock genuinely has to be
        /// held for the duration. What it must not be is non-preemptible while
        /// it is.
        ///
        /// This lived in `crates/core/syscall/src/handlers.rs` until the seam went
        /// in. Nothing about the reasoning changed with the move — but the
        /// reasoning is about holding a lock across a FAT32 read, which is an
        /// implementation concern and belongs on this side of the boundary.
        static KERNEL_FD_TABLE: azos_sync::pi_mutex::PiMutex<azos_fs::FdTable> =
            azos_sync::pi_mutex::PiMutex::new(azos_fs::FdTable::new());

        /// May the running task operate on `fd`?
        ///
        /// **This check did not exist.** The owner was stamped in `open`
        /// and read at task death, and nothing consulted it in between:
        /// `vfs_read`/`vfs_write`/`vfs_close`/`vfs_lseek`/`fd_dup`/
        /// `fd_dup2` test only `fd < MAX_FDS && in_use`. `KERNEL_FD_TABLE`
        /// is one machine-wide array of 16 slots and the syscall filter is
        /// opt-in, so **any ring-3 task could read, write, seek, dup or
        /// close any descriptor any other task had open** — sixteen
        /// guesses covers the table. That is the same finding
        /// `socket_access_ok` was written to close for sockets, on the one
        /// table of five that never got it.
        ///
        /// It has to live here and not in `crates/core/syscall`: that crate is
        /// deliberately forbidden from knowing a descriptor is a table
        /// index (the `FileOps` seam exists for that), and the stamp is on
        /// this side of it.
        ///
        /// Kernel callers pass: `current_user_pt() == 0` is how the rest of
        /// this kernel recognises them, and a descriptor a kernel task
        /// opened keeps `FD_NO_OWNER`, which no ring-3 tid can equal —
        /// `fd_set_owner` refuses to stamp that value.
        ///
        /// Wave 13: the owner is the PROCESS (`current_proc_tid`), so every
        /// thread of a process uses its descriptors.
        #[inline]
        fn fd_caller_may_use(t: &azos_fs::FdTable, fd: i32) -> bool {
            azos_syscall::file_ops::fd_access_allowed(
                azos_fs::fd_owner(t, fd),
                azos_sched::current_proc_tid(),
                azos_sched::current_user_pt() == 0,
                azos_fs::FD_NO_OWNER,
            )
        }

        /// Has the running task room for one more descriptor?
        ///
        /// Kernel callers are not charged: their descriptors carry
        /// `FD_NO_OWNER` and are not reclaimed on task death, so a quota on
        /// them would bound the kernel against itself. Ring 3 is what the
        /// table needs protecting from.
        #[inline]
        fn fd_quota_available(t: &azos_fs::FdTable) -> bool {
            if azos_sched::current_user_pt() == 0 {
                return true;
            }
            let tid = azos_sched::current_proc_tid();
            if tid == azos_fs::FD_NO_OWNER {
                return false;
            }
            azos_fs::fd_count_owned(t, tid) < azos_fs::MAX_FDS_PER_TASK
        }

        /// Gate canary `fd-table-pi-canary` (owner rule F1): the device part
        /// of a descriptor operation runs with `KERNEL_FD_TABLE` held again,
        /// the shape before wave 15; the `lat-fat` smoke's `pi_io_site` must
        /// name the table.
        #[inline(always)]
        fn fd_canary_hold() -> Option<azos_sync::pi_mutex::PiMutexGuard<'static, azos_fs::FdTable>> {
            if cfg!(feature = "fd-table-pi-canary") { Some(KERNEL_FD_TABLE.lock()) } else { None }
        }

        /// Close `fd` (already checked by the caller, under `t`): the slot
        /// under the lock, the flush of a dirty proxy outside it (owner rule
        /// F1: `KERNEL_FD_TABLE` is a `PiMutex`, never held across a device
        /// wait). Takes the guard and releases it.
        fn fd_close_unlocked(
            mut t: azos_sync::pi_mutex::PiMutexGuard<'_, azos_fs::FdTable>, fd: i32,
        ) -> i32 {
            let lone = azos_fs::fd_detach(&mut *t, fd);
            drop(t);
            match lone {
                Some(mut lone) => {
                    let _c = fd_canary_hold();
                    azos_fs::vfs_close(&mut lone, 0)
                }
                None => 0,
            }
        }

        /// `read` (`write` false) or `write` of `fd`, checked by the caller
        /// under `t`: a device-backed streaming file transfers with the
        /// table released, under its description's position lock (owner
        /// rule F1; `azos_fs::fd_stream_transfer`); ramfs, tmpfs, proxy and
        /// device files (a copy, or the console: no device wait) under the
        /// lock as before. Takes the guard and releases it.
        fn fd_transfer(
            mut t: azos_sync::pi_mutex::PiMutexGuard<'_, azos_fs::FdTable>,
            fd: i32, write: bool, buf: *mut u8, len: usize,
        ) -> i64 {
            if !azos_fs::fd_streams(&t, fd) {
                return if write {
                    azos_fs::vfs_write(&mut *t, fd, buf as *const u8, len)
                } else {
                    azos_fs::vfs_read(&mut *t, fd, buf, len)
                } as i64;
            }
            drop(t);
            azos_fs::fd_stream_transfer(
                &|f: &mut dyn FnMut(&mut azos_fs::FdTable)| f(&mut *KERNEL_FD_TABLE.lock()),
                fd_canary_hold, fd, write, buf, len)
        }

        impl azos_syscall::file_ops::FileOps for KernelFileOps {
            fn open(&self, path: &[u8], flags: u32) -> i64 {
                // Quota BEFORE the open (fail fast), and again under the lock
                // that allocates the slot (`fd_adopt` below).
                if !fd_quota_available(&KERNEL_FD_TABLE.lock()) { return -1; }
                // Owner rule F1: every device access of an open (the backend
                // lookup, the proxy load, the create) happens inside
                // `vfs_open`, before its slot is allocated, so it runs on a
                // scratch table with `KERNEL_FD_TABLE` released; the
                // descriptor then moves into the table under the lock.
                let mut scratch = azos_fs::ScratchFds::new();
                let sfd = {
                    let _c = fd_canary_hold();
                    azos_fs::vfs_open(&mut scratch, path, flags)
                };
                if sfd < 0 { return -1; }
                let mut t = KERNEL_FD_TABLE.lock();
                // Quota BEFORE allocation, under the lock that allocates.
                // `MAX_FDS` is the whole machine's table — sixteen slots — and
                // nothing capped what one task could take of it, so a ring-3
                // program opening files in a loop denied descriptors to
                // everyone, the flight recorder's rotation and the ELF loader
                // included. Counting and then taking the lock would let two of
                // a task's own threads both pass; that is the bug one level
                // down, and it is why this sits inside the guard rather than
                // above it. Same rule and same reasoning as
                // `MAX_SOCKETS_PER_TASK`.
                if !fd_quota_available(&t) {
                    drop(t);
                    azos_fs::fd_free(&mut scratch, sfd);
                    return -1;
                }
                let fd = azos_fs::fd_adopt(&mut *t, &mut scratch, sfd);
                if fd < 0 {
                    drop(t);
                    azos_fs::fd_free(&mut scratch, sfd);
                    return -1;
                }
                // Stamp the owner here, under the same lock that allocated the
                // slot. `crates/fs/fs` deliberately does not know about the
                // scheduler; the kernel is the only place that holds the table
                // AND knows who is running. A descriptor opened by a kernel
                // task keeps `FD_NO_OWNER` and is never auto-reclaimed.
                if fd >= 0 {
                    let tid = azos_sched::current_proc_tid();
                    if tid != azos_fs::FD_NO_OWNER && tid != u32::MAX {
                        azos_fs::fd_set_owner(&mut *t, fd, tid);
                    }
                }
                fd as i64
            }
            fn release_all(&self, tid: u32) -> usize {
                // CLOSED, not freed raw (RFC-0055): a FAT32 file's bytes and
                // size sit in its inode until `vfs_close` flushes them, and a
                // program the user shell runs routinely exits with a moved
                // descriptor still open (`args > f`) — freeing the slot raw
                // lost the file. What `vfs_close` misses is still reclaimed.
                // One descriptor at a time, each flushed with the table
                // released (owner rule F1, `fd_close_unlocked`).
                let mut closed = 0usize;
                if tid != azos_fs::FD_NO_OWNER {
                    for fd in 0..azos_fs::MAX_FDS as i32 {
                        let t = KERNEL_FD_TABLE.lock();
                        if azos_fs::fd_owner(&t, fd) == Some(tid) {
                            fd_close_unlocked(t, fd);
                            closed += 1;
                        }
                    }
                }
                closed + azos_fs::fd_release_owned(&mut *KERNEL_FD_TABLE.lock(), tid)
            }
            fn set_owner(&self, fd: i32, from: u32, to: u32) -> i64 {
                let mut t = KERNEL_FD_TABLE.lock();
                if from == azos_fs::FD_NO_OWNER || to == azos_fs::FD_NO_OWNER
                    || azos_fs::fd_owner(&t, fd) != Some(from)
                    || azos_fs::fd_count_owned(&t, to) >= azos_fs::MAX_FDS_PER_TASK
                {
                    return -1;
                }
                azos_fs::fd_set_owner(&mut *t, fd, to);
                0
            }
            fn close(&self, fd: i32) -> i64 {
                let t = KERNEL_FD_TABLE.lock();
                if !fd_caller_may_use(&t, fd) { return -1; }
                fd_close_unlocked(t, fd) as i64
            }
            fn read(&self, fd: i32, dst: &mut [u8]) -> i64 {
                let t = KERNEL_FD_TABLE.lock();
                if !fd_caller_may_use(&t, fd) { return -1; }
                fd_transfer(t, fd, false, dst.as_mut_ptr(), dst.len())
            }
            fn write(&self, fd: i32, src: &[u8]) -> i64 {
                let t = KERNEL_FD_TABLE.lock();
                if !fd_caller_may_use(&t, fd) { return -1; }
                fd_transfer(t, fd, true, src.as_ptr() as *mut u8, src.len())
            }
            // On behalf of `tid` (the io_ring owner, from the SQ poller): the
            // owner stamp, under the same lock as the transfer.
            fn read_as(&self, tid: u32, fd: i32, dst: &mut [u8]) -> i64 {
                let t = KERNEL_FD_TABLE.lock();
                if !azos_syscall::file_ops::fd_owned_by(
                    azos_fs::fd_owner(&t, fd), tid, azos_fs::FD_NO_OWNER) {
                    return -1;
                }
                fd_transfer(t, fd, false, dst.as_mut_ptr(), dst.len())
            }
            fn write_as(&self, tid: u32, fd: i32, src: &[u8]) -> i64 {
                let t = KERNEL_FD_TABLE.lock();
                if !azos_syscall::file_ops::fd_owned_by(
                    azos_fs::fd_owner(&t, fd), tid, azos_fs::FD_NO_OWNER) {
                    return -1;
                }
                fd_transfer(t, fd, true, src.as_ptr() as *mut u8, src.len())
            }
            fn lseek(&self, fd: i32, offset: i64, whence: i32) -> i64 {
                let mut t = KERNEL_FD_TABLE.lock();
                if !fd_caller_may_use(&t, fd) { return -1; }
                azos_fs::vfs_lseek(&mut *t, fd, offset, whence)
            }
            fn dup(&self, fd: i32) -> i64 {
                let mut t = KERNEL_FD_TABLE.lock();
                if !fd_caller_may_use(&t, fd) { return -1; }
                // A dup allocates a slot like an open does. Charging only
                // `open` would put the whole table one `dup` loop away.
                if !fd_quota_available(&t) { return -1; }
                let new_fd = azos_fs::fd_dup(&mut *t, fd);
                // A duplicate inherits the owner, or it would be unusable by
                // the task that just made it — `fd_dup` copies the whole entry
                // including `owner_task`, so this is an assertion of intent
                // rather than a fix. Stamped explicitly anyway: if that copy
                // ever narrows, the duplicate must not become ownerless and
                // therefore reachable by everyone.
                if new_fd >= 0 {
                    let tid = azos_sched::current_proc_tid();
                    if tid != azos_fs::FD_NO_OWNER && tid != u32::MAX {
                        azos_fs::fd_set_owner(&mut *t, new_fd, tid);
                    }
                }
                new_fd as i64
            }
            fn dup2(&self, oldfd: i32, newfd: i32) -> i64 {
                let mut t = KERNEL_FD_TABLE.lock();
                // BOTH descriptors. `dup2` closes `newfd` if it is open, so
                // checking only `oldfd` would let a task shut another task's
                // file by naming it as the target.
                if !fd_caller_may_use(&t, oldfd) { return -1; }
                if azos_fs::fd_owner(&t, newfd).is_some()
                    && !fd_caller_may_use(&t, newfd) {
                    return -1;
                }
                // Charged only when the target is FREE. `dup2` onto one of the
                // caller's own open descriptors closes it first, so the net
                // change is zero and charging it would refuse a call that
                // takes nothing — the classic way a quota becomes a bug.
                if azos_fs::fd_owner(&t, newfd).is_none() && !fd_quota_available(&t) {
                    return -1;
                }
                let rc = azos_fs::fd_dup2(&mut *t, oldfd, newfd);
                if rc >= 0 {
                    let tid = azos_sched::current_proc_tid();
                    if tid != azos_fs::FD_NO_OWNER && tid != u32::MAX {
                        azos_fs::fd_set_owner(&mut *t, rc, tid);
                    }
                }
                rc as i64
            }
            fn mkdir(&self, path: &[u8]) -> i64 {
                // A path on a mounted filesystem (`/fat`) belongs to that
                // backend, which answers with its own errno; the ramfs tree
                // below only ever knew the directories it holds itself.
                if azos_fs::vfs_on_mount(path) {
                    return match azos_fs::vfs_mkdir(path) {
                        Ok(()) => 0,
                        Err(e) => fs_errno(e),
                    };
                }
                let (parent_idx, name) = azos_fs::path_parent(path);
                if parent_idx == azos_fs::NO_IDX || name.is_empty() { return -1; }
                let dir_idx = azos_fs::inode_alloc(
                    azos_fs::INODE_DIR,
                    azos_fs::PERM_READ | azos_fs::PERM_WRITE | azos_fs::PERM_EXEC,
                );
                if dir_idx == azos_fs::NO_IDX { return -1; }
                match azos_fs::dir_add_entry(parent_idx, name, dir_idx) {
                    Ok(())  => 0,
                    Err(()) => { azos_fs::inode_free(dir_idx); -1 }
                }
            }
            fn unlink(&self, path: &[u8]) -> i64 {
                // As `mkdir`: a mounted path is the backend's (FAT32 removes
                // the file and frees its chain; a directory is `-EISDIR`).
                if azos_fs::vfs_on_mount(path) {
                    return match azos_fs::vfs_unlink(path) {
                        Ok(()) => 0,
                        Err(e) => fs_errno(e),
                    };
                }
                let (parent_idx, name) = azos_fs::path_parent(path);
                if parent_idx == azos_fs::NO_IDX || name.is_empty() { return -1; }
                match azos_fs::dir_remove_entry(parent_idx, name) {
                    Ok(())  => 0,
                    Err(()) => -1,
                }
            }
            fn readdir(&self, path: &[u8], index: u32) -> Option<([u8; 64], u32, bool)> {
                let dir_idx = azos_fs::path_lookup(path);
                if dir_idx != azos_fs::NO_IDX {
                    return azos_fs::dir_entry_at(dir_idx, index);
                }
                // RFC-0055: a directory under a mount (`/fat`), through the
                // backend's cookie walk, so ring 3 (`ls` in the user shell)
                // lists the volume too. The cookie is opaque, so the `index`-th
                // entry is reached by walking from the start.
                let mut ent = azos_fs::DirEnt::new();
                let mut cookie = 0u64;
                for _ in 0..index {
                    cookie = azos_fs::vfs_readdir(path, cookie, &mut ent).ok()??;
                }
                azos_fs::vfs_readdir(path, cookie, &mut ent).ok()??;
                let mut name = [0u8; 64];
                let n = ent.name().len().min(63);
                name[..n].copy_from_slice(&ent.name()[..n]);
                Some((name, ent.size.min(u32::MAX as u64) as u32, ent.is_dir))
            }
            fn read_whole(&self, path: &[u8], dst: &mut [u8]) -> usize {
                // A throwaway table: the descriptor this opens is never handed
                // to anyone, so it must not consume a slot in the real one. A
                // `ScratchFds`, not a copy of `KERNEL_FD_TABLE`: with open
                // descriptions the copy was 8 KiB on fleet and overran the
                // frame budget.
                let mut table = azos_fs::ScratchFds::new();
                let fd = azos_fs::vfs_open(&mut table, path, azos_fs::O_RDONLY);
                if fd < 0 { return 0; }
                let mut total = 0usize;
                loop {
                    // Never hand `vfs_read` a length that would run past the
                    // buffer: the remaining-space clamp is what makes the cap
                    // real.
                    let want = dst.len().saturating_sub(total);
                    if want == 0 {
                        // The file reached the cap. Refuse the whole read
                        // rather than return a prefix the caller would exec as
                        // a truncated image and misreport as a corrupt ELF. A
                        // file of exactly `dst.len()` is refused too, erring
                        // toward the safe side.
                        azos_fs::vfs_close(&mut table, fd);
                        return 0;
                    }
                    let n = azos_fs::vfs_read(
                        &mut table, fd,
                        unsafe { dst.as_mut_ptr().add(total) },
                        want,
                    );
                    if n <= 0 { break; }
                    // Defensive clamp: a driver returning more than `want` must
                    // not be able to walk `total` past the buffer end.
                    total = total.saturating_add((n as usize).min(want)).min(dst.len());
                }
                azos_fs::vfs_close(&mut table, fd);
                total
            }

            /// Wave 14 (SPAWNCACHE): `read_whole` in runs of at most
            /// [`HASH_RUN`] bytes, each handed to `sink` as soon as it is in
            /// `dst`.
            fn read_whole_with(&self, path: &[u8], dst: &mut [u8], sink: &mut dyn FnMut(&[u8])) -> usize {
                const HASH_RUN: usize = 16 * 1024;
                let mut table = azos_fs::ScratchFds::new();
                let fd = azos_fs::vfs_open(&mut table, path, azos_fs::O_RDONLY);
                if fd < 0 { return 0; }
                let mut total = 0usize;
                loop {
                    let room = dst.len().saturating_sub(total);
                    if room == 0 {
                        // Same refusal as `read_whole`: no prefix of a file
                        // that does not fit.
                        azos_fs::vfs_close(&mut table, fd);
                        return 0;
                    }
                    let want = room.min(HASH_RUN);
                    let n = azos_fs::vfs_read(
                        &mut table, fd,
                        unsafe { dst.as_mut_ptr().add(total) },
                        want,
                    );
                    if n <= 0 { break; }
                    let n = (n as usize).min(want);
                    sink(&dst[total..total + n]);
                    total += n;
                }
                azos_fs::vfs_close(&mut table, fd);
                total
            }

            fn content_stamp(&self, path: &[u8]) -> Option<azos_syscall::file_ops::ContentStamp> {
                azos_fs::vfs_content_stamp(path).map(|s| azos_syscall::file_ops::ContentStamp {
                    fs: s.fs, epoch: s.epoch, id: s.id, size: s.size,
                })
            }

            /// RFC-0048 P2: the VFS's `vfs_stat` (ramfs, or the backend mounted
            /// under the path), laid out by the syscall layer.
            fn stat(&self, path: &[u8]) -> Result<azos_syscall::file_ops::StatOut, i64> {
                use azos_abi::error::Errno;
                match azos_fs::vfs_stat(path) {
                    Some(st) => Ok(azos_syscall::file_ops::StatOut {
                        size: st.size, mode: st.mode, nlink: st.nlink, uid: st.uid,
                        gid: st.gid, atime: st.atime, mtime: st.mtime, ctime: st.ctime,
                    }),
                    None => Err(Errno::ENOENT.to_syscall_ret()),
                }
            }

            /// RFC-0048 P2. Two types: `tmpfs` (the streaming backend) and
            /// `fat32`, the one block volume — refused while it is already
            /// mounted anywhere (the boot mount at `/fat` included), since a
            /// second mount point would alias one volume's state. `src` is
            /// not consulted: there is one block device.
            fn mount(&self, _src: &[u8], target: &[u8], fstype: &[u8]) -> i64 {
                use azos_abi::error::Errno;
                let r = match fstype {
                    b"tmpfs" => azos_fs::vfs_mount_fs(target, &azos_fs::TMPFS_FS),
                    b"fat32" | b"vfat" => {
                        if azos_fs::fat32_mounted() {
                            return Errno::EBUSY.to_syscall_ret();
                        }
                        if azos_fs::fat32_mount().is_err() {
                            return Errno::EIO.to_syscall_ret();
                        }
                        azos_fs::vfs_mount(target, azos_fs::FS_TYPE_FAT32)
                    }
                    _ => return Errno::ENODEV.to_syscall_ret(),
                };
                match r { Ok(()) => 0, Err(()) => Errno::EBUSY.to_syscall_ret() }
            }

            fn sync(&self) -> i64 {
                use azos_abi::error::Errno;
                match azos_fs::fat32::fat32_sync_checked() {
                    Ok(()) => 0,
                    Err(azos_fs::FsError::Unsupported) => Errno::ENOSYS.to_syscall_ret(),
                    Err(azos_fs::FsError::NotMounted) => Errno::ENODEV.to_syscall_ret(),
                    Err(_) => Errno::EIO.to_syscall_ret(),
                }
            }

            // ── Owner round 23: rmdir, rename, truncate, fsync, statfs ──
            //
            // Straight onto the VFS's P2 entry points; `fs_errno` is the one
            // `FsErr` -> errno table.

            /// A backend directory (`vfs_rmdir`), or else an empty ramfs
            /// directory: `SYS_MKDIR` makes ramfs directories, so the call
            /// that removes one must reach them too.
            fn rmdir(&self, path: &[u8]) -> i64 {
                use azos_abi::error::Errno;
                // The mount table first, so a path under a mount never
                // reaches the ramfs; `NotFound` is also what a path under no
                // mount answers.
                match azos_fs::vfs_rmdir(path) {
                    Err(azos_fs::FsErr::NotFound) => {}
                    Ok(()) => return 0,
                    Err(e) => return fs_errno(e),
                }
                if azos_fs::path_lookup(path) == azos_fs::NO_IDX {
                    return Errno::ENOENT.to_syscall_ret();
                }
                match azos_fs::vfs_stat(path) {
                    Some(st) if !st.is_dir => return Errno::ENOTDIR.to_syscall_ret(),
                    Some(st) if st.size != 0 => return Errno::ENOTEMPTY.to_syscall_ret(),
                    _ => {}
                }
                let (parent_idx, name) = azos_fs::path_parent(path);
                if parent_idx == azos_fs::NO_IDX || name.is_empty() {
                    return Errno::EINVAL.to_syscall_ret();
                }
                match azos_fs::dir_remove_entry(parent_idx, name) {
                    Ok(()) => 0,
                    Err(()) => Errno::EBUSY.to_syscall_ret(),
                }
            }
            fn rename(&self, from: &[u8], to: &[u8]) -> i64 {
                match azos_fs::vfs_rename(from, to) { Ok(()) => 0, Err(e) => fs_errno(e) }
            }
            fn truncate(&self, path: &[u8], len: u64) -> i64 {
                match azos_fs::vfs_truncate(path, len) { Ok(()) => 0, Err(e) => fs_errno(e) }
            }
            fn fsync(&self, fd: i32) -> i64 {
                let t = KERNEL_FD_TABLE.lock();
                if !fd_caller_may_use(&t, fd) {
                    return azos_abi::error::Errno::EBADF.to_syscall_ret();
                }
                // Owner rule F1: the write and the sync outside the table's
                // lock, on a copy of a dirty proxy's bytes.
                let work = azos_fs::fd_fsync_begin(&t, fd);
                drop(t);
                let r = work.and_then(|w| {
                    let _c = fd_canary_hold();
                    azos_fs::fd_fsync_finish(w)
                });
                match r { Ok(()) => 0, Err(e) => fs_errno(e) }
            }
            fn statfs(&self, path: &[u8]) -> Result<azos_syscall::file_ops::StatFsOut, i64> {
                let st = azos_fs::vfs_statfs(path).map_err(fs_errno)?;
                Ok(azos_syscall::file_ops::StatFsOut {
                    fs_type: st.fs_type, block_size: st.block_size, blocks: st.blocks,
                    blocks_free: st.blocks_free, files: st.files, files_free: st.files_free,
                    name_max: st.name_max,
                })
            }
        }

        /// The errno a VFS failure returns to ring 3.
        fn fs_errno(e: azos_fs::FsErr) -> i64 {
            use azos_abi::error::Errno;
            use azos_fs::FsErr as F;
            match e {
                F::Unsupported => Errno::ENOSYS,
                F::NotFound => Errno::ENOENT,
                F::Exists => Errno::EEXIST,
                F::NotEmpty => Errno::ENOTEMPTY,
                F::NotDir => Errno::ENOTDIR,
                F::IsDir => Errno::EISDIR,
                F::NoSpace => Errno::ENOSPC,
                F::Io => Errno::EIO,
                F::Invalid => Errno::EINVAL,
                F::NameTooLong => Errno::ENAMETOOLONG,
                F::Busy => Errno::EBUSY,
            }
            .to_syscall_ret()
        }

        static KERNEL_FILE_OPS: KernelFileOps = KernelFileOps;
        azos_syscall::file_ops::set_file_ops(&KERNEL_FILE_OPS);
        #[cfg(feature = "lat-fat")]
        FD_TABLE_ADDR.store(&KERNEL_FD_TABLE as *const _ as usize,
            core::sync::atomic::Ordering::Relaxed);
    }

    // Wave 12 (RFC-0055 S5): the flight/behavior/config/OTA typed calls run
    // the console's own command bodies (`azos_shell::families`), which a
    // core crate cannot name. Installed with the other seams, before any
    // ring-3 task exists; without the Robot domain flight and behavior
    // answer `-ENOSYS` from those bodies.
    {
        struct KernelFamilyOps;
        impl azos_syscall::families::FamilyOps for KernelFamilyOps {
            fn flight(&self, op: u64) -> i64 {
                azos_shell::families::flight(op)
            }
            fn behavior(&self, op: u64, layer: u64) -> i64 {
                azos_shell::families::behavior(op, layer)
            }
            fn config_get(&self, key: &[u8], out: &mut [u8]) -> i64 {
                azos_shell::families::config_get(key, out)
            }
            fn config_set(&self, key: &[u8], val: &[u8]) -> i64 {
                azos_shell::families::config_set(key, val)
            }
            fn ota(&self, op: u64) -> i64 {
                azos_shell::families::ota(op)
            }
        }
        static KERNEL_FAMILY_OPS: KernelFamilyOps = KernelFamilyOps;
        azos_syscall::families::set_family_ops(&KERNEL_FAMILY_OPS);
    }

    // The actuation gate. Installed here, next to the other seams. It lives in
    // `domains/robot/safety-core`, which sees both the motor driver and the safety
    // layer — `domains/robot/robot` does not depend on `domains/robot/behavior`.
    //
    // Until this ran, the thesis was not true. `motor_envelope` and the e-stop
    // were applied by `rt_motor_task` alone, and `sys_motor_speed` /
    // `sys_motor_enable` reach `motor_set` without passing through it. The
    // autorun task grants `Motor(0)`/`Motor(1)` to a TID that `exec_user`
    // reuses, so a ring-3 program held those capabilities and could drive the
    // motors at any speed — including immediately after an e-stop, which is a
    // one-shot stop plus a flag only the RT task reads. Nothing re-stopped it.
    #[cfg(feature = "domain-robot")]
    azos_safety_core::actuation::install();
    // The part every domain shares (wave 11): recorders, ring-3 e-stop, and
    // the `gate_installed` flag the loader checks. After the robot's install,
    // so a robot image prints the same lines in the same order as before.
    azos_actuation::gate::install();
    // After the actuation hooks: an io_ring motor or PWM entry goes through the
    // same typed functions, and so the same halt rule (RFC-0041 §E).
    azos_ipc::io_ring::io_ring_register_ops(&azos_syscall::ioring_ops::KERNEL_IORING_OPS);
    // The io_ring SQ poller's spawn and wake. Registering them starts nothing:
    // a poller exists only for a ring whose owner's topology row declares
    // `sqpoll_idle_ms` (see the autorun seed) and that asked for one.
    azos_syscall::ioring_sqpoll::install();
}

/// Phase 8: IPC plumbing — pipes, POSIX-style signals, and the named-service
/// manager. Shared between both `kernel_main`s (riscv64 had this in place;
/// aarch64 never called any of the three, so a ring-3 task on that ISA had
/// no pipes, no signal delivery, and no service registry to bind to).
///
/// Must run before any task that could actually use one of the three — not
/// before the first `task_create*` call: riscv64's own "ota-recv" task is
/// created above this point in its `kernel_main` and uses none of them.
/// aarch64 calls this right after `install_procfs()`, ahead of every
/// `task_create*` on that ISA (the first is "autorun", further down inside
/// the disk-gated block) — strictly earlier than riscv64's own placement,
/// which is safe in the same direction: earlier can only make more tasks
/// see initialized IPC state, never fewer.
pub(crate) fn install_ipc_plumbing() {
    azos_ipc::pipe_init();
    azos_ipc::signal_init();
    azos_service::service_init();
    kprintln!("[IPC] Pipes, signals, service manager initialized");
}
