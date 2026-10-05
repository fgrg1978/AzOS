// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Linux/riscv64 backend: raw `ecall`, no libc.
//!
//! **Why no libc.** The comparison is kernel-vs-kernel. Going through glibc or
//! musl would add a userspace layer to one side and not the other, and this
//! project does not use C anyway. Raw `ecall` puts both sides at the same
//! distance from their kernel: one instruction.
//!
//! Syscall numbers are the RISC-V 64-bit (generic `asm-generic/unistd.h`) ABI,
//! which is what Linux uses on this architecture. They are NOT the x86-64
//! numbers — `getpid` is 172 here, not 39. Getting this wrong does not fail to
//! build; it calls a different syscall and quietly reports a different
//! measurement, which is the worst possible failure for a benchmark.

use super::bench_core::{
    Abi, Ipc, Mem, Net, Proc, Role, Shell, Vdso, IPC_SENTINEL, NET_PAYLOAD, NET_POLL_BUDGET,
    SPAWN_NAP_NS,
};

pub const SYS_WRITE: usize = 64;
pub const SYS_EXIT: usize = 93;
pub const SYS_GETPID: usize = 172;
pub const SYS_SCHED_YIELD: usize = 124;
/// `getrusage`, RISC-V generic ABI. Chosen over parsing
/// `/proc/self/status`: one syscall, a binary struct, no text parsing and no
/// file descriptors — the same shape of question AzOS answers with
/// `SYS_TASKINFO`, so neither side pays for the comparison in a way the other
/// does not.
pub const SYS_GETRUSAGE: usize = 165;

/// `RUSAGE_SELF`.
const RUSAGE_SELF: usize = 0;
/// Byte offsets of `ru_nvcsw` / `ru_nivcsw` inside `struct rusage` on LP64:
/// two `timeval` (16 B each) then fourteen `long`s, of which these are the
/// thirteenth and fourteenth. Spelled as arithmetic rather than as 128/136 so
/// the derivation is checkable without a header to hand.
const RUSAGE_NVCSW_OFF:  usize = 2 * 16 + 12 * 8;
const RUSAGE_NIVCSW_OFF: usize = 2 * 16 + 13 * 8;
/// `sizeof(struct rusage)` on LP64.
const RUSAGE_BYTES: usize = 2 * 16 + 14 * 8;

#[inline(always)]
unsafe fn syscall1(nr: usize, a0: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall0(nr: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            lateout("a0") ret,
            options(nostack),
        );
    }
    ret
}

pub struct LinuxAbi;

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
/// `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID`: musl's
/// `pthread_create` flags without `CLONE_SETTLS`/`CLONE_DETACHED` (the bench
/// has no thread-local storage).
const THREAD_FLAGS: usize = 0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x100000 | 0x200000;

impl super::bench_core::Threads for LinuxAbi {
    fn thread_spawn(entry: extern "C" fn() -> !, stack_top: usize, ctid: &'static core::sync::atomic::AtomicU32) -> i64 {
        // `clone(flags, stack, ptid, tls, ctid)`: the parent's TID store and
        // the child's clear both name `ctid`. The child resumes after the
        // `ecall` with `a0 == 0` on its new stack and jumps to `entry`, which
        // never returns; the parent gets the TID.
        ctid.store(u32::MAX, core::sync::atomic::Ordering::Release);
        let p = ctid.as_ptr() as usize;
        let ret = unsafe { syscall7(SYS_CLONE, THREAD_FLAGS, stack_top, p, 0, p, entry as usize) };
        ret as i64
    }
    fn thread_exit() -> ! {
        loop { unsafe { syscall1(SYS_EXIT, 0); } }
    }
    fn futex_wait(w: &core::sync::atomic::AtomicU32, val: u32) -> i64 {
        unsafe { syscall4(SYS_FUTEX, w.as_ptr() as usize, FUTEX_WAIT_PRIVATE, val as usize, 0) as i64 }
    }
    fn futex_wake(w: &core::sync::atomic::AtomicU32, n: u32) -> i64 {
        unsafe { syscall3(SYS_FUTEX, w.as_ptr() as usize, FUTEX_WAKE_PRIVATE, n as usize) as i64 }
    }
    fn join_wait(w: &core::sync::atomic::AtomicU32, val: u32) -> i64 {
        // `FUTEX_WAIT` (0), shared: `CLONE_CHILD_CLEARTID`'s wake is shared.
        unsafe { syscall4(SYS_FUTEX, w.as_ptr() as usize, 0, val as usize, 0) as i64 }
    }
}

impl Abi for LinuxAbi {
    /// `getpid` — the conventional null syscall. Linux serves it from the task
    /// struct with no locking, which is the closest analogue to this kernel's
    /// own `SYS_GETPID`.
    #[inline(always)]
    fn ctx_switches(&self) -> Option<(u64, u64)> {
        let mut ru = [0u8; RUSAGE_BYTES];
        let rc = unsafe {
            syscall2(SYS_GETRUSAGE, RUSAGE_SELF, ru.as_mut_ptr() as usize)
        };
        if rc < 0 { return None; }
        let g = |off: usize| u64::from_le_bytes(ru[off..off + 8].try_into().unwrap());
        Some((g(RUSAGE_NVCSW_OFF), g(RUSAGE_NIVCSW_OFF)))
    }

    fn current_cpu(&self) -> Option<u64> {
        let (mut cpu, mut node) = (0u32, 0u32);
        let rc = unsafe {
            syscall3(SYS_GETCPU, &mut cpu as *mut u32 as usize,
                     &mut node as *mut u32 as usize, 0)
        };
        if rc < 0 { return None; }
        Some(cpu as u64)
    }

    fn null_syscall(&self) {
        unsafe { core::hint::black_box(syscall0(SYS_GETPID)); }
    }

    #[inline(always)]
    fn yield_now(&self) {
        unsafe { core::hint::black_box(syscall0(SYS_SCHED_YIELD)); }
    }

    fn write(&self, bytes: &[u8]) {
        // fd 2 (stderr): unbuffered on both sides, so the report is not held
        // hostage by a flush that never happens before the process exits.
        unsafe { syscall3(SYS_WRITE, 2, bytes.as_ptr() as usize, bytes.len()); }
    }
}

/// `TCSBRK` with a non-zero argument is `tcdrain`: return once everything
/// written to the terminal has been transmitted.
const TCSBRK: usize = 0x5409;

/// Wait until the console (fd 2) has sent everything written to it.
///
/// **PID 1 must call this before it exits.** This benchmark runs as `/init`.
/// When it exits, Linux panics ("Attempted to kill init!") and stops the other
/// CPUs, and whatever the serial driver still held was never sent: in the
/// `-accel tcg,thread=single -icount` pass, the last lanes and `side=linux
/// done` were lost in 3 of 10 boots of the e8d673e binary and 1 of 6 of the
/// wave-11 one. One boot lost a line in the middle (`switch-loaded = 8870
/// ns/op (36.` and then the panic). The benchmark had finished; its report had
/// not. Best effort: a failed `ioctl` changes nothing.
pub fn drain_console() {
    unsafe { syscall3(SYS_IOCTL, 2, TCSBRK, 1); }
}

pub fn exit(code: usize) -> ! {
    unsafe { syscall1(SYS_EXIT, code); }
    // `exit` does not return; the loop is only here to satisfy `!`.
    loop {}
}

// ── IPC round trip: pipe pair ──────────────────────────────────────────────
//
// **These numbers are the generic ABI, and riscv64 has no legacy aliases.**
// There is no `fork` (use `clone` with SIGCHLD) and no `pipe` (use `pipe2`).
// Guessing `SYS_FORK = 2` from x86-64 would not fail to build — it would call
// something else entirely, which for a benchmark is the worst failure mode
// there is. Every one of these is checked at runtime below: a negative return
// aborts the measurement instead of producing a number.
pub const SYS_READ: usize = 63;
pub const SYS_PIPE2: usize = 59;
pub const SYS_CLONE: usize = 220;

/// `clone` flag that makes it behave as `fork`: new address space (no
/// CLONE_VM), child signals the parent on exit.
const SIGCHLD: usize = 17;

#[inline(always)]
unsafe fn syscall2(nr: usize, a0: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall5(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            options(nostack),
        );
    }
    ret
}

/// The four inherited pipe ends: `[p2c_r, p2c_w, c2p_r, c2p_w]`.
///
/// Written **before** `clone`, which is what makes them visible to both sides:
/// after the fork the two address spaces are copy-on-write and a write by
/// either process is invisible to the other. An `UnsafeCell` wrapper rather
/// than `static mut` so this stays free of the `static_mut_refs` lint — the
/// build gate treats warnings as failures.
struct Fds(core::cell::UnsafeCell<[i32; 4]>);
unsafe impl Sync for Fds {}
static FDS: Fds = Fds(core::cell::UnsafeCell::new([-1; 4]));

#[inline(always)]
fn fds() -> [i32; 4] {
    unsafe { *FDS.0.get() }
}

impl Ipc for LinuxAbi {
    fn spawn_peer(&self) -> Option<Role> {
        let mut p2c = [0i32; 2];
        let mut c2p = [0i32; 2];
        unsafe {
            if syscall2(SYS_PIPE2, p2c.as_mut_ptr() as usize, 0) < 0 { return None; }
            if syscall2(SYS_PIPE2, c2p.as_mut_ptr() as usize, 0) < 0 { return None; }
            // Published before the fork, on purpose — see `FDS`.
            *FDS.0.get() = [p2c[0], p2c[1], c2p[0], c2p[1]];
            match syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) {
                0 => Some(Role::Server),
                n if n > 0 => Some(Role::Client(n as u64)),
                _ => None,
            }
        }
    }

    /// Two syscalls, unavoidably: a pipe has no combined send-and-wait. This
    /// is the honest cost of the cheapest synchronous IPC the kernel offers
    /// for this shape, which is what the comparison asks for.
    #[inline(always)]
    fn round_trip(&self, _peer: u64, val: u64) -> Result<u64, i64> {
        let f = fds();
        let out = val.to_ne_bytes();
        let mut inp = [0u8; 8];
        unsafe {
            let w = syscall3(SYS_WRITE, f[1] as usize, out.as_ptr() as usize, 8);
            if w != 8 { return Err(w as i64); }
            let r = syscall3(SYS_READ, f[2] as usize, inp.as_mut_ptr() as usize, 8);
            if r != 8 { return Err(r as i64); }
        }
        Ok(u64::from_ne_bytes(inp))
    }

    fn serve(&self, bound: u64) -> ! {
        let f = fds();
        let mut served = 0u64;
        while served < bound {
            let mut inp = [0u8; 8];
            unsafe {
                if syscall3(SYS_READ, f[0] as usize, inp.as_mut_ptr() as usize, 8) != 8 { break; }
                let v = u64::from_ne_bytes(inp);
                let out = v.wrapping_add(1).to_ne_bytes();
                if syscall3(SYS_WRITE, f[3] as usize, out.as_ptr() as usize, 8) != 8 { break; }
                if v == IPC_SENTINEL { break; }
            }
            served += 1;
        }
        exit(0)
    }
}

// Generic-ABI numbers again -- `mmap` is 222 here, not the x86-64 9.
pub const SYS_MUNMAP: usize = 215;
pub const SYS_MMAP: usize = 222;

const PROT_READ_WRITE: usize = 0x3;
/// `MAP_PRIVATE | MAP_ANONYMOUS`. Anonymous so nothing touches a filesystem,
/// private so the fault lane measures ordinary demand paging.
const MAP_PRIVATE_ANONYMOUS: usize = 0x22;

#[inline(always)]
unsafe fn syscall6(
    nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize,
) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack),
        );
    }
    ret
}

impl Mem for LinuxAbi {
    fn map(&self, len: u64) -> Result<u64, i64> {
        let r = unsafe {
            syscall6(SYS_MMAP, 0, len as usize, PROT_READ_WRITE,
                     MAP_PRIVATE_ANONYMOUS, usize::MAX, 0)
        };
        if r < 0 { Err(r as i64) } else { Ok(r as u64) }
    }

    fn unmap(&self, base: u64, len: u64) -> Result<(), i64> {
        let r = unsafe { syscall2(SYS_MUNMAP, base as usize, len as usize) };
        if r < 0 { Err(r as i64) } else { Ok(()) }
    }
}

// Generic ABI again: `brk` is 214 and `wait4` is 260. There is no `waitpid`.
pub const SYS_BRK: usize = 214;
// `SYS_WAIT4` (260), used by `fork_exit_wait` since 2026-09-07. The note
// below is kept because it records why the number was reserved before it
// had a caller:
// `SYS_WAIT4` (260) is left documented: it will be needed when this lane
// measures the full cycle again.
#[allow(dead_code)]
pub const SYS_WAIT4: usize = 260;

impl Proc for LinuxAbi {
    fn brk_grow(&self, delta: u64) -> Result<u64, i64> {
        // Linux returns the CURRENT break when the argument is 0 or invalid,
        // which is the same query convention the Azos side uses.
        let cur = unsafe { syscall1(SYS_BRK, 0) };
        if cur < 0 { return Err(cur as i64); }
        let want = cur as usize + delta as usize;
        let got = unsafe { syscall1(SYS_BRK, want) };
        // Linux no falla con negativo: devuelve el break sin mover si no pudo.
        if (got as usize) < want { return Err(got as i64); }
        Ok(got as u64)
    }

    fn spawn_yield_peer(&self, iters: u64) -> Result<(), i64> {
        let pid = unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) };
        if pid < 0 { return Err(pid as i64); }
        if pid == 0 {
            let first = self.current_cpu();
            for _ in 0..iters { unsafe { syscall0(SYS_SCHED_YIELD); } }
            super::report_hart(self, b"peer", first, self.current_cpu());
            exit(0);
        }
        Ok(())
    }

    fn spawn_peer_raw(&self) -> Option<bool> {
        match unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) } {
            0 => Some(true),
            pid if pid > 0 => Some(false),
            _ => None,
        }
    }

    fn exit_child(&self) -> ! { exit(0) }

    fn fork_exit(&self) -> Result<(), i64> {
        // The full cycle, the child's exit inside the caller's window: see
        // `Proc::fork_exit` (wave 14).
        self.fork_exit_wait()
    }

    fn fork_exit_wait(&self) -> Result<(), i64> {
        let pid = unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) };
        if pid < 0 { return Err(pid as i64); }
        if pid == 0 { exit(0); }

        // `WNOHANG`, NOT a blocking `wait4`. Azos cannot block in `wait` at
        // all, so a blocking call here would time a sleep against a spin and
        // produce a difference that is about the two APIs rather than about
        // the two kernels. See `Proc::fork_exit_wait`.
        //
        // `wait4(pid, NULL, WNOHANG, NULL)` returns: the pid when reaped, 0
        // when that child is alive, negative on error. The `0` is why this
        // cannot share a "not positive" test with the Azos lane, whose
        // "not yet" is `-1`.
        for _ in 0..POLL_BOUND {
            let r = unsafe { syscall4(SYS_WAIT4, pid as usize, 0, WNOHANG, 0) };
            if r == pid { return Ok(()); }
            if r < 0 { return Err(r as i64); }
            unsafe { syscall0(SYS_SCHED_YIELD); }
        }
        Err(-2002)
    }
}

/// `WNOHANG` from `<sys/wait.h>`.
const WNOHANG: usize = 1;

// ── Wave 12: the shell lanes' counterparts (`bench_core::Shell`) ───────────

/// `execve`: the second half of `posix_spawn`.
pub const SYS_EXECVE: usize = 221;
/// `clone` flags of glibc's `posix_spawn`: share the address space (no copy
/// of this process's page tables, as `SYS_SPAWN_EX` makes none) and suspend
/// the parent until the child has exec'd or exited (`CLONE_VFORK`).
const CLONE_VM: usize = 0x100;
const CLONE_VFORK: usize = 0x4000;
/// The argument that makes this binary exit at once ([`exit_at_once`]).
const EXIT_ARG: &[u8] = b"--exit";

/// This binary's own path and `--exit`, as the argv of the spawned child,
/// and an empty environment. Written once by [`init_args`] from the initial
/// stack (argv[0] is `/init` booted directly, `/vsbench` under the seccomp
/// launcher), before anything is measured.
struct SpawnArgs(core::cell::UnsafeCell<[usize; 3]>);
unsafe impl Sync for SpawnArgs {}
static SPAWN_ARGV: SpawnArgs = SpawnArgs(core::cell::UnsafeCell::new([0; 3]));
static SPAWN_ENVP: [usize; 1] = [0];
static EXIT_ARG_Z: [u8; 7] = *b"--exit\0";

fn c_str_eq(p: usize, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { core::ptr::read((p + i) as *const u8) } != b {
            return false;
        }
    }
    unsafe { core::ptr::read((p + want.len()) as *const u8) == 0 }
}

/// From the initial stack (`sp` at `argc`): record argv[0] for the spawn
/// lane, and answer whether this process was started as that lane's child
/// (argv[1] == `--exit`), which then exits at once.
pub fn init_args(sp: usize) -> bool {
    let argc = unsafe { core::ptr::read(sp as *const usize) };
    let argv = sp + 8;
    let arg = |i: usize| unsafe { core::ptr::read((argv + 8 * i) as *const usize) };
    if argc >= 2 && arg(1) != 0 && c_str_eq(arg(1), EXIT_ARG) {
        return true;
    }
    if argc >= 1 {
        unsafe { *SPAWN_ARGV.0.get() = [arg(0), EXIT_ARG_Z.as_ptr() as usize, 0] };
    }
    false
}

/// `posix_spawn` of this binary with `--exit`: `clone(CLONE_VM |
/// CLONE_VFORK)`, then `execve` in the child. The child runs on this frame's
/// stack until it execs, as vfork's does, which is why this is a function of
/// its own that the parent leaves only after the child is gone from it, and
/// why the child path is two syscalls and an exit, with nothing stored.
#[inline(never)]
fn vfork_exec(path: usize, argv: usize, envp: usize) -> isize {
    let pid = unsafe { syscall5(SYS_CLONE, CLONE_VM | CLONE_VFORK | SIGCHLD, 0, 0, 0, 0) };
    if pid == 0 {
        unsafe { syscall3(SYS_EXECVE, path, argv, envp) };
        exit(127);
    }
    pid
}

impl Shell for LinuxAbi {
    fn spawn_wait(&self) -> Result<(), i64> {
        let argv = unsafe { &*SPAWN_ARGV.0.get() };
        if argv[0] == 0 {
            return Err(-2006);
        }
        let pid = vfork_exec(argv[0], argv.as_ptr() as usize, SPAWN_ENVP.as_ptr() as usize);
        if pid < 0 { return Err(pid as i64); }
        // WNOHANG polls with a `SPAWN_NAP_NS` sleep between them, as AzOS.
        let nap = Timespec { tv_sec: 0, tv_nsec: SPAWN_NAP_NS as i64 };
        let mut status = 0u32;
        for _ in 0..POLL_BOUND {
            let r = unsafe { syscall4(SYS_WAIT4, pid as usize, &mut status as *mut u32 as usize, WNOHANG, 0) };
            if r == pid {
                // Exited normally with 0: `status == 0`. 127 is a failed exec.
                return if status == 0 { Ok(()) } else { Err(-2005) };
            }
            if r < 0 { return Err(r as i64); }
            unsafe {
                syscall4(SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC as usize, 0,
                         &nap as *const Timespec as usize, 0);
            }
        }
        Err(-2002)
    }

    fn pipe_open(&self) -> Result<(u64, u64), i64> {
        let mut fds = [-1i32; 2];
        let r = unsafe { syscall2(SYS_PIPE2, fds.as_mut_ptr() as usize, 0) };
        if r < 0 { return Err(r as i64); }
        Ok((fds[0] as u64, fds[1] as u64))
    }

    fn pipe_rw(&self, r: u64, w: u64, buf: &mut [u8]) -> Result<(), i64> {
        let n = unsafe { syscall3(SYS_WRITE, w as usize, buf.as_ptr() as usize, buf.len()) };
        if n != buf.len() as isize { return Err(n as i64); }
        let m = unsafe { syscall3(SYS_READ, r as usize, buf.as_mut_ptr() as usize, buf.len()) };
        if m != buf.len() as isize { return Err(m as i64); }
        Ok(())
    }

    fn pipe_close(&self, r: u64, w: u64) {
        unsafe {
            syscall1(SYS_CLOSE, r as usize);
            syscall1(SYS_CLOSE, w as usize);
        }
    }

    fn file_open_read_close(&self, buf: &mut [u8]) -> Result<(), i64> {
        let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/init\0".as_ptr() as usize, 0, 0) };
        if fd < 0 {
            return Err(fd as i64);
        }
        let n = unsafe { syscall3(SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) };
        unsafe { syscall1(SYS_CLOSE, fd as usize) };
        if n != buf.len() as isize {
            return Err(n as i64);
        }
        Ok(())
    }

    fn file_dup_close(&self, fd: u64) -> Option<Result<(), i64>> {
        let d = unsafe { syscall1(SYS_DUP, fd as usize) };
        if d < 0 {
            return Some(Err(d as i64));
        }
        unsafe { syscall1(SYS_CLOSE, d as usize) };
        Some(Ok(()))
    }

    fn file_hold(&self) -> Result<u64, i64> {
        let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD as usize, b"/init\0".as_ptr() as usize, 0, 0) };
        if fd < 0 { Err(fd as i64) } else { Ok(fd as u64) }
    }

    fn file_release(&self, fd: u64) {
        unsafe { syscall1(SYS_CLOSE, fd as usize) };
    }

    fn tmp_setup(&self) -> Result<(), i64> {
        // O_RDWR | O_CREAT | O_TRUNC, 0644: the initramfs root is RAM.
        let fd = unsafe {
            syscall4(SYS_OPENAT, AT_FDCWD as usize, TMP_PATH.as_ptr() as usize, 0o1102, 0o644)
        };
        if fd < 0 {
            return Err(fd as i64);
        }
        let n = unsafe { syscall3(SYS_WRITE, fd as usize, [0x5Au8; 64].as_ptr() as usize, 64) };
        unsafe { syscall1(SYS_CLOSE, fd as usize) };
        if n != 64 {
            return Err(n as i64);
        }
        Ok(())
    }

    fn tmp_open_read_close(&self, buf: &mut [u8]) -> Result<(), i64> {
        let fd = unsafe { syscall4(SYS_OPENAT, AT_FDCWD as usize, TMP_PATH.as_ptr() as usize, 0, 0) };
        if fd < 0 {
            return Err(fd as i64);
        }
        let n = unsafe { syscall3(SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) };
        unsafe { syscall1(SYS_CLOSE, fd as usize) };
        if n != buf.len() as isize {
            return Err(n as i64);
        }
        Ok(())
    }
}

/// `openat` (asm-generic).
pub const SYS_OPENAT: usize = 56;
/// `dup` (asm-generic).
pub const SYS_DUP: usize = 23;
/// `AT_FDCWD`.
const AT_FDCWD: isize = -100;
/// `tmp-ord`'s file, in the initramfs root (RAM, as AzOS's `/tmp`).
const TMP_PATH: &[u8] = b"/vsb.tmp\0";

/// Poll attempts before `fork_exit_wait` gives up. Same bound as the Azos
/// lane, so neither side can look better by being allowed to try longer.
const POLL_BOUND: u32 = 100_000;

// Used by `fork_exit_wait`'s `wait4`. It carried `#[allow(dead_code)]` and a
// comment saying it was "kept for when the lane measures the full life cycle
// again" — which is now.
/// The thread-shaped `clone` (wave 13): `syscall5`'s five arguments, and
/// `entry` for the child. The child resumes after the `ecall` with `a0 == 0`
/// on its new stack and jumps to `entry` (in a callee-saved register, which
/// the child's copy of the register file keeps), which never returns; the
/// parent gets the TID. A helper of its own because no Rust code may run in
/// the child before it has left this frame.
#[inline(always)]
unsafe fn syscall7(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, entry: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            "bnez a0, 2f",
            "jalr s2",
            "2:",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("s2") entry,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            options(nostack),
        );
    }
    ret
}

// ── vDSO: locate it and resolve `__vdso_clock_gettime` without libc ─────────
//
// Normally the dynamic linker does this. There is none here, so it is done by
// hand, in four steps:
//
//   1. The kernel leaves `argc`, `argv[]`, `envp[]` and then the **auxiliary
//      vector** on the initial stack: (type, value) pairs up to `AT_NULL`. The
//      original `sp` must be captured, which is why `_start` is naked.
//   2. `AT_SYSINFO_EHDR` (33) gives the base address of the vDSO ELF.
//   3. Its program headers yield `PT_DYNAMIC`, and from there `DT_SYMTAB`,
//      `DT_STRTAB` and `DT_HASH`.
//   4. `DT_HASH[1]` is `nchain`, which **is** the symbol count: a linear scan
//      comparing names suffices.
//
// If any of this fails, `vdso_ready()` returns `false` and the lane reports no
// number. **It never falls back to `clock_gettime` as a syscall**: that
// fallback would measure a trap and label it vDSO, which is exactly the lie
// this lane exists not to tell.

const AT_NULL: usize = 0;
const AT_SYSINFO_EHDR: usize = 33;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const CLOCK_MONOTONIC: i32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timespec { tv_sec: i64, tv_nsec: i64 }

type ClockGettimeFn = unsafe extern "C" fn(i32, *mut Timespec) -> i32;
type GetCpuFn = unsafe extern "C" fn(*mut u32, *mut u32, usize) -> i32;

/// Generic ABI: `clock_gettime` is 113 and `getcpu` is 168.
pub const SYS_CLOCK_GETTIME: usize = 113;
pub const SYS_GETCPU: usize = 168;

struct VdsoSlot(core::cell::UnsafeCell<usize>);
unsafe impl Sync for VdsoSlot {}
/// Address of `__vdso_clock_gettime`, or 0 if it could not be resolved.
static VDSO_FN: VdsoSlot = VdsoSlot(core::cell::UnsafeCell::new(0));
/// Same for `__vdso_getcpu`.
static VDSO_CPU: VdsoSlot = VdsoSlot(core::cell::UnsafeCell::new(0));

#[inline(always)]
unsafe fn rd_u64(p: usize) -> u64 { unsafe { core::ptr::read_unaligned(p as *const u64) } }
#[inline(always)]
unsafe fn rd_u32(p: usize) -> u32 { unsafe { core::ptr::read_unaligned(p as *const u32) } }
#[inline(always)]
unsafe fn rd_u16(p: usize) -> u16 { unsafe { core::ptr::read_unaligned(p as *const u16) } }

/// Compare a NUL-terminated name against a literal.
unsafe fn name_eq(p: usize, want: &[u8]) -> bool {
    for (i, w) in want.iter().enumerate() {
        if unsafe { *((p + i) as *const u8) } != *w { return false; }
    }
    unsafe { *((p + want.len()) as *const u8) == 0 }
}

/// Walk the auxiliary vector and resolve the symbol. Call once, with the `sp`
/// the kernel handed the process.
pub fn vdso_init(sp: usize) {
    unsafe {
        // argc, then argv[argc], then NULL, then envp up to NULL.
        let argc = rd_u64(sp) as usize;
        let mut p = sp + 8 + argc * 8 + 8;      // skip argv[] and its NULL
        while rd_u64(p) != 0 { p += 8; }        // skip envp[]
        p += 8;                                  // skip envp's NULL

        // Auxiliary vector: (type, value) pairs.
        let mut base = 0usize;
        loop {
            let tag = rd_u64(p) as usize;
            if tag == AT_NULL { break; }
            if tag == AT_SYSINFO_EHDR { base = rd_u64(p + 8) as usize; }
            p += 16;
        }
        if base == 0 { return; }

        // ELF64 header: e_phoff at 32, e_phentsize at 54, e_phnum at 56.
        let phoff = rd_u64(base + 32) as usize;
        let phentsize = rd_u16(base + 54) as usize;
        let phnum = rd_u16(base + 56) as usize;

        // The load bias: the vDSO is linked at a virtual base that need not be
        // 0, so addresses in the dynamic section must be corrected by
        // (real_base - vaddr_of_first_LOAD).
        let mut load_off = base;
        let mut dyn_addr = 0usize;
        for i in 0..phnum {
            let ph = base + phoff + i * phentsize;
            match rd_u32(ph) {
                PT_LOAD if load_off == base => {
                    load_off = base.wrapping_sub(rd_u64(ph + 16) as usize);
                }
                PT_DYNAMIC => dyn_addr = rd_u64(ph + 16) as usize,
                _ => {}
            }
        }
        if dyn_addr == 0 { return; }
        let dyn_addr = load_off.wrapping_add(dyn_addr);

        let (mut symtab, mut strtab, mut hash) = (0usize, 0usize, 0usize);
        let mut d = dyn_addr;
        loop {
            let tag = rd_u64(d);
            if tag == DT_NULL { break; }
            let val = rd_u64(d + 8) as usize;
            match tag {
                DT_SYMTAB => symtab = load_off.wrapping_add(val),
                DT_STRTAB => strtab = load_off.wrapping_add(val),
                DT_HASH   => hash   = load_off.wrapping_add(val),
                _ => {}
            }
            d += 16;
        }
        if symtab == 0 || strtab == 0 || hash == 0 { return; }

        // DT_HASH: [nbucket, nchain, ...]. `nchain` IS the symbol count.
        let nchain = rd_u32(hash + 4) as usize;
        for i in 0..nchain {
            let sym = symtab + i * 24;           // Elf64_Sym mide 24 bytes
            let st_name = rd_u32(sym) as usize;
            if st_name == 0 { continue; }
            let st_value = rd_u64(sym + 8) as usize;
            if st_value == 0 { continue; }
            let addr = load_off.wrapping_add(st_value);
            // The whole table is walked: several symbols are of interest and
            // returning on the first would leave the rest unresolved.
            if name_eq(strtab + st_name, b"__vdso_clock_gettime") {
                *VDSO_FN.0.get() = addr;
            } else if name_eq(strtab + st_name, b"__vdso_getcpu") {
                *VDSO_CPU.0.get() = addr;
            }
        }
    }
}

impl Vdso for LinuxAbi {
    fn vdso_ready(&self) -> bool {
        unsafe { *VDSO_FN.0.get() != 0 }
    }

    #[inline(always)]
    fn clock_vdso(&self) -> u64 {
        let f = unsafe { *VDSO_FN.0.get() };
        if f == 0 { return 0; }
        let mut ts = Timespec::default();
        let g: ClockGettimeFn = unsafe { core::mem::transmute(f) };
        unsafe { g(CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64)
    }

    #[inline(always)]
    fn clock_syscall(&self) -> u64 {
        // The SAME operation, forced through the trap. This is the pair that
        // gives the vDSO number its meaning.
        let mut ts = Timespec::default();
        unsafe {
            syscall2(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as usize,
                     &mut ts as *mut Timespec as usize);
        }
        (ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64)
    }

    #[inline(always)]
    fn cpu_vdso(&self) -> Option<u64> {
        let f = unsafe { *VDSO_CPU.0.get() };
        if f == 0 { return None; }
        let (mut cpu, mut node) = (0u32, 0u32);
        let g: GetCpuFn = unsafe { core::mem::transmute(f) };
        unsafe { g(&mut cpu, &mut node, 0) };
        Some(cpu as u64)
    }

    #[inline(always)]
    fn cpu_syscall(&self) -> Option<u64> {
        let (mut cpu, mut node) = (0u32, 0u32);
        unsafe {
            syscall3(SYS_GETCPU, &mut cpu as *mut u32 as usize,
                     &mut node as *mut u32 as usize, 0);
        }
        Some(cpu as u64)
    }
}

// Generic ABI: socket 198, bind 200, connect 203, sendto 206, recvfrom 207.
// **There are no bare `send`/`recv`** in this ABI; `sendto`/`recvfrom` are
// used with a null address on a connected socket.
pub const SYS_SOCKET: usize = 198;
pub const SYS_BIND: usize = 200;
pub const SYS_CONNECT: usize = 203;
pub const SYS_SENDTO: usize = 206;
pub const SYS_RECVFROM: usize = 207;
/// Do not block in `recvfrom`.
const MSG_DONTWAIT: usize = 0x40;
pub const SYS_IOCTL: usize = 29;
/// `SIOCSIFFLAGS`: set an interface's flags.
const SIOCSIFFLAGS: usize = 0x8914;
/// `IFF_UP | IFF_RUNNING`.
const IFF_UP_RUNNING: u16 = 0x41;

/// Bring `lo` up.
///
/// **Needed, and not obvious.** In a minimal initramfs nobody has run
/// `ifconfig lo up`: the interface exists but is **down**, and binding to
/// `127.0.0.1` fails with `EADDRNOTAVAIL`. With libc the system's init would
/// do this; here there is no init, so it is done by hand with the same `ioctl`
/// `ifconfig` would use.
///
/// `struct ifreq` is 40 bytes: name in the first 16, flags as a `short` at
/// offset 16.
fn bring_lo_up() -> bool {
    let fd = unsafe { syscall3(SYS_SOCKET, 2, 2, 0) };
    if fd < 0 { return false; }
    let mut ifr = [0u8; 40];
    ifr[0] = b'l';
    ifr[1] = b'o';
    ifr[16..18].copy_from_slice(&IFF_UP_RUNNING.to_ne_bytes());
    let rc = unsafe {
        syscall3(SYS_IOCTL, fd as usize, SIOCSIFFLAGS, ifr.as_ptr() as usize)
    };
    rc >= 0
}

/// A 16-byte `sockaddr_in`: family, port in network order, IPv4, padding.
fn sockaddr_in(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&2u16.to_le_bytes());   // AF_INET
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip);
    sa
}

struct NetSlot(core::cell::UnsafeCell<(isize, bool)>);
unsafe impl Sync for NetSlot {}
static NET: NetSlot = NetSlot(core::cell::UnsafeCell::new((-1isize, false)));

impl Net for LinuxAbi {
    fn net_ready(&self) -> bool { true }

    fn net_setup(&self, local_port: u16, peer_port: u16) -> Result<(), i64> {
        // `127.0.0.1`: Linux's loopback. Azos uses its own IP because its
        // local delivery is conditioned on `dst == our_ip` and 127.0.0.0/8 is
        // not treated as local — a declared difference, not a hidden one.
        // `lo` is down in a minimal initramfs; without this the bind fails.
        // Idempotent: the child brings it up too and nothing breaks.
        bring_lo_up();

        let fd = unsafe { syscall3(SYS_SOCKET, 2, 2, 0) };   // AF_INET, SOCK_DGRAM
        if fd < 0 { return Err(-2000 + fd as i64); }
        let local = sockaddr_in([127, 0, 0, 1], local_port);
        let peer = sockaddr_in([127, 0, 0, 1], peer_port);
        unsafe {
            let rb = syscall3(SYS_BIND, fd as usize, local.as_ptr() as usize, 16);
            if rb < 0 { return Err(-3000 + rb as i64); }
            let rc = syscall3(SYS_CONNECT, fd as usize, peer.as_ptr() as usize, 16);
            if rc < 0 { return Err(-4000 + rc as i64); }
            *NET.0.get() = (fd, true);
        }
        Ok(())
    }

    #[inline(always)]
    fn net_round_trip(&self) -> Option<usize> {
        let (fd, ok) = unsafe { *NET.0.get() };
        if !ok { return None; }
        let out = [0xA5u8; NET_PAYLOAD];
        unsafe {
            if syscall6(SYS_SENDTO, fd as usize, out.as_ptr() as usize, NET_PAYLOAD, 0, 0, 0)
                != NET_PAYLOAD as isize { return None; }
        }
        // **`MSG_DONTWAIT` on purpose.** Without it Linux would block and the
        // scheduler would wake it; Azos cannot, because its `recv` does not
        // block. Comparing them that way would measure "blocking versus
        // polling" instead of the network path. Both poll with yield.
        let mut buf = [0u8; NET_PAYLOAD];
        for _ in 0..NET_POLL_BUDGET {
            let n = unsafe {
                syscall6(SYS_RECVFROM, fd as usize, buf.as_mut_ptr() as usize,
                         NET_PAYLOAD, MSG_DONTWAIT, 0, 0)
            };
            if n > 0 { return Some(n as usize); }
            unsafe { syscall0(SYS_SCHED_YIELD) };
        }
        None
    }

    fn net_echo(&self, n: u64) {
        let (fd, ok) = unsafe { *NET.0.get() };
        if !ok { return; }
        let mut buf = [0u8; NET_PAYLOAD];
        let mut served = 0u64;
        while served < n {
            let got = unsafe {
                syscall6(SYS_RECVFROM, fd as usize, buf.as_mut_ptr() as usize,
                         NET_PAYLOAD, MSG_DONTWAIT, 0, 0)
            };
            if got > 0 {
                unsafe {
                    syscall6(SYS_SENDTO, fd as usize, buf.as_ptr() as usize,
                             got as usize, 0, 0, 0);
                }
                served += 1;
            } else {
                unsafe { syscall0(SYS_SCHED_YIELD) };
            }
        }
    }
}

// ── Wave 6 counterparts: futex, the SPSC ring, io_uring ─────────────────────
//
// The AzOS lanes these answer live in `main.rs` (`ring_lanes`,
// `ioring_lanes`); each function below says which one it mirrors and where
// the work differs because the two kernels do not offer the same object.
// Iteration counts, batch sizes and labels are `main.rs`'s own constants and
// its `label_n`, so the two sides cannot drift apart in what they count.
//
// Generic ABI numbers once more: `close` 57, `futex` 98, `clock_nanosleep`
// 115, `io_uring_setup` 425, `io_uring_enter` 426.
pub const SYS_CLOSE: usize = 57;
pub const SYS_FUTEX: usize = 98;
pub const SYS_CLOCK_NANOSLEEP: usize = 115;
pub const SYS_IO_URING_SETUP: usize = 425;
pub const SYS_IO_URING_ENTER: usize = 426;

/// `FUTEX_WAIT` / `FUTEX_WAKE` WITHOUT `FUTEX_PRIVATE_FLAG`: the ring's page
/// is shared with a forked child, a different `mm`, and a private futex is
/// keyed by address space. The shared key (inode + page offset of the shmem
/// page) is also the closest analogue of what AzOS's notify resolves: a
/// (region, offset) pair from the caller's mapping.
const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const EAGAIN: isize = -11;
const EFAULT: isize = -14;
const ETIME: i32 = -62;
const ETIMEDOUT: isize = -110;
/// `MAP_SHARED | MAP_ANONYMOUS`: the ring page, inherited by the fork.
const MAP_SHARED_ANONYMOUS: usize = 0x21;
const TIMER_ABSTIME: usize = 1;
/// An absolute time already in the past on `CLOCK_MONOTONIC`: AzOS's
/// `sleep_until_ns(0)` and its `OP_TIMER` with deadline 0.
static TS_ZERO: Timespec = Timespec { tv_sec: 0, tv_nsec: 0 };
/// `azos_libsys::RING_WAIT_NS` (the ring's lost-wake backstop) as a
/// relative `timespec`, so both sides give up after the same wait.
static RING_WAIT_TS: Timespec = Timespec {
    tv_sec: (azos_libsys::RING_WAIT_NS / 1_000_000_000) as i64,
    tv_nsec: (azos_libsys::RING_WAIT_NS % 1_000_000_000) as i64,
};

#[inline(always)]
fn futex_wake(addr: usize, n: u32) -> isize {
    unsafe { syscall3(SYS_FUTEX, addr, FUTEX_WAKE, n as usize) }
}

/// `timeout` null = no limit, as AzOS's `NOTIFY_FOREVER`.
#[inline(always)]
fn futex_wait(addr: usize, expected: u32, timeout: *const Timespec) -> isize {
    unsafe { syscall4(SYS_FUTEX, addr, FUTEX_WAIT, expected as usize, timeout as usize) }
}

use azos_libsys::{RingSleep, RingStats, RingStep, SpscRing};

/// `azos_libsys::ring_sleep`, with `futex` where AzOS has notify.
fn ring_sleep(s: RingSleep, woke: impl FnOnce(), stats: &mut RingStats) {
    if let RingSleep::Wait { addr, expected } = s {
        stats.waits += 1;
        if futex_wait(addr, expected, &RING_WAIT_TS) == ETIMEDOUT {
            stats.timeouts += 1;
        }
        woke();
    }
}

/// `azos_libsys::ring_push`: the same decisions (the shared pure core),
/// the Linux kernel entry.
fn ring_push(r: &SpscRing, v: u64, stats: &mut RingStats) {
    loop {
        match r.try_push(v) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => {
                stats.wakes += 1;
                let _ = futex_wake(addr, 1);
                return;
            }
            RingStep::Blocked => ring_sleep(r.producer_sleep(), || r.producer_woke(), stats),
        }
    }
}

/// `azos_libsys::ring_pop`, likewise.
fn ring_pop(r: &SpscRing, stats: &mut RingStats) -> u64 {
    loop {
        match r.try_pop() {
            (RingStep::Done, v) => return v,
            (RingStep::DoneWake { addr }, v) => {
                stats.wakes += 1;
                let _ = futex_wake(addr, 1);
                return v;
            }
            (RingStep::Blocked, _) => ring_sleep(r.consumer_sleep(), || r.consumer_woke(), stats),
        }
    }
}

/// The server half, `serve.rs`'s `ring_serve` line for line: pop requests,
/// answer as the tag says, return on `TAG_STOP`.
fn ring_serve(abi: &impl Abi, base: usize) {
    use super::ipc_proto::ring;
    let req = SpscRing { base, cap: ring::RING_CAP };
    let resp = SpscRing { base: base + ring::RING_RESP_OFFSET, cap: ring::RING_CAP };
    let mut st = RingStats::default();
    let (mut items, mut ops0) = (0u64, 0u64);
    loop {
        let v = ring_pop(&req, &mut st);
        match v >> 56 {
            ring::TAG_PING => ring_push(&resp, v.wrapping_add(1), &mut st),
            ring::TAG_STREAM => {
                if items == 0 { ops0 = st.waits + st.wakes; }
                items += 1;
            }
            ring::TAG_STREAM_END => {
                let ops = (st.waits + st.wakes).saturating_sub(ops0);
                ring_push(&resp, (items << 32) | (ops & 0xFFFF_FFFF), &mut st);
                ring_push(&resp, abi.current_cpu().unwrap_or(u64::MAX), &mut st);
                items = 0;
            }
            ring::TAG_STOP => {
                ring_push(&resp, ring::RING_STOP_ACK, &mut st);
                return;
            }
            _ => {}
        }
    }
}

/// Counterpart of `main.rs`'s `ring_lanes`: `notify-wake-empty`,
/// `notify-wait-eagain`, `ring-pingpong`, `ring-stream`.
///
/// **Same work.** The notify pair runs on the request ring's head word inside
/// the shared page, before any peer exists (no waiter, and a word that holds
/// 0 against an expected 1), and the answers are checked exactly as AzOS
/// checks them: wake 0, wait `-EAGAIN`, and a wake on an unmapped address
/// `-EFAULT` (-14 on both kernels). The ring lanes run the SAME pure ring
/// code (`azos_libsys::SpscRing`), the same protocol (`ipc_proto::ring`)
/// and the same counts and canary.
///
/// **Different, and why.** AzOS's server is `VSSRV.ELF`, which receives the
/// ring's `Cap<Shm>` in a fast IPC call; Linux has no capability to move, so
/// the page is `MAP_SHARED | MAP_ANONYMOUS` and the server is a child forked
/// after it is mapped. That setup is outside every measured batch on both
/// sides.
pub fn ring_lanes(abi: &impl Abi, floor_ns: u64) {
    use super::bench_core::{batch, N_VDSO, PAGE};
    use super::ipc_proto::ring::*;
    use super::{fail_line, put_u, report, N_RING, N_RING_STREAM, N_RING_WARM, RING_CANARY_DIVISOR};

    let va = unsafe {
        syscall6(SYS_MMAP, 0, PAGE as usize, PROT_READ_WRITE, MAP_SHARED_ANONYMOUS, usize::MAX, 0)
    };
    if va < 0 { fail_line(abi, b"ring mmap shared", va as i64); return; }
    let va = va as usize;
    let req = SpscRing { base: va, cap: RING_CAP };
    let resp = SpscRing { base: va + RING_RESP_OFFSET, cap: RING_CAP };
    req.init();
    resp.init();

    let w0 = req.base;
    let t_wk = batch(N_VDSO, || { core::hint::black_box(futex_wake(w0, 1)); });
    let t_wt = batch(N_VDSO, || { core::hint::black_box(futex_wait(w0, 1, core::ptr::null())); });
    if futex_wake(w0, 1) != 0 || futex_wait(w0, 1, core::ptr::null()) != EAGAIN {
        fail_line(abi, b"notify empty-path answers", -1);
    } else {
        report(abi, b"notify-wake-empty", t_wk, N_VDSO, floor_ns);
        report(abi, b"notify-wait-eagain", t_wt, N_VDSO, floor_ns);
    }
    if futex_wake(0x1000, 1) != EFAULT {
        fail_line(abi, b"notify on an unmapped address", futex_wake(0x1000, 1) as i64);
    }

    match unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) } {
        0 => { ring_serve(abi, va); exit(0) }
        pid if pid > 0 => {}
        rc => { fail_line(abi, b"ring server fork", rc as i64); return; }
    }

    let mut st = RingStats::default();
    let mut bad = 0u64;
    for i in 0..N_RING_WARM {
        ring_push(&req, ring_tag(TAG_PING, i), &mut st);
        if ring_pop(&resp, &mut st) != ring_tag(TAG_PING, i) + 1 { bad += 1; }
    }
    let mut st = RingStats::default();
    let sw0 = abi.ctx_switches();
    let mut i = 0u64;
    let t_pp = batch(N_RING, || {
        ring_push(&req, ring_tag(TAG_PING, i), &mut st);
        if ring_pop(&resp, &mut st) != ring_tag(TAG_PING, i) + 1 { bad += 1; }
        i += 1;
    });
    let sw1 = abi.ctx_switches();
    if bad != 0 || st.timeouts != 0 {
        fail_line(abi, b"ring-pingpong wrong answers or lost wakes", -((bad + st.timeouts) as i64));
    } else {
        report(abi, b"ring-pingpong", t_pp, N_RING, floor_ns);
        abi.write(b"[VSBENCH] ring-pingpong client entries: waits=");
        put_u(abi, st.waits);
        abi.write(b" wakes=");
        put_u(abi, st.wakes);
        if let (Some((v0, i0)), Some((v1, i1))) = (sw0, sw1) {
            abi.write(b" switches=");
            put_u(abi, (v1 - v0) + (i1 - i0));
        }
        abi.write(b" over ");
        put_u(abi, N_RING);
        abi.write(b" round trips\n");
    }

    let mut st = RingStats::default();
    let mut peer_entries = 0u64;
    let mut peer_hart = u64::MAX;
    let t_st = batch(1, || {
        for i in 0..N_RING_STREAM {
            ring_push(&req, ring_tag(TAG_STREAM, i), &mut st);
        }
        ring_push(&req, ring_tag(TAG_STREAM_END, 0), &mut st);
        peer_entries = ring_pop(&resp, &mut st);
        peer_hart = ring_pop(&resp, &mut st);
    });
    let (peer_count, peer_ops) = (peer_entries >> 32, peer_entries & 0xFFFF_FFFF);
    let my_hart = abi.current_cpu().unwrap_or(u64::MAX - 1);
    let client_ops = st.waits + st.wakes;
    if peer_count != N_RING_STREAM || st.timeouts != 0 {
        fail_line(abi, b"ring-stream lost items or wakes", -(st.timeouts as i64) - 1);
    } else {
        report(abi, b"ring-stream", t_st, N_RING_STREAM, floor_ns);
    }
    abi.write(b"[VSBENCH] ring-stream kernel entries: client=");
    put_u(abi, client_ops);
    abi.write(b" server=");
    put_u(abi, peer_ops);
    abi.write(b" over ");
    put_u(abi, N_RING_STREAM);
    abi.write(b" items, client hart=");
    put_u(abi, my_hart);
    abi.write(b" server hart=");
    put_u(abi, peer_hart);
    abi.write(b"\n");
    if my_hart == peer_hart && (client_ops + peer_ops) * RING_CANARY_DIVISOR > N_RING_STREAM {
        fail_line(abi, b"ring-stream entered the kernel while neither empty nor full",
            (client_ops + peer_ops) as i64);
    }

    ring_push(&req, ring_tag(TAG_STOP, 0), &mut st);
    if ring_pop(&resp, &mut st) != RING_STOP_ACK {
        fail_line(abi, b"ring stop", -5);
    }
}

// ── The driver-request A/B (wave 11, SHMRING) ───────────────────────────────

use azos_libsys::{SpscBytes, SpscSlots};

/// `azos_libsys::slots_push`, with `futex` where AzOS has notify.
fn slots_push<const W: usize>(r: &SpscSlots<W>, item: &[u64; W], stats: &mut RingStats) {
    loop {
        match r.try_push(item) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => {
                stats.wakes += 1;
                let _ = futex_wake(addr, 1);
                return;
            }
            RingStep::Blocked => ring_sleep(r.producer_sleep(), || r.producer_woke(), stats),
        }
    }
}

/// `azos_libsys::slots_pop`, likewise.
fn slots_pop<const W: usize>(r: &SpscSlots<W>, out: &mut [u64; W], stats: &mut RingStats) {
    loop {
        match r.try_pop(out) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => {
                stats.wakes += 1;
                let _ = futex_wake(addr, 1);
                return;
            }
            RingStep::Blocked => ring_sleep(r.consumer_sleep(), || r.consumer_woke(), stats),
        }
    }
}

/// `serve.rs`'s `drvring_serve` line for line.
fn drvring_serve(abi: &impl Abi, base: usize) {
    use super::ipc_proto::drv;
    let req = SpscSlots::<{ drv::DRV_WORDS }> { base, cap: drv::DRV_RING_CAP };
    let resp = SpscSlots::<{ drv::DRV_WORDS }> { base: base + drv::DRV_RESP_OFFSET, cap: drv::DRV_RING_CAP };
    let mut st = RingStats::default();
    let mut it = [0u64; drv::DRV_WORDS];
    loop {
        let waits_before = st.waits;
        slots_pop(&req, &mut it, &mut st);
        match it[0] >> 56 {
            drv::TAG_CALL => {
                for w in it.iter_mut() { *w = w.wrapping_add(1); }
                slots_push(&resp, &it, &mut st);
            }
            drv::TAG_STATS => {
                let mut a = [0u64; drv::DRV_WORDS];
                a[0] = waits_before;
                a[1] = st.wakes;
                a[2] = st.timeouts;
                a[3] = abi.current_cpu().unwrap_or(u64::MAX);
                slots_push(&resp, &a, &mut st);
                st = RingStats::default();
            }
            drv::TAG_STOP => {
                let mut a = [0u64; drv::DRV_WORDS];
                a[0] = drv::DRV_STOP_ACK;
                slots_push(&resp, &a, &mut st);
                return;
            }
            _ => {}
        }
    }
}

/// Counterpart of `main.rs`'s `drv_lanes`: `drv-call`, `drvring-call`,
/// `drvring-batch8`, `drvring-ops`.
///
/// **`drv-call` on Linux** is a user-space driver's ordinary request path: a
/// 64-byte request written to a pipe, the driver process blocked in `read`,
/// its 64-byte answer written back — two traps and (one hart) two switches
/// per request, as AzOS's proxy path. Linux has no in-kernel proxy in
/// front of a user driver, so the AzOS lane also carries its sensor-read
/// handler and capability check; that difference is part of what is compared.
///
/// **The ring lanes** run the SAME pure ring code (`SpscSlots<8>`), protocol
/// (`ipc_proto::drv`), counts and canary, with `futex` for notify, against a
/// forked child on a `MAP_SHARED | MAP_ANONYMOUS` page.
pub fn drv_lanes(abi: &impl Abi, floor_ns: u64) {
    use super::bench_core::{batch, PAGE};
    use super::ipc_proto::drv::*;
    use super::{drv_entries_line, drvring_ops, fail_line, put_u, report, N_DRV, N_DRV_WARM};

    // ── drv-call ──
    let mut p2c = [0i32; 2];
    let mut c2p = [0i32; 2];
    let ok = unsafe {
        syscall2(SYS_PIPE2, p2c.as_mut_ptr() as usize, 0) >= 0
            && syscall2(SYS_PIPE2, c2p.as_mut_ptr() as usize, 0) >= 0
    };
    if !ok { fail_line(abi, b"drv-call pipe2", -1); return; }
    match unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) } {
        0 => {
            let mut buf = [0u8; 64];
            for _ in 0..N_DRV_WARM + N_DRV {
                unsafe {
                    if syscall3(SYS_READ, p2c[0] as usize, buf.as_mut_ptr() as usize, 64) != 64 { break; }
                    buf[0] = buf[0].wrapping_add(1);
                    if syscall3(SYS_WRITE, c2p[1] as usize, buf.as_ptr() as usize, 64) != 64 { break; }
                }
            }
            exit(0)
        }
        pid if pid > 0 => {}
        rc => { fail_line(abi, b"drv-call fork", rc as i64); return; }
    }
    let mut req = [0u8; 64];
    let mut ans = [0u8; 64];
    let mut bad = 0u64;
    let mut call = |i: u64, bad: &mut u64| unsafe {
        req[0] = i as u8;
        if syscall3(SYS_WRITE, p2c[1] as usize, req.as_ptr() as usize, 64) != 64
            || syscall3(SYS_READ, c2p[0] as usize, ans.as_mut_ptr() as usize, 64) != 64
            || ans[0] != (i as u8).wrapping_add(1)
        {
            *bad += 1;
        }
    };
    for i in 0..N_DRV_WARM { call(i, &mut bad); }
    let sw0 = abi.ctx_switches();
    let mut i = 0u64;
    let t = batch(N_DRV, || { call(i, &mut bad); i += 1; });
    let sw1 = abi.ctx_switches();
    if bad != 0 {
        fail_line(abi, b"drv-call reads not answered by the driver", -(bad as i64));
    } else {
        report(abi, b"drv-call", t, N_DRV, floor_ns);
        if let (Some((v0, i0)), Some((v1, i1))) = (sw0, sw1) {
            abi.write(b"[VSBENCH] drv-call switches=");
            put_u(abi, (v1 - v0) + (i1 - i0));
            abi.write(b" over ");
            put_u(abi, N_DRV);
            abi.write(b" requests\n");
        }
    }

    // ── drvring-* ──
    let va = unsafe {
        syscall6(SYS_MMAP, 0, PAGE as usize, PROT_READ_WRITE, MAP_SHARED_ANONYMOUS, usize::MAX, 0)
    };
    if va < 0 { fail_line(abi, b"drvring mmap shared", va as i64); return; }
    let va = va as usize;
    let req = SpscSlots::<DRV_WORDS> { base: va, cap: DRV_RING_CAP };
    let resp = SpscSlots::<DRV_WORDS> { base: va + DRV_RESP_OFFSET, cap: DRV_RING_CAP };
    req.init();
    resp.init();
    match unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) } {
        0 => { drvring_serve(abi, va); exit(0) }
        pid if pid > 0 => {}
        rc => { fail_line(abi, b"drvring server fork", rc as i64); return; }
    }
    let mut it = [0u64; DRV_WORDS];
    let mut bad = 0u64;
    let server_stats = |st: &mut RingStats| -> (u64, u64, u64, u64) {
        let mut a = [0u64; DRV_WORDS];
        slots_push(&req, &drv_req(TAG_STATS, 0), st);
        slots_pop(&resp, &mut a, st);
        (a[0], a[1], a[2], a[3])
    };
    let mut st = RingStats::default();
    for i in 0..N_DRV_WARM {
        slots_push(&req, &drv_req(TAG_CALL, i), &mut st);
        slots_pop(&resp, &mut it, &mut st);
        if !drv_is_answer(&it, i) { bad += 1; }
    }
    let _ = server_stats(&mut st);

    let mut st = RingStats::default();
    let sw0 = abi.ctx_switches();
    let mut i = 0u64;
    let t_call = batch(N_DRV, || {
        slots_push(&req, &drv_req(TAG_CALL, i), &mut st);
        slots_pop(&resp, &mut it, &mut st);
        if !drv_is_answer(&it, i) { bad += 1; }
        i += 1;
    });
    let sw1 = abi.ctx_switches();
    let (c_call, sv_call) = (st, server_stats(&mut RingStats::default()));

    let mut st = RingStats::default();
    let sw2 = abi.ctx_switches();
    let mut i = 0u64;
    let t_b8 = batch(N_DRV / DRV_BATCH, || {
        for k in 0..DRV_BATCH { slots_push(&req, &drv_req(TAG_CALL, i + k), &mut st); }
        for k in 0..DRV_BATCH {
            slots_pop(&resp, &mut it, &mut st);
            if !drv_is_answer(&it, i + k) { bad += 1; }
        }
        i += DRV_BATCH;
    });
    let sw3 = abi.ctx_switches();
    let (c_b8, sv_b8) = (st, server_stats(&mut RingStats::default()));
    let sw = |a: Option<(u64, u64)>, b: Option<(u64, u64)>| match (a, b) {
        (Some((v0, i0)), Some((v1, i1))) => Some((v1 - v0) + (i1 - i0)),
        _ => None,
    };
    let timeouts = c_call.timeouts + sv_call.2 + c_b8.timeouts + sv_b8.2;
    if bad != 0 || timeouts != 0 {
        fail_line(abi, b"drvring wrong answers or lost wakes", -((bad + timeouts) as i64));
    } else {
        report(abi, b"drvring-call", t_call, N_DRV, floor_ns);
        drv_entries_line(abi, b"drvring-call", (c_call.waits, c_call.wakes), (sv_call.0, sv_call.1),
            sw(sw0, sw1), N_DRV);
        report(abi, b"drvring-batch8", t_b8, N_DRV, floor_ns);
        drv_entries_line(abi, b"drvring-batch8", (c_b8.waits, c_b8.wakes), (sv_b8.0, sv_b8.1),
            sw(sw2, sw3), N_DRV);
        // No canary here: Linux preempts a waker for the task it woke even on
        // one hart, so the sides interleave within a batch and the entry
        // count measures the scheduler, not the doorbell (the same reason the
        // pre-existing `ring-stream` canary fails on this side at `-smp 1`).
    }
    drvring_ops(abi, floor_ns);

    let mut a = [0u64; DRV_WORDS];
    slots_push(&req, &drv_req(TAG_STOP, 0), &mut st);
    slots_pop(&resp, &mut a, &mut st);
    if a[0] != DRV_STOP_ACK { fail_line(abi, b"drvring stop", -5); }
}

/// Counterpart of `main.rs`'s `frame_lanes`: the same ring, producer and
/// consumer code (`SpscBytes`, `BytesProducer`, `frame_consume`), a forked
/// child producing, `futex` for notify, on a `MAP_SHARED | MAP_ANONYMOUS`
/// span of the same size.
pub fn frame_lanes(abi: &impl Abi, floor_ns: u64) {
    use super::bench_core::batch;
    use super::ipc_proto::frame::*;
    use super::{fail_line, frame_consume, frame_report, FrameRun, N_FRAMES};
    use azos_libsys::{BytesProducer, Publish};
    let len = FRAME_RING_BYTES.next_multiple_of(4096);
    let va = unsafe { syscall6(SYS_MMAP, 0, len, PROT_READ_WRITE, MAP_SHARED_ANONYMOUS, usize::MAX, 0) };
    if va < 0 { fail_line(abi, b"frame mmap shared", va as i64); return; }
    let r = SpscBytes { base: va as usize, cap: FRAME_RING_SLOTS, slot_bytes: FRAME_SLOT_BYTES };
    // The producer's side is set up BEFORE the fork, as VSSRV does it before
    // answering the setup call.
    let mut p = BytesProducer::new(r);
    match unsafe { syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0) } {
        0 => {
            let mut st = RingStats::default();
            let mut i = 0u64;
            while i <= N_FRAMES {
                if p.is_full() {
                    if let RingSleep::Wait { addr, expected } = p.producer_sleep() {
                        st.waits += 1;
                        let _ = futex_wait(addr, expected, &RING_WAIT_TS);
                        p.producer_woke();
                    }
                    continue;
                }
                let pr = if i < N_FRAMES {
                    p.push_with(0, |dst, room| frame_fill(dst, room, i))
                } else {
                    let mut s = [0u8; FRAME_STATS_BYTES];
                    s[..8].copy_from_slice(&st.waits.to_le_bytes());
                    s[8..].copy_from_slice(&st.wakes.to_le_bytes());
                    p.push(0, &s)
                };
                if pr == Publish::Wake {
                    st.wakes += 1;
                    let _ = futex_wake(r.base, 1);
                }
                i += 1;
            }
            exit(0)
        }
        pid if pid > 0 => {}
        rc => { fail_line(abi, b"frame producer fork", rc as i64); return; }
    }
    let mut run = FrameRun::default();
    let t = batch(1, || {
        run = frame_consume(&r, N_FRAMES,
            |a, e| futex_wait(a, e, &RING_WAIT_TS) == ETIMEDOUT,
            |a| { let _ = futex_wake(a, 1); });
    });
    frame_report(abi, t, &run, floor_ns);
}

// ── io_uring, by hand ────────────────────────────────────────────────────────
//
// The ABI (`include/uapi/linux/io_uring.h`), without liburing for the same
// reason there is no libc: `io_uring_setup` fills `struct io_uring_params`
// with the ring offsets, three `mmap`s of the ring fd expose the SQ ring, the
// CQ ring and the SQE array, and `io_uring_enter` submits and waits.

const IORING_OFF_SQ_RING: usize = 0;
const IORING_OFF_CQ_RING: usize = 0x800_0000;
const IORING_OFF_SQES: usize = 0x1000_0000;
const IORING_ENTER_GETEVENTS: usize = 1;
const IORING_OP_NOP: u8 = 0;
const IORING_OP_TIMEOUT: u8 = 11;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IORING_TIMEOUT_ABS: u32 = 1;
/// `MAP_SHARED | MAP_POPULATE`, what liburing maps the rings with.
const MAP_SHARED_POPULATE: usize = 0x01 | 0x8000;
/// AzOS's ring holds 32 entries (`RING_SQ_SIZE`); the largest batch is 32.
const URING_ENTRIES: u32 = 32;
const SQE_BYTES: usize = 64;
const CQE_BYTES: usize = 16;
/// `struct io_uring_params` as 30 `u32` words: 10 of header, then
/// `io_sqring_offsets` (words 10..20) and `io_cqring_offsets` (20..30).
const P_SQ_ENTRIES: usize = 0;
const P_CQ_ENTRIES: usize = 1;
const P_SQ_HEAD: usize = 10;
const P_SQ_TAIL: usize = 11;
const P_SQ_MASK: usize = 12;
const P_SQ_ARRAY: usize = 16;
const P_CQ_HEAD: usize = 20;
const P_CQ_TAIL: usize = 21;
const P_CQ_MASK: usize = 22;
const P_CQES: usize = 25;

struct Uring {
    fd: usize,
    sq: usize,
    sq_len: usize,
    cq: usize,
    cq_len: usize,
    sqes: usize,
    sqes_len: usize,
    p: [u32; 30],
}

impl Uring {
    fn setup() -> Result<Uring, isize> {
        let mut p = [0u32; 30];
        let fd = unsafe { syscall2(SYS_IO_URING_SETUP, URING_ENTRIES as usize, p.as_mut_ptr() as usize) };
        if fd < 0 { return Err(fd); }
        let fd = fd as usize;
        let sq_len = p[P_SQ_ARRAY] as usize + p[P_SQ_ENTRIES] as usize * 4;
        let cq_len = p[P_CQES] as usize + p[P_CQ_ENTRIES] as usize * CQE_BYTES;
        let sqes_len = p[P_SQ_ENTRIES] as usize * SQE_BYTES;
        let map = |len: usize, off: usize| unsafe {
            syscall6(SYS_MMAP, 0, len, PROT_READ_WRITE, MAP_SHARED_POPULATE, fd, off)
        };
        let sq = map(sq_len, IORING_OFF_SQ_RING);
        let cq = map(cq_len, IORING_OFF_CQ_RING);
        let sqes = map(sqes_len, IORING_OFF_SQES);
        for m in [sq, cq, sqes] {
            if m < 0 { return Err(m); }
        }
        Ok(Uring { fd, sq: sq as usize, sq_len, cq: cq as usize, cq_len, sqes: sqes as usize, sqes_len, p })
    }

    #[inline(always)]
    fn word(&self, base: usize, off_idx: usize) -> &core::sync::atomic::AtomicU32 {
        unsafe { &*((base + self.p[off_idx] as usize) as *const core::sync::atomic::AtomicU32) }
    }

    /// One SQE, whole (liburing's `io_uring_prep_rw` writes every field too).
    #[inline(always)]
    fn push(&self, op: u8, fd: i32, addr: usize, len: u32, off: u64, op_flags: u32, user: u64) -> bool {
        use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
        let tail = self.word(self.sq, P_SQ_TAIL).load(Relaxed);
        let head = self.word(self.sq, P_SQ_HEAD).load(Acquire);
        if tail.wrapping_sub(head) >= self.p[P_SQ_ENTRIES] { return false; }
        let mask = unsafe { *((self.sq + self.p[P_SQ_MASK] as usize) as *const u32) };
        let idx = tail & mask;
        let sqe = self.sqes + idx as usize * SQE_BYTES;
        unsafe {
            core::ptr::write_bytes(sqe as *mut u8, 0, SQE_BYTES);
            core::ptr::write(sqe as *mut u8, op);
            core::ptr::write((sqe + 4) as *mut i32, fd);
            core::ptr::write((sqe + 8) as *mut u64, off);
            core::ptr::write((sqe + 16) as *mut u64, addr as u64);
            core::ptr::write((sqe + 24) as *mut u32, len);
            core::ptr::write((sqe + 28) as *mut u32, op_flags);
            core::ptr::write((sqe + 32) as *mut u64, user);
            core::ptr::write((self.sq + self.p[P_SQ_ARRAY] as usize + idx as usize * 4) as *mut u32, idx);
        }
        self.word(self.sq, P_SQ_TAIL).store(tail.wrapping_add(1), Release);
        true
    }

    /// Submit `n` and wait until `n` have completed: AzOS's submit returns
    /// with every completion posted, and an io_uring timer completes from its
    /// hrtimer, so waiting here is what makes the two batches the same unit.
    #[inline(always)]
    fn submit_and_wait(&self, n: u32) -> isize {
        unsafe {
            syscall6(SYS_IO_URING_ENTER, self.fd, n as usize, n as usize,
                     IORING_ENTER_GETEVENTS, 0, 0)
        }
    }

    #[inline(always)]
    fn pop(&self) -> Option<(u64, i32)> {
        use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
        let head = self.word(self.cq, P_CQ_HEAD).load(Relaxed);
        let tail = self.word(self.cq, P_CQ_TAIL).load(Acquire);
        if head == tail { return None; }
        let mask = unsafe { *((self.cq + self.p[P_CQ_MASK] as usize) as *const u32) };
        let cqe = self.cq + self.p[P_CQES] as usize + (head & mask) as usize * CQE_BYTES;
        let (user, res) = unsafe {
            (core::ptr::read(cqe as *const u64), core::ptr::read((cqe + 8) as *const i32))
        };
        self.word(self.cq, P_CQ_HEAD).store(head.wrapping_add(1), Release);
        Some((user, res))
    }

    fn destroy(&self) {
        unsafe {
            syscall2(SYS_MUNMAP, self.sqes, self.sqes_len);
            syscall2(SYS_MUNMAP, self.cq, self.cq_len);
            syscall2(SYS_MUNMAP, self.sq, self.sq_len);
            syscall1(SYS_CLOSE, self.fd);
        }
    }
}

/// Counterpart of `main.rs`'s `ioring_lanes`: `chan-call`, `sleep-until0`,
/// and `ioring-{nop,chan,tmr} xN` for the same N, over real `io_uring`.
///
/// Operation by operation:
///  * `nop`  — `IORING_OP_NOP` against AzOS's NOP entry; completes 0.
///  * `chan` — a channel is a AzOS object; the same bytes go through a pipe
///    instead, in one process, as AzOS's channel is written and read by one
///    task: `IORING_OP_WRITE` of 8 bytes then `IORING_OP_READ` of 8, pairs in
///    one batch, both completing 8. The twin, `chan-call`, is `write` +
///    `read` on the same pipe, quoted per operation (one pair = two).
///  * `tmr`  — `IORING_OP_TIMEOUT` with an ABSOLUTE deadline of 0 on
///    `CLOCK_MONOTONIC`, already past, completing `-ETIME`. The twin,
///    `sleep-until0`, is `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, 0)`.
///    **Not the same mechanism as AzOS's**: AzOS completes a past
///    deadline in the submit; Linux arms an hrtimer that has already expired
///    and completes it from the timer interrupt, so this batch includes a
///    real wait for that interrupt. That is what Linux does for this request,
///    and the number says so rather than hiding it.
///
/// Every batch submits N and waits for N (`io_uring_enter(fd, N, N,
/// GETEVENTS)`, one call), and every completion is checked, as on AzOS; a
/// wrong one prints `FAIL rc=`. The CQ drain is inside the measurement.
pub fn ioring_lanes(abi: &impl Abi, floor_ns: u64) {
    use super::bench_core::{batch, ns_per_op};
    use super::{label_n, put_i, put_u, report, IORING_BATCHES, N_IORING_OPS};

    let ring = match Uring::setup() {
        Ok(r) => r,
        Err(rc) => {
            abi.write(b"[VSBENCH] ioring-batch: FAIL rc=");
            put_i(abi, rc as i64);
            abi.write(b" (create)\n");
            return;
        }
    };
    let mut pipe = [0i32; 2];
    let rc = unsafe { syscall2(SYS_PIPE2, pipe.as_mut_ptr() as usize, 0) };
    if rc < 0 {
        abi.write(b"[VSBENCH] ioring-batch: FAIL rc=");
        put_i(abi, rc as i64);
        abi.write(b" (channel create)\n");
        ring.destroy();
        return;
    }
    let (rd, wr) = (pipe[0], pipe[1]);
    // The message at offset 0; receives land at 64, as on AzOS.
    let mut data = [0u8; 72];
    data[..8].copy_from_slice(b"vsbench!");
    let msg = data.as_ptr() as usize;
    let inbox = msg + 64;

    let drain = |n: u32, want: &dyn Fn(u32) -> i32, bad: &mut u32, last: &mut i64| {
        let mut i = 0;
        while let Some((_, result)) = ring.pop() {
            if result != want(i) {
                *bad += 1;
                *last = result as i64;
            }
            i += 1;
        }
        if i != n { *bad += 1; }
    };
    let fail = |what: &[u8], bad: u32, last: i64| {
        abi.write(b"[VSBENCH] ioring-batch ");
        abi.write(what);
        abi.write(b": FAIL rc=");
        put_i(abi, last);
        abi.write(b" in ");
        put_u(abi, bad as u64);
        abi.write(b" batches\n");
    };

    // Syscall twins, per operation.
    let chan_pairs = N_IORING_OPS / 2;
    let mut buf = [0u8; 8];
    let mut twin_bad = 0u32;
    let t_chan = batch(chan_pairs, || {
        if unsafe { syscall3(SYS_WRITE, wr as usize, msg, 8) } != 8 { twin_bad += 1; }
        if unsafe { syscall3(SYS_READ, rd as usize, buf.as_mut_ptr() as usize, 8) } != 8 { twin_bad += 1; }
    });
    let t_tmr = batch(N_IORING_OPS, || {
        let rc = unsafe {
            syscall4(SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC as usize, TIMER_ABSTIME,
                     &TS_ZERO as *const Timespec as usize, 0)
        };
        if rc != 0 { twin_bad += 1; }
    });
    if twin_bad != 0 {
        fail(b"twins", twin_bad, -1);
        return;
    }
    report(abi, b"chan-call       ", t_chan, N_IORING_OPS, floor_ns);
    report(abi, b"sleep-until0    ", t_tmr, N_IORING_OPS, floor_ns);
    let chan_call_ns = ns_per_op(t_chan, N_IORING_OPS);
    let tmr_call_ns = ns_per_op(t_tmr, N_IORING_OPS);

    let ts0 = &TS_ZERO as *const Timespec as usize;
    let mut be = [0u32; 3];
    for &n in IORING_BATCHES.iter() {
        let iters = N_IORING_OPS / n as u64;
        for (k, prefix) in [&b"ioring-nop  x"[..], b"ioring-chan x", b"ioring-tmr  x"].iter().enumerate() {
            if k == 1 && n < 2 { continue; }
            let (mut bad, mut last) = (0u32, 0i64);
            let t = batch(iters, || {
                for i in 0..n {
                    let ok = match k {
                        0 => ring.push(IORING_OP_NOP, -1, 0, 0, 0, 0, i as u64),
                        1 if i % 2 == 0 => ring.push(IORING_OP_WRITE, wr, msg, 8, u64::MAX, 0, i as u64),
                        1 => ring.push(IORING_OP_READ, rd, inbox, 8, u64::MAX, 0, i as u64),
                        _ => ring.push(IORING_OP_TIMEOUT, -1, ts0, 1, 0, IORING_TIMEOUT_ABS, i as u64),
                    };
                    if !ok { bad += 1; }
                }
                let rc = ring.submit_and_wait(n);
                if rc != n as isize { bad += 1; last = rc as i64; }
                match k {
                    0 => drain(n, &|_| 0, &mut bad, &mut last),
                    1 => drain(n, &|_| 8, &mut bad, &mut last),
                    _ => drain(n, &|_| ETIME, &mut bad, &mut last),
                }
            });
            if bad != 0 {
                fail(prefix, bad, last);
                continue;
            }
            let (label, len) = label_n(prefix, n);
            report(abi, &label[..len], t, iters * n as u64, floor_ns);
            let per_op = ns_per_op(t, iters * n as u64);
            let twin = [floor_ns, chan_call_ns, tmr_call_ns][k];
            if be[k] == 0 && per_op <= twin { be[k] = n; }
        }
    }
    abi.write(b"[VSBENCH] ioring-batch break-even N (0 = never): nop=");
    put_u(abi, be[0] as u64);
    abi.write(b" chan=");
    put_u(abi, be[1] as u64);
    abi.write(b" tmr=");
    put_u(abi, be[2] as u64);
    abi.write(b"\n");

    unsafe {
        syscall1(SYS_CLOSE, rd as usize);
        syscall1(SYS_CLOSE, wr as usize);
    }
    ring.destroy();
}

/// `timer-periodic`'s sleep (wave 13): `clock_nanosleep(CLOCK_MONOTONIC,
/// TIMER_ABSTIME, deadline)`, restarted on `EINTR`.
pub fn sleep_until_abs_ns(deadline_ns: u64) {
    let ts = Timespec {
        tv_sec: (deadline_ns / 1_000_000_000) as i64,
        tv_nsec: (deadline_ns % 1_000_000_000) as i64,
    };
    loop {
        let rc = unsafe {
            syscall4(SYS_CLOCK_NANOSLEEP, CLOCK_MONOTONIC as usize, TIMER_ABSTIME,
                     &ts as *const Timespec as usize, 0)
        };
        if rc != -4 {
            return;
        }
    }
}
