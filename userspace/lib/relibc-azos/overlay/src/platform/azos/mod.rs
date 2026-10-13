// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The AzOS platform layer of relibc: `Sys`, the implementation of [`Pal`] over
//! the native ABI (`azos_abi`, `azos_libsys`).
//!
//! relibc is the *porting* layer: POSIX is a personality here, never the native
//! model. Everything below is a translation of a POSIX call into the ops the
//! native ABI has (34 calls and `invoke(handle, op, ..)`), or an honest refusal
//! where the native model has no such object:
//!
//! | POSIX | native |
//! |---|---|
//! | `open`, `read`, `write`, `close`, `stat`, `mkdir`, `unlink`, `rename`, directory reads | the domain's file ops and the node ops of the handle (`fs.rs`), under a per-process fd table that maps small integers to handles (`fdtab.rs`) |
//! | `pipe` | `DOMAIN_CREATE_PIPE` |
//! | `posix_spawn` | `SYS_SPAWN_EX` with the file actions as its move list (`proc.rs`) |
//! | `waitpid` | `DOMAIN_WAIT`, polled |
//! | threads, futexes | `SYS_THREAD_CREATE`, `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE` (`proc.rs`) |
//! | `mmap` (anonymous), `munmap` | `SYS_MO_MAP`, `SYS_MO_UNMAP` (`mem.rs`) |
//! | clocks, `nanosleep` | the vDSO clock and `SYS_SLEEP_UNTIL` (`time.rs`) |
//! | process entry, TLS | `start.rs` |
//!
//! Not native, so refused with `ENOSYS`: `fork` and `exec*` (a program is
//! created by `posix_spawn` only), signals and job control (the native model has
//! `SYS_ALERT` and death notices), sockets, `epoll`, `ptrace`, links, modes and
//! owners. `absent.rs` holds those impls of the `Pal*` traits.
//!
//! Errors: the native calls return `-errno` (the numbers are Linux's below 200,
//! `azos_abi::error`); `errno_of` maps the AzOS-specific ones (capability and
//! topology errors) to the nearest POSIX code.

use core::num::NonZeroU64;

use super::{types::*, Pal};
use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        errno::*,
        sys_resource::{rlimit, rusage},
        sys_select::timeval,
        sys_ioctl::TCGETS,
        sys_stat::stat,
        sys_statvfs::statvfs,
        sys_time::timezone,
        sys_uio::iovec,
        sys_utsname::utsname,
        signal::sigevent,
        termios::{termios, CS8},
        time::{itimerspec, timespec},
    },
    iter::NulTerminated,
    ld_so::tcb::OsSpecific,
    out::Out,
    pthread,
};

mod absent;
mod fdtab;
mod fs;
mod mem;
mod proc;
mod pure;
pub(crate) mod start;
mod time;

pub use self::start::thread_pointer;

/// The AzOS native-ABI implementation of [`Pal`].
pub struct Sys;

/// `-errno` returned by a native call, as the POSIX error it stands for.
pub(crate) fn errno_of(ret: isize) -> Errno {
    let n = ret.unsigned_abs();
    Errno(match n {
        1..=125 => n as c_int,
        // Capability and topology errors: the handle is not a usable fd, or
        // the image's row does not grant the operation.
        200 | 202 => EBADF,
        201 | 203 | 205 => EACCES,
        204 | 206..=208 => EPERM,
        209 => EDQUOT,
        210 => ENOEXEC,
        211..=213 => EPIPE,
        214 => ENOTCONN,
        216 => ETIMEDOUT,
        _ => EIO,
    })
}

/// A native result as a POSIX one: `< 0` is `-errno`.
pub(crate) fn check(ret: isize) -> Result<usize> {
    if ret < 0 { Err(errno_of(ret)) } else { Ok(ret as usize) }
}

/// The refusal for what the native model does not have.
pub(crate) const fn nosys<T>() -> Result<T> {
    Err(Errno(ENOSYS))
}

impl Sys {
    /// The console is the one terminal, and its line discipline is the kernel's:
    /// it can be asked what it is (`TCGETS`, which is how `isatty` and the stdio
    /// buffering mode learn it) and nothing can be set. Every other request, and
    /// every other descriptor, is "not a typewriter".
    pub unsafe fn ioctl(fd: c_int, request: c_ulong, out: *mut c_void) -> Result<c_int> {
        let f = fdtab::get(fd)?;
        if f.kind == fdtab::Kind::Console && request == TCGETS && !out.is_null() {
            // SAFETY: the caller passes a `termios` for this request, as ioctl(2) says.
            unsafe { out.cast::<termios>().write(termios { c_cflag: CS8 as _, ..termios::default() }) };
            return Ok(0);
        }
        Err(Errno(ENOTTY))
    }
}

impl Pal for Sys {
    fn faccessat(fd: c_int, path: CStr, amode: c_int, _flags: c_int) -> Result<()> {
        fs::access(fd, path, amode)
    }

    unsafe fn brk(addr: *mut c_void) -> Result<*mut c_void> {
        mem::brk(addr)
    }

    fn chdir(path: CStr) -> Result<()> {
        fs::chdir(path)
    }

    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        // The native model has capabilities, not mode bits.
        nosys()
    }

    fn fchownat(_fd: c_int, _path: CStr, _owner: uid_t, _group: gid_t, _flags: c_int) -> Result<()> {
        nosys()
    }

    fn clock_getres(clk_id: clockid_t, res: Option<Out<timespec>>) -> Result<()> {
        time::clock_getres(clk_id, res)
    }

    fn clock_gettime(clk_id: clockid_t, tp: Out<timespec>) -> Result<()> {
        time::clock_gettime(clk_id, tp)
    }

    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        // Setting the wall clock is an effect the native ABI gates (RFC time
        // chapter); no program of this layer holds that authority.
        Err(Errno(EPERM))
    }

    fn close(fildes: c_int) -> Result<()> {
        fdtab::close(fildes)
    }

    fn dup(fildes: c_int) -> Result<c_int> {
        fdtab::dup(fildes, 0, false)
    }

    fn dup2(fildes: c_int, fildes2: c_int) -> Result<c_int> {
        fdtab::dup2(fildes, fildes2)
    }

    unsafe fn execve(_path: CStr, _argv: *const *mut c_char, _envp: *const *mut c_char) -> Result<()> {
        // A native program is created by spawn, never by replacing an image.
        nosys()
    }

    unsafe fn fexecve(_fildes: c_int, _argv: *const *mut c_char, _envp: *const *mut c_char) -> Result<()> {
        nosys()
    }

    fn exit(status: c_int) -> ! {
        azos_libsys::exit(status)
    }

    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        // The thread's own stack cannot be unmapped from itself; the stack and
        // the TCB are leaked, as on the Linux platform of relibc.
        azos_libsys::thread_exit(0)
    }

    fn fchdir(fildes: c_int) -> Result<()> {
        fs::fchdir(fildes)
    }

    fn fdatasync(fildes: c_int) -> Result<()> {
        fs::fsync(fildes)
    }

    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        nosys()
    }

    fn fstatat(fildes: c_int, path: Option<CStr>, buf: Out<stat>, flags: c_int) -> Result<()> {
        fs::fstatat(fildes, path, buf, flags)
    }

    fn fstatvfs(fildes: c_int, buf: Out<statvfs>) -> Result<()> {
        fs::fstatvfs(fildes, buf)
    }

    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        fdtab::fcntl(fildes, cmd, arg)
    }

    unsafe fn fork() -> Result<pid_t> {
        // Native programs have no fork (D6): posix_spawn is the creation call.
        nosys()
    }

    fn fpath(fildes: c_int, out: &mut [u8]) -> Result<usize> {
        fs::fpath(fildes, out)
    }

    fn fsync(fildes: c_int) -> Result<()> {
        fs::fsync(fildes)
    }

    fn ftruncate(fildes: c_int, length: off_t) -> Result<()> {
        fs::ftruncate(fildes, length)
    }

    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
        unsafe { proc::futex_wait(addr, val, deadline) }
    }

    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
        unsafe { proc::futex_wake(addr, num) }
    }

    unsafe fn utimensat(_dirfd: c_int, _path: CStr, _times: *const timespec, _flag: c_int) -> Result<()> {
        nosys()
    }

    fn getcwd(buf: Out<[u8]>) -> Result<()> {
        fs::getcwd(buf)
    }

    fn getdents(fd: c_int, buf: &mut [u8], opaque_offset: u64) -> Result<usize> {
        fs::getdents(fd, buf, opaque_offset)
    }

    fn dir_seek(fd: c_int, opaque_offset: u64) -> Result<()> {
        fs::dir_seek(fd, opaque_offset)
    }

    unsafe fn dent_reclen_offset(this_dent: &[u8], _offset: usize) -> Option<(u16, u64)> {
        fs::dent_reclen_offset(this_dent)
    }

    // The image has one identity: no user database, no set-id (the native model
    // delegates authority with capabilities; identity chapter D10).
    fn getegid() -> gid_t {
        0
    }

    fn geteuid() -> uid_t {
        0
    }

    fn getgid() -> gid_t {
        0
    }

    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> {
        Ok(0)
    }

    fn getpagesize() -> usize {
        azos_libsys::PAGE_SIZE
    }

    fn getpgid(pid: pid_t) -> Result<pid_t> {
        // No process groups: every task is its own group.
        Ok(if pid == 0 { Self::getpid() } else { pid })
    }

    fn getpid() -> pid_t {
        azos_libsys::getpid() as pid_t
    }

    fn getppid() -> pid_t {
        // The kernel keeps no parent link a task can read.
        0
    }

    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> {
        nosys()
    }

    fn getrandom(_buf: &mut [u8], _flags: c_uint) -> Result<usize> {
        // Entropy is a service behind an interface (azos_devif::entropy), not a call.
        nosys()
    }

    fn getresgid(
        rgid: Option<Out<gid_t>>,
        egid: Option<Out<gid_t>>,
        sgid: Option<Out<gid_t>>,
    ) -> Result<()> {
        for o in [rgid, egid, sgid].into_iter().flatten() {
            let mut o = o;
            o.write(0);
        }
        Ok(())
    }

    fn getresuid(
        ruid: Option<Out<uid_t>>,
        euid: Option<Out<uid_t>>,
        suid: Option<Out<uid_t>>,
    ) -> Result<()> {
        for o in [ruid, euid, suid].into_iter().flatten() {
            let mut o = o;
            o.write(0);
        }
        Ok(())
    }

    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> {
        nosys()
    }

    unsafe fn setrlimit(_resource: c_int, _rlimit: *const rlimit) -> Result<()> {
        nosys()
    }

    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> {
        nosys()
    }

    fn getsid(pid: pid_t) -> Result<pid_t> {
        Ok(if pid == 0 { Self::getpid() } else { pid })
    }

    fn gettid() -> pid_t {
        Self::getpid()
    }

    fn gettimeofday(tp: Out<timeval>, tzp: Option<Out<timezone>>) -> Result<()> {
        time::gettimeofday(tp, tzp)
    }

    fn getuid() -> uid_t {
        0
    }

    fn linkat(_fd1: c_int, _oldpath: CStr, _fd2: c_int, _newpath: CStr, _flags: c_int) -> Result<()> {
        nosys()
    }

    fn lseek(fildes: c_int, offset: off_t, whence: c_int) -> Result<off_t> {
        fs::lseek(fildes, offset, whence)
    }

    fn mkdirat(fildes: c_int, path: CStr, _mode: mode_t) -> Result<()> {
        fs::mkdirat(fildes, path)
    }

    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        nosys()
    }

    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        nosys()
    }

    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> {
        // Nothing is ever paged out of a native image.
        Ok(())
    }

    unsafe fn mlockall(_flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fildes: c_int,
        off: off_t,
    ) -> Result<*mut c_void> {
        unsafe { mem::mmap(addr, len, prot, flags, fildes, off) }
    }

    unsafe fn mremap(
        _addr: *mut c_void,
        _len: usize,
        _new_len: usize,
        _flags: c_int,
        _args: *mut c_void,
    ) -> Result<*mut c_void> {
        nosys()
    }

    unsafe fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> Result<()> {
        unsafe { mem::mprotect(addr, len, prot) }
    }

    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        // Only anonymous memory can be mapped: nothing to write back.
        Ok(())
    }

    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn munlockall() -> Result<()> {
        Ok(())
    }

    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        unsafe { mem::munmap(addr, len) }
    }

    unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()> {
        unsafe { time::nanosleep(rqtp, rmtp) }
    }

    fn openat(dirfd: c_int, path: CStr, oflag: c_int, mode: mode_t) -> Result<c_int> {
        fs::openat(dirfd, path, oflag, mode)
    }

    fn pipe2(fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()> {
        fdtab::pipe2(fildes, flags)
    }

    fn posix_fallocate(_fd: c_int, _offset: u64, _length: NonZeroU64) -> Result<()> {
        nosys()
    }

    fn posix_getdents(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        fs::posix_getdents(fildes, buf)
    }

    unsafe fn rlct_clone(stack: *mut usize, _os_specific: &mut OsSpecific) -> Result<pthread::OsTid> {
        unsafe { proc::rlct_clone(stack) }
    }

    unsafe fn rlct_kill(_os_tid: pthread::OsTid, _signal: usize) -> Result<()> {
        // Cancellation by signal: a native thread is stopped with SYS_ALERT.
        nosys()
    }

    fn current_os_tid() -> pthread::OsTid {
        // SAFETY: only the pointer is taken, not a reference that outlives this call.
        proc::os_tid_of(unsafe { crate::ld_so::tcb::Tcb::current() }.map_or(0, |t| core::ptr::from_mut(t) as usize))
    }

    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        fs::read(fildes, buf)
    }

    fn pread(_fildes: c_int, _buf: &mut [u8], _offset: off_t) -> Result<usize> {
        // The node ops have no offset: a positioned read needs the file
        // interface the FS front defines.
        Err(Errno(ESPIPE))
    }

    unsafe fn readv(fildes: c_int, iov: *const iovec, iovcnt: c_int) -> Result<usize> {
        unsafe { fs::readv(fildes, iov, iovcnt) }
    }

    fn readlinkat(_dirfd: c_int, _pathname: CStr, _out: &mut [u8]) -> Result<usize> {
        // No symbolic links on the native volumes.
        Err(Errno(EINVAL))
    }

    fn renameat2(
        old_dir: c_int,
        old_path: CStr,
        new_dir: c_int,
        new_path: CStr,
        flags: c_uint,
    ) -> Result<()> {
        if flags != 0 {
            return Err(Errno(EINVAL));
        }
        fs::renameat(old_dir, old_path, new_dir, new_path)
    }

    fn sched_yield() -> Result<()> {
        azos_libsys::yield_now();
        Ok(())
    }

    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        nosys()
    }

    fn setpgid(_pid: pid_t, _pgid: pid_t) -> Result<()> {
        nosys()
    }

    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> {
        nosys()
    }

    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> {
        nosys()
    }

    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> {
        nosys()
    }

    fn setsid() -> Result<c_int> {
        nosys()
    }

    unsafe fn spawn(
        program: CStr,
        fac: Option<&crate::header::spawn::posix_spawn_file_actions_t>,
        fat: Option<&crate::header::spawn::posix_spawnattr_t>,
        argv: NulTerminated<*mut c_char>,
        envp: Option<NulTerminated<*mut c_char>>,
    ) -> Result<pid_t> {
        unsafe { proc::spawn(program, fac, fat, argv, envp) }
    }

    fn symlinkat(_path1: CStr, _fd: c_int, _path2: CStr) -> Result<()> {
        nosys()
    }

    fn sync() -> Result<()> {
        nosys()
    }

    fn timer_create(_clock_id: clockid_t, _evp: &sigevent) -> Result<timer_t> {
        nosys()
    }

    fn timer_delete(_timerid: timer_t) -> Result<()> {
        nosys()
    }

    fn timer_gettime(_timerid: timer_t) -> Result<itimerspec> {
        nosys()
    }

    fn timer_settime(
        _timerid: timer_t,
        _flags: c_int,
        _value: &itimerspec,
        _ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        nosys()
    }

    fn umask(mask: mode_t) -> mode_t {
        fs::umask(mask)
    }

    fn uname(utsname: Out<utsname>) -> Result<()> {
        fs::uname(utsname)
    }

    fn unlinkat(fd: c_int, path: CStr, flags: c_int) -> Result<()> {
        fs::unlinkat(fd, path, flags)
    }

    fn waitpid(pid: pid_t, stat_loc: Option<Out<c_int>>, options: c_int) -> Result<pid_t> {
        proc::waitpid(pid, stat_loc, options)
    }

    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        fs::write(fildes, buf)
    }

    fn pwrite(_fildes: c_int, _buf: &[u8], _offset: off_t) -> Result<usize> {
        Err(Errno(ESPIPE))
    }

    unsafe fn writev(fildes: c_int, iov: *const iovec, iovcnt: c_int) -> Result<usize> {
        unsafe { fs::writev(fildes, iov, iovcnt) }
    }

    fn verify() -> bool {
        // A binary of this platform runs on this kernel when the vDSO's ABI
        // version is the one it was built against (azos_abi::ABI_VERSION).
        azos_libsys::abi_matches()
    }
}
