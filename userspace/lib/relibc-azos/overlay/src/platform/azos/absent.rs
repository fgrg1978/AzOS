// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The families of relibc's platform layer the native model has no object for:
//! signals (a native task is stopped by `SYS_ALERT`, which is all `kill` maps
//! to), sockets (they are warrants on a network interface, not yet served to
//! this layer), `epoll` (a Port is the native wait object) and `ptrace` (a
//! thread-control warrant). Each is answered with `ENOSYS` so a program sees
//! "this system has no such call" and not a wrong behaviour.

use super::{check, nosys, Sys};
#[allow(deprecated)]
use crate::header::sys_time::itimerval;
use crate::{
    error::{Errno, Result},
    header::{
        bits_sigset_t::sigset_t,
        errno::{ENOSYS, ESRCH},
        signal::{sigaction, siginfo_t, sigval, stack_t, SIGCHLD, SIGCONT, SIGKILL, SIGURG, SIGWINCH},
        sys_epoll::epoll_event,
        sys_socket::{msghdr, socklen_t},
        time::timespec,
    },
    out::Out,
    platform::{
        types::{c_int, c_void, pid_t},
        PalEpoll, PalPtrace, PalSignal, PalSocket,
    },
};

impl PalSignal for Sys {
    #[expect(deprecated)]
    fn getitimer(_which: c_int, _out: &mut itimerval) -> Result<()> {
        nosys()
    }

    /// A signal is a stop request to a descendant: `SYS_ALERT` asks it to stop
    /// (`KILL_REQUEST`, the signal number riding along) and `SIGKILL` forces
    /// it. The alert has no probe form, so signal 0 and process groups are
    /// refused.
    fn kill(pid: pid_t, sig: c_int) -> Result<()> {
        let how = match sig {
            s if s == SIGKILL as c_int => azos_libsys::KILL_FORCE,
            1..64 => azos_libsys::KILL_REQUEST,
            _ => return nosys(),
        };
        if pid <= 0 {
            return nosys();
        }
        match check(azos_libsys::task_kill(pid as u32, how, sig as u64, 0))? {
            0 => Err(Errno(ESRCH)),
            _ => Ok(()),
        }
    }

    fn sigqueue(_pid: pid_t, _sig: c_int, _val: sigval) -> Result<()> {
        nosys()
    }

    fn killpg(_pgrp: pid_t, _sig: c_int) -> Result<()> {
        nosys()
    }

    /// No handler can be installed (`sigaction` is refused), so every signal
    /// takes its default action: the ones that end a process end it here, with
    /// the status a shell shows (128 + the number); the ones that are ignored
    /// by default are ignored.
    fn raise(sig: c_int) -> Result<()> {
        const IGNORED: [usize; 4] = [SIGCHLD, SIGCONT, SIGURG, SIGWINCH];
        match sig {
            0 => Ok(()),
            s if IGNORED.contains(&(s as usize)) => Ok(()),
            1..64 => azos_libsys::exit(128 + sig),
            _ => Err(Errno(crate::header::errno::EINVAL)),
        }
    }

    #[expect(deprecated)]
    fn setitimer(_which: c_int, _new: &itimerval, _old: Option<&mut itimerval>) -> Result<()> {
        nosys()
    }

    fn sigaction(_sig: c_int, _act: Option<&sigaction>, _oact: Option<&mut sigaction>) -> Result<()> {
        nosys()
    }

    unsafe fn sigaltstack(_ss: Option<&stack_t>, _old_ss: Option<&mut stack_t>) -> Result<()> {
        nosys()
    }

    fn sigpending(set: &mut sigset_t) -> Result<()> {
        *set = 0;
        Ok(())
    }

    /// Nothing is delivered asynchronously, so there is nothing to mask: the
    /// mask reads as empty and a change is accepted.
    fn sigprocmask(_how: c_int, _set: Option<&sigset_t>, oset: Option<&mut sigset_t>) -> Result<()> {
        if let Some(o) = oset {
            *o = 0;
        }
        Ok(())
    }

    fn sigsuspend(_mask: &sigset_t) -> Errno {
        Errno(ENOSYS)
    }

    fn sigtimedwait(
        _set: &sigset_t,
        _sig: Option<&mut siginfo_t>,
        _tp: Option<&timespec>,
    ) -> Result<c_int> {
        nosys()
    }
}

impl PalSocket for Sys {
    fn accept(_socket: c_int, _address_dst: Option<&mut [u8]>) -> Result<(c_int, socklen_t)> {
        nosys()
    }

    fn bind(_socket: c_int, _address_raw: &[u8]) -> Result<()> {
        nosys()
    }

    fn connect(_socket: c_int, _address_raw: &[u8]) -> Result<c_int> {
        nosys()
    }

    fn getpeername(_socket: c_int, _address_dst: &mut [u8]) -> Result<socklen_t> {
        nosys()
    }

    fn getsockname(_socket: c_int, _address_dst: &mut [u8]) -> Result<socklen_t> {
        nosys()
    }

    fn getsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: &mut [u8],
    ) -> Result<socklen_t> {
        nosys()
    }

    fn listen(_socket: c_int, _backlog: c_int) -> Result<()> {
        nosys()
    }

    fn recvfrom(
        _socket: c_int,
        _buf: Out<[u8]>,
        _flags: c_int,
        _address_raw: Option<&mut [u8]>,
    ) -> Result<(usize, socklen_t)> {
        nosys()
    }

    unsafe fn recvmsg(_socket: c_int, _msg: *mut msghdr, _flags: c_int) -> Result<usize> {
        nosys()
    }

    unsafe fn sendmsg(_socket: c_int, _msg: *const msghdr, _flags: c_int) -> Result<usize> {
        nosys()
    }

    fn sendto(_socket: c_int, _buf: &[u8], _flags: c_int, _dest_addr: Option<&[u8]>) -> Result<usize> {
        nosys()
    }

    fn setsockopt(_socket: c_int, _level: c_int, _option_name: c_int, _option_value: &[u8]) -> Result<()> {
        nosys()
    }

    fn shutdown(_socket: c_int, _how: c_int) -> Result<()> {
        nosys()
    }

    fn socket(_domain: c_int, _kind: c_int, _protocol: c_int) -> Result<c_int> {
        nosys()
    }

    fn socketpair(_domain: c_int, _kind: c_int, _protocol: c_int, _sv: &mut [c_int; 2]) -> Result<()> {
        nosys()
    }
}

impl PalEpoll for Sys {
    fn epoll_create1(_flags: c_int) -> Result<c_int> {
        nosys()
    }

    unsafe fn epoll_ctl(_epfd: c_int, _op: c_int, _fd: c_int, _event: *mut epoll_event) -> Result<()> {
        nosys()
    }

    unsafe fn epoll_pwait(
        _epfd: c_int,
        _events: *mut epoll_event,
        _maxevents: c_int,
        _timeout: c_int,
        _sigmask: *const sigset_t,
    ) -> Result<usize> {
        nosys()
    }
}

impl PalPtrace for Sys {
    unsafe fn ptrace(_request: c_int, _pid: pid_t, _addr: *mut c_void, _data: *mut c_void) -> Result<c_int> {
        nosys()
    }
}
