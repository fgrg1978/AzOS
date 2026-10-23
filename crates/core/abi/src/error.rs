// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Frozen error codes returned across the syscall boundary.
//!
//! Negative `i64` values mapped to `Errno::*` by user-space `libsys`. The
//! number values are stable forever within a major series.
//!
//! POSIX-equivalent codes use the same numeric value as Linux where it
//! makes sense; AZOS-specific codes start at 200.

use core::fmt;

/// AZOS error number. Returned as `-(errno as i64)` from a failing
/// syscall.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i64)]
#[non_exhaustive]
pub enum Errno {
    // ── POSIX-aligned (1..=99) ────────────────────────────────────────────
    /// Operation not permitted.
    EPERM = 1,
    /// No such file or directory.
    ENOENT = 2,
    /// No such process/task. Added for `SYS_CAP_GRANT` (user decision
    /// 2026-08-23): "no live task by that TID" and "no such resource" are
    /// different fixes for the caller, so they get different numbers. POSIX
    /// value 3. `SYS_CAP_GRANT` itself was removed 2026-09-03 (boot-only
    /// caps), but the code is a standard POSIX errno kept for the
    /// next syscall that needs "no such task" — it is not retired with it.
    ESRCH = 3,
    /// Interrupted wait. A blocking call
    /// (`LOG_CONSOLE_WAIT`, a pipe read or write) was ended by a stop request
    /// from an ancestor (`SYS_ALERT`), or `LOG_CONSOLE_WAIT` has a child's
    /// exit notice pending for the caller. POSIX value 4.
    EINTR = 4,
    /// I/O error.
    EIO = 5,
    /// Bad file descriptor / handle.
    EBADF = 9,
    /// Resource temporarily unavailable.
    /// No child process to wait for. Added 2026-09-07 for [`DOMAIN_WAIT`](crate::invoke::DOMAIN_WAIT)
    /// (`crates/core/abi/src/syscall_nr.rs`), which needs to say "that TID is not
    /// a child of yours, or you already reaped it" distinctly from "-1, not
    /// finished yet" — the first never becomes true however long the caller
    /// polls, and collapsing them makes a poll spin to its own bound.
    ///
    /// POSIX number, and 10 was free. NOT `ESRCH`: that is "no live task by
    /// that TID", which is a different fact — a child of another parent is
    /// alive and still not yours.
    ECHILD = 10,
    /// Resource temporarily unavailable.
    EAGAIN = 11,
    /// Out of memory.
    ENOMEM = 12,
    /// Permission denied.
    EACCES = 13,
    /// Bad address.
    EFAULT = 14,
    /// Device or resource busy.
    EBUSY = 16,
    /// File exists.
    EEXIST = 17,
    /// No such device.
    ENODEV = 19,
    /// Not a directory.
    ENOTDIR = 20,
    /// Is a directory.
    EISDIR = 21,
    /// Invalid argument.
    EINVAL = 22,
    /// Too many open files (handle table full).
    EMFILE = 24,
    /// No space left on device.
    ENOSPC = 28,
    /// Read-only filesystem.
    EROFS = 30,
    /// Broken pipe: a write to a pipe whose read
    /// ends are all closed. A native writer sees this; the Linux personality
    /// also raises `SIGPIPE`.
    /// POSIX value 32.
    EPIPE = 32,
    /// Function not implemented.
    ENOSYS = 38,
    /// File name too long for the filesystem (Linux's value).
    ENAMETOOLONG = 36,
    /// Directory not empty (`DOMAIN_RMDIR`; Linux's value).
    ENOTEMPTY = 39,
    /// A wait ran out (Linux's value): the futex wait, and the code of a
    /// `PORT_EVENT_CALL_NOTICE` whose caller's lent budget ran out.
    ETIMEDOUT = 110,
    /// Operation canceled (Linux's value): an io_ring entry linked
    /// (`SQE_F_LINK`) to one that failed or did not complete in its pass,
    /// and the code of a `PORT_EVENT_CALL_NOTICE` whose caller withdrew.
    ECANCELED = 125,
    /// Not the object's owner, or not otherwise authorized for this call —
    /// `-99`, the value `crates/core/syscall`'s handlers have returned as their
    /// own `E_PERM` since before this table existed (`handlers.rs::E_PERM`,
    /// 30 call sites: driver-ownership checks, `socket_access_ok`, and
    /// similar TID-authority gates that are not a capability-table lookup,
    /// so `ECAPPERMS` would misdescribe them).
    ///
    /// U07-6 (audit unit-07): folded in here so
    /// `Errno::from_syscall_ret(-99)` resolves instead of `None`, closing
    /// the gap between this table's claim to be the single source of truth
    /// for error codes (`abi/src/lib.rs`'s module doc) and the fact that it
    /// did not, until now, include a value `crates/core/syscall` has returned
    /// all along. Additive only: no call site's return value changes, this
    /// only makes an existing one nameable. It is numerically distinct
    /// from `EPERM.to_syscall_ret()` (`-1`) by construction — that
    /// distinction is `handlers.rs::E_PERM`'s whole reason to exist,
    /// separate from `dispatch.rs`'s own, differently-valued `E_PERM`
    /// (`-1`, the generic failure range, and — before V1.8 — the seccomp
    /// filter's denial too).
    ENOTOWNER = 99,

    // ── AZOS-specific (200..=299) ──────────────────────────────────────
    /// Capability handle has wrong kind.
    ECAPKIND = 200,
    /// Capability missing required permission.
    ECAPPERMS = 201,
    /// Capability generation stale (handle was revoked / freed).
    ECAPSTALE = 202,
    /// Topology violation: action not allowed by signed CAPS.TOML.
    ETOPOLOGY = 203,
    /// Safety policy violation (geofence, max-speed, ESTOP).
    ESAFETY = 204,
    /// Authentication failure on brain link (HMAC mismatch).
    EAUTH = 205,
    /// Replay detected on brain link (counter regressed).
    EREPLAY = 206,
    /// OTA signature verification failed.
    EOTASIG = 207,
    /// Anti-rollback counter would regress.
    EROLLBACK = 208,
    /// Resource quota exceeded.
    EQUOTA = 209,
    /// ABI version mismatch.
    EABIVERSION = 210,
    /// A fast call completed without an answer because the task serving its
    /// endpoint died while the call was queued or in service (wave 15 N5).
    EPEERDIED = 211,
    /// A fast call completed without an answer because its endpoint was
    /// destroyed while the call was queued or in service (wave 15 N5).
    EREVOKED = 212,
    /// Reserved: an endpoint with no sender capability left (Mach's
    /// no-senders notice). Not returned yet.
    ENOSENDERS = 213,
    /// A v2 call (`SYS_IPC_CALL_V2`) refused because its server took it with
    /// the v1 accept (110, or the accept half of 580), which can name only
    /// four words and one capability (wave 15 N11c). The server never saw
    /// the call, and every capability it carried went back to the caller.
    /// Linux has no equivalent (its IPC has no message version).
    EV1ACCEPT = 215,
    /// A v2 call's deadline (`MsgDesc::deadline`) had already passed when the
    /// kernel read it: the call was refused before it was queued, nothing
    /// moved. Linux has no equivalent (`ETIMEDOUT` is a wait that ran out;
    /// this one never started).
    EDEADLINE = 216,
    /// A real-time task called a proxy endpoint (the local face of a service
    /// on another node): the call is refused before it is queued. A call over
    /// a link takes as long as the link does, which a reservation cannot
    /// promise. Linux has no equivalent.
    ERTPROXY = 217,
    /// The connection of a stream socket has ended and nothing is left to read:
    /// `NODE_RECV` and `NODE_RECVFROM` answer it for a TCP socket where they
    /// answer a bare `-1` for every other refusal (a buffer the caller does
    /// not own, a socket that is not connected, an unbound datagram socket).
    /// It is the end of the stream, not a failure: a reader that gets it reports
    /// a clean end of file. The stack does not record whether the peer closed
    /// or reset, so both read as this.
    EEOF = 218,
    /// A memory object created volatile (`SHM_ATTR_VOLATILE`) lost its frames
    /// to memory pressure and has nothing left to map or copy: `SYS_MO_MAP`
    /// and a clone answer it. The contents are gone for good (nothing was
    /// written anywhere); the owner makes a new object. Linux has no
    /// equivalent (`MADV_FREE` pages read back as zeros).
    EPURGED = 219,
    /// A v2 call's server could not admit the call's remaining deadline
    /// against its scheduling context (its reservation's relative deadline is
    /// longer than the time left, or its per-call budget does not fit the
    /// time or the budget the caller lends): the call was refused before it
    /// was queued, nothing moved, and the kernel wrote the counter-offer (the
    /// refusal's receipt and the nearest admissible deadline or budget) into
    /// the caller's descriptor. Linux has no equivalent (`sched_setattr`
    /// answers `EBUSY` with no alternative).
    EADMIT = 220,
}

impl Errno {
    /// Returns the negative `i64` syscall return value for this error.
    #[inline]
    pub const fn to_syscall_ret(self) -> i64 {
        -(self as i64)
    }

    /// Tries to interpret a syscall return value as an `Errno`. Positive
    /// values and `0` are not errors and return `None`.
    #[inline]
    pub const fn from_syscall_ret(ret: i64) -> Option<Self> {
        if ret >= 0 {
            return None;
        }
        let raw = -ret;
        // Only return `Some` for values that map; otherwise fall through to
        // a safe default (caller treats unknown errno as `EIO`).
        match raw {
            1 => Some(Errno::EPERM),
            2 => Some(Errno::ENOENT),
            3 => Some(Errno::ESRCH),
            4 => Some(Errno::EINTR),
            10 => Some(Errno::ECHILD),
            5 => Some(Errno::EIO),
            9 => Some(Errno::EBADF),
            11 => Some(Errno::EAGAIN),
            12 => Some(Errno::ENOMEM),
            13 => Some(Errno::EACCES),
            14 => Some(Errno::EFAULT),
            16 => Some(Errno::EBUSY),
            17 => Some(Errno::EEXIST),
            19 => Some(Errno::ENODEV),
            20 => Some(Errno::ENOTDIR),
            21 => Some(Errno::EISDIR),
            22 => Some(Errno::EINVAL),
            24 => Some(Errno::EMFILE),
            28 => Some(Errno::ENOSPC),
            30 => Some(Errno::EROFS),
            32 => Some(Errno::EPIPE),
            36 => Some(Errno::ENAMETOOLONG),
            38 => Some(Errno::ENOSYS),
            39 => Some(Errno::ENOTEMPTY),
            110 => Some(Errno::ETIMEDOUT),
            125 => Some(Errno::ECANCELED),
            99 => Some(Errno::ENOTOWNER),
            200 => Some(Errno::ECAPKIND),
            201 => Some(Errno::ECAPPERMS),
            202 => Some(Errno::ECAPSTALE),
            203 => Some(Errno::ETOPOLOGY),
            204 => Some(Errno::ESAFETY),
            205 => Some(Errno::EAUTH),
            206 => Some(Errno::EREPLAY),
            207 => Some(Errno::EOTASIG),
            208 => Some(Errno::EROLLBACK),
            209 => Some(Errno::EQUOTA),
            210 => Some(Errno::EABIVERSION),
            211 => Some(Errno::EPEERDIED),
            212 => Some(Errno::EREVOKED),
            213 => Some(Errno::ENOSENDERS),
            215 => Some(Errno::EV1ACCEPT),
            216 => Some(Errno::EDEADLINE),
            217 => Some(Errno::ERTPROXY),
            218 => Some(Errno::EEOF),
            219 => Some(Errno::EPURGED),
            220 => Some(Errno::EADMIT),
            _ => None,
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Errno::EPERM => "operation not permitted",
            Errno::ENOENT => "no such file or directory",
            Errno::ESRCH => "no such task",
            Errno::EINTR => "interrupted",
            Errno::ECHILD => "no such child of this task",
            Errno::EIO => "I/O error",
            Errno::EBADF => "bad file descriptor",
            Errno::EAGAIN => "resource temporarily unavailable",
            Errno::ENOMEM => "out of memory",
            Errno::EACCES => "permission denied",
            Errno::EFAULT => "bad address",
            Errno::EBUSY => "device or resource busy",
            Errno::EEXIST => "file exists",
            Errno::ENODEV => "no such device",
            Errno::ENOTDIR => "not a directory",
            Errno::EISDIR => "is a directory",
            Errno::EINVAL => "invalid argument",
            Errno::EMFILE => "too many open handles",
            Errno::ENOSPC => "no space left on device",
            Errno::EROFS => "read-only filesystem",
            Errno::EPIPE => "broken pipe",
            Errno::ENOSYS => "function not implemented",
            Errno::ENAMETOOLONG => "file name too long",
            Errno::ENOTEMPTY => "directory not empty",
            Errno::ETIMEDOUT => "timed out",
            Errno::ECANCELED => "operation canceled",
            Errno::ENOTOWNER => "not the object's owner, or not otherwise authorized",
            Errno::ECAPKIND => "capability has wrong kind",
            Errno::ECAPPERMS => "capability missing required permission",
            Errno::ECAPSTALE => "capability generation stale",
            Errno::ETOPOLOGY => "topology violation",
            Errno::ESAFETY => "safety policy violation",
            Errno::EAUTH => "authentication failure",
            Errno::EREPLAY => "replay detected",
            Errno::EOTASIG => "OTA signature verification failed",
            Errno::EROLLBACK => "anti-rollback counter would regress",
            Errno::EQUOTA => "quota exceeded",
            Errno::EABIVERSION => "ABI version mismatch",
            Errno::EPEERDIED => "the serving task died during the call",
            Errno::EREVOKED => "the endpoint was destroyed during the call",
            Errno::ENOSENDERS => "no sender left on the endpoint",
            Errno::EV1ACCEPT => "v2 call refused by a v1 accept",
            Errno::EDEADLINE => "deadline already passed",
            Errno::ERTPROXY => "a real-time task may not call a remote endpoint",
            Errno::EEOF => "end of stream",
            Errno::EPURGED => "volatile memory object was purged",
            Errno::EADMIT => "the server cannot meet the call's deadline",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_known() {
        let cases = [
            Errno::EPERM,
            Errno::ENOENT,
            Errno::EIO,
            Errno::EBADF,
            Errno::ENOTOWNER,
            Errno::ECAPKIND,
            Errno::ECAPPERMS,
            Errno::ECAPSTALE,
            Errno::ETOPOLOGY,
            Errno::ESAFETY,
            Errno::EAUTH,
            Errno::EABIVERSION,
            Errno::EPEERDIED,
            Errno::EREVOKED,
            Errno::ENOSENDERS,
            Errno::EV1ACCEPT,
            Errno::EDEADLINE,
            Errno::ERTPROXY,
            Errno::EEOF,
            Errno::EPURGED,
            Errno::EADMIT,
            Errno::ETIMEDOUT,
        ];
        for e in cases {
            let ret = e.to_syscall_ret();
            assert!(ret < 0);
            assert_eq!(Errno::from_syscall_ret(ret), Some(e));
        }
    }

    #[test]
    fn non_negative_is_not_error() {
        assert_eq!(Errno::from_syscall_ret(0), None);
        assert_eq!(Errno::from_syscall_ret(42), None);
    }
}
