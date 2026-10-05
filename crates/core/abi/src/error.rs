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
    /// caps, RFC-0003), but the code is a standard POSIX errno kept for the
    /// next syscall that needs "no such task" — it is not retired with it.
    ESRCH = 3,
    /// Interrupted wait (RFC-0055, wave 11). A blocking call
    /// (`SYS_CONSOLE_WAIT`, a pipe read or write) was ended by a stop request
    /// from an ancestor (`SYS_TASK_KILL`), or `SYS_CONSOLE_WAIT` has a child's
    /// exit notice pending for the caller. POSIX value 4.
    EINTR = 4,
    /// I/O error.
    EIO = 5,
    /// Bad file descriptor / handle.
    EBADF = 9,
    /// Resource temporarily unavailable.
    /// No child process to wait for. Added 2026-09-07 for [`SYS_WAITPID`]
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
    /// Broken pipe (RFC-0055, wave 11): a write to a `Cap<Pipe>` whose read
    /// ends are all closed. There is no `SIGPIPE`; the writer sees this.
    /// POSIX value 32.
    EPIPE = 32,
    /// Function not implemented.
    ENOSYS = 38,
    /// File name too long for the filesystem (Linux's value).
    ENAMETOOLONG = 36,
    /// Directory not empty (`SYS_RMDIR`; Linux's value).
    ENOTEMPTY = 39,
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
