// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Clocks and sleeping: the vDSO's clocks (no trap) and `SYS_SLEEP_UNTIL`.
//!
//! The vDSO serves the boot-relative monotonic clock and three that are that
//! clock plus an offset the kernel publishes (`azos_abi::time::ClockId`:
//! `REAL`, `TAI`, `BOOT`; `azos_libsys::clock_now`). A POSIX clock id picks
//! one with `ClockId::from_posix`, the table the Linux personality reads too.
//! Until a time source has set the wall clock, `CLOCK_REALTIME` and
//! `CLOCK_TAI` read as time since boot.

use azos_abi::time::{ClockId, NS_PER_SEC};

use super::{errno_of, nosys};
use crate::{
    error::{Errno, Result},
    header::{
        errno::EINVAL,
        sys_select::timeval,
        sys_time::timezone,
        time::{
            timespec, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
        },
    },
    out::Out,
    platform::types::clockid_t,
};

/// Now on the monotonic clock, nanoseconds.
pub(crate) fn now_ns() -> u64 {
    azos_libsys::vdso_now_ns()
}

fn split(ns: u64) -> timespec {
    timespec { tv_sec: (ns / NS_PER_SEC) as _, tv_nsec: (ns % NS_PER_SEC) as _ }
}

/// The served native clock a POSIX id names; `None` for any other id (the
/// CPU-time clocks, which the caller answers `ENOSYS`, and unknown ones).
fn native_clock(clk_id: clockid_t) -> Option<ClockId> {
    u64::try_from(clk_id).ok().and_then(ClockId::from_posix)
}

pub(crate) fn clock_gettime(clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
    if let Some(clock) = native_clock(clk_id) {
        return match azos_libsys::clock_now(clock) {
            Ok(ns) => {
                tp.write(split(ns));
                Ok(())
            }
            Err(_) => Err(Errno(EINVAL)),
        };
    }
    match clk_id {
        // Per-process and per-thread CPU time is not published to ring 3.
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => nosys(),
        _ => Err(Errno(EINVAL)),
    }
}

pub(crate) fn clock_getres(clk_id: clockid_t, res: Option<Out<timespec>>) -> Result<()> {
    if native_clock(clk_id).is_some() {
        // Nanoseconds are the unit of the ABI; the counter ticks at its own
        // rate (azos_libsys::vdso_timebase_hz), which is the real resolution.
        if let Some(mut r) = res {
            let hz = azos_libsys::vdso_timebase_hz().max(1);
            r.write(split(NS_PER_SEC.div_ceil(hz)));
        }
        return Ok(());
    }
    match clk_id {
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => nosys(),
        _ => Err(Errno(EINVAL)),
    }
}

pub(crate) fn gettimeofday(mut tp: Out<timeval>, tzp: Option<Out<timezone>>) -> Result<()> {
    let ns = azos_libsys::clock_now(ClockId::REAL).map_err(|_| Errno(EINVAL))?;
    tp.write(timeval { tv_sec: (ns / NS_PER_SEC) as _, tv_usec: ((ns % NS_PER_SEC) / 1000) as _ });
    if let Some(mut tz) = tzp {
        tz.write(timezone { tz_minuteswest: 0, tz_dsttime: 0 });
    }
    Ok(())
}

pub(crate) unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()> {
    let rq = unsafe { rqtp.as_ref() }.ok_or(Errno(EINVAL))?;
    if rq.tv_sec < 0 || !(0..NS_PER_SEC as i64).contains(&(rq.tv_nsec as i64)) {
        return Err(Errno(EINVAL));
    }
    let ns = (rq.tv_sec as u64).saturating_mul(NS_PER_SEC).saturating_add(rq.tv_nsec as u64);
    if ns > 0 {
        match azos_libsys::sleep_until_ns(now_ns().saturating_add(ns)) {
            azos_libsys::SleepResult::Refused(rc) => return Err(errno_of(rc)),
            // Slept, or the deadline was already behind us: either way it is over.
            _ => {}
        }
    }
    if let Some(rm) = unsafe { rmtp.as_mut() } {
        *rm = timespec { tv_sec: 0, tv_nsec: 0 };
    }
    Ok(())
}
