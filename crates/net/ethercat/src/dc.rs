// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Distributed-clock arithmetic (ETG.1000.4 section 9.1).
//!
//! The master sends one BWR to [`reg::RX_TIME_P0`]: every slave latches, on
//! both ports, the local time at which the frame passed. Reading those
//! registers back gives each slave's receive times; from them come the two
//! values written to every slave: [`reg::SYS_TIME_OFFSET`] and
//! [`reg::SYS_TIME_DELAY`]. All times are nanoseconds. The 32-bit port times
//! wrap every 4.29 s, so only their differences mean anything and every
//! subtraction here is wrapping.
//!
//! [`reg`]: crate::reg

use crate::Error;

/// Value for [`crate::reg::SYS_TIME_OFFSET`] of one slave.
///
/// `target` is the system time the reference clock has at the instant it
/// latched (the reference's own offset is written the same way with `delay` 0;
/// pass its local latch time to keep its clock, or the master's wanted time to
/// steer it), `local_rx` the slave's own latch ([`crate::reg::RX_TIME_PU`]) and
/// `delay` its propagation delay from [`line_delays`].
///
/// The slave latched `delay` after the reference did, so at the reference's
/// latch instant its local time was `local_rx - delay`; the offset that makes
/// its system time equal `target` then is `target - local_rx + delay`, and from
/// that instant on both advance together: every slave reads the same system
/// time at the same true instant. The ESC's drift control (ARMW/FRMW with
/// [`crate::reg::SYS_TIME_DELAY`]) holds them there.
pub fn system_time_offset(target: u64, local_rx: u64, delay: u32) -> u64 {
    target.wrapping_sub(local_rx).wrapping_add(u64::from(delay))
}

/// The two receive times of one slave in a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortTimes {
    /// [`crate::reg::RX_TIME_P0`]: the frame arriving from the master side.
    pub p0: u32,
    /// [`crate::reg::RX_TIME_P1`]: the frame coming back from the next slave.
    /// Ignored for the last slave, which loops the frame itself.
    pub p1: u32,
}

/// Propagation delay from the first slave (the reference clock) to every slave
/// of a line, written to `out[i]` for slave `i`.
///
/// In a line each slave but the last sees the frame twice: forward on port 0 and
/// returning on port 1. The gap `p1 - p0` is the round trip through everything
/// behind it, so the hop to the next slave is half the difference of two
/// neighbours' gaps and the delay accumulates hop by hop. The ESC's own
/// forwarding time is inside every gap and cancels when they are subtracted.
/// Branching topologies need the port map and are out of scope.
///
/// `out` must be as long as `times`; a negative hop (timestamps that cannot come
/// from a line) is [`Error::BadTimestamps`].
pub fn line_delays(times: &[PortTimes], out: &mut [u32]) -> Result<(), Error> {
    if out.len() != times.len() {
        return Err(Error::BufferTooSmall);
    }
    let n = times.len();
    let gap = |i: usize| if i + 1 < n { times[i].p1.wrapping_sub(times[i].p0) } else { 0 };
    let mut delay = 0u32;
    for (i, slot) in out.iter_mut().enumerate() {
        if i > 0 {
            let diff = gap(i - 1).wrapping_sub(gap(i));
            if diff >= 1 << 31 {
                return Err(Error::BadTimestamps);
            }
            delay = delay.wrapping_add(diff / 2);
        }
        *slot = delay;
    }
    Ok(())
}
