// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The arithmetic of the next timer event, with no hardware in it.
//!
//! `timebase` owns the comparator writes; this module only answers two
//! questions, so the host suite (`tests/host/drivers-tests`, pulled in with
//! `#[path]`) can test them without a timer:
//!
//! * [`next_event`]: which instant to program after a tick or on the idle
//!   boundary (the earlier of the nearest timer sleeper and the cap the hart's
//!   state allows);
//! * [`earlier_than_programmed`]: whether a task blocking on a timer deadline
//!   needs the comparator moved (RFC-0052 §4.5: only when the deadline is
//!   earlier than what the hart already has programmed; otherwise no CSR,
//!   SBI or system-register write at all).
//!
//! Units are the counter's ticks (`timebase::now()`), never durations.

/// The per-hart record before the hart has programmed its comparator once.
/// A hart that never armed its timer is not reprogrammed from the block path:
/// its timer interrupt is not set up yet, and the first arm is the boot's.
pub const NOT_ARMED: u64 = 0;

/// What caps the next event when no sleeper is nearer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cap {
    /// A task is running: the scheduler period (`now + period`).
    Busy,
    /// Idle hart 0 while a hardware watchdog is armed: the keepalive
    /// (`now + keepalive`) whose timer interrupt feeds it.
    IdleKeepalive,
    /// Any other idle hart: the nearest sleeper if there is one, else the
    /// self-heal ceiling (`now + ceiling`). An idle non-0 hart is woken by IPI.
    IdleCeiling,
}

/// The instant to program: `min(nearest, now + cap)` for [`Cap::Busy`] and
/// [`Cap::IdleKeepalive`]; the nearest sleeper, or `now + ceiling` when there
/// is none, for [`Cap::IdleCeiling`]. Saturating: an overflow here would be a
/// panic inside the timer ISR under `overflow-checks`.
#[inline]
pub fn next_event(now: u64, nearest: Option<u64>, cap: Cap,
                  period: u64, keepalive: u64, ceiling: u64) -> u64 {
    let bound = match cap {
        Cap::Busy => now.saturating_add(period),
        Cap::IdleKeepalive => now.saturating_add(keepalive),
        Cap::IdleCeiling => return match nearest {
            Some(d) => d,
            None => now.saturating_add(ceiling),
        },
    };
    match nearest {
        Some(d) => d.min(bound),
        None => bound,
    }
}

/// Must a sleeper with `deadline` move the comparator that holds `programmed`?
///
/// Only when it is strictly earlier. A later or equal deadline is already
/// covered: the event at `programmed` comes first, and whoever handles it
/// (the timer ISR, the idle boundary) programs the next one from the nearest
/// sleeper, which then includes this one. [`NOT_ARMED`] answers no.
#[inline]
pub fn earlier_than_programmed(programmed: u64, deadline: u64) -> bool {
    programmed != NOT_ARMED && deadline < programmed
}

/// How many hart-0 keepalives fit in one watchdog timeout. The feed runs from
/// hart 0's timer interrupt only, so an idle hart 0 must take one at least
/// this often: three keepalives in a row may be lost or late (interrupts
/// masked, a long critical section, the one-event lag of a re-arm) before the
/// watchdog fires. Linux's watchdog core pings at timeout/2.
pub const KEEPALIVES_PER_TIMEOUT: u64 = 4;

/// The idle keepalive period, in microseconds, for a watchdog armed with
/// `timeout_ms`; `None` when no watchdog is armed (`timeout_ms == 0`): an
/// idle hart 0 then needs no periodic interrupt at all.
#[inline]
pub const fn keepalive_us(timeout_ms: u32) -> Option<u64> {
    if timeout_ms == 0 {
        None
    } else {
        Some((timeout_ms as u64).saturating_mul(1_000) / KEEPALIVES_PER_TIMEOUT)
    }
}
