// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Latest-value channels — a [`Log`] of one slot, plus a timestamp.
//!
//! `Channel<T>` is `Log<Stamped<T>, 1>` from `azos_rings`: one writer, any
//! number of readers, no heap, `T: Copy`. The writer never blocks; a reader
//! that meets a store in progress retries. The sequence number is the log's
//! head (0 = never published) and the timestamp is caller-provided
//! (typically `timebase::now()`), which gives the generic watchdog
//! `channel.age(now) > threshold -> stale`.
//!
//! What this crate adds to the log is the kernel's part: the writer masks
//! preemption around a store ([`Publisher`]), because a reader on the same
//! hart that outranks a preempted writer would spin on the in-progress store
//! forever (the hazard K-C29 closed for `SpinLock`); and the age helpers.
//!
//! One writer is a property of the type: [`Channel::publisher`] hands out
//! the single [`Publisher`] and returns `None` afterwards; the handle is not
//! `Clone`. A task that may be restarted at its entry without unwinding (so
//! its handle is never dropped) keeps the handle in a static instead.
//!
//! ```ignore
//! use azos_channel::Channel;
//!
//! static CH: Channel<Cmd> = Channel::new(Cmd { speed: 0 });
//!
//! // The one publisher, taken once:
//! let mut tx = CH.publisher().unwrap();
//! tx.publish(Cmd { speed: 50 }, timebase::now());
//!
//! // Any number of readers:
//! let snap = CH.read();
//! if snap.seq > 0 {
//!     use_cmd(snap.val);
//! }
//! ```

use azos_rings::{Log, Writer};
use azos_sync::critical_section;

/// A value and the time it was published.
#[derive(Clone, Copy)]
pub struct Stamped<T: Copy> {
    pub val: T,
    pub timestamp: u64,
}

/// A latest-value channel: a [`Log`] of one [`Stamped`] slot.
pub struct Channel<T: Copy>(Log<Stamped<T>, 1>);

/// A snapshot returned by [`Channel::read`].
#[derive(Clone, Copy)]
pub struct Snapshot<T: Copy> {
    /// The latest published value.
    pub val: T,
    /// Monotonic sequence number (0 = never published).
    pub seq: u64,
    /// Caller-provided timestamp of the last publish.
    pub timestamp: u64,
}

/// The channel's only writer. Not `Clone`.
pub struct Publisher<'a, T: Copy>(Writer<'a, Stamped<T>, 1>);

impl<T: Copy> Publisher<'_, T> {
    /// Publish a new value with the caller's timestamp. Never blocks.
    ///
    /// Preemption is off for the store, so a higher-priority reader on this
    /// hart cannot spin on a store the preempted writer would never finish.
    /// The cost is proportional to the write (a few stores), not the read.
    pub fn publish(&mut self, val: T, timestamp: u64) {
        let _preempt = critical_section();
        self.0.publish(Stamped { val, timestamp });
    }
}

impl<T: Copy> Channel<T> {
    /// A channel holding `default` with `seq` 0 (never published).
    pub const fn new(default: T) -> Self {
        Channel(Log::new(Stamped { val: default, timestamp: 0 }))
    }

    /// The one publisher, or `None` if it is already out.
    pub fn publisher(&self) -> Option<Publisher<'_, T>> {
        self.0.writer().map(Publisher)
    }

    /// Read the current value, sequence number and timestamp (copy-out;
    /// retries while the writer is mid-store, never blocks it).
    pub fn read(&self) -> Snapshot<T> {
        let (seq, s) = self.0.latest();
        Snapshot { val: s.val, seq, timestamp: s.timestamp }
    }

    /// Sequence number of the latest publish (0 = never), without a copy.
    pub fn seq(&self) -> u64 {
        self.0.head()
    }

    /// Returns `true` if the channel has been published to at least once.
    pub fn is_valid(&self) -> bool {
        self.seq() > 0
    }

    /// Age in ticks since the last publish, given the current time.
    ///
    /// Returns `u64::MAX` if the channel has never been published to (seq == 0).
    pub fn age(&self, now: u64) -> u64 {
        let snap = self.read();
        if snap.seq == 0 {
            u64::MAX
        } else {
            now.saturating_sub(snap.timestamp)
        }
    }

    /// Age in MICROSECONDS since the last publish, saturating.
    ///
    /// # The overflow this exists to stop, which was reachable
    ///
    /// [`age`](Self::age) returns `u64::MAX` for a channel nobody has
    /// published to — the right answer, and a value that cannot be converted
    /// to microseconds by multiplying. Every call site did
    /// `ch.age(now) * 1_000_000 / TIMER_FREQ`, and this kernel builds with
    /// `overflow-checks = true` and `panic = "abort"`, so that multiplication
    /// on an unpublished channel is a board RESET.
    ///
    /// **It was reachable on real hardware and invisible in QEMU.** The flight
    /// controller (`domains/robot/safety-core`'s `flight_control_task`, created
    /// unconditionally at boot) reads three channels this way on every
    /// iteration. `CH_RC_INPUT` is published only when `rc_read()` returns
    /// `Some`, and with `RcMode::Sbus` — the mode a real receiver uses — the
    /// driver fails closed and returns `None`, so the channel is never
    /// published and the first iteration multiplies `u64::MAX`. Under QEMU the
    /// mode is `Simulated`, which publishes, so no scenario could show it.
    /// The same window exists in QEMU if a failsafe frame arrives before any
    /// good one, since `rc_frame_is_fresh_input` correctly refuses to publish
    /// that too.
    ///
    /// # Why saturate rather than return an `Option`
    ///
    /// The callers feed this to a staleness check — "has it been too long
    /// since RC input" — and for an unpublished channel the honest answer to
    /// that question is "yes, longer than any threshold". `u64::MAX`
    /// microseconds IS that answer, and it makes the failsafe fire, which is
    /// what a flight controller with no RC data must do. An `Option` would
    /// push the decision to every call site and invite a `.unwrap_or(0)` —
    /// "no data" reading as "perfectly fresh", which is the failure this
    /// whole channel type exists to prevent.
    ///
    /// `timer_freq` is the platform's tick rate; a zero is treated as
    /// "unknown clock", which is again maximally stale rather than a divide
    /// by zero.
    pub fn age_us(&self, now: u64, timer_freq: u64) -> u64 {
        let ticks = self.age(now);
        if ticks == u64::MAX || timer_freq == 0 {
            return u64::MAX;
        }
        // Divide FIRST where the multiply would overflow. `ticks / freq * 1e6`
        // loses sub-second precision, so it is used only past the point where
        // precision has stopped mattering — any age that large is stale by
        // every threshold in the tree.
        match ticks.checked_mul(1_000_000) {
            Some(us) => us / timer_freq,
            None => (ticks / timer_freq).saturating_mul(1_000_000),
        }
    }
}
