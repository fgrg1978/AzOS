// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Generic typed channel — Phase H.
//!
//! A `Channel<T>` is a single-slot, single-producer / multi-reader IPC
//! primitive for bare-metal systems.  It stores one value of type `T: Copy`,
//! a monotonic sequence number, and a timestamp (caller-provided).
//!
//! # Design
//!
//! - **Zero-alloc**: no heap, no `Vec`, no `Box`.  `T` must be `Copy`.
//! - **SeqLock**: writer never blocks readers.  Readers detect concurrent
//!   writes via sequence counter and retry.  Perfect for sensor data
//!   published at high frequency and consumed by many tasks.
//! - **Sequence**: monotonic `u64` incremented on every `publish()`.
//!   Readers compare seq to detect new data without inspecting the payload.
//! - **Timestamp**: caller-provided `u64` (typically `timebase::now()`).
//!   Enables generic watchdog: `channel.age(now) > threshold → stale`.
//!
//! # Example
//!
//! ```ignore
//! use azos_channel::Channel;
//!
//! #[derive(Clone, Copy)]
//! struct Cmd { speed: i32 }
//!
//! static CH: Channel<Cmd> = Channel::new(Cmd { speed: 0 });
//!
//! // Publisher (single writer)
//! CH.publish(Cmd { speed: 50 }, timebase::now());
//!
//! // Reader (any number of concurrent readers)
//! let snap = CH.read();
//! if snap.seq > 0 {
//!     use_cmd(snap.val);
//! }
//! ```

use core::sync::atomic::{AtomicU64, Ordering};
use azos_sync::SeqLock;

/// A snapshot returned by [`Channel::read`].
#[derive(Clone, Copy)]
pub struct Snapshot<T: Copy> {
    /// The latest published value.
    pub val: T,
    /// Monotonic sequence number (0 = never published).
    pub seq: u64,
    /// Caller-provided timestamp of the last `publish()`.
    pub timestamp: u64,
}

/// Inner state protected by the SeqLock.
#[derive(Clone, Copy)]
struct Inner<T: Copy> {
    val: T,
    seq: u64,
    timestamp: u64,
}

/// A single-slot typed channel.
///
/// Stores one `T`, a sequence counter, and a timestamp.
/// Writer never blocks (SeqLock). Readers retry on contention.
pub struct Channel<T: Copy> {
    inner: SeqLock<Inner<T>>,
    /// Sequence counter — readable without locking for fast "has new data?" check.
    seq: AtomicU64,
}

// Safety: Channel provides synchronization via SeqLock.
unsafe impl<T: Copy + Send> Send for Channel<T> {}
unsafe impl<T: Copy + Send> Sync for Channel<T> {}

impl<T: Copy> Channel<T> {
    /// Create a new channel with a default value.
    ///
    /// `seq` starts at 0 (never published).
    pub const fn new(default: T) -> Self {
        Channel {
            inner: SeqLock::new(Inner {
                val: default,
                seq: 0,
                timestamp: 0,
            }),
            seq: AtomicU64::new(0),
        }
    }

    /// Publish a new value.
    ///
    /// Increments the sequence number and stores the caller-provided timestamp.
    /// `timestamp` should be `timebase::now()` or equivalent monotonic clock.
    ///
    /// # Single-writer contract
    /// Only one task should call `publish()` on a given channel.  If multiple
    /// writers are possible, serialize externally with a SpinLock.
    pub fn publish(&self, val: T, timestamp: u64) {
        let mut g = self.inner.write();
        g.seq += 1;
        g.val = val;
        g.timestamp = timestamp;
        let s = g.seq;
        drop(g);
        // Update the lock-free seq counter AFTER completing the write,
        // so readers that see a new seq will get consistent data.
        self.seq.store(s, Ordering::Release);
    }

    /// Read the current value, sequence number, and timestamp.
    ///
    /// Returns a `Snapshot<T>` (copy-out, lock-free — retries on contention).
    /// The reader never blocks the writer.
    pub fn read(&self) -> Snapshot<T> {
        let snap = self.inner.read();
        Snapshot {
            val: snap.val,
            seq: snap.seq,
            timestamp: snap.timestamp,
        }
    }

    /// Read the sequence counter without locking.
    ///
    /// Useful for fast "has new data?" checks:
    /// ```ignore
    /// if ch.seq() > my_last_seq { let snap = ch.read(); ... }
    /// ```
    pub fn seq(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Age in ticks since the last publish, given the current time.
    ///
    /// Returns `u64::MAX` if the channel has never been published to (seq == 0).
    pub fn age(&self, now: u64) -> u64 {
        let snap = self.inner.read();
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

    /// Returns `true` if the channel has been published to at least once.
    pub fn is_valid(&self) -> bool {
        self.seq.load(Ordering::Acquire) > 0
    }
}
