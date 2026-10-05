// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Brain-link transmit carry for RFC-0019 sealed messages.
//!
//! Sealing a message consumes record counters, and the brain accepts only the
//! exact next counter. A sealed message the socket does not take in full can
//! therefore be neither dropped nor sealed again: the next record would arrive
//! with a skipped counter — or, after a partial send, as a torn record — and
//! the brain ends the session. `TxCarry` holds the wire bytes of the last
//! sealed message until the socket has taken every one of them, and refuses to
//! seal another message while any remain.
//!
//! The logic lives here, free of the socket and the clock, so the host suite
//! (`tests/host/behavior-tests`) runs the code that ships; the kernel owns the one
//! instance (.bss) and injects `tcp::send_all_with_yield` and
//! `timebase::now`.
//!
//! Only sealed traffic goes through it. An unkeyed or HMAC-only link has no
//! record counter: a frame the socket does not take there is dropped as
//! before, and the frames after it stay readable.

/// How long a sealed message may sit in the carry with the socket taking
/// none of it before the session is ended (fail closed).
///
/// Two seconds, from two numbers in the tree:
///
/// - **Above one retransmission timeout.** The socket takes nothing while the
///   send window is full, and a segment lost then comes back only after
///   `RTO_INITIAL_MS` (1000 ms, `crates/net/net/src/tcp.rs`). A bound below that
///   would end a healthy session on one lost segment; twice it lets the first
///   retransmission land.
/// - **Below the brain's shortest comms timeout.** `comms_timeout_s` is 3.0 s
///   for the drone profile and 5.0 s for the others
///   (`AzOSRobotBrain/config.yaml`). A kernel whose sends have stopped is back
///   with a fresh session before the brain declares the link lost.
///
/// Not the 500 ms motor watchdog (`CFG_WATCHDOG_MS`): that bounds commands
/// arriving from the brain, a direction a transmit stall does not touch.
pub const BRAIN_TX_STALL_MS: u64 = 2_000;

/// Why [`TxCarry::seal_with`] did not seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealRefused {
    /// Bytes of the previous message are still unsent. Sealing now would
    /// consume record counters for a message queued behind them.
    Pending,
    /// The sealer produced no bytes, or more than the carry holds.
    Nothing,
}

/// The unsent tail of the last sealed message. See the module documentation.
pub struct TxCarry<const N: usize> {
    buf: [u8; N],
    start: usize,
    end: usize,
    /// Clock value of the last byte the socket took (or of the seal).
    last_progress: u64,
    stalled: bool,
}

impl<const N: usize> TxCarry<N> {
    pub const fn new() -> Self {
        TxCarry { buf: [0u8; N], start: 0, end: 0, last_progress: 0, stalled: false }
    }

    /// Nothing owed to the socket: the next message may be sealed.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Bytes of the last sealed message the socket has not taken.
    pub fn pending_len(&self) -> usize {
        self.end - self.start
    }

    /// Set by [`drain`](Self::drain) when a call took nothing and the last
    /// progress is at least the stall bound old. The caller ends the session.
    pub fn is_stalled(&self) -> bool {
        self.stalled
    }

    /// Forget everything — a closed socket or a new session.
    pub fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
        self.stalled = false;
    }

    /// Seal the next message straight into the carry.
    ///
    /// `seal` writes the message's wire bytes into the slice it is given and
    /// returns their length (0 for none). It is not called while bytes are
    /// pending, so a message that could not go out behind them consumes no
    /// record counter. `now` starts the stall timer.
    pub fn seal_with<F: FnOnce(&mut [u8]) -> usize>(
        &mut self,
        now: u64,
        seal: F,
    ) -> Result<usize, SealRefused> {
        if !self.is_empty() {
            return Err(SealRefused::Pending);
        }
        let n = seal(&mut self.buf);
        if n == 0 || n > N {
            self.reset();
            return Err(SealRefused::Nothing);
        }
        self.start = 0;
        self.end = n;
        self.last_progress = now;
        self.stalled = false;
        Ok(n)
    }

    /// Offer the pending bytes to `send` until the carry is empty or `send`
    /// takes nothing, and return how many it took.
    ///
    /// `send` returns how many leading bytes of its argument the socket took
    /// (a larger value counts as all of them). `clock` is read after each
    /// byte-taking call and once more when this call took nothing: progress
    /// restarts the stall timer, and a call that takes nothing with `stall`
    /// clock units since the last progress marks the carry stalled.
    pub fn drain<S, C>(&mut self, mut send: S, mut clock: C, stall: u64) -> usize
    where
        S: FnMut(&[u8]) -> usize,
        C: FnMut() -> u64,
    {
        let mut taken = 0usize;
        while !self.is_empty() {
            let n = send(&self.buf[self.start..self.end]).min(self.pending_len());
            if n == 0 {
                break;
            }
            self.start += n;
            taken += n;
            self.last_progress = clock();
            self.stalled = false;
        }
        if self.is_empty() {
            self.start = 0;
            self.end = 0;
        } else if taken == 0 && clock().saturating_sub(self.last_progress) >= stall {
            self.stalled = true;
        }
        taken
    }
}
