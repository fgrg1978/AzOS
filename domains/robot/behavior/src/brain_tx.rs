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
///
/// Kconfig `BRAIN_TX_STALL_MS` (default 2000, the reasoning above).
pub const BRAIN_TX_STALL_MS: u64 = azos_limits::BRAIN_TX_STALL_MS as u64;

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

// ── Wave 15 (B1): the behavior task enqueues, the `brain-tx` task sends ─────
//
// The behavior loop used to put each message on the control socket itself,
// waiting up to `BRAIN_SEND_BUDGET_US` (500 ms, the motor watchdog's order)
// on a closed window or an ARP miss. Now it seals the message into a
// [`TxQueue`] and returns; a task of its own drains the queue to the socket
// with the wait.
//
// **Two lanes are an admission policy, not two paths to the socket.** A
// sealed message spends record counters and the brain accepts only the next
// one, so once sealed a message can neither be dropped nor overtaken: the
// queue is one FIFO of wire bytes. What differs per lane is admission,
// decided BEFORE sealing (`admits` with the message's largest sealed size):
// control (status, REJECT) may use the whole queue; telemetry (sensor and
// camera frames) only what is left above `reserve` bytes. So telemetry can
// never fill the room a control message needs, and a refused telemetry
// frame is dropped unsealed — the newest one, since the older ones are
// already sealed — and counted. A control message that does not fit means
// the socket has stopped taking bytes; the queue's stall bound ends the
// session (fail closed), as the carry's did.

/// Which admission rule a message is enqueued under. See the section above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Status, REJECT: may use the whole queue.
    Control,
    /// Sensor and camera frames: only the room above the control reserve.
    Telemetry,
}

/// The sealed bytes the behavior task has queued for the control socket, and
/// the sender's stall state. One producer (behavior), one consumer
/// (`brain-tx`); the kernel serialises both under one lock that is held
/// only for copies and one non-blocking socket call.
pub struct TxQueue<const N: usize> {
    buf: [u8; N],
    /// Index of the oldest unsent byte.
    start: usize,
    /// Unsent bytes.
    len: usize,
    /// Bytes only [`Lane::Control`] may use.
    reserve: usize,
    /// Clock value of the last byte the socket took, or of the push that
    /// made the queue non-empty.
    last_progress: u64,
    stalled: bool,
    /// Telemetry frames refused for want of room above the reserve.
    pub telemetry_dropped: u32,
    /// Control messages refused: the queue was full (the session is
    /// stalling; see the section above).
    pub control_refused: u32,
    /// Messages admitted, per lane (control, telemetry).
    pub admitted: [u32; 2],
}

impl<const N: usize> TxQueue<N> {
    /// `reserve` is clamped to the queue's size.
    pub const fn new(reserve: usize) -> Self {
        TxQueue {
            buf: [0u8; N],
            start: 0,
            len: 0,
            reserve: if reserve > N { N } else { reserve },
            last_progress: 0,
            stalled: false,
            telemetry_dropped: 0,
            control_refused: 0,
            admitted: [0, 0],
        }
    }

    /// Nothing owed to the socket.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes queued and not yet taken by the socket.
    pub fn pending_len(&self) -> usize {
        self.len
    }

    /// Room left, whatever the lane.
    pub fn free(&self) -> usize {
        N - self.len
    }

    /// Set by [`drain`](Self::drain) when a call took nothing and the last
    /// progress is at least the stall bound old. The session is ended.
    pub fn is_stalled(&self) -> bool {
        self.stalled
    }

    /// Would a message of up to `len` wire bytes be admitted on `lane` now?
    /// Asked BEFORE sealing, with the message's largest sealed size, so a
    /// refused message spends no record counter. Only the consumer runs
    /// between this and [`push`](Self::push), and it only frees room.
    pub fn admits(&self, lane: Lane, len: usize) -> bool {
        match lane {
            Lane::Control => len <= self.free(),
            Lane::Telemetry => len.saturating_add(self.reserve) <= self.free(),
        }
    }

    /// Count a message [`admits`](Self::admits) refused on `lane`.
    pub fn refused(&mut self, lane: Lane) {
        match lane {
            Lane::Control => self.control_refused = self.control_refused.wrapping_add(1),
            Lane::Telemetry => self.telemetry_dropped = self.telemetry_dropped.wrapping_add(1),
        }
    }

    /// Append one whole message's wire bytes. `false` (and nothing queued,
    /// the refusal counted) if `lane` does not admit them. `now` starts the
    /// stall clock when the queue was empty.
    pub fn push(&mut self, lane: Lane, bytes: &[u8], now: u64) -> bool {
        if bytes.is_empty() {
            return true;
        }
        if !self.admits(lane, bytes.len()) {
            self.refused(lane);
            return false;
        }
        if self.len == 0 {
            self.start = 0;
            self.last_progress = now;
            self.stalled = false;
        }
        let mut at = (self.start + self.len) % N;
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = rest.len().min(N - at);
            self.buf[at..at + n].copy_from_slice(&rest[..n]);
            rest = &rest[n..];
            at = (at + n) % N;
        }
        self.len += bytes.len();
        let i = match lane { Lane::Control => 0, Lane::Telemetry => 1 };
        self.admitted[i] = self.admitted[i].wrapping_add(1);
        true
    }

    /// The oldest unsent bytes that are contiguous in the buffer.
    pub fn front(&self) -> &[u8] {
        let n = self.len.min(N - self.start);
        &self.buf[self.start..self.start + n]
    }

    /// The socket took `n` bytes of [`front`](Self::front) (clamped).
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.start = (self.start + n) % N;
        self.len -= n;
        if self.len == 0 {
            self.start = 0;
        }
    }

    /// Offer the queued bytes to `send` until the queue is empty or `send`
    /// takes nothing, and return how many it took. `send` returns how many
    /// leading bytes of its argument the socket took. Progress restarts the
    /// stall clock; a call that takes nothing with `stall` clock units since
    /// the last progress marks the queue stalled (same rule as
    /// [`TxCarry::drain`]).
    pub fn drain<S, C>(&mut self, send: S, clock: C, stall: u64) -> usize
    where
        S: FnMut(&[u8]) -> usize,
        C: FnMut() -> u64,
    {
        self.drain_bounded(send, clock, stall, usize::MAX)
    }

    /// [`drain`](Self::drain) with at most `calls` calls of `send` that take
    /// bytes: the kernel holds its lock for one socket call per hold.
    pub fn drain_bounded<S, C>(&mut self, mut send: S, mut clock: C, stall: u64, calls: usize) -> usize
    where
        S: FnMut(&[u8]) -> usize,
        C: FnMut() -> u64,
    {
        let mut taken = 0usize;
        let mut made = 0usize;
        while !self.is_empty() && made < calls {
            made += 1;
            let f = self.front();
            let n = send(f).min(f.len());
            if n == 0 {
                break;
            }
            self.consume(n);
            taken += n;
            self.last_progress = clock();
            self.stalled = false;
        }
        if !self.is_empty() && taken == 0 && clock().saturating_sub(self.last_progress) >= stall {
            self.stalled = true;
        }
        taken
    }

    /// Forget every queued byte — a closed socket or a new session. The
    /// counters are kept (they are per boot).
    pub fn reset(&mut self) {
        self.start = 0;
        self.len = 0;
        self.stalled = false;
    }
}
