// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera connection's sender policy (C1): when the kernel's camera task
//! dials the brain's camera port, when it sends a frame, and when it closes.
//!
//! On the control connection a camera frame is kilobytes of bulk among 70 B
//! sensor frames: a lost segment of it stalls every sensor and e-stop frame
//! queued behind it (TCP head-of-line blocking), and sending it inline holds
//! the behavior loop. The camera task sends it on a connection of its own.
//!
//! The rules, which the brain's listener (`AzOSRobotBrain/camera_link.py`)
//! mirrors on its side:
//!
//! - Dial only while a control session is up, and only with RFC-0019 armed.
//!   The brain refuses a camera connection on an HMAC-only link, and on an
//!   unkeyed link no camera frame fits its plaintext reader.
//! - A connection belongs to the control session it was dialed under: when
//!   that session ends or a new one replaces it, close.
//! - Close when the socket leaves Established or the transmit carry stalls.
//! - At most one frame per [`FRAME_PERIOD_MS`]. A period whose frame is due
//!   while the previous message is still unsent is skipped, never queued.
//! - After a failed dial, or a session that sent no frame, wait the previous
//!   wait doubled, up to [`BACKOFF_MAX_MS`]. After a session that sent a
//!   frame, wait [`BACKOFF_MIN_MS`].
//!
//! Free of the socket, the clock and the capture, so the host suite
//! (`tests/host/behavior-tests`) runs the code the kernel ships; the kernel task
//! gathers [`Inputs`] and [`Socket`], acts on each [`Step`], and reports back.

use core::sync::atomic::{AtomicU64, Ordering};

/// One camera frame per this many milliseconds, at most (~2 Hz, the rate the
/// behavior loop sent inline).
pub const FRAME_PERIOD_MS: u64 = 500;
/// Shortest wait before the next dial.
pub const BACKOFF_MIN_MS: u64 = 1_000;
/// Longest wait before the next dial.
pub const BACKOFF_MAX_MS: u64 = 30_000;
/// How long the task sleeps when nothing is due.
pub const POLL_MS: u64 = 100;

// ── Control session handoff ─────────────────────────────────────────────────

/// `generation << 1 | up`, one word so a reader never pairs the flag of one
/// session with the generation of another. Written only by the behavior task.
static CONTROL: AtomicU64 = AtomicU64::new(0);

/// The control connection's session as the camera task sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlSession {
    pub up: bool,
    /// Rises by one each time a control session becomes ready.
    pub generation: u64,
}

/// A control session is ready (connected, handshake done, status sent).
pub fn control_session_ready() {
    let _ = CONTROL.fetch_update(Ordering::Release, Ordering::Acquire, |v| {
        Some((((v >> 1).wrapping_add(1)) << 1) | 1)
    });
}

/// The control session ended; its generation stays until the next one.
pub fn control_session_ended() {
    CONTROL.fetch_and(!1, Ordering::Release);
}

pub fn control_session() -> ControlSession {
    let v = CONTROL.load(Ordering::Acquire);
    ControlSession { up: v & 1 == 1, generation: v >> 1 }
}

// ── Policy ──────────────────────────────────────────────────────────────────

/// What protects the brain link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkMode {
    /// No link key.
    Unkeyed,
    /// A link key, HMAC envelope only.
    HmacOnly,
    /// A link key and RFC-0019 (a handshake per connection).
    Encrypted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub now_ms: u64,
    /// A camera port is configured.
    pub enabled: bool,
    pub mode: LinkMode,
    pub control: ControlSession,
}

/// The camera connection's socket and transmit carry. Ignored while there is
/// no connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socket {
    pub established: bool,
    /// No sealed bytes are owed to the socket.
    pub carry_empty: bool,
    pub stalled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    Disabled,
    NotEncrypted,
    ControlEnded,
    ControlReplaced,
    NotEstablished,
    Stalled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing due before `until_ms`.
    Wait { until_ms: u64 },
    /// Dial, wait for Established, run the RFC-0019 handshake; then report
    /// [`CameraTx::dialed`] with this generation or [`CameraTx::dial_failed`].
    Dial { generation: u64 },
    /// Capture and seal one frame; then report [`CameraTx::frame_done`].
    Frame,
    /// Offer the carry's pending bytes to the socket, then step again.
    Drain,
    /// Close the socket; then report [`CameraTx::closed`].
    Close(CloseReason),
}

pub struct CameraTx {
    /// The control generation the live connection was dialed under.
    connection: Option<u64>,
    retry_at_ms: u64,
    backoff_ms: u64,
    next_frame_ms: u64,
    frames: u32,
}

impl CameraTx {
    pub const fn new() -> Self {
        CameraTx {
            connection: None,
            retry_at_ms: 0,
            backoff_ms: BACKOFF_MIN_MS,
            next_frame_ms: 0,
            frames: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Frames sealed on the live connection.
    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// The next thing to do.
    pub fn step(&mut self, i: &Inputs, s: &Socket) -> Step {
        let Some(generation) = self.connection else {
            if !i.enabled || i.mode != LinkMode::Encrypted || !i.control.up {
                return Step::Wait { until_ms: i.now_ms + POLL_MS };
            }
            if i.now_ms < self.retry_at_ms {
                return Step::Wait { until_ms: self.retry_at_ms };
            }
            return Step::Dial { generation: i.control.generation };
        };
        if !i.enabled {
            return Step::Close(CloseReason::Disabled);
        }
        if i.mode != LinkMode::Encrypted {
            return Step::Close(CloseReason::NotEncrypted);
        }
        if !i.control.up {
            return Step::Close(CloseReason::ControlEnded);
        }
        if i.control.generation != generation {
            return Step::Close(CloseReason::ControlReplaced);
        }
        if !s.established {
            return Step::Close(CloseReason::NotEstablished);
        }
        if s.stalled {
            return Step::Close(CloseReason::Stalled);
        }
        if !s.carry_empty {
            if i.now_ms >= self.next_frame_ms {
                self.next_frame_ms = i.now_ms + FRAME_PERIOD_MS;
            }
            return Step::Drain;
        }
        if i.now_ms >= self.next_frame_ms {
            return Step::Frame;
        }
        Step::Wait { until_ms: self.next_frame_ms.min(i.now_ms + POLL_MS) }
    }

    /// The dial and its handshake succeeded under `generation`.
    pub fn dialed(&mut self, generation: u64, now_ms: u64) {
        self.connection = Some(generation);
        self.next_frame_ms = now_ms;
        self.frames = 0;
    }

    /// The dial or its handshake failed.
    pub fn dial_failed(&mut self, now_ms: u64) {
        self.connection = None;
        self.back_off(now_ms);
    }

    /// A frame was due: `sealed` if one went into the carry.
    pub fn frame_done(&mut self, now_ms: u64, sealed: bool) {
        if sealed {
            self.frames = self.frames.saturating_add(1);
        }
        self.next_frame_ms = now_ms + FRAME_PERIOD_MS;
    }

    /// The connection was closed.
    pub fn closed(&mut self, now_ms: u64) {
        if self.frames > 0 {
            self.backoff_ms = BACKOFF_MIN_MS;
            self.retry_at_ms = now_ms + BACKOFF_MIN_MS;
        } else {
            self.back_off(now_ms);
        }
        self.connection = None;
        self.frames = 0;
    }

    fn back_off(&mut self, now_ms: u64) {
        self.retry_at_ms = now_ms + self.backoff_ms;
        self.backoff_ms = (self.backoff_ms * 2).min(BACKOFF_MAX_MS);
    }
}

impl Default for CameraTx {
    fn default() -> Self {
        Self::new()
    }
}
