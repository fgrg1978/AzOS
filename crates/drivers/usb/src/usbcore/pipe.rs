// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pipes: the data path of a class driver.
//!
//! A pipe is a pair of `Queue` rings. The class driver pushes [`Transfer`]s
//! into the submission ring and pops [`Completion`]s from the completion ring;
//! the USB core is the other end of both (`Queue` hands out one producer and
//! one consumer, so a second writer cannot exist). A transfer names a buffer
//! by its bus address: the buffer is the class driver's own (a MemObj it
//! mapped through the device's DMA domain), the core never allocates for it
//! and never copies, and a buffer the controller cannot reach is refused with
//! [`Status::Bounce`], not bounced behind the driver's back.
//!
//! The ring depth ([`PIPE_DEPTH`], Kconfig `USB_PIPE_DEPTH`) is also the most
//! transfers a driver may have outstanding (submitted and not yet reaped):
//! the core pulls a submission only while the completion ring has room for it
//! to finish, so a completion is never dropped.

use azos_rings::{Consumer, Full, Producer, Queue};

use crate::PIPE_DEPTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
}

/// One transfer a class driver asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// Returned in the completion.
    pub tag: u32,
    pub dir: Dir,
    /// The setup packet, for a control pipe; ignored otherwise (the
    /// direction is then the setup's).
    pub setup: [u8; 8],
    /// Bus address of the buffer, `len` bytes.
    pub buf: u64,
    pub len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Done; `actual` bytes moved (fewer than asked is a short packet).
    Ok,
    /// The endpoint stalled. The device side is cleared with
    /// CLEAR_FEATURE(ENDPOINT_HALT) on the control pipe.
    Stall,
    /// More data than the buffer held, or the device sent a packet it should
    /// not have.
    Babble,
    /// A bus error that persisted through the controller's retries.
    Transaction,
    /// The device went away.
    Disconnected,
    /// The buffer lies above what the controller can address.
    Bounce,
    /// A control request the claim does not allow.
    Denied,
    /// The transfer does not fit the pipe (direction, length, ring).
    Invalid,
    /// Another completion code of the controller.
    Other(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub tag: u32,
    pub status: Status,
    pub actual: u32,
}

/// The two rings of a pipe. The kernel keeps `MAX_PIPES` of them in static
/// memory; the pipe table of the core indexes them.
pub struct PipeRings {
    pub(crate) sq: Queue<Transfer, PIPE_DEPTH>,
    pub(crate) cq: Queue<Completion, PIPE_DEPTH>,
}

impl PipeRings {
    pub const fn new() -> PipeRings {
        PipeRings { sq: Queue::new(Full::Backpressure), cq: Queue::new(Full::Backpressure) }
    }
}

impl Default for PipeRings {
    fn default() -> Self {
        PipeRings::new()
    }
}

/// The class driver's end of a pipe: it submits and it reaps.
pub struct PipeEnd<'q> {
    pub id: u8,
    pub sq: Producer<'q, Transfer, PIPE_DEPTH>,
    pub cq: Consumer<'q, Completion, PIPE_DEPTH>,
}

impl<'q> PipeEnd<'q> {
    /// Take the driver's ends of `rings`. `None` while a previous holder still
    /// has either end.
    pub fn take(rings: &'q PipeRings, id: u8) -> Option<PipeEnd<'q>> {
        let sq = rings.sq.producer()?;
        let cq = rings.cq.consumer()?;
        Some(PipeEnd { id, sq, cq })
    }
}

/// The core's end of a pipe's rings.
pub(crate) struct CoreEnd<'q> {
    pub sq: Consumer<'q, Transfer, PIPE_DEPTH>,
    pub cq: Producer<'q, Completion, PIPE_DEPTH>,
    pub rings: &'q PipeRings,
}

impl<'q> CoreEnd<'q> {
    pub fn take(rings: &'q PipeRings) -> Option<CoreEnd<'q>> {
        let sq = rings.sq.consumer()?;
        let cq = rings.cq.producer()?;
        Some(CoreEnd { sq, cq, rings })
    }
}
