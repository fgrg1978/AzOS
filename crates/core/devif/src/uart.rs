// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Uart` interface: one serial port.
//!
//! The endpoint's badge is the port (`endpoint = "uart.1"`). `READ` observes
//! the port, `WRITE` attaches rings (which lets bytes leave the machine) and
//! `EXEC` configures the line.
//!
//! **The bytes travel on rings, never in calls.** The client makes two
//! queues, attenuates each to the end the driver needs (write-only for
//! [`RxQueue`], read-only for [`TxQueue`]) and moves those copies with
//! `attach`; it keeps the other ends. The driver pushes what arrives as
//! [`Chunk`]s on the receive queue and sends what the client pushes on the
//! transmit queue. A chunk the receive queue had no room for is dropped and
//! counted ([`Status::rx_lost`]); the next chunk that fits is flagged
//! [`CHUNK_OVERRUN`] so the reader sees the gap.
//!
//! # Failure contract
//!
//! Attaching a transmit queue lets bytes reach whatever the line is wired to,
//! and a lost reply must not make the client attach twice: `attach` is
//! `once_only`; a port that cannot be driven answers `FAULT` and the client
//! carries on without the line (`degrade`).

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap, Reader, Wire, Writer};

/// The interface id (ASCII "UART").
pub const UART_ID: u32 = 0x5541_5254;

/// Ports the interface can name.
pub const PORTS: u32 = 4;
/// Slowest line rate accepted, baud.
pub const BAUD_MIN: u32 = 300;
/// Fastest line rate accepted, baud.
pub const BAUD_MAX: u32 = 4_000_000;
/// [`Uart::configure`]: no parity bit.
pub const PARITY_NONE: u32 = 0;
/// [`Uart::configure`]: odd parity.
pub const PARITY_ODD: u32 = 1;
/// [`Uart::configure`]: even parity.
pub const PARITY_EVEN: u32 = 2;

/// What a `Cap<RxQueue>` names: a queue of [`Chunk`]s, the driver its
/// producer.
pub struct RxQueue;
/// What a `Cap<TxQueue>` names: a queue of [`Chunk`]s, the driver its
/// consumer.
pub struct TxQueue;

/// Most data bytes of a chunk.
pub const CHUNK_DATA: usize = 32;
/// Bytes of one slot of either queue.
pub const CHUNK_BYTES: usize = 8 + CHUNK_DATA;
/// `Chunk::flags`: bytes were lost before this chunk (a full queue or a
/// receiver overrun).
pub const CHUNK_OVERRUN: u32 = 1;
/// `Chunk::flags`: a break condition ended with this chunk.
pub const CHUNK_BREAK: u32 = 2;
/// `Chunk::flags`: a framing error in this chunk.
pub const CHUNK_FRAMING: u32 = 4;
/// `Chunk::flags`: a parity error in this chunk.
pub const CHUNK_PARITY: u32 = 8;

/// One slot of either queue: up to [`CHUNK_DATA`] bytes and what the line
/// said about them. On the transmit queue `flags` is zero and ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// Bytes of `data` that are meaningful.
    pub len: u32,
    /// `CHUNK_*`.
    pub flags: u32,
    pub data: [u8; CHUNK_DATA],
}

impl Chunk {
    /// A chunk of the first [`CHUNK_DATA`] bytes of `bytes`.
    pub fn new(bytes: &[u8], flags: u32) -> Chunk {
        let n = bytes.len().min(CHUNK_DATA);
        let mut data = [0u8; CHUNK_DATA];
        data[..n].copy_from_slice(&bytes[..n]);
        Chunk { len: n as u32, flags, data }
    }

    /// The meaningful bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data[..(self.len as usize).min(CHUNK_DATA)]
    }

    /// The slot's bytes, little-endian.
    pub fn encode(&self) -> [u8; CHUNK_BYTES] {
        let mut b = [0u8; CHUNK_BYTES];
        b[0..4].copy_from_slice(&self.len.to_le_bytes());
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..].copy_from_slice(&self.data);
        b
    }

    /// The chunk a slot holds; `None` for a length past [`CHUNK_DATA`] (a slot
    /// the other end wrote wrong is refused, not clamped).
    pub fn decode(b: &[u8; CHUNK_BYTES]) -> Option<Chunk> {
        let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if len as usize > CHUNK_DATA {
            return None;
        }
        let mut data = [0u8; CHUNK_DATA];
        data.copy_from_slice(&b[8..]);
        Some(Chunk { len, flags: u32::from_le_bytes([b[4], b[5], b[6], b[7]]), data })
    }
}

/// The producer end of the receive queue, as the host resolved the handle the
/// client moved. `true` when the chunk fit.
pub trait ChunkSink {
    fn push(&mut self, chunk: &Chunk) -> bool;
}

/// The consumer end of the transmit queue.
pub trait ChunkSource {
    fn pop(&mut self) -> Option<Chunk>;
}

/// What a port counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Received chunks the queue had no room for, plus bytes the receiver
    /// overran.
    pub rx_lost: u32,
    /// Transmit chunks the line did not take whole.
    pub tx_lost: u32,
}

impl Wire for Status {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.rx_lost.put(w);
        self.tx_lost.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Status { rx_lost: u32::get(r), tx_lost: u32::get(r) }
    }
}

#[azos_interface(id = 0x5541_5254, level = 1)]
pub trait Uart {
    /// Set the line: `baud` ([`BAUD_MIN`]..=[`BAUD_MAX`]), `data_bits`
    /// (5..=8), `parity` (`PARITY_*`) and `stop_bits` (1 or 2); anything else
    /// is `BAD_ARGUMENT`. `UNSUPPORTED` when the port cannot run it (a line
    /// the board fixed). Needs `EXEC`.
    #[idempotent]
    fn configure(&mut self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()>;
    /// Start the port's traffic on `rx` (the driver pushes) and `tx` (the
    /// driver pops). `BUSY` while rings are attached, `NOT_READY` when the
    /// port has no hardware behind it. Needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()>;
    /// Stop the traffic and let go of both rings. Needs `WRITE`.
    #[idempotent]
    fn detach(&mut self) -> Out<()>;
    /// What the port counted. Needs `READ`.
    #[idempotent]
    fn status(&self) -> Out<Status>;
}
