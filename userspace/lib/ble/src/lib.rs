// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Bluetooth LE host, the part under GATT (front `ble-hci`).
//!
//! A controller sits at the far end of a **`Uart` port** (the companion-radio
//! bridge, or the USB CDC-ACM function the kernel offers as a hot-plugged
//! port): HCI over the H4 framing. The bytes travel on the port's two rings, in
//! [`Chunk`](azos_devif::uart::Chunk)s, never in calls: the host takes the
//! chunks the driver pushed on the receive ring and leaves what it wants sent
//! as chunks for the transmit ring ([`Host::run`], over the two ring-end
//! traits the port's `attach` hands to a client). Nothing here makes a system
//! call: the host owns no clock (the caller passes `now_ms`), no entropy and no
//! key store ([`Platform`], [`Upper`]).
//!
//! * [`h4`]: the packet framing, incremental (a packet straddles chunks) and
//!   resynchronising (garbage, an oversized length, a stalled half packet).
//! * [`hci`]: the command encoder and the event decoder.
//! * [`l2cap`]: ACL headers, reassembly and fragmentation, and the LE
//!   signalling channel.
//! * [`att`]: the ATT PDUs; the host runs the MTU exchange and the one
//!   outstanding request rule, GATT (the later front) owns the attribute
//!   database.
//! * [`smp`] and [`crypto`]: LE Secure Connections pairing (just works and
//!   numeric comparison; P-256 on the host, AES-CMAC f4/f5/f6/g2), ending in a
//!   [`smp::Keys`] the upper layer stores (the key store is a later front).
//! * [`host`]: the state machine that ties them to a controller: the
//!   initialisation sequence, command and ACL flow control, advertising,
//!   scanning, connections in both roles.
//!
//! # Users
//!
//! The production user is `ble-gatt` (telemetry and wearables, a later wave).
//! Until it lands, the in-tree user is the host suite (`tests/host/ble-tests`),
//! which drives the library over a scripted controller and between two hosts,
//! and the gate runs it.
//!
//! # Limits (compile-time, stated once)
//!
//! [`MAX_CONN`] connections, an L2CAP payload of [`L2CAP_MTU`] bytes (the LE
//! data length extension's 251-byte PDU minus the 4-byte L2CAP header), one
//! controller command in flight, [`CMD_QUEUE`] queued commands.
#![no_std]
#![forbid(unsafe_code)]

pub mod att;
pub mod crypto;
pub mod h4;
pub mod hci;
pub mod host;
pub mod l2cap;
pub mod smp;

pub use host::{Config, Event, Host, Upper};

/// Simultaneous connections.
pub const MAX_CONN: usize = 2;
/// Largest L2CAP payload (ATT PDU or SMP PDU) the host receives or sends.
pub const L2CAP_MTU: usize = 247;
/// Commands the host queues for the controller (one is in flight at a time).
pub const CMD_QUEUE: usize = 8;
/// Bytes of the outbound H4 ring, which holds whole packets.
pub const TX_RING: usize = 1024;

/// A device address on the air: the type (`0` public, `1` random) and the six
/// bytes in the order HCI carries them (least significant first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PeerAddr {
    pub kind: u8,
    pub addr: [u8; 6],
}

/// A short read or a field out of range in something a peer or controller sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the PDU needs.
    Short,
    /// A field holds a value the PDU does not allow.
    Invalid,
    /// An opcode this host does not decode.
    Unknown,
    /// The output buffer is too small.
    NoRoom,
}

pub(crate) fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

pub(crate) fn put16(out: &mut [u8], at: usize, v: u16) {
    out[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

/// What the host asks of its environment: randomness (nonces and the ephemeral
/// P-256 key of pairing). A ring-3 service answers it from the entropy
/// service; a test from a seeded generator.
pub trait Platform {
    /// Fill `out` with random bytes.
    fn random(&mut self, out: &mut [u8]);
}
