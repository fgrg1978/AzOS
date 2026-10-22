// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! EtherCAT master protocol logic (IEC 61158 type 12), pure `no_std`.
//!
//! This crate is the wire half of an EtherCAT master and nothing else: it
//! builds and parses frames, describes the slave-side records a master has to
//! write, sequences a slave through the AL state machine and does the
//! distributed-clock arithmetic. It owns no socket, no clock and no buffer: the
//! cyclic loop that sends frames on a NIC queue and paces the polls is the
//! caller's (the `[fieldbus.NAME]` master, `ECAT-CYCLIC`).
//!
//! # Layout
//!
//! - [`frame`]: Ethernet II + EtherCAT header, datagram chain builder and
//!   parser, command set (APRD/APWR/APRW, FPRD/FPWR/FPRW, BRD/BWR/BRW,
//!   LRD/LWR/LRW, ARMW, FRMW, NOP).
//! - [`reg`]: ESC register addresses, the FMMU and sync-manager records.
//! - [`al`]: AL states, the legal transitions and [`al::Bringup`], a sans-I/O
//!   sequencer that takes one slave from INIT to PRE-OP, SAFE-OP or OP.
//! - [`dc`]: system-time offset and line-topology propagation delay.
//!
//! # Scope
//!
//! Process data and the AL state machine; no mailbox protocols (CoE, FoE, EoE),
//! no SII/EEPROM access, no branching-topology delay solver, no bit-granular
//! FMMU mapping decisions (the record carries the bit fields, the caller picks
//! them).

#![no_std]
#![forbid(unsafe_code)]

pub mod al;
pub mod dc;
pub mod frame;
pub mod reg;

/// Every way encoding or parsing can fail. All of them are properties of the
/// bytes or of the buffer handed in, never of the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The output buffer cannot hold what was asked of it.
    BufferTooSmall,
    /// The datagram chain would exceed one frame's 1498 payload bytes, or one
    /// datagram's 11-bit length.
    TooLong,
    /// The input ends before the structure it announces.
    Truncated,
    /// The Ethernet type field is not 0x88A4.
    NotEthercat,
    /// The EtherCAT header type nibble is not 1 (datagrams); network variables
    /// and mailbox-gateway frames are not handled here.
    UnsupportedType(u8),
    /// A datagram command byte outside the 0..=14 command set.
    UnknownCmd(u8),
    /// The "more datagrams" chain disagrees with the frame length: the last
    /// datagram announced a successor, or bytes remain after one that did not.
    BadChain,
    /// A frame was finished with no datagram in it.
    Empty,
    /// DC timestamps that cannot come from a line topology (a negative hop).
    BadTimestamps,
}
