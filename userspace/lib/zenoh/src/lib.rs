// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Our own codec of the Zenoh 1.x wire protocol, the one zenoh-pico 1.x and
//! zenohd speak. Written from the published specification (spec.zenoh.io,
//! 1.0.0); no Zenoh code is linked or downloaded.
//!
//! It is only a codec: no socket, no clock, no session state. A daemon owns
//! those and calls here to turn bytes into messages and back.
//!
//! * [`codec`]: VLE integers, length-prefixed arrays, the ZenohID.
//! * [`transport`]: INIT, OPEN, CLOSE, KEEP_ALIVE, FRAME, FRAGMENT, batches and
//!   the two-byte length prefix of stream links.
//! * [`network`]: DECLARE, PUSH, REQUEST, RESPONSE, RESPONSE_FINAL, INTEREST.
//! * [`keyexpr`]: validity, intersection and inclusion of key expressions with
//!   `*`, `**` and `$*`.
//!
//! **Decoding borrows.** A decoded message points into the input buffer; keep
//! the buffer alive while the message is used. Nothing is allocated to decode.
//!
//! **A VLE** is seven bits per byte, low group first, bit 7 for "more"; a
//! `u64` takes at most nine bytes, the ninth carrying all eight of its bits
//! (this is what zenoh-rust and zenoh-pico do, and it matters: an NTP64
//! timestamp has bit 63 set). The specification's prose says plain LEB128 in
//! one place and nine bytes in another; the implementations settle it.
//!
//! **What is not here:** OAM, JOIN (multicast), scouting, the shared-memory
//! extensions, compression, fragment reassembly, and the authentication
//! extensions of INIT and OPEN (skipped when optional).
#![no_std]

extern crate alloc;

pub mod codec;
pub mod keyexpr;
pub mod network;
pub mod transport;

pub use codec::{Error, Reader, Result, Writer, Zid};
