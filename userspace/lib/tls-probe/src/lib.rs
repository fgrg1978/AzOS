// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the probe runs: a TLS 1.2/1.3 handshake between a rustls client and a
//! rustls server (the rustls-rustcrypto provider on both sides, no aws-lc-rs, no
//! ring) over memory, the same exchange over any `Read + Write` (a `TcpStream`
//! on a device), and the QUIC transport types of quinn-proto.
//!
//! The crate is a library and a program so that the same code runs in two
//! places: on `*-unknown-azos` as the std program `tls-probe` (built by
//! `make sdk`, which links the whole graph), and on the host as `cargo test`
//! (the loopback handshake and its error cases), which is the only place a
//! handshake can be run before a device has a network. Host run, from the
//! repository root:
//!
//! ```text
//! python3 userspace/lib/tls-probe/vendor.py test
//! ```

pub mod quic;
pub mod tls;
