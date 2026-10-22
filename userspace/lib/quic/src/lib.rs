// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! QUIC in ring 3, for the transparent RPC link (Phase 9).
//!
//! The RPC engine (`userspace/lib/rpc`) carries one sealed frame per datagram
//! and does its own loss recovery. This crate is the other transport it can run
//! on: QUIC (RFC 9000) between the two nodes, with congestion control, flow
//! control, loss detection and a handshake that proves the peer receives at its
//! address. It is **ring 3 and std**: quinn-proto (the state machine, vendored,
//! no crypto feature) driven over `std::net::UdpSocket`, so the large parser of
//! network input is not in the process that holds the lend rights on the
//! exported endpoints.
//!
//! * [`suite`] and [`crypto`]: the crypto quinn-proto needs, over rustls' `quic`
//!   module and the rustls-rustcrypto provider (whose own QUIC support is a stub);
//! * [`identity`]: the TLS layer (RFC 7250 raw public keys) and why **Noise stays
//!   the authentication** inside it;
//! * [`pump`]: the driver, one frame per unidirectional stream;
//! * [`relay`]: the same link as a process of its own (`rpcquic`), for `rpcsrv`,
//!   which is `no_std` and keeps no network parser in it.
//!
//! The std programs that link it provide the entropy hooks of `getrandom` on
//! `*-unknown-azos` (see `userspace/services/rpcquic`); the library defines none.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod identity;
pub mod pump;
pub mod relay;
pub mod suite;

pub use identity::Identity;
pub use pump::{Event, Pump, Role, Sender, Settings, FRAME_MAX};
