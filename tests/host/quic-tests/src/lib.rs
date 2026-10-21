// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for QUIC in ring 3 (`userspace/lib/quic`).
//!
//! Three layers, bottom up, each tested where it can fail alone:
//!
//! * `handshake`: the crypto adaptor between quinn-proto and the
//!   rustls-rustcrypto provider, with two endpoints and no socket: the datagrams
//!   are carried by the test. The handshake, header and packet protection of
//!   both suites, stream data both ways, a server whose key does not match its signature.
//! * `link`: the driver over real UDP sockets on the loopback: connect, frames
//!   both ways, the source filter, a peer that closes, one that goes silent, one
//!   that restarts.
//! * `relay`: `rpcquic`, the same link as a process between two `rpcsrv` stand-ins.
//! * `rsa`: every provider refuses an RSA private key (the `deny.toml` claim
//!   about RUSTSEC-2023-0071), with a canary that restores the provider's loader.
//! * `rpc`: two RPC engines on that link: a Noise session inside QUIC, a call
//!   served by the far node, and a lost peer raising `NoConnection` in the
//!   caller after the engine's own retries (the relay cannot tell `rpcsrv`).

#[cfg(test)]
mod handshake;
#[cfg(test)]
mod link;
#[cfg(test)]
mod relay;
#[cfg(test)]
mod rpc;
#[cfg(test)]
mod rsa;
