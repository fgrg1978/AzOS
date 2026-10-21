// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the SSH server (`userspace/services/sshd`).
//!
//! The modules of the server are pulled in with `#[path]`, so the code under
//! test is the code `SSHD.ELF` is built from; the line discipline the session
//! uses is the terminal server's own (`userspace/services/termd`).
//!
//! What stands in for what:
//!
//! * **The primitives** are checked against their standards and against
//!   independent implementations: Ed25519 against RFC 8032 section 7.1,
//!   X25519 against RFC 7748 section 6.1 (RFC 8731, which defines the SSH key
//!   exchange over it, carries no vectors of its own; RFC 5656, the NIST-curve
//!   one, is not implemented), `chacha20-poly1305@openssh.com` against `ring`'s
//!   implementation of the same construction, SHA-256 against `sha2`.
//! * **The client** (`harness.rs`) is written here, from the RFCs, not from the
//!   server's code: it builds the exchange hash and the keys its own way and
//!   frames packets with the packet module only for the cipher.
//! * **The real client**: when the host has OpenSSH, `interop.rs` logs in with
//!   it over TCP to an in-process server.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/wire.rs"]
pub mod wire;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/packet.rs"]
pub mod packet;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/kex.rs"]
pub mod kex;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/auth.rs"]
pub mod auth;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/policy.rs"]
pub mod policy;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/server.rs"]
pub mod server;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sshd/src/session.rs"]
pub mod session;
#[allow(dead_code)]
#[path = "../../../../userspace/services/termd/src/disc.rs"]
pub mod disc;
#[allow(dead_code)]
#[path = "../../../../userspace/services/termd/src/edit.rs"]
pub mod edit;

#[cfg(test)]
mod harness;
#[cfg(test)]
mod interop;
#[cfg(test)]
mod t_auth;
#[cfg(test)]
mod t_conn;
#[cfg(test)]
mod t_kex;
#[cfg(test)]
mod t_packet;
#[cfg(test)]
mod t_policy;
#[cfg(test)]
mod t_session;
#[cfg(test)]
mod t_wire;
