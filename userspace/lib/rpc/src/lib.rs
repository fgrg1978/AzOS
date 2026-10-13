// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Transparent RPC, step 1 (Phase 9): an endpoint on another node called as if it
//! were local.
//!
//! The RPC server (`userspace/services/rpcsrv`) is the whole of it. Ring 3, no
//! authority of its own beyond its signed row: it serves the **proxy endpoints**
//! (`endpoint.rpc-<service>`, one per remote service, the only endpoints that
//! stand for a service elsewhere) and holds the lend right on the endpoints its
//! row exports (`export = ["name@class"]`). A caller calls the proxy endpoint
//! exactly as it would call the service: the same IDL stub, the same `MsgDesc`.
//! The server reads the header word, finds which peer serves that interface,
//! and sends the message **as the IDL wire format** ([`wire`]) in a frame; the
//! node on the other side runs the call against the real endpoint with a warrant
//! it derived for that peer and sends the reply back.
//!
//! * **Export is explicit.** A node answers only for an interface its topology
//!   exports to the requester's peer class. Anything else is `Refused`.
//! * **Warrants, not trust.** The exporting node calls the real service through
//!   a per-session capability derived from its own: attenuated to the call
//!   right, badged with the session, expiring ([`Config::warrant_ttl_ns`]) and
//!   renewed while the session lives. A MemObj that crosses is re-minted as a
//!   new object whose lent copy expires the same way; the sender's object is
//!   consumed.
//! * **Provenance on both sides.** Each node appends to its [`journal`] what it
//!   minted over the session, in the kernel's own provenance record, with the
//!   peer's node id and the session id.
//! * **A broken session revokes everything minted over it** (every warrant, every
//!   re-minted object, on both nodes) and the callers waiting on it are told
//!   [`IdlError::NoConnection`](azos_idl::IdlError::NoConnection), which is not
//!   `PeerDied`: the first says the link is gone and the outcome is unknown, the
//!   second that the far server died.
//! * **Delivery is the op's attribute.** `#[idempotent]` ops are resent when the
//!   answer is late; `#[at_most_once]` ops are resent with the same number and
//!   the far node answers a repeat from the reply it kept, never running it
//!   twice; `#[once_only]` ops are sent once, and a lost answer is
//!   `NoConnection`, not a second try. An op that declares nothing crosses no
//!   link.
//! * **A real-time caller is refused at the proxy endpoint** (the kernel's
//!   `-ERTPROXY`, the topology's `neverallow`): a reservation cannot cover a
//!   link.
//!
//! What this crate does not own: the clock, the capability calls, the memory
//! objects ([`Host`]), the datagrams ([`Link`]) and the proof of who a peer is
//! ([`Handshake`]; Noise/DICE come later). The link is one datagram per frame, so the
//! engine runs the same over UDP on virtio-net, a loopback, and the in-memory
//! pair `tests/host/rpc-tests` puts two servers on.
#![no_std]

pub mod engine;
pub mod journal;
pub mod policy;
pub mod session;
pub mod wire;

pub use azos_abi::ipc_msg::MsgDesc;
pub use engine::{Call, Rpc, Started};
pub use policy::{Policy, Service};
pub use session::State;

/// A node's identity on the links: non-zero, and the one the topology's
/// `[peer.NAME]` lists.
pub type NodeId = u32;

/// Sessions at once (one per peer node).
pub const MAX_SESSIONS: usize = 4;
/// The most entries a session's dedupe window has (Kconfig `RPC_DEDUPE_WINDOW`
/// is at most this).
pub const DEDUPE_CAP: usize = 16;
/// The most bytes of an answer the dedupe window keeps; a larger one is not
/// kept, and a repeat of that call finds its outcome unknown.
pub const REPLY_KEEP: usize = 512;
/// Interfaces a session can carry each way.
pub const IFACES_MAX: usize = 8;
/// Objects re-minted over a session that are held at once; the oldest is
/// closed (its lent copy revoked) to make room.
pub const MINTED_CAP: usize = 16;
/// Records of the provenance journal.
pub const JOURNAL_CAP: usize = 32;
/// Bytes of identity proof a handshake attaches to a Hello.
pub const PROOF_MAX: usize = 64;

/// The server's settings (Kconfig `RPC_*`, read by `rpcsrv`'s `main`).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// This node's id.
    pub node: NodeId,
    /// This boot's epoch: a different one under the same node id tells the peer
    /// the sessions it had with the old one are gone.
    pub epoch: u32,
    /// How long a warrant, or a lent copy of a re-minted object, lives.
    pub warrant_ttl_ns: u64,
    /// Entries of a session's dedupe window (1 to [`DEDUPE_CAP`]).
    pub dedupe_window: usize,
    /// Resends of a call before it is given up (idempotent and at-most-once
    /// ops; a once-only op is sent once).
    pub retries: u8,
    /// How long to wait for an answer before a resend.
    pub rto_ns: u64,
    /// Silence after which a session is probed.
    pub ping_ns: u64,
    /// Unanswered probes or calls in a row after which a session is broken.
    pub miss_limit: u8,
}

/// The host the server runs on: the clock, the capability and memory calls.
pub trait Host {
    /// Monotonic nanoseconds on this node's clock.
    fn now_ns(&mut self) -> u64;
    /// One line for the console.
    fn log(&mut self, line: &[u8]);
    /// The handle this task holds on the endpoint at pool `index` (what an
    /// `export` line names); `None` if it holds none.
    fn endpoint(&mut self, index: u32) -> Option<u32>;
    /// Derive from the unbadged endpoint capability `ep` a copy with `rights`,
    /// `badge` and `expiry_ns` (absolute, this clock; 0 none): `SYS_CAP_DERIVE`.
    fn derive(&mut self, ep: u32, rights: u16, badge: u32, expiry_ns: u64) -> Result<u32, i64>;
    /// Close `h` and, with it, everything derived from it: `SYS_CAP_CLOSE`.
    fn close(&mut self, h: u32);
    /// Call the local endpoint `ep` with `msg`; the reply replaces it. 0 when
    /// answered, else the kernel's negative code.
    fn call(&mut self, ep: u32, msg: &mut MsgDesc) -> i64;
    /// Bytes of the memory object `h`, or `None` if it is not one.
    fn mo_size(&mut self, h: u32) -> Option<usize>;
    /// Copy the memory object `h` into `out` (at most `out.len()` bytes);
    /// how many.
    fn mo_read(&mut self, h: u32, out: &mut [u8]) -> Option<usize>;
    /// A new memory object holding `data`, zero-filled to whole pages, with
    /// read, write and `DUP` rights: the server's handle.
    fn mo_create(&mut self, data: &[u8]) -> Result<u32, i64>;
}

/// The datagrams. One call is one frame; delivery is not promised.
pub trait Link {
    /// Send `frame` to node `peer`; `false` if it could not be sent at all.
    fn send(&mut self, peer: NodeId, frame: &[u8]) -> bool;
}

/// Who a peer is. **Left as an interface:** Noise and DICE will implement it;
/// until they do, [`Claimed`] takes the id a peer states, which is no proof (a
/// datagram can be forged) and is why this step is for a link between nodes
/// that trust their network.
pub trait Handshake {
    /// The proof this node attaches to a Hello or its answer for `peer`: its
    /// length, written to `out`.
    fn prove(&mut self, peer: NodeId, out: &mut [u8; PROOF_MAX]) -> usize;
    /// Does `proof` show that the sender of the Hello is `node`?
    fn verify(&mut self, node: NodeId, proof: &[u8]) -> bool;
}

/// The stand-in handshake: no proof is sent and the node id stated is believed.
/// The topology still decides what any node of a class may do; this decides
/// nothing about who is who.
pub struct Claimed;

impl Handshake for Claimed {
    fn prove(&mut self, _peer: NodeId, _out: &mut [u8; PROOF_MAX]) -> usize {
        0
    }
    fn verify(&mut self, _node: NodeId, _proof: &[u8]) -> bool {
        true
    }
}
