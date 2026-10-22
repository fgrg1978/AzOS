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
//! * **Every session is authenticated and sealed.** The handshake is Noise IK
//!   ([`chan`]) with the static keys the topology pins in its `[peer.NAME]`
//!   rows (`noise_pk`): a node whose key is not the pinned one never gets a
//!   session, and every frame after the handshake is encrypted and
//!   authenticated with the session's keys, a repeated one refused. There is
//!   no mode in which a node id is believed because a datagram states it.
//! * **Export is explicit.** A node answers only for an interface its topology
//!   exports to the requester's peer class. Anything else is `Refused`.
//! * **Warrants, not trust.** The exporting node calls the real service through
//!   a per-session capability derived from its own: attenuated to the call
//!   right, badged with the session, expiring ([`Config::warrant_ttl_ns`]) and
//!   renewed while the session lives. Every call carries a warrant token
//!   ([`wire::Token`]: the issuer, the interface, caveats chained by an HMAC
//!   under a key only the two ends of the session hold): the serving node
//!   verifies the chain, refuses what does not hold (another issuer, interface
//!   or node, an edited, dropped or reordered caveat) and derives the warrant
//!   from the re-minted result ([`session::Remint`]): its expiry and
//!   the caveats the kernel evaluates (`ENDPOINT_DERIVE`). The warrants a
//!   session keeps are keyed by interface **and caveat set** (and outlive no
//!   token that uses them), so a call never runs under the caveats or the
//!   expiry of another token. A `QUOTA` is counted by this node, per lineage
//!   of the token (the chain up to the caveat, which every copy shares), so
//!   narrowing a token never renews it; a token whose `OP_MASK` the
//!   kernel could never discharge on a call is refused before any derive.
//!   A MemObj that crosses is re-minted as a new object whose lent copy
//!   expires the same way; the sender's object is consumed.
//! * **Provenance on both sides.** Each node appends to its [`journal`] what it
//!   minted over the session, in the kernel's own provenance record, with the
//!   peer's node id and the session id.
//! * **A broken session revokes everything minted over it** (every warrant, every
//!   re-minted object, on both nodes) and the callers waiting on it are told
//!   [`IdlError::NoConnection`](azos_idl::IdlError::NoConnection), which is not
//!   `PeerDied`: the first says the link is gone and the outcome is unknown, the
//!   second that the far server died.
//! * **A withdrawn export is revoked on the peers, within a bound.** When the
//!   endpoint behind an export is closed or revoked, [`Rpc::revoke_export`]
//!   closes what this node lent over it and sends every peer that holds
//!   authority descending from it a sealed notice ([`wire::Kind::Revoke`]); the
//!   peer stops offering the interface, closes (`Host::close`) the
//!   objects it re-minted from this node's replies and answers
//!   ([`wire::Kind::RevokeAck`]): from the ack on, no effect of the withdrawn
//!   authority remains over the link. The notice is resent every `rto`; a peer
//!   that has not answered within the bound ([`Rpc::set_revoke_bound`], Kconfig
//!   `RPC_REVOKE_BOUND_MS`) has its **session broken**, which revokes everything
//!   minted over it. Both nodes record `Rule::RemoteRevoke` in their [`journal`].
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
//! objects, the node's secret key and its entropy ([`Host`]) and the datagrams
//! ([`Link`]). The link is one datagram per frame, so the engine runs the same
//! over UDP on virtio-net, a loopback, and the in-memory pair
//! `tests/host/rpc-tests` puts two servers on.
#![no_std]
#![forbid(unsafe_code)]

pub mod chan;
pub mod engine;
pub mod journal;
pub mod keys;
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
/// Warrants a session holds at once: one per interface and caveat set a
/// peer's tokens have made (the warrant cache is keyed by both); the one that
/// lapses first is closed to make room.
pub const WARRANTS_MAX: usize = 16;
/// Budgets a session counts at once: one per `QUOTA` caveat a peer's tokens
/// have spent from. A spent budget is never evicted (its entry is what keeps
/// refusing), so with every slot taken a token with a new `QUOTA` is refused.
pub const QUOTAS_MAX: usize = 16;
/// Objects re-minted over a session that are held at once; the oldest is
/// closed (its lent copy revoked) to make room.
pub const MINTED_CAP: usize = 16;
/// Records of the provenance journal.
pub const JOURNAL_CAP: usize = 32;

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
    /// `badge`, `expiry_ns` (absolute, this clock; 0 none) and `caveats` (at
    /// most [`wire::CAVEATS_MAX`], the kernel's limit) after the source's:
    /// `ENDPOINT_DERIVE`. The copy is never less restricted than `ep`.
    fn derive(&mut self, ep: u32, rights: u16, badge: u32, expiry_ns: u64, caveats: &[wire::Caveat]) -> Result<u32, i64>;
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
    /// This node's static X25519 private key ([`keys::NodeKey`]: the kernel's
    /// DICE identity of this image), whose public half the topology of the peers pins as
    /// this node's `noise_pk`; `None` when the node holds none, and then it
    /// neither dials nor answers.
    fn static_key(&mut self) -> Option<[u8; 32]>;
    /// Fill `out` from the kernel's entropy pool (the ephemeral keys of the
    /// handshakes); `false` when it cannot, and then no handshake starts.
    fn entropy(&mut self, out: &mut [u8; 32]) -> bool;
}

/// The datagrams. One call is one frame; delivery is not promised.
pub trait Link {
    /// Send `frame` to node `peer`; `false` if it could not be sent at all.
    fn send(&mut self, peer: NodeId, frame: &[u8]) -> bool;
}
