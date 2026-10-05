// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ML inference service's request/reply layout (`DRV_KIND_ML`).
//!
//! The kernel's behavior loop is the client (through the driver-server
//! proxy); `userspace/services/mlsrv` is the server. Both sides read these numbers
//! from here, so the op space cannot drift between them.
//!
//! # `OP_INFER`
//!
//! Request payload (4 bytes): `front_mm: u16 le`, `right_mm: u16 le` — the
//! two range readings the MLP takes, in the sensor bus's milli-units
//! (0..1000). The service turns them into the MLP's normalised input
//! `[front / 1000, right / 1000, 0.5, 0.9]`, which is exactly what the
//! in-kernel inference used to build.
//!
//! Reply payload ([`INFER_REPLY_LEN`] bytes): `class: u8` (0 go_forward,
//! 1 turn_right, 2 stop), three pad bytes, then the three logits as `f32`
//! bit patterns, little-endian.
//!
//! # `OP_STALL` and `OP_FAULT`
//!
//! Fault injection for the gate's ML-service row, honoured only when the
//! request's `client_tid` is the kernel's proxy sentinel (`u32::MAX`) — a
//! ring-3 client can neither stall the service nor kill it. `OP_STALL`
//! sleeps for the `u16 le` milliseconds in its payload and then answers like
//! `OP_INFER` on a zero vector: the service is alive and late. `OP_FAULT`
//! takes a store page fault on purpose and the kernel kills the task: the
//! service is dead.

/// Run the MLP on one sensor vector.
pub const OP_INFER: u32 = 1;
/// Sleep, then answer (kernel clients only; gate fault injection).
pub const OP_STALL: u32 = 0x57A1;
/// Die by a page fault (kernel clients only; gate fault injection).
pub const OP_FAULT: u32 = 0xDEAD;

/// Request payload length of [`OP_INFER`].
pub const INFER_REQ_LEN: usize = 4;
/// Reply payload length of [`OP_INFER`].
pub const INFER_REPLY_LEN: usize = 16;

/// Class the MLP answers for "obstacle: stop".
pub const CLASS_STOP: u8 = 2;
/// Number of classes; a reply class at or above this is malformed.
pub const CLASSES: u8 = 3;

/// The MLP weights the service loads at start (`tools/make_mlp.py`'s `.rmlp`
/// format), NUL-terminated for the open syscall.
///
/// An 8.3 name. The FAT32 driver matches short names only: the four-letter
/// extension this file had until wave 10, `MLP.RMLP`, was stored by `mcopy`
/// as `MLP~1.RML`, which no lookup reached, so the service always fell back
/// to its compiled-in weights. `tests/host/fs-tests` opens this path on a volume
/// the Makefile's own tools wrote.
pub const WEIGHTS_PATH: &[u8] = b"/fat/MLP.RML\0";
/// The GGUF policy the service's start-up self-test classifies with.
pub const POLICY_PATH: &[u8] = b"/fat/POLICY.GGF\0";

/// Ed25519 signature over [`WEIGHTS_PATH`]'s bytes: a bare 64-byte sidecar,
/// the `CAPS.SIG`/`CONFIG.SIG` format, signed with the same key
/// (`azos_topology::TRUSTED_PUBKEY`). An 8.3 name sharing the base name:
/// `MLP.RML.SIG` has two dots and the FAT32 driver could never open it.
pub const WEIGHTS_SIG_PATH: &[u8] = b"/fat/MLP.SIG\0";
/// Ed25519 signature over [`POLICY_PATH`]'s bytes; see [`WEIGHTS_SIG_PATH`].
pub const POLICY_SIG_PATH: &[u8] = b"/fat/POLICY.SIG\0";
