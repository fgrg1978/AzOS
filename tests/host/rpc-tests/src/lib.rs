// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for transparent RPC (Phase 9, step 1).
//!
//! Two RPC servers (`userspace/lib/rpc`, the engine of `rpcsrv`) run in one
//! test over an in-memory link that can drop, repeat and delay frames, on two
//! clocks that disagree by a thousand seconds. Each holds the static Noise key
//! its topology pins, so every session is the real handshake and every frame
//! sealed; a `Forger` is a peer that is not an engine, for the frames no stub
//! would send. Each has a fake host that keeps
//! what the kernel keeps for it: a table of handles with the warrant tree
//! (a derive is a child, a close takes the children with it, a lapsed handle
//! is refused), memory objects, and the real service behind each exported
//! endpoint, which is an `#[azos_interface]` implementation dispatched
//! through the generated `dispatch`, so the bytes that cross are the IDL wire
//! format and the caller is the generated stub.
//!
//! The kernel half (the `-ERTPROXY` refusal, a proxy endpoint being named
//! `rpc-...`, the `neverallow` rules, the `inspect.rpc` view) is tested with the kernel
//! tables: `tests/host/topology-tests` and `tests/host/syscall-tests`.

#[cfg(test)]
mod codec;
#[cfg(test)]
mod derive;
#[cfg(test)]
mod engine;
#[cfg(test)]
mod macaroon_wire;
#[cfg(test)]
mod world;
#[cfg(test)]
mod dice;
#[cfg(test)]
mod xnode;
