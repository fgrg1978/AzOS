// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the Zenoh gateway: the engine (`gw.rs`) and the key rule
//! (`route.rs`) of `userspace/services/zenohd`, pulled in with `#[path]` so the
//! code under test is the code `ZENOHD.ELF` is built from.
//!
//! **The test is the router.** It writes the bytes a Zenoh router writes (INIT
//! ack, OPEN ack, REQUEST, INTEREST, KEEP_ALIVE) with the in-tree codec and
//! reads what the gateway writes back. Behind the gateway is a model of the
//! kernel: a journal of decision records served through the real `Decisions`
//! interface (`azos_decisions::Service`), and a service endpoint (`Lamp`, an
//! interface with an effect, defined here with the IDL macro) whose call the
//! model admits or refuses, writing the record the kernel would write.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../../../userspace/services/zenohd/src/gw.rs"]
pub mod gw;
#[allow(dead_code)]
#[path = "../../../../userspace/services/zenohd/src/route.rs"]
pub mod route;

#[cfg(test)]
mod world;

#[cfg(test)]
mod tests;
