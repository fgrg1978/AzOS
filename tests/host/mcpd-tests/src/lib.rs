// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the MCP bridge: the engine (`bridge.rs`), the tool
//! catalog (`catalog.rs`), the warrant rules (`warrant.rs`) and the receipt
//! search (`receipt.rs`) of `userspace/services/mcpd`, pulled in with `#[path]`
//! so the code under test is the code `MCPD.ELF` is built from.
//!
//! **The test is the MCP client.** It writes the lines an MCP client writes
//! (`initialize`, `tools/list`, `tools/call`) and reads what the bridge writes
//! back. It is also the operator: it holds the root key and signs the warrants
//! (an agent's, a human's) the way the operator's tool does. Behind the bridge
//! is a model of the kernel: a journal of decision records served through the
//! real `Decisions` interface (`azos_decisions::Service`), and a service
//! endpoint (`Lamp`, an interface with a reader and an irreversible effect,
//! defined here with the IDL macro) whose call the model admits or refuses,
//! writing the record the kernel would write.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../../../userspace/services/mcpd/src/bridge.rs"]
pub mod bridge;
#[allow(dead_code)]
#[path = "../../../../userspace/services/mcpd/src/catalog.rs"]
pub mod catalog;
#[allow(dead_code)]
#[path = "../../../../userspace/services/mcpd/src/receipt.rs"]
pub mod receipt;
#[allow(dead_code)]
#[path = "../../../../userspace/services/mcpd/src/warrant.rs"]
pub mod warrant;

#[cfg(test)]
mod world;

#[cfg(test)]
mod tests;
