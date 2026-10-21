// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for `crates/core/ipc/src/ep_queue.rs` tests.
//!
//! The kernel `azos_ipc` crate cannot be compiled for the host (it depends
//! on RV64-only crates). `ep_queue.rs` names two of them itself, but only
//! under `cfg(not(test))`; under `cfg(test)` it uses the host substitutes it
//! carries. So, exactly like `tests/host/cap-tests`, we pull the file in via
//! `#[path]` and let its embedded `#[cfg(test)] mod tests` run.
//!
//! Run with:  cd tests/host/ipc-fast-tests && cargo test

// The per-endpoint call queues (wave 15 N5): no dependencies, their own host
// substitutes. They replaced the machine-wide slot table, `fast_ipc.rs`.
#[path = "../../../../crates/core/ipc/src/ep_queue.rs"]
pub mod ep_queue;

// The descriptor the provenance label rides in (B4).
#[allow(dead_code)]
#[path = "../../../../crates/core/abi/src/ipc_msg.rs"]
pub mod ipc_msg;

// The rights word `ipc_msg` names (Rights S3: `rights.rs` pins its width).
#[allow(dead_code)]
#[path = "../../../../crates/core/abi/src/cap.rs"]
pub mod cap;
#[cfg(test)]
mod b4;
#[cfg(test)]
mod rights;
