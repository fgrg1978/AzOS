// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for `crates/core/ipc/src/fast_ipc.rs` tests.
//!
//! The kernel `azos_ipc` crate cannot be compiled for the host (it depends
//! on RV64-only crates). `fast_ipc.rs` names two of them itself —
//! `azos_sync::SpinLock` and `azos_sched` — but only under
//! `cfg(not(test))`; under `cfg(test)` it uses the host substitutes defined in
//! its own `host_seam` module. So, exactly like `tests/host/cap-tests`, we pull the
//! file in via `#[path]` and let its embedded `#[cfg(test)] mod tests` run.
//!
//! Run with:  cd tests/host/ipc-fast-tests && cargo test

#[path = "../../../../crates/core/ipc/src/fast_ipc.rs"]
pub mod fast_ipc;
