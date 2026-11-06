// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS driver class traits — pure `no_std`, host-compatible.
//!
//! It has zero RISC-V dependencies so it compiles and runs unit
//! tests on the host (`cargo test --target aarch64-apple-darwin`).
//!
//! # Crate split rationale
//!
//! - `azos_drv_api` (this crate) — types and class traits only.
//!   Host-testable.
//! - `azos_drv_<class>` (`crates/drivers/<class>`) — the in-kernel driver
//!   impls, one crate per driver class. They cannot compile for the host
//!   because they pull RISC-V asm via `azos_arch`.
//!
//! The split lets the framework surface evolve under host
//! coverage while the impls stay no-std and target-specific.
//!
//! # Class traits
//!
//! One module per driver class that has a trait today: [`block`],
//! [`console`], [`net`]; [`recovery`] is what the block and network drivers
//! do when their device stops answering. The other classes are IDL interfaces
//! (`azos_devif`), served by a kernel host or on an endpoint.

#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod console;
pub mod net;
pub mod recovery;
