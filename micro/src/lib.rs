// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AzOS-micro: the MCU kernel.
//!
//! A separate kernel for parts with no MMU: riscv32imac, M-mode, memory
//! protection by PMP region domains. It reads the same signed topology and
//! speaks the same IPC and capability ABI as the main kernel, recompiled for
//! 32-bit words. Tasks are static (the rows of the topology), their kernel
//! state lives in grants inside their own regions, a server runs at its
//! endpoint's priority ceiling while it works, and a task can be started
//! only by `SYS_SPAWN_EX` under a launch capability: there is no fork and
//! no exec.
//!
//! # What it shares with the main kernel
//!
//! The pure modules below are compiled from the main kernel's own sources
//! (`#[path]`, the sharing mechanism the host suites already use), not
//! copied: the scheduling context and dispatch classes, the EDF/CBS
//! arithmetic, the QSBR counter rules and the scheduling-attribute order. The
//! topology parser and verifier, the ABI numbers, the capability handle and
//! the slot word are the crates `azos_topology` and `azos_abi`. A change to
//! any of them is a change to both kernels, and the 32-bit build checks the
//! layouts that must not move (`const` assertions in each file).
//!
//! Everything here is `no_std` and pure except [`hw`] and [`trap`], which
//! exist only on riscv32; the host suite (`tests/host/micro-tests`) drives
//! [`kernel::Kernel`] over a fake machine.

#![no_std]

/// The scheduling context and the dispatch classes (the main kernel's).
#[path = "../../crates/core/sched/src/sc.rs"]
pub mod sc;
/// EDF + CBS and the real-time band arithmetic (the main kernel's).
#[path = "../../crates/core/sched/src/rt_core.rs"]
pub mod rt_core;
/// The QSBR counter rules (the main kernel's). The micro kernel has one hart
/// and no reader that outlives a trap, so nothing consults a grace period
/// yet; the module is built for 32 bits here so the second hart of a P4
/// finds it ready.
#[path = "../../crates/core/sync/src/qsbr_core.rs"]
pub mod qsbr_core;
/// The order of scheduling attributes (the wait graph's, and the ceiling's).
#[path = "../../crates/core/sync/src/pi_attr.rs"]
pub mod pi_attr;

pub mod captable;
pub mod ceiling;
pub mod chip;
pub mod config;
pub mod domain;
pub mod grant;
pub mod kernel;
pub mod pmp_core;
pub mod sched;

#[cfg(target_arch = "riscv32")]
pub mod hw;
#[cfg(target_arch = "riscv32")]
pub mod trap;
