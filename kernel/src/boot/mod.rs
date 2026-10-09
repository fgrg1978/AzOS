// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-time install steps that `kernel_main` runs in order, one module per
//! subsystem. Everything is re-exported so `kernel_main` calls them by name.

mod early;
// The `[ISA]` boot line and the baseline/`require` refusals.
pub(crate) mod isa;
pub(crate) use early::early_main;
mod entropy;
pub(crate) use entropy::*;
mod config_auth;
pub(crate) use config_auth::*;
pub(crate) mod entropy_pool;
mod topology;
pub(crate) use topology::*;
#[cfg(feature = "energy")]
mod energy;
#[cfg(feature = "energy")]
pub(crate) use energy::*;
mod sched;
pub(crate) use sched::*;
mod blk_irq;
pub(crate) use blk_irq::*;
mod net;
pub(crate) use net::*;
mod seams;
pub(crate) use seams::*;
mod procfs;
pub(crate) use procfs::*;
// Kconfig CHAOS / DECISION_RECORDS: command line, canaries, ktests.
pub(crate) mod chaos;
mod robot;
pub(crate) use robot::*;
mod ota;
pub(crate) use ota::*;
mod stacks;
pub(crate) use stacks::*;
mod percpu;
pub(crate) use percpu::*;
// Entered from `boot.S` by symbol (`#[no_mangle]`); nothing in Rust names them.
pub(crate) mod smp;
