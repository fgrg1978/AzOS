// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `PowerAssert` interface: system power assertions, served by the kernel
//! on the `powerassert` endpoint (`crates/core/syscall/src/power_assert.rs`).
//!
//! An assertion keeps the machine out of system suspend while its owner
//! works: the machine-wide form of a device wakelock ([`crate::power`]'s
//! `DevicePower::hold`). The kernel takes the owner from the call (the
//! calling task), the holder names a reason and a timeout; the ledger
//! (`azos_energy::assertion`) bounds it by Kconfig `POWER_ASSERTIONS_PER_TASK`
//! and `POWER_ASSERTION_TTL_MAX_MS`. The suspend sequence refuses while one is
//! live (reason `asserted`, recorded under rule `suspend`). An assertion
//! whose timeout passes is released by the kernel and recorded (rule
//! `power-assertion`, verdict `deny`); a refused one is recorded too.
//!
//! A separate interface from `power` on purpose: `WRITE` on `power` is the
//! right to shut the machine down, and a task that only needs the machine to
//! stay awake (the package installer) must not hold it. The
//! classes: `hold` and `release` act (`WRITE`), `stats` observes (`READ`).
//! Without Kconfig `ENERGY` every op answers `UNSUPPORTED`.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "PASR").
pub const POWER_ASSERT_ID: u32 = 0x5041_5352;

/// A reason: a package is being staged or installed (`PKGD.ELF`).
pub const REASON_PACKAGE: u32 = 1;

/// [`PowerAssert::stats`] selectors: assertions live now.
pub const STAT_LIVE: u32 = 0;
/// Assertions granted.
pub const STAT_GRANTED: u32 = 1;
/// Released by their owner.
pub const STAT_RELEASED: u32 = 2;
/// Released by the kernel at their timeout.
pub const STAT_EXPIRED: u32 = 3;
/// Refused (reason, timeout, quota, full).
pub const STAT_REFUSED: u32 = 4;

#[azos_interface(id = 0x5041_5352, level = 1)]
pub trait PowerAssert {
    /// Keep the machine out of system suspend for `ttl_ms` milliseconds, for
    /// `reason` (non-zero, the holder's own code, recorded): the assertion's
    /// id. `BAD_ARGUMENT` for a reason of 0 or a timeout of 0 or past the
    /// longest; `BUSY` when the caller holds its quota or the ledger is full.
    /// Needs `WRITE`.
    #[at_most_once]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn hold(&mut self, reason: u32, ttl_ms: u32) -> Out<u32>;
    /// Give assertion `id` back. `NO_RESOURCE` when the caller holds no live
    /// assertion of that id. Needs `WRITE`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn release(&mut self, id: u32) -> Out<()>;
    /// A counter (`STAT_*`); `BAD_ARGUMENT` for another selector. Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 1_000_000]
    #[budget_us = 50]
    fn stats(&self, sel: u32) -> Out<u64>;
}
