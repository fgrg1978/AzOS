// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Cap<DriverRegistry>` typed wrappers — RFC-0003, 2026-09-06.
//!
//! ## What the typed form changes, precisely
//!
//! The untyped path (`SYS_DRIVER_REGISTER`, retired in RFC-0040 gap 1) was a
//! `DriverRegistry(kind)` write check where **`kind` is the caller's `a0`**. The
//! check is correct — a task holding only `DriverRegistry(GPIO)` is refused
//! for `DRV_KIND_MOTOR_PID` — but the shape puts the authority's subject in
//! the caller's hands and relies on a lookup to disagree.
//!
//! In the typed form the kind is **read out of the capability**. There is no
//! `kind` argument at all, so "register as a kind you do not hold" is not a
//! request the ABI can express. That is the whole delta, and it is the reason
//! this family was migrated first: it is the only one of the six kinds added
//! with `CapKind`'s widening that a live task actually holds today
//! (`kernel/src/tasks/loader.rs`'s autorun block grants `DriverRegistry(DRV_KIND_GPIO)`
//! and nothing else), so this migrates working code rather than opening a door.
//!
//! ## No numeric validation of the kind, deliberately
//!
//! `azos_driver_server::driver_register` accepts **any** `u32` as a kind —
//! it checks only that the kind is not already registered and that a slot is
//! free (read it: there is no comparison against `DRV_KIND_*`). Rejecting
//! out-of-range kinds here would therefore be a *second* and stricter rule
//! than the registry's own, i.e. a new source of truth for a bound that does
//! not exist, and it would drift the moment a `DRV_KIND_` is added. What
//! bounds the kind is not a range check: it is that this cap is minted only
//! at boot, from the topology, and the mint names the kind.
//!
//! ## What the typed path LOSES, and it is not nothing
//!
//! `cap_check` calls `record_cap_denial` on every refusal, so an untyped
//! `SYS_DRIVER_REGISTER` denial reaches the flight recorder. The typed
//! handlers do not go through `cap_check` at all — they dereference the cap
//! and return `ECAPKIND`/`ECAPSTALE`/`ECAPPERMS` — so **a refused typed call
//! is recorded nowhere**. A task forging a `Cap<DriverRegistry>` to hijack
//! driver identity, which is precisely the event this kind exists to stop,
//! produces an errno and no record.
//!
//! This is a pre-existing property of the whole typed family, not something
//! introduced here: `record_cap_denial` has exactly one caller in
//! `crates/core/syscall/src/handlers.rs` (inside `cap_check`), so `gpio_*_typed`,
//! `motor_*_typed`, `pwm_*_typed` and `i2c_*_typed` are all silent on denial
//! too. It is recorded here because it is the cost of the migration rather
//! than a detail of it: finishing the move to `Cap<T>` for every family, with
//! the recorder still wired only to the legacy path, ends at a kernel where
//! capability denials stopped being recorded. The recorder takes a
//! `HandleKind` and the typed path has a `CapKind`, so closing it is a small
//! design decision, not a one-line call — and it should be made before more
//! families migrate, not after.
//!
//! ## Why the ops are not here
//!
//! `crates/core/ipc` does not depend on `azos_driver_server` and this module
//! does not add that edge — it would be acyclic (`driver_server` depends only
//! on `azos_sync`) but it would also have to be mirrored into every host
//! test crate that `#[path]`-includes this file. So the *minting* and the
//! *cap dereference* live here, dependency-free and host-testable, and the
//! registry calls live in `crates/core/syscall/src/handlers.rs`, which already
//! depends on both.

use crate::cap::{targets, Cap, CapError, CapPerms, CapTable};

/// Topology-loader entry: grant `tid` the right to register as the driver for
/// `drv_kind` (a `DRV_KIND_*` value).
///
/// Returns `None` if `tid` is unknown or its cap table is full. See the module
/// doc for why `drv_kind` itself is not range-checked.
pub fn drvreg_grant_cap(
    tid: u32,
    drv_kind: u32,
    perms: CapPerms,
) -> Option<Cap<targets::DriverRegistry>> {
    crate::cap_store::grant::<targets::DriverRegistry>(tid, perms, drv_kind)
}

/// Dereference a `Cap<DriverRegistry>` to the single `DRV_KIND_*` it names.
///
/// `WRITE` is required for both register and unregister, and that is not
/// over-strict: unregistering someone else's driver denies the device, which
/// for a motor driver is a stopped robot. A read-only registry capability
/// would authorise neither operation, so it would be a capability for nothing
/// — which is why no caller passes `READ` here.
///
/// This is the REGISTER dereference: it resolves through `CapTable::get`, so
/// claiming a driver identity is refused while RFC-0036 containment is armed.
/// Unregistering uses [`drvreg_kind_for_release`].
pub fn drvreg_kind_of(
    table: &CapTable,
    cap: Cap<targets::DriverRegistry>,
) -> Result<u32, CapError> {
    table.get(cap, CapPerms::WRITE)
}

/// [`drvreg_kind_of`] for giving a registration back: the same `WRITE`
/// requirement, without the containment step.
///
/// Owner decision 2026-09-13: releasing an object is exempt from containment,
/// the way closing a socket is, and still needs its authority. Claiming one is
/// not a release and stays contained. The untyped `sys_driver_unregister`
/// applies the same rule, so the twins give one answer.
pub fn drvreg_kind_for_release(
    table: &CapTable,
    cap: Cap<targets::DriverRegistry>,
) -> Result<u32, CapError> {
    table.get_uncontained(cap, CapPerms::WRITE)
}
