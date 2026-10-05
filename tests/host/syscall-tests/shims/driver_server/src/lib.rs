// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_driver_server`, used only by
//! `tests/host/syscall-tests`.
//!
//! **Real, not a stand-in.** `crates/drivers/driver_server/src/lib.rs` is pure
//! `no_std` with exactly one dependency (`azos_sync::SpinLock`), so it
//! is pulled in whole with `#[path]`. That matters for target 2
//! (`cap_kind_for_driver`): the test enumerates every `DRV_KIND_*` constant
//! this crate declares and checks the map against all of them, so the
//! constants have to be the real ones, not a hand-copied list that could
//! drift the moment a new driver kind is added here and not there.

#[allow(dead_code, unused_attributes)]
#[path = "../../../../../../crates/drivers/driver_server/src/lib.rs"]
mod real;
pub use real::*;
