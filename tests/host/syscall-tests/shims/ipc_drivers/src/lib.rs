// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates (`azos_drv_*`), as seen from
//! `crates/core/ipc`'s `mmio_cap.rs`: the hardware bus, and the
//! published partition table the syscall layer reads, both re-exported from
//! `shims/drivers`. This is a separate crate instance from the outer
//! `tests/host/syscall-tests` package's own driver stand-in; the two are never
//! mixed at a call site.

/// The board constants, re-exported from `shims/drivers` (see this crate's
/// Cargo.toml).
pub use syscall_test_drivers::platform;

/// The hardware bus, re-exported from `shims/drivers`: one instance, seen by
/// the handler and by the capability's minter.
pub use syscall_test_drivers::hwbus;

/// The published partition table. Re-exported from
/// `shims/drivers`, NOT pulled a second time: the table is a set of statics,
/// and every reader must see the same one.
pub use syscall_test_drivers::partition;
