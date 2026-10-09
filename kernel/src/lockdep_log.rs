// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lockdep's printer (Kconfig LOCKDEP, `crates/core/sync/src/lockdep.rs`):
//! the queued reports and the hold summary, from task context only — the
//! ktest runner, and with LOCKDEP=y outside ktest the `log-flush` task
//! (`logger_set_pass_hook`). Never called from a lock path: the console
//! takes locks.

use azos_drv_sys::kprintln;

/// Print the reports queued since the last call, one line each.
pub(crate) fn reports(prefix: &str) {
    azos_sync::lockdep::drain(|r| kprintln!("{}{}", prefix, r));
}

/// Print the classes with the longest holds (Kconfig LOCKDEP_HOLD_TOP).
#[cfg_attr(not(feature = "ktest"), allow(dead_code))]
pub(crate) fn holds(prefix: &str) {
    azos_sync::lockdep::hold_top(azos_sync::lockdep::HOLD_TOP, |c| {
        kprintln!("{}{}", prefix, azos_sync::lockdep::HoldLine(c));
    });
}

/// The `log-flush` task's pass hook (LOCKDEP=y outside ktest).
pub(crate) fn drain() {
    reports("");
}
