// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_POWER_TYPED` (614) operations (RFC-0055 S5): the power family's one
//! typed call, used by the `POWER.ELF` tool. The capability is `Cap<Power>`
//! (`CapKind::Power`, resource 0).

/// Suspend until the next interrupt (`pm suspend`). Needs `WRITE`.
pub const POWER_OP_SUSPEND: u64 = 1;
/// Orderly reboot. Needs `WRITE`. Does not return.
pub const POWER_OP_REBOOT: u64 = 2;
/// Orderly power-off. Needs `WRITE`. Does not return.
pub const POWER_OP_SHUTDOWN: u64 = 3;
/// Read the scheduler tick rate (Hz). Needs `READ`.
pub const POWER_OP_SCHED_HZ_GET: u64 = 4;
/// Set the scheduler tick rate to `a2` Hz (`sched_hz set`). Needs `WRITE`.
pub const POWER_OP_SCHED_HZ_SET: u64 = 5;

/// Lowest rate `POWER_OP_SCHED_HZ_SET` takes; the console's `sched_hz` range.
pub const POWER_SCHED_HZ_MIN: u64 = 10;
/// Highest rate `POWER_OP_SCHED_HZ_SET` takes.
pub const POWER_SCHED_HZ_MAX: u64 = 10_000;
