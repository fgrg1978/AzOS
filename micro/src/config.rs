// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Kconfig symbols (`config/kernel/Kconfig.micro`) as typed constants, with the
//! relations between them checked at compile time. The values are
//! `azos_limits`' (the `.config` of `make micro`); nothing here has a default
//! of its own.

/// Tasks in the static table (`MICRO_MAX_TASKS`).
pub const MAX_TASKS: usize = azos_limits::MICRO_MAX_TASKS;
/// Named endpoints (`MICRO_MAX_ENDPOINTS`).
pub const MAX_ENDPOINTS: usize = azos_limits::MICRO_MAX_ENDPOINTS;
/// Capability slots in one task's table (`MICRO_CAPS_PER_TASK`).
pub const CAPS_PER_TASK: usize = azos_limits::MICRO_CAPS_PER_TASK;
/// PMP entries the hart implements (`MICRO_PMP_ENTRIES`).
pub const PMP_ENTRIES: usize = azos_limits::MICRO_PMP_ENTRIES;
/// PMP entries one task's domain may use (`MICRO_TASK_PMP_ENTRIES`).
pub const TASK_PMP_ENTRIES: usize = azos_limits::MICRO_TASK_PMP_ENTRIES;
/// log2 of the PMP granularity (`MICRO_PMP_GRAIN_LOG2`).
pub const GRAIN_LOG2: u32 = azos_limits::MICRO_PMP_GRAIN_LOG2 as u32;
/// Timer tick (`MICRO_TICK_HZ`).
pub const TICK_HZ: u32 = azos_limits::MICRO_TICK_HZ;
/// Round-robin slice in ticks (`MICRO_TIMESLICE_TICKS`).
pub const TIMESLICE_TICKS: u32 = azos_limits::MICRO_TIMESLICE_TICKS as u32;
/// First idle-class priority (`MICRO_IDLE_PRIO`).
pub const IDLE_PRIO: u32 = azos_limits::MICRO_IDLE_PRIO as u32;
/// `mtime` frequency (`MICRO_TIMEBASE_HZ`).
pub const TIMEBASE_HZ: u32 = azos_limits::MICRO_TIMEBASE_HZ;

/// Entries the shared code window takes: a TOR pair.
pub const CODE_PMP_ENTRIES: usize = 2;

/// `mtime` ticks in one scheduler tick.
pub const TICK_PERIOD: u64 = (TIMEBASE_HZ / TICK_HZ) as u64;

/// A task's stack is at least this many bytes (the floor of its Anon part).
pub const MIN_STACK: usize = 256;

const _: () = assert!(CODE_PMP_ENTRIES + TASK_PMP_ENTRIES <= PMP_ENTRIES, "the PMP table cannot hold a code window and one task's domain");
const _: () = assert!(CAPS_PER_TASK <= 512, "a handle's slot field addresses 512 slots");
const _: () = assert!(MAX_TASKS <= 255, "task indices are bytes");
const _: () = assert!(TIMEBASE_HZ >= TICK_HZ, "the tick is slower than the timebase");
const _: () = assert!(GRAIN_LOG2 >= 2);
const _: () = assert!(IDLE_PRIO <= 255);
