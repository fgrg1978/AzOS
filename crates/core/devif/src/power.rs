// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Power` interface: the power family and the energy policy, for the
//! `POWER.ELF` tool and anything that holds the endpoint.
//!
//! Policy lives in user space (`userspace/services/power`); the kernel only
//! enforces limits (`azos_energy::policy`: the real-time deadline floor, the
//! safety path's WCET floor, the idle slack). So the setters answer with the
//! outcome and, when a kernel limit refused the value, the reason:
//!
//! * `OK` with value 0: applied;
//! * `REFUSED` with a `POLICY_REFUSED_*` value (`azos_abi::power`): refused
//!   by a kernel limit and recorded;
//! * any other outcome: the call itself failed (`DENIED`: the right is
//!   missing or the system is contained; `UNSUPPORTED`: no `energy` in the
//!   kernel; `BAD_ARGUMENT`).
//!
//! Observing ops need `READ`; every op that changes something needs `WRITE`.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "POWR").
pub const POWER_ID: u32 = 0x504F_5752;

#[azos_interface(id = 0x504F_5752, level = 1)]
pub trait Power {
    /// Orderly power-off. Does not return when served. Needs `WRITE`.
    fn shutdown(&mut self) -> Out<()>;
    /// Orderly reboot. Does not return when served. Needs `WRITE`.
    fn reboot(&mut self) -> Out<()>;
    /// Suspend until the next interrupt; answers after the resume. Needs `WRITE`.
    fn suspend(&mut self) -> Out<()>;
    /// The scheduler tick rate, Hz. Needs `READ`.
    #[idempotent]
    fn sched_hz(&self) -> Out<u64>;
    /// Set the scheduler tick rate (`POWER_SCHED_HZ_MIN..=POWER_SCHED_HZ_MAX`,
    /// else `BAD_ARGUMENT`). Needs `WRITE`.
    fn set_sched_hz(&mut self, hz: u64) -> Out<()>;
    /// Choose the governor: `POLICY_GOV_FIXED` or `POLICY_GOV_DEADLINE_FLOOR`.
    fn set_governor(&mut self, gov: u32) -> Out<u32>;
    /// Restrict domain `domain` to OPP indices `min..=max` (slowest first).
    fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> Out<u32>;
    /// Schedutil headroom, percent.
    fn set_headroom(&mut self, pct: u32) -> Out<u32>;
    /// Shortest interval between two governor evaluations, microseconds.
    fn set_rate_limit(&mut self, us: u32) -> Out<u32>;
    /// Deepest idle state the idle governor may pick; `POLICY_IDLE_UNLIMITED`
    /// lifts the limit.
    fn set_idle_depth(&mut self, depth: u32) -> Out<u32>;
    /// A policy state word (`POLICY_STATE_*`). Needs `READ`.
    #[idempotent]
    fn state(&self, sel: u32) -> Out<u64>;
    /// A policy statistics word (`POLICY_STATS_*`). Needs `READ`.
    #[idempotent]
    fn stats(&self, sel: u32) -> Out<u64>;
}
