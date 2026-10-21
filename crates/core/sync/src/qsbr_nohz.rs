// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which CPUs count their user mode as an extended quiescent state, with no
//! atomics and no hardware (a child of `qsbr`, pulled by path into
//! `tests/host/sync-tests`).
//!
//! A CPU that takes a periodic tick reports a quiescent state at the tick's
//! return to user mode, so a grace period never waits for it long. A CPU that
//! stops its tick (Kconfig NOHZ_FULL) takes no such report, and a task that
//! runs user code for seconds would hold every grace period for as long
//! (rule F5). Its user mode must therefore be quiescent by itself: the CPU
//! leaves the state at each kernel entry and enters it at each return to
//! user mode, whatever the tick is doing, and a waiter that finds it in user
//! mode owes it no wait.
//!
//! Two sets of CPUs have that treatment: the real-time CPUs of
//! RCU_NOCBS_CPUS (a build-time mask) and the CPUs the scheduler may run
//! tickless (the topology's `isolcpus`, known at boot). The second set is
//! not "the CPUs whose tick is stopped right now": that changes while the CPU
//! is in the kernel, between the entry guard of a trap and its return, and a
//! guard that entered with the rule off would return with it on and leave the
//! CPU "in the kernel" in user mode. The whole set pays the transitions
//! always, and the tick stops or runs under it freely.

/// Is user mode an extended quiescent state on `cpu`? `nocbs` is
/// RCU_NOCBS_CPUS, `tickless` the CPUs published by the scheduler
/// (`qsbr::set_tickless_cpus`).
#[inline(always)]
pub const fn user_is_eqs(nocbs: usize, tickless: u64, cpu: usize) -> bool {
    crate::qsbr_core::cpu_in_mask(nocbs, cpu) || crate::qsbr_core::cpu_in_mask(tickless as usize, cpu)
}
