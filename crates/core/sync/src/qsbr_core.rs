// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure decisions behind `qsbr` (Kconfig RCU_QSBR): how a CPU's
//! quiescent-state counter moves, and when a grace period has seen every
//! CPU quiescent. No atomics, no hardware: host-tested in
//! `tests/host/sync-tests`, the way `preempt_core` is.
//!
//! A counter is odd while its CPU runs kernel code (a read section may be
//! open there) and even while the CPU is in user mode or idle (an extended
//! quiescent state). Every transition changes it, so a counter that moved
//! since a grace period's snapshot belongs to a CPU that passed a
//! quiescent state.

/// A snapshot entry that is not waited for (the CPU was quiescent, offline,
/// or is the waiter's own). No counter reaches it.
pub const DONE: u64 = u64::MAX;

/// Whether a counter value is an extended quiescent state (user or idle).
#[inline(always)]
pub const fn quiescent(v: u64) -> bool {
    v & 1 == 0
}

/// Entering the kernel (a trap from user mode or from idle, the idle task's
/// wake): the new value, or `None` if the CPU already was in the kernel.
#[inline(always)]
pub const fn enter(v: u64) -> Option<u64> {
    if quiescent(v) { Some(v.wrapping_add(1)) } else { None }
}

/// Leaving the kernel for user mode or idle: the new value, or `None` if
/// the CPU already was quiescent.
#[inline(always)]
pub const fn leave(v: u64) -> Option<u64> {
    if quiescent(v) { None } else { Some(v.wrapping_add(1)) }
}

/// A context switch: +2 in the kernel (still odd, but moved); a CPU found
/// even (it should not be: a switch runs in the kernel) becomes odd.
#[inline(always)]
pub const fn switch(v: u64) -> u64 {
    if quiescent(v) { v.wrapping_add(1) } else { v.wrapping_add(2) }
}

/// What a grace period starting now records for a CPU whose counter is
/// `v`: [`DONE`] if it is quiescent (no reader there can hold anything
/// unpublished before now), else the value to see change.
#[inline(always)]
pub const fn snapshot(v: u64) -> u64 {
    if quiescent(v) { DONE } else { v }
}

/// Has a CPU snapshotted as `snap` passed a quiescent state, its counter
/// now being `now`?
#[inline(always)]
pub const fn passed(snap: u64, now: u64) -> bool {
    snap == DONE || now != snap
}

/// Is a grace period started at `start_ms` and still open at `now_ms` a
/// stall under `timeout_ms`?
#[inline(always)]
pub const fn stalled(start_ms: u64, now_ms: u64, timeout_ms: u64) -> bool {
    now_ms.wrapping_sub(start_ms) > timeout_ms
}

/// The callback CPU: the lowest of `0..n` that is possible (`possible(c)`)
/// and not in `nocbs` (bit c), or `None`.
pub fn callback_cpu(n: usize, nocbs: usize, possible: impl Fn(usize) -> bool) -> Option<usize> {
    (0..n.min(usize::BITS as usize)).find(|&c| possible(c) && nocbs & (1 << c) == 0)
}
