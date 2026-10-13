// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

pub mod spinlock;
pub mod qspinlock;
/// Per-task counts of the sleeping locks held (the panic policy's check).
pub mod held;
/// Ownership of a resource across a device wait (owner rule F1).
pub mod claim;
pub mod waitqueue;
/// Pure decision logic behind `preempt`. Host-tested in `tests/host/sync-tests`.
pub mod preempt_core;
pub mod preempt;
/// Per-hart interrupt-context depth — see the module docs.
pub mod isr_depth;
/// Lockdep-lite (Kconfig LOCKDEP, wave 15 N1) — see the module docs.
pub mod lockdep;
pub mod scope;
/// QSBR read-copy-update (Kconfig RCU_QSBR, wave 15 N4) — see the module docs.
pub mod qsbr;
/// Pure logic behind `qsbr`. Host-tested in `tests/host/sync-tests`.
pub mod qsbr_core;
pub mod pi_attr;
pub mod waitgraph;
pub mod kmutex;
pub mod pi_futex;

pub use spinlock::{SpinLock, SpinLockGuard, IrqSaveGuard, IrqsOffGuard};
pub use preempt::{critical_section, PreemptGuard};
pub use waitqueue::WaitQueue;
