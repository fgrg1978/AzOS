// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

pub mod spinlock;
pub mod pi_mutex;
/// Sleeping lock without priority inheritance (owner rule F1).
pub mod sleep_lock;
pub mod seqlock;
pub mod waitqueue;
pub mod completion;
/// Pure decision logic behind `preempt`. Host-tested in `tests/host/sync-tests`.
pub mod preempt_core;
pub mod preempt;
/// Per-hart interrupt-context depth — see the module docs.
pub mod isr_depth;
/// Lockdep-lite (Kconfig LOCKDEP, wave 15 N1) — see the module docs.
pub mod lockdep;
pub mod scope;

pub use spinlock::{SpinLock, SpinLockGuard, IrqSaveGuard};
pub use preempt::{critical_section, PreemptGuard};
pub use pi_mutex::PiMutex;
pub use sleep_lock::SleepLock;
pub use seqlock::SeqLock;
pub use waitqueue::WaitQueue;
pub use completion::Completion;
