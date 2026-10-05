// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

pub mod spinlock;
pub mod pi_mutex;
pub mod seqlock;
pub mod waitqueue;
pub mod completion;
/// Pure decision logic behind `preempt`. Host-tested in `tests/host/sync-tests`.
pub mod preempt_core;
pub mod preempt;
/// Per-hart interrupt-context depth — see the module docs.
pub mod isr_depth;

pub use spinlock::{SpinLock, SpinLockGuard, IrqSaveGuard};
pub use preempt::{critical_section, PreemptGuard};
pub use pi_mutex::PiMutex;
pub use seqlock::SeqLock;
pub use waitqueue::WaitQueue;
pub use completion::Completion;
