// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! `lx_emul`: the base of the Linux driver compatibility layer (stage L0).
//!
//! Unmodified Linux driver modules will run in a ring-3 AzOS server,
//! `lxsrv`, on top of this crate, which re-implements the behaviour of the
//! Linux kernel core APIs they call: memory allocation, locks, timers,
//! workqueues, RCU, printk, the device model, reference counts and the
//! exported-symbol table. No Linux source is copied; behaviour is matched
//! where drivers can observe it.
//!
//! Constraints that shape every module:
//!
//! * `no_std` and **no heap**: lxsrv has no global allocator yet, so every
//!   container is fixed-capacity, sized by const generics, and addressed by
//!   generation-checked handles instead of pointers. Running out of a
//!   capacity is an error that is returned and counted, never a panic.
//! * **One thread, cooperative** (see [`sched`]): Linux kernel threads,
//!   the workqueue worker and anything they call (probe included) are
//!   stackful tasks of one loop and give the hart up only at a block point
//!   (`msleep`, `wait_event`, a contended mutex, ...); timer, RCU and
//!   interrupt callbacks run to completion in atomic context. The server
//!   gives the stacks; the per-ISA switch is in `switch/`.
//! * **No global state**: [`sched::Env`] owns every subsystem and is passed
//!   explicitly, so tests are independent and the server decides where the
//!   state lives.
//! * Misuse that would hang or corrupt on Linux (double free, self
//!   deadlock, refcount wrap, synchronize_rcu in a read section, a stale
//!   handle) is detected, reported and counted, so a gate can assert the
//!   counters stay at zero.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

pub mod device;
pub mod errno;
pub mod kref;
pub mod lock;
pub mod mem;
pub mod printk;
pub mod rcu;
pub mod sched;
pub mod symbols;
mod switch;
pub mod timer;
pub mod workqueue;

pub use sched::Env;
