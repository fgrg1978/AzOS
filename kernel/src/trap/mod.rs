// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The generic trap layer (S2): what the kernel does when the hardware traps,
//! written once for riscv64, aarch64 and x86_64.
//!
//! | file        | policy                                                                     |
//! |-------------|----------------------------------------------------------------------------|
//! | `frame.rs`  | [`Frame`], the common view of a saved frame; the services traits           |
//! | `syscall.rs`| the syscall flow and its **prologue** (entry counters, pledge, tracepoint) |
//! | `fault.rs`  | page-fault policy, exception policy, the fatal tail                         |
//! | `irq.rs`    | the interrupt bracket, the tick's shared work, the reschedule point        |
//! | `kernel.rs` | [`Kernel`]: the services over the scheduler, memory manager, tracer         |
//! | `crash.rs`  | the minidump of a ring-3 task a fault killed (Kconfig `CRASHDUMP`)          |
//!
//! Each ISA's `entry/<isa>/` keeps the asm stub (`asm/trap_entry.S`, its CFI
//! landing pads included), the register-frame decode (`impl Frame` and
//! `impl ArchFrame` for its `TrapFrame`, in `trap.rs`), the cause decode that
//! classifies a trap, and the controller (`irq.rs`: claim, EOI, the line
//! ladder). `tools/lint/trap_lint.py` fails the build when dispatch logic (a
//! `match` on syscall numbers, the page-fault policy, the fatal tail) shows up
//! there again.
//!
//! The first four files name nothing outside `core` and `azos_abi`, so
//! `tests/host/trap-tests` compiles them unchanged against fake frames.

#[cfg(feature = "crashdump")]
mod crash;
pub mod frame;
pub mod fault;
pub mod irq;
pub mod kernel;
pub mod syscall;

pub use frame::{Frame, TrapClass};
pub(crate) use kernel::ArchFrame;
pub use kernel::{Kernel, RESCHED};
