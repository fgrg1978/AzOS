// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the generic trap layer.
//!
//! What is real here, compiled from the kernel tree unmodified via `#[path]`:
//!
//!   * `kernel/src/trap/{frame,syscall,fault,irq}.rs`: the syscall flow and
//!     its prologue, the page-fault and exception policy, the fatal tail, the
//!     interrupt bracket, the tick's shared work and the reschedule gate;
//!   * `crates/core/sched/src/domain.rs`: the per-Domain entry counters and
//!     pledge mask the prologue calls;
//!   * `azos_abi::syscall_nr`: the case of each syscall number.
//!
//! What is faked (`fakes.rs`): the kernel itself (`trap/kernel.rs`: the
//! scheduler, the memory manager, the tracer, the console), as a `Services`
//! type that records what the policy asked of it, and three trap frames with
//! the register conventions of the three ISAs (number in a7 / x8 / rax, the
//! result register, whether the PC is stepped over the trap instruction, how
//! privilege and a write fault are encoded, which signal a cause earns).
//!
//! So a green run says: given these frames and this kernel, the one policy
//! behaves the same on every ISA's convention. It says nothing about the asm
//! that saves the frame, nor about the kernel types behind the services; the
//! boot rows (S6) carry those.

#[path = "../../../../crates/core/sched/src/domain.rs"]
pub mod domain;

/// `domain.rs` takes the table size from `crate::task`.
pub mod task {
    pub use azos_limits::MAX_TASKS;
}

pub mod trap;

#[cfg(test)]
mod fakes;

#[cfg(test)]
mod case_tests;
#[cfg(test)]
mod crashdump_tests;
#[cfg(test)]
mod fault_tests;
#[cfg(test)]
mod irq_tests;
#[cfg(test)]
mod pledge;
#[cfg(test)]
mod syscall_tests;
