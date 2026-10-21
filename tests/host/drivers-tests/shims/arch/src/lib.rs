// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_arch`, re-exporting the **real** `mmu` module.
//!
//! Same reasoning as `tests/host/mm-tests/shims/arch`: the facade is
//! `target_arch`-gated, but `arch-riscv64/src/mmu.rs` is pure arithmetic, so
//! the driver under test computes with the kernel's own `PAGE_SIZE` rather
//! than a number this shim made up.
#[path = "../../../../../../crates/core/arch-riscv64/src/mmu.rs"]
pub mod mmu;

/// The contract's page geometry under its ISA-neutral name.
pub use mmu::{PAGE_SHIFT, PAGE_SIZE};

/// The calling CPU, as `azos_arch::Cpu` answers it: the host runs one.
pub trait Cpu {
    fn hart_id(&self) -> usize;
}

/// The host stand-in for the ISA facade `azos_arch::ARCH`.
pub struct Arch;

pub static ARCH: Arch = Arch;

impl Cpu for Arch {
    fn hart_id(&self) -> usize {
        0
    }
}
