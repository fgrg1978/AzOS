// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The three ISA glues, as the kernel sees them: `&dyn Hypervisor`.

use azos_arch_api::Hypervisor;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/ext/hv/mod.rs"]
pub mod rv;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/ext/hv/mod.rs"]
pub mod arm;

pub use azos_arch_x86_64::hv as x86;

/// Every implementation, by name: the fake first.
pub fn all() -> Vec<(&'static str, Box<dyn Hypervisor>)> {
    vec![
        ("fake", Box::new(crate::fakes::FakeHv::default())),
        ("riscv64", Box::new(rv::HvImpl)),
        ("aarch64", Box::new(arm::HvImpl)),
        ("x86_64", Box::new(x86::HvImpl)),
    ]
}

/// The three real ones.
pub fn real() -> Vec<(&'static str, Box<dyn Hypervisor>)> {
    all().into_iter().skip(1).collect()
}
