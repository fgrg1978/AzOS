// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the hypervisor core (`crates/core/hv`) and of the three ISA
//! glues of `azos_arch_api::Hypervisor` (`arch/*/src/ext/hv/mod.rs`).
//!
//! The glues are the real files: riscv64's and aarch64's are pulled in by
//! path (their modules are pure and their CSR/instruction parts are
//! `cfg(target_arch)`), x86_64's is a module of its crate, which builds on the
//! host. Every stage-2 property is run against all three, plus a fake that
//! carries no tables, so a failure names the ISA.
//!
//! WHY. A wrong bit in a stage-2 entry is a guest that faults on its first
//! instruction with no message, and no guest runs before the guest-boot step
//! (QEMU `h=true`, `virtualization=on`, `svm=on`): these are the only check
//! until then.

#![cfg(test)]
#![allow(clippy::needless_range_loop)]

mod admission;
mod arm_enter;
mod exits;
mod fakes;
mod glue;
mod iface;
mod monitor;
mod pause;
mod psci;
mod rv_enter;
mod rv_plic;
mod sbi;
mod stage2;
mod vcpu;
mod vlapic;
mod vplic;
mod x86_enter;
mod x86_guest;
