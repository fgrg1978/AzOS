// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_drv_irqchip`.
//!
//! **WHY this exists.** `crates/core/ipc/src/irq_bind.rs`'s `irq_grant_cap`
//! (U03-2/U03-8) range-checks a PLIC line number against
//! `azos_drv_irqchip::plic::MAX_IRQS` before minting a `Cap<Irq>`. The real
//! `azos_drv_irqchip` is RV64-only (MMIO, `#[cfg(target_arch)]` register
//! layouts), so the `#[path]` host-test trick cannot pull it in. This crate
//! provides only the one constant that one function needs — not a general
//! driver shim, unlike `tests/host/topology-tests`' fuller one, because nothing
//! else `tests/host/ipc-lease-tests` pulls in touches a driver crate.
//!
//! The suite names it `azos_drv_irqchip` with `extern crate ... as` at its
//! root. The kernel never sees it.

pub mod plic {
    /// Mirrors `crates/drivers/irqchip/src/plic.rs`'s non-`k1` default (QEMU/VF2):
    /// the profile this host suite has no reason to vary by, since nothing
    /// here exercises the K1-specific PLIC line count.
    pub const MAX_IRQS: u32 = 128;
}
