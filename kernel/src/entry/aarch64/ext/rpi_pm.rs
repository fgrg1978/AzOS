// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Raspberry Pi's PM block (kernel feature `wdt-bcm2835-pm`): the
//! hardware watchdog (`azos_drv_sys::wdt`) and the reset handler of a Pi whose
//! firmware has no PSCI. aarch64-only: the Pis are the only boards with the
//! block, and the reset handler is the arch layer's PSCI fallback
//! (`azos_arch::firmware::set_platform_reset`), which the other ISAs do not
//! need (riscv64 resets through SBI SRST, x86_64 through ACPI).

/// The `brcm,bcm2835-pm` node's probe, with its window mapped: the watchdog
/// takes the window and the arch layer the reset handler. Nothing is written
/// to the block here. `Err` when a block is attached already.
pub(crate) fn attach(base: usize) -> Result<(), azos_drv_base::window::Taken> {
    azos_drv_sys::wdt::pm_attach(base)?;
    azos_arch::firmware::set_platform_reset(azos_drv_sys::wdt::pm_reset);
    Ok(())
}
