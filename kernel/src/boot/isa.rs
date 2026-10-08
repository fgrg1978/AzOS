// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `[ISA]` boot line and the refusals (config/Kconfig.arch, "Hardware
//! support model"; `azos_arch_api::isa`). Each ISA's boot hooks resolve
//! their extensions and call [`report`] once.
//!
//! Written straight to the UART, byte by byte, with no console lock and no
//! atomic read-modify-write: aarch64 calls it before the first lock, where
//! a level above the CPU (e.g. `+lse` codegen on an Armv8.0 core) would
//! fault on the lock's first LSE instruction instead of printing why.

use azos_arch_api::isa::{self, Ext};
use core::fmt::Write;

/// The UART, unlocked.
struct Raw;

impl Write for Raw {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            azos_drv_sys::uart::putc(b);
        }
        Ok(())
    }
}

/// Print the refusal and power off (PSCI SYSTEM_OFF / SBI shutdown), so a
/// QEMU run ends with the message as its last line.
fn refuse(f: impl FnOnce(&mut Raw) -> core::fmt::Result) -> ! {
    let _ = f(&mut Raw);
    let _ = Raw.write_str("\n");
    azos_arch_api::Boot::shutdown(&azos_arch::ARCH)
}

/// The CPU is below the baseline level: `missing` names the first feature
/// of the level it lacks. Never returns. Brings the UART up itself: on
/// aarch64 this runs before `uart::init` (register writes only, no lock),
/// and a second init right before the power-off is harmless elsewhere.
pub(crate) fn refuse_level(level: &str, missing: &str) -> ! {
    azos_drv_sys::uart::init();
    refuse(|w| isa::write_level_refusal(w, level, missing))
}

/// Print `[ISA] baseline=<level> <ext>=<state> ...`; refuse to boot when a
/// `require`d extension is missing.
pub(crate) fn report(level: &str, exts: &[Ext]) {
    let _ = isa::write_report(&mut Raw, level, exts);
    let _ = Raw.write_str("\n");
    if let Some(e) = isa::first_missing(exts) {
        refuse(|w| isa::write_refusal(w, e));
    }
}
