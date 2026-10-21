// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PS/2 keyboard and mouse by interrupt (Kconfig `DRV_PS2`), x86_64.
//!
//! The i8042 driver (`azos_drv_input::ps2`) probes and brings up the
//! controller; this decides whether to look at all (the ACPI FADT's 8042
//! flag), routes the two ISA lines (IRQ1 keyboard, IRQ12 mouse, or the GSIs
//! the MADT overrides name) through the IOAPIC to the boot CPU, hands the
//! driver the lines and then lets the controller raise them. The x86 external
//! interrupt arm (`entry/x86_64/irq.rs`) calls `ps2::irq`, which turns key
//! presses into bytes in the console's RX ring and publishes the rest.
//! Nothing prints but one `[PS2]` line, either the lines or why not.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("feature `ps2` (Kconfig DRV_PS2) is x86_64 only: it depends on ARCH_X86_64");

#[cfg(target_arch = "x86_64")]
use crate::kprintln;

/// Probe and wire the PS/2 controller. A no-op (one boot line) on a machine
/// whose firmware says it has no 8042 or whose controller does not answer.
#[cfg(target_arch = "x86_64")]
pub(crate) fn wire_ps2_irq() {
    let p = azos_arch::platform_impl::platform();
    match p.acpi.fadt {
        Some(f) if f.has_8042() => {}
        Some(_) => {
            kprintln!("[PS2] the ACPI FADT reports no 8042: skipped");
            return;
        }
        None => {
            kprintln!("[PS2] no ACPI FADT to say there is an 8042: skipped");
            return;
        }
    }
    let (kbd, aux) = match azos_drv_input::ps2::init() {
        Ok(found) => found,
        Err(e) => {
            kprintln!("[PS2] {}: skipped", e.describe());
            return;
        }
    };
    // The handler must know the lines before the IOAPIC unmasks them, and
    // the controller must not raise one before it is routed.
    let kbd_line = if kbd { p.isa_irq(1) } else { (u32::MAX, false, false) };
    let aux_line = if aux { p.isa_irq(12) } else { (u32::MAX, false, false) };
    azos_drv_input::ps2::set_irq_lines(kbd_line.0, aux_line.0);
    let routed = |name: &str, (gsi, level, active_low): (u32, bool, bool)| {
        if gsi == u32::MAX {
            return;
        }
        if azos_arch::irq::ioapic::route(gsi, azos_arch::irq::apic::id(), level, active_low, false) {
            azos_drv_irqchip::user_irq::mark_kernel(gsi);
            kprintln!("[PS2] {} on GSI {} ({}, active-{})", name, gsi,
                      if level { "level" } else { "edge" }, if active_low { "low" } else { "high" });
        } else {
            kprintln!("[PS2] {} GSI {} not routable: idle", name, gsi);
        }
    };
    routed("keyboard", kbd_line);
    routed("mouse", aux_line);
    if let Err(e) = azos_drv_input::ps2::enable_irqs() {
        kprintln!("[PS2] interrupts not enabled ({}): idle", e.describe());
    }
}
