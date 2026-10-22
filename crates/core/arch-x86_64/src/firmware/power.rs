// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Power-off and reset on x86_64, from what the FADT says.
//!
//! **Power-off is ACPI S5.** A PC platform writes `SLP_TYP << 10 | SLP_EN`
//! to its PM1a (and PM1b) control block; a hardware-reduced one (QEMU
//! microvm, some SoCs) writes `SLP_TYP << 2 | SLP_EN` to its sleep control
//! register. `SLP_TYP` is the first element of `\_S5` in the DSDT, read at
//! boot by [`acpi::find_s5`]; with none found ([`Refused::NoS5`]) the
//! power-off refuses rather than guess a value and the caller halts the CPU,
//! the machine left on. Before the PM1 write, a machine still in legacy mode
//! (SCI_EN clear) is handed to ACPI through SMI_CMD, as Linux does at boot.
//!
//! **Reset is a ladder**, each step tried after the last one did not reset
//! the machine: the FADT's RESET_REG (when the flags say it is implemented),
//! the 0xCF9 reset control port, the 8042's pulse-reset command (when the
//! FADT says there is an 8042), and the caller's triple fault.
//!
//! Pure over [`PowerIo`] (ports, memory, PCI configuration, a delay), so the
//! host tests (`tests/host/x86-platform-tests`) run the same sequences on a
//! recording machine; the kernel's `PowerIo` is the real instructions.

use super::acpi::{Fadt, Gas, FADT_HW_REDUCED, FADT_RESET_REG_SUP};

/// The machine as the power sequences touch it.
pub trait PowerIo {
    fn inb(&mut self, port: u16) -> u8;
    fn outb(&mut self, port: u16, v: u8);
    fn inw(&mut self, port: u16) -> u16;
    fn outw(&mut self, port: u16, v: u16);
    fn outl(&mut self, port: u16, v: u32);
    /// An 8-bit register in system memory, mapped by the kernel
    /// ([`for_each_mmio_register`]).
    fn write8(&mut self, pa: u64, v: u8);
    fn delay_us(&mut self, us: u64);
}

/// PM1 control: SCI_EN (bit 0), SLP_TYP (bits 12:10), SLP_EN (bit 13).
const PM1_SCI_EN: u16 = 1 << 0;
const PM1_SLP_TYP_SHIFT: u16 = 10;
const PM1_SLP_TYP: u16 = 7 << PM1_SLP_TYP_SHIFT;
const PM1_SLP_EN: u16 = 1 << 13;
/// Sleep control register: SLP_TYP (bits 4:2), SLP_EN (bit 5).
const SLEEP_CTL_SLP_TYP_SHIFT: u8 = 2;
const SLEEP_CTL_SLP_EN: u8 = 1 << 5;
/// How long a machine gets to turn SCI_EN on after ACPI_ENABLE (Linux's
/// `acpi_enable` waits as long), in 1 ms polls.
const SCI_EN_WAIT_MS: u64 = 3000;
/// How long each step gets to take the machine down before the next one.
const STEP_WAIT_US: u64 = 50_000;

/// The reset control register of the PC chipset (Intel PCH, AMD FCH):
/// bit 1 SYS_RST, bit 2 RST_CPU, bit 3 FULL_RST.
const CF9: u16 = 0xCF9;
const CF9_SYS_RST: u8 = 1 << 1;
const CF9_RESET: u8 = 0x0E;
/// The 8042: status (bit 1 input buffer full) and command port, and its
/// pulse-reset-line command.
const KBC_PORT: u16 = 0x64;
const KBC_IBF: u8 = 1 << 1;
const KBC_PULSE_RESET: u8 = 0xFE;
const KBC_WAIT_POLLS: u32 = 10_000;
/// PCI configuration mechanism #1 (a RESET_REG in PCI configuration space).
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Why the power-off did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No FADT was read: no ACPI, or a table the parser refused.
    NoFadt,
    /// The DSDT has no `\_S5` package the scan can read without AML.
    NoS5,
    /// The FADT names no register to write: no PM1a control block, or (on a
    /// hardware-reduced platform) no sleep control register.
    NoRegister,
    /// The register is in an address space this does not drive.
    Space(u8),
    /// The writes were made and the machine is still running.
    StillOn,
}

/// Write one of the FADT's 8-bit registers. `false`: a space this does
/// not drive (or no register).
fn write_gas8(io: &mut impl PowerIo, g: Gas, v: u8) -> bool {
    match g.space {
        _ if g.addr == 0 => false,
        Gas::MEMORY => {
            io.write8(g.addr, v);
            true
        }
        Gas::IO if g.addr <= 0xFFFF => {
            io.outb(g.addr as u16, v);
            true
        }
        // Bus 0 (ACPI 6.x §5.2.3.2): device bits 47:32, function 31:16,
        // register 15:0.
        Gas::PCI_CONFIG => {
            let (dev, func, reg) = ((g.addr >> 32) & 0x1F, (g.addr >> 16) & 0x7, g.addr & 0xFF);
            io.outl(PCI_CONFIG_ADDRESS, 1 << 31 | (dev as u32) << 11 | (func as u32) << 8 | (reg as u32 & 0xFC));
            io.outb(PCI_CONFIG_DATA + (reg as u16 & 3), v);
            true
        }
        _ => false,
    }
}

/// Enter S5 from `fadt`. Returns only when the machine did not power off,
/// with the reason; the caller halts.
pub fn power_off(fadt: Option<&Fadt>, io: &mut impl PowerIo) -> Refused {
    let Some(f) = fadt else { return Refused::NoFadt };
    let Some((typ_a, typ_b)) = f.s5 else { return Refused::NoS5 };
    if f.flags & FADT_HW_REDUCED != 0 {
        if f.sleep_ctl.addr == 0 {
            return Refused::NoRegister;
        }
        if !write_gas8(io, f.sleep_ctl, typ_a << SLEEP_CTL_SLP_TYP_SHIFT | SLEEP_CTL_SLP_EN) {
            return Refused::Space(f.sleep_ctl.space);
        }
    } else {
        if f.pm1a_cnt == 0 || f.pm1a_cnt > 0xFFFF {
            return Refused::NoRegister;
        }
        let a = f.pm1a_cnt as u16;
        let b = (f.pm1b_cnt != 0 && f.pm1b_cnt <= 0xFFFF).then_some(f.pm1b_cnt as u16);
        if io.inw(a) & PM1_SCI_EN == 0 && f.smi_cmd != 0 && f.smi_cmd <= 0xFFFF && f.acpi_enable != 0 {
            io.outb(f.smi_cmd as u16, f.acpi_enable);
            for _ in 0..SCI_EN_WAIT_MS {
                if io.inw(a) & PM1_SCI_EN != 0 {
                    break;
                }
                io.delay_us(1000);
            }
        }
        // As Linux's `acpi_hw_legacy_sleep`: SLP_TYP first, then SLP_EN,
        // each to PM1a then PM1b; the other bits as the machine has them.
        let typed = |cur: u16, typ: u8| cur & !(PM1_SLP_TYP | PM1_SLP_EN) | (typ as u16 & 7) << PM1_SLP_TYP_SHIFT;
        let va = typed(io.inw(a), typ_a);
        let vb = b.map(|b| (b, typed(io.inw(b), typ_b)));
        io.outw(a, va);
        if let Some((b, v)) = vb {
            io.outw(b, v);
        }
        io.outw(a, va | PM1_SLP_EN);
        if let Some((b, v)) = vb {
            io.outw(b, v | PM1_SLP_EN);
        }
    }
    io.delay_us(STEP_WAIT_US);
    Refused::StillOn
}

/// Run the reset ladder from `fadt`. Returns only when no step reset the
/// machine; the caller triple-faults.
pub fn reset(fadt: Option<&Fadt>, io: &mut impl PowerIo) {
    if let Some(f) = fadt.filter(|f| f.flags & FADT_RESET_REG_SUP != 0) {
        if write_gas8(io, f.reset, f.reset_value) {
            io.delay_us(STEP_WAIT_US);
        }
    }
    // As Linux's `reboot=pci`: SYS_RST alone, then the full reset with it.
    let cf9 = io.inb(CF9) & !CF9_RESET;
    io.outb(CF9, cf9 | CF9_SYS_RST);
    io.delay_us(50);
    io.outb(CF9, cf9 | CF9_RESET);
    io.delay_us(STEP_WAIT_US);
    // An ACPI 1.0 table, or none at all, describes a PC AT: the 8042 is there.
    if fadt.map_or(true, Fadt::has_8042) {
        for _ in 0..KBC_WAIT_POLLS {
            if io.inb(KBC_PORT) & KBC_IBF == 0 {
                break;
            }
            io.delay_us(10);
        }
        io.outb(KBC_PORT, KBC_PULSE_RESET);
        io.delay_us(STEP_WAIT_US);
    }
}

/// The FADT's registers in system memory (RESET_REG, SLEEP_CONTROL_REG):
/// the kernel maps their pages with its other device windows, so the
/// power-off and the reset can write them once the boot identity map is gone.
pub fn for_each_mmio_register(fadt: Option<&Fadt>, mut f: impl FnMut(u64)) {
    let Some(fadt) = fadt else { return };
    for g in [fadt.reset, fadt.sleep_ctl] {
        if g.space == Gas::MEMORY && g.addr != 0 {
            f(g.addr);
        }
    }
}
