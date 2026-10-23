// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86 power-off and reset (`firmware/power.rs`) and the `\_S5` scan
//! (`firmware/acpi.rs` `find_s5`) on a recording machine: which registers
//! are written, with what, in what order. The DSDT bytes are the AML the
//! firmware of each kind emits (QEMU's `build_dsdt` for pc/q35 and microvm,
//! the `Name (_S5, Package (0x04) { 0x05, Zero, ... })` of AMD/Intel boards).

use super::acpi::{self, Fadt, Gas, FADT_HW_REDUCED, FADT_RESET_REG_SUP};
use super::acpi_tests::sdt;
use super::power::{self, PowerIo, Refused};

// ── \_S5 ────────────────────────────────────────────────────────────────────

fn s5(body: &[u8]) -> Option<(u8, u8)> {
    acpi::find_s5(&sdt(b"DSDT", body))
}

/// `Name (_S5, Package (n) { ... })` with a one-byte PkgLength.
fn name_s5(elems: &[u8], n: u8) -> Vec<u8> {
    let mut b = vec![0x08, b'_', b'S', b'5', b'_', 0x12, (2 + elems.len()) as u8, n];
    b.extend_from_slice(elems);
    b
}

/// **Discriminates** each encoding the firmware in the field uses.
#[test]
fn s5_reads_the_plain_name_package() {
    // QEMU pc/q35: Package (0x04) { Zero, Zero, Zero, Zero }.
    assert_eq!(s5(&name_s5(&[0, 0, 0, 0], 4)), Some((0, 0)));
    // QEMU microvm: { 0x05 (BytePrefix), Zero, Zero, Zero }.
    assert_eq!(s5(&name_s5(&[0x0A, 5, 0, 0, 0], 4)), Some((5, 0)));
    // An Intel board: { 0x07, 0x07, Zero, Zero }; AMD: { 0x05, Zero }.
    assert_eq!(s5(&name_s5(&[0x0A, 7, 0x0A, 7, 0, 0], 4)), Some((7, 7)));
    assert_eq!(s5(&name_s5(&[0x0A, 5, 0], 2)), Some((5, 0)));
    // One (OneOp), a WordPrefix and a DWordPrefix constant.
    assert_eq!(s5(&name_s5(&[0x01, 0x0B, 3, 0], 2)), Some((1, 3)));
    assert_eq!(s5(&name_s5(&[0x0C, 6, 0, 0, 0], 1)), Some((6, 0)), "one element: SLP_TYPb 0");
    // The root-prefixed name: Name (\_S5, ...).
    let mut b = name_s5(&[0x0A, 5, 0], 2);
    b.insert(1, b'\\');
    assert_eq!(s5(&b), Some((5, 0)));
    // A two-byte PkgLength (lead byte bits 7:6 = 1), as a long package has.
    assert_eq!(s5(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x40 | 5, 0x00, 2, 0x0A, 5, 0]), Some((5, 0)));
    // Behind other AML: the scan finds it anywhere in the body.
    let mut b = vec![0x10, 0x05, b'_', b'S', b'B', b'_', 0x5B];
    b.extend(name_s5(&[0x0A, 5, 0], 2));
    assert_eq!(s5(&b), Some((5, 0)));
}

/// **Discriminates** the refusals: every shape that needs an interpreter is
/// `None`, never a value.
#[test]
fn s5_refuses_what_needs_aml() {
    // Method (_S5, 0) { Return (Package ...) }: MethodOp, not NameOp.
    assert_eq!(s5(&[0x14, 0x0A, b'_', b'S', b'5', b'_', 0x00, 0xA4, 0x12, 0x04, 0x02, 0x0A, 5, 0]), None);
    // The bytes in a string, not after a NameOp.
    assert_eq!(s5(&[0x0D, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0A, 5, 0]), None);
    // An element that is a name (Package () { SS5A, Zero }).
    assert_eq!(s5(&name_s5(&[b'S', b'S', b'5', b'A', 0], 2)), None);
    // DefVarPackage (0x13), an empty package, a value past SLP_TYP's 3 bits.
    let mut b = name_s5(&[0x0A, 5, 0], 2);
    b[5] = 0x13;
    assert_eq!(s5(&b), None);
    assert_eq!(s5(&name_s5(&[], 0)), None);
    assert_eq!(s5(&name_s5(&[0x0A, 8, 0], 2)), None);
    // Cut short anywhere: no value and no panic.
    let full = name_s5(&[0x0A, 5, 0x0A, 5], 2);
    for n in 0..full.len() {
        assert_eq!(s5(&full[..n]), None, "cut at {n}");
    }
    // No DSDT body at all.
    assert_eq!(acpi::find_s5(&[0; 20]), None);
    // A refused shape first, then the plain package: the plain one is read.
    let mut b = vec![0x14, 0x0A, b'_', b'S', b'5', b'_', 0x00, 0xA4];
    b.extend(name_s5(&[0x0A, 5, 0], 2));
    assert_eq!(s5(&b), Some((5, 0)));
}

// ── a recording machine ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Outb(u16, u8),
    Outw(u16, u16),
    Outl(u16, u32),
    Write8(u64, u8),
}

#[derive(Default)]
struct Machine {
    ops: Vec<Op>,
    /// What a PM1 control read returns; SCI_EN turns on once ACPI_ENABLE
    /// reaches `smi`, when `enables` is set.
    pm1: u16,
    smi: u16,
    enables: bool,
    /// Polls of the 8042 status that still say "input buffer full".
    kbc_busy: u32,
    delays: u64,
}

impl PowerIo for Machine {
    fn inb(&mut self, port: u16) -> u8 {
        if port == 0x64 && self.kbc_busy > 0 {
            self.kbc_busy -= 1;
            return 0x02;
        }
        if port == 0xCF9 { 0xF1 } else { 0 }
    }
    fn outb(&mut self, port: u16, v: u8) {
        if port == self.smi && self.enables {
            self.pm1 |= 1;
        }
        self.ops.push(Op::Outb(port, v));
    }
    fn inw(&mut self, _port: u16) -> u16 {
        self.pm1
    }
    fn outw(&mut self, port: u16, v: u16) {
        self.ops.push(Op::Outw(port, v));
    }
    fn outl(&mut self, port: u16, v: u32) {
        self.ops.push(Op::Outl(port, v));
    }
    fn write8(&mut self, pa: u64, v: u8) {
        self.ops.push(Op::Write8(pa, v));
    }
    fn delay_us(&mut self, us: u64) {
        self.delays += us;
    }
}

/// A q35-like FADT: PM1a at 0x604, SMI_CMD 0xB2 / ACPI_ENABLE 2, RESET_REG
/// I/O 0xCF9 = 6, an 8042.
fn q35() -> Fadt {
    Fadt {
        revision: 3,
        pm1a_cnt: 0x604,
        smi_cmd: 0xB2,
        acpi_enable: 2,
        iapc_boot_arch: 0b11,
        flags: FADT_RESET_REG_SUP,
        reset: Gas { space: Gas::IO, addr: 0xCF9 },
        reset_value: 6,
        s5: Some((0, 0)),
        ..Fadt::default()
    }
}

/// A microvm-like FADT: hardware-reduced, sleep control and RESET_REG in the
/// GED's memory window.
fn microvm() -> Fadt {
    Fadt {
        revision: 5,
        flags: FADT_HW_REDUCED | FADT_RESET_REG_SUP,
        sleep_ctl: Gas { space: Gas::MEMORY, addr: 0xFEA0_0000 },
        reset: Gas { space: Gas::MEMORY, addr: 0xFEA0_0002 },
        reset_value: 0x42,
        s5: Some((5, 0)),
        ..Fadt::default()
    }
}

// ── power-off ───────────────────────────────────────────────────────────────

/// **Discriminates** the PM1 sequence: SLP_TYP alone, then with SLP_EN; the
/// other bits of the register kept; PM1b written after PM1a in each phase.
#[test]
fn s5_on_a_pc_writes_slp_typ_then_slp_en() {
    let mut m = Machine { pm1: 1 | 0x1C00 | 0x0100, ..Machine::default() };
    let f = Fadt { pm1b_cnt: 0x684, s5: Some((5, 6)), ..q35() };
    assert_eq!(power::power_off(Some(&f), &mut m), Refused::StillOn);
    let a = 1 | 0x0100 | 5 << 10;
    let b = 1 | 0x0100 | 6 << 10;
    assert_eq!(m.ops, [Op::Outw(0x604, a), Op::Outw(0x684, b), Op::Outw(0x604, a | 1 << 13), Op::Outw(0x684, b | 1 << 13)]);
}

/// **Discriminates** the hand-over to ACPI mode: SCI_EN clear means
/// ACPI_ENABLE to SMI_CMD before the S5 write, and a machine that never
/// turns SCI_EN on is waited for a bounded time, not forever.
#[test]
fn s5_in_legacy_mode_enables_acpi_first() {
    let mut m = Machine { smi: 0xB2, enables: true, ..Machine::default() };
    power::power_off(Some(&q35()), &mut m);
    assert_eq!(m.ops[0], Op::Outb(0xB2, 2));
    assert_eq!(m.ops[1..], [Op::Outw(0x604, 1), Op::Outw(0x604, 1 | 1 << 13)]);
    // Already in ACPI mode: no SMI.
    let mut m = Machine { pm1: 1, smi: 0xB2, ..Machine::default() };
    power::power_off(Some(&q35()), &mut m);
    assert!(!m.ops.contains(&Op::Outb(0xB2, 2)));
    // SCI_EN never comes: about 3 s of polls, then the write all the same.
    let mut m = Machine { smi: 0xB2, ..Machine::default() };
    power::power_off(Some(&q35()), &mut m);
    assert!((3_000_000..=3_100_000).contains(&m.delays), "{} us", m.delays);
    assert_eq!(m.ops.last(), Some(&Op::Outw(0x604, 1 << 13)));
}

/// **Discriminates** the hardware-reduced path (microvm): the sleep control
/// register, SLP_TYP in bits 4:2, SLP_EN bit 5; never the PM1 port.
#[test]
fn s5_on_a_hardware_reduced_platform_writes_sleep_control() {
    let mut m = Machine::default();
    assert_eq!(power::power_off(Some(&microvm()), &mut m), Refused::StillOn);
    assert_eq!(m.ops, [Op::Write8(0xFEA0_0000, 5 << 2 | 1 << 5)]);
}

/// **Discriminates** the refusals: no FADT, no `\_S5`, no register, a space
/// not driven; each writes nothing.
#[test]
fn s5_refuses_without_a_sleep_type_or_a_register() {
    let refused = |f: Option<Fadt>| {
        let mut m = Machine::default();
        let r = power::power_off(f.as_ref(), &mut m);
        assert!(m.ops.is_empty(), "{r:?} wrote {:?}", m.ops);
        r
    };
    assert_eq!(refused(None), Refused::NoFadt);
    assert_eq!(refused(Some(Fadt { s5: None, ..q35() })), Refused::NoS5);
    assert_eq!(refused(Some(Fadt { pm1a_cnt: 0, ..q35() })), Refused::NoRegister);
    assert_eq!(refused(Some(Fadt { sleep_ctl: Gas::default(), ..microvm() })), Refused::NoRegister);
    assert_eq!(refused(Some(Fadt { sleep_ctl: Gas { space: 3, addr: 0x10 }, ..microvm() })), Refused::Space(3));
}

// ── reset ───────────────────────────────────────────────────────────────────

/// **Discriminates** the ladder's order: RESET_REG, then 0xCF9 (SYS_RST, then
/// the full reset, the other bits kept), then the 8042's pulse.
#[test]
fn reset_tries_reset_reg_then_cf9_then_the_8042() {
    let mut m = Machine::default();
    let f = Fadt { reset: Gas { space: Gas::IO, addr: 0x123 }, ..q35() };
    power::reset(Some(&f), &mut m);
    assert_eq!(m.ops, [Op::Outb(0x123, 6), Op::Outb(0xCF9, 0xF1 | 2), Op::Outb(0xCF9, 0xF1 | 0x0E), Op::Outb(0x64, 0xFE)]);
}

/// **Discriminates** what the FADT gates: RESET_REG only with RESET_REG_SUP,
/// the 8042 only where IAPC_BOOT_ARCH (or no FADT: a PC AT) says there is
/// one, RESET_REG in memory (microvm's GED) and in PCI configuration space.
#[test]
fn reset_follows_what_the_fadt_says() {
    let ops = |f: Option<Fadt>| {
        let mut m = Machine::default();
        power::reset(f.as_ref(), &mut m);
        m.ops
    };
    let cf9 = [Op::Outb(0xCF9, 0xF1 | 2), Op::Outb(0xCF9, 0xF1 | 0x0E)];
    assert_eq!(ops(Some(Fadt { flags: 0, ..q35() }))[..2], cf9, "RESET_REG_SUP clear: not written");
    assert_eq!(ops(None), [cf9[0], cf9[1], Op::Outb(0x64, 0xFE)], "no FADT: a PC AT");
    assert_eq!(ops(Some(microvm())), [Op::Write8(0xFEA0_0002, 0x42), cf9[0], cf9[1]], "no 8042");
    // PCI configuration space, bus 0 device 0x1F function 0 register 0x44.
    let pci = Fadt { reset: Gas { space: Gas::PCI_CONFIG, addr: 0x1F << 32 | 0x44 }, reset_value: 0x0E, ..q35() };
    assert_eq!(ops(Some(pci))[..2], [Op::Outl(0xCF8, 1 << 31 | 0x1F << 11 | 0x44), Op::Outb(0xCFC, 0x0E)]);
    // A space this does not drive: skipped, the ladder goes on.
    assert_eq!(ops(Some(Fadt { reset: Gas { space: 0x7F, addr: 1 }, ..q35() }))[..2], cf9);
}

/// The 8042 is given a bounded time to take the command.
#[test]
fn reset_waits_for_the_8042_input_buffer() {
    let mut m = Machine { kbc_busy: 3, ..Machine::default() };
    power::reset(None, &mut m);
    assert_eq!(m.ops.last(), Some(&Op::Outb(0x64, 0xFE)));
    assert_eq!(m.kbc_busy, 0);
    let mut m = Machine { kbc_busy: u32::MAX, ..Machine::default() };
    power::reset(None, &mut m);
    assert_eq!(m.ops.last(), Some(&Op::Outb(0x64, 0xFE)), "a stuck controller is still asked");
}

/// The registers the kernel maps for these sequences.
#[test]
fn the_memory_registers_are_the_ones_mapped() {
    let mut v = Vec::new();
    power::for_each_mmio_register(Some(&microvm()), |pa| v.push(pa));
    assert_eq!(v, [0xFEA0_0002, 0xFEA0_0000]);
    v.clear();
    power::for_each_mmio_register(Some(&q35()), |pa| v.push(pa));
    power::for_each_mmio_register(None, |pa| v.push(pa));
    assert!(v.is_empty());
}

/// The parser reads the fields these sequences use at their ACPI offsets.
#[test]
fn the_fadt_names_the_power_registers() {
    let mut t = sdt(b"FACP", &vec![0; 276 - 36]);
    t[8] = 6;
    t[40..44].copy_from_slice(&0x1000u32.to_le_bytes());
    t[48..52].copy_from_slice(&0xB2u32.to_le_bytes());
    t[52] = 0xA0;
    t[64..68].copy_from_slice(&0x404u32.to_le_bytes());
    t[68..72].copy_from_slice(&0x484u32.to_le_bytes());
    t[112..116].copy_from_slice(&(FADT_RESET_REG_SUP).to_le_bytes());
    t[116] = 1;
    t[120..128].copy_from_slice(&0xCF9u64.to_le_bytes());
    t[128] = 6;
    t[140..148].copy_from_slice(&0x2000u64.to_le_bytes());
    // X_PM1a_CNT_BLK in I/O wins; X_PM1b_CNT_BLK in memory does not.
    t[172] = 1;
    t[176..184].copy_from_slice(&0x1804u64.to_le_bytes());
    t[184] = 0;
    t[188..196].copy_from_slice(&0xFED0_0000u64.to_le_bytes());
    t[244] = 0;
    t[248..256].copy_from_slice(&0xFEA0_0000u64.to_le_bytes());
    super::acpi_tests::fix_checksum(&mut t);
    let f = acpi::parse_fadt(&t).unwrap();
    assert_eq!((f.smi_cmd, f.acpi_enable, f.pm1a_cnt, f.pm1b_cnt), (0xB2, 0xA0, 0x1804, 0x484));
    assert_eq!((f.reset, f.reset_value), (Gas { space: Gas::IO, addr: 0xCF9 }, 6));
    assert_eq!(f.sleep_ctl, Gas { space: Gas::MEMORY, addr: 0xFEA0_0000 });
    assert_eq!(f.dsdt, 0x2000, "X_DSDT wins");
    assert_eq!(f.s5, None, "filled by `parse` from the DSDT, not by the FADT");
    // An ACPI 1.0-sized table: the legacy DSDT field, no RESET_REG, no
    // sleep control.
    let f = acpi::parse_fadt(&t[..116]).unwrap();
    assert_eq!((f.dsdt, f.reset, f.sleep_ctl), (0x1000, Gas::default(), Gas::default()));
}

/// **Discriminates** the ports the boot reserves: PM1a/PM1b control (two
/// bytes each), the SMI command port, an I/O RESET_REG, 0xCF9 and the 8042
/// on a PC; on a hardware-reduced machine with a memory RESET_REG and no
/// 8042, only 0xCF9.
#[test]
fn the_power_ports_are_the_ones_reserved() {
    let mut got = Vec::new();
    let f = Fadt { pm1b_cnt: 0x684, ..q35() };
    power::for_each_io_port(Some(&f), |a, b| got.push((a, b)));
    assert_eq!(got, [(0x604, 0x605), (0x684, 0x685), (0xB2, 0xB2), (0xCF9, 0xCF9), (0xCF9, 0xCF9), (0x64, 0x64)]);
    got.clear();
    let m = Fadt { iapc_boot_arch: 0, ..microvm() };
    power::for_each_io_port(Some(&m), |a, b| got.push((a, b)));
    assert!(got.contains(&(0xCF9, 0xCF9)) && !got.iter().any(|&(a, _)| a == 0x64 || a == 0x604), "{got:?}");
}
