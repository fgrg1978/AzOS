// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ACPI static tables, read-only: RSDP -> XSDT (or RSDT) -> MADT, HPET,
//! MCFG, FADT, DMAR, IVRS, PPTT. What x86 boot needs from firmware (the CPUs,
//! the IOAPICs and their interrupt source overrides, the HPET and PCIe ECAM
//! windows, the ACPI PM timer, the IOMMU units and the RAM their devices
//! use, and what the CPUs share) is in these tables; the DSDT's AML is not
//! interpreted.
//!
//! Pure: every table is read through [`PhysMem`], no allocation, fixed
//! capacities, so the host tests (`tests/host/x86-platform-tests`) run the
//! same code on synthetic tables. Every table's checksum and length are
//! checked before a field is read; a bad table is counted and skipped, not
//! trusted.

/// Physical memory as the parser sees it: `len` bytes at `pa`, or `None`
/// where nothing is mapped. The kernel's impl is the boot identity map.
pub trait PhysMem {
    fn read(&self, pa: u64, len: usize) -> Option<&[u8]>;
}

/// Capacities (the MADT can list more; extras are counted in `*_skipped`).
pub const MAX_LAPICS: usize = 256;
pub const MAX_IOAPICS: usize = 8;
pub const MAX_ISOS: usize = 16;
pub const MAX_LAPIC_NMIS: usize = 8;
pub const MAX_MCFG: usize = 4;
pub const MAX_TABLES: usize = 32;
/// IOMMU units and reserved/unity-mapped regions kept per table.
pub const MAX_IOMMUS: usize = 8;
pub const MAX_IOMMU_REGIONS: usize = 8;
/// No sane table is larger; a bigger length is a corrupt header.
pub const MAX_TABLE_LEN: usize = 1 << 20;

const SDT_HEADER_LEN: usize = 36;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    le32(b, o) as u64 | (le32(b, o + 4) as u64) << 32
}

/// The 8-bit sum ACPI requires to be zero.
pub fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcpiError {
    /// No "RSD PTR " at the given address, or none found by the scan.
    NoRsdp,
    /// The RSDP failed its checksum.
    BadRsdp,
    /// The XSDT/RSDT is unreadable or fails its checksum.
    BadRoot,
}

/// One CPU from the MADT (LAPIC or x2APIC entry, enabled).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Cpu {
    pub apic_id: u32,
    pub uid: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct IoApic {
    pub id: u8,
    pub addr: u64,
    pub gsi_base: u32,
}

/// An interrupt source override: ISA IRQ `source` arrives on `gsi`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Iso {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    /// MPS INTI flags: polarity bits 0-1 (01 high, 11 low), trigger 2-3
    /// (01 edge, 11 level); 00 = the bus default.
    pub flags: u16,
}

impl Iso {
    /// Active-low? (`None`: the bus default.)
    pub const fn active_low(&self) -> Option<bool> {
        match self.flags & 0b11 {
            0b01 => Some(false),
            0b11 => Some(true),
            _ => None,
        }
    }
    /// Level-triggered? (`None`: the bus default.)
    pub const fn level(&self) -> Option<bool> {
        match (self.flags >> 2) & 0b11 {
            0b01 => Some(false),
            0b11 => Some(true),
            _ => None,
        }
    }
}

/// A LAPIC NMI input: `uid` 0xFF / 0xFFFF_FFFF = every CPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LapicNmi {
    pub uid: u32,
    pub lint: u8,
    pub flags: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Madt {
    /// The LAPIC base (the header's, or the 64-bit override's).
    pub lapic_addr: u64,
    /// Bit 0 PCAT_COMPAT: dual 8259s present (to be masked).
    pub flags: u32,
    pub cpus: [Cpu; MAX_LAPICS],
    pub n_cpus: usize,
    pub cpus_skipped: usize,
    pub ioapics: [IoApic; MAX_IOAPICS],
    pub n_ioapics: usize,
    pub isos: [Iso; MAX_ISOS],
    pub n_isos: usize,
    pub nmis: [LapicNmi; MAX_LAPIC_NMIS],
    pub n_nmis: usize,
    /// Entries whose length field was short or ran past the table.
    pub malformed: usize,
}

impl Madt {
    pub const EMPTY: Madt = Madt {
        lapic_addr: 0,
        flags: 0,
        cpus: [Cpu { apic_id: 0, uid: 0 }; MAX_LAPICS],
        n_cpus: 0,
        cpus_skipped: 0,
        ioapics: [IoApic { id: 0, addr: 0, gsi_base: 0 }; MAX_IOAPICS],
        n_ioapics: 0,
        isos: [Iso { bus: 0, source: 0, gsi: 0, flags: 0 }; MAX_ISOS],
        n_isos: 0,
        nmis: [LapicNmi { uid: 0, lint: 0, flags: 0 }; MAX_LAPIC_NMIS],
        n_nmis: 0,
        malformed: 0,
    };

    pub fn cpus(&self) -> &[Cpu] {
        &self.cpus[..self.n_cpus]
    }
    pub fn ioapics(&self) -> &[IoApic] {
        &self.ioapics[..self.n_ioapics]
    }
    pub fn isos(&self) -> &[Iso] {
        &self.isos[..self.n_isos]
    }
    pub fn nmis(&self) -> &[LapicNmi] {
        &self.nmis[..self.n_nmis]
    }

    /// The override for ISA IRQ `irq`, if the firmware gave one.
    pub fn iso_for(&self, irq: u8) -> Option<Iso> {
        self.isos().iter().copied().find(|o| o.bus == 0 && o.source == irq)
    }

    fn add_cpu(&mut self, apic_id: u32, uid: u32) {
        if self.cpus().iter().any(|c| c.apic_id == apic_id) {
            return; // the same CPU as a LAPIC and an x2APIC entry
        }
        if self.n_cpus < MAX_LAPICS {
            self.cpus[self.n_cpus] = Cpu { apic_id, uid };
            self.n_cpus += 1;
        } else {
            self.cpus_skipped += 1;
        }
    }

    /// Move the CPU with `apic_id` (the boot CPU) to index 0, keeping the
    /// others in table order: index = the kernel's dense CPU number.
    /// `false` if the table does not list it.
    pub fn boot_cpu_first(&mut self, apic_id: u32) -> bool {
        let Some(i) = self.cpus().iter().position(|c| c.apic_id == apic_id) else {
            return false;
        };
        let bsp = self.cpus[i];
        let mut j = i;
        while j > 0 {
            self.cpus[j] = self.cpus[j - 1];
            j -= 1;
        }
        self.cpus[0] = bsp;
        true
    }
}

/// Parse a MADT ("APIC") body. The caller has checked the header.
pub fn parse_madt(t: &[u8], out: &mut Madt) {
    out.n_cpus = 0;
    out.cpus_skipped = 0;
    out.n_ioapics = 0;
    out.n_isos = 0;
    out.n_nmis = 0;
    out.malformed = 0;
    if t.len() < SDT_HEADER_LEN + 8 {
        out.malformed += 1;
        return;
    }
    out.lapic_addr = le32(t, 36) as u64;
    out.flags = le32(t, 40);
    let mut o = SDT_HEADER_LEN + 8;
    while o + 2 <= t.len() {
        let kind = t[o];
        let len = t[o + 1] as usize;
        if len < 2 || o + len > t.len() {
            out.malformed += 1;
            break;
        }
        let e = &t[o..o + len];
        match (kind, len) {
            // Processor Local APIC: uid, apic id, flags (enabled bit 0).
            (0, 8..) => {
                if le32(e, 4) & 1 != 0 {
                    out.add_cpu(e[3] as u32, e[2] as u32);
                }
            }
            // I/O APIC.
            (1, 12..) => {
                if out.n_ioapics < MAX_IOAPICS {
                    out.ioapics[out.n_ioapics] = IoApic { id: e[2], addr: le32(e, 4) as u64, gsi_base: le32(e, 8) };
                    out.n_ioapics += 1;
                }
            }
            // Interrupt Source Override.
            (2, 10..) => {
                if out.n_isos < MAX_ISOS {
                    out.isos[out.n_isos] = Iso { bus: e[2], source: e[3], gsi: le32(e, 4), flags: le16(e, 8) };
                    out.n_isos += 1;
                }
            }
            // Local APIC NMI: uid (0xFF all), flags, LINT#.
            (4, 6..) => {
                if out.n_nmis < MAX_LAPIC_NMIS {
                    let uid = if e[2] == 0xFF { u32::MAX } else { e[2] as u32 };
                    out.nmis[out.n_nmis] = LapicNmi { uid, flags: le16(e, 3), lint: e[5] };
                    out.n_nmis += 1;
                }
            }
            // Local APIC Address Override.
            (5, 12..) => out.lapic_addr = le64(e, 4),
            // Processor Local x2APIC: x2apic id, flags, uid.
            (9, 16..) => {
                if le32(e, 8) & 1 != 0 {
                    out.add_cpu(le32(e, 4), le32(e, 12));
                }
            }
            // Local x2APIC NMI: flags, uid, LINT#.
            (0xA, 12..) => {
                if out.n_nmis < MAX_LAPIC_NMIS {
                    out.nmis[out.n_nmis] = LapicNmi { uid: le32(e, 4), flags: le16(e, 2), lint: e[8] };
                    out.n_nmis += 1;
                }
            }
            (0 | 1 | 2 | 4 | 5 | 9 | 0xA, _) => out.malformed += 1,
            _ => {}
        }
        o += len;
    }
}

/// The HPET table: the event-timer block's MMIO base.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Hpet {
    pub addr: u64,
    pub number: u8,
    pub min_tick: u16,
}

pub fn parse_hpet(t: &[u8]) -> Option<Hpet> {
    if t.len() < 56 {
        return None;
    }
    // Base address GAS at 40: address space id 0 = system memory.
    if t[40] != 0 {
        return None;
    }
    let addr = le64(t, 44);
    if addr == 0 {
        return None;
    }
    Some(Hpet { addr, number: t[52], min_tick: le16(t, 53) })
}

/// One MCFG entry: the ECAM window of a PCI segment's bus range.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct McfgEntry {
    pub base: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

impl McfgEntry {
    /// The window's size: 1 MiB per bus.
    pub const fn size(&self) -> u64 {
        (self.bus_end as u64 - self.bus_start as u64 + 1) << 20
    }
}

/// Parse the MCFG's entries into `out`; returns how many.
pub fn parse_mcfg(t: &[u8], out: &mut [McfgEntry]) -> usize {
    let mut n = 0;
    let mut o = SDT_HEADER_LEN + 8;
    while o + 16 <= t.len() && n < out.len() {
        let e = McfgEntry { base: le64(t, o), segment: le16(t, o + 8), bus_start: t[o + 10], bus_end: t[o + 11] };
        if e.base != 0 && e.bus_end >= e.bus_start {
            out[n] = e;
            n += 1;
        }
        o += 16;
    }
    n
}

/// A register the FADT names through a Generic Address Structure, for the
/// 8-bit registers ACPI fixes the width of (RESET_REG, SLEEP_CONTROL_REG).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Gas {
    /// 0 system memory, 1 system I/O, 2 PCI configuration space.
    pub space: u8,
    /// 0 = no register.
    pub addr: u64,
}

impl Gas {
    pub const MEMORY: u8 = 0;
    pub const IO: u8 = 1;
    pub const PCI_CONFIG: u8 = 2;

    fn at(t: &[u8], o: usize) -> Gas {
        Gas { space: t[o], addr: le64(t, o + 4) }
    }
}

/// The FADT fields the platform uses: the reset register, the PM1 control
/// blocks and the sleep control register (S5 power-off), the SMI command
/// that turns ACPI mode on, the DSDT and the `\_S5` sleep types read from
/// it, and the boot-architecture flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fadt {
    /// The table's revision (header byte 8): IAPC_BOOT_ARCH exists from 2.
    pub revision: u8,
    /// PM1a/PM1b control blocks: I/O ports (X_PM1x_CNT_BLK when it names
    /// system I/O, else PM1x_CNT_BLK), 0 = none.
    pub pm1a_cnt: u32,
    pub pm1b_cnt: u32,
    /// SMI_CMD and ACPI_ENABLE: the write that hands the fixed hardware to
    /// the OS (SCI_EN) on a machine still in legacy mode; 0 = none.
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    /// IAPC_BOOT_ARCH: bit 0 legacy devices, bit 1 8042, bit 5 no CMOS RTC.
    /// 0 when the table is too old (revision < 2) or too short to carry it.
    pub iapc_boot_arch: u16,
    /// CENTURY: the CMOS RAM index of the RTC's century register, 0 = the
    /// RTC has none.
    pub century: u8,
    /// Fixed feature flags: bit 10 RESET_REG_SUP, bit 20 HW_REDUCED_ACPI.
    pub flags: u32,
    /// RESET_REG and the value written to it.
    pub reset: Gas,
    pub reset_value: u8,
    /// SLEEP_CONTROL_REG (ACPI 5.0+): how a hardware-reduced platform,
    /// which has no PM1 blocks, enters a sleep state.
    pub sleep_ctl: Gas,
    /// The DSDT's physical address (X_DSDT when set, else DSDT), 0 = none.
    pub dsdt: u64,
    /// `\_S5`'s SLP_TYPa / SLP_TYPb, read from the DSDT by [`find_s5`]
    /// (`parse` fills it); `None` when the DSDT has no plain `\_S5` package.
    pub s5: Option<(u8, u8)>,
    /// The ACPI PM timer's I/O port (X_PM_TMR_BLK when it is system I/O,
    /// else PM_TMR_BLK), 0 = none. A 3.579545 MHz counter that runs in
    /// every C-state: the calibration reference of last resort.
    pub pm_tmr_port: u16,
    /// FADT flag TMR_VAL_EXT (bit 8): the counter is 32 bits, else 24.
    pub pm_tmr_wide: bool,
}

impl Fadt {
    /// Does the firmware say the machine has a port 0x60/0x64 keyboard
    /// controller (an i8042 or equivalent)? IAPC_BOOT_ARCH bit 1, from
    /// revision 2 on; a hardware-reduced platform (`flags` bit 20) has no
    /// legacy devices at all. An older table (ACPI 1.0) has no such field and
    /// describes a PC AT, where the controller is part of the machine.
    pub const fn has_8042(&self) -> bool {
        if self.flags & FADT_HW_REDUCED != 0 {
            return false;
        }
        self.revision < 2 || self.iapc_boot_arch & 0b10 != 0
    }

    /// Does the firmware say there is no CMOS RTC at ports 0x70/0x71?
    /// IAPC_BOOT_ARCH bit 5 (ACPI 5.0A), the one flag Linux reads for it.
    pub const fn no_cmos_rtc(&self) -> bool {
        self.iapc_boot_arch & FADT_BOOT_NO_CMOS_RTC != 0
    }

    /// The century register, when CENTURY names one the index port reaches:
    /// past the clock and status registers (0x00..=0x0D) and below 0x80
    /// (index bit 7 is the NMI mask). Anything else is no century register.
    pub const fn century_register(&self) -> Option<u8> {
        match self.century {
            c @ 0x0E..=0x7F => Some(c),
            _ => None,
        }
    }
}

/// IAPC_BOOT_ARCH bit 5: CMOS RTC Not Present.
pub const FADT_BOOT_NO_CMOS_RTC: u16 = 1 << 5;

/// FADT flag RESET_REG_SUP: RESET_REG is implemented.
pub const FADT_RESET_REG_SUP: u32 = 1 << 10;
/// FADT flag HW_REDUCED_ACPI: no PM1 blocks, no legacy devices.
pub const FADT_HW_REDUCED: u32 = 1 << 20;

pub fn parse_fadt(t: &[u8]) -> Option<Fadt> {
    if t.len() < 116 {
        return None;
    }
    let mut f = Fadt {
        revision: t[8],
        dsdt: le32(t, 40) as u64,
        smi_cmd: le32(t, 48),
        acpi_enable: t[52],
        pm1a_cnt: le32(t, 64),
        pm1b_cnt: le32(t, 68),
        flags: le32(t, 112),
        ..Fadt::default()
    };
    // CENTURY @108 is an ACPI 1.0 field: 0 where there is none.
    f.century = t[108];
    if f.revision >= 2 && t.len() >= 111 {
        f.iapc_boot_arch = le16(t, 109);
    }
    if t.len() >= 129 {
        f.reset = Gas::at(t, 116);
        f.reset_value = t[128];
    }
    // X_DSDT @140 (ACPI 2.0+) wins when set.
    if t.len() >= 148 && le64(t, 140) != 0 {
        f.dsdt = le64(t, 140);
    }
    // X_PM1a_CNT_BLK @172, X_PM1b_CNT_BLK @184: a system-I/O block wins over
    // the legacy port; one in memory is a block this does not drive, and the
    // legacy field stays.
    for (o, port) in [(172, &mut f.pm1a_cnt), (184, &mut f.pm1b_cnt)] {
        if t.len() >= o + 12 {
            let g = Gas::at(t, o);
            if g.space == Gas::IO && g.addr != 0 && g.addr <= 0xFFFF {
                *port = g.addr as u32;
            }
        }
    }
    // SLEEP_CONTROL_REG @244 (ACPI 5.0+).
    if t.len() >= 256 {
        f.sleep_ctl = Gas::at(t, 244);
    }
    f.pm_tmr_wide = f.flags & (1 << 8) != 0;
    // PM_TMR_BLK @76 (I/O port), PM_TMR_LEN @91 (4 when the timer exists).
    if t.len() > 91 && t[91] == 4 {
        let blk = le32(t, 76);
        if blk != 0 && blk <= 0xFFFF {
            f.pm_tmr_port = blk as u16;
        }
    }
    // X_PM_TMR_BLK (GAS @208, ACPI 3.0+) wins when it names system I/O; one
    // that names memory (a hardware-reduced platform) is a timer this reads
    // no way, and the legacy field is not trusted past it.
    if t.len() >= 220 && le64(t, 212) != 0 {
        f.pm_tmr_port = if t[208] == 1 && le64(t, 212) <= 0xFFFF { le64(t, 212) as u16 } else { 0 };
    }
    Some(f)
}

// ── \_S5 without an AML interpreter ────────────────────────────────────────

/// AML opcodes the `\_S5` scan reads (ACPI 6.x §20.2).
const AML_ZERO: u8 = 0x00;
const AML_ONE: u8 = 0x01;
const AML_NAME: u8 = 0x08;
const AML_BYTE: u8 = 0x0A;
const AML_WORD: u8 = 0x0B;
const AML_DWORD: u8 = 0x0C;
const AML_QWORD: u8 = 0x0E;
const AML_PACKAGE: u8 = 0x12;
const AML_ROOT: u8 = b'\\';

/// SLP_TYPa / SLP_TYPb of `\_S5` from the DSDT's bytes (the table, header
/// included), without an AML interpreter: the first `Name (_S5, Package
/// (n) { a, b, ... })` whose elements are integer constants, the shape every
/// firmware this targets emits (QEMU's `{ 0, 0, 0, 0 }` on pc/q35, `{ 5, ...}`
/// on microvm, AMD and Intel boards' `{ 0x05, Zero, ... }` / `{ 0x07, ... }`).
/// A package built at run time (a `Method`, a `DefVarPackage`, an element
/// that is a name) is `None`: reading it takes an interpreter, and the
/// caller refuses S5 rather than guess a value. Values past the 3 bits of
/// SLP_TYP are refused too. Where an `If` declares `_S5` in both arms the
/// first arm's wins: the scan does not evaluate the predicate.
pub fn find_s5(dsdt: &[u8]) -> Option<(u8, u8)> {
    let body = dsdt.get(SDT_HEADER_LEN..)?;
    let mut i = 0;
    while i + 4 <= body.len() {
        if &body[i..i + 4] == b"_S5_" {
            let named = match i {
                0 => false,
                1 => body[0] == AML_NAME,
                _ => body[i - 1] == AML_NAME || (body[i - 1] == AML_ROOT && body[i - 2] == AML_NAME),
            };
            if named {
                if let Some(v) = s5_package(&body[i + 4..]) {
                    return Some(v);
                }
            }
        }
        i += 1;
    }
    None
}

/// `PackageOp PkgLength NumElements a b ...` right after the name.
fn s5_package(b: &[u8]) -> Option<(u8, u8)> {
    if *b.first()? != AML_PACKAGE {
        return None;
    }
    // PkgLength: bits 7:6 of the lead byte count the bytes that follow it.
    let extra = (*b.get(1)? >> 6) as usize;
    let mut o = 2 + extra;
    let n = *b.get(o)?;
    o += 1;
    if n == 0 {
        return None;
    }
    let mut ints = [0u64; 2];
    for slot in ints.iter_mut().take((n as usize).min(2)) {
        let (v, len) = aml_integer(b.get(o..)?)?;
        *slot = v;
        o += len;
    }
    if ints.iter().any(|&v| v > 7) {
        return None;
    }
    Some((ints[0] as u8, ints[1] as u8))
}

/// An AML integer constant: its value and its length in bytes.
fn aml_integer(b: &[u8]) -> Option<(u64, usize)> {
    let width = match *b.first()? {
        AML_ZERO => return Some((0, 1)),
        AML_ONE => return Some((1, 1)),
        AML_BYTE => 1,
        AML_WORD => 2,
        AML_DWORD => 4,
        AML_QWORD => 8,
        _ => return None,
    };
    let v = b.get(1..1 + width)?.iter().rev().fold(0u64, |a, &x| a << 8 | x as u64);
    Some((v, 1 + width))
}

/// One DMAR remapping hardware unit (DRHD): an Intel VT-d register window.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Drhd {
    pub segment: u16,
    pub base: u64,
    /// The register window's size, from the DRHD's size field (4 KiB << n).
    pub size: u64,
    /// Flags bit 0: this unit covers every device of its segment not named
    /// by another unit's scope.
    pub include_all: bool,
}

/// A region some device DMAs to while the OS runs (a DMAR RMRR, an IVRS
/// IVMD): RAM the PMM must not hand out, `[base, base + len)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DmaRegion {
    pub segment: u16,
    pub base: u64,
    pub len: u64,
}

/// The DMAR table (Intel VT-d).
#[derive(Clone, Copy, Debug)]
pub struct Dmar {
    /// Host address width minus one, as the table gives it.
    pub host_addr_width: u8,
    /// Flags bit 0 INTR_REMAP, bit 1 X2APIC_OPT_OUT, bit 2
    /// DMA_CTRL_PLATFORM_OPT_IN.
    pub flags: u8,
    pub units: [Drhd; MAX_IOMMUS],
    pub n_units: usize,
    /// Reserved Memory Region Reporting structures.
    pub rmrr: [DmaRegion; MAX_IOMMU_REGIONS],
    pub n_rmrr: usize,
    /// Units or regions past the capacities, and structures that were short.
    pub skipped: usize,
    pub malformed: usize,
}

impl Dmar {
    pub const EMPTY: Dmar = Dmar {
        host_addr_width: 0,
        flags: 0,
        units: [Drhd { segment: 0, base: 0, size: 0, include_all: false }; MAX_IOMMUS],
        n_units: 0,
        rmrr: [DmaRegion { segment: 0, base: 0, len: 0 }; MAX_IOMMU_REGIONS],
        n_rmrr: 0,
        skipped: 0,
        malformed: 0,
    };
    pub fn units(&self) -> &[Drhd] {
        &self.units[..self.n_units]
    }
    pub fn rmrr(&self) -> &[DmaRegion] {
        &self.rmrr[..self.n_rmrr]
    }
    pub const fn intr_remap(&self) -> bool {
        self.flags & 1 != 0
    }
    /// The register base of the unit that covers PCI segment 0: the DRHD with
    /// INCLUDE_PCI_ALL on segment 0, else the first DRHD on segment 0.
    pub fn segment0_unit(&self) -> Option<u64> {
        let on0 = || self.units().iter().filter(|u| u.segment == 0 && u.base != 0);
        on0().find(|u| u.include_all).or_else(|| on0().next()).map(|u| u.base)
    }
}

/// Parse a DMAR body (36-byte header, host address width, flags, 10
/// reserved bytes, then remapping structures of type/length).
pub fn parse_dmar(t: &[u8], out: &mut Dmar) {
    *out = Dmar::EMPTY;
    if t.len() < SDT_HEADER_LEN + 12 {
        out.malformed += 1;
        return;
    }
    out.host_addr_width = t[36];
    out.flags = t[37];
    let mut o = SDT_HEADER_LEN + 12;
    while o + 4 <= t.len() {
        let kind = le16(t, o);
        let len = le16(t, o + 2) as usize;
        if len < 4 || o + len > t.len() {
            out.malformed += 1;
            break;
        }
        let e = &t[o..o + len];
        match (kind, len) {
            // DRHD: flags @4, size @5 (log2 of 4 KiB pages, minus 0), segment @6, base @8.
            (0, 16..) => {
                if out.n_units < MAX_IOMMUS {
                    out.units[out.n_units] = Drhd {
                        segment: le16(e, 6),
                        base: le64(e, 8),
                        size: 4096u64 << (e[5] & 0x1F),
                        include_all: e[4] & 1 != 0,
                    };
                    out.n_units += 1;
                } else {
                    out.skipped += 1;
                }
            }
            // RMRR: segment @6, base @8, limit @16 (inclusive).
            (1, 24..) => {
                let (base, limit) = (le64(e, 8), le64(e, 16));
                if limit < base {
                    out.malformed += 1;
                } else if out.n_rmrr < MAX_IOMMU_REGIONS {
                    out.rmrr[out.n_rmrr] = DmaRegion { segment: le16(e, 6), base, len: limit - base + 1 };
                    out.n_rmrr += 1;
                } else {
                    out.skipped += 1;
                }
            }
            (0 | 1, _) => out.malformed += 1,
            // ATSR, RHSA, ANDD, SATC, SIDP: not read.
            _ => {}
        }
        o += len;
    }
}

/// One IVRS I/O virtualization hardware definition (IVHD): an AMD-Vi unit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Ivhd {
    /// Block type: 0x10, or 0x11 / 0x40 (with the extended feature image).
    pub kind: u8,
    pub flags: u8,
    /// The unit's PCI function (bus:device.function).
    pub device_id: u16,
    pub segment: u16,
    /// The MMIO control-register base.
    pub base: u64,
    /// The extended feature register image (types 0x11 and 0x40), else 0.
    pub efr: u64,
}

/// The IVRS table (AMD-Vi).
#[derive(Clone, Copy, Debug)]
pub struct Ivrs {
    /// IVinfo: bits 21:15 VASize, 14:8 PASize, 0 EFRSup.
    pub info: u32,
    pub units: [Ivhd; MAX_IOMMUS],
    pub n_units: usize,
    /// IVMD memory definitions: RAM devices use unity-mapped.
    pub ivmd: [DmaRegion; MAX_IOMMU_REGIONS],
    pub n_ivmd: usize,
    pub skipped: usize,
    pub malformed: usize,
}

impl Ivrs {
    pub const EMPTY: Ivrs = Ivrs {
        info: 0,
        units: [Ivhd { kind: 0, flags: 0, device_id: 0, segment: 0, base: 0, efr: 0 }; MAX_IOMMUS],
        n_units: 0,
        ivmd: [DmaRegion { segment: 0, base: 0, len: 0 }; MAX_IOMMU_REGIONS],
        n_ivmd: 0,
        skipped: 0,
        malformed: 0,
    };
    pub fn units(&self) -> &[Ivhd] {
        &self.units[..self.n_units]
    }
    pub fn ivmd(&self) -> &[DmaRegion] {
        &self.ivmd[..self.n_ivmd]
    }
    /// The register base of the first AMD-Vi unit on PCI segment 0.
    pub fn segment0_unit(&self) -> Option<u64> {
        self.units().iter().find(|u| u.segment == 0 && u.base != 0).map(|u| u.base)
    }
}

/// Parse an IVRS body (36-byte header, IVinfo, 8 reserved bytes, then IVHD
/// and IVMD blocks of type/flags/length).
pub fn parse_ivrs(t: &[u8], out: &mut Ivrs) {
    *out = Ivrs::EMPTY;
    if t.len() < SDT_HEADER_LEN + 12 {
        out.malformed += 1;
        return;
    }
    out.info = le32(t, 36);
    let mut o = SDT_HEADER_LEN + 12;
    while o + 4 <= t.len() {
        let kind = t[o];
        let len = le16(t, o + 2) as usize;
        if len < 4 || o + len > t.len() {
            out.malformed += 1;
            break;
        }
        let e = &t[o..o + len];
        match (kind, len) {
            // IVHD 0x10: device id @4, base @8, segment @16. 0x11 and 0x40
            // carry the extended feature register at @24.
            (0x10, 24..) | (0x11 | 0x40, 40..) => {
                if out.n_units < MAX_IOMMUS {
                    out.units[out.n_units] = Ivhd {
                        kind,
                        flags: e[1],
                        device_id: le16(e, 4),
                        segment: le16(e, 16),
                        base: le64(e, 8),
                        efr: if kind == 0x10 { 0 } else { le64(e, 24) },
                    };
                    out.n_units += 1;
                } else {
                    out.skipped += 1;
                }
            }
            // IVMD 0x20 (all), 0x21 (select), 0x22 (range): start @16, length @24.
            (0x20..=0x22, 32..) => {
                if out.n_ivmd < MAX_IOMMU_REGIONS {
                    out.ivmd[out.n_ivmd] = DmaRegion { segment: 0, base: le64(e, 16), len: le64(e, 24) };
                    out.n_ivmd += 1;
                } else {
                    out.skipped += 1;
                }
            }
            (0x10 | 0x11 | 0x40 | 0x20..=0x22, _) => out.malformed += 1,
            _ => {}
        }
        o += len;
    }
}

// ---------------------------------------------------------------
// PPTT: the processor topology (what shares a core, a cluster, a cache)
// ---------------------------------------------------------------

/// Processors a [`Pptt`] keeps (the MADT's ceiling).
pub const MAX_PPTT_CPUS: usize = MAX_LAPICS;

/// A level the PPTT does not give.
pub const PPTT_NONE: u32 = u32::MAX;

/// Deepest chain of parents, and of next-level caches, followed.
const PPTT_DEPTH: usize = 16;

/// Processor-hierarchy flags (ACPI 6.4 table 5.158).
const PPTT_PACKAGE: u32 = 1 << 0;
const PPTT_UID_VALID: u32 = 1 << 1;
const PPTT_THREAD: u32 = 1 << 2;

/// One processor of the PPTT, as the labels `azos_sched::topo` compares. A
/// label is the table offset of the node that groups the processors, so it is
/// unique across the whole table; [`PPTT_NONE`] when the table has no such
/// node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PpttCpu {
    /// The ACPI processor id, which the MADT's entry for the CPU also carries
    /// (`Cpu::uid`).
    pub uid: u32,
    /// The core: the leaf itself, or its parent when the leaf is a thread.
    pub core: u32,
    /// The node that holds the core, when it is not the package: the cluster.
    pub cluster: u32,
    /// The last-level cache: the end of the next-level chain of the caches of
    /// the outermost node that has any.
    pub llc: u32,
    /// The nearest node flagged as a physical package.
    pub package: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Pptt {
    pub cpus: [PpttCpu; MAX_PPTT_CPUS],
    pub n_cpus: usize,
    /// Leaf processors past [`MAX_PPTT_CPUS`].
    pub cpus_skipped: usize,
    /// Structures whose length was short or ran past the table.
    pub malformed: usize,
}

impl Pptt {
    pub const EMPTY: Pptt = Pptt {
        cpus: [PpttCpu { uid: 0, core: PPTT_NONE, cluster: PPTT_NONE, llc: PPTT_NONE, package: PPTT_NONE };
            MAX_PPTT_CPUS],
        n_cpus: 0,
        cpus_skipped: 0,
        malformed: 0,
    };

    pub fn cpus(&self) -> &[PpttCpu] {
        &self.cpus[..self.n_cpus]
    }

    /// The processor with ACPI processor id `uid`.
    pub fn for_uid(&self, uid: u32) -> Option<PpttCpu> {
        self.cpus().iter().copied().find(|c| c.uid == uid)
    }
}

/// A processor hierarchy node (type 0) at `off`: its flags, parent, ACPI id
/// and the offsets of its private resources.
struct PpttNode<'a> {
    flags: u32,
    parent: u32,
    uid: u32,
    resources: &'a [u8],
}

fn pptt_node(t: &[u8], off: u32) -> Option<PpttNode<'_>> {
    let o = off as usize;
    if o < SDT_HEADER_LEN || o + 20 > t.len() || t[o] != 0 {
        return None;
    }
    let len = t[o + 1] as usize;
    let n = le32(t, o + 16) as usize;
    if len < 20 || o + len > t.len() || n.checked_mul(4)? > len - 20 {
        return None;
    }
    Some(PpttNode {
        flags: le32(t, o + 4),
        parent: le32(t, o + 8),
        uid: le32(t, o + 12),
        resources: &t[o + 20..o + 20 + 4 * n],
    })
}

/// The cache structure (type 1) at `off`: its next level, 0 for none.
fn pptt_cache_next(t: &[u8], off: u32) -> Option<u32> {
    let o = off as usize;
    if o < SDT_HEADER_LEN || o + 12 > t.len() || t[o] != 1 || (t[o + 1] as usize) < 12 || o + t[o + 1] as usize > t.len() {
        return None;
    }
    Some(le32(t, o + 8))
}

/// The last cache of the longest next-level chain among `node`'s private
/// resources: `(chain length, offset)`.
fn pptt_last_cache(t: &[u8], node: &PpttNode<'_>) -> Option<(usize, u32)> {
    let mut best: Option<(usize, u32)> = None;
    for r in node.resources.chunks_exact(4) {
        let mut cur = le32(r, 0);
        let mut len = 0;
        while let Some(next) = pptt_cache_next(t, cur) {
            len += 1;
            if next == 0 || len >= PPTT_DEPTH {
                break;
            }
            cur = next;
        }
        if len != 0 && best.map_or(true, |(l, _)| len > l) {
            best = Some((len, cur));
        }
    }
    best
}

/// Parse a PPTT. The caller has checked the header.
///
/// A processor is a leaf of the hierarchy (no node names it as its parent)
/// whose "ACPI processor id valid" flag is set. Walking up from it gives the
/// labels of [`PpttCpu`]. Where the table nests clusters, the innermost one
/// (the parent of the core) is the cluster.
pub fn parse_pptt(t: &[u8], out: &mut Pptt) {
    out.n_cpus = 0;
    out.cpus_skipped = 0;
    out.malformed = 0;
    let mut o = SDT_HEADER_LEN; // the structures follow the header
    // Every offset of a processor node, for the parent test.
    let is_parent = |off: u32| -> bool {
        let mut p = SDT_HEADER_LEN;
        while p + 2 <= t.len() {
            let len = t[p + 1] as usize;
            if len < 4 || p + len > t.len() {
                return false;
            }
            if t[p] == 0 && len >= 12 && le32(t, p + 8) == off {
                return true;
            }
            p += len;
        }
        false
    };
    while o + 2 <= t.len() {
        let len = t[o + 1] as usize;
        if len < 4 || o + len > t.len() {
            out.malformed += 1;
            break;
        }
        if t[o] == 0 {
            let Some(leaf) = pptt_node(t, o as u32) else {
                out.malformed += 1;
                o += len;
                continue;
            };
            if leaf.flags & PPTT_UID_VALID != 0 && !is_parent(o as u32) {
                if out.n_cpus == MAX_PPTT_CPUS {
                    out.cpus_skipped += 1;
                } else {
                    out.cpus[out.n_cpus] = pptt_cpu(t, o as u32, &leaf);
                    out.n_cpus += 1;
                }
            }
        }
        o += len;
    }
}

/// The labels of the leaf at `off`.
fn pptt_cpu(t: &[u8], off: u32, leaf: &PpttNode<'_>) -> PpttCpu {
    let core_off = if leaf.flags & PPTT_THREAD != 0 && leaf.parent != 0 { leaf.parent } else { off };
    let mut cpu = PpttCpu { uid: leaf.uid, core: core_off, cluster: PPTT_NONE, llc: PPTT_NONE, package: PPTT_NONE };
    // The cluster is whatever holds the core, unless that is the package.
    if let Some(core) = pptt_node(t, core_off) {
        if core.parent != 0 {
            if let Some(up) = pptt_node(t, core.parent) {
                if up.flags & PPTT_PACKAGE == 0 {
                    cpu.cluster = core.parent;
                }
            }
        }
    }
    // The package and the LLC: along the chain from the leaf to the root.
    let (mut cur, mut depth) = (off, 0);
    while let Some(n) = pptt_node(t, cur) {
        if cpu.package == PPTT_NONE && n.flags & PPTT_PACKAGE != 0 {
            cpu.package = cur;
        }
        // The outermost node with a cache has the last level.
        if let Some((_, end)) = pptt_last_cache(t, &n) {
            cpu.llc = end;
        }
        depth += 1;
        if n.parent == 0 || depth >= PPTT_DEPTH {
            break;
        }
        cur = n.parent;
    }
    cpu
}

/// Everything the boot takes from ACPI.
#[derive(Clone, Copy, Debug)]
pub struct AcpiInfo {
    pub rsdp: u64,
    pub revision: u8,
    /// Using the XSDT (64-bit pointers) rather than the RSDT.
    pub xsdt: bool,
    pub madt: Option<Madt>,
    pub hpet: Option<Hpet>,
    pub fadt: Option<Fadt>,
    /// Intel VT-d (DMAR) / AMD-Vi (IVRS): the IOMMU units and the RAM their
    /// devices use. At most one of the two is present on a real machine.
    pub dmar: Option<Dmar>,
    pub ivrs: Option<Ivrs>,
    /// The processor topology, when the firmware has a PPTT.
    pub pptt: Option<Pptt>,
    pub mcfg: [McfgEntry; MAX_MCFG],
    pub n_mcfg: usize,
    /// Every table read (signature, address, length), the root included,
    /// for the reservation of their pages.
    pub tables: [([u8; 4], u64, u32); MAX_TABLES],
    pub n_tables: usize,
    /// Tables skipped for a bad checksum, length or address.
    pub bad_tables: usize,
}

impl AcpiInfo {
    pub const EMPTY: AcpiInfo = AcpiInfo {
        rsdp: 0,
        revision: 0,
        xsdt: false,
        madt: None,
        hpet: None,
        fadt: None,
        dmar: None,
        ivrs: None,
        pptt: None,
        mcfg: [McfgEntry { base: 0, segment: 0, bus_start: 0, bus_end: 0 }; MAX_MCFG],
        n_mcfg: 0,
        tables: [([0; 4], 0, 0); MAX_TABLES],
        n_tables: 0,
        bad_tables: 0,
    };

    pub fn mcfg(&self) -> &[McfgEntry] {
        &self.mcfg[..self.n_mcfg]
    }
    pub fn tables(&self) -> &[([u8; 4], u64, u32)] {
        &self.tables[..self.n_tables]
    }

    /// The RAM ranges devices DMA to under the IOMMU's unity map (DMAR RMRRs,
    /// IVRS IVMDs): `(base, len)`, to keep out of the page allocator.
    pub fn for_each_dma_region(&self, mut f: impl FnMut(u64, u64)) {
        if let Some(d) = &self.dmar {
            d.rmrr().iter().for_each(|r| f(r.base, r.len));
        }
        if let Some(i) = &self.ivrs {
            i.ivmd().iter().for_each(|r| f(r.base, r.len));
        }
    }

    /// Number of IOMMU units the firmware lists, and which kind.
    pub fn iommu(&self) -> Option<(&'static str, usize)> {
        match (&self.dmar, &self.ivrs) {
            (Some(d), _) if d.n_units != 0 => Some(("Intel VT-d", d.n_units)),
            (_, Some(i)) if i.n_units != 0 => Some(("AMD-Vi", i.n_units)),
            _ => None,
        }
    }

    fn note(&mut self, sig: [u8; 4], pa: u64, len: u32) {
        if self.n_tables < MAX_TABLES {
            self.tables[self.n_tables] = (sig, pa, len);
            self.n_tables += 1;
        }
    }
}

/// Is there a valid RSDP at `pa`? Returns (revision, rsdt, xsdt).
pub fn check_rsdp<M: PhysMem>(mem: &M, pa: u64) -> Result<(u8, u32, u64), AcpiError> {
    let b = mem.read(pa, 20).ok_or(AcpiError::NoRsdp)?;
    if &b[0..8] != b"RSD PTR " {
        return Err(AcpiError::NoRsdp);
    }
    if !checksum_ok(b) {
        return Err(AcpiError::BadRsdp);
    }
    let rev = b[15];
    let rsdt = le32(b, 16);
    if rev >= 2 {
        let b = mem.read(pa, 36).ok_or(AcpiError::BadRsdp)?;
        let len = le32(b, 20) as usize;
        if len < 36 || len > 4096 {
            return Err(AcpiError::BadRsdp);
        }
        let full = mem.read(pa, len).ok_or(AcpiError::BadRsdp)?;
        if !checksum_ok(full) {
            return Err(AcpiError::BadRsdp);
        }
        return Ok((rev, rsdt, le64(b, 24)));
    }
    Ok((rev, rsdt, 0))
}

/// The legacy RSDP search (no pointer from the boot protocol): the first
/// KiB of the EBDA (segment at 0x40E), then 0xE0000..0x100000, on 16-byte
/// boundaries.
pub fn find_rsdp<M: PhysMem>(mem: &M) -> Option<u64> {
    let scan = |start: u64, end: u64| -> Option<u64> {
        let mut pa = start & !15;
        while pa + 20 <= end {
            if check_rsdp(mem, pa).is_ok() {
                return Some(pa);
            }
            pa += 16;
        }
        None
    };
    if let Some(seg) = mem.read(0x40E, 2) {
        let ebda = (le16(seg, 0) as u64) << 4;
        if ebda >= 0x8_0000 && ebda < 0xA_0000 {
            if let Some(pa) = scan(ebda, ebda + 1024) {
                return Some(pa);
            }
        }
    }
    scan(0xE_0000, 0x10_0000)
}

/// A table's bytes at `pa` once its header length and checksum are good.
pub fn table<M: PhysMem>(mem: &M, pa: u64) -> Option<&[u8]> {
    if pa == 0 {
        return None;
    }
    let h = mem.read(pa, SDT_HEADER_LEN)?;
    let len = le32(h, 4) as usize;
    if len < SDT_HEADER_LEN || len > MAX_TABLE_LEN {
        return None;
    }
    let t = mem.read(pa, len)?;
    if checksum_ok(t) { Some(t) } else { None }
}

/// Walk the root table from the RSDP at `rsdp_pa` and parse what the
/// platform uses into `out`.
pub fn parse<M: PhysMem>(mem: &M, rsdp_pa: u64, out: &mut AcpiInfo) -> Result<(), AcpiError> {
    *out = AcpiInfo::EMPTY;
    let (rev, rsdt, xsdt) = check_rsdp(mem, rsdp_pa)?;
    out.rsdp = rsdp_pa;
    out.revision = rev;
    out.note(*b"RSDP", rsdp_pa, if rev >= 2 { 36 } else { 20 });
    let (root_pa, width) = if xsdt != 0 { (xsdt, 8) } else { (rsdt as u64, 4) };
    out.xsdt = xsdt != 0;
    let root = table(mem, root_pa).ok_or(AcpiError::BadRoot)?;
    let want: &[u8; 4] = if width == 8 { b"XSDT" } else { b"RSDT" };
    if &root[0..4] != want {
        return Err(AcpiError::BadRoot);
    }
    out.note(*want, root_pa, root.len() as u32);
    let n = (root.len() - SDT_HEADER_LEN) / width;
    for i in 0..n {
        let o = SDT_HEADER_LEN + i * width;
        let pa = if width == 8 { le64(root, o) } else { le32(root, o) as u64 };
        let Some(t) = table(mem, pa) else {
            out.bad_tables += 1;
            continue;
        };
        let sig = [t[0], t[1], t[2], t[3]];
        out.note(sig, pa, t.len() as u32);
        match &sig {
            b"APIC" => {
                // In place: a Madt is ~3 KiB, too big to move through the
                // boot stack twice.
                let m = out.madt.insert(Madt::EMPTY);
                parse_madt(t, m);
            }
            b"HPET" => out.hpet = parse_hpet(t),
            b"FACP" => {
                // The DSDT is read here, while the boot identity map can
                // reach it: `\_S5` for the power-off, nothing else.
                out.fadt = parse_fadt(t).map(|mut f| {
                    f.s5 = table(mem, f.dsdt).filter(|d| &d[0..4] == b"DSDT").and_then(find_s5);
                    f
                });
            }
            b"MCFG" => out.n_mcfg = parse_mcfg(t, &mut out.mcfg),
            b"DMAR" => parse_dmar(t, out.dmar.insert(Dmar::EMPTY)),
            b"IVRS" => parse_ivrs(t, out.ivrs.insert(Ivrs::EMPTY)),
            // In place, like the MADT: a Pptt is ~5 KiB.
            b"PPTT" => parse_pptt(t, out.pptt.insert(Pptt::EMPTY)),
            _ => {}
        }
    }
    Ok(())
}
