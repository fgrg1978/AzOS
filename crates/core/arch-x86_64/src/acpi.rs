// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ACPI static tables, read-only: RSDP -> XSDT (or RSDT) -> MADT, HPET,
//! MCFG, FADT, DMAR, IVRS. What x86 boot needs from firmware (the CPUs, the
//! IOAPICs and their interrupt source overrides, the HPET and PCIe ECAM
//! windows, the ACPI PM timer, the IOMMU units and the RAM their devices
//! use) is in these tables; the DSDT's AML is not interpreted.
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

/// The FADT fields the platform uses: the reset register and the PM1a
/// control block (S5 shutdown), and the boot-architecture flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fadt {
    /// The table's revision (header byte 8): IAPC_BOOT_ARCH exists from 2.
    pub revision: u8,
    pub pm1a_cnt: u32,
    /// IAPC_BOOT_ARCH: bit 0 legacy devices, bit 1 8042, bit 5 no CMOS RTC.
    /// 0 when the table is too old (revision < 2) or too short to carry it.
    pub iapc_boot_arch: u16,
    /// Fixed feature flags: bit 10 RESET_REG_SUP, bit 20 HW_REDUCED_ACPI.
    pub flags: u32,
    /// RESET_REG (GAS): address space id and address; 0/0 = none.
    pub reset_space: u8,
    pub reset_addr: u64,
    pub reset_value: u8,
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
        if self.flags & (1 << 20) != 0 {
            return false;
        }
        self.revision < 2 || self.iapc_boot_arch & 0b10 != 0
    }
}

pub fn parse_fadt(t: &[u8]) -> Option<Fadt> {
    if t.len() < 116 {
        return None;
    }
    let mut f = Fadt { revision: t[8], pm1a_cnt: le32(t, 64), flags: le32(t, 112), ..Fadt::default() };
    if f.revision >= 2 && t.len() >= 111 {
        f.iapc_boot_arch = le16(t, 109);
    }
    if t.len() >= 129 {
        f.reset_space = t[116];
        f.reset_addr = le64(t, 120);
        f.reset_value = t[128];
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
            b"FACP" => out.fadt = parse_fadt(t),
            b"MCFG" => out.n_mcfg = parse_mcfg(t, &mut out.mcfg),
            b"DMAR" => parse_dmar(t, out.dmar.insert(Dmar::EMPTY)),
            b"IVRS" => parse_ivrs(t, out.ivrs.insert(Ivrs::EMPTY)),
            _ => {}
        }
    }
    Ok(())
}
