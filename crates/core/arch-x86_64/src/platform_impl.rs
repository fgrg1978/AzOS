// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86 platform as the boot found it: the PVH `hvm_start_info` (memory
//! map, command line, RSDP), the ACPI tables (CPUs, IOAPICs, overrides,
//! HPET, MCFG), the virtio-mmio transports, and the AP trampoline page.
//!
//! [`discover`] fills it once, on the boot CPU, from `firmware_table`
//! (before the PMM, with boot.S's 0..4 GiB identity map live); after that it
//! is read-only and every accessor is a plain load. The pure decisions are
//! in [`crate::bootinfo`] and [`crate::acpi`]; this file only reads memory
//! and CPUID and stores the answers.

#![cfg(target_arch = "x86_64")]

use core::cell::UnsafeCell;

use crate::acpi::{self, AcpiError, AcpiInfo, PhysMem};
use crate::bootinfo::{self, HvmStartInfo, MemEntry, VirtioMmio, MAX_MEM_ENTRIES, PVH_MAGIC};

/// The dense CPU-number ceiling (Kconfig `NR_CPUS`).
pub const NR_CPUS: usize = azos_limits::NR_CPUS;
/// The command-line bytes kept (Kconfig `X86_CMDLINE_MAX`).
pub const CMDLINE_MAX: usize = azos_limits::X86_CMDLINE_MAX;
/// virtio-mmio transports kept and scanned (Kconfig `X86_VIRTIO_MMIO_MAX`).
pub const VIRTIO_MAX: usize = azos_limits::X86_VIRTIO_MMIO_MAX;

/// Boot-time state: written by the boot CPU only, inside [`discover`],
/// before any other CPU runs or any interrupt is enabled; read-only after.
struct BootCell<T>(UnsafeCell<T>);
// SAFETY: see the type doc: one writer, before any concurrent reader exists.
unsafe impl<T> Sync for BootCell<T> {}

/// Where a fact came from, for the boot log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    None,
    Pvh,
    Scan,
    Madt,
    Fallback,
    Cmdline,
    MicrovmLayout,
}

pub struct Platform {
    pub start_info_pa: u64,
    pub start_info: Option<HvmStartInfo>,
    pub memmap: [MemEntry; MAX_MEM_ENTRIES],
    pub n_memmap: usize,
    pub memmap_dropped: usize,
    pub cmdline_pa: u64,
    pub cmdline: [u8; CMDLINE_MAX],
    pub cmdline_len: usize,
    /// The command line's full length (it may have been cut to CMDLINE_MAX).
    pub cmdline_full_len: usize,
    pub acpi: AcpiInfo,
    pub acpi_err: Option<AcpiError>,
    pub rsdp_source: Source,
    /// Dense CPU number -> APIC ID (index 0 = the boot CPU).
    pub apic_ids: [u32; NR_CPUS],
    pub n_cpus: usize,
    /// CPUs the MADT listed past NR_CPUS (not started).
    pub cpus_over_limit: usize,
    pub cpu_source: Source,
    pub bsp_apic_id: u32,
    pub lapic_pa: u64,
    pub virtio: [VirtioMmio; VIRTIO_MAX],
    pub n_virtio: usize,
    pub virtio_bad: usize,
    pub virtio_source: Source,
    pub trampoline_pa: Option<u64>,
}

static PLATFORM: BootCell<Platform> = BootCell(UnsafeCell::new(Platform {
    start_info_pa: 0,
    start_info: None,
    memmap: [MemEntry { addr: 0, size: 0, kind: 0, reserved: 0 }; MAX_MEM_ENTRIES],
    n_memmap: 0,
    memmap_dropped: 0,
    cmdline_pa: 0,
    cmdline: [0; CMDLINE_MAX],
    cmdline_len: 0,
    cmdline_full_len: 0,
    acpi: AcpiInfo::EMPTY,
    acpi_err: None,
    rsdp_source: Source::None,
    apic_ids: [0; NR_CPUS],
    n_cpus: 1,
    cpus_over_limit: 0,
    cpu_source: Source::None,
    bsp_apic_id: 0,
    lapic_pa: 0xFEE0_0000,
    virtio: [VirtioMmio { base: 0, size: 0, gsi: 0 }; VIRTIO_MAX],
    n_virtio: 0,
    virtio_bad: 0,
    virtio_source: Source::None,
    trampoline_pa: None,
}));

/// The platform the boot found (read-only once [`discover`] has run).
#[inline]
pub fn platform() -> &'static Platform {
    // SAFETY: written only inside `discover`, before any concurrent reader.
    unsafe { &*PLATFORM.0.get() }
}

impl Platform {
    pub fn memmap(&self) -> &[MemEntry] {
        &self.memmap[..self.n_memmap]
    }
    pub fn cmdline(&self) -> &[u8] {
        &self.cmdline[..self.cmdline_len]
    }
    pub fn virtio(&self) -> &[VirtioMmio] {
        &self.virtio[..self.n_virtio]
    }
    pub fn madt(&self) -> Option<&acpi::Madt> {
        self.acpi.madt.as_ref()
    }
    /// The APIC ID of dense CPU `cpu`.
    pub fn apic_id(&self, cpu: usize) -> Option<u32> {
        if cpu < self.n_cpus { Some(self.apic_ids[cpu]) } else { None }
    }
    /// The dense CPU number of APIC ID `apic_id`.
    pub fn cpu_of_apic(&self, apic_id: u32) -> Option<usize> {
        self.apic_ids[..self.n_cpus].iter().position(|&a| a == apic_id)
    }
    /// The GSI, level and polarity of ISA IRQ `irq`: the MADT override if
    /// any, else the ISA default (same number, edge, active-high).
    pub fn isa_irq(&self, irq: u8) -> (u32, bool, bool) {
        match self.madt().and_then(|m| m.iso_for(irq)) {
            Some(o) => (o.gsi, o.level().unwrap_or(false), o.active_low().unwrap_or(false)),
            None => (irq as u32, false, false),
        }
    }
    /// The virtio-mmio transport at `base`'s GSI.
    pub fn virtio_gsi(&self, base: u64) -> Option<u32> {
        self.virtio().iter().find(|d| d.base == base).map(|d| d.gsi)
    }
    /// The page spans the boot information occupies (start_info, memory map,
    /// command line, every ACPI table): what the PMM must not hand out and
    /// the trampoline must not overwrite.
    pub fn for_each_boot_span(&self, mut f: impl FnMut(u64, u64)) {
        if self.start_info_pa != 0 {
            f(self.start_info_pa, core::mem::size_of::<HvmStartInfo>() as u64);
        }
        if let Some(si) = self.start_info {
            if si.memmap_paddr != 0 {
                f(si.memmap_paddr, si.memmap_entries as u64 * core::mem::size_of::<MemEntry>() as u64);
            }
        }
        if self.cmdline_pa != 0 {
            f(self.cmdline_pa, self.cmdline_full_len as u64 + 1);
        }
        for &(_, pa, len) in self.acpi.tables() {
            f(pa, len as u64);
        }
    }
}

/// The boot identity map (boot.S: 0..4 GiB, 2 MiB pages) as [`PhysMem`].
struct BootIdentity;

const IDENTITY_LIMIT: u64 = 1 << 32;

impl PhysMem for BootIdentity {
    fn read(&self, pa: u64, len: usize) -> Option<&[u8]> {
        if pa == 0 || pa.checked_add(len as u64)? > IDENTITY_LIMIT {
            return None;
        }
        // SAFETY: boot.S maps 0..4 GiB 1:1 and nothing writes the firmware
        // tables; only called from `discover`, before the kernel tables.
        Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) })
    }
}

/// `cpuid` leaf/subleaf: (eax, ebx, ecx, edx).
#[inline]
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// The highest basic CPUID leaf.
pub fn cpuid_max() -> u32 {
    cpuid(0, 0).0
}

/// This CPU's APIC ID: the 32-bit x2APIC ID from leaf 0xB when the CPU has
/// it, else the 8-bit initial APIC ID of leaf 1.
pub fn cpuid_apic_id() -> u32 {
    if cpuid_max() >= 0xB {
        let (_, ebx, _, edx) = cpuid(0xB, 0);
        if ebx & 0xFFFF != 0 {
            return edx;
        }
    }
    cpuid(1, 0).1 >> 24
}

/// Read everything at `start_info_pa` and the ACPI tables it points to.
///
/// # Safety
/// Boot CPU only, once, before any other CPU or interrupt; boot.S's identity
/// map must still be live.
pub unsafe fn discover(start_info_pa: usize) {
    // SAFETY: the caller's contract: sole access.
    let p = unsafe { &mut *PLATFORM.0.get() };
    let mem = BootIdentity;
    p.start_info_pa = start_info_pa as u64;

    // ── PVH start_info: the memory map, the command line, the RSDP ──
    let si = mem.read(start_info_pa as u64, core::mem::size_of::<HvmStartInfo>())
        // SAFETY: size_of::<HvmStartInfo>() readable bytes; read_unaligned.
        .map(|b| unsafe { core::ptr::read_unaligned(b.as_ptr() as *const HvmStartInfo) })
        .filter(|si| si.magic == PVH_MAGIC);
    p.start_info = si;
    if let Some(si) = si {
        if si.version >= 1 && si.memmap_paddr != 0 {
            let n = si.memmap_entries as usize;
            p.n_memmap = n.min(MAX_MEM_ENTRIES);
            p.memmap_dropped = n - p.n_memmap;
            for i in 0..p.n_memmap {
                let pa = si.memmap_paddr + (i * core::mem::size_of::<MemEntry>()) as u64;
                if let Some(b) = mem.read(pa, core::mem::size_of::<MemEntry>()) {
                    // SAFETY: one MemEntry's bytes; read_unaligned.
                    p.memmap[i] = unsafe { core::ptr::read_unaligned(b.as_ptr() as *const MemEntry) };
                }
            }
        }
        if si.cmdline_paddr != 0 {
            p.cmdline_pa = si.cmdline_paddr;
            // NUL-terminated: read byte by byte up to a bound past our buffer.
            let mut len = 0;
            while len < 64 * 1024 {
                match mem.read(si.cmdline_paddr + len as u64, 1) {
                    Some(&[0]) | None => break,
                    Some(&[c]) => {
                        if len < CMDLINE_MAX {
                            p.cmdline[len] = c;
                        }
                    }
                    Some(_) => break,
                }
                len += 1;
            }
            p.cmdline_full_len = len;
            p.cmdline_len = len.min(CMDLINE_MAX);
        }
    }

    // ── ACPI ──
    let rsdp = match si.map(|s| s.rsdp_paddr).filter(|&r| r != 0) {
        Some(r) => {
            p.rsdp_source = Source::Pvh;
            Some(r)
        }
        None => acpi::find_rsdp(&mem).inspect(|_| p.rsdp_source = Source::Scan),
    };
    p.acpi_err = match rsdp {
        Some(r) => acpi::parse(&mem, r, &mut p.acpi).err(),
        None => Some(AcpiError::NoRsdp),
    };

    // ── CPUs: MADT order, the boot CPU first, NR_CPUS at most ──
    p.bsp_apic_id = cpuid_apic_id();
    let base_msr = crate::hw::rdmsr(crate::encode::APIC_BASE_MSR);
    p.lapic_pa = base_msr & crate::encode::APIC_BASE_ADDR_MASK;
    let bsp = p.bsp_apic_id;
    let madt_ok = p.acpi.madt.as_mut().is_some_and(|m| m.n_cpus != 0 && m.boot_cpu_first(bsp));
    match p.acpi.madt.as_ref() {
        Some(m) if madt_ok => {
            if m.lapic_addr != 0 {
                p.lapic_pa = m.lapic_addr;
            }
            p.n_cpus = m.n_cpus.min(NR_CPUS);
            p.cpus_over_limit = m.n_cpus - p.n_cpus + m.cpus_skipped;
            for (i, c) in m.cpus().iter().take(p.n_cpus).enumerate() {
                p.apic_ids[i] = c.apic_id;
            }
            p.cpu_source = Source::Madt;
        }
        _ => {
            p.apic_ids[0] = bsp;
            p.n_cpus = 1;
            p.cpu_source = Source::Fallback;
        }
    }

    // ── virtio-mmio: the command line (microvm without ACPI), else the
    //    machine's fixed layout ──
    let (n, bad) = bootinfo::parse_virtio_mmio(&p.cmdline[..p.cmdline_len], &mut p.virtio);
    p.virtio_bad = bad;
    if n != 0 {
        p.n_virtio = n;
        p.virtio_source = Source::Cmdline;
    } else if VIRTIO_MAX != 0 {
        let second = p.madt().is_some_and(|m| m.ioapics().iter().any(|io| io.gsi_base == 24));
        let (gsi0, count) = bootinfo::microvm_virtio_layout(p.acpi_err.is_none(), second);
        p.n_virtio = count.min(VIRTIO_MAX);
        for i in 0..p.n_virtio {
            p.virtio[i] = VirtioMmio {
                base: (azos_limits::X86_VIRTIO_MMIO_BASE + i * azos_limits::X86_VIRTIO_MMIO_STRIDE) as u64,
                size: azos_limits::X86_VIRTIO_MMIO_STRIDE as u64,
                gsi: gsi0 + i as u32,
            };
        }
        p.virtio_source = Source::MicrovmLayout;
    }

    // ── The AP trampoline page: low RAM no boot information sits in ──
    let mut avoid = [(0u64, 0u64); 4 + acpi::MAX_TABLES];
    let mut na = 0;
    p.for_each_boot_span(|s, l| {
        if na < avoid.len() {
            avoid[na] = (s & !0xFFF, ((s & 0xFFF) + l + 0xFFF) & !0xFFF);
            na += 1;
        }
    });
    p.trampoline_pa = bootinfo::pick_trampoline(p.memmap(), &avoid[..na], azos_limits::X86_AP_TRAMPOLINE_PA as u64);
}

/// Remap both 8259 PICs above the exception vectors (a spurious IRQ 7/15
/// then lands on a harmless vector, never on #DF) and mask every line: the
/// IOAPIC and the LAPIC carry every interrupt.
pub fn mask_8259() {
    for (port, v) in crate::encode::pic_remap(crate::encode::PIC_VECTOR_BASE) {
        crate::hw::outb(port, v);
    }
    crate::hw::outb(0x21, 0xFF);
    crate::hw::outb(0xA1, 0xFF);
}
