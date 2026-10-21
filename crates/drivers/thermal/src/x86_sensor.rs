// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 temperature as a [`SensorBank`]: Intel `coretemp` (the digital
//! thermal sensor MSRs) and AMD Zen (the SMU thermal register over SMN).
//!
//! One sensor, index 0: the package. Intel reads `IA32_PACKAGE_THERM_STATUS`
//! when the part has package thermal status, else `IA32_THERM_STATUS` of the
//! CPU that runs the read (the thermal task is pinned, so it is always the
//! same core). AMD reads `THM_TCON_CUR_TMP`, minus the part's Tctl offset.
//!
//! # Probe, and why it comes first
//!
//! An `rdmsr` of an MSR the CPU does not have raises `#GP`, and the kernel
//! has no exception fix-up for it. So nothing is read before [`probe`] has
//! decided from CPUID that the register exists:
//!
//! * a hypervisor (`CPUID.1:ECX[31]`) is refused outright: a virtual CPU
//!   reports whatever its host chose, and QEMU TCG has no `coretemp`,
//!   `MSR_TEMPERATURE_TARGET` or SMU at all;
//! * Intel needs `CPUID.6:EAX[0]` (digital thermal sensor) and a model that
//!   has `MSR_TEMPERATURE_TARGET` (Nehalem onwards; the first Atoms are
//!   left out: the register is not architectural there);
//! * AMD and Hygon need a Zen family (17h, 18h, 19h, 1Ah) and, behind the
//!   SMN index/data pair of the root complex (`00:00.0`, config offsets
//!   [`SMN_INDEX`] / [`SMN_DATA`]), a root complex that answers with the
//!   vendor's own PCI id.
//!
//! A refused probe is the [`Refused`] reason, which the kernel prints, and
//! the board has no sensor: the framework stays idle (invariant I4). The
//! actuator is the pairing board object's business ([`X86Board`]): the CPU's
//! own level request ([`crate::x86`]: Intel HWP, AMD CPPC) where the part has
//! one, and where it has none (or none the OS may drive) its refusal, so heat
//! raises the degrade level and, at the critical trip, requests the orderly
//! shutdown, instead of capping a clock.
//!
//! # The SMN pair is one transaction
//!
//! The SMN window is an index register and a data register in the config
//! space of the root complex, reached through the legacy 0xCF8/0xCFC port
//! pair, which is itself an address/data pair. Two harts that interleave on
//! either pair read or write the wrong register. So the sensor never touches
//! the pairs: [`RootComplex::smn_read`] is one call, and the board that
//! implements it holds the lock of every user of the config ports across the
//! index write and the data read.
//!
//! # Trips
//!
//! This module reads temperatures only. The trip points come from the zones
//! the board declares ([`crate::dt::build`] over a `DtThermal`); the sensor
//! index a zone names is 0. An x86_64 machine has no device tree and the
//! signed topology declares no thermal zones, so its one zone, the package,
//! is [`package_zone`]: a `passive` trip (cap every performance domain that
//! has two OPPs, one step per read), a `hot` trip and a `critical` trip at the
//! temperatures Kconfig `THERMAL_X86_PASSIVE_C`, `THERMAL_X86_HOT_C` and
//! `THERMAL_X86_CRITICAL_C` name. There is no ACPI `_TZ` here. The cooling
//! maps name the domains through the CPU numbers of the energy model, with
//! synthetic CPU phandles (the machine has no CPU nodes).
//!
//! # `[verify]`
//!
//! The AMD decode (`CUR_TEMP` in bits 31:21, 0.125 C steps, -49 C when
//! `CUR_TEMP_RANGE_SEL`, bit 19, is set; SMN address 0x59800; the 0x60 / 0x64
//! pair) follows Linux `k10temp`/`amd_nb` as remembered: the vendored Linux
//! tree has no `drivers/hwmon/k10temp.c` to check it against, and `k10temp`
//! may also treat `CUR_TEMP_TJ_SEL` (bits 17:16) reading 0b11 as the same
//! range select. No Zen part has run it yet.
//!
//! Host-tested in `tests/host/thermal-tests` (`x86_sensor` module) against
//! fake MSRs and a fake root complex.

use azos_dtb::{
    DtCooler, DtThermal, DT_THERMAL_MAPS, DT_THERMAL_NAME, DT_THERMAL_NO_LIMIT, DT_TRIP_CRITICAL, DT_TRIP_HOT,
    DT_TRIP_PASSIVE, MAX_CPU_REG,
};
use azos_energy::model::{EnergyModel, Opp, MAX_MODEL_CPUS};
use azos_energy::opp::{ActuateError, OppActuator};

use crate::sensor::{SensorBank, SensorError};

/// `IA32_THERM_STATUS`: bit 31 reading valid, bits 22:16 the digital readout
/// (degrees below TjMax).
const MSR_THERM_STATUS: u32 = 0x19c;
/// `MSR_TEMPERATURE_TARGET`: bits 23:16 TjMax, degrees Celsius.
const MSR_TEMPERATURE_TARGET: u32 = 0x1a2;
/// `IA32_PACKAGE_THERM_STATUS`: the package-level twin of `IA32_THERM_STATUS`.
const MSR_PACKAGE_THERM_STATUS: u32 = 0x1b1;
/// The valid bit of both status MSRs.
const STATUS_VALID: u64 = 1 << 31;
/// TjMax assumed when `MSR_TEMPERATURE_TARGET` reads zero (what Linux does).
const DEFAULT_TJMAX_MDEG: i32 = 100_000;
/// The plausible range of a TjMax, degrees Celsius: outside it the register
/// is not a TjMax and the sensor is refused rather than trusted.
const TJMAX_MIN_C: u32 = 60;
const TJMAX_MAX_C: u32 = 130;

/// `CPUID.6:EAX[0]`: digital thermal sensor.
const L6_DTS: u32 = 1 << 0;
/// `CPUID.6:EAX[6]`: package thermal status.
const L6_PTS: u32 = 1 << 6;

/// PCI config offsets of the SMN index and data registers on the root complex
/// (`00:00.0`), for the [`RootComplex`] that performs the access.
pub const SMN_INDEX: u8 = 0x60;
/// See [`SMN_INDEX`].
pub const SMN_DATA: u8 = 0x64;
/// `THM_TCON_CUR_TMP`: the current Tctl, in the SMN space.
const SMN_THM_TCON_CUR_TMP: u32 = 0x0005_9800;
/// `CUR_TEMP` is bits 31:21, in 0.125 C steps.
const CUR_TEMP_SHIFT: u32 = 21;
/// `CUR_TEMP_RANGE_SEL`: the reading is relative to -49 C instead of 0 C.
const CUR_TEMP_RANGE_SEL: u32 = 1 << 19;
const RANGE_SEL_MDEG: i32 = 49_000;
/// PCI vendor ids of the root complexes.
const PCI_VENDOR_AMD: u16 = 0x1022;
const PCI_VENDOR_HYGON: u16 = 0x1d94;

/// Who made the CPU (CPUID.0), for the sensor that applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    /// `GenuineIntel`.
    Intel,
    /// `AuthenticAMD`.
    Amd,
    /// `HygonGenuine`.
    Hygon,
    /// Any other vendor string.
    Other,
}

/// What the probe reads of the CPU. The kernel fills it from CPUID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86Cpu {
    /// CPUID.0 vendor string.
    pub vendor: Vendor,
    /// Display family (base plus extended).
    pub family: u16,
    /// Display model (base plus extended model).
    pub model: u16,
    /// CPUID.1:ECX[31]: a hypervisor runs this CPU.
    pub hypervisor: bool,
    /// The highest basic CPUID leaf (CPUID.0:EAX).
    pub max_basic_leaf: u32,
    /// CPUID.6:EAX, zero when the CPU has no leaf 6.
    pub l6_eax: u32,
    /// The brand string (CPUID.0x80000002..4), NUL padded; zeros when absent.
    pub brand: [u8; 48],
}

impl X86Cpu {
    /// The probe's view of a CPU from what the kernel read of it: the CPUID.1
    /// ECX word (bit 31 is the hypervisor bit), the highest basic leaf, leaf
    /// 6 EAX (read only when the CPU has the leaf; the caller passes zero
    /// otherwise) and the brand leaves.
    pub const fn from_cpuid(
        vendor: Vendor,
        family: u16,
        model: u16,
        l1_ecx: u32,
        max_basic_leaf: u32,
        l6_eax: u32,
        brand: [u8; 48],
    ) -> Self {
        Self {
            vendor,
            family,
            model,
            hypervisor: l1_ecx & (1 << 31) != 0,
            max_basic_leaf,
            l6_eax: if max_basic_leaf >= 6 { l6_eax } else { 0 },
            brand,
        }
    }
}

/// The brand string from CPUID.0x80000002..4 (`eax, ebx, ecx, edx` of each
/// leaf, little endian), NUL padded as the CPU gives it.
pub fn brand_from_leaves(leaves: [[u32; 4]; 3]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (i, leaf) in leaves.iter().enumerate() {
        for (j, w) in leaf.iter().enumerate() {
            out[i * 16 + j * 4..][..4].copy_from_slice(&w.to_le_bytes());
        }
    }
    out
}

/// The phandle the package zone gives its sensor ([`crate::runtime::single_sensor`]
/// resolves any non-zero phandle with cell 0 to sensor 0).
const PACKAGE_SENSOR: u32 = 1;
/// Hysteresis of the trips, milli-degrees.
const PACKAGE_HYST_MDEG: u32 = 3_000;
/// The phandle of the first trip; the others follow it.
const TRIP_PHANDLE: u32 = 2;
/// The phandle the package zone gives CPU `n` (the machine has no CPU nodes:
/// the cooling maps name a CPU, and its domain is the model's, through the
/// CPU's number).
const CPU_PHANDLE: u32 = 0x100;

/// The one zone of an x86_64 machine: the package, polled every `poll_ms`,
/// with a `passive` trip at `passive_c` (every domain of `model` that has two
/// OPPs is capped a step per read while it is active), a `hot` trip at `hot_c`
/// (degrade level 2) and a `critical` trip at `critical_c` (level 3 and the
/// orderly shutdown), degrees Celsius. `None` when the trips are not in
/// ascending order or `poll_ms` is zero.
pub fn package_zone(model: &EnergyModel, passive_c: u32, hot_c: u32, critical_c: u32, poll_ms: u32) -> Option<DtThermal> {
    if passive_c >= hot_c || hot_c >= critical_c || poll_ms == 0 {
        return None;
    }
    let mut dt = DtThermal::EMPTY;
    let n_cpus = MAX_MODEL_CPUS.min(MAX_CPU_REG);
    for (cpu, p) in dt.cpus[..n_cpus].iter_mut().enumerate() {
        *p = CPU_PHANDLE + cpu as u32;
    }
    dt.n_cpus = n_cpus as u8;
    let z = &mut dt.zones[0];
    let name = b"package";
    debug_assert!(name.len() <= DT_THERMAL_NAME);
    z.name[..name.len()].copy_from_slice(name);
    z.name_len = name.len() as u8;
    z.poll_ms = poll_ms;
    z.poll_passive_ms = poll_ms;
    z.sensor = PACKAGE_SENSOR;
    for (i, (kind, c)) in [(DT_TRIP_PASSIVE, passive_c), (DT_TRIP_HOT, hot_c), (DT_TRIP_CRITICAL, critical_c)].into_iter().enumerate() {
        z.trips[i].phandle = TRIP_PHANDLE + i as u32;
        z.trips[i].temp_mdeg = i32::try_from(c).ok()?.checked_mul(1000)?;
        z.trips[i].hyst_mdeg = PACKAGE_HYST_MDEG;
        z.trips[i].kind = kind;
    }
    z.n_trips = 3;
    // A domain with one OPP has nothing to cap: no map.
    let mut n_maps = 0;
    for d in model.domains().iter().filter(|d| d.opps().len() >= 2) {
        let cpu = d.cpus.trailing_zeros() as usize;
        if cpu >= n_cpus || n_maps >= DT_THERMAL_MAPS {
            continue;
        }
        let m = &mut z.maps[n_maps];
        m.trip = TRIP_PHANDLE;
        m.coolers[0] = DtCooler { phandle: CPU_PHANDLE + cpu as u32, min: DT_THERMAL_NO_LIMIT, max: DT_THERMAL_NO_LIMIT };
        m.n_coolers = 1;
        n_maps += 1;
    }
    z.n_maps = n_maps as u8;
    dt.n_zones = 1;
    Some(dt)
}

/// Why [`probe`] found no sensor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A hypervisor runs this CPU.
    Hypervisor,
    /// Not Intel, AMD or Hygon.
    Vendor,
    /// Intel: the CPU reports no digital thermal sensor (or no leaf 6).
    NoDts,
    /// Intel: a model without `MSR_TEMPERATURE_TARGET`, or whose TjMax reads
    /// as a value no part has.
    Model,
    /// AMD: not a Zen family; the older parts keep their temperature in the
    /// northbridge PCI function, which this module does not read.
    Family,
    /// AMD: the root complex at 00:00.0 is not the vendor's.
    NoRoot,
}

impl Refused {
    /// The reason in a boot line.
    pub const fn name(self) -> &'static str {
        match self {
            Refused::Hypervisor => "running under a hypervisor",
            Refused::Vendor => "unknown CPU vendor",
            Refused::NoDts => "no digital thermal sensor",
            Refused::Model => "no usable MSR_TEMPERATURE_TARGET",
            Refused::Family => "not a Zen family",
            Refused::NoRoot => "no AMD root complex at 00:00.0",
        }
    }
}

/// Which sensor the probe settled on, with what the reads need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Intel `coretemp`.
    Intel {
        /// `IA32_PACKAGE_THERM_STATUS` exists: read the package, not one core.
        package: bool,
        /// TjMax, milli-degrees Celsius.
        tjmax_mdeg: i32,
    },
    /// AMD / Hygon Zen, through SMN.
    Smn {
        /// Tctl minus the true die temperature, milli-degrees.
        tctl_offset_mdeg: i32,
    },
}

/// The root complex at PCI `00:00.0`, supplied by the board: the vendor id
/// that tells whose it is, and the SMN window behind it.
pub trait RootComplex {
    /// The PCI vendor id of `00:00.0`; `0xffff` when there is no device (or
    /// no config-space access in this build).
    fn vendor_id(&self) -> u16;
    /// The SMN register at `addr`: [`SMN_INDEX`] written with `addr`, then
    /// [`SMN_DATA`] read, as one sequence that no other hart's config-space
    /// access, and no other SMN user, can interleave with. All ones when
    /// there is nothing to read.
    fn smn_read(&mut self, addr: u32) -> u32;
}

/// `rdmsr`, supplied by the board. Only called for an MSR the probe has
/// established the CPU has.
pub trait MsrBus {
    /// Read MSR `msr` on the executing CPU.
    fn rdmsr(&mut self, msr: u32) -> u64;
}

/// Intel models with `MSR_TEMPERATURE_TARGET`: every family above 6, and
/// family 6 from Nehalem (0x1a) onwards except the first Atoms (Bonnell and
/// Saltwell: 0x1c, 0x26, 0x27, 0x35, 0x36), where Linux falls back to a
/// model table instead.
const fn intel_has_temperature_target(family: u16, model: u16) -> bool {
    if family > 6 {
        return true;
    }
    family == 6 && model >= 0x1a && !matches!(model, 0x1c | 0x26 | 0x27 | 0x35 | 0x36)
}

/// Tctl minus the die temperature, milli-degrees: the parts whose reported
/// control temperature is offset from the die (the first Ryzens and
/// Threadrippers, family 17h), by brand-string prefix as Linux `k10temp`
/// matches them. Every other part reports Tctl equal to the die temperature.
pub fn tctl_offset_mdeg(family: u16, brand: &[u8]) -> i32 {
    const TABLE: [(&[u8], i32); 6] = [
        (b"AMD Ryzen 5 1600X", 20_000),
        (b"AMD Ryzen 7 1700X", 20_000),
        (b"AMD Ryzen 7 1800X", 20_000),
        (b"AMD Ryzen 7 2700X", 10_000),
        (b"AMD Ryzen Threadripper 19", 27_000),
        (b"AMD Ryzen Threadripper 29", 27_000),
    ];
    if family != 0x17 {
        return 0;
    }
    let start = brand.iter().position(|&b| b != b' ' && b != 0).unwrap_or(brand.len());
    let brand = &brand[start..];
    TABLE.iter().find(|(id, _)| brand.starts_with(id)).map_or(0, |&(_, off)| off)
}

/// Decide from CPUID (and, behind it, the one register or device that
/// confirms it) which sensor this machine has. Reads no MSR the CPU might
/// not have: see the module documentation.
pub fn probe<M: MsrBus, R: RootComplex>(cpu: &X86Cpu, msr: &mut M, root: &R) -> Result<Kind, Refused> {
    if cpu.hypervisor {
        return Err(Refused::Hypervisor);
    }
    match cpu.vendor {
        Vendor::Intel => {
            if cpu.max_basic_leaf < 6 || cpu.l6_eax & L6_DTS == 0 {
                return Err(Refused::NoDts);
            }
            if !intel_has_temperature_target(cpu.family, cpu.model) {
                return Err(Refused::Model);
            }
            let tjmax_c = ((msr.rdmsr(MSR_TEMPERATURE_TARGET) >> 16) & 0xff) as u32;
            let tjmax_mdeg = match tjmax_c {
                0 => DEFAULT_TJMAX_MDEG,
                TJMAX_MIN_C..=TJMAX_MAX_C => tjmax_c as i32 * 1000,
                _ => return Err(Refused::Model),
            };
            Ok(Kind::Intel { package: cpu.l6_eax & L6_PTS != 0, tjmax_mdeg })
        }
        Vendor::Amd | Vendor::Hygon => {
            if !matches!(cpu.family, 0x17..=0x1a) {
                return Err(Refused::Family);
            }
            let want = if cpu.vendor == Vendor::Amd { PCI_VENDOR_AMD } else { PCI_VENDOR_HYGON };
            if root.vendor_id() != want {
                return Err(Refused::NoRoot);
            }
            Ok(Kind::Smn { tctl_offset_mdeg: tctl_offset_mdeg(cpu.family, &cpu.brand) })
        }
        Vendor::Other => Err(Refused::Vendor),
    }
}

/// Intel: milli-degrees from a status MSR value, `None` when the reading is
/// not valid.
const fn intel_mdeg(status: u64, tjmax_mdeg: i32) -> Option<i32> {
    if status & STATUS_VALID == 0 {
        return None;
    }
    let below = ((status >> 16) & 0x7f) as i32;
    Some(tjmax_mdeg - below * 1000)
}

/// AMD: die temperature in milli-degrees from `THM_TCON_CUR_TMP`. `None` for a
/// register that reads all ones (nothing behind the SMN pair) or zero (no
/// conversion yet).
const fn amd_mdeg(reg: u32, tctl_offset_mdeg: i32) -> Option<i32> {
    if reg == 0 || reg == u32::MAX {
        return None;
    }
    let mut tctl = (reg >> CUR_TEMP_SHIFT) as i32 * 125;
    if reg & CUR_TEMP_RANGE_SEL != 0 {
        tctl -= RANGE_SEL_MDEG;
    }
    Some(tctl - tctl_offset_mdeg)
}

/// The package temperature sensor of an x86_64 machine.
pub struct X86Sensor<M, R> {
    kind: Kind,
    msr: M,
    root: R,
}

impl<M: MsrBus, R: RootComplex> X86Sensor<M, R> {
    /// A sensor of the kind [`probe`] returned over the board's MSR and
    /// root-complex access.
    pub const fn new(kind: Kind, msr: M, root: R) -> Self {
        Self { kind, msr, root }
    }
}

impl<M: MsrBus, R: RootComplex> SensorBank for X86Sensor<M, R> {
    /// Sensor 0, the package: milli-degrees Celsius. `Invalid` for a reading
    /// the part flags as not valid (Intel) or a register with nothing behind
    /// it (AMD).
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        if sensor != 0 {
            return Err(SensorError::Absent);
        }
        match self.kind {
            Kind::Intel { package, tjmax_mdeg } => {
                let status = self.msr.rdmsr(if package { MSR_PACKAGE_THERM_STATUS } else { MSR_THERM_STATUS });
                intel_mdeg(status, tjmax_mdeg).ok_or(SensorError::Invalid)
            }
            Kind::Smn { tctl_offset_mdeg } => {
                let reg = self.root.smn_read(SMN_THM_TCON_CUR_TMP);
                amd_mdeg(reg, tctl_offset_mdeg).ok_or(SensorError::Invalid)
            }
        }
    }
}

/// The x86_64 board object: the probed sensor paired with the actuator the
/// board has ([`crate::x86::Actuator`]: HWP or CPPC level requests, which
/// refuse every request on a CPU that has neither).
pub struct X86Board<M, R, A> {
    /// The package temperature sensor.
    pub sensor: X86Sensor<M, R>,
    /// What moves the clock.
    pub actuator: A,
}

impl<M: MsrBus, R: RootComplex, A> SensorBank for X86Board<M, R, A> {
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        self.sensor.read_mdeg(sensor)
    }
}

impl<M, R, A: OppActuator> OppActuator for X86Board<M, R, A> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        self.actuator.set_opp(domain, opp)
    }
}
