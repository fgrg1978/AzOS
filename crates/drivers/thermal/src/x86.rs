// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the x86_64 board moves and measures: an [`OppActuator`] over the CPU's
//! own performance-level MSRs, and RAPL's package energy as a meter. The
//! temperature is [`crate::x86_sensor`]'s; this is the half that fills the
//! `A` slot of [`crate::x86_sensor::X86Board`].
//!
//! What the CPU offers is `azos_arch::cpu::pstate::probe`'s (CPUID, vendor,
//! model, never a hypervisor); this module is the part that does something
//! with it, over a [`Platform`] the kernel supplies (a local `rdmsr`, a
//! function-call IPI for another CPU's) so the host suite runs the arithmetic
//! against a fake CPU.
//!
//! # Actuator (domains of the energy model)
//!
//! A request is a minimum and a maximum *performance level* (Intel HWP:
//! `IA32_HWP_REQUEST`; AMD CPPC: `MSR_AMD_CPPC_REQ`), per logical CPU. Each
//! CPU of the domain gets its own request, in its own units (the levels of a
//! performance and an efficiency core are not the same scale), found from its
//! own capabilities register: HWP is switched on (`IA32_PM_ENABLE`, one-way)
//! or CPPC enabled before the capabilities are read, as the architecture
//! requires, and a CPU whose capabilities read as zero (the firmware did not
//! give the OS the control) is refused, not guessed at.
//!
//! The OPP's frequency picks the level by linear interpolation between the
//! domain's slowest and fastest OPP onto the CPU's `[lowest, highest]`, rounded
//! up so the request is never below what the OPP implies (the deadline floor
//! is expressed in OPPs). The fastest OPP releases the range
//! (`[lowest, highest]`, desired level 0: the hardware chooses): it is what
//! the machine did before the framework touched it, and what "put the clock
//! back" means ([`boot_khz`]). Any other OPP pins the CPU (`min = max =
//! level`). The request is read back, and a CPU that did not keep it (package
//! control, a locked register) is refused. The other fields of the request
//! (energy-performance preference, activity window) are kept as the firmware
//! set them.
//!
//! What the framework decides is not this module's: the heat cap and the
//! real-time and safety floors are applied by `azos_energy::thermal::Thermal::limit`
//! before [`OppActuator::set_opp`] is called, so a request is only ever for an
//! OPP at or above the floor, and within `[lowest, highest]` by construction.
//!
//! A CPU that takes no request ([`Perf::None`]) is the
//! [`azos_energy::opp::NoActuator`] case: every request is
//! [`ActuateError::Unsupported`], the runtime raises the degrade level instead.
//!
//! # Energy
//!
//! [`X86Pstate::energy`] samples the package energy counter (a 32-bit count of
//! `1 / 2^ESU` joules, `ESU` in bits 12:8 of the power-unit register) and
//! accumulates microjoules across its wrap. The thermal task calls it once per
//! tick and shows the total and the mean power of the last interval in
//! `/proc/thermal`.

use azos_energy::model::{EnergyModel, Opp, MAX_DOMAINS, MAX_MODEL_CPUS};
use azos_energy::opp::{ActuateError, OppActuator};

// ── MSRs ─────────────────────────────────────────────────────────────────────

/// `MSR_RAPL_POWER_UNIT` (Intel).
pub const MSR_RAPL_POWER_UNIT: u32 = 0x606;
/// `MSR_PKG_ENERGY_STATUS` (Intel).
pub const MSR_PKG_ENERGY_STATUS: u32 = 0x611;
/// `IA32_PM_ENABLE`: bit 0 switches HWP on (one-way until reset).
pub const IA32_PM_ENABLE: u32 = 0x770;
/// `IA32_HWP_CAPABILITIES`.
pub const IA32_HWP_CAPABILITIES: u32 = 0x771;
/// `IA32_HWP_REQUEST`.
pub const IA32_HWP_REQUEST: u32 = 0x774;
/// `MSR_AMD_RAPL_POWER_UNIT`.
pub const MSR_AMD_RAPL_POWER_UNIT: u32 = 0xC001_0299;
/// `MSR_AMD_PKG_ENERGY_STATUS`.
pub const MSR_AMD_PKG_ENERGY_STATUS: u32 = 0xC001_029B;
/// `MSR_AMD_CPPC_CAP1`: the performance levels of the part.
pub const MSR_AMD_CPPC_CAP1: u32 = 0xC001_02B0;
/// `MSR_AMD_CPPC_ENABLE`: bit 0 enables CPPC.
pub const MSR_AMD_CPPC_ENABLE: u32 = 0xC001_02B1;
/// `MSR_AMD_CPPC_REQ`: maximum, minimum, desired level and preference.
pub const MSR_AMD_CPPC_REQ: u32 = 0xC001_02B3;

/// The MSRs a function-call IPI may read or write on another CPU: the ones
/// the actuator drives, and nothing else (the IPI handler runs the access in
/// interrupt context on a CPU that did not ask for it). The meter's registers
/// are package-wide and read on the CPU that runs the tick.
pub const fn is_remote_msr(msr: u32) -> bool {
    matches!(
        msr,
        IA32_PM_ENABLE | IA32_HWP_CAPABILITIES | IA32_HWP_REQUEST | MSR_AMD_CPPC_CAP1 | MSR_AMD_CPPC_ENABLE | MSR_AMD_CPPC_REQ
    )
}

// ── What the board has ───────────────────────────────────────────────────────

/// How a level is requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perf {
    /// No way: the [`azos_energy::opp::NoActuator`] case.
    None,
    /// Intel HWP.
    Hwp,
    /// AMD CPPC.
    Cppc,
}

/// How energy is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meter {
    /// No counter.
    None,
    /// Intel RAPL.
    Intel,
    /// AMD RAPL.
    Amd,
}

/// What the probe found, as this module names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hw {
    /// Level request.
    pub perf: Perf,
    /// Energy counter.
    pub meter: Meter,
}

/// What the kernel gives the board to reach the CPU. `cpu` is a logical CPU
/// number of the energy model's masks.
pub trait Platform {
    /// The CPU that runs the caller.
    fn this_cpu(&self) -> usize;
    /// Whether `cpu` is running (a CPU that is not cannot take a request).
    fn cpu_online(&self, cpu: usize) -> bool;
    /// `rdmsr` on `cpu`; `None` if it could not be read (the CPU did not
    /// answer in time). Only MSRs [`is_remote_msr`] names are asked of another
    /// CPU.
    fn rdmsr(&mut self, cpu: usize, msr: u32) -> Option<u64>;
    /// `wrmsr` on `cpu`; false if it could not be written.
    fn wrmsr(&mut self, cpu: usize, msr: u32, v: u64) -> bool;
}

// ── Pure arithmetic ──────────────────────────────────────────────────────────

/// A CPU's performance levels (unitless; Intel HWP and AMD CPPC both use
/// 8-bit levels on a scale of their own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfRange {
    /// The lowest level the part runs at.
    pub lowest: u8,
    /// The highest level (the top of its turbo).
    pub highest: u8,
}

impl PerfRange {
    /// From `IA32_HWP_CAPABILITIES`: highest 7:0, guaranteed 15:8, most
    /// efficient 23:16, lowest 31:24. A register that reads zero, or whose
    /// lowest is above its highest, is not a capability (HWP not given to the
    /// OS): `None`.
    pub const fn from_hwp(caps: u64) -> Option<Self> {
        Self::checked((caps >> 24) as u8, caps as u8)
    }

    /// From `MSR_AMD_CPPC_CAP1`: highest 31:24, nominal 23:16, lowest
    /// non-linear 15:8, lowest 7:0.
    pub const fn from_cppc(cap1: u64) -> Option<Self> {
        Self::checked(cap1 as u8, (cap1 >> 24) as u8)
    }

    const fn checked(lowest: u8, highest: u8) -> Option<Self> {
        if lowest == 0 || highest == 0 || lowest > highest { None } else { Some(Self { lowest, highest }) }
    }

    /// The level that runs at `khz` when `slow..=fast` kHz (the domain's
    /// slowest and fastest OPP) is laid on `[lowest, highest]`: linear,
    /// rounded up, clamped. A domain with one OPP (`fast <= slow`) is at
    /// `highest`.
    pub const fn level_for(&self, khz: u32, slow: u32, fast: u32) -> u8 {
        if fast <= slow || khz >= fast {
            return self.highest;
        }
        if khz <= slow {
            return self.lowest;
        }
        let span = (self.highest - self.lowest) as u64;
        let num = (khz - slow) as u64 * span;
        let den = (fast - slow) as u64;
        self.lowest + ((num + den - 1) / den) as u8
    }
}

/// `IA32_HWP_REQUEST` with the minimum and maximum set and the desired level
/// zero (the hardware chooses between them); the energy-performance
/// preference and the activity window stay as `cur` has them. Package control
/// (bit 42) is cleared: with it set the CPU would follow the package register
/// and ignore this one.
pub const fn hwp_request(cur: u64, min: u8, max: u8) -> u64 {
    const KEEP: u64 = !(0x00FF_FFFF | 1 << 42);
    cur & KEEP | min as u64 | (max as u64) << 8
}

/// `MSR_AMD_CPPC_REQ` with the same meaning: maximum 7:0, minimum 15:8,
/// desired 23:16 (zero), preference 31:24 kept.
pub const fn cppc_request(cur: u64, min: u8, max: u8) -> u64 {
    const KEEP: u64 = !0x00FF_FFFF;
    cur & KEEP | max as u64 | (min as u64) << 8
}

/// The minimum and maximum of a request register are in its low 16 bits,
/// whichever way round: the part the read-back comparison looks at.
const fn request_window(v: u64) -> u16 {
    v as u16
}

/// The OPP a domain runs at when the framework has not touched it: with a
/// level request in the CPU the firmware leaves the whole range open (HWP's
/// and CPPC's reset state is the hardware choosing between lowest and
/// highest), which is the domain's fastest OPP and what a cap is lifted back
/// to. Neither register can be read to confirm it before the control is
/// switched on (`IA32_HWP_REQUEST` raises #GP until `IA32_PM_ENABLE`), so
/// this is the assumption, stated once. A CPU with no level request has no
/// clock the framework knows.
pub fn boot_khz(hw: Hw, model: &EnergyModel, domain: usize) -> Option<u32> {
    if hw.perf == Perf::None {
        return None;
    }
    model.domains().get(domain).and_then(|d| d.opps().last()).map(|o| o.freq_khz)
}

// ── RAPL ─────────────────────────────────────────────────────────────────────

/// The package energy counter across its 32-bit wrap.
#[derive(Clone, Copy, Debug)]
pub struct Rapl {
    esu: u8,
    last: u32,
    /// Counts accumulated since the first sample.
    counts: u64,
}

/// A sample of the counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Energy {
    /// Energy since the first sample, microjoules.
    pub total_uj: u64,
    /// Mean power over the last interval, milliwatts (0 at the first sample).
    pub power_mw: u32,
}

impl Rapl {
    /// A counter of `unit` (the power-unit register: energy unit in bits
    /// 12:8, in `1 / 2^ESU` joules) whose first reading is `first`. `None` for
    /// an `ESU` of 0 (not a unit any part has).
    pub const fn new(unit: u64, first: u32) -> Option<Self> {
        let esu = ((unit >> 8) & 0x1F) as u8;
        if esu == 0 { None } else { Some(Self { esu, last: first, counts: 0 }) }
    }

    /// Add the reading `raw`, `dt_ms` after the last one, and say what the
    /// counter now shows. One wrap per interval is assumed (hours at the
    /// powers a package draws).
    pub fn sample(&mut self, raw: u32, dt_ms: u64) -> Energy {
        let d = raw.wrapping_sub(self.last);
        self.last = raw;
        self.counts += d as u64;
        let to_uj = |c: u64| ((c as u128 * 1_000_000) >> self.esu) as u64;
        let power_mw = if dt_ms == 0 { 0 } else { (to_uj(d as u64) / dt_ms).min(u32::MAX as u64) as u32 };
        Energy { total_uj: to_uj(self.counts), power_mw }
    }
}

// ── The state ────────────────────────────────────────────────────────────────

/// The transport code of a CPU that did not answer a register access.
const NO_ANSWER: i32 = -110;

/// What is known of one CPU's level request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuPerf {
    /// Not looked at yet.
    Unprobed,
    /// Enabled, and this is its range.
    Ready(PerfRange),
    /// The CPU takes no request (the firmware kept the control, the register
    /// refused): never asked again.
    Unusable,
}

/// The actuator's and the meter's state, kept by the kernel across ticks. A
/// tick pairs it with the kernel's [`Platform`] in an [`Actuator`].
pub struct X86Pstate {
    hw: Hw,
    dom_cpus: [u32; MAX_DOMAINS],
    /// Per domain, the frequency of its slowest and fastest OPP, kHz.
    dom_khz: [(u32, u32); MAX_DOMAINS],
    cpu: [CpuPerf; MAX_MODEL_CPUS],
    rapl: Option<Rapl>,
    /// Set once the meter was looked for (a failed look is not repeated).
    rapl_tried: bool,
    last_sample_ms: Option<u64>,
    energy: Energy,
    /// Level requests the CPUs kept.
    pub applied: u32,
    /// Level requests a CPU refused or could not take.
    pub refused: u32,
}

impl X86Pstate {
    /// The state over `model`'s domains.
    pub fn new(hw: Hw, model: &EnergyModel) -> Self {
        let mut dom_cpus = [0; MAX_DOMAINS];
        let mut dom_khz = [(0, 0); MAX_DOMAINS];
        for (i, d) in model.domains().iter().enumerate().take(MAX_DOMAINS) {
            dom_cpus[i] = d.cpus;
            let o = d.opps();
            dom_khz[i] = (o.first().map_or(0, |o| o.freq_khz), o.last().map_or(0, |o| o.freq_khz));
        }
        Self {
            hw,
            dom_cpus,
            dom_khz,
            cpu: [CpuPerf::Unprobed; MAX_MODEL_CPUS],
            rapl: None,
            rapl_tried: false,
            last_sample_ms: None,
            energy: Energy::default(),
            applied: 0,
            refused: 0,
        }
    }

    /// What the board has.
    pub fn hw(&self) -> Hw {
        self.hw
    }

    /// The actuator for one tick over the kernel's access to the CPU.
    pub fn actuator<P: Platform>(&mut self, platform: P) -> Actuator<'_, P> {
        Actuator { state: self, platform }
    }

    /// The energy counter as of the last [`Self::energy`].
    pub fn last_energy(&self) -> Energy {
        self.energy
    }

    /// The range of `cpu`, if it is enabled and has one.
    pub fn range(&self, cpu: usize) -> Option<PerfRange> {
        match self.cpu.get(cpu) {
            Some(CpuPerf::Ready(r)) => Some(*r),
            _ => None,
        }
    }

    /// Sample the energy counter at `now_ms`. The first call finds the meter
    /// (reads the unit and the first count); a part that has none, or whose
    /// registers do not read, never gets another look.
    pub fn energy<P: Platform>(&mut self, p: &mut P, now_ms: u64) -> Option<Energy> {
        let (unit_msr, status_msr) = match self.hw.meter {
            Meter::None => return None,
            Meter::Intel => (MSR_RAPL_POWER_UNIT, MSR_PKG_ENERGY_STATUS),
            Meter::Amd => (MSR_AMD_RAPL_POWER_UNIT, MSR_AMD_PKG_ENERGY_STATUS),
        };
        let cpu = p.this_cpu();
        if self.rapl.is_none() {
            if self.rapl_tried {
                return None;
            }
            self.rapl_tried = true;
            let unit = p.rdmsr(cpu, unit_msr)?;
            let first = p.rdmsr(cpu, status_msr)? as u32;
            self.rapl = Rapl::new(unit, first);
            self.last_sample_ms = Some(now_ms);
            return self.rapl.map(|_| self.energy);
        }
        let raw = p.rdmsr(cpu, status_msr)? as u32;
        let dt = now_ms.saturating_sub(self.last_sample_ms.unwrap_or(now_ms));
        self.last_sample_ms = Some(now_ms);
        self.energy = self.rapl.as_mut()?.sample(raw, dt);
        Some(self.energy)
    }

    /// Enable the level control of `cpu` and read its range.
    fn bring_up<P: Platform>(&mut self, p: &mut P, cpu: usize) -> Result<PerfRange, ActuateError> {
        match self.cpu.get(cpu) {
            Some(CpuPerf::Ready(r)) => return Ok(*r),
            Some(CpuPerf::Unusable) | None => return Err(ActuateError::Unsupported),
            Some(CpuPerf::Unprobed) => {}
        }
        let (enable, caps, from): (u32, u32, fn(u64) -> Option<PerfRange>) = match self.hw.perf {
            Perf::Hwp => (IA32_PM_ENABLE, IA32_HWP_CAPABILITIES, PerfRange::from_hwp),
            Perf::Cppc => (MSR_AMD_CPPC_ENABLE, MSR_AMD_CPPC_CAP1, PerfRange::from_cppc),
            Perf::None => return Err(ActuateError::Unsupported),
        };
        // A CPU that did not answer is not condemned: it may answer next tick.
        let on = p.rdmsr(cpu, enable).ok_or(ActuateError::Fault(NO_ANSWER))?;
        if on & 1 == 0 {
            // HWP's enable is one-way; CPPC's is the OS's to set.
            if !p.wrmsr(cpu, enable, on | 1) {
                return Err(ActuateError::Fault(NO_ANSWER));
            }
            if p.rdmsr(cpu, enable).ok_or(ActuateError::Fault(NO_ANSWER))? & 1 == 0 {
                self.cpu[cpu] = CpuPerf::Unusable;
                return Err(ActuateError::Refused);
            }
        }
        let word = p.rdmsr(cpu, caps).ok_or(ActuateError::Fault(NO_ANSWER))?;
        match from(word) {
            Some(r) => {
                self.cpu[cpu] = CpuPerf::Ready(r);
                Ok(r)
            }
            None => {
                self.cpu[cpu] = CpuPerf::Unusable;
                Err(ActuateError::Refused)
            }
        }
    }

    /// Put `cpu` at `[min, max]` and check that it kept it.
    fn request<P: Platform>(&mut self, p: &mut P, cpu: usize, min: u8, max: u8) -> Result<(), ActuateError> {
        let (msr, build): (u32, fn(u64, u8, u8) -> u64) = match self.hw.perf {
            Perf::Hwp => (IA32_HWP_REQUEST, hwp_request),
            Perf::Cppc => (MSR_AMD_CPPC_REQ, cppc_request),
            Perf::None => return Err(ActuateError::Unsupported),
        };
        let cur = p.rdmsr(cpu, msr).ok_or(ActuateError::Fault(NO_ANSWER))?;
        let want = build(cur, min, max);
        if !p.wrmsr(cpu, msr, want) {
            return Err(ActuateError::Fault(NO_ANSWER));
        }
        let kept = p.rdmsr(cpu, msr).ok_or(ActuateError::Fault(NO_ANSWER))?;
        if request_window(kept) != request_window(want) {
            return Err(ActuateError::Refused);
        }
        Ok(())
    }
}

/// A tick's actuator: the state and the kernel's access to the CPU. It is the
/// `A` of [`crate::x86_sensor::X86Board`].
pub struct Actuator<'a, P> {
    state: &'a mut X86Pstate,
    platform: P,
}

impl<P: Platform> OppActuator for Actuator<'_, P> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        let st = &mut *self.state;
        if st.hw.perf == Perf::None || domain >= MAX_DOMAINS || st.dom_cpus[domain] == 0 {
            return Err(ActuateError::Unsupported);
        }
        let (slow, fast) = st.dom_khz[domain];
        let release = opp.freq_khz >= fast;
        let mut first_err = None;
        let mut done = 0u32;
        for cpu in 0..MAX_MODEL_CPUS {
            if st.dom_cpus[domain] & 1 << cpu == 0 || !self.platform.cpu_online(cpu) {
                continue;
            }
            let step = st.bring_up(&mut self.platform, cpu).and_then(|r| {
                let (min, max) = if release {
                    (r.lowest, r.highest)
                } else {
                    let l = r.level_for(opp.freq_khz, slow, fast);
                    (l, l)
                };
                st.request(&mut self.platform, cpu, min, max)
            });
            match step {
                Ok(()) => {
                    done += 1;
                    st.applied += 1;
                }
                Err(e) => {
                    st.refused += 1;
                    first_err.get_or_insert(e);
                }
            }
        }
        // The domain moved only if every online CPU of it did; a partial move
        // is reported as the failure it is (the runtime then raises the level),
        // and the next request starts from each CPU's read-back anyway.
        match (first_err, done) {
            (None, 0) => Err(ActuateError::Refused),
            (None, _) => Ok(()),
            (Some(e), _) => Err(e),
        }
    }
}
