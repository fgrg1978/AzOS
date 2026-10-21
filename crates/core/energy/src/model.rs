// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `EnergyModel`: what each performance domain can run at and
//! what it costs. Data, never code.
//!
//! A **performance domain** is a set of CPUs that share a clock (and so an
//! operating point). Per domain: its operating points (OPPs)
//! `{freq_khz, capacity, power_mw}`, slowest first, and its idle states
//! `{name, exit_latency_us, target_residency_us, power_mw}`, shallowest first.
//!
//! **Capacity** is on [`CAPACITY_SCALE`]: 1024 is the fastest CPU of the
//! machine at its fastest OPP, so the capacities of different domains compare
//! directly (a little core at its top OPP might be 400).
//!
//! # Sources, in order ([`resolve`])
//!
//! 1. The signed topology (`SCHED.TOML` `[energy.domain.NAME]` sections).
//! 2. The DTB (`operating-points-v2`, `idle-states`), see [`crate::dt`].
//! 3. CPUID, where the CPUs report a core type (x86 hybrid parts), see
//!    [`EnergyModel::from_core_classes`]. Only when the DTB carries no OPP
//!    table at all.
//! 4. None: every seam keeps today's behaviour.
//!
//! A model that fails [`EnergyModel::validate`] is not used: the outcome is
//! "none", and the fault is reported. A topology model that fails does **not**
//! fall through to the DTB: the signed file named a model, and replacing it
//! with one its signer never saw would be a decision nobody made. Nothing in
//! stages E0–E2 acts on the model, so refusing one costs nothing but the log
//! line; halting the boot over it would.

/// Performance domains one model holds.
pub const MAX_DOMAINS: usize = 4;
/// Operating points per domain.
pub const MAX_OPPS: usize = 16;
/// Idle states per domain.
pub const MAX_IDLE_STATES: usize = 4;
/// Bytes of an idle-state name.
pub const IDLE_NAME_LEN: usize = 16;
/// Capacity of the fastest CPU at its fastest OPP.
pub const CAPACITY_SCALE: u16 = 1024;
/// CPUs a domain's mask can name (`cpus` is a `u32`).
pub const MAX_MODEL_CPUS: usize = 32;

/// One operating point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opp {
    /// Core clock, kHz.
    pub freq_khz: u32,
    /// Work per unit time at this OPP, on [`CAPACITY_SCALE`].
    pub capacity: u16,
    /// Power of one CPU of the domain running flat out at this OPP, mW.
    pub power_mw: u32,
}

impl Opp {
    /// All zero.
    pub const EMPTY: Self = Self { freq_khz: 0, capacity: 0, power_mw: 0 };
}

/// One idle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleState {
    name: [u8; IDLE_NAME_LEN],
    name_len: u8,
    /// Time from the wake-up event to running again, us.
    pub exit_latency_us: u32,
    /// Shortest stay for which entering the state saves energy, us.
    pub target_residency_us: u32,
    /// Power of one CPU in the state, mW. 0 = not known (a DTB does not say).
    pub power_mw: u32,
    /// The CPU's register and translation context is lost in the state: a
    /// power-down state, entered through the arch's saved-context path and
    /// resumed at the secondary entry, so its real exit latency also holds
    /// the firmware's re-entry and the kernel's restore. Not known from the
    /// DTB alone (the PSCI `power_state` format decides it), so the boot sets
    /// it ([`PerfDomain::mark_context_loss`]) from what the arch will enter.
    /// A real-time CPU never enters one ([`crate::idle::allowed`]).
    pub loses_context: bool,
}

impl IdleState {
    /// All zero, no name.
    pub const EMPTY: Self = Self {
        name: [0; IDLE_NAME_LEN],
        name_len: 0,
        exit_latency_us: 0,
        target_residency_us: 0,
        power_mw: 0,
        loses_context: false,
    };

    /// A state named `name` (truncated to [`IDLE_NAME_LEN`] bytes).
    pub fn new(name: &[u8], exit_latency_us: u32, target_residency_us: u32, power_mw: u32) -> Self {
        let mut s = Self { exit_latency_us, target_residency_us, power_mw, ..Self::EMPTY };
        let n = name.len().min(IDLE_NAME_LEN);
        s.name[..n].copy_from_slice(&name[..n]);
        s.name_len = n as u8;
        s
    }

    /// The name's bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// CPUs sharing one clock, with their OPPs and idle states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfDomain {
    /// The CPUs, bit `n` = CPU `n` (the encoding of a profile's `cpu_mask`).
    pub cpus: u32,
    /// The clock at which the safety path's WCET bounds were established,
    /// kHz (invariant I6: no governor goes below the first OPP at or above
    /// it). 0 = not declared: the fastest OPP is the floor.
    pub wcet_ref_khz: u32,
    opps: [Opp; MAX_OPPS],
    n_opps: u8,
    idle: [IdleState; MAX_IDLE_STATES],
    n_idle: u8,
}

impl PerfDomain {
    /// No CPU, no OPP, no idle state.
    pub const EMPTY: Self = Self {
        cpus: 0,
        wcet_ref_khz: 0,
        opps: [Opp::EMPTY; MAX_OPPS],
        n_opps: 0,
        idle: [IdleState::EMPTY; MAX_IDLE_STATES],
        n_idle: 0,
    };

    /// An empty domain over `cpus`.
    pub const fn new(cpus: u32) -> Self {
        Self { cpus, ..Self::EMPTY }
    }

    /// Operating points, in declaration order (validated: slowest first).
    pub fn opps(&self) -> &[Opp] {
        &self.opps[..self.n_opps as usize]
    }

    /// Idle states, in declaration order (validated: shallowest first).
    pub fn idle_states(&self) -> &[IdleState] {
        &self.idle[..self.n_idle as usize]
    }

    /// Append an OPP. `Err(())` when [`MAX_OPPS`] are already there.
    pub fn push_opp(&mut self, opp: Opp) -> Result<(), ()> {
        if self.n_opps as usize >= MAX_OPPS {
            return Err(());
        }
        self.opps[self.n_opps as usize] = opp;
        self.n_opps += 1;
        Ok(())
    }

    /// Mark the idle states that lose the CPU's context: bit `d - 1` of
    /// `depths` is depth `d`, the `d`-th listed state (depth 0, `wfi`, never
    /// does). Bits past the states the domain has are ignored.
    pub fn mark_context_loss(&mut self, depths: u8) {
        for d in 1..self.n_idle as usize {
            if depths >> (d - 1) & 1 != 0 {
                self.idle[d].loses_context = true;
            }
        }
    }

    /// Append an idle state. `Err(())` when [`MAX_IDLE_STATES`] are there.
    pub fn push_idle(&mut self, s: IdleState) -> Result<(), ()> {
        if self.n_idle as usize >= MAX_IDLE_STATES {
            return Err(());
        }
        self.idle[self.n_idle as usize] = s;
        self.n_idle += 1;
        Ok(())
    }

    /// The fastest OPP's capacity (the last one, once validated), 0 if none.
    pub fn max_capacity(&self) -> u16 {
        self.opps().last().map_or(0, |o| o.capacity)
    }
}

/// Where a model came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelSource {
    /// No model: today's behaviour everywhere.
    None,
    /// The signed topology's `[energy.domain.*]` sections.
    Topology,
    /// The DTB's `operating-points-v2` / `idle-states`.
    Dtb,
    /// The core types the CPUs report through CPUID (x86 hybrid parts):
    /// capacities by class, power in relative units
    /// ([`EnergyModel::from_core_classes`]).
    Cpuid,
    /// The board firmware's clock range (Raspberry Pi: the VideoCore
    /// mailbox's ARM clock minimum and maximum), with power figures that are a
    /// declared placeholder ([`EnergyModel::from_clock_range`]).
    Firmware,
}

impl ModelSource {
    /// Lower-case name, for the boot log.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Topology => "topology",
            Self::Dtb => "dtb",
            Self::Cpuid => "cpuid",
            Self::Firmware => "firmware",
        }
    }
}

/// The energy model of the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnergyModel {
    /// Where it came from; [`ModelSource::None`] for an empty model.
    pub source: ModelSource,
    domains: [PerfDomain; MAX_DOMAINS],
    n_domains: u8,
}

impl EnergyModel {
    /// No model.
    pub const NONE: Self =
        Self { source: ModelSource::None, domains: [PerfDomain::EMPTY; MAX_DOMAINS], n_domains: 0 };

    /// An empty model that will be filled from `source`.
    pub const fn from_source(source: ModelSource) -> Self {
        Self { source, ..Self::NONE }
    }

    /// Whether a model was declared (validated or not).
    #[inline]
    pub fn is_present(&self) -> bool {
        !matches!(self.source, ModelSource::None)
    }

    /// The domains, in declaration order.
    pub fn domains(&self) -> &[PerfDomain] {
        &self.domains[..self.n_domains as usize]
    }

    /// Mutable access to the last domain pushed, for a parser filling it in.
    pub fn last_domain_mut(&mut self) -> Option<&mut PerfDomain> {
        match self.n_domains {
            0 => None,
            n => Some(&mut self.domains[n as usize - 1]),
        }
    }

    /// Mark domain `domain`'s idle states that lose the CPU's context
    /// ([`PerfDomain::mark_context_loss`]). A domain that does not exist is
    /// ignored.
    pub fn mark_context_loss(&mut self, domain: usize, depths: u8) {
        if domain < self.n_domains as usize {
            self.domains[domain].mark_context_loss(depths);
        }
    }

    /// Append a domain. `Err(())` when [`MAX_DOMAINS`] are already there.
    pub fn push_domain(&mut self, d: PerfDomain) -> Result<(), ()> {
        if self.n_domains as usize >= MAX_DOMAINS {
            return Err(());
        }
        self.domains[self.n_domains as usize] = d;
        self.n_domains += 1;
        Ok(())
    }

    /// Total OPPs over all domains (for the boot log).
    pub fn opp_count(&self) -> usize {
        self.domains().iter().map(|d| d.opps().len()).sum()
    }

    /// The domain CPU `cpu` belongs to.
    pub fn domain_of(&self, cpu: usize) -> Option<&PerfDomain> {
        if cpu >= MAX_MODEL_CPUS {
            return None;
        }
        self.domains().iter().find(|d| d.cpus & (1 << cpu) != 0)
    }

    /// Check the model against a machine of `num_cpus` CPUs.
    ///
    /// * At least one domain; each names at least one CPU, every CPU it names
    ///   exists, no CPU is in two domains, and every CPU is in one (a model
    ///   that leaves a CPU out cannot compare placements on it).
    /// * Per domain at least one OPP; frequencies non-zero and strictly
    ///   increasing; capacities in `1..=1024` and non-decreasing; power
    ///   non-zero and strictly increasing. The fastest OPP of some domain has
    ///   capacity exactly 1024 (the scale is relative to that CPU).
    /// * Idle states: a name; exit latency non-decreasing; target residency at
    ///   least the exit latency; power non-increasing where known (0 = not
    ///   known, as from a DTB).
    ///
    /// The first fault found is returned, in that order.
    pub fn validate(&self, num_cpus: usize) -> Result<(), ModelFault> {
        if cfg!(feature = "validate-canary") {
            return Ok(());
        }
        let num_cpus = num_cpus.min(MAX_MODEL_CPUS);
        if self.n_domains == 0 {
            return Err(ModelFault::NoDomains);
        }
        let mut seen = 0u32;
        let mut full = false;
        for (di, d) in self.domains().iter().enumerate() {
            let di = di as u8;
            if d.cpus == 0 {
                return Err(ModelFault::EmptyCpuMask { domain: di });
            }
            let past = if num_cpus >= 32 { 0 } else { d.cpus >> num_cpus };
            if past != 0 {
                return Err(ModelFault::CpuAbsent { domain: di, cpu: (past.trailing_zeros() as usize + num_cpus) as u8 });
            }
            if d.cpus & seen != 0 {
                return Err(ModelFault::CpuInTwoDomains { domain: di, cpu: (d.cpus & seen).trailing_zeros() as u8 });
            }
            seen |= d.cpus;
            if d.opps().is_empty() {
                return Err(ModelFault::NoOpps { domain: di });
            }
            let mut prev = Opp::EMPTY;
            for (oi, o) in d.opps().iter().enumerate() {
                let at = (di, oi as u8);
                if o.freq_khz == 0 {
                    return Err(ModelFault::ZeroFrequency { domain: at.0, opp: at.1 });
                }
                if o.capacity == 0 || o.capacity > CAPACITY_SCALE {
                    return Err(ModelFault::CapacityOutOfRange { domain: at.0, opp: at.1 });
                }
                if o.power_mw == 0 {
                    return Err(ModelFault::ZeroPower { domain: at.0, opp: at.1 });
                }
                if oi > 0 {
                    if o.freq_khz <= prev.freq_khz {
                        return Err(ModelFault::FrequencyNotIncreasing { domain: at.0, opp: at.1 });
                    }
                    if o.capacity < prev.capacity {
                        return Err(ModelFault::CapacityDecreasing { domain: at.0, opp: at.1 });
                    }
                    if o.power_mw <= prev.power_mw {
                        return Err(ModelFault::PowerNotIncreasing { domain: at.0, opp: at.1 });
                    }
                }
                prev = *o;
            }
            full |= d.max_capacity() == CAPACITY_SCALE;
            let mut prev_idle: Option<IdleState> = None;
            for (si, s) in d.idle_states().iter().enumerate() {
                let at = (di, si as u8);
                if s.name_len == 0 {
                    return Err(ModelFault::IdleNameEmpty { domain: at.0, state: at.1 });
                }
                if s.target_residency_us < s.exit_latency_us {
                    return Err(ModelFault::ResidencyBelowLatency { domain: at.0, state: at.1 });
                }
                if let Some(p) = prev_idle {
                    if s.exit_latency_us < p.exit_latency_us {
                        return Err(ModelFault::ExitLatencyDecreasing { domain: at.0, state: at.1 });
                    }
                    if s.power_mw != 0 && p.power_mw != 0 && s.power_mw > p.power_mw {
                        return Err(ModelFault::IdlePowerIncreasing { domain: at.0, state: at.1 });
                    }
                }
                prev_idle = Some(*s);
            }
        }
        let all = if num_cpus >= 32 { u32::MAX } else { (1u32 << num_cpus) - 1 };
        if seen & all != all {
            return Err(ModelFault::CpuUncovered { cpu: (!seen & all).trailing_zeros() as u8 });
        }
        if !full {
            return Err(ModelFault::NoFullCapacity);
        }
        Ok(())
    }
}

// ── The CPUID source (x86 hybrid parts) ──────────────────────────────────────

/// What a CPU says about its own core type (CPUID leaf 0x1A on Intel, leaf
/// 0x80000026 on AMD), as the energy model needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreClass {
    /// The CPU reports no core type: it does not claim to be part of a hybrid
    /// machine.
    Uniform,
    /// A performance core (Intel P / Core, AMD Zen 5).
    Performance,
    /// An efficiency core (Intel E / Atom, AMD Zen 5c).
    Efficiency,
    /// The CPU claims a core type this code does not know, or did not report
    /// one at all (it never came up).
    Unknown,
}

/// Capacity of an efficiency core at its only OPP, on [`CAPACITY_SCALE`]. CPUID
/// names the class, not the speed: this is the single-thread ratio of a
/// Gracemont/Crestmont core to its Golden/Redwood Cove sibling at stock
/// clocks (about 0.55 to 0.6), and of a Zen 5c core to a Zen 5 (about 0.65).
/// A machine that can read the real figure (HWP/CPPC, ITD) should say it in
/// its topology.
pub const CPUID_EFFICIENCY_CAPACITY: u16 = 600;
/// Relative power of one performance core flat out. CPUID cannot read power;
/// these two figures are the model's assumption that an efficiency core does
/// a unit of work for about half the energy of a performance core
/// (`1800 / 600` against `6000 / 1024`), the ratio EAS compares. They are not
/// milliwatts of any measurement: a power cap in mW means nothing against
/// them, and only the ratio is used.
pub const CPUID_PERFORMANCE_POWER_MW: u32 = 6000;
/// Relative power of one efficiency core flat out, see
/// [`CPUID_PERFORMANCE_POWER_MW`].
pub const CPUID_EFFICIENCY_POWER_MW: u32 = 1800;

impl EnergyModel {
    /// The model of a machine whose CPUs report their core type: one domain
    /// of the performance cores and one of the efficiency cores, each with a
    /// single OPP at `ref_khz` (the one clock the kernel can read, the TSC
    /// rate: a label, nothing sets the clock) and the capacity and relative
    /// power of its class ([`CPUID_EFFICIENCY_CAPACITY`],
    /// [`CPUID_PERFORMANCE_POWER_MW`]). `classes[cpu]` is CPU `cpu`'s class;
    /// CPUs past [`MAX_MODEL_CPUS`] are not modelled.
    ///
    /// * `Ok(None)`: no CPU reports a core type, or all report the same one.
    ///   The machine is symmetric and CPUID has nothing to add.
    /// * `Err(CoreClassUnknown)`: some CPU is `Unknown`, or reports no type
    ///   among CPUs that do. A model that guessed its class could send a task
    ///   to the wrong kind of core.
    pub fn from_core_classes(classes: &[CoreClass], ref_khz: u32) -> Result<Option<Self>, ModelFault> {
        let classes = &classes[..classes.len().min(MAX_MODEL_CPUS)];
        let typed = classes.iter().any(|c| matches!(c, CoreClass::Performance | CoreClass::Efficiency));
        if let Some(cpu) = classes.iter().position(|c| match c {
            CoreClass::Unknown => true,
            CoreClass::Uniform => typed,
            _ => false,
        }) {
            return Err(ModelFault::CoreClassUnknown { cpu: cpu as u8 });
        }
        let mask = |want: CoreClass| {
            classes.iter().enumerate().filter(|(_, c)| **c == want).fold(0u32, |m, (i, _)| m | 1 << i)
        };
        let (perf, eff) = (mask(CoreClass::Performance), mask(CoreClass::Efficiency));
        if perf == 0 || eff == 0 {
            return Ok(None);
        }
        let mut m = Self::from_source(ModelSource::Cpuid);
        for (cpus, capacity, power_mw) in [
            (perf, CAPACITY_SCALE, CPUID_PERFORMANCE_POWER_MW),
            (eff, CPUID_EFFICIENCY_CAPACITY, CPUID_EFFICIENCY_POWER_MW),
        ] {
            let mut d = PerfDomain::new(cpus);
            // One OPP and two domains fit the limits by construction.
            let _ = d.push_opp(Opp { freq_khz: ref_khz, capacity, power_mw });
            let _ = m.push_domain(d);
        }
        Ok(Some(m))
    }

    /// [`Self::from_core_classes`] over the classes CPUs `0..n` reported:
    /// `report(cpu)` is `None` for a CPU that reported nothing (it did not come
    /// up, or not in time). Such a CPU is `Unknown`, so the model is refused,
    /// and `missing` names the CPUs (bit per CPU) so the refusal can say why.
    pub fn from_core_reports(
        n: usize,
        ref_khz: u32,
        report: impl Fn(usize) -> Option<CoreClass>,
    ) -> CoreReports {
        let n = n.min(MAX_MODEL_CPUS);
        let mut classes = [CoreClass::Unknown; MAX_MODEL_CPUS];
        let mut missing = 0u32;
        for (cpu, c) in classes.iter_mut().enumerate().take(n) {
            match report(cpu) {
                Some(k) => *c = k,
                None => missing |= 1 << cpu,
            }
        }
        CoreReports { model: Self::from_core_classes(&classes[..n], ref_khz).transpose(), missing }
    }
}

/// Power of one CPU flat out at the top of a firmware-derived table, mW.
/// **Unmeasured**: a declared placeholder of the Cortex-A76 class
/// ([`EnergyModel::from_clock_range`]); a signed topology's
/// `[energy.domain.*]` replaces the whole table with measured figures.
pub const FIRMWARE_PLACEHOLDER_MAX_POWER_MW: u32 = 2000;

impl EnergyModel {
    /// The model of a machine whose firmware reports one clock range for all
    /// its CPUs (the Raspberry Pi mailbox's ARM clock): one domain holding
    /// `cpus`, with an OPP at `min_khz`, one every `step_khz` above it, and one
    /// at `max_khz` (always the last, so the top capacity is exactly
    /// [`CAPACITY_SCALE`]). A range wider than [`MAX_OPPS`] OPPs takes the
    /// smallest whole multiple of `step_khz` that fits.
    ///
    /// * capacity is linear in the clock (`freq * 1024 / max`), at least 1;
    /// * power is a **placeholder, unmeasured**: [`FIRMWARE_PLACEHOLDER_MAX_POWER_MW`]
    ///   at the top, cubic in the clock below it (the clock and the voltage it
    ///   needs both fall with it), raised to keep each OPP above the one under
    ///   it so the model validates. It orders the OPPs and nothing else: the
    ///   energy-aware placement compares domains and this model has one.
    ///
    /// `Err(ClockRangeDegenerate)` for a zero minimum, a minimum not below the
    /// maximum, a zero step or no CPU.
    pub fn from_clock_range(cpus: u32, min_khz: u32, max_khz: u32, step_khz: u32) -> Result<Self, ModelFault> {
        if !cfg!(feature = "firmware-model-canary") && (cpus == 0 || step_khz == 0 || min_khz == 0 || min_khz >= max_khz) {
            return Err(ModelFault::ClockRangeDegenerate);
        }
        let span = u64::from(max_khz.saturating_sub(min_khz));
        let wanted = span.div_ceil(u64::from(step_khz.max(1)));
        // `MAX_OPPS` OPPs are `MAX_OPPS - 1` gaps.
        let step = u64::from(step_khz) * wanted.div_ceil((MAX_OPPS - 1) as u64).max(1);
        let mut m = Self::from_source(ModelSource::Firmware);
        let mut d = PerfDomain::new(cpus);
        let mut prev_power = 0u32;
        for i in 0..MAX_OPPS as u64 {
            let grid = u64::from(min_khz) + i * step;
            // The last OPP is the firmware's maximum itself, not the grid
            // point that passes it.
            let top = grid >= u64::from(max_khz);
            let at = if top && !cfg!(feature = "firmware-model-canary") { max_khz } else { grid as u32 };
            let capacity = (u64::from(at) * u64::from(CAPACITY_SCALE) / u64::from(max_khz.max(1))).clamp(1, u64::from(u16::MAX)) as u16;
            let cubic = (u128::from(FIRMWARE_PLACEHOLDER_MAX_POWER_MW) * u128::from(at).pow(3))
                .div_ceil(u128::from(max_khz.max(1)).pow(3)) as u32;
            let power_mw = cubic.max(prev_power + 1);
            prev_power = power_mw;
            d.push_opp(Opp { freq_khz: at, capacity, power_mw }).map_err(|_| ModelFault::TooManyOpps { domain: 0 })?;
            if top {
                break;
            }
        }
        m.push_domain(d).map_err(|_| ModelFault::TooManyDomains)?;
        Ok(m)
    }
}

/// What [`EnergyModel::from_core_reports`] made of the CPUs' reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreReports {
    /// As `resolve` takes it: `None` when the machine is symmetric.
    pub model: Option<Result<EnergyModel, ModelFault>>,
    /// CPUs (bit per CPU) that reported nothing.
    pub missing: u32,
}

// ── Energy-aware placement ───────────────────────────────────────────────────
//
// Pure arithmetic over an [`EnergyModel`] and a utilisation vector; the
// kernel (`azos_sched::energy`) gathers the vector and applies the answer,
// the host suite (`tests/host/energy-tests/src/eas.rs`) runs this code on a
// big.LITTLE model.
//
// Utilisation here is capacity-invariant: on [`CAPACITY_SCALE`], 1024 is the
// work the fastest CPU does at its fastest OPP in all of the time. A busy
// fraction (`util::SCALE`) becomes that by multiplying with the capacity of
// the OPP the CPU ran at.

/// A CPU is full when its utilisation reaches this percent of the capacity
/// of its domain's fastest OPP (Linux's 80%: `util * 1280 < capacity * 1024`).
pub const EAS_FIT_PCT: u64 = 80;

/// Margin over the largest utilisation of a domain when choosing the OPP it
/// would run at, percent. The schedutil headroom, so the placement predicts
/// the clock the governor will choose.
const EAS_HEADROOM_PCT: u64 = crate::governor::HEADROOM_PCT as u64;

/// A placement must save more than `1 / EAS_STAY_DIV` of the energy the task
/// costs on the CPU it last ran on to move it (a move costs a cold cache
/// that the model does not see): 1/16, about 6%, as Linux.
const EAS_STAY_DIV: u64 = 16;

/// What [`EnergyModel::eas_pick`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EasChoice {
    /// Place the task on this CPU.
    Cpu(usize),
    /// A CPU of the candidates is full, or the task fits none of them: the
    /// energy comparison does not hold, and the caller balances load instead.
    Overutilised,
}

/// A busy fraction `busy` (on [`crate::SCALE`], what the trackers report) of a
/// CPU running at capacity `capacity`, as capacity-invariant utilisation: the
/// share of the fastest CPU's fastest OPP that the work would take.
#[inline]
pub fn invariant_util(busy: u32, capacity: u16) -> u32 {
    (busy as u64 * capacity as u64 / crate::SCALE as u64) as u32
}

/// Whether utilisation `util` fits a CPU whose domain tops out at `cap`.
#[inline]
fn eas_fits(util: u64, cap: u16) -> bool {
    util * 100 < cap as u64 * EAS_FIT_PCT
}

/// Utilisation of `cpu` in `util`, 0 for a CPU past the slice.
#[inline]
fn eas_util_of(util: &[u32], cpu: usize) -> u64 {
    util.get(cpu).copied().unwrap_or(0) as u64
}

impl EnergyModel {
    /// Whether the CPUs differ in capacity: two domains whose fastest OPPs
    /// are not the same. Only then does where a task runs change what it
    /// costs by more than the idle states do.
    pub fn is_asymmetric(&self) -> bool {
        match self.domains().split_first() {
            Some((first, rest)) => rest.iter().any(|d| d.max_capacity() != first.max_capacity()),
            None => false,
        }
    }

    /// Whether some CPU of `cpus` is full: its utilisation (capacity
    /// invariant, see above) does not fit the capacity of its domain's
    /// fastest OPP. A CPU in no domain is not judged.
    pub fn eas_overutilised(&self, util: &[u32], cpus: u32) -> bool {
        self.domains().iter().any(|d| {
            let mut m = d.cpus & cpus;
            while m != 0 {
                let c = m.trailing_zeros() as usize;
                m &= m - 1;
                if !eas_fits(eas_util_of(util, c), d.max_capacity()) {
                    return true;
                }
            }
            false
        })
    }

    /// Where a task of utilisation `task_util` costs the least energy.
    ///
    /// `util[cpu]` is the utilisation of each CPU without the task,
    /// `prev_cpu` the CPU it last ran on, `candidates` the CPUs it may be
    /// placed on (the others still burn energy and are counted, but are never
    /// chosen and, being out of reach of this task, are not judged full).
    ///
    /// The model: a domain runs at the lowest OPP whose capacity covers its
    /// busiest CPU with [`governor::HEADROOM_PCT`](crate::governor::HEADROOM_PCT)
    /// to spare, and costs `power(OPP) * (sum of its CPUs' utilisation) /
    /// capacity(OPP)`: the power of one CPU flat out, times the CPUs' worth of
    /// work it holds. Putting the task on a CPU changes the cost of that CPU's
    /// domain only, so only the domain's cost before and after is compared.
    /// Per domain two CPUs are tried: the candidate with the most spare
    /// capacity (it lifts the domain's OPP the least) and `prev_cpu`, each
    /// only if the task still fits it. The task moves off `prev_cpu` for a
    /// saving of more than 1/16 of what it costs there; with no saving
    /// that large it stays.
    ///
    /// [`EasChoice::Overutilised`] when [`eas_overutilised`](Self::eas_overutilised)
    /// holds for `candidates`, or the task fits none of them.
    pub fn eas_pick(&self, util: &[u32], task_util: u32, prev_cpu: usize, candidates: u32) -> EasChoice {
        if self.eas_overutilised(util, candidates) {
            return EasChoice::Overutilised;
        }
        let task = task_util as u64;
        // The cost of domain `d` with `extra` on `at`; each CPU counted once.
        let cost = |d: &PerfDomain, at: Option<usize>| -> u64 {
            let (mut max, mut sum) = (0u64, 0u64);
            let mut m = d.cpus;
            while m != 0 {
                let c = m.trailing_zeros() as usize;
                m &= m - 1;
                let u = eas_util_of(util, c) + if at == Some(c) { task } else { 0 };
                max = max.max(u);
                sum += u;
            }
            let need = (max * (100 + EAS_HEADROOM_PCT)).div_ceil(100);
            let opps = d.opps();
            let Some(top) = opps.len().checked_sub(1) else { return 0 };
            let o = &opps[crate::governor::lowest_opp_with_capacity(d, need).min(top)];
            o.power_mw as u64 * sum * 1024 / o.capacity.max(1) as u64
        };
        let mut best: Option<(u64, usize)> = None;
        let mut prev: Option<u64> = None;
        for d in self.domains() {
            let mut reach = d.cpus & candidates;
            if reach == 0 {
                continue;
            }
            // Candidate with the most spare capacity that the task fits.
            let mut roomiest: Option<(u64, usize)> = None;
            while reach != 0 {
                let c = reach.trailing_zeros() as usize;
                reach &= reach - 1;
                let u = eas_util_of(util, c);
                if eas_fits(u + task, d.max_capacity()) && roomiest.is_none_or(|(least, _)| u < least) {
                    roomiest = Some((u, c));
                }
            }
            let Some((_, room)) = roomiest else { continue };
            let before = cost(d, None);
            let mut try_cpu = |c: usize| {
                let delta = cost(d, Some(c)).saturating_sub(before);
                if c == prev_cpu {
                    prev = Some(delta);
                }
                if best.is_none_or(|(b, _)| delta < b) {
                    best = Some((delta, c));
                }
            };
            try_cpu(room);
            if prev_cpu != room
                && prev_cpu < MAX_MODEL_CPUS
                && d.cpus & candidates & (1 << prev_cpu) != 0
                && eas_fits(eas_util_of(util, prev_cpu) + task, d.max_capacity())
            {
                try_cpu(prev_cpu);
            }
        }
        match (best, prev) {
            (None, _) => EasChoice::Overutilised,
            (Some((_, cpu)), None) => EasChoice::Cpu(cpu),
            (Some((delta, cpu)), Some(stay)) => {
                if cpu != prev_cpu && stay - delta > stay / EAS_STAY_DIV {
                    EasChoice::Cpu(cpu)
                } else {
                    EasChoice::Cpu(prev_cpu)
                }
            }
        }
    }
}

/// Why a model was refused, or could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelFault {
    /// No domain declared.
    NoDomains,
    /// More than [`MAX_DOMAINS`] domains.
    TooManyDomains,
    /// More than [`MAX_OPPS`] OPPs in a domain.
    TooManyOpps {
        /// Domain index.
        domain: u8,
    },
    /// More than [`MAX_IDLE_STATES`] idle states in a domain.
    TooManyIdleStates {
        /// Domain index.
        domain: u8,
    },
    /// A domain names no CPU.
    EmptyCpuMask {
        /// Domain index.
        domain: u8,
    },
    /// A domain names a CPU this machine does not have.
    CpuAbsent {
        /// Domain index.
        domain: u8,
        /// The first such CPU.
        cpu: u8,
    },
    /// A CPU is in two domains.
    CpuInTwoDomains {
        /// The second domain naming it.
        domain: u8,
        /// The CPU.
        cpu: u8,
    },
    /// A CPU of this machine is in no domain.
    CpuUncovered {
        /// The first such CPU.
        cpu: u8,
    },
    /// A domain has no OPP.
    NoOpps {
        /// Domain index.
        domain: u8,
    },
    /// An OPP's frequency is zero.
    ZeroFrequency {
        /// Domain index.
        domain: u8,
        /// OPP index.
        opp: u8,
    },
    /// An OPP is not faster than the one before it.
    FrequencyNotIncreasing {
        /// Domain index.
        domain: u8,
        /// OPP index.
        opp: u8,
    },
    /// An OPP's capacity is 0 or above 1024.
    CapacityOutOfRange {
        /// Domain index.
        domain: u8,
        /// OPP index.
        opp: u8,
    },
    /// A faster OPP has less capacity than a slower one.
    CapacityDecreasing {
        /// Domain index.
        domain: u8,
        /// OPP index.
        opp: u8,
    },
    /// An OPP's power is zero (or, from a DTB, not given).
    ZeroPower {
        /// Domain index.
        domain: u8,
        /// OPP index.
        opp: u8,
    },
    /// A faster OPP does not cost more power than a slower one.
    PowerNotIncreasing {
        /// Domain index.
        domain: u8,
        /// OPP index.
        opp: u8,
    },
    /// No domain reaches capacity 1024 at its fastest OPP.
    NoFullCapacity,
    /// An idle state has no name.
    IdleNameEmpty {
        /// Domain index.
        domain: u8,
        /// State index.
        state: u8,
    },
    /// A deeper idle state wakes faster than a shallower one.
    ExitLatencyDecreasing {
        /// Domain index.
        domain: u8,
        /// State index.
        state: u8,
    },
    /// An idle state's target residency is below its exit latency.
    ResidencyBelowLatency {
        /// Domain index.
        domain: u8,
        /// State index.
        state: u8,
    },
    /// A deeper idle state costs more power than a shallower one.
    IdlePowerIncreasing {
        /// Domain index.
        domain: u8,
        /// State index.
        state: u8,
    },
    /// DTB: an OPP has no `opp-hz`, or one that does not fit kHz in `u32`.
    DtBadFrequency,
    /// DTB: a phandle (`operating-points-v2`, `cpu-idle-states`) names no
    /// node that was read.
    DtUnknownPhandle,
    /// DTB: some CPUs have an OPP table and others none.
    DtPartialTables,
    /// DTB: a table that was read is overfull (more than the extractor keeps).
    DtTruncated,
    /// CPUID: this CPU's core type is unknown, or it reports none among CPUs
    /// that do ([`EnergyModel::from_core_classes`]).
    CoreClassUnknown {
        /// The first such CPU.
        cpu: u8,
    },
    /// Firmware: the clock range cannot make a table
    /// ([`EnergyModel::from_clock_range`]): a zero minimum, a minimum not
    /// below the maximum, a zero step or no CPU.
    ClockRangeDegenerate,
}

/// Energy policy of the machine, chosen by the signed topology only:
/// no Kconfig symbol and no `CONFIG.INI` key sets it.
///
/// Stages E0–E2 record it and act on none of them; `Performance`, the
/// default, is today's behaviour (I4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnergyMode {
    /// Today's behaviour: no energy decision.
    Performance,
    /// Save energy where it costs no admitted guarantee (E3+).
    Balanced,
    /// Favour battery life over throughput (E3+).
    Endurance,
}

impl EnergyMode {
    /// Parse the topology's spelling.
    pub fn from_str(s: &[u8]) -> Option<Self> {
        match s {
            b"performance" => Some(Self::Performance),
            b"balanced" => Some(Self::Balanced),
            b"endurance" => Some(Self::Endurance),
            _ => None,
        }
    }

    /// The topology's spelling.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::Balanced => "balanced",
            Self::Endurance => "endurance",
        }
    }
}

/// What a topology declares about energy: the mode and, optionally, a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnergySpec {
    /// The energy mode.
    pub mode: EnergyMode,
    /// The model, [`EnergyModel::NONE`] when the topology declares none.
    pub model: EnergyModel,
}

impl EnergySpec {
    /// Performance mode, no model: today's behaviour.
    pub const DEFAULT: Self = Self { mode: EnergyMode::Performance, model: EnergyModel::NONE };
}

/// How [`resolve`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// The source of the model in use ([`ModelSource::None`] = no model).
    pub source: ModelSource,
    /// The topology declared a model and it was refused.
    pub topology_fault: Option<ModelFault>,
    /// The DTB carried a model (and the topology none) and it was refused, or
    /// could not be built.
    pub dtb_fault: Option<ModelFault>,
    /// The topology and the DTB declared none, the CPUs reported core types,
    /// and the model they make was refused, or could not be built.
    pub cpuid_fault: Option<ModelFault>,
    /// None of the above declared a model, the board firmware reported a
    /// clock range, and the table made from it was refused, or could not be
    /// built.
    pub firmware_fault: Option<ModelFault>,
}

/// Pick the model in use: the topology's if it declares one and it is valid;
/// else, when the topology declares none, the DTB's if it is valid; else,
/// when the DTB carries none either, the one the CPUs' core types make; else
/// the one the board firmware's clock range makes (placeholder power: the
/// measured figures are the signed topology's to give, and it is first); else
/// none.
///
/// `dtb` is `None` when the DTB carries no OPP table at all, `Some(Err)` when
/// it carries one that could not be turned into a model. `cpuid` is `None`
/// when the CPUs report no core types (or the machine has no such source),
/// `Some(Err)` when they do and no model could be built from them
/// ([`EnergyModel::from_core_classes`]). `firmware` is `None` when the board
/// reports no clock range, `Some(Err)` when it does and no table could be
/// made from it ([`EnergyModel::from_clock_range`]).
pub fn resolve(
    topology: &EnergyModel,
    dtb: Option<Result<EnergyModel, ModelFault>>,
    cpuid: Option<Result<EnergyModel, ModelFault>>,
    firmware: Option<Result<EnergyModel, ModelFault>>,
    num_cpus: usize,
) -> (EnergyModel, Resolution) {
    let mut r = Resolution {
        source: ModelSource::None,
        topology_fault: None,
        dtb_fault: None,
        cpuid_fault: None,
        firmware_fault: None,
    };
    if topology.is_present() {
        match topology.validate(num_cpus) {
            Ok(()) => {
                r.source = ModelSource::Topology;
                let mut m = *topology;
                m.source = ModelSource::Topology;
                return (m, r);
            }
            Err(f) => {
                r.topology_fault = Some(f);
                return (EnergyModel::NONE, r);
            }
        }
    }
    match dtb {
        None => resolve_reported(cpuid, firmware, num_cpus, r),
        Some(Err(f)) => {
            r.dtb_fault = Some(f);
            (EnergyModel::NONE, r)
        }
        Some(Ok(m)) => match m.validate(num_cpus) {
            Ok(()) => {
                r.source = ModelSource::Dtb;
                let mut m = m;
                m.source = ModelSource::Dtb;
                (m, r)
            }
            Err(f) => {
                r.dtb_fault = Some(f);
                (EnergyModel::NONE, r)
            }
        },
    }
}

/// The last sources: the model the CPUs' core types make, else the one the
/// board firmware's clock range makes, if valid.
fn resolve_reported(
    cpuid: Option<Result<EnergyModel, ModelFault>>,
    firmware: Option<Result<EnergyModel, ModelFault>>,
    num_cpus: usize,
    mut r: Resolution,
) -> (EnergyModel, Resolution) {
    let (source, candidate) = match (cpuid, firmware) {
        (None, None) => return (EnergyModel::NONE, r),
        (Some(c), _) => (ModelSource::Cpuid, c),
        (None, Some(f)) => (ModelSource::Firmware, f),
    };
    let checked = candidate.and_then(|m| m.validate(num_cpus).map(|()| m));
    match checked {
        Ok(mut m) => {
            r.source = source;
            m.source = source;
            (m, r)
        }
        Err(f) => {
            match source {
                ModelSource::Firmware => r.firmware_fault = Some(f),
                _ => r.cpuid_fault = Some(f),
            }
            (EnergyModel::NONE, r)
        }
    }
}
