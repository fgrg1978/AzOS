// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `EnergyModel` (RFC-0051 §4.2): what each performance domain can run at and
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
//! 3. None: every seam keeps today's behaviour (RFC-0051 invariant I4).
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
}

impl IdleState {
    /// All zero, no name.
    pub const EMPTY: Self = Self {
        name: [0; IDLE_NAME_LEN],
        name_len: 0,
        exit_latency_us: 0,
        target_residency_us: 0,
        power_mw: 0,
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
}

impl ModelSource {
    /// Lower-case name, for the boot log.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Topology => "topology",
            Self::Dtb => "dtb",
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
}

/// Energy policy of the machine, chosen by the signed topology only
/// (RFC-0051 invariant I5): no Kconfig symbol and no `CONFIG.INI` key sets it.
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
}

/// Pick the model in use: the topology's if it declares one and it is valid;
/// else, when the topology declares none, the DTB's if it is valid; else none.
///
/// `dtb` is `None` when the DTB carries no OPP table at all, `Some(Err)` when
/// it carries one that could not be turned into a model.
pub fn resolve(
    topology: &EnergyModel,
    dtb: Option<Result<EnergyModel, ModelFault>>,
    num_cpus: usize,
) -> (EnergyModel, Resolution) {
    let mut r = Resolution { source: ModelSource::None, topology_fault: None, dtb_fault: None };
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
        None => (EnergyModel::NONE, r),
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
