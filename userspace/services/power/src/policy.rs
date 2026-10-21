// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The power policy server's decisions, pure: the profile table, the steps
//! that apply a profile through [`PowerPolicy`], and what to do when the
//! kernel refuses one. No syscall here (`main.rs` implements the trait over
//! the kernel's `Power` interface), so the host suite (`tests/host/power-tests`) drives
//! the same code with a scripted kernel.
//!
//! Policy is here and the limits are the kernel's: a profile asks, the kernel
//! answers with a verdict, and [`fallback`] is the whole of what this program
//! decides about a refusal.

use azos_power::*;

/// The three presets; the signed topology's `[energy] mode` names one
/// (`POLICY_STATE_MODE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// Today's behaviour: no frequency request, nothing capped.
    Performance,
    /// Schedutil with the deadline and safety floors.
    Balanced,
    /// Balanced with a lower OPP cap, less headroom and a slower governor.
    Endurance,
}

impl Preset {
    /// The preset the kernel's mode word (`POLICY_STATE_MODE`) means.
    pub fn from_mode(w: u64) -> Option<Self> {
        match w {
            0 => Some(Self::Performance),
            1 => Some(Self::Balanced),
            2 => Some(Self::Endurance),
            _ => None,
        }
    }
    /// The preset a command line names.
    pub fn from_name(s: &[u8]) -> Option<Self> {
        match s {
            b"performance" => Some(Self::Performance),
            b"balanced" => Some(Self::Balanced),
            b"endurance" => Some(Self::Endurance),
            _ => None,
        }
    }
    /// How much energy the preset saves: 0 performance, 1 balanced, 2
    /// endurance (the kernel's mode word).
    pub const fn rank(self) -> u32 {
        match self {
            Self::Performance => 0,
            Self::Balanced => 1,
            Self::Endurance => 2,
        }
    }
    /// Its name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::Balanced => "balanced",
            Self::Endurance => "endurance",
        }
    }
}

/// The kernel's boot values (what `Performance` restores).
pub const DEFAULT_HEADROOM_PCT: u32 = 25;
/// The kernel's boot rate limit, microseconds.
pub const DEFAULT_RATE_LIMIT_US: u32 = 4_000;

/// What a preset asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// `POLICY_GOV_*`.
    pub governor: u32,
    /// OPP cap of every domain, percent of its table (100 = none).
    pub cap_pct: u32,
    /// Schedutil headroom, percent.
    pub headroom_pct: u32,
    /// Evaluation interval, microseconds.
    pub rate_limit_us: u32,
    /// Deepest idle state ([`POLICY_IDLE_UNLIMITED`] = any).
    pub idle_depth: u32,
}

/// The built-in table.
pub const fn profile(p: Preset) -> Profile {
    match p {
        Preset::Performance => Profile {
            governor: POLICY_GOV_FIXED as u32,
            cap_pct: 100,
            headroom_pct: DEFAULT_HEADROOM_PCT,
            rate_limit_us: DEFAULT_RATE_LIMIT_US,
            idle_depth: POLICY_IDLE_UNLIMITED,
        },
        Preset::Balanced => Profile {
            governor: POLICY_GOV_DEADLINE_FLOOR as u32,
            cap_pct: 100,
            headroom_pct: DEFAULT_HEADROOM_PCT,
            rate_limit_us: DEFAULT_RATE_LIMIT_US,
            idle_depth: POLICY_IDLE_UNLIMITED,
        },
        Preset::Endurance => Profile {
            governor: POLICY_GOV_DEADLINE_FLOOR as u32,
            cap_pct: 60,
            headroom_pct: 10,
            rate_limit_us: 20_000,
            idle_depth: POLICY_IDLE_UNLIMITED,
        },
    }
}

/// The index of the OPP at `pct` percent of a table of `n` points, rounded up
/// (so a cap never lands below what it asked for).
pub const fn cap_index(n: u32, pct: u32) -> u32 {
    if n == 0 {
        0
    } else {
        ((n - 1) * pct).div_ceil(100)
    }
}

/// One domain, as `POLICY_STATE_DOMAIN_BASE + d` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainInfo {
    /// OPPs in the table.
    pub n_opps: u32,
    /// The OPP last decided (255 before the first decision).
    pub cur: u32,
    /// The user range now.
    pub min: u32,
    /// Ditto (255 = no cap).
    pub max: u32,
    /// The kernel's safety floor.
    pub safety: u32,
    /// Idle states.
    pub n_idle: u32,
}

impl DomainInfo {
    /// Unpack the state word.
    pub const fn of(w: u64) -> Self {
        Self {
            n_opps: (w & 0xFF) as u32,
            cur: ((w >> 8) & 0xFF) as u32,
            min: ((w >> 16) & 0xFF) as u32,
            max: ((w >> 24) & 0xFF) as u32,
            safety: ((w >> 32) & 0xFF) as u32,
            n_idle: ((w >> 40) & 0xFF) as u32,
        }
    }
}

/// One setter call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `set_governor`.
    Governor(u32),
    /// `set_opp_range`.
    OppRange {
        /// Domain index.
        domain: u32,
        /// Lowest OPP.
        min: u32,
        /// Highest OPP.
        max: u32,
    },
    /// `set_headroom`.
    Headroom(u32),
    /// `set_rate_limit`.
    RateLimit(u32),
    /// `set_idle_depth`.
    IdleDepth(u32),
    /// `set_power_cap`.
    PowerCap {
        /// Domain index.
        domain: u32,
        /// Milliwatts (0 lifts the cap).
        mw: u32,
    },
    /// `set_parked`.
    Parked(u32),
    /// `set_qos_domains`.
    QosDomains {
        /// QoS class.
        class: u32,
        /// Domains the class may be placed on (bit d = domain d).
        domains: u32,
    },
}

/// What the server logs for each call it made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The call.
    pub step: Step,
    /// What the kernel answered.
    pub verdict: Verdict,
    /// This call was the fallback for a refused one.
    pub retry: bool,
}

/// How a run went.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Calls applied (fallbacks included).
    pub applied: u32,
    /// Calls the kernel refused (fallbacks included).
    pub refused: u32,
    /// Fallbacks tried.
    pub fallbacks: u32,
    /// The machine has no energy model: nothing was asked.
    pub no_model: bool,
    /// A call failed outright (no capability, no `energy` in the kernel) or a
    /// state read did: the run stopped.
    pub failed: bool,
}

/// The decision table for a refusal: what to ask instead, or `None` to leave
/// it. One level only: a refused fallback is not retried.
///
/// | Refused | Instead |
/// |---|---|
/// | OPP range, safety floor | the cap raised to the kernel's safety floor |
/// | OPP range, deadline floor | no cap (the table's top) |
/// | OPP range, other | nothing: the range itself was wrong |
/// | governor, no model | nothing |
/// | governor, other | `Fixed` (today's behaviour) |
/// | headroom / rate limit | the boot value |
/// | idle depth | no limit |
pub fn fallback(step: Step, why: u32, info: Option<DomainInfo>) -> Option<Step> {
    if cfg!(feature = "pw-fallback-canary") {
        return None;
    }
    match (step, why) {
        (Step::OppRange { domain, min, max }, POLICY_REFUSED_SAFETY_FLOOR) => {
            let floor = info?.safety;
            (floor > max).then_some(Step::OppRange { domain, min: min.min(floor), max: floor })
        }
        (Step::OppRange { domain, min: _, max }, POLICY_REFUSED_DEADLINE_FLOOR) => {
            let top = info?.n_opps.checked_sub(1)?;
            (top > max).then_some(Step::OppRange { domain, min: 0, max: top })
        }
        (Step::OppRange { .. }, _) => None,
        (Step::Governor(_), POLICY_REFUSED_NO_MODEL) => None,
        (Step::Governor(g), _) => (g != POLICY_GOV_FIXED as u32).then_some(Step::Governor(POLICY_GOV_FIXED as u32)),
        (Step::Headroom(h), _) => (h != DEFAULT_HEADROOM_PCT).then_some(Step::Headroom(DEFAULT_HEADROOM_PCT)),
        (Step::RateLimit(r), _) => (r != DEFAULT_RATE_LIMIT_US).then_some(Step::RateLimit(DEFAULT_RATE_LIMIT_US)),
        (Step::IdleDepth(d), _) => (d != POLICY_IDLE_UNLIMITED).then_some(Step::IdleDepth(POLICY_IDLE_UNLIMITED)),
        // The budget's steps answer a refusal in [`budget_fallback`], which
        // knows the machine.
        (Step::PowerCap { .. } | Step::Parked(_) | Step::QosDomains { .. }, _) => None,
    }
}

fn call<P: PowerPolicy + ?Sized>(p: &mut P, s: Step) -> u32 {
    match s {
        Step::Governor(g) => p.set_governor(g),
        Step::OppRange { domain, min, max } => p.set_opp_range(domain, min, max),
        Step::Headroom(h) => p.set_headroom(h),
        Step::RateLimit(r) => p.set_rate_limit(r),
        Step::IdleDepth(d) => p.set_idle_depth(d),
        Step::PowerCap { domain, mw } => p.set_power_cap(domain, mw),
        Step::Parked(mask) => p.set_parked(mask),
        Step::QosDomains { class, domains } => p.set_qos_domains(class, domains),
    }
}

fn domain<P: PowerPolicy + ?Sized>(p: &P, d: u32) -> Option<DomainInfo> {
    match p.state(POLICY_STATE_DOMAIN_BASE as u32 + d) {
        WORD_ERR => None,
        w => Some(DomainInfo::of(w)),
    }
}

/// One call, its verdict logged, and the answer to a refusal (`fallback_of`)
/// tried once. `false` when the call failed outright and the run should stop.
fn run_step<P: PowerPolicy + ?Sized>(
    p: &mut P,
    first: Step,
    log: &mut dyn FnMut(&Decision),
    out: &mut Outcome,
    fallback_of: &dyn Fn(Step, u32) -> Option<Step>,
) -> bool {
    let mut step = first;
    let mut retry = false;
    loop {
        let verdict = Verdict::of(call(p, step));
        log(&Decision { step, verdict, retry });
        match verdict {
            Verdict::Applied => {
                out.applied += 1;
                return true;
            }
            Verdict::Failed(_) => {
                out.failed = true;
                return cfg!(feature = "pw-stop-canary");
            }
            Verdict::Refused(why) => {
                out.refused += 1;
                match (retry, fallback_of(step, why)) {
                    (false, Some(next)) => {
                        out.fallbacks += 1;
                        step = next;
                        retry = true;
                    }
                    _ => return true,
                }
            }
        }
    }
}

/// Apply `prof`: the governor, headroom, rate limit and idle depth, then each
/// domain's OPP cap. Every call and its verdict goes to `log`; a refusal is
/// answered by [`fallback`]. Stops at a call that failed outright, and does
/// nothing on a machine with no energy model.
pub fn apply<P: PowerPolicy + ?Sized>(p: &mut P, prof: &Profile, log: &mut dyn FnMut(&Decision)) -> Outcome {
    let mut out = Outcome::default();
    let n = match p.state(POLICY_STATE_DOMAINS as u32) {
        WORD_ERR => {
            out.failed = true;
            return out;
        }
        0 if !cfg!(feature = "pw-nomodel-canary") => {
            out.no_model = true;
            return out;
        }
        n => n as u32,
    };
    let mut run = |p: &mut P, step: Step, info: Option<DomainInfo>, out: &mut Outcome| -> bool {
        run_step(p, step, log, out, &|s, why| fallback(s, why, info))
    };
    let head = [
        Step::Governor(prof.governor),
        Step::Headroom(prof.headroom_pct),
        Step::RateLimit(prof.rate_limit_us),
        Step::IdleDepth(prof.idle_depth),
    ];
    for s in head {
        if !run(p, s, None, &mut out) {
            return out;
        }
    }
    for d in 0..n {
        let Some(info) = domain(p, d) else {
            out.failed = true;
            return out;
        };
        let step = Step::OppRange { domain: d, min: 0, max: cap_index(info.n_opps, prof.cap_pct) };
        if !run(p, step, Some(info), &mut out) {
            return out;
        }
    }
    out
}

/// The words a profile governs, as the kernel reports them now. The serve
/// loop remembers the signature after [`apply`] and re-applies when it moves
/// (another client changed the policy), not when the kernel turned a request
/// into a fallback.
pub fn signature<P: PowerPolicy + ?Sized>(p: &P) -> [u64; 4] {
    [
        p.state(POLICY_STATE_GOVERNOR as u32),
        p.state(POLICY_STATE_HEADROOM as u32),
        p.state(POLICY_STATE_RATE_LIMIT as u32),
        p.state(POLICY_STATE_IDLE_DEPTH as u32),
    ]
}

// ---------------------------------------------------------------------------
// The budget: power caps, parked CPUs and QoS placement
// ---------------------------------------------------------------------------

/// Most domains the kernel's model holds (`azos_energy::model::MAX_DOMAINS`).
pub const MAX_DOMAINS: usize = 4;
/// QoS classes (`QOS_DEFAULT` 0, `QOS_LATENCY`, `QOS_THROUGHPUT`,
/// `QOS_BACKGROUND` 3).
pub const QOS_CLASSES: u32 = 4;
/// The QoS class of work nobody waits on.
pub const QOS_BACKGROUND: u32 = 3;
/// The QoS class of work that wants throughput, not latency.
pub const QOS_THROUGHPUT: u32 = 2;

/// What the machine asks of the power service besides the clock (the
/// [`Profile`]): how much of each domain's power it may draw, how many CPUs
/// stay parked and which QoS classes are kept off the fastest domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Power cap of every domain, percent of its top OPP's power (100: none).
    pub power_cap_pct: u32,
    /// CPUs parked (the highest-numbered; CPU 0 and the last CPU of a domain
    /// never): a count, as many as the rules allow when it is larger.
    pub park: u32,
    /// QoS classes kept off the fastest domain, one bit per class.
    pub efficient_qos: u32,
}

/// The built-in table: what a preset adds to its profile.
pub const fn budget(p: Preset) -> Budget {
    match p {
        Preset::Performance => Budget { power_cap_pct: 100, park: 0, efficient_qos: 0 },
        Preset::Balanced => Budget { power_cap_pct: 100, park: 0, efficient_qos: 1 << QOS_BACKGROUND },
        Preset::Endurance => {
            Budget { power_cap_pct: 100, park: 0, efficient_qos: 1 << QOS_BACKGROUND | 1 << QOS_THROUGHPUT }
        }
    }
}

/// The deepest degrade level (`DEGRADE_LEVEL_CONTAINED`); a larger number is
/// the same level (fail-closed, as the degrade vocabulary itself is).
pub const LEVEL_MAX: u8 = 3;

/// What the kernel's reserve is taken to be when the state word cannot be
/// read: the largest `ENERGY_BATTERY_RESERVE_PCT` allows, so that an unknown
/// reserve makes every level ask for less power, never more.
pub const RESERVE_UNKNOWN_PCT: u8 = 50;

/// The least a level may ask of a domain's power, percent of its top OPP's.
const SHARE_MIN_PCT: u32 = 1;

/// The power share of each degrade level, derived from the machine's own
/// declarations instead of chosen.
///
/// **Derivation.** The kernel keeps the last `reserve` percent of the pack for
/// the safe stop (Kconfig `ENERGY_BATTERY_RESERVE_PCT`; at and below it every
/// domain is held at its lowest legal OPP). Only the charge above it is the
/// mission's. A full pack spends `100 - reserve` percent at full power in some
/// time `T`. A level is entered at the charge `b` its topology row declares
/// (`[degrade.NAME] battery_pct`); there `b - reserve` percent is left, and
/// spending it at the share
///
/// ```text
/// share = (b - reserve) / (100 - reserve)
/// ```
///
/// of full power lasts the same `T`: the machine keeps at the level's entry
/// the endurance it had at full charge. The capacity of the pack cancels (it
/// is the same energy on both sides), so the model needs neither it nor the
/// machine's top power; the topology's rows and the kernel's reserve are all
/// it reads. The deeper the level, the lower its threshold, the smaller the
/// share: the tightening the levels promise falls out of the rows' order
/// (the topology requires a more restrictive level to have a strictly lower
/// threshold).
///
/// A level no row declares takes the tightest threshold any row declares (no
/// row at all: the reserve itself, the least a level may ask). The kernel's
/// floors bound whatever a level asks: a share below the slowest OPP's power
/// is answered with that power (`budget_fallback`), and the CPUs parked for
/// the rest of the reduction ([`Machine::park_for`]) never include CPU 0 or a
/// domain's last.
///
/// What this does not model: the mission's draw is not a constant fraction of
/// the machine's power, and a pack's usable energy shrinks with its load and
/// its age. It keeps the power policy proportional to the charge that is
/// left, which is the one thing the rows and the reserve say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levels {
    /// Percent of full power each level asks, by level (0 asks all of it).
    share_pct: [u32; LEVEL_MAX as usize + 1],
}

impl Levels {
    /// The shares for rows entered at `entries` (`(level, battery_pct)`, any
    /// order) over a kernel that keeps `reserve_pct`.
    pub fn derive(entries: &[(u8, u8)], reserve_pct: u8) -> Levels {
        let reserve = reserve_pct.min(99) as u32;
        let share_at = |b: u32| -> u32 {
            if cfg!(feature = "pw-levels-canary") {
                return 50;
            }
            (b.saturating_sub(reserve) * 100 / (100 - reserve)).clamp(SHARE_MIN_PCT, 100)
        };
        let tightest = entries.iter().map(|(_, b)| *b as u32).min().unwrap_or(reserve);
        let mut share_pct = [100; LEVEL_MAX as usize + 1];
        for level in 1..=LEVEL_MAX {
            let entry = entries.iter().find(|(l, _)| *l == level).map(|(_, b)| *b as u32);
            share_pct[level as usize] = share_at(entry.unwrap_or(tightest));
        }
        Levels { share_pct }
    }

    /// Percent of full power `level` asks.
    pub fn share_pct(&self, level: u8) -> u32 {
        self.share_pct[level.min(LEVEL_MAX) as usize]
    }
}

/// The lightest preset a degrade level runs: one rung of the preset ladder
/// (`Preset::rank`) per level, the last rung for every level past it.
pub const fn floor(level: u8) -> Preset {
    match level {
        0 => Preset::Performance,
        1 => Preset::Balanced,
        _ => Preset::Endurance,
    }
}

/// The preset in force at degrade `level` when the machine runs `base`: a
/// level only ever asks for more saving than the preset, never less.
pub const fn preset_at(base: Preset, level: u8) -> Preset {
    let f = floor(level);
    if f.rank() > base.rank() { f } else { base }
}

/// A preset and the budget it runs with at a degrade level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The preset in force: the base one, or the level's floor if that saves
    /// more.
    pub preset: Preset,
    /// Its budget, with the level's cap and parking.
    pub budget: Budget,
}

/// The plan for `base` at degrade `level` on machine `m` (`None`: the kernel
/// has no model, so there is no budget to size): the level's derived power
/// share ([`Levels`]) as the cap of every domain, and as many CPUs parked as
/// the share needs beyond what the slowest OPP gives ([`Machine::park_for`]).
pub fn plan(base: Preset, level: u8, levels: &Levels, m: Option<&Machine>) -> Plan {
    let preset = preset_at(base, level);
    let mut b = budget(preset);
    if level != 0 {
        let share = levels.share_pct(level);
        b.power_cap_pct = share;
        b.park = m.map_or(0, |m| m.park_for(share));
    }
    Plan { preset, budget: b }
}

/// The machine as the kernel's model describes it, as far as the budget needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Machine {
    /// Domains.
    pub domains: usize,
    /// CPUs of each domain.
    pub cpus: [u32; MAX_DOMAINS],
    /// Power of each domain's top OPP, milliwatts.
    pub top_mw: [u32; MAX_DOMAINS],
    /// Capacity of each domain's top OPP.
    pub top_capacity: [u32; MAX_DOMAINS],
    /// The kernel's safety floor of each domain (an OPP index).
    pub safety: [u32; MAX_DOMAINS],
    /// Power of each domain's safety-floor OPP, milliwatts.
    pub safety_mw: [u32; MAX_DOMAINS],
    /// Power of each domain's slowest OPP, milliwatts: the least a cap can ask.
    pub low_mw: [u32; MAX_DOMAINS],
}

impl Machine {
    /// The domain with the most capacity at its top OPP (the lowest index on
    /// a tie, as the kernel picks it).
    pub fn fastest(&self) -> usize {
        (0..self.domains).fold(0, |best, d| if self.top_capacity[d] > self.top_capacity[best] { d } else { best })
    }

    /// Read the machine from the kernel. `None` when it has no model or a
    /// read failed.
    pub fn read<P: PowerPolicy + ?Sized>(p: &P) -> Option<Machine> {
        let n = match p.state(POLICY_STATE_DOMAINS as u32) {
            WORD_ERR | 0 => return None,
            n => (n as usize).min(MAX_DOMAINS),
        };
        let mut m = Machine {
            domains: n,
            cpus: [0; MAX_DOMAINS],
            top_mw: [0; MAX_DOMAINS],
            top_capacity: [0; MAX_DOMAINS],
            safety: [0; MAX_DOMAINS],
            safety_mw: [0; MAX_DOMAINS],
            low_mw: [0; MAX_DOMAINS],
        };
        let opp = |d: usize, i: u32| match p.state((POLICY_STATE_OPP_BASE + d as u64 * POLICY_STATE_OPP_STRIDE) as u32 + i) {
            WORD_ERR => None,
            w => Some((w as u32, (w >> 32) as u32)),
        };
        for d in 0..n {
            m.cpus[d] = match p.state(POLICY_STATE_CPUS_BASE as u32 + d as u32) {
                WORD_ERR => return None,
                w => w as u32,
            };
            let info = domain(p, d as u32)?;
            let (mw, cap) = opp(d, info.n_opps.checked_sub(1)?)?;
            m.top_mw[d] = mw;
            m.top_capacity[d] = cap;
            m.safety[d] = info.safety;
            m.safety_mw[d] = opp(d, info.safety)?.0;
            m.low_mw[d] = opp(d, 0)?.0;
        }
        Some(m)
    }

    /// CPUs to park so that the domains draw `share_pct` percent of their top
    /// power, beyond what the power cap alone reaches. A cap goes no lower than
    /// the slowest OPP (`low_mw`); under it the rest of the reduction is taken
    /// from the CPUs, taking a domain's power to scale with the CPUs it keeps:
    /// `ceil(cpus * share / (low_mw / top_mw))` stay, at least one. The sum
    /// over the domains; [`park_mask`](Self::park_mask) applies the rules (CPU
    /// 0 and a domain's last CPU never park).
    pub fn park_for(&self, share_pct: u32) -> u32 {
        let mut total = 0;
        for d in 0..self.domains {
            let (cpus, top, low) = (self.cpus[d].count_ones() as u64, self.top_mw[d] as u64, self.low_mw[d] as u64);
            let want = share_pct as u64 * top;
            // The cap alone reaches it (`share * top >= 100 * low`).
            if cpus == 0 || top == 0 || want >= 100 * low {
                continue;
            }
            let keep = (cpus * want).div_ceil(100 * low).max(1);
            total += (cpus - keep.min(cpus)) as u32;
        }
        total
    }

    /// The CPUs `count` asks to park (as many as allowed when it is larger): the
    /// highest-numbered ones, never CPU 0, a CPU in no domain, or the last
    /// CPU of a domain.
    pub fn park_mask(&self, count: u32) -> u32 {
        let covered = self.cpus[..self.domains].iter().fold(0, |a, c| a | c);
        let mut mask = 0u32;
        let mut parked = 0;
        for cpu in (1..32).rev() {
            let bit = 1u32 << cpu;
            if parked >= count || covered & bit == 0 {
                continue;
            }
            let next = mask | bit;
            if self.cpus[..self.domains].iter().any(|d| d & !next == 0) {
                continue;
            }
            mask = next;
            parked += 1;
        }
        mask
    }

    /// The domains QoS class `class` is placed on under `b`: every domain,
    /// or every domain but the fastest for a class the budget keeps efficient
    /// (a machine with one domain has no other to keep it on).
    pub fn qos_domains(&self, class: u32, b: &Budget) -> u32 {
        let all = (1u32 << self.domains) - 1;
        if b.efficient_qos >> class & 1 != 0 && self.domains > 1 {
            all & !(1 << self.fastest())
        } else {
            all
        }
    }

    /// Domain `d`'s power cap under `b`, milliwatts (0: none).
    pub fn cap_mw(&self, d: usize, b: &Budget) -> u32 {
        if b.power_cap_pct >= 100 {
            0
        } else {
            (self.top_mw[d] as u64 * b.power_cap_pct as u64 / 100).max(1) as u32
        }
    }
}

/// The decision table for a refusal of a budget step: what to ask instead, or
/// `None` to leave it. One level only, like [`fallback`].
///
/// | Refused | Instead |
/// |---|---|
/// | power cap, safety floor | the cap raised to the power of the safety-floor OPP |
/// | power cap, deadline floor | no cap |
/// | power cap, below the slowest OPP's power | the cap raised to the lowest power allowed (that OPP's, or the safety floor's if higher) |
/// | power cap, other | nothing: the cap itself was wrong |
/// | parking, any | nothing parked (an admitted real-time reservation lives on a CPU the mask names) |
/// | QoS placement | nothing: the kernel's mapping limits are not negotiable |
pub fn budget_fallback(step: Step, why: u32, m: &Machine) -> Option<Step> {
    if cfg!(feature = "pw-budget-canary") {
        return None;
    }
    match (step, why) {
        (Step::PowerCap { domain, mw }, POLICY_REFUSED_RANGE) => {
            // The lowest power the kernel can allow: the slowest OPP's, or the
            // safety floor's if that is higher. A derived level share can be
            // under both ([`Levels`]), and a second refusal would leave the
            // level without a cap.
            let low = (*m.low_mw.get(domain as usize)?).max(*m.safety_mw.get(domain as usize)?);
            (low > mw).then_some(Step::PowerCap { domain, mw: low })
        }
        (Step::PowerCap { domain, mw }, POLICY_REFUSED_SAFETY_FLOOR) => {
            let floor = *m.safety_mw.get(domain as usize)?;
            (floor > mw).then_some(Step::PowerCap { domain, mw: floor })
        }
        (Step::PowerCap { domain, mw }, POLICY_REFUSED_DEADLINE_FLOOR) => {
            (mw != 0).then_some(Step::PowerCap { domain, mw: 0 })
        }
        (Step::Parked(mask), _) => (mask != 0).then_some(Step::Parked(0)),
        _ => None,
    }
}

/// Apply `b` on machine `m`: each domain's power cap, the parked CPUs, then
/// the QoS placement of every class. Every call and its verdict goes to `log`;
/// a refusal is answered by [`budget_fallback`]. Stops at a call that failed
/// outright.
pub fn apply_budget<P: PowerPolicy + ?Sized>(
    p: &mut P,
    b: &Budget,
    m: &Machine,
    log: &mut dyn FnMut(&Decision),
) -> Outcome {
    let mut out = Outcome::default();
    let fb = |s: Step, why: u32| budget_fallback(s, why, m);
    for d in 0..m.domains {
        let step = Step::PowerCap { domain: d as u32, mw: m.cap_mw(d, b) };
        if !run_step(p, step, log, &mut out, &fb) {
            return out;
        }
    }
    if !run_step(p, Step::Parked(m.park_mask(b.park)), log, &mut out, &fb) {
        return out;
    }
    for class in 0..QOS_CLASSES {
        let step = Step::QosDomains { class, domains: m.qos_domains(class, b) };
        if !run_step(p, step, log, &mut out, &fb) {
            return out;
        }
    }
    out
}

/// The words the budget governs, as the kernel reports them now: the parked
/// mask, a fold of the domains' power caps and one of the QoS placements.
/// Compared like [`signature`]: the serve loop re-applies when it moves.
pub fn budget_signature<P: PowerPolicy + ?Sized>(p: &P, m: &Machine) -> [u64; 3] {
    let mut caps = 0u64;
    for d in 0..m.domains {
        caps = caps << 24 | p.state(POLICY_STATE_POWER_CAP_BASE as u32 + d as u32) & 0xFF_FFFF;
    }
    let mut qos = 0u64;
    for c in 0..QOS_CLASSES {
        qos = qos << 8 | p.state(POLICY_STATE_QOS_BASE as u32 + c) & 0xFF;
    }
    [p.state(POLICY_STATE_PARKED as u32), caps, qos]
}

/// Apply the plan of `base` at degrade `level`: the profile, then the budget
/// (when the machine has a model to describe it and the profile found one).
/// Every call goes to `log`. Returns the plan and what it took.
pub fn apply_plan<P: PowerPolicy + ?Sized>(
    p: &mut P,
    base: Preset,
    level: u8,
    levels: &Levels,
    machine: Option<&Machine>,
    log: &mut dyn FnMut(&Decision),
) -> (Plan, Outcome) {
    let plan = plan(base, level, levels, machine);
    let mut o = apply(p, &profile(plan.preset), log);
    if let (Some(m), false, false) = (machine, o.no_model, o.failed) {
        let b = apply_budget(p, &plan.budget, m, log);
        o.applied += b.applied;
        o.refused += b.refused;
        o.fallbacks += b.fallbacks;
        o.failed |= b.failed;
    }
    (plan, o)
}
