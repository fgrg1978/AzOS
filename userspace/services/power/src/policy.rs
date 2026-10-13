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
    }
}

fn call<P: PowerPolicy + ?Sized>(p: &mut P, s: Step) -> u32 {
    match s {
        Step::Governor(g) => p.set_governor(g),
        Step::OppRange { domain, min, max } => p.set_opp_range(domain, min, max),
        Step::Headroom(h) => p.set_headroom(h),
        Step::RateLimit(r) => p.set_rate_limit(r),
        Step::IdleDepth(d) => p.set_idle_depth(d),
    }
}

fn domain<P: PowerPolicy + ?Sized>(p: &P, d: u32) -> Option<DomainInfo> {
    match p.state(POLICY_STATE_DOMAIN_BASE as u32 + d) {
        WORD_ERR => None,
        w => Some(DomainInfo::of(w)),
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
        let mut step = step;
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
                    match (retry, fallback(step, why, info)) {
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
