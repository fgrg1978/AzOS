// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The run-time energy policy: what user space may change and the limits the
//! kernel keeps (owner plan, Energy section 8).
//!
//! The seams in [`crate::seams`] are fixed at boot. This module is the live
//! part: a [`Policy`] of atomics the governor and the idle governor read, and
//! limit-checked setters. User space owns the *policy* (`userspace/services/
//! power` applies a profile through `PowerPolicy`); the kernel only enforces
//! *limits*, and a setter outside them is refused and recorded:
//!
//! | Setter | Refused when |
//! |---|---|
//! | [`Policy::set_governor`] | no model; anything but `Fixed` or `DeadlineFloor` (bare schedutil cannot honour I1) |
//! | [`Policy::set_opp_range`] | unknown domain; `min > max`; `max` past the last OPP; `max` below the WCET reference OPP (I6) or below the admitted real-time floor (I1) |
//! | [`Policy::set_headroom`] | outside [`HEADROOM_MIN_PCT`]`..=`[`HEADROOM_MAX_PCT`] |
//! | [`Policy::set_rate_limit`] | outside [`RATE_LIMIT_MIN_US`]`..=`[`RATE_LIMIT_MAX_US`] |
//! | [`Policy::set_idle_depth`] | deeper than the deepest state any domain lists |
//! | [`Policy::set_power_cap`] | unknown domain; below the power of the domain's slowest OPP; its OPP below the WCET reference OPP (I6) or the admitted real-time floor (I1) |
//! | [`Policy::set_parked`] | CPU 0; a CPU outside the model; the last unparked CPU of a domain; a CPU with admitted real-time work (I1) |
//! | [`Policy::set_qos_domains`] | not a QoS class; no domain; the default or latency class kept off the fastest domain |
//! | [`Policy::report_battery`] | a charge above 100 %; a level the topology has no row for; no battery declared |
//!
//! A cap that was legal when set can become illegal later (reservations are
//! admitted at run time), so the limits are enforced again at every governor
//! evaluation: [`Policy::clamp`] applies the user's range to the governor's
//! request and then lets the deadline and safety floors win. The idle depth
//! only ever shortens the list of states the idle governor chooses from, so
//! the real-time slack (I3) still applies on top.
//!
//! # The battery
//!
//! The signed topology's `[degrade.NAME]` rows (a level, the charge it is
//! entered at and the charge it is left above) are handed to the policy at
//! boot ([`Policy::init_battery`]). The power service estimates the charge and
//! reports it with the level it holds ([`Policy::report_battery`]). The kernel
//! keeps two limits on that report. The level may not be lighter than the rows
//! require at that charge (leaving a level is the service's, with its
//! hysteresis; entering it is not optional). And at or below the reserve
//! ([`BatteryLimits::reserve_pct`], Kconfig `ENERGY_BATTERY_RESERVE_PCT`) the
//! kernel holds every domain at its lowest legal OPP and runs the
//! deadline-floor governor, whatever range, cap or governor the policy set: the
//! charge left is for the safe stop. The floors still win over that, so the
//! reserve never starves an admitted reservation. A higher charge reported
//! later lifts it.
//!
//! The kernel also keeps the age of the last accepted report
//! ([`Policy::battery_alive`], [`Policy::check_report_age`]). A service that
//! died or stalled leaves its last charge in force, and the kernel cannot tell
//! a full pack from an empty one by that charge, so a report older than
//! [`BatteryLimits::report_timeout_ticks`] (Kconfig
//! `ENERGY_BATTERY_REPORT_TIMEOUT_MS`) holds the reserve as well: the safe
//! state is the lowest legal OPP, because the charge left for the safe stop
//! can no longer be vouched for. The hold lasts until the next accepted
//! report, which brings the charge (and so the reserve or its lifting) back.
//! The age is counted from boot, so a service that never starts is held the
//! same way. A refused report is not a sign of life.
//!
//! Every refusal bumps a counter and leaves a record in a small ring
//! ([`Policy::refusal`]); an application bumps `applied`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed};

use azos_abi::power::*;

use crate::governor::{self, Decision, HEADROOM_PCT, RATE_LIMIT_US};
use crate::model::{EnergyMode, EnergyModel, MAX_DOMAINS, MAX_MODEL_CPUS};

pub use azos_abi::power::POLICY_DEGRADE_ROWS_MAX;
use crate::seams::Governor;

/// Why a setter refused (the `POLICY_REFUSED_*` code it travels as).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// The machine has no energy model.
    NoModel = POLICY_REFUSED_NO_MODEL as u8,
    /// Not a governor user space may choose.
    Governor = POLICY_REFUSED_GOVERNOR as u8,
    /// No such domain.
    Domain = POLICY_REFUSED_DOMAIN as u8,
    /// Empty or out-of-table OPP range.
    Range = POLICY_REFUSED_RANGE as u8,
    /// Cap below the WCET reference OPP (I6).
    SafetyFloor = POLICY_REFUSED_SAFETY_FLOOR as u8,
    /// Cap below the admitted real-time floor (I1).
    DeadlineFloor = POLICY_REFUSED_DEADLINE_FLOOR as u8,
    /// Headroom outside its limits.
    Headroom = POLICY_REFUSED_HEADROOM as u8,
    /// Rate limit outside its limits.
    RateLimit = POLICY_REFUSED_RATE_LIMIT as u8,
    /// Deeper than any idle state.
    IdleDepth = POLICY_REFUSED_IDLE_DEPTH as u8,
    /// A CPU that cannot be parked.
    Park = POLICY_REFUSED_PARK as u8,
    /// A QoS mapping the kernel does not allow.
    Qos = POLICY_REFUSED_QOS as u8,
    /// A battery report the topology's declaration cannot take.
    Battery = POLICY_REFUSED_BATTERY as u8,
}

impl Refusal {
    /// The wire code.
    pub const fn code(self) -> u32 {
        self as u8 as u32
    }
}

/// Which setter a record is about, as its `POWER_OP_POLICY_*` number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// [`Policy::set_governor`].
    Governor = POWER_OP_POLICY_GOVERNOR as u8,
    /// [`Policy::set_opp_range`].
    OppRange = POWER_OP_POLICY_OPP_RANGE as u8,
    /// [`Policy::set_headroom`].
    Headroom = POWER_OP_POLICY_HEADROOM as u8,
    /// [`Policy::set_rate_limit`].
    RateLimit = POWER_OP_POLICY_RATE_LIMIT as u8,
    /// [`Policy::set_idle_depth`].
    IdleDepth = POWER_OP_POLICY_IDLE_DEPTH as u8,
    /// [`Policy::set_power_cap`].
    PowerCap = POWER_OP_POLICY_POWER_CAP as u8,
    /// [`Policy::set_parked`].
    Park = POWER_OP_POLICY_PARK as u8,
    /// [`Policy::set_qos_domains`].
    QosDomains = POWER_OP_POLICY_QOS_DOMAINS as u8,
    /// [`Policy::report_battery`].
    Battery = POWER_OP_POLICY_BATTERY as u8,
}

/// Refusal records kept (the most recent).
pub const LOG_LEN: usize = 8;
/// Governor value as stored.
const GOV_FIXED: u8 = 0;
const GOV_SCHEDUTIL: u8 = 1;
const GOV_DEADLINE: u8 = 2;
/// "No cap" / "no limit" in the 8-bit fields.
pub const NONE_U8: u8 = u8::MAX;
/// QoS classes (`azos_abi::syscall_nr::QOS_DEFAULT..=QOS_BACKGROUND`).
pub const QOS_CLASSES: usize = azos_abi::syscall_nr::QOS_BACKGROUND as usize + 1;

/// One `[degrade.NAME]` row of the signed topology, as the policy keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DegradeRow {
    /// The level entered, `1..=3` (`DEGRADE_LEVEL_*`).
    pub level: u8,
    /// Entered at or below this charge, percent.
    pub battery_pct: u8,
    /// Left above this charge, percent (`battery_pct` itself: no hysteresis).
    pub clear_pct: u8,
}

/// What the kernel keeps on the battery whatever the power service says (both
/// are Kconfig values, handed over at boot by the kernel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatteryLimits {
    /// The reserve, percent: at and below it every domain is held at its
    /// lowest legal OPP.
    pub reserve_pct: u8,
    /// The oldest an accepted report may be before the reserve is held as if
    /// the charge were at the reserve, timer ticks.
    pub report_timeout_ticks: u64,
}

impl DegradeRow {
    const fn pack(self) -> u32 {
        1 << 24 | self.level as u32 | (self.battery_pct as u32) << 8 | (self.clear_pct as u32) << 16
    }
    const fn unpack(w: u32) -> Option<Self> {
        if w >> 24 == 0 {
            return None;
        }
        Some(Self { level: w as u8, battery_pct: (w >> 8) as u8, clear_pct: (w >> 16) as u8 })
    }
}

/// A change of the degrade level the power service holds, for the caller to
/// record (`Rule::BatteryDegrade`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LevelChange {
    /// The charge reported, percent.
    pub soc_pct: u8,
    /// The level before.
    pub from: u8,
    /// The level now.
    pub to: u8,
}

/// The live policy. All reads and writes are relaxed atomics: a setter races
/// with a governor evaluation harmlessly (either sees the old or the new
/// value, and [`Policy::clamp`] re-checks the floors at each evaluation).
pub struct Policy {
    governor: AtomicU8,
    opp_min: [AtomicU8; MAX_DOMAINS],
    opp_max: [AtomicU8; MAX_DOMAINS],
    headroom_pct: AtomicU32,
    rate_limit_us: AtomicU32,
    idle_depth: AtomicU8,
    power_cap_mw: [AtomicU32; MAX_DOMAINS],
    power_cap_opp: [AtomicU8; MAX_DOMAINS],
    parked: AtomicU32,
    qos_domains: [AtomicU8; QOS_CLASSES],
    rows: [AtomicU32; POLICY_DEGRADE_ROWS_MAX],
    soc_pct: AtomicU8,
    level: AtomicU8,
    reserve_charge: AtomicBool,
    stale: AtomicBool,
    reserve_pct: AtomicU8,
    report_timeout_ticks: AtomicU64,
    report_at: AtomicU64,
    degrades: AtomicU32,
    reserve_entries: AtomicU32,
    stale_entries: AtomicU32,
    applied: AtomicU32,
    refused: AtomicU32,
    floor_wins: AtomicU32,
    by_reason: [AtomicU32; POLICY_REFUSED_COUNT],
    log: [AtomicU64; LOG_LEN],
}

impl Policy {
    /// Boot state: the governor `g` the seams chose, no OPP cap, today's
    /// headroom and rate limit, no idle limit.
    pub const fn new(g: Governor) -> Self {
        Self {
            governor: AtomicU8::new(gov_code(g)),
            opp_min: [const { AtomicU8::new(0) }; MAX_DOMAINS],
            opp_max: [const { AtomicU8::new(NONE_U8) }; MAX_DOMAINS],
            headroom_pct: AtomicU32::new(HEADROOM_PCT),
            rate_limit_us: AtomicU32::new(RATE_LIMIT_US as u32),
            idle_depth: AtomicU8::new(NONE_U8),
            power_cap_mw: [const { AtomicU32::new(0) }; MAX_DOMAINS],
            power_cap_opp: [const { AtomicU8::new(NONE_U8) }; MAX_DOMAINS],
            parked: AtomicU32::new(0),
            qos_domains: [const { AtomicU8::new(u8::MAX) }; QOS_CLASSES],
            rows: [const { AtomicU32::new(0) }; POLICY_DEGRADE_ROWS_MAX],
            soc_pct: AtomicU8::new(NONE_U8),
            level: AtomicU8::new(0),
            reserve_charge: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            reserve_pct: AtomicU8::new(0),
            report_timeout_ticks: AtomicU64::new(0),
            report_at: AtomicU64::new(0),
            degrades: AtomicU32::new(0),
            reserve_entries: AtomicU32::new(0),
            stale_entries: AtomicU32::new(0),
            applied: AtomicU32::new(0),
            refused: AtomicU32::new(0),
            floor_wins: AtomicU32::new(0),
            by_reason: [const { AtomicU32::new(0) }; POLICY_REFUSED_COUNT],
            log: [const { AtomicU64::new(0) }; LOG_LEN],
        }
    }

    /// Set the boot governor (the seams' choice), before the scheduler runs.
    pub fn init(&self, g: Governor) {
        self.governor.store(gov_code(g), Relaxed);
    }

    /// Hand over the topology's degrade rows (at most
    /// [`POLICY_DEGRADE_ROWS_MAX`]; the rest are dropped) and the limits the
    /// kernel keeps on the battery, before the power service reports anything.
    /// `now` (timer ticks) starts the report age. Without a row there is no
    /// battery to watch and no report can go stale.
    pub fn init_battery(&self, rows: &[DegradeRow], limits: BatteryLimits, now: u64) {
        for (slot, r) in self.rows.iter().zip(rows) {
            slot.store(r.pack(), Relaxed);
        }
        self.reserve_pct.store(limits.reserve_pct, Relaxed);
        self.report_at.store(now, Relaxed);
        let watched = !rows.is_empty();
        self.report_timeout_ticks.store(if watched { limits.report_timeout_ticks } else { 0 }, Relaxed);
    }

    // ── readers ──────────────────────────────────────────────────────────

    /// The governor in force.
    pub fn governor(&self) -> Governor {
        match self.governor.load(Relaxed) {
            GOV_DEADLINE => Governor::DeadlineFloor,
            GOV_SCHEDUTIL => Governor::Schedutil,
            _ => Governor::Fixed,
        }
    }
    /// The governor that runs: the one asked for, or the deadline-floor
    /// governor while the battery reserve is held, which makes decisions even
    /// where the policy asked for none.
    pub fn effective_governor(&self) -> Governor {
        if self.reserve_active() {
            Governor::DeadlineFloor
        } else {
            self.governor()
        }
    }
    /// Schedutil headroom, percent.
    pub fn headroom_pct(&self) -> u32 {
        self.headroom_pct.load(Relaxed)
    }
    /// Shortest interval between evaluations of a domain, microseconds.
    pub fn rate_limit_us(&self) -> u32 {
        self.rate_limit_us.load(Relaxed)
    }
    /// Deepest idle state the idle governor may pick ([`NONE_U8`] = no limit).
    pub fn idle_depth(&self) -> u8 {
        self.idle_depth.load(Relaxed)
    }
    /// Domain `d`'s user range, `(min, max)` ([`NONE_U8`] max = no cap).
    pub fn opp_range(&self, d: usize) -> (u8, u8) {
        match (self.opp_min.get(d), self.opp_max.get(d)) {
            (Some(lo), Some(hi)) => (lo.load(Relaxed), hi.load(Relaxed)),
            _ => (0, NONE_U8),
        }
    }
    /// Domain `d`'s power cap, `(mw, opp)`: 0 mW and [`NONE_U8`] when none.
    pub fn power_cap(&self, d: usize) -> (u32, u8) {
        match (self.power_cap_mw.get(d), self.power_cap_opp.get(d)) {
            (Some(mw), Some(opp)) => (mw.load(Relaxed), opp.load(Relaxed)),
            _ => (0, NONE_U8),
        }
    }
    /// The mask of parked CPUs.
    pub fn parked(&self) -> u32 {
        self.parked.load(Relaxed)
    }
    /// The mask of domains QoS class `class` may be placed on (all of them
    /// until a mapping is set).
    pub fn qos_domains(&self, class: usize) -> u8 {
        self.qos_domains.get(class).map_or(u8::MAX, |m| m.load(Relaxed))
    }
    /// The topology's degrade rows, in file order.
    pub fn degrade_rows(&self) -> impl Iterator<Item = DegradeRow> + '_ {
        self.rows.iter().map_while(|w| DegradeRow::unpack(w.load(Relaxed)))
    }
    /// The charge last reported, percent ([`NONE_U8`] before the first report).
    pub fn soc_pct(&self) -> u8 {
        self.soc_pct.load(Relaxed)
    }
    /// The degrade level the power service holds (0 = none).
    pub fn level(&self) -> u8 {
        self.level.load(Relaxed)
    }
    /// The reserve is held: the reported charge is at or below the reserve, or
    /// the report is stale.
    pub fn reserve_active(&self) -> bool {
        self.reserve_charge.load(Relaxed) || self.stale.load(Relaxed)
    }
    /// The last accepted report is older than the timeout (see the module doc).
    pub fn stale(&self) -> bool {
        self.stale.load(Relaxed)
    }
    /// The battery reserve, percent ([`BatteryLimits::reserve_pct`]).
    pub fn reserve_pct(&self) -> u8 {
        self.reserve_pct.load(Relaxed)
    }
    /// Times a report went stale.
    pub fn stale_entries(&self) -> u32 {
        self.stale_entries.load(Relaxed)
    }
    /// Level changes the battery reports caused.
    pub fn degrades(&self) -> u32 {
        self.degrades.load(Relaxed)
    }
    /// Times the reserve was entered.
    pub fn reserve_entries(&self) -> u32 {
        self.reserve_entries.load(Relaxed)
    }
    /// The lightest level the rows allow at charge `soc_pct`: the most
    /// restrictive row whose threshold the charge is at or below (0: none).
    pub fn required_level(&self, soc_pct: u32) -> u8 {
        self.degrade_rows().filter(|r| soc_pct <= r.battery_pct as u32).map(|r| r.level).max().unwrap_or(0)
    }
    /// Setter calls applied.
    pub fn applied(&self) -> u32 {
        self.applied.load(Relaxed)
    }
    /// Setter calls refused.
    pub fn refused(&self) -> u32 {
        self.refused.load(Relaxed)
    }
    /// Refusals with reason code `r`.
    pub fn refused_by(&self, r: usize) -> u32 {
        self.by_reason.get(r).map_or(0, |c| c.load(Relaxed))
    }
    /// Evaluations where a floor overrode the user's cap.
    pub fn floor_wins(&self) -> u32 {
        self.floor_wins.load(Relaxed)
    }
    /// The `i`-th most recent refusal record (0 = newest), packed
    /// `op << 56 | reason << 48 | seq << 32 | arg`: `op` is the
    /// `POWER_OP_POLICY_*` number, `arg` the call's argument as it travels;
    /// 0 = none.
    pub fn refusal(&self, i: usize) -> u64 {
        let n = self.refused.load(Relaxed) as usize;
        if i >= n.min(LOG_LEN) {
            return 0;
        }
        self.log[(n - 1 - i) % LOG_LEN].load(Relaxed)
    }

    // ── the words the power service reads ────────────────────────────────

    /// The state word `sel` (`POLICY_STATE_*`), `None` for an unknown one.
    /// `cur_opp(d)` is the OPP the governor last recorded for domain `d`
    /// (255 before its first decision). The kernel's `policy_state` and the
    /// host suite read the same words through this.
    pub fn state_word(
        &self,
        m: &EnergyModel,
        mode: EnergyMode,
        cur_opp: impl Fn(usize) -> u8,
        sel: u64,
    ) -> Option<u64> {
        Some(match sel {
            POLICY_STATE_MODE => match mode {
                EnergyMode::Performance => 0,
                EnergyMode::Balanced => 1,
                EnergyMode::Endurance => 2,
            },
            POLICY_STATE_GOVERNOR => gov_code(self.governor()) as u64,
            POLICY_STATE_DOMAINS => m.domains().len() as u64,
            POLICY_STATE_HEADROOM => self.headroom_pct() as u64,
            POLICY_STATE_RATE_LIMIT => self.rate_limit_us() as u64,
            POLICY_STATE_IDLE_DEPTH => self.idle_depth() as u64,
            POLICY_STATE_PARKED => self.parked() as u64,
            POLICY_STATE_BATTERY => {
                self.soc_pct() as u64
                    | (self.level() as u64) << 8
                    | (self.reserve_active() as u64) << 16
                    | (self.degrade_rows().count() as u64) << 24
                    | (self.stale() as u64) << 32
                    | (self.reserve_pct() as u64) << 40
            }
            s if (POLICY_STATE_BATTERY_ROW_BASE..POLICY_STATE_BATTERY_ROW_BASE + POLICY_DEGRADE_ROWS_MAX as u64)
                .contains(&s) =>
            {
                let r = self.degrade_rows().nth((s - POLICY_STATE_BATTERY_ROW_BASE) as usize)?;
                r.level as u64 | (r.battery_pct as u64) << 8 | (r.clear_pct as u64) << 16
            }
            s if (POLICY_STATE_QOS_BASE..POLICY_STATE_QOS_BASE + QOS_CLASSES as u64).contains(&s) => {
                self.qos_domains((s - POLICY_STATE_QOS_BASE) as usize) as u64
            }
            s if (POLICY_STATE_POWER_CAP_BASE..POLICY_STATE_POWER_CAP_BASE + MAX_DOMAINS as u64).contains(&s) => {
                let di = (s - POLICY_STATE_POWER_CAP_BASE) as usize;
                m.domains().get(di)?;
                self.power_cap(di).0 as u64
            }
            s if (POLICY_STATE_CPUS_BASE..POLICY_STATE_CPUS_BASE + MAX_DOMAINS as u64).contains(&s) => {
                m.domains().get((s - POLICY_STATE_CPUS_BASE) as usize)?.cpus as u64
            }
            s if (POLICY_STATE_OPP_BASE..POLICY_STATE_OPP_BASE + MAX_DOMAINS as u64 * POLICY_STATE_OPP_STRIDE)
                .contains(&s) =>
            {
                let k = s - POLICY_STATE_OPP_BASE;
                let d = m.domains().get((k / POLICY_STATE_OPP_STRIDE) as usize)?;
                let o = d.opps().get((k % POLICY_STATE_OPP_STRIDE) as usize)?;
                o.power_mw as u64 | (o.capacity as u64) << 32
            }
            s if (POLICY_STATE_DOMAIN_BASE..POLICY_STATE_DOMAIN_BASE + MAX_DOMAINS as u64).contains(&s) => {
                let di = (s - POLICY_STATE_DOMAIN_BASE) as usize;
                let d = m.domains().get(di)?;
                let (lo, hi) = self.opp_range(di);
                d.opps().len() as u64
                    | (cur_opp(di) as u64) << 8
                    | (lo as u64) << 16
                    | (hi as u64) << 24
                    | (governor::safety_floor_opp(d) as u64) << 32
                    | (d.idle_states().len() as u64) << 40
            }
            _ => return None,
        })
    }

    /// The statistics word `sel` (`POLICY_STATS_*`), `None` for an unknown
    /// one. `evals` and `changes` are the governor's counters, which live
    /// with the scheduler.
    pub fn stats_word(&self, evals: u32, changes: u32, sel: u64) -> Option<u64> {
        Some(match sel {
            POLICY_STATS_EVALS => evals as u64,
            POLICY_STATS_CHANGES => changes as u64,
            POLICY_STATS_APPLIED => self.applied() as u64,
            POLICY_STATS_REFUSED => self.refused() as u64,
            POLICY_STATS_FLOOR_WINS => self.floor_wins() as u64,
            POLICY_STATS_DEGRADES => self.degrades() as u64,
            POLICY_STATS_RESERVE_ENTRIES => self.reserve_entries() as u64,
            POLICY_STATS_STALE_ENTRIES => self.stale_entries() as u64,
            s if (POLICY_STATS_LOG_BASE..POLICY_STATS_LOG_BASE + LOG_LEN as u64).contains(&s) => {
                self.refusal((s - POLICY_STATS_LOG_BASE) as usize)
            }
            s if (POLICY_STATS_BY_REASON_BASE..POLICY_STATS_BY_REASON_BASE + POLICY_REFUSED_COUNT as u64)
                .contains(&s) =>
            {
                self.refused_by((s - POLICY_STATS_BY_REASON_BASE) as usize) as u64
            }
            _ => return None,
        })
    }

    // ── setters ──────────────────────────────────────────────────────────

    fn done(&self, op: Op, arg: u32, r: Result<(), Refusal>) -> Result<(), Refusal> {
        match r {
            Ok(()) => {
                self.applied.fetch_add(1, Relaxed);
            }
            Err(why) => {
                let n = self.refused.fetch_add(1, Relaxed);
                self.by_reason[why as usize].fetch_add(1, Relaxed);
                if !cfg!(feature = "pl-record-canary") {
                    let rec = (op as u64) << 56
                        | (why as u64) << 48
                        | ((n as u64) & 0xFFFF) << 32
                        | arg as u64;
                    self.log[n as usize % LOG_LEN].store(rec, Relaxed);
                }
            }
        }
        r
    }

    /// Choose the frequency governor (`POLICY_GOV_*`).
    pub fn set_governor(&self, model: &EnergyModel, gov: u32) -> Result<(), Refusal> {
        let r = if !model.is_present() {
            Err(Refusal::NoModel)
        } else {
            match gov as u64 {
                POLICY_GOV_FIXED => {
                    self.governor.store(GOV_FIXED, Relaxed);
                    Ok(())
                }
                POLICY_GOV_DEADLINE_FLOOR => {
                    self.governor.store(GOV_DEADLINE, Relaxed);
                    Ok(())
                }
                _ => Err(Refusal::Governor),
            }
        };
        self.done(Op::Governor, gov, r)
    }

    /// Restrict domain `domain` to OPPs `min..=max`. `admitted_ppm` is the
    /// real-time density admitted on the domain's most loaded hart (the
    /// caller reads it from the ledger).
    pub fn set_opp_range(
        &self,
        model: &EnergyModel,
        domain: u32,
        min: u32,
        max: u32,
        admitted_ppm: u32,
    ) -> Result<(), Refusal> {
        // The wire form of the argument (`POWER_OP_POLICY_OPP_RANGE`).
        let arg = (domain & 0xFF) | (min & 0xFF) << 8 | (max & 0xFF) << 16;
        let r = (|| {
            if !model.is_present() {
                return Err(Refusal::NoModel);
            }
            let Some(d) = model.domains().get(domain as usize) else {
                return Err(Refusal::Domain);
            };
            if min > max || max as usize >= d.opps().len() {
                return Err(Refusal::Range);
            }
            if (max as usize) < governor::safety_floor_opp(d) && !cfg!(feature = "pl-floor-canary") {
                return Err(Refusal::SafetyFloor);
            }
            if (max as usize) < governor::deadline_floor_opp(d, admitted_ppm) && !cfg!(feature = "pl-floor-canary") {
                return Err(Refusal::DeadlineFloor);
            }
            self.opp_min[domain as usize].store(min as u8, Relaxed);
            self.opp_max[domain as usize].store(max as u8, Relaxed);
            Ok(())
        })();
        self.done(Op::OppRange, arg, r)
    }

    /// Set the schedutil headroom, percent.
    pub fn set_headroom(&self, pct: u32) -> Result<(), Refusal> {
        let r = if (POLICY_HEADROOM_MIN_PCT..=POLICY_HEADROOM_MAX_PCT).contains(&pct) {
            self.headroom_pct.store(pct, Relaxed);
            Ok(())
        } else {
            Err(Refusal::Headroom)
        };
        self.done(Op::Headroom, pct, r)
    }

    /// Set the shortest interval between governor evaluations, microseconds.
    pub fn set_rate_limit(&self, us: u32) -> Result<(), Refusal> {
        let r = if (POLICY_RATE_LIMIT_MIN_US..=POLICY_RATE_LIMIT_MAX_US).contains(&us) {
            self.rate_limit_us.store(us, Relaxed);
            Ok(())
        } else {
            Err(Refusal::RateLimit)
        };
        self.done(Op::RateLimit, us, r)
    }

    /// Limit the idle governor to states `0..=depth` ([`POLICY_IDLE_UNLIMITED`]
    /// lifts the limit). Refused deeper than any state the model lists.
    pub fn set_idle_depth(&self, model: &EnergyModel, depth: u32) -> Result<(), Refusal> {
        let deepest = model.domains().iter().map(|d| d.idle_states().len()).max().unwrap_or(0).saturating_sub(1);
        let r = if !model.is_present() {
            Err(Refusal::NoModel)
        } else if depth == POLICY_IDLE_UNLIMITED {
            self.idle_depth.store(NONE_U8, Relaxed);
            Ok(())
        } else if depth as usize > deepest {
            Err(Refusal::IdleDepth)
        } else {
            self.idle_depth.store(depth as u8, Relaxed);
            Ok(())
        };
        self.done(Op::IdleDepth, depth, r)
    }

    /// Cap domain `domain` at `mw` milliwatts (0 lifts the cap): the highest
    /// OPP whose power does not exceed it becomes a ceiling next to the OPP
    /// range, and the floors win over it at every evaluation like over the
    /// range. Refused when `mw` is below the power of the domain's slowest
    /// OPP (nothing runs that low), or when the OPP it names is below the
    /// WCET reference OPP (I6) or the admitted real-time floor (I1).
    pub fn set_power_cap(&self, model: &EnergyModel, domain: u32, mw: u32, admitted_ppm: u32) -> Result<(), Refusal> {
        let arg = (domain & 0xFF) | mw << 8;
        let r = (|| {
            if !model.is_present() {
                return Err(Refusal::NoModel);
            }
            let Some(d) = model.domains().get(domain as usize) else {
                return Err(Refusal::Domain);
            };
            let opp = if mw == 0 {
                NONE_U8
            } else {
                let Some(top) = d.opps().iter().rposition(|o| o.power_mw <= mw) else {
                    return Err(Refusal::Range);
                };
                if top + 1 == d.opps().len() {
                    NONE_U8
                } else {
                    if top < governor::safety_floor_opp(d) && !cfg!(feature = "pl-limit-canary") {
                        return Err(Refusal::SafetyFloor);
                    }
                    if top < governor::deadline_floor_opp(d, admitted_ppm) && !cfg!(feature = "pl-limit-canary") {
                        return Err(Refusal::DeadlineFloor);
                    }
                    top as u8
                }
            };
            self.power_cap_mw[domain as usize].store(mw, Relaxed);
            self.power_cap_opp[domain as usize].store(opp, Relaxed);
            Ok(())
        })();
        self.done(Op::PowerCap, arg, r)
    }

    /// Park the CPUs of `mask` (bit n = CPU n) and unpark the rest. Parked
    /// CPUs get no energy-aware (EAS) wake placement and idle as deep as the
    /// real-time slack allows. That is all parking does today: the
    /// load-based placement (`find_best_cpu`) and the fair-queue balancer do
    /// not read the mask, so work already on a parked CPU stays, and on a
    /// machine where EAS is off nothing is steered. Taking a CPU offline is
    /// the hotplug front's (`Rule::CpuHotplug`). `admitted_ppm[c]` is the real-time density admitted on
    /// CPU `c`. Refused when the mask names CPU 0 (it keeps the watchdog), a
    /// CPU the model does not cover, or every CPU of a domain; a CPU with
    /// admitted real-time work is refused as the deadline floor (I1).
    pub fn set_parked(&self, model: &EnergyModel, mask: u32, admitted_ppm: &[u32]) -> Result<(), Refusal> {
        let r = (|| {
            if !model.is_present() {
                return Err(Refusal::NoModel);
            }
            let covered = model.domains().iter().fold(0u32, |a, d| a | d.cpus);
            if mask & 1 != 0 || mask & !covered != 0 {
                return Err(Refusal::Park);
            }
            if model.domains().iter().any(|d| d.cpus & !mask == 0) {
                return Err(Refusal::Park);
            }
            let rt = (0..MAX_MODEL_CPUS.min(admitted_ppm.len()))
                .any(|c| mask & (1 << c) != 0 && admitted_ppm[c] != 0);
            if rt && !cfg!(feature = "pl-limit-canary") {
                return Err(Refusal::DeadlineFloor);
            }
            self.parked.store(mask, Relaxed);
            Ok(())
        })();
        self.done(Op::Park, mask, r)
    }

    /// Let tasks of QoS class `class` be placed on the domains of `domains`
    /// only (bit d = domain d). Read by the energy-aware wake placement
    /// alone (see [`Policy::set_parked`] for what that leaves out). Refused for an unknown class, an empty mask
    /// or one naming a domain the model does not have, and for the default
    /// and latency classes without the fastest domain: a latency promise is
    /// not kept on the slow cores.
    pub fn set_qos_domains(&self, model: &EnergyModel, class: u32, domains: u32) -> Result<(), Refusal> {
        let arg = (class & 0xFF) | domains << 8;
        let r = (|| {
            if !model.is_present() {
                return Err(Refusal::NoModel);
            }
            let n = model.domains().len();
            if class as usize >= QOS_CLASSES || domains == 0 || domains >> n != 0 {
                return Err(Refusal::Qos);
            }
            let fastest = model
                .domains()
                .iter()
                .enumerate()
                .max_by_key(|(i, d)| (d.max_capacity(), core::cmp::Reverse(*i)))
                .map_or(0, |(i, _)| i);
            let must_reach = class as u64 == azos_abi::syscall_nr::QOS_DEFAULT as u64
                || class as u64 == azos_abi::syscall_nr::QOS_LATENCY as u64;
            if must_reach && domains & (1 << fastest) == 0 && !cfg!(feature = "pl-limit-canary") {
                return Err(Refusal::Qos);
            }
            self.qos_domains[class as usize].store(domains as u8, Relaxed);
            Ok(())
        })();
        self.done(Op::QosDomains, arg, r)
    }

    /// The power service reports the battery: the charge it estimated and the
    /// degrade level it holds. Returns the change of that level for the caller
    /// to record, `None` when it is the same. Refused for a charge above 100
    /// %; for a level that is none of the topology's rows' (or 0), or lighter
    /// than the rows require at this charge; and on a machine whose topology
    /// declares no row, which has nothing to degrade. A charge at or below the
    /// reserve holds it (see the module doc). The caller follows an accepted
    /// report with [`Policy::battery_alive`].
    pub fn report_battery(&self, soc_pct: u32, level: u32) -> Result<Option<LevelChange>, Refusal> {
        let arg = (soc_pct & 0xFF) | level << 8;
        let known = level == 0 || self.degrade_rows().any(|r| r.level as u32 == level);
        let verdict = if self.degrade_rows().next().is_none()
            || soc_pct > 100
            || !known
            || (level as u8) < self.required_level(soc_pct) && !cfg!(feature = "pl-limit-canary")
        {
            Err(Refusal::Battery)
        } else {
            Ok(())
        };
        self.done(Op::Battery, arg, verdict)?;
        let held = soc_pct <= self.reserve_pct() as u32 && !cfg!(feature = "pl-reserve-canary");
        self.soc_pct.store(soc_pct as u8, Relaxed);
        if held && !self.reserve_charge.swap(true, Relaxed) {
            self.reserve_entries.fetch_add(1, Relaxed);
        } else if !held {
            self.reserve_charge.store(false, Relaxed);
        }
        let from = self.level.swap(level as u8, Relaxed);
        if from == level as u8 {
            return Ok(None);
        }
        self.degrades.fetch_add(1, Relaxed);
        Ok(Some(LevelChange { soc_pct: soc_pct as u8, from, to: level as u8 }))
    }

    /// The power service's report was accepted at `now` (timer ticks): the
    /// report age restarts and a stale hold ends (the charge it brought decides
    /// the reserve from here).
    pub fn battery_alive(&self, now: u64) {
        self.report_at.store(now, Relaxed);
        self.stale.store(false, Relaxed);
    }

    /// Age the last accepted report at `now` (timer ticks, from the scheduler
    /// tick): older than the timeout, the report is stale and the reserve is
    /// held. Returns whether the hold changed, for the caller to re-evaluate
    /// the governor. An age of exactly the timeout is still fresh.
    pub fn check_report_age(&self, now: u64) -> bool {
        let timeout = self.report_timeout_ticks.load(Relaxed);
        if timeout == 0 {
            return false;
        }
        let stale = now.saturating_sub(self.report_at.load(Relaxed)) > timeout && !cfg!(feature = "pl-stale-canary");
        if self.stale.swap(stale, Relaxed) == stale {
            return false;
        }
        if stale {
            self.stale_entries.fetch_add(1, Relaxed);
        }
        true
    }

    // ── enforcement at evaluation ────────────────────────────────────────

    /// Apply domain `d`'s user range to the governor's decision `dec`, then
    /// let the floors win again: the cap bounds the schedutil request and the
    /// range's floor raises it, but the deadline floor (I1) and the safety
    /// floor (I6) are never lowered. Counts a cap the floors overrode.
    pub fn clamp(&self, d: usize, dec: Decision) -> Decision {
        let (lo, hi) = self.opp_range(d);
        // The power cap and the held reserve are ceilings beside the range.
        let hi = hi.min(self.power_cap(d).1);
        let (lo, hi) = if self.reserve_active() { (0, 0) } else { (lo as usize, hi as usize) };
        let hi = hi.max(lo);
        let su = dec.schedutil.max(lo).min(hi);
        if cfg!(feature = "pl-clamp-canary") {
            // Canary: the cap applies to the whole decision, floors included.
            return Decision { opp: dec.opp.max(lo).min(hi), ..dec };
        }
        let out = governor::combine(su, Some(dec.deadline), dec.safety);
        if out.opp > hi {
            self.floor_wins.fetch_add(1, Relaxed);
        }
        out
    }
}

const fn gov_code(g: Governor) -> u8 {
    match g {
        Governor::Fixed => GOV_FIXED,
        Governor::Schedutil => GOV_SCHEDUTIL,
        Governor::DeadlineFloor => GOV_DEADLINE,
    }
}
