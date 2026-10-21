// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Power` interface's limits and policy words (the interface is
//! `azos_devif::Power`, served by the kernel on the `power` endpoint to the
//! `POWER.ELF` tool).

// ── The energy policy ────────────────────────────────────────────────────────
//
// User space owns the power POLICY, the kernel only enforces LIMITS. These
// operations set the energy seams at run time (`azos_energy::policy`); a value
// outside the kernel's hard floors is refused and recorded. They are ops of the
// `Power` interface (`WRITE` to set, `READ` to read) and need the kernel
// feature `energy` (else `UNSUPPORTED`). A setter answers applied (`OK`, 0), or
// `REFUSED` with a `POLICY_REFUSED_*` reason (the limit check refused it;
// recorded), or another outcome (not a policy question: right, malformed call,
// no `energy`). The numbers below are the setter ids a refusal record carries.

/// Choose the frequency governor: `a2` = [`POLICY_GOV_FIXED`] or
/// [`POLICY_GOV_DEADLINE_FLOOR`]. Needs `WRITE`.
pub const POWER_OP_POLICY_GOVERNOR: u64 = 6;
/// Restrict one domain's OPP range: `a2` = `domain | min << 8 | max << 16`
/// (OPP indices, slowest first). Needs `WRITE`.
pub const POWER_OP_POLICY_OPP_RANGE: u64 = 7;
/// Schedutil headroom over the busiest CPU's demand, percent. Needs `WRITE`.
pub const POWER_OP_POLICY_HEADROOM: u64 = 8;
/// Shortest interval between two evaluations of a domain, microseconds.
/// Needs `WRITE`.
pub const POWER_OP_POLICY_RATE_LIMIT: u64 = 9;
/// Deepest idle state the idle governor may choose (0 = `wfi` only). Needs
/// `WRITE`.
pub const POWER_OP_POLICY_IDLE_DEPTH: u64 = 10;
/// Read the policy state word `a2` (a `POLICY_STATE_*` selector). Needs `READ`.
pub const POWER_OP_POLICY_STATE: u64 = 11;
/// Read the policy statistics word `a2` (a `POLICY_STATS_*` selector). Needs
/// `READ`.
pub const POWER_OP_POLICY_STATS: u64 = 12;
/// Cap one domain's power: `a2` = `domain | mw << 8` (0 mW lifts the cap). The
/// kernel turns it into an OPP cap through the energy model. Needs `WRITE`.
pub const POWER_OP_POLICY_POWER_CAP: u64 = 13;
/// Park CPUs: `a2` = the mask of CPUs to park (bit n = CPU n); the CPUs not in
/// it are unparked. A parked CPU gets no energy-aware wake placement and idles
/// as deep as the real-time slack allows. Needs `WRITE`.
pub const POWER_OP_POLICY_PARK: u64 = 14;
/// Map one QoS class to the domains its tasks may be placed on by the
/// energy-aware wake placement: `a2` = `class | domain_mask << 8`. Needs
/// `WRITE`.
pub const POWER_OP_POLICY_QOS_DOMAINS: u64 = 15;
/// Report the battery: `a2` = `soc_pct | level << 8` (the state of charge the
/// power service estimated and the degrade level, `0..=3` as `DEGRADE_LEVEL_*`,
/// it holds). Needs `WRITE`.
pub const POWER_OP_POLICY_BATTERY: u64 = 16;

/// Governor: no frequency request (the boot clock).
pub const POLICY_GOV_FIXED: u64 = 0;
/// Governor: schedutil with the deadline and safety floors. (1 is the bare
/// schedutil, which cannot honour the real-time floor: always refused.)
pub const POLICY_GOV_DEADLINE_FLOOR: u64 = 2;

/// Refusal: the machine has no energy model (nothing to govern).
pub const POLICY_REFUSED_NO_MODEL: u32 = 1;
/// Refusal: not a governor the kernel lets user space choose.
pub const POLICY_REFUSED_GOVERNOR: u32 = 2;
/// Refusal: no such performance domain.
pub const POLICY_REFUSED_DOMAIN: u32 = 3;
/// Refusal: `min > max`, or an OPP index the domain does not have.
pub const POLICY_REFUSED_RANGE: u32 = 4;
/// Refusal: the cap is below the domain's WCET reference frequency (the
/// safety path is never throttled, I6).
pub const POLICY_REFUSED_SAFETY_FLOOR: u32 = 5;
/// Refusal: the cap is below what the admitted real-time reservations need
/// (I1).
pub const POLICY_REFUSED_DEADLINE_FLOOR: u32 = 6;
/// Refusal: headroom outside `POLICY_HEADROOM_MIN_PCT..=POLICY_HEADROOM_MAX_PCT`.
pub const POLICY_REFUSED_HEADROOM: u32 = 7;
/// Refusal: rate limit outside `POLICY_RATE_LIMIT_MIN_US..=POLICY_RATE_LIMIT_MAX_US`.
pub const POLICY_REFUSED_RATE_LIMIT: u32 = 8;
/// Refusal: deeper than any idle state the model lists.
pub const POLICY_REFUSED_IDLE_DEPTH: u32 = 9;
/// Refusal: the parking mask names a CPU that cannot be parked (CPU 0, which
/// keeps the watchdog; a CPU outside the model; the last unparked CPU of its
/// domain). A CPU with admitted real-time work is `POLICY_REFUSED_DEADLINE_FLOOR`.
pub const POLICY_REFUSED_PARK: u32 = 10;
/// Refusal: not a QoS class, an empty domain mask, or a mask that exiles the
/// default or latency class from the fastest domain.
pub const POLICY_REFUSED_QOS: u32 = 11;
/// Refusal: a charge above 100 %, a level that is none of the topology's
/// `[degrade.NAME]` levels, a level below what the charge requires there, or a
/// machine whose topology declares no such row.
pub const POLICY_REFUSED_BATTERY: u32 = 12;
/// Number of refusal codes plus one (index bound for per-reason counters).
pub const POLICY_REFUSED_COUNT: usize = 13;

/// Hard limit: least headroom, percent.
pub const POLICY_HEADROOM_MIN_PCT: u32 = 10;
/// Hard limit: most headroom, percent.
pub const POLICY_HEADROOM_MAX_PCT: u32 = 100;
/// Hard limit: shortest evaluation interval, microseconds.
pub const POLICY_RATE_LIMIT_MIN_US: u32 = 1_000;
/// Hard limit: longest evaluation interval, microseconds.
pub const POLICY_RATE_LIMIT_MAX_US: u32 = 1_000_000;

/// State selector: the energy mode the signed topology chose (0 performance,
/// 1 balanced, 2 endurance).
pub const POLICY_STATE_MODE: u64 = 0;
/// State selector: the governor in force (0, 1 or 2).
pub const POLICY_STATE_GOVERNOR: u64 = 1;
/// State selector: number of performance domains.
pub const POLICY_STATE_DOMAINS: u64 = 2;
/// State selector: headroom, percent.
pub const POLICY_STATE_HEADROOM: u64 = 3;
/// State selector: rate limit, microseconds.
pub const POLICY_STATE_RATE_LIMIT: u64 = 4;
/// State selector: idle depth limit (`POLICY_IDLE_UNLIMITED` = none).
pub const POLICY_STATE_IDLE_DEPTH: u64 = 5;
/// State selector: the mask of parked CPUs.
pub const POLICY_STATE_PARKED: u64 = 6;
/// State selector: the battery, packed `soc_pct | level << 8 |
/// reserve_held << 16 | rows << 24 | stale << 32 | reserve_pct << 40`.
/// `soc_pct` is 255 until the power service reported one; `level` is the
/// degrade level the service holds (0 = none); `reserve_held` is set at and
/// below the reserve and while the report is stale; `stale` is set when the
/// last accepted report is older than the kernel's timeout; `reserve_pct` is
/// the reserve (Kconfig `ENERGY_BATTERY_RESERVE_PCT`).
pub const POLICY_STATE_BATTERY: u64 = 7;
/// State selector base: `POLICY_STATE_BATTERY_ROW_BASE + i` is the topology's
/// `[degrade.NAME]` row `i` (file order), packed `level | battery_pct << 8 |
/// clear_pct << 16`: the level is entered at or below `battery_pct` and left
/// above `clear_pct`.
pub const POLICY_STATE_BATTERY_ROW_BASE: u64 = 0x80;
/// State selector base: `POLICY_STATE_QOS_BASE + class` is the mask of domains
/// QoS class `class` may be placed on.
pub const POLICY_STATE_QOS_BASE: u64 = 0xC0;
/// State selector base: `POLICY_STATE_POWER_CAP_BASE + d` is domain `d`'s power
/// cap in mW (0 = none).
pub const POLICY_STATE_POWER_CAP_BASE: u64 = 0xE0;
/// State selector base: `POLICY_STATE_CPUS_BASE + d` is the mask of CPUs of
/// domain `d` (bit n = CPU n).
pub const POLICY_STATE_CPUS_BASE: u64 = 0xF0;
/// State selector base: `POLICY_STATE_OPP_BASE + d * 16 + i` is OPP `i` of
/// domain `d`, packed `power_mw | capacity << 32` (capacity on a scale of
/// 1024 for the fastest CPU of the machine at its fastest OPP).
pub const POLICY_STATE_OPP_BASE: u64 = 0x200;
/// OPP indices per domain in the `POLICY_STATE_OPP_BASE` selector space.
pub const POLICY_STATE_OPP_STRIDE: u64 = 16;
/// State selector base: `POLICY_STATE_DOMAIN_BASE + d` is domain `d`, packed
/// `n_opps | cur_opp << 8 | min << 16 | max << 24 | safety_floor << 32 |
/// n_idle << 40` (`cur_opp` = 255 before the governor's first decision, `max`
/// = 255 for no cap).
pub const POLICY_STATE_DOMAIN_BASE: u64 = 0x100;
/// The idle depth meaning "no limit".
pub const POLICY_IDLE_UNLIMITED: u32 = 255;

/// Stats selector: governor evaluations.
pub const POLICY_STATS_EVALS: u64 = 0;
/// Stats selector: evaluations that changed a domain's OPP.
pub const POLICY_STATS_CHANGES: u64 = 1;
/// Stats selector: setter calls applied.
pub const POLICY_STATS_APPLIED: u64 = 2;
/// Stats selector: setter calls refused.
pub const POLICY_STATS_REFUSED: u64 = 3;
/// Stats selector: evaluations where a floor overrode the user's cap.
pub const POLICY_STATS_FLOOR_WINS: u64 = 4;
/// Stats selector: degrade level changes the battery reports caused (each left
/// a `Rule::BatteryDegrade` record).
pub const POLICY_STATS_DEGRADES: u64 = 5;
/// Stats selector: times the battery reserve was entered.
pub const POLICY_STATS_RESERVE_ENTRIES: u64 = 6;
/// Stats selector: times the power service's report went stale (older than
/// Kconfig `ENERGY_BATTERY_REPORT_TIMEOUT_MS`), each holding the reserve.
pub const POLICY_STATS_STALE_ENTRIES: u64 = 7;
/// Stats selector base: `POLICY_STATS_LOG_BASE + i` is the `i`-th most recent
/// refusal record, packed `op << 56 | reason << 48 | seq << 32 | arg` (0 = none):
/// `op` is the `POWER_OP_POLICY_*` number and `arg` the call's argument as it
/// travelled (`seq` counts refusals, modulo 65536).
pub const POLICY_STATS_LOG_BASE: u64 = 0x10;
/// Stats selector base: `POLICY_STATS_BY_REASON_BASE + r` counts refusals with
/// reason `r`.
pub const POLICY_STATS_BY_REASON_BASE: u64 = 0x20;

/// `soc_pct` before the power service reported one.
pub const POLICY_SOC_UNKNOWN: u32 = 255;
/// Most degrade rows a topology declares (`azos_topology::MAX_DEGRADE_ROWS`).
pub const POLICY_DEGRADE_ROWS_MAX: usize = 3;

/// Lowest rate `POWER_OP_SCHED_HZ_SET` takes; the console's `sched_hz` range.
pub const POWER_SCHED_HZ_MIN: u64 = 10;
/// Highest rate `POWER_OP_SCHED_HZ_SET` takes.
pub const POWER_SCHED_HZ_MAX: u64 = 10_000;
