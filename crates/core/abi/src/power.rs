// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Power` interface's limits and policy words (RFC-0055 S5, RFC-0051;
//! the interface is `azos_devif::Power`, served by the kernel on the `power`
//! endpoint to the `POWER.ELF` tool).

// ── The energy policy (RFC-0051 / owner plan Energy section 8) ───────────────
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
/// Number of refusal codes plus one (index bound for per-reason counters).
pub const POLICY_REFUSED_COUNT: usize = 10;

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
/// Stats selector base: `POLICY_STATS_LOG_BASE + i` is the `i`-th most recent
/// refusal record, packed `op << 56 | reason << 48 | seq << 32 | arg` (0 = none):
/// `op` is the `POWER_OP_POLICY_*` number and `arg` the call's argument as it
/// travelled (`seq` counts refusals, modulo 65536).
pub const POLICY_STATS_LOG_BASE: u64 = 0x10;
/// Stats selector base: `POLICY_STATS_BY_REASON_BASE + r` counts refusals with
/// reason `r`.
pub const POLICY_STATS_BY_REASON_BASE: u64 = 0x20;

/// Lowest rate `POWER_OP_SCHED_HZ_SET` takes; the console's `sched_hz` range.
pub const POWER_SCHED_HZ_MIN: u64 = 10;
/// Highest rate `POWER_OP_SCHED_HZ_SET` takes.
pub const POWER_SCHED_HZ_MAX: u64 = 10_000;
