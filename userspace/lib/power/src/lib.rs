// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The power policy's library: how the energy seams are set at run time.
//!
//! Policy lives in user space (`userspace/services/power`); the kernel only
//! enforces limits (`azos_energy::policy`: the real-time deadline floor, the
//! safety path's WCET floor, the idle slack). So the interface is a typed set
//! of setters whose every call returns a **verdict**:
//!
//! * `0`: applied;
//! * `1..=9`: refused by a kernel limit and recorded (`POLICY_REFUSED_*` in
//!   `azos_abi::power`);
//! * bit 31 set: the call itself failed, the low bits are the interface's
//!   outcome code (`azos_devif::outcome`): no right, malformed, no `energy`
//!   in the kernel.
//!
//! The kernel serves the interface on the `power` endpoint
//! (`azos_devif::Power`); the trait here is the policy logic's view of it.

#![no_std]

pub use azos_abi::power::*;
pub use azos_devif::outcome;

/// The policy server's view of the policy setters: what its logic needs of
/// the kernel, one verdict per setter. The kernel hosts the `Power`
/// interface (`azos_devif`); the tool implements this trait over its client
/// stub, and the host suite (`tests/host/power-tests`) over a model of the
/// kernel's limits.
pub trait PowerPolicy {
    /// Choose the governor: [`POLICY_GOV_FIXED`] or [`POLICY_GOV_DEADLINE_FLOOR`].
    fn set_governor(&mut self, gov: u32) -> u32;
    /// Restrict domain `domain` to OPP indices `min..=max` (slowest first).
    fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> u32;
    /// Schedutil headroom, percent.
    fn set_headroom(&mut self, pct: u32) -> u32;
    /// Shortest interval between two governor evaluations, microseconds.
    fn set_rate_limit(&mut self, us: u32) -> u32;
    /// Deepest idle state the idle governor may pick; [`POLICY_IDLE_UNLIMITED`]
    /// lifts the limit.
    fn set_idle_depth(&mut self, depth: u32) -> u32;
    /// A state word (`POLICY_STATE_*`); [`WORD_ERR`] if the call failed.
    fn state(&self, sel: u32) -> u64;
    /// A statistics word (`POLICY_STATS_*`); [`WORD_ERR`] if the call failed.
    fn stats(&self, sel: u32) -> u64;
}

/// Bit 31 of a verdict: the call failed (not a policy question); the low bits
/// are the interface's outcome code (`azos_devif::outcome`).
pub const VERDICT_FAILED: u32 = 1 << 31;
/// A word reader's answer when the call failed.
pub const WORD_ERR: u64 = u64::MAX;

/// The verdict a setter's answer means: applied (0), refused by a kernel limit
/// (the `POLICY_REFUSED_*` reason), or failed (bit 31 and the outcome).
pub const fn verdict_of(code: u32, value: u32) -> u32 {
    match code {
        outcome::OK => 0,
        outcome::REFUSED => value,
        c => VERDICT_FAILED | c,
    }
}

/// The word a reader answered ([`WORD_ERR`] when the call failed).
pub const fn word_of(code: u32, value: u64) -> u64 {
    if code == outcome::OK {
        value
    } else {
        WORD_ERR
    }
}

/// What a verdict means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Applied.
    Applied,
    /// Refused by a kernel limit (`POLICY_REFUSED_*`).
    Refused(u32),
    /// The call failed (the interface's outcome code).
    Failed(u32),
}

impl Verdict {
    /// Decode a verdict word.
    pub const fn of(v: u32) -> Verdict {
        if v == 0 {
            Verdict::Applied
        } else if v & VERDICT_FAILED != 0 {
            Verdict::Failed(v & !VERDICT_FAILED)
        } else {
            Verdict::Refused(v)
        }
    }
}

/// The name of a refusal code, for the log.
pub const fn refusal_name(code: u32) -> &'static str {
    match code {
        POLICY_REFUSED_NO_MODEL => "no-model",
        POLICY_REFUSED_GOVERNOR => "governor",
        POLICY_REFUSED_DOMAIN => "domain",
        POLICY_REFUSED_RANGE => "range",
        POLICY_REFUSED_SAFETY_FLOOR => "safety-floor",
        POLICY_REFUSED_DEADLINE_FLOOR => "deadline-floor",
        POLICY_REFUSED_HEADROOM => "headroom",
        POLICY_REFUSED_RATE_LIMIT => "rate-limit",
        POLICY_REFUSED_IDLE_DEPTH => "idle-depth",
        _ => "unknown",
    }
}
