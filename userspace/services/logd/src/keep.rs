// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which decision and telemetry records `logd` writes to its files. The decision ring holds
//! every rule's records, a placement on every migrating wake among them, and
//! the files are a few hundred KiB (`LOGD_FILE_KB` x `LOGD_FILES_KEEP`): kept
//! whole they would push the kernel log out within seconds. So by default only
//! the refusals and denials are written (Kconfig `LOGD_DECISIONS_ALL` writes
//! every rule, for development), and never more than `LOGD_DECISIONS_PER_SEC`
//! a second: what the limit holds back is counted and written as one line per
//! period. The actuation telemetry is bounded the same way, per kind of event
//! (`LOGD_TELEMETRY_PER_SEC`), so a chatty motor cannot hold back a mode change
//! or an error. Pure: the host tests run this file as it ships
//! (`tests/host/libsys-tests`).

/// `azos_decision::Verdict::Refuse`.
pub const VERDICT_REFUSE: u8 = 1;
/// `azos_decision::Verdict::Deny`.
pub const VERDICT_DENY: u8 = 3;

/// Telemetry event kinds counted apart (`azos_actuation::logger::LOG_EVT_*` are below 16).
const KINDS: usize = 16;

/// The policy and this period's count.
pub struct Keep {
    all: bool,
    per_period: u64,
    used: u64,
    held: u64,
    telemetry_per_period: u64,
    telemetry_used: [u64; KINDS],
    telemetry_held: u64,
}

impl Keep {
    /// Every rule (`all`) or the refusals and denials, at most `per_sec` a
    /// second over periods of `period_ms` (at least one a period).
    /// Telemetry: `telemetry_per_sec` of each kind a second (at least one a
    /// period; none when 0).
    pub const fn new(all: bool, per_sec: u64, telemetry_per_sec: u64, period_ms: u64) -> Keep {
        Keep {
            all,
            per_period: per_period(per_sec, period_ms),
            used: 0,
            held: 0,
            telemetry_per_period: if telemetry_per_sec == 0 { 0 } else { per_period(telemetry_per_sec, period_ms) },
            telemetry_used: [0; KINDS],
            telemetry_held: 0,
        }
    }

    /// Is a record of `verdict` written? A refused one the rate limit held
    /// back is counted ([`Keep::period`]); one the policy leaves out is not.
    pub fn admit(&mut self, verdict: u8) -> bool {
        if !self.all && verdict != VERDICT_REFUSE && verdict != VERDICT_DENY {
            return false;
        }
        if self.used >= self.per_period {
            self.held += 1;
            return false;
        }
        self.used += 1;
        true
    }

    /// Is a telemetry record of `kind` written? One the rate limit held back is
    /// counted ([`Keep::telemetry_period`]).
    pub fn admit_telemetry(&mut self, kind: u16) -> bool {
        if self.telemetry_per_period == 0 {
            return false;
        }
        // Canary: one budget for every kind.
        #[cfg(feature = "canary-logd-telemetry-one-bucket")]
        let kind = 0;
        let used = &mut self.telemetry_used[kind as usize % KINDS];
        if *used >= self.telemetry_per_period {
            self.telemetry_held += 1;
            return false;
        }
        *used += 1;
        true
    }

    /// The period is over: how many decision records the limit held back in it.
    pub fn period(&mut self) -> u64 {
        let h = self.held;
        self.used = 0;
        self.held = 0;
        h
    }

    /// The period is over: how many telemetry records the limit held back in it.
    pub fn telemetry_period(&mut self) -> u64 {
        let h = self.telemetry_held;
        self.telemetry_used = [0; KINDS];
        self.telemetry_held = 0;
        h
    }
}

const fn per_period(per_sec: u64, period_ms: u64) -> u64 {
    let p = per_sec * period_ms / 1000;
    if p == 0 { 1 } else { p }
}
