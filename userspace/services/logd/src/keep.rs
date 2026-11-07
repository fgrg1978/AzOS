// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which decision and telemetry records `logd` writes to its files. The decision ring holds
//! every rule's records, a placement on every migrating wake among them, and
//! the files are a few hundred KiB (`LOGD_FILE_KB` x `LOGD_FILES_KEEP`): kept
//! whole they would push the kernel log out within seconds. So by default only
//! the refusals and denials are written (Kconfig `LOGD_DECISIONS_ALL` writes
//! every rule, for development), and never more than `LOGD_DECISIONS_PER_SEC`
//! a second: what the limit holds back is counted and written as one line per
//! period. The actuation telemetry is bounded per kind of event and per source
//! (a motor's id, an error's subsystem; `LOGD_TELEMETRY_PER_SEC`), so a chatty
//! motor cannot hold back another motor, a mode change or an error. What a
//! bucket's budget holds back is not lost to the newest: the newest held record
//! of the bucket is written at the end of the period with the count, so a
//! settled value survives. Pure: the host tests run this file as it ships
//! (`tests/host/libsys-tests`).

/// `azos_decision::Verdict::Refuse`.
pub const VERDICT_REFUSE: u8 = 1;
/// `azos_decision::Verdict::Deny`.
pub const VERDICT_DENY: u8 = 3;

/// `azos_actuation::logger::LOG_EVT_ACTUATOR_CMD`: payload byte 0 is the actuator.
const KIND_ACTUATOR_CMD: u16 = 2;
/// `azos_actuation::logger::LOG_EVT_ERROR`: payload byte 0 is the subsystem.
const KIND_ERROR: u16 = 8;

/// Payload bytes of a telemetry sample (`azos_records::TELEMETRY_PAYLOAD`).
pub const SAMPLE_BYTES: usize = 24;

/// A telemetry record as the reader handed it out.
#[derive(Clone, Copy)]
pub struct Sample {
    pub seq: u64,
    pub ts: u64,
    pub kind: u16,
    pub flags: u8,
    pub cpu: u8,
    pub len: u16,
    pub payload: [u8; SAMPLE_BYTES],
}

impl Sample {
    pub const fn empty() -> Sample {
        Sample { seq: 0, ts: 0, kind: 0, flags: 0, cpu: 0, len: 0, payload: [0; SAMPLE_BYTES] }
    }

    /// The budget this sample counts against: the kind and, for a motor
    /// command and an error, the actuator or subsystem; 1-based, 0 is free.
    fn key(&self) -> u32 {
        let source = if self.kind == KIND_ACTUATOR_CMD || self.kind == KIND_ERROR { self.payload[0] } else { 0 };
        1 + ((self.kind as u32) << 8 | source as u32)
    }
}

/// One budget of a period.
#[derive(Clone, Copy)]
struct Bucket {
    key: u32,
    used: u64,
    held: u64,
    newest: Sample,
}

const FREE: Bucket = Bucket { key: 0, used: 0, held: 0, newest: Sample::empty() };

/// The policy and this period's count; `KEYS` budgets of telemetry a period.
pub struct Keep<const KEYS: usize> {
    all: bool,
    per_period: u64,
    used: u64,
    held: u64,
    telemetry_per_period: u64,
    buckets: [Bucket; KEYS],
    /// Records of a period that found every budget taken by other keys.
    unplaced: u64,
}

impl<const KEYS: usize> Keep<KEYS> {
    /// Every rule (`all`) or the refusals and denials, at most `per_sec` a
    /// second over periods of `period_ms` (at least one a period).
    /// Telemetry: `telemetry_per_sec` of each kind and source a second (at
    /// least one a period; none when 0).
    pub const fn new(all: bool, per_sec: u64, telemetry_per_sec: u64, period_ms: u64) -> Keep<KEYS> {
        Keep {
            all,
            per_period: per_period(per_sec, period_ms),
            used: 0,
            held: 0,
            telemetry_per_period: if telemetry_per_sec == 0 { 0 } else { per_period(telemetry_per_sec, period_ms) },
            buckets: [FREE; KEYS],
            unplaced: 0,
        }
    }

    /// Is a decision record of `verdict` written? A refused one the rate limit
    /// held back is counted ([`Keep::period`]); one the policy leaves out is not.
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

    /// Is the telemetry sample written now? One its budget holds back is kept
    /// as the newest of its bucket and counted ([`Keep::telemetry_period`]).
    pub fn admit_telemetry(&mut self, s: &Sample) -> bool {
        if self.telemetry_per_period == 0 {
            return false;
        }
        let key = s.key();
        let Some(i) = self.buckets.iter().position(|b| b.key == key).or_else(|| self.buckets.iter().position(|b| b.key == 0)) else {
            self.unplaced += 1;
            return false;
        };
        let b = &mut self.buckets[i];
        b.key = key;
        // Canary: the newest held sample is not kept, the first one stays.
        #[cfg(feature = "canary-logd-telemetry-first-wins")]
        let keep_newest = b.held == 0;
        #[cfg(not(feature = "canary-logd-telemetry-first-wins"))]
        let keep_newest = true;
        // Canary: one budget for every kind and source.
        #[cfg(feature = "canary-logd-telemetry-one-bucket")]
        let b = &mut self.buckets[0];
        if b.used >= self.telemetry_per_period {
            b.held += 1;
            if keep_newest {
                b.newest = *s;
            }
            return false;
        }
        b.used += 1;
        true
    }

    /// The period is over: how many decision records the limit held back in it.
    pub fn period(&mut self) -> u64 {
        let h = self.held;
        self.used = 0;
        self.held = 0;
        h
    }

    /// The newest sample a held-back bucket kept and how many its budget held
    /// back, once each; `None` when every bucket has been taken.
    pub fn telemetry_held(&mut self) -> Option<(Sample, u64)> {
        let b = self.buckets.iter_mut().find(|b| b.held > 0)?;
        Some((b.newest, core::mem::take(&mut b.held)))
    }

    /// The period is over: the budgets start afresh. Returns the records no
    /// budget could be placed for.
    pub fn telemetry_period(&mut self) -> u64 {
        self.buckets = [FREE; KEYS];
        core::mem::take(&mut self.unplaced)
    }
}

const fn per_period(per_sec: u64, period_ms: u64) -> u64 {
    let p = per_sec * period_ms / 1000;
    if p == 0 { 1 } else { p }
}
