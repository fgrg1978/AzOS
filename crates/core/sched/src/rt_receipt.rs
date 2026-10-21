// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What `rt::reserve` says to the rest of the system around its admission: the
//! question to the Domain's `rt_time` envelope row, and the receipt of a refused
//! run-time reservation. Kept out of `rt_core.rs` so that file is the pure
//! arithmetic and nothing else: the decision ring this writes to uses 64-bit
//! atomics, which the 32-bit micro kernel, that compiles `rt_core.rs`, does not
//! have. Kept out of `rt.rs` so the host suite (`tests/host/sched-policy-tests`)
//! runs both against the real gate hook instead of reading the source.

use crate::rt_core::{self, refusal_numbers, Ask, HartLoad, Refusal};

/// Does the `rt_time` row of the Domain of task `tid` hold a reservation of
/// this shape (Documentation/effects.md)? One question per reservation, asked
/// by `rt::reserve` before it masks anything or takes `ADMIT`, because the
/// answer probes the topology and a refusal queues the gate's receipt. A shape
/// with no density (malformed) is not asked: admission refuses it for what is
/// wrong with it. A Domain whose row says `full`, a task of no row (the
/// kernel's own) and a build with no gate answer "not held" without a record.
///
/// `rt-envelope-canary` (host suite only, never in a build) skips the question.
pub fn held_by_row(tid: u32, runtime_us: u64, period_us: u64, deadline_us: u64) -> bool {
    if cfg!(feature = "rt-envelope-canary") {
        return false;
    }
    match rt_core::density_ppm(runtime_us, period_us, deadline_us) {
        Ok(density_ppm) => !azos_common::envelope::asked(azos_common::envelope::Ask::RtTime { tid, density_ppm }),
        Err(_) => false,
    }
}

/// The receipt of a refused run-time reservation: one `Rule::DeadlineAdmission`
/// / `Verdict::Refuse` record (Kconfig `DECISION_RECORDS_DEV` for the ring,
/// `DECISION_REFUSALS_DURABLE` for the flight recorder) with
/// [`refusal_numbers`]. `rt::reserve` calls it once, from its refusal arm.
/// A refusal by the Domain's row ([`Refusal::Envelope`]) writes nothing here:
/// the effect gate wrote it (`Rule::EnvelopeRtTime`, with its receipt) when it
/// answered no, and a refusal is one record.
pub fn record_refusal(tid: u32, why: Refusal, ask: Ask, loads: &[HartLoad], mask: u32, band_limit_ppm: u32) {
    if why == Refusal::Envelope {
        return;
    }
    azos_decision::record(
        azos_decision::Rule::DeadlineAdmission,
        azos_decision::Verdict::Refuse,
        tid,
        refusal_numbers(why, ask, loads, mask, band_limit_ppm),
    );
}
