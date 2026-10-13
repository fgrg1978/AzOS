// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The receipt of a refused run-time reservation. Kept out of `rt_core.rs`
//! so that file is the pure arithmetic and nothing else: the decision ring
//! this writes to uses 64-bit atomics, which the 32-bit micro kernel, that
//! compiles `rt_core.rs`, does not have.

use crate::rt_core::{refusal_numbers, Ask, HartLoad, Refusal};

/// The receipt of a refused run-time reservation: one `Rule::DeadlineAdmission`
/// / `Verdict::Refuse` record (Kconfig `DECISION_RECORDS_DEV` for the ring,
/// `DECISION_REFUSALS_DURABLE` for the flight recorder) with
/// [`refusal_numbers`]. `rt::reserve` calls it once, from its refusal arm.
pub fn record_refusal(tid: u32, why: Refusal, ask: Ask, loads: &[HartLoad], mask: u32, band_limit_ppm: u32) {
    azos_decision::record(
        azos_decision::Rule::DeadlineAdmission,
        azos_decision::Verdict::Refuse,
        tid,
        refusal_numbers(why, ask, loads, mask, band_limit_ppm),
    );
}
