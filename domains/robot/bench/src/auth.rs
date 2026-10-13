// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Authentication subsystem microbenchmarks — auth_envelope
//! wrap/unwrap; secure_channel encrypt/decrypt (when RFC-0019 lands
//! kernel-side).  Stub for `--features auth` until per-bench state
//! setup is wired in.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_behavior::auth_envelope;

/// auth_envelope::wrap on a 64-byte payload.  Identity-passthrough when
/// no LINK.KEY is loaded; with key it's HMAC-SHA256 envelope.
pub fn bench_envelope_wrap(iters: u64) -> BenchResult {
    let payload = [0x33u8; 64];
    let mut out = [0u8; 64 + auth_envelope::ENVELOPE_OVERHEAD];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = auth_envelope::wrap(&payload, &mut out);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// auth_envelope::unwrap — verify HMAC + extract payload from envelope.
/// Pre-build the envelope outside the timed loop.
pub fn bench_envelope_unwrap(iters: u64) -> BenchResult {
    let payload = [0x55u8; 64];
    let mut env = [0u8; 64 + auth_envelope::ENVELOPE_OVERHEAD];
    let env_len = auth_envelope::wrap(&payload, &mut env);
    if env_len == 0 {
        return BenchResult::from_total(0, 0, 0);
    }
    let mut out = [0u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = auth_envelope::unwrap(&env[..env_len], &mut out);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("auth.envelope_wrap",   &best_of(|| bench_envelope_wrap(iters)));   n += 1;
    report("auth.envelope_unwrap", &best_of(|| bench_envelope_unwrap(iters))); n += 1;
    n
}
