// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! The robot extension's benchmarks, reported like `azos_bench`'s.

mod protocol;

/// `azos_bench::run_all` and the brain protocol's benches: the one entry the
/// robot image's shell and boot bench call.
pub fn run_all(iters: u64) -> u32 {
    finish(azos_bench::run_all(iters), iters)
}

/// `azos_bench::run_all_quiescent` and the brain protocol's benches.
pub fn run_all_quiescent(iters: u64) -> u32 {
    finish(azos_bench::run_all_quiescent(iters), iters)
}

fn finish(base: u32, iters: u64) -> u32 {
    let n = base.saturating_add(protocol::run(iters));
    azos_drv_sys::kconsoleln!("[BENCH-RES] ── robot run_all done emitted={} ──", n);
    n
}
