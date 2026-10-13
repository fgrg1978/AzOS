// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side microbenchmarks for pure-logic kernel functions.
//!
//! These run on the host (cargo test --release) and measure
//! per-iteration latency of functions that are also exercised in the
//! kernel (via `#[wcet(...)]` annotations).  Goals:
//!
//! 1. **Detect logic regressions before bench.** If `parse_packet`
//!    suddenly gets 5× slower because someone added an allocation,
//!    a host microbench catches it in ~seconds, vs the 3-minute
//!    QEMU bench cycle.
//! 2. **Establish a portable baseline.** Host numbers are
//!    deterministic (no QEMU TCG rdcycle inflation), so two
//!    developers on the same hardware get matching results.
//! 3. **Complement kernel `wcet_per_fn`** — same functions
//!    measured under two regimes (host pure-logic vs kernel
//!    runtime), divergence between the two signals an
//!    integration cost (e.g. syscall overhead, lock contention).
//!
//! Output format mirrors the kernel's `[WCET]` log lines so the
//! brain `parse_wcet` collector can ingest it unchanged:
//!
//!     [HOST-UBENCH] <name> min=<ns> max=<ns> avg=<ns> samples=<n>
//!
//! Run with:
//!     cargo test --release --target aarch64-apple-darwin host_microbench
//!     # add `-- --nocapture` to see the printed measurements
//!
//! These are NOT gated as `#[ignore]` because they're fast (~ms
//! total) and serve as regression guards even under normal `cargo
//! test` runs.

use core::time::Duration;
use std::hint::black_box;
use std::time::Instant;

// Pull the same brain_protocol source the kernel ships, via #[path].
// Mirrors the pattern in property.rs.
#[allow(dead_code, unused_imports, clippy::all)]
#[path = "../../../../domains/robot/behavior/src/brain_protocol.rs"]
mod brain_protocol_src;

// ── Microbench primitives ────────────────────────────────────────────────────

/// Number of inner iterations per outer sample.  Picked so each sample
/// takes ~100 µs on a 2024-era host — long enough to amortise clock
/// jitter, short enough that 100 samples complete in 10 ms total.
const INNER_ITERS: u32 = 1000;

/// Number of outer samples to collect.  Final report uses min/max/avg
/// across these samples to dampen single-sample jitter.
const OUTER_SAMPLES: u32 = 100;

/// Run `body` `INNER_ITERS * OUTER_SAMPLES` times, return
/// (min_ns, max_ns, avg_ns) per single iteration.
fn measure<F: FnMut()>(name: &str, mut body: F) -> (u64, u64, u64) {
    let mut min_ns = u64::MAX;
    let mut max_ns = 0u64;
    let mut total_ns = 0u64;

    for _ in 0..OUTER_SAMPLES {
        let t0 = Instant::now();
        for _ in 0..INNER_ITERS {
            body();
        }
        let elapsed = t0.elapsed();
        let per_iter_ns = elapsed.as_nanos() as u64 / INNER_ITERS as u64;
        if per_iter_ns < min_ns { min_ns = per_iter_ns; }
        if per_iter_ns > max_ns { max_ns = per_iter_ns; }
        total_ns += per_iter_ns;
    }
    let avg_ns = total_ns / OUTER_SAMPLES as u64;

    // Format mirrors kernel [WCET] line for collector compatibility.
    println!(
        "[HOST-UBENCH] {} min={}ns max={}ns avg={}ns samples={}",
        name, min_ns, max_ns, avg_ns, OUTER_SAMPLES,
    );
    (min_ns, max_ns, avg_ns)
}

/// Sanity check: measure overhead of the timer-reading itself.  Any
/// per-op result smaller than this is hitting timing-resolution noise.
fn measure_timer_floor() -> u64 {
    let mut min_ns = u64::MAX;
    for _ in 0..OUTER_SAMPLES {
        let t0 = Instant::now();
        let _ = Instant::now().duration_since(t0);
        let elapsed = t0.elapsed().as_nanos() as u64;
        if elapsed < min_ns { min_ns = elapsed; }
    }
    min_ns
}

/// Enforce a per-iteration ceiling — or explain why it was skipped.
///
/// **Asserts on `min`, not `max`.** A maximum over 100 samples is the most
/// jitter-sensitive statistic there is: one scheduler preemption, one
/// migration, one competing build, and it triples. That is a property of the
/// machine, not of the code, and this project has already had a wall-clock
/// ceiling report a regression that did not exist. The minimum is the closest
/// thing to a noise-free reading when the machine cannot be quiesced, and a
/// genuine algorithmic regression moves it just as surely — nothing makes
/// `crc8` 10x slower in only its worst sample.
///
/// **Skipped under coverage instrumentation.** `-C instrument-coverage` adds a
/// counter increment per region, and on this host that inflates the MINIMUM
/// by 20-125x:
///
///     parse_packet_32B         35 ns ->  4379 ns   (125x)
///     crc8_64B                 69 ns ->  1405 ns    (20x)
///     build_parse_roundtrip    73 ns ->  1608 ns    (22x)
///
/// So `parse_packet_32B` clears its own 5000 ns ceiling by 12% under
/// instrumentation, which is luck, not headroom. The three ceilings failed
/// this way in the coverage run and took the whole suite -- and therefore all
/// of its regions -- out of the report, which is the one place they had no
/// business being enforced. The measurement still runs and still prints,
/// because the brain's `parse_wcet` collector ingests it either way.
///
/// Note what those uninstrumented figures also say about the ceilings: 35-73 ns
/// against limits of 5000-10000 ns is 70-140x of slack, so these catch a
/// catastrophic regression and nothing subtler. Tightening them is a real
/// decision (every notch traded against flakiness on a shared machine) and is
/// deliberately not taken here.
fn ceiling(name: &str, min_ns: u64, limit_ns: u64) {
    if std::env::var_os("AZOS_UBENCH_NO_CEILING").is_some() {
        println!("[HOST-UBENCH] {name}: ceiling skipped (instrumented build)");
        return;
    }
    assert!(
        min_ns < limit_ns,
        "{name}: {min_ns}ns per iteration exceeds the {limit_ns}ns ceiling. \
         This is the MINIMUM across {OUTER_SAMPLES} samples, so it is not host \
         noise -- something got genuinely slower.",
    );
}

// ── Microbenchmarks ──────────────────────────────────────────────────────────

#[test]
fn bench_crc8() {
    let payload = [0x12u8; 64];
    let (min, _max, _avg) = measure("crc8_64B", || {
        // black_box prevents the optimiser from constant-folding or
        // dead-stripping the call when its result is unused.  Without
        // it, release builds report 0 ns/iter because the loop body is
        // optimised away entirely.
        black_box(brain_protocol_src::crc8(black_box(&payload)));
    });
    // Sanity bound: 64-byte CRC on a 2024-era host should be ≤ 1 µs.
    // If this fires, someone replaced the table with a loop or added an
    // allocation per call.
    ceiling("crc8_64B", min, 5_000);
}

#[test]
fn bench_build_parse_packet_roundtrip() {
    let payload = [0x42u8; 32];
    let mut frame = [0u8; 256];
    let (min, _max, _avg) = measure("build_parse_packet_32B", || {
        let n = black_box(brain_protocol_src::build_packet(
            0x01, black_box(&payload), &mut frame,
        ));
        black_box(brain_protocol_src::parse_packet(black_box(&frame[..n])));
    });
    // Pure parser, no I/O.  Should be ≤ 2 µs even with allocation
    // (which there shouldn't be any of).
    ceiling("build_parse_roundtrip", min, 10_000);
}

#[test]
fn bench_parse_packet_only() {
    // Pre-build the frame outside the timed loop so we measure only
    // parsing.  Mirrors what the kernel's `parse_packet` `#[wcet(50_us)]`
    // annotation observes at runtime.
    let payload = [0x42u8; 32];
    let mut frame = [0u8; 256];
    let n = brain_protocol_src::build_packet(0x01, &payload, &mut frame);
    let frame_slice = &frame[..n];

    let (min, _max, _avg) = measure("parse_packet_32B", || {
        black_box(brain_protocol_src::parse_packet(black_box(frame_slice)));
    });
    // Parser-only — should be sub-microsecond on host.  CRC verify
    // dominates; for 32-byte payload that's ~40 byte CRC.
    ceiling("parse_packet_32B", min, 5_000);
}

#[test]
fn bench_timer_floor_diagnostic() {
    // Not a regression test — just prints the measurement floor so
    // results above are interpreted with the right resolution context.
    let floor_ns = measure_timer_floor();
    println!("[HOST-UBENCH] timer_floor min={}ns", floor_ns);
    // Sanity: timer reads should be < 1 µs on modern hardware.
    ceiling("timer_floor", floor_ns, 10_000);
}

// ── Compile-time alignment check ─────────────────────────────────────────────

/// Ensure the same `brain_protocol_src` path used by `property.rs` is in
/// scope here too.  Catches accidental relocation of the source file.
#[test]
fn brain_protocol_src_path_is_intact() {
    let _ = brain_protocol_src::crc8;
    let _ = brain_protocol_src::build_packet;
    let _ = brain_protocol_src::parse_packet;
}

#[allow(dead_code)]
const _: Duration = Duration::from_nanos(1);  // silence unused-import
