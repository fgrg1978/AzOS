// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Synthetic microbenchmarks for kernel subsystems.
//!
//! # Goal
//!
//! Give every subsystem (IPC, MM, sched, net, fs, crypto, auth, …) a tight-
//! loop microbenchmark that measures per-operation latency in CPU cycles.
//! Run from the kernel shell (`bench <subsystem>` or `bench all`) and from
//! the bench harness (which injects `bench all` automatically and parses
//! the `[BENCH-RES]` lines into the JSON sidecar consumed by
//! `bench_compare.py`).
//!
//! # Why synthetic vs `#[wcet(...)]` runtime instrumentation?
//!
//! - `#[wcet(...)]` measures the OPPORTUNISTIC cost: the function gets
//!   sampled whenever the live workload happens to call it.  Coverage is
//!   uneven (cap_get + channel_* never fire if no userspace task uses
//!   them) and per-sample wall time includes cross-hart contention that
//!   varies run-to-run.
//! - Synthetic microbenches run a tight loop INSIDE the bench function
//!   itself.  N=1000 iterations measured by a single `rdcycle` delta
//!   amortises the per-call jitter and gives a stable
//!   "this primitive costs X cycles avg" number.
//!
//! Both layers coexist: `#[wcet(...)]` for runtime distribution under
//! real load; `bench_*` for synthetic baselines that don't depend on
//! workload shape.
//!
//! # Wire format
//!
//! Each bench emits one line:
//!
//!     [BENCH-RES] <subsystem>.<name> iters=<N> min_cycles=<X>
//!                 max_cycles=<X> avg_cycles=<X> total_cycles=<X> repeats=<K>
//!
//! (or, for the common case where only a whole-loop bracket was ever taken —
//! `tail_measured == false`, see [`BenchResult`] — `avg_cycles`,
//! `total_cycles`, `repeats=<K>` and a trailing `tail=unmeasured` instead of
//! `min`/`max`; see [`report`]).
//!
//! Brain-side `parse_bench` (in `tools/bench_e2e_collect.py`) ingests
//! these and emits a top-level `bench_synth` dict into the result JSON:
//!
//!     {"bench_synth": {"ipc.channel_send_recv": {iters, min_c, max_c,
//!                                                avg_c}, …}}
//!
//! Same direction-aware regression gate as `wcet_per_fn` (smaller-is-
//! better for `.avg_cycles`, `.max_cycles`).
//!
//! # What these numbers can and cannot support
//!
//! **Baseline measured 2026-09-06, four runs of one identical binary under
//! QEMU TCG SMP-4, before the fix below existed (`repeats=1`, every bracket
//! taken once).** Median run-to-run spread across the 49 measurements:
//! **1.12x**. Worst: `net.ip_checksum_20B` at **16.3x** — 210, 150, 2450, 150
//! cycles. Tightest: `crypto.sc_handshake` at 1.04x (848k-882k cycles).
//!
//! The pattern was not random. The stable measurements were the expensive
//! ones, and the volatile ones were all near the cost of reading the counter
//! itself: `mm.read_cycles` reports ~210 cycles for one `rdcycle`, and every
//! measurement whose average is in the low hundreds is the same order as its
//! own instrument. The 2450 outlier was a whole-loop bracket that a
//! preemption landed inside — `total_cycles` for that run was ~245k against
//! ~15k.
//!
//! So, concretely:
//!
//! * A change worth **less than ~1.2x** on a cheap measurement **could not be
//!   detected here**, and a difference that size between two runs was not
//!   evidence of anything. This was established the hard way: after moving a
//!   spinning probe off the hart that carries motor control, the obvious
//!   question — did the latency improve — was one this harness could not
//!   answer. The fix below narrows this (see the K comparison), but does not
//!   remove it: the cleanest post-fix batch still had a 1.05x-1.13x median.
//! * The crypto lane IS trustworthy at the few-percent level, because a
//!   ~850k-cycle operation swamps both the instrument and a stray preemption.
//! * `emitted=49` is what the gate asserts, and that is the right thing for it
//!   to assert: the values are not stable enough to gate on, and the failure
//!   that actually happens silently is a subsystem ceasing to measure at all.
//!
//! ## The fix: [`best_of`] — repeat the bracket, keep the lowest total
//!
//! [`best_of`] re-runs a whole bench (its own setup + its whole `iters`-length
//! loop) [`BENCH_REPEATS`] times and keeps the repetition with the lowest
//! `total_cycles`. Every `run()` in this crate calls every `bench_*` through
//! it, so all 49 `[BENCH-RES]` lines now carry `repeats=<BENCH_REPEATS>`
//! instead of the implicit `repeats=1` above. This is a fix for exactly one
//! failure mode: a preemption landing inside *one* bracket of *one* run. It
//! does nothing for a whole QEMU boot running slow (see below) — every
//! repetition inside a stalled boot is stalled together, so the minimum
//! among them is still stalled.
//!
//! **K was chosen from measured spread, not taste** — four QEMU-TCG runs of
//! one identical binary per K, same protocol as the baseline above:
//!
//! | K | worst ratio | median ratio | wall time (boot+bench) |
//! |---|---|---|---|
//! | 1 (baseline, no repeat) | 16.3x (`net.ip_checksum_20B`) | 1.12x | ~2 s |
//! | 3 | 1.49x (`sched.task_yield`); several benches 1.27-1.35x | 1.13x | ~4 s |
//! | 5 | 1.50x (`cap.get_verify`, a 20-cycle floor measurement) in the
//!       cleanest batch; the specific documented outlier
//!       (`net.ip_checksum_20B`) never exceeded 1.31x in any batch | 1.05-1.13x
//!       across batches | ~4-6 s |
//! | 9 | 2.00x (`ipc.lease_active_count`), 1.91x (`crypto.x25519_scalarmult`)
//!       | 1.14x | ~4-6 s |
//!
//! K=3 does not reliably reject the outlier: with only 3 samples the
//! best-of-3 total is still frequently the elevated one, and several
//! benches other than the documented outlier climbed above 1.25x. K=5 is
//! where the *specific, documented* failure mode — a single preemption tick
//! landing inside one bracket — stopped reproducing: across two independent
//! four-run batches (one on a quiet host, one on a loaded one, load average
//! ~7 from concurrent builds elsewhere on this machine), `net.ip_checksum_20B`
//! stayed at 1.31x or tighter every time, down from the 16.3x it was chosen
//! to fix. K=9 bought nothing further for that failure mode and cost ~80%
//! more wall time for it: its worst ratios (2.0x, 1.9x) landed on *different*
//! benches than K=5's, which is the signature of a confound, not of K=9
//! finding a *cleaner* floor — see below. Wall time is a non-issue at any of
//! these K: the gate budgets 180 s for this scenario and even K=9 finished
//! in single-digit seconds, because QEMU boot dominates the wall clock, not
//! the bench loop. **Chosen: `BENCH_REPEATS = 5`** — it is the smallest K
//! that measurably closed the documented gap, and going further did not
//! close it any further.
//!
//! **What the K experiment surfaced that it cannot fix:** the two noisy
//! batches above (K=5's second batch, and K=9) were run back-to-back with
//! other cargo builds active on the same host (`uptime` load average ~7).
//! Their outliers landed on different, unrelated benches each time
//! (`ipc.pipe_write_read`, `mm.kheap_free`, `ipc.lease_active_count`,
//! `crypto.x25519_scalarmult`, …) with ratios up to 2.7x — well past the
//! 1.2x floor this crate already documented as its detection limit. That is
//! host-level contention stalling an *entire* QEMU boot, not a preemption
//! inside one bracket, and no amount of intra-run repetition touches it: if
//! the host stalls, every one of the `BENCH_REPEATS` repetitions stalls with
//! it, and the minimum is a minimum over stalled samples. The existing
//! `[WCET]`/`[JITTER]` reports from that same run showed `timer_isr` jitter
//! up to ~43 ms (against ~15-18 ms on a quiet host), confirming the host, not
//! the kernel, was the source. Comparing runs across this crate — or against
//! Linux — is only valid when nothing else on the host is building or
//! benchmarking at the same time; this was already true before this change
//! and remains true after it.

#![no_std]
// Bench names carry byte-size suffixes (`_64B`, `_1K`, `_256B`, `_1500B`)
// that read far better than the snake-case the linter wants
// (`_64_b`/`_1_k`).  The suffix IS the spec — it names the payload size the
// number applies to — so we keep it and silence the lint crate-wide.
#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Default iteration count per bench.  Picked so a single bench takes
/// ~ms on a 2024 host (10× that under QEMU TCG).  Override via the
/// `iters` argument to each `bench_*` function.
pub const DEFAULT_ITERS: u64 = 1000;

/// How many times [`best_of`] re-runs a bench's whole-loop bracket before
/// keeping the lowest `total_cycles`.  Chosen from measured spread, not
/// taste — see the module docs for the full K=3/5/9 comparison. In short:
/// K=5 is the smallest K at which the documented 16.3x preemption outlier
/// (`net.ip_checksum_20B`) stopped reproducing across repeated four-run
/// batches (never exceeded 1.31x afterward); K=9 bought nothing further for
/// that outlier. Wall time is not the constraint at any of these K — the
/// gate budgets 180 s for `run_all` and even K=9 finished in single-digit
/// seconds, dominated by QEMU boot rather than the bench loop.
pub const BENCH_REPEATS: u32 = 5;

/// Result of one microbenchmark.  All cycle counts come from
/// `azos_drv_sys::wcet::read_cycles()`.
#[derive(Copy, Clone)]
pub struct BenchResult {
    /// Number of iterations executed per loop repetition.
    pub iters: u64,
    /// `total_cycles / iters` from the winning repetition — **not** a
    /// per-iteration minimum. See [`min_cycles`](Self::min_cycles).
    ///
    /// This is only meaningful when [`tail_measured`](Self::tail_measured)
    /// is true. When it is false this holds the same value as `avg`,
    /// because the bench bracketed the whole loop with two `rdcycle` reads
    /// instead of timing each iteration. That is a deliberate trade — a
    /// single `rdcycle` costs about as much as the cheapest operation
    /// measured here (`mm.read_cycles` reports ~210 cycles), so
    /// per-iteration timing would dominate a 220-cycle result — but it
    /// means there is no per-iteration distribution to report, whatever
    /// `repeats` says.
    pub min_cycles: u64,
    /// Largest single-iter cycle delta observed.  See `min_cycles`.
    pub max_cycles: u64,
    /// Average cycles per iteration (`total_cycles / iters`) **of the
    /// winning repetition** — see [`repeats`](Self::repeats).
    pub avg_cycles: u64,
    /// Total cycles around the entire N-iteration loop, for the winning
    /// repetition (the lowest of `repeats` such totals).
    pub total_cycles: u64,
    /// How many times the whole `iters`-length loop was bracketed and
    /// timed before this result kept the lowest `total_cycles`.
    ///
    /// `1` means the bracket ran once and was reported as-is (no outlier
    /// rejection). [`best_of`] sets this to [`BENCH_REPEATS`] after
    /// picking the best of that many independent brackets — the fix for
    /// the 16.3x preemption outlier documented in the module docs: a
    /// timer tick landing inside one repetition still leaves the other
    /// `repeats - 1` clean, and the minimum total picks one of those.
    ///
    /// This is "best of `repeats` whole-loop totals", **not** a
    /// per-iteration minimum — that distinction is what `min_cycles` vs
    /// `tail_measured` tracks, and the two are independent.
    pub repeats: u32,
    /// Were `min_cycles`/`max_cycles` actually observed per iteration?
    ///
    /// `false` for every bench in this crate: all 49 are built with
    /// [`BenchResult::from_total`], which brackets the whole loop rather
    /// than timing individual iterations (see `min_cycles`). There is
    /// deliberately no constructor here that sets this `true` — the crate
    /// used to carry one (`from_per_iter`) with zero callers anywhere in
    /// the tree, which is exactly the shape of bug that let a fabricated
    /// min/max look measured for years. If real per-iteration timing is
    /// ever added, add its constructor back then, with a caller, not
    /// before. The flag exists so `report` can decline to print numbers
    /// nobody measured, rather than the reader having to know which
    /// constructor a bench happened to use.
    pub tail_measured: bool,
}

impl BenchResult {
    /// Build from a single bracketing measurement (start cycle, end
    /// cycle, iters).  Sets min=max=avg=total/iters, repeats=1.
    pub fn from_total(start: u64, end: u64, iters: u64) -> Self {
        let total = end.wrapping_sub(start);
        let avg = if iters > 0 { total / iters } else { 0 };
        BenchResult {
            iters,
            min_cycles: avg,
            max_cycles: avg,
            avg_cycles: avg,
            total_cycles: total,
            repeats: 1,
            tail_measured: false,
        }
    }
}

/// Run a bracketed measurement [`BENCH_REPEATS`] times and keep the one
/// with the lowest `total_cycles`.
///
/// This is the fix for the 16.3x outlier measured 2026-09-06
/// (`net.ip_checksum_20B`, 210/150/2450/150 cycles across four runs of one
/// binary): the 2450 sample was a preemption landing inside that run's
/// whole-loop bracket, inflating `total_cycles` from ~15k to ~245k.
/// Re-running the same bracket a few times and keeping the minimum total
/// rejects that outlier, because a tick landing in one repetition still
/// leaves the rest clean — see the module docs for the K=3/5/9 comparison
/// that picked [`BENCH_REPEATS`].
///
/// `f` should be a full `bench_*(iters)` call — each invocation re-runs
/// that bench's own setup and its whole `iters`-length loop, exactly like
/// running `bench all` multiple times in a row. Every bench in this crate
/// is written to tolerate that (own state, own teardown; see the `ipc`
/// module docs). This does **not** produce a per-iteration distribution:
/// it picks the best of several whole-loop totals, so `tail_measured`
/// stays false and `min_cycles`/`max_cycles` stay equal to `avg_cycles`.
pub fn best_of<F: FnMut() -> BenchResult>(mut f: F) -> BenchResult {
    let mut best = f();
    for _ in 1..BENCH_REPEATS {
        let r = f();
        if r.total_cycles < best.total_cycles {
            best = r;
        }
    }
    best.repeats = BENCH_REPEATS;
    best
}

/// Print one `[BENCH-RES]` line for the brain collector to ingest.
///
/// `name` should be `<subsystem>.<bench_name>` (e.g. `ipc.channel_send_recv`)
/// — the dot becomes the JSON nesting key separator on the brain side.
pub fn report(name: &str, r: &BenchResult) {
    if r.tail_measured {
        azos_drv_sys::kconsoleln!(
            "[BENCH-RES] {} iters={} min_cycles={} max_cycles={} avg_cycles={} total_cycles={} repeats={}",
            name, r.iters, r.min_cycles, r.max_cycles, r.avg_cycles, r.total_cycles, r.repeats,
        );
    } else {
        // No min, no max, and SAYING so. They were printed for years as
        // `min == max == avg`, which reads as a measured distribution with
        // zero spread — the strongest claim a real-time bench can make, and
        // the one nothing here established. `tail=unmeasured` is the honest
        // line; the collector on the brain side counts these lines and does
        // not parse the fields, so nothing downstream breaks.
        //
        // `repeats` says how many independent whole-loop totals `avg_cycles`
        // and `total_cycles` were the best of (see `best_of`) — 1 if the
        // bracket ran once, unadjusted. It is a claim about which
        // preemption outliers were rejected across repeated *whole loops*,
        // never a claim about a per-iteration distribution.
        azos_drv_sys::kconsoleln!(
            "[BENCH-RES] {} iters={} avg_cycles={} total_cycles={} repeats={} tail=unmeasured",
            name, r.iters, r.avg_cycles, r.total_cycles, r.repeats,
        );
    }
}

/// Round-up u64 saturating divide.  Used in benches that need to
/// expose "ops per millisecond" derived numbers without floating point.
#[inline]
pub fn cycles_to_ns(cycles: u64) -> u64 {
    let freq = azos_drv_sys::timebase::TIMER_FREQ;
    if freq == 0 { return 0; }
    cycles.saturating_mul(1_000_000_000) / freq
}

// ── Subsystems (gated by features) ───────────────────────────────────────────

#[cfg(feature = "ipc")]
pub mod ipc;

#[cfg(feature = "mm")]
pub mod mm;

#[cfg(feature = "sched")]
pub mod sched;

#[cfg(feature = "net")]
pub mod net;

#[cfg(feature = "fs")]
pub mod fs;

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "cap")]
pub mod cap;

#[cfg(feature = "protocol")]
pub mod protocol;

#[cfg(feature = "ota")]
pub mod ota;

#[cfg(feature = "asyncrt")]
pub mod asyncrt;

// ── Master entrypoint ────────────────────────────────────────────────────────

/// One-shot guard to make sure shell-`bench all` invocations don't recurse
/// or interleave on multi-hart shell access.  Best-effort; the bench
/// machinery itself is not re-entrant safe.
static BENCH_IN_PROGRESS: AtomicU64 = AtomicU64::new(0);

/// Run every enabled subsystem's bench suite, in declared order.
///
/// Returns the total number of `[BENCH-RES]` lines emitted.  Used by the
/// kernel shell `bench all` command; the bench harness scrapes the lines
/// out of the qemu.log directly.
pub fn run_all(iters: u64) -> u32 {
    if BENCH_IN_PROGRESS.swap(1, Ordering::AcqRel) != 0 {
        azos_drv_sys::kconsoleln!("[BENCH-RES] busy — another bench run in progress, skipping");
        return 0;
    }
    azos_drv_sys::kconsoleln!("[BENCH-RES] ── run_all start iters={} ──", iters);
    // Shadowed per enabled suite rather than `mut`: with no suite feature on
    // (a bare `cargo build` of the workspace member) a `mut` is never written.
    let emitted: u32 = 0;

    #[cfg(feature = "ipc")]
    let emitted = emitted.saturating_add(ipc::run(iters));

    #[cfg(feature = "mm")]
    let emitted = emitted.saturating_add(mm::run(iters));

    #[cfg(feature = "sched")]
    let emitted = emitted.saturating_add(sched::run(iters));

    #[cfg(feature = "net")]
    let emitted = emitted.saturating_add(net::run(iters));

    #[cfg(feature = "fs")]
    let emitted = emitted.saturating_add(fs::run(iters));

    #[cfg(feature = "crypto")]
    let emitted = emitted.saturating_add(crypto::run(iters));

    #[cfg(feature = "auth")]
    let emitted = emitted.saturating_add(auth::run(iters));

    #[cfg(feature = "cap")]
    let emitted = emitted.saturating_add(cap::run(iters));

    #[cfg(feature = "protocol")]
    let emitted = emitted.saturating_add(protocol::run(iters));

    #[cfg(feature = "ota")]
    let emitted = emitted.saturating_add(ota::run(iters));

    #[cfg(feature = "asyncrt")]
    let emitted = emitted.saturating_add(asyncrt::run(iters));

    azos_drv_sys::kconsoleln!("[BENCH-RES] ── run_all done emitted={} ──", emitted);
    BENCH_IN_PROGRESS.store(0, Ordering::Release);
    emitted
}

/// Run every subsystem suite EXCEPT `sched` — for the early-boot capture path
/// (`CFG_BENCH_BOOT`), which runs before `scheduler::start()`, so
/// `sched.task_yield` has no live scheduler to yield into.  Every other
/// subsystem only needs its data structures initialised (done by this point
/// in boot: ipc, fs/tmpfs, net/arp, crypto, auth) and is pure compute.
///
/// Runs in a quiescent single-active-hart, timer-OFF context → the cleanest
/// `rdcycle` measurement available under QEMU TCG.  See [`crate`] docs and
/// `CFG_BENCH_BOOT`.
pub fn run_all_quiescent(iters: u64) -> u32 {
    if BENCH_IN_PROGRESS.swap(1, Ordering::AcqRel) != 0 {
        return 0;
    }
    azos_drv_sys::kconsoleln!("[BENCH-RES] ── run_all start iters={} (boot/quiescent) ──", iters);
    // Shadowed per enabled suite rather than `mut`: with no suite feature on
    // (a bare `cargo build` of the workspace member) a `mut` is never written.
    let emitted: u32 = 0;

    #[cfg(feature = "ipc")]
    let emitted = emitted.saturating_add(ipc::run(iters));
    #[cfg(feature = "mm")]
    let emitted = emitted.saturating_add(mm::run(iters));
    // sched intentionally skipped — no live scheduler this early in boot.
    #[cfg(feature = "net")]
    let emitted = emitted.saturating_add(net::run(iters));
    #[cfg(feature = "fs")]
    let emitted = emitted.saturating_add(fs::run(iters));
    #[cfg(feature = "crypto")]
    let emitted = emitted.saturating_add(crypto::run(iters));
    #[cfg(feature = "auth")]
    let emitted = emitted.saturating_add(auth::run(iters));
    #[cfg(feature = "cap")]
    let emitted = emitted.saturating_add(cap::run(iters));
    #[cfg(feature = "protocol")]
    let emitted = emitted.saturating_add(protocol::run(iters));
    #[cfg(feature = "ota")]
    let emitted = emitted.saturating_add(ota::run(iters));

    #[cfg(feature = "asyncrt")]
    let emitted = emitted.saturating_add(asyncrt::run(iters));

    azos_drv_sys::kconsoleln!("[BENCH-RES] ── run_all done emitted={} ──", emitted);
    BENCH_IN_PROGRESS.store(0, Ordering::Release);
    emitted
}
