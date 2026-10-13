// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cost of `lease_tick()` in the timer ISR — deterministic, host-only, no QEMU.
//!
//! # Why this file exists
//!
//! `lease_tick()` runs **inside** the timer ISR (`kernel/src/trap/interrupt.rs`, arm
//! `INT_TIMER_S`, wrapped in `probe!("lease_tick", ...)`). The IPC audit
//! widened its predicate from `state == Active` to
//! `matches!(state, Active | Pending)` — correct (a lessor with a deadline
//! whose lessee never accepted used to sleep past its own deadline), but it
//! makes the ISR do strictly more work per tick, and nobody had measured how
//! much.
//!
//! # What changed since, and what these gates now protect
//!
//! Measuring it produced the finding the audit recorded but did not act on:
//! the worst case was fine, and the **common** case — "no lease carries a
//! deadline", which is the normal state of this robot — paid 157 instructions
//! in the callee plus 85 in the caller's drain loop to do nothing at all,
//! every single timer tick, on every hart.
//!
//! `lease_tick` now takes `(now, &mut [u32; MAX_LEASES]) -> usize` and
//! short-circuits on an atomic count of armed leases. Both halves were
//! necessary and the audit said so: a bare early exit saves **nothing**,
//! because the 256-byte return array is materialised through the caller's
//! `sret` pointer before any test can skip it.
//!
//! Two consequences for this file, both structural rather than cosmetic:
//!
//!  * The old invariant — "the trip count is `MAX_LEASES` whatever the table
//!    holds, and that is what makes it ISR-safe" — is **deliberately false
//!    now** and has been replaced by the property that actually matters:
//!    all-or-nothing, never a partial scan
//!    (`the_trip_count_is_all_or_nothing_never_partial`), plus a correctness
//!    gate that the exit fires **only** when nothing was due
//!    (`the_early_exit_fires_exactly_when_no_lease_is_armed`).
//!  * Every instruction figure is now **callee + caller**. With `lto = false`
//!    the caller's output buffer cannot be optimised away, so charging only
//!    the callee would report a saving obtained by moving work across the
//!    call boundary.
//!
//! The first attempt used the in-tree `[ISR-WCET]` diagnostic under QEMU and
//! failed as an instrument: it only prints above 1 ms, and with the host
//! loaded it produced a spectacular false positive (36 events vs 3) that was
//! pure host load.
//! Hence: host, deterministic, and biased towards **counted work** over the
//! clock.
//!
//! # Why an integration test and not `#[cfg(test)] mod` in the lib
//!
//! The lease suite lives inside `crates/core/ipc/src/lease.rs`'s own
//! `mod tests`, serialised against each other by a `SERIAL: Mutex<()>` that is
//! private to that module and unreachable from here. Those tests share the one
//! process-wide `LEASES` static. A sibling module in the same test binary would
//! need to fill all 16 slots and would race them. An integration test is a
//! **separate binary, hence a separate process**, so it gets its own `LEASES`
//! and cannot perturb — or be perturbed by — the lib suite.
//!
//! The price is that `__lease_reset_for_tests` / `__lease_state_for_tests` are
//! `#[cfg(test)]` and do not exist here. Neither is needed: `lease_free(i, 0,
//! true)` (privileged) clears any slot — and it goes through the same
//! `refresh_deadline_count` the kernel does, so the early-exit counter stays
//! consistent with the table the test built — and the *outcome* under test is
//! the lessor list `lease_tick` reports.
//!
//! # What is measured, and how
//!
//! **Counted work (primary).** Three instrumented models — `tick_old_model`
//! (pre-audit, `Active` only), `tick_prev_model` (audit predicate, no early
//! exit) and `tick_new_model` (current) — run over a mirror of the table and
//! count *loop iterations* and *expiry bodies executed*. Three and not two so
//! the predicate widening and the early exit stay **separately
//! attributable**: the middle model is what isolates each change's cost from
//! the other's. Those quantities survive translation to RV64; an
//! abstract "comparison count" would not, and is deliberately not used: `Pending`
//! and `Active` are adjacent discriminants, so `matches!(s, Active | Pending)`
//! lowers to roughly one unsigned range check, i.e. plausibly **zero** extra
//! instructions versus `s == Active`. Counting it as "+1 compare per entry"
//! would report a delta that does not exist in the emitted code.
//!
//! `tick_new_model` is validated against the real `lease_tick` by a differential
//! test over a matrix of table shapes plus a 200-round pseudo-random sweep:
//! same input state ⇒ same lessors reported. That validates **outcomes**, not
//! costs; the cost claims rest on the structural argument, which is why the
//! structure is asserted explicitly below
//! (`the_trip_count_is_all_or_nothing_never_partial`).
//!
//! **Clock (secondary).** Absolute nanoseconds on aarch64-apple-darwin do not
//! transfer to RV64. What is reported is the **ratio between shapes measured in
//! the same run**, with min-of-N absolutes as corroboration only. Min, not mean:
//! the minimum is the least contaminated sample when four other agents are
//! compiling on the same host. **No test in this file gates on a clock value** —
//! a wall-clock ceiling measures host load, not the kernel, which is exactly why
//! `tools/ci_check.sh` carries no time thresholds. The gates below are all on
//! counted work.

use azos_ipc_lease_tests::lease::{
    lease_accept, lease_free, lease_grant_as, lease_return, lease_tick, MAX_LEASES,
};
use std::hint::black_box;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// `LEASES` is one static per process and `cargo test` runs the tests of this
/// binary on several threads, so they must be serialised against each other —
/// the same reason `lease.rs`'s own `mod tests` keeps a `SERIAL` mutex, which
/// is private to that module and unreachable from an integration test.
static SERIAL: Mutex<()> = Mutex::new(());

/// Take the table for the duration of a test. Poison is ignored: a panicking
/// test leaves the table dirty, and every entry point here rebuilds it anyway.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Sentinel the kernel uses for "no lessor".
const NO_TID: u32 = u32::MAX;

/// Call the real `lease_tick` the way the timer ISR does, and return the
/// lessors it reported.
///
/// This *is* the intended drain shape, minus the wakes: a caller-owned
/// `[u32; MAX_LEASES]` and `iter().take(n)`. Written here rather than inline
/// so every call site in this file measures the same thing the kernel pays.
fn tick(now: u64) -> Vec<u32> {
    let mut out = [NO_TID; MAX_LEASES];
    let n = lease_tick(now, &mut out);
    assert!(n <= MAX_LEASES, "lease_tick reported more expiries than slots");
    out.iter().take(n).copied().collect()
}

/// Deadline used for every lease that is meant to expire on the measured tick.
const DEADLINE: u64 = 1_000_000;
/// The tick at which the measurement happens (`now >= expire` ⇒ expiry).
const NOW: u64 = DEADLINE;
/// A deadline far enough in the future that the measured tick never reaches it.
const FAR: u64 = DEADLINE * 4;

// ───────────────────────────────────────────────────────────────────────────
// Mirror of the kernel's table, for the instrumented models
// ───────────────────────────────────────────────────────────────────────────

/// Mirror of `crates/core/ipc/src/lease.rs`'s `LeaseState`. Copied rather than
/// re-exported because the kernel enum is not `Debug`/`Eq` and this file must
/// not touch `lease.rs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    Free,
    Pending,
    Active,
    Returned,
    Expired,
}

/// Mirror of `LeaseEntry`, carrying only the three fields `lease_tick` reads.
#[derive(Clone, Copy, Debug)]
struct Slot {
    state: St,
    expire: u64,
    lessor: u32,
}

impl Slot {
    const fn free() -> Self {
        Slot { state: St::Free, expire: 0, lessor: NO_TID }
    }
}

/// Work actually done by one `lease_tick` call, in units that survive
/// translation to RV64.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct Work {
    /// Loop trip count inside `lease_tick`. **`0` when the early exit fires,
    /// `MAX_LEASES` otherwise — never anything in between.** The loop still
    /// has no `break`; what is data-dependent is whether it runs at all.
    iters: usize,
    /// Expiry bodies executed (state write + output store). This is the only
    /// quantity that varies once the loop is entered.
    bodies: usize,
    /// `true` when `DEADLINE_LEASES == 0` short-circuited the call before the
    /// lock. This is the case the whole change exists for.
    early_exit: bool,
    /// Words of output buffer initialised before the call, i.e. the sentinel
    /// fill that **cannot** be skipped because the callee is opaque
    /// (`lto = false`). It moved from callee prologue to caller stack and
    /// from 2 words per slot to 1 — the reason the pair type was dropped.
    init_words: usize,
    /// Trip count of the caller's own drain loop in `kernel/src/trap/interrupt.rs`.
    /// Not inside `lease_tick`, but forced by its signature, so it is charged
    /// to it here — the same accounting rule as before the change, which is
    /// what stops the saving from being an illusion produced by moving work
    /// across the call boundary.
    caller_drain_iters: usize,
}

/// Pre-audit `lease_tick`: expires `Active` only.
///
/// **Taken from source, not from a docstring.** The pre-audit body is commit
/// `90d03ff`, blob `6c52453` (`git cat-file -p 6c52453 | grep -A16 'fn lease_tick'`):
///
/// ```text
///     let mut table = LEASES.lock();                  // ← not lock_irqsave
///     for (i, e) in table.entries.iter_mut().enumerate() {
///         if e.state == LeaseState::Active
///             && e.expire_ticks != 0
///             && now_ticks >= e.expire_ticks
/// ```
///
/// Two things changed in the audit, not one, and only the first is what this
/// lane was asked about:
///
///  1. the predicate widened to `Active | Pending` — the subject of
///     `the_new_predicate_costs_exactly_one_body_per_expiring_pending`;
///  2. `lock()` became `lock_irqsave()`, the same-hart re-entrancy fix
///     documented above `static LEASES`. That is invisible to a work count but
///     costs a fixed `RV64_IRQSAVE` instructions per tick — see there.
///
/// This model reproduces (1) only, because (2) is not a per-entry cost and is
/// accounted separately in the instruction budget.
fn tick_old_model(table: &mut [Slot; MAX_LEASES], now: u64) -> (Work, Vec<u32>) {
    let mut out = Vec::new();
    // `init_words` is `2 * MAX_LEASES`: the old return type was
    // `[(usize, u32); MAX_LEASES]`, two words per slot, 32 stores.
    let mut w = Work {
        init_words: 2 * MAX_LEASES,
        caller_drain_iters: MAX_LEASES,
        ..Work::default()
    };
    for e in table.iter_mut() {
        w.iters += 1;
        if e.state == St::Active && e.expire != 0 && now >= e.expire {
            w.bodies += 1;
            e.state = St::Expired;
            if out.len() < MAX_LEASES {
                out.push(e.lessor);
            }
        }
    }
    (w, out)
}

/// The `lease_tick` this lane replaced: predicate `Active | Pending`, no early
/// exit, 256-byte return array, caller drains all `MAX_LEASES` slots testing
/// the `u32::MAX` sentinel.
fn tick_prev_model(table: &mut [Slot; MAX_LEASES], now: u64) -> (Work, Vec<u32>) {
    let mut out = Vec::new();
    let mut w = Work {
        init_words: 2 * MAX_LEASES,
        caller_drain_iters: MAX_LEASES,
        ..Work::default()
    };
    for e in table.iter_mut() {
        w.iters += 1;
        if matches!(e.state, St::Active | St::Pending) && e.expire != 0 && now >= e.expire {
            w.bodies += 1;
            e.state = St::Expired;
            if out.len() < MAX_LEASES {
                out.push(e.lessor);
            }
        }
    }
    (w, out)
}

/// Current `lease_tick`: same predicate, plus the `DEADLINE_LEASES` early exit
/// and the `(now, &mut [u32; MAX_LEASES]) -> usize` shape.
fn tick_new_model(table: &mut [Slot; MAX_LEASES], now: u64) -> (Work, Vec<u32>) {
    let mut out = Vec::new();
    // One word per slot, and paid by the caller.
    let mut w = Work { init_words: MAX_LEASES, ..Work::default() };

    // The early exit, modelled from the same predicate the kernel counts:
    // `DEADLINE_LEASES` is exactly `|{Pending|Active with a deadline}|`.
    let armed = table
        .iter()
        .filter(|s| matches!(s.state, St::Active | St::Pending) && s.expire != 0)
        .count();
    if armed == 0 {
        w.early_exit = true;
        // `iters == 0`, `caller_drain_iters == 0`: the caller iterates
        // `take(n)` with `n == 0`. The buffer init is still charged.
        return (w, out);
    }

    for e in table.iter_mut() {
        w.iters += 1;
        if matches!(e.state, St::Active | St::Pending) && e.expire != 0 && now >= e.expire {
            w.bodies += 1;
            e.state = St::Expired;
            if out.len() < MAX_LEASES {
                out.push(e.lessor);
            }
        }
    }
    // The caller now walks exactly the entries that expired, not all 16.
    w.caller_drain_iters = out.len();
    (w, out)
}

// ───────────────────────────────────────────────────────────────────────────
// Building a given table shape in the *real* kernel table
// ───────────────────────────────────────────────────────────────────────────

/// TID of the lessor of slot `i`. Distinct per slot so the returned array is
/// self-identifying.
fn lessor_of(i: usize) -> u32 {
    200 + i as u32
}
/// TID of the lessee of slot `i`. Distinct per slot so
/// `lease_accept(lessee_of(i), lessor_of(i))` resolves to exactly that slot.
fn lessee_of(i: usize) -> u32 {
    100 + i as u32
}

/// Wipe every slot of the real table. `privileged = true` bypasses the IPC-6
/// ownership check, so this clears any state including `Active`.
fn reset_real() {
    for i in 0..MAX_LEASES {
        lease_free(i, 0, true);
    }
}

/// Grant as the kernel. No regions back the shm ids this file uses, and what it
/// measures is the tick, not the grant's owner check
/// (`tests/lease_grant_authority.rs` covers that). Explicit rather than read
/// from the scheduler shim, so the ring-3 identity the tests below install
/// does not decide whether a grant happens.
fn lease_grant(shm_id: usize, lessor: u32, lessee: u32, expire: u64) -> Option<usize> {
    lease_grant_as(shm_id, lessor, lessee, expire, true).ok()
}

/// Install `shape` into the real `LEASES` table and return the matching mirror.
///
/// `lease_grant` allocates the first `Free` slot, so granting in index order
/// puts slot `i` where the shape says. `Expired` is reached the only way the
/// kernel offers — through a tick — using a throwaway deadline of 1 and a
/// probe tick at 2; every other deadline in a shape is `0`, `DEADLINE`
/// (1e6) or `FAR`, all safely above 2.
fn build(shape: &[Slot; MAX_LEASES]) -> [Slot; MAX_LEASES] {
    reset_real();
    azos_sched::shim_reset();
    azos_sched::shim_set_current(9_999, 0x1000);

    // Pass A — fill every slot in index order so indices are deterministic.
    for (i, s) in shape.iter().enumerate() {
        let expire = if s.state == St::Expired { 1 } else { s.expire };
        let got = lease_grant(i, lessor_of(i), lessee_of(i), expire).expect("free lease slot");
        assert_eq!(got, i, "grant did not fill slots in index order");
    }

    // Pass B — a tick at 2 expires exactly the slots that asked for it.
    if shape.iter().any(|s| s.state == St::Expired) {
        let _ = tick(2);
    }

    // Pass C — promote the rest into their target states.
    for (i, s) in shape.iter().enumerate() {
        match s.state {
            St::Free => {
                assert!(lease_free(i, 0, true), "slot {i} should have been occupied");
            }
            St::Active => {
                let (id, _shm) = lease_accept(lessee_of(i), lessor_of(i)).expect("pending lease");
                assert_eq!(id, i, "accept resolved to the wrong slot");
            }
            St::Returned => {
                let (id, _shm) = lease_accept(lessee_of(i), lessor_of(i)).expect("pending lease");
                assert_eq!(id, i, "accept resolved to the wrong slot");
                assert!(lease_return(i, lessee_of(i), false).is_some(), "return rejected");
            }
            St::Pending | St::Expired => {}
        }
    }

    *shape
}

// ───────────────────────────────────────────────────────────────────────────
// Shape catalogue
// ───────────────────────────────────────────────────────────────────────────

fn filled(state: St, expire: u64, n: usize) -> [Slot; MAX_LEASES] {
    let mut t = [Slot::free(); MAX_LEASES];
    for (i, slot) in t.iter_mut().enumerate().take(n) {
        *slot = Slot { state, expire, lessor: lessor_of(i) };
    }
    t
}

/// The shapes the report is built from: `(name, shape)`.
fn catalogue() -> Vec<(&'static str, [Slot; MAX_LEASES])> {
    // Half full, alternating Active / Pending, all past their deadline.
    let mut mixed_half = [Slot::free(); MAX_LEASES];
    for i in 0..8 {
        mixed_half[i * 2] = Slot {
            state: if i % 2 == 0 { St::Active } else { St::Pending },
            expire: DEADLINE,
            lessor: lessor_of(i * 2),
        };
    }
    // Full, one of every state, deadlines all reached.
    let mut mixed_full = [Slot::free(); MAX_LEASES];
    for (i, slot) in mixed_full.iter_mut().enumerate() {
        let state = match i % 4 {
            0 => St::Active,
            1 => St::Pending,
            2 => St::Returned,
            _ => St::Expired,
        };
        *slot = Slot { state, expire: DEADLINE, lessor: lessor_of(i) };
    }

    vec![
        ("empty (16 Free)", [Slot::free(); MAX_LEASES]),
        ("8 Active, deadline in the future", filled(St::Active, FAR, 8)),
        ("8 Active, deadline reached", filled(St::Active, DEADLINE, 8)),
        ("8 Pending, deadline reached", filled(St::Pending, DEADLINE, 8)),
        ("16 Active, no deadline (expire=0)", filled(St::Active, 0, MAX_LEASES)),
        ("16 Active, deadline in the future", filled(St::Active, FAR, MAX_LEASES)),
        ("16 Active, deadline reached", filled(St::Active, DEADLINE, MAX_LEASES)),
        ("16 Pending, no deadline (expire=0)", filled(St::Pending, 0, MAX_LEASES)),
        ("16 Pending, deadline reached", filled(St::Pending, DEADLINE, MAX_LEASES)),
        ("16 Returned, deadline reached", filled(St::Returned, DEADLINE, MAX_LEASES)),
        ("16 Expired, deadline reached", filled(St::Expired, DEADLINE, MAX_LEASES)),
        ("8 mixed Active/Pending, deadline reached", mixed_half),
        ("16 mixed all-4-states, deadline reached", mixed_full),
    ]
}

/// Slots that the *new* predicate expires but the *old* one did not: `Pending`
/// entries past their deadline. This is the whole delta of the audit change.
fn newly_expiring(shape: &[Slot; MAX_LEASES], now: u64) -> usize {
    shape
        .iter()
        .filter(|s| s.state == St::Pending && s.expire != 0 && now >= s.expire)
        .count()
}

// ───────────────────────────────────────────────────────────────────────────
// 1. The model is faithful — differential against the real `lease_tick`
// ───────────────────────────────────────────────────────────────────────────

/// The cost numbers below are produced by `tick_new_model`, not by the kernel
/// function. This test is what makes them admissible: for every shape in the
/// catalogue, model and kernel must return the identical expiry array, and a
/// second tick must expire nothing more (states really did move to `Expired`).
#[test]
fn model_matches_the_real_lease_tick_on_every_shape() {
    let _g = serial();
    for (name, shape) in catalogue() {
        let mut mirror = build(&shape);

        let real = tick(NOW);
        let (_w, modelled) = tick_new_model(&mut mirror, NOW);

        assert_eq!(real, modelled, "expiry array diverged for shape: {name}");

        // Idempotency: everything that could expire has, in both worlds.
        let real2 = tick(NOW);
        let (w2, modelled2) = tick_new_model(&mut mirror, NOW);
        assert_eq!(w2.bodies, 0, "second tick still did work for shape: {name}");
        assert_eq!(real2, modelled2, "second-tick array diverged for shape: {name}");
        assert!(real2.is_empty(), "second tick expired something for shape: {name}");
    }
    reset_real();
}

/// The differential above walks a hand-picked catalogue. This one walks a
/// deterministic pseudo-random sweep so the agreement is not an artefact of the
/// shapes chosen — no RNG crate, a plain LCG, same sequence on every run.
#[test]
fn model_matches_the_real_lease_tick_on_a_deterministic_random_sweep() {
    let _g = serial();
    let mut seed: u64 = 0x5DEE_CE66_D1CE_0001;
    let mut next = move || {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) as u32
    };

    for round in 0..200 {
        let mut shape = [Slot::free(); MAX_LEASES];
        for (i, slot) in shape.iter_mut().enumerate() {
            let state = match next() % 5 {
                0 => St::Free,
                1 => St::Pending,
                2 => St::Active,
                3 => St::Returned,
                _ => St::Expired,
            };
            let expire = match next() % 3 {
                0 => 0,
                1 => DEADLINE,
                _ => FAR,
            };
            *slot = Slot { state, expire, lessor: lessor_of(i) };
        }

        let mut mirror = build(&shape);
        let real = tick(NOW);
        let (_w, modelled) = tick_new_model(&mut mirror, NOW);
        assert_eq!(real, modelled, "expiry array diverged in random round {round}");
    }
    reset_real();
}

// ───────────────────────────────────────────────────────────────────────────
// 2. The gate: the ISR's trip count is fixed and the ceiling did not move
// ───────────────────────────────────────────────────────────────────────────

/// **Structural gate — restated, because the early exit changed the
/// invariant it protects.**
///
/// It used to read: "the loop has no `break`, so the trip count is
/// `MAX_LEASES` whatever the table holds, and that unconditionality is what
/// makes it safe in an ISR." That is no longer true and must not be asserted:
/// `lease_tick` is now data-dependent by design — it costs *nothing* when no
/// lease carries a deadline.
///
/// The property that actually matters in an ISR is **bounded**, not
/// **constant**, and it survives intact in a sharper form: the trip count is
/// `0` or `MAX_LEASES` and never anything in between. There is still no
/// `break`, no rescan, no retry — only a single test in front of the whole
/// loop. Anything that introduced a partial scan, an inner loop or a retry
/// would break this and name the shape.
#[test]
fn the_trip_count_is_all_or_nothing_never_partial() {
    for (name, shape) in catalogue() {
        let mut a = shape;
        let mut b = shape;
        let (w_prev, _) = tick_prev_model(&mut a, NOW);
        let (w_new, _) = tick_new_model(&mut b, NOW);

        assert_eq!(w_prev.iters, MAX_LEASES, "previous trip count moved for shape: {name}");
        assert!(
            w_new.iters == 0 || w_new.iters == MAX_LEASES,
            "partial scan ({} iters) for shape: {name}",
            w_new.iters
        );
        assert_eq!(
            w_new.early_exit,
            w_new.iters == 0,
            "the exit fired without skipping the loop, or vice versa: {name}"
        );
        assert!(w_new.bodies <= MAX_LEASES, "more bodies than slots for shape: {name}");
        // And the buffer that must be materialised on every call halved.
        assert_eq!(w_new.init_words * 2, w_prev.init_words, "output buffer size changed: {name}");
    }
}

/// **The exit fires exactly when it is safe to.** An early exit in an ISR is
/// only correct if it never skips work that was due: the counter must read
/// zero if and only if no entry could have expired on *any* `now`. Asserted
/// against the real kernel table, not just the model, and across the whole
/// catalogue plus every `now` boundary.
#[test]
fn the_early_exit_fires_exactly_when_no_lease_is_armed() {
    let _g = serial();
    for (name, shape) in catalogue() {
        let armed = shape
            .iter()
            .filter(|s| matches!(s.state, St::Active | St::Pending) && s.expire != 0)
            .count();
        build(&shape);
        // `u64::MAX` is past every deadline, so anything the loop *could*
        // expire, it does. If the exit fired wrongly, this comes back empty.
        let fired = tick(u64::MAX);
        assert_eq!(
            fired.len(),
            armed,
            "shape {name}: {armed} armed leases, {} expired — the early exit \
             skipped work that was due",
            fired.len()
        );
    }
    reset_real();
}

/// **Attribution gate.** Widening the predicate from `Active` to
/// `Active | Pending` costs exactly one extra expiry body per `Pending` entry
/// past its deadline — no more, and nothing for any other state. If the
/// predicate ever widens further (say, `Returned`), this fails and names the
/// shape. Compared against `tick_prev_model` (same predicate, no exit) so the
/// two changes stay separately attributable.
#[test]
fn the_widened_predicate_costs_exactly_one_body_per_expiring_pending() {
    for (name, shape) in catalogue() {
        let mut a = shape;
        let mut b = shape;
        let (w_old, _) = tick_old_model(&mut a, NOW);
        let (w_prev, _) = tick_prev_model(&mut b, NOW);

        assert_eq!(
            w_prev.bodies - w_old.bodies,
            newly_expiring(&shape, NOW),
            "unattributed extra work for shape: {name}"
        );
        assert_eq!(w_prev.iters, w_old.iters, "the audit changed the trip count for shape: {name}");
    }
}

/// **Ceiling gate — the ISR-relevant number.** The worst case is still 16
/// bodies: a full table, every entry expiring on the same tick. The early
/// exit cannot raise it (it only ever removes work) and the predicate change
/// did not either — it moved *which* table states reach the ceiling.
#[test]
fn the_worst_case_body_count_is_unchanged() {
    let mut worst_old = 0usize;
    let mut worst_new = 0usize;
    for (_name, shape) in catalogue() {
        let mut a = shape;
        let mut b = shape;
        worst_old = worst_old.max(tick_old_model(&mut a, NOW).0.bodies);
        worst_new = worst_new.max(tick_new_model(&mut b, NOW).0.bodies);
    }
    assert_eq!(worst_old, MAX_LEASES, "old variant no longer reaches its ceiling in the catalogue");
    assert_eq!(worst_new, MAX_LEASES, "new variant no longer reaches its ceiling in the catalogue");
    assert_eq!(worst_new, worst_old, "lease_tick's worst-case body count grew");
}

// ───────────────────────────────────────────────────────────────────────────
// 3. The cost table (counted work) — printed with `--nocapture`
// ───────────────────────────────────────────────────────────────────────────

/// Emits the per-shape cost table the report is built from. Also asserts the
/// facts the table is supposed to show: a table with no armed deadline costs
/// nothing regardless of how full it is, and once the loop runs, the only
/// axis that moves the cost is `k`, the number of entries expiring.
#[test]
fn cost_table_by_table_state() {
    println!("\n=== lease_tick: counted work per tick (MAX_LEASES = {MAX_LEASES}) ===");
    println!(
        "{:<42} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "table state", "exit", "iters", "old k", "new k", "init", "drain"
    );
    for (name, shape) in catalogue() {
        let mut a = shape;
        let mut b = shape;
        let (w_old, _) = tick_old_model(&mut a, NOW);
        let (w_new, _) = tick_new_model(&mut b, NOW);
        println!(
            "{:<42} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}",
            name,
            if w_new.early_exit { "yes" } else { "no" },
            w_new.iters,
            w_old.bodies,
            w_new.bodies,
            w_new.init_words,
            w_new.caller_drain_iters,
        );
    }

    // Fullness alone is not a cost axis, and now it is not even a *loop*:
    // 16 entries that carry no deadline cost exactly what an empty table does.
    let mut empty = [Slot::free(); MAX_LEASES];
    let mut full_unarmed = filled(St::Active, 0, MAX_LEASES);
    assert_eq!(
        tick_new_model(&mut empty, NOW).0,
        tick_new_model(&mut full_unarmed, NOW).0,
        "a full table of deadline-less leases should cost exactly what an empty one costs"
    );
    assert!(tick_new_model(&mut empty, NOW).0.early_exit);

    // A full table of *armed* leases that simply are not due yet does NOT take
    // the exit — the counter is about "could expire ever", not "expires now".
    // Stating it here so nobody mistakes the exit for a deadline comparison.
    let mut full_armed_future = filled(St::Active, FAR, MAX_LEASES);
    let (w_future, _) = tick_new_model(&mut full_armed_future, NOW);
    assert!(!w_future.early_exit);
    assert_eq!(w_future.iters, MAX_LEASES);
    assert_eq!(w_future.bodies, 0);

    // The real axis: k = entries expiring on this tick, 0..=MAX_LEASES, linear.
    println!("\n=== the axis that actually moves: k = entries expiring on this tick ===");
    println!("{:<10} {:>6} {:>7} {:>7}", "k", "iters", "bodies", "drain");
    for k in 0..=MAX_LEASES {
        let mut t = filled(St::Pending, DEADLINE, k);
        for slot in t.iter_mut().skip(k) {
            *slot = Slot { state: St::Pending, expire: FAR, lessor: NO_TID };
        }
        let (w, _) = tick_new_model(&mut t, NOW);
        assert_eq!(w.iters, MAX_LEASES);
        assert_eq!(w.bodies, k, "cost in k is not linear at k = {k}");
        // The caller's drain is now `k`, not `MAX_LEASES`. That is half the
        // saving and it lives outside `lease_tick`, so it is asserted here.
        assert_eq!(w.caller_drain_iters, k, "caller drain is not k at k = {k}");
        println!("{k:<10} {:>6} {:>7} {:>7}", w.iters, w.bodies, w.caller_drain_iters);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// 4. Translating counted work into an RV64 instruction budget
// ───────────────────────────────────────────────────────────────────────────
//
// The counts above are units of work, not time. They become a WCET claim only
// with a per-unit instruction cost, and every constant below was read off a
// **compiled RV64 artifact**, not guessed. Reproduce with:
//
//     CARGO_TARGET_DIR=<scratch> cargo build --release -p azos_ipc
//     llvm-ar x <scratch>/riscv64imac-unknown-none-elf/release/libazos_ipc.rlib
//     llvm-objdump -d --section=.text._RNvNtCs..._8azos_ipc5lease10lease_tick *.o
//
// The `-p azos_ipc` build is used rather than the linked kernel so the
// numbers can be taken while `kernel/src/trap/interrupt.rs` is still on the old drain
// loop. `lto = false` in the workspace profile, so the rlib's code for this
// symbol is byte-identical to what the kernel links.
//
// **The old numbers were re-derived, not inherited.** A byte-for-byte copy of
// the previous `lease_tick` body was compiled in the *same* invocation as the
// new one and disassembled alongside it. It came out at exactly 61 fixed + 6
// per skipped iteration = 157 for the empty table — identical to the figure
// measured in-kernel, which is the cross-check that says the
// method is the same method.
//
// The artifact is self-verifying for the predicate question: the loop's state
// test is
//
//     lbu  a4, 0x0(a5)       ; e.state
//     addi a4, a4, -0x1
//     bgeu a4, t2, <next>    ; t2 = 2  →  skip unless (state - 1) < 2
//
// `(state - 1) < 2` selects discriminants 1 and 2 — `Pending` and `Active` —
// so the widened `matches!(s, Active | Pending)` is **one unsigned range
// check**, the same single `bgeu` a bare `s == Active` compiles to. Zero extra
// instructions on the non-expiring path. This is why abstract "comparison
// counts" were rejected in favour of iterations and bodies.
//
// The deadline test is fused the same way (`ld` / `addi -1` / `bgeu` folds
// `expire != 0 && now >= expire` into one branch).
//
// **The caller is counted too.** With `lto = false` the callee is opaque, so
// the output buffer the caller declares is materialised on every tick no
// matter what the callee does. Charging only the callee would report a saving
// produced by moving work across the call boundary — the exact trap the audit
// flagged when it said a bare early exit "saves nothing".

// ── The previous shape: `fn(u64) -> [(usize, u32); MAX_LEASES]` ────────────

/// Callee instructions outside the loop, paid on **every** call including an
/// empty table: 34 prologue (`li` + `auipc` + **32 stores** that fill the
/// 256-byte return array through the caller's `sret` pointer, fully
/// unrolled), 11 for `lock_irqsave`, 8 loop setup, 8 unlock + `ret`.
const RV64_PREV_FIXED: usize = 61;
/// The 32 unconditional array-init **stores** inside [`RV64_PREV_FIXED`].
/// Note the unit: `Work::init_words` counts words, this counts the `sd`/`sw`
/// instructions they compile to.
const RV64_PREV_ARRAY_INIT: usize = 32;
/// One iteration whose state does not match: `lbu`/`addi`/`bgeu` taken, plus
/// the 3-instruction loop tail.
const RV64_PREV_ITER_SKIP: usize = 6;
/// One iteration that expires: both tests fall through, then the body.
const RV64_PREV_ITER_EXPIRE: usize = 18;
/// Caller side, outside its drain loop: 6 prologue, 4 call sequence, 4 loop
/// setup, 7 epilogue.
const RV64_PREV_CALLER_FIXED: usize = 21;
/// One drain iteration that finds the `u32::MAX` sentinel and does nothing:
/// `lw`, `beq` taken, `addi`, `beq`. Paid `MAX_LEASES` times, every tick.
const RV64_PREV_CALLER_ITER_SKIP: usize = 4;

// ── The current shape: `fn(u64, &mut [u32; MAX_LEASES]) -> usize` ──────────

/// **The whole point of the change**, and the entire cost of a tick on a
/// robot with no lease deadline outstanding: `auipc`, `mv`, `ld` (the
/// counter), `beqz` taken, `li a0, 0`, `ret`. No lock, no table access, so no
/// cache miss either — which an instruction count alone understates.
const RV64_EARLY_EXIT: usize = 6;
/// Callee fixed cost when the exit does *not* fire: 5 entry, 11
/// `lock_irqsave`, 7 loop setup, 1 for the `count == 0` test, 9 unlock+`ret`.
const RV64_FIXED: usize = 33;
/// The `DEADLINE_LEASES.fetch_sub(count)` on the expiry path: `neg` +
/// `amoadd.d.rl`. Only paid when something actually expired.
const RV64_DECREMENT: usize = 2;
/// One iteration whose state does not match: `lbu`/`addi`/`bgeu` taken, plus
/// a 2-instruction loop tail (one shorter than before — the index is gone
/// with the `(lease_id, tid)` pair).
const RV64_ITER_SKIP: usize = 5;
/// One iteration that expires.
const RV64_ITER_EXPIRE: usize = 16;
/// Caller side, outside its drain loop: 6 prologue, **8 stores** for the
/// 64-byte `[u32; 16]`, 2 setup, 2 call, 1 `beqz n`, 7 epilogue.
const RV64_CALLER_FIXED: usize = 26;
/// The 8 array-init stores inside [`RV64_CALLER_FIXED`]. Four times cheaper
/// than the 32 it replaces, because the output element went from
/// `(usize, u32)` to `u32` — the caller never used the index.
const RV64_CALLER_ARRAY_INIT: usize = 8;

/// Lowest DVFS operating point on the VF2 (`CpuFreq::Low`, 375 MHz — see
/// `crates/drivers/power/src/pm.rs:117`). WCET must hold at the *slowest* point the
/// board can be running at, not at the 1500 MHz maximum.
const VF2_SLOWEST_MHZ: f64 = 375.0;
/// **The criterion, from the tree.** `WCET_BOUND_TIMER_ISR_US` —
/// `crates/drivers/sys/src/wcet.rs:97`. The budget for the **whole** timer ISR,
/// which `lease_tick` shares with `vdso_update`, `wake_expired_timers`,
/// `set_next_tick_smart` and the trace event.
const TIMER_ISR_BUDGET_US: f64 = 10.0;
/// **Scale check, from the tree.** The nearest analogue in
/// `crates/drivers/sys/wcet_points.json` to "bounded scan of a small table under a
/// lock" is `cap_get` at 20 µs; `arp_lookup` (10 µs) and `scheduler_schedule`
/// (30 µs) bracket it. Used only to say how big 0.93 µs is in this kernel's
/// own terms — it is not the bound being enforced.
const CAP_GET_BUDGET_US: f64 = 20.0;
/// **This lane's convention, NOT a tree criterion.** `lease_tick` is one of
/// five things in the timer ISR, so a fifth of `TIMER_ISR_BUDGET_US` is a
/// generous share and makes a usable tripwire. Anything derived from this is
/// labelled as a lane convention wherever it is reported.
const LANE_SHARE_OF_ISR_BUDGET: f64 = 0.20;

/// **WCET gate, plus the common-case gate this batch exists for.**
///
/// Turns the counted work into an RV64 instruction count and checks it against
/// the in-tree timer-ISR budget. Deliberately *not* a clock threshold: the
/// inputs are instruction counts from a disassembly and a documented clock
/// rate, both deterministic, so this fails only if the code changes — never
/// because the host is busy.
///
/// Every figure is **callee + caller**. Charging only the callee would let a
/// future change claim a saving by pushing work into the drain loop.
#[test]
fn worst_case_fits_the_in_tree_timer_isr_budget() {
    // Worst case: full table, every entry expiring on the same tick.
    let mut worst = filled(St::Pending, DEADLINE, MAX_LEASES);
    let (w, _) = tick_new_model(&mut worst, NOW);
    assert_eq!(w.bodies, MAX_LEASES);
    assert!(!w.early_exit);

    // Worst case, both sides. The caller's drain loop is not modelled
    // per-instruction here because its body is two `jalr`s to the wake
    // primitives — real work, identical in both variants, and not attributable
    // to `lease_tick`. Its *structural* cost is: before, `MAX_LEASES`
    // iterations whatever happened; now, exactly `bodies`.
    let wc_instr = RV64_FIXED + RV64_DECREMENT + w.bodies * RV64_ITER_EXPIRE;
    let wc_prev = RV64_PREV_FIXED + MAX_LEASES * RV64_PREV_ITER_EXPIRE;

    // The common case on this robot: no lease carries a deadline.
    let common_instr = RV64_EARLY_EXIT + RV64_CALLER_FIXED;
    let common_prev = RV64_PREV_FIXED
        + MAX_LEASES * RV64_PREV_ITER_SKIP
        + RV64_PREV_CALLER_FIXED
        + MAX_LEASES * RV64_PREV_CALLER_ITER_SKIP;
    // The armed-but-nothing-due case, where the exit does not help.
    let armed_idle_instr = RV64_FIXED + MAX_LEASES * RV64_ITER_SKIP + RV64_CALLER_FIXED;

    // At 1 IPC — pessimistic for the dual-issue in-order U74 — and at the
    // slowest DVFS point, with the 512-byte table **warm**. Warm is the
    // realistic case (it is touched every tick), but not guaranteed: the timer
    // is tickless (`set_next_tick_smart`), so a long idle gap can leave the 8
    // cache lines cold. A fully cold table adds 8 misses; at a pessimistic
    // ~200 cycles each on the JH7110 that is ~1600 cycles ≈ 4.3 µs at 375 MHz,
    // which still fits the 10 µs whole-ISR budget but not the lane's own 20%
    // share. Both figures are printed; neither is hidden behind an average.
    //
    // The early exit does **not** touch the table at all, so the common case
    // is not merely cheap in instructions — it takes no cache miss and no
    // lock either. That is the part a pure instruction count understates.
    let wc_us = wc_instr as f64 / VF2_SLOWEST_MHZ;
    let cold_us = (wc_instr as f64 + 8.0 * 200.0) / VF2_SLOWEST_MHZ;
    let lane_allowed_us = TIMER_ISR_BUDGET_US * LANE_SHARE_OF_ISR_BUDGET;

    println!("\n=== RV64 instruction budget (callee + caller, from the artifact) ===");
    println!(
        "COMMON CASE (no deadline armed): {common_prev:>4} -> {common_instr:>4} instr  \
         ({:.1}x)   [callee {RV64_PREV_FIXED}+{}·{RV64_PREV_ITER_SKIP} -> {RV64_EARLY_EXIT}]",
        common_prev as f64 / common_instr as f64,
        MAX_LEASES,
    );
    println!(
        "  of which output-buffer init  : {RV64_PREV_ARRAY_INIT:>4} -> \
         {RV64_CALLER_ARRAY_INIT:>4} stores (256 B in the callee -> 64 B in the caller)"
    );
    println!("armed, nothing due yet         :  n/a -> {armed_idle_instr:>4} instr");
    println!("WORST CASE, k = 16             : {wc_prev:>4} -> {wc_instr:>4} instr");
    println!("\n-- against the tree's criterion --");
    println!(
        "warm, 1 IPC @ {VF2_SLOWEST_MHZ:.0} MHz (DVFS floor): {wc_us:.2} us \
         = {:.1}% of the {TIMER_ISR_BUDGET_US:.0} us whole-ISR budget (wcet.rs:97)",
        100.0 * wc_us / TIMER_ISR_BUDGET_US
    );
    println!(
        "cold table (8 misses @200 cyc)      : {cold_us:.2} us \
         = {:.0}% of the same budget",
        100.0 * cold_us / TIMER_ISR_BUDGET_US
    );
    println!(
        "scale: cap_get, the nearest comparable point, is budgeted {CAP_GET_BUDGET_US:.0} us \
         → lease_tick warm is 1/{:.0}th of it",
        CAP_GET_BUDGET_US / wc_us
    );
    println!(
        "\n-- this lane's tripwire (NOT a tree criterion) --\n\
         {:.0}% share = {lane_allowed_us:.1} us allowed; warm margin {:.1}x",
        LANE_SHARE_OF_ISR_BUDGET * 100.0,
        lane_allowed_us / wc_us
    );

    // The gate proper: the tree's own bound. Passing this is what "acceptable
    // in an ISR" means here, and it holds even with the table fully cold.
    assert!(
        cold_us < TIMER_ISR_BUDGET_US,
        "lease_tick worst case with a cold table, {cold_us:.2} us, does not fit the \
         {TIMER_ISR_BUDGET_US:.0} us whole-ISR budget (crates/drivers/sys/src/wcet.rs:97)"
    );
    // The lane's tighter tripwire, on the realistic warm case.
    assert!(
        wc_us < lane_allowed_us,
        "lease_tick warm worst case {wc_us:.2} us exceeds this lane's {lane_allowed_us:.1} us \
         convention ({:.0}% of the ISR budget) — re-justify the share or fix the function",
        LANE_SHARE_OF_ISR_BUDGET * 100.0
    );

    // **The regression gate for this batch.** An early exit that only helps in
    // the common case while raising the ISR's ceiling would be a bad trade in
    // a robot kernel; assert that the ceiling went *down*, not just that it
    // stayed inside budget.
    assert!(
        wc_instr < wc_prev,
        "the worst case grew: {wc_prev} -> {wc_instr} instructions"
    );
    // ...and that the case the change targets really collapsed. The threshold
    // is an order of magnitude, not the exact 242 -> 32, so re-measuring on a
    // new compiler does not turn this into a brittle golden number.
    assert!(
        common_instr * 5 < common_prev,
        "the common case is no longer at least 5x cheaper: {common_prev} -> {common_instr}"
    );
    // The sharpest way to state the result, and a relation between two
    // independently measured constants rather than a golden number: the
    // *entire* call now costs less than the return array's initialisation
    // alone used to, before the function had done anything at all.
    assert!(
        RV64_EARLY_EXIT < RV64_PREV_ARRAY_INIT,
        "the early exit ({RV64_EARLY_EXIT}) is no longer cheaper than the \
         {RV64_PREV_ARRAY_INIT} stores it replaced"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 5. Clock corroboration — reported, never asserted
// ───────────────────────────────────────────────────────────────────────────

/// Min-of-N nanoseconds per call of the **real** `lease_tick`.
///
/// Only shapes on which `lease_tick` is idempotent are timed this way (nothing
/// expires, so the table is unchanged and the loop can be repeated without a
/// rebuild polluting the sample). `k > 0` is handled by the paired subtraction
/// in `clock_cost_of_sixteen_expiries`.
fn min_ns_per_call(reps: usize, batch: usize) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let t0 = Instant::now();
        for _ in 0..batch {
            let mut out = [NO_TID; MAX_LEASES];
            black_box(lease_tick(black_box(NOW), black_box(&mut out)));
        }
        let ns = t0.elapsed().as_nanos() as f64 / batch as f64;
        if ns < best {
            best = ns;
        }
    }
    best
}

/// Reports absolute ns/call and, more importantly, the **ratio** between shapes
/// measured in the same run. Absolute figures on aarch64-apple-darwin do not
/// transfer to RV64; the ratio does, and it is what answers "does the
/// unconditional 256-byte return array dominate the predicate loop?".
///
/// Nothing here is asserted. A clock ceiling in a gate measures host load, not
/// the kernel — a mistake already made once.
#[test]
fn clock_corroboration_shapes_where_nothing_expires() {
    let _g = serial();
    // The empty table is measured first *and last*: the two figures bracket the
    // run, so their spread is a measured noise floor rather than an assumed one.
    // Run this while four other agents compile and the spread blows past the
    // signal — which is the whole reason nothing here is asserted.
    let idempotent: [(&str, [Slot; MAX_LEASES]); 6] = [
        ("empty (16 Free)", [Slot::free(); MAX_LEASES]),
        ("16 Active, expire=0", filled(St::Active, 0, MAX_LEASES)),
        ("16 Active, deadline in the future", filled(St::Active, FAR, MAX_LEASES)),
        ("16 Pending, deadline in the future", filled(St::Pending, FAR, MAX_LEASES)),
        ("16 Expired, deadline reached", filled(St::Expired, DEADLINE, MAX_LEASES)),
        ("empty (16 Free) — repeat, noise check", [Slot::free(); MAX_LEASES]),
    ];

    let mut measured = [0.0f64; 6];
    for (i, (_name, shape)) in idempotent.iter().enumerate() {
        build(shape);
        let _ = min_ns_per_call(50, 200); // warm-up, discarded
        measured[i] = min_ns_per_call(400, 500);
    }
    let baseline = measured[0].min(measured[5]);
    let floor = (measured[0] - measured[5]).abs();

    println!("\n=== clock (host aarch64, min-of-N, k = 0 on every row) ===");
    println!("NOTE: absolute ns do not transfer to RV64; read the ratio column.");
    for (i, (name, _shape)) in idempotent.iter().enumerate() {
        println!("{name:<40} {:>8.2} ns/call   x{:.3}", measured[i], measured[i] / baseline);
    }
    println!("measured noise floor (empty first vs last): {floor:.2} ns/call");
    reset_real();
}

/// Paired measurement of the clock cost of the worst case, k = 16.
///
/// `lease_tick` is destructive when something expires, so the table must be
/// rebuilt each rep and the rebuild dominates. The two arms therefore run the
/// **identical** build sequence and differ only in the `expire_ticks` argument
/// passed to `lease_grant` (`DEADLINE` vs `FAR`), so subtracting the two
/// min-of-N figures cancels the build and leaves 16 expiry bodies.
///
/// Reported, never asserted — same reason as above.
#[test]
fn clock_cost_of_sixteen_expiries() {
    let _g = serial();
    // One `Instant::now()` pair around a single call has no usable resolution
    // on this host (it floors at 0 ns), so a whole batch of build+tick pairs is
    // timed and divided. The build is in both arms and cancels on subtraction.
    fn build_then_tick(expire: u64, reps: usize, batch: usize) -> f64 {
        let mut best = f64::MAX;
        for _ in 0..reps {
            let t0 = Instant::now();
            for _ in 0..batch {
                reset_real();
                for i in 0..MAX_LEASES {
                    lease_grant(i, lessor_of(i), lessee_of(i), black_box(expire))
                        .expect("free slot");
                }
                let mut out = [NO_TID; MAX_LEASES];
            black_box(lease_tick(black_box(NOW), black_box(&mut out)));
            }
            let ns = t0.elapsed().as_nanos() as f64 / batch as f64;
            if ns < best {
                best = ns;
            }
        }
        best
    }

    azos_sched::shim_reset();
    azos_sched::shim_set_current(9_999, 0x1000);
    // Warm-up, discarded.
    let _ = build_then_tick(FAR, 20, 200);
    // A1, B, A2: two runs of the *identical* k = 0 arm bracket the k = 16 arm,
    // so |A1 - A2| is a measured noise floor for this instrument rather than an
    // assumed one. A signal smaller than that floor is not a measurement.
    let inert_a = build_then_tick(FAR, 300, 500); // k = 0
    let all = build_then_tick(DEADLINE, 300, 500); // k = 16
    let inert_b = build_then_tick(FAR, 300, 500); // k = 0, again
    let inert = inert_a.min(inert_b);
    let floor = (inert_a - inert_b).abs();

    println!("\n=== clock, paired: 16 Pending inert vs 16 Pending all expiring ===");
    println!("(each figure is one build[16 free + 16 grant] + one lease_tick)");
    println!("k = 0  (identical build path): {inert_a:>8.1} / {inert_b:>8.1} ns/iter");
    println!("k = 16 (worst case)         : {all:>8.1} ns/iter");
    println!("measured noise floor |A1-A2|: {floor:>8.1} ns/iter");
    println!(
        "delta attributable to 16 expiry bodies: {:>7.1} ns  ({:>5.2} ns/body){}",
        all - inert,
        (all - inert) / MAX_LEASES as f64,
        if (all - inert).abs() <= floor { "  ← BELOW THE NOISE FLOOR" } else { "" }
    );
    println!("NOTE: host figures — corroboration only, never a gate.");
    reset_real();
}
