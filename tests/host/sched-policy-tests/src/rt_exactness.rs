// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Why reservation admission is the density sum and not the processor-demand
//! (dbf / QPA) test, on one hart driven only by `rt_core`'s CBS.
//!
//! The demand-bound test (Baruah, Rosier & Howell; QPA, Zhang & Burns) is
//! exact for EDF over sporadic tasks `(q, d, t)`: jobs at least `t` apart.
//! It admits strictly more than density (`sum q / min(d, t) <= 1`), which is
//! only sufficient for that model. But the kernel does not admit tasks, it
//! admits CBS servers, and a server here is not a sporadic `(q, d, t)` task:
//! the wake rule (`Cbs::release`) starts a new server period, full budget and
//! deadline `now + d`, for a task that wakes once its deadline is past, so a
//! task that runs its budget and sleeps until its deadline draws `q` every
//! `d`. The rate a server can take is its density, whatever its period, and
//! for servers of rate `q / d` the density sum is the exact EDF bound
//! (implicit deadlines). Admitting by dbf would promise a neighbour a deadline
//! that one such task breaks: `dbf_admits_a_set_a_suspending_server_breaks`.
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod rt_exactness;`.

use crate::rt_core::*;

/// How one server's task behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Arrival {
    /// A job of `q` every `t` from 0 (the sporadic model, at its worst).
    Periodic,
    /// Runs until its budget is gone, sleeps until its server deadline,
    /// wakes then: the most a server can take under the wake rule.
    UntilDeadline,
}

/// One server `(q, d, t)` in ticks.
#[derive(Clone, Copy)]
struct Srv {
    q: u64,
    d: u64,
    t: u64,
    how: Arrival,
}

const fn srv(q: u64, d: u64, t: u64, how: Arrival) -> Srv {
    Srv { q, d, t, how }
}

/// Deadline misses of each `Periodic` server over `horizon` ticks, one hart,
/// EDF by server deadline with hard CBS (`rt::pick`'s order with every
/// reservation at one rank, the default dispatch). An `UntilDeadline`
/// server's count is always 0: it has no deadline of its own to keep.
fn misses(set: &[Srv], horizon: u64) -> Vec<u32> {
    struct S {
        c: Cbs,
        how: Arrival,
        /// Work left in the current activation.
        left: u64,
        /// The job's own deadline (`Periodic`).
        due: u64,
        /// When an `UntilDeadline` task wakes next.
        wake: u64,
        misses: u32,
    }
    let mut s: Vec<S> = set
        .iter()
        .map(|v| S { c: Cbs::new(v.q, v.t, v.d, true, 0, 0), how: v.how, left: 0, due: 0, wake: 0, misses: 0 })
        .collect();
    for now in 0..horizon {
        for j in s.iter_mut() {
            let arrives = match j.how {
                Arrival::Periodic => now % j.c.t == 0,
                Arrival::UntilDeadline => j.left == 0 && now >= j.wake,
            };
            if arrives {
                if j.how == Arrival::Periodic && j.left != 0 {
                    j.misses += 1; // the previous job did not finish
                }
                j.left = j.c.q;
                j.due = now + j.c.d;
                j.c.release_due = true;
                j.c.release(now);
            }
            j.c.replenish_if_due(now);
        }
        let mut pick: Option<usize> = None;
        for k in 0..s.len() {
            if s[k].left == 0 || !s[k].c.eligible() {
                continue;
            }
            pick = match pick {
                Some(p) if !edf_before(0, s[k].c.deadline, 0, s[p].c.deadline) => Some(p),
                _ => Some(k),
            };
        }
        let Some(k) = pick else { continue };
        let j = &mut s[k];
        j.left -= 1;
        if j.left == 0 {
            if j.how == Arrival::Periodic && now + 1 > j.due {
                j.misses += 1; // finished late
            }
            // Asleep until the deadline the server holds now.
            j.wake = j.c.deadline;
        }
        if j.c.charge(1) && j.left != 0 {
            j.c.exhaust(now + 1);
        }
    }
    s.iter().map(|j| j.misses).collect()
}

/// The density admission of one hart, as `rt::reserve` applies it.
fn density_admits(set: &[Srv]) -> bool {
    let mut load = HartLoad::default();
    for v in set {
        let Ok(dens) = density_ppm(v.q, v.t, v.d) else { return false };
        if fits(load, dens, false, PPM as u32).is_err() {
            return false;
        }
        load.total_ppm += dens;
    }
    true
}

/// The processor-demand test for sporadic `(q, d, t)` tasks on one hart:
/// utilisation at most 1 and `dbf(L) <= L` at every `L` up to the hyperperiod
/// plus the longest deadline. Small integer sets only; this is the oracle the tests
/// compare the density admission against, not a kernel path.
fn dbf_admits(set: &[Srv]) -> bool {
    let gcd = |mut a: u64, mut b: u64| {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    };
    let hyper = set.iter().fold(1u64, |h, v| h / gcd(h, v.t) * v.t);
    // Utilisation at most 1 first: past the bound below only it decides.
    if set.iter().map(|v| v.q * (hyper / v.t)).sum::<u64>() > hyper {
        return false;
    }
    let bound = hyper + set.iter().map(|v| v.d).max().unwrap_or(0);
    (1..=bound).all(|l| {
        let dbf: u64 = set
            .iter()
            .map(|v| if l < v.d { 0 } else { ((l - v.d) / v.t + 1) * v.q })
            .sum();
        dbf <= l
    })
}

const P: Arrival = Arrival::Periodic;
const W: Arrival = Arrival::UntilDeadline;

/// A density-tight hart (1.0 exactly) with the most demanding wake pattern
/// on its tighter server: the neighbour keeps every deadline.
#[test]
fn a_density_admitted_set_keeps_its_deadlines_against_a_suspending_server() {
    let set = [srv(2, 4, 10, W), srv(4, 8, 10, P)];
    assert!(density_admits(&set));
    assert_eq!(misses(&set, 2_000), vec![0, 0]);
}

/// The set the exact test would add: density 1.3, so refused today; dbf
/// feasible (its demand at L = 2, 5, 10, 12 is 1, 5, 5, 6), and with
/// periodic arrivals it does keep every deadline. A server that wakes at its
/// deadline instead takes 1 of every 2 ticks and the neighbour misses, so a
/// dbf admission is a promise the CBS does not keep.
#[test]
fn dbf_admits_a_set_a_suspending_server_breaks() {
    let periodic = [srv(1, 2, 10, P), srv(4, 5, 10, P)];
    let suspending = [srv(1, 2, 10, W), srv(4, 5, 10, P)];
    assert!(!density_admits(&periodic), "density admits a 1.3 hart");
    assert!(dbf_admits(&periodic), "the oracle refuses a feasible set");
    assert_eq!(misses(&periodic, 2_000), vec![0, 0], "the periodic set is not feasible after all");
    let m = misses(&suspending, 2_000);
    assert!(m[1] > 0, "the suspending server did not cost the neighbour a deadline: {m:?}");
}

/// Every set of up to three servers drawn from small parameters that density
/// admits keeps the periodic servers' deadlines whatever subset of servers
/// suspends; and among them some set that dbf admits but density refuses
/// breaks one, so the oracle is not trivially the same test.
#[test]
fn density_admission_holds_for_every_wake_pattern_and_dbf_does_not() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let (mut admitted, mut dbf_broken) = (0, 0);
    for _ in 0..400 {
        let n = 2 + next(2) as usize;
        let mut set = Vec::new();
        for _ in 0..n {
            let t = [6, 8, 10, 12][next(4) as usize];
            let d = 2 + next(t - 1);
            let q = 1 + next(d.min(4));
            set.push(srv(q, d, t, P));
        }
        for pattern in 0u32..(1 << n) {
            let mut s = set.clone();
            for (i, v) in s.iter_mut().enumerate() {
                if pattern & (1 << i) != 0 {
                    v.how = W;
                }
            }
            let m = misses(&s, 600);
            let periodic_misses: u32 = m.iter().sum();
            if density_admits(&s) {
                admitted += 1;
                assert_eq!(periodic_misses, 0, "density admitted a set that missed: q/d/t {:?}",
                    s.iter().map(|v| (v.q, v.d, v.t, v.how == W)).collect::<Vec<_>>());
            } else if dbf_admits(&s) && periodic_misses > 0 {
                dbf_broken += 1;
            }
        }
    }
    assert!(admitted > 100, "too few density-admitted sets drawn ({admitted})");
    assert!(dbf_broken > 0, "no dbf-admitted set was broken by a suspending server");
}
