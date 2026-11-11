// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The two budget ledgers of `crates/core/mm/src/budget.rs` (`PageBudget`,
//! `KmemBudget`) under stress, on the real file pulled with `#[path]`:
//!
//!  * `all_or_nothing`: a refusal leaves EVERY number as it was;
//!  * `saturating`: the limits of the integer types, and a model check of
//!    long random sequences against plain `u64` arithmetic;
//!  * `harts`: several threads on one budget, the exact sum at the end;
//!  * `hysteresis`: the level does not flap at a watermark;
//!  * `locked_rt`: locked and real-time Domains never enter reclaim, and a
//!    promised restore is never refused.
//!
//! The charge-site table (every charge has its discharge) is in
//! `tests/host/syscall-tests/src/budget_sites.rs`.
//! No loom: the workspace does not vendor it, so the races are std threads
//! released together by a barrier over many short rounds (one long round let
//! the first thread take most of the headroom, see `budget_tests`).

use super::budget::{
    growth_pool, pressure_after, set_growth_pool, watermarks_for, Granted, KmemBudget, KmemClass, NoStorm,
    PageBudget, Pressure, Pressure::*, RequestRefused,
};

/// Every number a `PageBudget` keeps. The growth pool is process-wide and is
/// compared only by the rows that hold the pool lock.
type Snap = (u32, u32, u32, u32, u32, u32);

fn snap(b: &PageBudget) -> Snap {
    (b.used(), b.peak(), b.limit(), b.grown(), b.ceiling(), b.base())
}

fn ksnap(b: &KmemBudget) -> (u64, u64, [u64; 4]) {
    (b.used(), b.limit(), [0, 1, 2, 3].map(|i| b.used_of(KmemClass::from_index(i).unwrap())))
}

/// A small deterministic generator (xorshift64*): the sequences are the same on
/// every host and a failure names its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

mod all_or_nothing {
    use super::*;
    use crate::budget_tests::pool;

    /// Every way a request can be refused leaves the used count, the peak, the
    /// limit, the growth, the ceiling, the base AND the growth pool exactly as
    /// they were (`used` alone is what the older rows look at).
    #[test]
    fn a_refused_request_changes_nothing_whatever_the_reason() {
        let _g = pool(5);
        // (limit, ceiling, charged before, ask, may_grow, why)
        let table: [(u32, u32, u32, u32, bool, RequestRefused); 5] = [
            (16, 64, 10, 10, false, RequestRefused::Limit), // a real-time Domain never grows
            (16, 0, 10, 10, true, RequestRefused::Limit),   // no ceiling above the limit
            (16, 16, 10, 10, true, RequestRefused::Limit),  // a ceiling at the limit is none
            (16, 20, 10, 11, true, RequestRefused::Ceiling), // past the ceiling
            (16, 64, 10, 20, true, RequestRefused::Pool),   // 14 of growth, 5 in the pool
        ];
        for (limit, ceiling, before, ask, may_grow, why) in table {
            let b = PageBudget::new();
            b.set_limit_marked(limit, 85, 65);
            b.set_ceiling(ceiling);
            assert!(b.charge(before));
            let (s, pool_before) = (snap(&b), growth_pool());
            assert_eq!(b.charge_request(ask, may_grow), Err(why), "{limit}/{ceiling} ask {ask}");
            assert_eq!(snap(&b), s, "{why:?}: a refusal must change nothing, not even the peak");
            assert_eq!(growth_pool(), pool_before, "{why:?}: nor the growth pool");
        }
    }

    /// The plain charge is the same: refused at the limit, nothing moves, and
    /// the peak is not raised by the request that did not land.
    #[test]
    fn a_refused_charge_does_not_move_the_peak_or_the_marks() {
        let b = PageBudget::new();
        b.set_limit_marked(100, 85, 65);
        assert!(b.charge(90));
        b.discharge(30);
        let s = snap(&b);
        assert!(!b.charge(41), "60 + 41 is past 100");
        assert_eq!(snap(&b), s);
        assert_eq!((b.low(), b.high()), (65, 85));
        assert!(b.charge(40), "and exactly 100 is granted");
        assert_eq!((b.used(), b.peak()), (100, 100));
    }

    /// The kernel-memory ledger: a refusal leaves the sum, the limit and every
    /// class as they were, for every class.
    #[test]
    fn a_refused_kmem_charge_changes_no_class() {
        for c in KmemClass::ALL {
            let b = KmemBudget::new();
            b.set_limit_kib(1);
            assert_eq!(b.charge(KmemClass::CapTable, 700), Ok(()));
            assert_eq!(b.charge(KmemClass::PageTable, 200), Ok(()));
            let s = ksnap(&b);
            assert!(b.charge(c, 125).is_err(), "{c:?}: 900 + 125 is past 1024");
            assert_eq!(ksnap(&b), s, "{c:?}");
            assert!(b.charge(c, u64::MAX).is_err());
            assert_eq!(ksnap(&b), s, "{c:?}: a refusal of the largest ask");
        }
    }

    /// A granted request charges exactly what it asked, in every way it can be
    /// granted: within the limit, or by growth (the growth is the request's, never
    /// a page more).
    #[test]
    fn a_granted_request_charges_exactly_what_it_asked() {
        let _g = pool(1000);
        let b = PageBudget::new();
        b.set_limit(10);
        b.set_ceiling(100);
        assert_eq!(b.charge_request(7, true), Ok(Granted::Within));
        assert_eq!((b.used(), b.limit(), b.grown()), (7, 10, 0));
        assert_eq!(b.charge_request(20, true), Ok(Granted::Grew(17)));
        assert_eq!((b.used(), b.limit(), b.grown(), growth_pool()), (27, 27, 17, 983));
    }
}

mod saturating {
    use super::*;
    use crate::budget_tests::pool;

    /// A limit just under the top of the type: the request whose sum saturates
    /// is refused, not granted by the saturation.
    #[test]
    fn a_saturated_sum_is_refused_under_a_limit_below_the_top() {
        let b = PageBudget::new();
        b.set_limit(u32::MAX - 5);
        assert!(b.charge(u32::MAX - 5));
        let s = snap(&b);
        assert!(!b.charge(10), "u32::MAX - 5 + 10 saturates to u32::MAX, past the limit");
        assert!(!b.charge(u32::MAX));
        assert_eq!(snap(&b), s);
        b.discharge(u32::MAX);
        assert_eq!(b.used(), 0, "and the budget is usable afterwards");
        assert!(b.charge(1));
    }

    /// A restore near the top saturates, is never refused, and the peak follows.
    #[test]
    fn a_restore_near_the_top_saturates_and_the_peak_follows() {
        let b = PageBudget::new();
        b.set_limit(8);
        b.charge_restore(u32::MAX - 1);
        assert_eq!((b.used(), b.peak()), (u32::MAX - 1, u32::MAX - 1));
        b.charge_restore(10);
        assert_eq!((b.used(), b.peak()), (u32::MAX, u32::MAX));
        b.charge_restore(0);
        assert_eq!(b.used(), u32::MAX, "zero pages is a no-op");
        b.discharge(u32::MAX);
        assert_eq!(b.used(), 0);
    }

    /// Zero everywhere: a zero charge, a zero restore and a zero discharge change
    /// nothing at a full budget, an empty one, and an unlimited one.
    #[test]
    fn zero_is_a_no_op_at_every_fill() {
        for limit in [0u32, 4] {
            let b = PageBudget::new();
            b.set_limit(limit);
            for fill in [0u32, 4] {
                b.reset();
                assert!(b.charge(fill));
                let s = snap(&b);
                assert!(b.charge(0));
                b.charge_restore(0);
                b.discharge(0);
                assert_eq!(snap(&b), s, "limit {limit} fill {fill}");
            }
        }
    }

    /// The model: random sequences of every operation against plain `u64`
    /// arithmetic, with sizes from one page to past `u32::MAX`. `used` never
    /// goes below zero or passes a nonzero limit by a charge, a refusal never
    /// changes it, and the peak is the largest it ever was.
    #[test]
    fn page_budget_follows_a_model_over_long_random_sequences() {
        let _g = pool(0);
        for seed in 1..=8u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            for limit in [0u32, 1, 7, 1000, u32::MAX - 3] {
                let b = PageBudget::new();
                b.set_limit(limit);
                let (mut used, mut peak) = (0u64, 0u64);
                let cap = u64::from(u32::MAX);
                for step in 0..4000 {
                    let pages = match rng.below(6) {
                        0 => 0,
                        1 => 1,
                        2 => rng.below(8),
                        3 => rng.below(2000),
                        4 => cap - rng.below(4),
                        _ => cap,
                    };
                    let ctx = format!("seed {seed} limit {limit} step {step} pages {pages}");
                    match rng.below(4) {
                        0 => {
                            let granted = pages == 0 || limit == 0 || (used + pages).min(cap) <= u64::from(limit);
                            assert_eq!(b.charge(pages as u32), granted, "{ctx}");
                            if granted && pages != 0 {
                                used = (used + pages).min(cap);
                                peak = peak.max(used);
                            }
                        }
                        1 => {
                            b.discharge(pages as u32);
                            used = used.saturating_sub(pages);
                        }
                        2 => {
                            b.charge_restore(pages as u32);
                            if pages != 0 {
                                used = (used + pages).min(cap);
                                peak = peak.max(used);
                            }
                        }
                        _ => {
                            let r = b.charge_request(pages as u32, false);
                            let granted = pages == 0 || limit == 0 || (used + pages).min(cap) <= u64::from(limit);
                            assert_eq!(r.is_ok(), granted, "{ctx}");
                            if granted && pages != 0 {
                                used = (used + pages).min(cap);
                                peak = peak.max(used);
                            }
                        }
                    }
                    assert_eq!((u64::from(b.used()), u64::from(b.peak())), (used, peak), "{ctx}");
                }
            }
        }
    }

    /// The same for the kernel-memory ledger, with a limit: `used` is always the
    /// sum of the classes, never passes the limit, and a discharge returns
    /// exactly what the class held.
    #[test]
    fn kmem_budget_follows_a_model_over_long_random_sequences() {
        for seed in 1..=8u64 {
            let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
            for limit_kib in [0u32, 1, 64, 4096] {
                let b = KmemBudget::new();
                b.set_limit_kib(limit_kib);
                let limit = u64::from(limit_kib) * 1024;
                let mut held = [0u64; 4];
                for step in 0..4000 {
                    let class = KmemClass::from_index(rng.below(4) as u8).unwrap();
                    let bytes = match rng.below(5) {
                        0 => 0,
                        1 => rng.below(64),
                        2 => rng.below(8192),
                        3 => 1 << 40,
                        _ => u64::MAX / 8,
                    };
                    let i = class as usize;
                    let ctx = format!("seed {seed} limit {limit_kib} step {step} {class:?} {bytes}");
                    match rng.below(5) {
                        0 | 1 => {
                            let sum: u64 = held.iter().sum();
                            let fits = limit == 0 || sum.saturating_add(bytes) <= limit;
                            assert_eq!(b.charge(class, bytes).is_ok(), fits, "{ctx}");
                            if fits && sum.saturating_add(bytes) < u64::MAX / 2 {
                                held[i] += bytes;
                            } else if fits {
                                // Unlimited and huge: the saturation tests own this corner.
                                b.reset();
                                held = [0; 4];
                            }
                        }
                        2 | 3 => {
                            let took = b.discharge(class, bytes);
                            assert_eq!(took, held[i].min(bytes), "{ctx}");
                            held[i] -= took;
                        }
                        _ => {
                            assert_eq!(b.discharge_all(class), held[i], "{ctx}");
                            held[i] = 0;
                        }
                    }
                    assert_eq!(b.used(), held.iter().sum::<u64>(), "{ctx}: used is the sum of the classes");
                    for c in KmemClass::ALL {
                        assert_eq!(b.used_of(c), held[c as usize], "{ctx}");
                    }
                    assert!(limit == 0 || b.used() <= limit, "{ctx}: passed the limit");
                }
            }
        }
    }

    /// **A class word does not wrap.** `used` saturates at `u64::MAX` under no
    /// limit; the class a charge lands in must saturate with it, or the next
    /// discharge of that class returns a few bytes of a ledger that held
    /// 18 exabytes.
    /// **Canary** `kmem-class-wrap-canary`: the class word is a plain atomic add.
    #[test]
    fn a_class_word_saturates_with_the_sum_instead_of_wrapping() {
        let b = KmemBudget::new();
        assert_eq!(b.charge(KmemClass::CapTable, u64::MAX), Ok(()));
        assert_eq!(b.charge(KmemClass::CapTable, 10), Ok(()), "no limit: granted, saturated");
        assert_eq!(b.used(), u64::MAX);
        assert_eq!(b.used_of(KmemClass::CapTable), u64::MAX, "the class saturates, it does not wrap to 9");
        assert_eq!(b.discharge(KmemClass::CapTable, 10), 10);
        assert_eq!(b.used_of(KmemClass::CapTable), u64::MAX - 10);
    }

    /// The limits of `watermarks_for` over every limit a small domain has and
    /// the largest, for every pair of percentages the Kconfig ranges allow
    /// (`MM_RECLAIM_HIGH_PCT` 2..99, `MM_RECLAIM_LOW_PCT` below it): `low < high
    /// <= limit`, `high` at least one page, and no overflow on the way.
    #[test]
    fn the_watermarks_stay_ordered_and_inside_the_limit() {
        for limit in (1u32..=300).chain([1000, 65_536, u32::MAX - 1, u32::MAX]) {
            for high_pct in 2..=99u32 {
                for low_pct in [0u32, 1, high_pct / 2, high_pct - 1] {
                    let (low, high) = watermarks_for(limit, high_pct, low_pct);
                    assert!(high >= 1 && low < high && high <= limit, "limit {limit} {low_pct}/{high_pct}: {low}/{high}");
                }
            }
        }
        assert_eq!(watermarks_for(0, 85, 65), (0, 0));
        assert_eq!(watermarks_for(1000, 0, 65), (0, 0));
    }
}

mod harts {
    use super::*;
    use crate::budget_tests::pool;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    /// **Growth from several harts and several Domains on one pool.** Three
    /// Domains grow one page at a time from four threads each, against a pool
    /// that cannot hold what they ask. At the end the pool and the growth agree
    /// to the page: what the Domains grew by is exactly what the pool lost, no
    /// Domain is past its ceiling, and each Domain's growth is its limit less its
    /// base. With one-page requests the pool runs dry to the last page.
    #[test]
    fn growth_from_many_harts_and_domains_conserves_the_pool() {
        const POOL: u64 = 100;
        let _g = pool(POOL);
        for round in 0..40 {
            set_growth_pool(POOL);
            let doms: Vec<Arc<PageBudget>> = (0..3)
                .map(|_| {
                    let b = Arc::new(PageBudget::new());
                    b.set_limit(10);
                    b.set_ceiling(80);
                    b
                })
                .collect();
            let start = Arc::new(Barrier::new(12));
            let mut ts = Vec::new();
            for t in 0..12 {
                let (b, start) = (doms[t % 3].clone(), start.clone());
                ts.push(std::thread::spawn(move || {
                    start.wait();
                    let mut granted = 0u32;
                    for _ in 0..40 {
                        if b.charge_request(1, true).is_ok() {
                            granted += 1;
                        }
                    }
                    granted
                }));
            }
            let granted: u32 = ts.into_iter().map(|t| t.join().unwrap()).sum();
            let (mut grown, mut used) = (0u64, 0u64);
            for b in &doms {
                assert!(b.used() <= b.limit() && b.limit() <= b.ceiling(), "round {round}: past the limit or ceiling");
                assert_eq!(u64::from(b.grown()), u64::from(b.limit() - b.base()), "round {round}: growth is limit less base");
                grown += u64::from(b.grown());
                used += u64::from(b.used());
            }
            assert_eq!(u64::from(granted), used, "round {round}: a grant was not charged, or a charge was not granted");
            assert_eq!(growth_pool(), POOL - grown, "round {round}: the pool and the growth disagree");
            assert_eq!(grown, POOL.min(3 * 70), "round {round}: one-page requests drain the pool to the last page");
            for b in &doms {
                b.set_limit(10);
            }
            assert_eq!(growth_pool(), POOL, "round {round}: declaring the limits again gives all of it back");
        }
    }

    /// The same with requests of several sizes, and plain charges and discharges
    /// of the same Domains going on: nothing is double counted, and the books
    /// still close (pool lost == growth; used == grants net of gives).
    #[test]
    fn growth_with_mixed_sizes_and_discharges_still_closes_the_books() {
        const POOL: u64 = 64;
        let _g = pool(POOL);
        for round in 0..40 {
            set_growth_pool(POOL);
            let doms: Vec<Arc<PageBudget>> = (0..2)
                .map(|_| {
                    let b = Arc::new(PageBudget::new());
                    b.set_limit(8);
                    b.set_ceiling(48);
                    b
                })
                .collect();
            let net = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
            let start = Arc::new(Barrier::new(8));
            let mut ts = Vec::new();
            for t in 0..8usize {
                let (b, start, net) = (doms[t % 2].clone(), start.clone(), net.clone());
                ts.push(std::thread::spawn(move || {
                    let mut rng = Rng(0x1234_5678 + (t as u64) * 7919 + round);
                    start.wait();
                    for _ in 0..300 {
                        let n = 1 + rng.below(4) as u32;
                        match rng.below(3) {
                            0 => {
                                if b.charge_request(n, true).is_ok() {
                                    net[t % 2].fetch_add(u64::from(n), Ordering::Relaxed);
                                }
                            }
                            1 => {
                                if b.charge(n) {
                                    net[t % 2].fetch_add(u64::from(n), Ordering::Relaxed);
                                }
                            }
                            _ => {
                                // Give back only what this thread was granted: the
                                // `net` count moves with the discharge.
                                if net[t % 2]
                                    .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |v| v.checked_sub(u64::from(n)))
                                    .is_ok()
                                {
                                    b.discharge(n);
                                }
                            }
                        }
                    }
                }));
            }
            for t in ts {
                t.join().unwrap();
            }
            let mut grown = 0u64;
            for (i, b) in doms.iter().enumerate() {
                assert_eq!(u64::from(b.used()), net[i].load(Ordering::Relaxed), "round {round}: Domain {i} lost an update");
                assert!(b.limit() <= b.ceiling());
                assert_eq!(b.grown(), b.limit() - b.base());
                grown += u64::from(b.grown());
            }
            assert_eq!(growth_pool(), POOL - grown, "round {round}");
            for b in &doms {
                b.set_limit(8);
            }
            assert_eq!(growth_pool(), POOL);
        }
    }

    /// Charges, restores and discharges from eight threads on one budget: the
    /// count at the end is exactly the net of what each thread did, the restores
    /// are all counted (they are never refused), and the plain charges never took
    /// the count past the limit by themselves.
    /// **Canary** `budget-restore-refused-canary` drops a restore past the limit.
    #[test]
    fn restores_and_charges_and_discharges_from_many_harts_sum_exactly() {
        let _g = pool(0);
        for round in 0..40u64 {
            let b = Arc::new(PageBudget::new());
            b.set_limit(50);
            let net = Arc::new(AtomicU64::new(0));
            let start = Arc::new(Barrier::new(8));
            let ts: Vec<_> = (0..8u64)
                .map(|t| {
                    let (b, start, net) = (b.clone(), start.clone(), net.clone());
                    std::thread::spawn(move || {
                        let mut rng = Rng(0xABCD_0000 + t * 104_729 + round);
                        start.wait();
                        for _ in 0..400 {
                            let n = 1 + rng.below(3) as u32;
                            if t < 3 {
                                // Restores: promised, never refused, whatever the count is.
                                b.charge_restore(n);
                                net.fetch_add(u64::from(n), Ordering::Relaxed);
                            } else if rng.below(2) == 0 {
                                if b.charge(n) {
                                    net.fetch_add(u64::from(n), Ordering::Relaxed);
                                }
                            } else if net.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |v| v.checked_sub(u64::from(n))).is_ok() {
                                b.discharge(n);
                            }
                        }
                    })
                })
                .collect();
            for t in ts {
                t.join().unwrap();
            }
            assert_eq!(u64::from(b.used()), net.load(Ordering::Relaxed), "round {round}: a restore, charge or discharge was lost");
            assert!(u64::from(b.peak()) >= u64::from(b.used()));
        }
    }

    /// **Kernel memory, charged and given back by several harts on different
    /// classes and the same class.** The limit holds at every sample, and at the
    /// end `used` is the sum of the classes and the sum of what the threads still
    /// hold.
    /// **Canary** `kmem-racy-charge-canary`: the limit is tested and the sum
    /// stored in two steps.
    #[test]
    fn kmem_charges_and_discharges_from_many_harts_close_exactly() {
        const LIMIT_KIB: u32 = 8;
        for round in 0..60u64 {
            let b = Arc::new(KmemBudget::new());
            b.set_limit_kib(LIMIT_KIB);
            let limit = u64::from(LIMIT_KIB) * 1024;
            let over = Arc::new(AtomicU32::new(0));
            let start = Arc::new(Barrier::new(8));
            let ts: Vec<_> = (0..8usize)
                .map(|t| {
                    let (b, start, over) = (b.clone(), start.clone(), over.clone());
                    std::thread::spawn(move || {
                        let mut rng = Rng(0x5EED_0000 + (t as u64) * 6151 + round);
                        let mut held = [0u64; 4];
                        start.wait();
                        for _ in 0..1500 {
                            // Half the threads share a class, half have one each.
                            let class = KmemClass::from_index(if t < 4 { 0 } else { (t - 3) as u8 % 4 }).unwrap();
                            let n = 1 + rng.below(96);
                            if rng.below(3) != 0 {
                                if b.charge(class, n).is_ok() {
                                    held[class as usize] += n;
                                }
                            } else {
                                let give = n.min(held[class as usize]);
                                assert_eq!(b.discharge(class, give), give, "a thread's own charge was not there to give back");
                                held[class as usize] -= give;
                            }
                            if b.used() > limit {
                                over.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        held
                    })
                })
                .collect();
            let mut held = [0u64; 4];
            for t in ts {
                let h = t.join().unwrap();
                for i in 0..4 {
                    held[i] += h[i];
                }
            }
            assert_eq!(over.load(Ordering::Relaxed), 0, "round {round}: a sample saw the ledger past its limit");
            assert_eq!(b.used(), held.iter().sum::<u64>(), "round {round}: the sum lost an update");
            for c in KmemClass::ALL {
                assert_eq!(b.used_of(c), held[c as usize], "round {round}: {c:?}");
            }
            assert!(b.used() <= limit);
        }
    }

    /// **A change of level is told once, whichever hart asks.** Two threads move
    /// the charge across the high watermark and the limit while three poll
    /// `pressure_change`. Every answered change is a real one, and together they
    /// are a path: from the level the budget began at, through each one, to the
    /// level it ended at (a lost or doubled answer breaks the count in or out of
    /// some level).
    #[test]
    fn every_level_change_is_answered_once_across_harts() {
        for round in 0..40 {
            let b = Arc::new(PageBudget::new());
            b.set_limit_marked(1000, 85, 65);
            let seen: Arc<Mutex<Vec<(Pressure, Pressure)>>> = Arc::default();
            let start = Arc::new(Barrier::new(5));
            let done = Arc::new(AtomicU32::new(0));
            let mut ts = Vec::new();
            for t in 0..2u64 {
                let (b, start, done) = (b.clone(), start.clone(), done.clone());
                ts.push(std::thread::spawn(move || {
                    let mut rng = Rng(77 + t * 31 + round);
                    start.wait();
                    for _ in 0..3000 {
                        let n = 1 + rng.below(300) as u32;
                        if rng.below(2) == 0 {
                            b.charge(n);
                        } else {
                            b.discharge(n);
                        }
                    }
                    done.fetch_add(1, Ordering::Release);
                }));
            }
            for _ in 0..3 {
                let (b, start, seen, done) = (b.clone(), start.clone(), seen.clone(), done.clone());
                ts.push(std::thread::spawn(move || {
                    start.wait();
                    while done.load(Ordering::Acquire) < 2 {
                        if let Some(c) = b.pressure_change() {
                            seen.lock().unwrap().push(c);
                        }
                    }
                }));
            }
            for t in ts {
                t.join().unwrap();
            }
            // The last change nobody asked about yet.
            if let Some(c) = b.pressure_change() {
                seen.lock().unwrap().push(c);
            }
            let seen = seen.lock().unwrap();
            assert!(seen.iter().all(|(f, t)| f != t), "round {round}: a no-change was answered");
            for lvl in [Normal, Warning, Critical] {
                let out = seen.iter().filter(|(f, _)| *f == lvl).count() as i64;
                let inn = seen.iter().filter(|(_, t)| *t == lvl).count() as i64;
                let expect = i64::from(lvl == Normal) - i64::from(lvl == b.reported());
                assert_eq!(out - inn, expect, "round {round}: {lvl:?} is not on one path from Normal to {:?}", b.reported());
            }
        }
    }
}

mod hysteresis {
    use super::*;

    /// A budget of 1000 pages with the kernel's default marks 65/85 percent.
    fn row() -> PageBudget {
        let b = PageBudget::new();
        b.set_limit_marked(1000, 85, 65);
        b
    }

    fn to(b: &PageBudget, used: u32) {
        let now = b.used();
        if used > now {
            assert!(b.charge(used - now));
        } else {
            b.discharge(now - used);
        }
    }

    /// Count the changes `pressure_change` answers while the charge goes between
    /// `lo` and `hi` a thousand times.
    fn flaps(b: &PageBudget, lo: u32, hi: u32) -> Vec<(Pressure, Pressure)> {
        let mut seen = Vec::new();
        for _ in 0..1000 {
            to(b, hi);
            seen.extend(b.pressure_change());
            to(b, lo);
            seen.extend(b.pressure_change());
        }
        seen
    }

    /// **A charge oscillating around a watermark answers one change, not a
    /// thousand.** Around the high watermark (Normal to Warning once, then it
    /// stays Warning down to the low mark), around the limit (Warning to Critical
    /// once; Critical is left only below `high`), and around the low mark
    /// (Warning to Normal once; Normal is left only at `high`).
    /// **Canary** `pressure-flap-canary`: the level forgets where it was.
    #[test]
    fn an_oscillation_around_a_watermark_is_one_change() {
        let b = row();
        to(&b, 800);
        assert_eq!(b.pressure_change(), None);
        assert_eq!(flaps(&b, 849, 850), vec![(Normal, Warning)], "around high");
        to(&b, 900);
        b.pressure_change();
        assert_eq!(flaps(&b, 999, 1000), vec![(Warning, Critical)], "around the limit");
        to(&b, 900);
        assert_eq!(b.pressure_change(), None, "critical is left below high, not at the limit");
        // Back below high, down to the low mark.
        to(&b, 800);
        assert_eq!(b.pressure_change(), Some((Critical, Warning)));
        assert_eq!(flaps(&b, 650, 651), vec![(Warning, Normal)], "around low");
        assert_eq!(b.reported(), Normal);
        assert_eq!(flaps(&b, 700, 849), vec![], "normal is not left below high");
    }

    /// A random walk confined to a band the level does not leave is silent: from
    /// Warning inside `(low, high)`, from Critical inside `[high, limit)`.
    #[test]
    fn a_walk_inside_a_band_never_changes_the_level() {
        let mut rng = Rng(0xC0FFEE);
        let b = row();
        to(&b, 900);
        b.pressure_change();
        to(&b, 1000);
        assert_eq!(b.pressure_change(), Some((Warning, Critical)));
        for _ in 0..20_000 {
            to(&b, 850 + rng.below(150) as u32);
            assert_eq!(b.pressure_change(), None, "critical inside [high, limit)");
        }
        to(&b, 849);
        assert_eq!(b.pressure_change(), Some((Critical, Warning)));
        for _ in 0..20_000 {
            to(&b, 651 + rng.below(199) as u32);
            assert_eq!(b.pressure_change(), None, "warning inside (low, high)");
        }
    }

    /// A storm that reaches the low mark and a Domain that charges right back up
    /// to just under high: no change either way. (The storm's own end is covered
    /// in `pressure.rs`.)
    #[test]
    fn a_storms_exit_and_a_quick_refill_do_not_flap() {
        let b = row();
        to(&b, 900);
        assert_eq!(b.pressure_change(), Some((Normal, Warning)));
        to(&b, 650);
        assert_eq!(b.pressure_change(), Some((Warning, Normal)));
        to(&b, 849);
        assert_eq!(b.pressure_change(), None, "refilled to one under high: still normal");
        assert!(!b.over_high(), "and no storm is due");
    }

    /// The pure function itself never moves from `cur` to a lower level for a
    /// charge above the mark that would have raised it, for any marks.
    #[test]
    fn the_level_never_drops_while_the_charge_is_at_or_above_its_mark() {
        for &(low, high, limit) in &[(0u32, 1u32, 2u32), (3, 4, 5), (650, 850, 1000), (1, 99, 100)] {
            for used in 0..=limit + 2 {
                for cur in [Normal, Warning, Critical] {
                    let l = pressure_after(cur, used, low, high, limit);
                    if used >= limit {
                        assert_eq!(l, Critical);
                    } else if used >= high {
                        assert!(l >= Warning, "{cur:?} used {used} {low}/{high}/{limit}");
                        if cur == Critical {
                            assert_eq!(l, Critical, "critical stays until the charge is below high");
                        }
                    } else if used > low && cur != Normal {
                        assert_eq!(l, Warning);
                    }
                }
            }
        }
    }
}

mod locked_rt {
    use super::*;
    use crate::budget_tests::pool;

    /// A budget of 100 pages, marks 65/85, charged to `used`.
    fn at(used: u32) -> PageBudget {
        let b = PageBudget::new();
        b.set_limit_marked(100, 85, 65);
        b.set_ceiling(400);
        b.charge_restore(used);
        b
    }

    /// **A locked or real-time Domain never enters reclaim**, at any charge: below
    /// high, at high, at the limit and past it (a restore overshoot). Only an
    /// unlocked caller on a non-real-time hart at or above high opens a storm,
    /// and a refusal leaves no storm open and every number where it was.
    /// **Canary** `storm-ignore-locked-canary` (the same canary the reclaim rows
    /// use) lets a locked Domain in.
    #[test]
    fn locked_and_real_time_never_open_a_storm_at_any_charge() {
        for used in [0, 64, 65, 84, 85, 99, 100, 101, 150] {
            for locked in [false, true] {
                for rt in [false, true] {
                    let b = at(used);
                    let s = snap(&b);
                    let r = b.storm_begin(locked, rt);
                    let expect = if locked {
                        Err(NoStorm::Locked)
                    } else if rt {
                        Err(NoStorm::RtHart)
                    } else if used >= 85 {
                        Ok(())
                    } else {
                        Err(NoStorm::BelowHigh)
                    };
                    assert_eq!(r, expect, "used {used} locked {locked} rt {rt}");
                    if r.is_err() {
                        assert_eq!(b.reclaim_target(), 0, "no storm is open");
                        assert!(b.storm_end(4096).is_none(), "and none to close");
                        assert_eq!(snap(&b), s, "a refused storm changes nothing");
                    } else {
                        assert_eq!(b.storm_begin(false, false), Err(NoStorm::Busy));
                        assert!(b.storm_end(4096).is_some());
                    }
                }
            }
        }
    }

    /// A Domain that never grows (real time, locked) is refused at its limit
    /// whatever the ceiling and the pool, with nothing moved, and is never
    /// growth in the books.
    #[test]
    fn a_domain_that_never_grows_is_never_growth() {
        let _g = pool(1 << 20);
        let b = at(0);
        b.charge(100);
        let s = snap(&b);
        for ask in [1, 2, 100, u32::MAX] {
            assert_eq!(b.charge_request(ask, false), Err(RequestRefused::Limit));
        }
        assert_eq!(snap(&b), s);
        assert_eq!((b.grown(), growth_pool()), (0, 1 << 20));
    }

    /// **A promised restore is never refused.** At the limit, and over it, a
    /// restore is charged; the plain charge is then refused until the overshoot
    /// is given back, and the books close.
    /// **Canary** `budget-restore-refused-canary`: a restore past the limit is dropped.
    #[test]
    fn a_promised_restore_is_charged_at_and_over_the_limit() {
        let b = at(100);
        assert!(!b.charge(1));
        for _ in 0..5 {
            b.charge_restore(1);
        }
        assert_eq!(b.used(), 105, "five restores over the limit, all counted");
        assert_eq!(b.peak(), 105);
        assert_eq!(b.pressure(), Critical);
        assert!(!b.charge(1), "a plain charge is still refused");
        b.discharge(5);
        assert!(!b.charge(1), "at the limit it is refused");
        b.discharge(1);
        assert!(b.charge(1), "under it, granted");
    }
}
