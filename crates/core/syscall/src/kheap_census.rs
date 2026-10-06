// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kheap-census` printer (vsbench diagnostic, never shipped): the counters
//! live in `azos_mm::kheap_census`, which cannot print; this module tags each
//! syscall and, once a second of guest time, prints the cumulative tables as
//! `[KHEAP-*]` lines. The first dump also runs a micro-benchmark of the
//! allocator itself (`azos_mm::kheap::bench_raw`), census bookkeeping
//! excluded, on the heap as the running system has shaped it.

use azos_mm::kheap_census as c;
use core::sync::atomic::Ordering::Relaxed;

#[inline(always)]
pub fn enter(nr: u64) { c::set_tag(nr); }

pub fn leave() {
    c::clear_tag();
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    if c::due(f / 20) { dump(); }
}

static BENCHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn dump() {
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    let ns = |t: u64, n: u64| if n == 0 { 0 } else { t.saturating_mul(1_000_000_000 / f) / n };
    let en = c::EMPTY_N.load(Relaxed);
    azos_drv_sys::kprintln!(
        "[KHEAP-CENSUS] refused={} in_isr={} big_align={} live={} peak={} empty_ns={} used={} size={}",
        c::REFUSED.load(Relaxed), c::IN_ISR.load(Relaxed), c::BIG_ALIGN.load(Relaxed),
        c::LIVE.load(Relaxed), c::PEAK.load(Relaxed), ns(c::EMPTY_T.load(Relaxed), en),
        azos_mm::kheap::used(), azos_mm::kheap::size(),
    );
    for b in 0..c::NB {
        let (an, fnn) = (c::A_N[b].load(Relaxed), c::F_N[b].load(Relaxed));
        if an == 0 && fnn == 0 { continue; }
        azos_drv_sys::kprintln!(
            "[KHEAP-BUCKET] le={} allocs={} alloc_ns={} frees={} free_ns={}",
            8usize << b, an, ns(c::A_T[b].load(Relaxed), an), fnn, ns(c::F_T[b].load(Relaxed), fnn),
        );
    }
    for t in 0..c::NT {
        let row: [u32; c::NB] = core::array::from_fn(|b| c::CNT[t][b].load(Relaxed));
        if row.iter().all(|&v| v == 0) { continue; }
        azos_drv_sys::kprintln!(
            "[KHEAP-TAG] nr={} {} {} {} {} {} {} {} {} {} {} {} {}",
            if t == c::NT - 1 { -1 } else { t as i64 },
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11],
        );
    }
    let mut i = 0;
    while i < c::FINE.len() {
        let mut line = [(0usize, 0u32); 8];
        let mut k = 0;
        while i < c::FINE.len() && k < 8 {
            let v = c::FINE[i].load(Relaxed);
            if v != 0 { line[k] = (i * 8, v); k += 1; }
            i += 1;
        }
        if k == 0 { continue; }
        azos_drv_sys::kprintln!(
            "[KHEAP-FINE] {}:{} {}:{} {}:{} {}:{} {}:{} {}:{} {}:{} {}:{}",
            line[0].0, line[0].1, line[1].0, line[1].1, line[2].0, line[2].1, line[3].0, line[3].1,
            line[4].0, line[4].1, line[5].0, line[5].1, line[6].0, line[6].1, line[7].0, line[7].1,
        );
    }
    if !BENCHED.swap(true, Relaxed) { bench(); }
}

/// Alloc/free cost per size, census excluded: `ROUNDS` rounds of `K` allocs
/// then `K` frees (in reverse), timed as two intervals per round. Run twice:
/// on the heap as it is, and with `HOLES` small holes punched below the
/// test's blocks (a fragmented first-fit heap walks past them).
fn bench() {
    bench_pass("as-is");
    const HOLES: usize = 256;
    let mut keep = [(core::ptr::null_mut::<u8>(), 0usize); 2 * HOLES];
    for (i, k) in keep.iter_mut().enumerate() {
        // 24..=264 bytes, the spread the abitest census saw.
        let s = 24 + (i * 40) % 248;
        let lay = core::alloc::Layout::from_size_align(s, 8).unwrap();
        *k = (azos_mm::kheap::bench_raw_alloc(lay), s);
    }
    for (i, k) in keep.iter_mut().enumerate() {
        if i % 2 == 1 && !k.0.is_null() {
            azos_mm::kheap::bench_raw_free(k.0, core::alloc::Layout::from_size_align(k.1, 8).unwrap());
            k.0 = core::ptr::null_mut();
        }
    }
    bench_pass("holes=256");
    for k in keep.iter() {
        if !k.0.is_null() {
            azos_mm::kheap::bench_raw_free(k.0, core::alloc::Layout::from_size_align(k.1, 8).unwrap());
        }
    }
}

fn bench_pass(kind: &str) {
    const K: usize = 64;
    const ROUNDS: u64 = 32;
    const SIZES: [usize; 16] = [8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048, 4096, 8192];
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    for &s in SIZES.iter() {
        let lay = core::alloc::Layout::from_size_align(s, 8).unwrap();
        let mut ptrs = [core::ptr::null_mut::<u8>(); K];
        let (mut ta, mut tf) = (0u64, 0u64);
        for _ in 0..ROUNDS {
            let t0 = c::now();
            for p in ptrs.iter_mut() { *p = azos_mm::kheap::bench_raw_alloc(lay); }
            let t1 = c::now();
            for p in ptrs.iter().rev() {
                if !p.is_null() { azos_mm::kheap::bench_raw_free(*p, lay); }
            }
            let t2 = c::now();
            ta += t1 - t0;
            tf += t2 - t1;
        }
        let n = ROUNDS * K as u64;
        // An alloc and its free back to back: the steady state of a path
        // that allocates one object per call (a magazine hit with the cache).
        let t0 = c::now();
        for _ in 0..n {
            let p = azos_mm::kheap::bench_raw_alloc(lay);
            if !p.is_null() { azos_mm::kheap::bench_raw_free(core::hint::black_box(p), lay); }
        }
        let tp = c::now() - t0;
        azos_drv_sys::kprintln!(
            "[KHEAP-BENCH] heap={} size={} alloc_ns={} free_ns={} pair_ns={} slab={} cached={}",
            kind, s, ta * (1_000_000_000 / f) / n, tf * (1_000_000_000 / f) / n,
            tp * (1_000_000_000 / f) / n, azos_limits::KHEAP_SLAB, azos_mm::kheap::slab_cached(),
        );
    }
}
