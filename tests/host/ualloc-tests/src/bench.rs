// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The micro-benchmark (host only; `cargo test --release bench -- --ignored
//! --nocapture`): alloc+free pairs per size, 64 live chunks cycled, against
//! the host's own allocator. `general` is the SECURITY general posture of
//! the Kconfig (no quarantine, no poison, deterministic placement; the
//! checksum, the table lookups and the guards stay); `hardened` has the
//! quarantine, poison and random placement on. The engine runs over the model, whose `map` is
//! the host's `alloc_zeroed`, so the numbers are the engine's own cost plus
//! one host `mmap`-ish call per block, not AzOS system-call latency.

use crate::model::*;
use azos_ualloc::engine::{Config, Heap};
use std::alloc::{GlobalAlloc, Layout, System};
use std::time::Instant;

const LIVE: usize = 64;

fn engine_ns(cfg: Config, size: usize, pairs: usize) -> f64 {
    let mut model = Model::new(Some(42));
    model.release = true;
    let mut h: Big = Heap::new(model, cfg);
    let mut buf = [core::ptr::null_mut::<u8>(); LIVE];
    let t = Instant::now();
    for _ in 0..pairs / LIVE {
        for b in buf.iter_mut() {
            *b = std::hint::black_box(h.alloc(size, 8));
        }
        for b in buf.iter() {
            h.free(*b, Some(size));
        }
    }
    t.elapsed().as_nanos() as f64 / (pairs / LIVE * LIVE) as f64
}

fn system_ns(size: usize, pairs: usize) -> f64 {
    let l = Layout::from_size_align(size.max(1), 8).unwrap();
    let mut buf = [core::ptr::null_mut::<u8>(); LIVE];
    let t = Instant::now();
    for _ in 0..pairs / LIVE {
        for b in buf.iter_mut() {
            // SAFETY: non-zero size.
            *b = std::hint::black_box(unsafe { System.alloc(l) });
        }
        for b in buf.iter() {
            // SAFETY: the pointer and layout `alloc` took.
            unsafe { System.dealloc(*b, l) };
        }
    }
    t.elapsed().as_nanos() as f64 / (pairs / LIVE * LIVE) as f64
}

#[test]
#[ignore]
fn bench() {
    let general = Config { quarantine_bytes: 0, block_bytes: 32 * 1024, randomize: false, poison: false, guard: true, seed_required: false };
    let hard = Config { quarantine_bytes: 64 * 1024, block_bytes: 32 * 1024, randomize: true, poison: true, guard: true, seed_required: false };
    println!("ns per alloc+free pair, {LIVE} chunks live, release build, this host");
    println!("{:>7} {:>14} {:>16} {:>16} {:>8}", "size", "ualloc general", "ualloc hardened", "host System", "hard/gen");
    for size in [16usize, 64, 256, 1024, 2032, 8192] {
        let pairs = if size > 2032 { 64_000 } else { 2_000_000 };
        // One warm run, then the measured one.
        engine_ns(general, size, pairs / 10);
        let (a, b, s) = (engine_ns(general, size, pairs), engine_ns(hard, size, pairs), system_ns(size, pairs));
        println!("{size:>7} {a:>14.1} {b:>16.1} {s:>16.1} {:>7.2}x", b / a);
    }
}
