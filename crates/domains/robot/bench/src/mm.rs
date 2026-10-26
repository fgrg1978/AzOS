// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Memory-management subsystem microbenchmarks.
//!
//! Today: vDSO timing reads.  Will grow to cover heap alloc/free,
//! mmap path, PMP region updates as those primitives stabilise.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_mm::kheap;

/// `azos_drv_sys::timebase::now()` — bare mtime read.  This is the timing-resolution
/// floor: every bench above this is measuring genuine compute.
pub fn bench_get_time(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        // Read into a black-hole-ish local to prevent the optimiser from
        // eliding the call entirely.  Since timebase::now has side
        // effects (CSR read), the optimiser usually keeps it, but be
        // defensive with the volatile compiler_fence pattern.
        let t = azos_drv_sys::timebase::now();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(t);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `read_cycles()` itself — the rdcycle CSR read.  Floor for any
/// cycle-based measurement; subtract from other benches to estimate the
/// pure operation cost.
pub fn bench_read_cycles(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        let c = read_cycles();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(c);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `kheap::used()` — lock the kernel heap + read the used-bytes counter.
/// Measures the lock-acquire + single-field-read fast path (the cost any
/// allocator-accounting query pays).
pub fn bench_kheap_used(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(kheap::used());
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `kheap::free()` — same lock + read, free-bytes counter.
pub fn bench_kheap_free(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(kheap::free());
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `kheap::size()` — total-bytes counter.  Trio with used/free isolates the
/// lock cost (identical work) from any field-specific divergence.
pub fn bench_kheap_size(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(kheap::size());
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("mm.get_time",     &best_of(|| bench_get_time(iters)));     n += 1;
    report("mm.read_cycles",  &best_of(|| bench_read_cycles(iters)));  n += 1;
    report("mm.kheap_used",   &best_of(|| bench_kheap_used(iters)));   n += 1;
    report("mm.kheap_free",   &best_of(|| bench_kheap_free(iters)));   n += 1;
    report("mm.kheap_size",   &best_of(|| bench_kheap_size(iters)));   n += 1;
    n
}
