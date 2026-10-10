// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Capability subsystem microbenchmarks — RFC-0003 typed cap table.
//!
//! `CapTable::get` is on the hot path of every cap-checked syscall (W3+),
//! so its per-dereference cost is a first-class number.  All benches build
//! their own `CapTable` on the stack so they don't touch the live kernel
//! topology.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_ipc::cap::{CapTable, CapPerms};
use azos_ipc::cap::targets::Channel;

/// Cap dereference + verify — `CapTable::get` (the `#[wcet(20_us)]` path).
/// Slot index range check + occupancy + generation + kind + perms.  The
/// success path touches all five checks, so this is the worst-case verify.
pub fn bench_cap_get_verify(iters: u64) -> BenchResult {
    let t = CapTable::empty();
    let cap = match t.grant::<Channel>(CapPerms::RW, 42) {
        Some(c) => c,
        None    => return BenchResult::from_total(0, 0, 0),
    };

    let start = read_cycles();
    for _ in 0..iters {
        let _ = t.get(cap, CapPerms::READ);
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Cap allocation churn — `grant` then `revoke` on the same slot.  Each
/// iter frees slot 0 again so `grant`'s free-slot scan stays O(1); measures
/// the pack/unpack + generation-bump cost, not the table scan.
pub fn bench_cap_grant_revoke(iters: u64) -> BenchResult {
    let t = CapTable::empty();

    let start = read_cycles();
    for _ in 0..iters {
        if let Some(c) = t.grant::<Channel>(CapPerms::RW, 1) {
            t.revoke(c);
        }
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `CapTable::occupied` — full O(MAX_CAPS_PER_TASK) occupancy scan.  Used by
/// quota enforcement; cost scales with table size, not occupancy.
pub fn bench_cap_occupied(iters: u64) -> BenchResult {
    let t = CapTable::empty();
    let _ = t.grant::<Channel>(CapPerms::RW, 1);

    let start = read_cycles();
    for _ in 0..iters {
        let _ = t.occupied();
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("cap.get_verify",   &best_of(|| bench_cap_get_verify(iters)));   n += 1;
    report("cap.grant_revoke", &best_of(|| bench_cap_grant_revoke(iters))); n += 1;
    report("cap.occupied",     &best_of(|| bench_cap_occupied(iters)));     n += 1;
    n
}
