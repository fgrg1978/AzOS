// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPC subsystem microbenchmarks.
//!
//! All benches:
//! - Create their own state (pipe, port, …) so they don't depend on
//!   the kernel's runtime topology.
//! - Tear down state at the end (a pipe's region released, etc.) so repeated
//!   `bench all` invocations don't leak slots.
//! - Use a tight loop with ONE pair of `read_cycles()` calls around the
//!   loop (not per-iter) — TCG rdcycle reads are themselves expensive,
//!   per-iter timing would dominate the measurement.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_ipc::{kpipe, port};

/// Pipe write+read round-trip on the same pipe.  Per iter: 1 byte
/// written then read back through the byte ring in the pipe's region (the
/// kernel's own calls on it, `azos_ipc::kpipe`).
pub fn bench_pipe_write_read(iters: u64) -> BenchResult {
    let tid = azos_sched::current_proc_tid();
    let Ok(cap) = kpipe::create(tid) else { return BenchResult::from_total(0, 0, 0) };
    let Ok(r) = azos_ipc::cap_store::get(tid, cap, azos_ipc::cap::CapPerms::READ) else {
        return BenchResult::from_total(0, 0, 0);
    };
    let Ok(pipe) = kpipe::KPipe::open(r) else { return BenchResult::from_total(0, 0, 0) };
    let byte_out = [0xC3u8];
    let mut byte_in = [0u8];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = pipe.write(&byte_out, true);
        let _ = pipe.read(&mut byte_in, true);
    }
    let end = read_cycles();

    drop(pipe);
    let _ = azos_ipc::cap_store::with_table(tid, |t| azos_ipc::memobj::memobj_release_cap(tid, t, cap));
    BenchResult::from_total(start, end, iters)
}

/// `kpipe::create` + release — region allocation cost.
pub fn bench_pipe_create_destroy(iters: u64) -> BenchResult {
    let tid = azos_sched::current_proc_tid();
    let start = read_cycles();
    for _ in 0..iters {
        if let Ok(cap) = kpipe::create(tid) {
            let _ = azos_ipc::cap_store::with_table(tid, |t| azos_ipc::memobj::memobj_release_cap(tid, t, cap));
        }
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Port poll path — port_create + queue + poll round trip.
///
/// Note: real port traffic comes from drivers (IRQ → port_queue_event),
/// here we exercise the queue/poll mechanics in isolation.
pub fn bench_port_create_destroy(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        // Owner tid 0 = current task; safe in this kernel-side bench.
        if let Some(pid) = port::port_create(0) {
            port::port_destroy(pid);
        }
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `port_poll` on empty port — measures the empty-queue fast path.
pub fn bench_port_poll_empty(iters: u64) -> BenchResult {
    let pid = match port::port_create(0) {
        Some(p) => p,
        None    => return BenchResult::from_total(0, 0, 0),
    };

    let start = read_cycles();
    for _ in 0..iters {
        let _ = port::port_poll(pid);
    }
    let end = read_cycles();

    port::port_destroy(pid);
    BenchResult::from_total(start, end, iters)
}

/// Run every bench in this subsystem, report each.  Returns count of
/// `[BENCH-RES]` lines emitted.
pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("ipc.pipe_write_read",       &best_of(|| bench_pipe_write_read(iters)));       n += 1;
    report("ipc.pipe_create_destroy",   &best_of(|| bench_pipe_create_destroy(iters)));   n += 1;
    report("ipc.port_create_destroy",   &best_of(|| bench_port_create_destroy(iters)));   n += 1;
    report("ipc.port_poll_empty",       &best_of(|| bench_port_poll_empty(iters)));       n += 1;
    n
}
