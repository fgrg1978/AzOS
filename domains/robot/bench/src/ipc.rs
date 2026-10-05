// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPC subsystem microbenchmarks.
//!
//! All benches:
//! - Create their own state (channel, pipe, …) so they don't depend on
//!   the kernel's runtime topology.
//! - Tear down state at the end (`channel_destroy` etc.) so repeated
//!   `bench all` invocations don't leak slots.
//! - Use a tight loop with ONE pair of `read_cycles()` calls around the
//!   loop (not per-iter) — TCG rdcycle reads are themselves expensive,
//!   per-iter timing would dominate the measurement.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use azos_ipc::{channel, pipe, port, signal, lease};

/// Channel `channel_send` + `channel_recv` round-trip on the same channel.
///
/// Measures the cost of one send-then-recv on a freshly-created
/// channel.  Per iter: 1× send (8B payload), 1× recv into a 64B buffer.
pub fn bench_channel_send_recv(iters: u64) -> BenchResult {
    let ch = match channel::channel_create() {
        Some(c) => c,
        None    => return BenchResult::from_total(0, 0, 0),
    };
    let payload = [0xA5u8; 8];
    let mut buf  = [0u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        let _ = channel::channel_send(ch, &payload);
        let _ = channel::channel_recv(ch, &mut buf);
    }
    let end = read_cycles();

    channel::channel_destroy(ch);
    BenchResult::from_total(start, end, iters)
}

/// `channel_send` against an EMPTY-then-FULL channel boundary — measures
/// the path where the ring keeps draining so neither full nor empty
/// dominates.  Effectively: in-place send/recv pipeline.
pub fn bench_channel_full_send(iters: u64) -> BenchResult {
    let ch = match channel::channel_create() {
        Some(c) => c,
        None    => return BenchResult::from_total(0, 0, 0),
    };
    let payload = [0x5Au8; 8];
    let mut buf  = [0u8; 64];

    let start = read_cycles();
    for _ in 0..iters {
        // Send.  If the ring is at capacity, this returns -1 quickly.
        // Recv to drain.  Together they keep depth steady.
        let _ = channel::channel_send(ch, &payload);
        let _ = channel::channel_recv(ch, &mut buf);
    }
    let end = read_cycles();

    channel::channel_destroy(ch);
    BenchResult::from_total(start, end, iters)
}

/// Channel slot allocation cost — `channel_create` + `channel_destroy`.
pub fn bench_channel_create_destroy(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        if let Some(c) = channel::channel_create() {
            channel::channel_destroy(c);
        }
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Pipe write+read round-trip on the same pipe.  Per iter: 1 byte
/// written then read back through the kernel pipe buffer.
pub fn bench_pipe_write_read(iters: u64) -> BenchResult {
    let (rd, wr) = match pipe::pipe_create() {
        Some(pair) => pair,
        None       => return BenchResult::from_total(0, 0, 0),
    };
    let byte_out: u8 = 0xC3;
    let mut byte_in: u8 = 0;

    let start = read_cycles();
    for _ in 0..iters {
        let _ = pipe::pipe_write(wr, &byte_out as *const u8, 1);
        let _ = pipe::pipe_read(rd, &mut byte_in as *mut u8, 1);
    }
    let end = read_cycles();

    pipe::pipe_close_write(wr);
    pipe::pipe_close_read(rd);
    BenchResult::from_total(start, end, iters)
}

/// `pipe_create` + close both ends — slot allocation cost.
pub fn bench_pipe_create_destroy(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        if let Some((rd, wr)) = pipe::pipe_create() {
            pipe::pipe_close_write(wr);
            pipe::pipe_close_read(rd);
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

/// `signal_send` to current task.  Measures pending-bitmap update path.
/// signal_pending() drains afterwards so subsequent iters see fresh state.
pub fn bench_signal_send(iters: u64) -> BenchResult {
    // Use SIGUSR1 (typically signum 10) — catchable, no default kill
    // action that would terminate the bench task.  Quick range check:
    // pick the first valid catchable signum.
    let mut signum: u32 = 1;
    while signum < 32 && !(signal::signal_valid(signum) && signal::signal_catchable(signum)) {
        signum += 1;
    }
    if signum >= 32 { return BenchResult::from_total(0, 0, 0); }

    let start = read_cycles();
    for _ in 0..iters {
        // tid 0 = current task.
        let _ = signal::signal_send(0, signum);
        let _ = signal::signal_pending();
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `signal_pending` on empty mask — fast path.
pub fn bench_signal_pending(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        let _ = signal::signal_pending();
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// `lease_active_count` — read-only scan over the lease table.
/// Measures the per-slot iteration cost.
pub fn bench_lease_active_count(iters: u64) -> BenchResult {
    let start = read_cycles();
    for _ in 0..iters {
        let _ = lease::lease_active_count();
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

/// Run every bench in this subsystem, report each.  Returns count of
/// `[BENCH-RES]` lines emitted.
pub fn run(iters: u64) -> u32 {
    let mut n = 0u32;
    report("ipc.channel_send_recv",     &best_of(|| bench_channel_send_recv(iters)));     n += 1;
    report("ipc.channel_full_send",     &best_of(|| bench_channel_full_send(iters)));     n += 1;
    report("ipc.channel_create_destroy", &best_of(|| bench_channel_create_destroy(iters))); n += 1;
    report("ipc.pipe_write_read",       &best_of(|| bench_pipe_write_read(iters)));       n += 1;
    report("ipc.pipe_create_destroy",   &best_of(|| bench_pipe_create_destroy(iters)));   n += 1;
    report("ipc.port_create_destroy",   &best_of(|| bench_port_create_destroy(iters)));   n += 1;
    report("ipc.port_poll_empty",       &best_of(|| bench_port_poll_empty(iters)));       n += 1;
    report("ipc.signal_send",           &best_of(|| bench_signal_send(iters)));           n += 1;
    report("ipc.signal_pending",        &best_of(|| bench_signal_pending(iters)));        n += 1;
    report("ipc.lease_active_count",    &best_of(|| bench_lease_active_count(iters)));    n += 1;
    n
}
