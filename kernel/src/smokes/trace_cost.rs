// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 15 (TRACE): what one tracepoint costs, measured at boot (cargo
//! feature `trace-cost-probe`, never in a shipped build).
//!
//! Runs on the boot CPU right after the tracer is installed, before any
//! secondary CPU or interrupt can run, so nothing else writes its ring or
//! steals its time. Four loops of `N` iterations over the syscall class's
//! exit tracepoint (`azos_trace::sys_exit`), each timed with the timebase:
//!
//! * empty: the loop alone, subtracted below;
//! * masked: the class compiled in and switched off at run time, eight
//!   tracepoints per iteration;
//! * recording: switched on, the ring drained between batches of half its
//!   size (the drain is outside the timed span), so every record takes the
//!   steady-state path a reader keeps the ring on;
//! * full: switched on into a full ring (the drop path, drop policy).
//!
//! Under `-icount shift=0` one instruction is one nanosecond of virtual
//! time, so the `ns` it prints ARE instructions; on a real core they are
//! nanoseconds. Printed with two decimals.

use azos_drv_sys::kprintln;
use azos_spsc::trace::{region_bytes, Pop, TraceConsumer, TraceGeometry};

const N: u32 = 1 << 14;

fn ns(ticks: u64, hz: u64) -> u64 {
    (ticks as u128 * 1_000_000_000 / hz as u128) as u64
}

/// Hundredths of a nanosecond per iteration of `total` over `count`, the
/// loop's own share removed.
fn per(total_ns: u64, empty_ns: u64, count: u32) -> u64 {
    total_ns.saturating_sub(empty_ns * count as u64 / N as u64) * 100 / count as u64
}

pub(crate) fn trace_cost_probe(hz: u64) {
    let Some((base, ncpu, entries)) = azos_trace::region() else {
        kprintln!("[TRACE-COST] no tracer (KTRACE off)");
        return;
    };
    if !azos_limits::KTRACE_CLASS_SYSCALL || azos_trace::OVERWRITE {
        kprintln!("[TRACE-COST] needs KTRACE_CLASS_SYSCALL and the drop policy");
        return;
    }
    let now = azos_arch::cpu::now_ticks;
    let cpu = azos_arch::cpu::hart_id() as u32;
    let Some(g) = TraceGeometry::from_header(base, region_bytes(ncpu, entries)) else { return };
    let mut c = TraceConsumer::new(base, &g, cpu);
    let drain = |c: &mut TraceConsumer| {
        while let Pop::Rec(_) | Pop::Lost(_) = c.pop() {}
        c.release();
    };
    let prev = azos_ipc::trace::set_mask(0);

    // The loop alone: an empty `asm!` that takes the counter, so the loop
    // is kept and nothing else is emitted (a `black_box` would add a store,
    // and a load in the loops that pass it on).
    let t = now();
    for i in 0..N {
        // SAFETY: emits no instruction.
        unsafe { core::arch::asm!("/* {0} */", in(reg) i as usize, options(nomem, nostack, preserves_flags)) };
    }
    let empty = ns(now() - t, hz);

    // Eight tracepoints per iteration (eight sites): the loop's own
    // shape moves by an instruction from one build to the next, which
    // matters against a one-instruction tracepoint, so it is amortised.
    let t = now();
    for i in 0..N {
        azos_trace::sys_exit(i, 7, 0);
        azos_trace::sys_exit(i, 7, 1);
        azos_trace::sys_exit(i, 7, 2);
        azos_trace::sys_exit(i, 7, 3);
        azos_trace::sys_exit(i, 7, 4);
        azos_trace::sys_exit(i, 7, 5);
        azos_trace::sys_exit(i, 7, 6);
        azos_trace::sys_exit(i, 7, 7);
    }
    let masked8 = ns(now() - t, hz);

    azos_ipc::trace::set_mask(1 << azos_abi::trace::TRACE_CLASS_SYSCALL);
    drain(&mut c);
    let half = entries / 2;
    let (mut rec, mut done) = (0u64, 0u32);
    while done < N {
        let t = now();
        for i in 0..half {
            azos_trace::sys_exit(i, 7, 0);
        }
        rec += ns(now() - t, hz);
        done += half;
        drain(&mut c);
    }
    // Fill the ring, then time the drop path.
    for i in 0..entries {
        azos_trace::sys_exit(i, 7, 0);
    }
    let t = now();
    for i in 0..N {
        azos_trace::sys_exit(i, 7, 0);
    }
    let full = ns(now() - t, hz);
    drain(&mut c);
    azos_ipc::trace::set_mask(prev);

    let m = masked8.saturating_sub(empty) * 100 / (8 * N as u64);
    let (r, f) = (per(rec, empty, done), per(full, empty, N));
    kprintln!(
        "[TRACE-COST] cpu{} N={} masked={}.{:02} recording={}.{:02} full-drop={}.{:02} ns per tracepoint (= instructions under -icount shift=0)",
        cpu, N, m / 100, m % 100, r / 100, r % 100, f / 100, f % 100
    );
}
