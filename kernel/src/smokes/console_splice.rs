// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 / kernel console splice smoke (`console-splice-smoke`).

use crate::*;

// ── console-splice-smoke: the ring-3 / kernel console splice, reproduced ──
//
// Gate 192b's `ipc: census counters zero` went red with the property holding:
// `[IPCTEST] ALL PA[SCHED-DBG]   ASKS-SCHED ...` — a timer-ISR `kprintln!`
// landed between two pieces of a ring-3 line. This reproduces the three ways a
// kernel line can reach the wire while a ring-3 write is in flight:
//
//   * another hart's task-context `kprintln!` (`splice-k`, hart 2),
//   * the timer ISR's own `kprintln!` (`console_splice_isr_print`, every tick,
//     both ISAs, on whichever hart takes it), and
//   * with `-smp 1`, a same-hart preemption between two pieces.
//
// The ring-3 side is `splice-w` calling `uart::console_write_ring3` — the
// function `sys_write`'s fd 1/2 arm calls (crates/core/syscall/src/handlers.rs),
// so no new ELF, seccomp row or topology entry is needed. Every writer line is
// `[SPLICEU] n=NNNN <62 fixed bytes> END` (84 bytes with its newline); the
// host counts how many came out exactly that. See
// tools/console_splice_count.sh.
#[cfg(feature = "console-splice-smoke")]
static SPLICE_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Set by `splice-k` once it has printed its first line. The writer does not
/// start until then: a run in which the kernel printer never got its hart
/// during the window (seen once, `-smp 4`) proves nothing about splicing.
#[cfg(feature = "console-splice-smoke")]
static SPLICE_K_RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "console-splice-smoke")]
static SPLICE_ISR_LINES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// ISR lines whose `kprintln!` has returned (deferred or on the wire), so the
/// writer can wait for in-flight ones before it counts.
#[cfg(feature = "console-splice-smoke")]
static SPLICE_ISR_PRINTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// `splice-k`'s line count, published once it has stopped (`u32::MAX` =
/// still running).
#[cfg(feature = "console-splice-smoke")]
static SPLICE_K_DONE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// Ring-3 lines `splice-w` writes.
#[cfg(feature = "console-splice-smoke")]
const SPLICE_LINES: u32 = 2000;

/// How long the splice writer waits, in ms of counter time, before it starts
/// (boot printing), and at most for each of the other tasks it waits on. The
/// first was 20,000 yields and the others unbounded yield loops.
#[cfg(feature = "console-splice-smoke")]
const SPLICE_BOOT_SETTLE_MS: u64 = 2_000;
#[cfg(feature = "console-splice-smoke")]
const SPLICE_WAIT_MS: u64 = 30_000;

#[cfg(feature = "console-splice-smoke")]
pub(crate) fn console_splice_writer_task(_arg: usize) {
    use core::sync::atomic::Ordering;
    use azos_syscall::sleep::{sleep_ms, wait_until_ms};
    // Let boot finish printing, so the count is not mixed with boot lines.
    sleep_ms(SPLICE_BOOT_SETTLE_MS);
    kprintln!("[SPLICE] START lines={}", SPLICE_LINES);
    azos_drv_sys::uart::ring3_probe::reset();
    azos_drv_sys::uart::lock_probe::reset();
    SPLICE_ACTIVE.store(true, Ordering::SeqCst);
    if !wait_until_ms(SPLICE_WAIT_MS, 1, || SPLICE_K_RUNNING.load(Ordering::SeqCst)) {
        SPLICE_ACTIVE.store(false, Ordering::SeqCst);
        kprintln!("[SPLICE] FAIL splice-k never printed in {} ms", SPLICE_WAIT_MS);
        return;
    }
    let mut line = *b"[SPLICEU] n=0000 abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ END\n";
    for n in 0..SPLICE_LINES {
        let mut v = n;
        for k in (12..16).rev() {
            line[k] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        azos_drv_sys::uart::console_write_ring3(&line);
    }
    SPLICE_ACTIVE.store(false, Ordering::SeqCst);
    // Every kernel line of the window must be out (or reported dropped)
    // before the counts are read: the kprinter's last line, and any ISR line
    // already past its `SPLICE_ACTIVE` check.
    if !wait_until_ms(SPLICE_WAIT_MS, 1, || SPLICE_K_DONE.load(Ordering::SeqCst) != u32::MAX) {
        kprintln!("[SPLICE] FAIL splice-k did not stop in {} ms", SPLICE_WAIT_MS);
        return;
    }
    let k_lines = SPLICE_K_DONE.load(Ordering::SeqCst);
    if !wait_until_ms(SPLICE_WAIT_MS, 1, || {
        SPLICE_ISR_PRINTED.load(Ordering::SeqCst) == SPLICE_ISR_LINES.load(Ordering::SeqCst)
    }) {
        kprintln!("[SPLICE] FAIL an ISR line was still in flight after {} ms", SPLICE_WAIT_MS);
        return;
    }
    let (max_hold, holds, total_hold, max_call, calls, total_call) =
        azos_drv_sys::uart::ring3_probe::read();
    let (lk_max, lk_holds, lk_total, lk_bytes, lk_idle) = azos_drv_sys::uart::lock_probe::read();
    let (hwm, dropped_lines, deferred) = azos_drv_sys::uart::console_defer_stats();
    let (tx_async, tx_hwm, tx_irqs) = azos_drv_sys::uart::console_tx_stats();
    kprintln!("[SPLICE] DONE lines={} klines={} isr_lines={} defer_hwm={} defer_dropped_lines={} deferred_bytes={} ring3 holds={} max_hold_ticks={} total_hold_ticks={} calls={} max_call_ticks={} total_call_ticks={} uart_lock holds={} max_masked_ticks={} total_masked_ticks={} max_masked_wire_bytes={} idle_drains={} tick_hz={} tx_async={} tx_hwm={} tx_irqs={} max_masked_fill_bytes={}",
        SPLICE_LINES, k_lines, SPLICE_ISR_LINES.load(Ordering::Relaxed),
        hwm, dropped_lines, deferred,
        holds, max_hold, total_hold, calls, max_call, total_call,
        lk_holds, lk_max, lk_total, lk_bytes, lk_idle, azos_drv_sys::timebase::TIMER_FREQ,
        tx_async as u8, tx_hwm, tx_irqs, azos_drv_sys::uart::lock_probe::max_fill());
}

#[cfg(feature = "console-splice-smoke")]
pub(crate) fn console_splice_kprint_task(_arg: usize) {
    use core::sync::atomic::Ordering;
    // Bounded by the writer's settle plus its own wait budget: the writer sets
    // the flag once, after `SPLICE_BOOT_SETTLE_MS`.
    if !azos_syscall::sleep::wait_until_ms(SPLICE_BOOT_SETTLE_MS + SPLICE_WAIT_MS, 1, || {
        SPLICE_ACTIVE.load(Ordering::SeqCst)
    }) {
        kprintln!("[SPLICE] FAIL splice-k: the writer never started");
        SPLICE_K_DONE.store(0, Ordering::SeqCst);
        return;
    }
    let mut n: u32 = 0;
    while SPLICE_ACTIVE.load(Ordering::SeqCst) {
        kprintln!("[SPLICEK] k={:05} ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvutsrqponmlkjihgfedcba KEND", n);
        n = n.wrapping_add(1);
        SPLICE_K_RUNNING.store(true, Ordering::SeqCst);
        // Paced by time, one ≈ 100-byte line per ms: with the ISR lines that
        // is well under what the QEMU UART drains (≈ 265 B/ms, from
        // latbench's 241 µs / 64 B). While ring 3 owns the console a
        // `kprintln!` is a memcpy, so an unpaced loop floods the buffer and
        // measures only the drop policy — which it passes too (2026-09-28,
        // 200 µs pacing, ≈ 2x the wire for 60 s: 2000/2000 ring-3 lines,
        // every kernel line on the wire whole, every missing one covered by a
        // `[CONSOLE] dropped` report), but a gate row should see no drops.
        let until = azos_drv_sys::timebase::now()
            + azos_drv_sys::timebase::TIMER_FREQ / 1_000;
        while azos_drv_sys::timebase::now() < until { core::hint::spin_loop(); }
    }
    SPLICE_K_DONE.store(n, Ordering::SeqCst);
}

/// Called from the timer interrupt on both ISAs while the smoke runs.
#[cfg(feature = "console-splice-smoke")]
pub(crate) fn console_splice_isr_print() {
    use core::sync::atomic::Ordering;
    if SPLICE_ACTIVE.load(Ordering::Relaxed) {
        let n = SPLICE_ISR_LINES.fetch_add(1, Ordering::SeqCst);
        kprintln!("[SPLICEI] isr={:05} interrupt-context kernel line ------------------------------ IEND", n);
        SPLICE_ISR_PRINTED.fetch_add(1, Ordering::SeqCst);
    }
}
