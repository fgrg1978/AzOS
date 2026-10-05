// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel tracing — ring buffer of recent events (AQ8).
//!
//! Lightweight event tracing for post-mortem debugging.
//! Records last N events in a circular buffer. On crash, dump to UART.
//!
//! Each event is 32 bytes — buffer of 512 events = 16 KiB in BSS.

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum events in the trace buffer.
pub const TRACE_BUF_SIZE: usize = 512;
/// Size of one event.
pub const TRACE_EVENT_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------

pub const TRACE_IRQ: u8 = 1;
pub const TRACE_SCHED: u8 = 2;
pub const TRACE_SYSCALL: u8 = 3;
pub const TRACE_DRIVER: u8 = 4;
pub const TRACE_MM: u8 = 5;
pub const TRACE_FAULT: u8 = 6;
pub const TRACE_IPC: u8 = 7;
pub const TRACE_USER: u8 = 8;
/// Wave 13: a signal delivered to a Linux task: `[tid, signo, sender, action]`
/// (action 0 discarded, 1 handler, 2 terminated).
pub const TRACE_SIGNAL: u8 = 9;

// ---------------------------------------------------------------------------
// Event structure
// ---------------------------------------------------------------------------

/// A single trace event — 32 bytes, fits in half a cache line.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TraceEvent {
    pub timestamp: u64,      // CLINT ticks
    pub category: u8,        // TRACE_IRQ, TRACE_SCHED, etc.
    pub cpu: u8,             // hart ID
    pub _pad: [u8; 2],
    pub data: [u32; 4],      // 16 bytes of category-specific data
}

impl TraceEvent {
    pub const fn empty() -> Self {
        Self {
            timestamp: 0,
            category: 0,
            cpu: 0,
            _pad: [0; 2],
            data: [0; 4],
        }
    }
}

// Compile-time size check
const _: () = assert!(core::mem::size_of::<TraceEvent>() == TRACE_EVENT_SIZE);

// ---------------------------------------------------------------------------
// Global trace buffer
// ---------------------------------------------------------------------------

static mut TRACE_BUF: [TraceEvent; TRACE_BUF_SIZE] = {
    const EMPTY: TraceEvent = TraceEvent::empty();
    [EMPTY; TRACE_BUF_SIZE]
};

static TRACE_HEAD: AtomicU32 = AtomicU32::new(0);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enable tracing.
pub fn trace_start() {
    TRACE_ENABLED.store(true, Ordering::Release);
}

/// Disable tracing.
pub fn trace_stop() {
    TRACE_ENABLED.store(false, Ordering::Release);
}

/// Check if tracing is enabled.
pub fn trace_is_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Relaxed)
}

/// Record a trace event. Very lightweight (~10ns overhead).
#[inline]
pub fn trace_event(category: u8, d0: u32, d1: u32, d2: u32, d3: u32) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) { return; }

    let timestamp = azos_drv_sys::timebase::now();
    let cpu = azos_arch::cpu::hart_id() as u8;
    let idx = TRACE_HEAD.fetch_add(1, Ordering::Relaxed) as usize % TRACE_BUF_SIZE;

    unsafe {
        TRACE_BUF[idx] = TraceEvent {
            timestamp,
            category,
            cpu,
            _pad: [0; 2],
            data: [d0, d1, d2, d3],
        };
    }
}

/// Convenience: trace an IRQ event.
#[inline]
pub fn trace_irq(irq: u32, duration_us: u32) {
    trace_event(TRACE_IRQ, irq, duration_us, 0, 0);
}

/// Convenience: trace a context switch.
#[inline]
pub fn trace_sched(from_tid: u32, to_tid: u32) {
    trace_event(TRACE_SCHED, from_tid, to_tid, 0, 0);
}

/// Convenience: trace a syscall.
#[inline]
pub fn trace_syscall(num: u32, result: i32) {
    trace_event(TRACE_SYSCALL, num, result as u32, 0, 0);
}

/// Convenience: trace a page fault.
#[inline]
pub fn trace_fault(addr: u32, cause: u32, task_tid: u32) {
    trace_event(TRACE_FAULT, addr, cause, task_tid, 0);
}

/// Dump the last N events to the UART (for crash debugging).
pub fn trace_dump(last_n: usize) {
    // `TRACE_HEAD` counts every event ever recorded (it is only reduced
    // modulo the ring when indexing), so it is also the total: a second
    // counter would cost every event another atomic add for the same number.
    let total = TRACE_HEAD.load(Ordering::Acquire);
    let head = total as usize;
    let count = last_n.min(TRACE_BUF_SIZE).min(total as usize);

    azos_drv_sys::kconsoleln!("[TRACE] Dumping last {} events (total={})", count, total);

    let cat_name = |c: u8| -> &'static str {
        match c {
            TRACE_IRQ     => "IRQ",
            TRACE_SCHED   => "SCHED",
            TRACE_SYSCALL => "SYSCALL",
            TRACE_DRIVER  => "DRIVER",
            TRACE_MM      => "MM",
            TRACE_FAULT   => "FAULT",
            TRACE_IPC     => "IPC",
            TRACE_USER    => "USER",
            _             => "?",
        }
    };

    for i in 0..count {
        let idx = (head + TRACE_BUF_SIZE - count + i) % TRACE_BUF_SIZE;
        let ev = unsafe { &TRACE_BUF[idx] };
        if ev.timestamp == 0 { continue; }
        azos_drv_sys::kconsoleln!(
            "  [{:>3}] t={} cpu={} {:>7} data=[{:#x}, {:#x}, {:#x}, {:#x}]",
            i, ev.timestamp, ev.cpu, cat_name(ev.category),
            ev.data[0], ev.data[1], ev.data[2], ev.data[3],
        );
    }
}

/// Get total events recorded.
pub fn trace_total() -> u32 {
    TRACE_HEAD.load(Ordering::Relaxed)
}
