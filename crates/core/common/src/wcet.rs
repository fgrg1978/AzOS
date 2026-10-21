// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! WCET (Worst-Case Execution Time) measurement infrastructure (F16).
//!
//! Provides cycle-accurate timing for critical code paths using the RISC-V
//! `rdcycle` instruction. Tracks min/max/avg execution time per annotated
//! function to enable determinism certification.
//!
//! Usage:
//!   wcet_begin(WCET_SLOT_PID_LOOP);
//!   // ... critical code ...
//!   wcet_end(WCET_SLOT_PID_LOOP);
//!
//!   let stats = wcet_stats(WCET_SLOT_PID_LOOP);

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of WCET measurement slots.
pub const WCET_MAX_SLOTS: usize = 16;

/// Named slot indices for critical paths.
pub const WCET_SLOT_PID_LOOP: usize = 0;
pub const WCET_SLOT_SENSOR_READ: usize = 1;
pub const WCET_SLOT_CONTEXT_SWITCH: usize = 2;
pub const WCET_SLOT_IRQ_HANDLER: usize = 3;
pub const WCET_SLOT_ACTUATOR_WRITE: usize = 4;
pub const WCET_SLOT_TCP_HANDLE: usize = 5;
pub const WCET_SLOT_ML_INFERENCE: usize = 6;
pub const WCET_SLOT_DMA_TRANSFER: usize = 7;
pub const WCET_SLOT_BEHAVIOR_TICK: usize = 8;
pub const WCET_SLOT_FLIGHT_CTRL: usize = 9;

/// Slot names for reporting.
pub const WCET_SLOT_NAMES: [&str; WCET_MAX_SLOTS] = [
    "pid_loop", "sensor_read", "context_switch", "irq_handler",
    "actuator_write", "tcp_handle", "ml_inference", "dma_transfer",
    "behavior_tick", "flight_ctrl",
    "slot_10", "slot_11", "slot_12", "slot_13", "slot_14", "slot_15",
];

// ---------------------------------------------------------------------------
// Per-slot statistics
// ---------------------------------------------------------------------------

/// WCET statistics for one measurement slot.
pub struct WcetSlot {
    /// Minimum observed cycles.
    pub min_cycles: AtomicU64,
    /// Maximum observed cycles (WCET).
    pub max_cycles: AtomicU64,
    /// Total accumulated cycles (for average).
    pub total_cycles: AtomicU64,
    /// Number of measurements.
    pub count: AtomicU32,
    /// Start timestamp (per-CPU, set by wcet_begin).
    start: AtomicU64,
}

impl WcetSlot {
    pub const fn new() -> Self {
        Self {
            min_cycles: AtomicU64::new(u64::MAX),
            max_cycles: AtomicU64::new(0),
            total_cycles: AtomicU64::new(0),
            count: AtomicU32::new(0),
            start: AtomicU64::new(0),
        }
    }
}

/// Snapshot of WCET stats (for reporting).
#[derive(Clone, Copy, Default)]
pub struct WcetStats {
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub avg_cycles: u64,
    pub count: u32,
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static SLOTS: [WcetSlot; WCET_MAX_SLOTS] = {
    const EMPTY: WcetSlot = WcetSlot::new();
    [EMPTY; WCET_MAX_SLOTS]
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Begin timing a critical section.
#[inline(always)]
pub fn wcet_begin(slot: usize) {
    if slot >= WCET_MAX_SLOTS { return; }
    let cycles = rdcycle();
    SLOTS[slot].start.store(cycles, Ordering::Relaxed);
}

/// End timing a critical section and update statistics.
#[inline(always)]
pub fn wcet_end(slot: usize) {
    if slot >= WCET_MAX_SLOTS { return; }
    let end = rdcycle();
    let start = SLOTS[slot].start.load(Ordering::Relaxed);
    if start == 0 { return; } // wcet_begin was not called

    let elapsed = end.saturating_sub(start);

    // Update min
    let mut current_min = SLOTS[slot].min_cycles.load(Ordering::Relaxed);
    while elapsed < current_min {
        match SLOTS[slot].min_cycles.compare_exchange_weak(
            current_min, elapsed, Ordering::Relaxed, Ordering::Relaxed
        ) {
            Ok(_) => break,
            Err(v) => current_min = v,
        }
    }

    // Update max (WCET)
    let mut current_max = SLOTS[slot].max_cycles.load(Ordering::Relaxed);
    while elapsed > current_max {
        match SLOTS[slot].max_cycles.compare_exchange_weak(
            current_max, elapsed, Ordering::Relaxed, Ordering::Relaxed
        ) {
            Ok(_) => break,
            Err(v) => current_max = v,
        }
    }

    // Update total + count
    SLOTS[slot].total_cycles.fetch_add(elapsed, Ordering::Relaxed);
    SLOTS[slot].count.fetch_add(1, Ordering::Relaxed);
}

/// Get statistics for a slot.
pub fn wcet_stats(slot: usize) -> WcetStats {
    if slot >= WCET_MAX_SLOTS {
        return WcetStats::default();
    }
    let count = SLOTS[slot].count.load(Ordering::Relaxed);
    let total = SLOTS[slot].total_cycles.load(Ordering::Relaxed);
    let min_c = SLOTS[slot].min_cycles.load(Ordering::Relaxed);
    let max_c = SLOTS[slot].max_cycles.load(Ordering::Relaxed);

    WcetStats {
        min_cycles: if min_c == u64::MAX { 0 } else { min_c },
        max_cycles: max_c,
        avg_cycles: if count > 0 { total / count as u64 } else { 0 },
        count,
    }
}

/// Reset all WCET measurements.
pub fn wcet_reset() {
    for slot in &SLOTS {
        slot.min_cycles.store(u64::MAX, Ordering::Relaxed);
        slot.max_cycles.store(0, Ordering::Relaxed);
        slot.total_cycles.store(0, Ordering::Relaxed);
        slot.count.store(0, Ordering::Relaxed);
    }
}

/// Read the RISC-V cycle counter (rdcycle instruction).
#[inline(always)]
fn rdcycle() -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        let cycles: u64;
        unsafe { core::arch::asm!("rdcycle {}", out(reg) cycles, options(nomem, nostack)) };
        cycles
    }
    #[cfg(target_arch = "riscv32")]
    {
        // RV32: rdcycleh:rdcycle pair for 64-bit value
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdcycle {}", out(reg) lo, options(nomem, nostack));
            core::arch::asm!("rdcycleh {}", out(reg) hi, options(nomem, nostack));
        }
        ((hi as u64) << 32) | lo as u64
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "riscv32")))]
    { 0 }
}
