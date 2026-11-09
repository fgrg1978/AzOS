// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A safety task's heartbeat as the hardware-watchdog feed judges it, and the
//! feed rule over the two heartbeats it watches.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

/// One heartbeat's state. Read and written from one CPU only (the feeder).
pub struct Liveness {
    last: AtomicU32,
    stalled: AtomicU32,
    advanced_at: AtomicU64,
}

impl Liveness {
    pub const fn new() -> Self {
        Self { last: AtomicU32::new(0), stalled: AtomicU32::new(0), advanced_at: AtomicU64::new(0) }
    }

    /// One feed decision for heartbeat `hb` at counter time `now`: alive while
    /// it has never run (0), has advanced since the last call, or has stood
    /// still for at most `limit` calls or `grace` counter ticks.
    #[inline]
    pub fn alive(&self, hb: u32, now: u64, limit: u32, grace: u64) -> bool {
        if hb != self.last.load(Relaxed) {
            self.last.store(hb, Relaxed);
            self.stalled.store(0, Relaxed);
            self.advanced_at.store(now, Relaxed);
            return true;
        }
        if hb == 0 {
            return true;
        }
        // Saturating: a wrapped count would fall back under `limit` and feed again.
        let stalled = self.stalled.load(Relaxed).saturating_add(1);
        self.stalled.store(stalled, Relaxed);
        stalled <= limit || now.saturating_sub(self.advanced_at.load(Relaxed)) <= grace
    }
}

/// The hardware watchdog is fed only while the control loop AND the
/// enforcement task advance: either one stalled lets the board reset.
pub struct Feed {
    pub control: Liveness,
    pub enforce: Liveness,
}

impl Feed {
    pub const fn new() -> Self {
        Self { control: Liveness::new(), enforce: Liveness::new() }
    }

    /// Timer ISR, hart 0: whether to kick the hardware watchdog now.
    #[inline]
    pub fn kick(&self, control_hb: u32, enforce_hb: u32, now: u64, limit: u32, grace: u64) -> bool {
        let control = self.control.alive(control_hb, now, limit, grace);
        let enforce = self.enforce.alive(enforce_hb, now, limit, grace);
        control && enforce
    }
}
