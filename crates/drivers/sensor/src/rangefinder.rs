// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Rangefinder drivers — ultrasonic (HC-SR04) and ToF (VL53L0X).
///
/// Phase M1: proximity sensors for obstacle avoidance.
/// Under QEMU (`azos_drv_sys::ON_QEMU`), returns simulated distances.
/// There is no driver for the real sensors yet (ultrasonic: GPIO trigger +
/// echo pulse timing; ToF: I2C VL53L0X), so on a real board `us_init` and
/// `tof_init` refuse, with a `Rule::Rangefinder` record, and the sensors are
/// never ready: a read answers `None`, never a simulated distance, and obstacle
/// avoidance and the REFLEX daemon run without a rangefinder (the daemon refuses
/// to start).
///
/// Both sensors feed into the behavior engine L1 (avoid-obstacle)
/// without requiring the server.

use azos_decision::{Rule, Verdict};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

/// Record that `asked` sensors of `kind` were refused: `max` is the most the
/// driver would have taken.
fn record_refusal(kind: u32, asked: u8, max: usize) {
    if !cfg!(feature = "rangefinder-record-canary") {
        azos_decision::record(Rule::Rangefinder, Verdict::Refuse, kind, [asked as u64, max as u64, 0]);
    }
}

// ── Ultrasonic (HC-SR04) ────────────────────────────────────────────────────

/// Maximum number of ultrasonic sensors.
pub const US_MAX: usize = 4;

static US_READY: AtomicBool = AtomicBool::new(false);
static US_COUNT: AtomicU8 = AtomicU8::new(0);

/// Simulated distances in millimetres per sensor.
static US_DIST: [AtomicU16; US_MAX] = [
    AtomicU16::new(1500),  // front: 1.5m
    AtomicU16::new(800),   // right: 0.8m
    AtomicU16::new(2000),  // rear:  2.0m
    AtomicU16::new(800),   // left:  0.8m
];

/// Initialize ultrasonic sensor(s).
///
/// `count`: number of sensors (1-4).
/// In QEMU, just stores count and sets ready flag. `false` (nothing set up, a
/// record on the console) on a real board, which has no driver for it.
pub fn us_init(count: u8) -> bool {
    if !azos_drv_sys::ON_QEMU {
        azos_drv_sys::kwarn!("[RANGE] Ultrasonic: no driver for this board: not initialized, no simulated distances served");
        record_refusal(0, count, US_MAX);
        return false;
    }
    let count = if count > US_MAX as u8 { US_MAX as u8 } else { count };
    US_COUNT.store(count, Ordering::Relaxed);
    US_READY.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[RANGE] Ultrasonic: {} sensors initialized (simulated)", count);
    true
}

/// Read distance from ultrasonic sensor in millimetres.
///
/// Returns `None` if sensor not initialized or index out of range.
/// Valid range: 20-4000 mm (2 cm to 4 m).
pub fn us_read_mm(index: u8) -> Option<u32> {
    if !US_READY.load(Ordering::Acquire) { return None; }
    let idx = index as usize;
    if idx >= US_COUNT.load(Ordering::Relaxed) as usize { return None; }
    Some(US_DIST[idx].load(Ordering::Relaxed) as u32)
}

/// Set simulated ultrasonic distance (for testing).
pub fn us_set_distance(index: u8, mm: u16) {
    let idx = index as usize;
    if idx < US_MAX {
        US_DIST[idx].store(mm, Ordering::Relaxed);
    }
}

/// Get ultrasonic sensor count.
pub fn us_count() -> u8 {
    US_COUNT.load(Ordering::Relaxed)
}

// ── Time-of-Flight (VL53L0X) ───────────────────────────────────────────────

/// Maximum number of ToF sensors.
pub const TOF_MAX: usize = 2;

static TOF_READY: AtomicBool = AtomicBool::new(false);
static TOF_COUNT: AtomicU8 = AtomicU8::new(0);

/// Simulated ToF distances in millimetres.
static TOF_DIST: [AtomicU16; TOF_MAX] = [
    AtomicU16::new(1200),  // down-facing: 1.2m (altitude)
    AtomicU16::new(3000),  // forward-facing: 3.0m
];

/// VL53L0X default I2C address.
pub const VL53L0X_ADDR: u8 = 0x29;

/// Initialize ToF sensor(s).
///
/// `count`: number of sensors (1-2).
/// In QEMU, just stores count. `false` on a real board, as [`us_init`].
pub fn tof_init(count: u8) -> bool {
    if !azos_drv_sys::ON_QEMU {
        azos_drv_sys::kwarn!("[RANGE] ToF VL53L0X: no driver for this board: not initialized, no simulated distances served");
        record_refusal(1, count, TOF_MAX);
        return false;
    }
    let count = if count > TOF_MAX as u8 { TOF_MAX as u8 } else { count };
    TOF_COUNT.store(count, Ordering::Relaxed);
    TOF_READY.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[RANGE] ToF VL53L0X: {} sensors initialized (simulated)", count);
    true
}

/// Read distance from ToF sensor in millimetres.
///
/// Returns `None` if sensor not initialized or index out of range.
/// Valid range: 0-2000 mm (0 to 2 m for VL53L0X).
pub fn tof_read_mm(index: u8) -> Option<u16> {
    if !TOF_READY.load(Ordering::Acquire) { return None; }
    let idx = index as usize;
    if idx >= TOF_COUNT.load(Ordering::Relaxed) as usize { return None; }
    Some(TOF_DIST[idx].load(Ordering::Relaxed))
}

/// Set simulated ToF distance (for testing).
pub fn tof_set_distance(index: u8, mm: u16) {
    let idx = index as usize;
    if idx < TOF_MAX {
        TOF_DIST[idx].store(mm, Ordering::Relaxed);
    }
}

/// Get ToF sensor count.
pub fn tof_count() -> u8 {
    TOF_COUNT.load(Ordering::Relaxed)
}

// ── Combined info ───────────────────────────────────────────────────────────

/// Print rangefinder status.
pub fn range_info() {
    let us_n = US_COUNT.load(Ordering::Relaxed);
    let tof_n = TOF_COUNT.load(Ordering::Relaxed);

    if us_n > 0 {
        azos_drv_sys::kconsoleln!("[RANGE] Ultrasonic: {} sensors", us_n);
        for i in 0..us_n {
            if let Some(d) = us_read_mm(i) {
                azos_drv_sys::kconsoleln!("[RANGE]   US{}: {} mm", i, d);
            }
        }
    } else {
        azos_drv_sys::kconsoleln!("[RANGE] Ultrasonic: not initialized");
    }

    if tof_n > 0 {
        azos_drv_sys::kconsoleln!("[RANGE] ToF VL53L0X: {} sensors", tof_n);
        for i in 0..tof_n {
            if let Some(d) = tof_read_mm(i) {
                azos_drv_sys::kconsoleln!("[RANGE]   ToF{}: {} mm", i, d);
            }
        }
    } else {
        azos_drv_sys::kconsoleln!("[RANGE] ToF: not initialized");
    }
}
