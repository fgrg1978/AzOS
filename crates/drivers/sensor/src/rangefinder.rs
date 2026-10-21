// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Rangefinder drivers — ultrasonic (HC-SR04) and ToF (VL53L0X).
///
/// Phase M1: proximity sensors for obstacle avoidance.
/// In QEMU, returns simulated distances.
/// On real hardware:
/// - Ultrasonic: GPIO trigger + echo pulse timing
/// - ToF: I2C VL53L0X (time-of-flight laser)
///
/// Both sensors feed into the behavior engine L1 (avoid-obstacle)
/// without requiring the server.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

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
/// In QEMU, just stores count and sets ready flag.
/// On real hardware, would configure GPIO trigger/echo pins.
pub fn us_init(count: u8) {
    let count = if count > US_MAX as u8 { US_MAX as u8 } else { count };
    US_COUNT.store(count, Ordering::Relaxed);
    US_READY.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[RANGE] Ultrasonic: {} sensors initialized (simulated)", count);
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
/// In QEMU, just stores count.
/// On real hardware, would configure I2C and calibrate VL53L0X.
pub fn tof_init(count: u8) {
    let count = if count > TOF_MAX as u8 { TOF_MAX as u8 } else { count };
    TOF_COUNT.store(count, Ordering::Relaxed);
    TOF_READY.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[RANGE] ToF VL53L0X: {} sensors initialized (simulated)", count);
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
