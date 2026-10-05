// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// World State Shared Region (R03).
///
/// A single global struct updated by the sensor/AHRS task and readable by ALL
/// other tasks without locking.  Uses a seqlock for consistency.
///
/// ## Design
/// - **One writer** (sensor-ahrs task): updates world state at 100 Hz.
///   **As designed, not as shipped**: nothing in `kernel/` calls this
///   module's writer (or any of its readers) — the only caller outside this
///   file is `tests/host/world-state-tests`, its own dedicated host-test crate
///   — confirmed 2026-09-26, `grep -rn "world_state::" kernel/src crates
///   --include='*.rs' | grep -v world_state.rs`. The seqlock and the
///   update path both work; there is no producer wired to the sensor-ahrs
///   task yet.
/// - **Many readers** (behavior, nav, brain protocol, shell): read any time.
/// - **Seqlock**: writer increments `seq` to odd before write, even after.
///   Readers retry if `seq` is odd or changed between read start and end.
///
/// This is the AzOS equivalent of a "world model" — a consistent snapshot
/// of reality that every component can query in O(1) without IPC.
///
/// Fields use primitive types (i32/u32/i16) to avoid atomics on the data
/// payload; the seqlock provides the consistency boundary.

use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::{critical_section, PreemptGuard};

// ---------------------------------------------------------------------------
// World state structure
// ---------------------------------------------------------------------------

/// Full robot world state snapshot.
///
/// Updated at 100 Hz by sensor-ahrs task; readable by all other tasks.
/// Layout is `repr(C)` so the vDSO-style seqlock works correctly.
#[repr(C)]
pub struct WorldState {
    // ── Seqlock ────────────────────────────────────────────────────────────
    /// Sequence counter: even = stable, odd = write in progress.
    pub seq: AtomicU32,
    pub _pad: u32,

    // ── Attitude (from AHRS) ────────────────────────────────────────────────
    /// Roll  in millidegrees (e.g. 45000 = 45°).
    pub roll_mdeg:  i32,
    /// Pitch in millidegrees.
    pub pitch_mdeg: i32,
    /// Yaw   in millidegrees (0-359999).
    pub yaw_mdeg:   i32,

    // ── Angular rates (from IMU) ───────────────────────────────────────────
    /// Gyro X in mdeg/s.
    pub gyro_x_mdps: i32,
    /// Gyro Y in mdeg/s.
    pub gyro_y_mdps: i32,
    /// Gyro Z in mdeg/s.
    pub gyro_z_mdps: i32,

    // ── Linear acceleration (from IMU) ────────────────────────────────────
    /// Accel X in milli-g (e.g. 1000 = 1g).
    pub accel_x_mg: i32,
    pub accel_y_mg: i32,
    pub accel_z_mg: i32,

    // ── GPS position ─────────────────────────────────────────────────────
    /// Latitude  in degrees × 10^7.
    pub lat_deg7:  i32,
    /// Longitude in degrees × 10^7.
    pub lon_deg7:  i32,
    /// Altitude above MSL in millimetres.
    pub alt_mm:    i32,
    /// Ground speed in cm/s.
    pub gspeed_cms: u16,
    /// Course over ground in centidegrees (0-35999).
    pub cog_cdeg:   u16,
    /// Number of GPS satellites locked.
    pub gps_sats:  u8,
    /// GPS fix quality (0=no fix, 1=GPS, 2=DGPS).
    pub gps_fix:   u8,

    // ── Barometer ─────────────────────────────────────────────────────────
    /// Pressure in Pa × 100 (e.g. 101325 = 1013.25 hPa).
    pub pressure_pa_c: u32,
    /// Temperature in millidegrees Celsius.
    pub temp_mdeg_c: i32,

    // ── Odometry / encoders ───────────────────────────────────────────────
    /// Left wheel speed in mm/s.
    pub wheel_l_mms: i16,
    /// Right wheel speed in mm/s.
    pub wheel_r_mms: i16,
    /// Total distance travelled in mm.
    pub odom_mm:     u32,

    // ── Range sensors ─────────────────────────────────────────────────────
    /// Front rangefinder in mm (u16::MAX = no reading).
    pub range_front_mm: u16,
    /// Left rangefinder in mm.
    pub range_left_mm:  u16,
    /// Right rangefinder in mm.
    pub range_right_mm: u16,
    /// Rear rangefinder in mm.
    pub range_rear_mm:  u16,

    // ── Battery ───────────────────────────────────────────────────────────
    /// Battery voltage in millivolts.
    pub battery_mv: u16,
    /// Battery State of Charge in percent (0-100).
    pub battery_pct: u8,

    // ── Timestamp ─────────────────────────────────────────────────────────
    /// CLINT ticks at last update.
    pub timestamp_ticks: u64,
}

impl WorldState {
    pub const fn new() -> Self {
        WorldState {
            seq: AtomicU32::new(0),
            _pad: 0,
            roll_mdeg: 0, pitch_mdeg: 0, yaw_mdeg: 0,
            gyro_x_mdps: 0, gyro_y_mdps: 0, gyro_z_mdps: 0,
            accel_x_mg: 0, accel_y_mg: 0, accel_z_mg: 1000,
            lat_deg7: 0, lon_deg7: 0, alt_mm: 0,
            gspeed_cms: 0, cog_cdeg: 0, gps_sats: 0, gps_fix: 0,
            pressure_pa_c: 10_132_500, temp_mdeg_c: 20_000,
            wheel_l_mms: 0, wheel_r_mms: 0, odom_mm: 0,
            range_front_mm: u16::MAX, range_left_mm: u16::MAX,
            range_right_mm: u16::MAX, range_rear_mm: u16::MAX,
            battery_mv: 12_000, battery_pct: 100,
            timestamp_ticks: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

/// The global world state (updated by sensor-ahrs task).
///
/// Readers should use `world_state_read()` which handles the seqlock.
pub static WORLD_STATE: WorldState = WorldState::new();

// ---------------------------------------------------------------------------
// Seqlock write helpers (sensor-ahrs task only)
// ---------------------------------------------------------------------------

/// RAII guard for a `WORLD_STATE` seqlock write epoch (K-C29).
///
/// This hand-rolled seqlock — `world_state_write_begin`/`_end` bumping
/// `WORLD_STATE.seq` odd-then-even by hand — never got the preempt-guard
/// treatment `crates/core/sync/src/seqlock.rs`'s `SeqLock` did. See that file's
/// `SeqLock::write()` doc for the exact hazard, which applies here
/// unchanged: a reader spins while `seq` is odd, and if the writer is
/// preempted mid-epoch by a HIGHER-PRIORITY reader on the SAME hart, that
/// reader spins forever under this kernel's strict, non-aging priority
/// dispatch — the identical hazard `SpinLock` was fixed for (K-C29).
///
/// **Not reachable today.** `world_state_write_begin`/`_end` (and
/// `world_state_read`) have zero callers anywhere in this tree — the
/// sensor-ahrs task (`kernel/src/tasks/sensors.rs::sensor_ahrs_task`) publishes
/// through `CH_IMU`/`CH_BARO`/`CH_ATTITUDE` channels instead, never through
/// `WORLD_STATE`. The fix is applied anyway, mechanically, so the hazard
/// does not silently reappear the moment a writer is wired up to this type —
/// see the doc comment at the top of this file for what would make it live
/// (a task calling `world_state_write_begin()` while another task calls
/// `world_state_read()` on the same hart).
pub struct WorldStateWriteGuard {
    odd_seq: u32,
    /// Declared LAST — same reason as `SeqLockWriteGuard` in
    /// `crates/core/sync/src/seqlock.rs`: `Drop` runs field drops in declaration
    /// order, so the sequence returns to even and only THEN is preemption
    /// re-enabled. The other order would leave a window where a reader can
    /// still see an odd counter with the writer preemptible.
    _preempt: PreemptGuard,
}

impl Drop for WorldStateWriteGuard {
    fn drop(&mut self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        WORLD_STATE.seq.store(self.odd_seq.wrapping_add(1), Ordering::Release);
    }
}

/// Open a seqlock write epoch. The caller writes `WORLD_STATE`'s fields
/// (via its own raw-pointer route — this module does not hand out a
/// `DerefMut`, since nothing today calls this to say what that route should
/// look like) and then drops the returned guard to close the epoch; there is
/// deliberately no separate `world_state_write_end()` any more, so a
/// forgotten close is a compile error instead of a silently-open epoch.
///
/// Preemption is disabled here, BEFORE `seq` goes odd — see
/// `WorldStateWriteGuard`'s doc for why.
#[inline]
#[must_use = "the write epoch stays open, and preemption stays disabled, until \
              this guard is dropped"]
pub fn world_state_write_begin() -> WorldStateWriteGuard {
    let _preempt = critical_section();
    let seq = WORLD_STATE.seq.load(Ordering::Relaxed);
    let odd = seq.wrapping_add(1);
    WORLD_STATE.seq.store(odd, Ordering::Release);
    core::sync::atomic::fence(Ordering::SeqCst);
    WorldStateWriteGuard { odd_seq: odd, _preempt }
}

// ---------------------------------------------------------------------------
// Seqlock read (all other tasks)
// ---------------------------------------------------------------------------

/// A consistent snapshot of the world state.
///
/// Copied from `WORLD_STATE` inside a seqlock critical section.
#[derive(Clone, Copy, Default)]
pub struct WorldSnapshot {
    pub roll_mdeg:   i32,
    pub pitch_mdeg:  i32,
    pub yaw_mdeg:    i32,
    pub gyro_x_mdps: i32,
    pub gyro_y_mdps: i32,
    pub gyro_z_mdps: i32,
    pub accel_x_mg:  i32,
    pub accel_y_mg:  i32,
    pub accel_z_mg:  i32,
    pub lat_deg7:    i32,
    pub lon_deg7:    i32,
    pub alt_mm:      i32,
    pub gspeed_cms:  u16,
    pub cog_cdeg:    u16,
    pub gps_sats:    u8,
    pub gps_fix:     u8,
    pub pressure_pa_c: u32,
    pub temp_mdeg_c:   i32,
    pub wheel_l_mms: i16,
    pub wheel_r_mms: i16,
    pub odom_mm:     u32,
    pub range_front_mm: u16,
    pub range_left_mm:  u16,
    pub range_right_mm: u16,
    pub range_rear_mm:  u16,
    pub battery_mv:  u16,
    pub battery_pct: u8,
    pub timestamp_ticks: u64,
}

/// Read a consistent snapshot of the world state.
///
/// Spins (very briefly, at most one sensor-ahrs period = 10 ms) if a write
/// is in progress.  Returns the snapshot once a stable read is achieved.
pub fn world_state_read() -> WorldSnapshot {
    loop {
        let seq1 = WORLD_STATE.seq.load(Ordering::Acquire);
        if seq1 & 1 != 0 {
            // Write in progress — spin
            core::hint::spin_loop();
            continue;
        }
        // Read all fields
        let ws = &WORLD_STATE;
        let snap = WorldSnapshot {
            roll_mdeg:   unsafe { core::ptr::read_volatile(&ws.roll_mdeg) },
            pitch_mdeg:  unsafe { core::ptr::read_volatile(&ws.pitch_mdeg) },
            yaw_mdeg:    unsafe { core::ptr::read_volatile(&ws.yaw_mdeg) },
            gyro_x_mdps: unsafe { core::ptr::read_volatile(&ws.gyro_x_mdps) },
            gyro_y_mdps: unsafe { core::ptr::read_volatile(&ws.gyro_y_mdps) },
            gyro_z_mdps: unsafe { core::ptr::read_volatile(&ws.gyro_z_mdps) },
            accel_x_mg:  unsafe { core::ptr::read_volatile(&ws.accel_x_mg) },
            accel_y_mg:  unsafe { core::ptr::read_volatile(&ws.accel_y_mg) },
            accel_z_mg:  unsafe { core::ptr::read_volatile(&ws.accel_z_mg) },
            lat_deg7:    unsafe { core::ptr::read_volatile(&ws.lat_deg7) },
            lon_deg7:    unsafe { core::ptr::read_volatile(&ws.lon_deg7) },
            alt_mm:      unsafe { core::ptr::read_volatile(&ws.alt_mm) },
            gspeed_cms:  unsafe { core::ptr::read_volatile(&ws.gspeed_cms) },
            cog_cdeg:    unsafe { core::ptr::read_volatile(&ws.cog_cdeg) },
            gps_sats:    unsafe { core::ptr::read_volatile(&ws.gps_sats) },
            gps_fix:     unsafe { core::ptr::read_volatile(&ws.gps_fix) },
            pressure_pa_c: unsafe { core::ptr::read_volatile(&ws.pressure_pa_c) },
            temp_mdeg_c:   unsafe { core::ptr::read_volatile(&ws.temp_mdeg_c) },
            wheel_l_mms: unsafe { core::ptr::read_volatile(&ws.wheel_l_mms) },
            wheel_r_mms: unsafe { core::ptr::read_volatile(&ws.wheel_r_mms) },
            odom_mm:     unsafe { core::ptr::read_volatile(&ws.odom_mm) },
            range_front_mm: unsafe { core::ptr::read_volatile(&ws.range_front_mm) },
            range_left_mm:  unsafe { core::ptr::read_volatile(&ws.range_left_mm) },
            range_right_mm: unsafe { core::ptr::read_volatile(&ws.range_right_mm) },
            range_rear_mm:  unsafe { core::ptr::read_volatile(&ws.range_rear_mm) },
            battery_mv:  unsafe { core::ptr::read_volatile(&ws.battery_mv) },
            battery_pct: unsafe { core::ptr::read_volatile(&ws.battery_pct) },
            timestamp_ticks: unsafe { core::ptr::read_volatile(&ws.timestamp_ticks) },
        };
        core::sync::atomic::fence(Ordering::Acquire);
        let seq2 = WORLD_STATE.seq.load(Ordering::Acquire);
        if seq1 == seq2 { return snap; }
        core::hint::spin_loop();
    }
}
