// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Skill Resource Profiles (R01).
///
/// Each skill (motion primitive) carries a `SkillProfile` that declares its
/// expected worst-case resource consumption.  The arbiter uses profiles to:
///
/// 1. **Admission control** — reject skills whose requirements exceed current
///    resource budget (battery, CPU load, actuator bandwidth).
/// 2. **Priority boosting** — promote deadline-critical skills in the scheduler.
/// 3. **Telemetry** — report per-skill resource usage to the brain server.
///
/// ## Design
/// Profiles are static (`&'static SkillProfile`) — computed once per skill type
/// and stored in a registry table indexed by `SkillId`.  No heap allocation.
///
/// Budget tracking uses `AtomicU32` so the timer ISR can decrement battery
/// budget without taking a mutex.

use core::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered skills.
pub const MAX_SKILLS: usize = 32;

/// Budget units for CPU load (0-1000 = 0.0%-100.0%, 1 unit = 0.1%).
pub const CPU_BUDGET_TOTAL: u32 = 1000;

/// Budget units for battery (mWh × 10, e.g. 10_000 = 1000 mWh = 1 Wh).
pub const BATTERY_BUDGET_UNITS: u32 = 100_000; // 10 Wh default budget

/// Maximum CPU load a skill may claim (prevents starvation).
pub const SKILL_MAX_CPU_UNITS: u32 = 500; // 50%

/// Skill identifiers (matches AzOSRobotBrain's skill catalog).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SkillId {
    Idle          = 0,
    MoveForward   = 1,
    MoveBackward  = 2,
    TurnLeft      = 3,
    TurnRight     = 4,
    Stop          = 5,
    Spin          = 6,
    FollowLine    = 7,
    ObstacleAvoid = 8,
    Dock          = 9,
    TakeOff       = 10,
    Land          = 11,
    HoverHold     = 12,
    CameraCapture = 13,
    LidarScan     = 14,
    MapUpdate     = 15,
    Navigate      = 16,
    Unknown       = 255,
}

impl SkillId {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0  => Self::Idle,
            1  => Self::MoveForward,
            2  => Self::MoveBackward,
            3  => Self::TurnLeft,
            4  => Self::TurnRight,
            5  => Self::Stop,
            6  => Self::Spin,
            7  => Self::FollowLine,
            8  => Self::ObstacleAvoid,
            9  => Self::Dock,
            10 => Self::TakeOff,
            11 => Self::Land,
            12 => Self::HoverHold,
            13 => Self::CameraCapture,
            14 => Self::LidarScan,
            15 => Self::MapUpdate,
            16 => Self::Navigate,
            _  => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Profile definition
// ---------------------------------------------------------------------------

/// Resource requirements for a single skill.
#[derive(Clone, Copy)]
pub struct SkillProfile {
    /// Human-readable name (for shell/telemetry).
    pub name: &'static str,
    /// Estimated CPU load in units (0-1000; 1 unit = 0.1%).
    pub cpu_units: u32,
    /// Estimated peak power draw in milliwatts.
    pub power_mw: u32,
    /// Whether this skill drives actuators (motors/ESCs).
    pub uses_actuators: bool,
    /// Whether this skill uses the camera subsystem.
    pub uses_camera: bool,
    /// Whether this skill uses the LiDAR subsystem.
    pub uses_lidar: bool,
    /// Whether this skill requires network access (brain link).
    pub uses_network: bool,
    /// Minimum battery SOC (%) required to start (0 = no requirement).
    pub min_battery_pct: u8,
    /// Scheduler priority boost while skill is active (0 = no boost).
    pub priority_boost: i8,
    /// Estimated worst-case execution time in microseconds.
    pub wcet_us: u32,
}

impl SkillProfile {
    pub const fn default_profile(name: &'static str) -> Self {
        SkillProfile {
            name,
            cpu_units: 50, // 5%
            power_mw: 500,
            uses_actuators: false,
            uses_camera: false,
            uses_lidar: false,
            uses_network: false,
            min_battery_pct: 0,
            priority_boost: 0,
            wcet_us: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// Static profile table
// ---------------------------------------------------------------------------

/// Well-known skill profiles.  Indexed by `SkillId as usize`.
pub static SKILL_PROFILES: &[SkillProfile] = &[
    // Idle (0)
    SkillProfile { name: "idle", cpu_units: 5, power_mw: 50,
        uses_actuators: false, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 0, priority_boost: 0, wcet_us: 100 },
    // MoveForward (1)
    SkillProfile { name: "move_forward", cpu_units: 80, power_mw: 2500,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 5, priority_boost: 1, wcet_us: 2000 },
    // MoveBackward (2)
    SkillProfile { name: "move_backward", cpu_units: 80, power_mw: 2500,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 5, priority_boost: 1, wcet_us: 2000 },
    // TurnLeft (3)
    SkillProfile { name: "turn_left", cpu_units: 60, power_mw: 1800,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 5, priority_boost: 1, wcet_us: 1500 },
    // TurnRight (4)
    SkillProfile { name: "turn_right", cpu_units: 60, power_mw: 1800,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 5, priority_boost: 1, wcet_us: 1500 },
    // Stop (5)
    SkillProfile { name: "stop", cpu_units: 20, power_mw: 100,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 0, priority_boost: 2, wcet_us: 500 },
    // Spin (6)
    SkillProfile { name: "spin", cpu_units: 70, power_mw: 2000,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 5, priority_boost: 0, wcet_us: 1500 },
    // FollowLine (7)
    SkillProfile { name: "follow_line", cpu_units: 150, power_mw: 3000,
        uses_actuators: true, uses_camera: true, uses_lidar: false, uses_network: false,
        min_battery_pct: 10, priority_boost: 1, wcet_us: 5000 },
    // ObstacleAvoid (8)
    SkillProfile { name: "obstacle_avoid", cpu_units: 200, power_mw: 3500,
        uses_actuators: true, uses_camera: false, uses_lidar: true, uses_network: false,
        min_battery_pct: 10, priority_boost: 2, wcet_us: 8000 },
    // Dock (9)
    SkillProfile { name: "dock", cpu_units: 180, power_mw: 2800,
        uses_actuators: true, uses_camera: true, uses_lidar: false, uses_network: true,
        min_battery_pct: 3, priority_boost: 2, wcet_us: 10000 },
    // TakeOff (10)
    SkillProfile { name: "take_off", cpu_units: 300, power_mw: 8000,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 20, priority_boost: 3, wcet_us: 5000 },
    // Land (11)
    SkillProfile { name: "land", cpu_units: 250, power_mw: 6000,
        uses_actuators: true, uses_camera: false, uses_lidar: true, uses_network: false,
        min_battery_pct: 5, priority_boost: 3, wcet_us: 5000 },
    // HoverHold (12)
    SkillProfile { name: "hover_hold", cpu_units: 200, power_mw: 7000,
        uses_actuators: true, uses_camera: false, uses_lidar: false, uses_network: false,
        min_battery_pct: 15, priority_boost: 2, wcet_us: 3000 },
    // CameraCapture (13)
    SkillProfile { name: "camera_capture", cpu_units: 300, power_mw: 2000,
        uses_actuators: false, uses_camera: true, uses_lidar: false, uses_network: true,
        min_battery_pct: 5, priority_boost: 0, wcet_us: 30000 },
    // LidarScan (14)
    SkillProfile { name: "lidar_scan", cpu_units: 200, power_mw: 1500,
        uses_actuators: false, uses_camera: false, uses_lidar: true, uses_network: false,
        min_battery_pct: 5, priority_boost: 0, wcet_us: 20000 },
    // MapUpdate (15)
    SkillProfile { name: "map_update", cpu_units: 400, power_mw: 2500,
        uses_actuators: false, uses_camera: false, uses_lidar: true, uses_network: false,
        min_battery_pct: 10, priority_boost: 0, wcet_us: 50000 },
    // Navigate (16)
    SkillProfile { name: "navigate", cpu_units: 350, power_mw: 4000,
        uses_actuators: true, uses_camera: false, uses_lidar: true, uses_network: true,
        min_battery_pct: 15, priority_boost: 1, wcet_us: 30000 },
];

// ---------------------------------------------------------------------------
// Runtime budget tracker
// ---------------------------------------------------------------------------

/// Current consumed CPU budget (sum of active skills' cpu_units).
static ACTIVE_CPU_UNITS: AtomicU32 = AtomicU32::new(0);

/// Current battery level in percent (0-100). Set by sensor task.
static BATTERY_PCT: AtomicU32 = AtomicU32::new(100);

/// Update battery level (called from sensor task).
pub fn skill_set_battery_pct(pct: u8) {
    BATTERY_PCT.store(pct as u32, Ordering::Relaxed);
}

/// Get current battery level.
pub fn skill_battery_pct() -> u8 {
    BATTERY_PCT.load(Ordering::Relaxed) as u8
}

/// Admission check: returns true if `skill_id` may run given current budgets.
pub fn skill_admit(skill_id: SkillId) -> bool {
    let idx = skill_id as usize;
    if idx >= SKILL_PROFILES.len() { return false; }
    let profile = &SKILL_PROFILES[idx];

    // Battery check
    let battery = BATTERY_PCT.load(Ordering::Relaxed) as u8;
    if battery < profile.min_battery_pct { return false; }

    // CPU budget check
    let current_cpu = ACTIVE_CPU_UNITS.load(Ordering::Relaxed);
    if current_cpu + profile.cpu_units > CPU_BUDGET_TOTAL { return false; }

    true
}

/// Claim the CPU budget for a skill when it starts executing.
pub fn skill_start(skill_id: SkillId) {
    let idx = skill_id as usize;
    if idx >= SKILL_PROFILES.len() { return; }
    let cpu = SKILL_PROFILES[idx].cpu_units;
    ACTIVE_CPU_UNITS.fetch_add(cpu, Ordering::Relaxed);
}

/// Release the CPU budget for a skill when it finishes.
pub fn skill_end(skill_id: SkillId) {
    let idx = skill_id as usize;
    if idx >= SKILL_PROFILES.len() { return; }
    let cpu = SKILL_PROFILES[idx].cpu_units;
    // Saturating sub to avoid wrapping on unexpected double-end.
    let prev = ACTIVE_CPU_UNITS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(cpu))
    });
    let _ = prev;
}

/// Lookup a profile by skill ID.
pub fn skill_profile(skill_id: SkillId) -> Option<&'static SkillProfile> {
    let idx = skill_id as usize;
    SKILL_PROFILES.get(idx)
}

/// Print skill budget status.
pub fn skill_budget_info() {
    let cpu = ACTIVE_CPU_UNITS.load(Ordering::Relaxed);
    let bat = BATTERY_PCT.load(Ordering::Relaxed);
    azos_drv_sys::kprintln!("[SKILL] CPU budget: {}/{} units | Battery: {}%",
        cpu, CPU_BUDGET_TOTAL, bat);
}
