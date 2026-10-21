// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Frozen `#[repr(C)]` types crossing the user/kernel ABI boundary.
//!
//! All structures here are stable within a major series. Add fields only
//! at the end; never remove or reorder. Pad to natural alignment.

/// Sensor state snapshot, as returned by `SYS_SENSOR_READ`.
///
/// Layout chosen to match the kernel-side `domains/robot/behavior/src/types.rs`
/// `SensorState` so that the cross-crate copy is a `*src` deref.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct SensorState {
    /// Monotonic timestamp (microseconds since boot).
    pub timestamp_us: u64,
    /// Battery voltage in millivolts.
    pub battery_mv: u32,
    /// Battery state-of-charge in 1/100 of a percent (0..=10000).
    pub battery_soc_centipercent: u16,
    /// Bumper / contact switch bitmask. Bit `n` set ⇒ switch `n` triggered.
    pub bumpers: u16,
    /// Range to nearest forward obstacle in millimetres. `u32::MAX` ⇒
    /// no reading.
    pub range_front_mm: u32,
    /// Range to rear obstacle in millimetres. `u32::MAX` ⇒ no reading.
    pub range_rear_mm: u32,
    /// Current task TID for the safety supervisor (bookkeeping).
    pub safety_supervisor_tid: u32,
    /// Reserved for future extension. Must be zero.
    pub _reserved: [u32; 4],
}

/// Motor output snapshot, as accepted by `SYS_ROBOT_MOVE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct MotorOutput {
    /// Channel 0 raw value (signed, normalised −10000..=10000).
    pub ch0: i16,
    /// Channel 1.
    pub ch1: i16,
    /// Channel 2.
    pub ch2: i16,
    /// Channel 3.
    pub ch3: i16,
    /// Bit `n` ⇒ channel `n` is active. Inactive channels ignore their
    /// `chN` value.
    pub active_mask: u8,
    /// Pad to 4-byte alignment.
    pub _pad: [u8; 3],
}

/// Compact info block for `SYS_ROBOT_INFO`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct RobotInfo {
    /// Robot type discriminant (0=wheeled, 1=drone, 2=humanoid, 3=ackermann).
    pub robot_type: u8,
    /// Number of motor channels.
    pub motor_channels: u8,
    /// Number of sensor channels.
    pub sensor_channels: u8,
    /// Reserved.
    pub _pad: u8,
    /// Firmware ABI version (matches `ABI_VERSION` constant).
    pub abi_version: u32,
}

/// Safety profile snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct SafetyProfile {
    /// Maximum forward speed (millimetres per second).
    pub max_forward_speed_mmps: u32,
    /// Maximum rotation rate (milliradians per second).
    pub max_rotation_mrad_s: u32,
    /// Cliff sensor cutoff distance (millimetres).
    pub cliff_cutoff_mm: u32,
    /// Battery low cutoff (millivolts).
    pub battery_low_mv: u32,
    /// Geofence enabled.
    pub geofence_enabled: u8,
    /// ESTOP latched.
    pub estop_latched: u8,
    /// Reserved.
    pub _pad: [u8; 6],
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn sensor_state_size_is_stable() {
        // 8 + 4 + 2 + 2 + 4 + 4 + 4 + 16 = 44; round to 8-align ⇒ 48
        assert_eq!(size_of::<SensorState>(), 48);
    }

    #[test]
    fn motor_output_size_is_stable() {
        // 2*4 + 1 + 3 = 12
        assert_eq!(size_of::<MotorOutput>(), 12);
    }

    #[test]
    fn robot_info_size_is_stable() {
        assert_eq!(size_of::<RobotInfo>(), 8);
    }

    #[test]
    fn safety_profile_size_is_stable() {
        // 4*4 + 1 + 1 + 6 = 24
        assert_eq!(size_of::<SafetyProfile>(), 24);
    }
}
