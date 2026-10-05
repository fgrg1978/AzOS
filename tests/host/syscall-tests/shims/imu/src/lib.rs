// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_imu`, used only by `tests/host/syscall-tests`.
//! IMU hardware is not one of this crate's three test targets; the one
//! function is `todo!()`. Field names/types match the real `ImuData` because
//! `handlers.rs` destructures them (`imu.accel_mg`, `imu.gyro_mdps`).

pub struct ImuData {
    pub accel_mg: [i32; 3],
    pub gyro_mdps: [i32; 3],
    pub temp_cdeg: i32,
}

pub fn imu_read_scaled() -> Option<ImuData> {
    todo!("imu stand-in: not reached by any test in this crate")
}

pub fn imu_read_scaled_stamped() -> Option<(ImuData, u64)> {
    todo!("imu stand-in: not reached by any test in this crate")
}
