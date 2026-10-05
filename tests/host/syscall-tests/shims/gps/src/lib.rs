// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_gps`, used only by `tests/host/syscall-tests`.
//! GPS hardware is not one of this crate's three test targets; the one
//! function is `todo!()`. Fields match the real `GpsPosition` because
//! `handlers.rs` destructures them (`pos.lat_deg7`, `.lon_deg7`, `.alt_mm`,
//! `.fix`, `.sats`).

pub struct GpsPosition {
    pub lat_deg7: i32,
    pub lon_deg7: i32,
    pub alt_mm: i32,
    pub hdop: u16,
    pub fix: u8,
    pub sats: u8,
}

pub fn gps_read() -> Option<GpsPosition> {
    todo!("gps stand-in: not reached by any test in this crate")
}

pub struct StampedFix {
    pub pos: GpsPosition,
    pub acq: u64,
    pub synthetic: bool,
}

pub fn gps_read_stamped() -> Option<StampedFix> {
    todo!("gps stand-in: not reached by any test in this crate")
}
