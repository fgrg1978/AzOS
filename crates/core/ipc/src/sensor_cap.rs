// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Cap<Sensor>` typed wrappers — RFC-0003, closing the P2 gap.
//!
//! ## The gap this closes
//!
//! `crates/core/ipc/src/cap_seed.rs` listed `Sensor` first among the kinds with no
//! typed minter ("no `sensor_grant_cap`, phase P2"), and it was the largest
//! remaining one: `sys_sensor_read` has **fifteen ring-3 call sites** across
//! `userspace/`, more than every other hardware family combined, and none of
//! them could move off the untyped path because there was no typed sensor
//! syscall, no minter and no marker type reachable from a grant.
//!
//! ## The authority, unchanged
//!
//! `sys_sensor_read(sensor_type, buf, len)` (retired in RFC-0040 gap 1) gated
//! on `Sensor(sensor_type)` with READ. The resource is the sensor
//! TYPE — `SENSOR_TYPE_IMU` = 0 through `SENSOR_TYPE_POWER` = 9 — not an
//! instance id, so a `Cap<Sensor>(3)` names "the rangefinder", singular,
//! exactly as the untyped handle does. The typed form asks for the same
//! permission on the same object; what changes is that the type comes from
//! the capability instead of from `a0`.
//!
//! ## Why the read itself is not here
//!
//! `sys_sensor_read`'s body dispatches into `azos_imu`, `azos_gps`,
//! `azos_drv_sensor::{lidar, csi, ina219, rangefinder}` and the odometry
//! channels. `crates/core/ipc` depends on none of those and should not start:
//! parsing a capability and reading a sensor are different layers. So this
//! module holds the mint and the dereference — both dependency-free and
//! host-testable — and the dispatch stays in
//! `crates/core/syscall/src/handlers.rs`, which already reaches all of them. Same
//! split, and the same reason, as `drvreg_cap.rs`.

use crate::cap::{targets, Cap, CapError, CapPerms, CapTable};

/// Highest `sensor_type` the kernel dispatches, from `handlers.rs`'s
/// `SENSOR_TYPE_*` block (`POWER` = 9).
///
/// Restated rather than imported for the dependency reason in the module doc.
/// `tests/host/syscall-tests` joins the two by reading `handlers.rs` as text, the
/// same way `tests/host/drivers-tests` joins `motor_bridge_op_needs_pair` to the
/// `MOTOR_OP_*` constants — so this cannot drift silently.
pub const SENSOR_TYPE_MAX: u32 = 9;

/// Topology-loader entry: grant `tid` a `Cap<Sensor>` for `sensor_type`.
///
/// Refuses a type the kernel does not dispatch. Unlike `drvreg_cap`, where the
/// registry itself accepts any `u32` and a range check here would have been a
/// second and stricter rule, `sys_sensor_read`'s `match` has a `_ => -1` arm:
/// an out-of-range type is already rejected downstream, so refusing at mint
/// makes the capability table describe only grantable objects rather than
/// inventing a bound.
pub fn sensor_grant_cap(
    tid: u32,
    sensor_type: u32,
    perms: CapPerms,
) -> Option<Cap<targets::Sensor>> {
    if sensor_type > SENSOR_TYPE_MAX {
        return None;
    }
    crate::cap_store::grant::<targets::Sensor>(tid, perms, sensor_type)
}

/// Dereference a `Cap<Sensor>` to the sensor type it names.
///
/// `READ`, matching the untyped path's `cap_check(.., false)` and the
/// autorun seed's `HandlePerms::RO`. A sensor read is a read; demanding WRITE
/// would make the typed form stricter than the call it mirrors, which is the
/// authority change this migration exists not to make.
pub fn sensor_type_of(
    table: &CapTable,
    cap: Cap<targets::Sensor>,
) -> Result<u32, CapError> {
    let t = table.get(cap, CapPerms::READ)?;
    // A cap whose resource is out of range can only come from a table written
    // before `sensor_grant_cap`'s check existed, or from corruption. Fail
    // closed rather than passing it to the dispatch's `_` arm, so the two
    // cannot disagree about what a valid sensor type is.
    if t > SENSOR_TYPE_MAX {
        return Err(CapError::WrongKind);
    }
    Ok(t)
}
