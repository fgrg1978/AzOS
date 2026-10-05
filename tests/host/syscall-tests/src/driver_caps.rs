// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `cap_kind_for_driver` in `crates/core/syscall/src/handlers.rs`
// (target 2, ~line 2267).
//
// Its own doc says only four driver kinds have a `CapKind` analogue and the
// rest are denied by omission -- a fail-closed default carrying real
// weight: `drv_invoke_authorized` (the same file) treats `None` from this
// function as "deny userspace", so every kind not mapped here is
// unreachable from ring 3 through `SYS_DRV_INVOKE`, on purpose. The
// constants referenced below are the real ones from
// `azos_driver_server` (pulled in whole at
// `tests/host/syscall-tests/shims/driver_server`, not re-declared), so this
// enumerates the tree's actual driver-kind list rather than a copy of it
// that could drift.

use azos_driver_server::{
    DRV_KIND_ADC, DRV_KIND_CAN, DRV_KIND_CSI_CAM, DRV_KIND_DMA, DRV_KIND_GPIO,
    DRV_KIND_GPS, DRV_KIND_I2C, DRV_KIND_IMU, DRV_KIND_LIDAR, DRV_KIND_MOTOR_PID,
    DRV_KIND_NPU, DRV_KIND_PWM, DRV_KIND_SPI, DRV_KIND_UART, DRV_KIND_USB_XHCI,
    DRV_KIND_BUZZER, DRV_KIND_POWER_MON,
};
use azos_ipc::cap::CapKind;

/// Every `DRV_KIND_*` constant the tree declares, paired with the mapping
/// `cap_kind_for_driver` must produce for it. If `crates/drivers/driver_server`
/// gains a sixteenth kind, it belongs in this list too -- the point of
/// `all_declared_kinds_are_accounted_for` below is to make "I forgot to add
/// it here" visibly wrong (wrong count) rather than silently absent.
const ALL_KINDS: &[(u32, Option<CapKind>)] = &[
    (DRV_KIND_GPIO, Some(CapKind::Gpio)),
    (DRV_KIND_I2C, Some(CapKind::I2c)),
    (DRV_KIND_SPI, None),
    (DRV_KIND_UART, None),
    (DRV_KIND_PWM, Some(CapKind::Pwm)),
    (DRV_KIND_DMA, None),
    (DRV_KIND_CSI_CAM, None),
    (DRV_KIND_LIDAR, None),
    (DRV_KIND_MOTOR_PID, Some(CapKind::Motor)),
    (DRV_KIND_IMU, None),
    (DRV_KIND_GPS, None),
    (DRV_KIND_ADC, None),
    (DRV_KIND_NPU, None),
    (DRV_KIND_CAN, None),
    (DRV_KIND_USB_XHCI, None),
    // Served by ring-3 drivers; the kernel is their only client, so no
    // `SYS_DRV_INVOKE` path is opened to ring 3.
    (DRV_KIND_BUZZER, None),
    (DRV_KIND_POWER_MON, None),
];

/// The four kinds with a capability analogue return exactly that `CapKind`
/// -- the positive half of the mapping.
#[test]
fn the_four_capability_backed_kinds_map_to_their_cap_kind() {
    assert_eq!(cap_kind_for_driver(DRV_KIND_GPIO), Some(CapKind::Gpio));
    assert_eq!(cap_kind_for_driver(DRV_KIND_I2C), Some(CapKind::I2c));
    assert_eq!(cap_kind_for_driver(DRV_KIND_PWM), Some(CapKind::Pwm));
    assert_eq!(cap_kind_for_driver(DRV_KIND_MOTOR_PID), Some(CapKind::Motor));
}

/// Every other declared kind is denied by omission (`None`) -- checked
/// against every `DRV_KIND_*` the tree currently declares, not a
/// hand-picked sample. `drv_invoke_authorized` turns `None` into "userspace
/// may not invoke this driver", so a wrong `Some` here would open a
/// syscall path to a driver (UART, SPI, DMA, camera, LiDAR, IMU, GPS, ADC,
/// NPU, CAN, xHCI) that has no `CapKind` a caller could be asked to hold.
#[test]
fn every_kind_without_a_capability_analogue_is_denied() {
    for &(kind, expected) in ALL_KINDS {
        if expected.is_none() {
            assert_eq!(
                cap_kind_for_driver(kind), None,
                "DRV_KIND {kind:#06x} must deny by omission (no CapKind exists for it)"
            );
        }
    }
}

/// The full table, both halves, in one pass -- the property the module doc
/// states ("only four driver kinds have a capability analogue") read
/// directly off the real constant list.
#[test]
fn all_declared_kinds_are_accounted_for() {
    assert_eq!(ALL_KINDS.len(), 17, "a DRV_KIND_* was added or removed in azos_driver_server \
        without updating this table -- add it above with its expected mapping");
    let mapped = ALL_KINDS.iter().filter(|(_, v)| v.is_some()).count();
    assert_eq!(mapped, 4, "expected exactly the four documented capability-backed kinds");
    for &(kind, expected) in ALL_KINDS {
        assert_eq!(cap_kind_for_driver(kind), expected, "DRV_KIND {kind:#06x}");
    }
}

/// A kind with no `DRV_KIND_*` name at all (never registered) must also
/// deny -- the function's fallback arm, not just its named negatives.
#[test]
fn an_unregistered_kind_id_is_denied() {
    assert_eq!(cap_kind_for_driver(0xFFFF), None);
    assert_eq!(cap_kind_for_driver(0), None);
}
