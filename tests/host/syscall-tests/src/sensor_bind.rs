// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host test of `Sensor::bind_vdso` (`crates/core/syscall/src/sensor_host.rs`)
// against the build of the Robot domain. The rest of the suite drives the robot
// shims and builds only with `use-robot`; this file also builds without it, so
// the generic image's answer is asserted by the real `SensorServer`:
//
//     cargo test --release --no-default-features --features virtio-snd,linux-abi,board-io a_vdso_bind

use super::harness::serial;
use crate::khost::Caller;
use crate::sensor_host::SensorServer;
use azos_abi::cap::CapPerms;
use azos_devif::{outcome, Sensor};
use azos_abi::sensor_sample::instance::{BATTERY, ENCODER, GPS, IMU, ODOM, POWER};

const TID: u32 = 0x7e51_0002;

fn server(badge: u32, rights: CapPerms) -> SensorServer {
    SensorServer(Caller { tid: TID, badge, rights })
}

/// **A bind to the vDSO page, with the page mapped, answers by what the image
/// attached.** A number whose producer is not built in is vacant and refused
/// like a read of it (`NOT_READY`), so the interrupt never publishes a zero
/// slot. With the robot extension the encoder binds and the interrupt
/// publishes it; the battery, which no interrupt can sample, binds and is read
/// by `read` only. Without it the four robot sensors and the battery are
/// vacant, and the power monitor, the board I/O's, binds only with `board-io`.
/// Run both ways: the default features, and `--no-default-features` with
/// `board-io` (a board-io image without the robot) and without it.
///
/// **Canary** (`vdso-bind-canary`, a gate row, run without `use-robot`):
/// `bind_vdso` skips the vacancy check, so the build without the robot binds
/// all four and answers `Ok(true)` for the encoder and the odometry.
#[test]
fn a_vdso_bind_of_a_robot_sensor_follows_the_robot_domain() {
    let _g = serial();
    azos_mm::vdso::task_page_claim(0, TID).expect("a page for the slot");
    let bind = |ty: u32| server(ty, CapPerms::READ).bind_vdso();
    for ty in [IMU, ODOM, ENCODER, GPS] {
        let out = bind(ty);
        if cfg!(feature = "use-robot") {
            assert!(out.is_ok(), "sensor {ty} with the Robot domain: code {}", out.code);
            assert_eq!(out.value, matches!(ty, ODOM | ENCODER), "sensor {ty}");
        } else {
            assert_eq!(out.code, outcome::NOT_READY, "sensor {ty} without the Robot domain");
        }
    }
    // The battery is the robot's producer, the power monitor the board I/O's:
    // each binds where its producer is attached and is vacant elsewhere.
    let battery = bind(BATTERY);
    if cfg!(feature = "use-robot") {
        assert!(battery.is_ok() && !battery.value, "a sensor no interrupt samples binds as read-only, code {}", battery.code);
    } else {
        assert_eq!(battery.code, outcome::NOT_READY, "the robot's battery without the robot extension");
    }
    let power = bind(POWER);
    if cfg!(feature = "board-io") {
        assert!(power.is_ok() && !power.value, "the board I/O's power monitor binds as read-only, code {}", power.code);
    } else {
        assert_eq!(power.code, outcome::NOT_READY, "the power monitor without the board's I/O");
    }
}
