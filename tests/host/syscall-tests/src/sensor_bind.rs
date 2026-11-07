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
use azos_abi::sensor_sample::instance::{BATTERY, ENCODER, GPS, IMU, ODOM};

const TID: u32 = 0x7e51_0002;

fn server(badge: u32, rights: CapPerms) -> SensorServer {
    SensorServer(Caller { tid: TID, badge, rights })
}

/// **A bind to the vDSO page, with the page mapped, answers by the build.**
/// With the Robot domain the encoder binds and the interrupt publishes it;
/// the battery, which no interrupt can sample, binds and is read by `read`
/// only. Without the domain the four robot sensors are refused like a read
/// of them (`NOT_READY`), so the interrupt never publishes a zero slot, and
/// the battery still binds. Run both ways: the default features, and
/// `--no-default-features` (the generic image; the battery is the board's
/// sensor and is refused without `board-io`, like a read).
///
/// **Canary** (`vdso-bind-canary`, a gate row, run without `use-robot`):
/// `bind_vdso` skips `produced_in_this_image`, so the generic build binds all
/// four and answers `Ok(true)` for the encoder and the odometry.
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
    let battery = bind(BATTERY);
    if cfg!(feature = "board-io") {
        assert!(battery.is_ok() && !battery.value, "a sensor no interrupt samples binds as read-only, code {}", battery.code);
    } else {
        assert_eq!(battery.code, outcome::NOT_READY, "the board's sensor without the board's I/O");
    }
}
