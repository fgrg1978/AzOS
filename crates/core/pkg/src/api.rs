// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interfaces this device serves and their levels: what a package's
//! `[api]` is held to ([`crate::Device::api`]).
//!
//! One table, for the two places that judge a package: the ring-3 installer
//! (`userspace/services/pkgd`) and the kernel's boot-time apply
//! (`kernel/src/boot/pkg_apply.rs`), which repeats the installer's decision and
//! must not reach a different one. The levels of the interfaces the kernel
//! hosts are read off their own definitions (`<Name>Idl::LEVEL`). The four
//! served by ring-3 libraries (`Decisions`, `Names`, `Packages`, `Terminal`)
//! live in crates the kernel does not link; their levels are restated in
//! [`USER_SERVED`], and both `pkgd` (at compile time) and the host suite
//! compare them with the libraries' own, so the restatement cannot drift.

use azos_devif as d;

/// Interfaces in [`device_api`].
pub const COUNT: usize = 17;

/// The levels of the interfaces ring-3 libraries serve.
pub const USER_SERVED: UserServed = UserServed { decisions: 1, names: 1, packages: 1, terminal: 1 };

/// The levels of the four interfaces served from ring 3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserServed {
    /// `azos_decisions::DecisionsIdl::LEVEL`.
    pub decisions: u32,
    /// `azos_names::NamesIdl::LEVEL`.
    pub names: u32,
    /// `azos_packages::PackagesIdl::LEVEL`.
    pub packages: u32,
    /// `azos_term::TerminalIdl::LEVEL`.
    pub terminal: u32,
}

/// The device's interface table, sorted by name.
pub fn device_api() -> [(&'static str, u32); COUNT] {
    let u = USER_SERVED;
    [
        ("Block", d::BlockIdl::LEVEL as u32),
        ("Behavior", d::families::BehaviorIdl::LEVEL as u32),
        ("Config", d::families::ConfigIdl::LEVEL as u32),
        ("Decisions", u.decisions),
        ("Entropy", d::EntropyIdl::LEVEL as u32),
        ("Flight", d::families::FlightIdl::LEVEL as u32),
        ("Gpio", d::GpioIdl::LEVEL as u32),
        ("I2c", d::I2cIdl::LEVEL as u32),
        ("LinkKey", d::LinkKeyIdl::LEVEL as u32),
        ("Motor", d::MotorIdl::LEVEL as u32),
        ("Names", u.names),
        ("Ota", d::families::OtaIdl::LEVEL as u32),
        ("Packages", u.packages),
        ("Power", d::PowerIdl::LEVEL as u32),
        ("Pwm", d::PwmIdl::LEVEL as u32),
        ("Sensor", d::SensorIdl::LEVEL as u32),
        ("Terminal", u.terminal),
    ]
}
