// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interfaces of what the kernel hosts and of what a driver endpoint
//! serves.
//!
//! **A device is not a syscall number and not a capability kind.** A task
//! that may read a pin, command a wheel or ask for random bytes holds an
//! `Endpoint` capability whose *badge* names the resource (a pin, a bus and
//! an address, a wheel pair, a partition) and whose *rights* are the op
//! classes the holder may use: `READ` observes, `WRITE` acts, `EXEC` controls
//! (binds, resets, administers). The call is `ipc_call` on that endpoint with
//! a request in the IDL's wire form (`azos_idl`): the kernel serves the
//! interface itself for a driver it hosts ("kernel-hosted endpoint",
//! `azos_ipc::endpoint::kernel_host`), a ring-3 driver serves the same trait
//! from its own endpoint, and the client stub (`<Name>Client`) does not know
//! which.
//!
//! Every op answers with a typed outcome ([`outcome`]) and its value
//! ([`Out`]), never an `errno`: an op's refusals are values of its
//! interface.
//!
//! The registry [`IFACES`] gives each interface its name (the word a topology
//! row uses, `endpoint = "gpio.17"`), its IDL id and its host key (what a
//! kernel-hosted endpoint is owned by).
#![no_std]

pub use azos_idl::{IdlError, MsgDesc, Reader, Result as IdlResult, Transport, Wire, Writer};

pub mod outcome;
pub use outcome::Out;

pub mod entropy;
pub use entropy::{Entropy, EntropyCall, EntropyClient, EntropyIdl, ENTROPY_ID};

pub mod linkkey;
pub use linkkey::{LinkKey, LinkKeyCall, LinkKeyClient, LinkKeyIdl, LINK_KEY_ID};

pub mod power;
pub use power::{Power, PowerCall, PowerClient, PowerIdl, POWER_ID};

pub mod gpio;
pub use gpio::{Gpio, GpioCall, GpioClient, GpioIdl, GPIO_ID};

pub mod i2c;
pub use i2c::{Bytes, I2c, I2cCall, I2cClient, I2cIdl, I2C_ID};

pub mod pwm;
pub use pwm::{Pwm, PwmCall, PwmClient, PwmIdl, PWM_ID};

pub mod motor;
pub use motor::{Motor, MotorCall, MotorClient, MotorIdl, MOTOR_ID};

pub mod sensor;
pub use sensor::{Sample, Sensor, SensorCall, SensorClient, SensorIdl, SENSOR_ID};

pub mod block;
pub use block::{Block, BlockCall, BlockClient, BlockIdl, BLOCK_ID};

pub mod buzzer;
pub use buzzer::{Buzzer, BuzzerCall, BuzzerClient, BuzzerDirect, BuzzerIdl, BuzzerPlaced, BUZZER_ID};

pub mod time;
pub use time::TIME_ID;

pub mod families;
pub use families::{
    Behavior, BehaviorCall, BehaviorClient, BehaviorIdl, Config, ConfigCall, ConfigClient, ConfigIdl, Flight,
    FlightCall, FlightClient, FlightIdl, Ota, OtaCall, OtaClient, OtaIdl, BEHAVIOR_ID, CONFIG_ID, FLIGHT_ID, OTA_ID,
};

/// One interface of the registry.
#[derive(Clone, Copy, Debug)]
pub struct Iface {
    /// The word a topology row names it by: `endpoint = "<name>[.<resource>]"`.
    pub name: &'static str,
    /// The IDL interface id (`#[azos_interface(id = ...)]`).
    pub id: u32,
    /// The host key of a kernel-hosted endpoint of it (1-based, dense).
    pub key: u16,
    /// The badge a topology row's resource spelling means: the part of the
    /// target after the interface name (`17` for `gpio.17`, empty for an
    /// interface with no resource). `None`: the spelling names nothing.
    pub resource: fn(&str) -> Option<u32>,
}

/// The resource spelling of an interface with none: the empty string.
pub fn no_resource(rest: &str) -> Option<u32> {
    rest.is_empty().then_some(0)
}

/// A number as a topology spells it: decimal, or hexadecimal after `0x`.
fn number(s: &str) -> Option<u32> {
    match s.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// A resource spelled as one number below `limit`: a pin, a channel, a wheel,
/// a sensor type.
fn index_below(rest: &str, limit: u32) -> Option<u32> {
    number(rest).filter(|&n| n < limit)
}

fn gpio_pin(rest: &str) -> Option<u32> {
    index_below(rest, gpio::PINS)
}

fn pwm_channel(rest: &str) -> Option<u32> {
    index_below(rest, pwm::CHANNELS)
}

fn motor_wheel(rest: &str) -> Option<u32> {
    index_below(rest, motor::WHEELS)
}

fn sensor_type(rest: &str) -> Option<u32> {
    index_below(rest, sensor::TYPES)
}

/// `part.<n>`: partition `n` of the kernel's table; the badge is `n + 1`
/// (badge 0 is the whole medium, which no spelling names).
fn block_partition(rest: &str) -> Option<u32> {
    index_below(rest.strip_prefix("part.")?, block::PARTS).map(|n| n + 1)
}

/// `<bus>.<address>`: the device at `address` on `bus`, both below 256.
fn i2c_device(rest: &str) -> Option<u32> {
    let (bus, addr) = rest.split_once('.')?;
    let (bus, addr) = (number(bus)?, number(addr)?);
    (bus < 256 && addr < 256).then(|| i2c::badge(bus as u8, addr as u8))
}

/// The host keys, one per interface, dense from 1 (the index into [`IFACES`]
/// plus one).
pub mod key {
    pub const ENTROPY: u16 = 1;
    pub const LINK_KEY: u16 = 2;
    pub const POWER: u16 = 3;
    pub const FLIGHT: u16 = 4;
    pub const BEHAVIOR: u16 = 5;
    pub const CONFIG: u16 = 6;
    pub const OTA: u16 = 7;
    pub const GPIO: u16 = 8;
    pub const I2C: u16 = 9;
    pub const PWM: u16 = 10;
    pub const MOTOR: u16 = 11;
    pub const SENSOR: u16 = 12;
    pub const TIME: u16 = 13;
    pub const BLOCK: u16 = 14;
}

/// Every interface the kernel can host, by host key (`IFACES[key - 1]`).
pub const IFACES: &[Iface] = &[
    Iface { name: "entropy", id: ENTROPY_ID, key: key::ENTROPY, resource: no_resource },
    Iface { name: "linkkey", id: LINK_KEY_ID, key: key::LINK_KEY, resource: no_resource },
    Iface { name: "power", id: POWER_ID, key: key::POWER, resource: no_resource },
    Iface { name: "flight", id: FLIGHT_ID, key: key::FLIGHT, resource: no_resource },
    Iface { name: "behavior", id: BEHAVIOR_ID, key: key::BEHAVIOR, resource: no_resource },
    Iface { name: "config", id: CONFIG_ID, key: key::CONFIG, resource: no_resource },
    Iface { name: "ota", id: OTA_ID, key: key::OTA, resource: no_resource },
    Iface { name: "gpio", id: GPIO_ID, key: key::GPIO, resource: gpio_pin },
    Iface { name: "i2c", id: I2C_ID, key: key::I2C, resource: i2c_device },
    Iface { name: "pwm", id: PWM_ID, key: key::PWM, resource: pwm_channel },
    Iface { name: "motor", id: MOTOR_ID, key: key::MOTOR, resource: motor_wheel },
    Iface { name: "sensor", id: SENSOR_ID, key: key::SENSOR, resource: sensor_type },
    Iface { name: "time", id: TIME_ID, key: key::TIME, resource: no_resource },
    Iface { name: "block", id: BLOCK_ID, key: key::BLOCK, resource: block_partition },
];

/// Split a topology target `<iface>[.<resource>]` into its interface and the
/// badge its resource spelling means. `None` when the target names no
/// interface of the registry, or names a resource it does not have. A name
/// that merely starts with an interface's (`entropy2`) is not that interface.
pub fn parse_target(target: &str) -> Option<(&'static Iface, u32)> {
    let (name, rest) = match target.split_once('.') {
        Some((n, r)) => (n, r),
        None => (target, ""),
    };
    let i = by_name(name)?;
    (i.resource)(rest).map(|b| (i, b))
}

/// The interface called `name`.
pub fn by_name(name: &str) -> Option<&'static Iface> {
    IFACES.iter().find(|i| i.name == name)
}

/// The interface with host key `key`.
pub fn by_key(key: u16) -> Option<&'static Iface> {
    IFACES.get((key as usize).checked_sub(1)?).filter(|i| i.key == key)
}
