// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The registry of kernel-hosted interfaces and the wire form of `Out`.

use azos_devif::{by_key, by_name, key, outcome, parse_target, Out, IFACES};
use azos_idl::{MsgDesc, Reader, Wire, Writer, MSG_VERSION};

/// Keys are dense from 1 and match their position; ids and names are unique.
///
/// **Canary.** Give two interfaces one id, or skip a key: red.
#[test]
fn the_registry_is_dense_and_unique() {
    for (i, f) in IFACES.iter().enumerate() {
        assert_eq!(f.key as usize, i + 1, "{}: keys are dense from 1", f.name);
        assert_eq!(by_key(f.key).map(|x| x.name), Some(f.name));
        assert_eq!(by_name(f.name).map(|x| x.key), Some(f.key));
    }
    let mut ids: Vec<u32> = IFACES.iter().map(|f| f.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), IFACES.len(), "two interfaces share an id");
    let mut names: Vec<&str> = IFACES.iter().map(|f| f.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), IFACES.len(), "two interfaces share a name");
    assert!(by_key(0).is_none(), "key 0 names nothing");
    assert!(by_key(IFACES.len() as u16 + 1).is_none());
    assert_eq!(key::ENTROPY, 1);
}

/// A topology target names an interface and, where it has one, a resource;
/// anything that merely starts like one does not.
#[test]
fn a_target_names_an_interface_and_its_resource() {
    assert_eq!(parse_target("entropy").map(|(i, b)| (i.key, b)), Some((key::ENTROPY, 0)));
    assert_eq!(parse_target("power").map(|(i, b)| (i.key, b)), Some((key::POWER, 0)));
    // An interface with no resource takes none.
    assert!(parse_target("entropy.0").is_none());
    assert!(parse_target("entropy2").is_none());
    assert!(parse_target("entrop").is_none());
    assert!(parse_target("").is_none());
    // A task-hosted endpoint is spelled `endpoint.<name>`: never an interface.
    assert!(parse_target("endpoint.names").is_none());
}

/// `Out<T>` is the outcome word and then the value's words.
#[test]
fn out_crosses_as_the_code_then_the_value() {
    let mut m = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut m);
        Out::new(outcome::REFUSED, [7u64, 8]).put(&mut w);
        w.finish();
    }
    assert_eq!((m.n_words, m.words[0], m.words[1], m.words[2]), (3, outcome::REFUSED as u64, 7, 8));
    let mut r = Reader::new(&m);
    assert_eq!(<Out<[u64; 2]> as Wire>::get(&mut r), Out::new(outcome::REFUSED, [7, 8]));
    assert!(r.finish().is_ok());
    assert_eq!(<Out<[u64; 2]> as Wire>::WORDS, 3);
    assert_eq!(<Out<()> as Wire>::WORDS, 1);
    // A code that is not a u32 is a malformed reply, not a wrapped code.
    let mut bad = MsgDesc { version: MSG_VERSION, n_words: 1, ..MsgDesc::default() };
    bad.words[0] = 1 << 40;
    let mut r = Reader::new(&bad);
    let _ = <Out<()> as Wire>::get(&mut r);
    assert!(r.finish().is_err());
}

/// The resource spellings of the device interfaces, with their limits: a
/// spelling past the limit, in another base than the interface expects or
/// naming no resource where one is needed names nothing.
///
/// **Canary.** Drop the `+ 1` of `block_partition` (a partition's badge would
/// be the whole medium's for partition 0): the first block line goes red.
#[test]
fn a_device_resource_spelling_is_bounded() {
    let badge = |t: &str| parse_target(t).map(|(i, b)| (i.key, b));
    assert_eq!(badge("gpio.17"), Some((key::GPIO, 17)));
    assert!(badge("gpio.9999").is_none());
    assert!(badge("gpio").is_none(), "a pin needs a number");
    assert_eq!(badge("pwm.3"), Some((key::PWM, 3)));
    assert_eq!(badge("motor.0"), Some((key::MOTOR, 0)));
    assert_eq!(badge("motor.1"), Some((key::MOTOR, 1)));
    assert!(badge("motor.2").is_none(), "the drivetrain has two wheels");
    assert_eq!(badge("sensor.0"), Some((key::SENSOR, 0)));
    assert_eq!(badge("sensor.9"), Some((key::SENSOR, 9)));
    assert!(badge("sensor.10").is_none());
    assert!(badge("sensor.imu").is_none());
    assert_eq!(badge("i2c.0.0x68").map(|b| b.0), Some(key::I2C));
    assert!(badge("i2c.256.1").is_none());
    assert_eq!(badge("block.part.0"), Some((key::BLOCK, 1)), "badge 0 is the whole medium");
    assert_eq!(badge("block.part.15"), Some((key::BLOCK, 16)));
    assert!(badge("block.part.16").is_none());
    assert!(badge("block.0").is_none());
    assert!(badge("block").is_none());
    assert_eq!(badge("time"), Some((key::TIME, 0)));
    assert!(badge("time.0").is_none());
}
