// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Spi`, `Can`, `Uart` and `Adc` rows of the registry: the host keys, the
//! topology spelling of each interface's resource (the badge the kernel's
//! server reads back) and the bound of every spelling. The servers behind the
//! rows are `crates/core/syscall/src/devices.rs`, driven by
//! `tests/host/syscall-tests/src/h3_hosts.rs`.

use azos_devif::{adc, by_key, by_name, can, key, parse_target, spi, uart, IFACES};

fn badge(target: &str) -> Option<(u16, u32)> {
    parse_target(target).map(|(i, b)| (i.key, b))
}

/// The four rows exist, are dense after `clock`, and carry the interface ids.
///
/// **Canary.** Drop a row, or move one of the keys: red.
#[test]
fn the_four_interfaces_are_registered_after_clock() {
    assert_eq!((key::SPI, key::CAN, key::UART, key::ADC), (16, 17, 18, 19));
    assert_eq!((key::BLOCK, key::CLOCK), (14, 15), "the existing keys did not move");
    // The Vm and Vcpu rows (hv) follow, at keys 20 and 21, Net at 22, Display at 23, MemCtl at 24, Keys at 25, Sound at 26
    // and PowerAssert at 27.
    assert_eq!(IFACES.len(), 27);
    for (name, k, id) in [("spi", key::SPI, spi::SPI_ID), ("can", key::CAN, can::CAN_ID), ("uart", key::UART, uart::UART_ID), ("adc", key::ADC, adc::ADC_ID)] {
        let i = by_name(name).unwrap_or_else(|| panic!("no row {name}"));
        assert_eq!((i.key, i.id), (k, id), "{name}");
        assert_eq!(by_key(k).map(|x| x.name), Some(name));
    }
}

/// `spi.<bus>.<cs>` is the badge `bus << 8 | cs`; both parts are below 256 and
/// both are required.
#[test]
fn an_spi_target_names_a_bus_and_a_chip_select() {
    assert_eq!(badge("spi.0.1"), Some((key::SPI, spi::badge(0, 1))));
    assert_eq!(badge("spi.2.0x1f"), Some((key::SPI, spi::badge(2, 0x1f))));
    assert_eq!(badge("spi.255.255"), Some((key::SPI, spi::badge(255, 255))));
    for bad in ["spi", "spi.0", "spi.256.0", "spi.0.256", "spi.0.1.2", "spi.a.b", "spi.-1.0"] {
        assert!(parse_target(bad).is_none(), "{bad}");
    }
}

/// `can.<n>`, `uart.<n>` and `adc.<n>` take one index below the interface's
/// bound; a bare interface name names nothing.
#[test]
fn a_controller_port_or_channel_is_one_index_below_its_bound() {
    for (name, k, limit) in [("can", key::CAN, can::CONTROLLERS), ("uart", key::UART, uart::PORTS), ("adc", key::ADC, adc::CHANNELS)] {
        assert_eq!(badge(&format!("{name}.0")), Some((k, 0)));
        assert_eq!(badge(&format!("{name}.{}", limit - 1)), Some((k, limit - 1)));
        assert!(parse_target(&format!("{name}.{limit}")).is_none(), "{name}.{limit}");
        assert!(parse_target(name).is_none(), "{name} without a resource");
        assert!(parse_target(&format!("{name}.0.0")).is_none());
    }
    assert_eq!(badge("adc.0x3"), Some((key::ADC, 3)));
}
