// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot protocol (HID 1.11, appendix B).
//!
//! An interface of subclass 1 can be told (`SET_PROTOCOL(0)`) to send the
//! reports of appendix B whatever its own descriptor says: for a keyboard (interface
//! protocol 1) eight bits of modifiers, a reserved byte and six key usages; for a
//! mouse (protocol 2) three buttons and the X and Y movement in a byte each
//! (a wheel, if the device has one, is not part of the boot report). The driver
//! asks for it only when the device's own report descriptor cannot be had or
//! parsed, and reads the reports with the same decoder as any other: these
//! are the descriptors of appendix E.6 and E.10, parsed like a device's.

use crate::report::Layout;

/// Interface subclass: boot interface.
pub const SUBCLASS_BOOT: u8 = 1;
/// Interface protocols of a boot interface.
pub const PROTOCOL_KEYBOARD: u8 = 1;
pub const PROTOCOL_MOUSE: u8 = 2;

/// The report descriptor of the boot keyboard (HID 1.11, appendix E.6).
pub const KEYBOARD: [u8; 63] = [
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95,
    0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05,
    0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19,
    0x00, 0x29, 0x65, 0x81, 0x00, 0xc0,
];

/// The report descriptor of the boot mouse (HID 1.11, appendix E.10).
pub const MOUSE: [u8; 50] = [
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25,
    0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31,
    0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06, 0xc0, 0xc0,
];

/// The layout of the boot report of an interface of `protocol`; `None` for a
/// protocol that is neither keyboard nor mouse.
pub fn layout(protocol: u8) -> Option<Layout> {
    let d: &[u8] = match protocol {
        PROTOCOL_KEYBOARD => &KEYBOARD,
        PROTOCOL_MOUSE => &MOUSE,
        _ => return None,
    };
    Layout::parse(d).ok()
}
