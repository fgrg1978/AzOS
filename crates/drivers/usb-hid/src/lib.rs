// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The USB HID class driver for keyboards and mice (Kconfig `USB_HID`).
//!
//! - [`report`]: the report descriptor parser. Usages in, a [`report::Layout`]
//!   of controls out, each with the evdev meaning of its bits ([`usage`]).
//! - [`decode`]: a report to events, state kept across reports; the autorepeat
//!   a USB keyboard lacks.
//! - [`boot`]: the boot protocol's fixed descriptors, the fallback of a device
//!   whose own descriptor cannot be had.
//! - [`authorize`]: whether a device may bind a driver at all, and the
//!   decision record (`usb-authorize`) that says so.
//! - [`driver`]: the class driver itself, [`HidClass`], which an owner
//!   registers with the USB core and polls after every service. It hands the
//!   events to a [`Sink`]; the kernel's sink turns a key into a byte of the
//!   console's input ring (`azos_drv_input::keymap`) or an event of the ring the
//!   terminal server drains (`azos_drv_input::events`), the same two places the
//!   PS/2 and virtio-input drivers end in.
//!
//! No allocation, no unsafe code, no locks: tests/host/usb-hid-tests runs the
//! whole flow, descriptor to events, against the xHCI mock of
//! tests/host/usb-tests. The kernel half is kernel/src/boot/usb_hid.rs.
#![no_std]
#![forbid(unsafe_code)]

pub mod authorize;
pub mod boot;
pub mod decode;
pub mod driver;
pub mod report;
pub mod usage;

pub use authorize::{Facts, Policy, Reason};
pub use decode::{Decoder, Repeat};
pub use driver::{HidClass, Sink, State};
pub use report::{Control, Kind, Layout, ParseError};
