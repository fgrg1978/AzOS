// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hot-plug notifications.
//!
//! The USB core pushes one [`UsbEvent`] per device that appears or goes away
//! into a `Queue` its owner hands in ([`crate::usbcore::Usb::new`]). The queue is
//! the whole interface: a task that waits for hot-plug holds the consumer end,
//! and the kernel half turns each event into a Port event
//! (kernel/src/boot/usb.rs: source id = the slot, key = the vendor and
//! product id), so a task that holds a Port capability and waits on it sees
//! devices come and go without polling the USB core.

/// Entries of the hot-plug queue (a power of two).
pub const EVENT_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// A device finished enumeration and is configured.
    Attached = 1,
    /// A device is gone (unplugged, or its hub or port was).
    Detached = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbEvent {
    pub kind: EventKind,
    /// The controller slot the device held (its handle until `Detached`).
    pub slot: u8,
    /// The root port the device hangs below.
    pub root_port: u8,
    /// `vendor << 16 | product`.
    pub vid_pid: u32,
    /// `class << 16 | subclass << 8 | protocol` of the device descriptor.
    pub class: u32,
}
