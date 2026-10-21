// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The class-driver interface.
//!
//! A class driver (HID, mass storage, CDC) is placed where its owner chooses:
//! in the kernel, or in a ring-3 process. It reaches the USB core, and the
//! core reaches it, through two IDL interfaces (crates/core/idl), so neither
//! side knows where the other runs:
//!
//! - [`UsbClass`] is what a class driver serves. The core calls it when a
//!   device that matches the driver's [`Match`] rule appears
//!   ([`UsbClass::attach`]) and when it goes ([`UsbClass::detach`]).
//! - [`UsbDevice`] is what the core serves, once per claim: the driver holds
//!   an endpoint whose badge is its [`Claim`] and, through it, only the
//!   interface it claimed. A driver never holds a handle to the device, the
//!   controller or another driver's interface.
//!
//! The data path is not here: [`UsbDevice::pipe_open`] names a pipe and the
//! driver then moves data through that pipe's pair of `Queue` rings
//! ([`crate::usbcore::pipe`]). Calls carry authority; rings carry data.
//!
//! # A claim
//!
//! A claim is `slot << 24 | interface << 16 | generation`. The generation is
//! the number of times the slot has been enumerated, so a claim kept past an
//! unplug names nothing even when the slot holds another device. Interface
//! `0xff` is a device-scope claim: a watcher (a listing, a log) that may read
//! the device's descriptors and nothing else.

use azos_devif::Out;
use azos_idl::azos_interface;

use crate::MAX_CLASS_DRIVERS;

pub mod cdc;
pub mod msc;
pub mod uvc;

/// The interface id of [`UsbClass`] (ASCII "USBC").
pub const USB_CLASS_ID: u32 = 0x5553_4243;
/// The interface id of [`UsbDevice`] (ASCII "USBD").
pub const USB_DEVICE_ID: u32 = 0x5553_4244;

/// The interface number of a device-scope claim.
pub const WHOLE_DEVICE: u8 = 0xff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim(pub u32);

impl Claim {
    pub const fn new(slot: u8, iface: u8, generation: u16) -> Claim {
        Claim((slot as u32) << 24 | (iface as u32) << 16 | generation as u32)
    }
    pub const fn slot(self) -> u8 {
        (self.0 >> 24) as u8
    }
    pub const fn iface(self) -> u8 {
        (self.0 >> 16) as u8
    }
    pub const fn generation(self) -> u16 {
        self.0 as u16
    }
    pub const fn is_device_scope(self) -> bool {
        self.iface() == WHOLE_DEVICE
    }
}

/// What a class driver serves. `attach` is the whole of binding: a driver that
/// declines answers any code but `OK` and the next matching driver is asked.
#[azos_interface(id = 0x5553_4243, level = 1)]
pub trait UsbClass {
    /// A device (device scope) or an interface (interface scope) matching the
    /// driver's rule appeared. `vid_pid` is `vendor << 16 | product`,
    /// `triple` the class, subclass and protocol as `c << 16 | s << 8 | p`
    /// (of the interface, or of the device descriptor for device scope), and
    /// `speed_port` is `speed << 8 | root port`, speed as the slot context
    /// numbers it (1 full, 2 low, 3 high, 4 super, 5 super plus). `OK` takes
    /// the claim.
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32>;
    /// The claimed device is gone (or its configuration changed). Its pipes
    /// have completed their outstanding transfers as disconnected; the driver
    /// closes them and lets go of the claim.
    fn detach(&mut self, claim: u32) -> Out<u32>;
}

/// What the core serves for one claim. Rights: `READ` observes (`info`,
/// `endpoint`), `EXEC` opens and closes pipes.
#[azos_interface(id = 0x5553_4244, level = 1)]
pub trait UsbDevice {
    /// A fact about the claimed device: 0 `vendor << 16 | product`, 1
    /// `class << 16 | subclass << 8 | protocol` of the claimed interface (the
    /// device's, for a device-scope claim), 2 the speed, 3 `bcdUSB << 16 |
    /// bcdDevice`, 4 the interface's endpoint count, 5 the interface number,
    /// 6 the alternate setting the endpoints belong to (0, or the first
    /// alternate setting that has endpoints when setting 0 has none: the
    /// driver selects it with SET_INTERFACE before using a pipe).
    #[idempotent]
    fn info(&self, what: u32) -> Out<u64>;
    /// Endpoint `index` of the claimed interface: `address | attributes << 8 |
    /// max packet << 16 | interval << 32 | burst << 40`.
    #[idempotent]
    fn endpoint(&self, index: u32) -> Out<u64>;
    /// Open a pipe on endpoint `ep` (an address, bit 7 = IN) of the claimed
    /// interface, or the control endpoint (0). `ep` carries the alternate
    /// setting the endpoint belongs to in bits 15:8 (0: the interface's own
    /// table, setting [`info`](UsbDevice::info) 6). Returns the pipe's number;
    /// the driver then takes its ends of that pipe's rings.
    fn pipe_open(&mut self, ep: u32) -> Out<u32>;
    /// Close one of the claim's pipes. Transfers still queued are dropped.
    fn pipe_close(&mut self, pipe: u32) -> Out<u32>;
}

/// Whether a rule concerns whole devices (a watcher: many may attach) or an
/// interface (one driver owns it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Device,
    Interface,
}

/// The ids a driver answers to. `None` matches anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    pub scope: Scope,
    pub vid_pid: Option<u32>,
    pub class: Option<u8>,
    pub subclass: Option<u8>,
    pub protocol: Option<u8>,
}

impl Match {
    /// Every device (a watcher).
    pub const fn every_device() -> Match {
        Match { scope: Scope::Device, vid_pid: None, class: None, subclass: None, protocol: None }
    }
    /// Interfaces of class `class`.
    pub const fn interface_class(class: u8) -> Match {
        Match { scope: Scope::Interface, vid_pid: None, class: Some(class), subclass: None, protocol: None }
    }
    pub fn matches(&self, scope: Scope, vid_pid: u32, class: u8, subclass: u8, protocol: u8) -> bool {
        self.scope == scope
            && self.vid_pid.is_none_or(|v| v == vid_pid)
            && self.class.is_none_or(|c| c == class)
            && self.subclass.is_none_or(|s| s == subclass)
            && self.protocol.is_none_or(|p| p == protocol)
    }
}

/// The registered class drivers, in registration order. Built by whoever
/// owns the drivers and lent to [`crate::usbcore::Usb::service`] for the call.
pub struct Registry<'d> {
    entries: [Option<Entry<'d>>; MAX_CLASS_DRIVERS],
}

pub(crate) struct Entry<'d> {
    pub id: u8,
    pub rule: Match,
    pub driver: &'d mut dyn UsbClassCall,
}

/// No room for another class driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryFull;

impl<'d> Registry<'d> {
    pub fn new() -> Registry<'d> {
        Registry { entries: [const { None }; MAX_CLASS_DRIVERS] }
    }

    /// Register `driver` under `id` (unique among the registry's drivers; the
    /// core remembers which driver holds an interface by it).
    pub fn register(&mut self, id: u8, rule: Match, driver: &'d mut dyn UsbClassCall) -> Result<(), RegistryFull> {
        let slot = self.entries.iter_mut().find(|e| e.is_none()).ok_or(RegistryFull)?;
        *slot = Some(Entry { id, rule, driver });
        Ok(())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Entry<'d>> {
        self.entries.iter_mut().flatten()
    }

    pub(crate) fn by_id(&mut self, id: u8) -> Option<&mut Entry<'d>> {
        self.entries.iter_mut().flatten().find(|e| e.id == id)
    }
}

impl Default for Registry<'_> {
    fn default() -> Self {
        Registry::new()
    }
}
