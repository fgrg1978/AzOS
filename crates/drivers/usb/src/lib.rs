// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The native USB host (Kconfig `USB_HOST`, `USB_XHCI`).
//!
//! - [`xhci`]: the xHCI controller driver: registers, command ring, event
//!   ring, transfer rings, scratchpad buffers, contexts, ports. It reaches
//!   hardware only through [`hw::Regs`], [`hw::Memory`] and [`hw::Clock`].
//! - [`dwc3`]: the dual-role Synopsys core's side of an xHCI node: the
//!   `dr_mode` check and `GCTL.PRTCAPDIR`.
//! - [`dwc2`] (Kconfig `USB_DWC2`): the DesignWare USB 2.0 OTG core in host
//!   mode (the Raspberry Pi's), which presents the xHCI driver's model to the
//!   core in software ([`usbcore::hc`] holds either controller).
//! - [`usbcore`]: the USB core on top of it: device enumeration, descriptor
//!   parsing ([`usbcore::desc`]), hubs, pipes (a pair of `Queue` rings over
//!   driver-owned DMA buffers), hot-plug events ([`event`]).
//! - [`class`]: the class-driver interface (two IDL interfaces and the
//!   registry), so a class driver is placed in the kernel or in ring 3 and
//!   holds only the interface it claimed.
//! - [`class::msc`]: the mass-storage class driver: Bulk-Only Transport and
//!   SCSI (`azos_scsi`) over the pipes of one claim, as a block device for the
//!   kernel's request layer to wrap.
//! - [`class::cdc`]: the communications class drivers: CDC-ACM as a `Uart`
//!   (a USB serial console) and CDC-ECM / CDC-NCM (NTB parser) as a NIC for
//!   the network device table.
//! - [`class::smsc95xx`]: the SMSC LAN95xx Ethernet function (the Raspberry
//!   Pi 3 B's) as a NIC; it and the CDC one are [`class::net::NetFunction`]s,
//!   the one shape the kernel's NIC adapter takes.
//! - [`listing`]: the `lsusb`-style listing, a watcher class driver whose rows
//!   the kernel publishes through the introspection tree.
//!
//! No allocation, no locks, no I/O of its own: tests/host/usb-tests runs the
//! whole flow, enumeration of a device and of a hub, port changes, unplug and
//! transfer errors, against a register-level xHCI mock, and against a
//! register-level DWC2 mock (`dwc2` there). The kernel half is
//! kernel/src/boot/usb.rs.
#![no_std]

pub mod class;
#[cfg(feature = "dwc2")]
pub mod dwc2;
pub mod dwc3;
pub mod usbcore;
pub mod event;
pub mod hw;
pub mod listing;
pub mod xhci;

pub use class::{Claim, Match, Registry, Scope, UsbClass, UsbDevice};
pub use event::{EventKind, UsbEvent, EVENT_DEPTH};

/// Devices the core tracks (Kconfig `USB_MAX_DEVICES`).
pub const MAX_DEVICES: usize = azos_limits::USB_MAX_DEVICES as usize;
/// Pipes open at once (Kconfig `USB_MAX_PIPES`).
pub const MAX_PIPES: usize = azos_limits::USB_MAX_PIPES as usize;
/// Entries of each ring of a pipe (Kconfig `USB_PIPE_DEPTH`).
pub const PIPE_DEPTH: usize = azos_limits::USB_PIPE_DEPTH as usize;
/// Class drivers (and watchers) registered at once: the kernel's lister,
/// HID, mass storage, the two CDC functions (two interfaces each), the camera
/// and the LAN95xx function, and one spare.
pub const MAX_CLASS_DRIVERS: usize = 10;

const _: () = assert!(PIPE_DEPTH.is_power_of_two(), "USB_PIPE_DEPTH must be a power of two");
const _: () = assert!(MAX_DEVICES <= 127, "slot ids are 7 bits in a claim");
