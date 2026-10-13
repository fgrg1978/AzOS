// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The runtime hardware bus (the logic; the kernel's static instance and its
//! enumerators are in `azos_drv_bus::hwbus`).
//!
//! What was a boot-time list of three fixed devices is a bus that finds its
//! devices (PCI/PCIe through ECAM, device-tree nodes that carry a `compatible`,
//! populated virtio-mmio windows), gives each a [`Device`] object and a
//! [`Handle`] that a `Device` capability names, and binds drivers to them:
//!
//! - **Match tables** ([`tables`]): each native driver crate declares the ids
//!   it answers to in an `hwbus.ids` file; Linux leaf drivers' ids are read
//!   from their `MODULE_DEVICE_TABLE`. Both are generated at build time and
//!   `build.rs` refuses an id that is in both.
//! - **Policy** ([`policy`]): Kconfig `HWBUS_AUTOBIND` binds whatever the tables
//!   match (`Auto`), or detects everything and binds only what the signed
//!   topology's `[device.*]` rows admit (`TopologyOnly`); the rest is
//!   reported as "detected, not admitted".
//! - **Binding** ([`bus`]): native table first, then Linux, a topology row
//!   overriding either; [`Bus::unbind`], [`Bus::rebind`] and
//!   [`Bus::reconcile`] are what the signed topology, once installed, uses to
//!   bring the devices bound under the built-in one to its rows.
//!
//! A driver whose ids matched no device starts nothing, and a Linux class
//! server is launched only once one of its ids matched
//! ([`Bus::linux_class_wanted`]).
//!
//! No arch code, no locks, no I/O: it host-tests as it is.

#![no_std]

pub mod bus;
pub mod device;
pub mod pattern;
pub mod policy;
pub mod tables;

pub use bus::{
    AddError, Binding, Bus, Drivers, Event, Handle, ProbeError, Rules, Sink, Slot, State, UnbindError,
    MAX_DEVICES,
};
pub use device::{BusKind, Device, Name, PciId, COMPAT_LEN, NAME_LEN};
pub use pattern::{Pattern, ANY};
pub use policy::{decide, natural, Choice, Policy, Row, Verdict};
pub use tables::{first_conflict, LinuxEntry, NativeEntry, LINUX, NATIVE};
