// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Whether a device may bind a class driver (decision rule `usb-authorize`).
//!
//! A USB device names its own class. A flash stick that presents itself as a
//! keyboard types what its firmware says, with the user's rights; a keyboard
//! that is also a drive or a serial port is the same device with a second
//! purpose. So the driver does not bind to what a device claims to be: it asks
//! [`decide`], which answers from the build's [`Policy`] (Kconfig `USB_HID_ADMIT`,
//! `USB_BIND_MAX_TIER`, `USB_HID_REFUSE_COMPOSITE`) and the facts the USB core
//! has about the device ([`Facts`]), and writes the answer as a decision record
//! ([`record`]): the rule's subject is the root port, its numbers the device's
//! vendor/product id, the interface's class triple and the [`Reason`].
//!
//! The reasons are checked in this order: the class itself (1), the hubs the
//! device hangs below (2), the other interfaces of the device (3).
//!
//! The hardware bus's `[device.*]` rows cannot name a USB device yet (its
//! selectors are PCI ids, device-tree names and virtio ids), so there is no
//! signed per-device row to consult; a build whose bus binds only what the
//! topology admits (`HWBUS_AUTOBIND_TOPOLOGY`) defaults `USB_HID_ADMIT` to n
//! and refuses every HID device with reason 1.

use azos_decision::{Rule, Verdict};

/// What a build admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// HID keyboards and mice may bind at all (Kconfig `USB_HID_ADMIT`).
    pub admit_hid: bool,
    /// Hubs a device may hang below and still bind a driver; 0: only a device
    /// on a root port (Kconfig `USB_BIND_MAX_TIER`).
    pub max_tier: u8,
    /// A HID interface of a device with a storage or communications interface
    /// is refused (Kconfig `USB_HID_REFUSE_COMPOSITE`).
    pub refuse_composite: bool,
}

impl Policy {
    /// The policy this build was configured with.
    pub const BUILD: Policy = Policy {
        admit_hid: azos_limits::USB_HID_ADMIT,
        max_tier: azos_limits::USB_BIND_MAX_TIER as u8,
        refuse_composite: azos_limits::USB_HID_REFUSE_COMPOSITE,
    };
}

/// Why a device was or was not authorized: the third number of the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    Authorized = 0,
    /// The policy admits no HID device.
    NoRow = 1,
    /// The device hangs below more hubs than the policy trusts.
    HubNotTrusted = 2,
    /// The device has a storage or communications interface next to the HID one.
    CompositeDiffers = 3,
}

/// What the USB core knows about the device and the interface that matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub root_port: u8,
    /// `vendor << 16 | product`.
    pub vid_pid: u32,
    /// The interface's `class << 16 | subclass << 8 | protocol`.
    pub triple: u32,
    /// Hubs between the device and its root port.
    pub tier: u8,
    /// Some interface of the device is of a [`conflicting_class`].
    pub composite_conflict: bool,
}

/// Is an interface of `class` one a keyboard has no business next to: mass
/// storage (8), communications and its data interface (2, 0x0a), a wireless
/// controller (0xe0)?
pub const fn conflicting_class(class: u8) -> bool {
    matches!(class, 0x02 | 0x08 | 0x0a | 0xe0)
}

/// The decision.
pub fn decide(p: &Policy, f: &Facts) -> Reason {
    if !p.admit_hid {
        return Reason::NoRow;
    }
    #[cfg(not(feature = "canary-tier"))]
    if f.tier > p.max_tier {
        return Reason::HubNotTrusted;
    }
    #[cfg(not(feature = "canary-composite"))]
    if p.refuse_composite && f.composite_conflict {
        return Reason::CompositeDiffers;
    }
    Reason::Authorized
}

/// Write the decision record of `reason` for the device of `f`.
pub fn record(f: &Facts, reason: Reason) {
    #[cfg(not(feature = "canary-no-record"))]
    {
        let verdict = if reason == Reason::Authorized { Verdict::Admit } else { Verdict::Refuse };
        azos_decision::record(Rule::UsbAuthorize, verdict, f.root_port as u32, [f.vid_pid as u64, f.triple as u64, reason as u64]);
    }
    #[cfg(feature = "canary-no-record")]
    let _ = (f, reason, Rule::UsbAuthorize, Verdict::Admit);
}
