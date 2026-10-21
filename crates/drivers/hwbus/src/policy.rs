// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The binding decision: which driver a device gets, and whether it gets one.
//!
//! Pure: the tables, the policy and the topology's device rows in, a verdict
//! out. Nothing here touches hardware.
//!
//! # Order
//!
//! 0. A device a `boot` native entry names (the console UART, the interrupt
//!    controller, the PCI host: hardware the kernel booted on) is bound to
//!    that driver. No policy and no row can unbind the kernel's own console.
//! 1. A topology row whose selector names the device, if there is one (the
//!    first in file order): it may refuse the device, name the native driver to
//!    use instead of the table's choice, or only admit it.
//! 2. The native table, in table order.
//! 3. The Linux table, in table order. A native entry always beats a Linux
//!    one for the same device; the build refuses ids in both tables, so this
//!    only orders overlapping *classes*.
//!
//! # Policy
//!
//! [`Policy::Auto`] binds what the tables match. [`Policy::TopologyOnly`]
//! detects everything and binds only what a row admits: a device the tables
//! match but no row admits is [`Verdict::NotAdmitted`], which the kernel
//! records as a decision ("detected, not admitted").

use crate::device::Device;
use crate::pattern::Pattern;
use crate::tables::{LinuxEntry, NativeEntry};

/// Kconfig `HWBUS_AUTOBIND`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    /// Bind every device a table matches.
    Auto,
    /// Bind only the devices the signed topology admits.
    TopologyOnly,
}

impl Policy {
    /// The policy of this build (Kconfig `HWBUS_AUTOBIND`).
    pub const BUILD: Policy = if azos_limits::HWBUS_AUTOBIND_TOPOLOGY {
        Policy::TopologyOnly
    } else {
        Policy::Auto
    };

    /// What the policy admits without a row. The `policy-canary` feature
    /// makes the topology-only build admit like `Auto`, so the host rows that
    /// pin the policy fail with it on.
    const fn admits_unlisted(self) -> bool {
        match self {
            Policy::Auto => true,
            Policy::TopologyOnly => cfg!(feature = "policy-canary"),
        }
    }
}

/// One `[device.*]` row of the topology.
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    pub select: Pattern<'a>,
    /// `false`: the device is detected and never bound.
    pub admit: bool,
    /// The native driver to bind instead of the table's choice.
    pub driver: Option<&'a str>,
}

/// Who a device is handed to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Choice<'a> {
    /// An in-kernel driver, by the name its id file gave it.
    Native(&'a str),
    /// A Linux class server (ring 3) and the module the id came from.
    Linux { class: &'static str, module: &'static str },
}

/// What [`decide`] says about one device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict<'a> {
    Bind(Choice<'a>),
    /// Detected, a driver exists (`natural`), and it was not admitted: the
    /// policy is topology-only with no row for it (`by_row` false), or a row
    /// refuses it (`by_row` true, `natural` possibly `None`).
    NotAdmitted { natural: Option<Choice<'a>>, by_row: bool },
    /// No table names it and no row gives it a driver.
    Unmatched,
}

/// The table's choice for `dev`, native first.
pub fn natural<'t>(
    dev: &Device,
    native: &'t [NativeEntry],
    linux: &'t [LinuxEntry],
) -> Option<Choice<'t>> {
    native
        .iter()
        .find(|e| dev.matches(&e.pattern))
        .map(|e| Choice::Native(e.driver))
        .or_else(|| {
            linux
                .iter()
                .find(|e| dev.matches(&e.pattern))
                .map(|e| Choice::Linux { class: e.class, module: e.module })
        })
}

/// The binding decision for `dev`.
pub fn decide<'t>(
    dev: &Device,
    native: &'t [NativeEntry],
    linux: &'t [LinuxEntry],
    rows: &'t [Row<'t>],
    policy: Policy,
) -> Verdict<'t> {
    // What the kernel booted on is bound to its driver, whatever the rows say.
    if let Some(e) = native.iter().find(|e| e.boot && dev.matches(&e.pattern)) {
        return Verdict::Bind(Choice::Native(e.driver));
    }
    let nat = natural(dev, native, linux);
    match rows.iter().find(|r| dev.matches(&r.select)) {
        Some(r) if !r.admit => Verdict::NotAdmitted { natural: nat, by_row: true },
        Some(r) => match (r.driver, nat) {
            (Some(name), _) => Verdict::Bind(Choice::Native(name)),
            (None, Some(c)) => Verdict::Bind(c),
            (None, None) => Verdict::Unmatched,
        },
        None => match nat {
            None => Verdict::Unmatched,
            Some(c) if policy.admits_unlisted() => Verdict::Bind(c),
            Some(c) => Verdict::NotAdmitted { natural: Some(c), by_row: false },
        },
    }
}
