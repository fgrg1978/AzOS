// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which interfaces of a device may bind a class driver (decision rule
//! `usb-authorize`).
//!
//! A device names its own class, so the class it presents is no reason to hand
//! it to a driver: a flash stick that says "keyboard" types, one that says
//! "network card" becomes the machine's gateway, one that says "disk" has its
//! filesystem parsed in ring 0. The core asks [`Admission::decide`] before it
//! offers an interface to any registered class driver. The answer follows the
//! signed topology's `[usb.NAME]` rows, copied in with [`Admission::push`]: the
//! first row whose `vid`, `pid` and `class` all match decides (`class` is the
//! interface's), and an interface no row matches is refused. With no row at
//! all the build decides (Kconfig `USB_ADMIT_WITHOUT_ROWS`: development builds
//! admit, release and certifiable builds refuse).
//!
//! Hubs are the core's own and are not offered to class drivers, so no row is
//! needed for them. The decision is a record whose subject is the root port
//! and whose numbers are the vendor/product id, the interface's class triple
//! and the [`Reason`].

use azos_decision::{Rule, Verdict};

/// Rows kept: as many as the topology admits.
pub const MAX_ROWS: usize = azos_limits::TOPOLOGY_MAX_USB_RULES as usize;

/// One `[usb.NAME]` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub class: Option<u8>,
    pub allow: bool,
}

/// Why an interface was or was not admitted: the third number of the record.
/// The numbers 0 to 3 belong to the HID driver's own checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    /// A row admits it.
    Row = 4,
    /// A row refuses it.
    RowRefuses = 5,
    /// There are rows and none matches.
    NoRow = 6,
    /// There are no rows and the build does not admit without them.
    NoRows = 7,
    /// There are no rows and the build admits without them.
    OpenWithoutRows = 8,
}

impl Reason {
    pub const fn admitted(self) -> bool {
        matches!(self, Reason::Row | Reason::OpenWithoutRows)
    }
}

/// The admission rows of the USB core.
#[derive(Clone, Copy, Debug)]
pub struct Admission {
    rows: [Row; MAX_ROWS],
    len: usize,
    open_without_rows: bool,
    /// More rows were offered than fit: nothing is admitted.
    overflow: bool,
}

impl Admission {
    /// No rows, and what the build does with none.
    pub const fn build() -> Self {
        Self::with_default(azos_limits::USB_ADMIT_WITHOUT_ROWS)
    }

    pub const fn with_default(open_without_rows: bool) -> Self {
        Self {
            rows: [Row { vid: None, pid: None, class: None, allow: false }; MAX_ROWS],
            len: 0,
            open_without_rows,
            overflow: false,
        }
    }

    /// Append the next row, in file order. A row that does not fit makes the
    /// whole set refuse everything.
    pub fn push(&mut self, row: Row) {
        if self.len == MAX_ROWS {
            self.overflow = true;
            return;
        }
        self.rows[self.len] = row;
        self.len += 1;
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows[..self.len]
    }

    /// May the interface of `class` of the device `vid`:`pid` bind a driver?
    pub fn decide(&self, vid: u16, pid: u16, class: u8) -> Reason {
        #[cfg(feature = "canary-admit-all")]
        let _ = (vid, pid, class);
        #[cfg(feature = "canary-admit-all")]
        return Reason::Row;
        #[cfg(not(feature = "canary-admit-all"))]
        {
            if self.overflow {
                return Reason::NoRow;
            }
            if self.len == 0 {
                return if self.open_without_rows { Reason::OpenWithoutRows } else { Reason::NoRows };
            }
            for r in self.rows() {
                if r.vid.is_none_or(|v| v == vid) && r.pid.is_none_or(|p| p == pid) && r.class.is_none_or(|c| c == class) {
                    return if r.allow { Reason::Row } else { Reason::RowRefuses };
                }
            }
            Reason::NoRow
        }
    }
}

/// Write the decision record: `triple` is the interface's class, subclass and
/// protocol.
pub fn record(root_port: u8, vid_pid: u32, triple: u32, reason: Reason) {
    let verdict = if reason.admitted() { Verdict::Admit } else { Verdict::Refuse };
    azos_decision::record(Rule::UsbAuthorize, verdict, root_port as u32, [vid_pid as u64, triple as u64, reason as u64]);
}
