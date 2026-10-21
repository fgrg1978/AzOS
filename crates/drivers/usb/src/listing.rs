// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `lsusb`-style listing: the first class driver, and the proof that the
//! class-driver interface carries a real one.
//!
//! [`Lister`] is a watcher ([`Scope::Device`], matches every device). The core
//! offers it each device that finishes enumeration through
//! [`UsbClass::attach`] and tells it when the device goes through
//! [`UsbClass::detach`]; it keeps one [`Row`] per device slot. It claims no
//! interface and opens no pipe, so it holds exactly what a device-scope claim
//! grants: the identity the core passed. The rows are not a file: the kernel
//! publishes them through the introspection tree
//! (`usb/dev0 .. devN`, behind the crate feature `inspect`), and a reader
//! walks the tree with loads.
//!
//! ```text
//! usb/devices                      devices present
//! usb/changes                      attach and detach events seen
//! usb/devN/{present, vendor, product, class, speed, root_port}   N = slot - 1
//! ```
//!
//! The tree has a fixed shape (one `devN` per slot of the device table), so a
//! plug or an unplug rewrites values and never rebuilds the tree. Each slot
//! costs 7 nodes (`INSPECT_PUBLIC_PAGES` holds about 32 per page); `class` is
//! the device descriptor's class, 9 for a hub.

use azos_devif::outcome::OK;
use azos_devif::Out;

use crate::class::{Claim, Match, UsbClass};
use crate::MAX_DEVICES;

/// One device, as the lister saw it attach.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub present: bool,
    pub slot: u8,
    pub vendor: u16,
    pub product: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// The slot context's speed number (1 full, 2 low, 3 high, 4 super, 5
    /// super plus).
    pub speed: u8,
    pub root_port: u8,
}

pub struct Lister {
    rows: [Row; MAX_DEVICES],
    /// Attach and detach events seen, for a reader to tell that something
    /// changed.
    changes: u64,
}

impl Lister {
    pub const fn new() -> Lister {
        Lister { rows: [Row { present: false, slot: 0, vendor: 0, product: 0, class: 0, subclass: 0, protocol: 0, speed: 0, root_port: 0 }; MAX_DEVICES], changes: 0 }
    }

    /// The rule to register it under.
    pub const fn rule() -> Match {
        Match::every_device()
    }

    pub fn rows(&self) -> &[Row; MAX_DEVICES] {
        &self.rows
    }
    pub fn present(&self) -> usize {
        self.rows.iter().filter(|r| r.present).count()
    }
    pub fn changes(&self) -> u64 {
        self.changes
    }
}

impl Default for Lister {
    fn default() -> Self {
        Lister::new()
    }
}

impl UsbClass for Lister {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        let c = Claim(claim);
        let Some(row) = self.rows.get_mut((c.slot() as usize).wrapping_sub(1)) else {
            return Out::new(azos_devif::outcome::BAD_ARGUMENT, 0);
        };
        *row = Row {
            present: true,
            slot: c.slot(),
            vendor: (vid_pid >> 16) as u16,
            product: vid_pid as u16,
            class: (triple >> 16) as u8,
            subclass: (triple >> 8) as u8,
            protocol: triple as u8,
            speed: (speed_port >> 8) as u8,
            root_port: speed_port as u8,
        };
        self.changes += 1;
        Out::new(OK, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        let c = Claim(claim);
        if let Some(row) = self.rows.get_mut((c.slot() as usize).wrapping_sub(1)) {
            *row = Row::default();
            self.changes += 1;
        }
        Out::new(OK, 0)
    }
}

#[cfg(feature = "inspect")]
pub use tree::{build, refresh, Ids};

#[cfg(feature = "inspect")]
mod tree {
    use super::{Lister, MAX_DEVICES};
    use azos_inspect::{Builder, Error, NodeId, Writer};
    use core::fmt::Write as _;

    /// The nodes the refresh writes.
    pub struct Ids {
        devices: NodeId,
        changes: NodeId,
        dev: [DevIds; MAX_DEVICES],
    }

    #[derive(Clone, Copy)]
    struct DevIds {
        present: NodeId,
        vendor: NodeId,
        product: NodeId,
        class: NodeId,
        speed: NodeId,
        root_port: NodeId,
    }

    struct Name {
        buf: [u8; 12],
        len: usize,
    }

    impl core::fmt::Write for Name {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let b = s.as_bytes();
            if self.len + b.len() > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
            Ok(())
        }
    }

    fn dev_name(i: usize) -> Name {
        let mut n = Name { buf: [0; 12], len: 0 };
        let _ = write!(n, "dev{i}");
        n
    }

    /// Build the `usb` subtree under the tree's root.
    pub fn build(b: &mut Builder<'_, '_>, parent: NodeId) -> Result<Ids, Error> {
        let usb = b.dir(parent, "usb")?;
        let devices = b.u64(usb, "devices", 0)?;
        let changes = b.u64(usb, "changes", 0)?;
        let none = devices;
        let mut dev = [DevIds {
            present: none,
            vendor: none,
            product: none,
            class: none,
            speed: none,
            root_port: none,
        }; MAX_DEVICES];
        for (i, d) in dev.iter_mut().enumerate() {
            let n = dev_name(i);
            let dir = b.dir(usb, core::str::from_utf8(&n.buf[..n.len]).unwrap_or("dev"))?;
            *d = DevIds {
                present: b.u64(dir, "present", 0)?,
                vendor: b.u64(dir, "vendor", 0)?,
                product: b.u64(dir, "product", 0)?,
                class: b.u64(dir, "class", 0)?,
                speed: b.u64(dir, "speed", 0)?,
                root_port: b.u64(dir, "root_port", 0)?,
            };
        }
        Ok(Ids { devices, changes, dev })
    }

    /// Write every value from the lister's rows; the number of values that
    /// could not be written.
    pub fn refresh(w: &Writer<'_>, ids: &Ids, l: &Lister) -> u32 {
        let mut bad = 0;
        let mut put = |id: NodeId, v: u64| {
            if w.set_u64(id, v).is_err() {
                bad += 1;
            }
        };
        put(ids.devices, l.present() as u64);
        put(ids.changes, l.changes());
        for (d, r) in ids.dev.iter().zip(l.rows()) {
            put(d.present, r.present as u64);
            put(d.vendor, r.vendor as u64);
            put(d.product, r.product as u64);
            put(d.class, r.class as u64);
            put(d.speed, r.speed as u64);
            put(d.root_port, r.root_port as u64);
        }
        bad
    }
}
