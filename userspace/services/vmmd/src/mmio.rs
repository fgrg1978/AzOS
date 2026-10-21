// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio-mmio transport, version 2 (virtio 1.x, section 4.2).
//!
//! One [`Transport`] fronts one [`Device`] in a `0x200`-byte window of the
//! guest-physical space: the register file below `0x100`, the device's
//! configuration space above it. Version 2 is the modern, little-endian
//! interface: `VIRTIO_F_VERSION_1` is mandatory (a driver that does not
//! accept it has its `FEATURES_OK` refused), so the net header is the 12-byte
//! one.
//!
//! The registers are 32-bit and accessed that way; a register access of
//! another width or alignment is dropped (reads 0), which is what a bus that
//! does not decode it would do. The configuration space takes 1, 2, 4 and
//! 8-byte accesses.
//!
//! # Bring-up order
//!
//! `DRIVER_OK` only takes effect on a device whose `FEATURES_OK` the device
//! itself granted: a driver that writes `DRIVER_OK` first, or keeps it after
//! a refused `FEATURES_OK`, finds the bit not set and the queues never served.
//! `FEATURES_OK` is granted once and then sticks until a reset (the features
//! are frozen under a running device). So a served device always negotiated
//! `VERSION_1` and nothing the device did not offer, and the devices can take
//! the 12-byte net header (`num_buffers` included) as the only one there is:
//! no offered feature changes the header's size.
//!
//! The guest can wedge its own device and nothing else: a queue the driver
//! turns on is checked ([`Virtq::valid`]), a queue found corrupt flags the
//! device `NEEDS_RESET` and raises the configuration-change interrupt, and
//! nothing is processed again until the driver resets the device by writing 0
//! to `Status`.

use crate::guest::GuestMem;
use crate::virtq::{Virtq, VqError, QUEUE_MAX};

/// Bytes a device's window spans.
pub const WINDOW: u64 = 0x200;
const CONFIG: u64 = 0x100;

const MAGIC: u32 = 0x7472_6976; // "virt"
const VENDOR: u32 = 0x534F_7A41; // "AzOS"

mod reg {
    pub const MAGIC: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    pub const CONFIG_GENERATION: u64 = 0x0fc;
}

/// `Status` bits.
pub mod status {
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const NEEDS_RESET: u32 = 0x40;
    pub const FAILED: u32 = 0x80;
}

/// `InterruptStatus` bits.
const INT_USED: u32 = 1;
const INT_CONFIG: u32 = 2;

/// Feature bit 32: the modern interface.
pub const F_VERSION_1: u64 = 1 << 32;

/// Queues a device may have.
pub const MAX_QUEUES: usize = 2;

/// A virtio device behind a [`Transport`].
pub trait Device {
    /// The virtio device id (1 net, 2 block, 3 console).
    fn id(&self) -> u32;
    /// The feature bits offered, [`F_VERSION_1`] among them.
    fn features(&self) -> u64;
    /// Queues in use (at most [`MAX_QUEUES`]).
    fn queues(&self) -> usize;
    /// Read the configuration space at `off` (bytes past its end read 0).
    fn read_config(&self, off: usize, out: &mut [u8]);
    /// The driver kicked queue `q`. `Ok(true)`: buffers went back to it, the
    /// guest is to be interrupted.
    fn notify(&mut self, q: usize, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError>;
    /// Something happened on the host side (a frame arrived, the console has
    /// input) or work was left over: fill the buffers the driver offered for
    /// it. Same answer as [`Device::notify`].
    fn poll(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError>;
    /// Is a request still in flight, parked until the next [`Device::poll`]
    /// (the device spent its work budget on it)?
    fn busy(&self) -> bool {
        false
    }
    /// The driver reset the device: drop whatever was in flight, for it
    /// belonged to queues that are gone.
    fn reset(&mut self) {}
}

/// A device and its register file.
pub struct Transport<D: Device> {
    pub dev: D,
    status: u32,
    dev_feat_sel: u32,
    drv_feat_sel: u32,
    drv_feat: u64,
    queue_sel: u32,
    vqs: [Virtq; MAX_QUEUES],
    int_status: u32,
    /// Register accesses dropped for their width or alignment.
    pub bad_accesses: u32,
}

impl<D: Device> Transport<D> {
    pub fn new(dev: D) -> Self {
        Transport {
            dev,
            status: 0,
            dev_feat_sel: 0,
            drv_feat_sel: 0,
            drv_feat: 0,
            queue_sel: 0,
            vqs: [Virtq::EMPTY; MAX_QUEUES],
            int_status: 0,
            bad_accesses: 0,
        }
    }

    /// Is the interrupt line asserted?
    pub fn irq_level(&self) -> bool {
        self.int_status != 0
    }

    fn running(&self) -> bool {
        self.status & status::DRIVER_OK != 0 && self.status & (status::NEEDS_RESET | status::FAILED) == 0
    }

    fn reset(&mut self) {
        self.dev.reset();
        self.status = 0;
        self.dev_feat_sel = 0;
        self.drv_feat_sel = 0;
        self.drv_feat = 0;
        self.queue_sel = 0;
        self.int_status = 0;
        for q in &mut self.vqs {
            q.reset();
        }
    }

    /// A queue was found corrupt: stop serving and tell the driver.
    fn needs_reset(&mut self) {
        self.status |= status::NEEDS_RESET;
        self.int_status |= INT_CONFIG;
    }

    fn served(&mut self, r: Result<bool, VqError>) {
        match r {
            Ok(true) => self.int_status |= INT_USED,
            Ok(false) => {}
            Err(_) => self.needs_reset(),
        }
    }

    /// Is a request of the device parked for the next pass?
    pub fn busy(&self) -> bool {
        self.running() && self.dev.busy()
    }

    /// Host-side work (see [`Device::poll`]).
    pub fn poll(&mut self, mem: &mut dyn GuestMem) {
        if self.running() {
            let r = self.dev.poll(&mut self.vqs, mem);
            self.served(r);
        }
    }

    /// One access to the window at `off`, `len` bytes wide; `val` is what a
    /// write stores. Returns what a read gives.
    pub fn access(&mut self, off: u64, write: bool, len: usize, val: u64, mem: &mut dyn GuestMem) -> u64 {
        if off >= CONFIG {
            return self.config(off - CONFIG, write, len);
        }
        if len != 4 || off % 4 != 0 {
            self.bad_accesses += 1;
            return 0;
        }
        if write {
            self.write_reg(off, val as u32, mem);
            0
        } else {
            self.read_reg(off) as u64
        }
    }

    /// The configuration space is read-only: every field the models offer is
    /// fixed by the host, so a write is dropped.
    fn config(&mut self, off: u64, write: bool, len: usize) -> u64 {
        if !matches!(len, 1 | 2 | 4 | 8) || off % len as u64 != 0 {
            self.bad_accesses += 1;
            return 0;
        }
        if write {
            return 0;
        }
        let mut b = [0u8; 8];
        self.dev.read_config(off as usize, &mut b[..len]);
        u64::from_le_bytes(b)
    }

    fn q(&self) -> Option<&Virtq> {
        self.vqs.get(self.queue_sel as usize).filter(|_| (self.queue_sel as usize) < self.dev.queues())
    }

    fn q_mut(&mut self) -> Option<&mut Virtq> {
        let ok = (self.queue_sel as usize) < self.dev.queues();
        self.vqs.get_mut(self.queue_sel as usize).filter(|_| ok)
    }

    fn read_reg(&self, off: u64) -> u32 {
        match off {
            reg::MAGIC => MAGIC,
            reg::VERSION => 2,
            reg::DEVICE_ID => self.dev.id(),
            reg::VENDOR_ID => VENDOR,
            reg::DEVICE_FEATURES => (self.dev.features() >> (32 * (self.dev_feat_sel & 1))) as u32,
            reg::QUEUE_NUM_MAX => self.q().map_or(0, |_| QUEUE_MAX as u32),
            reg::QUEUE_READY => self.q().map_or(0, |q| q.ready as u32),
            reg::INTERRUPT_STATUS => self.int_status,
            reg::STATUS => self.status,
            reg::CONFIG_GENERATION => 0,
            _ => 0,
        }
    }

    fn write_reg(&mut self, off: u64, v: u32, mem: &mut dyn GuestMem) {
        match off {
            reg::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
            reg::DRIVER_FEATURES_SEL => self.drv_feat_sel = v,
            reg::DRIVER_FEATURES if self.status & status::FEATURES_OK == 0 => {
                let sh = 32 * (self.drv_feat_sel & 1);
                self.drv_feat = (self.drv_feat & !(0xFFFF_FFFFu64 << sh)) | (v as u64) << sh;
            }
            reg::QUEUE_SEL => self.queue_sel = v,
            reg::QUEUE_NUM => {
                if let Some(q) = self.q_mut().filter(|q| !q.ready) {
                    q.num = v.min(u16::MAX as u32) as u16;
                }
            }
            reg::QUEUE_READY => {
                let valid = self.q().is_some_and(|q| q.valid(mem));
                if let Some(q) = self.q_mut() {
                    if v & 1 == 0 {
                        let (num, d, a, u) = (q.num, q.desc, q.avail, q.used);
                        q.reset();
                        (q.num, q.desc, q.avail, q.used) = (num, d, a, u);
                    } else if valid {
                        q.ready = true;
                    }
                }
            }
            reg::QUEUE_NOTIFY => {
                let q = v as usize;
                if self.running() && q < self.dev.queues() && self.vqs[q].ready {
                    let r = self.dev.notify(q, &mut self.vqs, mem);
                    self.served(r);
                }
            }
            reg::INTERRUPT_ACK => self.int_status &= !v,
            reg::STATUS => self.write_status(v),
            reg::QUEUE_DESC_LOW => self.set_addr(v, false, |q| &mut q.desc),
            reg::QUEUE_DESC_HIGH => self.set_addr(v, true, |q| &mut q.desc),
            reg::QUEUE_DRIVER_LOW => self.set_addr(v, false, |q| &mut q.avail),
            reg::QUEUE_DRIVER_HIGH => self.set_addr(v, true, |q| &mut q.avail),
            reg::QUEUE_DEVICE_LOW => self.set_addr(v, false, |q| &mut q.used),
            reg::QUEUE_DEVICE_HIGH => self.set_addr(v, true, |q| &mut q.used),
            _ => {}
        }
    }

    fn set_addr(&mut self, v: u32, high: bool, field: impl FnOnce(&mut Virtq) -> &mut u64) {
        if let Some(q) = self.q_mut().filter(|q| !q.ready) {
            let f = field(q);
            *f = if high { (*f & 0xFFFF_FFFF) | (v as u64) << 32 } else { (*f & !0xFFFF_FFFF) | v as u64 };
        }
    }

    fn write_status(&mut self, v: u32) {
        if v == 0 {
            self.reset();
            return;
        }
        let mut s = v;
        // The device keeps what it has flagged, and what it granted; the
        // driver cannot clear either without a reset.
        s |= self.status & (status::NEEDS_RESET | status::FAILED | status::FEATURES_OK);
        if s & status::FEATURES_OK != 0 && self.status & status::FEATURES_OK == 0 {
            let offered = self.dev.features();
            if self.drv_feat & !offered != 0 || self.drv_feat & F_VERSION_1 == 0 {
                s &= !status::FEATURES_OK;
            }
        }
        // Queues are served only on features the device accepted.
        #[cfg(not(feature = "canary-driver-ok-unchecked"))]
        if s & status::FEATURES_OK == 0 {
            s &= !status::DRIVER_OK;
        }
        self.status = s;
    }
}
