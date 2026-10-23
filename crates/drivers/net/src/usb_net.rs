// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A USB network function as a NIC of the network device table (cargo feature
//! `usb-net`): a CDC-ECM or CDC-NCM function (`azos_usb::class::cdc`, Kconfig
//! `USB_CDC`) or an SMSC LAN95xx one (`azos_usb::class::smsc95xx`, Kconfig
//! `USB_SMSC95XX`), each an `azos_usb::class::net::NetFunction`.
//!
//! The protocol is the class driver's (descriptors or registers, setup, the
//! bulk pipes; pure and host-tested against an xHCI mock); this file is what
//! the kernel adds, as `block/src/usb_msc.rs` does for a stick: one lock
//! around the protocol, the [`NetDevice`] it implements, and the class-driver
//! handle the USB core is given.
//!
//! # Who runs it
//!
//! The protocol sits behind a sleeping mutex, not a spinlock: opening the
//! function's pipes goes through the core's controller commands, which sleep.
//! Every other use of it is short and never waits for the device.
//!
//! Two parties turn the crank, and both only ever push to or pop from the
//! pipes' rings:
//!
//! - the `usb` task runs the core's `service`, then [`UsbNic::drive`]: it
//!   opens the pipes of the claims the core just handed over, advances the
//!   setup, reaps completions, and reports when the NIC came up or went away
//!   (the caller then [`register_usb`](crate::net_device::register_usb)s or
//!   [`unregister_usb`](crate::net_device::unregister_usb)s it);
//! - the network stack: [`NetDevice::send`] puts a frame (or a block of them)
//!   into the bulk-OUT ring and [`NetDevice::recv`] takes frames out of the
//!   buffers bulk-IN completed. Each time something went into a ring the `usb`
//!   task is woken (the `kick` given at construction), so a frame costs the
//!   controller's time, not `USB_POLL_MS`.
//!
//! The core moves completions on its own turn, which the `usb` task runs every
//! `USB_POLL_MS` and whenever kicked: reception is polled at that period. No
//! interrupt reaches the network poller from here, so after each turn the
//! `usb` task wakes it when [`UsbNic::rx_pending`] says frames wait
//! (`kernel/src/boot/usb.rs`).
//!
//! The class driver is registered with the core once per rule of the function
//! ([`NetFunction::RULES`]: a CDC function's two interfaces, a vendor
//! function's one), through as many [`NicClass`] handles.

use azos_devif::Out;
use azos_drv_api::net::{NetDevice, NetError};
use azos_sync::kmutex::Mutex;
use azos_usb::class::cdc::SendError;
use azos_usb::class::net::NetFunction;
use azos_usb::class::UsbClass;
use azos_usb::hw::{Clock, Memory, Regs};
use azos_usb::usbcore::Usb;

/// What [`UsbNic::drive`] saw happen to the function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    None,
    /// The function came up: register the NIC.
    Up,
    /// The function went away or failed: unregister the NIC.
    Down,
}

/// One USB network function.
pub struct UsbNic<F: NetFunction> {
    func: Mutex<F>,
    /// Wake the `usb` task: a transfer was queued.
    kick: fn(),
    /// The NIC was reported up and not yet down. Touched by the `usb` task only.
    up: core::sync::atomic::AtomicBool,
}

impl<F: NetFunction + Send> UsbNic<F> {
    pub fn new(func: F, kick: fn()) -> Self {
        UsbNic { func: Mutex::new(func), kick, up: core::sync::atomic::AtomicBool::new(false) }
    }

    /// A class driver to register with the USB core (once per rule): it
    /// takes this NIC's lock for each call, which the registry holds for a
    /// whole service call otherwise.
    pub fn class(&self) -> NicClass<'_, F> {
        NicClass(self)
    }

    /// Turn the crank from the `usb` task, after the core's turn: open the
    /// pipes of the claims the core handed over, advance the setup, reap what
    /// completed, and say whether the NIC came up or went away.
    pub fn drive<R: Regs, M: Memory, C: Clock>(&self, usb: &mut Usb<'_, R, M, C>) -> Event {
        use core::sync::atomic::Ordering;
        let ready = {
            let mut f = self.func.lock();
            while let Some(claim) = f.session_wanted() {
                let mut session = usb.session(claim);
                f.open(&mut session);
            }
            f.service();
            f.is_ready()
        };
        match (ready, self.up.swap(ready, Ordering::AcqRel)) {
            (true, false) => Event::Up,
            (false, true) => Event::Down,
            _ => Event::None,
        }
    }

    /// Look at the protocol under the lock (its state and counters, for the
    /// boot's lines and the tests).
    pub fn inspect<T>(&self, f: impl FnOnce(&F) -> T) -> T {
        f(&self.func.lock())
    }

    /// Do received frames wait for the stack? The `usb` task wakes the
    /// network poller on it after each turn.
    pub fn rx_pending(&self) -> bool {
        self.func.lock().rx_pending()
    }

    /// Run `f` on the protocol under the lock; wake the `usb` task if it
    /// queued a transfer.
    fn with<T>(&self, f: impl FnOnce(&mut F) -> T) -> T {
        let (r, submitted) = {
            let mut c = self.func.lock();
            let r = f(&mut c);
            (r, c.take_submitted())
        };
        if submitted {
            (self.kick)();
        }
        r
    }
}

impl<F: NetFunction + Send> NetDevice for UsbNic<F> {
    fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
        self.with(|c| c.send(frame)).map(|()| frame.len()).map_err(|e| match e {
            SendError::NotReady => NetError::NotReady,
            SendError::BadLength => NetError::BadLength,
            SendError::QueueFull => NetError::QueueFull,
        })
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.with(|c| if c.is_ready() { Ok(c.recv(buf)) } else { Err(NetError::NotReady) })
    }

    fn mac(&self) -> [u8; 6] {
        self.func.lock().mac()
    }

    fn is_ready(&self) -> bool {
        self.func.lock().is_ready()
    }

    fn tx_batch_begin(&self) {
        self.func.lock().tx_begin();
    }

    fn tx_batch_end(&self) {
        self.with(|c| c.tx_end());
    }
}

/// The class driver the USB core is given: it forwards to the NIC's protocol
/// under its lock.
pub struct NicClass<'a, F: NetFunction>(&'a UsbNic<F>);

impl<F: NetFunction + Send> UsbClass for NicClass<'_, F> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        self.0.func.lock().attach(claim, vid_pid, triple, speed_port)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        self.0.func.lock().detach(claim)
    }
}
