// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A USB serial function (CDC-ACM) as a port of the `Uart` table (Kconfig
//! `USB_CDC`).
//!
//! The protocol is `azos_usb::class::cdc::CdcAcm` (descriptors, setup, the
//! bulk pipes, DTR/RTS, SET_LINE_CODING; pure and host-tested against an xHCI
//! mock); this file is what the kernel adds, as `crates/drivers/net/src/usb_cdc.rs`
//! does for the network function: one lock around the protocol, the
//! [`SerialLine`] the `Uart` table hosts it as, and the class-driver handle the
//! USB core is given.
//!
//! # Who runs it
//!
//! The protocol sits behind a sleeping mutex, not a spinlock: opening the
//! function's pipes goes through the core's controller commands, which sleep.
//! Three parties use it, and none holds the lock across a wait for the device:
//!
//! - the `usb` task: [`UsbSerial::drive`] after each turn of the core opens the
//!   pipes of the claims the core handed over, advances the setup and the line
//!   requests, and reports when the function came up or went away (the caller
//!   then offers the line to the table, or withdraws it);
//! - a task that attached its queues to the port, or the kernel's console:
//!   the table's pump task calls [`SerialLine::pump`], which moves chunks
//!   between the pipes and the attached ends. It only **tries** the lock: while
//!   the `usb` task is opening pipes it has nothing to move, and the pump task
//!   also serves the companion-radio bridge and the converters;
//! - a task that configures, attaches, detaches or reads the status: the
//!   ordinary `Uart` calls.
//!
//! Each time something went into a pipe's ring the `usb` task is woken (the
//! `kick` given at construction), so a chunk costs the controller's time, not
//! `USB_POLL_MS`.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_devif::uart::{Chunk, ChunkSink, ChunkSource, RxQueue, Status, TxQueue};
use azos_devif::{Cap, Out};
use azos_sync::kmutex::Mutex;
use azos_syscall::devices::SerialLine;
use azos_usb::class::cdc::CdcAcm;
use azos_usb::class::{Match, UsbClass};
use azos_usb::hw::{Clock, Memory, Regs};
use azos_usb::usbcore::Usb;

/// What [`UsbSerial::drive`] saw happen to the function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    None,
    /// The function came up: offer it to the `Uart` table.
    Up,
    /// The function went away or failed: withdraw it.
    Down,
}

/// One USB serial function.
pub(super) struct UsbSerial<'q, M: Memory, C: Clock> {
    acm: Mutex<CdcAcm<'q, M, C>>,
    /// Wake the `usb` task: a transfer was queued.
    kick: fn(),
    /// The function was reported up and not yet down. Touched by the `usb` task
    /// only.
    up: AtomicBool,
}

impl<'q, M: Memory + Send, C: Clock + Send> UsbSerial<'q, M, C> {
    pub(super) fn new(acm: CdcAcm<'q, M, C>, kick: fn()) -> Self {
        UsbSerial { acm: Mutex::new(acm), kick, up: AtomicBool::new(false) }
    }

    /// The rules to register the class driver under, one registry entry each
    /// (the communications interface, then the data interface).
    pub(super) const fn rules() -> [Match; 2] {
        [CdcAcm::<'q, M, C>::comm_rule(), CdcAcm::<'q, M, C>::data_rule()]
    }

    /// A class driver to register with the USB core (call twice, one per rule):
    /// it takes this function's lock for each call, which the registry holds
    /// for a whole service call otherwise.
    pub(super) fn class(&self) -> SerialClass<'_, 'q, M, C> {
        SerialClass(self)
    }

    /// Turn the crank from the `usb` task, after the core's turn: open the
    /// pipes of the claims the core handed over, advance the setup and the
    /// line requests, and say whether the function came up or went away.
    pub(super) fn drive<R: Regs, M2: Memory, C2: Clock>(&self, usb: &mut Usb<'_, R, M2, C2>) -> Event {
        let ready = {
            let mut c = self.acm.lock();
            while let Some(claim) = c.session_wanted() {
                let mut session = usb.session(claim);
                c.open(&mut session);
            }
            c.service();
            c.is_ready()
        };
        match (ready, self.up.swap(ready, Ordering::AcqRel)) {
            (true, false) => Event::Up,
            (false, true) => Event::Down,
            _ => Event::None,
        }
    }

    /// Run `f` on the protocol under the lock; wake the `usb` task if it queued
    /// a transfer.
    fn with<T>(&self, f: impl FnOnce(&mut CdcAcm<'q, M, C>) -> T) -> T {
        let (r, submitted) = {
            let mut c = self.acm.lock();
            let r = f(&mut c);
            (r, c.take_submitted())
        };
        if submitted {
            (self.kick)();
        }
        r
    }
}

/// The table's chunk ends, as the protocol's generic `pump` takes them.
struct DynSink<'a>(&'a mut dyn ChunkSink);

impl ChunkSink for DynSink<'_> {
    fn push(&mut self, chunk: &Chunk) -> bool {
        self.0.push(chunk)
    }
}

struct DynSource<'a>(&'a mut dyn ChunkSource);

impl ChunkSource for DynSource<'_> {
    fn pop(&mut self) -> Option<Chunk> {
        self.0.pop()
    }
}

impl<'q, M: Memory + Send, C: Clock + Send> SerialLine for UsbSerial<'q, M, C> {
    fn configure(&self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()> {
        self.with(|c| azos_devif::Uart::configure(c, baud, data_bits, parity, stop_bits))
    }

    fn attach(&self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        self.with(|c| azos_devif::Uart::attach(c, rx, tx))
    }

    fn attach_kernel(&self) -> Out<()> {
        self.with(|c| c.attach_kernel())
    }

    fn detach(&self) -> Out<()> {
        self.with(|c| azos_devif::Uart::detach(c))
    }

    fn status(&self) -> Out<Status> {
        azos_devif::Uart::status(&*self.acm.lock())
    }

    fn pump(&self, rx: &mut dyn ChunkSink, tx: &mut dyn ChunkSource) -> usize {
        let (moved, submitted) = {
            let Some(mut c) = self.acm.try_lock() else { return 0 };
            let moved = c.pump(&mut DynSink(rx), &mut DynSource(tx));
            (moved, c.take_submitted())
        };
        if submitted {
            (self.kick)();
        }
        moved
    }
}

/// The class driver the USB core is given: it forwards to the function's
/// protocol under its lock.
pub(super) struct SerialClass<'a, 'q, M: Memory, C: Clock>(&'a UsbSerial<'q, M, C>);

impl<M: Memory + Send, C: Clock + Send> UsbClass for SerialClass<'_, '_, M, C> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        UsbClass::attach(&mut *self.0.acm.lock(), claim, vid_pid, triple, speed_port)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        UsbClass::detach(&mut *self.0.acm.lock(), claim)
    }
}
