// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's side of the USB HID class driver (Kconfig `USB_HID`).
//!
//! The driver itself is `azos_usb_hid` (crates/drivers/usb-hid), pure and
//! host-tested against the xHCI mock. What only the kernel can do is where its
//! events end: [`KernelSink`] runs every key event through the console's
//! keymap (`azos_drv_input::keymap::route`, one [`Keymap`] per interface for
//! its modifier state) and puts the result in the same places the PS/2 and
//! virtio-input drivers end in: a console byte in the UART's RX ring
//! (`azos_drv_sys::uart::rx_push`, the one owner of console input, so the shell
//! reads a USB keyboard with no UART and no PS/2) or a packed event in the ring
//! the ring-3 terminal server drains (`azos_drv_input::events`) while the
//! console holds the focus, and the input server's stream alone while a task
//! holds it (Kconfig `INPUTD`, `events::console_holds`).
//!
//! **Context.** The other producers run in an interrupt handler with interrupts
//! off; the `usb` task calls the sink from task context. Both rings are written
//! under locks taken with interrupts already off (`RX_PRODUCER_LOCK`, the event
//! ring's), so an interrupt arriving while the task held one on the same hart
//! would spin on it for good. Every event is therefore pushed with interrupts
//! masked on the hart ([`Interrupts::disable_all`]) for the few stores it takes,
//! and the task wakes the console's parked reader afterwards
//! ([`super::console_rx_wake`]), as an interrupt arm does.

use azos_arch::Interrupts;
use azos_drv_input::events;
use azos_drv_input::keymap::{route, Keymap, Route, EV_KEY};
use azos_input_wire::event::pack;
use azos_sync::kmutex::Mutex;
use azos_usb::class::UsbClassDirect;
use azos_usb_hid::driver::MAX_BINDS;
use azos_usb_hid::{HidClass, Policy, Sink};

use crate::kprintln;

/// Where the events of the HID interfaces end.
pub(crate) struct KernelSink {
    keymaps: [Keymap; MAX_BINDS],
    /// Console bytes queued, or the terminal server nudged, since the last
    /// [`KernelSink::take_wake`]: the parked reader is owed a wake.
    wake: bool,
}

impl KernelSink {
    const fn new() -> KernelSink {
        KernelSink { keymaps: [Keymap::new(); MAX_BINDS], wake: false }
    }

    /// Is the console's reader owed a wake? Clears the debt.
    pub(crate) fn take_wake(&mut self) -> bool {
        core::mem::take(&mut self.wake)
    }
}

impl Sink for KernelSink {
    fn event(&mut self, dev: u8, ty: u16, code: u16, value: u32) {
        let Some(km) = self.keymaps.get_mut(dev as usize) else { return };
        let irq = azos_arch::ARCH.disable_all();
        let console = events::console_holds();
        let r = route(km, ty, code, value, console);
        if r == Route::Attention {
            events::attention();
        }
        match r {
            // A full console ring (or one not live yet) drops the byte, as it does
            // for the UART: the user types it again.
            Route::Byte(b) => {
                events::observe(pack(ty, code, value), true);
                self.wake |= azos_drv_sys::uart::rx_push(b)
            }
            // A swallowed key event (the release of a key that made a byte)
            // still belongs to the input server's stream.
            Route::Consumed => {
                if ty == EV_KEY {
                    events::observe(pack(ty, code, value), true);
                }
            }
            // A task holds the focus: the holder's, through the stream.
            Route::Withheld => events::observe(pack(ty, code, value), false),
            Route::Publish | Route::Attention => {
                // A full event ring drops the event and counts it (the ring's own
                // drop counter, which the terminal server resynchronizes on).
                let r = events::publish(pack(ty, code, value), console);
                if r.wake() {
                    azos_drv_sys::uart::rx_nudge();
                    self.wake = true;
                }
            }
        }
        azos_arch::ARCH.restore(irq);
    }

    fn gone(&mut self, dev: u8) {
        if let Some(km) = self.keymaps.get_mut(dev as usize) {
            *km = Keymap::new();
        }
    }
}

/// The driver and its sink, held for a service turn of the `usb` task.
pub(crate) struct Hid {
    pub(crate) class: UsbClassDirect<HidClass<'static>>,
    pub(crate) sink: KernelSink,
    /// Interfaces whose reports were flowing at the last turn, to print a change.
    running: usize,
}

/// The one HID driver of the one USB host. Static: it is about 15 KiB.
pub(crate) static HID: Mutex<Hid> = Mutex::new(Hid {
    class: UsbClassDirect(HidClass::new(&super::usb::RINGS, Policy::BUILD)),
    sink: KernelSink::new(),
    running: 0,
});

impl Hid {
    /// After the core's service: advance the interfaces, decode what arrived,
    /// wake the console's reader if input came.
    pub(crate) fn poll<R, M, C>(&mut self, usb: &mut azos_usb::usbcore::Usb<'static, R, M, C>)
    where
        R: azos_usb::hw::Regs,
        M: azos_usb::hw::Memory,
        C: azos_usb::hw::Clock,
    {
        let now_ms = azos_drv_sys::timebase::now().saturating_mul(1000) / azos_drv_sys::timebase::TIMER_FREQ;
        self.class.0.poll(usb, now_ms, &mut self.sink);
        let running = self.class.0.running();
        if running != self.running {
            kprintln!("[USB-HID] {} interface(s) delivering reports", running);
            self.running = running;
        }
        if self.sink.take_wake() {
            super::console_rx_wake();
        }
    }
}
