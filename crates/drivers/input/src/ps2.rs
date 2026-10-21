// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PS/2 keyboard and mouse on the i8042 controller (x86_64), by interrupt.
//!
//! The shape of virtio-input (`azos_drv_virtio::virtio::input`): [`init`]
//! finds and brings up the hardware in task context, the kernel routes the
//! two ISA lines (IRQ1 keyboard, IRQ12 mouse; through the IOAPIC, honouring
//! the MADT overrides) and hands them over ([`set_irq_lines`]), then
//! [`enable_irqs`] lets the controller raise them. Each interrupt arm calls
//! [`irq`], which reads the controller dry and routes every byte on the spot:
//!
//! * keyboard bytes go through the set-2 decoder ([`super::scancode`]) to
//!   evdev key events and through the shared keymap ([`super::keymap::route`])
//!   to a console byte in the UART's RX ring ([`azos_drv_sys::uart::rx_push`]):
//!   the same ring, the same single owner of console input, so the
//!   shell reads a PS/2 keyboard with no UART input at all;
//! * keys with no byte, the modifier keys, and everything the mouse does (its
//!   three- or four-byte packets, [`super::mouse`]), are published into the
//!   shared event ring ([`super::events`]), which the ring-3 terminal server
//!   drains, and counted in [`stats`].
//!
//! The byte-level routing is [`super::stream`] (pure, host-tested); this file
//! is the port I/O, the lines and the counters.
//!
//! Presence is decided by the caller from the ACPI FADT (`IAPC_BOOT_ARCH`
//! bit 1, the 8042 flag: `Fadt::has_8042`) and then by the controller's own
//! self-test ([`super::i8042::init`]); a machine that fails either gets no driver
//! and no interrupts. On every other ISA the port accessors read a floating
//! bus, so [`init`] fails the same way and nothing else changes.
//!
//! Controller state is behind one lock taken only inside the handler
//! (interrupts off), after the lines are enabled; bring-up touches the ports
//! alone, before any line is enabled.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use azos_sync::SpinLock;

use super::events;
use super::i8042::{self, Fail, Found, Ports, PORT_CMD, PORT_DATA, ST_AUX, ST_OBF};
use super::keymap::{pack, BTN_MOUSE, EV_KEY, EV_REL};
use super::stream::{Out, Stream};

/// The PC's I/O ports; on another ISA, a bus that floats high.
struct Hw;

#[cfg(target_arch = "x86_64")]
impl Ports for Hw {
    #[inline(always)]
    fn inb(&mut self, port: u16) -> u8 {
        let v: u8;
        // SAFETY: a read of the i8042's own ports (0x60/0x64).
        unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
        v
    }
    #[inline(always)]
    fn outb(&mut self, port: u16, v: u8) {
        // SAFETY: a write to the i8042's own ports (0x60/0x64).
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl Ports for Hw {
    fn inb(&mut self, _port: u16) -> u8 { 0xFF }
    fn outb(&mut self, _port: u16, _v: u8) {}
}

/// Bytes read per interrupt at most (the output buffer is a few deep; the
/// bound keeps a stuck status bit from holding the CPU in the handler).
const IRQ_BATCH: usize = 32;

static STREAM: SpinLock<Stream> = SpinLock::new(Stream::new());

/// Set by [`init`]: what answered. Written once, before any line is enabled.
static FOUND: SpinLock<Option<Found>> = SpinLock::new(None);
static READY: AtomicBool = AtomicBool::new(false);

/// The wired lines (`u32::MAX`: not wired), read lock-free by the arm.
static LINE_KBD: AtomicU32 = AtomicU32::new(u32::MAX);
static LINE_AUX: AtomicU32 = AtomicU32::new(u32::MAX);

static IRQS: AtomicU32 = AtomicU32::new(0);
static KBD_BYTES: AtomicU32 = AtomicU32::new(0);
static KEY_BYTES: AtomicU32 = AtomicU32::new(0);
static BYTE_DROPS: AtomicU32 = AtomicU32::new(0);
static MOUSE_BYTES: AtomicU32 = AtomicU32::new(0);
static MOUSE_REL: AtomicU32 = AtomicU32::new(0);
static MOUSE_BTN: AtomicU32 = AtomicU32::new(0);
static PUBLISHED: AtomicU32 = AtomicU32::new(0);
static RING_DROPS: AtomicU32 = AtomicU32::new(0);

/// What the driver has seen since boot.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub irqs: u32,
    /// Raw bytes read from the keyboard port, and the console bytes they made.
    pub kbd_bytes: u32,
    pub key_bytes: u32,
    /// Key bytes the RX ring refused (full, or a `^C` taken by a lent console).
    pub byte_drops: u32,
    /// Raw bytes read from the mouse port, then relative-axis and button events.
    pub mouse_bytes: u32,
    pub rel: u32,
    pub buttons: u32,
    /// Events put in the shared event ring, and those it had no room for.
    pub published: u32,
    pub ring_drops: u32,
}

pub fn stats() -> Stats {
    Stats {
        irqs: IRQS.load(Ordering::Relaxed),
        kbd_bytes: KBD_BYTES.load(Ordering::Relaxed),
        key_bytes: KEY_BYTES.load(Ordering::Relaxed),
        byte_drops: BYTE_DROPS.load(Ordering::Relaxed),
        mouse_bytes: MOUSE_BYTES.load(Ordering::Relaxed),
        rel: MOUSE_REL.load(Ordering::Relaxed),
        buttons: MOUSE_BTN.load(Ordering::Relaxed),
        published: PUBLISHED.load(Ordering::Relaxed),
        ring_drops: RING_DROPS.load(Ordering::Relaxed),
    }
}

/// Probe and bring up the controller (task context, before any line is
/// enabled). `Ok((keyboard, mouse))`: which ports have a working device.
pub fn init() -> Result<(bool, bool), Fail> {
    let found = i8042::init(&mut Hw, azos_limits::PS2_WAIT_SPINS as u32)?;
    *FOUND.lock() = Some(found);
    STREAM.lock().set_wheel(found.wheel);
    READY.store(true, Ordering::Release);
    Ok((found.kbd, found.aux))
}

/// Hand the driver the lines the kernel routed (`u32::MAX`: none for that
/// port). Call BEFORE the interrupt controller unmasks them.
pub fn set_irq_lines(kbd: u32, aux: u32) {
    LINE_KBD.store(kbd, Ordering::Release);
    LINE_AUX.store(aux, Ordering::Release);
}

/// Let the controller raise its interrupts, after the lines are routed.
pub fn enable_irqs() -> Result<(), Fail> {
    let found = (*FOUND.lock()).ok_or(Fail::NoDevice)?;
    i8042::enable_irqs(&mut Hw, azos_limits::PS2_WAIT_SPINS as u32, &found)
}

/// Is `line` one of the wired lines?
pub fn owns_line(line: u32) -> bool {
    line != u32::MAX
        && (LINE_KBD.load(Ordering::Acquire) == line || LINE_AUX.load(Ordering::Acquire) == line)
}

/// One event of the mouse or of a key with no byte: published, and counted
/// whether the ring took it. `true` when the terminal server was asleep on the
/// ring and its console wait was nudged, so the caller wakes the parked reader.
fn publish(ty: u16, code: u16, value: u32) -> bool {
    let r = events::publish(pack(ty, code, value));
    if r.kept() {
        PUBLISHED.fetch_add(1, Ordering::Relaxed);
    } else {
        RING_DROPS.fetch_add(1, Ordering::Relaxed);
    }
    if r.wake() {
        azos_drv_sys::uart::rx_nudge();
    }
    r.wake()
}

/// The interrupt arm for `line` (interrupt context, interrupts off): `None`
/// when the line is not the PS/2 controller's. Otherwise read the controller
/// dry and route every byte. `Some(true)`: console bytes were queued, or the
/// terminal server slept on the event ring and was nudged, so the caller wakes
/// the console's parked reader (`uart::rx_waiter_take`). Both
/// lines run the same body: the status byte says which port each byte came
/// from, so a byte is never taken for the wrong device.
pub fn irq(line: u32) -> Option<bool> {
    if !owns_line(line) {
        return None;
    }
    if !READY.load(Ordering::Acquire) {
        return Some(false);
    }
    IRQS.fetch_add(1, Ordering::Relaxed);
    let mut st = STREAM.lock();
    let mut hw = Hw;
    let mut wake = false;
    for _ in 0..IRQ_BATCH {
        let status = hw.inb(PORT_CMD);
        if status & ST_OBF == 0 {
            break;
        }
        let b = hw.inb(PORT_DATA);
        let aux = status & ST_AUX != 0;
        if aux {
            MOUSE_BYTES.fetch_add(1, Ordering::Relaxed);
        } else {
            KBD_BYTES.fetch_add(1, Ordering::Relaxed);
        }
        st.feed(aux, b, |o| match o {
            Out::Byte(c) => {
                if azos_drv_sys::uart::rx_push(c) {
                    KEY_BYTES.fetch_add(1, Ordering::Relaxed);
                    wake = true;
                } else {
                    BYTE_DROPS.fetch_add(1, Ordering::Relaxed);
                }
            }
            // A key the console took: the input server's stream gets it, the
            // terminal server's ring does not.
            Out::Taken(code, value) => events::observe(pack(EV_KEY, code, value)),
            Out::Event(ty, code, value) => {
                if ty == EV_REL {
                    MOUSE_REL.fetch_add(1, Ordering::Relaxed);
                } else if ty == EV_KEY && code >= BTN_MOUSE {
                    MOUSE_BTN.fetch_add(1, Ordering::Relaxed);
                }
                wake |= publish(ty, code, value);
            }
        });
    }
    Some(wake)
}
