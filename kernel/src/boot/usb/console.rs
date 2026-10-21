// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The console over a USB serial line (Kconfig `USB_CDC_CONSOLE`).
//!
//! When a CDC-ACM function comes up, the kernel holds its `Uart` port itself
//! (`azos_syscall::devices::attach_client`, a client with no queues) and this
//! file is that client, in both directions:
//!
//! - **Input.** What the device sends goes into the console's RX ring
//!   (`azos_drv_sys::uart::rx_push`), the one owner of console input, exactly
//!   where a UART byte or a USB keyboard's key ends: the shell reads it with
//!   no UART at all, and the console's parked reader is woken. `^C`
//!   interception, the single input owner and a lent console work as for any
//!   other source. Like the HID sink, the bytes are pushed with interrupts
//!   masked on the hart (the other producers run in an interrupt handler and
//!   the ring's producer lock is taken with interrupts already off), and the
//!   reader is woken afterwards.
//! - **Output.** Every byte the console is given (kernel lines, a ring-3
//!   `write(1, ..)`, the shell's echo) passes the console tap
//!   (`azos_drv_sys::uart::set_console_tee`), which may run in an interrupt
//!   handler or with locks held. [`tee`] therefore only copies the bytes, with
//!   `\n` as `\r\n`, into a ring of `USB_CDC_CONSOLE_BYTES` behind a leaf spin
//!   lock, a few at a time so a long write keeps interrupts masked for no
//!   longer than 64 bytes; nothing waits and nothing is woken. The pump task
//!   (`dev-pump`) drains it into chunks, polling every `DEVIF_PUMP_POLL_US`
//!   while the console is attached. A full ring drops the newest bytes and
//!   counts them: the count is the port's `tx_lost` (`Uart::status`), the same
//!   rule the UART's deferred buffer follows (the console never stalls a
//!   writer).
//!
//! The tap does nothing while no line is bound ([`BOUND`]): a machine whose
//! console is its UART pays one relaxed load per console write.
//!
//! Nothing here is printed from inside the lock: a line printed under it would
//! come back through the tap.

use core::sync::atomic::{AtomicBool, Ordering};

use azos_arch::Interrupts;
use azos_devif::uart::{Chunk, CHUNK_DATA};
use azos_sync::SpinLock;
use azos_syscall::devices::PortClient;

/// Bytes the tap keeps for the line.
const RING: usize = azos_limits::USB_CDC_CONSOLE_BYTES as usize;

/// Bytes the tap copies per lock hold.
const TEE_STEP: usize = 64;

/// A line is bound: the tap copies. Set after the table accepted the client,
/// cleared before the line is withdrawn.
static BOUND: AtomicBool = AtomicBool::new(false);

struct Ring {
    buf: [u8; RING],
    head: usize,
    len: usize,
    lost: u32,
}

impl Ring {
    const fn new() -> Ring {
        Ring { buf: [0; RING], head: 0, len: 0, lost: 0 }
    }

    fn push(&mut self, b: u8) {
        if self.len == RING {
            self.lost = self.lost.wrapping_add(1);
            return;
        }
        self.buf[(self.head + self.len) % RING] = b;
        self.len += 1;
    }

    /// Up to a chunk of the oldest bytes.
    fn take(&mut self) -> Option<Chunk> {
        let n = self.len.min(CHUNK_DATA);
        if n == 0 {
            return None;
        }
        let mut d = [0u8; CHUNK_DATA];
        for (i, slot) in d[..n].iter_mut().enumerate() {
            *slot = self.buf[(self.head + i) % RING];
        }
        self.head = (self.head + n) % RING;
        self.len -= n;
        Some(Chunk::new(&d[..n], 0))
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.lost = 0;
    }
}

static OUT: SpinLock<Ring> = SpinLock::new(Ring::new());

/// The console tap (`azos_drv_sys::uart::set_console_tee`): queue `bytes` for
/// the line. Any context.
pub(super) fn tee(bytes: &[u8]) {
    if !BOUND.load(Ordering::Relaxed) {
        return;
    }
    for piece in bytes.chunks(TEE_STEP) {
        let mut r = OUT.lock_irqsave();
        for &b in piece {
            if b == b'\n' {
                r.push(b'\r');
            }
            r.push(b);
        }
    }
}

/// The kernel's client of the serial port.
pub(super) struct Console;

/// The one client (the table keeps a reference to it).
pub(super) static CONSOLE: Console = Console;

/// Start tapping: output from now on is for the line, input from the line is
/// the console's. The ring starts empty (a device plugged in later does not get
/// the history of an earlier one).
pub(super) fn bind() {
    OUT.lock_irqsave().clear();
    BOUND.store(true, Ordering::Release);
}

/// Stop tapping (the line is going away).
pub(super) fn unbind() {
    BOUND.store(false, Ordering::Release);
    OUT.lock_irqsave().clear();
}

impl PortClient for Console {
    fn rx(&self, chunk: &Chunk) -> bool {
        let irq = azos_arch::ARCH.disable_all();
        let mut woke = false;
        for &b in chunk.bytes() {
            woke |= azos_drv_sys::uart::rx_push(b);
        }
        azos_arch::ARCH.restore(irq);
        if woke {
            super::super::console_rx_wake();
        }
        true
    }

    fn tx(&self) -> Option<Chunk> {
        OUT.lock_irqsave().take()
    }

    fn lost(&self) -> u32 {
        OUT.lock_irqsave().lost
    }
}
