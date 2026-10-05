// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The console class: the output half of a console device, the one method
//! the ring-3 console write path dispatches through (`azos_drv_sys::uart`).

pub trait Console: Send + Sync {
    /// Write a whole slice to the device, FIFO-batched.
    ///
    /// May wait, so it is called only by a console owner with no lock held
    /// and interrupts in the caller's state. Once the TX interrupt is wired
    /// (`azos_drv_sys::uart::enable_tx_irq`) the platform UART's impl copies the bytes into
    /// the TX ring and waits only while the ring is full; before that it
    /// spins on the device's transmit-ready bit between FIFO loads.
    ///
    /// Does no `\n` → `\r\n` translation: that is `azos_drv_sys::uart::write_translated`'s
    /// job, one level up, so both implementations do not carry a copy of it.
    fn write_bytes(&self, bytes: &[u8]);
}
