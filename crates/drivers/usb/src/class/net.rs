// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a USB network function is to the NIC adapter of the kernel
//! (`crates/drivers/net/src/usb_net.rs`): one trait, so a CDC-ECM/NCM
//! function ([`super::cdc::CdcNet`]) and a vendor one ([`super::smsc95xx`])
//! become a NIC through the same adapter, the same lock and the same turn of
//! the `usb` task.

use super::cdc::SendError;
use super::{Claim, Match, UsbClass, UsbDevice};

/// A network function's protocol, as the adapter drives it. Everything is
/// called under the adapter's lock; nothing here waits for the device.
pub trait NetFunction: UsbClass {
    /// The rules to register the class driver under, one registry entry each
    /// (a CDC function has two interfaces, a vendor one one).
    const RULES: &'static [Match];
    /// The claim to open a session for next; `None` when there is none.
    fn session_wanted(&self) -> Option<Claim>;
    /// Open the pipes of the claim [`NetFunction::session_wanted`] named.
    fn open(&mut self, dev: &mut dyn UsbDevice);
    /// Advance setup, reap completions, post receive buffers, clean up after
    /// an unplug.
    fn service(&mut self);
    fn is_ready(&self) -> bool;
    /// Received frames wait for the stack.
    fn rx_pending(&self) -> bool;
    /// A transfer went into a pipe since the last call.
    fn take_submitted(&mut self) -> bool;
    /// The function's MAC address; all-zero while it is not ready.
    fn mac(&self) -> [u8; 6];
    /// Queue a whole Ethernet frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), SendError>;
    /// The next received frame into `out`; its length, 0 when none waits.
    fn recv(&mut self, out: &mut [u8]) -> usize;
    /// Open and close a batch of sends (a function that packs frames into
    /// blocks shares one between them; others send each frame alone).
    fn tx_begin(&mut self);
    fn tx_end(&mut self);
}
