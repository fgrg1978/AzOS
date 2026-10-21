// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio-net backend (device id 1): a guest's NIC is one end of a
//! [`Link`], a virtual interface whose other end the host side owns.
//!
//! Frames cross as whole Ethernet frames, no offloads: the device offers
//! `MAC` and `STATUS` besides `VERSION_1`, so every buffer starts with the
//! 12-byte header (`virtio_net_hdr` with `num_buffers`) the modern interface
//! uses and the guest sends and receives plain frames.
//!
//! The guest is untrusted, so what it sends is bounded before the link sees
//! it: a frame larger than [`FRAME_MAX`] is dropped, and so is one whose
//! source address is not the MAC the guest was given (a guest does not speak
//! for another station), each counted. What the link then does with a frame is
//! under the authority of whoever holds its other end.
//!
//! Receive has no peek on the link, so one frame waits in the device until the
//! guest offers a buffer; a link that outpaces the guest sees its own queue
//! fill, not vmmd's.

use crate::guest::GuestMem;
use crate::mmio::{Device, F_VERSION_1, MAX_QUEUES};
use crate::virtq::{Virtq, VqError};

/// Bytes of the per-buffer header.
pub const HDR: usize = 12;
/// Largest frame carried (Ethernet header and 1500-byte payload, with room for a tag).
pub const FRAME_MAX: usize = 1536;

const F_MAC: u64 = 1 << 5;
const F_STATUS: u64 = 1 << 16;
const LINK_UP: u16 = 1;

/// The virtual interface a guest NIC is bridged to.
pub trait Link {
    /// Send a frame; `false` when the link dropped it.
    fn send(&mut self, frame: &[u8]) -> bool;
    /// Take the next received frame, if any.
    fn recv(&mut self, buf: &mut [u8]) -> Option<usize>;
}

/// The device.
pub struct Net<L: Link> {
    pub link: L,
    pub mac: [u8; 6],
    rx: [u8; FRAME_MAX],
    rx_len: usize,
    pub sent: u32,
    pub received: u32,
    /// Frames dropped on the way out: too large, too short or a foreign source.
    pub dropped_tx: u32,
    /// Frames dropped on the way in: the guest's buffer was too small.
    pub dropped_rx: u32,
}

impl<L: Link> Net<L> {
    pub fn new(link: L, mac: [u8; 6]) -> Self {
        Net { link, mac, rx: [0; FRAME_MAX], rx_len: 0, sent: 0, received: 0, dropped_tx: 0, dropped_rx: 0 }
    }

    fn transmit(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        let mut any = false;
        let mut buf = [0u8; HDR + FRAME_MAX];
        while let Some(chain) = vqs[1].pop(mem)? {
            let total = chain.readable();
            if total < (HDR + 14) as u64 || total > buf.len() as u64 {
                self.dropped_tx += 1;
            } else {
                let n = total as usize;
                chain.read_at(mem, 0, &mut buf[..n])?;
                let frame = &buf[HDR..n];
                // Ethernet: destination 0..6, source 6..12.
                if frame[6..12] != self.mac {
                    self.dropped_tx += 1;
                } else if self.link.send(frame) {
                    self.sent += 1;
                } else {
                    self.dropped_tx += 1;
                }
            }
            vqs[1].push_used(mem, &chain, 0)?;
            any = true;
        }
        Ok(any)
    }

    fn receive(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        let mut any = false;
        loop {
            if self.rx_len == 0 {
                match self.link.recv(&mut self.rx) {
                    Some(n) if n > 0 && n <= FRAME_MAX => self.rx_len = n,
                    _ => break,
                }
            }
            let Some(chain) = vqs[0].pop(mem)? else { break };
            let need = (HDR + self.rx_len) as u64;
            let mut written = 0;
            if chain.writable() >= need {
                let mut hdr = [0u8; HDR];
                hdr[10..12].copy_from_slice(&1u16.to_le_bytes()); // num_buffers
                chain.write_at(mem, 0, &hdr)?;
                chain.write_at(mem, HDR as u64, &self.rx[..self.rx_len])?;
                written = need as u32;
                self.received += 1;
            } else {
                self.dropped_rx += 1;
            }
            self.rx_len = 0;
            vqs[0].push_used(mem, &chain, written)?;
            any = true;
        }
        Ok(any)
    }
}

impl<L: Link> Device for Net<L> {
    fn id(&self) -> u32 {
        1
    }

    fn features(&self) -> u64 {
        F_VERSION_1 | F_MAC | F_STATUS
    }

    fn queues(&self) -> usize {
        2
    }

    /// `mac` (6 bytes) at 0, `status` (u16) at 6.
    fn read_config(&self, off: usize, out: &mut [u8]) {
        let mut cfg = [0u8; 8];
        cfg[..6].copy_from_slice(&self.mac);
        cfg[6..8].copy_from_slice(&LINK_UP.to_le_bytes());
        for (i, b) in out.iter_mut().enumerate() {
            *b = cfg.get(off + i).copied().unwrap_or(0);
        }
    }

    fn notify(&mut self, q: usize, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        // Queue 1 carries frames out; a kick on queue 0 offers receive buffers.
        if q == 1 { self.transmit(vqs, mem) } else { self.receive(vqs, mem) }
    }

    fn poll(&mut self, vqs: &mut [Virtq; MAX_QUEUES], mem: &mut dyn GuestMem) -> Result<bool, VqError> {
        self.receive(vqs, mem)
    }
}
