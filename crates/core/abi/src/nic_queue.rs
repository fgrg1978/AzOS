// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 packet rings on a NIC queue: what a `ty::NIC_QUEUE` capability
//! names and the slot format of the two rings its attach
//! (`invoke::DEVICE_NICQ_ATTACH`) runs the queue on.
//!
//! The shape is netmap's and AF_XDP's: one pair of rings per NIC queue, in
//! memory the program and the kernel both map, and no call per frame on
//! receive. Each ring is an `azos_rings::region::SpscBytes` (the frames form
//! of the region rings) in a region the program made: the receive ring's
//! producer is the kernel, the transmit ring's is the program. Every slot's
//! payload starts with a [`Desc`] ([`DESC_BYTES`]), then the frame, Ethernet
//! header first and no FCS; the slot's own header (`SlotInfo`) carries the
//! payload length, the producer's sequence number and the stamp.
//!
//! # Stamps
//!
//! A received frame carries when it arrived, a sent one (on request,
//! [`TX_STAMP`]) when it left, in the slot header's `acq_ns`, with the
//! descriptor saying what the number is: [`STAMP_HW`] the NIC's own stamp
//! (in the clock of the NIC), [`STAMP_SW`] the kernel's, read at the driver
//! boundary (the frame taken off the NIC's receive ring, or just before it is
//! handed to the NIC's transmit ring), in ns of the monotonic clock. Neither
//! flag: no stamp.
//!
//! # Completions
//!
//! A transmit slot that asked for a stamp is answered on the receive ring by
//! a [`DESC_TX_DONE`] descriptor carrying the transmit slot's sequence number
//! ([`Desc::tx_seq`]) and no frame; [`TX_REFUSED`] says the frame did not
//! leave (shorter than an Ethernet header, longer than a slot, not from the
//! interface's MAC, or the NIC refused it).

/// Bytes of the [`Desc`] at the start of every slot's payload.
pub const DESC_BYTES: usize = 8;
/// The longest frame a slot carries: an Ethernet header, a 1500-byte payload
/// and a VLAN tag, no FCS.
pub const FRAME_MAX: usize = 1518;
/// Payload bytes of one slot: the descriptor and the longest frame.
pub const SLOT_PAYLOAD: usize = DESC_BYTES + FRAME_MAX;
/// The shortest frame the transmit ring may carry: an Ethernet header.
pub const FRAME_MIN: usize = 14;
/// Bytes of one slot of either ring: the 16-byte slot header
/// (`azos_rings::region::SLOT_HDR_BYTES`) and [`SLOT_PAYLOAD`], rounded up
/// to the 8 bytes a byte slot is a multiple of.
pub const SLOT_BYTES: u32 = ((16 + SLOT_PAYLOAD + 7) & !7) as u32;
/// Bytes of a ring's header before its first slot
/// (`azos_rings::region::RING_SLOTS`).
pub const RING_HEADER_BYTES: usize = 256;

/// Bytes a ring of `slots` slots needs: what a program sizes each region by
/// (the kernel lays out the largest power of two of slots that fits).
pub const fn ring_bytes(slots: u32) -> usize {
    RING_HEADER_BYTES + slots as usize * SLOT_BYTES as usize
}

/// [`Desc::kind`]: a frame the NIC received (receive ring).
pub const DESC_RX: u8 = 1;
/// [`Desc::kind`]: a frame to send (transmit ring).
pub const DESC_TX: u8 = 2;
/// [`Desc::kind`]: what became of a transmit slot that asked for it (receive
/// ring, no frame).
pub const DESC_TX_DONE: u8 = 3;

/// [`Desc::flags`]: the stamp is the NIC's.
pub const STAMP_HW: u8 = 1;
/// [`Desc::flags`]: the stamp is the kernel's, taken at the driver boundary.
pub const STAMP_SW: u8 = 2;
/// [`Desc::flags`] of a [`DESC_TX`]: answer with a [`DESC_TX_DONE`] carrying the
/// departure stamp.
pub const TX_STAMP: u8 = 4;
/// [`Desc::flags`] of a [`DESC_TX_DONE`]: the frame did not leave.
pub const TX_REFUSED: u8 = 8;

/// The descriptor at the start of a slot's payload, little-endian: `kind`
/// (byte 0), `flags` (byte 1), two bytes that are 0, `tx_seq` (bytes 4..8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Desc {
    /// `DESC_*`.
    pub kind: u8,
    /// `STAMP_*`, [`TX_STAMP`], [`TX_REFUSED`].
    pub flags: u8,
    /// Of a [`DESC_TX_DONE`]: the sequence number of the transmit slot it
    /// answers (that slot's `SlotInfo::seq`). 0 otherwise.
    pub tx_seq: u32,
}

impl Desc {
    /// The descriptor's bytes.
    pub const fn encode(&self) -> [u8; DESC_BYTES] {
        let s = self.tx_seq.to_le_bytes();
        [self.kind, self.flags, 0, 0, s[0], s[1], s[2], s[3]]
    }

    /// The descriptor at the start of `b`; `None` when `b` is shorter than
    /// one.
    pub fn decode(b: &[u8]) -> Option<Desc> {
        let d = b.get(..DESC_BYTES)?;
        Some(Desc { kind: d[0], flags: d[1], tx_seq: u32::from_le_bytes([d[4], d[5], d[6], d[7]]) })
    }
}

/// The resource of the capability for queue `queue` of interface `ifindex`
/// (`eth0` is 1).
pub const fn resource(ifindex: u8, queue: u8) -> u32 {
    (ifindex as u32) << 8 | queue as u32
}

/// The interface a [`resource`] names.
pub const fn ifindex_of(resource: u32) -> u8 {
    (resource >> 8) as u8
}

/// The queue a [`resource`] names.
pub const fn queue_of(resource: u32) -> u8 {
    resource as u8
}

/// A MAC as the attach replies it: byte `i` in bits `8i..8i+8`.
pub const fn mac_word(mac: [u8; 6]) -> u64 {
    let mut w = 0u64;
    let mut i = 0;
    while i < 6 {
        w |= (mac[i] as u64) << (8 * i);
        i += 1;
    }
    w
}

/// The MAC a [`mac_word`] carries.
pub const fn mac_of_word(w: u64) -> [u8; 6] {
    let mut m = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        m[i] = (w >> (8 * i)) as u8;
        i += 1;
    }
    m
}
