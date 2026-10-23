// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the Ethernet transport needs around a PTP message (IEEE 1588 Annex
//! F): the EtherType, the group every port listens on, the frame around a
//! message, the identity a node gives its clock, and the wall time of a
//! stamp the NIC queue took. Pure functions: the queue is `queue.rs`'s.

/// The EtherType of PTP over Ethernet.
pub const ETHERTYPE: u16 = 0x88F7;
/// The group every message but the peer-delay ones goes to (Annex F).
pub const GROUP: [u8; 6] = [0x01, 0x1B, 0x19, 0x00, 0x00, 0x00];
/// An Ethernet header.
pub const HDR: usize = 14;
/// The EtherType of an 802.1Q tag.
const VLAN: u16 = 0x8100;

/// Put `msg` in a frame from `src` to [`GROUP`] at the start of `out`; the
/// frame's length, or `None` when `out` cannot hold it.
pub fn frame(src: [u8; 6], msg: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = HDR + msg.len();
    let f = out.get_mut(..n)?;
    f[..6].copy_from_slice(&GROUP);
    f[6..12].copy_from_slice(&src);
    f[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
    f[HDR..].copy_from_slice(msg);
    Some(n)
}

/// The PTP message a received frame carries: its EtherType is PTP's, behind
/// at most one 802.1Q tag. `None` for any other frame.
pub fn message(frame: &[u8]) -> Option<&[u8]> {
    let ty = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    let (ty, at) = if ty == VLAN { (u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]), HDR + 4) } else { (ty, HDR) };
    (ty == ETHERTYPE).then(|| &frame[at..])
}

/// The identity of a clock on the NIC whose MAC is `mac`: the EUI-64 the MAC
/// makes (`FF FE` in the middle), as IEEE 1588 §7.5.2.2.2 suggests.
pub fn mac_identity(mac: [u8; 6]) -> [u8; 8] {
    [mac[0], mac[1], mac[2], 0xFF, 0xFE, mac[3], mac[4], mac[5]]
}

/// The wall time of a stamp `stamp_ns` on the monotonic clock, read against
/// `(wall_now, mono_now)`, the two clocks read together: the stamp is as far
/// before `wall_now` as it is before `mono_now`.
pub fn wall_of(stamp_ns: u64, wall_now: i128, mono_now: u64) -> i128 {
    wall_now - (mono_now as i128 - stamp_ns as i128)
}
