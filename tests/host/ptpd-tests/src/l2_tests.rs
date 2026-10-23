// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IEEE 1588 over Ethernet (`l2.rs`): the frame around a message, the message
//! in a frame, the clock identity a MAC makes and the wall time of a stamp.

use crate::l2;

const MAC: [u8; 6] = [0x02, 0x00, 0x5E, 0x10, 0x20, 0x30];

/// **Discriminates.** A message goes out to the PTP group from the NIC's MAC
/// under EtherType 0x88F7 and reads back whole; a frame with another
/// EtherType carries no message. Canary: send to the source MAC, or swap the
/// EtherType's bytes, and the header assertion fails.
#[test]
fn a_message_travels_in_a_frame_to_the_ptp_group_and_reads_back() {
    let msg = [0x11u8, 0x02, 0x00, 0x2C, 0x00, 0x00, 7, 7, 7];
    let mut out = [0u8; 64];
    let n = l2::frame(MAC, &msg, &mut out).expect("room");
    assert_eq!(n, l2::HDR + msg.len());
    assert_eq!(&out[..6], &l2::GROUP);
    assert_eq!(&out[6..12], &MAC);
    assert_eq!(&out[12..14], &[0x88, 0xF7]);
    assert_eq!(l2::message(&out[..n]), Some(&msg[..]));
    let mut ip = out;
    ip[12..14].copy_from_slice(&[0x08, 0x00]);
    assert_eq!(l2::message(&ip[..n]), None, "IPv4 is not PTP");
    assert_eq!(l2::message(&out[..13]), None, "a frame cut inside its header");
    assert_eq!(l2::frame(MAC, &msg, &mut [0u8; 20]), None, "no room");
}

/// **Discriminates.** A PTP message behind one 802.1Q tag (a VLAN-tagged
/// segment) is read past the tag; a tagged frame of another EtherType is not
/// PTP.
#[test]
fn a_vlan_tagged_message_is_read_past_its_tag() {
    let mut f = vec![0u8; 18];
    f[..6].copy_from_slice(&l2::GROUP);
    f[6..12].copy_from_slice(&MAC);
    f[12..14].copy_from_slice(&[0x81, 0x00]);
    f[14..16].copy_from_slice(&[0x00, 0x05]);
    f[16..18].copy_from_slice(&[0x88, 0xF7]);
    f.extend_from_slice(&[1, 2, 3]);
    assert_eq!(l2::message(&f), Some(&[1u8, 2, 3][..]));
    f[16..18].copy_from_slice(&[0x08, 0x06]);
    assert_eq!(l2::message(&f), None);
}

/// **Discriminates.** The identity is the EUI-64 of the MAC.
#[test]
fn the_clock_identity_is_the_eui64_of_the_mac() {
    assert_eq!(l2::mac_identity(MAC), [0x02, 0x00, 0x5E, 0xFF, 0xFE, 0x10, 0x20, 0x30]);
}

/// **Discriminates.** A stamp taken 2 ms before the two clocks were read is
/// 2 ms before the wall clock's reading, whatever the two clocks' epochs.
/// Canary: add the difference instead of subtracting it and the stamp lands
/// in the future.
#[test]
fn a_stamp_is_as_far_before_the_wall_clock_as_before_the_monotonic_one() {
    let wall: i128 = 1_700_000_000_000_000_000;
    let mono: u64 = 5_000_000_000;
    assert_eq!(l2::wall_of(mono - 2_000_000, wall, mono), wall - 2_000_000);
    assert_eq!(l2::wall_of(mono, wall, mono), wall);
}
