// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure checksum arithmetic shared by the transport layers.
//!
//! **WHY this is not in `ip.rs`.** `ip.rs` pulls in `ethernet` and `arp`, so a
//! host test that wants the kernel's own pseudo-header sum cannot reach it
//! without dragging the link layer along — and a test that reimplements the
//! sum instead is worse than useless here: `tcp::handle_checked` verifies an
//! incoming segment against `ip::pseudo_checksum`, so a suite that crafts its
//! segments with a *copy* of that function would have both sides agree on the
//! same wrong value and pass while testing a checksum the kernel never
//! computes. Same reasoning as `seq.rs` in this crate.

/// Pseudo-header checksum for TCP/UDP (RFC 793 §3.1, RFC 768).
///
/// Returns the running 32-bit sum, not the folded 16-bit value: callers add
/// the segment body before folding.
pub fn pseudo_checksum(src: &[u8; 4], dst: &[u8; 4], proto: u8, len: u16) -> u32 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += proto as u32;
    sum += len as u32;
    sum
}
