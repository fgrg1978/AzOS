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

/// Add `data`'s RFC 1071 sum to the running 32-bit sum `sum`: `data` is
/// read as big-endian 16-bit words from its first byte, an odd last byte
/// being the high half of a word. Returns the running sum unfolded, like
/// [`pseudo_checksum`]; callers fold and complement it.
///
/// Eight bytes per step on aligned 64-bit loads (RFC 1071 §2: the sum is
/// byte-order independent, so native words are summed and the folded result
/// put back into network order once), where it used to be one 16-bit word
/// per step built from two byte loads: measured on riscv64 under -icount, a
/// 1,400-byte UDP frame's receive pass went from ~7,670 to ~2,170
/// instructions (`ifconfig`'s rx cycles per frame). The few bytes before
/// the first 8-byte boundary and after the last are summed one at a time.
pub fn sum_be16(sum: u32, data: &[u8]) -> u32 {
    // SAFETY: `u64` has no invalid bit patterns; `align_to` only splits.
    let (head, mid, tail) = unsafe { data.align_to::<u64>() };
    let mut acc: u64 = 0;
    for &w in mid {
        let (s, carry) = acc.overflowing_add(w);
        acc = s + carry as u64;
    }
    // Fold the native-order sum to 16 bits (end-around carries).
    acc = (acc & 0xFFFF_FFFF) + (acc >> 32);
    acc = (acc & 0xFFFF_FFFF) + (acc >> 32);
    acc = (acc & 0xFFFF) + (acc >> 16);
    acc = (acc & 0xFFFF) + (acc >> 16);
    acc = (acc & 0xFFFF) + (acc >> 16);
    let native = acc as u16;
    // A native 16-bit word of `mid` holds bytes (k, k+1) of `data`, where k
    // has the parity of `head.len()`. Even k: the word in network order is
    // the byte-swapped native word on a little-endian core. Odd k: the
    // byte at k is a LOW half in network order, so the little-endian native
    // word already is the network-order contribution. Big-endian: reversed.
    let odd = head.len() & 1 == 1;
    let mid_be = if cfg!(target_endian = "little") != odd { native.swap_bytes() } else { native };
    let mut s = sum as u64 + mid_be as u64;
    for (j, &b) in head.iter().enumerate() {
        s += if j & 1 == 0 { (b as u64) << 8 } else { b as u64 };
    }
    let base = head.len() + mid.len() * 8;
    for (j, &b) in tail.iter().enumerate() {
        s += if (base + j) & 1 == 0 { (b as u64) << 8 } else { b as u64 };
    }
    // Back to a running u32 the callers' folds accept.
    s = (s & 0xFFFF_FFFF) + (s >> 32);
    s = (s & 0xFFFF_FFFF) + (s >> 32);
    s as u32
}
