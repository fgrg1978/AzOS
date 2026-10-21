// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the Zenoh wire codec (`userspace/lib/zenoh`).
//!
//! Every vector is a byte string built by hand from the Zenoh 1.0 protocol
//! specification (spec.zenoh.io): the header flag bits, the field order and the
//! extension header are written out in the comments, not computed by the
//! codec under test. A vector that is canonical is also re-encoded and must
//! come back byte for byte.
#![cfg(test)]

mod keyexpr;
mod network;
mod transport;
mod vle;

/// `"41 09 32"` -> bytes.
pub fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|t| u8::from_str_radix(t, 16).unwrap()).collect()
}
