// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The brain-link key's reserved-sector record
//! (`crates/core/crypto/src/secure_channel.rs` `link_key_record_decode`).
//!
//! The kernel installs the key only from a valid record: a raw key, a torn
//! write or filesystem data in that sector is refused, never taken as the
//! key. The reference record is the one `tools/sign/link_key_provision.py` writes
//! for the key 01..20, so the host writer and the kernel's reader are held to
//! the same bytes.

use azos_crypto::secure_channel::{
    link_key_record_decode, LinkKeyFault, LINK_KEY_RECORD_BYTES, PSK_BYTES,
};

/// `tools/sign/link_key_provision.py`'s record for the key 01 02 .. 20.
const REFERENCE: &str =
    "4b4c4e4b010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200701978c";

fn key() -> [u8; PSK_BYTES] {
    core::array::from_fn(|i| i as u8 + 1)
}

/// The reference record at the start of a 512-byte sector whose remainder is
/// `fill` (old data the writer did not clear, or its zero padding).
fn sector(fill: u8) -> [u8; 512] {
    let rec: Vec<u8> = (0..REFERENCE.len()).step_by(2)
        .map(|i| u8::from_str_radix(&REFERENCE[i..i + 2], 16).unwrap()).collect();
    assert_eq!(rec.len(), LINK_KEY_RECORD_BYTES);
    let mut s = [fill; 512];
    s[..LINK_KEY_RECORD_BYTES].copy_from_slice(&rec);
    s
}

#[test]
fn the_tools_record_decodes_to_its_key() {
    assert_eq!(link_key_record_decode(&sector(0)), Ok(key()));
    assert_eq!(link_key_record_decode(&sector(0xA5)), Ok(key()),
        "only the record's own bytes count, not the rest of the sector");
}

#[test]
fn an_unprovisioned_sector_is_absent() {
    assert_eq!(link_key_record_decode(&[0u8; 512]), Err(LinkKeyFault::Absent));
}

/// The bug this record closes: the kernel used to take ANY non-zero bytes in
/// the sector as the key. A raw 32-byte key (the old provisioning), random
/// bytes or filesystem data must all be refused.
#[test]
fn raw_or_foreign_bytes_are_not_a_key() {
    let mut raw = [0u8; 512];
    raw[..PSK_BYTES].copy_from_slice(&key());
    assert_eq!(link_key_record_decode(&raw), Err(LinkKeyFault::Malformed), "a raw key");
    let mut fs: [u8; 512] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    fs[510] = 0x55;
    fs[511] = 0xAA;
    assert_eq!(link_key_record_decode(&fs), Err(LinkKeyFault::Malformed), "filesystem data");
}

#[test]
fn a_damaged_record_is_refused() {
    let flip = |at: usize| {
        let mut s = sector(0);
        s[at] ^= 0x01;
        link_key_record_decode(&s)
    };
    assert_eq!(flip(0), Err(LinkKeyFault::Malformed), "magic");
    assert_eq!(flip(4), Err(LinkKeyFault::Malformed), "version");
    assert_eq!(flip(5 + 17), Err(LinkKeyFault::Malformed), "a key bit");
    assert_eq!(flip(LINK_KEY_RECORD_BYTES - 1), Err(LinkKeyFault::Malformed), "the tag");
    // Torn write: the first half landed, the rest of the sector is erased.
    let mut torn = sector(0);
    torn[LINK_KEY_RECORD_BYTES / 2..].fill(0);
    assert_eq!(link_key_record_decode(&torn), Err(LinkKeyFault::Malformed), "a torn write");
    assert_eq!(link_key_record_decode(&sector(0)[..LINK_KEY_RECORD_BYTES - 1]),
        Err(LinkKeyFault::Malformed), "a short buffer");
}
