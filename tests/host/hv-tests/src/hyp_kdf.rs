// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the monitor derives from a root (crates/core/hyp-mon/src/arch/kdf.rs,
//! run here over `azos_crypto`'s HKDF, the source the monitor links): the
//! request format, its bounds, and answers that come from Python's `hmac`.
//!
//! WHY. The monitor's reply is the only way the kernel gets key material once
//! the root is guarded: a salt left out, or a length one off, is a key that is
//! another key, and nothing on the kernel's side can tell. The row that boots
//! the monitor is the arm phase's.

#[allow(dead_code)]
#[path = "../../../../crates/core/hyp-mon/src/arch/kdf.rs"]
mod kdf;

use azos_hyp_api::*;

fn root() -> [u8; KEY_LEN] {
    core::array::from_fn(|i| i as u8)
}

fn req(salt: &[u8], info: &[u8]) -> DeriveReq {
    DeriveReq::new(salt, info).unwrap()
}

fn hex(s: &str) -> [u8; KEY_LEN] {
    core::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn the_monitor_derives_hkdf_sha256_of_the_root_with_the_requests_salt_and_info() {
    let info: Vec<u8> = (0..54).collect();
    assert_eq!(
        kdf::derive(&root(), &req(b"azos keystore key v1", &info)),
        Some(hex("0592c62e4e194ffc23d6a8ef2ec32d94fdab341bba4dae7916d049f8617ebf4f"))
    );
    let info: Vec<u8> = (0..20).collect();
    assert_eq!(
        kdf::derive(&root(), &req(b"azos console login user v1", &info)),
        Some(hex("d01f8a896571eefa33b021df96a6195baeb661b1b031c576f4ab1ddd55c33a73"))
    );
    assert_eq!(kdf::derive(&root(), &req(b"", b"")), Some(hex("37ad29109f43265287804b674e2653d0a513718907f97fca97c95bded8104bbf")));
    assert_eq!(
        kdf::derive(&root(), &req(&[0; DERIVE_SALT_MAX], &[0; DERIVE_INFO_MAX])),
        Some(hex("ca379b5130bf576c6f6b8f28ea700263481f3db2a37cebcaf406228e7d12074b"))
    );
}

#[test]
fn a_different_salt_or_info_or_root_is_a_different_key() {
    let a = kdf::derive(&root(), &req(b"s", b"i")).unwrap();
    assert_ne!(Some(a), kdf::derive(&root(), &req(b"t", b"i")));
    assert_ne!(Some(a), kdf::derive(&root(), &req(b"s", b"j")));
    assert_ne!(Some(a), kdf::derive(&[1; KEY_LEN], &req(b"s", b"i")));
}

#[test]
fn a_request_has_bounds_and_the_kernel_builds_only_inside_them() {
    assert!(DeriveReq::new(&[0; DERIVE_SALT_MAX + 1], b"").is_none());
    assert!(DeriveReq::new(b"", &[0; DERIVE_INFO_MAX + 1]).is_none());
    // What the kernel wrote is not trusted: a length past the arrays is refused.
    let mut r = req(b"s", b"i");
    r.salt_len = DERIVE_SALT_MAX as u32 + 1;
    assert_eq!(kdf::derive(&root(), &r), None);
    assert!(derive_req_error(&r).is_some());
    r = req(b"s", b"i");
    r.info_len = u32::MAX;
    assert_eq!(kdf::derive(&root(), &r), None);
    // The keystore's own inputs fit (26-byte salt, 54-byte info).
    assert!(b"azos console login user v1".len() <= DERIVE_SALT_MAX && 4 + 1 + 1 + 32 + 16 <= DERIVE_INFO_MAX);
}

#[test]
fn the_reply_words_round_trip_the_output() {
    let out: [u8; KEY_LEN] = core::array::from_fn(|i| (i * 7 + 1) as u8);
    assert_eq!(words_to_out(out_to_words(&out)), out);
    assert_eq!(out_to_words(&out)[0], u64::from_le_bytes(out[..8].try_into().unwrap()));
}

fn guarded(ranges: &[[u64; 2]]) -> Guarded {
    let mut g = Guarded::new();
    for r in ranges {
        assert!(g.add(r[0], r[1]));
    }
    g
}

#[test]
fn a_root_is_only_a_root_inside_guarded_memory() {
    let g = guarded(&[[0x4100_0000, 0x4100_1000]]);
    assert_eq!(key_root_error(0, 0x4100_0000, &g), None);
    assert_eq!(key_root_error(KEY_ROOTS as u64 - 1, 0x4100_0fe0, &g), None, "the last 32 bytes of the page");
    assert!(key_root_error(KEY_ROOTS as u64, 0x4100_0000, &g).is_some(), "no such slot");
    assert!(key_root_error(0, 0x4100_0fe1, &g).is_some(), "past the end of the range");
    assert!(key_root_error(0, 0x4000_0000, &g).is_some(), "kernel memory");
    assert!(key_root_error(0, u64::MAX - 8, &g).is_some(), "wrapping");
    assert!(key_root_error(0, 0x4100_0000, &Guarded::new()).is_some(), "nothing guarded");
}

#[test]
fn a_request_is_read_only_from_aligned_kernel_memory() {
    let g = guarded(&[[0x4100_0000, 0x4100_1000]]);
    let (hole, hole_end) = (0x4060_0000, 0x4080_0000);
    let ram = [[0x4000_0000, 0x8000_0000]];
    let e = |pa| derive_req_addr_error(pa, &ram, hole, hole_end, &g);
    assert_eq!(e(0x4200_0000), None);
    assert!(e(0x0900_0000).is_some(), "a device frame below RAM");
    assert!(e(0x8000_0000 - 8).is_some(), "ending past RAM");
    assert_eq!(e(0x8000_0000 - 168), None, "the request's last byte is the last byte of RAM");
    assert_eq!(derive_req_addr_error(0x0900_0000, &[], hole, hole_end, &g), None, "RAM is named at the lock, not before");
    assert!(e(0x4200_0004).is_some(), "unaligned");
    assert!(e(0x4100_0000).is_some(), "the root's own page");
    assert!(e(0x4100_0000 - 8).is_some(), "ending inside a guarded page");
    assert!(e(0x4060_0000).is_some(), "the monitor");
    assert!(e(u64::MAX - 7).is_some(), "wrapping");
}
