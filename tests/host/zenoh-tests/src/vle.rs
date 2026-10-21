// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_zenoh::{Error, Reader, Writer};

fn enc(v: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.vle(v);
    w.into_vec()
}

#[test]
fn spec_examples() {
    // From the specification's primitives page.
    assert_eq!(enc(300), crate::hex("AC 02"));
    assert_eq!(enc(u32::MAX as u64), crate::hex("FF FF FF FF 0F"));
    // u64::MAX: eight continuation bytes of 7 bits, then the whole ninth byte
    // (zenoh-rust: VLE_LEN_MAX = 9; the page of the spec lists FF x9 01, which the
    // implementations do not write).
    assert_eq!(enc(u64::MAX), crate::hex("FF FF FF FF FF FF FF FF FF"));
    // A value with bit 63 set (any NTP64 time): the ninth byte is a value, not "more".
    assert_eq!(enc(0xE000_0000_0000_0000), crate::hex("80 80 80 80 80 80 80 80 E0"));
    assert_eq!(enc(1 << 56), crate::hex("80 80 80 80 80 80 80 80 01"));
    assert_eq!(enc((1 << 56) - 1), crate::hex("FF FF FF FF FF FF FF 7F"));
    assert_eq!(enc(0), [0x00]);
    assert_eq!(enc(127), [0x7F]);
    assert_eq!(enc(128), [0x80, 0x01]);
}

#[test]
fn round_trip_around_every_group_boundary() {
    for k in 0..64 {
        for d in [-1i64, 0, 1] {
            let v = ((1u64 << k) as i64).wrapping_add(d) as u64;
            let b = enc(v);
            let mut r = Reader::new(&b);
            assert_eq!(r.vle(), Ok(v), "{v}");
            assert!(r.is_empty());
        }
    }
    let b = enc(u64::MAX);
    assert_eq!(Reader::new(&b).vle(), Ok(u64::MAX));
}

#[test]
fn malformed() {
    // Cut inside the integer.
    assert_eq!(Reader::new(&[0x80]).vle(), Err(Error::Truncated));
    assert_eq!(Reader::new(&[]).vle(), Err(Error::Truncated));
    // Nine bytes are the most: the ninth is a whole byte, bit 7 included.
    let b = crate::hex("80 80 80 80 80 80 80 80 80");
    assert_eq!(Reader::new(&b).vle(), Ok(0x80 << 56));
    // Cut inside the ninth byte.
    let b = crate::hex("80 80 80 80 80 80 80 80");
    assert_eq!(Reader::new(&b).vle(), Err(Error::Truncated));
    // A tenth byte is not part of the integer.
    let b = crate::hex("FF FF FF FF FF FF FF FF FF 01");
    let mut r = Reader::new(&b);
    assert_eq!(r.vle(), Ok(u64::MAX));
    assert_eq!(r.u8(), Ok(0x01));
    // Narrow reads refuse what does not fit.
    let b = enc(1 << 32);
    assert_eq!(Reader::new(&b).vle32(), Err(Error::Overflow));
    let b = enc(65536);
    assert_eq!(Reader::new(&b).vle16(), Err(Error::Overflow));
}

#[test]
fn length_prefixed_arrays() {
    let mut w = Writer::new();
    w.z16(b"abc").unwrap();
    w.z32(b"").unwrap();
    w.z8(b"xy").unwrap();
    assert_eq!(w.as_slice(), crate::hex("03 61 62 63 00 02 78 79"));
    let mut r = Reader::new(w.as_slice());
    assert_eq!(r.z16(), Ok(&b"abc"[..]));
    assert_eq!(r.z32(), Ok(&b""[..]));
    assert_eq!(r.z8(), Ok(&b"xy"[..]));
    // A length that runs past the input.
    assert_eq!(Reader::new(&[0x05, 1, 2]).z16(), Err(Error::Truncated));
    // z16 and z8 limits on the writing side.
    assert_eq!(Writer::new().z16(&[0u8; 65536]), Err(Error::TooLong));
    assert_eq!(Writer::new().z8(&[0u8; 256]), Err(Error::TooLong));
    assert!(Writer::new().z16(&[0u8; 65535]).is_ok());
    // And on the reading side: a z8 length of 256 is refused.
    let mut r = Reader::new(&[0x80, 0x02]);
    assert_eq!(r.z8(), Err(Error::Overflow));
}
