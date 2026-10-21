// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC 4251 section 5 data types.

use crate::harness::base64_decode;
use crate::wire::*;

#[test]
fn mpint_examples_of_rfc4251() {
    // The examples of RFC 4251 section 5, for the positive values.
    let enc = |v: &[u8]| {
        let mut w = Writer::default();
        w.mpint(v);
        w.buf
    };
    assert_eq!(enc(&[]), [0, 0, 0, 0]);
    assert_eq!(enc(&[0, 0, 0]), [0, 0, 0, 0], "zero is the empty string");
    assert_eq!(enc(&[0x9a, 0x37, 0x8f, 0x9b, 0x2e, 0x33, 0x2a, 0x7e][..]), [0, 0, 0, 9, 0, 0x9a, 0x37, 0x8f, 0x9b, 0x2e, 0x33, 0x2a, 0x7e]);
    assert_eq!(enc(&[0x80]), [0, 0, 0, 2, 0, 0x80]);
    assert_eq!(enc(&[0, 0, 0x80]), [0, 0, 0, 2, 0, 0x80], "leading zeros are dropped, the sign byte put back");
    assert_eq!(enc(&[0x7f, 0xff]), [0, 0, 0, 2, 0x7f, 0xff]);
}

#[test]
fn string_and_name_list_round_trip() {
    let mut w = Writer::new(7);
    w.string(b"abc").name_list(&["a", "bc", "def"]).name_list(&[]).boolean(true).u32(0xdead_beef);
    let mut r = Reader::new(&w.buf);
    assert_eq!(r.u8(), Some(7));
    assert_eq!(r.string(), Some(&b"abc"[..]));
    assert_eq!(r.string(), Some(&b"a,bc,def"[..]));
    assert_eq!(r.string(), Some(&b""[..]));
    assert_eq!(r.boolean(), Some(true));
    assert_eq!(r.u32(), Some(0xdead_beef));
    assert_eq!(r.remaining(), 0);
    assert_eq!(r.u8(), None);
}

#[test]
fn reader_never_reads_past_the_end() {
    // A string whose length claims more than is there, and one whose length
    // wraps the offset arithmetic.
    for bad in [&[0u8, 0, 0, 5, 1, 2][..], &[0xff, 0xff, 0xff, 0xff, 1][..], &[0, 0, 0][..]] {
        let mut r = Reader::new(bad);
        assert_eq!(r.string(), None);
    }
    let mut r = Reader::new(&[1, 2, 3]);
    assert_eq!(r.skip(4), None);
    assert_eq!(r.skip(3), Some(()));
    assert_eq!(r.remaining(), 0);
}

#[test]
fn list_helpers() {
    assert!(list_has(b"a,bc,def", "bc"));
    assert!(!list_has(b"a,bc,def", "b"));
    assert!(!list_has(b"", "a"));
    assert_eq!(list_first(b"x,y"), b"x");
    assert_eq!(list_first(b""), b"");
}

#[test]
fn base64_vectors_of_rfc4648() {
    for (plain, enc) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")] {
        assert_eq!(base64_nopad(plain.as_bytes()), enc.as_bytes(), "encode {plain:?}");
        assert_eq!(base64_decode(enc.as_bytes()).as_deref(), Some(plain.as_bytes()), "decode {enc:?}");
    }
    assert_eq!(base64_decode(b"Zm9vYg==").as_deref(), Some(&b"foob"[..]), "padding is accepted");
    assert_eq!(base64_decode(b"Zm9v!"), None);
    assert_eq!(base64_decode(b"Z"), None, "one character is no length an encoder makes");
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(base64_decode(&base64_nopad(&all)).unwrap(), all);
}
