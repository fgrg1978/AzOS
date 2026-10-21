// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_ble::crypto::*;

fn h(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn a16(s: &str) -> [u8; 16] { h(s).try_into().unwrap() }
fn a32(s: &str) -> [u8; 32] { h(s).try_into().unwrap() }

#[test]
fn cmac_rfc4493() {
    let k = a16("2b7e1516 28aed2a6 abf71588 09cf4f3c");
    assert_eq!(cmac(&k, &[]), a16("bb1d6929 e9593728 7fa37d12 9b756746"));
    let m = h("6bc1bee2 2e409f96 e93d7e11 7393172a");
    assert_eq!(cmac(&k, &[&m]), a16("070a16b4 6b4d4144 f79bdd9d d04a287c"));
    let m40 = h("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411");
    assert_eq!(cmac(&k, &[&m40]), a16("dfa66747 de9ae630 30ca3261 1497c827"));
    // split across parts: same message
    assert_eq!(cmac(&k, &[&m40[..7], &m40[7..33], &m40[33..]]), a16("dfa66747 de9ae630 30ca3261 1497c827"));
}

#[test]
fn f4_spec() {
    let u = a32("20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6");
    let v = a32("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd");
    let x = a16("d5cb8454 d177733e ffffb2ec 712baeab");
    assert_eq!(f4(&u, &v, &x, 0), a16("f2c916f1 07a9bd1c f1eda1be a974872d"));
}

fn a7(s: &str) -> [u8; 7] { h(s).try_into().unwrap() }

#[test]
fn f5_spec() {
    let w = a32("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698");
    let n1 = a16("d5cb8454 d177733e ffffb2ec 712baeab");
    let n2 = a16("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf");
    let (mac, ltk) = f5(&w, &n1, &n2, &a7("00 56123737 bfce"), &a7("00 a713702d cfc1"));
    assert_eq!(mac, a16("2965f176 a1084a02 fd3f6a20 ce636e20"));
    assert_eq!(ltk, a16("69867911 69d7cd23 980522b5 94750a38"));
}

#[test]
fn f6_spec() {
    let w = a16("2965f176 a1084a02 fd3f6a20 ce636e20");
    let n1 = a16("d5cb8454 d177733e ffffb2ec 712baeab");
    let n2 = a16("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf");
    let r = a16("12a3343b b453bb54 08da42d2 0c2d0fc8");
    let io: [u8; 3] = h("010102").try_into().unwrap();
    assert_eq!(f6(&w, &n1, &n2, &r, &io, &a7("00 56123737 bfce"), &a7("00 a713702d cfc1")), a16("e3c47398 9cd0e8c5 d26c0b09 da958f61"));
}

#[test]
fn g2_spec() {
    let u = a32("20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6");
    let v = a32("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd");
    let x = a16("d5cb8454 d177733e ffffb2ec 712baeab");
    let y = a16("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf");
    assert_eq!(g2(&u, &v, &x, &y), 0x2f9ed5ba % 1_000_000);
}
