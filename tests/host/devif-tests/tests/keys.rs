// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Keys` interface: its registry row, its op table (what an `OP_MASK` and
//! the register budget are held to), the wire form of a policy.

use azos_devif::keys::{self, op, Policy, KEYS_ID, LOGIN_OPS, SIGNER_OPS};
use azos_devif::{by_key, by_name, key, parse_target, KeysIdl};
use azos_idl::{MsgDesc, Reader, Wire, Writer, MSG_VERSION};

/// The row: key 25, after `memctl`, the id "KEYS", no resource spelling.
///
/// **Canary.** Move the key, or give the row a resource: red.
#[test]
fn the_keys_row_is_registered_after_memctl_and_names_no_resource() {
    assert_eq!(key::KEYS, 25);
    assert_eq!(KEYS_ID.to_be_bytes(), *b"KEYS");
    let i = by_name("keys").expect("no row keys");
    assert_eq!((i.key, i.id), (key::KEYS, KEYS_ID));
    assert_eq!(by_key(key::KEYS).map(|x| x.name), Some("keys"));
    assert_eq!(parse_target("keys").map(|(i, b)| (i.name, b)), Some(("keys", 0)));
    assert!(parse_target("keys.0").is_none(), "one keystore per owner, the endpoint names no resource");
    assert_eq!(azos_devif::IFACES.iter().filter(|f| f.id == KEYS_ID).count(), 1);
}

/// The op numbers an `OP_MASK` names are the trait's order.
///
/// **Canary.** Move a method in the trait without moving its constant: red.
#[test]
fn the_op_constants_are_the_traits_order() {
    let want = [
        ("generate", op::GENERATE),
        ("import", op::IMPORT),
        ("derive", op::DERIVE),
        ("public", op::PUBLIC),
        ("sign", op::SIGN),
        ("seal", op::SEAL),
        ("unseal", op::UNSEAL),
        ("wrap", op::WRAP),
        ("unwrap", op::UNWRAP),
        ("destroy", op::DESTROY),
        ("login", op::LOGIN),
    ];
    assert_eq!(KeysIdl::OPS.len(), want.len());
    for (name, n) in want {
        let o = KeysIdl::OPS.iter().find(|o| o.name == name).unwrap_or_else(|| panic!("no op {name}"));
        assert_eq!(u64::from(o.op), n, "{name}");
    }
}

/// A signer's mask admits opening a key, its public part and a signature, and
/// nothing that makes, wraps or lets go of one.
///
/// **Canary.** Add an op to `SIGNER_OPS`: red.
#[test]
fn the_signer_mask_is_generate_public_and_sign() {
    let bit = |n: u64| 1u64 << n;
    assert_eq!(SIGNER_OPS, bit(op::GENERATE) | bit(op::PUBLIC) | bit(op::SIGN));
    assert_eq!(SIGNER_OPS.count_ones(), 3);
    for other in [op::IMPORT, op::DERIVE, op::SEAL, op::UNSEAL, op::WRAP, op::UNWRAP, op::DESTROY] {
        assert_eq!(SIGNER_OPS & bit(other), 0, "op {other}");
    }
}

/// Every request and reply fits the message (eight words), the only op with a
/// capability entry is `sign`, and it is the buffer.
///
/// **Canary.** Make `seal` take a second 32-byte block: the macro refuses the
/// trait (it no longer fits), so this file does not build.
#[test]
fn the_ops_fit_the_message_and_only_sign_carries_a_capability() {
    for o in KeysIdl::OPS {
        assert!(o.req_words <= 8 && o.rep_words <= 8, "{}", o.name);
        assert_eq!(o.req_caps, u8::from(o.name == "sign").into(), "{}", o.name);
        assert_eq!(o.rep_caps, 0, "{}", o.name);
    }
    let by = |n: &str| KeysIdl::OPS.iter().find(|o| o.name == n).unwrap();
    // header + key + sealed block / status + outcome + sealed block.
    assert_eq!((by("unseal").req_words, by("seal").rep_words), (8, 8));
    assert_eq!((by("unwrap").req_words, by("wrap").rep_words), (8, 8));
}

/// The login service's mask admits `login` and nothing else: it makes, uses,
/// wraps and destroys no key.
///
/// **Canary.** Add an op to `LOGIN_OPS`: red.
#[test]
fn the_login_mask_is_login_alone() {
    assert_eq!(LOGIN_OPS, 1u64 << op::LOGIN);
    assert_eq!(LOGIN_OPS & SIGNER_OPS, 0, "the signer cannot log anyone in, the login service cannot sign");
    // header + the user's name (2 words) + the credential (4 words) = 7 words;
    // status + outcome + the root.
    let by = KeysIdl::OPS.iter().find(|o| o.name == "login").unwrap();
    assert_eq!((by.req_words, by.req_caps), (7, 0));
}

fn encode(p: &Policy) -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    let mut w = Writer::new(&mut d);
    p.put(&mut w);
    d.n_words = 2;
    d
}

/// A policy survives the wire, every field in its own place.
#[test]
fn a_policy_round_trips() {
    let p = Policy {
        purpose: keys::purpose::WRAP,
        envelope: keys::envelope::IMAGE,
        backend: keys::backend::VOLUME,
        wrappable: true,
        max_uses: 0xDEAD_BEEF,
        ttl_s: 0x1234_5678,
    };
    let d = encode(&p);
    let mut r = Reader::new(&d);
    assert_eq!(Policy::get(&mut r), p);
    assert!(r.finish().is_ok());
    // Each field alone moves one thing.
    for q in [
        Policy { purpose: 1, ..Policy::default() },
        Policy { envelope: 1, ..Policy::default() },
        Policy { backend: 3, ..Policy::default() },
        Policy { wrappable: true, ..Policy::default() },
        Policy { max_uses: 1, ..Policy::default() },
        Policy { ttl_s: 1, ..Policy::default() },
    ] {
        let d = encode(&q);
        assert_eq!(Policy::get(&mut Reader::new(&d)), q);
        assert_ne!(d.words[..2], encode(&Policy::default()).words[..2]);
    }
}

/// A policy with a reserved bit set is a malformed message, not a policy the
/// server would read as something else.
///
/// **Canary.** Stop failing the reader on the reserved bits: the cases below go green.
#[test]
fn reserved_bits_of_a_policy_are_malformed() {
    for (w0, w1) in [(1u64 << 25, 0u64), (1 << 31, 0), (0, 1 << 32), (0, u64::MAX)] {
        let mut d = MsgDesc { version: MSG_VERSION, n_words: 2, ..MsgDesc::default() };
        d.words[0] = w0;
        d.words[1] = w1;
        let mut r = Reader::new(&d);
        let _ = Policy::get(&mut r);
        assert!(r.finish().is_err(), "{w0:#x} {w1:#x}");
    }
}
