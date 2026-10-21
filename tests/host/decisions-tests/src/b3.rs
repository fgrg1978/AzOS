// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Receipt-conditioned warrants (innovation B3), from the side of the person
// who asks "why was this refused": the `Rule::ReceiptCaveat` record a refused
// use writes, found by the kernel's own query and explained by `why` through
// the interface.
//
// A child module of `tests` (`mod b3 { include!("b3.rs"); }`): the kernel
// source, the loopback and the lock are the ones the other tests use. The
// record's first number is `azos_decision::receipt::word`, the constructor
// the capability resolve writes it with
// (`azos_ipc::cap::caveat::receipt::record_word` calls it): the words below
// come from the production function, not from a hand-written layout. The
// resolve half (a real refused use, the record it writes and its chain text)
// is `tests/host/cap-tests/src/b3.rs`, which asserts the very numbers line
// this suite asserts `why` prints.

use super::*;
use azos_decision::receipt::{self, KIND_REVERSIBLE, KIND_SAFE};

/// Wheel 3 of effect kind 1 (a motor): the device a caveat names.
const DEVICE: u16 = 1 << 8 | 3;

/// A refused use of a receipt-conditioned warrant is a durable record of its
/// own: the kernel's query finds it by rule and by the domain refused, and
/// `why <id>` prints the rule, the domain and the numbers by name: the
/// device, the receipt kind, the cause, the age of the newest receipt and the
/// limit. The answer to "why was the gate not opened" reads "wheel 3 left no
/// receipt in the last 250 ms", not a packed number. **Canary.** Write the
/// record with `Verdict::Admit` (a use that held): it is not durable, the
/// lookup is `None`, red; drop the `receipt_refusal` arm of `write_chain`: the
/// numbers print as the packed word, red.
#[test]
fn why_names_the_receipt_a_use_lacked() {
    let _g = GUARD.lock().unwrap();
    let before = azos_decision::total();
    let old = receipt::word(DEVICE, KIND_SAFE, receipt::OLD);
    let missing = receipt::word(DEVICE, KIND_REVERSIBLE, receipt::MISSING);
    azos_decision::record(Rule::ReceiptCaveat, Verdict::Refuse, 7701, [old, 501, 500]);
    azos_decision::record(Rule::ReceiptCaveat, Verdict::Refuse, 7702, [missing, 0, 500]);
    azos_decision::record(Rule::ReceiptCaveat, Verdict::Refuse, 7701, [missing, 0, 250]);
    let s = RefCell::new(Service(Kernel));
    let c = DecisionsClient::new(Loop(&s));

    // The query finds the refusals of one domain, oldest first.
    let f = Filter { rule: Some(Rule::ReceiptCaveat as u8), verdict: Some(Verdict::Refuse as u8), subject: Some(7701), after: before };
    let mut ids = [0u64; 8];
    let (n, _) = list(&c, &f, &mut ids).unwrap();
    assert_eq!(n, 2, "the other domain's refusal is not in the answer");
    let first = fetch(&c, ids[0]).unwrap().expect("a refusal is kept in the journal");
    assert_eq!((first.rule, first.verdict, first.subject), (Rule::ReceiptCaveat as u8, Verdict::Refuse as u8, 7701));
    assert_eq!(first.n, [old, 501, 500]);

    // `why <id>` names the device, the receipt and the cause, with the age and the limit.
    let mut out = String::new();
    assert_eq!(cli::run(&Cmd::Chain(ids[0]), &c, &mut out), Ok(0));
    assert!(out.starts_with(&format!("decision {}: receipt-caveat refuse\n", ids[0])), "{out}");
    assert!(out.contains("  subject   domain=7701\n"), "{out}");
    assert!(out.contains("  numbers   device=1:3 receipt=0(safe-state) cause=old age_ms=501 limit_ms=500\n"), "{out}");
    assert!(out.contains("  rejected  honour the receipt as written"), "{out}");
    out.clear();
    assert_eq!(cli::run(&Cmd::Chain(ids[1]), &c, &mut out), Ok(0));
    assert!(out.contains("  numbers   device=1:3 receipt=1(reversible) cause=missing limit_ms=250\n"), "{out}");
    assert!(!out.contains("age_ms"), "a device with no receipt has no age: {out}");
}

/// The word round-trips and refuses what is not one. **Canary.** Drop the
/// `w >> 40` test of `Refusal::decode`: the stray high bit decodes, red.
#[test]
fn the_receipt_word_round_trips_and_refuses_what_is_not_one() {
    let w = receipt::word(DEVICE, KIND_SAFE, receipt::OLD);
    assert_eq!(w, 0x2_0001_0305, "caveat 5, device 0x0103, receipt kind 0, cause 2");
    assert_eq!(receipt::Refusal::decode(w), Some(receipt::Refusal { device: DEVICE, kind: KIND_SAFE, cause: receipt::OLD }));
    assert_eq!(receipt::Refusal::decode(w | 1 << 40), None, "a bit past the layout");
    assert_eq!(receipt::Refusal::decode(w & !0xff | 4), None, "another caveat kind");
    assert_eq!(receipt::Refusal::decode(receipt::word(DEVICE, KIND_SAFE, 0)), None, "no cause");
    assert_eq!(receipt::Refusal::decode(receipt::word(DEVICE, KIND_SAFE, 4)), None, "an unknown cause");
}

/// A record whose first number does not decode (another writer, a newer
/// layout) prints as the plain numbers under the rule's field names, never as
/// a wrong name. **Canary.** Decode without the cause check: the word with
/// cause 0 prints "contradicted", red.
#[test]
fn a_receipt_record_that_does_not_decode_prints_plain_numbers() {
    let p = azos_decision::ProvenanceRecord::new(Rule::ReceiptCaveat as u8, Verdict::Refuse as u8, 5, [receipt::word(DEVICE, KIND_SAFE, 0), 9, 8]);
    let mut s = String::new();
    p.write_chain(&mut s).unwrap();
    assert!(s.contains(&format!("  numbers   caveat={} age_ms=9 limit_ms=8\n", receipt::word(DEVICE, KIND_SAFE, 0))), "{s}");
}
