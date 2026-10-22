// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Receipt-conditioned warrants (innovation B3): the `RECEIPT` caveat of
// `cap.rs` evaluated at resolve against the recorder's receipt index, and the
// caveated derive (`CapTable::mint_badged_caveated`, the kernel half of
// `ENDPOINT_DERIVE`) a verified remote token becomes a local capability
// through.
//
// A child module of `cap_store_tests` (`mod b3 { include!("b3.rs"); }`, next
// to `macaroon`): the module lock, the test clock and the slot helpers are
// the ones the warrant tests use. The index is a fake probe whose answers the
// test sets; the real index has its own suite in `logger.rs`
// (`receipt_index_tests`). Each test names the break that turns it red.

use super::*;
use crate::cap::targets::{Endpoint, Port};
use crate::cap::{caveat, Caveat, Caveats, NO_RECEIPT};
use azos_abi::cap::CapKind;
use azos_abi::invoke::EndpointDerive;
use std::sync::atomic::AtomicU64;

/// What the fake index answers, and what it was asked last
/// (`device << 8 | kind`; 0: nothing).
static AGE: AtomicU64 = AtomicU64::new(NO_RECEIPT);
static CONTRARY: AtomicU64 = AtomicU64::new(NO_RECEIPT);
static ASKED: AtomicU64 = AtomicU64::new(0);

fn fake_index(device: u16, kind: u8) -> (u64, u64) {
    ASKED.store((device as u64) << 8 | kind as u64, Ordering::SeqCst);
    (AGE.load(Ordering::SeqCst), CONTRARY.load(Ordering::SeqCst))
}

fn empty_index(_: u16, _: u8) -> (u64, u64) {
    (NO_RECEIPT, NO_RECEIPT)
}

/// Installs the fake index with these ages; puts an index that holds nothing
/// back when the test ends, however it ends (the other warrant tests refuse
/// a receipt caveat).
struct Index;

impl Index {
    fn with(age: u64, contrary: u64) -> Self {
        Self::set(age, contrary);
        crate::cap::set_receipt_probe(fake_index);
        ASKED.store(0, Ordering::SeqCst);
        Index
    }

    fn set(age: u64, contrary: u64) {
        AGE.store(age, Ordering::SeqCst);
        CONTRARY.store(contrary, Ordering::SeqCst);
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        crate::cap::set_receipt_probe(empty_index);
    }
}

/// The wheel 3 of effect kind 1 (a motor), the stop receipt, up to 500 ms old.
const DEVICE: u16 = 1 << 8 | 3;
const STOP: u8 = 0;
const MAX_MS: u32 = 500;
const ARG: u64 = caveat::receipt::arg(DEVICE, STOP, MAX_MS);

fn cav(list: &[(u8, u64)]) -> Caveats {
    list.iter().fold(Caveats::NONE, |c, &(k, a)| c.with(Caveat::new(k, a)).expect("a known kind"))
}

/// A fresh table, owned by domain 77, with one port capability carrying `list`.
fn table_with(list: &[(u8, u64)]) -> (Box<crate::cap::CapTable>, CapHandle) {
    crate::cap::set_clock(clock);
    let t = Box::new(crate::cap::CapTable::empty());
    t.set_owner(77);
    let w = Warrant { caveats: cav(list), ..Warrant::ROOT };
    let h = t.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 7, CapExt::NONE, w).expect("a free slot and block");
    (t, h)
}

fn use_plain(t: &crate::cap::CapTable, h: CapHandle) -> Result<u32, CapError> {
    t.get(Cap::<Port>::from_raw(h), CapPerms::READ)
}

fn use_op(t: &crate::cap::CapTable, h: CapHandle, class: u8) -> Result<u32, CapError> {
    t.get_op(Cap::<Port>::from_raw(h), CapPerms::READ, azos_abi::invoke::op(CapKind::Port, class, 0))
}

/// The decision records written since `before` by the receipt caveat.
fn refusals_since(before: u64) -> Vec<azos_decision::Record> {
    (before + 1..=azos_decision::total())
        .filter_map(azos_decision::get)
        .filter(|r| r.rule == azos_decision::Rule::ReceiptCaveat as u8)
        .collect()
}

/// A use is valid while the newest receipt of the kind is at most `max_age`
/// old, the limit included, and the index is asked for the device and kind
/// the caveat names. Presence and a use that names an op are the same.
/// **Canary.** Compare `age >= limit` in `receipt_held`: the age-at-limit
/// assertion goes red; ask the index for `kind ^ 1`: the asked assertion goes
/// red.
#[test]
fn a_use_is_valid_while_the_receipt_is_young() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let _i = Index::with(100, NO_RECEIPT);
    assert_eq!(use_plain(&t, h), Ok(7));
    assert_eq!(use_op(&t, h, 2), Ok(7));
    assert_eq!(ASKED.load(Ordering::SeqCst), (DEVICE as u64) << 8 | STOP as u64);
    Index::set(MAX_MS as u64, NO_RECEIPT);
    assert_eq!(use_plain(&t, h), Ok(7), "exactly max_age old still holds");
    Index::set(0, NO_RECEIPT);
    assert_eq!(use_plain(&t, h), Ok(7), "a receipt of this instant");
}

/// A receipt older than the caveat allows refuses the use, and the refusal
/// is a decision record naming the device, the receipt kind, the cause, the
/// age and the limit; the capability is still held. A fresh receipt makes it
/// valid again: the refusal is not a revoke. **Canary.** Skip the `age > limit`
/// test: the 501 ms use passes, red.
#[test]
fn an_old_receipt_refuses_the_use_and_says_which() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let _i = Index::with(MAX_MS as u64 + 1, NO_RECEIPT);
    let before = azos_decision::total();
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    let r = refusals_since(before);
    assert_eq!(r.len(), 1, "one refusal, one record");
    assert_eq!((r[0].verdict, r[0].subject), (azos_decision::Verdict::Refuse as u8, 77), "the domain that was refused");
    // Caveat 5, device 0x0103, receipt kind 0, cause 2 (old).
    assert_eq!(r[0].n, [0x2_0001_0305, 501, 500]);
    assert_eq!(r[0].n[0], caveat::receipt::record_word(ARG, caveat::receipt::OLD));
    assert!(t.holds_kind_with(ty::PORT, CapPerms::READ), "held, not usable");
    Index::set(5, NO_RECEIPT);
    assert_eq!(use_plain(&t, h), Ok(7), "a new receipt makes it valid again");
}

/// The whole path of a refusal, from a real refused use: the resolve writes
/// the record, and the chain `why` prints (and the line `why list`
/// prints) names the device, the receipt kind, the cause, the age and the
/// limit, for each of the three causes. The lines are the ones
/// `tests/host/decisions-tests/src/b3.rs` asserts `why` prints for the same
/// numbers. **Canary.** Print the packed word in `write_chain` (drop its
/// `receipt_refusal` arm): the decoded line is missing, red; give `record_word`
/// the wrong cause (`OLD` for `CONTRADICTED`): the third chain reads "old", red.
#[test]
fn a_refused_use_is_explained_by_name() {
    let _g = wguard();
    // A table records its 1st, 2nd and 4th refusal: one fresh table a cause.
    let chain = |before: u64| {
        let r = refusals_since(before);
        assert_eq!(r.len(), 1, "one refusal, one record");
        let p = azos_decision::ProvenanceRecord::from_record(&r[0]);
        let (mut chain, mut line) = (String::new(), String::new());
        p.write_chain(&mut chain).unwrap();
        p.write_line(&mut line).unwrap();
        (chain, line)
    };

    let _i = Index::with(MAX_MS as u64 + 1, NO_RECEIPT);
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let before = azos_decision::total();
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    let (chain_old, line_old) = chain(before);
    assert!(chain_old.contains("  subject   domain=77\n"), "{chain_old}");
    assert!(
        chain_old.contains("  numbers   device=1:3 receipt=0(safe-state) cause=old age_ms=501 limit_ms=500\n"),
        "{chain_old}"
    );
    assert!(line_old.contains(" device=1:3 receipt=0(safe-state) cause=old age_ms=501 limit_ms=500 "), "{line_old}");

    Index::set(NO_RECEIPT, NO_RECEIPT);
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let before = azos_decision::total();
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    let (chain_missing, _) = chain(before);
    assert!(
        chain_missing.contains("  numbers   device=1:3 receipt=0(safe-state) cause=missing limit_ms=500\n"),
        "no age for a receipt that never was: {chain_missing}"
    );

    Index::set(100, 40);
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let before = azos_decision::total();
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    let (chain_contra, _) = chain(before);
    assert!(
        chain_contra.contains("  numbers   device=1:3 receipt=0(safe-state) cause=contradicted age_ms=100 limit_ms=500\n"),
        "{chain_contra}"
    );
}

/// A later receipt of the contrary kind contradicts the receipt: a stop
/// followed by a drive no longer licenses what the stop licensed. Equal ages
/// count as contradicted (the clock cannot order them); an older contrary
/// receipt does not. **Canary.** Test `contrary < age` in `receipt_held`: the
/// equal-age assertion goes red; ignore `contrary`: the contradicted ones do.
#[test]
fn a_later_contrary_receipt_refuses_the_use() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let _i = Index::with(100, 40);
    let before = azos_decision::total();
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms), "driven 40 ms ago, stopped 100 ms ago");
    let r = refusals_since(before);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].n[0], caveat::receipt::record_word(ARG, caveat::receipt::CONTRADICTED));
    assert_eq!(r[0].n[0] >> 32 & 0xff, 3);
    assert_eq!((r[0].n[1], r[0].n[2]), (100, 500), "the age of the receipt that was contradicted, and the limit");
    Index::set(100, 100);
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms), "the same instant is not provably later");
    Index::set(100, 101);
    assert_eq!(use_plain(&t, h), Ok(7), "the contrary receipt is older: the stop stands");
    Index::set(100, NO_RECEIPT);
    assert_eq!(use_plain(&t, h), Ok(7), "no contrary receipt at all");
}

/// A device that left no receipt of the kind refuses the use, and so does a
/// caveat the index cannot be asked about (high bits set); the record says
/// "missing". **Canary.** Treat `NO_RECEIPT` as an age in `receipt_held`: the
/// maximal age is "old" and the cause assertion goes red; skip the
/// `well_formed` test: the malformed one asks the index, red.
#[test]
fn a_missing_receipt_refuses_and_is_named() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let _i = Index::with(NO_RECEIPT, NO_RECEIPT);
    let before = azos_decision::total();
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    let r = refusals_since(before);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].n, [caveat::receipt::record_word(ARG, caveat::receipt::MISSING), 0, 500]);
    assert_eq!(r[0].n[0], 0x1_0001_0305, "caveat 5, device 0x0103, kind 0, cause 1 (missing)");

    ASKED.store(0, Ordering::SeqCst);
    let (m, mh) = table_with(&[(caveat::RECEIPT, ARG | 1 << 60)]);
    Index::set(1, NO_RECEIPT);
    assert_eq!(use_plain(&m, mh), Err(CapError::MissingPerms), "a malformed argument is refused");
    assert_eq!(ASKED.load(Ordering::SeqCst), 0, "without asking the index");
}

/// An index that was never registered (or was cleared) holds no receipt: the
/// use is refused. The Drop of `Index` puts an empty one back for the other
/// tests; this is its answer.
#[test]
fn an_index_that_holds_nothing_refuses() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    crate::cap::set_receipt_probe(empty_index);
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
}

/// A refusal is recorded when the table's count of them is a power of two, so
/// a loop leaves a few records, not one a use: four refusals, three records
/// (the 1st, 2nd and 4th). **Canary.** Record every refusal: four records, red.
#[test]
fn a_loop_of_refusals_leaves_a_few_records() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let _i = Index::with(MAX_MS as u64 + 1, NO_RECEIPT);
    let before = azos_decision::total();
    for _ in 0..4 {
        assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    }
    assert_eq!(refusals_since(before).len(), 3);
}

/// A use the receipt refuses takes no count from a quota beside it, whichever
/// comes first in the list; the use that holds takes one. **Canary.** Charge
/// before the walk ends (charge in the QUOTA arm): the refused use spends the
/// quota, red.
#[test]
fn a_refused_receipt_charges_nothing() {
    let _g = wguard();
    for list in [[(caveat::QUOTA, 2), (caveat::RECEIPT, ARG)], [(caveat::RECEIPT, ARG), (caveat::QUOTA, 2)]] {
        let (t, h) = table_with(&list);
        let _i = Index::with(MAX_MS as u64 + 1, NO_RECEIPT);
        for _ in 0..3 {
            assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
        }
        Index::set(1, NO_RECEIPT);
        assert_eq!(use_plain(&t, h), Ok(7));
        assert_eq!(use_plain(&t, h), Ok(7));
        assert_eq!(use_plain(&t, h), Err(CapError::Revoked), "the two uses that held spent it");
    }
}

/// The receipt is one caveat among the others: an op mask beside it still
/// refuses, and so does a deadline.
#[test]
fn a_receipt_holds_beside_an_op_mask_and_a_deadline() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::OP_MASK, 0b100), (caveat::RECEIPT, ARG), (caveat::EXPIRY, 1000)]);
    let _i = Index::with(1, NO_RECEIPT);
    assert_eq!(use_op(&t, h, 2), Ok(7));
    assert_eq!(use_op(&t, h, 1), Err(CapError::MissingPerms), "the mask refuses with the receipt young");
    crate::cap::set_clock(clock);
    NOW.store(1000, Ordering::SeqCst);
    assert_eq!(use_op(&t, h, 2), Err(CapError::Revoked), "the deadline");
}

/// A use that names no op (`get`) cannot discharge an op mask: it is refused
/// and leaves a receipt, a `CapDenial` `Refuse` (the durable path of every
/// build) naming the type and the cause (`kind`, `reason` as a typed denial
/// prints them; the verdict tells it from a `Deny`), at the powers of two like
/// the receipt caveat's: four refusals, three records. A use that names its
/// op, allowed or refused, leaves none (the cause is the mask, not a call
/// site that lacks its op), and neither does a plain `get` of a capability
/// with no op mask. **Canary.** Delete the `opless_refusal` call in `gate`:
/// the count below is 0, red; record on the `get_op` refusal too: the
/// `get_op` assertion goes red.
#[test]
fn an_opless_use_of_an_op_mask_leaves_a_receipt() {
    let _g = wguard();
    let mask = 0b0110;
    let (t, h) = table_with(&[(caveat::OP_MASK, mask)]);
    let denials = |before: u64| -> Vec<azos_decision::Record> {
        (before + 1..=azos_decision::total())
            .filter_map(azos_decision::get)
            .filter(|r| r.rule == azos_decision::Rule::CapDenial as u8)
            .collect()
    };
    let before = azos_decision::total();
    for _ in 0..4 {
        assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    }
    let r = denials(before);
    assert_eq!(r.len(), 3, "the 1st, 2nd and 4th refusals");
    assert_eq!((r[0].verdict, r[0].subject), (azos_decision::Verdict::Refuse as u8, 77));
    assert_eq!(r[0].n, [ty::PORT.denial_code() as u64, CapError::MissingPerms.code() as u64, 0]);
    let mut line = String::new();
    azos_decision::ProvenanceRecord::from_record(&r[0]).write_line(&mut line).unwrap();
    assert!(line.contains("cap-denial refuse") && line.contains("reason=3") && !line.contains("dropped"), "{line}");

    let before = azos_decision::total();
    assert_eq!(use_op(&t, h, 1), Ok(7));
    assert_eq!(use_op(&t, h, 0), Err(CapError::MissingPerms));
    assert!(denials(before).is_empty(), "a use that names its op left a record");
    let (p, ph) = table_with(&[(caveat::EXPIRY, u64::MAX)]);
    assert_eq!(use_plain(&p, ph), Ok(7));
    assert!(denials(before).is_empty(), "a use of a capability with no op mask left a record");
}

// ── the caveated derive ─────────────────────────────────────────────────

/// A caveated derive appends its caveats after the source's, keeps the rest
/// of the warrant a derive keeps (parent, depth, badge, the earlier
/// deadline) and the copy discharges all of them. **Canary.** Build the
/// copy's list from the request alone in `mint_badged_caveated`: the source's
/// op mask is gone from the copy and the first assertion goes red.
#[test]
fn a_caveated_derive_keeps_the_sources_caveats_and_adds_its_own() {
    let _g = wguard();
    if !crate::cap::SLOT_EXT {
        return;
    }
    let srv = fresh_task();
    let w = Warrant { caveats: cav(&[(caveat::OP_MASK, 0b0110)]), ..Warrant::ROOT };
    let ep = cap_store::with_table(srv.tid, |t| t.grant_warranted(ty::ENDPOINT, CapPerms::RW_DELEGATE, 3, CapExt::NONE, w))
        .unwrap()
        .unwrap();
    let asked = cav(&[(caveat::RECEIPT, ARG), (caveat::QUOTA, 3), (caveat::NODE, 9)]);
    let h = cap_store::mint_badged_caveated(srv.tid, ep, 0xB3, CapPerms::WRITE, 5_000, &asked).expect("room for three");
    let cw = cap_store::with_table(srv.tid, |t| t.warrant_of(h)).flatten().unwrap();
    assert_eq!(
        cw.caveats.as_slice(),
        &[
            Caveat::new(caveat::OP_MASK, 0b0110),
            Caveat::new(caveat::RECEIPT, ARG),
            Caveat::new(caveat::QUOTA, 3),
            Caveat::new(caveat::NODE, 9),
        ],
        "the source's first, then the request, in order"
    );
    assert_eq!((cw.depth, cw.expiry_ns), (1, 5_000));
    assert_eq!(badge_of(srv.tid, h), Some(0xB3));
    // The copy is the source's child: revoking the source revokes it.
    let fresh = cap_store::revoke_derived(srv.tid, ep).unwrap();
    assert_ne!(fresh, ep);
    assert!(matches!(
        cap_store::get::<Endpoint>(srv.tid, Cap::from_raw(h), CapPerms::WRITE),
        Err(CapError::Stale | CapError::Revoked)
    ));
}

/// The copy resolves only what every caveat lets through: the source's op
/// mask cannot be widened by the request, a receipt it carries refuses while
/// the index says old, and a kind nothing evaluates refuses every use.
/// **Canary.** Skip the caveat walk (`canary_skip_caveats`): every refusal
/// below goes red.
#[test]
fn a_caveated_copy_only_narrows() {
    let _g = wguard();
    if !crate::cap::SLOT_EXT {
        return;
    }
    let t = Box::new(crate::cap::CapTable::empty());
    crate::cap::set_clock(clock);
    let w = Warrant { caveats: cav(&[(caveat::OP_MASK, 0b0110)]), ..Warrant::ROOT };
    let ep = t.grant_warranted(ty::ENDPOINT, CapPerms::RW_DELEGATE, 3, CapExt::NONE, w).unwrap();
    let mint = |list: &[(u8, u64)]| t.mint_badged_caveated(1, ep, 5, CapPerms::RW, 0, &cav(list));
    let op = |h: CapHandle, class: u8| {
        t.get_op(Cap::<Endpoint>::from_raw(h), CapPerms::READ, azos_abi::invoke::op(CapKind::Endpoint, class, 1))
    };

    // A wider mask asked for is the intersection with the source's.
    let wide = mint(&[(caveat::OP_MASK, 0xFFFF)]).unwrap();
    assert_eq!(op(wide, 1), Ok(3));
    assert_eq!(op(wide, 0), Err(CapError::MissingPerms), "class 0 was never in the source's mask");
    // A receipt carried by the copy is read at its use.
    let rc = mint(&[(caveat::RECEIPT, ARG)]).unwrap();
    {
        let _i = Index::with(MAX_MS as u64 + 1, NO_RECEIPT);
        assert_eq!(op(rc, 1), Err(CapError::MissingPerms));
        Index::set(1, NO_RECEIPT);
        assert_eq!(op(rc, 1), Ok(3));
    }
    // A kind the resolve does not evaluate is carried and never discharged.
    let rsv = mint(&[(caveat::NODE, 1)]).unwrap();
    assert_eq!(op(rsv, 1), Err(CapError::MissingPerms));
    // The source itself is unaffected by what was derived from it.
    assert_eq!(op(ep, 1), Ok(3));
}

/// What a derive refuses, it refuses whole: a list past the room the source
/// leaves is `NoSpace`, rights the source lacks and a badged source are
/// `MissingPerms`, a source that is not an endpoint is `WrongKind`, and a
/// refused derive mints nothing. A kind the kernel does not know cannot even
/// be written into the list.
#[test]
fn a_caveated_derive_refuses_what_a_derive_refuses() {
    let _g = wguard();
    if !crate::cap::SLOT_EXT {
        return;
    }
    let srv = fresh_task();
    let w = Warrant { caveats: cav(&[(caveat::OP_MASK, 0b1)]), ..Warrant::ROOT };
    let ep = cap_store::with_table(srv.tid, |t| t.grant_warranted(ty::ENDPOINT, CapPerms::RW_DELEGATE, 3, CapExt::NONE, w))
        .unwrap()
        .unwrap();
    let port: Cap<Port> = cap_store::grant(srv.tid, CapPerms::RW_DELEGATE, 1).unwrap();
    let m = |from: CapHandle, rights: CapPerms, list: &Caveats| {
        cap_store::mint_badged_caveated(srv.tid, from, 5, rights, 0, list)
    };
    let held = cap_store::occupied(srv.tid);

    // Three beside the source's one fill the list (four).
    let three = cav(&[(caveat::QUOTA, 1), (caveat::QUOTA, 1), (caveat::QUOTA, 1)]);
    let full = m(ep, CapPerms::RW_DELEGATE, &three).expect("the list has room for four");
    assert_eq!(cap_store::occupied(srv.tid), held + 1);
    let one = cav(&[(caveat::QUOTA, 1)]);
    assert_eq!(m(full, CapPerms::READ, &one), Err(CapError::MissingPerms), "a badge is set once");
    // The source's one caveat leaves room for three: four do not fit.
    let four = cav(&[(caveat::QUOTA, 1); 4]);
    assert_eq!(m(ep, CapPerms::WRITE, &four), Err(CapError::NoSpace));
    // Rights the source lacks.
    let src = cap_store::with_table(srv.tid, |t| t.grant_warranted(ty::ENDPOINT, CapPerms::from_bits_truncate(CapPerms::READ.bits() | CapPerms::DUP.bits()), 4, CapExt::NONE, Warrant::ROOT))
        .unwrap()
        .unwrap();
    assert_eq!(m(src, CapPerms::RW, &Caveats::NONE), Err(CapError::MissingPerms));
    assert_eq!(m(port.raw(), CapPerms::READ, &one), Err(CapError::WrongKind));
    assert_eq!(Caveats::NONE.with(Caveat::new(0x40, 1)), Err(CapError::MissingPerms));
    let after = cap_store::occupied(srv.tid);
    assert_eq!(m(src, CapPerms::RW, &Caveats::NONE), Err(CapError::MissingPerms));
    assert_eq!(m(ep, CapPerms::WRITE, &four), Err(CapError::NoSpace));
    assert_eq!(cap_store::occupied(srv.tid), after, "a refused derive mints nothing");
}

// ── the op's words ──────────────────────────────────────────────────────

/// The words of `ENDPOINT_DERIVE`, as the layout in `azos_abi::invoke`
/// documents them, decode to the request; a bit the layout does not use is
/// refused. **Canary.** Drop the `w[2] >> (8 * n)` test in `decode`: the stray
/// kind byte decodes, red.
#[test]
fn the_derive_words_decode_and_refuse_stray_bits() {
    let words = |w0: u64, w1: u64, w2: u64, a: [u64; 4], w7: u64| [w0, w1, w2, a[0], a[1], a[2], a[3], w7];
    let w0 = 0x0F | 2 << 8 | 0xB3u64 << 32;
    let kinds = caveat::RECEIPT as u64 | (caveat::QUOTA as u64) << 8;
    let ok = EndpointDerive::decode(&words(w0, 9_000, kinds, [ARG, 4, 0, 0], 0)).expect("a well-formed request");
    assert_eq!(
        ok,
        EndpointDerive {
            rights: 0x0F,
            badge: 0xB3,
            expiry_ns: 9_000,
            n: 2,
            kinds: [caveat::RECEIPT, caveat::QUOTA, 0, 0],
            args: [ARG, 4, 0, 0],
        }
    );
    let none = EndpointDerive::decode(&words(0x3 | 0x11u64 << 32, 0, 0, [0; 4], 0)).unwrap();
    assert_eq!((none.n, none.rights, none.badge), (0, 3, 0x11), "no caveat is a plain derive");
    let bad = [
        words(w0 | 1 << 16, 9_000, kinds, [ARG, 4, 0, 0], 0),
        words(w0 | 5 << 8 & 0xFF00, 9_000, kinds, [ARG, 4, 0, 0], 0),
        words(0x0F | 5 << 8 | 0xB3u64 << 32, 0, kinds, [ARG, 4, 0, 0], 0),
        words(w0, 9_000, kinds | 3 << 16, [ARG, 4, 0, 0], 0),
        words(w0, 9_000, kinds, [ARG, 4, 1, 0], 0),
        words(w0, 9_000, kinds, [ARG, 4, 0, 0], 1),
    ];
    for (i, w) in bad.iter().enumerate() {
        assert_eq!(EndpointDerive::decode(w), None, "case {i}");
    }
    assert!(azos_abi::invoke::ENDPOINT_DERIVE != 0 && azos_abi::invoke::op_kind(azos_abi::invoke::ENDPOINT_DERIVE) == CapKind::Endpoint as u8);
}

/// The test above proves the refusals discriminate: with the walk skipped, the
/// receipt caveat discharges nothing and a spent index still resolves.
#[test]
fn skipping_the_caveat_walk_lets_a_stale_receipt_through() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::RECEIPT, ARG)]);
    let _i = Index::with(MAX_MS as u64 + 1, NO_RECEIPT);
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms));
    {
        crate::cap::canary_skip_caveats(true);
        let r = use_plain(&t, h);
        crate::cap::canary_skip_caveats(false);
        assert_eq!(r, Ok(7), "with the walk skipped nothing is checked");
    }
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms), "disarmed");
}
