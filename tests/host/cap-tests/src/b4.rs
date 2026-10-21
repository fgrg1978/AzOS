// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Declassification warrants (innovation B4): the `DECLASSIFY` caveat of
// `cap.rs`, a human's one-shot permission to take label bits off ONE message.
// `CapTable::take_declassify` spends it (the kernel's `ipc_v2` call path calls
// it with the capability the message goes through); the record it writes is
// `Rule::Declassify`.
//
// A child module of `cap_store_tests` (`mod b4 { include!("b4.rs"); }`, next to
// `b3`): the module lock, the test clock and the slot helpers are the ones the
// warrant tests use. Each test names the break that turns it red.

use super::*;
use crate::cap::targets::Port;
use crate::cap::{caveat, derive_warrant, Caveat, Caveats, DeriveSpec};
use azos_abi::ipc_msg::{LABEL_AGENT, LABEL_SERVICE, LABEL_USER};

fn cav(list: &[(u8, u64)]) -> Caveats {
    list.iter().fold(Caveats::NONE, |c, &(k, a)| c.with(Caveat::new(k, a)).expect("a known kind"))
}

/// A table owned by domain 77 with one port capability carrying `list`.
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

/// The `declassify` records written since `before`.
fn declassified_since(before: u64) -> Vec<azos_decision::Record> {
    (before + 1..=azos_decision::total())
        .filter_map(azos_decision::get)
        .filter(|r| r.rule == azos_decision::Rule::Declassify as u8)
        .collect()
}

/// The warrant is spent by the first message that needs it and by no other:
/// the first take returns the bits it allows and writes ONE record
/// `[from, to, handle]`; the second finds it spent. After it the capability is
/// `Revoked`, like an exhausted quota; before it the capability works as any
/// other (an unspent warrant is not a barrier to ordinary use).
/// **Canary.** Replace the `swap(0)` in `take_declassify` by a `load`: the
/// second take returns `Some`, red.
#[test]
fn a_declassify_warrant_is_consumed_on_use_and_recorded() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]);
    assert_eq!(use_plain(&t, h), Ok(7), "unspent: usable as any capability");
    assert!(t.holds_kind_with(ty::PORT, CapPerms::READ));
    let before = azos_decision::total();

    let from = LABEL_AGENT | LABEL_SERVICE;
    assert_eq!(t.take_declassify(h, from), Some(LABEL_AGENT), "the warrant names the bits it lowers");
    let r = declassified_since(before);
    assert_eq!(r.len(), 1, "one use, one record");
    assert_eq!((r[0].verdict, r[0].subject), (azos_decision::Verdict::Admit as u8, 77), "the table's domain");
    assert_eq!(r[0].n, [from as u64, LABEL_SERVICE as u64, h.0 as u64], "from, to, the warrant");

    assert_eq!(t.take_declassify(h, from), None, "spent: a second message gets nothing");
    assert_eq!(declassified_since(before).len(), 1, "a refused take writes no admit record");
    assert_eq!(use_plain(&t, h), Err(CapError::Revoked), "a spent warrant is revoked");
    assert!(!t.holds_kind_with(ty::PORT, CapPerms::READ), "and no longer held");
}

/// A message with none of the bits the warrant names does not spend it: the
/// first call through a ticket is often a message of the planner's own.
/// **Canary.** Drop the `from & allowed == 0` return: the first take spends
/// it for nothing and the real one gets `None`, red.
#[test]
fn a_message_without_the_named_bits_leaves_the_warrant_whole() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]);
    let before = azos_decision::total();
    assert_eq!(t.take_declassify(h, LABEL_SERVICE), None);
    assert_eq!(t.take_declassify(h, 0), None);
    assert!(declassified_since(before).is_empty(), "nothing was lowered, nothing recorded");
    assert_eq!(t.take_declassify(h, LABEL_AGENT | LABEL_SERVICE), Some(LABEL_AGENT));
}

/// Two warrants in a chain allow only the bits they both name (a caveat added
/// later can only narrow), and both are spent by the one message.
/// **Canary.** Union the masks instead of intersecting: `Some(AGENT|USER)`, red.
#[test]
fn a_chain_of_warrants_allows_the_bits_they_all_name() {
    let _g = wguard();
    let (t, h) = table_with(&[
        (caveat::DECLASSIFY, (LABEL_AGENT | LABEL_USER) as u64),
        (caveat::DECLASSIFY, (LABEL_AGENT | LABEL_SERVICE) as u64),
    ]);
    assert_eq!(t.take_declassify(h, LABEL_AGENT | LABEL_USER | LABEL_SERVICE), Some(LABEL_AGENT));
    assert_eq!(t.take_declassify(h, LABEL_AGENT), None, "both were spent by the one message");
}

/// A capability with no declassify warrant, a quota and an empty slot all
/// give nothing, and a warrant of another capability is not spent by them.
#[test]
fn only_the_capability_that_carries_a_warrant_spends_it() {
    let _g = wguard();
    let (t, h) = table_with(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]);
    let plain = t.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 8, CapExt::NONE, Warrant::ROOT).expect("a slot");
    assert_eq!(t.take_declassify(plain, LABEL_AGENT), None, "no warrant on this one");
    let quota = t
        .grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 9, CapExt::NONE,
            Warrant { caveats: cav(&[(caveat::QUOTA, 3)]), ..Warrant::ROOT })
        .expect("a slot");
    assert_eq!(t.take_declassify(quota, LABEL_AGENT), None, "a quota is not a declassification");
    assert_eq!(t.take_declassify(CapHandle((h.0 & !0x1ff) | 40), LABEL_AGENT), None, "an empty slot");
    assert_eq!(t.take_declassify(h, LABEL_AGENT), Some(LABEL_AGENT), "the warrant itself was untouched");
}

/// A warrant is made only by the kernel's own grant: a copy of one is refused
/// (a second use of one human decision), and so is a derive that names one
/// (every other caveat restricts, this one grants, and `ENDPOINT_DERIVE` takes
/// the kinds from the caller's words). Attenuating the original in place (a
/// MOVE) is not a copy and keeps it whole.
/// **Canary.** Delete the check in `derive_warrant`: the copy succeeds, red;
/// delete the one in `narrow_warrant`: the self-issued warrant succeeds, red.
#[test]
fn a_declassify_warrant_cannot_be_copied_or_derived() {
    let _g = wguard();
    let ticket = Warrant { caveats: cav(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]), ..Warrant::ROOT };
    assert_eq!(
        derive_warrant(0x1000, CapPerms::RW_DELEGATE, &ticket, &DeriveSpec::SAME).err(),
        Some(CapError::MissingPerms)
    );
    // The in-place narrowing keeps it whole.
    let (_, kept) = crate::cap::narrow_warrant(CapPerms::RW_DELEGATE, &ticket, &DeriveSpec::SAME).expect("a move");
    assert_eq!(kept.caveats.as_slice().len(), 1);
    // A holder cannot write itself one, from a plain capability or from a
    // ticket, by derive or by move.
    let spec = DeriveSpec { caveats: cav(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]), ..DeriveSpec::SAME };
    assert_eq!(derive_warrant(0x1000, CapPerms::RW_DELEGATE, &Warrant::ROOT, &spec).err(), Some(CapError::MissingPerms));
    assert_eq!(crate::cap::narrow_warrant(CapPerms::RW_DELEGATE, &Warrant::ROOT, &spec).err(), Some(CapError::MissingPerms));
    assert_eq!(crate::cap::narrow_warrant(CapPerms::RW_DELEGATE, &ticket, &spec).err(), Some(CapError::MissingPerms));
    // Through the table, as ENDPOINT_DERIVE reaches it: nothing is minted.
    let (t, h) = table_with(&[]);
    let held = t.free_caveat_blocks();
    let r = t.mint_badged_caveated(1, h, 5, CapPerms::RW, 0, &spec.caveats);
    assert!(r.is_err(), "a self-issued declassify warrant was minted");
    assert_eq!(t.free_caveat_blocks(), held, "and nothing leaked");
}
