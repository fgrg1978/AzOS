// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Macaroon-style caveats on a warrant (`cap.rs`: `Caveats`, `narrow_warrant`,
// `CapTable::gate`).
//
// A child module of `cap_store_tests` (`mod macaroon { include!("macaroon.rs"); }`
// as its first item): the module lock, the test clock and the table-slot
// helpers are the ones the warrant tests use, so the clock the caveat
// deadlines read is never swapped under a test that is running.
//
// Each test names the break that turns it red; the last one arms the
// caveat-walk canary and proves the refusals above it discriminate.

use super::*;
use crate::cap::targets::Port;
use crate::cap::{caveat, narrow_warrant, Caveat, Caveats, DeriveSpec, CAVEATS_MAX};
use azos_abi::cap::CapKind;

fn cav(list: &[(u8, u64)]) -> Caveats {
    list.iter().fold(Caveats::NONE, |c, &(k, a)| c.with(Caveat::new(k, a)).expect("a known kind"))
}

fn with_caveats(list: &[(u8, u64)]) -> Warrant {
    Warrant { caveats: cav(list), ..Warrant::ROOT }
}

/// A fresh table with one port capability carrying `w`.
fn table_with(w: Warrant) -> (Box<crate::cap::CapTable>, CapHandle) {
    crate::cap::set_clock(clock);
    let t = Box::new(crate::cap::CapTable::empty());
    let h = t.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 7, CapExt::NONE, w).expect("a free slot and block");
    (t, h)
}

fn op_in_class(class: u8) -> u16 {
    azos_abi::invoke::op(CapKind::Port, class, 0)
}

fn use_op(t: &crate::cap::CapTable, h: CapHandle, class: u8) -> Result<u32, CapError> {
    t.get_op(Cap::<Port>::from_raw(h), CapPerms::READ, op_in_class(class))
}

fn use_plain(t: &crate::cap::CapTable, h: CapHandle) -> Result<u32, CapError> {
    t.get(Cap::<Port>::from_raw(h), CapPerms::READ)
}

/// Disarms the caveat-walk canary when the test ends, however it ends.
struct Armed;

impl Armed {
    fn new() -> Self {
        crate::cap::canary_skip_caveats(true);
        Armed
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        crate::cap::canary_skip_caveats(false);
    }
}

/// The list only grows: `narrow_warrant` returns the source's caveats followed
/// by the ones asked, never fewer, never reordered; a full list takes no more
/// (`NoSpace`). **Canary.** In `narrow_warrant` build the result from
/// `spec.caveats` alone: the prefix assertion goes red; drop the `append`
/// error (`unwrap_or(src.caveats)`): the full-list assertion goes red.
#[test]
fn caveats_are_append_only() {
    let _g = wguard();
    let src = with_caveats(&[(caveat::OP_MASK, 0b110), (caveat::QUOTA, 9)]);
    let ask = cav(&[(caveat::EXPIRY, 777)]);
    let (_, w) = narrow_warrant(CapPerms::RW_DELEGATE, &src, &DeriveSpec { caveats: ask, ..DeriveSpec::SAME }).unwrap();
    assert_eq!(
        w.caveats.as_slice(),
        &[Caveat::new(caveat::OP_MASK, 0b110), Caveat::new(caveat::QUOTA, 9), Caveat::new(caveat::EXPIRY, 777)],
        "the source's caveats, whole and in order, then the ones asked",
    );
    // Asking for none changes none.
    let (_, same) = narrow_warrant(CapPerms::RW_DELEGATE, &src, &DeriveSpec::SAME).unwrap();
    assert_eq!(same.caveats, src.caveats);
    // Nothing removes or replaces an entry: a chain of narrows is a prefix chain.
    let (_, w2) = narrow_warrant(CapPerms::RW_DELEGATE, &w, &DeriveSpec { caveats: cav(&[(caveat::NODE, 3)]), ..DeriveSpec::SAME }).unwrap();
    assert_eq!(w2.caveats.len(), 4);
    assert_eq!(&w2.caveats.as_slice()[..3], w.caveats.as_slice());
    // Full: one more is refused, and the list is unchanged.
    assert_eq!(w2.caveats.len(), CAVEATS_MAX);
    assert_eq!(
        narrow_warrant(CapPerms::RW_DELEGATE, &w2, &DeriveSpec { caveats: ask, ..DeriveSpec::SAME }).map(|_| ()),
        Err(CapError::NoSpace),
    );
    assert_eq!(Caveats::NONE.with(Caveat::new(caveat::QUOTA, 1)).and_then(|c| c.append(&cav(&[(caveat::QUOTA, 1); 4]))), Err(CapError::NoSpace));
}

/// A kind the kernel does not know is refused where a list is built and where
/// a derive appends; kind 0 (no caveat) is not a caveat. **Canary.** Make
/// `caveat::known` accept every kind: all three assertions go red.
#[test]
fn an_unknown_caveat_kind_is_refused() {
    let _g = wguard();
    for kind in [0u8, 7, 0x40, 0xff] {
        assert_eq!(Caveats::NONE.with(Caveat::new(kind, 1)), Err(CapError::MissingPerms), "kind {kind}");
    }
    assert!(!caveat::known(0) && !caveat::known(7));
    for kind in [caveat::EXPIRY, caveat::QUOTA, caveat::NODE, caveat::OP_MASK, caveat::RECEIPT, caveat::DECLASSIFY] {
        assert!(Caveats::NONE.with(Caveat::new(kind, 1)).is_ok(), "reserved or evaluated kind {kind}");
    }
    // The derive cannot be handed an unknown one either: the list a spec carries
    // is built only by `with`/`append`, so the refusal is at the request.
    let bad = Caveats::NONE.append(&cav(&[(caveat::QUOTA, 1)])).and_then(|c| c.with(Caveat::new(99, 0)));
    assert_eq!(bad, Err(CapError::MissingPerms));
}

/// An op mask refuses an op outside it, and a resolve that names no op at all.
/// **Canary.** In `gate`, treat `OP_MASK` as passing: the refusal assertions go
/// red; test `arg & 1 << class` instead of `arg >> class & 1`: the class 1
/// assertion goes red (precedence); let `Probe::Use(None)` pass: the plain
/// `get` assertion goes red.
#[test]
fn an_op_mask_refuses_an_op() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::OP_MASK, 0b0110)]));
    assert_eq!(use_op(&t, h, 1), Ok(7), "class 1 is in the mask");
    assert_eq!(use_op(&t, h, 2), Ok(7), "class 2 is in the mask");
    assert_eq!(use_op(&t, h, 0), Err(CapError::MissingPerms), "class 0 is not");
    assert_eq!(use_op(&t, h, 3), Err(CapError::MissingPerms), "class 3 is not");
    assert_eq!(use_op(&t, h, 15), Err(CapError::MissingPerms), "class 15 is not");
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms), "a resolve that names no op cannot discharge the mask");
    // Presence is not a use.
    assert!(t.holds_kind_with(ty::PORT, CapPerms::READ));
    // A capability without caveats takes any op.
    let (p, ph) = table_with(Warrant::ROOT);
    assert_eq!(use_op(&p, ph, 9), Ok(7));
    assert_eq!(use_plain(&p, ph), Ok(7));
    // Every caveat must hold: two masks intersect.
    let (m, mh) = table_with(with_caveats(&[(caveat::OP_MASK, 0b0110), (caveat::OP_MASK, 0b0100)]));
    assert_eq!(use_op(&m, mh, 1), Err(CapError::MissingPerms));
    assert_eq!(use_op(&m, mh, 2), Ok(7));
}

/// An expiry caveat is a deadline: a use at or after it is `Revoked`, the
/// capability is no longer held, a derived copy is bound by it, and the
/// earlier of two is the one that counts. **Canary.** In `gate`, compare
/// `now > arg`: the at-the-deadline assertion goes red; skip the `EXPIRY` arm:
/// the whole test goes red.
#[test]
fn an_expiry_caveat_ends_the_capability() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::EXPIRY, 1000), (caveat::EXPIRY, 500)]));
    NOW.store(499, Ordering::SeqCst);
    assert_eq!(use_plain(&t, h), Ok(7), "before either deadline");
    assert!(t.holds_kind_with(ty::PORT, CapPerms::READ));
    NOW.store(500, Ordering::SeqCst);
    assert_eq!(use_plain(&t, h), Err(CapError::Revoked), "the earlier caveat holds at 500");
    assert!(!t.holds_kind_with(ty::PORT, CapPerms::READ), "an expired capability is not held");
    assert!(t.is_void(h));
    // The word answers nothing from a cache: the gate flag is up.
    let w = t.slot_word(h);
    assert_eq!(crate::cap::CapTable::word_grants(w, h, ty::PORT, CapPerms::READ), None);
    // A caveat added by a derive binds the copy and not the source.
    let (s, sh) = table_with(Warrant::ROOT);
    let src = s.warrant_of(sh).unwrap();
    let (_, w) = narrow_warrant(CapPerms::RW_DELEGATE, &src, &DeriveSpec { caveats: cav(&[(caveat::EXPIRY, 800)]), ..DeriveSpec::SAME }).unwrap();
    let c = s.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 8, CapExt::NONE, w).unwrap();
    NOW.store(900, Ordering::SeqCst);
    assert_eq!(use_plain(&s, sh), Ok(7), "the source has no deadline");
    assert_eq!(use_plain(&s, c), Err(CapError::Revoked), "the copy does");
}

/// A quota caveat counts uses: each use that passes takes one, a refused use
/// takes none, presence takes none, and at 0 the capability is `Revoked`.
/// **Canary.** Drop the charge loop in `gate`: the third use succeeds; charge
/// in `Probe::Held`: the presence assertion goes red; charge before the other
/// caveats are checked: the refused-op assertion goes red.
#[test]
fn a_quota_caveat_counts_uses() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::QUOTA, 3), (caveat::OP_MASK, 0b10)]));
    for _ in 0..4 {
        assert!(t.holds_kind_with(ty::PORT, CapPerms::READ), "presence takes no count");
    }
    assert_eq!(use_op(&t, h, 0), Err(CapError::MissingPerms), "a refused use takes no count");
    assert_eq!(t.warrant_of(h).unwrap().caveats.as_slice()[0].arg, 3);
    assert_eq!(use_op(&t, h, 1), Ok(7));
    assert_eq!(use_op(&t, h, 1), Ok(7));
    assert_eq!(t.warrant_of(h).unwrap().caveats.as_slice()[0].arg, 1, "two uses taken");
    assert_eq!(use_op(&t, h, 1), Ok(7));
    assert_eq!(use_op(&t, h, 1), Err(CapError::Revoked), "spent");
    assert!(!t.holds_kind_with(ty::PORT, CapPerms::READ), "a spent capability is not held");
    // A copy starts with what is left and counts on its own.
    let (s, sh) = table_with(with_caveats(&[(caveat::QUOTA, 5)]));
    assert_eq!(use_plain(&s, sh), Ok(7));
    let src = s.warrant_of(sh).unwrap();
    let (_, w) = narrow_warrant(CapPerms::RW_DELEGATE, &src, &DeriveSpec::SAME).unwrap();
    assert_eq!(w.caveats.as_slice()[0].arg, 4);
}

/// The kind the resolve does not evaluate (node) is carried and derived
/// faithfully but discharges nothing: a use is refused until its evaluator
/// exists, presence is unaffected. (Declassify is evaluated since B4:
/// `b4.rs`.) **Canary.** Let the
/// catch-all arm of `gate` pass: the refusals go red.
#[test]
fn a_reserved_kind_is_carried_but_never_discharged() {
    let _g = wguard();
    for kind in [caveat::NODE] {
        assert!(!caveat::evaluated(kind));
        let (t, h) = table_with(with_caveats(&[(kind, 42)]));
        assert_eq!(t.warrant_of(h).unwrap().caveats.as_slice(), &[Caveat::new(kind, 42)], "carried");
        assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms), "kind {kind}");
        assert_eq!(use_op(&t, h, 0), Err(CapError::MissingPerms), "kind {kind} with an op");
        assert!(t.holds_kind_with(ty::PORT, CapPerms::READ), "kind {kind}: held, not usable");
    }
}

/// A derive and a move copy the caveats whole and a transfer may append, across
/// tables; a receiver with no free caveat block refuses before the sender
/// loses anything. **Canary.** In `xfer_plan` pass `Caveats::NONE` to the
/// spec AND build the warrant without `src.caveats` (drop the `append` seed):
/// the dup assertion goes red; drop the `free_caveat_blocks` test of
/// `move_locked`: the full-pool move leaves the sender without its capability.
#[test]
fn derive_and_move_keep_the_caveats() {
    let _g = wguard();
    let (a, b, c) = (wtask(44), wtask(45), wtask(46));
    let r = root_with(&a, CapPerms::RW_DELEGATE, 5, with_caveats(&[(caveat::QUOTA, 5)]));
    assert_eq!(cap_store::get(a.tid, ch(r), CapPerms::READ), Ok(5));
    let d = dup_x(&a, &b, CapXfer { caveats: cav(&[(caveat::EXPIRY, 5000)]), ..CapXfer::new(r, true) }).unwrap();
    assert_eq!(
        warrant(&b, d).caveats.as_slice(),
        &[Caveat::new(caveat::QUOTA, 4), Caveat::new(caveat::EXPIRY, 5000)],
        "what the source had left, then the request",
    );
    NOW.store(5000, Ordering::SeqCst);
    assert_eq!(cap_store::get(b.tid, ch(d), CapPerms::READ), Err(CapError::Revoked), "the copy's deadline");
    assert_eq!(cap_store::get(a.tid, ch(r), CapPerms::READ), Ok(5), "the source is untouched");
    // A move keeps the list and the count.
    NOW.store(0, Ordering::SeqCst);
    let moved = cap_store::move_cap(a.tid, c.tid, r, None).unwrap();
    assert_eq!(warrant(&c, moved).caveats.as_slice(), &[Caveat::new(caveat::QUOTA, 3)]);
    assert!(cap_store::get(a.tid, ch(r), CapPerms::READ).is_err(), "a move leaves the sender without it");
    // A receiver with every block taken: refused, the sender keeps its own.
    let full = wtask(47);
    let n = cap_store::with_table(full.tid, |t| t.free_caveat_blocks()).unwrap();
    for i in 0..n {
        root_with(&full, CapPerms::RW_DELEGATE, 100 + i as u32, with_caveats(&[(caveat::QUOTA, 1)]));
    }
    assert_eq!(cap_store::with_table(full.tid, |t| t.free_caveat_blocks()).unwrap(), 0);
    let held = root_with(&a, CapPerms::RW_DELEGATE, 6, with_caveats(&[(caveat::QUOTA, 9)]));
    assert_eq!(dup(&a, &full, held), Err(CapError::NoSpace));
    assert_eq!(cap_store::move_cap(a.tid, full.tid, held, None), Err(CapError::NoSpace));
    assert_eq!(cap_store::get(a.tid, ch(held), CapPerms::READ), Ok(6), "still the sender's");
    // A capability without caveats still fits.
    let plain = root(&a, CapPerms::RW_DELEGATE, 7);
    assert!(dup(&a, &full, plain).is_ok());
    // And the grant itself is refused, not stored without its caveats.
    let refused = cap_store::with_table(full.tid, |t| {
        t.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 9, CapExt::NONE, with_caveats(&[(caveat::QUOTA, 1)]))
    })
    .unwrap();
    assert!(refused.is_none());
}

/// A freed slot leaves no caveat behind: the next occupant of the slot, and
/// of the block, starts clean, and a stale handle names nothing.
/// **Canary.** Drop the `wipe` from `release_warrant`: the block count goes
/// red; stop zeroing `meta` there: the reused slot reads the old caveats.
#[test]
fn a_freed_slots_caveats_do_not_come_back() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::OP_MASK, 0b10), (caveat::QUOTA, 2)]));
    let total = t.free_caveat_blocks() + 1;
    t.revoke_raw(h);
    assert_eq!(t.free_caveat_blocks(), total, "the block is free again");
    assert!(t.warrant_of(h).is_none(), "the stale handle names nothing");
    let again = t.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 7, CapExt::NONE, Warrant::ROOT).unwrap();
    assert_eq!(again.slot(), h.slot(), "the same slot");
    assert!(t.warrant_of(again).unwrap().caveats.is_empty());
    assert_eq!(use_op(&t, again, 0), Ok(7), "nothing of the old mask");
    assert_eq!(t.free_caveat_blocks(), total);
    // A wipe of the table frees the pool as well.
    let _ = t.grant_warranted(ty::PORT, CapPerms::RW_DELEGATE, 8, CapExt::NONE, with_caveats(&[(caveat::QUOTA, 1)])).unwrap();
    assert_eq!(t.free_caveat_blocks(), total - 1);
    t.clear_all();
    assert_eq!(t.free_caveat_blocks(), total);
}

/// A fork copy (`install_at`) carries the caveats of the capability it copies,
/// as it carries its deadline: a child cannot shed an op mask by forking.
/// **Canary.** Install with `Warrant::ROOT` regardless: the copy answers any op.
#[test]
fn an_installed_copy_keeps_the_caveats() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::OP_MASK, 0b10)]));
    let w = t.warrant_of(h).unwrap();
    let child = crate::cap::CapTable::empty();
    let at = CapHandle::pack(ty::PORT, CapPerms::RW_DELEGATE, 1, 3);
    assert!(child.install_at(at, 7, &w));
    assert_eq!(child.warrant_of(at).unwrap().caveats, w.caveats);
    assert_eq!(use_op(&child, at, 0), Err(CapError::MissingPerms));
    assert_eq!(use_op(&child, at, 1), Ok(7));
    // A full pool refuses the copy rather than install it unrestricted.
    let n = child.free_caveat_blocks();
    for i in 0..n {
        let hh = CapHandle::pack(ty::PORT, CapPerms::RW_DELEGATE, 1, 10 + i as u16);
        assert!(child.install_at(hh, 1, &w));
    }
    assert!(!child.install_at(CapHandle::pack(ty::PORT, CapPerms::RW_DELEGATE, 1, 4), 7, &w));
}

// ── A call to an endpoint the kernel hosts: the mask is over IDL ops ─────────

fn hosted_resolve(t: &crate::cap::CapTable, h: CapHandle) -> Result<u32, CapError> {
    t.get_hosted_uncontained(Cap::<Port>::from_raw(h), CapPerms::NONE)
}

/// A call to a hosted interface has no op when its capability resolves, so the
/// resolve passes an `OP_MASK` and reports the mask; the mask is the
/// intersection of the capability's `OP_MASK` caveats, all ones for none. The
/// opless resolve of the same capability still refuses it, and a use that
/// names its op (a class) is unchanged.
///
/// **Canary.** Make `Probe::Hosted` refuse an `OP_MASK` (the `Use(None)` arm):
/// the first assertion is red. Return the first caveat's mask instead of the
/// intersection: the second is.
#[test]
fn a_hosted_call_passes_an_op_mask_and_reports_it() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::OP_MASK, 0b0110), (caveat::OP_MASK, 0b1100)]));
    assert_eq!(hosted_resolve(&t, h), Ok(7), "the mask is held to the op after the resolve");
    assert_eq!(t.hosted_op_mask(h), 0b0100, "two masks give the ops both list");
    assert_eq!(use_plain(&t, h), Err(CapError::MissingPerms), "an opless use still fails closed");
    assert_eq!(use_op(&t, h, 2), Ok(7), "a use that names its op class is unchanged");
    let (u, uh) = table_with(Warrant::ROOT);
    assert_eq!(hosted_resolve(&u, uh), Ok(7));
    assert_eq!(u.hosted_op_mask(uh), u64::MAX, "no caveat, every op");
    assert_eq!(u.hosted_op_mask(CapHandle::pack(ty::PORT, CapPerms::RW_DELEGATE, 9, 200)), 0, "not a live handle: no op");
}

/// Passing the mask passes nothing else: a hosted call is a use, so a deadline
/// ends it, a quota counts it (once, at the resolve) and a caveat the resolve
/// cannot evaluate (`NODE`) refuses it, exactly as for a use that names an op.
///
/// **Canary.** Let `Probe::Hosted` skip the rest of the walk (return at the
/// `OP_MASK` arm): the deadline, quota and reserved-kind assertions are red.
#[test]
fn a_hosted_call_still_meets_every_other_caveat() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::OP_MASK, 0b10), (caveat::QUOTA, 2)]));
    assert_eq!(hosted_resolve(&t, h), Ok(7));
    assert_eq!(hosted_resolve(&t, h), Ok(7));
    assert_eq!(hosted_resolve(&t, h), Err(CapError::Revoked), "the third call is past the quota");
    let (e, eh) = table_with(with_caveats(&[(caveat::OP_MASK, 0b10), (caveat::EXPIRY, 0)]));
    assert_eq!(hosted_resolve(&e, eh), Err(CapError::Revoked), "a lapsed deadline");
    let (n, nh) = table_with(with_caveats(&[(caveat::OP_MASK, 0b10), (caveat::NODE, 1)]));
    assert_eq!(hosted_resolve(&n, nh), Err(CapError::MissingPerms), "a caveat nobody evaluates");
}

/// **Canary.** With the caveat walk skipped, the refusals above stop refusing:
/// an op outside the mask passes, a spent quota still resolves and a reserved
/// kind is discharged. A test that passes with the walk skipped checks nothing.
#[test]
fn skipping_the_caveat_walk_is_caught() {
    let _g = wguard();
    let (t, h) = table_with(with_caveats(&[(caveat::OP_MASK, 0b10)]));
    let (q, qh) = table_with(with_caveats(&[(caveat::QUOTA, 1)]));
    let (r, rh) = table_with(with_caveats(&[(caveat::RECEIPT, 1)]));
    assert_eq!(use_op(&t, h, 0), Err(CapError::MissingPerms));
    assert_eq!(use_plain(&q, qh), Ok(7));
    assert_eq!(use_plain(&q, qh), Err(CapError::Revoked));
    assert_eq!(use_plain(&r, rh), Err(CapError::MissingPerms));
    {
        let _armed = Armed::new();
        assert_eq!(use_op(&t, h, 0), Ok(7), "the op outside the mask passes");
        assert_eq!(use_plain(&q, qh), Ok(7), "the spent quota resolves");
        assert_eq!(use_plain(&r, rh), Ok(7), "the reserved kind is discharged");
    }
    assert_eq!(use_op(&t, h, 0), Err(CapError::MissingPerms), "disarmed");
}
