// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the Input object: the interface and its marker types
//! (`crates/core/devif/src/input.rs`) and the input server's decisions
//! (`userspace/services/inputd/src/focus.rs`, pulled in with `#[path]` so the
//! code under test is the code `INPUTD.ELF` is built from).
//!
//! The service is driven through the generated client stub over a loopback
//! transport, so the wire form a client sends and receives is the one under
//! test: the capability entries of a reply (the warrant, the ring, the page)
//! are read off the descriptor. The kernel half (a revoked warrant fails the
//! holder's next call; a DUP child of a handle goes with it) is tested where
//! the kernel tables are: `tests/host/cap-tests` and `tests/host/topology-tests`.

#[allow(dead_code)]
#[path = "../../../../userspace/services/inputd/src/focus.rs"]
pub mod focus;

#[cfg(test)]
mod inputd {
    use crate::focus::*;
    use azos_abi::cap::CapPerms;
    use azos_devif::input::*;
    use azos_devif::{outcome, InputClient, InputIdl};
    use azos_idl::{IdlError, MsgDesc, Transport, CAP_MODE_DUP};
    use azos_input_wire::event::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// One ring the fake server made: its words, its slots, whether it was
    /// closed (and given back).
    #[derive(Default)]
    struct FakeRing {
        words: Vec<u64>,
        cap: usize,
        closed: bool,
        drops: u32,
    }

    /// The world the server sees.
    #[derive(Default)]
    struct World {
        stream: VecDeque<u64>,
        stream_drops: u32,
        now: u64,
        rings: Vec<FakeRing>,
        /// Slots of the rings made from now on.
        ring_cap: usize,
        /// Refuse the next ring / warrant.
        no_ring: bool,
        no_warrant: bool,
        /// (generation, handle) of every warrant derived; handles revoked.
        warrants: Vec<(u32, u32)>,
        revoked: Vec<u32>,
        sak: Vec<u64>,
        console: Vec<u8>,
    }

    const RING_HANDLE0: u32 = 100;
    const WARRANT_HANDLE0: u32 = 500;
    const PAGE_HANDLE: u32 = 900;

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<World>>);

    impl Host for Fake {
        fn pop(&mut self) -> Option<u64> {
            self.0.borrow_mut().stream.pop_front()
        }
        fn stream_drops(&mut self) -> u32 {
            self.0.borrow().stream_drops
        }
        fn now_ns(&mut self) -> u64 {
            self.0.borrow().now
        }
        fn make_ring(&mut self) -> Option<Ring> {
            let mut w = self.0.borrow_mut();
            if w.no_ring {
                return None;
            }
            let cap = w.ring_cap;
            let n = w.rings.len() as u32;
            w.rings.push(FakeRing { cap, ..FakeRing::default() });
            Some(Ring { handle: RING_HANDLE0 + n, base: ((RING_HANDLE0 + n) as usize) << 12 })
        }
        fn push(&mut self, ring: &Ring, word: u64) -> bool {
            let mut w = self.0.borrow_mut();
            let r = &mut w.rings[(ring.handle - RING_HANDLE0) as usize];
            assert!(!r.closed, "nothing is written to a ring after it is closed");
            if r.words.len() >= r.cap {
                r.drops += 1;
                return false;
            }
            r.words.push(word);
            true
        }
        fn close_ring(&mut self, ring: &Ring) {
            self.0.borrow_mut().rings[(ring.handle - RING_HANDLE0) as usize].closed = true;
        }
        fn derive_warrant(&mut self, generation: u32) -> Option<u32> {
            let mut w = self.0.borrow_mut();
            if w.no_warrant {
                return None;
            }
            let h = WARRANT_HANDLE0 + w.warrants.len() as u32;
            w.warrants.push((generation, h));
            Some(h)
        }
        fn revoke(&mut self, warrant: u32) {
            self.0.borrow_mut().revoked.push(warrant);
        }
        fn trusted_page(&mut self) -> Option<u32> {
            Some(PAGE_HANDLE)
        }
        fn note_sak(&mut self, now_ns: u64) {
            self.0.borrow_mut().sak.push(now_ns);
        }
        fn log(&mut self, line: &[u8]) {
            self.0.borrow_mut().console.extend_from_slice(line);
        }
    }

    impl Fake {
        fn send(&self, evs: &[(u16, u16, u32)]) {
            let mut w = self.0.borrow_mut();
            for &(t, c, v) in evs {
                w.stream.push_back(pack(t, c, v));
            }
        }
        fn ring(&self, n: usize) -> Vec<(u16, u16, u32)> {
            self.0.borrow().rings[n].words.iter().map(|&w| unpack(w)).collect()
        }
        fn console(&self) -> String {
            String::from_utf8(self.0.borrow().console.clone()).unwrap()
        }
    }

    struct Loop {
        svc: RefCell<Service<Fake>>,
        /// The badge of the capability the next call goes through.
        badge: RefCell<u32>,
        last: RefCell<MsgDesc>,
    }

    impl Transport for &Loop {
        fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
            let mut svc = self.svc.borrow_mut();
            svc.caller = *self.badge.borrow();
            let mut rep = MsgDesc::default();
            InputIdl::dispatch(&mut *svc, msg, &mut rep)?;
            *self.last.borrow_mut() = rep;
            *msg = rep;
            Ok(())
        }
    }

    /// A server in a build with a trusted surface (`gated`: the chord closes the
    /// gate on every caller but the trusted badge), the caller a row's plain
    /// badge 3.
    fn lp(w: &Fake) -> Loop {
        lp_gated(w, true)
    }

    fn lp_gated(w: &Fake, gated: bool) -> Loop {
        w.0.borrow_mut().ring_cap = 64;
        Loop { svc: RefCell::new(Service::new(w.clone(), gated)), badge: RefCell::new(3), last: RefCell::new(MsgDesc::default()) }
    }

    fn pump(l: &Loop) {
        while l.svc.borrow_mut().pump() {}
    }

    const CTRL: (u16, u16, u32) = (EV_KEY, KEY_LEFTCTRL, 1);
    const ALT: (u16, u16, u32) = (EV_KEY, KEY_LEFTALT, 1);
    const DEL: (u16, u16, u32) = (EV_KEY, KEY_DELETE, 1);
    const DEL_UP: (u16, u16, u32) = (EV_KEY, KEY_DELETE, 0);
    const A: (u16, u16, u32) = (EV_KEY, KEY_A, 1);

    /// **A grant lends the warrant and the ring, with exactly their rights.**
    /// The reply has two DUP entries: the warrant with the call right alone
    /// (not `DUP`: the holder cannot hand the focus on) and the ring read-write
    /// and mappable; the warrant's badge names the generation and no row badge
    /// can look like it.
    ///
    /// **Canaries.** Lend the warrant with `WARRANT_RIGHTS | DUP`: the rights
    /// assertion goes red. Derive the warrant with a generation-less badge:
    /// `generation_of` goes red.
    #[test]
    fn a_grant_lends_the_warrant_and_the_ring_with_their_own_rights() {
        let w = Fake::default();
        let l = lp(&w);
        let lease = InputClient::new(&l).take_focus().unwrap();
        assert!(lease.is_ok());
        assert_eq!(lease.value.generation, 1);
        assert!(lease.value.warrant.get().is_some() && lease.value.ring.get().is_some());
        let rep = *l.last.borrow();
        assert_eq!(rep.n_caps, 2);
        let (warrant, ring) = (rep.caps[0], rep.caps[1]);
        assert_eq!((warrant.handle, warrant.mode), (WARRANT_HANDLE0, CAP_MODE_DUP));
        assert_eq!(warrant.rights, CapPerms::WRITE.bits() as u16, "the call right and nothing else");
        assert_eq!(WARRANT_RIGHTS, CapPerms::WRITE);
        assert_eq!((ring.handle, ring.mode), (RING_HANDLE0, CAP_MODE_DUP));
        assert_eq!(ring.rights, RING_RIGHTS.bits() as u16);
        assert_eq!(w.0.borrow().warrants, [(1, WARRANT_HANDLE0)]);
        assert_eq!(generation_of(warrant_badge(1)), Some(1));
        assert_eq!(generation_of(3), None, "a row's badge is no warrant");
        assert_eq!(l.svc.borrow().holder(), 1);
        assert!(w.console().contains("focus 0 -> 1 (moved)"), "{}", w.console());
    }

    /// **Events reach the holder, in order, and only from the grant on.** What
    /// was typed before anyone held the focus is not replayed to the holder
    /// (the keys went nowhere), and events with no holder are dropped, not
    /// queued.
    ///
    /// **Canary.** Deliver with no holder into a ring made earlier: the
    /// "nothing before the grant" assertion goes red.
    #[test]
    fn the_holder_gets_the_events_after_its_grant_in_order() {
        let w = Fake::default();
        let l = lp(&w);
        w.send(&[A, (EV_REL, REL_X, 5)]);
        pump(&l);
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        assert_eq!(w.ring(0), [], "nothing from before the grant");
        w.send(&[(EV_REL, REL_X, 7), A, (EV_KEY, KEY_A, 0), (EV_ABS, ABS_X, 100)]);
        pump(&l);
        assert_eq!(w.ring(0), [(EV_REL, REL_X, 7), A, (EV_KEY, KEY_A, 0), (EV_ABS, ABS_X, 100)]);
        assert_eq!(c.status().unwrap().value.events, 6);
    }

    /// **Moving the focus revokes the old warrant and closes the old ring.**
    /// The second grant (from anyone) makes the old holder's warrant revoked,
    /// its ring closed and no longer written; events go to the new ring only.
    ///
    /// **Canaries.** Skip `host.revoke` in `drop_holder`: the revoked list goes
    /// red. Keep delivering to the old ring: the fake host panics on a write
    /// to a closed ring.
    #[test]
    fn the_second_grant_revokes_the_first_and_closes_its_ring() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        w.send(&[A]);
        pump(&l);
        let second = c.take_focus().unwrap();
        assert_eq!(second.value.generation, 2);
        {
            let wd = w.0.borrow();
            assert_eq!(wd.revoked, [WARRANT_HANDLE0], "the first warrant is revoked");
            assert!(wd.rings[0].closed && !wd.rings[1].closed);
        }
        w.send(&[(EV_KEY, KEY_A, 0)]);
        pump(&l);
        assert_eq!(w.ring(0), [A], "the old ring stopped where the focus moved");
        assert_eq!(w.ring(1), [(EV_KEY, KEY_A, 0)]);
        assert_eq!(l.svc.borrow().holder(), 2);
        assert!(w.console().contains("focus 1 -> 2 (moved)"));
    }

    /// **A grant that cannot be made whole leaves the focus where it was.** No
    /// memory object for the ring, or no capability for the warrant: `BUSY`,
    /// the old holder still holds, nothing of it is revoked, and a ring made
    /// for the failed grant is given back.
    ///
    /// **Canary.** Drop the old holder before making the new ring: the holder
    /// and revoked assertions go red.
    #[test]
    fn a_grant_that_fails_leaves_the_focus_where_it_was() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        w.0.borrow_mut().no_ring = true;
        let r = c.take_focus().unwrap();
        assert_eq!(r.code, outcome::BUSY);
        assert_eq!(l.last.borrow().n_caps, 0, "nothing is lent on a refusal");
        w.0.borrow_mut().no_ring = false;
        w.0.borrow_mut().no_warrant = true;
        assert_eq!(c.take_focus().unwrap().code, outcome::BUSY);
        {
            let wd = w.0.borrow();
            assert!(wd.revoked.is_empty(), "the holder keeps its warrant");
            assert!(!wd.rings[0].closed, "and its ring");
            assert!(wd.rings[1].closed, "the ring made for the failed grant is given back");
        }
        assert_eq!(l.svc.borrow().holder(), 1);
        w.0.borrow_mut().no_warrant = false;
        assert_eq!(c.take_focus().unwrap().value.generation, 2, "a failed grant used no generation");
    }

    /// **Release is the holder's, through the live warrant.** The plain
    /// endpoint (a row's badge), a warrant of a generation that is not the live
    /// one and a call with no badge are `DENIED`, counted and recorded; the
    /// live warrant releases, and the focus is then nobody's.
    ///
    /// **Canary.** Accept any warrant badge in `release`: the stale-generation
    /// refusal goes red.
    #[test]
    fn release_needs_the_live_warrant() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        assert_eq!(c.release().unwrap().code, outcome::DENIED, "no holder at all");
        c.take_focus().unwrap();
        c.take_focus().unwrap();
        for badge in [3, 0, warrant_badge(1), warrant_badge(9)] {
            *l.badge.borrow_mut() = badge;
            assert_eq!(c.release().unwrap().code, outcome::DENIED, "badge {badge:#x}");
            assert_eq!(l.svc.borrow().holder(), 2);
        }
        assert_eq!(c.status().unwrap().value.refused, 5);
        *l.badge.borrow_mut() = warrant_badge(2);
        assert!(c.release().unwrap().is_ok());
        assert_eq!(l.svc.borrow().holder(), 0);
        assert!(w.0.borrow().rings[1].closed && w.0.borrow().revoked.contains(&(WARRANT_HANDLE0 + 1)));
        assert!(w.console().contains("refused: no grant") && w.console().contains("released"));
        // Nobody holds the focus: an event is dropped, not queued for the next.
        w.send(&[A]);
        pump(&l);
        c.take_focus().unwrap();
        assert_eq!(w.ring(2), []);
    }

    /// **The Secure Attention Key is never delivered and takes the focus.**
    /// Ctrl+Alt+Delete: the modifiers go through (the server cannot know a
    /// chord is coming), the Delete press does not; the holder is revoked, its
    /// ring closed, the chord counted on the trusted page and recorded as a
    /// trusted-path move. The trusted surface that takes the focus next never
    /// sees the chord's Delete repeat or release either.
    ///
    /// **Canaries.** Skip `drop_holder` in `attention`: the holder and revoked
    /// assertions go red. Do not set `swallowing`: the new holder's ring
    /// receives the Delete repeat and release.
    #[test]
    fn the_attention_key_is_swallowed_and_takes_the_focus() {
        let w = Fake::default();
        w.0.borrow_mut().now = 1234;
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        w.send(&[CTRL, ALT, DEL]);
        pump(&l);
        assert_eq!(w.ring(0), [CTRL, ALT], "the Delete of the chord never reached the holder");
        {
            let wd = w.0.borrow();
            assert!(wd.rings[0].closed);
            assert_eq!(wd.revoked, [WARRANT_HANDLE0]);
            assert_eq!(wd.sak, [1234]);
        }
        assert_eq!(l.svc.borrow().holder(), 0);
        assert_eq!(c.status().unwrap().value.sak, 1);
        assert!(w.console().contains("focus 1 -> 0 (trusted path)"), "{}", w.console());
        // The trusted surface asks for the focus while the keys are still down:
        // it is told what is down (the modifiers), and not of the Delete.
        *l.badge.borrow_mut() = TRUSTED_BADGE;
        let r = c.take_focus().unwrap();
        assert_eq!(r.value.generation, 2);
        w.send(&[(EV_KEY, KEY_DELETE, 2), DEL_UP, (EV_KEY, KEY_LEFTALT, 0), (EV_KEY, KEY_LEFTCTRL, 0)]);
        pump(&l);
        assert_eq!(w.ring(1), [CTRL, ALT, (EV_KEY, KEY_LEFTALT, 0), (EV_KEY, KEY_LEFTCTRL, 0)]);
        // The swallow ended with the release: a lone Delete is an ordinary key
        // again, and either Ctrl and either Alt (AltGr) make the chord.
        w.send(&[DEL_UP, DEL]);
        pump(&l);
        assert_eq!(w.ring(1).last(), Some(&DEL));
        w.send(&[(EV_KEY, KEY_RIGHTCTRL, 1), (EV_KEY, KEY_RIGHTALT, 1), DEL]);
        pump(&l);
        assert_eq!(c.status().unwrap().value.sak, 2);
    }

    /// **After the chord only the trusted surface takes the focus.** The former
    /// holder and any other caller (a row's badge, none, the revoked warrant of
    /// the grant the chord took, a warrant of a generation that never was) is
    /// refused: `DENIED`, recorded `NO_GRANT`, counted in `refused`, no ring
    /// made and no warrant derived for it, the focus left with nobody. The
    /// trusted surface's call (badge [`TRUSTED_BADGE`]) is granted and clears the
    /// gate, so the next plain caller moves the focus as it always could.
    ///
    /// **Canaries.** Drop the `self.pending && !trusted` refusal in `take_focus`:
    /// the DENIED assertions go red (this is the old accepted-limit test, flipped).
    /// Never clear `pending`: the last plain grant is refused and the test goes red.
    #[test]
    fn after_the_attention_key_only_the_trusted_surface_takes_the_focus() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        let mut expected_refused = 0;
        for badge in [3, 0, 12, warrant_badge(1), warrant_badge(77)] {
            *l.badge.borrow_mut() = 3;
            let held = c.take_focus().unwrap().value.generation;
            w.send(&[CTRL, ALT, DEL]);
            pump(&l);
            assert_eq!(l.svc.borrow().holder(), 0, "the chord took the focus (badge {badge})");
            assert!(l.svc.borrow().pending(), "the chord closed the gate");
            assert_eq!(c.status().unwrap().value.pending, 1, "and the status says so");
            let (rings, warrants, revoked) = {
                let wd = w.0.borrow();
                (wd.rings.len(), wd.warrants.len(), wd.revoked.len())
            };
            *l.badge.borrow_mut() = badge;
            let again = c.take_focus().unwrap();
            assert_eq!(again.code, outcome::DENIED, "a plain caller (badge {badge}) is refused after the chord");
            expected_refused += 1;
            assert_eq!(l.svc.borrow().holder(), 0, "the focus stays with nobody");
            {
                let wd = w.0.borrow();
                assert_eq!((wd.rings.len(), wd.warrants.len(), wd.revoked.len()), (rings, warrants, revoked));
            }
            assert_eq!(c.status().unwrap().value.refused, expected_refused);
            let newest = *l.svc.borrow().records().next().unwrap();
            assert_eq!((newest.reason, newest.from, newest.to), (reason::NO_GRANT, 0, 0), "recorded as a refusal, not a move");
            // The trusted surface hands it on: it takes the focus (clearing the
            // gate), and the plain caller then moves it.
            *l.badge.borrow_mut() = TRUSTED_BADGE;
            let t = c.take_focus().unwrap();
            assert!(t.is_ok(), "the trusted surface takes the focus after the chord");
            assert_eq!(t.value.generation, held + 1);
            assert!(!l.svc.borrow().pending());
            assert_eq!(c.status().unwrap().value.pending, 0, "the trusted surface's grant opened it");
            *l.badge.borrow_mut() = badge;
            let plain = c.take_focus().unwrap();
            assert!(plain.is_ok(), "the trusted surface opened the gate: badge {badge} may take the focus again");
            assert_eq!(plain.value.generation, held + 2);
            w.send(&[(EV_KEY, KEY_DELETE, 0), (EV_KEY, KEY_LEFTALT, 0), (EV_KEY, KEY_LEFTCTRL, 0)]);
            pump(&l);
        }
        assert_eq!(w.0.borrow().sak.len(), 5, "every chord was counted on the trusted page");
        assert_eq!(w.console().matches("(trusted path)").count(), 5);
        assert_eq!(w.console().matches("(refused: no grant)").count(), 5);
    }

    /// **A failed grant by the trusted surface does not open the gate; a second
    /// chord while it is closed keeps it closed.** `BUSY` (no ring left) is the
    /// trusted surface's problem to retry; nobody else gets in meanwhile.
    ///
    /// **Canary.** Clear `pending` before the grant is whole in `take_focus`: the
    /// plain caller after the failed trusted grant is granted and this goes red.
    #[test]
    fn a_failed_trusted_grant_leaves_the_gate_closed() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        w.send(&[CTRL, ALT, DEL]);
        pump(&l);
        w.send(&[DEL_UP, (EV_KEY, KEY_LEFTALT, 0), (EV_KEY, KEY_LEFTCTRL, 0)]);
        pump(&l);
        w.send(&[CTRL, ALT, DEL]);
        pump(&l);
        assert!(l.svc.borrow().pending(), "two chords, one closed gate");
        *l.badge.borrow_mut() = TRUSTED_BADGE;
        w.0.borrow_mut().no_ring = true;
        assert_eq!(c.take_focus().unwrap().code, outcome::BUSY);
        w.0.borrow_mut().no_ring = false;
        w.0.borrow_mut().no_warrant = true;
        assert_eq!(c.take_focus().unwrap().code, outcome::BUSY);
        w.0.borrow_mut().no_warrant = false;
        assert!(l.svc.borrow().pending(), "a grant that failed opens nothing");
        *l.badge.borrow_mut() = 3;
        assert_eq!(c.take_focus().unwrap().code, outcome::DENIED);
        *l.badge.borrow_mut() = TRUSTED_BADGE;
        assert!(c.take_focus().unwrap().is_ok());
        assert!(!l.svc.borrow().pending());
    }

    /// **The trusted surface is not special before a chord, and gives no more
    /// than the focus.** Its badge takes the focus with nothing pending like any
    /// caller, releases only through its own warrant, and a plain caller's
    /// release of the compositor's grant is refused.
    ///
    /// **Canary.** Let `release` accept any badged caller: the first two assertions go red.
    #[test]
    fn the_trusted_badge_is_an_ordinary_caller_when_no_chord_is_pending() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        *l.badge.borrow_mut() = TRUSTED_BADGE;
        let lease = c.take_focus().unwrap();
        assert!(lease.is_ok() && !l.svc.borrow().pending());
        // The plain release (the row's badge, not the warrant) is refused; so is
        // the trusted badge: a release needs the live warrant.
        assert_eq!(c.release().unwrap().code, outcome::DENIED);
        *l.badge.borrow_mut() = 3;
        assert_eq!(c.release().unwrap().code, outcome::DENIED);
        *l.badge.borrow_mut() = warrant_badge(lease.value.generation);
        assert!(c.release().unwrap().is_ok());
        assert_eq!(l.svc.borrow().holder(), 0);
    }

    /// **Without a trusted surface in the build the chord only revokes.** The
    /// gate is a configuration fact (Kconfig `COMPOSITOR`): with no compositor
    /// row nobody holds the badge, so a closed gate could never be opened and the
    /// focus would be unobtainable. The former behavior holds: any caller takes
    /// the focus straight back.
    ///
    /// **Canary.** Set `pending` whatever `gated` says: this goes red.
    #[test]
    fn without_a_trusted_surface_the_chord_only_revokes() {
        let w = Fake::default();
        let l = lp_gated(&w, false);
        let mut c = InputClient::new(&l);
        for badge in [3, 0, 12] {
            *l.badge.borrow_mut() = badge;
            let held = c.take_focus().unwrap().value.generation;
            w.send(&[CTRL, ALT, DEL]);
            pump(&l);
            assert_eq!(l.svc.borrow().holder(), 0);
            assert!(!l.svc.borrow().pending());
            let again = c.take_focus().unwrap();
            assert!(again.is_ok(), "badge {badge} takes it straight back");
            assert_eq!(again.value.generation, held + 1);
            w.send(&[(EV_KEY, KEY_DELETE, 0), (EV_KEY, KEY_LEFTALT, 0), (EV_KEY, KEY_LEFTCTRL, 0)]);
            pump(&l);
        }
        assert_eq!(c.status().unwrap().value.refused, 0);
        assert_eq!(c.status().unwrap().value.pending, 0, "no trusted surface, no gate to be pending");
    }

    /// **The status crosses as four words and every field comes back as it went.**
    /// Two 32-bit fields share a word, so a swapped half would not show in a
    /// reply that holds one value in each; distinct values do.
    ///
    /// **Canary.** Swap `pending` and `sak` in `Status::put`: red.
    #[test]
    fn the_status_round_trips_on_the_wire() {
        use azos_idl::{Reader, Wire, Writer};
        let s = Status { holder: 1, grants: 2, sak: 3, events: u64::MAX - 5, lost: 4, refused: 5, pending: 1 };
        let mut msg = MsgDesc::default();
        s.put(&mut Writer::new(&mut msg));
        msg.n_words = <Status as Wire>::WORDS as u8;
        assert_eq!(Status::get(&mut Reader::new(&msg)), s);
        assert_eq!(<Status as Wire>::WORDS, 4);
    }

    /// **The trusted badge is its own value.** No warrant has it (a warrant's
    /// badge has the top bit), it is not a row's small badge, and the kernel
    /// stamps it on a calling grant that carries `EXEC` and not `READ`: a
    /// serving grant (`READ`) or a plain call right (`WRITE`) gets none.
    ///
    /// **Canary.** Give `TRUSTED_BADGE` the warrant bit: `generation_of` answers
    /// `Some` and this goes red.
    #[test]
    fn the_trusted_badge_is_no_warrant_and_no_row_badge() {
        assert_eq!(generation_of(TRUSTED_BADGE), None);
        assert_ne!(TRUSTED_BADGE, 0);
        assert_eq!(TRUSTED_BADGE & WARRANT_BADGE, 0);
        for g in [0, 1, 2, 77, !WARRANT_BADGE] {
            assert_ne!(warrant_badge(g), TRUSTED_BADGE, "generation {g}");
        }
        let (w, x, r) = (CapPerms::WRITE.bits(), CapPerms::EXEC.bits(), CapPerms::READ.bits());
        assert_eq!(grant_badge(w | x), Some(TRUSTED_BADGE));
        assert_eq!(grant_badge(x), Some(TRUSTED_BADGE));
        assert_eq!(grant_badge(w), None, "the plain call right is unbadged");
        assert_eq!(grant_badge(r | w), None, "the serving grant is unbadged");
        assert_eq!(grant_badge(r | w | x), None);
    }

    /// **Only the whole chord is the key.** Delete alone, with Ctrl alone, with
    /// Alt alone, after the modifiers were released, and a repeat of Delete
    /// that began before the modifiers: ordinary keys, delivered, no chord.
    ///
    /// **Canary.** Test `CTRL | ALT` as `CTRL || ALT`: the first two lines go
    /// red.
    #[test]
    fn a_partial_chord_is_an_ordinary_key() {
        let w = Fake::default();
        let l = lp(&w);
        InputClient::new(&l).take_focus().unwrap();
        w.send(&[DEL, DEL_UP, CTRL, DEL, DEL_UP, (EV_KEY, KEY_LEFTCTRL, 0), ALT, DEL, DEL_UP, (EV_KEY, KEY_LEFTALT, 0)]);
        // Ctrl pressed and released before Alt: no overlap.
        w.send(&[CTRL, (EV_KEY, KEY_LEFTCTRL, 0), ALT, DEL, DEL_UP, (EV_KEY, KEY_LEFTALT, 0)]);
        // A repeat (2) of a Delete whose press was before the modifiers is no
        // chord: only a press (1) completes one.
        w.send(&[(EV_KEY, KEY_DELETE, 2), CTRL, ALT, (EV_KEY, KEY_DELETE, 2)]);
        pump(&l);
        assert_eq!(l.svc.borrow().holder(), 1, "no chord, the focus stays");
        assert_eq!(w.0.borrow().sak.len(), 0);
        assert_eq!(w.ring(0).len(), 10 + 6 + 4, "every key was delivered");
    }

    /// **A new holder starts with the true state.** What is down when the grant
    /// is made (modifiers, mouse buttons) is replayed as presses at the start
    /// of its ring; what is up is not.
    ///
    /// **Canary.** Drop the replay loop in `take_focus`: the first assertion
    /// goes red.
    #[test]
    fn a_new_holder_is_told_what_is_down() {
        let w = Fake::default();
        let l = lp(&w);
        w.send(&[(EV_KEY, KEY_LEFTSHIFT, 1), (EV_KEY, BTN_LEFT, 1), (EV_KEY, KEY_RIGHTALT, 1), (EV_KEY, KEY_RIGHTALT, 0), A]);
        pump(&l);
        InputClient::new(&l).take_focus().unwrap();
        assert_eq!(w.ring(0), [(EV_KEY, KEY_LEFTSHIFT, 1), (EV_KEY, BTN_LEFT, 1)]);
    }

    /// **A dropped event cannot leave a key stuck.** The stream counts what it
    /// dropped when it was full; once it is drained the server lets go of
    /// everything it thinks is held, and tells the holder with releases.
    ///
    /// **Canary.** Ignore `stream_drops`: the releases and the `lost` count go
    /// red.
    #[test]
    fn a_dropped_stream_event_releases_what_was_held() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        w.send(&[(EV_KEY, KEY_LEFTSHIFT, 1), (EV_KEY, BTN_RIGHT, 1)]);
        pump(&l);
        w.0.borrow_mut().stream_drops = 3;
        w.send(&[(EV_REL, REL_Y, 1)]);
        pump(&l);
        assert_eq!(
            w.ring(0),
            [(EV_KEY, KEY_LEFTSHIFT, 1), (EV_KEY, BTN_RIGHT, 1), (EV_REL, REL_Y, 1), (EV_KEY, KEY_LEFTSHIFT, 0), (EV_KEY, BTN_RIGHT, 0)]
        );
        assert_eq!(c.status().unwrap().value.lost, 3);
        // And the state is clean: a grant now replays nothing.
        c.take_focus().unwrap();
        assert_eq!(w.ring(1), []);
        // The count was taken: a later pump with the same count does nothing.
        pump(&l);
        assert_eq!(c.status().unwrap().value.lost, 3);
    }

    /// **A holder that does not read loses the newest events, counted.** A full
    /// ring refuses the event (the host counts it in the ring), the server
    /// counts it in `lost`, and the events already in the ring are untouched.
    ///
    /// **Canaries.** Ignore `push`'s `false` in `deliver`: the `lost` assertion
    /// goes red. Overwrite instead of refusing in the fake ring (the drop-oldest
    /// policy): the ring-content assertion goes red.
    #[test]
    fn a_full_holder_ring_drops_the_newest_and_counts() {
        let w = Fake::default();
        let l = lp(&w);
        w.0.borrow_mut().ring_cap = 3;
        let mut c = InputClient::new(&l);
        c.take_focus().unwrap();
        for i in 0..5 {
            w.send(&[(EV_REL, REL_X, i)]);
        }
        pump(&l);
        assert_eq!(w.ring(0), [(EV_REL, REL_X, 0), (EV_REL, REL_X, 1), (EV_REL, REL_X, 2)]);
        assert_eq!(w.0.borrow().rings[0].drops, 2);
        assert_eq!(c.status().unwrap().value.lost, 2);
    }

    /// **The trusted page is lent read-only, whoever asks.** The chord is not a
    /// secret and cannot be faked: a task maps the page without write.
    ///
    /// **Canary.** Lend the page with `WRITE`: the rights assertion goes red.
    #[test]
    fn the_trusted_page_is_lent_read_only() {
        let w = Fake::default();
        let l = lp(&w);
        let r = InputClient::new(&l).trusted().unwrap();
        assert!(r.is_ok() && r.value.page.get().is_some());
        let rep = *l.last.borrow();
        assert_eq!((rep.caps[0].handle, rep.caps[0].mode), (PAGE_HANDLE, CAP_MODE_DUP));
        assert_eq!(rep.caps[0].rights, PAGE_RIGHTS.bits() as u16);
    }

    /// **The decision record is kept, newest over oldest, and counted.** Every
    /// move and refusal is a record with the shape of `Rule::Focus` (`from`,
    /// `to`, `reason`); the ring keeps the newest [`RECORDS_KEPT`].
    ///
    /// **Canaries.** Do not advance `made` in `record`: the length and the
    /// newest-first assertions go red. Index `records` without the modulus in
    /// `record`: the test panics past [`RECORDS_KEPT`].
    #[test]
    fn the_decision_record_keeps_the_newest() {
        let w = Fake::default();
        let l = lp(&w);
        let mut c = InputClient::new(&l);
        for _ in 0..RECORDS_KEPT + 2 {
            c.take_focus().unwrap();
        }
        let svc = l.svc.borrow();
        let r: Vec<Record> = svc.records().copied().collect();
        assert_eq!(r.len(), RECORDS_KEPT);
        assert_eq!((r[0].from, r[0].to, r[0].reason), (RECORDS_KEPT as u32 + 1, RECORDS_KEPT as u32 + 2, reason::MOVED));
        assert_eq!((r[1].from, r[1].to), (RECORDS_KEPT as u32, RECORDS_KEPT as u32 + 1));
    }

    /// The server takes over a stream that has things in it: what piled up
    /// before there was a server is dropped, and the drops counted so far are
    /// not this server's losses.
    ///
    /// **Canaries.** Skip the drain loop in `attach`: the backlog reaches the
    /// first holder and the ring assertion goes red. Skip the `drops_seen`
    /// assignment: the first `pump` charges the 40 old drops and the `lost`
    /// assertion goes red.
    #[test]
    fn attach_drops_the_backlog_and_the_old_drop_count() {
        let w = Fake::default();
        w.send(&[A, (EV_REL, REL_X, 1)]);
        w.0.borrow_mut().stream_drops = 40;
        let l = lp(&w);
        l.svc.borrow_mut().attach();
        InputClient::new(&l).take_focus().unwrap();
        pump(&l);
        assert_eq!(w.ring(0), []);
        assert_eq!(InputClient::new(&l).status().unwrap().value.lost, 0);
    }

    /// The ring markers: the close word and the drop counter are in the head
    /// line and do not collide with the ring's head index, the trusted page's
    /// counter and time read back what was recorded.
    ///
    /// **Canaries.** Give `CLOSED_OFF` the value of `DROPS_OFF`: the "a drop is
    /// not a close" assertion goes red. Give `SAK_AT_OFF` the value of
    /// `SAK_COUNT_OFF`: the count/time assertion goes red.
    #[test]
    fn the_ring_and_page_words_read_back() {
        #[repr(align(64))]
        struct Page([u8; 4096]);
        let mut p = Box::new(Page([0; 4096]));
        let base = p.0.as_mut_ptr() as usize;
        assert!(!EventRing::closed(base));
        EventRing::drop_one(base);
        EventRing::drop_one(base);
        assert_eq!(EventRing::drops(base), 2);
        assert!(!EventRing::closed(base), "a drop is not a close");
        EventRing::close(base);
        assert!(EventRing::closed(base));
        assert_eq!(EventRing::drops(base), 2);
        assert_eq!(TrustedPage::count(base), 0);
        TrustedPage::record(base, 77);
        TrustedPage::record(base, 99);
        assert_eq!((TrustedPage::count(base), TrustedPage::at_ns(base)), (2, 99));
        assert!(RING_SLOTS.is_power_of_two());
    }
}
