// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the Names object: the interface and the codec of the
//! name server's view of the signed topology (`userspace/lib/names`), and the
//! name server's decision and refusal record (`userspace/services/namesd/src/
//! service.rs`, pulled in with `#[path]` so the code under test is the code
//! `NAMESD.ELF` is built from).
//!
//! The service is driven through the generated client stub over a loopback
//! transport, so the wire form a borrower sends and receives is the one under
//! test. The kernel half (a DUP transfer with lowered rights is a child in the
//! warrant tree; the badge the kernel stamps) is tested where the kernel
//! tables are: `tests/host/topology-tests` (`names_tests`, `cap_seed`) and
//! `tests/host/cap-tests`.

#[allow(dead_code)]
#[path = "../../../../userspace/services/namesd/src/service.rs"]
pub mod service;

#[cfg(test)]
mod namesd {
    use crate::service::{Host, Refusal, Service, Why, LENT_RIGHTS, REFUSALS_KEPT};
    use azos_abi::cap::CapPerms;
    use azos_idl::{CAP_MODE_DUP, MSG_VERSION};
    use azos_names::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The world the server sees: a view text, the handles it holds, and what
    /// it wrote to the console.
    #[derive(Default)]
    struct World {
        view: Vec<u8>,
        handles: Vec<(u32, u32)>,
        console: Vec<u8>,
        view_reads: u32,
        /// The monotonic clock the server reads, nanoseconds.
        now: u64,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<World>>);

    impl Host for Fake {
        fn view(&mut self, buf: &mut [u8]) -> usize {
            let mut w = self.0.borrow_mut();
            w.view_reads += 1;
            let n = w.view.len().min(buf.len());
            buf[..n].copy_from_slice(&w.view[..n]);
            n
        }
        fn handle(&mut self, index: u32) -> Option<u32> {
            self.0.borrow().handles.iter().find(|(i, _)| *i == index).map(|(_, h)| *h)
        }
        fn log(&mut self, line: &[u8]) {
            self.0.borrow_mut().console.extend_from_slice(line);
        }
        fn now_ns(&mut self) -> u64 {
            self.0.borrow().now
        }
    }

    /// Row 7 (the shell) imports `term`; row 9 imports `log`; the server holds
    /// `term` (pool index 1, served by TERMD.ELF), and `log` (index 3, unserved).
    const VIEW: &str = "export term 1 TERMD.ELF\nexport log 3 -\nallow 7 term\nallow 9 log\n";

    fn world() -> Fake {
        let f = Fake::default();
        f.0.borrow_mut().view = VIEW.as_bytes().to_vec();
        f.0.borrow_mut().handles = vec![(1, 0x1111), (3, 0x3333)];
        f
    }

    /// A client stub over the service, as a borrower sees it: the request is
    /// dispatched with the caller's badge, the reply comes back as the wire
    /// form the kernel would carry (and tests can inspect).
    struct Loop {
        svc: RefCell<Service<Fake>>,
        badge: u32,
        last: RefCell<MsgDesc>,
    }

    impl Transport for &Loop {
        fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
            let mut svc = self.svc.borrow_mut();
            svc.caller = self.badge;
            let mut rep = MsgDesc::default();
            NamesIdl::dispatch(&mut *svc, msg, &mut rep)?;
            *self.last.borrow_mut() = rep;
            *msg = rep;
            Ok(())
        }
    }

    fn lp(badge: u32, w: &Fake) -> Loop {
        lp_ttl(badge, w, 0)
    }

    fn lp_ttl(badge: u32, w: &Fake, ttl_ns: u64) -> Loop {
        Loop { svc: RefCell::new(Service::new(w.clone(), ttl_ns)), badge, last: RefCell::new(MsgDesc::default()) }
    }

    fn name(n: &str) -> PackedName {
        pack_name(n.as_bytes()).unwrap()
    }

    /// **An allowed lookup lends the endpoint, and only that.** Row 7 imports
    /// `term`: the reply is a DUP entry for the server's handle for `term`
    /// (pool index 1), with explicit rights, and nothing is recorded.
    ///
    /// **Canaries.** Skip the `allowed` check in `decide`: row 8's lookup
    /// below is lent too. Look the handle up at the wrong index: the handle
    /// assertion goes red.
    #[test]
    fn an_allowed_lookup_is_lent_as_a_dup_entry() {
        let w = world();
        let l = lp(7, &w);
        let mut c = NamesClient::new(&l);
        let got = c.lookup(name("term")).unwrap();
        // The client sees a capability (its handle is the kernel's to assign;
        // the loopback shows the server's).
        assert!(got.get().is_some());
        let rep = *l.last.borrow();
        assert_eq!(rep.n_caps, 1);
        assert_eq!(rep.caps[0].handle, 0x1111, "the server's handle for the `term` endpoint");
        assert_eq!(rep.caps[0].mode, CAP_MODE_DUP, "a copy; the server keeps its own");
        assert_eq!(l.svc.borrow().refused, 0, "an allowed lookup records nothing");
        assert_eq!(rep.version, MSG_VERSION);
    }

    /// **A refused lookup lends nothing and is recorded.** A row that does not
    /// list the name (8), a name the row lists but the server does not hold,
    /// a call with no badge, and a name that is no name: each is `Lent::none`
    /// on the wire (no capability entry), counted, kept in the ring with who
    /// asked for what and why, and written to the console.
    ///
    /// **Canaries.** Drop `self.refuse(..)` from the `NotImported` arm: the
    /// count and the console line go red. Return `Lent::dup` on refusal: the
    /// entry assertion goes red.
    #[test]
    fn a_refused_lookup_lends_nothing_and_is_recorded() {
        let w = world();

        // Row 8 imports nothing.
        let l = lp(8, &w);
        let got = NamesClient::new(&l).lookup(name("term")).unwrap();
        assert_eq!(got.get(), None);
        assert_eq!(l.last.borrow().n_caps, 0, "no capability entry crossed");
        let svc = l.svc.borrow();
        assert_eq!(svc.refused, 1);
        let r: Vec<Refusal> = svc.refusals().copied().collect();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].badge, r[0].op, r[0].why), (8, 1, Why::NotImported));
        assert_eq!(&r[0].name[..r[0].name_len as usize], b"term");
        drop(svc);
        let console = String::from_utf8(w.0.borrow().console.clone()).unwrap();
        assert!(console.contains("REFUSED lookup badge=8 name=term (not-imported)"), "{console}");

        // Row 9 imports `log`, but nothing it can lend is held for index 3
        // once the handle is gone: NotHeld, still no entry.
        w.0.borrow_mut().handles.retain(|(i, _)| *i != 3);
        let l = lp(9, &w);
        assert_eq!(NamesClient::new(&l).lookup(name("log")).unwrap().get(), None);
        assert_eq!(l.svc.borrow().refusals().next().unwrap().why, Why::NotHeld);

        // Row 7 asks for a name it imports that the view does not export.
        w.0.borrow_mut().view = b"allow 7 term\n".to_vec();
        let l = lp(7, &w);
        assert_eq!(NamesClient::new(&l).lookup(name("term")).unwrap().get(), None);
        assert_eq!(l.svc.borrow().refusals().next().unwrap().why, Why::NotHeld);

        // No badge: the caller's row is unknown, whatever it asks.
        w.0.borrow_mut().view = VIEW.as_bytes().to_vec();
        let l = lp(0, &w);
        assert_eq!(NamesClient::new(&l).lookup(name("term")).unwrap().get(), None);
        assert_eq!(l.svc.borrow().refusals().next().unwrap().why, Why::Unidentified);

        // A zero name is no name.
        let l = lp(7, &w);
        assert_eq!(NamesClient::new(&l).lookup([0; 3]).unwrap().get(), None);
        assert_eq!(l.svc.borrow().refusals().next().unwrap().why, Why::Malformed);
    }

    /// The ring keeps the newest [`REFUSALS_KEPT`] and the count keeps going.
    #[test]
    fn the_refusal_ring_keeps_the_newest_and_the_count_keeps_going() {
        let w = world();
        let l = lp(8, &w);
        let mut c = NamesClient::new(&l);
        for i in 0..REFUSALS_KEPT + 3 {
            let n = format!("n{i}");
            let _ = c.lookup(name(&n)).unwrap();
        }
        let svc = l.svc.borrow();
        assert_eq!(svc.refused as usize, REFUSALS_KEPT + 3);
        let newest = svc.refusals().next().unwrap();
        assert_eq!(&newest.name[..newest.name_len as usize], format!("n{}", REFUSALS_KEPT + 2).as_bytes());
        assert_eq!(svc.refusals().count(), REFUSALS_KEPT);
    }

    /// **Attenuation.** What is lent carries the call right and nothing else:
    /// not `DUP` (the borrower cannot hand it on), not `READ` (it is not the
    /// server), and the rights are explicit (0 would mean the server's own).
    ///
    /// **Canaries.** `LENT_RIGHTS = RW | DUP`: both inequalities go red.
    /// `Lent::dup(h, 0)`: the non-zero assertion goes red.
    #[test]
    fn the_lent_capability_is_attenuated_to_the_call_right() {
        let w = world();
        let l = lp(7, &w);
        let _ = NamesClient::new(&l).lookup(name("term")).unwrap();
        let rights = CapPerms::from_bits_truncate(l.last.borrow().caps[0].rights as u8);
        assert_ne!(l.last.borrow().caps[0].rights, 0, "0 on the wire is the sender's own rights");
        assert_eq!(rights, CapPerms::WRITE);
        assert!(!rights.contains(CapPerms::DUP), "the borrower must not be able to gift it");
        assert!(!rights.contains(CapPerms::READ), "a borrower is not the server");
        assert_eq!(LENT_RIGHTS, CapPerms::WRITE);
    }

    /// `who_serves`: the serving task for a name the row imports; all zero
    /// when unserved (not a refusal) and when the row may not ask (a refusal).
    ///
    /// **Canary.** Skip the `allowed` check: row 8 learns who serves `term`.
    #[test]
    fn who_serves_answers_the_row_and_only_the_row() {
        let w = world();
        let l = lp(7, &w);
        let mut c = NamesClient::new(&l);
        let mut b = [0u8; NAME_MAX];
        let r = c.who_serves(name("term")).unwrap();
        let n = unpack_name(&r, &mut b);
        assert_eq!(&b[..n], b"TERMD.ELF");
        assert_eq!(l.svc.borrow().refused, 0);

        // Unserved: zero, and no refusal (the row may ask; nobody answers).
        let l9 = lp(9, &w);
        assert_eq!(NamesClient::new(&l9).who_serves(name("log")).unwrap(), [0; 3]);
        assert_eq!(l9.svc.borrow().refused, 0);

        // A row that does not import the name: zero and a recorded refusal.
        let l8 = lp(8, &w);
        assert_eq!(NamesClient::new(&l8).who_serves(name("term")).unwrap(), [0; 3]);
        let svc = l8.svc.borrow();
        let r = svc.refusals().next().unwrap();
        assert_eq!((r.op, r.why), (2, Why::NotImported));
    }

    /// **A lease has a deadline.** With a lifetime set the server stamps the
    /// entry `now + ttl` (the kernel derives the borrower's copy with the
    /// earlier of that and the server's own); with none it stamps 0, which
    /// leaves the copy as long-lived as the server's capability.
    ///
    /// **Canaries.** Drop `until` in `lookup` (back to `Lent::dup`): the
    /// stamped assertion reads 0 and goes red. Stamp `ttl` instead of
    /// `now + ttl`: the equality goes red. Stamp even when `ttl` is 0: the
    /// last assertion goes red.
    #[test]
    fn a_lookup_is_stamped_with_now_plus_the_lifetime() {
        let w = world();
        w.0.borrow_mut().now = 10_000_000_000;
        let l = lp_ttl(7, &w, 600_000_000_000);
        let got = NamesClient::new(&l).lookup(name("term")).unwrap();
        assert!(got.get().is_some());
        assert_eq!(l.last.borrow().caps[0].expiry_ns, 610_000_000_000);

        let l = lp_ttl(7, &w, 0);
        let _ = NamesClient::new(&l).lookup(name("term")).unwrap();
        assert_eq!(l.last.borrow().caps[0].expiry_ns, 0, "no lifetime, no deadline of the lease's own");
    }

    /// The model of what the kernel does with a lease, as far as a borrower
    /// can tell: a handle answers until its deadline and then the call is
    /// refused with the one code the v2 call gives an endpoint it cannot
    /// resolve (`-EPERM`). The name server is the real `Service`.
    struct Kernel {
        svc: RefCell<Service<Fake>>,
        world: Fake,
        /// Lent handles: (handle, deadline).
        leases: RefCell<Vec<(u32, u64)>>,
        closed: RefCell<Vec<u32>>,
        next: std::cell::Cell<u32>,
        ttl_ns: u64,
    }

    const NAMES_H: u32 = 0x77;

    impl azos_names::Call for &Kernel {
        fn call(&self, handle: u32, msg: &mut MsgDesc) -> isize {
            let now = self.world.0.borrow().now;
            if handle == NAMES_H {
                let mut svc = self.svc.borrow_mut();
                svc.caller = 7;
                let mut rep = MsgDesc::default();
                if NamesIdl::dispatch(&mut *svc, msg, &mut rep).is_err() {
                    return -22;
                }
                // The kernel derives the borrower's handle from the entry.
                if rep.n_caps == 1 {
                    let h = self.next.get();
                    self.next.set(h + 1);
                    let dl = rep.caps[0].expiry_ns;
                    self.leases.borrow_mut().push((h, dl));
                    rep.caps[0].handle = h;
                }
                *msg = rep;
                return 0;
            }
            match self.leases.borrow().iter().find(|(h, _)| *h == handle) {
                Some((_, dl)) if *dl == 0 || now < *dl && !self.closed.borrow().contains(&handle) => {
                    msg.n_words = 1;
                    msg.words[0] = 0;
                    0
                }
                _ => -1,
            }
        }
        fn close(&self, handle: u32) {
            self.closed.borrow_mut().push(handle);
        }
    }

    fn kernel(ttl_ns: u64) -> Kernel {
        let w = world();
        w.0.borrow_mut().now = 1_000;
        Kernel {
            svc: RefCell::new(Service::new(w.clone(), ttl_ns)),
            world: w,
            leases: RefCell::new(Vec::new()),
            closed: RefCell::new(Vec::new()),
            next: std::cell::Cell::new(0x100),
            ttl_ns,
        }
    }

    fn ping(t: &impl Transport) -> Result<(), IdlError> {
        let mut m = MsgDesc::default();
        m.version = MSG_VERSION;
        m.n_words = 1;
        t.call(&mut m)
    }

    /// **A lapsed lease is renewed, once, and the call succeeds.** The
    /// borrower holds a copy that dies at now + 100; after that a call is
    /// refused; `Renewing` asks the name server again, closes the dead handle,
    /// and the retry on the new one is served.
    ///
    /// **Canaries.** Make `lease_lapsed` return false: the second call fails
    /// (the lease is not renewed). Skip the `close` in `renew`: the closed
    /// list stays empty. Retry more than once: the call count assertion goes red.
    #[test]
    fn a_lapsed_lease_is_asked_for_again_and_the_call_succeeds() {
        let k = kernel(100);
        let r = azos_names::Renewing::new(&k, NAMES_H, name("term"), 0);
        // The first call asks (no handle yet) and is served.
        assert_eq!(ping(&r), Ok(()));
        let first = r.handle();
        assert_eq!(first, 0x100);
        assert_eq!(k.leases.borrow()[0], (0x100, 1_000 + k.ttl_ns));

        // Inside the lease: served on the same handle, no new lookup.
        k.world.0.borrow_mut().now = 1_050;
        assert_eq!(ping(&r), Ok(()));
        assert_eq!(r.handle(), first);
        assert_eq!(k.leases.borrow().len(), 1);

        // Past it: refused by the kernel, renewed, served on a new handle.
        k.world.0.borrow_mut().now = 1_100;
        assert_eq!(ping(&r), Ok(()));
        assert_ne!(r.handle(), first);
        assert_eq!(k.leases.borrow().len(), 2);
        assert_eq!(*k.closed.borrow(), vec![first], "the lapsed handle is released");
    }

    /// When the name server lends nothing any more (the row's import was
    /// withdrawn), the failed call stays failed: renewing is not a way round a refusal.
    #[test]
    fn a_lapsed_lease_the_server_will_not_renew_stays_refused() {
        let k = kernel(100);
        let r = azos_names::Renewing::new(&k, NAMES_H, name("term"), 0);
        assert_eq!(ping(&r), Ok(()));
        k.world.0.borrow_mut().now = 1_200;
        k.world.0.borrow_mut().view = b"export term 1 TERMD.ELF\n".to_vec();
        assert_eq!(ping(&r), Err(IdlError::Transport(-1)));
    }

    /// The view is read for every call and never cached: a topology change
    /// is a policy change.
    #[test]
    fn the_view_is_read_per_call() {
        let w = world();
        let l = lp(7, &w);
        let mut c = NamesClient::new(&l);
        let _ = c.lookup(name("term"));
        let _ = c.lookup(name("term"));
        assert_eq!(w.0.borrow().view_reads, 2);
    }
}

#[cfg(test)]
mod codec {
    use azos_names::*;

    #[test]
    fn names_pack_and_unpack() {
        let w = pack_name(b"term").unwrap();
        let mut b = [0u8; NAME_MAX];
        assert_eq!(unpack_name(&w, &mut b), 4);
        assert_eq!(&b[..4], b"term");
        let full = [b'a'; NAME_MAX];
        let w = pack_name(&full).unwrap();
        assert_eq!(unpack_name(&w, &mut b), NAME_MAX);
        // Refused, never truncated.
        assert!(pack_name(b"").is_none());
        assert!(pack_name(&[b'a'; NAME_MAX + 1]).is_none());
        // Distinct names are distinct keys, including a prefix of another.
        assert_ne!(pack_name(b"term").unwrap(), pack_name(b"termx").unwrap());
    }

    #[test]
    fn the_view_parses_line_by_line_and_skips_what_it_does_not_know() {
        assert_eq!(
            parse_line(b"export term 1 TERMD.ELF"),
            Some(Line::Export { name: b"term", index: 1, server: b"TERMD.ELF" })
        );
        assert_eq!(parse_line(b"allow 7 term"), Some(Line::Allow { badge: 7, name: b"term" }));
        for bad in [&b""[..], b"# header", b"export term x TERMD.ELF", b"allow x term", b"allow 7", b"allow 7 term extra",
                    b"export term 1", b"allow 99999999999 term", b"grant 7 term"] {
            assert_eq!(parse_line(bad), None, "{:?}", core::str::from_utf8(bad));
        }
        let v = b"export term 1 TERMD.ELF\nallow 7 term\nallow 70 log\n";
        assert!(allowed(v, 7, b"term"));
        // The badge and the name match whole, not as prefixes.
        assert!(!allowed(v, 70, b"term"));
        assert!(!allowed(v, 7, b"ter"));
        assert!(!allowed(v, 7, b"termx"));
        assert_eq!(export(v, b"term"), Some((1, &b"TERMD.ELF"[..])));
        assert_eq!(export(v, b"ter"), None);
    }
}
