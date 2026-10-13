// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the Decisions object (the question "why was this
//! refused" as a typed interface): the codec and the stubs
//! (`userspace/lib/decisions`), the decision server's decoder
//! (`userspace/services/decisd/src/bin.rs`) and the `why` tool's command
//! line and output (`userspace/services/why/src/cli.rs`), the last two pulled
//! in with `#[path]` so the code under test is the code the ELFs are built
//! from.
//!
//! Everything is driven through the generated client stub over a loopback
//! transport, so the wire form `why` sends is the one under test.

#[allow(dead_code)]
#[path = "../../../../userspace/services/decisd/src/bin.rs"]
pub mod bin;
#[allow(dead_code)]
#[path = "../../../../userspace/services/why/src/cli.rs"]
pub mod cli;

#[cfg(test)]
mod tests {
    use crate::bin::{BinSource, MAX};
    use crate::cli::{self, Cmd, Fail};
    use azos_decision::{Rule, Verdict, PROVENANCE_SIZE};
    use azos_decisions::*;
    use std::cell::RefCell;
    use std::sync::Mutex;

    /// The kernel's statics are the process's: one test at a time that
    /// writes records.
    static GUARD: Mutex<()> = Mutex::new(());

    fn rec(seq: u64, rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) -> ProvenanceRecord {
        let mut p = ProvenanceRecord::new(rule as u8, verdict as u8, subject, n);
        p.seq = seq;
        p.clock_ns = seq * 1_000_000;
        p
    }

    fn bytes(rs: &[ProvenanceRecord]) -> Vec<u8> {
        rs.iter().flat_map(|p| p.to_bytes()).collect()
    }

    /// A full record: every field set, to see each survive the wire.
    fn full() -> ProvenanceRecord {
        ProvenanceRecord {
            rule: Rule::CapDerive as u8,
            verdict: Verdict::Admit as u8,
            subject: 0x0A0B_0C0D,
            seq: 0x1111_2222_3333,
            cap_slot: [1, 2],
            parent_cap: [3, 4],
            topology_row_id: 0x55,
            node_id: 0x66,
            image_hash_prefix: 0x7777_8888_9999_AAAA,
            session_id: 0xBBBB,
            n: [0xC1, 0xC2, 0xC3],
            clock_ns: 0xDDDD_EEEE,
        }
    }

    /// The loopback: the request goes through the wire form to the server's
    /// dispatcher, as the kernel would carry it.
    struct Loop<'a, S: Source>(&'a RefCell<Service<S>>);

    impl<S: Source> Transport for Loop<'_, S> {
        fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
            let req = *msg;
            let _ = DecisionsIdl::dispatch(&mut *self.0.borrow_mut(), &req, msg);
            Ok(())
        }
    }

    fn served(rs: &[ProvenanceRecord]) -> RefCell<Service<BinSource>> {
        let mut s = BinSource::new();
        s.load(&bytes(rs));
        RefCell::new(Service(s))
    }

    // ── the codec ───────────────────────────────────────────────────────

    /// Two parts carry the whole record. **Canary.** Send word 12 of the
    /// record in neither part (shrink `PARTS` worth of words): the record
    /// that comes back differs in `parent_cap`.
    #[test]
    fn two_parts_carry_every_field() {
        let p = full();
        let a = pack_part(&p, 0).unwrap();
        let b = pack_part(&p, 1).unwrap();
        assert_eq!(join_parts(&a, &b), Some(p));
        assert_eq!(pack_part(&p, 2), None);
    }

    /// Parts of two decisions do not join, and a part 0 that says "not held"
    /// joins nothing. **Canary.** Drop the id test in `join_parts`: the
    /// mismatched pair joins, red.
    #[test]
    fn parts_of_two_decisions_do_not_join() {
        let (mut p, mut q) = (full(), full());
        q.seq = p.seq + 1;
        let a = pack_part(&p, 0).unwrap();
        let b = pack_part(&q, 1).unwrap();
        assert_eq!(join_parts(&a, &b), None);
        p.seq = 0;
        assert_eq!(join_parts(&pack_part(&p, 0).unwrap(), &pack_part(&p, 1).unwrap()), None);
    }

    #[test]
    fn the_count_word_keeps_both_halves() {
        assert_eq!(unpack_count(pack_count(6, 123_456_789)), (6, 123_456_789));
        assert_eq!(unpack_count(pack_count(0, 0)), (0, 0));
        // A count wider than a byte cannot spill into the total.
        assert_eq!(unpack_count(pack_count(300, 7)), (300 & 0xff, 7));
    }

    // ── the server and its decoder ──────────────────────────────────────

    fn refusals() -> Vec<ProvenanceRecord> {
        vec![
            rec(3, Rule::DeadlineAdmission, Verdict::Refuse, 7, [500, 1000, 2 << 32]),
            rec(4, Rule::CapDenial, Verdict::Deny, 9, [1, 2, 0]),
            rec(5, Rule::DeadlineAdmission, Verdict::Refuse, 8, [900, 1000, 40 | 3 << 32]),
            rec(9, Rule::MemoryAdmission, Verdict::Refuse, 2, [100, 50, 10]),
        ]
    }

    /// `get` over the wire returns the record that was exported. **Canary.**
    /// Decode the file with the records' halves swapped (`to_bytes` offsets):
    /// the numbers differ, red.
    #[test]
    fn a_client_fetches_a_decision_through_the_wire() {
        let s = served(&refusals());
        let c = DecisionsClient::new(Loop(&s));
        let p = fetch(&c, 5).unwrap().expect("decision 5 is held");
        assert_eq!((p.rule, p.verdict, p.subject, p.n), (Rule::DeadlineAdmission as u8, Verdict::Refuse as u8, 8, [900, 1000, 40 | 3 << 32]));
        assert_eq!(p.clock_ns, 5_000_000);
        assert_eq!(fetch(&c, 6).unwrap(), None, "an id nobody holds");
        assert_eq!(fetch(&c, 0).unwrap(), None);
    }

    /// `query` pages through the matches, six ids a reply. **Canary.** Report
    /// `after` as inclusive in `BinSource::query`: ids repeat across pages.
    #[test]
    fn a_query_pages_through_the_matches() {
        let many: Vec<_> = (1..=20).map(|i| rec(i, Rule::DeadlineAdmission, Verdict::Refuse, 7, [i, 0, 0])).collect();
        let s = served(&many);
        let c = DecisionsClient::new(Loop(&s));
        let mut ids = [0u64; 32];
        let (n, total) = list(&c, &Filter::ANY, &mut ids).unwrap();
        assert_eq!((n, total), (20, 20));
        assert_eq!(&ids[..n], (1..=20).collect::<Vec<u64>>().as_slice());
        // A short buffer ends the paging mid-way.
        let mut few = [0u64; 8];
        assert_eq!(list(&c, &Filter::ANY, &mut few).unwrap().0, 8);
        assert_eq!(few, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn the_filter_reaches_the_server() {
        let s = served(&refusals());
        let c = DecisionsClient::new(Loop(&s));
        let mut ids = [0u64; 8];
        let f = Filter { rule: Some(Rule::DeadlineAdmission as u8), ..Filter::ANY };
        assert_eq!(list(&c, &f, &mut ids).unwrap().0, 2);
        assert_eq!(&ids[..2], &[3, 5]);
        let f = Filter { verdict: Some(Verdict::Deny as u8), ..Filter::ANY };
        assert_eq!(list(&c, &f, &mut ids).unwrap().0, 1);
        assert_eq!(ids[0], 4);
        let f = Filter { subject: Some(8), after: 3, ..Filter::ANY };
        assert_eq!(list(&c, &f, &mut ids).unwrap().0, 1);
        assert_eq!(ids[0], 5);
        let f = Filter { subject: Some(8), after: 5, ..Filter::ANY };
        assert_eq!(list(&c, &f, &mut ids).unwrap().0, 0);
        // The newest id held is the total the server reports.
        assert_eq!(list(&c, &Filter::ANY, &mut ids).unwrap().1, 9);
    }

    /// The decoder takes whole records and nothing else.
    #[test]
    fn the_decoder_keeps_whole_records_and_the_newest() {
        let mut b = bytes(&refusals());
        let mut s = BinSource::new();
        // A partial tail is ignored.
        b.extend_from_slice(&[0xAA; PROVENANCE_SIZE - 1]);
        assert_eq!(s.load(&b), 4);
        assert_eq!(s.total(), 9);
        // A record with no id is not a decision.
        assert_eq!(s.load(&bytes(&[rec(0, Rule::CapDenial, Verdict::Deny, 1, [0; 3])])), 0);
        // More than the table holds: the newest are kept.
        let many: Vec<_> = (1..=MAX as u64 + 5).map(|i| rec(i, Rule::CapDenial, Verdict::Deny, 1, [0; 3])).collect();
        assert_eq!(s.load(&bytes(&many)), MAX);
        assert_eq!(s.lookup(5), None);
        assert!(s.lookup(6).is_some() && s.lookup(MAX as u64 + 5).is_some());
        assert_eq!(s.load(&[]), 0);
        assert_eq!(s.total(), 0);
    }

    /// A slot rewritten between the two parts: the client sees ids that
    /// differ and says "not held" instead of joining halves of two decisions.
    /// **Canary.** Skip the retry's id check in `fetch`: the halves join.
    #[test]
    fn a_rewrite_between_the_parts_is_not_joined() {
        struct Flaky(Vec<ProvenanceRecord>, std::cell::Cell<usize>);
        impl DecisionsCall for Flaky {
            fn query(&self, _: [u64; 2]) -> azos_idl::Result<[u64; REPLY_WORDS]> {
                Ok([0; REPLY_WORDS])
            }
            fn get(&self, _id: u64, part: u32) -> azos_idl::Result<[u64; REPLY_WORDS]> {
                // Part 0 is decision 5; part 1 is always decision 6's.
                let k = self.1.get();
                self.1.set(k + 1);
                let which = if part == 0 { 0 } else { 1 };
                Ok(pack_part(&self.0[which], part).unwrap())
            }
        }
        let c = Flaky(vec![rec(5, Rule::CapDenial, Verdict::Deny, 1, [1, 1, 1]), rec(6, Rule::CapDenial, Verdict::Deny, 2, [2, 2, 2])], Default::default());
        assert_eq!(fetch(&c, 5).unwrap(), None);
        assert_eq!(c.1.get(), 4, "two tries, two parts each, then give up");
    }

    // ── the why tool ────────────────────────────────────────────────────

    fn args(a: &[&str]) -> Vec<Vec<u8>> {
        a.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    fn parse(a: &[&str]) -> Result<Cmd, &'static str> {
        let owned = args(a);
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        cli::parse(&refs)
    }

    #[test]
    fn the_command_line() {
        assert_eq!(parse(&[]), Ok(Cmd::Latest));
        assert_eq!(parse(&["17"]), Ok(Cmd::Chain(17)));
        assert_eq!(parse(&["list"]), Ok(Cmd::List(Filter::ANY)));
        assert_eq!(
            parse(&["list", "-r", "deadline-admission", "-v", "refuse", "-s", "7", "-a", "3"]),
            Ok(Cmd::List(Filter {
                rule: Some(Rule::DeadlineAdmission as u8),
                verdict: Some(Verdict::Refuse as u8),
                subject: Some(7),
                after: 3
            }))
        );
        assert!(parse(&["list", "-r", "no-such-rule"]).is_err());
        assert!(parse(&["list", "-v"]).is_err());
        assert!(parse(&["list", "-x", "1"]).is_err());
        assert!(parse(&["list", "-s", "99999999999"]).is_err());
        assert!(parse(&["nonsense"]).is_err());
        assert!(parse(&["1", "2"]).is_err());
        // Every rule and verdict the kernel names can be asked for by name.
        for (i, r) in azos_decision::RULES.iter().enumerate() {
            assert_eq!(cli::rule_by_name(r.name.as_bytes()), Some(i as u8));
        }
        for (i, v) in azos_decision::VERDICTS.iter().enumerate() {
            assert_eq!(cli::verdict_by_name(v.as_bytes()), Some(i as u8));
        }
    }

    fn run(cmd: Cmd, s: &RefCell<Service<BinSource>>) -> (Result<i32, Fail>, String) {
        let c = DecisionsClient::new(Loop(s));
        let mut out = String::new();
        let r = cli::run(&cmd, &c, &mut out);
        (r, out)
    }

    /// The tool prints the chain of a refusal, numbers by name. **Canary.**
    /// Return the wrong part from `pack_part(.., 1)`: the clock or the
    /// provenance lines go red.
    #[test]
    fn why_prints_the_chain() {
        let s = served(&refusals());
        let (r, out) = run(Cmd::Chain(3), &s);
        assert_eq!(r, Ok(0));
        assert!(out.starts_with("decision 3: deadline-admission refuse\n"), "{out}");
        assert!(out.contains("  subject   tid=7\n"), "{out}");
        assert!(out.contains("  numbers   runtime_us=500 period_us=1000 available_us=0 reason=2(no-room)\n"), "{out}");
        assert!(out.contains("  clock     3000000 ns (0.003000 s)\n"), "{out}");
    }

    #[test]
    fn why_says_so_when_the_decision_is_not_held() {
        let s = served(&refusals());
        let (r, out) = run(Cmd::Chain(77), &s);
        assert_eq!(r, Ok(1));
        assert!(out.contains("decision 77 is not held"), "{out}");
    }

    #[test]
    fn why_lists_the_latest_and_filtered() {
        let many: Vec<_> = (1..=30).map(|i| rec(i, Rule::DeadlineAdmission, Verdict::Refuse, 7, [i, 1, 0])).collect();
        let s = served(&many);
        let (r, out) = run(Cmd::Latest, &s);
        assert_eq!(r, Ok(0));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1 + cli::LATEST, "{out}");
        assert!(lines[0].starts_with("# 12 shown, 30 decisions since boot"), "{out}");
        assert!(lines[1].starts_with("19 deadline-admission refuse"), "{out}");
        assert!(lines[12].starts_with("30 deadline-admission refuse"), "{out}");
        let s = served(&refusals());
        let (_, out) = run(Cmd::List(Filter { verdict: Some(Verdict::Deny as u8), ..Filter::ANY }), &s);
        assert!(out.contains("4 cap-denial deny tid=9") && !out.contains("deadline-admission"), "{out}");
    }

    // ── the kernel's own query behind the interface ─────────────────────

    /// `azos_decision`'s functions as a [`Source`]: what a kernel-hosted
    /// placement of the interface answers from.
    struct Kernel;
    impl Source for Kernel {
        fn total(&self) -> u64 {
            azos_decision::total()
        }
        fn query(&self, f: &Filter, out: &mut [u64]) -> usize {
            azos_decision::query(f, out)
        }
        fn lookup(&self, id: u64) -> Option<ProvenanceRecord> {
            azos_decision::lookup(id)
        }
    }

    /// A refusal the kernel's decision path recorded is explained by `why`
    /// over the interface, with no ring and no file in between.
    /// **Canary.** Stop `durable` storing into the journal: the chain is
    /// "not held", red.
    #[test]
    fn a_recorded_refusal_is_explained_through_the_interface() {
        let _g = GUARD.lock().unwrap();
        let before = azos_decision::total();
        azos_decision::record(Rule::DeadlineAdmission, Verdict::Refuse, 4242, [500, 1000, 2 << 32]);
        let s = RefCell::new(Service(Kernel));
        let c = DecisionsClient::new(Loop(&s));
        let mut out = String::new();
        let f = Filter { rule: Some(Rule::DeadlineAdmission as u8), subject: Some(4242), after: before, ..Filter::ANY };
        let cmd = Cmd::List(f);
        assert_eq!(cli::run(&cmd, &c, &mut out), Ok(0));
        let id = azos_decision::total();
        assert!(out.contains(&format!("{id} deadline-admission refuse tid=4242")), "{out}");
        out.clear();
        assert_eq!(cli::run(&Cmd::Chain(id), &c, &mut out), Ok(0));
        assert!(out.contains("numbers   runtime_us=500 period_us=1000 available_us=0 reason=2(no-room)"), "{out}");
    }
    /// A driver's move is a receipt: it is kept whole (with its topology
    /// row) and `why` explains it, while a move that is only an admission
    /// of another rule is not. **Canary.** Drop `Rule::Placement` from the
    /// `Place` arm of `record_keyed`'s `to_sink`: the lookup is `None`, red.
    #[test]
    fn a_placement_move_is_kept_and_explained() {
        let _g = GUARD.lock().unwrap();
        let before = azos_decision::total();
        // move = reason 1 (fault) << 16 | from 1 (kernel) << 8 | to 2 (ring 3)
        azos_decision::record(Rule::Placement, Verdict::Place, 6, [1 << 16 | 1 << 8 | 2, 0, 0]);
        let id = azos_decision::total();
        assert_eq!(id, before + 1);
        let p = azos_decision::lookup(id).expect("a move is held in the journal");
        assert_eq!((p.rule, p.verdict, p.subject, p.topology_row_id), (Rule::Placement as u8, Verdict::Place as u8, 6, 7));
        let s = RefCell::new(Service(Kernel));
        let c = DecisionsClient::new(Loop(&s));
        let mut out = String::new();
        assert_eq!(cli::run(&Cmd::Chain(id), &c, &mut out), Ok(0));
        assert!(out.contains("placement"), "{out}");
        // A placement `Admit` is not a move and is not kept.
        azos_decision::record(Rule::Placement, Verdict::Admit, 6, [0; 3]);
        assert_eq!(azos_decision::total(), id, "an admit claims no id: nothing stores it");
    }
}
