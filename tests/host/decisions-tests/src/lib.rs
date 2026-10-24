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

    // Receipt-conditioned warrants (`b3.rs`): a child module, so it shares the
    // kernel source, the loopback and the lock.
    mod b3 {
        include!("b3.rs");
    }

    /// **A login is durable whatever the verdict.** With the ring off (this
    /// crate builds `durable` only) an admitted session is held by id in the
    /// journal, like a refused attempt, and another rule's admission is not.
    ///
    /// **Canary.** Take `Rule::Login` out of `to_sink` in
    /// `azos_decision::record_keyed`: the admit is not held, red.
    #[test]
    fn an_admitted_login_is_held_like_a_refusal() {
        use azos_decision::{lookup, query, record, total, Filter};
        let _g = GUARD.lock().unwrap();
        let t0 = total();
        record(Rule::Login, Verdict::Admit, 3, [4, 0, 0]);
        record(Rule::Login, Verdict::Refuse, 0, [4, 1, 1]);
        record(Rule::DeadlineAdmission, Verdict::Admit, 3, [1, 2, 3]);
        let mut ids = [0u64; 8];
        let n = query(&Filter { after: t0, ..Filter::ANY }, &mut ids);
        assert_eq!(n, 2, "the two login attempts, and not the deadline admission");
        let admit = lookup(ids[0]).expect("the admit is held");
        assert_eq!((admit.rule, admit.verdict, admit.subject, admit.n), (Rule::Login as u8, Verdict::Admit as u8, 3, [4, 0, 0]));
        assert_eq!(lookup(ids[1]).map(|p| p.verdict), Some(Verdict::Refuse as u8));
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
    /// A record is stamped on TAI (owner decision 16-10): the timebase's
    /// nanoseconds plus the offset the vDSO publishes. Before the offset is
    /// installed the stamp is time since boot. **Canary.** Stamp with
    /// `ticks_to_ns` again (no offset): the second row goes red.
    #[test]
    fn a_record_is_stamped_on_tai() {
        const TAI_OFFSET_NS: u64 = 1_700_000_037_000_000_000;
        let _g = GUARD.lock().unwrap();
        // 1 kHz timebase, "now" = 5000 ticks = 5 s since boot.
        azos_decision::set_clock(|| 5_000, 1_000);
        assert_eq!(azos_decision::ticks_to_tai_ns(2_000), 2_000_000_000, "no offset yet: since boot");
        azos_decision::set_tai_offset(|| TAI_OFFSET_NS);
        assert_eq!(azos_decision::ticks_to_tai_ns(2_000), 2_000_000_000 + TAI_OFFSET_NS);
        assert_eq!(azos_decision::ticks_to_tai_ns(0), 0, "0 stays \"no clock when written\"");
        azos_decision::record(Rule::DeadlineAdmission, Verdict::Refuse, 5151, [1, 2, 3]);
        let p = azos_decision::lookup(azos_decision::total()).expect("a refusal is kept in the journal");
        assert_eq!(p.clock_ns, 5_000_000_000 + TAI_OFFSET_NS);
    }

    /// A package refusal recorded with its origin keeps the package's id
    /// prefix and its first row in the journal (the receipt `why` reads).
    /// **Canary.** Leave `durable` building the record from the numbers alone
    /// (the old sink): both fields read 0, red.
    #[test]
    fn a_package_refusal_keeps_its_image_and_row() {
        let _g = GUARD.lock().unwrap();
        let origin = azos_decision::Origin { topology_row_id: 12, image_hash_prefix: 0x1122_3344_5566_7788 };
        let id = azos_decision::record_with(Rule::PackageInstall, Verdict::Refuse, 0, [0, 2, 3], origin);
        assert_ne!(id, 0, "a refusal is a receipt");
        let p = azos_decision::lookup(id).expect("the refusal is in the journal");
        assert_eq!((p.rule, p.topology_row_id, p.image_hash_prefix, p.n), (Rule::PackageInstall as u8, 12, 0x1122_3344_5566_7788, [0, 2, 3]));
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

    /// Every rule has a stable number and a name, and the two map both ways:
    /// the number indexes `RULES`, the name finds the number back (the
    /// `why -r` flag). The numbers are written down here, so renumbering a
    /// rule goes red. **Canary.** Swap two variants' numbers in the enum, or
    /// two entries of `RULES`: the row for either goes red.
    #[test]
    fn every_rule_round_trips_number_and_name() {
        let all: &[(Rule, u8, &str)] = &[
            (Rule::DeadlineAdmission, 0, "deadline-admission"),
            (Rule::RtBandCap, 1, "rt-band-cap"),
            (Rule::MemoryAdmission, 2, "memory-admission"),
            (Rule::WakePlacement, 3, "wake-placement"),
            (Rule::CapDenial, 4, "cap-denial"),
            (Rule::DeadlineExpired, 5, "deadline-expired"),
            (Rule::SplitLock, 6, "split-lock"),
            (Rule::CapDerive, 7, "cap-derive"),
            (Rule::CapRevoke, 8, "cap-revoke"),
            (Rule::Neverallow, 9, "neverallow"),
            (Rule::DeviceAdmission, 10, "device-admission"),
            (Rule::IrqBudget, 11, "irq-budget"),
            (Rule::Placement, 12, "placement"),
            (Rule::PackageInstall, 13, "package-install"),
            (Rule::WaitCycle, 14, "wait-cycle"),
            (Rule::EffectDeadline, 15, "effect-deadline"),
            (Rule::SafeState, 16, "safe-state"),
            (Rule::Compensation, 17, "compensation"),
            (Rule::ReceiptCaveat, 18, "receipt-caveat"),
            (Rule::Declassify, 19, "declassify"),
            (Rule::ShadowRefusal, 20, "shadow-refusal"),
            (Rule::SubtreePolicy, 21, "subtree-policy"),
            (Rule::RemoteRevoke, 22, "remote-revoke"),
            (Rule::Compress, 23, "compress"),
            (Rule::SwapOut, 24, "swap-out"),
            (Rule::KmemCharge, 25, "kmem-charge"),
            (Rule::ClockStep, 26, "clock-step"),
            (Rule::PacketRefused, 27, "packet-refused"),
            (Rule::GuestEgress, 28, "guest-egress"),
            (Rule::Livepatch, 29, "livepatch"),
            (Rule::CpuHotplug, 30, "cpu-hotplug"),
            (Rule::Suspend, 31, "suspend"),
            (Rule::BatteryDegrade, 32, "battery-degrade"),
            (Rule::ProvenanceMeet, 33, "provenance-meet"),
            (Rule::EffectRecord, 34, "effect-record"),
            (Rule::MeasuredBoot, 35, "measured-boot"),
            (Rule::HardeningFallback, 36, "hardening-fallback"),
            (Rule::Pledge, 37, "pledge"),
            (Rule::AccelAdmission, 38, "accel-admission"),
            (Rule::TsnAdmission, 39, "tsn-admission"),
            (Rule::EnvelopeConfig, 40, "envelope-config"),
            (Rule::EnvelopeOta, 41, "envelope-ota"),
            (Rule::EnvelopeEgress, 42, "envelope-egress"),
            (Rule::EnvelopeDelete, 43, "envelope-delete"),
            (Rule::EnvelopeRtTime, 44, "envelope-rt-time"),
            (Rule::Freeze, 45, "freeze"),
            (Rule::ThreadControl, 46, "thread-control"),
            (Rule::Login, 47, "login"),
            (Rule::KeyUse, 48, "key-use"),
            (Rule::MemPressure, 49, "mem-pressure"),
            (Rule::Purge, 50, "purge"),
            (Rule::Wipe, 51, "wipe"),
            (Rule::MissionEnergy, 52, "mission-energy"),
            (Rule::DeferredActivity, 53, "deferred-activity"),
            (Rule::TimeProtection, 54, "time-protection"),
            (Rule::Attest, 55, "attest"),
            (Rule::BootChain, 56, "boot-chain"),
            (Rule::Ras, 57, "ras"),
            (Rule::Fieldbus, 58, "fieldbus"),
            (Rule::AudioCapture, 59, "audio-capture"),
            (Rule::Focus, 60, "focus"),
            (Rule::UsbAuthorize, 61, "usb-authorize"),
            (Rule::BlockTimeout, 62, "block-timeout"),
            (Rule::ClockSet, 63, "clock-set"),
            (Rule::EstopRelease, 64, "estop-release"),
            (Rule::Thermal, 65, "thermal"),
            (Rule::Durability, 66, "durability"),
            (Rule::NetTimeout, 67, "net-timeout"),
            (Rule::UsbHostFault, 68, "usb-host-fault"),
            (Rule::CallAdmission, 69, "call-admission"),
            (Rule::OppApply, 70, "opp-apply"),
            (Rule::PowerAssertion, 71, "power-assertion"),
            (Rule::NicQueue, 72, "nic-queue"),
            (Rule::Clocksource, 73, "clocksource"),
            (Rule::IoportReserved, 74, "ioport-reserved"),
        ];
        assert_eq!(azos_decision::RULES.len(), all.len(), "a rule without a name, or a name without a rule");
        for &(rule, num, name) in all {
            assert_eq!(rule as u8, num, "{name}: the number is part of the record format");
            assert_eq!(azos_decision::RULES[num as usize].name, name);
            assert_eq!(cli::rule_by_name(name.as_bytes()), Some(num));
            // The chain `why` prints names the rule from the number alone.
            let mut out = String::new();
            let mut p = ProvenanceRecord::new(num, Verdict::Refuse as u8, 1, [0; 3]);
            p.seq = 1;
            p.write_chain(&mut out).unwrap();
            assert!(out.contains(&format!("rule      {name}\n")), "{out}");
        }
        let mut names: Vec<&str> = azos_decision::RULES.iter().map(|r| r.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len(), "two rules share a name");
        assert_eq!(cli::rule_by_name(b"no-such-rule"), None);
        assert!(azos_decision::RULES.get(all.len()).is_none());
    }
    // ── the kernel's view of the records ────────────────────────────────

    /// The admin region's record slots as the kernel fills them
    /// (`kernel/src/boot/inspect_views.rs`: `azos_decision::view_slot`, the
    /// newest id per slot), for the records `rs` in order; `durable` says
    /// which went down the durable path.
    fn view(rs: &[(ProvenanceRecord, bool)], split: bool) -> Vec<ProvenanceRecord> {
        let mut slots: Vec<Option<ProvenanceRecord>> = vec![None; MAX];
        let mut nth = 0u64;
        for &(p, durable) in rs {
            let n = durable.then(|| {
                nth += 1;
                nth - 1
            });
            let k = azos_decision::view_slot(MAX, split, p.seq, n);
            if slots[k].map_or(true, |q| q.seq < p.seq) {
                slots[k] = Some(p);
            }
        }
        slots.into_iter().flatten().collect()
    }

    /// **A login stays in the view however many wake placements follow it.**
    /// The ring (DECISION_RECORDS_DEV) records a placement on every
    /// migrating wake; keyed by id alone, 24 of them push a login out of the
    /// admin region's records, and `why list -r login` shows none though the
    /// journal still holds it. With both kinds built, the durable records
    /// keep half the slots, so the logins (always durable) and the refusals
    /// are listed while the newest placements share the rest.
    ///
    /// **Canary.** The view not split (`split` false, every record by id):
    /// no login is listed.
    #[test]
    fn a_login_outlasts_a_flood_of_wake_placements_in_the_view() {
        let mut rs = Vec::new();
        let mut seq = 0;
        let mut push = |rs: &mut Vec<_>, rule, verdict, n, durable| {
            seq += 1;
            rs.push((rec(seq, rule, verdict, 0, n), durable));
        };
        for _ in 0..40 {
            push(&mut rs, Rule::WakePlacement, Verdict::Place, [1, 0, 7], false);
        }
        push(&mut rs, Rule::Login, Verdict::Refuse, [4, 1, 1], true);
        push(&mut rs, Rule::Login, Verdict::Admit, [4, 1, 0], true);
        for _ in 0..200 {
            push(&mut rs, Rule::WakePlacement, Verdict::Place, [2, 1, 7], false);
        }
        let logins = |split| {
            let s = served(&view(&rs, split));
            let c = DecisionsClient::new(Loop(&s));
            let mut ids = [0u64; MAX];
            let f = Filter { rule: Some(Rule::Login as u8), ..Filter::ANY };
            let (n, total) = list(&c, &f, &mut ids).unwrap();
            (ids[..n].to_vec(), total)
        };
        let (ids, total) = logins(true);
        assert_eq!(ids, vec![41, 42], "both logins listed, oldest first");
        assert_eq!(total, 242, "the newest placement is in the view");
        assert_eq!(view(&rs, true).len(), MAX / 2 + 2, "the placements fill their half, the logins two of theirs");
        assert!(logins(false).0.is_empty(), "keyed by id alone, the placements pushed the logins out");
    }
}

/// The text the console-login gate rows (`login: console`, tools/ci_check.sh)
/// match in `why list -r login`: the line of an admitted session and of a
/// refused attempt, as `ProvenanceRecord::write_line` renders them.
///
/// **Canary.** Rename a field of the `login` rule in `crates/core/decision`
/// (`attempt` to `tries`): the gate rows' markers stop matching, and this
/// test is red first.
#[cfg(test)]
mod login_lines {
    use azos_decision::{ProvenanceRecord, Rule, Verdict};

    fn line(verdict: Verdict, session: u32, n: [u64; 3]) -> String {
        let mut r = ProvenanceRecord::new(Rule::Login as u8, verdict as u8, session, n);
        r.seq = 7;
        let mut s = String::new();
        r.write_line(&mut s).unwrap();
        s
    }

    #[test]
    fn an_admitted_session_and_a_refused_attempt_read_as_the_gate_rows_expect() {
        // method 4 (local console), no failures before, reason 0 (admitted), the user's root as the session.
        assert!(line(Verdict::Admit, 1, [4, 0, 0]).contains("login admit session=1 method=4 attempt=0 reason=0"));
        // One wrong secret: a refusal of no session (0), reason 1.
        assert!(line(Verdict::Refuse, 0, [4, 1, 1]).contains("login refuse session=0 method=4 attempt=1 reason=1"));
        // Locked out and no root to verify with are the other two reasons.
        assert!(line(Verdict::Refuse, 0, [4, 5, 2]).contains("reason=2"));
        assert!(line(Verdict::Refuse, 0, [4, 0, 4]).contains("reason=4"));
        assert!(line(Verdict::Refuse, 0, [4, 0, 5]).contains("reason=5"));
    }

}
