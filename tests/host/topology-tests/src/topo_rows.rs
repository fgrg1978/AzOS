// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TOPO-ROWS-A and TOPO-ROWS-B (CAPS.TOML format 7): every row and field the
//! later fronts consume, parsed, verified, emitted and signed before any of
//! them exists. Each row has a valid case, the malformed cases it must refuse,
//! the format-6 refusal, a duplicate where the row has a name, and the
//! parse -> emit -> parse round trip (`first_difference`), so an emitter or
//! comparison that forgets a field turns a test red.
//!
//! The last test signs a topology that declares one of everything, flips one
//! byte in a row each front will read, and expects the loader to refuse it:
//! the rows are inside the signature, as the old ones were.

use azos_topology::emit::{emit_caps, emit_sched, first_difference, EMIT_FORMAT};
use azos_topology::signed::{load_signed, DeviceContext, SignedFile, SignedFiles, SignedRefusal};
use azos_topology::{
    parse_caps, parse_sched, AdmissionError, Binding, DeadlineRefusal, Envelope, ParseError, PrincipalKind, RowKind, Topology,
    VerifyError,
};
use ed25519_dalek::{Signer, SigningKey};

/// A class a row can name, and nothing else.
pub(crate) const SCHED: &str = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";

/// A string that lives as long as the topologies parsed from it.
pub(crate) fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

pub(crate) fn parse_with<'a>(sched: &'a str, caps: &'a str) -> (Box<Topology<'a>>, Result<(), ParseError>) {
    let mut t = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut t).unwrap_or_else(|e| panic!("SCHED.TOM: {e:?}\n{sched}"));
    let r = parse_caps(caps.as_bytes(), &mut t);
    (t, r)
}

fn parse(caps: &str) -> (Box<Topology<'_>>, Result<(), ParseError>) {
    parse_with(SCHED, caps)
}

/// Parse a format-7 body that must be accepted.
fn ok(body: &str) -> Box<Topology<'static>> {
    let caps: &'static str = Box::leak(format!("format = 7\n{body}").into_boxed_str());
    let (t, r) = parse(caps);
    assert_eq!(r, Ok(()), "{body}");
    t
}

/// The error a format-7 body must be refused with.
fn refused(body: &str) -> ParseError {
    let caps = format!("format = 7\n{body}");
    let (_, r) = parse(&caps);
    r.expect_err(body)
}

/// What a format-6 file that carries `body` is refused with.
fn refused_in_6(body: &str) -> ParseError {
    let caps = format!("format = 6\n{body}");
    let (_, r) = parse(&caps);
    r.expect_err(body)
}

/// Emit `t` and read it back: the first field that differs, if any.
pub(crate) fn round_trip(t: &Topology<'_>) -> Option<&'static str> {
    let mut sched = String::new();
    emit_sched(t, &mut sched).expect("emit SCHED.TOM");
    let mut caps = String::new();
    emit_caps(t, &Binding::default(), &mut caps).expect("emit CAPS.TOM");
    assert!(caps.contains(&format!("format = {EMIT_FORMAT}")), "{caps}");
    let (back, r) = parse_with(&sched, &caps);
    assert_eq!(r, Ok(()), "the emitted file parses back:\n{caps}");
    first_difference(t, &back)
}

#[test]
fn the_caps_format_is_eight() {
    assert_eq!(EMIT_FORMAT, 8);
    assert_eq!(azos_topology::parser::CAPS_FORMAT_MAX, 8);
    let (_, r) = parse("format = 9\n");
    assert_eq!(r, Err(ParseError::UnsupportedFormat));
}

// ── device: safe_state, commit_ns, compensate ──────────────────────────────

const DEVICE: &str = "[device.motor]\nmatch = \"dt:azos,motor\"\nsafe_state = \"brake\"\ncommit_ns = 2500000\ncompensate = \"release\"\n";

/// **Canary.** Drop a field from `handle_device_kv`: the assertion on it goes
/// red.
#[test]
fn a_device_row_declares_its_failure_contract() {
    let t = ok(DEVICE);
    let d = &t.devices()[0];
    assert_eq!(
        (d.safe_state.as_str(), d.commit_ns, d.compensate.as_str()),
        ("brake", 2_500_000, "release")
    );
    // Nothing declared, nothing assumed.
    let t = ok("[device.plain]\nmatch = \"virtio:2\"\n");
    let d = &t.devices()[0];
    assert!(d.safe_state.is_empty() && d.compensate.is_empty() && d.commit_ns == 0);
    // The largest commit time is accepted, not truncated.
    let t = ok("[device.m]\nmatch = \"virtio:2\"\ncommit_ns = 18446744073709551615\n");
    assert_eq!(t.devices()[0].commit_ns, u64::MAX);
}

#[test]
fn a_device_failure_contract_is_refused_below_format_7() {
    for key in ["safe_state = \"off\"", "commit_ns = 5", "compensate = \"undo\""] {
        assert_eq!(
            refused_in_6(&format!("[device.m]\nmatch = \"virtio:2\"\n{key}\n")),
            ParseError::FieldNeedsFormat,
            "{key}"
        );
    }
}

#[test]
fn a_malformed_device_failure_contract_is_refused() {
    let m = "[device.m]\nmatch = \"virtio:2\"\n";
    for (line, want) in [
        ("safe_state = \"\"", ParseError::BadValue),
        ("compensate = \"\"", ParseError::BadValue),
        ("safe_state = off", ParseError::BadValue),
        ("safe_state = \"off\" extra", ParseError::BadValue),
        ("safe_state = \"a b\"", ParseError::Admission(AdmissionError::BadDevice)),
        ("safe_state = \"a.b\"", ParseError::Admission(AdmissionError::BadDevice)),
        ("compensate = \"0123456789012345678901234\"", ParseError::Admission(AdmissionError::BadDevice)),
        ("commit_ns = 18446744073709551616", ParseError::BadValue),
        ("commit_ns = \"5\"", ParseError::BadValue),
        ("commit_ns = 5 5", ParseError::BadValue),
        ("commit_ns = -5", ParseError::BadValue),
    ] {
        assert_eq!(refused(&format!("{m}{line}\n")), want, "{line}");
    }
    // A device the bus never binds is never commanded.
    for line in ["safe_state = \"off\"", "commit_ns = 7", "compensate = \"undo\""] {
        assert_eq!(
            refused(&format!("[device.m]\nmatch = \"virtio:2\"\nadmit = false\n{line}\n")),
            ParseError::Admission(AdmissionError::BadDevice),
            "{line}"
        );
    }
}

#[test]
fn a_device_failure_contract_round_trips() {
    let t = ok(DEVICE);
    assert_eq!(round_trip(&t), None);
    let other = ok(&DEVICE.replace("2500000", "2500001"));
    assert_eq!(first_difference(&t, &other), Some("device failure contract"));
    let other = ok(&DEVICE.replace("brake", "coast"));
    assert_eq!(first_difference(&t, &other), Some("device failure contract"));
    let other = ok(&DEVICE.replace("release", "unwind"));
    assert_eq!(first_difference(&t, &other), Some("device failure contract"));
}

// ── class: envelope, principal ─────────────────────────────────────────────

fn sched_class(extra: &str) -> String {
    format!("[class.agents]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n{extra}")
}

#[test]
fn a_class_declares_its_envelope_and_principal() {
    let sched = sched_class("envelope = \"slow\"\nprincipal = \"agent\"\n");
    let (t, _) = parse_with(&sched, "format = 7\n");
    let c = &t.classes()[0];
    assert_eq!((c.envelope, c.principal), (Envelope::Slow, PrincipalKind::Agent));
    // The defaults are the unrestricted platform.
    let (t, _) = parse_with(leak(sched_class("")), "format = 7\n");
    let c = &t.classes()[0];
    assert_eq!((c.envelope, c.principal), (Envelope::Full, PrincipalKind::System));
    for (word, want) in [
        ("full", Envelope::Full),
        ("cautious", Envelope::Cautious),
        ("slow", Envelope::Slow),
        ("contained", Envelope::Contained),
    ] {
        assert_eq!(Envelope::from_bytes(word.as_bytes()), Some(want));
        assert_eq!(want.as_str(), word);
    }
    for (word, want) in [
        ("system", PrincipalKind::System),
        ("service", PrincipalKind::Service),
        ("user", PrincipalKind::User),
        ("agent", PrincipalKind::Agent),
    ] {
        assert_eq!(PrincipalKind::from_bytes(word.as_bytes()), Some(want));
        assert_eq!(want.as_str(), word);
    }
}

/// The meet is the more restrictive envelope, whatever the order.
#[test]
fn the_meet_of_envelopes_is_the_most_restrictive() {
    let all = [Envelope::Full, Envelope::Cautious, Envelope::Slow, Envelope::Contained];
    for a in all {
        assert_eq!(a.meet(Envelope::Full), a);
        assert_eq!(Envelope::Contained.meet(a), Envelope::Contained);
        for b in all {
            assert_eq!(a.meet(b), b.meet(a));
            assert_eq!(a.meet(b), if a >= b { a } else { b });
        }
    }
}

#[test]
fn a_malformed_class_envelope_or_principal_is_refused() {
    for (extra, want) in [
        ("envelope = \"tight\"\n", ParseError::UnknownEnumValue),
        ("envelope = \"Slow\"\n", ParseError::UnknownEnumValue),
        ("envelope = slow\n", ParseError::BadValue),
        ("envelope = \"slow\" x\n", ParseError::BadValue),
        ("envelope = 2\n", ParseError::BadValue),
        ("principal = \"root\"\n", ParseError::UnknownEnumValue),
        ("principal = \"\"\n", ParseError::UnknownEnumValue),
        ("principal = agent\n", ParseError::BadValue),
    ] {
        let sched = sched_class(extra);
        let mut t = Box::new(Topology::empty());
        assert_eq!(parse_sched(sched.as_bytes(), &mut t), Err(want), "{extra}");
    }
}

#[test]
fn a_class_envelope_and_principal_round_trip() {
    let sched = sched_class("envelope = \"contained\"\nprincipal = \"service\"\n");
    let (t, _) = parse_with(&sched, "format = 7\n");
    assert_eq!(round_trip(&t), None);
    let (u, _) = parse_with(leak(sched_class("envelope = \"slow\"\nprincipal = \"service\"\n")), "format = 7\n");
    assert_eq!(first_difference(&t, &u), Some("class envelope"));
    let (u, _) = parse_with(leak(sched_class("envelope = \"contained\"\nprincipal = \"agent\"\n")), "format = 7\n");
    assert_eq!(first_difference(&t, &u), Some("class principal"));
}

// ── task: shadow, isolated, kmem_kib ───────────────────────────────────────

#[test]
fn a_task_row_declares_shadow_and_kmem_kib() {
    let t = ok("[task.A.ELF]\nshadow = true\nkmem_kib = 512\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    let (a, b) = (&t.tasks()[0], &t.tasks()[1]);
    assert_eq!((a.shadow, a.kmem_kib), (true, 512));
    assert_eq!((b.shadow, b.isolated, b.kmem_kib), (false, false, 0), "the next row inherits nothing");
    assert_eq!(round_trip(&t), None);
    let u = ok("[task.A.ELF]\nshadow = true\nkmem_kib = 513\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    assert_eq!(first_difference(&t, &u), Some("task kmem_kib"));
    let u = ok("[task.A.ELF]\nkmem_kib = 512\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    assert_eq!(first_difference(&t, &u), Some("task shadow"));
    // The last row of the file is committed too.
    let t = ok("[task.A.ELF]\ncaps = []\n[task.B.ELF]\nshadow = true\nkmem_kib = 4294967295\ncaps = []\n");
    assert_eq!((t.tasks()[1].shadow, t.tasks()[1].kmem_kib), (true, u32::MAX));
}

#[test]
fn task_shadow_isolated_and_kmem_kib_are_refused_below_format_7() {
    for line in ["shadow = true", "isolated = true", "kmem_kib = 4"] {
        assert_eq!(
            refused_in_6(&format!("[task.A.ELF]\n{line}\ncaps = []\n")),
            ParseError::FieldNeedsFormat,
            "{line}"
        );
    }
}

#[test]
fn a_malformed_task_shadow_isolated_or_kmem_kib_is_refused() {
    for line in [
        "shadow = 1",
        "shadow = trueish",
        "shadow = \"true\"",
        "isolated = maybe",
        "isolated = false false",
        "kmem_kib = 4294967296",
        "kmem_kib = -1",
        "kmem_kib = \"4\"",
        "kmem_kib = 4 4",
        "kmem_kib =",
    ] {
        assert_eq!(refused(&format!("[task.A.ELF]\n{line}\ncaps = []\n")), ParseError::BadValue, "{line}");
    }
}

/// `[sched]` for the isolation tests: CPUs 2 and 3 are isolated; `hard` is a
/// class with admission control so a row can declare a profile in it.
const ISO_SCHED: &str = "[sched]\nisolcpus = 12\n\
[class.hard]\ncpu_budget_min_pct = 20\ncpu_budget_max_pct = 100\npolicy = \"edf\"\npriority_range = [0, 7]\nadmission_control = true\n\
[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";

fn iso_row(name: &str, extra: &str) -> String {
    format!(
        "[task.{name}]\nclass = \"hard\"\npriority = 4\nperiod_us = 10000\nruntime_us = 1000\n\
mem = \"locked\"\nmem_pages = 16\nisolated = true\n{extra}caps = []\n"
    )
}

fn iso_admit(rows: &str) -> Result<(), AdmissionError> {
    let caps = format!("format = 7\n{rows}");
    let (t, r) = parse_with(ISO_SCHED, &caps);
    assert_eq!(r, Ok(()), "{rows}");
    t.admission_check()
}

#[test]
fn an_isolated_row_owns_one_cpu_of_isolcpus() {
    assert_eq!(iso_admit(&iso_row("rt1", "cpu_mask = 4\n")), Ok(()));
    assert_eq!(iso_admit(&format!("{}{}", iso_row("rt1", "cpu_mask = 4\n"), iso_row("rt2", "cpu_mask = 8\n"))), Ok(()));
    let (t, _) = parse_with(ISO_SCHED, leak(format!("format = 7\n{}", iso_row("rt1", "cpu_mask = 4\n"))));
    assert_eq!(t.sched_config().isolcpus, 12);
    assert!(t.tasks()[0].isolated);
    assert_eq!(round_trip(&t), None);
}

/// **Canary.** Skip `isolation_admission` in `admission_check`: every case
/// goes red.
#[test]
fn an_isolated_row_that_cannot_have_its_cpu_is_refused() {
    let bad = Err(AdmissionError::BadRow(RowKind::Task));
    // Not in isolcpus (CPU 0, CPU 4).
    assert_eq!(iso_admit(&iso_row("rt1", "cpu_mask = 1\n")), bad);
    assert_eq!(iso_admit(&iso_row("rt1", "cpu_mask = 16\n")), bad);
    // More than one CPU.
    assert_eq!(iso_admit(&iso_row("rt1", "cpu_mask = 12\n")), bad);
    // Two rows on one CPU.
    assert_eq!(iso_admit(&format!("{}{}", iso_row("rt1", "cpu_mask = 4\n"), iso_row("rt2", "cpu_mask = 4\n"))), bad);
    // Two instances cannot share one CPU.
    assert_eq!(iso_admit(&iso_row("rt1", "cpu_mask = 4\ninstances = 2\n")), bad);
    // A class without admission control is never placed, so never isolated.
    assert_eq!(
        iso_admit(&iso_row("rt1", "cpu_mask = 4\n").replace("class = \"hard\"", "class = \"best_effort\"")),
        bad
    );
    // A row with no real-time profile.
    assert_eq!(
        iso_admit("[task.be]\nisolated = true\ncaps = []\n"),
        bad
    );
    // A row that is not isolated may not run on an isolated CPU: a second
    // real-time task, or a profile whose mask merely covers one.
    let plain = |name: &str, mask: u32| {
        iso_row(name, &format!("cpu_mask = {mask}\n")).replace("isolated = true\n", "")
    };
    assert_eq!(iso_admit(&format!("{}{}", iso_row("rt1", "cpu_mask = 4\n"), plain("rt2", 4))), bad);
    assert_eq!(iso_admit(&plain("rt2", 8)), bad);
    assert_eq!(iso_admit(&plain("rt2", 12)), bad);
    assert_eq!(iso_admit(&plain("rt2", 7)), bad);
    // Off the isolated CPUs it is fine.
    assert_eq!(iso_admit(&format!("{}{}", iso_row("rt1", "cpu_mask = 4\n"), plain("rt2", 3))), Ok(()));
    // No isolcpus at all.
    let caps = format!("format = 7\n{}", iso_row("rt1", "cpu_mask = 4\n"));
    let sched = ISO_SCHED.replace("isolcpus = 12\n", "");
    let (t, r) = parse_with(&sched, &caps);
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), bad);
}

/// An isolated row that names no CPU is REFUSED, not placed: the topology
/// never picks the CPU of an isolated row (owner decision 16-10; the
/// placement 98bb5070 added is gone). The refusal names the row, at install
/// time and at boot admission alike, and a row with a `cpu_mask` of its own is
/// placed on exactly that CPU, whatever its position. **Canary**: drop the
/// `m == 0` refusal in `isolation_admission`: the row is admitted with the
/// mask `!isolcpus` or none, and every `refused` below goes red.
#[test]
fn an_isolated_row_with_no_cpu_mask_is_refused_naming_its_row() {
    let refused = |task| Err(AdmissionError::Deadline(DeadlineRefusal::IsolatedWithoutCpu { task }));
    // The row alone, with a free isolated CPU available: still refused.
    assert_eq!(iso_admit(&iso_row("rt1", "")), refused(0));
    // The second row is the one that names no CPU (the first has its own).
    let rows = format!("{}{}", iso_row("a", "cpu_mask = 4\n"), iso_row("b", ""));
    assert_eq!(iso_admit(&rows), refused(1));
    // Each stage that admits a topology refuses it: the install-time check and
    // the boot admission with the board's CPU count.
    let (t, r) = parse_with(ISO_SCHED, leak(format!("format = 7\n{}", iso_row("rt1", ""))));
    assert_eq!(r, Ok(()), "the parser takes the row; admission refuses it");
    assert_eq!(t.deadline_admission(4).err(), refused(0).err());
    assert_eq!(t.deadline_admission(2).err(), refused(0).err(), "whatever the CPU count");
    // A row that is wrong in another way keeps its own refusal: no profile.
    assert_eq!(iso_admit("[task.be]\nisolated = true\ncaps = []\n"), Err(AdmissionError::BadRow(RowKind::Task)));
    // With a mask the row is admitted and placed on that CPU, however the
    // rows are ordered.
    let rows = format!("{}{}", iso_row("a", "cpu_mask = 8\n"), iso_row("b", "cpu_mask = 4\n"));
    let (t, r) = parse_with(ISO_SCHED, leak(format!("format = 7\n{rows}")));
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Ok(()));
    let rep = t.deadline_admission(4).unwrap();
    assert_eq!((rep.cpu_of(0), rep.cpu_of(1)), (Some(3), Some(2)));
    // Round trip: the mask is emitted and read back.
    assert_eq!(round_trip(&t), None);
}

/// The CPUs of `isolcpus` are for isolated rows alone: a real-time row that
/// names no CPU is placed off them. **Canary**: drop the `!iso` mask in
/// `deadline_admission`: with CPUs 0 and 1 isolated the row lands on CPU 0.
#[test]
fn a_row_that_is_not_isolated_is_never_placed_on_an_isolated_cpu() {
    let sched = ISO_SCHED.replace("isolcpus = 12", "isolcpus = 3");
    let plain = iso_row("rt1", "").replace("isolated = true\n", "");
    let (t, r) = parse_with(&sched, leak(format!("format = 7\n{plain}")));
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Ok(()));
    assert_eq!(t.deadline_admission(4).unwrap().cpu_of(0), Some(2));
    // Two CPUs, both isolated: nothing is left for it (the sched row itself
    // is refused first).
    assert_eq!(t.deadline_admission(2).err(), Some(AdmissionError::BadRow(RowKind::Sched)));
}

#[test]
fn isolcpus_must_leave_a_cpu_for_everything_else() {
    let (mut t, _) = parse_with(ISO_SCHED, "format = 7\n");
    assert!(t.deadline_admission(4).is_ok(), "2 of 4 CPUs isolated");
    // Every CPU of a 4-CPU machine is isolated.
    let sched = ISO_SCHED.replace("isolcpus = 12", "isolcpus = 15");
    let (u, _) = parse_with(&sched, "format = 7\n");
    assert_eq!(u.deadline_admission(4).err(), Some(AdmissionError::BadRow(RowKind::Sched)));
    assert!(u.deadline_admission(8).is_ok(), "but not a machine with 8");
    // And a mask that names all 32 is refused at topology admission, before
    // the CPU count is known.
    let sched = ISO_SCHED.replace("isolcpus = 12", "isolcpus = 4294967295");
    let (u, _) = parse_with(&sched, "format = 7\n");
    assert_eq!(u.admission_check(), Err(AdmissionError::BadRow(RowKind::Sched)));
    t.set_sched_config(azos_topology::SchedConfig::DEFAULT);
    assert_eq!(t.sched_config().isolcpus, 0);
}

#[test]
fn a_malformed_isolcpus_is_refused() {
    for line in ["isolcpus = 4294967296", "isolcpus = -1", "isolcpus = \"4\"", "isolcpus = 4 4", "isolcpus ="] {
        let sched = format!("[sched]\n{line}\n");
        let mut t = Box::new(Topology::empty());
        assert!(parse_sched(sched.as_bytes(), &mut t).is_err(), "{line}");
    }
    // A mask that fits is taken as it is.
    let mut t = Box::new(Topology::empty());
    parse_sched(b"[sched]\nisolcpus = 4294967295\n", &mut t).unwrap();
    assert_eq!(t.sched_config().isolcpus, u32::MAX);
}

#[test]
fn isolcpus_round_trips() {
    let (t, _) = parse_with(ISO_SCHED, "format = 7\n");
    assert_eq!(round_trip(&t), None);
    let (u, _) = parse_with(leak(ISO_SCHED.replace("isolcpus = 12", "isolcpus = 8")), "format = 7\n");
    assert_eq!(first_difference(&t, &u), Some("sched isolcpus"));
}

// ── peer: noise_pk, measurement ────────────────────────────────────────────

const PK1: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const PK2: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const PK3: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const MEAS: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn peer(extra: &str) -> String {
    format!("[peer.fleet]\nnodes = [2, 3]\n{extra}")
}

#[test]
fn a_peer_class_pins_noise_keys_and_a_measurement() {
    let t = ok(&peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\nmeasurement = \"{MEAS}\"\n")));
    let p = t.find_peer(b"fleet").unwrap();
    assert_eq!(p.noise_pks(), [[1u8; 32], [2u8; 32]]);
    assert_eq!(p.noise_pk_of(2), Some(&[1u8; 32]));
    assert_eq!(p.noise_pk_of(3), Some(&[2u8; 32]));
    assert_eq!(p.noise_pk_of(4), None, "a node the class does not list has no key");
    assert_eq!(p.measurement.map(|m| (m[0], m[31])), Some((0xa1, 0xc0)));
    assert_eq!(round_trip(&t), None);
    // The keys may come before the nodes: they are matched when the class is closed.
    let t = ok(&format!("[peer.fleet]\nnoise_pk = [\"{PK1}\", \"{PK2}\"]\nnodes = [2, 3]\n"));
    assert_eq!(t.find_peer(b"fleet").unwrap().noise_pks().len(), 2);
    // A class pins nothing unless it says so.
    let t = ok(&peer(""));
    let p = t.find_peer(b"fleet").unwrap();
    assert!(p.noise_pks().is_empty() && p.measurement.is_none() && p.noise_pk_of(2).is_none());
    assert_eq!(round_trip(&t), None);
    // A measurement without keys, and keys without a measurement.
    assert!(ok(&peer(&format!("measurement = \"{MEAS}\"\n"))).find_peer(b"fleet").unwrap().noise_pks().is_empty());
    assert!(ok(&peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\n"))).find_peer(b"fleet").unwrap().measurement.is_none());
}

/// The brain link reads exactly one row: `[peer.brain]`. Its first node's key
/// is the one `Noise_IK` is pinned to; no row, a row of another name, or a row
/// without keys pins nothing (`Noise_XX`).
///
/// **Canary.** Look the class up under another name, or take the second
/// node's key: the key read is not the first node's.
#[test]
fn the_brain_link_reads_the_first_key_of_peer_brain() {
    let brain = |extra: &str| format!("[peer.brain]\nnodes = [2, 3]\n{extra}");
    let t = ok(&brain(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\n")));
    assert_eq!(t.brain_noise_pk(), Some([1u8; 32]));
    assert_eq!(round_trip(&t), None);
    assert_eq!(ok(&brain("")).brain_noise_pk(), None, "a row without keys pins nothing");
    assert_eq!(
        ok(&peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\n"))).brain_noise_pk(),
        None,
        "a class of another name is not the brain"
    );
    assert_eq!(ok("").brain_noise_pk(), None, "no row, no pin");
}

#[test]
fn a_peer_pin_is_refused_below_format_7() {
    assert_eq!(refused_in_6(&peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\n"))), ParseError::FieldNeedsFormat);
    assert_eq!(refused_in_6(&peer(&format!("measurement = \"{MEAS}\"\n"))), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_peer_pin_is_refused() {
    let bad_peer = ParseError::Admission(AdmissionError::BadPeer);
    let one = &PK1[..63];
    for (extra, want) in [
        // One key per node, or none.
        (format!("noise_pk = [\"{PK1}\"]\n"), bad_peer),
        (format!("noise_pk = [\"{PK1}\", \"{PK2}\", \"{PK3}\"]\n"), bad_peer),
        // A key twice in the class.
        (format!("noise_pk = [\"{PK1}\", \"{PK1}\"]\n"), bad_peer),
        // Not a key.
        (format!("noise_pk = [\"{ZERO}\", \"{PK1}\"]\n"), bad_peer),
        (format!("measurement = \"{ZERO}\"\n"), bad_peer),
        (format!("noise_pk = [\"{one}\", \"{PK2}\"]\n"), ParseError::BadValue),
        (format!("noise_pk = [\"{PK1}x\", \"{PK2}\"]\n"), ParseError::NameTooLong),
        (format!("noise_pk = [\"{}g\", \"{PK2}\"]\n", &PK1[..63]), ParseError::BadValue),
        (format!("measurement = \"{one}\"\n"), ParseError::BadValue),
        (format!("measurement = {MEAS}\n"), ParseError::BadValue),
        (format!("measurement = \"{MEAS}\" x\n"), ParseError::BadValue),
        // Each at most once.
        (format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\nnoise_pk = [\"{PK1}\", \"{PK2}\"]\n"), ParseError::BadValue),
        (format!("measurement = \"{MEAS}\"\nmeasurement = \"{MEAS}\"\n"), ParseError::BadValue),
        ("noise_pk = PK\n".to_string(), ParseError::BadValue),
    ] {
        assert_eq!(refused(&peer(&extra)), want, "{extra}");
    }
    // A key two classes share is two nodes with one identity.
    assert_eq!(
        refused(&format!(
            "{}[peer.other]\nnodes = [7]\nnoise_pk = [\"{PK2}\"]\n",
            peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\n"))
        )),
        bad_peer
    );
}

#[test]
fn a_peer_pin_round_trips() {
    let a = peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\nmeasurement = \"{MEAS}\"\n"));
    let t = ok(&a);
    let u = ok(&a.replace(PK2, PK3));
    assert_eq!(first_difference(&t, &u), Some("peer noise_pk"));
    let u = ok(&a.replace(MEAS, PK3));
    assert_eq!(first_difference(&t, &u), Some("peer measurement"));
}

// ── export: no key ─────────────────────────────────────────────────────────

/// An export is `NAME@CLASS` and nothing else: the Zenoh gateway takes its key
/// from Kconfig (`ZENOH_DECISIONS_KEY`), so a key in the row has no reader and
/// is refused rather than ignored.
///
/// **Canary.** Teach the parser to accept `=KEYEXPR` again (split on `=` and
/// drop the tail): the `Err` assertion goes red.
#[test]
fn an_export_carries_no_zenoh_key() {
    let row = |export: &str| format!(
        "format = 7\n[task.RPCSRV.ELF]\nexport = [{export}]\ncaps = [\n\
  {{ kind = \"endpoint\", target = \"endpoint.decisions\", perm = \"w\", transfer = true }},\n\
]\n[peer.fleet]\nnodes = [2, 3]\n"
    );
    let (t, r) = parse(leak(row("\"decisions@fleet\"")));
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Ok(()));
    let (_, r) = parse(leak(row("\"decisions@fleet=azos/dec/**\"")));
    assert_eq!(r, Err(ParseError::Admission(AdmissionError::BadExport)));
}

// ── policy: scope = "subtree" ──────────────────────────────────────────────

const POLICY: &str = "[policy.kids]\ndomain = \"sh.ELF\"\nscope = \"subtree\"\ncreate_endpoints = false\n\
create_ports = false\nmemobj_max_pages = 64\n";

fn with_sh(rows: &str) -> String {
    format!("[task.sh.ELF]\ncaps = []\n{rows}")
}

#[test]
fn a_policy_row_limits_a_domain_and_its_subtree() {
    let t = ok(&with_sh(POLICY));
    assert_eq!(t.admission_check(), Ok(()));
    let p = &t.policies()[0];
    assert_eq!(p.name.as_str(), "kids");
    assert_eq!(p.domain.as_str(), "sh.ELF");
    assert_eq!(
        (p.scope, p.create_endpoints, p.create_ports, p.memobj_max_pages),
        (azos_topology::PolicyScope::Subtree, false, false, 64)
    );
    // The defaults narrow nothing but what the row says.
    let t = ok(&with_sh("[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = false\n"));
    let p = &t.policies()[0];
    assert_eq!(
        (p.scope, p.create_endpoints, p.create_ports, p.memobj_max_pages),
        (azos_topology::PolicyScope::This, true, false, 0)
    );
    // The same Domain may carry one row per scope.
    let both = with_sh(
        "[policy.a]\ndomain = \"sh.ELF\"\ncreate_ports = false\n\
[policy.b]\ndomain = \"sh.ELF\"\nscope = \"subtree\"\ncreate_ports = false\n",
    );
    assert_eq!(ok(&both).policies().len(), 2);
    assert_eq!(round_trip(&ok(&both)), None);
}

#[test]
fn a_policy_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(&with_sh(POLICY)), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_policy_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Policy));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Policy));
    for (body, want) in [
        ("[policy.p]\ncreate_ports = false\n", ParseError::MissingField),
        // A row that restricts nothing is a typo, not a policy.
        ("[policy.p]\ndomain = \"sh.ELF\"\n", bad_row),
        ("[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = true\nscope = \"subtree\"\n", bad_row),
        ("[policy.p]\ndomain = \"\"\ncreate_ports = false\n", bad_row),
        ("[policy.a.b]\ndomain = \"sh.ELF\"\ncreate_ports = false\n", bad_row),
        ("[policy.p]\ndomain = \"sh.ELF\"\nscope = \"tree\"\ncreate_ports = false\n", ParseError::UnknownEnumValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\nscope = subtree\ncreate_ports = false\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = 0\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\ncreate_endpoints = falsey\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\nmemobj_max_pages = 4294967296\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\nmemobj_max_pages = -1\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = false\ncreate_ports = false\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\ndomain = \"sh.ELF\"\ncreate_ports = false\n", ParseError::BadValue),
        ("[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = false\nspeed = 3\n", ParseError::UnknownField),
        // Two rows under one name, or for one Domain and scope.
        (
            "[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = false\n[policy.p]\ndomain = \"sh.ELF\"\nscope = \"subtree\"\ncreate_ports = false\n",
            dup_row,
        ),
        (
            "[policy.p]\ndomain = \"sh.ELF\"\ncreate_ports = false\n[policy.q]\ndomain = \"sh.ELF\"\ncreate_endpoints = false\n",
            dup_row,
        ),
    ] {
        assert_eq!(refused(&with_sh(body)), want, "{body}");
    }
    // One row per (Domain, scope), so spread the rows over Domains.
    let rows: String = (0..azos_topology::MAX_POLICIES + 1)
        .map(|i| format!("[task.d{i}]\ncaps = []\n"))
        .collect();
    let spread: String = (0..azos_topology::MAX_POLICIES + 1)
        .map(|i| format!("[policy.p{i}]\ndomain = \"d{i}\"\nmemobj_max_pages = 1\n"))
        .collect();
    assert_eq!(refused(&format!("{rows}{spread}")), dup_row, "one past the table");
}

/// **Canary.** Skip the policy loop of `admission_check`: the assertion goes red.
#[test]
fn a_policy_on_a_domain_with_no_row_is_refused_at_admission() {
    let t = ok(&POLICY.replace("sh.ELF", "nobody.ELF"));
    assert_eq!(t.admission_check(), Err(AdmissionError::BadRow(RowKind::Policy)));
    let t = ok(&with_sh(POLICY));
    assert_eq!(t.admission_check(), Ok(()));
}

#[test]
fn a_policy_row_round_trips() {
    let t = ok(&with_sh(POLICY));
    assert_eq!(round_trip(&t), None);
    for (from, to) in [
        ("scope = \"subtree\"\n", ""),
        ("create_endpoints = false\n", ""),
        ("create_ports = false\n", ""),
        ("memobj_max_pages = 64", "memobj_max_pages = 65"),
        ("\"sh.ELF\"", "\"sh.ELF2\""),
        ("[policy.kids]", "[policy.pups]"),
    ] {
        let u = ok(&with_sh(&POLICY.replace(from, to)));
        assert_eq!(first_difference(&t, &u), Some("policy"), "{from}");
    }
}

// ── livepatch ──────────────────────────────────────────────────────────────

const BID: &str = "00112233445566778899aabbccddeeff00112233";
const BLOB: &str = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const BLOB2: &str = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef";

fn patch(name: &str, isa: &str, blob: &str) -> String {
    format!("[livepatch.{name}]\nisa = \"{isa}\"\nbuild_id = \"{BID}\"\nsec_epoch = 3\nsha256 = \"{blob}\"\n")
}

#[test]
fn a_livepatch_row_admits_one_blob_for_one_kernel_build() {
    let t = ok(&patch("sched-fix", "aarch64", BLOB));
    let l = &t.livepatches()[0];
    assert_eq!(l.name.as_str(), "sched-fix");
    assert_eq!((l.isa, l.sec_epoch, l.build_id.len), (azos_topology::PatchIsa::Aarch64, 3, 20));
    assert_eq!(l.build_id.as_bytes()[..3], [0x00, 0x11, 0x22]);
    assert_eq!(l.sha256[0], 0xb0);
    assert_eq!(t.find_livepatch(azos_topology::PatchIsa::Aarch64, &l.sha256).map(|f| f.name.as_str()), Some("sched-fix"));
    assert!(t.find_livepatch(azos_topology::PatchIsa::Riscv64, &l.sha256).is_none(), "the ISA is part of the key");
    assert!(t.find_livepatch(azos_topology::PatchIsa::Aarch64, &[0u8; 32]).is_none());
    assert_eq!(round_trip(&t), None);
    // The same blob for another ISA is another admission; so is another blob.
    let both = format!("{}{}{}", patch("a", "aarch64", BLOB), patch("b", "riscv64", BLOB), patch("c", "x86_64", BLOB2));
    let t = ok(&both);
    assert_eq!(t.livepatches().len(), 3);
    assert_eq!(round_trip(&t), None);
    // Build-ids of 8 and 32 bytes are the ends of the range.
    for hex in ["0011223344556677", &BLOB[..64]] {
        let t = ok(&patch("a", "riscv64", BLOB2).replace(BID, hex));
        assert_eq!(t.livepatches()[0].build_id.as_bytes().len(), hex.len() / 2);
        assert_eq!(round_trip(&t), None);
    }
}

#[test]
fn a_livepatch_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(&patch("a", "riscv64", BLOB)), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_livepatch_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Livepatch));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Livepatch));
    let good = patch("a", "riscv64", BLOB);
    let edit = |from: &str, to: &str| good.replace(from, to);
    for (body, want) in [
        // Every key is required.
        (edit("isa = \"riscv64\"\n", ""), ParseError::MissingField),
        (edit(&format!("build_id = \"{BID}\"\n"), ""), ParseError::MissingField),
        (edit("sec_epoch = 3\n", ""), ParseError::MissingField),
        (edit(&format!("sha256 = \"{BLOB}\"\n"), ""), ParseError::MissingField),
        (edit("riscv64", "mips"), ParseError::UnknownEnumValue),
        (edit("\"riscv64\"", "riscv64"), ParseError::BadValue),
        // A build-id is 8 to 32 bytes of hex.
        (edit(BID, "00112233445566"), ParseError::BadValue),
        (edit(BID, &format!("{}0", &BLOB[..60])), ParseError::BadValue),
        (edit(BID, &format!("{BLOB}00")), ParseError::NameTooLong),
        (edit(BID, "0011223344556677zz"), ParseError::BadValue),
        // The epoch starts at 1 and fits a u32.
        (edit("sec_epoch = 3", "sec_epoch = 0"), bad_row),
        (edit("sec_epoch = 3", "sec_epoch = 4294967296"), ParseError::BadValue),
        (edit("sec_epoch = 3", "sec_epoch = -1"), ParseError::BadValue),
        // The blob hash is a SHA-256 and not nothing.
        (edit(BLOB, &BLOB[..62]), ParseError::BadValue),
        (edit(BLOB, &"00".repeat(32)), bad_row),
        (edit("[livepatch.a]", "[livepatch.a.b]"), bad_row),
        (format!("{good}sec_epoch = 4\n"), ParseError::BadValue),
        (format!("{good}speed = 4\n"), ParseError::UnknownField),
        // A name twice; a blob twice for one ISA.
        (format!("{good}{good}"), dup_row),
        (format!("{good}{}", patch("b", "riscv64", BLOB)), dup_row),
    ] {
        assert_eq!(refused(&body), want, "{body}");
    }
    let many: String = (0..azos_topology::MAX_LIVEPATCHES + 1)
        .map(|i| patch(&format!("p{i}"), "riscv64", &format!("{:02x}{}", i + 1, &BLOB[2..])))
        .collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

#[test]
fn a_livepatch_row_round_trips() {
    let good = patch("a", "riscv64", BLOB);
    let t = ok(&good);
    for (from, to) in [
        ("riscv64", "aarch64"),
        (BID, "00112233445566778899aabbccddeeff00112234"),
        ("sec_epoch = 3", "sec_epoch = 4"),
        (BLOB, BLOB2),
        ("[livepatch.a]", "[livepatch.z]"),
    ] {
        assert_eq!(first_difference(&t, &ok(&good.replace(from, to))), Some("livepatch"), "{from}");
    }
}

// ── degrade ────────────────────────────────────────────────────────────────

const DEGRADE: &str = "[degrade.low]\nlevel = \"cautious\"\nbattery_pct = 30\nclear_pct = 40\n\
[degrade.critical]\nlevel = \"slow\"\nbattery_pct = 15\n\
[degrade.dying]\nlevel = \"contained\"\nbattery_pct = 5\nclear_pct = 10\n";

#[test]
fn degrade_rows_declare_battery_thresholds_per_level() {
    let t = ok(DEGRADE);
    let d = t.degrades();
    assert_eq!(d.len(), 3);
    assert_eq!((d[0].level, d[0].battery_pct, d[0].clear_pct), (Envelope::Cautious, 30, 40));
    assert_eq!((d[1].level, d[1].battery_pct, d[1].clear_pct), (Envelope::Slow, 15, 15), "no hysteresis unless declared");
    assert_eq!((d[2].level, d[2].battery_pct, d[2].clear_pct), (Envelope::Contained, 5, 10));
    assert_eq!(round_trip(&t), None);
    // Order in the file does not matter, only the thresholds' agreement.
    let reversed = "[degrade.dying]\nlevel = \"contained\"\nbattery_pct = 5\n[degrade.low]\nlevel = \"cautious\"\nbattery_pct = 30\n";
    assert_eq!(ok(reversed).degrades().len(), 2);
    // The ends of the range.
    assert_eq!(ok("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 100\nclear_pct = 100\n").degrades()[0].battery_pct, 100);
    assert_eq!(ok("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 1\n").degrades()[0].battery_pct, 1);
}

#[test]
fn a_degrade_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(DEGRADE), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_degrade_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Degrade));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Degrade));
    for (body, want) in [
        ("[degrade.a]\nbattery_pct = 30\n", ParseError::MissingField),
        ("[degrade.a]\nlevel = \"slow\"\n", ParseError::MissingField),
        ("[degrade.a]\nlevel = \"full\"\nbattery_pct = 30\n", bad_row),
        ("[degrade.a]\nlevel = \"tight\"\nbattery_pct = 30\n", ParseError::UnknownEnumValue),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 0\n", bad_row),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 101\n", ParseError::BadValue),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = -1\n", ParseError::BadValue),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 3.5\n", ParseError::BadValue),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 30\nclear_pct = 29\n", bad_row),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 30\nclear_pct = 101\n", ParseError::BadValue),
        ("[degrade.a.b]\nlevel = \"slow\"\nbattery_pct = 30\n", bad_row),
        ("[degrade.a]\nlevel = \"slow\"\nlevel = \"slow\"\nbattery_pct = 30\n", ParseError::BadValue),
        ("[degrade.a]\nlevel = \"slow\"\nbattery_pct = 30\nspeed = 3\n", ParseError::UnknownField),
        // A level once; a name once.
        (
            "[degrade.a]\nlevel = \"slow\"\nbattery_pct = 30\n[degrade.b]\nlevel = \"slow\"\nbattery_pct = 20\n",
            dup_row,
        ),
        (
            "[degrade.a]\nlevel = \"slow\"\nbattery_pct = 30\n[degrade.a]\nlevel = \"contained\"\nbattery_pct = 20\n",
            dup_row,
        ),
        // A more restrictive level cannot be entered at a higher charge than
        // a less restrictive one, nor at the same.
        (
            "[degrade.a]\nlevel = \"cautious\"\nbattery_pct = 20\n[degrade.b]\nlevel = \"slow\"\nbattery_pct = 30\n",
            bad_row,
        ),
        (
            "[degrade.a]\nlevel = \"cautious\"\nbattery_pct = 20\n[degrade.b]\nlevel = \"slow\"\nbattery_pct = 20\n",
            bad_row,
        ),
        (
            "[degrade.b]\nlevel = \"slow\"\nbattery_pct = 20\n[degrade.a]\nlevel = \"cautious\"\nbattery_pct = 20\n",
            bad_row,
        ),
    ] {
        assert_eq!(refused(body), want, "{body}");
    }
}

#[test]
fn a_degrade_row_round_trips() {
    let t = ok(DEGRADE);
    for (from, to) in [
        ("battery_pct = 30", "battery_pct = 31"),
        ("clear_pct = 40", "clear_pct = 41"),
        ("clear_pct = 40\n", ""),
    ] {
        assert_eq!(first_difference(&t, &ok(&DEGRADE.replace(from, to))), Some("degrade"), "{from}");
    }
    let mut renamed = ok(&DEGRADE.replace("[degrade.low]", "[degrade.lo]"));
    assert_eq!(first_difference(&t, &renamed), Some("degrade"));
    renamed.clear();
    assert!(renamed.degrades().is_empty());
}

// ── clock ──────────────────────────────────────────────────────────────────

const CLOCK: &str = "[clock]\nptp_domain = 24\nleaps = [\"63072000:10\", \"78796800:11\", \"94694400:12\", \"126230400:13\"]\n";

/// 28 leap seconds since 1972, as the real table runs, offsets 10 to 37.
fn real_table() -> String {
    let entries: Vec<String> = (0..28).map(|i| format!("\"{}:{}\"", 63_072_000u64 + 31_536_000 * (i as u64), 10 + i)).collect();
    format!("[clock]\nleaps = [{}]\n", entries.join(", "))
}

#[test]
fn a_clock_row_declares_the_ptp_domain_and_the_tai_table() {
    let t = ok(CLOCK);
    let c = t.clock();
    assert_eq!(c.ptp_domain, Some(24));
    assert_eq!(c.leaps().len(), 4);
    assert_eq!((c.leaps()[0].utc_secs, c.leaps()[0].tai_offset), (63_072_000, 10));
    assert_eq!((c.leaps()[3].utc_secs, c.leaps()[3].tai_offset), (126_230_400, 13));
    assert_eq!(round_trip(&t), None);
    // Either key alone; the largest domain; the real table fits the default limit.
    assert_eq!(ok("[clock]\nptp_domain = 0\n").clock().ptp_domain, Some(0));
    assert_eq!(ok("[clock]\nptp_domain = 127\n").clock().ptp_domain, Some(127));
    assert!(ok("[clock]\nleaps = [\"5:1\"]\n").clock().ptp_domain.is_none());
    if azos_topology::LEAP_ENTRIES >= 28 {
        let real: &'static str = Box::leak(real_table().into_boxed_str());
        let t = ok(real);
        assert_eq!(t.clock().leaps().len(), 28);
        assert_eq!(round_trip(&t), None);
    }
    // A negative leap second moves the offset down by one.
    assert_eq!(ok("[clock]\nleaps = [\"10:20\", \"20:19\", \"30:20\"]\n").clock().leaps().len(), 3);
    // No row, nothing declared.
    let t = ok("");
    assert!(!t.clock().is_declared() && t.clock().leaps().is_empty());
}

#[test]
fn a_clock_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(CLOCK), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_clock_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Clock));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Clock));
    for (body, want) in [
        ("[clock]\n", bad_row),
        ("[clock]\nptp_domain = 128\n", ParseError::BadValue),
        ("[clock]\nptp_domain = -1\n", ParseError::BadValue),
        ("[clock]\nptp_domain = \"1\"\n", ParseError::BadValue),
        ("[clock]\nptp_domain = 1\nptp_domain = 1\n", ParseError::BadValue),
        ("[clock]\nleaps = []\n", bad_row),
        ("[clock]\nleaps = [\"10:0\"]\n", bad_row),
        ("[clock]\nleaps = [\"10:65536\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = [\"10\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = [\":10\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = [\"10:\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = [\"a:10\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = [\"10: 10\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = [\"18446744073709551616:10\"]\n", ParseError::BadValue),
        ("[clock]\nleaps = 10:11\n", ParseError::BadValue),
        // Time must advance, and the offset move by one.
        ("[clock]\nleaps = [\"20:10\", \"10:11\"]\n", bad_row),
        ("[clock]\nleaps = [\"10:10\", \"10:11\"]\n", bad_row),
        ("[clock]\nleaps = [\"10:10\", \"20:10\"]\n", bad_row),
        ("[clock]\nleaps = [\"10:10\", \"20:12\"]\n", bad_row),
        ("[clock]\nleaps = [\"10:10\", \"20:8\"]\n", bad_row),
        ("[clock]\nleaps = [\"10:10\"]\nleaps = [\"10:10\"]\n", ParseError::BadValue),
        ("[clock]\nzone = 1\n", ParseError::UnknownField),
        ("[clock]\nptp_domain = 1\n[clock]\nptp_domain = 2\n", dup_row),
    ] {
        assert_eq!(refused(body), want, "{body}");
    }
    let many: Vec<String> = (0..azos_topology::LEAP_ENTRIES + 1).map(|i| format!("\"{}:{}\"", 10 + i, 10 + i)).collect();
    assert_eq!(refused(&format!("[clock]\nleaps = [{}]\n", many.join(", "))), dup_row, "one past the table");
}

#[test]
fn a_clock_row_round_trips() {
    let t = ok(CLOCK);
    assert_eq!(first_difference(&t, &ok(&CLOCK.replace("= 24", "= 25"))), Some("clock ptp_domain"));
    assert_eq!(first_difference(&t, &ok(&CLOCK.replace("78796800:11", "78796801:11"))), Some("clock leaps"));
    assert_eq!(first_difference(&t, &ok(&CLOCK.replace(", \"126230400:13\"", ""))), Some("clock leaps"));
    assert_eq!(first_difference(&t, &ok("")), Some("clock ptp_domain"));
}

// ── swap and volume ────────────────────────────────────────────────────────

const SWAP: &str = "[swap.main]\npartition = 3\n";
const VOLUME: &str = "[volume.data]\npartition = 2\nmount = \"/data\"\naead = true\n\
[volume.sys]\npartition = 4\nmount = \"/sys/image\"\nread_only = true\nverity_root = \"a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0\"\n";

#[test]
fn a_swap_row_names_a_partition() {
    let t = ok(SWAP);
    assert_eq!((t.swaps()[0].name.as_str(), t.swaps()[0].partition), ("main", 3));
    assert_eq!(round_trip(&t), None);
    assert_eq!(ok("[swap.a]\npartition = 1\n").swaps()[0].partition, 1);
    assert_eq!(ok("[swap.a]\npartition = 16\n").swaps()[0].partition, 16);
    assert_eq!(first_difference(&t, &ok(&SWAP.replace("= 3", "= 5"))), Some("swap"));
    assert_eq!(first_difference(&t, &ok(&SWAP.replace("main", "other"))), Some("swap"));
}

#[test]
fn a_volume_row_declares_its_mount_and_integrity() {
    let t = ok(VOLUME);
    let (d, s) = (&t.volumes()[0], &t.volumes()[1]);
    assert_eq!((d.partition, d.mount.as_str(), d.read_only, d.aead, d.verity_root), (2, "/data", false, true, None));
    assert_eq!((s.partition, s.mount.as_str(), s.read_only, s.aead), (4, "/sys/image", true, false));
    assert_eq!(s.verity_root.map(|r| (r[0], r[31])), Some((0xa1, 0xc0)));
    assert_eq!(round_trip(&t), None);
    for (from, to) in [
        ("partition = 2", "partition = 5"),
        ("\"/data\"", "\"/data2\""),
        ("aead = true\n", ""),
        ("a1a2", "a1a3"),
        ("[volume.data]", "[volume.dat]"),
    ] {
        assert_eq!(first_difference(&t, &ok(&VOLUME.replace(from, to))), Some("volume"), "{from}");
    }
    // read_only differs on a volume that has no verity root.
    let rw = "[volume.d]\npartition = 2\nmount = \"/d\"\n";
    let ro = "[volume.d]\npartition = 2\nmount = \"/d\"\nread_only = true\n";
    assert_eq!(first_difference(&ok(rw), &ok(ro)), Some("volume"));
}

#[test]
fn swap_and_volume_rows_are_refused_below_format_7() {
    assert_eq!(refused_in_6(SWAP), ParseError::FieldNeedsFormat);
    assert_eq!(refused_in_6(VOLUME), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_swap_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Swap));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Swap));
    for (body, want) in [
        ("[swap.a]\n", ParseError::MissingField),
        ("[swap.a]\npartition = 0\n", bad_row),
        ("[swap.a]\npartition = 17\n", bad_row),
        ("[swap.a]\npartition = 256\n", ParseError::BadValue),
        ("[swap.a]\npartition = -1\n", ParseError::BadValue),
        ("[swap.a]\npartition = \"3\"\n", ParseError::BadValue),
        ("[swap.a]\npartition = 3\npartition = 3\n", ParseError::BadValue),
        ("[swap.a]\npartition = 3\nsize = 3\n", ParseError::UnknownField),
        ("[swap.a.b]\npartition = 3\n", bad_row),
        ("[swap.a]\npartition = 3\n[swap.a]\npartition = 4\n", dup_row),
        // A partition holds one thing: swap and volume tables together.
        ("[swap.a]\npartition = 3\n[swap.b]\npartition = 3\n", dup_row),
    ] {
        assert_eq!(refused(body), want, "{body}");
    }
    let many: String = (0..azos_topology::MAX_SWAPS + 1).map(|i| format!("[swap.s{i}]\npartition = {}\n", i + 1)).collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

#[test]
fn a_malformed_volume_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Volume));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Volume));
    let v = |extra: &str| format!("[volume.a]\npartition = 2\nmount = \"/data\"\n{extra}");
    let zero = "0".repeat(64);
    let root = "ab".repeat(32);
    for (body, want) in [
        ("[volume.a]\nmount = \"/data\"\n".to_string(), ParseError::MissingField),
        ("[volume.a]\npartition = 2\n".to_string(), ParseError::MissingField),
        (v("partition = 2\n"), ParseError::BadValue),
        (v("speed = 2\n"), ParseError::UnknownField),
        (v("aead = 1\n"), ParseError::BadValue),
        (v("read_only = yes\n"), ParseError::BadValue),
        (v(&format!("read_only = true\nverity_root = \"{}\"\n", &root[..62])), ParseError::BadValue),
        (v(&format!("read_only = true\nverity_root = {root}\n")), ParseError::BadValue),
        (v(&format!("read_only = true\nverity_root = \"{zero}\"\n")), bad_row),
        // A verity root belongs to a volume that cannot change.
        (v(&format!("verity_root = \"{root}\"\n")), bad_row),
        (v(&format!("read_only = false\nverity_root = \"{root}\"\n")), bad_row),
        ("[volume.a]\npartition = 0\nmount = \"/data\"\n".to_string(), bad_row),
        ("[volume.a]\npartition = 17\nmount = \"/data\"\n".to_string(), bad_row),
        ("[volume.a.b]\npartition = 2\nmount = \"/data\"\n".to_string(), bad_row),
    ] {
        assert_eq!(refused(&body), want, "{body}");
    }
    // Mount points.
    for bad in ["", "/", "data", "/data/", "//data", "/a//b", "/a/./b", "/a/..", "/../a", "/fat", "/fat/x", "/a b", "/a#b"] {
        assert_eq!(refused(&format!("[volume.a]\npartition = 2\nmount = \"{bad}\"\n")), bad_row, "{bad:?}");
    }
    for good in ["/data", "/a/b/c", "/fatty", "/data.1", "/a-b_c"] {
        let t = ok(&format!("[volume.a]\npartition = 2\nmount = \"{good}\"\n"));
        assert_eq!(t.volumes()[0].mount.as_str(), good);
    }
    let long = format!("/{}", "k".repeat(azos_topology::types::MAX_TARGET_LEN));
    assert!(refused(&format!("[volume.a]\npartition = 2\nmount = \"{long}\"\n")) != ParseError::MissingField);
    // Names, mounts and partitions are used once across both tables.
    assert_eq!(refused(&format!("{}[volume.a]\npartition = 3\nmount = \"/other\"\n", v(""))), dup_row);
    assert_eq!(refused(&format!("{}[volume.b]\npartition = 3\nmount = \"/data\"\n", v(""))), dup_row);
    assert_eq!(refused(&format!("{}[volume.b]\npartition = 2\nmount = \"/other\"\n", v(""))), dup_row);
    assert_eq!(refused(&format!("{}[swap.s]\npartition = 2\n", v(""))), ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Swap)));
    assert_eq!(refused(&format!("[swap.s]\npartition = 2\n{}", v(""))), dup_row);
    assert_eq!(ok(&format!("[swap.s]\npartition = 3\n{}", v(""))).volumes().len(), 1);
    let many: String = (0..azos_topology::MAX_VOLUMES + 1)
        .map(|i| format!("[volume.v{i}]\npartition = {}\nmount = \"/m{i}\"\n", i + 1))
        .collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

// ── guest ──────────────────────────────────────────────────────────────────

const GUEST: &str = "[guest.linux]\ncpus = 2\nmem_mib = 512\nenvelope = \"contained\"\ndevices = [\"virtio-blk\", \"virtio-net\", \"virtio-console\"]\n";

#[test]
fn a_guest_row_declares_cpus_memory_devices_and_envelope() {
    let t = ok(GUEST);
    let g = &t.guests()[0];
    assert_eq!((g.name.as_str(), g.cpus, g.mem_mib, g.envelope), ("linux", 2, 512, Envelope::Contained));
    assert_eq!(g.devices().iter().map(|d| d.as_str()).collect::<Vec<_>>(), ["virtio-blk", "virtio-net", "virtio-console"]);
    assert_eq!(round_trip(&t), None);
    // A headless guest has no devices; the ends of the ranges.
    let t = ok("[guest.g]\ncpus = 255\nmem_mib = 4294967295\nenvelope = \"full\"\n");
    assert_eq!((t.guests()[0].cpus, t.guests()[0].mem_mib, t.guests()[0].devices().len()), (255, u32::MAX, 0));
    assert_eq!(round_trip(&t), None);
    assert_eq!(ok("[guest.g]\ncpus = 1\nmem_mib = 1\nenvelope = \"slow\"\ndevices = []\n").guests()[0].devices().len(), 0);
    for (from, to) in [
        ("cpus = 2", "cpus = 3"),
        ("mem_mib = 512", "mem_mib = 513"),
        ("\"contained\"", "\"slow\""),
        ("\"virtio-net\"", "\"virtio-rng\""),
        (", \"virtio-console\"", ""),
        ("[guest.linux]", "[guest.lx]"),
    ] {
        assert_eq!(first_difference(&ok(GUEST), &ok(&GUEST.replace(from, to))), Some("guest"), "{from}");
    }
}

#[test]
fn a_guest_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(GUEST), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_guest_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Guest));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Guest));
    let edit = |from: &str, to: &str| GUEST.replace(from, to);
    let nine: Vec<String> = (0..azos_topology::GUEST_DEVICES + 1).map(|i| format!("\"d{i}\"")).collect();
    for (body, want) in [
        // The envelope has no default: a guest is untrusted.
        (edit("envelope = \"contained\"\n", ""), ParseError::MissingField),
        (edit("cpus = 2\n", ""), ParseError::MissingField),
        (edit("mem_mib = 512\n", ""), ParseError::MissingField),
        (edit("cpus = 2", "cpus = 0"), bad_row),
        (edit("cpus = 2", "cpus = 256"), ParseError::BadValue),
        (edit("cpus = 2", "cpus = -1"), ParseError::BadValue),
        (edit("mem_mib = 512", "mem_mib = 0"), bad_row),
        (edit("mem_mib = 512", "mem_mib = 4294967296"), ParseError::BadValue),
        (edit("mem_mib = 512", "mem_mib = \"512\""), ParseError::BadValue),
        (edit("\"contained\"", "\"locked\""), ParseError::UnknownEnumValue),
        (edit("\"virtio-net\"", "\"virtio.net\""), bad_row),
        (edit("\"virtio-net\"", "\"\""), bad_row),
        (edit("\"virtio-net\"", "\"virtio-blk\""), bad_row),
        (edit("\"virtio-net\"", "\"0123456789012345678901234\""), bad_row),
        (edit("devices = [", "devices = "), ParseError::BadValue),
        (format!("{GUEST}devices = []\n"), ParseError::BadValue),
        (format!("{GUEST}memory = 1\n"), ParseError::UnknownField),
        (format!("devices = [{}]\n", nine.join(", ")).replace("devices", "[guest.g]\ncpus = 1\nmem_mib = 1\nenvelope = \"full\"\ndevices"), bad_row),
        ("[guest.a.b]\ncpus = 1\nmem_mib = 1\nenvelope = \"full\"\n".to_string(), bad_row),
        (format!("{GUEST}{GUEST}"), dup_row),
    ] {
        assert_eq!(refused(&body), want, "{body}");
    }
    let many: String = (0..azos_topology::MAX_GUESTS + 1)
        .map(|i| format!("[guest.g{i}]\ncpus = 1\nmem_mib = 1\nenvelope = \"full\"\n"))
        .collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

// ── route and firewall ─────────────────────────────────────────────────────

use azos_topology::{FwAction, FwDir, FwProto, IpAddr, IpPrefix};

const ROUTES: &str = "[route.lan]\ndest = \"10.1.0.0/16\"\ndev = \"eth0\"\n\
[route.gw]\ndest = \"0.0.0.0/0\"\nvia = \"10.1.0.1\"\ndev = \"eth0\"\nmetric = 100\n\
[route.v6]\ndest = \"fd00:1::/32\"\nvia = \"fe80:0:0:0:0:0:0:1\"\ndev = \"wlan0\"\nmetric = 5\n\
[route.v6def]\ndest = \"::/0\"\nvia = \"fd00::1\"\ndev = \"wlan0\"\n";

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&[a, b, c, d]);
    IpAddr { v6: false, bytes }
}

#[test]
fn ip_addresses_and_prefixes_parse_to_bytes() {
    assert_eq!(IpAddr::parse(b"10.1.2.3"), Some(v4(10, 1, 2, 3)));
    assert_eq!(IpAddr::parse(b"0.0.0.0"), Some(v4(0, 0, 0, 0)));
    assert_eq!(IpAddr::parse(b"255.255.255.255"), Some(v4(255, 255, 255, 255)));
    for bad in ["", "1.2.3", "1.2.3.4.5", "1.2.3.256", "01.2.3.4", "1.2.3.", ".1.2.3", "1..2.3", "a.b.c.d", "1.2.3.4 ", "-1.2.3.4", "1.2.3.4/8"] {
        assert_eq!(IpAddr::parse(bad.as_bytes()), None, "{bad:?}");
    }
    let v6 = |s: &str| IpAddr::parse(s.as_bytes()).map(|a| (a.v6, a.bytes));
    assert_eq!(v6("::"), Some((true, [0; 16])));
    assert_eq!(v6("::1").map(|a| a.1[15]), Some(1));
    assert_eq!(v6("1::").map(|a| (a.1[0], a.1[1], a.1[15])), Some((0, 1, 0)));
    assert_eq!(v6("fe80::1:2").map(|a| (a.1[0], a.1[1], a.1[13], a.1[15])), Some((0xfe, 0x80, 1, 2)));
    assert_eq!(v6("2001:db8:0:0:0:0:0:1"), v6("2001:db8::1"));
    assert_eq!(v6("ABCD:ef01:2:3:4:5:6:7").map(|a| (a.1[0], a.1[1], a.1[2], a.1[3])), Some((0xab, 0xcd, 0xef, 0x01)));
    // `::` stands for at least one group.
    assert!(v6("1:2:3:4:5:6:7::").is_some());
    assert!(v6("1:2:3:4:5:6:7:8::").is_none());
    assert!(v6("::1:2:3:4:5:6:7").is_some());
    assert!(v6("::1:2:3:4:5:6:7:8").is_none());
    for bad in [":", ":::", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "12345::", "g::", "::1.2.3.4", "1:2:3:4:5:6:7:", ":1:2:3:4:5:6:7", "fe80::1%eth0", "1::2:", ":1::2"] {
        assert!(v6(bad).is_none(), "{bad:?}");
    }
    let p = |s: &str| IpPrefix::parse(s.as_bytes());
    assert_eq!(p("10.0.0.0/8").map(|p| (p.addr, p.len)), Some((v4(10, 0, 0, 0), 8)));
    assert_eq!(p("0.0.0.0/0").map(|p| p.len), Some(0));
    assert_eq!(p("1.2.3.4/32").map(|p| p.len), Some(32));
    assert_eq!(p("::/0").map(|p| (p.addr.v6, p.len)), Some((true, 0)));
    assert_eq!(p("fd00::/8").map(|p| p.len), Some(8));
    assert_eq!(p("::1/128").map(|p| p.len), Some(128));
    for bad in ["10.0.0.0", "10.0.0.0/", "10.0.0.0/33", "10.0.0.0/08", "10.0.0.0/-1", "10.0.0.0/a", "10.0.0.1/8", "10.0.0.0/8/8",
                "fd00::/129", "fd00::1/8", "/8", "10.0.0.0/0000"] {
        assert!(p(bad).is_none(), "{bad:?}");
    }
    // Display reads back to the same value.
    for t in ["10.1.2.3", "0.0.0.0", "fe80::1:2", "::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"] {
        let a = IpAddr::parse(t.as_bytes()).unwrap();
        assert_eq!(IpAddr::parse(a.to_string().as_bytes()), Some(a), "{t}");
    }
    for t in ["10.0.0.0/8", "fd00:1::/32", "::/0"] {
        let a = IpPrefix::parse(t.as_bytes()).unwrap();
        assert_eq!(IpPrefix::parse(a.to_string().as_bytes()), Some(a), "{t}");
    }
}

#[test]
fn route_rows_declare_static_routes_for_both_families() {
    let t = ok(ROUTES);
    let r = t.routes();
    assert_eq!(r.len(), 4);
    assert_eq!((r[0].name.as_str(), r[0].dest.len, r[0].via, r[0].dev.as_str(), r[0].metric), ("lan", 16, None, "eth0", 0));
    assert_eq!((r[1].dest.len, r[1].via, r[1].metric), (0, Some(v4(10, 1, 0, 1)), 100));
    assert!(r[2].dest.addr.v6 && r[2].via.is_some_and(|g| g.v6 && g.bytes[0] == 0xfe));
    assert_eq!((r[3].dest.len, r[3].dev.as_str()), (0, "wlan0"));
    assert_eq!(round_trip(&t), None);
    for (from, to) in [
        ("10.1.0.0/16", "10.2.0.0/16"),
        ("via = \"10.1.0.1\"", "via = \"10.1.0.2\""),
        ("eth0", "eth1"),
        ("metric = 100", "metric = 101"),
        ("metric = 5", "metric = 6"),
        ("[route.lan]", "[route.net]"),
        ("fd00:1::/32", "fd00:2::/32"),
    ] {
        assert_eq!(first_difference(&t, &ok(&ROUTES.replace(from, to))), Some("route"), "{from}");
    }
    // The same prefix at two metrics is two routes.
    let twice = "[route.a]\ndest = \"10.1.0.0/16\"\ndev = \"eth0\"\n[route.b]\ndest = \"10.1.0.0/16\"\ndev = \"eth1\"\nmetric = 1\n";
    assert_eq!(ok(twice).routes().len(), 2);
}

#[test]
fn a_route_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(ROUTES), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_route_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Route));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Route));
    let r = |extra: &str| format!("[route.a]\ndest = \"10.1.0.0/16\"\ndev = \"eth0\"\n{extra}");
    for (body, want) in [
        ("[route.a]\ndev = \"eth0\"\n".to_string(), ParseError::MissingField),
        ("[route.a]\ndest = \"10.1.0.0/16\"\n".to_string(), ParseError::MissingField),
        (r("dest = \"10.1.0.0/16\"\n"), ParseError::BadValue),
        (r("speed = 1\n"), ParseError::UnknownField),
        ("[route.a]\ndest = \"10.1.0.1/16\"\ndev = \"eth0\"\n".to_string(), ParseError::BadValue),
        ("[route.a]\ndest = 10.1.0.0/16\ndev = \"eth0\"\n".to_string(), ParseError::BadValue),
        ("[route.a]\ndest = \"default\"\ndev = \"eth0\"\n".to_string(), ParseError::BadValue),
        (r("via = \"10.1.0\"\n"), ParseError::BadValue),
        (r("via = \"fd00::1\"\n"), bad_row),
        (r("via = \"0.0.0.0\"\n"), bad_row),
        ("[route.a]\ndest = \"fd00::/8\"\nvia = \"10.0.0.1\"\ndev = \"eth0\"\n".to_string(), bad_row),
        ("[route.a]\ndest = \"fd00::/8\"\nvia = \"::\"\ndev = \"eth0\"\n".to_string(), bad_row),
        ("[route.a]\ndest = \"10.1.0.0/16\"\ndev = \"\"\n".to_string(), bad_row),
        ("[route.a]\ndest = \"10.1.0.0/16\"\ndev = \"eth/0\"\n".to_string(), bad_row),
        ("[route.a]\ndest = \"10.1.0.0/16\"\ndev = \"0123456789abcdef\"\n".to_string(), bad_row),
        (r("metric = 4294967296\n"), ParseError::BadValue),
        (r("metric = -1\n"), ParseError::BadValue),
        ("[route.a.b]\ndest = \"10.1.0.0/16\"\ndev = \"eth0\"\n".to_string(), bad_row),
        // Names once; a destination once per metric.
        (format!("{}{}", r(""), r("")), dup_row),
        (format!("{}[route.b]\ndest = \"10.1.0.0/16\"\ndev = \"eth1\"\n", r("")), dup_row),
    ] {
        assert_eq!(refused(&body), want, "{body}");
    }
    let many: String = (0..azos_topology::MAX_ROUTES + 1)
        .map(|i| format!("[route.r{i}]\ndest = \"10.{}.0.0/16\"\ndev = \"eth0\"\n", i))
        .collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

const FIREWALL: &str = "[firewall.ssh]\ndir = \"in\"\nproto = \"tcp\"\nport = 22\naddr = \"10.0.0.0/8\"\naction = \"allow\"\n\
[firewall.web]\ndir = \"in\"\nproto = \"tcp\"\nport = 8000\nport_end = 8099\naction = \"allow\"\n\
[firewall.ping]\ndir = \"in\"\nproto = \"icmp\"\naction = \"reject\"\n\
[firewall.egress]\ndir = \"forward\"\naddr = \"fd00::/8\"\naction = \"drop\"\n";

#[test]
fn firewall_rows_declare_ordered_packet_filter_rules() {
    let t = ok(FIREWALL);
    let f = t.firewalls();
    assert_eq!(f.len(), 4);
    assert_eq!(
        (f[0].dir, f[0].proto, f[0].port_lo, f[0].port_hi, f[0].addr.map(|a| a.len), f[0].action),
        (FwDir::In, FwProto::Tcp, 22, 22, Some(8), FwAction::Allow)
    );
    assert_eq!((f[1].port_lo, f[1].port_hi, f[1].addr), (8000, 8099, None));
    assert_eq!((f[2].proto, f[2].port_lo, f[2].port_hi, f[2].action), (FwProto::Icmp, 0, 0, FwAction::Reject));
    assert_eq!((f[3].dir, f[3].proto, f[3].addr.map(|a| a.addr.v6)), (FwDir::Forward, FwProto::Any, Some(true)));
    assert_eq!(f.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["ssh", "web", "ping", "egress"], "file order is rule order");
    assert_eq!(round_trip(&t), None);
    for (from, to) in [
        ("port = 22", "port = 23"),
        ("port_end = 8099", "port_end = 8100"),
        ("\"allow\"", "\"drop\""),
        ("10.0.0.0/8", "10.0.0.0/9"),
        ("\"icmp\"", "\"udp\""),
        ("dir = \"forward\"", "dir = \"out\""),
        ("[firewall.ssh]", "[firewall.sshd]"),
    ] {
        assert_eq!(first_difference(&t, &ok(&FIREWALL.replace(from, to))), Some("firewall"), "{from}");
    }
    // Two rules that differ in address or port are two rules.
    let two = "[firewall.a]\ndir = \"in\"\nproto = \"tcp\"\nport = 22\naction = \"allow\"\n\
[firewall.b]\ndir = \"in\"\nproto = \"tcp\"\nport = 22\naddr = \"10.0.0.0/8\"\naction = \"drop\"\n";
    assert_eq!(ok(two).firewalls().len(), 2);
}

#[test]
fn a_firewall_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(FIREWALL), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_firewall_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Firewall));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Firewall));
    let f = |extra: &str| format!("[firewall.a]\ndir = \"in\"\naction = \"drop\"\n{extra}");
    for (body, want) in [
        ("[firewall.a]\naction = \"drop\"\n".to_string(), ParseError::MissingField),
        ("[firewall.a]\ndir = \"in\"\n".to_string(), ParseError::MissingField),
        (f("dir = \"in\"\n"), ParseError::BadValue),
        (f("speed = 1\n"), ParseError::UnknownField),
        ("[firewall.a]\ndir = \"sideways\"\naction = \"drop\"\n".to_string(), ParseError::UnknownEnumValue),
        ("[firewall.a]\ndir = \"in\"\naction = \"deny\"\n".to_string(), ParseError::UnknownEnumValue),
        (f("proto = \"sctp\"\n"), ParseError::UnknownEnumValue),
        (f("proto = tcp\n"), ParseError::BadValue),
        // Ports.
        (f("port = 22\n"), bad_row),
        (f("proto = \"any\"\nport = 22\n"), bad_row),
        (f("proto = \"icmp\"\nport = 22\n"), bad_row),
        (f("proto = \"tcp\"\nport = 0\n"), ParseError::BadValue),
        (f("proto = \"tcp\"\nport = 65536\n"), ParseError::BadValue),
        (f("proto = \"tcp\"\nport = -1\n"), ParseError::BadValue),
        (f("proto = \"tcp\"\nport_end = 80\n"), ParseError::MissingField),
        (f("proto = \"tcp\"\nport = 80\nport_end = 79\n"), bad_row),
        (f("proto = \"tcp\"\nport = 80\nport_end = 0\n"), ParseError::BadValue),
        (f("proto = \"tcp\"\nport = 80\nport = 81\n"), ParseError::BadValue),
        // Addresses.
        (f("addr = \"10.0.0.1/8\"\n"), ParseError::BadValue),
        (f("addr = \"10.0.0.0\"\n"), ParseError::BadValue),
        (f("addr = \"any\"\n"), ParseError::BadValue),
        ("[firewall.a.b]\ndir = \"in\"\naction = \"drop\"\n".to_string(), bad_row),
        // Names once; a rule an earlier one makes unreachable.
        (format!("{}{}", f(""), f("")), dup_row),
        (
            format!("{}[firewall.b]\ndir = \"in\"\naction = \"allow\"\n", f("")),
            dup_row,
        ),
    ] {
        assert_eq!(refused(&body), want, "{body}");
    }
    let many: String = (0..azos_topology::MAX_FIREWALL_ROWS + 1)
        .map(|i| format!("[firewall.f{i}]\ndir = \"in\"\nproto = \"tcp\"\nport = {}\naction = \"drop\"\n", i + 1))
        .collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

// ── the rows are inside the signature ──────────────────────────────────────

pub(crate) const DEV: [u8; 16] = [0xd0; 16];

pub(crate) fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

/// A `.SIG` sidecar (the `DSIG` of `azos_crypto::sig`) around an Ed25519
/// signature.
pub(crate) fn dsig(sig: [u8; 64]) -> Vec<u8> {
    let mut v = b"DSIG".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&64u16.to_le_bytes());
    v.extend_from_slice(&sig);
    v
}

/// One of every row this file adds, in one pair of files.
fn kitchen_sink() -> (String, String) {
    let sched = format!(
        "[sched]\nisolcpus = 12\n\
[class.hard]\ncpu_budget_min_pct = 20\ncpu_budget_max_pct = 100\npolicy = \"edf\"\npriority_range = [0, 7]\nadmission_control = true\n\
[class.agents]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\nenvelope = \"slow\"\nprincipal = \"agent\"\n\
[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n"
    );
    let caps = format!(
        "{DEVICE}{}{}{}{}{}{}{}{}{}{}{}",
        iso_row("rt1", "cpu_mask = 4\nkmem_kib = 64\n"),
        "[task.obs.ELF]\nshadow = true\ncaps = []\n[policy.kids]\ndomain = \"rt1\"\nscope = \"subtree\"\ncreate_ports = false\nmemobj_max_pages = 128\n",
        patch("fix", "aarch64", BLOB),
        DEGRADE,
        CLOCK,
        SWAP,
        VOLUME,
        GUEST,
        ROUTES,
        FIREWALL,
        peer(&format!("noise_pk = [\"{PK1}\", \"{PK2}\"]\nmeasurement = \"{MEAS}\"\n")),
    );
    let rpc = "[task.RPCSRV.ELF]\nexport = [\"decisions@fleet\"]\ncaps = [\n\
  { kind = \"endpoint\", target = \"endpoint.decisions\", perm = \"w\", transfer = true },\n]\n";
    (sched, format!("{caps}{rpc}"))
}

/// Emit the kitchen sink as a bound pair, sign it, and load it.
fn signed_pair(mutate_caps: impl Fn(String) -> String, mutate_sched: impl Fn(String) -> String)
    -> Result<Option<u64>, SignedRefusal>
{
    let (sched, body) = kitchen_sink();
    let caps = format!("format = 7\n{body}");
    let (t, r) = parse_with(&sched, &caps);
    assert_eq!(r, Ok(()));
    assert_eq!(t.admission_check(), Ok(()));
    let mut sched_out = String::new();
    emit_sched(&t, &mut sched_out).unwrap();
    let b = Binding {
        format: EMIT_FORMAT,
        device: Some(DEV),
        counter: Some(1),
        sched_sha256: Some(azos_crypto::sha256::sha256(sched_out.as_bytes())),
    };
    let mut caps_out = String::new();
    emit_caps(&t, &b, &mut caps_out).unwrap();
    // Signed as emitted, loaded as (possibly) tampered.
    let sig = dsig(key().sign(caps_out.as_bytes()).to_bytes());
    let (caps_in, sched_in) = (mutate_caps(caps_out.clone()), mutate_sched(sched_out.clone()));
    let files = SignedFiles { caps: caps_in.as_bytes(), caps_sig: &sig, sched: sched_in.as_bytes() };
    let ctx = DeviceContext { device_id: Some(DEV), floor: 0, bind_device: true, enforce_floor: true };
    let mut loaded = Box::new(Topology::empty());
    let r = load_signed(&mut loaded, &files, key().verifying_key().as_bytes(), &ctx);
    if r.is_ok() {
        assert_eq!(first_difference(&t, &loaded), None, "what was signed is what loads");
    }
    r
}

/// **Canary.** Build with `--features azos_topology/topo-verify-skip-canary`:
/// the tampered files load and the assertions go red.
#[test]
fn the_new_rows_are_inside_the_signature() {
    assert_eq!(signed_pair(|c| c, |s| s), Ok(Some(1)), "the pair as signed loads");
    let tampered: &[(&str, &str)] = &[
        ("commit_ns = 2500000", "commit_ns = 2500001"),
        ("safe_state = \"brake\"", "safe_state = \"coast\""),
        ("kmem_kib = 64", "kmem_kib = 65"),
        ("shadow = true", "shadow = false"),
        (PK1, PK3),
        (MEAS, PK3),
        ("decisions@fleet", "decisions@fleef"),
        ("memobj_max_pages = 128", "memobj_max_pages = 129"),
        ("scope = \"subtree\"", "scope = \"self\""),
        ("sec_epoch = 3", "sec_epoch = 2"),
        (BLOB, BLOB2),
        ("battery_pct = 30", "battery_pct = 31"),
        ("level = \"slow\"", "level = \"cautious\""),
        ("ptp_domain = 24", "ptp_domain = 25"),
        ("\"126230400:13\"", "\"126230400:14\""),
        ("partition = 3", "partition = 5"),
        ("mount = \"/data\"", "mount = \"/data2\""),
        ("aead = true", "aead = false"),
        ("read_only = true", "read_only = false"),
        ("mem_mib = 512", "mem_mib = 513"),
        ("\"virtio-net\"", "\"virtio-rng\""),
        ("10.1.0.0/16", "10.2.0.0/16"),
        ("port = 22", "port = 23"),
    ];
    for (from, to) in tampered {
        let r = signed_pair(|c| { assert!(c.contains(from), "{from}"); c.replacen(from, to, 1) }, |s| s);
        assert_eq!(r, Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature)), "{from}");
    }
    // SCHED.TOM rows are bound through the signed hash.
    for (from, to) in [("isolcpus = 12", "isolcpus = 8"), ("envelope = \"slow\"", "envelope = \"full\""), ("principal = \"agent\"", "principal = \"user\"")] {
        let r = signed_pair(|c| c, |s| { assert!(s.contains(from), "{from}"); s.replacen(from, to, 1) });
        assert_eq!(r, Err(SignedRefusal::SchedHashMismatch), "{from}");
    }
}

// ── login: the SSH accounts and their keys ─────────────────────────────────

fn hex_key(b: u8) -> String {
    format!("{b:02x}").repeat(32)
}

/// **Canary.** Make `LoginStage::commit` skip `push_login`: the table is empty
/// and the first assertion goes red. Make the emitter drop a key: the round
/// trip names it.
#[test]
fn a_login_row_lists_the_keys_of_one_ssh_account() {
    let t = ok(&format!(
        "[login.alice]\nssh_key = [\"{}\", \"{}\"]\n[login.bob]\nssh_key = [\"{}\"]\n",
        hex_key(1), hex_key(2), hex_key(3)
    ));
    let l = t.logins();
    assert_eq!(l.len(), 2);
    assert_eq!((l[0].name.as_str(), l[0].keys()), ("alice", &[[1u8; 32], [2u8; 32]][..]));
    assert_eq!((l[1].name.as_str(), l[1].keys()), ("bob", &[[3u8; 32]][..]));
    assert_eq!(round_trip(&t), None);
    // A different key is a different topology.
    let u = ok(&format!(
        "[login.alice]\nssh_key = [\"{}\", \"{}\"]\n[login.bob]\nssh_key = [\"{}\"]\n",
        hex_key(1), hex_key(2), hex_key(4)
    ));
    assert_eq!(first_difference(&t, &u), Some("login"));
    // No login row, no login.
    assert!(ok("").logins().is_empty());
}

#[test]
fn a_login_row_is_refused_below_format_7() {
    assert_eq!(refused_in_6(&format!("[login.alice]\nssh_key = [\"{}\"]\n", hex_key(1))), ParseError::FieldNeedsFormat);
}

#[test]
fn a_malformed_login_row_is_refused() {
    let bad_row = ParseError::Admission(AdmissionError::BadRow(RowKind::Login));
    let dup_row = ParseError::Admission(AdmissionError::DuplicateRow(RowKind::Login));
    let k = hex_key(1);
    let zero = "0".repeat(64);
    for (body, want) in [
        ("[login.alice]\n".to_string(), ParseError::MissingField),
        ("[login.alice]\nssh_key = []\n".to_string(), bad_row),
        (format!("[login.alice]\nssh_key = [\"{zero}\"]\n"), bad_row),
        (format!("[login.alice]\nssh_key = [\"{}\"]\n", &k[..62]), ParseError::BadValue),
        (format!("[login.alice]\nssh_key = \"{k}\"\n"), ParseError::BadValue),
        (format!("[login.alice]\nssh_key = [\"{k}\"]\nssh_key = [\"{k}\"]\n"), ParseError::BadValue),
        (format!("[login.alice]\nssh_key = [\"{k}\"]\npassword = \"x\"\n"), ParseError::UnknownField),
        (format!("[login.alice.b]\nssh_key = [\"{k}\"]\n"), bad_row),
        // A key that two accounts share would log in as either; one account
        // does not list a key twice either.
        (format!("[login.alice]\nssh_key = [\"{k}\"]\n[login.bob]\nssh_key = [\"{k}\"]\n"), dup_row),
        (format!("[login.alice]\nssh_key = [\"{k}\", \"{k}\"]\n"), dup_row),
        (format!("[login.alice]\nssh_key = [\"{k}\"]\n[login.alice]\nssh_key = [\"{}\"]\n", hex_key(2)), dup_row),
    ] {
        assert_eq!(refused(&body), want, "{body}");
    }
    let keys: String = (0..azos_topology::LOGIN_KEYS + 1).map(|i| format!("\"{}\",", hex_key(i as u8 + 1))).collect();
    assert_eq!(refused(&format!("[login.alice]\nssh_key = [{keys}]\n")), bad_row, "one past the keys of a row");
    let many: String = (0..azos_topology::MAX_LOGINS + 1).map(|i| format!("[login.u{i}]\nssh_key = [\"{}\"]\n", hex_key(i as u8 + 1))).collect();
    assert_eq!(refused(&many), dup_row, "one past the table");
}

// ── task: principal ────────────────────────────────────────────────────────

/// **Canary.** Drop `principal` from `TaskExt::commit`: the first assertion
/// goes red. Drop it from the emitter: the round trip names it.
#[test]
fn a_task_row_declares_the_principal_it_acts_as() {
    let t = ok("[task.A.ELF]\nprincipal = \"user\"\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    assert_eq!(t.row_principal(b"A.ELF"), Some(PrincipalKind::User));
    assert_eq!(t.row_principal(b"B.ELF"), None, "the next row inherits nothing");
    assert_eq!(t.row_principal(b"C.ELF"), None, "a name no row has");
    assert_eq!(round_trip(&t), None);
    let u = ok("[task.A.ELF]\nprincipal = \"agent\"\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    assert_eq!(first_difference(&t, &u), Some("task principal"));
    let u = ok("[task.A.ELF]\ncaps = []\n[task.B.ELF]\ncaps = []\n");
    assert_eq!(first_difference(&t, &u), Some("task principal"));
}

#[test]
fn a_task_principal_is_refused_below_format_7_and_when_malformed() {
    assert_eq!(refused_in_6("[task.A.ELF]\nprincipal = \"user\"\ncaps = []\n"), ParseError::FieldNeedsFormat);
    for (line, want) in [
        ("principal = \"root\"", ParseError::UnknownEnumValue),
        ("principal = user", ParseError::BadValue),
        ("principal = \"user\"\nprincipal = \"agent\"", ParseError::BadValue),
    ] {
        assert_eq!(refused(&format!("[task.A.ELF]\n{line}\ncaps = []\n")), want, "{line}");
    }
}
