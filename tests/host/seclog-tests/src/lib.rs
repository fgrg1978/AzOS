// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_seclog`: a simulated kernel publishes security
//! records into a ring and seals them with the sealer the kernel runs; the
//! log goes through the text lines `logd` writes and back, and the verifier
//! reads it, whole and tampered with.
//!
//! The four tamper tests are the front's canaries in the other direction:
//! each is red unless its check finds the tampering, and each check has a
//! cargo feature that turns it off (`canary-no-gap-check`,
//! `canary-no-chain-check`, `canary-no-order-check`,
//! `canary-no-anchor-check`), under which its test must fail.

#![cfg(test)]

mod tool;

use azos_seclog::chain::{extend, Sealer};
use azos_seclog::text::{self, Parsed};
use azos_seclog::verify::{Finding, Summary, Verifier};
use azos_seclog::{kind, Anchor, Backend, Class, Envelope, Event, Hash, Loss, Seal, PAYLOAD};

#[derive(Clone)]
pub(crate) struct Rec {
    pub(crate) env: Envelope,
    pub(crate) payload: [u8; PAYLOAD],
}

/// One boot of the simulated kernel: a ring, its producers and the sealer.
pub(crate) struct Boot {
    pub(crate) recs: Vec<Rec>,
    sealer: Sealer,
    hardware: bool,
    pub(crate) tpm: Hash,
}

impl Boot {
    pub(crate) fn new(backend: Backend, tpm: Hash) -> Boot {
        let hardware = backend == Backend::TpmNv;
        let mut b = Boot { recs: Vec::new(), sealer: Sealer::new(backend, tpm), hardware, tpm };
        // Records written before the sealer starts (the boot's own denials).
        b.event(Class::CapDenial, 1);
        b.event(Class::ImageLoad, 2);
        let a = Anchor { backend, hardware, value: tpm };
        b.publish(kind::ANCHOR, &a.encode());
        b
    }

    fn publish(&mut self, kind: u16, p: &[u8]) -> u64 {
        let seq = self.recs.len() as u64;
        let mut payload = [0u8; PAYLOAD];
        payload[..p.len()].copy_from_slice(p);
        let env = Envelope { seq, ts: 1000 + seq * 7, clock: 0, source: 4, kind, len: p.len() as u16, cpu: (seq % 4) as u8, flags: 0 };
        self.recs.push(Rec { env, payload });
        seq
    }

    pub(crate) fn event(&mut self, class: Class, subject: u32) {
        let e = Event { id: subject as u64 + 100, subject, rule: 4, verdict: 3, class, n: [1, 2, 3], image_hash_prefix: 0xabcd, topology_row_id: 0 };
        self.publish(kind::EVENT, &e.encode());
    }

    /// The kernel's pass: fold what the ring holds, then seal.
    pub(crate) fn seal(&mut self) {
        let from = self.sealer.next() as usize;
        for r in self.recs[from..].to_vec() {
            self.sealer.fold(&r.env, &r.payload);
        }
        let s = self.sealer.seal(self.hardware);
        if self.hardware {
            self.tpm = extend(&self.tpm, &s.head);
        }
        self.publish(kind::SEAL, &s.encode());
    }

    /// The kernel's pass when the TPM refuses the extend: the seal is
    /// advisory. `taken`: the TPM did extend, and only its answer was lost.
    fn seal_refused(&mut self, taken: bool) {
        let from = self.sealer.next() as usize;
        for r in self.recs[from..].to_vec() {
            self.sealer.fold(&r.env, &r.payload);
        }
        let s = self.sealer.seal(false);
        if taken {
            self.tpm = extend(&self.tpm, &s.head);
        }
        self.publish(kind::SEAL, &s.encode());
    }

    /// The ring lapped the sealer: `n` records it never folds, and the loss
    /// it declares.
    fn lapped(&mut self, n: usize) -> (u64, u64) {
        let from = self.sealer.next() as usize;
        for r in self.recs[from..].to_vec() {
            self.sealer.fold(&r.env, &r.payload);
        }
        let first = self.recs.len() as u64;
        for i in 0..n {
            self.event(Class::Egress, 500 + i as u32);
        }
        let loss = self.sealer.skip_to(self.recs.len() as u64).unwrap();
        assert_eq!((loss.first, loss.count), (first, n as u64));
        self.publish(kind::LOSS, &loss.encode());
        (first, n as u64)
    }

    pub(crate) fn lines(&self) -> Vec<Vec<u8>> {
        self.recs.iter().map(|r| line(r)).collect()
    }
}

fn line(r: &Rec) -> Vec<u8> {
    let mut out = [0u8; text::MSG_MAX];
    let n = text::render(&r.env, &r.payload, &mut out);
    out[..n].to_vec()
}

pub(crate) fn seam() -> Vec<u8> {
    let mut out = [0u8; 16];
    let n = text::render_seam(&mut out);
    out[..n].to_vec()
}

/// A boot with `rounds` rounds of three events and a seal.
pub(crate) fn tpm_boot(tpm: Hash, rounds: usize) -> Boot {
    let mut b = Boot::new(Backend::TpmNv, tpm);
    for r in 0..rounds {
        b.event(Class::Microphone, 10 + r as u32);
        b.event(Class::Camera, 20 + r as u32);
        b.event(Class::Egress, 30 + r as u32);
        b.seal();
    }
    b
}

fn verify(lines: &[Vec<u8>]) -> (Vec<Finding>, Summary) {
    let mut v = Verifier::new();
    let mut found = Vec::new();
    for l in lines {
        match text::parse(l).expect("every line parses") {
            Parsed::Seam => v.seam(),
            Parsed::Record { env, payload } => v.record(&env, &payload, &mut |f| found.push(f)),
        }
    }
    let s = v.finish(&mut |f| found.push(f));
    (found, s)
}

fn evidence(f: &[Finding]) -> Vec<Finding> {
    f.iter().copied().filter(Finding::is_evidence).collect()
}

/// Two boots on a TPM, the second's anchor the first's last seal: no
/// evidence, every seal checked, and the export ends at the TPM's value.
fn two_boots() -> (Boot, Boot, Vec<Vec<u8>>) {
    let b1 = tpm_boot([0; 32], 3);
    let b2 = tpm_boot(b1.tpm, 2);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.lines());
    (b1, b2, lines)
}

#[test]
fn a_whole_log_verifies_and_reaches_the_tpm_value() {
    let (_, b2, lines) = two_boots();
    let (found, s) = verify(&lines);
    assert_eq!(evidence(&found), vec![]);
    assert_eq!(found, vec![], "no finding at all: every record is sealed and hardware-held");
    assert_eq!((s.boots, s.seals, s.seals_verified, s.seals_hardware), (2, 5, 5, 5));
    assert_eq!(s.last_anchor, Some(b2.tpm));
    assert_eq!(s.backend, Some(Backend::TpmNv));
}

#[test]
fn a_dropped_record_is_an_undeclared_gap() {
    let (_, _, mut lines) = two_boots();
    // Boot 1: 2 early events and the anchor (0..2), then mic, cam, egress at
    // 3..5 and the seal at 6. Drop the camera record.
    lines.remove(4);
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::Gap { boot: 1, first: 4, count: 1, declared: false }), "{found:?}");
    assert!(found.contains(&Finding::Unverifiable { boot: 1, seq: 6 }), "{found:?}");
}

#[test]
fn a_rewritten_record_breaks_the_next_seal() {
    let (_, _, mut lines) = two_boots();
    // The microphone record at 3: its subject, one hex digit of the payload.
    let s = String::from_utf8(lines[3].clone()).unwrap();
    let mut f: Vec<&str> = s.split(' ').collect();
    let hex = f[7].replacen("0a", "0b", 1);
    assert_ne!(hex, f[7]);
    f[7] = &hex;
    lines[3] = f.join(" ").into_bytes();
    let (found, s) = verify(&lines);
    assert!(found.contains(&Finding::Rewrite { boot: 1, seq: 6 }), "{found:?}");
    // The chain resynchronises on the seal: the later seals check out.
    assert_eq!(s.seals_verified, s.seals - 1);
}

#[test]
fn a_reordered_pair_is_reported() {
    let (_, _, mut lines) = two_boots();
    lines.swap(3, 4);
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::Reorder { boot: 1, seq: 3, after: 4 }), "{found:?}");
}

/// The attacker rewrites a record and recomputes every head and anchor of
/// the boot, so the boot is consistent with itself; the next boot's anchor,
/// which the TPM gave it, is not the forged boot's last seal.
#[test]
fn a_forged_head_breaks_the_link_to_the_next_boot() {
    let b1 = tpm_boot([0; 32], 3);
    let b2 = tpm_boot(b1.tpm, 2);
    let mut forged = Boot::new(Backend::TpmNv, [0; 32]);
    for r in 0..3 {
        forged.event(Class::Microphone, if r == 1 { 99 } else { 10 + r as u32 });
        forged.event(Class::Camera, 20 + r as u32);
        forged.event(Class::Egress, 30 + r as u32);
        forged.seal();
    }
    let mut lines = forged.lines();
    lines.push(seam());
    lines.extend(b2.lines());
    let (found, s) = verify(&lines);
    assert!(found.contains(&Finding::LinkBroken { boot: 2 }), "{found:?}");
    assert_eq!(s.seals_verified, s.seals, "each boot is consistent with itself");
}

/// The same forgery with no later boot in the export: consistent offline,
/// and only the TPM's live value refutes it.
#[test]
fn a_forged_last_boot_differs_from_the_live_tpm_value() {
    let real = tpm_boot([0; 32], 2);
    let mut forged = Boot::new(Backend::TpmNv, [0; 32]);
    forged.event(Class::Microphone, 77);
    forged.seal();
    let (found, s) = verify(&forged.lines());
    assert_eq!(evidence(&found), vec![]);
    assert_ne!(s.last_anchor, Some(real.tpm));
    let (_, s) = verify(&real.lines());
    assert_eq!(s.last_anchor, Some(real.tpm));
}

/// A seal whose head alone was changed: its anchor no longer follows.
#[test]
fn a_seal_with_a_changed_head_is_caught_twice() {
    let b = tpm_boot([0; 32], 2);
    let mut lines = b.lines();
    let mut r = b.recs[6].clone();
    let mut s = Seal::decode(&r.payload).unwrap();
    s.head[0] ^= 1;
    r.payload[..Seal::LEN].copy_from_slice(&s.encode());
    lines[6] = line(&r);
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::Rewrite { boot: 1, seq: 6 }), "{found:?}");
    assert!(found.contains(&Finding::AnchorMismatch { boot: 1, seq: 6 }), "{found:?}");
}

#[test]
fn a_loss_the_kernel_declares_is_not_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    let (first, n) = b.lapped(3);
    b.event(Class::Update, 40);
    b.seal();
    let lines: Vec<_> = b.recs.iter().filter(|r| r.env.seq < first || r.env.seq >= first + n).map(line).collect();
    let (found, s) = verify(&lines);
    assert_eq!(found, vec![Finding::Gap { boot: 1, first, count: n, declared: true }]);
    assert_eq!(s.seals_verified, s.seals);
}

#[test]
fn records_the_sealer_folded_but_the_export_lacks_are_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    b.event(Class::Usb, 41);
    b.event(Class::Login, 42);
    b.seal();
    let mut lines = b.lines();
    lines.remove(8);
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::Gap { boot: 1, first: 8, count: 1, declared: false }), "{found:?}");
}

#[test]
fn a_rotated_start_is_incomplete_not_evidence() {
    let b = tpm_boot([0; 32], 3);
    let lines = b.lines()[7..].to_vec();
    let (found, s) = verify(&lines);
    assert_eq!(evidence(&found), vec![]);
    assert!(found.contains(&Finding::Truncated { boot: 1, first: 7 }));
    // The first seal is adopted unchecked; the next ones are checked.
    assert_eq!((s.seals, s.seals_verified), (2, 1));
}

#[test]
fn forward_only_seals_are_advisory() {
    let mut b = Boot::new(Backend::Forward, [0; 32]);
    b.event(Class::Microphone, 1);
    b.seal();
    let (found, s) = verify(&b.lines());
    assert_eq!(found, vec![Finding::Advisory { boot: 1 }]);
    assert_eq!((s.seals_verified, s.seals_hardware, s.backend), (1, 0, Some(Backend::Forward)));
    assert_eq!(s.last_anchor, None, "no hardware holds a forward-only anchor");
}

/// The TPM refuses an extend: the kernel marks that seal and the later ones
/// advisory and stops extending, so the next boot reads the last seal the
/// TPM took. That is a declared fallback, not a rewrite: no evidence, the
/// boot is advisory, and the export ends at the value the TPM holds.
#[test]
fn a_seal_the_tpm_refused_links_the_next_boot_to_the_last_one_it_took() {
    let mut b1 = tpm_boot([0; 32], 2);
    let held = b1.tpm;
    b1.event(Class::Microphone, 50);
    b1.seal_refused(false);
    b1.event(Class::Camera, 51);
    b1.seal_refused(false);
    assert_eq!(b1.tpm, held);
    let b2 = tpm_boot(b1.tpm, 1);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.lines());
    let (found, s) = verify(&lines);
    assert_eq!(found, vec![Finding::Advisory { boot: 1 }]);
    assert_eq!((s.seals, s.seals_verified, s.seals_hardware), (5, 5, 3));
    assert_eq!(s.last_anchor, Some(b2.tpm));
    // The refused boot is the last one exported: the TPM holds the last seal
    // it took, not the advisory ones after it.
    let (found, s) = verify(&b1.lines());
    assert_eq!(evidence(&found), vec![]);
    assert_eq!(s.last_anchor, Some(held));
}

/// A refused extend the TPM did take (its answer was lost): the next boot
/// reads the first advisory seal's anchor, which links as well.
#[test]
fn a_refused_seal_the_tpm_did_take_links_too() {
    let mut b1 = tpm_boot([0; 32], 1);
    b1.event(Class::Update, 60);
    b1.seal_refused(true);
    b1.event(Class::Update, 61);
    b1.seal_refused(false);
    let b2 = tpm_boot(b1.tpm, 1);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.lines());
    let (found, _) = verify(&lines);
    assert_eq!(found, vec![Finding::Advisory { boot: 1 }]);
}

/// A forward-only boot between two TPM boots: the second TPM boot links to
/// the first one's last seal, over the boot no hardware held.
#[test]
fn a_tpm_boot_links_over_a_forward_only_boot() {
    let b1 = tpm_boot([0; 32], 2);
    let mut mid = Boot::new(Backend::Forward, [0; 32]);
    mid.event(Class::Login, 3);
    mid.seal();
    let b3 = tpm_boot(b1.tpm, 1);
    let mut lines = b1.lines();
    for b in [&mid, &b3] {
        lines.push(seam());
        lines.extend(b.lines());
    }
    let (found, s) = verify(&lines);
    assert_eq!(found, vec![Finding::Advisory { boot: 2 }]);
    assert_eq!(s.last_anchor, Some(b3.tpm));
    // The same three boots with the second TPM boot anchored elsewhere.
    let b3 = tpm_boot([9; 32], 1);
    let mut lines = b1.lines();
    for b in [&mid, &b3] {
        lines.push(seam());
        lines.extend(b.lines());
    }
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::LinkBroken { boot: 3 }), "{found:?}");
}

#[test]
fn records_after_the_last_seal_are_unsealed() {
    let mut b = tpm_boot([0; 32], 1);
    b.event(Class::Microphone, 5);
    let (found, _) = verify(&b.lines());
    assert_eq!(found, vec![Finding::Unsealed { boot: 1, count: 1 }]);
}

#[test]
fn a_restart_of_logd_inside_a_boot_is_not_a_new_boot() {
    let b = tpm_boot([0; 32], 2);
    let mut lines = b.lines();
    lines.insert(5, seam());
    let (found, s) = verify(&lines);
    assert_eq!((found, s.boots), (vec![], 1));
}

#[test]
fn the_sealer_folds_each_record_once_and_seals_skip_the_seal_count() {
    let mut s = Sealer::new(Backend::TpmNv, [7; 32]);
    let env = Envelope { seq: 0, kind: kind::EVENT, len: 4, ..Default::default() };
    assert!(s.fold(&env, &[1, 2, 3, 4]));
    assert!(!s.fold(&env, &[1, 2, 3, 4]), "a record before next is not folded again");
    assert_eq!(s.unsealed(), 1);
    let seal = s.seal(true);
    assert_eq!((seal.through, seal.count, seal.anchor), (1, 1, extend(&[7; 32], &seal.head)));
    let env = Envelope { seq: 1, kind: kind::SEAL, len: Seal::LEN as u16, ..Default::default() };
    s.fold(&env, &seal.encode());
    assert_eq!(s.unsealed(), 0, "folding its own seal does not make another one due");
    assert_eq!(s.skip_to(1), None);
    assert_eq!(s.skip_to(5), Some(Loss { first: 2, count: 3 }));
}

#[test]
fn lines_round_trip_and_bad_lines_are_refused() {
    let b = tpm_boot([0; 32], 1);
    for r in &b.recs {
        let Some(Parsed::Record { env, payload }) = text::parse(&line(r)) else { panic!() };
        assert_eq!((env.seq, env.ts, env.kind, env.len, env.cpu, payload), (r.env.seq, r.env.ts, r.env.kind, r.env.len, r.env.cpu, r.payload));
    }
    assert_eq!(text::parse(&seam()), Some(Parsed::Seam));
    for bad in ["v2 1 2 0 1 0 0 00", "v1 1 2 0 1 0 0 0", "v1 1 2 0 1 0 0 0g", "v1 1 2 300 1 0 0 00", "v1 x 2 0 1 0 0 00", "v1 1 2 0 1 0"] {
        assert_eq!(text::parse(bad.as_bytes()), None, "{bad}");
    }
    let mut r = b.recs[0].clone();
    r.env.len = 0;
    assert!(matches!(text::parse(&line(&r)), Some(Parsed::Record { env, .. }) if env.len == 0));
}

#[test]
fn every_class_and_backend_round_trips_its_number() {
    for v in 0..=255u8 {
        if let Some(c) = Class::from_u8(v) {
            assert_eq!(c as u8, v);
        }
        if let Some(b) = Backend::from_u8(v) {
            assert_eq!(b as u8, v);
        }
    }
    assert_eq!(Class::from_u8(3), None, "screen capture has no producer");
    assert_eq!(Class::from_u8(8), None, "debug attach has no producer");
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Format version 1, byte for byte: the payloads, the canonical bytes, the
/// genesis head, one fold, one extend and the line. The vectors were computed
/// apart from this crate (Python's struct and hashlib); a change to any field
/// is a new format version, never an edit of these.
#[test]
fn format_v1_is_frozen() {
    let e = Event {
        id: 0x0102_0304_0506_0708,
        subject: 0x1122_3344,
        rule: 59,
        verdict: 1,
        class: Class::Microphone,
        n: [1, 2, 3],
        image_hash_prefix: 0xab_cdef,
        topology_row_id: 7,
    };
    let ev = "0807060504030201443322113b010100010000000000000002000000000000000300000000000000efcdab000000000007000000";
    assert_eq!(e.encode().to_vec(), unhex(ev));
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = i as u8;
    }
    let a = Anchor { backend: Backend::TpmNv, hardware: true, value: v };
    assert_eq!(a.encode().to_vec(), unhex("0201000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    let seal = Seal { backend: Backend::Forward, hardware: false, count: 3, through: 9, head: [0xaa; 32], anchor: [0xbb; 32] };
    let mut want = unhex("01000000030000000900000000000000");
    want.extend([0xaa; 32]);
    want.extend([0xbb; 32]);
    assert_eq!(seal.encode().to_vec(), want);
    assert_eq!(Loss { first: 5, count: 2 }.encode().to_vec(), unhex("05000000000000000200000000000000"));

    let env = Envelope { seq: 4, ts: 1000, clock: 0, source: 4, kind: kind::EVENT, len: Event::LEN as u16, cpu: 2, flags: 1 };
    let mut payload = [0u8; PAYLOAD];
    payload[..Event::LEN].copy_from_slice(&e.encode());
    let mut c = [0u8; azos_seclog::CANON_MAX];
    let n = azos_seclog::canon(&env, &payload, &mut c);
    assert_eq!(c[..n].to_vec(), unhex(&format!("010400000000000000e80300000000000000010002013400{ev}")));
    let genesis = azos_seclog::chain::genesis();
    assert_eq!(genesis.to_vec(), unhex("17281353216267c1bf28c9bfd1a21646dca81d39157ebc2bb413333552044d2d"));
    let head = azos_seclog::chain::fold(&genesis, &env, &payload);
    assert_eq!(head.to_vec(), unhex("1c51514985cf0b56db5b046ac02e2b019a0815a2c50698d8f488bf60f40385b6"));
    assert_eq!(extend(&[0; 32], &head).to_vec(), unhex("3ca45c9bd392f242e67f216dbd9f2224c9e0ca6871ed3e024e12df0a4409d6e5"));
    let r = Rec { env, payload };
    assert_eq!(String::from_utf8(line(&r)).unwrap(), format!("v1 4 1000 0 1 2 1 {ev} event microphone rule=59 verdict=1"));
}
