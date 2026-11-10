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

mod pass;
mod tool;

use azos_seclog::chain::{extend, Sealer};
use azos_seclog::text::{self, Parsed};
use azos_seclog::verify::{By, Finding, Summary, Verifier};
use azos_seclog::{kind, Anchor, Backend, Class, Envelope, Event, Hash, Loss, Reason, Seal, CLASSES, FLAG_HARDWARE, PAYLOAD};

#[derive(Clone)]
pub(crate) struct Rec {
    pub(crate) env: Envelope,
    pub(crate) payload: [u8; PAYLOAD],
}

thread_local! {
    /// The simulated TPM's counter after each anchor value it held, so a boot
    /// started from an anchor goes on from its counter.
    static COUNTERS: std::cell::RefCell<std::collections::HashMap<Hash, u64>> = Default::default();
    static NONCE: std::cell::Cell<u64> = const { std::cell::Cell::new(0x5eed) };
}

fn counter_at(anchor: &Hash) -> u64 {
    COUNTERS.with(|c| c.borrow().get(anchor).copied().unwrap_or(0))
}

fn note_counter(anchor: Hash, counter: u64) {
    COUNTERS.with(|c| c.borrow_mut().insert(anchor, counter));
}

fn next_nonce() -> u64 {
    NONCE.with(|n| {
        n.set(n.get().wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407));
        n.get()
    })
}

/// One boot of the simulated kernel: a ring, its producers and the sealer.
pub(crate) struct Boot {
    pub(crate) recs: Vec<Rec>,
    sealer: Sealer,
    hardware: bool,
    failed: bool,
    pub(crate) tpm: Hash,
    pub(crate) counter: u64,
}

impl Boot {
    pub(crate) fn new(backend: Backend, tpm: Hash) -> Boot {
        let hardware = backend == Backend::TpmNv;
        let nonce = next_nonce();
        let counter = if hardware { counter_at(&tpm) } else { 0 };
        let mut b = Boot { recs: Vec::new(), sealer: Sealer::new(backend, tpm, nonce), hardware, failed: false, tpm, counter };
        // Records written before the sealer starts (the boot's own denials).
        b.event(Class::CapDenial, 1);
        b.event(Class::ImageLoad, 2);
        let a = Anchor {
            backend,
            flags: if hardware { FLAG_HARDWARE } else { 0 },
            reason: if hardware { Reason::Hardware } else { Reason::Configured },
            nonce,
            counter,
            value: tpm,
        };
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

    fn fold_all(&mut self) {
        let from = self.sealer.next() as usize;
        for r in self.recs[from..].to_vec() {
            self.sealer.fold(&r.env, &r.payload);
        }
    }

    /// The kernel's pass: fold what the ring holds, then seal (on a TPM:
    /// increment the counter, extend the anchor, read it back).
    pub(crate) fn seal(&mut self) {
        self.fold_all();
        let s = if self.hardware {
            self.counter += 1;
            self.tpm = extend(&self.tpm, &self.sealer.data(self.counter));
            note_counter(self.tpm, self.counter);
            self.sealer.seal(true, self.counter, Some(self.tpm), 0)
        } else {
            self.sealer.seal(false, 0, None, 0)
        };
        self.publish(kind::SEAL, &s.encode());
    }

    /// The kernel's pass when the TPM refuses the extend: the seal is
    /// advisory, and so is every later one of the boot, which takes no
    /// counter. `taken`: the TPM did extend, and only its answer was lost.
    fn seal_refused(&mut self, taken: bool) {
        self.fold_all();
        let counter = if self.failed {
            0
        } else {
            self.counter += 1;
            self.counter
        };
        if taken && !self.failed {
            self.tpm = extend(&self.tpm, &self.sealer.data(counter));
        }
        note_counter(self.tpm, self.counter);
        self.failed = true;
        let s = self.sealer.seal(false, counter, None, 0);
        self.publish(kind::SEAL, &s.encode());
    }

    /// The ring lapped the sealer: `n` records it never folds, and the loss
    /// it declares.
    fn lapped(&mut self, n: usize) -> (u64, u64) {
        self.fold_all();
        let first = self.recs.len() as u64;
        for i in 0..n {
            self.event(Class::Egress, 500 + i as u32);
        }
        let (f, count) = self.sealer.skip_to(self.recs.len() as u64).unwrap();
        assert_eq!((f, count), (first, n as u64));
        let mut by_class = [0u32; CLASSES];
        by_class[Class::Egress as usize] = n as u32;
        self.publish(kind::LOSS, &Loss { first, count, by_class, sink_alive: false }.encode());
        (first, n as u64)
    }

    /// The kernel declares that the sink lost `count` records from `first`:
    /// the record, and the count the next seals carry.
    fn sink_loss(&mut self, first: u64, count: u64) {
        self.sink_loss_of(first, count, 0, false);
    }

    /// The same of records of class number `class` (0: not known), declared with the sink running or not.
    fn sink_loss_of(&mut self, first: u64, count: u64, class: usize, sink_alive: bool) {
        let mut by_class = [0u32; CLASSES];
        by_class[class] = count as u32;
        self.publish(kind::SINK_LOSS, &Loss { first, count, by_class, sink_alive }.encode());
        self.sealer.sink_lost(first, count, &by_class, sink_alive);
    }

    /// A `sink-loss` record only: what whoever writes the volume can add.
    fn forged_sink_loss(&mut self, first: u64, count: u64) {
        let mut by_class = [0u32; CLASSES];
        by_class[0] = count as u32;
        self.publish(kind::SINK_LOSS, &Loss { first, count, by_class, sink_alive: false }.encode());
    }

    /// Something else extends the TPM's index.
    fn foreign_extend(&mut self) {
        self.tpm = extend(&self.tpm, &[0x66; 32]);
    }

    pub(crate) fn lines(&self) -> Vec<Vec<u8>> {
        self.recs.iter().map(|r| line(r)).collect()
    }
}

pub(crate) fn line(r: &Rec) -> Vec<u8> {
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
            Parsed::Unsupported(n) => panic!("format v{n}"),
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
    assert!(found.contains(&Finding::Gap { boot: 1, first: 4, count: 1, by: By::Nobody }), "{found:?}");
    assert!(found.contains(&Finding::Unverifiable { boot: 1, seq: 6, declared: false }), "{found:?}");
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
    assert_eq!(
        found,
        vec![
            Finding::ClassLost { boot: 1, class: Class::Egress as u8, count: n as u32, sink: false, claimed: false },
            Finding::Gap { boot: 1, first, count: n, by: By::Sealer }
        ]
    );
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
    assert!(found.contains(&Finding::Gap { boot: 1, first: 8, count: 1, by: By::Nobody }), "{found:?}");
}

#[test]
fn a_rotated_start_is_incomplete_not_evidence() {
    let b = tpm_boot([0; 32], 3);
    let lines = b.lines()[7..].to_vec();
    let (found, s) = verify(&lines);
    assert_eq!(evidence(&found), vec![]);
    assert!(found.contains(&Finding::Truncated { boot: 1, first: 7, explained: true }));
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
    assert_eq!(found, vec![Finding::Downgrade { boot: 2, reason: Reason::Configured }, Finding::Advisory { boot: 2 }]);
    assert!(evidence(&found).is_empty());
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

/// A fresh logd restart inside a boot reads the ring again from its oldest
/// record: what it writes again is the same boot, not a new one.
#[test]
fn a_fresh_logd_restart_rereads_the_same_boot() {
    let b = tpm_boot([0; 32], 2);
    let mut lines = b.lines();
    lines.push(seam());
    lines.extend(b.lines());
    let (found, s) = verify(&lines);
    assert_eq!((found, s.boots), (vec![], 1));
}

/// A re-read that ends where another boot begins: the next boot is still one.
#[test]
fn a_reread_then_a_new_boot() {
    let b1 = tpm_boot([0; 32], 2);
    let b2 = tpm_boot(b1.tpm, 1);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b1.lines()[..4].to_vec());
    lines.push(seam());
    lines.extend(b2.lines());
    let (found, s) = verify(&lines);
    assert_eq!((evidence(&found), s.boots), (vec![], 2), "{found:?}");
}

/// A boot whose anchor record was removed from the middle of the export.
#[test]
fn a_boot_without_its_anchor_record_is_evidence() {
    let (b1, _, mut lines) = two_boots();
    // b2 starts after b1's lines and the seam: its anchor is its record 2.
    lines.remove(b1.recs.len() + 1 + 2);
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::AnchorMissing { boot: 2, explained: false }), "{found:?}");
}

/// The kernel declared that logd lost the first records of a boot (the ring
/// lapped before logd read it): a truncated boot inside the export, honest.
#[test]
fn a_boot_start_the_kernel_declares_lost_by_the_sink_is_not_evidence() {
    let b1 = tpm_boot([0; 32], 2);
    let mut b2 = tpm_boot(b1.tpm, 1);
    b2.sink_loss(0, 4);
    b2.event(Class::Login, 3);
    b2.seal();
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.lines()[4..].to_vec());
    let (found, _) = verify(&lines);
    assert_eq!(evidence(&found), vec![], "{found:?}");
    assert!(found.contains(&Finding::Truncated { boot: 2, first: 4, explained: true }), "{found:?}");
}

/// The TPM took a seal and the boot ended before logd wrote its record: the
/// next boot's anchor is that seal's, which the records before it give.
#[test]
fn a_seal_a_crash_lost_still_links_the_next_boot() {
    let mut b1 = tpm_boot([0; 32], 2);
    b1.event(Class::Update, 5);
    let before = b1.recs.len();
    b1.seal();
    let b2 = tpm_boot(b1.tpm, 1);
    let mut lines = b1.lines()[..before].to_vec();
    lines.push(seam());
    lines.extend(b2.lines());
    let (found, _) = verify(&lines);
    assert_eq!(evidence(&found), vec![], "{found:?}");
    assert!(found.contains(&Finding::CrashSeal { boot: 1, through: before as u64 }), "{found:?}");
}

/// The anchor index was reset and replayed to the value after a boot's
/// second seal, and the export cut there: the counter the TPM kept going
/// says two seals are missing.
#[test]
fn a_replayed_anchor_leaves_a_counter_gap() {
    let b1 = tpm_boot([0; 32], 4);
    let seal2 = b1.recs.iter().filter(|r| r.env.kind == kind::SEAL).nth(1).unwrap();
    let s2 = Seal::decode(&seal2.payload).unwrap();
    note_counter(s2.anchor, b1.counter);
    let b2 = tpm_boot(s2.anchor, 1);
    let mut lines = b1.lines()[..=seal2.env.seq as usize].to_vec();
    lines.push(seam());
    lines.extend(b2.lines());
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::CounterGap { boot: 2, seq: u64::MAX }), "{found:?}");
}

/// Something else extended the index between two seals: the seal says the
/// TPM held a value it did not extend.
#[test]
fn a_foreign_extend_is_reported_as_diverged() {
    let mut b = tpm_boot([0; 32], 1);
    b.event(Class::Camera, 4);
    b.foreign_extend();
    b.seal();
    let (found, _) = verify(&b.lines());
    let seq = b.recs.len() as u64 - 1;
    assert!(found.contains(&Finding::Diverged { boot: 1, seq }), "{found:?}");
}

/// A forward-only seal that claims the hardware held it.
#[test]
fn a_shape_the_kernel_never_writes_is_malformed() {
    let mut b = Boot::new(Backend::Forward, [0; 32]);
    b.event(Class::Microphone, 1);
    b.seal();
    let mut r = b.recs.last().unwrap().clone();
    let mut s = Seal::decode(&r.payload).unwrap();
    s.flags |= FLAG_HARDWARE;
    r.payload[..Seal::LEN].copy_from_slice(&s.encode());
    let mut lines = b.lines();
    *lines.last_mut().unwrap() = line(&r);
    let (found, _) = verify(&lines);
    assert!(found.contains(&Finding::Malformed { boot: 1, seq: r.env.seq }), "{found:?}");
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
    let mut s = Sealer::new(Backend::TpmNv, [7; 32], 9);
    let env = Envelope { seq: 0, kind: kind::EVENT, len: 4, ..Default::default() };
    assert!(s.fold(&env, &[1, 2, 3, 4]));
    assert!(!s.fold(&env, &[1, 2, 3, 4]), "a record before next is not folded again");
    assert_eq!(s.unsealed(), 1);
    let data = s.data(41);
    let seal = s.seal(true, 41, None, 0);
    assert_eq!((seal.through, seal.count, seal.counter, seal.anchor), (1, 1, 41, extend(&[7; 32], &data)));
    assert_eq!((seal.prev, seal.boot_anchor, seal.nonce, seal.flags), ([7; 32], [7; 32], 9, FLAG_HARDWARE));
    assert_eq!(azos_seclog::chain::data_of(&seal), data);
    let env = Envelope { seq: 1, kind: kind::SEAL, len: Seal::LEN as u16, ..Default::default() };
    s.fold(&env, &seal.encode());
    assert_eq!(s.unsealed(), 0, "folding its own seal does not make another one due");
    assert_eq!(s.skip_to(1), None);
    assert_eq!(s.skip_to(5), Some((2, 3)));
    // A value read back that the extend does not give is the seal's anchor,
    // and the seal says so.
    let held = s.seal(true, 42, Some([1; 32]), 0);
    assert_eq!((held.anchor, held.flags), ([1; 32], FLAG_HARDWARE | azos_seclog::FLAG_DIVERGED));
    assert_eq!(s.anchor(), [1; 32]);
}

#[test]
fn lines_round_trip_and_bad_lines_are_refused() {
    let b = tpm_boot([0; 32], 1);
    for r in &b.recs {
        let Some(Parsed::Record { env, payload }) = text::parse(&line(r)) else { panic!() };
        assert_eq!((env.seq, env.ts, env.kind, env.len, env.cpu, payload), (r.env.seq, r.env.ts, r.env.kind, r.env.len, r.env.cpu, r.payload));
    }
    assert_eq!(text::parse(&seam()), Some(Parsed::Seam));
    assert_eq!(text::parse(b"v1 1 2 0 1 0 0 00"), Some(Parsed::Unsupported(1)), "another version is named, not read");
    assert_eq!(text::parse(b"v4 seam"), Some(Parsed::Unsupported(4)));
    for bad in ["v5 1 2 0 1 0 0 0", "v5 1 2 0 1 0 0 0g", "v5 1 2 300 1 0 0 00", "v5 x 2 0 1 0 0 00", "v5 1 2 0 1 0", "vx 1 2 0 1 0 0 00"] {
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

/// Format version 5, byte for byte: the payloads, the canonical bytes, the
/// genesis head, one fold, one seal's data and extend, and the line. The
/// genesis and the fold were checked apart from this crate (Python's hashlib);
/// a change to any field is a new format version, never an edit of these.
#[test]
fn format_v5_is_frozen() {
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
    let a = Anchor { backend: Backend::TpmNv, flags: FLAG_HARDWARE, reason: Reason::Hardware, nonce: 0x1122_3344_5566_7788, counter: 7, value: v };
    assert_eq!(a.encode().to_vec(), unhex("020100000000000088776655443322110700000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    let seal = Seal {
        backend: Backend::TpmNv,
        flags: FLAG_HARDWARE,
        count: 3,
        through: 9,
        counter: 8,
        nonce: 0x99,
        head: [0xaa; 32],
        anchor: [0xbb; 32],
        prev: [0xcc; 32],
        boot_anchor: [0xdd; 32],
        sink_lost: 11,
        sink_start: 4,
        sink_digest: [0xee; 32],
    };
    assert_eq!(seal.encode().to_vec(), unhex("0201000003000000090000000000000008000000000000009900000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd0b000000000000000400000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
    let mut by_class = [0u32; CLASSES];
    by_class[Class::Egress as usize] = 2;
    assert_eq!(Loss { first: 5, count: 2, by_class, sink_alive: true }.encode().to_vec(), unhex("050000000000000002000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000001"));
    let mut by_class = [0u32; CLASSES];
    by_class[Class::CapDenial as usize] = 3;
    let subjects = [(42, 7), (0, 0), (0, 0), (0, 0)];
    assert_eq!(azos_seclog::Held { by_class, subjects }.encode().to_vec(), unhex("000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000002a00000007000000000000000000000000000000000000000000000000000000"));

    let env = Envelope { seq: 4, ts: 1000, clock: 0, source: 4, kind: kind::EVENT, len: Event::LEN as u16, cpu: 2, flags: 1 };
    let mut payload = [0u8; PAYLOAD];
    payload[..Event::LEN].copy_from_slice(&e.encode());
    let mut c = [0u8; azos_seclog::CANON_MAX];
    let n = azos_seclog::canon(&env, &payload, &mut c);
    assert_eq!(c[..n].to_vec(), unhex("050400000000000000e803000000000000000100020134000807060504030201443322113b010100010000000000000002000000000000000300000000000000efcdab000000000007000000"));
    let genesis = azos_seclog::chain::genesis(&[0xdd; 32], 0x99);
    assert_eq!(genesis.to_vec(), unhex("352792a7d0034b6d73c0dc343ff556bbaf55953a51db678f269ab51232cdea62"));
    let head = azos_seclog::chain::fold(&genesis, &env, &payload);
    assert_eq!(head.to_vec(), unhex("598124c76a4868992c301beb0efb27e7fb26e737ee4dd1496f0248c1b6e63312"));
    let n = azos_seclog::chain::SealNumbers { count: 1, counter: 8, through: 5, sink_lost: 0, sink_start: 0, sink_digest: [0; 32] };
    let data = azos_seclog::chain::seal_data(&[0xdd; 32], 0x99, &n, &head);
    assert_eq!(data.to_vec(), unhex("354292f35cecc893a1a7cd235cd16fbbfff0d540bff78f7c4e1bc7a7bd1c9993"));
    assert_eq!(extend(&[0xdd; 32], &data).to_vec(), unhex("01ae8c188946f10866a6f2dec5bf5139519e5134eb0f147815cb63fb76c212eb"));
    let mut by_class = [0u32; CLASSES];
    by_class[Class::Egress as usize] = 2;
    assert_eq!(azos_seclog::chain::declaration(&[0; 32], 5, 2, &by_class, false).to_vec(), unhex("b255000223c2f9eb1e052266af913a7a7d065696b9048038a2458cf267a8f7d0"));
    let r = Rec { env, payload };
    assert_eq!(String::from_utf8(line(&r)).unwrap(), format!("v5 4 1000 0 1 2 1 {ev} event microphone rule=59 verdict=1"));
}

// Proofs of the review of the sealed security log: each asserts the right
// behaviour.
#[test]
fn review_p1a_a_deleted_boot_is_evidence() {
    let b1 = tpm_boot([0; 32], 3);
    let b2 = tpm_boot(b1.tpm, 2);
    let b3 = tpm_boot(b2.tpm, 2);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b3.lines()[3..].to_vec());
    let (found, s) = verify(&lines);
    assert_eq!(s.last_anchor, Some(b3.tpm), "the live TPM check passes");
    assert!(!evidence(&found).is_empty(), "boot 2 was deleted and nothing is evidence: {found:?}");
}

#[test]
fn review_p1b_a_forged_refused_seal_is_evidence() {
    let b1 = tpm_boot([0; 32], 3);
    let b2 = tpm_boot(b1.tpm, 2);
    let b3 = tpm_boot(b2.tpm, 2);
    // Format v2: a forged refused seal names a boot and the value before it;
    // its anchor is the next boot's real one.
    let s = Seal {
        backend: Backend::TpmNv,
        flags: 0,
        count: 1,
        through: 0,
        counter: 0,
        nonce: 1,
        head: azos_seclog::chain::genesis(&b1.tpm, 1),
        anchor: b2.tpm,
        prev: b1.tpm,
        boot_anchor: b1.tpm,
        sink_lost: 0,
        sink_start: 0,
        sink_digest: [0; 32],
    };
    let mut payload = [0u8; PAYLOAD];
    payload[..Seal::LEN].copy_from_slice(&s.encode());
    let env = Envelope { seq: 0, ts: 1, clock: 0, source: 4, kind: kind::SEAL, len: Seal::LEN as u16, cpu: 0, flags: 0 };
    let mut lines = b1.lines();
    lines.push(seam());
    lines.push(line(&Rec { env, payload }));
    lines.push(seam());
    lines.extend(b3.lines());
    let (found, _) = verify(&lines);
    assert!(!evidence(&found).is_empty(), "boot 2 replaced by a forged refused seal: {found:?}");
}

#[test]
fn review_p1c_seals_alone_are_evidence() {
    let b = tpm_boot([0; 32], 3);
    let seals: Vec<Rec> = b.recs.iter().filter(|r| r.env.kind == kind::SEAL).cloned().collect();
    let k = seals.len() as u64;
    let mut lines = Vec::new();
    for (i, mut r) in seals.into_iter().enumerate() {
        r.env.seq = k - i as u64;
        lines.push(seam());
        lines.push(line(&r));
    }
    let (found, s) = verify(&lines);
    assert_eq!(s.last_anchor, Some(b.tpm));
    assert!(!evidence(&found).is_empty(), "every event dropped: {found:?}");
}

#[test]
fn review_p2_a_declared_loss_logd_kept_is_not_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    b.lapped(3);
    b.event(Class::Update, 40);
    b.seal();
    let (found, _) = verify(&b.lines());
    assert_eq!(evidence(&found), vec![], "honest export shows evidence");
}

// Proofs of the verification of the fix round.

/// V1: whoever can write the log volume deletes a sealed record and appends
/// a `sink-loss` line covering it after the boot's last seal.
#[test]
fn verify_v1_a_forged_sink_loss_after_the_last_seal_hides_a_deleted_record() {
    let mut b = tpm_boot([0; 32], 2);
    // The microphone record of round 1 is at 3 (2 events and the anchor first).
    b.forged_sink_loss(3, 1);
    let mut lines = b.lines();
    lines.remove(3);
    let (found, _) = verify(&lines);
    assert!(!evidence(&found).is_empty(), "a deleted sealed record and a forged declaration: {found:?}");
    // The control: without the forged line, the deletion is evidence too.
    let mut lines = tpm_boot([0; 32], 2).lines();
    lines.remove(3);
    assert!(!evidence(&verify(&lines).0).is_empty());
}

/// V2: a non-first boot's anchor and its records up to its first seal
/// deleted, and a `sink-loss(0, first)` line appended.
#[test]
fn verify_v2_a_forged_sink_loss_hides_a_deleted_boot_start() {
    let b1 = tpm_boot([0; 32], 2);
    let mut b2 = tpm_boot(b1.tpm, 2);
    let first_seal = b2.recs.iter().position(|r| r.env.kind == kind::SEAL).unwrap();
    b2.forged_sink_loss(0, first_seal as u64);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.lines()[first_seal..].to_vec());
    let (found, _) = verify(&lines);
    assert!(!evidence(&found).is_empty(), "a deleted boot start and a forged declaration: {found:?}");
    // The control: the same deletion with no declaration is evidence.
    let b2 = tpm_boot(b1.tpm, 2);
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.lines()[first_seal..].to_vec());
    assert!(!evidence(&verify(&lines).0).is_empty());
}

/// V4: a long honest boot whose sealer the ring lapped 70 times, each loss
/// declared: none of it is evidence.
#[test]
fn verify_v4_a_long_boot_with_many_declared_losses_is_not_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    let mut lost = Vec::new();
    for _ in 0..70 {
        let (first, n) = b.lapped(2);
        lost.push((first, n));
        b.event(Class::Update, 7);
        b.seal();
    }
    let lines: Vec<_> = b.recs.iter().filter(|r| !lost.iter().any(|&(f, n)| r.env.seq >= f && r.env.seq < f + n)).map(line).collect();
    let (found, _) = verify(&lines);
    assert_eq!(evidence(&found), vec![], "{} evidence findings", evidence(&found).len());
}

/// The control of V1: logd lost a sealed record, the kernel declared it and
/// the next seal counts it: declared, not evidence.
#[test]
fn a_sink_loss_the_next_seal_counts_is_not_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    b.event(Class::Microphone, 77);
    let lost = b.recs.len() as u64 - 1;
    b.seal();
    b.sink_loss(lost, 1);
    b.event(Class::Camera, 78);
    b.seal();
    let lines: Vec<_> = b.recs.iter().filter(|r| r.env.seq != lost).map(line).collect();
    let (found, _) = verify(&lines);
    assert_eq!(evidence(&found), vec![], "{found:?}");
    assert!(found.contains(&Finding::Gap { boot: 1, first: lost, count: 1, by: By::Sink }), "{found:?}");
}

/// A forged sink-loss inserted before a seal that does not count it: the
/// declarations do not add up to the seal's count.
///
/// **Canary.** `canary-no-declaration-check`: the forged line explains the
/// deletion, red.
#[test]
fn a_forged_sink_loss_a_seal_does_not_count_is_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    b.event(Class::Microphone, 77);
    let lost = b.recs.len() as u64 - 1;
    b.seal();
    b.forged_sink_loss(lost, 1);
    b.event(Class::Camera, 78);
    b.seal();
    let lines: Vec<_> = b.recs.iter().filter(|r| r.env.seq != lost).map(line).collect();
    let (found, _) = verify(&lines);
    assert!(found.iter().any(|f| matches!(f, Finding::DeclarationMismatch { .. })), "{found:?}");
    assert!(!evidence(&found).is_empty());
    let unv = found.iter().any(|f| matches!(f, Finding::Unverifiable { declared: false, .. }));
    assert!(unv, "the seal over the deleted record stays unverified: {found:?}");
}

// Proofs of round 2 of the verification.

/// V6: logd started late and the kernel declared the boot's first records
/// lost (honest, counted by the seals). A volume writer deletes a microphone
/// record and moves the honest declaration's range onto it, count kept.
#[test]
fn verify_v6_a_rewritten_honest_declaration_hides_a_record() {
    let b1 = tpm_boot([0; 32], 2);
    let mut b2 = Boot::new(Backend::TpmNv, b1.tpm);
    let start = b2.recs.len() as u64;
    b2.sink_loss(0, start);
    let decl = b2.recs.len() as u64 - 1;
    b2.event(Class::Microphone, 66);
    let mic = b2.recs.len() as u64 - 1;
    b2.event(Class::Camera, 67);
    b2.seal();
    b2.event(Class::Egress, 68);
    b2.seal();
    let export = |b2: &Boot| {
        let mut lines = b1.lines();
        lines.push(seam());
        lines.extend(b2.recs.iter().filter(|r| r.env.seq >= start && r.env.seq != mic).map(line));
        lines
    };
    // The control: the deletion with the declaration left alone.
    assert!(!evidence(&verify(&export(&b2)).0).is_empty());
    // The forgery: the declaration's range moved onto the deleted record.
    let r = &mut b2.recs[decl as usize];
    let mut l = Loss::decode(&r.payload).unwrap();
    l.first = mic;
    let mut by_class = [0u32; CLASSES];
    by_class[Class::CapDenial as usize] = l.count as u32;
    l.by_class = by_class;
    r.payload[..Loss::LEN].copy_from_slice(&l.encode());
    let (found, _) = verify(&export(&b2));
    assert!(!evidence(&found).is_empty(), "a rewritten honest declaration hides a deleted record: {found:?}");
}

/// V7: the kernel sealed at its first pass and the ring lapped before logd
/// started, so the boot's first seal is not in the export (declared, and
/// counted by the next seal): an honest boot, no counter gap.
#[test]
fn verify_v7_an_honest_boot_whose_first_seal_logd_lost_is_not_evidence() {
    let b1 = tpm_boot([0; 32], 2);
    let mut b2 = Boot::new(Backend::TpmNv, b1.tpm);
    b2.seal();
    b2.event(Class::ImageLoad, 3);
    let start = b2.recs.len() as u64;
    b2.sink_loss(0, start);
    b2.event(Class::Login, 4);
    b2.seal();
    let mut lines = b1.lines();
    lines.push(seam());
    lines.extend(b2.recs.iter().filter(|r| r.env.seq >= start).map(line));
    let (found, _) = verify(&lines);
    assert_eq!(evidence(&found), vec![], "{found:?}");
}

/// Proof of round 3: the export's first boot cut by rotation, and its first
/// kept seal covers an honest sink-loss: no base to check it against, so it
/// explains nothing and is no evidence; the next seal is checked from this one.
#[test]
fn verify_r3_a_rotated_first_boot_whose_first_kept_seal_covers_a_declaration_is_not_evidence() {
    let mut b = tpm_boot([0; 32], 1);
    let cut = b.recs.len() as u64;
    b.event(Class::Camera, 5);
    let lost = b.recs.len() as u64 - 1;
    b.sink_loss(lost, 1);
    b.event(Class::Usb, 6);
    b.seal();
    b.event(Class::Login, 7);
    b.seal();
    let lines: Vec<_> = b.recs.iter().filter(|r| r.env.seq >= cut && r.env.seq != lost).map(line).collect();
    let (found, _) = verify(&lines);
    assert_eq!(evidence(&found), vec![], "{found:?}");
    // The base is taken from that seal: a declaration forged before the next
    // one is still a mismatch.
    let mut b2 = tpm_boot([0; 32], 1);
    b2.event(Class::Camera, 5);
    b2.seal();
    b2.forged_sink_loss(3, 1);
    b2.event(Class::Login, 7);
    b2.seal();
    let lines: Vec<_> = b2.recs.iter().filter(|r| r.env.seq >= cut).map(line).collect();
    let (found, _) = verify(&lines);
    assert!(found.iter().any(|f| matches!(f, Finding::DeclarationMismatch { .. })), "{found:?}");
}
