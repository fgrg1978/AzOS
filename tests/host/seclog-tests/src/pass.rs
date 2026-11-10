// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealer's pass (`azos_seclog::pass`, what the kernel's `seclog` task
//! runs) over a security ring in memory: producers publish into it, the pass
//! folds, declares and seals, and the verifier reads what the ring holds.

use azos_rings::region::record::{self as rec, Envelope, Head, Read, Region, RingSpec, Writer};
use azos_seclog::ack::Page;
use azos_seclog::chain::Sealer;
use azos_seclog::pass::{Config, Hw, Host, Note, Pass};
use azos_seclog::verify::{Finding, Verifier};
use azos_seclog::{kind, Backend, Class, Event, Hash, Held, Loss, Seal, CLASSES, PAYLOAD};

const ENTRIES: u32 = 32;
const LOG: usize = 64;
const HZ: u64 = 1000;

/// A region of one security ring, in memory.
struct Rig {
    _mem: Vec<u64>,
    region: Region,
    w: Writer,
}

impl Rig {
    fn new() -> Rig {
        let specs = [RingSpec { source: rec::SOURCE_SECURITY, slot_bytes: (rec::ENV_BYTES + PAYLOAD) as u32, entries: ENTRIES }];
        let bytes = rec::region_bytes(&specs);
        let mut mem = vec![0u64; bytes.div_ceil(8) + 8];
        let base = mem.as_mut_ptr() as *mut u8;
        // SAFETY: a zeroed, 8-aligned buffer of the region's size this rig owns.
        let region = unsafe {
            rec::format(base, &specs, HZ);
            Region::open(base, bytes).unwrap()
        };
        // SAFETY: the rig is the ring's one producer.
        let w = unsafe { region.writer(0).unwrap() };
        Rig { _mem: mem, region, w }
    }

    fn publish(&self, ts: u64, k: u16, p: &[u8]) -> u64 {
        let h = Head { ts, clock: 0, kind: k, len: p.len() as u16, cpu: 0, flags: 0 };
        self.w.publish(&h, |x| x.bytes(0, p))
    }

    fn event(&self, ts: u64, class: Class, subject: u32) -> u64 {
        let e = Event { id: 0, subject, rule: 1, verdict: 0, class, n: [0; 3], image_hash_prefix: 0, topology_row_id: 0 };
        self.publish(ts, kind::EVENT, &e.encode())
    }

    /// Every record the ring still holds, oldest first.
    fn records(&self) -> Vec<(Envelope, [u8; PAYLOAD])> {
        let ring = self.region.ring(0).unwrap();
        let mut c = ring.oldest();
        let (mut env, mut p) = (Envelope::default(), [0u8; PAYLOAD]);
        let mut v = Vec::new();
        while ring.read(&mut c, &mut env, &mut p) == Read::Record {
            v.push((env, p));
        }
        v
    }
}

struct FakeHost<'a> {
    rig: &'a Rig,
    now: u64,
    copied: [u32; CLASSES],
    held: [u32; CLASSES],
    seals: Vec<(Seal, bool)>,
    notes: Vec<Note>,
}

impl<'a> FakeHost<'a> {
    fn new(rig: &'a Rig) -> Self {
        FakeHost { rig, now: 0, copied: [0; CLASSES], held: [0; CLASSES], seals: Vec::new(), notes: Vec::new() }
    }

    fn event(&mut self, class: Class, subject: u32) -> u64 {
        self.copied[class as usize] += 1;
        self.rig.event(self.now, class, subject)
    }
}

impl Host for FakeHost<'_> {
    fn now(&self) -> u64 {
        self.now
    }
    fn tally(&self) -> ([u32; CLASSES], [u32; CLASSES], [(u32, u32); Held::SUBJECTS]) {
        (self.copied, self.held, [(0, 0); Held::SUBJECTS])
    }
    fn publish(&mut self, k: u16, p: &[u8]) -> u64 {
        self.rig.publish(self.now, k, p)
    }
    fn sealed(&mut self, s: &Seal, hardware: bool) {
        self.seals.push((*s, hardware));
    }
    fn note(&mut self, n: Note) {
        self.notes.push(n);
    }
}

/// A TPM: the extend index and the counter.
struct FakeTpm {
    anchor: Hash,
    counter: u64,
    refuse: bool,
    foreign: bool,
    /// The extend lands and the answer is lost.
    lose: bool,
}

impl Hw for FakeTpm {
    fn increment(&mut self) -> Option<u64> {
        self.counter += 1;
        Some(self.counter)
    }
    fn extend(&mut self, data: &Hash) -> bool {
        if self.refuse {
            return false;
        }
        if self.foreign {
            self.anchor = azos_seclog::chain::extend(&self.anchor, &[0x66; 32]);
        }
        self.anchor = azos_seclog::chain::extend(&self.anchor, data);
        !self.lose
    }
    fn read(&mut self) -> Option<Hash> {
        Some(self.anchor)
    }
}

const CFG: Config = Config { hz: HZ, seal_s: 60, urgent_s: 5, urgent_per_day: 3, declaration_per_day: 2 };

fn pass(p: &mut Pass<LOG>, rig: &Rig, host: &mut FakeHost<'_>, tpm: Option<&mut FakeTpm>, page: Option<&Page>) -> Option<u64> {
    let ring = rig.region.ring(0).unwrap();
    p.run(&ring, page, tpm.map(|t| t as &mut dyn Hw), host, &CFG, false)
}

fn verify(recs: &[(Envelope, [u8; PAYLOAD])]) -> Vec<Finding> {
    let mut v = Verifier::new();
    let mut f = Vec::new();
    for (env, p) in recs {
        v.record(env, p, &mut |x| f.push(x));
    }
    v.finish(&mut |x| f.push(x));
    f
}

fn kinds(recs: &[(Envelope, [u8; PAYLOAD])], k: u16) -> Vec<(u64, [u8; PAYLOAD])> {
    recs.iter().filter(|r| r.0.kind == k).map(|r| (r.0.seq, r.1)).collect()
}

fn new_boot(_rig: &Rig, host: &mut FakeHost<'_>, tpm: &FakeTpm) -> Pass<LOG> {
    let a = azos_seclog::Anchor {
        backend: Backend::TpmNv,
        flags: azos_seclog::FLAG_HARDWARE,
        reason: azos_seclog::Reason::Hardware,
        nonce: 5,
        counter: tpm.counter,
        value: tpm.anchor,
    };
    host.publish(kind::ANCHOR, &a.encode());
    Pass::new(Sealer::new(Backend::TpmNv, tpm.anchor, 5), 0, 0)
}

/// The first pass seals; the TPM holds that seal; what the ring holds then
/// verifies whole.
#[test]
fn pass_the_first_pass_seals_and_the_ring_verifies() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::ImageLoad, 1);
    assert!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None).is_some(), "the first pass seals");
    assert_eq!((host.seals.len(), host.seals[0].1, tpm.counter), (1, true, 1));
    assert_eq!(host.seals[0].0.anchor, tpm.anchor);
    assert_eq!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None), None, "nothing new, nothing sealed");
    let f = verify(&rig.records());
    assert!(f.iter().all(|x| !x.is_evidence()), "{f:?}");
}

/// The ring laps the sealer: the loss is declared, by class, and sealed as
/// soon as the urgent seals' spacing lets it, so no declaration stays
/// uncovered longer than `urgent_s`.
#[test]
fn pass_a_loss_is_declared_by_class_and_sealed_at_once() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::Login, 1);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    host.now += 1000;
    for i in 0..(ENTRIES + 8) {
        host.event(Class::Microphone, 100 + i);
    }
    assert_eq!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None), None, "1 s after a seal: not yet");
    host.now += 4000;
    assert!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None).is_some(), "urgent_s after the last seal");
    let recs = rig.records();
    let loss = kinds(&recs, kind::LOSS);
    assert_eq!(loss.len(), 1);
    let l = Loss::decode(&loss[0].1).unwrap();
    assert!(l.count >= 8 && l.by_class[Class::Microphone as usize] >= 8, "{l:?}");
    let last = host.seals.last().unwrap().0;
    assert!(last.through > loss[0].0, "the seal covers the declaration");
}

/// logd claims records still in the ring (a pending slot it gave up on): the
/// kernel waits until the ring drops them, then declares them.
#[test]
fn pass_a_claim_of_records_still_in_the_ring_waits_for_the_ring() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let page: Page = unsafe { core::mem::zeroed() };
    let mut p = new_boot(&rig, &mut host, &tpm);
    let lost = host.event(Class::Camera, 9);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
    page.claim(lost, 1);
    host.now += 1000;
    pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
    assert!(kinds(&rig.records(), kind::SINK_LOSS).is_empty(), "the record is still in the ring");
    // The ring moves on and drops it.
    for i in 0..ENTRIES {
        host.event(Class::CapDenial, 200 + i);
        if i % 8 == 0 {
            host.now += 1000;
            pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
        }
    }
    host.now += 1000;
    pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
    let sl: Vec<Loss> = kinds(&rig.records(), kind::SINK_LOSS).iter().map(|r| Loss::decode(&r.1).unwrap()).collect();
    assert_eq!(sl.len(), 1, "declared once the ring dropped it");
    assert_eq!((sl[0].first, sl[0].count, sl[0].by_class[Class::Camera as usize]), (lost, 1, 1));
    let s = host.seals.last().unwrap().0;
    assert_eq!(s.sink_lost, 1, "the seal counts it");
}

/// A declared sink loss says whether the sink was running: the claim of a
/// logd whose heartbeat moves rests on its word alone and is marked so, one
/// of a logd that had stopped is not; the seal commits the mark, and the
/// verifier reports it.
///
/// **Canary.** `canary-sink-claim-unmarked`: a declaration is never marked.
#[test]
fn pass_a_sink_loss_says_whether_the_sink_was_running() {
    let run = |beating: bool| {
        let rig = Rig::new();
        let mut host = FakeHost::new(&rig);
        let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
        let page: Page = unsafe { core::mem::zeroed() };
        let mut p = new_boot(&rig, &mut host, &tpm);
        let lost = host.event(Class::Camera, 9);
        pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
        page.claim(lost, 1);
        for i in 0..(ENTRIES + 8) {
            host.event(Class::CapDenial, 200 + i);
            if i % 8 == 0 {
                host.now += 3000;
                if beating {
                    page.beat.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
            }
        }
        host.now += 6000;
        if beating {
            page.beat.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        pass(&mut p, &rig, &mut host, Some(&mut tpm), Some(&page));
        let recs = rig.records();
        let sl = kinds(&recs, kind::SINK_LOSS);
        assert_eq!(sl.len(), 1, "declared once");
        let found = verify(&recs);
        assert!(found.iter().all(|f| !f.is_evidence()), "{found:?}");
        let marked = found.iter().any(|f| matches!(f, Finding::ClassLost { sink: true, claimed: true, .. }));
        (Loss::decode(&sl[0].1).unwrap().sink_alive, marked)
    };
    assert_eq!(run(true), (true, true), "a running sink's claim is marked");
    assert_eq!(run(false), (false, false), "a stopped sink's is not");
}

/// A sink page whose claim count is far ahead (logd's word): the kernel
/// reads at most a page's worth and says it lapped.
#[test]
fn pass_a_claim_count_from_the_sink_bounds_nothing() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let page: Page = unsafe { core::mem::zeroed() };
    page.claims.store(1 << 40, core::sync::atomic::Ordering::Relaxed);
    let mut p = Pass::<LOG>::new(Sealer::new(Backend::Forward, [0; 32], 1), 0, 0);
    host.event(Class::Usb, 1);
    let mut calls = 0;
    page.read_claims(0, |_| calls += 1);
    assert!(calls <= azos_seclog::ack::CLAIMS + 1);
    pass(&mut p, &rig, &mut host, None, Some(&page));
    assert!(host.notes.contains(&Note::ClaimsLapped));
}

/// High-value records in every pass: the urgent seals stop at the day's
/// budget; the period's seal still comes.
#[test]
fn pass_urgent_seals_keep_to_the_days_budget() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::Login, 1);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    for _ in 0..120 {
        host.now += 1000;
        host.event(Class::Login, 2);
        pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    }
    // 120 s: the first seal, at most 3 urgent ones and the two periodic ones.
    assert!(host.seals.len() <= 1 + 3 + 2, "{} seals", host.seals.len());
    assert!(host.notes.contains(&Note::UrgentBudget));
    assert_eq!(tpm.counter as usize, host.seals.len(), "one increment per seal");
}

/// The TPM refuses an extend once: nothing is sealed until the retry, which
/// the TPM takes under the counter the failed try took; every seal is
/// hardware and the chain verifies. A TPM that keeps refusing goes advisory
/// after the tries, and says so.
///
/// **Canary.** `canary-hw-latch`: the first refusal latches the boot's seals
/// to advisory.
#[test]
fn pass_a_transient_tpm_refusal_is_retried_and_a_persistent_one_goes_advisory() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::Update, 1);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    tpm.refuse = true;
    host.now += 61_000;
    host.event(Class::Update, 2);
    assert_eq!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None), None, "refused: nothing is sealed yet");
    assert!(host.notes.contains(&Note::Retrying));
    assert_eq!(host.seals.len(), 1);
    // Inside the wait the TPM is not asked.
    let asked = tpm.counter;
    host.now += 500;
    assert_eq!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None), None);
    assert_eq!(tpm.counter, asked);
    tpm.refuse = false;
    host.now += 1_000;
    assert!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None).is_some(), "the retry seals");
    host.now += 61_000;
    host.event(Class::Update, 3);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    let hw: Vec<bool> = host.seals.iter().map(|s| s.1).collect();
    assert_eq!(hw, vec![true, true, true]);
    assert_eq!(tpm.counter as usize, host.seals.len(), "the retry took no second increment");
    assert!(!host.notes.contains(&Note::Refused));
    let f = verify(&rig.records());
    assert!(f.iter().all(|x| !x.is_evidence()) && !f.iter().any(|x| matches!(x, Finding::Advisory { .. })), "{f:?}");
    // A TPM that never answers: advisory after the tries, and the pass says so.
    tpm.refuse = true;
    host.now += 61_000;
    host.event(Class::Update, 4);
    for _ in 0..40 {
        host.now += 4_000;
        pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    }
    assert!(host.notes.contains(&Note::Refused));
    assert_eq!(host.seals.last().map(|s| s.1), Some(false));
}

/// An extend the TPM took whose answer was lost is not taken again: the seal
/// is a hardware seal of the value the TPM holds, with no divergence, and the
/// chain verifies.
///
/// **Canary.** `canary-extend-readback`: the extend is taken again and the seal says diverged.
#[test]
fn pass_an_extend_the_tpm_took_with_its_answer_lost_is_not_taken_again() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::Update, 1);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    tpm.lose = true;
    host.now += 61_000;
    host.event(Class::Update, 2);
    assert!(pass(&mut p, &rig, &mut host, Some(&mut tpm), None).is_some(), "the TPM holds it: sealed");
    tpm.lose = false;
    host.now += 61_000;
    host.event(Class::Update, 3);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    let hw: Vec<bool> = host.seals.iter().map(|s| s.1).collect();
    assert_eq!(hw, vec![true, true, true]);
    assert!(!host.notes.contains(&Note::Diverged) && !host.notes.contains(&Note::Retrying));
    assert_eq!(tpm.counter as usize, host.seals.len());
    let f = verify(&rig.records());
    assert!(f.iter().all(|x| !x.is_evidence()), "{f:?}");
}

/// Something else extends the index: the seal says diverged.
#[test]
fn pass_a_foreign_extend_is_said() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: true, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::Update, 1);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    assert!(host.seals[0].0.flags & azos_seclog::FLAG_DIVERGED != 0);
    assert!(host.notes.contains(&Note::Diverged));
}

/// The urgent seals of the day are spent by a trigger; a declared loss is
/// still sealed, from a budget of its own.
#[test]
fn pass_a_declaration_has_its_own_seal_budget() {
    let rig = Rig::new();
    let mut host = FakeHost::new(&rig);
    let mut tpm = FakeTpm { anchor: [0; 32], counter: 0, refuse: false, foreign: false, lose: false };
    let mut p = new_boot(&rig, &mut host, &tpm);
    host.event(Class::Login, 1);
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    for _ in 0..8 {
        host.now += 5000;
        host.event(Class::Microphone, 2);
        pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    }
    assert!(host.notes.contains(&Note::UrgentBudget), "the trigger spent the urgent seals");
    let before = host.seals.len();
    host.now += 5000;
    for i in 0..(ENTRIES + 4) {
        host.event(Class::CapDenial, 300 + i);
    }
    pass(&mut p, &rig, &mut host, Some(&mut tpm), None);
    assert_eq!(host.seals.len(), before + 1, "the loss is sealed all the same");
    assert!(!kinds(&rig.records(), kind::LOSS).is_empty());
}
