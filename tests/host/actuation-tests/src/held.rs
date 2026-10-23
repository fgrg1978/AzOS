// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the hold after a safe-state drive (innovation B2, owner
//! decision 16-10): `safe_state.rs` over the real flight recorder, the real
//! decision journal and the real operator-release verification of `estop.rs`.
//!
//! After the kernel drives a device to its safe state it stays HELD for at
//! least `B2_HOLD_MIN_MS`; no stop lifts it; afterwards only `release`, with
//! the operator's signed warrant, does; a release and a refused release are
//! each one `Rule::SafeState` record. The properties and the test that holds
//! each:
//!
//! * stops of any kind leave the hold, however long it has lasted:
//!   `a_stop_does_not_lift_the_hold_however_long_it_lasts`;
//! * a release inside the minimum hold is refused with a record and does not
//!   spend the warrant: `a_release_inside_the_minimum_hold_is_refused_and_keeps_the_warrant`;
//! * a release without a valid warrant is refused with a record, whatever the
//!   age of the hold: `a_release_without_a_valid_warrant_is_refused`;
//! * a release with a warrant after the minimum hold is accepted, recorded
//!   once, and the device answers again: `a_warranted_release_after_the_minimum_hold_lifts_it`;
//! * a second drive restarts the minimum: `a_second_drive_restarts_the_minimum_hold`;
//! * the operator's channel, the body of a `PKT_MODE` reset frame, releases
//!   the held device it names with the e-stop release warrant, and a body of
//!   any other length is not that frame: `the_operators_frame_releases_the_device_it_names`;
//! * a device that is not held has nothing to release, and a held one does
//!   not release its neighbour: `only_the_held_device_can_be_released`;
//! * an accepted release lifts the device layer's hold too (the kind's release
//!   driver: the motor's pins and channel), a refused one does not, and a
//!   hold that comes back while the device layer's is lifted is driven again:
//!   `a_release_lifts_the_device_layers_hold_and_a_returning_hold_is_driven_again`.
//!
//! **Canaries** (mutations of `safe_state.rs`, run by hand, each red): dropping
//! the minimum-hold comparison in `release` fails the second and fifth tests;
//! skipping `verify_operator_release` fails the third; not restamping the hold
//! in `complete`'s redo drive fails the fifth; making `release_from_frame`
//! skip `release` fails the frame test.

use crate::effect_gate::{self, Class, Timing, KIND_MOTOR};
use crate::estop::{
    self, ReleaseDenial, RELEASE_CONTEXT, RELEASE_MSG_LEN, RELEASE_PROOF_BYTES, RELEASE_PURPOSE_HOLD,
    RELEASE_PURPOSE_LATCH, RELEASE_SIG_BYTES,
};
use crate::safe_state::{
    self, ReleaseError, CAUSE_RELEASED, CAUSE_RELEASE_NO_WARRANT, CAUSE_RELEASE_TOO_EARLY, STATE_COMMANDED, STATE_SAFE,
};
use crate::tests::{effect, fresh};
use azos_decision::{Record, Rule, Verdict};
use ed25519_dalek::{Signer, SigningKey};

const MS: u64 = 10_000; // timer ticks per millisecond (the shim's 10 MHz)
const T0: u64 = 1_000_000_000;
const OP_COAST: u8 = 1;
const OP_STOP: u8 = 2;
const DEVICE_ID: u32 = (KIND_MOTOR as u32) << 16 | 1;

fn min_hold_ms() -> u64 {
    azos_limits::B2_HOLD_MIN_MS as u64
}

/// Every safe-state drive the kernel asked for, `(subject, op)`.
static DRIVES: std::sync::Mutex<Vec<(u16, u8)>> = std::sync::Mutex::new(Vec::new());
/// Every device-layer release the kernel asked for.
static RELEASES: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
/// Set: the next release driver call first lets wheel 1 miss a deadline again.
static MISS_DURING_RELEASE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn mock_drive(subject: u16, op: u8) -> bool {
    DRIVES.lock().unwrap_or_else(|e| e.into_inner()).push((subject, op));
    true
}

fn mock_release(subject: u16) -> bool {
    if MISS_DURING_RELEASE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        stall_wheel_1();
    }
    RELEASES.lock().unwrap_or_else(|e| e.into_inner()).push(subject);
    true
}

fn drives() -> Vec<(u16, u8)> {
    DRIVES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn releases() -> Vec<u16> {
    RELEASES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn at(t: u64) {
    azos_drv_sys::clint::set_test_time(t);
}

fn operator() -> (SigningKey, [u8; 32]) {
    let signing = SigningKey::from_bytes(&[0x42u8; 32]);
    let public = signing.verifying_key().to_bytes();
    (signing, public)
}

/// The operator's warrant releasing `purpose` (kind and subject: wheel 1, the
/// device these tests hold; 0 for the latch) with `nonce`. The device id is
/// 16 zero bytes: no device record is installed, and the suite is a
/// development build (`estop.rs` binds the zero id then).
fn sign_for(key: &SigningKey, purpose: u8, nonce: u64) -> [u8; RELEASE_SIG_BYTES] {
    let (kind, subject) = if purpose == RELEASE_PURPOSE_HOLD { (KIND_MOTOR, 1u16) } else { (0, 0) };
    let c = RELEASE_CONTEXT.len();
    let mut msg = [0u8; RELEASE_MSG_LEN];
    msg[..c].copy_from_slice(RELEASE_CONTEXT);
    msg[c] = purpose;
    msg[c + 17] = kind;
    msg[c + 18..c + 20].copy_from_slice(&subject.to_be_bytes());
    msg[c + 20..].copy_from_slice(&nonce.to_be_bytes());
    key.sign(&msg).to_bytes()
}

/// The warrant releasing wheel 1's hold.
fn sign(key: &SigningKey, nonce: u64) -> [u8; RELEASE_SIG_BYTES] {
    sign_for(key, RELEASE_PURPOSE_HOLD, nonce)
}

/// Puts the clock, the hold table, the driver and the operator key right.
struct Scene {
    key: SigningKey,
}

impl Scene {
    fn new() -> Scene {
        safe_state::register(KIND_MOTOR, mock_drive, mock_drive, mock_release);
        DRIVES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        RELEASES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        MISS_DURING_RELEASE.store(false, std::sync::atomic::Ordering::SeqCst);
        at(T0);
        safe_state::clear_holds_for_test();
        estop::test_reset_operator_authority();
        let (key, public) = operator();
        assert!(estop::operator_authority_init(&public));
        Scene { key }
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_drv_sys::clint::clear_test_time();
        estop::test_reset_operator_authority();
    }
}

/// A 2 ms deadline on a kernel-hosted wheel, 500 us to commit.
fn timing() -> Timing {
    Timing { deadline_ns: 2_000_000, placement_ns: 200_000, commit_ns: 500_000, safe_op: OP_COAST, compensate_op: OP_STOP }
}

/// Wheel 1's op overruns its deadline and returns at `T0 + 5 ms`: the kernel
/// drives it there and the hold starts at that tick.
fn stall_wheel_1() -> u64 {
    at(T0);
    effect_gate::issue(&effect(Class::Reversible, 1), &timing(), || {
        at(T0 + 5 * MS);
        ((), true)
    })
    .expect("admitted");
    assert!(safe_state::held(KIND_MOTOR, 1));
    T0 + 5 * MS
}

/// Decision records of `rule` written after sequence `base`.
fn records(base: u64, rule: Rule) -> Vec<Record> {
    let mut out = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > base && r.rule == rule as u8 {
            out.push(*r);
        }
    });
    out
}

fn answers() -> bool {
    effect_gate::issue(&effect(Class::Reversible, 9), &timing(), || ((), true)).is_ok()
}

#[test]
fn a_stop_does_not_lift_the_hold_however_long_it_lasts() {
    let _g = fresh();
    let _s = Scene::new();
    let since = stall_wheel_1();

    // Stops are never refused, whether they land or fail, inside the minimum
    // hold or long after it: none of them lifts it.
    for (i, t) in [since + MS, since + (min_hold_ms() + 1) * MS, since + 3_600_000 * MS].into_iter().enumerate() {
        at(t);
        effect_gate::issue(&effect(Class::Safe, 10 + i as u32), &timing(), || ((), true)).expect("a stop is never refused");
        effect_gate::issue(&effect(Class::Safe, 20 + i as u32), &timing(), || ((), false)).expect("a stop is never refused");
        assert!(safe_state::held(KIND_MOTOR, 1), "a stop lifted the hold at +{} ms", (t - since) / MS);
        assert!(!answers(), "a held device took a motion op at +{} ms", (t - since) / MS);
    }
}

#[test]
fn a_release_inside_the_minimum_hold_is_refused_and_keeps_the_warrant() {
    let _g = fresh();
    let s = Scene::new();
    let since = stall_wheel_1();
    let sig = sign(&s.key, 1);

    // One millisecond short of the minimum.
    at(since + (min_hold_ms() - 1) * MS);
    let base = azos_decision::total();
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 1, &sig), Err(ReleaseError::TooEarly { remaining_ms: 1 }));
    assert!(safe_state::held(KIND_MOTOR, 1));
    let recs = records(base, Rule::SafeState);
    assert_eq!(recs.len(), 1, "a refused release is one record");
    assert_eq!((recs[0].verdict, recs[0].subject), (Verdict::Refuse as u8, DEVICE_ID));
    assert_eq!(recs[0].n, [STATE_SAFE, STATE_SAFE, (min_hold_ms() - 1) << 8 | CAUSE_RELEASE_TOO_EARLY]);

    // The warrant was not spent: the same one is accepted at the minimum.
    at(since + min_hold_ms() * MS);
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 1, &sig), Ok(()));
    assert!(!safe_state::held(KIND_MOTOR, 1));
}

#[test]
fn a_release_without_a_valid_warrant_is_refused() {
    let _g = fresh();
    let s = Scene::new();
    let since = stall_wheel_1();
    // Well past the minimum: only the warrant is missing.
    at(since + 10 * min_hold_ms() * MS);
    let held_ms = 10 * min_hold_ms();

    let attacker = SigningKey::from_bytes(&[0x99u8; 32]);
    let cases: [(&str, u64, [u8; RELEASE_SIG_BYTES], ReleaseError); 3] = [
        ("signed by another key", 1, sign(&attacker, 1), ReleaseError::NoWarrant(ReleaseDenial::BadOrReplayedProof)),
        ("signature for another nonce", 2, sign(&s.key, 1), ReleaseError::NoWarrant(ReleaseDenial::BadOrReplayedProof)),
        ("no signature at all", 3, [0u8; RELEASE_SIG_BYTES], ReleaseError::NoWarrant(ReleaseDenial::BadOrReplayedProof)),
    ];
    for (what, nonce, sig, want) in cases {
        let base = azos_decision::total();
        assert_eq!(safe_state::release(KIND_MOTOR, 1, nonce, &sig), Err(want), "{what}");
        assert!(safe_state::held(KIND_MOTOR, 1), "{what}: the device was released");
        let recs = records(base, Rule::SafeState);
        assert_eq!(recs.len(), 1, "{what}: one record");
        assert_eq!(recs[0].verdict, Verdict::Refuse as u8, "{what}");
        assert_eq!(recs[0].n, [STATE_SAFE, STATE_SAFE, held_ms << 8 | CAUSE_RELEASE_NO_WARRANT], "{what}");
    }

    // A replayed warrant: its nonce already released something (here the
    // e-stop latch, which shares the floor), so it is not good again.
    let sig = sign(&s.key, 5);
    estop::verify_operator_release(5, &sign_for(&s.key, RELEASE_PURPOSE_LATCH, 5))
        .expect("the e-stop release spends nonce 5");
    assert_eq!(
        safe_state::release(KIND_MOTOR, 1, 5, &sig),
        Err(ReleaseError::NoWarrant(ReleaseDenial::BadOrReplayedProof))
    );
    assert!(safe_state::held(KIND_MOTOR, 1));

    // No operator key provisioned: nothing can be a warrant.
    estop::test_reset_operator_authority();
    assert_eq!(
        safe_state::release(KIND_MOTOR, 1, 9, &sign(&s.key, 9)),
        Err(ReleaseError::NoWarrant(ReleaseDenial::NoAuthorityKey))
    );
    assert!(safe_state::held(KIND_MOTOR, 1));
    assert!(!answers());
}

#[test]
fn a_warranted_release_after_the_minimum_hold_lifts_it() {
    let _g = fresh();
    let s = Scene::new();
    let since = stall_wheel_1();
    assert!(!answers(), "precondition: held");

    at(since + (min_hold_ms() + 250) * MS);
    let base = azos_decision::total();
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 7, &sign(&s.key, 7)), Ok(()));
    assert!(!safe_state::held(KIND_MOTOR, 1));
    let recs = records(base, Rule::SafeState);
    assert_eq!(recs.len(), 1, "a release is one record");
    assert_eq!((recs[0].verdict, recs[0].subject), (Verdict::Admit as u8, DEVICE_ID));
    assert_eq!(recs[0].n, [STATE_SAFE, STATE_COMMANDED, (min_hold_ms() + 250) << 8 | CAUSE_RELEASED]);

    assert!(answers(), "the released device answers again");
    // The warrant is spent: it releases nothing twice.
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 7, &sign(&s.key, 7)), Err(ReleaseError::NotHeld));
}

#[test]
fn a_second_drive_restarts_the_minimum_hold() {
    let _g = fresh();
    let s = Scene::new();
    // The sweep drives the wheel at +3 ms; the stalled op returns at +400 ms
    // and drives it again after its last write: the minimum counts from there.
    at(T0);
    effect_gate::issue(&effect(Class::Reversible, 1), &timing(), || {
        at(T0 + 3 * MS);
        assert_eq!(safe_state::sweep(T0 + 3 * MS), 1);
        at(T0 + 400 * MS);
        ((), true)
    })
    .expect("admitted");
    let redriven = T0 + 400 * MS;

    // 500 ms after the FIRST drive: still inside the minimum of the second.
    at(T0 + 3 * MS + min_hold_ms() * MS);
    assert!(matches!(safe_state::release(KIND_MOTOR, 1, 1, &sign(&s.key, 1)), Err(ReleaseError::TooEarly { .. })));
    at(redriven + min_hold_ms() * MS);
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 1, &sign(&s.key, 1)), Ok(()));
}

#[test]
fn only_the_held_device_can_be_released() {
    let _g = fresh();
    let s = Scene::new();
    let since = stall_wheel_1();
    at(since + min_hold_ms() * MS);
    let base = azos_decision::total();

    // Wheel 0 is not held; a valid warrant does not release it, spends no
    // nonce and writes no record. A subject beyond the tables is not held.
    for subject in [0u16, safe_state::MAX_SUBJECTS, u16::MAX] {
        assert_eq!(safe_state::release(KIND_MOTOR, subject, 1, &sign(&s.key, 1)), Err(ReleaseError::NotHeld));
    }
    assert_eq!(safe_state::release(safe_state::MAX_KINDS as u8, 1, 1, &sign(&s.key, 1)), Err(ReleaseError::NotHeld));
    assert!(records(base, Rule::SafeState).is_empty());
    assert!(safe_state::held(KIND_MOTOR, 1), "a neighbour's release lifted this one");

    assert_eq!(safe_state::release(KIND_MOTOR, 1, 1, &sign(&s.key, 1)), Ok(()), "nonce 1 was not spent");
}

/// The body of a hold-release frame as the brain link carries it after the
/// mode id: nonce, signature, device kind, device subject.
fn frame_body(nonce: u64, sig: &[u8; RELEASE_SIG_BYTES], kind: u8, subject: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&nonce.to_be_bytes());
    b.extend_from_slice(sig);
    b.push(kind);
    b.extend_from_slice(&subject.to_be_bytes());
    assert_eq!(b.len(), safe_state::HOLD_RELEASE_BODY_BYTES);
    b
}

#[test]
fn the_operators_frame_releases_the_device_it_names() {
    let _g = fresh();
    let s = Scene::new();
    let since = stall_wheel_1();
    let sig = sign(&s.key, 3);

    // The e-stop release shapes (a bare request, the proof without a device,
    // a proof with trailing bytes) are not this frame, whatever their content.
    let good = frame_body(3, &sig, KIND_MOTOR, 1);
    assert_eq!(safe_state::release_from_frame(&[]), None);
    assert_eq!(safe_state::release_from_frame(&good[..RELEASE_PROOF_BYTES]), None);
    assert_eq!(safe_state::release_from_frame(&good[..good.len() - 1]), None);
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(safe_state::release_from_frame(&longer), None);
    assert!(safe_state::held(KIND_MOTOR, 1));

    // Inside the minimum hold the frame is refused and keeps the warrant.
    at(since + (min_hold_ms() - 1) * MS);
    assert_eq!(
        safe_state::release_from_frame(&good),
        Some(Err(ReleaseError::TooEarly { remaining_ms: 1 }))
    );
    assert!(safe_state::held(KIND_MOTOR, 1));

    // A frame that names another device releases nothing (wheel 2 is not held).
    at(since + min_hold_ms() * MS);
    assert_eq!(
        safe_state::release_from_frame(&frame_body(3, &sig, KIND_MOTOR, 2)),
        Some(Err(ReleaseError::NotHeld))
    );
    assert!(safe_state::held(KIND_MOTOR, 1));

    // A forged frame is refused with a record.
    let attacker = SigningKey::from_bytes(&[0x99u8; 32]);
    let base = azos_decision::total();
    assert_eq!(
        safe_state::release_from_frame(&frame_body(4, &sign(&attacker, 4), KIND_MOTOR, 1)),
        Some(Err(ReleaseError::NoWarrant(ReleaseDenial::BadOrReplayedProof)))
    );
    assert_eq!(records(base, Rule::SafeState).len(), 1);
    assert!(safe_state::held(KIND_MOTOR, 1));

    // The operator's frame at the minimum hold: released, once.
    let base = azos_decision::total();
    assert_eq!(safe_state::release_from_frame(&good), Some(Ok(())));
    assert!(!safe_state::held(KIND_MOTOR, 1));
    assert!(answers(), "the released device answers again");
    let recs = records(base, Rule::SafeState);
    assert_eq!(recs.len(), 1);
    assert_eq!((recs[0].verdict, recs[0].subject), (Verdict::Admit as u8, DEVICE_ID));
    assert_eq!(recs[0].n, [STATE_SAFE, STATE_COMMANDED, min_hold_ms() << 8 | CAUSE_RELEASED]);
}

/// **The release reaches the device layer.** The kernel's drive also holds the
/// device in its driver (the motor: its pins and channel, `azos_robot::
/// motor_release`), so a release the warrant accepts calls the kind's release
/// driver for that device, once; refusals (too early, no warrant) do not. A
/// miss that holds the device again while its driver hold is being lifted is
/// driven again with its op afterwards, so the device layer holds it as the
/// gate does.
///
/// **Canary.** Drop the `release_device` call in `release`: no release
/// reaches the driver. Drop the re-drive after it: the second part sees one
/// drive, not two.
#[test]
fn a_release_lifts_the_device_layers_hold_and_a_returning_hold_is_driven_again() {
    let _g = fresh();
    let s = Scene::new();
    let since = stall_wheel_1();
    at(since + MS);
    assert!(safe_state::release(KIND_MOTOR, 1, 3, &sign(&s.key, 3)).is_err());
    at(since + (min_hold_ms() + 1) * MS);
    assert!(safe_state::release(KIND_MOTOR, 1, 3, &[0u8; RELEASE_SIG_BYTES]).is_err());
    assert!(releases().is_empty(), "a refused release reached the driver");
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 3, &sign(&s.key, 3)), Ok(()));
    assert_eq!(releases(), vec![1], "the accepted release did not reach the driver");

    // Held again, and this time the wheel misses once more while its driver
    // hold is lifted.
    DRIVES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let since = stall_wheel_1();
    at(since + (min_hold_ms() + 1) * MS);
    MISS_DURING_RELEASE.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(safe_state::release(KIND_MOTOR, 1, 4, &sign(&s.key, 4)), Ok(()));
    assert!(safe_state::held(KIND_MOTOR, 1), "the new miss's hold was lost");
    assert_eq!(drives(), vec![(1, OP_COAST), (1, OP_COAST), (1, OP_COAST)],
        "the hold that came back during the release was not driven again");
}
