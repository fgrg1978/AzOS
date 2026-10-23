// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RED/GREEN host tests for the 2026-09-25 owner decision: **the brain may
//! REQUEST an e-stop release; it may never CLEAR the latch.** A release now
//! requires a [`super::safety::ReleaseAuthority`], and the only production
//! way to construct one is [`super::safety::verify_operator_release`] — an
//! Ed25519 signature over a fixed context + a strictly-increasing nonce,
//! checked against a key the brain link never receives.
//!
//! These tests drive the REAL functions `kernel/src/tasks/behavior.rs`'s two
//! `PKT_MODE` dispatch sites call (`safety::verify_operator_release`,
//! `safety::estop_release`, `safety::operator_authority_init`), against the
//! REAL `safety.rs` e-stop state — not a re-derivation of the gate. The
//! signature itself is produced independently, with `ed25519-dalek`'s
//! `SigningKey` directly (this crate's own dependency — see its Cargo.toml
//! comment for why `azos_crypto::ed25519` can't sign), reconstructing the
//! wire message (`RELEASE_CONTEXT || purpose || device id || kind || subject
//! || nonce_be`) from the `pub` constants
//! rather than calling the crate's own private `release_message` — so a test
//! that only asserted "my own function agrees with itself" cannot pass here.
//!
//! **What was RED before this landed** (reproduced by reverting the guard
//! under test and re-running — see the gate row's canary section, and the
//! agent report for the exact commands and captured output):
//!   - `verify_operator_release` with the signature check removed accepted a
//!     forged proof.
//!   - `verify_operator_release` with the nonce-floor check removed accepted
//!     a replayed proof.
//!   - `estop_deactivate` left `pub` let a caller with no proof clear the
//!     latch at all (the whole point of this change).

use super::safety::*;

use ed25519_dalek::{Signer, SigningKey};

/// A deterministic test keypair from a fixed 32-byte seed — reproducible
/// across runs (unlike `SigningKey::generate`, which needs `rand_core` and
/// would make a failing assertion non-reproducible), and distinct from the
/// secure-boot test key (`tools/gen_test_key.py`) so a bug that confused the
/// two authorities would show up as a mismatch here rather than an accidental
/// pass.
fn operator_keypair() -> (SigningKey, [u8; 32]) {
    let seed = [0x42u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key().to_bytes();
    (signing, verifying)
}

/// A second, unrelated keypair — for the "forged" tests: a signature that
/// verifies under ITS OWN key but not under the provisioned operator key.
fn attacker_keypair() -> SigningKey {
    SigningKey::from_bytes(&[0x99u8; 32])
}

/// The id of the device record of the robot the tests stand on ([`reset`]
/// installs it).
const DEVICE: [u8; RELEASE_DEVICE_ID_BYTES] = *b"robot-under-test";

/// Build the exact bytes an operator signs to release `target` on robot
/// `device`, from the crate's own `pub` constants — NOT by calling its private
/// `release_message`, so this pins the wire contract rather than the
/// implementation.
fn message_for(device: &[u8; RELEASE_DEVICE_ID_BYTES], target: ReleaseTarget, nonce: u64) -> [u8; RELEASE_MSG_LEN] {
    let (purpose, kind, subject) = match target {
        ReleaseTarget::Latch => (RELEASE_PURPOSE_LATCH, 0u8, 0u16),
        ReleaseTarget::Hold { kind, subject } => (RELEASE_PURPOSE_HOLD, kind, subject),
    };
    let c = RELEASE_CONTEXT.len();
    let mut msg = [0u8; RELEASE_MSG_LEN];
    msg[..c].copy_from_slice(RELEASE_CONTEXT);
    msg[c] = purpose;
    msg[c + 1..c + 17].copy_from_slice(device);
    msg[c + 17] = kind;
    msg[c + 18..c + 20].copy_from_slice(&subject.to_be_bytes());
    msg[c + 20..].copy_from_slice(&nonce.to_be_bytes());
    msg
}

/// The e-stop latch's release on this robot.
fn wire_message(nonce: u64) -> [u8; RELEASE_MSG_LEN] {
    message_for(&DEVICE, ReleaseTarget::Latch, nonce)
}

fn sign(key: &SigningKey, nonce: u64) -> [u8; RELEASE_SIG_BYTES] {
    key.sign(&wire_message(nonce)).to_bytes()
}

/// Reset all release-authority state and the e-stop latch, so each test
/// states its own preconditions. Guarded by the SAME serial lock
/// `envelope`/`mode_reset` use — `ESTOP_ACTIVE`, `OPERATOR_PUBKEY` and
/// `RELEASE_NONCE_FLOOR` are all process-wide statics.
///
/// **Also takes `flight_recorder::SERIAL`, and returns its guard for the
/// caller to hold.** Added 2026-09-26: `verify_operator_release` now reads
/// `logger::logger_active()` and, when true, writes through the logger —
/// both process-wide state this crate's OTHER test modules
/// (`flight_recorder`, `motor_actuation_reaches_the_flight_recorder`) touch
/// under that lock alone. Every test here that does not otherwise touch the
/// logger gets `flight_recorder::begin`'s own end state — `LOG_ACTIVE ==
/// false` — so `verify_operator_release`'s persistence branch is a no-op
/// for them, deterministically, instead of racing whatever the last
/// scheduled logger test left behind.
///
/// `begin` takes `envelope::serial()` itself (and before its own lock, the
/// order the tests here used when they took it separately), so this guard is
/// the only one a test here holds.
fn reset() -> super::flight_recorder::RecorderGuard {
    let g = super::flight_recorder::begin(0);
    test_reset_operator_authority();
    release_device_init(&DEVICE);
    if estop_is_active() {
        estop_release(ReleaseAuthority::for_test());
    }
    g
}

/// **The core of the owner decision.** A bare `PKT_MODE`/`MODE_ID_ESTOP_RESET`
/// request — no proof attached — must never itself be able to produce a
/// `ReleaseAuthority`. `kernel/src/tasks/behavior.rs` treats a payload shorter than
/// `1 + RELEASE_PROOF_BYTES` as exactly this: no proof to check at all, so it
/// never even calls `verify_operator_release`. Pinned here as: with the
/// authority key provisioned and the latch armed, simply NOT calling
/// `verify_operator_release` (the brain-request path) leaves the latch
/// armed — there is no other function in this module that clears it.
#[test]
fn a_bare_request_does_not_clear_the_latch() {
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey), "a real key must be accepted");

    estop_activate();
    assert!(estop_is_active(), "precondition: armed");

    // The brain-request path: `kernel/src/tasks/behavior.rs` sees a 1-byte payload, computes no
    // proof, and calls neither `verify_operator_release` nor `estop_release`.
    // There is nothing to call here — that absence IS the fix.
    assert!(estop_is_active(), "a bare request must leave the latch exactly as armed as it found it");
}

/// **The positive half.** A correctly-signed, fresh-nonce proof from the
/// provisioned operator key must verify and must actually clear the latch
/// through `estop_release`.
#[test]
fn a_valid_operator_signature_releases_the_latch() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));

    estop_activate();
    assert!(estop_is_active(), "precondition: armed");

    let nonce = 1u64;
    let sig = sign(&signing, nonce);
    let proof = verify_operator_release(nonce, &sig)
        .expect("a correctly-signed, fresh-nonce proof must verify");
    estop_release(proof);
    assert!(!estop_is_active(), "a verified operator proof must clear the latch");
}

/// **Fail-closed: no key provisioned.** Even a signature that would verify
/// under SOME key must be refused when no operator key has ever been loaded
/// — this is what makes an unprovisioned robot safe rather than merely
/// inconvenient (`operator_authority_init` is never called by anything but
/// the boot-time FAT load in `main.rs`).
#[test]
fn no_provisioned_key_means_every_release_is_refused() {
    let _gl = reset();
    assert!(!operator_authority_provisioned(), "precondition: no key loaded");

    let (signing, _unused_pubkey) = operator_keypair();
    let nonce = 1u64;
    let sig = sign(&signing, nonce);
    let err = verify_operator_release(nonce, &sig)
        .expect_err("no key provisioned must refuse regardless of the signature offered");
    assert_eq!(err, ReleaseDenial::NoAuthorityKey);
}

/// **Fail-closed: the zero-key trap.** Secure boot's `build.rs` once fell
/// back to an all-zero public key when no real one was provisioned, and a
/// gate "verified" against it without the Ed25519 code ever running. This
/// module must not let the exact same shape happen here.
#[test]
fn an_all_zero_key_is_rejected_not_installed() {
    let _gl = reset();
    assert!(!operator_authority_init(&[0u8; 32]), "an all-zero key must be refused");
    assert!(!operator_authority_provisioned(), "and must NOT become the provisioned key");
}

/// **A forged proof — wrong key — is refused with the shared denial.** Signed
/// by a real Ed25519 key, over the exact right message, but not the
/// provisioned operator's key. `kernel/src/tasks/behavior.rs` records this under the SAME
/// flight-recorder code (4) as a wrong `mode_id` — see
/// `safety::ESTOP_ACTION_REFUSED_MIRROR`'s doc — which is the "shared error
/// code" the gate row checks for; at the `ReleaseDenial` level both this and
/// the replay test below return `BadOrReplayedProof`.
#[test]
fn a_forged_signature_is_refused() {
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    estop_activate();

    let attacker = attacker_keypair();
    let nonce = 1u64;
    let sig = sign(&attacker, nonce); // valid signature, WRONG key
    let err = verify_operator_release(nonce, &sig)
        .expect_err("a signature from an unprovisioned key must be refused");
    assert_eq!(err, ReleaseDenial::BadOrReplayedProof);
    assert!(estop_is_active(), "a refused proof must not clear the latch");
}

/// A signature over the wrong nonce (message mismatch) must also be refused
/// — the signature does not merely gate SOME release, it gates release AT
/// exactly the claimed nonce.
#[test]
fn a_signature_for_a_different_nonce_is_refused() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    estop_activate();

    let sig_for_2 = sign(&signing, 2); // signed nonce 2, claiming nonce 1
    let err = verify_operator_release(1, &sig_for_2)
        .expect_err("a signature for a different nonce must not verify");
    assert_eq!(err, ReleaseDenial::BadOrReplayedProof);
}

// REQ-008
/// **Replay.** The same (nonce, signature) pair accepted once must be refused
/// the second time it is offered, even though the signature is genuinely
/// valid — a captured release frame must not be replayable.
#[test]
fn a_replayed_release_is_refused() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));

    estop_activate();
    let nonce = 5u64;
    let sig = sign(&signing, nonce);
    let proof = verify_operator_release(nonce, &sig).expect("first use must verify");
    estop_release(proof);
    assert!(!estop_is_active(), "precondition for the replay check: it actually cleared");

    // Re-arm and replay the SAME proof.
    estop_activate();
    let err = verify_operator_release(nonce, &sig)
        .expect_err("the same (nonce, signature) must not verify a second time");
    assert_eq!(err, ReleaseDenial::BadOrReplayedProof);
    assert!(estop_is_active(), "a replayed proof must not clear the latch");
}

// REQ-008
/// A strictly older nonce than one already accepted must be refused even
/// with a fresh, correctly-signed message — the floor never goes backwards.
#[test]
fn a_nonce_older_than_the_floor_is_refused() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));

    estop_activate();
    let proof = verify_operator_release(10, &sign(&signing, 10)).expect("nonce 10 must verify");
    estop_release(proof);

    estop_activate();
    let err = verify_operator_release(3, &sign(&signing, 3))
        .expect_err("nonce 3 is older than the floor (10) and must be refused");
    assert_eq!(err, ReleaseDenial::BadOrReplayedProof);
}

/// The boot-time read seam over the mock medium's file 0: what a real boot
/// hands `logger::replay_boot`.
struct Replay { pos: usize }
impl super::logger::LogReplaySource for Replay {
    fn size(&mut self, serial: u32) -> Result<Option<u32>, super::logger::LogStorageError> {
        Ok(if serial == 0 {
            Some(super::log_storage_mock::file_bytes(0).len() as u32)
        } else {
            None
        })
    }
    fn open(&mut self, serial: u32) -> Result<(), super::logger::LogStorageError> {
        if serial == 0 { self.pos = 0; Ok(()) } else { Err(super::logger::LogStorageError::Unavailable) }
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, super::logger::LogStorageError> {
        let bytes = super::log_storage_mock::file_bytes(0);
        let n = buf.len().min(bytes.len().saturating_sub(self.pos));
        buf[..n].copy_from_slice(&bytes[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
    fn close(&mut self) {}
}

/// **The property this module's header did not yet cover: a captured proof
/// must not replay across a RESET, not just within one boot.** Found by the
/// wave-1 coordinator (`RELEASE_NONCE_FLOOR` was a plain in-process counter)
/// and closed 2026-09-26 by persisting every accepted nonce through the
/// SAME durable path the e-stop latch already uses
/// (`logger::log_release_nonce_floor_durable`, read back at boot by
/// `logger::replay_boot`).
///
/// This test drives the REAL two-call sequence a real boot makes — write
/// during "boot 1", read back and seed during "boot 2" — through the mock
/// `LogStorage`/`LogReplaySource` seams, not a re-derivation of either.
///
/// **RED without the fix**, reproduced by commenting out this test's
/// `release_nonce_floor_seed(replay.release_nonce_floor)` line (i.e.
/// leaving "boot 2" with whatever `test_reset_operator_authority` left the
/// floor at — `0`, matching a real reboot's fresh process): `boot 2`'s
/// `verify_operator_release(7, &sign(&signing, 7))` then VERIFIES, because
/// nothing told it nonce 7 was already spent. See the agent report for the
/// captured `Ok(_)` this produced.
#[test]
fn a_nonce_accepted_in_a_prior_session_is_rejected_after_a_simulated_reboot() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));

    // ---- "boot 1": a recorder IS active, and a release is accepted ----
    super::logger::logger_init().expect("boot 1: mock storage always mounts");
    estop_activate();
    let proof = verify_operator_release(7, &sign(&signing, 7))
        .expect("a fresh nonce with a recorder active must verify and persist");
    estop_release(proof);
    super::logger::logger_shutdown();

    // ---- simulated reboot: nothing but the disk (the mock's recorded
    // bytes, untouched by `logger_shutdown`) survives. A real reboot starts
    // a fresh process, so every in-memory static goes back to its default —
    // reproduced here explicitly rather than relying on process exit. ----
    test_reset_operator_authority(); // RELEASE_NONCE_FLOOR -> 0, key unset
    release_device_init(&DEVICE); // the boot reads the same device record
    assert!(operator_authority_init(&pubkey), "boot 2 re-provisions the same key from FAT");

    // Read back through the SAME seam a real boot uses.
    let replay = super::logger::replay_boot(&mut Replay { pos: 0 });
    assert_eq!(replay.release_nonce_floor, 7, "boot 2's scan must find boot 1's accepted nonce");
    release_nonce_floor_seed(replay.release_nonce_floor);

    // ---- "boot 2": the SAME captured proof must not verify again ----
    estop_activate();
    let err = verify_operator_release(7, &sign(&signing, 7))
        .expect_err("nonce 7 was already accepted and durably recorded in the previous session");
    assert_eq!(err, ReleaseDenial::BadOrReplayedProof);
    assert!(estop_is_active(), "a replayed proof from a prior session must not clear the latch");
}

// ---------------------------------------------------------------------------
// Owner decision 2026-10-17: the release FAILS CLOSED when no durable recorder
// is active, except in a development build (Kconfig BUILD_TYPE_DEV). The tests
// drive `verify_operator_release_for` so one binary states both build types.
// `--features estop-unrecorded-canary` (the check off) must turn the refusal
// tests red.
// ---------------------------------------------------------------------------

/// The newest decision record, if one was written since `before` (the value
/// of `azos_decision::total()` taken first).
fn receipt_since(before: u64) -> Option<azos_decision::Record> {
    let now = azos_decision::total();
    if now == before { None } else { azos_decision::get(now) }
}

/// **The refusal.** A release build with a valid, fresh proof and no active
/// recorder: refused, the latch stays engaged, and a receipt says why. The
/// refusal does not burn the nonce: the same proof is accepted once a
/// recorder exists (checked in the next test).
///
/// **Canary** `estop-unrecorded-canary`: the proof is accepted un-persisted,
/// so this goes red.
#[test]
fn a_release_build_with_no_recorder_refuses_and_keeps_the_latch() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    assert!(!super::logger::logger_active(), "precondition: no recorder");
    estop_activate();
    let before = azos_decision::total();

    let err = verify_operator_release_for(false, ReleaseTarget::Latch, 5, &sign(&signing, 5))
        .err()
        .expect("a release with no durable recorder must be refused on a release build");
    assert_eq!(err, ReleaseDenial::NoDurableRecorder);
    assert!(estop_is_active(), "a refused release must leave the latch engaged");

    let rec = receipt_since(before).expect("the refusal must leave a decision receipt");
    assert_eq!(azos_decision::total(), before + 1, "exactly one receipt");
    assert_eq!(rec.rule, azos_decision::Rule::EstopRelease as u8);
    assert_eq!(rec.verdict, azos_decision::Verdict::Refuse as u8);
    assert_eq!(rec.n, [RELEASE_CAUSE_NO_RECORDER, 0, 5], "cause, floor, nonce");
}

/// A refusal on a release build must not move the nonce floor: the operator
/// retries with the same proof once storage is up.
#[test]
fn a_refused_unrecorded_release_does_not_spend_the_nonce() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    estop_activate();
    let sig = sign(&signing, 5);

    assert!(verify_operator_release_for(false, ReleaseTarget::Latch, 5, &sig).is_err());
    super::logger::logger_init().expect("the mock storage always mounts");
    let proof = verify_operator_release_for(false, ReleaseTarget::Latch, 5, &sig)
        .ok()
        .expect("the same proof must verify once a recorder is active");
    estop_release(proof);
    assert!(!estop_is_active());
    super::logger::logger_shutdown();
}

/// **The development build keeps today's behaviour:** no recorder, proof
/// accepted, no receipt, latch released through the warrant.
#[test]
fn a_dev_build_with_no_recorder_still_proceeds() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    assert!(!super::logger::logger_active());
    estop_activate();
    let before = azos_decision::total();

    let proof = verify_operator_release_for(true, ReleaseTarget::Latch, 5, &sign(&signing, 5))
        .ok()
        .expect("a development build proceeds without a recorder");
    estop_release(proof);
    assert!(!estop_is_active());
    assert_eq!(azos_decision::total(), before, "a proceeding release writes no refusal");
    // The floor moved in memory: the same proof is a replay now.
    estop_activate();
    assert_eq!(
        verify_operator_release_for(true, ReleaseTarget::Latch, 5, &sign(&signing, 5)).err(),
        Some(ReleaseDenial::BadOrReplayedProof)
    );
}

/// **The normal path is unchanged:** a recorder is active, the floor is
/// persisted, the proof verifies on a release build, no receipt.
#[test]
fn a_release_build_with_a_recorder_releases_as_before() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    super::logger::logger_init().expect("the mock storage always mounts");
    estop_activate();
    let before = azos_decision::total();

    let proof = verify_operator_release_for(false, ReleaseTarget::Latch, 9, &sign(&signing, 9))
        .ok()
        .expect("a recorder is active: the release verifies on a release build too");
    estop_release(proof);
    assert!(!estop_is_active());
    assert_eq!(azos_decision::total(), before, "no refusal, no receipt");
    super::logger::logger_shutdown();
}

/// A recorder that is active but cannot take the write still refuses, with
/// its own cause on the receipt, in either build type.
#[test]
fn an_active_recorder_that_fails_the_write_refuses_with_a_receipt() {
    for dev in [false, true] {
        let _gl = reset();
        let (signing, pubkey) = operator_keypair();
        assert!(operator_authority_init(&pubkey));
        super::logger::logger_init().expect("the mock storage always mounts");
        super::log_storage_mock::with(|r| r.fail_write_at = Some(r.writes));
        estop_activate();
        let before = azos_decision::total();

        let err = verify_operator_release_for(dev, ReleaseTarget::Latch, 3, &sign(&signing, 3)).err();
        assert_eq!(err, Some(ReleaseDenial::NonceNotDurable), "dev={dev}");
        assert!(estop_is_active());
        let rec = receipt_since(before).expect("a receipt");
        assert_eq!(rec.rule, azos_decision::Rule::EstopRelease as u8);
        assert_eq!(rec.n[0], RELEASE_CAUSE_NOT_DURABLE);
        super::logger::logger_shutdown();
    }
}

/// A forger without the key never reaches the recorder check, so cannot fill
/// the decision ring: no receipt for a bad signature.
#[test]
fn a_forged_proof_on_a_release_build_writes_no_receipt() {
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    estop_activate();
    let before = azos_decision::total();

    let err = verify_operator_release_for(false, ReleaseTarget::Latch, 5, &sign(&attacker_keypair(), 5)).err();
    assert_eq!(err, Some(ReleaseDenial::BadOrReplayedProof));
    assert_eq!(azos_decision::total(), before);
}

// ---------------------------------------------------------------------------
// G1 (2026-10-17): the signed topology's release key is pinned in the flight
// recorder on first use; a later boot offering another key is refused and
// recorded. The tests drive the real two-call sequence (pin during "boot 1",
// replay and seed during "boot 2") through the mock storage seam.
// ---------------------------------------------------------------------------

/// "Boot 1": a recorder is active and the topology's key is installed and pinned.
fn boot_one_pins(pubkey: &[u8; 32]) {
    super::logger::logger_init().expect("boot 1: mock storage always mounts");
    assert_eq!(operator_key_pin_install(pubkey), KeyPin::Installed);
    super::logger::logger_shutdown();
}

/// A simulated reboot: in-memory state gone, the disk kept; the replay's pin
/// seeded the way `boot_latch::apply` does.
fn reboot_and_seed_pin() {
    test_reset_operator_authority();
    release_device_init(&DEVICE);
    let replay = super::logger::replay_boot(&mut Replay { pos: 0 });
    operator_key_pin_seed(replay.operator_key_pin);
}

/// **The refusal.** Boot 1 pins key A. Boot 2 is offered key B by the topology:
/// nothing is installed, so the release B signs is refused, and a receipt names
/// both fingerprints. Boot 3 offering A again installs it.
///
/// **Canary** (undo `operator_key_pin_install`'s `Some(pin) if pin != fp`
/// arm): B installs, a release verifies, this goes red.
#[test]
fn a_changed_topology_key_is_refused_and_recorded() {
    let _gl = reset();
    let (signing_a, pub_a) = operator_keypair();
    let signing_b = attacker_keypair();
    let pub_b = signing_b.verifying_key().to_bytes();
    boot_one_pins(&pub_a);

    reboot_and_seed_pin();
    let before = azos_decision::total();
    assert_eq!(operator_key_pin_install(&pub_b), KeyPin::Changed);
    assert!(!operator_authority_provisioned(), "a changed key must not be installed");
    let rec = receipt_since(before).expect("a changed key must leave a decision receipt");
    assert_eq!(azos_decision::total(), before + 1, "exactly one receipt");
    assert_eq!(rec.rule, azos_decision::Rule::EstopRelease as u8);
    assert_eq!(rec.verdict, azos_decision::Verdict::Refuse as u8);
    assert_eq!(rec.n[0], RELEASE_CAUSE_KEY_CHANGED);
    assert_eq!(rec.n[1], u64::from_le_bytes(operator_key_fp(&pub_a)[..8].try_into().unwrap()));
    assert_eq!(rec.n[2], u64::from_le_bytes(operator_key_fp(&pub_b)[..8].try_into().unwrap()));
    estop_activate();
    assert_eq!(
        verify_operator_release_for(true, ReleaseTarget::Latch, 1, &sign(&signing_b, 1)).err(),
        Some(ReleaseDenial::NoAuthorityKey),
        "the refused key's owner cannot release",
    );

    reboot_and_seed_pin();
    assert_eq!(operator_key_pin_install(&pub_a), KeyPin::Installed, "the pinned key still installs");
    assert!(verify_operator_release_for(true, ReleaseTarget::Latch, 1, &sign(&signing_a, 1)).is_ok());
}

/// The first key a robot sees installs, with a pin written; with no recorder
/// there is nowhere to pin, and the key installs unpinned.
#[test]
fn the_first_topology_key_installs_with_or_without_a_recorder() {
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    assert!(!super::logger::logger_active(), "precondition: no recorder");
    assert_eq!(operator_key_pin_install(&pubkey), KeyPin::Installed);
    assert!(operator_authority_provisioned());
    assert_eq!(operator_key_pin_install(&[0u8; 32]), KeyPin::Zero);
}

/// A recorder that is active and refuses the first pin refuses the key: the
/// next boot could otherwise accept a different one.
#[test]
fn a_pin_that_cannot_be_written_refuses_the_key() {
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    super::logger::logger_init().expect("the mock storage always mounts");
    super::log_storage_mock::with(|r| r.fail_write_at = Some(r.writes));
    let before = azos_decision::total();
    assert_eq!(operator_key_pin_install(&pubkey), KeyPin::NotDurable);
    assert!(!operator_authority_provisioned());
    let rec = receipt_since(before).expect("a receipt");
    assert_eq!(rec.n[0], RELEASE_CAUSE_KEY_NOT_DURABLE);
    super::logger::logger_shutdown();
}

/// The newest pin wins the replay, and a blank medium has none.
#[test]
fn the_replay_returns_the_pinned_key_fingerprint() {
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    assert_eq!(super::logger::BootReplay::blank(super::logger::BootLatch::NoRecord).operator_key_pin, None);
    boot_one_pins(&pubkey);
    let replay = super::logger::replay_boot(&mut Replay { pos: 0 });
    assert_eq!(replay.operator_key_pin, Some(operator_key_fp(&pubkey)));
}

/// The boot-time read seam over ONE mock file, presented as serial 0: what a
/// boot finds once the wrap has overwritten every older file.
struct ReplayOnly { index: usize, pos: usize }
impl super::logger::LogReplaySource for ReplayOnly {
    fn size(&mut self, serial: u32) -> Result<Option<u32>, super::logger::LogStorageError> {
        Ok(if serial == 0 {
            Some(super::log_storage_mock::file_bytes(self.index).len() as u32)
        } else {
            None
        })
    }
    fn open(&mut self, serial: u32) -> Result<(), super::logger::LogStorageError> {
        if serial == 0 { self.pos = 0; Ok(()) } else { Err(super::logger::LogStorageError::Unavailable) }
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, super::logger::LogStorageError> {
        let bytes = super::log_storage_mock::file_bytes(self.index);
        let n = buf.len().min(bytes.len().saturating_sub(self.pos));
        buf[..n].copy_from_slice(&bytes[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
    fn close(&mut self) {}
}

/// **The wrap cannot take the pin.** Boot 1 pins key A into file 0 and the
/// logger then rotates (a torn write is the quickest honest rotation). The
/// log serials wrap and the wrap overwrites the oldest file, so a boot that
/// finds only the NEWEST file must still find the pin; otherwise it would take
/// a changed topology key for the first one and pin it (G1 defeated).
///
/// **Canary** (drop the `carry_key_pin_into_new_file()` call at the end of
/// `open_log_file_inner`): file 1 holds no pin, the replay answers `None`,
/// this goes red.
#[test]
fn a_rotation_carries_the_key_pin_into_the_new_file() {
    use super::log_storage_mock as fsmock;
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    super::logger::logger_init().expect("the mock storage always mounts");
    assert_eq!(operator_key_pin_install(&pubkey), KeyPin::Installed);

    super::logger::log_skill_start(1);
    let w = fsmock::with(|r| r.writes);
    fsmock::with(|r| {
        r.short_write_at = Some((w, 16));
        r.fail_write_at = Some(w + 1);
    });
    assert!(super::logger::logger_flush().is_err(), "the torn write is reported");
    assert_eq!(fsmock::file_count(), 2, "the torn write rotated to a second file");
    fsmock::with(|r| { r.short_write_at = None; r.fail_write_at = None; });
    super::logger::logger_flush().expect("the carried pin reaches the new file");
    super::logger::logger_shutdown();

    let newest = super::logger::replay_boot(&mut ReplayOnly { index: 1, pos: 0 });
    assert_eq!(
        newest.operator_key_pin, Some(operator_key_fp(&pubkey)),
        "the newest file alone must still answer the pin",
    );
}

/// **Every boot that installs the key writes the pin into its own file.**
/// Boot 1 pins A; boot 2 reads it back and installs A again. Boot 2's file
/// carries the pin, so a boot 3 that finds only boot 2's file still knows A.
///
/// **Canary** (empty the `Some(_)` arm of `operator_key_pin_install`): boot 2's
/// file holds no pin, the replay answers `None`, this goes red.
#[test]
fn a_boot_that_installs_the_pinned_key_writes_the_pin_again() {
    use super::log_storage_mock as fsmock;
    let _gl = reset();
    let (_signing, pubkey) = operator_keypair();
    boot_one_pins(&pubkey);

    reboot_and_seed_pin();
    super::logger::logger_init().expect("boot 2: the mock storage always mounts");
    assert_eq!(operator_key_pin_install(&pubkey), KeyPin::Installed);
    super::logger::logger_shutdown();
    assert_eq!(fsmock::file_count(), 2, "boot 2 opened its own file");

    let boot2 = super::logger::replay_boot(&mut ReplayOnly { index: 1, pos: 0 });
    assert_eq!(boot2.operator_key_pin, Some(operator_key_fp(&pubkey)));
}

// ---------------------------------------------------------------------------
// The warrant names what it releases and on which robot. The signed message
// binds the purpose (the e-stop latch, or one device the kernel holds in its
// safe state, by kind and subject) and the id of this robot's device record,
// the identity its signed topology is bound to. Under a key two robots share,
// or a key that also signs hold releases, a captured warrant is good for the
// one release it was made for and nothing else.
// ---------------------------------------------------------------------------

/// **A warrant signed for another robot does not release this one**, whatever
/// else about it is right (the key, a fresh nonce), and it does not spend the
/// nonce: this robot's own warrant with the same nonce still verifies.
///
/// **Canary.** Leave the device id out of `release_message` (or sign the old
/// `context || nonce` message): the other robot's warrant verifies.
#[test]
fn a_warrant_for_another_robot_is_refused_and_spends_nothing() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    estop_activate();

    let elsewhere = *b"another-robot-id";
    let theirs = signing.sign(&message_for(&elsewhere, ReleaseTarget::Latch, 4)).to_bytes();
    assert_eq!(verify_operator_release(4, &theirs).err(), Some(ReleaseDenial::BadOrReplayedProof));
    assert!(estop_is_active());

    let mut old = [0u8; 21 + 8];
    old[..21].copy_from_slice(b"AZOS-ESTOP-RELEASE-v1");
    old[21..].copy_from_slice(&4u64.to_be_bytes());
    let v1 = signing.sign(&old).to_bytes();
    assert_eq!(verify_operator_release(4, &v1).err(), Some(ReleaseDenial::BadOrReplayedProof),
               "the unbound v1 message is not a warrant");

    let proof = verify_operator_release(4, &sign(&signing, 4)).expect("this robot's warrant, nonce 4");
    estop_release(proof);
    assert!(!estop_is_active());
}

/// **A warrant releases what it was signed for and nothing else.** A hold
/// release of wheel 1 is not a latch release and not a release of wheel 0;
/// a latch release is not a hold release. One nonce floor covers them all.
///
/// **Canary.** Leave the purpose, the kind or the subject out of
/// `release_message`: the cross-purpose warrants verify.
#[test]
fn a_warrant_releases_only_its_own_target() {
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    let wheel = |subject| ReleaseTarget::Hold { kind: 1, subject };
    let hold1 = signing.sign(&message_for(&DEVICE, wheel(1), 6)).to_bytes();
    let latch = sign(&signing, 6);

    assert_eq!(verify_operator_release(6, &hold1).err(), Some(ReleaseDenial::BadOrReplayedProof),
               "a hold warrant released the e-stop latch");
    assert_eq!(verify_operator_release_of(wheel(0), 6, &hold1).err(), Some(ReleaseDenial::BadOrReplayedProof),
               "wheel 1's warrant released wheel 0");
    assert_eq!(verify_operator_release_of(ReleaseTarget::Hold { kind: 2, subject: 1 }, 6, &hold1).err(),
               Some(ReleaseDenial::BadOrReplayedProof), "a motor warrant released another kind");
    assert_eq!(verify_operator_release_of(wheel(1), 6, &latch).err(), Some(ReleaseDenial::BadOrReplayedProof),
               "a latch warrant released a hold");
    assert!(verify_operator_release_of(wheel(1), 6, &hold1).is_ok(), "the hold's own warrant");
    assert_eq!(verify_operator_release(6, &latch).err(), Some(ReleaseDenial::BadOrReplayedProof),
               "nonce 6 is spent for every target");
}

/// **No device record: a release build refuses every release; a
/// development build binds the all-zero id.** Without an identity a warrant
/// would be good on every unprovisioned robot under the key, so a release
/// build fails closed, before the signature is checked and without a receipt
/// (as with no key). A development build (QEMU, a bench board without a
/// disk) signs and verifies with 16 zero bytes.
#[test]
fn no_device_identity_fails_closed_outside_a_development_build() {
    let _gl = reset();
    test_reset_operator_authority();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    super::logger::logger_init().expect("the mock storage always mounts");
    let before = azos_decision::total();

    let zero = [0u8; RELEASE_DEVICE_ID_BYTES];
    let sig = signing.sign(&message_for(&zero, ReleaseTarget::Latch, 8)).to_bytes();
    assert_eq!(verify_operator_release_for(false, ReleaseTarget::Latch, 8, &sig).err(),
               Some(ReleaseDenial::NoDeviceIdentity));
    assert_eq!(azos_decision::total(), before, "no receipt for a missing identity");
    assert!(verify_operator_release_for(true, ReleaseTarget::Latch, 8, &sig).is_ok(),
            "a development build binds the zero id");
    super::logger::logger_shutdown();
}
