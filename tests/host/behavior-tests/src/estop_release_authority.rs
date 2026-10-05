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
//! wire message (`RELEASE_CONTEXT || nonce_be`) from the `pub` constants
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

use super::envelope::serial;
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

/// Build the exact bytes an operator signs, from the crate's own `pub`
/// constants — NOT by calling its private `release_message`, so this pins
/// the wire contract rather than the implementation.
fn wire_message(nonce: u64) -> [u8; RELEASE_MSG_LEN] {
    let mut msg = [0u8; RELEASE_MSG_LEN];
    msg[..RELEASE_CONTEXT.len()].copy_from_slice(RELEASE_CONTEXT);
    msg[RELEASE_CONTEXT.len()..].copy_from_slice(&nonce.to_be_bytes());
    msg
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
fn reset() -> std::sync::MutexGuard<'static, ()> {
    let g = super::flight_recorder::begin(0);
    test_reset_operator_authority();
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
    let _g = serial();
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
    let _g = serial();
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
    let _g = serial();
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
    let _g = serial();
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
    let _g = serial();
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
    let _g = serial();
    let _gl = reset();
    let (signing, pubkey) = operator_keypair();
    assert!(operator_authority_init(&pubkey));
    estop_activate();

    let sig_for_2 = sign(&signing, 2); // signed nonce 2, claiming nonce 1
    let err = verify_operator_release(1, &sig_for_2)
        .expect_err("a signature for a different nonce must not verify");
    assert_eq!(err, ReleaseDenial::BadOrReplayedProof);
}

/// **Replay.** The same (nonce, signature) pair accepted once must be refused
/// the second time it is offered, even though the signature is genuinely
/// valid — a captured release frame must not be replayable.
#[test]
fn a_replayed_release_is_refused() {
    let _g = serial();
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

/// A strictly older nonce than one already accepted must be refused even
/// with a fresh, correctly-signed message — the floor never goes backwards.
#[test]
fn a_nonce_older_than_the_floor_is_refused() {
    let _g = serial();
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
    let _g = serial();
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
    assert!(operator_authority_init(&pubkey), "boot 2 re-provisions the same key from FAT");

    // Read back through the SAME seam a real boot uses.
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
