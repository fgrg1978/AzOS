// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_config::signed::cfg_load_verified` —
//! W2-B5 (audit U10-2).
//!
//! Shares `crate::tests::TEST_LOCK` (see that module's doc) instead of a
//! lock of its own: every test here, like every test in `crate::tests`,
//! touches `azos_config`'s one `static mut` entry table, so two
//! independent locks would let a test from each file run concurrently and
//! corrupt each other's view of that table.

use std::sync::atomic::Ordering;

use azos_config::{
    cfg_apply, cfg_get, cfg_get_u32, cfg_load_verified, ConfigTrust,
    ESTOP_GPIO_PIN_FAIL_CLOSED, CFG_BENCH_BOOT, CFG_ESTOP_GPIO_PIN,
    CFG_LINK_ENCRYPT, CFG_OTA_AUTO_RECV_PORT,
};

/// Acquire the shared lock and reset the table, same contract as
/// `crate::tests::fresh()` (not reused directly: it returns a guard typed
/// to that module's own lifetime elision, and re-deriving it here is one
/// line versus changing that function's signature).
fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let g = crate::tests::TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    azos_config::cfg_load(b"").unwrap();
    g
}

/// RED before `cfg_load_verified` existed: `kernel/src/boot/config_auth.rs` called
/// `azos_config::cfg_load(&buf[..n])` on whatever bytes it read back
/// from `/fat/CONFIG.INI`, unconditionally — this exact "hostile" INI
/// would have armed every one of the four keys below. GREEN now: with
/// `sig_ok = false`, none of the untrusted bytes ever reach `cfg_load`,
/// and every dangerous key reads back at its safe value.
#[test]
fn fail_closed_disarms_every_dangerous_key() {
    let _g = fresh();
    // `estop_gpio_pin=5`, not `255`: this crate's `ESTOP_GPIO_PIN_FAIL_CLOSED`
    // constant IS `255` today (no board in this tree wires a real switch —
    // see that constant's doc), so a hostile value of `255` would pass this
    // assertion whether or not the authority check ran at all. `5` proves
    // the untrusted file's request is IGNORED, not merely that it happens
    // to coincide with the safe value.
    let hostile: &[u8] = b"estop_gpio_pin=5\n\
                            bench_boot=1\n\
                            ota_auto_recv_port=4444\n\
                            autorun=/fat/HIJACK.ELF\n\
                            link_encrypt=0\n";

    let outcome = cfg_load_verified(hostile, false);
    assert_eq!(outcome, ConfigTrust::FailClosed);
    cfg_apply();

    assert_eq!(
        CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed),
        ESTOP_GPIO_PIN_FAIL_CLOSED,
        "kill switch state must not follow the untrusted file's requested pin"
    );
    assert!(
        !CFG_BENCH_BOOT.load(Ordering::Relaxed),
        "bench_boot must not arm — the board must still boot, not halt"
    );
    assert_eq!(
        CFG_OTA_AUTO_RECV_PORT.load(Ordering::Relaxed),
        0,
        "no OTA listener may spawn from an unverified file"
    );
    assert_eq!(
        cfg_get(b"autorun"),
        None,
        "autorun must be refused — the drivetrain goes to nobody, not to HIJACK.ELF"
    );
    assert!(
        CFG_LINK_ENCRYPT.load(Ordering::Relaxed),
        "fail-closed keeps the safer default (AEAD on), not the file's request to disable it"
    );
}

/// A verified INI is loaded and applied exactly as `cfg_load`+`cfg_apply`
/// always have — the signature check must not change ordinary behaviour
/// for a signature that DOES verify.
#[test]
fn verified_ini_loads_normally() {
    let _g = fresh();
    let ini = b"estop_gpio_pin=12\nsched_hz=50\n";
    let outcome = cfg_load_verified(ini, true);
    assert_eq!(outcome, ConfigTrust::Verified);
    assert_eq!(CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed), 12);
    assert_eq!(cfg_get_u32(b"sched_hz", 0), 50);
}

/// `sig_ok = true` with an empty file (nothing was meaningfully signed
/// either way) still falls back to defaults rather than clearing the
/// store to nothing — matches the pre-existing "empty CONFIG.INI ⇒
/// generate defaults" boot behaviour verbatim (`kernel/src/boot/config_auth.rs`'s
/// `n > 0` check), now inside `cfg_load_verified` instead of duplicated
/// at the call site.
#[test]
fn verified_but_empty_falls_back_to_defaults() {
    let _g = fresh();
    let outcome = cfg_load_verified(b"", true);
    assert_eq!(outcome, ConfigTrust::FailClosed);
    assert_eq!(
        CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed),
        ESTOP_GPIO_PIN_FAIL_CLOSED
    );
}

/// End-to-end proof that the SIGNING half (`tools/gen_config_sig.py`) and
/// the VERIFYING half (`azos_topology::verify_signature` against
/// `azos_topology::TRUSTED_PUBKEY`, which `kernel/src/boot/config_auth.rs`'s diff calls
/// before ever calling `cfg_load_verified`) actually agree.
///
/// Fixture: `python3 tools/gen_config_sig.py` was run once, by hand, over
/// the exact 37 bytes below, using `tools/keys/test_priv.bin` (the key
/// `crates/core/topology/build.rs` embeds the public half of by default). The
/// resulting 64-byte signature is pasted as a hex literal so this test
/// has no runtime dependency on Python or the key files being present —
/// it proves the WIRE FORMAT the two tools agree on, not that the tool
/// still runs today. If this test ever needs regenerating: change
/// `INI_FIXTURE`, re-run the command in the comment below, and paste the
/// new hex.
///
/// `azos_config` itself takes no dependency on
/// `azos_topology`/`azos_crypto` (see `signed.rs`'s module doc) —
/// this crate (`config-tests`) already depends on neither, so this test
/// pulls `azos_topology` in directly rather than asking the crate
/// under test to.
#[test]
fn topology_key_verifies_a_python_signed_config_ini() {
    const INI_FIXTURE: &[u8] = b"sched_hz=42\nautorun=/fat/GPIODRV.ELF\n";
    // Generated by:
    //   python3 tools/gen_config_sig.py <fixture written to INI_FIXTURE's
    //   exact bytes> --priv tools/keys/test_priv.bin
    const SIGNATURE_HEX: &str =
        "8537924f501e92fe4d3b8127096c95d76b89feaecbbbca2557fdf08d0e28c1b\
         17037ed3827e5414f5bb287187664ab667544fdb71724535f77b07438f899b2\
         0d";

    let sig_bytes = decode_hex(SIGNATURE_HEX);
    assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 raw bytes");

    let result = azos_topology::verify_signature(
        INI_FIXTURE,
        &sig_bytes,
        &azos_topology::TRUSTED_PUBKEY,
    );
    assert!(
        result.is_ok(),
        "a signature `gen_config_sig.py` produced over these exact bytes \
         with `test_priv.bin` must verify against `TRUSTED_PUBKEY` \
         (`test_pub.bin`'s embedding) — if this fails, either the fixture \
         bytes drifted from what was signed, or `test_priv.bin`/`test_pub.bin` \
         on disk are no longer the pair this hex was generated from \
         (`tools/gen_test_key.py` reuses an existing `test_priv.bin`, so \
         regenerating the pair from scratch would break this test — \
         re-sign the fixture instead of regenerating the key)"
    );

    // And the fail-closed direction: one flipped bit must NOT verify —
    // otherwise this test would pass for a verifier that accepts anything.
    let mut corrupted = sig_bytes.clone();
    corrupted[0] ^= 0x01;
    assert!(azos_topology::verify_signature(
        INI_FIXTURE,
        &corrupted,
        &azos_topology::TRUSTED_PUBKEY,
    )
    .is_err());

    // And a byte-flip in the PAYLOAD must not verify either — the
    // signature covers the exact bytes, not a hash the parser could be
    // fooled about.
    let mut tampered_ini = INI_FIXTURE.to_vec();
    tampered_ini[0] ^= 0x01;
    assert!(azos_topology::verify_signature(
        &tampered_ini,
        &sig_bytes,
        &azos_topology::TRUSTED_PUBKEY,
    )
    .is_err());
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// A signed file that repeats a key is ambiguous: it is NOT loaded, the store
/// holds the factory defaults, and the kill switch is forced to its
/// fail-closed pin, exactly as for an unverified file (wave 11, HERM).
/// Anchored on values only the refusal can produce: `autorun` absent although
/// the first (and second) line set it, and the pin 255 although both lines
/// asked for 5 or 6.
#[test]
fn verified_but_ambiguous_fails_closed() {
    let _g = fresh();
    let ini: &[u8] = b"estop_gpio_pin=5\nautorun=/fat/A.ELF\nestop_gpio_pin=6\n";
    let outcome = cfg_load_verified(ini, true);
    match outcome {
        ConfigTrust::Rejected(e) => assert_eq!(e.key(), b"estop_gpio_pin"),
        other => panic!("expected Rejected, got {:?}", other),
    }
    cfg_apply();
    assert_eq!(
        CFG_ESTOP_GPIO_PIN.load(Ordering::Relaxed),
        ESTOP_GPIO_PIN_FAIL_CLOSED
    );
    assert_eq!(cfg_get(b"autorun"), None, "no line of an ambiguous file runs");
}

// ── Wave 11: replay protection and a fail-closed that latches ─────────────
//
// `config_authority_decision` is the whole policy (RFC-0054 finding 7); the
// kernel only gathers its two inputs. These pin every cell of the table.

mod authority {
    use azos_config::{
        config_after_rejected, config_authority_decision, AuthorityLoss as L, ConfigDecision as D,
        ConfigSigCheck as C, DeviceFloor as F,
    };

    const NOT_VALID: [C; 7] =
        [C::NoIni, C::NoSig, C::NoDeviceId, C::V1, C::BadFormat, C::WrongDevice, C::BadSignature];

    /// No device record: nothing can be loaded (there is no id to bind a
    /// signature to) and nothing latches (no record says a signed file was
    /// ever accepted) — the pre-wave-11 defaults.
    #[test]
    fn an_unprovisioned_device_takes_defaults_and_never_latches() {
        for c in NOT_VALID.iter().copied().chain([C::Valid(5)]) {
            assert!(matches!(config_authority_decision(F::Unprovisioned, c), D::Defaults(_)), "{c:?}");
        }
        assert_eq!(config_authority_decision(F::Unprovisioned, C::NoSig), D::Defaults(L::NoSig));
        assert_eq!(config_after_rejected(F::Unprovisioned), None);
    }

    /// Floor 0 (provisioned, nothing accepted yet): a valid sidecar loads and
    /// raises the floor to its counter; anything else is defaults, no latch.
    #[test]
    fn a_fresh_device_loads_a_valid_file_and_raises_the_floor() {
        assert_eq!(config_authority_decision(F::Provisioned(0), C::Valid(1)), D::Load { counter: 1, raise_floor: true });
        for c in NOT_VALID {
            assert!(matches!(config_authority_decision(F::Provisioned(0), c), D::Defaults(_)), "{c:?}");
        }
        assert_eq!(config_after_rejected(F::Provisioned(0)), None);
    }

    /// **The replay.** Floor 5: counter 5 loads without raising, 6 loads and
    /// raises, 4 — an older, validly signed file — latches as a replay.
    ///
    /// **Canary (by hand, 2026-10-02).** Change the `c >= f` guard to `true`:
    /// red on the counter-4 assertion (it loads).
    #[test]
    fn an_older_counter_is_a_replay_and_latches() {
        assert_eq!(config_authority_decision(F::Provisioned(5), C::Valid(5)), D::Load { counter: 5, raise_floor: false });
        assert_eq!(config_authority_decision(F::Provisioned(5), C::Valid(6)), D::Load { counter: 6, raise_floor: true });
        assert_eq!(config_authority_decision(F::Provisioned(5), C::Valid(4)), D::LatchEstop(L::Replay));
    }

    /// **The deletion.** A device that accepted a signed file before (floor
    /// >= 1) latches on every way of losing it — CONFIG.SIG deleted,
    /// CONFIG.INI deleted, tampered, v1, malformed, another device's — and on
    /// a signed file that repeats a key.
    ///
    /// **Canary (by hand, 2026-10-02).** Make the `_ if f == 0` arm `_ =>`
    /// (always defaults): red on "NoSig did not latch".
    #[test]
    fn a_lost_signature_on_a_provisioned_device_latches() {
        assert_eq!(config_authority_decision(F::Provisioned(1), C::NoSig), D::LatchEstop(L::NoSig), "NoSig did not latch");
        assert_eq!(config_authority_decision(F::Provisioned(1), C::NoIni), D::LatchEstop(L::NoIni));
        for c in NOT_VALID {
            assert!(matches!(config_authority_decision(F::Provisioned(9), c), D::LatchEstop(_)), "{c:?}");
        }
        assert_eq!(config_after_rejected(F::Provisioned(1)), Some(L::Ambiguous));
    }

    /// The durable record's `detail` codes are distinct and never 0.
    #[test]
    fn every_loss_has_its_own_nonzero_code() {
        let all = [L::NoIni, L::NoSig, L::Unprovisioned, L::V1, L::BadFormat, L::WrongDevice,
                   L::BadSignature, L::Replay, L::Ambiguous];
        let mut codes: Vec<u32> = all.iter().map(|l| l.code()).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        assert!(!codes.contains(&0));
    }
}
