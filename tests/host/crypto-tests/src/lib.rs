// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side crypto primitive tests using public NIST / RFC vectors.
//!
//! Sources:
//! - SHA-256:  NIST FIPS 180-4 §6.2.1 example digests.
//! - AES-128:  NIST FIPS 197 Appendix B (single-block) and OpenSSL
//!             evp test vectors for AES-CTR.
//! - X25519:   IETF RFC 7748 §5.2 test vectors.
//! - Ed25519:  the in-tree `sig_verify` is currently a HMAC-SHA256
//!             stub per its own doc comment ("For production:
//!             replace with full Ed25519 verify using curve25519
//!             arithmetic"). The tests here pin the stub's wire
//!             behaviour so when the real Ed25519 lands the
//!             change is detectable — see task #212 for the
//!             replacement.
//! - Entropy pool: RFC 4231 for its HMAC; see `entropy_tests` for the DRBG.

#[cfg(test)]
mod entropy_tests;

#[cfg(test)]
mod sha256_tests {
    use azos_crypto::sha256::{sha256, Sha256};

    /// Decode an ASCII hex string into a fixed-size byte array.
    fn hex_to_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars for 32 bytes");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// NIST FIPS 180-4 Appendix A.1 — short message test.
    #[test]
    fn nist_short_abc() {
        let want = hex_to_32(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(sha256(b"abc"), want);
    }

    /// SHA-256 of the empty string — well-known.
    #[test]
    fn empty_string() {
        let want = hex_to_32(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(sha256(b""), want);
    }

    /// NIST FIPS 180-4 Appendix A.1 — 56-byte (one-block boundary) message.
    #[test]
    fn nist_two_block_message() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let want = hex_to_32(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        assert_eq!(sha256(msg), want);
    }

    /// Streaming API must agree with the one-shot helper.
    #[test]
    fn incremental_matches_one_shot() {
        let chunks: &[&[u8]] = &[b"the quick brown ", b"fox jumps over ", b"the lazy dog"];
        let mut h = Sha256::new();
        for c in chunks {
            h.update(c);
        }
        let incremental = h.finalize();

        let mut joined = Vec::new();
        for c in chunks {
            joined.extend_from_slice(c);
        }
        let one_shot = sha256(&joined);
        assert_eq!(incremental, one_shot);
    }

    /// 1 MiB of zeros — exercises the multi-block path + length encoding.
    #[test]
    fn one_megabyte_of_zeros() {
        let buf = vec![0u8; 1024 * 1024];
        let d = sha256(&buf);
        // OpenSSL: sha256 of 1 MiB of zeros.
        let want = hex_to_32(
            "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58",
        );
        assert_eq!(d, want);
    }
}

#[cfg(test)]
mod aes128_tests {
    use azos_crypto::aes::{Aes128, AES_BLOCK_SIZE, AES_KEY_SIZE};

    fn hex_to_n<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// FIPS 197 Appendix B example — single-block ECB encrypt.
    #[test]
    fn fips197_appendix_b_single_block() {
        let key:   [u8; AES_KEY_SIZE]   = hex_to_n("000102030405060708090a0b0c0d0e0f");
        let pt:    [u8; AES_BLOCK_SIZE] = hex_to_n("00112233445566778899aabbccddeeff");
        let want:  [u8; AES_BLOCK_SIZE] = hex_to_n("69c4e0d86a7b0430d8cdb78070b4c55a");
        let mut block = pt;
        Aes128::new(&key).encrypt_block(&mut block);
        assert_eq!(block, want);
    }

    /// AES-CTR round-trip: encrypt then decrypt must recover plaintext.
    #[test]
    fn ctr_round_trip_recovers_plaintext() {
        let key   = hex_to_n::<AES_KEY_SIZE>("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex_to_n::<12>("f0f1f2f3f4f5f6f7f8f9fafb");
        let plaintext = b"the quick brown fox jumps over the lazy dog \
                          which is exactly 64 bytes of test data here.";
        let mut buf = plaintext.to_vec();
        Aes128::new(&key).ctr_encrypt(&nonce, &mut buf);
        // Ciphertext must differ from plaintext (catches no-op impl).
        assert_ne!(buf.as_slice(), plaintext);
        Aes128::new(&key).ctr_decrypt(&nonce, &mut buf);
        assert_eq!(buf.as_slice(), plaintext);
    }

    /// CTR is just XOR with the keystream, so encrypting twice with
    /// the same key+nonce returns the plaintext.
    #[test]
    fn ctr_self_inverse() {
        let key   = [0xAAu8; AES_KEY_SIZE];
        let nonce = [0x55u8; 12];
        let msg = [0xFFu8; 100];
        let mut buf = msg;
        let cipher = Aes128::new(&key);
        cipher.ctr_encrypt(&nonce, &mut buf);
        cipher.ctr_encrypt(&nonce, &mut buf);
        assert_eq!(buf, msg);
    }

    /// Different nonces must produce different ciphertexts.
    #[test]
    fn ctr_nonce_changes_keystream() {
        let key   = [0xAAu8; AES_KEY_SIZE];
        let nonce_a = [0x01u8; 12];
        let nonce_b = [0x02u8; 12];
        let cipher = Aes128::new(&key);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        cipher.ctr_encrypt(&nonce_a, &mut a);
        cipher.ctr_encrypt(&nonce_b, &mut b);
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod x25519_tests {
    use azos_crypto::x25519::{x25519, x25519_pubkey, BASEPOINT};

    fn hex_to_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// RFC 7748 §5.2 test vector 1 — scalar multiplication on an
    /// arbitrary u-coordinate.
    #[test]
    fn rfc7748_test_vector_1() {
        let scalar = hex_to_32(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );
        let u_in = hex_to_32(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        );
        let want = hex_to_32(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );
        assert_eq!(x25519(&scalar, &u_in), want);
    }

    /// RFC 7748 §5.2 test vector 2.
    #[test]
    fn rfc7748_test_vector_2() {
        let scalar = hex_to_32(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        );
        let u_in = hex_to_32(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        );
        let want = hex_to_32(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        );
        assert_eq!(x25519(&scalar, &u_in), want);
    }

    /// RFC 7748 §6.1 — Alice's public key derived from her private.
    /// (Tests `x25519_pubkey`, which is `x25519(priv, BASEPOINT)`.)
    #[test]
    fn rfc7748_alice_keygen() {
        let alice_priv = hex_to_32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        );
        let alice_pub_want = hex_to_32(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        );
        assert_eq!(x25519_pubkey(&alice_priv), alice_pub_want);
    }

    /// RFC 7748 §6.1 — Bob's keypair.
    #[test]
    fn rfc7748_bob_keygen() {
        let bob_priv = hex_to_32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        );
        let bob_pub_want = hex_to_32(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        );
        assert_eq!(x25519_pubkey(&bob_priv), bob_pub_want);
    }

    /// RFC 7748 §6.1 — Alice and Bob's shared secret matches both
    /// derivation paths.  This is the actual DH agreement test.
    #[test]
    fn rfc7748_diffie_hellman_agreement() {
        let alice_priv = hex_to_32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        );
        let bob_priv = hex_to_32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        );
        let alice_pub = x25519_pubkey(&alice_priv);
        let bob_pub   = x25519_pubkey(&bob_priv);

        let shared_a = x25519(&alice_priv, &bob_pub);
        let shared_b = x25519(&bob_priv,   &alice_pub);
        assert_eq!(shared_a, shared_b);

        let shared_want = hex_to_32(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        );
        assert_eq!(shared_a, shared_want);
    }

    /// BASEPOINT const must equal `[9, 0, ..., 0]` per the curve def.
    #[test]
    fn basepoint_is_nine_then_zeros() {
        assert_eq!(BASEPOINT[0], 9);
        assert_eq!(&BASEPOINT[1..], &[0u8; 31][..]);
    }
}

#[cfg(test)]
mod ed25519_tests {
    //! Real Ed25519 verify tests using RFC 8032 §7.1 vectors.
    //! Task #213 replaced the HMAC-SHA256 stub with ed25519-dalek;
    //! these tests prove the swap landed correctly and catch any
    //! future regression (e.g. accidental revert to the stub).

    use azos_crypto::ed25519::{
        sig_parse_header, sig_verify, sig_verify_manifest, manifest_message,
        SIG_ALGORITHM_ED25519, SIG_ALGORITHM_MANIFEST_V1, SIG_HEADER_SIZE, SIG_MAGIC,
        ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, MANIFEST_MESSAGE_SIZE,
    };
    use ed25519_dalek::{Signer, SigningKey};

    /// A well-formed signature header with a chosen algorithm byte.
    fn header_with_algorithm(alg: u8) -> [u8; SIG_HEADER_SIZE] {
        let mut h = [0u8; SIG_HEADER_SIZE];
        h[0..4].copy_from_slice(&SIG_MAGIC);
        h[4] = alg;
        // The key, signature and payload-size/fw_version fields are left
        // zero: this test is about the header gate, which runs before any
        // of them is read.
        h
    }

    /// **The algorithm byte is refused, not merely recorded.**
    ///
    /// `sig_parse_header` read `data[4]` into `FirmwareSignature::algorithm`
    /// and compared it against nothing, while `crates/core/ota/src/secure_boot.rs`
    /// documented in two places that the parse fails on a bad "magic/version".
    /// The check those comments describe did not exist until 2026-09-19.
    ///
    /// 2026-09-26: the supported algorithm bumped from `SIG_ALGORITHM_ED25519`
    /// (0, raw-image signing, no version binding) to
    /// `SIG_ALGORITHM_MANIFEST_V1` (1, signs `{fw_version, payload_size,
    /// sha256}` — see U09-4/U11-4/security finding #10). The legacy byte must
    /// now be REFUSED like any other unsupported algorithm — a `.SIG` with
    /// no version binding must not silently parse with an implicit version of
    /// 0, which would then fail every legitimate install once a floor is set.
    ///
    /// **Canary.** Delete the `data[4] != SIG_ALGORITHM_MANIFEST_V1` arm in
    /// `sig_parse_header`: every non-zero byte below parses and this fails.
    #[test]
    fn a_signature_header_naming_another_algorithm_is_refused() {
        // The one algorithm this kernel implements parses.
        let ok = header_with_algorithm(SIG_ALGORITHM_MANIFEST_V1);
        assert!(
            sig_parse_header(&ok).is_some(),
            "the supported algorithm must still parse — a refusal here would \
             reject every signature `tools/sign_ota.py` produces",
        );

        // Anything else does not, INCLUDING the legacy raw-image byte (0):
        // that format has no version binding and must not be treated as an
        // equally-trustworthy signature.
        for alg in [SIG_ALGORITHM_ED25519, 2, 7, 0x80, 0xFF] {
            assert!(
                sig_parse_header(&header_with_algorithm(alg)).is_none(),
                "algorithm byte {alg:#x} must be refused, not parsed and ignored",
            );
        }
    }

    /// A real signing key (test-generated, deterministic seed — signing is
    /// deterministic per RFC 8032, no RNG needed) for the manifest tests
    /// below, plus a helper that signs `{fw_version, payload_size, sha256}`
    /// exactly the way `tools/sign_ota.py` does.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn sign_manifest(
        sk: &SigningKey, fw_version: u32, payload_size: u32, digest: &[u8; 32],
    ) -> [u8; ED25519_SIGNATURE_SIZE] {
        let msg = manifest_message(fw_version, payload_size, digest);
        sk.sign(&msg).to_bytes()
    }

    /// **The core U09-4/U11-4 property: the signature binds the version.**
    ///
    /// Same image (same sha256), same signer, same `payload_size` — only
    /// `fw_version` differs between what was signed and what is checked.
    /// The manifest scheme must reject a version that was not the one
    /// actually signed, which is the property the OLD raw-image scheme
    /// (sign the image only, version travels unsigned on the wire) never
    /// had: with that scheme ANY claimed version "verifies", because
    /// nothing about the version was ever checked against the signature.
    ///
    /// RED without the fix: drop `fw_version`/`payload_size` from
    /// `manifest_message` (bind the signature to the image only) and this
    /// test's rollback-bypass assertion starts failing — a signature for
    /// version 5 would then also "verify" a claim of version 999.
    #[test]
    fn a_verified_manifest_signature_is_bound_to_its_own_version() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let pk: [u8; ED25519_PUBLIC_KEY_SIZE] = vk.to_bytes();

        let digest = [0x11u8; 32]; // stand-in for sha256(image)
        let signed_version = 5u32;
        let payload_size = 4096u32;
        let sig = sign_manifest(&sk, signed_version, payload_size, &digest);

        // The exact manifest that was signed verifies.
        assert!(sig_verify_manifest(&pk, &sig, signed_version, payload_size, &digest));

        // A different CLAIMED version over the same image/signature does
        // not. This is the anti-rollback bypass U09-4 describes, made
        // concrete: an attacker cannot take a validly-signed v5 image and
        // relabel it v999 to sail over a floor of, say, 10.
        assert!(!sig_verify_manifest(&pk, &sig, 999, payload_size, &digest));
        assert!(!sig_verify_manifest(&pk, &sig, 0, payload_size, &digest));

        // Nor can `payload_size` or the image hash be changed independently.
        assert!(!sig_verify_manifest(&pk, &sig, signed_version, payload_size + 1, &digest));
        let mut other_digest = digest;
        other_digest[0] ^= 1;
        assert!(!sig_verify_manifest(&pk, &sig, signed_version, payload_size, &other_digest));
    }

    /// `manifest_message` must actually be `MANIFEST_MESSAGE_SIZE` (40)
    /// bytes and lay the three fields out in the documented order — pins
    /// the wire format `tools/sign_ota.py` has to match byte-for-byte.
    #[test]
    fn manifest_message_layout_is_version_then_size_then_hash() {
        let digest = [0xAAu8; 32];
        let msg = manifest_message(0x0102_0304, 0x0506_0708, &digest);
        assert_eq!(msg.len(), MANIFEST_MESSAGE_SIZE);
        assert_eq!(msg.len(), 40);
        assert_eq!(&msg[0..4], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&msg[4..8], &0x0506_0708u32.to_le_bytes());
        assert_eq!(&msg[8..40], &digest[..]);
    }

    /// The gate runs BEFORE the key and signature fields are read, so a header
    /// that is too short for them is still refused by length first. Pins the
    /// ordering: an algorithm check placed after the field reads would be a
    /// bounds bug rather than a defence.
    #[test]
    fn the_length_gate_still_runs_before_the_algorithm_gate() {
        let full = header_with_algorithm(SIG_ALGORITHM_ED25519);
        for n in [0usize, 1, 4, 5, SIG_HEADER_SIZE - 1] {
            assert!(sig_parse_header(&full[..n]).is_none(), "len {n} must be refused");
        }
    }

    fn hex_to<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    // RFC 8032 §7.1 test vector 1 — empty message.
    const RFC8032_TV1_PUBKEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_TV1_SIG: &str =
        "e5564300c360ac729086e2cc806e828a\
         84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46b\
         d25bf5f0595bbe24655141438e7a100b";

    // RFC 8032 §7.1 test vector 2 — one-byte message 0x72.
    const RFC8032_TV2_PUBKEY: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const RFC8032_TV2_SIG: &str =
        "92a009a9f0d4cab8720e820b5f642540\
         a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c\
         387b2eaeb4302aeeb00d291612bb0c00";
    const RFC8032_TV2_MSG: u8 = 0x72;

    #[test]
    fn rfc8032_tv1_empty_message_verifies() {
        let pk:  [u8; ED25519_PUBLIC_KEY_SIZE] = hex_to(RFC8032_TV1_PUBKEY);
        let sig: [u8; ED25519_SIGNATURE_SIZE]  = hex_to(RFC8032_TV1_SIG);
        assert!(sig_verify(&pk, &sig, b""),
            "RFC 8032 §7.1 vector 1 must verify with the real Ed25519 \
             implementation. If this fails, sig_verify regressed to the \
             HMAC stub or ed25519-dalek was removed (#213).");
    }

    #[test]
    fn rfc8032_tv2_one_byte_message_verifies() {
        let pk:  [u8; ED25519_PUBLIC_KEY_SIZE] = hex_to(RFC8032_TV2_PUBKEY);
        let sig: [u8; ED25519_SIGNATURE_SIZE]  = hex_to(RFC8032_TV2_SIG);
        assert!(sig_verify(&pk, &sig, &[RFC8032_TV2_MSG]));
    }

    #[test]
    fn tampered_signature_rejected() {
        let pk:      [u8; ED25519_PUBLIC_KEY_SIZE] = hex_to(RFC8032_TV1_PUBKEY);
        let mut sig: [u8; ED25519_SIGNATURE_SIZE]  = hex_to(RFC8032_TV1_SIG);
        sig[0] ^= 1; // flip one bit
        assert!(!sig_verify(&pk, &sig, b""));
    }

    #[test]
    fn tampered_message_rejected() {
        // Vector 2 with the message byte changed must fail.
        let pk:  [u8; ED25519_PUBLIC_KEY_SIZE] = hex_to(RFC8032_TV2_PUBKEY);
        let sig: [u8; ED25519_SIGNATURE_SIZE]  = hex_to(RFC8032_TV2_SIG);
        assert!(!sig_verify(&pk, &sig, &[RFC8032_TV2_MSG ^ 1]));
    }

    #[test]
    fn tampered_pubkey_rejected() {
        let mut pk: [u8; ED25519_PUBLIC_KEY_SIZE] = hex_to(RFC8032_TV1_PUBKEY);
        let sig:    [u8; ED25519_SIGNATURE_SIZE]  = hex_to(RFC8032_TV1_SIG);
        pk[0] ^= 1;
        assert!(!sig_verify(&pk, &sig, b""));
    }

    #[test]
    fn oversized_firmware_rejected() {
        let pk = [0u8; ED25519_PUBLIC_KEY_SIZE];
        let sig = [0u8; ED25519_SIGNATURE_SIZE];
        // `sig_verify` now bounds a MESSAGE, not a whole firmware image
        // (renamed `MAX_VERIFY_SIZE` -> `MAX_VERIFY_MESSAGE_SIZE`, U09-14):
        // the manifest scheme signs a fixed 40-byte `{fw_version,
        // payload_size, sha256}` tuple, never the image itself. Still
        // exercises the same over-length rejection, at the new bound.
        let too_big = vec![0u8; azos_crypto::ed25519::MAX_VERIFY_MESSAGE_SIZE + 1];
        assert!(!sig_verify(&pk, &sig, &too_big));
    }

    #[test]
    fn malformed_pubkey_rejected() {
        // All-zeros is not a valid Ed25519 public key (point at
        // infinity is not on the curve in compressed encoding).
        // ed25519-dalek's from_bytes catches this.
        let pk_zero = [0u8; ED25519_PUBLIC_KEY_SIZE];
        let sig:    [u8; ED25519_SIGNATURE_SIZE]  = hex_to(RFC8032_TV1_SIG);
        // Note: depending on dalek version, the all-zero pubkey may
        // parse successfully but verify always fails — we just check
        // that the empty-message vector does NOT verify under it.
        assert!(!sig_verify(&pk_zero, &sig, b""));
    }
}
