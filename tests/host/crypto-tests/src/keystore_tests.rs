// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The keystore (`azos_crypto::keystore`): the policy of a key handle, the
//! derivations, and the sealed forms.
//!
//! **Canaries.** Each refusal is held by a pair: the same handle admitted for
//! the party the policy names and refused for the one it does not, so a
//! check that stopped looking would fail the second half. Compare the owner
//! with nothing (`belongs_to` true): `another_owner_*` and
//! `another_image_*` find the key served. Drop the measurement from
//! `derive_persistent`: `the_image_is_part_of_an_image_bound_key`. Take the
//! tag out of `siv_open`'s comparison: `a_changed_block_does_not_open`.

use azos_crypto::ed25519::sig_verify_message;
use azos_crypto::keystore::*;

const OWNER_A: Principal = Principal { owner_root: 1, measurement: [0xA0; 32] };
const OWNER_A_OTHER_IMAGE: Principal = Principal { owner_root: 1, measurement: [0xB0; 32] };
const OWNER_B: Principal = Principal { owner_root: 2, measurement: [0xA0; 32] };
const SYSTEM: Principal = Principal { owner_root: 0, measurement: [0xA0; 32] };
const ROOT: [u8; 32] = [0x77; 32];
const NO_NAME: [u8; NAME_LEN] = [0; NAME_LEN];

fn name(s: &[u8]) -> [u8; NAME_LEN] {
    let mut n = [0u8; NAME_LEN];
    n[..s.len()].copy_from_slice(s);
    n
}

fn policy(purpose: u8) -> Policy {
    Policy { purpose, envelope: Envelope::Owner, backend: Backend::Volatile, wrappable: false, max_uses: 0, ttl_s: 0 }
}

fn named(purpose: u8, backend: Backend, envelope: Envelope) -> Policy {
    Policy { purpose, envelope, backend, wrappable: false, max_uses: 0, ttl_s: 0 }
}

fn store() -> Keystore<8> {
    Keystore::new(3)
}

fn make(ks: &mut Keystore<8>, who: &Principal, p: Policy) -> u32 {
    ks.insert(who, 0, p, &NO_NAME, &[0x5A; 32]).unwrap()
}

// ── The codes the decision record reads ─────────────────────────────────────

#[test]
fn the_codes_are_the_key_use_records() {
    // `azos_decision::RULES[Rule::KeyUse]`: op 1 sign, 2 decrypt, 3 derive,
    // 4 wrap, 5 export; reason 0 allowed, 1 the key does not allow the op, 2
    // the task is not the key's owner, 3 the uses are used up, 4 expired.
    assert_eq!([Op::Sign as u8, Op::Crypt as u8, Op::Derive as u8, Op::Wrap as u8, Op::Export as u8], [1, 2, 3, 4, 5]);
    assert_eq!(
        [Reason::Allowed as u8, Reason::NotAllowed as u8, Reason::NotOwner as u8, Reason::Exhausted as u8, Reason::Expired as u8],
        [0, 1, 2, 3, 4]
    );
}

// ── Whose key it is ─────────────────────────────────────────────────────────

#[test]
fn the_owner_uses_its_key_and_another_owner_is_refused() {
    let mut ks = store();
    let h = make(&mut ks, &OWNER_A, policy(purpose::SIGN));
    assert!(ks.admit(&OWNER_A, 0, h, purpose::SIGN, true).is_ok());
    // The same handle, from another user: the key is not theirs.
    assert_eq!(ks.admit(&OWNER_B, 0, h, purpose::SIGN, true).err(), Some(Refusal::Refused(Reason::NotOwner)));
    // The system (owner 0) is an owner like another, not a master key.
    assert_eq!(ks.admit(&SYSTEM, 0, h, purpose::SIGN, true).err(), Some(Refusal::Refused(Reason::NotOwner)));
}

#[test]
fn another_image_of_the_owner_is_served_by_an_owner_key_and_refused_by_an_image_key() {
    let mut ks = store();
    let owner_wide = make(&mut ks, &OWNER_A, policy(purpose::SIGN));
    let bound = make(&mut ks, &OWNER_A, Policy { envelope: Envelope::Image, ..policy(purpose::SIGN) });
    assert!(ks.admit(&OWNER_A_OTHER_IMAGE, 0, owner_wide, purpose::SIGN, true).is_ok());
    assert_eq!(
        ks.admit(&OWNER_A_OTHER_IMAGE, 0, bound, purpose::SIGN, true).err(),
        Some(Refusal::Refused(Reason::NotOwner))
    );
    assert!(ks.admit(&OWNER_A, 0, bound, purpose::SIGN, true).is_ok());
}

#[test]
fn a_foreign_caller_cannot_destroy_a_key() {
    let mut ks = store();
    let h = make(&mut ks, &OWNER_A, policy(purpose::SEAL));
    assert_eq!(ks.destroy(&OWNER_B, h), Err(Refusal::Refused(Reason::NotOwner)));
    assert!(ks.admit(&OWNER_A, 0, h, purpose::SEAL, true).is_ok());
    assert_eq!(ks.destroy(&OWNER_A, h), Ok(()));
    assert_eq!(ks.admit(&OWNER_A, 0, h, purpose::SEAL, true).err(), Some(Refusal::NoKey));
}

// ── What the key allows ─────────────────────────────────────────────────────

#[test]
fn a_key_serves_its_purpose_only() {
    let mut ks = store();
    let sign = make(&mut ks, &OWNER_A, policy(purpose::SIGN));
    for other in [purpose::SEAL, purpose::DERIVE, purpose::WRAP] {
        assert_eq!(ks.admit(&OWNER_A, 0, sign, other, true).err(), Some(Refusal::Refused(Reason::NotAllowed)));
    }
    assert!(ks.admit(&OWNER_A, 0, sign, purpose::SIGN, true).is_ok());
}

#[test]
fn a_policy_names_exactly_one_purpose() {
    let mut ks = store();
    for bad in [0u8, purpose::SIGN | purpose::SEAL, 16, 0x80, purpose::ALL] {
        assert_eq!(ks.insert(&OWNER_A, 0, policy(bad), &NO_NAME, &[1; 32]), Err(MakeError::BadPolicy), "purpose {bad:#x}");
    }
    assert_eq!(ks.count_of(1), 0);
}

#[test]
fn only_a_wrappable_key_can_be_taken_for_wrapping() {
    let mut ks = store();
    let plain = make(&mut ks, &OWNER_A, policy(purpose::SEAL));
    let wrappable = make(&mut ks, &OWNER_A, Policy { wrappable: true, ..policy(purpose::SEAL) });
    assert_eq!(
        ks.admit(&OWNER_A, 0, plain, NEED_WRAPPABLE, true).err(),
        Some(Refusal::Refused(Reason::NotAllowed))
    );
    let a = ks.admit(&OWNER_A, 0, wrappable, NEED_WRAPPABLE, true).unwrap();
    assert_eq!(a.policy.purpose, purpose::SEAL, "the wrapped form is bound to the target's purpose");
}

// ── Uses and time ───────────────────────────────────────────────────────────

#[test]
fn the_uses_are_counted_and_the_last_one_is_the_limit() {
    let mut ks = store();
    let h = make(&mut ks, &OWNER_A, Policy { max_uses: 2, ..policy(purpose::SIGN) });
    assert!(ks.admit(&OWNER_A, 0, h, purpose::SIGN, true).is_ok());
    assert!(ks.admit(&OWNER_A, 0, h, purpose::SIGN, true).is_ok());
    assert_eq!(ks.admit(&OWNER_A, 0, h, purpose::SIGN, true).err(), Some(Refusal::Refused(Reason::Exhausted)));
    // Taking the public key is not a use of the secret.
    assert!(ks.admit(&OWNER_A, 0, h, purpose::SIGN, false).is_ok());
}

#[test]
fn a_refused_use_is_not_a_use() {
    let mut ks = store();
    let h = make(&mut ks, &OWNER_A, Policy { max_uses: 1, ..policy(purpose::SIGN) });
    for _ in 0..5 {
        assert!(ks.admit(&OWNER_A, 0, h, purpose::SEAL, true).is_err());
        assert!(ks.admit(&OWNER_B, 0, h, purpose::SIGN, true).is_err());
    }
    assert!(ks.admit(&OWNER_A, 0, h, purpose::SIGN, true).is_ok(), "the one use is still there");
}

#[test]
fn a_handle_expires_and_its_secret_goes() {
    let mut ks = store();
    let h = ks.insert(&OWNER_A, 100, Policy { ttl_s: 10, ..policy(purpose::SIGN) }, &NO_NAME, &[9; 32]).unwrap();
    assert!(ks.admit(&OWNER_A, 109, h, purpose::SIGN, true).is_ok());
    assert_eq!(ks.admit(&OWNER_A, 110, h, purpose::SIGN, true).err(), Some(Refusal::Refused(Reason::Expired)));
    // It stays expired: time does not run back, and the secret was wiped.
    assert_eq!(ks.admit(&OWNER_A, 105, h, purpose::SIGN, true).err(), Some(Refusal::Refused(Reason::Expired)));
    // To anyone else it is still not their key, whatever its age.
    assert_eq!(ks.admit(&OWNER_B, 200, h, purpose::SIGN, true).err(), Some(Refusal::Refused(Reason::NotOwner)));
}

#[test]
fn an_expired_slot_is_reused_with_a_new_handle() {
    let mut ks: Keystore<1> = Keystore::new(1);
    let old = ks.insert(&OWNER_A, 0, Policy { ttl_s: 5, ..policy(purpose::SIGN) }, &NO_NAME, &[1; 32]).unwrap();
    assert_eq!(ks.insert(&OWNER_A, 1, policy(purpose::SIGN), &NO_NAME, &[2; 32]), Err(MakeError::Full));
    let new = ks.insert(&OWNER_A, 6, policy(purpose::SIGN), &NO_NAME, &[2; 32]).unwrap();
    assert_ne!(old, new, "a handle is not reused with its slot");
    assert_eq!(ks.admit(&OWNER_A, 6, old, purpose::SIGN, true).err(), Some(Refusal::NoKey));
    assert_eq!(*ks.admit(&OWNER_A, 6, new, purpose::SIGN, true).unwrap().secret(), [2; 32]);
}

#[test]
fn a_child_does_not_outlive_its_parent() {
    let parent = policy(purpose::DERIVE);
    // A parent with no expiry leaves the child's own ttl.
    let c = child_policy(&parent, 0, &Policy { ttl_s: 30, ..policy(purpose::SEAL) }).unwrap();
    assert_eq!(c.ttl_s, 30);
    // A parent with 10 s left caps it, and a child that asked for none gets what is left.
    assert_eq!(child_policy(&parent, 10, &Policy { ttl_s: 30, ..policy(purpose::SEAL) }).unwrap().ttl_s, 10);
    assert_eq!(child_policy(&parent, 10, &policy(purpose::SEAL)).unwrap().ttl_s, 10);
    assert_eq!(child_policy(&parent, 10, &Policy { ttl_s: 3, ..policy(purpose::SEAL) }).unwrap().ttl_s, 3);
}

#[test]
fn a_child_is_volatile_and_its_envelope_is_not_wider() {
    let image_parent = Policy { envelope: Envelope::Image, ..policy(purpose::DERIVE) };
    assert!(child_policy(&image_parent, 0, &policy(purpose::SEAL)).is_none(), "an image key cannot beget an owner-wide one");
    assert!(child_policy(&image_parent, 0, &Policy { envelope: Envelope::Image, ..policy(purpose::SEAL) }).is_some());
    let owner_parent = policy(purpose::DERIVE);
    assert!(child_policy(&owner_parent, 0, &Policy { envelope: Envelope::Image, ..policy(purpose::SEAL) }).is_some());
    assert!(child_policy(&owner_parent, 0, &named(purpose::SEAL, Backend::Boot, Envelope::Owner)).is_none());
    assert!(child_policy(&owner_parent, 0, &policy(purpose::SEAL | purpose::SIGN)).is_none());
}

// ── The table ───────────────────────────────────────────────────────────────

#[test]
fn an_owner_holds_its_share_and_no_more() {
    let mut ks = store(); // 3 per owner
    for _ in 0..3 {
        make(&mut ks, &OWNER_A, policy(purpose::SEAL));
    }
    assert_eq!(ks.insert(&OWNER_A, 0, policy(purpose::SEAL), &NO_NAME, &[1; 32]), Err(MakeError::Full));
    // Another owner is not held back by it.
    assert!(ks.insert(&OWNER_B, 0, policy(purpose::SEAL), &NO_NAME, &[1; 32]).is_ok());
    assert_eq!(ks.count_of(1), 3);
    assert_eq!(ks.count_of(2), 1);
}

#[test]
fn a_full_table_refuses_and_a_destroyed_slot_is_reused() {
    let mut ks: Keystore<2> = Keystore::new(2);
    let a = ks.insert(&OWNER_A, 0, policy(purpose::SEAL), &NO_NAME, &[1; 32]).unwrap();
    let _b = ks.insert(&OWNER_B, 0, policy(purpose::SEAL), &NO_NAME, &[2; 32]).unwrap();
    assert_eq!(ks.insert(&OWNER_A, 0, policy(purpose::SEAL), &NO_NAME, &[3; 32]), Err(MakeError::Full));
    ks.destroy(&OWNER_A, a).unwrap();
    assert!(ks.insert(&OWNER_A, 0, policy(purpose::SEAL), &NO_NAME, &[3; 32]).is_ok());
    assert_eq!(ks.admit(&OWNER_A, 0, a, purpose::SEAL, true).err(), Some(Refusal::NoKey), "the old handle is stale");
}

#[test]
fn handles_that_were_never_made_are_no_key() {
    let mut ks = store();
    let h = make(&mut ks, &OWNER_A, policy(purpose::SEAL));
    for bad in [0u32, 1, 0xFFFF_FFFF, h ^ 0x100, (h & 0xFF) + 8] {
        if bad == h {
            continue;
        }
        assert_eq!(ks.admit(&OWNER_A, 0, bad, purpose::SEAL, true).err(), Some(Refusal::NoKey), "handle {bad:#x}");
    }
}

#[test]
fn a_named_key_opens_to_the_same_handle_and_a_changed_policy_is_refused() {
    let mut ks = store();
    let p = named(purpose::SIGN, Backend::Boot, Envelope::Image);
    let n = name(b"sshd.host");
    let h1 = ks.insert(&OWNER_A, 0, p, &n, &[4; 32]).unwrap();
    let h2 = ks.insert(&OWNER_A, 1, p, &n, &[4; 32]).unwrap();
    assert_eq!(h1, h2, "opening it again (a restart) is not a second key");
    assert_eq!(ks.count_of(1), 1);
    assert_eq!(ks.insert(&OWNER_A, 1, Policy { max_uses: 5, ..p }, &n, &[4; 32]), Err(MakeError::Mismatch));
    // Another image of the same owner gets its own key by that name; so does another owner.
    assert_ne!(ks.insert(&OWNER_A_OTHER_IMAGE, 0, p, &n, &[5; 32]).unwrap(), h1);
    assert_ne!(ks.insert(&OWNER_B, 0, p, &n, &[6; 32]).unwrap(), h1);
}

#[test]
fn a_name_and_the_backend_go_together() {
    let mut ks = store();
    // A volatile key has no name; a persistent one needs one.
    assert_eq!(
        ks.insert(&OWNER_A, 0, policy(purpose::SIGN), &name(b"x"), &[1; 32]),
        Err(MakeError::BadPolicy)
    );
    assert_eq!(
        ks.insert(&OWNER_A, 0, named(purpose::SIGN, Backend::Boot, Envelope::Owner), &NO_NAME, &[1; 32]),
        Err(MakeError::BadPolicy)
    );
}

#[test]
fn remaining_time_is_what_a_child_inherits() {
    let mut ks = store();
    let h = ks.insert(&OWNER_A, 100, Policy { ttl_s: 60, ..policy(purpose::DERIVE) }, &NO_NAME, &[1; 32]).unwrap();
    assert_eq!(ks.remaining_s(h, 100), Some(60));
    assert_eq!(ks.remaining_s(h, 130), Some(30));
    let forever = make(&mut ks, &OWNER_A, policy(purpose::DERIVE));
    assert_eq!(ks.remaining_s(forever, 5), Some(0));
    assert_eq!(ks.remaining_s(0x4242_4200, 0), None);
}

// ── Where a persistent secret comes from ────────────────────────────────────

#[test]
fn a_persistent_key_is_the_same_at_every_call() {
    let p = named(purpose::SIGN, Backend::Boot, Envelope::Owner);
    let a = derive_persistent(&ROOT, &OWNER_A, &p, &name(b"host")).unwrap();
    assert_eq!(a, derive_persistent(&ROOT, &OWNER_A, &p, &name(b"host")).unwrap());
    assert_ne!(a, [0; 32]);
}

#[test]
fn a_persistent_key_follows_its_root_owner_name_and_purpose() {
    let p = named(purpose::SIGN, Backend::Boot, Envelope::Owner);
    let base = derive_persistent(&ROOT, &OWNER_A, &p, &name(b"host")).unwrap();
    assert_ne!(base, derive_persistent(&[0x78; 32], &OWNER_A, &p, &name(b"host")).unwrap(), "another board");
    assert_ne!(base, derive_persistent(&ROOT, &OWNER_B, &p, &name(b"host")).unwrap(), "another owner");
    assert_ne!(base, derive_persistent(&ROOT, &OWNER_A, &p, &name(b"hosu")).unwrap(), "another name");
    let seal = named(purpose::SEAL, Backend::Boot, Envelope::Owner);
    assert_ne!(base, derive_persistent(&ROOT, &OWNER_A, &seal, &name(b"host")).unwrap(), "another purpose");
}

#[test]
fn the_image_is_part_of_an_image_bound_key() {
    let img = named(purpose::SIGN, Backend::Boot, Envelope::Image);
    let own = named(purpose::SIGN, Backend::Boot, Envelope::Owner);
    let a = derive_persistent(&ROOT, &OWNER_A, &img, &name(b"host")).unwrap();
    let b = derive_persistent(&ROOT, &OWNER_A_OTHER_IMAGE, &img, &name(b"host")).unwrap();
    assert_ne!(a, b, "another image, another key");
    // An owner-wide key is the same for both images, and not the image-bound one.
    let w1 = derive_persistent(&ROOT, &OWNER_A, &own, &name(b"host")).unwrap();
    let w2 = derive_persistent(&ROOT, &OWNER_A_OTHER_IMAGE, &own, &name(b"host")).unwrap();
    assert_eq!(w1, w2);
    assert_ne!(w1, a);
}

#[test]
fn no_root_no_key() {
    let p = named(purpose::SIGN, Backend::Boot, Envelope::Owner);
    assert_eq!(derive_persistent(&[0; 32], &OWNER_A, &p, &name(b"host")), None, "an unprovisioned board derives nothing");
    assert_eq!(derive_persistent(&ROOT, &OWNER_A, &policy(purpose::SIGN), &NO_NAME), None, "a volatile key has no root");
}

#[test]
fn the_roots_are_indexed_by_backend() {
    assert_eq!(Backend::Volatile.root_index(), None);
    let idx = [Backend::Boot, Backend::TpmNv, Backend::Volume].map(|b| b.root_index().unwrap());
    assert_eq!(idx, [0, 1, 2]);
    assert_eq!(ROOTS, 3);
    for v in 0..4u8 {
        assert_eq!(Backend::from_u8(v).unwrap() as u8, v);
    }
    assert!(Backend::from_u8(4).is_none() && Envelope::from_u8(2).is_none());
}

#[test]
fn a_child_follows_its_parent_label_and_purpose() {
    let parent = [0x33; 32];
    let c = derive_child(&parent, &name(b"wrap"), purpose::SEAL);
    assert_eq!(c, derive_child(&parent, &name(b"wrap"), purpose::SEAL));
    assert_ne!(c, derive_child(&[0x34; 32], &name(b"wrap"), purpose::SEAL), "another parent");
    assert_ne!(c, derive_child(&parent, &name(b"wrap2"), purpose::SEAL), "another label");
    assert_ne!(c, derive_child(&parent, &name(b"wrap"), purpose::SIGN), "another purpose");
    assert_ne!(c, parent);
}

/// The verifier of a console credential follows the board, the user, the name
/// and the credential, and nothing else; it is not a key a handle can open.
///
/// **Canary.** Leave `owner_root` out of the record key's info: the "another
/// user" line finds the same verifier.
#[test]
fn a_console_verifier_follows_board_user_name_and_credential() {
    let cred = [0x5a; 32];
    let base = login_public(&ROOT, 1, &name(b"alice"), &cred).unwrap();
    assert_eq!(base, login_public(&ROOT, 1, &name(b"alice"), &cred).unwrap(), "the same at every call");
    assert_ne!(base, login_public(&[0x78; 32], 1, &name(b"alice"), &cred).unwrap(), "another board");
    assert_ne!(base, login_public(&ROOT, 2, &name(b"alice"), &cred).unwrap(), "another user");
    assert_ne!(base, login_public(&ROOT, 1, &name(b"alicf"), &cred).unwrap(), "another name");
    assert_ne!(base, login_public(&ROOT, 1, &name(b"alice"), &[0x5b; 32]).unwrap(), "another credential");
    assert_eq!(login_public(&[0; 32], 1, &name(b"alice"), &cred), None, "an unprovisioned board verifies nothing");
    // No handle reaches it: a named key of the same owner and name, whatever its
    // purpose, is another key.
    for pur in [purpose::SIGN, purpose::DERIVE] {
        let p = named(pur, Backend::Boot, Envelope::Owner);
        let k = derive_persistent(&ROOT, &Principal { owner_root: 1, measurement: [0; 32] }, &p, &name(b"alice")).unwrap();
        assert_ne!(public_key(&k), base);
    }
}

// ── Using a secret ──────────────────────────────────────────────────────────

#[test]
fn signing_is_rfc_8032() {
    // RFC 8032 section 7.1, TEST 1 (empty message).
    let seed = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert_eq!(public_key(&seed), pk);
    let sig = sign(&seed, b"");
    let want = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    assert_eq!(hex(&sig), want);
    assert!(sig_verify_message(&pk, &sig, b""));
    assert!(!sig_verify_message(&pk, &sig, b"x"));
}

#[test]
fn a_block_sealed_under_a_key_opens_under_it() {
    let key = [0x21; 32];
    let data = [0x99; 32];
    let blob = siv_seal(&key, AAD_DATA, &data);
    assert_eq!(blob.len(), SEALED_LEN);
    assert_ne!(&blob[..32], &data[..], "the data is not in the clear");
    assert_eq!(siv_open(&key, AAD_DATA, &blob), Some(data));
    assert_eq!(blob, siv_seal(&key, AAD_DATA, &data), "deterministic: the nonce is the tag's");
    assert_ne!(blob, siv_seal(&key, AAD_DATA, &[0x98; 32]));
}

#[test]
fn a_block_opens_only_under_its_key_and_its_aad() {
    let key = [0x21; 32];
    let blob = siv_seal(&key, purpose::SIGN, &[7; 32]);
    assert_eq!(siv_open(&key, purpose::SIGN, &blob), Some([7; 32]));
    assert_eq!(siv_open(&[0x22; 32], purpose::SIGN, &blob), None, "another key");
    assert_eq!(siv_open(&key, purpose::SEAL, &blob), None, "another aad: a key wrapped as a signer is not a sealer");
    assert_eq!(siv_open(&key, AAD_DATA, &blob), None, "nor is it data");
}

#[test]
fn a_changed_block_does_not_open() {
    let key = [0x21; 32];
    let blob = siv_seal(&key, AAD_DATA, &[7; 32]);
    for i in 0..SEALED_LEN {
        for bit in [0x01u8, 0x80] {
            let mut bad = blob;
            bad[i] ^= bit;
            assert_eq!(siv_open(&key, AAD_DATA, &bad), None, "byte {i} bit {bit:#x}");
        }
    }
}

#[test]
fn a_wrapped_key_comes_back_as_the_same_secret() {
    // The path of `wrap` then `unwrap`: the target's purpose is the aad, and
    // the unwrapper finds it by trying the four.
    let wrapping = derive_child(&[1; 32], &name(b"w"), purpose::WRAP);
    let target = [0x5C; 32];
    let blob = siv_seal(&wrapping, purpose::SIGN, &target);
    let found: Vec<u8> = [purpose::SIGN, purpose::SEAL, purpose::DERIVE, purpose::WRAP]
        .into_iter()
        .filter(|&p| siv_open(&wrapping, p, &blob) == Some(target))
        .collect();
    assert_eq!(found, vec![purpose::SIGN]);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, c) in o.iter_mut().enumerate() {
        *c = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    o
}
