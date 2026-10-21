// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Command encodings against hand-built vectors, response decoding, the
//! rollback floor. Every command runs over every transport.

use crate::*;
use azos_tpm::tpm::{StartupType, FLOOR_ATTRS, FLOOR_INDEX, SECRET_ATTRS, SECRET_BYTES, SECRET_INDEX};
use azos_tpm::Error;

const AUTH_AREA_EMPTY: &str = "00 00 00 09 40 00 00 09 00 00 01 00 00";
const SESSION_RSP_TAIL: &str = "00 00 00 00 00 00 01 00 00";

fn digest_hex() -> String {
    (0..32).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ")
}

#[test]
fn startup_state_encodes_su_state() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(
            "80 01 00 00 00 0C 00 00 01 44 00 01",
            "80 01 00 00 00 0A 00 00 00 00",
        );
        t.startup(StartupType::State).unwrap();
        r.assert_clean();
    }
}

#[test]
fn get_random_small_and_chunked() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(
            "80 01 00 00 00 0C 00 00 01 7B 00 08",
            "80 01 00 00 00 14 00 00 00 00 00 08 01 02 03 04 05 06 07 08",
        );
        let mut a = [0u8; 8];
        t.get_random(&mut a).unwrap();
        assert_eq!(a, [1, 2, 3, 4, 5, 6, 7, 8]);
        r.assert_clean();

        // 40 bytes: 32 then 8.
        let (mut t, r) = rig(k, 0);
        let first: String = (0..32).map(|i| format!("{:02X}", 0x40 + i)).collect::<Vec<_>>().join(" ");
        r.dev.borrow_mut().expect(
            "80 01 00 00 00 0C 00 00 01 7B 00 20",
            &format!("80 01 00 00 00 2C 00 00 00 00 00 20 {first}"),
        );
        r.dev.borrow_mut().expect(
            "80 01 00 00 00 0C 00 00 01 7B 00 08",
            "80 01 00 00 00 14 00 00 00 00 00 08 A1 A2 A3 A4 A5 A6 A7 A8",
        );
        let mut b = [0u8; 40];
        t.get_random(&mut b).unwrap();
        assert_eq!(b[0], 0x40);
        assert_eq!(b[31], 0x5F);
        assert_eq!(&b[32..], &[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]);
        r.assert_clean();
    }
}

#[test]
fn get_random_short_answers_loop_and_lies_are_refused() {
    // The TPM may return fewer bytes than asked: ask again for the rest.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 7B 00 04",
        "80 01 00 00 00 0E 00 00 00 00 00 02 AA BB",
    );
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 7B 00 02",
        "80 01 00 00 00 0E 00 00 00 00 00 02 CC DD",
    );
    let mut a = [0u8; 4];
    t.get_random(&mut a).unwrap();
    assert_eq!(a, [0xAA, 0xBB, 0xCC, 0xDD]);
    // Zero bytes: an endless loop if believed.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 7B 00 04",
        "80 01 00 00 00 0C 00 00 00 00 00 00",
    );
    assert_eq!(t.get_random(&mut a), Err(Error::Malformed));
    // More than asked.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 7B 00 04",
        "80 01 00 00 00 11 00 00 00 00 00 05 01 02 03 04 05",
    );
    assert_eq!(t.get_random(&mut a), Err(Error::Malformed));
    // A TPM2B whose length runs past the response.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 0C 00 00 01 7B 00 04",
        "80 01 00 00 00 0E 00 00 00 00 FF FF AA BB",
    );
    assert_eq!(t.get_random(&mut a), Err(Error::Malformed));
}

#[test]
fn pcr_extend_vector() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        let cmd = format!(
            "80 02 00 00 00 41 00 00 01 82 00 00 00 08 {AUTH_AREA_EMPTY} 00 00 00 01 00 0B {}",
            digest_hex()
        );
        r.dev.borrow_mut().expect(&cmd, &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = i as u8;
        }
        t.pcr_extend(8, &d).unwrap();
        r.assert_clean();
    }
}

#[test]
fn pcr_extend_rejects_bad_pcr_without_touching_the_bus() {
    let (mut t, r) = rig(Kind::Direct, 0);
    assert_eq!(t.pcr_extend(24, &[0; 32]), Err(Error::BadArgument));
    assert_eq!(t.pcr_read(24), Err(Error::BadArgument));
    assert_eq!(r.dev.borrow().cmd_ready_writes, 0);
}

fn pcr_read_rsp(sel: &str, count: &str, size: &str) -> String {
    format!(
        "80 01 00 00 00 3E 00 00 00 00 00 00 00 05 {sel} {count} {size} {}",
        (0..32).map(|i| format!("{:02X}", 0xF0u8.wrapping_add(i))).collect::<Vec<_>>().join(" ")
    )
}

#[test]
fn pcr_read_vector_and_selection_checks() {
    const CMD10: &str = "80 01 00 00 00 14 00 00 01 7E 00 00 00 01 00 0B 03 00 04 00";
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(CMD10, &pcr_read_rsp("00 00 00 01 00 0B 03 00 04 00", "00 00 00 01", "00 20"));
        let d = t.pcr_read(10).unwrap();
        assert_eq!(d[0], 0xF0);
        assert_eq!(d[31], 0x0F);
        r.assert_clean();
    }
    // The TPM selected a different PCR than we asked for.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(CMD10, &pcr_read_rsp("00 00 00 01 00 0B 03 01 00 00", "00 00 00 01", "00 20"));
    assert_eq!(t.pcr_read(10), Err(Error::Malformed));
    // PCR not in the bank: no digest.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        CMD10,
        "80 01 00 00 00 20 00 00 00 00 00 00 00 05 00 00 00 01 00 0B 03 00 00 00 00 00 00 00",
    );
    assert_eq!(t.pcr_read(10), Err(Error::Malformed));
    // Digest of the wrong size.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(CMD10, &pcr_read_rsp("00 00 00 01 00 0B 03 00 04 00", "00 00 00 01", "00 21"));
    assert!(t.pcr_read(10).is_err());
}

#[test]
fn pcr_read_mask_bytes() {
    // PCR 23 is bit 7 of byte 2; PCR 0 bit 0 of byte 0.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 14 00 00 01 7E 00 00 00 01 00 0B 03 00 00 80",
        &pcr_read_rsp("00 00 00 01 00 0B 03 00 00 80", "00 00 00 01", "00 20"),
    );
    t.pcr_read(23).unwrap();
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        "80 01 00 00 00 14 00 00 01 7E 00 00 00 01 00 0B 03 01 00 00",
        &pcr_read_rsp("00 00 00 01 00 0B 03 01 00 00", "00 00 00 01", "00 20"),
    );
    t.pcr_read(0).unwrap();
}

#[test]
fn nv_define_vector() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        assert_eq!(FLOOR_ATTRS, 0x0204_0004);
        r.dev.borrow_mut().expect(
            &format!(
                "80 02 00 00 00 2F 00 00 01 2A 40 00 00 01 {AUTH_AREA_EMPTY} 00 02 AA BB 00 0E 01 50 00 01 00 0B 02 04 00 04 00 00 00 04"
            ),
            &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"),
        );
        t.nv_define(&[], FLOOR_INDEX, FLOOR_ATTRS, 4, &[0xAA, 0xBB]).unwrap();
        r.assert_clean();
    }
}

const NV_DEFINE_FLOOR: &str = "80 02 00 00 00 2F 00 00 01 2A 40 00 00 01 00 00 00 09 40 00 00 09 00 00 01 00 00 00 02 AA BB 00 0E 01 50 00 01 00 0B 02 04 00 04 00 00 00 04";
const NV_DEFINED_RSP: &str = "80 01 00 00 00 0A 00 00 01 4C";
const NV_READ_PUBLIC: &str = "80 01 00 00 00 0E 00 00 01 69 01 50 00 01";

/// An `NV_ReadPublic` reply for `FLOOR_INDEX` with the given fields; the
/// name is 34 bytes (alg + SHA-256 digest), its content is not examined.
fn nv_public_rsp(name_alg: &str, attrs: &str, policy: &str, size: &str) -> String {
    let policy_len = policy.split_whitespace().count();
    let area = 4 + 2 + 4 + 2 + policy_len + 2;
    let name: String = (0..34).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ");
    let total = 10 + 2 + area + 2 + 34;
    format!(
        "80 01 00 00 00 {total:02X} 00 00 00 00 00 {area:02X} 01 50 00 01 {name_alg} {attrs} 00 {policy_len:02X} {policy} {size} 00 22 {name}"
    )
}

fn provision_against(public: &str) -> Result<(), Error> {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_DEFINE_FLOOR, NV_DEFINED_RSP);
    r.dev.borrow_mut().expect(NV_READ_PUBLIC, public);
    let res = t.floor_provision(&[], FLOOR_INDEX, &[0xAA, 0xBB]);
    r.assert_clean();
    res
}

#[test]
fn floor_provision_defines_once_and_adopts_only_our_own_index() {
    // Fresh TPM: one define.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_DEFINE_FLOOR, "80 02 00 00 00 13 00 00 00 00 00 00 00 00 00 00 01 00 00");
    t.floor_provision(&[], FLOOR_INDEX, &[0xAA, 0xBB]).unwrap();
    r.assert_clean();
    // Already defined by us, never written, then written.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", "", "00 04")), Ok(()));
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "22 04 00 04", "", "00 04")), Ok(()));
    // Any other error from the define passes through.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_DEFINE_FLOOR, "80 01 00 00 00 0A 00 00 09 21");
    assert_eq!(t.floor_provision(&[], FLOOR_INDEX, &[0xAA, 0xBB]), Err(Error::Tpm(0x921)));
}

#[test]
fn floor_provision_refuses_a_squatted_index() {
    // A previous owner defined the index with weaker rights: every property
    // the floor relies on is checked, each on its own.
    // Plain owner write added (the owner can lower the floor without the auth).
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 06", "", "00 04")), Err(Error::NvMismatch));
    // Policy write instead of password write.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 08", "", "00 04")), Err(Error::NvMismatch));
    // Subject to the dictionary-attack lockout (NO_DA clear).
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "00 04 00 04", "", "00 04")), Err(Error::NvMismatch));
    // Platform-created.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "42 04 00 04", "", "00 04")), Err(Error::NvMismatch));
    // Write-locked (state the definition did not ask for).
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 08 04", "", "00 04")), Err(Error::NvMismatch));
    // A counter, not an ordinary index.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 14", "", "00 04")), Err(Error::NvMismatch));
    // Wrong size, wrong name algorithm, a policy attached.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", "", "00 08")), Err(Error::NvMismatch));
    assert_eq!(provision_against(&nv_public_rsp("00 04", "02 04 00 04", "", "00 04")), Err(Error::NvMismatch));
    let digest: String = (0..32).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ");
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", &digest, "00 04")), Err(Error::NvMismatch));
}

#[test]
fn nv_read_public_is_bounds_checked() {
    // The reply names another index.
    let mut other = nv_public_rsp("00 0B", "02 04 00 04", "", "00 04");
    other = other.replacen("01 50 00 01", "01 50 00 02", 1);
    assert_eq!(provision_against(&other), Err(Error::Malformed));
    // The area is shorter than its fields.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_DEFINE_FLOOR, NV_DEFINED_RSP);
    r.dev.borrow_mut().expect(
        NV_READ_PUBLIC,
        "80 01 00 00 00 12 00 00 00 00 00 04 01 50 00 01 00 00",
    );
    assert_eq!(t.floor_provision(&[], FLOOR_INDEX, &[0xAA, 0xBB]), Err(Error::Malformed));
    // The area's declared size runs past the response.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_DEFINE_FLOOR, NV_DEFINED_RSP);
    r.dev.borrow_mut().expect(NV_READ_PUBLIC, "80 01 00 00 00 0E 00 00 00 00 FF FF 00 00");
    assert_eq!(t.floor_provision(&[], FLOOR_INDEX, &[0xAA, 0xBB]), Err(Error::Malformed));
    // Bytes left after the name.
    let mut extra = nv_public_rsp("00 0B", "02 04 00 04", "", "00 04");
    extra = extra.replacen("00 00 00 3E", "00 00 00 3F", 1) + " 00";
    assert_eq!(provision_against(&extra), Err(Error::Malformed));
    // The TPM refuses the read: the error passes through, the index is not adopted.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_DEFINE_FLOOR, NV_DEFINED_RSP);
    r.dev.borrow_mut().expect(NV_READ_PUBLIC, "80 01 00 00 00 0A 00 00 01 8B");
    assert_eq!(t.floor_provision(&[], FLOOR_INDEX, &[0xAA, 0xBB]), Err(Error::Tpm(0x18B)));
}

const NV_READ4: &str = "80 02 00 00 00 25 00 00 01 4E 01 50 00 01 01 50 00 01 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB 00 04 00 00";

fn nv_read_rsp(value: &str) -> String {
    format!("80 02 00 00 00 19 00 00 00 00 00 00 00 06 00 04 {value} 00 00 01 00 00")
}

#[test]
fn nv_read_vector_and_bounds() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(NV_READ4, &nv_read_rsp("00 00 00 2A"));
        let mut b = [0u8; 4];
        t.nv_read(FLOOR_INDEX, &[0xAA, 0xBB], 0, &mut b).unwrap();
        assert_eq!(b, [0, 0, 0, 0x2A]);
        r.assert_clean();
    }
    // The TPM returns fewer bytes than asked.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        NV_READ4,
        "80 02 00 00 00 17 00 00 00 00 00 00 00 04 00 02 AA BB 00 00 01 00 00",
    );
    let mut b = [0u8; 4];
    assert_eq!(t.nv_read(FLOOR_INDEX, &[0xAA, 0xBB], 0, &mut b), Err(Error::Malformed));
    // parameterSize runs past the response.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(
        NV_READ4,
        "80 02 00 00 00 19 00 00 00 00 00 00 FF FF 00 04 00 00 00 2A 00 00 01 00 00",
    );
    assert_eq!(t.nv_read(FLOOR_INDEX, &[0xAA, 0xBB], 0, &mut b), Err(Error::Malformed));
    // Bad arguments never reach the bus.
    let (mut t, r) = rig(Kind::Direct, 0);
    assert_eq!(t.nv_read(FLOOR_INDEX, &[0; 33], 0, &mut b), Err(Error::BadArgument));
    assert_eq!(t.nv_read(FLOOR_INDEX, &[], 0, &mut []), Err(Error::BadArgument));
    assert_eq!(t.nv_read(FLOOR_INDEX, &[], 0, &mut [0u8; 129]), Err(Error::BadArgument));
    assert_eq!(t.nv_write(FLOOR_INDEX, &[], 0, &[]), Err(Error::BadArgument));
    assert_eq!(r.dev.borrow().cmd_ready_writes, 0);
}

const NV_WRITE4: &str = "80 02 00 00 00 29 00 00 01 37 01 50 00 01 01 50 00 01 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB 00 04 00 00 00 2B 00 00";

#[test]
fn nv_write_vector() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(NV_WRITE4, &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
        t.nv_write(FLOOR_INDEX, &[0xAA, 0xBB], 0, &[0, 0, 0, 0x2B]).unwrap();
        r.assert_clean();
    }
}

#[test]
fn floor_read_uninitialized_is_zero_and_errors_pass_through() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ4, "80 01 00 00 00 0A 00 00 01 4A");
    assert_eq!(t.floor_read(FLOOR_INDEX, &[0xAA, 0xBB]), Ok(0));
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ4, "80 01 00 00 00 0A 00 00 01 4B");
    assert_eq!(t.floor_read(FLOOR_INDEX, &[0xAA, 0xBB]), Err(Error::Tpm(0x14B)));
}

#[test]
fn floor_only_goes_up() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        let a = &[0xAA, 0xBB];
        // Stored 0x2A. Raising to 0x2B reads then writes.
        r.dev.borrow_mut().expect(NV_READ4, &nv_read_rsp("00 00 00 2A"));
        r.dev.borrow_mut().expect(NV_WRITE4, &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
        assert_eq!(t.floor_raise(FLOOR_INDEX, a, 0x2B), Ok(0x2B));
        // Equal and lower: one read each, no write (the script would
        // fail an unexpected write).
        r.dev.borrow_mut().expect(NV_READ4, &nv_read_rsp("00 00 00 2A"));
        assert_eq!(t.floor_raise(FLOOR_INDEX, a, 0x2A), Ok(0x2A));
        r.dev.borrow_mut().expect(NV_READ4, &nv_read_rsp("00 00 00 2A"));
        assert_eq!(t.floor_raise(FLOOR_INDEX, a, 1), Ok(0x2A));
        r.assert_clean();
    }
}

#[test]
fn floor_raise_from_unwritten_index() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ4, "80 01 00 00 00 0A 00 00 01 4A");
    r.dev.borrow_mut().expect(NV_WRITE4, &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
    assert_eq!(t.floor_raise(FLOOR_INDEX, &[0xAA, 0xBB], 0x2B), Ok(0x2B));
    r.assert_clean();
}

// ── The keystore secret: a 32-byte index of its own ─────────────────────────

const AUTH: &[u8] = &[0xAA, 0xBB];
const NV_DEFINE_SECRET: &str = "80 02 00 00 00 2F 00 00 01 2A 40 00 00 01 00 00 00 09 40 00 00 09 00 00 01 00 00 00 02 AA BB 00 0E 01 50 00 02 00 0B 02 04 00 04 00 00 00 20";
const NV_READ32: &str = "80 02 00 00 00 25 00 00 01 4E 01 50 00 02 01 50 00 02 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB 00 20 00 00";

fn secret_hex(first: u8) -> String {
    (0..32).map(|i| format!("{:02X}", first.wrapping_add(i))).collect::<Vec<_>>().join(" ")
}

fn secret_bytes(first: u8) -> [u8; 32] {
    core::array::from_fn(|i| first.wrapping_add(i as u8))
}

fn nv_read32_rsp(first: u8) -> String {
    format!("80 02 00 00 00 35 00 00 00 00 00 00 00 22 00 20 {} 00 00 01 00 00", secret_hex(first))
}

fn nv_write32(first: u8) -> String {
    format!("80 02 00 00 00 45 00 00 01 37 01 50 00 02 01 50 00 02 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB 00 20 {} 00 00", secret_hex(first))
}

const NV_READ_PUBLIC_SECRET: &str = "80 01 00 00 00 0E 00 00 01 69 01 50 00 02";

/// The secret's index is the floor's shape at 32 bytes: the same attributes,
/// its own number, its own size.
#[test]
fn the_secret_index_is_the_floors_shape_at_32_bytes() {
    assert_eq!((SECRET_ATTRS, SECRET_BYTES), (FLOOR_ATTRS, 32));
    assert_ne!(SECRET_INDEX, FLOOR_INDEX);
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(NV_DEFINE_SECRET, "80 02 00 00 00 13 00 00 00 00 00 00 00 00 00 00 01 00 00");
        t.secret_provision(&[], SECRET_INDEX, AUTH).unwrap();
        r.assert_clean();
    }
}

/// An index that was defined by someone else with other rights is not the
/// keystore's, whichever field differs; the shape that is ours is adopted.
///
/// **Canary.** `canary-nvsquat` makes `nv_adopt` adopt anything: every refusal
/// below goes green.
#[test]
fn the_secret_index_is_adopted_only_if_it_is_ours() {
    let public = |attrs: &str, size: &str| {
        let name: String = (0..34).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ");
        format!("80 01 00 00 00 4C 00 00 00 00 00 0E 01 50 00 02 00 0B {attrs} 00 00 {size} 00 22 {name}").replace("00 4C", &format!("00 {:02X}", 10 + 2 + 14 + 2 + 34))
    };
    let against = |public: &str| {
        let (mut t, r) = rig(Kind::Direct, 0);
        r.dev.borrow_mut().expect(NV_DEFINE_SECRET, NV_DEFINED_RSP);
        r.dev.borrow_mut().expect(NV_READ_PUBLIC_SECRET, public);
        t.secret_provision(&[], SECRET_INDEX, AUTH)
    };
    assert_eq!(against(&public("02 04 00 04", "00 20")), Ok(()), "ours, never written");
    assert_eq!(against(&public("22 04 00 04", "00 20")), Ok(()), "ours, written");
    assert_eq!(against(&public("02 04 00 06", "00 20")), Err(Error::NvMismatch), "the owner may also write");
    assert_eq!(against(&public("02 04 00 04", "00 04")), Err(Error::NvMismatch), "the floor's size");
    assert_eq!(against(&public("00 04 00 04", "00 20")), Err(Error::NvMismatch), "no password to read");
}

/// A first boot writes the secret the caller drew and reads it back; every
/// later boot reads what is stored and writes nothing.
///
/// **Canary.** Write `fresh` without reading first: the second half's script
/// has no write for it and the rig fails.
#[test]
fn the_secret_is_created_once_and_read_after() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ32, "80 01 00 00 00 0A 00 00 01 4A");
    r.dev.borrow_mut().expect(&nv_write32(0x10), &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
    r.dev.borrow_mut().expect(NV_READ32, &nv_read32_rsp(0x10));
    assert_eq!(t.secret_load_or_create(SECRET_INDEX, AUTH, &secret_bytes(0x10)), Ok(secret_bytes(0x10)));
    r.assert_clean();

    // The next boot draws other bytes and is handed the stored ones.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ32, &nv_read32_rsp(0x10));
    assert_eq!(t.secret_load_or_create(SECRET_INDEX, AUTH, &secret_bytes(0x90)), Ok(secret_bytes(0x10)));
    r.assert_clean();
}

#[test]
fn a_secret_that_cannot_be_written_or_read_back_is_an_error() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ32, "80 01 00 00 00 0A 00 00 01 4A");
    r.dev.borrow_mut().expect(&nv_write32(0x10), "80 01 00 00 00 0A 00 00 09 21");
    assert_eq!(t.secret_load_or_create(SECRET_INDEX, AUTH, &secret_bytes(0x10)), Err(Error::Tpm(0x921)));
    // A write that took but reads back as unwritten is not a secret.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ32, "80 01 00 00 00 0A 00 00 01 4A");
    r.dev.borrow_mut().expect(&nv_write32(0x10), &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
    r.dev.borrow_mut().expect(NV_READ32, "80 01 00 00 00 0A 00 00 01 4A");
    assert_eq!(t.secret_load_or_create(SECRET_INDEX, AUTH, &secret_bytes(0x10)), Err(Error::Malformed));
    // Any other read error passes through, and nothing is written over it.
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ32, "80 01 00 00 00 0A 00 00 01 4B");
    assert_eq!(t.secret_load_or_create(SECRET_INDEX, AUTH, &secret_bytes(0x10)), Err(Error::Tpm(0x14B)));
    r.assert_clean();
}
