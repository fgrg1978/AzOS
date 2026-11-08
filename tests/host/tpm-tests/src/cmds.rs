// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Command encodings against hand-built vectors, response decoding, the
//! rollback floor. Every command runs over every transport.

use crate::*;
use azos_tpm::tpm::{
    Adopted, StartupType, CHAIN_ATTRS, CHAIN_BYTES, CHAIN_INDEX, COUNTER_ATTRS, COUNTER_BYTES, COUNTER_INDEX, FLOOR_ATTRS, FLOOR_INDEX,
    FLOOR_MAX, ORDINARY_ATTRS, SECRET_ATTRS, SECRET_BYTES, SECRET_INDEX, UNDELETABLE_ATTRS,
};
use azos_tpm::Error;
use crate::fake::Dyn;

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

/// The orderly power-off's last TPM command (owner decision 2026-10-23):
/// `TPM2_Shutdown` (0x145) with `TPM_SU_STATE`, so the next boot's Startup
/// does not count an unorderly shutdown. A failure code reaches the caller
/// (the kernel says it and powers off anyway).
///
/// **Canary.** `CC_SHUTDOWN` as 0x144 (Startup), or `shutdown` sending
/// `TPM_SU_CLEAR`: the expected bytes differ and this row goes red.
#[test]
fn shutdown_state_encodes_su_state() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(
            "80 01 00 00 00 0C 00 00 01 45 00 01",
            "80 01 00 00 00 0A 00 00 00 00",
        );
        t.shutdown(StartupType::State).unwrap();
        r.assert_clean();

        // TPM_RC_FAILURE (0x101): reported, not swallowed.
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(
            "80 01 00 00 00 0C 00 00 01 45 00 01",
            "80 01 00 00 00 0A 00 00 01 01",
        );
        assert_eq!(t.shutdown(StartupType::State), Err(Error::Tpm(0x101)));
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
        assert_eq!(FLOOR_ATTRS, 0x0204_0024);
        r.dev.borrow_mut().expect(
            &format!(
                "80 02 00 00 00 2F 00 00 01 2A 40 00 00 01 {AUTH_AREA_EMPTY} 00 02 AA BB 00 0E 01 50 00 01 00 0B 02 04 00 24 00 00 00 08"
            ),
            &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"),
        );
        t.nv_define(&[], FLOOR_INDEX, FLOOR_ATTRS, 8, &[0xAA, 0xBB]).unwrap();
        r.assert_clean();
    }
}

const NV_DEFINE_FLOOR: &str = "80 02 00 00 00 2F 00 00 01 2A 40 00 00 01 00 00 00 09 40 00 00 09 00 00 01 00 00 00 02 AA BB 00 0E 01 50 00 01 00 0B 02 04 00 24 00 00 00 08";
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

fn provision_against(public: &str) -> Result<Adopted, Error> {
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
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 24", "", "00 08")), Ok(Adopted::Owner));
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "22 04 00 24", "", "00 08")), Ok(Adopted::Owner));
    // The undeletable variant the platform hierarchy defined: the same
    // rights plus PLATFORMCREATE | POLICY_DELETE, and a 32-byte policy.
    let policy: String = (0..32).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ");
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "42 04 04 24", &policy, "00 08")), Ok(Adopted::Undeletable));
    // Those attributes with no policy, or the policy without them: not ours.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "42 04 04 24", "", "00 08")), Err(Error::NvMismatch));
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 24", &policy, "00 08")), Err(Error::NvMismatch));
    assert_eq!(UNDELETABLE_ATTRS, 0x4000_0400);
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
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 26", "", "00 04")), Err(Error::NvMismatch));
    // Policy write instead of password write.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 28", "", "00 04")), Err(Error::NvMismatch));
    // Subject to the dictionary-attack lockout (NO_DA clear).
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "00 04 00 24", "", "00 04")), Err(Error::NvMismatch));
    // Platform-created.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "42 04 00 24", "", "00 04")), Err(Error::NvMismatch));
    // Write-locked (state the definition did not ask for).
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 08 24", "", "00 04")), Err(Error::NvMismatch));
    // A counter, not a bit field.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 14", "", "00 08")), Err(Error::NvMismatch));
    // Wrong size, wrong name algorithm, a policy attached.
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", "", "00 08")), Err(Error::NvMismatch));
    assert_eq!(provision_against(&nv_public_rsp("00 04", "02 04 00 24", "", "00 08")), Err(Error::NvMismatch));
    let digest: String = (0..32).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ");
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", &digest, "00 08")), Err(Error::NvMismatch));
}

/// The index an earlier build defined: ordinary (type 0), 4 bytes, otherwise
/// the same rights. Its holder can `NV_Write` any value, so the TPM would not
/// keep the floor monotonic: it is refused, not adopted.
///
/// **Canary.** With `FLOOR_ATTRS` ordinary and `FLOOR_BYTES` 4 (the earlier
/// build's definition) the first two cases are adopted and this goes red; the
/// last two keep the type and the size each refused on its own.
#[test]
fn floor_provision_refuses_the_ordinary_index_of_an_earlier_build() {
    assert_eq!(FLOOR_ATTRS & 0xF0, 0x20, "TPM_NT_BITS");
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", "", "00 04")), Err(Error::NvMismatch));
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "22 04 00 04", "", "00 04")), Err(Error::NvMismatch));
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 04", "", "00 08")), Err(Error::NvMismatch));
    assert_eq!(provision_against(&nv_public_rsp("00 0B", "02 04 00 24", "", "00 04")), Err(Error::NvMismatch));
}

#[test]
fn nv_read_public_is_bounds_checked() {
    // The reply names another index.
    let mut other = nv_public_rsp("00 0B", "02 04 00 24", "", "00 08");
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
    let mut extra = nv_public_rsp("00 0B", "02 04 00 24", "", "00 08");
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

const NV_READ8: &str = "80 02 00 00 00 25 00 00 01 4E 01 50 00 01 01 50 00 01 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB 00 08 00 00";

fn nv_set_bits_cmd(n: u32) -> String {
    let bits: String = (1u64 << (n - 1)).to_be_bytes().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
    format!("80 02 00 00 00 29 00 00 01 35 01 50 00 01 01 50 00 01 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB {bits}")
}

/// The `NV_Read` reply of a bit field with `bits` set.
fn nv_read8_rsp(bits: u64) -> String {
    let b: String = bits.to_be_bytes().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
    format!("80 02 00 00 00 1D 00 00 00 00 00 00 00 0A 00 08 {b} 00 00 01 00 00")
}

#[test]
fn floor_read_uninitialized_is_zero_and_errors_pass_through() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ8, "80 01 00 00 00 0A 00 00 01 4A");
    assert_eq!(t.floor_read(FLOOR_INDEX, &[0xAA, 0xBB]), Ok(0));
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ8, "80 01 00 00 00 0A 00 00 01 4B");
    assert_eq!(t.floor_read(FLOOR_INDEX, &[0xAA, 0xBB]), Err(Error::Tpm(0x14B)));
}

#[test]
fn floor_is_the_highest_set_bit() {
    let (mut t, r) = rig(Kind::Direct, 0);
    let a = &[0xAA, 0xBB];
    // Bits 0 and 41 set: floor 42, the low bit is noise.
    r.dev.borrow_mut().expect(NV_READ8, &nv_read8_rsp(1 | 1 << 41));
    assert_eq!(t.floor_read(FLOOR_INDEX, a), Ok(42));
    r.dev.borrow_mut().expect(NV_READ8, &nv_read8_rsp(1 << 63));
    assert_eq!(t.floor_read(FLOOR_INDEX, a), Ok(64));
    r.assert_clean();
}

#[test]
fn floor_only_goes_up() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        let a = &[0xAA, 0xBB];
        // Stored floor 0x2A. Raising to 0x2B reads then sets bit 0x2A.
        r.dev.borrow_mut().expect(NV_READ8, &nv_read8_rsp(1 << 0x29));
        r.dev.borrow_mut().expect(&nv_set_bits_cmd(0x2B), &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
        assert_eq!(t.floor_raise(FLOOR_INDEX, a, 0x2B), Ok(0x2B));
        // Equal, lower and zero: one read each, nothing sent.
        for to in [0x2A, 1, 0] {
            r.dev.borrow_mut().expect(NV_READ8, &nv_read8_rsp(1 << 0x29));
            assert_eq!(t.floor_raise(FLOOR_INDEX, a, to), Ok(0x2A));
        }
        r.assert_clean();
    }
}

#[test]
fn floor_raise_from_unwritten_index_and_above_the_field() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(NV_READ8, "80 01 00 00 00 0A 00 00 01 4A");
    r.dev.borrow_mut().expect(&nv_set_bits_cmd(0x2B), &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
    assert_eq!(t.floor_raise(FLOOR_INDEX, &[0xAA, 0xBB], 0x2B), Ok(0x2B));
    // FLOOR_MAX is the last bit (the limit tools/sign/sign_ota.py enforces at signing); the next has
    // none, nothing reaches the wire, and an image signed above it anyway cannot raise the floor.
    r.dev.borrow_mut().expect(NV_READ8, "80 01 00 00 00 0A 00 00 01 4A");
    r.dev.borrow_mut().expect(&nv_set_bits_cmd(FLOOR_MAX), &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"));
    assert_eq!(t.floor_raise(FLOOR_INDEX, &[0xAA, 0xBB], FLOOR_MAX), Ok(FLOOR_MAX));
    assert_eq!(t.floor_raise(FLOOR_INDEX, &[0xAA, 0xBB], FLOOR_MAX + 1), Err(Error::BadArgument));
    r.assert_clean();
}

// ── A model of one NV index, for what the TPM itself enforces ───────────────

const NT_ORDINARY: u32 = 0;
const NT_BITS: u32 = 2;
const NT_EXTEND: u32 = 4;

/// An NV index as the TPM 2.0 spec describes its type rules: `NV_SetBits`
/// ORs into a bit field and is refused on any other type, `NV_Write` is
/// refused on a bit field, `NV_Read` of a never-set index is
/// `TPM_RC_NV_UNINITIALIZED`. Authorization is not modelled (the holder of the
/// password is the attacker here). The exact code `NV_Write` gets on a bit
/// field is `TPM_RC_ATTRIBUTES` (0x82): swtpm answers exactly that, and the
/// driver passes any code through.
struct NvIndex {
    nt: u32,
    value: u64,
    digest: [u8; 32],
    written: bool,
}

fn rc(code: u32) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0, 0, 0, 0x0A];
    v.extend_from_slice(&code.to_be_bytes());
    v
}

fn ok(params: &[u8]) -> Vec<u8> {
    let mut v = vec![0x80, 0x02];
    v.extend_from_slice(&((10 + 4 + params.len() + 5) as u32).to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.extend_from_slice(&(params.len() as u32).to_be_bytes());
    v.extend_from_slice(params);
    v.extend_from_slice(&[0, 0, 1, 0, 0]);
    v
}

impl NvIndex {
    fn answer(&mut self, cmd: &[u8]) -> Vec<u8> {
        let cc = u32::from_be_bytes(cmd[6..10].try_into().unwrap());
        let auth = u32::from_be_bytes(cmd[18..22].try_into().unwrap()) as usize;
        let p = &cmd[22 + auth..];
        match cc {
            0x135 if self.nt == NT_BITS => {
                self.value |= u64::from_be_bytes(p[..8].try_into().unwrap());
                self.written = true;
                ok(&[])
            }
            0x136 if self.nt == NT_EXTEND => {
                let data = &p[2..2 + u16::from_be_bytes([p[0], p[1]]) as usize];
                let mut m = self.digest.to_vec();
                m.extend_from_slice(data);
                self.digest = azos_crypto::sha256::sha256(&m);
                self.written = true;
                ok(&[])
            }
            0x135 | 0x136 | 0x137 if self.nt != NT_ORDINARY || cc != 0x137 => rc(0x82),
            0x137 => {
                let data = &p[2..2 + u16::from_be_bytes([p[0], p[1]]) as usize];
                let mut b = [0u8; 8];
                b[8 - data.len()..].copy_from_slice(data);
                self.value = u64::from_be_bytes(b);
                self.written = true;
                ok(&[])
            }
            0x14E if !self.written => rc(0x14A),
            0x14E if self.nt == NT_EXTEND => {
                let mut params = vec![0, 32];
                params.extend_from_slice(&self.digest);
                ok(&params)
            }
            0x14E => {
                let mut params = vec![0, 8];
                params.extend_from_slice(&self.value.to_be_bytes());
                ok(&params)
            }
            _ => rc(0x143),
        }
    }
}

fn model_rig(nt: u32) -> (azos_tpm::tpm::Tpm<azos_tpm::tis::Tis<Dyn, FakeClock>>, Rig, std::rc::Rc<std::cell::RefCell<NvIndex>>) {
    let (t, r) = rig(Kind::Direct, 0);
    let nv = std::rc::Rc::new(std::cell::RefCell::new(NvIndex { nt, value: 0, digest: [0; 32], written: false }));
    let m = nv.clone();
    r.dev.borrow_mut().responder = Some(Box::new(move |c| m.borrow_mut().answer(c)));
    (t, r, nv)
}

/// Whoever holds the index's password can raise the floor and cannot lower
/// it: the TPM refuses `NV_Write` on the bit field and a lower `NV_SetBits`
/// leaves the highest bit where it was.
#[test]
fn the_tpm_refuses_to_lower_the_floor_bit_field() {
    let (mut t, r, nv) = model_rig(NT_BITS);
    let a = &[0xAA, 0xBB];
    assert_eq!(t.floor_read(FLOOR_INDEX, a), Ok(0));
    assert_eq!(t.floor_raise(FLOOR_INDEX, a, 5), Ok(5));
    assert_eq!(t.floor_raise(FLOOR_INDEX, a, 3), Ok(5));
    // A jump is one command, whatever its size.
    let n = r.dev.borrow().seen.len();
    assert_eq!(t.floor_raise(FLOOR_INDEX, a, 60), Ok(60));
    assert_eq!(r.dev.borrow().seen.len() - n, 2, "a read and one NV_SetBits");
    // The attacker's moves: overwrite with zero, or set a lower bit.
    assert_eq!(t.nv_write(FLOOR_INDEX, a, 0, &[0; 8]), Err(Error::Tpm(0x82)));
    t.nv_set_bits(FLOOR_INDEX, a, 1).unwrap();
    assert_eq!(nv.borrow().value, 1 << 59 | 1 << 4 | 1);
    assert_eq!(t.floor_read(FLOOR_INDEX, a), Ok(60));
    r.assert_clean();
}

/// **Canary.** The same moves against an ordinary index, the earlier build's
/// definition: `NV_Write` of zero lowers the floor to 0. This is what the
/// bit-field type rules out, and why `floor_provision` refuses such an index.
#[test]
fn an_ordinary_index_lets_the_floor_be_lowered() {
    let (mut t, r, _) = model_rig(NT_ORDINARY);
    let a = &[0xAA, 0xBB];
    t.nv_write(FLOOR_INDEX, a, 0, &(1u64 << 59).to_be_bytes()).unwrap();
    assert_eq!(t.floor_read(FLOOR_INDEX, a), Ok(60));
    t.nv_write(FLOOR_INDEX, a, 0, &[0; 8]).unwrap();
    assert_eq!(t.floor_read(FLOOR_INDEX, a), Ok(0));
    r.assert_clean();
}

// ── The keystore secret: a 32-byte index of its own ─────────────────────────

const AUTH: &[u8] = &[0xAA, 0xBB];
const NV_DEFINE_SECRET: &str = "80 02 00 00 00 2F 00 00 01 2A 40 00 00 01 00 00 00 09 40 00 00 09 00 00 01 00 00 00 02 AA BB 00 0E 01 50 00 02 00 0B 82 04 40 04 00 00 00 20";
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

/// The secret's index has the floor's rights at 32 bytes, its own number,
/// and can be locked for the TPM session in both directions (audit K2-H1:
/// its password is built from public constants, so the lock is what keeps
/// the secret): `READ_STCLEAR` (bit 31) and `WRITE_STCLEAR` (bit 14).
#[test]
fn the_secret_index_is_the_floors_rights_lockable_for_the_session() {
    assert_eq!((SECRET_ATTRS, SECRET_BYTES), (ORDINARY_ATTRS | 1 << 31 | 1 << 14, 32));
    assert_eq!(SECRET_ATTRS, 0x8204_4004);
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
    assert_eq!(against(&public("82 04 40 04", "00 20")), Ok(()), "ours, never written");
    assert_eq!(against(&public("A2 04 40 04", "00 20")), Ok(()), "ours, written");
    assert_eq!(against(&public("B2 04 48 04", "00 20")), Ok(()), "ours, written and locked (state bits)");
    assert_eq!(against(&public("82 04 40 06", "00 20")), Err(Error::NvMismatch), "the owner may also write");
    assert_eq!(against(&public("82 04 40 04", "00 04")), Err(Error::NvMismatch), "the floor's size");
    assert_eq!(against(&public("80 04 40 04", "00 20")), Err(Error::NvMismatch), "the lockout applies");
    assert_eq!(against(&public("02 04 00 04", "00 20")), Err(Error::NvMismatch), "no session lock (an older build's)");
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

fn nv_lock_cmd(cc: &str) -> String {
    format!("80 02 00 00 00 21 00 00 {cc} 01 50 00 02 01 50 00 02 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB")
}

/// `secret_lock`: `NV_WriteLock` then `NV_ReadLock` (CC 0x138, 0x14F) of the
/// secret's index under its own password. Both are asked for even when the
/// first is refused, so a refused write lock never leaves the read open.
///
/// **Canary.** Drop the `NV_ReadLock` from `secret_lock`: the script is not
/// consumed (and the second case sees no second command).
#[test]
fn the_secret_index_is_write_and_read_locked() {
    let ok = format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}");
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(&nv_lock_cmd("01 38"), &ok);
    r.dev.borrow_mut().expect(&nv_lock_cmd("01 4F"), &ok);
    assert_eq!(t.secret_lock(SECRET_INDEX, AUTH), Ok(()));
    r.assert_clean();
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(&nv_lock_cmd("01 38"), "80 01 00 00 00 0A 00 00 01 48");
    r.dev.borrow_mut().expect(&nv_lock_cmd("01 4F"), &ok);
    assert_eq!(t.secret_lock(SECRET_INDEX, AUTH), Err(Error::Tpm(0x148)));
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

#[test]
fn nv_extend_vector() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        let d = [0x5Au8; 32];
        let hex: String = d.iter().map(|b| format!(" {b:02X}")).collect();
        r.dev.borrow_mut().expect(
            &format!("80 02 00 00 00 43 00 00 01 36 01 50 00 03 01 50 00 03 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB 00 20{hex}"),
            &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"),
        );
        t.nv_extend(CHAIN_INDEX, &[0xAA, 0xBB], &d).unwrap();
        r.assert_clean();
    }
    assert_eq!((CHAIN_ATTRS & 0xF0, CHAIN_BYTES), (0x40, 32), "TPM_NT_EXTEND, one SHA-256 digest");
}

/// The security log's anchor: zeros before the first seal, then the fold
/// `azos_seclog::chain::extend` computes, and nothing but an extend moves it.
#[test]
fn the_tpm_only_extends_the_chain_index_as_the_verifier_folds_it() {
    let (mut t, r, nv) = model_rig(NT_EXTEND);
    let a = &[0xAA, 0xBB];
    assert_eq!(t.chain_read(CHAIN_INDEX, a), Ok([0; 32]));
    let (h1, h2) = ([1u8; 32], [2u8; 32]);
    t.nv_extend(CHAIN_INDEX, a, &h1).unwrap();
    t.nv_extend(CHAIN_INDEX, a, &h2).unwrap();
    let want = azos_seclog::chain::extend(&azos_seclog::chain::extend(&[0; 32], &h1), &h2);
    assert_eq!(t.chain_read(CHAIN_INDEX, a), Ok(want));
    // The attacker's moves: overwrite it, or set bits in it.
    assert_eq!(t.nv_write(CHAIN_INDEX, a, 0, &[0; 32]), Err(Error::Tpm(0x82)));
    assert_eq!(t.nv_set_bits(CHAIN_INDEX, a, 1), Err(Error::Tpm(0x82)));
    assert_eq!(nv.borrow().digest, want);
    r.assert_clean();
}

#[test]
fn nv_increment_vector() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(
            "80 02 00 00 00 21 00 00 01 34 01 50 00 04 01 50 00 04 00 00 00 0B 40 00 00 09 00 00 01 00 02 AA BB",
            &format!("80 02 00 00 00 13 00 00 00 00 {SESSION_RSP_TAIL}"),
        );
        t.nv_increment(COUNTER_INDEX, &[0xAA, 0xBB]).unwrap();
        r.assert_clean();
    }
    assert_eq!((COUNTER_ATTRS & 0xF0, COUNTER_BYTES), (0x10, 8), "TPM_NT_COUNTER, one u64");
}

// ── Several indexes, undefined and defined again: the attacker's real moves ──

/// A TPM's NV with several indexes, as TPM 2.0 Part 1 and Part 3 describe
/// them: an index is defined (`NV_DefineSpace` under the owner) and
/// undefined (`NV_UndefineSpace`); an extend index starts at zero; a counter
/// takes, at its first `NV_Increment`, one more than the highest value any
/// counter on the TPM has held (`maxCounter`, which an undefine raises and
/// nothing lowers). Authorization is not modelled: the attacker holds the
/// owner's empty password and the indexes' public ones.
#[derive(Default)]
struct Nv {
    idx: std::collections::HashMap<u32, NvIndex>,
    max_counter: u64,
}

const NT_COUNTER: u32 = 1;

impl Nv {
    /// `TPM2_NV_UndefineSpace(TPM_RH_OWNER, index)` with the owner's empty
    /// password: what anyone who can send the TPM commands can do (the driver
    /// has no such command; the attacker's tools do).
    fn undefine(&mut self, index: u32) {
        let i = self.idx.remove(&index).expect("defined");
        if i.nt == NT_COUNTER {
            self.max_counter = self.max_counter.max(i.value);
        }
    }

    fn answer(&mut self, cmd: &[u8]) -> Vec<u8> {
        let be32 = |a: usize| u32::from_be_bytes(cmd[a..a + 4].try_into().unwrap());
        let cc = be32(6);
        match cc {
            // NV_DefineSpace: one handle, the auth area, TPM2B auth, TPM2B_NV_PUBLIC.
            0x12A => {
                let auth = be32(14) as usize;
                let mut at = 18 + auth;
                at += 2 + u16::from_be_bytes([cmd[at], cmd[at + 1]]) as usize;
                let index = be32(at + 2);
                let attrs = be32(at + 8);
                if self.idx.contains_key(&index) {
                    return rc(0x14C);
                }
                self.idx.insert(index, NvIndex { nt: (attrs >> 4) & 0xF, value: 0, digest: [0; 32], written: false });
                ok(&[])
            }

            0x134 => match self.idx.get_mut(&be32(10)) {
                Some(i) if i.nt == NT_COUNTER => {
                    if !i.written {
                        i.value = self.max_counter;
                    }
                    i.value += 1;
                    i.written = true;
                    self.max_counter = self.max_counter.max(i.value);
                    ok(&[])
                }
                Some(_) => rc(0x82),
                None => rc(0x18B),
            },
            _ => match self.idx.get_mut(&be32(10)) {
                Some(i) => i.answer(cmd),
                None => rc(0x18B),
            },
        }
    }
}

fn nv_rig() -> (azos_tpm::tpm::Tpm<azos_tpm::tis::Tis<Dyn, FakeClock>>, Rig, std::rc::Rc<std::cell::RefCell<Nv>>) {
    let (t, r) = rig(Kind::Direct, 0);
    let nv = std::rc::Rc::new(std::cell::RefCell::new(Nv::default()));
    let m = nv.clone();
    r.dev.borrow_mut().responder = Some(Box::new(move |c| m.borrow_mut().answer(c)));
    (t, r, nv)
}

/// What the kernel does per seal: increment the counter, extend the anchor
/// with the seal's data (`azos_seclog::chain::seal_data`), read both back.
fn seal(t: &mut azos_tpm::tpm::Tpm<azos_tpm::tis::Tis<Dyn, FakeClock>>, k: u32) -> ([u8; 32], u64, [u8; 32]) {
    let a = &[0xAA, 0xBB];
    let counter = t.counter_increment(COUNTER_INDEX, a).unwrap();
    let data = azos_seclog::chain::seal_data(&[0; 32], 7, k, counter, 10 * k as u64, &[k as u8; 32]);
    t.nv_extend(CHAIN_INDEX, a, &data).unwrap();
    (data, counter, t.chain_read(CHAIN_INDEX, a).unwrap())
}

/// H2. Whoever can send owner commands undefines the anchor, defines it again
/// and replays the seals' public data up to seal 2: the anchor is seal 2's
/// again, so an export cut after it matches the live anchor. The counter
/// cannot follow: undefined and defined again it starts above every value it
/// held, so the live counter refutes the cut. The same replay with forged
/// data and the counters the seals had is consistent with the live anchor:
/// on an owner index the counter shows a removed seal, not a rewrite.
#[test]
fn an_owner_index_can_be_reset_and_replayed_and_the_counter_cannot() {
    let (mut t, r, nv) = nv_rig();
    let a = &[0xAA, 0xBB];
    assert_eq!(t.chain_provision(&[], CHAIN_INDEX, a), Ok(Adopted::Owner));
    assert_eq!(t.counter_provision(&[], COUNTER_INDEX, a), Ok(Adopted::Owner));
    let seals: Vec<_> = (1..=4).map(|k| seal(&mut t, k)).collect();
    assert_eq!(seals.iter().map(|s| s.1).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    // The reset and the replay.
    nv.borrow_mut().undefine(CHAIN_INDEX);
    assert_eq!(t.chain_provision(&[], CHAIN_INDEX, a), Ok(Adopted::Owner), "nv_adopt cannot tell it apart");
    assert_eq!(t.chain_read(CHAIN_INDEX, a), Ok([0; 32]));
    for s in &seals[..2] {
        t.nv_extend(CHAIN_INDEX, a, &s.0).unwrap();
    }
    assert_eq!(t.chain_read(CHAIN_INDEX, a), Ok(seals[1].2), "the anchor is seal 2's again");
    // The counter kept going; reset too, it comes back above every value.
    assert_eq!(t.counter_read(COUNTER_INDEX, a), Ok(4));
    nv.borrow_mut().undefine(COUNTER_INDEX);
    t.counter_provision(&[], COUNTER_INDEX, a).unwrap();
    assert_eq!(t.counter_read(COUNTER_INDEX, a), Ok(0), "defined, not yet incremented");
    assert_eq!(t.counter_increment(COUNTER_INDEX, a), Ok(5));
    assert!(nv.borrow().max_counter >= 4);
    // A rewrite with the same counters is consistent with the live anchor.
    nv.borrow_mut().undefine(CHAIN_INDEX);
    t.chain_provision(&[], CHAIN_INDEX, a).unwrap();
    let forged = azos_seclog::chain::seal_data(&[0; 32], 7, 1, 1, 10, &[0xEE; 32]);
    t.nv_extend(CHAIN_INDEX, a, &forged).unwrap();
    assert_eq!(t.chain_read(CHAIN_INDEX, a), Ok(azos_seclog::chain::extend(&[0; 32], &forged)));
    r.assert_clean();
}
