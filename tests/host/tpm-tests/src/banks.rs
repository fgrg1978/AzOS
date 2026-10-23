// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `GetCapability(TPM_CAP_PCRS)` and the retry on `TPM_RC_RETRY` /
//! `TPM_RC_TESTING`, over the TIS transports and over CRB.

use crate::crb::{assert_clean as crb_clean, crb_rig};
use crate::*;
use azos_tpm::crb::StartMethod;
use azos_tpm::tpm::{PcrBank, StartupType};
use azos_tpm::wire::{ALG_SHA1, ALG_SHA256, ALG_SHA384, RC_RETRY, RC_TESTING};
use azos_tpm::Error;

const GET_CAP_PCRS: &str = "80 01 00 00 00 16 00 00 01 7A 00 00 00 05 00 00 00 00 00 00 00 01";

/// A `GetCapability(TPM_CAP_PCRS)` reply: moreData 0, the capability, then
/// `banks` as `TPMS_PCR_SELECTION`s (`alg`, then the select bytes).
fn pcrs_reply(banks: &[(u16, &[u8])], tail: &str) -> String {
    let mut body = vec![0u8, 0, 0, 0, 5];
    body.extend_from_slice(&(banks.len() as u32).to_be_bytes());
    for (alg, sel) in banks {
        body.extend_from_slice(&alg.to_be_bytes());
        body.push(sel.len() as u8);
        body.extend_from_slice(sel);
    }
    let tail = fake::h(tail);
    let n = 10 + body.len() + tail.len();
    let mut r = vec![0x80, 0x01];
    r.extend_from_slice(&(n as u32).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&body);
    r.extend_from_slice(&tail);
    r.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// The banks as the TPM lists them, and whether the SHA-256 bank holds the
/// boot's three PCRs. A TPM whose firmware left only SHA-1 allocated (or
/// SHA-256 with the firmware's PCRs 0-7 only) would drop every SHA-256
/// extend: `holds` is what the boot checks first.
#[test]
fn pcr_banks_lists_the_allocated_banks() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        let all: &[u8] = &[0xFF, 0xFF, 0xFF];
        r.dev.borrow_mut().expect(GET_CAP_PCRS, &pcrs_reply(&[(ALG_SHA1, all), (ALG_SHA256, all)], ""));
        let b = t.pcr_banks().unwrap();
        assert_eq!(b.banks(), [PcrBank { alg: ALG_SHA1, pcrs: 0xFF_FFFF }, PcrBank { alg: ALG_SHA256, pcrs: 0xFF_FFFF }]);
        assert!(b.holds(ALG_SHA256, 8..11));
        assert!(!b.holds(ALG_SHA384, 8..11), "no SHA-384 bank");
        r.assert_clean();
    }
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(GET_CAP_PCRS, &pcrs_reply(&[(ALG_SHA256, &[0xFF, 0, 0]), (ALG_SHA1, &[0xFF, 0xFF, 0xFF])], ""));
    let b = t.pcr_banks().unwrap();
    assert!(!b.holds(ALG_SHA256, 8..11), "SHA-256 with the firmware's PCRs only");
    assert!(b.holds(ALG_SHA256, 0..8));
    r.assert_clean();
}

/// A reply that is not the PCR capability, lists more banks than the driver
/// keeps, cuts a selection short or carries bytes after the list is refused.
#[test]
fn pcr_banks_refuses_malformed_replies() {
    let all: &[u8] = &[0xFF, 0xFF, 0xFF];
    let nine: Vec<(u16, &[u8])> = (0..9).map(|i| (i as u16, all)).collect();
    let mut wrong_cap = pcrs_reply(&[(ALG_SHA256, all)], "");
    // The capability's last byte (header 10 + moreData 1 + 3).
    let at = (10 + 4) * 3;
    wrong_cap.replace_range(at..at + 2, "06");
    let short = {
        let s = pcrs_reply(&[(ALG_SHA256, all)], "");
        // Say the selection has 4 bytes where 3 follow.
        let at = (10 + 1 + 4 + 4 + 2) * 3;
        let mut s = s;
        s.replace_range(at..at + 2, "04");
        s
    };
    for bad in [pcrs_reply(&nine, ""), wrong_cap, short, pcrs_reply(&[(ALG_SHA256, all)], "00")] {
        let (mut t, r) = rig(Kind::Direct, 0);
        r.dev.borrow_mut().expect(GET_CAP_PCRS, &bad);
        assert_eq!(t.pcr_banks(), Err(Error::Malformed), "{bad}");
        r.assert_clean();
    }
}

const STARTUP: &str = "80 01 00 00 00 0C 00 00 01 44 00 00";
const STARTUP_OK: &str = "80 01 00 00 00 0A 00 00 00 00";

fn rc(code: u32) -> String {
    let b = code.to_be_bytes();
    format!("80 01 00 00 00 0A {:02X} {:02X} {:02X} {:02X}", b[0], b[1], b[2], b[3])
}

/// **`TPM_RC_RETRY` and `TPM_RC_TESTING` send the command again**, after
/// 20 ms, then 40 ms: the third answer is the one returned.
/// **Canary** `canary-no-retry`: the first `TPM_RC_TESTING` is the answer.
#[test]
fn retry_and_testing_send_the_command_again() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(STARTUP, &rc(RC_TESTING));
        r.dev.borrow_mut().expect(STARTUP, &rc(RC_RETRY));
        r.dev.borrow_mut().expect(STARTUP, STARTUP_OK);
        let t0 = r.clock.0.get();
        t.startup(StartupType::Clear).unwrap();
        assert!(r.clock.0.get() - t0 >= 60_000, "paused 20 + 40 ms");
        r.assert_clean();
    }
    let (mut t, d, _) = crb_rig(StartMethod::Crb);
    d.borrow_mut().expect(STARTUP, &rc(RC_RETRY));
    d.borrow_mut().expect(STARTUP, STARTUP_OK);
    t.startup(StartupType::Clear).unwrap();
    crb_clean(&d);
}

/// The retry is bounded: seven retries (20 ms doubling to 1.28 s, about
/// 2.5 s in all), then `TPM_RC_RETRY` is the answer. Any other warning code
/// is not retried.
#[test]
fn retry_is_bounded_and_only_for_those_two_codes() {
    let (mut t, r) = rig(Kind::Direct, 0);
    for _ in 0..8 {
        r.dev.borrow_mut().expect(STARTUP, &rc(RC_RETRY));
    }
    let t0 = r.clock.0.get();
    assert_eq!(t.startup(StartupType::Clear), Err(Error::Tpm(RC_RETRY)));
    let waited = r.clock.0.get() - t0;
    assert!((2_540_000..3_000_000).contains(&waited), "{waited} us");
    r.assert_clean();
    // TPM_RC_YIELDED (0x908) and TPM_RC_NV_RATE (0x920): not retried.
    for code in [0x908, 0x920] {
        let (mut t, r) = rig(Kind::Direct, 0);
        r.dev.borrow_mut().expect(STARTUP, &rc(code));
        assert_eq!(t.startup(StartupType::Clear), Err(Error::Tpm(code)));
        r.assert_clean();
    }
}
