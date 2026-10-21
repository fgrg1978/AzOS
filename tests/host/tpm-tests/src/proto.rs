// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! FIFO protocol: locality, burst pacing, expect, timeouts, response bounds.

use crate::fake::*;
use crate::*;
use azos_tpm::tpm::StartupType;
use azos_tpm::{Error, Wait};

const STARTUP: &str = "80 01 00 00 00 0C 00 00 01 44 00 00";
const STARTUP_OK: &str = "80 01 00 00 00 0A 00 00 00 00";

#[test]
fn probe_reads_identity_and_family() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        let info = t.probe().unwrap();
        assert_eq!((info.vid, info.did, info.rid), (0x15D1, 0x001B, 0x16), "{k:?}");
        r.assert_clean();
    }
}

#[test]
fn probe_refuses_tpm12_and_absent() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().family = 0;
        assert_eq!(t.probe(), Err(Error::NotTpm2), "{k:?}");
        assert_eq!(r.dev.borrow().active, None, "locality released after refusing");
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().present = false;
        assert_eq!(t.probe(), Err(Error::NoDevice), "{k:?}");
    }
}

#[test]
fn locality_above_four_is_refused() {
    let (mut t, _r) = rig(Kind::Direct, 5);
    assert_eq!(t.probe(), Err(Error::BadLocality));
}

#[test]
fn startup_transcript_all_transports_all_bursts() {
    for k in ALL {
        for burst in [1u16, 2, 3, 5, 8, 64, 4095] {
            let (mut t, r) = rig(k, 0);
            r.dev.borrow_mut().burst = burst;
            r.dev.borrow_mut().expect(STARTUP, STARTUP_OK);
            t.startup(StartupType::Clear).unwrap();
            r.assert_clean();
        }
    }
}

#[test]
fn works_in_another_locality() {
    for k in ALL {
        let (mut t, r) = rig(k, 3);
        r.dev.borrow_mut().expect(STARTUP, STARTUP_OK);
        t.startup(StartupType::Clear).unwrap();
        r.assert_clean();
        if let Kind::Mmio = k {
            let log = r.mmio_log.borrow();
            assert!(!log.is_empty());
            for (a, _, _) in log.iter() {
                assert!(*a >= MMIO_BASE + 3 * 0x1000 && *a < MMIO_BASE + 4 * 0x1000, "{a:#x}");
            }
        }
    }
}

#[test]
fn locality_is_released_after_success_and_after_failure() {
    for k in ALL {
        let (mut t, r) = rig(k, 0);
        r.dev.borrow_mut().expect(STARTUP, STARTUP_OK);
        t.startup(StartupType::Clear).unwrap();
        assert_eq!(r.dev.borrow().active, None, "{k:?}");
        assert_eq!(r.dev.borrow().release_count, 1);
        // A failure: the TPM never answers.
        r.dev.borrow_mut().never_data_avail = true;
        r.dev.borrow_mut().expect(STARTUP, STARTUP_OK);
        assert_eq!(t.startup(StartupType::Clear), Err(Error::Timeout(Wait::DataAvail)));
        assert_eq!(r.dev.borrow().active, None, "released after a timeout");
        assert_eq!(r.dev.borrow().release_count, 2);
    }
}

#[test]
fn locality_never_granted_times_out() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().deny_locality = true;
    assert_eq!(t.startup(StartupType::Clear), Err(Error::Timeout(Wait::Locality)));
    // Bounded by timeout A.
    let us = r.clock.0.get();
    assert!(us >= 750_000 && us < 750_000 + 1_000, "{us}");
}

#[test]
fn data_avail_timeout_aborts_and_follows_the_duration_class() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.never_data_avail = true;
        d.expect(STARTUP, STARTUP_OK);
    }
    assert_eq!(t.startup(StartupType::Clear), Err(Error::Timeout(Wait::DataAvail)));
    // Startup is a Medium command: 2 s.
    let us = r.clock.0.get();
    assert!(us >= 2_000_000 && us < 2_000_000 + 1_000, "{us}");
    // commandReady was written to abort (once to get ready, once to abort).
    assert_eq!(r.dev.borrow().cmd_ready_writes, 2);
}

#[test]
fn zero_burst_is_waited_out_then_times_out() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.zero_burst_reads = 5;
        d.expect(STARTUP, STARTUP_OK);
    }
    t.startup(StartupType::Clear).unwrap();
    r.assert_clean();
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().zero_burst_reads = u32::MAX;
    assert_eq!(t.startup(StartupType::Clear), Err(Error::Timeout(Wait::Burst)));
}

#[test]
fn burstcount_is_honoured_on_the_command_path() {
    // burst 3 against a 12-byte command: a driver that pushes everything at
    // once overruns the TPM's FIFO, which the device logs.
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.burst = 3;
        d.expect(STARTUP, STARTUP_OK);
    }
    t.startup(StartupType::Clear).unwrap();
    r.assert_clean();
}

#[test]
fn expect_cleared_early_is_an_error() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.early_expect_clear = true;
        d.expect(STARTUP, STARTUP_OK);
    }
    assert_eq!(t.startup(StartupType::Clear), Err(Error::ExpectMismatch));
    assert_eq!(r.dev.borrow().active, None);
}

#[test]
fn expect_still_set_after_the_last_byte_is_an_error() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.stuck_expect = true;
        d.expect(STARTUP, STARTUP_OK);
    }
    assert_eq!(t.startup(StartupType::Clear), Err(Error::ExpectMismatch));
}

fn rsp_case(rsp: &str, buf_burst: u16) -> Result<(), Error> {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.burst = buf_burst;
        d.expect(STARTUP, rsp);
    }
    t.startup(StartupType::Clear)
}

#[test]
fn response_size_is_bounded() {
    // Declares 0x0BB8 bytes into a 256-byte buffer.
    let mut big = String::from("80 01 00 00 0B B8 00 00 00 00");
    for _ in 0..16 {
        big.push_str(" 00");
    }
    assert_eq!(rsp_case(&big, 8), Err(Error::BadResponseSize));
    // Declares less than a header.
    assert_eq!(rsp_case("80 01 00 00 00 04 00 00 00 00", 8), Err(Error::BadResponseSize));
    // Declares 0.
    assert_eq!(rsp_case("80 01 00 00 00 00 00 00 00 00", 8), Err(Error::BadResponseSize));
}

#[test]
fn oversized_response_leaves_the_device_aborted_and_released() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.expect(STARTUP, "80 01 FF FF FF FF 00 00 00 00");
    }
    assert_eq!(t.startup(StartupType::Clear), Err(Error::BadResponseSize));
    assert_eq!(r.dev.borrow().active, None);
}

#[test]
fn truncated_response_is_an_error() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.truncate_at = Some(10);
        // Header says 12, the TPM stops after 10 bytes.
        d.expect(STARTUP, "80 01 00 00 00 0C 00 00 00 00 00 00");
    }
    assert_eq!(t.startup(StartupType::Clear), Err(Error::Truncated));
}

#[test]
fn trailing_data_is_an_error() {
    let (mut t, r) = rig(Kind::Direct, 0);
    {
        let mut d = r.dev.borrow_mut();
        d.trailing_avail = true;
        d.expect(STARTUP, STARTUP_OK);
    }
    assert_eq!(t.startup(StartupType::Clear), Err(Error::TrailingData));
}

#[test]
fn wrong_tag_and_tpm_error_codes() {
    // Success with the sessions tag where none was asked.
    assert_eq!(rsp_case("80 02 00 00 00 0A 00 00 00 00", 8), Err(Error::Malformed));
    // A TPM error is reported with its code.
    assert_eq!(rsp_case("80 01 00 00 00 0A 00 00 01 01", 8), Err(Error::Tpm(0x101)));
    // RC_INITIALIZE on Startup means "already started".
    assert_eq!(rsp_case("80 01 00 00 00 0A 00 00 01 00", 8), Ok(()));
}

#[test]
fn bad_commands_are_refused_before_the_bus() {
    let (mut t, r) = rig(Kind::Direct, 0);
    let mut rsp = [0u8; 64];
    use azos_tpm::tis::Duration;
    // Shorter than a header.
    assert_eq!(t.tis().transmit(&[0x80, 1, 0, 0], &mut rsp, Duration::Short), Err(Error::BadCommand));
    // Size field is not the length.
    let c = h("80 01 00 00 00 0D 00 00 01 44 00 00");
    assert_eq!(t.tis().transmit(&c, &mut rsp, Duration::Short), Err(Error::BadCommand));
    assert!(r.dev.borrow().violations.is_empty());
    assert_eq!(r.dev.borrow().cmd_ready_writes, 0);
}

#[test]
fn small_response_buffer_is_refused_not_overrun() {
    let (mut t, r) = rig(Kind::Direct, 0);
    r.dev.borrow_mut().expect(STARTUP, STARTUP_OK);
    use azos_tpm::tis::Duration;
    let mut rsp = [0u8; 12];
    let c = h(STARTUP);
    // The reply is 10 bytes: fits.
    assert_eq!(t.tis().transmit(&c, &mut rsp, Duration::Short), Ok(10));
    r.dev.borrow_mut().expect(STARTUP, "80 01 00 00 00 10 00 00 00 00 00 00 00 00 00 00");
    // 16 bytes into 12.
    assert_eq!(t.tis().transmit(&c, &mut rsp, Duration::Short), Err(Error::BadResponseSize));
}
