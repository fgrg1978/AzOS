// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ACPI TPM2 table and the wire helpers.

use azos_tpm::acpi::*;
use azos_tpm::crb::StartMethod;
use azos_tpm::wire::{parse_response, session_params, Cmd, Reader, ST_NO_SESSIONS, ST_SESSIONS};
use azos_tpm::Error;

fn table(start_method: u32, control_area: u64) -> Vec<u8> {
    let mut t = vec![0u8; 52];
    t[0..4].copy_from_slice(b"TPM2");
    t[4..8].copy_from_slice(&52u32.to_le_bytes());
    t[8] = 4;
    t[36..38].copy_from_slice(&1u16.to_le_bytes());
    t[40..48].copy_from_slice(&control_area.to_le_bytes());
    t[48..52].copy_from_slice(&start_method.to_le_bytes());
    let sum = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

#[test]
fn tpm2_table_selects_the_interface() {
    let t = Tpm2Table::parse(&table(6, 0)).unwrap();
    assert_eq!(t.revision, 4);
    assert_eq!(t.platform_class, 1);
    assert_eq!(t.interface(), Interface::Tis { base: 0xFED4_0000 });
    let t = Tpm2Table::parse(&table(7, 0xFED4_0040)).unwrap();
    assert_eq!(t.interface(), Interface::Crb { control_area: 0xFED4_0040, start: StartMethod::Crb });
    let acpi = Interface::Crb { control_area: 0x10, start: StartMethod::Acpi };
    assert_eq!(Tpm2Table::parse(&table(8, 0x10)).unwrap().interface(), acpi);
    assert_eq!(Tpm2Table::parse(&table(2, 0x10)).unwrap().interface(), acpi, "2: the CRB with an ACPI start");
    assert_eq!(Tpm2Table::parse(&table(11, 0)).unwrap().interface(), Interface::Unsupported(11), "Arm SMC");
}

#[test]
fn tpm2_table_rejects_bad_tables() {
    let good = table(6, 0);
    let mut sig = good.clone();
    sig[0] = b'X';
    assert_eq!(Tpm2Table::parse(&sig), Err(Tpm2Error::Signature));
    let mut sum = good.clone();
    sum[40] ^= 1;
    assert_eq!(Tpm2Table::parse(&sum), Err(Tpm2Error::Checksum));
    assert_eq!(Tpm2Table::parse(&good[..40]), Err(Tpm2Error::Short));
    // Length field larger than the buffer, and smaller than the fixed part.
    let mut big = good.clone();
    big[4..8].copy_from_slice(&200u32.to_le_bytes());
    assert_eq!(Tpm2Table::parse(&big), Err(Tpm2Error::Short));
    let mut small = good.clone();
    small[4..8].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(Tpm2Table::parse(&small), Err(Tpm2Error::Short));
    // Trailing bytes past the length are not summed.
    let mut tail = good.clone();
    tail.extend_from_slice(&[0xFF; 8]);
    assert!(Tpm2Table::parse(&tail).is_ok());
}

#[test]
fn reader_never_reads_past_the_end() {
    let mut r = Reader::new(&[1, 2, 3]);
    assert_eq!(r.u32(), Err(Error::Malformed));
    assert_eq!(r.u16(), Ok(0x0102));
    assert_eq!(r.u16(), Err(Error::Malformed));
    assert_eq!(r.u8(), Ok(3));
    assert_eq!(r.u8(), Err(Error::Malformed));
    let mut r = Reader::new(&[0, 5, 1, 2]);
    assert_eq!(r.tpm2b(), Err(Error::Malformed));
}

#[test]
fn cmd_builder_patches_size_and_reports_overflow() {
    let mut c = Cmd::new(ST_NO_SESSIONS, 0x144);
    c.u16(0);
    let c = c.finish().unwrap();
    assert_eq!(c.bytes_out(), &[0x80, 1, 0, 0, 0, 12, 0, 0, 1, 0x44, 0, 0]);
    let mut c = Cmd::new(ST_SESSIONS, 1);
    c.bytes(&[0u8; 300]);
    assert_eq!(c.finish().err(), Some(Error::BadCommand));
}

#[test]
fn response_checks() {
    let ok = [0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0];
    assert_eq!(parse_response(&ok, ST_NO_SESSIONS), Ok(&[][..]));
    assert_eq!(parse_response(&ok, ST_SESSIONS), Err(Error::Malformed));
    assert_eq!(parse_response(&ok[..9], ST_NO_SESSIONS), Err(Error::BadResponseSize));
    let mut sz = ok;
    sz[5] = 11;
    assert_eq!(parse_response(&sz, ST_NO_SESSIONS), Err(Error::Malformed));
    let mut rc = ok;
    rc[9] = 5;
    assert_eq!(parse_response(&rc, ST_SESSIONS), Err(Error::Tpm(5)));
    assert_eq!(session_params(&[0, 0, 0, 2, 9, 9, 7]), Ok(&[9u8, 9][..]));
    assert_eq!(session_params(&[0, 0, 0, 9, 9, 9]), Err(Error::Malformed));
    assert_eq!(session_params(&[0, 0]), Err(Error::Malformed));
}
