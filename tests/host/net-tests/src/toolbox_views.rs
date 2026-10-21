// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What toolbox's `host` and `ntp` print: the text modules
//! (`userspace/services/toolbox/src/{host,ntp}.rs`), pulled in with `#[path]`
//! so the code under test is the code `TOOLBOX.ELF` is built from. The calls
//! that produce what they print are the `net` and `clock` interfaces
//! (`tests/host/devif-tests`, `tests/host/syscall-tests`).

#[path = "../../../../userspace/services/toolbox/src/host.rs"]
mod host;
#[path = "../../../../userspace/services/toolbox/src/ntp.rs"]
mod ntp_view;

use azos_devif::clock::{SOURCE_NTP, STATE_SYNCED, STATE_UNSET};
use azos_devif::{Address, ClockStatus, NtpStatus};

fn v6(text: &[u8; 16]) -> String {
    let mut s = String::new();
    host::write_v6(&mut s, text).unwrap();
    s
}

fn groups(g: [u16; 8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    for (i, w) in g.iter().enumerate() {
        a[2 * i..2 * i + 2].copy_from_slice(&w.to_be_bytes());
    }
    a
}

/// RFC 5952 §4: lowercase, no leading zeros, the longest run of two or more
/// zero groups becomes `::` (the first on a tie), and a lone zero group stays.
///
/// **Canary.** Compress a single zero group: the `2001:db8:0:1:...` line fails.
#[test]
fn an_ipv6_address_is_written_in_the_form_of_rfc_5952() {
    for (g, want) in [
        ([0, 0, 0, 0, 0, 0, 0, 0], "::"),
        ([0, 0, 0, 0, 0, 0, 0, 1], "::1"),
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], "2001:db8::1"),
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], "2001:db8::"),
        ([0, 0, 0, 0, 0, 0x1, 0x2, 0x3], "::1:2:3"),
        ([0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0], "fe80::1234:5678:9abc:def0"),
        ([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1], "2001:db8::1:0:0:1"),
        ([0x2001, 0, 0, 1, 0, 0, 0, 1], "2001:0:0:1::1"),
        ([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1], "2001:db8:0:1:1:1:1:1"),
        ([0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946], "2606:2800:220:1:248:1893:25c8:1946"),
        ([0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff], "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ] {
        assert_eq!(v6(&groups(g)), want, "{g:x?}");
    }
}

#[test]
fn an_answer_is_one_line_by_family() {
    let mut s = String::new();
    host::write_line(&mut s, "host.example", &Address::v4([93, 184, 216, 34])).unwrap();
    host::write_line(&mut s, "host.example", &Address::v6(groups([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]))).unwrap();
    host::write_line(&mut s, "host.example", &Address::default()).unwrap();
    assert_eq!(s, "host.example has address 93.184.216.34\nhost.example has IPv6 address 2001:db8::1\n");
}

#[test]
fn the_report_before_any_sync_says_there_is_no_server_and_no_clock() {
    let mut s = String::new();
    ntp_view::write_report(&mut s, &NtpStatus::default(), None).unwrap();
    assert_eq!(
        s,
        "server none (no lease names one and NTP_SERVER is empty or did not resolve)\n\
         client not synced: 0 exchanges, 0 given up\n"
    );
}

#[test]
fn the_report_after_a_sync_names_the_server_the_exchange_and_the_discipline() {
    let ntp = NtpStatus { server: 0x0A00_007C, synced: 1, last_unix_sec: 1_789_257_600, age_ms: 61_500, exchanges: 3, failures: 1 };
    let clock = ClockStatus { state: STATE_SYNCED, source: SOURCE_NTP, freq_ppb: 12, phase_ns: -3, steps: 1, rejected: 0 };
    let mut s = String::new();
    ntp_view::write_report(&mut s, &ntp, Some(&clock)).unwrap();
    assert_eq!(
        s,
        "server 10.0.0.124\n\
         client synced: last reply 1789257600 s after the Unix epoch, 61 s ago; 3 exchanges, 1 given up\n\
         clock synced: source ntp, frequency +12 ppb, phase -3 ns, 1 steps, 0 samples refused\n"
    );
    let unset = ClockStatus { state: STATE_UNSET, ..ClockStatus::default() };
    let mut s = String::new();
    ntp_view::write_report(&mut s, &ntp, Some(&unset)).unwrap();
    assert!(s.ends_with("clock unset: source none, frequency +0 ppb, phase +0 ns, 0 steps, 0 samples refused\n"), "{s}");
}
