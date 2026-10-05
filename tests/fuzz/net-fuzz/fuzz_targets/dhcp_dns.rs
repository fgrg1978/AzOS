// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: DHCP OFFER/ACK and DNS answer parsing on arbitrary
//! payloads. See `tests/host/net-tests/src/lib.rs::fuzz_entry::dhcp_dns`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    azos_net_tests::fuzz_entry::dhcp_dns(data);
});
