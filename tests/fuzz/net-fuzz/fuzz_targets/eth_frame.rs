// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: Ethernet frames through the kernel's RX dispatch
//! (`net_poll` -> ARP / IPv4 -> ICMP, IGMP, UDP, TCP / IPv6), with a TCP
//! listener and bound UDP sockets so segments reach the state machines. See
//! `tests/host/net-tests/src/lib.rs::fuzz_entry::eth_frames` for the input format.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    azos_net_tests::fuzz_entry::eth_frames(data);
});
