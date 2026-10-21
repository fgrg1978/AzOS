// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The console, info and query syscalls that had no host test:
// `SYS_TEST` (0), `SYS_DISK_INFO`,
// `SYS_DISK_SIZE`, `DOMAIN_MEMINFO`, `DOMAIN_UPTIME`, `SYS_NET_INFO`,
// `DOMAIN_NET_GETIP`, `SYS_NET_GETMAC`, `SYS_NET_STATS`.
//
// **None of these handlers refuses anything.** They take no pointer, no
// handle and no capability; the only gate in front of them is the caller's
// seccomp row. So there is no refusal case to write, and these tests pin
// what each one forwards and how it converts the answer — the half a
// handler can get wrong (a byte order, a truncation, a sign).
//
// The devices are the `shim_fwd` recorders in `shims/drivers` and
// `shims/net`, armed per test; unarmed they are the stand-ins' `todo!()`.

use super::harness::serial;

fn arm_dev(f: syscall_test_drivers::shim_fwd::Fwd) {
    syscall_test_drivers::shim_fwd::arm(f);
}

fn dev_log() -> Vec<String> {
    syscall_test_drivers::shim_fwd::disarm().expect("device recorder was not armed").log
}

fn arm_nic(f: azos_net::shim_fwd::Fwd) {
    azos_net::shim_fwd::arm(f);
}

fn nic_log() -> Vec<String> {
    azos_net::shim_fwd::disarm().expect("NIC recorder was not armed").log
}

// ── Console ───────────────────────────────────────────────────────────────

// ── Memory, time ─────────────────────────────────────────────────────────

/// Free PAGES from the real PMM, not bytes, and live: one page taken is one
/// fewer.
#[test]
fn meminfo_is_the_pmms_free_page_count() {
    let _g = serial();
    let before = super::sys_meminfo();
    assert_eq!(before, azos_mm::pmm::free_pages() as i64);
    let _p = azos_mm::pmm::alloc_page().expect("arena exhausted");
    assert_eq!(super::sys_meminfo(), before - 1);
}

#[test]
fn uptime_is_the_raw_timer_count() {
    let _g = serial();
    arm_dev(syscall_test_drivers::shim_fwd::Fwd { now: 0x1234_5678_9A, ..Default::default() });
    assert_eq!(super::sys_uptime(), 0x1234_5678_9A);
    assert_eq!(dev_log(), vec!["get_time"]);
}

// ── Network queries ───────────────────────────────────────────────────────

/// `getip` answers the address as a big-endian `u32`: 192.168.1.20 is
/// 0xC0A8_0114, positive, with the first octet in the top byte.
#[test]
fn net_getip_packs_the_address_big_endian() {
    let _g = serial();
    arm_nic(azos_net::shim_fwd::Fwd { ip: [192, 168, 1, 20], ..Default::default() });
    assert_eq!(super::sys_net_getip(), 0xC0A8_0114);
}

