// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The console, info and query syscalls that had no host test:
// `SYS_TEST` (0), `SYS_PUTCHAR` (1), `SYS_GETCHAR` (2), `SYS_GPIO_INFO`,
// `SYS_PWM_INFO`, `SYS_I2C_INFO`, `SYS_MOTOR_INFO`, `SYS_DISK_INFO`,
// `SYS_DISK_SIZE`, `SYS_MEMINFO`, `SYS_UPTIME`, `SYS_NET_INFO`,
// `SYS_NET_GETIP`, `SYS_NET_PING`, `SYS_NET_GETMAC`, `SYS_NET_STATS`.
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

#[test]
fn test_prints_its_line_through_the_locked_writer() {
    let _g = serial();
    arm_dev(Default::default());
    assert_eq!(super::sys_test(), 0);
    assert_eq!(dev_log(), vec!["puts_locked \"[SYSCALL] test ok\\n\"".to_string()]);
}

/// `a0` is a register; the UART takes its low byte, through the ring-3
/// console path (never the lock-free `putc`).
#[test]
fn putchar_writes_the_low_byte_of_a0() {
    let _g = serial();
    arm_dev(Default::default());
    assert_eq!(super::sys_putchar(0x41), 0);
    assert_eq!(super::sys_putchar(0xFFFF_FF0A), 0);
    assert_eq!(dev_log(), vec!["console_write_ring3 [65]".to_string(), "console_write_ring3 [10]".to_string()]);
}

/// Empty FIFO is `-1` and does NOT read the data register; a byte above
/// 0x7F comes back positive, so it can never be mistaken for the `-1`.
#[test]
fn getchar_is_minus_one_on_an_empty_fifo_and_never_negative_for_a_byte() {
    let _g = serial();
    arm_dev(Default::default());
    assert_eq!(super::sys_getchar(), -1);
    assert_eq!(dev_log(), vec!["can_read".to_string()], "read the data register of an empty FIFO");

    arm_dev(syscall_test_drivers::shim_fwd::Fwd { rx: Some(0xFF), ..Default::default() });
    assert_eq!(super::sys_getchar(), 0xFF);
    assert_eq!(dev_log(), vec!["can_read".to_string(), "getc".to_string()]);
}

// ── Info printers ─────────────────────────────────────────────────────────

#[test]
fn each_info_call_reaches_its_own_printer_and_answers_zero() {
    let _g = serial();
    arm_dev(Default::default());
    assert_eq!(super::sys_gpio_info(), 0);
    assert_eq!(super::sys_pwm_info(), 0);
    assert_eq!(super::sys_i2c_info(), 0);
    assert_eq!(dev_log(), vec!["gpio_info", "pwm_info", "i2c_info"]);

    azos_robot::shim_arm_motor_info();
    assert_eq!(super::sys_motor_info(), 0);
    assert_eq!(azos_robot::shim_disarm_motor_info(), Some(1));

    arm_nic(Default::default());
    assert_eq!(super::sys_net_info(), 0);
    assert_eq!(super::sys_net_stats(), 0);
    assert_eq!(nic_log(), vec!["net_info", "net_info"]);
}

// ── Disk, memory, time ────────────────────────────────────────────────────

#[test]
fn disk_size_is_the_devices_sector_count_and_disk_info_prints_it() {
    let _g = serial();
    arm_dev(syscall_test_drivers::shim_fwd::Fwd { sectors: 131_072, ..Default::default() });
    assert_eq!(super::sys_disk_size(0), 131_072);
    assert_eq!(super::sys_disk_info(), 0);
    assert_eq!(dev_log(), vec!["capacity_sectors", "capacity_sectors"]);
}

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

/// `getmac` answers the six octets LITTLE-endian in the low 48 bits — the
/// opposite order from `getip` — with the top 16 bits clear.
#[test]
fn net_getmac_packs_the_mac_little_endian_in_48_bits() {
    let _g = serial();
    arm_nic(azos_net::shim_fwd::Fwd { mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0xFE], ..Default::default() });
    assert_eq!(super::sys_net_getmac(), 0x0000_FE34_1200_5452);
}

/// `ping` takes the address big-endian in `a0` (its low 32 bits) and answers
/// what the NIC answered.
#[test]
fn net_ping_unpacks_a0_big_endian_and_returns_the_nics_answer() {
    let _g = serial();
    arm_nic(azos_net::shim_fwd::Fwd { ping: -3, ..Default::default() });
    assert_eq!(super::sys_net_ping(0xFFFF_FFFF_0A00_0202), -3);
    assert_eq!(nic_log(), vec!["net_ping [10, 0, 2, 2]"]);
}
