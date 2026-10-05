// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `OTA.ELF`: the ring-3 form of the recovery console's `ota status` and
//! `ota rollback` (RFC-0055 S5, wave 12), through `SYS_OTA_TYPED` under its
//! row's `Cap<Power>`: READ for the status, WRITE to roll back.
//!
//! Usage: `ota status | rollback`. Exit 0 on success, 1 when refused, 2 on a
//! usage error.

#![no_std]
#![no_main]

#[path = "../common.rs"]
mod common;

use common::*;
use azos_libsys as sys;

fn slot(s: u8) -> &'static [u8] {
    match s {
        0 => b"A",
        1 => b"B",
        2 => b"R",
        _ => b"?",
    }
}

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    let op = match name {
        b"status" => sys::families::OTA_OP_STATUS,
        b"rollback" => sys::families::OTA_OP_ROLLBACK,
        _ => return usage(b"ota status | rollback"),
    };
    if sys::arg(2).is_some() {
        return usage(b"ota status | rollback");
    }
    let found = sys::cap_lookup(sys::CapKind::Power as u8, 0);
    let cap = if found >= 0 { found as u32 } else { 0 };
    let r = sys::ota_typed(cap, op);
    if r < 0 {
        return refused(b"ota", name, r);
    }
    if op == sys::families::OTA_OP_STATUS {
        let (active, good, boots, bad) = sys::families::ota_status_unpack(r as u64);
        put(1, b"ota: active ");
        put(1, slot(active));
        put(1, b" last-good ");
        put(1, slot(good));
        put(1, b" boots ");
        put_num(1, false, boots as u64);
        put(1, b" bad-mask ");
        put_num(1, false, bad as u64);
        put(1, b"\n");
    } else if r == 1 {
        put(1, b"ota: already on the last good slot\n");
    } else {
        put(1, b"ota: rolled back (reboot to apply)\n");
    }
    0
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let code = run();
    sys::exit(code)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}
