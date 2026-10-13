// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `OTA.ELF`: the ring-3 form of the recovery console's `ota status` and
//! `ota rollback` (RFC-0055 S5, wave 12), through the kernel-hosted
//! `ota` endpoint its row grants: READ for the status, WRITE to roll back.
//!
//! Usage: `ota status | rollback`. Exit 0 on success, 1 when refused, 2 on a
//! usage error.

#![no_std]
#![no_main]

#[path = "../common.rs"]
mod common;

use common::*;
use azos_libsys as sys;
use sys::dev::OtaCall;

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
    if !matches!(name, b"status" | b"rollback") || sys::arg(2).is_some() {
        return usage(b"ota status | rollback");
    }
    let mut c = sys::dev::OtaClient::new(sys::dev::Ep(endpoint(sys::dev::key::OTA)));
    if name == b"status" {
        match valued(c.status()) {
            Ok(w) => {
                let (active, good, boots, bad) = sys::families::ota_status_unpack(w);
                put(1, b"ota: active ");
                put(1, slot(active));
                put(1, b" last-good ");
                put(1, slot(good));
                put(1, b" boots ");
                put_num(1, false, boots as u64);
                put(1, b" bad-mask ");
                put_num(1, false, bad as u64);
                put(1, b"\n");
            }
            Err(code) => return refused(b"ota", name, code),
        }
    } else {
        match valued(c.rollback()) {
            Ok(1) => put(1, b"ota: already on the last good slot\n"),
            Ok(_) => put(1, b"ota: rolled back (reboot to apply)\n"),
            Err(code) => return refused(b"ota", name, code),
        }
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
