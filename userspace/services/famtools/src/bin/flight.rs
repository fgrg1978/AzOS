// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `FLIGHT.ELF`: the ring-3 form of the recovery console's `flight arm` and
//! `flight disarm` (RFC-0055 S5, wave 12), through `SYS_FLIGHT_TYPED`.
//!
//! Its topology row is the whole of its authority: `Cap<Motor>` WRITE on
//! both wheels of the drivetrain, and only under the actuation profile. It
//! presents the wheel-0 capability (found with `SYS_CAP_LOOKUP`, handle 0
//! when the row grants none); the kernel checks it and the pair, against the
//! same table the console uses, and records a refusal.
//!
//! Usage: `flight arm | disarm`. Exit 0 on success, 1 when refused, 2 on a
//! usage error.

#![no_std]
#![no_main]

#[path = "../common.rs"]
mod common;

use common::*;
use azos_libsys as sys;

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    let op = match name {
        b"arm" => sys::families::FLIGHT_OP_ARM,
        b"disarm" => sys::families::FLIGHT_OP_DISARM,
        _ => return usage(b"flight arm | disarm"),
    };
    if sys::arg(2).is_some() {
        return usage(b"flight arm | disarm");
    }
    let found = sys::cap_lookup(sys::CapKind::Motor as u8, 0);
    let cap = if found >= 0 { found as u32 } else { 0 };
    let r = sys::flight_typed(cap, op);
    if r < 0 {
        return refused(b"flight", name, r);
    }
    put(1, b"flight: ");
    put(1, name);
    put(1, b" ok\n");
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
