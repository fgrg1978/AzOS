// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `FLIGHT.ELF`: the ring-3 form of the recovery console's `flight arm` and
//! `flight disarm` (RFC-0055 S5, wave 12), through the kernel-hosted `flight` endpoint its row grants.
//!
//! Its topology row is the whole of its authority: `Cap<Motor>` WRITE on
//! both wheels of the drivetrain, and only under the actuation profile. It
//! presents the wheel-0 capability (found with `SYS_CAP_INFO`, handle 0
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
use sys::dev::FlightCall;

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    if !matches!(name, b"arm" | b"disarm") || sys::arg(2).is_some() {
        return usage(b"flight arm | disarm");
    }
    let mut c = sys::dev::FlightClient::new(sys::dev::Ep(endpoint(sys::dev::key::FLIGHT)));
    let r = if name == b"arm" { served(c.arm()) } else { served(c.disarm()) };
    if let Err(code) = r {
        return refused(b"flight", name, code);
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
