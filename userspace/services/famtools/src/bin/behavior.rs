// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `BEHAVIOR.ELF`: the ring-3 form of the recovery console's `behavior
//! enable|disable <layer>` and the enabled-layer read (wave 12),
//! through the kernel-hosted `behavior` endpoint its row grants.
//!
//! Usage: `behavior status | enable <layer> | disable <layer>` (layers 1..3).
//! Exit 0 on success, 1 when refused, 2 on a usage error.

#![no_std]
#![no_main]

#[path = "../common.rs"]
mod common;

use common::*;
use azos_libsys as sys;
use sys::dev::BehaviorCall;

const USAGE: &[u8] = b"behavior status | enable <layer> | disable <layer>";

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    let layer = match name {
        b"status" if sys::arg(2).is_none() => 0,
        b"enable" | b"disable" => match sys::arg(2).and_then(parse) {
            Some(l) if sys::arg(3).is_none() => l as u32,
            _ => return usage(USAGE),
        },
        _ => return usage(USAGE),
    };
    let mut c = sys::dev::BehaviorClient::new(sys::dev::Ep(endpoint(sys::dev::key::BEHAVIOR)));
    match name {
        b"status" => match valued(c.status()) {
            Ok(mask) => {
                put(1, b"behavior: enabled layers");
                for l in 0..sys::families::BEHAVIOR_LAYERS {
                    if mask & (1 << l) != 0 {
                        put(1, b" L");
                        put_num(1, false, l);
                    }
                }
                put(1, b"\n");
            }
            Err(code) => return refused(b"behavior", name, code),
        },
        _ => {
            let r = if name == b"enable" { served(c.enable(layer)) } else { served(c.disable(layer)) };
            if let Err(code) = r {
                return refused(b"behavior", name, code);
            }
            put(1, b"behavior: L");
            put_num(1, false, layer as u64);
            put(1, if name == b"enable" { b" enabled\n" } else { b" disabled\n" });
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
