// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `BEHAVIOR.ELF`: the ring-3 form of the recovery console's `behavior
//! enable|disable <layer>` and the enabled-layer read (RFC-0055 S5, wave 12),
//! through `SYS_BEHAVIOR_TYPED` under its row's `Cap<Power>`.
//!
//! Usage: `behavior status | enable <layer> | disable <layer>` (layers 1..3).
//! Exit 0 on success, 1 when refused, 2 on a usage error.

#![no_std]
#![no_main]

#[path = "../common.rs"]
mod common;

use common::*;
use azos_libsys as sys;

const USAGE: &[u8] = b"behavior status | enable <layer> | disable <layer>";

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    let (op, layer) = match name {
        b"status" if sys::arg(2).is_none() => (sys::families::BEHAVIOR_OP_STATUS, 0),
        b"enable" | b"disable" => match sys::arg(2).and_then(parse) {
            Some(l) if sys::arg(3).is_none() => (
                if name == b"enable" {
                    sys::families::BEHAVIOR_OP_ENABLE
                } else {
                    sys::families::BEHAVIOR_OP_DISABLE
                },
                l,
            ),
            _ => return usage(USAGE),
        },
        _ => return usage(USAGE),
    };
    let found = sys::cap_lookup(sys::CapKind::Power as u8, 0);
    let cap = if found >= 0 { found as u32 } else { 0 };
    let r = sys::behavior_typed(cap, op, layer);
    if r < 0 {
        return refused(b"behavior", name, r);
    }
    if op == sys::families::BEHAVIOR_OP_STATUS {
        put(1, b"behavior: enabled layers");
        for l in 0..sys::families::BEHAVIOR_LAYERS {
            if r as u64 & (1 << l) != 0 {
                put(1, b" L");
                put_num(1, false, l);
            }
        }
        put(1, b"\n");
    } else {
        put(1, b"behavior: L");
        put_num(1, false, layer);
        put(1, if op == sys::families::BEHAVIOR_OP_ENABLE { b" enabled\n" } else { b" disabled\n" });
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
