// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `CONFIG.ELF`: the ring-3 form of the recovery console's `config get` and
//! `config set` (RFC-0055 S5, wave 12), through `SYS_CONFIG_TYPED` under its
//! row's `Cap<Power>`. Setting any key needs WRITE; it is applied at once,
//! as on the console. Saving to `/fat/CONFIG.INI` stays a console command.
//!
//! Usage: `config get <key> | set <key> <value>`. Exit 0 on success, 1 when
//! refused or not set, 2 on a usage error.

#![no_std]
#![no_main]

#[path = "../common.rs"]
mod common;

use common::*;
use azos_libsys as sys;

const USAGE: &[u8] = b"config get <key> | set <key> <value>";

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    let Some(key) = sys::arg(2) else {
        return usage(USAGE);
    };
    let found = sys::cap_lookup(sys::CapKind::Power as u8, 0);
    let cap = if found >= 0 { found as u32 } else { 0 };
    let mut buf = [0u8; sys::families::CONFIG_VAL_MAX as usize];
    match name {
        b"get" if sys::arg(3).is_none() => {
            let r = sys::config_typed(cap, sys::families::CONFIG_OP_GET, key, &mut buf);
            if r < 0 {
                return refused(b"config", b"get", r);
            }
            put(1, key);
            put(1, b"=");
            put(1, &buf[..r as usize]);
            put(1, b"\n");
            0
        }
        b"set" if sys::arg(3).is_some() && sys::arg(4).is_none() => {
            let val = sys::arg(3).unwrap_or(b"");
            if val.len() > buf.len() {
                return usage(USAGE);
            }
            buf[..val.len()].copy_from_slice(val);
            let r = sys::config_typed(cap, sys::families::CONFIG_OP_SET, key, &mut buf[..val.len()]);
            if r < 0 {
                return refused(b"config", b"set", r);
            }
            put(1, b"config: ");
            put(1, key);
            put(1, b" set\n");
            0
        }
        _ => usage(USAGE),
    }
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
