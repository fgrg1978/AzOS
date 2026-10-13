// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `CONFIG.ELF`: the ring-3 form of the recovery console's `config get` and
//! `config set` (RFC-0055 S5, wave 12), through the kernel-hosted
//! `config` endpoint its row grants. Setting any key needs WRITE; it is applied at once,
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
use sys::dev::ConfigCall;

const USAGE: &[u8] = b"config get <key> | set <key> <value>";

/// `text` as NUL-padded little-endian words, or `None` when it does not fit
/// (or holds a NUL: a key and a value are text).
fn pack<const N: usize>(text: &[u8]) -> Option<[u64; N]> {
    if text.len() > N * 8 || text.contains(&0) {
        return None;
    }
    let mut b = [0u8; 64];
    b[..text.len()].copy_from_slice(text);
    Some(core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]))))
}

fn run() -> i32 {
    let name = sys::arg(1).unwrap_or(b"");
    let Some(key) = sys::arg(2) else {
        return usage(USAGE);
    };
    let Some(kw) = pack::<{ sys::dev::families::KEY_WORDS }>(key) else {
        return usage(USAGE);
    };
    let mut c = sys::dev::ConfigClient::new(sys::dev::Ep(endpoint(sys::dev::key::CONFIG)));
    match name {
        b"get" if sys::arg(3).is_none() => match valued(c.get(kw)) {
            Ok(words) => {
                let mut v = [0u8; sys::dev::families::VALUE_MAX];
                for (i, w) in words.iter().enumerate() {
                    v[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
                }
                let n = v.iter().position(|&b| b == 0).unwrap_or(v.len());
                put(1, key);
                put(1, b"=");
                put(1, &v[..n]);
                put(1, b"\n");
                0
            }
            Err(code) => refused(b"config", b"get", code),
        },
        b"set" if sys::arg(3).is_some() && sys::arg(4).is_none() => {
            let val = sys::arg(3).unwrap_or(b"");
            let Some(vw) = pack::<{ sys::dev::families::VALUE_WORDS }>(val) else {
                return usage(USAGE);
            };
            if let Err(code) = served(c.set(kw, vw)) {
                return refused(b"config", b"set", code);
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
