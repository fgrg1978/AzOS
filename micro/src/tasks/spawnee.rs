// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SPAWNEE.ELF`: started by `CAPTEST.ELF` through `SYS_SPAWN_EX`. Calls the
//! echo server once with its own capability and ends with 7, so a run shows
//! that a spawned task got the capabilities of its row and nothing else.

use azos_abi::cap::ty;
use azos_libsys as sys;

pub extern "C" fn main(_region: usize, _info: usize) -> ! {
    let ep = sys::cap_lookup(ty::ENDPOINT.raw(), 0);
    if ep <= 0 {
        sys::exit(1)
    }
    match sys::fast_ipc_call_ep_status(ep as u32, [41, 0, 0, 0]) {
        Ok(r) if r[0] == 42 => {
            sys::print(b"[SPAWNEE] echo answered 42\n");
            sys::exit(7)
        }
        _ => {
            sys::print(b"[SPAWNEE] FAIL echo\n");
            sys::exit(2)
        }
    }
}
