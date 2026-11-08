// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `COREUTIL.ELF`: the basic utilities (`azos_coreutils`: cp mv rm mkdir rmdir
//! touch stat du df find head tail grep sort uniq tr cut tee date env pwd
//! basename dirname seq printf, and the refusals of chmod, chown, ln, kill ...),
//! dispatched on `argv[0]`.
//!
//! Its topology row holds the root directory and the `/fat` and `/tmp` write
//! trees and nothing else: no endpoint, no introspection region, no task view.
//! The tools of `TOOLBOX.ELF` that look at the system hold no write tree; the
//! tools that change files hold no view of the system.

#![no_std]
#![no_main]

use azos_libsys as sys;

mod native;

/// Write a message on standard error.
fn fail(what: &[u8], why: &[u8]) {
    for part in [what, b": ", why, b"\n"] {
        let _ = sys::write(2, part);
    }
}

/// `bytes` of fresh memory: a memory object of this task's own, mapped.
fn scratch(bytes: usize) -> Option<&'static mut [u8]> {
    let pages = bytes.div_ceil(4096) as u64;
    let cap = sys::shm_create_typed(pages, sys::SHM_RW);
    if cap < 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        return None;
    }
    // SAFETY: the mapping is `pages` pages of read-write memory that nothing
    // else in this task refers to, kept for the task's life.
    Some(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, bytes) })
}

#[sys::main(panic_exit = 70)]
fn main() -> i32 {
    let name = sys::arg(0).unwrap_or(b"");
    // `argv[0]` may be a path: dispatch on its last component.
    let base = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
    if !azos_coreutils::is_tool(base) {
        fail(b"coreutil", b"run as one of azos_coreutils::NAMES");
        return 2;
    }
    // At most `SPAWN_ARGC_MAX` words, the name first.
    let mut argv: [&[u8]; 16] = [b""; 16];
    let mut n = 0;
    for i in 1..sys::argc().min(argv.len()) {
        argv[n] = sys::arg(i).unwrap_or(b"");
        n += 1;
    }
    let need = azos_coreutils::scratch_bytes(base);
    let buf: &mut [u8] = if need == 0 {
        &mut []
    } else {
        match scratch(need) {
            Some(s) => s,
            None => {
                fail(base, b"no memory for its working buffer");
                return 1;
            }
        }
    };
    let mut host = native::Native::new();
    let code = azos_coreutils::run(&mut host, base, &argv[..n], buf).unwrap_or(2);
    // A reader that went away is the tool being done, not a failure.
    let _ = host.flush();
    code
}
