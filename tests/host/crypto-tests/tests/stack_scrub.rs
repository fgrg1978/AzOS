// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `ct::scrub_stack` after HMAC and HKDF: the `hmac` and `hkdf` crates leave
//! the padded key (`key ^ ipad`, `key ^ opad`), the PRK and the T(i) blocks
//! on the stack, and the entries of `azos_crypto::hkdf` zero what their call
//! used before returning.
//!
//! How: the stack below this test's frame is painted, one entry is called,
//! and the same region is read back. Each probe is out of line and called
//! from the test's own frame, so it sees where the entry's frames were.
//!
//! Limits: this is the host build (its frames, not a kernel image's; the
//! kernel's are measured with tools/lint/stack_chain.py), memory below the
//! stack pointer is read as raw bytes, and a copy the compiler keeps in a
//! register or spills somewhere other than the callee frames is not seen.
//! It shows the scrub covers the call's depth and that no 32-byte run of a
//! key pattern is left in it. Canary: `--features canary-no-stack-scrub`
//! (the scrub does nothing) turns `no_key_bytes_survive_*` red.

use azos_crypto::ct::STACK_SCRUB_BYTES;
use azos_crypto::hkdf::{expand, extract, hkdf, hmac_sha256};

/// The window painted and read below the test's stack pointer.
const WINDOW: usize = 16 * 1024;
const PAINT: u8 = 0xcc;
const KEY: [u8; 32] = [0xa7; 32];

#[inline(always)]
fn sp() -> usize {
    let sp: usize;
    // SAFETY: reads the stack pointer register, nothing else.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack))
    };
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack))
    };
    sp
}

#[inline(never)]
fn paint() {
    let top = sp() - 64;
    for a in top - WINDOW..top {
        // SAFETY: below the stack pointer, inside the thread's stack mapping
        // (the test thread's stack is far larger than WINDOW).
        unsafe { (a as *mut u8).write_volatile(PAINT) };
    }
}

/// Bytes below this probe's stack pointer that are no longer the paint: how
/// deep the last call went.
#[inline(never)]
fn depth() -> usize {
    let top = sp() - 64;
    let mut lowest = top;
    for a in top - WINDOW..top {
        // SAFETY: as in `paint`.
        if unsafe { (a as *const u8).read_volatile() } != PAINT {
            lowest = a;
            break;
        }
    }
    top - lowest
}

/// Whether a run of 32 bytes equal to `b` sits below this probe's stack
/// pointer.
#[inline(never)]
fn has_run(b: u8) -> bool {
    let top = sp() - 64;
    let mut run = 0;
    for a in top - WINDOW..top {
        // SAFETY: as in `paint`.
        run = if unsafe { (a as *const u8).read_volatile() } == b { run + 1 } else { 0 };
        if run == 32 {
            return true;
        }
    }
    false
}

/// `key ^ ipad`, `key ^ opad`, and the secret itself.
fn patterns(secret: u8) -> [u8; 3] {
    [KEY[0] ^ 0x36, KEY[0] ^ 0x5c, secret]
}

#[test]
#[cfg_attr(debug_assertions, ignore = "an unoptimised build's frames are not the kernel's; the gate runs --release")]
fn the_scrub_covers_each_call() {
    let mut okm = [0u8; 64];
    let calls: [(&str, &dyn Fn(&mut [u8; 64])); 4] = [
        ("hmac_sha256", &|_| { hmac_sha256(&KEY, &[b"msg"]); }),
        ("extract", &|_| { extract(&KEY, b"ikm"); }),
        ("expand", &|o| assert!(expand(&KEY, b"info", o))),
        ("hkdf", &|o| assert!(hkdf(&KEY, b"ikm", b"info", o))),
    ];
    for (name, call) in calls {
        paint();
        call(&mut okm);
        let d = depth();
        // The scrub itself reaches STACK_SCRUB_BYTES plus its own frame; a
        // call deeper than that would show below it.
        assert!(
            d <= STACK_SCRUB_BYTES + 256,
            "{name} reached {d} bytes below the caller, past the {STACK_SCRUB_BYTES}-byte scrub"
        );
    }
}

#[test]
fn no_key_bytes_survive_hmac() {
    paint();
    let _ = hmac_sha256(&KEY, &[b"msg"]);
    for p in patterns(KEY[0]) {
        assert!(!has_run(p), "a run of {p:#04x} (key or padded key) survived hmac_sha256");
    }
}

#[test]
fn no_key_bytes_survive_hkdf() {
    // A PRK of 32 equal bytes: `expand` keys HMAC with it.
    let prk = [0x3cu8; 32];
    let mut okm = [0u8; 255 * 32];
    paint();
    assert!(expand(&prk, b"info", &mut okm));
    for p in [prk[0] ^ 0x36, prk[0] ^ 0x5c, prk[0]] {
        assert!(!has_run(p), "a run of {p:#04x} (PRK or padded PRK) survived expand");
    }
    paint();
    assert!(hkdf(&KEY, b"ikm", b"info", &mut okm[..64]));
    for p in patterns(KEY[0]) {
        assert!(!has_run(p), "a run of {p:#04x} survived hkdf");
    }
}
