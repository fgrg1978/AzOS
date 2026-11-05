// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SHA-256 hash function (FIPS 180-4).
//!
//! The hash and the portable block function are `sha256_core.rs`; this file
//! picks the block function that runs (below).

#[path = "sha256_core.rs"]
mod core_impl;

pub use core_impl::{blocks_dup64, blocks_wide, sha256, Digest, Sha256};
use core_impl::blocks_generic;
// arch-only: the riscv64 Zbb / Zknh block functions; every other ISA takes the portable code.
#[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
use core_impl::rv;

// ---------------------------------------------------------------------------
// Block dispatch (wave 13): the CPU's SHA-2 instructions when it has them
// ---------------------------------------------------------------------------
//
// `select_*` runs once at boot on what the CPU reports (ID registers, device
// tree: the vDSO hwcap inputs), never on build flags, and keeps a path only
// after it reproduces the FIPS 180-4 "abc" digest and the generic code's
// digests over several lengths and both alignments.

use core::sync::atomic::{AtomicU8, Ordering};

static MODE: AtomicU8 = AtomicU8::new(MODE_GENERIC);
const MODE_GENERIC: u8 = 0;
const MODE_ZBB: u8 = 1;
const MODE_ZKNH: u8 = 2;
const MODE_HOOK: u8 = 3;
/// A whole-blocks function a platform registers with [`select_hook`]:
/// `(state, blocks)`, `blocks.len()` a multiple of 64.
pub type BlocksFn = fn(&mut [u32; 8], &[u8]);

azos_common::ro_hook! {
    /// `MODE_HOOK`'s function.
    static HOOK: BlocksFn;
}

/// Name of the block function in use: `generic`, `zbb`, `zknh` or `hook`.
pub fn backend() -> &'static str {
    match MODE.load(Ordering::Relaxed) {
        MODE_ZBB => "zbb",
        MODE_ZKNH => "zknh",
        MODE_HOOK => "hook",
        _ => "generic",
    }
}

fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    match MODE.load(Ordering::Relaxed) {
        MODE_HOOK => {
            // `select_hook` stores the function before it publishes MODE_HOOK.
            match HOOK.get_relaxed() {
                Some(f) => f(state, blocks),
                None => blocks_generic(state, blocks),
            }
        }
        // arch-only: riscv64 extension arms; other ISAs fall to `_`.
        // SAFETY (both riscv arms): set only by `select_riscv`, after cpu@0
        // declared the extension and the path passed the self-test.
        #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
        MODE_ZBB => unsafe { rv::blocks_zbb(state, blocks) },
        #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
        MODE_ZKNH => unsafe { rv::blocks_zknh(state, blocks) },
        _ => blocks_generic(state, blocks),
    }
}

/// "abc", FIPS 180-4 B.1.
const ABC_DIGEST: Digest = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

/// FIPS 180-4 / NIST CAVP two-block messages (56 and 112 bytes) and 1,000
/// bytes of `(i * 31 + 7) mod 256`, with digests computed off-target
/// (Python hashlib): known answers that do not come from this file's
/// template, so a bug shared by the fast and the generic path still fails.
const KAT_56: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const KAT_56_DIGEST: Digest = [
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
];
const KAT_112: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
const KAT_112_DIGEST: Digest = [
    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
    0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1,
];
const KAT_PATTERN_LEN: usize = 1000;
const KAT_PATTERN_DIGEST: Digest = [
    0x50, 0x97, 0xe7, 0xd5, 0x87, 0x35, 0x2f, 0x50, 0x97, 0x06, 0x2a, 0xe6, 0x79, 0xf3, 0x7b, 0xda,
    0x58, 0x02, 0xd9, 0xf8, 0x75, 0xab, 0xa1, 0x4c, 0x8c, 0xb4, 0xd1, 0xa1, 0x88, 0xad, 0xa1, 0x79,
];

/// The self-test buffer, 8-aligned so that offsets 0, 4 and 1 give an
/// 8-aligned, a 4-aligned and an odd start.
#[repr(align(8))]
struct TestMsg([u8; KAT_PATTERN_LEN + 8]);

/// `want` for `msg`, one-shot and fed in uneven `update` pieces (a partial
/// buffer fill, whole blocks from the input, a block straddling the buffer).
fn known_answer(msg: &[u8], want: &Digest) -> bool {
    if sha256(msg) != *want {
        return false;
    }
    const STEPS: [usize; 5] = [1, 63, 64, 65, 7];
    let mut h = Sha256::new();
    let mut rest = msg;
    let mut i = 0;
    while !rest.is_empty() {
        let k = STEPS[i % STEPS.len()].min(rest.len());
        h.update(&rest[..k]);
        rest = &rest[k..];
        i += 1;
    }
    h.finalize() == *want
}

/// The selected path against known answers ("abc"; the 56- and 112-byte
/// FIPS messages and a 1,000-byte message, each at an 8-aligned, a
/// 4-aligned and an odd start, one-shot and streamed), then against the
/// generic code on the padding boundaries (55/56: one or two final blocks;
/// 63/64/65: around a whole block) at the same three starts.
fn self_test() -> bool {
    if sha256(b"abc") != ABC_DIGEST {
        return false;
    }
    let mut msg = TestMsg([0u8; KAT_PATTERN_LEN + 8]);
    let pattern = |b: &mut [u8]| {
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    };
    for off in [0usize, 4, 1] {
        for (m, want) in [(KAT_56, &KAT_56_DIGEST), (KAT_112, &KAT_112_DIGEST)] {
            msg.0[off..off + m.len()].copy_from_slice(m);
            if !known_answer(&msg.0[off..off + m.len()], want) {
                return false;
            }
        }
        pattern(&mut msg.0[off..off + KAT_PATTERN_LEN]);
        if !known_answer(&msg.0[off..off + KAT_PATTERN_LEN], &KAT_PATTERN_DIGEST) {
            return false;
        }
    }
    pattern(&mut msg.0);
    for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 200] {
        for off in [0usize, 4, 1] {
            let m = &msg.0[off..off + len];
            let fast = sha256(m);
            let mode = MODE.swap(MODE_GENERIC, Ordering::Relaxed);
            let slow = sha256(m);
            MODE.store(mode, Ordering::Relaxed);
            if fast != slow {
                return false;
            }
        }
    }
    true
}

/// Install a platform block function (aarch64: the ARMv8 SHA-2
/// instructions, wrapped by the kernel so the SIMD registers are free). Kept
/// only if it passes the self-test; returns whether it did. Boot only,
/// before anything else hashes.
pub fn select_hook(f: BlocksFn) -> bool {
    HOOK.set(f);
    MODE.store(MODE_HOOK, Ordering::Release);
    if self_test() {
        return true;
    }
    MODE.store(MODE_GENERIC, Ordering::Release);
    false
}

/// Back to the portable path, for good: a CPU that came up after [`select_hook`]
/// lacks the hook's instructions. Needs no write to the sealed hook.
pub fn select_generic() {
    MODE.store(MODE_GENERIC, Ordering::Release);
}

/// riscv64: Zknh, else Zbb, else generic, from what every CPU declares. Returns
/// the backend kept. Boot only, before anything else hashes.
// arch-only: an optional riscv64 extension path (Zbb/Zknh), probed at boot;
// every other ISA takes the portable code or the select_hook path
// (aarch64 SHA2 CE, x86_64 SHA-NI).
#[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
pub fn select_riscv(zbb: bool, zknh: bool) -> &'static str {
    // Zknh's path is compiled with Zbb on as well (rev8 word loads, and the
    // code generator may pick other Zbb forms), so it needs both.
    for (on, mode) in [(zknh && zbb, MODE_ZKNH), (zbb, MODE_ZBB)] {
        if on {
            MODE.store(mode, Ordering::Release);
            if self_test() {
                return backend();
            }
        }
    }
    MODE.store(MODE_GENERIC, Ordering::Release);
    backend()
}

/// `no-bitmanip` boards: no Zbb/Zknh code exists in the image; generic only.
#[cfg(all(target_arch = "riscv64", feature = "no-bitmanip"))]
pub fn select_riscv(_zbb: bool, _zknh: bool) -> &'static str {
    backend()
}
