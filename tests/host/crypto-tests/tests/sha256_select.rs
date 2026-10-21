// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `sha256::select_hook` (wave 13): a platform block function is kept only
//! if it reproduces the known digests. Its own test binary, because the
//! selection is process-global and would race the other hash tests.

use azos_crypto::sha256::{backend, select_hook, sha256};

/// A block function that is wrong in one bit of one word.
fn broken(state: &mut [u32; 8], _blocks: &[u8]) {
    state[3] ^= 1;
}

#[test]
fn a_wrong_hook_is_refused_and_the_generic_path_stays() {
    let abc = sha256(b"abc");
    assert!(!select_hook(broken), "a hook that breaks the digest was kept");
    assert_eq!(backend(), "generic");
    assert_eq!(sha256(b"abc"), abc);
}
