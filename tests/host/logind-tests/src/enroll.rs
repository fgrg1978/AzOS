// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The verifier an administrator lists in a `[login.NAME]` row, computed off
//! the board from its seed (`login_enroll`, the one implementation of the derivation outside the kernel: the gate's rows and a bench call it).

/// The root `Backend::Boot` keys derive from, for the board seed `seed`:
/// `HKDF-SHA256(salt = "azos keystore root v1", ikm = seed, info = "boot")`,
/// restated from the kernel's `azos_syscall::keys::root_for` so that a change
/// there that this does not follow fails `tests/host/logind-tests`. `None` for
/// a seed of all zeros: a board without one derives nothing.
pub fn boot_root(seed: &[u8; 32]) -> Option<[u8; 32]> {
    if seed.iter().all(|&b| b == 0) {
        return None;
    }
    let mut root = [0u8; 32];
    azos_crypto::hkdf::hkdf(b"azos keystore root v1", seed, b"boot", &mut root).then_some(root)
}

/// The verifier for `pass` of `user` (NUL-padded to `name`) at root `owner` on
/// the board whose seed is `seed`.
pub fn verifier(seed: &[u8; 32], owner: u32, name: &[u8; 16], user: &[u8], pass: &[u8]) -> Option<[u8; 32]> {
    let root = boot_root(seed)?;
    azos_crypto::keystore::login_public(&root, owner, name, &azos_login::credential(user, pass))
}
