// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Login` object: how the console's secure-attention prompt reaches the
//! login service, and the credential both of them and the enrolment tool make
//! of what a person typed.
//!
//! # Who does what
//!
//! * `termd` owns console input. On the secure-attention key (Ctrl+Alt+Del on
//!   a keyboard, `LOGIN_SAK_SERIAL_BYTE` on a serial line) it stops serving
//!   the shell, ends the session if one is live ([`Login::end`]; it draws the
//!   prompt only when that reports [`ended::OK`]), and asks for
//!   the user name and the passphrase itself: no other program reads the
//!   input or can make the key. It turns the line into a [`credential`] and
//!   calls [`Login::login`]; the typed text never leaves the terminal server.
//! * `logind` holds `EXEC` on the kernel's `keys` interface, masked to its
//!   `login` op, and a launch grant on the shell. It asks the kernel to verify
//!   the credential (`azos_devif::Keys::login`) and, when the kernel admits
//!   it, starts the shell as the user's session (`SPAWN_F_USER`).
//! * The kernel checks the credential against the signed topology's
//!   `[login.NAME]` row; neither the passphrase nor a hash of it is stored.
//!
//! # The credential
//!
//! [`credential`] is PBKDF2-HMAC-SHA256 with [`ROUNDS`] rounds, salted by the
//! user name. The stretching is not what protects a passphrase (the kernel
//! mixes in the board's own secret, `azos_crypto::keystore::login_public`, so a
//! verifier cannot be attacked without the board); it is the second line, for
//! the day the board's secret is read off the medium with the topology.
#![no_std]
#![forbid(unsafe_code)]

pub use azos_idl::{IdlError, MsgDesc, Transport};
use azos_crypto::hkdf::hmac_sha256;
use azos_idl::azos_interface;

/// The interface id (ASCII "LOGN").
pub const LOGIN_ID: u32 = 0x4C4F_474E;
/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.login";

/// Longest user name, in bytes: the kernel's `login` op carries it in two words.
pub const NAME_MAX: usize = 16;
/// Words of a user name.
pub const NAME_WORDS: usize = NAME_MAX / 8;
/// Bytes of a credential.
pub const CREDENTIAL_BYTES: usize = 32;
/// Words of a credential.
pub const CREDENTIAL_WORDS: usize = CREDENTIAL_BYTES / 8;
/// Longest passphrase the prompt takes, in bytes.
pub const PASSPHRASE_MAX: usize = 128;
/// PBKDF2 rounds of [`credential`].
pub const ROUNDS: u32 = 4096;

/// What [`Login::state`] says.
pub mod state {
    /// Nobody is enrolled: there is no login gate, the console session is the
    /// system's and the shell starts as it always did.
    pub const OPEN: u32 = 0;
    /// Users are enrolled and nobody is logged in.
    pub const LOCKED: u32 = 1;
    /// A user's session is live.
    pub const SESSION: u32 = 2;
}

/// What [`Login::end`] says.
pub mod ended {
    /// No session is left: nothing of the user's runs.
    pub const OK: u32 = 0;
    /// The shell survived the forced stop. The session is still recorded (a
    /// login is answered `NOT_NOW`) and the terminal server must not draw the
    /// secure prompt: the shell could draw over it or read it.
    pub const RUNNING: u32 = 1;
}

/// What [`Login::login`] says.
pub mod status {
    /// The credential was admitted and the user's shell started.
    pub const STARTED: u32 = 0;
    /// Refused: the user is unknown, the credential is wrong, or the account is
    /// locked after too many failures in a row. One answer for all three, as
    /// the kernel's (a locked account would say that it exists).
    pub const REFUSED: u32 = 1;
    /// The kernel cannot verify (the board holds no root), or the service
    /// cannot ask it.
    pub const NOT_READY: u32 = 2;
    /// The credential was admitted but the session did not start.
    pub const NO_SESSION: u32 = 3;
    /// A session is live already, or nobody is enrolled: not a login.
    pub const NOT_NOW: u32 = 4;
}

/// The Login interface. One client (the terminal server), one server (the
/// login service).
#[azos_interface(id = 0x4C4F_474E, level = 1, words = 8)]
pub trait Login {
    /// [`state::OPEN`], [`state::LOCKED`] or [`state::SESSION`].
    #[idempotent]
    fn state(&self) -> u32;
    /// Log `user` (a name of up to [`NAME_MAX`] bytes, NUL-padded, packed by
    /// [`pack_name`]) in with `credential` ([`credential`], packed by
    /// [`pack_credential`]). A [`status`].
    fn login(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> u32;
    /// End the user's session: the shell and everything beneath it stop. An
    /// [`ended`] code: [`ended::OK`] when there is no session any more (also
    /// when there was none), [`ended::RUNNING`] when the shell did not stop,
    /// in which case the session stays recorded and no other login is taken.
    fn end(&mut self) -> u32;
}

/// A user name as the words of the interface and of the kernel's `login` op.
/// `None` for a name longer than [`NAME_MAX`] or with a NUL in it.
pub fn pack_name(name: &[u8]) -> Option<[u64; NAME_WORDS]> {
    if name.len() > NAME_MAX || name.contains(&0) {
        return None;
    }
    let mut b = [0u8; NAME_MAX];
    b[..name.len()].copy_from_slice(name);
    Some(core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]))))
}

/// The name in `words`, up to its first NUL.
pub fn unpack_name(words: &[u64; NAME_WORDS], out: &mut [u8; NAME_MAX]) -> usize {
    for (c, w) in out.chunks_exact_mut(8).zip(words) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    out.iter().position(|&b| b == 0).unwrap_or(NAME_MAX)
}

/// A credential as the words of the interface and of the kernel's `login` op.
pub fn pack_credential(c: &[u8; CREDENTIAL_BYTES]) -> [u64; CREDENTIAL_WORDS] {
    core::array::from_fn(|i| u64::from_le_bytes(c[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8])))
}

/// The inverse of [`pack_credential`].
pub fn unpack_credential(w: &[u64; CREDENTIAL_WORDS]) -> [u8; CREDENTIAL_BYTES] {
    let mut c = [0u8; CREDENTIAL_BYTES];
    for (b, w) in c.chunks_exact_mut(8).zip(w) {
        b.copy_from_slice(&w.to_le_bytes());
    }
    c
}

/// Salt of [`credential`], before the user name.
const SALT: &[u8] = b"azos console credential v1\0";

/// PBKDF2-HMAC-SHA256 (RFC 8018) for one 32-byte block.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..rounds {
        u = hmac_sha256(password, &[&u]);
        for (t, u) in t.iter_mut().zip(u.iter()) {
            *t ^= u;
        }
    }
    t
}

/// The credential of `passphrase` for `user`: what the terminal server hands
/// the login service and what the enrolment tool derives the verifier from.
pub fn credential(user: &[u8], passphrase: &[u8]) -> [u8; CREDENTIAL_BYTES] {
    let mut salt = [0u8; SALT.len() + NAME_MAX];
    salt[..SALT.len()].copy_from_slice(SALT);
    let n = user.len().min(NAME_MAX);
    salt[SALT.len()..SALT.len() + n].copy_from_slice(&user[..n]);
    pbkdf2_sha256(passphrase, &salt[..SALT.len() + n], ROUNDS)
}
