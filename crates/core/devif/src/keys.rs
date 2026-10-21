// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Keys` interface: keys held for their users, used by handle.
//!
//! A task that signs, seals or derives does not hold the key. It holds a
//! **handle** the kernel gave it, and asks the kernel to use the key for it;
//! the secret stays in the kernel's keystore (`azos_crypto::keystore` decides,
//! `azos_syscall::keys` serves). Each key carries a [`Policy`]: one purpose, an
//! envelope (the owner's tasks, or the owner's tasks that run the image that
//! made it), a time to live and a number of uses. A use outside the policy
//! answers [`outcome::DENIED`] and is a `key-use` decision record with the
//! reason (`azos_decision::Rule::KeyUse`): the key does not allow the op,
//! the caller is not its owner, its uses are used up, it expired.
//!
//! The keystore is **per owner** (`owner_root`, the user the caller's Domain
//! belongs to; 0 is the system): a handle is a name in one owner's table, and
//! another owner that presents it is refused and recorded.
//!
//! # Capability shape
//!
//! The endpoint `keys` carries no resource. The op classes:
//!
//! * `READ`: use a key ([`Keys::sign`], [`Keys::seal`], [`Keys::unseal`]) and
//!   take its public part ([`Keys::public`]). They stay live while the system
//!   is contained: a signature is not an actuation.
//! * `WRITE`: make a key ([`Keys::generate`], [`Keys::import`],
//!   [`Keys::derive`], [`Keys::unwrap`]). Refused while the system is
//!   contained: no new secret is minted then, except that [`Keys::generate`]
//!   still opens a *named* key (the board determines it, so it is no new
//!   authority, and a service that signs with it must come back up when the
//!   system is contained). [`Keys::destroy`] needs `WRITE` too, but contained
//!   or not: letting go of a secret is always allowed.
//! * `EXEC`: let a key leave, wrapped ([`Keys::wrap`]), and open a user's
//!   console session ([`Keys::login`]), which is a control of the node and not
//!   a use of a key of the caller's.
//!
//! A holder narrows itself further with the capability's `OP_MASK`: the SSH
//! server is granted `generate`, `public` and `sign` and cannot import a
//! key or wrap one. See `azos_topology`.
//!
//! # Where the bytes go
//!
//! A reply holds six words, a request seven. The ops that fit carry their
//! data inline: a name is [`NAME_WORDS`] words, a 32-byte secret or block
//! [`BLOCK_WORDS`], a sealed block [`SEALED_WORDS`]. A signature is 64 bytes and
//! a message may be longer than a request, so [`Keys::sign`] works in a
//! memory object the caller shares: the message is at offset 0, the signature
//! replaces it. The object is named by a `Cap<KeyBuf>` in the request and
//! stays in the caller's table (`khost::takes_caps`); it must be read-write,
//! at least [`SIGN_BUF_MIN`] bytes and kernel-mapped, and the caller must hold
//! `READ` and `WRITE` on it.
//!
//! # Names and backends
//!
//! [`Keys::generate`] makes a key. With a zero name and the volatile backend
//! the secret is drawn from the entropy pool and lives in RAM until the key is
//! destroyed or the system resets. With a name and a deriving backend the
//! secret is derived from a root secret the board holds, so the same name gives
//! the same key at every boot and nothing is stored: `backend::BOOT` from the
//! board seed in BOOTMETA's reserved sector, `backend::TPM_NV` from a secret in
//! a TPM NV index, `backend::VOLUME` from a secret in a file on a sealed
//! volume. Opening a name again returns the same handle; opening it with another
//! policy is `REFUSED`. A backend whose root the board does not hold answers
//! `NOT_READY`.
//!
//! # Outcomes
//!
//! `DENIED`: the endpoint lacks the class, or the key's policy refuses the use.
//! `NO_RESOURCE`: no such handle (never made, destroyed, or its slot was
//! reused). `BAD_ARGUMENT`: a malformed policy, name, message or buffer.
//! `BUSY`: the table, or this owner's share of it, is full. `REFUSED`: a name
//! that exists with another policy. `NOT_READY`: the pool is unseeded, or the
//! backend has no root.

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap, Reader, Wire, Writer};

/// The interface id (ASCII "KEYS").
pub const KEYS_ID: u32 = 0x4B45_5953;

/// Words of a key's name: 16 bytes.
pub const NAME_WORDS: usize = 2;
/// Words of a secret or a data block: 32 bytes.
pub const BLOCK_WORDS: usize = 4;
/// Words of a sealed block: the 32 bytes and a 16-byte tag.
pub const SEALED_WORDS: usize = 6;
/// Most bytes of a message [`Keys::sign`] takes from the buffer.
pub const SIGN_MSG_MAX: usize = 256;
/// Bytes of a signature.
pub const SIG_BYTES: usize = 64;
/// Least size of the buffer of [`Keys::sign`]: room for the message or the signature.
pub const SIGN_BUF_MIN: usize = if SIGN_MSG_MAX > SIG_BYTES { SIGN_MSG_MAX } else { SIG_BYTES };

/// What a key is for. Exactly one.
pub mod purpose {
    /// An Ed25519 key: [`super::Keys::sign`] and [`super::Keys::public`].
    pub const SIGN: u8 = 1;
    /// A symmetric key that seals and opens 32-byte blocks.
    pub const SEAL: u8 = 2;
    /// A symmetric key that children are derived from.
    pub const DERIVE: u8 = 4;
    /// A symmetric key that wraps other keys.
    pub const WRAP: u8 = 8;
}

/// Who may use a key.
pub mod envelope {
    /// Any task of the owner.
    pub const OWNER: u8 = 0;
    /// The tasks of the owner that run the image that made the key.
    pub const IMAGE: u8 = 1;
}

/// Where a key's secret comes from.
pub mod backend {
    /// Random, in RAM.
    pub const VOLATILE: u8 = 0;
    /// Derived from the board seed (BOOTMETA).
    pub const BOOT: u8 = 1;
    /// Derived from a secret in a TPM NV index.
    pub const TPM_NV: u8 = 2;
    /// Derived from a secret in a file on a sealed volume.
    pub const VOLUME: u8 = 3;
}

/// What a `Cap<KeyBuf>` names: a read-write memory object of at least
/// [`SIGN_BUF_MIN`] bytes the caller shares with the keystore for one call.
pub struct KeyBuf;

/// The policy of a key, as it travels: two words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// One of [`purpose`].
    pub purpose: u8,
    /// One of [`envelope`].
    pub envelope: u8,
    /// One of [`backend`].
    pub backend: u8,
    /// May leave the keystore, wrapped.
    pub wrappable: bool,
    /// Uses the handle serves; 0 is no limit.
    pub max_uses: u32,
    /// Seconds the handle lives; 0 is no expiry.
    pub ttl_s: u32,
}

impl Wire for Policy {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(
            u64::from(self.purpose)
                | u64::from(self.envelope) << 8
                | u64::from(self.backend) << 16
                | u64::from(self.wrappable) << 24
                | u64::from(self.max_uses) << 32,
        );
        w.word(u64::from(self.ttl_s));
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let a = r.word();
        let ttl = r.word();
        // Bits 25..32 are reserved, and so are the high bits of the second word.
        if a >> 25 & 0x7F != 0 || ttl > u64::from(u32::MAX) {
            r.fail();
        }
        Policy {
            purpose: a as u8,
            envelope: (a >> 8) as u8,
            backend: (a >> 16) as u8,
            wrappable: a >> 24 & 1 != 0,
            max_uses: (a >> 32) as u32,
            ttl_s: ttl as u32,
        }
    }
}

#[azos_interface(id = 0x4B45_5953, level = 1)]
pub trait Keys {
    /// Make a key of `policy` and return its handle. A zero `name` with
    /// `backend::VOLATILE` draws a fresh random secret; a non-zero `name` with a
    /// deriving backend derives the secret from the backend's root (the same
    /// name, owner, purpose and envelope give the same key at every boot) and
    /// opens the key again if the owner already has it with this policy. A name
    /// with the volatile backend, or no name with another, is `BAD_ARGUMENT`.
    /// Needs `WRITE`.
    fn generate(&mut self, name: [u64; NAME_WORDS], policy: Policy) -> Out<u32>;

    /// Bring a 32-byte secret of the caller's own into the keystore as a
    /// volatile key of `policy` (no name, `backend::VOLATILE`). From then on
    /// the caller can wipe its copy and use the handle. Needs `WRITE`.
    fn import(&mut self, policy: Policy, secret: [u64; BLOCK_WORDS]) -> Out<u32>;

    /// A child of the `purpose::DERIVE` key `parent`, named by `label`: the same
    /// parent and label always give the same secret. The child is volatile,
    /// its envelope is the parent's or narrower, and it does not outlive the
    /// parent (a `ttl_s` of 0 asks for the parent's remainder). Needs `WRITE`
    /// and a parent that allows `derive`.
    fn derive(&mut self, parent: u32, label: [u64; NAME_WORDS], policy: Policy) -> Out<u32>;

    /// The public key of the `purpose::SIGN` key `key`, as four little-endian
    /// words. Not a use of the secret: it is not counted against `max_uses`.
    /// Needs `READ`.
    fn public(&mut self, key: u32) -> Out<[u64; BLOCK_WORDS]>;

    /// Sign with the `purpose::SIGN` key `key`: the message is the first `len`
    /// bytes (1..=[`SIGN_MSG_MAX`]) of the memory object `buf`, the signature
    /// (Ed25519, [`SIG_BYTES`] bytes) replaces them, and the answer is the
    /// signature's length. `UNSUPPORTED` for a buffer the kernel cannot touch
    /// as one piece. Needs `READ`.
    fn sign(&mut self, key: u32, buf: Cap<KeyBuf>, len: u32) -> Out<u32>;

    /// Seal the 32-byte `data` under the `purpose::SEAL` key `key`: the answer
    /// is the 32 bytes encrypted and a 16-byte tag. Deterministic. Needs `READ`.
    fn seal(&mut self, key: u32, data: [u64; BLOCK_WORDS]) -> Out<[u64; SEALED_WORDS]>;

    /// Open a block [`Keys::seal`] made under the same key. `DENIED` is a
    /// refused use; a block that does not open is `BAD_ARGUMENT` (and a use,
    /// counted). Needs `READ`.
    fn unseal(&mut self, key: u32, sealed: [u64; SEALED_WORDS]) -> Out<[u64; BLOCK_WORDS]>;

    /// Wrap the key `target`, which must be `wrappable`, under the
    /// `purpose::WRAP` key `key`: the answer is the target's secret sealed
    /// under `key`, bound to the target's purpose. Needs `EXEC`.
    fn wrap(&mut self, key: u32, target: u32) -> Out<[u64; SEALED_WORDS]>;

    /// Bring a wrapped key back: the new volatile key has the purpose it was
    /// wrapped with, the owner's envelope, the wrapping key's remaining time,
    /// and is not wrappable. `BAD_ARGUMENT` for a block that does not open under
    /// `key`. Needs `WRITE`.
    fn unwrap(&mut self, key: u32, sealed: [u64; SEALED_WORDS]) -> Out<u32>;

    /// Wipe the key and free its handle. Only the owner (and, for an
    /// image-bound key, the image) may. Needs `WRITE` of the capability, not
    /// of the system: it is allowed while contained.
    fn destroy(&mut self, key: u32) -> Out<()>;

    /// Log the user `user` in on the console with `credential`: 32 bytes the
    /// caller made of what was typed (the terminal server, which owns the
    /// console, hashes the line; the typed text never reaches the login
    /// service). The user's record is the signed topology's `[login.NAME]`
    /// row, which lists the public part of the Ed25519 key the credential
    /// derives on this board (`azos_crypto::keystore::login_public`: the
    /// board's root, the user's root and name, the credential); no secret and
    /// no hash of one is stored anywhere. The answer is the user's root
    /// (`owner_root`, never 0) and, as a side effect, the caller's Domain
    /// holds a one-shot **login grant** for it: the next `SYS_SPAWN_EX` with
    /// `SPAWN_F_USER` starts the user's session (and spends the grant, which
    /// also lapses with time).
    ///
    /// With **no `[login.NAME]` row in the topology** nobody is enrolled and
    /// the console session is the system's: an empty `user` is admitted with
    /// root 0 (a grant for the system's own session) and recorded. Once any
    /// user is enrolled an empty `user` is refused like any unknown one.
    ///
    /// `DENIED`: the user is unknown or the credential does not verify (the
    /// same answer, the same work) or the account is locked after too many
    /// failures in a row; a `login` decision record (`Rule::Login`, method 4
    /// local console) is written for every call, a refusal durably.
    /// `BAD_ARGUMENT`: a name that is not a login name. `NOT_READY`: the
    /// board holds no root to verify with, or no signed topology is loaded (a
    /// table of accounts that cannot be read is not one with nobody in it).
    /// Needs `EXEC`.
    fn login(&mut self, user: [u64; NAME_WORDS], credential: [u64; BLOCK_WORDS]) -> Out<u32>;
}

/// The op numbers, counted from 1 as the trait lists them: what an `OP_MASK`
/// names. A host test holds them to the generated table.
pub mod op {
    pub const GENERATE: u64 = 1;
    pub const IMPORT: u64 = 2;
    pub const DERIVE: u64 = 3;
    pub const PUBLIC: u64 = 4;
    pub const SIGN: u64 = 5;
    pub const SEAL: u64 = 6;
    pub const UNSEAL: u64 = 7;
    pub const WRAP: u64 = 8;
    pub const UNWRAP: u64 = 9;
    pub const DESTROY: u64 = 10;
    pub const LOGIN: u64 = 11;
}

/// The `OP_MASK` of a holder that opens a named key, reads its public part
/// and signs, and does nothing else (the SSH server's host key). Bit n is op n.
pub const SIGNER_OPS: u64 = 1 << op::GENERATE | 1 << op::PUBLIC | 1 << op::SIGN;

/// The `OP_MASK` of the login service (`LOGIND.ELF`): `login` and nothing
/// else. It holds `EXEC` on `keys` with this mask, so it cannot make, use,
/// wrap or destroy any key.
pub const LOGIN_OPS: u64 = 1 << op::LOGIN;
