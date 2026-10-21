// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The keystore: keys held for their users, each with a policy.
//!
//! A task that signs, seals or derives does not need the key, it needs the
//! *use* of it. The keystore keeps the key and hands out a **handle**; the
//! handle carries a [`Policy`], and every use is checked against it before the
//! secret is touched. The kernel hosts it as the `keys` interface
//! (`azos_devif::keys`, served by `azos_syscall::keys`); this module is the
//! part that decides, pure and host-tested (`tests/host/crypto-tests`).
//!
//! # The policy
//!
//! * **purpose**: exactly one of [`purpose::SIGN`] (an Ed25519 seed),
//!   [`purpose::SEAL`] (a key that seals and opens data), [`purpose::DERIVE`]
//!   (a key children are derived from) or [`purpose::WRAP`] (a key that wraps
//!   other keys). One key, one algorithm: a seed that also sealed data would
//!   tie the strength of one use to the other.
//! * **envelope**: who may use it. [`Envelope::Owner`] is any task of the
//!   owner (`owner_root`, the user the Domain belongs to; 0 is the system);
//!   [`Envelope::Image`] is the tasks of the owner that run the image that
//!   made the key (its measurement). The envelope also goes into the
//!   derivation of a persistent key, so another image cannot even name it.
//! * **ttl**: seconds the handle lives from its creation; 0 is no expiry. An
//!   expired handle's secret is wiped at the first use that finds it so.
//! * **max uses**: how many uses the handle serves; 0 is no limit.
//! * **wrappable**: whether the key may leave, wrapped under a
//!   [`purpose::WRAP`] key ([`Op::Wrap`]). A key that is not wrappable never
//!   leaves the keystore in any form.
//! * **backend**: where the secret comes from and where it lives
//!   ([`Backend`]): drawn at random and kept in RAM, or derived from a root
//!   secret the board holds (the BOOTMETA board seed, a secret in a TPM NV
//!   index, a secret on a sealed volume) so the same name gives the same key
//!   at every boot and nothing is written.
//!
//! # Refusals
//!
//! A use is refused for exactly one of the reasons of the `key-use` decision
//! record (`azos_decision::Rule::KeyUse`), checked in this order: the handle
//! belongs to another owner or image ([`Reason::NotOwner`], 2); it expired
//! ([`Reason::Expired`], 4); the key does not allow the op ([`Reason::NotAllowed`],
//! 1); its uses are used up ([`Reason::Exhausted`], 3). The codes are the
//! record's; a host test holds them to its table.
//!
//! # Per owner
//!
//! The table is shared and the slots are not: every slot records the owner it
//! was made for, a lookup compares the caller's owner to it before anything
//! else, and an owner can hold at most `per_owner` live handles, so one user
//! cannot fill the table.
//!
//! # Construction of the sealed forms
//!
//! [`siv_seal`] is a synthetic-IV construction: the tag is
//! `HMAC-SHA256(mac key, aad || data)` cut to 16 bytes, and the data is
//! encrypted with ChaCha20 under the first 12 bytes of the tag as the nonce
//! (as in RFC 5297, with the counter-mode stream of this crate). It needs no
//! nonce from the caller and is deterministic: the same data under the same
//! key and aad gives the same blob. Its output is exactly 48 bytes, which is
//! what an op of the interface can carry in registers.

use crate::chachapoly;
use crate::ct::{ct_eq, secure_zero};
use crate::ed25519;
use crate::hkdf;

/// Bytes of every secret: an Ed25519 seed or a 256-bit symmetric key.
pub const KEY_LEN: usize = 32;
/// Bytes of a sealed block: 32 of data and a 16-byte tag.
pub const SEALED_LEN: usize = KEY_LEN + 16;
/// Bytes of a key's name.
pub const NAME_LEN: usize = 16;
/// Bytes of an Ed25519 signature.
pub const SIG_LEN: usize = ed25519::ED25519_SIGNATURE_SIZE;
/// Most live handles a table holds (a handle names its slot in 8 bits).
pub const SLOTS_MAX: usize = 255;

/// The purposes. A key has exactly one.
pub mod purpose {
    /// An Ed25519 seed: [`super::sign`], [`super::public_key`].
    pub const SIGN: u8 = 1;
    /// A symmetric key: seals and opens 32-byte blocks.
    pub const SEAL: u8 = 2;
    /// A symmetric key children are derived from.
    pub const DERIVE: u8 = 4;
    /// A symmetric key that wraps other keys.
    pub const WRAP: u8 = 8;
    /// Every bit that means a purpose.
    pub const ALL: u8 = SIGN | SEAL | DERIVE | WRAP;
}

/// What `need` means for a key that is about to be wrapped.
pub const NEED_WRAPPABLE: u8 = 0;

/// Who may use a key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Envelope {
    /// Any task of the key's owner.
    Owner = 0,
    /// The tasks of the key's owner that run the image that made it.
    Image = 1,
}

impl Envelope {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Envelope::Owner),
            1 => Some(Envelope::Image),
            _ => None,
        }
    }
}

/// Where a key's secret comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Backend {
    /// Drawn at random when the key is made, kept in RAM, gone at reset.
    Volatile = 0,
    /// Derived from the board seed in BOOTMETA's reserved sector.
    Boot = 1,
    /// Derived from a secret held in a TPM NV index.
    TpmNv = 2,
    /// Derived from a secret held in a file on a sealed volume.
    Volume = 3,
}

/// The backends that derive, with a root each.
pub const ROOTS: usize = 3;

impl Backend {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Backend::Volatile),
            1 => Some(Backend::Boot),
            2 => Some(Backend::TpmNv),
            3 => Some(Backend::Volume),
            _ => None,
        }
    }

    /// The index of the root a deriving backend reads; `None` for `Volatile`.
    pub const fn root_index(self) -> Option<usize> {
        match self {
            Backend::Volatile => None,
            Backend::Boot => Some(0),
            Backend::TpmNv => Some(1),
            Backend::Volume => Some(2),
        }
    }
}

/// What a key allows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    /// One of [`purpose`].
    pub purpose: u8,
    pub envelope: Envelope,
    pub backend: Backend,
    /// May leave the keystore, wrapped under a [`purpose::WRAP`] key.
    pub wrappable: bool,
    /// Uses the handle serves; 0 is no limit.
    pub max_uses: u32,
    /// Seconds the handle lives; 0 is no expiry.
    pub ttl_s: u32,
}

impl Policy {
    /// Is the purpose exactly one of [`purpose`]?
    pub const fn purpose_ok(&self) -> bool {
        self.purpose & purpose::ALL == self.purpose && self.purpose.count_ones() == 1
    }
}

/// Who is asking: the owner of the caller's Domain, the measurement of its
/// image (all zeros when the loader did not measure it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Principal {
    pub owner_root: u32,
    pub measurement: [u8; 32],
}

/// The use being made of a key, numbered as the `op` field of the `key-use`
/// record: 1 sign, 2 decrypt (open or seal a block), 3 derive, 4 wrap, 5 export.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Op {
    Sign = 1,
    Crypt = 2,
    Derive = 3,
    Wrap = 4,
    /// Taking the public part (or a wrapped form) out.
    Export = 5,
}

/// Why a use was refused: the `reason` field of the `key-use` record, 0 being
/// "allowed".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Reason {
    Allowed = 0,
    /// The key does not allow the op (another purpose, not wrappable).
    NotAllowed = 1,
    /// The key belongs to another owner, or to another image.
    NotOwner = 2,
    /// The key's uses are used up.
    Exhausted = 3,
    /// The key's time to live is over.
    Expired = 4,
}

/// What a lookup can say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// No live handle of that name (never made, destroyed, or its slot was reused).
    NoKey,
    /// The handle exists and the policy refuses the use.
    Refused(Reason),
}

/// Why a key could not be made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MakeError {
    /// The policy is not valid (purpose, name, backend, ttl).
    BadPolicy,
    /// The table has no free slot, or the owner has used its share.
    Full,
    /// A key of that name exists with another policy.
    Mismatch,
}

/// A use that was admitted: a copy of the secret, wiped when dropped, and the
/// policy it was admitted under.
pub struct Admit {
    secret: [u8; KEY_LEN],
    pub policy: Policy,
    /// The handle, for the record.
    pub handle: u32,
}

impl Admit {
    pub fn secret(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }
}

impl Drop for Admit {
    fn drop(&mut self) {
        secure_zero(&mut self.secret);
    }
}

#[derive(Clone, Copy)]
struct Slot {
    /// Generation of the occupant, 1..=0xFF_FFFF; 0 when the slot is free.
    gen: u32,
    owner: u32,
    measurement: [u8; 32],
    policy: Policy,
    name: [u8; NAME_LEN],
    secret: [u8; KEY_LEN],
    /// Second at which the handle expires; 0 never.
    expires_s: u64,
    uses: u32,
    expired: bool,
}

const POLICY_NONE: Policy =
    Policy { purpose: 0, envelope: Envelope::Owner, backend: Backend::Volatile, wrappable: false, max_uses: 0, ttl_s: 0 };

impl Slot {
    const EMPTY: Slot = Slot {
        gen: 0,
        owner: 0,
        measurement: [0; 32],
        policy: POLICY_NONE,
        name: [0; NAME_LEN],
        secret: [0; KEY_LEN],
        expires_s: 0,
        uses: 0,
        expired: false,
    };

    fn is_free(&self) -> bool {
        self.gen == 0
    }

    /// The handle lapsed: the secret goes now, the slot stays (owner, policy)
    /// so that the next use still says "expired" to its owner and "not yours"
    /// to anyone else, until a later `insert` reuses it.
    fn wipe(&mut self) {
        secure_zero(&mut self.secret);
        self.expired = true;
    }

    fn lapsed(&self, now_s: u64) -> bool {
        self.expired || (self.expires_s != 0 && now_s >= self.expires_s)
    }

    /// Does the principal stand where the key's envelope says?
    fn belongs_to(&self, who: &Principal) -> bool {
        self.owner == who.owner_root
            && match self.policy.envelope {
                Envelope::Owner => true,
                Envelope::Image => self.measurement == who.measurement,
            }
    }
}

/// The table: `N` slots, `per_owner` of them at most for one owner.
pub struct Keystore<const N: usize> {
    slots: [Slot; N],
    next_gen: u32,
    per_owner: usize,
}

impl<const N: usize> Keystore<N> {
    pub const fn new(per_owner: usize) -> Self {
        assert!(N >= 1 && N <= SLOTS_MAX, "a handle names its slot in 8 bits");
        assert!(per_owner >= 1);
        Keystore { slots: [Slot::EMPTY; N], next_gen: 1, per_owner }
    }

    fn handle_of(&self, idx: usize, gen: u32) -> u32 {
        gen << 8 | (idx as u32 + 1)
    }

    fn index_of(&self, handle: u32) -> Option<usize> {
        let idx = (handle & 0xFF) as usize;
        let gen = handle >> 8;
        let i = idx.checked_sub(1)?;
        let s = self.slots.get(i)?;
        (gen != 0 && s.gen == gen).then_some(i)
    }

    /// Free the slots whose handles have lapsed.
    fn sweep(&mut self, now_s: u64) {
        for s in self.slots.iter_mut() {
            if !s.is_free() && s.lapsed(now_s) {
                secure_zero(&mut s.secret);
                *s = Slot::EMPTY;
            }
        }
    }

    /// Live handles of `owner`.
    pub fn count_of(&self, owner: u32) -> usize {
        self.slots.iter().filter(|s| !s.is_free() && !s.expired && s.owner == owner).count()
    }

    /// The handle of the live key `name` made for `who` with `policy`, if there
    /// is one: opening a named key twice gives the same handle.
    fn find_named(&self, who: &Principal, name: &[u8; NAME_LEN], policy: &Policy, now_s: u64) -> Option<(usize, bool)> {
        self.slots.iter().position(|s| {
            !s.is_free() && !s.lapsed(now_s) && s.name == *name && s.owner == who.owner_root && s.policy.purpose == policy.purpose
                && s.policy.backend == policy.backend
                && (s.policy.envelope != Envelope::Image || s.measurement == who.measurement)
                && s.policy.envelope == policy.envelope
        })
        .map(|i| (i, self.slots[i].policy == *policy))
    }

    /// Put `secret` in a slot for `who` under `policy`; the handle. `name` is
    /// all zeros for a volatile key; for a persistent one a second call with
    /// the same name and policy returns the first call's handle (and `secret`
    /// is not stored again), and a second call with another policy is
    /// [`MakeError::Mismatch`].
    pub fn insert(
        &mut self,
        who: &Principal,
        now_s: u64,
        policy: Policy,
        name: &[u8; NAME_LEN],
        secret: &[u8; KEY_LEN],
    ) -> Result<u32, MakeError> {
        if !policy.purpose_ok() {
            return Err(MakeError::BadPolicy);
        }
        let named = *name != [0u8; NAME_LEN];
        if named == (policy.backend == Backend::Volatile) {
            // A name asks for a key that is the same at the next call or boot;
            // a volatile one is drawn anew each time.
            return Err(MakeError::BadPolicy);
        }
        self.sweep(now_s);
        if named {
            if let Some((i, same)) = self.find_named(who, name, &policy, now_s) {
                if !same {
                    return Err(MakeError::Mismatch);
                }
                return Ok(self.handle_of(i, self.slots[i].gen));
            }
        }
        if self.count_of(who.owner_root) >= self.per_owner {
            return Err(MakeError::Full);
        }
        let Some(i) = self.slots.iter().position(Slot::is_free) else { return Err(MakeError::Full) };
        let gen = self.next_gen;
        self.next_gen = if gen >= 0xFF_FFFF { 1 } else { gen + 1 };
        self.slots[i] = Slot {
            gen,
            owner: who.owner_root,
            measurement: if policy.envelope == Envelope::Image { who.measurement } else { [0; 32] },
            policy,
            name: *name,
            secret: *secret,
            expires_s: if policy.ttl_s == 0 { 0 } else { now_s + u64::from(policy.ttl_s) },
            uses: 0,
            expired: false,
        };
        Ok(self.handle_of(i, gen))
    }

    /// Check a use of `handle` by `who` and, if it is allowed, hand out the
    /// secret. `need` is the purpose the op needs (`purpose::*`), or
    /// [`NEED_WRAPPABLE`] for a key about to be wrapped, which needs
    /// `wrappable` instead of a purpose. `counts` is whether the use is charged
    /// to the key's `max_uses` (taking the public key is not a use of the secret).
    pub fn admit(&mut self, who: &Principal, now_s: u64, handle: u32, need: u8, counts: bool) -> Result<Admit, Refusal> {
        let i = self.index_of(handle).ok_or(Refusal::NoKey)?;
        let s = &mut self.slots[i];
        if !s.belongs_to(who) {
            return Err(Refusal::Refused(Reason::NotOwner));
        }
        if s.lapsed(now_s) {
            s.wipe();
            return Err(Refusal::Refused(Reason::Expired));
        }
        let allowed = if need == NEED_WRAPPABLE { s.policy.wrappable } else { s.policy.purpose == need };
        if !allowed {
            return Err(Refusal::Refused(Reason::NotAllowed));
        }
        if counts {
            if s.policy.max_uses != 0 && s.uses >= s.policy.max_uses {
                return Err(Refusal::Refused(Reason::Exhausted));
            }
            s.uses = s.uses.saturating_add(1);
        }
        Ok(Admit { secret: s.secret, policy: s.policy, handle })
    }

    /// The seconds a live handle has left (0: it does not expire), for a
    /// child that may not outlive its parent. `None` when `admit` would not
    /// find the handle.
    pub fn remaining_s(&self, handle: u32, now_s: u64) -> Option<u64> {
        let s = &self.slots[self.index_of(handle)?];
        if s.expires_s == 0 {
            return Some(0);
        }
        Some(s.expires_s.saturating_sub(now_s).max(1))
    }

    /// Destroy the handle: its secret is wiped and the slot is free. Only the
    /// owner (and, for an image-bound key, the image) may.
    pub fn destroy(&mut self, who: &Principal, handle: u32) -> Result<(), Refusal> {
        let i = self.index_of(handle).ok_or(Refusal::NoKey)?;
        if !self.slots[i].belongs_to(who) {
            return Err(Refusal::Refused(Reason::NotOwner));
        }
        secure_zero(&mut self.slots[i].secret);
        self.slots[i] = Slot::EMPTY;
        Ok(())
    }
}

// ── The roots and the derivations ───────────────────────────────────────────

const ROOT_INFO: &[u8] = b"azos keystore key v1";
const CHILD_INFO: &[u8] = b"azos keystore derive v1";

/// The secret of the persistent key `name` of `who` under `policy`, from the
/// backend's root: `HKDF-SHA256(salt = ROOT_INFO, ikm = root,
/// info = owner || purpose || envelope || image || name)`. The image is the
/// measurement for an image-bound key and zeros for the others, so the key of
/// one image is not the key of another, nor the key of one owner the key of
/// another. `None` for a root of all zeros (the board holds none) and for a
/// volatile policy.
pub fn derive_persistent(
    root: &[u8; KEY_LEN],
    who: &Principal,
    policy: &Policy,
    name: &[u8; NAME_LEN],
) -> Option<[u8; KEY_LEN]> {
    if policy.backend == Backend::Volatile || root.iter().all(|&b| b == 0) {
        return None;
    }
    let mut info = [0u8; 4 + 1 + 1 + 32 + NAME_LEN];
    info[..4].copy_from_slice(&who.owner_root.to_be_bytes());
    info[4] = policy.purpose;
    info[5] = policy.envelope as u8;
    if policy.envelope == Envelope::Image {
        info[6..38].copy_from_slice(&who.measurement);
    }
    info[38..].copy_from_slice(name);
    let mut prk = hkdf::extract(ROOT_INFO, root);
    let mut out = [0u8; KEY_LEN];
    let ok = hkdf::expand(&prk, &info, &mut out);
    secure_zero(&mut prk);
    ok.then_some(out)
}

/// The key a child `label` of `parent` is: `HKDF-SHA256(salt = label,
/// ikm = parent, info = CHILD_INFO || purpose)`. A child of another label, or
/// of another purpose, is another key.
pub fn derive_child(parent: &[u8; KEY_LEN], label: &[u8; NAME_LEN], child_purpose: u8) -> [u8; KEY_LEN] {
    let mut info = [0u8; CHILD_INFO.len() + 1];
    info[..CHILD_INFO.len()].copy_from_slice(CHILD_INFO);
    info[CHILD_INFO.len()] = child_purpose;
    let mut prk = hkdf::extract(label, parent);
    let mut out = [0u8; KEY_LEN];
    // 32 bytes is far below the HKDF limit: this cannot fail.
    let ok = hkdf::expand(&prk, &info, &mut out);
    debug_assert!(ok);
    secure_zero(&mut prk);
    out
}

/// The salt of the console login's per-user key: no keystore handle can name
/// a key made under it (a handle's keys come from [`ROOT_INFO`]), so the key
/// of a user's login is out of reach of every task that holds `keys`.
const LOGIN_USER_LABEL: &[u8] = b"azos console login user v1";
const LOGIN_SEED_LABEL: &[u8] = b"azos console login seed v1";

/// The public key the console credential `credential` has for the login
/// `name` (user root `owner_root`) on a board whose root is `root`: the value
/// the signed topology lists in the user's `[login.NAME]` row and the `login`
/// op compares with.
///
/// Two steps, both HKDF-SHA256. The user's **record key** (purpose derive)
/// is `HKDF(salt = LOGIN_USER_LABEL, ikm = root, info = owner_root || name)`:
/// the board's secret, so a guess at the credential cannot be checked
/// without it. The credential makes an Ed25519 **seed** from it,
/// `HKDF(salt = credential, ikm = record key, info = LOGIN_SEED_LABEL)`, and
/// the public part of that seed is the verifier. Neither the record key nor
/// the seed is kept or returned. `None` for a root of all zeros.
pub fn login_public(
    root: &[u8; KEY_LEN],
    owner_root: u32,
    name: &[u8; NAME_LEN],
    credential: &[u8; KEY_LEN],
) -> Option<[u8; 32]> {
    if root.iter().all(|&b| b == 0) {
        return None;
    }
    let mut info = [0u8; 4 + NAME_LEN];
    info[..4].copy_from_slice(&owner_root.to_be_bytes());
    info[4..].copy_from_slice(name);
    let mut record = [0u8; KEY_LEN];
    let mut seed = [0u8; KEY_LEN];
    // 32 bytes is far below the HKDF limit: neither can fail.
    let a = hkdf::hkdf(LOGIN_USER_LABEL, root, &info, &mut record);
    let b = hkdf::hkdf(credential, &record, LOGIN_SEED_LABEL, &mut seed);
    debug_assert!(a && b);
    let public = public_key(&seed);
    secure_zero(&mut record);
    secure_zero(&mut seed);
    Some(public)
}

/// May a key of `req` be derived from a parent of `parent`, which has
/// `parent_left_s` seconds left (0: no expiry), by `who`? The child's policy
/// when it may: a child is volatile (it exists while its parent's secret does,
/// and is the same key every time), its envelope is not wider than the parent's,
/// and it does not outlive the parent.
pub fn child_policy(parent: &Policy, parent_left_s: u64, req: &Policy) -> Option<Policy> {
    if !req.purpose_ok() || req.backend != Backend::Volatile || req.envelope < parent.envelope {
        return None;
    }
    let ttl = match (parent_left_s, req.ttl_s) {
        (0, t) => u64::from(t),
        (left, 0) => left,
        (left, t) => left.min(u64::from(t)),
    };
    Some(Policy { ttl_s: ttl.min(u64::from(u32::MAX)) as u32, ..*req })
}

// ── Using a secret ──────────────────────────────────────────────────────────

/// The public key of the Ed25519 seed `seed`.
pub fn public_key(seed: &[u8; KEY_LEN]) -> [u8; 32] {
    ed25519::public_from_seed(seed)
}

/// The signature of `msg` by the Ed25519 seed `seed`.
pub fn sign(seed: &[u8; KEY_LEN], msg: &[u8]) -> [u8; SIG_LEN] {
    ed25519::sign_message(seed, msg)
}

fn siv_keys(key: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut mac = [0u8; KEY_LEN];
    let mut enc = [0u8; KEY_LEN];
    // 32 bytes is far below the HKDF limit: neither can fail.
    let a = hkdf::hkdf(b"azos keystore siv", key, b"mac", &mut mac);
    let b = hkdf::hkdf(b"azos keystore siv", key, b"enc", &mut enc);
    debug_assert!(a && b);
    (mac, enc)
}

/// Seal 32 bytes under `key`, bound to `aad` (see the module doc): the
/// ciphertext, then the 16-byte tag.
pub fn siv_seal(key: &[u8; KEY_LEN], aad: u8, data: &[u8; KEY_LEN]) -> [u8; SEALED_LEN] {
    let (mut mac, mut enc) = siv_keys(key);
    let t = hkdf::hmac_sha256(&mac, &[&[aad], data]);
    let mut nonce = [0u8; chachapoly::NONCE_LEN];
    nonce.copy_from_slice(&t[..chachapoly::NONCE_LEN]);
    let mut body = *data;
    // 32 bytes never wrap the block counter.
    let ok = chachapoly::chacha20_xor(&enc, 1, &nonce, &mut body);
    debug_assert!(ok);
    let mut out = [0u8; SEALED_LEN];
    out[..KEY_LEN].copy_from_slice(&body);
    out[KEY_LEN..].copy_from_slice(&t[..16]);
    secure_zero(&mut mac);
    secure_zero(&mut enc);
    secure_zero(&mut body);
    out
}

/// The data of a block sealed by [`siv_seal`] under `key` with `aad`; `None`
/// for a block of another key, another `aad` or other bytes.
pub fn siv_open(key: &[u8; KEY_LEN], aad: u8, sealed: &[u8; SEALED_LEN]) -> Option<[u8; KEY_LEN]> {
    let (mut mac, mut enc) = siv_keys(key);
    let mut nonce = [0u8; chachapoly::NONCE_LEN];
    nonce.copy_from_slice(&sealed[KEY_LEN..KEY_LEN + chachapoly::NONCE_LEN]);
    let mut body = [0u8; KEY_LEN];
    body.copy_from_slice(&sealed[..KEY_LEN]);
    let ok = chachapoly::chacha20_xor(&enc, 1, &nonce, &mut body);
    let mut t = hkdf::hmac_sha256(&mac, &[&[aad], &body]);
    let good = ok && ct_eq(&t[..16], &sealed[KEY_LEN..]);
    secure_zero(&mut mac);
    secure_zero(&mut enc);
    secure_zero(&mut t);
    if good {
        Some(body)
    } else {
        secure_zero(&mut body);
        None
    }
}

/// The `aad` of the sealed form of data sealed by a [`purpose::SEAL`] key.
pub const AAD_DATA: u8 = 0;
