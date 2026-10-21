// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Keys` interface the kernel hosts: keys held for their users, used by
//! handle (`azos_devif::keys` has the contract, `azos_crypto::keystore` the
//! policy; this file is the seam to the kernel).
//!
//! The ops are endpoint ops and not syscalls: a key handle is an authority, but
//! the interface needs no number and no capability kind of its own.
//!
//! # What this file adds to the policy
//!
//! * **Containment.** While the system is contained (`azos_ipc::cap::degraded_active`)
//!   no fresh secret is minted (`generate` of a volatile key, `import`, `derive`,
//!   `unwrap` answer `DENIED`); opening a named key, whose secret the board
//!   determines, is served, and so are the uses and `destroy`.
//! * **Whose key.** The caller's owner (`owner_root` of its Domain) and the
//!   measurement of its image (`principal`). A task in no Domain has no
//!   identity and gets `NOT_READY`, as does an image-bound key asked for by an
//!   image the loader did not measure.
//! * **The roots.** A persistent key is derived from the root of its backend
//!   ([`root_for`]): the board seed of BOOTMETA's reserved sector, read through the
//!   link-key seam (`link_key::read_key_via_hook`) once and kept as a derived
//!   root; a secret in a TPM NV index and a secret in a file on a sealed
//!   volume, which the boot installs ([`install_root`], [`install_volume_root`]).
//!   A backend whose root the board does not hold is `NOT_READY`.
//! * **The record.** Every use of a key is a `Rule::KeyUse` decision
//!   (subject the calling task; the handle, the op, the reason): `Admit` when
//!   it was served, `Refuse` when the policy turned it away. A refusal is a
//!   durable receipt, with a small budget per second so that a task spinning
//!   on a key it may not use cannot fill the recorder; past the budget the
//!   record is `Deny` (the ring only). The op numbers are the record's: 1 sign,
//!   2 seal and unseal, 3 derive, 4 wrap and unwrap, 5 the public key and
//!   destroy. A handle that does not exist is not a use and writes no record.
//! * **The buffer of `sign`.** A message of up to 256 bytes and a 64-byte
//!   signature do not fit a message's registers, so the caller shares a
//!   memory object (`Cap<KeyBuf>`, resolved in its own table, read-write, held
//!   with `READ` and `WRITE`). The message is copied out of it before the key
//!   is looked at, and the signature written back after the table's lock is
//!   gone: signing takes milliseconds on a small core and no lock is held
//!   across it.
//!
//! * **The console login** ([`azos_devif::Keys::login`]). The credential the
//!   login service hands in is checked against the signed topology's
//!   `[login.NAME]` row: `azos_crypto::keystore::login_public` derives, from
//!   the board's root, the user's record key and from it, with the credential,
//!   an Ed25519 key whose public part must be one the row lists. Nothing
//!   derived from the credential is stored. An account is the row's index
//!   plus one (`owner_root`, never 0), stable for as long as the signed
//!   topology is. A name no row lists is checked the same way against
//!   nothing, so an unknown name and a wrong credential answer alike in
//!   content and in work. Consecutive refusals lock the account
//!   (`LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_S`); a success arms the one-shot
//!   grant of the caller's Domain that `SPAWN_F_USER` spends
//!   ([`take_login_grant`]). Every call is a `Rule::Login` record, a refusal
//!   always durable.
//!
//! # Users
//!
//! `sshd` (`userspace/services/sshd`): its host key is a named, image-bound,
//! board-derived key; it asks for the public key once and for a signature at
//! every key exchange, and the secret never reaches ring 3. `logind`
//! (`userspace/services/logind`) calls `login` and nothing else. The other
//! callers are the host tests (`syscall-tests`, `keys_guards`; `crypto-tests`,
//! `keystore_tests`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use azos_abi::cap::{CapHandle, CapPerms};
use azos_crypto::ct::secure_zero;
use azos_crypto::keystore::{self as ks, Backend, Envelope, Keystore, Op, Principal, Reason, Refusal};
use azos_decision::{Rule, Verdict};
use azos_devif::keys::{self as wire, KeyBuf, BLOCK_WORDS, NAME_WORDS, SEALED_WORDS, SIGN_BUF_MIN, SIGN_MSG_MAX, SIG_BYTES};
use azos_devif::{outcome, Cap as WireCap, Out};
use azos_sync::SpinLock;

use crate::khost::Caller;

/// Live handles (Kconfig `KEYSTORE_KEYS`) and one owner's share of them
/// (`KEYSTORE_KEYS_PER_OWNER`).
const SLOTS: usize = azos_limits::KEYSTORE_KEYS as usize;
const PER_OWNER: usize = azos_limits::KEYSTORE_KEYS_PER_OWNER as usize;
const _: () = assert!(PER_OWNER <= SLOTS, "KEYSTORE_KEYS_PER_OWNER is more than KEYSTORE_KEYS");

// The numbers of the wire are the keystore's. A mismatch is a compile error,
// not a key that means something else on the other side of the call.
const _: () = assert!(
    wire::purpose::SIGN == ks::purpose::SIGN
        && wire::purpose::SEAL == ks::purpose::SEAL
        && wire::purpose::DERIVE == ks::purpose::DERIVE
        && wire::purpose::WRAP == ks::purpose::WRAP
        && wire::envelope::OWNER == Envelope::Owner as u8
        && wire::envelope::IMAGE == Envelope::Image as u8
        && wire::backend::VOLATILE == Backend::Volatile as u8
        && wire::backend::BOOT == Backend::Boot as u8
        && wire::backend::TPM_NV == Backend::TpmNv as u8
        && wire::backend::VOLUME == Backend::Volume as u8
        && wire::SIG_BYTES == ks::SIG_LEN
);

/// The table. A leaf lock: held to look a handle up or to put one in, never
/// across a signature, an entropy draw or a block read.
static STORE: SpinLock<Keystore<SLOTS>> = SpinLock::new(Keystore::new(PER_OWNER));

/// The roots, by [`Backend::root_index`]; `None` while the board has none.
static ROOTS: SpinLock<[Option<[u8; ks::KEY_LEN]>; ks::ROOTS]> = SpinLock::new([None; ks::ROOTS]);

/// Durable refusal receipts per second, and the window they are counted in.
const DURABLE_PER_SEC: u32 = 8;
static WINDOW_S: AtomicU64 = AtomicU64::new(u64::MAX);
static WINDOW_N: AtomicU32 = AtomicU32::new(0);

// ── The roots ───────────────────────────────────────────────────────────────

const ROOT_LABEL: &[u8] = b"azos keystore root v1";

/// Install the root of `backend` (the secret of the TPM index, the secret of
/// the sealed file). An all-zero root, or the volatile backend, installs
/// nothing. Called once by the boot, which reads the secret and wipes its copy.
pub fn install_root(backend: Backend, root: &[u8; ks::KEY_LEN]) -> bool {
    let Some(i) = backend.root_index() else { return false };
    if root.iter().all(|&b| b == 0) {
        return false;
    }
    ROOTS.lock()[i] = Some(*root);
    true
}

/// Is the root of `backend` installed (or, for the board seed, readable)?
pub fn has_root(backend: Backend) -> bool {
    root_for(backend).is_some()
}

/// The root of `backend`. The board seed is read from the reserved sector the
/// first time it is asked for and kept as a derived root, not as the seed
/// (`HKDF(seed, label)`): the seed is the link key's and the DICE identity's, and
/// a persistent key is not derived from it directly.
fn root_for(backend: Backend) -> Option<[u8; ks::KEY_LEN]> {
    let i = backend.root_index()?;
    if let Some(r) = ROOTS.lock()[i] {
        return Some(r);
    }
    if backend != Backend::Boot {
        return None;
    }
    let mut seed = [0u8; crate::link_key::LINK_KEY_BYTES];
    if !crate::link_key::read_key_via_hook(&mut seed) || seed.iter().all(|&b| b == 0) {
        secure_zero(&mut seed);
        return None;
    }
    let mut root = [0u8; ks::KEY_LEN];
    let ok = azos_crypto::hkdf::hkdf(ROOT_LABEL, &seed, b"boot", &mut root);
    secure_zero(&mut seed);
    if !ok {
        return None;
    }
    ROOTS.lock()[i] = Some(root);
    Some(root)
}

/// What [`install_volume_root`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeRoot {
    /// `KEYSTORE_VOLUME_ROOT_PATH` is empty: no volume backend.
    Off,
    /// The file was there and its secret is the root.
    Read,
    /// The file was not there: a secret from the entropy pool was written to it
    /// and read back.
    Created,
    /// No file system, an unseeded pool, a file that cannot be read or written:
    /// the backend answers `NOT_READY`.
    Failed,
}

/// Bytes of the file: the secret.
const VOLUME_ROOT_BYTES: usize = ks::KEY_LEN;

/// `O_WRONLY | O_CREAT | O_TRUNC` as the file layer reads them.
const OPEN_CREATE_TRUNC: u32 = 1 | 0x40 | 0x200;

/// Read the volume backend's secret from `KEYSTORE_VOLUME_ROOT_PATH` and
/// install it, creating the file from the entropy pool if it is not there.
/// After the mounts (the path is below a mount point) and the entropy step.
pub fn install_volume_root() -> VolumeRoot {
    install_volume_root_at(azos_limits::KEYSTORE_VOLUME_ROOT_PATH.as_bytes())
}

pub(crate) fn install_volume_root_at(path: &[u8]) -> VolumeRoot {
    if path.is_empty() {
        return VolumeRoot::Off;
    }
    let Some(ops) = crate::file_ops::file_ops() else { return VolumeRoot::Failed };
    let mut buf = [0u8; VOLUME_ROOT_BYTES + 1];
    // One byte of room more than the secret: a longer file reads as 0, not
    // as a prefix, and is not a root.
    let got = ops.read_whole(path, &mut buf);
    let outcome = if got == VOLUME_ROOT_BYTES {
        VolumeRoot::Read
    } else if got == 0 {
        let mut fresh = [0u8; VOLUME_ROOT_BYTES];
        let drawn = crate::entropy::fill_kernel(&mut fresh);
        let written = drawn && write_file(ops, path, &fresh);
        secure_zero(&mut fresh);
        if !written {
            secure_zero(&mut buf);
            return VolumeRoot::Failed;
        }
        // What is installed is what the medium now holds.
        if ops.read_whole(path, &mut buf) != VOLUME_ROOT_BYTES {
            secure_zero(&mut buf);
            return VolumeRoot::Failed;
        }
        VolumeRoot::Created
    } else {
        // A file of another size is not the secret, however it starts.
        secure_zero(&mut buf);
        return VolumeRoot::Failed;
    };
    let mut root = [0u8; ks::KEY_LEN];
    root.copy_from_slice(&buf[..VOLUME_ROOT_BYTES]);
    secure_zero(&mut buf);
    let ok = install_root(Backend::Volume, &root);
    secure_zero(&mut root);
    if ok { outcome } else { VolumeRoot::Failed }
}

fn write_file(ops: &dyn crate::file_ops::FileOps, path: &[u8], data: &[u8]) -> bool {
    let fd = ops.open_at(crate::file_ops::ROOT_DIR, crate::file_ops::rel_to_root(path), OPEN_CREATE_TRUNC);
    if fd < 0 {
        return false;
    }
    let fd = fd as i32;
    let ok = ops.write(fd, data) == data.len() as i64;
    let _ = ops.close(fd);
    ok
}

// ── The caller ──────────────────────────────────────────────────────────────

/// The owner and image of task `tid`; `None` for a task in no Domain.
fn principal(tid: u32) -> Option<Principal> {
    let key = azos_sched::idx_for_tid(tid).map(azos_sched::task_domain)?;
    let info = azos_sched::domain::info(key)?;
    Some(Principal { owner_root: info.owner_root, measurement: info.measurement })
}

/// The monotonic clock in whole seconds: a handle's time to live runs on it.
fn now_s() -> u64 {
    azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000_000
}

/// An image-bound key needs an image to be bound to: the all-zero measurement
/// is the one every unmeasured image shares.
fn bindable(who: &Principal, policy: &ks::Policy) -> bool {
    policy.envelope != Envelope::Image || who.measurement.iter().any(|&b| b != 0)
}

// ── The console login ───────────────────────────────────────────────────────

/// `Rule::Login` method 4: the local console.
const LOGIN_METHOD_CONSOLE: u64 = 4;
/// `Rule::Login` reasons (the record's table in `azos_decision`).
const LOGIN_ADMITTED: u64 = 0;
const LOGIN_WRONG: u64 = 1;
const LOGIN_LOCKED: u64 = 2;
/// The board holds no root to verify with: nobody can log in.
const LOGIN_NO_ROOT: u64 = 4;
/// No signed topology is loaded: there is no table of accounts to say who is
/// enrolled, which is not the same as a table with nobody in it.
const LOGIN_NO_TOPOLOGY: u64 = 5;

/// The refusals in a row of one account. The last counter is every name the
/// topology does not list, together.
#[derive(Clone, Copy)]
struct Tries {
    fails: u32,
    /// The second the lock lapses; 0: not locked.
    locked_until_s: u64,
}

const NO_TRIES: Tries = Tries { fails: 0, locked_until_s: 0 };
const UNKNOWN: usize = azos_topology::MAX_LOGINS;
static TRIES: SpinLock<[Tries; UNKNOWN + 1]> = SpinLock::new([NO_TRIES; UNKNOWN + 1]);

/// Longest login name the interface carries (its name field).
const LOGIN_NAME_MAX: usize = ks::NAME_LEN;

/// May `n` be a login name: what a `[login.NAME]` row accepts, in the width of
/// the interface's name field?
fn login_name_ok(n: &[u8]) -> bool {
    n.len() <= LOGIN_NAME_MAX && (n.is_empty() || azos_topology::types::import_name_ok(n))
}

/// Spend the login grant of task `tid`'s Domain (`SPAWN_F_USER`): the
/// `owner_root` the session it starts belongs to (0: the system's own, when
/// nobody is enrolled), or `None` when no credential was admitted for this
/// Domain, or the grant lapsed. The grant is gone either way.
///
/// `pub`, not `pub(crate)`: the caller is `ushell` (the spawn), a module the
/// host suite does not compile, where a crate-private function used only
/// by the suite's tests would be dead code.
pub fn take_login_grant(tid: u32) -> Option<u32> {
    let key = azos_sched::idx_for_tid(tid).map(azos_sched::task_domain)?;
    azos_sched::domain::take_login_grant(key, now_s())
}

/// Write the `login` decision for an attempt: the session's root (0 before
/// one exists), how many refusals preceded it, and why.
fn record_login(verdict: Verdict, session: u32, attempt: u32, reason: u64) {
    azos_decision::record(Rule::Login, verdict, session, [LOGIN_METHOD_CONSOLE, u64::from(attempt), reason]);
}

// ── The record ──────────────────────────────────────────────────────────────

/// Write the `key-use` decision for `op` on `handle` by `tid`.
fn record(tid: u32, handle: u32, op: Op, reason: Reason) {
    let verdict = if reason == Reason::Allowed {
        Verdict::Admit
    } else if durable_budget(now_s()) {
        Verdict::Refuse
    } else {
        Verdict::Deny
    };
    azos_decision::record(Rule::KeyUse, verdict, tid, [u64::from(handle), op as u64, reason as u64]);
}

/// May this second's refusal go to the durable path? `DURABLE_PER_SEC` may.
fn durable_budget(second: u64) -> bool {
    if WINDOW_S.swap(second, Ordering::Relaxed) != second {
        WINDOW_N.store(0, Ordering::Relaxed);
    }
    WINDOW_N.fetch_add(1, Ordering::Relaxed) < DURABLE_PER_SEC
}

// ── Words and bytes ─────────────────────────────────────────────────────────

fn bytes_of<const W: usize, const B: usize>(w: &[u64; W]) -> [u8; B] {
    let mut out = [0u8; B];
    for (c, w) in out.chunks_exact_mut(8).zip(w.iter()) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn words_of<const W: usize>(b: &[u8]) -> [u64; W] {
    let mut out = [0u64; W];
    for (o, c) in out.iter_mut().zip(b.chunks_exact(8)) {
        *o = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
    }
    out
}

fn to_policy(p: &wire::Policy) -> Option<ks::Policy> {
    let policy = ks::Policy {
        purpose: p.purpose,
        envelope: Envelope::from_u8(p.envelope)?,
        backend: Backend::from_u8(p.backend)?,
        wrappable: p.wrappable,
        max_uses: p.max_uses,
        ttl_s: p.ttl_s,
    };
    policy.purpose_ok().then_some(policy)
}

fn make_error<T: Default>(e: ks::MakeError) -> Out<T> {
    Out::err(match e {
        ks::MakeError::BadPolicy => outcome::BAD_ARGUMENT,
        ks::MakeError::Full => outcome::BUSY,
        ks::MakeError::Mismatch => outcome::REFUSED,
    })
}

// ── The interface ───────────────────────────────────────────────────────────

/// The `Keys` interface served for one caller.
pub struct Server(pub Caller);

impl Server {
    /// The caller's owner and image, or `NOT_READY`.
    fn who<T: Default>(&self) -> Result<Principal, Out<T>> {
        principal(self.0.tid).ok_or_else(|| Out::err(outcome::NOT_READY))
    }

    /// Admit a use of `handle` for the caller, and write its record. The
    /// refusal as the op's answer: a handle that does not exist is
    /// `NO_RESOURCE`, a policy that says no is `DENIED`.
    fn admit<T: Default>(
        &self,
        who: &Principal,
        handle: u32,
        op: Op,
        need: u8,
        counts: bool,
    ) -> Result<ks::Admit, Out<T>> {
        let r = STORE.lock().admit(who, now_s(), handle, need, counts);
        match r {
            Ok(a) => {
                record(self.0.tid, handle, op, Reason::Allowed);
                Ok(a)
            }
            Err(Refusal::NoKey) => Err(Out::err(outcome::NO_RESOURCE)),
            Err(Refusal::Refused(reason)) => {
                record(self.0.tid, handle, op, reason);
                Err(Out::err(outcome::DENIED))
            }
        }
    }

    /// Make a key from `secret` (wiped here) and return its handle.
    fn put(&self, who: &Principal, policy: ks::Policy, name: &[u8; ks::NAME_LEN], secret: &mut [u8; ks::KEY_LEN]) -> Out<u32> {
        let r = STORE.lock().insert(who, now_s(), policy, name, secret);
        secure_zero(secret);
        match r {
            Ok(h) => Out::ok(h),
            Err(e) => make_error(e),
        }
    }

    /// The message of `sign`, out of the caller's buffer.
    fn read_message(&self, buf: u32, msg: &mut [u8]) -> Result<(), u32> {
        let len = msg.len();
        with_buf(&self.0, buf, len, |base| {
            // SAFETY: `base` addresses at least `len` bytes of the object,
            // kernel-mapped, held by the region table's lock for this closure.
            unsafe { core::ptr::copy_nonoverlapping(base as *const u8, msg.as_mut_ptr(), len) }
        })
    }

    /// The signature of `sign`, into the caller's buffer.
    fn write_signature(&self, buf: u32, sig: &[u8; SIG_BYTES]) -> Result<(), u32> {
        with_buf(&self.0, buf, SIG_BYTES, |base| {
            // SAFETY: as above, for `SIG_BYTES` bytes, the object being
            // read-write.
            unsafe { core::ptr::copy_nonoverlapping(sig.as_ptr(), base as *mut u8, SIG_BYTES) }
        })
    }
}

/// Run `f` on the kernel's address of the first `bytes` bytes of the memory
/// object the caller's capability `raw` names (the buffer of `sign`).
///
/// `BAD_ARGUMENT` for a handle that is not a memory object or one too small
/// for [`SIGN_BUF_MIN`], `DENIED` (recorded under the object's kind) for a
/// missing right, `UNSUPPORTED` for an object the kernel cannot touch as one
/// piece (read-only, shared with a clone, hidden from the kernel, or not
/// physically contiguous).
fn with_buf(who: &Caller, raw: u32, bytes: usize, f: impl FnOnce(usize)) -> Result<(), u32> {
    let named = azos_ipc::cap_store::read_table(who.tid, |t| t.peek_raw(CapHandle(raw))).flatten();
    let Some((ty, rights, region)) = named else { return Err(outcome::BAD_ARGUMENT) };
    if ty != azos_abi::cap::ty::SHM {
        return Err(outcome::BAD_ARGUMENT);
    }
    if !rights.contains(CapPerms::READ.union(CapPerms::WRITE)) {
        crate::handlers::note_typed_denial_for(who.tid, ty, azos_ipc::cap::CapError::MissingPerms);
        return Err(outcome::DENIED);
    }
    let desc = azos_ipc::memobj::memobj_describe_ref(region).map_err(|_| outcome::BAD_ARGUMENT)?;
    if desc.page_count * azos_arch::PAGE_SIZE < SIGN_BUF_MIN {
        return Err(outcome::BAD_ARGUMENT);
    }
    match azos_ipc::memobj::memobj_with_span_ref(region, bytes, f) {
        Ok(Some(())) => Ok(()),
        Ok(None) => Err(outcome::UNSUPPORTED),
        Err(_) => Err(outcome::BAD_ARGUMENT),
    }
}

impl azos_devif::Keys for Server {
    /// In order: the right (`WRITE` of the capability; one capability-denial
    /// record on refusal); the policy and the caller's identity; the name; the
    /// system's containment (a fresh secret is not minted while contained, a
    /// named key is: the board already determines it, so opening it is not a new
    /// authority, and the remote door that signs with it must come back up when
    /// the system is contained); the secret (drawn from the pool for a volatile
    /// key, derived from the backend's root for a named one); the table.
    fn generate(&mut self, name: [u64; NAME_WORDS], policy: wire::Policy) -> Out<u32> {
        if !self.0.holds(CapPerms::WRITE) {
            self.0.deny(CapPerms::WRITE);
            return Out::err(outcome::DENIED);
        }
        let Some(policy) = to_policy(&policy) else { return Out::err(outcome::BAD_ARGUMENT) };
        let who = match self.who::<u32>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        if !bindable(&who, &policy) {
            return Out::err(outcome::NOT_READY);
        }
        let name: [u8; ks::NAME_LEN] = bytes_of(&name);
        let named = name != [0u8; ks::NAME_LEN];
        if named == (policy.backend == Backend::Volatile) {
            // A name asks for a key that is the same at the next call or boot;
            // a volatile one is drawn anew each time.
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if !named && !self.0.allows(CapPerms::WRITE) {
            self.0.deny(CapPerms::WRITE);
            return Out::err(outcome::DENIED);
        }
        let mut secret = [0u8; ks::KEY_LEN];
        if named {
            let Some(mut root) = root_for(policy.backend) else { return Out::err(outcome::NOT_READY) };
            let derived = ks::derive_persistent(&root, &who, &policy, &name);
            secure_zero(&mut root);
            match derived {
                Some(s) => secret = s,
                None => return Out::err(outcome::NOT_READY),
            }
        } else if !crate::entropy::fill_kernel(&mut secret) {
            return Out::err(outcome::NOT_READY);
        }
        self.put(&who, policy, &name, &mut secret)
    }

    /// In order: the right (`WRITE`); the policy (volatile, unnamed) and the
    /// caller's identity; the table.
    fn import(&mut self, policy: wire::Policy, secret: [u64; BLOCK_WORDS]) -> Out<u32> {
        if let Err(e) = self.0.gate::<u32>(CapPerms::WRITE) {
            return e;
        }
        let Some(policy) = to_policy(&policy) else { return Out::err(outcome::BAD_ARGUMENT) };
        if policy.backend != Backend::Volatile {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let who = match self.who::<u32>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        if !bindable(&who, &policy) {
            return Out::err(outcome::NOT_READY);
        }
        let mut words = secret;
        let mut bytes: [u8; ks::KEY_LEN] = bytes_of(&words);
        secure_zero(&mut words);
        self.put(&who, policy, &[0; ks::NAME_LEN], &mut bytes)
    }

    /// In order: the right (`WRITE`); the policy; the parent (a refusal is
    /// the parent's `key-use` record); the child's policy against the parent's
    /// (a request outside it is `BAD_ARGUMENT` and not a use of the parent);
    /// the table.
    fn derive(&mut self, parent: u32, label: [u64; NAME_WORDS], policy: wire::Policy) -> Out<u32> {
        if let Err(e) = self.0.gate::<u32>(CapPerms::WRITE) {
            return e;
        }
        let Some(req) = to_policy(&policy) else { return Out::err(outcome::BAD_ARGUMENT) };
        let who = match self.who::<u32>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        if !bindable(&who, &req) {
            return Out::err(outcome::NOT_READY);
        }
        // Look first, without charging a use: a request the parent's policy
        // does not allow must not cost the parent a use.
        let (peek, left) = {
            let mut s = STORE.lock();
            let left = s.remaining_s(parent, now_s());
            (s.admit(&who, now_s(), parent, ks::purpose::DERIVE, false), left)
        };
        let child = match peek {
            Ok(a) => match ks::child_policy(&a.policy, left.unwrap_or(0), &req) {
                Some(c) => Some(c),
                None => return Out::err(outcome::BAD_ARGUMENT),
            },
            // Not served: the counted look below refuses, and records why.
            Err(_) => None,
        };
        // Charge and record it for real; this is also where a refusal (owner,
        // expiry, purpose, uses) answers and is recorded.
        let adm = match self.admit::<u32>(&who, parent, Op::Derive, ks::purpose::DERIVE, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let Some(child) = child else { return Out::err(outcome::BAD_ARGUMENT) };
        let label: [u8; ks::NAME_LEN] = bytes_of(&label);
        let mut secret = ks::derive_child(adm.secret(), &label, child.purpose);
        self.put(&who, child, &[0; ks::NAME_LEN], &mut secret)
    }

    /// In order: the right (`READ`); the key (a `SIGN` key; taking the public
    /// part is no use of the secret and is not charged).
    fn public(&mut self, key: u32) -> Out<[u64; BLOCK_WORDS]> {
        if let Err(e) = self.0.gate::<[u64; BLOCK_WORDS]>(CapPerms::READ) {
            return e;
        }
        let who = match self.who::<[u64; BLOCK_WORDS]>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        match self.admit(&who, key, Op::Export, ks::purpose::SIGN, false) {
            Ok(a) => Out::ok(words_of(&ks::public_key(a.secret()))),
            Err(e) => e,
        }
    }

    /// In order: the right (`READ`); the length; the message, out of the
    /// caller's buffer (a bad buffer costs the key nothing); the key (a `SIGN`
    /// key); the signature, computed with no lock held, into the buffer.
    fn sign(&mut self, key: u32, buf: WireCap<KeyBuf>, len: u32) -> Out<u32> {
        if let Err(e) = self.0.gate::<u32>(CapPerms::READ) {
            return e;
        }
        if len == 0 || len as usize > SIGN_MSG_MAX {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let who = match self.who::<u32>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let mut msg = [0u8; SIGN_MSG_MAX];
        if let Err(code) = self.read_message(buf.raw(), &mut msg[..len as usize]) {
            return Out::err(code);
        }
        let adm = match self.admit::<u32>(&who, key, Op::Sign, ks::purpose::SIGN, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let mut sig = ks::sign(adm.secret(), &msg[..len as usize]);
        drop(adm);
        let wrote = self.write_signature(buf.raw(), &sig);
        secure_zero(&mut sig);
        match wrote {
            Ok(()) => Out::ok(SIG_BYTES as u32),
            Err(_) => Out::err(outcome::FAULT),
        }
    }

    /// In order: the right (`READ`); the key (a `SEAL` key).
    fn seal(&mut self, key: u32, data: [u64; BLOCK_WORDS]) -> Out<[u64; SEALED_WORDS]> {
        if let Err(e) = self.0.gate::<[u64; SEALED_WORDS]>(CapPerms::READ) {
            return e;
        }
        let who = match self.who::<[u64; SEALED_WORDS]>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let adm = match self.admit(&who, key, Op::Crypt, ks::purpose::SEAL, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let mut plain: [u8; ks::KEY_LEN] = bytes_of(&data);
        let blob = ks::siv_seal(adm.secret(), ks::AAD_DATA, &plain);
        secure_zero(&mut plain);
        Out::ok(words_of(&blob))
    }

    /// In order: the right (`READ`); the key (a `SEAL` key); the block (one
    /// that does not open under it is `BAD_ARGUMENT`, and the use was counted).
    fn unseal(&mut self, key: u32, sealed: [u64; SEALED_WORDS]) -> Out<[u64; BLOCK_WORDS]> {
        if let Err(e) = self.0.gate::<[u64; BLOCK_WORDS]>(CapPerms::READ) {
            return e;
        }
        let who = match self.who::<[u64; BLOCK_WORDS]>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let adm = match self.admit(&who, key, Op::Crypt, ks::purpose::SEAL, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let blob: [u8; ks::SEALED_LEN] = bytes_of(&sealed);
        match ks::siv_open(adm.secret(), ks::AAD_DATA, &blob) {
            Some(mut plain) => {
                let out = words_of(&plain);
                secure_zero(&mut plain);
                Out::ok(out)
            }
            None => Out::err(outcome::BAD_ARGUMENT),
        }
    }

    /// In order: the right (`EXEC`); the wrapping key (a `WRAP` key); the
    /// target (a `wrappable` key), whose purpose is the block's associated data.
    fn wrap(&mut self, key: u32, target: u32) -> Out<[u64; SEALED_WORDS]> {
        if let Err(e) = self.0.gate::<[u64; SEALED_WORDS]>(CapPerms::EXEC) {
            return e;
        }
        let who = match self.who::<[u64; SEALED_WORDS]>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let wrapping = match self.admit(&who, key, Op::Wrap, ks::purpose::WRAP, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let victim = match self.admit(&who, target, Op::Wrap, ks::NEED_WRAPPABLE, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let blob = ks::siv_seal(wrapping.secret(), victim.policy.purpose, victim.secret());
        Out::ok(words_of(&blob))
    }

    /// In order: the right (`WRITE`); the wrapping key (a `WRAP` key); the
    /// block, which must open under it for one of the four purposes (the
    /// purpose it was wrapped with is the one that opens it); the table. The
    /// new key is the owner's, volatile, not wrappable, and lives as long as
    /// the wrapping key has left.
    fn unwrap(&mut self, key: u32, sealed: [u64; SEALED_WORDS]) -> Out<u32> {
        if let Err(e) = self.0.gate::<u32>(CapPerms::WRITE) {
            return e;
        }
        let who = match self.who::<u32>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let left = STORE.lock().remaining_s(key, now_s());
        let wrapping = match self.admit::<u32>(&who, key, Op::Wrap, ks::purpose::WRAP, true) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let blob: [u8; ks::SEALED_LEN] = bytes_of(&sealed);
        for p in [ks::purpose::SIGN, ks::purpose::SEAL, ks::purpose::DERIVE, ks::purpose::WRAP] {
            if let Some(mut secret) = ks::siv_open(wrapping.secret(), p, &blob) {
                let policy = ks::Policy {
                    purpose: p,
                    envelope: Envelope::Owner,
                    backend: Backend::Volatile,
                    wrappable: false,
                    max_uses: 0,
                    ttl_s: left.unwrap_or(0).min(u64::from(u32::MAX)) as u32,
                };
                return self.put(&who, policy, &[0; ks::NAME_LEN], &mut secret);
            }
        }
        Out::err(outcome::BAD_ARGUMENT)
    }

    /// In order: the right (`WRITE` of the capability, containment aside);
    /// the key (its owner's, and its image's when bound). Destroying is not
    /// an op the system's containment stops: letting go of a secret is
    /// always safe.
    fn destroy(&mut self, key: u32) -> Out<()> {
        if !self.0.holds(CapPerms::WRITE) {
            self.0.deny(CapPerms::WRITE);
            return Out::err(outcome::DENIED);
        }
        let who = match self.who::<()>() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let r = STORE.lock().destroy(&who, key);
        match r {
            Ok(()) => Out::ok(()),
            Err(Refusal::NoKey) => Out::err(outcome::NO_RESOURCE),
            Err(Refusal::Refused(reason)) => {
                record(self.0.tid, key, Op::Export, reason);
                Out::err(outcome::DENIED)
            }
        }
    }

    /// In order: the right (`EXEC`, containment aside: letting a person in is
    /// not a new secret); the caller's Domain, which the grant is armed on; the
    /// name; the account (the row of the signed topology, or none); the lock;
    /// the board's root; the verifier, always computed, for a name the
    /// topology does not list too; the comparison against every key of the row,
    /// in constant time; the count, the grant and the record.
    fn login(&mut self, user: [u64; NAME_WORDS], credential: [u64; BLOCK_WORDS]) -> Out<u32> {
        if !self.0.holds(CapPerms::EXEC) {
            self.0.deny(CapPerms::EXEC);
            return Out::err(outcome::DENIED);
        }
        let mut words = credential;
        let mut cred: [u8; ks::KEY_LEN] = bytes_of(&words);
        secure_zero(&mut words);
        // `None`: no topology is loaded. That is not "nobody is enrolled" (a
        // loaded topology with no `[login.NAME]` row): the kernel cannot tell
        // an open console from a table it never read.
        let rows = azos_topology::get().map(|t| t.logins());
        let r = login_in(rows, self.0.tid, &user, &cred);
        secure_zero(&mut cred);
        r
    }
}

/// The body of [`Keys::login`](azos_devif::Keys::login) once the right is
/// known, against the accounts `rows` (the signed topology's, or a test's;
/// `None`: no topology is loaded and the call is `NOT_READY`, recorded); the
/// credential's copy is the caller's to wipe.
pub(crate) fn login_in(
    rows: Option<&[azos_topology::LoginSpec<'_>]>,
    tid: u32,
    user: &[u64; NAME_WORDS],
    cred: &[u8; ks::KEY_LEN],
) -> Out<u32> {
    let Some(dom) = azos_sched::idx_for_tid(tid).map(azos_sched::task_domain) else {
        return Out::err(outcome::NOT_READY);
    };
    let name: [u8; ks::NAME_LEN] = bytes_of(user);
    let len = name.iter().position(|&b| b == 0).unwrap_or(LOGIN_NAME_MAX);
    // Padded with NULs and nothing else after the name; a name the rows could
    // not carry is no name.
    if name[len..].iter().any(|&b| b != 0) || !login_name_ok(&name[..len]) {
        return Out::err(outcome::BAD_ARGUMENT);
    }
    let Some(rows) = rows else {
        record_login(Verdict::Refuse, 0, 0, LOGIN_NO_TOPOLOGY);
        return Out::err(outcome::NOT_READY);
    };
    let now = now_s();
    if rows.is_empty() && len == 0 {
        // Nobody is enrolled: the console session is the system's own.
        let ok = azos_sched::domain::arm_login_grant(dom, 0, now + azos_limits::LOGIN_GRANT_TTL_S as u64);
        record_login(Verdict::Admit, 0, 0, LOGIN_ADMITTED);
        return if ok { Out::ok(0) } else { Out::err(outcome::NOT_READY) };
    }
    let found = (len != 0).then(|| rows.iter().position(|l| l.name.as_bytes() == &name[..len])).flatten();
    let slot = found.unwrap_or(UNKNOWN);
    {
        let mut t = TRIES.lock();
        let e = &mut t[slot];
        if e.locked_until_s != 0 && now >= e.locked_until_s {
            *e = NO_TRIES;
        }
        if e.locked_until_s != 0 {
            let fails = e.fails;
            drop(t);
            record_login(Verdict::Refuse, 0, fails, LOGIN_LOCKED);
            return Out::err(outcome::DENIED);
        }
    }
    let Some(mut root) = root_for(Backend::Boot) else {
        record_login(Verdict::Refuse, 0, 0, LOGIN_NO_ROOT);
        return Out::err(outcome::NOT_READY);
    };
    // The account's root is its row's place in the signed topology plus one; a
    // name nobody listed is checked as the root no row has, against no key.
    let owner = found.map_or(u32::MAX, |i| i as u32 + 1);
    let none: &[[u8; 32]] = &[];
    let keys = found.map_or(none, |i| rows[i].keys());
    let public = ks::login_public(&root, owner, &name, cred);
    secure_zero(&mut root);
    let mut good = false;
    if let Some(p) = &public {
        for k in keys {
            good |= azos_crypto::ct::ct_eq(k, p);
        }
    }
    let mut t = TRIES.lock();
    let e = &mut t[slot];
    if good && found.is_some() {
        let before = e.fails;
        *e = NO_TRIES;
        drop(t);
        let armed = azos_sched::domain::arm_login_grant(dom, owner, now + azos_limits::LOGIN_GRANT_TTL_S as u64);
        record_login(Verdict::Admit, owner, before, LOGIN_ADMITTED);
        return if armed { Out::ok(owner) } else { Out::err(outcome::NOT_READY) };
    }
    e.fails = e.fails.saturating_add(1);
    if e.fails as usize >= azos_limits::LOGIN_MAX_FAILURES {
        e.locked_until_s = now + azos_limits::LOGIN_LOCKOUT_S as u64;
    }
    let fails = e.fails;
    drop(t);
    record_login(Verdict::Refuse, 0, fails, LOGIN_WRONG);
    Out::err(outcome::DENIED)
}

/// Back to "no keys, no roots". Test-only: a host test that made keys must not
/// leave them for the next.
#[cfg(test)]
pub fn __keys_clear_for_tests() {
    *STORE.lock() = Keystore::new(PER_OWNER);
    *ROOTS.lock() = [None; ks::ROOTS];
    WINDOW_S.store(u64::MAX, Ordering::Relaxed);
    WINDOW_N.store(0, Ordering::Relaxed);
    *TRIES.lock() = [NO_TRIES; UNKNOWN + 1];
}

// Host tests live in `tests/host/syscall-tests/src/keys_guards.rs`, for the
// reason `link_key.rs` gives at its foot.
