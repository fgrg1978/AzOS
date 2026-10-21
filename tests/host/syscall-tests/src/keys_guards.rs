// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Keys` interface --
// `crates/core/syscall/src/keys.rs::Server`: the authority in front of the
// keystore (the endpoint's rights, the op mask, containment), whose key it is
// (the owner of the caller's Domain, its image), the `key-use` records, and the
// roots persistent keys derive from. The policy itself (purposes, uses, time to
// live, the derivations) is `tests/host/crypto-tests`, `keystore_tests`.
//
// Every call here goes the way a task's does: the endpoint resolves, the call
// is admitted against the capability's op mask, the interface serves, through
// the generated client (`Holder`).
//
// Included inside `mod handlers { .. }` like `link_key_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_crypto::keystore as ks;
use azos_decision::{Rule, Verdict};
use azos_devif::keys::{self as wire, op, KeyBuf, Policy, SIGNER_OPS};
use azos_devif::{key, outcome, Cap as WireCap, KeysCall, KeysClient, Out};
use azos_idl::{IdlError, MsgDesc, Transport};
use azos_ipc::memobj::{memobj_create_cap, memobj_with_span_ref, MemPerms, MemSpec};
use std::sync::atomic::{AtomicU32, Ordering};

/// TIDs no other file in this crate uses.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e30_0001);

const SEED: [u8; 32] = [0x42; 32];
const IMAGE_X: [u8; 32] = [0xA1; 32];
const IMAGE_Y: [u8; 32] = [0xB2; 32];

fn seed_hook(out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    *out = SEED;
    true
}

fn no_seed_hook(_out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    false
}

/// A pool that always answers, with bytes that differ at every draw (a key
/// made twice must not be the same key).
static DRAWS: AtomicU32 = AtomicU32::new(1);

fn pool_fill(buf: &mut [u8]) -> bool {
    let n = DRAWS.fetch_add(1, Ordering::SeqCst) as u8;
    for (i, b) in buf.iter_mut().enumerate() {
        *b = n.wrapping_mul(31).wrapping_add(i as u8) | 1;
    }
    true
}

fn pool_recorder(_tid: u32) {}

/// The root `Boot` keys derive from, for `SEED`: restated here so that the test
/// pins the derivation (`HKDF-SHA256(salt = "azos keystore root v1",
/// ikm = seed, info = "boot")`) and not just its own consistency.
fn boot_root() -> [u8; 32] {
    let mut root = [0u8; 32];
    assert!(azos_crypto::hkdf::hkdf(b"azos keystore root v1", &SEED, b"boot", &mut root));
    root
}

fn name(s: &[u8]) -> [u64; 2] {
    let mut b = [0u8; 16];
    b[..s.len()].copy_from_slice(s);
    [u64::from_le_bytes(b[..8].try_into().unwrap()), u64::from_le_bytes(b[8..].try_into().unwrap())]
}

fn name_bytes(s: &[u8]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..s.len()].copy_from_slice(s);
    b
}

fn words(b: &[u8]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn host_policy() -> Policy {
    Policy { purpose: wire::purpose::SIGN, envelope: wire::envelope::IMAGE, backend: wire::backend::BOOT, ..Policy::default() }
}

fn volatile(purpose: u8) -> Policy {
    Policy { purpose, envelope: wire::envelope::OWNER, backend: wire::backend::VOLATILE, ..Policy::default() }
}

fn reset() {
    // A test that failed while the system was contained must not leave it so.
    azos_ipc::cap::degraded_set(false);
    crate::keys::__keys_clear_for_tests();
    crate::link_key::set_link_key_read_hook(seed_hook);
    crate::entropy::set_entropy_hooks(pool_fill, pool_recorder);
}

fn tidy() {
    azos_ipc::cap::degraded_set(false);
    crate::link_key::__link_key_read_hook_clear_for_tests();
    crate::entropy::__entropy_clear_for_tests();
    crate::keys::__keys_clear_for_tests();
}

/// The `key-use` records written for `tid`, oldest first: `(verdict, handle,
/// op, reason)`.
fn uses(tid: u32) -> Vec<(u8, u64, u64, u64)> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::KeyUse as u8 && r.subject == tid {
            v.push((r.verdict, r.n[0], r.n[1], r.n[2]));
        }
    });
    v
}

const ADMIT: u8 = Verdict::Admit as u8;
const REFUSE: u8 = Verdict::Refuse as u8;

/// A task in a Domain of `owner`, measured as `image`, holding one capability to
/// the kernel-hosted `keys`: what a topology row grants. Dropping it releases the
/// task.
struct Holder {
    tid: u32,
    ep: u32,
}

impl Holder {
    fn new(owner: u32, image: [u8; 32], slot: usize, perms: CapPerms, ops: u64) -> Holder {
        let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
        let dom = azos_sched::domain::create().expect("a free Domain slot");
        azos_sched::domain::set_measurement(dom, image);
        azos_sched::domain::set_identity(dom, owner, 0, 0);
        azos_sched::shim_bind_domain(tid, dom);
        ipc_task_pool::shim_bind(tid, slot);
        azos_ipc::cap_store::reset(tid);
        azos_sched::set_current_task_tid(tid);
        let cap = azos_ipc::endpoint::kernel_endpoint_cap_ops(tid, perms, key::KEYS, 0, ops).expect("grant");
        Holder { tid, ep: cap.raw().0 }
    }

    fn rw(owner: u32, image: [u8; 32], slot: usize) -> Holder {
        Holder::new(owner, image, slot, CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::EXEC), 0)
    }

    fn client(&self) -> KeysClient<&Holder> {
        KeysClient::new(self)
    }

    /// A one-page read-write memory object of this task's, for `sign`: its
    /// capability handle.
    fn buffer(&self) -> u32 {
        memobj_create_cap(self.tid, 1, &MemSpec::anon(MemPerms::ReadWrite)).expect("a buffer").raw().0
    }

    fn region(&self, cap: u32) -> u32 {
        azos_ipc::cap_store::read_table(self.tid, |t| t.peek_raw(azos_abi::cap::CapHandle(cap)))
            .flatten()
            .expect("the buffer is in the table")
            .2
    }

    fn put(&self, cap: u32, bytes: &[u8]) {
        let r = self.region(cap);
        let ok = memobj_with_span_ref(r, bytes.len(), |base| {
            // SAFETY: `base` addresses `bytes.len()` bytes of the object, held under the table's lock.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, bytes.len()) }
        });
        assert_eq!(ok.unwrap(), Some(()), "the buffer cannot be written from the kernel's side");
    }

    fn get(&self, cap: u32, len: usize) -> Vec<u8> {
        let r = self.region(cap);
        let mut out = vec![0u8; len];
        let ok = memobj_with_span_ref(r, len, |base| {
            // SAFETY: as in `put`.
            unsafe { core::ptr::copy_nonoverlapping(base as *const u8, out.as_mut_ptr(), len) }
        });
        assert_eq!(ok.unwrap(), Some(()));
        out
    }

    /// Sign `msg` with `k`: the outcome and, when served, the signature.
    fn sign(&self, k: u32, msg: &[u8]) -> Result<Vec<u8>, u32> {
        let buf = self.buffer();
        self.put(buf, msg);
        let out = self.client().sign(k, WireCap::<KeyBuf>::from_raw(buf), msg.len() as u32).map_err(|_| outcome::NO_SERVER)?;
        if !out.is_ok() {
            return Err(out.code);
        }
        assert_eq!(out.value, 64);
        Ok(self.get(buf, 64))
    }

    fn public(&self, k: u32) -> Out<[u64; 4]> {
        self.client().public(k).unwrap()
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        ipc_task_pool::shim_kill(self.tid);
        azos_sched::shim_unbind_domains();
        azos_ipc::memobj::memobj_release_all(self.tid);
    }
}

/// The call as the syscall layer makes it: a request that carries capability
/// entries only to an interface that takes them, the endpoint resolves, the call
/// is admitted against the op mask, the interface serves. A refusal at any step
/// is the syscall's own failure, which the client reads as a transport error.
impl Transport for &Holder {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        azos_sched::set_current_task_tid(self.tid);
        if msg.n_caps != 0 && !crate::khost::takes_caps(key::KEYS) {
            return Err(IdlError::Transport(-1));
        }
        azos_ipc::endpoint::endpoint_resolve(self.tid, self.ep).map_err(|_| IdlError::Transport(-1))?;
        let who = crate::khost::admit(self.tid, self.ep, msg.words[0]).ok_or(IdlError::Transport(-1))?;
        let req = *msg;
        crate::khost::serve(key::KEYS, &who, &req, msg);
        Ok(())
    }
}

// ── The host key: the user ──────────────────────────────────────────────────

/// **A signer opens its host key, reads the public part and signs, and the
/// secret is the board's.** The key is named, bound to the image and derived
/// from the board seed: the public key is the one the derivation gives, the
/// signature verifies under it, and the same name asked again is the same
/// handle (a restarted service finds its key).
///
/// **Canary.** Derive without the image (`Envelope::Owner` in `derive_persistent`'s
/// info): the second half of `another_image_*` is red. Sign with another seed:
/// the verification here is red.
#[test]
fn a_signer_opens_its_host_key_reads_the_public_part_and_signs() {
    let _g = serial();
    reset();
    let h = Holder::new(7, IMAGE_X, 44, CapPerms::READ.union(CapPerms::WRITE), SIGNER_OPS);
    let k = h.client().generate(name(b"sshd.host"), host_policy()).unwrap();
    assert!(k.is_ok(), "{k:?}");

    let who = ks::Principal { owner_root: 7, measurement: IMAGE_X };
    let p = ks::Policy {
        purpose: ks::purpose::SIGN,
        envelope: ks::Envelope::Image,
        backend: ks::Backend::Boot,
        wrappable: false,
        max_uses: 0,
        ttl_s: 0,
    };
    let secret = ks::derive_persistent(&boot_root(), &who, &p, &name_bytes(b"sshd.host")).unwrap();
    let pk = ks::public_key(&secret);
    assert_eq!(h.public(k.value), Out::ok(words(&pk)));

    let digest = [0x5Au8; 32];
    let sig = h.sign(k.value, &digest).expect("served");
    assert!(azos_crypto::ed25519::sig_verify_message(&pk, sig[..].try_into().unwrap(), &digest));
    let other = h.sign(k.value, &[0x5B; 32]).expect("served");
    assert_ne!(sig, other);

    // Opened again: the same handle, the same key.
    let again = h.client().generate(name(b"sshd.host"), host_policy()).unwrap();
    assert_eq!(again, k);

    // The uses are on the record: the public key, then two signatures.
    let rec = uses(h.tid);
    assert_eq!(
        rec,
        vec![
            (ADMIT, u64::from(k.value), 5, 0),
            (ADMIT, u64::from(k.value), 1, 0),
            (ADMIT, u64::from(k.value), 1, 0),
        ]
    );
    tidy();
}

/// **The secret is the image's and the owner's.** Another image of the same owner
/// asking for the same name gets another key; so does another owner; and a handle
/// presented by either is refused, with a record that says it was not theirs.
///
/// **Canary.** Compare nothing in `belongs_to`: the presented handles are served.
#[test]
fn another_image_or_owner_has_another_key_and_cannot_use_this_one() {
    let _g = serial();
    reset();
    let a = Holder::rw(7, IMAGE_X, 44);
    let y = Holder::rw(7, IMAGE_Y, 45);
    let b = Holder::rw(8, IMAGE_X, 46);
    let ka = a.client().generate(name(b"sshd.host"), host_policy()).unwrap().value;
    let ky = y.client().generate(name(b"sshd.host"), host_policy()).unwrap().value;
    assert_ne!(ka, ky);
    assert_ne!(a.public(ka).value, y.public(ky).value, "two images shared a host key");

    // Image Y presents image X's handle: not its key.
    assert_eq!(y.public(ka), Out::err(outcome::DENIED));
    assert_eq!(y.sign(ka, &[1; 32]), Err(outcome::DENIED));
    assert_eq!(uses(y.tid).iter().filter(|r| r.0 == REFUSE && r.3 == 2).count(), 2, "{:?}", uses(y.tid));

    // Another owner, the same image: its own key, and not this one's.
    let kb = b.client().generate(name(b"sshd.host"), host_policy()).unwrap().value;
    assert_ne!(a.public(ka).value, b.public(kb).value, "two owners shared a host key");
    assert_eq!(b.public(ka), Out::err(outcome::DENIED));
    assert_eq!(b.client().destroy(ka).unwrap(), Out::err(outcome::DENIED), "nor can it destroy it");
    assert!(a.public(ka).is_ok(), "the key is still there");
    tidy();
}

// ── Rights, mask, containment ───────────────────────────────────────────────

/// **The op class is the capability's.** Without `WRITE` nothing is made; without
/// `READ` nothing is used or read; without `EXEC` nothing is wrapped. The refusal
/// comes before the table is looked at.
///
/// **Canary.** Skip a gate: that op is served to the caller without the class.
#[test]
fn each_op_needs_its_class() {
    let _g = serial();
    reset();
    let full = Holder::rw(7, IMAGE_X, 44);
    let sealer = full.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().value;
    let wrapper = full.client().generate([0; 2], volatile(wire::purpose::WRAP)).unwrap().value;
    let victim = full.client().generate([0; 2], Policy { wrappable: true, ..volatile(wire::purpose::SEAL) }).unwrap().value;
    let signer = full.client().generate([0; 2], volatile(wire::purpose::SIGN)).unwrap().value;
    let blob = full.client().seal(sealer, [1; 4]).unwrap();
    assert!(blob.is_ok());
    let wrapped = full.client().wrap(wrapper, victim).unwrap();
    assert!(wrapped.is_ok());

    let no_write = Holder::new(7, IMAGE_X, 45, CapPerms::READ.union(CapPerms::EXEC), 0);
    let mut c = no_write.client();
    assert_eq!(c.generate([0; 2], volatile(wire::purpose::SEAL)).unwrap(), Out::err(outcome::DENIED));
    assert_eq!(c.import(volatile(wire::purpose::SEAL), [3; 4]).unwrap(), Out::err(outcome::DENIED));
    assert_eq!(c.derive(wrapper, [0; 2], volatile(wire::purpose::SEAL)).unwrap(), Out::err(outcome::DENIED));
    assert_eq!(c.unwrap(wrapper, wrapped.value).unwrap(), Out::err(outcome::DENIED));
    assert_eq!(c.destroy(sealer).unwrap(), Out::err(outcome::DENIED));
    // What READ and EXEC reach, it reaches.
    assert!(c.seal(sealer, [1; 4]).unwrap().is_ok());
    drop(no_write);

    let no_read = Holder::new(7, IMAGE_X, 45, CapPerms::WRITE.union(CapPerms::EXEC), 0);
    let mut c = no_read.client();
    assert_eq!(c.public(signer).unwrap(), Out::err(outcome::DENIED));
    assert_eq!(no_read.sign(signer, &[1; 32]), Err(outcome::DENIED));
    assert_eq!(c.seal(sealer, [1; 4]).unwrap(), Out::err(outcome::DENIED));
    assert_eq!(c.unseal(sealer, blob.value).unwrap(), Out::err(outcome::DENIED));
    drop(no_read);

    let no_exec = Holder::new(7, IMAGE_X, 45, CapPerms::READ.union(CapPerms::WRITE), 0);
    assert_eq!(no_exec.client().wrap(wrapper, victim).unwrap(), Out::err(outcome::DENIED));
    // And none of those refusals was a use of a key.
    assert!(uses(no_exec.tid).is_empty());
    tidy();
}

/// **A mask of generate, public and sign is all a signer has.** The other ops
/// are refused by the call before the interface runs, whatever the class.
///
/// **Canary.** Skip the mask in `khost::admit`: `import` is served.
#[test]
fn a_signer_mask_reaches_generate_public_and_sign_only() {
    let _g = serial();
    reset();
    let h = Holder::new(7, IMAGE_X, 44, CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::EXEC), SIGNER_OPS);
    let k = h.client().generate(name(b"sshd.host"), host_policy()).unwrap().value;
    assert!(h.public(k).is_ok());
    assert!(h.sign(k, &[9; 32]).is_ok());
    let mut c = h.client();
    assert!(c.import(volatile(wire::purpose::SEAL), [1; 4]).is_err(), "import crossed a signer's mask");
    assert!(c.derive(k, [0; 2], volatile(wire::purpose::SEAL)).is_err());
    assert!(c.seal(k, [1; 4]).is_err());
    assert!(c.wrap(k, k).is_err());
    assert!(c.destroy(k).is_err());
    // The key was not touched by any of them.
    assert!(h.sign(k, &[9; 32]).is_ok());
    for bit in [op::IMPORT, op::DERIVE, op::SEAL, op::UNSEAL, op::WRAP, op::UNWRAP, op::DESTROY] {
        assert_eq!(SIGNER_OPS >> bit & 1, 0);
    }
    tidy();
}

/// **Containment stops minting secrets and does not stop using keys.** While the
/// system is contained a new random key is refused, a signature and the public
/// key are served (nothing acts), a key can still be let go, and a named key
/// opens (its secret is the board's, and the remote door that signs with it must
/// come up while the system is contained).
///
/// **Canary.** Check `holds` instead of `allows` for the volatile path of
/// `generate`: the first assertion is red. Check `allows` for the named path: the
/// `opens while contained` line is. Check `allows` in `destroy`: the last is.
#[test]
fn containment_stops_making_keys_and_not_using_or_destroying_them() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let k = h.client().generate(name(b"sshd.host"), host_policy()).unwrap().value;
    let v = h.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().value;
    azos_ipc::cap::degraded_set(true);
    assert_eq!(h.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap(), Out::err(outcome::DENIED));
    let again = h.client().generate(name(b"sshd.host"), host_policy()).unwrap();
    assert_eq!(again, Out::ok(k), "a named key opens while contained");
    let fresh = h.client().generate(name(b"other.key"), host_policy()).unwrap();
    assert!(fresh.is_ok(), "so does one that was never opened: it is the board's");
    assert_eq!(h.client().import(volatile(wire::purpose::SEAL), [1; 4]).unwrap(), Out::err(outcome::DENIED));
    assert!(h.public(k).is_ok());
    assert!(h.sign(k, &[1; 32]).is_ok());
    assert!(h.client().seal(v, [1; 4]).unwrap().is_ok(), "sealing is not an action");
    assert_eq!(h.client().destroy(v).unwrap(), Out::ok(()));
    azos_ipc::cap::degraded_set(false);
    assert_eq!(h.client().public(v).unwrap(), Out::err(outcome::NO_RESOURCE), "it is gone");
    tidy();
}

// ── The roots ───────────────────────────────────────────────────────────────

/// **A backend with no root answers `NOT_READY`; a volatile key needs none.**
/// No board seed: a `Boot` key is not made. No installed secret: `TpmNv` and
/// `Volume` are not made either. A volatile key is drawn from the pool, and an
/// unseeded pool is `NOT_READY` too.
///
/// **Canary.** Derive from a zero root: the first assertion is red.
#[test]
fn a_backend_without_a_root_is_not_ready() {
    let _g = serial();
    reset();
    crate::link_key::set_link_key_read_hook(no_seed_hook);
    let h = Holder::rw(7, IMAGE_X, 44);
    assert_eq!(h.client().generate(name(b"k"), host_policy()).unwrap(), Out::err(outcome::NOT_READY));
    for backend in [wire::backend::TPM_NV, wire::backend::VOLUME] {
        let p = Policy { backend, ..host_policy() };
        assert_eq!(h.client().generate(name(b"k"), p).unwrap(), Out::err(outcome::NOT_READY), "backend {backend}");
    }
    assert!(h.client().generate([0; 2], volatile(wire::purpose::SIGN)).unwrap().is_ok());
    crate::entropy::__entropy_clear_for_tests();
    assert_eq!(
        h.client().generate([0; 2], volatile(wire::purpose::SIGN)).unwrap(),
        Out::err(outcome::NOT_READY),
        "an unseeded pool makes no key"
    );
    tidy();
}

/// **An installed root is a backend, and it is its own.** The TPM's secret makes
/// `TpmNv` keys, the volume's makes `Volume` keys, and the same name under each
/// (and under `Boot`) is three keys.
///
/// **Canary.** Index every root with the same slot: the three public keys are one.
#[test]
fn each_installed_root_is_its_own_backend() {
    let _g = serial();
    reset();
    assert!(crate::keys::install_root(ks::Backend::TpmNv, &[0x11; 32]));
    assert!(crate::keys::install_root(ks::Backend::Volume, &[0x22; 32]));
    assert!(!crate::keys::install_root(ks::Backend::Volume, &[0; 32]), "an all-zero root is none");
    assert!(!crate::keys::install_root(ks::Backend::Volatile, &[0x33; 32]));
    let h = Holder::rw(7, IMAGE_X, 44);
    let mut pks = Vec::new();
    for backend in [wire::backend::BOOT, wire::backend::TPM_NV, wire::backend::VOLUME] {
        let k = h.client().generate(name(b"k"), Policy { backend, ..host_policy() }).unwrap();
        assert!(k.is_ok(), "backend {backend}");
        pks.push(h.public(k.value).value);
    }
    assert!(pks[0] != pks[1] && pks[1] != pks[2] && pks[0] != pks[2], "{pks:?}");
    tidy();
}

/// A recording of the files the volume backend reads and writes.
struct MemFiles {
    files: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    writable: bool,
}

impl crate::file_ops::FileOps for MemFiles {
    fn open_at(&self, _root: &[u8], rel: &[u8], flags: u32) -> i64 {
        if !self.writable {
            return -1;
        }
        let mut f = self.files.lock().unwrap();
        assert_eq!(flags, 1 | 0x40 | 0x200, "created for writing, emptied");
        f.retain(|(p, _)| p != rel);
        f.push((rel.to_vec(), Vec::new()));
        (f.len() - 1) as i64
    }
    fn close(&self, _fd: i32) -> i64 { 0 }
    fn read(&self, _fd: i32, _dst: &mut [u8]) -> i64 { -1 }
    fn write(&self, fd: i32, src: &[u8]) -> i64 {
        self.files.lock().unwrap()[fd as usize].1.extend_from_slice(src);
        src.len() as i64
    }
    fn lseek(&self, _fd: i32, _offset: i64, _whence: i32) -> i64 { -1 }
    fn dup(&self, _fd: i32) -> i64 { -1 }
    fn mkdir(&self, _path: &[u8]) -> i64 { -1 }
    fn unlink(&self, _path: &[u8]) -> i64 { -1 }
    fn readdir(&self, _path: &[u8], _index: u32) -> Option<([u8; 64], u32, bool)> { None }
    fn release_all(&self, _tid: u32) -> usize { 0 }
    fn read_whole(&self, path: &[u8], dst: &mut [u8]) -> usize {
        let rel = crate::file_ops::rel_to_root(path);
        let f = self.files.lock().unwrap();
        match f.iter().find(|(p, _)| p == rel) {
            Some((_, data)) if data.len() <= dst.len() => {
                dst[..data.len()].copy_from_slice(data);
                data.len()
            }
            _ => 0,
        }
    }
}

/// **The volume's secret is read if the file is there, made if it is not, and a
/// file of another size is no root.** A path that is empty is no backend. A file
/// system that cannot write leaves the backend without a root.
///
/// **Canary.** Install the buffer without reading the file back: the `Created`
/// root is not what the medium holds.
#[test]
fn the_volume_root_is_read_or_created_and_a_bad_file_is_no_root() {
    let _g = serial();
    reset();
    let path = b"/keys/ROOT.KEY";
    assert_eq!(crate::keys::install_volume_root_at(b""), crate::keys::VolumeRoot::Off);
    assert!(!crate::keys::has_root(ks::Backend::Volume));

    static OK: MemFiles = MemFiles { files: std::sync::Mutex::new(Vec::new()), writable: true };
    crate::file_ops::set_file_ops(&OK);
    assert_eq!(crate::keys::install_volume_root_at(path), crate::keys::VolumeRoot::Created);
    let made = OK.files.lock().unwrap()[0].1.clone();
    assert_eq!(made.len(), 32);
    assert!(crate::keys::has_root(ks::Backend::Volume));

    // The next boot reads the file and installs the same root: the same key.
    let h = Holder::rw(7, IMAGE_X, 44);
    let first = h.client().generate(name(b"k"), Policy { backend: wire::backend::VOLUME, ..host_policy() }).unwrap();
    let pk1 = h.public(first.value).value;
    crate::keys::__keys_clear_for_tests();
    assert_eq!(crate::keys::install_volume_root_at(path), crate::keys::VolumeRoot::Read);
    let again = h.client().generate(name(b"k"), Policy { backend: wire::backend::VOLUME, ..host_policy() }).unwrap();
    assert_eq!(h.public(again.value).value, pk1);

    // A file of the wrong size (longer or shorter) is not a root.
    crate::keys::__keys_clear_for_tests();
    OK.files.lock().unwrap()[0].1.push(0);
    assert_eq!(crate::keys::install_volume_root_at(path), crate::keys::VolumeRoot::Failed);
    OK.files.lock().unwrap()[0].1.truncate(31);
    assert_eq!(crate::keys::install_volume_root_at(path), crate::keys::VolumeRoot::Failed);
    assert!(!crate::keys::has_root(ks::Backend::Volume));

    // A medium that cannot be written, an unseeded pool.
    static RO: MemFiles = MemFiles { files: std::sync::Mutex::new(Vec::new()), writable: false };
    crate::file_ops::set_file_ops(&RO);
    assert_eq!(crate::keys::install_volume_root_at(path), crate::keys::VolumeRoot::Failed);
    crate::file_ops::set_file_ops(&OK);
    OK.files.lock().unwrap().clear();
    crate::entropy::__entropy_clear_for_tests();
    assert_eq!(crate::keys::install_volume_root_at(path), crate::keys::VolumeRoot::Failed);
    assert!(OK.files.lock().unwrap().is_empty(), "nothing was written from an unseeded pool");
    crate::file_ops::__file_ops_clear_for_tests();
    tidy();
}

// ── The rest of the ops through the interface ───────────────────────────────

/// **Seal, unseal and derive, end to end.** A block sealed opens, under its key
/// only; a child derived twice is one key and another label is another key.
///
/// **Canary.** Seal with a constant key: the block opens under `other`.
#[test]
fn seal_unseal_and_derive_round_trip_through_the_interface() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let mut c = h.client();

    let s = c.generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().value;
    let blob = c.seal(s, [1, 2, 3, 4]).unwrap();
    assert!(blob.is_ok());
    assert_eq!(c.unseal(s, blob.value).unwrap(), Out::ok([1, 2, 3, 4]));
    let mut bad = blob.value;
    bad[5] ^= 1;
    assert_eq!(c.unseal(s, bad).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    let other = c.generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().value;
    assert_eq!(c.unseal(other, blob.value).unwrap(), Out::err(outcome::BAD_ARGUMENT), "another key");

    let owner_wide = Policy { purpose: wire::purpose::DERIVE, envelope: wire::envelope::OWNER, ..host_policy() };
    let d = c.generate(name(b"derive.root"), owner_wide).unwrap().value;
    let c1 = c.derive(d, name(b"child"), volatile(wire::purpose::SIGN)).unwrap();
    let c2 = c.derive(d, name(b"child"), volatile(wire::purpose::SIGN)).unwrap();
    let c3 = c.derive(d, name(b"child2"), volatile(wire::purpose::SIGN)).unwrap();
    assert!(c1.is_ok() && c2.is_ok() && c3.is_ok(), "{c1:?} {c2:?} {c3:?}");
    let (c1, c2, c3) = (c1.value, c2.value, c3.value);
    assert!(h.public(c1).is_ok());
    assert_eq!(h.public(c1), h.public(c2), "the same parent and label are one key");
    assert_ne!(h.public(c1).value, h.public(c3).value);
    // An image-bound parent begets no owner-wide child, and the refusal is not a use of it.
    let bound = c.generate(name(b"bound.root"), Policy { max_uses: 1, ..Policy { purpose: wire::purpose::DERIVE, ..host_policy() } }).unwrap().value;
    assert_eq!(c.derive(bound, name(b"x"), volatile(wire::purpose::SIGN)).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    let image_child = Policy { envelope: wire::envelope::IMAGE, ..volatile(wire::purpose::SIGN) };
    assert!(c.derive(bound, name(b"x"), image_child).unwrap().is_ok(), "the one use was still there");
    assert_eq!(c.derive(s, name(b"x"), volatile(wire::purpose::SIGN)).unwrap(), Out::err(outcome::DENIED), "a sealer derives nothing");

    tidy();
}

/// **Wrap, unwrap and import, end to end.** A wrapped key comes back and does
/// what it did (the same key, the same signature); a key that is not wrappable
/// stays; a sealer unwraps nothing; an imported secret is a key.
///
/// **Canary.** Wrap without binding the purpose: unwrap finds the block under
/// another purpose and the new key signs as a sealer.
#[test]
fn wrap_unwrap_and_import_round_trip_through_the_interface() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let mut c = h.client();
    let s = c.generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().value;
    let w = c.generate([0; 2], volatile(wire::purpose::WRAP)).unwrap().value;
    let signer = c.generate([0; 2], Policy { wrappable: true, ..volatile(wire::purpose::SIGN) }).unwrap().value;
    let plain = c.generate([0; 2], volatile(wire::purpose::SIGN)).unwrap().value;
    assert_eq!(c.wrap(w, plain).unwrap(), Out::err(outcome::DENIED), "a key that is not wrappable stays");
    let wrapped = c.wrap(w, signer).unwrap();
    assert!(wrapped.is_ok());
    let back = c.unwrap(w, wrapped.value).unwrap();
    assert!(back.is_ok());
    assert_eq!(h.public(back.value), h.public(signer), "the same key came back");
    assert_eq!(h.sign(back.value, &[3; 32]), h.sign(signer, &[3; 32]));
    let mut torn = wrapped.value;
    torn[0] ^= 1;
    assert_eq!(c.unwrap(w, torn).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(c.unwrap(s, wrapped.value).unwrap(), Out::err(outcome::DENIED), "a sealer unwraps nothing");

    let imported = c.import(volatile(wire::purpose::SIGN), words(&[0x77; 32])).unwrap();
    assert!(imported.is_ok());
    assert_eq!(h.public(imported.value).value, words(&ks::public_key(&[0x77; 32])));
    tidy();
}

/// **The uses of a handle run out, and the refusal is a durable receipt.**
///
/// **Canary.** Count the use after the check instead of before: the third call is served.
#[test]
fn a_handle_serves_its_uses_and_then_is_denied_with_a_record() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let k = h.client().generate([0; 2], Policy { max_uses: 2, ..volatile(wire::purpose::SIGN) }).unwrap().value;
    assert!(h.sign(k, &[1; 32]).is_ok());
    assert!(h.sign(k, &[1; 32]).is_ok());
    assert_eq!(h.sign(k, &[1; 32]), Err(outcome::DENIED));
    assert!(h.public(k).is_ok(), "the public key is not a use");
    let rec = uses(h.tid);
    assert_eq!(rec.last().copied(), Some((ADMIT, u64::from(k), 5, 0)));
    assert_eq!(rec[2], (REFUSE, u64::from(k), 1, 3));
    tidy();
}

/// **A handle expires and says so.**
///
/// **Canary.** Read the clock in milliseconds: the key outlives its ttl.
#[test]
fn a_handle_expires_after_its_ttl() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let k = h.client().generate([0; 2], Policy { ttl_s: 10, ..volatile(wire::purpose::SIGN) }).unwrap().value;
    azos_drv_irqchip::clint::set_time(9 * 10_000_000);
    assert!(h.sign(k, &[1; 32]).is_ok());
    azos_drv_irqchip::clint::set_time(10 * 10_000_000);
    assert_eq!(h.sign(k, &[1; 32]), Err(outcome::DENIED));
    assert_eq!(uses(h.tid).last().copied(), Some((REFUSE, u64::from(k), 1, 4)));
    azos_drv_irqchip::clint::set_time(0);
    tidy();
}

/// **A refusal storm writes a few durable receipts, not one per call.** The
/// budget is per second; past it the record is `Deny` (the ring alone).
///
/// **Canary.** Always `Refuse`: the ring is full of durable receipts.
#[test]
fn refusals_are_receipts_within_a_budget() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let k = h.client().generate([0; 2], volatile(wire::purpose::SIGN)).unwrap().value;
    for _ in 0..20 {
        assert_eq!(h.client().seal(k, [1; 4]).unwrap(), Out::err(outcome::DENIED));
    }
    let rec = uses(h.tid);
    assert_eq!(rec.len(), 20);
    let durable = rec.iter().filter(|r| r.0 == REFUSE).count();
    assert_eq!(durable, 8);
    assert!(rec.iter().all(|r| r.3 == 1 && r.2 == 2));
    assert_eq!(rec.iter().filter(|r| r.0 == Verdict::Deny as u8).count(), 12);
    tidy();
}

// ── The buffer of `sign` ────────────────────────────────────────────────────

/// **A buffer the kernel cannot use costs the key nothing.** No buffer, a handle
/// that is not a memory object, a message of no bytes or too many, a buffer held
/// without write: each is refused and the key's uses are intact.
///
/// **Canary.** Admit before reading the message: the key with one use is spent.
#[test]
fn a_bad_buffer_or_length_is_refused_before_the_key_is_used() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let k = h.client().generate([0; 2], Policy { max_uses: 1, ..volatile(wire::purpose::SIGN) }).unwrap().value;
    let buf = h.buffer();
    h.put(buf, &[1; 32]);
    let mut c = h.client();
    let mut call = |cap: u32, len: u32| c.sign(k, WireCap::<KeyBuf>::from_raw(cap), len).unwrap();
    assert_eq!(call(buf, 0), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(call(buf, 257), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(call(0x7777, 32), Out::err(outcome::BAD_ARGUMENT), "no such handle");
    let ep = h.ep;
    assert_eq!(call(ep, 32), Out::err(outcome::BAD_ARGUMENT), "an endpoint is not a buffer");
    assert!(uses(h.tid).is_empty(), "a refused call was recorded as a use");
    assert_eq!(call(buf, 32).code, outcome::OK, "the one use is still there");
    assert_eq!(call(buf, 32), Out::err(outcome::DENIED));
    tidy();
}

/// **A message of the longest size signs, and the signature replaces it.**
#[test]
fn the_longest_message_signs() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let k = h.client().generate(name(b"k"), host_policy()).unwrap().value;
    let msg: Vec<u8> = (0..256u32).map(|i| (i * 7) as u8).collect();
    let sig = h.sign(k, &msg).expect("served");
    let pk: [u8; 32] = {
        let o = h.public(k).value;
        core::array::from_fn(|i| o[i / 8].to_le_bytes()[i % 8])
    };
    assert!(azos_crypto::ed25519::sig_verify_message(&pk, sig[..].try_into().unwrap(), &msg));
    assert!(!azos_crypto::ed25519::sig_verify_message(&pk, sig[..].try_into().unwrap(), &msg[..255]));
    tidy();
}

// ── The table ───────────────────────────────────────────────────────────────

/// **One owner cannot fill the table, and the system's keys are the system's.**
/// An owner past its share is `BUSY`; another owner still makes keys; destroying
/// gives the slot back.
///
/// **Canary.** Count keys of all owners against the share: the second owner is `BUSY` too.
#[test]
fn an_owner_holds_its_share_of_the_table() {
    let _g = serial();
    reset();
    let share = azos_limits::KEYSTORE_KEYS_PER_OWNER as usize;
    let a = Holder::rw(7, IMAGE_X, 44);
    let mut made = Vec::new();
    for _ in 0..share {
        let k = a.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap();
        assert!(k.is_ok());
        made.push(k.value);
    }
    assert_eq!(a.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap(), Out::err(outcome::BUSY));
    let b = Holder::rw(8, IMAGE_X, 45);
    assert!(b.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().is_ok());
    assert_eq!(a.client().destroy(made[0]).unwrap(), Out::ok(()));
    assert!(a.client().generate([0; 2], volatile(wire::purpose::SEAL)).unwrap().is_ok());
    assert_eq!(a.client().destroy(made[0]).unwrap(), Out::err(outcome::NO_RESOURCE), "a second destroy finds nothing");
    tidy();
}

/// **A named key with another policy, a name without a root backend, a policy
/// that is not valid: each is refused with its own outcome.**
#[test]
fn a_malformed_or_conflicting_request_has_its_own_outcome() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, IMAGE_X, 44);
    let mut c = h.client();
    assert!(c.generate(name(b"k"), host_policy()).unwrap().is_ok());
    assert_eq!(c.generate(name(b"k"), Policy { max_uses: 3, ..host_policy() }).unwrap(), Out::err(outcome::REFUSED));
    // A name with the volatile backend; no name with a deriving one.
    assert_eq!(c.generate(name(b"k"), volatile(wire::purpose::SIGN)).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(c.generate([0; 2], host_policy()).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    // Not a purpose, two purposes, not an envelope, not a backend.
    for p in [
        Policy { purpose: 0, ..host_policy() },
        Policy { purpose: 3, ..host_policy() },
        Policy { envelope: 2, ..host_policy() },
        Policy { backend: 4, ..host_policy() },
    ] {
        assert_eq!(c.generate(name(b"z"), p).unwrap(), Out::err(outcome::BAD_ARGUMENT), "{p:?}");
    }
    // An import is volatile.
    assert_eq!(c.import(host_policy(), [1; 4]).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    tidy();
}

/// **An image the loader did not measure has no image-bound key.**
///
/// **Canary.** Bind to a zero measurement: every unmeasured image shares one host key.
#[test]
fn an_unmeasured_image_cannot_have_an_image_bound_key() {
    let _g = serial();
    reset();
    let h = Holder::rw(7, [0; 32], 44);
    assert_eq!(h.client().generate(name(b"k"), host_policy()).unwrap(), Out::err(outcome::NOT_READY));
    let owner_wide = Policy { envelope: wire::envelope::OWNER, ..host_policy() };
    assert!(h.client().generate(name(b"k"), owner_wide).unwrap().is_ok());
    tidy();
}

// ── The console login ───────────────────────────────────────────────────────

const MAX_FAILS: usize = azos_limits::LOGIN_MAX_FAILURES;

/// The `login` records written after record number `mark`
/// (`azos_decision::total()` taken before), oldest first: `(verdict, session,
/// [method, attempt, reason])`. A count of the ring would stall once it is full.
fn login_records(mark: u64) -> Vec<(u8, u32, [u64; 3])> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::Login as u8 && r.seq > mark {
            v.push((r.verdict, r.subject, r.n));
        }
    });
    v
}

fn credential(b: u8) -> [u8; 32] {
    [b; 32]
}

fn cred_words(c: &[u8; 32]) -> [u64; 4] {
    words(c)
}

/// The verifier an administrator would list for `who`: the root of `SEED`, the
/// account's place in the table (`owner`), the credential.
fn verifier(owner: u32, who: &[u8], cred: &[u8; 32]) -> [u8; 32] {
    ks::login_public(&boot_root(), owner, &name_bytes(who), cred).unwrap()
}

fn account<'a>(who: &'a [u8], keys: &[[u8; 32]]) -> azos_topology::types::LoginSpec<'a> {
    let mut a = azos_topology::types::LoginSpec::empty();
    a.name = azos_topology::MaybeStr::from_bytes(who);
    a.keys[..keys.len()].copy_from_slice(keys);
    a.keys_len = keys.len() as u8;
    a
}

/// The table of the tests: alice (root 1) and bob (root 2), each with one
/// verifier; alice's second key is an ssh key, which no credential matches.
fn table() -> [azos_topology::types::LoginSpec<'static>; 2] {
    [
        account(b"alice", &[[0x11; 32], verifier(1, b"alice", &credential(0xA1))]),
        account(b"bob", &[verifier(2, b"bob", &credential(0xB2))]),
    ]
}

fn login(rows: &[azos_topology::types::LoginSpec<'_>], tid: u32, who: &[u8], cred: &[u8; 32]) -> Out<u32> {
    azos_sched::set_current_task_tid(tid);
    crate::keys::login_in(Some(rows), tid, &name(who), cred)
}

fn at_second(s: u64) {
    azos_drv_irqchip::clint::set_time(s * 10_000_000);
}

/// **The right credential admits the user, issues the user's root, and arms a
/// grant that is spent once; a wrong one is a durable refusal.** The root is the
/// row's place plus one, so bob is 2 whichever order the logins come in.
///
/// **Canary.** Return the root of the first row for every user: bob reads 1. Do
/// not write the record on a refusal: the last assertion is red. Leave the
/// grant armed after `take_login_grant`: the second take is `Some`.
#[test]
fn the_right_credential_admits_the_user_and_arms_one_grant() {
    let _g = serial();
    reset();
    at_second(100);
    let h = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, 0);
    let rows = table();
    let before = azos_decision::total();
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::ok(2));
    assert_eq!(crate::keys::take_login_grant(h.tid), Some(2));
    assert_eq!(crate::keys::take_login_grant(h.tid), None, "a grant starts one session");
    assert_eq!(login(&rows, h.tid, b"alice", &credential(0xA1)), Out::ok(1), "the verifier among an ssh key and itself");
    assert_eq!(crate::keys::take_login_grant(h.tid), Some(1));
    let r = login_records(before);
    assert_eq!(&r[..], &[(ADMIT, 2, [4, 0, 0]), (ADMIT, 1, [4, 0, 0])]);
    // Refused: durable, subject 0, reason 1 (wrong secret), attempt 1.
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB3)), Out::err(outcome::DENIED));
    assert_eq!(login_records(before).last().copied(), Some((REFUSE, 0, [4, 1, 1])));
    assert_eq!(crate::keys::take_login_grant(h.tid), None, "a refusal arms nothing");
    at_second(0);
    tidy();
}

/// **A credential is the user's own: another user's, another board's and an ssh
/// key's do not verify; an unknown name answers like a wrong credential.**
///
/// **Canary.** Leave the owner out of `login_public`'s info (crypto-tests holds
/// that too): alice's credential, listed for bob's row by an administrator who
/// computed it for owner 1, verifies for bob.
#[test]
fn a_credential_is_the_users_own() {
    let _g = serial();
    reset();
    let h = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, 0);
    // Listed for owner 1 and name alice, offered for bob (owner 2).
    let rows = [account(b"alice", &[verifier(1, b"alice", &credential(0xA1))]), account(b"bob", &[verifier(1, b"alice", &credential(0xA1))])];
    assert_eq!(login(&rows, h.tid, b"alice", &credential(0xA1)), Out::ok(1));
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xA1)), Out::err(outcome::DENIED), "a verifier is for one owner and one name");
    // An ssh key is not a credential.
    let ssh = [account(b"carol", &[[0x11; 32]])];
    assert_eq!(login(&ssh, h.tid, b"carol", &[0x11; 32]), Out::err(outcome::DENIED));
    // An unknown name: the same answer, the same record shape.
    let n = azos_decision::total();
    assert_eq!(login(&rows, h.tid, b"mallory", &credential(0xA1)), Out::err(outcome::DENIED));
    assert_eq!(login_records(n)[0], (REFUSE, 0, [4, 1, 1]));
    // No grant came out of any refusal.
    crate::keys::take_login_grant(h.tid);
    assert_eq!(crate::keys::take_login_grant(h.tid), None);
    tidy();
}

/// **Consecutive refusals lock the account for a while; a good credential
/// before the limit clears the count; names nobody listed share one counter.**
/// While locked even the right credential is refused, reason 2, without being
/// looked at; when the lock lapses the account is open again.
///
/// **Canary.** Count a success as a failure: the count never clears and the
/// "clears the count" half locks bob. Never lock: the locked half admits.
#[test]
fn consecutive_refusals_lock_the_account_for_a_while() {
    let _g = serial();
    reset();
    at_second(1000);
    let h = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, 0);
    let rows = table();
    for _ in 0..MAX_FAILS - 1 {
        assert_eq!(login(&rows, h.tid, b"bob", &credential(0)), Out::err(outcome::DENIED));
    }
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::ok(2), "one short of the limit, a good credential gets in");
    crate::keys::take_login_grant(h.tid);
    for _ in 0..MAX_FAILS - 1 {
        assert_eq!(login(&rows, h.tid, b"bob", &credential(0)), Out::err(outcome::DENIED), "and the count started again");
    }
    // One more refusal locks; alice is a different counter.
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0)), Out::err(outcome::DENIED));
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::err(outcome::DENIED), "locked: the right credential is refused");
    let (verdict, session, n) = login_records(0).last().copied().unwrap();
    assert_eq!((verdict, session, n[0], n[2]), (REFUSE, 0, 4, 2));
    assert_eq!(crate::keys::take_login_grant(h.tid), None);
    assert_eq!(login(&rows, h.tid, b"alice", &credential(0xA1)), Out::ok(1), "a lock is an account's own");
    crate::keys::take_login_grant(h.tid);
    // Just before the lock lapses, and at it.
    at_second(1000 + azos_limits::LOGIN_LOCKOUT_S as u64 - 1);
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::err(outcome::DENIED));
    at_second(1000 + azos_limits::LOGIN_LOCKOUT_S as u64);
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::ok(2));
    // Names nobody lists: one counter for all of them, and it does not touch a real account.
    crate::keys::take_login_grant(h.tid);
    for i in 0..MAX_FAILS {
        let nm = [b'x', b'a' + i as u8];
        assert_eq!(login(&rows, h.tid, &nm, &credential(0)), Out::err(outcome::DENIED));
    }
    let n = azos_decision::total();
    assert_eq!(login(&rows, h.tid, b"never-seen", &credential(0)), Out::err(outcome::DENIED));
    assert_eq!(login_records(n)[0].2[2], 2, "enumerating names runs into the lock");
    assert_eq!(login(&rows, h.tid, b"alice", &credential(0xA1)), Out::ok(1));
    at_second(0);
    tidy();
}

/// **The grant lapses, and a name or a credential that cannot be is refused
/// before it is counted.**
///
/// **Canary.** Forget the TTL: the late spawn finds the grant.
#[test]
fn the_grant_lapses_and_a_malformed_name_is_no_attempt() {
    let _g = serial();
    reset();
    at_second(50);
    let h = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, 0);
    let rows = table();
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::ok(2));
    at_second(50 + azos_limits::LOGIN_GRANT_TTL_S as u64 + 1);
    assert_eq!(crate::keys::take_login_grant(h.tid), None, "a stalled login service sits on nothing");
    at_second(50);
    let n = azos_decision::total();
    let mut bad = name(b"bob");
    bad[1] = 1; // a byte after the name's end
    for who in [bad, name(b"b/b"), name(b"bo b")] {
        azos_sched::set_current_task_tid(h.tid);
        assert_eq!(crate::keys::login_in(Some(&rows), h.tid, &who, &credential(0xB2)), Out::err(outcome::BAD_ARGUMENT));
    }
    assert!(login_records(n).is_empty(), "not an attempt: no record, no count");
    for _ in 0..MAX_FAILS {
        let _ = crate::keys::login_in(Some(&rows), h.tid, &bad, &credential(0));
    }
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::ok(2), "and no lock came of it");
    at_second(0);
    tidy();
}

/// **Nobody enrolled: the console session is the system's, recorded; once a
/// user is enrolled the empty name is refused. A board with no root verifies
/// nobody.**
///
/// **Canary.** Admit the empty name whatever the table holds: the second half
/// reads `Ok(0)`.
#[test]
fn nobody_enrolled_the_session_is_the_systems_and_no_root_no_login() {
    let _g = serial();
    reset();
    let h = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, 0);
    let n = azos_decision::total();
    assert_eq!(login(&[], h.tid, b"", &credential(0)), Out::ok(0));
    assert_eq!(crate::keys::take_login_grant(h.tid), Some(0), "root 0 is a grant like any other");
    assert_eq!(login_records(n)[0], (ADMIT, 0, [4, 0, 0]));
    assert_eq!(login(&[], h.tid, b"alice", &credential(0)), Out::err(outcome::DENIED), "nobody enrolled is nobody by name");
    let rows = table();
    assert_eq!(login(&rows, h.tid, b"", &credential(0)), Out::err(outcome::DENIED), "enrolled: the empty name is unknown");
    assert_eq!(crate::keys::take_login_grant(h.tid), None);
    // The root read above is kept; a board without one is a table that never read it.
    crate::keys::__keys_clear_for_tests();
    crate::link_key::set_link_key_read_hook(no_seed_hook);
    let n = azos_decision::total();
    assert_eq!(login(&rows, h.tid, b"bob", &credential(0xB2)), Out::err(outcome::NOT_READY));
    assert_eq!(login_records(n)[0], (REFUSE, 0, [4, 0, 4]));
    assert_eq!(crate::keys::take_login_grant(h.tid), None);
    tidy();
}

/// **No topology is not "nobody enrolled": the empty name, the system's own
/// session, is admitted only against a table that was read and lists no login.
/// With none loaded the call is `NOT_READY`, records a refusal (reason 5) and
/// arms nothing.**
///
/// **Canary.** Map `None` to the empty table in `login_in`'s caller (the old
/// `map_or(&[][..], ..)`): the first assertion reads `Ok(0)` and arms root 0.
#[test]
fn a_missing_topology_is_not_nobody_enrolled() {
    let _g = serial();
    reset();
    let h = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, 0);
    azos_sched::set_current_task_tid(h.tid);
    let n = azos_decision::total();
    assert_eq!(crate::keys::login_in(None, h.tid, &name(b""), &credential(0)), Out::err(outcome::NOT_READY));
    assert_eq!(login_records(n), vec![(REFUSE, 0, [4, 0, 5])], "a refusal, with its own reason");
    assert_eq!(crate::keys::take_login_grant(h.tid), None, "no grant for the system's root");
    assert_eq!(crate::keys::login_in(None, h.tid, &name(b"alice"), &credential(0xA1)), Out::err(outcome::NOT_READY), "no name is checked against a table nobody read");
    assert_eq!(crate::keys::take_login_grant(h.tid), None);
    // The same call against a table that was read and lists nobody is the open console.
    assert_eq!(login(&[], h.tid, b"", &credential(0)), Out::ok(0));
    assert_eq!(crate::keys::take_login_grant(h.tid), Some(0));
    tidy();
}

/// **Through the endpoint: `login` needs `EXEC`, and a holder whose mask lacks
/// it never reaches the interface; the verdict of the empty topology is the
/// system's session.**
///
/// **Canary.** Gate on `WRITE` instead: the read-write holder logs in.
#[test]
fn the_login_op_needs_exec_and_its_mask_bit() {
    let _g = serial();
    reset();
    // A topology is loaded (a missing one is `NOT_READY`, above) and the one
    // the tests share lists no login: nobody is enrolled.
    super::subtree_policy::topology();
    assert!(azos_topology::get().is_some_and(|t| t.logins().is_empty()));
    let rw = Holder::new(0, IMAGE_X, 44, CapPerms::READ.union(CapPerms::WRITE), 0);
    assert_eq!(rw.client().login(name(b""), cred_words(&credential(0))).unwrap(), Out::err(outcome::DENIED), "READ and WRITE are not EXEC");
    drop(rw);
    let signer = Holder::new(0, IMAGE_X, 44, CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::EXEC), SIGNER_OPS);
    assert!(signer.client().login(name(b""), cred_words(&credential(0))).is_err(), "the signer's mask has no login bit");
    drop(signer);
    let svc = Holder::new(0, IMAGE_X, 44, CapPerms::EXEC, wire::LOGIN_OPS);
    assert_eq!(svc.client().login(name(b""), cred_words(&credential(0))).unwrap(), Out::ok(0));
    assert_eq!(crate::keys::take_login_grant(svc.tid), Some(0));
    // And the service can do nothing else with `keys`.
    assert!(svc.client().generate(name(b"k"), host_policy()).is_err());
    tidy();
}
