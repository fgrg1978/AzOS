// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `LinkKey` interface (U06-9, an endpoint op
// since D6 part A) -- `crates/core/syscall/src/link_key.rs::Server`.
//
// The server lives at THIS crate's root (`crate::link_key`, pulled in with
// `#[path]` by `lib.rs`, the same way `crate::motor_cmd` is: it names
// `crate::handlers::{E_CONTAINED, note_typed_denial_for}`, both `pub(crate)`,
// so it has to sit where `mod handlers` is a sibling rather than a parent).
// This file is included inside `mod handlers { .. }` in `lib.rs` like every
// other guard file in this crate, and reaches the server under test through
// the full path `crate::link_key::...`.
//
// Three outcomes: (a) a holder of `READ` reads the key; (b) a caller without
// `READ` is refused before the hook ran; (c) an absent or all-zero key is
// `NOT_READY` and no byte of it leaves. The node identity (`node_key`) needs
// `READ` like the other ops; what keeps the rows that only need it from the
// seed is the capability's op mask, tested end to end at the bottom (the
// resolve, `khost::admit`, the generated client).

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::{outcome, LinkKey, Out};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering};

/// TIDs no other file in this crate uses.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e00_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// How many times a hook ran.
static HOOK_CALLS: AtomicU32 = AtomicU32::new(0);

/// The known-good key `ok_hook` hands back.
const TEST_KEY: [u8; crate::link_key::LINK_KEY_BYTES] = [0x42; crate::link_key::LINK_KEY_BYTES];

fn ok_hook(out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    *out = TEST_KEY;
    true
}

fn absent_hook(_out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    false
}

fn server(rights: CapPerms) -> crate::link_key::Server {
    crate::link_key::Server(Caller { tid: fresh_tid(), badge: 0, rights })
}

/// The words of a key.
fn words(k: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(k[i * 8..i * 8 + 8].try_into().unwrap()))
}

/// (a) Pass: a holder of `READ` gets exactly the key the hook produced.
///
/// **Canary.** Return the words of an all-zero key: the equality fails.
#[test]
fn a_holder_of_read_reads_the_key() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(ok_hook);
    assert_eq!(server(CapPerms::READ).read(), Out::ok(words(&TEST_KEY)));
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1);
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (b) Refused: no `READ` (none, `WRITE`, `EXEC`). The reserved sector is
/// never read, and nothing of the key is in the answer.
///
/// **Canary.** Skip the `allows` check in `Server::read`: this reads the key.
#[test]
fn a_caller_without_read_is_refused_before_the_hook_runs() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(ok_hook);
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        assert_eq!(server(rights).read(), Out::err(outcome::DENIED), "{rights:?}");
    }
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 0, "a refused caller reached the sector");
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (c) A holder of `READ` with no key behind it: `NOT_READY`, the zero words.
/// Also with no hook installed (fails closed, like an absent key).
///
/// **Canary.** Answer `OK` when the hook says no: this reads OK.
#[test]
fn an_absent_key_or_no_hook_is_not_ready() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(absent_hook);
    assert_eq!(server(CapPerms::READ).read(), Out::err(outcome::NOT_READY));
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1);
    crate::link_key::__link_key_read_hook_clear_for_tests();
    assert_eq!(server(CapPerms::READ).read(), Out::err(outcome::NOT_READY), "no hook installed");
}

// ── The node identity (DICE-ID): `Server::node_key` ─────────────────────────

/// Put a task in a fresh Domain measured as `m` (all zeros: not measured);
/// the task's tid.
fn task_in_domain(m: [u8; 32]) -> u32 {
    let tid = fresh_tid();
    let key = azos_sched::domain::create().expect("a free Domain slot");
    azos_sched::domain::set_measurement(key, m);
    azos_sched::shim_bind_domain(tid, key);
    tid
}

fn node_server(tid: u32, rights: CapPerms) -> crate::link_key::Server {
    crate::link_key::Server(Caller { tid, badge: 0, rights })
}

/// (d) Pass: the caller gets `HKDF(seed, its own Domain's measurement)`, and a
/// task of another image on the same board gets another key. The seed itself
/// is never in the answer.
///
/// **Canary.** Derive from a constant measurement instead of the caller's: the
/// second key equals the first.
#[test]
fn node_key_is_the_callers_own_image_identity() {
    let _g = serial();
    crate::link_key::set_link_key_read_hook(ok_hook);
    let (ma, mb) = ([0xA1; 32], [0xB2; 32]);
    let (ta, tb) = (task_in_domain(ma), task_in_domain(mb));
    let a = node_server(ta, CapPerms::READ).node_key();
    let b = node_server(tb, CapPerms::READ).node_key();
    let want_a = azos_crypto::dice::node_static_key(&TEST_KEY, &ma).unwrap();
    assert_eq!(a, Out::ok(words(&want_a)));
    assert!(a.is_ok() && b.is_ok());
    assert_ne!(a.value, b.value, "two images shared a node key");
    assert_ne!(a.value, words(&TEST_KEY), "the seed itself crossed");
    assert_eq!(node_server(ta, CapPerms::READ).node_key(), a, "not stable across calls");
    azos_sched::shim_unbind_domains();
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (e) Refused: no `READ`; the seed is not read. `WRITE` and `EXEC` are not
/// enough: the identity is an observation, like every op of the interface.
///
/// **Canary.** Skip the `allows` check in `Server::node_key`, or check `WRITE`
/// instead of `READ`: the key is issued to a caller without `READ`.
#[test]
fn node_key_without_read_is_refused_before_the_seed_is_read() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(ok_hook);
    let t = task_in_domain([0xA1; 32]);
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC, CapPerms::WRITE.union(CapPerms::EXEC)] {
        assert_eq!(node_server(t, rights).node_key(), Out::err(outcome::DENIED), "{rights:?}");
    }
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 0);
    azos_sched::shim_unbind_domains();
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (f) No identity, `NOT_READY`: a task in no Domain, a Domain that was never
/// measured, and a board with no seed (or no hook).
///
/// **Canary.** Treat a zero measurement as a measurement: the unmeasured
/// Domain is issued the key every unmeasured image would share.
#[test]
fn node_key_needs_a_measured_domain_and_a_seed() {
    let _g = serial();
    crate::link_key::set_link_key_read_hook(ok_hook);
    assert_eq!(node_server(fresh_tid(), CapPerms::READ).node_key(), Out::err(outcome::NOT_READY), "no Domain");
    let unmeasured = task_in_domain([0; 32]);
    assert_eq!(node_server(unmeasured, CapPerms::READ).node_key(), Out::err(outcome::NOT_READY), "unmeasured");
    let measured = task_in_domain([0xA1; 32]);
    crate::link_key::set_link_key_read_hook(absent_hook);
    assert_eq!(node_server(measured, CapPerms::READ).node_key(), Out::err(outcome::NOT_READY), "no seed");
    crate::link_key::__link_key_read_hook_clear_for_tests();
    assert_eq!(node_server(measured, CapPerms::READ).node_key(), Out::err(outcome::NOT_READY), "no hook");
    azos_sched::shim_unbind_domains();
}

// ── The brain's pinned key: `Server::brain_pk` ──────────────────────────────

/// A caller without `READ` is refused before the topology is consulted.
///
/// **Canary.** Skip the `allows` check in `Server::brain_pk`: this reads
/// `NO_RESOURCE` (or a key), not `DENIED`.
#[test]
fn brain_pk_without_read_is_refused() {
    let _g = serial();
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        assert_eq!(server(rights).brain_pk(), Out::err(outcome::DENIED), "{rights:?}");
    }
}

/// With `READ` and no `[peer.brain]` row (no topology at all, or one without
/// the row: this crate's tests install none that has it) nothing is pinned:
/// `NO_RESOURCE`, which the client reads as `Noise_XX`, never as a failure.
/// The row itself is read by `Topology::brain_noise_pk`, pinned in
/// `tests/host/topology-tests`.
///
/// **Canary.** Answer `NOT_READY`: the client would treat "nothing pinned" as
/// a failed call and never run the link.
#[test]
fn brain_pk_with_no_brain_row_is_no_resource() {
    let _g = serial();
    assert_eq!(server(CapPerms::READ).brain_pk(), Out::err(outcome::NO_RESOURCE));
}

// ── The op mask: `READ` that reaches `node_key` and nothing else ───────────

use azos_devif::linkkey::NODE_KEY_OPS;
use azos_devif::{key, LinkKeyCall, LinkKeyClient, LinkKeyIdl};
use azos_idl::{IdlError, MsgDesc, Transport};
use std::sync::Mutex;

/// Cap-store pool slot for this file; no other file in this crate binds 57.
const SLOT: usize = 57;

/// `(kind code, reason code)` of every typed capability denial recorded.
static DENIALS: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn denials() -> Vec<(u8, u32)> {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

const ENDPOINT_CODE: u8 = azos_abi::cap::ty::ENDPOINT.denial_code();
const MISSING_PERMS: u32 = 3;

/// A task in a measured Domain holding one capability to the kernel-hosted
/// `linkkey`: what a topology row grants (`kernel_endpoint_cap_ops`, `ops` the
/// row's mask, 0 for none). Dropping it releases the task.
struct Holder {
    tid: u32,
    ep: u32,
}

impl Holder {
    fn new(perms: CapPerms, ops: u64) -> Holder {
        DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let tid = task_in_domain([0xA1; 32]);
        ipc_task_pool::shim_bind(tid, SLOT);
        azos_ipc::cap_store::reset(tid);
        azos_sched::set_current_task_tid(tid);
        set_cap_deny_typed_recorder(typed_recorder);
        let cap = azos_ipc::endpoint::kernel_endpoint_cap_ops(tid, perms, key::LINK_KEY, 0, ops).expect("grant");
        Holder { tid, ep: cap.raw().0 }
    }

    fn client(&self) -> LinkKeyClient<&Holder> {
        LinkKeyClient::new(self)
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        azos_ipc::cap::degraded_set(false);
        ipc_task_pool::shim_kill(self.tid);
        azos_sched::shim_unbind_domains();
        crate::link_key::__link_key_read_hook_clear_for_tests();
    }
}

/// The call as the syscall layer makes it: the endpoint resolves (any right,
/// containment aside), the call is admitted against the capability's op mask
/// from the request's header, the interface serves. A refusal at either step is
/// the syscall's own failure, which the client reads as a transport error.
impl Transport for &Holder {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        azos_ipc::endpoint::endpoint_resolve(self.tid, self.ep).map_err(|_| IdlError::Transport(-1))?;
        let who = crate::khost::admit(self.tid, self.ep, msg.words[0]).ok_or(IdlError::Transport(-1))?;
        let req = *msg;
        crate::khost::serve(key::LINK_KEY, &who, &req, msg);
        Ok(())
    }
}

/// **The mask of the identity rows reaches `node_key` and no other op.** The
/// capability is `READ` with an `OP_MASK` of `NODE_KEY_OPS`: `node_key` is
/// served (the caller's own key, never the seed); `read` (the raw seed) and
/// `brain_pk` are refused by the call before the interface runs, the sector is
/// never read for them, and each refusal is recorded as a capability denial.
///
/// **Canary.** Skip the mask in `khost::admit`: `read` returns the seed (the
/// first assertion). Make `kernel_hosted` resolve with `get_uncontained`
/// again: even `node_key` fails (the positive control).
#[test]
fn a_read_masked_to_node_key_reaches_node_key_and_not_the_seed() {
    let _g = serial();
    HOOK_CALLS.store(0, Ordering::SeqCst);
    crate::link_key::set_link_key_read_hook(ok_hook);
    let h = Holder::new(CapPerms::READ, NODE_KEY_OPS);
    let want = azos_crypto::dice::node_static_key(&TEST_KEY, &[0xA1; 32]).unwrap();

    assert_eq!(h.client().node_key().unwrap(), Out::ok(words(&want)));
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1, "node_key reads the seed in the kernel");
    assert!(denials().is_empty());

    assert!(h.client().read().is_err(), "the raw seed crossed a masked capability");
    assert!(h.client().brain_pk().is_err(), "an op outside the mask was served");
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1, "a refused op reached the sector");
    assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS); 2], "each refusal is recorded");
}

/// **The same right without the mask calls every op** (the positive control of
/// the test above, and what `brain_client` holds): `read` returns the seed,
/// `node_key` the identity, `brain_pk` answers.
///
/// **Canary.** Treat a capability with no mask as one with an empty mask: the
/// first assertion is red.
#[test]
fn a_read_without_a_mask_calls_every_op() {
    let _g = serial();
    crate::link_key::set_link_key_read_hook(ok_hook);
    let h = Holder::new(CapPerms::READ, 0);
    assert_eq!(h.client().read().unwrap(), Out::ok(words(&TEST_KEY)));
    assert!(h.client().node_key().unwrap().is_ok());
    assert_eq!(h.client().brain_pk().unwrap(), Out::err(outcome::NO_RESOURCE));
    assert!(denials().is_empty());
}

/// **Containment does not stop the identity.** The system is contained
/// (`degraded`): the acting class is refused everywhere, and `node_key` is an
/// observation, so a masked `READ` still gets its key, as an unmasked one
/// does. The mask does not widen anything either: `read` stays refused.
///
/// **Canary.** Gate `node_key` on `WRITE`: the first assertion is red.
#[test]
fn containment_does_not_block_node_key() {
    let _g = serial();
    crate::link_key::set_link_key_read_hook(ok_hook);
    let h = Holder::new(CapPerms::READ, NODE_KEY_OPS);
    azos_ipc::cap::degraded_set(true);
    let id = h.client().node_key();
    let seed = h.client().read();
    azos_ipc::cap::degraded_set(false);
    assert!(id.unwrap().is_ok(), "containment stopped the identity");
    assert!(seed.is_err());
}

/// **The mask is held to the interface's op table.** `NODE_KEY_OPS` is the
/// bit of the op named `node_key`, and neither `read` nor `brain_pk` shares it;
/// an op past bit 63 and op 0 are in no mask.
///
/// **Canary.** Move `node_key` in the trait without moving the constant: red.
#[test]
fn node_key_ops_name_node_key() {
    let bit = |name: &str| LinkKeyIdl::OPS.iter().find(|o| o.name == name).map(|o| 1u64 << o.op).expect("an op of that name");
    assert_eq!(NODE_KEY_OPS, bit("node_key"));
    assert_eq!(NODE_KEY_OPS & (bit("read") | bit("brain_pk")), 0);
    assert_eq!(NODE_KEY_OPS.count_ones(), 1);
}

/// **`admit` turns away an op the mask omits, whatever the op.** A header for
/// op 0, for the last op of the interface and for op 70 against a capability
/// that lists only `node_key`; the all-ones mask of an unmasked capability
/// admits them (the interface then answers `BadOp` for the unknown one).
///
/// **Canary.** Test `ops >> op & 1` with the op unbounded (`op >= 64` wraps):
/// op 70 reads as op 6 and, for a mask with that bit, is admitted.
#[test]
fn admit_refuses_every_op_outside_the_mask() {
    let _g = serial();
    let masked = Holder::new(CapPerms::READ, NODE_KEY_OPS | 1 << 6);
    let hdr = |op: u16| azos_idl::header(azos_devif::LINK_KEY_ID, 1, op);
    for op in [0u16, 1, 3, 5, 7, 64, 70, u16::MAX] {
        assert!(crate::khost::admit(masked.tid, masked.ep, hdr(op)).is_none(), "op {op}");
    }
    for op in [2u16, 6] {
        assert!(crate::khost::admit(masked.tid, masked.ep, hdr(op)).is_some(), "op {op}");
    }
    drop(masked);
    let open = Holder::new(CapPerms::READ, 0);
    for op in [0u16, 1, 3, 70] {
        assert!(crate::khost::admit(open.tid, open.ep, hdr(op)).is_some(), "op {op}");
    }
}
