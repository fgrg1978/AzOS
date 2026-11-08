// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_CAP_INFO` `CAP_INFO_ENDPOINT` (`crates/core/syscall/src/named_cap.rs`,
// pulled in with `#[path]`): a task's right found by the endpoint it names,
// over the real capability tables, endpoint registry and topology slot
// (`HOGATE.ELF` in `subtree_policy`'s topology grants call rights with the
// same rights on `endpoint.ho_login` and `endpoint.ho_term`).

use super::harness::serial;
use crate::named_cap::lookup;
use azos_abi::cap::{ty, CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_ipc::cap_store;
use azos_ipc::endpoint::{destroy_ref, endpoint_named_cap};

const SLOT_GATE: usize = 38;
const SLOT_POOL: usize = 39;
const GATE: u32 = 6711;
const POOL: u32 = 6712;
const LEND: CapPerms = CapPerms::WRITE.union(CapPerms::DELEGATE);

fn row(name: &[u8]) -> Option<usize> {
    azos_topology::get()?.tasks().iter().position(|r| r.name.as_bytes() == name)
}

fn bind() {
    super::subtree_policy::topology();
    for (tid, slot) in [(GATE, SLOT_GATE), (POOL, SLOT_POOL)] {
        ipc_task_pool::shim_bind(tid, slot);
        cap_store::reset(tid);
    }
    azos_ipc::cap::senders::set_hooks(azos_ipc::endpoint::sender_delta, azos_ipc::endpoint::flush_notices);
}

/// The right `tid` holds under `h`: the endpoint's packed reference.
fn resource(tid: u32, h: CapHandle) -> u32 {
    cap_store::read_table(tid, |t| t.peek_raw(h).map(|(_, _, r)| r)).flatten().unwrap()
}

/// Grant `GATE` a call right with the same rights on each of `names`, in
/// that order; the handles.
fn grant(names: &[&[u8]]) -> Vec<CapHandle> {
    names.iter().map(|n| endpoint_named_cap(GATE, LEND, n).expect("a call right").raw()).collect()
}

fn done(hs: &[CapHandle]) {
    for &h in hs {
        let _ = destroy_ref(resource(GATE, h));
    }
    cap_store::reset(GATE);
    cap_store::reset(POOL);
}

/// **A right is found by the endpoint it names, not by its rights or its
/// order.** Two call rights with the same rights (WRITE, DUP, TRANSFER) on
/// `ho_login` and `ho_term`, granted in either order: each lookup answers the
/// one on its own endpoint (the login right with `transfer` is no longer the
/// one a rights test mistakes for the job's source).
///
/// **Canary.** Make `held` skip the `ref_is_named` test: whichever right is
/// first answers both names, and one order goes red.
#[test]
fn a_right_is_found_by_its_endpoint_whatever_the_order_or_the_rights() {
    let _g = serial();
    bind();
    let gate = row(b"HOGATE.ELF");
    for order in [[&b"ho_login"[..], b"ho_term"], [b"ho_term", b"ho_login"]] {
        let hs = grant(&order);
        let want = |n: &[u8]| hs[order.iter().position(|o| *o == n).unwrap()];
        let call = CapPerms::WRITE;
        assert_eq!(lookup(GATE, gate, b"ho_login", call, CapPerms::READ), Ok(want(b"ho_login")), "{order:?}");
        assert_eq!(lookup(GATE, gate, b"ho_term", call.union(CapPerms::DUP), CapPerms::READ), Ok(want(b"ho_term")), "{order:?}");
        done(&hs);
    }
}

/// **A right the row grants and the task does not hold fails closed**
/// (`ECAPSTALE`), told apart from a right the row does not grant (`ENOENT`):
/// the terminal server locks its console on the first and opens it on the
/// second. A right that does not fit the rights asked for is not granted.
///
/// **Canary.** Make `lookup` answer `ENOENT` for every right not held: the
/// granted-and-missing assertion goes red.
#[test]
fn a_granted_right_not_held_is_told_from_one_not_granted() {
    let _g = serial();
    bind();
    let (gate, plain) = (row(b"HOGATE.ELF"), row(b"PLAIN.ELF"));
    assert!(gate.is_some() && plain.is_some());
    assert_eq!(lookup(GATE, gate, b"ho_login", CapPerms::WRITE, CapPerms::READ), Err(Errno::ECAPSTALE));
    assert_eq!(lookup(GATE, plain, b"ho_login", CapPerms::WRITE, CapPerms::READ), Err(Errno::ENOENT));
    assert_eq!(lookup(GATE, None, b"ho_login", CapPerms::WRITE, CapPerms::READ), Err(Errno::ENOENT));
    assert_eq!(lookup(GATE, gate, b"ho_login", CapPerms::READ, CapPerms::NONE), Err(Errno::ENOENT), "the row grants no READ on it");
    done(&[]);
}

/// The endpoints a test made, destroyed when it ends (a panic included), so
/// the pool is whole for the next test.
struct Made(Vec<u32>);

impl Drop for Made {
    fn drop(&mut self) {
        for &r in &self.0 {
            let _ = destroy_ref(r);
        }
        cap_store::reset(GATE);
        cap_store::reset(POOL);
    }
}

/// **No bound on where the pool put an endpoint**: a right on an endpoint
/// past index 15 (the old scan's end) is found.
///
/// **Canary.** Make `held` look only at endpoints below index 16: the right is
/// not found and this goes red.
#[test]
fn a_right_on_an_endpoint_past_index_15_is_found() {
    let _g = serial();
    bind();
    let mut made = Made(Vec::new());
    // Fill the pool's low indices (what the suite's other tests left in use
    // counts), until the next endpoint would land past 15.
    for i in 0.. {
        let c = endpoint_named_cap(POOL, CapPerms::WRITE, format!("hopad{i:02}").as_bytes()).expect("a free endpoint");
        let r = resource(POOL, c.raw());
        if azos_ipc::cap::objref::idx(ty::ENDPOINT, r) > 15 {
            let _ = destroy_ref(r);
            break;
        }
        made.0.push(r);
    }
    let hs = grant(&[b"ho_login"]);
    let r = resource(GATE, hs[0]);
    made.0.push(r);
    assert!(azos_ipc::cap::objref::idx(ty::ENDPOINT, r) > 15, "the login endpoint is not past index 15 (index {})", azos_ipc::cap::objref::idx(ty::ENDPOINT, r));
    assert_eq!(lookup(GATE, row(b"HOGATE.ELF"), b"ho_login", CapPerms::WRITE, CapPerms::READ), Ok(hs[0]));
}
