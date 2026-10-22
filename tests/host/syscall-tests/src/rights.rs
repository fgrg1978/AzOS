// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Rights S3 at the syscall: `TRANSFER` is the right to give a capability to
// another Domain, `MAP` the right to have a region in an address space
// (`SYS_MO_MAP` of a `Cap<Shm>`; `READ` alone no longer maps).
//
// Driven through the pulled handlers as ring-3 callers with their own
// capability tables and real page tables, as `typed_ipc.rs` does; the last test
// audits the grants of the default topology, which is what the services'
// flows (the name server's lend, the introspection tool's map) stand on.
//
// A child module of `handlers` (`mod rights { use super::*; include!("rights.rs"); }`).

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::cap::{CapHandle, CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use azos_ipc::cap::targets::Shm;
use azos_ipc::cap::{Cap, CapError};
use azos_ipc::cap_store::{self, CapXfer};
use std::sync::atomic::{AtomicU32, Ordering};

/// Task-pool slots shared with `typed_ipc.rs`: the tests of this crate run one
/// at a time (`serial`) and each binds its callers afresh.
const SLOT_A: usize = 62;
const SLOT_B: usize = 63;
/// A page mapped user-RW in every caller's page table.
const BUF: usize = 0x0074_0000;

const VIEW: CapPerms = CapPerms::READ.union(CapPerms::MAP);

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7740_0001);

fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

fn errno(e: Errno) -> i64 {
    e.to_syscall_ret()
}

/// Puts back what a test here changes, panic or not.
struct Scene(Vec<u32>);

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::cap::degraded_set(false);
        azos_sched::set_current_user_pt(0);
        azos_sched::set_current_task_tid(0);
        azos_sched::set_current_proc_tid(0);
        for &t in &self.0 {
            azos_ipc::memobj::memobj_release_all(t);
            cap_store::reset(t);
        }
    }
}

/// `tid` as a ring-3 caller at `slot`: an empty table and a fresh page table.
fn ring3(tid: u32, slot: usize) -> usize {
    ipc_task_pool::shim_bind(tid, slot);
    cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, BUF, phys, PagePerms::USER_RW).expect("map");
    become_task(tid, pt);
    pt
}

fn become_task(tid: u32, pt: usize) {
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
}

fn handle(ret: i64) -> u64 {
    assert!(ret > 0, "expected a capability handle, got {ret}");
    ret as u64
}

fn cap(h: u64) -> Cap<Shm> {
    Cap::from_raw(CapHandle::from_raw(h as u32))
}

/// The packed reference `tid`'s capability `h` stores.
fn resource_of(tid: u32, h: u64) -> u32 {
    cap_store::get(tid, cap(h), CapPerms::NONE).expect("a live capability")
}

/// The rights `tid`'s capability `h` resolves with.
fn rights_of(tid: u32, h: u64) -> CapPerms {
    cap_store::with_table(tid, |t| t.peek_raw(CapHandle::from_raw(h as u32))).flatten().expect("a live capability").1
}

/// Grant `tid` a `Cap<Shm>` on `resource` straight into its table.
fn held(tid: u32, perms: CapPerms, resource: u32) -> u64 {
    cap_store::grant::<Shm>(tid, perms, resource).expect("cap table full").raw().as_raw() as u64
}

/// The references the region `r` holds in all.
fn shm_refs(r: u32) -> Option<u32> {
    azos_ipc::memobj::memobj_info(azos_ipc::cap::objref::SHM.idx(r)).map(|(_, refs, _)| refs)
}

fn writable(pt: usize, va: usize) -> bool {
    azos_mm::vmm::translate_user(pt, va, true).is_some()
}

/// `SYS_MO_MAP` of a region asks `READ` and `MAP`; `WRITE` decides the writable
/// bit and nothing else. A capability that reads and writes a region through
/// the kernel maps nothing, and a refused map leaves nothing behind.
///
/// **Canary.** Resolve the map with `READ` alone (`memobj_resolve_map`): the
/// two `ECAPPERMS` lines read a base address.
#[test]
fn a_region_maps_with_map_and_read_alone_maps_nothing() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene(vec![a, b]);
    let pt_a = ring3(a, SLOT_A);
    let pt_b = ring3(b, SLOT_B);
    become_task(a, pt_a);
    let rw = handle(sys_shm_create_typed(1, 1));
    let r = resource_of(a, rw);
    let creator = rights_of(a, rw);
    assert!(creator.contains(CapPerms::RW.union(CapPerms::MAP)), "the creator maps its own region: {creator:?}");
    assert!(creator.contains(CapPerms::DELEGATE), "and may share or gift it: {creator:?}");

    let no_map = held(b, CapPerms::RW, r);
    let map_no_read = held(b, CapPerms::WRITE.union(CapPerms::MAP), r);
    let view = held(b, VIEW, r);
    let full = held(b, CapPerms::RW.union(CapPerms::MAP), r);
    become_task(b, pt_b);
    let refs = shm_refs(r);
    assert_eq!(sys_shm_map_typed(no_map, 0), errno(Errno::ECAPPERMS), "READ and WRITE are no window");
    assert_eq!(sys_shm_map_typed(map_no_read, 0), errno(Errno::ECAPPERMS), "MAP without READ reads nothing");
    assert_eq!(shm_refs(r), refs, "a refused map took no reference");
    // The capability still reads the region through the kernel.
    assert_eq!(cap_store::get(b, cap(no_map), CapPerms::READ), Ok(r));

    let va = sys_shm_map_typed(view, 0);
    assert!(va > 0, "READ|MAP maps: {va}");
    assert!(!writable(pt_b, va as usize), "without WRITE the window is read-only");
    assert_eq!(sys_shm_release_typed(view), 0);
    let va = sys_shm_map_typed(full, 0);
    assert!(va > 0, "RW|MAP maps: {va}");
    assert!(writable(pt_b, va as usize), "with WRITE it is writable");
    assert_eq!(sys_shm_release_typed(full), 0);
}

/// A SHARE (a DUP entry of a message) hands over exactly the rights asked: a
/// receiver given `RW` can read and write the region through the kernel and has
/// no window; the same share with `MAP` has one.
#[test]
fn a_share_maps_only_if_the_rights_it_carries_include_map() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene(vec![a, b]);
    let pt_a = ring3(a, SLOT_A);
    let pt_b = ring3(b, SLOT_B);
    become_task(a, pt_a);
    let rw = handle(sys_shm_create_typed(1, 1));
    let share = |rights: CapPerms| -> u64 {
        let x = CapXfer { rights: Some(rights), ..CapXfer::new(CapHandle::from_raw(rw as u32), true) };
        let mut out = [CapHandle(0); 1];
        cap_store::move_caps(a, b, &[x], true, &mut out).expect("the share is made");
        out[0].as_raw() as u64
    };
    let blind = share(CapPerms::RW);
    let sighted = share(VIEW);
    assert_eq!(rights_of(b, blind), CapPerms::RW);
    assert_eq!(rights_of(b, sighted), VIEW);
    become_task(b, pt_b);
    assert_eq!(sys_shm_map_typed(blind, 0), errno(Errno::ECAPPERMS));
    let va = sys_shm_map_typed(sighted, 0);
    assert!(va > 0, "the share with MAP maps: {va}");
    assert_eq!(sys_shm_release_typed(sighted), 0);
}

/// Giving a region away needs `TRANSFER`; sharing it (a copy the sender keeps)
/// needs `TRANSFER` and `DUP`. `MAP` and `READ` give neither.
///
/// **Canary.** Make `move_locked` ask `DUP`: the `TRANSFER`-only and the
/// `DUP`-only rows swap their answers.
#[test]
fn a_region_capability_moves_with_transfer_and_is_shared_with_transfer_and_dup() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene(vec![a, b]);
    ring3(a, SLOT_A);
    ring3(b, SLOT_B);
    become_task(a, azos_sched::current_user_pt());
    let rw = handle(sys_shm_create_typed(1, 1));
    let r = resource_of(a, rw);
    let try_move = |perms: CapPerms| cap_store::move_cap(a, b, CapHandle::from_raw(held(a, perms, r) as u32), None);
    let try_share = |perms: CapPerms| {
        let x = CapXfer::new(CapHandle::from_raw(held(a, perms, r) as u32), true);
        cap_store::move_caps(a, b, &[x], true, &mut [CapHandle(0); 1]).map(|_| ())
    };
    let seen = CapPerms::RW.union(CapPerms::MAP);
    assert_eq!(try_move(seen), Err(CapError::MissingPerms), "READ, WRITE and MAP give nothing away");
    assert_eq!(try_move(seen.union(CapPerms::DUP)), Err(CapError::MissingPerms), "DUP is the right to copy");
    assert!(try_move(seen.union(CapPerms::TRANSFER)).is_ok(), "TRANSFER moves it");
    assert_eq!(try_share(seen.union(CapPerms::TRANSFER)), Err(CapError::MissingPerms), "a copy needs DUP too");
    assert_eq!(try_share(seen.union(CapPerms::DUP)), Err(CapError::MissingPerms), "a copy is a transfer too");
    assert!(try_share(seen.union(CapPerms::DELEGATE)).is_ok(), "both: shared");
    // The creator's own capability carries both, so the common flow (make a
    // region, hand it on) needs no extra grant.
    assert!(cap_store::move_cap(a, b, CapHandle::from_raw(rw as u32), None).is_ok(), "the creator may gift its region");
}

/// A socket the task opens is the creator's to give away or lend: `RW` and
/// `DELEGATE`. The abitest moves one to a server over the 582 exchange.
#[test]
fn the_creator_of_a_socket_may_give_it_away() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene(vec![a]);
    ipc_task_pool::shim_bind(a, SLOT_A);
    cap_store::reset(a);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(a);
    let raw = super::sys_socket_typed(
        azos_net::socket::AF_INET as u64,
        azos_net::socket::SOCK_DGRAM as u64,
        azos_net::socket::IPPROTO_UDP as u64,
    );
    assert!(raw > 0, "socket_typed returned {raw}");
    assert_eq!(rights_of(a, raw as u64), CapPerms::RW_DELEGATE);
    assert_eq!(super::sys_close_typed(raw as u64), 0);
}

/// The grants of the default topology, audited against the flows that stand on
/// them: a row says `transfer = true` only on the call right of the endpoint it
/// lends (a name server's `term`, the RPC server's `decisions`), or on the one
/// grant of its own endpoint a server both serves and lends from (the input
/// server's `input`, the compositor's `compositor`: `READ|WRITE`), and that grant
/// carries `TRANSFER` and `DUP` (a lend is a DUP entry); every introspection
/// region is `READ|MAP` and nothing else (the tool maps it, and cannot write it
/// or hand it on), and the terminal server's two (`input.events`,
/// `console.screen`) are `READ|WRITE|MAP`, its alone but for the input server's
/// `input.events` (its own ring of the same object); nothing else in a built-in
/// row says `TRANSFER`, `DUP` or `MAP`.
///
/// **Canary.** Make `CapSpec::grant_perms` ignore `transfer`: the lend rows (when
/// the build has them) read `WRITE` alone and the synthetic row below goes red.
/// Drop `transfer` from `COMPOSITOR_SERVE` (builder.rs): one serving row of the
/// two this build carries lends from its own endpoint.
#[test]
fn the_default_topology_hands_each_row_the_rights_its_flows_need() {
    use azos_topology::{CapSpec, MaybeStr};
    let topo = azos_topology::default_minimal();
    let lent: &[&[u8]] = &[b"endpoint.term", b"endpoint.decisions", b"endpoint.input", b"endpoint.compositor", b"endpoint.audio"];
    // The servers whose one grant of their own endpoint both serves (`READ`)
    // and is the call right their badged rights are derived from and lent
    // (`builder.rs` `INPUT_SERVE`, `COMPOSITOR_SERVE`).
    let serve_and_lend: &[(&str, &[u8])] = &[("INPUTD.ELF", b"endpoint.input"), ("COMPSRV.ELF", b"endpoint.compositor")];
    let (mut transfers, mut regions, mut serving) = (0, 0, 0);
    for task in topo.tasks() {
        for c in topo.caps_of(task) {
            let who = (task.name.as_str(), c.target.as_str());
            let given = c.grant_perms();
            assert!(
                !c.perms.contains(CapPerms::DUP) && !c.perms.contains(CapPerms::TRANSFER),
                "{who:?}: a row gets DUP and TRANSFER from `transfer = true`, not from its letters"
            );
            if c.transfer {
                transfers += 1;
                // A serving server's grant is its own endpoint: `READ` claims it,
                // the call right (with `DUP` and `TRANSFER`) is what its badged
                // rights are derived from; no other row serves and lends at once.
                let own = serve_and_lend.contains(&(task.name.as_str(), c.target.as_bytes()));
                serving += own as usize;
                let call = if own { CapPerms::READ.union(CapPerms::WRITE) } else { CapPerms::WRITE };
                assert_eq!((c.kind, c.perms), (CapKind::Endpoint, call), "{who:?}: only a call right is lent");
                assert!(lent.contains(&c.target.as_bytes()), "{who:?}: not on the audited list of lent endpoints");
                assert_eq!(given, call.union(CapPerms::DELEGATE), "{who:?}: lent = call + DUP + TRANSFER");
            } else {
                assert_eq!(given, c.perms, "{who:?}: no transfer, no extra right");
            }
            if c.kind == CapKind::MemObj {
                regions += 1;
                // The terminal server's two regions are the only ones a task
                // writes (the ring's tail, the screen's overlay words).
                let rw = matches!(c.target.as_bytes(), b"input.events" | b"console.screen");
                let want = if rw { VIEW.union(CapPerms::WRITE) } else { VIEW };
                assert_eq!((given, c.transfer), (want, false), "{who:?}: a region is mapped and read (and written only by the terminal server's two), nothing more");
                // The input server writes the tail of its own ring of the events region.
                assert!(
                    !rw || matches!(task.name.as_str(), "TERMD.ELF" | "INPUTD.ELF"),
                    "{who:?}: only the terminal server and the input server hold a writable region"
                );
            } else {
                assert!(!given.contains(CapPerms::MAP), "{who:?}: MAP is for memory objects");
            }
        }
    }
    eprintln!("rights audit: {transfers} lend rows, {regions} region rows in the default topology of this build");
    // Each server's row of this build lends from its grant: one that lost
    // `transfer` would read no extra right above and still pass.
    let want = azos_topology::builder::INPUTD_ROW as usize + azos_topology::builder::COMPOSITOR_ROW as usize;
    assert_eq!(serving, want, "a serving server's row in this build does not lend from its own endpoint");
    // The same rule on a row of our own, so the check holds in a build whose
    // default topology has no lend row.
    let lend = CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::WRITE,
        target: MaybeStr::from_bytes(b"endpoint.term"),
        transfer: true, ops: 0,
    };
    assert_eq!(lend.grant_perms(), CapPerms::WRITE.union(CapPerms::DELEGATE));
    assert_eq!(CapSpec { transfer: false, ..lend }.grant_perms(), CapPerms::WRITE);
}

/// The letters of a row's `perm` carry `TRANSFER` (`t`) and `MAP` (`m`) through
/// the parser and the emitter that writes the signed file: a row that lost a
/// letter on the way to a board would lose that right silently.
///
/// **Canary.** Drop `(CapPerms::MAP, b'm')` from `perm_letters` (emit.rs): the
/// emitted file says `r` and the second parse reads no `MAP`.
#[test]
fn the_perm_letters_of_transfer_and_map_survive_parse_and_emit() {
    use azos_topology::emit::{emit_caps, emit_sched};
    use azos_topology::{parse_caps, parse_sched, Binding, Topology};
    let sched = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";
    let caps = "format = 7\n[task.T.ELF]\ncaps = [\n\
        { kind = \"memobj\", target = \"inspect.public\", perm = \"rm\" },\n\
        { kind = \"endpoint\", target = \"endpoint.x\", perm = \"wdt\" },\n\
        { kind = \"endpoint\", target = \"endpoint.y\", perm = \"w\", transfer = true },\n]\n";
    let want = [VIEW, CapPerms::WRITE.union(CapPerms::DELEGATE), CapPerms::WRITE];
    fn parse<'a>(sched: &'a str, caps: &'a str) -> Box<Topology<'a>> {
        let mut t = Box::new(Topology::empty());
        parse_sched(sched.as_bytes(), &mut t).expect("SCHED");
        parse_caps(caps.as_bytes(), &mut t).expect("CAPS");
        t
    }
    let first = parse(sched, caps);
    let row = |t: &Topology<'_>| t.caps_of(&t.tasks()[0]).iter().map(|c| (c.perms, c.grant_perms())).collect::<Vec<_>>();
    let given = row(&first);
    assert_eq!(given.iter().map(|g| g.0).collect::<Vec<_>>(), want, "the letters parse");
    assert_eq!(given[2].1, CapPerms::WRITE.union(CapPerms::DELEGATE), "and `transfer = true` adds DELEGATE");
    let (mut s2, mut c2) = (String::new(), String::new());
    emit_sched(&first, &mut s2).expect("emit SCHED");
    emit_caps(&first, &Binding::default(), &mut c2).expect("emit CAPS");
    let back = parse(&s2, &c2);
    assert_eq!(row(&back), given, "the emitted file reads back the same rights:\n{c2}");
}
