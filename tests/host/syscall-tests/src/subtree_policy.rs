// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// SUBTREE-POLICY: the enforcement point and the topology-row-to-limits mapping,
// through the shipping code. `families::creation_gate` is called by the three
// creation handlers (`sys_endpoint_create_typed`, `sys_port_create_typed`,
// `sys_shm_create_typed`), `families::install_policy` turns the installed
// topology's `[policy.NAME]` rows into the limits of a Domain. The Domain table
// is the real `crates/core/sched/src/domain.rs` (the sched shim pulls it); the
// topology is the real one, installed once for this process from the rows below.
//
// A test of `domain.rs` alone (tests/host/sched-wake-tests/src/subtree_policy.rs)
// passes against a handler with no gate at all; every test here goes through
// the handler, so it does not.
//
// **Canary.** `subtree-gate-canary` makes `creation_gate` allow everything: the
// handler tests below go red (the host row names
// `the_creation_handlers_refuse_what_the_policy_forbids`).

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::error::Errno;
use azos_abi::syscall_nr::{SHM_CREATE_CLONE, SHM_CREATE_SRC_SHIFT};
use azos_decision::{Rule, Verdict};
use azos_sched::domain::{self, Create, Key};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Once;

/// The task-pool slot the callers here are bound to; no other file binds it.
const SLOT: usize = 45;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7840_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

fn eacces() -> i64 {
    Errno::EACCES.to_syscall_ret()
}

const SCHED: &str = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";

/// Also the motor tests' topology (`motor_guards`): wheel 0 has a device row
/// with a ring-3 driver whose call budget is 900 us, a commit time, a
/// `brake` safe state (which the kernel cannot drive lock-free) and a `stop`
/// inverse; wheel 1 has none.
///
/// Four rows: `JOBS.ELF` holds a `self` row (no ports) and a `subtree` row (no
/// endpoints), so both are narrowed together on it; `CAPPED.ELF` holds a
/// `subtree` ceiling of 4 pages; `PLAIN.ELF` holds none.
const CAPS: &str = "format = 7\n\
[task.JOBS.ELF]\ncaps = []\n\
[task.CAPPED.ELF]\ncaps = []\n\
[task.PLAIN.ELF]\ncaps = []\n\
[task.MOTORDRV.ELF]\ncaps = []\nplace = \"ring3\"\ncall_budget_us = 900\n\
[device.motor.0]\nmatch = \"dt:azos,motor0\"\ndriver = \"MOTORDRV.ELF\"\nsafe_state = \"brake\"\ncommit_ns = 400000\ncompensate = \"stop\"\n\
[policy.jobsself]\ndomain = \"JOBS.ELF\"\ncreate_ports = false\n\
[policy.jobstree]\ndomain = \"JOBS.ELF\"\nscope = \"subtree\"\ncreate_endpoints = false\n\
[policy.capped]\ndomain = \"CAPPED.ELF\"\nscope = \"subtree\"\nmemobj_max_pages = 4\n";

/// Install the topology above, once for the process (the slot is write-once).
pub(super) fn topology() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        azos_topology::init_with(|t| {
            azos_topology::parse_sched(SCHED.as_bytes(), t).expect("SCHED");
            azos_topology::parse_caps(CAPS.as_bytes(), t).expect("CAPS");
        })
        .expect("the test topology is admitted");
    });
}

/// What a test made: Domains, and the tasks that created ports and MemObjs in
/// them. Dropped when the test is done (a panic included): the tasks' ports,
/// MemObjs and capabilities go, the Domains end in reverse order, so the next
/// test finds the tables whole.
#[derive(Default)]
struct Scene {
    doms: Vec<Key>,
    tids: Vec<u32>,
}

impl Scene {
    fn root(&mut self) -> Key {
        let k = domain::create().expect("a free Domain slot");
        self.doms.push(k);
        k
    }
    fn child(&mut self, parent: Key) -> Key {
        let k = domain::create_child(parent).expect("a free Domain slot");
        self.doms.push(k);
        k
    }

    /// Make a fresh task the calling one: a ring-3 task with an empty
    /// capability table, in the Domain `dom` (`None`: in no Domain, as a
    /// kernel task).
    fn task_in(&mut self, dom: Option<Key>) {
        let tid = fresh_tid();
        self.tids.push(tid);
        ipc_task_pool::shim_bind(tid, SLOT);
        azos_ipc::cap_store::reset(tid);
        azos_sched::set_current_user_pt(0xBAD0_0000);
        azos_sched::set_current_task_tid(tid);
        azos_sched::set_current_proc_tid(tid);
        match dom {
            Some(k) => azos_sched::shim_bind_domain(tid, k),
            None => azos_sched::shim_unbind_domains(),
        }
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_sched::set_current_user_pt(0);
        azos_sched::set_current_task_tid(0);
        azos_sched::set_current_proc_tid(0);
        azos_sched::shim_unbind_domains();
        for &t in &self.tids {
            azos_ipc::port::port_release_all(t);
            azos_ipc::memobj::memobj_release_all(t);
            azos_ipc::cap_store::reset(t);
        }
        for &k in self.doms.iter().rev() {
            domain::leave(k);
        }
    }
}

/// The `subtree-policy` records written for the Domain `subject`, oldest first.
fn records_for(subject: Key) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::SubtreePolicy as u8 && r.subject == subject {
            v.push(*r);
        }
    });
    v
}

/// What `Domain` `d` is refused when it asks for `what`: the depth of the
/// Domain whose words refused it, and whose they are.
fn refused(d: Key, what: Create) -> Option<(u8, Key)> {
    domain::refusal(d, what).map(|r| (r.depth, r.policy))
}

#[test]
fn the_ring_is_live_in_this_suite() {
    // The ring is process-global and the count is read before and after: a
    // record written by a test running beside this one moved it by 2 (5 runs
    // of 1000 failed here).
    let _g = serial();
    let before = azos_decision::total();
    azos_decision::record(Rule::SubtreePolicy, Verdict::Refuse, 0xD0_0001, [0; 3]);
    assert_eq!(azos_decision::total(), before + 1, "decision `on` is not enabled: the record tests would be vacuous");
}

/// **The rows of a task row become the limits of its Domain: a `self` row binds
/// that Domain only, a `subtree` row binds it and every Domain beneath it, and
/// the rows of one task row are narrowed together.** `JOBS.ELF` forbids ports to
/// itself and endpoints to itself and below.
///
/// **Canary.** Install a `self` row as a `subtree` one: the child is refused
/// ports. Drop the `subtree` row: the child is allowed endpoints. Install
/// nothing: every line that expects a refusal fails.
#[test]
fn install_policy_binds_the_rows_of_a_task_row_with_their_reach() {
    let _g = serial();
    topology();
    let mut doms = Scene::default();

    let jobs = doms.root();
    crate::families::install_policy(jobs, "JOBS.ELF");
    let kid = doms.child(jobs);
    let grandkid = doms.child(kid);
    assert_eq!(refused(jobs, Create::Port), Some((0, jobs)), "its own `self` row");
    assert_eq!(refused(jobs, Create::Endpoint), Some((0, jobs)), "its `subtree` row binds it too");
    assert_eq!(refused(jobs, Create::MemObj(1 << 20)), None, "nothing says a word on MemObjs");
    assert_eq!(refused(kid, Create::Endpoint), Some((1, jobs)), "the `subtree` row, one level down");
    assert_eq!(refused(grandkid, Create::Endpoint), Some((2, jobs)), "and two");
    assert_eq!(refused(kid, Create::Port), None, "a `self` row does not reach a child");
    assert_eq!(refused(grandkid, Create::Port), None);

    let capped = doms.root();
    crate::families::install_policy(capped, "CAPPED.ELF");
    let under = doms.child(capped);
    for d in [capped, under] {
        assert_eq!(refused(d, Create::MemObj(4)), None, "at the ceiling");
        assert!(refused(d, Create::MemObj(5)).is_some(), "above it");
        assert!(refused(d, Create::MemObj(u32::MAX)).is_some(), "a size that is not stated");
        assert_eq!(refused(d, Create::Endpoint), None);
        assert_eq!(refused(d, Create::Port), None);
    }

    // A row nothing refers to, and a name no row has, bind nothing.
    for row in ["PLAIN.ELF", "NOSUCH.ELF", ""] {
        let d = doms.root();
        crate::families::install_policy(d, row);
        for what in [Create::Endpoint, Create::Port, Create::MemObj(u32::MAX)] {
            assert_eq!(refused(d, what), None, "row {row:?}");
        }
    }
}

/// **A new image replaces what the previous one's rows bound, and nothing an
/// ancestor or the floor imposes.** `install_policy` on a Domain that already
/// has rows (a Linux `execve` into another row would be that) leaves it bound by
/// the new row only; its parent's `subtree` row and the limits folded into its
/// floor stay.
///
/// **Canary.** Make `set_policy` keep the old words: the replaced `self` row
/// still refuses ports. Make it clear the floor too: the deep Domain is allowed
/// endpoints after the second install.
#[test]
fn a_second_install_replaces_its_own_rows_but_not_an_ancestors_or_the_floor() {
    let _g = serial();
    topology();
    let mut doms = Scene::default();

    let jobs = doms.root();
    crate::families::install_policy(jobs, "JOBS.ELF");
    let c = doms.child(jobs);
    crate::families::install_policy(c, "JOBS.ELF");
    assert_eq!(refused(c, Create::Port), Some((0, c)), "bound by its own `self` row");
    crate::families::install_policy(c, "CAPPED.ELF");
    assert_eq!(refused(c, Create::Port), None, "the old image's `self` row is gone");
    assert!(refused(c, Create::MemObj(5)).is_some(), "the new image's row binds");
    assert_eq!(refused(c, Create::Endpoint), Some((1, jobs)), "the parent's `subtree` row still does");
    crate::families::install_policy(c, "PLAIN.ELF");
    assert_eq!(refused(c, Create::MemObj(5)), None, "a row-less image is bound by its ancestors only");
    assert_eq!(refused(c, Create::Endpoint), Some((1, jobs)));

    // Past `WALK_MAX` levels the ancestor's words live in the floor, which a
    // new image does not shed.
    let top = doms.root();
    crate::families::install_policy(top, "JOBS.ELF");
    let mut deep = top;
    for _ in 0..domain::WALK_MAX + 2 {
        deep = doms.child(deep);
    }
    assert!(refused(deep, Create::Endpoint).is_some(), "the subtree row holds {} levels down", domain::WALK_MAX + 2);
    crate::families::install_policy(deep, "PLAIN.ELF");
    assert!(refused(deep, Create::Endpoint).is_some(), "a new image does not shed the floor");
}

/// **The three creation handlers answer `-EACCES` when the calling task's
/// Domain, or an ancestor's `subtree` row, forbids the creation, and create it
/// otherwise.** A handler without the gate passes every other test of the
/// policy; this is the one that fails it.
///
/// `JOBS.ELF`: no ports for itself, no endpoints for it and below. `CAPPED.ELF`:
/// no MemObj above 4 pages for it and below, a clone that does not say its size
/// asked as the largest. A task in no Domain (a kernel task) is never refused.
///
/// **Canary.** `subtree-gate-canary` (`creation_gate` allows all): every
/// refusal line reads a capability handle.
#[test]
fn the_creation_handlers_refuse_what_the_policy_forbids() {
    let _g = serial();
    topology();
    let mut doms = Scene::default();

    // Endpoints and ports.
    let jobs = doms.root();
    crate::families::install_policy(jobs, "JOBS.ELF");
    let kid = doms.child(jobs);

    doms.task_in(Some(jobs));
    assert_eq!(sys_port_create_typed(), eacces(), "the `self` row, at the Domain itself");
    assert_eq!(sys_endpoint_create_typed(), eacces(), "the `subtree` row binds the Domain itself");

    doms.task_in(Some(kid));
    assert!(sys_port_create_typed() > 0, "a child is not bound by the parent's `self` row");
    assert_eq!(sys_endpoint_create_typed(), eacces(), "a child is by its `subtree` row");

    doms.task_in(None);
    assert!(sys_port_create_typed() > 0, "a task in no Domain");
    assert!(sys_endpoint_create_typed() > 0, "a task in no Domain");

    // MemObjs.
    let capped = doms.root();
    crate::families::install_policy(capped, "CAPPED.ELF");
    let under = doms.child(capped);
    for (label, dom) in [("the Domain", capped), ("a child", under)] {
        doms.task_in(Some(dom));
        let small = sys_shm_create_typed(2, 1);
        assert!(small > 0, "{label}: 2 pages, {small}");
        assert!(sys_shm_create_typed(4, 1) > 0, "{label}: at the ceiling");
        assert_eq!(sys_shm_create_typed(5, 1), eacces(), "{label}: above it");
        let clone = |pages: u64| sys_shm_create_typed(pages, 1 | SHM_CREATE_CLONE | ((small as u64) << SHM_CREATE_SRC_SHIFT));
        assert_eq!(clone(0), eacces(), "{label}: a clone that does not state its size is the largest object");
        assert!(clone(2) > 0, "{label}: a clone that states a size within the ceiling");
    }
    doms.task_in(None);
    assert!(sys_shm_create_typed(64, 1) > 0, "a task in no Domain is not capped");
}

/// **A refusal leaves a `subtree-policy` record naming the Domain whose limit
/// refused (`policy`), how far above the actor it is (`depth`) and the creation
/// (`action`); an allowed creation leaves none.**
///
/// **Canary.** Delete the `record` in `domain::check_create`: the refusal reads
/// no record. Record on every check: the allowed creation reads one.
#[test]
fn a_refused_creation_is_recorded_and_an_allowed_one_is_not() {
    let _g = serial();
    topology();
    let mut doms = Scene::default();

    let jobs = doms.root();
    crate::families::install_policy(jobs, "JOBS.ELF");
    let kid = doms.child(jobs);
    doms.task_in(Some(kid));

    assert!(sys_port_create_typed() > 0);
    assert!(records_for(kid).is_empty(), "an allowed creation is not a refusal");
    assert_eq!(sys_endpoint_create_typed(), eacces());
    let rs = records_for(kid);
    assert_eq!(rs.len(), 1, "one record per refusal");
    assert_eq!(rs[0].verdict, Verdict::Refuse as u8);
    assert_eq!(rs[0].n, [u64::from(jobs), 1, Create::Endpoint.action()], "whose limit, how far above, what");
}
