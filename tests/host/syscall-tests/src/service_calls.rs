// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The service-registry syscalls, `SYS_SERVICE_REGISTER` (390), `_DISCOVER`
// (391), `_HEARTBEAT` (392) and `_STOP` (393). No test reached any of them:
// `abitest` calls `service_discover` only with a string libsys refuses before
// the ecall (see `IMAGE_PROFILES`' ABITEST row in `crates/core/sched/src/seccomp.rs`).
//
// The registry is the real `crates/core/service/src/lib.rs` (`shims/service` builds
// that file). It has no reset and holds 32 entries, so every test here uses
// names no other test uses.
//
// The last two tests were `#[ignore]`d findings (the handlers registered any
// TID and stopped any name). The owner checks landed 2026-09-27; they now run.

use super::harness::serial;
use azos_arch_api::PagePerms;

const A: u32 = 41;
const B: u32 = 42;
/// Where ring-3 names live. Clear of the other guard files.
const NAME_VA: usize = 0x0075_0000;
/// Never mapped by this file.
const UNMAPPED_VA: usize = 0x0076_0000;

/// Ring 3 with one page mapped at [`NAME_VA`]; returns its host pointer.
fn ring3(tid: u32) -> *mut u8 {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, NAME_VA, phys, PagePerms::USER_RW).expect("map");
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    phys as *mut u8
}

/// Put `bytes` at [`NAME_VA`] and return that VA.
fn name_at(page: *mut u8, bytes: &[u8]) -> u64 {
    unsafe {
        core::ptr::write_bytes(page, 0, 4096);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), page, bytes.len());
    }
    NAME_VA as u64
}

fn state_of(name: &[u8]) -> Option<(u32, u8, u32)> {
    let mut out = None;
    azos_service::service_list(|e| {
        let n = e.name.iter().position(|&b| b == 0).unwrap_or(e.name.len());
        if &e.name[..n] == name {
            out = Some((e.tid, e.state as u8, e.heartbeat));
        }
    });
    out
}

const RUNNING: u8 = azos_service::ServiceState::Running as u8;
const STOPPED: u8 = azos_service::ServiceState::Stopped as u8;

/// The four calls, as `(label, fn(name_ptr) -> rc)`.
fn every_call() -> [(&'static str, fn(u64) -> i64); 4] {
    [
        ("register", |p| super::sys_service_register(p, A as u64, 1)),
        ("discover", super::sys_service_discover),
        ("heartbeat", super::sys_service_heartbeat),
        ("stop", super::sys_service_stop_handler),
    ]
}

/// Round trip from ring 3: the name arrives trimmed at its NUL, `discover`
/// answers the registered TID, `heartbeat` counts, `stop` stops, and a second
/// `register` of a live name is refused.
#[test]
fn register_discover_heartbeat_stop_round_trip() {
    let _g = serial();
    let page = ring3(A);
    let p = name_at(page, b"t.round\0");
    assert_eq!(super::sys_service_register(p, A as u64, 9), 0);
    assert_eq!(state_of(b"t.round"), Some((A, RUNNING, 0)), "stored under another name");
    assert_eq!(super::sys_service_discover(p), A as i64);
    assert_eq!(super::sys_service_heartbeat(p), 0);
    assert_eq!(super::sys_service_heartbeat(p), 0);
    assert_eq!(state_of(b"t.round"), Some((A, RUNNING, 2)));
    assert_eq!(super::sys_service_register(p, A as u64, 9), -1, "a duplicate name registered");
    assert_eq!(super::sys_service_stop_handler(p), 0);
    assert_eq!(state_of(b"t.round"), Some((A, STOPPED, 2)));

    let q = name_at(page, b"t.never\0");
    assert_eq!(super::sys_service_discover(q), -1, "found a name never registered");
    assert_eq!(super::sys_service_heartbeat(q), -1);
    assert_eq!(super::sys_service_stop_handler(q), -1);
}

/// Refusal: a null name pointer, an unmapped one, and a name with no NUL in
/// the handler's 64-byte buffer are `-1` from all four calls, and none of them
/// registers anything.
#[test]
fn every_service_call_refuses_null_unmapped_and_unterminated_names() {
    let _g = serial();
    let page = ring3(A);
    let long = name_at(page, &[b'q'; 64]); // 64 bytes, then the page's zeroes
    for (label, call) in every_call() {
        assert_eq!(call(0), -1, "{label}: null");
        assert_eq!(call(UNMAPPED_VA as u64), -1, "{label}: unmapped");
        assert_eq!(call(long), -1, "{label}: 64 bytes without a NUL");
    }
    let mut n = 0;
    azos_service::service_list(|e| if e.name[0] == b'q' { n += 1 });
    assert_eq!(n, 0, "a refused register stored an entry");
}

/// A name that ends one byte short of the buffer is accepted: the bound is
/// the buffer, not something shorter.
#[test]
fn a_63_byte_name_is_accepted() {
    let _g = serial();
    let page = ring3(A);
    let mut n = [b'w'; 64];
    n[63] = 0;
    assert_eq!(super::sys_service_register(name_at(page, &n), A as u64, 1), 0);
}

/// FINDING — `SYS_SERVICE_REGISTER` takes the TID to register from `a1` and
/// never compares it with the caller. Task A registers a name that
/// `discover` then resolves to task B, which asked for nothing. What this
/// asserts is the refusal an authority check would give; today the call
/// answers `0` and the name points at B.
///
/// Reach: no `IMAGE_PROFILES` row lists 390..=393, so a filtered image is
/// refused at dispatch; kernel tasks (unrestricted) and the two audit-mode
/// rows (CAPTEST.ELF, ABITEST.ELF) reach the handler.
// Findings closed 2026-09-27 (owner decision round 7): these were `#[ignore]`
// while the handler registered any TID and stopped any name. The refusal is the
// handlers' `E_PERM` (-99), recorded as `SAFETY_SERVICE_REFUSED`; see also
// `service_authority.rs`.
#[test]
fn register_refuses_a_tid_that_is_not_the_caller() {
    let _g = serial();
    let page = ring3(A);
    let p = name_at(page, b"t.spoof\0");
    let rc = super::sys_service_register(p, B as u64, 1);
    assert_eq!(rc, -99, "A registered a service in B's name; discover now answers {}", super::sys_service_discover(p));
}

/// FINDING — `SYS_SERVICE_STOP` stops any service by name: B registers
/// itself, A stops it. Asserts the refusal an ownership check would give;
/// today A's call answers `0` and B's service is `Stopped`. Same reach as
/// the test above.
#[test]
fn stop_refuses_a_service_the_caller_did_not_register() {
    let _g = serial();
    let page = ring3(B);
    let p = name_at(page, b"t.victim\0");
    assert_eq!(super::sys_service_register(p, B as u64, 1), 0);
    azos_sched::set_current_task_tid(A);
    let rc = super::sys_service_stop_handler(p);
    assert_eq!(rc, -99, "A stopped B's service; its state is now {:?}", state_of(b"t.victim"));
}
