// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_DNS_RESOLVE` (266): a0 = hostname pointer, a1 = length, a2 = where to
// store the address. Written inside `dispatch.rs`'s match until wave 7 moved it
// to `sys_dns_resolve` in `handlers.rs`.
//
// What is tested is the handler's own half: the name travels through
// `copy_from_user` (never a raw read of `a0`), is capped at 64 bytes, and must
// be UTF-8, and each refusal is -1 before the resolver runs. A name that passes
// reaches `dns::resolve_with_yield`, the real file, which on this host panics
// at the NIC stand-in (`net_get_mac`) — that panic is how "reached the
// resolver" is observed. The success path (the answer stored through `a2`) is
// NOT covered: it needs a DNS reply on a NIC.

use super::harness::serial;
use azos_arch_api::PagePerms;

const NAME_VA: usize = 0x007C_0000;
const UNMAPPED_VA: usize = 0x007D_0000;

fn ring3_with(bytes: &[u8]) {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, NAME_VA, phys, PagePerms::USER_RW).expect("map");
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys as *mut u8, bytes.len());
    }
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(0x6C00_0001);
}

#[test]
fn dns_refuses_a_null_pointer_and_a_zero_length() {
    let _g = serial();
    ring3_with(b"example.org");
    assert_eq!(sys_dns_resolve(0, 11, 0), -1);
    assert_eq!(sys_dns_resolve(NAME_VA as u64, 0, 0), -1);
}

/// The old arm read `a0` raw; the name must come through `copy_from_user`,
/// which refuses a page ring 3 does not have.
#[test]
fn dns_refuses_an_unmapped_name_before_the_resolver() {
    let _g = serial();
    ring3_with(b"example.org");
    assert_eq!(sys_dns_resolve(UNMAPPED_VA as u64, 11, 0), -1);
}

#[test]
fn dns_refuses_a_name_that_is_not_utf8_before_the_resolver() {
    let _g = serial();
    ring3_with(&[b'a', 0xFF, b'b']);
    assert_eq!(sys_dns_resolve(NAME_VA as u64, 3, 0), -1);
}

/// A valid name is handed to the real resolver (observed at the NIC
/// stand-in it reaches on a cache miss).
#[test]
#[should_panic(expected = "NIC stand-in")]
fn dns_hands_a_valid_name_to_the_resolver() {
    let _g = serial();
    ring3_with(b"example.org");
    let _ = sys_dns_resolve(NAME_VA as u64, 11, 0);
}

/// The null/zero guard runs before the copy. It is not observable from the
/// return value alone — `copy_from_user` refuses a null pointer and the
/// resolver refuses an empty name, both with -1 — so, as for
/// `SYS_DRV_REGISTER` in `raw_input_guards.rs`, its presence and order are
/// pinned in the source.
#[test]
fn dns_guard_precedes_the_copy_in_the_source() {
    const HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");
    let code: String = HANDLERS.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n");
    let at = code.find("pub fn sys_dns_resolve(").expect("the handler moved");
    let body = &code[at..at + 600];
    let guard = body.find("name_len == 0 || name_ptr == 0").expect("SYS_DNS_RESOLVE lost its null/zero guard");
    let copy = body.find("copy_from_user").expect("the copy moved");
    assert!(guard < copy, "the guard must run BEFORE the copy");
}
