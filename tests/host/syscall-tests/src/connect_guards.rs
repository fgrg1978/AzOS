// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the pointer validation in `sys_connect_syscall`
// (`crates/core/syscall/src/handlers.rs:969`) — the `sockaddr` pointer it takes
// straight from a1, and the ownership gate / source-port arithmetic it does
// on a0 first.
//
// The `addr_ptr` path goes through `read_sockaddr` (`handlers.rs:881`), which
// for a user caller copies 16 bytes with `azos_sched::copy_from_user`.
// **What that costs and what it buys:** `copy_from_user` is the one place in
// this crate where kernel logic is transcribed rather than pulled (see
// `shims/sched/src/lib.rs`) — but the decision it makes per page is a call
// into the real `azos_mm::vmm::translate_user`, which is the actual Sv39
// permission walk. So the refusals below are the kernel's real answer about
// whether a user VA is mapped, USER, and readable; only the chunking loop
// around it is local. Read these as "what `sys_connect` does with a refusal",
// not as coverage of `crates/core/sched/src/process.rs`.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;

/// A VA well clear of everything else these tests use.
const SCRATCH: usize = 0x0020_0000;

/// A UDP socket owned by, and current for, tid 1 — with a user page table
/// installed, so `read_sockaddr` takes the `copy_from_user` branch rather
/// than the kernel raw-pointer branch.
///
/// UDP and not TCP on purpose: `socket_connect_with_yield` completes a UDP
/// connect immediately (no handshake to wait for), so the *success* control
/// in each test below returns without ever calling `azos_sched::
/// task_yield`, which is a `todo!()` here.
fn udp_socket_for_current_task(pt: usize) -> i32 {
    let fd = azos_net::socket_create_owned(
        azos_net::socket::AF_INET,
        azos_net::socket::SOCK_DGRAM,
        azos_net::socket::IPPROTO_UDP,
        1,
    );
    assert!(fd >= 0, "socket table full");
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    fd
}

/// Map one arena page at `va` with `flags` and return a host-writable pointer
/// to it. The arena is real memory this process owns, so the "physical"
/// address a PTE holds is a pointer we can fill in — which is what lets a
/// test place a *valid* sockaddr and prove the refusals below are about the
/// pointer, not about the bytes.
fn map_scratch(pt: usize, va: usize, flags: PagePerms) -> *mut u8 {
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, va, phys, flags).expect("map");
    phys as *mut u8
}

/// A well-formed `sockaddr_in`: AF_INET, port 9000, 10.0.0.2.
fn write_sockaddr(dst: *mut u8) {
    let mut raw = [0u8; 16];
    raw[0..2].copy_from_slice(&2u16.to_le_bytes()); // family, little-endian
    raw[2..4].copy_from_slice(&9000u16.to_be_bytes()); // port, network order
    raw[4..8].copy_from_slice(&[10, 0, 0, 2]);
    unsafe { core::ptr::copy_nonoverlapping(raw.as_ptr(), dst, 16) };
}

/// A null `sockaddr` pointer, from both kinds of caller.
///
/// **Divergence is on the kernel-context call, not the user one.** For a user
/// caller, deleting `read_sockaddr`'s `if ptr == 0` line changes nothing: the
/// copy still goes through `translate_user`, VA 0 is unmapped, the copy
/// fails, the answer is still -1. The check earns its place on the
/// `user_pt == 0` branch, which does a raw 16-byte read at the pointer — with
/// the line removed that is a load from address 0 in S-mode, i.e. a fatal
/// fault and a reset. Both are asserted, with which is which recorded, so the
/// user-context assertion is not mistaken for coverage of the check.
#[test]
fn connect_refuses_a_null_sockaddr() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let fd = udp_socket_for_current_task(pt);

    // User context: subsumed by the page walk, asserted for completeness.
    assert_eq!(sys_connect_syscall(fd as u64, 0, 16), -1);

    // Kernel context: this is the one the null check exists for.
    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_connect_syscall(fd as u64, 0, 16), -1);

    azos_net::socket_close(fd);
}

/// The security property `sys_connect`'s ownership gate exists for:
/// connecting a socket the caller does not own redirects another task's
/// stream to a peer of the attacker's choosing. An in-range, live,
/// *someone-else's* fd is the case the gate has to catch — an out-of-range
/// one is caught by `socket_connect_with_yield`'s own range check anyway (see
/// `connect_denies_an_out_of_range_fd`).
///
/// **Divergence:** delete `if !socket_access_ok(fd) { return -1; }` from
/// `sys_connect_syscall` and this call succeeds, returning 0 with the other
/// task's socket now pointed at 10.0.0.2.
#[test]
fn connect_refuses_a_socket_owned_by_another_task() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let mine = udp_socket_for_current_task(pt);
    let theirs = azos_net::socket_create_owned(
        azos_net::socket::AF_INET,
        azos_net::socket::SOCK_DGRAM,
        azos_net::socket::IPPROTO_UDP,
        2,
    );
    assert!(theirs >= 0);

    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    write_sockaddr(p);

    assert_eq!(
        sys_connect_syscall(theirs as u64, SCRATCH as u64, 16),
        -1,
        "tid 1 must not connect tid 2's socket"
    );
    assert_eq!(
        sys_connect_syscall(mine as u64, SCRATCH as u64, 16),
        0,
        "control: the identical call on its own socket succeeds"
    );

    azos_net::socket_close(mine);
    azos_net::socket_close(theirs);
}

/// A pointer into the caller's own address space that simply is not mapped.
/// The required outcome is a clean -1 — on the board this is a page fault in
/// S-mode while servicing a syscall, which `panic = "abort"` turns into a
/// reset.
///
/// The mapped control at the end is what stops this passing for the wrong
/// reason: the same syscall, the same socket, a pointer differing only in
/// being mapped, must succeed.
#[test]
fn connect_refuses_an_unmapped_sockaddr() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let fd = udp_socket_for_current_task(pt);

    assert_eq!(sys_connect_syscall(fd as u64, SCRATCH as u64, 16), -1);

    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    write_sockaddr(p);
    assert_eq!(
        sys_connect_syscall(fd as u64, SCRATCH as u64, 16),
        0,
        "control: the identical call with the page mapped must succeed"
    );
    azos_net::socket_close(fd);
}

/// **The partial-validation hole.** The `sockaddr` starts on a page that is
/// mapped and readable and ends on one that is not. A validator that checks
/// only the base address says yes; the read then walks off the end of the
/// mapping.
///
/// **Divergence:** the two versions — per-page validation and
/// base-address-only validation — agree on every pointer that does not
/// straddle a page boundary. They differ only here. So the offsets are
/// chosen to put the 16-byte read across the boundary by one byte at a time:
/// `PAGE_SIZE - 15` is the first offset that straddles, `PAGE_SIZE - 16` is
/// the last that does not, and both are asserted.
#[test]
fn connect_refuses_a_sockaddr_that_straddles_into_an_unmapped_page() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let fd = udp_socket_for_current_task(pt);

    // First page mapped, the next one deliberately left unmapped.
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);

    // The last pointer that fits entirely inside the mapped page.
    let last_ok = SCRATCH + PAGE_SIZE - 16;
    write_sockaddr(unsafe { p.add(PAGE_SIZE - 16) });
    assert_eq!(
        sys_connect_syscall(fd as u64, last_ok as u64, 16),
        0,
        "16 bytes ending on the last byte of the page are entirely readable"
    );

    // One byte further and the read's last byte falls in the unmapped page.
    for off in 1..=15usize {
        assert_eq!(
            sys_connect_syscall(fd as u64, (last_ok + off) as u64, 16),
            -1,
            "sockaddr at page_end - {} must be refused, not partially read",
            16 - off
        );
    }
    azos_net::socket_close(fd);
}

/// A user task naming a kernel address. The page is mapped and readable —
/// what disqualifies it is the missing `USER` bit, which is the only thing
/// separating "a pointer" from "a pointer this ring may follow".
///
/// **Divergence:** a validator that checked `is_valid()` instead of
/// `contains(USER)` returns the same answer for every user page and differs
/// only here, which is why the same VA is then remapped `USER_RW` and the
/// identical call asserted to succeed.
#[test]
fn connect_refuses_a_kernel_page_named_by_a_user_task() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let fd = udp_socket_for_current_task(pt);

    // KERNEL_RW: VALID + READ + WRITE, but no USER.
    let p = map_scratch(pt, SCRATCH, PagePerms::KERNEL_RW);
    write_sockaddr(p);
    assert_eq!(
        sys_connect_syscall(fd as u64, SCRATCH as u64, 16),
        -1,
        "a kernel-only page must not be readable through a syscall argument"
    );

    // Same address, same bytes, USER bit added.
    azos_mm::vmm::unmap(pt, SCRATCH);
    azos_mm::vmm::map(pt, SCRATCH, p as usize, PagePerms::USER_RW).unwrap();
    assert_eq!(
        sys_connect_syscall(fd as u64, SCRATCH as u64, 16),
        0,
        "control: the refusal above was about the USER bit and nothing else"
    );
    azos_net::socket_close(fd);
}

/// The fd side: an out-of-range `fd` must be refused *before* it is used for
/// anything. The ephemeral source port used to be derived from it --
/// `0xC000 + fd`, which overflowed a `u16` at `fd == 0x4000` and, under
/// `overflow-checks` with `panic = "abort"`, aborted the board. The port now
/// comes from the TCP layer's allocator and no longer depends on `fd`; the
/// historical values stay below as regression inputs for the gate
/// (`socket_access_ok`), which is now the only layer between them and the
/// socket table.
#[test]
fn connect_denies_an_out_of_range_fd() {
    let _g = serial();
    let pt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let fd = udp_socket_for_current_task(pt);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    write_sockaddr(p);

    for bogus in [
        azos_net::MAX_SOCKETS as u64,
        0x4000u64,          // 0xC000 + 0x4000 == 0x1_0000: the historical abort
        0x1_0000u64,        // wraps to 0 when narrowed with `as u16`
        u64::MAX,
    ] {
        assert_eq!(sys_connect_syscall(bogus, SCRATCH as u64, 16), -1, "fd = {bogus:#x}");
    }
    // Control: the owned, in-range fd with the same pointer succeeds.
    assert_eq!(sys_connect_syscall(fd as u64, SCRATCH as u64, 16), 0);
    azos_net::socket_close(fd);
}
