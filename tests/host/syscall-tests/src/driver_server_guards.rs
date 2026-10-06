// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `SYS_DRIVER_*` handlers in `crates/core/syscall/src/handlers.rs`
// (`sys_driver_stats`, `sys_driver_reply`, `sys_driver_fetch_request`,
// `sys_driver_poll_event`; `sys_driver_try_reply`/`sys_driver_request` were
// retired in wave 11, see the note near the end).
//
// **Why this family and not the hardware syscalls next to it.** Every other
// group in this crate either has a `todo!()` shim between it and ring 3
// (`sys_gpio_*`, `sys_i2c_*`, filesystem, sockets' send path — see the
// module doc / crate report for the full trace) or is already covered
// (mmap/munmap, `sys_connect`). `crates/drivers/driver_server` is different: its
// only dependency is `azos_sync::SpinLock` (`shims/driver_server`'s own
// doc), so it is pulled in whole with `#[path]`, real code, and every
// handler here reaches it with no stub in between. That makes this the one
// place in the crate where a POINTER-WRITE handler can be tested against a
// real positive control, not just a one-sided rejection.
//
// **What that real code turned up.** `DriverQueue::pop` and the IRQ latch's
// `swap(false, ..)` are both destructive reads, and two of the handlers below
// call them BEFORE validating the destination pointer. A ring-3 driver that
// passes a partially-mapped output buffer does not get "try again" — it gets
// a silent loss: a queued client request, or a latched interrupt, that
// existed one instruction ago and now does not. Both are reproduced below
// with the narrowest possible bad pointer (a straddle, not a wild address),
// each is paired with a control that proves the mechanism is fully wired
// (submit → fetch, register → poll → IRQ). (The non-destructive sibling
// they were contrasted with, `SYS_DRIVER_TRY_REPLY`, was retired in wave 11.)
//
// **Isolation.** `azos_driver_server::REGISTRY` and `TOTAL_REQUESTS` are
// process-wide statics with no test-only reset (unlike `azos_mm`'s
// `shim_reset`) — this crate does not own `crates/drivers/driver_server`, so no
// reset was added there. Every test below uses a `KIND` value nothing else
// in the tree uses (`0x9100 + n`, chosen clear of every real `DRV_KIND_*`,
// all of which are `<= 0x000F`) and unregisters it before returning, the
// same convention `socket_gate.rs` uses for `azos_net::SOCKS`. Do not
// reuse a `KIND` across two tests below: `cargo test`'s default parallelism
// only serialises access to the state THIS file's tests take `serial()`
// for, but a stale registration from an aborted test would still be visible
// to `driver_register`'s "already registered" check.

use super::harness::serial;
use azos_abi::error::Errno;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use azos_driver_server::{
    driver_fetch_request, driver_register, driver_reply, driver_signal_irq,
    driver_submit_request, driver_try_take_reply, driver_unregister, stats,
    DriverReply, DriverRequest, DriverServerStats, DRV_EVENT_IRQ, DRV_EVENT_NONE,
    TOTAL_REQUESTS,
};

/// A VA well clear of everything `mmap_guards.rs` / `connect_guards.rs` use.
const SCRATCH: usize = 0x0040_0000;

/// A fresh, empty user page table, installed as the current one, with `tid`
/// as the current task. Same shape as `mmap_guards.rs`'s `fresh_user_pt`,
/// duplicated rather than shared — every guard file in this crate defines
/// its own copy.
fn fresh_user_pt(tid: u32) -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    pt
}

/// Map one arena page at `va` and return a host-writable/readable pointer to
/// it — the "physical" address doubles as a real host pointer, same trick
/// `connect_guards.rs`'s `map_scratch` uses.
fn map_scratch(pt: usize, va: usize, flags: PagePerms) -> *mut u8 {
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, va, phys, flags).expect("map");
    phys as *mut u8
}

// ── SYS_DRIVER_STATS ────────────────────────────────────────────────────────
//
// `sys_driver_stats` (`handlers.rs:2979`) copies a 16-byte `DriverServerStats`
// (four `u32`s) to `user_out_ptr` via `copy_to_user`. Nothing about it is
// destructive to read, so this is the cleanest pointer-write test available:
// a straddle pair plus a byte-for-byte positive control.

#[test]
fn driver_stats_refuses_a_null_pointer() {
    let _g = serial();
    assert_eq!(sys_driver_stats(0), -1);
}

#[test]
fn driver_stats_refuses_an_unmapped_pointer() {
    let _g = serial();
    fresh_user_pt(1);
    assert_eq!(sys_driver_stats(SCRATCH as u64), -1);
}

#[test]
fn driver_stats_refuses_a_kernel_only_page() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::KERNEL_RW);
    assert_eq!(
        sys_driver_stats(SCRATCH as u64), -1,
        "a page without the USER bit must not be a valid syscall-output destination"
    );
}

/// **Divergence:** a validator that checks only the base address of the
/// destination range agrees with the real per-page check on every pointer
/// except one whose tail runs past the mapped page — so that is the only
/// input asserted here. The positive control (`page_end - n`) and the
/// straddle (`page_end - n + 1 ..= page_end - 1`) are the pair
/// `connect_guards.rs` already uses for the same reason.
#[test]
fn driver_stats_straddle_pair_with_a_byte_exact_positive_control() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);
    let kind = 0x9101;
    assert!(driver_register(kind, 1, 0, 0, 0));

    let n = core::mem::size_of::<DriverServerStats>();
    assert_eq!(n, 16, "layout assumption behind the offsets below");

    let before = stats();
    let last_ok = SCRATCH + PAGE_SIZE - n;
    assert_eq!(
        sys_driver_stats(last_ok as u64), 0,
        "a write ending exactly on the last byte of the mapped page must succeed"
    );
    // Not just the return code: the actual bytes written must be the real
    // stats, not zeros or garbage from a short copy.
    let got = unsafe { core::slice::from_raw_parts(p.add(PAGE_SIZE - n), n) };
    let mut want = [0u8; 16];
    want[0..4].copy_from_slice(&before.active_drivers.to_ne_bytes());
    want[4..8].copy_from_slice(&before.total_requests.to_ne_bytes());
    want[8..12].copy_from_slice(&before.total_irqs.to_ne_bytes());
    want[12..16].copy_from_slice(&before.queue_high_water.to_ne_bytes());
    assert_eq!(got, &want[..]);

    for off in 1..=(n - 1) {
        assert_eq!(
            sys_driver_stats((last_ok + off) as u64), -1,
            "stats write at page_end - {} must be refused, not partially written", n - off
        );
    }

    assert!(driver_unregister(kind));
}

// ── SYS_DRIVER_REPLY ─────────────────────────────────────────────────────────
//
// `sys_driver_reply` (`handlers.rs:2895`) reads an 80-ish-byte `DriverReply`
// from `user_reply_ptr` via `copy_from_user` BEFORE calling `driver_reply`,
// which publishes it. That ordering is what makes a failed copy safe here —
// contrast with `SYS_DRIVER_FETCH_REQUEST` below, where the equivalent
// destructive step runs FIRST.

#[test]
fn driver_reply_refuses_a_null_pointer() {
    let _g = serial();
    assert_eq!(sys_driver_reply(0x9102, 0), -1);
}

/// **Divergence + non-corruption.** The mutant to fear is "ignore the
/// `copy_from_user` failure and publish whatever ended up in `reply`
/// anyway" (e.g. the zeroed default). That mutant agrees with the correct
/// code on every input except one where a copy fails AFTER a real reply is
/// already on file — there, the correct code leaves the file alone and the
/// mutant clobbers it with a zeroed token that no client will ever ask for.
/// So the straddle is asserted against the SURVIVAL of a prior reply, not
/// just against the return code.
#[test]
fn driver_reply_straddle_does_not_clobber_a_reply_already_on_file() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);
    let kind = 0x9102;
    assert!(driver_register(kind, 1, 0, 0, 0));

    let n = core::mem::size_of::<DriverReply>();

    // Positive control: a reply ending exactly on the last mapped byte is
    // read and published correctly.
    let mut good = DriverReply::zeroed();
    good.token = 0xABCD_1234;
    good.status = 7;
    good.out_len = 3;
    good.output[0] = 9;
    good.output[1] = 8;
    good.output[2] = 7;
    unsafe { (p.add(PAGE_SIZE - n) as *mut DriverReply).write(good) };
    let last_ok = SCRATCH + PAGE_SIZE - n;
    assert_eq!(sys_driver_reply(kind as u64, last_ok as u64), 0);

    let mut out = DriverReply::zeroed();
    assert!(driver_try_take_reply(kind, 0xABCD_1234, &mut out));
    assert_eq!((out.status, out.out_len, &out.output[..3]), (7, 3, &[9, 8, 7][..]));

    // The straddle: one byte at a time past the mapped page.
    for off in 1..=(n - 1) {
        assert_eq!(
            sys_driver_reply(kind as u64, (last_ok + off) as u64), -1,
            "reply at page_end + {off} bytes must be refused, not partially read"
        );
    }

    // The reply from the positive control must be untouched.
    let mut out2 = DriverReply::zeroed();
    assert!(
        driver_try_take_reply(kind, 0xABCD_1234, &mut out2),
        "a rejected sys_driver_reply overwrote the previously published reply"
    );
    assert_eq!((out2.status, out2.out_len, &out2.output[..3]), (7, 3, &[9, 8, 7][..]));

    assert!(driver_unregister(kind));
}

// ── SYS_DRIVER_FETCH_REQUEST ─────────────────────────────────────────────────
//
// **LIVE DEFECT.** `driver_fetch_request` (the real
// `crates/drivers/driver_server::driver_fetch_request`, via `DriverQueue::pop`) POPS
// the request off the per-kind queue. `sys_driver_fetch_request`
// (`handlers.rs:2861`) only copies it out to userspace AFTERWARDS. A ring-3
// driver process that passes an output pointer whose backing page is not
// fully mapped gets `-1` back — and the request is simply gone: it already
// left the queue, no other consumer will ever see it, and the client that
// submitted it is left waiting for a reply that will never be produced.
// Reproduced below with the narrowest possible "not fully mapped" case: the
// FIRST byte of the destination is mapped and readable, only the tail is
// not.

#[test]
fn driver_fetch_request_refuses_a_null_pointer_without_touching_the_queue() {
    let _g = serial();
    let kind = 0x9103;
    assert!(driver_register(kind, 1, 0, 0, 0));
    let tok = driver_submit_request(kind, 1, 42, &[1, 2, 3], 8);
    assert!(tok > 0, "table full? test measures nothing");

    assert_eq!(sys_driver_fetch_request(kind as u64, 0), -1);

    // The null-pointer guard runs before the pop, so a real fetch afterwards
    // must still see the request.
    let req = driver_fetch_request(kind).expect("the null-pointer rejection dropped the request");
    assert_eq!(req.token, tok);
    assert!(driver_unregister(kind));
}

/// **The finding.** See the module-level doc above.
#[test]
fn driver_fetch_request_keeps_the_request_when_the_output_pointer_is_not_fully_mapped() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);
    let kind = 0x9104;
    assert!(driver_register(kind, 1, 0, 0, 0));

    let n = core::mem::size_of::<DriverRequest>();
    let before_total = TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed);
    let tok = driver_submit_request(kind, 7, 99, &[5, 6, 7], 4);
    assert!(tok > 0);

    // One byte past the last fully-mapped destination address.
    let bad_ptr = SCRATCH + PAGE_SIZE - n + 1;
    assert_eq!(sys_driver_fetch_request(kind as u64, bad_ptr as u64), -1);

    assert!(
        driver_fetch_request(kind).is_some(),
        "sys_driver_fetch_request consumed the request even though the copy to \
         userspace failed. The request is then permanently gone rather than merely \
         delayed: no other consumer will ever see it, and the client that submitted \
         it waits forever. Answering -1 while silently eating the caller's work is \
         worse than either succeeding or failing cleanly, which is why the \
         destination is validated BEFORE the pop."
    );
    // The counter agrees with the return value: this was not counted as a
    // served request either, so the two observables do not contradict each
    // other even though the request itself is lost.
    assert_eq!(
        TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed), before_total,
        "a failed fetch must not be counted as a served request"
    );

    assert!(driver_unregister(kind));
}

/// The pre-pop guard must PREPARE the destination, not merely ask about it.
///
/// **The gap.** Owner decision 100c made that guard a pure probe, and a
/// copy-on-write leaf answers "writable" because a write to it *will* succeed
/// — `copy_to_user` breaks the COW when the write happens. But
/// `handle_cow_fault` begins with `pmm::alloc_page()?` (`crates/core/mm/src/cow.rs`),
/// so with no page to copy into the break fails, `copy_to_user` answers
/// `false`, and the request is already popped. A probe cannot close that: the
/// caller does not need an answer, it needs a guarantee. Hence
/// `user_range_prepare_write`.
///
/// **The observable, and the one that does not work.** Asserting that the
/// destination's physical address moved by the end of the syscall proves
/// nothing — it moves either way, because `copy_to_user` breaks the COW a few
/// lines after the pop, and that canary passed 252/252 against the reverted
/// fix. What separates "prepared before the pop" from "broken after it" is the
/// failure itself: with the allocator empty,
///   * preparing → the guard fails, the request is never popped, it survives;
///   * probing   → the guard passes, the request is popped, the copy fails,
///                 and the request is gone for good.
///
/// `page_addref` (refcount 2) is essential, not decoration: at refcount 1
/// `handle_cow_fault` takes its sole-owner path and flips `WRITE` in place
/// **without allocating**, so an empty arena would not stop it and this would
/// pass against both versions.
///
/// **This test was written, withdrawn, and is back.** It was withdrawn because
/// draining the arena turned two `mmap_guards` tests red and I diagnosed that
/// as "there is no per-test allocator isolation". There is — `serial()` — and
/// the real cause was the COW refcount table, which had no reset, so the
/// second reference this test takes outlived it and the frame came back to
/// another test as un-freeable. `harness::reset_state` clears it now.
#[test]
fn driver_fetch_request_keeps_the_request_when_a_cow_destination_cannot_be_broken() {
    let _g = serial();
    let pt = fresh_user_pt(1);

    // What fork leaves behind: user-readable, NOT writable, marked COW, with a
    // second owner so the break must really copy. Built through the real
    // `fork_cow` (not a hand-crafted COW word) so this is testing the same
    // marker production the kernel actually uses — `fork_cow` addrefs and
    // flips WRITE→COW on `pt`'s own leaf, giving the "second owner" for free.
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, phys, PagePerms::USER_RW).expect("map");
    let _cow_child = azos_mm::vmm::fork_cow(pt, 0, 0).expect("fork produces the COW leaf");

    let kind = 0x9107;
    assert!(driver_register(kind, 1, 0, 0, 0));
    let tok = driver_submit_request(kind, 7, 99, &[5, 6, 7], 4);
    assert!(tok > 0);

    // Empty the arena so `handle_cow_fault`'s `alloc_page` must fail.
    let mut held = ::std::vec::Vec::new();
    while let Ok(p) = azos_mm::pmm::alloc_page() {
        held.push(p);
    }

    let rc = sys_driver_fetch_request(kind as u64, SCRATCH as u64);
    let survived = driver_fetch_request(kind).is_some();

    // Put the arena back AND unregister BEFORE asserting: a failing assert
    // panics, and neither cleanup would run. The registry is process-global
    // with no reset (see this file's header), so a leaked registration takes a
    // neighbouring test down with it — which is exactly what the first canary
    // run of this test did, turning one expected red into two.
    for p in held.into_iter().rev() {
        let _ = azos_mm::pmm::free_page(p);
    }
    assert!(driver_unregister(kind));

    assert_eq!(rc, -1, "with no page to copy into, the fetch cannot succeed");
    assert!(
        survived,
        "the request was consumed even though the copy could not happen. The \
         guard only ASKED whether a write would be permitted — a copy-on-write \
         leaf answers yes — and left the break to `copy_to_user`, which runs \
         AFTER the pop and fails when the allocator is empty. The request is \
         then permanently gone: no other consumer sees it and the client waits \
         forever."
    );
}

/// Positive control: the mechanism submit → fetch → copy really works when
/// the pointer is good, proving the finding above is about the pointer
/// guard and not about `driver_submit_request`/`driver_fetch_request` being
/// broken in some other way.
#[test]
fn driver_fetch_request_succeeds_and_copies_the_real_request() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let kind = 0x9105;
    assert!(driver_register(kind, 1, 0, 0, 0));

    let before_total = TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed);
    let tok = driver_submit_request(kind, 7, 99, &[5, 6, 7], 4);
    assert!(tok > 0);

    assert_eq!(sys_driver_fetch_request(kind as u64, SCRATCH as u64), 0);
    let got = unsafe { core::ptr::read(p as *const DriverRequest) };
    assert_eq!(got.token, tok);
    assert_eq!(got.op, 99);
    assert_eq!(got.client_tid, 7);
    assert_eq!(&got.input[..3], &[5, 6, 7]);
    assert_eq!(
        TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed), before_total + 1
    );

    assert!(driver_unregister(kind));
}

// ── SYS_DRIVER_REPLY_FETCH (RFC-0041 §D) ─────────────────────────────────────
//
// The reply and the next fetch in one trap. Beyond "both halves work", the
// property that matters is that a refusal did NOTHING: a driver told "failed"
// still holds its reply and sends it again, and a reply published by a call
// that answered "failed" would come back as a duplicate of its token. Every
// refusal below is therefore
// asserted against the reply being absent (or a prior one intact) and the
// request still being queued, not just against the return code.

/// Offset of the request buffer inside the scratch page, clear of a staged
/// reply at offset 0.
const REQ_OFF: usize = 0x200;

/// Write a `DriverReply` with `token` at `p + off` (the host view of a mapped
/// user page).
fn stage_reply(p: *mut u8, off: usize, token: u64, status: i32) {
    let mut r = DriverReply::zeroed();
    r.token = token;
    r.status = status;
    r.out_len = 1;
    r.output[0] = 0x5A;
    unsafe { (p.add(off) as *mut DriverReply).write_unaligned(r) };
}

/// Positive control for everything below: one call publishes the staged reply
/// and writes the queued request.
#[test]
fn driver_reply_fetch_publishes_the_reply_and_writes_the_next_request() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let kind = 0x9130;
    assert!(driver_register(kind, 1, 0, 0, 0));
    stage_reply(p, 0, 0x7001, 3);
    let tok = driver_submit_request(kind, 7, 99, &[5, 6, 7], 4);
    assert!(tok > 0);
    let before_total = TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed);

    assert_eq!(
        sys_driver_reply_fetch(kind as u64, SCRATCH as u64, (SCRATCH + REQ_OFF) as u64), 0
    );

    let mut out = DriverReply::zeroed();
    assert!(driver_try_take_reply(kind, 0x7001, &mut out), "the reply half published nothing");
    assert_eq!((out.status, out.out_len, out.output[0]), (3, 1, 0x5A));
    let got = unsafe { core::ptr::read_unaligned(p.add(REQ_OFF) as *const DriverRequest) };
    assert_eq!((got.token, got.op, got.client_tid), (tok, 99, 7));
    assert_eq!(&got.input[..3], &[5, 6, 7]);
    assert_eq!(
        TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed), before_total + 1
    );

    assert!(driver_unregister(kind));
}

/// `-1` with an empty queue still means the reply went out, which is what lets
/// the driver drop it.
#[test]
fn driver_reply_fetch_with_an_empty_queue_still_publishes_the_reply() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let kind = 0x9131;
    assert!(driver_register(kind, 1, 0, 0, 0));
    stage_reply(p, 0, 0x7002, 4);

    assert_eq!(
        sys_driver_reply_fetch(kind as u64, SCRATCH as u64, (SCRATCH + REQ_OFF) as u64), -1
    );

    let mut out = DriverReply::zeroed();
    assert!(driver_try_take_reply(kind, 0x7002, &mut out), "-1 answered but no reply published");
    assert_eq!(out.status, 4);
    assert!(driver_unregister(kind));
}

/// A null reply pointer is "no reply owed" (a serve loop's first call), not a
/// zeroed reply: the reply already on file must survive it.
#[test]
fn driver_reply_fetch_with_a_null_reply_only_fetches() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let kind = 0x9132;
    assert!(driver_register(kind, 1, 0, 0, 0));
    let mut prior = DriverReply::zeroed();
    prior.token = 0x7003;
    prior.status = 6;
    assert!(driver_reply(kind, prior));
    let tok = driver_submit_request(kind, 7, 11, &[1], 4);
    assert!(tok > 0);

    assert_eq!(sys_driver_reply_fetch(kind as u64, 0, (SCRATCH + REQ_OFF) as u64), 0);

    let got = unsafe { core::ptr::read_unaligned(p.add(REQ_OFF) as *const DriverRequest) };
    assert_eq!(got.token, tok);
    let mut out = DriverReply::zeroed();
    assert!(
        driver_try_take_reply(kind, 0x7003, &mut out),
        "a null reply pointer overwrote the reply already on file"
    );
    assert_eq!(out.status, 6);
    assert!(driver_unregister(kind));
}

/// **The ordering.** The request buffer is checked before the reply is
/// published. The mutant to fear publishes first and then refuses the buffer:
/// same `-4`, and the reply is out.
#[test]
fn driver_reply_fetch_refuses_a_bad_request_buffer_before_publishing_anything() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);
    let kind = 0x9133;
    assert!(driver_register(kind, 1, 0, 0, 0));
    stage_reply(p, 0, 0x7004, 5);
    let tok = driver_submit_request(kind, 7, 12, &[2], 4);
    assert!(tok > 0);

    let n = core::mem::size_of::<DriverRequest>();
    let straddle = SCRATCH + PAGE_SIZE - n + 1;
    assert_eq!(sys_driver_reply_fetch(kind as u64, SCRATCH as u64, straddle as u64), -4);
    assert_eq!(sys_driver_reply_fetch(kind as u64, SCRATCH as u64, 0), -4);

    let mut out = DriverReply::zeroed();
    assert!(
        !driver_try_take_reply(kind, 0x7004, &mut out),
        "a call that answered -4 published the reply"
    );
    let req = driver_fetch_request(kind).expect("a call that answered -4 took the request");
    assert_eq!(req.token, tok);
    assert!(driver_unregister(kind));
}

/// **Fail-fast.** A reply that cannot be read takes no request. The mutant
/// to fear goes on to the fetch anyway: the request leaves the queue for a
/// driver that was told nothing happened.
#[test]
fn driver_reply_fetch_refuses_an_unreadable_reply_without_taking_a_request() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);
    let kind = 0x9134;
    assert!(driver_register(kind, 1, 0, 0, 0));
    let mut prior = DriverReply::zeroed();
    prior.token = 0x7005;
    prior.status = 8;
    assert!(driver_reply(kind, prior));
    let tok = driver_submit_request(kind, 7, 13, &[3], 4);
    assert!(tok > 0);
    let before_total = TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed);

    let nr = core::mem::size_of::<DriverReply>();
    let straddle = SCRATCH + PAGE_SIZE - nr + 1;
    assert_eq!(sys_driver_reply_fetch(kind as u64, straddle as u64, SCRATCH as u64), -3);

    let mut out = DriverReply::zeroed();
    assert!(
        driver_try_take_reply(kind, 0x7005, &mut out),
        "a refused reply clobbered the reply already on file"
    );
    assert_eq!(out.status, 8);
    let req = driver_fetch_request(kind).expect("a refused reply still took the request");
    assert_eq!(req.token, tok);
    assert_eq!(
        TOTAL_REQUESTS.load(core::sync::atomic::Ordering::Relaxed), before_total,
        "a refused call counted a served request"
    );
    assert!(driver_unregister(kind));
}

/// Ownership, with the same "nothing done" check as the refusals above.
#[test]
fn driver_reply_fetch_refuses_a_task_that_is_not_the_registered_driver() {
    let _g = serial();
    let pt = fresh_user_pt(2);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let kind = 0x9135;
    assert!(driver_register(kind, 1, 0, 0, 0));
    stage_reply(p, 0, 0x7006, 9);
    let tok = driver_submit_request(kind, 7, 14, &[4], 4);
    assert!(tok > 0);

    assert_eq!(
        sys_driver_reply_fetch(kind as u64, SCRATCH as u64, (SCRATCH + REQ_OFF) as u64), E_PERM
    );

    let mut out = DriverReply::zeroed();
    assert!(!driver_try_take_reply(kind, 0x7006, &mut out), "a stranger published a reply");
    let req = driver_fetch_request(kind).expect("a stranger took the request");
    assert_eq!(req.token, tok);
    assert!(driver_unregister(kind));
}


// ── SYS_DRIVER_POLL_EVENT ────────────────────────────────────────────────────
//
// **Second instance of the fetch_request bug class.** `driver_poll_event`'s
// IRQ arm is destructive: `slot.irq_pending.swap(false, ..)`. It is called
// unconditionally, before `sys_driver_poll_event` (`handlers.rs:2842`) even
// looks at `user_out_ptr`. A bad (non-null, partially-mapped) output pointer
// still consumes the latched IRQ and then reports `-1` — the interrupt is
// silently dropped, not merely un-delivered this time. Same shape and same
// root cause as the fetch_request finding above: a destructive read placed
// before, rather than after, the fallible copy to userspace.

#[test]
fn driver_poll_event_with_a_null_pointer_still_consumes_the_irq() {
    let _g = serial();
    let kind = 0x9109;
    let irq = 0x9109;
    assert!(driver_register(kind, 1, 0, 0, irq));
    assert!(driver_signal_irq(irq));

    // `user_out_ptr == 0` skips the copy entirely, but not the call to
    // `driver_poll_event` above it, which already swapped `irq_pending`.
    // Documented current behaviour: the event KIND is still reported (the
    // return value), only the payload is silently dropped.
    assert_eq!(
        sys_driver_poll_event(kind as u64, 0), DRV_EVENT_IRQ as i64,
        "the event kind must still be reported even with nowhere to put the payload"
    );
    assert_eq!(
        sys_driver_poll_event(kind as u64, 0), DRV_EVENT_NONE as i64,
        "the IRQ was latched once and the call above already consumed it"
    );

    assert!(driver_unregister(kind));
}

/// **The finding.**
#[test]
fn driver_poll_event_keeps_the_irq_when_the_output_pointer_is_not_fully_mapped() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);
    let kind = 0x910A;
    let irq = 0x910A;
    assert!(driver_register(kind, 1, 0, 0, irq));
    assert!(driver_signal_irq(irq));

    let n = 8usize; // payload is a u64
    let bad_ptr = SCRATCH + PAGE_SIZE - n + 1;
    assert_eq!(sys_driver_poll_event(kind as u64, bad_ptr as u64), -1);

    // The interrupt must still be there. A refused call consumed nothing, so a
    // retry with a good pointer gets it — which is the only behaviour a driver
    // can be written against. Consuming it and answering -1 leaves the driver
    // waiting on an event that already happened, with nothing to signal it
    // again.
    let last_ok = SCRATCH + PAGE_SIZE - n;
    assert_ne!(
        sys_driver_poll_event(kind as u64, last_ok as u64), DRV_EVENT_NONE as i64,
        "the IRQ signalled above was swallowed by the REFUSED call: \
         `driver_poll_event` clears the pending flag before the pointer is \
         checked, so a -1 return also means the interrupt is gone for good"
    );

    assert!(driver_unregister(kind));
}

/// Positive control: register, signal, poll with a good pointer, and check
/// the actual payload bytes (the IRQ number), not just the return value.
#[test]
fn driver_poll_event_reports_the_irq_number_through_a_good_pointer() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let kind = 0x910B;
    let irq = 0x910B;
    assert!(driver_register(kind, 1, 0, 0, irq));
    assert!(driver_signal_irq(irq));

    assert_eq!(sys_driver_poll_event(kind as u64, SCRATCH as u64), DRV_EVENT_IRQ as i64);
    let payload = unsafe { core::ptr::read(p as *const u64) };
    assert_eq!(payload, irq as u64);

    assert!(driver_unregister(kind));
}

// ── SYS_DRIVER_REQUEST / SYS_DRIVER_TRY_REPLY: retired (wave 11) ──────────
//
// 525/526 took no capability and checked no ownership: any task allowed to
// issue them queued a request to ANY driver kind (around `drv_invoke_authorized`)
// and read ANY reply by guessing its token, a per-kind counter (OVSwrap review
// F3). No profile granted them and no image called them, so the numbers are in
// `RETIRED_SYSCALLS` and the handlers and their tests are gone; the in-kernel
// proxy reaches the queue through `driver_submit_request` directly.
// `tests/host/abi-tests` (`no_dispatch_arm_matches_a_retired_number`) and
// `tests/host/seccomp-tests` (`no_profile_grants_a_retired_number`) hold them out.

// ── Untested by design ───────────────────────────────────────────────────────
//
//  * `sys_driver_register` / `sys_driver_unregister` take only small integers
//    (`kind`, `mmio_base`, `mmio_size`, `irq`) with no pointer or length —
//    exercised as setup machinery by every test above, which is coverage of
//    their success path; their failure arms (kind already registered / not
//    found) are one-line real-crate checks with no ring-3-reachable overflow
//    or OOB behind them, so a dedicated canary was not written.
//  * `errno_for_driver_err` and `cap_kind_for_driver` are covered in
//    `errno.rs` / `driver_caps.rs`.

// ── Ownership of driver traffic ────────────────────────────────────────────
//
// Added 2026-09-06. Until then `driver_tid` was recorded at registration and
// read NOWHERE in the tree — write-only. So `fetch`, `poll` and `reply` had no
// notion of an owner: any ring-3 task could drain another driver's request
// queue (fetch POPS, so the real driver never saw it) or write its reply.
//
// The tests above run in kernel context, where `cap_check` and this new check
// both pass by design, so they went on passing with the guard absent. These
// run as a user task, which is the only context in which the guard exists.

/// A ring-3 task that is not the registered driver must not touch its traffic.
///
/// Physically: `fetch` steals a request the real driver will now never see,
/// and `reply` writes an answer the kernel proxy accepts as that driver's.
/// With ring-3 sensor and actuator drivers — which is what the driver server
/// is for — that is the control loop acting on a reading nobody measured, or
/// believing an actuator acknowledged a command that was never written.
#[test]
fn driver_traffic_refuses_a_task_that_is_not_the_registered_driver() {
    let _g = serial();
    // Register kind 1 to some other task, from kernel context.
    azos_sched::set_current_user_pt(0);
    assert!(azos_driver_server::driver_register(1, 4242, 0, 0, 0),
            "could not register the driver this test needs");

    // Now become a different ring-3 task.
    let pt = fresh_user_pt(7);
    let p = map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    let _ = p;

    assert_eq!(
        sys_driver_fetch_request(1, SCRATCH as u64), E_PERM,
        "an unrelated task drained the registered driver's request queue"
    );
    assert_eq!(
        sys_driver_poll_event(1, SCRATCH as u64), E_PERM,
        "an unrelated task consumed the registered driver's latched interrupt"
    );
    assert_eq!(
        sys_driver_reply(1, SCRATCH as u64), E_PERM,
        "an unrelated task wrote a reply on the registered driver's behalf"
    );

    azos_sched::set_current_user_pt(0);
    azos_driver_server::driver_unregister(1);
}

/// A slot must be released when its owner dies, and the release must be
/// attributable — which is why `driver_tid` had to start being read.
///
/// Nothing released these before: `task_release_all_resources` reclaimed
/// handles, ports, io_rings, sockets and file descriptors and never touched
/// the driver registry, and the comment in `user_driver_proxy.rs` claiming it
/// did was false. With traffic now owner-checked, an unreleased slot is worse
/// than untidy: the kind becomes permanently unclaimable and every client of
/// it pays the proxy's full reply timeout before giving up.
#[test]
fn a_dead_owners_driver_slot_is_released() {
    let _g = serial();
    azos_sched::set_current_user_pt(0);
    assert!(azos_driver_server::driver_register(2, 555, 0, 0, 0));
    assert!(azos_driver_server::driver_is_owner(2, 555),
            "registration did not record the owner");

    assert_eq!(azos_driver_server::driver_release_all(555), 1,
               "the dead owner's slot was not released");
    assert!(!azos_driver_server::driver_is_owner(2, 555),
            "the slot still names a task that no longer exists");
    // And the kind is claimable again, which is the property that matters.
    assert!(azos_driver_server::driver_register(2, 556, 0, 0, 0),
            "the kind stayed unclaimable after its owner died");
    azos_driver_server::driver_unregister(2);
}

// ── Cap<DriverRegistry>: the typed register/unregister path ────────────────
//
// The untyped `sys_driver_register` (retired in RFC-0040 gap 1) took the kind
// in `a0` and gated on `DriverRegistry(a0)`. The typed one (`SYS_DRIVER_REGISTER_TYPED`,
// 556) has NO kind argument: it reads the kind out of the capability. These
// two tests are the difference, exercised at the handler boundary with the
// real `crates/drivers/driver_server` and the real `crates/core/ipc/src/cap_store.rs`
// behind them.
//
// **Two task tables, and they are not the same one.** `cap_store` resolves
// TIDs through the `shims/ipc_sched` pool (`ipc_task_pool` in this crate's
// Cargo.toml), while the handler asks `azos_sched::current_task_tid()`,
// which is this crate's own `shims/sched`. A test must bind the TID in the
// first and set it current in the second, or the mint lands in a table the
// handler will not look in — which reads as "the capability was refused"
// rather than "the test is wired wrong". `bind_typed_caller` does both.

/// Bind `tid` in the cap-store's task pool AND make it the current task, so a
/// capability minted for it is the one the handler dereferences.
fn bind_typed_caller(tid: u32, slot: usize) {
    ipc_task_pool::shim_bind(tid, slot);
    azos_sched::set_current_task_tid(tid);
    // Ring 3: `cap_check`'s kernel bypass (`current_user_pt() == 0`) does not
    // apply to the typed path — it has no `cap_check` at all — but leaving
    // the caller in kernel context would make these tests silent about which
    // gate actually ran.
    azos_sched::set_current_user_pt(0x1000);
}

/// The typed handler registers the kind the CAPABILITY names.
///
/// `0x9110` rather than a real `DRV_KIND_*`, per this file's isolation
/// convention — the registry is a process-wide static with no test reset.
#[test]
fn typed_register_uses_the_kind_from_the_capability() {
    use azos_ipc::cap::CapPerms;
    const KIND: u32 = 0x9110;
    const TID: u32 = 9110;

    let _g = serial();
    bind_typed_caller(TID, 11);

    let cap = azos_ipc::drvreg_cap::drvreg_grant_cap(TID, KIND, CapPerms::RW)
        .expect("mint Cap<DriverRegistry>(KIND)");

    assert_eq!(
        crate::handlers::sys_driver_register_typed(cap.raw().as_raw() as u64, 0, 0, 0),
        0,
        "a valid capability must be accepted"
    );
    assert!(
        azos_driver_server::driver_is_owner(KIND, TID),
        "the registry must name the capability's kind, owned by the caller"
    );

    // And the typed unregister releases exactly that kind.
    assert_eq!(
        crate::handlers::sys_driver_unregister_typed(cap.raw().as_raw() as u64),
        0
    );
    assert!(!azos_driver_server::driver_is_owner(KIND, TID));
    azos_driver_server::driver_unregister(KIND);
    ipc_task_pool::shim_kill(TID);
}

/// A capability for one kind does not register another — and, unlike the
/// untyped path, asking is not expressible.
///
/// The assertion is indirect on purpose: there is no argument to put the
/// wrong kind in, so what is proved is that after registering with the GPIO
/// capability, the OTHER kind is still unowned and still claimable by anyone.
/// A handler that took the kind from an argument, or that ignored the cap's
/// resource index, would fail this.
///
/// **Canary — and the first version of this test failed it.** Making
/// `drvreg_kind_of` return a constant instead of `table.get(...)`'s value
/// left this test GREEN, because asserting only that OTHER is unowned is
/// satisfied by a handler that registers nothing at all. The positive half
/// below (`HELD` owned by `TID`) is what makes the pair discriminating: under
/// that mutation neither kind is registered and the first assertion fails.
/// A one-sided "the wrong thing did not happen" is not a test of the right
/// thing happening.
#[test]
fn a_capability_for_one_kind_does_not_register_another() {
    use azos_ipc::cap::CapPerms;
    const HELD: u32 = 0x9111;
    const OTHER: u32 = 0x9112;
    const TID: u32 = 9111;

    let _g = serial();
    bind_typed_caller(TID, 12);

    let cap = azos_ipc::drvreg_cap::drvreg_grant_cap(TID, HELD, CapPerms::RW)
        .expect("mint Cap<DriverRegistry>(HELD)");
    assert_eq!(
        crate::handlers::sys_driver_register_typed(cap.raw().as_raw() as u64, 0, 0, 0),
        0
    );

    assert!(
        azos_driver_server::driver_is_owner(HELD, TID),
        "the capability's own kind was not registered — see this test's canary note"
    );
    assert!(
        !azos_driver_server::driver_is_owner(OTHER, TID),
        "holding one kind's capability registered a second kind"
    );
    // Still claimable by a different task — i.e. genuinely unregistered,
    // not merely owned by someone else.
    assert!(
        azos_driver_server::driver_register(OTHER, 7777, 0, 0, 0),
        "OTHER was not left free"
    );

    azos_driver_server::driver_unregister(OTHER);
    azos_driver_server::driver_unregister(HELD);
    ipc_task_pool::shim_kill(TID);
}

/// A forged handle is refused with a capability errno, not a bare -1.
///
/// `Cap::NULL` is what a caller passing 0 produces, and it is the cheapest
/// possible attack on this syscall. `ECAPSTALE` rather than `EINVAL` matters:
/// the two are distinguishable at the ABI, and a caller cannot tell "your cap
/// expired" from "the kernel lost your table" if they collapse.
#[test]
fn typed_register_refuses_a_forged_capability() {
    use azos_abi::error::Errno;
    const TID: u32 = 9113;

    let _g = serial();
    bind_typed_caller(TID, 13);

    assert_eq!(
        crate::handlers::sys_driver_register_typed(0, 0, 0, 0),
        Errno::ECAPSTALE.to_syscall_ret(),
        "a null capability must be refused as stale"
    );
    ipc_task_pool::shim_kill(TID);
}

// ── SYS_CAP_LOOKUP: the read half that was missing ────────────────────────
//
// Of the thirty typed syscalls (528-557) only three return a handle they mint.
// Twenty-one others require one the caller must already have, and a capability
// granted at boot landed in the task's table with no way for the task to learn
// its handle — so every hardware family's typed path had no possible ring-3
// caller, with a green gate over all of them. `sys_cap_lookup` is that path.

/// A lookup finds the capability the task holds, and the handle it returns
/// actually works on the typed syscall it was looked up for.
///
/// End to end on purpose: a handle that decodes but does not dereference
/// would satisfy a test that only checked the bits.
#[test]
fn cap_lookup_returns_a_handle_that_the_typed_syscall_accepts() {
    use azos_abi::cap::CapKind;
    use azos_ipc::cap::CapPerms;
    const KIND: u32 = 0x9120;
    const TID: u32 = 9120;

    let _g = serial();
    bind_typed_caller(TID, 20);
    azos_ipc::drvreg_cap::drvreg_grant_cap(TID, KIND, CapPerms::RW)
        .expect("mint the capability the lookup must find");

    let raw = crate::handlers::sys_cap_lookup(CapKind::DriverRegistry as u64, KIND as u64);
    assert!(raw >= 0, "lookup did not find a held capability (got {raw})");

    // The handle is not merely plausible — it registers.
    assert_eq!(
        crate::handlers::sys_driver_register_typed(raw as u64, 0, 0, 0),
        0,
        "the looked-up handle was refused by the syscall it names"
    );
    assert!(azos_driver_server::driver_is_owner(KIND, TID));

    azos_driver_server::driver_unregister(KIND);
    ipc_task_pool::shim_kill(TID);
}

/// **The security property of the whole primitive, and its canary.**
///
/// A lookup that returns a handle for a capability the caller does not hold
/// IS a mint — it would hand out authority the boot never granted, which is
/// precisely what removing `SYS_CAP_GRANT` decided against. So the negative
/// is not a rounding-out of the positive above; it is the reason this syscall
/// is allowed to exist at all.
///
/// Three shapes of "not held", because they fail at different places: a kind
/// the table has none of, the right kind with the wrong resource index, and a
/// table that holds nothing.
///
/// **Canary.** Make `CapTable::lookup` ignore its `resource` argument and
/// return the first slot of the right kind: the middle assertion must go red.
#[test]
fn cap_lookup_never_answers_for_a_capability_the_task_does_not_hold() {
    use azos_abi::cap::CapKind;
    use azos_ipc::cap::CapPerms;
    const HELD: u32 = 0x9121;
    const NOT_HELD: u32 = 0x9122;
    const TID: u32 = 9121;
    const EMPTY_TID: u32 = 9122;
    let enoent = azos_abi::error::Errno::ENOENT.to_syscall_ret();

    let _g = serial();
    bind_typed_caller(TID, 21);
    azos_ipc::drvreg_cap::drvreg_grant_cap(TID, HELD, CapPerms::RW).expect("mint");

    // A kind this table holds nothing of.
    assert_eq!(
        crate::handlers::sys_cap_lookup(CapKind::Motor as u64, 0),
        enoent,
        "answered for a KIND the task holds none of"
    );
    // The right kind, a resource index never granted. This is the one a
    // resource-blind lookup would get wrong, and it is the same blindness
    // `holds_kind_with` had against `holds_kind_resource_with`.
    assert_eq!(
        crate::handlers::sys_cap_lookup(CapKind::DriverRegistry as u64, NOT_HELD as u64),
        enoent,
        "answered for a RESOURCE the task was never granted"
    );
    // A task whose table holds nothing at all.
    ipc_task_pool::shim_bind(EMPTY_TID, 22);
    azos_sched::set_current_task_tid(EMPTY_TID);
    assert_eq!(
        crate::handlers::sys_cap_lookup(CapKind::DriverRegistry as u64, HELD as u64),
        enoent,
        "answered from an empty table — a lookup that mints"
    );

    ipc_task_pool::shim_kill(TID);
    ipc_task_pool::shim_kill(EMPTY_TID);
}

/// A kind byte that is not a `CapKind` is `EINVAL`, not a match.
///
/// `CapKind::from_raw` has no catch-all arm, and this is the ABI edge where
/// that matters: 24..=255 are unpopulated, and aliasing any of them onto a
/// real kind would let a caller name a family by a number the enum does not
/// define. 24 (`Entropy`, wave 9 P9, 2026-09-28) is the highest defined kind
/// as of this writing.
#[test]
fn cap_lookup_refuses_a_kind_byte_that_names_no_kind() {
    let einval = azos_abi::error::Errno::EINVAL.to_syscall_ret();
    let _g = serial();
    bind_typed_caller(9123, 23);
    // 22 is `CapKind::Endpoint` (2026-09-19) and 23 is `CapKind::LinkKey`
    // (2026-09-26, U06-9), so neither belongs in this list any more. The
    // boundary moves with the enum: leaving a stale value here would keep the
    // test green only until something minted the kind it names, then assert
    // the opposite of what it is named for. 24 is `CapKind::Entropy` and 25
    // `CapKind::Lease` (both wave 9); 26 `CapKind::Pipe` and 27
    // `CapKind::Launch` (RFC-0055, wave 11); 28 `CapKind::Trace` (wave 15);
    // 29 is the first byte past the last variant today.
    for bad in [29u64, 63, 255, 256, u64::MAX] {
        assert_eq!(
            crate::handlers::sys_cap_lookup(bad, 0),
            einval,
            "kind byte {bad} was not refused"
        );
    }
    // And the positive half, so the boundary is not merely relaxed: 22 and 23
    // name real kinds now, so each must be refused for NOT HOLDING one, never
    // for being an unknown byte. Asserting only the negatives would let a
    // future widening of the enum pass silently.
    assert_eq!(
        crate::handlers::sys_cap_lookup(22, 0),
        azos_abi::error::Errno::ENOENT.to_syscall_ret(),
        "Endpoint (22) must be refused for HOLDING none (ENOENT), not for being \
         an unknown kind byte (EINVAL)",
    );
    assert_eq!(
        crate::handlers::sys_cap_lookup(23, 0),
        azos_abi::error::Errno::ENOENT.to_syscall_ret(),
        "LinkKey (23) must be refused for HOLDING none (ENOENT), not for being \
         an unknown kind byte (EINVAL)",
    );
    assert_eq!(
        crate::handlers::sys_cap_lookup(24, 0),
        azos_abi::error::Errno::ENOENT.to_syscall_ret(),
        "Entropy (24) must be refused for HOLDING none (ENOENT), not for being \
         an unknown kind byte (EINVAL)",
    );
    assert_eq!(
        crate::handlers::sys_cap_lookup(25, 0),
        azos_abi::error::Errno::ENOENT.to_syscall_ret(),
        "Lease (25) must be refused for HOLDING none (ENOENT), not for being \
         an unknown kind byte (EINVAL)",
    );
    ipc_task_pool::shim_kill(9123);
}
