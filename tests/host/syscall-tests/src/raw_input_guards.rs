// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for handlers whose reject paths run entirely inside real,
// pulled-in code (`copy_from_user`, size/length ceilings) before reaching a
// hardware call this crate cannot exercise. Each group below states exactly
// how far into the handler a test can go before the next call is a
// `todo!()` stub in one of `shims/*` — see the crate report for the full
// per-handler trace. None of the "not reachable beyond here" claims below
// are inferred: each was confirmed by grepping the relevant shim for
// `todo!()` and reading the call order in `handlers.rs`.

use super::harness::serial;
use crate::ipc_handlers::*;

/// Give the current test task the `Disk` capability, so the disk tests below
/// keep testing what they claim to test.
///
/// `sys_disk_read`/`sys_disk_write` gained a capability gate on 2026-09-05 —
/// they had none, and any ring-3 task could read every sector or overwrite
/// the partition table. The gate is the FIRST statement in each handler,
/// deliberately: running it after the bounds checks would let an unauthorised
/// caller map the medium's geometry by probing for the boundary between -1
/// and E_PERM.
///
/// That ordering is what made these five tests fail: they assert the bounds
/// checks, and without a capability they never reached them. Granting one is
/// the right fix rather than moving the gate — the bound and the permission
/// are separate properties and each deserves its own test. The refusal half
/// lives in `hw_cap_guards.rs`.
fn grant_disk(tid: u32) {
    use azos_abi::cap::{CapKind, CapPerms};
    /// The cap-store pool slot the disk tests bind their caller to. 22 and
    /// 51-59 are taken by other files in this crate.
    const SLOT: usize = 60;
    // Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
    // handlers ask this crate's `shims/sched` (see `gpio_typed_lock.rs`).
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    // `CapKind::Disk` names no object: the resource is 0, as `sys_disk_*` ask.
    assert!(azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(CapKind::Disk, CapPerms::RW, 0))
                .flatten()
                .is_some(),
            "could not grant the Disk capability the disk tests need");
}
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use azos_abi::error::Errno;

const SCRATCH: usize = 0x0050_0000;

fn fresh_user_pt(tid: u32) -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    pt
}

fn map_scratch(pt: usize, va: usize, flags: PagePerms) -> *mut u8 {
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, va, phys, flags).expect("map");
    phys as *mut u8
}

/// Map enough whole pages at `va` to cover `len` bytes. Needed for
/// `sys_exec`'s length-ceiling test: a range long enough to test the
/// ceiling meaningfully has to be FULLY mapped, or a rejection could be
/// (and, in a first draft of that test, was) about the unmapped tail rather
/// than about the length check under test.
fn map_range(pt: usize, va: usize, len: usize, flags: PagePerms) {
    let mut off = 0usize;
    while off < len {
        let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
        azos_mm::vmm::map(pt, va + off, phys, flags).expect("map");
        off += PAGE_SIZE;
    }
}

// ── SYS_DISK_WRITE ───────────────────────────────────────────────────────────
//
// `sys_disk_write` (`handlers.rs:560`) validates `buf`/`count`, computes
// `byte_len`, and THEN calls `copy_from_user` — all real code — before ever
// touching `azos_drv_virtio::virtio::blk::write`, which is `todo!()` in
// `shims/drivers` (that shim's own doc: "every function below is `todo!()`
// ... none of it is reachable from this crate's three test targets"). So
// every guard up to and including the pointer copy is reachable and
// testable; a call that clears all of them would panic here, so no test
// below constructs one — the positive control for this handler does not
// exist in this harness, and is recorded as absent rather than faked.

/// **The one independent guard of the three** (same finding as
/// `sys_disk_read`'s equivalent test, verified separately here because the
/// two handlers diverge sharply on what a removed guard actually reaches:
/// `sys_disk_write` calls `copy_from_user` before its `todo!()`, and with
/// the guard gone and `buf == 0` this becomes a raw kernel-context copy FROM
/// address 0 — `shims/sched`'s `copy_from_user` does an unchecked
/// `copy_nonoverlapping` when `current_user_pt() == 0`, so the mutant
/// SIGSEGVs instead of panicking cleanly. Confirmed in isolation; not run as
/// part of a mixed batch for exactly that reason.
#[test]
fn disk_write_refuses_a_null_buffer() {
    let _g = serial();
    assert_eq!(sys_disk_write(0, 1, 0, 0), -1);
}

/// **Not a discriminator**, same reasoning and same verification as
/// `sys_disk_read`'s equivalent test: `count == 0` is subsumed by the
/// `byte_len == 0` check two lines down.
#[test]
fn disk_write_refuses_a_zero_count() {
    let _g = serial();
    fresh_user_pt(1);
    grant_disk(1);
    assert_eq!(sys_disk_write(0, 0, SCRATCH as u64, 0), -1);
}

/// **Not a discriminator — checked and recorded as such.** `count >
/// DISK_MAX_SECTORS` was mutated away (kept `buf == 0 || count == 0`) and
/// this test still passed: `byte_len = count * 512` is checked against
/// `DISK_BOUNCE_BYTES` two lines down, and `DISK_BOUNCE_BYTES ==
/// DISK_MAX_SECTORS * 512` exactly, so for any `count` that does not
/// overflow the multiply the two checks reject the identical set of values.
/// Same shape as `mmap_guards.rs`'s subsumed `munmap` ceilings. Kept as a
/// regression test on the OBSERVABLE (`sys_disk_write` must refuse an
/// over-ceiling count), not as evidence this specific line is load-bearing.
#[test]
fn disk_write_refuses_a_count_over_the_sector_ceiling() {
    let _g = serial();
    fresh_user_pt(1);
    grant_disk(1);
    assert_eq!(sys_disk_write(0, 129, SCRATCH as u64, 0), -1); // DISK_MAX_SECTORS == 128
}

/// The pointer-validation half: `copy_from_user` runs before the `todo!()`
/// driver call, so an unmapped or straddling `buf` is fully testable and
/// must never reach it (a reachable `todo!()` would panic the test, not
/// return -1 -- so this also doubles as a proof that these inputs stay on
/// the guarded side).
#[test]
fn disk_write_refuses_an_unmapped_buffer() {
    let _g = serial();
    fresh_user_pt(1);
    grant_disk(1);
    assert_eq!(sys_disk_write(0, 1, SCRATCH as u64, 0), -1);
}

#[test]
fn disk_write_refuses_a_kernel_only_buffer() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    grant_disk(1);
    map_scratch(pt, SCRATCH, PagePerms::KERNEL_RW);
    assert_eq!(sys_disk_write(0, 1, SCRATCH as u64, 0), -1);
}

/// **Divergence:** a base-address-only validator agrees with the real
/// per-page `copy_from_user` on every pointer except one whose tail runs
/// into an unmapped page — a one-sector (512-byte) write that starts 1 byte
/// before the boundary is exactly that input.
#[test]
fn disk_write_refuses_a_buffer_that_straddles_into_an_unmapped_page() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    grant_disk(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);

    let bad_ptr = SCRATCH + PAGE_SIZE - 1; // 512 bytes, straddles by 511
    assert_eq!(sys_disk_write(0, 1, bad_ptr as u64, 0), -1);
}

// ── SYS_DISK_READ ────────────────────────────────────────────────────────────
//
// `sys_disk_read` (`handlers.rs:536`) has the OPPOSITE ordering from
// `sys_disk_write`: `copy_to_user` runs AFTER
// `azos_drv_virtio::virtio::blk::read`, which is the `todo!()`. So only the
// guards that return before that call are reachable — the pointer-copy half
// is not, and no test below constructs an input that would reach it.

/// **The one independent guard of the three.** Mutated away (the whole
/// `if buf == 0 || count == 0 || count > DISK_MAX_SECTORS` line) and run in
/// isolation: this is the only one of the three disjuncts whose removal is
/// actually observable from here — `count == 0` and `count >
/// DISK_MAX_SECTORS` are both subsumed by the `byte_len` check two lines
/// down (see the notes below), but `buf == 0` is not, because `byte_len`
/// never depends on `buf`. With the guard gone this input reaches
/// `virtio::blk::read`, `todo!()` in `shims/drivers`, and the test fails on
/// that panic — proof the guard is load-bearing here, not just present.
#[test]
fn disk_read_refuses_a_null_buffer() {
    let _g = serial();
    assert_eq!(sys_disk_read(0, 1, 0, 0), -1);
}

/// **Not a discriminator.** Mutated away together with the other two
/// disjuncts (see `disk_read_refuses_a_null_buffer`'s note): `count == 0`
/// makes `byte_len == 0`, which the very next line already rejects. Kept as
/// a regression test on the observable, not as evidence this disjunct is
/// load-bearing.
#[test]
fn disk_read_refuses_a_zero_count() {
    let _g = serial();
    assert_eq!(sys_disk_read(0, 0, SCRATCH as u64, 0), -1);
}

/// Same non-discriminator caveat as `sys_disk_write`'s equivalent test above
/// — `count > DISK_MAX_SECTORS` is subsumed by the `byte_len >
/// DISK_BOUNCE_BYTES` check two lines down. Verified by the same mutation.
#[test]
fn disk_read_refuses_a_count_over_the_sector_ceiling() {
    let _g = serial();
    assert_eq!(sys_disk_read(0, 129, SCRATCH as u64, 0), -1);
}

// **Untestable, recorded rather than skipped silently:**
//   * `count == DISK_MAX_SECTORS` exactly (the ceiling's inclusive boundary,
//     both handlers) — the accepted side runs into the `todo!()` driver call
//     in both `sys_disk_read` and `sys_disk_write`.
//   * `(count as usize).checked_mul(512)` — `count` is already bounded to
//     `<= DISK_MAX_SECTORS` (128) by the check one line above, so the
//     product is at most 65536 and the `checked_mul` can never see an
//     overflow. Confirmed by inspection (128 * 512 fits in a `usize` with
//     an enormous margin on every target this crate builds for); subsumed
//     the same way `munmap`'s redundant ceiling checks are in
//     `mmap_guards.rs`.
//   * `sys_disk_read`'s pointer-copy guard (`copy_to_user` for `buf`) — runs
//     after the `todo!()` driver call.
//   * `count > DISK_MAX_SECTORS` itself, in BOTH handlers — mutated away and
//     re-checked above: fully subsumed by the `byte_len > DISK_BOUNCE_BYTES`
//     check, which is exactly `count * 512 > DISK_MAX_SECTORS * 512`.

// ── SYS_DRV_INVOKE ───────────────────────────────────────────────────────────
//
// `sys_drv_invoke` (`handlers.rs:2375`) is fully reachable end to end: its
// only dependencies are the length ceilings, `copy_from_user`/`copy_to_user`
// (real), and `azos_drv_base::runtime::registry::REGISTRY` — the real,
// empty-in-production `Registry` (`shims/drivers`'s own doc: pulled in
// verbatim, "empty in production and only exercised by tests"). Nothing
// populates it here, so every kind reports `ENODEV` once past the pointer
// checks — which is exactly the observable that proves the copy ran.

use azos_abi::syscall_nr::{DRIVER_INVOKE_MAX_INPUT_BYTES, DRIVER_INVOKE_MAX_OUTPUT_BYTES};

/// Never registered in `azos_drv_base::runtime::registry::REGISTRY`,
/// which starts (and stays, in this harness) empty.
const UNUSED_DRV_KIND: u64 = 0xFFFF_0001;

#[test]
fn drv_invoke_refuses_an_oversized_input_length() {
    let _g = serial();
    assert_eq!(
        sys_drv_invoke(UNUSED_DRV_KIND, 0, 0x1000, (DRIVER_INVOKE_MAX_INPUT_BYTES + 1) as u64, 0, 0),
        Errno::EINVAL.to_syscall_ret()
    );
}

#[test]
fn drv_invoke_refuses_an_oversized_output_capacity() {
    let _g = serial();
    assert_eq!(
        sys_drv_invoke(UNUSED_DRV_KIND, 0, 0, 0, 0x1000, (DRIVER_INVOKE_MAX_OUTPUT_BYTES + 1) as u64),
        Errno::EINVAL.to_syscall_ret()
    );
}

/// **Divergence:** `in_len` sits at the ceiling (accepted by the size check
/// above), so this exercises the copy itself, not the length guard. A
/// base-address-only validator would accept this pointer; the real per-page
/// walk must not.
#[test]
fn drv_invoke_refuses_an_input_pointer_that_straddles_into_an_unmapped_page() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);

    let n = DRIVER_INVOKE_MAX_INPUT_BYTES;
    let ptr = SCRATCH + PAGE_SIZE - 1; // guaranteed to straddle for any n > 1
    assert_eq!(
        sys_drv_invoke(UNUSED_DRV_KIND, 0, ptr as u64, n as u64, 0, 0),
        Errno::EFAULT.to_syscall_ret()
    );
}

/// Positive control for the copy: a fully mapped input of exactly the
/// ceiling length is accepted (no `EFAULT`), and since `REGISTRY` is empty,
/// the call proceeds to "no such driver" -- `ENODEV`. If the copy were
/// short-circuited or skipped, this would still read `ENODEV`, so the
/// discriminating half is the straddle test above; this one exists to show
/// the accepted side is not itself broken (e.g. it must not read `EINVAL`
/// or panic).
#[test]
fn drv_invoke_accepts_a_full_ceiling_input_and_reports_no_such_driver() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);

    let n = DRIVER_INVOKE_MAX_INPUT_BYTES;
    assert_eq!(
        sys_drv_invoke(UNUSED_DRV_KIND, 0, SCRATCH as u64, n as u64, 0, 0),
        Errno::ENODEV.to_syscall_ret()
    );
}

#[test]
fn drv_invoke_refuses_a_kernel_task_calling_with_zero_length_and_reports_no_such_driver() {
    // Sanity control for the in_len == 0 path (no copy at all): a kernel
    // caller (current_user_pt() == 0, the default from `serial()`) must
    // reach the same registry lookup, not a different code path.
    let _g = serial();
    assert_eq!(sys_drv_invoke(UNUSED_DRV_KIND, 0, 0, 0, 0, 0), Errno::ENODEV.to_syscall_ret());
}

// **Not reached from this harness at all:** the arm past a successful
// registry lookup (`drv_invoke_authorized`, `handle_request`, and the
// output `copy_to_user`) needs a real `&dyn Driver` in `REGISTRY`, which
// nothing in this crate constructs -- building one would mean writing a
// fake `Driver` impl, which is scaffolding for its own sake given the
// property under test (pointer/length validation) is already fully
// exercised by the tests above.

// ── SYS_EXEC ─────────────────────────────────────────────────────────────────
//
// `sys_exec` (`handlers.rs:221`) checks `data_ptr`/`len`, then `len >
// EXEC_MAX_BYTES`, then `copy_from_user` — all real — before calling
// `azos_sched::exec_user`, which is `todo!()` in `shims/sched`
// ("not reached by any test in this crate"). So, like `sys_disk_write`,
// every guard through the pointer copy is reachable; the accepted side
// (a real ELF, correctly sized and mapped) is not, and no test below
// constructs one.

const EXEC_MAX_BYTES: u64 = 128 * 1024;

#[test]
fn exec_refuses_a_null_data_pointer() {
    let _g = serial();
    assert_eq!(sys_exec(0, 16), -1);
}

#[test]
fn exec_refuses_a_zero_length() {
    let _g = serial();
    fresh_user_pt(1);
    assert_eq!(sys_exec(SCRATCH as u64, 0), -1);
}

/// **Divergence:** the mutant is `len >= EXEC_MAX_BYTES`, differing only at
/// `len == EXEC_MAX_BYTES` -- which must be ACCEPTED, and acceptance runs
/// into `copy_from_user` and then `exec_user` (`todo!()`). That boundary is
/// therefore untestable from this harness; only the reject side
/// (`EXEC_MAX_BYTES + 1`) is asserted, and this is recorded as an untested
/// guard rather than shipped as a full pair.
///
/// **The whole range is mapped, not just its start — and this matters more
/// than it looks.** A first draft of this test called `sys_exec` against an
/// unmapped `SCRATCH` and passed even with this ceiling check deleted
/// (confirmed by mutation): it was really re-testing
/// `exec_refuses_an_unmapped_data_pointer`, not the ceiling. With the
/// destination fully backed, deleting the ceiling instead lets
/// `copy_from_user` succeed for `EXEC_MAX_BYTES + 1` bytes and the function
/// falls through to `azos_sched::exec_user(&buf[..len])`, where `buf` is
/// the fixed `EXEC_BOUNCE: [u8; EXEC_MAX_BYTES]` -- `&buf[..131073]` on a
/// 131072-byte array is a slice-bounds panic. Confirmed by mutation: that is
/// exactly what fires, before `exec_user` is even called. `panic = "abort"`
/// on the real target turns that into a board reset, so this ceiling is not
/// a soft sanity check on ELF size — it is the only thing stopping an
/// in-bounds copy into an out-of-bounds slice of a real kernel buffer.
#[test]
fn exec_refuses_a_length_over_the_ceiling() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    let len = (EXEC_MAX_BYTES + 1) as usize;
    map_range(pt, SCRATCH, len, PagePerms::USER_RW);
    assert_eq!(sys_exec(SCRATCH as u64, EXEC_MAX_BYTES + 1), -1);
}

#[test]
fn exec_refuses_an_unmapped_data_pointer() {
    let _g = serial();
    fresh_user_pt(1);
    assert_eq!(sys_exec(SCRATCH as u64, 16), -1);
}

#[test]
fn exec_refuses_a_kernel_only_data_pointer() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::KERNEL_RW);
    assert_eq!(sys_exec(SCRATCH as u64, 16), -1);
}

/// **Divergence:** same base-address-only-validator mutant as everywhere
/// else in this crate; the one input it gets wrong is a range whose tail
/// crosses into an unmapped page.
#[test]
fn exec_refuses_data_that_straddles_into_an_unmapped_page() {
    let _g = serial();
    let pt = fresh_user_pt(1);
    map_scratch(pt, SCRATCH, PagePerms::USER_RW);
    assert_eq!(azos_mm::vmm::translate_user(pt, SCRATCH + PAGE_SIZE, false), None);

    let bad_ptr = SCRATCH + PAGE_SIZE - 15;
    assert_eq!(sys_exec(bad_ptr as u64, 16), -1);
}

// ── SYS_IORING_CREATE_TYPED ──────────────────────────────────────────────────
//
// **Not reachable beyond its null-pointer guard, for a reason worth
// recording explicitly.** `sys_ioring_create_typed` (`crates/core/syscall/src/ipc_handlers.rs`)
// calls `azos_ipc::io_ring::io_ring_create_cap`, whose first action
// (`crates/core/ipc/src/io_ring.rs`'s `io_ring_create`, pulled in real) is an
// UNCONDITIONAL `azos_sched::current_user_pt()` call. From inside
// `shims/ipc`, that name resolves to `shims/ipc_sched`'s OWN
// `current_user_pt`, which is `todo!()` there (its module doc: reachable
// only from a `#[cfg(not(test))]` arm of `channel.rs` that never runs under
// `cargo test` -- but `io_ring.rs`'s call is NOT behind any such cfg, so
// this path panics unconditionally). This is a real gap in the shim, not in
// `handlers.rs`, and is flagged separately rather than silently worked
// around with a fake page-table setup that would not exist on the real
// path either.
#[test]
fn ioring_create_refuses_a_null_pointer() {
    let _g = serial();
    assert_eq!(sys_ioring_create_typed(0), Errno::EINVAL.to_syscall_ret());
}

/// Defects the 2026-09-19 user-pointer audit found, each pinned so it cannot
/// come back. These are source-text assertions where the behaviour needs two
/// harts (which this host harness cannot make) and value assertions where it
/// does not.
#[cfg(test)]
mod audit_2026_09_19 {
    const HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");

    /// Comments stripped: a comment that quotes a pattern is not code.
    fn code(src: &str) -> String {
        src.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n")
    }

    /// **The disk bounce buffers must stay behind a lock held across the copy.**
    ///
    /// They were `static mut` taken by `addr_of_mut!`, with a SAFETY comment
    /// claiming syscalls run with preemption disabled — nothing does that — and
    /// `blk::read` releases `BLK_LOCK` before the handler copies out. Two harts
    /// raced: one filled the buffer, the other overwrote it, the first copied
    /// the other's sectors to its caller. On the write side the wrong bytes
    /// reached the sector, and the sectors under the partition table are the
    /// flight recorder and the boot image.
    ///
    /// Two harts are what it takes to observe, and this harness has one, so the
    /// assertion is on the shape: no unsynchronised `static mut` buffer in the
    /// syscall surface at all. That is the class, not the instance.
    #[test]
    fn no_syscall_handler_keeps_an_unsynchronised_static_mut_buffer() {
        let c = code(HANDLERS);
        let offenders: Vec<&str> = c
            .lines()
            .filter(|l| l.contains("static mut ") && (l.contains("[u8;") || l.contains("BUF") || l.contains("BOUNCE")))
            .collect();
        assert!(
            offenders.is_empty(),
            "a shared mutable buffer with no lock is back in the syscall surface; \
             use a `PiMutex` held across BOTH the driver call and the copy, as \
             `DISK_RD_BUF` and `CAM_BUF` do: {offenders:?}"
        );
        assert!(c.contains("static DISK_RD_BUF: PiMutex<"), "the read bounce lost its lock");
        assert!(c.contains("static DISK_WR_BUF: PiMutex<"), "the write bounce lost its lock");
    }

    /// **Clamp in the wide type, then narrow.** `(x as u16).min(LIMIT)` cannot
    /// clamp what the cast already wrapped: `0x1_0000` arrived as 0 and was
    /// reported as success — a 0 Hz buzzer tone and a 0-byte reply capacity.
    #[test]
    fn register_arguments_are_clamped_before_they_are_narrowed() {
        let c = code(HANDLERS);
        for pat in ["(freq_hz as u16)", "(out_cap as u16)"] {
            assert!(
                !c.contains(pat),
                "{pat} narrows before clamping: a value past u16 wraps to a small \
                 one and the .min() below can no longer see it"
            );
        }
        assert!(c.contains("freq_hz.min(MAX_BUZZER_FREQ_HZ as u64) as u16"));
        // The `out_cap` clamp lived in `sys_driver_request`, retired with 526
        // in wave 11 (OVSwrap review F3); the negative check above still keeps
        // the narrow-first shape out.
    }

    /// **A zero length is not a valid name.** `copy_from_user` answers `true`
    /// for `len == 0` before walking anything, so `SYS_DRV_REGISTER` registered
    /// a driver under an empty name from a null pointer and reported success.
    ///
    /// The body left `dispatch.rs` for `handlers::sys_drv_register` in wave 7;
    /// `drv_calls.rs` now drives it with a null pointer and a zero length. The
    /// order check stays here: the real registry refuses an empty name on its
    /// own, so a guard moved after the copy would not change any return value.
    #[test]
    fn drv_register_refuses_a_null_pointer_and_a_zero_length() {
        let c = code(HANDLERS);
        let at = c.find("pub fn sys_drv_register(").expect("the handler moved");
        let arm = &c[at..at + 500];
        let guard = arm.find("name_len == 0 || name_ptr == 0").expect(
            "SYS_DRV_REGISTER accepts a null name again — `SYS_DNS_RESOLVE` has \
             had this guard all along",
        );
        let copy = arm.find("copy_from_user").expect("the copy moved");
        assert!(guard < copy, "the guard must run BEFORE the copy");
    }
}
