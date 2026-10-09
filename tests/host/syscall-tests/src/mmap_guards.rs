// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the pointer/length guards in `sys_mmap` and `sys_munmap`
// (`crates/core/syscall/src/handlers.rs:1133` and `:1235`).
//
// **WHY these two.** They take a raw address and a raw length straight out of
// a0/a1 with no ABI narrowing, and both have already reset the board:
// `munmap(0x1000_0000, 4096)` zeroed the UART's PTE for every hart, and
// `mmap(0, u64::MAX, ..)` drained physical memory with no unwind. With
// `panic = "abort"` and `overflow-checks = true`, an arithmetic mistake in
// here is not an error return, it is a reset with the actuators energised.
//
// **These run against the real Sv39 walker**, not a model — `azos_mm`
// here is `crates/core/mm/src/{addr,pmm,vmm,cow,demand}.rs` pulled in whole over a
// leaked host arena. See `shims/mm/src/lib.rs` for why a model was rejected.
//
// Every test states the input at which the guard's plausible mutant DIFFERS
// from the guard. Where no such input is reachable, that is recorded in a
// comment and no test is written: a test that samples where the correct and
// broken versions agree passes against its own mutant and proves nothing.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;

/// Anonymous-mapping fd, as `sys_mmap` spells it.
const ANON: u64 = u64::MAX;

/// The kernel-mapped MMIO windows that sit BELOW `USER_VA_TOP`, in VPN[2]=0
/// — the slot every user page table shares with the kernel's. Bases from
/// `crates/drivers/base/src/platform.rs`'s qemu arm; losing the UART kills
/// `kprintln!`, the CLINT kills the timer tick, the PLIC kills device IRQs.
const CLINT: usize = 0x0200_0000;
const PLIC: usize = 0x0C00_0000;
const UART: usize = 0x1000_0000;

/// A fresh, empty user page table, installed as the current one.
///
/// `pmm::alloc_page` rather than `vmm::create_pagetable` on purpose:
/// `create_pagetable` registers the root in `vmm`'s 128-slot `PT_META` array,
/// which `shim_reset` (a `pmm::init`) does not clear — so a per-test root
/// would burn a metadata slot per test and start failing partway through the
/// suite for a reason that has nothing to do with what is under test. Nothing
/// on the mmap/munmap path consults `PT_META`.
fn fresh_user_pt() -> usize {
    // Wave 14 (DEMANDPAGE): the previous root's regions go first; roots here
    // are never torn down, and dead ones would fill the region table.
    let old = azos_sched::current_user_pt();
    if old != 0 {
        azos_mm::pager::forget(old);
    }
    azos_sched::shim_set_sched_class(3);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::pager::forget(pt);
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    // Owner decision 102 — clear the frame budget HERE, not in the tests that
    // set one.
    //
    // The shim's limit is a process-wide static. A test that sets one and then
    // fails an assertion never reaches its own cleanup, and the next test maps
    // into a budget it never asked for: the first version of the budget tests
    // turned two unrelated `mmap` tests red the moment their own canary fired.
    // Resetting on every entry makes a leaked limit unreachable instead of
    // merely unlikely — the same reason `serial()` is taken by every test here
    // rather than by the ones that happen to race.
    azos_sched::shim_set_page_limit(0);
    // RFC-0049 M1c: same reasoning for the lock.
    azos_sched::shim_set_mem_locked(false);
    pt
}

/// A page of the arena, to point a PTE at.
fn a_page() -> usize {
    azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize()
}

// ── sys_mmap ───────────────────────────────────────────────────────────────

/// A kernel task (`user_pt == 0`) has no user address space to map into.
/// Without this check the handler would walk page table 0 — a null
/// dereference in S-mode, i.e. a reset.
#[test]
fn mmap_refuses_a_kernel_caller() {
    let _g = serial();
    azos_sched::shim_set_brk(0x1_0000);
    // user_pt is 0 from `serial()`.
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), -1);
}

/// **Divergence:** with the `len == 0` check removed, `num_pages` is 0, the
/// mapping loop runs zero times, and the handler *succeeds*, returning the
/// aligned break as the base of a zero-page allocation. The mutant returns a
/// non-negative address where the original returns -1, so this is asserted at
/// the one input where they differ.
#[test]
fn mmap_refuses_a_zero_length() {
    let _g = serial();
    fresh_user_pt();
    azos_sched::shim_set_brk(0x1_0000);
    assert_eq!(sys_mmap(0, 0, 3, 0, ANON, 0), -1);
    assert_eq!(azos_sched::update_user_brk(0), 0x1_0000, "a refused mmap must not move the break");
}

/// The null-brk refusal (`base < USER_GUARD_LIMIT`).
///
/// **Divergence:** the mutant is `<=`, which differs from `<` at exactly one
/// input — `base == USER_GUARD_LIMIT`. So the test that matters is the
/// *positive* one: a break sitting exactly on the guard limit must be
/// accepted. `base == 0` is asserted too because it is the defect the check
/// was written for (a task whose break was never initialised got a
/// successful allocation whose base was the null pointer), but on its own it
/// would not distinguish `<` from `<=`.
#[test]
fn mmap_null_brk_refusal_stops_exactly_at_the_guard_limit() {
    let _g = serial();
    fresh_user_pt();

    azos_sched::shim_set_brk(0);
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), -1, "a null break is not an address");

    azos_sched::shim_set_brk((azos_mm::vmm::USER_GUARD_LIMIT - 1) as u64);
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), -1);

    azos_sched::shim_set_brk(azos_mm::vmm::USER_GUARD_LIMIT as u64);
    assert_eq!(
        sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0),
        azos_mm::vmm::USER_GUARD_LIMIT as i64,
        "a break exactly at the guard limit is the lowest legitimate one, not the highest illegitimate one"
    );
}

/// `PROT_EXEC` is refused with `-EINVAL`, on a call that would otherwise map.
///
/// **Divergence:** without the check, the `prot = 4` call maps a page and
/// returns its base. `prot = 0` and `prot = 3` (read | write) are the positive
/// controls: a check that refused every non-zero `prot`, or every call, fails
/// them. The refused call must also leave the break where it was, so the next
/// call's base is the one a first call gets.
///
/// **Canary.** Delete the `MMAP_PROT_EXEC` check: the first assertion reads the
/// mapped base instead of `-EINVAL`.
#[test]
fn mmap_refuses_prot_exec_and_still_maps_read_write() {
    let _g = serial();
    fresh_user_pt();
    let base = azos_mm::vmm::USER_GUARD_LIMIT;
    azos_sched::shim_set_brk(base as u64);

    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, MMAP_PROT_EXEC, 0, ANON, 0), -22, "PROT_EXEC alone");
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 7, 0, ANON, 0), -22, "read | write | exec");
    assert_eq!(azos_sched::update_user_brk(0), base as u64, "a refused mmap must not move the break");

    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), base as i64, "read | write maps");
    assert_eq!(
        sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0),
        (base + PAGE_SIZE) as i64,
        "read | write still maps"
    );
}

/// **`prot` is exact (wave 13, security).** `PROT_READ` maps a page a write
/// cannot reach (it used to be read-write whatever `prot` said); `0` reserves
/// the range and maps nothing. **Canary.** `--features mmap-prot-canary`: the
/// read-only page translates for a write.
#[test]
fn mmap_honours_prot_read_and_prot_none() {
    let _g = serial();
    let pt = fresh_user_pt();
    let base = azos_mm::vmm::USER_GUARD_LIMIT;
    azos_sched::shim_set_brk(base as u64);
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 1, 0, ANON, 0), base as i64, "PROT_READ maps");
    assert!(azos_mm::vmm::translate_user(pt, base, false).is_some(), "readable");
    assert_eq!(azos_mm::vmm::translate_user(pt, base, true), None, "not writable");
    let none = base + PAGE_SIZE;
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 0, 0, ANON, 0), none as i64, "PROT_NONE reserves");
    assert_eq!(azos_mm::vmm::user_page(pt, none), azos_mm::vmm::UserPage::Missing, "and maps nothing");
    assert_eq!(azos_sched::update_user_brk(0), (none + PAGE_SIZE) as u64, "the break moved past it");
}

// ── Owner decision 102 — the per-task frame budget ───────────────────────
//
// Scan unit 3 finding 3: CPU had quotas, memory had none, and one ring-3 task
// could walk `brk`/`mmap` until the allocator was empty — taking the kernel
// heap, the copy-on-write break and every allocating safety path with it.
//
// These test the WIRING in `handlers.rs`: that `sys_mmap` charges before it
// allocates and refuses over budget, and that `sys_munmap` gives back what it
// actually freed. The counter itself is the shim's stand-in for `Task::
// user_pages`; its semantics are transcribed beside it and must not drift.
//
// The gate's live row carries only the NEGATIVE half — "the ceiling is not in
// the way of real programs". This is the positive half, and without it a
// budget that never refuses anything would be indistinguishable from a budget
// that is not wired at all.

/// **Canary.** Delete the `mm_charge` call in `sys_mmap`: the over-budget
/// request succeeds and the first assertion reads a base instead of `-1`.
#[test]
fn mmap_refuses_a_request_that_would_exceed_the_frame_budget() {
    let _g = serial();
    fresh_user_pt();
    let base = azos_mm::vmm::USER_GUARD_LIMIT;
    azos_sched::shim_set_brk(base as u64);
    azos_sched::shim_set_page_limit(4);

    // One page over. Refused whole — `mmap` returns a single contiguous range
    // and a caller that asked for five pages cannot use four.
    assert_eq!(
        sys_mmap(0, (5 * PAGE_SIZE) as u64, 3, 0, ANON, 0), -1,
        "a request past the budget must be refused"
    );
    assert_eq!(
        azos_sched::shim_user_pages(), 0,
        "a refused request must charge NOTHING — a partial charge describes \
         memory the caller did not get, and ratchets the task toward a \
         standstill one refusal at a time"
    );
    assert_eq!(
        azos_sched::update_user_brk(0), base as u64,
        "a refused mmap must not move the break"
    );

    // Exactly at the budget still works: the ceiling is inclusive, and a test
    // that only ever saw refusals could not tell a working budget from one
    // wired to refuse everything.
    assert_eq!(
        sys_mmap(0, (4 * PAGE_SIZE) as u64, 3, 0, ANON, 0), base as i64,
        "a request that exactly fills the budget must succeed"
    );
    assert_eq!(azos_sched::shim_user_pages(), 4);

    // And now nothing more fits, which proves the charge PERSISTED rather than
    // being evaluated against an empty counter each time.
    assert_eq!(
        sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), -1,
        "the budget is spent — one more page must be refused"
    );

    azos_sched::shim_set_page_limit(0);
}

/// **Canary.** Delete the `mm_discharge` call in `sys_munmap`: the second
/// `mmap` is refused because the budget never came back.
#[test]
fn munmap_gives_the_frames_back_to_the_budget() {
    let _g = serial();
    fresh_user_pt();
    let base = azos_mm::vmm::USER_GUARD_LIMIT;
    azos_sched::shim_set_brk(base as u64);
    azos_sched::shim_set_page_limit(4);

    assert_eq!(sys_mmap(0, (4 * PAGE_SIZE) as u64, 3, 0, ANON, 0), base as i64);
    assert_eq!(azos_sched::shim_user_pages(), 4);

    assert_eq!(sys_munmap(base as u64, (4 * PAGE_SIZE) as u64), 0);
    assert_eq!(
        azos_sched::shim_user_pages(), 0,
        "munmap freed four frames and must discharge four. Over-counting is \
         the dangerous direction: a long-lived task that maps and unmaps in a \
         loop would ratchet to a standstill, and on this board that task may \
         be the one driving the motors."
    );

    // The real assertion: the budget is usable again.
    assert_eq!(
        sys_mmap(0, (4 * PAGE_SIZE) as u64, 3, 0, ANON, 0) > 0, true,
        "the frames came back to the allocator but not to the budget"
    );

    azos_sched::shim_set_page_limit(0);
}

/// The VA ceiling: a mapping ends at or below the base of the shm/MMIO window.
/// Above `USER_VA_TOP` the "user" page table is the kernel's, so a USER_RW page
/// there is a user-writable window into kernel address space. The shm/MMIO
/// window lies below that, and a frame mapped inside it is never freed
/// (`sys_munmap` and teardown skip the window).
///
/// **Divergence:** the mutant `>=` differs only when the mapping ends flush
/// against the window base, which must SUCCEED; the old ceiling `USER_VA_TOP`
/// differs when it ends one page past the base, which must be refused. The
/// refusal is asserted first: after the accepted call the page below the base
/// is mapped, and a call over it could then fail for that reason alone.
#[test]
fn mmap_va_ceiling_is_exclusive_at_the_top_and_inclusive_below_it() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (window_base, _) = azos_sched::user_shm_window();

    // One byte more than a page needs a second page, which lies in the window.
    azos_sched::shim_set_brk((window_base - PAGE_SIZE) as u64);
    assert_eq!(sys_mmap(0, PAGE_SIZE as u64 + 1, 3, 0, ANON, 0), -1);
    assert_eq!(azos_mm::vmm::translate_user(pt, window_base, false), None);

    azos_sched::shim_set_brk((window_base - PAGE_SIZE) as u64);
    assert_eq!(
        sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0),
        (window_base - PAGE_SIZE) as i64,
        "a mapping whose last byte is the last one below the window must be allowed"
    );
    assert_eq!(azos_mm::vmm::translate_user(pt, window_base, false), None);
}

/// The length ceiling (`len > MAX_DEMAND_ALLOC_BYTES`).
///
/// **Divergence:** the mutant is `>=`, differing only at `len == MAX`. The
/// only way to tell them apart is for a request of exactly `MAX` to succeed,
/// which is why `shims/mm` sizes its arena to back 16,384 pages.
#[test]
fn mmap_length_ceiling_is_inclusive() {
    let _g = serial();
    fresh_user_pt();
    let max = azos_mm::demand::MAX_DEMAND_ALLOC_BYTES;

    azos_sched::shim_set_brk(0x1_0000);
    assert_eq!(
        sys_mmap(0, max as u64, 3, 0, ANON, 0),
        0x1_0000,
        "a request of exactly MAX_DEMAND_ALLOC_BYTES is at the ceiling, not over it"
    );

    // Second half needs a clean arena; `serial()` is already held (and is not
    // reentrant), so reset without re-locking.
    super::harness::reset_state();
    fresh_user_pt();
    azos_sched::shim_set_brk(0x1_0000);
    assert_eq!(sys_mmap(0, max as u64 + 1, 3, 0, ANON, 0), -1);
}

/// `base.saturating_add(page_size - 1)` with the break at the very top of the
/// address space.
///
/// **Divergence:** replace the `saturating_add` with `+` and this input
/// panics under `overflow-checks` — which, with `panic = "abort"`, is a board
/// reset. A panic fails the test, so the mutant is caught. The original must
/// return a clean -1.
///
/// **Reachability caveat, stated rather than implied:** this drives the break
/// directly through the shim. Whether the real scheduler can be made to hold
/// `user_brk == u64::MAX` is a `crates/core/sched` question this crate does not
/// answer. The guard is still the right shape — it is the only thing between
/// a hostile break value and an abort.
#[test]
fn mmap_survives_a_break_at_the_top_of_the_address_space() {
    let _g = serial();
    fresh_user_pt();
    for brk in [u64::MAX, u64::MAX - 1, (usize::MAX & !(PAGE_SIZE - 1)) as u64] {
        azos_sched::shim_set_brk(brk);
        assert_eq!(sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), -1, "brk = {brk:#x}");
    }
}

/// A hostile length must not be able to leave physical pages stranded.
///
/// The recorded defect: "the OOM path below returned without unwinding, so
/// the pages already mapped stayed lost for the lifetime of the boot." This
/// drains the arena to a known margin, asks for far more than remains, and
/// checks the pages came back.
///
/// **Divergence:** delete the `mmap_unwind` call in the `Err(_)` arm and the
/// ~1,000 pages mapped before the allocator ran dry are never freed —
/// `shim_pages_in_use()` ends about a thousand higher. The slack in the
/// assertion is for the intermediate page-table pages `vmm::walk` allocates,
/// which `mmap_unwind` deliberately does NOT free (they are still valid
/// tables); a thousand-page leak clears that slack by more than an order of
/// magnitude.
#[test]
fn a_failed_mmap_leaves_no_physical_pages_stranded() {
    let _g = serial();
    fresh_user_pt();
    azos_sched::shim_set_brk(0x1_0000);

    // Drain the arena down to ~1,000 free pages.
    let mut ballast = Vec::new();
    while azos_mm::pmm::free_pages() > 1000 {
        ballast.push(azos_mm::pmm::alloc_page().expect("drain"));
    }
    let before = azos_mm::shim_pages_in_use();

    // Ask for the full ceiling: 16,384 pages, of which only ~1,000 exist.
    // Wave 14 (DEMANDPAGE): committed at map time (`MAP_POPULATE`, 0x8000),
    // the path this row is about; a plain `mmap` now only reserves, and a
    // reservation needs no frame to succeed.
    let max = azos_mm::demand::MAX_DEMAND_ALLOC_BYTES;
    assert_eq!(sys_mmap(0, max as u64, 3, MMAP_MAP_POPULATE, ANON, 0), -1, "must fail: the arena cannot back it");

    let after = azos_mm::shim_pages_in_use();
    assert!(
        after <= before + 64,
        "a failed mmap stranded {} pages (before {before}, after {after})",
        after - before
    );
    assert_eq!(
        azos_sched::update_user_brk(0),
        0x1_0000,
        "a failed mmap must not have advanced the break"
    );
    drop(ballast);
}

// ── sys_munmap ─────────────────────────────────────────────────────────────

/// Same reasoning as `mmap_refuses_a_kernel_caller`.
#[test]
fn munmap_refuses_a_kernel_caller() {
    let _g = serial();
    assert_eq!(sys_munmap(0x1_0000, PAGE_SIZE as u64), -1);
}

/// **Divergence:** with the `len == 0` check removed, `rounded` is 0, `end`
/// equals `start`, the loop runs zero times and the handler returns 0 —
/// success — for a request that unmapped nothing. The mutant returns 0 where
/// the original returns -1.
#[test]
fn munmap_refuses_a_zero_length() {
    let _g = serial();
    fresh_user_pt();
    assert_eq!(sys_munmap(0x1_0000, 0), -1);
}

/// The VA ceiling on the *end* of the range (`Some(e) if e <= USER_VA_TOP`).
///
/// **Divergence:** the mutant is `<`, differing only when
/// `end == USER_VA_TOP` exactly — a range whose last byte is the last user
/// byte. That must succeed, so this asserts `0`, not `-1`. Written the other
/// way round (asserting a failure) the test would pass against every mutant.
#[test]
fn munmap_end_ceiling_is_inclusive() {
    let _g = serial();
    let pt = fresh_user_pt();
    let phys = a_page();
    azos_mm::vmm::map(pt, USER_VA_TOP - PAGE_SIZE, phys, PagePerms::USER_RW).unwrap();

    assert_eq!(
        sys_munmap((USER_VA_TOP - PAGE_SIZE) as u64, 1),
        0,
        "a range ending flush against the ceiling is inside the user half, not outside it"
    );
    assert_eq!(
        azos_mm::vmm::translate_user(pt, USER_VA_TOP - PAGE_SIZE, false),
        None,
        "and it really was unmapped, not merely reported as such"
    );
}

/// A range that starts inside the user half and ends above it. This is the
/// partial-validation shape: the *base* is perfectly valid, and only the end
/// is out of bounds.
///
/// **Divergence:** delete the `e <= USER_VA_TOP` arm and the loop walks past
/// the ceiling and zeroes the PTE installed at `USER_VA_TOP` below — which,
/// in the kernel, is a PTE reached through tables the kernel shares. So this
/// asserts on the *survival of the page above the ceiling*, not just on the
/// return value: a mutant that returned -1 for some other reason but still
/// unmapped would be caught.
#[test]
fn munmap_refuses_a_range_whose_end_crosses_the_ceiling() {
    let _g = serial();
    let pt = fresh_user_pt();
    let below = a_page();
    let above = a_page();
    azos_mm::vmm::map(pt, USER_VA_TOP - PAGE_SIZE, below, PagePerms::USER_RW).unwrap();
    // A page just above the ceiling, marked USER so `translate_user` can see
    // it: standing in for the kernel PTE that lives there for real.
    azos_mm::vmm::map(pt, USER_VA_TOP, above, PagePerms::USER_RW).unwrap();

    assert_eq!(sys_munmap((USER_VA_TOP - PAGE_SIZE) as u64, PAGE_SIZE as u64 + 1), -1);
    assert_eq!(
        azos_mm::vmm::translate_user(pt, USER_VA_TOP, false),
        Some(above),
        "the page above the ceiling must be untouched"
    );
    assert_eq!(
        azos_mm::vmm::translate_user(pt, USER_VA_TOP - PAGE_SIZE, false),
        Some(below),
        "a refused munmap must unmap nothing at all, not just stop at the boundary"
    );
}

/// The length ceiling (`len > MAX_DEMAND_ALLOC_BYTES`).
///
/// **Divergence:** the mutant is `>=`, differing only at `len == MAX`, which
/// must succeed. Note the base: `MAX` is 64 MiB, so the range has to start
/// low enough that its end still clears `USER_VA_TOP`.
#[test]
fn munmap_length_ceiling_is_inclusive() {
    let _g = serial();
    let pt = fresh_user_pt();
    let max = azos_mm::demand::MAX_DEMAND_ALLOC_BYTES;
    let phys = a_page();
    azos_mm::vmm::map(pt, 0x0100_0000, phys, PagePerms::USER_RW).unwrap();

    assert_eq!(sys_munmap(0x0100_0000, max as u64), 0);
    assert_eq!(azos_mm::vmm::translate_user(pt, 0x0100_0000, false), None);

    assert_eq!(sys_munmap(0x0100_0000, max as u64 + 1), -1);
}

/// The hostile-input sweep: the values a ring-3 caller actually reaches for.
/// Every one must be a clean -1. A panic here is a board reset, and
/// `length = u64::MAX` specifically used to be an unkillable hang — the old
/// `saturating_add` clamped `end` to `usize::MAX` and the loop ran ~2^52
/// iterations inside the kernel with interrupts on and no way out.
///
/// This test is a *survival* assertion (no panic, no hang, no unmapping),
/// not a mutation discriminator: see the note below on which of the two
/// ceilings each of these actually trips.
#[test]
fn munmap_survives_every_extreme_argument() {
    let _g = serial();
    let pt = fresh_user_pt();
    let phys = a_page();
    azos_mm::vmm::map(pt, 0x0100_0000, phys, PagePerms::USER_RW).unwrap();

    for (addr, len) in [
        (u64::MAX, u64::MAX),
        (u64::MAX, 1u64),
        (0u64, u64::MAX),
        (0x0100_0000u64, u64::MAX),
        // The base is one byte below the top of the address space, so the
        // page-align-down and the `checked_add` both sit on the edge.
        (u64::MAX - 1, PAGE_SIZE as u64),
        (USER_VA_TOP as u64, PAGE_SIZE as u64),
        // NOT `USER_VA_TOP - 1`: that aligns down to the last user page and
        // ends flush against the ceiling, which is *accepted* — see
        // `munmap_end_ceiling_is_inclusive`. A first draft asserted -1 there
        // and failed, which is the boundary doing its job.
    ] {
        assert_eq!(sys_munmap(addr, len), -1, "munmap({addr:#x}, {len:#x})");
    }
    assert_eq!(
        azos_mm::vmm::translate_user(pt, 0x0100_0000, false),
        Some(phys),
        "no refused call may unmap anything"
    );
}

// ── Guards with no test, and why ───────────────────────────────────────────
//
// Written down rather than covered, because a test at an input where the
// guard and its mutant agree passes against the mutant and proves nothing.
// Each of these was mutated and the whole suite run; the result recorded is
// what actually happened, not what was expected.
//
//  * **`sys_munmap`'s `start >= USER_VA_TOP`** is fully subsumed by the
//    `end <= USER_VA_TOP` check below it. `len == 0` is already rejected, so
//    `rounded >= PAGE_SIZE`, so `end > start`; if `start >= USER_VA_TOP` then
//    `end > USER_VA_TOP` and the second check rejects anyway. Mutating it to
//    `>` — and deleting it outright — left every munmap test green. Confirmed
//    by the sweep, not assumed. It is defence in depth against a future
//    reordering, which is a fine reason to keep it and not a reason to claim
//    coverage of it.
//
//  * **`sys_munmap`'s `len > MAX_DEMAND_ALLOC_BYTES`** is likewise subsumed
//    for the *rejection* direction: a length that clears the ceiling also
//    pushes `end` past `USER_VA_TOP` or overflows `checked_add`, so the
//    return value is -1 either way. Only its *inclusive boundary* is
//    observable, which is what `munmap_length_ceiling_is_inclusive` asserts.
//
//  * **`len.saturating_add(page_size - 1)` in both handlers** cannot
//    overflow: the `len > MAX_DEMAND_ALLOC_BYTES` check runs first, so `len`
//    is at most 64 MiB by the time it is used. Same for
//    `num_pages.checked_mul(page_size)` in `sys_mmap`. No reachable input
//    distinguishes them from plain arithmetic. (The `base.saturating_add` in
//    `sys_mmap` is a different matter — `base` comes from the task's break,
//    not from a checked length, and
//    `mmap_survives_a_break_at_the_top_of_the_address_space` catches its
//    removal.)
//
// ── The guard's blind spot ─────────────────────────────────────────────────

/// **LIVE DEFECT, reproduced. This test asserts the broken behaviour on
/// purpose — read the whole comment before touching it.**
///
/// `sys_munmap`'s ceiling check is `start >= USER_VA_TOP`, and
/// `USER_VA_TOP == 0x8000_0000`. Its own comment (`handlers.rs:1247`) cites
/// the incident it was written for: "`munmap(0x1000_0000, 4096)` cleared the
/// UART mapping for every hart; the next `kprintln!` took a fatal S-mode
/// store fault and, with `panic = "abort"`, reset the board."
///
/// **`0x1000_0000` is below `0x8000_0000`. The check does not reject it.**
/// It rejects kernel *RAM* (which is at `0x8000_0000` on every RV64 board
/// here) and nothing else. Every MMIO window — CLINT `0x0200_0000`, PLIC
/// `0x0C00_0000`, UART `0x1000_0000`, virtio `0x1000_1000` — sits in
/// VPN[2] = 0, below the ceiling.
///
/// And VPN[2] = 0 is precisely the slot `crates/core/sched/src/process.rs:26-40`
/// documents as *shared*: "Every user page table carries the kernel's own
/// mappings, merged in by `vmm::copy_kernel_entries_to_user` at VPN[1]
/// granularity for VPN[2]=0." The merge copies the kernel's L1 entry — a
/// pointer to the kernel's own L0 table — into the user's L1. So the PTE
/// `vmm::unmap` zeroes when walking the *user* root is a PTE in the
/// *kernel's* table.
///
/// This test builds that exact arrangement out of real kernel code
/// (`vmm::init`, `vmm::map_mmio_region`, `vmm::copy_kernel_entries_to_user`,
/// the real Sv39 walker) and shows the kernel losing its MMIO mapping to one
/// syscall from ring 3. `SYS_MUNMAP` (`dispatch.rs:383`) has no capability
/// check; the seccomp filter is opt-in.
///
/// The guard now refuses these addresses: the test asserts `-1`, that the
/// kernel translation survives, and that a task can still unmap its own page.
#[test]
fn munmap_cannot_reach_the_kernels_own_page_table_through_the_shared_tables() {
    let _g = serial();

    // A kernel page table with real MMIO windows in it, built by the code
    // that builds the real one. `vmm::init` needs some RAM range to
    // identity-map; one page is enough — what matters is that it sets
    // `KERNEL_PT`, which `map_mmio_region` and `copy_kernel_entries_to_user`
    // both read.
    azos_mm::vmm::init(azos_mm::shim_arena_base(), PAGE_SIZE).unwrap();
    let kpt = azos_mm::vmm::kernel_pagetable();

    // The three that matter most: losing the UART kills `kprintln!`, losing
    // the CLINT kills the timer tick, losing the PLIC kills every device IRQ.
    for mmio in [CLINT, PLIC, UART] {
        azos_mm::vmm::map_mmio_region(mmio, PAGE_SIZE).unwrap();
        assert_eq!(azos_mm::vmm::translate(kpt, mmio), Some(mmio));
    }

    // A user page table shaped like a real ring-3 task's: image at 0x10000,
    // i.e. VPN[2] = 0 — the same L2 slot the MMIO windows live in, which is
    // what forces `copy_kernel_entries_to_user` down its *merge* path rather
    // than its wholesale-copy path.
    let upt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let text = a_page();
    azos_mm::vmm::map(upt, 0x1_0000, text, PagePerms::USER_RX).unwrap();
    azos_mm::vmm::copy_kernel_entries_to_user(upt);

    azos_sched::set_current_user_pt(upt);
    azos_sched::set_current_task_tid(1);

    for mmio in [CLINT, PLIC, UART] {
        assert_eq!(
            sys_munmap(mmio as u64, PAGE_SIZE as u64),
            -1,
            "munmap({mmio:#x}) was ACCEPTED from ring 3. This is not a wrong return value: \
             the call reaches the KERNEL's own page table, because the user table shares \
             the kernel's tables rather than copying them. Losing the UART kills kprintln, \
             the CLINT kills the timer tick, the PLIC kills every device IRQ."
        );
        assert_eq!(
            azos_mm::vmm::translate(kpt, mmio),
            Some(mmio),
            "and {mmio:#x} is still mapped in the kernel page table -- a refusal that \
             unmapped it anyway would be worse than no refusal, because the return value \
             would say the machine is fine"
        );
    }

    // Refusing the kernel's pages must not mean refusing everything: the task
    // can still unmap its own. Without this the fix could be "return -1
    // always", which satisfies every assertion above and breaks the syscall.
    let own = a_page();
    azos_mm::vmm::map(upt, 0x20_0000, own, PagePerms::USER_RW).unwrap();
    assert_eq!(
        sys_munmap(0x20_0000, PAGE_SIZE as u64), 0,
        "a task must still be able to unmap its OWN page",
    );
    assert_eq!(
        azos_mm::vmm::translate_user(upt, 0x20_0000, false), None,
        "and it really went, rather than being reported as gone",
    );

    // The image is untouched throughout.
    assert_eq!(azos_mm::vmm::translate(upt, 0x1_0000), Some(text));
}

/// The guard *does* hold for kernel RAM, which is where it was aimed.
/// Asserted separately so the finding above cannot be mistaken for "the check
/// does nothing".
#[test]
fn munmap_does_protect_addresses_at_and_above_the_user_ceiling() {
    let _g = serial();
    let pt = fresh_user_pt();
    let phys = a_page();
    azos_mm::vmm::map(pt, USER_VA_TOP, phys, PagePerms::USER_RW).unwrap();
    for addr in [USER_VA_TOP, USER_VA_TOP + PAGE_SIZE, 0x8020_0000usize] {
        assert_eq!(sys_munmap(addr as u64, PAGE_SIZE as u64), -1, "{addr:#x}");
    }
    assert_eq!(azos_mm::vmm::translate_user(pt, USER_VA_TOP, false), Some(phys));
}

// ── The write direction ────────────────────────────────────────────────────

/// If `munmap` can zero a kernel PTE through a shared table, can `mmap` write
/// one? On the qemu/vf2 layout: **no — but not because of any check in the
/// handler.**
///
/// `sys_mmap`'s only ceiling is `end_va > USER_VA_TOP`, the same
/// `0x8000_0000` that misses the MMIO range. What actually stops it is
/// `vmm::map`'s `AlreadyMapped`: every shared region's *first* page is
/// occupied, because each MMIO base (CLINT `0x0200_0000`, PLIC
/// `0x0C00_0000`, UART `0x1000_0000`) happens to sit exactly on the 2 MiB
/// boundary of the VPN[1] slot it occupies. A mapping walking up from the
/// break hits that page first, fails, and unwinds.
///
/// This asserts all three halves of that: the refusal, the kernel tables
/// still resolving, and the pages coming back — the last being an unwind on a
/// failure that originates in `map`, a different arm from the OOM one
/// `a_failed_mmap_leaves_no_physical_pages_stranded` covers.
#[test]
fn mmap_cannot_walk_into_a_shared_kernel_table_on_this_layout() {
    let _g = serial();
    let (kpt, upt) = a_task_sharing_the_kernels_mmio_tables();
    let before = azos_mm::shim_pages_in_use();

    // Break just past the image page, the way a real task's is. NOT at
    // 0x1_0000: that is the image page itself, and the very first `map` would
    // hit `AlreadyMapped` before touching anything — which would make this
    // test blind to the unwind it is here to check (it was, at first).
    azos_sched::shim_set_brk(0x2_0000);
    let max = azos_mm::demand::MAX_DEMAND_ALLOC_BYTES;
    // 64 MiB from 0x20000 runs ~8,000 pages up to the CLINT at 0x0200_0000
    // and fails there, so there is a real partial mapping to unwind.
    assert_eq!(sys_mmap(0, max as u64, 3, 0, ANON, 0), -1);

    for mmio in [CLINT, PLIC, UART] {
        assert_eq!(
            azos_mm::vmm::translate(kpt, mmio),
            Some(mmio),
            "the kernel must still resolve {mmio:#x}"
        );
        assert_eq!(
            azos_mm::vmm::translate_user(upt, mmio, true),
            None,
            "and it must not have become user-writable"
        );
    }
    // Same slack, same reason, as `a_failed_mmap_leaves_no_physical_pages_
    // stranded`: `mmap_unwind` frees the mapped pages but deliberately not
    // the intermediate page tables `vmm::walk` allocated (they are still
    // valid tables). ~8,000 pages were mapped before the collision, so a
    // missing unwind misses this bound by two orders of magnitude — measured
    // at +15 with the unwind in place.
    let after = azos_mm::shim_pages_in_use();
    assert!(
        after <= before + 64,
        "the AlreadyMapped failure stranded {} pages (before {before}, after {after})",
        after - before
    );
    assert_eq!(azos_sched::update_user_brk(0), 0x2_0000);
}

/// **What the layout is doing for the handler, made explicit.** Point the
/// break at a *free* slot inside a shared kernel L0 table and `sys_mmap`
/// installs a USER_RW page there — into the kernel's own table, visible
/// through the kernel page table and through every other task's, since they
/// all share it.
///
/// **This is not reachable from ring 3 on the current tree, and the test says
/// so rather than implying otherwise.** Every writer of `user_brk` is bounded
/// below the CLINT: `sys_brk_impl` caps at `USER_LOW_MAX == 0x0200_0000`
/// (`crates/core/sched/src/process.rs:45`), `sys_mmap` cannot step over the CLINT
/// page (the test above), and `sys_alloc_demand` fails there too because
/// `demand::map_demand` also rejects `AlreadyMapped`. So the hazard is held
/// shut by a coincidence of address-map arithmetic — the CLINT base being
/// 2 MiB-aligned — and not by anything in `handlers.rs`. A board whose lowest
/// kernel-mapped window did not start on its VPN[1] boundary, or a change to
/// any brk writer's ceiling, opens it. Recorded as an executable statement of
/// what the ceiling in `sys_mmap` does *not* cover.
#[test]
fn mmap_cannot_write_into_an_empty_slot_of_a_shared_kernel_table() {
    let _g = serial();
    let (kpt, upt) = a_task_sharing_the_kernels_mmio_tables();

    // Inside the shared L0 table (which covers CLINT..CLINT+2 MiB) but past
    // the 16 pages `map_mmio_region(CLINT, 0x1_0000)` occupies. A first
    // draft used `CLINT + PAGE_SIZE` and failed its own precondition — that
    // page is inside the CLINT window.
    let target = CLINT + 0x1_0000;
    assert_eq!(azos_mm::vmm::translate(kpt, target), None, "precondition: slot is free");

    azos_sched::shim_set_brk(target as u64);
    assert_eq!(
        sys_mmap(0, PAGE_SIZE as u64, 3, 0, ANON, 0), -1,
        "a ring-3 mmap was allowed to write a PTE into a table the kernel owns. \
         The slot was EMPTY, which is why no address-based check catches this: \
         `va_is_kernel_mapped` is false for a hole, and a mapper marching \
         upward through an address space reaches the holes in a kernel-owned \
         L0 before it reaches anything mapped.",
    );

    assert_eq!(
        azos_mm::vmm::translate(kpt, target), None,
        "the KERNEL page table must be unchanged. A page installed here is \
         visible in every address space -- every later exec re-merges the same \
         L0 -- and teardown skips it as a borrowed kernel table, so it is never \
         freed either.",
    );
    assert_eq!(
        azos_mm::vmm::translate_user(upt, target, true), None,
        "and nothing user-writable was left behind in a table every task shares",
    );
}

/// A `mmap` followed by a `munmap` must give the frames back.
///
/// `sys_munmap` used `vmm::unmap`, which clears the PTE and frees nothing.
/// There is no per-task frame list, and exit teardown only frees what is still
/// mapped -- so a mapped-then-unmapped frame was accounted to nobody and lost
/// for the rest of the boot. A fork+exec loop repeats it with a fresh break
/// each time; the end state is a PMM with nothing left, which on a robot is not
/// a crash but a machine that cannot respawn its controller.
///
/// **Counted, not observed through the page table.** The test that already
/// existed asserted the mapping was gone, and it passed for the whole time the
/// frames were leaking: an unmapped PTE and a returned frame look identical
/// from `translate`. This is the same lesson as the sentinel test below --
/// the observable has to be the thing that changed.
///
/// Asserts equality rather than "no worse", because a mapper that returns
/// only some of what it took is the same bug arriving more slowly.
#[test]
fn a_mapped_then_unmapped_range_gives_every_frame_back() {
    let _g = serial();
    let pt = fresh_user_pt();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    azos_sched::shim_set_brk(0x2_0000);

    const PAGES: usize = 8;
    let before = azos_mm::shim_pages_in_use();

    // Wave 14: committed at map time (`MAP_POPULATE`), the frames this row
    // counts; the demand-paged twin is `demand_paging::munmap_frees_...`.
    let base = sys_mmap(0, (PAGES * PAGE_SIZE) as u64, 3, MMAP_MAP_POPULATE, ANON, 0);
    assert!(base > 0, "mmap failed ({base}); the test measures nothing");
    let mapped = azos_mm::shim_pages_in_use();
    assert!(
        mapped >= before + PAGES,
        "mmap took {} pages for {PAGES} requested — the arithmetic below would be \
         measuring something else",
        mapped - before,
    );

    assert_eq!(sys_munmap(base as u64, (PAGES * PAGE_SIZE) as u64), 0);

    let after = azos_mm::shim_pages_in_use();
    assert_eq!(
        after, mapped - PAGES,
        "munmap returned {} of the {PAGES} frames mmap took. The mapping is gone \
         from the page table either way, which is why the pre-existing test \
         passed while every one of them leaked.",
        (mapped - after),
    );
}

/// The dangerous direction of the same change: a frame the task does NOT own
/// must survive its `munmap`.
///
/// Freeing too little is a leak, and the machine eventually stops. Freeing too
/// much hands one frame to two owners, and the machine keeps running while a
/// device buffer and someone's heap occupy the same memory. That is the worse
/// failure and it is silent, so it needs a test of its own — when the
/// "release the frames" change was written, mutating the shared-memory window
/// out of the ownership rule failed nothing in the entire tree.
///
/// The shm window is the case exercised here because it is the one a VA can
/// reach: `shm_map_user` and `mmio_map_user` install real `USER` leaves there
/// whose frames belong to a device or to another task. The other two arms of
/// the rule — the vDSO page and a COW page another task still holds — are not
/// constructible from this harness, and that is stated rather than papered
/// over.
#[test]
fn munmap_does_not_free_a_frame_the_task_does_not_own() {
    let _g = serial();
    let pt = fresh_user_pt();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);

    let (shm_lo, _shm_hi) = azos_sched::user_shm_window();

    // A frame standing in for one a device or another task owns, mapped USER
    // inside the window exactly as `shm_map_user` would.
    let borrowed = a_page();
    azos_mm::vmm::map(pt, shm_lo, borrowed, PagePerms::USER_RW).unwrap();

    let before = azos_mm::shim_pages_in_use();
    assert_eq!(sys_munmap(shm_lo as u64, PAGE_SIZE as u64), 0);
    let after = azos_mm::shim_pages_in_use();

    assert_eq!(
        after, before,
        "munmap released a frame inside the shared-memory window. The mapping \
         going away is correct; returning the frame to the allocator is not — \
         it is still owned by whoever mapped it here, and the allocator will \
         now hand it to someone else as well.",
    );
    assert_eq!(
        azos_mm::vmm::translate_user(pt, shm_lo, false), None,
        "the mapping itself must still be removed — refusing to free is not \
         refusing to unmap",
    );
}

/// **Fork leaves the shm/MMIO window out of the child.** `fork_cow` made every
/// `USER` leaf copy-on-write, the window's included. A frame there belongs to
/// a shm region or a device: the parent's next store landed on a private
/// copy while the region kept the original, the second task to write freed
/// the region's frame under it, and a page nobody wrote kept its refcount
/// entry for good, since teardown skips the window.
///
/// A private page outside the window is forked alongside, so the test also
/// fails if the skip takes more than the window.
///
/// **Canary.** Remove the window `continue` in `fork_cow_inner`: the child
/// maps the window's frame.
#[test]
fn fork_leaves_the_shm_window_out_of_the_child() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let rw = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    const PRIVATE_VA: usize = 0x2_0000;

    let region_frame = a_page();
    azos_mm::vmm::map(pt, shm_lo, region_frame, rw).unwrap();
    let private = a_page();
    azos_mm::vmm::map(pt, PRIVATE_VA, private, rw).unwrap();

    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");

    assert_eq!(
        azos_mm::vmm::translate_user(child, shm_lo, false), None,
        "the child holds no capability or record for the window and must not map it",
    );
    assert_eq!(azos_mm::vmm::page_getref(region_frame), 0, "a window frame takes no refcount entry");
    assert_eq!(
        azos_mm::vmm::translate_user(pt, shm_lo, true), Some(region_frame),
        "the parent's store must reach the region's frame, not a copy",
    );

    assert_eq!(azos_mm::vmm::translate_user(child, PRIVATE_VA, false), Some(private));
    assert_eq!(azos_mm::vmm::page_getref(private), 2, "a page outside the window is still shared");

    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    let _ = azos_mm::vmm::unmap_user_and_free(pt, PRIVATE_VA, shm_lo, shm_hi);
    assert_eq!(azos_mm::vmm::page_getref(private), 0, "the entry went back with the last holder");
}

/// **W^X across fork (wave 13, security).** `fork_cow` marked every user
/// leaf copy-on-write, code and read-only data included, so a store to one
/// took the COW break, which hands back a WRITABLE private copy that keeps
/// the execute bit. Now only a writable leaf becomes COW: a read-only or
/// executable leaf is shared as it is (frame counted), and a store to it,
/// or a kernel write for the task (`translate_user(.., true)`), is refused.
///
/// **Canary.** Feature `cow-ro-canary` (or drop the `writable` test in
/// `fork_cow_inner`): the child's code leaf is COW and the write translates.
#[test]
fn fork_keeps_code_and_rodata_read_only() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let rx = PagePerms { read: true, write: false, exec: true, accessed: true, dirty: false, ..PagePerms::USER_RW };
    let ro = PagePerms { read: true, write: false, exec: false, accessed: true, dirty: false, ..PagePerms::USER_RW };
    const CODE_VA: usize = 0x2_0000;
    const RODATA_VA: usize = 0x2_1000;
    let code = a_page();
    let rodata = a_page();
    azos_mm::vmm::map(pt, CODE_VA, code, rx).unwrap();
    azos_mm::vmm::map(pt, RODATA_VA, rodata, ro).unwrap();

    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");

    for (va, frame) in [(CODE_VA, code), (RODATA_VA, rodata)] {
        assert_eq!(azos_mm::vmm::translate_user(child, va, false), Some(frame), "still shared, readable");
        assert_eq!(azos_mm::vmm::page_getref(frame), 2, "the shared frame is counted");
        assert!(!azos_mm::vmm::user_write_would_be_permitted(child, va),
                "a read-only/executable leaf must not report writable (it is not copy-on-write)");
        assert_eq!(azos_mm::vmm::translate_user(child, va, true), None,
                   "a write to it must be refused, never broken into a writable copy");
        assert!(azos_mm::vmm::handle_cow_fault(child, va).is_err(),
                "a store fault on it is a protection violation, not a COW break");
        assert_eq!(azos_mm::vmm::translate_user(pt, va, true), None, "the parent's stays read-only too");
    }

    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    let _ = azos_mm::vmm::unmap_user_and_free(pt, CODE_VA, shm_lo, shm_hi);
    let _ = azos_mm::vmm::unmap_user_and_free(pt, RODATA_VA, shm_lo, shm_hi);
    assert_eq!(azos_mm::vmm::page_getref(code), 0);
    assert_eq!(azos_mm::vmm::page_getref(rodata), 0);
}

/// **A fork's child inherits its parent's demand reservations (wave 14).**
/// The fork walk saw valid entries only, so a child lost every demand marker
/// and its first touch of one was an unhandled fault that killed it. Since
/// `brk` reserves instead of allocating, that was every forked child's
/// untouched heap. The child gets the marker itself: no frame, no refcount,
/// the parent's entry unchanged, and the child's first touch (here a kernel
/// copy into it, `translate_user`) commits a zeroed page of its own.
///
/// **Canary.** Feature `fork-demand-canary` (or `next_valid` back in the
/// fork's leaf walk): the child has no entry at the reserved page.
#[test]
fn fork_gives_the_child_the_parents_demand_reservations() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let rw = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    const MAPPED: usize = 0x2_0000;
    const RESERVED: usize = 0x2_1000;
    let mapped = a_page();
    azos_mm::vmm::map(pt, MAPPED, mapped, rw).unwrap();
    azos_mm::vmm::map_demand(pt, RESERVED, rw).unwrap();
    // A run of them (the fork copies a run word for word), then a hole.
    azos_mm::vmm::map_demand(pt, RESERVED + PAGE_SIZE, rw).unwrap();
    azos_mm::vmm::map_demand(pt, RESERVED + 2 * PAGE_SIZE, rw).unwrap();
    azos_mm::vmm::map_demand(pt, RESERVED + 4 * PAGE_SIZE, rw).unwrap();

    let (child, reserved) = azos_mm::vmm::fork_cow_shared(pt, shm_lo, shm_hi, false).expect("fork");
    assert_eq!(reserved, 4, "the reservations the child got, for its fork to charge");

    for k in [0, 1, 2, 4] {
        assert_eq!(azos_mm::vmm::user_page(child, RESERVED + k * PAGE_SIZE),
                   azos_mm::vmm::UserPage::Demand, "the child holds reservation {k}");
    }
    assert_eq!(azos_mm::vmm::user_page(child, RESERVED + 3 * PAGE_SIZE),
               azos_mm::vmm::UserPage::Missing, "and nothing where the parent has nothing");
    assert_eq!(azos_mm::vmm::user_page(pt, RESERVED), azos_mm::vmm::UserPage::Demand,
               "the parent's is untouched");
    assert!(azos_mm::vmm::user_write_would_be_permitted(child, RESERVED),
            "a writable reservation reports writable before it is committed");
    let committed = azos_mm::vmm::translate_user(child, RESERVED, true)
        .expect("a copy into the child's reservation commits it");
    assert_ne!(committed, mapped);
    assert_eq!(azos_mm::vmm::user_page(pt, RESERVED), azos_mm::vmm::UserPage::Demand,
               "committing the child's page leaves the parent's reservation alone");
    assert_eq!(azos_mm::vmm::page_getref(committed), 0, "a committed page is the child's alone");

    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    let _ = azos_mm::vmm::unmap_user_and_free(pt, MAPPED, shm_lo, shm_hi);
    for k in [0, 1, 2, 4] {
        assert!(azos_mm::demand::clear_demand_marker(pt, RESERVED + k * PAGE_SIZE));
    }
}

/// **The last holder of a copy-on-write frame keeps it (wave 14).** A break
/// always allocated a frame, copied 4 KiB into it and dropped the original,
/// also when every other sharer had already broken or exited and the
/// original was the breaker's alone. Now a count of 0 or 1 restores the
/// write bit on the same frame (Linux's `wp_page_reuse`), with the
/// permissions a copy gets. A frame still shared is copied as before.
///
/// **Canary.** Feature `cow-reuse-canary`: the parent's break after the
/// child's exit hands it a new frame.
#[test]
fn cow_break_by_the_last_holder_keeps_the_frame() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let rw = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    const DATA: usize = 0x2_0000;
    const KEPT: usize = 0x2_1000;
    let data = a_page();
    let kept = a_page();
    azos_mm::vmm::map(pt, DATA, data, rw).unwrap();
    azos_mm::vmm::map(pt, KEPT, kept, rw).unwrap();

    let (child, reserved) = azos_mm::vmm::fork_cow_shared(pt, shm_lo, shm_hi, false).expect("fork");
    assert_eq!(reserved, 0, "pages, not reservations");
    assert_eq!(azos_mm::vmm::page_getref(data), 2);

    // Shared: the child's break copies, and the parent keeps the original.
    azos_mm::vmm::handle_cow_fault(child, DATA).expect("child break");
    let childs = azos_mm::vmm::translate_user(child, DATA, false).unwrap();
    assert_ne!(childs, data, "a frame two tasks map is copied, never handed to one of them");
    assert_eq!(azos_mm::vmm::page_getref(data), 1);

    // Now the parent is `data`'s last holder: same frame, writable, untracked.
    azos_mm::vmm::handle_cow_fault(pt, DATA).expect("parent break");
    assert_eq!(azos_mm::vmm::translate_user(pt, DATA, true), Some(data),
               "the last holder keeps its frame");
    assert_eq!(azos_mm::vmm::page_getref(data), 0, "a private page takes no refcount entry");
    assert_eq!(azos_mm::vmm::user_page(pt, DATA), azos_mm::vmm::UserPage::Leaf { exec: false });

    // The child exits: `kept` goes back to one holder, and the parent's
    // break of it is a reuse as well.
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    assert_eq!(azos_mm::vmm::page_getref(kept), 1);
    azos_mm::vmm::handle_cow_fault(pt, KEPT).expect("break after the child's exit");
    assert_eq!(azos_mm::vmm::translate_user(pt, KEPT, true), Some(kept));
    assert_eq!(azos_mm::vmm::page_getref(kept), 0);

    assert!(azos_mm::vmm::unmap_user_and_free(pt, DATA, shm_lo, shm_hi), "a private page is freed on unmap");
    assert!(azos_mm::vmm::unmap_user_and_free(pt, KEPT, shm_lo, shm_hi));
}

/// **`mprotect`'s write permission is exact (wave 13, security).**
/// `protect_user_range` makes a read-write leaf read-only and back, never adds
/// write to an executable leaf, and keeps copy-on-write honest: a COW leaf
/// made writable stays COW (its frame still shared), one made read-only loses
/// the marker, so a store faults instead of breaking it into a writable copy.
///
/// **Canary.** Make `protect_user_range` skip its write (or map every
/// `sys_mmap` page read-write, `mmap-prot-canary`): the read-only asserts fail.
#[test]
fn mprotect_sets_write_exactly_and_respects_cow_and_exec() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let rw = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    let rx = PagePerms { read: true, write: false, exec: true, accessed: true, dirty: false, ..PagePerms::USER_RW };
    const DATA: usize = 0x2_0000;
    const CODE: usize = 0x2_1000;
    let data = a_page();
    let code = a_page();
    azos_mm::vmm::map(pt, DATA, data, rw).unwrap();
    azos_mm::vmm::map(pt, CODE, code, rx).unwrap();

    assert_eq!(azos_mm::vmm::protect_user_range(pt, DATA, DATA + 4096, false), 1);
    assert_eq!(azos_mm::vmm::translate_user(pt, DATA, true), None, "read-only refuses a write");
    assert_eq!(azos_mm::vmm::translate_user(pt, DATA, false), Some(data), "and stays readable");
    assert_eq!(azos_mm::vmm::protect_user_range(pt, DATA, DATA + 4096, true), 1);
    assert_eq!(azos_mm::vmm::translate_user(pt, DATA, true), Some(data), "writable again");
    assert_eq!(azos_mm::vmm::protect_user_range(pt, CODE, CODE + 4096, true), 0, "W^X: never on code");
    assert_eq!(azos_mm::vmm::user_page(pt, CODE), azos_mm::vmm::UserPage::Leaf { exec: true });

    // Copy-on-write: fork shares DATA (COW in both tables).
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    assert_eq!(azos_mm::vmm::protect_user_range(child, DATA, DATA + 4096, true), 0,
               "a COW leaf made writable stays COW");
    assert!(azos_mm::vmm::user_write_would_be_permitted(child, DATA));
    assert_eq!(azos_mm::vmm::protect_user_range(child, DATA, DATA + 4096, false), 1);
    assert!(!azos_mm::vmm::user_write_would_be_permitted(child, DATA),
            "read-only: the COW marker is gone, a store faults");
    assert!(azos_mm::vmm::handle_cow_fault(child, DATA).is_err(), "no COW break into a writable copy");
    assert_eq!(azos_mm::vmm::page_getref(data), 2, "still shared, still counted");

    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    let _ = azos_mm::vmm::unmap_user_and_free(pt, DATA, shm_lo, shm_hi);
    let _ = azos_mm::vmm::unmap_user_and_free(pt, CODE, shm_lo, shm_hi);
    assert_eq!(azos_mm::vmm::page_getref(data), 0);
}

/// **A page-table root some hart still translates through is not freed — any
/// of it.** `destroy_user_pagetable_skip_range` asks `Mmu::root_holders`
/// first and, while the answer is non-zero, returns it and releases nothing:
/// not the root, not its L1/L0 tables, not the leaf behind them. The hart
/// still on the root reaches all of them. Asked again once no hart holds it,
/// the same call frees every one.
///
/// This is the free the exit path, exec and the slot-reuse reclaim all end
/// in, and the shape of the kernel page fault that found it: a dying hart
/// still had the root in `satp` when another hart's claim of its slot tore
/// the table down, and the frame came back as someone else's page.
///
/// **Canary.** Drop the `root_holders` check at the top of
/// `destroy_user_pagetable_skip_range`: the held call returns 0 having freed
/// the four frames, and the test fails there.
#[test]
fn a_root_still_live_on_a_hart_is_refused_whole() {
    use core::sync::atomic::Ordering;
    let _g = serial();
    let pt = fresh_user_pt();
    let rw = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    azos_mm::vmm::map(pt, 0x2_0000, a_page(), rw).unwrap();
    let before = azos_mm::shim_pages_in_use();
    let refusals = azos_mm::vmm::LIVE_ROOT_REFUSALS.load(Ordering::SeqCst);

    azos_arch::LIVE_ROOT.store(pt, Ordering::SeqCst);
    let held = azos_mm::vmm::destroy_user_pagetable_skip_range(pt, 0, 0);
    azos_arch::LIVE_ROOT.store(0, Ordering::SeqCst);
    assert_eq!(held, 1 << 2, "the holder mask comes back to the caller, who prints it");
    assert_eq!(
        azos_mm::shim_pages_in_use(), before,
        "a teardown under a live root freed frames the holder still walks",
    );
    assert_eq!(azos_mm::vmm::LIVE_ROOT_REFUSALS.load(Ordering::SeqCst), refusals + 1);

    assert_eq!(azos_mm::vmm::destroy_user_pagetable_skip_range(pt, 0, 0), 0);
    assert_eq!(
        before - azos_mm::shim_pages_in_use(), 4,
        "released: root, L1, L0 and the leaf",
    );
}

/// The half an address-based check structurally cannot cover: an **empty slot**
/// in a kernel-owned table.
///
/// `va_is_kernel_mapped` answers "is this address mapped by the kernel", and
/// for a hole the answer is no. But the hole is still in the kernel's L0, and
/// `unmap` writes `Pte::empty()` over whatever is at that slot without caring
/// whether it was occupied. Same store, same table, and it does not need the
/// address to be mapped for the store to land in the kernel's page table.
///
/// The store is harmless the day it writes zero over zero. It stops being
/// harmless the moment anything else uses those slots, and by then the
/// mechanism that allows it has been in the tree for a year.
///
/// Observed with a sentinel rather than through `translate`, because
/// `translate` reports None both before and after — which is exactly why the
/// first version of this suite had no test here and why removing the `unmap`
/// gate fired no canary.
#[test]
fn munmap_cannot_write_over_an_empty_slot_of_a_shared_kernel_table() {
    let _g = serial();
    let (kpt, _upt) = a_task_sharing_the_kernels_mmio_tables();

    // A free slot inside the L0 the kernel owns for the CLINT megapage.
    let target = CLINT + 0x1_0000;
    assert_eq!(azos_mm::vmm::translate(kpt, target), None, "precondition: slot is free");

    // Find that L0 slot's address by walking the kernel's own tables.
    use azos_arch::mmu::{vpn0, vpn1, vpn2};
    let l2 = unsafe { core::ptr::read_volatile((kpt + vpn2(target) * 8) as *const u64) };
    let l1_base = ((l2 >> 10) & ((1u64 << 44) - 1)) as usize * PAGE_SIZE;
    let l1 = unsafe { core::ptr::read_volatile((l1_base + vpn1(target) * 8) as *const u64) };
    let l0_base = ((l1 >> 10) & ((1u64 << 44) - 1)) as usize * PAGE_SIZE;
    let slot = (l0_base + vpn0(target) * 8) as *mut u64;

    // A sentinel that is NOT a valid PTE, so nothing treats it as a mapping,
    // but is not zero either, so an overwrite is visible.
    const SENTINEL: u64 = 0xDEAD_0000_0000_0000;
    let saved = unsafe { core::ptr::read_volatile(slot) };
    assert_eq!(saved, 0, "precondition: the slot really is empty");
    unsafe { core::ptr::write_volatile(slot, SENTINEL) };

    azos_sched::shim_set_brk(target as u64);
    let _ = sys_munmap(target as u64, PAGE_SIZE as u64);

    let after = unsafe { core::ptr::read_volatile(slot) };
    unsafe { core::ptr::write_volatile(slot, saved) };   // leave the table as found

    assert_eq!(
        after, SENTINEL,
        "a ring-3 munmap wrote into the kernel's own L0 table. The slot was empty, so no \
         address-based guard sees it: the write is the finding, not the value.",
    );
}

/// Kernel PT + a user PT shaped like a real ring-3 task's, with the kernel's
/// VPN[2]=0 tables merged in — the arrangement `crates/core/sched/src/process.rs`
/// produces at every `exec` and `fork`.
///
/// `map_mmio_region` sizes match `kernel/src/main.rs`'s qemu arm.
fn a_task_sharing_the_kernels_mmio_tables() -> (usize, usize) {
    azos_mm::vmm::init(azos_mm::shim_arena_base(), PAGE_SIZE).unwrap();
    let kpt = azos_mm::vmm::kernel_pagetable();
    azos_mm::vmm::map_mmio_region(CLINT, 0x1_0000).unwrap();
    azos_mm::vmm::map_mmio_region(PLIC, 0x40_0000).unwrap();
    azos_mm::vmm::map_mmio_region(UART, 0x1000).unwrap();

    let upt = azos_mm::pmm::alloc_page().unwrap().as_usize();
    let text = a_page();
    azos_mm::vmm::map(upt, 0x1_0000, text, PagePerms::USER_RX).unwrap();
    azos_mm::vmm::copy_kernel_entries_to_user(upt);
    azos_sched::set_current_user_pt(upt);
    azos_sched::set_current_task_tid(1);
    (kpt, upt)
}

/// **The second finding, now fixed.** `sys_mmap` got `saturating_add` here and
/// `sys_alloc_demand` did not:
///
/// ```text
/// sys_mmap:          base.saturating_add(page_size - 1) & !(page_size - 1)
/// sys_alloc_demand:  (base + page_size - 1)             & !(page_size - 1)
/// ```
///
/// Rust groups the second as `(base + page_size) - 1`, so a break anywhere in
/// the last page of the address space overflows. With `overflow-checks = true`
/// and `panic = "abort"`, an arithmetic overflow inside a syscall handler is
/// not a wrong answer -- it is a board reset.
///
/// There were TWO sites: fixing only `aligned_base` left `end_va`'s
/// `aligned_base + num_pages * page_size` panicking one line later. That is
/// why this asserts the RETURN VALUE rather than merely the absence of a
/// panic: a test that only caught the first site would have passed on a
/// handler that still aborts.
///
/// Not reachable from ring 3 today -- no `brk` writer can put the break in that
/// range -- but the missing guard was real, in one of two siblings, and the
/// repo's rule is to fix the class rather than the instance.
#[test]
fn alloc_demand_refuses_a_break_in_the_last_page_instead_of_overflowing() {
    let _g = serial();
    fresh_user_pt();
    azos_sched::shim_set_brk(u64::MAX);
    assert_eq!(
        sys_alloc_demand(PAGE_SIZE as u64), -1,
        "a break in the last page must be refused, not added to",
    );
}

/// **`sys_alloc_demand` ends at or below the shm/MMIO window**, the ceiling
/// `sys_mmap` has and for the same reason (see
/// `mmap_va_ceiling_is_exclusive_at_the_top_and_inclusive_below_it`).
///
/// **Divergence:** the old ceiling `USER_VA_TOP` accepts the two-page request
/// that ends one page inside the window. It is asserted first, before the
/// accepted one-page request installs a PTE the second call could collide with.
#[test]
fn alloc_demand_ends_at_or_below_the_shm_window() {
    let _g = serial();
    fresh_user_pt();
    let (window_base, _) = azos_sched::user_shm_window();

    azos_sched::shim_set_brk((window_base - PAGE_SIZE) as u64);
    assert_eq!(sys_alloc_demand(2 * PAGE_SIZE as u64), -1, "the second page lies in the window");

    azos_sched::shim_set_brk((window_base - PAGE_SIZE) as u64);
    assert_eq!(
        sys_alloc_demand(PAGE_SIZE as u64),
        (window_base - PAGE_SIZE) as i64,
        "a range that ends flush against the window must be allowed",
    );
}

/// **RFC-0049 M1: a demand reservation is charged when it is made, and a
/// reserved page never touched is given back by `munmap`.** Charging at the
/// fault instead would make the fault the place a budget refuses, and the
/// task would die on a load it was promised; charging at reservation and
/// forgetting untouched pages at `munmap` would ratchet the budget.
///
/// **Canaries** (run by hand 2026-09-28): drop the `mm_charge` in
/// `sys_alloc_demand` — "the reservation is charged" fails (0 != 4); drop the
/// `clear_demand_marker` arm in `sys_munmap` — "untouched pages come back"
/// fails (4 != 0).
#[test]
fn alloc_demand_charges_the_reservation_and_munmap_returns_untouched_pages() {
    let _g = serial();
    fresh_user_pt();
    let base = azos_mm::vmm::USER_GUARD_LIMIT;
    azos_sched::shim_set_brk(base as u64);
    azos_sched::shim_set_page_limit(4);

    assert_eq!(sys_alloc_demand(4 * PAGE_SIZE as u64), base as i64);
    assert_eq!(azos_sched::shim_user_pages(), 4, "the reservation is charged");
    assert_eq!(sys_alloc_demand(PAGE_SIZE as u64), -1, "a fifth page is over the budget");

    assert_eq!(sys_munmap(base as u64, (4 * PAGE_SIZE) as u64), 0);
    assert_eq!(azos_sched::shim_user_pages(), 0, "untouched pages come back");
    azos_sched::shim_set_page_limit(0);
}

/// **RFC-0049 P2: a `mem = "locked"` task is refused `SYS_ALLOC_DEMAND`**,
/// whatever its seccomp profile: every page of a reservation is a fault, and
/// a locked task takes none. The refusal is counted with the budget refusals.
///
/// **Canary** (run by hand 2026-09-28): drop the `current_mem_locked` check —
/// the call returns the base address instead of `-1`.
#[test]
fn alloc_demand_is_refused_to_a_locked_task() {
    let _g = serial();
    fresh_user_pt();
    let base = azos_mm::vmm::USER_GUARD_LIMIT;
    azos_sched::shim_set_brk(base as u64);
    azos_sched::shim_set_mem_locked(true);
    let before = azos_sched::shim_mm_refusals();
    assert_eq!(sys_alloc_demand(PAGE_SIZE as u64), -1);
    assert_eq!(azos_sched::shim_mm_refusals(), before + 1);
    assert_eq!(azos_sched::shim_user_pages(), 0, "nothing charged");
    azos_sched::shim_set_mem_locked(false);
    assert_eq!(sys_alloc_demand(PAGE_SIZE as u64), base as i64, "unlocked, the same call succeeds");
}

// ── Kconfig LOCKED_HUGE_LEAVES: a locked row's 2 MiB-leaf region ───────────
//
// The mapper (`vmm::map_user_mega_range`), the range check `sys_munmap` uses
// to refuse it (`vmm::user_range_has_mega_leaf`), and teardown, on the real
// Sv39 walker. `sys_munmap`'s own refusal is compiled only when the option is
// on, which this host build's `.config` does not set, so it is not reached
// here; its predicate is.

/// 2 MiB, the Sv39 level-1 leaf.
const MEGA: usize = 2 * 1024 * 1024;
/// Where `LOCKED_ARENA_VA` lands on QEMU riscv64 (the shm/MMIO window base).
const ARENA: usize = 0x6000_0000;

fn huge_flags() -> PagePerms {
    PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }
}

/// Two 2 MiB leaves map the region; a user-permission walk resolves inside
/// it; the munmap predicate sees it; the page-by-page unmap leaves it whole.
///
/// **Canary.** Make `map_user_mega_range` map page leaves (`vmm::map` per
/// 4 KiB) instead of `map_mega`: `leaf_level` reads 0 and the first
/// assertion fails.
#[test]
fn huge_region_is_two_level1_leaves_that_munmap_cannot_take() {
    let _g = serial();
    let pt = fresh_user_pt();
    let pa = azos_mm::pmm::alloc_contiguous_aligned(2 * MEGA / PAGE_SIZE, MEGA)
        .expect("a 2 MiB-aligned 4 MiB run in the arena").as_usize();
    azos_mm::vmm::map_user_mega_range(pt, ARENA, pa, 2 * MEGA, huge_flags()).expect("mapped");
    assert_eq!(azos_mm::vmm::leaf_level(pt, ARENA), Some(1));
    assert_eq!(azos_mm::vmm::leaf_level(pt, ARENA + MEGA + 5 * PAGE_SIZE), Some(1));
    assert_eq!(azos_mm::vmm::translate_user(pt, ARENA + MEGA + 123, true), Some(pa + MEGA + 123));
    assert!(azos_mm::vmm::user_range_has_mega_leaf(pt, ARENA + PAGE_SIZE, ARENA + 2 * PAGE_SIZE));
    assert!(!azos_mm::vmm::user_range_has_mega_leaf(pt, ARENA + 2 * MEGA, ARENA + 3 * MEGA),
        "the slot past the region holds no leaf");
    let free = azos_mm::pmm::free_pages();
    assert_eq!(azos_mm::vmm::unmap_user_range_and_free(pt, ARENA, ARENA + 2 * MEGA, 0, 0), 0,
        "no 4 KiB frame of the region is the task's to free");
    assert_eq!(azos_mm::pmm::free_pages(), free);
    assert_eq!(azos_mm::vmm::leaf_level(pt, ARENA), Some(1), "still mapped");
}

/// Refused before anything is written: executable, unaligned, or onto a
/// slot already in use (the first slot stays unmapped when the second is
/// taken).
#[test]
fn map_user_mega_range_refuses_and_writes_nothing() {
    let _g = serial();
    let pt = fresh_user_pt();
    let pa = azos_mm::pmm::alloc_contiguous_aligned(2 * MEGA / PAGE_SIZE, MEGA)
        .expect("a 2 MiB-aligned 4 MiB run in the arena").as_usize();
    let rx = PagePerms { accessed: true, ..PagePerms::USER_RX };
    assert!(azos_mm::vmm::map_user_mega_range(pt, ARENA, pa, MEGA, rx).is_err(), "never executable");
    assert!(azos_mm::vmm::map_user_mega_range(pt, ARENA + PAGE_SIZE, pa, MEGA, huge_flags()).is_err());
    assert!(azos_mm::vmm::map_user_mega_range(pt, ARENA, pa + PAGE_SIZE, MEGA, huge_flags()).is_err());
    azos_mm::vmm::map(pt, ARENA + MEGA + PAGE_SIZE, a_page(), huge_flags()).expect("a page in the second slot");
    assert!(azos_mm::vmm::map_user_mega_range(pt, ARENA, pa, 2 * MEGA, huge_flags()).is_err());
    assert_eq!(azos_mm::vmm::leaf_level(pt, ARENA), None, "the first slot was not written");
}

/// Teardown frees the tables and never the region: the frames are the row's
/// for the whole boot.
///
/// **Canary.** Let `destroy_user_pagetable_skip_range` treat a level-1 leaf
/// like a page leaf (free its base through `page_decref`): two more frames
/// come back and the count is off.
#[test]
fn teardown_frees_the_tables_not_the_region() {
    let _g = serial();
    let pt = fresh_user_pt();
    let pa = azos_mm::pmm::alloc_contiguous_aligned(2 * MEGA / PAGE_SIZE, MEGA)
        .expect("a 2 MiB-aligned 4 MiB run in the arena").as_usize();
    let before = azos_mm::pmm::free_pages();
    azos_mm::vmm::map_user_mega_range(pt, ARENA, pa, 2 * MEGA, huge_flags()).expect("mapped");
    let tables = before - azos_mm::pmm::free_pages();
    assert_eq!(tables, 1, "one level-1 table under the root");
    azos_sched::set_current_user_pt(0);
    assert_eq!(azos_mm::vmm::destroy_user_pagetable_skip_range(pt, 0, 0), 0);
    assert_eq!(azos_mm::pmm::free_pages(), before + 1,
        "the level-1 table and the root come back, the 1024 region frames do not");
}

/// **A fork child's `mprotect(RW)` of a page its parent shares read-only
/// lands on its own copy (wave 14, security).** A fork shares a read-only
/// leaf as it is (frame counted, no COW marker); `protect_user_range` then
/// set the write bit in place, and the child's stores went to the parent's
/// frame. Now the leaf is made copy-on-write: the child's first store breaks
/// it into a private copy and the parent's bytes stay. The lease seal's
/// write give-back (`set_user_range_write`) adds write the same way and is
/// held to the same rule, for a page a fork made copy-on-write.
///
/// **Canary.** Feature `mprotect-shared-canary`: the child's writable
/// translation is the parent's frame.
#[test]
fn mprotect_shared_lands_on_a_private_copy() {
    let _g = serial();
    let pt = fresh_user_pt();
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    const RO_VA: usize = 0x2_4000;
    const RW_VA: usize = 0x2_5000;
    let ro = PagePerms { read: true, write: false, exec: false, accessed: true, dirty: false, ..PagePerms::USER_RW };
    let rw = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    let ro_frame = a_page();
    let rw_frame = a_page();
    unsafe { *(azos_mm::addr::phys_to_virt(ro_frame) as *mut u8) = 0x5a; }
    unsafe { *(azos_mm::addr::phys_to_virt(rw_frame) as *mut u8) = 0x3c; }
    azos_mm::vmm::map(pt, RO_VA, ro_frame, ro).unwrap();
    azos_mm::vmm::map(pt, RW_VA, rw_frame, rw).unwrap();
    let child = azos_mm::vmm::fork_cow(pt, shm_lo, shm_hi).expect("fork");
    assert_eq!(azos_mm::vmm::page_getref(ro_frame), 2);

    // mprotect(RW) in the child, then its store (a kernel write for it
    // breaks copy-on-write exactly as a store fault would).
    azos_mm::vmm::protect_user_range(child, RO_VA, RO_VA + PAGE_SIZE, true);
    // The lease give-back on a page the fork made copy-on-write.
    azos_mm::vmm::set_user_range_write(child, RW_VA, RW_VA + PAGE_SIZE, false);
    azos_mm::vmm::set_user_range_write(child, RW_VA, RW_VA + PAGE_SIZE, true);
    for (va, frame, old) in [(RO_VA, ro_frame, 0x5au8), (RW_VA, rw_frame, 0x3c)] {
        let mine = azos_mm::vmm::translate_user(child, va, true).expect("writable in the child");
        assert_ne!(mine, frame, "{va:#x}: the child's writable page is the parent's frame");
        unsafe { *(azos_mm::addr::phys_to_virt(mine) as *mut u8) = 0xa5; }
        assert_eq!(unsafe { *(azos_mm::addr::phys_to_virt(frame) as *const u8) }, old, "{va:#x}: parent's byte");
        assert_eq!(unsafe { *(azos_mm::addr::phys_to_virt(mine) as *const u8) }, 0xa5, "{va:#x}: child's byte");
    }
    // A sole page still becomes writable in place.
    azos_mm::vmm::destroy_user_pagetable_skip_range(child, shm_lo, shm_hi);
    azos_mm::vmm::protect_user_range(pt, RO_VA, RO_VA + PAGE_SIZE, true);
    assert_eq!(azos_mm::vmm::translate_user(pt, RO_VA, true), Some(ro_frame), "sole: written in place");
}

/// **The vDSO page never becomes writable through a user's table (wave 15,
/// security).** Every address space maps the one vDSO frame read-only. With
/// no other counted holder (no fork since boot), `protect_user_range` set the
/// write bit in place, so a task's `mprotect(RW)` and store rewrote the page
/// every task reads its clock from; with one, it made the leaf copy-on-write.
/// Now neither `mprotect` nor the lease give-back adds write to it, and
/// `sys_mprotect` refuses the range (`user_leaf_is_kernel_shared`).
///
/// **Canary.** Feature `vdso-write-canary`: the leaf is writable in place.
#[test]
fn mprotect_never_makes_the_vdso_writable() {
    let _g = serial();
    if azos_mm::vdso::vdso_phys() == 0 {
        azos_mm::vdso::vdso_init();
    }
    let vdso = azos_mm::vdso::vdso_phys();
    assert_ne!(vdso, 0, "precondition: a vDSO page");
    let pt = fresh_user_pt();
    const VA: usize = 0x2_6000;
    let ro = PagePerms { accessed: true, ..PagePerms::USER_RO };
    azos_mm::vmm::map(pt, VA, vdso, ro).unwrap();
    assert_eq!(azos_mm::vmm::protect_user_range(pt, VA, VA + PAGE_SIZE, true), 0,
        "mprotect(RW) changed the vDSO leaf");
    assert_eq!(azos_mm::vmm::set_user_range_write(pt, VA, VA + PAGE_SIZE, true), 0,
        "the lease give-back changed the vDSO leaf");
    assert_eq!(azos_mm::vmm::translate_user(pt, VA, true), None, "the vDSO is writable");
    assert_eq!(azos_mm::vmm::translate_user(pt, VA, false), Some(vdso), "and still readable");
    assert!(azos_mm::vmm::user_leaf_is_kernel_shared(pt, VA), "sys_mprotect must see the vDSO leaf");
    // An ordinary read-only page next to it is still made writable.
    const OWN: usize = 0x2_7000;
    let own = a_page();
    azos_mm::vmm::map(pt, OWN, own, ro).unwrap();
    assert!(!azos_mm::vmm::user_leaf_is_kernel_shared(pt, OWN));
    assert_eq!(azos_mm::vmm::protect_user_range(pt, OWN, OWN + PAGE_SIZE, true), 1);
    assert_eq!(azos_mm::vmm::translate_user(pt, OWN, true), Some(own));
}
