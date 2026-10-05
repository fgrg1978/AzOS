// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// One serial lock for the whole crate, and the state reset that goes with it.
//
// **WHY one lock and not one per test module.** Every target under test reads
// process-global state: `azos_net::SOCKS`, the `azos_sched` shim's
// "current task" registers, and — since the mm shim started pulling the real
// `crates/core/mm` — the PMM bitmap, `KERNEL_PT` and the page-table metadata
// table. `cargo test` runs test fns on several threads. Two modules each
// holding their own `Mutex` serialise against themselves and race against
// each other, which is worse than no lock at all: it fails intermittently and
// only under load.
//
// `serial()` also puts the shared state back to a known point, so a test
// cannot inherit the previous one's task identity, break, or free pages. That
// is not tidiness — `shim_pages_in_use()` is an assertion target, and a test
// that inherited a leak would read someone else's.

use std::sync::Mutex;

pub static SERIAL: Mutex<()> = Mutex::new(());

/// Take the crate-wide lock and reset the shared state.
///
/// Kernel context by default (`user_pt == 0`, `tid == 0`, break 0): a
/// leftover "current task" from the previous test must not leak into this
/// one, and every guard under test branches on exactly those registers.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_state();
    g
}

/// The reset half of [`serial`], without the lock.
///
/// For a test that needs a second clean arena mid-test — a boundary test that
/// asserts both sides of a ceiling, where the accepted side consumes 16,384
/// pages. Calling `serial()` again there would deadlock: `std::sync::Mutex`
/// is not reentrant, and the first version of these tests hung the whole
/// suite doing exactly that.
///
/// **What it does NOT reset: `vmm::KERNEL_PT` and `vmm::PT_META`.** Neither
/// has a public setter, and nothing in `crates/core/mm` clears them. So after a
/// test that called `vmm::init`, `KERNEL_PT` still points at an arena page
/// that the next `shim_reset` frees and hands out again — as a user root, or
/// as data. Harmless today because the only readers of `KERNEL_PT`
/// (`copy_kernel_entries_to_user`, `map_mmio_region`, `destroy_user_pagetable`)
/// are called from tests that call `vmm::init` themselves first. **If you
/// write a test that touches any of those, call `vmm::init` in it**, or it
/// will quietly walk a page some other test is using. `PT_META` has 128 slots
/// and no reset either, which is why `fresh_user_pt` allocates roots with
/// `pmm::alloc_page` instead of `vmm::create_pagetable`.
pub fn reset_state() {
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(0);
    azos_sched::shim_set_brk(0);
    azos_sched::shim_reset_user_windows();
    azos_mm::shim_reset();
    // The COW refcount table is process-global and `shim_reset` does not touch
    // it. A test that took a second reference on a frame used to leave that
    // refcount behind; the arena reset then handed the same frame to the next
    // test, whose `munmap` correctly refused to free it — "another COW holder"
    // — and the leak was reported against the innocent test. That cost one
    // withdrawn COW test and a wrong diagnosis ("there is no per-test
    // allocator isolation"; there is, and it is this function).
    azos_mm::cow::shim_reset_refs();
    // MUST come after `shim_reset`, and must exist at all: the arena reset
    // recycles the page `KERNEL_PT` points at, so leaving the pointer set
    // makes the next page-table walk read another test's data as PTEs. That
    // made two ceiling tests pass alone and fail in the suite -- a verdict
    // that depends on execution order is not a verdict.
    azos_mm::vmm::shim_forget_kernel_pt();
    // Armed stand-ins go back to `todo!()`. Each one answers only for the test
    // that armed it: a recorder left armed would let the next test reach a
    // device, a NIC or the exit-notice table without panicking, which is the
    // signal several canaries in this crate rely on.
    syscall_test_drivers::shim_fwd::disarm();
    azos_net::shim_fwd::disarm();
    azos_robot::shim_disarm_motor_info();
    azos_sched::shim_take_exit_table();
    azos_sched::process::shim_take_fork_calls();
    azos_sched::shim_disarm_yield();
    azos_sched::shim_disarm_block_outcome();
    azos_sched::shim_set_block_hook(None);
    let _ = azos_sched::shim_take_blocks();
    azos_ipc::shim_set_signal_pending(None);
    azos_net::shim_arm_net_poll(false);
    azos_drv_irqchip::clint::set_time(0);
}
