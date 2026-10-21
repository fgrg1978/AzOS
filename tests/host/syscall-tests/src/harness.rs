// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// One serial lock for the whole crate, and the state reset that goes with it.
//
// **WHY one lock and not one per test module.** Every target under test reads
// process-global state: `azos_net::SOCKS`, the `azos_sched` shim's
// "current task" registers, and — since the mm shim started pulling the real
// `crates/core/mm` — the frame descriptors, `KERNEL_PT` and the page-table metadata
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
pub fn serial() -> SerialGuard {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    azos_sched::shim_serial_enter();
    reset_state();
    SerialGuard(g)
}

/// The lock [`serial`] returns. Dropping it tells the sched shim nobody owns
/// its state any more (the lock itself is released after, field order), so an
/// access from a test that never took it is refused instead of racing.
pub struct SerialGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl Drop for SerialGuard {
    fn drop(&mut self) {
        azos_sched::shim_serial_leave();
    }
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
    // The scheduler shim's registers: current task, process id, break, frame
    // budgets, class, recorders, filters, forced stop, futex log. Not only the
    // identity: `current_proc_tid()` is the task's own tid only while its
    // register is 0, and `futex_calls` used to leave it at a fixed process id --
    // the next test to create an io_ring then owned it under that id, its Scene
    // released the rings of its own tid only, and after eight such tests the
    // per-task ring quota answered `create returned -24` (EMFILE) in whichever
    // `ioring_ops_guards` test ran next (42/200 runs). The same shape: three
    // `invoke_guards` tests end with an enforcing syscall filter armed, and the
    // next test to run (`h3_hosts`, `keys_guards`, ...) had its first syscall
    // killed by that filter, at `task_exit_with_code` (about 1 run in 300).
    azos_sched::shim_reset();
    azos_sched::shim_reset_user_windows();
    azos_mm::shim_reset();
    // The COW share counts are the frame descriptors' `refcount`, and
    // `shim_reset` rebuilt every descriptor: no count survives the reset (a
    // count left on a recycled frame once made the next test's `munmap`
    // refuse to free it, "another COW holder", and the leak was reported
    // against the innocent test).
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
    azos_sched::shim_take_exit_table();
    azos_sched::shim_unbind_domains();
    azos_sched::process::shim_take_fork_calls();
    azos_sched::shim_disarm_yield();
    azos_sched::shim_disarm_block_outcome();
    azos_sched::shim_set_block_hook(None);
    let _ = azos_sched::shim_take_blocks();
    azos_net::shim_arm_net_poll(false);
    azos_drv_irqchip::clint::set_time(0);
    flush_decision_ring();
}

/// Overwrite the whole decision ring with records of a rule no test reads.
///
/// The ring is process-global and holds only `azos_decision::ENTRIES` records
/// (64 here): every record a test writes evicts the one written 64 records
/// before it, whoever wrote that. A test that counts the records of one rule
/// before and after (`clock_guards`' `before + 1`) then fails when the record
/// it evicts is an earlier test's record of the same rule -- which of the
/// earlier tests wrote last is the order the threads got the lock in, so a run
/// failed now and then (once in about 1500 under load). After this, every test starts with a ring that
/// holds nothing of any other test's.
fn flush_decision_ring() {
    for _ in 0..azos_decision::ENTRIES {
        azos_decision::record(azos_decision::Rule::Compress, azos_decision::Verdict::Admit, 0, [0; 3]);
    }
}

/// **`serial()` hands over a ring without the previous test's records.**
///
/// **Canary.** Drop the `flush_decision_ring()` call from `reset_state`: the
/// earlier record of the counted rule is still there and the count reads 1.
#[test]
fn a_reset_leaves_no_earlier_record_in_the_decision_ring() {
    let _g = serial();
    azos_decision::record(azos_decision::Rule::ClockStep, azos_decision::Verdict::Admit, 0xD0_0002, [0; 3]);
    reset_state();
    let mut left = 0;
    azos_decision::for_each(|r| {
        if r.rule == azos_decision::Rule::ClockStep as u8 {
            left += 1;
        }
    });
    assert_eq!(left, 0, "a record of the previous test survived the reset");
}

/// A second capability for what `h` names in `tid`'s table: the same type,
/// rights and resource, its warrant carrying one `OP_MASK` caveat of `mask`
/// (bit n = op class n, `azos_abi::invoke::op_class`). The original keeps
/// working, so a test holds both: the capability without the caveat is the
/// positive control of every refusal the caveated one gets.
pub fn op_masked(tid: u32, h: u64, mask: u64) -> u64 {
    use azos_ipc::cap::{caveat, CapExt, Caveat, Caveats, Warrant};
    let w = Warrant {
        caveats: Caveats::NONE.with(Caveat::new(caveat::OP_MASK, mask)).expect("OP_MASK is a known caveat"),
        ..Warrant::ROOT
    };
    azos_ipc::cap_store::with_table(tid, |t| {
        let (ty, perms, resource) = t.peek_raw(azos_abi::cap::CapHandle::from_raw(h as u32)).expect("a live capability");
        t.grant_warranted(ty, perms, resource, CapExt::NONE, w).expect("a free slot and caveat block").as_raw() as u64
    })
    .expect("a live capability table")
}

/// The `OP_MASK` argument naming exactly the op classes in `classes`.
pub fn classes(classes: &[u8]) -> u64 {
    classes.iter().fold(0, |m, &c| m | 1 << c)
}
