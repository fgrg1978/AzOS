// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The F06 driver-server calls `SYS_DRV_REGISTER` (300), `_IRQ_WAIT` (304),
// `_IRQ_ACK` (305), `_DMA_ALLOC` (306), `_DMA_FREE` (307), `_DMA_SYNC` (308),
// `_HEARTBEAT` (309) and `_GET_DEVICE` (310), and `SYS_IRQ_BIND` (510) and
// `SYS_TRACE_DUMP` (518). Each body was written inside `dispatch.rs`'s match
// until wave 7 moved it into a `sys_*` function in `handlers.rs`; this file is
// their first host coverage.
//
// **The refusal code is -1, and the tests assert it exactly.** `dispatch.rs`
// has its own `E_PERM = -1`, which shadows the glob-imported
// `handlers::E_PERM = -99` inside that file. A moved body that kept writing
// `E_PERM` would now answer -99 with nothing else failing, so every refusal
// below is compared against the literal.
//
// The driver registry (`crates/core/sched/src/driver.rs`) and the IRQ binding
// table (`crates/core/ipc/src/irq_bind.rs`) are the real files. Neither has a
// reset, so each test registers only what it needs and unbinds what it bound.
//
// **Not covered on this host:** `SYS_DRV_IRQ_ACK`'s PLIC completion is
// `#[cfg(target_arch = "riscv64")]` and is compiled out here; the tests prove
// the capability gate in front of it, not the completion.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_arch_api::PagePerms;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_TID: AtomicU32 = AtomicU32::new(0x6B00_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// The `cap_store` pool slot every ring-3 caller here is bound to.
const SLOT: usize = 46;
/// Where ring-3 buffers live in this file. Clear of the other guard files.
const BUF_VA: usize = 0x007A_0000;
/// Never mapped by this file.
const UNMAPPED_VA: usize = 0x007B_0000;

/// Ring 3, bound to [`SLOT`] with an empty capability table, with one page
/// mapped at [`BUF_VA`]; returns that page's host pointer.
fn ring3(tid: u32) -> *mut u8 {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, BUF_VA, phys, PagePerms::USER_RW).expect("map");
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096) };
    phys as *mut u8
}

fn hold(tid: u32, kind: CapKind, resource: u32, perms: CapPerms) {
    assert!(
        azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(kind, perms, resource))
            .flatten()
            .is_some(),
        "could not grant {kind:?} {resource:#x} to {tid:#x}"
    );
}

fn name_of(id: usize) -> Vec<u8> {
    let e = azos_sched::driver_info(id).expect("no such driver");
    let n = e.name.iter().position(|&b| b == 0).unwrap_or(e.name.len());
    e.name[..n].to_vec()
}

// ── SYS_DRV_REGISTER (300) ─────────────────────────────────────────────────

#[test]
fn drv_register_copies_the_name_from_ring3_and_returns_the_slot() {
    let _g = serial();
    let page = ring3(fresh_tid());
    unsafe { core::ptr::copy_nonoverlapping(b"drv.reg".as_ptr(), page, 7) };
    let id = sys_drv_register(BUF_VA as u64, 7);
    assert!(id >= 0, "refused: {id}");
    assert_eq!(name_of(id as usize), b"drv.reg");
}

/// The name is capped at 32 bytes before the copy, not refused.
#[test]
fn drv_register_caps_the_name_at_32_bytes() {
    let _g = serial();
    let page = ring3(fresh_tid());
    let long: Vec<u8> = (0..40u8).map(|i| b'a' + (i % 26)).collect();
    unsafe { core::ptr::copy_nonoverlapping(long.as_ptr(), page, long.len()) };
    let id = sys_drv_register(BUF_VA as u64, long.len() as u64);
    assert!(id >= 0, "refused: {id}");
    assert_eq!(name_of(id as usize), &long[..32]);
}

#[test]
fn drv_register_refuses_null_empty_and_unmapped_names() {
    let _g = serial();
    ring3(fresh_tid());
    assert_eq!(sys_drv_register(0, 4), -1, "null pointer");
    assert_eq!(sys_drv_register(BUF_VA as u64, 0), -1, "zero length");
    assert_eq!(sys_drv_register(UNMAPPED_VA as u64, 4), -1, "unmapped name");
}

// ── SYS_DRV_IRQ_WAIT (304) ─────────────────────────────────────────────────

/// A wake is 0, a K-C29 refusal is -EAGAIN, and the block names the line with
/// `a0` narrowed by `as u32` (the high half dropped, as the arm did).
#[test]
fn drv_irq_wait_blocks_on_the_line_and_reports_the_outcome() {
    let _g = serial();
    azos_sched::shim_take_blocks();
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Returned);
    assert_eq!(sys_drv_irq_wait(7), 0);
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Refused);
    assert_eq!(sys_drv_irq_wait((1u64 << 32) | 9), -11);
    assert_eq!(
        azos_sched::shim_take_blocks(),
        vec![azos_sched::WaitReason::Irq(7), azos_sched::WaitReason::Irq(9)]
    );
}

// ── SYS_DRV_IRQ_ACK (305) ──────────────────────────────────────────────────

#[test]
fn drv_irq_ack_refuses_ring3_without_the_irq_capability_with_minus_one() {
    let _g = serial();
    let tid = fresh_tid();
    ring3(tid);
    hold(tid, CapKind::Irq, 6, CapPerms::READ);
    // Holding line 6 does not admit line 7.
    assert_eq!(sys_drv_irq_ack(7), -1);
}

#[test]
fn drv_irq_ack_admits_a_holder_and_the_kernel() {
    let _g = serial();
    let tid = fresh_tid();
    ring3(tid);
    hold(tid, CapKind::Irq, 7, CapPerms::READ);
    assert_eq!(sys_drv_irq_ack(7), 0);
    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_drv_irq_ack(8), 0);
}

// ── SYS_DRV_DMA_ALLOC / _FREE / _SYNC (306-308) ────────────────────────────

/// Kernel-only: a ring-3 caller is refused before any page is taken.
#[test]
fn dma_alloc_refuses_ring3_and_allocates_nothing() {
    let _g = serial();
    ring3(fresh_tid());
    let before = azos_mm::shim_pages_in_use();
    assert_eq!(sys_drv_dma_alloc(4096), -1);
    assert_eq!(azos_mm::shim_pages_in_use(), before, "a refused alloc took a page");
}

#[test]
fn dma_alloc_bounds_the_size_for_the_kernel() {
    let _g = serial();
    let before = azos_mm::shim_pages_in_use();
    assert_eq!(sys_drv_dma_alloc(0), -1);
    assert_eq!(sys_drv_dma_alloc(65_537), -1);
    assert_eq!(azos_mm::shim_pages_in_use(), before);
    // The ceiling itself is admitted (one page, whatever the size).
    let phys = sys_drv_dma_alloc(65_536);
    assert!(phys > 0, "refused the 64 KiB ceiling: {phys}");
    assert_eq!(azos_mm::shim_pages_in_use(), before + 1);
    assert_eq!(sys_drv_dma_free(phys as u64), 0);
    assert_eq!(azos_mm::shim_pages_in_use(), before);
}

/// Kernel-only: a ring-3 free of a live page is refused and the page stays
/// allocated (the escape primitive the gate closes).
#[test]
fn dma_free_refuses_ring3_and_frees_nothing() {
    let _g = serial();
    let phys = sys_drv_dma_alloc(4096);
    assert!(phys > 0);
    let held = azos_mm::shim_pages_in_use();
    ring3(fresh_tid());
    let after_setup = azos_mm::shim_pages_in_use();
    assert_eq!(sys_drv_dma_free(phys as u64), -1);
    assert_eq!(azos_mm::shim_pages_in_use(), after_setup, "a ring-3 free released a page");
    assert!(held <= after_setup);
    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_drv_dma_free(phys as u64), 0);
    assert_eq!(azos_mm::shim_pages_in_use(), after_setup - 1);
}

#[test]
fn dma_sync_answers_zero_for_anyone() {
    let _g = serial();
    assert_eq!(sys_drv_dma_sync(), 0);
    ring3(fresh_tid());
    assert_eq!(sys_drv_dma_sync(), 0);
}

// ── SYS_DRV_HEARTBEAT (309) ────────────────────────────────────────────────

/// A registered, running driver: `id`. Registered as the kernel.
fn running_driver(name: &[u8]) -> usize {
    azos_sched::set_current_user_pt(0);
    let id = azos_sched::driver_register(name).expect("registry full");
    assert!(azos_sched::driver_start(id, 0x6BFF_0001));
    id
}

/// The clock reads `ms` milliseconds.
fn clock_at_ms(ms: u64) {
    azos_drv_irqchip::clint::set_time(ms * (azos_drv_sys::timebase::TIMER_FREQ / 1000));
}

#[test]
fn heartbeat_from_the_kernel_stamps_the_clock_in_milliseconds() {
    let _g = serial();
    let id = running_driver(b"drv.hb.k");
    clock_at_ms(4_321);
    assert_eq!(sys_drv_heartbeat(id as u64), 0);
    clock_at_ms(0);
    assert_eq!(azos_sched::driver_info(id).unwrap().last_heartbeat, 4_321);
}

/// U07-5: a ring-3 caller that does not own the driver-server kind named by
/// `a0` is refused with -1 and the heartbeat is not refreshed.
#[test]
fn heartbeat_from_a_ring3_stranger_is_refused_and_stamps_nothing() {
    let _g = serial();
    let id = running_driver(b"drv.hb.u");
    let stamp = azos_sched::driver_info(id).unwrap().last_heartbeat;
    ring3(fresh_tid());
    clock_at_ms(9_999);
    assert_eq!(sys_drv_heartbeat(id as u64), -1);
    clock_at_ms(0);
    assert_eq!(azos_sched::driver_info(id).unwrap().last_heartbeat, stamp);
}

// ── SYS_DRV_GET_DEVICE (310) ───────────────────────────────────────────────

#[test]
fn get_device_copies_at_most_out_len_bytes_of_the_name() {
    let _g = serial();
    azos_sched::set_current_user_pt(0);
    let id = azos_sched::driver_register(b"drv.dev").expect("registry full") as u64;
    let page = ring3(fresh_tid());
    assert_eq!(sys_drv_get_device(id, BUF_VA as u64, 3), 3);
    assert_eq!(unsafe { core::slice::from_raw_parts(page, 8) }, b"drv\0\0\0\0\0");
    assert_eq!(sys_drv_get_device(id, BUF_VA as u64, 64), 7);
    assert_eq!(unsafe { core::slice::from_raw_parts(page, 8) }, b"drv.dev\0");
}

#[test]
fn get_device_refuses_an_unknown_id_and_an_unmapped_buffer() {
    let _g = serial();
    azos_sched::set_current_user_pt(0);
    let id = azos_sched::driver_register(b"drv.dev2").expect("registry full") as u64;
    ring3(fresh_tid());
    assert_eq!(sys_drv_get_device(16, BUF_VA as u64, 8), -1, "slot past the registry");
    assert_eq!(sys_drv_get_device(id, UNMAPPED_VA as u64, 8), -1, "unmapped destination");
}

// ── SYS_IRQ_BIND (510) ─────────────────────────────────────────────────────

#[test]
fn irq_bind_refuses_ring3_without_the_irq_capability_with_minus_one() {
    let _g = serial();
    let tid = fresh_tid();
    ring3(tid);
    hold(tid, CapKind::Irq, 10, CapPerms::READ);
    assert_eq!(sys_irq_bind(11, 0, 0, 0), -1);
}

#[test]
fn irq_bind_wake_task_binds_and_an_unknown_target_type_is_refused() {
    let _g = serial();
    let tid = fresh_tid();
    ring3(tid);
    hold(tid, CapKind::Irq, 12, CapPerms::READ);
    assert_eq!(sys_irq_bind(12, 2, 0, 0), -1, "target type 2 accepted");
    assert_eq!(sys_irq_bind(12, 0, 0, 0), 0);
    // No live port at index 0x3F: the port form is refused by `irq_bind`.
    assert_eq!(sys_irq_bind(12, 1, 0x3F, 0xAB), -1);
    azos_ipc::irq_bind::irq_unbind_all(tid);
}

/// Wave 10 IRQ5: a line the interrupt controller refuses after the binding
/// was stored leaves no binding behind, and a routed one keeps it. (The
/// refusal itself is ISA code — PLIC probe, APLIC read-back, GIC
/// `ITLinesNumber` — so the route is the closure here; the QEMU rows run the
/// real one.)
///
/// **Canary.** Drop the `irq_unbind` in `route_stored_binding_with`: the
/// refused binding is still stored.
#[test]
fn a_refused_route_undoes_the_stored_binding_and_a_routed_one_keeps_it() {
    use azos_ipc::irq_bind::{irq_bind, irq_bindings_of, irq_unbind_all, IrqTarget};
    let _g = serial();
    let tid = fresh_tid();
    assert_eq!(irq_bind(13, tid, IrqTarget::WakeTask(tid)), 0);
    assert!(!route_stored_binding_with(13, tid, |_| false));
    assert_eq!(irq_bindings_of(13), 0, "the refused binding is still stored");

    assert_eq!(irq_bind(13, tid, IrqTarget::WakeTask(tid)), 0);
    assert!(route_stored_binding_with(13, tid, |irq| irq == 13));
    assert_eq!(irq_bindings_of(13), 1, "the routed binding was dropped");
    irq_unbind_all(tid);
}

// ── SYS_TRACE_DUMP (518) ───────────────────────────────────────────────────

#[test]
fn trace_dump_defaults_zero_to_fifty_entries() {
    let _g = serial();
    azos_ipc::shim_take_trace_dumps();
    assert_eq!(sys_trace_dump(0), 0);
    assert_eq!(sys_trace_dump(7), 0);
    assert_eq!(azos_ipc::shim_take_trace_dumps(), vec![50, 7]);
}
