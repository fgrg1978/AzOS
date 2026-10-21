// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The handler halves of an interrupt line's ops (`DEVICE_IRQ_BIND`,
// `DEVICE_IRQ_ACK`) that sit behind the capability checks of `invoke.rs`
// (those are driven through the entry in `typed_ipc.rs`): the controller's
// refusal, and what an ACK answers for a line whose handler is out of budget.
//
// The IRQ binding table (`crates/core/ipc/src/irq_bind.rs`) is the real file.
// It has no reset visible here, so each test binds only what it needs and
// unbinds what it bound.
//
// **Not covered on this host:** the controller itself (`arch_irq_bound`,
// the unmask of an ACK) is ISA code compiled out here; the QEMU rows run it.

use super::harness::serial;
use azos_ipc::irq_bind::{irq_bind_port, irq_bindings_of, irq_unbind_all, Route};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_TID: AtomicU32 = AtomicU32::new(0x6B00_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// A line no other test here binds.
const LINE: u32 = 13;

fn port_for(tid: u32) -> u32 {
    azos_ipc::port::port_create_ref(tid as usize).expect("a port")
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
    let _g = serial();
    let tid = fresh_tid();
    let port = port_for(tid);
    assert!(irq_bind_port(LINE, tid, port, 1, Route::Any(0)).is_ok());
    assert!(!route_stored_binding_with(LINE, tid, |_| false));
    assert_eq!(irq_bindings_of(LINE), 0, "the refused binding is still stored");

    assert!(irq_bind_port(LINE, tid, port, 1, Route::Any(0)).is_ok());
    assert!(route_stored_binding_with(LINE, tid, |irq| irq == LINE));
    assert_eq!(irq_bindings_of(LINE), 1, "the routed binding was dropped");
    irq_unbind_all(tid);
}

/// `DEVICE_IRQ_ACK`'s handler answers 0 for a live line and `-ENOENT` for one
/// nobody binds. (The third answer, 1 for a line held by a spent budget, needs
/// a binding on a reservation, which is `IRQ_THREADED`: the binding table's own
/// suite drives it, `tests/host/ipc-tests`.)
///
/// **Canary.** Answer 0 for `Ack::NotBound` in `sys_irq_ack`: the missing line
/// reads 0.
#[test]
fn an_ack_answers_for_a_missing_binding() {
    let _g = serial();
    let tid = fresh_tid();
    assert_eq!(sys_irq_ack(tid, LINE), azos_abi::error::Errno::ENOENT.to_syscall_ret(), "nobody binds the line");
    let port = port_for(tid);
    assert!(irq_bind_port(LINE, tid, port, 1, Route::Any(0)).is_ok());
    assert_eq!(sys_irq_ack(tid, LINE), 0);
    irq_unbind_all(tid);
}
