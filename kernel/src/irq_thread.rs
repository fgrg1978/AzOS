// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's own interrupt lines, threaded (Kconfig `IRQ_THREADED`).
//!
//! A ring-3 driver's line has a minimal top half (the external-interrupt
//! handler masks the line, completes it, and `irq_bind::irq_dispatch` queues
//! one event on the driver's port) and a handler that is a thread on a hard
//! reservation. The kernel's lines used to run whole in the interrupt
//! handler: the UART console's FIFO drain, the virtio completions. With
//! `IRQ_THREADED` they go through the **same mechanism**:
//!
//! * **One kernel thread**, `irq-thread`, pinned to the boot CPU (where the
//!   kernel routes its lines), on a hard reservation of its own
//!   (`IRQ_THREAD_BUDGET_PCT` of `IRQ_THREAD_PERIOD_US`, priority
//!   `IRQ_THREAD_PRIORITY`). It owns an event port and binds every
//!   registered line to it with `irq_bind_port`, exactly as a ring-3 driver
//!   does: the same table, the same budget rule.
//! * **Top half** (per ISA, `deferred()` says whether the line is the
//!   thread's): mask the line, complete it, `irq_dispatch`. Nothing touches
//!   the device.
//! * **Bottom half**: the thread takes the line's event, runs the handler
//!   that used to run in the interrupt (`kernel_line_bottom_half`, the one
//!   body per ISA, shared with the inline path), and ACKs the line. A thread
//!   that ran out of budget leaves its lines masked until it is replenished
//!   (`irq_bind::irq_sc_throttle`), so a device storming the console or a
//!   virtio queue cannot take more than the thread's share, and the share is
//!   admitted.
//! * **The timer** keeps its top half (re-arm, count, watchdog, timer wakes,
//!   vDSO): it has no line to thread.
//!
//! **Which lines.** Level and edge lines of riscv64's PLIC/APLIC and
//! aarch64's GIC: both controllers latch an edge that arrives while the line
//! is masked. x86_64's IOAPIC does not (a masked edge is lost), so none of
//! its kernel lines is registered there and it runs no thread. MSI vectors (the NIC's, the NVMe controller's) cannot be
//! masked at all and only wake a task: they were already minimal.
//!
//! **Fallback.** Until the thread runs, or if its reservation is refused,
//! every line stays inline: `deferred()` is false and the interrupt handlers
//! behave as they did without `IRQ_THREADED`.

#[cfg(not(target_arch = "x86_64"))]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(target_arch = "x86_64"))]
use azos_abi::syscall_nr::PORT_EVENT_IRQ;
#[cfg(not(target_arch = "x86_64"))]
use azos_ipc::irq_bind::{irq_ack_unmask, irq_bind_port_budgeted, Route};
#[cfg(not(target_arch = "x86_64"))]
use azos_sched::rt::{self, Reservation};

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("the IRQ thread knows riscv64, aarch64 and x86_64: a new ISA names its bottom half here");

// The bottom half of a kernel line is the ISA's own: the handler body its
// interrupt handler ran inline, shared with that inline path. x86_64
// registers no line, so it has none.
#[cfg(target_arch = "riscv64")]
use crate::entry::riscv64::irq::kernel_line_bottom_half;
#[cfg(target_arch = "aarch64")]
use crate::entry::aarch64::irq::kernel_line_bottom_half;

/// Whether this build threads the kernel's lines.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) const ENABLED: bool = azos_limits::IRQ_THREADED;

/// Lines tracked (one bit each): the interrupt controllers' ceiling.
#[cfg(not(target_arch = "x86_64"))]
const WORDS: usize = 256 / 32;

/// Lines a driver registered ([`register`]), and the subset bound to the
/// thread's port ([`deferred`]).
#[cfg(not(target_arch = "x86_64"))]
static REGISTERED: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];
#[cfg(not(target_arch = "x86_64"))]
static BOUND: [AtomicU32; WORDS] = [const { AtomicU32::new(0) }; WORDS];

/// The thread's TID and its port (the packed reference), `0` before it runs.
#[cfg(not(target_arch = "x86_64"))]
static THREAD_TID: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_arch = "x86_64"))]
static PORT: AtomicU32 = AtomicU32::new(0);
/// The CPU the thread and its lines are on.
#[cfg(not(target_arch = "x86_64"))]
static CPU: AtomicU32 = AtomicU32::new(0);

#[cfg(not(target_arch = "x86_64"))]
fn bit(map: &[AtomicU32; WORDS], line: u32) -> Option<(&AtomicU32, u32)> {
    map.get(line as usize / 32).map(|w| (w, 1u32 << (line % 32)))
}

/// Is `line` the thread's (bound to its port)? The top half asks on every
/// external interrupt: one load of one bitmap word.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub(crate) fn deferred(line: u32) -> bool {
    ENABLED && bit(&BOUND, line).is_some_and(|(w, m)| w.load(Ordering::Acquire) & m != 0)
}

/// x86_64 registers no line: the IOAPIC loses an edge that arrives while the
/// entry is masked, and its kernel lines are edge. With nothing to thread
/// there, [`start`] creates no thread.
#[cfg(target_arch = "x86_64")]
pub(crate) fn register(_line: u32) {}

/// x86_64 has no line to thread: no thread.
#[cfg(target_arch = "x86_64")]
pub(crate) fn start(_cpu: usize) {}

/// A driver's interrupt line is the kernel's and may be threaded: the console
/// UART, a virtio device. Called where the line is enabled. Without
/// `IRQ_THREADED`, a no-op.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn register(line: u32) {
    if !ENABLED {
        return;
    }
    if let Some((w, m)) = bit(&REGISTERED, line) {
        w.fetch_or(m, Ordering::AcqRel);
    }
    // The thread is already running: bind the late line now.
    if PORT.load(Ordering::Acquire) != 0 {
        bind(line);
    }
}

/// Bind `line` to the thread's port. The thread's SC is the line's budget.
#[cfg(not(target_arch = "x86_64"))]
fn bind(line: u32) {
    let (tid, port, cpu) = (
        THREAD_TID.load(Ordering::Acquire),
        PORT.load(Ordering::Acquire),
        CPU.load(Ordering::Relaxed),
    );
    match irq_bind_port_budgeted(line, tid, port, line as u64, Route::Cpu(cpu)) {
        Ok(_) => {
            if let Some((w, m)) = bit(&BOUND, line) {
                w.fetch_or(m, Ordering::AcqRel);
            }
        }
        Err(e) => azos_drv_sys::kwarn!("[IRQ] kernel line {} stays in the interrupt handler: {:?}", line, e),
    }
}

/// Create the thread on `cpu`, once, from `kernel_main` before the scheduler
/// starts. The thread admits its own reservation when it first runs (a
/// refusal leaves every line inline, and the thread exits).
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn start(cpu: usize) {
    if !ENABLED {
        return;
    }
    azos_sched::task_create_affinity(
        "irq-thread",
        thread_main,
        cpu,
        azos_limits::IRQ_THREAD_PRIORITY as u32,
        cpu as i8,
    );
}

/// The nanoseconds the port wait reads its clock in.
#[cfg(not(target_arch = "x86_64"))]
fn now_ns() -> u64 {
    azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::freq())
}

#[cfg(not(target_arch = "x86_64"))]
fn thread_main(cpu: usize) {
    let prio = azos_limits::IRQ_THREAD_PRIORITY as u32;
    let period = azos_limits::IRQ_THREAD_PERIOD_US as u64;
    let r = Reservation {
        runtime_us: (period * azos_limits::IRQ_THREAD_BUDGET_PCT as u64 / 100).max(1),
        period_us: period,
        deadline_us: 0,
        hard: true,
        cpu_mask: 1 << cpu,
        band: azos_sched::task::is_rt_priority(prio),
        level: prio,
    };
    let tid = azos_sched::current_task_tid();
    let me = azos_sched::idx_for_tid(tid).unwrap_or(usize::MAX);
    if let Err(e) = rt::reserve(me, r) {
        azos_drv_sys::kwarn!(
            "[IRQ] irq-thread reservation refused ({}): the kernel's lines stay in the interrupt handler",
            e.name()
        );
        azos_sched::task_exit();
    }
    let Ok(port) = azos_ipc::port::port_create_ref(tid as usize).ok_or(()) else {
        azos_drv_sys::kwarn!("[IRQ] irq-thread has no port: the kernel's lines stay in the interrupt handler");
        azos_sched::task_exit();
    };
    CPU.store(cpu as u32, Ordering::Relaxed);
    THREAD_TID.store(tid, Ordering::Release);
    PORT.store(port, Ordering::Release);
    #[cfg(not(target_arch = "x86_64"))]
    for (i, w) in REGISTERED.iter().enumerate() {
        let bits = w.load(Ordering::Acquire);
        for b in 0..32 {
            if bits & (1 << b) != 0 {
                bind((i * 32 + b) as u32);
            }
        }
    }
    azos_drv_sys::kprintln!(
        "[IRQ] irq-thread up on CPU {}: budget {} % of {} us, priority {}",
        cpu, azos_limits::IRQ_THREAD_BUDGET_PCT, azos_limits::IRQ_THREAD_PERIOD_US, azos_limits::IRQ_THREAD_PRIORITY
    );

    loop {
        let waited = azos_ipc::port::port_wait_until_ref(port, tid, u64::MAX, now_ns, |until| {
            let reason = match until {
                None => azos_sched::WaitReason::Port(port),
                Some(ns) => azos_sched::WaitReason::Timer(azos_abi::time::ns_to_ticks_ceil(
                    ns,
                    azos_drv_sys::timebase::freq(),
                )),
            };
            azos_sched::task_block_killable(reason) == azos_sched::BlockOutcome::Refused
        });
        let Ok(Some(event)) = waited else { continue };
        match event.source_type {
            #[cfg(not(target_arch = "x86_64"))]
            PORT_EVENT_IRQ => {
                let line = event.source_id;
                kernel_line_bottom_half(line);
                // Unmasks the line unless the thread's budget is spent, in
                // which case the replenishment does.
                let _ = irq_ack_unmask(line, tid);
            }
            _ => {}
        }
    }
}
