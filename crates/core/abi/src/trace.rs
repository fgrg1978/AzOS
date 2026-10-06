// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel tracer's ABI (wave 15, TRACE): `SYS_TRACE_CTL_TYPED` (632)
//! operations, the event classes a mask selects, and the event ids a record
//! carries. The capability is `Cap<Trace>` (`CapKind::Trace`, resource 0),
//! granted only by a topology row (`TRACECTL.ELF`'s).
//!
//! The shared-memory layout the records travel in is `azos_spsc::trace`
//! (both sides compile that crate); this module only names things.

// ── SYS_TRACE_CTL_TYPED (632): a0 = Cap<Trace>, a1 = op, a2 = arg ───────────

/// The classes compiled into this kernel, as a mask (`1 << TRACE_CLASS_*`).
/// Needs `READ`. `-ENOSYS` when the tracer is compiled out (Kconfig `KTRACE`).
pub const TRACE_OP_INFO: u64 = 1;
/// Map the trace region (every CPU's ring) into the caller, read-write (the
/// reader stores its tails), and return its base address. Needs `READ` and
/// `WRITE`. `-EBUSY` when the caller already maps it.
pub const TRACE_OP_MAP: u64 = 2;
/// The runtime class mask now. Needs `READ`.
pub const TRACE_OP_GET_MASK: u64 = 3;
/// Set the runtime class mask to `a2` (bits of classes not compiled in are
/// ignored) and return the previous one. Needs `WRITE`. `0` stops recording.
pub const TRACE_OP_SET_MASK: u64 = 4;
/// Bytes of the trace region (what [`TRACE_OP_MAP`] maps). Needs `READ`.
pub const TRACE_OP_REGION_BYTES: u64 = 5;

// ── Classes: bit positions in the runtime mask ──────────────────────────────

/// Scheduler: context switch, wakeup.
pub const TRACE_CLASS_SCHED: u32 = 0;
/// Interrupts: entry and exit.
pub const TRACE_CLASS_IRQ: u32 = 1;
/// System calls: entry, exit, and a seccomp denial.
pub const TRACE_CLASS_SYSCALL: u32 = 2;
/// Fast IPC: call and reply.
pub const TRACE_CLASS_IPC: u32 = 3;
/// Page faults.
pub const TRACE_CLASS_FAULT: u32 = 4;
/// Process life cycle: spawn, exit, a delivered signal.
pub const TRACE_CLASS_PROC: u32 = 5;
/// Masked-window maxima from the `LAT_TRACE` tracer.
pub const TRACE_CLASS_LAT: u32 = 6;
/// Number of classes; a mask is `(1 << TRACE_CLASSES) - 1` at most.
pub const TRACE_CLASSES: u32 = 7;
/// Every class.
pub const TRACE_MASK_ALL: u32 = (1 << TRACE_CLASSES) - 1;

/// The class's short name, as `tracectl` prints and parses it.
pub const fn trace_class_name(class: u32) -> &'static str {
    match class {
        TRACE_CLASS_SCHED => "sched",
        TRACE_CLASS_IRQ => "irq",
        TRACE_CLASS_SYSCALL => "syscall",
        TRACE_CLASS_IPC => "ipc",
        TRACE_CLASS_FAULT => "fault",
        TRACE_CLASS_PROC => "proc",
        TRACE_CLASS_LAT => "lat",
        _ => "?",
    }
}

// ── Event ids: (class << 8) | n ─────────────────────────────────────────────

/// The class an event id belongs to.
pub const fn trace_event_class(event: u16) -> u32 {
    (event >> 8) as u32
}

const fn ev(class: u32, n: u16) -> u16 {
    ((class as u16) << 8) | n
}

/// `[prev_tid, next_tid, prev_state, reason]`.
pub const TRACE_EV_SCHED_SWITCH: u16 = ev(TRACE_CLASS_SCHED, 1);
/// `[tid, target_cpu, waker_tid, 0]`.
pub const TRACE_EV_SCHED_WAKEUP: u16 = ev(TRACE_CLASS_SCHED, 2);
/// `[irq, 0, 0, 0]`.
pub const TRACE_EV_IRQ_ENTRY: u16 = ev(TRACE_CLASS_IRQ, 1);
/// `[irq, 0, 0, 0]`.
pub const TRACE_EV_IRQ_EXIT: u16 = ev(TRACE_CLASS_IRQ, 2);
/// `[nr, tid, arg0 low, arg1 low]`.
pub const TRACE_EV_SYS_ENTER: u16 = ev(TRACE_CLASS_SYSCALL, 1);
/// `[nr, tid, ret low, ret high]`.
pub const TRACE_EV_SYS_EXIT: u16 = ev(TRACE_CLASS_SYSCALL, 2);
/// A seccomp denial: `[nr, tid, 0, 0]`.
pub const TRACE_EV_SYS_DENY: u16 = ev(TRACE_CLASS_SYSCALL, 3);
/// `[caller_tid, server_tid, label, 0]`.
pub const TRACE_EV_IPC_CALL: u16 = ev(TRACE_CLASS_IPC, 1);
/// `[server_tid, caller_tid, status, 0]`.
pub const TRACE_EV_IPC_REPLY: u16 = ev(TRACE_CLASS_IPC, 2);
/// `[addr low, addr high, cause, tid]`.
pub const TRACE_EV_PAGE_FAULT: u16 = ev(TRACE_CLASS_FAULT, 1);
/// `[child_tid, parent_tid, 0, 0]`.
pub const TRACE_EV_PROC_SPAWN: u16 = ev(TRACE_CLASS_PROC, 1);
/// `[tid, exit_code, 0, 0]`.
pub const TRACE_EV_PROC_EXIT: u16 = ev(TRACE_CLASS_PROC, 2);
/// `[tid, signo, sender_tid, action]` (action 0 discarded, 1 handler,
/// 2 terminated).
pub const TRACE_EV_PROC_SIGNAL: u16 = ev(TRACE_CLASS_PROC, 3);
/// A new longest interrupts-masked window on this CPU:
/// `[ticks low, ticks high, open site low, close site low]`.
pub const TRACE_EV_LAT_IRQSOFF: u16 = ev(TRACE_CLASS_LAT, 1);
/// A new longest preemption-disabled window: as [`TRACE_EV_LAT_IRQSOFF`].
pub const TRACE_EV_LAT_PREEMPTOFF: u16 = ev(TRACE_CLASS_LAT, 2);

/// The event's name, as `tracectl` prints it.
pub const fn trace_event_name(event: u16) -> &'static str {
    match event {
        TRACE_EV_SCHED_SWITCH => "sched_switch",
        TRACE_EV_SCHED_WAKEUP => "sched_wakeup",
        TRACE_EV_IRQ_ENTRY => "irq_entry",
        TRACE_EV_IRQ_EXIT => "irq_exit",
        TRACE_EV_SYS_ENTER => "sys_enter",
        TRACE_EV_SYS_EXIT => "sys_exit",
        TRACE_EV_SYS_DENY => "sys_deny",
        TRACE_EV_IPC_CALL => "ipc_call",
        TRACE_EV_IPC_REPLY => "ipc_reply",
        TRACE_EV_PAGE_FAULT => "page_fault",
        TRACE_EV_PROC_SPAWN => "proc_spawn",
        TRACE_EV_PROC_EXIT => "proc_exit",
        TRACE_EV_PROC_SIGNAL => "proc_signal",
        TRACE_EV_LAT_IRQSOFF => "lat_irqsoff",
        TRACE_EV_LAT_PREEMPTOFF => "lat_preemptoff",
        _ => "unknown",
    }
}
