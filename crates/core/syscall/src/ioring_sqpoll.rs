// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The io_ring SQ poller task (`crates/core/ipc/src/io_ring.rs`, "SQ polling").
//!
//! One kernel task per polled ring, created by the pass that ran the ring's
//! `OP_SQPOLL_START` (so only for an owner whose topology row declares
//! `sqpoll_idle_ms`), at the owner's priority. It loops over
//! `io_ring_sqpoll_pass`: while entries keep arriving it passes and yields;
//! after `idle_ms` of an empty queue it parks through the
//! `io_ring_sqpoll_prepare_park` handshake and blocks until a wake-up submit,
//! the earliest parked timer's deadline, or — while a notify wait is parked —
//! one millisecond, the cadence at which it re-looks at the word (the notify
//! primitive's wake does not reach it). When its ring is destroyed, or its
//! owner exits, the destroy wakes it, its pass reads `Gone`, it prints its
//! counters and exits.
//!
//! Authority is not this module's: every entry of every pass is decided by
//! `run_pass` exactly as a submitted one is (see `io_ring.rs`).
//!
//! Kernel only: the host suites drive the ring-side API directly.

use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_ipc::io_ring::{self, SqpollHooks, SqpollPark, SqpollPass};

/// The hooks `install` registers.
static HOOKS: SqpollHooks = SqpollHooks { spawn, wake };

/// Register the SQ poller hooks with the ring module. Called once at boot,
/// after the op table.
pub fn install() {
    io_ring::io_ring_register_sqpoll(&HOOKS);
}

/// `OP_SQPOLL_START`'s task: named `ioring-sqpoll`, at the owner's priority,
/// pinned to a hart OTHER than the owner's. Created with
/// `try_task_create_affinity`, which is fallible and is also what `fork` uses
/// from a syscall.
///
/// A poller sharing its owner's hart only takes turns with it: measured in
/// wave 6, SQPOLL on one hart cost 2126/2394 instructions per op at x1 against
/// ~1000 for a plain submit. So (owner decision 2026-09-28) a machine with ONE
/// online hart refuses the poller — the ring keeps working by submit — and the
/// refusal is recorded (`SAFETY_TOPO_CLASS_REFUSED`, site
/// `topo_sched::SITE_SQPOLL_SHARED_HART`); with more harts the poller is pinned
/// to the next one after the owner's. `pass` runs in the owner's submit
/// syscall, so the current hart is the owner's.
fn spawn(r: u32, owner_tid: u32) -> Option<u32> {
    let prio = azos_sched::task_priority(owner_tid)?;
    let harts = azos_sched::smp::NUM_ONLINE_CPUS.load(core::sync::atomic::Ordering::Acquire);
    if harts < 2 {
        crate::topo_sched::record_refusal(crate::topo_sched::SITE_SQPOLL_SHARED_HART, owner_tid);
        azos_drv_sys::kwarn!(
            "[SQPOLL] refused for tid {}: one online hart, the poller would share it with its owner",
            owner_tid);
        return None;
    }
    let hart = (azos_sched::current_task_hart() + 1) % harts;
    let idx = azos_sched::try_task_create_affinity(
        "ioring-sqpoll", poller, r as usize, prio, hart as i8)?;
    azos_sched::tid_for_idx(idx)
}

/// Wake a parked poller. The predicate accepts any wait: the poller blocks in
/// one place only, and a wake that lands before it has committed to blocking
/// must be stamped (K-C9), which a predicate on the not-yet-set wait reason
/// would refuse.
fn wake(poller_tid: u32) {
    let _ = azos_sched::scheduler::wake_task_by_tid(poller_tid, &|_| true);
}

fn ms_to_ticks(ms: u32) -> u64 {
    azos_abi::time::ns_to_ticks_ceil(ms as u64 * 1_000_000, TIMER_FREQ)
}

/// The poller's body. `arg` is the ring's packed reference.
fn poller(arg: usize) {
    let r = arg as u32;
    let born = now();
    let first_hart = azos_sched::current_task_hart();
    let (mut passes, mut empty, mut parks, mut ran, mut busy) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut last_work = now();
    loop {
        let t0 = now();
        let p = io_ring::io_ring_sqpoll_pass(r);
        busy = busy.wrapping_add(now().wrapping_sub(t0));
        match p {
            SqpollPass::Gone => break,
            SqpollPass::Busy => azos_sched::task_yield(),
            SqpollPass::Done { ran: n, idle_ms, next_deadline_ns, words } => {
                passes += 1;
                if n != 0 {
                    ran += n as u64;
                    last_work = now();
                    azos_sched::task_yield();
                    continue;
                }
                empty += 1;
                if now().wrapping_sub(last_work) < ms_to_ticks(idle_ms) {
                    azos_sched::task_yield();
                    continue;
                }
                match io_ring::io_ring_sqpoll_prepare_park(r) {
                    SqpollPark::Gone => break,
                    SqpollPark::Busy | SqpollPark::NotIdle => continue,
                    SqpollPark::Parked => {
                        parks += 1;
                        let until = if words {
                            now().saturating_add(ms_to_ticks(1))
                        } else if next_deadline_ns != u64::MAX {
                            azos_abi::time::ns_to_ticks_ceil(next_deadline_ns, TIMER_FREQ)
                        } else {
                            u64::MAX
                        };
                        azos_sched::wait::task_block(azos_sched::WaitReason::Timer(until));
                        last_work = now();
                    }
                }
            }
        }
    }
    // Under `-icount` a tick count is an instruction count, so `busy` is the
    // hart time the poller spent in passes and `life` the time it existed.
    azos_drv_sys::kprintln!(
        "[SQPOLL] ring={:#x} passes={} empty={} parks={} ran={} busy_ticks={} life_ticks={} hart={}->{}",
        r, passes, empty, parks, ran, busy, now().wrapping_sub(born),
        first_hart, azos_sched::current_task_hart()
    );
    azos_sched::task_exit();
}
