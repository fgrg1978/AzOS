// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `install_sched_hooks` smoke cluster (aarch64 parity task S2): the
//! callbacks that function wires — WaitQueue block/wake and the task-exit
//! resource-release hook — were all silent on
//! aarch64 until that function was written. Silent means no error and no
//! failing test, which is exactly what makes a marker that only checks
//! "the hook is installed" worthless: the tasks below instead read
//! back the ACTUAL effect of each callback firing. ISA-neutral (no
//! `target_arch` branch anywhere in this cluster) and diskless — none of
//! `azos_ipc::cap_store`/`azos_sync::waitqueue` need the topology or a
//! mounted volume — so it is spawned
//! unconditionally alongside `phase3-a`/`phase3-b`, the same place both
//! `kernel_main`s already create tasks that need no disk.
//!
//! Feature-gated rather than folded into the plain `qemu` feature so
//! enabling it cannot perturb any existing gate row's log-matching: this
//! prints NEW lines no existing row greps for, but keeping it opt-in
//! costs nothing and removes the risk entirely.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use crate::kprintln;

// ── WaitQueue: prove `wait()` BLOCKS, not spins ─────────────────────
//
// `crates/core/sync/src/waitqueue.rs`'s own doc: with no callbacks
// registered, `wait()` degrades to a no-op — it returns immediately
// instead of blocking. A caller built around `wait()` (`Completion`) then races ahead of whatever it was supposed to wait
// for. The producer counts up to a large, generous number and only
// THEN wakes the waiter; the waiter calls `wait()` once and immediately
// reads the counter. A real block reads back near the generous ceiling
// (the waiter only resumed once the producer finished and called
// `wake_one()`); a broken `wait()` reads back near zero (the waiter's
// single call returned at once, racing the producer's very first few
// increments).
//
// `static mut` + `&raw mut`, the same idiom this file already uses for
// `CFG_BUF`/`AUTORUN_PATH`: `WaitQueue::wait()`/`wake_one()` take
// `&mut self` at the type level even though the only field they touch
// (`inner`) is spinlock-protected, and both tasks below are pinned to
// the SAME hart (`WAKE_HART`), so there is never a second live access
// in flight — only ever one task running at a time on that hart.
static mut WQ: azos_sync::waitqueue::WaitQueue =
    azos_sync::waitqueue::WaitQueue::new();
static WQ_COUNTER: AtomicU32 = AtomicU32::new(0);
static WQ_WAITER_DONE: AtomicU32 = AtomicU32::new(0);
/// Generous: large enough that "the waiter raced ahead" (broken) and
/// "the waiter blocked until woken" (correct) read back nothing alike,
/// on either ISA's QEMU-TCG instruction rate.
const WQ_CEILING: u32 = 300_000;
const WQ_HART: i8 = 0;
/// Bounded so a genuinely broken wake path still ends the row instead of
/// spinning forever: the producer wakes once per millisecond for this
/// long (counter time; it was 100 wakes one yield apart, a count).
const WQ_WAKE_FOR_MS: u64 = 5_000;

fn wq_producer_task(_arg: usize) {
    for _ in 0..WQ_CEILING {
        WQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
    let wq = unsafe { &mut *(&raw mut WQ) };
    // Wake REPEATEDLY until the waiter reports in, instead of once.
    //
    // One `wake_one()` is a lost wake-up waiting to happen, and this
    // smoke lost it about two runs in three (measured 2026-09-24): the
    // producer can finish counting and wake before the waiter has
    // reached `wait()` at all, and a wake aimed at a task that is not
    // yet blocked has nowhere to land — the kernel's wake-stamp recovery
    // covers a task caught MID-block, not one that has not arrived.
    // Repeating preserves what the marker discriminates: a `wait()` that
    // spins instead of blocking still returns early, with the counter
    // far below the ceiling.
    let woken = azos_syscall::sleep::wait_until_ms(WQ_WAKE_FOR_MS, 1, || {
        if WQ_WAITER_DONE.load(Ordering::Acquire) == 1 {
            return true;
        }
        wq.wake_one();
        false
    });
    if !woken {
        FAILS.fetch_add(1, Ordering::SeqCst);
        kprintln!("[SCHEDHOOKS] waitqueue FAIL: the waiter did not report in {} ms of wakes",
            WQ_WAKE_FOR_MS);
    }
}

fn wq_waiter_task(_arg: usize) {
    let wq = unsafe { &mut *(&raw mut WQ) };
    wq.wait();
    let n = WQ_COUNTER.load(Ordering::Relaxed);
    WQ_AT_WAKE.store(n as u32, Ordering::Release);
    WQ_WAITER_DONE.store(1, Ordering::Release);
    kprintln!("[SCHEDHOOKS] waitqueue: counter at wake = {} (ceiling {})",
        n, WQ_CEILING);
}

/// For the ktest verdict ([`sched_hooks_wired`]): each scenario's reading,
/// `u32::MAX` / `usize::MAX` until it reported, and the FAIL lines printed.
static WQ_AT_WAKE: AtomicU32 = AtomicU32::new(u32::MAX);
static CAP_AFTER: AtomicUsize = AtomicUsize::new(usize::MAX);
static FAILS: AtomicU32 = AtomicU32::new(0);

// ── Capability revocation: prove exit actually revokes, not just runs
//    the hook ───────────────────────────────────────────────────────
//
// The child mints itself a typed `Cap<Socket>`, confirms it is present,
// then returns — this kernel's own exit path for a kernel task
// (`phase3_task_a`/`b` exit exactly this way).
//
// **Reads by POOL SLOT INDEX, not by TID, after exit.** The first cut
// of this marker read `cap_store::occupied(tid)` both before and
// after. Measured, not assumed: it read `before=1 after=0` whether or
// not `set_task_exit_hook` was registered — a canary that does not
// discriminate is worse than none, because it reads as coverage. Root
// cause: `scheduler::do_schedule` frees `TASK_VALID` for a Zombie's
// slot on the very same context switch that leaves its stack (K-C6),
// essentially immediately after exit — not after some later reaping
// pass — so `cap_store::occupied(tid)` (which resolves `tid` through
// `TASK_VALID` first) reads 0 within a few instructions of exit
// REGARDLESS of whether `cap_store::reset` ever ran. The exit hook
// itself DOES run synchronously and DOES call `cap_store::reset`
// before any of that (`task_exit_with_code`'s own ordering comment) —
// the bug was only in how this marker observed it.
// `cap_store::occupied_at_slot(idx)` added for exactly this: the child
// captures its own table index (`cap_store::table_slot`, while
// still alive) and the observer reads that same slot directly,
// independent of whether the TID that used to own it still resolves.
// This cluster creates no further task after the child, so nothing
// else can claim that slot before the read.
static CAP_CHILD_TID: AtomicU32 = AtomicU32::new(0);
static CAP_CHILD_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);
static CAP_BEFORE: AtomicUsize = AtomicUsize::new(usize::MAX);
const CAP_RESOURCE: u32 = 0xCA95;
const CAP_HART: i8 = 0;
/// How long the observer waits for the child to publish itself, and then
/// for it to be gone (counter time; it was an unbounded yield loop and
/// then 100,000 yields, a count).
const CAP_WAIT_MS: u64 = 5_000;

fn cap_child_task(_arg: usize) {
    let tid = azos_sched::current_task_tid();
    // The index of the table its domain owns (D2): captured while it is alive.
    let _ = azos_ipc::cap_store::grant::<azos_ipc::cap::targets::Socket>(
        tid, azos_ipc::cap::CapPerms::READ, CAP_RESOURCE);
    let idx = azos_ipc::cap_store::table_slot(tid).unwrap_or(usize::MAX);
    let before = azos_ipc::cap_store::occupied_at_slot(idx);
    CAP_BEFORE.store(before, Ordering::Release);
    CAP_CHILD_IDX.store(idx, Ordering::Release);
    // Publish the tid LAST: the observer task treats "tid published" as
    // "safe to start waiting", and the grant + idx above must already
    // be visible when it does.
    CAP_CHILD_TID.store(tid, Ordering::Release);
    // Falling off the end of this function is this task's exit.
}

fn cap_observer_task(_arg: usize) {
    use azos_syscall::sleep::wait_until_ms;
    if !wait_until_ms(CAP_WAIT_MS, 1, || CAP_CHILD_TID.load(Ordering::Acquire) != 0) {
        FAILS.fetch_add(1, Ordering::SeqCst);
        kprintln!("[SCHEDHOOKS] cap revocation FAIL: the child never published its tid \
                   in {} ms", CAP_WAIT_MS);
        return;
    }
    let tid = CAP_CHILD_TID.load(Ordering::Acquire);
    let idx = CAP_CHILD_IDX.load(Ordering::Acquire);
    // Anchored on the child's EXIT, not on the property read below: its
    // TID stops resolving when the switch away from it frees the slot,
    // and the exit hook has run before that (`task_exit_with_code`).
    if !wait_until_ms(CAP_WAIT_MS, 1, || azos_sched::idx_for_tid(tid).is_none()) {
        FAILS.fetch_add(1, Ordering::SeqCst);
        kprintln!("[SCHEDHOOKS] cap revocation FAIL: child tid={} still alive after {} ms",
            tid, CAP_WAIT_MS);
        return;
    }
    let before = CAP_BEFORE.load(Ordering::Acquire);
    let after = azos_ipc::cap_store::occupied_at_slot(idx);
    CAP_AFTER.store(after, Ordering::Release);
    kprintln!("[SCHEDHOOKS] cap revocation: before={} after={} (tid={} slot={})",
        before, after, tid, idx);
}

/// Spawn every task in this cluster. Called once from both
/// `kernel_main`s, unconditionally (this module compiles to nothing
/// without the feature) — see this module's own doc for the placement
/// reasoning.
pub fn spawn() {
    azos_sched::task_create_affinity(
        "schedhooks-wq-waiter", wq_waiter_task, 0,
        azos_sched::DEFAULT_PRIORITY, WQ_HART);
    azos_sched::task_create_affinity(
        "schedhooks-wq-producer", wq_producer_task, 0,
        azos_sched::DEFAULT_PRIORITY, WQ_HART);
    azos_sched::task_create_affinity(
        "schedhooks-cap-observer", cap_observer_task, 0,
        azos_sched::DEFAULT_PRIORITY, CAP_HART);
    azos_sched::task_create_affinity(
        "schedhooks-cap-child", cap_child_task, 0,
        azos_sched::DEFAULT_PRIORITY, CAP_HART);
}

// The scheduler hooks the sync and IPC crates install, exercised from tasks:
// a WaitQueue waiter sleeps until a producer has made real progress (counter
// at wake >= half its ceiling); a task's capability slot is cleared when
// the task exits (before=1 after=0). The row `aarch64: sched hooks` judged
// the lines on aarch64; the test runs on both ISAs.
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    fn sched_hooks_wired() {
        spawn();
        crate::ktest::wait("a scenario did not report", || {
            FAILS.load(Ordering::SeqCst) != 0
                || (WQ_AT_WAKE.load(Ordering::Acquire) != u32::MAX
                    && CAP_AFTER.load(Ordering::Acquire) != usize::MAX)
        })?;
        if FAILS.load(Ordering::SeqCst) != 0 {
            return Err("a scenario printed [SCHEDHOOKS] ... FAIL");
        }
        if WQ_AT_WAKE.load(Ordering::Acquire) < WQ_CEILING as u32 / 2 {
            return Err("waitqueue: wait() returned before the producer made real progress");
        }
        if CAP_BEFORE.load(Ordering::Acquire) != 1 || CAP_AFTER.load(Ordering::Acquire) != 0 {
            return Err("cap revocation: the exited task's capability slot was not cleared");
        }
        Ok(())
    }
}
