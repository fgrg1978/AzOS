// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The futex table's requeue (wave 15 N9, Kconfig FUTEX_REQUEUE), every ISA.
//!
//! * `futex_requeue_wakes_one_not_the_herd`: kernel tasks wait on a
//!   condition word (a shared key); a `CMP_REQUEUE` wakes one and moves the
//!   rest onto the mutex word. The herd counter (tasks that ran) is exactly
//!   1 until the mutex word is woken, then all of them.
//!   Canary `canary=futex-requeue-wake-all`: the requeue wakes every waiter
//!   and moves none, the counter reads the whole herd: `not ok`.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_sched::futex::Key;

const PRIO: u32 = 12;
const HERD: u32 = 6;
/// Any object id no shm region uses: the ktest's own key space.
const OBJ: u32 = 0xF17E_0009;
const COND: Key = Key::Shared { obj: OBJ, offset: 0 };
const MUTEX: Key = Key::Shared { obj: OBJ, offset: 4 };

static WORD: AtomicU32 = AtomicU32::new(0);
static RAN: AtomicU32 = AtomicU32::new(0);

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

fn waiter(_: usize) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let deadline = azos_drv_sys::timebase::now() + 10_000 * per_ms;
    let rc = azos_sched::futex::wait_key(COND, 0, Some(deadline), &|| Some(WORD.load(Ordering::Acquire)));
    if rc == 0 {
        RAN.fetch_add(1, Ordering::AcqRel);
    }
}

fn waiting(k: Key) -> usize {
    azos_sched::futex_table::TABLE.lock_irqsave().waiters_on(k)
}

azos_ktest::ktest_late! {
    fn futex_requeue_wakes_one_not_the_herd() {
        if !azos_sched::futex_table::REQUEUE {
            return Err("Kconfig FUTEX_REQUEUE is off in this ktest kernel");
        }
        for k in 0..HERD as usize {
            azos_sched::task_create_affinity("n9-herd", waiter, k, PRIO, -1);
        }
        crate::ktest::wait("the herd never filed on the condition word",
            || waiting(COND) == HERD as usize)?;
        // The broadcast: wake one, move the rest to the mutex word.
        let read = || Some(WORD.load(Ordering::Acquire));
        let (woken, moved) = azos_sched::futex::requeue(COND, MUTEX, 1, u32::MAX, Some(0), &read)
            .map_err(|_| "CMP_REQUEUE refused an unchanged word")?;
        crate::ktest::wait("the woken waiter never ran", || RAN.load(Ordering::Acquire) >= 1)?;
        sleep_ms(20);
        let ran = RAN.load(Ordering::Acquire);
        if woken != 1 || moved != HERD - 1 || ran != 1 {
            azos_drv_sys::kprintln!("[futex] herd: woken={} moved={} ran={}", woken, moved, ran);
            // Release whoever is still filed before failing.
            azos_sched::futex::wake_key(MUTEX, u32::MAX);
            return Err("the requeue woke the herd (herd counter != 1)");
        }
        if waiting(MUTEX) != (HERD - 1) as usize {
            return Err("the moved waiters are not filed on the mutex word");
        }
        azos_sched::futex::wake_key(MUTEX, u32::MAX);
        crate::ktest::wait("a requeued waiter never ran after the mutex wake",
            || RAN.load(Ordering::Acquire) == HERD)?;
        Ok(())
    }
}
