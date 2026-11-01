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
//! * `futex_look_under_the_table_faults_nothing`: a `CMP_REQUEUE` and a
//!   `CMP_REQUEUE_PI` of a task with a user address space, on a word nothing
//!   maps and on a resident one: the calls answer as they must and lockdep,
//!   whose check is on every user access that may fault, stays silent. Canary
//!   `canary=futex-look-faults`: the look reads the word as a syscall's copy
//!   does, under the table, and lockdep reports it.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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
    let deadline = azos_drv_sys::timebase::now() + azos_limits::KTEST_LATE_TIMEOUT_MS as u64 * per_ms;
    let rc = azos_sched::futex::wait(&|| Some((COND, WORD.load(Ordering::Acquire))), &|| false, 0, Some(deadline));
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
        let look = || Some((COND, WORD.load(Ordering::Acquire)));
        let (woken, moved) = azos_sched::futex::requeue(&look, &|| false, MUTEX, 1, u32::MAX, Some(0))
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

// ── What a look does under the table ────────────────────────────────────────

/// Mapped nowhere in the task's table.
const NOWHERE: u64 = 0x4100_0000;
/// The resident word, holding 0.
const RESIDENT: u64 = 0x4200_0000;
static LOOK_DONE: AtomicBool = AtomicBool::new(false);
static LOOK_VERDICT: AtomicU32 = AtomicU32::new(0);

struct NoPiWord;

impl azos_sched::futex::PiWord for NoPiWord {
    fn read(&self) -> Result<u32, azos_sync::pi_futex::UserFault> {
        Err(azos_sync::pi_futex::UserFault)
    }
    fn cmpxchg(&self, _expected: u32, _new: u32) -> Result<u32, azos_sync::pi_futex::UserFault> {
        Err(azos_sync::pi_futex::UserFault)
    }
}

fn look_at(addr: u64) -> Option<(Key, u32)> {
    if canary!("futex-look-faults") {
        let key = azos_sched::futex::private_key(addr)?;
        return azos_sched::UserPtr::<u32>::new(addr).read().ok().map(|v| (key, v));
    }
    azos_syscall::vdso_notify::futex_look(addr, false)
}

fn look_task(_: usize) {
    let verdict = (|| {
        let pt = azos_mm::vmm::create_pagetable().map_err(|_| 1u32)?;
        let frame = azos_mm::pmm::alloc_page().map_err(|_| 2u32)?;
        azos_mm::vmm::map(pt, RESIDENT as usize, frame.as_usize(), azos_arch_api::PagePerms::USER_RW).map_err(|_| 3u32)?;
        // The table is this task's for `current_user_pt` only: it keeps
        // running in the kernel's.
        let satp = azos_sched::kernel_task_satp();
        azos_sched::scheduler::set_current_user_info(satp, pt as u64, 0);
        let r = (|| {
            let settle = |a: u64| azos_syscall::vdso_notify::futex_settle(a);
            let Some(to) = azos_sched::futex::private_key(RESIDENT + 8) else { return 1u32 };
            if azos_sched::futex::requeue(&|| look_at(NOWHERE), &|| settle(NOWHERE), to, 0, 0, Some(0)) != Err(-azos_sched::futex::EFAULT) {
                return 4;
            }
            if azos_sched::futex::requeue(&|| look_at(RESIDENT), &|| settle(RESIDENT), to, 0, 0, Some(1)) != Err(-azos_sched::futex::EAGAIN) {
                return 5;
            }
            if azos_sync::pi_futex::ENABLED {
                let rc = azos_sched::futex::cmp_requeue_pi(&|| look_at(NOWHERE), &|| settle(NOWHERE), MUTEX, 0, 0, &NoPiWord);
                if rc != -azos_sched::futex::EFAULT {
                    return 6;
                }
            }
            0
        })();
        azos_sched::scheduler::set_current_user_info(satp, 0, 0);
        azos_sched::process::destroy_user_address_space(pt as u64);
        Ok::<u32, u32>(r)
    })();
    LOOK_VERDICT.store(verdict.unwrap_or_else(|e| e), Ordering::Release);
    LOOK_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn futex_look_under_the_table_faults_nothing() {
        if !azos_sched::futex_table::REQUEUE {
            return Ok(());
        }
        azos_sched::task_create_affinity("futex-look", look_task, 0, PRIO, -1);
        crate::ktest::wait("the task never finished", || LOOK_DONE.load(Ordering::Acquire))?;
        match LOOK_VERDICT.load(Ordering::Acquire) {
            0 => Ok(()),
            1..=3 => Err("no user address space to run in"),
            4 => Err("CMP_REQUEUE on an unmapped word did not answer EFAULT"),
            5 => Err("CMP_REQUEUE on a resident word that differs did not answer EAGAIN"),
            _ => Err("CMP_REQUEUE_PI on an unmapped word did not answer EFAULT"),
        }
    }
}
