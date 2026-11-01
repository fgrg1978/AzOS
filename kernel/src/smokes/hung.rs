// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hung-task and stuck-CPU detectors (Kconfig HUNG_DETECT) in the running
//! kernel, every ISA. Each test drives the watchdog pass's own step
//! (`azos_actuation::sys_wdt::hung_pass`) on a state of its own with a short
//! timeout, and reads what it left in the decision journal.
//!
//! * `hung_task_detector_reports_a_blocked_owner_wait`: a task parked on a
//!   mutex whose owner sleeps is reported once, naming the owner; the owner,
//!   asleep longer on a wait queue that names no owner, is not. Canary
//!   feature `hung-task-canary`: the scan reads no task, `not ok`.
//! * `stuck_cpu_detector_names_the_cpu`: a CPU held in a critical section is
//!   reported once, by its id, and no other CPU is. Needs a second CPU
//!   (`not ok` at one). Canary `canary=hung-cpu-blind`: the scan reads no
//!   CPU, `not ok`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_actuation::sys_wdt::{hung_pass, HungAction};
use azos_arch::Cpu as _;
use azos_decision::{Rule, Verdict};
use azos_sched::hung::{Hung, Kind};
use azos_sync::kmutex::Mutex;

/// The test's timeout (ms): short, with the pass driven by hand.
const TIMEOUT_MS: u64 = 60;
/// How long a test waits for its report.
const REPORT_WAIT_MS: u64 = 4000;

static OWNED: Mutex<u32> = Mutex::new(0);
static OWNER_HOLDS: AtomicBool = AtomicBool::new(false);
static OWNER_RELEASE: AtomicBool = AtomicBool::new(false);
static OWNER_DONE: AtomicBool = AtomicBool::new(false);
static WAITER_TID: AtomicU32 = AtomicU32::new(0);
static WAITER_DONE: AtomicBool = AtomicBool::new(false);
static OWNER_TID: AtomicU32 = AtomicU32::new(0);
static OWNER_Q: azos_sync::WaitQueue = azos_sync::WaitQueue::new();
static MUTEX_HUNG: Hung = Hung::new();

fn owner(_: usize) {
    OWNER_TID.store(azos_sched::current_task_tid(), Ordering::SeqCst);
    let g = OWNED.lock();
    OWNER_HOLDS.store(true, Ordering::SeqCst);
    // Asleep on a wait queue: no owner to name, however long it lasts.
    OWNER_Q.wait_if(|| !OWNER_RELEASE.load(Ordering::SeqCst));
    drop(g);
    OWNER_DONE.store(true, Ordering::SeqCst);
}

fn waiter(_: usize) {
    WAITER_TID.store(azos_sched::current_task_tid(), Ordering::SeqCst);
    drop(OWNED.lock());
    WAITER_DONE.store(true, Ordering::SeqCst);
}

/// The `Rule::Hang` records written since journal position `from`, as
/// `(subject, verdict, n)`.
fn hang_records(from: u64, mut each: impl FnMut(u32, u8, [u64; 3])) {
    for seq in from + 1..=azos_decision::total() {
        if let Some(r) = azos_decision::get(seq).filter(|r| r.rule == Rule::Hang as u8) {
            each(r.subject, r.verdict, r.n);
        }
    }
}

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

azos_ktest::ktest_late! {
    fn hung_task_detector_reports_a_blocked_owner_wait() {
        if !azos_sched::hung::ON {
            return Err("HUNG_DETECT is off in this ktest kernel");
        }
        if !azos_sync::waitgraph::ENABLED {
            return Err("WAIT_GRAPH is off in this ktest kernel");
        }
        if canary!("hung-task-blind") {
            azos_sched::hung::canary_blind_tasks();
        }
        for s in [&OWNER_HOLDS, &OWNER_RELEASE, &OWNER_DONE, &WAITER_DONE] {
            s.store(false, Ordering::SeqCst);
        }
        azos_sched::task_create_affinity("hung-owner", owner, 0, 2, -1);
        crate::ktest::wait("the owner never took the mutex", || OWNER_HOLDS.load(Ordering::SeqCst))?;
        azos_sched::task_create_affinity("hung-waiter", waiter, 0, 2, -1);
        let from = azos_decision::total();
        let mut reports = 0;
        let seen = crate::ktest::until_for(REPORT_WAIT_MS, || {
            reports += hung_pass(&MUTEX_HUNG, now(), TIMEOUT_MS, TIMEOUT_MS, HungAction::None);
            reports > 0
        });
        // Past a second timeout the same hang is not reported again.
        crate::ktest::until_for(3 * TIMEOUT_MS, || false);
        let again = hung_pass(&MUTEX_HUNG, now(), TIMEOUT_MS, TIMEOUT_MS, HungAction::None);
        let (waiter_tid, owner_tid) = (WAITER_TID.load(Ordering::SeqCst), OWNER_TID.load(Ordering::SeqCst));
        let mut records = 0;
        let mut ok = true;
        hang_records(from, |subject, verdict, n| {
            records += 1;
            ok &= subject == waiter_tid
                && verdict == Verdict::Admit as u8
                && n[1] >> 32 == Kind::Owner as u64
                && n[1] as u32 == owner_tid
                && n[2] >> 32 == HungAction::None as u64;
        });
        OWNER_RELEASE.store(true, Ordering::SeqCst);
        OWNER_Q.wake_all();
        crate::ktest::wait("the owner never finished", || OWNER_DONE.load(Ordering::SeqCst))?;
        crate::ktest::wait("the waiter never finished", || WAITER_DONE.load(Ordering::SeqCst))?;
        if !seen {
            return Err("a task blocked on a mutex past the timeout was not reported");
        }
        if again != 0 || records != 1 {
            return Err("one hang was reported more than once, or something else was reported");
        }
        if !ok {
            return Err("the record does not name the waiter, its owner and the kind");
        }
        let after = hung_pass(&MUTEX_HUNG, now(), TIMEOUT_MS, TIMEOUT_MS, HungAction::None);
        if after != 0 {
            return Err("a task that ran again was reported");
        }
        Ok(())
    }
}

static HOLD_CPU: AtomicU32 = AtomicU32::new(0);
static HOLD_STARTED: AtomicBool = AtomicBool::new(false);
static HOLD_RELEASE: AtomicBool = AtomicBool::new(false);
static HOLD_DONE: AtomicBool = AtomicBool::new(false);
static CPU_HUNG: Hung = Hung::new();

/// A CPU that cannot schedule: preemption off, in the kernel, until released.
fn holder(_: usize) {
    HOLD_CPU.store(azos_arch::ARCH.hart_id() as u32, Ordering::SeqCst);
    {
        let _p = azos_sync::critical_section();
        HOLD_STARTED.store(true, Ordering::SeqCst);
        while !HOLD_RELEASE.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
    }
    HOLD_DONE.store(true, Ordering::SeqCst);
}

azos_ktest::ktest_late! {
    fn stuck_cpu_detector_names_the_cpu() {
        if !azos_sched::hung::ON || !azos_sync::qsbr::ON {
            return Err("HUNG_DETECT or RCU_QSBR is off in this ktest kernel");
        }
        let me = azos_arch::ARCH.hart_id();
        let n = azos_percpu::nr_cpu_ids();
        let Some(cpu) = (1..n).map(|d| (me + d) % n).find(|&c| azos_percpu::cpu_online(c)) else {
            return Err("needs a second CPU");
        };
        if canary!("hung-cpu-blind") {
            azos_sched::hung::canary_blind_cpus();
        }
        for s in [&HOLD_STARTED, &HOLD_RELEASE, &HOLD_DONE] {
            s.store(false, Ordering::SeqCst);
        }
        azos_sched::task_create_affinity("hung-hold", holder, 0, 2, cpu as i8);
        crate::ktest::wait("the holder task never ran", || HOLD_STARTED.load(Ordering::SeqCst))?;
        let from = azos_decision::total();
        let mut reports = 0;
        let seen = crate::ktest::until_for(REPORT_WAIT_MS, || {
            reports += hung_pass(&CPU_HUNG, now(), TIMEOUT_MS, TIMEOUT_MS, HungAction::None);
            reports > 0
        });
        crate::ktest::until_for(3 * TIMEOUT_MS, || false);
        let again = hung_pass(&CPU_HUNG, now(), TIMEOUT_MS, TIMEOUT_MS, HungAction::None);
        let held_on = HOLD_CPU.load(Ordering::SeqCst);
        let mut records = 0;
        let mut ok = true;
        hang_records(from, |subject, verdict, n| {
            records += 1;
            ok &= subject == held_on && verdict == Verdict::Admit as u8 && n[1] >> 32 == Kind::Cpu as u64;
        });
        HOLD_RELEASE.store(true, Ordering::SeqCst);
        crate::ktest::wait("the holder task never finished", || HOLD_DONE.load(Ordering::SeqCst))?;
        if !seen {
            return Err("a CPU held in the kernel past the timeout was not reported");
        }
        if again != 0 || records != 1 {
            return Err("one stuck CPU was reported more than once, or another CPU was reported");
        }
        if !ok {
            return Err("the record does not name the held CPU and the kind");
        }
        Ok(())
    }
}
