// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CPUs that differ (Kconfig `SCHED_ASYM_CPUS`): the first half of the CPUs are
//! the small ones. The gate rows `asym ...` boot this on such a machine (an
//! asymmetric DTB, or `canary=x86-hybrid-synth`); anywhere else these skip.
//! Logic only: QEMU's CPUs do not differ in speed.

use azos_decision::{Filter, Rule, Verdict};
use azos_drv_sys::kprintln;
use azos_ktest::skip;
use azos_sched::rt::{self, Reservation};
use azos_sched::rt_core::Refusal;
use azos_sched::topo;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const FAIR_PRIO: u32 = 18;
const RT_PRIO: u32 = 8;
const NO_CPU: usize = usize::MAX;

fn differing() -> Result<(), &'static str> {
    if topo::ASYM && topo::differs() {
        Ok(())
    } else {
        skip!("needs SCHED_ASYM_CPUS and CPUs that differ")
    }
}

/// The last CPU of the smallest class: placement fills the first ones first,
/// and the boot CPU has the daemons.
fn small_cpu() -> Option<usize> {
    let n = azos_percpu::nr_cpu_ids();
    let k = (0..n).map(topo::class).max()?;
    (1..n).rfind(|&c| topo::class(c) == k)
}

static RUN_STOP: AtomicBool = AtomicBool::new(false);
static RUN_DONE: AtomicBool = AtomicBool::new(false);
static RUN_UNPIN: AtomicBool = AtomicBool::new(false);
static RUN_TID: AtomicU32 = AtomicU32::new(0);
static RUN_CPU: AtomicUsize = AtomicUsize::new(NO_CPU);

/// Computes without a pause, publishing where it runs, until told to stop.
fn spinner(_: usize) {
    RUN_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    if RUN_UNPIN.load(Ordering::Acquire) {
        azos_sched::scheduler::ktest_set_pin(azos_sched::current_task_tid(), -1);
    }
    while !RUN_STOP.load(Ordering::Acquire) {
        RUN_CPU.store(azos_sched::smp::current_cpu_id(), Ordering::Release);
        core::hint::spin_loop();
    }
    RUN_DONE.store(true, Ordering::Release);
    azos_sched::task_exit();
}

/// A spinner started on `cpu`; `unpin`: free to leave it as soon as it runs.
fn spin_on(name: &'static str, cpu: usize, prio: u32, unpin: bool) -> Result<(), &'static str> {
    RUN_STOP.store(false, Ordering::Release);
    RUN_DONE.store(false, Ordering::Release);
    RUN_UNPIN.store(unpin, Ordering::Release);
    RUN_CPU.store(NO_CPU, Ordering::Release);
    azos_sched::task_create_affinity(name, spinner, 0, prio, cpu as i8);
    crate::ktest::wait("the spinner never ran", || RUN_CPU.load(Ordering::Acquire) != NO_CPU)
}

fn stop_spinner() -> Result<(), &'static str> {
    RUN_STOP.store(true, Ordering::Release);
    crate::ktest::wait("the spinner never stopped", || RUN_DONE.load(Ordering::Acquire))
}

azos_ktest::ktest_late! {
    fn asym_classes_installed() {
        differing()?;
        let n = azos_percpu::nr_cpu_ids();
        let big = (0..n).filter(|&c| topo::class(c) == 0).count();
        let small = small_cpu().ok_or("no small CPU")?;
        if big == n || big == 0 {
            return Err("the machine is not split in classes");
        }
        if topo::capacity(small) >= topo::CAPACITY_SCALE {
            return Err("a CPU of the small class has the full capacity");
        }
        if topo::class_mask(0) & 1 << small != 0 {
            return Err("the biggest class's mask names a small CPU");
        }
        Ok(())
    }
}

fn budget(cpu_mask: u32) -> Reservation {
    Reservation { runtime_us: 100, period_us: 10_000, deadline_us: 0, hard: true, cpu_mask, band: false, level: FAIR_PRIO }
}

static SELF_HART: AtomicUsize = AtomicUsize::new(NO_CPU);
static SELF_RECORDED: AtomicBool = AtomicBool::new(false);

/// What `SYS_SCHEDCTL` asks of the caller's own task: no CPU named.
fn reserves_itself(_: usize) {
    let idx = azos_sched::idx_for_tid(azos_sched::current_task_tid()).expect("the running task has a slot");
    let me = azos_sched::smp::current_cpu_id();
    let tid = azos_sched::current_task_tid();
    let before = azos_decision::total();
    let got = rt::reserve(idx, budget(0));
    if got.is_ok() {
        rt::ktest_release(idx);
    }
    let f = Filter { rule: Some(Rule::RtCoreClass as u8), verdict: Some(Verdict::Place as u8), subject: Some(tid), after: before };
    let recorded = azos_decision::query(&f, &mut [0u64; 1]) != 0;
    SELF_RECORDED.store(recorded, Ordering::Release);
    SELF_HART.store(if got == Ok(me) { me } else { NO_CPU - 1 }, Ordering::Release);
    azos_sched::task_exit();
}

static PARKED_TID: AtomicU32 = AtomicU32::new(0);
static PARKED_GO: AtomicBool = AtomicBool::new(false);

fn parked(_: usize) {
    PARKED_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    while !PARKED_GO.load(Ordering::Acquire) {
        azos_syscall::sleep::sleep_ms(5);
    }
    PARKED_TID.store(0, Ordering::Release);
    azos_sched::task_exit();
}

fn refused_on_record(tid: u32, from: u64) -> bool {
    let f = Filter {
        rule: Some(Rule::DeadlineAdmission as u8),
        verdict: Some(Verdict::Refuse as u8),
        subject: Some(tid),
        after: from,
    };
    azos_decision::query(&f, &mut [0u64; 1]) != 0
}

azos_ktest::ktest_late! {
    // A task that is not running and names no CPU, and a request that names CPUs
    // of two classes, are refused; a pin, a mask of one class and a running
    // task's own request (`SYS_SCHEDCTL`'s) are admitted.
    fn asym_admission_within_one_class() {
        differing()?;
        let small = small_cpu().ok_or("no small CPU")?;
        let big = (0..azos_percpu::nr_cpu_ids()).find(|&c| topo::class(c) == 0).ok_or("no big CPU")?;
        PARKED_GO.store(false, Ordering::Release);
        let idx = azos_sched::task_create("asym-parked", parked, 0, FAIR_PRIO);
        crate::ktest::wait("the parked task never ran", || PARKED_TID.load(Ordering::Acquire) != 0)?;
        let tid = PARKED_TID.load(Ordering::Acquire);
        let before = azos_decision::total();
        let verdicts = (rt::reserve(idx, budget(0)), rt::reserve(idx, budget(1 << small | 1 << big)));
        let on_record = azos_decision::DURABLE && refused_on_record(tid, before);
        azos_sched::scheduler::ktest_set_pin(tid, small as i8);
        let pinned = rt::reserve(idx, budget(0));
        let pinned_ok = pinned == Ok(small);
        rt::ktest_release(idx);
        azos_sched::scheduler::ktest_set_pin(tid, -1);
        let within = rt::reserve(idx, budget(1 << small));
        let within_ok = within == Ok(small);
        rt::ktest_release(idx);
        PARKED_GO.store(true, Ordering::Release);
        crate::ktest::wait("the parked task never left", || PARKED_TID.load(Ordering::Acquire) == 0)?;
        SELF_HART.store(NO_CPU, Ordering::Release);
        azos_sched::task_create("asym-self", reserves_itself, 0, FAIR_PRIO);
        crate::ktest::wait("the task never asked", || SELF_HART.load(Ordering::Acquire) != NO_CPU)?;
        if SELF_HART.load(Ordering::Acquire) == NO_CPU - 1 {
            return Err("a running task's own request, naming no CPU, was not admitted where it runs");
        }
        if !SELF_RECORDED.load(Ordering::Acquire) {
            return Err("the admission did not record its core class");
        }
        if verdicts != (Err(Refusal::CoreClass), Err(Refusal::CoreClass)) {
            return Err("an unpinned task, or a mask over two classes, was not refused core-class");
        }
        if azos_decision::DURABLE && !on_record {
            return Err("the core-class refusal left no decision record");
        }
        if !pinned_ok {
            return Err("a task pinned to one CPU was not admitted there");
        }
        if !within_ok {
            return Err("a mask within one class was not admitted");
        }
        Ok(())
    }
}

static PLACED_CPU: AtomicUsize = AtomicUsize::new(NO_CPU);

fn records_its_cpu(_: usize) {
    PLACED_CPU.store(azos_sched::smp::current_cpu_id(), Ordering::Release);
    azos_sched::task_exit();
}

azos_ktest::ktest_late! {
    fn asym_rt_task_placed_on_a_big_cpu() {
        differing()?;
        // Logical CPU 0 is whichever CPU booted: the small one is taken first, so
        // that a placement blind to capacity picks it.
        let n = azos_percpu::nr_cpu_ids();
        let small = (0..n).find(|&c| topo::class(c) != 0).ok_or("no small CPU")?;
        let big = (small..n).find(|&c| topo::class(c) == 0).ok_or("no big CPU after the first small one")?;
        if azos_sched::scheduler::ktest_rt_pick_between(small, big) != big {
            return Err("placement sends a task to a small CPU with a big one as free");
        }
        // A real task runs where placement says, loads moving between the two.
        for _ in 0..8 {
            PLACED_CPU.store(NO_CPU, Ordering::Release);
            let said = azos_sched::scheduler::ktest_place_now(RT_PRIO);
            azos_sched::task_create("asym-rt", records_its_cpu, 0, RT_PRIO);
            crate::ktest::wait("the task never ran", || PLACED_CPU.load(Ordering::Acquire) != NO_CPU)?;
            if PLACED_CPU.load(Ordering::Acquire) == said {
                return Ok(());
            }
        }
        Err("a real-time task never ran where placement said")
    }
}

// A task that computes for longer than the misfit window and sleeps: placement and
// the misfit move must agree, or it pays a move every period.
const PERIODS: u32 = 12;
static HOG_PERIOD: AtomicU32 = AtomicU32::new(0);
static HOG_TID: AtomicU32 = AtomicU32::new(0);

fn periodic_hog(ms: usize) {
    let tid = azos_sched::current_task_tid();
    azos_sched::scheduler::fairq::misfit_watch(tid);
    azos_sched::scheduler::ktest_set_pin(tid, -1);
    HOG_TID.store(tid, Ordering::Release);
    let hz = azos_drv_sys::timebase::TIMER_FREQ;
    for period in 1..=PERIODS {
        let until = azos_drv_sys::timebase::now() + hz * ms as u64 / 1000;
        while azos_drv_sys::timebase::now() < until {
            core::hint::spin_loop();
        }
        HOG_PERIOD.store(period, Ordering::Release);
        // Woken by the test, through wake placement; the timer is only its bound.
        azos_sched::task_block(azos_sched::WaitReason::Timer(azos_drv_sys::timebase::now() + hz));
    }
    azos_sched::task_exit();
}

azos_ktest::ktest_late! {
    fn asym_periodic_hog_does_not_bounce() {
        differing()?;
        let small = small_cpu().ok_or("no small CPU")?;
        HOG_PERIOD.store(0, Ordering::Release);
        HOG_TID.store(0, Ordering::Release);
        let ms = 40 * azos_limits::SCHED_MISFIT_TICKS as usize;
        azos_sched::task_create_affinity("asym-hog", periodic_hog, ms, FAIR_PRIO, small as i8);
        for period in 1..=PERIODS {
            crate::ktest::wait("the hog never ended its period", || HOG_PERIOD.load(Ordering::Acquire) >= period)?;
            azos_syscall::sleep::sleep_ms(5);
            azos_sched::scheduler::wake_task_by_tid(HOG_TID.load(Ordering::Acquire), &|_| true);
        }
        let moved = azos_sched::scheduler::fairq::misfit_watched_moves();
        kprintln!("# asym_periodic_hog: {} misfit moves over {} periods", moved, PERIODS);
        // Load-based placement may still pick a small CPU now and then.
        if moved >= PERIODS / 2 {
            return Err("the hog was moved as a misfit about every period");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn asym_builtin_rows_on_the_biggest_class() {
        differing()?;
        let topo_now = azos_topology::get().ok_or("no topology")?;
        let mut rows = 0;
        for t in topo_now.tasks() {
            if let Some(r) = azos_syscall::topo_sched::row_reservation(t.name.as_bytes()) {
                rows += 1;
                if r.cpu_mask & !topo::class_mask(0) != 0 {
                    return Err("a row with a budget may run on a small CPU");
                }
            }
        }
        if rows == 0 {
            return skip!("no row with a budget");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn asym_misfit_leaves_the_small_cpu() {
        differing()?;
        let small = small_cpu().ok_or("no small CPU")?;
        // The balancer may take the spinner too, while something else on the CPU
        // holds it in the queue: that run says nothing, the next one does.
        for _ in 0..8 {
            spin_on("asym-misfit", small, FAIR_PRIO, true)?;
            let tid = RUN_TID.load(Ordering::Acquire);
            let moved = crate::ktest::wait("the lone task stayed on the small CPU", || {
                let c = RUN_CPU.load(Ordering::Acquire);
                c != NO_CPU && topo::class(c) == 0
            });
            let as_misfit = azos_sched::scheduler::fairq::misfit_last_tid() == tid;
            stop_spinner()?;
            moved?;
            if as_misfit {
                return Ok(());
            }
        }
        Err("every move of the lone task was the balancer's")
    }
}

azos_ktest::ktest_late! {
    fn asym_misfit_leaves_real_time_and_pinned_alone() {
        differing()?;
        let small = small_cpu().ok_or("no small CPU")?;
        // Many times the misfit window at any tick rate the gate builds.
        let window = 100 * azos_limits::SCHED_MISFIT_TICKS as u64;
        spin_on("asym-rt-spin", small, RT_PRIO, true)?;
        azos_syscall::sleep::sleep_ms(window);
        let idx = azos_sched::idx_for_tid(RUN_TID.load(Ordering::Acquire)).ok_or("the spinner has no slot")?;
        let rt_stayed = RUN_CPU.load(Ordering::Acquire) == small
            && !azos_sched::scheduler::fairq::ktest_misfit_may_move(idx);
        stop_spinner()?;
        if !rt_stayed {
            return Err("a real-time task was moved");
        }
        spin_on("asym-pin-spin", small, FAIR_PRIO, false)?;
        azos_syscall::sleep::sleep_ms(window);
        let pinned_stayed = RUN_CPU.load(Ordering::Acquire) == small;
        stop_spinner()?;
        if !pinned_stayed {
            return Err("a pinned task was moved");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    // The bit the row made one CPU lack: rv its DTB's Zbb on the last CPU, else
    // `canary=asym-weak-last-cpu`.
    fn asym_hwcap_is_the_weakest_cpus() {
        let (bit, armed) = super::seams::weak_cpu_hwcap(topo::differs());
        if !armed {
            return skip!("needs CPUs that differ in hwcap");
        }
        if azos_mm::vdso::vdso_hwcap() & bit != 0 {
            return Err("the shared hwcap word advertises what one CPU lacks");
        }
        if !super::seams::sha256_follows(bit) {
            return Err("the kernel's SHA-256 does not follow the shared word");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn asym_off_warns_records_and_counts_cpus_equal() {
        if topo::ASYM || !topo::differs() {
            return skip!("needs SCHED_ASYM_CPUS off and CPUs that differ");
        }
        if super::smp::ASYM_OFF_RECEIPT.load(Ordering::Relaxed) == 0 {
            return Err("no asym-cpus decision record");
        }
        if (0..azos_percpu::nr_cpu_ids()).any(|c| topo::capacity(c) != topo::CAPACITY_SCALE || topo::class(c) != 0) {
            return Err("a CPU counts as different with SCHED_ASYM_CPUS off");
        }
        Ok(())
    }
}
