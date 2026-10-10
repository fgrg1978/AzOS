// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! QSBR (Kconfig RCU_QSBR, wave 15 N4) in the running kernel, every ISA.
//!
//! * `rcu_free_waits_for_the_reader`: an object retired with `call_rcu`
//!   while a read section holds it stays whole (its free poisons it) until
//!   the section ends, then is freed by the callback task on the callback
//!   CPU. Canary `canary=rcu-free-no-grace`: `call_rcu` frees at once, the
//!   reader sees the poison, `not ok`.
//! * `rcu_idle_cpu_is_quiescent`: grace periods end while the other CPUs
//!   idle tickless, with no stall. Canary `canary=rcu-idle-qs-skip`: the
//!   idle task never enters its extended quiescent state, an idle CPU holds
//!   the grace period, the stall detector counts it, `not ok`.
//! * `lockdep_no_sleep_in_rcu_read`: canary `canary=lockdep-rcu-sleep`
//!   sleeps (a wait's entry) inside a read section; lockdep reports it.
//! * `cap_lookup_lock_free_never_stale`: the lock-free capability reads and
//!   the lookup cache (Kconfig CAP_LOOKUP_CACHE) answer what the table holds,
//!   before and after a revoke.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use azos_arch::Cpu as _;
use azos_sync::qsbr::{self, RcuHead};

const MAGIC: u64 = 0x5243_555f_4f42_4a31; // "RCU_OBJ1"
const POISON: u64 = 0x6b6b_6b6b_6b6b_6b6b;

#[repr(C)]
struct Obj {
    head: UnsafeCell<RcuHead>,
    magic: AtomicU64,
    freed: AtomicBool,
}

// SAFETY: `head` is touched only by `call_rcu` and the callback, one at a time.
unsafe impl Sync for Obj {}

static OBJS: [Obj; 2] = [const {
    Obj { head: UnsafeCell::new(RcuHead::new()), magic: AtomicU64::new(0), freed: AtomicBool::new(false) }
}; 2];
static CUR: AtomicPtr<Obj> = AtomicPtr::new(core::ptr::null_mut());
static RAN_ON: AtomicUsize = AtomicUsize::new(usize::MAX);

/// The "free": poison the object (as a slab free poisons), and say where it
/// ran. `head` is the first field of a `#[repr(C)]` `Obj`.
unsafe fn retire(head: *mut RcuHead) {
    let o = &*(head as *const Obj);
    o.magic.store(POISON, Ordering::SeqCst);
    o.freed.store(true, Ordering::SeqCst);
    RAN_ON.store(azos_arch::ARCH.hart_id(), Ordering::SeqCst);
}

fn now_ms() -> u64 {
    azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1)
}

fn spin_us(us: u64) {
    let per_us = (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1);
    let end = azos_drv_sys::timebase::now() + us * per_us;
    while azos_drv_sys::timebase::now() < end {
        core::hint::spin_loop();
    }
}

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

azos_ktest::ktest_late! {
    fn rcu_free_waits_for_the_reader() {
        if !qsbr::ON {
            return Err("RCU_QSBR is off in this ktest kernel");
        }
        let (a, b) = (&OBJS[0], &OBJS[1]);
        for o in [a, b] {
            o.magic.store(MAGIC, Ordering::SeqCst);
            o.freed.store(false, Ordering::SeqCst);
        }
        CUR.store(a as *const Obj as *mut Obj, Ordering::Release);
        {
            let _r = qsbr::read();
            let p = CUR.load(Ordering::Acquire);
            // The writer's half, on this CPU inside the section: publish the
            // replacement, retire the old one.
            CUR.store(b as *const Obj as *mut Obj, Ordering::Release);
            // SAFETY: `a` is static and retired once per run.
            unsafe { qsbr::call_rcu(a.head.get(), retire) };
            // Hold the section a while (under LOCK_MAX_HOLD_US, the read
            // section's hold bound): the callback task's polls run meanwhile.
            spin_us(azos_sync::lockdep::MAX_HOLD_US / 2);
            // SAFETY: `p` is one of the static objects.
            if unsafe { (*p).magic.load(Ordering::SeqCst) } != MAGIC {
                return Err("the object was freed inside a read section that held it (no grace period)");
            }
        }
        let t0 = now_ms();
        while !a.freed.load(Ordering::SeqCst) {
            if now_ms().wrapping_sub(t0) > 2 * qsbr::STALL_TIMEOUT_MS {
                return Err("the retired object was never freed (no grace period ended)");
            }
            sleep_ms(qsbr::GP_POLL_MS);
        }
        let cpu = RAN_ON.load(Ordering::SeqCst);
        if Some(cpu) != qsbr::callback_cpu() {
            return Err("the callback ran off the callback CPU (RCU_NOCBS_CPUS)");
        }
        if b.freed.load(Ordering::SeqCst) {
            return Err("the live object was freed");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn rcu_idle_cpu_is_quiescent() {
        if !qsbr::ON {
            return Err("RCU_QSBR is off in this ktest kernel");
        }
        let stalls = qsbr::stalls();
        let me = azos_arch::ARCH.hart_id();
        let others = (0..azos_percpu::nr_cpu_ids())
            .filter(|&c| c != me && azos_percpu::cpu_online(c)).count();
        let (mut quiet, mut longest) = (0usize, 0u64);
        for _ in 0..10 {
            // Let the other CPUs settle into tickless idle.
            sleep_ms(20);
            let t0 = now_ms();
            let mut gp = qsbr::Gp::start(t0, me);
            quiet += others - gp.waiting();
            loop {
                let now = now_ms();
                if gp.poll(now) {
                    longest = longest.max(now.wrapping_sub(t0));
                    break;
                }
                if now.wrapping_sub(t0) > 2 * qsbr::STALL_TIMEOUT_MS {
                    return Err("a grace period did not end (an idle CPU held it)");
                }
                sleep_ms(qsbr::GP_POLL_MS);
            }
        }
        crate::kprintln!("# rcu: {} of {} CPU snapshots quiescent at the start, longest grace period {} ms, stalls {}",
            quiet, 10 * others, longest, qsbr::stalls() - stalls);
        if qsbr::stalls() != stalls {
            return Err("the stall detector fired (an idle CPU held a grace period)");
        }
        if others != 0 && quiet == 0 {
            return Err("no idle CPU was quiescent at a grace period's start (the idle hook)");
        }
        Ok(())
    }
}

static HOLD_STARTED: AtomicBool = AtomicBool::new(false);
static HOLD_DONE: AtomicBool = AtomicBool::new(false);
/// How long the holder keeps its CPU in the kernel without a quiescent
/// state, and the test's stall window (well under it).
const HOLD_MS: u64 = 300;
const STALL_WINDOW_MS: u64 = 100;

/// A CPU stuck in the kernel: preemption off, no switch, for [`HOLD_MS`].
fn holder(_: usize) {
    {
        let _p = azos_sync::critical_section();
        HOLD_STARTED.store(true, Ordering::SeqCst);
        spin_us(HOLD_MS * 1000);
    }
    HOLD_DONE.store(true, Ordering::SeqCst);
}

azos_ktest::ktest_late! {
    fn rcu_stall_detector_names_the_cpu() {
        if !qsbr::ON {
            return Err("RCU_QSBR is off in this ktest kernel");
        }
        let me = azos_arch::ARCH.hart_id();
        let n = azos_percpu::nr_cpu_ids();
        let Some(cpu) = (1..n).map(|d| (me + d) % n).find(|&c| azos_percpu::cpu_online(c)) else {
            return Ok(()); // one CPU: nothing to hold a grace period but this one
        };
        HOLD_STARTED.store(false, Ordering::SeqCst);
        HOLD_DONE.store(false, Ordering::SeqCst);
        let stalls = qsbr::stalls();
        azos_sched::task_create_affinity("rcu-hold", holder, 0, 2, cpu as i8);
        crate::ktest::wait("the holder task never ran", || HOLD_STARTED.load(Ordering::SeqCst))?;
        let t0 = now_ms();
        let mut gp = qsbr::Gp::start(t0, me);
        loop {
            let now = now_ms();
            if gp.poll_within(now, STALL_WINDOW_MS) {
                break;
            }
            if now.wrapping_sub(t0) > 2 * qsbr::STALL_TIMEOUT_MS {
                return Err("the grace period never ended after the holder let go");
            }
            sleep_ms(qsbr::GP_POLL_MS);
        }
        crate::ktest::wait("the holder task never finished", || HOLD_DONE.load(Ordering::SeqCst))?;
        if qsbr::stalls() != stalls + 1 {
            return Err("a CPU held a grace period past the window and no stall was counted");
        }
        if qsbr::last_stall_cpu() != Some(cpu) {
            return Err("the stall named another CPU than the one holding the grace period");
        }
        Ok(())
    }
}

static LD_RCU_WQ: azos_sync::WaitQueue = azos_sync::WaitQueue::new();

azos_ktest::ktest_late! {
    fn lockdep_no_sleep_in_rcu_read() {
        if !azos_sync::lockdep::ON || !qsbr::ON {
            return Err("LOCKDEP or RCU_QSBR is off in this ktest kernel");
        }
        {
            let _r = qsbr::read();
            let _ = CUR.load(Ordering::Acquire);
            // `canary=lockdep-rcu-sleep`: a wait's entry (its lockdep check;
            // the predicate never sleeps) inside the section.
            if canary!("lockdep-rcu-sleep") {
                LD_RCU_WQ.wait_if(|| false);
            }
        }
        // Legal outside the section.
        LD_RCU_WQ.wait_if(|| false);
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn cap_lookup_lock_free_never_stale() {
        use azos_ipc::cap::{targets::Gpio, CapKind, CapPerms};
        use azos_ipc::cap_store;
        let tid = azos_sched::current_task_tid();
        const PIN: u32 = 0x7a5;
        let look = || cap_store::read_table(tid, |t| t.lookup(CapKind::Gpio, PIN)).flatten();
        if look().is_some() {
            return Err("the table already names the probe resource");
        }
        let Some(cap) = cap_store::grant::<Gpio>(tid, CapPerms::READ, PIN) else {
            return Err("grant into the ktest task's table failed");
        };
        // Twice: a scan that fills the cache, then a cache hit.
        for _ in 0..2 {
            match look() {
                Some(h) if h.as_raw() == cap.raw().as_raw() => {}
                _ => return Err("the lock-free lookup missed a held capability"),
            }
        }
        if cap_store::get(tid, cap, CapPerms::READ) != Ok(PIN) {
            return Err("the lock-free get did not resolve a held capability");
        }
        cap_store::revoke(tid, cap);
        if look().is_some() {
            return Err("the lookup answered from a revoked slot (a stale cache entry)");
        }
        if cap_store::get(tid, cap, CapPerms::READ).is_ok() {
            return Err("the lock-free get resolved a revoked capability");
        }
        Ok(())
    }
}
