// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Tick counter, control heartbeat and hardware-watchdog feed.
//!
//! `tick`, `halt_if_panicked` and `feed_from_timer_tick` run inside the timer
//! ISR. They touch atomics, `hart_id` and `wdt_kick` only. All three are
//! `#[inline]`: the ISR calls them across a crate boundary and the release
//! profile has `lto = false`.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use azos_drv_sys::kprintln;

/// Total timer ticks received across all CPUs (for verification).
///
/// Written only by [`tick`], from the timer ISR. Outside this crate it is read
/// through [`ticks`]; `sys_wdt` reads it directly.
pub(crate) static TICK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Timer ISR: count one tick and return the new total.
///
/// Returns the count this increment produced, which the ISR hands to
/// `vdso_update`; a separate [`ticks`] load could already include another
/// hart's tick. Wraps at `u64::MAX`, as the atomic itself does, so the path has
/// no overflow check.
#[inline]
pub fn tick() -> u64 {
    (TICK_COUNT.fetch_add(1, Ordering::Relaxed) as u64).wrapping_add(1)
}

/// The current tick total.
#[inline]
pub fn ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed) as u64
}

/// K-A1: liveness counter, incremented once per `rt_motor_task` iteration.
/// The timer ISR feeds the hardware WDT only while this advances, so a hung
/// control task (motors frozen at their last command) lets the WDT reset the
/// board instead of being masked by the still-running ISR. Zero means no
/// control task has ever run (an image without one): the feed then never
/// stalls on it. `pub` because the control task lives in a domain crate
/// (`azos_safety_core::rt_motor`).
pub static CONTROL_HEARTBEAT: AtomicU32 = AtomicU32::new(0);

/// The control heartbeat, read-only: completed `rt_motor_task` iterations.
/// For measurement (the SCHED-RT rows read how long it stood still).
#[inline]
pub fn control_heartbeat() -> u32 {
    CONTROL_HEARTBEAT.load(Ordering::Relaxed)
}
/// Last heartbeat observed by the WDT feeder (hart-0-owned).
static WDT_LAST_HEARTBEAT: AtomicU32 = AtomicU32::new(0);
/// Consecutive ticks the control heartbeat has not advanced (hart-0-owned).
static WDT_STALL_TICKS: AtomicU32 = AtomicU32::new(0);
/// Ticks the control task may stall before the WDT stops being fed. At the
/// 100 Hz tick this is ~400 ms of grace; with the 500 ms HW timeout the board
/// resets within ~900 ms of a genuine control-task hang. Comfortably above the
/// RT-priority control task's real scheduling period, so no false resets.
const WDT_CONTROL_STALL_LIMIT: u32 = 40;
/// `timebase::now()` when the feeder last saw the heartbeat advance
/// (hart-0-owned).
static WDT_LAST_ADVANCE: AtomicU64 = AtomicU64::new(0);
/// The same ~400 ms of grace in time, which the tick count only approximates:
/// timer interrupts are not 100 Hz. Each handler programs the nearest timer
/// sleeper, and since wave 11 (ONESHOT) a task blocking on a timer deadline
/// moves the comparator too, so with a 1 ms sleeper on hart 0 forty ticks are
/// ~40 ms (measured default boot, -smp 1: ~600 handler entries/s on riscv64
/// before that change). The feed continues while EITHER bound still holds, so
/// the grace is never shorter than 400 ms and never longer than it was.
const WDT_CONTROL_STALL_GRACE_MS: u64 = 400;

/// Timer ISR: if any hart has panicked, stop this hart's actuators and park it.
#[inline]
pub fn halt_if_panicked() {
    // If any hart has panicked, halt this one: bring our actuators to a
    // safe state and wfi-loop without kicking the WDT or scheduling, so
    // the board resets cleanly instead of limping on in a bad state.
    if azos_common::is_panicked() {
        // The actuators belong to a domain (the robot's wheels and ESC):
        // it registered their lock-free stop with `gate::
        // register_panic_stop_hook` at boot. Run here, in the same order.
        crate::gate::run_panic_stop_hooks();
        loop { azos_arch::cpu::wfi(); }
    }
}

/// Timer ISR: one more tick with the control heartbeat stalled; returns the new
/// stall count.
///
/// Saturating. `fetch_add(1) + 1` put an overflow-panic branch inside the timer
/// ISR under `overflow-checks = true`, and a wrapping count would drop back
/// under `WDT_CONTROL_STALL_LIMIT` after 2^32 stalled ticks and feed the WDT
/// again. The load and the store are separate operations: the counter is
/// hart-0-owned (both writers are in `feed_from_timer_tick`, under
/// `hart_id() == 0`), and the trap path does not set `sstatus.SIE` before
/// `schedule()`, so no second timer trap runs between them on that hart.
#[inline]
fn note_stalled_tick() -> u32 {
    let stalled = WDT_STALL_TICKS.load(Ordering::Relaxed).saturating_add(1);
    WDT_STALL_TICKS.store(stalled, Ordering::Relaxed);
    stalled
}

/// Timer ISR: K-A1 hardware-WDT feed, gated on `CONTROL_HEARTBEAT`.
#[inline]
pub fn feed_from_timer_tick() {
    // K-A1: feed the hardware WDT from hart 0 only, and only while the
    // RT control task is advancing. Kicking unconditionally would keep
    // the board alive even if the control task hung with the motors at
    // their last command; gating on its heartbeat lets the HW WDT reset
    // instead. `hb == 0` keeps feeding until the task first runs (no
    // boot-time false reset); after that a stall beyond the grace window
    // stops the kicks. (WDT is a no-op on QEMU; real effect on VF2/K1.)
    if azos_arch::cpu::hart_id() == 0 {
        let hb = CONTROL_HEARTBEAT.load(Ordering::Relaxed);
        if hb != WDT_LAST_HEARTBEAT.load(Ordering::Relaxed) {
            WDT_LAST_HEARTBEAT.store(hb, Ordering::Relaxed);
            WDT_STALL_TICKS.store(0, Ordering::Relaxed);
            WDT_LAST_ADVANCE.store(azos_drv_sys::timebase::now(), Ordering::Relaxed);
            azos_drv_sys::wdt::wdt_kick();
        } else if hb == 0 || {
            let stalled = note_stalled_tick();
            let since = azos_drv_sys::timebase::now()
                .saturating_sub(WDT_LAST_ADVANCE.load(Ordering::Relaxed));
            stalled <= WDT_CONTROL_STALL_LIMIT
                || since <= azos_drv_sys::timebase::TIMER_FREQ
                    .saturating_mul(WDT_CONTROL_STALL_GRACE_MS) / 1_000
        } {
            azos_drv_sys::wdt::wdt_kick();
        }
        // else: control task stalled after running — stop feeding the WDT.
    }
}

/// Arm the hardware watchdog with the configured timeout. Called by the kernel
/// immediately before `sched::start()`.
pub fn hw_init() {
    let wdt_ms = azos_config::CFG_WATCHDOG_MS.load(Ordering::Relaxed);
    azos_drv_sys::wdt::wdt_init(wdt_ms);
    if azos_drv_sys::wdt::wdt_has_hardware() {
        kprintln!("[WDT] Hardware watchdog initialized ({} ms timeout)", wdt_ms);
        kprintln!("[WDT] Counter = {}", azos_drv_sys::wdt::wdt_counter());
    } else {
        kprintln!("[WDT] No hardware WDT (QEMU) — software watchdog active");
    }
}
