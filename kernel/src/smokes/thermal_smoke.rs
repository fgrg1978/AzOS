// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The thermal row (`thermal-smoke`): `-smp 2 -icount shift=0,sleep=off`, the
//! balanced fake two-domain model (`azos_topology::builder::FAKE_ENERGY_MODEL`
//! with `energy-fake-balanced`: the DeadlineFloor governor, a WCET reference
//! clock per domain) and the framework's own runtime and task over a board
//! with no hardware: one fixture zone, a scripted temperature and a clock that
//! only remembers (`azos_thermal::fake`). QEMU has no thermal sensor, so this
//! is the one place the whole path (task -> governor seam -> tick -> floors ->
//! clock -> record) runs on a booted kernel.
//!
//! One busy task per CPU keeps both domains saturated, so the governor asks
//! for the top OPP of each; the controller then walks the temperature through
//! the trips and reads what the kernel's thermal task did. Each check ends in
//! one verdict line only its own path prints (`[THERMAL] <check> PASS|FAIL`):
//!
//! * **governor** — at 40 C the governor's request reaches the clock: both
//!   domains at their top OPP. (Nothing but the thermal task's tick moves the
//!   fake clock.) Canary `thermal-tick-canary` (the task never ticks): FAIL.
//! * **throttle** — at 75 C (past the passive trip) both clocks come down to
//!   their floors (the safety floor, or the deadline floor if real-time work is
//!   admitted) and the level reads cautious: the floors hold the
//!   clocks up while the heat asks for less. Canary `thermal-tick-canary`: FAIL.
//! * **floor** — in no sample of the throttle and degrade phases was a clock
//!   below its domain's safety floor. Canary `thermal-floor-canary` (the
//!   framework lowers the clock below the floors): FAIL.
//! * **degrade** — at 95 C (past the hot trip) the level reads slow, and the
//!   framework's ring holds the decision (`Level` 2). Canary
//!   `thermal-tick-canary`: FAIL.
//! * **recover** — back at 40 C the clocks return to the top OPP, the level to
//!   0, and the ring holds the relaxations. Canary `thermal-tick-canary`: FAIL.
//!
//! The run ends with `[THERMAL] done`. Every record also reaches the console
//! (`[THERMAL] zone ...`) and `Rule::Thermal`; the gate row greps the lines.

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_energy::governor::{deadline_floor_opp, safety_floor_opp};
use azos_energy::model::MAX_DOMAINS;
use azos_energy::thermal::{Event, LEVEL_CAUTIOUS, LEVEL_SLOW, LOG_LEN};
use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};
use azos_thermal::runtime::Runtime;

const CTL_PRIO: u32 = 14;
/// Behind the thermal task (Kconfig `THERMAL_TASK_PRIORITY`, 20 by default): a
/// busy task that out-ranked it would starve the very tick under test.
const BUSY_PRIO: u32 = 28;
const COOL_MDEG: i32 = 40_000;
const WARM_MDEG: i32 = 75_000;
const HOT_MDEG: i32 = 95_000;
/// Longest wait for a phase to show its effect, milliseconds of virtual time.
const PHASE_MS: u64 = 800;

static TEMP: AtomicI32 = AtomicI32::new(COOL_MDEG);
/// No sample of a phase found a clock below its floor.
static FLOOR_HELD: AtomicBool = AtomicBool::new(true);

/// The scripted temperature, milli-degrees Celsius: the fake sensor's reading.
pub fn temp() -> i32 {
    TEMP.load(Ordering::Relaxed)
}

fn ms(ms: u64) -> u64 {
    TIMER_FREQ.saturating_mul(ms) / 1_000
}

fn block_until(deadline: u64) {
    while now() < deadline {
        if task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
            while now() < deadline {
                core::hint::spin_loop();
            }
        }
    }
}

/// The controller on CPU 0 and a busy task on each CPU.
pub fn spawn() {
    azos_sched::task_create_affinity("thermal-ctl", ctl_task, 0, CTL_PRIO, 0);
    azos_sched::task_create_affinity("thermal-busy0", busy_task, 0, BUSY_PRIO, 0);
    azos_sched::task_create_affinity("thermal-busy1", busy_task, 1, BUSY_PRIO, 1);
    kprintln!("[THERMAL] created thermal-ctl on cpu 0, a busy task on each cpu");
}

fn busy_task(_: usize) {
    loop {
        core::hint::spin_loop();
    }
}

/// Per domain: the top OPP's frequency and the floor's, kHz. The floor is what
/// `Thermal::limit` holds: the larger of the deadline floor of the real-time
/// density admitted on the domain's most loaded hart and the safety floor.
fn clocks() -> ([u32; MAX_DOMAINS], [u32; MAX_DOMAINS]) {
    let (mut top, mut floor) = ([0; MAX_DOMAINS], [0; MAX_DOMAINS]);
    for (i, d) in azos_sched::energy::model().domains().iter().enumerate().take(MAX_DOMAINS) {
        top[i] = d.opps().last().map_or(0, |o| o.freq_khz);
        let opp = deadline_floor_opp(d, azos_sched::energy::domain_admitted_ppm(i)).max(safety_floor_opp(d));
        floor[i] = d.opps().get(opp).map_or(0, |o| o.freq_khz);
    }
    (top, floor)
}

/// Whether the framework's ring holds `ev` with `arg` (the last [`LOG_LEN`]).
fn has(rt: &Runtime, ev: Event, arg: u8) -> bool {
    (0..LOG_LEN).filter_map(|i| rt.thermal.record(i)).any(|r| r.event == ev && r.arg == arg)
}

/// Note whether any domain's clock is below its floor right now.
fn sample_floor(floor: &[u32; MAX_DOMAINS]) {
    let n = azos_sched::energy::model().domains().len().min(MAX_DOMAINS);
    let below = crate::boot::thermal::smoke_view(|_, khz| (0..n).any(|d| khz[d] != 0 && khz[d] < floor[d]));
    if below == Some(true) {
        FLOOR_HELD.store(false, Ordering::Relaxed);
    }
}

/// Wait up to [`PHASE_MS`] for `f` to hold, sampling the floors on the way.
fn wait_for(floor: &[u32; MAX_DOMAINS], mut f: impl FnMut(&Runtime, &[u32; MAX_DOMAINS]) -> bool) -> bool {
    let end = now() + ms(PHASE_MS);
    loop {
        sample_floor(floor);
        if crate::boot::thermal::smoke_view(|rt, khz| f(rt, khz)) == Some(true) {
            return true;
        }
        if now() >= end {
            return false;
        }
        block_until(now() + ms(5));
    }
}

/// One verdict line: the check, what it asserts, and the evaluations made and
/// the clocks at that moment.
fn verdict(name: &str, ok: bool, what: &str) {
    let ok = if ok { "PASS" } else { "FAIL" };
    match crate::boot::thermal::smoke_view(|rt, khz| (rt.ticks, *khz)) {
        Some((ticks, khz)) => kprintln!("[THERMAL] {} {} ({}; ticks={} khz={},{})", name, ok, what, ticks, khz[0], khz[1]),
        None => kprintln!("[THERMAL] {} {} ({}; no runtime)", name, ok, what),
    }
}

fn ctl_task(_: usize) {
    let n = azos_sched::energy::model().domains().len().min(MAX_DOMAINS);
    let (top, floor) = clocks();
    let at = |want: &[u32; MAX_DOMAINS], khz: &[u32; MAX_DOMAINS]| (0..n).all(|d| khz[d] == want[d]);

    // Cool: the governor's request reaches the clock.
    TEMP.store(COOL_MDEG, Ordering::Relaxed);
    let ok = wait_for(&floor, |_, khz| at(&top, khz));
    verdict("governor", ok, "the governed clocks are the top OPPs");

    // Warm: the passive trip caps the clocks down to the floors, no lower.
    TEMP.store(WARM_MDEG, Ordering::Relaxed);
    let ok = wait_for(&floor, |rt, khz| {
        at(&floor, khz) && rt.last().level == LEVEL_CAUTIOUS && has(rt, Event::TripUp, 0) && has(rt, Event::Uncooled, 0)
    });
    verdict("throttle", ok, "the clocks stand at the floors, the level is cautious");

    // Hot: the level rises, the clocks stay at the floors.
    TEMP.store(HOT_MDEG, Ordering::Relaxed);
    let ok = wait_for(&floor, |rt, khz| rt.last().level == LEVEL_SLOW && has(rt, Event::Level, LEVEL_SLOW) && at(&floor, khz));
    verdict("degrade", ok, "the level is slow and the ring holds it");
    verdict("floor", FLOOR_HELD.load(Ordering::Relaxed), "no clock was ever below its floor");

    // Cool again: the clocks and the level come back.
    TEMP.store(COOL_MDEG, Ordering::Relaxed);
    let ok = wait_for(&floor, |rt, khz| {
        at(&top, khz) && rt.last().level == 0 && has(rt, Event::Level, 0) && has(rt, Event::TripDown, 0)
    });
    verdict("recover", ok, "the clocks are back at the top, the level is 0");

    kprintln!("[THERMAL] done");
    loop {
        block_until(now() + ms(10_000));
    }
}
