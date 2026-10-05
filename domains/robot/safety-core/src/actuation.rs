// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The actuation seams the kernel installs at boot: the motor gate, the halt
//! query, the capability-denial recorders and the ring-3 emergency stop.

use azos_drv_sys::kprintln;
use core::sync::atomic::{AtomicU32, Ordering};
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Motor actuation record — Q1.3, 2026-09-25.
// ---------------------------------------------------------------------------
//
// `domains/robot/robot`'s `motor_set_reporting` already calls the hook installed
// below only on a CHANGE of (id, direction, effective speed) — a held
// command is naturally one call, not one per control tick. That alone is
// not a rate limit: a ramping PID output can change the duty every tick
// while it ramps, and "record on change" would then degrade to "record
// every tick" for the whole ramp — the exact flood class
// `crates/core/syscall/src/handlers.rs`'s `admit_denial_record` already exists to
// bound for capability denials. This is the same shape (a fixed budget per
// window, the excess counted rather than silently vanishing), keyed by
// motor id instead of task id: there are only `MAX_MOTORS` wheels and the
// budget belongs to the wheel, not to whichever caller is driving it this
// tick.

/// One motor's admission window for [`admit_motor_record`].
///
/// `last` is the (direction code, speed) of the MOST RECENT change offered
/// to this window, admitted or not — so that if the window closes with at
/// least one SUPPRESSED change and nothing since re-opens it (a ramp that
/// hits the budget and then holds its final value), the caller can still
/// get that settled value into the ring on the NEXT window's first call,
/// instead of the ring silently keeping only the ramp's first four steps
/// forever. See [`admit_motor_record`]'s `catch_up` return.
#[derive(Clone, Copy)]
struct MotorRecordWindow {
    used:       bool,
    start:      u64,
    recorded:   u32,
    suppressed: u32,
    last:       (u8, u32),
}
impl MotorRecordWindow {
    const FRESH: Self = Self { used: false, start: 0, recorded: 0, suppressed: 0, last: (0, 0) };
}

/// At most this many change-triggered actuation records per motor per
/// window (`azos_drv_sys::timebase::TIMER_FREQ` ticks, i.e. ~1 s) —
/// mirrors `DENIAL_RECORDS_PER_WINDOW` in `crates/core/syscall/src/handlers.rs`.
const MOTOR_RECORD_BUDGET_PER_WINDOW: u32 = 4;

static MOTOR_RECORD_TABLE: SpinLock<[MotorRecordWindow; azos_robot::motor::MAX_MOTORS]> =
    SpinLock::new([MotorRecordWindow::FRESH; azos_robot::motor::MAX_MOTORS]);

/// Records suppressed by the per-motor budget, since boot. Diagnostic only —
/// read by `motor_records_suppressed()` in host tests — and deliberately NOT
/// written to the flight recorder as its own event: unlike a capability
/// denial this is not itself news, and [`admit_motor_record`]'s `catch_up`
/// already gets the settled value into the ring on the window after.
///
/// `panic = "abort"` + `overflow-checks = true` makes a wrapping plain
/// integer op a hard stop, but an atomic `fetch_add` is exempt from that
/// instrumentation entirely and just wraps — which is the correct, SAFE
/// behavior for a diagnostic counter two harts can race on (`rt_motor`'s
/// control loop and a ring-3 syscall on another core both reach this hook),
/// not a hazard to work around by hand.
static MOTOR_RECORDS_SUPPRESSED: AtomicU32 = AtomicU32::new(0);

/// Count of actuation records the per-motor budget has suppressed since
/// boot. Test/diagnostic accessor. Racy under concurrent suppression on two
/// harts (a lost `fetch_add` undercounts) — not load-bearing, a diagnostic
/// only.
pub fn motor_records_suppressed() -> u32 {
    MOTOR_RECORDS_SUPPRESSED.load(Ordering::Relaxed)
}

/// Admit or suppress one change-triggered record for motor `id`, carrying
/// `(dir_code, speed)` so the window can remember it as `last`. Returns
/// `(admit, catch_up)`: `admit` says whether THIS change should be recorded
/// now; `catch_up`, `Some` only on a window rollover that closed with an
/// unrecorded suppression, is the previous window's last value — the
/// caller records it (if present) BEFORE this change, so the ring never
/// permanently loses the settled state of a ramp that stopped changing
/// right as its budget ran out.
///
/// `id` outside `MAX_MOTORS` always admits with no catch-up —
/// `motor_set_reporting` already refuses such an id before this hook is
/// ever reached, so this is a defensive default, not a path this crate
/// expects to exercise.
fn admit_motor_record(id: u32, dir_code: u8, speed: u32, now: u64, window: u64) -> (bool, Option<(u8, u32)>) {
    let idx = id as usize;
    if idx >= azos_robot::motor::MAX_MOTORS { return (true, None); }
    let mut table = MOTOR_RECORD_TABLE.lock();
    let w = &mut table[idx];
    let mut catch_up = None;
    if !w.used || now.wrapping_sub(w.start) >= window {
        if w.used && w.suppressed > 0 {
            catch_up = Some(w.last);
        }
        *w = MotorRecordWindow { used: true, start: now, recorded: 0, suppressed: 0, last: (dir_code, speed) };
    }
    w.last = (dir_code, speed);
    let admit = if w.recorded < MOTOR_RECORD_BUDGET_PER_WINDOW {
        w.recorded += 1;
        true
    } else {
        w.suppressed = w.suppressed.saturating_add(1);
        MOTOR_RECORDS_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    };
    (admit, catch_up)
}

/// The robot's half of the one latch-and-stop sequence
/// (`azos_actuation::gate::latch_and_stop`, which holds the reasoning):
/// motors 0 and 1, the ESC, then the payload, after the latch is set.
/// Registered by [`install`].
///
/// **Motors 0 and 1 are every motor that exists**: `robot_init` calls
/// `motor_init` exactly twice, and `motor_stop` on an uninitialised id
/// returns -1 without touching anything. Said out loud because `MAX_MOTORS`
/// is 4 and the gap invites a second look.
fn stop_robot_actuators() {
    azos_robot::motor_stop(0);
    azos_robot::motor_stop(1);
    azos_robot_drivers::esc::esc_disarm();
    // H22, 2026-09-26: the payload actuators (spray pump) are the third
    // family this sequence now covers, alongside the wheels and the ESC —
    // a command already in flight when the latch engages must not keep
    // running until `payload_exec` refuses the NEXT one.
    azos_behavior::payload::payload_emergency_stop();
}

/// The panic-path stop: lock-free, run from the panic handler and from the
/// timer interrupt of a hart that sees another one panicked.
fn stop_robot_actuators_panic() {
    azos_robot::motor_stop_panic(0);
    azos_robot::motor_stop_panic(1);
    azos_robot_drivers::esc::esc_disarm_panic();
}

/// Re-exported so `azos_safety_core::actuation::latch_and_stop` still
/// resolves for robot callers.
pub use azos_actuation::gate::latch_and_stop;

/// Install the robot's seams, in the order the kernel always installed them.
/// Called once from `kernel_main`, after the file-ops seam and right before
/// `azos_actuation::gate::install`.
pub fn install() {
    // The robot's stop work, registered into the shared latch first: from
    // here on every latch (brain link, ring 3, kill switch, sys-wdt) stops
    // the wheels, the ESC and the payload, and makes the cached remote
    // action the stop.
    azos_actuation::estop::register_on_latch_hook(azos_behavior::safety::on_estop_latched);
    azos_actuation::gate::register_stop_hook(stop_robot_actuators);
    azos_actuation::gate::register_panic_stop_hook(stop_robot_actuators_panic);
    // Ring-3 images start only once the motor gate is in place (the loader
    // asks `azos_actuation::gate::gate_installed`).
    azos_actuation::gate::set_domain_gate_check(azos_robot::motor::motor_gate_installed);

    // `#[allow(dead_code)]`: unused only under `gate-skip-smoke`, which
    // skips the one call below that would otherwise use it.
    #[allow(dead_code)]
    fn actuation_gate(_id: u32, speed_pct: u32) -> u32 {
        // A marker was tried here on 2026-09-07 and REMOVED, because it
        // did not discriminate. See the note in `tools/ci_check.sh` above
        // the `userspace: reflex reacts` scenario: `rt_motor_task` writes
        // the motors every control tick, so a print at this hook fires
        // ~2300 times per boot whether or not any ring-3 program commanded
        // anything (2328 occurrences in the baseline, 2308 with
        // `sys_motor_speed_typed` stubbed to actuate nothing). Wiring that
        // into the gate would have added a check that always passes.
        //
        // What a working version needs is caller identity, which this hook
        // does not have — `set_motor_gate`'s signature is `(id, speed)` —
        // or a marker inside the syscall handler, which needs the smoke
        // feature plumbed into `crates/core/syscall`. Both are more than a
        // print, and neither should be guessed at.

        // E-stop first and unconditionally: it outranks every other
        // consideration, and it is a latch, not a momentary signal.
        if azos_behavior::safety::estop_is_active() { return 0; }
        // Then the envelope, which composes the per-robot-type ceiling,
        // RFC-0035's low-confidence cap and RFC-0037's graded degrade
        // level, taking the tightest. It works in signed percentages on a
        // pair; a single unsigned speed is passed as both halves and the
        // magnitude of the result is the permitted speed.
        let s = speed_pct.min(100) as i32;
        let (l, _) = azos_behavior::safety::motor_envelope(s, s);
        if l <= 0 { 0 } else { l as u32 }
    }
    // `gate-skip-smoke`: canary for Q1.4's fail-closed default. Never on in
    // a normal build — nothing in `kernel/Cargo.toml`'s default feature set
    // turns it on — and it skips EXACTLY this one call, nothing else `install`
    // does: the halt query, the denial recorders and ring-3 estop still arm,
    // so a boot with this feature isolates the ONE property under test
    // (does `gate_speed`'s `None` branch really clamp to 0) from everything
    // else `install` wires.
    #[cfg(not(feature = "gate-skip-smoke"))]
    azos_robot::motor::set_motor_gate(actuation_gate);
    #[cfg(feature = "gate-skip-smoke")]
    kprintln!("[SAFETY] actuation gate SKIPPED (gate-skip-smoke) — motor writes must clamp to 0");

    // The halt query beside it. The gate sets the duty; this decides the
    // direction pins. While it answers true, `motor_set_reporting` writes
    // brake and coast and refuses forward and backward without touching
    // the pins (owner decision 2026-09-13), for every caller — this
    // kernel's own `rt_motor_task` included, whose refused writes still
    // leave duty 0 on the channel. The two conditions are a latched e-stop
    // and RFC-0036 containment (`DEGRADE_LEVEL_CONTAINED`, speed cap 0 %).
    fn actuation_halt() -> bool {
        azos_behavior::safety::estop_is_active()
            || azos_ipc::cap::degraded_active()
    }
    azos_robot::motor::set_motor_halt(actuation_halt);
    kprintln!("[SAFETY] actuation gate armed (estop + envelope on every motor write)");

    // Q1.3: every ADMITTED actuation command gets a bounded, rate-limited
    // record. `domains/robot/robot` already calls this only on a change of (id,
    // direction, effective speed); `admit_motor_record` above bounds the
    // rest (a ramping PID output can still change every tick).
    //
    // `LOG_EVT_ACTUATOR_CMD` / `log_actuator_cmd` (`domains/robot/behavior/src/
    // logger.rs`) already existed for exactly this shape with zero callers —
    // reused rather than adding a second event kind. `actuator_type` carries
    // the motor id, `ch0` the applied `MotorDir` discriminant (0 Forward, 1
    // Backward, 2 Brake, 3 Coast), `ch1` the effective speed 0-100; `ch2`/
    // `ch3` are unused (0).
    //
    // Ring-only, like the capability-denial hooks beside it: durability
    // waits for the watchdog's existing periodic flush
    // (`azos_behavior::logger::logger_tick`) — no second durable path
    // invented for this, per Q1.3's own constraint. A held command's
    // control-loop cadence never reaches this function at all (no change,
    // no call), so the cost on `rt_motor`'s cadence is the unchanged case:
    // not measured beyond that.
    fn record_motor_change(id: u32, dir: azos_robot::motor::MotorDir, speed_pct: u32) {
        let now = azos_drv_sys::timebase::now();
        let dir_code = dir as u8;
        let speed = speed_pct.min(100);
        let (admit, catch_up) = admit_motor_record(
            id, dir_code, speed, now, azos_drv_sys::timebase::TIMER_FREQ);

        // A previous window closed with at least one change the budget
        // never let through — its LAST value, so the ring still reaches the
        // settled state even when nothing changes again to trigger it.
        // Written first, so ring/disk order matches wall-clock order.
        if let Some((cdir, cspeed)) = catch_up {
            azos_behavior::logger::log_actuator_cmd(id as u8, cdir as i16, cspeed as i16, 0, 0);
            #[cfg(feature = "actuation-smoke")]
            kprintln!("[ACTREC] motor id={} dir={} duty={} ring_len={} (catch-up)",
                id, cdir, cspeed, azos_behavior::logger::logger_ring_len());
        }

        if !admit { return; }
        azos_behavior::logger::log_actuator_cmd(id as u8, dir_code as i16, speed as i16, 0, 0);
        #[cfg(feature = "actuation-smoke")]
        kprintln!("[ACTREC] motor id={} dir={} duty={} ring_len={}",
            id, dir_code, speed, azos_behavior::logger::logger_ring_len());
    }
    azos_robot::motor::set_motor_recorder(record_motor_change);
    kprintln!("[SAFETY] actuation record armed (motor commands logged on change)");

    // H22/U08-6, 2026-09-26: `flight_arm` needs the same fact `motor_gate`
    // reads, and cannot depend on `azos_behavior` to get it (this crate
    // already depends on `azos_flight`, so the reverse edge would be a
    // cycle) — same shape as the motor gate two hooks above.
    azos_flight::set_arm_gate(azos_behavior::safety::estop_is_active);
    kprintln!("[SAFETY] flight-arm gate armed (refuses while e-stop latch holds)");

    // The capability-denial and audit recorders and the ring-3 e-stop are
    // not robot-specific: `azos_actuation::gate::install` arms them,
    // right after this function (wave 11).
}
