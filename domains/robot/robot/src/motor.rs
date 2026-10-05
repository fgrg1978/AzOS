// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Motor control — port of robot/motor.c
///
/// Controls DC motors via PWM channels and direction GPIO pins.
/// Uses simulated GPIO/PWM from drivers crate.

use super::pid::Pid;

pub const MAX_MOTORS: usize = 4;

/// PWM period for motor channels. Matches `PwmChannel::new()`'s default
/// `period_ns` (see `drivers::pwm`), so this is an explicit statement of
/// the value QEMU/sim already used implicitly — not a new behavior.
/// On real vf2/k1 hardware the right motor driver PWM frequency is a
/// hardware decision (depends on the motor driver IC); 1 kHz is a common
/// safe default for brushed DC motor drivers but should be confirmed
/// against the actual motor driver datasheet before hardware bring-up.
pub const MOTOR_PWM_PERIOD_NS: u32 = 1_000_000; // 1 kHz

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum MotorDir {
    Forward  = 0,
    Backward = 1,
    Brake    = 2,
    Coast    = 3,
}

#[derive(Clone, Copy)]
pub struct Motor {
    pub id:          u32,
    pub pwm_ch:      u32,
    pub dir_pin_a:   u32,
    pub dir_pin_b:   u32,
    pub direction:   MotorDir,
    pub speed_pct:   u32,    // 0-100%
    pub initialized: bool,
    pub pid:         Pid,
}

impl Motor {
    pub const fn new() -> Self {
        Motor {
            id:          0,
            pwm_ch:      0,
            dir_pin_a:   0,
            dir_pin_b:   0,
            direction:   MotorDir::Coast,
            speed_pct:   0,
            initialized: false,
            pid:         Pid::new(),
        }
    }
}

use azos_sync::SpinLock;
static MOTORS: SpinLock<[Motor; MAX_MOTORS]> = SpinLock::new([Motor::new(); MAX_MOTORS]);

/// Initialize a motor with its PWM channel and direction GPIO pins.
pub fn motor_init(id: u32, pwm_ch: u32, dir_a: u32, dir_b: u32) -> i32 {
    if id as usize >= MAX_MOTORS { return -1; }

    // Configure GPIO direction pins as outputs
    azos_drv_gpio::gpio::gpio_set_direction(dir_a, azos_drv_gpio::gpio::GpioDir::Output);
    azos_drv_gpio::gpio::gpio_set_direction(dir_b, azos_drv_gpio::gpio::GpioDir::Output);

    // Configure PWM. Period MUST be set before duty — on vf2/k1 real
    // hardware `pwm_set_duty_pct` writes the same compare register that
    // holds the period count (see `drivers::pwm` doc comment on
    // `pwm_set_duty_pct`: TRM-blocked register aliasing bug, not fixed
    // here), so at minimum the period must be programmed once up front.
    if azos_drv_actuator::pwm::pwm_set_period(pwm_ch, MOTOR_PWM_PERIOD_NS) != 0 {
        azos_drv_sys::kerr!(
            "[MOTOR] motor {}: pwm_set_period(ch={}) failed", id, pwm_ch
        );
    }
    azos_drv_actuator::pwm::pwm_enable(pwm_ch);
    azos_drv_actuator::pwm::pwm_set_duty_pct(pwm_ch, 0);

    let mut motors = MOTORS.lock();
    let m = &mut motors[id as usize];
    m.id          = id;
    m.pwm_ch      = pwm_ch;
    m.dir_pin_a   = dir_a;
    m.dir_pin_b   = dir_b;
    m.direction   = MotorDir::Coast;
    m.speed_pct   = 0;
    m.initialized = true;
    0
}

/// Set motor direction and speed (0-100%).
/// The safety gate every motor write passes through.
///
/// Takes the requested speed percentage and returns the permitted one; 0 means
/// refuse. `None` until the kernel installs one at boot, and until then the
/// requested speed is CLAMPED TO 0 — owner decision 2026-09-25 (Q1.4),
/// reversing the previous passthrough default.
///
/// **Fail closed, not fail open.** The previous behaviour ("no gate installed
/// -> the requested speed is used unchanged") was argued as "what a build
/// with no safety layer at all should do". That reasoning assumed the only
/// way to reach this branch was a deliberate build with the safety layer
/// left out. It is also what a kernel reaches for a few instructions on
/// every real boot, before `azos_safety_core::actuation::install()`
/// runs (`kernel/src/main.rs`), and what it would reach for the rest of a
/// boot where that call was skipped by a future refactor, an early panic
/// recovery, or a build variant nobody re-audited. A passthrough default
/// makes exactly that ordering bug indistinguishable from "no safety
/// policy exists" at the one place — the PWM write — every motor command
/// from every path (syscall, in-kernel task, driver server) is required to
/// cross. `None => 0` makes the same bug STOP the motors instead of moving
/// them at whatever speed was asked. See [`motor_gate_installed`] for the
/// structural check `autorun_task` uses to refuse starting ring-3 code at
/// all while this is true, and `tests/host/behavior-tests` /
/// `tests/host/regression-tests` for the host proof.
///
/// ## Why this exists, and why it is HERE
///
/// The product thesis says this system is an actuation authority: the brain is
/// untrusted and the OS is the thing that refuses. It was not. `motor_envelope`
/// (speed ceilings, low-confidence cap, graded degrade level) and
/// `estop_is_active()` were applied by `rt_motor_task` — one caller of
/// `motor_set` among several. `sys_motor_speed` and `sys_motor_enable` are
/// other callers, they reach ring 3, and `autorun_task` grants `Motor(0)` and
/// `Motor(1)` to a TID that `exec_user` then reuses for the ring-3 process. So
/// a user program holding those capabilities drove the motors at any speed it
/// liked, and — worse — **one call after an e-stop re-energised a motor that
/// nothing then re-stopped**, because the e-stop path is a one-shot
/// `motor_stop` plus a flag that only `rt_motor_task` reads.
///
/// A `grep` for `estop`, `degrade` or `envelope` across the whole syscall
/// crate returned nothing. Meanwhile `safety.rs` and `main.rs` both described
/// the arrangement as "structurally unbypassable".
///
/// Putting the gate in the syscall handler would have closed that one door.
/// This is the door itself: `motor_set` is where the PWM duty is written, so
/// every path — syscall, in-kernel task, driver server, anything added later —
/// crosses it. Same reasoning as the page-table guard that went into the
/// mapper rather than into `sys_munmap`.
static MOTOR_GATE: azos_sync::SpinLock<Option<fn(u32, u32) -> u32>> =
    azos_sync::SpinLock::new(None);

/// Install the actuation gate. Called once at boot from
/// `azos_safety_core::actuation::install`, which sees both the motors and
/// the safety layer.
pub fn set_motor_gate(f: fn(id: u32, speed_pct: u32) -> u32) {
    *MOTOR_GATE.lock() = Some(f);
}

/// Apply the installed gate, if any. The lock is released before the call, so
/// nothing is held while the safety layer runs.
///
/// `None => 0`, not `None => speed_pct` — see [`set_motor_gate`]'s doc for
/// why the fail-closed default is the correct one here.
#[inline]
fn gate_speed(id: u32, speed_pct: u32) -> u32 {
    let g = *MOTOR_GATE.lock();
    match g { Some(f) => f(id, speed_pct), None => 0 }
}

/// Whether [`set_motor_gate`] has been called. `false` for a kernel that has
/// not yet reached `azos_safety_core::actuation::install()`, or one that
/// never will.
///
/// Reads the same `Option` [`gate_speed`] matches on — not a second flag a
/// caller could observe out of step with the one that actually decides duty.
/// The boot-time refusal this exists for (`autorun_task`,
/// `kernel/src/main.rs`) needs a fact, not a second source of truth for the
/// same fact.
pub fn motor_gate_installed() -> bool {
    MOTOR_GATE.lock().is_some()
}

/// The halt query every motor write consults, beside the gate.
///
/// The gate decides the DUTY. This decides the H-bridge DIRECTION PINS: while
/// it answers true, [`motor_set_reporting`] writes `Brake` and `Coast` as asked
/// and refuses `Forward` and `Backward` — owner decision 2026-09-13, "stopping
/// yes, changing direction no". The kernel installs it answering a latched
/// e-stop or RFC-0036 containment, neither of which this crate can see.
///
/// `None` until installed, and then nothing is halted: the same rule as the
/// gate, for the same reason.
static MOTOR_HALT: azos_sync::SpinLock<Option<fn() -> bool>> =
    azos_sync::SpinLock::new(None);

/// Install the halt query. Called once at boot by the kernel, beside
/// [`set_motor_gate`].
pub fn set_motor_halt(f: fn() -> bool) {
    *MOTOR_HALT.lock() = Some(f);
}

/// Ask the installed halt query, if any. The lock is released before the call.
#[inline]
fn motor_halted() -> bool {
    let h = *MOTOR_HALT.lock();
    match h { Some(f) => f(), None => false }
}

/// Records a CHANGE in a motor's applied (direction, effective speed).
///
/// Owner decision 2026-09-25 (Q1.3): the product thesis says no irreversible
/// effect happens without a record, and until now a SUCCESSFUL motor command
/// left none — only refusals and stops were recorded. This is the seam that
/// closes it, installed once at boot by
/// `azos_safety_core::actuation::install`, beside [`MOTOR_GATE`] and
/// [`MOTOR_HALT`] and for the same reason: `domains/robot/robot` cannot depend on
/// `domains/robot/behavior` (the flight recorder), so a function pointer crosses
/// the seam instead of a direct call.
///
/// `None` until installed — [`motor_set_reporting`] simply does not record,
/// same as an uninstalled gate does not clamp. Called only on a CHANGE of
/// `(id, direction, speed)` from what was last applied to that motor id
/// (compared in [`motor_set_reporting`] against the `Motor` table before it
/// is overwritten), never on a repeat: `rt_motor_task` rewrites both wheels
/// every control tick, and a held command must be one record, not one per
/// tick — the failure class `sys_wdt.rs`'s e-stop poll already had to learn
/// for the same reason. The installed function additionally rate-limits per
/// motor (`domains/robot/safety-core/src/actuation.rs`), because "on change" alone
/// still fires every tick of a ramping PID output.
static MOTOR_RECORD: azos_sync::SpinLock<Option<fn(id: u32, dir: MotorDir, speed_pct: u32)>> =
    azos_sync::SpinLock::new(None);

/// Install the actuation recorder. Called once at boot from
/// `azos_safety_core::actuation::install`, beside [`set_motor_gate`] and
/// [`set_motor_halt`].
pub fn set_motor_recorder(f: fn(id: u32, dir: MotorDir, speed_pct: u32)) {
    *MOTOR_RECORD.lock() = Some(f);
}

/// Call the installed recorder, if any. The lock is released before the
/// call, matching [`gate_speed`]/[`motor_halted`].
#[inline]
fn record_motor_change(id: u32, dir: MotorDir, speed_pct: u32) {
    let r = *MOTOR_RECORD.lock();
    if let Some(f) = r { f(id, dir, speed_pct); }
}

/// [`motor_set_reporting`]'s return code for a `Forward` or `Backward` command
/// refused while the halt query answers true. Distinct from `-1` (bad id,
/// uninitialised motor, panicked machine) so a syscall can answer with the
/// containment errno rather than a generic failure.
pub const MOTOR_REFUSED_HALTED: i32 = -2;

/// The direction and speed the motor table records for motor `id`; `None` for
/// a bad id or an uninitialised motor. The direction is the one the last
/// admitted command wrote to the pins: a refused command sets only the speed,
/// to 0.
pub fn motor_state(id: u32) -> Option<(MotorDir, u32)> {
    if id as usize >= MAX_MOTORS { return None; }
    let m = MOTORS.lock();
    let r = &m[id as usize];
    if r.initialized { Some((r.direction, r.speed_pct)) } else { None }
}

/// The motor bound to PWM channel `ch`, if any.
///
/// Exists so the routes that reach `pwm_set_duty_pct` WITHOUT going through
/// `motor_set` can refuse a channel that drives a wheel. The actuation gate
/// lives inside `motor_set`, and `SYS_DRV_INVOKE`'s PWM driver and the typed
/// PWM capability both write the same compare register one level below it —
/// so on a board where motors 0 and 1 are PWM channels 0 and 1, either route
/// could spin a wheel through a latched e-stop.
///
/// Returns `None` for a channel no initialised motor claims, which is how the
/// buzzer keeps working: it owns its own channel and is not an actuator the
/// safety envelope has an opinion about.
/// The motor whose H-bridge direction pin is `pin`, if any.
///
/// The GPIO twin of [`pwm_channel_motor_id`], and it exists for exactly the
/// same reason: the routes that reach `gpio_write` WITHOUT going through
/// `motor_set` must be able to refuse a pin that steers a wheel. The PWM half
/// of that hole was closed and this half was not — one class, two instances.
///
/// What it protects is not how FAST a wheel turns but which WAY. The duty
/// lives on the PWM channel; these two pins decide what the bridge does with
/// it. Both high is a brake, flipping one reverses a wheel that is already
/// turning, and setting either to Input floats the bridge input — none of it
/// passes through `gate_speed`, so a latched e-stop and the motor envelope are
/// bypassed together. A caller that legitimately needs a direction change has
/// `SYS_MOTOR_ENABLE`, which does go through the gate.
///
/// Returns `None` for a pin no initialised motor claims, which is how every
/// other GPIO user keeps working.
pub fn gpio_pin_motor_id(pin: u32) -> Option<u32> {
    let m = MOTORS.lock();
    for i in 0..MAX_MOTORS {
        if m[i].initialized && (m[i].dir_pin_a == pin || m[i].dir_pin_b == pin) {
            return Some(m[i].id);
        }
    }
    None
}

pub fn pwm_channel_motor_id(ch: u32) -> Option<u32> {
    let m = MOTORS.lock();
    for i in 0..MAX_MOTORS {
        if m[i].initialized && m[i].pwm_ch == ch {
            return Some(m[i].id);
        }
    }
    None
}

pub fn motor_set(id: u32, dir: MotorDir, speed_pct: u32) -> i32 {
    motor_set_reporting(id, dir, speed_pct).0
}

/// `motor_set`, plus the duty this command actually left on the wheel's PWM
/// channel — `None` when nothing was driven (bad id, uninitialised motor, or
/// a machine that has already panicked).
///
/// The point is that the second half of the pair comes from the same critical
/// section as the write (see `pwm::pwm_set_duty_pct_reporting`) rather than
/// from a later read of the channel. These channels have two writers: a
/// syscall commands a wheel and `rt_motor_task` drives the same wheel every
/// control tick. A caller that wrote and then called `pwm_get` could be handed
/// the other writer's duty, which is a race in whatever compares the asked-for
/// and applied values — spurious red when the control loop wins the window,
/// false green when it happens to write the same number.
///
/// What the applied value is good for: it is produced by the hardware write
/// itself, so it distinguishes a command that actuated from a call that merely
/// returned 0 — the failure mode measured on 2026-09-07, when a typed handler
/// stubbed to drive nothing left the scenario green. It is also where the
/// safety layer becomes visible, since `gate_speed` can clamp the request to
/// something smaller before it ever reaches the channel.
///
/// A `Forward` or `Backward` command refused by the halt rule (below) is not a
/// `None`: it writes duty 0, reports that, and returns `MOTOR_REFUSED_HALTED`.
pub fn motor_set_reporting(id: u32, dir: MotorDir, speed_pct: u32) -> (i32, Option<u32>) {
    // Refuse to drive motors after a panic: motor_stop_panic() has already
    // brought them to a safe state and must not be undone by a straggling
    // control path on another hart.
    if azos_common::is_panicked() { return (-1, None); }
    if id as usize >= MAX_MOTORS { return (-1, None); }
    let (pwm_ch, dir_a, dir_b) = {
        let m = MOTORS.lock();
        if !m[id as usize].initialized { return (-1, None); }
        (m[id as usize].pwm_ch, m[id as usize].dir_pin_a, m[id as usize].dir_pin_b)
    };

    // Owner decision 2026-09-13, "stopping yes, changing direction no". The
    // gate only sets the DUTY, so a clamped command used to reconfigure the
    // H-bridge all the same: a latched e-stop answered duty 0 and the pins were
    // written for whatever direction was asked. While the halt query answers
    // true (a latched e-stop or containment, as the kernel installs it):
    //
    // * `Brake` and `Coast` are written as asked, at duty 0;
    // * `Forward` and `Backward` are refused. The pins keep what they were set
    //   to, the recorded direction keeps saying so, and the call returns
    //   `MOTOR_REFUSED_HALTED`. Duty 0 is still written and reported: the
    //   kernel's control loop rewrites both wheels every tick, and its refused
    //   commands are what hold a wheel at 0 — a refusal that wrote nothing
    //   would leave the last applied duty on the channel.
    //
    // While halted the duty is 0 without consulting the gate, so it does not
    // depend on the installed gate agreeing. The query is read once per
    // command.
    let halted = motor_halted();
    if halted && matches!(dir, MotorDir::Forward | MotorDir::Backward) {
        let applied = azos_drv_actuator::pwm::pwm_set_duty_pct_reporting(pwm_ch, 0);
        // The direction pins are untouched here (refused, not applied), but
        // the duty dropping to 0 is itself the actuation effect an
        // investigator wants — e.g. a 50% command mid-halt. Recorded with
        // the motor's last APPLIED direction, not the refused `dir`: the
        // pins still reflect the old one.
        let (changed, last_dir) = {
            let mut motors = MOTORS.lock();
            let m = &mut motors[id as usize];
            let changed = m.speed_pct != 0;
            m.speed_pct = 0;
            (changed, m.direction)
        };
        if changed { record_motor_change(id, last_dir, 0); }
        return (MOTOR_REFUSED_HALTED, applied);
    }
    let speed = if halted { 0 } else { gate_speed(id, speed_pct.min(100)) };

    match dir {
        MotorDir::Forward  => {
            azos_drv_gpio::gpio::gpio_write(dir_a, 1);
            azos_drv_gpio::gpio::gpio_write(dir_b, 0);
        }
        MotorDir::Backward => {
            azos_drv_gpio::gpio::gpio_write(dir_a, 0);
            azos_drv_gpio::gpio::gpio_write(dir_b, 1);
        }
        MotorDir::Brake => {
            azos_drv_gpio::gpio::gpio_write(dir_a, 1);
            azos_drv_gpio::gpio::gpio_write(dir_b, 1);
        }
        MotorDir::Coast => {
            azos_drv_gpio::gpio::gpio_write(dir_a, 0);
            azos_drv_gpio::gpio::gpio_write(dir_b, 0);
        }
    }
    let applied = azos_drv_actuator::pwm::pwm_set_duty_pct_reporting(pwm_ch, speed);

    let changed = {
        let mut motors = MOTORS.lock();
        let m = &mut motors[id as usize];
        let changed = m.direction != dir || m.speed_pct != speed;
        m.direction  = dir;
        m.speed_pct  = speed;
        changed
    };
    // Recorded with `speed` — the EFFECTIVE, post-gate value `gate_speed`
    // returned above, not the caller's `speed_pct` ask. The lock is released
    // first, matching `gate_speed`/`motor_halted`'s own discipline: nothing
    // of this crate's is held while the recorder (installed by
    // `safety-core`, which calls into `behavior`) runs.
    if changed { record_motor_change(id, dir, speed); }
    (0, applied)
}

/// Stop a motor (coast).
pub fn motor_stop(id: u32) -> i32 {
    motor_stop_reporting(id).0
}

/// `motor_stop`, reporting the applied duty the way [`motor_set_reporting`]
/// does. Exists so a caller that needs the pair does not have to open-code
/// `MotorDir::Coast, 0` and drift from what stopping means here.
pub fn motor_stop_reporting(id: u32) -> (i32, Option<u32>) {
    motor_set_reporting(id, MotorDir::Coast, 0)
}

/// Emergency motor stop for the panic handler — bypasses the `MOTORS`
/// spinlock and calls the lock-free `_panic` GPIO/PWM variants instead
/// of `gpio_write`/`pwm_set_duty_pct`.
///
/// Deliberately sacrifices mutual exclusion, same rationale as
/// `drivers::gpio::gpio_write_panic` / `drivers::pwm::pwm_set_duty_pct_panic`
/// (see their doc comments): if another hart holds `MOTORS` — or the
/// `GPIO`/`PWM` locks reached through the normal `motor_stop` ->
/// `motor_set` path — at the moment of a panic, waiting for any of them
/// would spin forever and the panic message would never reach UART.
/// Getting the actuators to a safe (coast) state and the crash reason
/// printed matters more than leaving `Motor` bookkeeping consistent
/// while the kernel is already crashing. This is why the `Motor` fields
/// are read via `SpinLock::get_mut_unchecked` instead of `.lock()`, and
/// why this function does not write back `direction`/`speed_pct` into
/// `MOTORS` afterward the way `motor_set` does — the kernel is halting
/// or rebooting right after, so there is nothing left to read that state.
///
/// # Safety
/// May race with a concurrent `motor_init`/`motor_set` on another hart
/// for the same `id`, producing a torn read of `Motor` (e.g. a stale
/// `pwm_ch` paired with a fresher `dir_pin_a`). Only call this from the
/// panic handler.
pub fn motor_stop_panic(id: u32) {
    if id as usize >= MAX_MOTORS { return; }

    let (pwm_ch, dir_a, dir_b, initialized) = {
        let motors = unsafe { MOTORS.get_mut_unchecked() };
        let m = &motors[id as usize];
        (m.pwm_ch, m.dir_pin_a, m.dir_pin_b, m.initialized)
    };
    if !initialized { return; }

    // Coast: both direction pins low, 0% duty — mirrors the
    // `MotorDir::Coast` arm of `motor_set` above.
    azos_drv_gpio::gpio::gpio_write_panic(dir_a, 0);
    azos_drv_gpio::gpio::gpio_write_panic(dir_b, 0);
    azos_drv_actuator::pwm::pwm_set_duty_pct_panic(pwm_ch, 0);
}

/// Brake a motor (short-circuit for fast stop).
pub fn motor_brake(id: u32) -> i32 {
    motor_set(id, MotorDir::Brake, 0)
}

/// Print motor status.
pub fn motor_info() {
    let motors = MOTORS.lock();
    for i in 0..MAX_MOTORS {
        let m = &motors[i];
        if m.initialized {
            let dir = match m.direction {
                MotorDir::Forward  => "FWD",
                MotorDir::Backward => "REV",
                MotorDir::Brake    => "BRK",
                MotorDir::Coast    => "CST",
            };
            azos_drv_sys::kconsoleln!(
                "[MOTOR] Motor {}: pwm_ch={}, dir={}, speed={}%",
                i, m.pwm_ch, dir, m.speed_pct
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test-only accessors.
// ---------------------------------------------------------------------------
//
// `cfg(test)` is crate-wide, so both vanish from the real `azos_robot`
// the kernel links — same technique `crates/core/actuation/src/logger.rs`'s
// `set_serial_for_test` uses. No production caller needs either: the kernel
// installs a gate and a recorder exactly once at boot and never uninstalls
// them, so nothing outside a test ever needs `MOTOR_GATE`/`MOTOR_RECORD`
// put back to `None`.

/// Reset the installed gate to `None`, so a test can observe [`gate_speed`]'s
/// fail-closed default after an earlier test in the same process installed
/// one — `MOTOR_GATE` is a process-wide static with no public "uninstall".
///
/// `cfg(any(test, feature = "test-util"))`, not `cfg(test)` alone: a host
/// test crate that pulls this file in with `#[path]` rather than building
/// `azos_robot` itself under `cargo test` needs the feature half — see
/// `test-util`'s doc in `Cargo.toml`.
#[cfg(any(test, feature = "test-util"))]
pub fn clear_motor_gate_for_test() {
    *MOTOR_GATE.lock() = None;
}

/// Reset the installed recorder to `None`, for the same reason as
/// [`clear_motor_gate_for_test`].
#[cfg(any(test, feature = "test-util"))]
pub fn clear_motor_recorder_for_test() {
    *MOTOR_RECORD.lock() = None;
}
