# Motor output envelope

The robot profile treats the brain as untrusted: a planner, possibly driven by
a language or vision model, that sends motor commands over a link. The kernel
decides what reaches the wheels. This note describes the gate that sits
between any command and the PWM hardware, the three limits it composes, and
the argument for where it sits.

## What the envelope is

Source: `domains/robot/behavior/src/safety.rs`

`motor_envelope(speed_l, speed_r) -> (i32, i32)` takes a requested pair of
speed percentages (plus or minus 100) and returns the pair the machine may
apply. It is O(1): a few branches, two `min` steps and two clamps, with no
allocation and no I/O. The steps, in order:

1. **Emergency stop.** If the latch is set (`estop_is_active`, in
   `crates/core/actuation/src/estop.rs`), return `(0, 0)`. This overrides
   everything.
2. **Robot-type cap.** For wheeled and Ackermann robots the cap is
   `SAFETY_WHEELED_MAX_SPEED_PCT` (80). Other robot types start at 100 here: their
   per-type limits are handled on their own paths (the flight loop in
   `domains/robot/safety-core/src/flight_ctrl.rs` reads the same e-stop latch
   every tick). The robot type is a build-time choice
   (`ROBOT_TYPE_ID`, Kconfig `config/domains/Kconfig.robot`).
3. **Confidence cap.** If the most recent brain command was marked
   low-confidence, the cap becomes `min(cap, SAFETY_LOW_CONFIDENCE_CAP_PCT)` (40).
4. **Degrade-level cap.** The cap becomes `min(cap, level_cap_pct(degrade_level()))`
   (see [degrade-levels.md](degrade-levels.md)).
5. Clamp both channels to plus or minus the final cap.

Every limit is a `min`, so the composition is monotone: adding a constraint can
only tighten the result, and the tightest one wins. Clearing the tightest
restores the next. Applying a looser limit after a tighter one, or letting the
last step overwrite the cap, would let the looser constraint through.

## Where it sits

Source: `domains/robot/robot/src/motor.rs`, `domains/robot/safety-core/src/actuation.rs`, `domains/robot/safety-core/src/rt_motor.rs`

The envelope has to be at the one place every command becomes a duty write,
not at the places commands come in. Gating at the ingest sites (the network
link, the UART bridge) is bypass-prone: a new source, or a path that was missed,
would reach the motors ungated.

The control task (`rt_motor_task`) applies `motor_envelope` to the command it
reads before the PID and PWM stages, but it is only one caller of `motor_set`.
A ring-3 program holding a motor capability reaches the motors through
syscalls, and a driver server through its own path. What makes the envelope
unavoidable is the gate inside the motor layer:

* `set_motor_gate` in `domains/robot/robot/src/motor.rs` installs a function
  `(id, speed_pct) -> speed_pct` that `motor_set_reporting` applies to every
  duty before it is written.
* `azos_safety_core::actuation::install` installs `actuation_gate`, which returns
  0 for an active e-stop and otherwise returns the magnitude `motor_envelope`
  permits.
* With no gate installed the answer is 0, not the requested speed. A boot that
  skipped the install, or an early panic path, then stops the motors instead of
  driving them at whatever was asked. The loader, the boot launcher and the
  driver supervisor refuse to start ring-3 code while
  `azos_actuation::gate::gate_installed` is false, which folds in
  `motor_gate_installed` through `set_domain_gate_check`.
* The raw device interfaces cannot reach a wheel past the gate: a PWM channel
  or GPIO pin bound to a motor is refused by the kernel-hosted PWM and GPIO
  interfaces (`crates/core/syscall/src/devices.rs`) and the I/O ring
  (`pwm_channel_is_motor_bound`, `gpio_pin_is_motor_bound` in
  `crates/core/syscall/src/handlers.rs`).
* A second query, `set_motor_halt` / `actuation_halt`, answers true for a
  latched e-stop or full containment. While it does, the motor layer admits
  brake and coast and refuses forward and backward, so direction pins are not
  changed on a halted machine.

The control task reports the envelope's interventions on the edges: one
console line and one `SAFETY_ENVELOPE_REFUSED` flight-recorder record when a
command first exceeds the envelope, one when it is within bounds again. A
clamp that holds for a minute is one event.

Every change of a wheel's applied (direction, duty), after the gate, is one
actuator-command record (`set_motor_recorder`, `record_motor_change` in
`domains/robot/safety-core/src/actuation.rs`), at most four per wheel per
second; the value a window suppressed is written at the next window's first
change. With Kconfig `MOTOR_COMMANDER_EXIT_STOP` (default `y` with the robot
domain) a ring-3 task that leaves a wheel at a non-zero duty through the
`Motor` interface and then exits has that wheel stopped (coast, duty 0) and a
durable `SAFETY_ESTOP` record written that does not latch
(`crates/core/syscall/src/motor_commander.rs`).

## Confidence-aware limit

Source: `domains/robot/behavior/src/brain_protocol.rs`, `domains/robot/behavior/src/safety.rs`, `kernel/src/tasks/behavior.rs`

Commands are not equally trustworthy. A scripted or planned step is more
reliable than a single reactive action taken from one camera frame. The brain
marks a command with `FLAG_LOW_CONFIDENCE` (0x04, a bit of
`ActuatorCmd.flags`; `ActuatorCmd::is_low_confidence`). When the kernel
receives an actuator command it records the flag with `cmd_set_low_confidence`,
and `motor_envelope` reads it through `cmd_low_confidence`. An uncertain action
is then physically bounded tighter (`SAFETY_LOW_CONFIDENCE_CAP_PCT`) than a
deterministic one.

The signal can only tighten the envelope. The brain cannot use it to loosen
anything.

## Why a runtime gate

Source: `domains/robot/behavior/src/safety.rs`

The envelope follows the Simplex pattern: a small, simple gate that does not
depend on the complex, untrusted component in front of it, and that holds
whatever the component asks for. The gate is a runtime-assurance mechanism. It
is bounded by construction and is not a formally verified component, and the
design does not claim it is.

It is not redundant with the sensor-reactive layer. The emergency-stop layer
`safety_check` (L0 of the behavior arbiter) asks whether the world is unsafe
right now (obstacle, tilt, battery, temperature). The envelope asks whether this
command, in itself, is inside the actuator's allowed range. They are
orthogonal and both are needed. The envelope is also where the per-type speed
constant (`SAFETY_WHEELED_MAX_SPEED_PCT`, the only one) is enforced at the
output.

## Limitations

Source: `domains/robot/behavior/src/safety.rs`, `domains/robot/behavior/src/brain_protocol.rs`

* The speed unit is a duty percentage per wheel. The envelope does not know
  the robot's real velocity, mass or stopping distance.
* The confidence input is binary and coarse. The flag tracks the most recent
  actuator command, not a tag carried through the arbiter, and a low-confidence
  command keeps the cap low until a normal command clears it. That is the
  conservative direction, and the motor-command watchdog (500 ms) safe-stops on
  link loss regardless. A graded confidence needs a confidence byte on the
  command.
* No acceleration or jerk limit (it needs the previous output as state), and no
  check of the commanded motion against a geofence.
* Types other than wheeled and Ackermann get no per-type magnitude cap in this
  function; their limits live on their own paths.
* The per-type cap is a compile-time constant, not per-deployment
  configuration.
