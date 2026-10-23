# Graded degrade levels

The robot profile lets the brain (the untrusted, AI-driven planner on the other
end of the link) restrict what the machine may do without stopping it
outright. The brain selects one of four ordered levels. Each level caps motor
speed, and the most restrictive one also denies write and actuation
capabilities to user tasks. The kernel decides what each level means; the
brain can raise or lower the level on the wire, but a level can only deny or
slow and never grants anything, and an unrecognised or malformed input resolves
to the most restrictive level.

This is one use of the general kernel: the level state lives in the capability
core, the speed mapping lives in a robot-domain leaf crate, and the enforcement
points are the ones every motor command and every capability use already
crosses.

## Levels

Source: `domains/robot/degrade-policy/src/lib.rs`, `crates/core/ipc/src/cap.rs`

```text
FULL (0)  <  CAUTIOUS (1)  <  SLOW (2)  <  CONTAINED (3)
100 %         70 %             30 %          0 %
```

| Level | Index | Speed ceiling | Meaning |
|---|---:|---:|---|
| `DEGRADE_LEVEL_FULL` | 0 | 100 % | No extra restriction. |
| `DEGRADE_LEVEL_CAUTIOUS` | 1 | 70 % | The brain perceived a mild situational risk. |
| `DEGRADE_LEVEL_SLOW` | 2 | 30 % | The brain perceived a significant situational risk. |
| `DEGRADE_LEVEL_CONTAINED` | 3 | 0 % | Critical hazard, or the brain lost its perception. Stop, plus capability denial. |

Higher is more restrictive. The ceiling is a percentage of the per-robot-type
maximum, not of an absolute speed, so a level never widens a limit that was
already tighter. The ordering is what lets the level compose with the other
ceilings by taking a minimum.

`DEGRADE_LEVEL_MAX` equals `DEGRADE_LEVEL_CONTAINED`. Clamping an out-of-range
index to the maximum is therefore the same operation as failing closed.

## Where the pieces live

Source: `domains/robot/degrade-policy/src/lib.rs`, `crates/core/ipc/src/cap.rs`, `domains/robot/behavior/src/safety.rs`

Three places hold part of the design, and the split is deliberate.

* **Level state and containment** are in `crates/core/ipc/src/cap.rs`:
  `DEGRADE_LEVEL` (one atomic byte), `degrade_level_set`, `degrade_level`, and
  the denial inside `CapTable::get`. The capability core is part of the
  trusted base, and containment has to be enforced where capabilities are
  dereferenced.
* **The level-to-speed mapping** is `level_cap_pct` in the dependency-free
  crate `domains/robot/degrade-policy` (`azos_degrade_policy`). A speed ceiling
  is motor policy, and putting it in the trusted base would grow that base
  without any security gain. The crate has no dependencies, so the capability
  core and the robot domain can both see it without seeing each other.
* **Application of the ceiling** is `motor_envelope` in
  `domains/robot/behavior/src/safety.rs`.

The level numbers are declared in both the capability core and the policy
crate. `domains/robot/behavior/src/safety.rs` sees both and asserts at compile
time that the five constants agree, so a drift is a build error and not a
mis-mapped speed cap.

`level_cap_pct` is a pure `const fn`. Its last match arm maps any level that is
not FULL, CAUTIOUS or SLOW to `DEGRADE_SPEED_CAP_CONTAINED_PCT` (0). The
catch-all arm is the fail-closed property: a brain running newer software than
the kernel cannot unlock speed by sending a level the kernel does not know.

## Wire protocol

Source: `domains/robot/behavior/src/brain_protocol.rs`, `kernel/src/tasks/behavior.rs`

Two packet types set the level. Both handlers exist on the network link and on
the UART bridge in `kernel/src/tasks/behavior.rs`. The network link is a Noise
session; the bridge carries frames with no authentication, and it is down in
both directions under Kconfig `LINK_PROVISIONING_ENFORCED` (default `n`; the
kernel's `vf2` and `k1` cargo features select it). On a bridge that is up,
anyone on the wire can set the level.

**`PKT_SEMANTIC_LEVEL` (0x8B)** carries one byte, the level index.

* A packet with no payload is treated as `DEGRADE_LEVEL_CONTAINED`, not FULL.
* An out-of-range index is clamped by `degrade_level_set` (`level.min(DEGRADE_LEVEL_MAX)`),
  not rejected. Rejecting would leave the previous, looser level in force in
  response to a message sent because something got worse.

**`PKT_DEGRADE` (0x8A)** is the older one-bit form. Its payload byte is a
reason: `DEGRADE_CLEAR` (0) clears, and `DEGRADE_REASON_PERCEPTION_BLIND` (1),
`DEGRADE_REASON_SENSOR_INCOHERENT` (2) and `DEGRADE_REASON_UNMODELLED_HAZARD`
(3) arm. Arming means `degraded_set(true)`, which sets CONTAINED; the reason
only distinguishes the record the flight recorder keeps. A frame with no reason
byte arms containment with `DEGRADE_REASON_MALFORMED` (0xFF); it does not clear.

`degraded_set(bool)` and `degraded_active()` write and read the same atomic as
the graded level, with the invariant that `degraded_active()` is true exactly
when the level is CONTAINED. The one-bit and four-level views cannot disagree.

**Clearing from a mode command.** A `PKT_MODE` command clears containment only
when its mode id is `MODE_ID_ESTOP_RESET` (0xFF), the same reserved value that
clears an emergency stop (`mode_clears_containment`). Any other mode id leaves
the level as it was and, while containment is active, is recorded as a refusal
(`mode_degrade_record`). Unlike the e-stop, whose clear needs the operator's
signed release proof in the same frame, containment is cleared by the bare
reset id: the level is the brain's to set, not the operator's.

**Sticky.** A level holds until the brain sends another. There is no timeout on
the level: it is a standing constraint, not a heartbeat. Loss of the link is a
separate failure, handled by the 500 ms motor-command watchdog in
`domains/robot/safety-core/src/rt_motor.rs`, which safe-stops at any level.

**Global.** The level is one system-wide value, set at packet ingest and read
at each enforcement point. It is coarse by design. Per-task or self-decaying
levels are not built.

## Enforcement

Source: `domains/robot/behavior/src/safety.rs`, `domains/robot/safety-core/src/actuation.rs`, `domains/robot/robot/src/motor.rs`, `crates/core/ipc/src/cap.rs`

Two mechanisms apply a level, and neither replaces the other.

### Speed ceiling at the motor write

`motor_envelope(speed_l, speed_r)` in `domains/robot/behavior/src/safety.rs`
returns the permitted pair. In order: an active emergency stop returns
`(0, 0)`; the per-robot-type cap applies (`SAFETY_WHEELED_MAX_SPEED_PCT` for
wheeled and Ackermann robots; other types pass through at 100 and have their own
envelope elsewhere); a low-confidence command is capped at
`SAFETY_LOW_CONFIDENCE_CAP_PCT`; finally the degrade ceiling,
`level_cap_pct(degrade_level())`, is applied. Each step is a `min`, so the
tightest ceiling wins and clearing the tighter one restores the wider. Using
`max`, or letting the last step overwrite, would let the looser constraint
through. The pair is then clamped to plus or minus the resulting cap.
The composed envelope is described in [motor-envelope.md](motor-envelope.md).

The envelope is applied by `rt_motor_task` and, more importantly, by the
actuation gate installed into the motor layer at boot
(`domains/robot/safety-core/src/actuation.rs`, `set_motor_gate` in
`domains/robot/robot/src/motor.rs`). `motor_set` is where the duty is written,
so every caller crosses the gate: the control task, a ring-3 syscall, a
driver server. Until the kernel installs a gate, the gate answers 0.

### Capability denial at CONTAINED

`CapTable::get` returns `CapError::Contained` for a request that needs
`CapPerms::WRITE` while `degraded_active()` is true. The check runs after the
forgery checks (null, slot, generation, kind, permissions, revocation), so a
stale, forged or under-permissioned capability still fails with its own error
first and containment never changes the outcome of those checks. Read access
stays live: a contained task can still observe. `CapError::Contained` is a
distinct error so callers and tests can tell containment from a permission
bug. Nothing is checked when not contained beyond one atomic load.

The same predicate is consulted on paths that do not resolve through `get`:
the kernel-hosted endpoint checks (`table_holds_host_right`,
`table_holds_host_badge_right` in `crates/core/ipc/src/endpoint.rs`), the
untyped write paths (`untyped_write_contained` in
`crates/core/syscall/src/handlers.rs`), I/O ring submission
(`crates/core/syscall/src/ioring_ops.rs`) and the host-interface caller
(`Caller::allows` in `crates/core/syscall/src/khost.rs`).

A small set of operations is deliberately resolved without the containment step:
releasing an object the caller holds (`get_uncontained`, as `io_ring_destroy_cap`
does), and commanding a wheel (`Caller::holds` in
`crates/core/syscall/src/khost.rs`, used by the `Motor` interface's per-wheel
ops; the I/O ring's `OP_MOTOR_SPEED` likewise asks no containment). Destroying stays
live the way closing a socket does. Wheel commands are not refused one level up
because the motor layer applies its own halt rule: while an emergency stop is
latched or containment is active (`actuation_halt`), `motor_set_reporting`
admits brake and coast and refuses forward and backward.

### Why both are needed

The kernel's own control loop does not go through `CapTable::get`. Capability
denial alone would contain user tasks while the in-kernel loop kept driving.
The speed ceiling alone would slow the wheels while a user task kept a live
write capability to everything else it can reach. A change that removes one
because the other covers it is wrong.

## Constrain-only

Source: `crates/core/ipc/src/cap.rs`

A level can only deny or slow. It grants nothing. A brain that is wrong,
compromised or hallucinating can over-contain, or can return the level to FULL,
which is the unrestricted baseline; it cannot widen access beyond that baseline
through this path. The emergency stop and
the in-kernel envelope remain the authority on physical motion regardless of
the brain.

## Flight recorder

Source: `crates/core/actuation/src/logger.rs`, `kernel/src/tasks/behavior.rs`

Level changes are safety events and are recorded.

* `SAFETY_DEGRADE` records `PKT_DEGRADE` arm and clear, and mode-command
  clears and refusals.
* `SAFETY_SEMANTIC_LEVEL` records a `PKT_SEMANTIC_LEVEL` change. The action
  field is the level that took effect (after clamping), the detail is the level
  it replaced. A repeat of the level already in force writes nothing.
* `SAFETY_SEMANTIC_MALFORMED` records a payload-less `PKT_SEMANTIC_LEVEL`
  that was treated as CONTAINED. It is a separate code from the previous one on
  purpose: it says the kernel could not tell what was asked, which is a link
  fault or a hostile sender and not a decision.
* `SAFETY_UNKNOWN_PKT` records a packet type the build does not act on, so a
  brain that sends a level to a kernel without this support does not fail open
  in silence.

The decision of what to record is `semantic_level_record` in
`crates/core/actuation/src/logger.rs`, a pure function shared by both receive paths.

## The same vocabulary elsewhere

Source: `crates/core/topology/src/types.rs`, `crates/core/actuation/src/effect_gate.rs`, `crates/core/ipc/src/endpoint.rs`, `crates/core/energy/src/thermal.rs`

The four levels are also the vocabulary of other restrictions. These are
separate from the brain-set global level above: they do not write
`degrade_level_set`, and the global level does not read them.

**Class envelope and provenance meet.** A scheduling class in the signed
topology declares an `envelope` (`Envelope::Full`, `Cautious`, `Slow`,
`Contained` in `crates/core/topology/src/types.rs`) and a principal kind. The
kernel keeps, per task, a label of the principal kinds whose data the task is
serving or has read (`label` in `crates/core/ipc/src/endpoint.rs`), and per
kind the most restrictive envelope any class declares for it. When a ring-3
task issues a motor effect through the `Motor` interface (not the I/O ring's
`OP_MOTOR_SPEED`, which bypasses the effect gate), the effect gate (`issue` in
`crates/core/actuation/src/effect_gate.rs`) asks `provenance_of(tid)` for the
label and the meet of its envelopes, the most restrictive one, and applies that
level before anything else. At CAUTIOUS or SLOW, a motor effect whose duty
percent is above `ENVELOPE_DUTY_CAP_PCT[level]` (`[100, 70, 30, 0]`, the same
numbers as the policy crate, kept as literals because the gate links no robot
domain) is refused; the envelope-row kinds (delete, egress, config, OTA,
real-time time) are held to their own per-level ceilings, and the SoC kinds have
no magnitude and pass. At CONTAINED every non-motor effect kind is refused, and a motor effect passes
only with a duty of 0 (the cap at that level). A refusal is a decision record
(`Rule::ProvenanceMeet`) with a receipt, and a stop is never refused. The
effect that is let through still crosses the motor-layer gate and the global
level. The effect gate is installed when the build enables write-ahead receipts
(Kconfig `EFFECT_WRITE_AHEAD`); the provenance meet additionally needs IPC
labels (Kconfig `IPC_LABELS`), and without them no effect is held to a label.

The effect: data the brain touched is held to the brain's envelope even when a
more trusted planner issues the effect, because the planner's label carries
the brain's kind.

**Thermal and battery.** The thermal policy maps its situations to levels
(`LEVEL_CAUTIOUS`, `LEVEL_SLOW`, `LEVEL_CONTAINED` in
`crates/core/energy/src/thermal.rs`), and the energy policy accepts a battery
report carrying a level from the topology's `[degrade.NAME]` rows
(`report_battery` in `crates/core/energy/src/policy.rs`). Each keeps its own
level and records its changes.

## Limitations

Source: `domains/robot/degrade-policy/src/lib.rs`, `crates/core/ipc/src/cap.rs`

* The 70 % and 30 % ceilings are chosen values. No stopping-distance model and
  no measurement supports them, and the kernel does not know a robot's mass,
  brake authority or sensor range. What the design fixes is the shape: four
  ordered levels, each strictly more restrictive, unknown input at the tightest.
  A deployment must not treat the two interior numbers as validated safe
  speeds. Replacing them needs a per-robot-type stopping-distance model or a
  measured stopping distance validated against one.
* The level is global and sticky. There is no per-task level and no automatic
  decay.
* Capability containment covers write access through user-task capabilities. It
  does not restrict the in-kernel control loop, which is governed by the
  envelope, the emergency stop and the watchdog.
