# Energy-aware scheduling

Energy is decided in three places that the scheduling policy does not own:
where a woken task runs, how fast a CPU runs, and how deep an idle CPU
sleeps. This note describes the mechanisms, the invariants that keep them from
touching real-time and safety guarantees, and the current limits. All of it is behind Kconfig `ENERGY` (cargo feature `energy`);
without it the kernel runs the behaviour it had before these seams existed.

## Principle

Source: `crates/core/energy/src/lib.rs`, `crates/core/energy/src/seams.rs`.

A scheduling policy answers "which task runs next on this CPU". Energy
awareness is not another policy. It is a set of seams the scheduler consults,
combinable with any policy:

- **Placement**: which CPU a woken task is enqueued on.
- **Governor**: which operating point (OPP) a performance domain runs at.
- **Idle governor**: which idle state an idle CPU enters.

The seams are enum-dispatched (no `dyn`), because the variant set is closed
and known at build time. The `azos_energy` crate is pure `no_std` data and
integer arithmetic. The kernel half (gathering inputs, applying answers) is `crates/core/sched/src/energy.rs`.

The default selection (the default `Seams` constant in `seams.rs`) is
`Placement::Legacy`, `Governor::Fixed` (no request, the clock stays where the platform left it) and
`IdleGovernor::WfiOnly`. `Seams::select` chooses anything else only when an
energy model is present **and** the signed topology's mode is `balanced` or
`endurance`.

## Energy model

Source: `crates/core/energy/src/model.rs`, `crates/core/energy/src/dt.rs`,
`crates/core/topology/src/parser.rs` (`parse_energy`),
`kernel/src/boot/energy.rs` (`install_energy`).

The model is data, never code. A **performance domain** is a set of CPUs that
share a clock. Each domain lists:

- OPPs `{freq_khz, capacity, power_mw}`, slowest first. Capacity is on
  `CAPACITY_SCALE` (1024 is the fastest CPU of the machine at its fastest
  OPP, so domains compare directly). `power_mw` is the power of one CPU
  running flat out at that OPP.
- Idle states `{name, exit_latency_us, target_residency_us, power_mw}`,
  shallowest first.
- Optionally `wcet_ref_khz`, the clock at which the safety path's worst-case
  execution times were established (see invariant I6).

Limits: `MAX_DOMAINS` 4, `MAX_OPPS` 16 per domain, `MAX_IDLE_STATES` 4 per
domain, 32 CPUs.

Sources, in order (`resolve`):

1. The signed topology's `SCHED.TOML` sections `[energy]` (key `mode`) and
   `[energy.domain.NAME]` (keys `cpus`, `wcet_ref_khz`, `opps`, `idle`).
2. The device tree: `operating-points-v2` and `idle-states`, extracted by
   `azos_dtb::dtb_energy` and turned into a model by `azos_energy::dt`.
3. None. Every seam then keeps its default behaviour.

`EnergyModel::validate` rejects a model that does not describe the machine:
every CPU must be in exactly one domain, frequencies strictly increasing,
capacities in `1..=1024` and non-decreasing, power non-zero and strictly
increasing, exit latencies non-decreasing, and some domain's fastest OPP must
have capacity exactly 1024. A refused model becomes "none" and the fault is
logged. A model declared by the topology that fails validation does not fall
through to the device tree: the signed file named a model, and substituting
one its signer never saw would be a decision nobody made. On x86_64 there
is no device-tree `idle-states`; a domain the topology declares without an
`idle` table gets its idle list from the `mwait` ladder in
`crates/core/arch-x86_64/src/cpu/idle.rs`, and a declared list is checked
against it.

## Utilisation tracking

Source: `crates/core/energy/src/util.rs`, `crates/core/sched/src/energy.rs`
(`on_switch`, `on_tick`, `task_util`, `cpu_util`), Kconfig `ENERGY_UTIL_*`.

`UtilTracker` keeps a per-task and a per-CPU busy fraction on `SCALE` (1024
means running all the time). Two variants, chosen by Kconfig and both O(1) per
update whatever the gap since the last one:

- **Window** (default): busy time per fixed window; the signal is the larger
  of the last closed window and the mean of the last four.
- **PELT-like**: a geometric average with a half-life of 32 periods, in Q32
  fixed point, with a 32-entry lookup table for `y^n`.

The signals are updated at dispatch and switch-out (including the direct IPC
hand-off, which bypasses `do_schedule`) and at the timer tick. A wake-up
updates nothing; a reader that needs the value now (placement) asks for
`task_util`, which projects the stored state to the present without writing.
Each task slot is written only by the hart switching it in or out, the same
ownership rule as `Task::total_runtime`. Idle tasks are not tracked.

The signal is a busy fraction at whatever OPP the CPU ran at, not a
frequency-invariant value; consumers scale it by the capacity of that OPP
(`invariant_util`).

## Frequency governor

Source: `crates/core/energy/src/governor.rs`, `crates/core/energy/src/seams.rs`
(`Governor`), `crates/core/sched/src/energy.rs` (`gov_maybe`).

`Governor::DeadlineFloor` computes three floors per domain and takes the
maximum:

- **schedutil** (`schedutil_opp`): the lowest OPP whose capacity covers the
  busiest CPU's demand plus a headroom (25 % by default).
- **deadline floor** (`deadline_floor_opp`): the lowest OPP whose capacity
  covers the real-time density admitted on the domain's most loaded hart,
  plus a 20 % margin. The input is `rt::ADMITTED_PPM` in
  `crates/core/sched/src/rt.rs`, a lock-free copy of each hart's admitted
  density maintained by the real-time admission ledger. The density `Σ q/d`
  is used rather than the utilisation `Σ q/t`; it is never smaller, so the
  floor errs high. A reservation's runtime is taken as measured at the
  domain's fastest OPP; a runtime measured at a slower clock would only lower
  the floor.
- **safety floor** (`safety_floor_opp`): the lowest OPP at or above the
  domain's `wcet_ref_khz`. With none declared, or one above every OPP, it is
  the fastest OPP: a model that does not say at which clock the safety bounds
  hold never lets a governor lower the clock.

`Governor::Schedutil` (schedutil and safety floor only) exists as the building
block; `Seams::select` never chooses it and the policy refuses it, because it
cannot honour the deadline floor.

Evaluation is per domain, rate-limited (4 ms by default), from any CPU's tick
and from idle entry. An idle CPU is tick-less, so a domain whose CPUs are all
idle is re-evaluated by a hart that still runs, from utilisation projected
forward in time. One hart wins the compare-and-swap that claims a domain's
evaluation interval.

**The decision is recorded.** The scheduler stores the chosen OPP per domain
and counts evaluations, changes, and which floor decided (`gov_stats`); it
does not itself change a clock. Applying an OPP goes through the
`OppActuator` trait (`crates/core/energy/src/opp.rs`): a platform implements
it for its clock interface, `NoActuator` stands for a platform that cannot
change its clock, and `Dvfs` keeps the per-domain current-OPP bookkeeping.
The governor decision is recorded and counted; no actuator is wired to it
(see Thermal below for the other user of the trait).

## Idle governor

Source: `crates/core/energy/src/idle.rs`, `crates/core/sched/src/energy.rs`
(`idle_wait`), `crates/core/arch-api/src/lib.rs` (`Cpu::cpu_idle`),
`kernel/src/boot/energy.rs` (`install_idle_states`).

`IdleGovernor::Teo` is a timer-events-oriented governor in the style of
Linux's `teo`. The kernel idle task goes through `idle_wait`
(`kernel/src/tasks/system.rs`).

- The sleep bound is the earlier of the nearest timer sleeper
  (`nearest_timer_deadline`) and what the hart has already programmed
  (`timebase::programmed`, which includes the hart 0 watchdog keepalive and
  the real-time enforcement arms).
- The candidate is the deepest state whose target residency fits the bound
  and whose exit latency fits the real-time slack (`rt::rt_slack`, the time to
  the nearest deadline a reservation on that CPU can have).
- Per-CPU history of wake-ups, binned by state, can only move the choice
  shallower: if wake-ups earlier than the timer bound dominate below the
  candidate, the governor steps back. History therefore cannot break the
  real-time slack rule.
- The state is entered through the one arch idle seam, `Cpu::cpu_idle(depth)`,
  which returns the microseconds actually slept; that is what the history
  learns from. Depth 0 is `wfi`. aarch64 enters retention or standby states
  with PSCI `CPU_SUSPEND`, riscv64 with SBI HSM `hart_suspend`, and a state an
  ISA cannot enter is entered as the deepest one below it, else as the
  shallow wait. x86_64 enters its states by `mwait` hint from the ladder,
  with the depth capped at the first state the model understates.
  Non-retentive (power-down) states are available with Kconfig
  `CPU_IDLE_POWERDOWN`, which adds a resume entry.

The idle path moves no timer, so the hart 0 watchdog keepalive is never
delayed.

## Energy-aware placement

Source: `crates/core/energy/src/model.rs` (`eas_pick`, `is_asymmetric`),
`crates/core/sched/src/energy.rs` (`eas_place`),
`crates/core/sched/src/scheduler/wake.rs` (`wake_target_cpu`,
`eas_wake_cpu`), Kconfig `SCHED_EAS`.

Placement is not a separate enum variant. `Placement` has one variant,
`Legacy`, and energy-aware placement is a pre-pass inside it: when
`SCHED_EAS` is set, a model is present, the mode is not `performance` and the
model is asymmetric (domains whose fastest OPPs differ), `wake_target_cpu`
asks `eas_place` first and falls back to `find_best_cpu` when it answers
`None`.

The pass applies only to fair-class tasks that are not pinned. Real-time and
deadline tasks, pinned tasks, isolated CPUs and CPUs holding real-time state
are never chosen or judged; they keep the load-based placement and its
liveness rule.

`EnergyModel::eas_pick` is pure arithmetic:

- Utilisation is converted to capacity-invariant form.
- If some candidate CPU is full (utilisation at or above 80 % of the capacity
  of its domain's fastest OPP) or the task fits none, the answer is
  `Overutilised` and the load-based placement decides.
- Otherwise, per domain, two CPUs are tried: the candidate with the most
  spare capacity that the task fits, and the CPU the task last ran on. A
  domain's cost is the power of the OPP it would need (lowest OPP covering its
  busiest CPU plus the schedutil headroom) times the work it holds divided by
  that OPP's capacity.
- The task leaves its last CPU only for a saving of more than 1/16 of what it
  costs there, because a move costs a cold cache the model does not see.

## Timer slack and coalescing

Source: `crates/core/sched/src/sc.rs` (`timer_slack_us`),
`crates/core/sched/src/timer_heap.rs` (`coalesce_target`),
`crates/core/abi/src/syscall_nr.rs` (`SCHEDCTL_HINT_QOS`, `QOS_*`),
Kconfig `QOS_TIMER_TOLERANCE`, `QOS_TIMER_TOLERANCE_ROWS_ONLY`, `QOS_SLACK_*_US`.

Fewer wake-ups save energy as surely as lower clocks. With
`QOS_TIMER_TOLERANCE` (it needs the timer heap, `SCHED_TIMER_HEAP`), a timer
armed by a fair-class task may fire up to a slack **after** its deadline, never
before. The slack comes from the task's QoS hint (set with
`SCHEDCTL_HINT_QOS`: default, latency, throughput, background), through one
tier value per hint. The heap arms such a timer at a wake-up that is already
scheduled inside the window, so two sleepers share one interrupt and one
stretch of a deep idle state. The idle governor reads the same heap through
`nearest_timer_deadline`, so it sees the coalesced schedule.

- Only the fair class has slack. Stop, deadline and real-time tasks get none,
  whatever their hint: `timer_slack_us` tests the class before it looks at the
  mode or the tiers.
- The default tiers for the default and latency hints are 0 (exact). Only a
  task that declared itself throughput or background work moves, unless a
  product raises the tiers.
- With `QOS_TIMER_TOLERANCE_ROWS_ONLY` (the default on robot, industrial and
  automotive presets), a task gets slack only if its signed topology row says
  `timer_slack = true`; every other task, kernel tasks included, keeps exact
  deadlines.

## Run-time policy

Source: `crates/core/energy/src/policy.rs`, `crates/core/syscall/src/power.rs`,
`crates/core/abi/src/power.rs` (`POWER_OP_POLICY_*`), `userspace/services/power`.

The seams are chosen at boot. Within them, user space owns the policy and the
kernel enforces limits. The `power` endpoint offers limit-checked setters: the
governor, the OPP range of a domain, the schedutil headroom, the evaluation
rate limit, an idle-depth limit, a per-domain power cap, parking of CPUs, and
a mapping from QoS class (`QOS_DEFAULT`, `QOS_LATENCY`, `QOS_THROUGHPUT`,
`QOS_BACKGROUND`) to the domains it may use. A setter outside its limits is
refused and the refusal is recorded in a small ring with a counter.
Examples of what is refused: a range or cap that would put a domain below the
admitted real-time floor or the WCET reference OPP, parking CPU 0 or a CPU
with admitted real-time work, or keeping the default and latency classes off
the fastest domain. Limits are re-applied at every governor evaluation
(`Policy::clamp`), because a cap that was legal when set can become illegal as
reservations are admitted later.

**Battery reserve.** If the topology declares `[degrade.NAME]` rows, the power
service reports the charge and the degrade level it holds. At or below
`ENERGY_BATTERY_RESERVE_PCT` the kernel holds every domain at its lowest legal
OPP and runs the deadline-floor governor, whatever the policy asks; the floors
still win. A report older than `ENERGY_BATTERY_REPORT_TIMEOUT_MS` holds the
reserve too, because a stale charge cannot be vouched for.

## Thermal

Source: `crates/core/energy/src/thermal.rs`, `crates/drivers/thermal/`,
Kconfig `THERMAL`.

The thermal framework is policy plus platform adapters: zones and trips from
the device tree's `thermal-zones`, step-wise cooling by capping a domain's
OPP, and a cap that never goes below the deadline and safety floors. What the
clock cannot do raises the degrade level, and a critical trip requests an
orderly shutdown. The runtime entry point is `Runtime::tick` in
`crates/drivers/thermal/src/runtime.rs`, generic over a sensor bank and an
`OppActuator`. The kernel's `thermal` task (`kernel/src/boot/thermal.rs`) builds
the runtime from the device tree on a board that has a sensor and clock pair
(the VisionFive 2, a Raspberry Pi) and ticks it at the zones' polling delay,
with the governor's recorded OPP and the admitted real-time density as inputs;
that tick is where a governor decision first reaches a clock. A board with no
pair (QEMU, x86_64) builds no zone: no sensor is read and no clock is touched.

## Invariants

Source: `crates/core/energy/src/governor.rs`, `crates/core/energy/src/idle.rs`,
`crates/core/energy/src/policy.rs`.

- **I1** No energy decision lowers a domain below the admitted real-time
  reservations: the governor answers `max(schedutil, deadline floor, safety
  floor)`, and the policy and thermal caps are clamped above the floors.
- **I2** Energy placement never moves a pinned task and never handles real-time
  or deadline tasks.
- **I3** The idle governor never picks a state whose exit latency exceeds the
  slack to the nearest real-time deadline armed on that CPU. A live counter of
  violations is kept and must stay zero.
- **I4** With no model, or in `performance` mode, behaviour is the default
  one: the seams are `Legacy`, `Fixed` and `WfiOnly`.
- **I5** The energy mode comes from the signed topology only. No Kconfig symbol
  and no configuration key sets it.
- **I6** No governor selects an OPP below the one at which the safety path's
  WCET bounds were established, and nothing here delays the hart 0 watchdog
  keepalive.

## Non-goals

Source: `config/arch/Kconfig.platform` (`SYSTEM_SUSPEND`),
`crates/core/energy/src/governor.rs`.

- Whole-machine suspend is not a scheduler seam. It exists separately behind
  Kconfig `SYSTEM_SUSPEND`, which is refused on robot, industrial and
  automotive images because their safety loop must keep running.
- A separate "energy scheduler" replacing the scheduling policies.
- Any energy decision on the safety path (emergency stop, actuation gate,
  watchdog).

## Current limits

Source: `crates/core/sched/src/energy.rs`, `crates/core/energy/src/seams.rs`,
`crates/core/energy/src/opp.rs`, `config/kernel/Kconfig.energy` (`THERMAL`).

- The governor decision is recorded and counted; no actuator applies it to a
  clock.
- There is no per-task performance floor or ceiling (a `uclamp`-like hint).
  The per-task inputs are the QoS hint, which maps to a set of domains and to a
  timer-slack tier, and the topology row's `timer_slack` opt-in.
- `balanced` and `endurance` select the same seams.
- The utilisation signal is not frequency-invariant, so the governor's demand
  estimate is `util x capacity(current OPP)` and a saturated CPU climbs one
  OPP step per evaluation.
- Capacity is assumed linear in frequency. Memory-bound work does not scale
  that way; the deadline floor's margin is a flat percentage, not a per-domain
  figure.
- The model holds at most four performance domains.
