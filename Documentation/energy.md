# Energy and power

This document describes how the kernel decides where tasks run, how fast CPUs run and how deeply they sleep, and how the machine suspends, hot-plugs CPUs and powers devices down. It covers the idle seam of each ISA, the idle governor, the frequency governor and its floors, thermal zones, the run-time policy a ring-3 service may set within kernel limits, runtime device power management with wakelocks, CPU hotplug, system suspend, and the battery reserve. Related documents: [scheduler.md](scheduler.md) for placement, balancing and the real-time classes, [time.md](time.md) for the boot clock that suspend feeds.

## Layers

| Layer | Crate or file | Role |
|---|---|---|
| decision logic | `crates/core/energy` | model, utilisation trackers, governors, idle choice, thermal policy, run-time policy; pure data and integer arithmetic |
| kernel side | `crates/core/sched/src/energy.rs` | utilisation signals on the dispatch path, the installed model, governor evaluation, idle wait, policy setters |
| boot | `kernel/src/boot/energy.rs` | resolves the model (on a Pi, from the mailbox's clock range), installs idle states, hands the battery rows to the policy, installs the suspend platform |
| architecture | `crates/core/arch-riscv64`, `crates/core/arch-aarch64`, `crates/core/arch-x86_64` | `Cpu::cpu_idle(depth)`: enters an idle state |
| thermal runtime | `crates/drivers/thermal` | sensors and clock actuation behind the thermal policy |
| thermal task | `kernel/src/boot/thermal.rs` | builds the board's runtime at boot and ticks it from the `thermal` task |
| device and system PM | `crates/core/devif/src/power.rs`, `crates/drivers/power` | `Power` and `DevicePower` interfaces; the suspend sequence |
| policy | `userspace/services/power` | `POWER.ELF`, the ring-3 policy server |

Kconfig `ENERGY` compiles in utilisation tracking, the model and the governors. Without it the three seams (placement, frequency governor, idle governor) are `const`s with one behaviour each and fold to the code they replaced: legacy wake placement, no frequency request, `wfi` in the idle task. `THERMAL`, `SCHED_EAS`, `SYSTEM_SUSPEND` and `CPU_IDLE_POWERDOWN` (riscv64 and aarch64 only) depend on it; `CPU_HOTPLUG` is independent.

Source: `config/kernel/Kconfig.energy` (`ENERGY`, `THERMAL`, `SCHED_EAS`), `config/arch/Kconfig.platform` (`SYSTEM_SUSPEND`, `CPU_HOTPLUG`, `CPU_IDLE_POWERDOWN`), `crates/core/energy/src/lib.rs`, `crates/core/energy/src/seams.rs`.

## Energy model

`EnergyModel` describes performance domains: sets of CPUs that share a clock. A model holds up to `MAX_DOMAINS` (4) domains. Per domain:

* up to `MAX_OPPS` (16) operating points `Opp { freq_khz, capacity, power_mw }`, slowest first; `capacity` is on `CAPACITY_SCALE` (1024 is the fastest CPU of the machine at its fastest point);
* up to `MAX_IDLE_STATES` (4) idle states `IdleState { name, exit_latency_us, target_residency_us, power_mw, loses_context }`, shallowest first; `loses_context` marks a power-down state, set at boot from what the ISA will enter (`PerfDomain::mark_context_loss`), not read from the device tree;
* `wcet_ref_khz`: the clock at which the safety path's execution-time bounds were established (0 = not declared, which makes the fastest point the floor);
* `cpus`: a mask of at most `MAX_MODEL_CPUS` (32) CPUs.

`energy::resolve` picks the source, in order: the signed topology's `[energy.domain.NAME]` sections; the device tree's `operating-points-v2` and `idle-states` (`azos_energy::dt`); on x86_64, the core types the CPUs report through CPUID (`EnergyModel::from_core_reports`, resolved once the secondary CPUs have started and recorded their type, `install_energy_after_smp`; a started CPU that recorded none refuses the model); on a Raspberry Pi, the firmware's ARM clock range (below); none. A model that fails `EnergyModel::validate` is refused and reported, and the machine runs with none. A topology or device-tree model that fails does not fall through to the next source. A device-tree idle state whose `min-residency-us` is below its exit latency has its residency raised to the latency, with a warning.

**Raspberry Pi: the OPP table from the firmware's clock range.** The Pi 5's device tree has no `operating-points-v2` (Linux builds its cpufreq table at run time from the firmware's minimum and maximum), so with no topology or device-tree model the energy step builds domain 0 from the ARM clock the VideoCore reports (`GET_CLOCK_RATE`, `GET_MIN_CLOCK_RATE`, `GET_MAX_CLOCK_RATE`, `RpiFirmware::probe_clock`). It runs before the model is resolved, so the energy step is also where the mailbox is enabled and the clock probed; the thermal runtime, built after it, reads that probe. `EnergyModel::from_clock_range` makes one domain holding every CPU, with an OPP at the minimum, one every 100 MHz above it (`azos_thermal::rpi::MODEL_STEP_KHZ`) and one at the maximum, which is always the last (the Pi 5's 1.5 to 2.4 GHz gives ten); a range wider than 16 OPPs takes the smallest whole multiple of the step that fits. Capacity is linear in the clock. The boot log lists every OPP of the table (`[ENERGY]   opp N: ...`).

* **The steps are not probed.** The firmware documents a range and no list of rates (it accepts any rate in it and its PLL rounds), and finding the accepted ones would mean moving the live clock at boot, under cores that are starting. 100 MHz is a choice, not a probed value (the fake PLL of `tests/host/thermal-tests` models it). The actuator is the run-time check: `set_opp` verifies the rate the firmware settled on, a rate rounded under the request is put back and refused, and the thermal runtime raises the degrade level instead.
* **The power figures are a placeholder, unmeasured**: `FIRMWARE_PLACEHOLDER_MAX_POWER_MW` (2000 mW per CPU) at the top and cubic in the clock below it, raised to stay strictly increasing (the validation refuses a zero or a non-increasing power). They order the OPPs and nothing else; the model has one domain, so the energy-aware placement has nothing to compare, and the frequency governor reads capacity, not power. Measured figures are the signed topology's `[energy.domain.NAME]` row, which ranks first and replaces the table whole (its OPPs should lie inside the firmware's range: `set_opp` refuses a rate outside it).
* **No range, no table**: a firmware that does not answer the range tags (QEMU's `raspi`) leaves no actuator and no model; the line says so.

Kconfig `ENERGY` must be on for any of this (`config/fragments/overlays/rpi5.frag` sets it); the rates the Pi 5 PLL lands on exactly and the measured power are not validated on a board.

The energy mode is the topology's alone (`[energy] mode`): `EnergyMode::Performance`, `Balanced` or `Endurance`. It is not a Kconfig symbol.

Source: `crates/core/energy/src/model.rs`, `crates/core/energy/src/dt.rs`, `crates/drivers/thermal/src/rpi.rs` (`ArmClock::energy_model`), `kernel/src/entry/aarch64/ext/rpi_mbox.rs` (`energy_model`), `kernel/src/boot/energy.rs` (`install_energy`).

## Utilisation

With `ENERGY`, the scheduler tracks how busy each task and each CPU has been. A signal is a `UtilState`; the value is on `SCALE` (1024 = running all the time). It is updated at dispatch and switch-out (`energy::on_switch`, including the direct IPC hand-off and the first dispatch) and at the tick (`energy::on_tick`). A wake-up updates nothing; a reader that needs the value now asks `task_util` or `cpu_util_at`, which project the signal forward without writing it. A task's signal is written only by the hart that switches it in or out or ticks it. Idle tasks are not tracked.

Two trackers exist, chosen by Kconfig (`ENERGY_UTIL_WINDOW`, `ENERGY_UTIL_PELT`); both do O(1) work per update:

| Tracker | Rule |
|---|---|
| window (default) | busy time per window of `ENERGY_UTIL_WINDOW_US` (default 10000); the signal is the larger of the last closed window and the mean of the last `HISTORY` (4) windows |
| PELT-like | per period of `ENERGY_PELT_PERIOD_US` (default 1024), `avg = avg * y + input * (1 - y)` with `y^32 = 1/2`, in Q32 fixed point |

Source: `crates/core/energy/src/util.rs`, `crates/core/sched/src/energy.rs`.

## Seams

Three decisions go through closed enums, dispatched by `match` rather than `dyn`:

| Seam | Variants | `Seams::TODAY` |
|---|---|---|
| `Placement` | `Legacy` | the pinned CPU, else `find_best_cpu` ([scheduler.md](scheduler.md)) |
| `Governor` | `Fixed`, `Schedutil`, `DeadlineFloor` | `Fixed`: no frequency request |
| `IdleGovernor` | `WfiOnly`, `Teo` | `WfiOnly`: `wfi` (depth 0) |

`Seams::select(model, mode)` picks them at boot: with no model, or in `Performance` mode, the result is `Seams::TODAY`; in `Balanced` and `Endurance` it is `DeadlineFloor` and `Teo` (placement stays `Legacy`; the two modes select the same seams). The `const`s `PLACEMENT`, `GOVERNOR` and `IDLE_GOVERNOR` stay `TODAY`: they are what a kernel built without `ENERGY` runs. `Governor::Schedutil` alone is never selected, because it reads no reservation and cannot honour the deadline floor. `energy::install` stores the model, mode and seams once at boot.

Source: `crates/core/energy/src/seams.rs`, `crates/core/sched/src/energy.rs` (`install`, `seams`, `mode`, `model`).

## Idle

### The idle seam

The idle task of each CPU waits through `azos_sched::energy::idle_wait` (with `ENERGY`) or the `IdleGovernor` seam (without). The state is entered with `Cpu::cpu_idle(depth)`, which idles the calling CPU in the state of index `depth` and returns how long it slept in microseconds, measured whatever the depth. Depth 0 is `wfi` (`hlt` on x86_64); depth `d >= 1` is the `d`-th idle state of the model for the CPU's domain. Like `wfi`, it returns when any interrupt is pending. If a depth cannot be entered, the CPU enters the deepest state below it that can be, else the shallow wait.

| ISA | Depth 0 | Depth `d >= 1` |
|---|---|---|
| riscv64 | `wfi` | SBI HSM `hart_suspend` with the state's `riscv,sbi-suspend-param`. A retentive type (bit 31 clear) keeps the hart's state and the call returns on wake-up. A non-retentive type is entered only with `CPU_IDLE_POWERDOWN` and a registered resume entry: the hart saves its context, resumes at the secondary entry and restores it |
| aarch64 | `wfi` | PSCI `CPU_SUSPEND` with the state's `arm,psci-suspend-param`. A standby or retention state returns on wake-up. A power-down state needs `CPU_IDLE_POWERDOWN` and a resume entry, as above |
| x86_64 | `hlt` | `MWAIT` hint (`MWAITX` on AMD and Hygon) from a ladder of states ordered by exit latency |

A device-tree state is not entered, on riscv64 and aarch64, if it has no suspend parameter or declares `local-timer-stop` (the CPU's timer stops in it and nothing else wakes the CPU for its own deadline). `SuspendState::enterable` encodes the rule. A depth the firmware refuses for good is retired (`IdleLadder::retire`) and not tried again. At boot, `install_idle_states` gives each CPU its ladder from the device tree and logs which depths are entered as themselves.

x86_64: a state is on the ladder only if `MONITOR`/`MWAIT` are usable with the `CPUID.5` extensions, `CPUID.5:EDX` lists a sub-state for its hint, and, for any hint above C1/C1E, the CPU reports that neither the local APIC timer nor the TSC stops in it (`ARAT` and the invariant TSC bit). Exit latencies and residencies come from per-model tables; a model with no table gets no deep state, because a latency is never guessed. AMD and Hygon get the single `MWAITX` C1 state. The model's idle list for a domain without an `idle` table is `[hlt, ladder...]`; a topology-declared table is checked against the ladder, and `cpu_idle` is capped at the first state the table understates (`cap_depth`). With `IF` clear, or no ladder, every depth is `hlt`.

Source: `crates/core/arch-api/src/lib.rs` (`Cpu::cpu_idle`), `crates/core/arch-riscv64/src/api_impl.rs`, `crates/core/arch-riscv64/src/firmware.rs` (`hart_suspend_retentive`, `IdleLadder`, `SuspendState`), `crates/core/arch-aarch64/src/api_impl.rs`, `crates/core/arch-aarch64/src/firmware.rs` (`cpu_suspend_standby`, `IdleLadder`, `SuspendState`), `crates/core/arch-x86_64/src/lib.rs`, `crates/core/arch-x86_64/src/cpu/idle.rs`, `kernel/src/boot/energy.rs` (`install_idle_states`, `report_idle_ladder`), `kernel/src/tasks/system.rs` (`idle_wait`, `idle_task`), `config/arch/Kconfig.platform` (`CPU_IDLE_POWERDOWN`).

### The idle governor

`IdleGovernor::Teo` is a timer-events-oriented governor. `idle_wait(cpu, enter)`:

1. evaluates the frequency governor if it is not `Fixed` (see below);
2. takes the sleep bound as the earlier of the nearest timer sleeper (`nearest_timer_deadline`) and what the hart has programmed (`timebase::programmed`);
3. takes the real-time slack from `rt::rt_slack`: the nearest deadline a reservation on that CPU can have, `u64::MAX` with none;
4. limits the candidate states by the policy's idle depth (a parked CPU is not held to it);
5. on a CPU with real-time state (`idle::holds_real_time`: a band task running, queued or bound to it, an admitted reservation, or `isolcpus`), cuts the list before the first state that loses context (`idle::allowed`), whatever the slack;
6. calls `idle::select`, then `enter(depth)`, then `idle::reflect` with the measured sleep.

`idle::select` starts from the deepest state whose target residency fits the sleep bound and, for states past 0, whose exit latency fits the real-time slack (`timer_candidate`). It then moves shallower while early wake-ups dominate the history below the candidate (`2 * early > total`). History can only make the choice shallower, never deeper, so it cannot exceed the slack. `select` reports what limited the choice: `Limit::Timer`, `RtSlack` or `History`. Per CPU, each state has two decaying counters: `hits` (woken by the timer, within 1/16 of the bound) and `intercepts` (woken earlier). Each wake-up decays every counter by 1/8 and adds `STEP` (64) to one. The governor never touches a timer, so the watchdog keepalive on hart 0 is never moved. Counters (`idle_stats`) include a check that no choice has an exit latency above the slack.

Source: `crates/core/energy/src/idle.rs`, `crates/core/sched/src/energy.rs` (`idle_wait`, `idle_stats`), `crates/core/sched/src/rt.rs` (`rt_slack`).

## Frequency governor

A performance domain is evaluated, rate-limited, from any CPU's tick and idle entry (`gov_maybe`): one hart evaluates a domain per interval, using projected signals so a domain whose CPUs are all idle is still evaluated by a CPU that runs. The default interval is `RATE_LIMIT_US` (4 ms), settable within limits.

`Governor::DeadlineFloor` answers the maximum of three floors, each an OPP index (`governor::combine`):

| Floor | Rule |
|---|---|
| schedutil | the lowest OPP whose capacity covers the domain's busiest CPU, `util * capacity(current)`, plus a headroom (default `HEADROOM_PCT`, 25 percent) |
| deadline | the lowest OPP whose capacity covers the admitted reservations of the domain's most loaded hart (`rt::ADMITTED_PPM`, the sum of densities `q/d`), plus `DEADLINE_MARGIN_PCT` (20) |
| safety | the lowest OPP at or above `wcet_ref_khz`; with none declared, or one above every OPP, the fastest OPP |

`Decision` records which floor set the answer (`Why::Schedutil`, `DeadlineFloor`, `SafetyFloor`; ties go to safety, then deadline). The policy's OPP range then bounds the request and the floors win again (`Policy::clamp`).

`gov_maybe` stores the chosen OPP index per domain (`domain_opp`) and counts evaluations, changes and the floor that decided (`gov_stats`). `azos_sched::energy` calls no `OppActuator`: the scheduler records the decision. `domain_opp` is what energy-aware placement scales capacity with ([scheduler.md](scheduler.md)); before the first decision a domain is taken to run at its fastest OPP.

`OppActuator` (`crates/core/energy/src/opp.rs`) is the seam through which an OPP reaches a clock: `set_opp(domain, &Opp)`, answering `ActuateError::{Unsupported, Refused, Fault}`. `NoActuator` refuses every request. `Dvfs` keeps which OPP each domain runs at, skips a request that changes nothing, and counts what the actuator applied and refused.

Source: `crates/core/energy/src/governor.rs`, `crates/core/energy/src/opp.rs`, `crates/core/sched/src/energy.rs` (`gov_maybe`, `gov_stats`, `domain_opp`, `domain_admitted_ppm`).

## Thermal

Policy is `azos_energy::thermal`; sensors and clocks are `azos_thermal`. A **zone** is read through one sensor and has up to `MAX_TRIPS` (6) trips and `MAX_MAPS` (6) cooling maps; a `Thermal` holds up to `MAX_ZONES` (8) zones (the device tree's `thermal-zones`, built by `azos_thermal::dt`).

| Element | Meaning |
|---|---|
| `Trip` | `temp_mdeg`, `hyst_mdeg` (active until the temperature is below `temp - hyst`), and a `TripKind` |
| `TripKind::Passive` | cool by capping the clock (cooling maps apply) |
| `TripKind::Active` | recorded, no clock action of its own |
| `TripKind::Hot` | capping was not enough: degrade level `LEVEL_SLOW` (2) |
| `TripKind::Critical` | an orderly shutdown is requested |
| `CoolingMap` | while trip `trip` is active, cap domain `domain` by a state between `min_state` and `max_state` (state `n` = at most OPP `top - n`) |

**Cooling by capping.** At or above a trip's temperature, a map's state rises by one per evaluation, clamped to `min_state..=max_state`. Inside the hysteresis band the state holds. Below the band the trip is inactive and the state falls by one per evaluation. A domain's cap is the largest state over every map that names it, in every zone.

**Floors.** `Thermal::limit` returns `max(min(want, cap), floor)`, where the floor is the larger of the deadline floor of the admitted reservations and the safety floor. Heat never lowers a clock below what an admitted guarantee needs. When the cap would have gone lower, the domain is floor-bound (`Limited::bound`).

**Degrade levels.** `Thermal::settle` returns the level the power service should hold and whether a critical trip latched a shutdown:

| Situation | Level |
|---|---|
| a domain floor-bound while capped, or a clock that cannot be moved while the heat wants it lower | `LEVEL_CAUTIOUS` (1) |
| a `Hot` trip active, or a sensor lost | `LEVEL_SLOW` (2) |
| a `Critical` trip reached | `LEVEL_CONTAINED` (3), shutdown latched |

A sensor is lost after `SENSOR_FAIL_LIMIT` (3) failed reads; its zone's maps then cap their domains at their deepest state until a read succeeds. Every trip crossing, floor-bound transition, level change and sensor loss is a `Record` in a ring of `LOG_LEN` (16).

**Runtime.** `azos_thermal::runtime::Runtime::tick(hw, model, now_ms, inputs)` reads the zones that are due, applies `limit` to each domain through `Dvfs` and the platform's `OppActuator`, and returns the `Settled` outcome. A platform plugs in as a `SensorBank` plus an `OppActuator`. `Runtime::from_dt` builds the runtime from the device tree: the zones over the energy model (one sensor per board, so a zone's sensor is index 0 when its phandle names a one-cell controller), and each domain's boot OPP from the clock the board reads back, so a clock the heat pulled down has an OPP to be put back at.

**StarFive JH7110.** `azos_thermal::jh7110::Jh7110` pairs the `sfctemp` sensor (`starfive,jh7110-temp`, one control and data register, `DOUT * 237.5 / 4094 - 81.1` degrees; a conversion of 0 is `Invalid`) with the CPU clock of the SoC frameworks (`azos_thermal::soc::SocCpuClock`, the clock the first CPU node names, each step a write-ahead `KIND_CLOCK` effect). No regulator moves the rail, so the clock may go down from its boot rate and back to it, never above (`ceiling_khz`, the rate read at boot); a request above it is refused.

**SpacemiT K1.** `azos_thermal::k1::K1Tsensor` is the `TSEN` block (`spacemit,k1-tsensor`, five channels: soc, package, gpu, cluster 0, cluster 1) as a `SensorBank`; the thermal framework holds up to eight zones, enough for the five of the K1 tree. The kernel starts the block at probe (`kernel/src/boot/hwbus.rs`, `k1-tsensor`). `K1Tsensor::start` reads the control register first: an all-ones word is what a window with nothing behind it returns, and then nothing is written and the bind is refused. After the writes it reads the control and enable registers back, and a block that did not keep them (held in reset) is refused too. The read-back cannot see a window that never answers: the block's clock and reset belong to the APBC controller, which has no provider, so the bind skips them as unmodelled and the probe relies on them being on. The CPU cluster clocks are `azos_soc::k1::K1Clk` (Kconfig `SOC_K1`): the `CLK_CPU_Cn_CORE` / `CLK_CPU_Cn_HI` clocks of the APMU with the PLL tree under them, built from the device tree; a cluster switch selects among the inputs the firmware left running and never reprograms a PLL. The host suites are `tests/host/soc-tests` (`k1_tests`) and `tests/host/thermal-tests` (`k1_tsensor`).

**K1 DVFS.** `azos_thermal::k1::K1Opp` is the `OppActuator` of a board whose rail the kernel moves: one table per cluster (`C0`, `C1`), keyed by kHz, with the voltage of each OPP from the device tree's `operating-points-v2` (`opp-microvolt`, read by `dtb_energy` into `DtOpp::{uv, uv_max}`). An OPP over its own `opp-microvolt` maximum or over the rail's `regulator-max-microvolt` is dropped from the table and refused when asked for, never clamped; a table with an OPP that has no voltage, two equal frequencies, or a faster OPP at a lower voltage is refused whole. The clock and rail are read back before every move: going up the rail is raised first (never lowered), the actuator waits the rail's `regulator-ramp-delay`, then the clock rises, and a clock that will not move puts the rail back; going down the clock falls first and the rail follows. Three things are about what the hardware makes or does, not what the table says:

* **The clock makes the rate it can** (`K1Hw::round_khz`). The DT row says 819000000 and the PLL divider makes 819200000, so the voltage of a move is that of the slowest row at or above the frequency that results, and a request for the row the cluster already runs is a no-op. A clock that would land above the fastest row is refused.
* **A shared buck holds the higher cluster's voltage** (`K1Hw::rail_of`). The Milk-V Jupiter tree puts all eight CPUs on `buck1` (`cpu-supply = <&buck1_0v9>`), so lowering cluster 0 must not take the rail from cluster 1: the voltage a move asks for is the largest of its own need at the new clock and what each other cluster on the rail needs at the clock it runs now (and a rail firmware left below that is raised first). A cluster that has no table, or whose clock is above the fastest row, holds the rail where it is; a cluster on the rail that cannot be read stops the move before anything is written.
* **`Ok` and `Err` are about the clock.** `Dvfs` believes the domain is at the OPP of the last `Ok`, and the heat caps and restores by that belief. A rail that will not follow the clock down (or be raised after it fell) is therefore not a refusal of the throttle: the clock moved, the answer is `Ok`, the rail stays above what the clock needs (power wasted, nothing broken), `K1Opp::take_lag` hands the kernel a `RailLag` (the thermal task prints it and `thermal/rail_lagged` counts it), and the next move reads the state again and retries. An `Err` means the clock did not move (a rail raised for it is put back; if that fails the rail stays high and is reported the same way); a supply below what an unmoved clock needs that cannot be raised is an `Err`.

The providers (`azos_soc::k1`, Kconfig `SOC_K1`) are built from the device tree like the JH7110's: `K1Clk` on the `spacemit,k1-syscon-apmu` node and `P1Buck` for the `buckN` nodes of the P1 PMIC, reached through `azos_soc::I2cBus` (a regulator behind a PMIC is not an MMIO word; `RegulatorOps` takes an `Io` with the optional I2C master, and `regulator-ramp-delay` is in `Constraints`). The kernel's `I2cBus` is `boot::hwbus::PmicI2c`: it names the master by the window of its device-tree node and uses the I2C driver's synchronous transfer. The K1 I2C controllers attach after the frameworks are built, so the six always-on bucks are providers at build (a consumer's `cpu-supply` resolves, with the rail's constraints) but not tried then: a rail whose master is not there is deferred, not failed (`always-on-pending` in the `[SOC]` line and the introspection tree's `soc/always_on_pending`), and no effect is recorded for a write that cannot happen. They stay unpinned: pinning needs a PMIC read made under the frameworks' lock, and nothing takes these rails through the framework (a consumer that took one and dropped it would cut it).

`azos_thermal::k1_soc::k1_plan` reads one cluster per domain of the energy model (the first CPU of the domain: its `clocks` entry 0, its `cpu-supply` buck, its OPP table, the rail's ceiling and ramp) and `SocK1Hw` is the hardware behind `K1Hw`: the clock through the clock framework one operation at a time (`K1Clocks`, a write-ahead `KIND_CLOCK` effect each) and the rail through a copy of the buck that the plan kept, with a `KIND_REGULATOR` set-voltage effect recorded first and the voltage held to the rail's `regulator-min/max-microvolt` as well as to the table's ceiling. The rail does **not** go through the regulator manager: a voltage step is up to eight register transfers (the voltage read-back, the selector's write and its read-back; one byte at a time through the K1 master, about 110 to 170 microseconds each at 400 kHz), which is more than a spin lock may be held (`LOCK_MAX_HOLD_US`, 100 us by default) and a sleeping lock may not be held across a device wait. So the thermal task of a K1 holds no lock across the tick: it takes the runtime out of its state (`thermal/status` says `ticking` meanwhile; only this task writes it), takes the frameworks' lock for each clock operation and no lock for the rail, and the transfers sleep between controller steps. What this gives up is the manager's bookkeeping, which a DVFS step does not change, and the assumption that nothing else writes the buck's selector while it moves. `azos_thermal::k1::runtime_from_dt` builds the runtime with the K1's sensor rule: a zone's `thermal-sensors = <&tsensor N>` is channel N (the one-sensor boards' rule would keep one of the five zones). A cluster the tree does not wire completely is left alone and its caps are refused (the level rises instead); the boot says so, and says when the model has no domain or OPPs with no row in the tree's table. The host suites (`tests/host/soc-tests` `k1_tests`, `wire`, `tests/host/thermal-tests` `k1_opp`, `k1_tsensor`) run the providers against register models and the whole path over the Jupiter tree (`tests/host/soc-tests/fixtures/k1-jupiter.dts`), with the order of every write and its record.

**Needs a valid energy model.** The thermal domains and the K1 plan are the energy model's, and the model refuses an OPP of power 0. The Linux K1 trees carry no `opp-microwatt`, so a K1 image needs either a tree that gives it or a signed topology with `[energy.domain.*]` rows whose OPP frequencies are the tree's (`614400`, `819000`, `1000000`, `1228800`, `1600000` kHz); without one the model is empty and the K1 board has no domain to move (the boot says `no energy model`; the sensor and the critical trip still work).

**Timing.** The rail step is the longest thing the thermal task does; the host suite proves the order and the records, not the time, and the `[THERMAL]` lines do not time a move (first read-back to last clock write).

The hardware facts the K1 code is written against, with the Linux v7.3 file each comes from and what the host suites cannot show:

| Fact | Known from | Not shown by the host suites |
|---|---|---|
| Cluster clock `APMU_CPU_C0_CLK_CTRL` 0x38C, `APMU_CPU_C1_CLK_CTRL` 0x390: core mux `[2:0]` (inputs `pll1_d4_614p4`, `pll1_d3_819p2`, `pll1_d6_409p6`, `pll1_d5_491p52`, `pll1_d2_1228p8`, `pll3_d3`, `pll2_d3`, HI), FC bit 12, HI select bit 13 | `drivers/clk/spacemit/ccu-k1.c`, `ccu_mix.c` | that the FC bit clears within the read budget (`POLL_BUDGET`, 20000 reads, stands for Linux's 10 ms; no timebase in the poll); that every input the OPPs use is running at boot (the provider switches among running inputs only); the HI select against the core select when both change; whether the ACE clock (bits 8:6, not modelled) must follow a cluster at 1.6 GHz |
| PLLs: `APBS_PLLn_SWCR1..3` (0x100, 0x118, 0x124 + 0/4/8), enable bit 31 of `SWCR3`, lock bits `MPMU_POSR` 27..29, rate tables | `ccu-k1.c`, `ccu_pll.c`, `include/soc/spacemit/k1-syscon.h` | which PLL3 rate the firmware leaves (1.6 GHz needs 1.6 or 3.2 GHz); that the PLL block is at `0xd4090000` and the MPMU at `0xd4050000` in the board's tree; PLL3 relock from a parked source is **not** implemented (no PLL is reprogrammed) |
| P1 bucks: enable `0x47 + 3(n-1)` bit 0, selector the next register (the whole byte), 500000 + 5000·sel (sel 0..170), 1375000 + 25000·(sel-171) (171..254), 255 is the sleep value and not a voltage; `buck1`/`buck2` 500000..1050000 uV, `regulator-ramp-delay` 5000 uV/us | `drivers/regulator/spacemit-p1.c`, the Linux `mfd/spacemit,p1.yaml` binding, `arch/riscv/boot/dts/spacemit/k1-milkv-jupiter.dts` and `k1-bananapi-f3.dts` (both give all eight CPUs `buck1`) | the PMIC's wire format (one address byte, one data byte, a write followed by a repeated-start read: the regmap is in `drivers/mfd/simple-mfd-i2c.c`, not in the reference tree); that a write to the selector takes effect without a go bit (the selector is read back after every write, which proves the register holds it, not that the rail moved); the real slew (the DT delay is a lower bound for the wait); that the I2C master `i2c8` at `0xd401d800` is left clocked and out of reset by the firmware (the K1 has no TWSI clock provider here) |
| The OPP rows (614.4, 819, 1000, 1228.8, 1600 MHz; 0.95 V up to 1.2288 GHz, 1.05 V at 1.6 GHz, maxima 1.05 V) | `arch/riscv/boot/dts/spacemit/k1-opp.dtsi` | each row on silicon, and that the DT's maximum-voltage fix holds on the board's silicon revision |
| Temperature sensor: `PCTRL` 0x00, `EN` 0x08, `TIME` 0x0C, `INT_EN` 0x14, `DATA` 0x20 + (n/2)·4, temperature = reading - 278 degrees | `drivers/thermal/spacemit/k1_tsensor.c` | that the block's clock and reset (`CLK_TSEN`, `CLK_TSEN_BUS`, `RESET_TSEN` of the APBC controller, not a provider here: the bind skips them as unmodelled) are left on by the firmware: a block in reset reads zeros, which is `Invalid`, and the zone caps at its deepest state after three failed reads |
| Two clusters of four X60 cores | `k1.dtsi` `cpu-map` | that the energy model's domain order is `C0`, `C1` (the DT's CPU-table order; `k1_plan` takes the domain's first CPU, so it follows the model whatever the order) |
| Five thermal zones (soc, package, gpu, cluster 0, cluster 1), `thermal-sensors = <&thermal N>` | `k1.dtsi` | that the board's tree names the five and that `[THERMAL] board=k1 zones=5` is printed |
| The order of a move on the wire | this suite (`k1_opp`) | the rail's settling after a rise against `regulator-ramp-delay` (scope the rail), and that no brown-out or hang follows a 1.6 GHz step with the other cluster running |

**The kernel's thermal task** (`kernel/src/boot/thermal.rs`, `THERMAL`). At boot, after the energy model is resolved (on a Raspberry Pi the energy step has already enabled the mailbox and probed the clock), the kernel reads the DTB's `thermal-zones` and builds the runtime for the board it finds: the VisionFive 2 (the JH7110 object above), the K1 (above) or a Raspberry Pi (the VideoCore mailbox, `brcm,bcm2835-mbox`, for both the temperature and the ARM clock). The mailbox posts a buffer the firmware writes into by DMA, so it is enabled only for a SoC whose root `compatible` names a known bus map (BCM2835/6/7 and BCM2711: the `0xC000_0000` alias, first GiB of RAM; BCM2712, the Pi 5: the identity map, its `soc` and root nodes carry no `dma-ranges`, first 4 GiB; `azos_firmware::BusWindow`), and a message whose buffer lies outside that window is refused before it is posted. The ARM clock is an actuator only after `RpiFirmware::probe_clock` found a range that can move (`GET_CLOCK_RATE`, `GET_MIN_CLOCK_RATE`, `GET_MAX_CLOCK_RATE`: minimum above zero and below the maximum, the current rate inside); an emulated property channel (QEMU `raspi`) does not give one, and the object is then the sensor alone (every cap refused, the level rises). A rate outside the range is refused before it is posted, and the rate the firmware settled on is checked against the request: below it is a clock under the admitted real-time floor (put back and refused), above it is accepted only while it is still a step down from where the clock was. An x86_64 machine has no device tree: when the CPUID probe finds a package sensor (Intel `coretemp`, AMD Zen over SMN; never under a hypervisor), its one zone is built from `THERMAL_X86_PASSIVE_C`, `THERMAL_X86_HOT_C`, `THERMAL_X86_CRITICAL_C` and `THERMAL_X86_POLL_MS` (defaults 75, 85 and 100 degrees, 1000 ms): the passive trip caps every domain of the energy model that has two OPPs, the hot trip raises the level, the critical trip requests the shutdown. The AMD sensor reads through the config-space port pair under the lock every config access takes. The clock is the CPU's own level request (`azos_arch::cpu::pstate` decides from CPUID whether there is one, `crates/drivers/thermal/src/x86.rs` makes it): Intel HWP (`IA32_HWP_REQUEST`, after `IA32_PM_ENABLE`) or AMD CPPC (`0xC00102B0..B3`), per logical CPU. The OPP's frequency is laid linearly on the CPU's own `[lowest, highest]` from its capabilities register, rounded up; the fastest OPP releases the range and any other pins `min = max`; the request is read back and a CPU that did not keep it is refused. The heat cap and the real-time and safety floors are applied before the request, as for every board. A register of another CPU is reached with the function-call IPI (`entry/x86_64/ext/thermal_hw.rs`; only the actuator's registers may be asked that way). The boot state of a domain is its fastest OPP: with a level request the firmware leaves the whole range open, and neither register can be read before the control is switched on. RAPL's package energy (`MSR_RAPL_POWER_UNIT`/`MSR_PKG_ENERGY_STATUS`, AMD `0xC0010299`/`0xC001029B`) is sampled each tick across its 32-bit wrap and shown in the introspection tree's `thermal/` (`package_energy_uj`, `package_power_mw`). Every MSR is behind a CPUID bit (or, for Intel's RAPL, the family and model) read first, since there is no fixup for a `rdmsr` that faults: a CPU with a sensor and no level request refuses every cap, so the degrade level rises instead, and QEMU's TCG, which has none of them (and any hypervisor), builds no board. The level request is made for an OPP of the energy model, so it reaches a CPU only when the model has a domain with two OPPs (the topology's `[energy.domain.*]`; the CPUID model of a hybrid part has one OPP per domain, and a machine with no model has no domain), and the boot says so when it will not; the sensor, the degrade level, the critical shutdown and the energy counter work either way. A board with none of these builds no zone. The clock half is `ENERGY`'s, not `THERMAL`'s: with `THERMAL` off, or on a board whose tree declares no zone, the kernel builds a runtime with no zone over the board's clock alone (`azos_thermal::runtime::NoSensor`), and the same task applies the governor's choices; only a board with neither a zone nor a clock to move (QEMU) creates no task. The `thermal` task (priority `THERMAL_TASK_PRIORITY`, on the lowest CPU outside `RCU_NOCBS_CPUS` and `isolcpus`, never real-time; when every CPU is in one of them there is no task and the boot says so) sleeps `Runtime::poll_interval_ms` (the zones' polling delay, the passive one while a trip is active, never under 10 ms; with no zone, until woken), is woken early when the governor's choice for a domain changes (`gov_maybe` wakes it, `apply_take`), and each time:

1. takes from the governor seam the OPP the governor recorded for each domain (`azos_sched::energy::domain_opp`; none while the governor is `Fixed`) and the real-time density admitted on the domain's most loaded hart (`domain_admitted_ppm`, the I1 floor), so the floors are the live ledger's;
2. ticks the runtime. This is the one place a governor decision reaches a clock: `gov_maybe` records, the thermal task actuates, capped by the heat and held up by the floors. It then answers each choice to the governor (`gov_ack`: applied, capped, raised, refused by the actuator, no actuator). The governor asserts the answer comes: a choice for a domain the board can move that is still unanswered after `ENERGY_APPLY_DEADLINE_MS` is overdue. Refused and overdue choices are counted (`POLICY_STATS_OPP_REACHED`, `_CAPPED`, `_UNAPPLIED`, `_OVERDUE`) and recorded under `opp-apply`, once per run (`azos_energy::opp::apply_record`);
3. leaves every new entry of the framework's ring as a console line (`[THERMAL] zone ...`) and a `Rule::Thermal` decision record (`why`: a trip that fired is `place`, a domain the floors keep hot, a level raise, a lost sensor and the shutdown request are `refuse`, their relaxations `admit`);
4. on a latched critical trip, powers the machine off in order (`power_off_orderly`).

The introspection tree's `thermal/` shows the board, the evaluations made, the level, the shutdown request, the active trips of each zone and each domain's cap and OPP; the ring is on the console and in the decision records. The degrade level the framework settles on is not carried to the power service: no channel exists for a level the kernel raised (the power interface's state words carry the battery's level the other way), so it shows in `thermal/level` and on the console only.

The QEMU row `thermal-smoke` runs the same task and runtime over a fake board (a scripted temperature, a clock that only remembers: `azos_thermal::fake`) and the balanced fake model, and walks the temperature through the passive and hot trips and back: throttle to the floors, the degrade record, the clocks restored (`kernel/src/smokes/thermal_smoke.rs`).

Source: `crates/core/energy/src/thermal.rs`, `crates/core/energy/src/model.rs` (`from_clock_range`), `crates/drivers/thermal/src/rpi.rs`, `kernel/src/boot/thermal.rs`, `kernel/src/boot/energy.rs`, `kernel/src/entry/aarch64/ext/rpi_mbox.rs`, `kernel/src/entry/x86_64/ext/thermal_hw.rs`, `crates/core/arch-x86_64/src/cpu/pstate.rs`, `crates/drivers/thermal/src/x86.rs`, `crates/drivers/thermal/src/x86_sensor.rs`, `kernel/src/smokes/thermal_smoke.rs`, `crates/drivers/thermal/src/runtime.rs`, `crates/drivers/thermal/src/fake.rs`, `crates/drivers/thermal/src/sensor.rs`, `crates/drivers/thermal/src/dt.rs`, `crates/drivers/thermal/src/k1.rs`, `crates/drivers/thermal/src/k1_soc.rs`, `crates/drivers/thermal/src/jh7110.rs`, `crates/drivers/thermal/src/soc.rs`, `crates/drivers/soc/src/k1/`, `crates/drivers/thermal/src/lib.rs`, `config/kernel/Kconfig.energy` (`THERMAL`), `kernel/Cargo.toml` (feature `thermal`).

## Run-time policy

Policy lives in user space; the kernel enforces limits. The `Power` interface (`azos_devif::power::Power`, interface id `POWER_ID`) is served on the `power` endpoint. Observing ops need `READ`; every op that changes something needs `WRITE`. A setter answers `OK` with 0 (applied); `REFUSED` with a `POLICY_REFUSED_*` value when a kernel limit refused it, which is recorded; `DENIED`, `UNSUPPORTED` (no `energy`) or `BAD_ARGUMENT` when the call itself failed.

| Op | Effect |
|---|---|
| `shutdown`, `reboot` | orderly power-off or reboot; `once_only`, never retried |
| `suspend` | suspend to RAM ([System suspend](#system-suspend)) |
| `sched_hz`, `set_sched_hz` | read or set the tick rate (`POWER_SCHED_HZ_MIN`..`POWER_SCHED_HZ_MAX`, 10..10000 Hz; `BAD_ARGUMENT` outside) |
| `set_governor` | `POLICY_GOV_FIXED` or `POLICY_GOV_DEADLINE_FLOOR` |
| `set_opp_range` | restrict a domain to OPP indices `min..=max` |
| `set_headroom`, `set_rate_limit` | schedutil headroom (percent), shortest interval between evaluations (us) |
| `set_idle_depth` | deepest idle state the idle governor may pick; `POLICY_IDLE_UNLIMITED` lifts it |
| `set_power_cap` | cap a domain at `mw` milliwatts; the kernel turns it into an OPP ceiling through the model; 0 lifts it |
| `set_parked` | park the CPUs of a mask (energy-aware wake placement never chooses them and the idle governor lets them sleep as deep as the slack allows; load-based placement and the balancer do not read the mask, so work already there stays) |
| `set_qos_domains` | place tasks of a QoS class on the given domains only |
| `report_battery` | report charge and degrade level ([Battery](#battery)) |
| `state`, `stats` | read a `POLICY_STATE_*` or `POLICY_STATS_*` word |
| `cpu_online` | take a CPU offline or bring it back ([CPU hotplug](#cpu-hotplug)) |

Each op declares what happens when the service fails (`on_failure`) and how long it may take; a failed power-off or reboot escalates to the safety path, policy changes and reads degrade (the previous policy stays in force).

`azos_energy::policy::Policy` holds the live values as atomics and refuses a setter outside these limits, bumping a counter and leaving a record (`Policy::refusal`):

| Setter | Refused when (`Refusal`) |
|---|---|
| `set_governor`, `set_opp_range`, `set_idle_depth`, `set_power_cap`, `set_parked`, `set_qos_domains` | no model (`NoModel`) |
| `set_governor` | anything but `Fixed` or `DeadlineFloor` (`Governor`) |
| `set_opp_range` | unknown domain (`Domain`); `min > max` or `max` past the last OPP (`Range`); `max` below the safety floor (`SafetyFloor`) or the admitted reservations' floor (`DeadlineFloor`) |
| `set_headroom`, `set_rate_limit` | outside `POLICY_HEADROOM_MIN_PCT..=POLICY_HEADROOM_MAX_PCT` (10..=100, `Headroom`), `POLICY_RATE_LIMIT_MIN_US..=POLICY_RATE_LIMIT_MAX_US` (1000..=1000000, `RateLimit`) |
| `set_idle_depth` | deeper than the deepest state any domain lists (`IdleDepth`) |
| `set_power_cap` | unknown domain (`Domain`); below the power of the domain's slowest OPP (`Range`); its OPP below the safety floor (`SafetyFloor`) or the deadline floor (`DeadlineFloor`) |
| `set_parked` | CPU 0, a CPU outside the model, or every CPU of a domain (`Park`); a CPU with admitted reservations (`DeadlineFloor`) |
| `set_qos_domains` | not a QoS class, an empty mask or a domain the model lacks; the default or latency class kept off the fastest domain (`Qos`) |
| `report_battery` | a charge above 100; a level the topology has no row for; a level lighter than the rows require at that charge; no battery declared (`Battery`) |

A cap that was legal when set can become illegal as reservations are admitted, so the limits are enforced again at every governor evaluation. The parked mask and the QoS mapping are read by energy-aware placement; the parked mask is also read by the idle governor.

Source: `crates/core/devif/src/power.rs`, `crates/core/energy/src/policy.rs`, `crates/core/abi/src/power.rs`, `crates/core/syscall/src/power.rs`, `crates/core/sched/src/energy.rs` (`policy_*`).

## Power service

`POWER.ELF` (`userspace/services/power`) decides policy and applies it through the `Power` interface on the `power` endpoint its topology row grants. Its preset is the topology's `[energy] mode`, unless one is named on the command line. It applies a built-in profile per preset (`policy.rs`), logs each kernel verdict, and answers a refusal with a fallback decision. It also decides the machine's budget (power cap per domain, parked CPUs, the domains each QoS class may use), reads the battery, chooses the degrade level from the topology's `[degrade.NAME]` rows with their hysteresis, and keeps device idle timeouts.

**What a degrade level asks.** A level is entered at the charge its row declares (`battery_pct`) and caps every domain's power at a share of its top OPP's, derived from that charge and the kernel's reserve (`ENERGY_BATTERY_RESERVE_PCT`, read back in `POLICY_STATE_BATTERY`): `share = (battery_pct - reserve) / (100 - reserve)`. The reserve is the energy kept for the safe stop, so only the charge above it is the mission's, and the share makes that charge last, at the level's entry, as long as a full pack lasts at full power; the pack's capacity cancels. Rows at 30, 20 and 12 % over a 10 % reserve give 22, 11 and 2 %. A product that wants a gentler first level raises that row's threshold (55 over a 10 % reserve asks half the power). Below what the slowest OPP can draw, the CPUs the share still needs are parked (a domain's power taken to scale with the CPUs it keeps; CPU 0 and a domain's last CPU never park), and a share under the lowest power the kernel allows is answered with that power. The preset floor climbs one rung per level (`balanced`, then `endurance`). Source: `policy::Levels`, `Machine::park_for`.

| Command | Effect |
|---|---|
| `power serve [PRESET]` | apply the profile, stay resident, re-apply when another client moved the policy |
| `power apply [PRESET]` | apply once |
| `power state` | print the policy state, the battery and the statistics |
| `power devices` | print the runtime power of each tracked device |
| `power cpu N online\|offline` | `cpu_online` ([CPU hotplug](#cpu-hotplug)); a refusal prints the `HotplugReason` code |
| `power suspend`, `reboot`, `shutdown`, `sched_hz [HZ]` | the corresponding op, as a client of the same capability |

Source: `userspace/services/power/src/main.rs`, `userspace/services/power/src/policy.rs`, `userspace/services/power/src/battery.rs`, `userspace/services/power/src/degrade.rs`, `userspace/services/power/src/devices.rs`.

## Runtime power management and wakelocks

`DevicePower` (`azos_devif::power::DevicePower`, interface id `DEVICE_POWER_ID`) is the power state of one device. The driver of the device serves it from its own endpoint, next to the device's own interface; the power service holds the client. The mechanism is `runtime::RuntimePm`: a state machine with no clock, device or allocation (the driver passes the time and the device's suspend and resume callbacks).

A device is `PM_ACTIVE` or `PM_SUSPENDED`. A suspended device resumes on its next use, or on `resume`. With an idle timeout set, a device nobody used for that long suspends itself, unless a wakelock is live. A **wakelock** keeps the device from suspending until it is released or its deadline passes.

| Op | Right | Effect |
|---|---|---|
| `state()`, `stats(sel)` | `READ` | `PM_ACTIVE`/`PM_SUSPENDED`; a `PM_STAT_*` counter or the `k`-th newest record (`PM_STAT_RECORD_BASE + k`) |
| `idle()` | `WRITE` | the caller is done: the idle clock starts (the timeout suspends, not this call) |
| `hold(ttl_ms)` | `WRITE` | take a wakelock; returns a non-zero lease id. `BAD_ARGUMENT` for a ttl of 0 or above the ledger's longest, `BUSY` when the quota is used |
| `release(lease)` | `WRITE` | give a wakelock back; `NO_RESOURCE` for a lease that is not live |
| `suspend()`, `resume()` | `EXEC` | suspend now (`BUSY` while a wakelock is live, `FAULT` if the callback failed); resume now |
| `set_idle_timeout(ms)` | `EXEC` | autosuspend after `ms` without use; 0 never; `BAD_ARGUMENT` above `IDLE_TIMEOUT_MAX_MS` (one hour) |

A wakelock is a warrant in the kernel's sense: a lease id naming one holder's claim, with a deadline. The ledger is bounded by a `Quota { max_held, max_ttl_ms }` (up to `runtime::LEASES` (8) live leases; Kconfig `DEVICE_WAKELOCKS`, default 4, and `DEVICE_WAKELOCK_TTL_MAX_MS`, default 60000), so one client cannot pin a device awake for ever. A lease whose holder died or forgot lapses at its deadline. Every grant, release, lapse and refusal is recorded in a ring of `runtime::RECORDS` (16).

Op classes travel in the badge the signed topology stamps on the grant (`CLASS_READ`, `CLASS_WRITE`, `CLASS_EXEC`); the holder cannot choose it. `PmServer` answers `DENIED` to an op whose class the badge does not carry, so a call with no badge is refused entirely.

**Endpoints and rows.** Each device is served on a task-hosted endpoint, `endpoint.pm-<device>` (`runtime::DEVICES`: `gpio`, `ina`). The driver's row (`GPIODRV.ELF`, `INADRV.ELF`) holds `READ` on it, which is the right to serve; `POWER.ELF`'s row holds `EXEC` on it (the `ina` grant exists only where the monitor has a ring-3 row, `INADRV_ROW`). The kernel badges the calling grant when it seeds the row (`cap_seed`, `runtime::grant_badge`): the low bits are the op classes (holding the grant is `CLASS_READ`; `WRITE` and `EXEC` map to their classes, so `POWER.ELF` carries observe and control and cannot take a wakelock), the bits above are the device's key (its position in `runtime::DEVICES`, plus one). Ring 3 has no by-name lookup of a task-hosted endpoint and its pool index is the topology's row order, so the power service scans the endpoint capabilities it holds once, at start, and takes the one whose badge carries each device's key (`devices::resolve`).

Source: `crates/core/devif/src/power.rs` (`DevicePower`, `runtime`), `userspace/drivers/gpio_drv/src/main.rs`, `userspace/drivers/ina_drv/src/main.rs`, `config/subsys/Kconfig.drivers` (`DEVICE_WAKELOCKS`).

## CPU hotplug

With Kconfig `CPU_HOTPLUG`, the `cpu_online(cpu, on)` op of the `power` endpoint (needs `WRITE`) stops a CPU and starts it again. It answers `OK` with the number of tasks moved off the CPU (offline) or of CPUs online (online); `REFUSED` with a `HotplugReason` code; `BAD_ARGUMENT` for `on > 1`; `UNSUPPORTED` without the option. Every change and every refusal is a `Rule::CpuHotplug` decision record and a console line.

**Offline.** A `cpu-down` thread pinned to the CPU cuts the online prefix first, then drains: ready tasks move to other CPUs (`migrate_off_cpu`, each placed where `find_best_cpu` puts a new task), timer sleepers move to the takeover CPU's heap (`timer_sleepers::migrate_off`), and the CPU stops through the firmware. A task queued onto it in the window before the stop is moved by a rescue drain afterwards. **Online.** The CPU is started through its secondary entry; a CPU that went offline resumes where it stopped (the saved-context path), one that never ran starts as at boot.

| ISA | Stop | Start |
|---|---|---|
| riscv64 | SBI HSM `hart_stop` | SBI HSM `hart_start` |
| aarch64 | PSCI `CPU_OFF` | PSCI `CPU_ON` |
| x86_64 | halt with interrupts off, then an INIT puts it in wait-for-SIPI (`stop_current`, `park_init`) | INIT-SIPI-SIPI |

The scheduler walks the online CPUs as a prefix `0..n`, so offline takes the highest online CPU and online the first one past the prefix. Refusals (`HotplugReason`):

| Reason | Cause |
|---|---|
| `NotPossible` | no such CPU |
| `NoChange` | already in the state asked for |
| `BootCpu` | the boot CPU keeps the timekeeping and the first interrupt routes |
| `LastCpu` | it would leave no CPU online |
| `CallerCpu` | the caller runs on the CPU |
| `RealTime` | the CPU holds real-time state (a band task, an admitted reservation) |
| `Isolated` | the CPU is in `isolcpus` |
| `Pinned` | a task is pinned to the CPU |
| `NotAtPrefixEdge` | not the highest online CPU (offline) or the first past the prefix (online) |
| `NoFirmware` | the firmware has no stop or start call |
| `Busy` | another change is running |
| `Timeout` | the CPU did not reach the point where it can stop or start in time; it is as it was |
| `FirmwareRefused` | the firmware refused; the CPU is as it was |
| `NeverStopped` | online only: the CPU never stopped here, so there is no saved context to resume |

Source: `crates/core/sched/src/smp.rs` (`cpu_offline`, `cpu_online`), `crates/core/sched/src/hart_set.rs` (`HotplugReason`, `check_offline`, `check_online`), `crates/core/sched/src/scheduler/lifecycle.rs` (`migrate_off_cpu`), `crates/core/sched/src/timer_sleepers.rs` (`migrate_off`), `crates/core/arch-riscv64/src/firmware.rs`, `crates/core/arch-aarch64/src/firmware.rs`, `crates/core/arch-x86_64/src/smp.rs` (`stop_current`, `park_init`), `crates/core/syscall/src/power.rs` (`cpu_online`), `userspace/services/power/src/main.rs` (`cpu_cmd`), `config/arch/Kconfig.platform` (`CPU_HOTPLUG`).

## System suspend

With Kconfig `SYSTEM_SUSPEND` (depends on `ENERGY`; unavailable on the robot, industrial and automotive presets), the `suspend` op puts the machine to RAM and returns after the resume with 0, or with a `Reason` code. The sequence is `azos_drv_power::pm::suspend::run`; the kernel supplies the steps through the `Platform` trait.

```text
gates      enabled; firmware call and resume entry present; no system power
           assertion live; one CPU online; the caller holds a wake source
record     Rule::Suspend, Admit, state ENTER
freeze     user tasks stop being picked
quiesce    devices go down through runtime PM
save       CPU and interrupt state the firmware will not keep
enter      the firmware call (PSCI SYSTEM_SUSPEND, SBI SUSP)
restore, unquiesce, thaw    in reverse
boot clock the slept time is added to the boot offset
record     Rule::Suspend, Admit, state RESUME
```

A step that fails undoes the steps before it, newest first, and the suspend is refused with a `Rule::Suspend` `Refuse` record. A refusal at a gate does nothing.

In this kernel every suspend is refused at the gates: riscv64 and aarch64 have no resume entry (`RESUME_ENTRY` is `None` in both `firmware.rs`), x86_64 cannot read `\_S3`, and `KernelSuspend::HAS_FREEZER` is `false`. The boot prints `[ENERGY] system suspend: not available (reason)`.

| `Reason` | Code | Cause |
|---|---|---|
| `Disabled` | 1 | not built in |
| `NoFirmware` | 2 | the firmware does not implement the call |
| `NoResumeEntry` | 3 | the kernel has no entry point for the firmware to resume at |
| `NoAcpiS3` | 4 | x86_64: S3 needs the DSDT's `\_S3` object, which only an AML interpreter reads |
| `CpusOnline` | 5 | a CPU other than the caller's is online (with `CPU_HOTPLUG`, take them off first) |
| `NoWakeSource` | 6 | the caller holds no interrupt capability |
| `FreezeFailed` | 7 | the user tasks could not be frozen |
| `DeviceBusy` | 8 | a device refused to go down (a live wakelock, or a failing callback) |
| `SaveFailed` | 9 | the CPU or interrupt state could not be saved |
| `EnterFailed` | 10 | the firmware answered with an error |
| `NoFreezer` | 11 | the scheduler cannot hold user tasks off the CPU |
| `InProgress` | 12 | another suspend is running |
| `Asserted` | 13 | a task holds a system power assertion (blockers: the live ones) |

**System power assertions** (`azos_energy::assertion`, the `powerassert` endpoint, `azos_devif::power_assert::PowerAssert`): the machine-wide form of a device wakelock. `hold(reason, ttl_ms)` (`WRITE`) keeps the machine out of system suspend; the owner is the calling task, the reason the holder's code (recorded, never interpreted), the timeout at most `POWER_ASSERTION_TTL_MAX_MS`, and each task holds at most `POWER_ASSERTIONS_PER_TASK` (16 in all). `release(id)` (`WRITE`) gives it back, its owner only; `stats(sel)` (`READ`) reads the counters. A refusal and a lapse (released by the kernel at the timeout, the holder silent) are `power-assertion` decision records. A separate endpoint from `power`, whose `WRITE` is the shutdown. User: `PKGD.ELF` holds one around every request it serves (reason `REASON_PACKAGE`).

In the kernel's platform (`KernelSuspend`), wake sources are the interrupt capabilities of the caller's table; `quiesce` has nothing to take down because no kernel-hosted driver implements runtime PM (the ring-3 half is the power service's, before it asks); `clocks` has no persistent clock, so a sleep the counter did not count is not known and is not invented. The associated constant `KernelSuspend::HAS_FREEZER` (`false`: no dispatch path skips a frozen task) selects the freeze step: `support()` returns `Reason::NoFreezer` after the firmware and resume-entry checks, and `freeze` returns an error. A refusal at that gate leaves a record like any other.

On a resume where the monotonic counter stopped, `slept_ns` (the persistent clock's advance minus the monotonic clock's) is added to the boot offset with `vdso_add_suspended`, so `CLOCK_BOOTTIME` includes the sleep ([time.md](time.md)).

Source: `crates/drivers/power/src/pm/suspend.rs`, `crates/drivers/power/src/pm.rs`, `kernel/src/boot/energy.rs` (`KernelSuspend`, `install_suspend`, `enter_firmware`), `crates/core/arch-x86_64/src/firmware/suspend.rs`, `config/arch/Kconfig.platform` (`SYSTEM_SUSPEND`), `crates/core/devif/src/power.rs` (`Power::suspend`).

## Battery

The signed topology's `[degrade.NAME]` rows (a level, the charge it is entered at, the charge it is left above) are handed to the policy at boot (`install_battery`, `Policy::init_battery`). The power service estimates the charge and reports it with the level it holds (`report_battery`).

* **Rows bind the level.** A reported level may not be lighter than the rows require at that charge: entering a level is not optional; leaving it is the service's, with its hysteresis. A change of level leaves a `Rule::BatteryDegrade` record (charge, level before, level now).
* **Reserve.** At or below `ENERGY_BATTERY_RESERVE_PCT` the kernel holds every performance domain at its lowest legal OPP and runs the deadline-floor governor, whatever range, cap or governor the policy set. The deadline and safety floors still win, so the reserve never starves an admitted reservation. A higher charge reported later lifts it. Neither the topology nor the service can lower it.
* **Report age.** The kernel keeps the age of the last accepted report (`battery_alive`, `check_report_age`). A report older than `ENERGY_BATTERY_REPORT_TIMEOUT_MS` holds the same reserve until the next accepted report, counted from boot, so a service that never starts is held the same way. A refused report is not a sign of life.
* **Scope.** Only a machine whose topology declares `[degrade.NAME]` rows has a battery for the reserve to apply to.

Source: `crates/core/energy/src/policy.rs` (`BatteryLimits`, `DegradeRow`, `report_battery`, `check_report_age`), `crates/core/sched/src/energy.rs` (`install_battery`, `policy_report_battery`), `kernel/src/boot/energy.rs` (`install_battery`), `userspace/services/power/src/battery.rs`, `config/kernel/Kconfig.energy` (`ENERGY_BATTERY_RESERVE_PCT`, `ENERGY_BATTERY_REPORT_TIMEOUT_MS`).
