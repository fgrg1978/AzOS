# Scheduler

The scheduler lives in `crates/core/sched` (crate `azos_sched`). It dispatches tasks over per-CPU ready queues, in five classes with a fixed precedence. This document describes the classes, the scheduling context, priority inheritance, CPU placement, and the module layout. Related documents: [time.md](time.md) for clocks and timers, [energy.md](energy.md) for idle states, frequency and placement by energy.

## Priorities and the ready queues

Every task has a priority number in `0..32`; a lower number is more urgent. Each CPU owns one ready queue per priority (32 FIFO lists) and a bitmap of the non-empty ones, guarded by that CPU's lock. A remote CPU may enqueue on the queue it does not own. With `SCHED_REMOTE_WAKE_DEFER` it tries the owner's lock once; if the lock is held (or earlier deferred wakes are pending) the task goes on the owner's lock-free deferred-wake list and the owner queues it when it takes the doorbell IPI, so no CPU spins with interrupts masked on another CPU's lock.

| Constant | Value | Meaning |
|---|---|---|
| `NUM_PRIORITIES` | 32 | priority levels |
| `RT_PRIORITY_THRESHOLD` | 12 | levels `0..12` are the real-time band |
| `DEFAULT_PRIORITY` | 16 | the fair level that weighs as nice 0 |
| `IDLE_PRIORITY` | 31 | the idle task's level |

Levels `12..31` are fair levels. Priority is the only per-task knob the dispatcher reads for the band and the fair class; the class itself is derived from priority and from whether the task holds a reservation (see [Dispatch classes](#dispatch-classes)).

Source: `crates/core/sched/src/task.rs` (constants), `crates/core/sched/src/scheduler/mod.rs` (`PerCpuSched`, `CPU_LOCKS`, `cpu_enqueue_locked`, `cpu_dequeue`, `enqueue_remote_aware`), `config/kernel/Kconfig.sched`.

## Dispatch classes

`sc::Class` is the dispatch class. The discriminant is the precedence rank; a runnable task of a lower rank takes the CPU from one of a higher rank.

| Rank | `Class` | Who is in it |
|---|---|---|
| 0 | `Stop` | a per-CPU stop task, and the kernel safety loops exempt from the band budget |
| 1 | `Dl` | tasks holding an admitted EDF + CBS reservation |
| 2 | `Rt` | fixed-priority band, priority `< RT_PRIORITY_THRESHOLD` |
| 3 | `Fair` | every other task, scheduled by EEVDF |
| 4 | `Idle` | the per-CPU idle task |

`sc::classify(prio, reserved, stop, rt_threshold, idle_prio)` maps a task to its class: stop first, then deadline if reserved, then idle if `prio >= idle_prio`, then `Rt` if `prio < rt_threshold`, else `Fair`. `classes::class_for` applies it with the build's configuration. The class is written where its inputs change (slot creation, base-priority changes, reservation admission and release), not on the switch path.

Classes can be compiled out with `SCHED_CLASS_DL` and `SCHED_CLASS_RT`. `SCHED_CLASS_STOP`, `SCHED_CLASS_FAIR` and `SCHED_CLASS_IDLE` are not optional (`classes.rs` asserts them). Without `SCHED_CLASS_RT`, band levels are scheduled as fair levels. `SCHED_DEFAULT` selects the class of a task created without a class request (by priority, fair, or RT).

Two class vocabularies exist and are separate types:

* `sc::Class` (this section) decides which queue the CPU is taken from.
* `class::SchedClass` (`SafetyCritical`, `HardRT`, `SoftRT`, `BestEffort`, `Idle`, `Interactive`) names the `[class.<name>]` sections of a signed topology; `SchedClass::from_name` parses them; the interactive class is declared as `session` (the interactive shell's row in the built-in topology; a signed topology of a deployment gets it only by declaring `[class.session]`; see [effects.md](effects.md)). The principal belongs to a topology class, so the shell needs a class name of its own. A task in `session` is dispatched as a fair task like `best_effort`, runs at the latency QoS tier (`SchedClass::qos_hint`, applied by `classes::on_row_class` where the row's class is written: slot creation and row application; the task may say otherwise with `SCHEDCTL`'s QoS hint afterwards), and reports `interactive` in `task_class_raw` and in the kernel's log lines, never `best_effort`. The tier decides the task's timer slack and its energy QoS domains; the fair queue's weight is not changed by it. Each task carries one as a raw byte (`Task::sched_class_raw`, `task_class_raw`), set from its topology row and read by admission checks, for example the refusal of a real-time caller on a proxy endpoint (`crates/core/syscall/src/ipc_deadline.rs`); the dispatcher does not use it.

The dispatcher (`do_schedule`) takes its pick from a fused path: `rt::pick` when the hart has real-time state, otherwise the ready-bitmap dequeue (`cpu_dequeue`), which hands the fair levels to EEVDF. `classes::pick_here` walks the same queues through the `SchedClassOps` table (`classes::TABLE`) in precedence order and is the class-by-class view of that decision; `sc::pick_in_precedence` and `sc::should_preempt` are the pure walk and the cross-class preemption rule. Each class implements `SchedClassOps` (`enqueue`, `dequeue`, `pick`, `tick`, `preempt_check`): `StopClass`, `DlClass`, `RtClass`, `FairClass`, `IdleClass`.

Source: `crates/core/sched/src/sc.rs`, `crates/core/sched/src/classes.rs`, `crates/core/sched/src/class.rs`, `crates/core/sched/src/scheduler/mod.rs` (`do_schedule`, `cpu_dequeue`), `config/kernel/Kconfig.sched` (`SCHED_CLASS_*`, `SCHED_DEFAULT_*`).

## Scheduling context

A task runs on a scheduling context (SC): `classes::SC[slot]`, one `SchedContext` per task slot. Its layout is frozen: `SC_SIZE` is 64 bytes on a 64-bit target (40 on a 32-bit one) and a compile-time assertion fails the build if a field is added. Every field is an atomic, because the wait-graph walk, admission and the inspection tools read it while the owner writes it.

| Field | Meaning |
|---|---|
| `budget_us`, `period_us`, `deadline_us` | reservation parameters (0 = none; deadline 0 = the period) |
| `prio_or_weight` | RT/DL: the level; set with the class by `set_class` |
| `class`, `flags` | `Class` discriminant; `SC_FLAG_TIMER_SLACK` |
| `qos_id` | the task's QoS hint (`QOS_DEFAULT`..`QOS_BACKGROUND`) |
| `blocked_on` | address of the `PiWaiters` the task waits on (0 = none); written only by the wait graph |
| `on_cpu` | CPU the SC runs on, `NO_CPU` if none; written at every switch with `WAIT_GRAPH` |
| `irq` | how many interrupt lines this SC serves (`irq_attach` / `irq_detach`) |
| `c_lo_us`, `c_hi_us`, `criticality`, `cluster` | reserved: nothing in the tree writes them |

The SC belongs to its task. The tree does not transfer budget from one SC to another; what a waiting client lends a server is priority (see [Priority donation and the wait graph](#priority-donation-and-the-wait-graph)).

### QoS hints and timer slack

`SYS_SCHEDCTL` with `SCHEDCTL_HINT_QOS` records a QoS hint (0..=3) in the caller's SC; it grants nothing and needs no capability. The timer-sleeper heap reads it: `sc::timer_slack_us` returns how long a timer armed by a task may fire after its deadline. Only the fair class has slack; stop, deadline, real-time and idle tasks get 0 whatever their hint, row or mode. `SlackMode` is `Off`, `Rows` (only a task whose topology row says `timer_slack = true`, recorded in `SC_FLAG_TIMER_SLACK`) or `All`. The heap arms a slack-tolerant sleeper at an instant it already wakes for, inside `[deadline, deadline + slack]` (`TimerHeap::coalesce_target`). Kconfig: `QOS_TIMER_TOLERANCE` (off: `Off`), `QOS_TIMER_TOLERANCE_ROWS_ONLY` (`Rows` instead of `All`; the default of the robot, industrial and automotive presets).

Source: `crates/core/sched/src/sc.rs`, `crates/core/sched/src/timer_heap.rs`, `crates/core/sched/src/timer_sleepers.rs`, `crates/core/abi/src/syscall_nr.rs` (`SCHEDCTL_HINT_QOS`, `QOS_*`), `crates/core/syscall/src/schedctl.rs`.

## Stop class

The stop class has two sources of tasks:

* a per-CPU slot, installed with `classes::set_stop_task(cpu, idx)` and read by `StopClass::pick`;
* the kernel safety loops marked with `rt::exempt_from_band_cap(idx)`. They are never skipped when the band budget is exhausted and are not charged to it, and their SC is `Class::Stop`.

In the fused dispatch the exempt loops are the stop class: `rt_core::stop_pick` keeps a running exempt loop, or takes a queued one past any running task, ahead of every reservation and band task; between two exempt loops the more urgent level wins. `StopClass::tick` and `preempt_check` never preempt: stop work runs to completion. The per-CPU slot is read by the class walk (`pick_here`); the fused dispatch does not consult it.

Source: `crates/core/sched/src/classes.rs` (`StopClass`, `set_stop_task`), `crates/core/sched/src/rt.rs` (`exempt_from_band_cap`), `crates/core/sched/src/rt_core.rs` (`stop_pick`, `stop_preempts`).

## Deadline class: EDF with CBS

A task holds a reservation `(runtime, period, deadline)` admitted by `rt::reserve`. Time is in microseconds at the interface and counter ticks inside. Each hart keeps its reservations in a set of up to `rt::SET_CAP` (16) entries and schedules them by earliest absolute deadline. Every eligible reservation ranks ahead of every band level (`rt_core::dl_rank` returns 0), so deadline order is across the whole hart; `edf_before` compares a rank and then the deadline.

### Constant bandwidth server

`rt_core::Cbs` is the per-task server:

* **Release rule.** When a task that blocked becomes runnable at `now`, it keeps its `(budget, deadline)` only if the deadline is ahead and the budget left fits the reserved density up to it (`budget / (deadline - now) <= q / d`); otherwise a new server period starts: `deadline = now + d`, full budget (`Cbs::release`).
* **Charge.** Run time is charged against the budget (`Cbs::charge`).
* **Overrun** (`Cbs::exhaust`). A *hard* server is throttled until its deadline and skipped by the pick; a *soft* server has its deadline postponed by one period and its budget refilled, and keeps competing. Overruns are counted.
* **Replenishment** (`Cbs::replenish_if_due`). A throttled server whose deadline has come gets a full budget and the next period.

### Admission

`rt::reserve(idx, Reservation)` admits at run time, on the first hart of the request's CPU mask (narrowed to the task's pin, or to the calling hart for an unpinned caller) that has room. It pins the task to that hart. The level test is the same code the boot admission of topology rows applies (`azos_topology::deadline`), so a set admitted at boot is admitted here.

| Check | Rule |
|---|---|
| shape | `q` and `t` non-zero, `q <= d <= t` (`rt_core::density_ppm`) |
| density | the hart's summed density `ceil(q * 1e6 / min(d, t))` plus the new one stays `<= 1e6` ppm (`rt_core::fits`) |
| band cap | a band task's reservations on one hart sum to at most `RT_BAND_CAP_PCT` of it |
| levels | reservations at different priority levels pass `levels_fit` (`azos_abi::rt_levels`), shared with the boot check |
| set | the hart's set has a free slot; the task holds no reservation yet |

A refusal is `rt_core::Refusal`; `Refusal::errno` gives the syscall result.

| `Refusal` | errno | Cause |
|---|---|---|
| `Malformed` | `EINVAL` | zero `q` or `t`, `q > d`, `d > t` |
| `NoRoom`, `BandCap`, `Busy`, `Levels` | `EBUSY` | no hart fits, band cap, already reserved or set full, level test |
| `ClassOff` | `ENOSYS` | `SCHED_CLASS_DL` is off (as `SYS_SCHEDCTL` answers for a class compiled out) |
| `Envelope` | `EACCES` | the Domain's `rt_time` envelope row holds a reservation of this density (reason 7, `envelope`; below) |

A run-time refusal is printed and, but for `Envelope`, written as a `Rule::DeadlineAdmission` decision record (`rt_core::refusal_numbers`). With Kconfig `EFFECT_WRITE_AHEAD`, `rt::reserve` first asks the effect gate whether the task's Domain may take a reservation of this density (the `rt_time` row of its scheduler class, [effects.md](effects.md)); a refusal there is `Refusal::Envelope` (`EACCES`, reason 7, `envelope`) and the gate's own `Rule::EnvelopeRtTime` record instead of the `DeadlineAdmission` one (`rt_receipt::held_by_row`, `rt_receipt::record_refusal`). With the `energy` feature, admission publishes `rt::ADMITTED_PPM[cpu]`, which the energy governor reads (see [energy.md](energy.md)).

### Entry points

`SYS_SCHEDCTL` (`sys_schedctl`) moves the calling task to a class (a target other than the caller is `EPERM`): `SCHEDCTL_CLASS_DL` takes a runtime and a period (the relative deadline is the period), `SCHEDCTL_CLASS_RT` and `SCHEDCTL_CLASS_FAIR` take a priority. DL and RT require a warrant with `WRITE` on a `time` endpoint, checked first; a refusal is recorded. Fair needs none but cannot leave the band or a reservation (`EBUSY`); its priority must be a fair level (`EINVAL` otherwise). Topology `deadline` rows reach `reserve` from the spawn path (`crates/core/syscall/src/spawn.rs`). With `IRQ_THREADED`, binding an interrupt line requires the binder to hold a hard reservation (see `config/kernel/Kconfig.sched`).

Source: `crates/core/sched/src/rt_core.rs`, `crates/core/sched/src/rt.rs`, `crates/core/abi/src/rt_levels.rs`, `crates/core/topology/src/deadline.rs`, `crates/core/syscall/src/schedctl.rs`, `crates/core/abi/src/syscall_nr.rs` (`SYS_SCHEDCTL`), `config/kernel/Kconfig.sched`.

## Real-time class: the band

Priorities `0..12` form the band. Dispatch inside it is strict priority, FIFO within a level, with no time slicing; a ready task of a more urgent level preempts (`RtClass::preempt_check`). The band is bounded by a per-hart budget (`rt_core::Band`): in each window of `RT_BAND_WINDOW_MS`, while a task outside the band is ready on the hart, the band may run at most `RT_BAND_CAP_PCT` percent. Past it, the pick skips the band levels until the window ends (`rt_core::band_throttled`). With nothing else ready the band keeps the CPU, and the overshoot is charged. A cap of 100 disables the budget. Enforcement instants (budget exhaustion, window end, reservation budget, replenishment) are armed with `timebase::arm_if_earlier`, which only writes the comparator when the instant is earlier than what the hart already has programmed.

Source: `crates/core/sched/src/rt_core.rs` (`Band`, `band_cap_ticks`), `crates/core/sched/src/rt.rs` (`pick`, `tick`), `crates/drivers/sys/src/timebase.rs` (`arm_if_earlier`), `config/kernel/Kconfig.sched` (`RT_BAND_WINDOW_MS`, `RT_BAND_CAP_PCT`).

## Fair class: EEVDF

Every task outside the band and idle is a fair task, scheduled by Earliest Eligible Virtual Deadline First. The arithmetic is `eevdf_core.rs` (no scheduler state); `fairq.rs` stores the per-task numbers and walks the ready lists.

* **Weight.** The priority maps to a weight through Linux's nice table (`WEIGHTS`, 1.25 times per level, 1024 at nice 0); `DEFAULT_PRIORITY` is nice 0 (`weight_of_prio`).
* **Virtual time.** A task's virtual runtime advances `dt * 1024 / weight` while it runs (`vdelta`). Its virtual deadline is `vruntime + slice * 1024 / weight` (`vslice`).
* **Pick.** With `V` the weighted mean of the virtual runtimes on the queue (the running task included), a task is eligible when `vruntime <= V`. The pick is the eligible task with the earliest virtual deadline (`choose`). A short slice means an early deadline, not a larger share.
* **Slice.** `FAIR_SLICE_US`. The timer tick is the preemption point.
* **Sleep and wake.** A sleeper keeps its lag (`lag_on_sleep`), clamped to two slices or one tick (whichever is longer), and rejoins at the mean adjusted by it (`place_wake`).
* **Queue.** The queue is the fair levels' ready lists; the pick is O(ready fair tasks on the hart). There is no tree.
* **Hook.** `fairq::qos_override` is the place where the SC's `qos_id` would choose weight and slice; it returns `None`.

Source: `crates/core/sched/src/eevdf_core.rs`, `crates/core/sched/src/fairq.rs`, `config/kernel/Kconfig.sched` (`FAIR_SLICE_US`).

## Idle class

Each CPU has an idle task at `IDLE_PRIORITY`. `IdleClass::pick` peeks the idle level and the class never preempts. The idle task enters a low-power state through the architecture's idle seam; see [energy.md](energy.md).

Source: `crates/core/sched/src/classes.rs` (`IdleClass`), `kernel/src/tasks/system.rs` (`idle_task`).

## Wake placement and wake preemption

**Placement.** A woken task goes to its pinned CPU if it has one (`cpu_affinity >= 0`). Otherwise `find_best_cpu` scores each online CPU with a `CpuLoad` of its resident tasks that outrank the one being placed and picks the lowest `(rt_blocking, blocking, total)` (`pick_cpu_by_load`). With `SCHED_O1_PLACEMENT` the score is read from a per-CPU, per-priority histogram of resident tasks (`resident_histogram`, kept current at every write to a field the score depends on), O(priorities) instead of a scan of every task slot. For a synchronous IPC hand-off, `ipc_wake_target_cpu` can co-locate the woken task with its waker (`SCHED_IPC_AFFINITY`) unless a resident outranks it. With `SCHED_EAS` the fair class is placed by energy first (see [Energy-aware placement](#energy-aware-placement)).

**Doorbell.** An enqueue on another CPU rings that CPU's scheduler doorbell (a software IPI); the target runs `schedule()` on its own state.

**Wake preemption.** A task made ready on the calling CPU is compared with the task that CPU runs, so it does not wait for the next tick. `wake_enqueue_preempting` queues and then calls `wake_preempt_check`, which asks `preempt::local_resched`; a positive answer sets the CPU's need-resched. `preempt::must_preempt` is the rule:

| Candidate vs running | Preempts when |
|---|---|
| different classes | the candidate's class has the lower rank |
| both `Stop` | never |
| both `Rt` | the candidate's priority number is strictly smaller |
| both `Dl` | the candidate's absolute deadline is earlier; if a deadline is unreadable, yes (the target decides on its own tick) |
| both `Fair` | never here; EEVDF decides on the tick |
| both `Idle`, or candidate `Idle` | never |
| nothing real running | any non-idle candidate |

A synchronous IPC hand-off does not run the check: its waker blocks right after.

Source: `crates/core/sched/src/scheduler/wake.rs` (`wake_enqueue_preempting`, `wake_preempt_check`, `wake_target_cpu`), `crates/core/sched/src/scheduler/wake/preempt.rs`, `crates/core/sched/src/scheduler/mod.rs` (`find_best_cpu`, `ring_doorbell`), `crates/core/sched/src/task.rs` (`CpuLoad`, `pick_cpu_by_load`), `crates/core/sched/src/resident_histogram.rs`, `config/kernel/Kconfig.sched` (`SCHED_O1_PLACEMENT`, `SCHED_IPC_AFFINITY`, `SCHED_REMOTE_WAKE_DEFER`).

## Priority donation and the wait graph

Two priority-inheritance mechanisms coexist. The wait graph is the one selected by `WAIT_GRAPH`; counted donation is the fallback of the clients that have one.

### Wait graph

`azos_sync::waitgraph` is one inheritance core for every object a task blocks on while another task owns it. A task blocks on at most one object (`SchedContext::blocked_on`). Each object embeds a `PiWaiters`: its owner and its waiters ordered by `PiAttr`, most urgent first. The effective attribute of a task is the most urgent of its base attribute and the top waiter of every object it owns. The owner runs on its own SC, boosted to that attribute.

`PiAttr` orders `Stop > Dl > Rt > Fair > Idle`; inside `Dl` the earlier absolute deadline wins, inside `Rt` the lower priority number. A boosted owner inherits a deadline donor's absolute deadline in the graph. Fair and idle donors boost nothing.

| `EdgeKind` | Client |
|---|---|
| `Mutex` | `azos_sync::kmutex::Mutex` |
| `FutexPi` | PI futexes (`pi_futex.rs`, `FUTEX_PI`) |
| `IpcCall` | a fast-IPC call blocked on its server (`azos_ipc::fastcall`) |
| `DriverProxy` | node type defined for driver proxy requests (the kernel's proxy uses counted donation, below) |
| `Claim` | a FAT32 claim held by its owner during device I/O |

**Walk.** A block, unblock, release or attribute change walks the chain from the affected owner: recompute its effective attribute; if it changed and the owner is itself blocked, re-sort it in that object's waiters and continue at that object's owner. The walk stops when nothing changes, at a task that is not blocked, or after `PI_MAX_DEPTH` steps (Kconfig, default 16); reaching the cap stops boosting there, the block succeeds, and the event is counted.

**Deadlock refusal.** If the walk reaches the task that started it, or an object it already visited, the block is undone and returns `WaitError::Deadlock` (`EDEADLK`). A `wait-cycle` decision record (`Rule::WaitCycle`) is written after the undo. A recursive acquire returns `WaitError::SelfOwned`.

**Scheduler side.** `classes::ClassPi` implements `SchedPi` over the classes and is registered at boot (`waitgraph::register_sched`). `base_attr` reads the SC class and the task's base priority (a DL task's deadline is read on the reservation's own hart). `pi_prio` turns the effective attribute into a priority number: `Stop` and `Dl` run at level 0, `Rt` at its own level, fair and idle do not boost. The boost is installed as a floor (`PI_PRIO[slot]`), and the live priority becomes `min(base, floor)`. A ring-3 owner's boost is held at `RT_PRIORITY_THRESHOLD` or less urgent (`graph_floored`). `ClassPiInline` serves the lock-free fast-IPC path, which uses a per-slot quiet key (`quiet_key`) to skip the walk when the call boosts nothing. Exit clears the task's graph state (`classes::on_task_exit`).

### Counted donation

`donation_for(donor, target)` gives a waiting donor's live priority to its target, once, and undoes it once when the wait ends; the target's priority moves only towards more urgent (`boost_step`), and the count rises on every donation so several donors can share one target. It is not transitive: nothing follows the target's own waits. A target already as urgent as the donation is not boosted, which is what stops an A-waits-on-B-waits-on-A loop. A ring-3 target is held at `RT_PRIORITY_THRESHOLD` at the most urgent (`floored`). `donation_for_call` judges a fast-IPC call against the target's base priority, so a second client's donation is still counted.

| Client | Mechanism |
|---|---|
| fast IPC call | wait graph (`Edge::lend`) with `WAIT_GRAPH`; `donate_priority_for_call_at` without |
| user-driver proxy | `donate_priority` / `return_donation` |
| kernel mutex, PI futex | wait graph; without `WAIT_GRAPH` the mutex sleeps and excludes but boosts nobody and PI futexes answer `ENOSYS` |

Source: `crates/core/sync/src/waitgraph.rs`, `crates/core/sync/src/pi_attr.rs`, `crates/core/sync/src/kmutex.rs`, `crates/core/sync/src/pi_futex.rs`, `crates/core/sched/src/classes.rs` (`ClassPi`, `ClassPiInline`, `pi_prio`, `graph_floored`), `crates/core/sched/src/donation.rs`, `crates/core/sched/src/scheduler/donation.rs`, `crates/core/ipc/src/fastcall.rs`, `crates/drivers/sys/src/user_driver_proxy.rs`, `kernel/src/boot/sched.rs` (`register_sched`, `PROXY_HOOKS`), `crates/fs/fs/src/fat32.rs`, `config/kernel/Kconfig.sync` (`WAIT_GRAPH`, `PI_MAX_DEPTH`, `FUTEX_PI`).

## CPU topology

`topo` answers "who is near this CPU?" once, at boot, for the balancer, energy-aware placement and core scheduling. Each firmware source reduces to one `CpuRaw` per CPU (opaque labels, equal when two CPUs share a level); `topo::build` turns the labels into masks with one rule for every source, and `topo::install` publishes them in atomics.

| `Level` | CPUs that | When the source is silent |
|---|---|---|
| `Smt` | are hardware threads of one core | the CPU alone |
| `Cluster` | share a cluster, module or tile | the core |
| `Llc` | share the last-level cache | the node |
| `Node` | share a memory node | the package |
| `Package` | sit in one socket | every CPU |

| `Source` | Origin |
|---|---|
| `Dt` | device tree `/cpus/cpu-map` and `capacity-dmips-mhz` |
| `Pptt` | ACPI PPTT |
| `Cpuid` | CPUID extended-topology and cache leaves, decoded by `CpuidShape` |
| `None` | no description: each CPU alone at the inner levels, one package |

Each level is a superset of the one before. Where a firmware describes levels that do not nest, groups are merged until they do and `Topology::irregular` reports it. Capacity is normalised so the largest CPU is `CAPACITY_SCALE` (1024); unless every CPU states it, all are 1024. `topo::mask(level, cpu)` and `topo::capacity(cpu)` read the installed topology. CPU ids are at most `topo::MAX_CPUS` (64).

Source: `crates/core/sched/src/topo.rs`, `kernel/src/boot/smp.rs`.

## Load balancing

With `SCHED_BALANCE`, queued fair tasks move between CPUs so that none idles while another has fair work waiting. The policy is pure (`scheduler/balance.rs`); the queue side is `fairq.rs`.

* **Pull** (`balance::pull`). A CPU about to idle walks the topology levels nearest first (`Llc`, `Node`, `Package`), takes from the busiest CPU of the first level with a gap, and stops at the first level that gave a task.
* **Push** (`balance::push`). A CPU with fair work queued hands one task to the least loaded CPU, with the same walk, at most once per `SCHED_BALANCE_INTERVAL_MS`, from the tick.
* **Gain test** (`balance::improves`). A move of weight `w` across `hop` levels requires `scaled(dst) + w * (1 + hop) < scaled(src)`, where `scaled` is load over capacity. Passes reach a fixed point and a moved task does not bounce back.
* **What may move.** Only queued, ready fair tasks that are not pinned, not a reservation, not mid-switch. Not a participant, as sender or receiver: an `isolcpus` CPU (`fairq::set_isolated_cpus`) and a CPU with real-time state (`fairq::rt_cpu`: a band task, an exhausted band window, an admitted reservation).
* **Bounds.** `SCHED_BALANCE_MOVES` tasks and `SCHED_BALANCE_SCAN` queue entries per pass. A sender whose lock is held is skipped (`Take::Busy`).

Source: `crates/core/sched/src/scheduler/balance.rs`, `crates/core/sched/src/fairq.rs` (`balance_idle`, `set_isolated_cpus`, `rt_cpu`), `kernel/src/boot/topology.rs`, `config/kernel/Kconfig.sched`.

## Energy-aware placement

On CPUs that differ in capacity, a woken fair task can be placed where the energy model says it adds the least energy. It applies when all of the following hold: `SCHED_EAS` is built in, a model is installed, the topology's energy mode is not `performance`, and the model is asymmetric (`energy::install` sets the gate). It never applies to real-time or deadline tasks or pinned tasks. The candidates are the online CPUs that are neither isolated nor hold real-time state, minus the CPUs the power policy parked, restricted to the domains the task's QoS class is mapped to. `EnergyModel::eas_pick` chooses among them; when it answers `Overutilised` (a candidate CPU's utilisation reaches `EAS_FIT_PCT` percent of its domain's fastest-OPP capacity, or the task fits none of them), `find_best_cpu` decides. Otherwise it compares, per performance domain, the CPU with the most spare capacity and the CPU the task last ran on, by the energy the task adds at the OPP the domain would need, and moves the task off its last CPU only for a saving of more than 1/16 of its cost there. The model, the policy and the mode are described in [energy.md](energy.md).

Source: `crates/core/sched/src/scheduler/wake.rs` (`wake_target_cpu`, `eas_wake_cpu`), `crates/core/sched/src/energy.rs` (`eas_active`, `eas_place`), `crates/core/energy/src/model.rs` (`eas_pick`, `EAS_FIT_PCT`), `config/kernel/Kconfig.sched` (`SCHED_EAS`).

## Core scheduling

With `SCHED_CORE`, the hardware threads of one core (the `Smt` mask, more than one CPU) run tasks of one Domain at a time. Each hart publishes the claim it is committed to (`topo::Claim`: the task's Domain key, strong for band and reservation tasks, idle compatible with everything). `CoreSched::admit` lets a hart take a claim only if every sibling's claim is the same Domain or idle; otherwise it answers `Admit::Refuse` with the siblings to ring. `topo::core_pick` filters a pick through that rule: a refused candidate is stashed, the next best is drawn (up to `SCHED_CORE_SCAN`), and with nothing that fits the running task keeps the CPU if compatible, else the CPU idles.

Real-time keeps priority: a strong claim displaces the siblings' fair tasks at once and is never displaced by a fair one. A fair candidate refused for `SCHED_CORE_PATIENCE_US` displaces its siblings the same way. The IPC direct switch is allowed on a core-scheduled hart only between tasks with the same claim (`core_direct_ok`). A hart with no SMT sibling is not affected.

Source: `crates/core/sched/src/topo.rs` (`Claim`, `Admit`, `CoreSched`, `core_pick`), `crates/core/sched/src/scheduler/mod.rs` (`core_smt`, `core_claim_of`, `core_direct_ok`), `config/kernel/Kconfig.sched` (`SCHED_CORE*`).

## Tickless busy CPUs (`NOHZ_FULL`)

A CPU of the topology's `[sched] isolcpus` that runs exactly one real-time task, with nothing else ready, can stop its periodic tick. The decision is taken at the tick itself, when the timer is re-armed:

* `nohz::lone_rt` requires: the CPU is isolated, the running task is in the band, no other level but idle is ready, and no wake is pending on its deferred list.
* `nohz::observe` stops the tick at the second consecutive tick that sees the same lone task (`LONE_TICKS_TO_STOP` is 2), because a task's first entry to user mode does not leave RCU's quiescent state as a trap return does.
* `nohz::stop_bound` sets how far out a stopped tick sleeps: `NOHZ_FULL_RESIDUAL_MS`, cut to hart 0's watchdog keepalive when armed and to the idle-poll bound while kernel work that only the tick observes is pending. The comparator is programmed at the earlier of that and the nearest timer deadline; timer sleepers and real-time enforcement instants are never rounded to it.
* The tick returns on an enqueue on the CPU (`timebase::tick_restart`), on a switch off the task, or when the stopped tick's own interrupt finds the CPU no longer alone.
* An isolated CPU's user mode is an extended quiescent state for RCU (`azos_sync::qsbr::set_tickless_cpus`), so no grace period waits for a tick it does not take.

Source: `crates/drivers/sys/src/nohz.rs`, `crates/drivers/sys/src/timebase.rs` (`set_tick_stop_hook`, `tick_stopped`, `tick_restart`), `crates/core/sched/src/scheduler/mod.rs` (`nohz_publish`, `nohz_tick_hook`), `crates/core/sync/src/qsbr.rs`, `config/kernel/Kconfig.sched` (`NOHZ_FULL`, `NOHZ_FULL_RESIDUAL_MS`).

## Timer sleepers

With `SCHED_TIMER_HEAP` (cargo `sched-timer-heap`), a task that sleeps on a timer is armed in an indexed min-heap (`timer_heap::TimerHeap`) on the CPU it blocks on, with one entry per task slot; each CPU has its own heap and lock (`SCHED_TIMER_HEAP_PER_CPU`; off, one heap for the machine). That CPU's tick pops the due entries, at most `SCHED_TIMER_WAKE_BATCH` per hold of the heap lock (`wake_expired_timers`), and `nearest_timer_deadline` feeds the tickless comparator. Entries are not removed when a sleeper is woken another way; the top entry is validated against the live task (`peek_live`) when it is reached. Without the heap, the tick sweeps every task slot. See [time.md](time.md) for the clocks the deadlines are read on.

Source: `crates/core/sched/src/timer_heap.rs`, `crates/core/sched/src/timer_sleepers.rs`, `crates/core/sched/src/wait.rs`, `config/kernel/Kconfig.sched` (`SCHED_TIMER_HEAP`, `SCHED_TIMER_HEAP_PER_CPU`, `SCHED_TIMER_WAKE_BATCH`).

## Module layout

The crate root (`lib.rs`) declares the model modules and re-exports the API. The dispatcher is `scheduler/`; several of its children are real files elsewhere in `src/`, pulled in with `#[path]` so they can reach the ready queues without widening their visibility.

| Module | File | Role |
|---|---|---|
| `class` | `src/class.rs` | topology class names (`SchedClass`) |
| `sc` | `src/sc.rs` | `Class`, `SchedContext`, `SchedClassOps`, precedence walk (pure) |
| `eevdf_core` | `src/eevdf_core.rs` | EEVDF arithmetic (pure) |
| `rt_core` | `src/rt_core.rs` | band budget, EDF + CBS, admission arithmetic (pure) |
| `rt_receipt` | `src/rt_receipt.rs` | writes the decision record of a refused reservation |
| `topo` | `src/topo.rs` | CPU topology and core scheduling policy (pure) |
| `donation`, `timer_heap`, `ready_list`, `wake_list` | `src/*.rs` | donation rule, timer heap, ready-queue and deferred-wake lists |
| `scheduler` | `src/scheduler/mod.rs` | dispatcher: pool, per-CPU queues, `do_schedule`, placement, doorbells |
| `scheduler::wake` | `src/scheduler/wake.rs` | block and wake paths, placement, reaper, timer sweep |
| `scheduler::wake::preempt` | `src/scheduler/wake/preempt.rs` | wake-up preemption rule (pure) |
| `scheduler::wake::attrib` | `src/scheduler/wake/attrib.rs` | wake attribution ring (`metrics/wake/`, Kconfig `WAKE_RING_ENTRIES`) |
| `scheduler::ipc_fast` | `src/scheduler/ipc_fast.rs` | fast-IPC hand-off and direct switch |
| `scheduler::lifecycle` | `src/scheduler/lifecycle.rs` | init, task creation, exit, wait, tick entry (`schedule`) |
| `scheduler::budget` | `src/scheduler/budget.rs` | task-state queries, frame budget, census |
| `scheduler::donation` | `src/scheduler/donation.rs` | donation cell, boost and restore, donation entry points |
| `scheduler::balance` | `src/scheduler/balance.rs` | load-balancing policy (pure) |
| `scheduler::rt` | `src/rt.rs` | band budget and EDF + CBS on the dispatch path |
| `scheduler::classes` | `src/classes.rs` | class implementations, SC table, wait-graph hooks |
| `scheduler::fairq` | `src/fairq.rs` | fair class queue over EEVDF |
| `scheduler::energy` | `src/energy.rs` | utilisation signals, installed model, policy (feature `energy`) |
| `scheduler::timer_sleepers` | `src/timer_sleepers.rs` | per-CPU timer-sleeper heaps (feature `sched-timer-heap`) |
| `scheduler::resident_histogram` | `src/resident_histogram.rs` | per-CPU, per-priority resident counts for wake placement |
| `scheduler::ipc_direct` | `src/ipc_direct.rs` | eligibility rule of the fast-IPC same-hart direct switch (pure) |
| `scheduler::tid_alloc`, `scheduler::slot_bitmap` | `src/tid_alloc.rs`, `src/slot_bitmap.rs` | TID candidate search, task-slot bitmap (pure) |
| `scheduler::lifecycle::{exit_note, stop_policy, signal}` | `src/exit_note.rs`, `src/stop_policy.rs`, `src/signal_state.rs` | exit bookkeeping, who may stop whom (`SYS_ALERT`), per-task signal words |
| `smp`, `wait`, `process`, `group`, `futex`, `futex_table`, `domain`, `spawn`, `task`, `asid` | `src/*.rs` | secondary CPU start and liveness, block API, processes, threads and futexes, task control block, address-space ids |
| `spawn_policy`, `filter`, `seccomp` | `src/*.rs` | `SYS_SPAWN_EX` decisions before a task exists, task-policy types, syscall filter profiles |
| `driver`, `supervisor` | `src/*.rs` | driver registry with heartbeat and crash bookkeeping, cold restart of ring-3 drivers |
| `qos`, `fp`, `pac`, `foreign`, `user_window` | `src/*.rs` | resource-partition tag at switch (riscv64 Ssqosid), riscv64 F/D state of Linux tasks, aarch64 per-process PAC keys, foreign-ABI entry and reflect, shm/MMIO VA window allocator |
| `swcensus`, `prof`, `cpuid_probe`, `percpu_audit` | `src/*.rs` | switch instruction census (`SWITCH_CENSUS`), fork/exit/wait phase profile (`fork-profile`), hart-id cross-check (`cpuid-probe`), per-hart read audit (`ktest`) |

Only the dispatcher's own state (`TASKS`, `PER_CPU`, the locks) lives in `scheduler/mod.rs`; children reach it through `use super::*`.

Source: `crates/core/sched/src/lib.rs`, `crates/core/sched/src/scheduler/mod.rs`.
