# Observability

What the kernel records about itself and how a developer reads it back. The
mechanisms, from "why was this refused" to "what was every CPU doing":

| Mechanism | Answers | Read with |
|-----------|---------|-----------|
| Decision records | Why did the kernel refuse, deny, admit or place this? | `why`, `tools/dev/perfetto_export.py` |
| Inspect tree and metrics | What are the kernel's current numbers? Why did that task wake? | `toolbox inspect`, `why woke` |
| Crash dumps | What state was a task in when a fault killed it? | `why crash` |
| Panic record | What happened when the kernel itself stopped? | `/fat/CRASH.LOG` |
| Sampling profiler | Where does the CPU time go? | `tracectl profile` |
| Trace | What happened, in order, on each CPU? | `tracectl stream` |
| Kernel log | What is the kernel saying right now? | The console, and `KLOGn.TXT` (`log`) |
| Flight recorder | What durable events and refusals preceded a reset? | `/LOG/LOGnnnnn.BIN` |
| Lockdep | Which lock order, interrupt-safety or hold-time rule did the kernel break? | The console |
| Fault injection | Does the kernel survive an allocation, IPC, timer or disk fault? | `chaos/` in the inspect tree |

Most of these are compile-time options (Kconfig symbols are named in each
section); a mechanism that is off is not linked. The authority model that decides
who may read them is in [security.md](security.md); update-time records are in
[update.md](update.md); network refusals in [network.md](network.md).

## Decision records

Source: `crates/core/decision/src/lib.rs`, `crates/core/decision/src/prov.rs`,
`crates/core/decision/src/query.rs`, `crates/core/decision/src/journal.rs`,
`crates/core/decision/src/deny.rs`, `kernel/src/boot/inspect_views.rs`,
`userspace/lib/decisions`, `userspace/services/decisd`,
`userspace/services/why`.

An admission, placement or refusal path writes one record: the rule that
decided (`Rule`), the verdict (`Verdict`: `admit`, `refuse`, `place`, `deny`),
the subject (a task id, a topology row, a CPU count; the meaning is per rule),
up to three numbers the rule compared, and, from the rule's table entry
(`RULES`, one `RuleInfo` per rule), the names of those numbers and the
alternative the rule rejected for each verdict.

**Storage.** There are two independent paths.

- **The ring** (Kconfig `DECISION_RECORDS_DEV`, kernel feature `decisions`)
  holds `DECISION_RECORDS_ENTRIES` records; the oldest is overwritten. It is
  lock-free so the wake path, which runs with scheduler locks held and
  interrupts masked, can write to it: a writer claims a sequence number, clears
  the slot's sequence word, writes the fields and publishes the sequence with
  release ordering; a reader keeps a slot only if the sequence reads the same
  before and after the fields. Records are numbers only, so a torn read is
  dropped, never misread. With the feature off, `record` is empty and the ring
  is not linked.
- **The durable path** (Kconfig `DECISION_REFUSALS_DURABLE`, kernel feature
  `decisions-durable`). A record whose verdict is `refuse` is also handed to a
  sink the kernel installs (`set_durable_sink`), which writes it to the flight
  recorder. The sink defers when the caller is real-time (it queues on the
  logger's ring and wakes the flusher), so a refusal never makes a real-time task
  wait on the medium. A `deny` (capability denial) goes there too, but can arrive
  per syscall, so it passes a token bucket per subject
  (`DECISION_DENY_DURABLE_PER_SEC`, `DECISION_DENY_DURABLE_BURST`). A denial the
  bucket drops is counted, and the count rides in the third number of the next
  denial record written; `deny_dropped_total` is the total. A record that reaches
  the durable path is also kept whole in a small RAM journal
  (`DECISION_JOURNAL_ENTRIES`), so a lookup can name it whether or not the ring
  is built.

**Ids and the clock.** A record that is stored anywhere claims a sequence number
first, its id, unique since boot. Ids restart after a reset; the flight
recorder's compact receipts carry the recorder's own timestamp. Each stored
record is stamped with the kernel clock (`set_clock`; nanoseconds of monotonic
time since boot until PTP or NTP has set an offset).

**Provenance record.** `ProvenanceRecord` (104 bytes, little endian) is the
record plus the fields that say who and what the decision was about. It exists
in three forms: the full form for readers on the host, a 13-word form that the
journal stores and the `Decisions` interface carries, and a compact form for the
durable receipt (20-byte flight-recorder payloads, two of them: a base with
rule, verdict, subject and the numbers, and an extension, written only when it has
something to say, with the image hash prefix and the topology row id). Which
fields are filled:

| Field | State |
|-------|-------|
| `rule`, `verdict`, `subject`, `n[3]`, `seq`, `clock_ns` | Filled by every record |
| `topology_row_id` | Filled by `placement` (the row's index plus one); 0 otherwise |
| `cap_slot`, `parent_cap`, `node_id`, `session_id`, `image_hash_prefix` | Part of the layout; no call site has the value, so they read 0 (the kernel keeps no image hash per task) |

**Rules.** `Rule` has 66 variants (numbers 0 to 65); the first three numbers are
what `RuleInfo::fields` names.

| Id | Name | Subject | Numbers | Records |
|----|------|---------|---------|---------|
| 0 | `deadline-admission` | cpus or tid | placed or runtime, rows or period, reason and available | Boot deadline admission of real-time rows |
| 1 | `rt-band-cap` | cpus | placed, cap percentage | The real-time band cap on one CPU |
| 2 | `memory-admission` | rows | need, free, reserve (pages) | Boot memory admission of ring-3 rows |
| 3 | `wake-placement` | tid | cpu, last cpu, priority | A woken unpinned task placed on another CPU than its last |
| 4 | `cap-denial` | tid | kind, reason, dropped | A typed capability check refused a handle |
| 5 | `deadline-expired` | tid | deadline, now, clock | An IPC call whose deadline had passed, refused before queueing |
| 6 | `split-lock` | tid | rip, cpu | A ring-3 locked atomic crossed a cache line (x86_64) and the task was killed |
| 7 | `cap-derive` | domain | expiry | A capability derived from another, rights attenuated |
| 8 | `cap-revoke` | domain | descendant | A capability revoked with its descendants |
| 9 | `neverallow` | row | rule, kind, grant | A topology refused for a forbidden grant |
| 10 | `device-admission` | device | bus, id, why | A detected device a driver table names and no row admits |
| 11 | `irq-budget` | tid | line, masked, overruns | A reservation serving interrupt lines ran out of budget |
| 12 | `placement` | row | move, measured, limit | A driver changed host, or was refused a move |
| 13 | `package-install` | rows | images, signer, reason | A signed package admitted or refused |
| 14 | `wait-cycle` | task | kind, owner, links | A wait that would close a cycle of owners was refused (`EDEADLK`) |
| 15 | `effect-deadline` | tid | effect, deadline, needed | A physical effect the device cannot commit within its deadline |
| 16 | `safe-state` | device | from, to, cause | A device driven into, or held out of, its safe state |
| 17 | `compensation` | tid | effect, action, status | A compensating action run or refused after a released effect failed |
| 18 | `receipt-caveat` | domain | caveat, age, limit | A receipt caveat on a delegated authority checked |
| 19 | `declassify` | domain | from label, to label, grant | A value moved to a lower information label, or refused |
| 20 | `shadow-refusal` | tid | rule, verdict, would-be | A refusal a rule in audit-only mode would have made |
| 21 | `subtree-policy` | node | policy, depth, action | A policy on a domain-tree node decided an operation under it |
| 22 | `remote-revoke` | node | domain, cap, epoch | A capability revoked on behalf of another node |
| 23 | `compress` | pages | pages, bytes in, bytes out | Pages compressed in memory |
| 24 | `swap-out` | pages | pages, reason, free | Pages written to the backing store |
| 25 | `kmem-charge` | domain | bytes, used, limit | Kernel memory charged to a domain's quota, or refused |
| 26 | `clock-step` | clock | clock, delta, limit | A clock stepped beyond its slew limit, or refused |
| 27 | `packet-refused` | iface | proto, reason, length | A packet dropped by the network rules |
| 28 | `guest-egress` | guest | kind, target, reason | A guest tried to reach outside its grant |
| 29 | `livepatch` | patch | patch, symbol, reason | A kernel livepatch applied or refused |
| 30 | `cpu-hotplug` | cpu | op, load, reason | A CPU taken offline or online, or refused |
| 31 | `suspend` | domain | state, blockers, reason | Suspend of the system or a domain |
| 32 | `battery-degrade` | mode | level, from mode, to mode | A drop to a lower mode on low battery |
| 33 | `provenance-meet` | tid | inputs, label, result | Labelled inputs combined, result given the meet of the labels |
| 34 | `effect-record` | tid | effect, reason, ring length | An effect refused because its record could not be committed first |
| 35 | `measured-boot` | pcr | stage, digest, how | A boot stage extended into a TPM PCR, or the extend failed |
| 36 | `hardening-fallback` | guard | isa | A hardware guard on the kernel's access to user memory (SMEP, SMAP, PAN) that the CPU lacks, with the boot going on without it |
| 37 | `pledge` | tid | mask, action, nr | A call refused by the pledge mask of the caller's Domain, at the trap prologue or on an `io_ring` entry (the action word says which), or the mask narrowed |
| 38 | `accel-admission` | tid | accel, need_kib, free_kib | A job admitted to, or refused by, an accelerator's memory and time budget |
| 39 | `tsn-admission` | stream | period_ns, frame_bytes, reason | A time-sensitive network stream admitted to a port's gate schedule, or refused |
| 40 | `envelope-config` | tid | op, key, level | A configuration key written, or the write refused by the Domain's `config` envelope row |
| 41 | `envelope-ota` | tid | step, slot, level | A step of applying an update (stage, switch) taken, or refused by the Domain's `ota` envelope row |
| 42 | `envelope-egress` | tid | dest, class, level | A Domain's first packet to a destination off the node refused by its `egress` envelope row |
| 43 | `envelope-delete` | tid | op, volume, level | A delete on a volume (cut, rename over a file, unlink, snapshot drop) refused by the Domain's `delete` envelope row |
| 44 | `envelope-rt-time` | tid | asked_ppm, ceiling_ppm, level | A real-time reservation refused by the Domain's `rt_time` envelope row |
| 45 | `freeze` | domain | op, tasks, reason | A Domain frozen or thawed, or the request refused |
| 46 | `thread-control` | tid | target, op, reason | A task acted on another (stop, resume, registers, memory, kill), or was refused |
| 47 | `login` | session | method, attempt, reason | A session opened, or an attempt refused |
| 48 | `key-use` | tid | key, op, reason | A key used (sign, decrypt, derive, wrap, export), or the use refused |
| 49 | `mem-pressure` | domain | level, free_pages, action | The memory pressure level changed and the action it calls for |
| 50 | `purge` | domain | what, bytes, reason | Cached or secret data purged, or the purge refused |
| 51 | `wipe` | device | how, bytes, status | Storage or a device wiped, or the wipe refused |
| 52 | `mission-energy` | tid | need_mj, left_mj, reserve_mj | An activity admitted against the mission's energy, or refused for the reserve |
| 53 | `deferred-activity` | tid | kind, wait_ms, reason | An activity deferred to an idle or charging window, or run now for its deadline |
| 54 | `time-protection` | domain | from, to, mechanism | Timing-carrying state flushed or partitioned on a Domain switch, or not possible |
| 55 | `attest` | tid | scope, nonce, reason | A quote of the measured state given to a verifier, or refused |
| 56 | `boot-chain` | stage | version, floor, reason | A boot chain link verified before it ran, or refused; stage 6 is the CPU microcode (revision after, revision before, outcome and CPU) |
| 57 | `ras` | cpu | kind, addr, action | A hardware error report and the action taken on it |
| 58 | `fieldbus` | bus | node, id, reason | A fieldbus node or frame admitted, or refused |
| 59 | `audio-capture` | tid | device, rate_hz, reason | An audio capture stream admitted, or refused |
| 60 | `focus` | tid | from, to, reason | The input focus moved, or a request to take it refused |
| 61 | `usb-authorize` | port | vid_pid, class, reason | A USB device authorized to bind a driver, or refused |
| 62 | `block-timeout` | device | sector, waited_ms, action | A block request timed out and the action taken (2 device reset, 3 request failed, 4 device offline, 5 latched with its resets spent, 6 the reset did not bring it back) |
| 63 | `clock-set` | tid | clock, new_ns, reason | A clock set outright, or the set refused |
| 64 | `estop-release` | - | cause, floor, nonce | A verified e-stop release refused because its nonce floor could not be made durable |
| 65 | `thermal` | zone | event, arg, temp_mdeg | A trip fired (place), a domain the floors keep hot, a level raise, a lost sensor or the shutdown request (refuse), or the relaxation of any of them (admit) |
| 66 | `durability` | record | from, to, flush | A record that must survive a power cut (1 the topology counter floor, 2 the CONFIG.SIG floor) written to a device that cannot confirm the flush (`flush` 1: `Unsupported`): refused, the floor stays the old one this boot |
| 67 | `net-timeout` | device | pending, waited_ms, action | A NIC's transmit ring wedged and the action taken (2 device reset, 5 latched with its resets spent, 6 the reset did not bring it back) |
| 68 | `usb-host-fault` | device | cause_trb, waited_ms, action | A USB host controller left a command unanswered or reported a host system / host controller error (`cause_trb`: cause 1 timeout, 2 HSE, 3 HCE in its second byte, the unanswered command's TRB type in its first), and the action taken (2 controller reset and its devices enumerated again, 5 latched with its resets spent, 6 the reset did not bring it back) |
| 69 | `call-admission` | tid | deadline_ns, alt, kind<<32+server | A v2 call refused because its server's scheduling context cannot meet the remaining deadline; `alt` is the counter-offer (kind 1: a deadline in ns, 2: a budget in us) |
| 70 | `opp-apply` | domain | choice, target, outcome | The energy governor's OPP choice stopped reaching the clock (the actuator refused it: refuse; no apply step answered it by `ENERGY_APPLY_DEADLINE_MS`: deny, `outcome` 6) or reaches it again (admit); `target` 255: no apply step answered |
| 71 | `power-assertion` | task | reason, ttl_ms, id | A system power assertion (keep the machine out of system suspend) refused by its quota, or released by the kernel at its timeout with the holder silent; a grant is not recorded |
| 72 | `nic-queue` | tid | ifindex, queue, why | A program refused a NIC queue that carries the node's own stack (1) or the route to its link peer, the e-stop's path (2) |
| 73 | `clocksource` | clock | reason, drift_ppm, limit_ppm | x86_64: the TSC refused as the clock at boot (not invariant) or demoted by the watchdog (it drifted from the HPET or the PM timer) (refuse), or kept though not invariant because nothing else can be read (admit) |
| 74 | `ioport-reserved` | tid | first, last, kernel_port | A topology row's I/O port grant refused: the range holds a port a kernel driver bound (COM1, the CMOS clock, PCI configuration, the 8042, the PIT's channel 0) |

**Reading them.**

- The introspection tree's admin region holds the newest 24 records whole and
  binary (`decisions/records/<n>`, `ProvenanceRecord::to_bytes`, record `id` in
  slot `id % 24`: from the ring, or the durable journal), each written where it
  is recorded (`azos_decision::set_view_sink`); the public region has the counts
  (`decisions/{recorded, deny_dropped}`). The admin
  region is the one that may name a task, and a record's subject may be one.
- `DECISD.ELF` serves the `Decisions` object (`userspace/lib/decisions`) over the
  `endpoint.decisions` endpoint to any row holding a call capability (`WRITE`) on
  it. `query` lists ids matching a `Filter` (rule, verdict, subject, an
  exclusive `after` id) a page at a time; `get` returns one record in two parts
  (a reply holds seven words and a record is thirteen), re-asked if the slot was
  rewritten in between. On each request the server reads the records again;
  the kernel writes a record into the region before its caller goes on, so a
  request sees every decision made before it without waiting for a refresh. No
  text is parsed on either side.
- `WHY.ELF` is the client:

```text
why [--remote]       the latest decisions, one line each
why ID               the chain behind decision ID
why list [-r RULE] [-v VERDICT] [-s SUBJECT] [-a AFTER_ID]
why crash [TID]      the minidump of a task a fault killed
why woke [N]         the last N logged wakes with their source, Domain and age (task IDs with the admin right)
```

`why ID` prints the chain from the record: rule, verdict, subject, the numbers
the rule compared, the capability slot and its parent, the topology row, the image
hash prefix and the clock, with `-` where a field has no value. Exit status is 0,
1 when the decision is not held, 2 on a usage error or missing endpoint, 3 when
the server failed. With `--remote` it asks the peer node's decision server
through the proxy endpoint `endpoint.rpc-decisions`; a lost link is
`NoConnection`, not a dead server.

The recovery console reads the same data with `why [id]`.

## Inspect tree and metrics

Source: `crates/core/inspect/src/lib.rs`, `crates/core/inspect/src/format.rs`,
`kernel/src/boot/inspect.rs`, `kernel/src/boot/inspect_metrics.rs`,
`userspace/lib/inspect`, `userspace/services/toolbox`, Kconfig `INSPECT`.

The introspection tree is what the kernel knows about itself, as data a program
reads without a system call. A **region** is a block of memory (a `MemObj` the
kernel created and alone writes) holding one tree of typed nodes (`Kind`:
directory, `u64`, `i64`, string, bytes, histogram). A reader maps it read-only and walks
it with loads: no syscall, no copy, no lock.

**The regions** have the same layout and no shared byte:

| Region | Handed to | Holds |
|--------|-----------|-------|
| Public (`Class::Public`) | Any task whose topology row has `MemObj inspect.public` (`READ|MAP`) | Counters, gauges, the devices, the drivers, the system's identity |
| Admin (`Class::Admin`) | A task that also holds the full task view | Subtrees that name other tasks: the task list, the wake log, the decision records |
| A view (`inspect.names`, `.rpc`, `.mcp`, `.components`, `.logins`, `.clock`) | Only the rows that declare it | The signed topology's wiring one service needs (`kernel/src/boot/inspect_views.rs`) |

There is no `/proc` and no `/sys`: apart from the log and trace rings, these
regions are the kernel's only read-out of its state. A Linux binary's `/proc` is the Linux runtime's
(`userspace/lib/linux_rt`, ring 3), and it answers only `/proc/self/exe`.

The admin region is not a flag on public nodes, so a reader of the public one has
nothing to be refused. A task finds the capability with the capability lookup
(`SYS_CAP_INFO`, query `CAP_INFO_LOOKUP`; `azos_libsys::cap_lookup`) for type
`Shm` and the key `SHM_INSPECT_PUBLIC`, `SHM_INSPECT_ADMIN` for the admin
region or `SHM_INSPECT_<VIEW>` for a view, then acquires and maps it read-only
(`azos_libsys::inspect_map`). Before a
region is published, the kernel opens it the way a ring-3 reader does and
publishes nothing for a region that fails.

**Consistency** is two seqlocks. The epoch (header word 2) covers the tree's
shape; a shape change is a rebuild, during which the epoch is odd. A reader holds
the epoch it opened under and every operation ends by checking it; a change is
`Error::Restructured` (reopen with `Reader::refresh`, look nodes up again, since
ids belong to one epoch). Each node has its own sequence number covering its value,
so a histogram or string is read whole; writers claim it with a compare-exchange,
and a reader that finds it odd for `SPIN_MAX` reads gets `Error::Contended`
instead of spinning on a preempted writer. Every access is an atomic access of an
aligned 64-bit word. The header carries `FORMAT_VERSION`, and `Reader::open`
refuses any other version.

**The tree.** Its shapes are built once, at boot, and never rebuilt. What a
reader acts on is written where it changes, before the change's caller goes
on (below); the counters are sampled by an `inspect` task every
`INSPECT_REFRESH_MS` (a task rather than a timer hook, because the census walks
every task slot), pinned off the real-time CPUs.

```text
inspect/{format_version, refresh_ms, refreshes}
sched/{tasks_ready, tasks_blocked, tasks_running,
       cpu/cpuN/{runq_len, moved_in, moved_out, rt_load_ppm, rt_band_ppm}, blocked_on/{...},
       rt/{...}, balance/{...}}
memory/{page_size, pages_total, pages_free, pages_used, peak_user_pages,
        quota_refusals, domains}
decisions/{recorded, deny_dropped}
system/{version, platform}
fs/tmpfs/{files, used_bytes, max_bytes}
drivers/<slot>/{kind, name, isolation, perms}
devices/<handle>/{name, identity, state, driver, base, size, irq}
chaos/{seed, <point>/{rate, checked, fired}}                (CHAOS)
soc/{up, clocks, resets, ...}                               (SOC_FRAMEWORKS)
thermal/{status, board, ticks, level, shutdown, records, zones/<z>/active, domains/<d>/{cap, opp}}   (THERMAL)
latency/{irqsoff, preemptoff}/{max_ns, hart, windows, unpaired, start, end, top/<n>/{max_ns, count, site}}   (LAT_TRACE)
metrics/...                               (below)
admin: sched/tasks/<row>/{tid, name, state, priority, parent}   (64 rows, or MAX_TASKS; tid 0: a free row)
admin: wake/{now_us, rN}                                    (WAKE_RING_ENTRIES: the wake log with task IDs)
admin: decisions/records/<n>                                (the newest 24 records, bytes; record id in slot id % 24)
```

The views, each its own region:

```text
inspect.names       endpoints/<name>/{index, server}, imports/<badge> = "name,..."
inspect.rpc         endpoints/<name>/{index, server}, peers/<n>/{class, node, noise_pk}, exports/<n>/{endpoint, class}
inspect.mcp         endpoints/<name>/{index, server}
inspect.components  components/<n>/{image, restart, serves, needs, dir, start}, components/rows
inspect.logins      logins/<n>/{user, key}
inspect.clock       clock/ptp_domain
```

A view lists the named endpoints the rows declaring it hold; the reader
checks its own table for the handle and its rights.

**Written on change.** No reader waits for a refresh, and none sees a value
older than its last change:

* the task list, at each task made, become a zombie, freed, re-linked to a
  reaper or swapped at an exec (`azos_sched::set_task_view_hook`,
  `kernel/src/boot/inspect_tasks.rs`); a spawn's caller finds its child, and
  a reaped child is gone, when the call returns;
* a view's `endpoints/<name>/{index, server}`, at each change in the endpoint
  pool, under its lock (`azos_ipc::endpoint::set_view_hook`): the endpoints a
  row's spawn created are in its view before it runs;
* a component's `start`, when the boot launcher finds its image missing;
* a decision record, where it is recorded (`azos_decision::set_view_sink`).

The writes are atomic stores under each node's seqlock and take no other
lock, so they run under the scheduler's and the pool's locks and on the wake
path. A listed task's state (ready or blocked) and effective priority move at
every switch: they are sampled with the counters, every `INSPECT_REFRESH_MS`.

The per-CPU number is the length of the CPU's run queue; the scheduler keeps no
per-CPU dispatch counter.

**`metrics/`** holds counters and gauges the subsystems already keep, as
read-only nodes. Nothing runs per event: the values are read once per refresh
and no source gets a hook. A source that is not compiled in has no node.

```text
metrics/trace/cpuN/{records, drops}                         (KTRACE)
metrics/sched/{switches_voluntary, switches_preempted, migrations}
metrics/energy/{gov/..., idle/..., domains/dN/opp}          (energy model)
metrics/net/{packet/{delivered, dropped}, rx_drops/.., arp_txq/.., ethN/{mtu, attached, configured}}
metrics/memory/{zones/.., zpool/..}
metrics/decisions/{lost, unknown_rule, by_rule/<rule name>}
metrics/syscalls/{unshown, dN/{domain, none, authority, block_wake}}   (DOMAIN_ENTRY_COUNTERS)
metrics/storage/{written_bytes, unowned_bytes, unshown, dN/{domain, written_bytes}}
metrics/sync/<site>/{expired, lost}                         (bounded sleeps)
metrics/wake/{total, offered, now_us, unshown, sources, dN/{domain, wakes, per_s}, rN}   (WAKE_RING_ENTRIES)
```

A counter node never decreases. A 32-bit source is widened so a wrap is not a
drop. The scheduler keeps switch counts per task and a slot's counts leave with
its task, so `SwitchTally` adds each task's growth since the last refresh; a task
that ran and exited between two refreshes loses its last stretch, so the count is
a lower bound. The decision recorder keeps a ring and no per-rule count;
`RuleTally` walks the records written since the previous refresh, and a record
the ring overwrote before the walk got to it is counted in `decisions/lost`.
`sched/migrations` is the count of the `wake-placement` rule.

**`metrics/syscalls/` and `metrics/storage/`** are per-Domain groups, the one
exception to "a counter never decreases". A group `dN` is bound to a Domain the
first time a refresh finds it with kernel entries (or block writes) and keeps it
until the Domain ends; its values are that Domain's and start again with the next
one (`domain` names it); Domains past the `DOMAIN_GROUPS` (4) groups are counted
in `unshown`. `syscalls/dN` counts the Domain's kernel entries by foundational
case (`none`, a Linux task's number with no case; `authority`; `block_wake`).
`storage/` is the write ledger (`azos_sched::domain::add_written`): the bytes of
block writes the device completed, the device total (`written_bytes`), the part
no live Domain owns (`unowned_bytes`), and each group's share.

**`metrics/sync/`** is the lost-wake evidence. A sleep that waits for another
task or a device (the block request layer's waiters, the FAT claims, the pager's
store and swap waits, `Claim`, the controller turn queue, the ADS1115 bus) is
bounded by one slice (`WAIT_SLICE_US`, 1 ms) and counted per site when it ends
at its deadline with no wake: `expired`. `lost` is the part of them whose
condition had already become true, the event that happened and whose wake did
not come within a slice. A boot that ends with every `lost` at 0 refutes a lost
wake at those sites; a nonzero one names the site (a waker delayed past a slice
between publishing and waking counts too, so read it on an idle board first).
The sleeps of a lock, the log flusher and the RCU callback task carry no
deadline: their wake is proven in place (comment at each site).

**`metrics/wake/`** is the wake attribution (`crates/core/sched/src/scheduler/wake/attrib.rs`,
Kconfig `WAKE_RING_ENTRIES`; 0 compiles it out). Every wake of a blocked task,
at the four places the scheduler makes one (the TID-directed wake, the sweep, the
wait queue, the K-C25 reaper), is counted in the Domain of the task it woke
(`dN/wakes`, exact, with `per_s` the rate over the last refresh; `total` is the
machine's) and, if the ring takes it, logged with its source: `timer` (a
deadline passed), `irq` (an event of a bound interrupt line, the line in the
entry), `isr` (an interrupt handler of the kernel itself), `ipc_call` /
`ipc_reply` (the peer in the entry), `futex`, `notify` (a word of a shm region),
`ring`, `port`, `waitq`, `wake` (any other wake of a timed sleeper: a signal, a
stop request) and `reap`. `rN` is the N-th newest logged wake, a histogram node of
`[seq, at_us, src, line, domain, cpu, from_cpu]` (`src` indexes the names in
`sources`; `line` is the interrupt line of an `irq` wake, else 0; `domain` the key
of the Domain of the task woken, the same as a `dN/domain`, 0 for a kernel task;
`cpu` the CPU the task was queued on, `from_cpu` the CPU that woke it); `now_us`
is the clock when the values were written. **The public region carries no task
ID**: it is one set of words for every task that maps it, so it cannot show a
reader its own Domain's tasks and hide the others'; it shows none (owner
decision 21-10: a program without the admin right sees the waker only for its
own Domain, and the other Domains' wakes only as counters and a source). The
task IDs are in the admin region, behind the task view (`wake/rN` there is the
same row followed by `[tid, waker]`: the task woken and the task that woke it,
0 when the source names none; only the entries the ring has are nodes). The machine's own wakes are all logged; the wakes tasks make
(an IPC round trip makes two) one in `2^WAKE_RING_SAMPLE_LOG2` per woken Domain,
by the Domain's count, so a busy hand-off pays for the count and one test and the
ring is not filled by it (`offered` counts the wakes the ring was offered; one
that found its slot taken by another wake is offered and not logged, and leaves a
gap in the `seq`s). The ring is
lock-free: a ticket from one atomic add, a swap that takes the slot (a wake that
arrives a lap late finds it taken and writes nothing), the stores, the tag last; a
reader drops an entry whose slot a later wake began to reuse, so it never gets a
mixed one. A wake that finds its target not yet asleep is stamped, not delivered, and is
not a wake. `why woke [N]` (`WHY.ELF`, `userspace/services/why/src/woke.rs`)
prints the last N logged wakes (source, the Domain woken, the CPU, the age; with
the admin region in its row also the waker and the task woken, else a `(admin)`
where the waker would be) and says at the head of the listing which view it read.
It lists the first Domains the tree publishes (`DOMAIN_GROUPS`, in the order they were bound, not ranked by wakes). The line of an `irq` wake is the one
`irq_dispatch` announces around the delivery; the event on the driver's port
carries the CPU the line is routed to (byte 9 of the 16-byte event).

**Reading it.** `TOOLBOX.ELF`'s `inspect` applet (`inspect [-j [-t MS] [-p MS]]
[PREFIX]`) prints the tree, a subtree such as `metrics`, or with `-j` a Perfetto
counter trace. `ps` reads the task list from the admin tree. The library
`azos_inspect_lib::Inspector` answers paths over both regions as one namespace
and repeats a read that meets a rebuild (`RETRIES` times).

## Crash dumps

Source: `crates/core/recovery/src/crashdump.rs`, `kernel/src/trap/crash.rs`,
`userspace/services/why`, Kconfig `CRASHDUMP`.

A fault that kills a ring-3 task leaves a minidump. A kernel panic is not a
dump; it keeps `/fat/CRASH.LOG` (next section).

**Contents** (`AZCD`, version 1, little endian): the registers of the trap, a
bounded window of the stack from the stack pointer up, the task's maps (runs of
mapped pages with permissions; the executable run holding `pc` gives the image's
load address, which turns `pc` into a symbol), the last decision records whose
subject is the task or its process (why the kernel refused or denied what it did
just before), the SHA-256 of the task's
image (the key the symbol file of that exact build is stored under), the task
name, cause, CPU and tick count, and a CRC-32. The bounds are Kconfig
(`CRASHDUMP_STACK_BYTES`, `CRASHDUMP_MAPS`, `CRASHDUMP_DECISIONS`). The layout
module names nothing but `core`, so the kernel encodes with it, `why` decodes with
the same source, and the host tests run it unchanged.

**On the fault path** (`capture`, before the kill tears the task down): the
registers, the stack window (read through the page table without committing or
copying a page), the maps, the decision records and the image hash go into a
slot of the crash ring (`CRASHDUMP_RING`). There is no I/O, no allocation and
no lock but two capability and tree tables, so a faulting real-time task never
waits on a device. First of all a 32-byte record (task, status) goes on the
flight recorder's ring, queue only; once the log flusher has written it out, a
reset does not lose it.

**Off the fault path** (`drain`, a job of the log flusher task): the dump is
written as `CRASHn.DMP` in the root of the first write tree the faulting domain
holds (a `Cap<Dir>`, never a global path), resolved at the fault. A domain whose
row holds no write tree has nowhere to put a dump and takes no ring slot; the
flight-recorder record is all it leaves. The files are a ring of
`CRASHDUMP_FILES` slot names, so a crash loop cannot fill the volume. A ring slot
is a state machine (`FREE`, `FILLING`, `PENDING`, `WRITING`, `DONE`) rather than a
lock, since the fault path may run on several harts; when every slot is busy the
oldest waiting one is overwritten and the drop is counted.

`why crash [TID]` reads the dump files beneath the read-only root directory its
row holds and prints the report.

## Panic record and crash log

Source: `kernel/src/panic.rs`, `crates/fs/src/crash_log.rs`,
`kernel/src/pstore.rs`, `crates/fs/src/pstore.rs`, Kconfig `PSTORE_SIZE_KB`.

- **`/fat/CRASH.LOG`** collects one entry (at most 512 bytes) per kernel panic.
  Appending is capped at `CRASH_LOG_CAP` (64 KiB, 128 entries). When an append
  would exceed the cap the current contents move to `/fat/CRASH.OLD` (best
  effort) and the log is replaced by just the new entry; the new entry is recorded
  even if the copy fails. The decision (`plan_rotation`) is a pure function of two
  sizes and a cap, so it runs on the host.
- **pstore.** With `PSTORE_SIZE_KB` non-zero (default 4 on QEMU, 0 on boards), the top of the RAM range the boot
  found is taken out of the page allocator and holds a panic record that survives a
  warm reboot. The panic handler writes it with no lock and no allocation (one
  atomic claim, so a second panicking hart cannot tear it). After `/fat` mounts,
  `recover` appends a valid record to `CRASH.LOG`, reports a damaged one, and
  clears the region. A contained panic (`PANIC_POLICY_CONTAIN`) stores a record
  that is cleared again once the file has the entry.
- **Quiesce.** With `PANIC_QUIESCE` (default y) the reset path claims the console
  and rings every other CPU to park, waiting at most `PANIC_STOP_WAIT_US`, before
  it prints, so two reports never interleave; the report ends with
  `[PANIC] other CPUs parked: n/m`.
- **Backtrace.** With `PROFILER` on, the panic path and every fatal trap print the
  panicking CPU's own call chain with the profiler's walker (`prof::backtrace`);
  `tools/dev/symbolize_bt.py <kernel ELF> <console log>` turns the addresses into function, file and
  line, undoing the KASLR slide the log's `[KASLR]` line gives.

## Sampling profiler

Source: `kernel/src/prof.rs`, `crates/core/trace/src/prof.rs`,
`userspace/services/tracectl/src/profile.rs`, the ISA crates' `pmu.rs`,
Kconfig `PROFILER`, `PROFILER_DEPTH`, `PROFILER_TICK_DIV`, `PROFILER_PMU`,
`PROFILER_PMU_PERIOD`, `RV_SSCOFPMF`.

The profiler is the trace class `prof` (bit 7 of the runtime mask). It needs
`KTRACE`. The scheduler tick of each ISA calls `on_tick` with the PC, frame
pointer, stack pointer and mode (user or kernel) of the code it interrupted.
While the class is on, every `PROFILER_TICK_DIV`-th tick on a CPU walks the
frame-pointer chain and writes one sample (a header record plus the frames, two
to a record) into that CPU's trace ring. Class off, or `PROFILER` off, the hook
is the mask test or nothing at all. The tick runs with interrupts masked, so a
sample's records follow one another; no lock is taken and nothing is allocated,
which is why the user stack is read through its page table without committing a
missing page.

**The walk** (`prof::walk`) believes a link only when the frame pointer is
non-zero and aligned for the ISA, both words of the record lie inside the stack
the sample came from, the pointer is above the previous frame's, the memory read
succeeds, and the return address points into code. The first failing check ends
the walk and the sample says which (`Stop`). A function interrupted before its
prologue or after its epilogue skips its caller. A kernel-mode sample is bounded
by the interrupted stack pointer and the top of the running task's kernel stack
(or this CPU's interrupt stack); a user sample by the user stack pointer and
the stack's size. With `PROFILER` on, the build keeps a frame pointer in every
function of the kernel and user images (`-C force-frame-pointers=yes`,
`tools/build/kconfig_to_cargo.py`). The sampling rate is the
scheduler tick divided by `PROFILER_TICK_DIV`, exact only to the tick: code
running with interrupts masked is sampled at the instruction that unmasks them.

**PMU sampling** (`PROFILER_PMU`, default on with `PROFILER`). A tick-driven
sample cannot see a hot path shorter than a tick, and it is in phase with the
work the tick itself wakes. Where the CPU's PMU can interrupt on an overflow,
a counter of its own (never the cycle counter `Pmu::cycles` readers share)
counts core cycles and interrupts every `PROFILER_PMU_PERIOD` of them; that
interrupt takes the sample, the same walk and record, and the CPU's tick takes
none. The CPU's own tick arms it once the class is on; once the class is off,
the next overflow disarms it, so with the profiler off nothing is armed. The
counter count and widths are the boot probe's (`[PMU] ... sample=<bits>` or
`sample=none`):

| ISA | Counter | Interrupt | Probe |
|-----|---------|-----------|-------|
| riscv64 | an `hpmcounterN` from SBI `counter_config_matching` (CPU_CYCLES), loaded by `counter_start` | LCOFI (`scause` 13), `scountovf` names the counter | `RV_SSCOFPMF`: the `riscv,isa` token, then a trap-safe `scountovf` read; also `RV_PMU`'s programmable counter |
| aarch64 | the last PMUv3 event counter (`PMCR_EL0.N - 1`, `N >= 3`), CPU_CYCLES | the DTB `pmu` node's PPI; `PMOVSSET_EL0` / `PMOVSCLR_EL0` | `A64_PMU` and the DTB |
| x86_64 | Intel PMC1 (UnHalted Core Cycles), AMD core counter 3 (0x76), `INT` set | the LAPIC LVT performance-counter entry, vector 0xEE | `X86_PMU` (CPUID leaf 0xA / AMD leaves) |

The x86_64 interrupt is an ordinary vector, not an NMI: the per-CPU trace ring
is safe against every producer but a re-entrant one, which an NMI landing
inside another record would be, and the kernel has no NMI stack. The price is
the tick's: interrupts-masked code is sampled where it unmasks. A real-time CPU
(`isolcpus`, a band task, an admitted reservation) is never armed and disarms at
its next overflow; its tick records the PC only. QEMU: riscv64 needs
`-cpu rv64,sscofpmf=on`; aarch64 `virt` has the PMU and its PPI; x86_64 TCG has
no PMU, so there the profiler samples on the tick. The summary line
`tracectl: profile origins: tick=N pmu=N rt=N` counts the samples by origin.

**Reading it.** `tracectl profile [-t MS] [-p MS] [-k KERNEL_ELF] [-u USER_ELF]
[-o FOLDED] [-j PERFETTO]` switches the class on, drains every CPU's ring, puts
the mask back, and writes folded stacks (`mode:tidN;outermost;...;innermost COUNT`,
the input of `flamegraph.pl` or `inferno`) and, with `-j`, a Perfetto trace with
one track per CPU. The kernel records addresses, not names; symbols come from the
ELF files given. Without them, or for an address no symbol covers, the output is
`0xADDR`.

## Trace and Perfetto export

Source: `crates/core/trace/src/lib.rs`, `crates/core/abi/src/trace.rs`,
`crates/core/syscall/src/trace_ctl.rs`, `userspace/services/tracectl`,
`tools/dev/perfetto_export.py`, Kconfig `KTRACE`.

The kernel event tracer keeps one lock-free single-producer, single-consumer
ring per CPU in one kernel-owned shared-memory region, mapped read-only for a
reader holding `Cap<Trace>`. Each CPU is the only producer of its ring; the
ring-3 reader is the only consumer, so run one at a time. The producer rings no
doorbell; the reader polls. Records are 32 bytes; each ring holds
`KTRACE_RING_ENTRIES` (a power of two), and `KTRACE_BOOT_MASK` is the mask
recording from boot.

**Classes** (`KTRACE_CLASS_*` compile them in; a runtime mask switches them):

| Class | Bit | Events |
|-------|-----|--------|
| `sched` | 0 | `sched_switch`, `sched_wakeup` |
| `irq` | 1 | `irq_entry`, `irq_exit` |
| `syscall` | 2 | `sys_enter`, `sys_exit`, `sys_deny` |
| `ipc` | 3 | `ipc_call`, `ipc_reply` |
| `fault` | 4 | `page_fault` |
| `proc` | 5 | `proc_spawn`, `proc_exit`, `proc_signal` |
| `lat` | 6 | `lat_irqsoff`, `lat_preemptoff` (a new longest masked window, with `LAT_TRACE`) |
| `prof` | 7 | `prof_sample`, `prof_frames` |

**Tracepoint forms.** `KTRACE` off, or its class off: nothing, because
every tracepoint is an `#[inline(always)]` test of constants that folds away.
Compiled in but masked at run time: a load of the mask, an `and` and a branch (the
mask sits alone on its cache line), or with `KTRACE_STATIC_KEYS` a patched branch
written through the kernel's one text writer (`text_poke`, see
[update.md](update.md)). Recording is out of line: interrupts masked (the ring is
per CPU, so that is its whole mutual exclusion), the CPU taken from `tp` /
`TPIDR_EL1`, a timestamp (`KTRACE_TS_CYCLES`: cycle counter, else the timebase),
and five stores into the record's own cache line. Interrupts are masked with the
CSR or `DAIF` directly, not through `azos_arch`, so the tracer does not measure
(or trace) itself. The CPU, clock and masking code exists for riscv64 and
aarch64 only: an x86_64 kernel builds the host stub, which writes every record
into ring 0 with timestamp 0 and masks nothing. A full ring either overwrites or
drops (`KTRACE_POLICY_OVERWRITE`, else drop); drops are counted per CPU.

**`tracectl`** is the reader. Its topology row is its whole authority: `Cap<Trace>`
and a read-write `/fat` for a trace file. Without the capability it still asks, so
the refusal is the kernel's and is recorded.

```text
tracectl info                      geometry, classes, mask, per-CPU drops
tracectl start [CLASSES]           start recording (default: every class)
tracectl stop                      stop recording (mask 0)
tracectl stream [-n N] [-t MS] [-c CLASSES] [-p MS] [-m N] [-q] [-o FILE]
tracectl profile ...               the sampling profiler (above)
CLASSES: all | a comma list of sched,irq,syscall,ipc,fault,proc,lat,prof | 0xMASK
```

`stream` records the classes, prints decoded records (`[cpuN] SEC.NANOS event
key=value ...`) until `N` records or `MS` milliseconds, and puts the mask back as
found. A change of the mask while it streams opens a segment, and the summary
counts each segment's records per class, those of a masked class near a boundary
("late") and past it ("outside", which must be 0).

**Masked-window tracer** (Kconfig `LAT_TRACE`, kernel feature `lat-trace`;
`kernel/src/lat_trace.rs`, `azos_arch_api::lat`). Hooks on every interrupt
mask and unmask, preemption-counter transition and trap entry and exit time each
window with interrupts or preemption off; a site is the `#[track_caller]`
location that opened it. The longest window of each kind (with its CPU and its
sites) and the sites with the longest windows are published in the introspection
tree's `latency/`, and a new longest window is a `lat`-class
trace record.

**Perfetto.** `tools/dev/perfetto_export.py` merges the flight recorder, the decision
records and a kernel trace into one Chrome trace-event JSON that Perfetto loads, so
"what did the machine decide, and what was it doing at that moment" is one
timeline.

```text
perfetto_export.py [--recorder LOGNNNNN.BIN ...] [--decisions FILE ...]
                   [--trace FILE ...] [--hz TICKS_PER_SECOND] -o out.json
perfetto_export.py --self-test
```

| Input | Format |
|-------|--------|
| `--recorder` | A flight-recorder file; the timestamps are raw timebase ticks, so `--hz` places them. Safety records are named by violation code; durable decision receipts (codes `0x1B` base, `0x1C` extension) are decoded to rule, verdict, subject and numbers. |
| `--decisions` | `why list` saved as text, or the records raw (104-byte records back to back, as `decisions/records/<n>` of the admin region holds them; file name ends `.bin`); placed by the record's clock |
| `--trace` | `tracectl stream` text output, placed by its own clock |

Tracks: process 1 "kernel trace" (one thread per CPU), process 2 "decisions" (one
thread per rule), process 3 "flight recorder" (one thread per record kind); every
record is an instant event whose arguments are the fields. `--self-test` checks the
script's rule and verdict tables against `crates/core/decision/src/lib.rs` and
`crates/core/actuation/src/logger.rs`. `inspect -j` and `tracectl profile -j` write
Perfetto JSON directly.

## Kernel log

Source: `crates/drivers/sys/src/uart.rs`, `crates/drivers/sys/src/console_defer.rs`,
`config/kernel/Kconfig.trace` (`LOG_LEVEL`), `crates/core/actuation/src/logger.rs`.

Kernel output goes to the console UART through macros in `azos_drv_sys`:

| Macro | Level | Use |
|-------|-------|-----|
| `kerr!` | 3 (err) | Something failed or was refused and the system is worse for it: a fault that kills a task, a failed boot self-check, a driver given up on, a halting refusal |
| `kwarn!` | 4 (warn) | A security refusal or safety event the system handled (a capability or seccomp denial, a verification failure, an e-stop, a watchdog stop), or a degraded mode |
| `kinfo!`, `kprintln!`, `kprint!` | 6 (info) | Progress and status |
| `kdebug!` | 7 (debug) | Developer diagnostics |
| `kconsole!`, `kconsoleln!` | always | Not a log line: output a person asked for, and the panic report |

The numbering is Linux's. The level is a **compile-time** choice
(`LOG_LEVEL`: err, warn, info or debug; the build script rejects any other value).
A line above it sits behind a constant-false `if`: its format string, formatting
code and call are not in the image and its arguments are not evaluated. Not
affected by the level: the shell's and ring-3 programs' console output, the panic
report, and the durable records (flight recorder, `/fat/CRASH.LOG`, pstore).

**Structured log** (Kconfig `KLOG`; `crates/drivers/sys/src/klog.rs`, `klog/wire.rs`). Each
line the macros above print is also a record `{ts, level, module, msg}` in one ring of
`KLOG_ENTRIES` slots of 320 bytes (an 8-byte stamp, the timebase tick, the sequence number,
level, flags, CPU, a 24-byte module path and a 256-byte message), a kernel-owned memory
object that a ring-3 task maps read-only (`MemObj klog.ring`, `READ|MAP`). The console path
is unchanged: the line is formatted once, before the console lock, as it already was, and
the same bytes go out the same way. A producer claims a slot with one atomic add and stores
the record between two stamps; it never waits and takes no lock, so an interrupt handler
that interrupts a producer gets a slot of its own. A full ring overwrites its oldest record.
A reader keeps its own cursor and writes nothing to the region: it takes slot `c` when its
stamp is `2c+2`, re-reads the stamp after the copy, and counts as lost what the producer
lapped; any number of readers can read at once.

The first lines are printed before the page allocator exists, so until `kernel_main`
creates the object (`kernel/src/boot/klog_region.rs`) a small ring in `.bss`
(`KLOG_EARLY_ENTRIES`) takes the records, and the handover copies them with their own
timestamps; a line older than that ring's depth is only on the console. A `kprint!`
fragment (a line with no newline) is flagged and the record after it continues it; a line
longer than the console's 256-byte pre-format buffer is flagged as cut.

`logd` (`userspace/services/logd`, see [services](services.md#logd)) drains the ring into a
ring of files, `KLOGn.TXT`, under its `/fat` grant; `LOGD_FILE_KB`, `LOGD_FILES_KEEP`,
`LOGD_MAX_LEVEL` and `LOGD_POLL_MS` are its retention. `log [-n N] [-l LEVEL] [-m MODULE]`
(`TOOLBOX.ELF`) prints the last lines back. This is the durable kernel log for a running
system; the pstore and `/fat/CRASH.LOG` stay what they were, the record of a panic.

**Console ownership** (`console_defer.rs`). Ring 3 can own the UART with
interrupts on. A kernel line written meanwhile waits in a bounded buffer
(`CONSOLE_DEFER_BYTES`) that the owner drains: a kernel writer that finds the console owned, or a residual waiting,
appends to the buffer in order and returns, waiting for the owner only as long as
one of the owner's lock holds. The owner writes its line with interrupts on, then
drains what was deferred, chunk by chunk, each copied out under the lock and written
with it released, and gives the console back in the lock hold that sees the buffer
empty. Each drain has a byte budget, so a kernel printer faster than the wire cannot
keep the owner from returning; a residual is drained by the next kernel line, the
next owner, or the idle loop. A kernel writer in task context takes the same
ownership; one in an interrupt handler or under a spinlock puts at most one chunk
of the residual on the wire and defers its own line.

**Flight recorder.** `crates/core/actuation/src/logger.rs` keeps a ring of
fixed-size 32-byte records in RAM (`LOG_RING_ENTRIES`, a power of two; lock-free,
many producers, one consumer) and a log flusher task writes them to
`/LOG/LOGnnnnn.BIN` (a five-digit monotonic session serial), rotating when a file
exceeds `LOG_FILE_ROTATE_BYTES`.

| Part | Layout |
|------|--------|
| File header (16 bytes) | `RBL1`, version u16, reserved u16, open timestamp u64 |
| Record (32 bytes) | timestamp u64, kind u8, flags u8, 2 bytes padding, 20-byte payload |

A full ring evicts the oldest record, counted in `events_dropped`, except a
latching e-stop record not yet known durable or a committed write-ahead effect
record, which are never evicted: then the new record is the one lost (and
counted). Of the ring, `LOG_RING_SAFETY_RESERVE` slots are kept for safety
records (an e-stop latch or release, the boot replay's restore record, the
release nonce floor); a stop's record may use half of them. A safety record finds
a slot without evicting anything until the reserve itself is full. Real-time producers never wait: durable
entry points queue and wake the flusher instead of flushing in the caller. The
recorder is where durable decision receipts, the per-fault crash record, safety
violations and the e-stop log land.

**No procfs.** The kernel publishes no text files: what `/proc` and `/sys` once
carried is in the introspection tree (`system/`, `memory/`, `fs/`, `drivers/`,
`devices/`, the admin task list, the views), the vDSO clock and
`DOMAIN_UPTIME` (the uptime). A Linux binary's `/proc` is the Linux runtime's
(`userspace/lib/linux_rt`, ring 3).

## Lockdep

Source: `crates/core/sync/src/lockdep.rs`, `kernel/src/lockdep_log.rs`, Kconfig
choice `LOCKDEP_N` / `LOCKDEP_KTEST` / `LOCKDEP_Y` (the last two in development
builds only), cargo feature `lockdep`.

A lock's class is the site of its constructor (`#[track_caller]`). At each
acquisition, from the first lock the boot CPU takes, the checker records the
"A held, B taken" class pair in a fixed lock-free table (`LOCKDEP_EDGES`) and
reports the inversion when B then A is already recorded (before the spin, so a
real deadlock is reported rather than hung); it also reports taking a lock the
holder already holds, a class taken both in interrupt context and with
interrupts on (`LOCKDEP_IRQ_INFERENCE`), object-level and scope violations
(`LOCKDEP_SCOPE_CHECKS`), a sleep or device wait with a spinlock held, and a lock
held on return to user mode. Checked chains are cached (`LOCKDEP_CHAINS`).
Every hold is timed per class (`LOCKDEP_HOLD_BUCKETS`); a spinlock held past
`LOCK_MAX_HOLD_US` is a violation with `LOCKDEP_HOLD_ENFORCE`, a note without.
A sleeping lock contended by real-time tasks on two CPUs is a note
(`LOCKDEP_RT_CROSS_CPU`). Reports are queued once each (`LOCKDEP_REPORTS`) and
never printed from a lock path: the ktest runner prints them and fails the
running test; with `LOCKDEP_Y` outside ktest the log flusher task prints them
(`lockdep_log::drain`). Notes fail nothing. Without the feature no lock carries
a field or a call of it.

## Fault injection

Source: `crates/core/chaos/src/lib.rs`, Kconfig `CHAOS` (development builds,
refused with `SECURE_BOOT_ENFORCED`), `CHAOS_SEED`, `CHAOS_TIMER_DELAY_US`,
kernel feature `chaos`.

A fixed set of named points fails the way the real fault would: `frame-alloc`
(the frame allocator answers out of memory), `heap-alloc` (the kernel heap
answers null; tests only, refused on the command line), `ipc-send` (a channel
send is refused), `timer-wake` (sleepers are woken `CHAOS_TIMER_DELAY_US` late),
`spurious-irq` (an IPI with no cause) and `disk-io` (a block read or write
fails). A point is armed with a rate (one firing in `rate` calls) and an optional
skip count, from a test or with `chaos=<name>:<rate>[,...]` on the kernel command
line, which takes effect once boot init is done. Which calls fire follows a
per-point generator seeded from `chaos_seed=` (default `CHAOS_SEED`), so a seed
and a call order repeat the same failures. Each point's rate, calls checked and
firings are in the introspection tree's `chaos/`. With the feature off every
point is a constant `false`.
