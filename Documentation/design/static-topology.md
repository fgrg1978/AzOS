# Static topology

The static topology is the signed, declarative description of what runs on a
machine and what each part of it is allowed to do: the scheduler classes, the
task rows with their capability grants, memory budgets and real-time
profiles, and the rows for devices, package signers, remote peers, guests,
network rules and similar system-level objects. The kernel reads it once at
boot, checks it, and keeps it read-only for as long as it runs. Every task
that is started later takes its capabilities, class and budgets from it.

The topology is two text files in a restricted TOML subset, `CAPS.TOML` and
`SCHED.TOML`, parsed by a small allocation-free parser into a fixed-size
`Topology` value. This note describes the formats the parser accepts today,
how the files are authenticated and installed, and which checks run before a
topology is published.

Source: `crates/core/topology/src/lib.rs`, `crates/core/topology/src/types.rs`,
`crates/core/topology/src/parser.rs`.

## Where it lives

All of the code is in the `azos_topology` crate (`crates/core/topology`). The
crate is `no_std` and does not allocate. Its modules:

| Module | Role |
|--------|------|
| `parser` | Parses `SCHED.TOML` (`parse_sched`) and `CAPS.TOML` (`parse_caps`, `parse_binding`). |
| `types` | `Topology`, the row types, the fixed pools and the admission checks (`Topology::admission_check`). |
| `signed` | The signed-file loader (`fill_signed`, `load_signed`) and the boot source policy (`decide`). |
| `verify` | Signature verification of the file bytes against the trusted key (the configured algorithm, `SigAlg::CONFIGURED`). |
| `paths` | The on-disk file names. |
| `deadline` | Feasibility of the declared real-time profiles. |
| `memory` | Frame budgets and memory admission. |
| `neverallow` | Grants that no topology may make. |
| `placement` | Where a driver row runs and whether it may move. |
| `emit` | Writes a `Topology` back out as the two files. |
| `builder` | The built-in topology (`fill_default_minimal`). |
| `state` | The single read-only slot that holds the installed topology. |
| `device_record` | The device id and the counter floor the binding keys are checked against. |
| `apply` | The pure half of applying a row's class and priority to a task. |

The kernel side is `install_topology` in `kernel/src/boot/topology.rs`.

Source: `crates/core/topology/src/lib.rs`, `kernel/src/boot/topology.rs`.

## Files

| File on the volume | Contents |
|--------------------|----------|
| `/fat/CAPS.TOM` | Task rows and every other row kind, plus the binding keys (device, counter, SCHED hash). |
| `/fat/CAPS.SIG` | A `DSIG` (`azos_crypto::sig`): magic, the signature algorithm's id, the signature's length and a signature over the exact bytes of `CAPS.TOM` (72 bytes for Ed25519). |
| `/fat/SCHED.TOM` | The `[sched]` section and the scheduler classes (and, when built with the `energy` feature, the energy model). |

The text formats are called `CAPS.TOML` and `SCHED.TOML`; the file names are
the FAT 8.3 short names. The kernel's FAT32 driver matches short names only,
so a name such as `CAPS.TOML` would be stored under a generated alias that no
loader could guess. For the same reason the signature sidecar shares the
base name of the file it signs.

There is no signature file for `SCHED.TOM`. `CAPS.SIG` covers `CAPS.TOM`, and
`CAPS.TOM` carries the SHA-256 of the `SCHED.TOM` it was signed with, so one
signature authenticates both. A `SCHED.SIG` left on a volume is ignored
(`SCHED_SIG_PATH` is kept only so tools can name it).

Source: `crates/core/topology/src/paths.rs`, `crates/core/topology/src/signed.rs`.

## The accepted syntax

The parser accepts a subset of TOML and refuses everything else with a
`ParseError`. It is single pass and line oriented, borrows every string from
the input buffer, and never allocates. The kernel keeps the file buffers for
its whole life because the installed topology's names and targets point into
them.

| Element | Accepted form |
|---------|---------------|
| Comment | `#` to the end of the line, outside a string. |
| Section header | `[kind.NAME]`, or one of the bare headers `[sched]`, `[operator]`, `[clock]`, `[energy]`. Nothing but a comment may follow the `]`. |
| Names | After the dot, any text up to the closing bracket, at most `TOPOLOGY_NAME_MAX` bytes. |
| Integer | Unsigned decimal digits. No sign, no hex, no floats, and no digit separators: a number ends at the first non-digit. |
| String | `"..."` on one line. No escape sequences: a backslash is refused. |
| Boolean | `true` or `false`. |
| Range | `[lo, hi]`, each 0 to 255 (used only by `priority_range`). |
| String array | `["a", "b"]` on one line. |
| Number array | `[2, 3]` on one line. |
| Inline-table array | `caps = [ { ... }, { ... } ]`, over one or several lines, several tables per line, comments and blank lines between them. |

Rules that hold everywhere:

- An unknown key inside a section, an unknown section header or a key of the
  wrong type is an error, never ignored. A value that does not fit its field is
  refused, never truncated. (Lines before the first section are the exception:
  an unknown key there is ignored.)
- Text after a value is refused for the task keys added from format 2 on, for
  `start`, for every key of the sections added in formats 6 and 7, and for
  the binding keys. Three keys of `SCHED.TOML` also refuse it: `isolcpus`,
  and a class's `envelope` and `principal`. The oldest keys (in `[sched]`
  `partition_window_us`; in `[class.*]` `cpu_budget_min_pct`,
  `cpu_budget_max_pct`, `policy`, `priority_range`, `preemption`,
  `time_slice_ms` and `admission_control`; the `[pipeline.*]` and `[operator]`
  keys; and the task keys `class`, `priority`, `mem_pages`, `mem`,
  `mem_huge_mib`, `instances`, `sqpoll_idle_ms`, `period_us`, `runtime_us`,
  `deadline_us`, `cpu_mask`) read the leading value and do not look at what
  follows it, so `period_us = 10_000` is read as 10. Write plain digits.
- These keys are refused when repeated: `format`, the binding keys, the keys
  of the format-7 sections and of `[clock]`, `key_id` and a non-empty
  `warrants` in `[signer.*]`, `match` in `[device.*]`, and `noise_pk` and
  `measurement` in `[peer.*]` (the last two are format-7 keys of a format-6
  section). For every other key the last occurrence wins.
- Whole sections that belong to the other file are skipped without being
  read: `SCHED.TOM` skips `[task.*]` and every row section, and `CAPS.TOM`
  skips `[class.*]`, `[sched]` and the energy sections. Keys outside any
  section are ignored in `SCHED.TOM`; in `CAPS.TOM` the lines before the
  first section are the top-level keys described below.
- An array that is not closed before the end of the file is refused with
  `UnterminatedArray`.

Source: `crates/core/topology/src/parser.rs` (`parse_section_line`,
`parse_quoted_string`, `parse_unsigned_int`, `parse_inline_table`,
`parse_sched`, `parse_caps`).

## SCHED.TOML

`SCHED.TOML` holds the global scheduler settings and the scheduler classes.
It has no per-task content: a task names its class in `CAPS.TOML`.

```toml
[sched]
partition_window_us = 10000     # default 10000
isolcpus = 0                    # CPU mask, bit n = CPU n; default 0

[class.safety_critical]
cpu_budget_min_pct = 20
cpu_budget_max_pct = 100
policy = "edf"
priority_range = [0, 7]
preemption = "always"
admission_control = true
envelope = "full"
principal = "system"

[class.soft_rt]
cpu_budget_min_pct = 25
cpu_budget_max_pct = 60
policy = "rr"
priority_range = [16, 23]
preemption = "timer-only"
time_slice_ms = 10

[class.best_effort]
cpu_budget_min_pct = 20
cpu_budget_max_pct = 100
policy = "cfs"
priority_range = [24, 30]
preemption = "timer-only"

[class.idle]
cpu_budget_min_pct = 5
cpu_budget_max_pct = 5
policy = "sporadic"
priority_range = [31, 31]
preemption = "never"
```

### `[sched]`

| Key | Type | Meaning |
|-----|------|---------|
| `partition_window_us` | integer | Window of the partition budget accounting. Default 10000. |
| `isolcpus` | integer | Mask of CPUs kept for isolated real-time rows. Default 0 (none). |

Source: `crates/core/topology/src/parser.rs` (`handle_sched_kv`),
`kernel/src/boot/topology.rs` (the CPUs are handed to the scheduler's
fair-share queue so that it leaves them alone).

### `[class.NAME]`

| Key | Type | Values and default |
|-----|------|--------------------|
| `cpu_budget_min_pct` | integer | 0 to 100. |
| `cpu_budget_max_pct` | integer | 0 to 100. |
| `policy` | string | `fifo`, `edf`, `rr`, `cfs`, `sporadic`. Default `fifo`. |
| `priority_range` | range | `[lo, hi]`, `lo <= hi`. |
| `preemption` | string | `always`, `timer-only`, `never`. Default `always`. |
| `time_slice_ms` | integer | Up to 65535. For `rr`. |
| `admission_control` | boolean | Whether the real-time profiles of the class's rows are checked for feasibility. Default `false`. |
| `envelope` | string | `full`, `cautious`, `slow`, `contained`: the ceiling on the physical effects the class's tasks may cause. Default `full`. |
| `principal` | string | `system`, `service`, `user`, `agent`: who the class's tasks act as. Default `system`. |

At most `TOPOLOGY_MAX_CLASSES` classes; a class name may not repeat.

What the kernel does with a class:

- A row's class name selects the scheduler class by name (`safety_critical`,
  `hard_rt`, `soft_rt`, `best_effort`, `idle`, and `session` for the interactive
  class). A class with any other name
  parses and is admitted, but the scheduler refuses to apply it: the task keeps
  the priority it was created with and the refusal is recorded.
- The row's priority is clamped into the class's `priority_range` when the
  row is applied to a task.
- `admission_control` and `cpu_budget_max_pct` feed boot admission of the
  real-time profiles (see the admission section). `cpu_budget_min_pct` is
  summed over the classes and must not exceed 100.
- `principal` is given to each task spawned from a row of the class, and the
  `envelope` each principal kind is held to is published, as the most
  restrictive envelope among the classes that declare that kind
  (`apply_principal`, when the IPC label feature is enabled).
- No code outside the topology crate reads `partition_window_us`,
  `policy`, `preemption` or `time_slice_ms`. The class budgets are checked at
  boot; they are not enforced in dispatch.

Source: `crates/core/topology/src/parser.rs` (`handle_class_kv`,
`handle_sched_kv`), `crates/core/topology/src/types.rs` (`ClassSpec`,
`SchedConfig`, `Topology::push_class`), `crates/core/syscall/src/topo_sched.rs`,
`crates/core/sched/src/class.rs` (`SchedClass::from_name`).

### `[energy]` and `[energy.domain.NAME]`

When the topology crate is built with its `energy` feature (the kernel's
`energy` feature turns it on), `SCHED.TOML` may also declare an energy model.
Without the feature the sections are recognised and skipped.

```toml
[energy]
mode = "balanced"               # performance (default), balanced, endurance

[energy.domain.little]
cpus = 1                        # CPU mask
wcet_ref_khz = 600000           # optional
opps = [
  { freq_khz = 600000, capacity = 300, power_mw = 60 },
  { freq_khz = 1200000, capacity = 600, power_mw = 200 },
]
idle = [
  { name = "wfi", exit_latency_us = 1, target_residency_us = 1, power_mw = 20 },
]
```

The parser checks syntax and ranges only. Whether the model is consistent is
a question for `azos_energy::EnergyModel::validate`, asked at boot.

Source: `crates/core/topology/src/parser.rs` (`parse_energy`),
`crates/core/topology/Cargo.toml` (feature `energy`).

## CAPS.TOML

### Format number and binding keys

The lines before the first section are the top-level keys:

```toml
format = 8
device = "00112233445566778899aabbccddeeff"
counter = 3
sched_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

`format = N` may appear once and selects what the file may contain. A file
with no `format` line is format 1. The parser reads formats 1 to 8
(`CAPS_FORMAT_MAX`). A key or section that belongs to a later format than
the file declares is refused with `FieldNeedsFormat`, so a writer and this
reader cannot disagree about what a file means.

| Format | Adds |
|--------|------|
| 1 | The base: `[task.NAME]` rows with `caps`, `class`, `priority`, real-time profile keys, memory keys, `start`; `[pipeline.NAME]`; `[operator]`. |
| 2 | Task key `restart`. |
| 3 | Task key `abi`. |
| 4 | Top-level binding keys `device`, `counter`, `sched_sha256`. |
| 5 | Task keys `imports`, `timer_slack`. |
| 6 | Sections `[device.NAME]`, `[signer.NAME]`, `[peer.NAME]`; task keys `export`, `place`, `stateless`, `call_budget_us`, `lx_class`. |
| 7 | Task keys `shadow`, `isolated`, `kmem_kib`; device keys `safe_state`, `commit_ns`, `compensate`; peer keys `noise_pk`, `measurement`; sections `[policy.NAME]`, `[livepatch.NAME]`, `[degrade.NAME]`, `[clock]`, `[swap.NAME]`, `[volume.NAME]`, `[guest.NAME]`, `[route.NAME]`, `[firewall.NAME]`. |

The three binding keys (format 4 or later, each at most once, before the
first section) sit inside the signed bytes:

| Key | Meaning |
|-----|---------|
| `device` | 32 hex digits: the id of the one device the file is signed for. |
| `counter` | Integer, at least 1, never decreasing across the files a device accepts. |
| `sched_sha256` | 64 hex digits: SHA-256 of the `SCHED.TOM` this file goes with. |

The parser only reads these keys. Whether a missing key is acceptable, and
what they are compared with, is the loader's policy (see "Loading and
installing").

Source: `crates/core/topology/src/parser.rs` (`CAPS_FORMAT_MAX`, `Binding`,
`parse_binding`, `top_level_line`).

### `[task.NAME]`

A task row names an image or a kernel task and everything it may be given.
A row for a program is named after its image (`SENSORD.ELF`); the kernel finds
the row of a program by that name (the autorun loader falls back to a row called
`autorun` for an image that has none). A fork child has no row of its own and
inherits its parent's. Names must be unique, and there are at most `MAX_TASKS`
rows.

| Key | Format | Type | Meaning |
|-----|--------|------|---------|
| `class` | 1 | string | Scheduler class name. Default `best_effort`. |
| `priority` | 1 | integer, 0 to 255 | Static priority; clamped into the class's range. |
| `caps` | 1 | inline-table array | The capability grants, see below. |
| `period_us`, `runtime_us`, `deadline_us` | 1 | integer (`u32`) | Real-time profile. `deadline_us = 0` means the period. |
| `cpu_mask` | 1 | integer (`u32`) | CPUs the row may run on, bit n = CPU n; 0 means any. |
| `mem_pages` | 1 | integer (`u32`) | Frame budget in 4 KiB units. 0 means no limit of its own. |
| `mem` | 1 | string | `"ceiling"` (default) or `"locked"`. |
| `mem_huge_mib` | 1 | integer | MiB of a locked row mapped with 2 MiB leaves: even, 2 to 256. |
| `instances` | 1 | integer | Live instances allowed, 1 to `MAX_TASKS`. Default 1. |
| `sqpoll_idle_ms` | 1 | integer (`u32`) | Idle time of an io_ring submission-queue poller the row may start. 0 means it may not start one. |
| `start` | 1 | boolean | The kernel starts this image at boot. Default `false`: a row alone starts nothing. |
| `restart` | 2 | string | `always`, `on-failure` (default), `no`: what the supervisor does when a supervised task of the row ends. |
| `abi` | 3 | string | `native` (default) or `linux`: the syscall table the image is run against. |
| `imports` | 5 | string array | Endpoint names the name server may lend to the row. |
| `timer_slack` | 5 | boolean | The row's timers may be coalesced. Default `false`. |
| `export` | 6 | string array | `"NAME@CLASS"` entries: endpoints the row may lend to the nodes of a peer class. Only the row named `RPCSRV.ELF` may carry it. |
| `place` | 6 | string | `kernel` or `ring3` (default): the host a driver starts in. |
| `stateless` | 6 | boolean | The driver can be started on the other host with no state transfer. Default `false`. |
| `call_budget_us` | 6 | integer (`u32`) | The call budget a move into the kernel is admitted against. 0 means none. |
| `lx_class` | 6 | string | The row serves a Linux driver class; the kernel starts it only once a device of that class has been bound. |
| `shadow` | 7 | boolean | Observe-only admission: the task starts with weak (read-only) capabilities and each effect it asks for that a strong holder would have been refused is recorded instead of applied. |
| `isolated` | 7 | boolean | The row owns one CPU of `[sched] isolcpus` by itself. |
| `kmem_kib` | 7 | integer (`u32`) | Ceiling on the kernel memory charged to the row's domain. 0 means no ceiling of its own. |
| `principal` | 7 | string | `system`, `service`, `user` or `agent`: who the row acts as, over its class's. Default: the class's; and when that is `system`, the principal of the task that spawned it (an agent's children stay agents). |

Notes on the keys:

- `mem = "locked"` turns `mem_pages` into a reservation that must be
  declared. A locked row cannot fork or demand-page. Any other ring-3 row's
  `mem_pages` is a ceiling.
- A row that sits in the scheduler's real-time band with a reservation must be
  `mem = "locked"`; topology admission refuses it otherwise.
- `abi = "linux"` is refused for a row that holds any grant except `node`
  grants: a translated image reaches the machine only through files and the
  right to start images.
- `isolated` needs a real-time profile whose `cpu_mask` names exactly one CPU,
  that CPU in `isolcpus`, one instance, and no other isolated row on it. An
  isolated row with no `cpu_mask` is refused (`Deadline(IsolatedWithoutCpu)`,
  naming the row): the topology never picks the CPU for it. A row that is not
  isolated may not name any CPU in `isolcpus`.
- `imports` names are 1 to 24 bytes of `[A-Za-z0-9_-]`, no name repeated within the
  row, at most `TOPOLOGY_MAX_IMPORTS` per row, and the key may appear once per
  row. A name is not authority: it lists
  what the row may ask the name server for, and the server lends a derived
  capability or records a refusal. Every imported name must be one the name
  server's row holds (see admission).
- `export` entries are checked when the row is committed (alphabet, no
  repeats, only `RPCSRV.ELF`) and at admission (the row holds the endpoint
  with the lend right, and the peer class exists).

Source: `crates/core/topology/src/parser.rs` (`handle_task_kv`),
`crates/core/topology/src/types.rs` (`TaskSpec`, `TaskAbi`, `RestartPolicy`,
`Topology::set_last_task_*`), `crates/core/topology/src/memory.rs`,
`crates/core/syscall/src/spawn.rs`.

### Capability grants

Each element of `caps` is an inline table:

```toml
caps = [
  { kind = "endpoint", target = "endpoint.imu",   perm = "r" },
  { kind = "endpoint", target = "i2c.0.0x68",    perm = "rw" },
  { kind = "endpoint", target = "endpoint.fleet", perm = "w", transfer = true },
  { kind = "node",     target = "/data",          perm = "rw" },
  { kind = "node",     target = "TOOLBOX.ELF",    perm = "x" },
  { kind = "device",   target = "irq.3",          perm = "r" },
]
```

| Field | Meaning |
|-------|---------|
| `kind` | Required. One of `endpoint`, `memobj`, `port`, `domain`, `node`, `device`, `log`. |
| `target` (or `resource`) | What the grant names; its spelling depends on the kind. Default empty. |
| `perm` (or `perms`) | Letters from `r` read, `w` write, `x` exec, `d` dup, `t` transfer, `m` map (either case). Default `r`. |
| `transfer` | Boolean. `true` adds the delegate right (dup and transfer), so the task may hand the capability to another task. Default `false`. |
| `ops` | Positive integer, for a grant of a kernel-hosted interface only (`target = "linkkey"`, `"gpio.17"`, ...): a mask of the IDL ops the holder may call, bit n for the op numbered n of the interface, counted from 1. The kernel mints it as an `OP_MASK` caveat of the capability and holds every call through it to the mask. Absent: every op the rights reach. `0`, a non-number, and a grant of a task's endpoint (`endpoint.NAME`) or of any other kind are refused at parse. The built-in rows of `RPCSRV.ELF`, `MCPD.ELF` and `SSHD.ELF` hold `READ` on `linkkey` with `ops = 4` (`node_key`, the second op), so they can ask for their node identity and cannot read the board seed. |

A grant transfers authority only when it says so; omission never does.
At most `MAX_CAPS_PER_TASK` grants per row and `MAX_CAPS_TOTAL` overall.

How the kernel mints a grant from `(kind, target, perm)` is
`seed_one_cap` in `crates/core/ipc/src/cap_seed.rs`. Targets it reads:

| Kind | Target spellings |
|------|------------------|
| `endpoint` | `endpoint.<name>` for a task-hosted endpoint, or `<iface>[.<resource>]` for an interface the kernel hosts (`gpio.17`, `i2c.0.0x68`, `pwm.4`, `entropy`, `power`). |
| `device` | `irq.<N>`, `msi.<k>`, `mmio.<selector>` (a hardware-bus selector, see `[device.NAME]`), or `drv.<kind as decimal>` (the right to register as that driver). |
| `node` | An absolute directory path such as `/data`, or an image name such as `TOOLBOX.ELF` with `perm = "x"` (the right to start it). |
| `memobj` | `inspect.<public|admin>`. |
| `domain` | `tasks`, with `perm = "r"`. |
| `log` | `trace`, with `perm` within `rw`. |

The parser does not check target spellings: a grant whose target the minter
cannot honour mints nothing. `port` is accepted by the parser, and
`seed_one_cap` has no minter for it.
The endpoints `motor.<wheel>` exist only in a build with the
`profile-actuation` feature; in any other build a row that grants one fails to
parse.

Two rules apply to the whole file, checked after it is parsed:

- One writer per motor: no two rows may hold `WRITE` on the same
  `motor.<wheel>` endpoint (`motor_write_conflict`).
- A row holding `WRITE` on the `flight` endpoint must also hold `WRITE` on
  both wheels (`flight_without_drivetrain`).

Source: `crates/core/topology/src/parser.rs` (`cap_spec_from_inline`,
`parse_cap_kind`, `parse_cap_perms`, `motor_write_conflict`,
`flight_without_drivetrain`), `crates/core/ipc/src/cap_seed.rs`,
`crates/core/abi/src/cap.rs` (`CapPerms`).

### Rows that are not tasks

#### `[pipeline.NAME]`

A data path and the contiguous DMA memory it needs.

```toml
[pipeline.camera]
dma_kb = 2048
```

`dma_kb` is rounded up to 4 KiB pages. At most `TOPOLOGY_MAX_PIPELINES`;
names are unique. The kernel sizes its DMA pool from the pipelines' sum, with
a floor.

Source: `crates/core/topology/src/parser.rs` (`handle_pipeline_kv`),
`kernel/src/boot/topology.rs`.

#### `[operator]`

```toml
[operator]
pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

The 32-byte Ed25519 public key of the operator who may release an armed
emergency stop. Exactly 64 hex digits; anything else is a parse error.
Without the section the key is all zero, which means none is declared.

Source: `crates/core/topology/src/parser.rs` (`handle_pipeline_kv`,
`handle_operator_kv`), `crates/core/topology/src/types.rs`
(`Topology::operator_pubkey`).

#### `[device.NAME]` (format 6, keys added in format 7)

What the hardware bus does with the devices a selector matches.

```toml
[device.virtio-net]
match = "pci:1af4:1041"
admit = false

[device.brake]
match = "dt:vendor,brake-ctl"
safe_state = "brake"
commit_ns = 2000000
compensate = "release"
```

| Key | Format | Meaning |
|-----|--------|---------|
| `match` | 6 | Required. A selector: `pci:<vendor>:<device>` (hex, `*` for any), `pciclass:<class>:<mask>`, `dt:<compatible>`, `virtio:<id>` (decimal). Parsed by `azos_hwbus::Pattern::parse`. |
| `driver` | 6 | Native driver to bind instead of the table's choice. Up to 32 bytes. |
| `admit` | 6 | `false` refuses the device: it is detected and never bound. Default `true`. |
| `safe_state` | 7 | Operation of the device's interface that drives it to a safe state. |
| `commit_ns` | 7 | Longest time from an accepted command to its effect being committed. |
| `compensate` | 7 | Operation that undoes a reversible effect. |

Operation names are 1 to 24 bytes of `[A-Za-z0-9_-]`. A refused device
(`admit = false`) may not name a driver, a safe state, a commit time or a
compensation. At most `TOPOLOGY_MAX_DEVICE_ROWS` rows; names are unique.

Source: `crates/core/topology/src/parser.rs` (`handle_device_kv`),
`crates/core/topology/src/types.rs` (`DeviceSpec`, `Topology::push_device`),
`crates/drivers/hwbus/src/pattern.rs`, `kernel/src/boot/hwbus.rs`,
`crates/core/syscall/src/motor_host.rs`.

#### `[signer.NAME]` (format 6)

A package author the device admits, and the ceiling of what that author's
packages may ask for.

```toml
[signer.vendor-a]
key_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
rt = false
mem_pages_max = 1024
warrants = ["endpoint:endpoint.", "node:/data/"]
```

| Key | Meaning |
|-----|---------|
| `key_id` | Required. 64 hex digits: SHA-256 of the algorithm number (2 bytes, little endian) followed by the public key. Unique. |
| `rt` | Whether a package of this signer may ask for real time. Default `false`. |
| `mem_pages_max` | Required, non-zero: the most frames one row of this signer's packages may declare. |
| `warrants` | `"kind:prefix"` entries: a grant kind word, a colon, a target prefix (possibly empty). A package grant is covered when an entry has its kind and its target starts with the prefix. |

At most `MAX_SIGNERS` signers and `SIGNER_WARRANTS_TOTAL` entries in all.

Source: `crates/core/topology/src/parser.rs` (`SignerStage`),
`crates/core/topology/src/types.rs` (`SignerSpec`, `Topology::push_signer`,
`Topology::signer_covers`), `crates/core/pkg/src/admit.rs`.

#### `[peer.NAME]` (format 6, keys added in format 7)

A class of remote nodes, used by `export` entries.

```toml
[peer.fleet]
nodes = [2, 3]
noise_pk = ["1111111111111111111111111111111111111111111111111111111111111111", "2222222222222222222222222222222222222222222222222222222222222222"]
measurement = "3333333333333333333333333333333333333333333333333333333333333333"
```

`nodes` is required: 1 to `TOPOLOGY_PEER_NODES` node ids, none zero (0 is this
node), none repeated and none listed in another class. `noise_pk` (format 7)
holds one static public key per node, in the order of `nodes`, or is left
out; no key is all-zero or shared by two nodes. `measurement` (format 7) is
the image measurement every node of the class must attest; not all-zero.
Class names are 1 to 24 bytes of `[A-Za-z0-9_-]` and unique, at most
`TOPOLOGY_MAX_PEERS`. The RPC server's row can only lend an endpoint to a class
declared here: nothing leaves the node except through an `export` entry.

Source: `crates/core/topology/src/parser.rs` (`PeerStage`),
`crates/core/topology/src/types.rs` (`PeerSpec`, `ExportSpec`,
`Topology::push_peer`, `Topology::set_last_task_exports`).

### Format 7 rows

These sections need `format = 7`. Each section is committed when the next
section begins or the file ends. A key may appear once per section. Every
name after the dot is 1 to 24 bytes of `[A-Za-z0-9_-]` and unique within its
kind, and each kind except `[clock]` has a limit on the number of rows.

```toml
[policy.svc-limits]
domain = "SVC.ELF"
scope = "subtree"
create_endpoints = false
memobj_max_pages = 256

[livepatch.fix-a]
isa = "riscv64"
build_id = "00112233445566778899aabbccddeeff"
sec_epoch = 2
sha256 = "4444444444444444444444444444444444444444444444444444444444444444"

[degrade.low]
level = "cautious"
battery_pct = 30
clear_pct = 40

[degrade.critical]
level = "contained"
battery_pct = 10

[clock]
ptp_domain = 24
leaps = ["1435708800:36", "1483228800:37"]

[swap.swap0]
partition = 2

[login.alice]
ssh_key = ["1111111111111111111111111111111111111111111111111111111111111111"]

[volume.data]
partition = 3
mount = "/data"
read_only = true
verity_root = "5555555555555555555555555555555555555555555555555555555555555555"

[guest.linux0]
cpus = 2
mem_mib = 512
envelope = "contained"
devices = ["blk0", "net0"]

[route.default]
dest = "0.0.0.0/0"
via = "10.0.0.1"
dev = "eth0"
metric = 10

[firewall.ssh-in]
dir = "in"
action = "allow"
proto = "tcp"
port = 22
addr = "10.0.0.0/24"

[firewall.drop-in]
dir = "in"
action = "drop"
```

| Section | Keys | What admission checks |
|---------|------|-----------------------|
| `[policy.NAME]` | `domain` (required, the name of a `[task.NAME]` row); `scope` (`self` default, or `subtree`); `create_endpoints`, `create_ports` (booleans, default `true`); `memobj_max_pages` (0 means no ceiling). | The row must restrict something. One row per domain and scope. The named task row must exist. |
| `[livepatch.NAME]` | All required: `isa` (`riscv64`, `aarch64`, `x86_64`); `build_id` (hex, 8 to 32 bytes); `sec_epoch` (at least 1); `sha256` (64 hex digits). | `sha256` not all-zero. No two rows admit the same blob for one ISA. |
| `[degrade.NAME]` | `level` (`cautious`, `slow`, `contained`; required); `battery_pct` (1 to 100, required); `clear_pct` (`battery_pct` to 100; defaults to `battery_pct`). | At most three rows, one per level. A more restrictive level has a strictly lower threshold. |
| `[clock]` | `ptp_domain` (0 to 127); `leaps` (string array of `"unix_seconds:tai_offset"`, oldest first). | At most one `[clock]` section; it must declare something. Times strictly increase and the offset changes by exactly one second between entries; no offset of 0. |
| `[swap.NAME]` | `partition` (1 to 16, required). | The partition is used by no other swap or volume row. |
| `[login.NAME]` | `ssh_key` (required, array of 64-hex-digit ssh-ed25519 public keys, at most `TOPOLOGY_LOGIN_KEYS`). | NAME is the user name `ssh` is given and the name typed at the console login (at most 16 bytes there). No key all-zero, none listed twice in the topology (a key two accounts share would log in as either). At most `TOPOLOGY_MAX_LOGINS` rows. |
| `[volume.NAME]` | `partition` and `mount` (required); `read_only`, `aead` (booleans, default `false`); `verity_root` (64 hex digits). | Partition as for swap. `mount` is absolute, has no trailing slash and no empty, `.` or `..` component, is not `/`, `/fat` or beneath `/fat`, and is unique. `verity_root` only on a read-only volume and never all-zero. |
| `[guest.NAME]` | `cpus` (1 to 255), `mem_mib` (at least 1) and `envelope` (all required: there is no default for a guest); `devices` (string array of backend names, default none). | Backend names in the endpoint alphabet, none twice. |
| `[route.NAME]` | `dest` (required, `addr/len`, IPv4 or IPv6) and `dev` (required, an interface name of 1 to 15 bytes of `[A-Za-z0-9_.-]`); `via` (gateway address); `metric` (default 0). | The gateway is of the destination's family and not the unspecified address. No two rows share a destination and metric. A prefix with host bits set is refused. |
| `[firewall.NAME]` | `dir` (`in`, `out`, `forward`) and `action` (`allow`, `drop`, `reject`), required; `proto` (`any` default, `tcp`, `udp`, `icmp`); `port`, `port_end`; `addr` (a prefix, the remote address). | Rules are tried in file order and the first match decides. A rule that matches exactly what an earlier one matches is refused as unreachable. `port` only with `tcp` or `udp`; `port_end` needs `port` and is not below it; port 0 is spelled by leaving `port` out. |

Which of these rows other code reads today:

| Rows | Read by |
|------|---------|
| `policy` | `crates/core/syscall/src/families.rs` (limits on what a domain may create). |
| `livepatch` | `kernel/src/boot/livepatch.rs` (a patch blob is applied only if a row names its SHA-256). |
| `degrade` | `kernel/src/boot/energy.rs`. |
| `clock` | `crates/core/syscall/src/clock.rs` (the TAI-UTC table), `kernel/src/boot/inspect_views.rs` (the PTP domain, in the `inspect.clock` view). |
| `volume` | `kernel/src/boot/azvol.rs`. |
| `guest` | `kernel/src/boot/hv.rs`, `crates/core/hv/src/admit.rs`. |
| `route`, `firewall` | `kernel/src/boot/net.rs`. |
| `login` | `kernel/src/boot/inspect_views.rs` publishes the rows in the `inspect.logins` view (one entry per key, `logins/<n>/{user, key}`); the SSH server (`userspace/services/sshd`) reads it at every connection and the login service (`userspace/services/logind`) whether it is empty. The `login` op of `keys` (`crates/core/syscall/src/keys.rs`) compares a console credential's verifier (`login_enroll`, `tests/host/logind-tests`) with the keys of the row. The row's place in the file plus one is the user's `owner_root`. A key's hex is the 32 bytes of an OpenSSH `ssh-ed25519` public key: `awk '{print $2}' id_ed25519.pub | base64 -d | tail -c 32 | xxd -p -c 64`. |
| `swap` | Nothing outside the topology crate reads `Topology::swaps` today. The swap partition is claimed through the block layer's partition table (`azos_drv_block::partition::claim_swap`). |

Source: `crates/core/topology/src/parser.rs` (`PolicyStage`, `LivepatchStage`,
`DegradeStage`, `ClockStage`, `SwapStage`, `VolumeStage`, `GuestStage`,
`RouteStage`, `FirewallStage`, `LoginStage`), `crates/core/topology/src/types.rs`
(`Topology::push_policy`, `push_livepatch`, `push_degrade`, `set_clock`,
`push_swap`, `push_login`, `push_volume`, `push_guest`, `push_route`, `push_firewall`).

### Format 8 rows

Format 8 adds the rows and keys below. They are declared before any code
reads them (TOPO-ROWS-C), so the fronts that consume them read
`crates/core/topology/src/types.rs` and edit nothing here. The rules of format
7 hold: a section is committed when the next begins, a key appears once, a
name is 1 to 24 bytes of `[A-Za-z0-9_-]` and unique within its kind, and a
file that says `format = 7` and uses any of this is refused with
`FieldNeedsFormat`. `dev` values are 1 to `TOPOLOGY_NAME_MAX` bytes of
`[A-Za-z0-9_.-]`, not starting with a dot.

```toml
[task.INDEX.ELF]
security_boundary = true
partition_id = 7

[guest.ais]
cpus = 2
mem_mib = 64
envelope = "slow"
passthrough = ["uart2", "nvme0"]
static = true
pcpus = 12
mem_base = 2147483648

[tsn.uplink]
dev = "eth0"
window_us = 1000
link_budget = 100000

[usb.storage]
class = 8
authorize = "deny"

[usb.rest]
authorize = "allow"
```

| Section or key | Keys | What admission checks |
|----------------|------|-----------------------|
| `[task.NAME]` | `security_boundary` (boolean, default `false`): the row's Domain is a security boundary; `partition_id` (1 to 65535): the hardware resource partition it runs in. Read by `RowMem::partition_id` into the Domain at spawn and exec (`azos_sched::scheduler::set_task_partition`); a child Domain starts in its creator's. The scheduler makes it the hart's resource tag on every context switch (`azos_sched::qos`; riscv64 Ssqosid `srmcfg`, Kconfig `RV_SSQOSID`). A partition the hardware cannot tag runs in partition 0, said on the console. | A partition id only on a security-boundary row. |
| `[guest.NAME]` | `passthrough` (string array of device names, default none); `static` (boolean, default `false`): a static partition; `pcpus` (CPU mask) and `mem_base` (physical address). | Passthrough names in the endpoint alphabet, none twice and none also in `devices`. A static guest has `pcpus` with exactly `cpus` bits set and a page-aligned, non-zero `mem_base`; no other guest has either key. Two static guests share no CPU and no memory. |
| `[tsn.NAME]` | `dev`, `window_us` (1 to 1000000, the Qbv gate cycle), `link_budget` (1 to 10000000 kbit/s); all required. | One row per device. |
| `[fieldbus.NAME]` | `kind` (`ethercat`, `canopen`, `modbus`) and `dev` required; `cycle_us`. | One row per device. `cycle_us` exactly for EtherCAT. |
| `[audio.NAME]` | `dev`, `rate_hz` (8000 to 384000), `channels` (1 to 32) required; `dir` (`playback` default, `capture`, `duplex`). | One row per device. |
| `[display.NAME]` | `dev`, `width`, `height` required; `rotation` (0, 90, 180, 270; default 0); `primary` (boolean). | One row per device; at most one primary. Sizes of at least 1. |
| `[user.NAME]` | `root` and `keystore`, both required absolute paths (the rules of a `[volume.NAME]` mount point). | The root is used by one row only; the keystore is not the root. |
| `[key.NAME]` | `purpose` (`link`, `sign`, `aead`) and `source` (`dice`, `keystore`, `hardware`) required; `user`. | `user` exactly when the source is `keystore`, and that `[user.NAME]` row must exist. A row holds no key material. |
| `[mission]` | `reserve_mj` (at least 1, required); `task`. | At most one section. The named task row must exist. |
| `[boot_chain.NAME]` | `stage` (0 to 255) and `digest` (64 hex digits), both required. | Name and stage unique, digest not all-zero, stages consecutive from 0. |
| `[island.NAME]` | `image` (a file name), `sha256` (64 hex digits) and `mailbox` (a queue name) required; `wake` (string array of event names, at most `TOPOLOGY_ISLAND_WAKE`). | Image and mailbox unique, digest not all-zero, event names in the endpoint alphabet and unique. |
| `[activity.NAME]` | `task` and `trigger` (`idle`, `charging`, `timer`) required; `period_ms`. | `period_ms` (at least 1) exactly for `timer`. One activity per task, and the task row must exist. |
| `[numa.NAME]` | `node` (0 to 63) and `cpus` (CPU mask, not empty), both required. | Node unique; no CPU in two nodes. |
| `[envelope.NAME]` | `kind` (`config`, `ota`, `egress`, `delete`, `rt_time`, `mic`), `class` and `level` (`full`, `cautious`, `slow`, `contained`), all required. | One row per class and kind. The class must exist. Read today by the `mic` effect of `Sound::open` and, with Kconfig `EFFECT_WRITE_AHEAD`, by the effect gate for `delete` (unlink, rename over a file, cut below a file's size, snapshot drop), `egress` (a Domain's first packet to a destination off the node, by class), `config` (a write of a configuration key, by the key's reach), `ota` (staging an update, switching to it) and `rt_time` (the share of a hart one deadline reservation may take); the levels are ceilings, see [Storage and network envelopes](../effects.md#storage-and-network-envelopes) and [Configuration, update and real-time-time envelopes](../effects.md#configuration-update-and-real-time-time-envelopes). The development topology states all five as `full` for the classes its tasks run in (15 rows). A class with no row is `full`. |
| `[rtc]` | `dev` (required); `utc` (boolean, default `true`). | At most one section. |
| `[nic.NAME]` | `dev` required; `mtu` (576 to 9216, default 1500); `mac` (`aa:bb:cc:dd:ee:ff`). | One row per device. A MAC is unicast, not all-zero, and in no other row. |
| `[model.NAME]` | `bundle` (64 hex digits, required); `variant` (a name). | Bundle not all-zero and in no other row. |
| `[usb.NAME]` | `authorize` (`allow`, `deny`; required); `vid`, `pid` (4 hex digits each), `class` (0 to 255). | Rules are tried in file order, the first match decides, and a device no rule matches is refused. A `pid` needs a `vid`. A row without `vid` or `class` matches every device and ends the list; a repeated selector is unreachable. |

`verity_root` is the `[volume.NAME]` key above; format 8 adds no second one.

These rows are read by the fronts named in their `types.rs` doc comments;
until those land, nothing outside the topology crate reads them.

Source: `crates/core/topology/src/parser.rs` (`Kind8`, `Stage8` and the
stages beside it, `GuestStage`, `TaskExt`), `crates/core/topology/src/types.rs`
(`Topology::push_tsn` and the other `push_*` and `set_*` functions of the
rows, `format8_admission`, `set_last_task_boundary`, `push_guest`).

## Loading and installing

`install_topology` runs once, after the FAT32 volume is mounted and before any
task that takes capabilities from the topology exists. Which topology it
installs follows the Kconfig choice between `TOPOLOGY_SOURCE_BUILTIN`,
`TOPOLOGY_SOURCE_SIGNED_OR_BUILTIN` and `TOPOLOGY_SOURCE_SIGNED_REQUIRED`:

| Policy | Behaviour |
|--------|-----------|
| Built-in | The topology compiled into the image. The volume is not read. |
| Signed if present and valid, else built-in | The signed set when all three files are present and it is accepted; the built-in one when none are present. A set that is present but refused falls back to the built-in topology (`TOPOLOGY_INVALID_FALLBACK`), or halts (`TOPOLOGY_INVALID_HALT`). |
| Signed required | The signed set or no boot: a missing or refused set halts. |

A missing or refused set writes a safety record (`SAFETY_TOPO_SOURCE`) that
names the step and the file, and prints a line to the console.

For a signed set the order is fixed:

1. Read the three files. A partial set is refused (`Incomplete`), as is a file
   larger than its buffer (`TOPOLOGY_CAPS_MAX_KB`, `TOPOLOGY_SCHED_MAX_KB`).
2. Verify `CAPS.SIG` over the exact bytes of `CAPS.TOM` against the trusted key
   (`TRUSTED_PUBKEY`). No byte of the file is interpreted before this passes.
3. Read the top-level binding keys from the verified bytes (`parse_binding`).
4. Check the binding: `sched_sha256` must match the SHA-256 of `SCHED.TOM`
   (always required, it is what authenticates that file); `device` must match
   this device's id (required when `TOPOLOGY_BIND_DEVICE` is set, and checked
   whenever present); `counter` must be at least the floor kept in a reserved
   sector of the volume (required when `TOPOLOGY_COUNTER_FLOOR` is set). An
   older, validly signed file put back on the volume is refused as a replay.
5. Parse `SCHED.TOM`, then `CAPS.TOM`.
6. Run admission on the candidate (next section), before it is published.
7. Publish it. The slot is written once by the boot CPU; afterwards it is
   read-only, and a second `init` returns an error.

Parsing happens after verification because the parser is a byte-level state
machine fed from a volume that other software can write; verifying first
keeps it off unsigned input.

The trusted public key is embedded at build time from the file named by
`TOPOLOGY_PUBKEY_PATH`, or from the test public key in the `keys` directory under `tools` when the `dev-key`
feature is set. A build with neither fails, and a build configured as a
release refuses the test key. The same key verifies the signed `CONFIG.INI`.

Source: `crates/core/topology/src/signed.rs`, `crates/core/topology/src/verify.rs`,
`crates/core/topology/build.rs`, `crates/core/topology/src/state.rs`,
`kernel/src/boot/topology.rs`, `config/subsys/Kconfig.topology`.

## Admission

`Topology::admission_check` runs on every topology that is installed: the
signed candidate, the built-in one, and the ones the host tools build. It
returns the first failure as an `AdmissionError`. It cannot know the machine,
so it tests the real-time profiles against `deadline::MAX_ADMISSION_CPUS` CPUs
(32); the kernel then repeats the real-time check with the real CPU count and
adds the memory check against the real amount of free memory, once those are
known.

| Check | Refusal |
|-------|---------|
| The classes' `cpu_budget_min_pct` sum to at most 100. | `BudgetOverflow` |
| Every task names a declared class. | `UnknownClass` |
| No two rows hold `WRITE` on one motor; `flight` implies both wheels. | `MotorWriteConflict`, `FlightWithoutDrivetrain` |
| Every `imports` name is one the name server's row lends: the row holding `READ` on `endpoint.names` must also hold a `WRITE` grant with `transfer = true` and no `READ` on that name. | `UnknownImport` |
| Every `export` names an endpoint the row may lend and a declared peer class. | `UnknownExport` |
| No `neverallow` rule is broken (when `TOPOLOGY_NEVERALLOW` is set). | `Neverallow` |
| The real-time profiles are feasible (below). | `Deadline` |
| `isolated` rows name the one CPU of `isolcpus` they own; other rows avoid it. | `BadRow(Task)`, `Deadline(IsolatedWithoutCpu)` (no `cpu_mask`) |
| Every `[policy.NAME]` names an existing row. | `BadRow(Policy)` |
| A row in the real-time band with a reservation is `mem = "locked"`. | `Deadline(BandNotLocked)` |

Refused while the rows are read, before `admission_check` runs (the parser
returns them as `ParseError::Admission`, and the host tools that build a
topology get them from the same `push_*` and `set_last_task_*` methods):

| Rule | Refusal |
|------|---------|
| Class and task names are unique; the class and task tables are not full. | `DuplicateClass`, `DuplicateTask` |
| A class's `priority_range` is not inverted. | `InvalidPriorityRange` |
| A Linux-ABI row holds only `node` grants (`Topology::set_last_task_abi`). | `LinuxRowHoldsHardware` |
| Pool sizes, name alphabets, repeated names and the per-row rules listed in the sections above. | `BadRow`, `DuplicateRow`, `BadDevice`, `BadSigner`, `BadPeer`, `BadImport`, ... |

### Real-time feasibility

Only rows with a declared profile in a class with `admission_control = true`
are considered. The model is partitioned earliest-deadline-first:

- Each row runs on one CPU among those its `cpu_mask` allows.
- A row's density is `runtime_us / min(deadline_us, period_us)`, rounded up;
  the sum on one CPU must be at most 100 %.
- Rows are placed first-fit in decreasing density, equal densities in
  declaration order, so the verdict is deterministic.
- The rows of one class on one CPU may not exceed that class's
  `cpu_budget_max_pct`.
- Reservations placed on one CPU at different priority levels must also pass
  the cross-level rule shared with run-time `reserve`.
- A profile is malformed if the period or the runtime is zero, the deadline
  exceeds the period, the runtime exceeds the deadline, or the mask names no
  CPU.
- `isolcpus` may not cover every CPU of the machine.

The test is sufficient, not necessary: it never admits an infeasible set, and
it can refuse a feasible one.

At boot the kernel runs the test again with the real hart count, checks the
real-time band's share of each CPU (`RT_BAND_CAP_PCT`), and checks memory
admission: the frames the ring-3 rows may hold (a locked row once, a ceiling
row twice if its image may fork, each times `instances`), plus the kernel's
reserve, must fit in the free pages. A `mem_pages` unit is 4 KiB on every ISA
and page size.

Source: `crates/core/topology/src/deadline.rs` (`admit`, `SchedProfile`),
`crates/core/topology/src/types.rs` (`Topology::deadline_admission`),
`crates/core/topology/src/memory.rs`, `kernel/src/boot/topology.rs`.

### `neverallow`

The rules in `neverallow::RULES` state grants that no topology may make,
whatever its file says. A rule's exceptions live in the kernel image (in the
rule table), not in the topology, so a row cannot excuse itself.

| Rule | Forbids |
|------|---------|
| `actuation-outside-actuation-row` | A ring-3 row holding a motor, a PWM or GPIO write, or the buzzer, unless the table lists the row as an actuation row. |
| `desktop-grants-no-motor` | Any row holding a motor in a desktop image. |
| `names-import-and-service-export` | A row that imports names and also serves an endpoint or registers a driver. |
| `actuation-grant-not-transferable` | A motor, PWM, GPIO or buzzer grant that carries `TRANSFER`. |
| `proxy-endpoint-not-realtime` | A row with a real-time reservation or class holding any grant on a proxy endpoint (`endpoint.rpc-*`). |
| `proxy-endpoint-served-by-rpcsrv-only` | A row other than `RPCSRV.ELF` serving a proxy endpoint. |

A refusal writes a decision record naming the rule and the row.
`make check-neverallow` runs the rules over the topology of every preset and
defconfig, with no kernel build.

Source: `crates/core/topology/src/types.rs` (`Topology::admission_check`,
`isolation_admission`, `deadline_admission`), `crates/core/topology/src/deadline.rs`,
`crates/core/topology/src/memory.rs`, `crates/core/topology/src/neverallow.rs`,
`tools/check_neverallow.py`, `mk/lints.mk`.

## Producing the files

`emit` writes a `Topology` back out as the two files, in the same syntax the
parser reads. It writes every field the parser can express and refuses, with an
`EmitError`, anything it cannot (a grant whose kind has no word, a string with
a quote or backslash, an energy model). Fields at their default are left out.

The host emitter `topo_emit` (`tests/host/topology-tests/src/bin/topo_emit.rs`)
uses it to write the built-in topology of a configuration as `CAPS.TOM` and
`SCHED.TOM`. It is built with the same `.config` and the same topology features
as the kernel that will boot the files, parses its own output back, and exits
with an error unless the result equals the built-in topology field by field.

| Make target | Result |
|-------------|--------|
| `make topology-files` | Both ISAs' files under the build output root, unbound unless `TOPO_DEVICE` is given, signed with the test key (a fixture). |
| `make topo-volume TOPO_IMAGE=<img>` | Emits bound to the image's own device id and `TOPO_COUNTER`, signs `CAPS.TOM` with `TOPO_PRIV`, and copies the three files onto the image. The image must already carry its device record. |

`tools/gen_config_sig.py` writes the signature; `tools/device_provision.py`
writes the device record and the counter floor sector that the binding keys
are checked against.

Source: `crates/core/topology/src/emit.rs`,
`tests/host/topology-tests/src/bin/topo_emit.rs`, `mk/images.mk`,
`tools/gen_config_sig.py`, `tools/device_provision.py`.

## The built-in topology

`fill_default_minimal` in `builder.rs` builds the topology a kernel installs
when the policy is built-in, or when a signed set is absent or refused and the
policy falls back. It declares five classes (`safety_critical`, `hard_rt`,
`soft_rt`, `best_effort`, `idle`) whose minimum budgets sum to 100 %, the
kernel task rows, the rows of the images the configuration ships, and the
hardware bus rows of the board. Features of the topology crate add or remove
rows, which is how test configurations declare extra rows without widening the
default. The drivetrain grant, for example, is the `profile-actuation` feature
and is off unless the build turns it on.

Source: `crates/core/topology/src/builder.rs`, `crates/core/topology/Cargo.toml`.

## Limits

The topology is stored in fixed arrays. Their sizes are Kconfig symbols, so a
small profile pays for a small table. The ones that bound the formats above:
`MAX_TASKS`, `MAX_CAPS_TOTAL`, `MAX_CAPS_PER_TASK` (`config/limits/Kconfig.limits`),
and `TOPOLOGY_MAX_CLASSES`, `TOPOLOGY_MAX_PIPELINES`,
`TOPOLOGY_MAX_DEVICE_ROWS`, `TOPOLOGY_MAX_IMPORTS`, `TOPOLOGY_IMPORTS_TOTAL`,
`TOPOLOGY_MAX_SIGNERS`, `TOPOLOGY_SIGNER_WARRANTS_TOTAL`, `TOPOLOGY_MAX_PEERS`,
`TOPOLOGY_PEER_NODES`, `TOPOLOGY_EXPORTS_TOTAL`, `TOPOLOGY_MAX_POLICIES`,
`TOPOLOGY_MAX_LIVEPATCHES`, `TOPOLOGY_LEAP_ENTRIES`, `TOPOLOGY_MAX_SWAPS`,
`TOPOLOGY_MAX_VOLUMES`, `TOPOLOGY_MAX_GUESTS`, `TOPOLOGY_GUEST_DEVICES`,
`TOPOLOGY_MAX_ROUTES`, `TOPOLOGY_MAX_FIREWALL_ROWS`, `TOPOLOGY_MAX_TSN`,
`TOPOLOGY_MAX_FIELDBUS`, `TOPOLOGY_MAX_AUDIO`, `TOPOLOGY_MAX_DISPLAYS`,
`TOPOLOGY_MAX_USERS`, `TOPOLOGY_MAX_KEYS`, `TOPOLOGY_MAX_BOOT_STAGES`,
`TOPOLOGY_MAX_ISLANDS`, `TOPOLOGY_ISLAND_WAKE`, `TOPOLOGY_MAX_ACTIVITIES`,
`TOPOLOGY_MAX_NUMA`, `TOPOLOGY_MAX_ENVELOPES`, `TOPOLOGY_MAX_NICS`,
`TOPOLOGY_MAX_MODELS`, `TOPOLOGY_MAX_USB_RULES`, `TOPOLOGY_GUEST_PASSTHROUGH`,
`TOPOLOGY_NAME_MAX`,
`TOPOLOGY_TARGET_MAX`, `TOPOLOGY_INLINE_FIELDS_MAX` and the buffer sizes
`TOPOLOGY_CAPS_MAX_KB` and `TOPOLOGY_SCHED_MAX_KB` (`config/subsys/Kconfig.topology`).
A file that exceeds one of them is refused, never truncated.

Source: `config/limits/Kconfig.limits`, `config/subsys/Kconfig.topology`.

## Design choices and costs

- **A restricted syntax, parsed in place.** The parser has to run at boot with
  no allocator, on bytes read from a volume. A hand-written subset keeps the
  accepted language small enough to read in full, and everything outside it
  is an error. The cost is that a file that is valid TOML may be refused.
- **Verify, then parse, then admit.** Each step only sees the output of the
  one before it. A topology that fails any step is never published.
- **Fail closed.** Unknown keys, unknown sections, out-of-range values and
  keys from a later format are errors, so a typo cannot silently grant or
  withhold authority.
- **Names are data, authority is a grant.** An `imports` entry or a signer
  warrant states what may be asked for; only a grant in a signed row is
  authority.
- **One immutable topology per boot.** There is no run-time grant and no
  in-place update: a different topology means a different signed set and a
  reboot. This keeps every authority question answerable by reading one
  file.
- **All or nothing.** A single error refuses the whole file. The fallback
  and halt policies of the topology source choice decide what the machine
  does then.
- **Verbose.** A large deployment is hundreds of lines. The files are meant to
  be generated (`emit`, the make rules) and read, not edited blind.

Source: `crates/core/topology/src/parser.rs`, `crates/core/topology/src/signed.rs`,
`crates/core/topology/src/state.rs`.
