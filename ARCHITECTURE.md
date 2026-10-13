# AzOS architecture

This document describes how AzOS is put together and what it is meant to do.
It describes the code in this tree; where a mechanism exists only in part, the
text says so.

## Overview

AzOS is a hybrid kernel. The scheduler, memory manager, IPC, system-call layer,
file systems, network stack and most drivers run in one kernel image in
supervisor mode (S-mode on riscv64, EL1 on aarch64). Programs, services and a
few drivers run as isolated ring-3 tasks (U-mode / EL0). A component goes to
ring 3 when isolating it buys something, such as a driver that nothing
safety-related reads. It stays in the kernel when a safety decision reads it
or when the extra crossings add cost and no isolation.

The kernel is written in Rust (`no_std`). It builds for riscv64
(`riscv64imac-unknown-none-elf`) and aarch64 (`aarch64-unknown-none-softfloat`)
from one source tree and one kernel entry function.

```
 +----------------------------------------------------------------------+
 |  Host planner (separate repository, AzOSRobotBrain)    robot domain  |
 +-------------------------------^--------------------------------------+
                                 | planner link: TCP (UART bridge fallback),
                                 | framed protocol, optional encryption
 +-------------------------------|--------------------------------------+
 |  Ring 3 (U-mode / EL0)        |                                      |
 |   shell + tools   ML service  brain client   ring-3 drivers          |
 |   (SH, TOOLBOX)   (MLSRV)     (robot)        (INA219, buzzer)        |
 |   [optional] Linux personality: static Linux binaries (LINUX_ABI)    |
 |   [optional] Linux driver server skeleton (LINUX_DRIVERS)            |
 +---------- system calls: per-image filter + typed capabilities -------+
 |  Kernel core (S-mode / EL1)                                          |
 |   sched   mm   ipc + caps   syscall   topology   actuation authority |
 |   fs (VFS, FAT32, tmpfs, procfs)   net (TCP/IP)   drivers             |
 |   [robot domain] motor loop, safety envelope, flight, behavior        |
 +----------------------------------------------------------------------+
 |  Arch layer: arch-riscv64 (Sv39, SBI)   arch-aarch64 (VMSAv8-64, GIC) |
 +----------------------------------------------------------------------+
 |  Firmware: OpenSBI (riscv64)            PSCI (aarch64)                |
 +----------------------------------------------------------------------+
 |  Hardware: QEMU virt today; board descriptions for VisionFive 2, K1  |
 +----------------------------------------------------------------------+
```

The ISA crates implement one trait surface (`crates/core/arch-api`: CPU,
interrupts, MMU, boot, vectors, platform); `crates/core/arch` re-exports the
active one. The kernel's boot sequence per ISA is the `ArchEntry` trait (see
"Adding an ISA").

## Boot and composition

Both ISAs enter one `kernel_main` (`kernel/src/main.rs`). ISA-specific steps
are hooks under `kernel/src/entry/{riscv64,aarch64}/`.

**Early boot.** `kernel_main` first calls `boot::early_main`
(`kernel/src/boot/early.rs`), the same on every ISA, as Linux's
`start_kernel` calls `setup_arch`. It owns the common steps, in one order
for every ISA, and their log lines: the console, the device-tree parse, the
CPU count, the PCI host and the ring-3 interrupt trigger types (all read
before the page allocator may reuse the blob), the page allocator, the
panic-record region, the kernel page tables with every platform device
window mapped before they go live, W^X and NX over the image and RAM, the
null and stack guards, the heap, the vDSO page. Where the ISAs differ it
calls a hook of the kernel's `ArchEntry` implementation
(`kernel/src/entry/<isa>/arch_entry.rs` over `boot_hooks.rs`), in the order
the trait declares them: `pre_console`, `trap_init`, `boot_banner`,
`firmware_table`, `irqchip_probe`, `timer_probe`, `cpu_features`,
`firmware_memory`, `irq_trigger_controller`, `irq_triggers`,
`firmware_done`, `reserve_firmware_table`, `kernel_mmio_windows`,
`mmu_enabled`, `restrict_low_half`, `verify_guards`, `post_heap`,
`timebase_hz`, `irqchip_init`, `irq_enable_early`, `console_irq`,
`line_hooks`, `irq_routing_init`, `smp_probe`, `timer_init`,
`boot_selftests`. Every hook is required, `#[inline(always)]` on a
zero-sized type: no `dyn`, no table. The ISA's view of the firmware table
is its associated `Firmware` type; `early_main` reads it only through
`firmware_memory`. Code only one ISA runs lives beside the hooks:
`smp.rs` (the secondary-CPU wake), `board_map.rs` (the device windows),
and the ISA's self-tests (`aarch64/selftests.rs`, `riscv64/zicboz.rs`).

`tools/boot_seq_lint.py` lists the common steps and fails when one appears
in a `boot_hooks.rs` without a `// boot-seq: <why>` note, or when a step is
in neither `early_main` nor an ISA's hooks.

- **riscv64.** OpenSBI starts the kernel on one hart in S-mode. Secondary
  harts are started later with the SBI hart-state-management call.
- **aarch64.** The kernel runs at EL1. If it is entered at EL2 it drops to
  EL1. Secondary CPUs wait until they are started with PSCI `CPU_ON`, using
  the conduit named in the device tree.

`kernel_main` then runs these steps in order:

1. Early architecture setup: device-tree parse, physical memory, page tables,
   kernel heap, interrupt controller.
2. Entropy and block devices.
3. File systems: procfs at `/proc`, then FAT32 at `/fat`. After the mount it
   recovers the RAM panic record and opens the flight recorder.
4. The signed device configuration and the A/B image-slot verification.
5. The network stack, the watchdogs and the hardware the domain needs.
6. The topology install: the signed topology from the volume or the built-in
   one, then deadline and memory admission.
7. Kernel tasks, then the ring-3 programs. These are the autorun list from the
   configuration and the topology rows marked `start`.
8. Secondary CPUs, then the scheduler.

**Topology.** The topology is a table of scheduler classes and rows. A row
is keyed by the program's image name. It gives the task's priority, scheduling
profile (period, runtime, deadline, CPU mask), memory budget, the capabilities
minted for it, its restart policy and its ABI (native or Linux). Every ring-3
task the kernel starts gets its authority from its row.

The topology has two sources. One is built into the kernel image
(`crates/core/topology/src/builder.rs`). The other is a signed pair on the
FAT volume: `CAPS.TOM` (the rows) and `SCHED.TOM` (the classes), under one
bare Ed25519 signature, `CAPS.SIG`, made with the key that also signs
`CONFIG.SIG`. Before its first section, `CAPS.TOM` (format 4) carries a
binding inside the signed bytes: `sched_sha256`, the SHA-256 of the one
`SCHED.TOM` it goes with; `device`, the device id from the device record in
the reserved tail (the id `CONFIG.SIG` is bound to); and `counter`. At the
topology install the kernel reads the three files and verifies `CAPS.SIG`
before parsing anything. It then checks `SCHED.TOM`'s hash, the device id, and
that the counter is not below the floor it keeps in a reserved tail sector
(`TOPOLOGY_FLOOR_SECTOR`, the same raise-only rule as the configuration
counter). Only then does it parse the two files and run the same admission
the built-in topology passes (structure, deadline admission on the real CPU
count, the real-time band, memory) on the candidate before it is published.
Accepting a higher counter raises the floor. The Kconfig choice
`TOPOLOGY_SOURCE` decides what happens:

| Policy | Signed set valid | No set on the volume | Set present but refused |
|---|---|---|---|
| `BUILTIN` | not read | built-in | not read |
| `SIGNED_OR_BUILTIN` (QEMU default) | signed | built-in, warning, record | built-in, error, record (or halt with `TOPOLOGY_INVALID_HALT`) |
| `SIGNED_REQUIRED` (product default) | signed | record, halt | record, halt |

Every board other than QEMU (`BOARD_VF2`, `BOARD_K1`, `BOARD_GENERIC`)
defaults to `SIGNED_REQUIRED`, and every product make target builds the FAT
volume that carries the signed set, bound to the volume's device and signed
with the board key: `make vf2` builds `build/disk-board.img`, `make k1`
builds `build/disk-board-k1.img`, and `make build-fleet` builds
`build/disk-board-fleet.img`. Without the board signing key these targets
stop with an error instead of producing an unsigned volume.

The record is a durable `SAFETY_TOPO_SOURCE` flight-recorder entry whose
action says which case it was and whose detail names the file and the step
that refused. A halt stops the boot CPU before the scheduler starts and before
any task the topology admits is created. A partial set (some of the three
files) counts as present and refused. A set signed for another device, an
older counter, and a `SCHED.TOM` that is not the one `CAPS.TOM` names are each
refused with their own record detail. `TOPOLOGY_BIND_DEVICE` and
`TOPOLOGY_COUNTER_FLOOR` make the device and the counter optional (still
checked when present); the hash is always required. Whoever can rewrite the
reserved tail (a card reader, not the USB export) can reset the floor. The
file buffers are Kconfig sizes (`TOPOLOGY_CAPS_MAX_KB`,
`TOPOLOGY_SCHED_MAX_KB`) and stay allocated: the installed topology's names
point into them.

`make topo-volume TOPO_IMAGE=<image>` writes the built-in topology of a given
`.config` and kernel feature set onto an image, bound to that image's device
id and to `TOPO_COUNTER`, signed with the test key for QEMU images;
`build/disk-board.img` signs with the board key. The emitter parses its
output back and refuses to write a set that does not reproduce the built-in
topology field by field.

**Signed application packages (plan D14).** A package is images plus a
manifest of what they ask for, signed by their AUTHOR; the device decides what
an author's code may hold. `crates/core/pkg` is the format, the verification
and the admission, `tools/azpkg.py` builds, signs, verifies and inspects, and
`PKGD.ELF` (ring 3, the `Packages` interface on `endpoint.packages`) runs the
checks on the device. The file is a header (magic, algorithm id, the lengths of
the key and the signature, which are fields, so a post-quantum scheme is a new
algorithm id and not a new format), the author's key, the signature, a
metadata text (name, version, ABI, hardware classes, the lowest level of each
IDL interface it calls, the SBOM hash, one SHA-256 and size per image), the
rows and the images. The signature covers a 78-byte message: a domain tag, the
algorithm id and the SHA-256 of the metadata and of the rows; the images are
bound through the metadata, so the signature is checked before any image is
hashed. The rows are `[task.NAME]` sections in `CAPS.TOM`'s own syntax, so a
package's warrants (endpoint grants), scheduling budgets (class, period,
runtime) and memory budget are parsed and judged by the code that judges the
owner's rows.

The trust root is the topology key. From format 6 `CAPS.TOM` may carry
`[signer.NAME]` sections: an author's key id (`sha256(algorithm || key)`), a
ceiling of `kind:prefix` warrants, whether that author's packages may ask for
real time, and a frame ceiling per row. They are inside the signed bytes, so a
package cannot add a signer for itself, and a device whose topology has none
admits no package. Verification is in this order, none of it trusting what the
next step reads: structure, algorithm, the signer, the signature, then the
metadata, then the image hashes. Admission follows: hardware class, ABI
version, interface levels, then the rows are parsed into the topology (only
`[task.NAME]` sections; no `[operator]`, `[pipeline]`, `[class]` or `[signer]`),
each image must have exactly one row and each row one image, each grant must
lie inside the signer's ceiling, and the merged topology must pass
`admission_check`: the `neverallow` rules (a package row holding a motor, a PWM
or GPIO write is refused as any ring-3 row is), one writer per motor, the
real-time admission. A refusal rolls the topology back to where it was. The
installer judges a package against the topology plus the packages already
staged, so two that cannot coexist are not both accepted.

Installing is an effect, and is recorded: `PKG.ELF install FILE` hands the
installer a memory object holding the file and its length (never a path:
a `Cap<File>` names a descriptor of the task that opened it), and an admitted package is staged
whole as `/fat/PKG/XXXXXXXX.PKG` while the decision, with the package id
(`sha256(message || key id)`) as the provenance hash, is appended to
`/fat/PKG/JOURNAL.BIN` as a 104-byte `ProvenanceRecord`
(`Rule::PackageInstall`). A refusal is journalled too, and an install that
cannot be journalled is undone. Staging is not applying, and nothing
applies yet: a staged package's rows join no topology and none of its images
runs (the installer's own later admissions are judged against it, and that is
all). The application is the kernel's, at boot, and it is not built. It must
verify and admit the staged package again against the topology it is booting,
with the device id and the counter floor the ring-3 installer cannot check,
because anyone who can write the volume can write `/fat/PKG`. A row's `imports`
are held to the signer's `endpoint:` warrants like a grant (a name is authority),
and a staged file is named by four bytes of its package id, moving on to the
next four when another package holds the name. Each package also has an SPDX 2.3
SBOM whose hash is a signed key of its manifest, and `tools/azpkg.py` refuses
to build a package whose images, components or source tags carry a licence
outside `tools/azpkg_licences.txt`.

**Image hashes.** The build hashes each shipped ring-3 ELF.
`userspace/image_hashes.py` writes `build/image_hashes.rs`, a table from
SHA-256 digest to image name, and the kernel compiles it in. The image name
selects both the system-call filter and the topology row.

**Device configuration.** `/fat/CONFIG.INI` holds per-device settings: the
autorun list, network addresses, tick rate, watchdog timeouts, link options,
and the robot's control parameters. The kernel accepts it only with a valid
`CONFIG.SIG`. The signature is Ed25519 over a domain tag, the device id, a
counter and the SHA-256 of the file. The device id must match the one in the
device record on the boot medium. The counter must not be lower than the floor
stored there, and accepting a higher counter raises the floor.

If the signature fails, the kernel falls back to factory defaults. On an
unprovisioned device those defaults fail closed: there is no autorun and no
update listener. On a provisioned device that has lost its configuration
authority, the kernel also latches the e-stop and writes a safety record.

## Tasks and scheduling

- **Scheduler.** The production scheduler is a priority scheduler with 32
  levels and per-CPU run queues. Level 0 is the most urgent and level 31 is
  idle. A second backend, adaptive partitioning, can be selected in Kconfig.
  It is experimental, and it falls back to the priority scheduler on error.
- **Real-time band.** Priorities below 12 form the real-time band. The
  periodic tick does not preempt a band task.
- **Band cap.** Each CPU limits how much of a time window the band may use
  while a non-band task is ready on that CPU. The limit is `RT_BAND_CAP_PCT`
  of `RT_BAND_WINDOW_MS`.
- **Admission.** Admission is a capacity check, not a deadline scheduler. At
  boot, the deadline rows of the topology are admitted against the number of
  CPUs found at boot and against the band cap. A set that does not
  fit stops the boot. Reservations made after boot are placed on an online
  CPU, first fit, against the same limit. Admission still treats a priority
  level as the unit EDF orders within (dispatch now orders reservations by
  deadline across levels, so the test is conservative), so a CPU whose
  reservations sit at different levels must also pass a cross-level test: for each level, its density plus the
  density of the levels above, plus their budgets over its shortest deadline,
  must not exceed the CPU. Boot and run-time admission apply the same test
  to the same levels: a topology row that fails it on every CPU it may use
  stops the boot, naming the row and the levels, and a reservation made
  after boot that fails it is refused.
- **Dispatch classes.** Every task has a scheduling context (SC, 64 bytes,
  its layout fixed by a build-time size check) holding its class, its time
  parameters and the fields the wait graph and mixed criticality use. The
  classes are stop, deadline (tasks with an admitted reservation), real-time
  (the band), fair and idle, in that fixed order of precedence. Each is an
  implementation of one class interface (enqueue, dequeue, pick, tick,
  preemption check) over the run queues above; `SCHED_CLASS_STOP`, `_DL` and
  `_RT` remove a class from the build, fair and idle are always present. The
  context switch takes its pick from the priority levels and the
  reservation sets as described above, and that pick is the class order:
  on a CPU with RT state, the band's exempt safety loops (actuation,
  e-stop, watchdog) are the stop class and run first, an eligible
  reservation runs before every other band level, reservations are ordered
  by absolute deadline alone, and the band cap and window are charged as
  before.
  `SYS_SCHEDCTL` moves the calling task between classes: to a fair
  priority freely, to an RT band priority or to a deadline reservation
  (admitted like a topology row's) only with a capability to the `time` endpoint holding
  `WRITE`, which only a topology row grants (`endpoint = "time"`). A refusal is
  recorded as a capability denial. With `WAIT_GRAPH`
  (default on) the SC's `blocked_on` names the object a task waits on in a
  wait graph: each object keeps its waiters by urgency, an owner runs at the
  most urgent attribute among its own and its waiters' (a deadline waiter
  passes its absolute deadline), a chain walk carries a boost through at
  most `PI_MAX_DEPTH` owners, and a block that would close a cycle fails
  with `EDEADLK`. The kernel mutex and PI futexes use it. When
  an owner exits still holding an object with waiters, the graph detaches
  it and calls the object kind's owner-died handler: the kernel mutex then
  wakes its waiters and the most urgent one takes it (the `EOWNERDEAD`
  rule), and that next owner's guard reports `owner_died()` until it
  unlocks, so it can revalidate the data; robust PI futexes are handed over earlier, by the robust list.
- **SMP.** The kernel places a waking unpinned task on a suitable CPU and
  signals other CPUs with an inter-processor interrupt (SBI on riscv64,
  GICv3 SGI on aarch64). Tasks are not stolen between run queues at run time.
  A task pinned to a CPU the boot does not have is re-pinned, with a warning,
  when it is created.
- **CPU ceiling.** `NR_CPUS` (Kconfig, 1 to 64) is the largest CPU id plus
  one a build can run, as `CONFIG_NR_CPUS` is in Linux. Its default depends
  on the board and profile: 8 on the K1, 5 on the VF2 (its S7 monitor core is
  hart 0 and the four U74 cores are harts 1 to 4), 4 on the embedded profile,
  and 64 otherwise. A CPU id is the hart id on riscv64 and the boot-assigned
  logical id on aarch64. Both are kept in the per-CPU register (`tp` or
  `TPIDR_EL1`), read and written through the `Cpu` trait of the
  architecture API (`percpu_base`, `set_percpu_base`).
- **Possible and online CPUs.** The boot hooks describe the firmware's CPUs
  in one structure (`FirmwareCpus`, filled from the DTB's `/cpus` on both
  ISAs). The count is cut to `NR_CPUS`. The cut is logged as a warning, and
  the CPUs above the ceiling are never started. The result is the
  possible-CPU mask and `nr_cpu_ids`. The online mask is kept separate, so a
  CPU can later leave it without moving any per-CPU state. CPU hotplug is not
  implemented.
- **Per-CPU areas.** At boot, after the heap and before the scheduler or any
  secondary CPU starts, the kernel allocates one area per possible CPU from
  the frame allocator. An area holds that CPU's run queues, real-time band
  reservations, adaptive-partitioning tables and trace-ring producer. The
  run queues are linked lists threaded through one table of one link per
  task slot, so an area's size does not depend on `MAX_TASKS`. A
  secondary CPU's area also holds its boot stack (`SECONDARY_STACK_SIZE_KB`)
  and its interrupt stack (`INTERRUPT_STACK_SIZE_KB`). Each per-CPU variable
  is reached through a table of one pointer per CPU, indexed by CPU id. A CPU
  without an area holds a non-canonical address there, so an access faults
  instead of reading another CPU's state, and a boot self-check verifies
  this.
- **Static per-CPU tables.** Some per-CPU state stays in fixed tables sized
  by `NR_CPUS`, because it is needed before the areas exist or is indexed by
  assembly:
  - the preemption counters and interrupt-depth counters (every lock uses
    them from the first console line);
  - the slab allocator's per-CPU magazine pointers (the heap serves
    allocations before the areas exist);
  - the scheduler's current-task word, ready bitmap and CPU locks (32 bytes
    and one word per CPU, read on every system call);
  - the tables of stack addresses and published page-table roots that
    `boot.S`, `trap_entry.S` and the context switch read by symbol;
  - riscv64's per-hart trap-vector slots and aarch64's per-core bring-up
    records.

  Together these cost under 500 bytes of image per CPU of the ceiling. The
  boot CPU keeps the linker's boot stack and one static interrupt stack.
- **Tickless idle.** A CPU whose run queue is empty programs its timer for the
  nearest timer deadline instead of the periodic tick, bounded by an idle
  ceiling, or by a shorter keep-alive or polling interval when one is needed. It restores the periodic tick when work arrives.

## Memory

- **Page tables.** riscv64 uses Sv39. aarch64 uses VMSAv8-64 with a 4 KiB,
  16 KiB or 64 KiB granule, chosen at build time. x86_64 uses 4-level
  paging, or 5-level (LA57) when Kconfig allows it and the CPU has it. On
  aarch64 the kernel is linked in the upper half and runs from TTBR1, and
  TTBR0 holds the user space. On x86_64 the kernel image is linked in the top
  2 GiB (the compiler's kernel code model) and RAM is reached through a
  separate direct map (Linux's physmap base, 64 TiB), with the firmware
  map's holes left out of it; every user root shares the kernel's
  top-level entries. On both, the low half of the kernel's own
  table holds device windows only, which the boot reads back. On riscv64
  the kernel shares each user root: every 1 GiB slot above the user
  address space is one kernel table linked into every root, and its leaves
  carry the global bit (Kconfig `RV_KERNEL_GLOBAL`). The slots below it
  (user code beside the kernel's low device windows) keep each root's own
  table and are never global. A device window mapped after task roots exist
  is pushed into every live root (riscv64 and x86_64). A mapper writing a
  user root walks the kernel's table in step and refuses to descend into a
  table the kernel shares, so a push that lands mid-walk cannot make a user
  page appear in every address space; a user unmap leaves the kernel's
  device leaves in its own table alone. On aarch64 a task's
  `TTBR0_EL1` root gets the recorded device windows when it is built; every
  window the kernel maps is mapped during boot, before the first task root
  exists, so there is nothing to push.
- **Kernel W^X.** Once paging is on, the kernel image is mapped with text
  read-execute, read-only data read-only, and data read-write. Execute
  permission is removed from all RAM outside the image. Both properties are
  checked by reading the page tables back at boot, and a failed check is
  reported on the console. One path writes kernel text after that:
  `azos_mm::text_poke`, used only by the tracer's static keys. It refuses
  unless the instruction's page is mapped read-execute and not writable. It
  maps that frame at a temporary alias above the RAM map, read-write and
  never executable, and writes one aligned 32-bit word through it. Then it
  unmaps the alias with a TLB shootdown on every CPU and synchronises every
  CPU's instruction fetch. The text mapping itself stays read-execute: a
  write through it takes a kernel store fault, and a gate canary checks
  that.
- **User W^X.**
  - `fork` shares read-only and executable pages and marks only writable
    pages copy-on-write. The copy-on-write fault handler refuses an entry that
    is executable.
  - `mprotect` refuses `PROT_EXEC` and refuses write access to an executable
    mapping or to the vDSO and signal-trampoline pages, which every address
    space shares. The Linux personality's `mprotect` uses the same code.
  - The ELF loader maps each `PT_LOAD` segment with its own permissions
    (read-only, read-execute, read-write) and refuses an image in which two
    segments mapped differently share a page, or (Kconfig
    `ELF_REFUSE_EXEC_HEADERS`) in which an executable segment covers the ELF
    headers, the program-header sign of read-only data linked into the text
    segment. A build-time lint checks every user image, section headers
    included, at the page size of each aarch64 granule.
- **Demand paging.** Demand paging goes through a `Pager` trait
  (`crates/core/mm`). The one pager in the tree serves zero-filled anonymous
  memory. File-backed paging does not exist.
- **Shared program text.** The executable frames of a program image are kept
  once, with a reference count, and mapped read-execute into every task that
  runs that image. Data pages are copied for each task.
- **Quotas.** Each task's page frames are charged against the memory budget in
  its topology row. The charge covers the image, the stack, the page tables
  and demand-paging reservations, and a thread group is charged to its
  leader. Copy-on-write breaks are counted but not charged. At boot, the sum
  of the row budgets is checked against RAM.
- **Allocators.** The physical frame allocator is a buddy allocator over one
  32-byte descriptor per frame of all the RAM the firmware reports (state,
  owner, copy-on-write share count), with a small per-hart cache of single
  frames in front of its one lock. The kernel heap is
  a first-fit linked-list allocator over a region reserved at boot. In front
  of it, by default, sits a per-CPU cache of fixed size classes (Kconfig
  `KHEAP_SLAB`): each CPU holds two magazines of free objects per class, a
  per-class depot trades full and empty magazines between CPUs, and objects
  are carved from slabs taken from the heap. A small allocation or free is a
  magazine pop or push with interrupts masked on that CPU: no lock, no heap
  walk. Larger requests go to the heap. When the heap refuses, the cache
  returns what it holds and the request is retried once; a second refusal is
  returned to the caller. Class sizes, magazine depth, per-CPU and depot
  limits and debug poisoning are Kconfig options with per-profile defaults.
- **Ring-3 allocator.** Native programs get their heap from `azos_ualloc`
  (`userspace/lib/ualloc`), a hardened allocator in Scudo's shape. Requests up
  to 2 KiB are cut from per-size-class blocks that a class takes from
  `SYS_MMAP` when it runs out (the kernel charges a mapping whole, so blocks
  are Kconfig-sized, `USER_ALLOC_BLOCK_KB`); larger ones get a mapping of
  their own, unmapped on free and never mapped again, since `mmap` only moves
  the break up and `brk` does not shrink it. Every chunk has a 16-byte header with its size, class, state
  and a 32-bit checksum keyed with a cookie read from the kernel entropy pool
  (`SYS_ENTROPY_READ_TYPED`, the `entropy` capability) and the chunk's own
  address. Double frees, pointers the allocator did not hand out, overwritten
  headers, a wrong size on a sized free and corrupted free-list links (masked
  with the cookie, checked against the block table) end in a recorded fault:
  one `[ualloc]` line and a trap instruction, so the kernel kills the task
  with a fault status. Which free slot an allocation takes, the order a fresh
  block is handed out in, the position of a large allocation inside its pages
  and the quarantine's eviction order are random when the pool seeds them. A
  quarantine holds freed chunks back (`USER_ALLOC_QUARANTINE_KB`), their first
  512 bytes poisoned and checked as they leave, so a write through a stale
  pointer is caught. Blocks and large allocations sit between guard pages: an
  `mmap` with `prot = 0` reserves the range and maps nothing (there is no
  ring-3 `mprotect`), and a touch kills the task. The engine
  is generic over the system calls, so `tests/host/ualloc-tests` runs it over
  a model with each detection and its control. `USER_ALLOC_*` default on in
  every `SECURITY` posture but `general`; `LXSRV.ELF` is the first user.

## IPC and capabilities

**Capability tables.** Each task has a capability table, sized per resource
profile. A handle is 32 bits and packs the object type, the rights (read,
write, exec, dup), a generation and a slot index. The type is a generic kind
(four bits) and a class within it (two bits, a `CapType`). Each typed call checks, in
order:

1. the slot exists,
2. the generation matches,
3. the kind is the one the call expects,
4. the handle carries the needed rights.

A stale or wrongly typed handle fails. There are eight generic kinds: Endpoint
(an IPC rendezvous, or a kernel-hosted interface), MemObj (shared memory, a
lease), Queue (an io_ring), Port, Domain (a task), Node (a file,
a socket, a pipe, the right to launch an image), Device (an interrupt line, a
hardware-bus device and its register window, a driver slot) and Log (the tracer). What a capability names
within its kind is its class, and what a device or a kernel service offers is
an endpoint interface, not a kind. A denial is recorded under the kind. Capabilities are minted from the topology at spawn.
No call grants or duplicates a capability to another task; the only transfer
is a move with a fast call. Revocation is done by the kernel.

Each slot's hot word is one 64-bit word (kind, rights, generation,
resource), so with Kconfig `RCU_QSBR` the checks above and the find-by-resource call
(`SYS_CAP_INFO`) read the table without its lock: a reader sees a slot
whole, as of one writer's store, and the tables are never freed. Writers
still take the table's lock. Each table keeps a small direct-mapped cache
(Kconfig `CAP_LOOKUP_CACHE`) of the slot a lookup of a (kind, resource)
found; a hit is checked against the slot, and a grant of the key clears its
entry, so the lowest matching slot is still the answer. Searches stop past
the highest slot granted since the table was last wiped, and a grant's
search for a free slot starts at the lowest slot that may be free.

With Kconfig `CAP_SLOT_EXT` a slot is 128 bits: the hot word and an
extension word holding the badge and a reserved field (eight more rights
bits). A grant stores the extension word before the hot word that publishes it; a
lock-free read of the extension word checks the hot word before and after,
and a slot's generation never repeats. Only the paths that need the badge
read the second word. A badged copy is minted only from an unbadged
endpoint capability that carries `DUP` (`CapTable::mint_badged`; the badge
is set once; `SYS_CAP_DERIVE`); the badge moves with the capability.
A fork child holds no badged capability: the
parent's endpoint capabilities are not copied (the child's come from its
topology row, unbadged, and from the parent's own endpoints, `WRITE` only),
and the fork's install of the parent's handles writes an empty extension
word, so a reused table never shows its previous owner's badge. A badge
names one client the server minted it for; a child is a principal the
server never saw.

Every slot also carries a warrant (`cap.rs`, `Warrant`): the slot it was
derived from (domain key, slot and generation, so a parent can be in any
domain), its depth below a root, an optional monotonic deadline and an
optional quota (a count or bytes, a field for later charging). A dup transfer
and a badged mint derive, and rights, deadline and quota only narrow
(`derive_warrant`; a Kani proof says it never widens); a move keeps the place
the capability has. Revoking a capability revokes the whole subtree below it,
across domains: whatever frees a slot that something was derived from owes a
sweep (`cap_store::sweep`), which frees every slot whose parent is dead until
a pass frees none, at most `WARRANT_DEPTH_MAX + 1` passes, one table lock at a
time. A parent is alive only if its domain still owns its table and the slot
still holds the referenced generation, so a reused slot or domain never
resurrects a descendant. Each holder whose slot was revoked gets a pending
notice (`take_notices`, or `Revoked` from the next refused use of a dead
handle); a deadline is checked on use and fails as `Revoked`. Every derive and
revoke writes a decision record (`Rule::CapDerive`, `Rule::CapRevoke`) naming
the slot, its parent and the domain.

Hardware is reached through capability-typed calls. MMIO and
IRQ capabilities name an entry in the board's resource table, never an
address.

**IPC mechanisms:**

- **Fast call.** Synchronous call and reply through a capability to an
  endpoint; the endpoint is the only address (no call names a task). The
  message travels in registers (four 64-bit words), with priority donation
  to the server. A capability can be moved with a call. The receiver gets a
  fresh generation, so the sender's handle becomes stale.
  The call (`crates/core/ipc/src/ep_queue.rs`) queues on its endpoint. Each task slot has one call record (a caller
  blocks for its answer), so the number of calls in flight is bounded only
  by the number of tasks. Each endpoint has a send queue (calls no server
  has taken, in arrival order), threaded through the records under the
  endpoint's own `SpinLock`, always taken with interrupts off; a call a
  server has taken is on no list, its record naming the endpoint. Each task slot has a ready
  mask with one bit per endpoint it serves that has calls queued, so an
  accept (which names no endpoint) finds work with one load. The call is
  checked again under the queue lock against the endpoint it looked up. A
  record's identity is one atomic word (generation,
  endpoint, state), and the handle both sides hold is the record and its
  generation, so a reply or a collect for a call that is over finds nothing;
  an answered call is collected without the lock.
  When the serving task dies, every call queued on its endpoints or in
  service there completes with `-EPEERDIED` (a named endpoint is then kept,
  unserved and empty, for a successor); when the owner destroys an
  endpoint, its calls complete with `-EREVOKED`. A caller that
  gives up withdraws its call and frees its record. The call
  path takes no lock to find the endpoint: its generation and serving task
  are one atomic word, read in a QSBR read section (`endpoint.rs`), and a
  destroyed endpoint's slot goes back to the pool only after a grace period
  (`call_rcu`).
  With Kconfig `IPC_PORT_NOTICES`, the kernel counts each endpoint's send
  capabilities: `Cap<Endpoint>`s with `WRITE` and without `READ` (`READ` is
  the right to serve, so the server's own `RW` is not one). The count changes
  where a table slot is written or cleared (`cap.rs`, `cap::senders`), so it
  stays exact through a grant, a move (one that lowers `RW` to `WRITE` adds a
  sender), a revoke, the fork copy and the table wipe at a task's exit; the
  fast call itself does no capability operation unless it moves one. The
  serving task may bind its endpoint to an event port (the port's bind op,
  source 4, `READ` and serving required). When the count falls to zero the
  port reports one no-senders event (code `ENOSENDERS`), posted after the
  table lock is released; a bind made when there is no sender reports one at
  once.

  **Reply warrant and message descriptor (ABI v2 of the call).** The right
  to answer an accepted call is held in its record by one task, at first
  the server that accepted it. The holder can move it to another task (a
  worker); from then on only that task can answer, and only once: the
  first reply moves the record out of the accepted state and every later
  reply is refused. A task that dies holding a warrant completes the call
  with `-EPEERDIED`. A v2 call records the badge of the endpoint
  capability it went through, and the server reads it on accept; a v1
  call reads as unbadged, never as an earlier call's badge. The v2 message
  layout is one `repr(C)` descriptor (`azos_abi::ipc_msg::MsgDesc`): a version,
  up to `IPC_MSG_INLINE_WORDS` inline words (per ISA), and up to
  `IPC_MSG_MAX_CAPS` capability entries, each MOVE or DUP with rights that
  may only be lowered and an `expiry_ns` (absolute MONO nanoseconds, 0 =
  the sender's own) that may only be shortened: the receiver's copy lapses
  there, the kernel takes the earlier of it and the sender's own, and an
  entry born expired is refused like a passed deadline (`-EDEADLINE`). The
  name server stamps every endpoint it lends with `now + NAMES_LEND_TTL_MS`;
  a borrower whose lease lapsed asks again (`azos_names::Renewing`). The
  entries transfer all or nothing: every one is
  checked under both tables' locks (live, `DUP`, rights, no slot twice,
  room in the receiver) before the sender loses any; on a refusal the
  MOVE entries are consumed unless the message carries `KEEP`
  (`cap_store::move_caps`). The v1 fast call is unchanged. The v2 calls
  are `SYS_IPC_CALL_V2`, `SYS_IPC_ACCEPT_V2`, `SYS_IPC_REPLY_V2` and
  `SYS_IPC_REPLY_DELEGATE`, which moves the warrant only to a thread of
  the holder's own process. They share the v1 call queue: the v2 message
  waits beside its call record. A v2 server accepts v1 calls; a v1 accept
  refuses a v2 call instead of taking it: the server sees nothing, the
  caller gets `-EV1ACCEPT`, every MOVE capability the call carried goes
  back to the caller and every DUP copy is destroyed. A message no server
  took never leaves a capability in a server's table: a caller that exits
  before it collects, or an endpoint destroyed under a queued call, has
  every one revoked.
- **Kernel-hosted endpoints.** A device or a kernel service is an endpoint,
  not a syscall number and not a capability kind. An `Endpoint` capability
  whose owner is the kernel (`azos_ipc::endpoint::kernel_host`, owner words
  from `0xFFFF_0001`) is served by the kernel itself: `SYS_IPC_CALL_V2`, or
  the register form `SYS_IPC_FAST_CALL_EP` for an interface declared
  `words = 4`, decodes the request with the interface's IDL dispatcher
  (`crates/core/devif`, `crates/core/syscall/src/khost.rs`) and runs the op on
  the caller's own stack: no queue, no task switch, no allocation. The
  capability's **badge** is the resource (a pin, a bus and an address, a wheel
  pair, a partition) and its **rights** are the op classes: `READ` observes,
  `WRITE` acts, `EXEC` controls. Any right may call the endpoint; the op checks
  its class (`Caller::allows`), and a contained system (RFC-0036) refuses the
  acting class only. A topology row grants one with `endpoint = "<iface>[.<resource>]"`
  (`entropy`, ...); a task finds it with `SYS_CAP_INFO` (the lookup query: `Endpoint`, `host_key << 32 | badge`).
  A ring-3 driver serves the same trait from its own endpoint and the client
  stub does not know which. Ops answer with a typed outcome (`azos_devif::outcome`),
  never an `errno`. The seccomp row of an image lists the interfaces it may call
  (`ImageProfile::ifaces`, `SyscallFilter::ifaces`): the syscall list says "may
  call an endpoint" and this says which, so a binary that may read the entropy
  pool still cannot touch the power endpoint; an unlisted interface kills the
  task (audit mode records it), and a grant of an interface the image does not
  list is withheld at seeding. Interfaces so far: `entropy`, `linkkey` (the
  brain-link PSK), `power` (shutdown, reboot, suspend, the scheduler rate and
  the energy policy), `flight`, `behavior`, `config` and `ota` (the recovery
  console's families), and the devices `gpio` (badge = pin), `i2c` (badge =
  `bus << 8 | address`; a transfer is at most 32 bytes inline) and `pwm`
  (badge = channel), the last two registers' worth of calls on the register
  form, and `motor` (badge = wheel: per-wheel ops need `WRITE`, the PID ops
  need `WRITE` on both wheels, `estop` on the wheel used; the halt rule stays in the motor
  layer, so a latched e-stop refuses a command whoever sends it) and `sensor`
  (badge = sensor type 0..9, `READ` only: a read returns the record and its
  acquisition stamp on the vDSO clock, `bind_vdso` publishes the sensor on the
  caller's vDSO page; the LiDAR scan and the camera frame do not fit a reply
  and answer `UNSUPPORTED`, they travel on `stream.lidar` / `stream.camera` and
  the io_ring's `READ_SENSOR` op), `block` (badge = partition `n + 1`, from the
  row `block.part.<n>`: `sectors` answers the partition's length and the
  sectors move through the io_ring's `OP_BLOCK_READ` / `OP_BLOCK_WRITE`, at
  most four per entry, partition-relative, refused and recorded past the
  partition's end) and `time` (no resource: the warrant `SYS_SCHEDCTL` asks
  for; `classes` says what it covers). A pin or a
  channel a motor drives is refused to a holder (`REFUSED`): the motor path is
  the gated one. The io_ring's device ops
  check the same endpoints (`ring_dev_ok`) and ask the submitter's profile for
  the interface (`OpGate::Iface`) instead of a syscall number. The topology
  admits `WRITE` on `flight` only for a row that also holds `WRITE` on both
  drivetrain wheels (arming is authority over the whole drivetrain). A badge
  needs Kconfig `CAP_SLOT_EXT` (default y): without it every endpoint
  capability reads as resource 0 and a device with a resource cannot be
  granted.
- **Channels.** Asynchronous queues of small fixed-size messages.
- **Shared memory and rings.**
  - A MemObj (`crates/core/ipc/src/memobj.rs`) is the one object for memory
    that is named, charged, transferred or shared; `Cap<Shm>` names it.
    Kinds: Anon (zero-filled frames), Contig (a physically contiguous run, with
    a device-visible flag), and a reserved Paged. (A Phys kind for device or
    scanout memory waits for its first user.) Attributes: swappable (stored),
    NO_KERNEL_MAP (the kernel never reads it through the direct map), and a
    reserved volatile. The frames are charged to the Domain that holds the
    owning reference. A map is bounded by the capability's rights, so a READ
    share of a writable object maps read-only. A clone is a copy-on-write
    snapshot (frames shared through the frame count until a write mapping).
    A MOVE entry of an IPC transfer hands the references, the ownership and
    the charge to the receiver and removes the sender's mapping; a DUP entry
    is a SHARE (a v1 fast call shares with `FAST_CALL_CAP_SHARE`). The protect
    form of `SYS_MO_MAP` changes a whole mapping within what its map was
    allowed. Anonymous memory (`SYS_MO_MAP` with handle 0) is the same object
    without a table slot: a private Anon reservation on the marker-PTE path.
  - `io_ring` is a submission and completion ring shared between a task and
    the kernel. The kernel checks each entry against the task's filter and
    capabilities. A file write or a send completes when it is queued (flag
    `QUEUED`); an `OP_FSYNC` never waits in the submit: it parks and is
    completed `DURABLE` from the filesystem's flush task once the flush is
    done. A `LINK` flag on an entry makes the next one run only if it
    succeeded, and a linked entry that parks holds back the rest. A
    real-time task never runs a file entry itself: its pass stops there and
    a kernel worker outside the real-time band runs the rest of the batch,
    in order, completing it through the same ring. A send names a
    `Cap<Socket>` and completes when the bytes are queued.
  - Single-producer single-consumer rings in a shared region carry data
    between tasks and from kernel sensor streams to ring 3.
- **Notifications.** A futex-style wait and wake on a word in a
  shared-memory region. Event ports multiplex channels, rings, timers,
  interrupts and endpoint notices. An event is 16 bytes: key, source type,
  a code (a positive errno for a notice, 0 otherwise) and the source's
  handle. With Kconfig `IPC_PORT_NOTICES`, a bound channel, ring, endpoint
  or interrupt that is destroyed, or whose owner dies, reports one
  source-gone event (code `EREVOKED` or `EPEERDIED`) held in its own source
  slot, so it is never dropped, and the slot is freed when the event is
  taken: a task waiting on the port is woken rather than left waiting for a
  source that no longer exists.
- **Futex table.** Every futex-style waiter, native or Linux, is filed in
  one table of hashed buckets. A process-private word is keyed by (process,
  address) and hashes into its process's bank of buckets; a word in a
  shared-memory region is keyed by (region, offset), so a native notify and
  a Linux shared futex on the same word meet, whatever address each process
  maps it at. Requeue (`FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`) moves waiters
  between words without waking them. With Kconfig `FUTEX_PI`, a
  `FUTEX_WAIT_REQUEUE_PI` waiter is taken only by `FUTEX_CMP_REQUEUE_PI` to
  its PI word: the top waiter wakes owning that word when it is free, and
  the others are enqueued on the word's wait-graph object on their behalf
  without being woken, so the owner is boosted at once; each wakes when
  the word is handed to it, or on a signal or its timeout, and finishes
  the lock itself (as Linux does). A plain wake or requeue that would reach
  such a waiter answers `EINVAL` and takes nobody. Exit-path wakes (the robust list and the
  clear-child-tid word) key a shared-memory word by its region. Each key that has
  priority-inheritance state keeps its own slot for it, chained from its
  bucket. Kconfig `FUTEX_SHARED`, `FUTEX_REQUEUE` and
  the bucket counts select the parts.
- **Leases.** A lease grants a shared-memory region from one task to another
  for a bounded time, for example for zero-copy camera frames or inference
  inputs. The mapping belongs to the lease and is removed when the lease is
  returned, freed or expires.
- **Transparent RPC** (`userspace/services/rpcsrv`, engine in
  `userspace/lib/rpc`). An endpoint on another node is called as a local one:
  the topology names a **proxy endpoint** `endpoint.rpc-<service>`, the RPC
  server (ring 3, no authority beyond its row) serves it, and the caller uses
  the same IDL stub and the same `MsgDesc`. The server reads the header word
  to find which peer serves the interface and sends the message **in the IDL
  wire format** in a frame (a 40-byte header, then the descriptor as it is:
  inline words and capability entries, with the deadline as time remaining and
  its clock class, and the pages of each MemObj after the entries; the sender's
  object is consumed and the far side re-mints a new one). The node on the
  other side runs the call against the real endpoint. Nothing leaves a node
  except through an `export = ["name@class"]` entry of the RPC server's row to
  a `[peer.class]` of the signed topology (CAPS.TOML format 6; `/proc/rpc` is
  the server's view of it), and the exporting node calls the service through a
  **per-session warrant**: a child of its own capability, attenuated to the
  call right, badged with the session, expiring after `RPC_WARRANT_TTL_MS` and
  renewed while used. A MemObj that crossed is lent as a copy that lapses the
  same way. Both nodes append to a provenance journal (the kernel's
  `ProvenanceRecord`, with the peer's node id and the session id filled), and
  a **broken session** (probes unanswered `RPC_MISS_LIMIT` times, or a Bye)
  revokes every warrant and re-minted object over it on both nodes and tells
  the waiting callers `IdlError::NoConnection`, which is not `PeerDied`. Delivery
  is the op's attribute: `#[idempotent]` is resent, `#[at_most_once]` is resent
  with the same call number and answered from a per-session window on the far
  node, `#[once_only]` is sent once and a lost answer is `NoConnection`; an op
  that declares none crosses no link. A real-time caller is refused on a proxy
  endpoint (`-ERTPROXY` at the call, `neverallow` rule
  `proxy-endpoint-not-realtime` at admission). The lower node id dials; the
  link is one UDP datagram per frame (`RPC_PEER_ADDR`, `RPC_UDP_PORT`); the
  handshake is the `azos_rpc::Handshake` interface and proves nothing yet
  (Noise/DICE come later), so the link is for nodes that trust their network:
  datagrams from any address but `RPC_PEER_ADDR:RPC_UDP_PORT` are dropped, and
  with a peer configured the server refuses to start unless Kconfig
  `RPC_ALLOW_CLAIMED_PEER` is on. A fragment that would end past the largest
  message (17 KiB) is dropped at the frame check.
  Limits of this step: one peer link per server, one outstanding call, a
  request served for a peer holds the engine until the real service answers
  or `rto * (retries + 1)` passes (the call carries that deadline whatever the
  caller sent).

## System calls and per-image filters

### The native table and `invoke`

The kernel has thirty-four native system calls (`crates/core/abi/src/syscall_nr.rs`),
dense from 1, in families:

| Family | Calls |
|---|---|
| handles | `SYS_CAP_INFO` (find, query), `SYS_CAP_CLOSE`, `SYS_CAP_DERIVE` (badge, narrower rights, expiry), `SYS_CAP_REVOKE` (everything derived from a handle) |
| domain | `SYS_SPAWN_EX`, `SYS_THREAD_CREATE`, `SYS_THREAD_EXIT`, `SYS_EXIT`, `SYS_ALERT`, `SYS_GETPID` |
| time and scheduling | `SYS_YIELD`, `SYS_SLEEP_UNTIL` (absolute, or relative with a flag), `SYS_SCHEDCTL` |
| memory | `SYS_MO_CREATE`, `SYS_MO_MAP`, `SYS_MO_UNMAP` (a region is a handle, anonymous memory is handle 0) |
| IPC | the register-form fast call, reply, accept and reply-and-accept; the descriptor-form call, accept, reply and reply-delegate; `SYS_RING_SETUP`, `SYS_RING_ENTER`, `SYS_PORT_WAIT` |
| futex | `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE` |
| foreign ABI | `SYS_FOREIGN_ENTRY`, `SYS_FOREIGN_RESUME`, `SYS_FOREIGN_FORK` |
| generic | `SYS_INVOKE`, `SYS_SERVICE_DISCOVER` |

Everything else is an **op** of `SYS_INVOKE(handle, op, words)`: an operation
on an object the caller holds a handle to, selected by the handle's type and a
16-bit op number (`crates/core/abi/src/invoke.rs`). An op is `kind << 12 |
class << 8 | index`; the kernel refuses an op that does not belong to the
handle's kind. There are two forms: the *register form* (the `INVOKE_REGS` flag
of the op word) takes up to four words in the next four registers and replies
in up to four, and the *descriptor form* takes a `MsgDesc`. The handles an op
can name are the ones the caller holds (a file, a pipe end or a socket is a
`Node`; the console and the tracer are `Log`; a port, a memory object) and its
own domain, a handle every task has and the table never stores
(`DOMAIN_SELF`): the namespace (`open`, `stat`, `readdir`, `mkdir`, `unlink`,
`rename`, `truncate`), the network (`socket`), the process (`wait`, `brk`, the
service names, the filter, the subreaper mark), driver slots, modules, the
notify words and the driver server loop are ops of it. An interrupt line is an
op of its own `Device` handle (`DEVICE_IRQ_BIND`, `DEVICE_IRQ_ACK`). The
console is a `Log` capability every task is seeded with at admission, so even
a console write is a handle and an op, not a call.

Filters grade at the op *class*. A class is the unit an image profile grants
(`ImageProfile::ops`, a per-kind mask of 16 classes in `SyscallFilter::ops`):
`READ`, `WRITE`, `WAIT`, `CTL` and `ADMIN` for every kind, and for the domain
`FS_OPEN`, `FS_MUTATE`, `MODULE`, `NET` and `DRIVER`. An
unlisted class kills the task (audit mode records it), exactly as an unlisted
call number does; `tests/host/seccomp-tests` derives the classes a program's
`libsys` wrappers use from its source and holds each row to them. There is no
role profile for the network any more: a program that may use sockets lists
the `NET` class of the domain and the node.

`SYS_SPAWN_EX`, which needs a launch capability for the image, is the only
native process creation call: there is no native `fork`, `exec`, `execpath` or
path-named `spawn`. Copying an address space belongs to the foreign-ABI family:
`SYS_FOREIGN_FORK` is refused unless the caller registered a foreign entry, and
only an image whose profile lists it can ask (a Linux image, whose `clone` the
personality or the ring-3 runtime answers with it, and two test images whose
peers are copies of them, which register an entry they never enter).
`execve` is the Linux personality's own, kernel-side, and replaces an image
only with one the digest table binds.

`ABI_VERSION` (2) has three readers: `libsys` embeds an ELF note
(`.note.azos.abi`) that the loader checks and refuses on a mismatch, the kernel
publishes the version in the vDSO (`VDSO_ABI_VERSION_OFFSET`), and
`libsys::abi_matches` compares the two at run time.

Every ring-3 program the kernel starts runs under a system-call filter chosen
by the SHA-256 of its ELF:

- **Spawn.** The kernel hashes the image and looks the digest up in the
  compiled-in table. If the digest is unknown it refuses to start the image.
  If it is known, the kernel installs that image's filter and seeds the task
  from that image's topology row. When autorun refuses an image, it writes a
  durable safety record.
- **Filter lifetime.** A task cannot remove its filter, and only a Linux
  `execve` changes it. Enabling a filter is one-way, and a second install is
  refused. A fork copies the parent's filter.
- **Exec.** The Linux `execve` re-hashes the new image and refuses an unknown
  digest. It installs the new image's own filter and row in place of the
  caller's, so the filter belongs to the running image, whether that is
  narrower or wider than the caller's, and the caller needs a launch grant for
  an image of another row. An image whose row says `abi = "linux"` can be
  started only by spawn or by a Linux `execve`.
- **Verified-digest cache.** Hashing an image on every spawn is avoided by a
  small cache of verified digests. Entries are keyed by the file's identity on
  the FAT32 volume (start cluster, size and the volume's write epoch), never
  by path. Any write to the volume invalidates them. Files on tmpfs are never
  cached. The same cache can keep a program's text frames for reuse.

### Foreign ABIs: trap reflect and a ring-3 runtime

The kernel has one system-call ABI. Another operating system's ABI (today
Linux's) is hosted by a **ring-3 runtime in the process's own address space**,
and the kernel carries only a generic mechanism to reach it
(`crates/core/abi/src/foreign.rs`, `crates/core/sched/src/foreign.rs`). Three
native calls make the family: `SYS_FOREIGN_ENTRY` registers the
runtime's trap entry, `SYS_FOREIGN_RESUME` hands the thread back to
the foreign program with a register frame, and `SYS_FOREIGN_FORK` copies the
process for the foreign program's `fork`.

- **Two modes, one bit per thread.** A thread that registered an entry is in
  *runtime* mode (its traps are native calls, filtered by the image profile)
  or in *foreign* mode (its next trap is reflected). The mode is the per-CPU
  syscall filter word the native path already loads: a foreign-mode thread
  publishes 0, the existing out-of-line branch. A native thread's system call
  executes no instruction for the existence of this family.
- **Reflect.** The trapping thread's registers are pushed as a `ForeignFrame`
  on its own user stack (below the red zone, 16-byte aligned); the thread
  returns to the registered entry in runtime mode with the frame's address in
  its first argument register and as the stack pointer. The runtime therefore
  runs one frame deep on the foreign program's stack, per thread, with no
  runtime stack to manage.
- **Resume.** The runtime stores the result in the frame and calls
  `SYS_FOREIGN_RESUME(frame)`: every register is restored (the flag word only
  in `FLAGS_USER_MASK`), the thread is back in foreign mode and continues at
  the frame's program counter. Floating-point and vector state and the
  thread pointer are not in the frame: they stay the foreign program's, and
  the runtime is built without floating point.
- **Hosting.** With Kconfig `LINUX_RUNTIME`, `spawn` maps the runtime
  (`userspace/lib/linux_rt` behind `userspace/services/lxrt`, linked at
  `VDSO_USER_BASE + 0x10000`, embedded in the kernel image so its signature
  covers it) into every Linux row's address space and starts the process at
  the runtime. The runtime registers its entry and resumes the program at its
  `AT_ENTRY` with the Linux initial stack the kernel laid out. A
  `SYS_SPAWN_EX` request reaches it as it reaches a native child: the kernel
  writes the startup block (descriptors 0..7 and the working directory, the
  handles already moved into the child's capability table) above the Linux
  stack, passes its address in the second argument register, and the runtime
  builds its descriptor table and working directory from it. A spawn without a
  request has no block: the console on 0..2 and `/`.
- **Authority.** None is added. The runtime's native calls meet the row's
  image profile and the task's capability tables as any native call does; a
  Linux program that jumps into the runtime has the image's authority and no
  more. Only the native filter is enforced: a filter over Linux numbers inside
  the runtime would be advisory.
- **State.** A Linux process's descriptors, working directory, umask and signal
  state live in the runtime, in the process's memory, and a fork copies them
  with it. The kernel keeps no Linux state for a hosted process.
- **Supported ISAs.** The kernel mechanism is on riscv64, aarch64 and x86_64
  (`abitest` runs a native foreign program on each, and the x86_64 row has its
  canary). The runtime exists where the personality does: riscv64 and aarch64,
  which share Linux's asm-generic call table. Linux's x86-64 ABI is a
  different table (call numbers, `struct stat`, `sigaction`, `clone` argument
  order) that nothing implements yet, in the kernel or in the runtime;
  hosting it on x86_64 is that table in `azos_linux_abi`, an entry stub and a
  linker script for `lxrt`, and a test program, with no change to the trap
  mechanism.
- **What the runtime answers.** Identity, descriptors (files, pipes,
  directories, the console), the working directory, umask, time, memory
  (`brk`, anonymous `mmap`), tty `ioctl`s, signal state, and processes in the
  fork shape (`clone` over `SYS_FOREIGN_FORK`, which hands the child the
  parent's open files and pipe ends at the same handles, sharing offsets;
  `wait4` over the domain's `wait` op). Everything else answers `-ENOSYS` and is
  reported once per call.
- **What it does not answer yet.** The calls that need a native primitive the
  ABI does not have: seek (a `Cap<File>` has none),
  `mprotect`, signal delivery and `kill` (no upcall into the process),
  threads (`clone` with `CLONE_THREAD`), `execve` (the native exec refuses a
  Linux image), requeue and
  priority-inheritance futexes, and console input. The in-kernel personality
  (`LINUX_RUNTIME` off) answers them and stays until the runtime does. The
  runtime's `fork` is not built on a native memory-clone and a blank domain
  yet: it sits on `SYS_FOREIGN_FORK`, which a native program cannot use.

## Drivers

**Interrupts as scheduled objects (Kconfig `IRQ_THREADED`).** A line is bound to
an event port by an op of its `Device` capability: the line is routed to one CPU
and every interrupt queues a `PORT_EVENT_IRQ` event on the port. The top half
is the external-interrupt handler masking the line, completing it, and
`irq_bind::irq_dispatch` queueing the event; the line stays masked until the
handler's `DEVICE_IRQ_ACK`. With `IRQ_THREADED` the handler (the task that
bound the line) must run on a hard reservation (EDF + CBS), so it is admitted
like any other time, and the line is routed to the CPU the reservation runs on.
When the reservation runs out of budget the scheduler tells `irq_bind`
(`irq_sc_throttle`): idle lines are masked and held, a line already in service
stays masked past its ACK, and the replenishment unmasks them, with one
`irq-budget` decision record per overrun. A message-signalled slot (`msi.<k>`)
takes its vector at bind and gives it back with the binding; an MSI cannot be
masked, so its deliveries are dropped while the handler is out of budget. The
kernel's own lines (the console UART, the virtio devices) keep a top half that
only masks, completes and queues, and run their handlers in one kernel thread
(`kernel/src/irq_thread.rs`) bound to the same table on a reservation of its
own; the timer keeps its top half and hands the lease sweep to that thread. What
is not charged: the top half's own time. Mask-until-ACK bounds its rate to the
handler's ACK rate, which the budget bounds.

**Classes.** Drivers are grouped by class under `crates/drivers/<class>`:
`irqchip`, `sys` (console, timers, watchdog), `virtio`, `block`, `net`, `bus`
(I2C, SPI, CAN, USB, UART bridge), `gpio`, `sensor`, `actuator`, `power`,
`display`, `camera`, `pci`, `dma`, `iommu` and others. `crates/drivers/api`
defines the `Driver` trait and the class traits for block, console, network
and USB devices. `crates/drivers/base` holds the board description and the
in-kernel driver registry.

**The hardware bus.** Devices are found, not listed. `crates/drivers/hwbus`
(logic, host-tested) and `azos_drv_bus::hwbus` (the static instance) hold one
table of device objects; `kernel/src/boot/hwbus.rs` fills it from the device
tree's nodes that carry a `compatible` and a `reg` (riscv64, aarch64), the
populated virtio-mmio windows, and the PCI/PCIe functions behind the ECAM
window or the legacy port pair (bus 0 and every bus behind a bridge the
firmware numbered). Each device has a handle (slot and generation); a `Device`
capability (`ty::MMIO`) names a handle, never an address, and
`DOMAIN_MMIO_MAP` maps that device's window, writable only if the capability
carries WRITE. A topology grants one by what the device is
(`mmio.dt:google,goldfish-rtc`, `mmio.pci:1af4:1041`, `mmio.virtio:2#1`), and a
program finds its handle in `/proc/devices`. A device a kernel driver owns has
no mappable window.

Drivers are matched, not called. Each native driver crate declares its ids in
an `hwbus.ids` file; the Linux leaf drivers' ids come from their
`MODULE_DEVICE_TABLE` (`lx/DEVICE_SOURCES`, `tools/lx_device_table.py`). The
two tables are generated at build time and the build refuses an id in both.
A device is bound to the first native entry that names it, else the first
Linux entry (a ring-3 class server, launched by a topology row marked
`lx_class` only once one of its ids matched an admitted device), and a
`[device.NAME]` row of the topology may name another native driver or refuse
the device. A driver none of whose ids matched starts nothing, and the
drivers no longer scan for their hardware: they are asked about the device the
bus found. Entries marked `boot` (the console, the interrupt controllers and
timers, the PCI host bridge, the firmware framebuffer) are hardware the
kernel drives outside the bus; they are bound whatever the policy says.

Kconfig `HWBUS_AUTOBIND` is the policy. Auto (desktop, server, IoT/HMI,
gateway, generic) binds what the tables match. Topology-only (robot,
industrial, automotive, firmware, wearable) detects everything and binds only
what the signed topology admits; a device a table names and no row admits is
the decision "detected, not admitted" (`/proc/decisions`, rule
`device-admission`). The disk the signed topology is read from is bound before
any topology can be read, so the built-in topology carries the rows that
admit its image's devices (`BUILTIN_DEVICE_ROWS`); after the topology is
installed the bus runs the decision again under its rows (`reconcile`):
`unbind` and `rebind` release a device from a driver that can let go.
Ring 3 may map a device's registers only once its life has settled with no
kernel driver in it (not `Detected`, not `ProbeFailed`, not natively bound);
a mapping is booked with the bus, and a device a task has mapped is never
given to a kernel driver afterwards, because a mapping cannot be taken back.

**Placement.** A driver whose chip logic is written separately from its host
can run in the kernel or in a ring-3 process. Today that is the INA219 power
monitor and the buzzer. The INA219's placement is chosen per build in Kconfig
(`DRV_INA219_PLACEMENT`). The buzzer's is an attribute of its topology row
(`place = "kernel" | "ring3"`, CAPS.TOML format 6), and Kconfig
`DRV_BUZZER_PLACEMENT` only picks it for the built-in topology. A ring-3
driver:

- registers with the in-kernel driver server through a driver-registry
  capability, or serves its interface on an endpoint its row grants,
- reaches its hardware through typed bus capabilities,
- cannot allocate DMA memory, which stays kernel-only.

The kernel calls the INA219 through a proxy that implements the same `Driver`
trait. It calls the buzzer through the generated stub of its interface
(`Buzzer`, `crates/core/devif`): the direct-call stub while the driver is in
the kernel, the endpoint-call stub, over the kernel's own transport
(`azos_syscall::kcall`), while it is in ring 3; `BuzzerPlaced` is the value
that is either. The kernel's call is the body of `SYS_IPC_CALL_V2`. It refuses,
with `-EBUSY` and without queueing anything, where the caller may not block
(a spinlock held, such as the closure of `cap_store::with_table`, or interrupts
masked).

**Elastic placement.** A row marked `stateless = true` (CAPS.TOML format 6)
holds nothing a restart cannot rebuild, so its driver can change host while the
system runs, with no state transfer (`azos_topology::placement::Elastic`):

- **Demote on fault.** A panic in the kernel host is contained and ends its
  task. The supervisor starts the ring-3 program from the row, behind the
  same endpoint.
- **Promote on deadline.** The kernel times every call to the driver. When
  `PLACEMENT_PROMOTE_MISSES` of the last 16 calls break the row's
  `call_budget_us`, the driver moves into the kernel, if the kernel host's
  cost, measured at boot on the real controller, fits the budget and the
  kernel host has not faulted within `PLACEMENT_HOLDOFF_S`.

Every move, and every refused move, is a `Rule::Placement` decision record
(`why`, `/proc/decisions`) written by the one function that changes the host.
A move is a durable receipt, as a refusal is, and a refusal names the cost the
budget would have had to cover.

**Kernel-only drivers.** A driver that a safety decision reads has no
placement choice. This covers the interrupt controllers, watchdog, PWM, GPIO,
motor and ESC, RC receiver, I2C with the IMU, rangefinder, the battery ADC,
UART and the boot block devices. The build tool refuses a configuration that
places one of them in ring 3.

**Queued I2C transactions.** A caller that may not wait for the bus, such as
the real-time IMU task, queues a transaction per bus and collects the result
on a later tick. The result is stamped when its last byte arrives
(`I2C_TXN_QUEUE_DEPTH`, `IMU_SAMPLE_QUEUED`). On the DesignWare controller, a
service step moves the FIFOs: it reads what has arrived and refills the
commands, bounded by the FIFO depth. A task runs the step until the
controller's interrupt line is wired. A NACK or a timeout ends the
transaction as failed. A synchronous caller queues its transfer the same
way, on its own buffers. It sleeps between the steps of its transfer and
holds the bus lock only within a step. The typed I2C system calls check the
capability under the table lock and transfer after releasing it. The QEMU
simulation completes a transaction at submit. The DesignWare path has not
run on hardware.

In the current tree, ring-3 driver rows are started only in QEMU builds,
whose disks carry the driver images.

**Supervisor.** A kernel supervisor task restarts a ring-3 driver that fails.
The restart re-reads the image, re-checks its digest and re-grants the
capabilities from its row, while the driver's slot and endpoints stay held.

- **Limit.** At most `SUP_RESTART_BURST` restarts within
  `SUP_RESTART_INTERVAL_S`. After that the driver kind stays down until
  reboot, and the give-up is recorded.
- **Per-row override.** A topology row can override the policy with
  `restart = always` or `restart = no`.

## Storage and network

**File systems.** The VFS (`crates/fs/fs`) has a `FileSystem` trait and a
fixed mount table. There are three implementations:

- **FAT32**, the persistent volume.
- **tmpfs**, mounted on request.
- **procfs**, which also serves a sysfs view.

**FAT32 details:**

- **Block cache.** FAT32 reads and writes through a shared block cache,
  sized per profile. With `FS_WRITEBACK` (the default) it is write-back: a
  write dirties a cache line and returns. Each journal barrier closes an
  epoch without I/O. Dirty lines reach the device oldest epoch first, with a
  device flush between epochs; consecutive dirty sectors of one epoch go out
  as one multi-sector request. Re-writing a line of an older, unwritten
  epoch keeps the old contents as a shadow line until it is written. A power
  cut therefore leaves a prefix of epochs plus part of one, the states the
  write-through journal allowed. `fsync`, `sync` and the durable records
  (e-stop and safety records, OTA marks, the crash log) return only after
  their writes are flushed; a close does no I/O. A device that cannot
  flush mounts write-through. The
  `fs-wb` task writes the rest back by age (`FS_WRITEBACK_MAX_AGE_MS`: 1 s in
  the robot domain, 5 s otherwise) and by dirty-line watermark. A writer
  never evicts a dirty line under the cache lock; it writes back with the
  lock released and retries. Another reader of the medium makes FAT32 write
  back first; another writer drops only the sectors it wrote.
- **Writes in place.** A writable open reads and writes the file in place
  through the block cache, as on Linux: no whole-file load on open, no
  rewrite on close. Under write-back the directory entry (size, first
  cluster) is written ahead, into the epoch after the current one, with no
  barrier: consecutive writes of a file share one epoch for their data and
  chain, and the entry is one cache line rewritten in place that reaches
  the device once, after them, at the write-back or the `fsync` that
  closes both epochs. Readers find the entry through the cache, so they see
  the new size at once; a plain write to a line held ahead joins its epoch.
  A cut leaves the old entry or one naming a whole prefix. The chain is
  extended before the entry naming the new size, so a cut after a
  write-back wrote the entry and before the next one wrote it again can
  leave the old size over a longer chain. That tail ends in end-of-chain:
  a new cluster's end-of-chain mark reaches the medium before the link to
  it (an epoch boundary where the two are in different FAT sectors: once
  per FAT sector the chain crosses, every 128 clusters for a contiguous
  chain). Reads stop at the size; the file's next write past it
  reuses the tail, and a truncate or unlink frees it. Until then it is
  leaked space, as Linux's FAT driver leaves it and fsck.fat trims it.
  Write-through orders each entry with a flush. `O_TRUNC` to zero clears the entry (also
  written ahead) and holds the old chain.
  A write is not atomic. Atomic replace is a temp file, `fsync`, then
  `rename` over the live name: over an existing file `rename` is one
  journal record (a cut leaves the old file with the source still named,
  or the new one with the source gone), to a new name an in-place rewrite
  of the 8.3 name in one sector.
- **Deferred frees.** With `FS_DEFERRED_FREE` (write-back), a chain that
  an `O_TRUNC` to zero, an overwrite or a rename over a file takes away
  from its name stays allocated in the FAT until the flush that makes the
  write unlinking it durable (for a journaled replacement, the record's
  clear). That flush frees it into the next epoch, which the next flush
  carries. No allocation can hand a held chain out, so the new data and
  chain of an in-place rewrite share the cleared entry's epoch: its
  `fsync` is two device flushes, and a cut leaves the old file, an empty
  one or the new one, whole. A cut before the free reaches the medium
  leaks the chain. `statfs` counts held chains as free; an allocation
  that finds the volume full while chains are held flushes once, frees
  them and retries. A hold that finds every slot taken
  (`FS_DEFERRED_FREE_SLOTS`) closes the epochs and frees every held chain
  into the next one, which the write-back writes after a flush. A mount, an
  unmount or another writer of the medium forgets the held chains (they
  leak). Write-through frees one epoch
  after the entry.
- **Journal.** A one-sector journal is replayed at mount.
- **Locks across device I/O.** No lock held across a device request turns
  preemption off. The FAT holds no mutex across device I/O: a FAT entry
  update claims its FAT sector in a bitmap, and a second updater of the same
  sector sleeps on a wait queue until the first publishes. While it sleeps
  it lends its priority to the claim's owner (the scheduler's counted
  donation with its ring-3 floor; with `WAIT_GRAPH` the waiter also takes a
  wait-graph edge, which does not boost a Fair waiter), and the owner gives
  it back after waking its waiters. The write-back
  claim does the same, so `log-flush` (12) waiting in an fsync on `fs-wb`
  (20) is not starved by load between the two. Real-time tasks do no block
  I/O and never take a claim, so no real-time waiter inherits disk latency. The allocator
  scans without a claim and confirms its candidate on the claimed sector. The
  VirtIO block driver submits a request under its lock and waits for the
  completion without it. Each request in flight owns a staging slot
  (`VIRTIO_BLK_INFLIGHT`, up to five, `VIRTIO_BLK_SLOT_KB` each), and a
  request that finds every slot taken sleeps without priority inheritance.
  A write larger than one slot is submitted on every free slot before its
  first wait. Completions arrive by interrupt on every ISA (riscv64 PLIC or
  APLIC, aarch64 GIC SPI, x86_64 IOAPIC): a waiting task sleeps until the
  line's handler wakes it, bounded by the request's deadline; before the
  scheduler runs, or with interrupts or preemption off, it polls. The cache lock is released
  before a request goes to the device. A real-time task on the writer's CPU
  keeps its period while FAT32 writes.
- **No priority-inheritance mutex across a device wait, for any task.** What
  must exclude across one is the ownership of a resource, not a lock: a claim
  (`azos_sync::claim::Claim`) keeps it as data under a kernel mutex held only
  for the instant of taking or giving it, and a contender sleeps on the
  claim's wait queue with nothing held and boosts nobody (nothing to
  inherit: real-time tasks do no block I/O). The exec and spawn image buffer
  and the flight recorder's flush are claims. The raw disk calls share
  nothing: each takes a bounce buffer of its own from the heap (a failed
  allocation fails the call, `ENOMEM`). Lockdep reports a `Mutex` held across
  a device wait (`might_wait_device`; the canary `claim-mutex-held` keeps the
  claim's mutex for the owner's whole tenure to prove it).
  The machine-wide descriptor table keeps priority inheritance
  (real-time tasks use it for in-memory and device files) and is never held
  across device I/O. An open runs on a private table and the descriptor
  then moves into the shared one. A read or write of a streaming file runs
  on a lent copy of the descriptor that keeps the file alive, under the open
  file description's position claim (as Linux's `f_pos_lock`, but a claim:
  nothing is held across the device wait), so two threads sharing a
  description never transfer at the same offset. Its offset is published
  under the table lock afterwards. In-memory files keep the table lock. A
  close flushes a dirty file outside the lock once its last descriptor is
  gone, and `fsync` writes a copy of the bytes. The
  panic path counts the claims a task owns the same way it counts held
  mutexes.
- **Real-time tasks do no block I/O.** A task whose own priority is in the
  real-time band never enters the block layer. With `RT_BLOCK_IO_CHECK`
  (on in the development configs) the block layer panics, naming the task,
  if one does. The only exception is the crash-log write of a task that is
  already panicking.
- **Real-time tasks only append to the console.** A kernel log line from a
  real-time task is copied into the UART transmit ring, or into the
  console's deferred buffer when the ring is full or the UART has no
  transmit interrupt. A non-real-time context drains the buffer: the next
  kernel line from task context, the transmit interrupt, or the idle loop.
  The real-time task never takes the console over to drain other lines and
  never waits for room. When the buffer is full, whole lines are dropped and
  counted (`CONSOLE_RT_APPEND_ONLY`). With `RT_CONSOLE_WIRE_CHECK` (on in the
  development configs), a real-time task that reaches the wait for the wire
  panics, naming the task.
- **A task-context console line is never dropped.** A kernel line (up to
  256 bytes, `LINE_RESERVE`) from a non-real-time task that holds no spinlock and no sleeping lock waits for
  the console's line lock when another context owns the console and the
  deferred buffer is nearly full, then goes out after what was deferred.
  Only callers that may not sleep (interrupt handlers, spinlock holders,
  real-time tasks) drop whole lines into a full buffer, counted.
- **Write observer.** Writers that reach the medium without going through
  FAT32 call a write observer. These are the raw disk call and the USB
  mass-storage gadget. FAT32 registers the observer to drop the cache lines a
  write touched.

**Network.** The TCP/IP stack is the kernel's own (`crates/net/net`): Ethernet,
ARP, IPv4, UDP, TCP, DHCP, DNS, NTP and IGMP. IPv6 covers link-local addressing,
neighbour discovery, ICMPv6 echo and UDP; TCP over IPv6 is not connected to
sockets. Ring 3 uses BSD-style socket calls and capability-typed socket calls.
One receive pass runs at a time: the net-poll task drains the NIC, and a call
from another task that finds a pass in progress leaves the owner a request
instead of draining beside it, so frames reach the protocols in ring order.
TCP delays acknowledgements (RFC 1122): in-order data is acknowledged every
second full-sized segment, at the end of a receive pass, on our own data, or
after `TCP_DELACK_MS`. A connection is reached through a handle that carries
its slot's generation, so an operation through a handle whose slot was freed
and reissued does nothing. A connect that names no local port takes a free
one from the ephemeral range (`TCP_EPHEMERAL_PORT_MIN..MAX`), skipping ports
held by live or TIME-WAIT connections. A task waiting for a handshake, an incoming connection,
the send window, an ARP reply or a DNS answer blocks until the receive path
wakes it, with its timeout as the bound.

**VirtIO.** The VirtIO drivers cover block, network and entropy devices.
Block and network run over the MMIO transport (legacy and modern). A modern
PCI transport exists, but the kernel uses it only in self-tests. The network
driver pops received frames in batches under one lock and hands them to the
stack in place, without copying them out of its receive buffers. On modern
transports it negotiates `VIRTIO_F_EVENT_IDX`: doorbells and interrupts are
requested by ring index rather than by the notification flags.

## Safety and records

**Actuation authority.** Every domain links `crates/core/actuation`:

- **E-stop latch.** Once set, it stops actuation, and it is persisted in the
  flight recorder and restored at boot.
- **Release.** Only an operator release clears the latch. The release is
  signed with Ed25519 over a fixed context and a monotonic nonce, and the
  nonce floor survives reboots.
- **Motor gating.** Motor calls require a motor capability. A deployment
  without the actuation profile in its topology grants none.
- **Robot envelope.** The robot domain adds a per-robot-type safety envelope.
  It clamps every motor command before the duty-cycle write.
- **RC receiver and geofence.** Two robot-domain options (`RC_INPUT`,
  `GEOFENCE`; off compiles them out). Once an RC link exists, link loss
  and the kill switch latch the e-stop, and in manual mode the sticks
  drive below the e-stop layer and the obstacle stop, through the
  envelope. The geofence is armed at the first trusted GPS fix; a breach
  latches the e-stop. Each latch writes a safety record.
- **Dead commander.** When a ring-3 task that left a wheel turning exits
  or dies, its exit sets that wheel to duty 0 and writes a safety record.
  The e-stop is not latched, so a restarted commander can drive again
  (`MOTOR_COMMANDER_EXIT_STOP`).

**Watchdogs:**

- **System watchdog.** A kernel task checks stack canaries, timer liveness,
  the kill-switch input and driver health, and latches the e-stop on a trip.
- **Hardware watchdog.** On a board that has one, the timer interrupt feeds
  it. Once the robot control loop has started, it is fed only while that
  loop's heartbeat advances, so a hung loop resets the board.

**Flight recorder.** Safety events are written to `LOG/LOGNNNNN.BIN` on the
FAT32 volume.
Each boot opens a new file whose serial number continues from the highest one
on disk.
Records first go into a lock-free ring in RAM (`LOG_RING_ENTRIES`). A
producer claims a slot with one compare-and-swap and never waits for a lock.
When the ring is full, the new record evicts the oldest one, and every record
evicted is counted (a producer can lose the slot it freed to another producer
and evict again). The exception is a latching e-stop record that is not yet
durable: it is never evicted, and the new record is dropped and counted
instead. Records leave the ring only once the medium has taken them. The
recorder prints that a latching e-stop record is durable only after an fsync
that covers it has returned.
The `log-flush` task writes the ring to disk (`LOG_FLUSHER_PRIORITY`, outside
the real-time band). The flush lock is a sleeping lock without priority
inheritance, and no real-time task takes it.
A real-time task that asks for a flush, or for a durable record such as an
e-stop, does not wait for it. It wakes `log-flush` and returns. Its record is
on disk once `log-flush` has run one flush after the request. A durable record
from any other task is flushed and synced before the call returns.
The real-time system watchdog (`sys-wdt`, on every ISA) requests a flush every
500 ms and hands its OTA boot-good mark to `log-flush`. At boot the recorder is replayed to restore the e-stop latch and the
release nonce floor.

**Panic report.** On the reset path the panicking CPU stops the actuators,
then claims the console: any other CPU's UART write waits until the report
is out. It rings every other online CPU with the scheduler IPI, whose handler
parks the CPU once the panic flag is set, and waits up to
`PANIC_STOP_WAIT_US` for them (`PANIC_QUIESCE`). Queued console output goes
out first and the report starts on a fresh line, so no other CPU's output
can splice it; it names any CPU that did not park. A second CPU that panics
meanwhile parks instead of printing. The console is released once the report's
core lines are out, before the crash-log write. The `[FATAL]` halts (a kernel
page fault, an unhandled trap) take the same steps before they print, on
every ISA, and the console owner never waits for the UART lock.

**Crash log.** The panic handler first writes a record to a reserved RAM
area, then appends the report to `/fat/CRASH.LOG`. If the append fails, the
next boot copies the RAM record to the file. `CRASH.LOG` rotates to
`CRASH.OLD` at 64 KiB.

**Log levels.** `LOG_LEVEL` (err, warn, info, debug) is a build-time choice.
Console lines below the level are compiled out. The flight recorder and the
panic report are not affected by it.

## Tracing

**Kernel event tracer** (`KTRACE`). One single-producer/single-consumer ring
per CPU, all in one kernel-owned shared-memory region
(`crates/core/spsc/src/trace.rs` is the layout both sides compile;
`crates/core/trace` is the kernel side):

- **Records.** 32 bytes: a timestamp, the index the record was written at, an
  event id, the CPU and four arguments. The timestamp is the clock vDSO's
  timebase by default (the rate is in the region header), or the CPU cycle
  counter.
- **Classes.** Scheduler (switch, wakeup), interrupts (entry, exit), syscalls
  (entry, exit, seccomp denial), fast IPC (call, reply), page faults, process
  life cycle (spawn, exit, signal) and the `LAT_TRACE` maxima. Each class is
  compiled in or out by its own Kconfig symbol and masked at run time.
- **Record path.** Each CPU is the only producer of its ring, so masking that
  CPU's interrupts around the record is its whole mutual exclusion. A record
  takes no lock and no atomic read-modify-write, and divides nothing. It
  writes only its own cache line and publishes itself with a release store
  of its index. The consumer's tail is read only when the producer's cached
  copy says the ring is full. There is no doorbell: the reader polls.
- **Full ring.** By default the newest record is dropped and counted in the
  ring's drop word. `KTRACE_POLICY_OVERWRITE` keeps the newest instead: the
  reader re-checks each record after copying it and counts the ones
  overwritten under it as lost.
- **Reader.** `tracectl` (`TRACECTL.ELF`) holds `Cap<Trace>`, which only its
  topology row grants. With it, the tracer's ops (`LOG_TRACE_MAP`, `LOG_TRACE_INFO`,
  `LOG_TRACE_SET_MASK`) map the region and read or set the class mask; a call without it is refused and recorded.
  The tool streams decoded records to the console or a file, and the shell
  starts it like any other tool. The panic path prints each CPU's last
  records from the kernel's own view of its ring.

**Static keys** (`KTRACE_STATIC_KEYS`). Every tracepoint check is one
naturally aligned 32-bit instruction, recorded with its class in a table the
linker collects (`.azos_keys`). It is linked as a branch to the class's mask
test, and at boot the sites of masked-off classes are rewritten to nops
through `text_poke`. A mask change rewrites the changed classes' sites, mask
first and text after, so a site in either state is correct at any instant.
The rewrite runs while the other CPUs keep executing. On aarch64, NOP and B
are in the architecture's list of instructions that may be modified while
another PE executes them. On riscv64 a site is never compressed or relaxed,
so a hart fetches the old word or the new one, never a mix; Linux's riscv
jump labels rely on the same property. A kernel that cannot set up the
alias keeps every site a branch: the mask test, correct and slower.

**Cost**, in instructions under QEMU `-icount`, both ISAs. Compiled out:
none, every tracepoint folds away, and every vsbench lane is unchanged.
Compiled in, class masked off: one nop per tracepoint with static keys.
riscv64 adds a 2-byte padding `c.nop` before a site that would otherwise
start 2 bytes off a 4-byte boundary. Without static keys it is 4 (the
mask's address, a load, an `and`, a branch). Recording: 48 per event on both
ISAs with static keys (the branch, the mask test, the call), 47 on riscv64
and 44 on aarch64 without; a full ring costs 46 and 42. The boot probe
`trace-cost-probe` measures these. On the riscv64 syscall path (two
sites, both padded) `syscall-floor` is 195 compiled out, 199 with static
keys and 203 with the mask test.

## In-kernel tests

`crates/core/ktest` is a test registry in the style of Linux's KUnit. The
`ktest!` macro defines a test, `fn() -> Result<(), &'static str>`, next to
the code it checks, and places a 32-byte `{name, fn, phase}` entry in the
`.azos_ktest` link section. Every kernel linker script brackets that section
right after the static-key table in `.rodata`, so the registry is a slice
over read-only data, with no constructor, allocation or fixed-size table.
With Kconfig `KTEST` off (the default in every mode) the crate is not a
dependency of the kernel and every test sits in a module compiled only with
the `ktest` feature: the section is empty and the kernel has the same size,
function for function. With it on, `kernel_main` calls the runner
(`kernel/src/ktest.rs`) after boot init, before the secondary harts wake and
before any task runs. The runner executes the tests in name order, printing
each name before its test, then TAP (`1..N`, `ok i - name`,
`not ok i - name # reason`). Tests defined with `ktest_late!` form a second
phase, like KUnit's late-init tests: boot continues, and once the scheduler
runs on every CPU a `ktest-late` kernel task (Kconfig `KTEST_LATE_PRIORITY`)
runs them in name order. A late test starts its scenario's tasks (pinned
probes, priority donation, cross-CPU TLB shootdown) and waits for them on the
clock, at most `KTEST_LATE_TIMEOUT_MS`. Both phases share one TAP plan: the
early tests are numbered first, the late ones continue the count. After the
last test the runner prints a summary, flushes the console and powers the
machine off with the verdict in QEMU's exit status on every ISA: the
`sifive_test` finisher on riscv64 (written once, then the CPU halts, since
OpenSBI's own shutdown would overwrite the code), semihosting `SYS_EXIT` on
aarch64 (Kconfig `KTEST_SEMIHOSTING_EXIT`; PSCI's power-off has no status)
and `isa-debug-exit` on x86_64. The gate's ktest rows require the status and
the TAP summary to agree. The kernel does not unwind, so a panicking test cannot be resumed: the
panic handler prints that test's `not ok` and a `Bail out!` line, and the
tests after it do not run. Tests that need a boot-time value, such as the
image layout only the ISA boot hook knows, read it from a note that hook
records when `KTEST` is on. The gate boots one test kernel per ISA, requires
the plan to match the expected count and every result to be `ok`, and boots
the same kernel built with the tests' canaries to require exactly those
tests' `not ok`.

**Fault injection.** With Kconfig `CHAOS` (development only, never with
secure boot) `crates/core/chaos` adds named injection points: frame
allocation, heap allocation, channel send, timer wake (the sweep wakes
sleepers late), spurious interrupts (an IPI with no cause) and block I/O.
Each fails the way the real fault does. A point is armed from a test, or for
one boot from the command line (`chaos=<point>:<rate>`, `chaos_seed=<n>`),
which takes effect once boot init is done; a fixed seed fails the same calls.
The `chaos_*` ktests check that each fault is refused cleanly, leaves no
frame or heap byte behind, and is counted; `/proc/chaos` shows the counts.
The kernel's heap allocations are infallible, so the heap point is armed only
from a test. Off, every point is a constant `false`.

**Spin-wait and CAS.** Every kernel spinner reaches the CPU's wait hints and
compare-and-swap through one trait, `SpinWait` (`crates/core/arch-api/src/spin.rs`):
`cpu_relax`, `wait_while32/64` (wait until a word changes), `cas32/64`
(strong CAS with an explicit ordering, never SeqCst), `swap32/64`,
`tas_acquire32` (test-and-set acquire of a 0/1 word), `qlock_acquire32` (the
queued lock's fetch-or fast path) and `unlock_low_byte32` (a release store
of a word's low byte). The trait's provided
bodies are the fallback every ISA has: the compiler's LR/SC loop on riscv64,
LDAXR/STLXR at Armv8.0 and LOCK CMPXCHG on x86_64, and a relax loop. Each ISA
overrides what an extension does better, behind its n / probe / require
choice: Zacas `amocas.w/.d` and Zawrs `lr` + `wrs.nto` on riscv64, LSE
`CASA`/`CASAL` on aarch64 (and `SEVL`; `WFE`; `LDAXR`; `WFE` as the wait on
every core), UMONITOR/UMWAIT on x86_64 (WAITPKG, with a TSC deadline per wait
step). `wait_while` polls `SPIN_WAIT_RELAX_SPINS` times before it takes the
hint. `n` and `require` compile the choice in. `probe` on riscv64 and
aarch64 works like Linux's ALTERNATIVE: each use is a 4-byte site recorded in
`.azos_keys`, linked as its safe form (a branch to an LR/SC or LL/SC loop
placed after the function, or a nop) and rewritten once by
`kernel/src/boot/spin_patch.rs`, on the boot CPU before the secondaries start
and through the W^X-preserving text write, to the instruction the assembler
encoded for that site (`amocas`, `casa`, `swpa`, `ldseta`, `wrs.nto`, `pause`). After
boot a probe site costs what `require` costs. On riscv64 the device tree's
claim is first executed once under a private trap vector, so a false claim
leaves the sites linked rather than trapping in a lock. The boot prints
`[SPIN] cas: ...; wait: ...` and `[SPIN] boot patch: ...`. x86_64's WAITPKG,
used only while waiting, tests a boot-set flag.
`SpinLock` has two implementations behind one API, chosen by Kconfig
`SPINLOCK_IMPL`, both on one 32-bit word with no sub-word atomic (riscv64 has
none without Zabha). `mcs` (the default on edge and fleet with at least 4
CPUs and on embedded with at least 2) is Linux's qspinlock
(`crates/core/sync/src/qspinlock.rs`): the word holds a locked byte, a
pending bit and the queue tail (CPU and node index). The uncontended acquire
is one fetch-or of the locked bit and a branch (`qlock_acquire32`:
`amoor.w.aq`, LSE `LDSETA` or LL/SC; a CMPXCHG on x86_64), the release a
release store of the low byte (`unlock_low_byte32`). One contender waits on
the pending bit; the others queue, each spinning on its own CPU's node (four
per CPU, one per nesting level: task, deferred work, interrupt, NMI-like),
and are served in arrival order; the tail changes only by full-word CAS
loops. A waiter frees its node when it takes the lock, so a held lock owns
no node. A fetch-or that lands on a free word with a waiter on it gives the
lock back at once and queues, so arrival order holds. `ttas` is a
test-and-test-and-set lock through `tas_acquire32`: an inline exchange
(`amoswap.w.aq`, `SWPA` or LDAXR/STXR, `XCHG`) and a branch. In both, the
waiting runs out of line behind a trampoline that saves every caller-saved
register, so a lock site pays no call clobbers.

**Lock classes.** Every kernel lock is either a bounded spin lock (a
`SpinLock`, whose critical section is short and bounded: fixed-size data,
no I/O, no sleep) or a sleeping lock (`Mutex`, the wait-graph kernel mutex; or a
claim: ownership of a resource across a device wait, `azos_sync::claim`, or a
WaitQueue-based one in the FAT32 and block layers). Most of the 170 locks are bounded spin locks (140).
These are the sleeping locks and the spin locks that do long or unbounded
work under the lock and are to become sleeping locks:

| Subsystem | Sleeping locks | SpinLocks to convert (work under the lock) |
|---|---|---|
| syscall | `EXEC_BOUNCE` (Claim); `CAM_BUF` (Mutex) | `FRAME_BUF` (user copies that can fault) |
| shell, actuation | `SPAWN_PATH` (Mutex); `LOG_FILE` (Claim) | |
| fs | `DESC_POS` (Claim); FAT32 sector and write-back claims (WaitQueue) | `TMPFS` (allocation and copies up to TMPFS_MAX_KB) |
| block, virtio | `BLK_LOCK` (Mutex); SD/eMMC `MMC_QUEUES` (a Mutex for programming the controller, a FIFO ticket queue on a WaitQueue for the request; device waits run with no lock held); virtio-blk slot claims (WaitQueue) | virtio-rng `RNG` (polls the device) |
| drivers | `JPEG_RAW`, `CONSOLE_LINE_LOCK` (Mutex); ADS1115 queue (WaitQueue) | DMA `DMA` (sim memcpy of a caller-chosen length) |
| ipc, mm | | trace `KEYS` and `text_poke::LOCK` (text rewrites, remote fence and TLB shootdown with interrupts off) |
| net, ota | | `TCP` (copy loops up to TCP_RECV_MAX_PER_CALL, one lock for every connection); `META_RMW` (boot-metadata storage I/O) |
| kernel | `KERNEL_FD_TABLE` (Mutex); loader claim | `LOG_SLOT` (FAT32 close, an fsync); `BRAIN_TXQ` (TCP send) |
| robot | `PATH3D` (Mutex) | `SLAM` (ray traces over up to 360 beams) |

Every other lock is a bounded spin lock: the scheduler's per-CPU queues,
wait-queue internals, IPC endpoints (one call-queue lock per
endpoint, interrupt-safe), the page allocator and
heap, the capability store, driver register state and the protocol tables.

**Lock dependency checking.** With Kconfig `LOCKDEP` set to `ktest` (the
development default) or `y`, `crates/core/sync/src/lockdep.rs` checks every
lock acquisition in the kernel, from the first lock the boot CPU takes (the
per-CPU id it needs is set by each ISA's boot assembly); only the sleep check
waits for the CPU's first context switch. A lock's class is where its constructor was
called (`SpinLock::new`, `Mutex::new`, `Claim::new` and
`WaitQueue::new` take the caller's location), so call sites do not change.
Each CPU keeps the stack of locks it holds; a task's part of it is saved and
restored at the context switch. A fixed-size, lock-free table records which
class was held when another was taken, and taking B under A after A was taken
under B is reported before the lock is spun on; a cache of already-checked
chains of held classes keeps the walk to once per chain, and locks taken in
interrupt context are ordered only among themselves. A sleep or a device wait
(WaitQueue waits, Mutex acquisition, the block layer, the
virtio-blk completion wait) with a SpinLock held, with interrupts off or in
an interrupt, a lock still held on a return to user mode (checked on the trap
paths of all three ISAs) and a task exiting with a lock are reported too.
Interrupt safety is inferred per class, as Linux does with one state: a
class taken in interrupt context and also taken with interrupts on in task
context is reported without the interrupt having to arrive at the wrong
moment. Every hold is timed with the platform timer into a per-class
histogram, from the boot's timer probe on (x86_64's clock is calibrated
there; an earlier hold is not timed); a SpinLock held past `LOCK_MAX_HOLD_US` is a violation with
`LOCKDEP_HOLD_ENFORCE`, the default on hardware boards, and a note on the
QEMU board, where emulated time follows host load. The gate also enforces it
on QEMU in instruction time: one virtual CPU under `-icount shift=0`, where a
microsecond is 1,000 guest instructions. A Mutex
contended by real-time tasks on two CPUs is reported: until proxy
execution, such tasks share only SpinLocks. Reports are queued, never
printed from the lock path; the boot prints those made before its console
existed as soon as it has one, a ktest kernel fails `lockdep_boot_phase_clean`
on those made before its first test, and the ktest runner prints them and
fails the test that was running, or the run, and prints the classes with the longest
holds. With `LOCKDEP=y` outside ktest the `log-flush` task prints them. Off,
no lock carries a class and no path calls the checker: the kernel is the
same, instruction for instruction. Cycles longer than two locks are not
searched.

**Lock scopes.** Who may touch per-CPU and shared state is part of its type
(`crates/core/sync/src/scope.rs`). A `PerCpu<T>` is used only by its own
CPU with preemption off, proved by a token (a preemption guard, a SpinLock
guard, or `IrqOff` for exclusive access); it has no lock. A `CpuOwned<T>`
has a SpinLock per CPU: another CPU's is locked only from task context,
since remote work from an interrupt goes through a deferred list and an
IPI. A `Global<T>` is a lock any CPU takes, and an `Object<T, LEVEL>` is a
lock per object taken in a fixed level order, checked at compile time when
the outer guard is in hand and by lockdep otherwise; two of one level are
taken together in address order. Lockdep checks at run time what the types
cannot: another CPU's `CpuOwned` locked in interrupt context, and a
`PerCpu` reached with preemption on. `azos_percpu::PerCpuRemote` is the
storage under them, any CPU's instance from any CPU; the per-CPU timer
heaps are a `PerCpu`.

**Read-copy-update.** With Kconfig `RCU_QSBR`,
`crates/core/sync/src/qsbr.rs` gives readers a section that takes no lock
(`qsbr::read`: preemption off on the CPU, and a held entry for lockdep, so a
sleep inside it is reported) and writers `call_rcu` and `synchronize_rcu`,
which free what a reader may hold only after a grace period: every online
CPU has passed a quiescent state. Each CPU keeps two words. One is odd while
it runs kernel code and even while it is idle (and, on a CPU listed in
`RCU_NOCBS_CPUS`, while it is in user mode); the idle task, every interrupt
from idle and those CPUs' kernel entries and exits move it, and so does
every context switch. The other records the grace-period number current at
the CPU's last return to user mode from an interrupt. A CPU that was even
when a grace period started, has moved since, or has returned to user mode
after it started, has passed. So a tickless idle CPU, or an RT CPU running
one task in user mode without a tick, never holds a grace period and is
never sent an interrupt for one; a CPU running user code passes at its next
tick. A syscall's return reports nothing: with `RCU_NOCBS_CPUS` empty a
syscall carries no instruction for this, and with a mask a CPU outside it
pays one test. Callbacks go onto the calling CPU's
lock-free list and run in one kernel task pinned to the lowest CPU outside
`RCU_NOCBS_CPUS`, after the grace period that followed their queueing, so
none runs on an RT CPU. A grace period older than `RCU_STALL_TIMEOUT_MS` is
counted as a stall naming the CPU that holds it. Off, none of this is
compiled and the capability reads take the table lock.

**Decision records.** With Kconfig `DECISION_RECORDS_DEV`, boot deadline and
memory admission, the real-time band cap, a woken task's move to another CPU
and typed capability denials each write one fixed-size record: the rule, the
verdict, the subject, the numbers compared and the rejected alternative.
`crates/core/decision` keeps them in a lock-free ring, and `/proc/decisions`
prints it. Off, the record sites compile out. Refusals have a second path,
Kconfig `DECISION_REFUSALS_DURABLE` (on in every preset): a refusal (boot
admission, the band cap, a run-time `rt::reserve`) also writes a
`SAFETY_DECISION_REFUSED` flight-recorder record, queued for the log flusher
when the caller is real-time. It does not need the ring.

**Asking why.** Every stored record claims an id (a sequence number, unique
since boot, ring on or off) and is stamped with the kernel clock. A decision
that went down the durable path is also kept whole, with every provenance field,
in a small RAM journal (`DECISION_JOURNAL_ENTRIES`), so the question can be
answered with the ring off. `azos_decision::query` (a filter on rule, verdict
and subject, paged by id) and `lookup` (one id) read the ring and the journal;
nothing parses text. Three faces use them. The recovery console's `why [id]`
prints the chain of a decision (rule, verdict, subject, the numbers by name, the
alternative rejected, capability slot and parent, topology row, image hash
prefix, clock; `-` where no call site has the value yet) or lists the latest.
The `Decisions` interface (`userspace/lib/decisions`, `#[azos_interface]`, ops
`query` and `get`) is the same query over an endpoint: `DECISD.ELF` serves it on
`endpoint.decisions`, from the binary records of `/proc/decisions.bin`, and
`WHY.ELF`, whose row holds the call capability, prints the chain. A record is 13
words and a reply seven, so `get` returns it in two parts. `tools/perfetto_export.py`
turns the flight-recorder files, `/proc/decisions` or `/proc/decisions.bin` and
`tracectl stream` output into one Perfetto timeline. After a reset the ids restart;
a durable receipt on the medium is matched by the recorder's own timestamp.

## Configuration and profiles

`make config` runs Kconfig over `Kconfig` and `config/Kconfig.*`.
`tools/kconfig_to_cargo.py` turns the result into cargo features, and
`crates/core/limits` turns it into compile-time constants.

**Domains.** The application domain, derived from the preset (`PRESET_*`; the `USE_*` symbols have no prompt), decides which crates are linked. It also
sets the starting value of other options, each of which can still be changed
by hand. The domains are:

| Domain | What it links or changes |
|---|---|
| Generic | The Kconfig default. No robot crate. |
| IoT / HMI | Starts with the board's display driver and the camera on. |
| Gateway / edge | On the edge profile, starts with many more, smaller network connections and sockets. |
| Industrial | Starts the threat model at physical access to the device. |
| Drivers as ring-3 servers | Starts every driver that has a placement choice in ring 3. |
| Robotics | Links `domains/robot`: the motor control loop, the safety envelope, flight and navigation, the behavior layer and the planner link. |

Robotics is one domain among these and the least used. The QEMU test
defconfigs select it, because their scenarios drive motors, and so do the
board defconfigs.

**Resource profiles.** Independently of the domain, a resource profile sizes
the static tables: capability slots, sockets, caches and heap. There are
three:

- **Embedded**, for 16–64 MiB boards. Its linker script holds the image to a
  fixed budget.
- **Edge**, the default, for single-board computers.
- **Fleet**, for gateways aggregating many devices.

**Userspace programs and the console program.** The "Userspace programs"
menu is generated at every Kconfig parse by `tools/gen_userspace_kconfig.py`
from the directories under `userspace/` (each program's
`[package.metadata.azos]`, or `azos.toml`, names its images) and is not
committed: a program directory that is added or deleted appears in, or
leaves, the next configuration. It has one `USERSPACE_<IMAGE>` option per
image, which puts that image on the board volume. Images that the built-in
topology always has a row for are selected and cannot be removed, except on
a small board (`HWCLASS_EMBEDDED`), which builds only what its topology
starts (a program's `start` condition in its metadata, today the decision
server when the kernel keeps decisions) and what its config names. The
`CONSOLE_PROGRAM` choice picks what the kernel starts on the console: the
native shell (the edge and fleet default), BusyBox `sh`, any other included
image, a custom `/fat` image with arguments, or none. Its topology row says
`start = true`, so it is hash-bound, confined by its seccomp profile and
row, and supervised like any other row. A Linux-ABI console program gets
its argv, descriptors 0-2 on the console and the console input. The
in-kernel shell remains the recovery console. With secure boot off,
`init=/fat/NAME.ELF` on the kernel command line (`/chosen/bootargs`) names
another image for one boot, provided that image has a topology row. With
secure boot on, `init=` is ignored and the boot log says so.
Development builds (Kconfig `BUILD_TYPE_DEV` and `CANARY_RUNTIME`, never with
secure boot) also
read `canary=<name>[,<name>]` there: it arms named gate canaries for one
boot, so a canary test boots the same kernel as the test it checks.
On aarch64 the command line arrives only with a device tree, which the
loader hands over in `x0` when it boots the kernel as an arm64 `Image`
(the `kernel.img` that `llvm-objcopy -O binary` makes from the ELF). QEMU
`virt` booting the ELF itself passes no device tree, so that boot has no
command line; every aarch64 boot in the gate uses the `Image`.

**CPU baseline and extensions.** Every ISA is configured the same way
(`config/Kconfig.arch`):

- A **baseline level**: `RISCV64_LEVEL` (rv64imac, rv64gc, rv64gcv),
  `AARCH64_LEVEL` (Armv8.0 to 8.5) or `X86_64_LEVEL` (x86-64 v1 to v4).
  It is the only thing codegen assumes for the kernel and the user images.
  `tools/kconfig_to_cargo.py --rustflags` and `--user-rustflags` turn it into
  target features. They use stable feature names, never `+v8.Na`. The
  soft-float aarch64 kernel gets only the features that need no SIMD
  registers (`+lse`, `+rcpc`, ...); the user images get the whole list.
  The soft-float x86_64 kernel likewise gets `-C target-cpu=x86-64-vN` and
  only the integer `require` extensions (`+popcnt`, `+bmi2`, `+adx`, ...); its
  user images are hard-float (`userspace/x86_64-azos-user.json`, SSE2 and up)
  and get the level's SIMD too. The
  boot checks the level before anything that depends on it. On aarch64 that
  is the first hook, before the first lock: a `+lse` kernel on an Armv8.0
  core would otherwise fault at its first atomic instead of saying why. A CPU
  below the level is refused with a message naming the missing feature, and
  the machine powers off.
- **Each optional extension is a three-way choice**: `n` (never used, even
  when present: its path is never selected and the vDSO hwcap hides it),
  `probe` (used only when the boot probe finds it, with a fallback otherwise)
  or `require` (part of the baseline: target features where the ISA allows,
  and a CPU without it is refused). riscv64 has Zicboz, Zicbom, Sstc, Svpbmt, Zba,
  Zbb, Zbs, V, AIA, Zihintpause, Zawrs and Zacas. aarch64 has LSE, PAN, CRC32, PAuth, BTI, MTE, SVE, AES,
  PMULL and SHA2. x86_64 has the extensions of its levels (SSE4.2, POPCNT;
  XSAVE, AVX, AVX2, BMI1, BMI2, FMA, MOVBE; AVX-512 F/BW/CD/DQ/VL), AES-NI,
  PCLMULQDQ, SHA-NI, RDRAND, RDSEED, ADX, FSGSBASE, PCID, INVPCID, SMEP,
  SMAP, UMIP, PKU, LA57 (5-level paging), 1 GiB pages, CET-IBT, CET shadow stack, XSAVEOPT, XSAVES,
  x2APIC, TSC-deadline, invariant TSC and WAITPKG, read from CPUID leaves 1, 7, 0xD,
  0x80000001 and 0x80000007. Some of these are detected and reported
  only, because no kernel path uses them yet; each symbol's help says which.
  For those, `n` and `probe` differ only in the boot line.
- **Per-board defaults** say what a board has. QEMU uses rv64imac,
  Armv8.0 and x86-64-v2 with everything on `probe` (V is `n`). The VisionFive 2 uses
  rv64gc. The K1 uses rv64gcv with Zba/Zbb/Zbs and V set to `require`; both
  boards set Zawrs and Zacas to `n` (their cores' upstream device trees do
  not list them). The
  Raspberry Pi 5 uses Armv8.2 with LSE set to `require` and PAuth, BTI, MTE
  and SVE set to `n`. A level that contains an extension forces `require` on
  it: Armv8.1 implies LSE, PAN and CRC32, 8.3 PAuth, 8.5 BTI, x86-64-v2 SSE4.2
  and POPCNT, v3 XSAVE, AVX, AVX2, BMI1/2, FMA and MOVBE, v4 AVX-512. On
  x86_64 an extension whose prerequisite is `n` is `n` too (AVX needs XSAVE,
  AVX2 needs AVX, CET needs XSAVES), and `make config` offers nothing else.

The boot prints one line with the baseline and each extension's state:
`[ISA] baseline=rv64imac zicboz=probed-present sstc=probed-present ... v=n`.
The policies reach Rust as `azos_arch_api::isa`. Every kernel rule in the
Makefile takes its flags from the one emitter. `crates/core/limits/build.rs`
refuses a kernel build whose target features disagree with its Kconfig, in
either direction. A K1 flag in a VF2 build, or a `require` the flags
forgot, is a build error. The plain `cargo build` of the default config
needs nothing extra: `.cargo/config.toml` carries riscv64's default level.
A board's user images are built from its config:
`make RV_USER_KCONFIG=build/k1.config userspace` or
`make AARCH64_USER_KCONFIG=<config> userspace-aarch64`.

Other menus cover the architecture (including the aarch64 page granule),
timing and scheduling, security mitigations, network, OTA, the Linux options
and development aids.

## Adding an ISA

A port is a list of methods the compiler asks for, plus a few files. The
x86_64 port is the latest: `make qemu-x86_64` boots it on QEMU `-M microvm`
(PVH entry, long mode, COM1) with every CPU the MADT names, and with
`QEMU_X86_64_DISK=build/disk-x86_64.img` its FAT volume is a virtio-blk device
in the microvm virtio-mmio window and the console program runs in ring 3.
The x86_64 user images (`make userspace-x86_64`, into `build/x86_64/`) are
linked by each program's `user_x86_64.ld` for `userspace/x86_64-azos-user.json`,
a bare-metal hard-float System V target (rustc's `x86_64-unknown-none` is
soft-float); libsys's `_azos_entry` realigns the stack and calls the
program's `_start`, and the kernel keeps each task's XMM/MXCSR state across
switches and forks. The TSC is read in ring 3: the vDSO publishes the
kernel's TSC-to-clock conversion (`VDSO_COUNTER_*`). libsys enters the kernel with
`syscall` (number in rax, arguments in rdi, rsi, rdx, r10, r8, r9; the
fast-IPC replies come back in rdx, rsi, rdi, r8, r9, r10), and they are bound
by their own digest table, `build/image_hashes_x86_64.rs`. The shared page-table walks follow
`Mmu::levels()`: a root above level 2 (x86_64's PML4, a PML5 under LA57) is
walked down to its level-2 tables first, and on riscv64 and aarch64, whose
roots are level-2 tables, that step is constant-folded away.

- **`crates/core/arch-<isa>`** implements every trait `crates/core/arch-api`
  exports, on a zero-sized type the facade (`crates/core/arch`) names `ARCH`:
  `Cpu` (6 methods, including the per-CPU base), `Interrupts` (6), `Mmu` (24
  required, 1 provided, the `PAGE_SIZE` constant), `Boot` (3), `Vector` (2),
  `ArchPlatform` (8, and a `UserAccess` type). Shared crates reach the ISA only
  through these; the facade refuses to compile for a bare-metal target it has
  no branch for.
- **`kernel/src/entry/<isa>/`**: `boot_hooks.rs` and `arch_entry.rs`, the
  kernel's `ArchEntry` (37 methods, four associated types, a
  `PAGE_TABLES` name and a `CONSOLE_MMIO` flag: the 27 early-boot hooks `boot::early_main` calls, the
  late VirtIO map, the boot-once text patch, the secondary-CPU wake, the
  scheduler hand-off, the four
  secondary-CPU steps the shared `secondary_main` calls, the vDSO clock and
  counter scale);
  `kernel/src/entry/<isa>.rs` with the `TrapFrame` and its `TrapContext` (11
  methods); and `asm/boot.S` (exports `_start`, calls `kernel_main` and, per
  secondary CPU, `secondary_main`; x86_64 enters a secondary through a
  real-mode trampoline below 1 MiB and `asm/ap_entry.S`), `asm/trap_entry.S` (the vector table and
  the return path, calling the ISA's Rust dispatcher) and
  `asm/context_switch.S` (exports `context_switch`).
- **`kernel/linker-<isa>.ld`**, defining the section symbols the shared code
  reads (`_text_start` ... `_kernel_end`, `__azos_keys_start/_end`).
- **Configuration**: an `ARCH_<ISA>` entry in the `config/Kconfig.arch`
  choice, with a `<ISA>_LEVEL` baseline choice and one n / probe / require
  choice per optional extension (the model under "Configuration and
  profiles"), with per-board defaults; their policy table in
  `crates/core/arch-api/src/isa.rs`; the target triple and the level's
  target features (kernel and user) in `tools/kconfig_to_cargo.py`; the
  boot hook that checks the level before anything compiled for it runs and
  prints the `[ISA]` line through `kernel/src/boot/isa.rs`; a defconfig
  named in the Makefile, after which `make ARCH=<isa> check` type-checks
  the kernel.
- **Shared code**: `tools/arch_cfg_lint.py` requires every `cfg(target_arch)`
  outside the arch crates to have an else arm, a `compile_error!`, or a
  `// arch-only: <why>` note, so a branch cannot vanish silently on a new
  ISA; the per-file counts in `tools/arch_cfg_lint.baseline` may only fall.
  `tools/arch_stub_check.py` runs `cargo check` of each arch-consuming crate
  against the skeleton and lists what reaches past the contract.
  `tools/boot_seq_lint.py` keeps the common early-boot steps in
  `boot::early_main`: a port writes only the hooks.

## Source layout

```
kernel/          composition root: kernel_main, entry and trap code per ISA,
                 boot steps (kernel/src/boot), kernel tasks, panic handler
crates/core/     abi, arch-api, arch-riscv64, arch-aarch64, arch-x86_64
                 (skeleton), sched, mm, ipc,
                 channel, spsc, syscall, topology, actuation, config,
                 limits, crypto, ota, shell, libsys, linux-abi, lx-loader, ...
crates/drivers/  one crate per driver class, plus api, base, driver_server
crates/fs/       VFS, FAT32, tmpfs, procfs, block cache, crash log
crates/net/      TCP/IP stack, encrypted link, stream multiplexer, TFTP
domains/robot/   robot domain: behavior, safety-core, flight, nav, AHRS, ...
userspace/       ring-3 programs (services, drivers, tests, benchmarks),
                 image_hashes.py
lx/              Linux driver compatibility layer (optional, GPL-2.0-only glue)
config/          Kconfig tree and defconfigs
tools/           build, check, signing, benchmark and analysis scripts
tests/           host test crates (tests/host), QEMU scenarios (tests/qemu),
                 fuzz targets (tests/fuzz)
formal/          TLA+ models (scaffolding)
```

## Scope

### In scope

- **The kernel guarantee.** No irreversible effect happens outside an
  envelope checked outside the planner, without an explicit capability, or
  without a durable record. The kernel enforces the capability and the
  record. The latch that stops actuation is kernel code in every domain; the
  robot domain's envelope is kernel code too.
- **The division of work:**
  - The **kernel** owns scheduling, memory, IPC and capabilities,
    system-call filtering, file systems, networking, the drivers that safety
    decisions read, and the actuation authority.
  - **Ring 3** runs programs, services such as the shell, the ML inference
    service and the planner client, and the drivers that can move out.
  - The **planner** proposes actions over the planner link. The kernel
    decides whether they take effect.
- **One kernel for several deployments.** General-purpose devices, IoT/HMI,
  gateways, industrial control and robots, each chosen as a domain and sized
  by a resource profile.
- **Two ISAs, built from one tree:** riscv64 and aarch64. Both run under QEMU
  `virt`.
- **Linux drivers in ring-3 servers** (`LINUX_DRIVERS`). Unmodified Linux
  driver modules run in a ring-3 server, so a device can use an existing
  Linux driver without that driver entering the kernel. Not built yet: today
  there is a module loader and an empty server, and every module option fails
  the build.

### Out of scope

- **A POSIX or Linux replacement.** Native programs use the AzOS system-call
  ABI through `crates/core/libsys`, a Rust wrapper library, or through Rust's
  `std` on the `*-unknown-azos` targets (the SDK, `sdk/README.md`), which maps
  straight to handles, threads, futexes and the vDSO clock; there is no
  native libc and no POSIX layer under either. The Linux personality (`LINUX_ABI`) is optional and off by
  default. It runs static Linux binaries only, with no dynamic loader. It
  covers files, pipes, directories, memory, time, identity, processes
  (fork-style `clone`, `wait4`, `execve`), threads and futexes, and signals.
  Any other call returns `ENOSYS`. A Linux program holds no hardware
  capability.
- **A desktop or GUI.** There is no window system or compositor. Display
  support is a framebuffer.
- **File-backed paging and swap.** There is no file-backed paging and no swap.
- **Certification.** AzOS is not certified for any safety or security
  standard.
- **Hardware.** AzOS has not been brought up on real hardware. The
  VisionFive 2 and SpacemiT K1 board descriptions are built but have not
  run.
- **The planner itself.** Perception, planning and models live in the
  separate `AzOSRobotBrain` repository, outside the kernel's trust boundary.

## AzOS-micro (the MCU kernel)

`micro/` is a second kernel for parts with no MMU, built by `make micro` for
`riscv32imac-unknown-none-elf` (core and alloc from source). It is not a
configuration of the kernel above: it runs in M-mode, protects memory with PMP,
and has its own workspace, its own link script and its own Kconfig symbols
(`config/Kconfig.micro`, `MICRO_*`; `config/defconfigs/micro.config`).

- **Tasks.** One slot per row of the signed topology (and per `instances`),
  reserved at boot; an image is a function in the kernel image named by the
  row. There is no fork and no exec: `SYS_SPAWN_EX` starts a reserved slot of
  a row the caller holds a `Launch` capability for.
- **Domains.** A task's PMP entries cover its Anon part (eager, from a pool),
  the Phys windows its `mmio` capabilities name and the Contig blocks its
  `shm` capabilities name (a `[pipeline.NAME]`, power-of-two, one NAPOT entry);
  the code window (text and read-only data) is shared. A region costs one
  entry (NAPOT) or two (a TOR pair); a domain over `MICRO_TASK_PMP_ENTRIES` is
  refused at boot. The task is told its regions in a start block (`StartInfo`).
- **Grants.** The top of a task's Anon region is the kernel's: no entry covers
  it. The capability table and the request queue of an endpoint the task
  serves live there, so state is charged to the row and goes with the task.
- **Ceiling.** The ceiling of an endpoint is the most urgent of its server and
  its clients (`PiAttr`, from the topology); a server holding a request runs
  there. No wait graph. A server in the idle class with a client above it is
  refused at boot (it would never be picked to reach its accept), and a row
  cannot call an endpoint it serves. One idle row without an endpoint
  capability is the floor: it never blocks and is started again if it ends.
- **ABI.** The main kernel's: handles and the 128-bit slot
  (`azos_abi::cap::slot_word`), the fast-IPC calls, error codes, one machine
  word wide. A word cannot carry the SHARE flag of `SYS_IPC_FAST_CALL_EP`, so
  a call moves its capability or none; `SYS_SPAWN_EX` takes the image's name;
  the uptime op of the task's own domain is the 64-bit counter as two words (a0 low, a1 high).
- **Shared code.** `sc.rs`, `rt_core.rs`, `qsbr_core.rs` and `pi_attr.rs` are
  compiled from the main kernel's sources (`#[path]`); the topology parser
  and `azos_abi` are the same crates. The host suite `micro-tests` runs the
  kernel over a fake machine; `userspace/tests/captest/src/abi_cases.rs` is
  one source for the cases both kernels' `captest` checks.
