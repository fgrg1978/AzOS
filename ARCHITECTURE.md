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
`line_release`, `irq_routing_init`, `smp_probe`, `timer_init`,
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
  CPU, first fit, against the same limit. EDF orders reservations only within
  one priority level, so a CPU whose reservations sit at different levels
  must also pass a cross-level test: for each level, its density plus the
  density of the levels above, plus their budgets over its shortest deadline,
  must not exceed the CPU. Boot and run-time admission apply the same test
  to the same levels: a topology row that fails it on every CPU it may use
  stops the boot, naming the row and the levels, and a reservation made
  after boot that fails it is refused.
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
  table holds device windows only, which the boot reads back.
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
- **Allocators.** The physical frame allocator is a bitmap. The kernel heap is
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

## IPC and capabilities

**Capability tables.** Each task has a capability table, sized per resource
profile. A handle is 32 bits and packs the object kind, the rights (read,
write, exec, dup), a generation and a slot index. Each typed call checks, in
order:

1. the slot exists,
2. the generation matches,
3. the kind is the one the call expects,
4. the handle carries the needed rights.

A stale or wrongly typed handle fails. Kinds cover IPC objects (channel,
shared memory, port, ring, endpoint, lease, pipe), hardware (IRQ, MMIO region,
GPIO, I2C, PWM, motor, ADC, buzzer, sensor, power, disk, network
configuration), and system objects (file, socket, task, driver registry, link
key, entropy, launch). Capabilities are minted from the topology at spawn.
No call grants or duplicates a capability to another task; the only transfer
is a move with a fast call. Revocation is done by the kernel.

Hardware is reached through capability-typed calls. Two untyped hardware calls
remain because they have no typed form: ADC read and motor create. MMIO and
IRQ capabilities name an entry in the board's resource table, never an
address.

**IPC mechanisms:**

- **Fast call.** Synchronous call and reply through a capability to an
  endpoint. The message travels in registers (four 64-bit words), with
  priority donation to the server. A capability can be moved with a call. The
  receiver gets a fresh generation, so the sender's handle becomes stale.
- **Channels.** Asynchronous queues of small fixed-size messages.
- **Shared memory and rings.**
  - Shared-memory regions can be mapped by several tasks.
  - `io_ring` is a submission and completion ring shared between a task and
    the kernel. The kernel checks each entry against the task's filter and
    capabilities.
  - Single-producer single-consumer rings in a shared region carry data
    between tasks and from kernel sensor streams to ring 3.
- **Notifications.** A futex-style wait and wake on a word in a
  shared-memory region. Event ports multiplex channels, rings, timers and
  interrupts.
- **Leases.** A lease grants a shared-memory region from one task to another
  for a bounded time, for example for zero-copy camera frames or inference
  inputs. The mapping belongs to the lease and is removed when the lease is
  returned, freed or expires.

## System calls and per-image filters

Every ring-3 program the kernel starts runs under a system-call filter chosen
by the SHA-256 of its ELF:

- **Spawn.** The kernel hashes the image and looks the digest up in the
  compiled-in table. If the digest is unknown it refuses to start the image.
  If it is known, the kernel installs that image's filter and seeds the task
  from that image's topology row. When autorun refuses an image, it writes a
  durable safety record.
- **Filter lifetime.** A task cannot remove its filter, and only `exec`
  changes it. Enabling a filter is one-way, and a second install is refused.
  `fork` copies the parent's filter.
- **Exec.** `exec` is available only to a task whose filter allows it. It
  re-hashes the new image and refuses an unknown digest. On success it
  installs the new image's own filter and row in place of the caller's, so
  the filter belongs to the running image, whether that is narrower or wider
  than the caller's. An image whose row says `abi = "linux"` can be started
  only by spawn.
- **Verified-digest cache.** Hashing an image on every spawn is avoided by a
  small cache of verified digests. Entries are keyed by the file's identity on
  the FAT32 volume (start cluster, size and the volume's write epoch), never
  by path. Any write to the volume invalidates them. Files on tmpfs are never
  cached. The same cache can keep a program's text frames for reuse.

## Drivers

**Classes.** Drivers are grouped by class under `crates/drivers/<class>`:
`irqchip`, `sys` (console, timers, watchdog), `virtio`, `block`, `net`, `bus`
(I2C, SPI, CAN, USB, UART bridge), `gpio`, `sensor`, `actuator`, `power`,
`display`, `camera`, `pci`, `dma`, `iommu` and others. `crates/drivers/api`
defines the `Driver` trait and the class traits for block, console, network
and USB devices. `crates/drivers/base` holds the board description and the
in-kernel driver registry.

**Placement.** A driver whose chip logic is written separately from its host
can run in the kernel or in a ring-3 process, chosen per driver in Kconfig
(`DRV_<NAME>_PLACEMENT`). Today that is the INA219 power monitor and the
buzzer. A ring-3 driver:

- registers with the in-kernel driver server through a driver-registry
  capability,
- serves requests in a reply-and-wait loop,
- reaches its hardware through typed bus capabilities,
- cannot allocate DMA memory, which stays kernel-only.

The kernel calls a ring-3 driver through a proxy that implements the same
`Driver` trait.

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
  rewrite on close; the directory entry follows the data one epoch later.
  `O_TRUNC` to zero clears the entry, then frees the chain an epoch later.
  A write is not atomic. Atomic replace is a temp file, `fsync`, then
  `rename` over the live name: over an existing file `rename` is one
  journal record (a cut leaves the old file with the source still named,
  or the new one with the source gone), to a new name an in-place rewrite
  of the 8.3 name in one sector.
- **Journal.** A one-sector journal is replayed at mount.
- **Locks across device I/O.** No lock held across a device request turns
  preemption off. The FAT holds no mutex across device I/O: a FAT entry
  update claims its FAT sector in a bitmap, and a second updater of the same
  sector sleeps on a wait queue without priority inheritance until the first
  publishes, so a real-time waiter never inherits disk latency. The allocator
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
- **No priority-inheritance mutex across a device wait, for any task.** A
  lock that must exclude across one is a sleeping lock without priority
  inheritance (`SleepLock`): the exec and spawn image buffer, the raw disk
  calls' bounce buffers, the shell's spawn buffer and the flight recorder's
  flush lock. The machine-wide descriptor table keeps priority inheritance
  (real-time tasks use it for in-memory and device files) and is never held
  across device I/O. An open runs on a private table and the descriptor
  then moves into the shared one. A read or write of a streaming file runs
  on a lent copy of the descriptor that keeps the file alive, under the open
  file description's position lock (a sleeping lock without priority
  inheritance, as Linux's `f_pos_lock`), so two threads sharing a
  description never transfer at the same offset. Its offset is published
  under the table lock afterwards. In-memory files keep the table lock. A
  close flushes a dirty file outside the lock once its last descriptor is
  gone, and `fsync` writes a copy of the bytes. The
  panic path counts sleeping locks a task holds the same way it counts held
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
- **Write observer.** Writers that reach the medium without going through
  FAT32 call a write observer. These are the raw disk call and the USB
  mass-storage gadget. FAT32 registers the observer to drop the cache lines a
  write touched.

**Network.** The TCP/IP stack is the kernel's own (`crates/net/net`): Ethernet,
ARP, IPv4, UDP, TCP, DHCP, DNS, NTP and IGMP. IPv6 covers link-local addressing,
neighbour discovery, ICMPv6 echo and UDP; TCP over IPv6 is not connected to
sockets. Ring 3 uses BSD-style socket calls and capability-typed socket calls.
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
PCI transport exists, but the kernel uses it only in self-tests.

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
When the ring is full, the new record evicts the oldest one, and the loss is
counted. Records leave the ring only once the medium has taken them.
The `log-flush` task writes the ring to disk (`LOG_FLUSHER_PRIORITY`, outside
the real-time band). The flush lock is a sleeping lock without priority
inheritance, and no real-time task takes it.
A real-time task that asks for a flush, or for a durable record such as an
e-stop, does not wait for it. It wakes `log-flush` and returns. Its record is
on disk once `log-flush` has run one flush after the request. A durable record
from any other task is flushed and synced before the call returns.
The real-time system watchdog also hands its OTA boot-good mark to `log-flush`. At boot the recorder is replayed to restore the e-stop latch and the
release nonce floor.

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
  topology row grants. With it, `SYS_TRACE_CTL_TYPED` maps the region and
  reads or sets the class mask; a call without it is refused and recorded.
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
machine off. On
riscv64 the power-off carries the verdict (SBI system reset with a failure
reason, so QEMU exits non-zero); aarch64's PSCI power-off has no reason
field. The kernel does not unwind, so a panicking test cannot be resumed: the
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

**Decision records.** With Kconfig `DECISION_RECORDS`, boot deadline and
memory admission, the real-time band cap, a woken task's move to another CPU
and typed capability denials each write one fixed-size record: the rule, the
verdict, the subject, the numbers compared and the rejected alternative.
`crates/core/decision` keeps them in a lock-free ring, and `/proc/decisions`
prints it. Off, the record sites compile out.

## Configuration and profiles

`make config` runs Kconfig over `Kconfig` and `config/Kconfig.*`.
`tools/kconfig_to_cargo.py` turns the result into cargo features, and
`crates/core/limits` turns it into compile-time constants.

**Domains.** The application domain decides which crates are linked. It also
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
topology always has a row for are selected and cannot be removed. The
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
  and a CPU without it is refused). riscv64 has Zicboz, Sstc, Svpbmt, Zba,
  Zbb, Zbs, V and AIA. aarch64 has LSE, PAN, CRC32, PAuth, BTI, MTE, SVE, AES,
  PMULL and SHA2. x86_64 has the extensions of its levels (SSE4.2, POPCNT;
  XSAVE, AVX, AVX2, BMI1, BMI2, FMA, MOVBE; AVX-512 F/BW/CD/DQ/VL), AES-NI,
  PCLMULQDQ, SHA-NI, RDRAND, RDSEED, ADX, FSGSBASE, PCID, INVPCID, SMEP,
  SMAP, UMIP, PKU, LA57 (5-level paging), 1 GiB pages, CET-IBT, CET shadow stack, XSAVEOPT, XSAVES,
  x2APIC, TSC-deadline and invariant TSC, read from CPUID leaves 1, 7, 0xD,
  0x80000001 and 0x80000007. Some of these are detected and reported
  only, because no kernel path uses them yet; each symbol's help says which.
  For those, `n` and `probe` differ only in the boot line.
- **Per-board defaults** say what a board has. QEMU uses rv64imac,
  Armv8.0 and x86-64-v2 with everything on `probe` (V is `n`). The VisionFive 2 uses
  rv64gc. The K1 uses rv64gcv with Zba/Zbb/Zbs and V set to `require`. The
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
                 channel, spsc, pubsub, syscall, topology, actuation, config,
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
  ABI through `crates/core/libsys`, a Rust wrapper library; there is no
  native libc. The Linux personality (`LINUX_ABI`) is optional and off by
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
