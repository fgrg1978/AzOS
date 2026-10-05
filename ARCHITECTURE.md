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
interrupts, MMU, boot, vectors); `crates/core/arch` re-exports the active one.

## Boot and composition

Both ISAs enter one `kernel_main` (`kernel/src/main.rs`). ISA-specific steps
are hooks under `kernel/src/entry/{riscv64,aarch64}/`.

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
6. The topology install, including deadline and memory admission.
7. Kernel tasks, then the ring-3 programs. These are the autorun list from the
   configuration and the topology rows marked `start`.
8. Secondary CPUs, then the scheduler.

**Topology.** The topology is a table of rows compiled into the kernel image.
It is not loaded from disk. A row is keyed by the program's image name. It
gives the task's priority, scheduling profile (period, runtime, deadline, CPU
mask), memory budget, the capabilities minted for it, its restart policy and
its ABI (native or Linux). Every ring-3 task the kernel starts gets its
authority from its row.

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
  CPU, first fit, against the same limit.
- **SMP.** The kernel supports up to 8 CPUs. It places a waking unpinned task
  on a suitable CPU and signals other CPUs with an inter-processor interrupt
  (SBI on riscv64, GICv3 SGI on aarch64). Tasks are not stolen between run
  queues at run time.
- **Tickless idle.** A CPU whose run queue is empty programs its timer for the
  nearest timer deadline instead of the periodic tick, bounded by an idle
  ceiling, or by a shorter keep-alive or polling interval when one is needed. It restores the periodic tick when work arrives.

## Memory

- **Page tables.** riscv64 uses Sv39. aarch64 uses VMSAv8-64 with a 4 KiB,
  16 KiB or 64 KiB granule, chosen at build time. On aarch64 the kernel is
  linked in the upper half and runs from TTBR1, and TTBR0 holds the user
  space.
- **Kernel W^X.** Once paging is on, the kernel image is mapped with text
  read-execute, read-only data read-only, and data read-write. Execute
  permission is removed from all RAM outside the image. Both properties are
  checked by reading the page tables back at boot, and a failed check is
  reported on the console.
- **User W^X.**
  - `fork` shares read-only and executable pages and marks only writable
    pages copy-on-write. The copy-on-write fault handler refuses an entry that
    is executable.
  - `mprotect` refuses `PROT_EXEC` and refuses write access to an executable
    mapping. The Linux personality's `mprotect` uses the same code.
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
  a linked-list allocator.

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

- **Block cache.** FAT32 reads and writes through a shared block cache in
  write-through mode, sized per profile.
- **Journal.** A one-sector journal is replayed at mount.
- **Write observer.** Writers that reach the medium without going through
  FAT32 call a write observer. These are the raw disk call and the USB
  mass-storage gadget. FAT32 registers the observer to drop the cache lines a
  write touched.

**Network.** The TCP/IP stack is the kernel's own (`crates/net/net`): Ethernet,
ARP, IPv4, UDP, TCP, DHCP, DNS, NTP and IGMP. IPv6 covers link-local addressing,
neighbour discovery, ICMPv6 echo and UDP; TCP over IPv6 is not connected to
sockets. Ring 3 uses BSD-style socket calls and capability-typed socket calls.

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

**Watchdogs:**

- **System watchdog.** A kernel task checks stack canaries, timer liveness,
  the kill-switch input and driver health, and latches the e-stop on a trip.
- **Hardware watchdog.** On a board that has one, the timer interrupt feeds
  it. Once the robot control loop has started, it is fed only while that
  loop's heartbeat advances, so a hung loop resets the board.

**Flight recorder.** Safety events are written to `LOG/LOGNNNNN.BIN` on the
FAT32 volume.
Each boot opens a new file whose serial number continues from the highest one
on disk. At boot the recorder is replayed to restore the e-stop latch and the
release nonce floor.

**Crash log.** The panic handler first writes a record to a reserved RAM
area, then appends the report to `/fat/CRASH.LOG`. If the append fails, the
next boot copies the RAM record to the file. `CRASH.LOG` rotates to
`CRASH.OLD` at 64 KiB.

**Log levels.** `LOG_LEVEL` (err, warn, info, debug) is a build-time choice.
Console lines below the level are compiled out. The flight recorder and the
panic report are not affected by it.

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

Other menus cover the architecture (including the aarch64 page granule),
timing and scheduling, security mitigations, network, OTA, the Linux options
and development aids.

## Source layout

```
kernel/          composition root: kernel_main, entry and trap code per ISA,
                 boot steps (kernel/src/boot), kernel tasks, panic handler
crates/core/     abi, arch-api, arch-riscv64, arch-aarch64, sched, mm, ipc,
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
