# AzOS — Changelog

All notable changes to the AzOS kernel and tooling (named KernOS until 2026-10-04).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is SemVer. Per-crate changelogs live next to each crate
(currently only `crates/core/abi/CHANGELOG.md`).

## [Unreleased]

- Runtime hardware bus with autodetection (`crates/drivers/hwbus`,
  `azos_drv_bus::hwbus`, `kernel/src/boot/hwbus.rs`). The boot-time list of
  three fixed devices and the static `MMIO_REGIONS` table are gone: PCI/PCIe
  functions (bus 0 and the buses behind bridges), device-tree nodes with a
  `compatible` and populated virtio-mmio windows become device objects, and
  drivers are bound to them from two generated match tables (native, from each
  driver crate's `hwbus.ids`; Linux, from `MODULE_DEVICE_TABLE` through
  `tools/lx_device_table.py`; the build refuses an id in both). The virtio
  disk, NIC, keyboard and entropy drivers, the NVMe driver and the virtio-pci
  NIC no longer scan for their hardware. Kconfig `HWBUS_AUTOBIND` (auto for
  desktop, server, IoT/HMI, gateway and generic; topology-only for robot,
  industrial, automotive, firmware and wearable) and `HWBUS_MAX_DEVICES`.
  CAPS.TOML format 6: `[device.NAME]` rows (`match`, `driver`, `admit`) and the
  task key `lx_class`. A `Device` capability (`ty::MMIO`) now names a bus
  handle: `mmio.<selector>` grants (`mmio.dt:google,goldfish-rtc`), a window
  writable by the capability's WRITE, `/proc/devices` for the handle; the
  `SAFETY_CAP_DENIED` record of such a refusal carries the handle. The
  decision rule `device-admission` records "detected, not admitted".
- Interrupts as scheduled objects (L5, Kconfig `IRQ_THREADED`, default on for the
  hard and mixed real-time classes). A line is bound to an event port by an op of
  its `Device` capability (`DEVICE_IRQ_BIND` with a CPU, `DEVICE_IRQ_ACK`);
  `DOMAIN_IRQ_BIND/WAIT/ACK`, the port source `PORT_SRC_IRQ` and the wake-task
  binding with its pending bit are deleted. With `IRQ_THREADED` the binder is
  the handler and must hold a hard reservation; a handler that runs out of
  budget has its lines masked until the replenishment (a held line stays masked
  past its ACK) and leaves an `irq-budget` decision record. The kernel's UART
  console and virtio lines run their bottom halves in a per-boot-CPU kernel
  thread on a reservation of its own (`IRQ_THREAD_PRIORITY`,
  `IRQ_THREAD_BUDGET_PCT`, `IRQ_THREAD_PERIOD_US`), and the timer's lease sweep
  moves there too. Message-signalled interrupts reach ring 3 where the platform
  has them (x86_64 LAPIC vectors, riscv64 IMSIC identities with AIA): an
  `msi.<k>` slot takes its vector at bind and answers the message the device
  writes. Host tests: the binding table (bind, budget, throttle, storm, MSI), the
  op's refusals; ktests `irq_storm_is_contained` (canary `irq-storm`) and
  `irq_msi_reaches_a_ring3_binding`.
- Elastic placement of a stateless driver (Phase 4). A topology row (CAPS.TOML
  format 6) says `place = "kernel" | "ring3"`, `stateless = true` and a
  `call_budget_us`; the built-in `BUZZDRV.ELF` row is the first (Kconfig
  `DRV_BUZZER_PLACEMENT` picks its `place`, `DRV_BUZZER_CALL_BUDGET_US` its
  budget). The buzzer is the `Buzzer` interface (`azos_devif::buzzer`,
  `#[azos_interface]`) served by both hosts from one chip-logic source: the
  ring-3 program on `endpoint.buzzer`, the kernel host through the direct-call
  stub. The kernel calls it with `BuzzerPlaced` (the new generated
  `<Name>Placed`), over `azos_syscall::kcall`, the kernel's own transport:
  `SYS_IPC_CALL_V2`'s body on kernel memory, refused with `-EBUSY` where the
  caller may not block (a spinlock held, `cap_store::with_table`'s closure).
  `azos_topology::placement::Elastic` moves the driver: a contained panic in
  the kernel host restarts it in ring 3 behind the same endpoint; when
  `PLACEMENT_PROMOTE_MISSES` of the last 16 timed calls break the budget it
  moves into the kernel, if the kernel host's boot-measured cost fits and it
  has not faulted within `PLACEMENT_HOLDOFF_S`. Every move and refusal is a
  `Rule::Placement` decision record (`why`), durable like a refusal, written by
  the one function that changes the host. `DRV_KIND_BUZZER`, `buzzer_op` and
  the buzzer's driver proxy are gone.
- Signed application packages (plan D14): a package is images plus a manifest
  of the warrants (endpoint grants), scheduling and memory budgets, hardware
  classes and IDL interface levels they ask for, signed by their AUTHOR.
  `crates/core/pkg` (`azos_pkg`) is the container (algorithm id, variable-length
  key and signature; Ed25519 today), the verification against the signers of
  the signed topology and the admission as a topology delta: the rows are
  `[task.NAME]` sections merged into the topology and judged by
  `admission_check` (the `neverallow` rules included) and by the signer's
  ceiling. `CAPS.TOM` format 6 adds `[signer.NAME]` (key id, `kind:prefix`
  warrants, real time, frames per row; Kconfig `TOPOLOGY_MAX_SIGNERS`,
  `TOPOLOGY_SIGNER_WARRANTS_TOTAL`), so the owner's topology key is the only
  root of trust. `PKGD.ELF` serves the `Packages` interface on
  `endpoint.packages` (a package crosses as a memory object and its length, never a path), stages the
  signed package under `/fat/PKG` and journals the decision
  (`Rule::PackageInstall`, the package id as provenance); `PKG.ELF` is its
  client. `tools/azpkg.py` builds, signs, verifies and inspects packages, emits
  an SPDX 2.3 SBOM whose hash is a signed key of the manifest, and lints the
  licences of the package, its components and its sources against
  `tools/azpkg_licences.txt`. Kconfig `PKG_*` sizes the buffers
  (`config/Kconfig.packages`). Nothing applies a staged
  package yet (the kernel's boot-time application is not built), so a staged
  package's rows join no topology and none of its images runs; the installer
  checks neither the device id nor the counter floor. A row's `imports` are
  held to the signer's `endpoint:` warrants (refusal step 17), and a staged
  file whose 8.3 name another package holds is staged under the next four
  bytes of its id, never over the other.
- `make relibc`: C on the native ABI. relibc (Redox's libc, MIT) is pinned in
  `third_party/RELIBC_PIN` (upstream's last tag is from 2020, so a `master` commit) and
  fetched outside the repo by `tools/relibc_fetch.sh`. `userspace/lib/relibc-azos` holds a
  patch against it and an overlay: the `azos` platform module (descriptors over handles,
  files and directories, `posix_spawn` over `SYS_SPAWN_EX`, threads and futexes, anonymous
  `mmap`, vDSO clocks; `ENOSYS` for `fork`, `exec`, signals, sockets, `epoll`, `ptrace`),
  target specs and linker scripts for riscv64, aarch64 and x86_64. `userspace/tests/relibc`
  has a C hello world and `tinybox` (cat, wc, ls, run, threads, ...), linked with `zig cc`.
  x86_64 moves `main` to a second thread because ring 3 cannot set its FS base.
  `tools/lx_license_lint.py` accepts MIT in the patch directory only (T6) and checks the pin
  (`--relibc-pin`); `libsys::thread_create_with_tls` passes the thread pointer.
- Transparent RPC, step 1 (Phase 9): `RPCSRV.ELF` (`userspace/services/rpcsrv`,
  engine `userspace/lib/rpc`) calls an endpoint on another node as a local one.
  The topology names a **proxy endpoint** `endpoint.rpc-<service>` (an
  `Endpoint` the kernel marks at creation: no new kind; the reserved proxy kind
  constant is gone), the server serves it, and the IDL wire format is the
  transport format (a descriptor in UDP frames; a deadline crosses as time
  remaining and clock class; a MemObj's pages move and are re-minted).
  Nothing leaves a node except through an `export = ["name@class"]` entry of
  the server's row to a `[peer.class]` section (CAPS.TOML format 6;
  `/proc/rpc`); the exporting node calls the service through a per-session
  warrant (attenuated, badged with the session, expiring `RPC_WARRANT_TTL_MS`,
  renewed), and a broken session revokes everything minted over it on both
  nodes and raises `IdlError::NoConnection` (distinct from the new
  `PeerDied`, `DeadlineExpired` and `Refused` statuses). Delivery follows the
  op's attribute (`Delivery`): `#[idempotent]` is resent, `#[at_most_once]` is
  deduplicated by a per-session window, `#[once_only]` is never retried, an
  unmarked op crosses no link. Both nodes keep provenance records (the kernel's
  `ProvenanceRecord`, peer node id and session id filled). A real-time caller
  is refused on a proxy endpoint: `-ERTPROXY` at the v1 and v2 calls and two
  `neverallow` rules at admission (`proxy-endpoint-not-realtime`,
  `proxy-endpoint-served-by-rpcsrv-only`). `why --remote` asks the peer's
  decision server. Kconfig `RPC_*` (`config/Kconfig.network`,
  `TOPOLOGY_MAX_PEERS`, `TOPOLOGY_PEER_NODES`, `TOPOLOGY_EXPORTS_TOTAL`).
  Noise/DICE come later: the handshake is an interface and proves nothing yet,
  so the server drops datagrams from any address but the configured peer's and
  refuses to run with a peer unless `RPC_ALLOW_CLAIMED_PEER` is set.
- `neverallow` assertions over the topology (SELinux's lesson): the table in
  `crates/core/topology/src/neverallow.rs` states grants no topology may make,
  and `Topology::admission_check` refuses one that does
  (`AdmissionError::Neverallow`, Kconfig `TOPOLOGY_NEVERALLOW`, default y) on
  every install path: the signed candidate (the kernel falls back or halts as
  `TOPOLOGY_SOURCE` says), the built-in topology (the board halts), the host
  emitter and the micro kernel. A refusal writes a `neverallow` decision record
  (`Rule::Neverallow`: the row, the rule, the kind and index of the grant).
  Four rules: no ring-3 row holds a motor, a PWM or GPIO write grant or the
  buzzer unless the table lists that exact grant (kind and target) for that row
  (`autorun`: the drivetrain, `pwm.4`, `gpio.20`; `FLIGHT.ELF`: the drivetrain;
  `BUZZDRV.ELF`: `pwm.5`; each with its reason); no row of a `USE_DESKTOP`
  image holds a motor; no row both imports names and serves an endpoint or a
  driver; no actuation grant is transferable. Exceptions live in the table, in
  the kernel image, never in a topology file. `make check-neverallow`
  (`tools/check_neverallow.py`) runs the rules over every preset on every ISA,
  every defconfig and the micro topology (a preset whose sizes `azos_limits` refuses,
  like the server's heap against its RAM, is checked with the sizes raised, never
  skipped; one that still does not build fails the run), and refuses a canary topology
  (feature `neverallow-row-canary`, also a kernel feature for the gate).
  The desktop presets disagreed with rule 2 (the QEMU board's `profile-actuation`
  grants `motor.0` and `motor.1` whatever the domain), so Kconfig
  `TOPOLOGY_DRIVETRAIN` (hidden under `USE_DESKTOP`) now gates the built-in
  drivetrain grants (`builder::DRIVETRAIN`).
- Unsafe budget (`tools/unsafe_budget.py`, baseline `tools/unsafe_budget.tsv`):
  counts `unsafe` blocks, fns, impls and attributes per crate, tests,
  `target/` and `third_party/` excluded, with a lexer that skips comments and
  literals. The gate row (`tools/ci_check.sh`, `tools/gate_tier.sh n0`) fails
  when a crate differs from the baseline: growth needs a reviewed
  `--update` in the same commit, and a removed `unsafe` lowers it so it cannot
  come back unseen. `--report` prints the per-crate table and the total
  (2840 at this commit) for a release.
- Hardened allocator for native ring-3 programs (`userspace/lib/ualloc`,
  `azos_ualloc`; plan phase 5 item 6): size-class blocks, random chunk
  placement from the kernel entropy pool, checksummed chunk headers (double
  free, foreign pointer, overwritten header, wrong size and corrupted free
  list end in a recorded fault), a quarantine of freed chunks with poison, and
  guard pages (`mmap` with `prot = 0`) around blocks and large allocations.
  Kconfig `USER_ALLOC_*` (`config/Kconfig.security`), on by default in every
  `SECURITY` posture but `general`. `LXSRV.ELF` links it in place of its bump
  arena and holds READ on the entropy pool for it (its seccomp row lists
  `SYS_CAP_LOOKUP`, `SYS_ENTROPY_READ_TYPED` and `SYS_MUNMAP`). Host suite
  `ualloc-tests` (detections with controls, a shadow-checked random workload,
  a micro-benchmark).
- A small board (HWCLASS_EMBEDDED) uses only the native drivers its config
  names: no Linux layer (LINUX_DRIVERS and every LX_* were already off there;
  LINUX_RUNTIME now is too), and DRV_VIRTIO_INPUT, DRV_PS2 and the camera and
  display drivers USE_IOT_HMI implies default off. `make check-presets`
  asserts it for every preset on every ISA with the class forced, for the
  small-board defconfigs, and runs a canary that must trip the rule.

- Type zones for physical frames (Kconfig `PMM_TYPE_ZONES`, on for every SECURITY
  posture but general; `PMM_ZONE_MAX_PAGES` bounds a zone): page-table pages and
  io_ring pages are tagged on allocation (`pmm::alloc_page_zone`), and a freed
  tagged frame goes on its zone's list, never to the per-hart cache or the buddy
  lists, so a use-after-free of a page-table frame cannot see it as a ring-3 data
  page (the kalloc_type lesson). Task, capability-table, endpoint and MemObj
  objects are static tables, type-isolated by construction, so there is no
  kernel-heap zone. `pmm::free_pages` counts a zone's free frames, as it counts a
  frame in another hart's cache. Canary `zone-share-canary`; ktest
  `mm_zone_no_cross_type_reuse`.
- AzOS-micro, the MCU kernel (`micro/`, `make micro`): a separate kernel for
  parts with no MMU. riscv32imac, M-mode, memory protection by PMP region
  domains (Anon, Phys, Contig); a static task table built from the signed
  topology (`micro/topology`, verified with the main kernel's loader); kernel
  state kept in grants inside each task's own region (the capability table,
  the request queue of an endpoint it serves); a server runs at its
  endpoint's priority ceiling while it works (`PiAttr`'s order, no wait
  graph); `SYS_SPAWN_EX` under a launch capability is the only way to start a
  task. The IPC and capability ABI is the main kernel's (`azos_abi`, the
  128-bit capability slot, the fast-IPC calls), recompiled for 32-bit words.
  Kconfig `MICRO_*` (`config/Kconfig.micro`, `config/defconfigs/micro.config`).
  The pure modules `sc.rs`, `rt_core.rs`, `qsbr_core.rs`, `pi_attr.rs` and
  the crates `azos_topology` and `azos_abi` build for 32-bit; the scheduling
  context's times are one word each (its size is 64 bytes, 40 on rv32), the
  capability slot word is `azos_abi::cap::slot_word`, and `PiAttr` and the
  refusal receipt moved out of `waitgraph.rs` and `rt_core.rs`. The ABI cases
  `captest` checks are shared between the two kernels
  (`userspace/tests/captest/src/abi_cases.rs`). Host suite `micro-tests` runs
  the micro kernel over a fake machine; `make micro-qemu` boots it on QEMU
  virt rv32 (not run in CI yet). `SYS_UPTIME` answers the 64-bit counter as a
  pair of words (low in a0, high in a1) because one 32-bit word wraps in
  minutes; a server that closed its `READ` capability serves no more until
  its row starts again; a row cannot call an endpoint it serves; the code
  window is aligned to `MICRO_PMP_GRAIN_LOG2` by the linker and checked at
  boot; a server in the idle class with a client above it is refused at
  boot; the idle row that always runs (no endpoint capability) never blocks
  and is started again if it exits or faults.

- Removed the `no-mmu` build and the `NO_MMU` / `HWCLASS_MCU` Kconfig symbols:
  the flat-address mode never ran on hardware. An MMU-less part is AzOS-micro.

- DMA domains and IOMMUs (RFC-0046 stage 1b; Kconfig "DMA and IOMMU"). Every virtio
  driver (block, net, rng, input) maps each buffer and ring through a `DmaDomain`
  (`crates/drivers/dma`) instead of handing the device `virt_to_phys` of a pointer:
  an identity domain, a software-checked one (the default: RAM and device reach,
  every live mapping recorded) or, with an IOMMU, a translating one per device.
  `crates/drivers/iommu` drives four units behind one interface: the RISC-V IOMMU,
  Arm SMMUv3, Intel VT-d and AMD-Vi (device tables, polled command and fault
  queues, the Sv39/Sv48, LPAE, VT-d second-level and AMD-Vi page tables); every
  layout was checked against the Linux headers and the QEMU models and is tested
  against vectors computed by hand. `IOMMU_RISCV`, `IOMMU_SMMUV3`, `IOMMU_VTD` and
  `IOMMU_AMDVI` (default `n`) put every PCI function in pass-through and the
  virtio-net NIC in a domain that maps only its buffers, rings and interrupt
  doorbell; a refused DMA is logged by the `iommu-faults` task. `DMA_NONCOHERENT`
  adds cache maintenance around every transfer (riscv64 Zicbom `cbo.clean` /
  `cbo.flush`, new `RV_ZICBOM` choice and `[ISA]` entry; aarch64 `dc cvac` /
  `dc civac`). The old `iommu` kernel feature (it only added `pci`), `DmaMapTable`
  and `AddrTranslate` are gone. The ACPI parser reads the DMAR and IVRS register
  bases. Host suites `dma-tests`, `iommu-tests` (57), `dtb-tests`, `pci-tests` and
  `x86-platform-tests` cover it; nothing here has run on QEMU or a board yet.

- Energy policy at run time (kernel feature `energy`): the governor, the OPP range
  of each performance domain, the schedutil headroom, the rate limit and an
  idle-depth limit are runtime-atomic and set through `SYS_POWER_TYPED`
  (`crates/core/energy/src/policy.rs`). User space decides, the kernel enforces
  limits: a setter outside them (a cap below the WCET reference OPP, below the
  admitted real-time floor, a governor that cannot honour the deadline floor,
  out-of-range headroom or rate) is refused with a recorded decision, and the
  floors are applied again at every governor evaluation. `POWER.ELF`
  (`userspace/services/power`) is now the policy server: `power serve|apply
  [preset]` applies a built-in profile per preset through the `PowerPolicy` IDL
  object (`userspace/lib/power`), logs every decision and answers a refusal from
  a decision table; `power state` prints the policy; the old commands stay as
  sub-commands. The scheduling context records a QoS hint (`SYS_SCHEDCTL` hint
  form); no timer tolerance reads it. Host suites `energy-tests` (policy,
  3 canaries) and `power-tests` (3 canaries).
- Locks, owner rule F1: `SleepLock` is gone. What must exclude across a device
  wait is the ownership of a resource, so it is a claim
  (`crates/core/sync/src/claim.rs`): the state is data under a kernel mutex held
  only for the instant of taking or giving the claim, and a contender sleeps
  with the mutex released (`unlock_for_io`). The exec and spawn image buffer
  (`EXEC_BOUNCE`), the flight recorder's flush (`LOG_FILE`) and the open file
  description's position (`DESC_POS`) are claims. `SYS_DISK_READ` and
  `SYS_DISK_WRITE` share nothing: each call takes its own bounce buffer from the
  heap (`ENOMEM` when it cannot), 128 KiB less `.bss`. Lockdep loses the
  `SleepLock` kind. Canary `claim-mutex-held` keeps the claim's mutex across the
  owner's device waits and lockdep notes it; `claim-held-keeps-dead` replaces
  `sleep-held-keeps-dead`; the gate feature `exec-bounce-pi-canary` now keeps
  the claim's mutex across the image read.

- NVMe: a native driver for NVM Express controllers over PCIe (Kconfig `DRV_NVME`,
  `crates/drivers/block/src/nvme.rs` over the host-tested wire-protocol crate
  `crates/drivers/nvme`). The controller is attached by the PCI bring-up before
  `blkdev::init` and becomes the block device, so the FAT32 volume mounts from it
  (riscv64 AIA and aarch64 ITS, completions by MSI-X; polled where no route
  exists). One admin queue and one I/O queue pair shared by all CPUs, PRP lists,
  `NVME_INFLIGHT` commands in flight, Flush. The PCI bring-up now runs before the
  block device is brought up. The ring-3 disk syscalls and the shell's `disk`
  command go through `blkdev` instead of calling `virtio::blk` directly. Gate
  rows `nvme: boot disk` and `nvme: prp canary` (riscv64).

- Fair class: EEVDF (`crates/core/sched/src/eevdf_core.rs`, `fairq.rs`) replaces
  the per-level round robin. A fair task (priority 12..30) has a weight from its
  priority (Linux's nice table, priority 16 = nice 0) and a slice
  (`FAIR_SLICE_US`, default 3000); the CPU is shared by weight, the pick is the
  eligible task with the earliest virtual deadline, and a sleeper keeps its
  lag (clamped to two slices). Behaviour change: among fair tasks the priority
  is no longer a strict order, only a weight. `Task::time_slice`,
  `TIME_SLICE_TICKS` and `RT_TIME_SLICE_TICKS` are gone. No `FAIR_POLICY`
  choice: no preset needs round robin.
- Flight recorder: the rt-motor watchdog writes `SAFETY_RT_WATCHDOG` (0x19)
  records on its transitions only — the first SAFE STOP (durable), the first
  clear, and one repeats count per 60 s window that saw more — as its console
  lines do. Log file format unchanged (`LOG_FILE_VERSION` 1: a new code in the
  existing safety-violation record). Gate rows `rt watchdog recorded`
  (riscv64, aarch64, canary).
- Project rename: KernOS → AzOS (2026-10-04). Crate prefix `robot_os_*` → `azos_*`,
  symbols `KERNOS_*`/`kernos_*` → `AZOS_*`/`azos_*`, `kernos-config` → `azos-config`.
- Drivers split by class: `azos_drivers` → `crates/drivers/<class>` crates
  `azos_drv_{base,irqchip,sys,gpio,bus,virtio,block,net,sensor,actuator,npu,power,dmac}`;
  `azos_drivers_api` → `azos_drv_api` (class traits: block, console, net, usb); ESC and
  RC → `domains/robot/drivers` (`azos_robot_drivers`); shell → `crates/core/shell`;
  imu/baro/gps → `crates/drivers/`. Old names are gone, no aliases.

### Changed — ML

- Fail closed on a missing ML service: with ML enabled, a boot on which the
  ring-3 ML service never started now holds STOP through L1, as a service
  that died already did; before, L1 passed and L2/L3 drove. `ml_enabled=0`
  and `no-ml` builds are unchanged. Ten consecutive cycles without a verdict
  write one `SAFETY_ML_ABSENT` (0x18) record per episode. Gate rows
  `ml service absent` (riscv64, aarch64, and a canary).
- Removed from the kernel: the `ml-demo` task, the shell's `ml`, `cam` and
  `model` commands, and the boot-time MLP weights load. The
  console no longer holds `Cap<AiSession>`; `pipeline` no longer needs ML.
  `azos_ml` (now `userspace/lib/ml`) is linked only by the ring-3 service;
  the `ml-kill-smoke` and `mlsf-bench` kernel features and their gate rows are
  gone.
- The MLP weights file is `/fat/MLP.RML` (was `MLP.RMLP`, not an 8.3 name, so
  the ML service never found it and used its compiled-in weights).

### Changed — scheduler

- The timer min-heap (`sched-timer-heap`) stays off by default: its gate was
  not green. The per-tick sleeper sweep remains the default on both ISAs.

### Changed — 2026-09-27

- aarch64: the kernel is built for `aarch64-unknown-none-softfloat`; user
  FP/SIMD state is saved lazily (CPACR_EL1.FPEN traps the first use), traps no
  longer save FP registers, and every return to user mode goes through
  `trap_return`. Syscall floor 270 → 230 instructions.
- virtio-net over PCI with MSI-X (RX interrupts, TX interrupt only when the
  ring is full) on riscv64 AIA and aarch64 ITS; polled on the PLIC machine.
  Egress costs +0.7 % (riscv64) / +0.3 % (aarch64) instructions against the
  MMIO NIC.
- Storage: virtio-blk negotiates and issues FLUSH; `fsync`, `sync` and the
  durable log appends flush the device and report a failure to confirm.
- Timer min-heap (`sched-timer-heap`, still off by default): fixed a lost
  wake — a retry re-armed a sleeper with a stale deadline and the next
  nearest-deadline query dropped its entry.

### Fixed — console, 2026-09-27

- The riscv64 console ignored input: the UART was initialised twice and the
  second pass disabled its receive interrupt while the console stayed in
  interrupt mode.

### Added — interrupt controllers and scheduler, 2026-09-27

- riscv64: AIA support (APLIC in MSI delivery mode + IMSIC), discovered from
  the DTB; the PLIC machine is unchanged. PCI MSI-X delivery through the
  IMSIC, shown by a boot-time virtio-net-pci TX self-test.
- aarch64: GICv3 ITS driver and LPIs; the same MSI-X self-test delivers
  through the ITS as an LPI. The ITS tables are passed as physical
  addresses, a memory-backed collection table is used when the ITS holds
  none, and each mapped LPI is enabled in the configuration table.
- aarch64: syscalls run with interrupts enabled once the trap frame is saved;
  `trap_return` masks interrupts before restoring `ELR_EL1`/`SPSR_EL1`.
- Scheduler, each behind a feature: O(1) per-CPU resident counts for
  placement (`sched-o1-placement`) and same-hart placement of fast-IPC wakes
  (`sched-ipc-affinity`), both on by default in the kernel
  (`--no-default-features` restores the previous behaviour); and a timer
  min-heap replacing the per-tick sleeper sweep (`sched-timer-heap`), off by
  default because it can lose a periodic kernel sleeper's wake.

### Fixed — security, 2026-09-27

- aarch64: every kernel-only page now carries UXN. Kernel text was
  executable from EL0: AP=00 with UXN clear is the architectural EL0
  execute-only encoding.

### Changed — capabilities and trap return, 2026-09-26

- `Cap<Power>` and `Cap<AiSession>` can now be granted from the topology
  (`power`, `ai.session`). The console's `pm suspend` and `model load` check
  them instead of the drivetrain capability. The default topology grants
  neither to the autorun image.
- riscv64: `trap_return` restores the frame's `sstatus` before writing
  `sscratch` and `sepc`. With interrupts enabled inside a syscall, a timer
  taken in that gap built its frame over the one being restored. Syscalls now
  run with interrupts enabled once the trap frame is saved.

### Fixed — drivers, 2026-09-26

- PWM: the JH7110's real OpenCores PTC shape (8 independent channels) and
  the QEMU/K1 simulation share one constant, `PWM_DOMAIN_INDEPENDENT_8`. A `vf2` build gates capabilities on
  `PWM_DOMAIN_VF2_DRIVER` (4 channels, shared `PWMCFG`), the layout the
  compiled driver actually programs, and `pwm.rs` asserts at compile time that
  the gate's domain matches the driver. Gating the SiFive-layout driver with
  the hardware shape would have let a holder of a free channel rewrite the
  control register the motor channels share.

- scheduler: an idle hart with an empty run queue now re-arms its timer for
  the nearest real deadline (the tickless path) from both "nothing to pick"
  returns of `do_schedule`; before, only the self-pick path did, which an
  idle hart never takes, so the timer ISR's periodic clamp stood on every
  tick. Idle wakeups on a single hart: 74/s → 9/s (three 30 s windows each).

- virtio-net: the header length now follows the negotiated transport
  (10 bytes on the legacy MMIO transport, 12 bytes once `VIRTIO_F_VERSION_1`
  is negotiated on a modern one, per virtio 1.2 §5.1.6.1). With the modern
  transport the fixed 10-byte header shifted every frame by two bytes:
  DHCP DISCOVER was sent, no OFFER was ever parsed. The gate's aarch64
  network rows are the only ones that boot the modern transport.

### Fixed — test tooling and fixtures, 2026-09-26

- `build/disk-linkkey.img` now also writes the link key into reserved tail
  sector 0, where the kernel reads it since the key left the exported
  volume; the FAT copy remains for the host-side peer tools.
- `tools/fake_brain.py --wrap` sends its unwrapped probe as one read's whole
  answer; sent back to back with the first wrapped command, the client's
  refusal of the read discarded that command with it.
- Gate rows updated to the landed decisions: reflex expectations follow the
  daemon's own 30 % through the move syscall; the gate-skip half asserts the
  autorun refusal; the operator-release rows wait for the release phase;
  the symbol canary reads `nm` output from a file; the tickless row's `sed`
  is BSD-safe; the aarch64 PCI row runs after the secure-boot block.

### Documentation, 2026-09-26

- **One safety coding standard (SC-1..SC-10).** An earlier, differently
  numbered draft is retired (its SC-4 was "no `unwrap()`/`expect()`"; the
  surviving standard's SC-4 is "no recursion"). No `// SAFETY-EXEMPT(SC-N)`
  comment exists anywhere in the tree (`grep -rn "SAFETY-EXEMPT" crates
  kernel` → 0), so nothing in the code needs renumbering.
- The mdBook skeleton is retired. `README.md` is the sole public description.

## [0.1.0-pre] — early snapshot (2026-05-14)

An early snapshot, not a stable release. Nothing here is a compatibility
promise: `crates/abi` is **not** stable and changes with the design (the ABI
has no users outside this tree). Verified under QEMU only (single CPU, 4-CPU
SMP, virtio disk, network forwarding).

Earlier revisions of this file called this snapshot `1.0.0` and described the
ABI as frozen. Neither was true: there is no tagged release, and the ABI has
been changed since.

## [0.1.0-pre.0] — first snapshot (2026-05-14)

The first snapshot of AzOS. The capability, ABI and topology foundations are
in place; the scheduler is feature-complete modulo a few migration items.
`crates/abi` is the shared ABI crate — see `crates/core/abi/CHANGELOG.md` for its
public-surface diff.

### Added — kernel

- `crates/abi` — the ABI crate (RFC-0008). Single source of truth
  for syscall numbers, errno, `#[repr(C)]` types, `CapHandle` wire
  format.
- `crates/ipc/src/cap.rs` — `Cap<T>` typed capability wrapper +
  per-task `CapTable` (RFC-0003). 7 unit tests, 3 Kani harnesses
  (under `#[cfg(kani)]`).
- `crates/ipc/src/cap_store.rs` — per-tid `[SpinLock<CapTable>; 64]`
  for kernel-side cap-table lookups.
- `crates/topology/` — alloc-free RFC-0005 TOML subset parser +
  signed CAPS.TOML / SCHED.TOML loader. `default_minimal()` builder
  for QEMU / dev boots.
- `crates/sched/src/class.rs` — `SchedClass` enum (5 RFC-0004
  classes) + `ClassBudget` with `AtomicU32` bookkeeping.
- `crates/sched/src/policies/` — 5 scheduling policies under common
  `Policy` trait: FIFO, EDF + CBS, RoundRobin, CFS, Sporadic.
- `crates/sched/src/partitions.rs` — Adaptive Partitioning Scheduler
  combinator. Three-phase pick (under-min → non-exhausted →
  degraded). Multi-window catch-up.
- `crates/sched/src/aps_state.rs` — per-CPU APS state + enqueue /
  pick / account helpers.
- `crates/sched/src/scheduler.rs` — extended `Task` struct with
  `sched_class_raw`, `sched_deadline_us`, `sched_time_slice_us`.
  New entry points `task_create_with_class`, `task_set_class`.
  Dispatch core branches on `SCHED_USE_APS` atomic flag (default
  false; legacy path drives boot, APS bookkeeping stays warm).
- `kernel/src/main.rs` — `topology::init(default_minimal())` wired
  before `sched::init()`. Boot-time `[APS] smoke OK` print
  confirms the APS path end-to-end.
- `SYS_CHAN_WRITE_TYPED` (528), `SYS_CHAN_READ_TYPED` (529) — first
  cap-typed syscalls. Errno discipline preserves cap-deref failure
  modes (`ECAPSTALE` / `ECAPKIND` / `ECAPPERMS`) end-to-end.

### Added — verification

- `formal/tla/cap_table.tla` — capability-table forgery resistance
  spec (4 invariants, 289 states TLC-verified).
- `formal/tla/topology_load.tla` — boot state-machine spec
  (`SpawnImpliesLoaded`, 55 states verified).
- `formal/tla/sched_aps.tla` — Adaptive Partitioning Scheduler
  invariants (3 invariants, 13,589 states verified).
- A system invariant ledger.

### Added — docs & process

- 16 design RFCs (RFC-0001 through RFC-0018).
- Architecture and test-strategy design notes.
- An mdBook skeleton with chapters for capability IPC, scheduler,
  topology, brain overview, brain protocol (since retired).
- `CONTRIBUTING.md` — DCO + RFC + ADR + style.
- `README.md` rewritten with AZOS branding.

### Added — testing

- 4 host test crates excluded from the workspace
  (`crates/{abi-tests, cap-tests, topology-tests,
  sched-policy-tests}/`).
- Total real tests passing: 1341 (103 regression + 58 ota + 24
  topology + 18 abi + 7 cap + 44 sched-policy + 1087 brain pytest).

### Fixed

- **`crates/ipc/src/cap.rs::CapTable::revoke`** — generation was
  reset on revoke, allowing forgery collision after slot reuse.
  Now `revoke` preserves generation and only clears kind / perms /
  resource. Discovered by `cap-tests::generation_bump_after_reuse`
  on first real run; fixed before this snapshot.
- **`crates/sched/src/partitions.rs::Aps::tick`** —
  multi-window catch-up bug. A delayed first tick at boot would
  reset budgets on every subsequent tick until the start caught up.
  Now advances `(elapsed / window)` windows in one step.

## Design foundation (2026-05-10)

Initial design RFCs. No code changes.
