# AzOS — Changelog

All notable changes to the AzOS kernel and tooling (named KernOS until 2026-10-04).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is SemVer. Per-crate changelogs live next to each crate
(currently only `crates/core/abi/CHANGELOG.md`).

## [Unreleased]

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
  `azos_ml` is linked only by the opt-in `ml-kill-smoke` and
  `mlsf-bench` features.
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
