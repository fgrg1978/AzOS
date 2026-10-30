# AzOS

**A capability-based hybrid kernel in Rust for RISC-V, ARM64 and x86-64.**

> **No irreversible effect occurs outside an envelope verified outside the
> model, without an explicit capability, and without a record.**

General-purpose operating systems decide *who you are*. AzOS also decides
*what you may cause*: moving a motor, erasing a disk, flashing firmware,
opening a network link. The kernel mediates each of these through a typed
capability, checks it against a signed topology and writes a durable record of
the decision. The target is machines where an effect cannot be undone: robots,
industrial controllers, vehicles, gateways and connected devices. The same
tree also builds desktop and server configurations.

## Status

**Early development. Not for production use.**

## What is in the tree

- **Typed handles.** A task acts through handles it holds. A handle names an
  object of one of eight kinds (endpoint, memory object, queue, port, domain,
  node, device, log) and carries rights. Handles derive from a warrant tree: a
  derived handle can be narrowed, given an expiry and a quota, and revoking a
  handle revokes what was derived from it. Refusals, derivations and
  revocations are written as decision records that name the rule.
  Source: `crates/core/abi/src/cap.rs`, `crates/core/ipc/src/cap.rs`,
  `crates/core/decision/src/lib.rs`.
- **Scheduling classes.** Dispatch classes run in a fixed order: stop,
  deadline (EDF with CBS reservations), real-time band (fixed priority), fair
  (EEVDF) and idle. A deadline reservation is admitted against the CPUs the
  machine has, and a set that does not fit is refused. An interrupt line can
  be bound to a handler that runs on its own reservation (Kconfig
  `IRQ_THREADED`). Source: `crates/core/sched/src/sc.rs`,
  `config/kernel/Kconfig.sched`.
- **A small native ABI.** 33 system calls, plus `SYS_INVOKE(handle, op,
  words)` for operations on an object a task holds a handle to. Devices and
  services are interfaces declared as Rust traits in an IDL
  (`#[azos_interface]`) and called through endpoints; the kernel hosts some
  interfaces itself. Source: `crates/core/abi/src/syscall_nr.rs`,
  `crates/core/idl`, `crates/core/devif`.
- **Hybrid placement.** The scheduler, memory manager, IPC, file systems,
  network stack and the drivers a safety decision reads live in the kernel
  image. Other drivers and services run in ring 3. A topology row can mark a
  stateless driver as movable between the two behind the same endpoint; each
  move is a decision record. Source: `crates/core/topology/src/placement.rs`,
  `kernel/src/drv_supervisor.rs`.
- **Signed configuration.** The device configuration (`CONFIG.INI`), the
  capability topology (`CAPS.TOM`) and application packages are verified with
  Ed25519. The first two are bound to the device id and checked against a
  counter floor; a package is signed by its author and admitted only against
  signers the topology names. Every ring-3 program runs under a system-call
  filter chosen by the SHA-256 of its ELF. Source: `crates/core/topology`,
  `crates/core/pkg`, `crates/core/sched/src/seccomp.rs`,
  `userspace/image_hashes.py`.
- **Memory.** Kernel and user mappings are W^X. Physical memory is a buddy
  allocator over a per-frame descriptor table with per-CPU caches. A memory
  object that is moved over IPC leaves the sender's address space. Drivers
  map DMA buffers through a DMA domain, backed by an IOMMU where the platform
  has one. Source: `crates/core/mm`, `crates/core/ipc/src/memobj.rs`,
  `crates/drivers/dma`, `crates/drivers/iommu`.
- **Records and recovery.** A flight recorder on the FAT32 volume keeps safety
  records across resets, the panic path writes `CRASH.LOG`, and a recovery
  console runs on the UART when ring 3 cannot start. A service endpoint can be
  handed to a successor without losing queued callers. Source:
  `crates/core/actuation/src/logger.rs`, `crates/fs/src/crash_log.rs`,
  `crates/core/recovery`.
- **Introspection without system calls.** The kernel publishes a tree of typed
  values (scheduler, memory, decision counters) into a memory object that
  holders map read-only. Source: `crates/core/inspect`,
  `kernel/src/boot/inspect.rs`.

## One tree, three ISAs

The same source builds for **riscv64, aarch64 and x86_64** behind one
architecture API (`arch/api`). Each ISA has a compile-time
baseline level, and every optional extension above it is a three-way
`make config` choice (`n`, `probe`, `require`) resolved at boot. Source:
`config/arch/Kconfig.isa`, `arch/api/src/isa.rs`.

`make config` starts from a preset, and the preset sets the defaults of the
other axes (hardware class, real-time mode, driver placement, security
posture):

| Family | Presets |
|---|---|
| General | Generic |
| Embedded control | Robot, Industrial, Automotive, Firmware |
| Connected devices | IoT / HMI, Wearable, Gateway |
| Computers | Desktop, Server |

Kconfig is the single source of configuration. Source: `Kconfig`,
`config/axes/Kconfig.preset`.

## Programming interfaces

- **Native SDK.** A Rust `std` target for AzOS that maps onto handles, ports
  and rings, not onto POSIX. See [`sdk/README.md`](sdk/README.md).
- **C programs.** A port of relibc to the native ABI (`posix_spawn`, no
  `fork`). See
  [`userspace/lib/relibc-azos/README.md`](userspace/lib/relibc-azos/README.md).
- **Linux binaries.** An optional personality (Kconfig `LINUX_ABI`, off by
  default) runs static Linux binaries of a topology row marked `abi = "linux"`,
  with no hardware capability. It is translated in the kernel or, with
  `LINUX_RUNTIME`, hosted by a ring-3 runtime.
- **Between nodes.** `userspace/services/rpcsrv` exports endpoints to a peer
  node under per-session warrants. Interfaces declare delivery semantics per
  operation (`#[idempotent]`, `#[at_most_once]`, `#[once_only]`).

## Build and run

Host: macOS or Linux, the nightly Rust toolchain pinned by
`rust-toolchain.toml`, Python 3 with `kconfiglib`, and QEMU.

```bash
make defconfig     # two questions, the ISA and the domain (or make config to pick every option)
make build         # build what .config selects: kernel, images, system volume
make qemu          # boot what make build built, with its system volume
make sdk           # the Rust std target for AzOS, on the three ISAs
make check0        # cargo check per ISA + the host suites the diff reaches
make ci            # the full gate: builds, host suites and QEMU scenarios
make help          # every target
```

`make build` prints where the kernel, the system volume and the SDK target are.
Work in a checkout outside a synced folder: in a path with spaces (iCloud
Drive's "Mobile Documents") make runs `config`, `defconfig-*` and `help` only
and refuses every goal that builds or runs. Every output (kernels, images, ELFs, cargo target directories) goes to
`$AZOS_OUT`, by default `~/azos-out/<checkout name>-<hash>`
(`python3 tools/lib/out_dir.py` prints it), never into the checkout. To run a bare
`cargo`, export `AZOS_OUT` and point `CARGO_TARGET_DIR` under it. The Makefile
is split by concern under `mk/` (`vars.mk`, `userspace.mk`, `images.mk`,
`system.mk`, `kernel.mk`, `host.mk`, `qemu.mk`, `lints.mk`).

## Layout

```
kernel/      composition root: kernel_main, boot steps, trap entry and
             boot hooks per ISA (kernel/src/entry/<isa>), kernel tasks
arch/        the ISA crates: api, facade, riscv64, aarch64, x86_64 (each
             with its kernel linker scripts in boot/)
crates/      core (abi, sched, mm, ipc, syscall, topology, idl, ...),
             drivers (one crate per class; lx/, the glue for running Linux
             driver modules in ring-3 servers), fs, net, lib (control math),
             domains (use-specific crates: robot)
userspace/   ring-3 services, drivers, libraries (relibc port, names, rpc, ...),
             tests and benchmark programs
sdk/         the std target for AzOS and its own test program
micro/       AzOS-micro, a separate kernel for parts without an MMU
config/      Kconfig fragments and defconfigs
mk/          the Makefile, split by concern
tools/       build, check, signing, packaging and analysis tools
tests/       host test crates, fuzz targets, QEMU smoke test
formal/      TLA+ models
boot/        U-Boot boot script source
third_party/ vendored crates and pinned external trees
```

## Documentation

[`Documentation/README.md`](Documentation/README.md) is the index of the
reference documentation. [`ARCHITECTURE.md`](ARCHITECTURE.md) is the overview
of how the pieces fit, and [`ROADMAP.md`](ROADMAP.md) states the direction of
the work. Change history starts at [`CHANGELOG.md`](CHANGELOG.md); the ABI
crate keeps its own in
[`crates/core/abi/CHANGELOG.md`](crates/core/abi/CHANGELOG.md).

## Isolation

A ring-3 program holds only the capabilities its signed topology row grants. It
runs under a system-call filter bound to its image digest and inherits nothing
else from its creator. The native ABI has no uid, root or setuid, so a
compromised program has no privileged identity to escalate to.
[`Documentation/security.md`, Isolation model](Documentation/security.md#isolation-model)
states what this boundary covers, how it compares with a Linux system, and its
current limits.

## License, contributing and security

Dual-licensed under `Apache-2.0 OR GPL-2.0-only`, at your option: see
[`LICENSE`](LICENSE) and [`LICENSES/`](LICENSES). Contributions are accepted
under [`CLA.md`](CLA.md); see [`CONTRIBUTING.md`](CONTRIBUTING.md). To report
a vulnerability, see [`SECURITY.md`](SECURITY.md).
