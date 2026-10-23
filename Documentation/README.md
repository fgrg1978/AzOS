# AzOS documentation

This directory documents the code in this repository. Start with the overview,
then follow the structure page to the part you need. [../ARCHITECTURE.md](../ARCHITECTURE.md)
is a one-file map that links into the pages below.

## Start here

| Document | What it covers |
|---|---|
| [overview.md](overview.md) | What AzOS is and the design principles visible in the code. |
| [structure.md](structure.md) | Every top-level directory and crate, the per-ISA layout, the userspace layout. |

## Core concepts

| Document | What it covers |
|---|---|
| [capabilities.md](capabilities.md) | Handles, kinds, rights, derive, move and revoke; the warrant tree. |
| [effects.md](effects.md) | The authority over irreversible effects: e-stop, effect gate, safe state, records. |
| [abi.md](abi.md) | The native syscall table, `SYS_INVOKE`, register conventions, shared structures. |
| [ipc.md](ipc.md) | Endpoints, the fast call, message descriptors, ports, memory objects, rings. |
| [idl.md](idl.md) | The interface definition language and the stubs it generates. |

## Kernel subsystems

| Document | What it covers |
|---|---|
| [scheduler.md](scheduler.md) | Dispatch classes, EEVDF, EDF with CBS, admission, wake placement, priority donation and the wait graph, balancing, core scheduling, tickless CPUs. |
| [time.md](time.md) | The counter per ISA, timer programming, clocks, the vDSO clock, SNTP and PTP, deadlines. |
| [energy.md](energy.md) | Utilisation tracking, the energy model, governors, idle states, thermal, runtime power, hotplug, suspend, battery. |
| [memory.md](memory.md) | Frames, memory objects, the page cache and mmap, the kernel heap, W^X, reclaim, marker PTEs, TLB invalidation. |
| [storage.md](storage.md) | The VFS, file systems, caches, block devices, the volume format. |
| [network.md](network.md) | The network stack, link layers and ring-3 protocol libraries. |

## Hardware and drivers

| Document | What it covers |
|---|---|
| [hal.md](hal.md) | The arch trait surface, the facade, the ISA extension model, the per-ISA layout and the generic trap layer. |
| [drivers.md](drivers.md) | The driver framework, the two placements, the driver crates. |

## Compatibility, virtualization and updates

| Document | What it covers |
|---|---|
| [linux.md](linux.md) | The Linux ABI personality and the Linux driver layer. |
| [virtualization.md](virtualization.md) | The hypervisor core and the ring-3 monitor. |
| [update.md](update.md) | Whole-system updates, packages and livepatch. |
| [security.md](security.md) | Filters, signatures, memory protections and mitigations. |
| [observability.md](observability.md) | Tracing, introspection, decision records, crash records, in-kernel tests. |

## Building software for AzOS

| Document | What it covers |
|---|---|
| [sdk.md](sdk.md) | The native `std` SDK and its targets. |
| [services.md](services.md) | The ring-3 services and libraries. |
| [config.md](config.md) | Kconfig, presets, defconfigs and the runtime configuration store. |
| [os-feature-matrix.md](os-feature-matrix.md) | Every Kconfig switch and choice with its value in each defconfig; generated. |
| [building.md](building.md) | The build system, outputs, images and checks. |
| [api-reference.md](api-reference.md) | Where each public API is defined. |

## Design notes

Each note describes one mechanism in depth: what it is, the invariants it keeps
and its limits. Authors start from the two templates.

| Document | What it covers |
|---|---|
| [design/TEMPLATE.md](design/TEMPLATE.md) | Template for a design note. |
| [design/TEMPLATE-experiment.md](design/TEMPLATE-experiment.md) | Template for an experiment note. |
| [design/capability-model.md](design/capability-model.md) | The capability model: tables, rights, derivation and revocation. |
| [design/user-shell.md](design/user-shell.md) | The ring-3 shell and how a command gets the authority of its topology row. |
| [design/static-topology.md](design/static-topology.md) | The signed declarative topology: classes, task rows, budgets and grants. |
| [design/supply-chain-tools.md](design/supply-chain-tools.md) | The local tools that answer what the build consumes and whether it repeats. |
| [design/safety-coding-standard.md](design/safety-coding-standard.md) | Rules SC-1 to SC-10 for the safety and control path. |
| [design/energy-aware-scheduling.md](design/energy-aware-scheduling.md) | Wake placement, frequency and idle depth under the energy model. |
| [design/absolute-sleep.md](design/absolute-sleep.md) | `SYS_SLEEP_UNTIL` and drift-free periodic wakeups. |
| [design/trap-and-switch-cost.md](design/trap-and-switch-cost.md) | The cost of traps and address-space switches and how it is kept small. |
| [design/page-size.md](design/page-size.md) | The base page per ISA and the larger-translation mechanisms. |
| [design/arch/aarch64-trap-return-windows.md](design/arch/aarch64-trap-return-windows.md) | Masking interrupts across the aarch64 trap return. |
| [design/forward-secret-link.md](design/forward-secret-link.md) | The forward-secret encrypted brain link. |
| [design/multi-stream-link.md](design/multi-stream-link.md) | Stream framing that lets several streams share the brain link. |
| [design/robot/degrade-levels.md](design/robot/degrade-levels.md) | The four graded degrade levels the brain can select. |
| [design/robot/motor-envelope.md](design/robot/motor-envelope.md) | The gate between a motor command and the PWM hardware. |
| [design/robot/transactional-control-ticks.md](design/robot/transactional-control-ticks.md) | Surviving a recoverable fault inside the control loop. |
| [design/prior-art/linux-bsd.md](design/prior-art/linux-bsd.md) | Prior art: Linux and BSD kernel mechanisms. |
| [design/prior-art/capability-rust-os.md](design/prior-art/capability-rust-os.md) | Prior art: capability, microkernel and Rust operating systems. |
| [design/prior-art/harmony-fuchsia.md](design/prior-art/harmony-fuchsia.md) | Prior art: HongMeng and Fuchsia. |

## Conventions

- Each page names the files it describes in a `Source` line per section. Paths
  are relative to the repository root.
- Pages describe what is in the tree. Where a mechanism is optional, the page
  names the Kconfig symbol or cargo feature that selects it.
- Other documents in the repository: [../ARCHITECTURE.md](../ARCHITECTURE.md),
  [../sdk/README.md](../sdk/README.md), [../CONTRIBUTING.md](../CONTRIBUTING.md),
  [../SECURITY.md](../SECURITY.md).
