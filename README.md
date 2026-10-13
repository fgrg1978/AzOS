# AzOS

**A capability-based hybrid kernel in Rust for RISC-V, ARM64 and x86-64.
Every irreversible effect has an owner, a limit and a receipt.**

> **No irreversible effect occurs outside an envelope verified outside the
> model, without an explicit capability, and without a record.**

General-purpose operating systems decide *who you are*. AzOS also decides
*what you may cause*: moving a motor, erasing a disk, flashing firmware,
opening a network link. Each of these is a typed, attenuable, expiring
capability. The kernel checks it, runs it inside a verified envelope and writes
a durable record with its provenance. AzOS is built for the machines where
that matters: robots, industrial controllers, vehicles, gateways, connected
devices. It scales up to desktops and servers.

*Az* is the family name of the author's projects (AzPhone, AzWatch, AzBike,
AzCar, ...); *OS* stands for operating system.

## Why AzOS

- **Authority you can audit.** The kernel has no ambient root and no global
  namespace of devices. A task holds typed handles (endpoint, memory object,
  queue, port, domain, node, device, log), each with explicit rights. Handles
  derive from a warrant tree: a child warrant can be narrowed, given an expiry
  and a quota, and revoking a warrant revokes its whole subtree. Every grant,
  refusal and revocation leaves a decision record that says *why*.
- **Real time with admission, not hope.** Fair tasks use EEVDF. Deadline tasks
  get CBS reservations that are admitted against the CPUs the board really
  has. Interrupts are scheduled objects with their own budget, so an IRQ storm
  cannot break an admitted deadline. A set that does not fit is refused up
  front instead of missing deadlines later.
- **A small, typed ABI.** About 34 system calls in families, plus
  `invoke(handle, op, message)`. Device and service functions are interfaces
  in a native IDL, called through endpoints with deadlines and clocks on every
  message. Queues and logs carry all I/O: there are no blocking copies on the
  hot path.
- **Hybrid by placement, not by dogma.** The scheduler, memory, IPC, file
  systems, the network stack and the critical drivers live in one kernel
  image. Other drivers and services run in ring 3. Some stateless drivers can
  move between the two at run time behind the same handle: one that faults is
  demoted, and one too slow for its deadline is promoted. Each move is
  admitted and recorded.
- **Signed everything.** The device configuration, the capability topology
  and application packages are Ed25519-signed, bound to the device and
  protected against rollback. A package declares the warrants it needs, and
  installing it is itself a recorded, admitted effect. Each ring-3 program
  carries a system-call filter bound to the SHA-256 of its image.
- **Memory safety in depth.** The kernel is written in Rust. Kernel and user
  memory are W^X. Physical memory uses a buddy allocator with per-CPU caches.
  Memory objects are moved between tasks, not shared by accident: a MOVE drops
  the sender's mapping. Where the hardware has them, DMA goes through IOMMU
  domains.
- **Live update and recovery.** A service can be replaced in place: its
  endpoint queue is handed over to the successor without losing callers. A
  recovery console, a flight recorder that survives reboots, and a panic
  screen keep the machine diagnosable.

## One tree, three ISAs, many devices

The same source builds for **riscv64, aarch64 and x86_64**, with one
architecture API and the same extension model on each ISA. Every feature
lands on all three. `make config` picks a preset, and the preset sets the
defaults for everything else:

| Family | Presets |
|---|---|
| Embedded control | Robot, Industrial, Automotive, Firmware |
| Connected devices | IoT / HMI, Wearable, Gateway |
| Computers | Desktop, Server |

The same menu sets the hardware class (embedded boards with 16–64 MiB up to
servers), the real-time mode (none, soft, hard or mixed), and where drivers
are placed. Kconfig is the single source of configuration. Small boards link
only what their topology names.

A hardware bus discovers devices over PCI/PCIe, Device Tree and virtio. On
safety-critical presets it binds only what the signed topology admits.

## Built for an ecosystem

- **Native SDK:** a Rust `std` target for AzOS that maps straight onto
  handles, ports and rings, not onto POSIX.
- **C programs:** a port of relibc to the native ABI (`posix_spawn`, no
  `fork`).
- **Linux binaries:** an optional Linux personality in ring 3 runs static
  Linux programs under their own filter, with no hardware authority.
- **Distributed by design:** a transparent RPC transport exports endpoints to
  peer nodes, with attenuated, expiring per-peer warrants. Revocation follows
  a broken session. The interfaces declare their delivery semantics:
  idempotent, at most once, or once only.

## Performance

Measured on the same QEMU harness (`userspace/bench/vsbench`,
`tools/vsbench_compare.sh`) on riscv64 under `-icount`. That counts guest
instructions per operation, not hardware time. Against Linux on the same
harness, AzOS executes about 24% fewer instructions per system call and about
80% fewer per IPC round trip. Context switching under load, process spawn and
memory mapping take about 80%, 40% and 70% fewer, and file I/O and UDP are
within about 5%.

## Status

**Early development. Not for production use.**

## Build and run

Host: macOS or Linux, the nightly Rust toolchain with `rust-src`, Python 3
with `kconfiglib`, and QEMU.

```bash
make config        # pick a preset, hardware class and options
make build         # riscv64 kernel for QEMU virt (make qemu boots it)
make aarch64       # aarch64 kernel (make qemu-aarch64)
make x86_64        # x86_64 kernel (make qemu-x86_64)
make sdk           # the Rust std target for AzOS
make check0        # cargo check per ISA + the host suites the diff reaches
make ci            # every build, the host suites and the QEMU scenarios
```

## Layout

```
kernel/      composition root: boot, trap entry, SMP bring-up
crates/      kernel subsystems: core (ipc, sched, mm, syscall, idl, ...),
             drivers, fs, net
domains/     use-specific crates (robot)
userspace/   ring-3 services, libraries (SDK, relibc, IDL clients) and tests
sdk/         the std target for AzOS
config/      Kconfig tree, presets and defconfigs
formal/      proof harnesses
tools/       build, check, signing, packaging and benchmark tools
```

[`ARCHITECTURE.md`](ARCHITECTURE.md) describes the design in depth.
[`ROADMAP.md`](ROADMAP.md) gives the direction of the work ahead.

## License, contributing and security

Dual-licensed under `Apache-2.0 OR GPL-2.0-only`, at your option: see
[`LICENSE`](LICENSE) and [`LICENSES/`](LICENSES). Contributions are accepted
under [`CLA.md`](CLA.md); see [`CONTRIBUTING.md`](CONTRIBUTING.md). To report
a vulnerability, see [`SECURITY.md`](SECURITY.md).
