# AzOS

*Az* is the family name of the author's projects (AzPhone, AzWatch, AzBike,
AzCar, ...); *OS*, operating system.

AzOS is an operating system on a general-purpose hybrid kernel in Rust
(`no_std`) for riscv64 and aarch64, built around one guarantee:

> **No irreversible effect occurs outside an envelope verified outside the
> model, without an explicit capability, and without a record.**

## What it is

AzOS keeps most subsystems (scheduler, memory manager, IPC, file systems,
network stack, drivers) in one kernel image and moves work out to ring 3
only where the isolation pays for itself. Tasks talk through capability-typed
IPC: every handle names the kind of object it grants and the rights it
carries, and the kernel checks both on each call. A driver that no safety
decision reads can be placed in the kernel or in a ring-3 server, chosen per
driver at build time; a driver that a safety decision reads stays in the
kernel.

## Architecture and scope

[`ARCHITECTURE.md`](ARCHITECTURE.md) describes the layers, boot, scheduling,
memory, IPC and capabilities, system-call filters, drivers, storage, network,
safety records and configuration, and states the scope. In short: AzOS is a
kernel for devices whose irreversible effects must pass a kernel-held
authority. It is not a POSIX or Linux replacement (the Linux personality is
optional), has no desktop or GUI, and is not certified.

## One kernel, several deployment profiles

The same tree builds images for different jobs. The application domain is a
build-time choice (`make config`): generic (the default), IoT / HMI (display,
camera, battery monitoring), gateway / edge (many mostly idle network links),
industrial (timing and fault-containment defaults), drivers as ring-3
servers, and robotics. A domain changes which crates are linked and the
starting value of other options, each of which can still be set by hand.
Independently, a
resource profile sizes the static tables: embedded (16–64 MiB boards), edge
(single-board computers) or fleet (gateways aggregating many devices).

Robotics is one example profile, and the least-used one. Only the robot
domain links the motor control loop, the robot safety envelope and the
planner link (the host-side planner is a separate repository,
`AzOSRobotBrain`). Every domain links the shared actuation authority: the
e-stop latch, the signed operator release, the flight recorder and the system
watchdog.

## What sets it apart

- **System-call filters bound to the program image.** Each shipped ring-3
  program has a filter keyed by the SHA-256 of its ELF. The kernel installs it
  at spawn and refuses an image whose digest it does not know. A task cannot
  remove or replace its own filter; `exec` installs the new image's filter.
- **Signed device configuration.** `CONFIG.INI` is accepted only with an
  Ed25519 signature (`CONFIG.SIG`) that names this device and carries a
  counter no lower than the last one accepted, so a configuration for another
  device, or an older one, is not taken; anything else falls back to factory
  defaults.
- **Signed capability topology.** The topology every ring-3 task's
  capabilities, class, priority and memory budget come from is read from the
  volume (`CAPS.TOM`, `SCHED.TOM`) when one Ed25519 signature over
  `CAPS.TOM` verifies under the embedded key and `CAPS.TOM` names this
  device, a counter no lower than the last one accepted, and the SHA-256 of
  `SCHED.TOM`; the set must also parse and pass the boot's admission.
  Otherwise the topology built into the image is used, with a warning and a
  flight-recorder record. A build option makes the signed topology required.
  `make topo-volume` writes the built-in topology onto an image that way.
- **Hardware authority is a capability.** GPIO, PWM, I2C, sensors, power and
  motors are reached through capability-typed calls; the untyped hardware
  calls are retired, except two that have no typed form. A deployment without
  the actuation profile grants no motor capability at all.
- **W^X for kernel and user memory.** The kernel image is mapped W^X and, once
  paging is on, no RAM outside the image is executable. In user space,
  copy-on-write never produces a writable copy of an executable page,
  `mprotect` refuses write on an executable mapping and refuses `PROT_EXEC`,
  and program text frames are shared read-execute between tasks that run the
  same image.
- **Durable safety records.** Safety events go to an on-disk flight recorder
  that continues its numbering across reboots instead of overwriting the
  previous session, and the e-stop latch is read back from it at boot. Panics
  append to `CRASH.LOG`, which rotates to `CRASH.OLD` at 64 KiB.
- **Real-time bands with admission.** Deadline rows in the topology are
  admitted at boot against the CPUs the board really has, and the real-time
  band is capped per CPU (`RT_BAND_CAP_PCT`); reservations made after boot go
  through the same limit. A set that does not fit halts the boot instead of
  missing deadlines later.
- **Compile-time log levels.** `LOG_LEVEL` (err / warn / info / debug) removes
  the lines below the chosen level from the image; the durable records and
  the panic report are not affected.
- **Small images per profile.** The embedded profile links against a fixed
  image budget, checked by the linker script, for boards with 16–64 MiB.
- **Optional Linux personality.** With `LINUX_ABI` (off by default) a static
  Linux binary runs unmodified, its calls translated onto the native ones,
  under its own system-call filter and with no hardware capability.

## Performance

Measured with the same-QEMU harness (`userspace/bench/vsbench`,
`tools/vsbench_compare.sh`) on riscv64 under `-icount`, which counts guest
instructions per operation, not hardware time, from one run per path. On 15
of 16 compared paths AzOS is ahead of Linux or at parity: it executes from
about 18% fewer instructions per operation (system call) to about 80% fewer
(IPC round trip), with process spawn about 40% and memory map about 70%
fewer, while file I/O and UDP are within about 3%. Context switching under
load is about 40% behind. No hardware has been measured.

## Status

**Early development. Not for production use, and not for safety-critical
deployments.** It runs under QEMU (`virt` on both ISAs). Bring-up on real
boards (StarFive VisionFive 2, SpacemiT K1) has not been done, so nothing here
has been measured or verified on hardware. No certification has been sought
or obtained. The proof harnesses in `formal/` are scaffolding, not claims.

## Build and run

Host: macOS or Linux, the nightly Rust toolchain with `rust-src`, Python 3
with `kconfiglib`, and QEMU.

```bash
make build/image_hashes.rs   # ring-3 programs and the SHA-256 table the filters bind to
make build                   # riscv64 kernel for QEMU virt
make qemu                    # boot it (make qemu-smp: 4 CPUs)
make aarch64                 # aarch64 kernel (make qemu-aarch64 boots it)
make config                  # choose domain, profile and options
make ci                      # every build, the host suites, the QEMU scenarios
```

`make ci` runs `tools/ci_check.sh`; it is run by hand, there is no hosted CI.

## Layout

```
kernel/      composition root: boot, trap entry, SMP bring-up
crates/      kernel subsystems: core (ipc, sched, mm, syscall, topology, ...),
             drivers, fs, net
domains/     domain-specific crates (robot)
userspace/   the ring-3 programs and tests the kernel boots
config/      Kconfig tree and defconfigs
tools/       the check script, benchmark and analysis tools
```

## License, contributing and security

Dual-licensed, `Apache-2.0 OR GPL-2.0-only` at your option: see
[`LICENSE`](LICENSE) and [`LICENSES/`](LICENSES). Contributions go under
[`CLA.md`](CLA.md); see [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a
vulnerability, see [`SECURITY.md`](SECURITY.md).
