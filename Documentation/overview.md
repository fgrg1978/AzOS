# AzOS overview

AzOS is a hybrid kernel written in Rust (`no_std`) for three instruction sets:
riscv64, aarch64 and x86_64. Its access control is built on capabilities: a task
can do only what a typed, unforgeable handle in its own table lets it do, and a
handle can be narrowed, passed on and revoked. This page says what the system
is and lists the design principles that the code in this tree shows. Each
section ends with a `Source` line naming the files to read.

Contents: [What it is](#what-it-is) | [Authority by capability](#authority-by-capability) |
[Syscalls for authority and sleep](#syscalls-only-for-authority-and-sleep) |
[Irreversible effects](#every-irreversible-effect-is-authorised-bounded-and-recorded) |
[Service placement](#service-placement-kernel-or-ring-3) |
[Kconfig](#kconfig-is-the-single-source-of-configuration) |
[One source, three ISAs](#one-source-three-isas) | [Scope](#scope-and-non-goals)

## What it is

"Hybrid" means the kernel image holds the scheduler, the memory manager, IPC and
capabilities, the system-call layer, the file systems, the network stack and
the drivers that safety decisions read. Programs, services and drivers that can
be isolated run as ring-3 tasks (U-mode on riscv64, EL0 on aarch64, ring 3 on
x86_64). A driver written once can be hosted in either place (see
[service placement](#service-placement-kernel-or-ring-3)).

| Property | Where it shows in the tree |
|---|---|
| One kernel image, `kernel_main` | `kernel/src/main.rs` |
| Kernel targets | `riscv64imac-unknown-none-elf`, `aarch64-unknown-none-softfloat`, `x86_64-unknown-none` (`mk/vars.mk`) |
| Ring-3 programs | `userspace/`; Rust `std` targets `*-unknown-azos` in `sdk/targets/` |
| Second, separate kernel for MMU-less parts | `micro/` (riscv32imac, M-mode, PMP) |
| Application domains are optional features | `config/Kconfig.use`, `domains/robot/` |

AzOS is a general-purpose kernel with application domains on top. The `robot`
domain (`domains/robot/`) is linked only when the image selects it
(`USE_ROBOT` in `config/Kconfig.use`, kernel feature `use-robot`); the shared
actuation authority (`crates/core/actuation`) is linked by every domain.

Source: `kernel/src/main.rs`, `kernel/Cargo.toml`, `config/Kconfig.use`,
`micro/src/lib.rs`, `sdk/README.md`.
Next: [structure.md](structure.md) for the directory map.

## Authority by capability

There is no ambient root. A task reaches an object only through a handle in
its own capability table.

- **Handle format.** A handle is a `u32`: a 6-bit type tag (4-bit kind plus
  2-bit class), 6 permission bits, an 11-bit generation and a 9-bit slot index.
  A slot is retired when its generation reaches the maximum, never wrapped, so
  a stale handle is refused (`-ECAPSTALE`).
- **Kinds.** `CapKind` has eight kinds plus `Null`: `Endpoint`, `MemObj`, `Queue`, `Port`,
  `Domain`, `Node`, `Device`, `Log`.
- **Rights.** `CapPerms` has six bits: `READ`, `WRITE`, `EXEC`, `DUP`,
  `TRANSFER`, `MAP`. Copying a handle needs `DUP`; giving it to another domain
  also needs `TRANSFER`.
- **Derive and revoke.** `SYS_CAP_DERIVE` makes a narrower child handle;
  `SYS_CAP_REVOKE` revokes every capability derived from a held handle, in this
  task and in any task it was lent or moved to, and returns a replacement
  handle for the held one.
- **Devices are not capability kinds.** A pin, a bus address, a wheel pair or a
  partition is the badge of an `Endpoint` capability. The rights are the op
  classes of the interface behind it (`READ` observes, `WRITE` acts, `EXEC`
  controls). The kernel serves the interface itself for a driver it hosts; a
  ring-3 driver serves the same trait from its own endpoint, and the client
  stub does not know which (`crates/core/devif`).
- **Where capabilities come from.** At boot the kernel loads a signed topology
  (`CAPS.TOM` with its `CAPS.SIG`, plus `SCHED.TOM`, which the signed file binds
  by SHA-256). Every task spawned afterwards takes its capability table and
  scheduling class from that structure. The signature (Ed25519) is over the raw
  file bytes. The topology is immutable once installed
  (`crates/core/topology`).
- **Per-image filters.** A task's syscall filter is a bitmap plus a word naming
  the device interfaces it may call. It can be installed once and never
  removed or replaced. At exec the kernel takes the profile from
  `IMAGE_PROFILES`, which is bound to the SHA-256 of the exact ELF the build
  put on the image (`crates/core/sched/src/seccomp.rs`,
  `userspace/image_hashes.py`).

Source: `crates/core/abi/src/cap.rs`, `crates/core/devif/src/lib.rs`,
`crates/core/topology/src/lib.rs`, `crates/core/topology/src/verify.rs`,
`crates/core/sched/src/seccomp.rs`.
Next: [capabilities.md](capabilities.md), [security.md](security.md).

## Syscalls only for authority and sleep

The native table has 33 calls, numbered densely from 1
(`crates/core/abi/src/syscall_nr.rs`). Everything else is an op of one generic
call, `SYS_INVOKE`, selected by the type of the handle it is invoked on. A call
that merely moves data does not need the kernel at all.

| Family | Calls |
|---|---|
| Handles | `SYS_CAP_INFO`, `SYS_CAP_CLOSE`, `SYS_CAP_DERIVE`, `SYS_CAP_REVOKE` |
| Domain and threads | `SYS_SPAWN_EX`, `SYS_THREAD_CREATE`, `SYS_THREAD_EXIT`, `SYS_EXIT`, `SYS_ALERT`, `SYS_GETPID` |
| Time and scheduling | `SYS_YIELD`, `SYS_SLEEP_UNTIL`, `SYS_SCHEDCTL` |
| Memory objects | `SYS_MO_CREATE`, `SYS_MO_MAP`, `SYS_MO_UNMAP` |
| IPC | `SYS_IPC_FAST_CALL_EP`, `SYS_IPC_FAST_REPLY`, `SYS_IPC_FAST_ACCEPT`, `SYS_IPC_FAST_REPLY_ACCEPT`, `SYS_IPC_CALL_V2`, `SYS_IPC_ACCEPT_V2`, `SYS_IPC_REPLY_V2`, `SYS_IPC_REPLY_DELEGATE` |
| Rings and ports | `SYS_RING_SETUP`, `SYS_RING_ENTER`, `SYS_PORT_WAIT` |
| Futex | `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE` |
| Foreign ABI | `SYS_FOREIGN_ENTRY`, `SYS_FOREIGN_RESUME`, `SYS_FOREIGN_FORK` |
| Generic | `SYS_INVOKE` |

`SYS_INVOKE(handle, op, w0..w3)` takes the op number in the namespace of the
handle's type. The op number encodes the kind (bits 12..16), the class (bits
8..12) and an index (bits 0..8). The classes (`CLASS_READ`, `CLASS_WRITE`,
`CLASS_WAIT`, `CLASS_CTL`, `CLASS_ADMIN`, `CLASS_NET`, `CLASS_MODULE`,
`CLASS_DRIVER` and others in `crates/core/abi/src/invoke.rs`) are the unit that
an image profile grants. A
handle is the only address in the call: no path, task id or integer file
descriptor.

Data moves without a trap:

- **Shared rings.** `crates/core/rings` provides `Queue` (single producer,
  single consumer, backpressured), `Log` (one writer, overwrite-oldest, any
  number of readers with private cursors; `Log<T, 1>` is a latest-value cell)
  and the `region` forms two address spaces map. One writer or one consumer is
  a property of the type: a second handle cannot be made. The doorbell rings
  only when the other side announced it may be asleep. The io_ring page has one
  layout for both sides (`crates/core/abi/src/io_ring.rs`).
- **Read-only pages.** The vDSO is one read-only page mapped at a fixed
  address (`VDSO_USER_BASE`); the kernel writes timing data under a seqlock and
  ring 3 reads it without a trap (`crates/core/mm/src/vdso.rs`). The
  introspection tree (`crates/core/inspect`) is a region the kernel alone
  writes; a reader maps it read-only and walks it with loads. The public and
  the admin regions share no byte.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/abi/src/invoke.rs`,
`crates/core/abi/src/io_ring.rs`, `crates/core/rings/src/lib.rs`,
`crates/core/mm/src/vdso.rs`, `crates/core/inspect/src/lib.rs`.
Next: [abi.md](abi.md), [ipc.md](ipc.md), [observability.md](observability.md).

## Every irreversible effect is authorised, bounded and recorded

An effect that cannot be undone (driving an actuator, erasing storage,
installing a package) passes through code in the kernel that checks the
capability, applies a limit and writes a record.

- **Authority.** `crates/core/actuation` is the authority over irreversible
  effects that every domain with an actuator shares: the emergency-stop latch
  with its signed release (`estop`), the one latch-and-stop sequence
  (`gate`), the flight recorder (`logger`), the boot-time latch replay, the GPIO
  kill switch and the system watchdog.
- **Write-ahead receipts.** With the `effect-gate` feature (Kconfig
  `EFFECT_WRITE_AHEAD`), `effect_gate::issue` takes the device op as a closure
  and runs it itself, so the record is committed before the op is issued; there
  is no call that issues without committing. A ring at its limit refuses a
  reversible effect with a receipt. An effect that moves a device toward its
  safe state is never refused, and its record uses a reserve.
- **Deadlines and safe state.** `safe_state` admits an effect with a declared
  deadline against the device's placement latency, watches it, and drives a
  device that missed it to its declared safe state. The device stays held until
  `safe_state::release`, with the operator's signed warrant.
- **Decision records.** `crates/core/decision` writes one `Record` per
  admission, placement or refusal: the rule that decided, the verdict, the
  subject, up to three numbers compared and the alternative the rule rejected.
  The kernel renders the ring at `/proc/decisions`. With the `durable` feature
  every refusal is also handed to the flight recorder, which survives a reset.
- **Domain code plugs in, it does not own the gate.** Robot-specific parts
  (the motor gate and its envelope, the control loop, flight) live in
  `domains/robot` and register through `hooks`; `azos_actuation` depends on no
  domain crate.

Source: `crates/core/actuation/src/lib.rs`, `crates/core/actuation/src/effect_gate.rs`,
`crates/core/actuation/src/safe_state.rs`, `crates/core/decision/src/lib.rs`,
`domains/robot/safety-core`.
Next: [effects.md](effects.md), [observability.md](observability.md).

## Service placement: kernel or ring 3

Isolation is chosen per component. A component goes to ring 3 when isolation
costs nothing that matters; it stays in the kernel when a safety decision reads
it or when the extra crossings buy no isolation.

- **One source, two hosts.** A chip driver can be written once and hosted twice,
  in the kernel (called directly, no message, no task switch) and in a ring-3
  program that serves the same interface on an endpoint
  (`crates/drivers/buzzer`, `crates/drivers/ina219`, `userspace/drivers/`).
  Their build scripts hash their own `src/` into a marker that both hosts
  carry, and `tools/chip_source_check.py` requires every host binary to carry
  the marker of the source in the tree (`crates/drivers/chip_source.rs`).
- **Placement is a topology row.** `place = "kernel" | "ring3"`,
  `stateless = true` (the driver keeps nothing a restart cannot rebuild) and
  `call_budget_us`. Only a `stateless` row may move at run time. A fault demotes
  a kernel-hosted driver to ring 3. A ring-3 driver whose calls exceed its
  budget is promoted into the kernel if the kernel host's measured cost fits.
  Each move writes a `Rule::Placement` decision record.
- **Ring-3 driver framework.** A ring-3 task registers as the driver for a
  hardware kind with a capability; in-kernel clients reach it through a request
  queue (`crates/drivers/driver_server`). A supervisor restarts a driver that
  dies, up to a burst limit, and records the restart
  (`kernel/src/drv_supervisor.rs`).
- **Services.** The shell, the name server, the package installer, the decision
  server, the terminal server and others are ring-3 programs whose topology row
  is their whole authority (`userspace/services/`).

Source: `crates/core/topology/src/placement.rs`, `crates/drivers/driver_server/src/lib.rs`,
`kernel/src/drv_supervisor.rs`, `crates/drivers/chip_source.rs`.
Next: [drivers.md](drivers.md), [services.md](services.md).

## Kconfig is the single source of configuration

Everything that varies between images is a Kconfig symbol. The root `Kconfig`
sources the fragments in `config/`, and `.config` is generated output.

- **Cargo features come from Kconfig.** `kernel/Cargo.toml` has an empty
  `default` list; each build's features come from the expanded `.config`
  through `tools/kconfig_to_cargo.py`, using `# cargo-feature:` tags in
  `config/Kconfig.*`. `tools/kconfig_lint.py` checks the tags against the
  feature table.
- **Constants come from Kconfig.** `crates/core/limits` generates compile-time
  constants from `.config` with `crates/core/azos-config` in its build script.
- **Presets and axes.** One `PRESET` choice sets the profile axes (hardware
  class, use, structure, real-time class, security, build type, virtualization
  role). A value set by hand wins over the preset; presets never `select`.
  Defconfigs are in `config/defconfigs/`.
- **Userspace programs are generated into the menu.** `tools/gen_userspace_kconfig.py`
  runs at every parse, so a program directory added to `userspace/` shows up at
  the next configuration.
- **Outputs stay out of the checkout.** Build products go under `$AZOS_OUT`
  (`mk/vars.mk`, `tools/out_dir.py`).

Source: `Kconfig`, `config/Kconfig.preset`, `config/Kconfig.use`,
`kernel/Cargo.toml`, `crates/core/azos-config/src/lib.rs`,
`crates/core/limits`, `tools/kconfig_to_cargo.py`, `mk/vars.mk`.
Next: [config.md](config.md), [building.md](building.md).

## One source, three ISAs

The same kernel crate builds for riscv64, aarch64 and x86_64.

- **Contract.** `crates/core/arch-api` defines the trait surface: `Cpu`,
  `Interrupts`, `Mmu`, `Boot`, `Vector`, `SpinWait`, plus `ArchPlatform` and
  `ArchEntry`. Each ISA crate (`arch-riscv64`, `arch-aarch64`, `arch-x86_64`)
  implements it, and `crates/core/arch` re-exports the one that matches
  `target_arch`.
- **One boot sequence.** `kernel_main` calls `boot::early_main`
  (`kernel/src/boot/early.rs`), which owns the common steps and their order
  and calls the hooks of the kernel's `ArchEntry` implementation where the
  ISAs differ. Every early-boot hook is required, with no default, so a new ISA
  cannot leave a step out silently. Hooks are `#[inline(always)]` on a zero-sized type:
  no `dyn`, no table.
- **One trap layer.** `kernel/src/trap/` holds the syscall flow, fault policy
  and interrupt bracket once; each ISA supplies its frame, trap entry asm and
  interrupt controller under `kernel/src/entry/<isa>/`.
- **One layout.** The three ISAs share a file layout, with ISA-only code under
  `ext/`. `tools/arch_layout_lint.py` enforces it. See
  [structure.md](structure.md).
- **One ABI shape.** The syscall numbers are the same on every ISA; only the
  registers differ (`a7`/`a0..a5` on riscv64, `x8`/`x0..x5` on aarch64,
  `rax`/`rdi, rsi, rdx, r10, r8, r9` on x86_64).

Source: `crates/core/arch-api/src/contract.rs`, `crates/core/arch/src/lib.rs`,
`kernel/src/boot/early.rs`, `kernel/src/trap/mod.rs`,
`crates/core/abi/src/syscall_nr.rs`, `tools/arch_layout_lint.py`.
Next: [hal.md](hal.md).

## Scope and non-goals

In scope: a kernel with capability-based authority, real-time scheduling classes,
IPC, file systems, a network stack, a driver framework with two placements, a
signed package and update path, and a Linux-ABI personality for static Linux
binaries. An optional hypervisor core and an optional Linux-driver layer
exist behind Kconfig options ([virtualization.md](virtualization.md),
[linux.md](linux.md)).

What the code does not try to be:

- **Not a POSIX system.** The native SDK has no file descriptor numbers, no
  `errno`, no signals and no POSIX layer; `std` on `*-unknown-azos` maps to
  handles, threads, futexes and the vDSO clock (`sdk/README.md`). A task that
  needs Linux behaviour gets it from the Linux personality, which uses Linux
  numbers translated by `crates/core/linux-abi` or the ring-3 runtime
  `userspace/lib/linux_rt`. Those numbers are not in the native table.
- **Not a desktop system.** Display support is a framebuffer
  (`crates/drivers/fb`); there is no window system in the tree.
- **Not a robot kernel.** The robot domain is one optional use of the kernel
  (`config/Kconfig.use`).
- **Not the planner.** Perception, planning and models live outside the kernel;
  the kernel decides whether a proposed action takes effect.
- **No ambient authority.** No global device namespace and no root user: see
  [authority by capability](#authority-by-capability).

Source: `sdk/README.md`, `config/Kconfig.use`, `crates/core/abi/src/syscall_nr.rs`,
`crates/core/linux-abi/src/lib.rs`, `crates/drivers/fb/src/lib.rs`.
