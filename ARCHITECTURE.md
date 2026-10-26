# AzOS architecture

This file is a map. It says how the parts of AzOS fit together and where each
one lives, and it links to the document in [Documentation/](Documentation/README.md)
that covers the part in depth. It describes the code in this tree; every
section names the paths to read.

## Reading order

1. [Documentation/overview.md](Documentation/overview.md): what AzOS is and the
   design principles the code shows.
2. [Documentation/structure.md](Documentation/structure.md): every directory
   and crate, and the per-ISA layout.
3. The topic documents below, in any order.
4. [Documentation/README.md](Documentation/README.md): the full index.

## The system in one picture

```
 ring 3   programs and services          ring-3 drivers        Linux-ABI tasks
          (userspace/services)           (userspace/drivers)   (optional)
          libsys / std SDK ---------------- syscalls + SYS_INVOKE ----------+
 ---------------------------------------------------------------------------
 kernel   syscall layer (crates/core/syscall) + per-image filters (sched)
          capabilities + IPC (ipc)    scheduler (sched)    memory (mm)
          topology (signed)           actuation authority  decision records
          fs (VFS, FAT32, tmpfs,      net (TCP/IP)         drivers
              azvol)
          [optional] robot domain, hypervisor core, Linux personality
 ---------------------------------------------------------------------------
 arch     arch-api traits  ->  arch-riscv64 | arch-aarch64 | arch-x86_64
 ---------------------------------------------------------------------------
 entry    kernel/src/entry/<isa>: boot asm, trap asm, ArchEntry hooks
```

The kernel image is one program, `kernel_main` in `kernel/src/main.rs`, built
for each ISA from the same sources. Ring 3 is U-mode on riscv64, EL0 on
aarch64 and ring 3 on x86_64.

Source: `kernel/src/main.rs`, `crates/core/arch/src/lib.rs`,
`crates/core/arch-api/src/lib.rs`, `userspace/`.

## Boot path

| Step | What happens | Code |
|---|---|---|
| 1 | The ISA entry asm (`boot.S`) sets up the boot stack and calls `kernel_main` | `kernel/src/entry/<isa>/asm/boot.S`, `kernel/src/main.rs` |
| 2 | `boot::early_main` runs the common early steps in one order for every ISA and calls an `ArchEntry` hook where the ISAs differ | `kernel/src/boot/early.rs`, `crates/core/arch-api/src/contract.rs` |
| 3 | Boot install steps run in order, one module per subsystem | `kernel/src/boot/` |
| 4 | The signed topology is verified, admitted and published; it is immutable afterwards | `kernel/src/boot/topology.rs`, `crates/core/topology` |
| 5 | Secondary CPUs start and the scheduler starts | `kernel/src/entry/<isa>/smp.rs`, `kernel/src/boot/smp.rs`, `crates/core/sched` |
| 6 | Kernel tasks start; the kernel starts the component manager, which starts and supervises the other startable rows of the topology | `kernel/src/tasks/`, `kernel/src/boot/launch.rs`, `userspace/services/compmgr` |

The early-boot hooks of `ArchEntry` run from `pre_console` through
`boot_selftests`, in the order the trait declares them
(`crates/core/arch-api/src/contract.rs`).

Source: `kernel/src/main.rs`, `kernel/src/boot/early.rs`,
`crates/core/arch-api/src/contract.rs`.

## Map by topic

Each section: what the part is, where it lives, and the document to read next.

### Capabilities

A capability is a `u32` handle in a per-task table: type tag, permission bits,
generation, slot. Kinds: `Endpoint`, `MemObj`, `Queue`, `Port`, `Domain`,
`Node`, `Device`, `Log`. Handles are derived (narrowed), moved, shared and
revoked. A topology row is the authority a task starts with.

- Source: `crates/core/abi/src/cap.rs` (wire format), `crates/core/ipc/src/cap.rs`
  and `cap_store.rs` (kernel side), `crates/core/topology`.
- Doc: [capabilities.md](Documentation/capabilities.md).

### Effects

Irreversible effects pass through the actuation authority: an e-stop latch with
a signed release, an effect gate that commits a record before the device op,
safe-state handling for missed deadlines, and a flight recorder. Decision
records say which rule decided and on what numbers.

- Source: `crates/core/actuation`, `crates/core/decision`, `domains/robot/safety-core`.
- Doc: [effects.md](Documentation/effects.md).

### ABI

33 native syscalls, dense from 1, plus `SYS_INVOKE` for every op on a handle.
The register conventions per ISA, error codes, shared structures, the vDSO
address and the io_ring page layout are in one crate that kernel and ring 3
both import.

- Source: `crates/core/abi`, `crates/core/syscall`, `crates/core/libsys`.
- Doc: [abi.md](Documentation/abi.md), [api-reference.md](Documentation/api-reference.md).

### IPC

Calls go to endpoints. The fast path moves a request in registers
(`SYS_IPC_FAST_CALL_EP` and its accept and reply partners); the V2 calls use a
message descriptor. Each endpoint has its own call queue. Memory objects carry
bulk data and `Queue` / `Log` rings carry streams. Ports deliver events, and
`SYS_PORT_WAIT` waits on them.

- Source: `crates/core/ipc` (`endpoint.rs`, `ep_queue.rs`, `fastcall.rs`,
  `memobj.rs`, `port.rs`, `io_ring.rs`), `crates/core/rings`,
  `crates/core/syscall/src/{fastpath,ipc_handlers,ipc_v2}.rs`.
- Doc: [ipc.md](Documentation/ipc.md).

### IDL

Interfaces between components are Rust traits annotated with
`#[azos_interface(id = N, level = L)]`. One op table generates a client stub
(`<Name>Client`), a server dispatcher (`<Name>Idl::dispatch`), a direct-call
stub for the in-kernel placement (`<Name>Direct`) and the caller's trait
(`<Name>Call`), so code that uses an interface does not know where it is
placed. `azos_devif` defines the interfaces of kernel-hosted devices with it.

- Source: `crates/core/idl`, `crates/core/idl-macros`, `crates/core/devif`.
- Doc: [idl.md](Documentation/idl.md).

### Scheduler

The dispatch classes have a fixed precedence `stop > deadline > real-time >
fair > idle` (`azos_sched::sc::Class`). The fair class is EEVDF. The deadline
class is EDF with CBS reservations, admitted against the CPUs available. A
real-time band has its own budget arithmetic. Topology classes
(`SafetyCritical`, `HardRT`, `SoftRT`, `BestEffort`, `Idle`) name budget groups.
`SYS_SCHEDCTL` changes a task's class under a warrant. The arithmetic lives in
`eevdf_core.rs`, `rt_core.rs` and `sc.rs`, which have no kernel state, so host
tests run the same code.

- Source: `crates/core/sched`, `crates/core/sync` (locks, wait queues, priority
  inheritance, QSBR RCU), `crates/core/percpu`.
- Doc: [scheduler.md](Documentation/scheduler.md).

### Time

The ABI speaks nanoseconds; the hardware counter ticks at a board-specific
frequency, and the kernel and ring 3 convert with the same functions
(`ns_to_ticks_ceil` rounds up, so a deadline is never reached early).
`SYS_SLEEP_UNTIL` takes an absolute deadline. The vDSO page lets ring 3 read the
clock without a trap.

- Source: `crates/core/abi/src/time.rs`, `crates/core/mm/src/vdso.rs`,
  `crates/drivers/sys` (timebase and timer programming),
  `crates/core/sched/src/timer_heap.rs`.
- Doc: [time.md](Documentation/time.md).

### Energy

Utilisation tracking per task and per CPU, an energy model with operating
points and idle states, and enum-dispatched seams for placement, frequency
governor and idle governor. The model comes from the signed topology or the
device tree.

- Source: `crates/core/energy`, `userspace/services/power`, `userspace/lib/power`.
- Doc: [energy.md](Documentation/energy.md).

### Memory

A frame descriptor table and a buddy allocator with per-hart caches sit under a
kernel heap with an optional slab front. Page tables and mappings are in
`vmm`, copy-on-write in `cow`, demand paging through pagers in `pager`, a
compressed pool and swap in `zpool` and `swap`. `wx` computes the W^X
boundaries once; `vmm::enforce_wx` applies them and `vmm::verify_wx` checks
them. A per-task frame budget is charged to the task's domain.

- Source: `crates/core/mm`, `kernel/src/boot/{swap,pagecache}.rs`.
- Doc: [memory.md](Documentation/memory.md).

### Storage

A VFS with FAT32 and tmpfs; a block cache and a page cache; a crash
log and a pstore; `azvol`, a native volume format with snapshots and per-block
encryption. Block devices come from VirtIO, SD/eMMC or NVMe drivers and a
partition table parser.

- Source: `crates/fs`, `crates/drivers/block`, `crates/drivers/nvme`,
  `crates/drivers/virtio`, `kernel/src/pstore.rs`, `kernel/src/boot/azvol.rs`.
- Doc: [storage.md](Documentation/storage.md).

### HAL

The arch contract (`Cpu`, `Interrupts`, `Mmu`, `Boot`, `Vector`, `SpinWait`,
`ArchPlatform`, `ArchEntry`) is one trait surface implemented three times.
Below the drivers, the SoC frameworks (clock tree, resets, regulators, pin
control, power domains), the DMA mapping API, the IOMMU interface, PCI
enumeration, the device tree parser and the interrupt-controller selection are
shared crates.

- Source: `crates/core/arch-api`, `crates/core/arch-*`,
  `crates/drivers/{soc,dma,iommu,pci,dtb,irqchip,base}`.
- Doc: [hal.md](Documentation/hal.md).

### Drivers

Drivers are crates under `crates/drivers`; drivers with a runtime presence
register through the `Driver` trait of `azos_drv_api`, and some crates are pure
protocol logic with no registration. A driver can run in the kernel or, when its
source is written for both, in a ring-3 server that serves the same IDL
interface on an endpoint. A topology row picks the host (`place`), and a
`stateless` driver can move between hosts at run time. A supervisor restarts a
ring-3 driver that dies.

- Source: `crates/drivers/*`, `crates/drivers/driver_server`,
  `crates/core/topology/src/placement.rs`, `kernel/src/drv_supervisor.rs`,
  `userspace/drivers/`.
- Doc: [drivers.md](Documentation/drivers.md).

### Linux

Two optional layers. The Linux ABI personality runs static Linux binaries: a
task whose topology row says `abi = "linux"` traps with Linux syscall numbers,
and the kernel translates them to native handlers
(`crates/core/syscall/src/linux.rs`) or a ring-3 runtime does
(`userspace/lib/linux_rt`, `userspace/services/lxrt`). The Linux driver layer
is made of a loader for relocatable Linux driver modules (`lx-loader`), a
ring-3 server (`userspace/services/lxsrv`), a Rust reimplementation of the
kernel APIs such modules call (`lx/emul`) and a small C base module built
against a pinned Linux tree (`lx/glue`).

- Source: `crates/core/linux-abi`, `crates/core/lx-loader`, `lx/`,
  `userspace/services/{lxsrv,lxrt}`, `config/axes/Kconfig.personality`.
- Doc: [linux.md](Documentation/linux.md).

### Network

A polling-based stack: Ethernet, ARP, IPv4 and IPv6, ICMP, UDP, TCP, DHCP,
DNS, NTP, IGMP, NAT, a packet filter and BSD-style sockets. Link-layer pieces:
an encrypted link with handshake and record layer, a stream multiplexer and a
TFTP client. Ring-3 libraries add TLS, QUIC, Zenoh, RPC and MCP.

- Source: `crates/net/*`, `crates/drivers/net`,
  `userspace/lib/{tls,quic,zenoh,rpc,mcp}`,
  `userspace/services/{rpcsrv,rpcquic,zenohd,mcpd,ptpd}`.
- Doc: [network.md](Documentation/network.md).

### Security

Capabilities and the per-image syscall filter bound to the image's SHA-256;
Ed25519-signed topology, configuration and packages; W^X mappings and guard
pages; a hardened ring-3 allocator; speculation mitigations selected by
Kconfig; a TPM driver core; the primitives in `azos_crypto`.

- Source: `crates/core/sched/src/seccomp.rs`, `crates/core/topology/src/verify.rs`,
  `crates/core/crypto`, `crates/core/mm/src/wx.rs`, `crates/drivers/tpm`,
  `userspace/lib/ualloc`, `config/subsys/Kconfig.topology`, `config/axes/Kconfig.security`.
- Doc: [security.md](Documentation/security.md).

### Update

A whole-system update is one signed manifest, one slot, one switch (`ota`):
A/B slot management, a rollback floor (optionally held in a TPM NV index) and
Ed25519 verification. Signed application packages are verified, admitted
against the device's hardware class and ABI, and installed as a recorded
effect. A signed kernel livepatch redirects non-sleeping functions, bounded by
QSBR.

- Source: `crates/core/ota`, `crates/core/pkg`, `userspace/services/{pkgd,pkg}`,
  `kernel/src/boot/{ota,livepatch}.rs`, `crates/core/mm/src/{text_poke,livepatch_fmt}.rs`.
- Doc: [update.md](Documentation/update.md).

### Observability

A per-CPU lock-free event tracer; the introspection tree read from ring 3 with
loads only (the kernel's only read-out: no `/proc`, no `/sys`); decision
records; a panic record in
reserved RAM (pstore) and a crash log on the volume; minidumps of faulted ring-3
tasks; in-kernel tests (`ktest`) and boot smokes.

- Source: `crates/core/{trace,inspect,decision,ktest,chaos}`,
  `crates/fs/src/{crash_log,pstore}.rs`, `kernel/src/{pstore,ktest}.rs`,
  `kernel/src/smokes/`, `userspace/services/{tracectl,why,decisd}`.
- Doc: [observability.md](Documentation/observability.md).

### SDK

A Rust `std` target for each ISA (`riscv64imac-unknown-azos`,
`aarch64-unknown-azos`, `x86_64-unknown-azos`) built with `-Zbuild-std`. There
are no file descriptor numbers, no `errno`, no signals and no POSIX layer: the
port maps `std` to handles, threads, futexes and the vDSO clock. C programs are
ported through a relibc overlay.

- Source: `sdk/`, `crates/core/stdrt`, `crates/core/libsys`, `userspace/lib/relibc-azos`.
- Doc: [sdk.md](Documentation/sdk.md), [sdk/README.md](sdk/README.md).

### Services

Ring-3 programs whose topology row is their whole authority: the component
manager, name server, package installer, decision server, terminal server,
shell and tools, power policy and the protocol gateways. Services reach each
other through endpoints they were wired to, not through a global name space.
The kernel keeps no service table: names are resolved by `namesd` and the
topology rows, and a restarted driver re-claims its endpoints.

- Source: `userspace/services/`, `userspace/lib/`.
- Doc: [services.md](Documentation/services.md).

### Config

Kconfig is the single source. A preset sets the profile axes, `.config` is
expanded into cargo features (`tools/build/kconfig_to_cargo.py`) and constants
(`crates/core/limits`), and a runtime `KEY=VALUE` store (`CONFIG.INI`, under a
signature check at boot) covers what is decided per device.

- Source: `Kconfig`, `config/`, `crates/core/{azos-config,limits,config}`,
  `tools/build/kconfig_*.py`, `kernel/src/boot/config_auth.rs`.
- Doc: [config.md](Documentation/config.md).

### Building

`make` drives everything: configuration targets, kernel builds per ISA,
userspace builds, image creation, QEMU runs, checks and lints. Outputs go to
`$AZOS_OUT`, never into the checkout.

- Source: `Makefile`, `mk/*.mk`, `tools/build/make_help.txt`, `tools/lib/out_dir.py`,
  `tools/gate/ci_check.sh`.
- Doc: [building.md](Documentation/building.md).

### Virtualization

A hypervisor core admits guests declared in the signed topology and owns VM
objects, guest memory and the vCPU loop. It posts device accesses to a ring-3
monitor (`vmmd`). The ISA-specific primitives (RISC-V H extension, ARM EL2, AMD
SVM) sit behind `azos_arch_api::Hypervisor` and live in the `hv` module of each arch
crate's `ext/`.

- Source: `crates/core/hv`, `userspace/services/vmmd`,
  `crates/core/arch-*/src/ext/hv/`, `kernel/src/boot/hv.rs`, `config/axes/Kconfig.virt`.
- Doc: [virtualization.md](Documentation/virtualization.md).

### API reference

Where the public surfaces are defined: `azos_abi` (kernel and ring-3 boundary),
`azos_libsys` (ring-3 wrappers), `azos_devif` and `azos_idl` (interfaces),
`azos_drv_api` (driver framework), `azos_arch_api` (ISA contract).

- Doc: [api-reference.md](Documentation/api-reference.md).

## The robot domain

`domains/robot` holds the robot application domain: a behavior engine, AHRS,
navigation, flight control, telemetry, ESC and RC drivers and the motor safety
envelope. It is linked only when the image selects `USE_ROBOT` (kernel feature
`use-robot`) and plugs into the shared actuation authority through
`azos_actuation::hooks`. Its ring-3 pieces are
`userspace/services/{brain_client,reflex,infsrv}`.

Source: `domains/robot/`, `config/axes/Kconfig.use`, `crates/core/actuation/src/hooks.rs`.

## AzOS-micro

`micro/` is a second kernel for parts without an MMU: riscv32imac, M-mode,
protection by PMP region domains. It reads the same signed topology and speaks
the same capability and IPC ABI, and it compiles the main kernel's pure modules
(scheduling context, EDF/CBS arithmetic, QSBR rules) with `#[path]`. Tasks are
static rows of the topology; there is no fork and no exec.

- Source: `micro/`, `config/kernel/Kconfig.micro`, `config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config`,
  `tests/host/micro-tests`.

## Adding an ISA

An ISA is three pieces, and the layout lint reports which files are missing.

1. An arch crate `crates/core/arch-<isa>` implementing the `arch-api` traits,
   with ISA-only code under `ext/`.
2. A kernel entry directory `kernel/src/entry/<isa>` with `arch_entry.rs`
   (the `ArchEntry` impl with every early-boot hook), `boot_hooks.rs`, `asm/`
   (`boot.S`, `context_switch.S`, `trap_entry.S`), `trap.rs`, `irq.rs`, `smp.rs`,
   `resume.rs` and `ext/`.
3. A branch in the facade (`crates/core/arch/src/lib.rs`), a kernel linker
   script (`kernel/linker-*.ld`), the ring-3 target spec (`sdk/targets/`, which
   carries the user image layout too) and a Kconfig ISA symbol (`config/arch/Kconfig.isa`).

Check with `python3 tools/lint/arch_layout_lint.py`. See
[Documentation/structure.md](Documentation/structure.md#per-isa-layout) for the
full layout.

Source: `tools/lint/arch_layout_lint.py`, `crates/core/arch/src/lib.rs`,
`kernel/src/entry/`, `crates/core/arch-api/src/contract.rs`.
