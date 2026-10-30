# API reference

The public Rust crates are documented with rustdoc. `make doc` builds that
documentation from the doc comments in the source; nothing generated is kept in
the repository.

Source: `mk/host.mk` (the `doc` target), `crates/core/*/src/lib.rs`.

## Build

```sh
make doc                 # the ISA .config selects (the default ARCH)
make doc ARCH=aarch64    # the aarch64 build of the same crates
make doc ARCH=x86_64     # the x86_64 build of the same crates
```

| Item | Value |
|------|-------|
| Output | `$AZOS_OUT/doc`, replaced on every run |
| Output root | `$AZOS_OUT`, printed by `python3 tools/lib/out_dir.py` |
| Cargo target dir | `$AZOS_OUT/tgt/doc-<arch>` |
| Toolchain | the pinned nightly of `rust-toolchain.toml`, with `rust-src` |
| Target | the triple `tools/build/kconfig_to_cargo.py` derives from the `ARCH` defconfig |
| Rustdoc flags | `-D warnings`, plus the ISA's baseline codegen flags from `tools/build/kconfig_to_cargo.py --rustflags` |

The target builds `core` and `alloc` from source (`build-std` in `.cargo/config.toml`), so no
cross target has to be installed. Each ISA documents the items compiled for
that ISA: `azos_libsys`, for one, selects its trap instruction with
`#[cfg(target_arch = ...)]`.

Source: `mk/host.mk`, `tools/lib/out_dir.py`, `tools/build/kconfig_to_cargo.py`,
`rust-toolchain.toml`, `.cargo/config.toml`.

## Browse

The output is static HTML. Open the index of any crate in a browser:

```sh
open "$AZOS_OUT/doc/azos_abi/index.html"
```

All crates of one run share one search box and one crate list in the sidebar.
There is no top-level `index.html`; start from the index of a crate.

## Warnings are errors

`make doc` passes `RUSTDOCFLAGS="-D warnings"`, so a documentation warning in
one of the crates below fails the build. The usual causes:

* An intra-doc link that resolves to nothing: ``[`name`]`` where `name` is not in
  scope, `[63:60]` in running text (write `\[63:60\]`), or a module whose parent
  and file both carry documentation (the parent's `///` and the file's `//!`
  are resolved together, in the parent's scope; keep one of them).
* A link to a private item from a public item.
* An ambiguous link, such as ``[`write`]`` where a function and a macro share the
  name (write ``[`write()`]``).
* A link whose explicit target is the one rustdoc would already resolve.
* A link to an item compiled only for another configuration (the modules of
  `azos_stdrt` that exist only on `target_os = "azos"`). Name such an item in a
  plain code span instead.

Source: `mk/host.mk`.

## Crates

| Crate | Package | Path | Provides |
|-------|---------|------|----------|
| `azos_abi` | `azos_abi` | `crates/core/abi` | Syscall numbers, error codes and the `repr(C)` types that cross the user/kernel boundary |
| `azos_libsys` | `azos_libsys` | `crates/core/libsys` | Syscall wrappers for ring-3 programs |
| `azos_idl` | `azos_idl` | `crates/core/idl` | The interface definition language: `#[azos_interface]` and its runtime |
| `azos_devif` | `azos_devif` | `crates/core/devif` | The interfaces of kernel-hosted services and driver endpoints |
| `azos_rings` | `azos_rings` | `crates/core/rings` | `Queue` and `Log`, in process and over a shared-memory region |
| `azos_bytepipe` | `azos_bytepipe` | `crates/core/bytepipe` | The POSIX byte pipe over a byte ring |
| `azos_arch_api` | `azos_arch_api` | `arch/api` | The cross-ISA trait surface |
| `azos_stdrt` | `azos_stdrt` | `crates/core/stdrt` | The layer under Rust's `std` on `*-unknown-azos` |

All eight are `no_std`. `azos_abi`, `azos_libsys`, `azos_devif`, `azos_rings`,
`azos_bytepipe` and `azos_arch_api` are members of the root Cargo workspace.
`azos_idl` and `azos_stdrt` each carry their own `[workspace]` table, so
`make doc` documents them from their own directory into the same Cargo target
dir; that is why one run still yields one index and one search.

Source: `Cargo.toml`, `crates/core/*/Cargo.toml`, `mk/host.mk`.

### azos_abi

The single definition of everything that crosses the user/kernel boundary. The
kernel, `azos_libsys` and the userspace images all read these definitions.

| Module | Contents |
|--------|----------|
| `syscall_nr` | The native syscall table |
| `invoke` | `SYS_INVOKE`: one call for every operation on an object a task holds a handle to |
| `cap` | The capability handle wire format (`CapHandle`, `CapKind`, `CapPerms`) |
| `error` | Error codes (`Errno`) |
| `types` | Frozen `#[repr(C)]` types |
| `ipc_msg` | The message descriptor of the v2 call (`MsgDesc`, `CapDesc`) |
| `io_ring` | The io_ring page as ring 3 sees it: offsets, sizes, opcodes, flags |
| `vdso` | The vDSO page's fixed user-space address, field offsets and layout version, the per-ISA `hwcap` bits and the per-task page offsets |
| `time` | `ClockId`, the clock offsets (`ClockWords`), and nanosecond and counter-tick conversions |
| `drv_kind` | The `DRV_KIND_*` device-kind identifiers of the driver registry |
| `exit_status` | The exit statuses the kernel assigns when it kills a task |
| `families` | Operation selectors of the flight, behavior, config and OTA families |
| `foreign` | The two calls that let a ring-3 runtime host another system-call ABI |
| `power` | The limits and policy words of the `Power` interface |
| `rt_levels` | The cross-level admission rule for EDF and CBS reservations |
| `sensor_sample` | The stamp of a sensor sample |
| `trace` | The kernel tracer's event classes and event ids |
| `ushell` | The spawn request block, the startup block and the console flag values |
| `prelude` | The handle, kind, permission and error types in one import |

Source: `crates/core/abi/src/lib.rs` and the module files beside it.

### azos_libsys

Safe wrappers around the kernel's trap, so that a `no_std` program issues
syscalls without writing assembly. The trap instruction is selected per ISA
(`ecall` on riscv64, `svc #0` on aarch64; x86_64 is the third `target_arch`
branch). The result register carries an `i64`; a negative value is an error.

| Module | Contents |
|--------|----------|
| crate root | The syscall wrappers, the `invoke` entry, the typed capability calls, fast IPC, the vDSO clock |
| `hwcap` | The bits of the vDSO hardware-capability word, per ISA |
| `ioring` | Ring-3 view of an io_ring page and a producer/consumer over it (`Ring`) |
| `pipe` | The POSIX pipe ends a process holds, over `azos_bytepipe` |
| `dev` | Clients of the `azos_devif` interfaces (`lookup`, `Ep`, `Regs`) |
| `utest` | The test harness of user code |

The helpers that issue no trap live in `crates/core/libsys/src/pure.rs`, which
`azos_stdrt` includes by path.

Source: `crates/core/libsys/src/lib.rs`, `ioring.rs`, `pipe.rs`, `dev.rs`,
`utest.rs`, `pure.rs`.

### azos_idl

An interface is a Rust trait annotated `#[azos_interface(id = N, level = L)]`.
One interface generates, from one op table:

| Generated item | Role |
|----------------|------|
| `<Name>Client<T: Transport>` | The endpoint-call stub: packs arguments into a `MsgDesc`, calls the `Transport`, unpacks the reply |
| `<Name>Idl::dispatch` | The server dispatcher: decodes a request, calls the implementation, encodes the reply |
| `<Name>Direct<S>` | The direct-call stub: the same call in process, with no message |
| `<Name>Call` | The caller's trait, implemented by both stubs |
| `<Name>Idl::OPS` | The op table, one `OpInfo` per method |

The attribute itself is a proc macro in `crates/core/idl-macros`
(`azos_idl_macros`, built for the host); `azos_idl` re-exports it. The crate also
holds `Transport`, `Wire`, `Cap<T>`, `IdlError` and the support the generated
stubs call.

Source: `crates/core/idl/src/lib.rs`, `crates/core/idl/src/lint.rs`,
`crates/core/idl-macros`.

### azos_devif

The interfaces of the services the kernel hosts and of the devices a driver
endpoint serves. Each is an `#[azos_interface]` trait: the kernel serves it from
the endpoint a topology row grants, a ring-3 driver serves the same trait from
its own endpoint, and the client stub does not know which. The badge of the
endpoint names the resource; the rights are the op classes the holder may use
(`READ` observes, `WRITE` acts, `EXEC` controls).

Each interface module exports the trait, `<Name>Call`, `<Name>Client`,
`<Name>Idl` and an `<NAME>_ID` constant; `time` holds only `TIME_ID`. The registry `IFACES` maps a topology
target `<iface>[.<resource>]` to an interface and a badge (`parse_target`,
`by_name`, `by_key`).

| Interface | Module | Resource spelling |
|-----------|--------|-------------------|
| `Entropy` | `entropy` | none |
| `LinkKey` | `linkkey` | none |
| `Keys` | `keys` | none |
| `Power` | `power` | none |
| `Flight`, `Behavior`, `Config`, `Ota` | `families` | none |
| `Gpio` | `gpio` | `gpio.<pin>` |
| `I2c` | `i2c` | `i2c.<bus>.<address>` |
| `Spi` | `spi` | `spi.<bus>.<chip select>` |
| `Can` | `can` | `can.<controller>` |
| `Adc` | `adc` | `adc.<channel>` |
| `Uart` | `uart` | `uart.<port>` |
| `Pwm` | `pwm` | `pwm.<channel>` |
| `Motor` | `motor` | `motor.<wheel>` |
| `Sensor` | `sensor` | `sensor.<type>` |
| `Block` | `block` | `block.part.<n>` |
| `Clock` | `clock` | none |
| `Vm`, `Vcpu` | `vm` | `vm.<n>`, `vcpu.<n>.<k>` |
| `Net` | `net` | none |
| `Display` | `display` | `display.<connector>` |
| `MemCtl` | `memctl` | none |
| `Sound` | `sound` | `sound.<device>`; the ring-3 audio server serves it on `endpoint.audio` |
| `Volume` | `volume` | `volume.<n>` (0 the boot volume, `p` the row on partition `p`) |
| `time` endpoint | `time` | none |
| `Buzzer` | `buzzer` | not in `IFACES` |
| `VmCtl` | `vmctl` | not in `IFACES` |
| `Infer` | `infer` | not in `IFACES`; served by the ring-3 inference service |
| `Input` | `input` | not in `IFACES`; served by `INPUTD.ELF` on `endpoint.input` |

`outcome` holds the outcome codes an op answers with (`outcome::REFUSED`,
`outcome::NOT_READY`, ...).

Source: `crates/core/devif/src/lib.rs` and the module files beside it.

### azos_rings

Two ring shapes, as typed in-process values and as views over a shared-memory
region.

| Shape | Behaviour |
|-------|-----------|
| `Queue` | SPSC and backpressured; every item is consumed once. A full ring hands the item back or drops and counts it, chosen by `Full` |
| `Log` | One writer, sequence-numbered slots, overwrite-oldest, any number of readers each with a private cursor; a reader that falls behind is told how many items it lost |

The `region` module holds the shared-memory forms over one SPSC index protocol:
`SpscRing` (one `u64` per slot) and `SpscSlots` (`W` words per slot), `SpscBytes` (byte slots with
variable-length payloads), `SpscStream` (a byte stream) and `trace` (per-CPU
trace record rings). The doorbell is a trait; the ring is pure `no_std`.

Source: `crates/core/rings/src/lib.rs`, `queue.rs`, `log.rs`,
`crates/core/rings/src/region/mod.rs`.

### azos_bytepipe

The POSIX byte pipe as a `SpscStream` in a `Cap<Shm>` region, a header of end
counts and sleep events beside it, and the futex as the doorbell. It provides
EOF when the last writer closes, `EPIPE` when no reader is left, `O_NONBLOCK`
and `PIPE_BUF` atomic writes. `BytePipe` is the pipe, `End` names a side,
`PipeError` and `Slept` are its results, and the `Sys` trait is what the pipe
needs from the system (the futex calls).

Source: `crates/core/bytepipe/src/lib.rs`.

### azos_arch_api

What the kernel needs from an architecture, not how an architecture provides it.
Every ISA crate (`arch-riscv64`, `arch-aarch64`, `arch-x86_64`) implements this
surface.

| Item | Captures |
|------|----------|
| `Cpu` | Hart id, wait-for-interrupt, halt |
| `Interrupts` | Enable and disable, timer deadline, IPI send |
| `Mmu` | Page size, map and unmap, page-table switch, TLB shootdown |
| `Boot` | Shutdown, reboot, hart start |
| `Vector` | Optional SIMD kernels |
| `Pmu` | The cycle, instruction and event counters, with `PmuCaps` |
| `Hypervisor` | The guest-control surface, with `Exit`, `GuestCtx`, `Stage2Root`; `StageTableMem` (where stage-2 table pages live) and `HypercallHost` (what a hypercall is written against) |
| `ArchPlatform`, `ArchEntry` | The rest of the contract: required methods an ISA must provide, and the kernel's boot hooks (`FirmwareMemory`, `LineHooks`) |

| Module | Contents |
|--------|----------|
| `isa` | Baseline level and the per-extension `n` / `probe` / `require` policy |
| `spin` | `SpinWait` and `CasOrder`: spin-wait hints and compare-and-swap |
| `contig` | Contiguous runs of level-0 leaves |
| `tlb_gen` | Per-hart TLB generation for retained translations |
| `entropy` | The CPU's entropy instruction as a seed source |
| `aging` | The Accessed-bit walk behind `Mmu::harvest_accessed` (page aging) |
| `pmu` | The performance-counter seam behind `Pmu` |
| `kaslr` | Virtual KASLR (the Kconfig choice `KASLR_NEVER` / `KASLR_PROBE` / `KASLR_REQUIRE`): policy, slide choice, relocation walk and device-tree seed |
| `lat` | Masked-window tracer (cargo feature `lat-trace`) |

Source: `arch/api/src/lib.rs`, `contract.rs`, `isa.rs`, `spin.rs`,
`contig.rs`, `tlb_gen.rs`, `entropy.rs`, `aging.rs`, `pmu.rs`, `kaslr.rs`,
`lat.rs`.

### azos_stdrt

The functions that `library/std/src/sys/*/azos.rs` calls: traps, handles, the
vDSO clock, threads over `thread_create`, futexes, the hardened allocator, the
console and the startup block, with no `errno` and no POSIX. It is linked into
`std` through its `rustc-dep-of-std` feature (`tools/build/sdk_std.py`) and is not used
by a program directly.

| Module | Contents | Rendered by `make doc` |
|--------|----------|------------------------|
| `pure`, `tls`, `netpure`, `entropy` | Code that issues no trap | yes |
| `sys`, `start`, `time`, `mem`, `alloc`, `thread`, `futex`, `console`, `net` | The trap, startup, clock, memory, threads, locks, streams, sockets | no |

The modules in the second row exist only on `target_os = "azos"`, which `make
doc` does not build for; read their module documentation in
`crates/core/stdrt/src/<module>.rs`. The `std` overlay itself is in `sdk/std`.

Source: `crates/core/stdrt/src/lib.rs`, `sdk/std`, `tools/build/sdk_std.py`.
