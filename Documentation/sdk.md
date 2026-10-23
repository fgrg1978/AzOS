<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# AzOS SDK

How to write a program for AzOS in Rust or C: the `std` target, the `libsys`
system-call library, the relibc port, and the shape of a minimal native program
and a native driver. A ring-3 program is an ELF image started by the kernel
from a topology row; what it may do is that row's capabilities and the system-call
filter bound to its image (see [services.md](services.md)). Build commands are in
[building.md](building.md); configuration options are in [config.md](config.md).

| Way to write a program | Language | Library | Section |
|---|---|---|---|
| Rust with `std` | Rust | `std` on `*-unknown-azos`, plus `azos_libsys` for native calls | [The std target](#the-std-target) |
| Rust without `std` | Rust | `azos_libsys` | [libsys](#libsys), [A minimal native program](#a-minimal-native-program) |
| C | C | relibc on the native ABI | [relibc](#relibc) |
| Ring-3 driver | Rust, `no_std` | `azos_libsys` | [A native driver](#a-native-driver) |

## The std target

Source: `sdk/README.md`, `sdk/targets/`, `sdk/std/sys/`,
`crates/core/stdrt/src/lib.rs`, `tools/sdk_std.py`, `tools/sdk_cargo.py`.

A Rust `std` target for each ISA: `riscv64imac-unknown-azos`,
`aarch64-unknown-azos` and `x86_64-unknown-azos` (`os = "azos"`, panic strategy
`abort`). `std` is built with `-Zbuild-std` from the toolchain pinned in
`rust-toolchain.toml`. `make sdk` builds every std program for the three ISAs
(the list is `SDK_ELFS` in `mk/userspace.mk`: `userspace/services/why`,
`userspace/services/pkgd`, `userspace/services/rpcquic`, `tests/sdk/sdktest` and `userspace/lib/tls-probe`);
`make sdk-check` type-checks the port layer on the three ISAs and runs its host
tests.

| Path | What |
|---|---|
| `sdk/targets/*.json` | The one target spec per ISA, of every native image (`std` or not): codegen baseline and the image layout (image base, page size, entry `_azos_entry`, a static PIE). No image has a linker script. The ISA baseline beyond them comes from Kconfig. |
| `sdk/std/sys/**` | The files of the port, copied into `library/std/src/sys/` of the library source. Each is thin: a call into `azos_stdrt`. |
| `crates/core/stdrt` | The port layer (`azos_stdrt`): traps, startup block, vDSO clock, threads, futexes, the hardened allocator, console, entropy, sockets. |
| `tools/sdk_std.py` | Assembles `$AZOS_OUT/build/sdk/rust-src/library` from the toolchain's `rust-src`, `sdk/std/sys` and the dispatch edits to `std`. |
| `tools/sdk_cargo.py` | Runs cargo for one ISA with the target, flags and environment taken from the expanded Kconfig. |
| `crates/core/libsys-macros` | `#[main]` and `#[test]`, re-exported by `azos_libsys`. |

`tools/sdk_std.py` points cargo at the assembled tree with
`__CARGO_TESTS_ONLY_SRC_ROOT`, an internal cargo hook, not a supported cargo
interface. The tool applies each edit of the library as one exact replacement and
refuses when the text has moved (`python3 tools/sdk_std.py --check`), so a
toolchain change is the moment to re-check them. The assembled tree is a build
product and is not committed.

### What the port maps to

There are no file descriptor numbers, no `errno`, no signals and no POSIX layer in
the port. The module list of `crates/core/stdrt/src/lib.rs` is the map.

| `std` area | Native object | Where |
|---|---|---|
| Entry and arguments | The ELF entry is `_azos_entry` (`start`); the startup block of `SYS_SPAWN_EX` gives `std::env::args`, the environment and the working directory. fds 0..2 are handles from the block, or the console. | `crates/core/stdrt/src/start.rs` |
| Memory | `std::alloc::System` is the engine of `azos_ualloc` (size classes, checksummed headers, quarantine, guard pages, randomized placement) over `SYS_MO_MAP`, keyed from the kernel entropy pool through the `Entropy` interface. Its knobs are Kconfig `USER_ALLOC_*`. | `crates/core/stdrt/src/alloc.rs`, `crates/core/stdrt/src/mem.rs`, `userspace/lib/ualloc/src/lib.rs` |
| Threads | `thread_create` on a stack the port maps with guard pages; `join` waits on the word the kernel clears at thread exit. Locks, condition variables, `Once` and the parker are futex based. Thread-local storage is keyed: the image has no `PT_TLS`, and a registry finds the running thread's block from its stack pointer. | `crates/core/stdrt/src/thread.rs`, `crates/core/stdrt/src/futex.rs`, `crates/core/stdrt/src/tls.rs` |
| Time | `Instant` is the vDSO clock (no trap where ring 3 may read the counter); `sleep` is `SYS_SLEEP_UNTIL`. `SystemTime::now` is the real-time clock the vDSO publishes (the monotonic clock plus the offset a time source set), so it reads the uptime since 1970 until a source has set it. | `crates/core/stdrt/src/time.rs` |
| Output | stdout and stderr are the console handle's `WRITE` op, or `NODE_WRITE` on a handle the spawner passed. The console has no read: console input belongs to the terminal server (`termd`). | `crates/core/stdrt/src/console.rs` |
| Randomness | The kernel pool through the `Entropy` interface (`HashMap` keys, the allocator seed). | `crates/core/stdrt/src/entropy.rs` |
| Errors | `io::ErrorKind` is derived from the negative native result, never from an `errno`. | `sdk/std/sys/pal/azos/mod.rs` |

### std::net

`std::net` is built on the `Node` socket ops of the native ABI. A socket is a
`Cap<Socket>` handle made by `DOMAIN_SOCKET` and ended by `SYS_CAP_CLOSE`; each
call on it is one `invoke` op. The socket ops do not block, so a blocking read or
write is a poll with an absolute sleep (`SYS_SLEEP_UNTIL`) between looks, and the
timeouts and the nonblocking flag belong to the port layer. Only `NODE_CONNECT`
blocks inside the kernel. The end of a stream is the kernel's own code (`-EEOF`);
a bare `-1` is a refusal. A socket is closed only once no call holds its handle,
so `shutdown(Both)` on a shared `TcpStream` cannot reach a recycled handle.

| `std::net` | Served | Notes |
|---|---|---|
| `TcpStream` over IPv4 | yes | timeouts, nonblocking mode, `shutdown` of the read side and of both |
| `UdpSocket` over IPv4 | yes | timeouts, multicast join and leave |
| `TcpListener` | no | `bind` answers `Unsupported`: the port layer does not use the kernel's `NODE_LISTEN` and `NODE_ACCEPT` ops, which `azos_libsys::listen_typed` and `accept_typed` wrap for a `no_std` server (`userspace/services/sshd`) |
| Name lookup | no | no resolver op |
| IPv6 addresses and UDP over IPv6 | no | no IPv6 `sockaddr` form in the native socket ops, and no UDP over IPv6 in the stack |
| `shutdown(Write)`, a stream's local address, `peek` | no | `Unsupported` |

A program that opens a socket needs a system-call filter row that names one op
of the `net` invoke class.

Source: `crates/core/stdrt/src/net.rs`, `crates/core/stdrt/src/netpure.rs`,
`sdk/std/sys/net/connection/azos.rs`, `sdk/std/sys/net/connection/azos/addr.rs`.

### Not provided

`std::fs` and `std::process` answer `Unsupported`. The native file calls are
path-named domain ops, which the interface lint (`crates/core/idl`) refuses as
authority. A program that needs files uses the libsys file calls, which take a
directory handle (see [libsys](#libsys)).

### Writing a std program

```toml
# Cargo.toml
[dependencies]
azos_libsys = { path = "…/crates/core/libsys" }   # only for native calls std has none for

[profile.release]
panic = "abort"      # the target has no unwinding
strip = "symbols"    # the loader reads a bounded amount of the file
```

`fn main` is the entry. `userspace/services/why/Cargo.toml` is a complete example
of a std program, and `tests/sdk/sdktest/src/main.rs` exercises the port. Build with
`tools/sdk_cargo.py`:

```sh
python3 tools/sdk_cargo.py --isa riscv64 --kconfig <expanded .config> -- build --release --manifest-path userspace/services/why/Cargo.toml
```

A std program needs the `entropy` capability in its topology row (the allocator
draws on the pool from its first allocation), and its system-call filter row lists
the entropy interface. `tests/host/seccomp-tests` derives the std baseline of a row
from `stdrt`.

### Tests of user code

`#[azos::test] fn name()` (or `-> Result<(), &'static str>`) registers a test in the
`azos_ktest` section, the registry the kernel's `ktest!` uses
(`crates/core/ktest/src/lib.rs`), bracketed by `__start_azos_ktest` and
`__stop_azos_ktest`, which the linker defines for a section named like a C
identifier. `azos_libsys::utest::run()` runs the tests in name order,
prints TAP on the console, and returns the number of failures, clamped to 255, which
is the program's exit status. A panic ends the process; the `# running NAME` line
printed before each test names the culprit.

Source: `crates/core/libsys/src/utest.rs`, `crates/core/libsys-macros/src/lib.rs`.

## libsys

Source: `crates/core/libsys/src/lib.rs`, `crates/core/libsys/src/dev.rs`,
`crates/core/libsys/src/ioring.rs`, `crates/core/libsys/src/pipe.rs`,
`crates/core/libsys/src/pure.rs`, `crates/core/abi/src/syscall_nr.rs`.

`azos_libsys` is the `#![no_std]` wrapper around the kernel's trap ABI. Every
function that traps selects the trap opcode of its ISA with `cfg(target_arch = ...)`
inside one function body (`ecall`, `svc #0`, and the x86_64 syscall opcode); the
build stops with a `compile_error!` on any other ISA. System-call numbers are
imported from `azos_abi::syscall_nr`, and the register convention is documented in
`crates/core/abi/src/syscall_nr.rs`. A negative return is an error. On x86_64 the
programs enter at `_azos_entry`, which aligns the stack and calls `_start`.

| Family | Functions (all in `azos_libsys`) |
|---|---|
| Process and thread | `exit`, `getpid`, `yield_now`, `spawn_ex`, `task_kill`, `wait_status`, `waitpid`, `thread_create`, `thread_exit`, `futex_wait`, `futex_wake`, `schedctl`, `qos_hint`, `task_subreaper` |
| Confinement | `seccomp` (`DOMAIN_SET_FILTER`), `pledge` (`DOMAIN_PLEDGE`); both one way |
| Time | `vdso_now_ns`, `vdso_uptime_ms`, `clock_now`, `sleep`, `sleep_until_ns`; `SleepResult` |
| vDSO and ABI | `vdso_hwcap`, `vdso_hwcap2`, `vdso_task_map`, `vdso_task_counters`, `vdso_sensor_read`, `abi_matches` |
| Startup block | `startup_init`, `argc`, `arg`, `getenv`, `env_at`, `cwd`, `fd_get`, `dup`, `dup2`, `fd_install` |
| Memory | `mmap`, `munmap`, `shm_create_typed`, `shm_map_typed`, `shm_protect_typed`, `shm_release_typed`, `shm_acquire_typed`, `shm_end_drop_typed` |
| Capabilities | `cap_info`, `cap_lookup`, `cap_derive`, `endpoint_derive`, `cap_revoke`, `close_typed`; `CapInfo`, `ty` |
| IPC | `invoke`, `invoke_desc`, `ipc_call_v2`, `ipc_accept_v2`, `ipc_reply_v2`, `ipc_reply_delegate`, `fast_ipc_call_ep`, `fast_ipc_accept`, `fast_ipc_reply`, `fast_ipc_reply_accept` |
| Ports | `port_create_typed`, `endpoint_create_typed`, `port_bind_typed`, `port_bind_timer`, `port_bind_endpoint`, `port_bind_pressure`, `port_unbind_typed`, `port_wait_typed`, `port_wait_until_typed`, `port_poll_typed`, `port_destroy_typed` |
| Files | `root_dir`, `open_at`, `open_root`, `read`, `write`, `file_read_typed`, `file_write_typed`, `stat`, `statfs`, `readdir`, `mkdir`, `unlink`, `rmdir`, `rename`, `truncate`, `fsync_typed`, `close`, `console_write`, `print`, `println` |
| Sockets | `socket_typed`, `connect_typed`, `send_typed`, `recv_typed`, `bind_typed`, `listen_typed`, `accept_typed`, `sendto_typed`, `recvfrom_typed`, `mcast_join_typed`, `mcast_leave_typed` |
| Driver server | `drv_srv_register_typed`, `drv_srv_reply_wait`, `drv_srv_reply_fetch`, `drv_srv_fetch_request`, `drv_srv_reply`, `drv_srv_unregister_typed`, `mmio_map`, `irq_bind`, `irq_ack` |
| Foreign ABI | `foreign_entry`, `foreign_resume`, `foreign_fork` (for a ring-3 runtime that hosts another system-call ABI) |
| Rings | `ioring_create_typed`, `ioring_submit_typed`, `ioring_destroy_typed`; `ioring::Ring` is the ring-3 producer and consumer over the ring page |

Modules:

| Module | What |
|---|---|
| `dev` | Clients of the interfaces the kernel hosts and of driver endpoints (`azos_devif`). `dev::lookup(key, badge)` finds the endpoint capability the task's row grants. `Ep` is the v2 call and `Regs` the register form (`SYS_IPC_FAST_CALL_EP`, four words each way) for an interface declared `words = 4`. Helpers such as `entropy_read`, `link_key_read` and `sensor_read` wrap one interface. |
| `ioring` | Ring-3 view of an io_ring page: SQEs, CQEs and the opcodes. It never enters the kernel, so every system call a program makes is a visible `sys::NAME(..)` call. |
| `pipe` | The process's half of a POSIX-style pipe: a `Cap<Shm>` region with a byte ring (`azos_bytepipe`), with the futex as the doorbell. |
| `utest` | The test harness of user code (above). |
| `hwcap` | The bits of the vDSO hardware-capability word, per ISA. |
| `pure` | Helpers with no trap, tested on the host (`tests/host/libsys-tests` includes the file with `#[path]`). |

Every call goes through a `sys::name(..)` function, so `tests/host/seccomp-tests`
can derive the exact system-call profile of an image from its sources.

## relibc

Source: `userspace/lib/relibc-azos/README.md`, `config/axes/Kconfig.libc`,
`tools/third_party_fetch.sh`, `tools/relibc_build.sh`, `.gitmodules`.

relibc is Redox's C library, written in Rust (MIT). It is the porting layer for C
code. POSIX is a personality here, not the native model: native programs use the
SDK, and a C program that wants `open`, `posix_spawn` or `pthread` gets them from
this library as far as the native ABI has an object for them.

Nothing of relibc is stored in the repository except what AzOS adds to it:

| Path | What |
|---|---|
| `third_party/relibc` | A gitlink (`.gitmodules`, `update = none`): the upstream commit. |
| `tools/third_party_fetch.sh relibc` | Shallow-fetches that commit (and its `dlmalloc-rs` submodule) into `third_party/relibc`, in a checkout outside iCloud Drive. |
| `userspace/lib/relibc-azos/patches/` | The changes to upstream files. |
| `userspace/lib/relibc-azos/overlay/` | AzOS's own files: the `azos` platform module, three target specs, three linker scripts. |
| `tools/relibc_build.sh` | Copies the checkout, applies the patches and the overlay, builds `libc.a` and C programs. |
| `config/axes/Kconfig.libc` | `CONFIG_RELIBC`, the switch, read from each ISA's configuration. |

The platform layer (`userspace/lib/relibc-azos/overlay/src/platform/azos/`) implements relibc's `Pal` over
`azos_libsys`:

| Area | Behaviour |
|---|---|
| Files | A per-process descriptor table maps small integers to handles, the console and directories. A descriptor acts on its handle or not at all: `ftruncate`, `fstat` and `fstatvfs` are refused with `ENOSYS` rather than run on the name the file was opened by. A directory has no native handle: `opendir` reads its entries once and `getdents` serves that snapshot. |
| Processes | `posix_spawn` is `SYS_SPAWN_EX`; the file actions become its move list. `waitpid` polls `DOMAIN_WAIT`. There is no `fork` and no `exec*`. |
| Threads | `SYS_THREAD_CREATE` with a thread pointer and `SYS_FUTEX_*`. |
| Memory | Anonymous `mmap` over `SYS_MO_MAP`; the allocator is relibc's dlmalloc. |
| Time | The vDSO clocks. `CLOCK_REALTIME`, `CLOCK_TAI` and `CLOCK_BOOTTIME` are the monotonic clock plus the offset the kernel publishes. |
| Entry | `_azos_entry` (the entry the target spec names) reads the startup block and lays out the System V stack relibc expects. On x86_64 ring 3 cannot set its FS base, so the first thread builds the thread control block and hands `main` to a second thread created with it as thread pointer. |
| Refused with `ENOSYS` | Signals (`kill` is a stop request, `SYS_ALERT`), sockets, `epoll`, `ptrace`, links, modes, owners, seek. |

Build a C program:

```sh
tools/third_party_fetch.sh relibc && make relibc     # for each ISA whose configuration sets CONFIG_RELIBC=y
tools/relibc_build.sh cc <isa> OUT.elf SRC.c...
```

`make relibc` builds `hello.elf` and `tinybox.elf` from
`userspace/tests/relibc/hello.c` and `userspace/tests/relibc/tinybox.c` under
`$AZOS_OUT/build/relibc/<isa>/`. `cc` compiles with `-D__azos__`, the relibc headers,
`-nostdlib -static`, the layout of the ISA's target spec (`tools/user_link_args.py
--driver`: a static executable at the same image base and entry, no linker script) and
`libc.a`. It needs `zig` and
`cbindgen` (see [building.md](building.md)). To move the pin, change
the gitlink (`git update-index --cacheinfo 160000,<commit>,third_party/relibc`), run
`tools/third_party_fetch.sh relibc`, then `tools/relibc_build.sh prepare`, which fails
on a patch hunk that no longer applies.

## A minimal native program

Source: `crates/core/libsys-macros/src/lib.rs`, `userspace/tests/uhello/`,
`userspace/tests/uhello/Cargo.toml`, `userspace/.cargo/config.toml`, `sdk/targets/`.

A `no_std` program imports `azos_libsys` and writes an entry. With the macro:

```rust
#![no_std]
#![no_main]

use azos_libsys as azos;

#[azos::main(panic_exit = 70)]
fn main() -> i32 {
    azos::println(b"hello from ring 3");
    0
}
```

`#[azos::main]` generates `_start` (the image enters at `_azos_entry`, which
`azos_libsys` defines and which calls `_start`), which reads the startup block
(`azos_libsys::startup_init`), calls `main` and ends the process with its value
(`()` is 0; `-> !` never returns). With `panic_exit = N` it also generates a
`#[panic_handler]` that ends the process with `N`; without it the program supplies
its own. The macro names `::azos_libsys`, so the dependency must be declared in
`Cargo.toml` under that crate name.

`userspace/tests/uhello/src/main.rs` shows the same program with a hand-written
`_start` and `#[panic_handler]`, and is the smallest complete directory to copy:

| File | What |
|---|---|
| `Cargo.toml` | Depends on `azos_libsys`; release profile with `panic = "abort"`; an empty `[workspace]` table so the crate is standalone. |
| `src/main.rs` | The program. |

Nothing else: the target spec of each ISA (`sdk/targets`) carries the layout, and
`userspace/.cargo/config.toml` (the one cargo configuration of every image) the
default target and `build-std`. A crate with a linker script or a cargo
configuration of its own is refused by `tools/user_entry_lint.py` (gate tier n0).
An image that asks for a stack other than Kconfig `USER_STACK_SIZE_KB` says so in
a `build.rs` (`cargo:rustc-link-arg-bins=-zstack-size=N`, e.g.
`userspace/services/toolbox/build.rs`).

An image gets its authority from a topology row named after the image (an upper-case
8.3 name such as `UHELLO.ELF`) and its system-call filter from the profile bound to
the image's digest (`crates/core/sched/src/seccomp.rs`). A program that is not
declared in the topology has no row to take capabilities from. A crate declares the
FAT32 images it builds, whether the built-in topology has a row for it, and when the
topology starts it, in `[package.metadata.azos]` of its `Cargo.toml`
(`tools/gen_userspace_kconfig.py` turns those into `make config` options).

## A native driver

Source: `userspace/drivers/gpio_drv/src/main.rs`, `userspace/drivers/buzz_drv/src/main.rs`,
`userspace/drivers/ina_drv/src/main.rs`, `crates/core/abi/src/drv_kind.rs`,
`crates/core/devif/src/power.rs`.

A ring-3 driver is an ordinary process that serves requests the kernel forwards. The
reference is `userspace/drivers/gpio_drv`; `buzz_drv` and `ina_drv` serve typed
interfaces on endpoints instead. The sequence in `gpio_drv`:

1. **Find the registry capability.** `cap_lookup(ty::DRIVER_REGISTRY.raw(), DRV_KIND_GPIO)`
   returns the handle of the `DriverRegistry` capability that the program's topology
   row grants. The kind comes from `azos_abi::drv_kind`.
2. **Register.** `drv_srv_register_typed(cap, 0, 0, 0)` takes only that handle. There is
   no `kind` argument, so a driver cannot register for a device its row does not name.
3. **Serve.** `drv_srv_reply_wait(kind, reply, request, park_ms)` posts the reply owed
   for the previous request, if any, and fetches the next one in one call. With the
   queue empty it parks the task until a request is queued, bounded by `park_ms`
   (0 is the kernel's default bound). It returns 0 for a request, -1 when the park
   ended with none, and another value when the kernel refused with nothing done.
4. **Handle.** Requests and replies are `#[repr(C)]` records (`DriverRequest`,
   `DriverReply`) whose layout must match the kernel's driver server; the reply carries
   the request's `token`.
5. **Power.** The driver is a device with a power state. `azos_libsys::dev::power::runtime`
   holds the runtime power core (`RuntimePm`, `PmDevice`, `PmServer`); a second thread
   made with `thread_create` accepts `DevicePower` calls with `ipc_accept_v2` and
   answers with `ipc_reply_v2`.

The row of the program grants only what the device needs: the right to register as
that one driver kind, and the MMIO window, PWM channel or I2C slave behind it. A
driver that moves between kernel and ring 3 sits behind the same handle; the
placement options are in [config.md](config.md).
