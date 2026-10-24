# The native SDK

A Rust `std` target for AzOS, `riscv64imac-unknown-azos`, `aarch64-unknown-azos`
and `x86_64-unknown-azos`, built with `-Zbuild-std` from the toolchain pinned in
`rust-toolchain.toml`. `make sdk` builds every std program on the three ISAs
(`WHY.ELF`, `PKGD.ELF`, `RPCQUIC.ELF`, the TLS probe and the SDK's own test,
`tests/sdk/sdktest`); `make sdk-check` type-checks the port layer on the three
ISAs and runs its host tests.

## What is where

| Path | What |
|---|---|
| `sdk/targets/*.json` | The one target spec per ISA (`os = "azos"`), of every native image, `std` or not: it carries the layout too (image base, page size, entry `_azos_entry`, a static PIE), so no image has a linker script. The ISA baseline beyond them comes from Kconfig. |
| `sdk/std/sys/**` | The files of the port, copied into `library/std/src/sys/` of the library source. Each is thin: a call into `azos_stdrt`. |
| `crates/core/stdrt` | The port layer: traps, startup block, vDSO clock, threads, futexes, the hardened allocator, console, entropy. |
| `tools/build/sdk_std.py` | Assembles `$AZOS_OUT/build/sdk/rust-src/library` from the toolchain's `rust-src` plus `std/sys` and the dispatch edits. |
| `tools/build/sdk_cargo.py` | Runs cargo for one ISA with the target, flags and environment from the expanded Kconfig. |
| `crates/core/libsys-macros` | `#[main]` and `#[test]`, re-exported by `azos_libsys`. |

`tools/build/sdk_cargo.py` points cargo at the assembled tree with
`__CARGO_TESTS_ONLY_SRC_ROOT`, an internal cargo hook used by cargo's own tests,
not a supported interface. The assembly is tied to the pinned nightly: each edit of the
library is an exact one-time replacement and the tool refuses when the text
moved (`python3 tools/build/sdk_std.py --check`), so a toolchain bump is the moment to
re-check them. The assembled tree is a build product and is never committed.

Source: `sdk/`, `tools/build/sdk_std.py`, `tools/build/sdk_cargo.py`.

## What the port maps to

No file descriptor numbers, no `errno`, no signals, no POSIX layer:

- **Entry and arguments.** The ELF entry is `_azos_entry` (`stdrt::start`); the
  startup block of `SYS_SPAWN_EX` gives `std::env::args`, the environment and the
  working directory. fds 0..2 are the block's handles, or the console.
- **Memory.** `std::alloc::System` is `azos_ualloc`'s engine (size classes,
  checksummed headers, quarantine, guard pages, randomized placement) over
  `SYS_MO_MAP`, keyed from the kernel entropy pool through the `Entropy`
  interface. Its knobs are Kconfig `USER_ALLOC_*`.
- **Threads.** `thread_create` on a stack the port maps with guard pages;
  `join` waits on the word the kernel clears at exit. `std`'s locks, condition
  variables, `Once` and the parker are futex based (`SYS_FUTEX_*`). Thread-local
  storage is keyed (the image has no `PT_TLS`): the registry finds the running
  thread's block from its stack pointer.
- **Time.** `Instant` is the vDSO clock (no trap where ring 3 may read the
  counter); `sleep` is `SYS_SLEEP_UNTIL`. `SystemTime::now` is the real-time
  clock the vDSO publishes (the monotonic clock plus the offset NTP set): it
  reads 1970 plus the uptime until a sync, so a program that checks
  certificates waits for one.
- **Sockets.** `std::net` over the `Node` socket ops (`stdrt::net`): `TcpStream`
  and `UdpSocket` on IPv4 with timeouts, nonblocking, `shutdown` of the read side
  and of both, multicast. A blocking read or write is a poll with an absolute
  sleep between looks (the ops do not block). The end of a stream is the
  kernel's own code (`-EEOF`); a bare `-1` is a refusal, never a clean end. A
  socket is closed only once no call holds its handle, so `shutdown(Both)` on a
  shared `TcpStream` cannot reach a recycled handle. Not served yet: `TcpListener`,
  name lookup, IPv6 addresses and UDP over IPv6, `shutdown(Write)` and a stream's
  local address. The first two are service functions that come as IDL interfaces
  on endpoints (a listener and a resolver, over the stack's
  `crates/net/net/src/dns.rs` and TCP listener), not as more socket ops; that work is not done. A program that opens
  a socket has a seccomp row naming one op of the `net` class.
- **Output.** stdout and stderr are the console handle's `WRITE` op (a handle
  the spawner passed is written with `NODE_WRITE`). The console has no read:
  console input belongs to the terminal server.
- **Errors.** `io::ErrorKind` from the negative native result
  (`pal::map_native_error`), never an errno.

Source: `crates/core/stdrt/src/` (`start.rs`, `alloc.rs`, `thread.rs`, `futex.rs`,
`time.rs`, `net.rs`, `console.rs`), `sdk/std/sys/`.

## Not provided

`std::fs` and `std::process` answer `Unsupported`. The native file calls are
path-named domain ops, which the interface lint (`crates/core/idl`) refuses as
authority; a client of the file-system interface (a `Cap<Dir>` root) is a front
of its own, and `sdktest` holds the edge (`fs_is_not_provided`). What of
`std::net` the socket ops cannot serve is listed under Sockets above, and
`sdktest` holds that edge too (`net_edges_and_udp_timeouts`).

Source: `tests/sdk/sdktest/src/main.rs`.

## Writing a program

```toml
# Cargo.toml
[dependencies]
azos_libsys = { path = "…/crates/core/libsys" }   # only for the native calls std has none for

[profile.release]
panic = "abort"      # the target has no unwinding
strip = "symbols"    # the loader reads at most 128 KiB of file
```

`fn main` is the entry. A program that is not on `std` (`#![no_std]
#![no_main]`) writes `#[azos::main(panic_exit = 70)] fn main() -> i32` after
`use azos_libsys as azos;` and gets the entry and the panic handler. Its
topology row grants the `entropy` capability and its seccomp row lists the
entropy interface (a std program draws on the pool from its first allocation);
`tests/host/seccomp-tests` derives the std baseline of a row from `stdrt`.

Source: `crates/core/libsys`, `crates/core/libsys-macros`.

## Tests of user code

`#[azos::test] fn name()` (or `-> Result<(), &'static str>`) registers a test in
the `azos_ktest` section, the registry the kernel's `ktest!` uses, bracketed by
`__start_azos_ktest` and `__stop_azos_ktest`, which the linker defines. `azos_libsys::utest::run()` runs
them in name order and prints TAP on the console; the number of failures is the
exit status. A panic is an abort: the `# running NAME` line printed before each
test names the culprit.

Source: `crates/core/libsys/src/utest.rs`, `crates/core/ktest/src/lib.rs`.
