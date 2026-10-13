# The native SDK

A Rust `std` target for AzOS, `riscv64imac-unknown-azos`, `aarch64-unknown-azos`
and `x86_64-unknown-azos`, built with `-Zbuild-std` from the toolchain pinned in
`rust-toolchain.toml`. `make sdk` builds every std program on the three ISAs
(`WHY.ELF` and the SDK's own test, `tests/sdk/sdktest`); `make sdk-check`
type-checks the port layer and runs its host tests.

## What is where

| Path | What |
|---|---|
| `targets/*.json` | The target specs (`os = "azos"`). The ISA baseline beyond them comes from Kconfig. |
| `ld/user_<isa>.ld` | The one linker script per ISA: image layout, the ABI note, the test registry brackets. |
| `std/sys/**` | The files of the port, copied into `library/std/src/sys/` of the library source. Each is thin: a call into `azos_stdrt`. |
| `crates/core/stdrt` | The port layer: traps, startup block, vDSO clock, threads, futexes, the hardened allocator, console, entropy. |
| `tools/sdk_std.py` | Assembles `build/sdk/rust-src/library` from the toolchain's `rust-src` plus `std/sys` and the dispatch edits. |
| `tools/sdk_cargo.py` | Runs cargo for one ISA with the target, flags and environment from the expanded Kconfig. |
| `crates/core/libsys-macros` | `#[main]` and `#[test]`, re-exported by `azos_libsys`. |

`tools/sdk_std.py` points cargo at the assembled tree with
`__CARGO_TESTS_ONLY_SRC_ROOT`, an internal cargo hook used by cargo's own tests,
not a supported interface. It is tied to the pinned nightly: each edit of the
library is an exact one-time replacement and the tool refuses when the text
moved (`python3 tools/sdk_std.py --check`), so a toolchain bump is the moment to
re-check them. The assembled tree is a build product and is never committed.

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
  counter); `sleep` is `SYS_SLEEP_UNTIL`. There is no wall clock in the ABI, so
  `SystemTime::now` panics.
- **Output.** stdout and stderr are the console handle's `WRITE` op (a handle
  the spawner passed is written with `NODE_WRITE`). The console has no read:
  console input belongs to the terminal server.
- **Errors.** `io::ErrorKind` from the negative native result
  (`pal::map_native_error`), never an errno.

## Not provided

`std::fs`, `std::net` and `std::process` answer `Unsupported`. The native file
and socket calls are path-named domain ops, which the interface lint
(`crates/core/idl`) refuses as authority; a client of the file-system and
network interfaces (a `Cap<Dir>` root, socket endpoints) is a front of its own,
and `sdktest` holds the edge (`fs_and_net_are_not_provided`).

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

## Tests of user code

`#[azos::test] fn name()` (or `-> Result<(), &'static str>`) registers a test in
the `.azos_ktest` section, the registry the kernel's `ktest!` uses, bracketed by
the same two symbols in `ld/user_<isa>.ld`. `azos_libsys::utest::run()` runs
them in name order and prints TAP on the console; the number of failures is the
exit status. A panic is an abort: the `# running NAME` line printed before each
test names the culprit.
