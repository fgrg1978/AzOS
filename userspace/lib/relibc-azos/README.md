<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# relibc on the native ABI

relibc is Redox's C library, written in Rust (MIT). It is AzOS's **porting layer
for C code**. POSIX is a personality here, not the native model: native programs use the SDK, and a C program that wants `open`, `fork`
semantics or `pthread` gets them from this library, as far as the native ABI has
an object for them.

Nothing of relibc is stored in this repository except what AzOS adds to it:

| Path | What |
|---|---|
| `third_party/relibc` | a gitlink (`.gitmodules`, `update = none`): the upstream commit |
| `tools/third_party_fetch.sh relibc` | shallow-fetches that commit into `third_party/relibc` (`$RELIBC_SRC` overrides the tree the build reads), in a checkout outside iCloud Drive |
| `userspace/lib/relibc-azos/patches/` | the changes to upstream files (MIT, like the tree they patch) |
| `userspace/lib/relibc-azos/overlay/` | our own files: the `azos` platform module (Apache-2.0 OR GPL-2.0-only); the Rust targets are the native specs (`sdk/targets`) and a C program is linked with their layout (`tools/user_link_args.py --driver`), no linker script |
| `tools/relibc_build.sh` | copies the checkout, applies the patches and the overlay, builds `libc.a` and C programs |
| `config/axes/Kconfig.libc` | `CONFIG_RELIBC`: the switch, read from each ISA's own configuration |
| `make relibc` | all of it, for every ISA whose configuration sets `CONFIG_RELIBC=y` (the QEMU defconfigs do) |

`tools/lx_license_lint.py` accepts MIT only in `patches/` (rule T6) and checks the
pin with every other third-party tree (`--pin`).

Source: `tools/third_party_fetch.sh`, `tools/relibc_build.sh`, `config/axes/Kconfig.libc`,
`.gitmodules`.

## The platform layer (`overlay/src/platform/azos`)

`Sys` implements relibc's `Pal` over `azos_libsys`; the file header of
`mod.rs` is the table. In short:

- **Files**: a per-process descriptor table (`fdtab.rs`) maps small integers to
  handles, the console, and directories; the file ops are in `fs.rs`, the one
  module that knows how a file is reached, so the filesystem interface (IDL)
  replaces it there. The kernel keeps no working directory, so `fs.rs` keeps one
  and passes absolute paths. **A descriptor acts on its handle or not at all**: a
  file handle has read, write and fsync, so `ftruncate`, `fstat` and `fstatvfs`
  (and `statvfs(path)`, which upstream does as open + `fstatvfs`) are refused
  with `ENOSYS` instead of being run on the name the file was opened by, which
  may by then be another file. A directory has no native handle: `opendir`
  reads its entries once and `getdents` serves that snapshot; `fchdir` and a
  relative path under a `dirfd` are refused. `O_CREAT | O_EXCL` is refused
  (`EINVAL`, as the Linux personality does): the native open cannot refuse an
  existing file, and a check before it would race with it. `mkstemp`, `tmpfile`
  and `fopen("x")` fail until the native open can say "create only".
- **Processes**: `posix_spawn` is `SYS_SPAWN_EX`, the file actions become its move
  list (a moved handle leaves the parent); `waitpid` polls `DOMAIN_WAIT`.
  `fork` and `exec*` do not exist.
- **Threads**: `SYS_THREAD_CREATE` with a thread pointer, `SYS_FUTEX_*`.
- **Memory**: anonymous `mmap` over `SYS_MO_MAP`; the allocator is relibc's dlmalloc.
- **Time**: the vDSO clocks, no trap: monotonic, and `CLOCK_REALTIME`,
  `CLOCK_TAI` and `CLOCK_BOOTTIME` as monotonic plus the offset the kernel
  publishes. `CLOCK_REALTIME` and `CLOCK_TAI` read as time since boot until a
  time source (NTP, PTP) has set the wall clock.
- **Entry** (`start.rs`): `_azos_entry` (the entry the target spec names) reads the startup block and lays out the System V
  stack relibc expects. On **x86_64** ring 3 cannot set its FS base, so the first
  thread builds the TCB and hands `main` to a second thread created with it as
  thread pointer.
- **Refused with `ENOSYS`** (`absent.rs` and `mod.rs`): signals (`kill` is a stop
  request, `SYS_ALERT`), sockets, `epoll`, `ptrace`, links, modes, owners, seek.

Source: `userspace/lib/relibc-azos/overlay/src/platform/azos/` (`mod.rs`,
`fdtab.rs`, `fs.rs`, `proc.rs`, `mem.rs`, `time.rs`, `start.rs`, `absent.rs`).

## Building a C program

```
tools/third_party_fetch.sh relibc && make relibc   # needs zig; CONFIG_RELIBC=y: $AZOS_OUT/build/relibc/<isa>/{hello,tinybox}.elf
```

Link with `tools/relibc_build.sh cc <isa> OUT.elf SRC.c..`: `-D__azos__`, the relibc
headers (`$AZOS_OUT/build/relibc/include`), `-nostdlib -static`, the layout of the ISA's
target spec (`tools/user_link_args.py --driver`: a static executable at its image base
and entry) and `libc.a`.

The programs: `userspace/tests/relibc/hello.c` (the startup), `tinybox.c` (cat, wc,
ls, mkdir, rm, run, threads, sleep, ...).

Source: `tools/relibc_build.sh`, `userspace/tests/relibc/`.

## Moving the pin

Change the gitlink (`git update-index --cacheinfo 160000,<commit>,third_party/relibc`),
run `tools/third_party_fetch.sh relibc`, then re-apply the
patches (`tools/relibc_build.sh prepare` fails on a hunk that does not apply;
`tools/relibc_build.sh diff` prints the patch a repaired work tree amounts to).
