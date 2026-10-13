<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# relibc on the native ABI

relibc is Redox's C library, written in Rust (MIT). It is AzOS's **porting layer
for C code** (plan decision D12). POSIX is a personality here, not the native
model: native programs use the SDK, and a C program that wants `open`, `fork`
semantics or `pthread` gets them from this library, as far as the native ABI has
an object for them.

Nothing of relibc is stored in this repository except what AzOS adds to it:

| | |
|---|---|
| `third_party/RELIBC_PIN` | the upstream commit (upstream's last tag is from 2020, so a `master` commit) |
| `tools/relibc_fetch.sh` | shallow-fetches that commit into `~/azos-dl/relibc`, outside the repo |
| `patches/` | the changes to upstream files (MIT, like the tree they patch) |
| `overlay/` | our own files: the `azos` platform module, three target specs, three linker scripts (Apache-2.0 OR GPL-2.0-only) |
| `tools/relibc_build.sh` | copies the checkout, applies the patches and the overlay, builds `libc.a` and C programs |
| `config/Kconfig.relibc` | `CONFIG_RELIBC`: the switch, read from each ISA's own configuration |
| `make relibc` | all of it, for every ISA whose configuration sets `CONFIG_RELIBC=y` (the QEMU defconfigs do) |

`tools/lx_license_lint.py` accepts MIT only in `patches/` (rule T6) and checks the
pin (`--relibc-pin`).

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
  `fork` and `exec*` do not exist (D6).
- **Threads**: `SYS_THREAD_CREATE` with a thread pointer, `SYS_FUTEX_*`.
- **Memory**: anonymous `mmap` over `SYS_MO_MAP`; the allocator is relibc's dlmalloc.
- **Time**: the vDSO monotonic clock; no wall clock is served yet, so
  `CLOCK_REALTIME` reads the same clock.
- **Entry** (`start.rs`): `_start` reads the startup block and lays out the System V
  stack relibc expects. On **x86_64** ring 3 cannot set its FS base, so the first
  thread builds the TCB and hands `main` to a second thread created with it as
  thread pointer.
- **Refused with `ENOSYS`** (`absent.rs` and `mod.rs`): signals (`kill` is a stop
  request, `SYS_ALERT`), sockets, `epoll`, `ptrace`, links, modes, owners, seek.

## Building a C program

```
tools/relibc_fetch.sh && make relibc          # CONFIG_RELIBC=y: build/relibc/<isa>/{hello,tinybox}.elf
```

Link with `tools/relibc_build.sh cc <isa> OUT.elf SRC.c..`: `-D__azos__`, the relibc
headers (`build/relibc/include`), `-nostdlib -static`, the linker script
`build/relibc/<isa>/lib/azos.ld` and `libc.a`.

The programs: `userspace/tests/relibc/hello.c` (the startup), `tinybox.c` (cat, wc,
ls, mkdir, rm, run, threads, sleep, ...).

## Moving the pin

Change `third_party/RELIBC_PIN`, run `tools/relibc_fetch.sh`, then re-apply the
patches (`tools/relibc_build.sh prepare` fails on a hunk that does not apply;
`tools/relibc_build.sh diff` prints the patch a repaired work tree amounts to).
