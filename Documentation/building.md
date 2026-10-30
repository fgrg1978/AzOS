<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# Building and testing

How to build the kernel and the ring-3 programs for the three ISAs, where the outputs
go, how to run them in QEMU, and which checks to run when. `make help` prints the target
list. Configuration is in [config.md](config.md); writing programs is in [sdk.md](sdk.md).

## Toolchains

Source: `rust-toolchain.toml`, `.cargo/config.toml`, `Makefile`, `mk/vars.mk`,
`tools/build/relibc_build.sh`, `deny.toml`.

| Tool | Used for |
|---|---|
| Rust nightly with `rust-src` and `llvm-tools-preview` | Everything. `rust-toolchain.toml` pins a dated nightly, so every build uses one compiler. Kernel and ring-3 builds use `-Zbuild-std` (`.cargo/config.toml`), so no prebuilt target is needed. |
| Python 3 with `kconfiglib` | `make config` and every `olddefconfig` step; the build tools under `tools/`. The `PYTHON` make variable names the interpreter (default `/opt/homebrew/bin/python3`, `mk/kernel.mk`). |
| QEMU: `qemu-system-riscv64`, `qemu-system-aarch64`, `qemu-system-x86_64` | `make qemu*` targets and the QEMU scenarios of the gate. |
| `zig`, `cbindgen` | `make relibc` and `make busybox` (C programs): `zig` is the C compiler and linker, `cbindgen` generates relibc's headers. |
| A Linux-targeting `clang` (`LX_CC`) | The Linux module fixtures (`LXTEST.KO`) and the static Linux test program. |
| A container runtime | `make lx-kbuild`, which builds Linux modules with Linux's own Kbuild in a pinned container. Without one the target prints `SKIP: <reason>`. |
| `cargo-deny` | The supply-chain check of the N0 tier, offline. |

The ISA targets are `riscv64imac-unknown-none-elf`, `aarch64-unknown-none-softfloat` (the
kernel) and `x86_64-unknown-none`. Every ring-3 image, `std` or not, is built for the one
target spec of its ISA, `sdk/targets/<isa>-unknown-azos.json` (see [sdk.md](sdk.md)), which
carries the image layout as well: no image has a linker script or a cargo configuration of
its own (`userspace/.cargo/config.toml` is the one; `tools/lint/user_entry_lint.py`). The one
exception is the Linux runtime (`userspace/services/lxrt`) on aarch64 and x86_64, built for
rustc's soft-float targets because it shares the Linux program's FP registers. The target and the codegen flags of every
build come from the expanded Kconfig through `tools/build/kconfig_to_cargo.py`.

## Where outputs go

Source: `tools/lib/out_dir.py`, `mk/vars.mk`, `tools/lint/out_dir_lint.py`.

Every output (kernels, images, ELFs, cargo target directories) lives under `AZOS_OUT`,
never in the checkout. The default is `$HOME/azos-out/<checkout name>-<8 hex digits of its
real path>`: one root per checkout, so two worktrees never share outputs. `python3
tools/lib/out_dir.py` prints it; the `AZOS_OUT` environment variable overrides it.

| Path | Holds |
|---|---|
| `$AZOS_OUT/build/` | Generated configs, hash tables, ELFs, disk images, kernel images |
| `$AZOS_OUT/target/` | The cargo target directory of the root workspace (`CARGO_TARGET_DIR`) |
| `$AZOS_OUT/tgt/<dir>/` | The cargo target directory of the standalone crate at `<dir>` (every crate under `userspace/` and every suite under `tests/host/`) |

Rust sources `include!` generated tables from `$AZOS_OUT/build`, so `AZOS_OUT` is exported
to every command. To run a bare `cargo` command, export `AZOS_OUT` and point
`CARGO_TARGET_DIR` under it. `python3 tools/lint/out_dir_lint.py` fails when a tool writes into
the checkout. `make clean` removes `$AZOS_OUT`; `make prune` deletes stale build variants.

Keys: a development build embeds the test signing key (the pair is generated in
the `keys` directory beside `tools/sign/gen_test_key.py` and is not committed; the `dev-key` feature). A release build refuses
that key and needs `TOPOLOGY_PUBKEY_PATH` to name the fleet public key.

## The configured system

Source: `Makefile`, `mk/vars.mk` ("The configured system"), `mk/kernel.mk`, `mk/qemu.mk`,
`tools/build/make_help.txt`.

`make defconfig`, `make config` (or `make defconfig-<name>`) selects; `make build` builds exactly that;
`make qemu` boots exactly that. The ISA is the configuration's (`CONFIG_ARCH_*`, the
ARCH choice in `config/arch/Kconfig.isa`); no target names one. `make build` builds
the kernel, the ring-3 images and the system volume (the shell volume: the console
program, Kconfig `CONSOLE_PROGRAM`, and every image the topology starts), then
prints where they are:

| | riscv64 | aarch64 | x86_64 |
|---|---|---|---|
| Kernel | `$AZOS_OUT/target/riscv64imac-unknown-none-elf/release/kernel` | `$AZOS_OUT/build/kernel-aarch64.img`, the arm64 Image (`-16k`/`-64k` with another granule) | `$AZOS_OUT/build/kernel-x86_64.elf` |
| System volume | `$AZOS_OUT/build/disk-sh.img` | `$AZOS_OUT/build/disk-aarch64-sh.img` | `$AZOS_OUT/build/disk-x86_64.img` |
| SDK target | `sdk/targets/riscv64imac-unknown-azos.json` | `sdk/targets/aarch64-unknown-azos.json` | `sdk/targets/x86_64-unknown-azos.json` |
| `make qemu` (a copy of the system volume on virtio-blk, `-m` from Kconfig `RAM_SIZE`) | QEMU `virt` | QEMU `virt`, GICv3, entered at EL1 (`qemu-aarch64-el2`: at EL2) | QEMU `microvm`, PVH entry |
| Variants | `build-rvv`, `build-pci`, `qemu-smp`, `qemu-full-smp`, `qemu-rvv`, `qemu-full-smp-rvv`, `qemu-pci` | | `qemu-pci-x86_64`, `run-x86-pc` (each from its own defconfig; q35 with OVMF, booted by Limine; needs `LIMINE_DIR`, `OVMF_CODE`, `OVMF_VARS`) |
| Type-check only | `make ARCH=riscv64 check` | `make ARCH=aarch64 check` | `make ARCH=x86_64 check` |

QEMU runs under TCG on every host. `make qemu-gdb` is `make qemu` with the GDB
stub on :1234 and the CPUs stopped at reset, for the ISA the configuration selects.
A target of one ISA refuses when the
configuration selects another. The internal per-ISA kernel targets (`riscv64`,
`aarch64`, `x86_64`) are what `make build` and the gate call.

Each kernel target expands its configuration with `olddefconfig` into a file under
`$AZOS_OUT/build/`, builds with the target and `--features` that `tools/build/kconfig_to_cargo.py`
prints, and embeds the table of image hashes the seccomp profiles are bound to. Variables:

| Variable | Meaning |
|---|---|
| `ARCH=riscv64\|aarch64\|x86_64` | The ISA of `make check`, `make doc` and `make azos-guest`; the default is the one `.config` selects |
| `AARCH64_PAGE_SIZE=4096\|16384\|65536` | The aarch64 translation granule of the kernel and the programs |
| `QEMU_LOG_LEVEL=err\|warn\|info\|debug` | Log level of the QEMU kernels (default `debug`) |
| `CHECK_SELECT=...` | A selection on the cell `make check` type-checks (`tools/build/kconfig_to_cargo.py --select`), for example `ktest` |
| `CHECK_DEFCONFIG_<isa>=...` | A different defconfig for `make check` |
| `TOPOLOGY_PUBKEY_PATH=<file>` | The topology public key a release build embeds; `vf2`, `k1`, `rpi5` and `build-fleet` refuse to build without it |
| `BUILD_TYPE=DEV` | `vf2` only: a development image (the test key allowed, `KTEST` possible); unset is the product build |
| `NETBOOT_CASE=<case>` | The case `make netboot-row` runs (default `x86-pxe`) |
| `PRUNE_ARGS=--dry-run` | `make prune` only reports |

Other targets:

| Target | What |
|---|---|
| `make sdk`, `make sdk-check` | The std programs for the three ISAs; the port layer's checks ([sdk.md](sdk.md)) |
| `make relibc`, `make busybox` | C programs against relibc; BusyBox for the three ISAs (needs `zig` and the fetched tree, `tools/build/third_party_fetch.sh busybox`) |
| `make micro-config`, `micro-topology`, `micro-check`, `micro`, `micro-test`, `micro-qemu` | The MCU kernel (`micro/`): riscv32imac, M-mode, PMP |
| `make vf2`, `flash-vf2`, `vf2-console`, `vf2-ktest`, `vf2-pstore` | The VisionFive 2 image, writing it to an SD card (`VF2_SD`), its serial console (`VF2_SERIAL`), and the board-farm rows (`tools/dev/farm/README.md`) |
| `make k1`, `flash-k1`, `k1-console` | The same for the SpacemiT K1 (`K1_SD`, `K1_SERIAL`) |
| `make build-fleet` | The Fleet-profile kernel and its board volume |
| `make azos-guest ARCH=riscv64\|aarch64` | The hypervisor kernel, a guest kernel and the host volume that carries it; `tools/dev/run_guest.sh <isa>` boots it |
| `make topology-files` | The signed capability topology files for both ISAs |
| `make sim SIM_DEFCONFIG=<defconfig> SIM_CPUS=<n>` | The host dry boot of a topology: the records its boot admission would write, without a QEMU ([static-topology.md](design/static-topology.md)) |
| `make make-gguf` | The policy file |
| `make qemu-systest` | The system-call test program in ring 3 |
| `make qemu-dhcp-smoke`, `qemu-net-pair` | Network smoke runs |
| `make lx-kbuild`, `lx-compare` | Linux modules built by Linux's Kbuild in a container; instruction counts against Linux on the same QEMU |
| `make ota-send`, `tftp-serve`, `boot-scr` | Send firmware over TCP; serve it over TFTP; the U-Boot A/B slot-selection script |
| `make worktree-seed FROM=<worktree>` | Seed a fresh worktree's cargo caches from another |

The hypervisor kernels use the `*-hv` defconfigs and QEMU CPU options that expose the
extension (`-cpu rv64,h=true` on riscv64, `virtualization=on` on aarch64, `-cpu max,svm=on`
on x86_64); `tools/dev/qemu.sh` lists the modes. See [virtualization.md](virtualization.md).

## Network boot

Source: `tools/gate/netboot/`, `mk/qemu.mk` (`netboot-row`, `netboot-uboot`), the `netboot ...` rows of
`tools/gate/ci_check.sh`.

A machine with nothing on a disk fetches AzOS over the network. The rows boot QEMU with no drive
(only the firmware's flash banks and a NIC) and judge the console; each path has canaries that
sabotage the fetch and pass only on the loader's named refusal.

| | Firmware | Path | Rows |
|---|---|---|---|
| x86_64 | OVMF (QEMU's edk2) on q35 | UEFI PXE: DHCP names `BOOTX64.EFI` (Limine), TFTP serves it; Limine reads its configuration and the kernel from the same server | `x86-pxe` |
| x86_64 | OVMF | UEFI HTTP Boot: the DHCP bootfile is an `http://` URL of an ESP image, served by a host HTTP server on a port of the row's own; the firmware registers it as a RAM disk and runs the Limine in it | `x86-http` |
| riscv64 | OpenSBI, then U-Boot 2025.07 (`qemu-riscv64_smode`) | a boot script runs `dhcp` + `tftpboot` of a signed FIT image, then `bootm` | `riscv64-tftp` |
| aarch64 | | none: the kernel is an arm64 `Image` without a PE/COFF header, which edk2's PXE and HTTP Boot cannot run | none |

```sh
make netboot-row NETBOOT_CASE=x86-pxe        # builds the kernel image, boots the case; exit status = verdict
make netboot-uboot                           # the riscv64 U-Boot, built under $AZOS_OUT/netboot
```

`tools/gate/netboot/row.sh` lists the cases. Each path has a canary for a bootfile the server does not
have; the Limine paths one for a changed kernel byte (`-badkernel`) and one for a changed configuration
(`x86-pxe-badconfig`); the U-Boot path one for a changed kernel (`-badkernel`) and one for an image signed
by a key the device tree does not hold (`-badkey`).

What verifies the fetched image is the loader, because the kernel's own secure-boot gate
(`[SECURE-BOOT]`, `crates/core/ota`) judges `KERN_A.BIN` on the FAT volume and a machine with no disk
has none (the diskless console reads `[SECURE-BOOT] Slot A signature: unverified (no trusted signing key
embedded (dev build))`, which the rows do not judge). So:

- riscv64: U-Boot (`CONFIG_FIT_SIGNATURE`) refuses a FIT whose configuration is not signed
  (`sha256,rsa2048`) by a key of its control device tree marked `required`, or whose kernel hash differs.
  The rows print its lines (`Verifying Hash Integrity ... sha256,rsa2048:azos-netboot+ OK`, then
  `sha256+ OK`). Under QEMU the control device tree is QEMU's own with the key added (`-dtb`), and the
  script U-Boot runs sits where its `boot.scr` is read to (`-device loader`).
- x86_64: Limine checks the BLAKE2B-512 the configuration names for the kernel
  (`path: boot():/boot/kernel.elf#<hash>`), and the BLAKE2B of the configuration enrolled in
  `BOOTX64.EFI` (`limine enroll-config`). It is silent when the hash matches; the canaries show it
  panics (`Blake2b hash for URI ... does not match`, `CHECKSUM MISMATCH FOR CONFIG FILE`) when it does
  not. What authenticates `BOOTX64.EFI` itself is the firmware's Secure Boot, which these rows do not
  turn on.

The keys are throwaway test keys made per run; no release key is read.

Needs: QEMU's edk2 images (`OVMF_CODE`), Limine 10.x binaries (`LIMINE_DIR`, default
`third_party/limine`, fetched by `tools/build/third_party_fetch.sh limine`), `mkfs.fat` and mtools, `mkimage` and `dtc`, `openssl`, and for U-Boot a riscv64 GCC
(`riscv64-unknown-elf-gcc`), GNU make and an `ld.lld` (rustc's own is used): the bare-metal GNU linker
cannot make U-Boot's `-pie` image. U-Boot is built from the pinned tree (`third_party/u-boot`,
`tools/build/third_party_fetch.sh u-boot`) out of tree in `$AZOS_OUT/netboot`; the checkout is never
written. A row exits "skipped" when one of these is absent.

The riscv64 row boots a FIT with `bootm` rather than `booti` on the flat `kernel.bin`: a signature cannot
ride on a flat binary. (`booti` would take it: `_start` opens with the Linux RISC-V Image header,
checked by `tools/gate/image_header.py`, and `tools/image/boot.cmd` and `tools/dev/farm/boot.cmd` boot it that way.)

## Host tests

Source: `tests/host/`, `tools/gate/rows_for_diff.py`.

Logic that does not need a kernel runs on the host. Each directory under `tests/host/` is a
standalone crate that pulls the shipped source in by path (for example `libsys-tests`
includes `crates/core/libsys/src/pure.rs` with `#[path]`), so the code under test is the
shipped code and not a copy. Run one suite with its own target directory:

```sh
cd tests/host/<suite> && CARGO_TARGET_DIR=$AZOS_OUT/tgt/tests/host/<suite> cargo test --release
```

`tools/gate/rows_for_diff.py --host` prints the suites that a diff reaches: a suite is selected
when a changed path is in it, in a crate it reaches through `path =` or `workspace = true`
dependencies, or in the directory of a file it (or such a crate) pulls in with `#[path]` or
`include!` (`tools/gate/gate_rows.py`'s crate graph, which the row deps below also use).
`tests/fuzz/` holds the `cargo-fuzz` targets, run by `tools/gate/fuzz.sh`.

## ktest

Source: `crates/core/ktest/src/lib.rs`, `kernel/src/ktest.rs`, `config/axes/Kconfig.build`.

`ktest!` defines an in-kernel test, `fn() -> Result<(), &'static str>`, and places its entry
in the `azos_ktest` link section, which every kernel linker script brackets with
`__start_azos_ktest` and `__stop_azos_ktest`. The tests are compiled only with Kconfig
`KTEST` (the kernel feature `ktest`, development builds only); with the feature off the crate
is not in the dependency graph and the section is empty. A ktest kernel runs the registry
at boot, prints TAP on the console, and powers off. On aarch64 it leaves QEMU through
semihosting `SYS_EXIT` (`KTEST_SEMIHOSTING_EXIT`), because PSCI `SYSTEM_OFF` carries no status.

| Phase | Macro | Runs |
|---|---|---|
| `EARLY` | `ktest!` | on the boot hart, after boot init, before the scheduler starts |
| `LATE` | `ktest_late!` | in a kernel task once the scheduler started and every hart is online, so a test may create tasks and block |

Tests run in order of phase and then name, not link order. The kernel does not unwind: a
panic ends the run, and the panic handler reports the test that was running as failed. The
same registry serves ring 3 through `#[azos::test]` ([sdk.md](sdk.md)).

## Check tiers

Source: `mk/lints.mk`, `tools/gate/gate_tier.sh`, `tools/gate/ci_check.sh`, `tools/gate/check_fast.sh`,
`tools/gate/gate_rows.tsv`, `tools/gate/rows_for_diff.py`.

| Tier | Command | What it runs |
|---|---|---|
| N0, the edit loop | `make check0` | `make ARCH=<isa> check` for the three ISAs, the lints below, `cargo deny`, and the host suites the diff reaches |
| N1, the change check | `make check1` | N0's suites, then the per-ISA smoke boots and the QEMU gate rows that the diff maps to |
| Fronts' check | `make check-fast` | Per ISA: one ktest boot, one boot of the same kernel with every composable runtime canary armed, and one userspace boot (the ABI conformance checks) |
| Full | `make ci` | `tools/gate/ci_check.sh`: every feature combination built with zero warnings, every host suite, every lint, and every QEMU scenario |
| Full, with the brain | `make ci-full` | `make ci`, then the AzOSRobotBrain tests and the protocol sync check (`tools/gate/ci_full.sh`) |
| Presets | `make check-presets` | Every preset expands on every ISA ([config.md](config.md)) |
| Topology rules | `make check-neverallow` | No preset's, defconfig's or the MCU kernel's topology breaks a `neverallow` rule |

`tools/gate/gate_rows.tsv` lists every gate row with its tier (`n1` rows may run in the change
check; `n2` rows run only in the full gate) and the path globs that select it. A row's globs
must cover what it demonstrably reads (`tools/gate/gate_rows.py` `required_deps`): its host suite
and that suite's crate closure, the scripts and fixtures its call and functions name, the
programs of the disk image it boots, the optional crates and test-hook files of its features,
and the files that print the markers it waits for. `python3 tools/gate/gate_rows.py --check-deps`
names each row and source a manifest line misses, `--check` runs it with the other manifest
checks, and `--write` adds the missing globs and keeps every existing one; a source edit that
moves a marker or a hook turns the check red until `--write` runs.

`tools/gate/rows_for_diff.py --rows` maps a diff to rows: the per-ISA smoke boots first, then the
rows whose globs name a changed file itself or whose gate code changed (the row with the
fewest globs first), then the representative rows of a core change (build graph, config,
boot, trap, `kernel/src/smokes/`), then the other glob hits; at most `GATE_N1_MAX_ROWS`
(default 16) run, and the rest are named for `make ci`. The diff is the working tree against
`GATE_BASE` (default `HEAD`); `GATE_DRY=1` prints what would run.
Knobs of the full gate: `CI_TIER=fast` (every build, host and lint row, one QEMU row per
subsystem per ISA) or `CI_TIER=rows` with `CI_ROWS` (the rows named); `CI_JOBS` or
`GATE_JOBS` (jobs at once, default 4); `CI_SKIP_QEMU=1`; `CI_SKIP_FUZZ=1`; `CI_INJECT_FAIL=<row>` (a
canary: that row must fail). Per-row timing goes to `$AZOS_OUT/build/ci-logs/timing.tsv`. The
gate is run by hand; there is no hosted CI.

A QEMU row that reached its marker also fails when its console printed a warning (`tools/gate/console_judge.py`):
a console program that gave up, a component or program that did not run or is not on the volume, lockdep, a
`WARN`/`WARNING` line, a recovery fallback, a ktest bail-out. Every row gets this through `ok()`, so no row calls it:
the gate puts `tools/gate/qemu_tap.py` first on `PATH` as `qemu-system-<arch>`; it notes the file QEMU's console goes
to and becomes QEMU. A warning a row provokes on purpose, or a development image prints on every boot, is listed
with its reason in `tools/gate/console_allow.tsv` (row-label regex, class, line regex, reason). The end of a gate
run prints how many rows were judged. `CI_CONSOLE_JUDGE=0` turns the judge off; `CI_CONSOLE_PLANT=<row label>`
appends a warning line to that row's console first, the canary that a passing row then fails.

### Lints

N0 runs each lint after its own self-test, so a lint that went blind fails.

| Lint | Command | Rule |
|---|---|---|
| Output directory | `python3 tools/lint/out_dir_lint.py` | nothing writes into the checkout |
| Boot sequence | `python3 tools/lint/boot_seq_lint.py` | the order of boot steps |
| Facade bypass | `python3 tools/lint/arch_cfg_lint.py --facade` | shared code does not reach ISA-specific modules; per-file counts are ratcheted in `tools/lint/arch_cfg_lint.baseline` |
| Trap layer | `python3 tools/lint/trap_lint.py` | the trap layer is written once: no dispatch logic in `entry/<isa>/`, a case for every system-call number |
| Arch layout | `python3 tools/lint/arch_layout_lint.py` | the three ISAs share one file layout; ISA-only code is under `ext/` |
| Kconfig | `python3 tools/lint/kconfig_lint.py` | Kconfig is the only source of the feature set ([config.md](config.md)) |
| Unsafe budget | `make unsafe-budget` (`python3 tools/lint/unsafe_budget.py`) | a crate carries no more `unsafe` than `tools/lint/unsafe_budget.tsv` says, keeps its `#![forbid(unsafe_code)]`, and a kernel crate's share of code lines in files with `unsafe` (and the kernel's total) does not rise; `--report` prints the shares |
| Size budget | `make size-check` | the riscv64 QEMU defconfig kernel's `.text`/`.rodata`/`.data`/`.bss` stay within 0.25% of `tools/lint/size_budget.tsv`; `make size-update REASON=".."` moves it in the commit that changes the image; `python3 tools/lint/size_budget.py --memory [LABEL=ELF[,CONFIG]]` prints an ELF's static memory (sections, per crate, large buffers, board fit) |
| Presets | `python3 tools/lint/check_presets.py` | every preset expands on every ISA |
| Feature matrix | `python3 tools/build/gen_feature_matrix.py --check` | `Documentation/os-feature-matrix.md` is what the Kconfig tree and the defconfigs yield |
| Make help | `bash tools/lint/check_make_help.sh` | `make help` names no target the Makefile lacks |
| Documentation | `python3 tools/lint/doc_lint.py` | every path and relative link in the public docs exists; `Documentation/README.md` links every file |
| Requirement trace | `python3 tools/lint/req_trace.py` | the `// REQ-nnn` tags in the code agree with `formal/INVARIANTS.md` |
| Gate rows manifest | `python3 tools/gate/gate_rows.py --check` | `tools/gate/gate_rows.tsv` names exactly the gate's rows, and each row's globs cover what it reads; `tools/gate/rows_for_diff.py --self-test` runs first |
| SPDX headers | `python3 tools/lint/spdx_headers.py --check` | every tracked source file carries its licence header |
| Conflict markers | `git grep` | no tracked file outside `third_party/` holds a merge-conflict marker line |
| Config index | `python3 tools/build/gen_config_index.py --check` | `Documentation/config.md`'s option index is what the Kconfig tree declares; `--self-test` runs first |
| Kernel constants | `python3 tools/build/export_kernel_consts.py --self-test` | every Kconfig symbol the brain's constant mirror exports is declared (`make ci-full` compares the mirror itself) |
| Zbc CRC constants | `python3 tools/build/lx_kbuild/zbc_crc_constants.py` | the CRC-32 fold constants `crates/drivers/lx/glue/lxbase.c` carries are the derived ones |
| OTA sender | `python3 tools/dev/ota_send.py --self-test` | the sender's header and its single and fleet sends, against a localhost receiver |
| Claims scanner | `bash tools/lint/claims_check.sh --self-test` | the absolute-claim scanner still finds what it looks for; the scan of the tree (a review aid that always passes) is by hand |
| Supply chain | `cargo deny check licenses bans sources` | licences, bans and sources of the registry crates (`deny.toml`) |

Other checks live in `tools/`: `tools/lint/aarch64_fp_free_check.sh`
(the kernel names no FP register outside the lazy user-FP save and restore),
and `tools/lint/lx_license_lint.py` (the licences of the Linux driver layer).

## A usual order

```sh
make defconfig              # or: make config, make defconfig-<name>
make check0                 # while editing
make check1                 # before sharing a change
make ci                     # before pushing
```
