<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# Building and testing

How to build the kernel and the ring-3 programs for the three ISAs, where the outputs
go, how to run them in QEMU, and which checks to run when. `make help` prints the target
list. Configuration is in [config.md](config.md); writing programs is in [sdk.md](sdk.md).

## Toolchains

Source: `rust-toolchain.toml`, `.cargo/config.toml`, `Makefile`, `mk/vars.mk`,
`tools/relibc_build.sh`, `deny.toml`.

| Tool | Used for |
|---|---|
| Rust nightly with `rust-src` and `llvm-tools-preview` | Everything. `rust-toolchain.toml` pins the channel, so every build uses one compiler. Kernel and ring-3 builds use `-Zbuild-std` (`.cargo/config.toml`), so no prebuilt target is needed. |
| Python 3 with `kconfiglib` | `make config` and every `olddefconfig` step; the build tools under `tools/`. The `PYTHON` make variable names the interpreter. |
| QEMU: `qemu-system-riscv64`, `qemu-system-aarch64`, `qemu-system-x86_64` | `make qemu*` targets and the QEMU scenarios of the gate. |
| `zig`, `cbindgen` | `make relibc` and `make busybox` (C programs): `zig` is the C compiler and linker, `cbindgen` generates relibc's headers. |
| A Linux-targeting `clang` (`LX_CC`) | The Linux module fixtures (`LXTEST.KO`) and the static Linux test program. |
| A container runtime | `make lx-kbuild`, which builds Linux modules with Linux's own Kbuild in a pinned container. Without one the target prints `SKIP: <reason>`. |
| `cargo-deny` | The supply-chain check of the N0 tier, offline. |

The ISA targets are `riscv64imac-unknown-none-elf`, `aarch64-unknown-none-softfloat` (the
kernel) and `x86_64-unknown-none`; ring-3 images use the hard-float `aarch64-unknown-none`
and, for x86_64, the spec `userspace/x86_64-azos-user.json`. The std SDK targets are
`<isa>-unknown-azos` (see [sdk.md](sdk.md)). The target and the codegen flags of every
build come from the expanded Kconfig through `tools/kconfig_to_cargo.py`.

## Where outputs go

Source: `tools/out_dir.py`, `mk/vars.mk`, `tools/out_dir_lint.py`.

Every output (kernels, images, ELFs, cargo target directories) lives under `AZOS_OUT`,
never in the checkout. The default is `$HOME/azos-out/<checkout name>-<8 hex digits of its
real path>`: one root per checkout, so two worktrees never share outputs. `python3
tools/out_dir.py` prints it; the `AZOS_OUT` environment variable overrides it.

| Path | Holds |
|---|---|
| `$AZOS_OUT/build/` | Generated configs, hash tables, ELFs, disk images, kernel images |
| `$AZOS_OUT/target/` | The cargo target directory of the root workspace (`CARGO_TARGET_DIR`) |
| `$AZOS_OUT/tgt/<dir>/` | The cargo target directory of the standalone crate at `<dir>` (every crate under `userspace/` and every suite under `tests/host/`) |

Rust sources `include!` generated tables from `$AZOS_OUT/build`, so `AZOS_OUT` is exported
to every command. To run a bare `cargo` command, export `AZOS_OUT` and point
`CARGO_TARGET_DIR` under it. `python3 tools/out_dir_lint.py` fails when a tool writes into
the checkout. `make clean` removes `$AZOS_OUT`; `make prune` deletes stale build variants.

Keys: a development build embeds the test signing key (the pair is generated in
the `keys` directory beside `tools/gen_test_key.py` and is not committed; the `dev-key` feature). A release build refuses
that key and needs `TOPOLOGY_PUBKEY_PATH` to name the fleet public key.

## Targets per ISA

Source: `Makefile`, `mk/kernel.mk`, `mk/userspace.mk`, `mk/qemu.mk`, `mk/lints.mk`,
`tools/make_help.txt`.

| | riscv64 | aarch64 | x86_64 |
|---|---|---|---|
| Kernel | `make build` (`make build-rvv` adds the vector extension) | `make aarch64` writes `$AZOS_OUT/build/kernel-aarch64.img` | `make x86_64` writes `$AZOS_OUT/build/kernel-x86_64.elf` |
| Ring-3 programs | `make userspace` | `make userspace-aarch64` | `make userspace-x86_64` |
| Run in QEMU | `make qemu`, `qemu-smp` (4 CPUs), `qemu-full-smp` (disk, network, a program), `qemu-rvv`, `qemu-gdb` | `make qemu-aarch64` (entered at EL1), `qemu-aarch64-el2` | `make qemu-x86_64` (microvm); `qemu-pci-x86_64`, `run-x86-pc` |
| Type-check only | `make ARCH=riscv64 check` | `make ARCH=aarch64 check` | `make ARCH=x86_64 check` |
| Default configuration | `config/defconfigs/qemu.config` | `config/defconfigs/qemu-aarch64.config` | `config/defconfigs/qemu-x86_64.config` |

Each kernel target expands its defconfig with `olddefconfig` into a file under
`$AZOS_OUT/build/`, builds with the target and `--features` that `tools/kconfig_to_cargo.py`
prints, and embeds the table of image hashes the seccomp profiles are bound to. Variables:

| Variable | Meaning |
|---|---|
| `AARCH64_PAGE_SIZE=4096\|16384\|65536` | The aarch64 translation granule of the kernel and the programs |
| `QEMU_LOG_LEVEL=err\|warn\|info\|debug` | Log level of the QEMU kernels (default `debug`) |
| `CHECK_FEATURES=...` | Extra cargo features for `make check`, for example `qemu,ktest` |
| `CHECK_DEFCONFIG_<isa>=...` | A different defconfig for `make check` |
| `TOPOLOGY_PUBKEY_PATH=<file>` | The topology public key a release build embeds |

Other targets:

| Target | What |
|---|---|
| `make sdk`, `make sdk-check` | The std programs for the three ISAs; the port layer's checks ([sdk.md](sdk.md)) |
| `make relibc`, `make busybox` | C programs against relibc; BusyBox (needs `zig`) |
| `make micro-config`, `micro-check`, `micro`, `micro-test`, `micro-qemu` | The MCU kernel (`micro/`) |
| `make topology-files` | The signed capability topology files for both ISAs |
| `make make-gguf` | The policy file |
| `make qemu-systest` | The system-call test program in ring 3 |
| `make qemu-dhcp-smoke`, `qemu-net-pair` | Network smoke runs |

The hypervisor kernels use the `*-hv` defconfigs and QEMU CPU options that expose the
extension (`-cpu rv64,h=true` on riscv64, `virtualization=on` on aarch64, `-cpu max,svm=on`
on x86_64); `tools/qemu.sh` lists the modes. See [virtualization.md](virtualization.md).

## Network boot

Source: `tools/netboot/`, `mk/qemu.mk` (`netboot-row`, `netboot-uboot`), the `netboot ...` rows of
`tools/ci_check.sh`.

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

`tools/netboot/row.sh` lists the cases. Each path has a canary for a bootfile the server does not
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
`~/azos-dl/limine`), `mkfs.fat` and mtools, `mkimage` and `dtc`, `openssl`, and for U-Boot a riscv64 GCC
(`riscv64-unknown-elf-gcc`), GNU make and an `ld.lld` (rustc's own is used): the bare-metal GNU linker
cannot make U-Boot's `-pie` image. U-Boot is built from the approved tarball (`U_BOOT_TARBALL`,
digest-checked) in `$AZOS_OUT/netboot`, never in the checkout. A row exits "skipped" when one of
these is absent.

The riscv64 row boots a FIT with `bootm` rather than `booti` on the flat `kernel.bin`: a signature cannot
ride on a flat binary. (`booti` would take it: `_start` opens with the Linux RISC-V Image header,
checked by `tools/image_header.py`, and `tools/boot.cmd` and `tools/farm/boot.cmd` boot it that way.)

## Host tests

Source: `tests/host/`, `tools/rows_for_diff.py`.

Logic that does not need a kernel runs on the host. Each directory under `tests/host/` is a
standalone crate that pulls the shipped source in by path (for example `libsys-tests`
includes `crates/core/libsys/src/pure.rs` with `#[path]`), so the code under test is the
shipped code and not a copy. Run one suite with its own target directory:

```sh
cd tests/host/<suite> && CARGO_TARGET_DIR=$AZOS_OUT/tgt/tests/host/<suite> cargo test --release
```

`tools/rows_for_diff.py --host` prints the suites that a diff reaches: a suite is selected
when a changed path is in it or in a crate it depends on through `path =` dependencies.
`tests/fuzz/` holds the `cargo-fuzz` targets, run by `tools/fuzz.sh`.

## ktest

Source: `crates/core/ktest/src/lib.rs`, `kernel/src/ktest.rs`, `config/Kconfig.development`.

`ktest!` defines an in-kernel test, `fn() -> Result<(), &'static str>`, and places its entry
in the `.azos_ktest` link section, which every kernel linker script brackets with
`__azos_ktest_start` and `__azos_ktest_end`. The tests are compiled only with Kconfig
`KTEST` (the kernel feature `ktest`, development builds only); with the feature off the crate
is not in the dependency graph and the section is empty. A ktest kernel runs the registry
at boot, prints TAP on the console, and powers off.

| Phase | Macro | Runs |
|---|---|---|
| `EARLY` | `ktest!` | on the boot hart, after boot init, before the scheduler starts |
| `LATE` | `ktest_late!` | in a kernel task once the scheduler started and every hart is online, so a test may create tasks and block |

Tests run in order of phase and then name, not link order. The kernel does not unwind: a
panic ends the run, and the panic handler reports the test that was running as failed. The
same registry serves ring 3 through `#[azos::test]` ([sdk.md](sdk.md)).

## Check tiers

Source: `mk/lints.mk`, `tools/gate_tier.sh`, `tools/ci_check.sh`, `tools/check_fast.sh`,
`tools/gate_rows.tsv`, `tools/rows_for_diff.py`.

| Tier | Command | What it runs |
|---|---|---|
| N0, the edit loop | `make check0` | `make ARCH=<isa> check` for the three ISAs, the lints below, `cargo deny`, and the host suites the diff reaches |
| N1, the change check | `make check1` | N0's suites, then the per-ISA smoke boots and the QEMU gate rows that the diff maps to |
| Fronts' check | `make check-fast` | Per ISA: one ktest boot, one boot of the same kernel with every composable runtime canary armed, and one userspace boot (the ABI conformance checks) |
| Full | `make ci` | `tools/ci_check.sh`: every feature combination built with zero warnings, every host suite, every lint, and every QEMU scenario |
| Presets | `make check-presets` | Every preset expands on every ISA ([config.md](config.md)) |
| Topology rules | `make check-neverallow` | No preset's, defconfig's or the MCU kernel's topology breaks a `neverallow` rule |

`tools/gate_rows.tsv` lists every gate row with its tier (`n1` rows may run in the change
check; `n2` rows run only in the full gate) and the path globs that select it. The diff is
the working tree against `GATE_BASE` (default `HEAD`); `GATE_DRY=1` prints what would run.
Knobs of the full gate: `CI_TIER=fast` (every build, host and lint row, one QEMU row per
subsystem per ISA) or `CI_TIER=rows` with `CI_ROWS` (the rows named); `CI_JOBS` or
`GATE_JOBS` (jobs at once); `CI_SKIP_QEMU=1`; `CI_SKIP_FUZZ=1`; `CI_INJECT_FAIL=<row>` (a
canary: that row must fail). Per-row timing goes to `$AZOS_OUT/build/ci-logs/timing.tsv`. The
gate is run by hand; there is no hosted CI.

### Lints

N0 runs each lint after its own self-test, so a lint that went blind fails.

| Lint | Command | Rule |
|---|---|---|
| Output directory | `python3 tools/out_dir_lint.py` | nothing writes into the checkout |
| Boot sequence | `python3 tools/boot_seq_lint.py` | the order of boot steps |
| Facade bypass | `python3 tools/arch_cfg_lint.py --facade` | shared code does not reach ISA-specific modules; per-file counts are ratcheted in `tools/arch_cfg_lint.baseline` |
| Trap layer | `python3 tools/trap_lint.py` | the trap layer is written once: no dispatch logic in `entry/<isa>/`, a case for every system-call number |
| Arch layout | `python3 tools/arch_layout_lint.py` | the three ISAs share one file layout; ISA-only code is under `ext/` |
| Kconfig | `python3 tools/kconfig_lint.py` | Kconfig is the only source of the feature set ([config.md](config.md)) |
| Unsafe budget | `make unsafe-budget` (`python3 tools/unsafe_budget.py`) | a crate carries no more `unsafe` than `tools/unsafe_budget.tsv` says, keeps its `#![forbid(unsafe_code)]`, and a kernel crate's share of code lines in files with `unsafe` (and the kernel's total) does not rise; `--report` prints the shares |
| Size budget | `make size-check` | the riscv64 QEMU defconfig kernel's `.text`/`.rodata`/`.data`/`.bss` stay within 0.25% of `tools/size_budget.tsv`; `make size-update REASON=".."` moves it in the commit that changes the image |
| Presets | `python3 tools/check_presets.py` | every preset expands on every ISA |
| Feature matrix | `python3 tools/gen_feature_matrix.py --check` | `Documentation/os-feature-matrix.md` is what the Kconfig tree and the defconfigs yield |
| Make help | `bash tools/check_make_help.sh` | `make help` names no target the Makefile lacks |
| Supply chain | `cargo deny check licenses bans sources` | licences, bans and sources of the registry crates (`deny.toml`) |

Other checks live in `tools/`: `tools/arch_stub_check.py`, `tools/aarch64_fp_free_check.sh`
(the kernel names no FP register outside the lazy user-FP save and restore),
`tools/lx_license_lint.py` and `tools/spdx_headers.py` (licences).

## A usual order

```sh
make config                 # or: make defconfig-<name>
make check0                 # while editing
make check1                 # before sharing a change
make ci                     # before pushing
```
