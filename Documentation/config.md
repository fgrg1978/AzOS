<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# Configuration

AzOS is configured with Kconfig. The Kconfig files are the only source of what a build
contains and how it is sized; there is no second table in a Makefile, a cargo manifest or
a script. This page covers the source tree of the options, the presets and defconfigs, the
bridge to cargo, and how to add an option. Build commands are in [building.md](building.md).

## Single source

Source: `Kconfig`, `config/`, `tools/kconfig_lint.py`, `kernel/Cargo.toml`.

The root `Kconfig` sources every fragment under `config/`. `.config` is generated and
ignored by git; the fragments are the source.

| Fragment | What it holds |
|---|---|
| `config/axes/Kconfig.preset` | The preset and the profile axes (below). |
| `config/axes/Kconfig.use` | The `USE` axis: what the image is for, derived from the preset and never asked. |
| `config/domains/Kconfig.robot`, `config/domains/Kconfig.brain` | The robot domain menus, shown only for `USE_ROBOT`. |
| `config/arch/Kconfig.isa` | ISA selection and the hardware support model (below). |
| `config/axes/Kconfig.virt` | The hypervisor core (`HV`, `HV_REQUIRE`, `HV_MAX_VCPUS`). |
| `config/arch/Kconfig.platform` | Board selection and platform addresses, and the x86_64 platform menu. |
| `config/limits/Kconfig.limits` | The resource cap table: every static-array bound, with defaults per hardware class. |
| `config/kernel/Kconfig.sched` | Scheduler, IPC, timers and watchdog. |
| `config/subsys/Kconfig.net` | Ethernet and the TCP/IP stack parameters. |
| `config/subsys/Kconfig.ota`, `config/axes/Kconfig.security` | Secure boot, link encryption, hardening, the threat model. |
| `config/subsys/Kconfig.packages`, `config/subsys/Kconfig.ota` | Signed application packages and OTA updates. |
| `config/subsys/Kconfig.drivers` | Driver enables and per-driver placement (kernel or ring 3). |
| `config/axes/Kconfig.personality` | The Linux compatibility layer. |
| `config/axes/Kconfig.libc` | `CONFIG_RELIBC`, the C library for ported C programs. |
| `Kconfig.userspace` | Generated at every parse by `tools/gen_userspace_kconfig.py` from the directories under `userspace/`; never committed. |
| `config/kernel/Kconfig.trace` | Build type, debug probes, in-kernel tests, tracing, logging. |
| `config/kernel/Kconfig.micro` | The MCU kernel (`micro/`). |

`tools/kconfig_lint.py` enforces the single-source rule: every `# cargo-feature:` tag names a
feature of `kernel/Cargo.toml` and sits in a `config` block of an existing symbol, each
feature has exactly one owning symbol, no `select` forces a visible symbol, and
`kernel/Cargo.toml` has no `default` features.

## Axes and presets

Source: `config/axes/Kconfig.preset`, `config/axes/Kconfig.use`, `config/axes/Kconfig.virt`,
`config/kernel/Kconfig.trace`, `tools/check_presets.py`.

One `PRESET` choice sets the defaults of every axis, and through them the options the axes
own. A preset works through `default ... if PRESET_*` lines and `imply`; it never `select`s,
so a value set by hand wins. A defconfig is one `PRESET` line plus its machine lines (ISA,
board, RAM, hardware class).

| Axis | Symbols | Values | What it decides |
|---|---|---|---|
| Preset | `PRESET_*` | `GENERIC`, `ROBOT`, `INDUSTRIAL`, `AUTOMOTIVE`, `FIRMWARE`, `IOT_HMI`, `WEARABLE`, `GATEWAY`, `DESKTOP`, `SERVER` | The starting value of all other axes. |
| Use | `USE_*` | one per preset | Which crates are linked (`USE_ROBOT` links the robot crates under `domains/robot/`) and which menus show. Every use links the shared actuation authority. |
| Hardware class | `HWCLASS_*` | `EMBEDDED`, `SBC`, `DESKTOP`, `SERVER` | The resource-limit tier: embedded the smallest tables, `SBC` and `DESKTOP` the edge tables, `SERVER` the fleet tables. |
| Structure | `STRUCTURE_*` | `HYBRID`, `RING3_DRIVERS` | Where drivers run: each as its own placement choice says, or every placeable driver in ring 3. Drivers a safety decision reads have no placement choice and stay in the kernel. |
| Real-time class | `RT_*` | `NONE`, `SOFT`, `HARD`, `MIXED` | What the image promises about time. Hard and mixed need memory committed at map time. |
| Security posture | `SECURITY_*` | `GENERAL`, `HARDENED`, `SEPARATION_STATIC`, `CONFIDENTIAL` | The threat model and the default of mandatory OTA signatures. |
| Virtualization role | `VIRT_*` | `NONE`, `HOSTED`, `SPLIT`, `STATIC` | The hypervisor role (see [virtualization.md](virtualization.md)). |
| Build type | `BUILD_TYPE_*` | `DEV`, `RELEASE`, `CERTIFIABLE` | Named by the defconfig, not keyed on the board or the preset: release is the default and every QEMU defconfig says `BUILD_TYPE_DEV`. A release build forces off the test-only machinery (`KTEST`, `CHAOS`, `CANARY_RUNTIME`) and refuses the test signing key. |

The limits in `config/limits/Kconfig.limits` default by `HWCLASS` directly: `HWCLASS_EMBEDDED`,
`HWCLASS_SBC || HWCLASS_DESKTOP` (the edge tables) and `HWCLASS_SERVER` (the fleet tables).

| Preset | USE | Real-time class | Security | Notes |
|---|---|---|---|---|
| Generic | generic | none | general | General-purpose kernel. |
| Robot | robot | hard | general | Links the robot crates; write-ahead receipts for ring-3 motor ops. |
| Industrial | industrial | hard | separation, static | `VIRT` static; memory committed at map time. |
| Automotive | automotive | hard | separation, static | As industrial. |
| Firmware | firmware | soft | hardened | Hardware class embedded. |
| IoT / HMI | iot-hmi | soft | hardened | Display, touch, battery. |
| Wearable | wearable | soft | hardened | Hardware class embedded. |
| Gateway | gateway | soft | hardened | Larger network tables. |
| Desktop | desktop | soft | hardened | Hardware class desktop; demand paging; `VIRT` hosted on x86_64, split on aarch64. |
| Server | server | none | hardened | Hardware class server; `VIRT` hosted on x86_64, split on aarch64. |

`make check-presets` expands every preset on every ISA and hands the result to
`tools/kconfig_to_cargo.py`; it fails when an expansion warns, the preset is not the one
that came out, or a small board enables a Linux adapter layer or a driver its topology
does not name.

### Hardware support model

Source: `config/arch/Kconfig.isa-riscv64`, `tools/kconfig_to_cargo.py`, `crates/core/limits/build.rs`.

Every ISA is configured the same way. Each ISA has a baseline level (`RISCV64_LEVEL`,
`AARCH64_LEVEL`, `X86_64_LEVEL`) that is the only thing codegen assumes for the whole kernel
and its user images, and is checked at boot. Each optional extension is a three-way choice:

| Value | Meaning |
|---|---|
| `n` (never) | Not used even when the CPU has it; its path is compiled out and the vDSO hwcap hides it. |
| `probe` | Compiled in, used only when the boot probe finds it, with a fallback. |
| `require` | Part of the baseline: codegen may assume it and the boot refuses a CPU without it. |

`crates/core/limits/build.rs` refuses a `.config` whose level and extensions disagree (an
extension the level includes must be `require`), and checks the kernel's target features
against the ones `tools/kconfig_to_cargo.py --target-features` derives.

### Defconfigs

Source: `config/defconfigs/`.

`make defconfig-<name>` copies `config/defconfigs/<name>.config` to `.config` and runs
`olddefconfig`. The hardware-class and use presets:

| Defconfig | Preset | Hardware class | ISA |
|---|---|---|---|
| `edge` | Generic | single-board computer | riscv64 |
| `embedded` | Generic | embedded | riscv64 |
| `fleet` | Generic | server | riscv64 |
| `qemu`, `robot-edge` | Robot | single-board computer | riscv64 |
| `robot-embedded` | Robot | embedded | riscv64 |
| `robot-fleet` | Robot | server | riscv64 |
| `experimental` | Robot | single-board computer | riscv64 |
| `qemu-aarch64` | Robot | single-board computer | aarch64 |
| `qemu-x86_64`, `qemu-x86_64-limine`, `qemu-x86_64-pci` | Robot | single-board computer | x86_64 |
| `qemu-hv`, `qemu-aarch64-hv`, `qemu-x86_64-hv` | Robot with a `VIRT` role | single-board computer | riscv64, aarch64, x86_64 |
| `micro` | Generic | embedded | riscv32 (the MCU kernel) |

The other files in the directory are board defconfigs; each sets a `BOARD_*` choice on
top of a preset. `make savedefconfig` writes the minimal form of `.config` to
`last_saved.config` in `config/defconfigs/`.

## From Kconfig to the build

Source: `tools/kconfig_to_cargo.py`, `crates/core/azos-config/src/lib.rs`,
`crates/core/limits/build.rs`, `crates/core/limits/src/lib.rs`,
`tools/gen_userspace_kconfig.py`, `tools/out_dir.py`.

A Kconfig symbol reaches the build in one of two ways.

**As a constant.** `crates/core/limits/build.rs` reads `.config` (the path in
`KCONFIG_CONFIG`, else `.config` at the workspace root), validates it, and writes
`generated.rs` into the crate's output directory. Every integer, bool and string option
becomes a `pub const` of the crate `azos_limits`, named after the symbol with `CONFIG_`
stripped. Code reads it as `azos_limits::NAME`.

| `.config` value | Rust constant |
|---|---|
| `y` / `n` | `bool` |
| `0x...` | `usize` |
| decimal integer | by the symbol's suffix: `_ATTEMPTS`, `_PROBES`, `_MULT`, `_FREQ`, `_CPUS`, `_HZ`, `_MM` give `u32`; `_TICKS`, `_MS`, `_US` give `u64`; `_BYTES`, `_SIZE`, `_COUNT`, `_KB`, `_MB` and anything else give `usize` |
| anything else | `&str` |

A few keys also get an extra `_BYTES` constant (`KERNEL_HEAP_SIZE`, the `*_STACK_SIZE_KB`
keys, `OTA_MAX_IMAGE_SIZE_MB`). A bool that a valid `.config` leaves out because its menu
is hidden is filled in as `n`, so code compiled into every image can read it. The build
fails with the option names when a combination is invalid, for example an ISA
level that disagrees with its extensions, or a console program path that is not an 8.3 image
directly under `/fat`.

**As a cargo feature.** A symbol that owns a kernel cargo feature says so inside its own
block with a tag (below). `tools/kconfig_to_cargo.py` reads the tags from the Kconfig files
and turns a `.config` into cargo arguments:

| Invocation | Output |
|---|---|
| `python3 tools/kconfig_to_cargo.py [.config]` | `--target <triple>` and `--features a,b,...` for the kernel build |
| `--base` | only the `base` features: those that shape the image whatever board or test feature a recipe names by hand |
| `--rustflags` / `--user-rustflags` | the ISA baseline codegen flags of the kernel / of the ring-3 images; add `--toml` for the inside of a TOML array |
| `--target-features` | the feature lists `crates/core/limits/build.rs` checks the kernel build against |
| `--sdk-env` | the environment variables of the std port layer, one per line |

The target comes from the `ARCH_*` choice: `riscv64imac-unknown-none-elf`,
`aarch64-unknown-none-softfloat` (the kernel is soft-float; ring-3 images are hard-float)
and `x86_64-unknown-none`. A `.config` whose driver placement puts a safety-read driver in
ring 3 is refused.

## Adding an option

Source: `tools/kconfig_to_cargo.py`, `tools/kconfig_lint.py`, `crates/core/limits/build.rs`,
`config/limits/Kconfig.limits`.

1. **Declare it** in the fragment that owns its subject, with a type, a prompt (or none for
   a derived symbol), a `default` per hardware class where the value is a size, and a
   `help` text that says what it costs:
   ```
   config MY_TABLE_ENTRIES
       int "Entries in my table"
       range 8 4096
       default 16   if HWCLASS_EMBEDDED
       default 1024 if HWCLASS_SERVER
       default 64
       help
         What the table holds, and the cost in RAM per entry.
   ```
   Presets and axes set defaults through `default ... if` and `imply`. Do not `select` a
   symbol that has a prompt (`tools/kconfig_lint.py` refuses it); use `depends on`.
2. **Use it.** For a size or a switch, import it: `azos_limits::MY_TABLE_ENTRIES`. A new
   symbol needs a real consumer (`tools/kconfig_lint.py` refuses a symbol nothing reads,
   a symbol defined twice, and a symbol whose defaults all give one value); a symbol nothing
   imports changes nothing when it is edited (`python3 tools/gen_config_index.py --list` lists every declared symbol).
3. **If it selects code**, give the symbol a cargo feature: add `# cargo-feature: my-feature`
   as the first line of its block (`# cargo-feature: my-feature base` also puts it in the
   output of `--base`), and declare `my-feature` in `kernel/Cargo.toml`. One symbol owns
   one feature, and the tag must sit inside a `config` block.
4. **If it is a program under `userspace/`,** do not write Kconfig by hand: add
   `[package.metadata.azos]` to the crate's `Cargo.toml` (`images`, `topology`, `default`,
   `start`); `tools/gen_userspace_kconfig.py` generates the options.
5. **Refresh and check.**
   ```sh
   make olddefconfig         # update .config with the new symbol's default
   make check-presets        # every preset still expands on every ISA
   python3 tools/kconfig_lint.py
   python3 tools/gen_feature_matrix.py   # regenerate Documentation/os-feature-matrix.md
   make check0               # type-check the three ISAs and run the host suites the diff reaches
   ```
   If a defconfig needs a non-default value, set it in that file; the rest of the
   defconfigs take the default.

[os-feature-matrix.md](os-feature-matrix.md) lists every switch and choice with its value in
each defconfig. It is generated by `tools/gen_feature_matrix.py`, and the N0 gate fails when
it is stale.

A value is changed with `make config` (menuconfig), `make nconfig`, `make oldconfig`
(ask for new symbols) or `make olddefconfig` (take defaults).
