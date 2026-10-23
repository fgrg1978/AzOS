<!-- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Fernando Rodriguez -->
# Configuration

AzOS is configured with Kconfig. The Kconfig files are the only source of what a build
contains and how it is sized; there is no second table in a Makefile, a cargo manifest or
a script. This page is the configuration guide: the layout of the Kconfig tree, the axes
and presets, the defconfig matrix, the bridge to cargo, how to add an option, and the
index of every option. Build commands are in [building.md](building.md).

## Layout

Source: `Kconfig`, `config/Kconfig`, `config/*/Kconfig.*`, `tools/kconfig_lint.py`.

The root `Kconfig` sources `config/Kconfig`, which declares the menus and sources one topic
file per subject. A topic file holds only its symbols (and its own sub-menus); `.config` is
generated and ignored by git.

| Directory | What its files hold |
|---|---|
| `config/axes/` | The profile axes: the preset, the hardware class, structure, real-time class, security posture (with the mitigation switches it sets), virtualization role, build type, the application domain (`USE`), the Linux personality and the C library. |
| `config/arch/` | The ISA choice, one file per ISA for its baseline level and extensions, and the board choice with its platform addresses. |
| `config/kernel/` | The core kernel: scheduler, IPC and capabilities, synchronization, memory management, kernel tasks, energy and thermal, panic and crash dump, hardening, live patches, tracing and logging, the lock dependency checker, decision records, and AzOS-micro. |
| `config/subsys/` | Subsystems and drivers: storage, file systems, network, RPC, network services, the signed topology, secure boot, entropy and TPM, the keystore, packages, drivers, USB, display and input, console and login, audio, OTA. |
| `config/domains/` | Application domains, shown only for their `USE`: the robot domain and its brain link. |
| `config/limits/` | The resource cap table: the integers that bound a static table, with defaults per hardware class. |
| config/Kconfig.userspace | Generated at every parse by `tools/gen_userspace_kconfig.py` from the directories under `userspace/`; never committed. |
| `config/fragments/`, `config/defconfigs/` | The defconfig matrix (below). |

The topic files, in menu order:

| File | Topic |
|---|---|
| `config/axes/Kconfig.preset` | `PRESET`, the one choice a defconfig needs |
| `config/axes/Kconfig.hwclass` | `HWCLASS`: the hardware class, the tier the limits key on |
| `config/axes/Kconfig.structure` | `STRUCTURE`: where the drivers run |
| `config/axes/Kconfig.rt` | `RT`: the real-time class |
| `config/axes/Kconfig.security` | `SECURITY` and the mitigation switches it sets |
| `config/axes/Kconfig.virt` | `VIRT` and the hypervisor core (`HV`) |
| `config/axes/Kconfig.build` | `BUILD_TYPE` and the test machinery (ktest, canaries, chaos, census, boot bench) |
| `config/axes/Kconfig.use` | `USE`, derived from the preset |
| `config/domains/Kconfig.robot` | The robot domain: robot type, safety layer, RC input |
| `config/domains/Kconfig.brain` | The brain link |
| `config/arch/Kconfig.isa` | ISA choice, FP state format, page size |
| `config/arch/Kconfig.isa-riscv64`, `-aarch64`, `-x86_64` | Each ISA's baseline level and extensions (n / probe / require) |
| `config/arch/Kconfig.platform` | Board, SoC frameworks, platform addresses |
| `config/limits/Kconfig.limits` | The resource cap table |
| `config/kernel/Kconfig.sched` | Scheduler: tick, classes, balancer, QoS, threaded IRQs |
| `config/kernel/Kconfig.ipc` | IPC, the syscall entry and capabilities |
| `config/kernel/Kconfig.sync` | Locks, futexes, RCU and lock-wait instructions |
| `config/kernel/Kconfig.mm` | TLB, kernel heap, reclaim, swap, page zones |
| `config/kernel/Kconfig.tasks` | Kernel task priorities, supervised restarts, driver placement |
| `config/kernel/Kconfig.energy` | Energy accounting and thermal management |
| `config/kernel/Kconfig.panic` | Panic policy and crash dump |
| `config/kernel/Kconfig.hardening` | User allocator, slab, KASLR, control-flow integrity notes |
| `config/kernel/Kconfig.livepatch` | Kernel live patches |
| `config/subsys/Kconfig.storage` | The block request layer |
| `config/subsys/Kconfig.fs` | File system write-back and deferred free |
| `config/subsys/Kconfig.net` | Ethernet and the TCP/IP stack |
| `config/subsys/Kconfig.rpc` | The RPC link between nodes |
| `config/subsys/Kconfig.netsvc` | NTP, Zenoh, PTP, MCP bridge, SSH |
| `config/subsys/Kconfig.topology` | The signed topology: source, binding, sizing |
| `config/subsys/Kconfig.secure-boot` | Secure boot and link provisioning enforcement |
| `config/subsys/Kconfig.entropy` | Entropy sources and the TPM |
| `config/subsys/Kconfig.keystore` | The keystore |
| `config/subsys/Kconfig.packages` | Signed application packages |
| `config/subsys/Kconfig.drivers` | Driver enables and per-driver placement (kernel or ring 3) |
| `config/subsys/Kconfig.usb` | USB host stack and class drivers |
| `config/subsys/Kconfig.display` | Display, framebuffer, input server, compositor |
| `config/subsys/Kconfig.console` | Console, user shell and login |
| `config/axes/Kconfig.personality` | Linux compatibility (ABI, runtime, driver layer) |
| `config/axes/Kconfig.libc` | The C library (relibc) |
| `config/subsys/Kconfig.audio` | The audio server's policy |
| `config/subsys/Kconfig.ota` | OTA firmware updates |
| `config/kernel/Kconfig.trace` | Logging, tracing, profiling, inspection |
| `config/kernel/Kconfig.lockdep` | The lock dependency checker |
| `config/kernel/Kconfig.decisions` | Decision records |
| `config/kernel/Kconfig.micro` | AzOS-micro, the MCU kernel |

`tools/kconfig_lint.py` enforces the single-source rules: every `# cargo-feature:` tag
names a feature of `kernel/Cargo.toml` and sits in a `config` block of an existing symbol,
each feature has exactly one owning symbol, no `select` forces a visible symbol,
`kernel/Cargo.toml` has no `default` features, every symbol has a reader (code, the build
or another symbol), no symbol is defined twice, and no symbol's defaults all give one
value.

## Axes and presets

Source: `config/axes/`, `tools/check_presets.py`.

One `PRESET` choice sets the defaults of every axis, and through them the options the axes
own. A preset works through `default ... if PRESET_*` lines and `imply`; it never `select`s,
so a value set by hand wins. A hard incompatibility is a `depends on`.

| Axis | Symbols | Values | What it decides |
|---|---|---|---|
| Preset | `PRESET_*` | `GENERIC`, `ROBOT`, `INDUSTRIAL`, `AUTOMOTIVE`, `FIRMWARE`, `IOT_HMI`, `WEARABLE`, `GATEWAY`, `DESKTOP`, `SERVER` | The starting value of all other axes. |
| Use | `USE_*` | one per preset that something reads | Which crates are linked (`USE_ROBOT` links the robot crates under `domains/robot/`) and which menus show. Derived from the preset (`def_bool`), never asked. Every use links the shared actuation authority. |
| Hardware class | `HWCLASS_*` | `EMBEDDED`, `SBC`, `DESKTOP`, `SERVER` | The resource-limit tier: embedded the smallest tables, `SBC` and `DESKTOP` the edge tables, `SERVER` the fleet tables. |
| Structure | `STRUCTURE_*` | `HYBRID`, `RING3_DRIVERS` | Where drivers run: each as its own placement choice says, or every placeable driver in ring 3. Drivers a safety decision reads have no placement choice and stay in the kernel. |
| Real-time class | `RT_*` | `NONE`, `SOFT`, `HARD`, `MIXED` | What the image promises about time. Hard and mixed need memory committed at map time. |
| Security posture | `SECURITY_*` | `GENERAL`, `HARDENED`, `SEPARATION_STATIC`, `CONFIDENTIAL` | The threat model (it absorbed the separate threat choice), the mitigation defaults and mandatory OTA signatures. |
| Virtualization role | `VIRT_*` | `NONE`, `HOSTED`, `SPLIT`, `STATIC` | The hypervisor role (see [virtualization.md](virtualization.md)). |
| Build type | `BUILD_TYPE_*` | `DEV`, `RELEASE`, `CERTIFIABLE` | Named by the defconfig, not keyed on the board or the preset: release is the default. A release build forces off the test-only machinery (`KTEST`, `CHAOS`, `CANARY_RUNTIME`) and refuses the test signing key. |

| Preset | USE | Real-time class | Security | Notes |
|---|---|---|---|---|
| Generic | generic | none | general | General-purpose kernel. |
| Robot | robot | hard | general | Links the robot crates; write-ahead receipts for ring-3 motor ops. |
| Industrial | industrial | hard | separation, static | `VIRT` static; memory committed at map time. |
| Automotive | automotive | hard | separation, static | As industrial. |
| Firmware | (none) | soft | hardened | Hardware class embedded. |
| IoT / HMI | iot-hmi | soft | hardened | Display, touch, battery. |
| Wearable | wearable | soft | hardened | Hardware class embedded. |
| Gateway | gateway | soft | hardened | Larger network tables. |
| Desktop | desktop | soft | hardened | Hardware class desktop; demand paging; `VIRT` hosted on x86_64, split on aarch64. |
| Server | server | none | hardened | Hardware class server; `VIRT` hosted on x86_64, split on aarch64. |

`make check-presets` expands every preset on every ISA and hands the result to
`tools/kconfig_to_cargo.py`; it fails when an expansion warns, the preset is not the one
that came out, or a small board enables a Linux adapter layer or a driver its topology
does not name.

### Limits

Source: `config/limits/Kconfig.limits`.

The cap table holds only integers that bound something: a table size, a pool, a ring, a
stack, a queue depth. Its defaults key on `HWCLASS` directly (`HWCLASS_EMBEDDED`,
`HWCLASS_SBC || HWCLASS_DESKTOP`, `HWCLASS_SERVER`). Switches and tunables (priorities,
intervals, watermarks) live in the topic file of their subsystem. Two kinds of bound sit in
the table, and they are changed differently:

- **Determinism-critical**: a bound a worst-case time, a table walk, admission or an ABI is
  reasoned over (`MAX_TASKS`, `MAX_CAPS_PER_TASK`, the IPC endpoint and message bounds,
  `PI_MAX_DEPTH`, `WARRANT_DEPTH_MAX`, `WCET_MAX_POINTS`, the log ring, the futex and
  kernel-mutex hash buckets, `PMM_MAX_ORDER`, `NR_CPUS`, every stack size, the slab classes,
  `KERNEL_CMDLINE_MAX`, `VFS_MAX_MOUNTS`, ...). Raising one moves a bound the scheduler's
  admission or the topology compiler checks against.
- **Capacity**: pure size, safe to scale with RAM (`TCP_MAX_CONNS`, `MAX_SOCKETS`, the file
  descriptor and capability pools, `KERNEL_HEAP_SIZE`, the slab magazines, the swap and
  zpool sizes, the block cache, NIC and NVMe ring sizes, `TMPFS_MAX_*`, ...).

### Hardware support model

Source: `config/arch/`, `tools/kconfig_to_cargo.py`, `crates/core/limits/build.rs`.

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

## Defconfigs

Source: `config/fragments/`, `config/defconfigs/`, `tools/gen_defconfigs.py`.

A defconfig is assembled from fragments, and its name says which:

```
<preset>-<hwclass>-<arch>[-<build>][+<overlay>...]
```

| Part | Fragment | Content |
|---|---|---|
| preset | `config/fragments/presets/<preset>.frag` | `PRESET_<PRESET>=y` |
| hwclass | `config/fragments/hwclass/<hwclass>.frag` | `HWCLASS_<HWCLASS>=y`; embedded and server also name the RAM the class is built for |
| arch | `config/fragments/arch/<arch>.frag` | `ARCH_<ARCH>=y` (the level and extensions keep their Kconfig defaults) |
| build | `config/fragments/build/<build>.frag` | `BUILD_TYPE_<BUILD>=y`; no build part is the default, release |
| overlay | `config/fragments/overlays/<overlay>.frag` and `<overlay>-<arch>.frag` | what the cell needs beyond its axes (below) |

Fragments merge in that order and a later one wins. Two axis fragments that set one symbol
to different values are refused, and so are two overlays: an overlay is the only thing that
overrides an axis, and the assembled file says so in a comment where it does.

| Overlay | What it adds |
|---|---|
| `qemu` | The QEMU development and test images: the kernel log at debug. |
| `linux` | The Linux personality (`LINUX_ABI`) and the C library (`RELIBC`), on so the gate tests them. |
| `gui` | The input server; on riscv64 the compositor on QEMU's ramfb, on x86_64 the USB keyboard. |
| `hv-host`, `hv-example-guest` | The hypervisor host role (hosted on riscv64 and x86_64, split on aarch64) and its built-in example guest. |
| `hv-guest` | The guest kernel of `make azos-guest`: the RAM the host gives it. |
| `board-generic` | A board with no `BOARD_*` entry: what it has comes from its device tree. |
| `vf2`, `k1`, `rpi5` | A board: its `BOARD_*` entry and the lines its board defaults do not already give. |
| `limine`, `pci` | x86_64 variants: booted by Limine with a framebuffer console; the PCI storage and NIC drivers the PCI rows bind. |
| `micro` | AzOS-micro, the MCU kernel (`make micro`). |

A board overlay holds only what the firmware tables cannot give the kernel yet; the lines
that wait for the device tree or ACPI (a RAM size, a PCI configuration window, a board's
driver set) say so in their fragment.

`config/defconfigs/` holds the assembled files of the cells something builds, and nothing
else. `python3 tools/gen_defconfigs.py` (`make defconfigs`) rewrites them;
`python3 tools/gen_defconfigs.py --check`, run by `make check0`, fails when one is not what
its fragments assemble or does not keep the axes its name gives once Kconfig has expanded
it. `make defconfig-<name>` loads a committed defconfig into `.config` and runs
`olddefconfig`; any other name is assembled on the fly
(`make defconfig-industrial-embedded-aarch64+board-generic`).

| Defconfig | Used by |
|---|---|
| `generic-sbc-<arch>-dev+qemu+linux+gui` | `make check` (all three ISAs), the gate's generic image |
| `robot-sbc-<arch>-dev+qemu+linux+gui` | `make check CHECK_PRESET=robot`, `make aarch64` / `make x86_64`, the gate's robot rows, vsbench |
| `generic-sbc-riscv64-dev` | `make defconfig-generic-sbc-riscv64-dev`, the fallback when there is no `.config` |
| `generic-embedded-riscv64+board-generic`, `generic-server-riscv64+board-generic` | the embedded and fleet profiles (`make build-fleet`) |
| `robot-embedded-riscv64+board-generic`, `robot-server-riscv64+board-generic` | the gate's embedded and fleet rows |
| `generic-embedded-riscv64-dev+board-generic+micro` | `make micro` |
| `generic-sbc-<arch>-dev+qemu+hv-guest`, `robot-sbc-<arch>-dev+qemu+linux+hv-host+hv-example-guest` | `make azos-guest` (riscv64, aarch64) |
| `robot-sbc-x86_64-dev+qemu+linux+limine`, `robot-sbc-x86_64-dev+qemu+linux+pci` | `make x86_64-limine`, `make x86_64-pci` and their gate rows |
| `robot-sbc-riscv64+vf2`, `robot-sbc-riscv64+k1`, `robot-sbc-aarch64+rpi5` | `make vf2`, `make k1`, `make rpi5` |

`make savedefconfig` writes the minimal form of `.config` to
`$AZOS_OUT/build/last_saved.config`.

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

Kconfig gives a build its defaults. A device may override a few of them at run time from
the signed key-value file the boot reads (`CONFIG.INI`, `crates/core/config`); a symbol's
help says when it is one of them.

## Adding an option

Source: `tools/kconfig_to_cargo.py`, `tools/kconfig_lint.py`, `crates/core/limits/build.rs`.

1. **Declare it** in the topic file that owns its subject (a table bound in
   `config/limits/Kconfig.limits`, a switch or tunable next to its subsystem), with a type,
   a prompt (or none for a derived symbol), a `default` per hardware class where the value
   is a size, and a `help` text that says what it costs:
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
   symbol that has a prompt (`tools/kconfig_lint.py` refuses it); use `depends on`. A new
   subject gets its own topic file, sourced from `config/Kconfig` inside its menu.
2. **Use it.** For a size or a switch, import it: `azos_limits::MY_TABLE_ENTRIES`. A new
   symbol needs a real consumer (`tools/kconfig_lint.py` refuses a symbol nothing reads,
   a symbol defined twice, and a symbol whose defaults all give one value).
3. **If it selects code**, give the symbol a cargo feature: add `# cargo-feature: my-feature`
   as the first line of its block (`# cargo-feature: my-feature base` also puts it in the
   output of `--base`), and declare `my-feature` in `kernel/Cargo.toml`. One symbol owns
   one feature, and the tag must sit inside a `config` block.
4. **If it is a program under `userspace/`,** do not write Kconfig by hand: add
   `[package.metadata.azos]` to the crate's `Cargo.toml` (`images`, `topology`, `default`,
   `start`); `tools/gen_userspace_kconfig.py` generates the options.
5. **If a defconfig needs a non-default value**, set it in the fragment that owns the
   reason (an overlay for a board or a test image, never a generated defconfig), then run
   `python3 tools/gen_defconfigs.py`.
6. **Refresh and check.**
   ```sh
   make olddefconfig         # update .config with the new symbol's default
   make check-presets        # every preset still expands on every ISA
   python3 tools/kconfig_lint.py
   python3 tools/gen_feature_matrix.py   # regenerate Documentation/os-feature-matrix.md
   python3 tools/gen_config_index.py     # regenerate the option index below
   make check0               # type-check the three ISAs and run the host suites the diff reaches
   ```

[os-feature-matrix.md](os-feature-matrix.md) lists every switch and choice with its value in
each defconfig. It is generated by `tools/gen_feature_matrix.py`, and `make check0` fails
when it, the defconfigs or the index below are stale.

A value is changed with `make config` (menuconfig), `make nconfig`, `make oldconfig`
(ask for new symbols) or `make olddefconfig` (take defaults).

## Option index

Generated by `python3 tools/gen_config_index.py` from the Kconfig tree: one row per declared
symbol, the topic file that declares it, and its prompt.
The index lists every declared option: 1230.

| Option | File | Description |
|--------|------|-------------|
| `A64_AES_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_AES_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_AES_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_BTI_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_BTI_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_BTI_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_CONTIG_HINT` | `config/arch/Kconfig.isa-aarch64` | Contiguous hint: 64 KiB runs of 16 pages (4 KiB granule) |
| `A64_CRC32_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_CRC32_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_CRC32_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_E0PD_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_E0PD_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_E0PD_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_HAFDBS_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_HAFDBS_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_HAFDBS_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_LSE_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_LSE_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_LSE_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_MIT_BHB_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `A64_MIT_BHB_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the core is affected, say so when the tree cannot |
| `A64_MIT_BHB_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected core the tree cannot mitigate |
| `A64_MIT_SPECTRE_V2_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `A64_MIT_SPECTRE_V2_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the core is affected, say so when the tree cannot |
| `A64_MIT_SPECTRE_V2_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected core the tree cannot mitigate |
| `A64_MIT_SSB_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `A64_MIT_SSB_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the core is affected, say so when the tree cannot |
| `A64_MIT_SSB_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected core the tree cannot mitigate |
| `A64_MTE_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_MTE_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_MTE_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_PAN_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_PAN_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_PAN_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_PAUTH_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_PAUTH_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_PAUTH_PROC_KEYS` | `config/arch/Kconfig.isa-aarch64` | Per-process pointer-authentication keys (APIA, APIB, APDA, APDB, APGA) |
| `A64_PAUTH_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_PMULL_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_PMULL_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_PMULL_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_PMU_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_PMU_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_PMU_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_RNG_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_RNG_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_RNG_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_SHA2_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_SHA2_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_SHA2_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_SVE_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_SVE_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_SVE_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_TLBIRANGE_MIN_PAGES` | `config/kernel/Kconfig.sync` | aarch64: smallest shootdown that uses a TLB range invalidation (pages) |
| `A64_TLBIRANGE_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_TLBIRANGE_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_TLBIRANGE_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `A64_WFET_TICKS` | `config/kernel/Kconfig.sync` | aarch64: WFET deadline (generic counter ticks) |
| `A64_WFXT_NEVER` | `config/arch/Kconfig.isa-aarch64` | n: never use it |
| `A64_WFXT_PROBE` | `config/arch/Kconfig.isa-aarch64` | probe: use it when the boot finds it, fall back otherwise |
| `A64_WFXT_REQUIRE` | `config/arch/Kconfig.isa-aarch64` | require: baseline; refuse to boot without it |
| `AARCH64_LEVEL_8_0` | `config/arch/Kconfig.isa-aarch64` | Armv8.0 (Cortex-A53/A72, QEMU virt; the default) |
| `AARCH64_LEVEL_8_1` | `config/arch/Kconfig.isa-aarch64` | Armv8.1 (+ LSE atomics, CRC32, RDM, PAN, VHE) |
| `AARCH64_LEVEL_8_2` | `config/arch/Kconfig.isa-aarch64` | Armv8.2 (+ PAN2, DC CVAP, UAO: Cortex-A55/A76, Raspberry Pi 5) |
| `AARCH64_LEVEL_8_3` | `config/arch/Kconfig.isa-aarch64` | Armv8.3 (+ PAuth, RCpc, JSCVT, FCMA) |
| `AARCH64_LEVEL_8_4` | `config/arch/Kconfig.isa-aarch64` | Armv8.4 (+ DIT, FlagM, RCpc2, DotProd) |
| `AARCH64_LEVEL_8_5` | `config/arch/Kconfig.isa-aarch64` | Armv8.5 (+ BTI, SB, FlagM2, FRINTTS) |
| `AARCH64_PAGE_16K` | `config/arch/Kconfig.isa` | 16 KiB (39-bit VA, 3 levels) |
| `AARCH64_PAGE_4K` | `config/arch/Kconfig.isa` | 4 KiB (39-bit VA, 3 levels) |
| `AARCH64_PAGE_64K` | `config/arch/Kconfig.isa` | 64 KiB (48-bit VA, 3 levels) |
| `ADS1115_CONVERSION_POLL_ITERS` | `config/subsys/Kconfig.drivers` | ADS1115 ADC: most config-register polls of one blocking read |
| `ADS1115_PIPELINE` | `config/subsys/Kconfig.drivers` | ADS1115 ADC: pipelined battery reading (no conversion polling) |
| `AHCI_NCQ_DEPTH` | `config/limits/Kconfig.limits` | AHCI command slots (native command queuing depth; 1: one at a time) |
| `AHCI_XFER_KB` | `config/limits/Kconfig.limits` | AHCI bounce buffer (KiB; one command's largest transfer) |
| `ALLOC_RANDOM` | `config/kernel/Kconfig.hardening` | Randomize allocation order (slab carve order, buddy list order) |
| `ARCH_AARCH64` | `config/arch/Kconfig.isa` | Aarch64 (ARMv8.0-A and later) |
| `ARCH_RISCV64` | `config/arch/Kconfig.isa` | RISC-V 64-bit (rv64imac / rv64gc) |
| `ARCH_X86_64` | `config/arch/Kconfig.isa` | x86_64 (port skeleton: type-checks only) |
| `ARP_CACHE_SIZE` | `config/subsys/Kconfig.net` | ARP cache entries |
| `ARP_PENDING_SIZE` | `config/subsys/Kconfig.net` | Outstanding ARP requests remembered |
| `ASID_BITS` | `config/kernel/Kconfig.mm` | Address-space ID width the allocator uses (bits) |
| `AUDIOD` | `config/subsys/Kconfig.audio` | Audio server (AUDIOD.ELF): mixes the clients' streams into the one device stream |
| `AUDIOD_PUMP_LEVEL` | `config/subsys/Kconfig.audio` | Audio server: the mixer's real-time band level |
| `AUDIOD_PUMP_PERIOD_US` | `config/subsys/Kconfig.audio` | Audio server: the mixer's reservation, period (us) |
| `AUDIOD_PUMP_RUNTIME_US` | `config/subsys/Kconfig.audio` | Audio server: the mixer's reservation, run time per period (us) |
| `AUDIO_ARENA_KB_MAX` | `config/subsys/Kconfig.audio` | Audio server: largest arena of one stream (KiB) |
| `AUDIO_CAPTURE` | `config/subsys/Kconfig.audio` | Audio server: capture streams (the microphone) |
| `AUDIO_MAX_PERIODS` | `config/subsys/Kconfig.audio` | Audio server: most periods in one stream's arena |
| `AUDIO_MAX_STREAMS` | `config/subsys/Kconfig.audio` | Audio server: streams open at once |
| `AUTORUN` | `config/kernel/Kconfig.tasks` | autorun: load and become CONFIG.INI's `autorun` image at boot |
| `AUTORUN_MEM_PAGES` | `config/limits/Kconfig.limits` | Frame budget of the default topology's autorun row (pages) |
| `B2_HOLD_MIN_MS` | `config/domains/Kconfig.robot` | Minimum hold of a device after the kernel drove it to its safe state (ms) |
| `BLK_DISCARD_BATCHED` | `config/subsys/Kconfig.storage` | batched: gather what one flush frees, adjacent runs merged, and discard it together |
| `BLK_DISCARD_OFF` | `config/subsys/Kconfig.storage` | off: never discard |
| `BLK_DISCARD_ONLINE` | `config/subsys/Kconfig.storage` | online: discard each freed chain on its own, before it is freed |
| `BLK_FUA` | `config/subsys/Kconfig.storage` | fsync commits with a force-unit-access write where the device has one |
| `BLK_IOSCHED_MQ_DEADLINE` | `config/subsys/Kconfig.storage` | mq-deadline: earliest deadline first |
| `BLK_IOSCHED_NONE` | `config/subsys/Kconfig.storage` | none: arrival order |
| `BLK_IOSCHED_RT_DEADLINE` | `config/subsys/Kconfig.storage` | rt-deadline: mq-deadline plus a reserved real-time request slot |
| `BLK_MERGE_MAX` | `config/subsys/Kconfig.storage` | Requests merged into one device command (1-16) |
| `BLK_QUEUE_DEPTH` | `config/subsys/Kconfig.storage` | Block requests queued per hart (2-64) |
| `BOARD_GENERIC` | `config/arch/Kconfig.platform` | Generic / custom (manually specify all addresses) |
| `BOARD_K1` | `config/arch/Kconfig.platform` | SpacemiT K1 / BananaPi BPI-F3 (RISC-V + RVV 1.0) |
| `BOARD_QEMU` | `config/arch/Kconfig.platform` | QEMU virt (riscv64/aarch64/x86_64 simulation) |
| `BOARD_RPI5` | `config/arch/Kconfig.platform` | Raspberry Pi 5 (BCM2712, aarch64) - not ported yet |
| `BOARD_VF2` | `config/arch/Kconfig.platform` | StarFive VisionFive 2 (JH7110, RISC-V) |
| `BOOT_BENCH_ITERS` | `config/axes/Kconfig.build` | Boot [BENCH-RES] sweep: iterations per microbenchmark |
| `BOOT_BENCH_PRIORITY` | `config/axes/Kconfig.build` | Boot [BENCH-RES] sweep: task priority |
| `BOOT_INI_MAX_KB` | `config/subsys/Kconfig.topology` | Largest CONFIG.INI the boot reads (KiB) |
| `BOOT_SELFTESTS` | `config/axes/Kconfig.build` | Boot self-tests: start the demo, stress and probe work at boot |
| `BRAIN_NET_WAIT_POLL_MS` | `config/domains/Kconfig.brain` | Brain link: network wait poll period (ms) |
| `BRAIN_SEND_BUDGET_US` | `config/domains/Kconfig.brain` | Brain link: longest blocking send (us) |
| `BRAIN_TX_CONTROL_RESERVE_BYTES` | `config/domains/Kconfig.brain` | Brain link: queue bytes only control messages may use |
| `BRAIN_TX_IDLE_PARK_MS` | `config/domains/Kconfig.brain` | Brain link: brain-tx park with an empty queue (ms) |
| `BRAIN_TX_PRIORITY` | `config/domains/Kconfig.brain` | Brain link: priority of the brain-tx sender task |
| `BRAIN_TX_QUEUE_BYTES` | `config/domains/Kconfig.brain` | Brain link: control-socket transmit queue (bytes) |
| `BRAIN_TX_STALL_MS` | `config/domains/Kconfig.brain` | Brain link: end the session after the socket takes nothing (ms) |
| `BUILD_TYPE_CERTIFIABLE` | `config/axes/Kconfig.build` | Certifiable: release, with secure boot and signed OTA forced on |
| `BUILD_TYPE_DEV` | `config/axes/Kconfig.build` | Development: test machinery and the TEST key allowed |
| `BUILD_TYPE_RELEASE` | `config/axes/Kconfig.build` | Release: test machinery forced off, TEST key refused |
| `BUSYBOX` | `config/axes/Kconfig.personality` | BusyBox (static, run through the Linux personality) |
| `CAMERA_RING_BACKPRESSURE` | `config/subsys/Kconfig.drivers` | Back-pressure (capture waits for the slowest consumer) |
| `CAMERA_RING_OVERWRITE_OLDEST` | `config/subsys/Kconfig.drivers` | Overwrite the oldest frame (the latest frame wins) |
| `CAMERA_RING_SLOTS` | `config/subsys/Kconfig.drivers` | Camera frame ring: slots |
| `CAMERA_TX_CAPTURE_PERIOD_MS` | `config/subsys/Kconfig.drivers` | Camera frame ring: capture period for the brain link's sender |
| `CANARY_RUNTIME` | `config/axes/Kconfig.build` | Runtime gate canaries: canary=<name>[,<name>] on the kernel command line |
| `CANARY_RUNTIME_MAX` | `config/limits/Kconfig.limits` | Runtime gate canaries: most names the armed set holds |
| `CAP_LOOKUP_CACHE` | `config/limits/Kconfig.limits` | Capability lookup cache: entries per task table (0 = none, a power of two) |
| `CAP_REVOKE_CHAIN_CANARY` | `config/axes/Kconfig.build` | Canary: skip the revoked-ancestor check on a capability's use |
| `CAP_SLOT_EXT` | `config/kernel/Kconfig.ipc` | Capability slots are 128 bits: badge and rights width |
| `CAP_WEAK` | `config/kernel/Kconfig.ipc` | Weak (transitively read-only) capabilities for shadow rows |
| `CHAOS` | `config/axes/Kconfig.build` | Fault injection (chaos=<point>:<rate> on the kernel command line) |
| `CHAOS_SEED` | `config/axes/Kconfig.build` | Fault injection: default seed |
| `CHAOS_TIMER_DELAY_US` | `config/axes/Kconfig.build` | Fault injection: how late an injected timer-wake fault wakes (us) |
| `COMPOSITOR` | `config/subsys/Kconfig.display` | Compositor (COMPSRV.ELF): the sole holder of the Display interface, the trusted path's banner |
| `COMPOSITOR_BANNER_MS` | `config/subsys/Kconfig.display` | Compositor: milliseconds the trusted-path banner holds the focus gate after the Secure Attention Key |
| `COMPOSITOR_FRAME_MS` | `config/subsys/Kconfig.display` | Compositor: milliseconds between two looks at the clients' damage and the trusted page |
| `COMPOSITOR_SURFACE_PAGES` | `config/subsys/Kconfig.display` | Compositor: 4 KiB pages of the screen's surface the server's row may hold |
| `CONSOLE_ARGS` | `tools/gen_userspace_kconfig.py` | (no prompt — internal/derived) |
| `CONSOLE_DEFER_BYTES` | `config/subsys/Kconfig.console` | Console deferred-line buffer (bytes) |
| `CONSOLE_LOCKDOWN` | `config/axes/Kconfig.security` | Production console lockdown: no kernel console, unprivileged user shell |
| `CONSOLE_LOGIN` | `config/subsys/Kconfig.console` | Console login: the native shell starts only after a secure-attention login |
| `CONSOLE_PATH` | `tools/gen_userspace_kconfig.py` | (no prompt — internal/derived) |
| `CONSOLE_PROGRAM_ABICHILD` | `tools/gen_userspace_kconfig.py` | ABICHILD.ELF (userspace/tests/abichild) |
| `CONSOLE_PROGRAM_ABITEST` | `tools/gen_userspace_kconfig.py` | ABITEST.ELF (userspace/tests/abitest) |
| `CONSOLE_PROGRAM_AUDIOD` | `tools/gen_userspace_kconfig.py` | AUDIOD.ELF (userspace/services/audiod) |
| `CONSOLE_PROGRAM_BEHAVIOR` | `tools/gen_userspace_kconfig.py` | BEHAVIOR.ELF (userspace/services/famtools) |
| `CONSOLE_PROGRAM_BRAINCLI` | `tools/gen_userspace_kconfig.py` | BRAINCLI.ELF (userspace/services/brain_client) |
| `CONSOLE_PROGRAM_BUSYBOX_SH` | `tools/gen_userspace_kconfig.py` | BusyBox sh (BUSYBOX.ELF, Linux personality, GPL-2.0-only) |
| `CONSOLE_PROGRAM_BUZZDRV` | `tools/gen_userspace_kconfig.py` | BUZZDRV.ELF (userspace/drivers/buzz_drv) |
| `CONSOLE_PROGRAM_CAPTEST` | `tools/gen_userspace_kconfig.py` | CAPTEST.ELF (userspace/tests/captest) |
| `CONSOLE_PROGRAM_COMPMGR` | `tools/gen_userspace_kconfig.py` | COMPMGR.ELF (userspace/services/compmgr) |
| `CONSOLE_PROGRAM_COMPSRV` | `tools/gen_userspace_kconfig.py` | COMPSRV.ELF (userspace/services/compositor) |
| `CONSOLE_PROGRAM_CONFIG` | `tools/gen_userspace_kconfig.py` | CONFIG.ELF (userspace/services/famtools) |
| `CONSOLE_PROGRAM_CUSTOM` | `tools/gen_userspace_kconfig.py` | Custom image and arguments |
| `CONSOLE_PROGRAM_CUSTOM_ARGS` | `tools/gen_userspace_kconfig.py` | Custom console program: argv (space-separated, argv[0] first) |
| `CONSOLE_PROGRAM_CUSTOM_PATH` | `tools/gen_userspace_kconfig.py` | Custom console program: image path (/fat/NAME.ELF) |
| `CONSOLE_PROGRAM_DECISD` | `tools/gen_userspace_kconfig.py` | DECISD.ELF (userspace/services/decisd) |
| `CONSOLE_PROGRAM_EPSRV` | `tools/gen_userspace_kconfig.py` | EPSRV.ELF (userspace/tests/epsrv) |
| `CONSOLE_PROGRAM_FLIGHT` | `tools/gen_userspace_kconfig.py` | FLIGHT.ELF (userspace/services/famtools) |
| `CONSOLE_PROGRAM_GPIODRV` | `tools/gen_userspace_kconfig.py` | GPIODRV.ELF (userspace/drivers/gpio_drv) |
| `CONSOLE_PROGRAM_HELLO` | `tools/gen_userspace_kconfig.py` | HELLO.ELF (userspace/tests/hello) |
| `CONSOLE_PROGRAM_INADRV` | `tools/gen_userspace_kconfig.py` | INADRV.ELF (userspace/drivers/ina_drv) |
| `CONSOLE_PROGRAM_INPUTD` | `tools/gen_userspace_kconfig.py` | INPUTD.ELF (userspace/services/inputd) |
| `CONSOLE_PROGRAM_IPCTEST` | `tools/gen_userspace_kconfig.py` | IPCTEST.ELF (userspace/tests/ipctest) |
| `CONSOLE_PROGRAM_LATBENCH` | `tools/gen_userspace_kconfig.py` | LATBENCH.ELF (userspace/bench/latbench) |
| `CONSOLE_PROGRAM_LOGD` | `tools/gen_userspace_kconfig.py` | LOGD.ELF (userspace/services/logd) |
| `CONSOLE_PROGRAM_LOGIND` | `tools/gen_userspace_kconfig.py` | LOGIND.ELF (userspace/services/logind) |
| `CONSOLE_PROGRAM_LXHELLO` | `tools/gen_userspace_kconfig.py` | LXHELLO.ELF (userspace/tests/lxhello) |
| `CONSOLE_PROGRAM_LXSRV` | `tools/gen_userspace_kconfig.py` | LXSRV.ELF (userspace/services/lxsrv) |
| `CONSOLE_PROGRAM_LXTHR` | `tools/gen_userspace_kconfig.py` | LXTHR.ELF (userspace/tests/lxthreads) |
| `CONSOLE_PROGRAM_MCPD` | `tools/gen_userspace_kconfig.py` | MCPD.ELF (userspace/services/mcpd) |
| `CONSOLE_PROGRAM_MLSRV` | `tools/gen_userspace_kconfig.py` | MLSRV.ELF (userspace/services/infsrv) |
| `CONSOLE_PROGRAM_NONE` | `tools/gen_userspace_kconfig.py` | None (the in-kernel shell has the console) |
| `CONSOLE_PROGRAM_OTA` | `tools/gen_userspace_kconfig.py` | OTA.ELF (userspace/services/famtools) |
| `CONSOLE_PROGRAM_PKG` | `tools/gen_userspace_kconfig.py` | PKG.ELF (userspace/services/pkg) |
| `CONSOLE_PROGRAM_PKGD` | `tools/gen_userspace_kconfig.py` | PKGD.ELF (userspace/services/pkgd) |
| `CONSOLE_PROGRAM_POWER` | `tools/gen_userspace_kconfig.py` | POWER.ELF (userspace/services/power) |
| `CONSOLE_PROGRAM_PTPD` | `tools/gen_userspace_kconfig.py` | PTPD.ELF (userspace/services/ptpd) |
| `CONSOLE_PROGRAM_REFLEX` | `tools/gen_userspace_kconfig.py` | REFLEX.ELF (userspace/services/reflex) |
| `CONSOLE_PROGRAM_RPCQUIC` | `tools/gen_userspace_kconfig.py` | RPCQUIC.ELF (userspace/services/rpcquic) |
| `CONSOLE_PROGRAM_RPCSRV` | `tools/gen_userspace_kconfig.py` | RPCSRV.ELF (userspace/services/rpcsrv) |
| `CONSOLE_PROGRAM_SH` | `tools/gen_userspace_kconfig.py` | Native shell (SH.ELF, served by TERMD.ELF, named by NAMESD.ELF) |
| `CONSOLE_PROGRAM_SSHD` | `tools/gen_userspace_kconfig.py` | SSHD.ELF (userspace/services/sshd) |
| `CONSOLE_PROGRAM_SYSTEST` | `tools/gen_userspace_kconfig.py` | SYSTEST.ELF (userspace/tests/syscall_test) |
| `CONSOLE_PROGRAM_TOOLBOX` | `tools/gen_userspace_kconfig.py` | TOOLBOX.ELF (userspace/services/toolbox) |
| `CONSOLE_PROGRAM_TRACECTL` | `tools/gen_userspace_kconfig.py` | TRACECTL.ELF (userspace/services/tracectl) |
| `CONSOLE_PROGRAM_UHELLO` | `tools/gen_userspace_kconfig.py` | UHELLO.ELF (userspace/tests/uhello) |
| `CONSOLE_PROGRAM_VMMD` | `tools/gen_userspace_kconfig.py` | VMMD.ELF (userspace/services/vmmd) |
| `CONSOLE_PROGRAM_VSBENCH` | `tools/gen_userspace_kconfig.py` | VSBENCH.ELF (userspace/bench/vsbench) |
| `CONSOLE_PROGRAM_VSSRV` | `tools/gen_userspace_kconfig.py` | VSSRV.ELF (userspace/bench/vssrv) |
| `CONSOLE_PROGRAM_WHY` | `tools/gen_userspace_kconfig.py` | WHY.ELF (userspace/services/why) |
| `CONSOLE_PROGRAM_ZENOHD` | `tools/gen_userspace_kconfig.py` | ZENOHD.ELF (userspace/services/zenohd) |
| `CONSOLE_RT_APPEND_ONLY` | `config/kernel/Kconfig.trace` | Real-time callers of the kernel log only append to the console |
| `CONSOLE_TX_IRQ_BUDGET` | `config/subsys/Kconfig.console` | Console: most bytes one TX interrupt moves to the UART |
| `CONSOLE_TX_RING_BYTES` | `config/subsys/Kconfig.console` | Console UART transmit ring (bytes) |
| `CONTROL_TXN_TICKS` | `config/kernel/Kconfig.sched` | Control plane: transactional ticks (rollback recoverable faults) |
| `CPU_HOTPLUG` | `config/arch/Kconfig.platform` | CPU hotplug: take a CPU offline and bring it back at run time |
| `CPU_IDLE_POWERDOWN` | `config/arch/Kconfig.platform` | Non-retentive CPU idle states (power-down) with a resume entry |
| `CRASHDUMP` | `config/kernel/Kconfig.panic` | Crash dump: a minidump of every ring-3 task a fault kills |
| `CRASHDUMP_DECISIONS` | `config/kernel/Kconfig.panic` | Crash dump: decision records kept |
| `CRASHDUMP_FILES` | `config/kernel/Kconfig.panic` | Crash dump: file slots per Domain directory |
| `CRASHDUMP_MAPS` | `config/kernel/Kconfig.panic` | Crash dump: map runs kept |
| `CRASHDUMP_RING` | `config/kernel/Kconfig.panic` | Crash dump: crash ring depth (dumps kept in RAM) |
| `CRASHDUMP_STACK_BYTES` | `config/kernel/Kconfig.panic` | Crash dump: stack window (bytes, from the stack pointer up) |
| `DECISION_DENY_DURABLE_BURST` | `config/kernel/Kconfig.decisions` | Explainable decision records: durable capability denials, burst |
| `DECISION_DENY_DURABLE_PER_SEC` | `config/kernel/Kconfig.decisions` | Explainable decision records: durable capability denials per second, per task |
| `DECISION_JOURNAL_ENTRIES` | `config/kernel/Kconfig.decisions` | Explainable decision records: durable journal depth |
| `DECISION_RECORDS_DEV` | `config/kernel/Kconfig.decisions` | Explainable decision records: the ring, every rule |
| `DECISION_RECORDS_ENTRIES` | `config/kernel/Kconfig.decisions` | Explainable decision records: ring depth |
| `DECISION_REFUSALS_DURABLE` | `config/kernel/Kconfig.decisions` | Explainable decision records: durable receipt of every refusal |
| `DEVICE_TIMEOUT_RESETS` | `config/limits/Kconfig.limits` | Resets a block, network or USB host controller gets after a timeout (0-3) |
| `DEVICE_WAKELOCKS` | `config/subsys/Kconfig.drivers` | Device runtime PM: wakelocks live at once, per device |
| `DEVICE_WAKELOCK_TTL_MAX_MS` | `config/subsys/Kconfig.drivers` | Device runtime PM: longest wakelock (milliseconds) |
| `DEVIF_PUMP_POLL_US` | `config/subsys/Kconfig.drivers` | device pump: look again at a source with no interrupt after (us) |
| `DMA_DOMAIN_IDENTITY` | `config/subsys/Kconfig.drivers` | identity: the device is handed physical addresses, unchecked |
| `DMA_DOMAIN_SOFT` | `config/subsys/Kconfig.drivers` | software-checked: each mapping must lie in RAM and in the device's reach |
| `DMA_MAP_ENTRIES` | `config/subsys/Kconfig.drivers` | Live DMA mappings per domain |
| `DMA_NONCOHERENT` | `config/subsys/Kconfig.drivers` | Devices are NOT cache-coherent with the CPU (cache maintenance around every DMA transfer) |
| `DMA_POOL_FLOOR_KB` | `config/limits/Kconfig.limits` | Minimum DMA pool reserved at boot (KiB) |
| `DNS_CACHE_SIZE` | `config/subsys/Kconfig.net` | DNS cache entries |
| `DOMAIN_ENTRY_COUNTERS` | `config/kernel/Kconfig.trace` | Count kernel entries per Domain by foundational case |
| `DRV_AHCI` | `config/subsys/Kconfig.drivers` | SATA disk over PCIe (native AHCI 1.3 host) |
| `DRV_BUZZER_CALL_BUDGET_US` | `config/subsys/Kconfig.drivers` | Piezo buzzer: call budget (microseconds, 0: none) |
| `DRV_BUZZER_PLACEMENT_KERNEL` | `config/subsys/Kconfig.drivers` | kernel |
| `DRV_BUZZER_PLACEMENT_RING3` | `config/subsys/Kconfig.drivers` | ring3 |
| `DRV_DISPLAY_HDMI` | `config/subsys/Kconfig.display` | HDMI framebuffer (VF2 DC8200 + HDMI TX) |
| `DRV_DISPLAY_RAMFB` | `config/subsys/Kconfig.display` | QEMU ramfb framebuffer |
| `DRV_E1000E` | `config/subsys/Kconfig.drivers` | Intel e1000e Ethernet (82574L, I217/I218/I219) over PCIe |
| `DRV_IGC` | `config/subsys/Kconfig.drivers` | Intel I225/I226 2.5 GbE Ethernet (igc) over PCIe |
| `DRV_INA219_PLACEMENT_KERNEL` | `config/subsys/Kconfig.drivers` | kernel |
| `DRV_INA219_PLACEMENT_RING3` | `config/subsys/Kconfig.drivers` | ring3 |
| `DRV_NVME` | `config/subsys/Kconfig.drivers` | NVMe SSD over PCIe (native driver, admin + an I/O queue pair per CPU) |
| `DRV_PCI` | `config/subsys/Kconfig.drivers` | PCI bus: ECAM enumeration, MSI-X, virtio-pci transport |
| `DRV_PS2` | `config/subsys/Kconfig.drivers` | PS/2 keyboard and mouse (i8042 controller, PC) |
| `DRV_RING3_DEFAULT` | `config/subsys/Kconfig.drivers` | Place drivers that support it in ring 3 by default |
| `DRV_RTC` | `config/subsys/Kconfig.drivers` | Real-time clock (seeds the wall clock at boot, written back by a reference) |
| `DRV_RTC_PCF8563` | `config/subsys/Kconfig.drivers` | RTC: NXP PCF8563 on I2C (boards) |
| `DRV_VIRTIO_INPUT` | `config/subsys/Kconfig.drivers` | virtio-input keyboards and mice (QEMU) |
| `DRV_VIRTIO_SND` | `config/subsys/Kconfig.drivers` | virtio-sound audio device (QEMU) |
| `E1000E_EXT_DESC` | `config/subsys/Kconfig.drivers` | e1000e extended descriptors (RFCTL.EXTEN receive, DEXT transmit) |
| `E1000E_LINK_WAIT_MS` | `config/subsys/Kconfig.drivers` | e1000e: milliseconds to wait for link at bring-up (0 = do not wait) |
| `E1000E_RX_DESCS` | `config/limits/Kconfig.limits` | e1000e receive ring entries (a multiple of 8) |
| `E1000E_TX_DESCS` | `config/limits/Kconfig.limits` | e1000e transmit ring entries (a multiple of 8) |
| `EFFECT_WATCH_SLOTS` | `config/domains/Kconfig.robot` | In-flight effects the deadline watch holds |
| `EFFECT_WRITE_AHEAD` | `config/domains/Kconfig.robot` | Write-ahead receipts: record a ring-3 motor op before it reaches the wheel |
| `ELF_REFUSE_EXEC_HEADERS` | `config/axes/Kconfig.security` | ELF loader: refuse an executable segment that maps the ELF headers |
| `ENERGY` | `config/kernel/Kconfig.energy` | Energy-aware scheduling: utilisation tracking and the energy model |
| `ENERGY_BATTERY_REPORT_TIMEOUT_MS` | `config/kernel/Kconfig.energy` | Battery report timeout (ms) |
| `ENERGY_BATTERY_RESERVE_PCT` | `config/kernel/Kconfig.energy` | Battery reserve (percent of charge) |
| `ENERGY_PELT_PERIOD_US` | `config/kernel/Kconfig.energy` | Utilisation period (us, PELT-like tracker) |
| `ENERGY_UTIL_PELT` | `config/kernel/Kconfig.energy` | PELT-like geometric decay, half-life 32 periods |
| `ENERGY_UTIL_WINDOW` | `config/kernel/Kconfig.energy` | Window (WALT-like): max(last window, mean of the last four) |
| `ENERGY_UTIL_WINDOW_US` | `config/kernel/Kconfig.energy` | Utilisation window (us, window tracker) |
| `ENTROPY_CPU_RETRIES` | `config/subsys/Kconfig.entropy` | CPU entropy instruction: retries per word |
| `ENTROPY_CPU_SOURCE_CREDIT` | `config/subsys/Kconfig.entropy` | credit: mix and credit (trust the CPU) |
| `ENTROPY_CPU_SOURCE_MIX` | `config/subsys/Kconfig.entropy` | mix-only: mix, never credit |
| `ENTROPY_CPU_SOURCE_OFF` | `config/subsys/Kconfig.entropy` | off: never read the CPU's entropy instruction |
| `ENTROPY_TPM_SOURCE_CREDIT` | `config/subsys/Kconfig.entropy` | credit: mix and credit (trust the TPM) |
| `ENTROPY_TPM_SOURCE_MIX` | `config/subsys/Kconfig.entropy` | mix-only: mix, never credit |
| `ENTROPY_TPM_SOURCE_OFF` | `config/subsys/Kconfig.entropy` | off: never ask the TPM for random bytes |
| `EXEC_IMAGE_CACHE_KB` | `config/limits/Kconfig.limits` | Verified exec image cache (KiB of frames; 0 = off) |
| `FAIR_SLICE_US` | `config/kernel/Kconfig.sched` | Fair class: slice (us) |
| `FAT32_SECTOR_CLAIM_SLOTS` | `config/limits/Kconfig.limits` | FAT32 FAT-sector claim slots (1-64; concurrent FAT updates) |
| `FAT_PI_IO_SITES` | `config/limits/Kconfig.limits` | FAT32 F1 probe: distinct (task, lock) sites recorded (diagnostics) |
| `FB_CONSOLE` | `config/subsys/Kconfig.display` | Framebuffer text console (mirrors the UART console) |
| `FB_CONSOLE_COLS_MAX` | `config/subsys/Kconfig.console` | Framebuffer console: text columns the grid can hold |
| `FB_CONSOLE_ROWS_MAX` | `config/subsys/Kconfig.console` | Framebuffer console: text rows the grid can hold |
| `FB_CONSOLE_SCROLLBACK` | `config/limits/Kconfig.limits` | Framebuffer console: lines of scrollback kept for the terminal server |
| `FB_GENERIC` | `config/subsys/Kconfig.display` | Generic framebuffer (virtio-gpu, ramfb, Limine, device-tree simple-framebuffer) |
| `FB_PANIC_SCREEN` | `config/subsys/Kconfig.display` | Framebuffer panic screen |
| `FILE_CENSUS_EVERY` | `config/axes/Kconfig.build` | Backend operations per file-census line |
| `FIREWALL_CONNTRACK_MAX` | `config/subsys/Kconfig.net` | Firewall: tracked TCP/UDP flows |
| `FIREWALL_INBOUND_DROP` | `config/subsys/Kconfig.net` | Firewall: drop inbound packets no rule accepts |
| `FIREWALL_TCP_TIMEOUT_S` | `config/subsys/Kconfig.net` | Firewall: idle timeout of an established TCP flow (s) |
| `FIREWALL_UDP_TIMEOUT_S` | `config/subsys/Kconfig.net` | Firewall: idle timeout of a tracked UDP flow (s) |
| `FP_HARDFLOAT_D` | `config/arch/Kconfig.isa` | RISC-V D extension (32 × f64 = 256 B, default rv64) |
| `FP_HARDFLOAT_F` | `config/arch/Kconfig.isa` | RISC-V F extension (32 × f32 = 128 B) |
| `FP_NEON` | `config/arch/Kconfig.isa` | Aarch64 NEON (32 × 128-bit q-regs = 512 B) |
| `FP_RVV` | `config/arch/Kconfig.isa` | RISC-V V extension (32 × vlen-bit + control regs) |
| `FP_SOFTFLOAT` | `config/arch/Kconfig.isa` | No FP save area (soft-float) |
| `FP_SVE` | `config/arch/Kconfig.isa` | Aarch64 SVE (variable-length, up to 2048-bit per reg) |
| `FP_XSAVE_EAGER` | `config/arch/Kconfig.isa` | x86_64 XSAVE area, EAGER switch (512 B legacy + XSAVE header + enabled components) |
| `FS_BLOCK_CACHE_KB` | `config/limits/Kconfig.limits` | FAT32 block cache (KiB; 0 = the 4 KiB, 8-sector cache) |
| `FS_DEFERRED_FREE` | `config/subsys/Kconfig.fs` | FAT32 write-back: free a truncated or replaced chain once its unlinking entry is durable |
| `FS_DEFERRED_FREE_SLOTS` | `config/limits/Kconfig.limits` | FAT32 write-back: chains held until their unlinking entry is durable |
| `FS_DISCARD_RUNS` | `config/subsys/Kconfig.storage` | Free runs gathered before FAT32 issues a discard (2-64) |
| `FS_WRITEBACK` | `config/subsys/Kconfig.fs` | FAT32 write-back block cache (writes queue in RAM; fsync/sync make them durable) |
| `FS_WRITEBACK_MAX_AGE_MS` | `config/subsys/Kconfig.fs` | FAT32 write-back: oldest unsynced write before the fs-wb task writes it (ms) |
| `FS_WRITEBACK_PRIORITY` | `config/kernel/Kconfig.tasks` | FAT32 write-back task priority (outside the RT band: 12..30) |
| `FS_WRITEBACK_RUN_KB` | `config/limits/Kconfig.limits` | FAT32 write-back: largest single device write of a coalesced run (KiB) |
| `FS_WRITEBACK_WATERMARK_PCT` | `config/subsys/Kconfig.fs` | FAT32 write-back: dirty share of the cache that wakes the fs-wb task (%) |
| `FUTEX_DOMAIN_BANKS` | `config/limits/Kconfig.limits` | Futex hash banks (one per process, modulo collisions) |
| `FUTEX_PI` | `config/kernel/Kconfig.sync` | PI futexes: FUTEX_LOCK_PI/UNLOCK_PI/TRYLOCK_PI and requeue-PI |
| `FUTEX_PI_EXIT_RETRY_US` | `config/kernel/Kconfig.sync` | PI futex: back-off (us) before a locker retries a word whose owner is exiting |
| `FUTEX_PRIVATE_BUCKETS` | `config/limits/Kconfig.limits` | Futex hash buckets per domain bank (private keys) |
| `FUTEX_REQUEUE` | `config/kernel/Kconfig.sync` | FUTEX_REQUEUE and FUTEX_CMP_REQUEUE |
| `FUTEX_SHARED` | `config/kernel/Kconfig.sync` | Linux shared futexes on shm words keyed by (region, offset) |
| `FUTEX_SHARED_BUCKETS` | `config/limits/Kconfig.limits` | Futex hash buckets for shared keys (shm words, notify) |
| `GEOFENCE` | `config/domains/Kconfig.robot` | On-board geofence armed at the home fix |
| `GEOFENCE_MIN_SATELLITES` | `config/domains/Kconfig.robot` | Geofence: minimum satellites for a trusted fix |
| `GEOFENCE_RADIUS_M` | `config/domains/Kconfig.robot` | Geofence radius (m) |
| `HAS_RVV` | `config/arch/Kconfig.isa-riscv64` | (no prompt — internal/derived) |
| `HDMI_HEIGHT` | `config/arch/Kconfig.platform` | HDMI framebuffer height (pixels) |
| `HDMI_WIDTH` | `config/arch/Kconfig.platform` | HDMI framebuffer width (pixels) |
| `HV` | `config/axes/Kconfig.virt` | (no prompt — internal/derived) |
| `HV_EXAMPLE_GUEST` | `config/axes/Kconfig.virt` | Declare an example guest in the built-in topology |
| `HV_EXAMPLE_GUEST_MEM_MIB` | `config/axes/Kconfig.virt` | RAM of the example guest (MiB) |
| `HV_MAX_VCPUS` | `config/axes/Kconfig.virt` | vCPUs over all guests |
| `HV_REQUIRE` | `config/axes/Kconfig.virt` | Refuse to boot when the CPU cannot host the guests |
| `HWBUS_AUTOBIND_AUTO` | `config/subsys/Kconfig.drivers` | Auto: bind every device a driver table matches |
| `HWBUS_AUTOBIND_TOPOLOGY` | `config/subsys/Kconfig.drivers` | Topology only: bind what the signed topology admits |
| `HWBUS_MAX_DEVICES` | `config/limits/Kconfig.limits` | Hardware bus: device objects |
| `HWCLASS_DESKTOP` | `config/axes/Kconfig.hwclass` | Desktop / workstation |
| `HWCLASS_EMBEDDED` | `config/axes/Kconfig.hwclass` | Embedded (small boards, 16-64 MiB of RAM) |
| `HWCLASS_SBC` | `config/axes/Kconfig.hwclass` | Single-board computer (VF2, K1, Raspberry Pi 5, RK3588) |
| `HWCLASS_SERVER` | `config/axes/Kconfig.hwclass` | Server / gateway machine |
| `I2C_DW_RX_FIFO_DEPTH` | `config/subsys/Kconfig.drivers` | I2C: DesignWare controller RX FIFO depth (entries) |
| `I2C_K1_FAST_MODE` | `config/subsys/Kconfig.drivers` | I2C: SpacemiT K1 controllers in fast mode (400 kHz) |
| `I2C_SERVICE_POLL_US` | `config/subsys/Kconfig.drivers` | I2C: service step period while a transaction is on the wire (us) |
| `I2C_SERVICE_PRIORITY` | `config/subsys/Kconfig.drivers` | I2C: priority of the i2c-svc task |
| `I2C_TXN_QUEUE_DEPTH` | `config/subsys/Kconfig.drivers` | I2C: queued transactions per bus |
| `I2C_XFER_TIMEOUT_US` | `config/subsys/Kconfig.drivers` | I2C: queued transaction timeout (us) |
| `IGC_LINK_WAIT_MS` | `config/subsys/Kconfig.drivers` | igc: milliseconds to wait for link at bring-up (0 = do not wait) |
| `IGC_RX_DESCS` | `config/limits/Kconfig.limits` | igc receive ring entries (a multiple of 8) |
| `IGC_TX_DESCS` | `config/limits/Kconfig.limits` | igc transmit ring entries (a multiple of 8) |
| `IMU_SAMPLE_POLLED` | `config/subsys/Kconfig.drivers` | Synchronous read in the task (before wave 15) |
| `IMU_SAMPLE_QUEUED` | `config/subsys/Kconfig.drivers` | Queued read, re-armed from the task's tick (no wait) |
| `INFER_MODEL_SIG_REQUIRED` | `config/axes/Kconfig.security` | Require an Ed25519 signature on the inference service's model data files |
| `INFSRV_BLOB_KIB` | `config/limits/Kconfig.limits` | Inference service: blob arena (KiB) |
| `INFSRV_CONTEXTS` | `config/limits/Kconfig.limits` | Inference service: client contexts accounted |
| `INFSRV_ENERGY_QUOTA_UJ` | `config/kernel/Kconfig.energy` | Inference service: energy quota of a context per window (uJ) |
| `INFSRV_ENERGY_WINDOW_MS` | `config/kernel/Kconfig.energy` | Inference service: energy quota window (ms) |
| `INFSRV_MODELS` | `config/limits/Kconfig.limits` | Inference service: model bundles held |
| `INFSRV_WORK_KIB` | `config/limits/Kconfig.limits` | Inference service: working memory for a run (KiB) |
| `INPUTD` | `config/subsys/Kconfig.display` | Input server (INPUTD.ELF): the focus is a warrant, the Secure Attention Key is a trusted path |
| `INSPECT` | `config/kernel/Kconfig.trace` | Introspection tree: kernel state as read-only memory (no /proc, no system call) |
| `INSPECT_ADMIN_PAGES` | `config/kernel/Kconfig.trace` | Introspection tree: pages of the admin region (0 = none) |
| `INSPECT_PUBLIC_PAGES` | `config/kernel/Kconfig.trace` | Introspection tree: pages of the public region |
| `INSPECT_REFRESH_MS` | `config/kernel/Kconfig.trace` | Introspection tree: refresh period (ms) |
| `INTERRUPT_STACK_SIZE_KB` | `config/limits/Kconfig.limits` | Per-hart interrupt stack (KiB) |
| `IOMMU_AMDVI` | `config/subsys/Kconfig.drivers` | AMD-Vi: confine PCI DMA |
| `IOMMU_BYPASS` | `config/subsys/Kconfig.drivers` | IOMMU in pass-through: do NOT confine any device's DMA |
| `IOMMU_DOMAINS` | `config/subsys/Kconfig.drivers` | Translating PCI functions at once (with an IOMMU_* unit) |
| `IOMMU_FAULT_POLL_MS` | `config/subsys/Kconfig.drivers` | IOMMU fault log poll interval (ms; with an IOMMU_* unit) |
| `IOMMU_RISCV` | `config/subsys/Kconfig.drivers` | RISC-V IOMMU (riscv-iommu-pci): confine PCI DMA |
| `IOMMU_SMMUV3` | `config/subsys/Kconfig.drivers` | Arm SMMUv3 (QEMU virt iommu=smmuv3): confine PCI DMA |
| `IOMMU_VTD` | `config/subsys/Kconfig.drivers` | Intel VT-d (QEMU q35 intel-iommu): confine PCI DMA |
| `IORING_ASYNC` | `config/subsys/Kconfig.storage` | io_ring data entries are queued: no file or block work in a submit |
| `IORING_MAX_PARKED` | `config/limits/Kconfig.limits` | io_ring: entries one ring holds parked (timers, waits, fsyncs) |
| `IORING_MAX_REGBUFS` | `config/limits/Kconfig.limits` | io_ring: registered buffers one ring holds (OP_BUF_REGISTER) |
| `IORING_WORKER` | `config/subsys/Kconfig.storage` | io_ring worker: runs a real-time submitter's file entries outside the RT band |
| `IORING_WORKER_PRIORITY` | `config/kernel/Kconfig.tasks` | io_ring worker task priority (outside the RT band: 12..30) |
| `IPC_CALL_WAKE_RETRIES` | `config/limits/Kconfig.limits` | Wake-ups a blocked fast call or accept tolerates before giving up |
| `IPC_ENDPOINTS` | `config/limits/Kconfig.limits` | Fast-call endpoints the machine may have live at once |
| `IPC_ENDPOINTS_PER_TASK` | `config/limits/Kconfig.limits` | Endpoints one task may own at once |
| `IPC_FASTPATH` | `config/kernel/Kconfig.ipc` | IPC fast path: a call or reply to a parked peer skips the dispatch |
| `IPC_FASTPATH_RESUME` | `config/kernel/Kconfig.ipc` | IPC fast path: finish a parked peer's syscall and start it at its exit |
| `IPC_LABELS` | `config/kernel/Kconfig.ipc` | IPC: provenance labels, and the effect gate's meet over them |
| `IPC_MSG_INLINE_WORDS` | `config/limits/Kconfig.limits` | Inline 64-bit words of a v2 call message (message descriptor) |
| `IPC_MSG_MAX_CAPS` | `config/limits/Kconfig.limits` | Capabilities one IPC message may carry (all or nothing) |
| `IPC_PORT_NOTICES` | `config/kernel/Kconfig.ipc` | Endpoint no-senders and source-gone notices on event ports |
| `IPC_RESOLVE_CACHE` | `config/kernel/Kconfig.ipc` | IPC: per-task cache of the last endpoint a fast call resolved |
| `IRQ_THREADED` | `config/kernel/Kconfig.sched` | Interrupts as scheduled objects: the handler runs on a hard reservation |
| `IRQ_THREAD_BUDGET_PCT` | `config/kernel/Kconfig.sched` | IRQ thread: budget (% of a CPU) |
| `IRQ_THREAD_PERIOD_US` | `config/kernel/Kconfig.sched` | IRQ thread: period (us) |
| `IRQ_THREAD_PRIORITY` | `config/kernel/Kconfig.sched` | IRQ thread: priority |
| `KASLR_AVAILABLE` | `config/kernel/Kconfig.hardening` | (no prompt — internal/derived) |
| `KASLR_NEVER` | `config/kernel/Kconfig.hardening` | n: link address = run address |
| `KASLR_PROBE` | `config/kernel/Kconfig.hardening` | probe: slide when the boot finds a seed, else run at the link address |
| `KASLR_REQUIRE` | `config/kernel/Kconfig.hardening` | require: refuse to boot without a seed |
| `KERNEL_CMDLINE_INIT` | `config/subsys/Kconfig.console` | Honour init=/fat/NAME.ELF on the kernel command line (secure boot off) |
| `KERNEL_CMDLINE_MAX` | `config/limits/Kconfig.limits` | Kernel command line: bytes read from /chosen/bootargs |
| `KERNEL_HEAP_SIZE` | `config/limits/Kconfig.limits` | Kernel heap size (KiB) |
| `KERNEL_STACK_SIZE_KB` | `config/limits/Kconfig.limits` | Per-task kernel stack (KiB) |
| `KEYSTORE_KEYS` | `config/subsys/Kconfig.keystore` | Keystore: key handles the kernel holds |
| `KEYSTORE_KEYS_PER_OWNER` | `config/subsys/Kconfig.keystore` | Keystore: handles one owner may hold |
| `KEYSTORE_TPM_NV` | `config/subsys/Kconfig.keystore` | Keystore: a secret in a TPM NV index as a root (backend tpm_nv) |
| `KEYSTORE_VOLUME_ROOT_PATH` | `config/subsys/Kconfig.keystore` | Keystore: file holding the secret of the volume backend |
| `KHEAP_SLAB` | `config/kernel/Kconfig.mm` | Per-CPU size-class cache in front of the kernel heap |
| `KHEAP_SLAB_BYTES` | `config/limits/Kconfig.limits` | Smallest slab (bytes, a power of two) |
| `KHEAP_SLAB_CLASSES` | `config/limits/Kconfig.limits` | Size classes (bytes, ascending, multiples of 8, at most 16) |
| `KHEAP_SLAB_CPU_CACHE_KB` | `config/limits/Kconfig.limits` | Most memory one CPU caches in magazines (KiB) |
| `KHEAP_SLAB_DEBUG` | `config/kernel/Kconfig.mm` | Poison freed objects and check red zones |
| `KHEAP_SLAB_DEPOT_MAGS` | `config/limits/Kconfig.limits` | Full magazines kept per class in the depot |
| `KHEAP_SLAB_KEEP_EMPTY` | `config/limits/Kconfig.limits` | Empty slabs a class keeps |
| `KHEAP_SLAB_MAG_DEPTH` | `config/limits/Kconfig.limits` | Magazine depth (objects) |
| `KHEAP_SLAB_MAX_CLASS` | `config/limits/Kconfig.limits` | Largest request served by the cache (bytes) |
| `KHEAP_SLAB_MIN_OBJS` | `config/limits/Kconfig.limits` | Fewest objects in a slab |
| `KILL_SWITCH_PRIORITY` | `config/kernel/Kconfig.tasks` | Kill-switch task priority (real-time band: 1..11) |
| `KILL_SWITCH_RECHECK_MS` | `config/kernel/Kconfig.tasks` | Kill-switch re-check period (ms) |
| `KLOG` | `config/kernel/Kconfig.trace` | Structured kernel log: every log line as a record in a ring ring 3 reads |
| `KLOG_EARLY_ENTRIES` | `config/kernel/Kconfig.trace` | Structured kernel log: records kept before the ring exists (power of two) |
| `KLOG_ENTRIES` | `config/kernel/Kconfig.trace` | Structured kernel log: records the ring holds (power of two) |
| `KMUTEX_ADAPTIVE_SPIN` | `config/kernel/Kconfig.sync` | Kernel mutex: spin-hint iterations while the owner runs, before sleeping |
| `KMUTEX_PARK_BUCKETS` | `config/limits/Kconfig.limits` | Kernel mutex: hashed sleep queues shared by every Mutex |
| `KMUTEX_STEAL_RULE` | `config/kernel/Kconfig.sync` | Kernel mutex: after a release only a more urgent task may overtake the top waiter |
| `KTEST` | `config/axes/Kconfig.build` | In-kernel tests (ktest): run every registered test at boot, then power off |
| `KTEST_LATE_PRIORITY` | `config/axes/Kconfig.build` | Priority of the late ktest runner task |
| `KTEST_LATE_TIMEOUT_MS` | `config/axes/Kconfig.build` | Longest a late ktest waits for its probe task (ms) |
| `KTEST_SEMIHOSTING_EXIT` | `config/axes/Kconfig.build` | ktest runner leaves QEMU through semihosting SYS_EXIT (aarch64) |
| `KTRACE` | `config/kernel/Kconfig.trace` | Kernel event tracer, read live from ring 3 |
| `KTRACE_BOOT_MASK` | `config/kernel/Kconfig.trace` | Trace classes recording from boot (runtime mask) |
| `KTRACE_CLASS_FAULT` | `config/kernel/Kconfig.trace` | Trace class: page faults |
| `KTRACE_CLASS_IPC` | `config/kernel/Kconfig.trace` | Trace class: fast IPC (call, reply) |
| `KTRACE_CLASS_IRQ` | `config/kernel/Kconfig.trace` | Trace class: interrupts (entry, exit) |
| `KTRACE_CLASS_LAT` | `config/kernel/Kconfig.trace` | Trace class: masked-window maxima (LAT_TRACE) |
| `KTRACE_CLASS_PROC` | `config/kernel/Kconfig.trace` | Trace class: process life cycle (spawn, exit, signal) |
| `KTRACE_CLASS_SCHED` | `config/kernel/Kconfig.trace` | Trace class: scheduler (switch, wakeup) |
| `KTRACE_CLASS_SYSCALL` | `config/kernel/Kconfig.trace` | Trace class: system calls (entry, exit, seccomp denial) |
| `KTRACE_KEY_BATCH` | `config/kernel/Kconfig.trace` | Static-key sites rewritten per lock hold |
| `KTRACE_POLICY_DROP` | `config/kernel/Kconfig.trace` | Drop the newest record and count it |
| `KTRACE_POLICY_OVERWRITE` | `config/kernel/Kconfig.trace` | Overwrite the oldest record (flight recorder) |
| `KTRACE_RING_ENTRIES` | `config/kernel/Kconfig.trace` | Trace records per CPU ring (power of two) |
| `KTRACE_STATIC_KEYS` | `config/kernel/Kconfig.trace` | Tracepoints as patched branches (static keys) |
| `KTRACE_TS_CYCLES` | `config/kernel/Kconfig.trace` | The CPU cycle counter |
| `KTRACE_TS_TIMEBASE` | `config/kernel/Kconfig.trace` | The monotonic timebase (the clock vDSO's) |
| `LAT_TRACE` | `config/kernel/Kconfig.trace` | Interrupts-masked / preemption-disabled window tracer |
| `LINK_PROVISIONING_ENFORCED` | `config/subsys/Kconfig.secure-boot` | Brain link provisioning: no boot without a link key, no UART bridge |
| `LINUX_ABI` | `config/axes/Kconfig.personality` | Linux syscall personality (static Linux binaries) |
| `LINUX_DRIVERS` | `config/axes/Kconfig.personality` | Linux driver support (ring-3 servers) |
| `LINUX_IO_MAX` | `config/axes/Kconfig.personality` | Linux personality: bytes one read/write/readv/writev moves at most |
| `LINUX_ROBUST_LIST_LIMIT` | `config/axes/Kconfig.personality` | Linux personality: robust futex list entries walked at a thread's exit |
| `LINUX_RUNTIME` | `config/axes/Kconfig.personality` | Host the Linux personality in a ring-3 runtime (trap reflect) |
| `LIVEPATCH` | `config/kernel/Kconfig.livepatch` | Signed kernel livepatch of non-sleeping functions |
| `LIVEPATCH_ENTRY_NOPS` | `config/kernel/Kconfig.livepatch` | Live-update entry NOPs per function (patchable-function-entry) |
| `LIVEPATCH_FP` | `config/kernel/Kconfig.livepatch` | Live-update frame pointers (-C force-frame-pointers=yes) |
| `LIVEPATCH_GRACE_MS` | `config/kernel/Kconfig.livepatch` | Livepatch: the bounded grace period after a redirect (ms) |
| `LIVEPATCH_MAX_BLOB_KIB` | `config/kernel/Kconfig.livepatch` | Livepatch: largest patch blob (KiB) |
| `LIVEPATCH_MAX_FUNCS` | `config/kernel/Kconfig.livepatch` | Livepatch: functions one patch may replace |
| `LIVEPATCH_MAX_PATCHES` | `config/kernel/Kconfig.livepatch` | Livepatch: patches applied at once |
| `LIVEPATCH_POOL_KIB` | `config/kernel/Kconfig.livepatch` | Live-update patch pool (KiB of RX space in the kernel image) |
| `LOCKDEP_CHAINS` | `config/kernel/Kconfig.lockdep` | Lockdep: lock chains cached as already checked (table size) |
| `LOCKDEP_CLASSES` | `config/kernel/Kconfig.lockdep` | Lockdep: lock classes tracked per class (table size) |
| `LOCKDEP_EDGES` | `config/kernel/Kconfig.lockdep` | Lockdep: dependency edges kept (table size) |
| `LOCKDEP_HOLD_BUCKETS` | `config/kernel/Kconfig.lockdep` | Lockdep: hold-time histogram buckets per class |
| `LOCKDEP_HOLD_ENFORCE` | `config/kernel/Kconfig.lockdep` | Lockdep: a SpinLock held past LOCK_MAX_HOLD_US fails the run |
| `LOCKDEP_HOLD_TOP` | `config/kernel/Kconfig.lockdep` | Lockdep: classes the summary prints by longest hold |
| `LOCKDEP_IRQ_INFERENCE` | `config/kernel/Kconfig.lockdep` | Lockdep: infer interrupt safety per class |
| `LOCKDEP_KTEST` | `config/kernel/Kconfig.lockdep` | In ktest kernels |
| `LOCKDEP_MAX_DEPTH` | `config/kernel/Kconfig.lockdep` | Lockdep: locks one context may hold at once |
| `LOCKDEP_N` | `config/kernel/Kconfig.lockdep` | Off |
| `LOCKDEP_REPORTS` | `config/kernel/Kconfig.lockdep` | Lockdep: violation reports queued for printing |
| `LOCKDEP_RT_CROSS_CPU` | `config/kernel/Kconfig.lockdep` | Lockdep: note a sleeping lock contended by RT tasks on two CPUs |
| `LOCKDEP_SCOPE_CHECKS` | `config/kernel/Kconfig.lockdep` | Lockdep: check lock scopes (PerCpu, CpuOwned, Object levels) |
| `LOCKDEP_Y` | `config/kernel/Kconfig.lockdep` | In every development kernel |
| `LOCKED_HUGE_LEAVES` | `config/arch/Kconfig.isa-riscv64` | Explicit 2 MiB leaves for big fixed regions of locked rows |
| `LOCK_MAX_HOLD_US` | `config/kernel/Kconfig.lockdep` | Longest a SpinLock may be held (us): the IRQs-off bound |
| `LOGD_FILES_KEEP` | `config/kernel/Kconfig.trace` | logd: log files kept (retention) |
| `LOGD_FILE_KB` | `config/kernel/Kconfig.trace` | logd: size at which the log file rotates (KiB) |
| `LOGD_MAX_LEVEL` | `config/kernel/Kconfig.trace` | logd: highest level kept in the files (3 err, 4 warn, 6 info, 7 debug) |
| `LOGD_POLL_MS` | `config/kernel/Kconfig.trace` | logd: how often it drains the ring and writes the files (ms) |
| `LOGIN_GRANT_TTL_S` | `config/subsys/Kconfig.console` | Console login: seconds a verified credential may start its session |
| `LOGIN_LOCKOUT_S` | `config/subsys/Kconfig.console` | Console login: seconds an account stays locked |
| `LOGIN_MAX_FAILURES` | `config/subsys/Kconfig.console` | Console login: wrong credentials in a row before the account is locked |
| `LOGIN_SAK_SERIAL_BYTE` | `config/subsys/Kconfig.console` | Console login: the byte that is the secure-attention key on a serial console |
| `LOG_FLUSHER_JOBS` | `config/limits/Kconfig.limits` | Deferred block-I/O job slots on the log flusher |
| `LOG_FLUSHER_PRIORITY` | `config/kernel/Kconfig.tasks` | Log flusher task priority (outside the RT band: 12..30) |
| `LOG_LEVEL` | `config/kernel/Kconfig.trace` | (no prompt — internal/derived) |
| `LOG_LEVEL_DEBUG` | `config/kernel/Kconfig.trace` | debug: every kernel line |
| `LOG_LEVEL_ERR` | `config/kernel/Kconfig.trace` | err: errors only |
| `LOG_LEVEL_INFO` | `config/kernel/Kconfig.trace` | info: also boot progress and status lines |
| `LOG_LEVEL_WARN` | `config/kernel/Kconfig.trace` | warn: errors, security refusals, safety warnings |
| `LOG_RING_ENTRIES` | `config/limits/Kconfig.limits` | Flight-recorder ring entries (power of two) |
| `LOG_RING_SAFETY_RESERVE` | `config/limits/Kconfig.limits` | Flight-recorder ring slots kept for safety records |
| `LX_ACCEPT_UNCONFINED_DMA` | `config/axes/Kconfig.personality` | Allow DMA-capable Linux servers on a board without an IOMMU |
| `LX_BLUETOOTH` | `config/axes/Kconfig.personality` | Bluetooth |
| `LX_DRM_PANEL` | `config/axes/Kconfig.personality` | Display panels (DRM/KMS panel drivers) |
| `LX_FS_EXT2` | `config/axes/Kconfig.personality` | ext2 |
| `LX_FS_EXT4_RO` | `config/axes/Kconfig.personality` | ext4 read-only (no journal replay) |
| `LX_FS_EXT4_RW` | `config/axes/Kconfig.personality` | ext4 read-write with journal (jbd2) |
| `LX_IIO` | `config/axes/Kconfig.personality` | IIO sensors |
| `LX_MODULE_TOKENS` | `config/axes/Kconfig.personality` | Module verification tokens live at once |
| `LX_SERVER_SKELETON` | `config/axes/Kconfig.personality` | Server skeleton only (development) |
| `LX_SND_ASOC` | `config/axes/Kconfig.personality` | Audio (ALSA core + ASoC codecs) |
| `LX_USB_CDC` | `config/axes/Kconfig.personality` | CDC serial (cdc-acm) |
| `LX_USB_DWC3` | `config/axes/Kconfig.personality` | Board USB controller (xhci-plat over dwc3) |
| `LX_USB_HID` | `config/axes/Kconfig.personality` | HID keyboard / mouse (usbhid) |
| `LX_USB_STORAGE` | `config/axes/Kconfig.personality` | Mass storage (usb-storage) |
| `LX_USB_UVC` | `config/axes/Kconfig.personality` | UVC camera (uvcvideo) |
| `LX_USB_XHCI` | `config/axes/Kconfig.personality` | xHCI host controller over PCI (xhci-pci, usbcore, hub) |
| `LX_WIFI` | `config/axes/Kconfig.personality` | Wi-Fi (mac80211 / cfg80211) |
| `MAX_CAPS_PER_TASK` | `config/limits/Kconfig.limits` | Maximum capabilities per task |
| `MAX_CAPS_TOTAL` | `config/limits/Kconfig.limits` | Total capability pool size |
| `MAX_FDS_PER_PROC` | `config/limits/Kconfig.limits` | File descriptors per process |
| `MAX_FDS_TOTAL` | `config/limits/Kconfig.limits` | Global file descriptor table size |
| `MAX_IO_RINGS` | `config/limits/Kconfig.limits` | Maximum io_rings system-wide |
| `MAX_MEMOBJS` | `config/limits/Kconfig.limits` | Maximum MemObjs system-wide (shared-memory regions and kernel regions) |
| `MAX_MMIO_REGIONS` | `config/limits/Kconfig.limits` | Device windows the kernel records for replay into task tables |
| `MAX_PORTS` | `config/limits/Kconfig.limits` | Maximum IPC ports (rendezvous endpoints) |
| `MAX_PORT_SOURCES` | `config/limits/Kconfig.limits` | Maximum event sources bound to one port |
| `MAX_SOCKETS` | `config/limits/Kconfig.limits` | Maximum total sockets (TCP + UDP) |
| `MAX_TASKS` | `config/limits/Kconfig.limits` | Maximum schedulable tasks |
| `MCP_BRIDGE` | `config/subsys/Kconfig.netsvc` | MCP bridge (MCPD.ELF): the endpoints a row can call as Model Context Protocol tools |
| `MCP_CALL_RATE` | `config/subsys/Kconfig.netsvc` | Tool calls served per second, at most |
| `MCP_ENROL_TTL_MS` | `config/subsys/Kconfig.netsvc` | Life of the operator's warrant printed at boot (ms) |
| `MCP_GRANT_MAX_MS` | `config/subsys/Kconfig.netsvc` | Longest life of a warrant the bridge issues (ms) |
| `MCP_PEER_ADDR` | `config/subsys/Kconfig.netsvc` | IPv4 address the bridge connects to (dotted quad) |
| `MCP_PORT` | `config/subsys/Kconfig.netsvc` | TCP port the bridge connects to |
| `MCP_PROPOSAL_TTL_MS` | `config/subsys/Kconfig.netsvc` | How long a proposed irreversible op waits for its confirmation (ms) |
| `MCP_WARRANT_MAX_MS` | `config/subsys/Kconfig.netsvc` | Longest life of the warrant a call gets from the kernel (ms) |
| `MEMOBJ_MOVED_WINDOWS` | `config/limits/Kconfig.limits` | MemObj: windows of mappings a MOVE removed, awaiting their owner |
| `MEM_KERNEL_RESERVE_KB` | `config/limits/Kconfig.limits` | RAM memory admission keeps back for the kernel (KiB) |
| `MICRO` | `config/kernel/Kconfig.micro` | Describe an AzOS-micro build (riscv32, M-mode, PMP) |
| `MICRO_CAPS_PER_TASK` | `config/kernel/Kconfig.micro` | Capability slots per task |
| `MICRO_CLINT_BASE` | `config/kernel/Kconfig.micro` | CLINT base (mtime, mtimecmp) |
| `MICRO_CONTIG_KIB` | `config/kernel/Kconfig.micro` | Contiguous pool (KiB) |
| `MICRO_IDLE_PRIO` | `config/kernel/Kconfig.micro` | Idle priority |
| `MICRO_KSTACK_BYTES` | `config/kernel/Kconfig.micro` | Kernel stack (bytes) |
| `MICRO_MAX_ENDPOINTS` | `config/kernel/Kconfig.micro` | Named endpoints |
| `MICRO_MAX_TASKS` | `config/kernel/Kconfig.micro` | Tasks (static table) |
| `MICRO_PMP_ENTRIES` | `config/kernel/Kconfig.micro` | PMP entries the hart implements |
| `MICRO_PMP_GRAIN_LOG2` | `config/kernel/Kconfig.micro` | PMP granularity (log2 of bytes) |
| `MICRO_POOL_KIB` | `config/kernel/Kconfig.micro` | Anonymous region pool (KiB) |
| `MICRO_RAM_BASE` | `config/kernel/Kconfig.micro` | RAM base address |
| `MICRO_RAM_KIB` | `config/kernel/Kconfig.micro` | RAM the image may use (KiB) |
| `MICRO_TASK_PMP_ENTRIES` | `config/kernel/Kconfig.micro` | PMP entries one task's domain may use |
| `MICRO_TICK_HZ` | `config/kernel/Kconfig.micro` | Scheduler tick (Hz) |
| `MICRO_TIMEBASE_HZ` | `config/kernel/Kconfig.micro` | mtime frequency (Hz) |
| `MICRO_TIMESLICE_TICKS` | `config/kernel/Kconfig.micro` | Round-robin slice (ticks) |
| `MICRO_UART_BASE` | `config/kernel/Kconfig.micro` | Console UART (16550) base |
| `MITIGATION_SPECTRE_V1_INDEX` | `config/axes/Kconfig.security` | Spectre v1: mask table indices that come from ring 3 |
| `ML_REPLY_TIMEOUT_US` | `config/domains/Kconfig.robot` | Behavior loop: inference service reply timeout (us) |
| `MM_AGING_CHUNKS` | `config/limits/Kconfig.limits` | Page-age table: chunks of 64 pages the reclaimer tracks |
| `MM_AGING_INTERVAL_MS` | `config/kernel/Kconfig.mm` | Page-age pass interval per Domain (ms) |
| `MM_COMPRESS_ALGO_WKDM` | `config/kernel/Kconfig.mm` | wkdm |
| `MM_DEMAND_PAGING` | `config/kernel/Kconfig.mm` | Demand-paged anonymous mmap |
| `MM_PRECOMMIT_RT` | `config/kernel/Kconfig.mm` | Pre-commit mmap for real-time-class tasks |
| `MM_RECLAIM_COMPRESS` | `config/kernel/Kconfig.mm` | reclaim+compress: anonymous pages are compressed before anything else |
| `MM_RECLAIM_HIGH_PCT` | `config/kernel/Kconfig.mm` | Domain reclaim high watermark (% of its frame limit) |
| `MM_RECLAIM_LOW_PCT` | `config/kernel/Kconfig.mm` | Domain reclaim low watermark (% of its frame limit) |
| `MM_RECLAIM_OFF` | `config/kernel/Kconfig.mm` | off: no reclaim; admission instead of overcommit |
| `MM_RECLAIM_POLL_MS` | `config/kernel/Kconfig.mm` | Reclaim task poll interval (ms) |
| `MM_RECLAIM_PRIORITY` | `config/kernel/Kconfig.tasks` | Reclaim task priority (outside the RT band: 12..30) |
| `MM_REGIONS_PER_SPACE` | `config/limits/Kconfig.limits` | Demand-paged mmap region records per address space |
| `MM_SWAP_BACKEND` | `config/kernel/Kconfig.mm` | (no prompt — internal/derived) |
| `MM_SWAP_BACKEND_FILE` | `config/kernel/Kconfig.mm` | file: a swap file on FAT32 or azvol (desktop, iot-hmi) |
| `MM_SWAP_BACKEND_OFF` | `config/kernel/Kconfig.mm` | off: no swap |
| `MM_SWAP_BACKEND_PARTITION` | `config/kernel/Kconfig.mm` | partition: a swap partition (server) |
| `MM_SWAP_DOMAIN_KIB` | `config/limits/Kconfig.limits` | Default swap quota per Domain (KiB; 0 = none) |
| `MM_SWAP_ENCRYPT` | `config/kernel/Kconfig.mm` | (no prompt — internal/derived) |
| `MM_SWAP_FILE_GROW_SEGMENTS` | `config/limits/Kconfig.limits` | Swap file growth step (segments) |
| `MM_SWAP_FILE_PATH` | `config/kernel/Kconfig.mm` | Swap file path (MM_SWAP_BACKEND_FILE) |
| `MM_SWAP_FILE_RUNS` | `config/limits/Kconfig.limits` | Sector runs a swap file may be scattered in (4-128) |
| `MM_SWAP_FILE_SHRINK_POLLS` | `config/kernel/Kconfig.mm` | Idle reclaim passes before the swap file shrinks |
| `MM_SWAP_FULL_PCT` | `config/kernel/Kconfig.mm` | Live share of a segment before it is written out (%) |
| `MM_SWAP_SEGMENTS` | `config/limits/Kconfig.limits` | Segments that can be swapped out at once (swap slots) |
| `MM_THP_RESV` | `config/kernel/Kconfig.mm` | Superpage reservations: a 2 MiB run per aligned anonymous region, promoted when full |
| `MM_ZPOOL_DOMAIN_KIB` | `config/limits/Kconfig.limits` | Default compressed-pool quota per Domain (KiB; 0 = none) |
| `MM_ZPOOL_ENTRIES` | `config/limits/Kconfig.limits` | Compressed-pool index entries (pages it can hold) |
| `MM_ZPOOL_MAX_RATIO_PCT` | `config/kernel/Kconfig.mm` | Largest compressed size worth storing (% of a page) |
| `MM_ZPOOL_SEGMENTS` | `config/limits/Kconfig.limits` | Compressed-pool segments (ceiling on its memory) |
| `MM_ZPOOL_SEGMENT_PAGES` | `config/limits/Kconfig.limits` | Frames per compressed-pool segment |
| `MOTOR_COMMANDER_EXIT_STOP` | `config/domains/Kconfig.robot` | A dead motor commander's wheels go to a safe stop |
| `MULTISTREAM_SCHED_PRIORITY` | `config/domains/Kconfig.brain` | Multi-stream scheduler: priority (control preempts bulk) |
| `NAMES_LEND_TTL_MS` | `config/kernel/Kconfig.ipc` | Lifetime of a capability the name server lends (ms, 0 = the server's own) |
| `NAT_ICMP_TIMEOUT_S` | `config/subsys/Kconfig.net` | NAT: idle timeout of an ICMP echo mapping (s) |
| `NAT_PORT_MAX` | `config/subsys/Kconfig.net` | NAT: highest translated port |
| `NAT_PORT_MIN` | `config/subsys/Kconfig.net` | NAT: lowest translated port |
| `NAT_TABLE_MAX` | `config/subsys/Kconfig.net` | NAT: tracked mappings |
| `NAT_TCP_TIMEOUT_S` | `config/subsys/Kconfig.net` | NAT: idle timeout of an established TCP mapping (s) |
| `NAT_TCP_TRANSIENT_S` | `config/subsys/Kconfig.net` | NAT: timeout of an unanswered or closing TCP mapping (s) |
| `NAT_UDP_TIMEOUT_S` | `config/subsys/Kconfig.net` | NAT: idle timeout of a UDP mapping (s) |
| `NET` | `config/subsys/Kconfig.net` | TCP/IP stack: bring-up, the net-poll task and the network clients |
| `NET_DNS_TIMEOUT_MS` | `config/subsys/Kconfig.net` | How long one DNS query waits for its answer (ms) |
| `NET_IP_FORWARD` | `config/subsys/Kconfig.net` | Forward IPv4 packets between interfaces |
| `NET_IRQ_IDLE_CEILING_MS` | `config/subsys/Kconfig.net` | net poll task longest sleep with an RX interrupt (ms) |
| `NET_MAX_INTERFACES` | `config/subsys/Kconfig.net` | Network interfaces the stack can hold |
| `NET_NAT` | `config/subsys/Kconfig.net` | NAPT: masquerade forwarded traffic behind the uplink |
| `NET_PACKET_RX_SLOTS` | `config/subsys/Kconfig.net` | Frames queued per AF_PACKET socket |
| `NET_PACKET_SOCKETS` | `config/subsys/Kconfig.net` | Raw layer-2 (AF_PACKET) sockets open at once |
| `NET_POLL_PERIOD_US` | `config/subsys/Kconfig.net` | net poll task period while the NIC is polled (us) |
| `NET_RX_BATCH_MAX` | `config/subsys/Kconfig.net` | virtio-net RX frames popped per lock and handed up by reference |
| `NET_RX_DRAIN_PER_POLL` | `config/subsys/Kconfig.net` | Frames drained from the NIC per net_poll pass |
| `NET_RX_IRQ` | `config/subsys/Kconfig.net` | NIC RX interrupt instead of timer polling |
| `NET_TX_BATCH_MAX` | `config/subsys/Kconfig.net` | virtio-net TX frames published per doorbell inside a batch |
| `NET_TX_BATCH_SELFCHECK` | `config/subsys/Kconfig.net` | Boot self-check of virtio-net TX doorbell batching |
| `NET_TX_TIMEOUT_MS` | `config/subsys/Kconfig.net` | NIC transmit ring budget before the device is reset (ms) |
| `NET_VIRTIO_EVENT_IDX` | `config/subsys/Kconfig.net` | virtio-net: negotiate VIRTIO_F_EVENT_IDX on modern transports |
| `NET_VIRTIO_RXQ_SIZE` | `config/subsys/Kconfig.net` | virtio-net RX ring entries (= posted RX buffers) |
| `NET_VIRTIO_TXQ_SIZE` | `config/subsys/Kconfig.net` | virtio-net TX ring entries (2 per frame in flight) |
| `NET_WAIT_SLOTS` | `config/subsys/Kconfig.net` | Tasks that can wait on one kind of network event at once |
| `NOHZ_FULL` | `config/kernel/Kconfig.sched` | Tickless busy CPUs: an isolated CPU running one real-time task stops its tick |
| `NOHZ_FULL_RESIDUAL_MS` | `config/kernel/Kconfig.sched` | NOHZ_FULL: longest a stopped tick sleeps (ms) |
| `NR_CPUS` | `config/limits/Kconfig.limits` | Maximum number of CPUs (ceiling, like Linux CONFIG_NR_CPUS) |
| `NTP_CLIENT` | `config/subsys/Kconfig.netsvc` | SNTP client task: keep the wall clock steered from a time server |
| `NTP_INTERVAL_S` | `config/subsys/Kconfig.netsvc` | Seconds between time exchanges once synchronised |
| `NTP_SERVER` | `config/subsys/Kconfig.netsvc` | Time server: a name or a dotted-quad IPv4 address (empty: only a lease names one) |
| `NVME_INFLIGHT` | `config/limits/Kconfig.limits` | NVMe commands in flight at once (1-8) |
| `NVME_QUEUES` | `config/limits/Kconfig.limits` | NVMe I/O queue pairs (1-8, at most one per CPU) |
| `NVME_QUEUE_DEPTH` | `config/limits/Kconfig.limits` | NVMe I/O queue depth (entries per submission/completion queue) |
| `NVME_SLOT_KB` | `config/limits/Kconfig.limits` | NVMe bounce buffer per in-flight slot (KiB; one command's largest transfer) |
| `OTA_FLOOR_BOOTMETA` | `config/subsys/Kconfig.ota` | BOOTMETA: the FAT volume's boot record only |
| `OTA_FLOOR_TPM_NV` | `config/subsys/Kconfig.ota` | TPM NV: BOOTMETA and a TPM NV index, the higher wins |
| `OTA_MAX_IMAGE_SIZE_MB` | `config/subsys/Kconfig.ota` | Maximum OTA image size (MiB) |
| `OTA_SIG_MANDATORY` | `config/subsys/Kconfig.ota` | OTA images must be signed (refuse unsigned updates) |
| `PAGE_SHIFT` | `config/arch/Kconfig.isa` | (no prompt — internal/derived) |
| `PANIC_CONTAIN_LAND_MS` | `config/kernel/Kconfig.panic` | Contained panic: Land duration before Disarm (ms) |
| `PANIC_POLICY_CONTAIN` | `config/kernel/Kconfig.panic` | Contain (park the culprit task; the control loop keeps running) |
| `PANIC_POLICY_RESET` | `config/kernel/Kconfig.panic` | Reset (every panic: safe state, then halt or reboot) |
| `PANIC_QUIESCE` | `config/kernel/Kconfig.panic` | Panic: stop the other CPUs and own the console before the report |
| `PANIC_STOP_WAIT_US` | `config/kernel/Kconfig.panic` | Panic: how long to wait for the other CPUs to park (us) |
| `PCI_SOC_HOST` | `config/subsys/Kconfig.drivers` | SoC PCIe host controllers: JH7110 (PLDA) and BCM2712 (brcmstb) |
| `PID_DT_MS` | `config/domains/Kconfig.robot` | Motor PID loop delta-T (ms) |
| `PI_MAX_DEPTH` | `config/limits/Kconfig.limits` | Longest ownership chain a priority-inheritance walk follows |
| `PI_TRACE_DEPTH` | `config/limits/Kconfig.limits` | Mutex trace: nesting levels recorded per task (diagnostics) |
| `PKG_FETCH_TFTP` | `config/subsys/Kconfig.packages` | Installer may fetch a package from a TFTP server (development builds) |
| `PKG_MAX_API` | `config/subsys/Kconfig.packages` | Interface levels one package may require |
| `PKG_MAX_IMAGES` | `config/subsys/Kconfig.packages` | Programs one package may carry |
| `PKG_MAX_KB` | `config/subsys/Kconfig.packages` | Largest package the installer accepts (KiB) |
| `PKG_MAX_STAGED` | `config/subsys/Kconfig.packages` | Packages staged at once |
| `PKG_META_MAX_KB` | `config/subsys/Kconfig.packages` | Largest manifest or warrant section of a package (KiB) |
| `PKG_SNAPSHOTS_KEPT` | `config/subsys/Kconfig.packages` | Restore points of the package volume kept |
| `PLACEMENT_HOLDOFF_S` | `config/kernel/Kconfig.tasks` | Placement: hold-off after a fault in the kernel host (seconds) |
| `PLACEMENT_PROMOTE_MISSES` | `config/kernel/Kconfig.tasks` | Placement: calls over the budget that ask for a move into the kernel |
| `PMM_MAX_ORDER` | `config/limits/Kconfig.limits` | Largest physically contiguous block the page allocator forms (order) |
| `PMM_PCP_BATCH` | `config/limits/Kconfig.limits` | Frames a hart moves between its page cache and the buddy lists at once |
| `PMM_PCP_HIGH` | `config/limits/Kconfig.limits` | Most single frames one hart keeps in its page cache |
| `PMM_TYPE_ZONES` | `config/kernel/Kconfig.mm` | Type-isolated physical frames (page tables and io_ring pages) |
| `PMM_ZONE_MAX_PAGES` | `config/limits/Kconfig.limits` | Most frames one type zone may own (0: no bound) |
| `PMP_REGIONS_RESERVED` | `config/arch/Kconfig.isa-riscv64` | PMP regions reserved for M-mode kernel use |
| `PMU_USER` | `config/arch/Kconfig.isa` | Let ring 3 read the cycle and instruction counters |
| `POWER_OFF_STEP_TIMEOUT_MS` | `config/subsys/Kconfig.storage` | Orderly power-off: longest wait for one storage step (ms) |
| `PRESET_AUTOMOTIVE` | `config/axes/Kconfig.preset` | Embedded control: Automotive (ECU, ADAS, telematics) |
| `PRESET_DESKTOP` | `config/axes/Kconfig.preset` | Computers: Desktop (workstation, laptop, mini-PC) |
| `PRESET_FIRMWARE` | `config/axes/Kconfig.preset` | Embedded control: Firmware (BMC, storage or power controllers) |
| `PRESET_GATEWAY` | `config/axes/Kconfig.preset` | Connected devices: Gateway (edge router, protocol bridge) |
| `PRESET_GENERIC` | `config/axes/Kconfig.preset` | General: Generic (QEMU, development, evaluation) |
| `PRESET_INDUSTRIAL` | `config/axes/Kconfig.preset` | Embedded control: Industrial (PLC, CNC, motion control) |
| `PRESET_IOT_HMI` | `config/axes/Kconfig.preset` | Connected devices: IoT / HMI (smart panels, kiosks, appliances) |
| `PRESET_ROBOT` | `config/axes/Kconfig.preset` | Embedded control: Robot (mobile robots, drones, robotic arms) |
| `PRESET_SERVER` | `config/axes/Kconfig.preset` | Computers: Server (rack server, cloud node, NAS) |
| `PRESET_WEARABLE` | `config/axes/Kconfig.preset` | Connected devices: Wearable (smartwatch, fitness band) |
| `PROFILER` | `config/kernel/Kconfig.trace` | Sampling profiler: timer-driven PC and stack samples |
| `PROFILER_DEPTH` | `config/kernel/Kconfig.trace` | Profiler: frames per sample (the PC included) |
| `PROFILER_TICK_DIV` | `config/kernel/Kconfig.trace` | Profiler: sample every Nth scheduler tick |
| `PROXY_REPLY_TIMEOUT_MS` | `config/subsys/Kconfig.drivers` | Ring-3 driver proxy: reply timeout (ms) |
| `PROXY_SPIN_US` | `config/subsys/Kconfig.drivers` | Ring-3 driver proxy: spin before blocking on a reply (us) |
| `PS2_WAIT_SPINS` | `config/subsys/Kconfig.drivers` | PS/2: status reads a controller wait gives up after |
| `PSTORE_SIZE_KB` | `config/arch/Kconfig.platform` | Panic record region in RAM (KiB, 0 = off) |
| `PTPD` | `config/subsys/Kconfig.netsvc` | PTP daemon (PTPD.ELF): IEEE 1588 slave over UDP steering the wall clock |
| `PTPD_DOMAIN` | `config/subsys/Kconfig.netsvc` | PTP domain of the built-in topology's [clock] row |
| `QOS_SLACK_BACKGROUND_US` | `config/kernel/Kconfig.sched` | Timer slack of QOS_BACKGROUND (us) |
| `QOS_SLACK_DEFAULT_US` | `config/kernel/Kconfig.sched` | Timer slack of QOS_DEFAULT, the hint every task starts with (us) |
| `QOS_SLACK_LATENCY_US` | `config/kernel/Kconfig.sched` | Timer slack of QOS_LATENCY (us) |
| `QOS_SLACK_THROUGHPUT_US` | `config/kernel/Kconfig.sched` | Timer slack of QOS_THROUGHPUT (us) |
| `QOS_TIMER_TOLERANCE` | `config/kernel/Kconfig.sched` | QoS timer tolerance: a task's QoS tier lets its timers fire late and share wake-ups |
| `QOS_TIMER_TOLERANCE_ROWS_ONLY` | `config/kernel/Kconfig.sched` | Only tasks whose topology row says timer_slack = true get slack |
| `RAM_SIZE` | `config/arch/Kconfig.platform` | RAM size (MiB) |
| `RCU_CALLBACK_PRIORITY` | `config/kernel/Kconfig.sync` | RCU: callback task priority (outside the RT band: 12..30) |
| `RCU_GP_POLL_MS` | `config/kernel/Kconfig.sync` | RCU: grace-period poll interval of a waiter (ms) |
| `RCU_NOCBS_CPUS` | `config/kernel/Kconfig.sync` | RCU: CPUs that never run RCU callbacks (the RT CPUs, a mask) |
| `RCU_QSBR` | `config/kernel/Kconfig.sync` | Read-copy-update, quiescent-state based (QSBR) |
| `RCU_STALL_TIMEOUT_MS` | `config/kernel/Kconfig.sync` | RCU: a grace period older than this is a stall (ms) |
| `RC_DRIVE_CHANNEL` | `config/domains/Kconfig.robot` | RC channel of the drive (forward/back) stick (1-16) |
| `RC_FAILSAFE_ESTOP` | `config/domains/Kconfig.robot` | RC link loss latches the e-stop |
| `RC_INPUT` | `config/domains/Kconfig.robot` | RC receiver feeds the safety path |
| `RC_KILL_CHANNEL` | `config/domains/Kconfig.robot` | RC channel of the kill switch (1-16, 0 = none) |
| `RC_LINK_TIMEOUT_MS` | `config/domains/Kconfig.robot` | RC link timeout (ms) |
| `RC_MODE_CHANNEL` | `config/domains/Kconfig.robot` | RC channel of the manual-override switch (1-16, 0 = none) |
| `RC_STEER_CHANNEL` | `config/domains/Kconfig.robot` | RC channel of the steering stick (1-16) |
| `RC_STICK_DEADBAND_US` | `config/domains/Kconfig.robot` | RC stick deadband (us) |
| `RC_STICK_FULL_SCALE_PCT` | `config/domains/Kconfig.robot` | RC stick full-deflection speed (percent) |
| `RC_SWITCH_HIGH_US` | `config/domains/Kconfig.robot` | RC switch threshold (us) |
| `RECOVERY_CONSOLE` | `config/subsys/Kconfig.console` | Recovery console: a kernel console task for when ring 3 cannot start |
| `RELIBC` | `config/axes/Kconfig.libc` | relibc: libc.a and the test C programs (make relibc) |
| `RING3_MEM_PAGES_DEFAULT` | `config/limits/Kconfig.limits` | Frame budget of a ring-3 topology row that declares none (pages) |
| `RISCV64_LEVEL_RV64GC` | `config/arch/Kconfig.isa-riscv64` | rv64gc (+ F, D, Zicsr, Zifencei: JH7110 / VisionFive 2) |
| `RISCV64_LEVEL_RV64GCV` | `config/arch/Kconfig.isa-riscv64` | rv64gcv (+ V 1.0: SpacemiT K1 / X60) |
| `RISCV64_LEVEL_RV64IMAC` | `config/arch/Kconfig.isa-riscv64` | rv64imac (QEMU virt, any RV64 with atomics and C) |
| `ROBOT_ACKERMANN` | `config/domains/Kconfig.robot` | Ackermann (car-like, 2-channel: throttle + steering) |
| `ROBOT_DRONE` | `config/domains/Kconfig.robot` | Drone (4-channel quadrotor PWM) |
| `ROBOT_HUMANOID` | `config/domains/Kconfig.robot` | Humanoid (N-channel joint angles) |
| `ROBOT_NONE` | `config/domains/Kconfig.robot` | None (no platform chosen at build time) |
| `ROBOT_TYPE_ID` | `config/domains/Kconfig.robot` | (no prompt — internal/derived) |
| `ROBOT_WHEELED` | `config/domains/Kconfig.robot` | Wheeled (2-channel differential drive) |
| `RPC_DEDUPE_WINDOW` | `config/subsys/Kconfig.rpc` | Calls per session the far node remembers the answer of |
| `RPC_MISS_LIMIT` | `config/subsys/Kconfig.rpc` | Unanswered probes or calls in a row that break a session |
| `RPC_NODE_ID` | `config/subsys/Kconfig.rpc` | This node's id on the RPC links |
| `RPC_PEER_ADDR` | `config/subsys/Kconfig.rpc` | IPv4 address of the peer's RPC server (dotted quad) |
| `RPC_PEER_NODE` | `config/subsys/Kconfig.rpc` | Node id of the peer node (0 = none: the RPC server is not started) |
| `RPC_PEER_NOISE_PK` | `config/subsys/Kconfig.rpc` | Static Noise (X25519) public key of the peer node (64 hex digits) |
| `RPC_PING_MS` | `config/subsys/Kconfig.rpc` | Silence after which a session is probed (ms) |
| `RPC_QUIC` | `config/subsys/Kconfig.rpc` | Carry the RPC link over QUIC (through the rpcquic relay) |
| `RPC_QUIC_PORT` | `config/subsys/Kconfig.rpc` | UDP port of the QUIC connection between the relays |
| `RPC_QUIC_RELAY_PORT` | `config/subsys/Kconfig.rpc` | Local UDP port of the rpcquic relay |
| `RPC_RETRIES` | `config/subsys/Kconfig.rpc` | Resends of a call before it is given up (idempotent, at-most-once) |
| `RPC_REVOKE_BOUND_MS` | `config/subsys/Kconfig.rpc` | Bound on a revocation reaching a peer (ms) |
| `RPC_RTO_MS` | `config/subsys/Kconfig.rpc` | Wait for an answer before a resend (ms) |
| `RPC_UDP_PORT` | `config/subsys/Kconfig.rpc` | UDP port of the RPC link |
| `RPC_WARRANT_TTL_MS` | `config/subsys/Kconfig.rpc` | Lifetime of a warrant minted for a peer (ms) |
| `RPI_FIRMWARE` | `config/subsys/Kconfig.drivers` | Raspberry Pi VideoCore firmware mailbox (power domains, and thermal) |
| `RTC_FLOOR_YEAR` | `config/subsys/Kconfig.drivers` | RTC: earliest year the kernel believes |
| `RTC_PCF8563_I2C_BUS` | `config/subsys/Kconfig.drivers` | RTC: I2C bus the PCF8563 sits on |
| `RTC_UIP_POLLS` | `config/subsys/Kconfig.drivers` | RTC: status reads a CMOS update wait gives up after |
| `RT_BAND_CAP_PCT` | `config/kernel/Kconfig.sched` | RT band budget: share of each window the band may use (%) |
| `RT_BAND_WINDOW_MS` | `config/kernel/Kconfig.sched` | RT band budget: window (ms) |
| `RT_BLOCK_IO_CHECK` | `config/kernel/Kconfig.trace` | Panic when a real-time task enters the block layer |
| `RT_CONSOLE_WIRE_CHECK` | `config/kernel/Kconfig.trace` | Panic when a real-time task waits for the console wire |
| `RT_HARD` | `config/axes/Kconfig.rt` | Hard |
| `RT_MIXED` | `config/axes/Kconfig.rt` | Mixed (a hard cluster beside a general cluster) |
| `RT_NONE` | `config/axes/Kconfig.rt` | None |
| `RT_SOFT` | `config/axes/Kconfig.rt` | Soft |
| `RV_AIA_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_AIA_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_AIA_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_H_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_H_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_H_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_KERNEL_GLOBAL` | `config/arch/Kconfig.isa-riscv64` | Global (G) bit on the kernel half's leaves |
| `RV_PMU_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_PMU_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_PMU_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_SSQOSID_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_SSQOSID_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_SSQOSID_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_SSTC_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_SSTC_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_SSTC_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_SVADU_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_SVADU_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_SVADU_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_SVINVAL_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_SVINVAL_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_SVINVAL_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_SVNAPOT_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_SVNAPOT_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_SVNAPOT_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_SVPBMT_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_SVPBMT_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_SVPBMT_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_V_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_V_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_V_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZACAS_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZACAS_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZACAS_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZAWRS_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZAWRS_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZAWRS_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZBA_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZBA_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZBA_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZBB_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZBB_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZBB_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZBS_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZBS_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZBS_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZICBOM_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZICBOM_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZICBOM_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZICBOZ_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZICBOZ_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZICBOZ_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZIHINTPAUSE_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZIHINTPAUSE_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZIHINTPAUSE_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `RV_ZKR_NEVER` | `config/arch/Kconfig.isa-riscv64` | n: never use it |
| `RV_ZKR_PROBE` | `config/arch/Kconfig.isa-riscv64` | probe: use it when the boot finds it, fall back otherwise |
| `RV_ZKR_REQUIRE` | `config/arch/Kconfig.isa-riscv64` | require: baseline; refuse to boot without it |
| `SAFETY_COMMS_TIMEOUT_S` | `config/domains/Kconfig.robot` | Safety comms timeout (seconds) |
| `SAFETY_DRONE_COMMS_TIMEOUT_S` | `config/domains/Kconfig.robot` | Drone comms timeout (seconds) |
| `SCHED_BALANCE` | `config/kernel/Kconfig.sched` | Fair class: balance load between CPUs |
| `SCHED_BALANCE_INTERVAL_MS` | `config/kernel/Kconfig.sched` | Load balancing: push interval (ms) |
| `SCHED_BALANCE_MOVES` | `config/kernel/Kconfig.sched` | Load balancing: moves per pass |
| `SCHED_BALANCE_SCAN` | `config/kernel/Kconfig.sched` | Load balancing: queue entries examined per pass |
| `SCHED_CLASS_DL` | `config/kernel/Kconfig.sched` | Dispatch class: deadline (EDF + CBS reservations) |
| `SCHED_CLASS_FAIR` | `config/kernel/Kconfig.sched` | (no prompt — internal/derived) |
| `SCHED_CLASS_IDLE` | `config/kernel/Kconfig.sched` | (no prompt — internal/derived) |
| `SCHED_CLASS_RT` | `config/kernel/Kconfig.sched` | Dispatch class: real-time band (fixed priority) |
| `SCHED_CLASS_STOP` | `config/kernel/Kconfig.sched` | (no prompt — internal/derived) |
| `SCHED_CORE` | `config/kernel/Kconfig.sched` | Core scheduling: SMT siblings run one Domain at a time |
| `SCHED_CORE_PATIENCE_US` | `config/kernel/Kconfig.sched` | Core scheduling: wait before a fair task displaces its siblings (us) |
| `SCHED_CORE_SCAN` | `config/kernel/Kconfig.sched` | Core scheduling: queued tasks looked at per pick |
| `SCHED_DEFAULT_FAIR` | `config/kernel/Kconfig.sched` | Fair, unless the priority is the band or idle |
| `SCHED_DEFAULT_LEGACY` | `config/kernel/Kconfig.sched` | By priority (band -> RT, idle -> idle, else fair) |
| `SCHED_DEFAULT_RT` | `config/kernel/Kconfig.sched` | RT for every non-idle task (static RT appliances only) |
| `SCHED_EAS` | `config/kernel/Kconfig.sched` | Energy-aware wake placement on asymmetric CPUs |
| `SCHED_HZ` | `config/kernel/Kconfig.sched` | Scheduler tick frequency (Hz) |
| `SCHED_HZ_FLOOR` | `config/kernel/Kconfig.sched` | (no prompt — internal/derived) |
| `SCHED_IPC_AFFINITY` | `config/kernel/Kconfig.sched` | Fast-IPC hand-off wakes co-locate on the waker's hart |
| `SCHED_O1_PLACEMENT` | `config/kernel/Kconfig.sched` | O(priorities) wake placement (a per-priority load histogram) |
| `SCHED_REMOTE_WAKE_DEFER` | `config/kernel/Kconfig.sched` | Defer a contended wake onto another CPU to that CPU |
| `SCHED_SAVING_GATE_CLOCK_EVERY` | `config/kernel/Kconfig.sched` | Spins between clock reads in the context-saving gate |
| `SCHED_SAVING_GATE_US` | `config/kernel/Kconfig.sched` | Longest wait for a picked task's context save (us) |
| `SCHED_SWITCH_COUNTERS` | `config/kernel/Kconfig.sched` | Count each task's context switches (voluntary / preempted) |
| `SCHED_TIMER_HEAP` | `config/kernel/Kconfig.sched` | Timer sleepers in an indexed min-heap |
| `SCHED_TIMER_HEAP_PER_CPU` | `config/kernel/Kconfig.sched` | One timer-sleeper heap per CPU (sched-timer-heap) |
| `SCHED_TIMER_WAKE_BATCH` | `config/kernel/Kconfig.sched` | Timer sleepers popped per heap lock hold (sched-timer-heap) |
| `SCHED_WAKE_PREEMPT_CANARY` | `config/axes/Kconfig.build` | Canary: a wake-up does not ask the waking CPU to reschedule for a better class |
| `SDK_THREAD_STACK_KB` | `config/limits/Kconfig.limits` | Native SDK: default stack of a std thread, KiB |
| `SECONDARY_STACK_SIZE_KB` | `config/limits/Kconfig.limits` | Boot stack of each secondary CPU (KiB) |
| `SECURE_BOOT_ENFORCED` | `config/subsys/Kconfig.secure-boot` | Enforce Ed25519 signature verification at boot |
| `SECURITY_CONFIDENTIAL` | `config/axes/Kconfig.security` | Confidential |
| `SECURITY_GENERAL` | `config/axes/Kconfig.security` | General |
| `SECURITY_HARDENED` | `config/axes/Kconfig.security` | Hardened |
| `SECURITY_SEPARATION_STATIC` | `config/axes/Kconfig.security` | Separation, static |
| `SH_START_TIMEOUT_S` | `config/subsys/Kconfig.console` | User shell: seconds to take the console before the recovery console does |
| `SLAB_HARDENED` | `config/kernel/Kconfig.hardening` | Harden the slab and buddy free lists (obfuscated links, safe unlink) |
| `SOC_FRAMEWORKS` | `config/arch/Kconfig.platform` | SoC resource frameworks: clocks, resets, regulators, power domains from the device tree |
| `SOC_JH7110` | `config/arch/Kconfig.platform` | StarFive JH7110 providers: clock and reset controllers, power management unit, pad controllers |
| `SOC_K1` | `config/arch/Kconfig.platform` | SpacemiT K1 providers: CPU cluster clocks with their PLL tree |
| `SPINLOCK_IMPL_MCS` | `config/kernel/Kconfig.sync` | mcs: queued (qspinlock), FIFO |
| `SPINLOCK_IMPL_TTAS` | `config/kernel/Kconfig.sync` | ttas: test-and-test-and-set |
| `SPINLOCK_MCS_NODES` | `config/kernel/Kconfig.sync` | Queued SpinLock: nesting levels per CPU |
| `SPINLOCK_MCS_PENDING` | `config/kernel/Kconfig.sync` | Queued SpinLock: pending bit |
| `SPIN_WAIT_RELAX_SPINS` | `config/kernel/Kconfig.sync` | Spin-wait: relax polls before the wait hint |
| `SSHD` | `config/subsys/Kconfig.netsvc` | SSH server (SSHD.ELF): remote commands over SSH-2, public-key login only |
| `SSHD_PORT` | `config/subsys/Kconfig.netsvc` | TCP port the SSH server listens on |
| `STRUCTURE_HYBRID` | `config/axes/Kconfig.structure` | Hybrid (each driver in the kernel or ring 3, as its own choice says) |
| `STRUCTURE_RING3_DRIVERS` | `config/axes/Kconfig.structure` | Drivers as ring-3 servers |
| `SUP_RESTART_BURST` | `config/kernel/Kconfig.tasks` | Supervised driver: restarts allowed within the interval |
| `SUP_RESTART_INTERVAL_S` | `config/kernel/Kconfig.tasks` | Supervised driver: restart-limit interval (seconds) |
| `SWITCH_CENSUS` | `config/axes/Kconfig.build` | Census of the yield-and-switch path, phase by phase |
| `SWITCH_CENSUS_DUMP_MIN` | `config/axes/Kconfig.build` | Fewest switches that make a census dump worth printing |
| `SYSCALL_FILTER_MAX` | `config/limits/Kconfig.limits` | Syscall filter entries per image profile |
| `SYSCALL_LEAN_ENTRY` | `config/kernel/Kconfig.ipc` | Native syscalls save only what the native ABI preserves |
| `SYSTEM_SUSPEND` | `config/arch/Kconfig.platform` | System suspend to RAM |
| `TASK_AUTORUN_PLACE` | `config/kernel/Kconfig.tasks` | autorun loader: placement class |
| `TASK_AUTORUN_PRIORITY` | `config/kernel/Kconfig.tasks` | autorun loader: priority (12 .. 30) |
| `TASK_BEHAVIOR_PLACE` | `config/kernel/Kconfig.tasks` | Robot behavior (behavior, brain-tx, camera-tx, ml-infer): placement class |
| `TASK_CONTROL_PLACE` | `config/kernel/Kconfig.tasks` | Robot control loops (rt-motor, flight-ctrl): placement class |
| `TASK_IOMMU_FAULTS_PRIORITY` | `config/kernel/Kconfig.tasks` | iommu-faults: priority (12 .. 30) |
| `TASK_NET_POLL_PLACE` | `config/kernel/Kconfig.tasks` | net-poll: placement class |
| `TASK_NET_POLL_PRIORITY` | `config/kernel/Kconfig.tasks` | net-poll: priority (0 most urgent .. 31) |
| `TASK_OTA_RECV_PLACE` | `config/kernel/Kconfig.tasks` | ota-recv: placement class |
| `TASK_RECOVERY_PRIORITY` | `config/kernel/Kconfig.tasks` | recovery console: priority (12 .. 30) |
| `TASK_RT_CLUSTER_CPUS` | `config/kernel/Kconfig.tasks` | Real-time cluster: CPUs, from the boot CPU up |
| `TASK_SENSING_PLACE` | `config/kernel/Kconfig.tasks` | Robot sensor loops (imu, sensor-ahrs): placement class |
| `TASK_SYS_WDT_PLACE` | `config/kernel/Kconfig.tasks` | sys-wdt: placement class |
| `TCP_BUF_SIZE` | `config/subsys/Kconfig.net` | TCP per-connection receive and send ring (bytes) |
| `TCP_DELACK_MS` | `config/subsys/Kconfig.net` | TCP delayed-ACK bound (ms); 0 = acknowledge every segment at once |
| `TCP_DELACK_PASS_FLUSH` | `config/subsys/Kconfig.net` | Flush held ACKs at the end of each network poll pass |
| `TCP_DELACK_SEGS` | `config/subsys/Kconfig.net` | Full-sized segments received before an immediate ACK |
| `TCP_ECN` | `config/subsys/Kconfig.net` | TCP Explicit Congestion Notification (RFC 3168) |
| `TCP_EPHEMERAL_PORT_MAX` | `config/subsys/Kconfig.net` | Highest local port a TCP connect may pick |
| `TCP_EPHEMERAL_PORT_MIN` | `config/subsys/Kconfig.net` | Lowest local port a TCP connect may pick |
| `TCP_MAX_CONNS` | `config/limits/Kconfig.limits` | Maximum simultaneous TCP connections |
| `TCP_RECV_MAX_PER_CALL` | `config/subsys/Kconfig.net` | Most bytes one TCP recv() copies out |
| `TCP_SYNCOOKIES` | `config/subsys/Kconfig.net` | TCP SYN cookies under a SYN flood (RFC 4987) |
| `TCP_TIMESTAMPS` | `config/subsys/Kconfig.net` | TCP timestamps (RFC 7323): RTT measurement and PAWS |
| `TCP_WINDOW_UPDATE_SHIFT` | `config/subsys/Kconfig.net` | Window update sent at once when the edge moves by ring >> N |
| `THERMAL` | `config/kernel/Kconfig.energy` | Thermal framework: zones, trips and cooling by OPP capping |
| `THERMAL_TASK_PRIORITY` | `config/kernel/Kconfig.energy` | Thermal task priority (outside the RT band: 12..30) |
| `THERMAL_X86_CRITICAL_C` | `config/kernel/Kconfig.energy` | x86_64 package: critical trip (degrees Celsius) |
| `THERMAL_X86_HOT_C` | `config/kernel/Kconfig.energy` | x86_64 package: hot trip (degrees Celsius) |
| `THERMAL_X86_PASSIVE_C` | `config/kernel/Kconfig.energy` | x86_64 package: passive trip (degrees Celsius) |
| `THERMAL_X86_POLL_MS` | `config/kernel/Kconfig.energy` | x86_64 package: polling delay (ms) |
| `TIMER_FREQ` | `config/arch/Kconfig.platform` | Timer frequency (Hz) |
| `TLB_ASID_SCOPED` | `config/kernel/Kconfig.mm` | ASID-scoped shootdowns: invalidate only the target address space's ASID |
| `TLB_FLUSH_CEILING_PAGES` | `config/kernel/Kconfig.mm` | Pages above which a ranged TLB flush drops the whole address space |
| `TLB_RETAIN` | `config/kernel/Kconfig.mm` | Keep TLB entries across user address-space switches (ASID/PCID tags) |
| `TLB_SPACE_MASK` | `config/kernel/Kconfig.mm` | Per-address-space hart mask: a shootdown marks stale only the harts that ran the space |
| `TLB_SPACE_PROBE` | `config/kernel/Kconfig.mm` | Per-address-space hart mask: probes before the table counts as full |
| `TLB_SPACE_SLOTS_BITS` | `config/kernel/Kconfig.mm` | Per-address-space hart mask: table size (log2 slots) |
| `TMPFS_MAX_FILES` | `config/limits/Kconfig.limits` | Maximum files in tmpfs |
| `TMPFS_MAX_KB` | `config/limits/Kconfig.limits` | tmpfs data capacity (KiB) |
| `TOOLBOX_INSTANCES` | `config/limits/Kconfig.limits` | Live TOOLBOX.ELF processes the shell can run at once |
| `TOPOLOGY_BIND_DEVICE` | `config/subsys/Kconfig.topology` | The signed topology must name this device |
| `TOPOLOGY_CAPS_MAX_KB` | `config/subsys/Kconfig.topology` | Largest CAPS.TOM the boot reads (KiB) |
| `TOPOLOGY_COUNTER_FLOOR` | `config/subsys/Kconfig.topology` | Refuse a signed topology older than the last one accepted |
| `TOPOLOGY_DRIVETRAIN` | `config/subsys/Kconfig.topology` | The built-in topology may declare the drivetrain |
| `TOPOLOGY_EXPORTS_TOTAL` | `config/subsys/Kconfig.topology` | Export entries across the RPC server's row |
| `TOPOLOGY_FLOOR_SECTOR` | `config/subsys/Kconfig.topology` | Reserved tail sector of the topology counter floor |
| `TOPOLOGY_GUEST_DEVICES` | `config/subsys/Kconfig.topology` | Device backends one guest row may list |
| `TOPOLOGY_GUEST_PASSTHROUGH` | `config/subsys/Kconfig.topology` | Devices one [guest.NAME] row may pass through |
| `TOPOLOGY_IMPORTS_TOTAL` | `config/subsys/Kconfig.topology` | Imports declared across all rows of a topology |
| `TOPOLOGY_INLINE_FIELDS_MAX` | `config/subsys/Kconfig.topology` | Fields in one grant's inline table |
| `TOPOLOGY_INVALID_FALLBACK` | `config/subsys/Kconfig.topology` | Fall back to the built-in topology |
| `TOPOLOGY_INVALID_HALT` | `config/subsys/Kconfig.topology` | Halt |
| `TOPOLOGY_ISLAND_WAKE` | `config/subsys/Kconfig.topology` | Wake events one [island.NAME] row may list |
| `TOPOLOGY_LEAP_ENTRIES` | `config/subsys/Kconfig.topology` | Leap-second entries the [clock] row of a topology may declare |
| `TOPOLOGY_LOGIN_KEYS` | `config/subsys/Kconfig.topology` | ssh_key entries one [login.NAME] row may list |
| `TOPOLOGY_MAX_ACTIVITIES` | `config/subsys/Kconfig.topology` | [activity.NAME] rows (deferred work) a topology may declare |
| `TOPOLOGY_MAX_AUDIO` | `config/subsys/Kconfig.topology` | [audio.NAME] rows (audio streams) a topology may declare |
| `TOPOLOGY_MAX_BOOT_STAGES` | `config/subsys/Kconfig.topology` | [boot_chain.NAME] rows (boot stages) a topology may declare |
| `TOPOLOGY_MAX_CLASSES` | `config/subsys/Kconfig.topology` | Scheduler classes a topology may declare |
| `TOPOLOGY_MAX_DEVICE_ROWS` | `config/subsys/Kconfig.topology` | [device.NAME] rows a topology may declare |
| `TOPOLOGY_MAX_DISPLAYS` | `config/subsys/Kconfig.topology` | [display.NAME] rows (panels) a topology may declare |
| `TOPOLOGY_MAX_ENVELOPES` | `config/subsys/Kconfig.topology` | [envelope.NAME] rows (effect ceilings) a topology may declare |
| `TOPOLOGY_MAX_FIELDBUS` | `config/subsys/Kconfig.topology` | [fieldbus.NAME] rows (fieldbus masters) a topology may declare |
| `TOPOLOGY_MAX_FIREWALL_ROWS` | `config/subsys/Kconfig.topology` | [firewall.NAME] rows (packet filter rules) a topology may declare |
| `TOPOLOGY_MAX_GUESTS` | `config/subsys/Kconfig.topology` | [guest.NAME] rows (virtual machines the device may run) a topology may declare |
| `TOPOLOGY_MAX_IMPORTS` | `config/subsys/Kconfig.topology` | Names one task row may import from the name server |
| `TOPOLOGY_MAX_ISLANDS` | `config/subsys/Kconfig.topology` | [island.NAME] rows (low-power islands) a topology may declare |
| `TOPOLOGY_MAX_KEYS` | `config/subsys/Kconfig.topology` | [key.NAME] rows (named keys) a topology may declare |
| `TOPOLOGY_MAX_LIVEPATCHES` | `config/subsys/Kconfig.topology` | [livepatch.NAME] rows (signed kernel patches the device admits) a topology may declare |
| `TOPOLOGY_MAX_LOGINS` | `config/subsys/Kconfig.topology` | [login.NAME] rows (SSH logins) a topology may declare |
| `TOPOLOGY_MAX_MODELS` | `config/subsys/Kconfig.topology` | [model.NAME] rows (model bundles) a topology may declare |
| `TOPOLOGY_MAX_NICS` | `config/subsys/Kconfig.topology` | [nic.NAME] rows (network interfaces) a topology may declare |
| `TOPOLOGY_MAX_NUMA` | `config/subsys/Kconfig.topology` | [numa.NAME] rows (memory nodes) a topology may declare |
| `TOPOLOGY_MAX_PEERS` | `config/subsys/Kconfig.topology` | [peer.NAME] sections (classes of remote nodes) a topology may declare |
| `TOPOLOGY_MAX_PIPELINES` | `config/subsys/Kconfig.topology` | [pipeline.NAME] sections a topology may declare |
| `TOPOLOGY_MAX_POLICIES` | `config/subsys/Kconfig.topology` | [policy.NAME] rows (limits on a Domain and its subtree) a topology may declare |
| `TOPOLOGY_MAX_ROUTES` | `config/subsys/Kconfig.topology` | [route.NAME] rows (static routes) a topology may declare |
| `TOPOLOGY_MAX_SIGNERS` | `config/subsys/Kconfig.topology` | Package signers one topology may admit |
| `TOPOLOGY_MAX_SWAPS` | `config/subsys/Kconfig.topology` | [swap.NAME] rows (swap areas on a partition) a topology may declare |
| `TOPOLOGY_MAX_TSN` | `config/subsys/Kconfig.topology` | [tsn.NAME] rows (TSN admissions) a topology may declare |
| `TOPOLOGY_MAX_USB_RULES` | `config/subsys/Kconfig.topology` | [usb.NAME] rows (USB authorization rules) a topology may declare |
| `TOPOLOGY_MAX_USERS` | `config/subsys/Kconfig.topology` | [user.NAME] rows (human users) a topology may declare |
| `TOPOLOGY_MAX_VOLUMES` | `config/subsys/Kconfig.topology` | [volume.NAME] rows (native volumes to mount) a topology may declare |
| `TOPOLOGY_NAME_MAX` | `config/subsys/Kconfig.topology` | Longest task, class or pipeline name in a topology (bytes) |
| `TOPOLOGY_NEVERALLOW` | `config/subsys/Kconfig.topology` | Refuse a topology that breaks a neverallow rule |
| `TOPOLOGY_PEER_NODES` | `config/subsys/Kconfig.topology` | Nodes one peer class may list |
| `TOPOLOGY_SCHED_MAX_KB` | `config/subsys/Kconfig.topology` | Largest SCHED.TOM the boot reads (KiB) |
| `TOPOLOGY_SIGNER_WARRANTS_TOTAL` | `config/subsys/Kconfig.topology` | Warrant ceilings declared across all signers |
| `TOPOLOGY_SOURCE_BUILTIN` | `config/subsys/Kconfig.topology` | Built-in only (never read the volume) |
| `TOPOLOGY_SOURCE_SIGNED_OR_BUILTIN` | `config/subsys/Kconfig.topology` | Signed if present and valid, else built-in |
| `TOPOLOGY_SOURCE_SIGNED_REQUIRED` | `config/subsys/Kconfig.topology` | Signed required (halt without it) |
| `TOPOLOGY_TARGET_MAX` | `config/subsys/Kconfig.topology` | Longest grant target in a topology (bytes) |
| `TPM` | `config/subsys/Kconfig.entropy` | TPM 2.0 (entropy, measured boot, OTA rollback floor) |
| `TPM_PCR_BASE` | `config/subsys/Kconfig.entropy` | First PCR of the boot measurements |
| `TPM_SPI_BUS` | `config/subsys/Kconfig.entropy` | SPI bus the device-tree TPM sits on |
| `UART_16550_TX_FIFO_DEPTH` | `config/subsys/Kconfig.drivers` | Console: 16550 transmit FIFO depth (bytes per THR-empty) |
| `UDP_MAX_SOCKETS` | `config/subsys/Kconfig.net` | UDP sockets (bound ports) the stack holds |
| `UDP_RX_SLOTS` | `config/subsys/Kconfig.net` | Datagrams queued per UDP socket |
| `USB_BIND_MAX_TIER` | `config/limits/Kconfig.limits` | USB: hub tiers below the root whose devices may bind a driver |
| `USB_CDC` | `config/subsys/Kconfig.usb` | USB CDC devices: network adapters (ECM, NCM) as NICs, serial devices (ACM) as Uart ports |
| `USB_CDC_BUFS` | `config/limits/Kconfig.limits` | USB CDC: transfers in flight per direction (bulk buffers) |
| `USB_CDC_CONSOLE` | `config/subsys/Kconfig.usb` | USB serial console: the console on the first CDC-ACM device that comes up |
| `USB_CDC_CONSOLE_BAUD` | `config/subsys/Kconfig.usb` | USB serial console: line rate asked of the device (baud) |
| `USB_CDC_CONSOLE_BYTES` | `config/limits/Kconfig.limits` | USB serial console: bytes of output queued for the device |
| `USB_CDC_NTB_KB` | `config/limits/Kconfig.limits` | USB CDC-NCM: network transfer block size (KiB, a multiple of 4) |
| `USB_DWC2` | `config/subsys/Kconfig.usb` | DesignWare USB 2.0 OTG core as a host (Raspberry Pi; device tree) |
| `USB_HID` | `config/subsys/Kconfig.usb` | USB HID class driver (keyboards and mice) |
| `USB_HID_ADMIT` | `config/subsys/Kconfig.usb` | USB HID: devices may bind without a signed row |
| `USB_HID_MAX_IFACES` | `config/limits/Kconfig.limits` | USB HID interfaces served at once |
| `USB_HID_REFUSE_COMPOSITE` | `config/subsys/Kconfig.usb` | USB HID: refuse a keyboard that is also storage or a serial/network port |
| `USB_HID_REPEAT_DELAY_MS` | `config/subsys/Kconfig.usb` | USB keyboard: milliseconds a key is held before it repeats |
| `USB_HID_REPEAT_PERIOD_MS` | `config/subsys/Kconfig.usb` | USB keyboard: milliseconds between repeats of a held key |
| `USB_HOST` | `config/subsys/Kconfig.usb` | USB host stack (core, hubs, class-driver interface) |
| `USB_MAX_DEVICES` | `config/limits/Kconfig.limits` | USB devices tracked at once (hubs included) |
| `USB_MAX_PIPES` | `config/limits/Kconfig.limits` | USB pipes open at once (bulk and interrupt, all devices) |
| `USB_MSC_TIMEOUT_MS` | `config/subsys/Kconfig.usb` | USB mass storage: milliseconds a command may take |
| `USB_MSC_XFER_KB` | `config/limits/Kconfig.limits` | USB mass storage: data staging buffer per disk (KiB, a multiple of 4) |
| `USB_PIPE_DEPTH` | `config/limits/Kconfig.limits` | USB pipe ring entries (transfers in flight per pipe; a power of two) |
| `USB_POLL_MS` | `config/subsys/Kconfig.usb` | USB service period (ms): how often the usb task drains the controller |
| `USB_SMSC95XX` | `config/subsys/Kconfig.usb` | USB Ethernet: SMSC LAN95xx (the Raspberry Pi 3 B's on-board Ethernet) as a NIC |
| `USB_STORAGE` | `config/subsys/Kconfig.usb` | USB mass storage (bulk-only sticks and disks) as a block device |
| `USB_STORAGE_VOLUME` | `config/subsys/Kconfig.usb` | Mount the FAT32 volume of a USB stick beside /fat |
| `USB_UVC` | `config/subsys/Kconfig.usb` | USB video class (UVC webcams) as the perception camera |
| `USB_VOLUME_CACHE_KB` | `config/subsys/Kconfig.usb` | USB stick volume: sector cache (KiB, 0 or a power of two from 4) |
| `USB_XHCI` | `config/subsys/Kconfig.usb` | xHCI host controller (USB 3.x/2.0/1.1, PCI class 0C0330 and device tree) |
| `USERSPACE_ABICHILD` | `tools/gen_userspace_kconfig.py` | ABICHILD.ELF (userspace/tests/abichild) |
| `USERSPACE_ABITEST` | `tools/gen_userspace_kconfig.py` | ABITEST.ELF (userspace/tests/abitest) |
| `USERSPACE_AUDIOD` | `tools/gen_userspace_kconfig.py` | AUDIOD.ELF (userspace/services/audiod) |
| `USERSPACE_BEHAVIOR` | `tools/gen_userspace_kconfig.py` | BEHAVIOR.ELF (userspace/services/famtools) |
| `USERSPACE_BRAINCLI` | `tools/gen_userspace_kconfig.py` | BRAINCLI.ELF (userspace/services/brain_client) |
| `USERSPACE_BUZZDRV` | `tools/gen_userspace_kconfig.py` | BUZZDRV.ELF (userspace/drivers/buzz_drv) |
| `USERSPACE_CAPTEST` | `tools/gen_userspace_kconfig.py` | CAPTEST.ELF (userspace/tests/captest) |
| `USERSPACE_COMPMGR` | `tools/gen_userspace_kconfig.py` | COMPMGR.ELF (userspace/services/compmgr) |
| `USERSPACE_COMPSRV` | `tools/gen_userspace_kconfig.py` | COMPSRV.ELF (userspace/services/compositor) |
| `USERSPACE_CONFIG` | `tools/gen_userspace_kconfig.py` | CONFIG.ELF (userspace/services/famtools) |
| `USERSPACE_DECISD` | `tools/gen_userspace_kconfig.py` | DECISD.ELF (userspace/services/decisd) |
| `USERSPACE_EPSRV` | `tools/gen_userspace_kconfig.py` | EPSRV.ELF (userspace/tests/epsrv) |
| `USERSPACE_FLIGHT` | `tools/gen_userspace_kconfig.py` | FLIGHT.ELF (userspace/services/famtools) |
| `USERSPACE_GPIODRV` | `tools/gen_userspace_kconfig.py` | GPIODRV.ELF (userspace/drivers/gpio_drv) |
| `USERSPACE_GPL` | `config/axes/Kconfig.personality` | Allow third-party GPL userspace programs (e.g. BusyBox) |
| `USERSPACE_HELLO` | `tools/gen_userspace_kconfig.py` | HELLO.ELF (userspace/tests/hello) |
| `USERSPACE_INADRV` | `tools/gen_userspace_kconfig.py` | INADRV.ELF (userspace/drivers/ina_drv) |
| `USERSPACE_INPUTD` | `tools/gen_userspace_kconfig.py` | INPUTD.ELF (userspace/services/inputd) |
| `USERSPACE_IPCTEST` | `tools/gen_userspace_kconfig.py` | IPCTEST.ELF (userspace/tests/ipctest) |
| `USERSPACE_LATBENCH` | `tools/gen_userspace_kconfig.py` | LATBENCH.ELF (userspace/bench/latbench) |
| `USERSPACE_LOGD` | `tools/gen_userspace_kconfig.py` | LOGD.ELF (userspace/services/logd) |
| `USERSPACE_LOGIND` | `tools/gen_userspace_kconfig.py` | LOGIND.ELF (userspace/services/logind) |
| `USERSPACE_LXHELLO` | `tools/gen_userspace_kconfig.py` | LXHELLO.ELF (userspace/tests/lxhello) |
| `USERSPACE_LXSRV` | `tools/gen_userspace_kconfig.py` | LXSRV.ELF (userspace/services/lxsrv) |
| `USERSPACE_LXTHR` | `tools/gen_userspace_kconfig.py` | LXTHR.ELF (userspace/tests/lxthreads) |
| `USERSPACE_MCPD` | `tools/gen_userspace_kconfig.py` | MCPD.ELF (userspace/services/mcpd) |
| `USERSPACE_MLSRV` | `tools/gen_userspace_kconfig.py` | MLSRV.ELF (userspace/services/infsrv) |
| `USERSPACE_NAMESD` | `tools/gen_userspace_kconfig.py` | NAMESD.ELF (userspace/services/namesd) |
| `USERSPACE_OTA` | `tools/gen_userspace_kconfig.py` | OTA.ELF (userspace/services/famtools) |
| `USERSPACE_PKG` | `tools/gen_userspace_kconfig.py` | PKG.ELF (userspace/services/pkg) |
| `USERSPACE_PKGD` | `tools/gen_userspace_kconfig.py` | PKGD.ELF (userspace/services/pkgd) |
| `USERSPACE_POWER` | `tools/gen_userspace_kconfig.py` | POWER.ELF (userspace/services/power) |
| `USERSPACE_PTPD` | `tools/gen_userspace_kconfig.py` | PTPD.ELF (userspace/services/ptpd) |
| `USERSPACE_REFLEX` | `tools/gen_userspace_kconfig.py` | REFLEX.ELF (userspace/services/reflex) |
| `USERSPACE_RPCQUIC` | `tools/gen_userspace_kconfig.py` | RPCQUIC.ELF (userspace/services/rpcquic) |
| `USERSPACE_RPCSRV` | `tools/gen_userspace_kconfig.py` | RPCSRV.ELF (userspace/services/rpcsrv) |
| `USERSPACE_SH` | `tools/gen_userspace_kconfig.py` | SH.ELF (userspace/services/sh) |
| `USERSPACE_SSHD` | `tools/gen_userspace_kconfig.py` | SSHD.ELF (userspace/services/sshd) |
| `USERSPACE_SYSTEST` | `tools/gen_userspace_kconfig.py` | SYSTEST.ELF (userspace/tests/syscall_test) |
| `USERSPACE_TERMD` | `tools/gen_userspace_kconfig.py` | TERMD.ELF (userspace/services/termd) |
| `USERSPACE_TOOLBOX` | `tools/gen_userspace_kconfig.py` | TOOLBOX.ELF (userspace/services/toolbox) |
| `USERSPACE_TRACECTL` | `tools/gen_userspace_kconfig.py` | TRACECTL.ELF (userspace/services/tracectl) |
| `USERSPACE_UHELLO` | `tools/gen_userspace_kconfig.py` | UHELLO.ELF (userspace/tests/uhello) |
| `USERSPACE_VMMD` | `tools/gen_userspace_kconfig.py` | VMMD.ELF (userspace/services/vmmd) |
| `USERSPACE_VSBENCH` | `tools/gen_userspace_kconfig.py` | VSBENCH.ELF (userspace/bench/vsbench) |
| `USERSPACE_VSSRV` | `tools/gen_userspace_kconfig.py` | VSSRV.ELF (userspace/bench/vssrv) |
| `USERSPACE_WHY` | `tools/gen_userspace_kconfig.py` | WHY.ELF (userspace/services/why) |
| `USERSPACE_ZENOHD` | `tools/gen_userspace_kconfig.py` | ZENOHD.ELF (userspace/services/zenohd) |
| `USER_ALLOC_BLOCK_KB` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: size-class block, KiB |
| `USER_ALLOC_GUARD_PAGES` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: guard pages around blocks and large allocations |
| `USER_ALLOC_MAX_MAPS` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: live mappings (blocks + large allocations) |
| `USER_ALLOC_POISON_FREED` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: poison freed chunks and check the poison |
| `USER_ALLOC_QUARANTINE_KB` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: quarantine of freed small chunks, KiB (0 = off) |
| `USER_ALLOC_QUARANTINE_SLOTS` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: quarantine entries |
| `USER_ALLOC_RANDOMIZE` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: randomize chunk placement |
| `USER_ALLOC_SEED_REQUIRED` | `config/kernel/Kconfig.hardening` | Ring-3 allocator: fault when no kernel entropy is available |
| `USER_SHELL` | `config/subsys/Kconfig.console` | (no prompt — internal/derived) |
| `USER_STACK_MAX_KB` | `config/limits/Kconfig.limits` | Largest user stack an image may ask for (KiB) |
| `USER_STACK_SIZE_KB` | `config/limits/Kconfig.limits` | Default user-task stack size (KiB) |
| `USE_AUTOMOTIVE` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_DESKTOP` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_GATEWAY` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_GENERIC` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_INDUSTRIAL` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_IOT_HMI` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_ROBOT` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_SERVER` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `USE_WEARABLE` | `config/axes/Kconfig.use` | (no prompt — internal/derived) |
| `VFS_MAX_FILES` | `config/limits/Kconfig.limits` | Maximum inodes in the in-kernel RAM filesystem |
| `VFS_MAX_MOUNTS` | `config/limits/Kconfig.limits` | Maximum mounted filesystems |
| `VIRTIO_BLK_INFLIGHT` | `config/limits/Kconfig.limits` | virtio-blk requests in flight at once (1-8) |
| `VIRTIO_BLK_IRQ_SLICE_US` | `config/subsys/Kconfig.storage` | virtio-blk: longest sleep of a waiter between completion checks (us) |
| `VIRTIO_BLK_QUEUES` | `config/limits/Kconfig.limits` | virtio-blk request queues used (1-4) |
| `VIRTIO_BLK_SLOT_KB` | `config/limits/Kconfig.limits` | virtio-blk bounce buffer per in-flight slot (KiB; one request's largest transfer) |
| `VIRT_HOSTED` | `config/axes/Kconfig.virt` | Hosted (guests run beside the kernel) |
| `VIRT_NONE` | `config/axes/Kconfig.virt` | None |
| `VIRT_SPLIT` | `config/axes/Kconfig.virt` | Split (a resident monitor under the kernel) |
| `VIRT_STATIC` | `config/axes/Kconfig.virt` | Static partitioning (pinned guests, fixed at build time) |
| `WAIT_GRAPH` | `config/kernel/Kconfig.sync` | Wait graph: one priority-inheritance core for mutex, PI futex and IPC |
| `WAIT_SLICE_US` | `config/kernel/Kconfig.sched` | Bounded sleeps: longest sleep without a wake (us) |
| `WAKE_RING_ENTRIES` | `config/kernel/Kconfig.trace` | Wake attribution: wakes the last-wake ring holds (power of two, 0 = off) |
| `WAKE_RING_SAMPLE_LOG2` | `config/kernel/Kconfig.trace` | Wake attribution: log one wake in 2^N of those tasks make (0 = all) |
| `WARRANT_DEPTH_MAX` | `config/limits/Kconfig.limits` | Warrant tree: longest derivation chain below a root capability |
| `WCET_MAX_POINTS` | `config/limits/Kconfig.limits` | Maximum WCET measurement points (fixed + per-function) |
| `WDT_BCM2835_PM` | `config/subsys/Kconfig.drivers` | Raspberry Pi PM block: hardware watchdog, reboot and power-off (BCM2835/6/7) |
| `WDT_BCM2835_PM_ARM` | `config/subsys/Kconfig.drivers` | Raspberry Pi PM block: arm it as the hardware watchdog |
| `WDT_SBSA` | `config/subsys/Kconfig.drivers` | Arm SBSA Generic Watchdog |
| `WDT_SP5100_TCO` | `config/subsys/Kconfig.drivers` | AMD FCH watchdog (SP5100 TCO) on Zen chipsets |
| `X86_64_LEVEL_V1` | `config/arch/Kconfig.isa-x86_64` | x86-64 (v1: SSE2) |
| `X86_64_LEVEL_V2` | `config/arch/Kconfig.isa-x86_64` | x86-64-v2 (SSE4.2, POPCNT, CMPXCHG16B) |
| `X86_64_LEVEL_V3` | `config/arch/Kconfig.isa-x86_64` | x86-64-v3 (AVX, AVX2, BMI1/2, F16C, FMA, LZCNT, MOVBE, XSAVE) |
| `X86_64_LEVEL_V4` | `config/arch/Kconfig.isa-x86_64` | x86-64-v4 (+ AVX-512 F, BW, CD, DQ, VL) |
| `X86_ADX_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_ADX_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_ADX_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AES_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AES_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AES_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AP_INIT_DELAY_US` | `config/arch/Kconfig.platform` | Wait after INIT before the first STARTUP IPI (us) |
| `X86_AP_SIPI_DELAY_US` | `config/arch/Kconfig.platform` | Wait after each STARTUP IPI (us) |
| `X86_AP_START_TIMEOUT_MS` | `config/arch/Kconfig.platform` | Wait for a secondary CPU to acknowledge its start (ms) |
| `X86_AP_TRAMPOLINE_PA` | `config/arch/Kconfig.platform` | AP real-mode trampoline page (0 = choose) |
| `X86_AVX2_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX2_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX2_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AVX512BW_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX512BW_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX512BW_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AVX512CD_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX512CD_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX512CD_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AVX512DQ_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX512DQ_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX512DQ_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AVX512F_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX512F_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX512F_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AVX512VL_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX512VL_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX512VL_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_AVX_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_AVX_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_AVX_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_BMI1_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_BMI1_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_BMI1_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_BMI2_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_BMI2_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_BMI2_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_BOOT_LIMINE` | `config/arch/Kconfig.platform` | Limine boot protocol (a PC: UEFI or BIOS through Limine) |
| `X86_BOOT_PVH` | `config/arch/Kconfig.platform` | PVH (QEMU microvm -kernel, Xen PVH) |
| `X86_CET_IBT_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_CET_IBT_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_CET_IBT_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_CET_SHSTK_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_CET_SHSTK_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_CET_SHSTK_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_CMDLINE_MAX` | `config/arch/Kconfig.platform` | Kernel command-line bytes kept from the PVH start_info |
| `X86_FMA_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_FMA_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_FMA_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_FSGSBASE_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_FSGSBASE_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_FSGSBASE_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_GBPAGES_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_GBPAGES_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_GBPAGES_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_HPET` | `config/arch/Kconfig.platform` | Calibrate the TSC against the HPET |
| `X86_IMAGE_MAX_MIB` | `config/arch/Kconfig.platform` | Largest kernel image the boot maps (MiB) |
| `X86_INVARIANT_TSC_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_INVARIANT_TSC_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_INVARIANT_TSC_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_INVLPGB_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_INVLPGB_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_INVLPGB_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_INVPCID_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_INVPCID_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_INVPCID_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_IOAPIC_FALLBACK_BASE` | `config/arch/Kconfig.platform` | IOAPIC MMIO base when there is no MADT |
| `X86_IRQ_VECTOR_BASE` | `config/arch/Kconfig.platform` | IDT vector of GSI 0 (IOAPIC device lines) |
| `X86_IST_STACK_SIZE_KB` | `config/arch/Kconfig.isa-x86_64` | IST stack for #DF, NMI and #MC, each (KiB) |
| `X86_KERNEL_GLOBAL_PAGES` | `config/arch/Kconfig.isa-x86_64` | Global (G) kernel leaves |
| `X86_LA57_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_LA57_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_LA57_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_LAPIC_TIMER_DIVIDE` | `config/arch/Kconfig.platform` | LAPIC timer divide (one-shot fallback) |
| `X86_MIT_BHI_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_BHI_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_BHI_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_GDS_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_GDS_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_GDS_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_L1TF_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_L1TF_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_L1TF_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_MDS_TAA_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_MDS_TAA_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_MDS_TAA_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_MELTDOWN_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_MELTDOWN_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_MELTDOWN_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_RETBLEED_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_RETBLEED_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_RETBLEED_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_RFDS_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_RFDS_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_RFDS_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_SPECTRE_V2_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_SPECTRE_V2_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_SPECTRE_V2_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_SRSO_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_SRSO_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_SRSO_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MIT_ZENBLEED_NEVER` | `config/axes/Kconfig.security` | n: do not look at it, do nothing |
| `X86_MIT_ZENBLEED_PROBE` | `config/axes/Kconfig.security` | probe: mitigate when the CPU is affected, say so when the tree cannot |
| `X86_MIT_ZENBLEED_REQUIRE` | `config/axes/Kconfig.security` | require: refuse to boot on an affected CPU the tree cannot mitigate |
| `X86_MOVBE_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_MOVBE_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_MOVBE_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_MSI_VECTORS` | `config/arch/Kconfig.platform` | IDT vectors reserved for PCI MSI and MSI-X |
| `X86_PCID_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_PCID_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_PCID_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_PCI_ECAM_BASE` | `config/arch/Kconfig.platform` | PCI ECAM base when the firmware has no MCFG (0: use ports 0xCF8/0xCFC) |
| `X86_PCI_MEM32_BASE` | `config/arch/Kconfig.platform` | PCI 32-bit memory window: first address (BAR assignment) |
| `X86_PCI_MEM32_SIZE` | `config/arch/Kconfig.platform` | PCI 32-bit memory window: size |
| `X86_PCLMULQDQ_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_PCLMULQDQ_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_PCLMULQDQ_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_PKU_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_PKU_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_PKU_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_PMTIMER` | `config/arch/Kconfig.platform` | Calibrate the TSC against the ACPI PM timer when there is no HPET |
| `X86_PMU_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_PMU_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_PMU_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_POPCNT_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_POPCNT_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_POPCNT_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_QEMU_DEBUG_EXIT` | `config/axes/Kconfig.build` | Power-off and reset leave QEMU through isa-debug-exit (x86_64) |
| `X86_RDRAND_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_RDRAND_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_RDRAND_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_RDSEED_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_RDSEED_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_RDSEED_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SHA_NI_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_SHA_NI_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_SHA_NI_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SMAP_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_SMAP_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_SMAP_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SMEP_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_SMEP_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_SMEP_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SPLIT_LOCK_KERNEL_PANIC` | `config/arch/Kconfig.isa-x86_64` | x86_64: a split lock in the kernel panics (development) instead of warning |
| `X86_SPLIT_LOCK_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_SPLIT_LOCK_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_SPLIT_LOCK_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SSE4_2_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_SSE4_2_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_SSE4_2_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SVM_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_SVM_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_SVM_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_SYSRET` | `config/arch/Kconfig.isa-x86_64` | Return from system calls with sysretq |
| `X86_TSC_CALIBRATE_MS` | `config/arch/Kconfig.platform` | TSC (and LAPIC timer) calibration window (ms) |
| `X86_TSC_DEADLINE_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_TSC_DEADLINE_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_TSC_DEADLINE_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_TSC_FREQ_CPUID` | `config/arch/Kconfig.platform` | Trust the TSC rate CPUID reports (leaf 15H, hypervisor leaf) |
| `X86_UMIP_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_UMIP_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_UMIP_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_UMWAIT_C02` | `config/kernel/Kconfig.sync` | x86_64: UMWAIT may enter C0.2 (deeper, slower wake) |
| `X86_UMWAIT_TSC_TICKS` | `config/kernel/Kconfig.sync` | x86_64: UMWAIT deadline (TSC ticks) |
| `X86_VIRTIO_MMIO_BASE` | `config/arch/Kconfig.platform` | First virtio-mmio transport (QEMU microvm) |
| `X86_VIRTIO_MMIO_MAX` | `config/arch/Kconfig.platform` | virtio-mmio transports kept and scanned |
| `X86_VIRTIO_MMIO_STRIDE` | `config/arch/Kconfig.platform` | virtio-mmio transport stride |
| `X86_VMX_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_VMX_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_VMX_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_WAITPKG_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_WAITPKG_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_WAITPKG_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_X2APIC_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_X2APIC_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_X2APIC_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_XSAVEOPT_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_XSAVEOPT_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_XSAVEOPT_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_XSAVES_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_XSAVES_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_XSAVES_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `X86_XSAVE_AREA_BYTES` | `config/arch/Kconfig.isa-x86_64` | Per-task FP/SIMD save area (bytes, a multiple of 64) |
| `X86_XSAVE_NEVER` | `config/arch/Kconfig.isa-x86_64` | n: never use it |
| `X86_XSAVE_PROBE` | `config/arch/Kconfig.isa-x86_64` | probe: use it when the boot finds it, fall back otherwise |
| `X86_XSAVE_REQUIRE` | `config/arch/Kconfig.isa-x86_64` | require: baseline; refuse to boot without it |
| `ZENOH_DECISIONS_KEY` | `config/subsys/Kconfig.netsvc` | Key expression the Decisions ops are served under as queryables (empty: none) |
| `ZENOH_DECISION_TOPIC` | `config/subsys/Kconfig.netsvc` | Key prefix the kernel's decision records are published under (empty: none) |
| `ZENOH_GW` | `config/subsys/Kconfig.netsvc` | Zenoh gateway (ZENOHD.ELF): the decision records as topics, the Decisions ops as queryables |
| `ZENOH_LEASE_MS` | `config/subsys/Kconfig.netsvc` | Silence from the router after which the session is dropped (ms) |
| `ZENOH_QUERY_RATE` | `config/subsys/Kconfig.netsvc` | Queries served per second, at most |
| `ZENOH_QUERY_TIMEOUT_MS` | `config/subsys/Kconfig.netsvc` | Longest life of the warrant a query gets (ms) |
| `ZENOH_ROUTER_ADDR` | `config/subsys/Kconfig.netsvc` | IPv4 address of the Zenoh router (dotted quad) |
| `ZENOH_ROUTER_PORT` | `config/subsys/Kconfig.netsvc` | TCP port of the Zenoh router |
