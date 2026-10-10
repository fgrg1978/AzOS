# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS (Rust) - Makefile wrapper
# Wraps cargo build + QEMU invocation

QEMU  := qemu-system-riscv64
QEMU_FLAGS := -machine virt -nographic -bios default
CARGO := $(shell command -v cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)

# Cargo output paths
TARGET := riscv64imac-unknown-none-elf
PROFILE ?= release
ifeq ($(PROFILE),release)
    CARGO_FLAGS := --release
    TARGET_DIR := target/$(TARGET)/release
else
    CARGO_FLAGS :=
    TARGET_DIR := target/$(TARGET)/debug
endif

KERNEL_ELF := $(TARGET_DIR)/kernel

# User-space toolchain
RISCV_AS  := riscv64-unknown-elf-as
RISCV_LD  := riscv64-unknown-elf-ld
HELLO_DIR     := userspace/tests/hello
HELLO_ELF     := build/hello.elf
# RFC-0047: a static Linux binary built from our own C (no C library), run
# under the Linux personality. Built with any Linux-targeting clang and
# rustc's own rust-lld; see the `$(LXHELLO_ELF)` rule.
LXHELLO_DIR   := userspace/tests/lxhello
LXHELLO_ELF   := build/lxhello.elf
SYSTEST_DIR   := userspace/tests/syscall_test
SYSTEST_ELF   := build/syscall_test.elf
# E11.AQ3 — ring-3 GPIO driver (Rust no_std ELF, built standalone).
GPIO_DRV_DIR  := userspace/drivers/gpio_drv
GPIO_DRV_BUILT:= $(GPIO_DRV_DIR)/target/riscv64imac-unknown-none-elf/release/gpio_drv
GPIO_DRV_ELF  := build/gpio_drv.elf
# Wave 9 — the ring-3 ML inference service the behavior task spawns
# (`kernel/src/behavior_ml.rs`). Same standalone shape as gpio_drv.
MLSRV_DIR     := userspace/services/mlsrv
MLSRV_BUILT   := $(MLSRV_DIR)/target/riscv64imac-unknown-none-elf/release/mlsrv
MLSRV_ELF     := build/mlsrv.elf

# Wave 9 (DRV1) — the ring-3 buzzer and INA219 drivers (RFC-0040 rule 3).
# Started by the kernel from their `start = true` topology rows, not by
# autorun. Shipped only on the drivers disks below (and the board volume).
BUZZ_DRV_DIR  := userspace/drivers/buzz_drv
BUZZ_DRV_BUILT:= $(BUZZ_DRV_DIR)/target/riscv64imac-unknown-none-elf/release/buzz_drv
BUZZ_DRV_ELF  := build/buzz_drv.elf
INA_DRV_DIR   := userspace/drivers/ina_drv
INA_DRV_BUILT := $(INA_DRV_DIR)/target/riscv64imac-unknown-none-elf/release/ina_drv
INA_DRV_ELF   := build/ina_drv.elf
# RFC-0055 (wave 11): the user shell and its multicall tool image.
SH_DIR        := userspace/services/sh
SH_BUILT      := $(SH_DIR)/target/riscv64imac-unknown-none-elf/release/sh
SH_ELF        := build/sh.elf
SH_SRC        := $(SH_DIR)/src/main.rs $(SH_DIR)/src/edit.rs $(SH_DIR)/src/parse.rs \
                 $(SH_DIR)/src/path.rs $(SH_DIR)/src/req.rs $(SH_DIR)/Cargo.toml
TOOLBOX_DIR   := userspace/services/toolbox
TOOLBOX_BUILT := $(TOOLBOX_DIR)/target/riscv64imac-unknown-none-elf/release/toolbox
TOOLBOX_ELF   := build/toolbox.elf
TOOLBOX_SRC   := $(TOOLBOX_DIR)/src/main.rs $(TOOLBOX_DIR)/Cargo.toml
# RFC-0055 S5: the power tool (`Cap<Power>`, `SYS_POWER_TYPED`).
POWER_DIR     := userspace/services/power
POWER_BUILT   := $(POWER_DIR)/target/riscv64imac-unknown-none-elf/release/power
POWER_ELF     := build/power.elf
POWER_SRC     := $(POWER_DIR)/src/main.rs $(POWER_DIR)/Cargo.toml
# Wave 15 (TRACE): the kernel tracer's reader (`Cap<Trace>`, `SYS_TRACE_CTL_TYPED`).
TRACECTL_DIR  := userspace/services/tracectl
TRACECTL_BUILT:= $(TRACECTL_DIR)/target/riscv64imac-unknown-none-elf/release/tracectl
TRACECTL_ELF  := build/tracectl.elf
TRACECTL_SRC  := $(TRACECTL_DIR)/src/main.rs $(TRACECTL_DIR)/Cargo.toml
# Wave 12: the other privileged families' tools, one crate with one binary
# each (`FLIGHT.ELF`, `BEHAVIOR.ELF`, `CONFIG.ELF`, `OTA.ELF`).
FAMTOOLS_DIR  := userspace/services/famtools
FAMTOOLS_SRC  := $(wildcard $(FAMTOOLS_DIR)/src/*.rs $(FAMTOOLS_DIR)/src/bin/*.rs) $(FAMTOOLS_DIR)/Cargo.toml
FAMTOOLS_OUT  := $(FAMTOOLS_DIR)/target/riscv64imac-unknown-none-elf/release
FLIGHT_ELF    := build/flight.elf
BEHAVIOR_ELF  := build/behavior.elf
CONFIG_ELF    := build/config.elf
OTA_ELF       := build/ota.elf
FAM_ELFS      := $(FLIGHT_ELF) $(BEHAVIOR_ELF) $(CONFIG_ELF) $(OTA_ELF)
# RFC-0053 L0/L0b: the Linux driver server skeleton. Links the module loader
# (crates/core/lx-loader, no Linux code) and nothing from lx/.
LXSRV_DIR     := userspace/services/lxsrv
LXSRV_BUILT   := $(LXSRV_DIR)/target/riscv64imac-unknown-none-elf/release/lxsrv
LXSRV_ELF     := build/lxsrv.elf
LXSRV_SRC     := $(LXSRV_DIR)/src/main.rs $(LXSRV_DIR)/Cargo.toml \
                 $(wildcard crates/core/lx-loader/src/*.rs) crates/core/lx-loader/Cargo.toml
# Three more standalone Rust ring-3 ELFs. They compiled and were never once
# executed: nothing built them (they are absent from the `userspace:` target
# below), so nothing copied them to a disk image and nothing could exec them.
# Same shape of hole SYSTEST.ELF sat in for months.
UHELLO_DIR    := userspace/tests/uhello
UHELLO_BUILT  := $(UHELLO_DIR)/target/riscv64imac-unknown-none-elf/release/uhello
UHELLO_ELF    := build/uhello.elf
# RFC-0040 gap 2 stage 2b — the server half of `endpoint.demo`. A separate
# image from uhello because a ring-3 program's role on an endpoint is its
# capability permission, and permissions come from the topology row looked up
# by IMAGE NAME: one image, one row, one role. See userspace/tests/epsrv/src/main.rs.
VSSRV_DIR     := userspace/bench/vssrv
VSSRV_BUILT   := $(VSSRV_DIR)/target/riscv64imac-unknown-none-elf/release/vssrv
VSSRV_ELF     := build/vssrv.elf
EPSRV_DIR     := userspace/tests/epsrv
EPSRV_BUILT   := $(EPSRV_DIR)/target/riscv64imac-unknown-none-elf/release/epsrv
EPSRV_ELF     := build/epsrv.elf
REFLEX_DIR    := userspace/services/reflex
REFLEX_BUILT  := $(REFLEX_DIR)/target/riscv64imac-unknown-none-elf/release/reflex
REFLEX_ELF    := build/reflex.elf
BRAINCLI_DIR  := userspace/services/brain_client
BRAINCLI_BUILT:= $(BRAINCLI_DIR)/target/riscv64imac-unknown-none-elf/release/brain_client
BRAINCLI_ELF  := build/brain_client.elf
# captest — ring-3 capability test (positive AND negative halves).
CAPTEST_DIR   := userspace/tests/captest
CAPTEST_BUILT := $(CAPTEST_DIR)/target/riscv64imac-unknown-none-elf/release/captest
CAPTEST_ELF   := build/captest.elf
# latbench — ring-3 syscall latency microbenchmark.
# vsbench - the same ring-3 work, measured on Azos and on Linux/riscv64.
# The Linux side is NOT built here: it needs a different target and its own
# toolchain.
VSBENCH_DIR   := userspace/bench/vsbench
VSBENCH_BUILT := $(VSBENCH_DIR)/target/riscv64imac-unknown-none-elf/release/vsbench
VSBENCH_ELF   := build/vsbench.elf

LATBENCH_DIR  := userspace/bench/latbench
LATBENCH_BUILT:= $(LATBENCH_DIR)/target/riscv64imac-unknown-none-elf/release/latbench
LATBENCH_ELF  := build/latbench.elf
# abitest - syscall ABI conformance from ring 3.
ABITEST_DIR   := userspace/tests/abitest
ABITEST_BUILT := $(ABITEST_DIR)/target/riscv64imac-unknown-none-elf/release/abitest
ABITEST_ELF   := build/abitest.elf
# ipctest - ring-3 IPC probe: fast-path round trip, server impersonation, and
# the shm/port/io_ring ownership gates.
IPCTEST_DIR   := userspace/tests/ipctest
IPCTEST_BUILT := $(IPCTEST_DIR)/target/riscv64imac-unknown-none-elf/release/ipctest
IPCTEST_ELF   := build/ipctest.elf

# ── aarch64 userspace parity (phase 6 prep) ──────────────────────────────────
#
# Same 13 programs, built for `aarch64-unknown-none` (hard-float; the level is
# Kconfig AARCH64_LEVEL, AARCH64_USER_ISA below) into `build/aarch64/` instead of `build/`, so
# they never collide with the RISC-V names `IMAGE_ELFS`/`image_hashes.py`
# bind seccomp profiles to. **No aarch64 kernel exec path exists yet** — these
# targets exist to prove the toolchain (rust-lld, page-aligned segments,
# `x8`/`svc #0` — see `crates/core/abi/src/syscall_nr.rs`'s "Register convention")
# out ahead of it, not to ship on a board.
#
# `hello`/`syscall_test`'s RISC-V originals are hand-assembled (`hello.S`,
# `test.S`); no aarch64 GNU cross-assembler is available on this host, so
# their aarch64 counterparts are small Rust crates instead (see
# `userspace/tests/hello/Cargo.toml`) — each directory's own `.cargo/config.toml`
# already defaults `[build] target` to `aarch64-unknown-none`, so no
# `--target` flag is needed for those two.
TARGET_AARCH64 := aarch64-unknown-none
comma := ,
# ── aarch64 translation granule of the user images ──────────────────────────
# config/Kconfig.arch AARCH64_PAGE_* picks the kernel's granule; a user image
# must be linked for the same page (`-z max-page-size`, which every
# user_aarch64.ld aligns its first writable section to) and libsys must agree
# (`libsys::PAGE_SIZE`, from AZOS_PAGE_SIZE). The default, 4096, builds
# exactly what this Makefile always built, into the same places. Any other
# value builds into its own directories and its own digest table, which the
# kernel of that granule binds (crates/core/sched/src/seccomp.rs):
#   make AARCH64_PAGE_SIZE=16384 build/image_hashes_aarch64_16k.rs  -> build/aarch64-16k/*.elf
#   make AARCH64_PAGE_SIZE=16384 aarch64                            -> build/kernel-aarch64-16k.img
AARCH64_PAGE_SIZE ?= 4096
# ── aarch64 baseline of the user images ─────────────────────────────────────
# The Kconfig level and `require`d extensions (config/Kconfig.arch
# AARCH64_LEVEL, A64_*) as user codegen flags, from the expanded config the
# kernel is built from (tools/kconfig_to_cargo.py --user-rustflags). Armv8.0
# with nothing required (QEMU's default) emits nothing, so the default images
# and their digests are what this Makefile always built. A board's images:
#   make AARCH64_USER_KCONFIG=build/rpi5.config userspace-aarch64
AARCH64_USER_KCONFIG ?= build/aarch64$(if $(filter 16384,$(AARCH64_PAGE_SIZE)),-16k,$(if $(filter 65536,$(AARCH64_PAGE_SIZE)),-64k)).config
AARCH64_USER_ISA := $(if $(wildcard $(AARCH64_USER_KCONFIG)),$(shell python3 tools/kconfig_to_cargo.py --user-rustflags --toml $(AARCH64_USER_KCONFIG)))
ifeq ($(AARCH64_PAGE_SIZE),4096)
AARCH64_PG_SUFFIX :=
AARCH64_PG_FLAGS  := $(if $(AARCH64_USER_ISA),--config 'target.$(TARGET_AARCH64).rustflags=[$(AARCH64_USER_ISA)]')
AARCH64_UTARGET   := target
else
ifeq ($(AARCH64_PAGE_SIZE),16384)
AARCH64_PG_SUFFIX := -16k
else ifeq ($(AARCH64_PAGE_SIZE),65536)
AARCH64_PG_SUFFIX := -64k
else
$(error AARCH64_PAGE_SIZE must be 4096, 16384 or 65536 (an aarch64 translation granule))
endif
AARCH64_UTARGET   := target$(AARCH64_PG_SUFFIX)
# Above 4 KiB the ELF/program headers share `.text`'s first page in the file
# (see user_aarch64.ld), and the loader maps an executable segment only onto a
# page it owns outright (W^X, crates/core/sched/src/process.rs). The script's
# PHDRS block keeps the headers in no segment and `.rodata` in an R segment of
# its own; `--no-rosegment`, used here before, made `.rodata` executable.
AARCH64_PG_FLAGS  := --target-dir $(AARCH64_UTARGET) --config 'target.$(TARGET_AARCH64).rustflags=["-C","link-arg=-zmax-page-size=$(AARCH64_PAGE_SIZE)"$(if $(AARCH64_USER_ISA),$(comma)$(AARCH64_USER_ISA))]'
endif
AARCH64_PG_TABLE  := $(subst -,_,$(AARCH64_PG_SUFFIX))
AARCH64_DIR    := build/aarch64$(AARCH64_PG_SUFFIX)
HELLO_ELF_AARCH64     := $(AARCH64_DIR)/hello.elf
LXHELLO_ELF_AARCH64   := $(AARCH64_DIR)/lxhello.elf
SYSTEST_ELF_AARCH64   := $(AARCH64_DIR)/syscall_test.elf
GPIO_DRV_ELF_AARCH64  := $(AARCH64_DIR)/gpio_drv.elf
MLSRV_ELF_AARCH64     := $(AARCH64_DIR)/mlsrv.elf
BUZZ_DRV_ELF_AARCH64  := $(AARCH64_DIR)/buzz_drv.elf
INA_DRV_ELF_AARCH64   := $(AARCH64_DIR)/ina_drv.elf
SH_ELF_AARCH64        := $(AARCH64_DIR)/sh.elf
TOOLBOX_ELF_AARCH64   := $(AARCH64_DIR)/toolbox.elf
POWER_ELF_AARCH64     := $(AARCH64_DIR)/power.elf
TRACECTL_ELF_AARCH64  := $(AARCH64_DIR)/tracectl.elf
FLIGHT_ELF_AARCH64    := $(AARCH64_DIR)/flight.elf
BEHAVIOR_ELF_AARCH64  := $(AARCH64_DIR)/behavior.elf
CONFIG_ELF_AARCH64    := $(AARCH64_DIR)/config.elf
OTA_ELF_AARCH64       := $(AARCH64_DIR)/ota.elf
FAM_ELFS_AARCH64      := $(FLIGHT_ELF_AARCH64) $(BEHAVIOR_ELF_AARCH64) $(CONFIG_ELF_AARCH64) $(OTA_ELF_AARCH64)
LXSRV_ELF_AARCH64     := $(AARCH64_DIR)/lxsrv.elf
UHELLO_ELF_AARCH64    := $(AARCH64_DIR)/uhello.elf
EPSRV_ELF_AARCH64     := $(AARCH64_DIR)/epsrv.elf
VSSRV_ELF_AARCH64     := $(AARCH64_DIR)/vssrv.elf
REFLEX_ELF_AARCH64    := $(AARCH64_DIR)/reflex.elf
BRAINCLI_ELF_AARCH64  := $(AARCH64_DIR)/brain_client.elf
CAPTEST_ELF_AARCH64   := $(AARCH64_DIR)/captest.elf
LATBENCH_ELF_AARCH64  := $(AARCH64_DIR)/latbench.elf
ABITEST_ELF_AARCH64   := $(AARCH64_DIR)/abitest.elf
IPCTEST_ELF_AARCH64   := $(AARCH64_DIR)/ipctest.elf
VSBENCH_ELF_AARCH64   := $(AARCH64_DIR)/vsbench.elf

# Every Rust ring-3 program links crates/core/libsys. Cargo tracks that path
# dependency, but only if make invokes cargo at all: without libsys listed as a
# prerequisite make declares the ELF up to date and the disk images ship a
# binary built against an older libsys. Observed 2026-09-03 — build/reflex.elf
# dated Aug 24 against a libsys dated Aug 31.
# lib.rs is named explicitly as well as wildcarded: a wildcard that expands to
# nothing (wrong path, moved crate) is silent, and would reopen this same hole
# somewhere new. hello and syscall_test are pure assembly and link no libsys,
# so they are deliberately not covered here.
# U12-8: iCloud sync leaves a conflicting file as "name N.ext" or "name N"
# (seen at the repo root: `.config 2` .. `.config 5`). A bare $(wildcard) or
# `find` returns that duplicate as its own whitespace-separated word, and
# `make` then treats it as a SEPARATE prerequisite — "No rule to make target
# ....../lib 2.rs" aborts every ELF rule that shares this list, not just the
# one that would have matched the duplicate. `-not -name '* [0-9]*'` drops
# any name with a space then a digit, the shape every one of these
# duplicates takes; it does nothing when no duplicate exists.
LIBSYS_DIR := crates/core/libsys
LIBSYS_SRC := $(LIBSYS_DIR)/Cargo.toml $(LIBSYS_DIR)/src/lib.rs \
              $(shell find $(LIBSYS_DIR)/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
              crates/core/abi/Cargo.toml $(shell find crates/core/abi/src -name '*.rs' -not -name '* [0-9]*') \
              crates/core/spsc/Cargo.toml $(shell find crates/core/spsc/src -name '*.rs' -not -name '* [0-9]*') \
              Cargo.toml userspace/rustc_stable_metadata.py
# (libsys takes `azos_abi` from the root workspace manifest, so the abi
# sources and that manifest are prerequisites of every ring-3 ELF as well, and
# so is the rustc wrapper below, which decides their bytes.)

# How every ring-3 Rust ELF is built: through `userspace/rustc_stable_metadata.py`,
# so its bytes depend on source and toolchain only, never on WHERE the tree is.
# Each userspace crate is its own workspace, and `crates/core/libsys` is a path
# dependency outside it; for such a package cargo hashes the absolute source path
# into `-C metadata`, rustc turns that into the crate disambiguator, and items
# are ordered by names that carry it. The same brain_client sources built in two
# directories differed in `.strtab`, and with symbols stripped in 2975 bytes of
# `.text` (measured 2026-09-14, after gate 40 refused a brain_client rebuilt in
# its snapshot directory). The kernel binds each image profile to these bytes.
# With the wrapper the two directories give identical ELFs, symbols included.
# `tests/host/seccomp-tests` checks every recipe goes through here.
#
# The `--cfg` carries a digest of the wrapper because cargo does not rebuild when
# only `RUSTC_WRAPPER` changes: switching to the wrapper recompiled nothing and
# left artifacts with the old path-derived metadata in place (measured). The
# rustflags array is part of cargo's fingerprint, so a changed wrapper rebuilds
# every userspace crate, build-std's included.
USPACE_METADATA_TAG := $(shell python3 -c 'import hashlib; print(hashlib.sha256(open("userspace/rustc_stable_metadata.py", "rb").read()).hexdigest()[:12])')
# The riscv64 user images' codegen beyond the target triple: the Kconfig
# extensions set to `require` (config/Kconfig.arch RV_ZBA/ZBB/ZBS; nothing on
# QEMU's default, so the default images and digests do not move). A board's
# images: `make RV_USER_KCONFIG=build/k1.config userspace`.
RV_USER_KCONFIG ?= build/qemu-dev.config
RV_USER_ISA := $(if $(wildcard $(RV_USER_KCONFIG)),$(shell python3 tools/kconfig_to_cargo.py --user-rustflags --toml --skip-base $(RV_USER_KCONFIG)))
USPACE_BUILD := RUSTC_WRAPPER='$(CURDIR)/userspace/rustc_stable_metadata.py' $(CARGO) +nightly build --release --config 'target.$(TARGET).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)"$(if $(RV_USER_ISA),$(comma)$(RV_USER_ISA))]'

# VisionFive 2 configuration (Phase 10)
# Override these from the command line as needed:
#   make vf2 VF2_SERIAL=/dev/tty.usbserial-XXXX
#   make flash-vf2 VF2_SD=/dev/disk4
VF2_SERIAL  ?= /dev/ttyUSB0
VF2_SD      ?= /dev/sdb       # SD card device on Linux; use diskN on macOS
VF2_BAUD    ?= 115200

# VF2 kernel ELF (built with vf2 feature + vf2 linker script)
VF2_LINKER   := kernel/linker-vf2.ld
VF2_RUSTFLAGS := -C link-arg=-T$(VF2_LINKER)
VF2_ELF      := target/$(TARGET)/release/kernel-vf2
VF2_BIN      := build/kernel-vf2.bin

# SpacemiT K1 (BananaPi BPI-F3) configuration (Phase B)
# Override from command line as needed:
#   make k1 K1_SERIAL=/dev/tty.usbserial-XXXX
#   make flash-k1 K1_SD=/dev/disk5
K1_SERIAL  ?= /dev/ttyUSB0
K1_SD      ?= /dev/sdb       # SD card device on Linux; use diskN on macOS
K1_BAUD    ?= 115200

# K1 kernel ELF (built with k1 feature + k1 linker script)
# K1 has native RVV 1.0 (VLEN=256) — k1 feature enables RVV code paths.
K1_LINKER   := kernel/linker-k1.ld
# ISA extensions the K1 has and the VF2 does not.
#
# The SpacemiT X60 is an RVA22 part (`config/defconfigs/k1.config`: rv64gcv), and RVA22
# mandates Zba, Zbb and Zbs. So the compiler may use them everywhere in a K1
# build — address arithmetic, bit counting, the scheduler's ready-bitmap pick —
# not only in hand-written `asm!`.
#
# **Only the K1.** The VF2's JH7110 is rv64gc (SiFive U74, `config/defconfigs/vf2.config`):
# it has none of these, and a binary carrying them dies with an illegal
# instruction on its first one. Both binaries are called `kernel`, so nothing but
# a check stops one reaching the wrong board — `tools/ci_check.sh` disassembles
# the VF2 and QEMU kernels and fails if any of these instructions is present.
#
# NOT the way to reach an extension that only SOME target has: that is a runtime
# probe with a scalar fallback (`crates/core/arch-riscv64/src/cbo.rs` for Zicboz). This
# is for extensions the board is known to have at build time.
#
# The flags come from the Kconfig (config/Kconfig.arch: the K1's RV_ZBA/ZBB/ZBS
# default to `require`) through tools/kconfig_to_cargo.py --rustflags, the one
# emitter every kernel rule uses; crates/core/limits/build.rs refuses a kernel
# build whose target features disagree with its Kconfig.
K1_RUSTFLAGS := -C link-arg=-T$(K1_LINKER)
K1_BIN      := build/kernel-k1.bin

# RVV: QEMU CPU model with Vector 1.0 extension (VLEN=128).
# Used by qemu-rvv and qemu-full-smp-rvv targets.
# K1 uses VLEN=256 natively (not QEMU emulated).
QEMU_RVV_CPU := rv64,v=true,vlen=128,vext_spec=v1.0

# Fleet profile (RFC-0026): gateway boards with ≥ 1 GiB RAM.
# Static tables + 256 MiB heap don't fit the default 8 MiB linker.
# linker-fleet.ld carves a 1022 MiB RAM region above OpenSBI.
FLEET_LINKER   := kernel/linker-fleet.ld
FLEET_RUSTFLAGS := -C link-arg=-T$(FLEET_LINKER)

.PHONY: check0 check1 prune all build build-rvv build-fleet clean qemu qemu-smp qemu-full-smp qemu-net-pair \
        qemu-rvv qemu-full-smp-rvv qemu-systest qemu-dhcp-smoke qemu-pi-smoke userspace userspace-aarch64 syscall-test make-mlp make-gguf \
        vf2 flash-vf2 k1 flash-k1 k1-console ci

all: build

# The SHA-256 of every ELF the disk image ships, keyed by the name it is copied
# under. `crates/core/sched/src/seccomp.rs` `include!`s it: each seccomp image
# profile is bound to the digest of those exact bytes, and the kernel refuses to
# exec an image that matches none. Every kernel build target depends on it, so
# the table follows the ELFs; `tests/host/seccomp-tests` re-hashes build/*.elf and
# fails on a stale one, and a missing one fails the kernel build.
# IMAGE_ELFS must list exactly the `mcopy -i $@ $(..) ::NAME` lines of the
# disk-image recipe below, in the same order (checked by tests/host/seccomp-tests).
IMAGE_ELFS := HELLO.ELF=$(HELLO_ELF) SYSTEST.ELF=$(SYSTEST_ELF) \
              GPIODRV.ELF=$(GPIO_DRV_ELF) MLSRV.ELF=$(MLSRV_ELF) UHELLO.ELF=$(UHELLO_ELF) \
              EPSRV.ELF=$(EPSRV_ELF) VSSRV.ELF=$(VSSRV_ELF) \
              REFLEX.ELF=$(REFLEX_ELF) BRAINCLI.ELF=$(BRAINCLI_ELF) \
              CAPTEST.ELF=$(CAPTEST_ELF) LATBENCH.ELF=$(LATBENCH_ELF) \
              ABITEST.ELF=$(ABITEST_ELF) IPCTEST.ELF=$(IPCTEST_ELF) \
              VSBENCH.ELF=$(VSBENCH_ELF) \
              BUZZDRV.ELF=$(BUZZ_DRV_ELF) INADRV.ELF=$(INA_DRV_ELF) \
              SH.ELF=$(SH_ELF) TOOLBOX.ELF=$(TOOLBOX_ELF) POWER.ELF=$(POWER_ELF) \
              FLIGHT.ELF=$(FLIGHT_ELF) BEHAVIOR.ELF=$(BEHAVIOR_ELF) \
              CONFIG.ELF=$(CONFIG_ELF) OTA.ELF=$(OTA_ELF) \
              TRACECTL.ELF=$(TRACECTL_ELF) \
              LXSRV.ELF=$(LXSRV_ELF) \
              LXHELLO.ELF=$(LXHELLO_ELF)
IMAGE_HASHES := build/image_hashes.rs

# The BOARD volume's ML service, and the image-hash table its kernel binds
# (wave 11 BOARDIMG; the key rules are with TOPOLOGY_KEY_STAMP below). Only the
# MLSRV.ELF row differs from IMAGE_ELFS: the board table lists the digest of
# the named-key service, never of the QEMU test-key one, so a board kernel
# refuses to run a QEMU-built `mlsrv`. `build/disk-board.img`'s manifest
# resolves its names through IMAGE_ELFS_BOARD, and `vf2`/`k1`/`build-fleet`
# build their kernel with `--features board-image` (azos_sched), which
# `include!`s IMAGE_HASHES_BOARD instead of IMAGE_HASHES.
BOARD_DIR := build/board
# What the signed-topology emitter reads (wave 15 TOPOSIGN; its targets are
# near the end of this file, with the rest of the topology rules).
TOPO_EMIT_DEPS := tests/host/topology-tests/src/bin/topo_emit.rs tests/host/topology-tests/Cargo.toml \
	crates/core/topology/build.rs crates/core/topology/Cargo.toml kernel/Cargo.toml \
	$(shell find crates/core/topology/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*')
MLSRV_ELF_BOARD := $(BOARD_DIR)/mlsrv.elf
IMAGE_ELFS_BOARD := $(patsubst MLSRV.ELF=%,MLSRV.ELF=$(MLSRV_ELF_BOARD),$(IMAGE_ELFS))
IMAGE_HASHES_BOARD := $(BOARD_DIR)/image_hashes.rs

$(IMAGE_HASHES_BOARD): userspace/image_hashes.py \
               $(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF_BOARD) \
               $(UHELLO_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) \
               $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) $(VSBENCH_ELF) \
               $(EPSRV_ELF) $(VSSRV_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) \
               $(SH_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(TRACECTL_ELF) $(FAM_ELFS) $(LXSRV_ELF) $(LXHELLO_ELF)
	@mkdir -p $(BOARD_DIR)
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS_BOARD)

$(IMAGE_HASHES): userspace/image_hashes.py \
               $(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF) \
               $(UHELLO_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) \
               $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) $(VSBENCH_ELF) \
               $(EPSRV_ELF) $(VSSRV_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) \
               $(SH_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(TRACECTL_ELF) $(FAM_ELFS) $(LXSRV_ELF) $(LXHELLO_ELF)
	@mkdir -p build
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing build/thirdparty_hashes.rs \
		BUSYBOX.ELF=$(BUSYBOX_ELF_RISCV64) LXTHR.ELF=$(LXTHR_ELF_RISCV64)

# ── RFC-0053 stage L0b: the module loader's test module and digest table ────
#
# LXTEST.KO is a relocatable object (ET_REL, the shape of a Linux `.ko`)
# compiled from our own C (`userspace/tests/lxmod/lxtest.c`, Apache-2.0 OR
# GPL-2.0-only, no Linux header), so the loader, `SYS_MODULE_VERIFY` and the
# token-gated `SYS_MODULE_MAP_X` run end to end with no GPL object in any
# image (stage L1, the first Linux object, needs the owner's sign-off).
# `-mno-relax`/`-mcmodel=medany` (riscv64) and `-mgeneral-regs-only`
# (aarch64) are the flags RFC-0053 6.2 scopes the loader to.
#
# The kernel binds each module to the SHA-256 of these exact bytes
# (`build/module_hashes*.rs`, `include!`d under the `lx-loader` feature only).
# The default kernel neither includes the table nor has the two syscalls.
LX_CC ?= /opt/homebrew/opt/llvm/bin/clang
LXMOD_SRC := userspace/tests/lxmod/lxtest.c
LXMOD_CFLAGS := -ffreestanding -fno-pic -fno-common -fno-builtin -nostdinc -O2 \
                -Wall -Wextra -Werror
LXTEST_KO := build/lx/lxtest-riscv64.ko
LXTEST_KO_AARCH64 := build/lx/lxtest-aarch64.ko
MODULE_HASHES := build/module_hashes.rs
MODULE_HASHES_AARCH64 := build/module_hashes_aarch64.rs

$(LXTEST_KO): $(LXMOD_SRC)
	@mkdir -p build/lx
	$(LX_CC) --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
		-mcmodel=medany -mno-relax $(LXMOD_CFLAGS) -c $< -o $@

$(LXTEST_KO_AARCH64): $(LXMOD_SRC)
	@mkdir -p build/lx
	$(LX_CC) --target=aarch64-unknown-elf -mgeneral-regs-only -mcmodel=small \
		$(LXMOD_CFLAGS) -c $< -o $@

# RFC-0053 L1: the Linux modules, built by Linux's own Kbuild against the
# pinned tree inside a pinned container (owner decision, round 49: podman on
# this Mac). `make lx-kbuild-image` builds the image (the one step that uses
# the network: the base pull and apt) and records it in
# tools/lx_kbuild/IMAGE; `make lx-kbuild` runs Kbuild for both ISAs with no
# network and the tree mounted read-only, writes $(LX_KBUILD_DIR), and runs
# the licence lint over the .ko set. Without podman, a running podman
# machine, the image or a fetched tree it prints `SKIP: <reason>` and the
# module table and the lx disks simply omit the Linux modules.
# `LX_LINUX_SRC=<tree>` builds from a tree fetched elsewhere (the iCloud
# checkout cannot hold one). `make lx-kbuild-repro` rebuilds from scratch
# into a second directory and requires identical .ko hashes.
LX_KBUILD_DIR := build/lx/kbuild
LX_LINUX_RELEASE := $(patsubst v%,%,$(shell sed -n 's/^tag=//p' lx/LINUX_PIN))
# lxsrv reads it at compile time (`option_env!`) to build the vermagic it
# admits; exported so its recipe keeps the plain `$(USPACE_BUILD)` form.
export LX_LINUX_RELEASE
LX_KO_RV := $(wildcard $(LX_KBUILD_DIR)/riscv64/lxbase.ko $(LX_KBUILD_DIR)/riscv64/xz_dec.ko)
LX_KO_A64 := $(wildcard $(LX_KBUILD_DIR)/aarch64/lxbase.ko $(LX_KBUILD_DIR)/aarch64/xz_dec.ko)
LX_XZTEST := $(wildcard $(LX_KBUILD_DIR)/XZTEST.XZ)

.PHONY: lx-kbuild-image lx-kbuild lx-kbuild-repro lx-compare
# AzOS vs Linux, same QEMU, same .ko, instruction counts (-icount): see
# tools/lx_kbuild/compare.sh. Rebuilds the kernels with bench-minimal.
lx-compare:
	@bash tools/lx_kbuild/compare.sh
lx-kbuild-image:
	tools/lx_kbuild/run.sh image

lx-kbuild:
	@rc=0; tools/lx_kbuild/run.sh build $(LX_KBUILD_DIR) || rc=$$?; \
	if [ $$rc -eq 3 ]; then exit 0; elif [ $$rc -ne 0 ]; then exit $$rc; fi; \
	python3 tools/lx_license_lint.py --ko $(LX_KBUILD_DIR)

lx-kbuild-repro:
	@rc=0; tools/lx_kbuild/run.sh build build/lx/kbuild-repro > /dev/null || rc=$$?; \
	if [ $$rc -eq 3 ]; then tools/lx_kbuild/run.sh check; exit 0; elif [ $$rc -ne 0 ]; then exit $$rc; fi; \
	diff $(LX_KBUILD_DIR)/SHA256SUMS build/lx/kbuild-repro/SHA256SUMS && \
	echo "lx-kbuild-repro: two clean builds, identical .ko and fixture hashes"

$(MODULE_HASHES): tools/module_hashes.py $(LXTEST_KO) $(LX_KO_RV)
	python3 tools/module_hashes.py $@ LXTEST.KO=$(LXTEST_KO) --skip-missing \
		LXBASE.KO=$(LX_KBUILD_DIR)/riscv64/lxbase.ko XZ_DEC.KO=$(LX_KBUILD_DIR)/riscv64/xz_dec.ko

$(MODULE_HASHES_AARCH64): tools/module_hashes.py $(LXTEST_KO_AARCH64) $(LX_KO_A64)
	python3 tools/module_hashes.py $@ LXTEST.KO=$(LXTEST_KO_AARCH64) --skip-missing \
		LXBASE.KO=$(LX_KBUILD_DIR)/aarch64/lxbase.ko XZ_DEC.KO=$(LX_KBUILD_DIR)/aarch64/xz_dec.ko

.PHONY: lx-modules
lx-modules: $(MODULE_HASHES) $(MODULE_HASHES_AARCH64)

# The application domain of the .config decides the crates (wave 11):
# `--domain-only` adds `--no-default-features` plus the rest of the kernel's
# defaults for every domain but Robot, so `make config` (Generic) + `make`
# builds the Generic kernel. A Robot .config adds nothing (`domain-robot` is
# a default feature). `-p azos_kernel`, here and in every kernel recipe
# below: without it cargo builds every workspace member, and a Generic build
# then compiled the robot crates anyway (domains/robot/*, as members), with
# none of the features the kernel would have given them.
#
# The development QEMU kernels (`build`, `build-rvv`, `build-pci` and the
# `qemu-*` smoke targets) build from `$(QEMU_DEV_KCONFIG)`: the `.config`
# with the kernel log level set to QEMU_LOG_LEVEL, debug by default, so a
# dev boot prints every line (its rule is next to the Kconfig targets). A
# product build (`vf2`, `k1`, `build-fleet`, the profiles' defconfigs) keeps
# its profile's level, warn. `make qemu QEMU_LOG_LEVEL=warn` boots what ships.
QEMU_DEV_KCONFIG := build/qemu-dev.config
QEMU_DEV_ENV      = KCONFIG_CONFIG="$(CURDIR)/$(QEMU_DEV_KCONFIG)"
#
# `QEMU_DEV_ISA`: the Kconfig's riscv64 codegen beyond .cargo/config.toml's
# baseline (RV_ZBA/ZBB/ZBS set to `require`), merged into the target's
# rustflags; empty on the default config.
QEMU_DEV_ISA = rf="$$(python3 tools/kconfig_to_cargo.py --rustflags --toml --skip-base $(QEMU_DEV_KCONFIG))"; \
	isa=""; [ -z "$$rf" ] || isa="target.$(TARGET).rustflags=[$$rf]";
build: $(IMAGE_HASHES) .config $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ISA) $(QEMU_DEV_ENV) $(CARGO) build $(CARGO_FLAGS) -p azos_kernel --features qemu \
		$${isa:+--config "$$isa"} \
		$$(python3 tools/kconfig_to_cargo.py --domain-only $(QEMU_DEV_KCONFIG))
	@$(MAKE) --no-print-directory prune

# Cargo never deletes an artifact: every feature set leaves another copy of
# every crate in deps/. `prune` drops crates this tree no longer has and build
# variants not among the newest 8 per crate AND older than 7 days
# (tools/prune_build.py; PRUNE_ARGS="--dry-run" to only report). Every build
# target runs it; the gate runs it at start.
PRUNE_ARGS ?= --quiet
prune:
	@python3 tools/prune_build.py $(PRUNE_ARGS)

# A fresh worktree's first build, from another worktree's cargo target dirs
# (tools/worktree_seed.py): APFS clones, keeping only the units that cannot
# depend on the tree's path (build-std, crates.io); every path package is
# rebuilt here. `make worktree-seed FROM=~/azos-wt/<other>`.
.PHONY: worktree-seed
worktree-seed:
	@test -n "$(FROM)" || { echo "usage: make worktree-seed FROM=<another worktree>"; exit 2; }
	@python3 tools/worktree_seed.py $(SEED_ARGS) "$(FROM)"

# Build kernel with RVV 1.0 support (requires QEMU with -cpu rv64,v=true).
build-rvv: $(IMAGE_HASHES) $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ISA) $(QEMU_DEV_ENV) $(CARGO) build $(CARGO_FLAGS) --features rvv,qemu $${isa:+--config "$$isa"}
	@$(MAKE) --no-print-directory prune

# Build kernel with PROFILE_FLEET defconfig and the fleet linker script
# (1022 MiB RAM region for the 256 MiB heap + per-task tables that
# overflow the default 8 MiB linker).  This target is the kernel side of
# the RFC-0026 fleet defconfig and runs only on gateway boards with
# >= 1 GiB RAM.  Not part of the default `build` target — opt-in.
build-fleet: $(IMAGE_HASHES_BOARD) build/disk-board-fleet.img
	$(call require_board_key,FLEET)
	$(call check_board_priv_if_given,FLEET)
	@$(MAKE) defconfig-fleet
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" \
	RUSTFLAGS="$(FLEET_RUSTFLAGS) $$(python3 tools/kconfig_to_cargo.py --rustflags .config)" \
	$(CARGO) build $(CARGO_FLAGS) -p azos_kernel --features board-image \
		$$(python3 tools/kconfig_to_cargo.py .config | tr -s ' ')
	@echo "[FLEET] kernel built, volume build/disk-board-fleet.img (signed topology) — use a gateway board with >= 1 GiB RAM"
	@$(MAKE) --no-print-directory prune

# Build the minimal hello.elf user-space test binary + GPIO ring-3 driver.
userspace: $(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF) \
           $(UHELLO_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) \
           $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) $(VSBENCH_ELF) \
           $(EPSRV_ELF) $(VSSRV_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) \
           $(SH_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(TRACECTL_ELF) $(FAM_ELFS) $(LXSRV_ELF) $(LXHELLO_ELF)

# E11.AQ3 ring-3 driver — Rust no_std ELF.  Builds via the crate's own
# .cargo/config.toml which pins target=riscv64imac-unknown-none-elf and
# the user.ld linker script.  The output is copied (not stripped) into
# build/gpio_drv.elf for the disk image to pick up.
$(GPIO_DRV_ELF): $(GPIO_DRV_DIR)/src/main.rs $(GPIO_DRV_DIR)/Cargo.toml $(GPIO_DRV_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(GPIO_DRV_DIR) && $(USPACE_BUILD)
	cp $(GPIO_DRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# The topology/config key the ring-3 ML service verifies MLP.SIG/POLICY.SIG
# with (`azos_topology::TRUSTED_PUBKEY`). `crates/core/topology/build.rs` has
# no default any more: it embeds the file TOPOLOGY_PUBKEY_PATH names, or, built
# `--features dev-key`, the TEST key (tools/keys/test_pub.bin).
#
# TWO ML services, never one (wave 11 BOARDIMG): QEMU disks and the board
# volume used to share `build/mlsrv.elf` and one image-hash table, so
# `DEV_KEYS=1` shipped a test-key service to a board and a named key left the
# QEMU disks' test-signed MLP.SIG unverifiable.
#   * `build/mlsrv.elf` (and `build/aarch64*/mlsrv.elf`) serves the QEMU disks:
#     ALWAYS `--features dev-key`, and TOPOLOGY_PUBKEY_PATH is removed from its
#     build environment (an explicit path beats the feature in build.rs, so a
#     key named for a board must not leak into it).
#   * `build/board/mlsrv.elf` serves the board volume and its kernel's hash
#     table: never `dev-key`, TOPOLOGY_PUBKEY_PATH required, and a key file
#     that holds the test key's bytes is refused (BOARD_TOPOLOGY_KEY below).
# make does not see environment changes, so each choice is written to a stamp
# the ELF depends on: switching keys rebuilds the service instead of shipping
# the previous one. A stamp is rewritten only when its choice changes, so an
# unchanged choice rebuilds nothing.
MLSRV_KEY_FEATURES := --features dev-key
# The key choice reaches build.rs through the environment, and a variable given
# on the command line is exported to every recipe: the QEMU service must not
# see TOPOLOGY_PUBKEY_PATH (an explicit path beats `dev-key` in build.rs), the
# board service must see exactly the named key. Both stay `$(USPACE_BUILD)`
# recipes (tests/host/seccomp-tests checks that).
MLSRV_QEMU_BUILD = env -u TOPOLOGY_PUBKEY_PATH $(USPACE_BUILD)
MLSRV_BOARD_BUILD = env TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" $(USPACE_BUILD)
TOPOLOGY_KEY_STAMP := build/topology_key.stamp
TOPOLOGY_KEY_CHOICE := dev-key
.PHONY: FORCE
FORCE:
$(TOPOLOGY_KEY_STAMP): FORCE
	@mkdir -p build
	@[ "$$(cat $@ 2>/dev/null)" = "$(TOPOLOGY_KEY_CHOICE)" ] || printf '%s\n' "$(TOPOLOGY_KEY_CHOICE)" > $@

# A board image names its topology/config key: `vf2`/`k1`/`build-fleet` and
# `build/disk-board.img` refuse without TOPOLOGY_PUBKEY_PATH (the fleet's
# 32-byte Ed25519 public key). There is no test-key escape hatch any more:
# `DEV_KEYS=1` is refused for a board, and so is a TOPOLOGY_PUBKEY_PATH whose
# bytes equal tools/keys/test_pub.bin.
# abspath through python: make's $(abspath) splits a path at its spaces.
BOARD_TOPOLOGY_KEY := $(if $(TOPOLOGY_PUBKEY_PATH),$(shell python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' '$(TOPOLOGY_PUBKEY_PATH)'))
define require_board_key
	@[ -n "$(BOARD_TOPOLOGY_KEY)" ] || { echo "[$(1)] refusing: no topology/config key. Set TOPOLOGY_PUBKEY_PATH to the fleet's 32-byte Ed25519 public key. A board image never carries the test key (DEV_KEYS=1 is for QEMU disks only)."; exit 1; }
	@[ -f "$(BOARD_TOPOLOGY_KEY)" ] || { echo "[$(1)] refusing: TOPOLOGY_PUBKEY_PATH=$(BOARD_TOPOLOGY_KEY) does not exist."; exit 1; }
	@python3 tools/check_board_keys.py key "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_pub.bin || { echo "[$(1)] refusing: a board image is a BUILD_TYPE_RELEASE build and BUILD_TYPE_RELEASE refuses the TEST signing key; TOPOLOGY_PUBKEY_PATH names the TEST key (tools/keys/test_pub.bin or a copy of it). Name the fleet's own public key."; exit 1; }
endef

# The board volume is SIGNED, so it also needs the private half:
# TOPOLOGY_PRIVKEY_PATH (a 32-byte Ed25519 seed). It signs CONFIG.SIG and the
# ML data files' .SIG sidecars. Refused when it is missing, is not the private
# half of TOPOLOGY_PUBKEY_PATH, or is tools/keys/test_priv.bin. The kernel
# targets (`vf2`/`k1`/`build-fleet`) embed only the public key; they check the
# pair only when a private key is given, so a build host need not hold it.
BOARD_SIGN_PRIV := $(if $(TOPOLOGY_PRIVKEY_PATH),$(shell python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' '$(TOPOLOGY_PRIVKEY_PATH)'))
define require_board_priv
	@[ -n "$(BOARD_SIGN_PRIV)" ] || { echo "[$(1)] refusing: no signing key. Set TOPOLOGY_PRIVKEY_PATH to the private half (32-byte seed) of TOPOLOGY_PUBKEY_PATH; the board volume is never signed with the test key."; exit 1; }
	@[ -f "$(BOARD_SIGN_PRIV)" ] || { echo "[$(1)] refusing: TOPOLOGY_PRIVKEY_PATH=$(BOARD_SIGN_PRIV) does not exist."; exit 1; }
	@python3 tools/check_board_keys.py pair "$(BOARD_SIGN_PRIV)" "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_priv.bin tools/keys/test_pub.bin || { echo "[$(1)] refusing: TOPOLOGY_PRIVKEY_PATH does not match TOPOLOGY_PUBKEY_PATH, or is the test key."; exit 1; }
endef
define check_board_priv_if_given
	@[ -z "$(BOARD_SIGN_PRIV)" ] || python3 tools/check_board_keys.py pair "$(BOARD_SIGN_PRIV)" "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_priv.bin tools/keys/test_pub.bin || { echo "[$(1)] refusing: TOPOLOGY_PRIVKEY_PATH does not match TOPOLOGY_PUBKEY_PATH, or is the test key."; exit 1; }
endef

# The signing key choice, as a stamp (a hash of the seed, never the seed): a
# changed or removed key re-signs the board sidecars instead of reusing them.
BOARD_PRIV_STAMP := $(BOARD_DIR)/signing_key.stamp
BOARD_PRIV_CHOICE := $(if $(TOPOLOGY_PRIVKEY_PATH),key $(TOPOLOGY_PRIVKEY_PATH) $(shell shasum -a 256 "$(TOPOLOGY_PRIVKEY_PATH)" 2>/dev/null | cut -c1-64),no-key)
$(BOARD_PRIV_STAMP): FORCE
	@mkdir -p $(BOARD_DIR)
	@[ "$$(cat $@ 2>/dev/null)" = "$(BOARD_PRIV_CHOICE)" ] || printf '%s\n' "$(BOARD_PRIV_CHOICE)" > $@

# The board's key stamp (the ELF and table variables are defined with
# IMAGE_ELFS_BOARD, next to IMAGE_HASHES, because prerequisite lists expand
# when they are read).
BOARD_KEY_STAMP := $(BOARD_DIR)/topology_key.stamp
BOARD_KEY_CHOICE := $(if $(TOPOLOGY_PUBKEY_PATH),key $(TOPOLOGY_PUBKEY_PATH) $(shell shasum -a 256 "$(TOPOLOGY_PUBKEY_PATH)" 2>/dev/null | cut -c1-64),no-key)
$(BOARD_KEY_STAMP): FORCE
	@mkdir -p $(BOARD_DIR)
	@[ "$$(cat $@ 2>/dev/null)" = "$(BOARD_KEY_CHOICE)" ] || printf '%s\n' "$(BOARD_KEY_CHOICE)" > $@

# The ML service links crates/core/ml (the MLP, RMLP loader and GGUF engine,
# without azos_arch) as well as libsys; cargo does not see through to
# make, so the ml sources are prerequisites here.
MLSRV_DEPS := $(MLSRV_DIR)/src/main.rs $(MLSRV_DIR)/Cargo.toml \
              $(shell find crates/core/ml/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
              crates/core/ml/Cargo.toml $(LIBSYS_SRC) \
              $(shell find crates/core/topology/src crates/core/limits/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
              crates/core/topology/Cargo.toml crates/core/topology/build.rs crates/core/limits/Cargo.toml \
              crates/core/limits/build.rs Kconfig $(shell find config -maxdepth 1 -name 'Kconfig.*' -not -name '* [0-9]*') $(wildcard .config) $(wildcard tools/keys/test_pub.bin)
$(MLSRV_ELF): $(MLSRV_DEPS) $(MLSRV_DIR)/user.ld $(TOPOLOGY_KEY_STAMP)
	@mkdir -p build
	cd $(MLSRV_DIR) && $(MLSRV_QEMU_BUILD) $(MLSRV_KEY_FEATURES)
	cp $(MLSRV_BUILT) $@

# The board volume's ML service: the same crate, the named key, no `dev-key`.
# Built and copied in one recipe because the crate's target dir is shared with
# the QEMU build above (cargo's fingerprint rebuilds on the env/feature change).
$(MLSRV_ELF_BOARD): $(MLSRV_DEPS) $(MLSRV_DIR)/user.ld $(BOARD_KEY_STAMP)
	$(call require_board_key,BOARD-MLSRV)
	@mkdir -p $(BOARD_DIR)
	cd $(MLSRV_DIR) && $(MLSRV_BOARD_BUILD)
	cp $(MLSRV_BUILT) $@
	python3 tools/check_board_keys.py elf "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_pub.bin $@

# The ring-3 buzzer and INA219 drivers: gpio_drv's pattern. Their chip
# logic is a crate (crates/drivers/buzzer, crates/drivers/ina219) the
# in-kernel placement compiles too, so its files are prerequisites of the
# image, and the built ELF must carry that source's marker
# (tools/chip_source_check.py, wave 12): a host that stopped linking the
# crate does not build.
CHIP_SRC_COMMON := crates/drivers/chip_source.rs tools/chip_source_check.py
INA219_CHIP_SRC := $(wildcard crates/drivers/ina219/src/*.rs) crates/drivers/ina219/Cargo.toml \
                   crates/drivers/ina219/build.rs $(CHIP_SRC_COMMON)
BUZZER_CHIP_SRC := $(wildcard crates/drivers/buzzer/src/*.rs) crates/drivers/buzzer/Cargo.toml \
                   crates/drivers/buzzer/build.rs $(CHIP_SRC_COMMON)
$(BUZZ_DRV_ELF): $(BUZZ_DRV_DIR)/src/main.rs $(BUZZER_CHIP_SRC) $(BUZZ_DRV_DIR)/Cargo.toml \
               $(BUZZ_DRV_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(BUZZ_DRV_DIR) && $(USPACE_BUILD)
	python3 tools/chip_source_check.py buzzer $(BUZZ_DRV_BUILT)
	cp $(BUZZ_DRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(INA_DRV_ELF): $(INA_DRV_DIR)/src/main.rs $(INA219_CHIP_SRC) $(INA_DRV_DIR)/Cargo.toml \
               $(INA_DRV_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(INA_DRV_DIR) && $(USPACE_BUILD)
	python3 tools/chip_source_check.py ina219 $(INA_DRV_BUILT)
	cp $(INA_DRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# RFC-0055: the user shell and its tool image.
$(SH_ELF): $(SH_SRC) $(SH_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(SH_DIR) && $(USPACE_BUILD)
	cp $(SH_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TOOLBOX_ELF): $(TOOLBOX_SRC) $(TOOLBOX_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(TOOLBOX_DIR) && $(USPACE_BUILD)
	cp $(TOOLBOX_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(POWER_ELF): $(POWER_SRC) $(POWER_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(POWER_DIR) && $(USPACE_BUILD)
	cp $(POWER_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TRACECTL_ELF): $(TRACECTL_SRC) $(TRACECTL_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(TRACECTL_DIR) && $(USPACE_BUILD)
	cp $(TRACECTL_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Wave 12: one binary of the family-tools crate per image.
$(FLIGHT_ELF): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) --bin flight
	cp $(FAMTOOLS_OUT)/flight $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BEHAVIOR_ELF): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) --bin behavior
	cp $(FAMTOOLS_OUT)/behavior $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CONFIG_ELF): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) --bin config
	cp $(FAMTOOLS_OUT)/config $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OTA_ELF): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user.ld $(LIBSYS_SRC)
	@mkdir -p build
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) --bin ota
	cp $(FAMTOOLS_OUT)/ota $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LXSRV_ELF): $(LXSRV_SRC) $(LXSRV_DIR)/user.ld $(LIBSYS_SRC) lx/LINUX_PIN
	@mkdir -p build
	cd $(LXSRV_DIR) && $(USPACE_BUILD)
	cp $(LXSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Same standalone pattern as gpio_drv: each crate carries its own
# .cargo/config.toml pinning the target, user.ld and build-std.
$(UHELLO_ELF): $(UHELLO_DIR)/src/main.rs $(UHELLO_DIR)/Cargo.toml $(UHELLO_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(UHELLO_DIR) && $(USPACE_BUILD)
	cp $(UHELLO_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(EPSRV_ELF): $(EPSRV_DIR)/src/main.rs $(EPSRV_DIR)/Cargo.toml $(EPSRV_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(EPSRV_DIR) && $(USPACE_BUILD)
	cp $(EPSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Depends on vsbench's `serve.rs` as well as its own source: the loop is
# pulled in with `#[path]` and cargo does not track that as a dependency.
$(VSSRV_ELF): $(VSSRV_DIR)/src/main.rs $(VSSRV_DIR)/Cargo.toml $(VSSRV_DIR)/user.ld \
               userspace/bench/vsbench/src/serve.rs userspace/bench/vsbench/src/ipc_proto.rs $(LIBSYS_SRC)
	@mkdir -p build
	cd $(VSSRV_DIR) && $(USPACE_BUILD)
	cp $(VSSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(REFLEX_ELF): $(REFLEX_DIR)/src/main.rs $(REFLEX_DIR)/Cargo.toml $(REFLEX_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(REFLEX_DIR) && $(USPACE_BUILD)
	cp $(REFLEX_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BRAINCLI_ELF): $(BRAINCLI_DIR)/src/main.rs $(BRAINCLI_DIR)/src/link.rs $(BRAINCLI_DIR)/Cargo.toml $(BRAINCLI_DIR)/user.ld \
               domains/robot/behavior/src/auth_envelope_core.rs crates/net/encrypt-link/src/lib.rs \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(BRAINCLI_DIR) && $(USPACE_BUILD)
	cp $(BRAINCLI_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CAPTEST_ELF): $(CAPTEST_DIR)/src/main.rs $(CAPTEST_DIR)/src/stream.rs $(CAPTEST_DIR)/Cargo.toml $(CAPTEST_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(CAPTEST_DIR) && $(USPACE_BUILD)
	cp $(CAPTEST_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Extra vsbench cargo features (wave 15: its canaries, e.g.
# `VSBENCH_FEATURES=switch-peer-canary`; tools/vsbench_compare.sh passes its
# VSBENCH_BENCH_FEATURES here). The stamp holds the set the ELFs were built
# with and changes only when the set does, so a canary ELF can never be
# reused by a later default build.
VSBENCH_FEATURES ?=
# The disk copies of VSBENCH.ELF are STRIPPED (N0, wave 15): the autorun
# loader refuses an ELF of AUTORUN_ELF_MAX (128 KiB) or more, and about 60 KiB
# of the unstripped file was `.symtab`/`.strtab`, which no loader reads. The
# loaded segments are byte-identical; the symbols stay in the cargo target.
VSBENCH_FEATURES_ARG := $(if $(strip $(VSBENCH_FEATURES)),$(comma)$(strip $(VSBENCH_FEATURES)))
build/vsbench.features: FORCE
	@mkdir -p build
	@printf '%s\n' '$(strip $(VSBENCH_FEATURES))' | cmp -s - $@ \
	    || printf '%s\n' '$(strip $(VSBENCH_FEATURES))' >$@

$(VSBENCH_ELF): $(VSBENCH_DIR)/src/main.rs $(VSBENCH_DIR)/src/bench_core.rs $(VSBENCH_DIR)/src/ipc_proto.rs \
               $(VSBENCH_DIR)/src/abi_azos.rs $(VSBENCH_DIR)/Cargo.toml $(VSBENCH_DIR)/user.ld \
               $(LIBSYS_SRC) build/vsbench.features
	@mkdir -p build
	cd $(VSBENCH_DIR) && $(USPACE_BUILD) --features azos$(VSBENCH_FEATURES_ARG)
	$(AARCH64_OBJCOPY) --strip-all $(VSBENCH_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LATBENCH_ELF): $(LATBENCH_DIR)/src/main.rs $(LATBENCH_DIR)/Cargo.toml $(LATBENCH_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(LATBENCH_DIR) && $(USPACE_BUILD)
	cp $(LATBENCH_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ABITEST_ELF): $(ABITEST_DIR)/src/main.rs $(ABITEST_DIR)/Cargo.toml $(ABITEST_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(ABITEST_DIR) && $(USPACE_BUILD)
	cp $(ABITEST_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# NOTE: cargo does NOT track .ld files. `user.ld` is listed as a prerequisite
# so make re-runs cargo, but cargo answers "Fresh" and does NOT relink. After
# touching the linker script the rebuild must be forced (touch main.rs, or
# `cargo clean -p ipctest`) and the resulting ELF's PT_LOAD headers checked
# with `riscv64-unknown-elf-readelf -l build/ipctest.elf`: no PT_LOAD may carry
# both W and X.
$(IPCTEST_ELF): $(IPCTEST_DIR)/src/main.rs $(IPCTEST_DIR)/Cargo.toml $(IPCTEST_DIR)/user.ld \
               $(LIBSYS_SRC)
	@mkdir -p build
	cd $(IPCTEST_DIR) && $(USPACE_BUILD)
	cp $(IPCTEST_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# ── RFC-0047: the Linux personality's test binary ──────────────────────────
# A static Linux ELF from userspace/tests/lxhello/lxhello.c: no C library,
# its own `_start`, Linux syscall numbers. `LX_CC` is any clang that targets
# riscv64 and aarch64 Linux (Apple's /usr/bin/clang has no riscv64 backend;
# Homebrew's llvm does); the linker is rustc's own rust-lld, with lld's
# default layout for a static executable (what an unmodified Linux binary
# has), the page size the kernel maps.
LX_CC ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang) clang)
LX_LLD = $(shell rustc --print sysroot)/lib/rustlib/$(shell rustc -vV | sed -n 's/^host: //p')/bin/rust-lld
LX_CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-pic -fno-pie \
             -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -nostdlib
# The same default layout at every aarch64 granule: lld puts the headers and
# `.rodata` in an R segment and starts the RX `.text` on the next page of
# `-z max-page-size` (same file offset, no padding), so no page is shared and
# `.rodata` is not executable. `--no-rosegment`, used above 4 KiB before,
# folded the headers and `.rodata` into the RX segment (the loader now
# refuses that, Kconfig ELF_REFUSE_EXEC_HEADERS; tools/elf_page_perms.py).

$(LXHELLO_ELF): $(LXHELLO_DIR)/lxhello.c
	@mkdir -p build
	$(LX_CC) --target=riscv64-unknown-linux-musl -march=rv64imac -mabi=lp64 -mno-relax $(LX_CFLAGS) \
		-c $< -o build/lxhello.o
	$(LX_LLD) -flavor gnu -static -e _start -z max-page-size=4096 -o $@ build/lxhello.o
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes, static Linux ELF)"

# The link flags as a prerequisite (rewritten only when they change): an
# image linked with other flags, `--no-rosegment` above all, is relinked.
LX_A64_LINK := -static -e _start -z max-page-size=$(AARCH64_PAGE_SIZE)
$(AARCH64_DIR)/lxhello.link: FORCE
	@mkdir -p $(AARCH64_DIR)
	@printf '%s\n' '$(LX_A64_LINK)' | cmp -s - $@ || printf '%s\n' '$(LX_A64_LINK)' >$@

$(LXHELLO_ELF_AARCH64): $(LXHELLO_DIR)/lxhello.c $(AARCH64_DIR)/lxhello.link
	@mkdir -p $(AARCH64_DIR)
	$(LX_CC) --target=aarch64-unknown-linux-musl -mgeneral-regs-only $(LX_CFLAGS) \
		-c $< -o $(AARCH64_DIR)/lxhello.o
	$(LX_LLD) -flavor gnu $(LX_A64_LINK) -o $@ $(AARCH64_DIR)/lxhello.o
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes, static Linux ELF)"

# ── Third-party GPL userspace: BusyBox (RFC-0055 S7, RFC-0047) ──────────────
# Built only when the .config sets CONFIG_BUSYBOX=y (which needs
# CONFIG_USERSPACE_GPL and CONFIG_LINUX_ABI); never part of the base image,
# never committed, never fetched by make. The pinned release tarball is
# provided at BUSYBOX_TARBALL (outside the repository), checked against
# BUSYBOX_SHA256 (busybox.net's published .sha256), extracted and built under
# BUSYBOX_WORK (outside the repository) with `zig cc` (musl and the Linux uapi
# headers bundled; tools/busybox_cc.sh), host tools with the system clang, from
# allnoconfig plus userspace/thirdparty/busybox.fragment, static. Both ISAs;
# riscv64 is rv64gc/lp64d (the kernel keeps a Linux task's F/D state). The
# digests go to build/thirdparty_hashes{,_aarch64}.rs (empty without a build),
# which bind BUSYBOX.ELF to its row in crates/core/sched/src/seccomp.rs.
# GPL-2.0-only: `make busybox-source-offer` writes the written offer.
BUSYBOX_VERSION  := 1.36.1
BUSYBOX_URL      := https://busybox.net/downloads/busybox-$(BUSYBOX_VERSION).tar.bz2
BUSYBOX_SHA256   := b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314
BUSYBOX_TARBALL  ?= $(HOME)/azos-tools/src/busybox-$(BUSYBOX_VERSION).tar.bz2
BUSYBOX_WORK     ?= $(HOME)/azos-tools/build/busybox-$(BUSYBOX_VERSION)
BUSYBOX_ZIG      ?= $(or $(LX_ZIG),$(firstword $(wildcard /opt/homebrew/bin/zig /usr/local/bin/zig) zig))
BUSYBOX_HOSTCC   ?= /usr/bin/clang
BUSYBOX_FRAGMENT := userspace/thirdparty/busybox.fragment
BUSYBOX_ELF_RISCV64 := $(BUSYBOX_WORK)/busybox-riscv64.elf
BUSYBOX_ELF_AARCH64 := $(BUSYBOX_WORK)/busybox-aarch64.elf
BUSYBOX_OFFER    := $(BUSYBOX_WORK)/BUSYBOX-SOURCE-OFFER.txt
BUSYBOX_CONFIG_FILE := $(or $(KCONFIG_CONFIG),.config)
THIRDPARTY_HASHES := build/thirdparty_hashes.rs
THIRDPARTY_HASHES_AARCH64 := build/thirdparty_hashes_aarch64.rs

.PHONY: busybox busybox-check busybox-source-offer thirdparty-hashes
busybox-check:
	@grep -q '^CONFIG_BUSYBOX=y' $(BUSYBOX_CONFIG_FILE) || { \
	  echo "busybox: CONFIG_BUSYBOX is not set in $(BUSYBOX_CONFIG_FILE) (needs USERSPACE_GPL and LINUX_ABI; default off)"; exit 1; }
	@command -v $(BUSYBOX_ZIG) >/dev/null 2>&1 || { \
	  echo "busybox: no zig ($(BUSYBOX_ZIG)): install zig (Homebrew: zig) or set LX_ZIG=<path>"; exit 1; }
	@[ -f $(BUSYBOX_TARBALL) ] || { \
	  echo "busybox: $(BUSYBOX_TARBALL) is missing; fetch $(BUSYBOX_URL) there (make never downloads)"; exit 1; }
	@got=$$(shasum -a 256 $(BUSYBOX_TARBALL) | cut -d' ' -f1); [ "$$got" = "$(BUSYBOX_SHA256)" ] || { \
	  echo "busybox: SHA-256 mismatch for $(BUSYBOX_TARBALL): got $$got, pinned $(BUSYBOX_SHA256) -- refused"; exit 1; }

# One ISA: busybox-one ISA=<riscv64|aarch64>.
busybox-one:
	@mkdir -p $(BUSYBOX_WORK)/$(ISA)
	rm -rf $(BUSYBOX_WORK)/$(ISA)/src && mkdir -p $(BUSYBOX_WORK)/$(ISA)/src
	tar -xjf $(BUSYBOX_TARBALL) -C $(BUSYBOX_WORK)/$(ISA)/src --strip-components=1
	$(MAKE) -s -C $(BUSYBOX_WORK)/$(ISA)/src HOSTCC=$(BUSYBOX_HOSTCC) allnoconfig >/dev/null
	@set -e; cd "$(BUSYBOX_WORK)/$(ISA)/src" && grep -v '^#' "$(CURDIR)/$(BUSYBOX_FRAGMENT)" | while IFS= read -r l; do \
	  [ -n "$$l" ] || continue; k=$${l%%=*}; \
	  sed -i '' -e "/^# $$k is not set$$/d" -e "/^$$k=/d" .config; echo "$$l" >> .config; done
	yes "" | $(MAKE) -s -C $(BUSYBOX_WORK)/$(ISA)/src HOSTCC=$(BUSYBOX_HOSTCC) oldconfig >/dev/null
	BUSYBOX_ZIG=$(BUSYBOX_ZIG) BUSYBOX_ZIG_TARGET=$(ISA)-linux-musl \
	  $(MAKE) -s -C $(BUSYBOX_WORK)/$(ISA)/src HOSTCC=$(BUSYBOX_HOSTCC) CC="$(CURDIR)/tools/busybox_cc.sh" \
	  AR="$(BUSYBOX_ZIG) ar" STRIP=$(dir $(LX_CC))llvm-strip NM=$(dir $(LX_CC))llvm-nm \
	  OBJCOPY=$(dir $(LX_CC))llvm-objcopy busybox
	cp $(BUSYBOX_WORK)/$(ISA)/src/busybox $(BUSYBOX_WORK)/busybox-$(ISA).elf
	@echo "[BUSYBOX] $(BUSYBOX_WORK)/busybox-$(ISA).elf ($$(wc -c < $(BUSYBOX_WORK)/busybox-$(ISA).elf | tr -d ' ') bytes)"

# Rebuilt only when the tarball, the fragment or the compiler wrapper changes:
# BusyBox stamps its build date into the binary, so a rebuild is a new digest
# (and every kernel built against the old table would refuse it).
$(BUSYBOX_ELF_RISCV64): $(BUSYBOX_TARBALL) $(BUSYBOX_FRAGMENT) tools/busybox_cc.sh
	$(MAKE) busybox-check
	$(MAKE) busybox-one ISA=riscv64

$(BUSYBOX_ELF_AARCH64): $(BUSYBOX_TARBALL) $(BUSYBOX_FRAGMENT) tools/busybox_cc.sh
	$(MAKE) busybox-check
	$(MAKE) busybox-one ISA=aarch64

busybox: busybox-check $(BUSYBOX_ELF_RISCV64) $(BUSYBOX_ELF_AARCH64)
	$(MAKE) busybox-source-offer thirdparty-hashes

# The third-party digest tables: BUSYBOX.ELF when it was built, empty otherwise.
# Written with every image-hash table, and again by `make busybox`.
thirdparty-hashes:
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(THIRDPARTY_HASHES) \
		BUSYBOX.ELF=$(BUSYBOX_ELF_RISCV64) LXTHR.ELF=$(LXTHR_ELF_RISCV64)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(THIRDPARTY_HASHES_AARCH64) \
		BUSYBOX.ELF=$(BUSYBOX_ELF_AARCH64) LXTHR.ELF=$(LXTHR_ELF_AARCH64)

# ── Wave 13 (THREADS): LXTHR.ELF, pthreads under the Linux personality ──────
# Our own C (userspace/tests/lxthreads/lxthreads.c, Apache-2.0 OR
# GPL-2.0-only) linked statically with musl (MIT) by `zig cc`, both ISAs.
# Built only by `make lxthreads`, which needs zig and fetches nothing; like
# BusyBox it is not part of the base image, and its digests join BusyBox's in
# build/thirdparty_hashes{,_aarch64}.rs (empty without a build), binding
# LXTHR.ELF to its row in crates/core/sched/src/seccomp.rs.
LXTHR_SRC         := userspace/tests/lxthreads/lxthreads.c
LXTHR_ELF_RISCV64 := build/lxthreads/lxthr-riscv64.elf
LXTHR_ELF_AARCH64 := build/lxthreads/lxthr-aarch64.elf
# `-z stack-size`: musl sizes every thread's stack from the main program's
# PT_GNU_STACK, which zig sets to 8 MiB; this kernel's mmap commits and charges
# each page, so the program declares musl's own default, 128 KiB.
LXTHR_CFLAGS      := -static -O2 -s -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE \
                     -Wl,-z,max-page-size=4096 -Wl,-z,stack-size=131072

.PHONY: lxthreads lxthreads-check
lxthreads-check:
	@command -v $(BUSYBOX_ZIG) >/dev/null 2>&1 || { \
	  echo "lxthreads: no zig ($(BUSYBOX_ZIG)): install zig (Homebrew: zig) or set LX_ZIG=<path>"; exit 1; }

$(LXTHR_ELF_RISCV64): $(LXTHR_SRC)
	@$(MAKE) -s lxthreads-check
	@mkdir -p $(dir $@)
	$(BUSYBOX_ZIG) cc -target riscv64-linux-musl $(LXTHR_CFLAGS) -o $@ $<
	@echo "[LXTHR] $@ ($$(wc -c < $@ | tr -d ' ') bytes, static musl)"

$(LXTHR_ELF_AARCH64): $(LXTHR_SRC)
	@$(MAKE) -s lxthreads-check
	@mkdir -p $(dir $@)
	$(BUSYBOX_ZIG) cc -target aarch64-linux-musl $(LXTHR_CFLAGS) -o $@ $<
	@echo "[LXTHR] $@ ($$(wc -c < $@ | tr -d ' ') bytes, static musl)"

lxthreads: $(LXTHR_ELF_RISCV64) $(LXTHR_ELF_AARCH64)
	$(MAKE) thirdparty-hashes

build/disk-lxthr.img: build/disk-lxabi.img $(wildcard $(LXTHR_ELF_RISCV64))
	@[ -f "$(LXTHR_ELF_RISCV64)" ] || { echo "no $(LXTHR_ELF_RISCV64): run make lxthreads"; exit 1; }
	cp build/disk-lxabi.img $@
	mcopy -i $@ "$(LXTHR_ELF_RISCV64)" ::LXTHR.ELF
	@echo "[DISK] FAT32 image: $@ (user shell, LXHELLO.ELF, LXTHR.ELF)"

build/disk-aarch64-lxthr.img: build/disk-aarch64-lxabi.img $(wildcard $(LXTHR_ELF_AARCH64))
	@[ -f "$(LXTHR_ELF_AARCH64)" ] || { echo "no $(LXTHR_ELF_AARCH64): run make lxthreads"; exit 1; }
	cp build/disk-aarch64-lxabi.img $@
	mcopy -i $@ "$(LXTHR_ELF_AARCH64)" ::LXTHR.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell, LXHELLO.ELF, LXTHR.ELF)"

busybox-source-offer:
	@mkdir -p $(BUSYBOX_WORK)
	@{ echo "BusyBox $(BUSYBOX_VERSION) -- GPL-2.0-only. Written offer of source (GPL-2.0 section 3(b))."; \
	   echo ""; \
	   echo "A AzOS volume carrying BUSYBOX.ELF contains BusyBox $(BUSYBOX_VERSION), built unmodified"; \
	   echo "from $(BUSYBOX_URL)"; \
	   echo "(SHA-256 $(BUSYBOX_SHA256)) from allnoconfig plus the lines of"; \
	   echo "$(BUSYBOX_FRAGMENT) (shipped with this offer), static, with zig cc"; \
	   echo "(target <isa>-linux-musl; musl is MIT)."; \
	   echo "For at least three years from distribution, the complete corresponding source code"; \
	   echo "(the tarball above and the build configuration) is available on request from the"; \
	   echo "distributor of the volume, for no more than the cost of physically performing the"; \
	   echo "transfer. BusyBox is not part of the AzOS kernel or base image."; } > $(BUSYBOX_OFFER)
	@echo "[BUSYBOX] wrote $(BUSYBOX_OFFER)"

# RFC-0047 stage 3: the shell volume with LXHELLO.ELF plus BUSYBOX.ELF, for
# the `linux: busybox` gate rows. The image is copied by a quoted path on
# purpose: it is not one of IMAGE_ELFS (seccomp-tests scans `$(VAR)` copies).
build/disk-busybox.img: build/disk-lxabi.img $(wildcard $(BUSYBOX_ELF_RISCV64))
	@[ -f "$(BUSYBOX_ELF_RISCV64)" ] || { echo "no $(BUSYBOX_ELF_RISCV64): run make busybox"; exit 1; }
	cp build/disk-lxabi.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_RISCV64)" ::BUSYBOX.ELF
	@echo "[DISK] FAT32 image: $@ (user shell, LXHELLO.ELF, third-party BUSYBOX.ELF)"

build/disk-aarch64-busybox.img: build/disk-aarch64-lxabi.img $(wildcard $(BUSYBOX_ELF_AARCH64))
	@[ -f "$(BUSYBOX_ELF_AARCH64)" ] || { echo "no $(BUSYBOX_ELF_AARCH64): run make busybox"; exit 1; }
	cp build/disk-aarch64-lxabi.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_AARCH64)" ::BUSYBOX.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell, LXHELLO.ELF, third-party BUSYBOX.ELF)"

$(HELLO_ELF): $(HELLO_DIR)/hello.S $(HELLO_DIR)/user.ld
	@mkdir -p build
	$(RISCV_AS) -march=rv64imac -mabi=lp64 -o build/hello.o $(HELLO_DIR)/hello.S
	$(RISCV_LD) -T $(HELLO_DIR)/user.ld -o $@ build/hello.o
	@echo "[USPACE] Built $@"

# Build the syscall test user-space binary (Phase G3).
syscall-test: $(SYSTEST_ELF)

$(SYSTEST_ELF): $(SYSTEST_DIR)/test.S $(HELLO_DIR)/user.ld
	@mkdir -p build
	$(RISCV_AS) -march=rv64imac -mabi=lp64 -o build/syscall_test.o $(SYSTEST_DIR)/test.S
	$(RISCV_LD) -T $(HELLO_DIR)/user.ld -o $@ build/syscall_test.o
	@echo "[USPACE] Built $@"

# ── aarch64 userspace parity (phase 6 prep) ──────────────────────────────────
#
# Same recipe shape as the RISC-V rules above, through the same
# $(USPACE_BUILD) (path-independent `-C metadata`, `tests/host/seccomp-tests`
# checks every recipe uses it) with an explicit `--target $(TARGET_AARCH64)`
# added — each crate's `.cargo/config.toml` keeps `[build] target` at the
# RISC-V triple, so every OTHER invocation is unaffected. hello/syscall_test
# need no `--target` flag: their own `.cargo/config.toml` (a Rust crate, not
# hello.S/test.S — see the note above `TARGET_AARCH64`) already defaults to
# aarch64-unknown-none.
#
# Phase 6 (userspace on aarch64): the exec path now exists, so these ELFs
# need the same digest binding riscv64's `IMAGE_ELFS`/`IMAGE_HASHES` give
# theirs — a separate table (`build/image_hashes_aarch64.rs`,
# `crates/core/sched/src/seccomp.rs` cfg-selects it), not a merged one; see that
# `include!` site's own comment for why. Order does not matter here the way
# it does for `IMAGE_ELFS` (nothing checks it against a disk-image recipe
# order for this table yet), but is kept matching `userspace-aarch64` below
# for readability.
IMAGE_ELFS_AARCH64 := HELLO.ELF=$(HELLO_ELF_AARCH64) SYSTEST.ELF=$(SYSTEST_ELF_AARCH64) \
              GPIODRV.ELF=$(GPIO_DRV_ELF_AARCH64) MLSRV.ELF=$(MLSRV_ELF_AARCH64) UHELLO.ELF=$(UHELLO_ELF_AARCH64) \
              EPSRV.ELF=$(EPSRV_ELF_AARCH64) VSSRV.ELF=$(VSSRV_ELF_AARCH64) \
              REFLEX.ELF=$(REFLEX_ELF_AARCH64) BRAINCLI.ELF=$(BRAINCLI_ELF_AARCH64) \
              CAPTEST.ELF=$(CAPTEST_ELF_AARCH64) LATBENCH.ELF=$(LATBENCH_ELF_AARCH64) \
              ABITEST.ELF=$(ABITEST_ELF_AARCH64) IPCTEST.ELF=$(IPCTEST_ELF_AARCH64) \
              VSBENCH.ELF=$(VSBENCH_ELF_AARCH64) \
              BUZZDRV.ELF=$(BUZZ_DRV_ELF_AARCH64) INADRV.ELF=$(INA_DRV_ELF_AARCH64) \
              SH.ELF=$(SH_ELF_AARCH64) TOOLBOX.ELF=$(TOOLBOX_ELF_AARCH64) POWER.ELF=$(POWER_ELF_AARCH64) \
              FLIGHT.ELF=$(FLIGHT_ELF_AARCH64) BEHAVIOR.ELF=$(BEHAVIOR_ELF_AARCH64) \
              CONFIG.ELF=$(CONFIG_ELF_AARCH64) OTA.ELF=$(OTA_ELF_AARCH64) \
              TRACECTL.ELF=$(TRACECTL_ELF_AARCH64) \
              LXSRV.ELF=$(LXSRV_ELF_AARCH64) \
              LXHELLO.ELF=$(LXHELLO_ELF_AARCH64)
IMAGE_HASHES_AARCH64 := build/image_hashes_aarch64$(AARCH64_PG_TABLE).rs

$(IMAGE_HASHES_AARCH64): userspace/image_hashes.py \
               $(HELLO_ELF_AARCH64) $(SYSTEST_ELF_AARCH64) $(GPIO_DRV_ELF_AARCH64) $(MLSRV_ELF_AARCH64) \
               $(UHELLO_ELF_AARCH64) $(REFLEX_ELF_AARCH64) $(BRAINCLI_ELF_AARCH64) \
               $(CAPTEST_ELF_AARCH64) $(LATBENCH_ELF_AARCH64) $(ABITEST_ELF_AARCH64) \
               $(IPCTEST_ELF_AARCH64) $(VSBENCH_ELF_AARCH64) $(EPSRV_ELF_AARCH64) \
               $(VSSRV_ELF_AARCH64) $(BUZZ_DRV_ELF_AARCH64) $(INA_DRV_ELF_AARCH64) \
               $(SH_ELF_AARCH64) $(TOOLBOX_ELF_AARCH64) $(POWER_ELF_AARCH64) $(TRACECTL_ELF_AARCH64) $(FAM_ELFS_AARCH64) $(LXSRV_ELF_AARCH64) $(LXHELLO_ELF_AARCH64)
	@mkdir -p build
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS_AARCH64)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing build/thirdparty_hashes_aarch64.rs \
		BUSYBOX.ELF=$(BUSYBOX_ELF_AARCH64) LXTHR.ELF=$(LXTHR_ELF_AARCH64)

# libsys reads the granule at compile time (`option_env!("AZOS_PAGE_SIZE")`);
# unset, it is 4096, so the default build's environment is unchanged. The
# targets are every ELF of the aarch64 hash table (`IMAGE_ELFS_AARCH64`, the
# path after each `NAME.ELF=`), not a second hand-kept list: that list missed
# SH, TOOLBOX and POWER, which then linked for the granule but ran libsys at
# 4 KiB.
IMAGE_ELF_PATHS_AARCH64 := $(foreach e,$(IMAGE_ELFS_AARCH64),$(lastword $(subst =, ,$(e))))
ifneq ($(AARCH64_PAGE_SIZE),4096)
$(IMAGE_ELF_PATHS_AARCH64): export AZOS_PAGE_SIZE := $(AARCH64_PAGE_SIZE)
endif

userspace-aarch64: $(HELLO_ELF_AARCH64) $(SYSTEST_ELF_AARCH64) $(GPIO_DRV_ELF_AARCH64) $(MLSRV_ELF_AARCH64) \
           $(UHELLO_ELF_AARCH64) $(REFLEX_ELF_AARCH64) $(BRAINCLI_ELF_AARCH64) $(CAPTEST_ELF_AARCH64) \
           $(LATBENCH_ELF_AARCH64) $(ABITEST_ELF_AARCH64) $(IPCTEST_ELF_AARCH64) $(VSBENCH_ELF_AARCH64) \
           $(EPSRV_ELF_AARCH64) $(VSSRV_ELF_AARCH64) $(BUZZ_DRV_ELF_AARCH64) $(INA_DRV_ELF_AARCH64) \
           $(SH_ELF_AARCH64) $(TOOLBOX_ELF_AARCH64) $(POWER_ELF_AARCH64) $(TRACECTL_ELF_AARCH64) $(FAM_ELFS_AARCH64) $(LXSRV_ELF_AARCH64) $(LXHELLO_ELF_AARCH64)

$(HELLO_ELF_AARCH64): $(HELLO_DIR)/src/main.rs $(HELLO_DIR)/Cargo.toml $(HELLO_DIR)/user_aarch64.ld
	@mkdir -p $(AARCH64_DIR)
	cd $(HELLO_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS)
	cp $(HELLO_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/hello_aarch64 $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SYSTEST_ELF_AARCH64): $(SYSTEST_DIR)/src/main.rs $(SYSTEST_DIR)/Cargo.toml $(SYSTEST_DIR)/user_aarch64.ld
	@mkdir -p $(AARCH64_DIR)
	cd $(SYSTEST_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS)
	cp $(SYSTEST_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/syscall_test_aarch64 $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(GPIO_DRV_ELF_AARCH64): $(GPIO_DRV_DIR)/src/main.rs $(GPIO_DRV_DIR)/Cargo.toml $(GPIO_DRV_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(GPIO_DRV_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(GPIO_DRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/gpio_drv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Hard-float: `aarch64-unknown-none` (the kernel alone is soft-float).
$(MLSRV_ELF_AARCH64): $(MLSRV_DEPS) $(MLSRV_DIR)/user_aarch64.ld $(TOPOLOGY_KEY_STAMP)
	@mkdir -p $(AARCH64_DIR)
	cd $(MLSRV_DIR) && $(MLSRV_QEMU_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64) $(MLSRV_KEY_FEATURES)
	cp $(MLSRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/mlsrv $@

$(BUZZ_DRV_ELF_AARCH64): $(BUZZ_DRV_DIR)/src/main.rs $(BUZZER_CHIP_SRC) $(BUZZ_DRV_DIR)/Cargo.toml $(BUZZ_DRV_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(BUZZ_DRV_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	python3 tools/chip_source_check.py buzzer $(BUZZ_DRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/buzz_drv
	cp $(BUZZ_DRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/buzz_drv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(INA_DRV_ELF_AARCH64): $(INA_DRV_DIR)/src/main.rs $(INA219_CHIP_SRC) $(INA_DRV_DIR)/Cargo.toml \
               $(INA_DRV_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(INA_DRV_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	python3 tools/chip_source_check.py ina219 $(INA_DRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/ina_drv
	cp $(INA_DRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/ina_drv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SH_ELF_AARCH64): $(SH_SRC) $(SH_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(SH_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(SH_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/sh $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TOOLBOX_ELF_AARCH64): $(TOOLBOX_SRC) $(TOOLBOX_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(TOOLBOX_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(TOOLBOX_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/toolbox $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(POWER_ELF_AARCH64): $(POWER_SRC) $(POWER_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(POWER_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(POWER_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/power $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TRACECTL_ELF_AARCH64): $(TRACECTL_SRC) $(TRACECTL_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(TRACECTL_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(TRACECTL_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/tracectl $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(FLIGHT_ELF_AARCH64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64) --bin flight
	cp $(FAMTOOLS_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/flight $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BEHAVIOR_ELF_AARCH64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64) --bin behavior
	cp $(FAMTOOLS_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/behavior $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CONFIG_ELF_AARCH64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64) --bin config
	cp $(FAMTOOLS_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/config $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OTA_ELF_AARCH64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_aarch64.ld $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64) --bin ota
	cp $(FAMTOOLS_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/ota $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LXSRV_ELF_AARCH64): $(LXSRV_SRC) $(LXSRV_DIR)/user_aarch64.ld $(LIBSYS_SRC) lx/LINUX_PIN
	@mkdir -p $(AARCH64_DIR)
	cd $(LXSRV_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(LXSRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/lxsrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(UHELLO_ELF_AARCH64): $(UHELLO_DIR)/src/main.rs $(UHELLO_DIR)/Cargo.toml $(UHELLO_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(UHELLO_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(UHELLO_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/uhello $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(EPSRV_ELF_AARCH64): $(EPSRV_DIR)/src/main.rs $(EPSRV_DIR)/Cargo.toml $(EPSRV_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(EPSRV_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(EPSRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/epsrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VSSRV_ELF_AARCH64): $(VSSRV_DIR)/src/main.rs $(VSSRV_DIR)/Cargo.toml $(VSSRV_DIR)/user_aarch64.ld \
               userspace/bench/vsbench/src/serve.rs userspace/bench/vsbench/src/ipc_proto.rs $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(VSSRV_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(VSSRV_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/vssrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(REFLEX_ELF_AARCH64): $(REFLEX_DIR)/src/main.rs $(REFLEX_DIR)/Cargo.toml $(REFLEX_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(REFLEX_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(REFLEX_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/reflex $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BRAINCLI_ELF_AARCH64): $(BRAINCLI_DIR)/src/main.rs $(BRAINCLI_DIR)/src/link.rs $(BRAINCLI_DIR)/Cargo.toml $(BRAINCLI_DIR)/user_aarch64.ld \
               domains/robot/behavior/src/auth_envelope_core.rs crates/net/encrypt-link/src/lib.rs \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(BRAINCLI_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(BRAINCLI_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/brain_client $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CAPTEST_ELF_AARCH64): $(CAPTEST_DIR)/src/main.rs $(CAPTEST_DIR)/src/stream.rs $(CAPTEST_DIR)/Cargo.toml $(CAPTEST_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(CAPTEST_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(CAPTEST_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/captest $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VSBENCH_ELF_AARCH64): $(VSBENCH_DIR)/src/main.rs $(VSBENCH_DIR)/src/bench_core.rs $(VSBENCH_DIR)/src/ipc_proto.rs \
               $(VSBENCH_DIR)/src/abi_azos.rs $(VSBENCH_DIR)/Cargo.toml $(VSBENCH_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC) build/vsbench.features
	@mkdir -p $(AARCH64_DIR)
	cd $(VSBENCH_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64) --features azos$(VSBENCH_FEATURES_ARG)
	$(AARCH64_OBJCOPY) --strip-all $(VSBENCH_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/vsbench $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LATBENCH_ELF_AARCH64): $(LATBENCH_DIR)/src/main.rs $(LATBENCH_DIR)/Cargo.toml $(LATBENCH_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(LATBENCH_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(LATBENCH_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/latbench $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ABITEST_ELF_AARCH64): $(ABITEST_DIR)/src/main.rs $(ABITEST_DIR)/Cargo.toml $(ABITEST_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(ABITEST_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(ABITEST_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/abitest $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(IPCTEST_ELF_AARCH64): $(IPCTEST_DIR)/src/main.rs $(IPCTEST_DIR)/Cargo.toml $(IPCTEST_DIR)/user_aarch64.ld \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(IPCTEST_DIR) && $(USPACE_BUILD) $(AARCH64_PG_FLAGS) --target $(TARGET_AARCH64)
	cp $(IPCTEST_DIR)/$(AARCH64_UTARGET)/$(TARGET_AARCH64)/release/ipctest $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

make-gguf build/policy.gguf: tools/make_gguf.py
	@mkdir -p build
	python3 tools/make_gguf.py

clean:
	$(CARGO) clean
	rm -f build/hello.o $(HELLO_ELF) build/syscall_test.o $(SYSTEST_ELF) \
		build/mlp.rmlp build/policy.gguf build/disk.img

# Single CPU
qemu: build
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF)

# RFC-0046 stage 1 — gate 4: native PCI enumeration on QEMU `virt`.
# `disable-legacy=on` on every virtio-*-pci device matters: without it QEMU's
# device is "transitional" and lets a driver that never negotiates
# VIRTIO_F_VERSION_1 limp along on the legacy path, which would hide the same
# bug class U05-12 was about. `nvme` is for enumeration only — no NVMe driver
# exists yet (native-first rule, owner decision 2026-09-26); it just gives
# the enumeration line something non-virtio to print.
#
# NOT included here: `-machine virt,aia=aplic-imsic`. Tried it this session —
# it FAULTS at PLIC init (`[EXCEPTION] Store/AMO access fault`, `stval:
# 0xc00000X`, i.e. right at the PLIC's own base): enabling AIA replaces the
# PLIC the kernel's IRQ init still targets, and there is no APLIC/IMSIC driver
# in this tree yet (stage 1a, not done — `grep -rn "imsic\|aplic" crates/
# kernel/` is empty). Add it back to QEMU_PCI_ARGS once that driver lands;
# until then it turns "boots and enumerates" into "does not boot" for no
# purpose (MSI-X isn't delivered either way without that driver).
QEMU_PCI_ARGS := -device virtio-blk-pci,disable-legacy=on,drive=pciblk0 \
                 -drive file=build/pci-blk0.img,if=none,format=raw,id=pciblk0 \
                 -device virtio-net-pci,disable-legacy=on,netdev=pcinet0 \
                 -netdev user,id=pcinet0 \
                 -device nvme,serial=deadbeef,drive=pcinvme0 \
                 -drive file=build/pci-nvme0.img,if=none,format=raw,id=pcinvme0

build/pci-blk0.img build/pci-nvme0.img:
	@mkdir -p build
	dd if=/dev/zero of=$@ bs=1M count=8 2>/dev/null

# NOTE: depends on `build-pci`, not plain `build` — the latter's
# `--features qemu` alone does not compile in `crates/drivers/pci`/`virtio/pci.rs`
# at all (they're behind the `pci` feature), so a kernel built via `build`
# would boot but never print a `[PCI]` line.
build-pci: $(IMAGE_HASHES) .config $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ENV) $(CARGO) build $(CARGO_FLAGS) --features qemu,pci

qemu-pci: build-pci build/pci-blk0.img build/pci-nvme0.img
	$(QEMU) $(QEMU_FLAGS) $(QEMU_PCI_ARGS) -kernel $(KERNEL_ELF)

# aarch64 counterpart. `iommu=smmuv3` IS safe to enable here (unlike riscv64's
# `aia`): SMMUv3 defaults to bypass for any stream with no table entry, so a
# kernel with no SMMUv3 driver still boots identically — the flag only
# matters once stage 1b's IOMMU driver programs a stream table entry. ECAM
# base for this machine: 0x40_1000_0000 (verified via `-machine
# virt,dumpdtb=`, NOT the RFC's unchecked `0x3f00_0000`).
#
# Boots the flat Image, not the ELF: QEMU hands a DTB pointer in x0 only to an
# Image, and the kernel reads the host bridge (ECAM, mem32 window) from it
# (`[PCI] host bridge: ... (dtb)`). The ELF boots with x0 = 0 and falls back to
# the built-in constants. Build the kernel with `--features qemu,pci` first.
AARCH64_PCI_IMG := build/kernel-aarch64-pci.img
qemu-pci-aarch64: build/pci-blk0.img build/pci-nvme0.img
	@test -f $(AARCH64_ELF) || { echo "build the aarch64 kernel with --features qemu,pci first: $(AARCH64_ELF)"; exit 1; }
	@mkdir -p build
	"$(AARCH64_OBJCOPY)" -O binary $(AARCH64_ELF) $(AARCH64_PCI_IMG)
	qemu-system-aarch64 -M virt,gic-version=3,iommu=smmuv3 -cpu max,pauth=on -nographic \
		$(QEMU_PCI_ARGS) -kernel $(AARCH64_PCI_IMG)

# 4 CPUs (SMP testing)
qemu-smp: build
	$(QEMU) $(QEMU_FLAGS) -smp 4 -kernel $(KERNEL_ELF)

# Full: SMP + disk + network
qemu-full-smp: build userspace build/disk.img
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-smp 4 \
		-global virtio-mmio.force-legacy=false \
		-drive file=build/disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::8080-:8080 \
		-device virtio-net-device,netdev=net0

# Boot with a disk whose CONFIG.INI autoruns SYSTEST.ELF instead of the GPIO
# driver, so the syscall test actually executes. It exercises the ring-3 path
# end to end: ELF load from FAT32, exec, getpid/write/brk/exit via ecall.
# Prints `[SYSCALL_TEST] ALL PASSED!` or `FAILED!`.
qemu-systest: build userspace build/disk-systest.img
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-smp 4 \
		-global virtio-mmio.force-legacy=false \
		-drive file=build/disk-systest.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0

# DHCP against QEMU's built-in user-mode server. Asserts we reach Bound and
# end up with an address from the 10.0.2.x pool, not just that the call
# returned. Prints `[DHCPSMOKE] PASS ...` or `FAIL <reason>`.
qemu-dhcp-smoke: $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ENV) $(CARGO) build --release --features qemu,dhcp-smoke
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

# K-A14 — PiMutex donation on a single hart: a low-priority holder and a
# higher-priority waiter pinned to the same CPU. The old spinning mutex
# deadlocked here; the waiter never released the hart, so the owner it had
# just boosted could not run. Prints `[PISMOKE] PASS ...` or `FAIL <reason>`.
qemu-pi-smoke: $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ENV) $(CARGO) build --release --features qemu,pi-smoke
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF)

# RVV: single CPU with Vector extension
qemu-rvv: build-rvv
	$(QEMU) $(QEMU_FLAGS) -cpu $(QEMU_RVV_CPU) -kernel $(KERNEL_ELF)

# RVV: 4 CPUs + disk + network + Vector extension
qemu-full-smp-rvv: build-rvv userspace build/disk.img
	$(QEMU) $(QEMU_FLAGS) -cpu $(QEMU_RVV_CPU) \
		-smp 4 \
		-global virtio-mmio.force-legacy=false \
		-drive file=build/disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::8080-:8080 \
		-device virtio-net-device,netdev=net0 \
		-kernel $(KERNEL_ELF)

# GDB debug
qemu-gdb: build
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) -s -S

# Generate MLP weight file from the Python script (Phase 15).
# Writes tools/make_mlp.py output to build/mlp.rmlp (292 bytes).
make-mlp build/mlp.rmlp: tools/make_mlp.py
	@mkdir -p build
	python3 tools/make_mlp.py
	@echo "[ML] Weight file: build/mlp.rmlp ($$(wc -c < build/mlp.rmlp | tr -d ' ') bytes)"

# Two disk images from one recipe, differing only in which ELF `autorun` starts.
# disk.img keeps GPIODRV (the ring-3 driver demo); disk-systest.img runs the
# syscall test, which was built and copied onto the disk for months without
# anything ever invoking it.
build/disk.img:         AUTORUN_ELF := /fat/GPIODRV.ELF
build/disk-systest.img: AUTORUN_ELF := /fat/SYSTEST.ELF
build/disk-uhello.img:  AUTORUN_ELF := /fat/UHELLO.ELF
build/disk-reflex.img:  AUTORUN_ELF := /fat/REFLEX.ELF
build/disk-braincli.img: AUTORUN_ELF := /fat/BRAINCLI.ELF
# Wave 9 (P3): brain_client runs the RFC-0019 encrypted link, and so does the
# kernel's own brain link by default — both dial 10.0.2.2:9000, and SLIRP hides
# which is which. With both encrypted, the host peer would hand its script,
# e-stop included, to the kernel's link as well, and the ring-3 rows' ordering
# assertions would race it. `link_encrypt=0` keeps the KERNEL's link HMAC-only
# on this test image; `tools/fake_brain.py --encrypt` recognises that
# connection by its reply to HELLO and only drains it. brain_client ignores
# `link_encrypt` (see `userspace/services/brain_client/src/link.rs`).
# `brain_client_rekey_secs=10` shortens brain_client's wall-clock rekey so one
# 40 s boot sees a client REKEY; the key can only shorten the interval.
build/disk-braincli.img: CFG_EXTRA := link_encrypt=0\nbrain_client_rekey_secs=10\n
build/disk-captest.img: AUTORUN_ELF := /fat/CAPTEST.ELF
build/disk-latbench.img: AUTORUN_ELF := /fat/LATBENCH.ELF
build/disk-abitest.img: AUTORUN_ELF := /fat/ABITEST.ELF
# The envelope scenario runs no ring-3 program: it exercises the kernel's own
# actuation chokepoint and then reads the flight-recorder file back. An autorun
# here would just compete with the RT control loop for CPU.
build/disk-envelope.img: AUTORUN_ELF :=
build/disk-ipctest.img: AUTORUN_ELF := /fat/IPCTEST.ELF
build/disk-vsbench.img: AUTORUN_ELF := /fat/VSBENCH.ELF
# Wave 12: vsbench's `spawn+wait` lane starts TOOLBOX.ELF (as `true`), so the
# bench volume carries it; no other image of this recipe does.
build/disk-vsbench.img: DISK_EXTRA := $(TOOLBOX_ELF)=TOOLBOX.ELF
build/disk-vsbench.img: $(TOOLBOX_ELF)
# gpio_drv was built into every image since E11.AQ3 and made the autorun of
# none of them, so the ring-3 driver path had no scenario at all.
build/disk-gpiodrv.img: AUTORUN_ELF := /fat/GPIODRV.ELF

# The "brain lies" scenario. Same autorun as disk.img ON PURPOSE: GPIODRV is
# what exposed the net-poll starvation (a ring-3 program created inside the
# real-time band never yielded hart 3 to the poller, so the RX ring was never
# drained and the robot could not complete a single TCP handshake). Keeping it
# here makes this scenario the regression test for that, on top of what it was
# written for.
#
# What it does change is `link_encrypt`: the default is ON, and with no
# LINK.KEY on the image the kernel connects and immediately closes
# ("no plaintext fallback", RFC-0019). That is the correct behaviour and the
# gate proves it in `link auth rejects missing key`; here it would just stop
# the frames from ever reaching the dispatch this scenario exists to test.
build/disk-brainlies.img: AUTORUN_ELF := /fat/GPIODRV.ELF
build/disk-brainlies.img: CFG_EXTRA := link_encrypt=0\n

# Same recipe again for the RECORD half of that scenario, which boots a kernel
# built with `brain-lies-smoke` and reads SAFETY_UNKNOWN_PKT back off the log.
# Its own image rather than a reuse: the probe scans LOG00000.BIN, so a
# previous run's records on a shared image would let it pass without this boot
# writing anything.
build/disk-brainrec.img: AUTORUN_ELF := /fat/GPIODRV.ELF
build/disk-brainrec.img: CFG_EXTRA := link_encrypt=0\n

# And again for the TCP e-stop, which needs the kernel's OWN brain link up:
# `PKT_ESTOP` over TCP is handled in `behavior_task`, not by any ring-3
# program, so `link_encrypt=0` is not a convenience here — without it the link
# closes on the handshake and the frame never reaches the branch under test.
# Its own image name because the Makefile needs an explicit rule per name; a
# missing one yields no image and a silent boot that reads as a kernel fault.
build/disk-brainestop.img: AUTORUN_ELF := /fat/GPIODRV.ELF
build/disk-brainestop.img: CFG_EXTRA := link_encrypt=0\n

# The PHYSICAL kill switch. Same shape as the image above — the wheels have to
# be turning before the switch is pressed, and the brain link is what turns
# them. `estop_gpio_pin` is deliberately NOT set here: the pin has to be driven
# high before the poll can see it, which a config line cannot promise. See
# `estop_gpio_smoke_task`.
build/disk-estopgpio.img: AUTORUN_ELF := /fat/GPIODRV.ELF
build/disk-estopgpio.img: CFG_EXTRA := link_encrypt=0\n

# Wave 9 (DRV1): the base of the ring-3 drivers disk (`build/disk-drv.img`,
# after this recipe). No autorun: the drivers are the only ring-3 tasks.
build/disk-drvbase.img: AUTORUN_ELF :=
# RFC-0053 L1, the Linux comparison (`make lx-compare`): LXSRV.ELF as the
# autorun, because a `bench-minimal` kernel parks the topology launcher with
# every other boot task, so the server runs alone, as /init does on Linux.
build/disk-lxbench-base.img: AUTORUN_ELF := /fat/LXSRV.ELF

# The optional third argument is the signing key (default: the TEST key; the
# board volume passes BOARD_SIGN_PRIV).
# CONFIG.SIG v2 (wave 11, RFC-0054 finding 7): a signed CONFIG.INI names ONE
# device and a counter. Each image gets a fresh random device id in its
# reserved tail (`tools/device_provision.py`, sector 2, floor 0) and its
# CONFIG.INI is signed for that id at counter 1. Usage, in a recipe whose image
# is already formatted: $(call provision_and_sign_config,<ini>,<sig-out>)
CONFIG_SIG_TOOLS := tools/gen_config_sig.py tools/device_provision.py
provision_and_sign_config = python3 tools/device_provision.py $@ >/dev/null && \
	python3 tools/gen_config_sig.py $(1) --config-v2 --counter 1 --image $@ --priv $(or $(3),$(TEST_PRIV_KEY)) --out $(2)

# Temporaries live next to their target (`$@.tmp_*`), not in fixed /tmp paths:
# two disk builds at once (parallel fronts in separate worktrees, or `make -j`)
# used to share /tmp/_robtos_config.ini and ship each other's CONFIG.INI.
build/disk.img build/disk-systest.img build/disk-uhello.img \
build/disk-reflex.img build/disk-braincli.img build/disk-captest.img \
build/disk-latbench.img build/disk-abitest.img build/disk-ipctest.img build/disk-vsbench.img \
build/disk-envelope.img build/disk-gpiodrv.img build/disk-brainlies.img \
		build/disk-brainrec.img build/disk-brainestop.img \
		build/disk-estopgpio.img build/disk-drvbase.img build/disk-lxbench-base.img: \
		$(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF) $(UHELLO_ELF) \
		$(EPSRV_ELF) $(VSSRV_ELF) \
		$(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) $(LATBENCH_ELF) $(ABITEST_ELF) \
		$(VSBENCH_ELF) \
		$(IPCTEST_ELF) \
		build/mlp.rmlp build/policy.gguf build/mlp.sig build/policy.sig \
		$(TEST_PRIV_KEY) $(CONFIG_SIG_TOOLS)
	@mkdir -p build
	dd if=/dev/zero of=$@ bs=1M count=32
	# U06-9/#30 (2026-09-26): extend the raw image by
	# MSC_RESERVED_TAIL_SECTORS (8 sectors = 4 KiB) and format ONLY the
	# first 32768 1-KiB blocks (32 MiB) as FAT32, leaving the tail
	# reserved -- see `kernel/src/msc_gadget.rs::MSC_RESERVED_TAIL_SECTORS`.
	# Without this the reserved region LINK.KEY/the entropy seed file live
	# in does not exist on this image (`reserved_region_read`/`write` then
	# fail closed -- safe, but the key/seed never load). 65536 sectors x
	# 512 B = 32 MiB = 32768 KiB, the mkfs.fat BLOCKS unit.
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "Hello from AzOS FAT32!\n" > $@.tmp_hello.txt
	@printf "AzOS Phase 18 — Persistent configuration + dynamic model loading\n" > $@.tmp_readme.txt
	@printf "# AzOS Configuration\nml_enabled=1\nlog_level=1\nmotor_max_speed=100\nwatchdog_ms=500\nnet_ip=10.0.2.15\nnet_gateway=10.0.2.2\nnet_mask=255.255.255.0\nbehavior_server_ip=10.0.2.2\nbehavior_server_port=9000\nbehavior_l1_enabled=1\nbehavior_l2_enabled=1\nbehavior_l3_enabled=1\nautorun=$(AUTORUN_ELF)\n" \
		> $@.tmp_config.ini
	@printf "$(CFG_EXTRA)" >> $@.tmp_config.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" \
		> $@.tmp_bootmeta
	# W2-B5 (U10-2): every image from this recipe ships CONFIG.SIG, signed with
	# the same dev/test key `crates/core/topology::TRUSTED_PUBKEY` embeds; without it
	# the kernel takes cfg_load_verified's fail-closed branch (autorun refused).
	# Wave 11: CONFIG.SIG v2 is bound to the device id in the image's reserved
	# tail (a fresh random one per image) and to counter 1.
	$(call provision_and_sign_config,$@.tmp_config.ini,$@.tmp_config.sig)
	mcopy -i $@ $@.tmp_hello.txt ::HELLO.TXT
	mcopy -i $@ $@.tmp_readme.txt ::README.TXT
	mcopy -i $@ $(HELLO_ELF) ::HELLO.ELF
	mcopy -i $@ $(SYSTEST_ELF) ::SYSTEST.ELF
	mcopy -i $@ $(GPIO_DRV_ELF) ::GPIODRV.ELF
	mcopy -i $@ $(MLSRV_ELF) ::MLSRV.ELF
	mcopy -i $@ $(UHELLO_ELF) ::UHELLO.ELF
	mcopy -i $@ $(EPSRV_ELF) ::EPSRV.ELF
	mcopy -i $@ $(VSSRV_ELF) ::VSSRV.ELF
	mcopy -i $@ $(REFLEX_ELF) ::REFLEX.ELF
	mcopy -i $@ $(BRAINCLI_ELF) ::BRAINCLI.ELF
	mcopy -i $@ $(CAPTEST_ELF) ::CAPTEST.ELF
	mcopy -i $@ $(LATBENCH_ELF) ::LATBENCH.ELF
	mcopy -i $@ $(ABITEST_ELF) ::ABITEST.ELF
	mcopy -i $@ $(IPCTEST_ELF) ::IPCTEST.ELF
	mcopy -i $@ $(VSBENCH_ELF) ::VSBENCH.ELF
	$(foreach f,$(DISK_EXTRA),mcopy -i $@ $(word 1,$(subst =, ,$(f))) ::$(word 2,$(subst =, ,$(f)));)
	# 8.3 name, as the FAT32 driver matches no other: `azos_abi::ml_srv::WEIGHTS_PATH`.
	mcopy -i $@ build/mlp.rmlp ::MLP.RML
	mcopy -i $@ build/policy.gguf ::POLICY.GGF
	mcopy -i $@ build/mlp.sig ::MLP.SIG
	mcopy -i $@ build/policy.sig ::POLICY.SIG
	mcopy -i $@ $@.tmp_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta ::BOOTMETA
	@rm -f $@.tmp_hello.txt $@.tmp_readme.txt $@.tmp_config.ini $@.tmp_config.sig $@.tmp_bootmeta
	@echo "[DISK] FAT32 image: $@ (autorun=$(AUTORUN_ELF))"

# Wave 9 (DRV1): the ring-3 drivers disk — the base above plus the two driver
# images, the only riscv64 gate image that carries them. A `qemu` kernel
# starts every topology row with `start = true` whose image is on the volume,
# so this is the one gate disk that starts BUZZDRV.ELF and INADRV.ELF; no
# other scenario gains two tasks or two root directory entries.
build/disk-drv.img: build/disk-drvbase.img $(BUZZ_DRV_ELF) $(INA_DRV_ELF)
	cp build/disk-drvbase.img $@
	mcopy -i $@ $(BUZZ_DRV_ELF) ::BUZZDRV.ELF
	mcopy -i $@ $(INA_DRV_ELF) ::INADRV.ELF
	@echo "[DISK] FAT32 image: $@ (ring-3 drivers BUZZDRV.ELF, INADRV.ELF)"

# RFC-0055 (wave 11): the user-shell disk — the drivers base (no autorun) plus
# SH.ELF, TOOLBOX.ELF and POWER.ELF. The only gate image that carries them: on every
# other volume `/fat/SH.ELF` is absent, so the kernel console is the recovery
# console at once, as before, and no scenario gains a task.
build/disk-sh.img: build/disk-drvbase.img $(SH_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(FAM_ELFS) $(TRACECTL_ELF)
	cp build/disk-drvbase.img $@
	mcopy -i $@ $(SH_ELF) ::SH.ELF
	mcopy -i $@ $(TOOLBOX_ELF) ::TOOLBOX.ELF
	mcopy -i $@ $(POWER_ELF) ::POWER.ELF
	mcopy -i $@ $(FLIGHT_ELF) ::FLIGHT.ELF
	mcopy -i $@ $(BEHAVIOR_ELF) ::BEHAVIOR.ELF
	mcopy -i $@ $(CONFIG_ELF) ::CONFIG.ELF
	mcopy -i $@ $(OTA_ELF) ::OTA.ELF
	mcopy -i $@ $(TRACECTL_ELF) ::TRACECTL.ELF
	@echo "[DISK] FAT32 image: $@ (user shell SH.ELF, TOOLBOX.ELF, POWER.ELF, FLIGHT/BEHAVIOR/CONFIG/OTA.ELF, TRACECTL.ELF)"

# RFC-0053 L0b: the Linux-server disk -- the drivers base (no autorun) plus
# LXSRV.ELF and its test module. The only gate image that carries them; a
# kernel built with `lx-server` starts LXSRV.ELF from its topology row
# (`start = true`), and every other volume lacks the image, so no other
# scenario gains a task. The module is copied under its 8.3 name, which is
# also its key in `build/module_hashes.rs`. RFC-0053 L1: when `make
# lx-kbuild` has built them, the Kbuild modules LXBASE.KO and XZ_DEC.KO and
# the fixture XZTEST.XZ go on too (the only volumes that ever carry a
# Linux-compiled object).
build/disk-lx.img: build/disk-drvbase.img $(LXSRV_ELF) $(LXTEST_KO) $(LX_KO_RV) $(LX_XZTEST)
	cp build/disk-drvbase.img $@
	mcopy -i $@ $(LXSRV_ELF) ::LXSRV.ELF
	mcopy -i $@ build/lx/lxtest-riscv64.ko ::LXTEST.KO
	@if [ -f $(LX_KBUILD_DIR)/riscv64/xz_dec.ko ]; then \
		mcopy -i $@ $(LX_KBUILD_DIR)/riscv64/lxbase.ko ::LXBASE.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/riscv64/xz_dec.ko ::XZ_DEC.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/XZTEST.XZ ::XZTEST.XZ && \
		echo "[DISK] $@: + Kbuild modules LXBASE.KO, XZ_DEC.KO, fixture XZTEST.XZ"; fi
	@echo "[DISK] FAT32 image: $@ (Linux server skeleton LXSRV.ELF, test module LXTEST.KO)"

# RFC-0047 (wave 12): the user-shell disk plus LXHELLO.ELF, the static Linux
# test binary the `linux:` gate rows start from the shell. Only a kernel
# built with `linux-abi-test` has a row for it.
build/disk-lxabi.img: build/disk-sh.img $(LXHELLO_ELF)
	cp build/disk-sh.img $@
	mcopy -i $@ $(LXHELLO_ELF) ::LXHELLO.ELF
	@echo "[DISK] FAT32 image: $@ (user shell + static Linux LXHELLO.ELF)"

# ── Board volume: ELFs the TOPOLOGY declares (RFC-0005) ─────────────────────
# Owner decision 2026-09-24: the set of ELFs above (IMAGE_ELFS) predates the
# generic-hybrid pivot and is a hand-maintained, robot-shaped list — every
# disk-*.img target above ships all thirteen regardless of what it tests.
# The rule now: an ELF ships on a BOARD's FAT32 volume iff the topology
# declares a service that ELF provides. Nothing above this comment changes —
# every disk-*.img target keeps shipping the full IMAGE_ELFS set, unchanged,
# because those are gate scenarios (`tools/ci_check.sh`), not deployments.
# `build/disk-board.img` below is the actual board artifact: no existing
# target here plays that role today (`vf2`/`k1`/`flash-vf2`/`flash-k1`,
# further down, build and flash `kernel.bin` only — no FAT32 data volume at
# all), so this is additive, not a rewrite of something already shipping.
#
# The single source of truth is `crates/core/topology/src/builder.rs`'s board
# service registry (the `TASK_GPIODRV_IMAGE` block comment there): every
# unconditional `TaskSpec` row whose name ends `.ELF`. `board_elfs`
# (`tests/host/topology-tests/src/bin/board_elfs.rs`) queries it, built with NO
# topology feature on — a board build turns on none of
# `cap-refusal-canary`/`ipc-endpoint-canary`/`profile-actuation` (see that
# crate's own Cargo.toml), so the crate's default feature set already IS a
# board build. `tools/gen_board_manifest.py` then resolves each declared
# name to the build path IMAGE_ELFS already knows (failing loudly — ORPHAN
# SERVICE — if the topology names an ELF nothing here builds), and
# `tools/check_board_disk.py` reads the FINISHED image back with `mdir` and
# fails — ORPHAN ELF / ORPHAN SERVICE — if what actually landed on the FAT32
# volume and what the topology declared disagree. Two independent checks,
# pre- and post-build, so drift cannot survive either a bad generator run or
# a hand-edited recipe.
build/board_elfs.list: tests/host/topology-tests/src/bin/board_elfs.rs \
		$(shell find crates/core/topology/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
		tests/host/topology-tests/Cargo.toml
	@mkdir -p build
	cd tests/host/topology-tests && $(CARGO) run -q --bin board_elfs > "$(CURDIR)/build/board_elfs.list.tmp"
	mv build/board_elfs.list.tmp $@

build/board_manifest.txt: build/board_elfs.list tools/gen_board_manifest.py $(MLSRV_ELF_BOARD)
	@mkdir -p build
	python3 tools/gen_board_manifest.py build/board_elfs.list $(IMAGE_ELFS_BOARD) > $@

# The ML data sidecars for the board volume: the same bytes as the QEMU
# disks' MLP.RML/POLICY.GGF, signed with the board key (never the test key).
$(BOARD_DIR)/mlp.sig: build/mlp.rmlp tools/gen_config_sig.py $(BOARD_PRIV_STAMP)
	$(call require_board_priv,BOARD-SIG)
	@mkdir -p $(BOARD_DIR)
	python3 tools/gen_config_sig.py build/mlp.rmlp --priv "$(BOARD_SIGN_PRIV)" --out $@

$(BOARD_DIR)/policy.sig: build/policy.gguf tools/gen_config_sig.py $(BOARD_PRIV_STAMP)
	$(call require_board_priv,BOARD-SIG)
	@mkdir -p $(BOARD_DIR)
	python3 tools/gen_config_sig.py build/policy.gguf --priv "$(BOARD_SIGN_PRIV)" --out $@

# Wave 15 (TOPOSIGN follow-up, owner round 73): every product image path ships
# its FAT volume, because a product kernel defaults to
# TOPOLOGY_SOURCE_SIGNED_REQUIRED and halts without the signed topology. One
# volume per product profile, same recipe; only the topology differs (emitted
# for that profile's .config and features, bound to the volume's device id,
# signed with the board key):
#   build/disk-board.img        VF2 (`make vf2`; the name predates the others)
#   build/disk-board-k1.img     K1  (`make k1`)
#   build/disk-board-fleet.img  the fleet profile (`make build-fleet`)
# No board key, no volume: `require_board_priv` refuses with a message rather
# than ship an unsigned topology.
build/disk-board.img:       BOARD_VOL_KCONFIG := build/vf2.config
build/disk-board-k1.img:    BOARD_VOL_KCONFIG := build/k1.config
build/disk-board-fleet.img: BOARD_VOL_KCONFIG := build/fleet.config
build/disk-board.img build/disk-board-k1.img build/disk-board-fleet.img: AUTORUN_ELF := /fat/GPIODRV.ELF
build/disk-board.img build/disk-board-k1.img build/disk-board-fleet.img: \
		build/board_manifest.txt tools/check_board_disk.py \
		tools/check_board_keys.py $(IMAGE_HASHES_BOARD) $(BOARD_DIR)/mlp.sig $(BOARD_DIR)/policy.sig \
		$(BOARD_PRIV_STAMP) \
		$(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF_BOARD) $(UHELLO_ELF) \
		$(EPSRV_ELF) $(VSSRV_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) \
		$(CAPTEST_ELF) $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) \
		$(VSBENCH_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) build/mlp.rmlp build/policy.gguf \
		$(CONFIG_SIG_TOOLS) $(TOPO_EMIT_DEPS) build/vf2.config build/k1.config build/fleet.config
	$(call require_board_key,BOARD)
	$(call require_board_priv,BOARD)
	@mkdir -p build
	dd if=/dev/zero of=$@ bs=1M count=32
	# U06-9/#30 (2026-09-26): extend the raw image by
	# MSC_RESERVED_TAIL_SECTORS (8 sectors = 4 KiB) and format ONLY the
	# first 32768 1-KiB blocks (32 MiB) as FAT32, leaving the tail
	# reserved -- see `kernel/src/msc_gadget.rs::MSC_RESERVED_TAIL_SECTORS`.
	# Without this the reserved region LINK.KEY/the entropy seed file live
	# in does not exist on this image (`reserved_region_read`/`write` then
	# fail closed -- safe, but the key/seed never load). 65536 sectors x
	# 512 B = 32 MiB = 32768 KiB, the mkfs.fat BLOCKS unit.
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "# AzOS Configuration\nml_enabled=1\nlog_level=1\nmotor_max_speed=100\nwatchdog_ms=500\nnet_ip=10.0.2.15\nnet_gateway=10.0.2.2\nnet_mask=255.255.255.0\nbehavior_server_ip=10.0.2.2\nbehavior_server_port=9000\nbehavior_l1_enabled=1\nbehavior_l2_enabled=1\nbehavior_l3_enabled=1\nautorun=$(AUTORUN_ELF)\n" \
		> $@.tmp_board_config.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" \
		> $@.tmp_board_bootmeta
	$(call provision_and_sign_config,$@.tmp_board_config.ini,$@.tmp_board_config.sig,$(BOARD_SIGN_PRIV))
	mcopy -i $@ build/mlp.rmlp ::MLP.RML
	mcopy -i $@ build/policy.gguf ::POLICY.GGF
	mcopy -i $@ $(BOARD_DIR)/mlp.sig ::MLP.SIG
	mcopy -i $@ $(BOARD_DIR)/policy.sig ::POLICY.SIG
	mcopy -i $@ $@.tmp_board_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_board_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_board_bootmeta ::BOOTMETA
	# Wave 15: the board kernel's topology as signed files (TOPOLOGY_SOURCE),
	# bound to this volume's device id, signed with the board key.
	$(call topo_bind,riscv64,$(BOARD_VOL_KCONFIG),$(call board_topo_features,$(BOARD_VOL_KCONFIG)),$(BOARD_DIR)/topo-$(basename $(notdir $@)),$@,$(BOARD_SIGN_PRIV))
	# The topology's images plus the ones this volume's .config selects
	# under "Userspace programs" (`make config`).
	python3 tools/gen_board_manifest.py build/board_elfs.list --config $(BOARD_VOL_KCONFIG) $(IMAGE_ELFS_BOARD) > $@.manifest
	@while IFS='=' read -r name path; do \
		[ -z "$$name" ] && continue; \
		mcopy -i $@ "$$path" "::$$name" || exit 1; \
	done < $@.manifest
	@rm -f $@.tmp_board_config.ini $@.tmp_board_bootmeta
	python3 tools/check_board_disk.py $@ $@.manifest
	python3 tools/check_board_keys.py disk $@ $(IMAGE_HASHES_BOARD) $(MLSRV_ELF) tools/keys/test_pub.bin
	python3 tools/check_board_keys.py sigs $@ "$(BOARD_TOPOLOGY_KEY)"
	@echo "[DISK] Board FAT32 image (topology-derived, signed topology for $(BOARD_VOL_KCONFIG)): $@ (autorun=$(AUTORUN_ELF))"

.PHONY: board-elfs
board-elfs: build/board_elfs.list
	@cat build/board_elfs.list

# ── aarch64 disk images (Phase 6 — userspace on aarch64) ─────────────────────
#
# `AARCH64_PAGE_SIZE=16384|65536` (see `TARGET_AARCH64` above) names every
# image below `build/disk-aarch64-16k*.img` / `-64k*` and fills it from that
# granule's ELFs; the default names and contents are the 4 KiB ones.
#
# Same recipe shape as the riscv64 images above, own variable (not a
# parameterized rule: `make`'s pattern rules cannot vary the ELF set the way
# `AUTORUN_ELF`/`CFG_EXTRA` vary a single name), carrying the aarch64 ELFs
# from `userspace-aarch64` instead. MLP.RML and POLICY.GGF too, since wave 9:
# the ring-3 ML service the behavior task spawns on this ISA as on riscv64
# reads both (weights, and the GGUF policy self-test) when it starts.
build/disk-aarch64$(AARCH64_PG_SUFFIX).img:         AUTORUN_ELF_AARCH64 := /fat/HELLO.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-systest.img: AUTORUN_ELF_AARCH64 := /fat/SYSTEST.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-abitest.img: AUTORUN_ELF_AARCH64 := /fat/ABITEST.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-ipctest.img: AUTORUN_ELF_AARCH64 := /fat/IPCTEST.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-captest.img: AUTORUN_ELF_AARCH64 := /fat/CAPTEST.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img: AUTORUN_ELF_AARCH64 := /fat/VSBENCH.ELF
# Wave 12: see `build/disk-vsbench.img`'s DISK_EXTRA.
build/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img: DISK_EXTRA := $(TOOLBOX_ELF_AARCH64)=TOOLBOX.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img: $(TOOLBOX_ELF_AARCH64)
build/disk-aarch64$(AARCH64_PG_SUFFIX)-gpiodrv.img: AUTORUN_ELF_AARCH64 := /fat/GPIODRV.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX)-reflex.img:  AUTORUN_ELF_AARCH64 := /fat/REFLEX.ELF
# aarch64 parity (this task): the network round-trip scenario. Needs
# `net_ip`/`net_gateway`/`net_mask`/`behavior_server_ip`/`behavior_server_port`
# in CONFIG.INI, which the other aarch64 images below do not — those lines
# are harmless on them too (nothing on this ISA reads `behavior_server_*`
# without a `behavior` task, which `kernel_main` does not create here), so
# they are written for every aarch64 image rather than carrying a second
# CONFIG.INI recipe for one name. Same host peer as riscv64's own
# `disk-braincli.img`: `tools/fake_brain.py` on 10.0.2.2:9000 (QEMU SLIRP's
# gateway address maps to the host).
build/disk-aarch64$(AARCH64_PG_SUFFIX)-braincli.img: AUTORUN_ELF_AARCH64 := /fat/BRAINCLI.ELF
# Wave 9 (DRV1): the base of `build/disk-aarch64$(AARCH64_PG_SUFFIX)-drv.img`; see `build/disk-drv.img`.
build/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img: AUTORUN_ELF_AARCH64 :=
build/disk-aarch64-lxbench-base.img: AUTORUN_ELF_AARCH64 := /fat/LXSRV.ELF
build/disk-aarch64$(AARCH64_PG_SUFFIX).img build/disk-aarch64$(AARCH64_PG_SUFFIX)-systest.img build/disk-aarch64$(AARCH64_PG_SUFFIX)-abitest.img \
build/disk-aarch64$(AARCH64_PG_SUFFIX)-ipctest.img build/disk-aarch64$(AARCH64_PG_SUFFIX)-captest.img build/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img \
build/disk-aarch64$(AARCH64_PG_SUFFIX)-gpiodrv.img build/disk-aarch64$(AARCH64_PG_SUFFIX)-reflex.img build/disk-aarch64$(AARCH64_PG_SUFFIX)-braincli.img \
build/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img build/disk-aarch64-lxbench-base.img: \
		$(HELLO_ELF_AARCH64) $(SYSTEST_ELF_AARCH64) $(GPIO_DRV_ELF_AARCH64) $(MLSRV_ELF_AARCH64) \
		$(UHELLO_ELF_AARCH64) $(EPSRV_ELF_AARCH64) $(VSSRV_ELF_AARCH64) \
		$(REFLEX_ELF_AARCH64) $(BRAINCLI_ELF_AARCH64) $(CAPTEST_ELF_AARCH64) \
		$(LATBENCH_ELF_AARCH64) $(ABITEST_ELF_AARCH64) $(IPCTEST_ELF_AARCH64) \
		$(VSBENCH_ELF_AARCH64) build/mlp.rmlp build/policy.gguf build/mlp.sig build/policy.sig \
		tools/keys/test_priv.bin $(CONFIG_SIG_TOOLS)
	@mkdir -p build
	dd if=/dev/zero of=$@ bs=1M count=32
	# U06-9/#30 (2026-09-26): extend the raw image by
	# MSC_RESERVED_TAIL_SECTORS (8 sectors = 4 KiB) and format ONLY the
	# first 32768 1-KiB blocks (32 MiB) as FAT32, leaving the tail
	# reserved -- see `kernel/src/msc_gadget.rs::MSC_RESERVED_TAIL_SECTORS`.
	# Without this the reserved region LINK.KEY/the entropy seed file live
	# in does not exist on this image (`reserved_region_read`/`write` then
	# fail closed -- safe, but the key/seed never load). 65536 sectors x
	# 512 B = 32 MiB = 32768 KiB, the mkfs.fat BLOCKS unit.
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "Hello from AzOS FAT32!\n" > $@.tmp_hello_aarch64.txt
	@printf "net_ip=10.0.2.15\nnet_gateway=10.0.2.2\nnet_mask=255.255.255.0\nbehavior_server_ip=10.0.2.2\nbehavior_server_port=9000\nautorun=$(AUTORUN_ELF_AARCH64)\n" > $@.tmp_config_aarch64.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" \
		> $@.tmp_bootmeta_aarch64
	mcopy -i $@ $@.tmp_hello_aarch64.txt ::HELLO.TXT
	mcopy -i $@ $(HELLO_ELF_AARCH64) ::HELLO.ELF
	mcopy -i $@ $(SYSTEST_ELF_AARCH64) ::SYSTEST.ELF
	mcopy -i $@ $(GPIO_DRV_ELF_AARCH64) ::GPIODRV.ELF
	mcopy -i $@ $(MLSRV_ELF_AARCH64) ::MLSRV.ELF
	mcopy -i $@ $(UHELLO_ELF_AARCH64) ::UHELLO.ELF
	mcopy -i $@ $(EPSRV_ELF_AARCH64) ::EPSRV.ELF
	mcopy -i $@ $(VSSRV_ELF_AARCH64) ::VSSRV.ELF
	mcopy -i $@ $(REFLEX_ELF_AARCH64) ::REFLEX.ELF
	mcopy -i $@ $(BRAINCLI_ELF_AARCH64) ::BRAINCLI.ELF
	mcopy -i $@ $(CAPTEST_ELF_AARCH64) ::CAPTEST.ELF
	mcopy -i $@ $(LATBENCH_ELF_AARCH64) ::LATBENCH.ELF
	mcopy -i $@ $(ABITEST_ELF_AARCH64) ::ABITEST.ELF
	mcopy -i $@ $(IPCTEST_ELF_AARCH64) ::IPCTEST.ELF
	mcopy -i $@ $(VSBENCH_ELF_AARCH64) ::VSBENCH.ELF
	$(foreach f,$(DISK_EXTRA),mcopy -i $@ $(word 1,$(subst =, ,$(f))) ::$(word 2,$(subst =, ,$(f)));)
	# 8.3 name, as the FAT32 driver matches no other: `azos_abi::ml_srv::WEIGHTS_PATH`.
	mcopy -i $@ build/mlp.rmlp ::MLP.RML
	mcopy -i $@ build/policy.gguf ::POLICY.GGF
	mcopy -i $@ build/mlp.sig ::MLP.SIG
	mcopy -i $@ build/policy.sig ::POLICY.SIG
	$(call provision_and_sign_config,$@.tmp_config_aarch64.ini,$@.tmp_config_aarch64.sig)
	mcopy -i $@ $@.tmp_config_aarch64.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config_aarch64.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta_aarch64 ::BOOTMETA
	@rm -f $@.tmp_config_aarch64.ini $@.tmp_config_aarch64.sig $@.tmp_hello_aarch64.txt $@.tmp_bootmeta_aarch64
	@echo "[DISK] aarch64 FAT32 image: $@ (autorun=$(AUTORUN_ELF_AARCH64))"

# Wave 9 (DRV1): see `build/disk-drv.img`.
build/disk-aarch64$(AARCH64_PG_SUFFIX)-drv.img: build/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img $(BUZZ_DRV_ELF_AARCH64) $(INA_DRV_ELF_AARCH64)
	cp build/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img $@
	mcopy -i $@ $(BUZZ_DRV_ELF_AARCH64) ::BUZZDRV.ELF
	mcopy -i $@ $(INA_DRV_ELF_AARCH64) ::INADRV.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (ring-3 drivers BUZZDRV.ELF, INADRV.ELF)"

# RFC-0055: see `build/disk-sh.img`.
build/disk-aarch64-sh.img: build/disk-aarch64-drvbase.img $(SH_ELF_AARCH64) $(TOOLBOX_ELF_AARCH64) $(POWER_ELF_AARCH64) $(FAM_ELFS_AARCH64) $(TRACECTL_ELF_AARCH64)
	cp build/disk-aarch64-drvbase.img $@
	mcopy -i $@ $(SH_ELF_AARCH64) ::SH.ELF
	mcopy -i $@ $(TOOLBOX_ELF_AARCH64) ::TOOLBOX.ELF
	mcopy -i $@ $(POWER_ELF_AARCH64) ::POWER.ELF
	mcopy -i $@ $(FLIGHT_ELF_AARCH64) ::FLIGHT.ELF
	mcopy -i $@ $(BEHAVIOR_ELF_AARCH64) ::BEHAVIOR.ELF
	mcopy -i $@ $(CONFIG_ELF_AARCH64) ::CONFIG.ELF
	mcopy -i $@ $(OTA_ELF_AARCH64) ::OTA.ELF
	mcopy -i $@ $(TRACECTL_ELF_AARCH64) ::TRACECTL.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell SH.ELF, TOOLBOX.ELF, POWER.ELF, FLIGHT/BEHAVIOR/CONFIG/OTA.ELF, TRACECTL.ELF)"

# RFC-0053 L0b: see `build/disk-lx.img`.
build/disk-aarch64-lx.img: build/disk-aarch64-drvbase.img $(LXSRV_ELF_AARCH64) $(LXTEST_KO_AARCH64) $(LX_KO_A64) $(LX_XZTEST)
	cp build/disk-aarch64-drvbase.img $@
	mcopy -i $@ $(LXSRV_ELF_AARCH64) ::LXSRV.ELF
	mcopy -i $@ build/lx/lxtest-aarch64.ko ::LXTEST.KO
	@if [ -f $(LX_KBUILD_DIR)/aarch64/xz_dec.ko ]; then \
		mcopy -i $@ $(LX_KBUILD_DIR)/aarch64/lxbase.ko ::LXBASE.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/aarch64/xz_dec.ko ::XZ_DEC.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/XZTEST.XZ ::XZTEST.XZ && \
		echo "[DISK] $@: + Kbuild modules LXBASE.KO, XZ_DEC.KO, fixture XZTEST.XZ"; fi
	@echo "[DISK] aarch64 FAT32 image: $@ (Linux server skeleton LXSRV.ELF, test module LXTEST.KO)"

# RFC-0053 L1: the comparison volumes (`make lx-compare`): the lx disk's
# files (taken from that disk, so each image keeps ONE recipe line that copies
# it, which tests/host/seccomp-tests checks against IMAGE_ELFS) on a volume
# whose CONFIG.INI autoruns LXSRV.ELF.
LX_BENCH_FILES := LXSRV.ELF LXTEST.KO LXBASE.KO XZ_DEC.KO XZTEST.XZ
build/disk-lxbench.img: build/disk-lxbench-base.img build/disk-lx.img
	rm -rf build/lx/bench-rv && mkdir -p build/lx/bench-rv
	for f in $(LX_BENCH_FILES); do mcopy -i build/disk-lx.img ::$$f build/lx/bench-rv/$$f || exit 1; done
	cp build/disk-lxbench-base.img $@
	for f in $(LX_BENCH_FILES); do mcopy -i $@ build/lx/bench-rv/$$f ::$$f || exit 1; done

build/disk-aarch64-lxbench.img: build/disk-aarch64-lxbench-base.img build/disk-aarch64-lx.img
	rm -rf build/lx/bench-a64 && mkdir -p build/lx/bench-a64
	for f in $(LX_BENCH_FILES); do mcopy -i build/disk-aarch64-lx.img ::$$f build/lx/bench-a64/$$f || exit 1; done
	cp build/disk-aarch64-lxbench-base.img $@
	for f in $(LX_BENCH_FILES); do mcopy -i $@ build/lx/bench-a64/$$f ::$$f || exit 1; done

# RFC-0047: see `build/disk-lxabi.img`.
build/disk-aarch64-lxabi.img: build/disk-aarch64-sh.img $(LXHELLO_ELF_AARCH64)
	cp build/disk-aarch64-sh.img $@
	mcopy -i $@ $(LXHELLO_ELF_AARCH64) ::LXHELLO.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell + static Linux LXHELLO.ELF)"

# ── aarch64 secure-boot fixtures (Ed25519 accept / reject / recover) ─────────
#
# The SAME three fixtures as riscv64's `disk-signed`/`disk-badsig`/
# `disk-recovery` above, over the aarch64 base image. The payloads and
# signatures are reused VERBATIM (`build/KERN_A.BIN`, `KERN_A.SIG`,
# `KERN_BAD.SIG`, `KERN_R.BIN`, `KERN_R.SIG`) and deliberately NOT
# regenerated per ISA: `crates/core/ota::secure_boot` verifies FILES read off the
# FAT volume, never the running kernel image, so an Ed25519 signature over
# `KERN_A.BIN` means exactly the same thing to an aarch64 kernel as to a
# riscv64 one. Regenerating them here would fork the fixtures and let the two
# ISAs' rows drift apart while both stayed green.
#
# `build/disk-aarch64.img` carries BOOTMETA (added above, for parity with
# riscv64's `disk.img`) and no KERN_A.* — so on its own it is the CONTROL:
# slot A answers SignatureAbsent before any crypto runs.
build/disk-aarch64-signed.img: build/disk-aarch64.img build/KERN_A.BIN build/KERN_A.SIG
	cp build/disk-aarch64.img $@
	mcopy -o -i $@ build/KERN_A.BIN ::KERN_A.BIN
	mcopy -o -i $@ build/KERN_A.SIG ::KERN_A.SIG
	@echo "[DISK] aarch64 FAT32 image with signed slot A: $@"

build/disk-aarch64-badsig.img: build/disk-aarch64-signed.img build/KERN_BAD.SIG
	cp build/disk-aarch64-signed.img $@
	mcopy -o -i $@ build/KERN_BAD.SIG ::KERN_A.SIG
	@echo "[DISK] aarch64 FAT32 image with CORRUPTED slot A signature: $@"

# Slot A unsigned (inherited from the base image), slot R signed — the
# one-file delta that turns the control's refusal into owner decision 99's
# fall to recovery. On aarch64 the reset at the end of that fall is PSCI
# `SYSTEM_RESET` (`arch-api`'s `Boot::reboot`), not SBI.
build/disk-aarch64-recovery.img: build/disk-aarch64.img build/KERN_R.BIN build/KERN_R.SIG
	cp build/disk-aarch64.img $@
	mcopy -o -i $@ build/KERN_R.BIN ::KERN_R.BIN
	mcopy -o -i $@ build/KERN_R.SIG ::KERN_R.SIG
	@echo "[DISK] aarch64 FAT32 image with unsigned slot A and a SIGNED recovery slot: $@"

# Seccomp image binding (crates/core/sched/src/seccomp.rs): a profile follows the
# BYTES of an image, never the name they are copied under.
#
# RENAMED: the ABITEST image with uhello's bytes copied over ABITEST.ELF.
# Autorun opens /fat/ABITEST.ELF, the digest is uhello's, so uhello runs under
# UHELLO.ELF's profile and its getpid is refused. Bound by name, it would run
# under ABITEST.ELF's wider row, which allows getpid.
# RFC-0048 P3 gate row (wave 9): the captest volume inside partition 0 of an
# MBR medium, with a 64-sector raw partition 1 after it for `disk.part.1`.
# See tools/make_parted_disk.py for the layout.
build/disk-parted.img: build/disk-captest.img tools/make_parted_disk.py
	python3 tools/make_parted_disk.py build/disk-captest.img $@

build/disk-seccomp-renamed.img: build/disk-abitest.img $(UHELLO_ELF)
	cp build/disk-abitest.img $@
	mcopy -o -i $@ $(UHELLO_ELF) ::ABITEST.ELF
	@echo "[DISK] FAT32 image: $@ (ABITEST.ELF carries uhello's bytes)"

# REPLACED: the UHELLO image with UHELLO.ELF one byte longer. Still a loadable
# ELF (the byte lands after the section header table, which ends the file), and
# its digest matches no shipped ELF, so the kernel refuses to exec it.
build/disk-seccomp-replaced.img: build/disk-uhello.img $(UHELLO_ELF)
	cp build/disk-uhello.img $@
	cp $(UHELLO_ELF) build/uhello-replaced.elf
	printf '\n' >> build/uhello-replaced.elf
	mcopy -o -i $@ build/uhello-replaced.elf ::UHELLO.ELF
	@echo "[DISK] FAT32 image: $@ (UHELLO.ELF is one byte longer than the shipped ELF)"

# Same image, plus a /fat/LINK.KEY, used to prove the `link-auth-enforced`
# gate ACCEPTS a valid key. A gate exercised only by its negative test is
# indistinguishable from a gate that always refuses, so CI runs both halves.
build/disk-linkkey.img: build/disk.img
	cp build/disk.img $@
	@dd if=/dev/urandom of=$@.tmp_linkkey bs=32 count=1 2>/dev/null
	mcopy -i $@ $@.tmp_linkkey ::LINK.KEY
	# U06-9 (2026-09-26): the KERNEL no longer reads /fat/LINK.KEY — it reads
	# reserved tail sector 0 (`msc_gadget::RESERVED_SECTOR_LINK_KEY`, LBA =
	# image sectors - MSC_RESERVED_TAIL_SECTORS), which the USB MSC export
	# cannot address. The FAT copy above stays for the PEER tools
	# (`tools/link_peer.py --image`, mtools). Same 32 bytes in both places.
	# Gate 182e: without this line every kernel-link row booted
	# "key sector absent/unprovisioned".
	dd if=$@.tmp_linkkey of=$@ bs=512 seek=$$(( $$(wc -c < $@) / 512 - 8 )) conv=notrunc 2>/dev/null
	@rm -f $@.tmp_linkkey
	@echo "[DISK] FAT32 image with LINK.KEY: $@"

# W2-B5: same image, CONFIG.SIG flipped by one bit — boots into the fail-closed
# state (`[CFG] WARNING ... fell back to factory defaults`). One flipped bit,
# not a missing file, so Ed25519 verification actually runs and rejects: byte
# 32, the first byte of the v2 sidecar's signature (bytes 0-31 are its magic,
# version, device id and counter, which would be refused before the curve).
build/disk-configtamper.img: build/disk.img
	cp $< $@
	mcopy -n -i $@ ::CONFIG.SIG $@.tmp_tamper.sig
	python3 -c "d = bytearray(open('$@.tmp_tamper.sig', 'rb').read()); d[32] ^= 0x01; open('$@.tmp_tamper.sig', 'wb').write(d)"
	mcopy -o -i $@ $@.tmp_tamper.sig ::CONFIG.SIG
	@rm -f $@.tmp_tamper.sig
	@echo "[DISK] FAT32 image: $@ (CONFIG.SIG tampered — boots into fail-closed state)"

# W2-A4 (V1.9): BRAINCLI autorun + the brain-link key. brain_client refuses
# to start without one, and the peer (`fake_brain.py --wrap`) needs the same
# bytes, so the key is also left at build/braincli_linkkey.bin.
#
# U06-9 (2026-09-26): the KERNEL no longer reads /fat/LINK.KEY, and neither
# does brain_client (`link_key_init` now goes through `SYS_LINK_KEY_READ_TYPED`)
# — see `build/disk-linkkey.img`'s own comment above for the mechanism this
# mirrors (reserved tail sector 0, `msc_gadget::RESERVED_SECTOR_LINK_KEY`,
# unaddressable over the USB MSC export). Unlike that recipe, this one has no
# peer that still needs a FAT copy: `fake_brain.py --wrap` reads
# build/braincli_linkkey.bin directly on the host, so the `mcopy ::LINK.KEY`
# line is dropped outright rather than kept alongside the reserved-sector
# write.
build/disk-braincli-linkkey.img: build/disk-braincli.img
	@cp $< $@
	@dd if=/dev/urandom of=build/braincli_linkkey.bin bs=32 count=1 2>/dev/null
	dd if=build/braincli_linkkey.bin of=$@ bs=512 seek=$$(( $$(wc -c < $@) / 512 - 8 )) conv=notrunc 2>/dev/null
	@echo "[DISK] FAT32 image with BRAINCLI autorun + reserved-sector link key: $@"

# ── Secure-boot fixtures (Ed25519 accept / reject) ───────────────────────────
#
# `build/disk.img` carries no KERN_A.BIN and no KERN_A.SIG, so the only
# secure-boot scenario it can support is "signature file absent" — which
# `secure_boot_verify_slot_detailed()` answers before touching any crypto.
# These two images add the missing halves: one with a VALID signature (the
# Ed25519 verifier must run and accept) and one whose signature is
# mathematically wrong (the verifier must run and reject). Same argument as
# `build/disk-linkkey.img` above: a gate only ever observed refusing is
# indistinguishable from a gate wired to always refuse.
#
# The signing key is a TEST pair generated on demand into tools/keys/ and
# never committed — see tools/gen_test_key.py for why generating beats
# shipping a fixed pair. `tools/keys/.gitignore` already excludes both halves.
TEST_PRIV_KEY := tools/keys/test_priv.bin
TEST_PUB_KEY  := tools/keys/test_pub.bin

# One recipe, two outputs. gen_test_key.py is idempotent (keeps an intact
# private key, always re-derives the public half), so make invoking it once per
# target is harmless.
$(TEST_PRIV_KEY) $(TEST_PUB_KEY): tools/gen_test_key.py
	python3 tools/gen_test_key.py

# Wave 11: the ML data files' Ed25519 sidecars — bare 64-byte signatures over
# the exact bytes, the CONFIG.SIG format and key (`gen_config_sig.py`), which
# the ML service verifies before using either file (Kconfig
# ML_DATA_SIG_REQUIRED). 8.3 names on the volume: MLP.SIG, POLICY.SIG.
build/mlp.sig: build/mlp.rmlp tools/gen_config_sig.py $(TEST_PRIV_KEY)
	python3 tools/gen_config_sig.py build/mlp.rmlp --priv $(TEST_PRIV_KEY) --out $@

build/policy.sig: build/policy.gguf tools/gen_config_sig.py $(TEST_PRIV_KEY)
	python3 tools/gen_config_sig.py build/policy.gguf --priv $(TEST_PRIV_KEY) --out $@

# The signed slot payload. Content is arbitrary as far as Ed25519 cares, so it
# is generated rather than pulled from a build artifact: no dependency on
# riscv64-unknown-elf-objcopy (not installed everywhere), and no risk of the
# fixture changing size under us. Deterministic seed so a rebuild produces
# byte-identical output and cargo/make stay quiet.
#
# 256 KiB is chosen, not arbitrary: it is comfortably under both
# SECURE_BOOT_MAX_IMAGE_SIZE and MAX_VERIFY_SIZE (2 MiB each — exceeding either
# yields ImageTooLargeToVerify or a bogus SignatureInvalid), while spanning 64
# SECURE_BOOT_READ_CHUNK_SIZE reads, so the chunked `read_slot_image()` loop is
# exercised rather than short-circuited by a single-chunk file.
build/KERN_A.BIN:
	@mkdir -p build
	python3 -c "import random; random.seed(0x52424F53); open('build/KERN_A.BIN','wb').write(random.randbytes(262144))"
	@echo "[SECBOOT] slot payload: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

build/KERN_A.SIG: build/KERN_A.BIN $(TEST_PRIV_KEY)
	python3 tools/sign_ota.py build/KERN_A.BIN --fw-version 1 --priv $(TEST_PRIV_KEY) --out $@

# Bad signature: well-formed RSIG header, trusted public key, wrong scalar.
# Anything cruder (missing file, broken magic, foreign key) is rejected before
# sig_verify is ever called. See tools/corrupt_sig.py.
build/KERN_BAD.SIG: build/KERN_A.SIG tools/corrupt_sig.py
	python3 tools/corrupt_sig.py build/KERN_A.SIG $@

# ACCEPT fixture: image + matching signature at the FAT volume ROOT. Root, not
# a /fat subdirectory — `secure_boot.rs` reaches the FAT32 driver directly
# rather than through the VFS mount point, and U-Boot's `fatload` (tools/boot.cmd)
# can only produce the root layout anyway.
build/disk-signed.img: build/disk.img build/KERN_A.BIN build/KERN_A.SIG
	cp build/disk.img $@
	mcopy -o -i $@ build/KERN_A.BIN ::KERN_A.BIN
	mcopy -o -i $@ build/KERN_A.SIG ::KERN_A.SIG
	@echo "[DISK] FAT32 image with signed slot A: $@"

# REJECT fixture: identical, except KERN_A.SIG has one flipped bit in s.
build/disk-badsig.img: build/disk-signed.img build/KERN_BAD.SIG
	cp build/disk-signed.img $@
	mcopy -o -i $@ build/KERN_BAD.SIG ::KERN_A.SIG
	@echo "[DISK] FAT32 image with CORRUPTED slot A signature: $@"

# RECOVERY fixture (owner decision 99): slot A unsigned, slot R signed.
#
# `build/disk.img` already lacks KERN_A.SIG, so slot A answers
# SignatureAbsent — the same refusal the "rejects unsigned" control asserts.
# The ONLY difference here is that a signed KERN_R.BIN exists, so the enforced
# kernel must steer BOOTMETA at R and reset instead of halting. That one-file
# delta is what makes the pair discriminating: same kernel, same slot-A
# verdict, opposite outcome.
#
# Distinct content from KERN_A.BIN (different seed) so that a bug which
# verified A's bytes while claiming to verify R would fail the signature
# rather than pass by coincidence.
build/KERN_R.BIN:
	@mkdir -p build
	python3 -c "import random; random.seed(0x5245434F); open('build/KERN_R.BIN','wb').write(random.randbytes(262144))"
	@echo "[SECBOOT] recovery payload: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

build/KERN_R.SIG: build/KERN_R.BIN $(TEST_PRIV_KEY)
	python3 tools/sign_ota.py build/KERN_R.BIN --fw-version 1 --priv $(TEST_PRIV_KEY) --out $@

# UNFIT-SLOT fixture (owner decision 2026-09-19): slot A signed and bootable,
# slot B present with a mathematically wrong signature.
#
# This is the shape of the attack the `bad_slots` record exists for: the board
# keeps running A (which verifies), while B holds an image that could be
# selected by a rollback. The boot gate must verify B even though it is not
# booting it, and write the verdict down.
#
# Corrupt, not absent: an absent .SIG answers `Unverified`, which is also what
# an *uninstalled* slot looks like, and the kernel deliberately does not brand
# that. Only `Failed` condemns a slot, so the fixture has to produce `Failed`.
build/KERN_B.BIN:
	@mkdir -p build
	python3 -c "import random; random.seed(0x4B45524E); open('build/KERN_B.BIN','wb').write(random.randbytes(262144))"
	@echo "[SECBOOT] slot B payload: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

build/KERN_B.SIG: build/KERN_B.BIN $(TEST_PRIV_KEY)
	python3 tools/sign_ota.py build/KERN_B.BIN --fw-version 1 --priv $(TEST_PRIV_KEY) --out $@

build/KERN_B_BAD.SIG: build/KERN_B.SIG tools/corrupt_sig.py
	python3 tools/corrupt_sig.py build/KERN_B.SIG $@

build/disk-badslotb.img: build/disk-signed.img build/KERN_B.BIN build/KERN_B_BAD.SIG
	cp build/disk-signed.img $@
	mcopy -o -i $@ build/KERN_B.BIN ::KERN_B.BIN
	mcopy -o -i $@ build/KERN_B_BAD.SIG ::KERN_B.SIG
	@echo "[DISK] FAT32 image with signed slot A and an UNFIT slot B: $@"

build/disk-recovery.img: build/disk.img build/KERN_R.BIN build/KERN_R.SIG
	cp build/disk.img $@
	mcopy -o -i $@ build/KERN_R.BIN ::KERN_R.BIN
	mcopy -o -i $@ build/KERN_R.SIG ::KERN_R.SIG
	@echo "[DISK] FAT32 image with unsigned slot A and a SIGNED recovery slot: $@"

# ── VisionFive 2 targets ──────────────────────────────────────────────────────

# U12-2: expand config/defconfigs/vf2.config the way `aarch64:` expands its own
# profile, instead of building from whatever the workspace `.config` happens
# to hold. Before this, `vf2:` never read config/defconfigs/vf2.config at all — only
# comments referenced it — so a VF2 image built after `make defconfig-edge`
# (BOARD_QEMU, RAM_SIZE=256) shipped an 8 GiB board's `azos_limits` capped
# at QEMU's 256 MiB ceiling, silently.
VF2_KCONFIG := build/vf2.config

$(VF2_KCONFIG): config/defconfigs/vf2.config \
		$(shell find . config -maxdepth 1 -name 'Kconfig*' -not -name '* [0-9]*')
	@mkdir -p build
	cp config/defconfigs/vf2.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_VF2=y$$' $@ || { echo "[VF2] $@ lost CONFIG_BOARD_VF2"; exit 1; }

# Build kernel for VisionFive 2 (JH7110). --target/--features come from the
# expanded profile through tools/kconfig_to_cargo.py, as `make aarch64` does;
# the linker script stays on the command line (RUSTFLAGS + --config), since
# the bridge only derives target/features, never link args.
vf2: $(IMAGE_HASHES_BOARD) $(VF2_KCONFIG) build/disk-board.img
	$(call require_board_key,VF2)
	$(call check_board_priv_if_given,VF2)
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" \
	KCONFIG_CONFIG="$(CURDIR)/$(VF2_KCONFIG)" \
	RUSTFLAGS="$(VF2_RUSTFLAGS) $$(python3 tools/kconfig_to_cargo.py --rustflags $(VF2_KCONFIG))" \
	$(CARGO) build --release -p azos_kernel --features board-image \
		$$(python3 tools/kconfig_to_cargo.py $(VF2_KCONFIG) | tr -s ' ') \
		--config "build.rustflags=['-C','link-arg=-T$(VF2_LINKER)']"
	@mkdir -p build
	riscv64-unknown-elf-objcopy -O binary \
		target/$(TARGET)/release/kernel $(VF2_BIN)
	@echo "[VF2] Built $(VF2_BIN) and its volume build/disk-board.img (signed topology)"
	@ls -lh $(VF2_BIN)

# Flash kernel.bin to SD card for VisionFive 2 boot.
# Boot flow: U-Boot SPL → OpenSBI → U-Boot proper → kernel.bin from SD fat32 /boot/
flash-vf2: vf2
	@echo "[VF2] Flashing $(VF2_BIN) to SD card $(VF2_SD)"
	@echo "  Make sure $(VF2_SD)1 is FAT32 and mounted at /mnt/vf2boot (or adjust)"
	@if [ -b "$(VF2_SD)1" ]; then \
		mkdir -p /mnt/vf2boot && \
		mount $(VF2_SD)1 /mnt/vf2boot && \
		cp $(VF2_BIN) /mnt/vf2boot/kernel.bin && \
		umount /mnt/vf2boot && \
		echo "[VF2] kernel.bin written to $(VF2_SD)1:/kernel.bin"; \
	else \
		echo "[VF2] $(VF2_SD)1 not found — copy $(VF2_BIN) manually to the SD FAT32 partition"; \
	fi

# Open serial console to VF2 (requires minicom or picocom).
vf2-console:
	@echo "[VF2] Opening $(VF2_SERIAL) at $(VF2_BAUD) baud (Ctrl+A X to exit)"
	picocom -b $(VF2_BAUD) $(VF2_SERIAL) || \
	minicom -b $(VF2_BAUD) -D $(VF2_SERIAL)

# ── SpacemiT K1 (BananaPi BPI-F3) targets ────────────────────────────────────

# U12-2: same fix as $(VF2_KCONFIG) above, for K1's own profile.
K1_KCONFIG := build/k1.config

# The fleet profile expanded on its own (wave 15): `build-fleet` expands it
# into the workspace .config (`defconfig-fleet`); its volume's topology is
# emitted from this copy, which the same defconfig yields.
build/fleet.config: config/defconfigs/fleet.config \
		$(shell find . config -maxdepth 1 -name 'Kconfig*' -not -name '* [0-9]*')
	@mkdir -p build
	cp config/defconfigs/fleet.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig

$(K1_KCONFIG): config/defconfigs/k1.config \
		$(shell find . config -maxdepth 1 -name 'Kconfig*' -not -name '* [0-9]*')
	@mkdir -p build
	cp config/defconfigs/k1.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_K1=y$$' $@ || { echo "[K1] $@ lost CONFIG_BOARD_K1"; exit 1; }

# Build kernel for K1 (RV64GCVB + native RVV 1.0, VLEN=256).
# The k1 feature automatically enables RVV code paths (kernel/Cargo.toml
# `k1 = ["rvv", ...]`); tools/kconfig_to_cargo.py additionally emits `rvv`
# explicitly for CONFIG_BOARD_K1, which is redundant with that feature edge,
# not in conflict with it.
k1: $(IMAGE_HASHES_BOARD) $(K1_KCONFIG) build/disk-board-k1.img
	$(call require_board_key,K1)
	$(call check_board_priv_if_given,K1)
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" \
	KCONFIG_CONFIG="$(CURDIR)/$(K1_KCONFIG)" \
	RUSTFLAGS="$(K1_RUSTFLAGS) $$(python3 tools/kconfig_to_cargo.py --rustflags $(K1_KCONFIG))" \
	$(CARGO) build --release -p azos_kernel --features board-image \
		$$(python3 tools/kconfig_to_cargo.py $(K1_KCONFIG) | tr -s ' ') \
		--config "build.rustflags=['-C','link-arg=-T$(K1_LINKER)']"
	@mkdir -p build
	riscv64-unknown-elf-objcopy -O binary \
		target/$(TARGET)/release/kernel $(K1_BIN)
	@echo "[K1] Built $(K1_BIN) and its volume build/disk-board-k1.img (signed topology)"
	@ls -lh $(K1_BIN)

# Flash kernel.bin to SD card for K1 boot.
# Boot flow: Boot ROM → U-Boot SPL → OpenSBI → U-Boot proper → kernel.bin
# K1 U-Boot expects the kernel at offset 0x200000 in the boot partition.
flash-k1: k1
	@echo "[K1] Flashing $(K1_BIN) to SD card $(K1_SD)"
	@echo "  Make sure $(K1_SD)1 is FAT32 and mounted at /mnt/k1boot (or adjust)"
	@if [ -b "$(K1_SD)1" ]; then \
		mkdir -p /mnt/k1boot && \
		mount $(K1_SD)1 /mnt/k1boot && \
		cp $(K1_BIN) /mnt/k1boot/kernel.bin && \
		umount /mnt/k1boot && \
		echo "[K1] kernel.bin written to $(K1_SD)1:/kernel.bin"; \
	else \
		echo "[K1] $(K1_SD)1 not found — copy $(K1_BIN) manually to the SD FAT32 partition"; \
	fi

# Open serial console to K1 (requires minicom or picocom).
k1-console:
	@echo "[K1] Opening $(K1_SERIAL) at $(K1_BAUD) baud (Ctrl+A X to exit)"
	picocom -b $(K1_BAUD) $(K1_SERIAL) || \
	minicom -b $(K1_BAUD) -D $(K1_SERIAL)

# OTA: send firmware to robot over TCP.
# Usage: make ota-send ROBOT=10.0.2.15 [PORT=8080] [PLATFORM=qemu] [FW_VER=1]
ROBOT    ?= 10.0.2.15
PORT     ?= 8080
PLATFORM ?= qemu
FW_VER   ?= 1

# OTA needs raw binary, not ELF (ELF has debug info = too large).
OTA_BIN := build/kernel-ota.bin

$(OTA_BIN): build
	@mkdir -p build
	riscv64-unknown-elf-objcopy -O binary $(KERNEL_ELF) $@
	@echo "[OTA] Raw binary: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

ota-send: $(OTA_BIN)
	python3 tools/ota_send.py $(OTA_BIN) $(ROBOT) \
		--port $(PORT) --platform $(PLATFORM) --version $(FW_VER)

# Generate U-Boot boot script for A/B OTA slot selection (VF2/K1).
boot-scr: tools/boot.cmd
	@mkdir -p build
	mkimage -C none -A riscv -T script -d tools/boot.cmd build/boot.scr
	@echo "[OTA] boot.scr generated"

# DEV01 — TFTP fast-iteration netboot for the freshly-built kernel.
# `tftp-serve`: builds + raw-binarifies + serves on udp/$(TFTP_PORT).
# Default port is 6969 (unprivileged); override with TFTP_PORT=69 if
# you run as root.
TFTP_PORT ?= 6969
tftp-serve: $(OTA_BIN)
	python3 tools/tftp_serve.py $(OTA_BIN) --port $(TFTP_PORT)

# DEV01.4 — QEMU built-in TFTP smoke. QEMU's user-mode network
# gateway (10.0.2.2) serves files from build/tftp/; the kernel,
# built with `--features tftp-smoke`, calls tftp_fetch at boot
# and prints `[TFTP] fetched N bytes ... OK`. No external server
# needed — `-netdev user,tftp=...` does it all in-process.
TFTP_SMOKE_DIR := build/tftp
TFTP_SMOKE_FILE := $(TFTP_SMOKE_DIR)/TFTP.BIN
# Two full 512-byte DATA blocks plus a short final one. See
# tools/make_tftp_fixture.sh for why the size and the contents both matter.
TFTP_SMOKE_BYTES := 1100

# .PHONY, not a file rule: a fixture left from an earlier run would be reused
# silently, and the scenario would then be measuring that run instead of this
# one.
.PHONY: $(TFTP_SMOKE_FILE)
$(TFTP_SMOKE_FILE):
	@bash tools/make_tftp_fixture.sh $@ $(TFTP_SMOKE_BYTES)

# ── Two-node network smoke (DEV01.5) ─────────────────────────────────────────
# Boots two kernel instances wired by QEMU's `socket` net backend and asserts a
# 256-byte TCP payload round-trips byte-for-byte. Unlike qemu-tftp-smoke (UDP,
# one direction, peer is QEMU's own TFTP server) both ends here are our kernel,
# so it covers TCP handshake + RX checksum validation in both directions.
# Fails the build on FAIL, panic, or timeout.
qemu-net-pair: $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ENV) $(CARGO) build --release --features qemu,net-smoke
	QEMU=$(QEMU) bash tools/net_pair_smoke.sh

qemu-tftp-smoke: $(TFTP_SMOKE_FILE) $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ENV) $(CARGO) build --release --features qemu,tftp-smoke
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-netdev user,id=net0,tftp=$(TFTP_SMOKE_DIR) \
		-device virtio-net-device,netdev=net0

# ── aarch64 boot smoke ───────────────────────────────────────────────────────

# aarch64 boot smoke. In `crates/` and gated by `tools/ci_check.sh` since
# 2026-09-19 — it is no longer a parked demo. Requires:
#   rustup target add aarch64-unknown-none
#   (+ qemu-system-aarch64 in PATH)
AARCH64_SMOKE_BIN := tests/qemu/aarch64-smoke/target/aarch64-unknown-none/release/aarch64_smoke

$(AARCH64_SMOKE_BIN):
	cd tests/qemu/aarch64-smoke && $(CARGO) +nightly build --release \
	    -Z build-std=core,compiler_builtins \
	    -Z build-std-features=compiler-builtins-mem

# ARMv8.5: `-cpu max,pauth=on` plus `mte=on` on the MACHINE (MTE is a machine
# property in QEMU, not a CPU one). Boots at EL2 so HVC #0 reaches QEMU's
# emulated PSCI; we drop to EL1 via _drop_to_el1 before any GIC programming.
# `-smp 2` is required for the cross-core SGI stage.
qemu-aarch64-smoke: $(AARCH64_SMOKE_BIN)
	qemu-system-aarch64 -M virt,gic-version=3,mte=on \
	    -cpu max,pauth=on -smp 2 -nographic -kernel $(AARCH64_SMOKE_BIN)

# The same image on an ARMv8.0 part: it must still boot and report the baseline
# as NOT MET. No extension is a hard requirement.
qemu-aarch64-smoke-v80: $(AARCH64_SMOKE_BIN)
	qemu-system-aarch64 -M virt,gic-version=3 \
	    -cpu cortex-a72 -smp 2 -nographic -kernel $(AARCH64_SMOKE_BIN)

# ── RFC-0026 Kconfig targets ─────────────────────────────────────────────────
# Install kconfiglib first:
#   /opt/homebrew/bin/python3 -m pip install --user --break-system-packages kconfiglib

KCONFIG_CONFIG     ?= .config
KCONFIG_DEFCONFIG_DIR := config/defconfigs
PYTHON             ?= /opt/homebrew/bin/python3

# Colour scheme of `make config` / `menuconfig` / `nconfig`: white text on a
# black background, whatever the terminal's own theme is (every element names
# both colours). The selected row is inverted, the separators are a grey bar,
# and items hidden by a dependency are red. kconfiglib's own `MENUCONFIG_STYLE`
# syntax; an exported MENUCONFIG_STYLE overrides this one (`make config
# MENUCONFIG_STYLE=default` brings back the stock yellow-on-white theme).
MENUCONFIG_STYLE   ?= path=fg:white,bg:black,bold \
                      separator=fg:white,bg:brightblack,bold \
                      list=fg:white,bg:black \
                      selection=fg:black,bg:white,bold \
                      inv-list=fg:red,bg:black \
                      inv-selection=fg:red,bg:white \
                      help=path show-help=list \
                      frame=fg:black,bg:white,bold \
                      body=fg:white,bg:black \
                      edit=fg:black,bg:white jump-edit=edit \
                      text=list

.PHONY: menuconfig config nconfig oldconfig olddefconfig
menuconfig:
	MENUCONFIG_STYLE='$(MENUCONFIG_STYLE)' $(PYTHON) -m menuconfig

config: menuconfig

nconfig:
	MENUCONFIG_STYLE='$(MENUCONFIG_STYLE)' $(PYTHON) -m menuconfig --style=nconfig

oldconfig:
	$(PYTHON) -m oldconfig

olddefconfig:
	$(PYTHON) -m olddefconfig

defconfig-%:
	@cp $(KCONFIG_DEFCONFIG_DIR)/$*.config $(KCONFIG_CONFIG)
	@$(PYTHON) -m olddefconfig
	@echo "[CONFIG] active = $*"

.PHONY: savedefconfig
savedefconfig:
	$(PYTHON) -m savedefconfig --out $(KCONFIG_DEFCONFIG_DIR)/last_saved.config

$(KCONFIG_CONFIG):
	@echo "[CONFIG] no .config — falling back to edge defconfig"
	@$(MAKE) defconfig-edge

# The development QEMU kernels' configuration (see `build`): `.config` at
# QEMU_LOG_LEVEL. Re-derived on every make, replaced only when it changed
# (`azos_limits` rebuilds on the file).
QEMU_LOG_LEVEL ?= debug
QEMU_LEVEL_LINE = CONFIG_LOG_LEVEL_$(shell printf '%s' '$(QEMU_LOG_LEVEL)' | tr '[:lower:]' '[:upper:]')=y
$(QEMU_DEV_KCONFIG): $(KCONFIG_CONFIG) FORCE
	@mkdir -p $(dir $@)
	@case '$(QEMU_LOG_LEVEL)' in err|warn|info|debug) ;; \
	  *) echo "QEMU_LOG_LEVEL=$(QEMU_LOG_LEVEL): want err, warn, info or debug" >&2; exit 1 ;; esac
	@{ grep -v 'LOG_LEVEL' $(KCONFIG_CONFIG) && echo '$(QEMU_LEVEL_LINE)'; } >$@.new
	@KCONFIG_CONFIG=$@.new $(PYTHON) -m olddefconfig >/dev/null
	@grep -qx '$(QEMU_LEVEL_LINE)' $@.new || { echo "could not set $(QEMU_LEVEL_LINE) in $@" >&2; exit 1; }
	@if cmp -s $@.new $@; then rm -f $@.new; else mv $@.new $@; fi

# ── aarch64 kernel (QEMU virt) ───────────────────────────────────────────────
# The aarch64 counterpart of `make build` / `make qemu`. Three things differ
# from RISC-V, and each is here on purpose:
#
#  * Its own Kconfig profile. config/defconfigs/qemu-aarch64.config is minimal, so it
#    is expanded by olddefconfig into build/aarch64.config — the same expansion
#    tools/ci_check.sh does for the fleet profile — and handed to the build via
#    KCONFIG_CONFIG. The workspace .config (the RISC-V edge profile) is not
#    touched, so `make build` is unaffected.
#  * The linker script goes on the command line, as `make vf2` / `make k1` do,
#    NOT in .cargo/config.toml like RISC-V's: cargo merges that file into every
#    config below it, and tests/qemu/aarch64-smoke and the thirteen aarch64
#    userspace builds carry their own `-T` for the same triple — they would
#    receive a second script and stop linking.
#  * The output is an arm64 `Image` (header in kernel/src/entry/aarch64/asm/
#    boot.S), not the ELF: for an ELF, QEMU passes x0 = 0 and puts no DTB in
#    RAM (measured 2026-09-21); for an Image it passes the DTB in x0, which is
#    also the protocol U-Boot `booti` uses on real boards.
#  * Soft-float target: the kernel names no FP/SIMD register outside the
#    lazy user-FP save/restore (kernel/src/entry/aarch64/fp_lazy.rs,
#    tools/aarch64_fp_free_check.sh). Userspace stays `aarch64-unknown-none`
#    (TARGET_AARCH64 above).
AARCH64_TARGET   := aarch64-unknown-none-softfloat
AARCH64_LINKER   := kernel/linker-aarch64.ld
AARCH64_KCONFIG  := build/aarch64$(AARCH64_PG_SUFFIX).config
# A non-default granule builds in its own target directory: switching granule
# rebuilds every crate (azos_arch_api's PAGE_SIZE is a feature), and the
# 4 KiB kernel's artifacts should survive it.
ifeq ($(AARCH64_PAGE_SIZE),4096)
AARCH64_KTARGET_ENV :=
AARCH64_ELF      := target/$(AARCH64_TARGET)/release/kernel
else
AARCH64_KTARGET_ENV := CARGO_TARGET_DIR="$(CURDIR)/target/aarch64$(AARCH64_PG_SUFFIX)"
AARCH64_ELF      := target/aarch64$(AARCH64_PG_SUFFIX)/$(AARCH64_TARGET)/release/kernel
endif
AARCH64_IMG      := build/kernel-aarch64$(AARCH64_PG_SUFFIX).img
# rustc's own llvm-objcopy (rustup component llvm-tools), the one the gate uses.
AARCH64_OBJCOPY   = $(shell rustc --print sysroot)/lib/rustlib/$(shell rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy
QEMU_AARCH64_KERNEL_FLAGS := -cpu max,pauth=on -smp 2 -nographic

# ── make ARCH=<isa> check ───────────────────────────────────────────────────
# Type-check the kernel for one ISA without linking. For the x86_64 port
# skeleton (config/Kconfig.arch ARCH_X86_64) it is the only build there is;
# its errors and compile_error!s are the porting checklist. The target triple
# and the baseline codegen flags (`--rustflags`: x86_64's X86_64_LEVEL) come
# from the expanded defconfig through tools/kconfig_to_cargo.py, and
# `-Zbuild-std` (.cargo/config.toml) builds core/alloc from rust-src, so no
# target has to be installed. RUSTFLAGS is set only when the ISA has baseline
# flags: an empty one would override riscv64's build.rustflags.
ARCH ?= riscv64
CHECK_DEFCONFIG_riscv64 := config/defconfigs/qemu.config
CHECK_DEFCONFIG_aarch64 := config/defconfigs/qemu-aarch64.config
CHECK_DEFCONFIG_x86_64  := config/defconfigs/qemu-x86_64.config
CHECK_KCONFIG := build/check-$(ARCH).config
# The image table the kernel `include!`s, made when missing (order-only: a
# type-check never waits for a userspace rebuild; `make` refreshes the table).
# Without it a fresh worktree's `make check0` failed in azos_sched.
CHECK_TABLE_riscv64 := $(IMAGE_HASHES)
CHECK_TABLE_aarch64 := $(IMAGE_HASHES_AARCH64)
CHECK_TABLE_x86_64  := build/image_hashes_x86_64.rs

.PHONY: check
check: | $(CHECK_TABLE_$(ARCH))
	@test -n "$(CHECK_DEFCONFIG_$(ARCH))" || { echo "[CHECK] unknown ARCH=$(ARCH) (riscv64, aarch64, x86_64)"; exit 1; }
	@mkdir -p build
	cp "$(CHECK_DEFCONFIG_$(ARCH))" "$(CHECK_KCONFIG)"
	KCONFIG_CONFIG="$(CHECK_KCONFIG)" $(PYTHON) -m olddefconfig
	rf="$$(python3 tools/kconfig_to_cargo.py --rustflags "$(CHECK_KCONFIG)")"; \
	if [ -n "$$rf" ]; then export RUSTFLAGS="$$rf"; else unset RUSTFLAGS; fi; \
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(CURDIR)/$(CHECK_KCONFIG)" \
	    $(CARGO) check --release -p azos_kernel \
	    $$(python3 tools/kconfig_to_cargo.py "$(CHECK_KCONFIG)" | tr -s ' ')

# ── x86_64: build and boot (QEMU microvm, PVH) ─────────────────────────────
# `make ARCH=x86_64 x86_64` builds the kernel ELF; `make qemu-x86_64` boots it
# on `-M microvm` (PVH entry via -kernel, COM1 on stdio, isa-debug-exit so a
# stop ends QEMU with a status). With `QEMU_X86_64_DISK=<FAT image>` (e.g.
# build/disk-x86_64.img) the volume is a virtio-blk-device on the microvm
# virtio-mmio window and the console program runs in ring 3; without one it
# stops at the kernel shell. Same Kconfig expansion as `check`.
# X86_64_FEATURES adds cargo features (`make x86_64 X86_64_FEATURES=ktest`).
X86_64_FEATURES ?=
X86_64_KCONFIG := build/x86_64.config
X86_64_ELF     := target/x86_64-unknown-none/release/kernel
X86_64_IMG     := build/kernel-x86_64.elf
X86_64_LINKER  := kernel/linker-x86_64.ld
# curve25519-dalek picks its AVX2 "simd" backend on x86_64; the kernel is
# soft-float (no SSE/AVX state at CPL0), so it takes the portable one.
X86_64_DALEK   := --cfg curve25519_dalek_backend=\"serial\"
# -cpu max: the default model (qemu64) is below the x86-64-v2 baseline, and the
# kernel refuses it (the canary: `make qemu-x86_64 QEMU_X86_64_CPU=qemu64`).
QEMU_X86_64_CPU ?= max
QEMU_X86_64_FLAGS := -M microvm -cpu $(QEMU_X86_64_CPU) -m 128M -nographic -no-reboot \
	-device isa-debug-exit,iobase=0xf4,iosize=0x04

.PHONY: x86_64 qemu-x86_64
$(X86_64_KCONFIG): config/defconfigs/qemu-x86_64.config $(wildcard Kconfig config/Kconfig*)
	@mkdir -p build
	cp config/defconfigs/qemu-x86_64.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_ARCH_X86_64=y$$' $@ || { echo "[X86_64] $@ lost CONFIG_ARCH_X86_64"; exit 1; }

# ── x86_64 userspace ────────────────────────────────────────────────────────
#
# The ring-3 programs for `userspace/x86_64-azos-user.json`, into
# `build/x86_64/`, bound by their own digest table
# (`build/image_hashes_x86_64.rs`, which crates/core/sched/src/seccomp.rs
# `include!`s on x86_64), exactly as the aarch64 set is. The target is
# bare-metal x86_64 with the hard-float System V ABI (SSE/SSE2, as every
# x86-64 CPU has; the kernel alone is soft-float), static and in the small
# code model: a JSON spec, because rustc's `x86_64-unknown-none` is
# soft-float. Each crate's `.cargo/config.toml` carries the link flags
# (`user_x86_64.ld`); the baseline (Kconfig X86_64_LEVEL and every
# `require`d extension, the SIMD ones included) comes from the kernel's own
# expanded config through `kconfig_to_cargo.py --user-rustflags`, at recipe
# time, so an image is always built for the level the kernel refuses CPUs
# below.
#
# HELLO.ELF is `userspace/tests/hello`, the Rust stand-in aarch64 also uses
# for riscv64's hand-assembled `hello.S` (its binary keeps the crate's
# `hello_aarch64` name). Not in the set yet: syscall_test (aarch64-only),
# latbench/vsbench/vssrv (they read the raw counter and convert it at the
# vDSO's TIMER_FREQ; on x86_64 that counter is the TSC, at its own rate),
# captest (board RTC/IRQ fixtures) and lxsrv (the Linux personality's
# register layout is aarch64/riscv64 only).
TARGET_X86_64 := x86_64-azos-user
X86_64_DIR    := build/x86_64
X86_64_UFLAGS  = -Zjson-target-spec --target $(CURDIR)/userspace/$(TARGET_X86_64).json \
	--config 'target.$(TARGET_X86_64).rustflags=['"$$(python3 $(CURDIR)/tools/kconfig_to_cargo.py --user-rustflags --toml $(CURDIR)/$(X86_64_KCONFIG))"']'
X86_64_UBUILT := target/$(TARGET_X86_64)/release
HELLO_ELF_X86_64     := $(X86_64_DIR)/hello.elf
UHELLO_ELF_X86_64    := $(X86_64_DIR)/uhello.elf
EPSRV_ELF_X86_64     := $(X86_64_DIR)/epsrv.elf
REFLEX_ELF_X86_64    := $(X86_64_DIR)/reflex.elf
BRAINCLI_ELF_X86_64  := $(X86_64_DIR)/brain_client.elf
ABITEST_ELF_X86_64   := $(X86_64_DIR)/abitest.elf
IPCTEST_ELF_X86_64   := $(X86_64_DIR)/ipctest.elf
GPIO_DRV_ELF_X86_64  := $(X86_64_DIR)/gpio_drv.elf
BUZZ_DRV_ELF_X86_64  := $(X86_64_DIR)/buzz_drv.elf
INA_DRV_ELF_X86_64   := $(X86_64_DIR)/ina_drv.elf
MLSRV_ELF_X86_64     := $(X86_64_DIR)/mlsrv.elf
SH_ELF_X86_64        := $(X86_64_DIR)/sh.elf
TOOLBOX_ELF_X86_64   := $(X86_64_DIR)/toolbox.elf
POWER_ELF_X86_64     := $(X86_64_DIR)/power.elf
TRACECTL_ELF_X86_64  := $(X86_64_DIR)/tracectl.elf
FLIGHT_ELF_X86_64    := $(X86_64_DIR)/flight.elf
BEHAVIOR_ELF_X86_64  := $(X86_64_DIR)/behavior.elf
CONFIG_ELF_X86_64    := $(X86_64_DIR)/config.elf
OTA_ELF_X86_64       := $(X86_64_DIR)/ota.elf
IMAGE_ELFS_X86_64 := HELLO.ELF=$(HELLO_ELF_X86_64) UHELLO.ELF=$(UHELLO_ELF_X86_64) EPSRV.ELF=$(EPSRV_ELF_X86_64) \
              REFLEX.ELF=$(REFLEX_ELF_X86_64) BRAINCLI.ELF=$(BRAINCLI_ELF_X86_64) \
              ABITEST.ELF=$(ABITEST_ELF_X86_64) IPCTEST.ELF=$(IPCTEST_ELF_X86_64) \
              GPIODRV.ELF=$(GPIO_DRV_ELF_X86_64) BUZZDRV.ELF=$(BUZZ_DRV_ELF_X86_64) INADRV.ELF=$(INA_DRV_ELF_X86_64) \
              MLSRV.ELF=$(MLSRV_ELF_X86_64) \
              SH.ELF=$(SH_ELF_X86_64) TOOLBOX.ELF=$(TOOLBOX_ELF_X86_64) POWER.ELF=$(POWER_ELF_X86_64) \
              TRACECTL.ELF=$(TRACECTL_ELF_X86_64) \
              FLIGHT.ELF=$(FLIGHT_ELF_X86_64) BEHAVIOR.ELF=$(BEHAVIOR_ELF_X86_64) \
              CONFIG.ELF=$(CONFIG_ELF_X86_64) OTA.ELF=$(OTA_ELF_X86_64)
IMAGE_ELF_PATHS_X86_64 := $(foreach e,$(IMAGE_ELFS_X86_64),$(lastword $(subst =, ,$(e))))
$(IMAGE_ELF_PATHS_X86_64): userspace/$(TARGET_X86_64).json
IMAGE_HASHES_X86_64 := build/image_hashes_x86_64.rs

$(IMAGE_HASHES_X86_64): userspace/image_hashes.py $(IMAGE_ELF_PATHS_X86_64)
	@mkdir -p build
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS_X86_64)

.PHONY: userspace-x86_64
userspace-x86_64: $(IMAGE_ELF_PATHS_X86_64)

$(HELLO_ELF_X86_64): $(HELLO_DIR)/src/main.rs $(HELLO_DIR)/Cargo.toml $(HELLO_DIR)/user_x86_64.ld $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(HELLO_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(HELLO_DIR)/$(X86_64_UBUILT)/hello_aarch64 $@

$(UHELLO_ELF_X86_64): $(UHELLO_DIR)/src/main.rs $(UHELLO_DIR)/Cargo.toml $(UHELLO_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(UHELLO_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(UHELLO_DIR)/$(X86_64_UBUILT)/uhello $@

$(EPSRV_ELF_X86_64): $(EPSRV_DIR)/src/main.rs $(EPSRV_DIR)/Cargo.toml $(EPSRV_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(EPSRV_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(EPSRV_DIR)/$(X86_64_UBUILT)/epsrv $@

$(REFLEX_ELF_X86_64): $(REFLEX_DIR)/src/main.rs $(REFLEX_DIR)/Cargo.toml $(REFLEX_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(REFLEX_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(REFLEX_DIR)/$(X86_64_UBUILT)/reflex $@

$(BRAINCLI_ELF_X86_64): $(BRAINCLI_DIR)/src/main.rs $(BRAINCLI_DIR)/src/link.rs $(BRAINCLI_DIR)/Cargo.toml $(BRAINCLI_DIR)/user_x86_64.ld \
               domains/robot/behavior/src/auth_envelope_core.rs crates/net/encrypt-link/src/lib.rs \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(BRAINCLI_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(BRAINCLI_DIR)/$(X86_64_UBUILT)/brain_client $@

$(ABITEST_ELF_X86_64): $(ABITEST_DIR)/src/main.rs $(ABITEST_DIR)/Cargo.toml $(ABITEST_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(ABITEST_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(ABITEST_DIR)/$(X86_64_UBUILT)/abitest $@

$(IPCTEST_ELF_X86_64): $(IPCTEST_DIR)/src/main.rs $(IPCTEST_DIR)/Cargo.toml $(IPCTEST_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(IPCTEST_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(IPCTEST_DIR)/$(X86_64_UBUILT)/ipctest $@

$(GPIO_DRV_ELF_X86_64): $(GPIO_DRV_DIR)/src/main.rs $(GPIO_DRV_DIR)/Cargo.toml $(GPIO_DRV_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(GPIO_DRV_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(GPIO_DRV_DIR)/$(X86_64_UBUILT)/gpio_drv $@

$(BUZZ_DRV_ELF_X86_64): $(BUZZ_DRV_DIR)/src/main.rs $(BUZZER_CHIP_SRC) $(BUZZ_DRV_DIR)/Cargo.toml $(BUZZ_DRV_DIR)/user_x86_64.ld \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(BUZZ_DRV_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	python3 tools/chip_source_check.py buzzer $(BUZZ_DRV_DIR)/$(X86_64_UBUILT)/buzz_drv
	cp $(BUZZ_DRV_DIR)/$(X86_64_UBUILT)/buzz_drv $@

$(INA_DRV_ELF_X86_64): $(INA_DRV_DIR)/src/main.rs $(INA219_CHIP_SRC) $(INA_DRV_DIR)/Cargo.toml \
               $(INA_DRV_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(INA_DRV_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	python3 tools/chip_source_check.py ina219 $(INA_DRV_DIR)/$(X86_64_UBUILT)/ina_drv
	cp $(INA_DRV_DIR)/$(X86_64_UBUILT)/ina_drv $@

$(MLSRV_ELF_X86_64): $(MLSRV_DEPS) $(MLSRV_DIR)/user_x86_64.ld $(TOPOLOGY_KEY_STAMP) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(MLSRV_DIR) && $(MLSRV_QEMU_BUILD) $(X86_64_UFLAGS) $(MLSRV_KEY_FEATURES)
	cp $(MLSRV_DIR)/$(X86_64_UBUILT)/mlsrv $@

$(SH_ELF_X86_64): $(SH_SRC) $(SH_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(SH_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(SH_DIR)/$(X86_64_UBUILT)/sh $@

$(TOOLBOX_ELF_X86_64): $(TOOLBOX_SRC) $(TOOLBOX_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(TOOLBOX_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(TOOLBOX_DIR)/$(X86_64_UBUILT)/toolbox $@

$(POWER_ELF_X86_64): $(POWER_SRC) $(POWER_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(POWER_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(POWER_DIR)/$(X86_64_UBUILT)/power $@

$(TRACECTL_ELF_X86_64): $(TRACECTL_SRC) $(TRACECTL_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(TRACECTL_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(TRACECTL_DIR)/$(X86_64_UBUILT)/tracectl $@

$(FLIGHT_ELF_X86_64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin flight
	cp $(FAMTOOLS_DIR)/$(X86_64_UBUILT)/flight $@

$(BEHAVIOR_ELF_X86_64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin behavior
	cp $(FAMTOOLS_DIR)/$(X86_64_UBUILT)/behavior $@

$(CONFIG_ELF_X86_64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin config
	cp $(FAMTOOLS_DIR)/$(X86_64_UBUILT)/config $@

$(OTA_ELF_X86_64): $(FAMTOOLS_SRC) $(FAMTOOLS_DIR)/user_x86_64.ld $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin ota
	cp $(FAMTOOLS_DIR)/$(X86_64_UBUILT)/ota $@

# ── x86_64 disk images ──────────────────────────────────────────────────────
#
# The aarch64 images' recipe with the x86_64 ELFs: a 32 MiB FAT32 volume and
# its reserved tail, CONFIG.INI signed with the test key, the ML service's
# weights. `disk-x86_64.img` names no autorun image (the console program,
# Kconfig CONSOLE_PROGRAM, is the first user task); the others autorun one
# test. QEMU attaches it as a virtio-blk-device on microvm's virtio-mmio
# window (`QEMU_X86_64_DISK` below).
build/disk-x86_64.img:         AUTORUN_ELF_X86_64 :=
build/disk-x86_64-abitest.img: AUTORUN_ELF_X86_64 := /fat/ABITEST.ELF
build/disk-x86_64-ipctest.img: AUTORUN_ELF_X86_64 := /fat/IPCTEST.ELF
build/disk-x86_64.img build/disk-x86_64-abitest.img build/disk-x86_64-ipctest.img: \
		$(IMAGE_ELF_PATHS_X86_64) build/mlp.rmlp build/policy.gguf build/mlp.sig build/policy.sig \
		tools/keys/test_priv.bin $(CONFIG_SIG_TOOLS)
	@mkdir -p build
	dd if=/dev/zero of=$@ bs=1M count=32
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "net_ip=10.0.2.15\nnet_gateway=10.0.2.2\nnet_mask=255.255.255.0\nautorun=$(AUTORUN_ELF_X86_64)\n" > $@.tmp_config.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" > $@.tmp_bootmeta
	mcopy -i $@ $(HELLO_ELF_X86_64) ::HELLO.ELF
	mcopy -i $@ $(UHELLO_ELF_X86_64) ::UHELLO.ELF
	mcopy -i $@ $(EPSRV_ELF_X86_64) ::EPSRV.ELF
	mcopy -i $@ $(REFLEX_ELF_X86_64) ::REFLEX.ELF
	mcopy -i $@ $(BRAINCLI_ELF_X86_64) ::BRAINCLI.ELF
	mcopy -i $@ $(ABITEST_ELF_X86_64) ::ABITEST.ELF
	mcopy -i $@ $(IPCTEST_ELF_X86_64) ::IPCTEST.ELF
	mcopy -i $@ $(GPIO_DRV_ELF_X86_64) ::GPIODRV.ELF
	mcopy -i $@ $(BUZZ_DRV_ELF_X86_64) ::BUZZDRV.ELF
	mcopy -i $@ $(INA_DRV_ELF_X86_64) ::INADRV.ELF
	mcopy -i $@ $(MLSRV_ELF_X86_64) ::MLSRV.ELF
	mcopy -i $@ $(SH_ELF_X86_64) ::SH.ELF
	mcopy -i $@ $(TOOLBOX_ELF_X86_64) ::TOOLBOX.ELF
	mcopy -i $@ $(POWER_ELF_X86_64) ::POWER.ELF
	mcopy -i $@ $(TRACECTL_ELF_X86_64) ::TRACECTL.ELF
	mcopy -i $@ $(FLIGHT_ELF_X86_64) ::FLIGHT.ELF
	mcopy -i $@ $(BEHAVIOR_ELF_X86_64) ::BEHAVIOR.ELF
	mcopy -i $@ $(CONFIG_ELF_X86_64) ::CONFIG.ELF
	mcopy -i $@ $(OTA_ELF_X86_64) ::OTA.ELF
	mcopy -i $@ build/mlp.rmlp ::MLP.RML
	mcopy -i $@ build/policy.gguf ::POLICY.GGF
	mcopy -i $@ build/mlp.sig ::MLP.SIG
	mcopy -i $@ build/policy.sig ::POLICY.SIG
	$(call provision_and_sign_config,$@.tmp_config.ini,$@.tmp_config.sig)
	mcopy -i $@ $@.tmp_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta ::BOOTMETA
	@rm -f $@.tmp_config.ini $@.tmp_config.sig $@.tmp_bootmeta
	@echo "[DISK] x86_64 FAT32 image: $@ (autorun=$(AUTORUN_ELF_X86_64))"

# The seccomp table of the x86_64 images (crates/core/sched/src/seccomp.rs).
x86_64: $(X86_64_KCONFIG) $(IMAGE_HASHES_X86_64)
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(CURDIR)/$(X86_64_KCONFIG)" \
	    RUSTFLAGS="-C link-arg=-T$(X86_64_LINKER) -C relocation-model=static $(X86_64_DALEK) $$(python3 tools/kconfig_to_cargo.py --rustflags $(X86_64_KCONFIG))" \
	    $(CARGO) build --release -p azos_kernel \
	    $$(python3 tools/kconfig_to_cargo.py $(X86_64_KCONFIG) | tr -s ' ') \
	    $(if $(X86_64_FEATURES),--features $(X86_64_FEATURES))
	@mkdir -p build
	cp $(X86_64_ELF) $(X86_64_IMG)
	@echo "[X86_64] Built $(X86_64_IMG)"

QEMU_X86_64_DISK ?=
qemu-x86_64: x86_64 $(QEMU_X86_64_DISK)
	qemu-system-x86_64 $(QEMU_X86_64_FLAGS) -kernel $(X86_64_IMG) \
	    $(if $(QEMU_X86_64_DISK),-drive file=$(QEMU_X86_64_DISK)$(comma)if=none$(comma)format=raw$(comma)id=d0 -device virtio-blk-device$(comma)drive=d0)

.PHONY: aarch64 qemu-aarch64 qemu-aarch64-el2

# U12-8: see the LIBSYS_SRC comment above — same iCloud-duplicate hazard,
# same fix, inlined rather than a shared variable so a board Kconfig rule
# defined earlier in this file (`$(VF2_KCONFIG)`/`$(K1_KCONFIG)`) does not
# depend on a `:=` assignment that has not been parsed yet.
$(AARCH64_KCONFIG): config/defconfigs/qemu-aarch64.config \
		$(shell find . config -maxdepth 1 -name 'Kconfig*' -not -name '* [0-9]*')
	@mkdir -p build
	cp config/defconfigs/qemu-aarch64.config $@
	$(if $(AARCH64_PG_SUFFIX),echo "CONFIG_AARCH64_PAGE_$(subst -,,$(subst k,K,$(AARCH64_PG_SUFFIX)))=y" >> $@)
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_ARCH_AARCH64=y$$' $@ || { echo "[AARCH64] $@ lost CONFIG_ARCH_AARCH64"; exit 1; }
	@grep -q '^CONFIG_PAGE_SHIFT=$(if $(filter 16384,$(AARCH64_PAGE_SIZE)),14,$(if $(filter 65536,$(AARCH64_PAGE_SIZE)),16,12))$$' $@ \
		|| { echo "[AARCH64] $@ does not carry the $(AARCH64_PAGE_SIZE)-byte granule"; exit 1; }

# --target and --features come from the expanded profile through
# tools/kconfig_to_cargo.py, as `make build-fleet` does; the rule above has
# already checked CONFIG_ARCH_AARCH64=y, which that script maps to
# $(AARCH64_TARGET), so $(AARCH64_ELF) is the file cargo writes.
#
# `env -u CARGO_BUILD_RUSTFLAGS` and an explicit RUSTFLAGS: an environment
# RUSTFLAGS — even an empty one — overrides `build.rustflags`, so the script is
# passed here rather than through `--config`, where a stray variable in the
# caller's shell would silently drop it.
aarch64: $(AARCH64_KCONFIG) $(IMAGE_HASHES_AARCH64)
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(CURDIR)/$(AARCH64_KCONFIG)" $(AARCH64_KTARGET_ENV) \
	    RUSTFLAGS="-C link-arg=-T$(AARCH64_LINKER) $$(python3 tools/kconfig_to_cargo.py --rustflags $(AARCH64_KCONFIG))" \
	    $(CARGO) build --release -p azos_kernel \
	    $$(python3 tools/kconfig_to_cargo.py $(AARCH64_KCONFIG) | tr -s ' ')
	@mkdir -p build
	"$(AARCH64_OBJCOPY)" -O binary $(AARCH64_ELF) $(AARCH64_IMG)
	@echo "[AARCH64] Built $(AARCH64_IMG)"
	@$(MAKE) --no-print-directory prune

# Entered at EL1: QEMU `virt` without virtualization has no EL2.
qemu-aarch64: aarch64
	qemu-system-aarch64 -M virt,gic-version=3 $(QEMU_AARCH64_KERNEL_FLAGS) -kernel $(AARCH64_IMG)

# Entered at EL2, the way U-Boot / TF-A hand over on real boards: exercises the
# EL2->EL1 trampoline and SMC-conduit PSCI.
qemu-aarch64-el2: aarch64
	qemu-system-aarch64 -M virt,gic-version=3,virtualization=on $(QEMU_AARCH64_KERNEL_FLAGS) -kernel $(AARCH64_IMG)

# ── Raspberry Pi 5 (BCM2712, aarch64) — not ported ──────────────────────────
# `make defconfig-rpi5` selects the board in .config. `make rpi5` expands the
# same profile into build/rpi5.config and builds the aarch64 kernel from it;
# the build stops at the compile_error! in kernel/src/entry/aarch64.rs, which
# says what the port still needs (GICv2 backend, BCM2712 PL011 console,
# firmware boot). The target exists so the board is visible, and it fails
# honestly until the port is done. Like every board target it needs the
# fleet's public key (TOPOLOGY_PUBKEY_PATH) and refuses the test key; the check
# runs first, before any user image is built.
RPI5_KCONFIG := build/rpi5.config
.PHONY: rpi5 rpi5-key
$(RPI5_KCONFIG): config/defconfigs/rpi5.config \
		$(shell find . config -maxdepth 1 -name 'Kconfig*' -not -name '* [0-9]*')
	@mkdir -p build
	cp config/defconfigs/rpi5.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_RPI5=y$$' $@ || { echo "[RPI5] $@ lost CONFIG_BOARD_RPI5"; exit 1; }

rpi5-key:
	$(call require_board_key,RPI5)

rpi5: rpi5-key $(KCONFIG_CONFIG) $(RPI5_KCONFIG) $(IMAGE_HASHES_AARCH64)
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(CURDIR)/$(RPI5_KCONFIG)" $(AARCH64_KTARGET_ENV) \
	    RUSTFLAGS="-C link-arg=-T$(AARCH64_LINKER) $$(python3 tools/kconfig_to_cargo.py --rustflags $(RPI5_KCONFIG))" \
	    $(CARGO) build --release -p azos_kernel \
	    $$(python3 tools/kconfig_to_cargo.py $(RPI5_KCONFIG) | tr -s ' ')

# ── Signed capability topology files (wave 15 TOPOSIGN) ─────────────────────
#
# Kconfig TOPOLOGY_SOURCE: a kernel installs /fat/CAPS.TOM + CAPS.SIG and
# /fat/SCHED.TOM when they verify, are bound to this device and counter, parse
# and are admitted. ONE signature: CAPS.TOM (format 4) carries
# `sched_sha256`, the SHA-256 of SCHED.TOM, plus `device` (the image's device
# record, the id CONFIG.SIG v2 is bound to) and `counter` (TOPO_COUNTER); the
# kernel refuses a counter below the floor it keeps in reserved tail sector
# TOPOLOGY_FLOOR_SECTOR. SCHED.SIG is retired and never written.
#
# These targets write the BUILT-IN topology (crates/core/topology/src/
# builder.rs) as those files, so a volume can carry exactly what a kernel would
# build:
#
#   make topo-volume TOPO_IMAGE=<img>   bind to <img>'s device, sign, copy on
#   make build/disk-topo.img            build/disk.img + the riscv64 set
#   make build/disk-aarch64-topo.img    build/disk-aarch64.img + aarch64's
#   make topology-files                 both ISAs' files, unbound unless
#                                       TOPO_DEVICE is given (inspection)
#
# The topology depends on the .config (row budgets, limits) and on the
# kernel's features (canary rows, profiles), so the emitter
# (tests/host/topology-tests/src/bin/topo_emit.rs) is built with the same
# KCONFIG_CONFIG and with the azos_topology features those kernel features
# turn on, as `cargo tree` resolves them; `emit-target-<isa>` adds the rows
# only a kernel of that ISA declares. It parses its own output back and exits
# 1 unless the result equals the built-in topology field by field.
#
#   TOPO_KERNEL_FEATURES   kernel features of the kernel that boots the files
#                          (default `qemu`, the gate's QEMU kernels)
#   TOPO_KCONFIG_RISCV64   its .config (default $(QEMU_DEV_KCONFIG))
#   TOPO_KCONFIG_AARCH64   (default $(AARCH64_KCONFIG))
#   TOPO_ISA               topo-volume's ISA (riscv64 | aarch64)
#   TOPO_COUNTER           the signed counter (default 1: the gate rows pin it)
#   TOPO_DEVICE            32 hex digits, instead of the image's own id
#   TOPO_PRIV              topo-volume's signing key (default the TEST key:
#                          QEMU fixtures only; board volumes sign with
#                          TOPOLOGY_PRIVKEY_PATH, below)
#
# Only the dedicated -topo images carry the files, not build/disk.img itself:
# one gate disk is booted by kernels whose built-in topologies differ (every
# canary and smoke feature adds or changes rows), and under the QEMU default
# TOPOLOGY_SOURCE_SIGNED_OR_BUILTIN a signed default topology on the shared
# disk would replace each of them.
TOPO_KERNEL_FEATURES ?= qemu
TOPO_KCONFIG_RISCV64 ?= $(QEMU_DEV_KCONFIG)
TOPO_KCONFIG_AARCH64 ?= $(AARCH64_KCONFIG)
TOPO_ISA ?= riscv64
TOPO_COUNTER ?= 1
TOPO_DEVICE ?=
TOPO_PRIV ?= $(TEST_PRIV_KEY)
TOPO_DIR_RISCV64 := build/topo/riscv64
TOPO_DIR_AARCH64 := build/topo/aarch64
topo_set = $(1)/CAPS.TOM $(1)/CAPS.SIG $(1)/SCHED.TOM

# The azos_topology features a kernel built with features $(1) (a comma list,
# or a shell expression printing one) turns on, as `--features` arguments.
topo_features = $$($(CARGO) tree -q -p azos_kernel --features "$(1)" -e features -i azos_topology --prefix none \
	| sed -n 's/^azos_topology feature "\(.*\)"$$/azos_topology\/\1/p' | grep -v '/default$$' | sort -u | tr '\n' ' ')

# $(call topo_emit,<riscv64|aarch64>,<.config>,<kernel features>,<out dir>,<extra topo_emit args>)
define topo_emit
	@mkdir -p $(4)
	feats="emit-target-$(1) $(call topo_features,$(3))"; \
	cd tests/host/topology-tests && KCONFIG_CONFIG="$(abspath $(2))" CARGO_TARGET_DIR="$(CURDIR)/target/topo-emit-$(1)" \
		$(CARGO) run -q --release --bin topo_emit --features "$$feats" -- "$(CURDIR)/$(4)/CAPS.TOM" "$(CURDIR)/$(4)/SCHED.TOM" $(5)
endef

# $(call topo_bind,<isa>,<.config>,<kernel features>,<out dir>,<image>,<priv key>):
# emit bound to <image>'s device id (or TOPO_DEVICE) and TOPO_COUNTER, sign
# CAPS.TOM with <priv key>, put the three files on <image> (and drop a stale
# SCHED.SIG). The image must already carry its device record.
define topo_bind
	@mkdir -p $(dir $(4)); dev="$(or $(TOPO_DEVICE),$$(python3 tools/device_provision.py --show --id-only $(5)))"; \
	case "$$dev" in [0-9a-f][0-9a-f]*) ;; *) echo "[TOPO] $(5): no device record (tools/device_provision.py) to bind the topology to"; exit 1;; esac; \
	echo "$$dev" > $(4).device
	$(call topo_emit,$(1),$(2),$(3),$(4),--device $$(cat "$(CURDIR)/$(4).device") --counter $(TOPO_COUNTER))
	python3 tools/gen_config_sig.py $(4)/CAPS.TOM --priv "$(6)" --out $(4)/CAPS.SIG
	for f in CAPS.TOM CAPS.SIG SCHED.TOM; do mcopy -o -i $(5) $(4)/$$f ::$$f || exit 1; done
	@mdel -i $(5) ::SCHED.SIG >/dev/null 2>&1 || true
endef

.PHONY: topo-volume
topo-volume: $(TOPO_EMIT_DEPS) $(if $(filter aarch64,$(TOPO_ISA)),$(TOPO_KCONFIG_AARCH64),$(TOPO_KCONFIG_RISCV64)) $(TEST_PRIV_KEY)
	@[ -n "$(TOPO_IMAGE)" ] && [ -f "$(TOPO_IMAGE)" ] || { echo "[TOPO] topo-volume needs TOPO_IMAGE=<an existing image>"; exit 1; }
	$(call topo_bind,$(TOPO_ISA),$(if $(filter aarch64,$(TOPO_ISA)),$(TOPO_KCONFIG_AARCH64),$(TOPO_KCONFIG_RISCV64)),$(TOPO_KERNEL_FEATURES),build/topo/vol-$(TOPO_ISA),$(TOPO_IMAGE),$(TOPO_PRIV))
	@echo "[TOPO] $(TOPO_IMAGE): signed topology bound to device $$(cat build/topo/vol-$(TOPO_ISA).device), counter $(TOPO_COUNTER)"

# What the inspection files were emitted for: rewritten only when it changes.
$(TOPO_DIR_RISCV64)/inputs $(TOPO_DIR_AARCH64)/inputs: FORCE
	@mkdir -p $(@D)
	@printf '%s\n' "$(TOPO_KERNEL_FEATURES) $(TOPO_DEVICE) $(TOPO_COUNTER) $(abspath $(if $(findstring riscv64,$@),$(TOPO_KCONFIG_RISCV64),$(TOPO_KCONFIG_AARCH64)))" > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@; rm -f $@.tmp

topo_emit_args = $(if $(TOPO_DEVICE),--device $(TOPO_DEVICE)) --counter $(TOPO_COUNTER)
$(TOPO_DIR_RISCV64)/CAPS.TOM: $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_RISCV64) $(TOPO_DIR_RISCV64)/inputs
	$(call topo_emit,riscv64,$(TOPO_KCONFIG_RISCV64),$(TOPO_KERNEL_FEATURES),$(TOPO_DIR_RISCV64),$(topo_emit_args))
$(TOPO_DIR_AARCH64)/CAPS.TOM: $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_AARCH64) $(TOPO_DIR_AARCH64)/inputs
	$(call topo_emit,aarch64,$(TOPO_KCONFIG_AARCH64),$(TOPO_KERNEL_FEATURES),$(TOPO_DIR_AARCH64),$(topo_emit_args))
# Written by the same run, after CAPS.TOM.
$(TOPO_DIR_RISCV64)/SCHED.TOM: $(TOPO_DIR_RISCV64)/CAPS.TOM ; @true
$(TOPO_DIR_AARCH64)/SCHED.TOM: $(TOPO_DIR_AARCH64)/CAPS.TOM ; @true
# A bare 64-byte Ed25519 signature over CAPS.TOM (the CAPS.SIG format), TEST
# key: these are QEMU fixtures.
build/topo/riscv64/CAPS.SIG: $(TOPO_DIR_RISCV64)/CAPS.TOM $(TEST_PRIV_KEY) tools/gen_config_sig.py
	python3 tools/gen_config_sig.py $< --priv $(TEST_PRIV_KEY) --out $@
build/topo/aarch64/CAPS.SIG: $(TOPO_DIR_AARCH64)/CAPS.TOM $(TEST_PRIV_KEY) tools/gen_config_sig.py
	python3 tools/gen_config_sig.py $< --priv $(TEST_PRIV_KEY) --out $@

.PHONY: topology-files
topology-files: $(call topo_set,$(TOPO_DIR_RISCV64)) $(call topo_set,$(TOPO_DIR_AARCH64))
	@ls -l $^

build/disk-topo.img: build/disk.img $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_RISCV64) $(TEST_PRIV_KEY)
	cp build/disk.img $@
	$(call topo_bind,riscv64,$(TOPO_KCONFIG_RISCV64),$(TOPO_KERNEL_FEATURES),build/topo/img-riscv64,$@,$(TEST_PRIV_KEY))
	@echo "[DISK] FAT32 image with the signed topology (test key, counter $(TOPO_COUNTER)): $@"

build/disk-aarch64-topo.img: build/disk-aarch64.img $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_AARCH64) $(TEST_PRIV_KEY)
	cp build/disk-aarch64.img $@
	$(call topo_bind,aarch64,$(TOPO_KCONFIG_AARCH64),$(TOPO_KERNEL_FEATURES),build/topo/img-aarch64,$@,$(TEST_PRIV_KEY))
	@echo "[DISK] FAT32 image with the signed topology (test key, counter $(TOPO_COUNTER)): $@"

# The board volumes' sets: each product profile's topology (BOARD_VOL_KCONFIG,
# with `board-image` and that profile's features), bound to the volume's own
# device record and signed with the board key (`require_board_priv`), never
# the test key. Used inside the build/disk-board*.img recipe, after the volume
# is provisioned.
board_topo_features = board-image$$(python3 tools/kconfig_to_cargo.py $(1) | sed -n 's/.*--features /,/p')

# ── CI: build all feature combinations (0 errors, 0 warnings). ───────────────
ci:
	@bash tools/ci_check.sh

# The short tiers (tools/gate_tier.sh): N0 the edit loop (`cargo check` per
# ISA + the host suites the diff reaches), N1 the front check (N0's suites,
# then the per-ISA smoke boots and the gate rows the diff maps to,
# tools/rows_for_diff.py). GATE_BASE=<rev> diffs against a revision, not HEAD.
check0:
	@bash tools/gate_tier.sh n0

check1:
	@bash tools/gate_tier.sh n1

# Full CI: azos builds + AzOSRobotBrain tests + protocol sync.
ci-full:
	@bash tools/ci_full.sh

help:
	@cat "$(CURDIR)/tools/make_help.txt"
