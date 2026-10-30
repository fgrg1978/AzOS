# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Variables: output roots, toolchains, every ELF/image name and path, the board and
# BUILD_TYPE settings, the per-ISA image tables. Nothing here is a rule, so it is
# read first; a variable that a rule lists as a prerequisite is defined here or in
# an earlier include (see the order in the Makefile).
# Included by the top-level Makefile; the order of the includes there is part of the contract.


# Output root. Every build output and every image QEMU loads lives under it,
# never in the checkout (tools/lib/out_dir.py computes the default, once, for the
# Makefile and the shell/Python tools alike): one root per checkout, so two
# worktrees never share outputs. Rust sources `include!` their tables from
# `$AZOS_OUT/build` (env!("AZOS_OUT")), so it is exported to every command.
#   OUT_BUILD   generated configs, hash tables, ELFs, disk images, kernel images
#   OUT_TARGET  the root cargo workspace's target dir (also CARGO_TARGET_DIR)
#   OUT_TGT     one target dir per standalone crate: $(OUT_TGT)/<repo-relative dir>
# In comments below, `build/` and `target/` mean $(OUT_BUILD)/ and $(OUT_TARGET)/.
AZOS_OUT ?= $(shell python3 "$(CURDIR)/tools/lib/out_dir.py")
AZOS_OUT := $(AZOS_OUT)
export AZOS_OUT
OUT_BUILD  := $(AZOS_OUT)/build
OUT_TARGET := $(AZOS_OUT)/target
OUT_TGT    := $(AZOS_OUT)/tgt
export CARGO_TARGET_DIR := $(OUT_TARGET)

# The configuration (`make config` writes it) and the ISA it selects
# (config/arch/Kconfig.isa, the ARCH choice): `make build` builds that ISA and
# `make qemu` boots it ("The configured system", at the end of this file).
# Without a configuration it is riscv64, the ISA of the defconfig the
# `$(KCONFIG_CONFIG)` rule (mk/kernel.mk) falls back to.
KCONFIG_CONFIG ?= .config
KCONFIG_ISA := $(or $(shell sed -n -E 's/^CONFIG_ARCH_(RISCV64|AARCH64|X86_64)=y$$/\1/p' '$(KCONFIG_CONFIG)' 2>/dev/null | tr '[:upper:]' '[:lower:]'),riscv64)
# The ISA of `make check`, `make doc` and `make azos-guest`: the configuration's,
# or the one named (`make check ARCH=aarch64`).
ARCH ?= $(KCONFIG_ISA)

QEMU  := qemu-system-riscv64
QEMU_FLAGS := -machine virt -nographic -bios default
CARGO := $(shell command -v cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)

# The riscv64 kernel's cargo output (the `riscv64` build, the boards,
# size-kernel): its triple, its profile's directory and its ELF.
RISCV64_TARGET := riscv64imac-unknown-none-elf
PROFILE ?= release
ifeq ($(PROFILE),release)
    CARGO_FLAGS := --release
    RISCV64_TARGET_DIR := $(OUT_TARGET)/$(RISCV64_TARGET)/release
else
    CARGO_FLAGS :=
    RISCV64_TARGET_DIR := $(OUT_TARGET)/$(RISCV64_TARGET)/debug
endif

RISCV64_KERNEL_ELF := $(RISCV64_TARGET_DIR)/kernel

# The ring-3 images' target on each ISA: the one spec per ISA in sdk/targets,
# no_std and std alike. It carries the whole layout (image base, page size,
# entry, a static position-independent executable): no image has a linker
# script (tools/lint/user_entry_lint.py). Cargo names the output directory after it.
USER_SPECS          := $(CURDIR)/sdk/targets
TARGET_RISCV64_USER := riscv64imac-unknown-azos

# User-space toolchain
RISCV_AS  := riscv64-unknown-elf-as
HELLO_DIR     := userspace/tests/hello
HELLO_ELF     := $(OUT_BUILD)/hello.elf
# A static Linux binary built from our own C (no C library), run
# under the Linux personality. Built with any Linux-targeting clang and
# rustc's own rust-lld; see the `$(LXHELLO_ELF)` rule.
LXHELLO_DIR   := userspace/tests/lxhello
LXHELLO_ELF   := $(OUT_BUILD)/lxhello.elf
SYSTEST_DIR   := userspace/tests/syscall_test
SYSTEST_ELF   := $(OUT_BUILD)/syscall_test.elf
# E11.AQ3 — ring-3 GPIO driver (Rust no_std ELF, built standalone).
GPIO_DRV_DIR  := userspace/drivers/gpio_drv
GPIO_DRV_BUILT:= $(OUT_TGT)/$(GPIO_DRV_DIR)/$(TARGET_RISCV64_USER)/release/gpio_drv
GPIO_DRV_ELF  := $(OUT_BUILD)/gpio_drv.elf
# Wave 9 — the ring-3 ML inference service the behavior task spawns
# (`kernel/src/behavior_ml.rs`). Same standalone shape as gpio_drv.
MLSRV_DIR     := userspace/services/infsrv
MLSRV_BUILT   := $(OUT_TGT)/$(MLSRV_DIR)/$(TARGET_RISCV64_USER)/release/infsrv
MLSRV_ELF     := $(OUT_BUILD)/mlsrv.elf

# Wave 9 (DRV1) — the ring-3 buzzer and INA219 drivers.
# Started by the kernel from their `start = true` topology rows, not by
# autorun. Shipped only on the drivers disks below (and the board volume).
BUZZ_DRV_DIR  := userspace/drivers/buzz_drv
BUZZ_DRV_BUILT:= $(OUT_TGT)/$(BUZZ_DRV_DIR)/$(TARGET_RISCV64_USER)/release/buzz_drv
BUZZ_DRV_ELF  := $(OUT_BUILD)/buzz_drv.elf
INA_DRV_DIR   := userspace/drivers/ina_drv
INA_DRV_BUILT := $(OUT_TGT)/$(INA_DRV_DIR)/$(TARGET_RISCV64_USER)/release/ina_drv
INA_DRV_ELF   := $(OUT_BUILD)/ina_drv.elf
# The user shell and its multicall tool image.
SH_DIR        := userspace/services/sh
SH_BUILT      := $(OUT_TGT)/$(SH_DIR)/$(TARGET_RISCV64_USER)/release/sh
SH_ELF        := $(OUT_BUILD)/sh.elf
# The Terminal object (interface + codec) the shell and its server share, and
# the terminal server (the console program of the native shell session).
TERM_LIB_SRC  := userspace/lib/term/src/lib.rs userspace/lib/term/Cargo.toml
# The Names object (interface + view codec): the name server and its clients.
NAMES_LIB_SRC := userspace/lib/names/src/lib.rs userspace/lib/names/Cargo.toml
# The Login object (interface and credential): the terminal server, the login
# service and the component manager's table of contracts.
LOGIN_LIB_SRC := userspace/lib/login/src/lib.rs userspace/lib/login/Cargo.toml
SH_SRC        := $(SH_DIR)/src/main.rs $(SH_DIR)/src/parse.rs $(SH_DIR)/src/ident.rs \
                 $(SH_DIR)/src/path.rs $(SH_DIR)/src/req.rs $(SH_DIR)/Cargo.toml $(TERM_LIB_SRC) $(NAMES_LIB_SRC)
TERMD_DIR     := userspace/services/termd
TERMD_BUILT   := $(OUT_TGT)/$(TERMD_DIR)/$(TARGET_RISCV64_USER)/release/termd
TERMD_ELF     := $(OUT_BUILD)/termd.elf
TERMD_SRC     := $(wildcard $(TERMD_DIR)/src/*.rs) $(TERMD_DIR)/Cargo.toml $(TERM_LIB_SRC) $(LOGIN_LIB_SRC)
NAMESD_DIR     := userspace/services/namesd
NAMESD_BUILT   := $(OUT_TGT)/$(NAMESD_DIR)/$(TARGET_RISCV64_USER)/release/namesd
NAMESD_ELF     := $(OUT_BUILD)/namesd.elf
NAMESD_SRC     := $(NAMESD_DIR)/src/main.rs $(NAMESD_DIR)/src/service.rs $(NAMESD_DIR)/Cargo.toml $(NAMES_LIB_SRC)
COMPMGR_DIR   := userspace/services/compmgr
COMPMGR_BUILT := $(OUT_TGT)/$(COMPMGR_DIR)/$(TARGET_RISCV64_USER)/release/compmgr
COMPMGR_ELF   := $(OUT_BUILD)/compmgr.elf
COMPMGR_SRC   := $(COMPMGR_DIR)/src/main.rs $(COMPMGR_DIR)/src/tree.rs $(COMPMGR_DIR)/src/contracts.rs $(COMPMGR_DIR)/Cargo.toml \
                 $(NAMES_LIB_SRC) $(TERM_LIB_SRC) $(LOGIN_LIB_SRC) $(DECISIONS_LIB_SRC) $(PACKAGES_LIB_SRC)
TOOLBOX_DIR   := userspace/services/toolbox
TOOLBOX_BUILT := $(OUT_TGT)/$(TOOLBOX_DIR)/$(TARGET_RISCV64_USER)/release/toolbox
TOOLBOX_ELF   := $(OUT_BUILD)/toolbox.elf
TOOLBOX_SRC   := $(wildcard $(TOOLBOX_DIR)/src/*.rs) $(TOOLBOX_DIR)/Cargo.toml $(TOOLBOX_DIR)/build.rs crates/drivers/sys/src/klog/wire.rs
# The power tool (the kernel-hosted `power` endpoint).
POWER_DIR     := userspace/services/power
POWER_BUILT   := $(OUT_TGT)/$(POWER_DIR)/$(TARGET_RISCV64_USER)/release/power
POWER_ELF     := $(OUT_BUILD)/power.elf
POWER_LIB_SRC := userspace/lib/power/src/lib.rs userspace/lib/power/Cargo.toml
POWER_SRC     := $(POWER_DIR)/src/main.rs $(POWER_DIR)/src/policy.rs $(POWER_DIR)/Cargo.toml $(POWER_LIB_SRC)
# Wave 15 (TRACE): the kernel tracer's reader (`Cap<Trace>`, the tracer's ops).
TRACECTL_DIR  := userspace/services/tracectl
TRACECTL_BUILT:= $(OUT_TGT)/$(TRACECTL_DIR)/$(TARGET_RISCV64_USER)/release/tracectl
TRACECTL_ELF  := $(OUT_BUILD)/tracectl.elf
TRACECTL_SRC  := $(TRACECTL_DIR)/src/main.rs $(TRACECTL_DIR)/src/profile.rs $(TRACECTL_DIR)/Cargo.toml $(TRACECTL_DIR)/build.rs crates/core/trace/src/prof.rs
# The decision query: the server (`Decisions` on `endpoint.decisions`, from
# the introspection tree's admin records) and `why`, its client tool; both over
# `userspace/lib/decisions`.
DECISIONS_LIB_SRC := userspace/lib/decisions/src/lib.rs userspace/lib/decisions/Cargo.toml
DECISD_DIR := userspace/services/decisd
DECISD_BUILT:= $(OUT_TGT)/$(DECISD_DIR)/$(TARGET_RISCV64_USER)/release/decisd
DECISD_ELF := $(OUT_BUILD)/decisd.elf
DECISD_SRC := $(DECISD_DIR)/src/main.rs $(DECISD_DIR)/src/bin.rs $(DECISD_DIR)/Cargo.toml $(DECISIONS_LIB_SRC)
INPUTD_DIR := userspace/services/inputd
INPUTD_BUILT:= $(OUT_TGT)/$(INPUTD_DIR)/$(TARGET_RISCV64_USER)/release/inputd
INPUTD_ELF := $(OUT_BUILD)/inputd.elf
INPUTD_SRC := $(INPUTD_DIR)/src/main.rs $(INPUTD_DIR)/src/focus.rs $(INPUTD_DIR)/Cargo.toml crates/core/devif/src/input.rs crates/drivers/input/wire/src/event.rs
# The compositor (Kconfig COMPOSITOR): the sole holder of the Display interface and
# the Secure Attention Key's trusted surface. It links the pixel engine and the
# protocol library, and includes the framebuffer console's font.
COMPSRV_DIR := userspace/services/compositor
COMPSRV_BUILT:= $(OUT_TGT)/$(COMPSRV_DIR)/$(TARGET_RISCV64_USER)/release/compositor
COMPSRV_ELF := $(OUT_BUILD)/compsrv.elf
COMPSRV_SRC := $(wildcard $(COMPSRV_DIR)/src/*.rs) $(COMPSRV_DIR)/Cargo.toml $(wildcard userspace/lib/compositor/src/*.rs userspace/lib/compose/src/*.rs) crates/core/devif/src/input.rs crates/core/devif/src/display.rs crates/drivers/fb/src/font.rs
# The kernel log's sink (Kconfig KLOG): drains `MemObj klog.ring` into KLOGn.TXT;
# it shares the ring's wire with the kernel and the toolbox's `log`.
LOGD_DIR   := userspace/services/logd
LOGD_BUILT := $(OUT_TGT)/$(LOGD_DIR)/$(TARGET_RISCV64_USER)/release/logd
LOGD_ELF   := $(OUT_BUILD)/logd.elf
LOGD_SRC   := $(LOGD_DIR)/src/main.rs $(LOGD_DIR)/src/store.rs $(LOGD_DIR)/Cargo.toml $(LOGD_DIR)/build.rs crates/drivers/sys/src/klog/wire.rs
WHY_DIR       := userspace/services/why
WHY_ELF       := $(OUT_BUILD)/why.elf
WHY_SRC       := $(WHY_DIR)/src/main.rs $(WHY_DIR)/src/cli.rs $(WHY_DIR)/Cargo.toml $(DECISIONS_LIB_SRC)
# Signed application packages: the installer (`Packages` on
# `endpoint.packages`) and `pkg`, its client tool, over `userspace/lib/packages`
# and the format/verification/admission in `crates/core/pkg`. The installer
# verifies the signed topology with the topology key, so it is built twice like
# the ML service (see MLSRV_KEY_FEATURES below): `build/pkgd.elf` with the test
# key for the QEMU disks, `build/board/pkgd.elf` with the named key for a board.
PACKAGES_LIB_SRC := $(shell find userspace/lib/packages/src crates/core/pkg/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
               userspace/lib/packages/Cargo.toml crates/core/pkg/Cargo.toml
PKGD_DIR      := userspace/services/pkgd
TLS_LIB_SRC   := $(shell find userspace/lib/tls/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') userspace/lib/tls/Cargo.toml
PKGD_ELF      := $(OUT_BUILD)/pkgd.elf
PKG_DIR       := userspace/services/pkg
PKG_BUILT     := $(OUT_TGT)/$(PKG_DIR)/$(TARGET_RISCV64_USER)/release/pkg
PKG_ELF       := $(OUT_BUILD)/pkg.elf
PKG_SRC       := $(PKG_DIR)/src/main.rs $(PKG_DIR)/Cargo.toml $(PACKAGES_LIB_SRC)
RPC_LIB_SRC   := $(wildcard userspace/lib/rpc/src/*.rs) userspace/lib/rpc/Cargo.toml
RPCSRV_DIR    := userspace/services/rpcsrv
RPCSRV_BUILT  := $(OUT_TGT)/$(RPCSRV_DIR)/$(TARGET_RISCV64_USER)/release/rpcsrv
RPCSRV_ELF    := $(OUT_BUILD)/rpcsrv.elf
RPCSRV_SRC    := $(RPCSRV_DIR)/src/main.rs $(RPCSRV_DIR)/Cargo.toml $(RPC_LIB_SRC) $(DECISIONS_LIB_SRC)
# The Zenoh gateway (Kconfig ZENOH_GW) over the in-tree Zenoh codec.
ZENOH_LIB_SRC := $(wildcard userspace/lib/zenoh/src/*.rs) userspace/lib/zenoh/Cargo.toml
ZENOHD_DIR    := userspace/services/zenohd
ZENOHD_BUILT  := $(OUT_TGT)/$(ZENOHD_DIR)/$(TARGET_RISCV64_USER)/release/zenohd
ZENOHD_ELF    := $(OUT_BUILD)/zenohd.elf
# The relay of the QUIC link (Kconfig RPC_QUIC): a std program (userspace/lib/quic), its recipes with the SDK's.
RPCQUIC_ELF   := $(OUT_BUILD)/rpcquic.elf
ZENOHD_SRC    := $(wildcard $(ZENOHD_DIR)/src/*.rs) $(ZENOHD_DIR)/Cargo.toml $(ZENOH_LIB_SRC) $(DECISIONS_LIB_SRC) $(UALLOC_SRC)
# The PTP daemon (Kconfig PTPD).
PTPD_DIR    := userspace/services/ptpd
PTPD_BUILT  := $(OUT_TGT)/$(PTPD_DIR)/$(TARGET_RISCV64_USER)/release/ptpd
PTPD_ELF    := $(OUT_BUILD)/ptpd.elf
PTPD_SRC     := $(wildcard $(PTPD_DIR)/src/*.rs) $(PTPD_DIR)/Cargo.toml $(PTPD_DIR)/build.rs

# The audio server (Kconfig AUDIOD).
AUDIOD_DIR   := userspace/services/audiod
AUDIOD_BUILT := $(OUT_TGT)/$(AUDIOD_DIR)/$(TARGET_RISCV64_USER)/release/audiod
AUDIOD_ELF   := $(OUT_BUILD)/audiod.elf
AUDIOD_SRC   := $(wildcard $(AUDIOD_DIR)/src/*.rs) $(AUDIOD_DIR)/Cargo.toml
# The MCP bridge (Kconfig MCP_BRIDGE) over the in-tree MCP codec and the RPC
# transport's warrant token.
MCP_LIB_SRC   := $(wildcard userspace/lib/mcp/src/*.rs) userspace/lib/mcp/Cargo.toml
MCPD_DIR      := userspace/services/mcpd
MCPD_BUILT    := $(OUT_TGT)/$(MCPD_DIR)/$(TARGET_RISCV64_USER)/release/mcpd
MCPD_ELF      := $(OUT_BUILD)/mcpd.elf
MCPD_SRC      := $(wildcard $(MCPD_DIR)/src/*.rs) $(MCPD_DIR)/Cargo.toml $(MCP_LIB_SRC) $(RPC_LIB_SRC) $(DECISIONS_LIB_SRC) $(UALLOC_SRC)
# The SSH server (Kconfig SSHD, default y; n on MICRO and a certifiable build). It pulls in the terminal
# server's line discipline and the shell's path and spawn-request modules with
# #[path], so their files are among its sources.
SSHD_DIR      := userspace/services/sshd
SSHD_BUILT    := $(OUT_TGT)/$(SSHD_DIR)/$(TARGET_RISCV64_USER)/release/sshd
SSHD_ELF      := $(OUT_BUILD)/sshd.elf
SSHD_SRC      := $(wildcard $(SSHD_DIR)/src/*.rs) $(SSHD_DIR)/Cargo.toml userspace/services/termd/src/disc.rs userspace/services/termd/src/edit.rs \
                 userspace/services/sh/src/path.rs userspace/services/sh/src/req.rs $(UALLOC_SRC)
# The login service (Kconfig CONSOLE_LOGIN, default n): the Login object's
# server. The interface (`LOGIN_LIB_SRC`, above) is a library of its own.
LOGIND_DIR    := userspace/services/logind
LOGIND_BUILT  := $(OUT_TGT)/$(LOGIND_DIR)/$(TARGET_RISCV64_USER)/release/logind
LOGIND_ELF    := $(OUT_BUILD)/logind.elf
LOGIND_SRC    := $(wildcard $(LOGIND_DIR)/src/*.rs) $(LOGIND_DIR)/Cargo.toml $(LOGIN_LIB_SRC)
# Hypervisor H1: the ring-3 virtual-machine monitor (the device models of a guest).
VMMD_DIR      := userspace/services/vmmd
VMMD_BUILT    := $(OUT_TGT)/$(VMMD_DIR)/$(TARGET_RISCV64_USER)/release/vmmd
VMMD_ELF      := $(OUT_BUILD)/vmmd.elf
VMMD_SRC      := $(wildcard $(VMMD_DIR)/src/*.rs) $(VMMD_DIR)/Cargo.toml $(VMMD_DIR)/build.rs
# Kconfig LINUX_RUNTIME: the ring-3 half of the Linux personality
# (userspace/lib/linux_rt behind userspace/services/lxrt). Not a disk image:
# the kernel embeds it (`include_bytes!` in kernel/src/boot/seams.rs) and maps
# it into every Linux process at spawn. Built only when the .config asks.
LXRT_DIR      := userspace/services/lxrt
LXRT_BUILT    := $(OUT_TGT)/$(LXRT_DIR)/$(TARGET_RISCV64_USER)/release/lxrt
LXRT_ELF      := $(OUT_BUILD)/linux_rt.elf
LXRT_SRC      := $(LXRT_DIR)/src/main.rs $(LXRT_DIR)/Cargo.toml $(LXRT_DIR)/build.rs \
                 userspace/lib/linux_rt/src/lib.rs userspace/lib/linux_rt/Cargo.toml \
                 $(wildcard crates/core/linux-abi/src/*.rs) $(wildcard crates/core/abi/src/*.rs)
LXRT_TARGET_AARCH64 := aarch64-unknown-none-softfloat
# rustc's own soft-float x86_64 target (no SSE: see lxrt/build.rs).
LXRT_TARGET_X86_64 := x86_64-unknown-none
# The runtime on those two: the layout from lxrt/build.rs, the small code model,
# and on x86_64 a static executable (the target's default is a PIE in the
# kernel code model) the kernel maps unrelocated.
LXRT_UFLAGS_AARCH64 = --target $(LXRT_TARGET_AARCH64) \
	--config 'target.$(LXRT_TARGET_AARCH64).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)","-C","code-model=small"]'
LXRT_UFLAGS_X86_64 = --target $(LXRT_TARGET_X86_64) \
	--config 'target.$(LXRT_TARGET_X86_64).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)","-C","code-model=small","-C","relocation-model=static"]'
# `yes` when the .config asks for LINUX_RUNTIME: the runtime ELF then joins the
# prerequisites of the image-hash tables every kernel build depends on, as the
# embedded runtime's `include_bytes!` needs it to exist.
LXRT_NEED     = $(shell grep -qs '^CONFIG_LINUX_RUNTIME=y' $(or $(KCONFIG_CONFIG),.config) </dev/null && echo yes)
# Wave 12: the other privileged families' tools, one crate with one binary
# each (`FLIGHT.ELF`, `BEHAVIOR.ELF`, `CONFIG.ELF`, `OTA.ELF`).
FAMTOOLS_DIR  := userspace/services/famtools
FAMTOOLS_SRC  := $(wildcard $(FAMTOOLS_DIR)/src/*.rs $(FAMTOOLS_DIR)/src/bin/*.rs) $(FAMTOOLS_DIR)/Cargo.toml
FAMTOOLS_OUT  := $(OUT_TGT)/$(FAMTOOLS_DIR)/$(TARGET_RISCV64_USER)/release
FLIGHT_ELF    := $(OUT_BUILD)/flight.elf
BEHAVIOR_ELF  := $(OUT_BUILD)/behavior.elf
CONFIG_ELF    := $(OUT_BUILD)/config.elf
OTA_ELF       := $(OUT_BUILD)/ota.elf
FAM_ELFS      := $(FLIGHT_ELF) $(BEHAVIOR_ELF) $(CONFIG_ELF) $(OTA_ELF)
# Every Kconfig file (the root, config/Kconfig, the topic files under
# config/*/ and the generated config/Kconfig.userspace): an expanded config
# depends on all of them. iCloud's "NAME 2" duplicates are not sources.
KCONFIG_FILES := Kconfig $(shell find config -name 'Kconfig*' -not -name '* [0-9]*' | sort)
# The hardened ring-3 allocator (userspace/lib/ualloc, Kconfig USER_ALLOC_*):
# its knobs reach the program through azos_limits, so the configuration is an
# input of the programs that link it (KCONFIG_CONFIG is defined further down).
UALLOC_SRC    := $(wildcard userspace/lib/ualloc/src/*.rs) userspace/lib/ualloc/Cargo.toml \
                 $(or $(KCONFIG_CONFIG),.config)
# The Linux driver server skeleton. Links the module loader
# (crates/core/lx-loader, no Linux code) and nothing from crates/drivers/lx/.
LXSRV_DIR     := userspace/services/lxsrv
LXSRV_BUILT   := $(OUT_TGT)/$(LXSRV_DIR)/$(TARGET_RISCV64_USER)/release/lxsrv
LXSRV_ELF     := $(OUT_BUILD)/lxsrv.elf
LXSRV_SRC     := $(LXSRV_DIR)/src/main.rs $(LXSRV_DIR)/Cargo.toml \
                 $(wildcard crates/core/lx-loader/src/*.rs) crates/core/lx-loader/Cargo.toml \
                 $(UALLOC_SRC)
# Three more standalone Rust ring-3 ELFs. They compiled and were never once
# executed: nothing built them (they are absent from the `userspace:` target
# below), so nothing copied them to a disk image and nothing could exec them.
# Same shape of hole SYSTEST.ELF sat in for months.
UHELLO_DIR    := userspace/tests/uhello
UHELLO_BUILT  := $(OUT_TGT)/$(UHELLO_DIR)/$(TARGET_RISCV64_USER)/release/uhello
UHELLO_ELF    := $(OUT_BUILD)/uhello.elf
# The server half of `endpoint.demo`. A separate
# image from uhello because a ring-3 program's role on an endpoint is its
# capability permission, and permissions come from the topology row looked up
# by IMAGE NAME: one image, one row, one role. See userspace/tests/epsrv/src/main.rs.
VSSRV_DIR     := userspace/bench/vssrv
VSSRV_BUILT   := $(OUT_TGT)/$(VSSRV_DIR)/$(TARGET_RISCV64_USER)/release/vssrv
VSSRV_ELF     := $(OUT_BUILD)/vssrv.elf
EPSRV_DIR     := userspace/tests/epsrv
EPSRV_BUILT   := $(OUT_TGT)/$(EPSRV_DIR)/$(TARGET_RISCV64_USER)/release/epsrv
EPSRV_ELF     := $(OUT_BUILD)/epsrv.elf
ABICHILD_DIR   := userspace/tests/abichild
ABICHILD_BUILT := $(OUT_TGT)/$(ABICHILD_DIR)/$(TARGET_RISCV64_USER)/release/abichild
ABICHILD_ELF   := $(OUT_BUILD)/abichild.elf
REFLEX_DIR    := userspace/services/reflex
REFLEX_BUILT  := $(OUT_TGT)/$(REFLEX_DIR)/$(TARGET_RISCV64_USER)/release/reflex
REFLEX_ELF    := $(OUT_BUILD)/reflex.elf
BRAINCLI_DIR  := userspace/services/brain_client
BRAINCLI_BUILT:= $(OUT_TGT)/$(BRAINCLI_DIR)/$(TARGET_RISCV64_USER)/release/brain_client
BRAINCLI_ELF  := $(OUT_BUILD)/brain_client.elf
# captest — ring-3 capability test (positive AND negative halves).
CAPTEST_DIR   := userspace/tests/captest
CAPTEST_BUILT := $(OUT_TGT)/$(CAPTEST_DIR)/$(TARGET_RISCV64_USER)/release/captest
CAPTEST_ELF   := $(OUT_BUILD)/captest.elf
# latbench — ring-3 syscall latency microbenchmark.
# vsbench - the same ring-3 work, measured on Azos and on Linux/riscv64.
# The Linux side is NOT built here: it needs a different target and its own
# toolchain.
VSBENCH_DIR   := userspace/bench/vsbench
VSBENCH_BUILT := $(OUT_TGT)/$(VSBENCH_DIR)/$(TARGET_RISCV64_USER)/release/vsbench
VSBENCH_ELF   := $(OUT_BUILD)/vsbench.elf

LATBENCH_DIR  := userspace/bench/latbench
LATBENCH_BUILT:= $(OUT_TGT)/$(LATBENCH_DIR)/$(TARGET_RISCV64_USER)/release/latbench
LATBENCH_ELF  := $(OUT_BUILD)/latbench.elf
# abitest - syscall ABI conformance from ring 3.
ABITEST_DIR   := userspace/tests/abitest
ABITEST_BUILT := $(OUT_TGT)/$(ABITEST_DIR)/$(TARGET_RISCV64_USER)/release/abitest
ABITEST_ELF   := $(OUT_BUILD)/abitest.elf
# ipctest - ring-3 IPC probe: fast-path round trip, server impersonation, and
# the shm/port/io_ring ownership gates.
IPCTEST_DIR   := userspace/tests/ipctest
IPCTEST_BUILT := $(OUT_TGT)/$(IPCTEST_DIR)/$(TARGET_RISCV64_USER)/release/ipctest
IPCTEST_ELF   := $(OUT_BUILD)/ipctest.elf

# ── aarch64 userspace parity (phase 6 prep) ──────────────────────────────────
#
# Same 13 programs, built for `aarch64-unknown-azos` (sdk/targets, hard-float; the level is
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
# `userspace/tests/hello/Cargo.toml`).
TARGET_AARCH64 := aarch64-unknown-azos
comma := ,
# ── aarch64 translation granule of the user images ──────────────────────────
# config/arch/Kconfig.isa AARCH64_PAGE_* picks the kernel's granule; a user image
# must be linked for the same page (`-z max-page-size`: lld starts each segment
# on a page of its own at that size; the target spec's 4096 is the default
# granule's) and libsys must agree
# (`libsys::PAGE_SIZE`, from AZOS_PAGE_SIZE). The default, 4096, builds
# exactly what this Makefile always built, into the same places. Any other
# value builds into its own directories and its own digest table, which the
# kernel of that granule binds (crates/core/sched/src/seccomp.rs):
#   make AARCH64_PAGE_SIZE=16384 build/image_hashes_aarch64_16k.rs  -> build/aarch64-16k/*.elf
#   make AARCH64_PAGE_SIZE=16384 aarch64                            -> build/kernel-aarch64-16k.img
# With an aarch64 configuration it is the configuration's (CONFIG_PAGE_SHIFT).
ifeq ($(KCONFIG_ISA),aarch64)
KCONFIG_PAGE_SHIFT := $(shell sed -n 's/^CONFIG_PAGE_SHIFT=//p' '$(KCONFIG_CONFIG)')
AARCH64_PAGE_SIZE ?= $(if $(filter 14,$(KCONFIG_PAGE_SHIFT)),16384,$(if $(filter 16,$(KCONFIG_PAGE_SHIFT)),65536,4096))
endif
AARCH64_PAGE_SIZE ?= 4096
# ── aarch64 baseline of the user images ─────────────────────────────────────
# The Kconfig level and `require`d extensions (config/arch/Kconfig.isa-aarch64
# AARCH64_LEVEL, A64_*) as user codegen flags, from the expanded config the
# kernel is built from (tools/build/kconfig_to_cargo.py --user-rustflags). Armv8.0
# with nothing required (QEMU's default) emits nothing, so the default images
# and their digests are what this Makefile always built. A board's images:
#   make AARCH64_USER_KCONFIG=build/rpi5.config userspace-aarch64
AARCH64_USER_KCONFIG ?= $(OUT_BUILD)/aarch64$(if $(filter 16384,$(AARCH64_PAGE_SIZE)),-16k,$(if $(filter 65536,$(AARCH64_PAGE_SIZE)),-64k)).config
AARCH64_USER_ISA := $(if $(wildcard $(AARCH64_USER_KCONFIG)),$(shell python3 tools/build/kconfig_to_cargo.py --user-rustflags --toml $(AARCH64_USER_KCONFIG)))
ifeq ($(AARCH64_PAGE_SIZE),4096)
AARCH64_PG_SUFFIX :=
AARCH64_PG_LINK   :=
else
ifeq ($(AARCH64_PAGE_SIZE),16384)
AARCH64_PG_SUFFIX := -16k
else ifeq ($(AARCH64_PAGE_SIZE),65536)
AARCH64_PG_SUFFIX := -64k
else
$(error AARCH64_PAGE_SIZE must be 4096, 16384 or 65536 (an aarch64 translation granule))
endif
# Above 4 KiB lld starts each segment on a page of the granule (the loader maps
# an executable segment only onto a page it owns outright, W^X,
# crates/core/sched/src/process.rs); the headers and `.rodata` stay in the
# read-only segment.
AARCH64_PG_LINK   := $(comma)"-C","link-arg=-zmax-page-size=$(AARCH64_PAGE_SIZE)"
endif
AARCH64_PG_TABLE  := $(subst -,_,$(AARCH64_PG_SUFFIX))
AARCH64_UFLAGS     = --target $(USER_SPECS)/$(TARGET_AARCH64).json \
	--config 'target.$(TARGET_AARCH64).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)"$(AARCH64_PG_LINK)$(if $(AARCH64_USER_ISA),$(comma)$(AARCH64_USER_ISA))]'
AARCH64_DIR    := $(OUT_BUILD)/aarch64$(AARCH64_PG_SUFFIX)
HELLO_ELF_AARCH64     := $(AARCH64_DIR)/hello.elf
LXHELLO_ELF_AARCH64   := $(AARCH64_DIR)/lxhello.elf
SYSTEST_ELF_AARCH64   := $(AARCH64_DIR)/syscall_test.elf
GPIO_DRV_ELF_AARCH64  := $(AARCH64_DIR)/gpio_drv.elf
MLSRV_ELF_AARCH64     := $(AARCH64_DIR)/mlsrv.elf
BUZZ_DRV_ELF_AARCH64  := $(AARCH64_DIR)/buzz_drv.elf
INA_DRV_ELF_AARCH64   := $(AARCH64_DIR)/ina_drv.elf
SH_ELF_AARCH64        := $(AARCH64_DIR)/sh.elf
TERMD_ELF_AARCH64     := $(AARCH64_DIR)/termd.elf
NAMESD_ELF_AARCH64    := $(AARCH64_DIR)/namesd.elf
COMPMGR_ELF_AARCH64   := $(AARCH64_DIR)/compmgr.elf
TOOLBOX_ELF_AARCH64   := $(AARCH64_DIR)/toolbox.elf
POWER_ELF_AARCH64     := $(AARCH64_DIR)/power.elf
TRACECTL_ELF_AARCH64  := $(AARCH64_DIR)/tracectl.elf
DECISD_ELF_AARCH64 := $(AARCH64_DIR)/decisd.elf
INPUTD_ELF_AARCH64 := $(AARCH64_DIR)/inputd.elf
COMPSRV_ELF_AARCH64 := $(AARCH64_DIR)/compsrv.elf
LOGD_ELF_AARCH64      := $(AARCH64_DIR)/logd.elf
WHY_ELF_AARCH64       := $(AARCH64_DIR)/why.elf
PKGD_ELF_AARCH64      := $(AARCH64_DIR)/pkgd.elf
PKG_ELF_AARCH64       := $(AARCH64_DIR)/pkg.elf
RPCSRV_ELF_AARCH64    := $(AARCH64_DIR)/rpcsrv.elf
ZENOHD_ELF_AARCH64    := $(AARCH64_DIR)/zenohd.elf
PTPD_ELF_AARCH64    := $(AARCH64_DIR)/ptpd.elf
AUDIOD_ELF_AARCH64  := $(AARCH64_DIR)/audiod.elf
RPCQUIC_ELF_AARCH64   := $(AARCH64_DIR)/rpcquic.elf
MCPD_ELF_AARCH64      := $(AARCH64_DIR)/mcpd.elf
SSHD_ELF_AARCH64      := $(AARCH64_DIR)/sshd.elf
LOGIND_ELF_AARCH64    := $(AARCH64_DIR)/logind.elf
VMMD_ELF_AARCH64      := $(AARCH64_DIR)/vmmd.elf
LXRT_ELF_AARCH64      := $(AARCH64_DIR)/linux_rt.elf
FLIGHT_ELF_AARCH64    := $(AARCH64_DIR)/flight.elf
BEHAVIOR_ELF_AARCH64  := $(AARCH64_DIR)/behavior.elf
CONFIG_ELF_AARCH64    := $(AARCH64_DIR)/config.elf
OTA_ELF_AARCH64       := $(AARCH64_DIR)/ota.elf
FAM_ELFS_AARCH64      := $(FLIGHT_ELF_AARCH64) $(BEHAVIOR_ELF_AARCH64) $(CONFIG_ELF_AARCH64) $(OTA_ELF_AARCH64)
LXSRV_ELF_AARCH64     := $(AARCH64_DIR)/lxsrv.elf
UHELLO_ELF_AARCH64    := $(AARCH64_DIR)/uhello.elf
EPSRV_ELF_AARCH64     := $(AARCH64_DIR)/epsrv.elf
ABICHILD_ELF_AARCH64  := $(AARCH64_DIR)/abichild.elf
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
              crates/core/rings/Cargo.toml $(shell find crates/core/rings/src -name '*.rs' -not -name '* [0-9]*') \
              crates/core/ktest/Cargo.toml $(shell find crates/core/ktest/src -name '*.rs' -not -name '* [0-9]*') \
              crates/core/libsys-macros/Cargo.toml $(shell find crates/core/libsys-macros/src -name '*.rs' -not -name '* [0-9]*') \
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
# extensions set to `require` (config/arch/Kconfig.isa-riscv64 RV_ZBA/ZBB/ZBS; nothing on
# QEMU's default, so the default images and digests do not move). A board's
# images: `make RV_USER_KCONFIG=build/k1.config userspace`.
RV_USER_KCONFIG ?= $(OUT_BUILD)/qemu-dev.config
RV_USER_ISA := $(if $(wildcard $(RV_USER_KCONFIG)),$(shell python3 tools/build/kconfig_to_cargo.py --user-rustflags --toml --skip-base $(RV_USER_KCONFIG)))
# Cargo hashes the target spec's contents into every artifact's fingerprint,
# so an edit of sdk/targets/*.json relinks every image; a crate's build.rs (the
# stack an image asks for, `-z stack-size`) is tracked by cargo itself.
USPACE_BUILD := RUSTC_WRAPPER='$(CURDIR)/userspace/rustc_stable_metadata.py' $(CARGO) +nightly build --release -Zjson-target-spec
# Each ISA's target and rustflags: the wrapper's digest (above) and the Kconfig
# codegen flags. A recipe adds exactly one of RV_UFLAGS, AARCH64_UFLAGS and
# X86_64_UFLAGS after $(USPACE_BUILD).
RV_UFLAGS := --target $(USER_SPECS)/$(TARGET_RISCV64_USER).json \
	--config 'target.$(TARGET_RISCV64_USER).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)"$(if $(RV_USER_ISA),$(comma)$(RV_USER_ISA))]'

# ── The native SDK (plan phase 6, item 2) ───────────────────────────────────
# A Rust `std` program for `<isa>-unknown-azos` (sdk/targets): `std` is built
# from the pinned toolchain's library source plus the port in sdk/std, which
# calls crates/core/stdrt (tools/build/sdk_std.py assembles that tree). The program
# is built by tools/build/sdk_cargo.py, which takes the ISA baseline and the runtime's
# knobs (the ring-3 allocator, the default thread stack) from the expanded
# Kconfig named here and nothing else, and goes through the metadata wrapper
# above like every ring-3 ELF. One target directory per ISA (and granule) holds
# the std build every SDK program shares.
#   make sdk                    every SDK program, on the three ISAs
#   make sdk-check              stdrt type-checks on the three ISAs; its host tests
SDK_TARGET_DIR := $(OUT_BUILD)/sdk/target
SDK_SRC := $(shell find sdk -type f -not -name '* [0-9]*') tools/build/sdk_std.py tools/build/sdk_cargo.py \
           crates/core/stdrt/Cargo.toml $(shell find crates/core/stdrt/src -name '*.rs' -not -name '* [0-9]*') \
           crates/core/libsys/src/pure.rs crates/core/abi/Cargo.toml \
           $(shell find crates/core/abi/src -name '*.rs' -not -name '* [0-9]*') \
           userspace/lib/ualloc/Cargo.toml $(shell find userspace/lib/ualloc/src -name '*.rs' -not -name '* [0-9]*') \
           userspace/rustc_stable_metadata.py
SDK_BUILD_riscv64 = $(PYTHON) tools/build/sdk_cargo.py --isa riscv64 --kconfig $(RV_USER_KCONFIG) --target-dir $(SDK_TARGET_DIR) -- build --release
SDK_BUILD_aarch64 = $(PYTHON) tools/build/sdk_cargo.py --isa aarch64 --kconfig $(AARCH64_USER_KCONFIG) --page-size $(AARCH64_PAGE_SIZE) --target-dir $(SDK_TARGET_DIR)$(AARCH64_PG_SUFFIX) -- build --release
SDK_BUILD_x86_64  = $(PYTHON) tools/build/sdk_cargo.py --isa x86_64 --kconfig $(X86_64_KCONFIG) --target-dir $(SDK_TARGET_DIR) -- build --release
SDK_OUT_riscv64   = $(SDK_TARGET_DIR)/riscv64imac-unknown-azos/release
SDK_OUT_aarch64   = $(SDK_TARGET_DIR)$(AARCH64_PG_SUFFIX)/aarch64-unknown-azos/release
SDK_OUT_x86_64    = $(SDK_TARGET_DIR)/x86_64-unknown-azos/release

# VisionFive 2 configuration (Phase 10)
# Override these from the command line as needed:
#   make vf2 VF2_SERIAL=/dev/tty.usbserial-XXXX
#   make flash-vf2 VF2_SD=/dev/disk4
VF2_SERIAL  ?= /dev/ttyUSB0
VF2_SD      ?= /dev/sdb       # SD card device on Linux; use diskN on macOS
VF2_BAUD    ?= 115200

# VF2 kernel ELF (built with vf2 feature + vf2 linker script)
VF2_LINKER   := arch/riscv64/boot/linker-vf2.ld
VF2_RUSTFLAGS := -C link-arg=-T$(VF2_LINKER)
VF2_ELF      := $(OUT_TARGET)/$(RISCV64_TARGET)/release/kernel-vf2
VF2_BIN      = $(OUT_BUILD)/kernel-vf2$(VF2_SUFFIX).bin
# Where cargo builds the board kernel. The farm's targets use target/farm: a
# board kernel built with other features must not replace the `release/kernel`
# the gate's QEMU rows boot.
VF2_TARGET_DIR ?= $(OUT_TARGET)

# SpacemiT K1 (BananaPi BPI-F3) configuration (Phase B)
# Override from command line as needed:
#   make k1 K1_SERIAL=/dev/tty.usbserial-XXXX
#   make flash-k1 K1_SD=/dev/disk5
K1_SERIAL  ?= /dev/ttyUSB0
K1_SD      ?= /dev/sdb       # SD card device on Linux; use diskN on macOS
K1_BAUD    ?= 115200

# K1 kernel ELF (built with k1 feature + k1 linker script)
# K1 has native RVV 1.0 (VLEN=256) — k1 feature enables RVV code paths.
K1_LINKER   := arch/riscv64/boot/linker-k1.ld
# ISA extensions the K1 has and the VF2 does not.
#
# The SpacemiT X60 is an RVA22 part (`config/defconfigs/robot-sbc-riscv64+k1.config`: rv64gcv), and RVA22
# mandates Zba, Zbb and Zbs. So the compiler may use them everywhere in a K1
# build — address arithmetic, bit counting, the scheduler's ready-bitmap pick —
# not only in hand-written `asm!`.
#
# **Only the K1.** The VF2's JH7110 is rv64gc (SiFive U74, `config/defconfigs/robot-sbc-riscv64+vf2.config`):
# it has none of these, and a binary carrying them dies with an illegal
# instruction on its first one. Both binaries are called `kernel`, so nothing but
# a check stops one reaching the wrong board — `tools/gate/ci_check.sh` disassembles
# the VF2 and QEMU kernels and fails if any of these instructions is present.
#
# NOT the way to reach an extension that only SOME target has: that is a runtime
# probe with a scalar fallback (`arch/riscv64/src/cache.rs` for Zicboz). This
# is for extensions the board is known to have at build time.
#
# The flags come from the Kconfig (config/arch/Kconfig.isa-riscv64: the K1's RV_ZBA/ZBB/ZBS
# default to `require`) through tools/build/kconfig_to_cargo.py --rustflags, the one
# emitter every kernel rule uses; crates/core/limits/build.rs refuses a kernel
# build whose target features disagree with its Kconfig.
K1_RUSTFLAGS := -C link-arg=-T$(K1_LINKER)
K1_BIN      := $(OUT_BUILD)/kernel-k1.bin

# RVV: QEMU CPU model with Vector 1.0 extension (VLEN=128).
# Used by qemu-rvv and qemu-full-smp-rvv targets.
# K1 uses VLEN=256 natively (not QEMU emulated).
QEMU_RVV_CPU := rv64,v=true,vlen=128,vext_spec=v1.0

# Fleet profile: gateway boards with ≥ 1 GiB RAM.
# Static tables + 256 MiB heap don't fit the default 8 MiB linker.
# linker-fleet.ld carves a 1022 MiB RAM region above OpenSBI.
FLEET_LINKER   := arch/riscv64/boot/linker-fleet.ld
FLEET_RUSTFLAGS := -C link-arg=-T$(FLEET_LINKER)

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
              EPSRV.ELF=$(EPSRV_ELF) ABICHILD.ELF=$(ABICHILD_ELF) VSSRV.ELF=$(VSSRV_ELF) \
              REFLEX.ELF=$(REFLEX_ELF) BRAINCLI.ELF=$(BRAINCLI_ELF) \
              CAPTEST.ELF=$(CAPTEST_ELF) LATBENCH.ELF=$(LATBENCH_ELF) \
              ABITEST.ELF=$(ABITEST_ELF) IPCTEST.ELF=$(IPCTEST_ELF) \
              VSBENCH.ELF=$(VSBENCH_ELF) \
              BUZZDRV.ELF=$(BUZZ_DRV_ELF) INADRV.ELF=$(INA_DRV_ELF) \
              COMPMGR.ELF=$(COMPMGR_ELF) SH.ELF=$(SH_ELF) TERMD.ELF=$(TERMD_ELF) NAMESD.ELF=$(NAMESD_ELF) TOOLBOX.ELF=$(TOOLBOX_ELF) POWER.ELF=$(POWER_ELF) \
              FLIGHT.ELF=$(FLIGHT_ELF) BEHAVIOR.ELF=$(BEHAVIOR_ELF) \
              CONFIG.ELF=$(CONFIG_ELF) OTA.ELF=$(OTA_ELF) \
              TRACECTL.ELF=$(TRACECTL_ELF) DECISD.ELF=$(DECISD_ELF) INPUTD.ELF=$(INPUTD_ELF) COMPSRV.ELF=$(COMPSRV_ELF) LOGD.ELF=$(LOGD_ELF) WHY.ELF=$(WHY_ELF) \
              PKGD.ELF=$(PKGD_ELF) PKG.ELF=$(PKG_ELF) RPCSRV.ELF=$(RPCSRV_ELF) ZENOHD.ELF=$(ZENOHD_ELF) PTPD.ELF=$(PTPD_ELF) AUDIOD.ELF=$(AUDIOD_ELF) RPCQUIC.ELF=$(RPCQUIC_ELF) MCPD.ELF=$(MCPD_ELF) SSHD.ELF=$(SSHD_ELF) LOGIND.ELF=$(LOGIND_ELF) VMMD.ELF=$(VMMD_ELF) \
              LXSRV.ELF=$(LXSRV_ELF) \
              LXHELLO.ELF=$(LXHELLO_ELF)
IMAGE_HASHES := $(OUT_BUILD)/image_hashes.rs

# The BOARD volume's ML service, and the image-hash table its kernel binds
# (wave 11 BOARDIMG; the key rules are with TOPOLOGY_KEY_STAMP below). Only the
# MLSRV.ELF row differs from IMAGE_ELFS: the board table lists the digest of
# the named-key service, never of the QEMU test-key one, so a board kernel
# refuses to run a QEMU-built `mlsrv`. `build/disk-board.img`'s manifest
# resolves its names through IMAGE_ELFS_BOARD, and `vf2`/`k1`/`build-fleet`
# build their kernel with `--features board-image` (azos_sched), which
# `include!`s IMAGE_HASHES_BOARD instead of IMAGE_HASHES.
BOARD_DIR := $(OUT_BUILD)/board
# What the signed-topology emitter reads (wave 15 TOPOSIGN; its targets are
# near the end of this file, with the rest of the topology rules).
TOPO_EMIT_DEPS := tests/host/topology-tests/src/bin/topo_emit.rs tests/host/topology-tests/Cargo.toml \
	crates/core/topology/build.rs crates/core/topology/Cargo.toml kernel/Cargo.toml \
	$(shell find crates/core/topology/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*')
MLSRV_ELF_BOARD := $(BOARD_DIR)/mlsrv.elf
PKGD_ELF_BOARD := $(BOARD_DIR)/pkgd.elf
IMAGE_ELFS_BOARD := $(patsubst PKGD.ELF=%,PKGD.ELF=$(PKGD_ELF_BOARD),$(patsubst MLSRV.ELF=%,MLSRV.ELF=$(MLSRV_ELF_BOARD),$(IMAGE_ELFS)))
IMAGE_HASHES_BOARD := $(BOARD_DIR)/image_hashes.rs

# The .config decides the kernel's features (wave 11, F5): Kconfig is the
# only source. A kernel recipe builds `-p azos_kernel` with what
# tools/build/kconfig_to_cargo.py prints for its configuration; what a target builds
# beyond it (a smoke, a driver) is a selection, `--select` (`kernel_select`
# below), applied to a copy of the configuration that the build then reads, so
# the constants azos_limits generates agree with the features. No recipe names
# a feature itself (tools/lint/feature_source_lint.py). `-p azos_kernel`, here and
# in every kernel recipe below: without it cargo builds every workspace
# member, and a Generic build then compiled the robot crates anyway
# (crates/domains/robot/*, as members), with none of the features the kernel would
# have given them.
#
# The development QEMU kernels (`build`, `build-rvv`, `build-pci` and the
# `qemu-*` smoke targets) build from `$(QEMU_DEV_KCONFIG)`: the `.config`
# with the kernel log level set to QEMU_LOG_LEVEL, debug by default, so a
# dev boot prints every line (its rule is next to the Kconfig targets). A
# product build (`vf2`, `k1`, `build-fleet`, the profiles' defconfigs) keeps
# its profile's level, warn. `make qemu QEMU_LOG_LEVEL=warn` boots what ships.
QEMU_DEV_KCONFIG := $(OUT_BUILD)/qemu-dev.config
QEMU_DEV_ENV      = KCONFIG_CONFIG="$(QEMU_DEV_KCONFIG)"
QEMU_DEV_ARGS     = $$(python3 tools/build/kconfig_to_cargo.py $(QEMU_DEV_KCONFIG))
# `$(call kernel_select,<config>,<selection>,<copy>)`: a recipe line that
# writes <copy> (<config> with the selection applied) and leaves its cargo
# arguments in `$$args`; the build that follows reads KCONFIG_CONFIG=<copy>.
kernel_select = args="$$(python3 tools/build/kconfig_to_cargo.py --select '$(2)' --out '$(3)' '$(1)')" || exit 1
#
# `QEMU_DEV_ISA`: the Kconfig's riscv64 codegen beyond .cargo/config.toml's
# baseline (RV_ZBA/ZBB/ZBS set to `require`), merged into the target's
# rustflags; empty on the default config.
QEMU_DEV_ISA = rf="$$(python3 tools/build/kconfig_to_cargo.py --rustflags --toml --skip-base $(QEMU_DEV_KCONFIG))"; \
	isa=""; [ -z "$$rf" ] || isa="target.$(RISCV64_TARGET).rustflags=[$$rf]";
# BUILD_TYPE for the vf2 targets (the farm's board image): `make vf2
# BUILD_TYPE=DEV` is a development image. Unset or RELEASE is the product
# build, byte for byte what it was: no test key, the fleet key required.
# DEV builds from a vf2 config with CONFIG_BUILD_TYPE_DEV=y (Kconfig BUILD_TYPE:
# crates/core/topology/build.rs then accepts the TEST key, and KTEST may be
# on), signs the board volume with the TEST pair unless TOPOLOGY_PUBKEY_PATH /
# TOPOLOGY_PRIVKEY_PATH name another, and tools/sign/check_board_keys.py runs with
# --allow-test. Nothing else changes: the TEST key is a build-type decision,
# never a fallback. DEV is refused for every goal but the vf2 ones and `rpi5`
# (`make rpi5 BUILD_TYPE=DEV`: the bring-up image, see mk/kernel.mk).
#   VF2_TEST=ktest   (`make vf2-ktest`)   DEV + CONFIG_KTEST: the farm's test kernel
#   VF2_TEST=pstore  (`make vf2-pstore`)  DEV + a pstore region + the pstore smoke
# Each variant has its own expanded config, kernel and volume
# (build/vf2-<variant>.config, kernel-vf2-<variant>.bin, disk-board-<variant>.img).
BUILD_TYPE ?=
ifneq ($(filter-out DEV RELEASE,$(BUILD_TYPE)),)
$(error BUILD_TYPE is DEV or RELEASE (unset is RELEASE), got "$(BUILD_TYPE)")
endif
BOARD_DEV := $(filter DEV,$(BUILD_TYPE))
VF2_GOALS := vf2 vf2-ktest vf2-pstore flash-vf2
DEV_GOALS := $(VF2_GOALS) rpi5
VF2_TEST ?=
ifneq ($(filter-out ktest pstore,$(VF2_TEST)),)
$(error VF2_TEST is ktest or pstore (make vf2-ktest / vf2-pstore), got "$(VF2_TEST)")
endif
ifneq ($(VF2_TEST),)
ifeq ($(BOARD_DEV),)
$(error VF2_TEST=$(VF2_TEST) needs BUILD_TYPE=DEV)
endif
endif
ifneq ($(BOARD_DEV),)
ifneq ($(filter-out $(DEV_GOALS),$(or $(MAKECMDGOALS),all)),)
$(error BUILD_TYPE=DEV is for the board targets $(DEV_GOALS) only, not: $(filter-out $(DEV_GOALS),$(or $(MAKECMDGOALS),all)))
endif
TOPOLOGY_PUBKEY_PATH ?= tools/keys/test_pub.bin
TOPOLOGY_PRIVKEY_PATH ?= tools/keys/test_priv.bin
endif
VF2_VARIANT := $(if $(BOARD_DEV),$(or $(VF2_TEST),dev))
VF2_SUFFIX := $(if $(VF2_VARIANT),-$(VF2_VARIANT))
VF2_KCONFIG := $(OUT_BUILD)/vf2$(VF2_SUFFIX).config
VF2_DISK := $(OUT_BUILD)/disk-board$(VF2_SUFFIX).img
BOARD_KEYCHECK := python3 tools/sign/check_board_keys.py$(if $(BOARD_DEV), --allow-test)

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
	@$(BOARD_KEYCHECK) key "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_pub.bin || { echo "[$(1)] refusing: a board image is a BUILD_TYPE_RELEASE build and BUILD_TYPE_RELEASE refuses the TEST signing key; TOPOLOGY_PUBKEY_PATH names the TEST key (tools/keys/test_pub.bin or a copy of it). Name the fleet's own public key, or build the vf2 development image with BUILD_TYPE=DEV."; exit 1; }
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
	@$(BOARD_KEYCHECK) pair "$(BOARD_SIGN_PRIV)" "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_priv.bin tools/keys/test_pub.bin || { echo "[$(1)] refusing: TOPOLOGY_PRIVKEY_PATH does not match TOPOLOGY_PUBKEY_PATH, or is the test key."; exit 1; }
endef
define check_board_priv_if_given
	@[ -z "$(BOARD_SIGN_PRIV)" ] || $(BOARD_KEYCHECK) pair "$(BOARD_SIGN_PRIV)" "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_priv.bin tools/keys/test_pub.bin || { echo "[$(1)] refusing: TOPOLOGY_PRIVKEY_PATH does not match TOPOLOGY_PUBKEY_PATH, or is the test key."; exit 1; }
endef

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
              EPSRV.ELF=$(EPSRV_ELF_AARCH64) ABICHILD.ELF=$(ABICHILD_ELF_AARCH64) VSSRV.ELF=$(VSSRV_ELF_AARCH64) \
              REFLEX.ELF=$(REFLEX_ELF_AARCH64) BRAINCLI.ELF=$(BRAINCLI_ELF_AARCH64) \
              CAPTEST.ELF=$(CAPTEST_ELF_AARCH64) LATBENCH.ELF=$(LATBENCH_ELF_AARCH64) \
              ABITEST.ELF=$(ABITEST_ELF_AARCH64) IPCTEST.ELF=$(IPCTEST_ELF_AARCH64) \
              VSBENCH.ELF=$(VSBENCH_ELF_AARCH64) \
              BUZZDRV.ELF=$(BUZZ_DRV_ELF_AARCH64) INADRV.ELF=$(INA_DRV_ELF_AARCH64) \
              COMPMGR.ELF=$(COMPMGR_ELF_AARCH64) SH.ELF=$(SH_ELF_AARCH64) TERMD.ELF=$(TERMD_ELF_AARCH64) NAMESD.ELF=$(NAMESD_ELF_AARCH64) TOOLBOX.ELF=$(TOOLBOX_ELF_AARCH64) POWER.ELF=$(POWER_ELF_AARCH64) \
              FLIGHT.ELF=$(FLIGHT_ELF_AARCH64) BEHAVIOR.ELF=$(BEHAVIOR_ELF_AARCH64) \
              CONFIG.ELF=$(CONFIG_ELF_AARCH64) OTA.ELF=$(OTA_ELF_AARCH64) \
              TRACECTL.ELF=$(TRACECTL_ELF_AARCH64) DECISD.ELF=$(DECISD_ELF_AARCH64) INPUTD.ELF=$(INPUTD_ELF_AARCH64) COMPSRV.ELF=$(COMPSRV_ELF_AARCH64) LOGD.ELF=$(LOGD_ELF_AARCH64) WHY.ELF=$(WHY_ELF_AARCH64) \
              PKGD.ELF=$(PKGD_ELF_AARCH64) PKG.ELF=$(PKG_ELF_AARCH64) RPCSRV.ELF=$(RPCSRV_ELF_AARCH64) ZENOHD.ELF=$(ZENOHD_ELF_AARCH64) PTPD.ELF=$(PTPD_ELF_AARCH64) AUDIOD.ELF=$(AUDIOD_ELF_AARCH64) RPCQUIC.ELF=$(RPCQUIC_ELF_AARCH64) MCPD.ELF=$(MCPD_ELF_AARCH64) SSHD.ELF=$(SSHD_ELF_AARCH64) LOGIND.ELF=$(LOGIND_ELF_AARCH64) VMMD.ELF=$(VMMD_ELF_AARCH64) \
              LXSRV.ELF=$(LXSRV_ELF_AARCH64) \
              LXHELLO.ELF=$(LXHELLO_ELF_AARCH64)
IMAGE_HASHES_AARCH64 := $(OUT_BUILD)/image_hashes_aarch64$(AARCH64_PG_TABLE).rs

# ── aarch64 kernel (QEMU virt) ───────────────────────────────────────────────
# The aarch64 kernel `make build` builds with an aarch64 configuration (the
# internal `aarch64` target). Three things differ from RISC-V, and each is
# here on purpose:
#
#  * Its own expanded configuration. AARCH64_DEFCONFIG (the .config at
#    QEMU_LOG_LEVEL with an aarch64 .config, else config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+gui.config)
#    is expanded by olddefconfig into build/aarch64.config and handed to the
#    build via KCONFIG_CONFIG; the user images read the same file.
#  * The linker script goes on the command line, as `make vf2` / `make k1` do,
#    NOT in .cargo/config.toml like RISC-V's: cargo merges that file into every
#    config below it, and the aarch64 userspace builds carry their own `-T`
#    for the same triple — they would
#    receive a second script and stop linking.
#  * The output is an arm64 `Image` (header in kernel/src/entry/aarch64/asm/
#    boot.S), not the ELF: for an ELF, QEMU passes x0 = 0 and puts no DTB in
#    RAM (measured 2026-09-21); for an Image it passes the DTB in x0, which is
#    also the protocol U-Boot `booti` uses on real boards.
#  * Soft-float target: the kernel names no FP/SIMD register outside the
#    lazy user-FP save/restore (kernel/src/entry/aarch64/fp_lazy.rs,
#    tools/lint/aarch64_fp_free_check.sh). Userspace stays `aarch64-unknown-none`
#    (TARGET_AARCH64 above).
AARCH64_TARGET   := aarch64-unknown-none-softfloat
AARCH64_LINKER   := arch/aarch64/boot/linker-aarch64.ld
AARCH64_KCONFIG  := $(OUT_BUILD)/aarch64$(AARCH64_PG_SUFFIX).config
# `make aarch64 AARCH64_DEFCONFIG=<file> AARCH64_KCONFIG=<expanded> AARCH64_IMG=<image> ...` builds another
# configuration beside the default one (`make azos-guest`, the x86_64 `X86_64_DEFCONFIG` shape).
# With an aarch64 configuration it is that configuration (`make build`).
ifeq ($(KCONFIG_ISA),aarch64)
AARCH64_DEFCONFIG ?= $(QEMU_DEV_KCONFIG)
endif
AARCH64_DEFCONFIG ?= config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+gui.config
# A non-default granule builds in its own target directory: switching granule
# rebuilds every crate (azos_arch_api's PAGE_SIZE is a feature), and the
# 4 KiB kernel's artifacts should survive it.
ifeq ($(AARCH64_PAGE_SIZE),4096)
AARCH64_KTARGET_ENV :=
AARCH64_ELF      := $(OUT_TARGET)/$(AARCH64_TARGET)/release/kernel
else
AARCH64_KTARGET_ENV := CARGO_TARGET_DIR="$(OUT_TARGET)/aarch64$(AARCH64_PG_SUFFIX)"
AARCH64_ELF      := $(OUT_TARGET)/aarch64$(AARCH64_PG_SUFFIX)/$(AARCH64_TARGET)/release/kernel
endif
AARCH64_IMG      := $(OUT_BUILD)/kernel-aarch64$(AARCH64_PG_SUFFIX).img
# rustc's own llvm-objcopy (rustup component llvm-tools), the one the gate uses.
AARCH64_OBJCOPY   = $(shell rustc --print sysroot)/lib/rustlib/$(shell rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy
QEMU_AARCH64_KERNEL_FLAGS := -cpu max,pauth=on -smp 2 -nographic

# ── x86_64: build and boot (QEMU microvm, PVH) ─────────────────────────────
# With an x86_64 configuration `make build` builds the kernel ELF (the internal
# `x86_64` target) and `make qemu` boots it on `-M microvm` (PVH entry via
# -kernel, COM1 on stdio, isa-debug-exit so a stop ends QEMU with a status).
# X86_64_SELECT is a selection on the configuration (`make x86_64
# X86_64_SELECT=ktest`, tools/build/kconfig_to_cargo.py --select).
# X86_64_DEFCONFIG / X86_64_KCONFIG (a path relative to the tree) build from
# another configuration into its own expanded file, so the default one never
# goes stale under it (a build from a configuration of its own).
X86_64_SELECT ?=
# With an x86_64 configuration it is that configuration (`make build`).
ifeq ($(KCONFIG_ISA),x86_64)
X86_64_DEFCONFIG ?= $(QEMU_DEV_KCONFIG)
endif
X86_64_DEFCONFIG ?= config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+gui.config
X86_64_KCONFIG ?= $(OUT_BUILD)/x86_64.config
# Where cargo builds this kernel: the Limine variant has its own directory so
# the two never rebuild each other (RUSTFLAGS differ in the linker script).
X86_64_TARGET_DIR ?= $(OUT_TARGET)
X86_64_TARGET  := x86_64-unknown-none
X86_64_ELF     := $(X86_64_TARGET_DIR)/$(X86_64_TARGET)/release/kernel
X86_64_IMG     := $(OUT_BUILD)/kernel-x86_64.elf
X86_64_LINKER  := arch/x86_64/boot/linker-x86_64.ld
# curve25519-dalek picks its AVX2 "simd" backend on x86_64; the kernel is
# soft-float (no SSE/AVX state at CPL0), so it takes the portable one. So do
# the ring-3 images (X86_64_UFLAGS), as on riscv64 and aarch64: the AVX2
# double-base multiply of a signature check reserves 3,696 B realigned to 32
# bytes, and put sshd's deepest chain at 17,000 B of its 16 KiB stack
# (tools/lint/stack_frames.py reads realigned frames since 2026-10-24).
X86_64_DALEK   := --cfg curve25519_dalek_backend=\"serial\"
# -cpu max: the default model (qemu64) is below the x86-64-v2 baseline, and the
# kernel refuses it (the canary: `make qemu QEMU_X86_64_CPU=qemu64`, x86_64 configured).
QEMU_X86_64_CPU ?= max
QEMU_X86_64_FLAGS := -M microvm -cpu $(QEMU_X86_64_CPU) -nographic -no-reboot \
	-device isa-debug-exit,iobase=0xf4,iosize=0x04

# ── x86_64 userspace ────────────────────────────────────────────────────────
#
# The ring-3 programs for `sdk/targets/x86_64-unknown-azos.json`, into
# `build/x86_64/`, bound by their own digest table
# (`build/image_hashes_x86_64.rs`, which crates/core/sched/src/seccomp.rs
# `include!`s on x86_64), exactly as the aarch64 set is. The target is
# the hard-float System V ABI (SSE/SSE2, as every x86-64 CPU has; the kernel
# alone is soft-float) in the small code model: a JSON spec, because rustc's
# `x86_64-unknown-none` is soft-float. The spec carries the layout and the
# entry (`_azos_entry`, libsys: it realigns the stack and calls `_start`); the
# baseline (Kconfig X86_64_LEVEL and every `require`d extension, the SIMD ones
# included) comes from the kernel's own expanded config through
# `kconfig_to_cargo.py --user-rustflags`, at recipe time, so an image is
# always built for the level the kernel refuses CPUs below.
#
# HELLO.ELF is `userspace/tests/hello`, the Rust stand-in aarch64 also uses
# for riscv64's hand-assembled `hello.S` (its binary keeps the crate's
# `hello_aarch64` name). Not in the set yet: syscall_test (aarch64-only),
# latbench (it reads the raw counter and converts it at the vDSO's
# TIMER_FREQ; on x86_64 that counter is the TSC, at its own rate),
# captest (board RTC/IRQ fixtures) and lxsrv (the Linux personality's
# register layout is aarch64/riscv64 only).
TARGET_X86_64 := x86_64-unknown-azos
X86_64_DIR    := $(OUT_BUILD)/x86_64
X86_64_UFLAGS  = --target $(USER_SPECS)/$(TARGET_X86_64).json \
	--config 'target.$(TARGET_X86_64).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)","--cfg=curve25519_dalek_backend=\"serial\"",'"$$(python3 $(CURDIR)/tools/build/kconfig_to_cargo.py --user-rustflags --toml $(X86_64_KCONFIG))"']'
X86_64_UBUILT := $(TARGET_X86_64)/release
HELLO_ELF_X86_64     := $(X86_64_DIR)/hello.elf
SYSTEST_ELF_X86_64   := $(X86_64_DIR)/syscall_test.elf
UHELLO_ELF_X86_64    := $(X86_64_DIR)/uhello.elf
EPSRV_ELF_X86_64     := $(X86_64_DIR)/epsrv.elf
ABICHILD_ELF_X86_64  := $(X86_64_DIR)/abichild.elf
REFLEX_ELF_X86_64    := $(X86_64_DIR)/reflex.elf
BRAINCLI_ELF_X86_64  := $(X86_64_DIR)/brain_client.elf
ABITEST_ELF_X86_64   := $(X86_64_DIR)/abitest.elf
IPCTEST_ELF_X86_64   := $(X86_64_DIR)/ipctest.elf
CAPTEST_ELF_X86_64   := $(X86_64_DIR)/captest.elf
LATBENCH_ELF_X86_64  := $(X86_64_DIR)/latbench.elf
GPIO_DRV_ELF_X86_64  := $(X86_64_DIR)/gpio_drv.elf
BUZZ_DRV_ELF_X86_64  := $(X86_64_DIR)/buzz_drv.elf
INA_DRV_ELF_X86_64   := $(X86_64_DIR)/ina_drv.elf
MLSRV_ELF_X86_64     := $(X86_64_DIR)/mlsrv.elf
SH_ELF_X86_64        := $(X86_64_DIR)/sh.elf
TERMD_ELF_X86_64     := $(X86_64_DIR)/termd.elf
NAMESD_ELF_X86_64    := $(X86_64_DIR)/namesd.elf
COMPMGR_ELF_X86_64   := $(X86_64_DIR)/compmgr.elf
TOOLBOX_ELF_X86_64   := $(X86_64_DIR)/toolbox.elf
POWER_ELF_X86_64     := $(X86_64_DIR)/power.elf
TRACECTL_ELF_X86_64  := $(X86_64_DIR)/tracectl.elf
DECISD_ELF_X86_64 := $(X86_64_DIR)/decisd.elf
INPUTD_ELF_X86_64 := $(X86_64_DIR)/inputd.elf
COMPSRV_ELF_X86_64 := $(X86_64_DIR)/compsrv.elf
LOGD_ELF_X86_64      := $(X86_64_DIR)/logd.elf
WHY_ELF_X86_64       := $(X86_64_DIR)/why.elf
PKGD_ELF_X86_64      := $(X86_64_DIR)/pkgd.elf
PKG_ELF_X86_64       := $(X86_64_DIR)/pkg.elf
RPCSRV_ELF_X86_64    := $(X86_64_DIR)/rpcsrv.elf
ZENOHD_ELF_X86_64    := $(X86_64_DIR)/zenohd.elf
PTPD_ELF_X86_64    := $(X86_64_DIR)/ptpd.elf
AUDIOD_ELF_X86_64  := $(X86_64_DIR)/audiod.elf
RPCQUIC_ELF_X86_64   := $(X86_64_DIR)/rpcquic.elf
MCPD_ELF_X86_64      := $(X86_64_DIR)/mcpd.elf
SSHD_ELF_X86_64      := $(X86_64_DIR)/sshd.elf
LOGIND_ELF_X86_64    := $(X86_64_DIR)/logind.elf
VMMD_ELF_X86_64      := $(X86_64_DIR)/vmmd.elf
FLIGHT_ELF_X86_64    := $(X86_64_DIR)/flight.elf
BEHAVIOR_ELF_X86_64  := $(X86_64_DIR)/behavior.elf
CONFIG_ELF_X86_64    := $(X86_64_DIR)/config.elf
OTA_ELF_X86_64       := $(X86_64_DIR)/ota.elf
VSBENCH_ELF_X86_64   := $(X86_64_DIR)/vsbench.elf
VSSRV_ELF_X86_64     := $(X86_64_DIR)/vssrv.elf
LXSRV_ELF_X86_64     := $(X86_64_DIR)/lxsrv.elf
LXHELLO_ELF_X86_64   := $(X86_64_DIR)/lxhello.elf
# The Linux runtime the x86_64 kernel embeds (Kconfig LINUX_RUNTIME), as
# LXRT_ELF is for riscv64: a prerequisite of the image-hash table, not a disk
# image. `yes` when the x86_64 configuration asks for it (the generated
# configuration may not exist yet when this is read: its defconfig counts too).
LXRT_ELF_X86_64      := $(X86_64_DIR)/linux_rt.elf
LXRT_NEED_X86_64      = $(shell grep -qs '^CONFIG_LINUX_RUNTIME=y' $(X86_64_KCONFIG) $(X86_64_DEFCONFIG) </dev/null && echo yes)
IMAGE_ELFS_X86_64 := HELLO.ELF=$(HELLO_ELF_X86_64) SYSTEST.ELF=$(SYSTEST_ELF_X86_64) UHELLO.ELF=$(UHELLO_ELF_X86_64) EPSRV.ELF=$(EPSRV_ELF_X86_64) ABICHILD.ELF=$(ABICHILD_ELF_X86_64) \
              REFLEX.ELF=$(REFLEX_ELF_X86_64) BRAINCLI.ELF=$(BRAINCLI_ELF_X86_64) \
              ABITEST.ELF=$(ABITEST_ELF_X86_64) IPCTEST.ELF=$(IPCTEST_ELF_X86_64) \
              CAPTEST.ELF=$(CAPTEST_ELF_X86_64) LATBENCH.ELF=$(LATBENCH_ELF_X86_64) \
              GPIODRV.ELF=$(GPIO_DRV_ELF_X86_64) BUZZDRV.ELF=$(BUZZ_DRV_ELF_X86_64) INADRV.ELF=$(INA_DRV_ELF_X86_64) \
              MLSRV.ELF=$(MLSRV_ELF_X86_64) \
              SH.ELF=$(SH_ELF_X86_64) TERMD.ELF=$(TERMD_ELF_X86_64) NAMESD.ELF=$(NAMESD_ELF_X86_64) COMPMGR.ELF=$(COMPMGR_ELF_X86_64) TOOLBOX.ELF=$(TOOLBOX_ELF_X86_64) POWER.ELF=$(POWER_ELF_X86_64) \
              TRACECTL.ELF=$(TRACECTL_ELF_X86_64) DECISD.ELF=$(DECISD_ELF_X86_64) INPUTD.ELF=$(INPUTD_ELF_X86_64) COMPSRV.ELF=$(COMPSRV_ELF_X86_64) LOGD.ELF=$(LOGD_ELF_X86_64) WHY.ELF=$(WHY_ELF_X86_64) \
              PKGD.ELF=$(PKGD_ELF_X86_64) PKG.ELF=$(PKG_ELF_X86_64) RPCSRV.ELF=$(RPCSRV_ELF_X86_64) ZENOHD.ELF=$(ZENOHD_ELF_X86_64) PTPD.ELF=$(PTPD_ELF_X86_64) AUDIOD.ELF=$(AUDIOD_ELF_X86_64) RPCQUIC.ELF=$(RPCQUIC_ELF_X86_64) MCPD.ELF=$(MCPD_ELF_X86_64) SSHD.ELF=$(SSHD_ELF_X86_64) LOGIND.ELF=$(LOGIND_ELF_X86_64) VMMD.ELF=$(VMMD_ELF_X86_64) \
              FLIGHT.ELF=$(FLIGHT_ELF_X86_64) BEHAVIOR.ELF=$(BEHAVIOR_ELF_X86_64) \
              CONFIG.ELF=$(CONFIG_ELF_X86_64) OTA.ELF=$(OTA_ELF_X86_64) \
              VSBENCH.ELF=$(VSBENCH_ELF_X86_64) VSSRV.ELF=$(VSSRV_ELF_X86_64) \
              LXSRV.ELF=$(LXSRV_ELF_X86_64) \
              LXHELLO.ELF=$(LXHELLO_ELF_X86_64)
IMAGE_ELF_PATHS_X86_64 := $(foreach e,$(IMAGE_ELFS_X86_64),$(lastword $(subst =, ,$(e))))
IMAGE_HASHES_X86_64 := $(OUT_BUILD)/image_hashes_x86_64.rs

# ── The configured system: `make build`, `make qemu` ────────────────────────
# `make build` builds the ISA $(KCONFIG_CONFIG) selects (KCONFIG_ISA, at the
# top): the kernel, the ring-3 images and the system volume, from the
# configuration expanded at QEMU_LOG_LEVEL (QEMU_DEV_KCONFIG, then the ISA's
# own expansion), and prints where they are. `make qemu` boots that kernel.
#   SYSTEM_KCONFIG  the expanded configuration the kernel and the images read
#   SYSTEM_KERNEL   the internal target that builds the kernel (mk/kernel.mk)
#   SYSTEM_VOLUME   the system volume: the shell volume, which carries the
#                   console program (Kconfig CONSOLE_PROGRAM) and every image
#                   the topology starts, and names no autorun image
#   TARGET          the kernel's target triple
#   USER_TARGET     the ring-3 images' and the SDK's (sdk/targets/<it>.json)
#   KERNEL_ELF      the kernel ELF cargo writes
#   KERNEL_IMAGE    what QEMU loads: the ELF, or on aarch64 the arm64 Image
#   SDK_BUILD       how a std program is built for it (sdk/README.md)
SYSTEM_KCONFIG_riscv64 := $(QEMU_DEV_KCONFIG)
SYSTEM_KCONFIG_aarch64 := $(AARCH64_KCONFIG)
SYSTEM_KCONFIG_x86_64  := $(X86_64_KCONFIG)
SYSTEM_VOLUME_riscv64  := $(OUT_BUILD)/disk-sh.img
SYSTEM_VOLUME_aarch64  := $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-sh.img
SYSTEM_VOLUME_x86_64   := $(OUT_BUILD)/disk-x86_64.img
TARGET_riscv64         := $(RISCV64_TARGET)
TARGET_aarch64         := $(AARCH64_TARGET)
TARGET_x86_64          := $(X86_64_TARGET)
USER_TARGET_riscv64    := $(TARGET_RISCV64_USER)
USER_TARGET_aarch64    := $(TARGET_AARCH64)
USER_TARGET_x86_64     := $(TARGET_X86_64)
KERNEL_ELF_riscv64     := $(RISCV64_KERNEL_ELF)
KERNEL_ELF_aarch64     := $(AARCH64_ELF)
KERNEL_ELF_x86_64      := $(X86_64_ELF)
KERNEL_IMAGE_riscv64   := $(RISCV64_KERNEL_ELF)
KERNEL_IMAGE_aarch64   := $(AARCH64_IMG)
KERNEL_IMAGE_x86_64    := $(X86_64_IMG)

SYSTEM_KCONFIG := $(SYSTEM_KCONFIG_$(KCONFIG_ISA))
SYSTEM_KERNEL  := $(KCONFIG_ISA)
SYSTEM_VOLUME  := $(SYSTEM_VOLUME_$(KCONFIG_ISA))
TARGET         := $(TARGET_$(KCONFIG_ISA))
USER_TARGET    := $(USER_TARGET_$(KCONFIG_ISA))
KERNEL_ELF     := $(KERNEL_ELF_$(KCONFIG_ISA))
KERNEL_IMAGE   := $(KERNEL_IMAGE_$(KCONFIG_ISA))
SDK_BUILD       = $(SDK_BUILD_$(KCONFIG_ISA))

# `make qemu`: the machine of each ISA, the gate's (tools/gate/ci_check.sh
# `ushell_row`), with the RAM the configuration expects (Kconfig RAM_SIZE) and
# the system volume on virtio-blk, so boot ends in the console program, not in
# the recovery console. It boots a copy of the volume (QEMU_VOLUME): a boot
# writes to it (BOOTMETA, logs), and each `make qemu` starts from what `make
# build` made. TCG on every host, Apple silicon included. QEMU_AARCH64_MACHINE
# with `virtualization=on` enters the kernel at EL2 (`make qemu-aarch64-el2`).
QEMU_AARCH64_MACHINE ?= virt,gic-version=3
QEMU_VOLUME := $(OUT_BUILD)/qemu-$(KCONFIG_ISA).img
QEMU_RAM     = $(shell sed -n 's/^CONFIG_RAM_SIZE=//p' '$(SYSTEM_KCONFIG)')M
QEMU_BLK     = -drive file=$(QEMU_VOLUME),if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0
QEMU_SYSTEM_riscv64 = $(QEMU) $(QEMU_FLAGS) -smp 4 -m $(QEMU_RAM) -global virtio-mmio.force-legacy=false \
	$(QEMU_BLK) -device virtio-rng-device -kernel $(KERNEL_IMAGE)
QEMU_SYSTEM_aarch64 = qemu-system-aarch64 -M $(QEMU_AARCH64_MACHINE) $(QEMU_AARCH64_KERNEL_FLAGS) -m $(QEMU_RAM) \
	-global virtio-mmio.force-legacy=false $(QEMU_BLK) -device virtio-rng-device -kernel $(KERNEL_IMAGE)
QEMU_SYSTEM_x86_64  = qemu-system-x86_64 $(QEMU_X86_64_FLAGS) -m $(QEMU_RAM) $(QEMU_BLK) -kernel $(KERNEL_IMAGE) \
	$(if $(QEMU_X86_64_UCODE),-initrd $(QEMU_X86_64_UCODE))

# The goals that build or boot the riscv64 kernel only (the variants of
# `build` and `qemu` above it in `make help`); with another ISA configured they
# would boot a kernel `make build` did not build, so they refuse.
RISCV64_ONLY_GOALS := build-rvv build-pci build-nvme qemu-smp qemu-full-smp qemu-rvv qemu-full-smp-rvv \
	qemu-gdb qemu-pci qemu-nvme qemu-systest qemu-dhcp-smoke qemu-net-pair
AARCH64_ONLY_GOALS := qemu-aarch64-el2
ifneq ($(KCONFIG_ISA),riscv64)
ifneq ($(filter $(RISCV64_ONLY_GOALS),$(MAKECMDGOALS)),)
$(error $(filter $(RISCV64_ONLY_GOALS),$(MAKECMDGOALS)): riscv64 only, and $(KCONFIG_CONFIG) selects $(KCONFIG_ISA))
endif
endif
ifneq ($(KCONFIG_ISA),aarch64)
ifneq ($(filter $(AARCH64_ONLY_GOALS),$(MAKECMDGOALS)),)
$(error $(filter $(AARCH64_ONLY_GOALS),$(MAKECMDGOALS)): aarch64 only, and $(KCONFIG_CONFIG) selects $(KCONFIG_ISA))
endif
endif
