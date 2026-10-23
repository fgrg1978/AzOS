# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# User space: the ring-3 ELF rules on the three ISAs, the SDK, the Linux
# personality binaries and modules (lxhello, kbuild), BusyBox, relibc.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# ── The module loader's test module and digest table ────
#
# LXTEST.KO is a relocatable object (ET_REL, the shape of a Linux `.ko`)
# compiled from our own C (`userspace/tests/lxmod/lxtest.c`, Apache-2.0 OR
# GPL-2.0-only, no Linux header), so the loader, `DOMAIN_MODULE_VERIFY` and the
# token-gated `DOMAIN_MODULE_MAP_X` run end to end with no GPL object in any
# image (stage L1, the first Linux object, needs the owner's sign-off).
# `-mno-relax`/`-mcmodel=medany` (riscv64), `-mgeneral-regs-only` (aarch64)
# and `-mno-red-zone -mgeneral-regs-only` (x86_64) are the only flags the
# loader accepts.
#
# The kernel binds each module to the SHA-256 of these exact bytes
# (`build/module_hashes*.rs`, `include!`d under the `lx-loader` feature only).
# The default kernel neither includes the table nor has the two syscalls.
LX_CC ?= /opt/homebrew/opt/llvm/bin/clang
LXMOD_SRC := userspace/tests/lxmod/lxtest.c
LXMOD_CFLAGS := -ffreestanding -fno-pic -fno-common -fno-builtin -nostdinc -O2 \
                -Wall -Wextra -Werror
LXTEST_KO := $(OUT_BUILD)/lx/lxtest-riscv64.ko
LXTEST_KO_AARCH64 := $(OUT_BUILD)/lx/lxtest-aarch64.ko
LXTEST_KO_X86_64 := $(OUT_BUILD)/lx/lxtest-x86_64.ko
MODULE_HASHES := $(OUT_BUILD)/module_hashes.rs
MODULE_HASHES_AARCH64 := $(OUT_BUILD)/module_hashes_aarch64.rs

$(LXTEST_KO): $(LXMOD_SRC)
	@mkdir -p $(OUT_BUILD)/lx
	$(LX_CC) --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
		-mcmodel=medany -mno-relax $(LXMOD_CFLAGS) -c $< -o $@

$(LXTEST_KO_AARCH64): $(LXMOD_SRC)
	@mkdir -p $(OUT_BUILD)/lx
	$(LX_CC) --target=aarch64-unknown-elf -mgeneral-regs-only -mcmodel=small \
		$(LXMOD_CFLAGS) -c $< -o $@

# x86_64: Linux's module flags (no red zone, no FP/SIMD state, no unwind
# tables) with the small code model a ring-3 server's low region can hold.
$(LXTEST_KO_X86_64): $(LXMOD_SRC)
	@mkdir -p $(OUT_BUILD)/lx
	$(LX_CC) --target=x86_64-unknown-elf -mcmodel=small -mno-red-zone -mgeneral-regs-only \
		-fno-asynchronous-unwind-tables $(LXMOD_CFLAGS) -c $< -o $@

# The Linux modules, built by Linux's own Kbuild against the
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
LX_KBUILD_DIR := $(OUT_BUILD)/lx/kbuild
# A third-party tree's pinned upstream tag (.gitmodules), by name; the Linux
# release is the Linux tree's, without its `v`.
tp_tag = $(shell git config -f .gitmodules submodule.third_party/$(1).tag)
LX_LINUX_RELEASE := $(patsubst v%,%,$(call tp_tag,linux))
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
	@rc=0; tools/lx_kbuild/run.sh build $(OUT_BUILD)/lx/kbuild-repro > /dev/null || rc=$$?; \
	if [ $$rc -eq 3 ]; then tools/lx_kbuild/run.sh check; exit 0; elif [ $$rc -ne 0 ]; then exit $$rc; fi; \
	diff $(LX_KBUILD_DIR)/SHA256SUMS $(OUT_BUILD)/lx/kbuild-repro/SHA256SUMS && \
	echo "lx-kbuild-repro: two clean builds, identical .ko and fixture hashes"

$(MODULE_HASHES): tools/module_hashes.py $(LXTEST_KO) $(LX_KO_RV)
	python3 tools/module_hashes.py $@ LXTEST.KO=$(LXTEST_KO) --skip-missing \
		LXBASE.KO=$(LX_KBUILD_DIR)/riscv64/lxbase.ko XZ_DEC.KO=$(LX_KBUILD_DIR)/riscv64/xz_dec.ko

$(MODULE_HASHES_AARCH64): tools/module_hashes.py $(LXTEST_KO_AARCH64) $(LX_KO_A64)
	python3 tools/module_hashes.py $@ LXTEST.KO=$(LXTEST_KO_AARCH64) --skip-missing \
		LXBASE.KO=$(LX_KBUILD_DIR)/aarch64/lxbase.ko XZ_DEC.KO=$(LX_KBUILD_DIR)/aarch64/xz_dec.ko

.PHONY: lx-modules
lx-modules: $(MODULE_HASHES) $(MODULE_HASHES_AARCH64) $(LXTEST_KO_X86_64)

userspace: $(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF) \
           $(UHELLO_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) \
           $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) $(VSBENCH_ELF) \
           $(EPSRV_ELF) $(ABICHILD_ELF) $(VSSRV_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) \
           $(SH_ELF) $(TERMD_ELF) $(NAMESD_ELF) $(COMPMGR_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(TRACECTL_ELF) $(DECISD_ELF) $(INPUTD_ELF) $(COMPSRV_ELF) $(LOGD_ELF) $(WHY_ELF) $(PKGD_ELF) $(PKG_ELF) $(RPCSRV_ELF) $(ZENOHD_ELF) $(VMMD_ELF) $(PTPD_ELF) $(AUDIOD_ELF) $(RPCQUIC_ELF) $(MCPD_ELF) $(SSHD_ELF) $(LOGIND_ELF) $(FAM_ELFS) $(LXSRV_ELF) $(LXHELLO_ELF)

# E11.AQ3 ring-3 driver — Rust no_std ELF, for the riscv64 target spec
# ($(RV_UFLAGS), sdk/targets: the layout too, no linker script).  The output
# is copied (not stripped) into build/gpio_drv.elf for the disk image to pick up.
$(GPIO_DRV_ELF): $(GPIO_DRV_DIR)/src/main.rs $(GPIO_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(GPIO_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(GPIO_DRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(GPIO_DRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# The topology/config key the ring-3 inference service verifies POLICY.SIG and
# the model bundles with (`azos_topology::TRUSTED_PUBKEY`). `crates/core/topology/build.rs` has
# no default any more: it embeds the file TOPOLOGY_PUBKEY_PATH names, or, built
# `--features dev-key`, the TEST key (tools/keys/test_pub.bin).
#
# TWO ML services, never one (wave 11 BOARDIMG): QEMU disks and the board
# volume used to share `build/mlsrv.elf` and one image-hash table, so
# `DEV_KEYS=1` shipped a test-key service to a board and a named key left the
# QEMU disks' test-signed BEHAVIOR.MBL unverifiable.
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
TOPOLOGY_KEY_STAMP := $(OUT_BUILD)/topology_key.stamp
TOPOLOGY_KEY_CHOICE := dev-key
.PHONY: FORCE
FORCE:
$(TOPOLOGY_KEY_STAMP): FORCE
	@mkdir -p $(OUT_BUILD)
	@[ "$$(cat $@ 2>/dev/null)" = "$(TOPOLOGY_KEY_CHOICE)" ] || printf '%s\n' "$(TOPOLOGY_KEY_CHOICE)" > $@

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

# The inference service (MLSRV.ELF, userspace/services/infsrv) links
# userspace/lib/ml (the GGUF engine and bundle reader), the
# interface crates of the Infer endpoint and the decision records, as well as
# libsys; cargo does not see through to make, so those sources are
# prerequisites here.
MLSRV_DEPS := $(wildcard $(MLSRV_DIR)/src/*.rs) $(MLSRV_DIR)/Cargo.toml $(MLSRV_DIR)/build.rs \
              $(shell find userspace/lib/ml/src userspace/lib/decisions/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
              userspace/lib/ml/Cargo.toml userspace/lib/decisions/Cargo.toml $(LIBSYS_SRC) \
              $(shell find crates/core/topology/src crates/core/limits/src crates/core/devif/src crates/core/idl/src crates/core/decision/src crates/core/rings/src crates/core/crypto/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
              crates/core/topology/Cargo.toml crates/core/topology/build.rs crates/core/limits/Cargo.toml \
              crates/core/devif/Cargo.toml crates/core/idl/Cargo.toml crates/core/decision/Cargo.toml \
              crates/core/rings/Cargo.toml crates/core/crypto/Cargo.toml \
              crates/core/limits/build.rs $(KCONFIG_FILES) $(wildcard .config) $(wildcard tools/keys/test_pub.bin)
$(MLSRV_ELF): $(MLSRV_DEPS) $(TOPOLOGY_KEY_STAMP)
	@mkdir -p $(OUT_BUILD)
	cd $(MLSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MLSRV_DIR)" && $(MLSRV_QEMU_BUILD) $(RV_UFLAGS) $(MLSRV_KEY_FEATURES)
	cp $(MLSRV_BUILT) $@

# The package installer reads the signed topology with the same key, so the same
# two builds: the QEMU one with `dev-key`, the board one with the named key
# (`build/board/pkgd.elf`, hashed into the board's image table). It is a std
# program (it fetches over TLS, userspace/lib/tls): built like the relay of the
# QUIC link below, by tools/sdk_cargo.py on the vendored tree, in the same target
# directory as the probe. The key choice reaches build.rs through the
# environment as for the ML service: the QEMU build must not see
# TOPOLOGY_PUBKEY_PATH, the board build exactly the named key.
PKGD_DEPS := $(wildcard $(PKGD_DIR)/src/*.rs) $(PKGD_DIR)/Cargo.toml $(PKGD_DIR)/Cargo.lock $(PACKAGES_LIB_SRC) $(TLS_LIB_SRC) $(LIBSYS_SRC) $(SDK_SRC) third_party/VENDOR_PIN \
              $(shell find crates/core/topology/src crates/core/limits/src crates/core/decision/src crates/core/devif/src crates/core/idl/src crates/net/tftp/src userspace/lib/names/src userspace/lib/decisions/src userspace/lib/term/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
              crates/core/topology/Cargo.toml crates/core/topology/build.rs crates/core/limits/Cargo.toml \
              crates/core/limits/build.rs $(KCONFIG_FILES) $(wildcard .config) $(wildcard tools/keys/test_pub.bin)
PKGD_CARGO = --vendored -- build --release --manifest-path $(PKGD_DIR)/Cargo.toml
$(PKGD_ELF): $(PKGD_DEPS) $(TOPOLOGY_KEY_STAMP) $(RV_USER_KCONFIG)
	@mkdir -p $(OUT_BUILD)
	env -u TOPOLOGY_PUBKEY_PATH $(PYTHON) tools/sdk_cargo.py --isa riscv64 --kconfig $(RV_USER_KCONFIG) --target-dir $(TLSPROBE_TGT) $(PKGD_CARGO) $(MLSRV_KEY_FEATURES)
	cp $(TLSPROBE_TGT)/riscv64imac-unknown-azos/release/pkgd $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PKGD_ELF_BOARD): $(PKGD_DEPS) $(BOARD_KEY_STAMP) $(RV_USER_KCONFIG)
	$(call require_board_key,BOARD-PKGD)
	@mkdir -p $(BOARD_DIR)
	env TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" $(PYTHON) tools/sdk_cargo.py --isa riscv64 --kconfig $(RV_USER_KCONFIG) --target-dir $(TLSPROBE_TGT) $(PKGD_CARGO)
	cp $(TLSPROBE_TGT)/riscv64imac-unknown-azos/release/pkgd $@
	$(BOARD_KEYCHECK) elf "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_pub.bin $@

# The board volume's ML service: the same crate, the named key, no `dev-key`.
# Built and copied in one recipe because the crate's target dir is shared with
# the QEMU build above (cargo's fingerprint rebuilds on the env/feature change).
$(MLSRV_ELF_BOARD): $(MLSRV_DEPS) $(BOARD_KEY_STAMP)
	$(call require_board_key,BOARD-MLSRV)
	@mkdir -p $(BOARD_DIR)
	cd $(MLSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MLSRV_DIR)" && $(MLSRV_BOARD_BUILD) $(RV_UFLAGS)
	cp $(MLSRV_BUILT) $@
	$(BOARD_KEYCHECK) elf "$(BOARD_TOPOLOGY_KEY)" tools/keys/test_pub.bin $@

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
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(BUZZ_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(BUZZ_DRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	python3 tools/chip_source_check.py buzzer $(BUZZ_DRV_BUILT)
	cp $(BUZZ_DRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(INA_DRV_ELF): $(INA_DRV_DIR)/src/main.rs $(INA219_CHIP_SRC) $(INA_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(INA_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(INA_DRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	python3 tools/chip_source_check.py ina219 $(INA_DRV_BUILT)
	cp $(INA_DRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# The user shell and its tool image.
$(SH_ELF): $(SH_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(SH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SH_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(SH_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TERMD_ELF): $(TERMD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(TERMD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TERMD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(TERMD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(NAMESD_ELF): $(NAMESD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(NAMESD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(NAMESD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(NAMESD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(COMPMGR_ELF): $(COMPMGR_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(COMPMGR_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(COMPMGR_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(COMPMGR_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TOOLBOX_ELF): $(TOOLBOX_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(TOOLBOX_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TOOLBOX_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	$(AARCH64_OBJCOPY) --strip-all $(TOOLBOX_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(POWER_ELF): $(POWER_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(POWER_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(POWER_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(POWER_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TRACECTL_ELF): $(TRACECTL_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(TRACECTL_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TRACECTL_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(TRACECTL_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(DECISD_ELF): $(DECISD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(DECISD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(DECISD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(DECISD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(INPUTD_ELF): $(INPUTD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(INPUTD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(INPUTD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(INPUTD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(COMPSRV_ELF): $(COMPSRV_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(COMPSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(COMPSRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(COMPSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LOGD_ELF): $(LOGD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(LOGD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LOGD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(LOGD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(WHY_ELF): $(WHY_SRC) $(SDK_SRC) $(LIBSYS_SRC) $(RV_USER_KCONFIG)
	@mkdir -p $(OUT_BUILD)
	$(SDK_BUILD_riscv64) --manifest-path $(WHY_DIR)/Cargo.toml
	cp $(SDK_OUT_riscv64)/why $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PKG_ELF): $(PKG_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(PKG_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(PKG_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(PKG_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(RPCSRV_ELF): $(RPCSRV_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(RPCSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(RPCSRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(RPCSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ZENOHD_ELF): $(ZENOHD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(ZENOHD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ZENOHD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(ZENOHD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PTPD_ELF): $(PTPD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(PTPD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(PTPD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(PTPD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(AUDIOD_ELF): $(AUDIOD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(AUDIOD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(AUDIOD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(AUDIOD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(MCPD_ELF): $(MCPD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(MCPD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MCPD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(MCPD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SSHD_ELF): $(SSHD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(SSHD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SSHD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(SSHD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LOGIND_ELF): $(LOGIND_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(LOGIND_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LOGIND_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(LOGIND_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VMMD_ELF): $(VMMD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(VMMD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VMMD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(VMMD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LXRT_ELF): $(LXRT_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(LXRT_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LXRT_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(LXRT_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Wave 12: one binary of the family-tools crate per image.
$(FLIGHT_ELF): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS) --bin flight
	cp $(FAMTOOLS_OUT)/flight $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BEHAVIOR_ELF): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS) --bin behavior
	cp $(FAMTOOLS_OUT)/behavior $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CONFIG_ELF): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS) --bin config
	cp $(FAMTOOLS_OUT)/config $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OTA_ELF): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS) --bin ota
	cp $(FAMTOOLS_OUT)/ota $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LXSRV_ELF): $(LXSRV_SRC) $(LIBSYS_SRC) .gitmodules
	@mkdir -p $(OUT_BUILD)
	cd $(LXSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LXSRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(LXSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Same standalone pattern as gpio_drv: one crate, one image, the target spec
# and userspace/.cargo/config.toml (build-std) for every one.
$(UHELLO_ELF): $(UHELLO_DIR)/src/main.rs $(UHELLO_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(UHELLO_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(UHELLO_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(UHELLO_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(EPSRV_ELF): $(EPSRV_DIR)/src/main.rs $(EPSRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(EPSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(EPSRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(EPSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ABICHILD_ELF): $(ABICHILD_DIR)/src/main.rs $(ABICHILD_DIR)/src/shared.rs $(ABICHILD_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(ABICHILD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ABICHILD_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(ABICHILD_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Depends on vsbench's `serve.rs` as well as its own source: the loop is
# pulled in with `#[path]` and cargo does not track that as a dependency.
$(VSSRV_ELF): $(VSSRV_DIR)/src/main.rs $(VSSRV_DIR)/Cargo.toml \
               userspace/bench/vsbench/src/serve.rs userspace/bench/vsbench/src/ipc_proto.rs $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(VSSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VSSRV_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(VSSRV_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(REFLEX_ELF): $(REFLEX_DIR)/src/main.rs $(REFLEX_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(REFLEX_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(REFLEX_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(REFLEX_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BRAINCLI_ELF): $(BRAINCLI_DIR)/src/main.rs $(BRAINCLI_DIR)/src/link.rs $(BRAINCLI_DIR)/Cargo.toml \
               crates/core/crypto/src/secure_channel.rs \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(BRAINCLI_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(BRAINCLI_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(BRAINCLI_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CAPTEST_ELF): $(CAPTEST_DIR)/src/main.rs $(CAPTEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(CAPTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(CAPTEST_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(CAPTEST_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Extra vsbench cargo features (wave 15: its canaries, e.g.
# `VSBENCH_FEATURES=switch-peer-canary`; tools/vsbench_compare.sh passes its
# VSBENCH_BENCH_FEATURES here). The stamp holds the set the ELFs were built
# with and changes only when the set does, so a canary ELF can never be
# reused by a later default build.
VSBENCH_FEATURES ?=
# The disk copies of VSBENCH.ELF are STRIPPED (N0, wave 15): about 60 KiB
# of the unstripped file was `.symtab`/`.strtab`, which no loader reads, and
# the autorun loader stages every byte of the file. The loaded segments are
# byte-identical; the symbols stay in the cargo target.
VSBENCH_FEATURES_ARG := $(if $(strip $(VSBENCH_FEATURES)),$(comma)$(strip $(VSBENCH_FEATURES)))
$(OUT_BUILD)/vsbench.features: FORCE
	@mkdir -p $(OUT_BUILD)
	@printf '%s\n' '$(strip $(VSBENCH_FEATURES))' | cmp -s - $@ \
	    || printf '%s\n' '$(strip $(VSBENCH_FEATURES))' >$@

$(VSBENCH_ELF): $(VSBENCH_DIR)/src/main.rs $(VSBENCH_DIR)/src/bench_core.rs $(VSBENCH_DIR)/src/ipc_proto.rs \
               $(VSBENCH_DIR)/src/abi_azos.rs $(VSBENCH_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(OUT_BUILD)/vsbench.features
	@mkdir -p $(OUT_BUILD)
	cd $(VSBENCH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VSBENCH_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS) --features azos$(VSBENCH_FEATURES_ARG)
	$(AARCH64_OBJCOPY) --strip-all $(VSBENCH_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LATBENCH_ELF): $(LATBENCH_DIR)/src/main.rs $(LATBENCH_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(LATBENCH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LATBENCH_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(LATBENCH_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ABITEST_ELF): $(ABITEST_DIR)/src/main.rs $(ABICHILD_DIR)/src/shared.rs $(ABITEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(ABITEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ABITEST_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(ABITEST_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(IPCTEST_ELF): $(IPCTEST_DIR)/src/main.rs $(IPCTEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(OUT_BUILD)
	cd $(IPCTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(IPCTEST_DIR)" && $(USPACE_BUILD) $(RV_UFLAGS)
	cp $(IPCTEST_BUILT) $@
	@echo "[USPACE] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# ── The Linux personality's test binary ──────────────────────────
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
	@mkdir -p $(OUT_BUILD)
	$(LX_CC) --target=riscv64-unknown-linux-musl -march=rv64imac -mabi=lp64 -mno-relax $(LX_CFLAGS) \
		-c $< -o $(OUT_BUILD)/lxhello.o
	$(LX_LLD) -flavor gnu -static -e _start -z max-page-size=4096 -o $@ $(OUT_BUILD)/lxhello.o
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

# x86_64: its own program (lxhello_x86_64.c): Linux's x86-64 numbers and
# registers differ from the asm-generic ones the file above is written in, and
# the stage it runs is the ring-3 runtime's (`lxhello rt`). The image keeps the
# name LXHELLO.ELF: the same topology row, the same shell command.
$(LXHELLO_ELF_X86_64): $(LXHELLO_DIR)/lxhello_x86_64.c
	@mkdir -p $(X86_64_DIR)
	$(LX_CC) --target=x86_64-unknown-linux-musl $(LX_CFLAGS) -c $< -o $(X86_64_DIR)/lxhello.o
	$(LX_LLD) -flavor gnu -static -e _start -z max-page-size=4096 -o $@ $(X86_64_DIR)/lxhello.o
	@echo "[USPACE-X86_64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes, static Linux ELF)"

# ── Third-party GPL userspace: BusyBox ──────────────
# Built only when the .config sets CONFIG_BUSYBOX=y (which needs
# CONFIG_USERSPACE_GPL and CONFIG_LINUX_ABI); never part of the base image,
# never committed, never fetched by make. The source is the gitlink
# third_party/busybox (.gitmodules: its upstream tag), checked out by
# `tools/third_party_fetch.sh busybox`; each ISA builds from a copy of it
# (the checkout stays pristine) under BUSYBOX_WORK (outside the repository),
# with `zig cc` (musl and the Linux uapi headers bundled; tools/busybox_cc.sh),
# host tools with the system clang, from allnoconfig plus
# userspace/thirdparty/busybox.fragment, static. All three ISAs; riscv64 is
# rv64gc/lp64d (the kernel keeps a Linux task's F/D state). The digests go to
# build/thirdparty_hashes{,_aarch64,_x86_64}.rs (empty without a build),
# which bind BUSYBOX.ELF to its row in crates/core/sched/src/seccomp.rs.
# GPL-2.0-only: `make busybox-source-offer` writes the written offer.
BUSYBOX_SRC      := third_party/busybox
BUSYBOX_URL      := $(shell git config -f .gitmodules submodule.$(BUSYBOX_SRC).url)
BUSYBOX_TAG      := $(call tp_tag,busybox)
BUSYBOX_COMMIT   := $(shell git ls-files -s $(BUSYBOX_SRC) | awk '$$1 == "160000" { print $$2 }')
BUSYBOX_VERSION  := $(subst _,.,$(BUSYBOX_TAG))
BUSYBOX_WORK     ?= $(HOME)/azos-tools/build/busybox-$(BUSYBOX_VERSION)
BUSYBOX_ZIG      ?= $(or $(LX_ZIG),$(firstword $(wildcard /opt/homebrew/bin/zig /usr/local/bin/zig) zig))
BUSYBOX_HOSTCC   ?= /usr/bin/clang
BUSYBOX_FRAGMENT := userspace/thirdparty/busybox.fragment
BUSYBOX_ISAS     := riscv64 aarch64 x86_64
BUSYBOX_ELF_RISCV64 := $(BUSYBOX_WORK)/busybox-riscv64.elf
BUSYBOX_ELF_AARCH64 := $(BUSYBOX_WORK)/busybox-aarch64.elf
BUSYBOX_ELF_X86_64  := $(BUSYBOX_WORK)/busybox-x86_64.elf
BUSYBOX_OFFER    := $(BUSYBOX_WORK)/BUSYBOX-SOURCE-OFFER.txt
# What the ELFs are built from, by content: the pinned commit and the digests
# of the fragment and the compiler wrapper, rewritten only when one of them
# changes. BUSYBOX_WORK is outside the tree and shared by every worktree, so
# the ELFs must not follow a checkout's mtimes: a fresh worktree's fragment
# is newer than every ELF built before it, and every build there that reads
# the ELFs (the digest tables, the volumes) would rebuild them.
BUSYBOX_INPUTS_STAMP := $(BUSYBOX_WORK)/source.inputs
BUSYBOX_CONFIG_FILE := $(or $(KCONFIG_CONFIG),.config)
BUSYBOX_ON := $(shell grep -qs '^CONFIG_BUSYBOX=y' $(BUSYBOX_CONFIG_FILE) && echo y)
THIRDPARTY_HASHES := $(OUT_BUILD)/thirdparty_hashes.rs
THIRDPARTY_HASHES_AARCH64 := $(OUT_BUILD)/thirdparty_hashes_aarch64.rs
THIRDPARTY_HASHES_X86_64 := $(OUT_BUILD)/thirdparty_hashes_x86_64.rs

.PHONY: busybox busybox-check busybox-one busybox-source-offer thirdparty-hashes
busybox-check:
	@grep -q '^CONFIG_BUSYBOX=y' $(BUSYBOX_CONFIG_FILE) || { \
	  echo "busybox: CONFIG_BUSYBOX is not set in $(BUSYBOX_CONFIG_FILE) (needs USERSPACE_GPL and LINUX_ABI; default off)"; exit 1; }
	@command -v $(BUSYBOX_ZIG) >/dev/null 2>&1 || { \
	  echo "busybox: no zig ($(BUSYBOX_ZIG)): install zig (Homebrew: zig) or set LX_ZIG=<path>"; exit 1; }
	@[ -n "$(BUSYBOX_COMMIT)" ] || { echo "busybox: $(BUSYBOX_SRC) is not a gitlink"; exit 1; }
	@[ -e $(BUSYBOX_SRC)/.git ] && [ "$$(git -C $(BUSYBOX_SRC) rev-parse HEAD)" = "$(BUSYBOX_COMMIT)" ] \
	  && [ -z "$$(git -C $(BUSYBOX_SRC) status --porcelain --untracked-files=no)" ] || { \
	  echo "busybox: $(BUSYBOX_SRC) is not a clean checkout of $(BUSYBOX_COMMIT): run tools/third_party_fetch.sh busybox (make never downloads)"; exit 1; }

$(BUSYBOX_INPUTS_STAMP): FORCE
	@mkdir -p $(BUSYBOX_WORK)
	@{ echo '$(BUSYBOX_COMMIT)'; shasum -a 256 $(BUSYBOX_FRAGMENT) tools/busybox_cc.sh | cut -c1-64; } >$@.$$$$ \
	  && { cmp -s $@.$$$$ $@ && rm -f $@.$$$$ || mv -f $@.$$$$ $@; }

# One ISA: busybox-one ISA=<riscv64|aarch64|x86_64>.
busybox-one:
	@case " $(BUSYBOX_ISAS) " in *" $(ISA) "*) ;; *) echo "busybox-one: ISA must be one of $(BUSYBOX_ISAS)"; exit 1;; esac
	rm -rf $(BUSYBOX_WORK)/$(ISA)/src && mkdir -p $(BUSYBOX_WORK)/$(ISA)/src
	rsync -a --exclude .git $(BUSYBOX_SRC)/ $(BUSYBOX_WORK)/$(ISA)/src/
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

# Rebuilt only when the pin, the fragment or the compiler wrapper changes:
# BusyBox stamps its build date into the binary, so a rebuild is a new digest
# (and every kernel built against the old table would refuse it). Only a
# configuration with CONFIG_BUSYBOX builds them: in any other one an ELF a
# BusyBox build left is read as it is (the digest tables bind those bytes),
# and the rebuild, which busybox-check would refuse there, is never tried.
ifeq ($(BUSYBOX_ON),y)
$(BUSYBOX_WORK)/busybox-%.elf: $(BUSYBOX_INPUTS_STAMP)
	$(MAKE) busybox-check
	$(MAKE) busybox-one ISA=$*
endif

busybox: busybox-check $(BUSYBOX_ELF_RISCV64) $(BUSYBOX_ELF_AARCH64) $(BUSYBOX_ELF_X86_64)
	$(MAKE) busybox-source-offer thirdparty-hashes

# The third-party digest tables: BUSYBOX.ELF when it was built, empty otherwise.
# Written with every image-hash table, and again by `make busybox`.
thirdparty-hashes:
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(THIRDPARTY_HASHES) \
		BUSYBOX.ELF=$(BUSYBOX_ELF_RISCV64) LXTHR.ELF=$(LXTHR_ELF_RISCV64)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(THIRDPARTY_HASHES_AARCH64) \
		BUSYBOX.ELF=$(BUSYBOX_ELF_AARCH64) LXTHR.ELF=$(LXTHR_ELF_AARCH64)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(THIRDPARTY_HASHES_X86_64) BUSYBOX.ELF=$(BUSYBOX_ELF_X86_64)

# ── Wave 13 (THREADS): LXTHR.ELF, pthreads under the Linux personality ──────
# Our own C (userspace/tests/lxthreads/lxthreads.c, Apache-2.0 OR
# GPL-2.0-only) linked statically with musl (MIT) by `zig cc`, both ISAs.
# Built only by `make lxthreads`, which needs zig and fetches nothing; like
# BusyBox it is not part of the base image, and its digests join BusyBox's in
# build/thirdparty_hashes{,_aarch64}.rs (empty without a build), binding
# LXTHR.ELF to its row in crates/core/sched/src/seccomp.rs.
LXTHR_SRC         := userspace/tests/lxthreads/lxthreads.c
LXTHR_ELF_RISCV64 := $(OUT_BUILD)/lxthreads/lxthr-riscv64.elf
LXTHR_ELF_AARCH64 := $(OUT_BUILD)/lxthreads/lxthr-aarch64.elf
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

# ── C on the native ABI: relibc (Redox's libc, MIT; plan decision D12) ───────
# relibc is the porting layer for C code, not the native model: POSIX is a
# personality here (userspace/lib/relibc-azos). `make relibc` builds the pinned
# relibc (the gitlink third_party/relibc, checked out by
# `tools/third_party_fetch.sh relibc`; make never downloads) with the patch and
# the `azos` platform module of userspace/lib/relibc-azos, then the C programs
# of userspace/tests/relibc (every .c there) against it with `zig cc`, into
# build/relibc/<isa>/. Kconfig RELIBC (config/axes/Kconfig.libc) decides it per ISA:
# each ISA is built only when ITS configuration (RELIBC_KCONFIG_<isa>, the one
# its userspace is built from) sets CONFIG_RELIBC=y. The codegen baseline of each
# ISA is the one its userspace images use (Kconfig, tools/kconfig_to_cargo.py
# --user-rustflags). The ELFs are checked for the loader's page rules
# (tools/elf_page_perms.py); they are not in an image or a topology yet: the
# kernel runs an image only when a seccomp row binds its digest. The build is the
# only compile check of the platform layer. Needs zig and cbindgen
# (tools/relibc_build.sh).
RELIBC_SRC   ?= $(CURDIR)/third_party/relibc
RELIBC_ZIG   ?= $(BUSYBOX_ZIG)
RELIBC_ISAS  := riscv64 aarch64 x86_64
RELIBC_PROGS := $(basename $(notdir $(wildcard userspace/tests/relibc/*.c)))
RELIBC_KCONFIG_riscv64 = $(RV_USER_KCONFIG)
RELIBC_KCONFIG_aarch64 = $(AARCH64_USER_KCONFIG)
RELIBC_KCONFIG_x86_64  = $(X86_64_KCONFIG)
RELIBC_TOML_riscv64 = $(if $(wildcard $(RV_USER_KCONFIG)),$(shell python3 tools/kconfig_to_cargo.py --user-rustflags --toml --skip-base $(RV_USER_KCONFIG)))
RELIBC_TOML_aarch64 = $(AARCH64_USER_ISA)
RELIBC_TOML_x86_64  = $(if $(wildcard $(X86_64_KCONFIG)),$(shell python3 tools/kconfig_to_cargo.py --user-rustflags --toml $(X86_64_KCONFIG)))
# An aarch64 image of another granule (AARCH64_PAGE_SIZE) goes to its own directory.
RELIBC_OUT_riscv64 := $(OUT_BUILD)/relibc
RELIBC_OUT_x86_64  := $(OUT_BUILD)/relibc
RELIBC_OUT_aarch64 := $(OUT_BUILD)/relibc$(AARCH64_PG_SUFFIX)
RELIBC_RUN = RELIBC_SRC='$(RELIBC_SRC)' RELIBC_ZIG='$(RELIBC_ZIG)' RELIBC_OUT='$(RELIBC_OUT_$(ISA))' bash tools/relibc_build.sh

.PHONY: relibc relibc-check relibc-one
relibc-check:
	@command -v $(RELIBC_ZIG) >/dev/null 2>&1 || { \
	  echo "relibc: no zig ($(RELIBC_ZIG)): install zig (Homebrew: zig) or set LX_ZIG=<path>"; exit 1; }
	@[ -e '$(RELIBC_SRC)/.git' ] || { \
	  echo "relibc: no checkout at $(RELIBC_SRC): run tools/third_party_fetch.sh relibc (make never downloads)"; exit 1; }

# One ISA: relibc-one ISA=<riscv64|aarch64|x86_64>, when its configuration asks.
relibc-one:
	@case "$(ISA)" in riscv64|aarch64|x86_64) ;; *) echo "relibc-one: ISA must be riscv64, aarch64 or x86_64"; exit 1;; esac
	@$(MAKE) -s $(RELIBC_KCONFIG_$(ISA))
	@grep -q '^CONFIG_RELIBC=y' $(RELIBC_KCONFIG_$(ISA)) || { \
	  echo "relibc: CONFIG_RELIBC is not set in $(RELIBC_KCONFIG_$(ISA)) ($(ISA))"; exit 1; }
	@kb="$$(sed -n 's/^CONFIG_USER_STACK_SIZE_KB=//p' $(RELIBC_KCONFIG_$(ISA)) 2>/dev/null)"; \
	  [ -z "$$kb" ] || export AZOS_USER_STACK_BYTES=$$((kb * 1024)); \
	  $(if $(filter aarch64,$(ISA)),export AZOS_PAGE_SIZE=$(AARCH64_PAGE_SIZE);) \
	  export RELIBC_RUSTFLAGS_TOML='$(RELIBC_TOML_$(ISA))'; \
	  $(RELIBC_RUN) headers && $(RELIBC_RUN) libs $(ISA) && \
	  for p in $(RELIBC_PROGS); do \
	    $(RELIBC_RUN) cc $(ISA) $(RELIBC_OUT_$(ISA))/$(ISA)/$$p.elf userspace/tests/relibc/$$p.c || exit 1; \
	  done && \
	  python3 tools/elf_page_perms.py $(if $(filter aarch64,$(ISA)),--page $(AARCH64_PAGE_SIZE)) $(foreach p,$(RELIBC_PROGS),$(RELIBC_OUT_$(ISA))/$(ISA)/$(p).elf) && \
	  echo "[RELIBC] $(ISA): $(foreach p,$(RELIBC_PROGS),$(RELIBC_OUT_$(ISA))/$(ISA)/$(p).elf)"

# Every ISA whose configuration sets CONFIG_RELIBC; none is an error.
# (Their configurations are made first, in the recipe: x86_64's variable is
# defined further down the file than a prerequisite list can see.)
relibc: relibc-check
	@$(MAKE) -s $(foreach i,$(RELIBC_ISAS),$(RELIBC_KCONFIG_$(i)))
	@set -e; n=0; \
	for isa in $(RELIBC_ISAS); do \
	  case $$isa in riscv64) c='$(RELIBC_KCONFIG_riscv64)';; aarch64) c='$(RELIBC_KCONFIG_aarch64)';; x86_64) c='$(RELIBC_KCONFIG_x86_64)';; esac; \
	  if grep -q '^CONFIG_RELIBC=y' $$c; then $(MAKE) -s relibc-one ISA=$$isa; n=$$((n + 1)); \
	  else echo "[RELIBC] $$isa: CONFIG_RELIBC is not set in $$c, skipped"; fi; \
	done; \
	[ $$n -gt 0 ] || { echo "relibc: no ISA configuration sets CONFIG_RELIBC (make config: C library)"; exit 1; }

busybox-source-offer:
	@mkdir -p $(BUSYBOX_WORK)
	@{ echo "BusyBox $(BUSYBOX_VERSION) -- GPL-2.0-only. Written offer of source (GPL-2.0 section 3(b))."; \
	   echo ""; \
	   echo "A AzOS volume carrying BUSYBOX.ELF contains BusyBox $(BUSYBOX_VERSION), built unmodified"; \
	   echo "from $(BUSYBOX_URL), tag $(BUSYBOX_TAG)"; \
	   echo "(git commit $(BUSYBOX_COMMIT)) from allnoconfig plus the lines of"; \
	   echo "$(BUSYBOX_FRAGMENT) (shipped with this offer), static, with zig cc"; \
	   echo "(target <isa>-linux-musl; musl is MIT)."; \
	   echo "For at least three years from distribution, the complete corresponding source code"; \
	   echo "(the tree at that commit and the build configuration) is available on request from the"; \
	   echo "distributor of the volume, for no more than the cost of physically performing the"; \
	   echo "transfer. BusyBox is not part of the AzOS kernel or base image."; } > $(BUSYBOX_OFFER)
	@echo "[BUSYBOX] wrote $(BUSYBOX_OFFER)"

# The two hand-assembled riscv64 tests are linked by rust-lld with the flags
# the target spec gives every native image (tools/user_link_args.py): no
# linker script, the same layout and entry (`_azos_entry`).
USER_LD_RISCV64 = $(LX_LLD) -flavor gnu $(shell python3 tools/user_link_args.py riscv64)
$(HELLO_ELF): $(HELLO_DIR)/hello.S $(USER_SPECS)/$(TARGET_RISCV64_USER).json tools/user_link_args.py tools/syscall_defs.py crates/core/abi/src/syscall_nr.rs crates/core/abi/src/invoke.rs
	@mkdir -p $(OUT_BUILD)
	$(RISCV_AS) -march=rv64imac -mabi=lp64 $(shell python3 tools/syscall_defs.py SYS_EXIT SYS_INVOKE SYS_CAP_INFO INVOKE_CONSOLE_WRITE CONSOLE_TYPE) -o $(OUT_BUILD)/hello.o $(HELLO_DIR)/hello.S
	$(USER_LD_RISCV64) -o $@ $(OUT_BUILD)/hello.o
	@echo "[USPACE] Built $@"

# Build the syscall test user-space binary (Phase G3).
syscall-test: $(SYSTEST_ELF)

$(SYSTEST_ELF): $(SYSTEST_DIR)/test.S $(USER_SPECS)/$(TARGET_RISCV64_USER).json tools/user_link_args.py tools/syscall_defs.py crates/core/abi/src/syscall_nr.rs crates/core/abi/src/invoke.rs
	@mkdir -p $(OUT_BUILD)
	$(RISCV_AS) -march=rv64imac -mabi=lp64 $(shell python3 tools/syscall_defs.py SYS_EXIT SYS_GETPID SYS_INVOKE SYS_CAP_INFO SYS_MO_MAP INVOKE_CONSOLE_WRITE CONSOLE_TYPE) -o $(OUT_BUILD)/syscall_test.o $(SYSTEST_DIR)/test.S
	$(USER_LD_RISCV64) -o $@ $(OUT_BUILD)/syscall_test.o
	@echo "[USPACE] Built $@"

# libsys reads the granule at compile time (`option_env!("AZOS_PAGE_SIZE")`);
# unset, it is 4096, so the default build's environment is unchanged. The
# targets are every ELF of the aarch64 hash table (`IMAGE_ELFS_AARCH64`, the
# path after each `NAME.ELF=`), not a second hand-kept list: that list missed
# SH, TOOLBOX and POWER, which then linked for the granule but ran libsys at
# 4 KiB.
IMAGE_ELF_PATHS_AARCH64 := $(foreach e,$(IMAGE_ELFS_AARCH64),$(lastword $(subst =, ,$(e))))
# The target spec is every image's layout: an edit of it rebuilds them (cargo
# hashes its contents into the fingerprint, so the link reruns too).
$(IMAGE_ELF_PATHS_AARCH64): $(USER_SPECS)/$(TARGET_AARCH64).json
IMAGE_ELF_PATHS_RISCV64 := $(foreach e,$(IMAGE_ELFS),$(lastword $(subst =, ,$(e))))
$(IMAGE_ELF_PATHS_RISCV64): $(USER_SPECS)/$(TARGET_RISCV64_USER).json
ifneq ($(AARCH64_PAGE_SIZE),4096)
$(IMAGE_ELF_PATHS_AARCH64): export AZOS_PAGE_SIZE := $(AARCH64_PAGE_SIZE)
endif

userspace-aarch64: $(HELLO_ELF_AARCH64) $(SYSTEST_ELF_AARCH64) $(GPIO_DRV_ELF_AARCH64) $(MLSRV_ELF_AARCH64) \
           $(UHELLO_ELF_AARCH64) $(REFLEX_ELF_AARCH64) $(BRAINCLI_ELF_AARCH64) $(CAPTEST_ELF_AARCH64) \
           $(LATBENCH_ELF_AARCH64) $(ABITEST_ELF_AARCH64) $(IPCTEST_ELF_AARCH64) $(VSBENCH_ELF_AARCH64) \
           $(EPSRV_ELF_AARCH64) $(ABICHILD_ELF_AARCH64) $(VSSRV_ELF_AARCH64) $(BUZZ_DRV_ELF_AARCH64) $(INA_DRV_ELF_AARCH64) \
           $(SH_ELF_AARCH64) $(TERMD_ELF_AARCH64) $(NAMESD_ELF_AARCH64) $(COMPMGR_ELF_AARCH64) $(TOOLBOX_ELF_AARCH64) $(POWER_ELF_AARCH64) $(TRACECTL_ELF_AARCH64) $(DECISD_ELF_AARCH64) $(INPUTD_ELF_AARCH64) $(COMPSRV_ELF_AARCH64) $(LOGD_ELF_AARCH64) $(WHY_ELF_AARCH64) $(PKGD_ELF_AARCH64) $(PKG_ELF_AARCH64) $(RPCSRV_ELF_AARCH64) $(ZENOHD_ELF_AARCH64) $(VMMD_ELF_AARCH64) $(PTPD_ELF_AARCH64) $(AUDIOD_ELF_AARCH64) $(RPCQUIC_ELF_AARCH64) $(MCPD_ELF_AARCH64) $(SSHD_ELF_AARCH64) $(LOGIND_ELF_AARCH64) $(FAM_ELFS_AARCH64) $(LXSRV_ELF_AARCH64) $(LXHELLO_ELF_AARCH64)

$(HELLO_ELF_AARCH64): $(HELLO_DIR)/src/main.rs $(HELLO_DIR)/Cargo.toml
	@mkdir -p $(AARCH64_DIR)
	cd $(HELLO_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(HELLO_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(HELLO_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/hello_aarch64 $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SYSTEST_ELF_AARCH64): $(SYSTEST_DIR)/src/main.rs $(SYSTEST_DIR)/Cargo.toml
	@mkdir -p $(AARCH64_DIR)
	cd $(SYSTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SYSTEST_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(SYSTEST_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/syscall_test_aarch64 $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(GPIO_DRV_ELF_AARCH64): $(GPIO_DRV_DIR)/src/main.rs $(GPIO_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(GPIO_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(GPIO_DRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(GPIO_DRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/gpio_drv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# Hard-float: `aarch64-unknown-none` (the kernel alone is soft-float).
$(MLSRV_ELF_AARCH64): $(MLSRV_DEPS) $(TOPOLOGY_KEY_STAMP)
	@mkdir -p $(AARCH64_DIR)
	cd $(MLSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MLSRV_DIR)$(AARCH64_PG_SUFFIX)" && $(MLSRV_QEMU_BUILD) $(AARCH64_UFLAGS) $(MLSRV_KEY_FEATURES)
	cp $(OUT_TGT)/$(MLSRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/infsrv $@

$(BUZZ_DRV_ELF_AARCH64): $(BUZZ_DRV_DIR)/src/main.rs $(BUZZER_CHIP_SRC) $(BUZZ_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(BUZZ_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(BUZZ_DRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	python3 tools/chip_source_check.py buzzer $(OUT_TGT)/$(BUZZ_DRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/buzz_drv
	cp $(OUT_TGT)/$(BUZZ_DRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/buzz_drv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(INA_DRV_ELF_AARCH64): $(INA_DRV_DIR)/src/main.rs $(INA219_CHIP_SRC) $(INA_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(INA_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(INA_DRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	python3 tools/chip_source_check.py ina219 $(OUT_TGT)/$(INA_DRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/ina_drv
	cp $(OUT_TGT)/$(INA_DRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/ina_drv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TERMD_ELF_AARCH64): $(TERMD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(TERMD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TERMD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(TERMD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/termd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(NAMESD_ELF_AARCH64): $(NAMESD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(NAMESD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(NAMESD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(NAMESD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/namesd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(COMPMGR_ELF_AARCH64): $(COMPMGR_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(COMPMGR_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(COMPMGR_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(COMPMGR_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/compmgr $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SH_ELF_AARCH64): $(SH_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(SH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SH_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(SH_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/sh $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TOOLBOX_ELF_AARCH64): $(TOOLBOX_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(TOOLBOX_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TOOLBOX_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	$(AARCH64_OBJCOPY) --strip-all $(OUT_TGT)/$(TOOLBOX_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/toolbox $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(POWER_ELF_AARCH64): $(POWER_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(POWER_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(POWER_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(POWER_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/power $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TRACECTL_ELF_AARCH64): $(TRACECTL_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(TRACECTL_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TRACECTL_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(TRACECTL_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/tracectl $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(DECISD_ELF_AARCH64): $(DECISD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(DECISD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(DECISD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(DECISD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/decisd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(INPUTD_ELF_AARCH64): $(INPUTD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(INPUTD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(INPUTD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(INPUTD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/inputd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(COMPSRV_ELF_AARCH64): $(COMPSRV_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(COMPSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(COMPSRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(COMPSRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/compositor $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LOGD_ELF_AARCH64): $(LOGD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(LOGD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LOGD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(LOGD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/logd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(WHY_ELF_AARCH64): $(WHY_SRC) $(SDK_SRC) $(LIBSYS_SRC) $(AARCH64_USER_KCONFIG)
	@mkdir -p $(AARCH64_DIR)
	$(SDK_BUILD_aarch64) --manifest-path $(WHY_DIR)/Cargo.toml
	cp $(SDK_OUT_aarch64)/why $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PKGD_ELF_AARCH64): $(PKGD_DEPS) $(TOPOLOGY_KEY_STAMP) $(AARCH64_USER_KCONFIG)
	@mkdir -p $(AARCH64_DIR)
	env -u TOPOLOGY_PUBKEY_PATH $(PYTHON) tools/sdk_cargo.py --isa aarch64 --kconfig $(AARCH64_USER_KCONFIG) --page-size $(AARCH64_PAGE_SIZE) --target-dir $(TLSPROBE_TGT)$(AARCH64_PG_SUFFIX) $(PKGD_CARGO) $(MLSRV_KEY_FEATURES)
	cp $(TLSPROBE_TGT)$(AARCH64_PG_SUFFIX)/aarch64-unknown-azos/release/pkgd $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PKG_ELF_AARCH64): $(PKG_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(PKG_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(PKG_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(PKG_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/pkg $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(RPCSRV_ELF_AARCH64): $(RPCSRV_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(RPCSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(RPCSRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(RPCSRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/rpcsrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ZENOHD_ELF_AARCH64): $(ZENOHD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(ZENOHD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ZENOHD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(ZENOHD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/zenohd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PTPD_ELF_AARCH64): $(PTPD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(PTPD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(PTPD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(PTPD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/ptpd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(AUDIOD_ELF_AARCH64): $(AUDIOD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(AUDIOD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(AUDIOD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(AUDIOD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/audiod $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(MCPD_ELF_AARCH64): $(MCPD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(MCPD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MCPD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(MCPD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/mcpd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SSHD_ELF_AARCH64): $(SSHD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(SSHD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SSHD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(SSHD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/sshd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LOGIND_ELF_AARCH64): $(LOGIND_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(LOGIND_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LOGIND_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(LOGIND_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/logind $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VMMD_ELF_AARCH64): $(VMMD_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(VMMD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VMMD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(VMMD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/vmmd $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# The Linux runtime shares the program's FP/SIMD state, so it is built with the
# soft-float target (no vector register is named anywhere in it), where every
# other image is hard-float. 4 KiB granule only.
$(LXRT_ELF_AARCH64): $(LXRT_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(LXRT_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LXRT_DIR)" && $(USPACE_BUILD) $(LXRT_UFLAGS_AARCH64)
	cp $(OUT_TGT)/$(LXRT_DIR)/$(LXRT_TARGET_AARCH64)/release/lxrt $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# x86_64: the same, on rustc's soft-float `x86_64-unknown-none` (not the
# hard-float `x86_64-unknown-azos` the other images use, and none of the
# Kconfig baseline flags, which would enable SSE: lxrt/build.rs).
$(LXRT_ELF_X86_64): $(LXRT_SRC) $(LIBSYS_SRC)
	@mkdir -p $(X86_64_DIR)
	cd $(LXRT_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LXRT_DIR)" && $(USPACE_BUILD) $(LXRT_UFLAGS_X86_64)
	cp $(OUT_TGT)/$(LXRT_DIR)/$(LXRT_TARGET_X86_64)/release/lxrt $@
	@echo "[USPACE-X86_64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(FLIGHT_ELF_AARCH64): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS) --bin flight
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/flight $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BEHAVIOR_ELF_AARCH64): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS) --bin behavior
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/behavior $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CONFIG_ELF_AARCH64): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS) --bin config
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/config $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OTA_ELF_AARCH64): $(FAMTOOLS_SRC) $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS) --bin ota
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/ota $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LXSRV_ELF_AARCH64): $(LXSRV_SRC) $(LIBSYS_SRC) .gitmodules
	@mkdir -p $(AARCH64_DIR)
	cd $(LXSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LXSRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(LXSRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/lxsrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(UHELLO_ELF_AARCH64): $(UHELLO_DIR)/src/main.rs $(UHELLO_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(UHELLO_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(UHELLO_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(UHELLO_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/uhello $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(EPSRV_ELF_AARCH64): $(EPSRV_DIR)/src/main.rs $(EPSRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(EPSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(EPSRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(EPSRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/epsrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ABICHILD_ELF_AARCH64): $(ABICHILD_DIR)/src/main.rs $(ABICHILD_DIR)/src/shared.rs $(ABICHILD_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(ABICHILD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ABICHILD_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(ABICHILD_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/abichild $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VSSRV_ELF_AARCH64): $(VSSRV_DIR)/src/main.rs $(VSSRV_DIR)/Cargo.toml \
               userspace/bench/vsbench/src/serve.rs userspace/bench/vsbench/src/ipc_proto.rs $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(VSSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VSSRV_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(VSSRV_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/vssrv $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(REFLEX_ELF_AARCH64): $(REFLEX_DIR)/src/main.rs $(REFLEX_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(REFLEX_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(REFLEX_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(REFLEX_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/reflex $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(BRAINCLI_ELF_AARCH64): $(BRAINCLI_DIR)/src/main.rs $(BRAINCLI_DIR)/src/link.rs $(BRAINCLI_DIR)/Cargo.toml \
               crates/core/crypto/src/secure_channel.rs \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(BRAINCLI_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(BRAINCLI_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(BRAINCLI_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/brain_client $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(CAPTEST_ELF_AARCH64): $(CAPTEST_DIR)/src/main.rs $(CAPTEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(CAPTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(CAPTEST_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(CAPTEST_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/captest $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VSBENCH_ELF_AARCH64): $(VSBENCH_DIR)/src/main.rs $(VSBENCH_DIR)/src/bench_core.rs $(VSBENCH_DIR)/src/ipc_proto.rs \
               $(VSBENCH_DIR)/src/abi_azos.rs $(VSBENCH_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(OUT_BUILD)/vsbench.features
	@mkdir -p $(AARCH64_DIR)
	cd $(VSBENCH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VSBENCH_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS) --features azos$(VSBENCH_FEATURES_ARG)
	$(AARCH64_OBJCOPY) --strip-all $(OUT_TGT)/$(VSBENCH_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/vsbench $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(LATBENCH_ELF_AARCH64): $(LATBENCH_DIR)/src/main.rs $(LATBENCH_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(LATBENCH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LATBENCH_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(LATBENCH_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/latbench $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(ABITEST_ELF_AARCH64): $(ABITEST_DIR)/src/main.rs $(ABICHILD_DIR)/src/shared.rs $(ABITEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(ABITEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ABITEST_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(ABITEST_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/abitest $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(IPCTEST_ELF_AARCH64): $(IPCTEST_DIR)/src/main.rs $(IPCTEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC)
	@mkdir -p $(AARCH64_DIR)
	cd $(IPCTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(IPCTEST_DIR)$(AARCH64_PG_SUFFIX)" && $(USPACE_BUILD) $(AARCH64_UFLAGS)
	cp $(OUT_TGT)/$(IPCTEST_DIR)$(AARCH64_PG_SUFFIX)/$(TARGET_AARCH64)/release/ipctest $@
	@echo "[USPACE-AARCH64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(IMAGE_ELF_PATHS_X86_64): $(USER_SPECS)/$(TARGET_X86_64).json
.PHONY: userspace-x86_64
userspace-x86_64: $(IMAGE_ELF_PATHS_X86_64)

$(HELLO_ELF_X86_64): $(HELLO_DIR)/src/main.rs $(HELLO_DIR)/Cargo.toml $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(HELLO_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(HELLO_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(HELLO_DIR)/$(X86_64_UBUILT)/hello_aarch64 $@

$(UHELLO_ELF_X86_64): $(UHELLO_DIR)/src/main.rs $(UHELLO_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(UHELLO_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(UHELLO_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(UHELLO_DIR)/$(X86_64_UBUILT)/uhello $@

$(EPSRV_ELF_X86_64): $(EPSRV_DIR)/src/main.rs $(EPSRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(EPSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(EPSRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(EPSRV_DIR)/$(X86_64_UBUILT)/epsrv $@

$(ABICHILD_ELF_X86_64): $(ABICHILD_DIR)/src/main.rs $(ABICHILD_DIR)/src/shared.rs $(ABICHILD_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(ABICHILD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ABICHILD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(ABICHILD_DIR)/$(X86_64_UBUILT)/abichild $@

$(REFLEX_ELF_X86_64): $(REFLEX_DIR)/src/main.rs $(REFLEX_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(REFLEX_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(REFLEX_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(REFLEX_DIR)/$(X86_64_UBUILT)/reflex $@

$(BRAINCLI_ELF_X86_64): $(BRAINCLI_DIR)/src/main.rs $(BRAINCLI_DIR)/src/link.rs $(BRAINCLI_DIR)/Cargo.toml \
               crates/core/crypto/src/secure_channel.rs \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(BRAINCLI_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(BRAINCLI_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(BRAINCLI_DIR)/$(X86_64_UBUILT)/brain_client $@

$(ABITEST_ELF_X86_64): $(ABITEST_DIR)/src/main.rs $(ABICHILD_DIR)/src/shared.rs $(ABITEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(ABITEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ABITEST_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(ABITEST_DIR)/$(X86_64_UBUILT)/abitest $@

$(IPCTEST_ELF_X86_64): $(IPCTEST_DIR)/src/main.rs $(IPCTEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(IPCTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(IPCTEST_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(IPCTEST_DIR)/$(X86_64_UBUILT)/ipctest $@

$(SYSTEST_ELF_X86_64): $(SYSTEST_DIR)/src/main.rs $(SYSTEST_DIR)/Cargo.toml $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(SYSTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SYSTEST_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(SYSTEST_DIR)/$(X86_64_UBUILT)/syscall_test_aarch64 $@

$(CAPTEST_ELF_X86_64): $(CAPTEST_DIR)/src/main.rs $(CAPTEST_DIR)/src/abi_cases.rs $(CAPTEST_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(CAPTEST_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(CAPTEST_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(CAPTEST_DIR)/$(X86_64_UBUILT)/captest $@

$(LATBENCH_ELF_X86_64): $(LATBENCH_DIR)/src/main.rs $(LATBENCH_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(LATBENCH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LATBENCH_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(LATBENCH_DIR)/$(X86_64_UBUILT)/latbench $@

$(LXSRV_ELF_X86_64): $(LXSRV_SRC) $(LIBSYS_SRC) .gitmodules $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(LXSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LXSRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(LXSRV_DIR)/$(X86_64_UBUILT)/lxsrv $@

$(GPIO_DRV_ELF_X86_64): $(GPIO_DRV_DIR)/src/main.rs $(GPIO_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(GPIO_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(GPIO_DRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(GPIO_DRV_DIR)/$(X86_64_UBUILT)/gpio_drv $@

$(BUZZ_DRV_ELF_X86_64): $(BUZZ_DRV_DIR)/src/main.rs $(BUZZER_CHIP_SRC) $(BUZZ_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(BUZZ_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(BUZZ_DRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	python3 tools/chip_source_check.py buzzer $(OUT_TGT)/$(BUZZ_DRV_DIR)/$(X86_64_UBUILT)/buzz_drv
	cp $(OUT_TGT)/$(BUZZ_DRV_DIR)/$(X86_64_UBUILT)/buzz_drv $@

$(INA_DRV_ELF_X86_64): $(INA_DRV_DIR)/src/main.rs $(INA219_CHIP_SRC) $(INA_DRV_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(INA_DRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(INA_DRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	python3 tools/chip_source_check.py ina219 $(OUT_TGT)/$(INA_DRV_DIR)/$(X86_64_UBUILT)/ina_drv
	cp $(OUT_TGT)/$(INA_DRV_DIR)/$(X86_64_UBUILT)/ina_drv $@

$(MLSRV_ELF_X86_64): $(MLSRV_DEPS) $(TOPOLOGY_KEY_STAMP) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(MLSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MLSRV_DIR)" && $(MLSRV_QEMU_BUILD) $(X86_64_UFLAGS) $(MLSRV_KEY_FEATURES)
	cp $(OUT_TGT)/$(MLSRV_DIR)/$(X86_64_UBUILT)/infsrv $@

$(TERMD_ELF_X86_64): $(TERMD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(TERMD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TERMD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(TERMD_DIR)/$(X86_64_UBUILT)/termd $@

$(NAMESD_ELF_X86_64): $(NAMESD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(NAMESD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(NAMESD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(NAMESD_DIR)/$(X86_64_UBUILT)/namesd $@

$(COMPMGR_ELF_X86_64): $(COMPMGR_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(COMPMGR_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(COMPMGR_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(COMPMGR_DIR)/$(X86_64_UBUILT)/compmgr $@

$(SH_ELF_X86_64): $(SH_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(SH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SH_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(SH_DIR)/$(X86_64_UBUILT)/sh $@

$(TOOLBOX_ELF_X86_64): $(TOOLBOX_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(TOOLBOX_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TOOLBOX_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	$(AARCH64_OBJCOPY) --strip-all $(OUT_TGT)/$(TOOLBOX_DIR)/$(X86_64_UBUILT)/toolbox $@

$(POWER_ELF_X86_64): $(POWER_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(POWER_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(POWER_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(POWER_DIR)/$(X86_64_UBUILT)/power $@

$(TRACECTL_ELF_X86_64): $(TRACECTL_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(TRACECTL_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(TRACECTL_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(TRACECTL_DIR)/$(X86_64_UBUILT)/tracectl $@

$(DECISD_ELF_X86_64): $(DECISD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(DECISD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(DECISD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(DECISD_DIR)/$(X86_64_UBUILT)/decisd $@

$(INPUTD_ELF_X86_64): $(INPUTD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(INPUTD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(INPUTD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(INPUTD_DIR)/$(X86_64_UBUILT)/inputd $@

$(COMPSRV_ELF_X86_64): $(COMPSRV_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(COMPSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(COMPSRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(COMPSRV_DIR)/$(X86_64_UBUILT)/compositor $@

$(LOGD_ELF_X86_64): $(LOGD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(LOGD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LOGD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(LOGD_DIR)/$(X86_64_UBUILT)/logd $@

$(WHY_ELF_X86_64): $(WHY_SRC) $(SDK_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	$(SDK_BUILD_x86_64) --manifest-path $(WHY_DIR)/Cargo.toml
	cp $(SDK_OUT_x86_64)/why $@

# The TLS/QUIC probe (userspace/lib/tls-probe): a std program that links rustls
# (the rustls-rustcrypto provider) and quinn-proto from third_party/vendor, the
# one tree crates.io dependencies of std programs come from (sdk_cargo.py
# --vendored: offline, locked, scoped to these builds; the kernel workspace's
# cargo config never sees it). Its own target directory: the flags differ from
# the other SDK programs', and a shared one would rebuild std on every switch.
TLSPROBE_DIR     := userspace/lib/tls-probe
TLSPROBE_SRC      = $(wildcard $(TLSPROBE_DIR)/src/*.rs $(TLSPROBE_DIR)/pki/*.der) $(TLSPROBE_DIR)/Cargo.toml $(TLSPROBE_DIR)/Cargo.lock third_party/VENDOR_PIN $(SDK_SRC)
TLSPROBE_TGT     := $(OUT_BUILD)/sdk/target-vendored
TLSPROBE_ELF     := $(OUT_BUILD)/tls-probe.elf
TLSPROBE_ELF_AARCH64 := $(OUT_BUILD)/aarch64$(AARCH64_PG_SUFFIX)/tls-probe.elf
TLSPROBE_ELF_X86_64  := $(OUT_BUILD)/x86_64/tls-probe.elf
TLSPROBE_CARGO    = --vendored -- build --release --manifest-path $(TLSPROBE_DIR)/Cargo.toml

$(TLSPROBE_ELF): $(TLSPROBE_SRC) $(RV_USER_KCONFIG)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/sdk_cargo.py --isa riscv64 --kconfig $(RV_USER_KCONFIG) --target-dir $(TLSPROBE_TGT) $(TLSPROBE_CARGO)
	cp $(TLSPROBE_TGT)/riscv64imac-unknown-azos/release/tls-probe $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TLSPROBE_ELF_AARCH64): $(TLSPROBE_SRC) $(AARCH64_USER_KCONFIG)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/sdk_cargo.py --isa aarch64 --kconfig $(AARCH64_USER_KCONFIG) --page-size $(AARCH64_PAGE_SIZE) --target-dir $(TLSPROBE_TGT)$(AARCH64_PG_SUFFIX) $(TLSPROBE_CARGO)
	cp $(TLSPROBE_TGT)$(AARCH64_PG_SUFFIX)/aarch64-unknown-azos/release/tls-probe $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(TLSPROBE_ELF_X86_64): $(TLSPROBE_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/sdk_cargo.py --isa x86_64 --kconfig $(X86_64_KCONFIG) --target-dir $(TLSPROBE_TGT) $(TLSPROBE_CARGO)
	cp $(TLSPROBE_TGT)/x86_64-unknown-azos/release/tls-probe $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# The relay of the QUIC link (userspace/services/rpcquic over the library in
# userspace/lib/quic; Kconfig RPC_QUIC): a
# std program on the same vendored tree and target directory as the probe above.
# It is on every image like the other services; its topology row comes with
# RPC_QUIC.
RPCQUIC_DIR      := userspace/services/rpcquic
RPCQUIC_LIB      := userspace/lib/quic
RPCQUIC_SRC       = $(wildcard $(RPCQUIC_DIR)/src/*.rs $(RPCQUIC_LIB)/src/*.rs) $(RPCQUIC_DIR)/Cargo.toml $(RPCQUIC_DIR)/Cargo.lock $(RPCQUIC_LIB)/Cargo.toml third_party/VENDOR_PIN $(RPC_LIB_SRC) $(SDK_SRC)
RPCQUIC_CARGO     = --vendored -- build --release --manifest-path $(RPCQUIC_DIR)/Cargo.toml

$(RPCQUIC_ELF): $(RPCQUIC_SRC) $(RV_USER_KCONFIG)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/sdk_cargo.py --isa riscv64 --kconfig $(RV_USER_KCONFIG) --target-dir $(TLSPROBE_TGT) $(RPCQUIC_CARGO)
	cp $(TLSPROBE_TGT)/riscv64imac-unknown-azos/release/rpcquic $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(RPCQUIC_ELF_AARCH64): $(RPCQUIC_SRC) $(AARCH64_USER_KCONFIG)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/sdk_cargo.py --isa aarch64 --kconfig $(AARCH64_USER_KCONFIG) --page-size $(AARCH64_PAGE_SIZE) --target-dir $(TLSPROBE_TGT)$(AARCH64_PG_SUFFIX) $(RPCQUIC_CARGO)
	cp $(TLSPROBE_TGT)$(AARCH64_PG_SUFFIX)/aarch64-unknown-azos/release/rpcquic $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(RPCQUIC_ELF_X86_64): $(RPCQUIC_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/sdk_cargo.py --isa x86_64 --kconfig $(X86_64_KCONFIG) --target-dir $(TLSPROBE_TGT) $(RPCQUIC_CARGO)
	cp $(TLSPROBE_TGT)/x86_64-unknown-azos/release/rpcquic $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

# The SDK's own test (tests/sdk/sdktest): a std program that runs the user-code
# harness over the port. Built here; booting it needs an image whose topology
# row grants it the entropy capability and the `net` op class (nothing ships it
# yet).
SDKTEST_DIR      := tests/sdk/sdktest
SDKTEST_SRC       = $(SDKTEST_DIR)/src/main.rs $(SDKTEST_DIR)/Cargo.toml $(SDK_SRC) $(LIBSYS_SRC)
SDKTEST_ELF      := $(OUT_BUILD)/sdktest.elf
SDKTEST_ELF_AARCH64 := $(OUT_BUILD)/aarch64$(AARCH64_PG_SUFFIX)/sdktest.elf
SDKTEST_ELF_X86_64  := $(OUT_BUILD)/x86_64/sdktest.elf
SDK_ELFS          = $(WHY_ELF) $(WHY_ELF_AARCH64) $(WHY_ELF_X86_64) $(SDKTEST_ELF) $(SDKTEST_ELF_AARCH64) $(SDKTEST_ELF_X86_64) \
                    $(TLSPROBE_ELF) $(TLSPROBE_ELF_AARCH64) $(TLSPROBE_ELF_X86_64) \
                    $(RPCQUIC_ELF) $(RPCQUIC_ELF_AARCH64) $(RPCQUIC_ELF_X86_64) \
                    $(PKGD_ELF) $(PKGD_ELF_AARCH64) $(PKGD_ELF_X86_64)

.PHONY: sdk sdk-check
sdk: $(SDK_ELFS)

# The std port layer type-checks alone on the three ISAs (the pinned toolchain's
# stock library, no std), and its host tests run.
sdk-check: $(RV_USER_KCONFIG) $(AARCH64_USER_KCONFIG) $(X86_64_KCONFIG)
	$(PYTHON) tools/sdk_cargo.py --isa riscv64 --kconfig $(RV_USER_KCONFIG) --build-std core --target-dir $(SDK_TARGET_DIR)/check -- check --release --manifest-path crates/core/stdrt/Cargo.toml
	$(PYTHON) tools/sdk_cargo.py --isa aarch64 --kconfig $(AARCH64_USER_KCONFIG) --page-size $(AARCH64_PAGE_SIZE) --build-std core --target-dir $(SDK_TARGET_DIR)/check$(AARCH64_PG_SUFFIX) -- check --release --manifest-path crates/core/stdrt/Cargo.toml
	$(PYTHON) tools/sdk_cargo.py --isa x86_64 --kconfig $(X86_64_KCONFIG) --build-std core --target-dir $(SDK_TARGET_DIR)/check -- check --release --manifest-path crates/core/stdrt/Cargo.toml
	cd tests/host/stdrt-tests && CARGO_TARGET_DIR="$(OUT_TGT)/tests/host/stdrt-tests" $(CARGO) test --release
	cd crates/core/libsys-macros && CARGO_TARGET_DIR="$(OUT_TGT)/crates/core/libsys-macros" $(CARGO) test --offline

$(SDKTEST_ELF): $(SDKTEST_SRC) $(RV_USER_KCONFIG)
	@mkdir -p $(OUT_BUILD)
	$(SDK_BUILD_riscv64) --manifest-path $(SDKTEST_DIR)/Cargo.toml
	cp $(SDK_OUT_riscv64)/sdktest $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SDKTEST_ELF_AARCH64): $(SDKTEST_SRC) $(AARCH64_USER_KCONFIG)
	@mkdir -p $(dir $@)
	$(SDK_BUILD_aarch64) --manifest-path $(SDKTEST_DIR)/Cargo.toml
	cp $(SDK_OUT_aarch64)/sdktest $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(SDKTEST_ELF_X86_64): $(SDKTEST_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(dir $@)
	$(SDK_BUILD_x86_64) --manifest-path $(SDKTEST_DIR)/Cargo.toml
	cp $(SDK_OUT_x86_64)/sdktest $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PKGD_ELF_X86_64): $(PKGD_DEPS) $(TOPOLOGY_KEY_STAMP) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	env -u TOPOLOGY_PUBKEY_PATH $(PYTHON) tools/sdk_cargo.py --isa x86_64 --kconfig $(X86_64_KCONFIG) --target-dir $(TLSPROBE_TGT) $(PKGD_CARGO) $(MLSRV_KEY_FEATURES)
	cp $(TLSPROBE_TGT)/x86_64-unknown-azos/release/pkgd $@
	@echo "[SDK] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(PKG_ELF_X86_64): $(PKG_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(PKG_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(PKG_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(PKG_DIR)/$(X86_64_UBUILT)/pkg $@

$(RPCSRV_ELF_X86_64): $(RPCSRV_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(RPCSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(RPCSRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(RPCSRV_DIR)/$(X86_64_UBUILT)/rpcsrv $@

$(ZENOHD_ELF_X86_64): $(ZENOHD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(ZENOHD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(ZENOHD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(ZENOHD_DIR)/$(X86_64_UBUILT)/zenohd $@

$(PTPD_ELF_X86_64): $(PTPD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(PTPD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(PTPD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(PTPD_DIR)/$(X86_64_UBUILT)/ptpd $@

$(AUDIOD_ELF_X86_64): $(AUDIOD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(AUDIOD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(AUDIOD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(AUDIOD_DIR)/$(X86_64_UBUILT)/audiod $@

$(MCPD_ELF_X86_64): $(MCPD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(MCPD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(MCPD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(MCPD_DIR)/$(X86_64_UBUILT)/mcpd $@

$(SSHD_ELF_X86_64): $(SSHD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(SSHD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(SSHD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(SSHD_DIR)/$(X86_64_UBUILT)/sshd $@

$(LOGIND_ELF_X86_64): $(LOGIND_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(LOGIND_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(LOGIND_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(LOGIND_DIR)/$(X86_64_UBUILT)/logind $@

$(VMMD_ELF_X86_64): $(VMMD_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(VMMD_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VMMD_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(VMMD_DIR)/$(X86_64_UBUILT)/vmmd $@

$(FLIGHT_ELF_X86_64): $(FAMTOOLS_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin flight
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)/$(X86_64_UBUILT)/flight $@

$(BEHAVIOR_ELF_X86_64): $(FAMTOOLS_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin behavior
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)/$(X86_64_UBUILT)/behavior $@

$(CONFIG_ELF_X86_64): $(FAMTOOLS_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin config
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)/$(X86_64_UBUILT)/config $@

$(OTA_ELF_X86_64): $(FAMTOOLS_SRC) $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(FAMTOOLS_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(FAMTOOLS_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS) --bin ota
	cp $(OUT_TGT)/$(FAMTOOLS_DIR)/$(X86_64_UBUILT)/ota $@

# vsbench (wave 15): stripped, as on the other two ISAs (the autorun cap).
# vsbench's ipc-roundtrip peer (spawned as /fat/VSSRV.ELF, endpoint.bench).
$(VSSRV_ELF_X86_64): $(VSSRV_DIR)/src/main.rs $(VSSRV_DIR)/Cargo.toml \
               userspace/bench/vsbench/src/serve.rs userspace/bench/vsbench/src/ipc_proto.rs $(LIBSYS_SRC) $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(VSSRV_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VSSRV_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS)
	cp $(OUT_TGT)/$(VSSRV_DIR)/$(X86_64_UBUILT)/vssrv $@
	@echo "[USPACE-X86_64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(VSBENCH_ELF_X86_64): $(VSBENCH_DIR)/src/main.rs $(VSBENCH_DIR)/src/bench_core.rs $(VSBENCH_DIR)/src/ipc_proto.rs \
               $(VSBENCH_DIR)/src/abi_azos.rs $(VSBENCH_DIR)/Cargo.toml \
               $(LIBSYS_SRC) $(OUT_BUILD)/vsbench.features $(X86_64_KCONFIG)
	@mkdir -p $(X86_64_DIR)
	cd $(VSBENCH_DIR) && export CARGO_TARGET_DIR="$(OUT_TGT)/$(VSBENCH_DIR)" && $(USPACE_BUILD) $(X86_64_UFLAGS) --features azos$(VSBENCH_FEATURES_ARG)
	$(AARCH64_OBJCOPY) --strip-all $(OUT_TGT)/$(VSBENCH_DIR)/$(X86_64_UBUILT)/vsbench $@
	@echo "[USPACE-X86_64] Built $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

