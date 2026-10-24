# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Host tools: OTA, TFTP, worktree seeding, the policy file and clean.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# A fresh worktree's first build, from another worktree's cargo target dirs
# (tools/dev/worktree_seed.py): APFS clones, keeping only the units that cannot
# depend on the tree's path (build-std, crates.io); every path package is
# rebuilt here. `make worktree-seed FROM=~/azos-wt/<other>`.
.PHONY: worktree-seed
worktree-seed:
	@test -n "$(FROM)" || { echo "usage: make worktree-seed FROM=<another worktree>"; exit 2; }
	@python3 tools/dev/worktree_seed.py $(SEED_ARGS) "$(FROM)"

make-gguf $(OUT_BUILD)/policy.gguf: tools/image/make_gguf.py
	@mkdir -p $(OUT_BUILD)
	python3 tools/image/make_gguf.py

# Every output of this checkout lives under $(AZOS_OUT); nothing else to clean.
clean:
	rm -rf $(AZOS_OUT)

# OTA: send firmware to robot over TCP.
# Usage: make ota-send ROBOT=10.0.2.15 [PORT=8080] [PLATFORM=qemu] [FW_VER=1]
ROBOT    ?= 10.0.2.15
PORT     ?= 8080
PLATFORM ?= qemu
FW_VER   ?= 1

# OTA needs raw binary, not ELF (ELF has debug info = too large).
OTA_BIN := $(OUT_BUILD)/kernel-ota.bin

$(OTA_BIN): build
	@mkdir -p $(OUT_BUILD)
	riscv64-unknown-elf-objcopy -O binary $(KERNEL_ELF) $@
	@echo "[OTA] Raw binary: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

ota-send: $(OTA_BIN)
	python3 tools/dev/ota_send.py $(OTA_BIN) $(ROBOT) \
		--port $(PORT) --platform $(PLATFORM) --version $(FW_VER)

# Generate U-Boot boot script for A/B OTA slot selection (VF2/K1).
boot-scr: tools/image/boot.cmd
	@mkdir -p $(OUT_BUILD)
	mkimage -C none -A riscv -T script -d tools/image/boot.cmd $(OUT_BUILD)/boot.scr
	@echo "[OTA] boot.scr generated"

# DEV01 — TFTP fast-iteration netboot for the freshly-built kernel.
# `tftp-serve`: builds + raw-binarifies + serves on udp/$(TFTP_PORT).
# Default port is 6969 (unprivileged); override with TFTP_PORT=69 if
# you run as root.
TFTP_PORT ?= 6969
tftp-serve: $(OTA_BIN)
	python3 tools/dev/tftp_serve.py $(OTA_BIN) --port $(TFTP_PORT)


# ── make doc: rustdoc of the public crates ──────────────────────────────────
# (ARCH and CHECK_DEFCONFIG_* come from mk/lints.mk, read after this file, so
# everything that names them is expanded when the recipe runs.)
# rustdoc for the crates a program or a driver links against, into
# $(AZOS_OUT)/doc (open $(AZOS_OUT)/doc/azos_abi/index.html). Warnings are
# errors for these crates: a broken intra-doc link fails the build. rustdoc
# gets the ISA's baseline codegen flags too, or the crates it documents would
# mismatch the ones rustc built (x86_64's retpoline). The
# standalone crates (their own `[workspace]`) are documented from their own
# directory into the same cargo target dir, so rustdoc merges one index and
# one search across all of them. `make doc ARCH=aarch64` documents the
# aarch64 build of the same crates (the default is riscv64, like `check`).
# Documentation/api-reference.md says what each crate is.
DOC_WS_PKGS     := azos_abi azos_libsys azos_devif azos_rings azos_bytepipe azos_arch_api
DOC_STANDALONE  := crates/core/idl crates/core/stdrt
DOC_TARGET_DIR   = $(OUT_TGT)/doc-$(ARCH)

.PHONY: doc
doc:
	@test -n "$(CHECK_DEFCONFIG_$(ARCH))" || { echo "[DOC] unknown ARCH=$(ARCH) (riscv64, aarch64, x86_64)"; exit 1; }
	@mkdir -p $(OUT_BUILD)
	cp "$(CHECK_DEFCONFIG_$(ARCH))" "$(OUT_BUILD)/doc-$(ARCH).config"
	KCONFIG_CONFIG="$(OUT_BUILD)/doc-$(ARCH).config" $(PYTHON) -m olddefconfig
	set -e; kc="$(OUT_BUILD)/doc-$(ARCH).config"; \
	triple="$$(python3 tools/build/kconfig_to_cargo.py "$$kc" | tr -s ' ' '\n' | sed -n '/^--target$$/{n;p;}')"; \
	test -n "$$triple" || { echo "[DOC] no target for ARCH=$(ARCH)"; exit 1; }; \
	rf="$$(python3 tools/build/kconfig_to_cargo.py --rustflags "$$kc")"; \
	if [ -n "$$rf" ]; then export RUSTFLAGS="$$rf"; else unset RUSTFLAGS; fi; \
	export CARGO_TARGET_DIR="$(DOC_TARGET_DIR)" KCONFIG_CONFIG="$$kc" RUSTDOCFLAGS="-D warnings $$rf"; \
	unset CARGO_BUILD_RUSTFLAGS; \
	$(CARGO) doc --release --no-deps --target "$$triple" $(foreach p,$(DOC_WS_PKGS),-p $(p)); \
	for d in $(DOC_STANDALONE); do \
	    (cd "$$d" && $(CARGO) doc --release --no-deps --target "$$triple") || exit 1; \
	done; \
	rm -rf "$(AZOS_OUT)/doc"; \
	cp -R "$(DOC_TARGET_DIR)/$$triple/doc" "$(AZOS_OUT)/doc"; \
	echo "[DOC] $(AZOS_OUT)/doc/azos_abi/index.html"

# ── Host dry boot of a topology (tools/gate/azos_sim) ────────────────────────────
#
#   make sim SIM_DEFCONFIG=config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config SIM_CPUS=4
#   make sim SIM_DEFCONFIG=... SIM_TOPOLOGY=$(AZOS_OUT)/build/topo/riscv64
#
# Replays the kernel's boot admission of a topology on the host, through the
# functions the kernel calls (azos_topology::boot_admission), and prints the
# decision records the boot would write, the rows it would refuse and the
# `*.ELF` rows with no filter row. Like the emitter (`make topology-files`),
# the build takes the expanded defconfig as KCONFIG_CONFIG and the
# azos_topology features the kernel's features turn on, plus the ISA's
# `emit-target-*`.
#
#   SIM_DEFCONFIG  the defconfig (default the gate's riscv64 cell, generic-sbc-riscv64-dev+qemu+linux+gui)
#   SIM_TOPOLOGY   `builtin` (default) or a directory with CAPS.TOM + SCHED.TOM
#   SIM_CPUS       the board's CPU count or QEMU's -smp (default NR_CPUS, a ceiling)
#   SIM_SELECT     the selection the kernel was built with beyond its
#                  defconfig (tools/build/kconfig_to_cargo.py --select; default none)
#   SIM_EXTRA_FEATURES  azos_sim's own cargo features (the gate canary
#                  `sim-cpu-canary`)
#   SIM_ARGS       more azos_sim arguments (`--check-log <boot log>`: hold the
#                  dry boot to a real boot's console, SIM_CPUS = its -smp)
SIM_DEFCONFIG ?= config/defconfigs/generic-sbc-riscv64-dev+qemu+linux+gui.config
SIM_TOPOLOGY ?= builtin
SIM_CPUS ?=
SIM_ARGS ?=
SIM_EXTRA_FEATURES ?=
SIM_KCONFIG = $(OUT_BUILD)/sim/$(notdir $(SIM_DEFCONFIG))
SIM_SELECT ?=
.PHONY: sim
sim: | $(IMAGE_HASHES)
	@mkdir -p $(OUT_BUILD)/sim
	@cp "$(SIM_DEFCONFIG)" "$(SIM_KCONFIG)" && KCONFIG_CONFIG="$(SIM_KCONFIG)" python3 -m olddefconfig >/dev/null
	@isa=$$(sed -nE 's/^CONFIG_ARCH_(RISCV64|AARCH64|X86_64)=y$$/\1/p' "$(SIM_KCONFIG)" | tr A-Z a-z); \
	test -n "$$isa" || { echo "[SIM] $(SIM_KCONFIG): no CONFIG_ARCH_*"; exit 2; }; \
	feats="azos_topology/emit-target-$$isa $(call topo_features,$(SIM_KCONFIG),$(SIM_SELECT),$(SIM_KCONFIG:.config=-sel.config)) $(SIM_EXTRA_FEATURES)"; \
	echo "[SIM] $(SIM_DEFCONFIG) ($$isa), selection '$(SIM_SELECT)'"; \
	cd tools/gate/azos_sim && KCONFIG_CONFIG="$(abspath $(SIM_KCONFIG))" CARGO_TARGET_DIR="$(OUT_TGT)/tools/gate/azos_sim" \
		$(CARGO) run -q --release --features "$$feats" -- $(if $(SIM_CPUS),--cpus $(SIM_CPUS)) $(SIM_ARGS) "$(SIM_TOPOLOGY)"
