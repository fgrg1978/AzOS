# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Host tools: OTA, TFTP, worktree seeding, the policy file and clean.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# A fresh worktree's first build, from another worktree's cargo target dirs
# (tools/worktree_seed.py): APFS clones, keeping only the units that cannot
# depend on the tree's path (build-std, crates.io); every path package is
# rebuilt here. `make worktree-seed FROM=~/azos-wt/<other>`.
.PHONY: worktree-seed
worktree-seed:
	@test -n "$(FROM)" || { echo "usage: make worktree-seed FROM=<another worktree>"; exit 2; }
	@python3 tools/worktree_seed.py $(SEED_ARGS) "$(FROM)"

make-gguf $(OUT_BUILD)/policy.gguf: tools/make_gguf.py
	@mkdir -p $(OUT_BUILD)
	python3 tools/make_gguf.py

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
	python3 tools/ota_send.py $(OTA_BIN) $(ROBOT) \
		--port $(PORT) --platform $(PLATFORM) --version $(FW_VER)

# Generate U-Boot boot script for A/B OTA slot selection (VF2/K1).
boot-scr: tools/boot.cmd
	@mkdir -p $(OUT_BUILD)
	mkimage -C none -A riscv -T script -d tools/boot.cmd $(OUT_BUILD)/boot.scr
	@echo "[OTA] boot.scr generated"

# DEV01 — TFTP fast-iteration netboot for the freshly-built kernel.
# `tftp-serve`: builds + raw-binarifies + serves on udp/$(TFTP_PORT).
# Default port is 6969 (unprivileged); override with TFTP_PORT=69 if
# you run as root.
TFTP_PORT ?= 6969
tftp-serve: $(OTA_BIN)
	python3 tools/tftp_serve.py $(OTA_BIN) --port $(TFTP_PORT)


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
	triple="$$(python3 tools/kconfig_to_cargo.py "$$kc" | tr -s ' ' '\n' | sed -n '/^--target$$/{n;p;}')"; \
	test -n "$$triple" || { echo "[DOC] no target for ARCH=$(ARCH)"; exit 1; }; \
	rf="$$(python3 tools/kconfig_to_cargo.py --rustflags "$$kc")"; \
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
