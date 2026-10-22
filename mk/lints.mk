# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Checks: `make ARCH=<isa> check` and the CI tiers (check0, check1, ...).
# Included by the top-level Makefile; the order of the includes there is part of the contract.

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
CHECK_KCONFIG := $(OUT_BUILD)/check-$(ARCH).config
# The image table the kernel `include!`s, made when missing (order-only: a
# type-check never waits for a userspace rebuild; `make` refreshes the table).
# Without it a fresh worktree's `make check0` failed in azos_sched.
CHECK_TABLE_riscv64 := $(IMAGE_HASHES)
CHECK_TABLE_aarch64 := $(IMAGE_HASHES_AARCH64)
CHECK_TABLE_x86_64  := $(OUT_BUILD)/image_hashes_x86_64.rs $(THIRDPARTY_HASHES_X86_64)

.PHONY: check
# CHECK_FEATURES adds cargo features (`make check CHECK_FEATURES=qemu,ktest`):
# FEATURES= is not read here, so a ktest-only file is otherwise never compiled.
CHECK_FEATURES ?=
check: | $(CHECK_TABLE_$(ARCH))
	@test -n "$(CHECK_DEFCONFIG_$(ARCH))" || { echo "[CHECK] unknown ARCH=$(ARCH) (riscv64, aarch64, x86_64)"; exit 1; }
	@mkdir -p $(OUT_BUILD)
	cp "$(CHECK_DEFCONFIG_$(ARCH))" "$(CHECK_KCONFIG)"
	KCONFIG_CONFIG="$(CHECK_KCONFIG)" $(PYTHON) -m olddefconfig
	rf="$$(python3 tools/kconfig_to_cargo.py --rustflags "$(CHECK_KCONFIG)")"; \
	if [ -n "$$rf" ]; then export RUSTFLAGS="$$rf"; else unset RUSTFLAGS; fi; \
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(CHECK_KCONFIG)" \
	    $(CARGO) check --release -p azos_kernel \
	    $$(python3 tools/kconfig_to_cargo.py "$(CHECK_KCONFIG)" | tr -s ' ') \
	    $(if $(CHECK_FEATURES),--features $(CHECK_FEATURES))

# ── CI: build all feature combinations (0 errors, 0 warnings). ───────────────
ci:
	@env -u CARGO_TARGET_DIR bash tools/ci_check.sh

# The short tiers (tools/gate_tier.sh): N0 the edit loop (`cargo check` per
# ISA + the host suites the diff reaches), N1 the front check (N0's suites,
# then the per-ISA smoke boots and the gate rows the diff maps to,
# tools/rows_for_diff.py). GATE_BASE=<rev> diffs against a revision, not HEAD.
# N0 also runs the output-dir lint (tools/out_dir_lint.py): nothing may write
# into the checkout.
check0:
	@env -u CARGO_TARGET_DIR bash tools/gate_tier.sh n0

check1:
	@env -u CARGO_TARGET_DIR bash tools/gate_tier.sh n1

# Every preset (config/Kconfig.preset) expands on every ISA and the cargo
# bridge accepts it (tools/check_presets.py). No kernel is built.
check-presets:
	@$(PYTHON) tools/check_presets.py

# No preset's topology breaks a neverallow rule (tools/check_neverallow.py):
# the built-in topology of every preset on every ISA, of every defconfig, and
# the micro kernel's, against crates/core/topology/src/neverallow.rs. Host
# builds only; no kernel is built and nothing boots.
check-neverallow:
	@$(PYTHON) tools/check_neverallow.py

# The two `unsafe` ratchets (tools/unsafe_budget.py, baseline
# tools/unsafe_budget.tsv): per crate the unsafe count and whether it forbids
# unsafe code, per kernel crate and in total the share of code lines in files
# with unsafe. The gate's n0 tier and tools/ci_check.sh run it too.
.PHONY: unsafe-budget
unsafe-budget:
	@$(PYTHON) tools/unsafe_budget.py --self-test
	@$(PYTHON) tools/unsafe_budget.py

# The size budget (tools/size_budget.py, baseline tools/size_budget.tsv): the
# .text/.rodata/.data/.bss of the kernel `make build` makes, built from
# config/defconfigs/qemu.config as shipped (neither the developer's .config nor
# qemu-dev.config's log level) and from no caller RUSTFLAGS, into a target dir
# of its own so it never invalidates the development build. The config is
# rewritten only when its text changes: a fresh mtime would rebuild every
# crate behind azos_limits. Build only; nothing boots.
# `make size-update REASON=".."` moves the baseline (in the commit that grows
# or shrinks the image).
SIZE_DEFCONFIG  := config/defconfigs/qemu.config
SIZE_KCONFIG    := $(OUT_BUILD)/size-riscv64.config
SIZE_TARGET_DIR := $(AZOS_OUT)/target/size
SIZE_ELF        := $(SIZE_TARGET_DIR)/$(TARGET)/release/kernel
SIZE_LABEL      := riscv64-qemu
.PHONY: size-kernel size-check size-update
$(SIZE_KCONFIG): $(SIZE_DEFCONFIG) FORCE
	@mkdir -p $(dir $@)
	@cp $(SIZE_DEFCONFIG) $@.new
	@KCONFIG_CONFIG=$@.new $(PYTHON) -m olddefconfig >/dev/null
	@if cmp -s $@.new $@; then rm -f $@.new; else mv $@.new $@; fi

size-kernel: $(SIZE_KCONFIG) | $(IMAGE_HASHES)
	rf="$$(python3 tools/kconfig_to_cargo.py --rustflags --toml --skip-base $(SIZE_KCONFIG))"; \
	isa=""; [ -z "$$rf" ] || isa="target.$(TARGET).rustflags=[$$rf]"; \
	env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(SIZE_KCONFIG)" \
	    $(CARGO) build --release --target-dir $(SIZE_TARGET_DIR) -p azos_kernel --features qemu \
	    $${isa:+--config "$$isa"} $$(python3 tools/kconfig_to_cargo.py --base $(SIZE_KCONFIG))
	@$(MAKE) --no-print-directory prune

size-check: size-kernel
	@$(PYTHON) tools/size_budget.py --self-test
	@$(PYTHON) tools/size_budget.py $(SIZE_LABEL)=$(SIZE_ELF)

size-update: size-kernel
	@test -n "$(REASON)" || { echo 'make size-update REASON="why the image moved"'; exit 1; }
	@$(PYTHON) tools/size_budget.py --report $(SIZE_LABEL)=$(SIZE_ELF)
	@$(PYTHON) tools/size_budget.py --update --reason "$(REASON)" $(SIZE_LABEL)=$(SIZE_ELF)

# The fronts' check (tools/check_fast.sh): per ISA one ktest boot, one boot
# of the same kernel with every composable runtime canary armed, one
# userspace (abitest) boot, judged by tools/check_fast.py. CI_JOBS ISAs at once.
check-fast:
	@env -u CARGO_TARGET_DIR bash tools/check_fast.sh

# Full CI: azos builds + AzOSRobotBrain tests + protocol sync.
ci-full:
	@bash tools/ci_full.sh

