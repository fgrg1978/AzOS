# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Checks: `make ARCH=<isa> check` and the CI tiers (check0, check1, ...).
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# ── make ARCH=<isa> check ───────────────────────────────────────────────────
# Type-check the kernel for one ISA without linking (config/arch/Kconfig.isa
# ARCH_RISCV64 / ARCH_AARCH64 / ARCH_X86_64). The target triple
# and the baseline codegen flags (`--rustflags`: x86_64's X86_64_LEVEL) come
# from the expanded defconfig through tools/build/kconfig_to_cargo.py, and
# `-Zbuild-std` (.cargo/config.toml) builds core/alloc from rust-src, so no
# target has to be installed. RUSTFLAGS is set only when the ISA has baseline
# flags: an empty one would override riscv64's build.rustflags.
# CHECK_PRESET picks the gate cell: generic (the default, the image the gate
# is about), robot (the robot worked example, which links crates/domains/robot/)
# or microvm (a virtual machine's kernel: no Linux personality and no GUI, so
# its cell has the QEMU overlay alone).
CHECK_PRESET ?= generic
CHECK_OVERLAYS_microvm := qemu
CHECK_OVERLAYS = $(or $(CHECK_OVERLAYS_$(CHECK_PRESET)),qemu+linux+gui)
CHECK_DEFCONFIG_riscv64 = config/defconfigs/$(CHECK_PRESET)-sbc-riscv64-dev+$(CHECK_OVERLAYS).config
CHECK_DEFCONFIG_aarch64 = config/defconfigs/$(CHECK_PRESET)-sbc-aarch64-dev+$(CHECK_OVERLAYS).config
CHECK_DEFCONFIG_x86_64  = config/defconfigs/$(CHECK_PRESET)-sbc-x86_64-dev+$(CHECK_OVERLAYS).config
CHECK_KCONFIG := $(OUT_BUILD)/check-$(ARCH)-$(CHECK_PRESET).config
# The image table the kernel `include!`s, made when missing (order-only: a
# type-check never waits for a userspace rebuild; `make` refreshes the table).
# Without it a fresh worktree's `make check0` failed in azos_sched.
CHECK_TABLE_riscv64 := $(IMAGE_HASHES)
CHECK_TABLE_aarch64 := $(IMAGE_HASHES_AARCH64)
CHECK_TABLE_x86_64  := $(OUT_BUILD)/image_hashes_x86_64.rs $(THIRDPARTY_HASHES_X86_64)

.PHONY: check
# CHECK_SELECT is a selection on the cell (`make check CHECK_SELECT=ktest`,
# tools/build/kconfig_to_cargo.py --select): a ktest-only file is otherwise never compiled.
CHECK_SELECT ?=
# CHECK_APPEND adds lines to the cell's config before it is expanded
# (`make check CHECK_APPEND='# CONFIG_KLOG is not set'`: a cell the defconfigs
# do not name, such as the structured log off with its sink built).
CHECK_APPEND ?=
# The profile of the type-check: release (the default) or validate
# (.cargo/config.toml: release's code, 16 codegen units, incremental), which
# `make check0 COMPILE_ONLY=1` and `make check-compile` use. Neither emits code.
CHECK_PROFILE ?= release
CHECK_PROFILE_FLAG = $(if $(filter release,$(CHECK_PROFILE)),--release,--profile $(CHECK_PROFILE))
# The target dir of the type-check: the output root's, or one per ISA under
# AZOS_SHARED_TARGET (tools/gate/validate_env.sh) so that build-std and the
# crates.io dependencies are built once for every checkout.
CHECK_TARGET_DIR ?= $(if $(AZOS_SHARED_TARGET),$(AZOS_SHARED_TARGET)/check-$(ARCH),$(OUT_TARGET))
# With a shared target dir the units of this checkout's packages are tagged, so no two checkouts share one.
CHECK_CARGO_CONFIG = $(if $(and $(AZOS_SHARED_TARGET),$(filter validate,$(CHECK_PROFILE))),-Zprofile-rustflags --config 'profile.validate.rustflags=["--cfg"$(comma)"azos_wt=\"$(AZOS_WT_TAG)\""]' --config 'profile.validate.package."*".rustflags=[]')
check: | $(CHECK_TABLE_$(ARCH))
	@test -n "$(CHECK_DEFCONFIG_$(ARCH))" || { echo "[CHECK] unknown ARCH=$(ARCH) (riscv64, aarch64, x86_64)"; exit 1; }
	@mkdir -p $(OUT_BUILD)
	cp "$(CHECK_DEFCONFIG_$(ARCH))" "$(CHECK_KCONFIG)"
	@if [ -n "$(CHECK_APPEND)" ]; then printf '%s\n' "$(CHECK_APPEND)" >> "$(CHECK_KCONFIG)"; fi
	KCONFIG_CONFIG="$(CHECK_KCONFIG)" $(PYTHON) -m olddefconfig
	$(call kernel_select,$(CHECK_KCONFIG),$(CHECK_SELECT),$(CHECK_KCONFIG:.config=-sel.config)); \
	rf="$$(python3 tools/build/kconfig_to_cargo.py --rustflags "$(CHECK_KCONFIG)")"; \
	if [ -n "$$rf" ]; then export RUSTFLAGS="$$rf"; else unset RUSTFLAGS; fi; \
	env -u CARGO_BUILD_RUSTFLAGS CARGO_TARGET_DIR="$(CHECK_TARGET_DIR)" KCONFIG_CONFIG="$(CHECK_KCONFIG:.config=-sel.config)" \
	    $(CARGO) check $(CHECK_PROFILE_FLAG) $(CHECK_CARGO_CONFIG) -p azos_kernel $$args

.PHONY: check-deps
# The kernel's dependency set for the type-check's cell (`cargo tree`, no
# build): one package name a line. tools/lint/profile_cut_lint.py reads it.
check-deps: | $(CHECK_TABLE_$(ARCH))
	@test -n "$(CHECK_DEFCONFIG_$(ARCH))" || { echo "[CHECK] unknown ARCH=$(ARCH) (riscv64, aarch64, x86_64)"; exit 1; }
	@mkdir -p $(OUT_BUILD)
	@cp "$(CHECK_DEFCONFIG_$(ARCH))" "$(CHECK_KCONFIG)"
	@KCONFIG_CONFIG="$(CHECK_KCONFIG)" $(PYTHON) -m olddefconfig >/dev/null
	@$(call kernel_select,$(CHECK_KCONFIG),$(CHECK_SELECT),$(CHECK_KCONFIG:.config=-sel.config)); \
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(CHECK_KCONFIG:.config=-sel.config)" \
	    $(CARGO) tree -p azos_kernel $$args -e normal --prefix none --format '{p}'

# ── CI: build all feature combinations (0 errors, 0 warnings). ───────────────
ci:
	@env -u CARGO_TARGET_DIR bash tools/gate/ci_check.sh

# The short tiers (tools/gate/gate_tier.sh): N0 the edit loop (`cargo check` per
# ISA + the host suites the diff reaches), N1 the front check (N0's suites,
# then the per-ISA smoke boots and the gate rows the diff maps to,
# tools/gate/rows_for_diff.py). GATE_BASE=<rev> diffs against a revision, not HEAD.
# N0 also runs the output-dir lint (tools/lint/out_dir_lint.py): nothing may write
# into the checkout.
check0:
	@env -u CARGO_TARGET_DIR bash tools/gate/gate_tier.sh n0

# The fastest check of a front: `cargo check` (no codegen, `validate` profile) of the
# kernel cells the diff reaches (ISAs and presets from the paths,
# tools/gate/compile_plan.py) and of the host suites it reaches; no lints, no
# budgets, nothing boots. `make check0 COMPILE_ONLY=1` is the batch form: check0's
# lints and host suites with the type-checks and the suites' builds in the validate
# profile. AZOS_SHARED_TARGET=<dir> shares build-std and the dependencies between
# checkouts, AZOS_SCCACHE=1 wraps rustc in sccache (tools/gate/validate_env.sh).
# Both profiles are for validation only: the size budget, vsbench and every
# measurement row stay on `release`.
.PHONY: check-compile
check-compile:
	@env -u CARGO_TARGET_DIR bash tools/gate/gate_tier.sh compile

# Every lint of the tree and nothing else, no build (the lint role's one entry
# point; check0 runs the same list after its per-ISA checks).
.PHONY: lint
lint:
	@env -u CARGO_TARGET_DIR bash tools/gate/gate_tier.sh lints

check1:
	@env -u CARGO_TARGET_DIR bash tools/gate/gate_tier.sh n1

# Every preset (config/axes/Kconfig.preset) expands on every ISA and the cargo
# bridge accepts it (tools/lint/check_presets.py). No kernel is built.
check-presets:
	@$(PYTHON) tools/lint/check_presets.py

# No preset's topology breaks a neverallow rule (tools/lint/check_neverallow.py):
# the built-in topology of every preset on every ISA, of every defconfig, and
# the micro kernel's, against crates/core/topology/src/neverallow.rs. Host
# builds only; no kernel is built and nothing boots.
check-neverallow:
	@$(PYTHON) tools/lint/check_neverallow.py

# The two `unsafe` ratchets (tools/lint/unsafe_budget.py, baseline
# tools/lint/unsafe_budget.tsv): per crate the unsafe count and whether it forbids
# unsafe code, per kernel crate and in total the share of code lines in files
# with unsafe. The gate's n0 tier and tools/gate/ci_check.sh run it too.
.PHONY: unsafe-budget
unsafe-budget:
	@$(PYTHON) tools/lint/unsafe_budget.py --self-test
	@$(PYTHON) tools/lint/unsafe_budget.py

# The size budget (tools/lint/size_budget.py, baseline tools/lint/size_budget.tsv): the
# .text/.rodata/.data/.bss of the kernel `make build` makes, built from
# config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config as shipped (neither the developer's .config nor
# qemu-dev.config's log level) and from no caller RUSTFLAGS, into a target dir
# of its own so it never invalidates the development build. The config is
# rewritten only when its text changes: a fresh mtime would rebuild every
# crate behind azos_limits. The kernel binds the image-hash table of the
# userspace images the configuration enables, so the table is made from this
# configuration too: its rows are .rodata, and what the last `make` here left
# (no .config: none; the gate's: all) moved the measure by a page. Build only;
# nothing boots.
# `make size-update REASON=".."` moves the baseline (in the commit that grows
# or shrinks the image).
SIZE_DEFCONFIG  := config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config
SIZE_KCONFIG    := $(OUT_BUILD)/size-riscv64.config
SIZE_TARGET_DIR := $(AZOS_OUT)/target/size
SIZE_ELF        := $(SIZE_TARGET_DIR)/$(RISCV64_TARGET)/release/kernel
SIZE_LABEL      := riscv64-qemu
.PHONY: size-kernel size-check size-update
$(SIZE_KCONFIG): $(SIZE_DEFCONFIG) FORCE
	@mkdir -p $(dir $@)
	@cp $(SIZE_DEFCONFIG) $@.new
	@KCONFIG_CONFIG=$@.new $(PYTHON) -m olddefconfig >/dev/null
	@if cmp -s $@.new $@; then rm -f $@.new; else mv $@.new $@; fi

size-kernel: $(SIZE_KCONFIG)
	KCONFIG_CONFIG="$(SIZE_KCONFIG)" $(MAKE) --no-print-directory $(IMAGE_HASHES)
	rf="$$(python3 tools/build/kconfig_to_cargo.py --rustflags --toml --skip-base $(SIZE_KCONFIG))"; \
	isa=""; [ -z "$$rf" ] || isa="target.$(RISCV64_TARGET).rustflags=[$$rf]"; \
	env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(SIZE_KCONFIG)" \
	    $(BUILDQ_BIN) $(CARGO) build --release --target-dir $(SIZE_TARGET_DIR) -p azos_kernel \
	    $${isa:+--config "$$isa"} $$(python3 tools/build/kconfig_to_cargo.py $(SIZE_KCONFIG))
	@$(MAKE) --no-print-directory prune

size-check: size-kernel
	@$(PYTHON) tools/lint/size_budget.py --self-test
	@$(PYTHON) tools/lint/size_budget.py $(SIZE_LABEL)=$(SIZE_ELF)

size-update: size-kernel
	@test -n "$(REASON)" || { echo 'make size-update REASON="why the image moved"'; exit 1; }
	@$(PYTHON) tools/lint/size_budget.py --report $(SIZE_LABEL)=$(SIZE_ELF)
	@$(PYTHON) tools/lint/size_budget.py --update --reason "$(REASON)" $(SIZE_LABEL)=$(SIZE_ELF)

# The microvm cells' size budget (labels x86_64-microvm and aarch64-microvm in
# tools/lint/size_budget.tsv): each ISA's kernel as `make x86_64` / `make
# aarch64` builds it from config/defconfigs/microvm-sbc-<isa>-dev+qemu.config,
# with the image table of that configuration, into target dirs of their own.
# `make size-update-microvm REASON=".."` moves both lines.
SIZE_MV_DIR := $(AZOS_OUT)/target/size-microvm
SIZE_MV_ELF_x86_64  := $(SIZE_MV_DIR)/x86_64/$(X86_64_TARGET)/release/kernel
SIZE_MV_ELF_aarch64 := $(SIZE_MV_DIR)/aarch64/$(AARCH64_TARGET)/release/kernel
SIZE_MV_LABELS := x86_64-microvm=$(SIZE_MV_ELF_x86_64) aarch64-microvm=$(SIZE_MV_ELF_aarch64)
.PHONY: size-kernel-microvm size-check-microvm size-update-microvm
size-kernel-microvm:
	@mkdir -p $(OUT_BUILD)
	@for isa in x86_64 aarch64; do \
	    k="$(OUT_BUILD)/size-$$isa-microvm.config"; \
	    cp "config/defconfigs/microvm-sbc-$$isa-dev+qemu.config" "$$k.new"; \
	    KCONFIG_CONFIG="$$k.new" $(PYTHON) -m olddefconfig >/dev/null; \
	    if cmp -s "$$k.new" "$$k"; then rm -f "$$k.new"; else mv "$$k.new" "$$k"; fi; \
	done
	KCONFIG_CONFIG="$(OUT_BUILD)/size-x86_64-microvm.config" $(MAKE) --no-print-directory x86_64 \
	    X86_64_DEFCONFIG=config/defconfigs/microvm-sbc-x86_64-dev+qemu.config \
	    X86_64_KCONFIG=$(OUT_BUILD)/size-x86_64-microvm.config X86_64_TARGET_DIR=$(SIZE_MV_DIR)/x86_64 \
	    X86_64_IMG=$(OUT_BUILD)/size-kernel-x86_64-microvm.elf
	KCONFIG_CONFIG="$(OUT_BUILD)/size-aarch64-microvm.config" $(MAKE) --no-print-directory aarch64 \
	    AARCH64_DEFCONFIG=config/defconfigs/microvm-sbc-aarch64-dev+qemu.config \
	    AARCH64_KCONFIG=$(OUT_BUILD)/size-aarch64-microvm.config AARCH64_USER_KCONFIG=$(OUT_BUILD)/size-aarch64-microvm.config \
	    AARCH64_KTARGET_ENV='CARGO_TARGET_DIR=$(SIZE_MV_DIR)/aarch64' AARCH64_ELF=$(SIZE_MV_ELF_aarch64) \
	    AARCH64_IMG=$(OUT_BUILD)/size-kernel-aarch64-microvm.img

size-check-microvm: size-kernel-microvm
	@$(PYTHON) tools/lint/size_budget.py $(SIZE_MV_LABELS)

size-update-microvm: size-kernel-microvm
	@test -n "$(REASON)" || { echo 'make size-update-microvm REASON="why the image moved"'; exit 1; }
	@$(PYTHON) tools/lint/size_budget.py --report $(SIZE_MV_LABELS)
	@$(PYTHON) tools/lint/size_budget.py --update --reason "$(REASON)" $(SIZE_MV_LABELS)

# RustSec advisories against the snapshot in third_party/advisory-db (tools/lint/advisories.sh).
.PHONY: advisories advisories-update
advisories:
	@bash tools/lint/advisories.sh check

advisories-update:
	@bash tools/lint/advisories.sh update

# The fronts' check (tools/gate/check_fast.sh): per ISA one ktest boot, one boot
# of the same kernel with every composable runtime canary armed, one
# userspace (abitest) boot, judged by tools/gate/check_fast.py. CI_JOBS ISAs at once.
check-fast:
	@env -u CARGO_TARGET_DIR bash tools/gate/check_fast.sh

# Full CI: azos builds, then the optional brain repo's tests and protocol sync (skipped when it is absent).
ci-full:
	@bash tools/gate/ci_full.sh

