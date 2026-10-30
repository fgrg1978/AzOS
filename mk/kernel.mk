# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Kernel: the build recipes (the configured system, boards, the riscv64,
# aarch64 and x86_64 kernels, micro), the Kconfig targets and the expanded
# configurations.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# `make build`: the system $(KCONFIG_CONFIG) selects (mk/vars.mk, "The
# configured system"). The ISA's expanded configuration is made by a make of
# its own first: the images' codegen flags are read from it when the makefiles
# are (RV_USER_ISA, AARCH64_USER_ISA), so it must exist before the make that
# builds them starts.
.PHONY: riscv64
build: $(KCONFIG_CONFIG) $(QEMU_DEV_KCONFIG)
	@$(MAKE) --no-print-directory $(SYSTEM_KCONFIG)
	@$(MAKE) --no-print-directory $(SYSTEM_KERNEL) $(SYSTEM_VOLUME)
	@$(MAKE) --no-print-directory prune
	@echo "[BUILD] $(KCONFIG_ISA), from $(KCONFIG_CONFIG) ($(SYSTEM_KCONFIG)):"
	@echo "  kernel  $(KERNEL_IMAGE)"
	@echo "  volume  $(SYSTEM_VOLUME)"
	@echo "  SDK     sdk/targets/$(USER_TARGET).json; a std program: $(SDK_BUILD) --manifest-path <crate>/Cargo.toml"
	@echo "  boot    make qemu"

# The riscv64 kernel of $(QEMU_DEV_KCONFIG): `make build` with a riscv64
# configuration.
riscv64: $(IMAGE_HASHES) $(KCONFIG_CONFIG) $(QEMU_DEV_KCONFIG)
	$(QEMU_DEV_ISA) $(QEMU_DEV_ENV) $(CARGO) build $(CARGO_FLAGS) -p azos_kernel \
		$${isa:+--config "$$isa"} \
		$(QEMU_DEV_ARGS)

# Cargo never deletes an artifact: every feature set leaves another copy of
# every crate in deps/. `prune` drops crates this tree no longer has and build
# variants not among the newest 8 per crate AND older than 7 days
# (tools/build/prune_build.py; PRUNE_ARGS="--dry-run" to only report). Every build
# target runs it; the gate runs it at start.
PRUNE_ARGS ?= --quiet
prune:
	@python3 tools/build/prune_build.py $(PRUNE_ARGS)

# Build kernel with RVV 1.0 support (requires QEMU with -cpu rv64,v=true):
# the development configuration with the vector extension probed (RV_V_PROBE).
build-rvv: $(IMAGE_HASHES) $(QEMU_DEV_KCONFIG)
	$(call kernel_select,$(QEMU_DEV_KCONFIG),CONFIG_RV_V_PROBE=y,$(OUT_BUILD)/qemu-dev-rvv.config); \
	$(QEMU_DEV_ISA) KCONFIG_CONFIG="$(OUT_BUILD)/qemu-dev-rvv.config" $(CARGO) build $(CARGO_FLAGS) -p azos_kernel $${isa:+--config "$$isa"} $$args
	@$(MAKE) --no-print-directory prune

# Build kernel with the fleet defconfig (HWCLASS_SERVER) and the fleet linker script
# (1022 MiB RAM region for the 256 MiB heap + per-task tables that
# overflow the default 8 MiB linker).  This target is the kernel side of
# the fleet defconfig and runs only on gateway boards with
# >= 1 GiB RAM.  Not part of the default `build` target — opt-in.
build-fleet: $(IMAGE_HASHES_BOARD) $(OUT_BUILD)/disk-board-fleet.img
	$(call require_board_key,FLEET)
	$(call check_board_priv_if_given,FLEET)
	@$(MAKE) defconfig-generic-server-riscv64+board-generic
	$(call kernel_select,.config,board-image,$(OUT_BUILD)/fleet-image.config); \
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" KCONFIG_CONFIG="$(OUT_BUILD)/fleet-image.config" \
	RUSTFLAGS="$(FLEET_RUSTFLAGS) $$(python3 tools/build/kconfig_to_cargo.py --rustflags .config)" \
	$(CARGO) build $(CARGO_FLAGS) -p azos_kernel $$args
	@echo "[FLEET] kernel built, volume $(OUT_BUILD)/disk-board-fleet.img (signed topology) — use a gateway board with >= 1 GiB RAM"
	@$(MAKE) --no-print-directory prune

# Build the minimal hello.elf user-space test binary + GPIO ring-3 driver.
# ── VisionFive 2 targets ──────────────────────────────────────────────────────

# U12-2: expand config/defconfigs/robot-sbc-riscv64+vf2.config the way `aarch64:` expands its own
# profile, instead of building from whatever the workspace `.config` happens
# to hold. Before this, `vf2:` never read config/defconfigs/robot-sbc-riscv64+vf2.config at all — only
# comments referenced it — so a VF2 image built after `make defconfig-generic-sbc-riscv64-dev`
# (BOARD_QEMU, RAM_SIZE=256) shipped an 8 GiB board's `azos_limits` with
# QEMU's 256 MiB expected-RAM bound, silently.
# The config of each vf2 variant: the profile, the lines the variant adds
# (VF2_EXTRA_<variant>), olddefconfig, and a guard that every one of them survived the
# expansion (a symbol that does not exist, or whose dependency is unmet, is
# dropped silently otherwise). VF2_KCONFIG, the variant of this invocation,
# is defined with BUILD_TYPE.
VF2_VARIANT_CONFIGS := $(OUT_BUILD)/vf2-dev.config $(OUT_BUILD)/vf2-ktest.config $(OUT_BUILD)/vf2-pstore.config
VF2_EXTRA_dev    := CONFIG_BUILD_TYPE_DEV=y
# ktest runs in kernel_main after install_topology: under the profile's
# TOPOLOGY_SOURCE_SIGNED_REQUIRED a board with no working storage would halt
# there, before the first test. The test kernel takes the built-in topology.
# A development build defaults LOCKDEP_HOLD_ENFORCE off (QEMU's timer is host
# wall time); on the board the hold times are real, so the ktest image enforces.
VF2_EXTRA_ktest  := CONFIG_BUILD_TYPE_DEV=y CONFIG_KTEST=y CONFIG_TOPOLOGY_SOURCE_BUILTIN=y CONFIG_LOCKDEP_HOLD_ENFORCE=y
VF2_EXTRA_pstore := CONFIG_BUILD_TYPE_DEV=y CONFIG_PSTORE_SIZE_KB=4
VF2_KCONFIG_DEPS := config/defconfigs/robot-sbc-riscv64+vf2.config \
		$(KCONFIG_FILES)

# What a variant adds is a stamp its config depends on (rewritten only when the
# text changes): a config built before the variant's lines changed is rebuilt,
# not trusted.
.PRECIOUS: $(OUT_BUILD)/vf2-%.extra
$(OUT_BUILD)/vf2-%.extra: FORCE
	@mkdir -p $(OUT_BUILD)
	@[ "$$(cat $@ 2>/dev/null)" = "$(VF2_EXTRA_$*)" ] || printf '%s\n' "$(VF2_EXTRA_$*)" > $@

$(OUT_BUILD)/vf2.config: $(VF2_KCONFIG_DEPS)
	@mkdir -p $(OUT_BUILD)
	cp config/defconfigs/robot-sbc-riscv64+vf2.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_VF2=y$$' $@ || { echo "[VF2] $@ lost CONFIG_BOARD_VF2"; exit 1; }

$(VF2_VARIANT_CONFIGS): $(OUT_BUILD)/vf2-%.config: $(VF2_KCONFIG_DEPS) $(OUT_BUILD)/vf2-%.extra
	@mkdir -p $(OUT_BUILD)
	cp config/defconfigs/robot-sbc-riscv64+vf2.config $@
	@for l in $(VF2_EXTRA_$*); do echo "$$l" >> $@; done
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_VF2=y$$' $@ || { echo "[VF2] $@ lost CONFIG_BOARD_VF2"; exit 1; }
	@for l in $(VF2_EXTRA_$*); do grep -qx "$$l" $@ || { echo "[VF2] $@ lost $$l"; exit 1; }; done

# The selection a vf2 kernel builds with beyond its config: the board volume's
# image table (BOARD_IMAGE), and the pstore variant's smoke
# (kernel/src/pstore.rs), a test hook.
VF2_SELECT := board-image$(if $(filter pstore,$(VF2_TEST)),$(comma)pstore-smoke)

# Build kernel for VisionFive 2 (JH7110). --target/--features come from the
# expanded profile through tools/build/kconfig_to_cargo.py, as `make aarch64` does;
# the linker script stays on the command line (RUSTFLAGS + --config), since
# the bridge only derives target/features, never link args.
# `make vf2 BUILD_TYPE=DEV` is the development image (see BUILD_TYPE above).
vf2: $(IMAGE_HASHES_BOARD) $(VF2_KCONFIG) $(VF2_DISK)
	$(call require_board_key,VF2)
	$(call check_board_priv_if_given,VF2)
	$(call kernel_select,$(VF2_KCONFIG),$(VF2_SELECT),$(VF2_KCONFIG:.config=-image.config)); \
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" \
	KCONFIG_CONFIG="$(VF2_KCONFIG:.config=-image.config)" \
	RUSTFLAGS="$(VF2_RUSTFLAGS) $$(python3 tools/build/kconfig_to_cargo.py --rustflags $(VF2_KCONFIG))" \
	$(CARGO) build --release --target-dir $(VF2_TARGET_DIR) -p azos_kernel $$args \
		--config "build.rustflags=['-C','link-arg=-T$(VF2_LINKER)']"
	@mkdir -p $(OUT_BUILD)
	riscv64-unknown-elf-objcopy -O binary \
		$(VF2_TARGET_DIR)/$(RISCV64_TARGET)/release/kernel $(VF2_BIN)
	@echo "[VF2] Built $(VF2_BIN) and its volume $(VF2_DISK) (signed topology)"
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

# The farm's runs (tools/dev/farm/README.md): build the development image, stage
# it on the board's TFTP root, power-cycle the board, judge its console. The
# farm check comes first: no board configured on this host is exit 3 before a
# build is spent on it.
FARM := python3 tools/dev/farm/farm.py
FARM_TARGET_DIR := $(OUT_TARGET)/farm
vf2-ktest:
	@$(FARM) check
	$(MAKE) --no-print-directory vf2 BUILD_TYPE=DEV VF2_TEST=ktest VF2_TARGET_DIR=$(FARM_TARGET_DIR)
	$(FARM) run ktest --kernel $(OUT_BUILD)/kernel-vf2-ktest.bin --elf $(FARM_TARGET_DIR)/$(RISCV64_TARGET)/release/kernel

vf2-pstore:
	@$(FARM) check
	$(MAKE) --no-print-directory vf2 BUILD_TYPE=DEV VF2_TEST=pstore VF2_TARGET_DIR=$(FARM_TARGET_DIR)
	$(FARM) run pstore --kernel $(OUT_BUILD)/kernel-vf2-pstore.bin

# Open serial console to VF2 (requires minicom or picocom).
vf2-console:
	@echo "[VF2] Opening $(VF2_SERIAL) at $(VF2_BAUD) baud (Ctrl+A X to exit)"
	picocom -b $(VF2_BAUD) $(VF2_SERIAL) || \
	minicom -b $(VF2_BAUD) -D $(VF2_SERIAL)

# ── SpacemiT K1 (BananaPi BPI-F3) targets ────────────────────────────────────

# U12-2: same fix as $(VF2_KCONFIG) above, for K1's own profile.
K1_KCONFIG := $(OUT_BUILD)/k1.config

# The fleet profile expanded on its own (wave 15): `build-fleet` expands it
# into the workspace .config (`defconfig-generic-server-riscv64+board-generic`); its volume's topology is
# emitted from this copy, which the same defconfig yields.
$(OUT_BUILD)/fleet.config: config/defconfigs/generic-server-riscv64+board-generic.config \
		$(KCONFIG_FILES)
	@mkdir -p $(OUT_BUILD)
	cp config/defconfigs/generic-server-riscv64+board-generic.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig

$(K1_KCONFIG): config/defconfigs/robot-sbc-riscv64+k1.config \
		$(KCONFIG_FILES)
	@mkdir -p $(OUT_BUILD)
	cp config/defconfigs/robot-sbc-riscv64+k1.config $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_K1=y$$' $@ || { echo "[K1] $@ lost CONFIG_BOARD_K1"; exit 1; }

# Build kernel for K1 (RV64GCVB + native RVV 1.0, VLEN=256).
# The k1 feature automatically enables RVV code paths (kernel/Cargo.toml
# `k1 = ["rvv", ...]`); tools/build/kconfig_to_cargo.py additionally emits `rvv`
# explicitly for CONFIG_BOARD_K1, which is redundant with that feature edge,
# not in conflict with it.
k1: $(IMAGE_HASHES_BOARD) $(K1_KCONFIG) $(OUT_BUILD)/disk-board-k1.img
	$(call require_board_key,K1)
	$(call check_board_priv_if_given,K1)
	$(call kernel_select,$(K1_KCONFIG),board-image,$(K1_KCONFIG:.config=-image.config)); \
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" \
	KCONFIG_CONFIG="$(K1_KCONFIG:.config=-image.config)" \
	RUSTFLAGS="$(K1_RUSTFLAGS) $$(python3 tools/build/kconfig_to_cargo.py --rustflags $(K1_KCONFIG))" \
	$(CARGO) build --release -p azos_kernel $$args \
		--config "build.rustflags=['-C','link-arg=-T$(K1_LINKER)']"
	@mkdir -p $(OUT_BUILD)
	riscv64-unknown-elf-objcopy -O binary \
		$(OUT_TARGET)/$(RISCV64_TARGET)/release/kernel $(K1_BIN)
	@echo "[K1] Built $(K1_BIN) and its volume $(OUT_BUILD)/disk-board-k1.img (signed topology)"
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

# ── Kconfig targets ─────────────────────────────────────────────────
# Install kconfiglib first:
#   /opt/homebrew/bin/python3 -m pip install --user --break-system-packages kconfiglib

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

# kconfiglib has one curses front end, menuconfig (it takes no style argument).
nconfig: menuconfig

oldconfig:
	$(PYTHON) -m oldconfig

olddefconfig:
	$(PYTHON) -m olddefconfig

# `make defconfig`: two questions, the ISA (the host's by default) and the domain
# (a preset), and a defconfig that builds and boots in QEMU; ARCH= and PRESET=
# answer them. defconfig-<name> stays for boards and advanced combinations.
.PHONY: defconfig
defconfig:
	@name="$$($(PYTHON) tools/build/defconfig_menu.py $(if $(filter command line,$(origin ARCH)),--arch $(ARCH)) $(if $(PRESET),--preset $(PRESET)))" \
	  && $(MAKE) --no-print-directory defconfig-$$name \
	  && $(PYTHON) tools/build/defconfig_menu.py --after "$$name"

# A committed config/defconfigs/NAME.config, else NAME assembled from the
# fragments under config/fragments/ (tools/build/gen_defconfigs.py: the name is
# <preset>-<hwclass>-<arch>[-<build>][+<overlay>...]).
defconfig-%:
	@if [ -f $(KCONFIG_DEFCONFIG_DIR)/$*.config ]; then cp $(KCONFIG_DEFCONFIG_DIR)/$*.config $(KCONFIG_CONFIG); \
	else $(PYTHON) tools/build/gen_defconfigs.py --print '$*' >$(KCONFIG_CONFIG).new && mv $(KCONFIG_CONFIG).new $(KCONFIG_CONFIG); fi
	@KCONFIG_CONFIG=$(KCONFIG_CONFIG) $(PYTHON) -m olddefconfig
	@echo "[CONFIG] active = $*"

# The committed defconfigs, regenerated from their fragments (`make lint`
# checks them with --check).
.PHONY: defconfigs
defconfigs:
	$(PYTHON) tools/build/gen_defconfigs.py

.PHONY: savedefconfig
savedefconfig:
	@mkdir -p $(OUT_BUILD)
	$(PYTHON) -m savedefconfig --out $(OUT_BUILD)/last_saved.config

$(KCONFIG_CONFIG):
	@echo "[CONFIG] no .config — falling back to generic-sbc-riscv64-dev"
	@$(MAKE) defconfig-generic-sbc-riscv64-dev

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

# An expansion is made from the file its DEFCONFIG names: the .config's
# expansion when it selects the ISA, the shipped default otherwise. make
# compares modification times only, so after the .config changes ISA an
# expansion of the other source would be kept for being newer. The stamp
# holds the name of the source and is rewritten only when it changes.
define config_source_stamp
$(1).src: FORCE
	@mkdir -p $$(dir $$@)
	@printf '%s\n' '$(2)' | cmp -s - $$@ || printf '%s\n' '$(2)' >$$@
endef
$(eval $(call config_source_stamp,$(X86_64_KCONFIG),$(X86_64_DEFCONFIG)))
$(eval $(call config_source_stamp,$(AARCH64_KCONFIG),$(AARCH64_DEFCONFIG)))

.PHONY: x86_64
$(X86_64_KCONFIG): $(X86_64_DEFCONFIG) $(X86_64_KCONFIG).src $(KCONFIG_FILES)
	@mkdir -p $(dir $@)
	cp $(X86_64_DEFCONFIG) $@
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_ARCH_X86_64=y$$' $@ || { echo "[X86_64] $@ lost CONFIG_ARCH_X86_64"; exit 1; }

# The seccomp table of the x86_64 images (crates/core/sched/src/seccomp.rs).
x86_64: $(X86_64_KCONFIG) $(IMAGE_HASHES_X86_64)
	$(call kernel_select,$(X86_64_KCONFIG),$(X86_64_SELECT),$(X86_64_KCONFIG:.config=-sel.config)); \
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(X86_64_KCONFIG:.config=-sel.config)" CARGO_TARGET_DIR="$(X86_64_TARGET_DIR)" \
	    RUSTFLAGS="-C link-arg=-T$(X86_64_LINKER) -C relocation-model=static $(X86_64_DALEK) $$(python3 tools/build/kconfig_to_cargo.py --rustflags $(X86_64_KCONFIG))" \
	    $(CARGO) build --release -p azos_kernel $$args
	@mkdir -p $(OUT_BUILD)
	cp $(X86_64_ELF) $(X86_64_IMG)
	@echo "[X86_64] Built $(X86_64_IMG)"

.PHONY: aarch64

# U12-8: see the LIBSYS_SRC comment above — same iCloud-duplicate hazard,
# same fix, inlined rather than a shared variable so a board Kconfig rule
# defined earlier in this file (`$(VF2_KCONFIG)`/`$(K1_KCONFIG)`) does not
# depend on a `:=` assignment that has not been parsed yet.
$(AARCH64_KCONFIG): $(AARCH64_DEFCONFIG) $(AARCH64_KCONFIG).src \
		$(KCONFIG_FILES)
	@mkdir -p $(dir $@)
	cp $(AARCH64_DEFCONFIG) $@
	$(if $(AARCH64_PG_SUFFIX),echo "CONFIG_AARCH64_PAGE_$(subst -,,$(subst k,K,$(AARCH64_PG_SUFFIX)))=y" >> $@)
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_ARCH_AARCH64=y$$' $@ || { echo "[AARCH64] $@ lost CONFIG_ARCH_AARCH64"; exit 1; }
	@grep -q '^CONFIG_PAGE_SHIFT=$(if $(filter 16384,$(AARCH64_PAGE_SIZE)),14,$(if $(filter 65536,$(AARCH64_PAGE_SIZE)),16,12))$$' $@ \
		|| { echo "[AARCH64] $@ does not carry the $(AARCH64_PAGE_SIZE)-byte granule"; exit 1; }

# --target and --features come from the expanded profile through
# tools/build/kconfig_to_cargo.py, as `make build-fleet` does; the rule above has
# already checked CONFIG_ARCH_AARCH64=y, which that script maps to
# $(AARCH64_TARGET), so $(AARCH64_ELF) is the file cargo writes.
#
# `env -u CARGO_BUILD_RUSTFLAGS` and an explicit RUSTFLAGS: an environment
# RUSTFLAGS — even an empty one — overrides `build.rustflags`, so the script is
# passed here rather than through `--config`, where a stray variable in the
# caller's shell would silently drop it.
aarch64: $(AARCH64_KCONFIG) $(IMAGE_HASHES_AARCH64)
	env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(AARCH64_KCONFIG)" $(AARCH64_KTARGET_ENV) \
	    RUSTFLAGS="-C link-arg=-T$(AARCH64_LINKER) $$(python3 tools/build/kconfig_to_cargo.py --rustflags $(AARCH64_KCONFIG))" \
	    $(CARGO) build --release -p azos_kernel \
	    $$(python3 tools/build/kconfig_to_cargo.py $(AARCH64_KCONFIG) | tr -s ' ')
	@mkdir -p $(OUT_BUILD)
	"$(AARCH64_OBJCOPY)" -O binary $(AARCH64_ELF) $(AARCH64_IMG)
	@echo "[AARCH64] Built $(AARCH64_IMG)"
	@$(MAKE) --no-print-directory prune

# ── Raspberry Pi 5 (BCM2712, aarch64) ───────────────────────────────────────
# `make defconfig-robot-sbc-aarch64+rpi5` selects the board in .config. `make rpi5` expands the
# same profile into build/rpi5.config, builds the aarch64 kernel from it and
# writes the flat Image the Pi firmware loads, build/rpi5/kernel8.img: copy it
# to the SD card's FAT boot partition next to config.txt and the BCM2712 DTB.
# Every board fact comes from that DTB at boot, so the image holds none. Like
# every board target it needs the fleet's public key (TOPOLOGY_PUBKEY_PATH)
# and refuses the test key; the check runs first, before any user image is
# built.
#
# `make rpi5 BUILD_TYPE=DEV` is the bring-up image, build/rpi5-dev/kernel8.img
# from build/rpi5-dev.config: BUILD_TYPE_DEV (secure boot off, the TEST key
# allowed) and the built-in topology, since the Pi 5 has no storage driver
# yet and a release image halts at the signed boot slots it cannot read; and
# info-level console lines, the boot steps a board check reads.
RPI5_SUFFIX  := $(if $(BOARD_DEV),-dev)
RPI5_EXTRA   := $(if $(BOARD_DEV),CONFIG_BUILD_TYPE_DEV=y CONFIG_TOPOLOGY_SOURCE_BUILTIN=y CONFIG_LOG_LEVEL_INFO=y)
RPI5_KCONFIG := $(OUT_BUILD)/rpi5$(RPI5_SUFFIX).config
RPI5_IMG     := $(OUT_BUILD)/rpi5$(RPI5_SUFFIX)/kernel8.img
.PHONY: rpi5 rpi5-key
# The variant's lines as a stamp, as for the vf2 variants: a config expanded
# before they changed is rebuilt.
.PRECIOUS: $(OUT_BUILD)/rpi5$(RPI5_SUFFIX).extra
$(OUT_BUILD)/rpi5$(RPI5_SUFFIX).extra: FORCE
	@mkdir -p $(OUT_BUILD)
	@[ "$$(cat $@ 2>/dev/null)" = "$(RPI5_EXTRA)" ] || printf '%s\n' "$(RPI5_EXTRA)" > $@
$(RPI5_KCONFIG): config/defconfigs/robot-sbc-aarch64+rpi5.config $(OUT_BUILD)/rpi5$(RPI5_SUFFIX).extra \
		$(KCONFIG_FILES)
	@mkdir -p $(OUT_BUILD)
	cp config/defconfigs/robot-sbc-aarch64+rpi5.config $@
	@for l in $(RPI5_EXTRA); do echo "$$l" >> $@; done
	KCONFIG_CONFIG=$@ $(PYTHON) -m olddefconfig
	@grep -q '^CONFIG_BOARD_RPI5=y$$' $@ || { echo "[RPI5] $@ lost CONFIG_BOARD_RPI5"; exit 1; }
	@for l in $(RPI5_EXTRA); do grep -qx "$$l" $@ || { echo "[RPI5] $@ lost $$l"; exit 1; }; done

rpi5-key:
	$(call require_board_key,RPI5)

rpi5: rpi5-key $(KCONFIG_CONFIG) $(RPI5_KCONFIG) $(IMAGE_HASHES_AARCH64)
	TOPOLOGY_PUBKEY_PATH="$(BOARD_TOPOLOGY_KEY)" env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$(RPI5_KCONFIG)" $(AARCH64_KTARGET_ENV) \
	    RUSTFLAGS="-C link-arg=-T$(AARCH64_LINKER) $$(python3 tools/build/kconfig_to_cargo.py --rustflags $(RPI5_KCONFIG))" \
	    $(CARGO) build --release -p azos_kernel \
	    $$(python3 tools/build/kconfig_to_cargo.py $(RPI5_KCONFIG) | tr -s ' ')
	@mkdir -p $(dir $(RPI5_IMG))
	"$(AARCH64_OBJCOPY)" -O binary $(AARCH64_ELF) $(RPI5_IMG)
	@echo "[RPI5] Built $(RPI5_IMG)"

# ── AzOS-micro: the MCU kernel (strategic plan, phase 8) ─────────────────────
#
# A separate kernel (micro/, its own workspace): riscv32imac, M-mode, PMP
# region domains. It is built from the same Kconfig (config/kernel/Kconfig.micro,
# config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config), reads a signed topology in the main
# kernel's format, and shares the pure crates of the main kernel. Nothing
# here touches the main kernel's build or its .config.
#
#   make micro-config     build/micro.config from config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config
#   make micro-topology   build/micro/topology/{CAPS.TOM,CAPS.SIG,SCHED.TOM}
#   make micro-check      type-check the image (no link)
#   make micro            build/micro/azos-micro.elf
#   make micro-test       the host suite (tests/host/micro-tests)
#   make micro-qemu       run the image on QEMU virt rv32 (PMP on)
#
# The image verifies its topology against the TEST key (cargo feature
# dev-key, BUILD_TYPE_DEV in the defconfig); a fleet key is
# TOPOLOGY_PUBKEY_PATH with MICRO_FEATURES empty and TOPO_PRIV the matching
# private key. The rv32 target is built from source (`-Zbuild-std`, cargo
# config in micro/.cargo), so no rustup target is needed.
MICRO_CONFIG   := $(OUT_BUILD)/micro.config
MICRO_TOPO_DIR := $(OUT_BUILD)/micro/topology
MICRO_ELF      := $(OUT_BUILD)/micro/azos-micro.elf
MICRO_FEATURES ?= dev-key
MICRO_PRIV     ?= $(TEST_PRIV_KEY)
MICRO_ENV       = KCONFIG_CONFIG="$(abspath $(MICRO_CONFIG))" MICRO_TOPOLOGY_DIR="$(abspath $(MICRO_TOPO_DIR))"
MICRO_SRC      := $(wildcard micro/src/*.rs micro/src/tasks/*.rs) micro/Cargo.toml micro/build.rs micro/link.ld \
                  userspace/tests/captest/src/abi_cases.rs \
                  crates/core/sched/src/sc.rs crates/core/sched/src/rt_core.rs \
                  crates/core/sync/src/pi_attr.rs \
                  crates/core/libsys/Cargo.toml crates/core/libsys/src/rv32.rs

.PHONY: micro-config micro-topology micro-check micro micro-test micro-qemu
micro-config: $(MICRO_CONFIG)
# Every Kconfig file: a symbol added to any of them (config/limits/Kconfig.limits) must reach
# micro.config, or azos_limits refuses the stale file in micro-tests.
$(MICRO_CONFIG): config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config $(KCONFIG_FILES)
	@mkdir -p $(@D)
	cp config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config $@
	KCONFIG_CONFIG="$@" $(PYTHON) -m olddefconfig
	@echo "[CONFIG] micro = config/defconfigs/generic-embedded-riscv64-dev+board-generic+micro.config"

micro-topology: $(MICRO_TOPO_DIR)/CAPS.SIG
$(MICRO_TOPO_DIR)/CAPS.SIG: micro/topology/CAPS.in micro/topology/SCHED.TOM tools/build/micro_topology.py tools/sign/gen_config_sig.py $(MICRO_PRIV)
	python3 tools/build/micro_topology.py $(MICRO_TOPO_DIR) --priv $(MICRO_PRIV)

micro-check: $(MICRO_CONFIG) $(MICRO_TOPO_DIR)/CAPS.SIG
	cd micro && CARGO_TARGET_DIR="$(OUT_TGT)/micro" $(MICRO_ENV) $(CARGO) check --release --features "$(MICRO_FEATURES)" --lib --bins

micro: $(MICRO_ELF)
$(MICRO_ELF): $(MICRO_CONFIG) $(MICRO_TOPO_DIR)/CAPS.SIG $(MICRO_SRC)
	cd micro && CARGO_TARGET_DIR="$(OUT_TGT)/micro" $(MICRO_ENV) $(CARGO) build --release --features "$(MICRO_FEATURES)" --bin azos_micro
	@mkdir -p $(@D)
	cp $(OUT_TGT)/micro/riscv32imac-unknown-none-elf/release/azos_micro $@
	@echo "[MICRO] $@ ($$(wc -c < $@) bytes)"

micro-test: $(MICRO_CONFIG)
	cd tests/host/micro-tests && CARGO_TARGET_DIR="$(OUT_TGT)/tests/host/micro-tests" $(MICRO_ENV) $(CARGO) test --release

micro-qemu: $(MICRO_ELF)
	qemu-system-riscv32 -machine virt -cpu rv32 -bios none -nographic -serial mon:stdio -kernel $(MICRO_ELF)

