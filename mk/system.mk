# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The configured system: the selection of ring-3 images and the system volume
# `make build` and `make qemu` use, one per ISA.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# The images the .config enables (USER_ON, mk/vars.mk), written only when the
# selection changes, so the digest tables and the volumes follow Kconfig and not
# only the ELFs' timestamps.
$(USER_ON_STAMP): FORCE
	@mkdir -p $(OUT_BUILD)
	@printf '%s\n' "$(foreach e,$(IMAGE_ELFS_ON),$(firstword $(subst =, ,$(e))))" > $@.tmp \
	  && { cmp -s $@.tmp $@ && rm -f $@.tmp || mv -f $@.tmp $@; }

# A system volume carries exactly the images of its selection (SYS_ELFS) and
# the data files its kernel reads. The scenario volumes of the gate
# (mk/images.mk) carry fixed sets for their rows and are not built from this.
# BEHAVIOR.MBL and POLICY.* are the ML service's model files; they are copied
# whatever the selection, as the kernel's behavior task looks for them.
define system_volume_recipe
	@mkdir -p $(OUT_BUILD)
	dd if=/dev/zero of=$@ bs=1M count=32
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "Hello from AzOS FAT32!\n" > $@.tmp_hello.txt
	@printf "$(SYS_INI)autorun=\n" > $@.tmp_config.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" > $@.tmp_bootmeta
	mcopy -i $@ $@.tmp_hello.txt ::HELLO.TXT
	$(if $(filter PKGD PKG,$(USER_ON)),mmd -i $@ ::PKG)
	$(foreach e,$(SYS_ELFS),mcopy -i $@ $(lastword $(subst =, ,$(e))) ::$(firstword $(subst =, ,$(e)));)
	mcopy -i $@ $(OUT_BUILD)/behavior.mbl ::BEHAVIOR.MBL
	mcopy -i $@ $(OUT_BUILD)/policy.gguf ::POLICY.GGF
	mcopy -i $@ $(OUT_BUILD)/policy.sig ::POLICY.SIG
	$(call provision_and_sign_config,$@.tmp_config.ini,$@.tmp_config.sig)
	mcopy -i $@ $@.tmp_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta ::BOOTMETA
	@rm -f $@.tmp_hello.txt $@.tmp_config.ini $@.tmp_config.sig $@.tmp_bootmeta
	@echo "[DISK] $(SYS_ISA) FAT32 image: $@ ($(words $(SYS_ELFS)) ring-3 images from $(KCONFIG_CONFIG))"
endef

SYSTEM_VOLUME_BASE_riscv64 = $(OUT_BUILD)/disk-system.img
SYSTEM_VOLUME_BASE_aarch64 = $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-system.img
SYSTEM_VOLUME_BASE_x86_64  = $(OUT_BUILD)/disk-x86_64-system.img

SYSTEM_DATA = $(OUT_BUILD)/policy.gguf $(OUT_BUILD)/policy.sig $(OUT_BUILD)/behavior.mbl \
              $(TEST_PRIV_KEY) $(CONFIG_SIG_TOOLS) $(USER_ON_STAMP)

$(SYSTEM_VOLUME_BASE_riscv64): SYS_ISA := riscv64
$(SYSTEM_VOLUME_BASE_riscv64): SYS_INI := $(DISK_INI_riscv64)
$(SYSTEM_VOLUME_BASE_riscv64): SYS_ELFS = $(IMAGE_ELFS_ON)
$(SYSTEM_VOLUME_BASE_riscv64): $(IMAGE_ELF_PATHS_ON) $(SYSTEM_DATA)
	$(system_volume_recipe)

$(SYSTEM_VOLUME_BASE_aarch64): SYS_ISA := aarch64
$(SYSTEM_VOLUME_BASE_aarch64): SYS_INI := $(DISK_INI_aarch64)
$(SYSTEM_VOLUME_BASE_aarch64): SYS_ELFS = $(IMAGE_ELFS_AARCH64_ON)
$(SYSTEM_VOLUME_BASE_aarch64): $(IMAGE_ELF_PATHS_AARCH64_ON) $(SYSTEM_DATA)
	$(system_volume_recipe)

$(SYSTEM_VOLUME_BASE_x86_64): SYS_ISA := x86_64
$(SYSTEM_VOLUME_BASE_x86_64): SYS_INI := $(DISK_INI_x86_64)
$(SYSTEM_VOLUME_BASE_x86_64): SYS_ELFS = $(IMAGE_ELFS_X86_64_ON)
$(SYSTEM_VOLUME_BASE_x86_64): $(IMAGE_ELF_PATHS_X86_64_ON) $(SYSTEM_DATA)
	$(system_volume_recipe)

# The same volume plus BusyBox (BUSYBOX_ON), which is third-party and has no
# USERSPACE_ symbol of its own: BUSYBOX is its Kconfig choice.
define system_busybox_recipe
	@[ -f "$(SYS_BUSYBOX)" ] || { echo "no $(SYS_BUSYBOX): run make busybox"; exit 1; }
	cp $< $@
	mcopy -i $@ "$(SYS_BUSYBOX)" ::BUSYBOX.ELF
	@echo "[DISK] FAT32 image: $@ (the system volume plus third-party BUSYBOX.ELF)"
endef

$(OUT_BUILD)/disk-system-busybox.img: SYS_BUSYBOX := $(BUSYBOX_ELF_RISCV64)
$(OUT_BUILD)/disk-system-busybox.img: $(SYSTEM_VOLUME_BASE_riscv64) $(wildcard $(BUSYBOX_ELF_RISCV64))
	$(system_busybox_recipe)

$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-system-busybox.img: SYS_BUSYBOX := $(BUSYBOX_ELF_AARCH64)
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-system-busybox.img: $(SYSTEM_VOLUME_BASE_aarch64) $(wildcard $(BUSYBOX_ELF_AARCH64))
	$(system_busybox_recipe)

$(OUT_BUILD)/disk-x86_64-system-busybox.img: SYS_BUSYBOX := $(BUSYBOX_ELF_X86_64)
$(OUT_BUILD)/disk-x86_64-system-busybox.img: $(SYSTEM_VOLUME_BASE_x86_64) $(wildcard $(BUSYBOX_ELF_X86_64))
	$(system_busybox_recipe)
