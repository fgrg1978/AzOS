# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Images: the image-hash tables, FAT32 disk images, secure-boot fixtures, the
# board volumes and the signed topology files.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

$(IMAGE_HASHES_BOARD): userspace/image_hashes.py \
               $(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF_BOARD) \
               $(UHELLO_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) \
               $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) $(VSBENCH_ELF) \
               $(EPSRV_ELF) $(ABICHILD_ELF) $(VSSRV_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) \
               $(SH_ELF) $(TERMD_ELF) $(NAMESD_ELF) $(COMPMGR_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(TRACECTL_ELF) $(DECISD_ELF) $(INPUTD_ELF) $(COMPSRV_ELF) $(LOGD_ELF) $(WHY_ELF) $(PKGD_ELF_BOARD) $(PKG_ELF) $(RPCSRV_ELF) $(ZENOHD_ELF) $(VMMD_ELF) $(PTPD_ELF) $(AUDIOD_ELF) $(RPCQUIC_ELF) $(MCPD_ELF) $(SSHD_ELF) $(LOGIND_ELF) $(FAM_ELFS) $(LXSRV_ELF) $(LXHELLO_ELF)
	@mkdir -p $(BOARD_DIR)
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS_BOARD)

$(IMAGE_HASHES): userspace/image_hashes.py \
               $(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF) \
               $(UHELLO_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) \
               $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) $(VSBENCH_ELF) \
               $(EPSRV_ELF) $(ABICHILD_ELF) $(VSSRV_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) \
               $(SH_ELF) $(TERMD_ELF) $(NAMESD_ELF) $(COMPMGR_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(TRACECTL_ELF) $(DECISD_ELF) $(INPUTD_ELF) $(COMPSRV_ELF) $(LOGD_ELF) $(WHY_ELF) $(PKGD_ELF) $(PKG_ELF) $(RPCSRV_ELF) $(ZENOHD_ELF) $(VMMD_ELF) $(PTPD_ELF) $(AUDIOD_ELF) $(RPCQUIC_ELF) $(MCPD_ELF) $(SSHD_ELF) $(LOGIND_ELF) $(FAM_ELFS) $(LXSRV_ELF) $(LXHELLO_ELF) \
               $(if $(LXRT_NEED),$(LXRT_ELF))
	@mkdir -p $(OUT_BUILD)
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(OUT_BUILD)/thirdparty_hashes.rs \
		BUSYBOX.ELF=$(BUSYBOX_ELF_RISCV64) LXTHR.ELF=$(LXTHR_ELF_RISCV64)

$(OUT_BUILD)/disk-lxthr.img: $(OUT_BUILD)/disk-lxabi.img $(wildcard $(LXTHR_ELF_RISCV64))
	@[ -f "$(LXTHR_ELF_RISCV64)" ] || { echo "no $(LXTHR_ELF_RISCV64): run make lxthreads"; exit 1; }
	cp $(OUT_BUILD)/disk-lxabi.img $@
	mcopy -i $@ "$(LXTHR_ELF_RISCV64)" ::LXTHR.ELF
	@echo "[DISK] FAT32 image: $@ (user shell, LXHELLO.ELF, LXTHR.ELF)"

$(OUT_BUILD)/disk-aarch64-lxthr.img: $(OUT_BUILD)/disk-aarch64-lxabi.img $(wildcard $(LXTHR_ELF_AARCH64))
	@[ -f "$(LXTHR_ELF_AARCH64)" ] || { echo "no $(LXTHR_ELF_AARCH64): run make lxthreads"; exit 1; }
	cp $(OUT_BUILD)/disk-aarch64-lxabi.img $@
	mcopy -i $@ "$(LXTHR_ELF_AARCH64)" ::LXTHR.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell, LXHELLO.ELF, LXTHR.ELF)"

# The shell volume with LXHELLO.ELF plus BUSYBOX.ELF, for
# the `linux: busybox` gate rows. The image is copied by a quoted path on
# purpose: it is not one of IMAGE_ELFS (seccomp-tests scans `$(VAR)` copies).
$(OUT_BUILD)/disk-busybox.img: $(OUT_BUILD)/disk-lxabi.img $(wildcard $(BUSYBOX_ELF_RISCV64))
	@[ -f "$(BUSYBOX_ELF_RISCV64)" ] || { echo "no $(BUSYBOX_ELF_RISCV64): run make busybox"; exit 1; }
	cp $(OUT_BUILD)/disk-lxabi.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_RISCV64)" ::BUSYBOX.ELF
	@echo "[DISK] FAT32 image: $@ (user shell, LXHELLO.ELF, third-party BUSYBOX.ELF)"

# The system volume of a configuration with BUSYBOX (SYSTEM_VOLUME, mk/vars.mk):
# the shell volume plus BUSYBOX.ELF. The ELF is the cache's (`make busybox`,
# which `make build` runs first), copied by a quoted path as above.
$(OUT_BUILD)/disk-sh-busybox.img: $(OUT_BUILD)/disk-sh.img $(wildcard $(BUSYBOX_ELF_RISCV64))
	@[ -f "$(BUSYBOX_ELF_RISCV64)" ] || { echo "no $(BUSYBOX_ELF_RISCV64): run make busybox"; exit 1; }
	cp $(OUT_BUILD)/disk-sh.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_RISCV64)" ::BUSYBOX.ELF
	@echo "[DISK] FAT32 image: $@ (user shell + third-party BUSYBOX.ELF)"

$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-sh-busybox.img: $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-sh.img $(wildcard $(BUSYBOX_ELF_AARCH64))
	@[ -f "$(BUSYBOX_ELF_AARCH64)" ] || { echo "no $(BUSYBOX_ELF_AARCH64): run make busybox"; exit 1; }
	cp $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-sh.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_AARCH64)" ::BUSYBOX.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell + third-party BUSYBOX.ELF)"

$(OUT_BUILD)/disk-aarch64-busybox.img: $(OUT_BUILD)/disk-aarch64-lxabi.img $(wildcard $(BUSYBOX_ELF_AARCH64))
	@[ -f "$(BUSYBOX_ELF_AARCH64)" ] || { echo "no $(BUSYBOX_ELF_AARCH64): run make busybox"; exit 1; }
	cp $(OUT_BUILD)/disk-aarch64-lxabi.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_AARCH64)" ::BUSYBOX.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell, LXHELLO.ELF, third-party BUSYBOX.ELF)"

$(OUT_BUILD)/disk-x86_64-busybox.img: $(OUT_BUILD)/disk-x86_64.img $(wildcard $(BUSYBOX_ELF_X86_64))
	@[ -f "$(BUSYBOX_ELF_X86_64)" ] || { echo "no $(BUSYBOX_ELF_X86_64): run make busybox"; exit 1; }
	cp $(OUT_BUILD)/disk-x86_64.img $@
	mcopy -i $@ "$(BUSYBOX_ELF_X86_64)" ::BUSYBOX.ELF
	@echo "[DISK] x86_64 FAT32 image: $@ (user shell, LXHELLO.ELF, third-party BUSYBOX.ELF)"

$(IMAGE_HASHES_AARCH64): userspace/image_hashes.py \
               $(HELLO_ELF_AARCH64) $(SYSTEST_ELF_AARCH64) $(GPIO_DRV_ELF_AARCH64) $(MLSRV_ELF_AARCH64) \
               $(UHELLO_ELF_AARCH64) $(REFLEX_ELF_AARCH64) $(BRAINCLI_ELF_AARCH64) \
               $(CAPTEST_ELF_AARCH64) $(LATBENCH_ELF_AARCH64) $(ABITEST_ELF_AARCH64) \
               $(IPCTEST_ELF_AARCH64) $(VSBENCH_ELF_AARCH64) $(EPSRV_ELF_AARCH64) $(ABICHILD_ELF_AARCH64) \
               $(VSSRV_ELF_AARCH64) $(BUZZ_DRV_ELF_AARCH64) $(INA_DRV_ELF_AARCH64) \
               $(SH_ELF_AARCH64) $(TERMD_ELF_AARCH64) $(NAMESD_ELF_AARCH64) $(COMPMGR_ELF_AARCH64) $(TOOLBOX_ELF_AARCH64) $(POWER_ELF_AARCH64) $(TRACECTL_ELF_AARCH64) $(DECISD_ELF_AARCH64) $(INPUTD_ELF_AARCH64) $(COMPSRV_ELF_AARCH64) $(LOGD_ELF_AARCH64) $(WHY_ELF_AARCH64) $(PKGD_ELF_AARCH64) $(PKG_ELF_AARCH64) $(RPCSRV_ELF_AARCH64) $(ZENOHD_ELF_AARCH64) $(VMMD_ELF_AARCH64) $(PTPD_ELF_AARCH64) $(AUDIOD_ELF_AARCH64) $(RPCQUIC_ELF_AARCH64) $(MCPD_ELF_AARCH64) $(SSHD_ELF_AARCH64) $(LOGIND_ELF_AARCH64) $(FAM_ELFS_AARCH64) $(LXSRV_ELF_AARCH64) $(LXHELLO_ELF_AARCH64) \
               $(if $(LXRT_NEED),$(LXRT_ELF_AARCH64))
	@mkdir -p $(OUT_BUILD)
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS_AARCH64)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $(OUT_BUILD)/thirdparty_hashes_aarch64.rs \
		BUSYBOX.ELF=$(BUSYBOX_ELF_AARCH64) LXTHR.ELF=$(LXTHR_ELF_AARCH64)

# Two disk images from one recipe, differing only in which ELF `autorun` starts.
# disk.img keeps GPIODRV (the ring-3 driver demo); disk-systest.img runs the
# syscall test, which was built and copied onto the disk for months without
# anything ever invoking it.
$(OUT_BUILD)/disk.img:         AUTORUN_ELF := /fat/GPIODRV.ELF
$(OUT_BUILD)/disk-systest.img: AUTORUN_ELF := /fat/SYSTEST.ELF
$(OUT_BUILD)/disk-uhello.img:  AUTORUN_ELF := /fat/UHELLO.ELF
$(OUT_BUILD)/disk-reflex.img:  AUTORUN_ELF := /fat/REFLEX.ELF
$(OUT_BUILD)/disk-braincli.img: AUTORUN_ELF := /fat/BRAINCLI.ELF
# Wave 9 (P3): brain_client runs the encrypted link, and so does the
# kernel's own brain link (the link is always a Noise session) once the image
# carries a key (`disk-braincli-linkkey.img`) — both dial 10.0.2.2:9000, and
# SLIRP hides which is which. With both answered, the host peer would hand its
# script, e-stop included, to the kernel's link as well, and the ring-3 rows'
# ordering assertions would race it. `tools/gate/fake_brain.py --serve` recognises
# the kernel's session by its first message (PKT_STATUS; brain_client opens
# with PKT_SENSOR) and only drains it.
# `brain_client_rekey_secs=10` shortens brain_client's wall-clock rekey so one
# 40 s boot sees a client REKEY; the key can only shorten the interval.
$(OUT_BUILD)/disk-braincli.img: CFG_EXTRA := brain_client_rekey_secs=10\n
$(OUT_BUILD)/disk-captest.img: AUTORUN_ELF := /fat/CAPTEST.ELF
$(OUT_BUILD)/disk-latbench.img: AUTORUN_ELF := /fat/LATBENCH.ELF
$(OUT_BUILD)/disk-abitest.img: AUTORUN_ELF := /fat/ABITEST.ELF
# The envelope scenario runs no ring-3 program: it exercises the kernel's own
# actuation chokepoint and then reads the flight-recorder file back. An autorun
# here would just compete with the RT control loop for CPU.
$(OUT_BUILD)/disk-envelope.img: AUTORUN_ELF :=
$(OUT_BUILD)/disk-ipctest.img: AUTORUN_ELF := /fat/IPCTEST.ELF
$(OUT_BUILD)/disk-vsbench.img: AUTORUN_ELF := /fat/VSBENCH.ELF
# Wave 12: vsbench's `spawn+wait` lane starts TOOLBOX.ELF (as `true`), so the
# bench volume carries it; no other image of this recipe does.
$(OUT_BUILD)/disk-vsbench.img: DISK_EXTRA := $(TOOLBOX_ELF)=TOOLBOX.ELF
$(OUT_BUILD)/disk-vsbench.img: $(TOOLBOX_ELF)
# gpio_drv was built into every image since E11.AQ3 and made the autorun of
# none of them, so the ring-3 driver path had no scenario at all.
$(OUT_BUILD)/disk-gpiodrv.img: AUTORUN_ELF := /fat/GPIODRV.ELF

# The "brain lies" scenario. Same autorun as disk.img ON PURPOSE: GPIODRV is
# what exposed the net-poll starvation (a ring-3 program created inside the
# real-time band never yielded hart 3 to the poller, so the RX ring was never
# drained and the robot could not complete a single TCP handshake). Keeping it
# here makes this scenario the regression test for that, on top of what it was
# written for.
#
# What it does change is the link key: the kernel's brain link is always a
# Noise session, and with no key on the image it connects and immediately
# closes. That is the correct behaviour and the gate proves it in
# `link auth rejects missing key`; here it would just stop the frames from
# ever reaching the dispatch this scenario exists to test. So the image is in
# `KEYED_DISKS`, and the peer runs the brain side of the session with the key
# it reads out of the image.
$(OUT_BUILD)/disk-brainlies.img: AUTORUN_ELF := /fat/GPIODRV.ELF

# Same recipe again for the RECORD half of that scenario, which boots a kernel
# built with `brain-lies-smoke` and reads SAFETY_UNKNOWN_PKT back off the log.
# Its own image rather than a reuse: the probe scans LOG00000.BIN, so a
# previous run's records on a shared image would let it pass without this boot
# writing anything.
$(OUT_BUILD)/disk-brainrec.img: AUTORUN_ELF := /fat/GPIODRV.ELF

# And again for the TCP e-stop, which needs the kernel's OWN brain link up:
# `PKT_ESTOP` over TCP is handled in `behavior_task`, not by any ring-3
# program, so the key is not a convenience here — without it the link closes
# and the frame never reaches the branch under test.
# Its own image name because the Makefile needs an explicit rule per name; a
# missing one yields no image and a silent boot that reads as a kernel fault.
$(OUT_BUILD)/disk-brainestop.img: AUTORUN_ELF := /fat/GPIODRV.ELF

# The PHYSICAL kill switch. Same shape as the image above — the wheels have to
# be turning before the switch is pressed, and the brain link is what turns
# them. `estop_gpio_pin` is deliberately NOT set here: the pin has to be driven
# high before the poll can see it, which a config line cannot promise. See
# `estop_gpio_smoke_task`.
$(OUT_BUILD)/disk-estopgpio.img: AUTORUN_ELF := /fat/GPIODRV.ELF

# Wave 9 (DRV1): the base of the ring-3 drivers disk (`build/disk-drv.img`,
# after this recipe). No autorun: the drivers are the only ring-3 tasks.
$(OUT_BUILD)/disk-drvbase.img: AUTORUN_ELF :=
# L1, the Linux comparison (`make lx-compare`): LXSRV.ELF as the
# autorun, because a `bench-minimal` kernel parks the topology launcher with
# every other boot task, so the server runs alone, as /init does on Linux.
$(OUT_BUILD)/disk-lxbench-base.img: AUTORUN_ELF := /fat/LXSRV.ELF

# The optional third argument is the signing key (default: the TEST key; the
# board volume passes BOARD_SIGN_PRIV).
# CONFIG.SIG v2 (wave 11): a signed CONFIG.INI names ONE
# device and a counter. Each image gets a fresh random device id in its
# reserved tail (`tools/sign/device_provision.py`, sector 2, floor 0) and its
# CONFIG.INI is signed for that id at counter 1. Usage, in a recipe whose image
# is already formatted: $(call provision_and_sign_config,<ini>,<sig-out>)
CONFIG_SIG_TOOLS := tools/sign/gen_config_sig.py tools/sign/device_provision.py
LINK_KEY_TOOL := tools/sign/link_key_provision.py

# The behavior loop's model bundle (see its rule, below).
BEHAVIOR_MBL_SRC  := kernel/src/behavior_ml.rs
BEHAVIOR_MBL_ARGS := --name behavior-mlp --in-bytes 16 --out-bytes 12 \
	--variant gguf:1:$(OUT_BUILD)/policy.gguf:1000:20:4096 \
	--expect-ref-from $(BEHAVIOR_MBL_SRC):BEHAVIOR_MODEL_REF

# Images whose kernel brain link must come up (the link is always a Noise
# session, so it needs the link key): a random 32-byte key, as a link-key
# record (`tools/sign/link_key_provision.py`), in the reserved tail sector 0 the
# kernel reads (`reserved_tail::LINK_KEY`, unaddressable over the USB export),
# and the raw key in ::LINK.KEY for the host
# peers (`tools/gate/fake_brain.py --image`, `tools/gate/link_peer.py --image`). Same
# mechanism as `build/disk-linkkey.img` below.
KEYED_DISKS := $(OUT_BUILD)/disk-brainlies.img $(OUT_BUILD)/disk-brainrec.img \
	$(OUT_BUILD)/disk-brainestop.img $(OUT_BUILD)/disk-estopgpio.img
provision_link_key = dd if=/dev/urandom of=$@.tmp_linkkey bs=32 count=1 2>/dev/null && \
	mcopy -i $@ $@.tmp_linkkey ::LINK.KEY && \
	python3 tools/sign/link_key_provision.py $@ $@.tmp_linkkey && \
	rm -f $@.tmp_linkkey
provision_and_sign_config = python3 tools/sign/device_provision.py $@ >/dev/null && \
	python3 tools/sign/gen_config_sig.py $(1) --config-v2 --counter 1 --image $@ --priv $(or $(3),$(TEST_PRIV_KEY)) --out $(2)

# Temporaries live next to their target (`$@.tmp_*`), not in fixed /tmp paths:
# two disk builds at once (parallel fronts in separate worktrees, or `make -j`)
# used to share /tmp/_robtos_config.ini and ship each other's CONFIG.INI.
$(OUT_BUILD)/disk.img $(OUT_BUILD)/disk-systest.img $(OUT_BUILD)/disk-uhello.img \
$(OUT_BUILD)/disk-reflex.img $(OUT_BUILD)/disk-braincli.img $(OUT_BUILD)/disk-captest.img \
$(OUT_BUILD)/disk-latbench.img $(OUT_BUILD)/disk-abitest.img $(OUT_BUILD)/disk-ipctest.img $(OUT_BUILD)/disk-vsbench.img \
$(OUT_BUILD)/disk-envelope.img $(OUT_BUILD)/disk-gpiodrv.img $(OUT_BUILD)/disk-brainlies.img \
		$(OUT_BUILD)/disk-brainrec.img $(OUT_BUILD)/disk-brainestop.img \
		$(OUT_BUILD)/disk-estopgpio.img $(OUT_BUILD)/disk-drvbase.img $(OUT_BUILD)/disk-lxbench-base.img: \
		$(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF) $(UHELLO_ELF) \
		$(EPSRV_ELF) $(ABICHILD_ELF) $(VSSRV_ELF) \
		$(REFLEX_ELF) $(BRAINCLI_ELF) $(CAPTEST_ELF) $(LATBENCH_ELF) $(ABITEST_ELF) \
		$(VSBENCH_ELF) \
		$(IPCTEST_ELF) \
		$(OUT_BUILD)/policy.gguf $(OUT_BUILD)/policy.sig $(OUT_BUILD)/behavior.mbl \
		$(TEST_PRIV_KEY) $(CONFIG_SIG_TOOLS) $(LINK_KEY_TOOL)
	@mkdir -p $(OUT_BUILD)
	dd if=/dev/zero of=$@ bs=1M count=32
	# U06-9/#30 (2026-09-26): extend the raw image by
	# TAIL_SECTORS (8 sectors = 4 KiB) and format ONLY the
	# first 32768 1-KiB blocks (32 MiB) as FAT32, leaving the tail
	# reserved -- see `kernel/src/reserved_tail.rs::TAIL_SECTORS`.
	# Without this the reserved region LINK.KEY/the entropy seed file live
	# in does not exist on this image (`reserved_tail::read`/`write` then
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
	mcopy -i $@ $(ABICHILD_ELF) ::ABICHILD.ELF
	mcopy -i $@ $(VSSRV_ELF) ::VSSRV.ELF
	mcopy -i $@ $(REFLEX_ELF) ::REFLEX.ELF
	mcopy -i $@ $(BRAINCLI_ELF) ::BRAINCLI.ELF
	mcopy -i $@ $(CAPTEST_ELF) ::CAPTEST.ELF
	mcopy -i $@ $(LATBENCH_ELF) ::LATBENCH.ELF
	mcopy -i $@ $(ABITEST_ELF) ::ABITEST.ELF
	mcopy -i $@ $(IPCTEST_ELF) ::IPCTEST.ELF
	mcopy -i $@ $(VSBENCH_ELF) ::VSBENCH.ELF
	$(foreach f,$(DISK_EXTRA),mcopy -i $@ $(word 1,$(subst =, ,$(f))) ::$(word 2,$(subst =, ,$(f)));)
	# 8.3 names, as the FAT32 driver matches no other (`tests/host/fs-tests`).
	mcopy -i $@ $(OUT_BUILD)/behavior.mbl ::BEHAVIOR.MBL
	mcopy -i $@ $(OUT_BUILD)/policy.gguf ::POLICY.GGF
	mcopy -i $@ $(OUT_BUILD)/policy.sig ::POLICY.SIG
	mcopy -i $@ $@.tmp_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta ::BOOTMETA
	$(if $(filter $@,$(KEYED_DISKS)),$(call provision_link_key))
	@rm -f $@.tmp_hello.txt $@.tmp_readme.txt $@.tmp_config.ini $@.tmp_config.sig $@.tmp_bootmeta
	@echo "[DISK] FAT32 image: $@ (autorun=$(AUTORUN_ELF))"

# Wave 9 (DRV1): the ring-3 drivers disk — the base above plus the two driver
# images, the only riscv64 gate image that carries them. A `qemu` kernel
# starts every topology row with `start = true` whose image is on the volume
# (through COMPMGR.ELF, the component manager, which carries the rows since
# the kernel stopped starting them), so this is the one gate disk that starts
# BUZZDRV.ELF and INADRV.ELF; no other scenario gains their tasks.
$(OUT_BUILD)/disk-drv.img: $(OUT_BUILD)/disk-drvbase.img $(BUZZ_DRV_ELF) $(INA_DRV_ELF) $(COMPMGR_ELF)
	cp $(OUT_BUILD)/disk-drvbase.img $@
	mcopy -i $@ $(BUZZ_DRV_ELF) ::BUZZDRV.ELF
	mcopy -i $@ $(INA_DRV_ELF) ::INADRV.ELF
	mcopy -i $@ $(COMPMGR_ELF) ::COMPMGR.ELF
	@echo "[DISK] FAT32 image: $@ (ring-3 drivers BUZZDRV.ELF, INADRV.ELF, and COMPMGR.ELF, which starts them)"

# The user-shell disk — the drivers base (no autorun) plus
# SH.ELF, TOOLBOX.ELF and POWER.ELF. The only gate image that carries them: on every
# other volume `/fat/SH.ELF` is absent, so the kernel console is the recovery
# console at once, as before, and no scenario gains a task.
$(OUT_BUILD)/disk-sh.img: $(OUT_BUILD)/disk-drvbase.img $(SH_ELF) $(TERMD_ELF) $(NAMESD_ELF) $(COMPMGR_ELF) $(TOOLBOX_ELF) $(POWER_ELF) $(FAM_ELFS) $(TRACECTL_ELF) $(DECISD_ELF) $(INPUTD_ELF) $(COMPSRV_ELF) $(LOGD_ELF) $(WHY_ELF) $(PKGD_ELF) $(PKG_ELF) $(RPCSRV_ELF) $(ZENOHD_ELF) $(VMMD_ELF) $(PTPD_ELF) $(AUDIOD_ELF) $(RPCQUIC_ELF) $(MCPD_ELF) $(SSHD_ELF) $(LOGIND_ELF)
	cp $(OUT_BUILD)/disk-drvbase.img $@
	mmd -i $@ ::PKG
	mcopy -i $@ $(SH_ELF) ::SH.ELF
	mcopy -i $@ $(TERMD_ELF) ::TERMD.ELF
	mcopy -i $@ $(NAMESD_ELF) ::NAMESD.ELF
	mcopy -i $@ $(COMPMGR_ELF) ::COMPMGR.ELF
	mcopy -i $@ $(TOOLBOX_ELF) ::TOOLBOX.ELF
	mcopy -i $@ $(POWER_ELF) ::POWER.ELF
	mcopy -i $@ $(FLIGHT_ELF) ::FLIGHT.ELF
	mcopy -i $@ $(BEHAVIOR_ELF) ::BEHAVIOR.ELF
	mcopy -i $@ $(CONFIG_ELF) ::CONFIG.ELF
	mcopy -i $@ $(OTA_ELF) ::OTA.ELF
	mcopy -i $@ $(TRACECTL_ELF) ::TRACECTL.ELF
	mcopy -i $@ $(DECISD_ELF) ::DECISD.ELF
	mcopy -i $@ $(INPUTD_ELF) ::INPUTD.ELF
	mcopy -i $@ $(COMPSRV_ELF) ::COMPSRV.ELF
	mcopy -i $@ $(LOGD_ELF) ::LOGD.ELF
	mcopy -i $@ $(WHY_ELF) ::WHY.ELF
	mcopy -i $@ $(PKGD_ELF) ::PKGD.ELF
	mcopy -i $@ $(PKG_ELF) ::PKG.ELF
	mcopy -i $@ $(RPCSRV_ELF) ::RPCSRV.ELF
	mcopy -i $@ $(ZENOHD_ELF) ::ZENOHD.ELF
	mcopy -i $@ $(PTPD_ELF) ::PTPD.ELF
	mcopy -i $@ $(AUDIOD_ELF) ::AUDIOD.ELF
	mcopy -i $@ $(RPCQUIC_ELF) ::RPCQUIC.ELF
	mcopy -i $@ $(MCPD_ELF) ::MCPD.ELF
	mcopy -i $@ $(SSHD_ELF) ::SSHD.ELF
	mcopy -i $@ $(LOGIND_ELF) ::LOGIND.ELF
	mcopy -i $@ $(VMMD_ELF) ::VMMD.ELF
	@echo "[DISK] FAT32 image: $@ (user shell SH.ELF with its terminal server TERMD.ELF and name server NAMESD.ELF, TOOLBOX.ELF, POWER.ELF, FLIGHT/BEHAVIOR/CONFIG/OTA.ELF, TRACECTL.ELF, DECISD.ELF, LOGD.ELF, WHY.ELF, PKGD.ELF, PKG.ELF, RPCSRV.ELF, ZENOHD.ELF, PTPD.ELF, RPCQUIC.ELF, MCPD.ELF, SSHD.ELF)"

# The Linux-server disk -- the drivers base (no autorun) plus
# LXSRV.ELF and its test module. The only gate image that carries them; a
# kernel built with `lx-server` starts LXSRV.ELF from its topology row
# (`start = true`), and every other volume lacks the image, so no other
# scenario gains a task. The module is copied under its 8.3 name, which is
# also its key in `build/module_hashes.rs`. When `make
# lx-kbuild` has built them, the Kbuild modules LXBASE.KO and XZ_DEC.KO and
# the fixture XZTEST.XZ go on too (the only volumes that ever carry a
# Linux-compiled object).
$(OUT_BUILD)/disk-lx.img: $(OUT_BUILD)/disk-drvbase.img $(LXSRV_ELF) $(COMPMGR_ELF) $(LXTEST_KO) $(LX_KO_RV) $(LX_XZTEST)
	cp $(OUT_BUILD)/disk-drvbase.img $@
	mcopy -i $@ $(LXSRV_ELF) ::LXSRV.ELF
	mcopy -i $@ $(COMPMGR_ELF) ::COMPMGR.ELF
	mcopy -i $@ $(OUT_BUILD)/lx/lxtest-riscv64.ko ::LXTEST.KO
	@if [ -f $(LX_KBUILD_DIR)/riscv64/xz_dec.ko ]; then \
		mcopy -i $@ $(LX_KBUILD_DIR)/riscv64/lxbase.ko ::LXBASE.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/riscv64/xz_dec.ko ::XZ_DEC.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/XZTEST.XZ ::XZTEST.XZ && \
		echo "[DISK] $@: + Kbuild modules LXBASE.KO, XZ_DEC.KO, fixture XZTEST.XZ"; fi
	@echo "[DISK] FAT32 image: $@ (Linux server skeleton LXSRV.ELF, test module LXTEST.KO)"

# The user-shell disk plus LXHELLO.ELF, the static Linux
# test binary the `linux:` gate rows start from the shell. Only a kernel
# built with `linux-abi-test` has a row for it.
$(OUT_BUILD)/disk-lxabi.img: $(OUT_BUILD)/disk-sh.img $(LXHELLO_ELF)
	cp $(OUT_BUILD)/disk-sh.img $@
	mcopy -i $@ $(LXHELLO_ELF) ::LXHELLO.ELF
	@echo "[DISK] FAT32 image: $@ (user shell + static Linux LXHELLO.ELF)"

# ── Board volume: ELFs the TOPOLOGY declares ─────────────────────
# Owner decision 2026-09-24: the set of ELFs above (IMAGE_ELFS) predates the
# generic-hybrid pivot and is a hand-maintained, robot-shaped list — every
# disk-*.img target above ships all thirteen regardless of what it tests.
# The rule now: an ELF ships on a BOARD's FAT32 volume iff the topology
# declares a service that ELF provides. Nothing above this comment changes —
# every disk-*.img target keeps shipping the full IMAGE_ELFS set, unchanged,
# because those are gate scenarios (`tools/gate/ci_check.sh`), not deployments.
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
# board build. `tools/image/gen_board_manifest.py` then resolves each declared
# name to the build path IMAGE_ELFS already knows (failing loudly — ORPHAN
# SERVICE — if the topology names an ELF nothing here builds), and
# `tools/image/check_board_disk.py` reads the FINISHED image back with `mdir` and
# fails — ORPHAN ELF / ORPHAN SERVICE — if what actually landed on the FAT32
# volume and what the topology declared disagree. Two independent checks,
# pre- and post-build, so drift cannot survive either a bad generator run or
# a hand-edited recipe.
# A small board (CONFIG_HWCLASS_EMBEDDED) ships, of the declared images, only
# those its topology starts or its .config names (gen_userspace_kconfig.py).
$(OUT_BUILD)/board_elfs.list: tests/host/topology-tests/src/bin/board_elfs.rs \
		$(shell find crates/core/topology/src -maxdepth 1 -name '*.rs' -not -name '* [0-9]*') \
		tests/host/topology-tests/Cargo.toml
	@mkdir -p $(OUT_BUILD)
	cd tests/host/topology-tests && CARGO_TARGET_DIR="$(OUT_TGT)/tests/host/topology-tests" $(CARGO) run -q --bin board_elfs > "$(OUT_BUILD)/board_elfs.list.tmp"
	mv $(OUT_BUILD)/board_elfs.list.tmp $@

$(OUT_BUILD)/board_manifest.txt: $(OUT_BUILD)/board_elfs.list tools/image/gen_board_manifest.py $(MLSRV_ELF_BOARD) $(PKGD_ELF_BOARD)
	@mkdir -p $(OUT_BUILD)
	python3 tools/image/gen_board_manifest.py $(OUT_BUILD)/board_elfs.list $(IMAGE_ELFS_BOARD) > $@

# The inference service's model files for the board volume: the same bytes as
# the QEMU disks' BEHAVIOR.MBL and POLICY.GGF, signed with the board key (never
# the test key).
$(BOARD_DIR)/behavior.mbl: $(OUT_BUILD)/policy.gguf tools/image/make_mbl.py tools/sign/sigalg.py $(BEHAVIOR_MBL_SRC) $(BOARD_PRIV_STAMP)
	$(call require_board_priv,BOARD-SIG)
	@mkdir -p $(BOARD_DIR)
	python3 tools/image/make_mbl.py $(BEHAVIOR_MBL_ARGS) --priv "$(BOARD_SIGN_PRIV)" --out $@

$(BOARD_DIR)/policy.sig: $(OUT_BUILD)/policy.gguf tools/sign/gen_config_sig.py $(BOARD_PRIV_STAMP)
	$(call require_board_priv,BOARD-SIG)
	@mkdir -p $(BOARD_DIR)
	python3 tools/sign/gen_config_sig.py $(OUT_BUILD)/policy.gguf --priv "$(BOARD_SIGN_PRIV)" --out $@

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
$(VF2_DISK):                BOARD_VOL_KCONFIG := $(VF2_KCONFIG)
$(OUT_BUILD)/disk-board-k1.img:    BOARD_VOL_KCONFIG := $(OUT_BUILD)/k1.config
$(OUT_BUILD)/disk-board-fleet.img: BOARD_VOL_KCONFIG := $(OUT_BUILD)/fleet.config
$(VF2_DISK) $(OUT_BUILD)/disk-board-k1.img $(OUT_BUILD)/disk-board-fleet.img: AUTORUN_ELF := /fat/GPIODRV.ELF
$(VF2_DISK) $(OUT_BUILD)/disk-board-k1.img $(OUT_BUILD)/disk-board-fleet.img: \
		$(OUT_BUILD)/board_manifest.txt tools/image/check_board_disk.py \
		tools/sign/check_board_keys.py $(IMAGE_HASHES_BOARD) $(BOARD_DIR)/behavior.mbl $(BOARD_DIR)/policy.sig \
		$(BOARD_PRIV_STAMP) \
		$(HELLO_ELF) $(SYSTEST_ELF) $(GPIO_DRV_ELF) $(MLSRV_ELF_BOARD) $(PKGD_ELF_BOARD) $(PKG_ELF) $(UHELLO_ELF) \
		$(EPSRV_ELF) $(ABICHILD_ELF) $(VSSRV_ELF) $(REFLEX_ELF) $(BRAINCLI_ELF) \
		$(CAPTEST_ELF) $(LATBENCH_ELF) $(ABITEST_ELF) $(IPCTEST_ELF) \
		$(VSBENCH_ELF) $(BUZZ_DRV_ELF) $(INA_DRV_ELF) $(OUT_BUILD)/policy.gguf \
		$(CONFIG_SIG_TOOLS) $(TOPO_EMIT_DEPS) $(VF2_KCONFIG) $(OUT_BUILD)/k1.config $(OUT_BUILD)/fleet.config
	$(call require_board_key,BOARD)
	$(call require_board_priv,BOARD)
	@mkdir -p $(OUT_BUILD)
	dd if=/dev/zero of=$@ bs=1M count=32
	# U06-9/#30 (2026-09-26): extend the raw image by
	# TAIL_SECTORS (8 sectors = 4 KiB) and format ONLY the
	# first 32768 1-KiB blocks (32 MiB) as FAT32, leaving the tail
	# reserved -- see `kernel/src/reserved_tail.rs::TAIL_SECTORS`.
	# Without this the reserved region LINK.KEY/the entropy seed file live
	# in does not exist on this image (`reserved_tail::read`/`write` then
	# fail closed -- safe, but the key/seed never load). 65536 sectors x
	# 512 B = 32 MiB = 32768 KiB, the mkfs.fat BLOCKS unit.
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "# AzOS Configuration\nml_enabled=1\nlog_level=1\nmotor_max_speed=100\nwatchdog_ms=500\nnet_ip=10.0.2.15\nnet_gateway=10.0.2.2\nnet_mask=255.255.255.0\nbehavior_server_ip=10.0.2.2\nbehavior_server_port=9000\nbehavior_l1_enabled=1\nbehavior_l2_enabled=1\nbehavior_l3_enabled=1\nautorun=$(AUTORUN_ELF)\n" \
		> $@.tmp_board_config.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" \
		> $@.tmp_board_bootmeta
	$(call provision_and_sign_config,$@.tmp_board_config.ini,$@.tmp_board_config.sig,$(BOARD_SIGN_PRIV))
	mcopy -i $@ $(BOARD_DIR)/behavior.mbl ::BEHAVIOR.MBL
	mcopy -i $@ $(OUT_BUILD)/policy.gguf ::POLICY.GGF
	mcopy -i $@ $(BOARD_DIR)/policy.sig ::POLICY.SIG
	mcopy -i $@ $@.tmp_board_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_board_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_board_bootmeta ::BOOTMETA
	# Wave 15: the board kernel's topology as signed files (TOPOLOGY_SOURCE),
	# bound to this volume's device id, signed with the board key.
	$(call topo_bind,riscv64,$(BOARD_VOL_KCONFIG),board-image,$(BOARD_DIR)/topo-$(basename $(notdir $@)),$@,$(BOARD_SIGN_PRIV))
	# The topology's images plus the ones this volume's .config selects
	# under "Userspace programs" (`make config`).
	# The images this volume's topology declares, from its own .config (the
	# shared board_elfs.list is the workspace config's: the gate's generic one
	# has the input server and the compositor, a board's may not).
	cd tests/host/topology-tests && KCONFIG_CONFIG="$(BOARD_VOL_KCONFIG)" CARGO_TARGET_DIR="$(OUT_TGT)/tests/host/topology-tests-board" $(CARGO) run -q --bin board_elfs > "$@.elfs"
	python3 tools/image/gen_board_manifest.py $@.elfs --config $(BOARD_VOL_KCONFIG) $(IMAGE_ELFS_BOARD) > $@.manifest
	# The package installer stages under /fat/PKG: its tree grant cannot create
	# the directory it is rooted at, so the volume carries it.
	mmd -i $@ ::PKG
	@while IFS='=' read -r name path; do \
		[ -z "$$name" ] && continue; \
		mcopy -i $@ "$$path" "::$$name" || exit 1; \
	done < $@.manifest
	@rm -f $@.tmp_board_config.ini $@.tmp_board_bootmeta
	python3 tools/image/check_board_disk.py $@ $@.manifest
	$(BOARD_KEYCHECK) disk $@ $(IMAGE_HASHES_BOARD) $(MLSRV_ELF) tools/keys/test_pub.bin
	$(BOARD_KEYCHECK) disk $@ $(IMAGE_HASHES_BOARD) $(PKGD_ELF) tools/keys/test_pub.bin PKGD.ELF
	python3 tools/sign/check_board_keys.py sigs $@ "$(BOARD_TOPOLOGY_KEY)"
	@echo "[DISK] Board FAT32 image (topology-derived, signed topology for $(BOARD_VOL_KCONFIG)): $@ (autorun=$(AUTORUN_ELF))"

.PHONY: board-elfs
board-elfs: $(OUT_BUILD)/board_elfs.list
	@cat $(OUT_BUILD)/board_elfs.list

# ── aarch64 disk images (Phase 6 — userspace on aarch64) ─────────────────────
#
# `AARCH64_PAGE_SIZE=16384|65536` (see `TARGET_AARCH64` above) names every
# image below `build/disk-aarch64-16k*.img` / `-64k*` and fills it from that
# granule's ELFs; the default names and contents are the 4 KiB ones.
#
# Same recipe shape as the riscv64 images above, own variable (not a
# parameterized rule: `make`'s pattern rules cannot vary the ELF set the way
# `AUTORUN_ELF`/`CFG_EXTRA` vary a single name), carrying the aarch64 ELFs
# from `userspace-aarch64` instead. BEHAVIOR.MBL and POLICY.GGF too:
# the ring-3 ML service the behavior task spawns on this ISA as on riscv64
# reads both (weights, and the GGUF policy self-test) when it starts.
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX).img:         AUTORUN_ELF_AARCH64 := /fat/HELLO.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-systest.img: AUTORUN_ELF_AARCH64 := /fat/SYSTEST.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-abitest.img: AUTORUN_ELF_AARCH64 := /fat/ABITEST.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-ipctest.img: AUTORUN_ELF_AARCH64 := /fat/IPCTEST.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-captest.img: AUTORUN_ELF_AARCH64 := /fat/CAPTEST.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img: AUTORUN_ELF_AARCH64 := /fat/VSBENCH.ELF
# Wave 12: see `build/disk-vsbench.img`'s DISK_EXTRA.
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img: DISK_EXTRA := $(TOOLBOX_ELF_AARCH64)=TOOLBOX.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img: $(TOOLBOX_ELF_AARCH64)
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-gpiodrv.img: AUTORUN_ELF_AARCH64 := /fat/GPIODRV.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-reflex.img:  AUTORUN_ELF_AARCH64 := /fat/REFLEX.ELF
# aarch64 parity (this task): the network round-trip scenario. Needs
# `net_ip`/`net_gateway`/`net_mask`/`behavior_server_ip`/`behavior_server_port`
# in CONFIG.INI, which the other aarch64 images below do not — those lines
# are harmless on them too (nothing on this ISA reads `behavior_server_*`
# without a `behavior` task, which `kernel_main` does not create here), so
# they are written for every aarch64 image rather than carrying a second
# CONFIG.INI recipe for one name. Same host peer as riscv64's own
# `disk-braincli.img`: `tools/gate/fake_brain.py` on 10.0.2.2:9000 (QEMU SLIRP's
# gateway address maps to the host).
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-braincli.img: AUTORUN_ELF_AARCH64 := /fat/BRAINCLI.ELF
# Wave 9 (DRV1): the base of `build/disk-aarch64$(AARCH64_PG_SUFFIX)-drv.img`; see `build/disk-drv.img`.
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img: AUTORUN_ELF_AARCH64 :=
$(OUT_BUILD)/disk-aarch64-lxbench-base.img: AUTORUN_ELF_AARCH64 := /fat/LXSRV.ELF
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX).img $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-systest.img $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-abitest.img \
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-ipctest.img $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-captest.img $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-vsbench.img \
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-gpiodrv.img $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-reflex.img $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-braincli.img \
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img $(OUT_BUILD)/disk-aarch64-lxbench-base.img: \
		$(HELLO_ELF_AARCH64) $(SYSTEST_ELF_AARCH64) $(GPIO_DRV_ELF_AARCH64) $(MLSRV_ELF_AARCH64) \
		$(UHELLO_ELF_AARCH64) $(EPSRV_ELF_AARCH64) $(ABICHILD_ELF_AARCH64) $(VSSRV_ELF_AARCH64) \
		$(REFLEX_ELF_AARCH64) $(BRAINCLI_ELF_AARCH64) $(CAPTEST_ELF_AARCH64) \
		$(LATBENCH_ELF_AARCH64) $(ABITEST_ELF_AARCH64) $(IPCTEST_ELF_AARCH64) \
		$(VSBENCH_ELF_AARCH64) $(OUT_BUILD)/policy.gguf $(OUT_BUILD)/policy.sig $(OUT_BUILD)/behavior.mbl \
		tools/keys/test_priv.bin $(CONFIG_SIG_TOOLS)
	@mkdir -p $(OUT_BUILD)
	dd if=/dev/zero of=$@ bs=1M count=32
	# U06-9/#30 (2026-09-26): extend the raw image by
	# TAIL_SECTORS (8 sectors = 4 KiB) and format ONLY the
	# first 32768 1-KiB blocks (32 MiB) as FAT32, leaving the tail
	# reserved -- see `kernel/src/reserved_tail.rs::TAIL_SECTORS`.
	# Without this the reserved region LINK.KEY/the entropy seed file live
	# in does not exist on this image (`reserved_tail::read`/`write` then
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
	mcopy -i $@ $(ABICHILD_ELF_AARCH64) ::ABICHILD.ELF
	mcopy -i $@ $(VSSRV_ELF_AARCH64) ::VSSRV.ELF
	mcopy -i $@ $(REFLEX_ELF_AARCH64) ::REFLEX.ELF
	mcopy -i $@ $(BRAINCLI_ELF_AARCH64) ::BRAINCLI.ELF
	mcopy -i $@ $(CAPTEST_ELF_AARCH64) ::CAPTEST.ELF
	mcopy -i $@ $(LATBENCH_ELF_AARCH64) ::LATBENCH.ELF
	mcopy -i $@ $(ABITEST_ELF_AARCH64) ::ABITEST.ELF
	mcopy -i $@ $(IPCTEST_ELF_AARCH64) ::IPCTEST.ELF
	mcopy -i $@ $(VSBENCH_ELF_AARCH64) ::VSBENCH.ELF
	$(foreach f,$(DISK_EXTRA),mcopy -i $@ $(word 1,$(subst =, ,$(f))) ::$(word 2,$(subst =, ,$(f)));)
	# 8.3 names, as the FAT32 driver matches no other (`tests/host/fs-tests`).
	mcopy -i $@ $(OUT_BUILD)/behavior.mbl ::BEHAVIOR.MBL
	mcopy -i $@ $(OUT_BUILD)/policy.gguf ::POLICY.GGF
	mcopy -i $@ $(OUT_BUILD)/policy.sig ::POLICY.SIG
	$(call provision_and_sign_config,$@.tmp_config_aarch64.ini,$@.tmp_config_aarch64.sig)
	mcopy -i $@ $@.tmp_config_aarch64.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config_aarch64.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta_aarch64 ::BOOTMETA
	@rm -f $@.tmp_config_aarch64.ini $@.tmp_config_aarch64.sig $@.tmp_hello_aarch64.txt $@.tmp_bootmeta_aarch64
	@echo "[DISK] aarch64 FAT32 image: $@ (autorun=$(AUTORUN_ELF_AARCH64))"

# Wave 9 (DRV1): see `build/disk-drv.img`.
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-drv.img: $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img $(BUZZ_DRV_ELF_AARCH64) $(INA_DRV_ELF_AARCH64) $(COMPMGR_ELF_AARCH64)
	cp $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img $@
	mcopy -i $@ $(BUZZ_DRV_ELF_AARCH64) ::BUZZDRV.ELF
	mcopy -i $@ $(INA_DRV_ELF_AARCH64) ::INADRV.ELF
	mcopy -i $@ $(COMPMGR_ELF_AARCH64) ::COMPMGR.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (ring-3 drivers BUZZDRV.ELF, INADRV.ELF, and COMPMGR.ELF, which starts them)"

# See `build/disk-sh.img`.
$(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-sh.img: $(OUT_BUILD)/disk-aarch64$(AARCH64_PG_SUFFIX)-drvbase.img $(SH_ELF_AARCH64) $(TERMD_ELF_AARCH64) $(NAMESD_ELF_AARCH64) $(COMPMGR_ELF_AARCH64) $(TOOLBOX_ELF_AARCH64) $(POWER_ELF_AARCH64) $(FAM_ELFS_AARCH64) $(TRACECTL_ELF_AARCH64) $(DECISD_ELF_AARCH64) $(INPUTD_ELF_AARCH64) $(COMPSRV_ELF_AARCH64) $(LOGD_ELF_AARCH64) $(WHY_ELF_AARCH64) $(PKGD_ELF_AARCH64) $(PKG_ELF_AARCH64) $(RPCSRV_ELF_AARCH64) $(ZENOHD_ELF_AARCH64) $(VMMD_ELF_AARCH64) $(PTPD_ELF_AARCH64) $(AUDIOD_ELF_AARCH64) $(RPCQUIC_ELF_AARCH64) $(MCPD_ELF_AARCH64) $(SSHD_ELF_AARCH64) $(LOGIND_ELF_AARCH64)
	cp $< $@
	mmd -i $@ ::PKG
	mcopy -i $@ $(SH_ELF_AARCH64) ::SH.ELF
	mcopy -i $@ $(TERMD_ELF_AARCH64) ::TERMD.ELF
	mcopy -i $@ $(NAMESD_ELF_AARCH64) ::NAMESD.ELF
	mcopy -i $@ $(COMPMGR_ELF_AARCH64) ::COMPMGR.ELF
	mcopy -i $@ $(TOOLBOX_ELF_AARCH64) ::TOOLBOX.ELF
	mcopy -i $@ $(POWER_ELF_AARCH64) ::POWER.ELF
	mcopy -i $@ $(FLIGHT_ELF_AARCH64) ::FLIGHT.ELF
	mcopy -i $@ $(BEHAVIOR_ELF_AARCH64) ::BEHAVIOR.ELF
	mcopy -i $@ $(CONFIG_ELF_AARCH64) ::CONFIG.ELF
	mcopy -i $@ $(OTA_ELF_AARCH64) ::OTA.ELF
	mcopy -i $@ $(TRACECTL_ELF_AARCH64) ::TRACECTL.ELF
	mcopy -i $@ $(DECISD_ELF_AARCH64) ::DECISD.ELF
	mcopy -i $@ $(INPUTD_ELF_AARCH64) ::INPUTD.ELF
	mcopy -i $@ $(COMPSRV_ELF_AARCH64) ::COMPSRV.ELF
	mcopy -i $@ $(LOGD_ELF_AARCH64) ::LOGD.ELF
	mcopy -i $@ $(WHY_ELF_AARCH64) ::WHY.ELF
	mcopy -i $@ $(PKGD_ELF_AARCH64) ::PKGD.ELF
	mcopy -i $@ $(PKG_ELF_AARCH64) ::PKG.ELF
	mcopy -i $@ $(RPCSRV_ELF_AARCH64) ::RPCSRV.ELF
	mcopy -i $@ $(ZENOHD_ELF_AARCH64) ::ZENOHD.ELF
	mcopy -i $@ $(PTPD_ELF_AARCH64) ::PTPD.ELF
	mcopy -i $@ $(AUDIOD_ELF_AARCH64) ::AUDIOD.ELF
	mcopy -i $@ $(RPCQUIC_ELF_AARCH64) ::RPCQUIC.ELF
	mcopy -i $@ $(MCPD_ELF_AARCH64) ::MCPD.ELF
	mcopy -i $@ $(SSHD_ELF_AARCH64) ::SSHD.ELF
	mcopy -i $@ $(LOGIND_ELF_AARCH64) ::LOGIND.ELF
	mcopy -i $@ $(VMMD_ELF_AARCH64) ::VMMD.ELF
	@echo "[DISK] aarch64 FAT32 image: $@ (user shell SH.ELF, TOOLBOX.ELF, POWER.ELF, FLIGHT/BEHAVIOR/CONFIG/OTA.ELF, TRACECTL.ELF, DECISD.ELF, LOGD.ELF, WHY.ELF, PKGD.ELF, PKG.ELF, RPCSRV.ELF, ZENOHD.ELF, PTPD.ELF, RPCQUIC.ELF, MCPD.ELF, SSHD.ELF)"

# See `build/disk-lx.img`.
$(OUT_BUILD)/disk-aarch64-lx.img: $(OUT_BUILD)/disk-aarch64-drvbase.img $(LXSRV_ELF_AARCH64) $(COMPMGR_ELF_AARCH64) $(LXTEST_KO_AARCH64) $(LX_KO_A64) $(LX_XZTEST)
	cp $(OUT_BUILD)/disk-aarch64-drvbase.img $@
	mcopy -i $@ $(LXSRV_ELF_AARCH64) ::LXSRV.ELF
	mcopy -i $@ $(COMPMGR_ELF_AARCH64) ::COMPMGR.ELF
	mcopy -i $@ $(OUT_BUILD)/lx/lxtest-aarch64.ko ::LXTEST.KO
	@if [ -f $(LX_KBUILD_DIR)/aarch64/xz_dec.ko ]; then \
		mcopy -i $@ $(LX_KBUILD_DIR)/aarch64/lxbase.ko ::LXBASE.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/aarch64/xz_dec.ko ::XZ_DEC.KO && \
		mcopy -i $@ $(LX_KBUILD_DIR)/XZTEST.XZ ::XZTEST.XZ && \
		echo "[DISK] $@: + Kbuild modules LXBASE.KO, XZ_DEC.KO, fixture XZTEST.XZ"; fi
	@echo "[DISK] aarch64 FAT32 image: $@ (Linux server skeleton LXSRV.ELF, test module LXTEST.KO)"

# The comparison volumes (`make lx-compare`): the lx disk's
# files (taken from that disk, so each image keeps ONE recipe line that copies
# it, which tests/host/seccomp-tests checks against IMAGE_ELFS) on a volume
# whose CONFIG.INI autoruns LXSRV.ELF.
LX_BENCH_FILES := LXSRV.ELF LXTEST.KO LXBASE.KO XZ_DEC.KO XZTEST.XZ
$(OUT_BUILD)/disk-lxbench.img: $(OUT_BUILD)/disk-lxbench-base.img $(OUT_BUILD)/disk-lx.img
	rm -rf $(OUT_BUILD)/lx/bench-rv && mkdir -p $(OUT_BUILD)/lx/bench-rv
	for f in $(LX_BENCH_FILES); do mcopy -i $(OUT_BUILD)/disk-lx.img ::$$f $(OUT_BUILD)/lx/bench-rv/$$f || exit 1; done
	cp $(OUT_BUILD)/disk-lxbench-base.img $@
	for f in $(LX_BENCH_FILES); do mcopy -i $@ $(OUT_BUILD)/lx/bench-rv/$$f ::$$f || exit 1; done

$(OUT_BUILD)/disk-aarch64-lxbench.img: $(OUT_BUILD)/disk-aarch64-lxbench-base.img $(OUT_BUILD)/disk-aarch64-lx.img
	rm -rf $(OUT_BUILD)/lx/bench-a64 && mkdir -p $(OUT_BUILD)/lx/bench-a64
	for f in $(LX_BENCH_FILES); do mcopy -i $(OUT_BUILD)/disk-aarch64-lx.img ::$$f $(OUT_BUILD)/lx/bench-a64/$$f || exit 1; done
	cp $(OUT_BUILD)/disk-aarch64-lxbench-base.img $@
	for f in $(LX_BENCH_FILES); do mcopy -i $@ $(OUT_BUILD)/lx/bench-a64/$$f ::$$f || exit 1; done

# See `build/disk-lxabi.img`.
$(OUT_BUILD)/disk-aarch64-lxabi.img: $(OUT_BUILD)/disk-aarch64-sh.img $(LXHELLO_ELF_AARCH64)
	cp $(OUT_BUILD)/disk-aarch64-sh.img $@
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
$(OUT_BUILD)/disk-aarch64-signed.img: $(OUT_BUILD)/disk-aarch64.img $(OUT_BUILD)/KERN_A.BIN $(OUT_BUILD)/KERN_A.SIG
	cp $(OUT_BUILD)/disk-aarch64.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.BIN ::KERN_A.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.SIG ::KERN_A.SIG
	@echo "[DISK] aarch64 FAT32 image with signed slot A: $@"

# The same over the aarch64 shell volume (see `disk-sh-signed.img`).
$(OUT_BUILD)/disk-aarch64-sh-signed.img: $(OUT_BUILD)/disk-aarch64-sh.img $(OUT_BUILD)/KERN_A.BIN $(OUT_BUILD)/KERN_A.SIG
	cp $(OUT_BUILD)/disk-aarch64-sh.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.BIN ::KERN_A.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.SIG ::KERN_A.SIG
	@echo "[DISK] aarch64 FAT32 shell image with signed slot A: $@"

$(OUT_BUILD)/disk-aarch64-badsig.img: $(OUT_BUILD)/disk-aarch64-signed.img $(OUT_BUILD)/KERN_BAD.SIG
	cp $(OUT_BUILD)/disk-aarch64-signed.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_BAD.SIG ::KERN_A.SIG
	@echo "[DISK] aarch64 FAT32 image with CORRUPTED slot A signature: $@"

# Slot A unsigned (inherited from the base image), slot R signed — the
# one-file delta that turns the control's refusal into owner decision 99's
# fall to recovery. On aarch64 the reset at the end of that fall is PSCI
# `SYSTEM_RESET` (`arch-api`'s `Boot::reboot`), not SBI.
$(OUT_BUILD)/disk-aarch64-recovery.img: $(OUT_BUILD)/disk-aarch64.img $(OUT_BUILD)/KERN_R.BIN $(OUT_BUILD)/KERN_R.SIG
	cp $(OUT_BUILD)/disk-aarch64.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_R.BIN ::KERN_R.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_R.SIG ::KERN_R.SIG
	@echo "[DISK] aarch64 FAT32 image with unsigned slot A and a SIGNED recovery slot: $@"

# Seccomp image binding (crates/core/sched/src/seccomp.rs): a profile follows the
# BYTES of an image, never the name they are copied under.
#
# RENAMED: the ABITEST image with uhello's bytes copied over ABITEST.ELF.
# Autorun opens /fat/ABITEST.ELF, the digest is uhello's, so uhello runs under
# UHELLO.ELF's profile and its getpid is refused. Bound by name, it would run
# under ABITEST.ELF's wider row, which allows getpid.
# Gate row (wave 9): the captest volume inside partition 0 of an
# MBR medium, with a 64-sector raw partition 1 after it for `block.part.1`.
# See tools/image/make_parted_disk.py for the layout.
$(OUT_BUILD)/disk-parted.img: $(OUT_BUILD)/disk-captest.img tools/image/make_parted_disk.py tools/image/azos_records.py
	python3 tools/image/make_parted_disk.py $(OUT_BUILD)/disk-captest.img $@

# Gate row `riscv64: GPT records partition`: disk.img's FAT32 volume inside
# partition 0 of a GPT medium laid out to its end, disk.img's reserved tail
# (the device record) in the AzOS records partition. See
# tools/image/make_parted_disk.py for the layout.
$(OUT_BUILD)/disk-gpt.img: $(OUT_BUILD)/disk.img tools/image/make_parted_disk.py tools/image/azos_records.py
	python3 tools/image/make_parted_disk.py --gpt $(OUT_BUILD)/disk.img $@

$(OUT_BUILD)/disk-seccomp-renamed.img: $(OUT_BUILD)/disk-abitest.img $(UHELLO_ELF)
	cp $(OUT_BUILD)/disk-abitest.img $@
	mcopy -o -i $@ $(UHELLO_ELF) ::ABITEST.ELF
	@echo "[DISK] FAT32 image: $@ (ABITEST.ELF carries uhello's bytes)"

# REPLACED: the UHELLO image with UHELLO.ELF one byte longer. Still a loadable
# ELF (the byte lands after the section header table, which ends the file), and
# its digest matches no shipped ELF, so the kernel refuses to exec it.
$(OUT_BUILD)/disk-seccomp-replaced.img: $(OUT_BUILD)/disk-uhello.img $(UHELLO_ELF)
	cp $(OUT_BUILD)/disk-uhello.img $@
	cp $(UHELLO_ELF) $(OUT_BUILD)/uhello-replaced.elf
	printf '\n' >> $(OUT_BUILD)/uhello-replaced.elf
	mcopy -o -i $@ $(OUT_BUILD)/uhello-replaced.elf ::UHELLO.ELF
	@echo "[DISK] FAT32 image: $@ (UHELLO.ELF is one byte longer than the shipped ELF)"

# Same image, plus a /fat/LINK.KEY, used to prove the `link-provisioning-enforced`
# key gate ACCEPTS a valid key. A gate exercised only by its negative test is
# indistinguishable from a gate that always refuses, so CI runs both halves.
$(OUT_BUILD)/disk-linkkey.img: $(OUT_BUILD)/disk.img $(LINK_KEY_TOOL)
	cp $(OUT_BUILD)/disk.img $@
	@dd if=/dev/urandom of=$@.tmp_linkkey bs=32 count=1 2>/dev/null
	mcopy -i $@ $@.tmp_linkkey ::LINK.KEY
	# U06-9 (2026-09-26): the KERNEL no longer reads /fat/LINK.KEY — it reads
	# reserved tail sector 0 (`reserved_tail::LINK_KEY`, LBA =
	# image sectors - TAIL_SECTORS), as a link-key record, which the USB MSC export
	# cannot address. The FAT copy above stays for the PEER tools
	# (`tools/gate/link_peer.py --image`, mtools): the same 32 bytes, raw.
	# Gate 182e: without this line every kernel-link row booted
	# "key sector absent/unprovisioned".
	python3 tools/sign/link_key_provision.py $@ $@.tmp_linkkey
	@rm -f $@.tmp_linkkey
	@echo "[DISK] FAT32 image with LINK.KEY: $@"

# W2-B5: same image, CONFIG.SIG flipped by one bit — boots into the fail-closed
# state (`[CFG] WARNING ... fell back to factory defaults`). One flipped bit,
# not a missing file, so Ed25519 verification actually runs and rejects: byte
# 32, the first byte of the v2 sidecar's signature (bytes 0-31 are its magic,
# version, device id and counter, which would be refused before the curve).
$(OUT_BUILD)/disk-configtamper.img: $(OUT_BUILD)/disk.img
	cp $< $@
	mcopy -n -i $@ ::CONFIG.SIG $@.tmp_tamper.sig
	python3 -c "d = bytearray(open('$@.tmp_tamper.sig', 'rb').read()); d[32] ^= 0x01; open('$@.tmp_tamper.sig', 'wb').write(d)"
	mcopy -o -i $@ $@.tmp_tamper.sig ::CONFIG.SIG
	@rm -f $@.tmp_tamper.sig
	@echo "[DISK] FAT32 image: $@ (CONFIG.SIG tampered — boots into fail-closed state)"

# W2-A4 (V1.9): BRAINCLI autorun + the brain-link key. brain_client refuses
# to start without one, and the peer (`fake_brain.py --link-key`) needs the same
# bytes, so the key is also left at build/braincli_linkkey.bin.
#
# U06-9 (2026-09-26): the KERNEL no longer reads /fat/LINK.KEY, and neither
# does brain_client (`link_key_init` now goes through the kernel-hosted `linkkey` endpoint)
# — see `build/disk-linkkey.img`'s own comment above for the mechanism this
# mirrors (reserved tail sector 0, `reserved_tail::LINK_KEY`,
# unaddressable over the USB MSC export). Unlike that recipe, this one has no
# peer that still needs a FAT copy: `fake_brain.py --link-key` reads
# build/braincli_linkkey.bin directly on the host, so the `mcopy ::LINK.KEY`
# line is dropped outright rather than kept alongside the reserved-sector
# write.
$(OUT_BUILD)/disk-braincli-linkkey.img: $(OUT_BUILD)/disk-braincli.img $(LINK_KEY_TOOL)
	@cp $< $@
	@dd if=/dev/urandom of=$(OUT_BUILD)/braincli_linkkey.bin bs=32 count=1 2>/dev/null
	python3 tools/sign/link_key_provision.py $@ $(OUT_BUILD)/braincli_linkkey.bin
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
# never committed — see tools/sign/gen_test_key.py for why generating beats
# shipping a fixed pair. `tools/keys/.gitignore` already excludes both halves.
TEST_PRIV_KEY := tools/keys/test_priv.bin
TEST_PUB_KEY  := tools/keys/test_pub.bin

# One recipe, two outputs. gen_test_key.py is idempotent (keeps an intact
# private key, always re-derives the public half), so make invoking it once per
# target is harmless.
$(TEST_PRIV_KEY) $(TEST_PUB_KEY): tools/sign/gen_test_key.py
	python3 tools/sign/gen_test_key.py

# The GGUF policy file's Ed25519 sidecar: a bare 64-byte signature over the
# exact bytes, the CONFIG.SIG format and key (`gen_config_sig.py`), which the
# inference service verifies before its start-up self-test parses the file
# (Kconfig INFER_MODEL_SIG_REQUIRED). 8.3 name on the volume: POLICY.SIG.
$(OUT_BUILD)/policy.sig: $(OUT_BUILD)/policy.gguf tools/sign/gen_config_sig.py $(TEST_PRIV_KEY)
	python3 tools/sign/gen_config_sig.py $(OUT_BUILD)/policy.gguf --priv $(TEST_PRIV_KEY) --out $@

# The behavior loop's model: the MLP of policy.gguf as a signed `.MBL` bundle,
# one `gguf` variant (`tools/image/make_mbl.py`). The kernel's behavior task calls it
# through the Infer interface of the inference service (`kernel/src/behavior_ml.rs`),
# naming it by its model reference, which the build checks against the
# kernel's constant (`--expect-ref-from`). 16 bytes in (4 x f32), 12 out
# (3 x f32); the cost table is the figures the broker admits a call on: a run
# measured in tens of microseconds is signed at 1 ms, inside the 10 ms the loop
# gives a call. The file is found by its extension, so the name is free.
$(OUT_BUILD)/behavior.mbl: $(OUT_BUILD)/policy.gguf tools/image/make_mbl.py tools/sign/sigalg.py $(BEHAVIOR_MBL_SRC) $(TEST_PRIV_KEY)
	python3 tools/image/make_mbl.py $(BEHAVIOR_MBL_ARGS) --priv $(TEST_PRIV_KEY) --out $@

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
$(OUT_BUILD)/KERN_A.BIN:
	@mkdir -p $(OUT_BUILD)
	python3 -c "import random; random.seed(0x52424F53); open('$(OUT_BUILD)/KERN_A.BIN','wb').write(random.randbytes(262144))"
	@echo "[SECBOOT] slot payload: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OUT_BUILD)/KERN_A.SIG: $(OUT_BUILD)/KERN_A.BIN $(TEST_PRIV_KEY)
	python3 tools/sign/sign_ota.py $(OUT_BUILD)/KERN_A.BIN --fw-version 1 --priv $(TEST_PRIV_KEY) --out $@

# Bad signature: well-formed RSIG header, trusted public key, wrong scalar.
# Anything cruder (missing file, broken magic, foreign key) is rejected before
# sig_verify is ever called. See tools/sign/corrupt_sig.py.
$(OUT_BUILD)/KERN_BAD.SIG: $(OUT_BUILD)/KERN_A.SIG tools/sign/corrupt_sig.py
	python3 tools/sign/corrupt_sig.py $(OUT_BUILD)/KERN_A.SIG $@

# ACCEPT fixture: image + matching signature at the FAT volume ROOT. Root, not
# a /fat subdirectory — `secure_boot.rs` reaches the FAT32 driver directly
# rather than through the VFS mount point, and U-Boot's `fatload` (tools/image/boot.cmd)
# can only produce the root layout anyway.
$(OUT_BUILD)/disk-signed.img: $(OUT_BUILD)/disk.img $(OUT_BUILD)/KERN_A.BIN $(OUT_BUILD)/KERN_A.SIG
	cp $(OUT_BUILD)/disk.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.BIN ::KERN_A.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.SIG ::KERN_A.SIG
	@echo "[DISK] FAT32 image with signed slot A: $@"

# The shell volume with the signed slot A: the QEMU volume of the whole-system
# update rows that stage a bundle over the network (`pkg fetch-update`, then
# `ota switch`), which need the installer, `pkg` and `ota` (the shell image)
# and a slot A that verifies under the test key (the secure-boot kernel).
$(OUT_BUILD)/disk-sh-signed.img: $(OUT_BUILD)/disk-sh.img $(OUT_BUILD)/KERN_A.BIN $(OUT_BUILD)/KERN_A.SIG
	cp $(OUT_BUILD)/disk-sh.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.BIN ::KERN_A.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_A.SIG ::KERN_A.SIG
	@echo "[DISK] FAT32 shell image with signed slot A: $@"

# REJECT fixture: identical, except KERN_A.SIG has one flipped bit in s.
$(OUT_BUILD)/disk-badsig.img: $(OUT_BUILD)/disk-signed.img $(OUT_BUILD)/KERN_BAD.SIG
	cp $(OUT_BUILD)/disk-signed.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_BAD.SIG ::KERN_A.SIG
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
$(OUT_BUILD)/KERN_R.BIN:
	@mkdir -p $(OUT_BUILD)
	python3 -c "import random; random.seed(0x5245434F); open('$(OUT_BUILD)/KERN_R.BIN','wb').write(random.randbytes(262144))"
	@echo "[SECBOOT] recovery payload: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OUT_BUILD)/KERN_R.SIG: $(OUT_BUILD)/KERN_R.BIN $(TEST_PRIV_KEY)
	python3 tools/sign/sign_ota.py $(OUT_BUILD)/KERN_R.BIN --fw-version 1 --priv $(TEST_PRIV_KEY) --out $@

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
$(OUT_BUILD)/KERN_B.BIN:
	@mkdir -p $(OUT_BUILD)
	python3 -c "import random; random.seed(0x4B45524E); open('$(OUT_BUILD)/KERN_B.BIN','wb').write(random.randbytes(262144))"
	@echo "[SECBOOT] slot B payload: $@ ($$(wc -c < $@ | tr -d ' ') bytes)"

$(OUT_BUILD)/KERN_B.SIG: $(OUT_BUILD)/KERN_B.BIN $(TEST_PRIV_KEY)
	python3 tools/sign/sign_ota.py $(OUT_BUILD)/KERN_B.BIN --fw-version 1 --priv $(TEST_PRIV_KEY) --out $@

$(OUT_BUILD)/KERN_B_BAD.SIG: $(OUT_BUILD)/KERN_B.SIG tools/sign/corrupt_sig.py
	python3 tools/sign/corrupt_sig.py $(OUT_BUILD)/KERN_B.SIG $@

$(OUT_BUILD)/disk-badslotb.img: $(OUT_BUILD)/disk-signed.img $(OUT_BUILD)/KERN_B.BIN $(OUT_BUILD)/KERN_B_BAD.SIG
	cp $(OUT_BUILD)/disk-signed.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_B.BIN ::KERN_B.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_B_BAD.SIG ::KERN_B.SIG
	@echo "[DISK] FAT32 image with signed slot A and an UNFIT slot B: $@"

$(OUT_BUILD)/disk-recovery.img: $(OUT_BUILD)/disk.img $(OUT_BUILD)/KERN_R.BIN $(OUT_BUILD)/KERN_R.SIG
	cp $(OUT_BUILD)/disk.img $@
	mcopy -o -i $@ $(OUT_BUILD)/KERN_R.BIN ::KERN_R.BIN
	mcopy -o -i $@ $(OUT_BUILD)/KERN_R.SIG ::KERN_R.SIG
	@echo "[DISK] FAT32 image with unsigned slot A and a SIGNED recovery slot: $@"


# The third-party table (BUSYBOX.ELF when `make busybox` built it, empty
# otherwise) is a target of its own, so an output tree whose image table is
# already current still gets it.
$(IMAGE_HASHES_X86_64): userspace/image_hashes.py $(IMAGE_ELF_PATHS_X86_64) \
               $(if $(LXRT_NEED_X86_64),$(LXRT_ELF_X86_64)) $(THIRDPARTY_HASHES_X86_64)
	@mkdir -p $(OUT_BUILD)
	python3 tools/lint/user_entry_lint.py --image $(filter-out $(LXHELLO_ELF_X86_64),$(IMAGE_ELF_PATHS_X86_64))
	python3 userspace/image_hashes.py $@ $(IMAGE_ELFS_X86_64)

$(THIRDPARTY_HASHES_X86_64): userspace/image_hashes.py $(wildcard $(BUSYBOX_ELF_X86_64))
	@mkdir -p $(OUT_BUILD)
	python3 userspace/image_hashes.py --const THIRDPARTY_SHA256 --skip-missing $@ BUSYBOX.ELF=$(BUSYBOX_ELF_X86_64)

# ── x86_64 disk images ──────────────────────────────────────────────────────
#
# The aarch64 images' recipe with the x86_64 ELFs: a 32 MiB FAT32 volume and
# its reserved tail, CONFIG.INI signed with the test key, the ML service's
# weights. `disk-x86_64.img` names no autorun image (the console program,
# Kconfig CONSOLE_PROGRAM, is the first user task); the others autorun one
# test. QEMU attaches it as a virtio-blk-device on microvm's virtio-mmio
# window (`make qemu`).
$(OUT_BUILD)/disk-x86_64.img:         AUTORUN_ELF_X86_64 :=
$(OUT_BUILD)/disk-x86_64-abitest.img: AUTORUN_ELF_X86_64 := /fat/ABITEST.ELF
$(OUT_BUILD)/disk-x86_64-ipctest.img: AUTORUN_ELF_X86_64 := /fat/IPCTEST.ELF
$(OUT_BUILD)/disk-x86_64-systest.img: AUTORUN_ELF_X86_64 := /fat/SYSTEST.ELF
$(OUT_BUILD)/disk-x86_64-captest.img: AUTORUN_ELF_X86_64 := /fat/CAPTEST.ELF
$(OUT_BUILD)/disk-x86_64-latbench.img: AUTORUN_ELF_X86_64 := /fat/LATBENCH.ELF
# vsbench (tools/bench/vsbench_x86_64.sh); its `spawn+wait` lane starts TOOLBOX.ELF,
# which every x86_64 image carries.
$(OUT_BUILD)/disk-x86_64-vsbench.img: AUTORUN_ELF_X86_64 := /fat/VSBENCH.ELF
$(OUT_BUILD)/disk-x86_64.img $(OUT_BUILD)/disk-x86_64-abitest.img $(OUT_BUILD)/disk-x86_64-ipctest.img $(OUT_BUILD)/disk-x86_64-vsbench.img \
$(OUT_BUILD)/disk-x86_64-systest.img $(OUT_BUILD)/disk-x86_64-captest.img $(OUT_BUILD)/disk-x86_64-latbench.img: \
		$(IMAGE_ELF_PATHS_X86_64) $(OUT_BUILD)/policy.gguf $(OUT_BUILD)/policy.sig $(OUT_BUILD)/behavior.mbl \
		tools/keys/test_priv.bin $(CONFIG_SIG_TOOLS)
	@mkdir -p $(OUT_BUILD)
	dd if=/dev/zero of=$@ bs=1M count=32
	dd if=/dev/zero of=$@ bs=512 count=8 seek=65536 conv=notrunc
	mkfs.fat -F 32 -n "ROBTOS" $@ 32768
	@printf "Hello from AzOS FAT32!\n" > $@.tmp_hello.txt
	@printf "net_ip=10.0.2.15\nnet_gateway=10.0.2.2\nnet_mask=255.255.255.0\nautorun=$(AUTORUN_ELF_X86_64)\n" > $@.tmp_config.ini
	@printf "active_slot=a\nboot_count=0\nlast_good=a\nfw_version_a=0\nfw_version_b=0\n" > $@.tmp_bootmeta
	mcopy -i $@ $@.tmp_hello.txt ::HELLO.TXT
	mcopy -i $@ $(HELLO_ELF_X86_64) ::HELLO.ELF
	mcopy -i $@ $(SYSTEST_ELF_X86_64) ::SYSTEST.ELF
	mcopy -i $@ $(UHELLO_ELF_X86_64) ::UHELLO.ELF
	mcopy -i $@ $(EPSRV_ELF_X86_64) ::EPSRV.ELF
	mcopy -i $@ $(ABICHILD_ELF_X86_64) ::ABICHILD.ELF
	mcopy -i $@ $(REFLEX_ELF_X86_64) ::REFLEX.ELF
	mcopy -i $@ $(BRAINCLI_ELF_X86_64) ::BRAINCLI.ELF
	mcopy -i $@ $(ABITEST_ELF_X86_64) ::ABITEST.ELF
	mcopy -i $@ $(IPCTEST_ELF_X86_64) ::IPCTEST.ELF
	mcopy -i $@ $(CAPTEST_ELF_X86_64) ::CAPTEST.ELF
	mcopy -i $@ $(LATBENCH_ELF_X86_64) ::LATBENCH.ELF
	mcopy -i $@ $(GPIO_DRV_ELF_X86_64) ::GPIODRV.ELF
	mcopy -i $@ $(BUZZ_DRV_ELF_X86_64) ::BUZZDRV.ELF
	mcopy -i $@ $(INA_DRV_ELF_X86_64) ::INADRV.ELF
	mcopy -i $@ $(MLSRV_ELF_X86_64) ::MLSRV.ELF
	mmd -i $@ ::PKG
	mcopy -i $@ $(SH_ELF_X86_64) ::SH.ELF
	mcopy -i $@ $(TERMD_ELF_X86_64) ::TERMD.ELF
	mcopy -i $@ $(NAMESD_ELF_X86_64) ::NAMESD.ELF
	mcopy -i $@ $(COMPMGR_ELF_X86_64) ::COMPMGR.ELF
	mcopy -i $@ $(TOOLBOX_ELF_X86_64) ::TOOLBOX.ELF
	mcopy -i $@ $(POWER_ELF_X86_64) ::POWER.ELF
	mcopy -i $@ $(TRACECTL_ELF_X86_64) ::TRACECTL.ELF
	mcopy -i $@ $(DECISD_ELF_X86_64) ::DECISD.ELF
	mcopy -i $@ $(INPUTD_ELF_X86_64) ::INPUTD.ELF
	mcopy -i $@ $(COMPSRV_ELF_X86_64) ::COMPSRV.ELF
	mcopy -i $@ $(LOGD_ELF_X86_64) ::LOGD.ELF
	mcopy -i $@ $(WHY_ELF_X86_64) ::WHY.ELF
	mcopy -i $@ $(PKGD_ELF_X86_64) ::PKGD.ELF
	mcopy -i $@ $(PKG_ELF_X86_64) ::PKG.ELF
	mcopy -i $@ $(RPCSRV_ELF_X86_64) ::RPCSRV.ELF
	mcopy -i $@ $(ZENOHD_ELF_X86_64) ::ZENOHD.ELF
	mcopy -i $@ $(PTPD_ELF_X86_64) ::PTPD.ELF
	mcopy -i $@ $(AUDIOD_ELF_X86_64) ::AUDIOD.ELF
	mcopy -i $@ $(RPCQUIC_ELF_X86_64) ::RPCQUIC.ELF
	mcopy -i $@ $(MCPD_ELF_X86_64) ::MCPD.ELF
	mcopy -i $@ $(SSHD_ELF_X86_64) ::SSHD.ELF
	mcopy -i $@ $(LOGIND_ELF_X86_64) ::LOGIND.ELF
	mcopy -i $@ $(VMMD_ELF_X86_64) ::VMMD.ELF
	mcopy -i $@ $(FLIGHT_ELF_X86_64) ::FLIGHT.ELF
	mcopy -i $@ $(BEHAVIOR_ELF_X86_64) ::BEHAVIOR.ELF
	mcopy -i $@ $(CONFIG_ELF_X86_64) ::CONFIG.ELF
	mcopy -i $@ $(OTA_ELF_X86_64) ::OTA.ELF
	mcopy -i $@ $(VSBENCH_ELF_X86_64) ::VSBENCH.ELF
	mcopy -i $@ $(VSSRV_ELF_X86_64) ::VSSRV.ELF
	mcopy -i $@ $(LXSRV_ELF_X86_64) ::LXSRV.ELF
	mcopy -i $@ $(LXHELLO_ELF_X86_64) ::LXHELLO.ELF
	mcopy -i $@ $(OUT_BUILD)/behavior.mbl ::BEHAVIOR.MBL
	mcopy -i $@ $(OUT_BUILD)/policy.gguf ::POLICY.GGF
	mcopy -i $@ $(OUT_BUILD)/policy.sig ::POLICY.SIG
	$(call provision_and_sign_config,$@.tmp_config.ini,$@.tmp_config.sig)
	mcopy -i $@ $@.tmp_config.ini ::CONFIG.INI
	mcopy -i $@ $@.tmp_config.sig ::CONFIG.SIG
	mcopy -i $@ $@.tmp_bootmeta ::BOOTMETA
	@rm -f $@.tmp_hello.txt $@.tmp_config.ini $@.tmp_config.sig $@.tmp_bootmeta
	@echo "[DISK] x86_64 FAT32 image: $@ (autorun=$(AUTORUN_ELF_X86_64))"

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
#   make build/disk-x86_64-topo.img     build/disk-x86_64.img + x86_64's
#   make topology-files                 every ISA's files, unbound unless
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
#   TOPO_SELECT            the selection the kernel that boots the files was
#                          built with beyond its .config (tools/build/kconfig_to_cargo.py
#                          --select; default none)
#   TOPO_KCONFIG_RISCV64   its .config (default $(RV_USER_KCONFIG): the development
#                          configuration with a riscv64 .config, else a riscv64 expansion)
#   TOPO_KCONFIG_AARCH64   (default $(AARCH64_KCONFIG))
#   TOPO_KCONFIG_X86_64    (default $(X86_64_KCONFIG))
#   TOPO_ISA               topo-volume's ISA (riscv64 | aarch64 | x86_64)
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
TOPO_SELECT ?=
TOPO_KCONFIG_RISCV64 ?= $(RV_USER_KCONFIG)
TOPO_KCONFIG_AARCH64 ?= $(AARCH64_KCONFIG)
TOPO_KCONFIG_X86_64 ?= $(X86_64_KCONFIG)
TOPO_ISA ?= riscv64
TOPO_COUNTER ?= 1
TOPO_DEVICE ?=
TOPO_PRIV ?= $(TEST_PRIV_KEY)
TOPO_DIR_RISCV64 := $(OUT_BUILD)/topo/riscv64
TOPO_DIR_AARCH64 := $(OUT_BUILD)/topo/aarch64
TOPO_DIR_X86_64 := $(OUT_BUILD)/topo/x86_64
# The .config of an ISA's files.
topo_kconfig = $(TOPO_KCONFIG_$(call topo_isa_var,$(1)))
topo_isa_var = $(if $(filter aarch64,$(1)),AARCH64,$(if $(filter x86_64,$(1)),X86_64,RISCV64))
topo_set = $(1)/CAPS.TOM $(1)/CAPS.SIG $(1)/SCHED.TOM

# The azos_topology features the kernel of .config $(1) built with selection
# $(2) turns on, as `--features` arguments: the kernel's features are the
# configuration's with the selection applied (copy $(3)), as its build has them.
topo_features = $$($(CARGO) tree -q -p azos_kernel -e features -i azos_topology --prefix none \
	--features "$$(python3 tools/build/kconfig_to_cargo.py --select '$(2)' --out '$(3)' '$(1)' | sed -n 's/.*--features //p')" \
	| sed -n 's/^azos_topology feature "\(.*\)"$$/azos_topology\/\1/p' | grep -v '/default$$' | sort -u | tr '\n' ' ')

# $(call topo_emit,<riscv64|aarch64|x86_64>,<.config>,<kernel selection>,<out dir>,<extra topo_emit args>)
define topo_emit
	@mkdir -p $(4)
	feats="emit-target-$(1) $(call topo_features,$(2),$(3),$(4).kconfig)"; \
	cd tests/host/topology-tests && KCONFIG_CONFIG="$(abspath $(2))" CARGO_TARGET_DIR="$(OUT_TGT)/tests/host/topology-tests/emit-$(1)" \
		$(CARGO) run -q --release --bin topo_emit --features "$$feats" -- "$(4)/CAPS.TOM" "$(4)/SCHED.TOM" $(5)
endef

# $(call topo_bind,<isa>,<.config>,<kernel selection>,<out dir>,<image>,<priv key>):
# emit bound to <image>'s device id (or TOPO_DEVICE) and TOPO_COUNTER, sign
# CAPS.TOM with <priv key>, put the three files on <image> (and drop a stale
# SCHED.SIG). The image must already carry its device record.
define topo_bind
	@mkdir -p $(dir $(4)); dev="$(or $(TOPO_DEVICE),$$(python3 tools/sign/device_provision.py --show --id-only $(5)))"; \
	case "$$dev" in [0-9a-f][0-9a-f]*) ;; *) echo "[TOPO] $(5): no device record (tools/sign/device_provision.py) to bind the topology to"; exit 1;; esac; \
	echo "$$dev" > $(4).device
	$(call topo_emit,$(1),$(2),$(3),$(4),--device $$(cat "$(4).device") --counter $(TOPO_COUNTER))
	python3 tools/sign/gen_config_sig.py $(4)/CAPS.TOM --priv "$(6)" --out $(4)/CAPS.SIG
	for f in CAPS.TOM CAPS.SIG SCHED.TOM; do mcopy -o -i $(5) $(4)/$$f ::$$f || exit 1; done
	@mdel -i $(5) ::SCHED.SIG >/dev/null 2>&1 || true
endef

.PHONY: topo-volume
topo-volume: $(TOPO_EMIT_DEPS) $(call topo_kconfig,$(TOPO_ISA)) $(TEST_PRIV_KEY)
	@[ -n "$(TOPO_IMAGE)" ] && [ -f "$(TOPO_IMAGE)" ] || { echo "[TOPO] topo-volume needs TOPO_IMAGE=<an existing image>"; exit 1; }
	$(call topo_bind,$(TOPO_ISA),$(call topo_kconfig,$(TOPO_ISA)),$(TOPO_SELECT),$(OUT_BUILD)/topo/vol-$(TOPO_ISA),$(TOPO_IMAGE),$(TOPO_PRIV))
	@echo "[TOPO] $(TOPO_IMAGE): signed topology bound to device $$(cat $(OUT_BUILD)/topo/vol-$(TOPO_ISA).device), counter $(TOPO_COUNTER)"

# What the inspection files were emitted for: rewritten only when it changes.
$(TOPO_DIR_RISCV64)/inputs $(TOPO_DIR_AARCH64)/inputs $(TOPO_DIR_X86_64)/inputs: FORCE
	@mkdir -p $(@D)
	@printf '%s\n' "$(TOPO_SELECT) $(TOPO_DEVICE) $(TOPO_COUNTER) $(abspath $(call topo_kconfig,$(notdir $(@D))))" > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@; rm -f $@.tmp

topo_emit_args = $(if $(TOPO_DEVICE),--device $(TOPO_DEVICE)) --counter $(TOPO_COUNTER)
$(TOPO_DIR_RISCV64)/CAPS.TOM: $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_RISCV64) $(TOPO_DIR_RISCV64)/inputs
	$(call topo_emit,riscv64,$(TOPO_KCONFIG_RISCV64),$(TOPO_SELECT),$(TOPO_DIR_RISCV64),$(topo_emit_args))
$(TOPO_DIR_AARCH64)/CAPS.TOM: $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_AARCH64) $(TOPO_DIR_AARCH64)/inputs
	$(call topo_emit,aarch64,$(TOPO_KCONFIG_AARCH64),$(TOPO_SELECT),$(TOPO_DIR_AARCH64),$(topo_emit_args))
$(TOPO_DIR_X86_64)/CAPS.TOM: $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_X86_64) $(TOPO_DIR_X86_64)/inputs
	$(call topo_emit,x86_64,$(TOPO_KCONFIG_X86_64),$(TOPO_SELECT),$(TOPO_DIR_X86_64),$(topo_emit_args))
# Written by the same run, after CAPS.TOM.
$(TOPO_DIR_RISCV64)/SCHED.TOM: $(TOPO_DIR_RISCV64)/CAPS.TOM ; @true
$(TOPO_DIR_AARCH64)/SCHED.TOM: $(TOPO_DIR_AARCH64)/CAPS.TOM ; @true
$(TOPO_DIR_X86_64)/SCHED.TOM: $(TOPO_DIR_X86_64)/CAPS.TOM ; @true
# A bare 64-byte Ed25519 signature over CAPS.TOM (the CAPS.SIG format), TEST
# key: these are QEMU fixtures.
$(OUT_BUILD)/topo/riscv64/CAPS.SIG: $(TOPO_DIR_RISCV64)/CAPS.TOM $(TEST_PRIV_KEY) tools/sign/gen_config_sig.py
	python3 tools/sign/gen_config_sig.py $< --priv $(TEST_PRIV_KEY) --out $@
$(OUT_BUILD)/topo/aarch64/CAPS.SIG: $(TOPO_DIR_AARCH64)/CAPS.TOM $(TEST_PRIV_KEY) tools/sign/gen_config_sig.py
	python3 tools/sign/gen_config_sig.py $< --priv $(TEST_PRIV_KEY) --out $@
$(OUT_BUILD)/topo/x86_64/CAPS.SIG: $(TOPO_DIR_X86_64)/CAPS.TOM $(TEST_PRIV_KEY) tools/sign/gen_config_sig.py
	python3 tools/sign/gen_config_sig.py $< --priv $(TEST_PRIV_KEY) --out $@

.PHONY: topology-files
topology-files: $(call topo_set,$(TOPO_DIR_RISCV64)) $(call topo_set,$(TOPO_DIR_AARCH64)) $(call topo_set,$(TOPO_DIR_X86_64))
	@ls -l $^

$(OUT_BUILD)/disk-topo.img: $(OUT_BUILD)/disk.img $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_RISCV64) $(TEST_PRIV_KEY)
	cp $(OUT_BUILD)/disk.img $@
	$(call topo_bind,riscv64,$(TOPO_KCONFIG_RISCV64),$(TOPO_SELECT),$(OUT_BUILD)/topo/img-riscv64,$@,$(TEST_PRIV_KEY))
	@echo "[DISK] FAT32 image with the signed topology (test key, counter $(TOPO_COUNTER)): $@"

$(OUT_BUILD)/disk-aarch64-topo.img: $(OUT_BUILD)/disk-aarch64.img $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_AARCH64) $(TEST_PRIV_KEY)
	cp $(OUT_BUILD)/disk-aarch64.img $@
	$(call topo_bind,aarch64,$(TOPO_KCONFIG_AARCH64),$(TOPO_SELECT),$(OUT_BUILD)/topo/img-aarch64,$@,$(TEST_PRIV_KEY))
	@echo "[DISK] FAT32 image with the signed topology (test key, counter $(TOPO_COUNTER)): $@"

$(OUT_BUILD)/disk-x86_64-topo.img: $(OUT_BUILD)/disk-x86_64.img $(TOPO_EMIT_DEPS) $(TOPO_KCONFIG_X86_64) $(TEST_PRIV_KEY)
	cp $(OUT_BUILD)/disk-x86_64.img $@
	$(call topo_bind,x86_64,$(TOPO_KCONFIG_X86_64),$(TOPO_SELECT),$(OUT_BUILD)/topo/img-x86_64,$@,$(TEST_PRIV_KEY))
	@echo "[DISK] FAT32 image with the signed topology (test key, counter $(TOPO_COUNTER)): $@"

# The board volumes' sets: each product profile's topology (BOARD_VOL_KCONFIG
# with the `board-image` selection the board kernels build with), bound to the
# volume's own device record and signed with the board key
# (`require_board_priv`), never the test key. Used inside the
# build/disk-board*.img recipe, after the volume is provisioned.


# ── AzOS inside AzOS (hypervisor guest) ──────────────────────────────────────
#
#   make azos-guest [ARCH=riscv64|aarch64]
#
# Builds, for one ISA, the two halves of the nested boot and joins them:
#   host.kernel   the hypervisor kernel (config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+hv-host+hv-example-guest.config and its
#                 aarch64 sibling: VIRT on, Kconfig HV_EXAMPLE_GUEST, so its
#                 built-in topology declares `[guest.azos]`),
#   KERNEL.ELF    the guest kernel (config/defconfigs/generic-sbc-riscv64-dev+qemu+hv-guest.config and siblings:
#                 no hypervisor inside, small RAM) as the ELF VMMD.ELF loads at
#                 start-up (`ctl::DEFAULT_IMAGE`): each PT_LOAD at its physical
#                 address in guest RAM, entered at the ELF entry
#                 (userspace/services/vmmd/src/loader.rs). On aarch64 that is the
#                 ELF of the build, not its Image;
#   DISK.IMG      the guest's virtio-blk disk, AZOS_GUEST_DISK_MIB of zeroes,
#   host-volume.img  the host's shell volume (build/disk*-sh.img: it carries
#                 VMMD.ELF) with VM/KERNEL.ELF and VM/DISK.IMG added (VMMD.ELF's
#                 `/fat/VM` tree).
# All of it under $(OUT_BUILD)/azos-guest/<isa>/. `tools/dev/run_guest.sh <isa>` runs
# it under QEMU with nested virtualisation and waits for the guest's banner.
# The userspace images of the volume are built from the workspace .config, as
# every image of the tree is.
# x86_64 has no guest entry yet: a PC kernel is entered through its PVH note (or a
# flat image's real-mode/long-mode stub), and this target builds neither.
# The target refuses the ISA rather than leave a KERNEL.ELF that cannot start; the
# x86_64 defconfig pair and the run line come with the entry.
ifneq ($(and $(filter azos-guest,$(MAKECMDGOALS)),$(filter x86_64,$(ARCH))),)
$(error azos-guest: no x86_64 guest entry yet (see mk/images.mk); use ARCH=riscv64 or ARCH=aarch64)
endif
AZOS_GUEST_DIR := $(OUT_BUILD)/azos-guest/$(ARCH)
AZOS_GUEST_DISK_MIB ?= 4

AZOS_GUEST_DEFCONFIG_riscv64 := config/defconfigs/generic-sbc-riscv64-dev+qemu+hv-guest.config
AZOS_GUEST_DEFCONFIG_aarch64 := config/defconfigs/generic-sbc-aarch64-dev+qemu+hv-guest.config
AZOS_HOST_DEFCONFIG_riscv64  := config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+hv-host+hv-example-guest.config
AZOS_HOST_DEFCONFIG_aarch64  := config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+hv-host+hv-example-guest.config
AZOS_HOST_VOLUME_riscv64     := $(OUT_BUILD)/disk-sh.img
AZOS_HOST_VOLUME_aarch64     := $(OUT_BUILD)/disk-aarch64-sh.img
AZOS_HASHES_riscv64          := $(IMAGE_HASHES)
AZOS_HASHES_aarch64          := $(IMAGE_HASHES_AARCH64)

# One kernel build: `$(call azos_kernel_<isa>,<defconfig>,<name>)` expands the
# defconfig into $(AZOS_GUEST_DIR)/<name>.config, builds it in a cargo target
# directory of its own and leaves what QEMU loads in <name>.kernel (the ELF on
# riscv64, the arm64 Image on aarch64).
# The cargo features are the whole list the expanded config derives
# (tools/build/kconfig_to_cargo.py, as the aarch64 build does): `make build`'s `--base`
# subset leaves out `hv`.
define azos_kernel_riscv64
@mkdir -p $(AZOS_GUEST_DIR)
cp $(1) $(AZOS_GUEST_DIR)/$(2).config
KCONFIG_CONFIG=$(AZOS_GUEST_DIR)/$(2).config $(PYTHON) -m olddefconfig
rf="$$(python3 tools/build/kconfig_to_cargo.py --rustflags --toml --skip-base $(AZOS_GUEST_DIR)/$(2).config)"; \
	isa=""; [ -z "$$rf" ] || isa="target.$(RISCV64_TARGET).rustflags=[$$rf]"; \
	env KCONFIG_CONFIG=$(AZOS_GUEST_DIR)/$(2).config CARGO_TARGET_DIR=$(OUT_TARGET)/azos-guest-$(ARCH)-$(2) \
	    $(CARGO) build --release -p azos_kernel $${isa:+--config "$$isa"} \
	    $$(python3 tools/build/kconfig_to_cargo.py $(AZOS_GUEST_DIR)/$(2).config | tr -s ' ')
cp $(OUT_TARGET)/azos-guest-$(ARCH)-$(2)/$(RISCV64_TARGET)/release/kernel $(AZOS_GUEST_DIR)/$(2).kernel
endef

define azos_kernel_aarch64
@mkdir -p $(AZOS_GUEST_DIR)
$(MAKE) --no-print-directory aarch64 AARCH64_DEFCONFIG=$(1) AARCH64_KCONFIG=$(AZOS_GUEST_DIR)/$(2).config \
	AARCH64_KTARGET_ENV='CARGO_TARGET_DIR=$(OUT_TARGET)/azos-guest-$(ARCH)-$(2)' \
	AARCH64_ELF=$(OUT_TARGET)/azos-guest-$(ARCH)-$(2)/$(AARCH64_TARGET)/release/kernel AARCH64_IMG=$(AZOS_GUEST_DIR)/$(2).kernel
endef

# The guest kernel's ELF: riscv64's <name>.kernel is it, aarch64's is the Image
# made from it. Copied stripped: the release profile keeps debug info (tens of
# MiB the host volume has no room for), and the monitor reads only the program
# headers and the segments.
AZOS_GUEST_ELF_riscv64 := $(AZOS_GUEST_DIR)/guest.kernel
AZOS_GUEST_ELF_aarch64 := $(OUT_TARGET)/azos-guest-aarch64-guest/$(AARCH64_TARGET)/release/kernel

# Both kernels are rebuilt by cargo whenever a source changed (FORCE), the files
# built from them whenever one of them did.
$(AZOS_GUEST_DIR)/guest.kernel: $(AZOS_GUEST_DEFCONFIG_$(ARCH)) $(AZOS_HASHES_$(ARCH)) FORCE
	$(call azos_kernel_$(ARCH),$(AZOS_GUEST_DEFCONFIG_$(ARCH)),guest)

$(AZOS_GUEST_DIR)/host.kernel: $(AZOS_HOST_DEFCONFIG_$(ARCH)) $(AZOS_HASHES_$(ARCH)) FORCE
	$(call azos_kernel_$(ARCH),$(AZOS_HOST_DEFCONFIG_$(ARCH)),host)

$(AZOS_GUEST_DIR)/KERNEL.ELF: $(AZOS_GUEST_DIR)/guest.kernel
	"$(AARCH64_OBJCOPY)" --strip-all $(AZOS_GUEST_ELF_$(ARCH)) $@
	@echo "[AZOS-GUEST] $@: $$(wc -c < $@) bytes"

$(AZOS_GUEST_DIR)/DISK.IMG:
	@mkdir -p $(AZOS_GUEST_DIR)
	dd if=/dev/zero of=$@ bs=1048576 count=$(AZOS_GUEST_DISK_MIB) 2>/dev/null

$(AZOS_GUEST_DIR)/host-volume.img: $(AZOS_HOST_VOLUME_$(ARCH)) $(AZOS_GUEST_DIR)/KERNEL.ELF $(AZOS_GUEST_DIR)/DISK.IMG
	cp $(AZOS_HOST_VOLUME_$(ARCH)) $@
	mmd -i $@ ::VM
	mcopy -i $@ $(AZOS_GUEST_DIR)/KERNEL.ELF ::VM/KERNEL.ELF
	mcopy -i $@ $(AZOS_GUEST_DIR)/DISK.IMG ::VM/DISK.IMG
	@echo "[AZOS-GUEST] host volume $@ (VMMD.ELF, VM/KERNEL.ELF, VM/DISK.IMG)"

.PHONY: azos-guest
azos-guest: $(AZOS_GUEST_DIR)/host.kernel $(AZOS_GUEST_DIR)/host-volume.img
	@echo "[AZOS-GUEST] $(ARCH): host kernel $(AZOS_GUEST_DIR)/host.kernel, volume $(AZOS_GUEST_DIR)/host-volume.img; boot with tools/dev/run_guest.sh $(ARCH)"
