# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# QEMU: the boot targets of the three ISAs and the smoke runs.
# Included by the top-level Makefile; the order of the includes there is part of the contract.

# Single CPU
qemu: build
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF)

# Gate 4: native PCI enumeration on QEMU `virt`.
# `disable-legacy=on` on every virtio-*-pci device matters: without it QEMU's
# device is "transitional" and lets a driver that never negotiates
# VIRTIO_F_VERSION_1 limp along on the legacy path, which would hide the same
# bug class U05-12 was about. `nvme` gives the enumeration line something
# non-virtio to print; the NVMe driver (Kconfig DRV_NVME) is not built here —
# `make qemu-nvme` boots the FAT32 image from it.
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
                 -drive file=$(OUT_BUILD)/pci-blk0.img,if=none,format=raw,id=pciblk0 \
                 -device virtio-net-pci,disable-legacy=on,netdev=pcinet0 \
                 -netdev user,id=pcinet0 \
                 -device nvme,serial=deadbeef,drive=pcinvme0 \
                 -drive file=$(OUT_BUILD)/pci-nvme0.img,if=none,format=raw,id=pcinvme0

$(OUT_BUILD)/pci-blk0.img $(OUT_BUILD)/pci-nvme0.img:
	@mkdir -p $(OUT_BUILD)
	dd if=/dev/zero of=$@ bs=1M count=8 2>/dev/null

# NOTE: depends on `build-pci`, not plain `build` — the latter's
# configuration alone does not compile in `crates/drivers/pci`/`virtio/pci.rs`
# at all (they're behind the `pci` feature), so a kernel built via `build`
# would boot but never print a `[PCI]` line.
build-pci: $(IMAGE_HASHES) .config $(QEMU_DEV_KCONFIG)
	$(call kernel_select,$(QEMU_DEV_KCONFIG),pci,$(OUT_BUILD)/qemu-dev-pci.config); \
	KCONFIG_CONFIG="$(OUT_BUILD)/qemu-dev-pci.config" $(CARGO) build $(CARGO_FLAGS) -p azos_kernel $$args

qemu-pci: build-pci $(OUT_BUILD)/pci-blk0.img $(OUT_BUILD)/pci-nvme0.img
	$(QEMU) $(QEMU_FLAGS) $(QEMU_PCI_ARGS) -kernel $(KERNEL_ELF)

# Boot from an NVMe SSD (Kconfig DRV_NVME): the gate's disk image as the
# controller's namespace, MSI-X through the AIA IMSIC (a PLIC machine boots
# too, polled). The disk is the repo's `build/disk.img`.
build-nvme: $(IMAGE_HASHES) .config $(QEMU_DEV_KCONFIG)
	$(call kernel_select,$(QEMU_DEV_KCONFIG),pci$(comma)nvme,$(OUT_BUILD)/qemu-dev-nvme.config); \
	KCONFIG_CONFIG="$(OUT_BUILD)/qemu-dev-nvme.config" $(CARGO) build $(CARGO_FLAGS) -p azos_kernel $$args

qemu-nvme: build-nvme $(OUT_BUILD)/disk.img
	$(QEMU) -machine virt,aia=aplic-imsic -nographic -bios default -smp 1 -m 256M -kernel $(KERNEL_ELF) \
		-drive file=$(OUT_BUILD)/disk.img,if=none,format=raw,id=nv -device nvme,serial=x,drive=nv

# aarch64 counterpart. `iommu=smmuv3` IS safe to enable here (unlike riscv64's
# `aia`): SMMUv3 defaults to bypass for any stream with no table entry, so a
# kernel with no SMMUv3 driver still boots identically — the flag only
# matters once stage 1b's IOMMU driver programs a stream table entry. ECAM
# base for this machine: 0x40_1000_0000 (verified via `-machine
# virt,dumpdtb=`, NOT the unchecked `0x3f00_0000` from the design notes).
#
# Boots the flat Image, not the ELF: QEMU hands a DTB pointer in x0 only to an
# Image, and the kernel reads the host bridge (ECAM, mem32 window) from it
# (`[PCI] host bridge: ... (dtb)`). The ELF boots with x0 = 0 and falls back to
# the built-in constants. Build the kernel with DRV_PCI on (`make aarch64` from a
# configuration with CONFIG_DRV_PCI=y) first.
AARCH64_PCI_IMG := $(OUT_BUILD)/kernel-aarch64-pci.img
qemu-pci-aarch64: $(OUT_BUILD)/pci-blk0.img $(OUT_BUILD)/pci-nvme0.img
	@test -f $(AARCH64_ELF) || { echo "build the aarch64 kernel with CONFIG_DRV_PCI=y first: $(AARCH64_ELF)"; exit 1; }
	@mkdir -p $(OUT_BUILD)
	"$(AARCH64_OBJCOPY)" -O binary $(AARCH64_ELF) $(AARCH64_PCI_IMG)
	qemu-system-aarch64 -M virt,gic-version=3,iommu=smmuv3 -cpu max,pauth=on -nographic \
		$(QEMU_PCI_ARGS) -kernel $(AARCH64_PCI_IMG)

# 4 CPUs (SMP testing)
qemu-smp: build
	$(QEMU) $(QEMU_FLAGS) -smp 4 -kernel $(KERNEL_ELF)

# Full: SMP + disk + network
qemu-full-smp: build userspace $(OUT_BUILD)/disk.img
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-smp 4 \
		-global virtio-mmio.force-legacy=false \
		-drive file=$(OUT_BUILD)/disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::8080-:8080 \
		-device virtio-net-device,netdev=net0

# Boot with a disk whose CONFIG.INI autoruns SYSTEST.ELF instead of the GPIO
# driver, so the syscall test actually executes. It exercises the ring-3 path
# end to end: ELF load from FAT32, exec, getpid/write/brk/exit via ecall.
# Prints `[SYSCALL_TEST] ALL PASSED!` or `FAILED!`.
qemu-systest: build userspace $(OUT_BUILD)/disk-systest.img
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-smp 4 \
		-global virtio-mmio.force-legacy=false \
		-drive file=$(OUT_BUILD)/disk-systest.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0

# DHCP against QEMU's built-in user-mode server. Asserts we reach Bound and
# end up with an address from the 10.0.2.x pool, not just that the call
# returned. Prints `[DHCPSMOKE] PASS ...` or `FAIL <reason>`.
qemu-dhcp-smoke: $(QEMU_DEV_KCONFIG)
	$(call kernel_select,$(QEMU_DEV_KCONFIG),dhcp-smoke,$(OUT_BUILD)/qemu-dev-dhcp-smoke.config); \
	KCONFIG_CONFIG="$(OUT_BUILD)/qemu-dev-dhcp-smoke.config" $(CARGO) build --release -p azos_kernel $$args
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

# RVV: single CPU with Vector extension
qemu-rvv: build-rvv
	$(QEMU) $(QEMU_FLAGS) -cpu $(QEMU_RVV_CPU) -kernel $(KERNEL_ELF)

# RVV: 4 CPUs + disk + network + Vector extension
qemu-full-smp-rvv: build-rvv userspace $(OUT_BUILD)/disk.img
	$(QEMU) $(QEMU_FLAGS) -cpu $(QEMU_RVV_CPU) \
		-smp 4 \
		-global virtio-mmio.force-legacy=false \
		-drive file=$(OUT_BUILD)/disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::8080-:8080 \
		-device virtio-net-device,netdev=net0 \
		-kernel $(KERNEL_ELF)

# GDB debug
qemu-gdb: build
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) -s -S

# ── Two-node network smoke (DEV01.5) ─────────────────────────────────────────
# Boots two kernel instances wired by QEMU's `socket` net backend and asserts a
# 256-byte TCP payload round-trips byte-for-byte. Both ends are our kernel, so
# it covers TCP handshake + RX checksum validation in both directions.
# Fails the build on FAIL, panic, or timeout.
qemu-net-pair: $(QEMU_DEV_KCONFIG)
	$(call kernel_select,$(QEMU_DEV_KCONFIG),net-smoke,$(OUT_BUILD)/qemu-dev-net-smoke.config); \
	KCONFIG_CONFIG="$(OUT_BUILD)/qemu-dev-net-smoke.config" $(CARGO) build --release -p azos_kernel $$args
	QEMU=$(QEMU) bash tools/gate/net_pair_smoke.sh

QEMU_X86_64_DISK ?=
# The signed microcode image as the PVH boot module (`make ucode`,
# mk/firmware.mk; Kconfig X86_UCODE_LOAD). QEMU ignores the MSR write: the
# boot log shows the image verified, the patch chosen and the revision read
# back unchanged.
QEMU_X86_64_UCODE ?=
qemu-x86_64: x86_64 $(QEMU_X86_64_DISK) $(QEMU_X86_64_UCODE)
	qemu-system-x86_64 $(QEMU_X86_64_FLAGS) -kernel $(X86_64_IMG) \
	    $(if $(QEMU_X86_64_UCODE),-initrd $(QEMU_X86_64_UCODE)) \
	    $(if $(QEMU_X86_64_DISK),-drive file=$(QEMU_X86_64_DISK)$(comma)if=none$(comma)format=raw$(comma)id=d0 -device virtio-blk-device$(comma)drive=d0)

# PCI on x86_64: the same kernel with Kconfig DRV_PCI and DRV_NVME, in its own
# Kconfig expansion, cargo target directory and image. microvm has no PCI bus
# unless started with `pcie=on` (the gate's plain microvm row keeps none).
# The NVMe disk holds the FAT32 image, so the boot disk is the controller.
X86_64_PCI_IMG := $(OUT_BUILD)/kernel-x86_64-pci.elf

.PHONY: x86_64-pci qemu-pci-x86_64
x86_64-pci:
	$(MAKE) x86_64 X86_64_DEFCONFIG=config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+pci.config \
	    X86_64_KCONFIG=$(OUT_BUILD)/x86_64-pci.config \
	    X86_64_TARGET_DIR=$(OUT_TARGET)/x86_64-pci \
	    X86_64_IMG=$(X86_64_PCI_IMG)

QEMU_X86_64_PCI_DISK ?= $(OUT_BUILD)/disk-x86_64.img
qemu-pci-x86_64: x86_64-pci $(QEMU_X86_64_PCI_DISK)
	qemu-system-x86_64 $(subst microvm,microvm$(comma)pcie=on,$(QEMU_X86_64_FLAGS)) -kernel $(X86_64_PCI_IMG) \
	    -drive file=$(QEMU_X86_64_PCI_DISK)$(comma)if=none$(comma)format=raw$(comma)id=pcinvme0 \
	    -device nvme$(comma)serial=deadbeef$(comma)drive=pcinvme0 \
	    -device virtio-net-pci$(comma)disable-legacy=on$(comma)netdev=pcinet0 -netdev user$(comma)id=pcinet0

# ── x86_64 PC: the Limine boot protocol (Kconfig X86_BOOT_LIMINE) ───────────
# `make x86_64-limine` builds the same kernel with the 64-bit Limine entry and
# arch/x86_64/boot/linker-x86_64-limine.ld (a higher-half ELF with `.limine_requests`):
# its own Kconfig expansion, cargo target directory and image, the PVH build
# untouched. `make run-x86-pc` stages an EFI system partition (Limine's
# BOOTX64.EFI, limine.conf, the kernel) and boots it on QEMU q35 under OVMF.
# Limine is the gitlink third_party/limine (a release's `vX.Y-binary` tag,
# .gitmodules), fetched by `tools/build/third_party_fetch.sh limine`; make never
# downloads it. LIMINE_DIR points at another Limine binary release.
# Boot-tested with v10.x-binary (base revision 3); the userspace images of
# the x86_64 build read the workspace `.config`, so a fresh tree needs one
# first (`cp build/x86_64-limine.config .config` after a failed first
# `make x86_64-limine`, or any `make defconfig-*`).
X86_64_LIMINE_IMG := $(OUT_BUILD)/kernel-x86_64-limine.elf

.PHONY: x86_64-limine
x86_64-limine:
	$(MAKE) x86_64 X86_64_DEFCONFIG=config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+limine.config \
	    X86_64_KCONFIG=$(OUT_BUILD)/x86_64-limine.config \
	    X86_64_LINKER=arch/x86_64/boot/linker-x86_64-limine.ld \
	    X86_64_TARGET_DIR=$(OUT_TARGET)/x86_64-limine \
	    X86_64_IMG=$(X86_64_LIMINE_IMG)

LIMINE_DIR ?= $(CURDIR)/third_party/limine
# UEFI firmware: QEMU's own (homebrew / distro) edk2 build; the vars file is
# the matching template (copied, so the run never writes the original).
OVMF_CODE ?= $(firstword $(wildcard /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
    /usr/local/share/qemu/edk2-x86_64-code.fd /usr/share/qemu/edk2-x86_64-code.fd \
    /usr/share/OVMF/OVMF_CODE.fd))
OVMF_VARS ?= $(firstword $(wildcard $(dir $(OVMF_CODE))edk2-i386-vars.fd $(dir $(OVMF_CODE))OVMF_VARS.fd))
X86_PC_ESP := $(OUT_BUILD)/x86-pc-esp
X86_PC_VARS := $(OUT_BUILD)/x86-pc-vars.fd
QEMU_X86_PC_FLAGS := -M q35 -cpu $(QEMU_X86_64_CPU) -m 256M -display none -no-reboot \
	-serial stdio -device isa-debug-exit,iobase=0xf4,iosize=0x04

# The QEMU command line of the PC (everything after the program name), with
# the ESP, the OVMF vars copy and the CPU model it was asked for: `run-x86-pc`
# runs it, and the gate's q35 CPU-model rows (tools/gate/ci_check.sh `x86_pc_row`)
# print it with `make -s x86-pc-qemu-args QEMU_X86_64_CPU=<model>`.
X86_PC_QEMU_ARGS = $(QEMU_X86_PC_FLAGS) \
	-drive if=pflash,format=raw,unit=0,readonly=on,file=$(OVMF_CODE) \
	-drive if=pflash,format=raw,unit=1,file=$(X86_PC_VARS) \
	-drive file=fat:rw:$(X86_PC_ESP),format=raw,if=none,id=esp \
	-device ide-hd,drive=esp

.PHONY: x86-pc-prereq x86-pc-esp x86-pc-qemu-args run-x86-pc
# Limine (when not fetched) and the UEFI firmware: say which is missing.
x86-pc-prereq:
	@missing=""; \
	test -n "$(LIMINE_DIR)" -a -f "$(LIMINE_DIR)/BOOTX64.EFI" || missing="$$missing\n  \$$(LIMINE_DIR)/BOOTX64.EFI   (tools/build/third_party_fetch.sh limine, or set LIMINE_DIR to a Limine release; BIOS boot is not used here)"; \
	test -n "$(OVMF_CODE)" -a -f "$(OVMF_CODE)" || missing="$$missing\n  OVMF_CODE (edk2-x86_64-code.fd from QEMU's share directory, or OVMF_CODE.fd)"; \
	test -n "$(OVMF_VARS)" -a -f "$(OVMF_VARS)" || missing="$$missing\n  OVMF_VARS (edk2-i386-vars.fd, or OVMF_VARS.fd, next to the code file)"; \
	if [ -n "$$missing" ]; then printf "[X86-PC] cannot boot, missing:$$missing\n"; exit 1; fi

# The ESP directory (Limine, its configuration, the kernel) and the OVMF
# variable store, for one boot. X86_PC_UCODE: the signed microcode image
# (`make ucode`) as /UCODE.BIN, a boot module Limine loads (Kconfig
# X86_UCODE_LOAD).
X86_PC_UCODE ?=
x86-pc-esp: x86_64-limine x86-pc-prereq $(X86_PC_UCODE)
	rm -rf $(X86_PC_ESP)
	mkdir -p $(X86_PC_ESP)/EFI/BOOT $(X86_PC_ESP)/boot
	cp "$(LIMINE_DIR)/BOOTX64.EFI" $(X86_PC_ESP)/EFI/BOOT/BOOTX64.EFI
	cp $(X86_64_LIMINE_IMG) $(X86_PC_ESP)/boot/kernel.elf
	$(if $(X86_PC_UCODE),cp $(X86_PC_UCODE) $(X86_PC_ESP)/UCODE.BIN)
	printf 'timeout: 0\nserial: yes\n\n/AzOS\n    protocol: limine\n    path: boot():/boot/kernel.elf\n$(if $(X86_PC_UCODE),    module_path: boot():/UCODE.BIN\n)' > $(X86_PC_ESP)/limine.conf
	printf 'TIMEOUT=0\nSERIAL=yes\n\n:AzOS\n    PROTOCOL=limine\n    KERNEL_PATH=boot:///boot/kernel.elf\n$(if $(X86_PC_UCODE),    MODULE_PATH=boot:///UCODE.BIN\n)' > $(X86_PC_ESP)/limine.cfg
	cp "$(OVMF_VARS)" $(X86_PC_VARS)

x86-pc-qemu-args:
	@echo '$(X86_PC_QEMU_ARGS)'

run-x86-pc: x86-pc-esp
	qemu-system-x86_64 $(X86_PC_QEMU_ARGS)

# Entered at EL1: QEMU `virt` without virtualization has no EL2.
qemu-aarch64: aarch64
	qemu-system-aarch64 -M virt,gic-version=3 $(QEMU_AARCH64_KERNEL_FLAGS) -kernel $(AARCH64_IMG)

# Entered at EL2, the way U-Boot / TF-A hand over on real boards: exercises the
# EL2->EL1 trampoline and SMC-conduit PSCI.
qemu-aarch64-el2: aarch64
	qemu-system-aarch64 -M virt,gic-version=3,virtualization=on $(QEMU_AARCH64_KERNEL_FLAGS) -kernel $(AARCH64_IMG)


# ── Network boot: nothing on a disk (tools/gate/netboot, Documentation/building.md) ─
# `make netboot-row NETBOOT_CASE=<case>` builds the kernel image the case's ISA
# fetches (tools/gate/netboot/kernel_image.sh) and boots QEMU with no disk, the
# firmware fetching AzOS over the network; the exit status is the verdict. The
# cases and what each judges are listed at the top of tools/gate/netboot/row.sh
# (`x86-pxe`, `x86-http`, `riscv64-tftp`, and for each a canary that
# sabotages the fetch and must be refused). `make netboot-uboot` builds the
# U-Boot the riscv64 cases boot, from the owner-approved tarball, under
# $(AZOS_OUT)/netboot (never in the checkout).
NETBOOT_CASE ?= x86-pxe

.PHONY: netboot-uboot netboot-row
netboot-uboot:
	@bash tools/gate/netboot/uboot_build.sh

netboot-row:
	@case "$(NETBOOT_CASE)" in \
	    x86-*) isa=x86_64 ;; riscv64-*) isa=riscv64 ;; \
	    *) echo "[NETBOOT] NETBOOT_CASE=$(NETBOOT_CASE): see the case list in tools/gate/netboot/row.sh"; exit 2 ;; \
	esac; \
	img="$$(bash tools/gate/netboot/kernel_image.sh $$isa)" && bash tools/gate/netboot/row.sh "$(NETBOOT_CASE)" "$$img"
