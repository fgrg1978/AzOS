# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Firmware the kernel loads into the hardware: the x86 CPU microcode image
# (Kconfig X86_UCODE_LOAD, arch/x86_64/src/cpu/ucode.rs).
#
# `make ucode` writes $(UCODE_BIN): the published Intel and AMD files,
# concatenated per vendor and signed with the update key (tools/image/mk_ucode.py),
# the image the kernel takes as a boot module and verifies before it parses a
# byte. The vendors' files are NOT in the tree and are not downloaded here:
# they are read from $(AZOS_DL) (default ~/azos-dl), where intel-ucode
# (github.com/intel/Intel-Linux-Processor-Microcode-Data-Files) and
# linux-firmware's amd-ucode/ were fetched with the owner's consent.
#
#   UCODE_INTEL / UCODE_AMD   the files that go in (default: every one; an
#                             empty value leaves that vendor out). All of
#                             Intel's are ~17 MiB; a PC needs one file:
#                             UCODE_INTEL=$(AZOS_DL)/intel-ucode/intel-ucode/06-5e-03
#   UCODE_PRIV                the update key's private half (default the
#                             TEST key; a product image is signed with the
#                             key whose public half the kernel embeds,
#                             PROD_PUBKEY_PATH)
#
# Where it goes: QEMU's PVH entry takes it as `-initrd` (`make qemu-x86_64
# QEMU_X86_64_UCODE=$(UCODE_BIN)`); the PC's ESP carries it as /UCODE.BIN with
# a `module_path:` line in limine.conf (`make x86-pc-esp X86_PC_UCODE=...`,
# mk/qemu.mk), and the kernel is built with PROD_PUBKEY_PATH naming the
# public half of UCODE_PRIV.

AZOS_DL     ?= $(HOME)/azos-dl
UCODE_INTEL ?= $(sort $(wildcard $(AZOS_DL)/intel-ucode/intel-ucode/[0-9a-f]*-[0-9a-f]*-[0-9a-f]*))
UCODE_AMD   ?= $(sort $(wildcard $(AZOS_DL)/amd-fw/amd-ucode/microcode_amd*.bin))
UCODE_PRIV  ?= $(TEST_PRIV_KEY)
UCODE_BIN   ?= $(OUT_BUILD)/UCODE.BIN

.PHONY: ucode
ucode: $(UCODE_BIN)

$(UCODE_BIN): tools/image/mk_ucode.py tools/sign/sigalg.py $(UCODE_INTEL) $(UCODE_AMD) $(UCODE_PRIV)
	@test -n "$(strip $(UCODE_INTEL) $(UCODE_AMD))" || { \
	    echo "[UCODE] no Intel or AMD microcode file under $(AZOS_DL) (intel-ucode/intel-ucode/, amd-fw/amd-ucode/): set AZOS_DL, UCODE_INTEL or UCODE_AMD"; exit 1; }
	@mkdir -p $(dir $@)
	@python3 tools/image/mk_ucode.py --out $@ --priv $(UCODE_PRIV) \
	    $(if $(strip $(UCODE_INTEL)),--intel $(UCODE_INTEL)) $(if $(strip $(UCODE_AMD)),--amd $(UCODE_AMD))
