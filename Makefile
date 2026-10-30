# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS (Rust) - Makefile wrapper
# Wraps cargo build + QEMU invocation

# This file holds the includes and the top-level targets. The rest is in mk/:
#   vars.mk       variables (read first; it defines no rule)
#   userspace.mk  ring-3 ELFs, SDK, Linux personality binaries, BusyBox, relibc
#   images.mk     image-hash tables, disk images, fixtures, board volumes, topology files
#   firmware.mk   firmware the kernel loads into the hardware (the x86 microcode image)
#   kernel.mk     kernel builds, boards, Kconfig targets, micro
#   host.mk       host-side tools (OTA, TFTP, weight files, clean)
#   qemu.mk       QEMU boot targets and smoke runs
#   lints.mk      `make check` and the CI tiers
# The include order matters: prerequisite lists expand when they are read, so a
# variable must be defined before the rule that lists it (images.mk defines the
# TEST key paths that kernel.mk, read after it, uses).

# make splits words on spaces, so a path with one cannot be a target or a
# prerequisite, and every output here is named by its absolute path. An
# output root under such a path stops every goal at parse time; a checkout
# under one (iCloud Drive's "Mobile Documents") refuses the goals that build
# or run, before anything does: builds belong outside iCloud. The
# configuration goals and help name no checkout path in a rule (they read and
# write its own .config, relative) and stay.
empty :=
SPACE_SAFE_GOALS := config menuconfig nconfig oldconfig olddefconfig savedefconfig defconfig-% help
ifneq ($(findstring $(empty) $(empty),$(AZOS_OUT)),)
$(error build outside iCloud: path has spaces)
endif
ifneq ($(findstring $(empty) $(empty),$(CURDIR)),)
ifneq ($(and $(MAKECMDGOALS),$(if $(filter-out $(SPACE_SAFE_GOALS),$(MAKECMDGOALS)),,y)),y)
$(error build outside iCloud: path has spaces)
endif
endif

include mk/vars.mk

.PHONY: check0 check1 check-presets check-neverallow check-fast prune all build build-rvv build-fleet clean qemu qemu-smp qemu-full-smp qemu-net-pair \
        qemu-rvv qemu-full-smp-rvv qemu-systest qemu-dhcp-smoke userspace userspace-aarch64 syscall-test make-gguf \
        vf2 vf2-ktest vf2-pstore flash-vf2 k1 flash-k1 k1-console ci

all: build

include mk/userspace.mk
include mk/images.mk
include mk/firmware.mk
include mk/kernel.mk
include mk/host.mk
include mk/qemu.mk
include mk/lints.mk

help:
	@cat "$(CURDIR)/tools/build/make_help.txt"
