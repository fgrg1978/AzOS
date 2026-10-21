# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS (Rust) - Makefile wrapper
# Wraps cargo build + QEMU invocation

# This file holds the includes and the top-level targets. The rest is in mk/:
#   vars.mk       variables (read first; it defines no rule)
#   userspace.mk  ring-3 ELFs, SDK, Linux personality binaries, BusyBox, relibc
#   images.mk     image-hash tables, disk images, fixtures, board volumes, topology files
#   kernel.mk     kernel builds, boards, Kconfig targets, micro
#   host.mk       host-side tools (OTA, TFTP, weight files, clean)
#   qemu.mk       QEMU boot targets and smoke runs
#   lints.mk      `make check` and the CI tiers
# The include order matters: prerequisite lists expand when they are read, so a
# variable must be defined before the rule that lists it (images.mk defines the
# TEST key paths that kernel.mk, read after it, uses).

include mk/vars.mk

.PHONY: check0 check1 check-presets check-neverallow check-fast prune all build build-rvv build-fleet clean qemu qemu-smp qemu-full-smp qemu-net-pair \
        qemu-rvv qemu-full-smp-rvv qemu-systest qemu-dhcp-smoke userspace userspace-aarch64 syscall-test make-gguf \
        vf2 vf2-ktest vf2-pstore flash-vf2 k1 flash-k1 k1-console ci

all: build

include mk/userspace.mk
include mk/images.mk
include mk/kernel.mk
include mk/host.mk
include mk/qemu.mk
include mk/lints.mk

help:
	@cat "$(CURDIR)/tools/make_help.txt"
