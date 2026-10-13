#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The C compiler `make busybox` hands BusyBox's build (RFC-0047 stage 3):
# `zig cc -target $BUSYBOX_ZIG_TARGET` (zig bundles musl and the Linux uapi
# headers), with the GNU ld options BusyBox's scripts/trylink passes that
# zig's linker refuses dropped (--warn-common, --sort-common,
# --sort-section, --verbose, --cref, -Map <file>). Nothing else changes.
set -u
args=()
for a in "$@"; do
  case "$a" in
    -Wl,*)
      IFS=',' read -ra parts <<< "${a#-Wl,}"; keep=(); skip=0
      for p in "${parts[@]}"; do
        if [ "$skip" = 1 ]; then skip=0; continue; fi
        case "$p" in
          --warn-common|--sort-common|--sort-section=*|--verbose|--cref) ;;
          -Map|--sort-section) skip=1 ;;
          *) keep+=("$p") ;;
        esac
      done
      if [ ${#keep[@]} -gt 0 ]; then args+=("-Wl,$(IFS=,; echo "${keep[*]}")"); fi ;;
    *) args+=("$a") ;;
  esac
done
exec "${BUSYBOX_ZIG:-zig}" cc -target "$BUSYBOX_ZIG_TARGET" "${args[@]}"
