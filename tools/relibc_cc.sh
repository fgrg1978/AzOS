#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The C compiler cargo's `cc` crate calls while building relibc's few C files
# (src/c): `zig cc` for the freestanding triple of $AZOS_ISA, with the flags
# `cc` derives from the Rust target name (it does not know `*-unknown-azos`)
# dropped; `-fPIC` stays (the programs are static PIEs, sdk/targets). Set by
# tools/relibc_build.sh.
set -u
case "${AZOS_ISA:-}" in
    riscv64) t=(-target riscv64-freestanding -mcpu=generic_rv64+m+a+c) ;;
    aarch64) t=(-target aarch64-freestanding -mstrict-align) ;;
    x86_64)  t=(-target x86_64-freestanding) ;;
    *) echo "relibc_cc: AZOS_ISA is not set" >&2; exit 2 ;;
esac
args=()
for a in "$@"; do
    case "$a" in --target=*|-m64|-march=*|-mabi=*) ;; *) args+=("$a") ;; esac
done
exec "${RELIBC_ZIG:-zig}" cc "${t[@]}" "${args[@]}"
