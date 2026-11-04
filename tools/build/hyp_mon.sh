#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Build the resident monitor (crates/core/hyp-mon) into a flat image for the
# kernel's `.hyp` section, and prove the link invariant: the monitor resolves
# no kernel symbol (no undefined symbols, not a dynamic object). Position-
# independent, its own linker script, `.bss` carried in the blob as zeros so
# the kernel's hole is one extent and the monitor needs no runtime bss clear.
#
# Usage: hyp_mon.sh <isa> <out.bin> [feature,feature,...]
# Only aarch64 is implemented; riscv64 and x86_64 keep their layout and build
# nothing until their monitor lands (ARCH_HAS_HYP_MONITOR unset there).
set -euo pipefail
ISA="${1:?isa}"; OUT="${2:?out.bin}"; FEATS="${3:-}"
CRATE="crates/core/hyp-mon"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [ "$ISA" != aarch64 ]; then
    echo "hyp_mon.sh: $ISA has no monitor yet (ARCH_HAS_HYP_MONITOR unset)"; exit 2
fi

TARGET=aarch64-unknown-none-softfloat
TGTDIR="${HYP_MON_TARGET_DIR:-${AZOS_OUT:?AZOS_OUT}/hyp-mon}"
ELF="$TGTDIR/$TARGET/release/hyp-mon"
sel=()
[ -n "$FEATS" ] && sel=(--features "$FEATS")

( cd "$CRATE" && env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
    RUSTFLAGS="-C relocation-model=pic -C link-arg=-Taarch64/hyp-mon.ld" \
    CARGO_TARGET_DIR="$TGTDIR" \
    cargo build --release --target "$TARGET" \
      -Z build-std=core -Z build-std-features=compiler-builtins-mem ${sel+"${sel[@]}"} )

SR="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
NM="$SR/llvm-nm"; OBJCOPY="$SR/llvm-objcopy"

# Link invariant: no undefined symbol (a reference to a kernel symbol would be
# one) and no dynamic relocation (a fully resolved static image).
undef="$("$NM" -u "$ELF" || true)"
if [ -n "$undef" ]; then
    echo "hyp_mon link FAIL: the monitor has undefined symbols (a kernel reference?):"
    echo "$undef"; exit 1
fi
if "$SR/llvm-readobj" --dynamic-table "$ELF" 2>/dev/null | grep -q 'DynamicSection\|DT_'; then
    echo "hyp_mon link FAIL: the monitor is a dynamic object (unresolved at link)"; exit 1
fi

mkdir -p "$(dirname "$OUT")"
"$OBJCOPY" -O binary --set-section-flags .bss=alloc,load,contents "$ELF" "$OUT"
echo "hyp-mon ($ISA${FEATS:+, $FEATS}): $(wc -c < "$OUT") bytes -> $OUT"
