#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# aarch64_fp_free_check: prove the aarch64 KERNEL touches no FP/SIMD register
# outside the functions that exist to move user FP state.
#
#   bash tools/aarch64_fp_free_check.sh <kernel ELF>
#
# The kernel is built for `aarch64-unknown-none-softfloat`, so rustc never
# allocates a V/Q/D/S/H/B register or emits an FP instruction on its own.
# What remains is hand-written: inline asm and the `.S` files. This script
# disassembles the whole ELF, attributes every instruction that names an
# FP/SIMD register (or FPCR/FPSR) to its enclosing symbol, and fails if any
# symbol outside ALLOWED does so.
#
# ALLOWED is the complete list of places that legitimately touch FP state:
# `context_switch` (lazy save of the outgoing task's live user state), the
# two `fp_state` helpers (lazy load on first use; fork snapshot), and two
# boot-only probes that run before any user task exists, and (wave 13) the
# FEAT_SHA256 block function `azos_sha256_ce_blocks`, plain assembly the
# kernel reaches only through `fp_lazy::with_kernel_simd`. The trap entry and
# `trap_return` are deliberately NOT allowed: they must not save or restore
# FP state any more, and a reintroduced `stp q`/`ldp q` there fails this.
#
# Exit status: 0 = clean, 1 = an FP/SIMD use outside ALLOWED (listed),
# 2 = could not run (missing tool / ELF / empty disassembly).

set -u

ELF="${1:-}"
[ -n "$ELF" ] && [ -f "$ELF" ] || { echo "aarch64_fp_free_check: no ELF: '$ELF'" >&2; exit 2; }

OBJDUMP="${OBJDUMP:-$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objdump}"
[ -x "$OBJDUMP" ] || { echo "aarch64_fp_free_check: llvm-objdump not found: $OBJDUMP" >&2; exit 2; }

# Symbols allowed to name FP/SIMD registers: exact demangled names (the
# kernel binary crate is `kernel`; a trailing `::h<hash>` is ignored).
ALLOWED='
context_switch
azos_arch_aarch64::fp_state::save_fp_state
azos_arch_aarch64::fp_state::restore_fp_state
kernel::entry::aarch64::fp_survives_interrupt_probe
kernel::boot_hooks::fp_self_check
azos_sha256_ce_blocks
'

dis="$("$OBJDUMP" -d --no-show-raw-insn --demangle "$ELF" 2>/dev/null)"
[ -n "$dis" ] || { echo "aarch64_fp_free_check: empty disassembly of $ELF" >&2; exit 2; }

# One line per offending instruction: "<symbol>\t<instruction>". The operand
# regex names every FP/SIMD register form (v0.16b, q3, d8, s0, h1, b2) and the
# two FP control/status registers. `<...>` symbol annotations are stripped
# first so a symbol whose NAME contains "d8" cannot match.
hits="$(printf '%s\n' "$dis" | awk '
    /^[0-9a-f]+ <.*>:$/ {
        sym = $0; sub(/^[0-9a-f]+ </, "", sym); sub(/>:$/, "", sym); next
    }
    /^ *[0-9a-f]+:[ \t]/ {
        line = $0; sub(/<[^>]*>/, "", line)
        n = split(line, f, "\t"); ins = f[2] " " f[3]
        ops = f[3]
        if (ops ~ /(^|[^a-z0-9_])([vqdshb]([0-9]|[12][0-9]|3[01]))([^0-9a-z_]|\.|$)/ \
            || ops ~ /(^|[^a-z_])(fpcr|fpsr)([^a-z_]|$)/) {
            print sym "\t" ins
        }
    }')"

bad=""
while IFS="$(printf '\t')" read -r sym ins; do
    [ -n "$sym" ] || continue
    ok=0
    for a in $ALLOWED; do
        # Strip a trailing Rust hash (`::h0123abcd...`) before comparing.
        s="${sym%::h[0-9a-f]*}"
        [ "$s" = "$a" ] && { ok=1; break; }
    done
    [ "$ok" -eq 1 ] || bad="$bad$sym	$ins
"
done <<EOF
$hits
EOF

if [ -n "$bad" ]; then
    nfn="$(printf '%s' "$bad" | cut -f1 | sort -u | grep -c .)"
    echo "aarch64_fp_free_check: FP/SIMD register use outside the allowed set in $nfn function(s):"
    printf '%s' "$bad" | cut -f1 | sort | uniq -c | sort -rn | sed 's/^/    /'
    echo "  first instruction per function:"
    printf '%s' "$bad" | awk -F '\t' '!seen[$1]++ { print "    " $1 ": " $2 }'
    exit 1
fi
nallowed="$(printf '%s\n' "$hits" | cut -f1 | sort -u | grep -c .)"
echo "aarch64_fp_free_check: clean ($nallowed allowed symbol(s) touch FP/SIMD state, nothing else does)"
exit 0
