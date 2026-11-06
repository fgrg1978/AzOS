#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# x86_64_simd_free_check: prove the x86_64 KERNEL executes no SIMD instruction
# and picks nothing from CPUID outside its own CPU code.
#
#   bash tools/lint/x86_64_simd_free_check.sh <kernel ELF>
#   bash tools/lint/x86_64_simd_free_check.sh --self-test
#
# The kernel is soft-float and keeps no SIMD state at CPL0: it saves a task's
# FP state at a switch and restores it on the way back to ring 3, and nothing
# in between may touch the registers (arch/x86_64/src/fp.rs, which does so with
# xsave/xrstor, instructions that name no register). The RustCrypto crates
# azos_crypto links carry CPUID-selected SSE2/AVX2/AES-NI/SHA-NI code; the
# build pins their portable backends (tools/build/kconfig_to_cargo.py,
# crates/core/crypto/Cargo.toml) and this script proves the linked ELF:
#
#   * no instruction names an xmm/ymm/zmm/mm register or MXCSR, anywhere;
#   * `cpuid` appears only in the kernel's own code (CPU_PREFIXES: the boot,
#     the feature probes, the serialising uses), never in a library's.
#
# Exit status: 0 = clean, 1 = a violation (listed), 2 = could not run.

set -u

OBJDUMP="${OBJDUMP:-$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objdump}"
[ -x "$OBJDUMP" ] || { echo "x86_64_simd_free_check: llvm-objdump not found: $OBJDUMP" >&2; exit 2; }

# Demangled symbol prefixes whose code may execute `cpuid`.
CPU_PREFIXES='
kernel::
azos_arch_x86_64::
<azos_arch_x86_64::
_start
'

check() { # check <ELF>: the verdict on stdout, the exit status as above
    local elf="$1" dis hits bad
    dis="$("$OBJDUMP" -d --no-show-raw-insn --demangle "$elf" 2>/dev/null)"
    [ -n "$dis" ] || { echo "x86_64_simd_free_check: empty disassembly of $elf" >&2; return 2; }
    # "<simd|cpuid>\t<symbol>\t<instruction>" per offending line; the `<...>`
    # target annotation is dropped first so a symbol NAME cannot match.
    hits="$(printf '%s\n' "$dis" | awk '
        /^[0-9a-f]+ <.*>:$/ { sym = $0; sub(/^[0-9a-f]+ </, "", sym); sub(/>:$/, "", sym); next }
        /^ *[0-9a-f]+:[ \t]/ {
            line = $0; sub(/ <.*$/, "", line)
            n = split(line, f, "\t"); ins = f[2] " " f[3]
            if (f[3] ~ /%([xyz]mm[0-9]|mm[0-7]|mxcsr)/ || f[2] ~ /^(ldmxcsr|stmxcsr|vldmxcsr|vstmxcsr)$/) print "simd\t" sym "\t" ins
            else if (f[2] ~ /^cpuid/) print "cpuid\t" sym "\t" ins
        }')"
    bad=""
    while IFS="$(printf '\t')" read -r kind sym ins; do
        [ -n "$kind" ] || continue
        if [ "$kind" = cpuid ]; then
            local ok=0 p
            for p in $CPU_PREFIXES; do
                case "$sym" in "$p"*) ok=1; break ;; esac
            done
            [ "$ok" -eq 1 ] && continue
        fi
        bad="$bad$kind	$sym	$ins
"
    done <<EOF
$hits
EOF
    if [ -n "$bad" ]; then
        echo "x86_64_simd_free_check: $elf:"
        printf '%s' "$bad" | awk -F '\t' '!seen[$1 FS $2]++ { print "    " $1 " in " $2 ": " $3 }'
        return 1
    fi
    echo "x86_64_simd_free_check: clean ($(printf '%s\n' "$hits" | grep -c '^cpuid') cpuid site(s), all in the kernel's own code; no SIMD register)"
    return 0
}

if [ "${1:-}" = --self-test ]; then
    CC="${CC:-clang}"
    command -v "$CC" >/dev/null 2>&1 || { echo "x86_64_simd_free_check: --self-test needs an assembler ($CC)" >&2; exit 2; }
    t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
    asm() { # asm <name> <body>: an x86_64 ELF object at $t/<name>.o
        printf '%s\n' "$2" >"$t/$1.s"
        "$CC" -target x86_64-unknown-none-elf -c "$t/$1.s" -o "$t/$1.o" 2>"$t/$1.err" \
            || { echo "x86_64_simd_free_check: --self-test cannot assemble: $(cat "$t/$1.err")" >&2; exit 2; }
    }
    asm clean '"azos_arch_x86_64::cpu::features::detect": cpuid
 ret
"kernel::other": xsave (%rdi)
 ret'
    asm sse '"kernel::copy": movaps %xmm1, %xmm0
 ret'
    asm lib '"sha2::sha256::x86::shani_cpuid::init": cpuid
 ret'
    fail=0
    check "$t/clean.o" >/dev/null; [ $? -eq 0 ] || { echo "self-test: the clean object was refused"; fail=1; }
    check "$t/sse.o" >/dev/null; [ $? -eq 1 ] || { echo "self-test: one SSE instruction passed"; fail=1; }
    check "$t/lib.o" >/dev/null; [ $? -eq 1 ] || { echo "self-test: a library's cpuid passed"; fail=1; }
    [ "$fail" -eq 0 ] && echo "x86_64_simd_free_check: self-test ok (a clean object passes; one SSE instruction and a library cpuid fail)"
    exit "$fail"
fi

ELF="${1:-}"
[ -n "$ELF" ] && [ -f "$ELF" ] || { echo "x86_64_simd_free_check: no ELF: '$ELF'" >&2; exit 2; }
check "$ELF"
exit $?
