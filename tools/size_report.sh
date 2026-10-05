#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# tools/size_report.sh — static memory of kernel ELFs: sections, image end,
# per-subsystem (crate) totals, the large static buffers, and what is left of
# a 16 / 64 MiB board once the image and the kernel heap are placed.
#
# Usage:
#   tools/size_report.sh [LABEL=ELF[,CONFIG]] ...
#
# CONFIG is the expanded .config the ELF was built from. The script looks for
# the `azos_limits` generated.rs next to the ELF whose SHA-256 prefix
# matches it and reads the constants (heap, RAM_SIZE, tasks, TCP) from THAT
# file, so a report never pairs an ELF with a config it was not built from.
#
# With no argument, the builds the gate produces, where they exist:
#   default   target/riscv64imac-unknown-none-elf/release/kernel   ${KCONFIG_CONFIG:-.config}
#   fleet     target/fleet/riscv64imac-unknown-none-elf/release/kernel     target/fleet/fleet.config
#   embedded  target/embedded/riscv64imac-unknown-none-elf/release/kernel  target/embedded/embedded.config
#
# Environment: LLVM_BIN (directory holding llvm-nm and llvm-size; default: the
# active rustup toolchain's llvm-tools), TOP (rows in the crate table, 25),
# BIG_KIB (smallest buffer listed, 64).
#
# Figures are what the linker placed: symbol sizes from `llvm-nm -S`, section
# sizes from `llvm-size -A`. Heap, page tables and task frames are not in the
# image; the heap size comes from the config, the rest is reported as what is
# left for the PMM.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

TOP="${TOP:-25}"
BIG_KIB="${BIG_KIB:-64}"
OPENSBI_KIB=2048   # firmware window below the kernel on every rv64 layout here

if [ -z "${LLVM_BIN:-}" ]; then
    sysroot="$(rustc --print sysroot 2>/dev/null)"
    host="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
    LLVM_BIN="${sysroot}/lib/rustlib/${host}/bin"
fi
NM="${LLVM_BIN}/llvm-nm"
SIZE="${LLVM_BIN}/llvm-size"
if [ ! -x "$NM" ] || [ ! -x "$SIZE" ]; then
    echo "size_report: llvm-nm/llvm-size not found in ${LLVM_BIN}" >&2
    echo "  (rustup component add llvm-tools-preview, or set LLVM_BIN)" >&2
    exit 2
fi

if [ "$#" -eq 0 ]; then
    set -- \
        "default=target/riscv64imac-unknown-none-elf/release/kernel,${KCONFIG_CONFIG:-.config}" \
        "fleet=target/fleet/riscv64imac-unknown-none-elf/release/kernel,target/fleet/fleet.config" \
        "embedded=target/embedded/riscv64imac-unknown-none-elf/release/kernel,target/embedded/embedded.config"
fi

kib() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1024 }'; }

# Value of `pub const NAME: T = V;` in a generated.rs, or empty.
gen_const() { sed -n "s/^pub const $2: [a-z0-9]* = \\(.*\\);$/\\1/p" "$1"; }

report() {
    local label="$1" elf="$2" cfg="$3"
    echo "=================================================================="
    echo "== ${label}"
    echo "=================================================================="
    if [ ! -f "$elf" ]; then
        echo "  not built: $elf"
        echo ""
        return
    fi
    echo "  elf:    $elf ($(date -r "$elf" '+%Y-%m-%d %H:%M'))"

    # --- The config the ELF was compiled from --------------------------------
    local gen="" sha=""
    if [ -n "$cfg" ] && [ -f "$cfg" ]; then
        sha="$(shasum -a 256 "$cfg" | cut -c1-12)"
        gen="$(grep -l "Config SHA-256 prefix: ${sha} " \
            "$(dirname "$elf")"/build/azos_limits-*/out/generated.rs 2>/dev/null | sed -n 1p)"
        if [ -n "$gen" ]; then
            echo "  config: $cfg ($sha, compiled in)"
        else
            echo "  config: $cfg ($sha) is NOT the one compiled into this ELF:"
            echo "          no generated.rs under $(dirname "$elf")/build carries it"
        fi
    else
        echo "  config: none given"
    fi
    local profile="?" ram_mib="" ram_base="" heap="" tasks="" kstack="" conns="" tcpbuf=""
    if [ -n "$gen" ]; then
        for p in EMBEDDED EDGE FLEET; do
            [ "$(gen_const "$gen" "PROFILE_$p")" = "true" ] && profile="$p"
        done
        ram_mib="$(gen_const "$gen" RAM_SIZE)"
        ram_base="$(gen_const "$gen" RAM_BASE)"
        heap="$(gen_const "$gen" KERNEL_HEAP_SIZE_BYTES)"
        tasks="$(gen_const "$gen" MAX_TASKS)"
        kstack="$(gen_const "$gen" KERNEL_STACK_SIZE_BYTES)"
        conns="$(gen_const "$gen" TCP_MAX_CONNS)"
        tcpbuf="$(gen_const "$gen" TCP_BUF_SIZE)"
        echo "  consts: PROFILE_${profile} RAM_SIZE=${ram_mib} MiB KERNEL_HEAP=$(kib "$heap") KiB" \
             "MAX_TASKS=${tasks} KERNEL_STACK=${kstack} B TCP=${conns}x${tcpbuf} B"
    fi

    # --- Sections -------------------------------------------------------------
    echo ""
    echo "  section                      bytes         KiB"
    "$SIZE" -A "$elf" | awk '
        $1 ~ /^\./ && $1 !~ /^\.(debug|riscv\.attributes|comment|symtab|strtab|shstrtab)/ {
            printf "  %-20s %13d %11.1f\n", $1, $2, $2 / 1024
        }'

    # --- Image bounds ---------------------------------------------------------
    local syms text_start kernel_end stack_start stack_end bss_end
    syms="$("$NM" "$elf" 2>/dev/null)"
    sym() { printf '%s\n' "$syms" | awk -v n="$1" '$3 == n { print $1; exit }'; }
    text_start="$(sym _text_start)"; kernel_end="$(sym _kernel_end)"
    stack_start="$(sym _stack_start)"; stack_end="$(sym _stack_end)"; bss_end="$(sym _bss_end)"
    local image=$(( 0x${kernel_end:-0} - 0x${text_start:-0} ))
    echo ""
    echo "  _text_start  0x${text_start}"
    echo "  _bss_end     0x${bss_end}"
    echo "  _stack_start 0x${stack_start}   _stack_end 0x${stack_end}"
    echo "  _kernel_end  0x${kernel_end}"
    printf "  image [_text_start, _kernel_end): %d B = %s KiB\n" "$image" "$(kib "$image")"
    if [ -z "$stack_end" ] || [ $((0x$stack_end)) -gt $((0x$kernel_end)) ]; then
        echo "  WARNING: boot stack is not inside the image: this ELF was linked with a"
        echo "           script older than the in-image .stack section; rebuild it."
    fi

    # --- Per subsystem --------------------------------------------------------
    # The crate is the first path segment of the demangled name; `<T as Trait>`
    # impls count toward T's crate. Local labels and names that do not demangle
    # to a path are "(unattributed)". Symbol sizes exclude alignment padding, so
    # the sum is compared with the sections'.
    local nmS
    nmS="$("$NM" -S -C --defined-only "$elf" 2>/dev/null)"
    echo ""
    echo "  subsystem (crate)                       text      rodata        data         bss       total (KiB)"
    printf '%s\n' "$nmS" | awk -v top="$TOP" '
        NF >= 4 && length($2) >= 8 && $3 ~ /^[tTrRdDbBsSgG]$/ {
            size = strtonum_hex($2)
            name = $4; for (i = 5; i <= NF; i++) name = name " " $i
            n = name; sub(/^<(&mut |&)?/, "", n)
            crate = n; k = index(n, "::")
            if (k > 0) crate = substr(n, 1, k - 1); else crate = "(unattributed)"
            if (crate ~ /[ .$]/ || crate ~ /^_R/) crate = "(unattributed)"
            t = $3
            if (t ~ /[tT]/) text[crate] += size
            else if (t ~ /[rR]/) ro[crate] += size
            else if (t ~ /[dDgG]/) dat[crate] += size
            else bss[crate] += size
            tot[crate] += size; seen[crate] = 1
            all += size
        }
        function strtonum_hex(h,   i, c, v) {
            v = 0; h = tolower(h)
            for (i = 1; i <= length(h); i++) {
                c = index("0123456789abcdef", substr(h, i, 1)) - 1
                v = v * 16 + c
            }
            return v
        }
        END {
            for (c in seen) print tot[c], c, text[c] + 0, ro[c] + 0, dat[c] + 0, bss[c] + 0
            print "SUM", all
        }' | sort -k1,1nr | awk -v top="$TOP" '
        $1 == "SUM" { sum = $2; next }
        {
            row++
            if (row <= top) {
                printf "  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f\n", $2, $3/1024, $4/1024, $5/1024, $6/1024, $1/1024
            } else { ot += $3; oro += $4; od += $5; ob += $6; o += $1; others++ }
        }
        END {
            if (others > 0)
                printf "  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f\n", "(" others " more)", ot/1024, oro/1024, od/1024, ob/1024, o/1024
            printf "  %-32s %59.1f\n", "symbols, all crates", sum/1024
        }'

    # --- Large static buffers --------------------------------------------------
    echo ""
    echo "  static objects >= ${BIG_KIB} KiB (data and bss)                            bytes         KiB"
    printf '%s\n' "$nmS" | awk -v min="$((BIG_KIB * 1024))" '
        function hex(h,   i, v) { v = 0; h = tolower(h); for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return v }
        NF >= 4 && $3 ~ /^[dDbBsSgG]$/ {
            s = hex($2)
            if (s >= min) {
                name = $4; for (i = 5; i <= NF; i++) name = name " " $i
                sub(/ \(\.llvm\.[0-9]+\)$/, "", name)
                printf "%d\t%s\n", s, name
            }
        }' | sort -k1,1nr | awk -F'\t' '{ printf "  %-68s %11d %11.1f\n", $2, $1, $1 / 1024 }'

    # Named buffers the budget discussion refers to: absent means not linked.
    echo ""
    echo "  named buffers                                         bytes         KiB"
    local pat what
    for pair in \
        "secure_boot_verify_image_detailed::IMG_BUF|secure boot image buffer (IMG_BUF)" \
        "dfu_recovery::DFU_STAGING|DFU staging (DFU_STAGING)" \
        "azos_net::tcp::TCP|TCP connection table (TCP)" \
        "scheduler::TASK_STACKS|task kernel stacks (TASK_STACKS)" \
        "scheduler::TASKS|task slots (TASKS)" \
        "scheduler::PER_CPU|per-CPU scheduler state (PER_CPU)" \
        "azos_mm::pmm::PMM|PMM bitmap (PMM)" \
        "cap_store::CAP_TABLES|capability tables (CAP_TABLES)" \
        "azos_ipc::pipe::PIPES|pipes (PIPES)" \
        "cmd_exec::ELF_BUF|shell exec buffer (ELF_BUF)" \
        "handlers::EXEC_BOUNCE|exec bounce buffer (EXEC_BOUNCE)"; do
        pat="${pair%%|*}"; what="${pair#*|}"
        printf '%s\n' "$nmS" | awk -v pat="$pat" -v what="$what" '
            function hex(h,   i, v) { v = 0; h = tolower(h); for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return v }
            NF >= 4 && $3 ~ /^[dDbBsSgG]$/ {
                name = $4; for (i = 5; i <= NF; i++) name = name " " $i
                sub(/ \(\.llvm\.[0-9]+\)$/, "", name)
                if (substr(name, length(name) - length(pat) + 1) == pat) { s += hex($2); n++ }
            }
            END {
                if (n == 0) printf "  %-50s %23s\n", what, "absent (not linked)"
                else printf "  %-50s %11d %11.1f\n", what, s, s / 1024
            }'
    done

    # --- What is left on a board -----------------------------------------------
    # RAM starts one firmware window below the link address (every rv64 script
    # here links the kernel 2 MiB above RAM; the ELF, not RAM_BASE, is the
    # authority: the qemu build of an edge/VF2 .config links at 0x80200000).
    # The heap is reserved right after _kernel_end (kernel/src/entry/{riscv64,aarch64}/boot_hooks.rs). What
    # remains is the PMM's for page tables, task frames and user memory. The
    # device tree QEMU passes also sits in the top megabytes of RAM.
    if [ -n "$heap" ] && [ -n "$text_start" ]; then
        echo ""
        echo "  board RAM   image + heap (KiB)   left for PMM frames (KiB)"
        local rb=$(( 0x$text_start - OPENSBI_KIB * 1024 )) mib need left
        for mib in 16 64 ${ram_mib}; do
            need=$(( image + heap ))
            left=$(( rb + mib * 1024 * 1024 - 0x$kernel_end - heap ))
            printf "  %4d MiB    %18s   %24s%s\n" "$mib" "$(kib "$need")" "$(kib "$left")" \
                "$([ "$left" -lt 0 ] && echo '   DOES NOT FIT')"
        done | awk '!seen[$0]++'
    fi
    echo ""
}

for arg in "$@"; do
    label="${arg%%=*}"
    rest="${arg#*=}"
    elf="${rest%%,*}"
    cfg=""
    case "$rest" in *,*) cfg="${rest#*,}" ;; esac
    report "$label" "$elf" "$cfg"
done
