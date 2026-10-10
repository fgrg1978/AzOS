#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# `make check-fast`: the fronts' check. Per ISA (riscv64, aarch64, x86_64):
#
#   1. ktest   ONE boot of the ktest kernel: every in-kernel test.
#   2. canary  ONE boot of the SAME image with every composable runtime
#              canary armed (`canary=...`, tools/check_fast.py SETS): each
#              must break exactly its own tests.
#   3. system  ONE userspace boot (the abitest volume): the ABI conformance
#              checks, the FAT mount and autorun, no crash.
#
# Each verdict is tools/check_fast.py's, one line per property, with the full
# gate's plan counts and canary sets read from tools/ci_check.sh.
#
# Kernels: two per ISA, built once, serially (cargo's lock serializes them
# anyway): the ktest kernel (`qemu,ktest,chaos,decisions`) for boots 1 and 2,
# the plain `qemu` kernel for boot 3 (a ktest kernel powers off after its
# tests). The ISAs' boot chains then run in parallel, CI_JOBS of them
# (default 3), never past 4 QEMUs host-wide.
#
#   CHECK_FAST_ISAS="rv arm x86"   which ISAs
#   CHECK_FAST_SYSTEM_APPEND=...   kernel command line of the system boot
#                                  (e.g. canary=x86-fork-fp-skip: abitest red)
#   CHECK_FAST_KTEST_APPEND=...    the same for the ktest boot (a canary there
#                                  must turn the ktest verdict red)
#   CHECK_FAST_NOBUILD=1           boot the kernels of the previous run
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
REPO="$PWD"
export TOPOLOGY_PUBKEY_PATH="${TOPOLOGY_PUBKEY_PATH:-$REPO/tools/keys/test_pub.bin}"
ISAS="${CHECK_FAST_ISAS:-rv arm x86}"
JOBS="${GATE_JOBS:-${CI_JOBS:-3}}"
OUT="$REPO/target/check-fast"
KTEST_FEATS="qemu,ktest,chaos,decisions"
BOOT_LIMIT_S="${CHECK_FAST_BOOT_LIMIT_S:-300}"
mkdir -p "$OUT"
t0=$SECONDS

# The gate's own configurations (tools/ci_check.sh primary_config /
# aarch64_config): the same paths, so the kernels share its build cache.
cfg() { # cfg <defconfig> <out>
    local tmp; tmp="$(mktemp -d)" || return 1
    mkdir -p "$(dirname "$2")"
    cp "config/defconfigs/$1" "$tmp/c" && KCONFIG_CONFIG="$tmp/c" python3 -m olddefconfig >/dev/null 2>&1 \
        && { cmp -s "$tmp/c" "$2" || cp "$tmp/c" "$2"; }
    local rc=$?; rm -rf "$tmp"; return $rc
}
RV_CFG="$REPO/target/primary/qemu.config"
ARM_CFG="$REPO/target/primary-aarch64/qemu-aarch64.config"
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"

build_rv() { # build_rv <features> <copy>
    KCONFIG_CONFIG="$RV_CFG" cargo build --release --features "$1" >>"$OUT/build-rv.log" 2>&1 \
        && cp target/riscv64imac-unknown-none-elf/release/kernel "$2"
}
build_arm() {
    env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$ARM_CFG" cargo build --release \
        --target aarch64-unknown-none-softfloat -p azos_kernel --features "$1" \
        --config 'build.rustflags=["-C","link-arg=-Tkernel/linker-aarch64.ld"]' >>"$OUT/build-arm.log" 2>&1 \
        && "$OBJCOPY" -O binary target/aarch64-unknown-none-softfloat/release/kernel "$2"
}
build_x86() { # the x86_64 build adds `qemu` itself; X86_64_FEATURES are the extras
    make x86_64 X86_64_FEATURES="$1" >>"$OUT/build-x86.log" 2>&1 && cp build/kernel-x86_64.elf "$2"
}
DISK_rv=build/disk-abitest.img
DISK_arm=build/disk-aarch64-abitest.img
DISK_x86=build/disk-x86_64-abitest.img

builds_ok=1
if [ "${CHECK_FAST_NOBUILD:-0}" != 1 ]; then
    cfg qemu.config "$RV_CFG" && cfg qemu-aarch64.config "$ARM_CFG" || { echo "check-fast: olddefconfig failed"; exit 2; }
    for isa in $ISAS; do
        b0=$SECONDS; : >"$OUT/build-$isa.log"
        printf "  %-44s" "build $isa (ktest + qemu kernels, disk)"
        rm -f "$OUT/$isa-ktest.k" "$OUT/$isa-sys.k" "$OUT/$isa-sys.img"
        case $isa in
            rv) build_rv "$KTEST_FEATS" "$OUT/rv-ktest.k" && build_rv qemu "$OUT/rv-sys.k" ;;
            arm) build_arm "$KTEST_FEATS" "$OUT/arm-ktest.k" && build_arm qemu "$OUT/arm-sys.k" ;;
            x86) build_x86 ktest,chaos,decisions "$OUT/x86-ktest.k" && build_x86 "" "$OUT/x86-sys.k" ;;
        esac
        d="DISK_$isa"
        if [ -f "$OUT/$isa-sys.k" ] && rm -f "${!d}" && make "${!d}" >>"$OUT/build-$isa.log" 2>&1 \
           && cp "${!d}" "$OUT/$isa-sys.img"; then
            echo "ok ($((SECONDS - b0)) s)"
        else
            echo "FAIL (see $OUT/build-$isa.log)"; builds_ok=0
            grep -E '^(error|warning)' "$OUT/build-$isa.log" | sed -n 1,5p | sed 's/^/      /'
        fi
    done
    [ "$builds_ok" = 1 ] || { echo "check-fast: RED (build) after $((SECONDS - t0)) s"; exit 1; }
fi
tb=$SECONDS

qemu_slots() { echo $(( $(pgrep -x qemu-system-riscv64 | wc -l) + $(pgrep -x qemu-system-aarch64 | wc -l) + $(pgrep -x qemu-system-x86_64 | wc -l) )); }

# boot <isa> <kind: ktest|canary|system> <log> [append]; prints QEMU's status.
boot() {
    local isa="$1" kind="$2" log="$3" app="${4:-}" k disk="" stop="" i=0
    local -a ap=() dev=(); [ -n "$app" ] && ap=(-append "$app")
    if [ "$kind" = system ]; then
        k="$OUT/$isa-sys.k"; disk="$OUT/$isa-sys.run.img"; cp "$OUT/$isa-sys.img" "$disk"
        dev=(-drive "file=$disk,if=none,format=raw,id=hd0" -device virtio-blk-device,drive=hd0)
        stop='\[ABITEST\] [0-9]+ check\(s\) run|KERNEL PANIC|\[FATAL\]|AARCH64-TRAP\] unhandled'
    else
        k="$OUT/$isa-ktest.k"
    fi
    while [ "$(qemu_slots)" -ge 4 ]; do sleep 2; done
    : >"$log"
    case $isa in
        rv) qemu-system-riscv64 -machine virt -nographic -bios default -kernel "$k" \
                -smp 4 ${dev[@]+-global virtio-mmio.force-legacy=false} ${ap[@]+"${ap[@]}"} ${dev[@]+"${dev[@]}"} </dev/null >"$log" 2>&1 & ;;
        arm) qemu-system-aarch64 -M virt,gic-version=3 -cpu max,pauth=on -smp "$([ "$kind" = system ] && echo 2 || echo 4)" -nographic \
                -semihosting-config enable=on,target=native -kernel "$k" \
                ${dev[@]+-global virtio-mmio.force-legacy=false} ${ap[@]+"${ap[@]}"} ${dev[@]+"${dev[@]}"} </dev/null >"$log" 2>&1 & ;;
        x86) qemu-system-x86_64 -M microvm -cpu max -m 256M -nographic -no-reboot \
                -device isa-debug-exit,iobase=0xf4,iosize=0x04 -smp "$([ "$kind" = system ] && echo 2 || echo 4)" \
                ${ap[@]+"${ap[@]}"} ${dev[@]+"${dev[@]}"} -kernel "$k" </dev/null >"$log" 2>&1 & ;;
    esac
    local pid=$!
    while [ "$i" -lt $((BOOT_LIMIT_S * 2)) ] && kill -0 "$pid" 2>/dev/null; do
        # abitest's `FAILED: N` line follows its summary: one settle second.
        if [ -n "$stop" ] && tr -d '\r' <"$log" | grep -aqE "$stop"; then sleep 1; break; fi
        i=$((i + 1)); sleep 0.5
    done
    local rc=stopped
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null; sleep 1; kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    else
        wait "$pid" 2>/dev/null; rc=$?
    fi
    rm -f ${disk:+"$disk"}
    echo "$rc"
}

# One ISA's chain: three boots, judged as they land; the verdict file holds
# the judge's lines.
chain() {
    local isa="$1" v="$OUT/$isa.verdict" c0=$SECONDS rc can fail=0
    : >"$v"
    rc="$(boot "$isa" ktest "$OUT/$isa-ktest.log" "${CHECK_FAST_KTEST_APPEND:-}")"
    { echo "[$isa] ktest ($(( SECONDS - c0 )) s)"; python3 tools/check_fast.py ktest "$isa" "$OUT/$isa-ktest.log" "$rc"; } >>"$v" || fail=1
    c0=$SECONDS; can="$(python3 tools/check_fast.py cmdline "$isa")"
    rc="$(boot "$isa" canary "$OUT/$isa-canary.log" "$can")"
    { echo "[$isa] runtime canaries, one boot ($(( SECONDS - c0 )) s)"; python3 tools/check_fast.py canary "$isa" "$OUT/$isa-canary.log" "$rc"; } >>"$v" || fail=1
    c0=$SECONDS
    rc="$(boot "$isa" system "$OUT/$isa-system.log" "${CHECK_FAST_SYSTEM_APPEND:-}")"
    { echo "[$isa] system ($(( SECONDS - c0 )) s)"; python3 tools/check_fast.py system "$isa" "$OUT/$isa-system.log"; } >>"$v" || fail=1
    echo "$fail" >"$OUT/$isa.rc"
}

running=0
for isa in $ISAS; do
    rm -f "$OUT/$isa.rc"
    chain "$isa" &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
done
wait
red=0
for isa in $ISAS; do
    cat "$OUT/$isa.verdict"
    [ "$(cat "$OUT/$isa.rc" 2>/dev/null)" = 0 ] || red=1
done
echo "check-fast: $([ "$red" = 0 ] && echo green || echo RED), $((SECONDS - t0)) s (builds $((tb - t0)) s, boots $((SECONDS - tb)) s, CI_JOBS=$JOBS); logs in $OUT"
exit "$red"
