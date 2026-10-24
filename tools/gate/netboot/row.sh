#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# One network-boot row: boot QEMU with NOTHING on a disk, let the firmware fetch
# AzOS over the network, and judge the console.
#
#   tools/gate/netboot/row.sh <case> <kernel image> [logdir]
#
# The kernel image is what tools/gate/netboot/kernel_image.sh prints for the case's
# ISA (an x86_64 Limine ELF, a riscv64 flat binary). The log is kept in <logdir>
# (default $AZOS_OUT/build/netboot-logs) when the row fails, removed when it
# passes. Exit 0: the case did what it is meant to do; 1: it did not (the
# reason on stdout); 2: the row cannot run here (a firmware file is missing,
# printed): the gate counts that as skipped.
#
# Cases (the ISA, the path, what the case is):
#   x86-pxe              q35 + OVMF: UEFI PXE fetches Limine over TFTP, Limine
#                        its configuration and the kernel; reaches the banner
#   x86-pxe-nofile         canary: the DHCP bootfile names a file the server does not have
#   x86-pxe-badkernel      canary: one byte of the kernel changed after its hash was taken
#   x86-pxe-badconfig      canary: limine.conf changed after its hash was enrolled in Limine
#   x86-http             q35 + OVMF: UEFI HTTP Boot fetches an ESP image (Limine,
#                        configuration, kernel) from a host HTTP server on a port of
#                        this row's own; reaches the banner
#   x86-http-nofile        canary: the URL names a file the server does not have (404)
#   x86-http-badkernel     canary: as x86-pxe-badkernel, inside the image
#   riscv64-tftp         virt + OpenSBI + U-Boot: `dhcp` + `tftpboot` of a signed
#                        FIT, `bootm` verifies it; reaches the banner
#   riscv64-tftp-nofile    canary: the DHCP bootfile names a file the server does not have
#   riscv64-tftp-badkernel canary: one byte of the kernel changed after the image was signed
#   riscv64-tftp-badkey    canary: the image is signed by a key the device tree does not hold
#
# A canary passes only when the boot did NOT reach the banner and the console
# carries the line that names why (the loader's refusal): a sabotaged boot that
# fails for another reason, or that simply never starts, is not a pass.
#
# Environment: LIMINE_DIR (default third_party/limine), OVMF_CODE / OVMF_VARS
# (default QEMU's own edk2 build), U_BOOT_BIN (default: built on demand by
# uboot_build.sh),
# QEMU_X86_64_CPU (default max), NETBOOT_TIMEOUT (seconds per boot, default 150),
# NETBOOT_KEEP=1 (keep the console log of a passing row too).
set -uo pipefail

case_="${1:?usage: row.sh <case> <kernel image> [logdir]}"
kernel="${2:?usage: row.sh <case> <kernel image> [logdir]}"
here="$(cd "$(dirname "$0")/../../.." && pwd)"
export AZOS_OUT="${AZOS_OUT:-$(python3 "$here/tools/lib/out_dir.py")}"
logdir="${3:-$AZOS_OUT/build/netboot-logs}"
limit="${NETBOOT_TIMEOUT:-150}"
nb="$here/tools/gate/netboot"
mkdir -p "$logdir"
work="$(mktemp -d "${TMPDIR:-/tmp}/azos-netboot.XXXXXX")"
log="$logdir/$case_.log"
pids=()
cleanup() {
    local p
    for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    rm -rf "${work:?}"
}
trap cleanup EXIT

skip() { echo "$1"; exit 2; }
fail() { echo "$1"; echo "log kept: $log"; exit 1; }

# The console as text: the firmware paints with escape sequences and the
# serial line carries CR.
text() { python3 -c '
import re, sys
s = open(sys.argv[1], "rb").read().decode("latin1")
sys.stdout.write(re.sub(r"\x1b\[[0-9;?=]*[A-Za-z]", "", s).replace("\r", ""))' "$1"; }

# The most QEMUs the host may run at once (the gate's rule).
qemu_slot() {
    while [ $(( $(pgrep -x qemu-system-riscv64 | wc -l) + $(pgrep -x qemu-system-aarch64 | wc -l) + $(pgrep -x qemu-system-x86_64 | wc -l) )) -ge 4 ]; do sleep 2; done
}

# run_qemu <program> <marker ERE: stop when the console matches> <qemu args...>
run_qemu() {
    local prog="$1" marker="$2" i=0; shift 2
    qemu_slot
    : >"$log"
    "$prog" "$@" </dev/null >"$log" 2>&1 &
    local pid=$!
    pids+=("$pid")
    while [ "$i" -lt "$((limit * 2))" ] && kill -0 "$pid" 2>/dev/null; do
        text "$log" 2>/dev/null | grep -aqE "$marker" && break
        i=$((i + 1)); sleep 0.5
    done
    sleep 1
    kill "$pid" 2>/dev/null; sleep 1; kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    text "$log" >"$log.t" && mv "$log.t" "$log"
}

# want <ERE> <description>: the console carries the line, or the row says what is missing.
want() { grep -aqE -- "$1" "$log" || fail "missing: $2"; }
# deny <ERE> <description>
deny() { grep -aqE -- "$1" "$log" && fail "found: $2: $(grep -aE -- "$1" "$log" | sed -n 1p)"; return 0; }

# verdict <canary yes|no> <banner ERE> <the refusal's ERE> <the refusal in words>
verdict() {
    local canary="$1" banner="$2" why_re="$3" why="$4"
    if [ "$canary" = no ]; then
        deny 'KERNEL PANIC|\[X86-TRAP\]|PANIC: ' "the kernel or the loader panicked"
        want "$banner" "the kernel's banner ($banner): the image never started"
    else
        deny "$banner" "the sabotaged image still booted"
        want "$why_re" "$why"
    fi
    [ -n "${NETBOOT_KEEP:-}" ] || rm -f "${log:?}"
    echo "ok"
    exit 0
}

x86_setup() {
    OVMF_CODE="${OVMF_CODE:-$(ls /opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-x86_64-code.fd /usr/share/qemu/edk2-x86_64-code.fd /usr/share/OVMF/OVMF_CODE.fd 2>/dev/null | sed -n 1p)}"
    [ -f "${OVMF_CODE:-}" ] || skip "no OVMF (OVMF_CODE: QEMU's edk2-x86_64-code.fd)"
    OVMF_VARS="${OVMF_VARS:-$(ls "$(dirname "$OVMF_CODE")"/edk2-i386-vars.fd "$(dirname "$OVMF_CODE")"/OVMF_VARS.fd 2>/dev/null | sed -n 1p)}"
    [ -f "${OVMF_VARS:-}" ] || skip "no OVMF variable store (OVMF_VARS)"
    [ -f "${LIMINE_DIR:-$here/third_party/limine}/BOOTX64.EFI" ] || skip "no Limine (tools/build/third_party_fetch.sh limine, or LIMINE_DIR)"
    command -v mkfs.fat >/dev/null && command -v mcopy >/dev/null || skip "no mkfs.fat / mtools (the HTTP Boot image)"
    cp "$OVMF_VARS" "$work/vars.fd"
    # No disk: only the firmware's two flash banks, the NIC, and the debug-exit port.
    X86_QEMU=(-M q35 -cpu "${QEMU_X86_64_CPU:-max}" -m 256M -display none -no-reboot -serial stdio
        -device isa-debug-exit,iobase=0xf4,iosize=0x04
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE"
        -drive "if=pflash,format=raw,unit=1,file=$work/vars.fd")
}

riscv_setup() {
    # The gate builds U-Boot once, before its rows, and names it here; by hand
    # it is built on demand.
    if [ -z "${U_BOOT_BIN:-}" ]; then
        U_BOOT_BIN="$(bash "$nb/uboot_build.sh" 2>"$work/uboot.err")" || skip "U-Boot did not build: $(sed -n '$p' "$work/uboot.err")"
    fi
    [ -f "$U_BOOT_BIN" ] || skip "no U-Boot at $U_BOOT_BIN (tools/gate/netboot/uboot_build.sh)"
    command -v mkimage >/dev/null || skip "no mkimage (U-Boot tools)"
    command -v dtc >/dev/null || skip "no dtc"
    # shellcheck source=tools/gate/netboot/riscv64_machine.sh
    . "$nb/riscv64_machine.sh"
}

X86_BANNER='AzOS Rust kernel booted! \(x86_64\)'
X86_STOP='AzOS Rust kernel booted|PANIC|Press a key|System halted|failed to load Boot000[0-9] "UEFI HTTPv4'

case "$case_" in
  x86-pxe|x86-pxe-nofile|x86-pxe-badkernel|x86-pxe-badconfig)
    x86_setup
    tamper=""; canary=no; file=BOOTX64.EFI
    case "$case_" in
        x86-pxe-nofile) canary=yes; file=NOSUCH.EFI ;;
        x86-pxe-badkernel) canary=yes; tamper="--tamper kernel" ;;
        x86-pxe-badconfig) canary=yes; tamper="--tamper config" ;;
    esac
    # shellcheck disable=SC2086
    bash "$nb/stage_x86.sh" "$kernel" "$work/root" $tamper >/dev/null || fail "stage_x86.sh failed"
    stop="$X86_STOP"
    # The missing file is the firmware's TFTP error at once; waiting for it to
    # give up on every boot option takes minutes.
    [ "$case_" = x86-pxe-nofile ] && stop='PXE-E[0-9]+|AzOS Rust kernel booted'
    run_qemu qemu-system-x86_64 "$stop" "${X86_QEMU[@]}" \
        -netdev "user,id=n0,tftp=$work/root,bootfile=$file" -device virtio-net-pci,netdev=n0
    # The firmware's PXE client is the one that fetched Limine; Limine fetched
    # the rest from the same server (no disk exists to read it from).
    if [ "$canary" = no ]; then
        want 'Start PXE over IPv4' "UEFI PXE never started"
        want 'NBP file downloaded successfully' "the firmware did not download the boot program"
        want 'limine: Loading executable `boot\(\):/boot/kernel.elf`' "Limine did not load the kernel"
        want '\[LIMINE\] image linked at' "the kernel did not start under Limine"
    fi
    case "$case_" in
        x86-pxe) verdict no "$X86_BANNER" "" "" ;;
        x86-pxe-nofile) verdict yes "$X86_BANNER" 'PXE-E23|PXE-E3[0-9]|NBP filesize is 0' "the firmware's PXE error for the missing file" ;;
        x86-pxe-badkernel) verdict yes "$X86_BANNER" 'Blake2b hash for URI .boot\(\):/boot/kernel.elf. does not match' "Limine's BLAKE2B refusal of the kernel" ;;
        x86-pxe-badconfig) verdict yes "$X86_BANNER" 'CHECKSUM MISMATCH FOR CONFIG FILE' "Limine's refusal of the configuration" ;;
    esac
    ;;

  x86-http|x86-http-nofile|x86-http-badkernel)
    x86_setup
    tamper=""; canary=no; file=azos-esp.img
    case "$case_" in
        x86-http-nofile) canary=yes; file=nosuch.img ;;
        x86-http-badkernel) canary=yes; tamper="--tamper kernel" ;;
    esac
    mkdir -p "$work/www"
    # shellcheck disable=SC2086
    bash "$nb/stage_x86.sh" "$kernel" "$work/root" $tamper --image "$work/www/azos-esp.img" >/dev/null || fail "stage_x86.sh failed"
    python3 "$nb/http_serve.py" "$work/www" --port-file "$work/port" --log "$work/http.log" &
    pids+=("$!")
    for _ in $(seq 1 50); do [ -s "$work/port" ] && break; sleep 0.1; done
    [ -s "$work/port" ] || fail "the HTTP server did not start"
    port="$(cat "$work/port")"
    # No tftp= : the only way to the image is the URL.
    run_qemu qemu-system-x86_64 "$X86_STOP" "${X86_QEMU[@]}" \
        -netdev "user,id=n0,bootfile=http://10.0.2.2:$port/$file" -device virtio-net-pci,netdev=n0
    cp "$work/http.log" "$logdir/$case_.http.log"
    if [ "$canary" = no ]; then
        want 'Start HTTP Boot over IPv4' "UEFI HTTP Boot never started"
        want "URI: http://10.0.2.2:$port/$file" "the firmware did not take the URL"
        grep -qE "^GET /$file 200" "$work/http.log" || fail "the HTTP server never served $file (log: $(tr '\n' ';' <"$work/http.log"))"
        want 'limine: Loading executable `boot\(\):/boot/kernel.elf`' "Limine did not load the kernel"
        want '\[LIMINE\] image linked at' "the kernel did not start under Limine"
    fi
    case "$case_" in
        x86-http) rm -f "${logdir:?}/${case_:?}.http.log"; verdict no "$X86_BANNER" "" "" ;;
        x86-http-nofile)
            grep -qE "^(HEAD|GET) /$file 404" "$work/http.log" || fail "the server did not answer 404 for $file"
            rm -f "${logdir:?}/${case_:?}.http.log"
            verdict yes "$X86_BANNER" 'Start HTTP Boot over IPv4' "the firmware's HTTP attempt" ;;
        x86-http-badkernel)
            rm -f "${logdir:?}/${case_:?}.http.log"
            verdict yes "$X86_BANNER" 'Blake2b hash for URI .boot\(\):/boot/kernel.elf. does not match' "Limine's BLAKE2B refusal of the kernel" ;;
    esac
    ;;

  riscv64-tftp|riscv64-tftp-nofile|riscv64-tftp-badkernel|riscv64-tftp-badkey)
    riscv_setup
    tamper=""; canary=no; file=azos.itb
    case "$case_" in
        riscv64-tftp-nofile) canary=yes; file=nosuch.itb ;;
        riscv64-tftp-badkernel) canary=yes; tamper="--tamper kernel" ;;
        riscv64-tftp-badkey) canary=yes; tamper="--tamper key" ;;
    esac
    # shellcheck disable=SC2086
    bash "$nb/stage_riscv64.sh" "$kernel" "$work/st" $tamper >/dev/null || fail "stage_riscv64.sh failed"
    RV_BANNER='AzOS Rust kernel booted'
    RV_STOP="$RV_BANNER|\[netboot\] FAILED|PANIC|panic"
    # No disk: the script U-Boot runs is put in RAM where its boot.scr is read
    # to, the device tree carries the key.
    run_qemu qemu-system-riscv64 "$RV_STOP" -machine virt "${RV_COMMON[@]}" \
        -kernel "$U_BOOT_BIN" -dtb "$work/st/virt.dtb" \
        -device "loader,file=$work/st/boot.scr,addr=$RV_SCRIPT" \
        -netdev "user,id=n0,tftp=$work/st/tftp,bootfile=$file" -device virtio-net-pci,netdev=n0
    if [ "$canary" = no ]; then
        want 'TFTP from server 10\.0\.2\.2' "U-Boot did not use TFTP"
        want "Filename '$file'" "U-Boot did not ask for $file"
        want '\[netboot\] fetched '"$file" "tftpboot did not finish"
        want 'Verifying Hash Integrity \.\.\. sha256,rsa2048:azos-netboot\+ OK' "the configuration's signature was not verified"
        want 'sha256\+ OK' "the kernel's hash was not verified"
    fi
    case "$case_" in
        riscv64-tftp) verdict no "$RV_BANNER" "" "" ;;
        riscv64-tftp-nofile) verdict yes "$RV_BANNER" '\[netboot\] FAILED: tftpboot' "U-Boot's tftpboot failure" ;;
        riscv64-tftp-badkernel) verdict yes "$RV_BANNER" 'Bad hash value for .hash-1. hash node in .kernel-1. image node' "U-Boot's refusal of the changed kernel (the configuration's signature still verifies: it signs the hash, not the data)" ;;
        riscv64-tftp-badkey) verdict yes "$RV_BANNER" 'Failed to verify required signature .key-azos-netboot.' "U-Boot's refusal of the foreign signature" ;;
    esac
    ;;

  *) echo "row.sh: unknown case $case_" >&2; exit 2 ;;
esac
