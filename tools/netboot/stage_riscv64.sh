#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Stage the riscv64 netboot: the signed FIT image the TFTP server serves, the
# boot script the machine runs, and the device tree whose key verifies the
# image: U-Boot runs boot.scr, and `dhcp` + `tftpboot` bring the kernel, which
# is a signed FIT.
#
#   tools/netboot/stage_riscv64.sh <kernel.bin> <outdir> [--tamper kernel|key]
#
#   <outdir>/tftp/azos.itb   FIT: the flat kernel, a sha256 hash of it, and a
#                            sha256,rsa2048 signature of the configuration
#   <outdir>/boot.scr        the script (mkimage -T script): the rows load it
#                            with QEMU's `-device loader` at U-Boot's
#                            ${scriptaddr}, where its boot.scr is read from
#   <outdir>/virt.dtb        QEMU's virt device tree with the public key under
#                            /signature (`required = "conf"`): U-Boot's control
#                            device tree, here the one OpenSBI hands it
#
# Verification is U-Boot's (CONFIG_FIT_SIGNATURE): `bootm` refuses the image
# unless the configuration's signature verifies against a `required` key of the
# control device tree and the kernel's hash matches. Under QEMU the device tree
# is handed in with -dtb.
#
# The key is a throwaway RSA-2048 pair made per call into <outdir>/keys: a test
# key, never a release one (a release image's key is the owner's, offline).
# --tamper kernel changes one byte of the kernel AFTER it was signed; --tamper
# key signs with a key the device tree does not hold: the two canaries.
#
# Needs: mkimage (U-Boot tools), dtc, openssl, and the QEMU the rows run, which
# dumps its device tree (a dump, no guest boots).
set -euo pipefail

kernel="${1:?usage: stage_riscv64.sh <kernel.bin> <outdir> [--tamper kernel|key]}"
out="${2:?usage: stage_riscv64.sh <kernel.bin> <outdir> [--tamper kernel|key]}"
shift 2
tamper=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tamper) tamper="${2:?}"; shift 2 ;;
        *) echo "stage_riscv64: unknown argument $1" >&2; exit 2 ;;
    esac
done
case "$tamper" in ""|kernel|key) ;; *) echo "stage_riscv64: --tamper kernel|key" >&2; exit 2 ;; esac
[ -f "$kernel" ] || { echo "stage_riscv64: no kernel at $kernel" >&2; exit 1; }
for t in mkimage dtc openssl qemu-system-riscv64; do
    command -v "$t" >/dev/null || { echo "stage_riscv64: $t not found" >&2; exit 1; }
done

# The machine the rows boot; the dumped device tree must describe exactly it.
# shellcheck source=tools/netboot/riscv64_machine.sh
. "$(dirname "$0")/riscv64_machine.sh"

rm -rf "$out"; mkdir -p "$out/tftp" "$out/keys" "$out/work"
out="$(cd "$out" && pwd)"   # absolute: mkimage runs below, in the work directory
w="$out/work"
cp "$kernel" "$w/kernel.bin"

# Keys: the one the device tree trusts, and (for --tamper key) a stranger.
openssl genrsa -out "$out/keys/azos-netboot.key" 2048 2>/dev/null
# mkimage takes the public half for the device tree from a certificate.
openssl req -batch -new -x509 -days 2 -subj /CN=azos-netboot -key "$out/keys/azos-netboot.key" -out "$out/keys/azos-netboot.crt"
signkey="$out/keys"
if [ "$tamper" = key ]; then
    mkdir -p "$out/keys-other"
    openssl genrsa -out "$out/keys-other/azos-netboot.key" 2048 2>/dev/null
    signkey="$out/keys-other"
fi

cat >"$w/azos.its" <<ITS
/dts-v1/;
/ {
    description = "AzOS netboot image";
    #address-cells = <2>;
    images {
        kernel-1 {
            description = "AzOS kernel (flat binary, linked at 0x80200000)";
            data = /incbin/("kernel.bin");
            type = "kernel";
            arch = "riscv";
            os = "linux";
            compression = "none";
            load = <0x0 $RV_LOAD>;
            entry = <0x0 $RV_LOAD>;
            hash-1 { algo = "sha256"; };
        };
    };
    configurations {
        default = "conf-1";
        conf-1 {
            description = "AzOS";
            kernel = "kernel-1";
            signature-1 {
                algo = "sha256,rsa2048";
                key-name-hint = "azos-netboot";
                sign-images = "kernel";
            };
        };
    };
};
ITS

# QEMU's own device tree for the machine, with the public key added: signing
# with `-K <dtb> -r` writes the key under /signature as `required = "conf"`.
rv_dumpdtb "$w/virt.dtb"
if [ "$tamper" = key ]; then
    # The device tree takes the trusted key; the image the server holds is
    # signed by a stranger.
    (cd "$w" && mkimage -f azos.its -k "$out/keys" -K virt.dtb -r trusted.itb >/dev/null \
        && mkimage -f azos.its -k "$out/keys-other" azos.itb >/dev/null)
else
    (cd "$w" && mkimage -f azos.its -k "$out/keys" -K virt.dtb -r azos.itb >/dev/null)
fi
if [ "$tamper" = kernel ]; then
    # One byte of the kernel's data inside the FIT, found by a run of the
    # kernel's own bytes, flipped after the signature was made.
    python3 - "$w/azos.itb" "$w/kernel.bin" <<'PY'
import sys
itb = bytearray(open(sys.argv[1], "rb").read())
k = open(sys.argv[2], "rb").read()
needle = k[4096:4096 + 64]
at = itb.find(needle)
if at < 0 or itb.find(needle, at + 1) >= 0:
    sys.exit("stage_riscv64: cannot place the kernel's bytes in the FIT exactly once")
itb[at + 8] ^= 0xFF
open(sys.argv[1], "wb").write(itb)
PY
fi
cp "$w/azos.itb" "$out/tftp/azos.itb"
cp "$w/virt.dtb" "$out/virt.dtb"

# The script. DHCP leases an address and names the file (BOOTP `file`, what
# QEMU's `bootfile=` sets); tftpboot fetches it;
# bootm verifies it and starts it. A failure powers the machine off with a
# line that says which step: the rows read that line.
cat >"$w/boot.cmd" <<'SCR'
echo [netboot] riscv64: dhcp + tftpboot
setenv autoload no
if dhcp; then
else
    echo [netboot] FAILED: no DHCP lease
    poweroff
fi
if tftpboot ${kernel_addr_r} ${bootfile}; then
    echo [netboot] fetched ${bootfile}: ${filesize} bytes
else
    echo [netboot] FAILED: tftpboot ${bootfile}
    poweroff
fi
bootm ${kernel_addr_r} - ${fdt_addr}
echo [netboot] FAILED: bootm refused the image
poweroff
SCR
mkimage -A riscv -T script -C none -n "azos netboot" -d "$w/boot.cmd" "$out/boot.scr" >/dev/null
rm -rf "$w" "$out/keys" "$out/keys-other"
echo "$out"
