#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# AzOS vs Linux on the same QEMU with the same .ko (RFC-0053 L1; owner
# rule, wave 13: be better than Linux, and say where the cost goes).
#
#   tools/lx_kbuild/compare.sh            # `make lx-compare`
#
# Both sides run alone (-smp 1) under `-icount shift=0,sleep=off`, so every
# number is an instruction count, converted from counter ticks with a
# calibration loop of exactly 8,000,000 instructions each side runs:
#   AzOS  a `bench-minimal` kernel with `lx-server`, LXSRV.ELF autorun
#           (every other boot task parked): loads LXBASE.KO and XZ_DEC.KO
#           (parse+admit, SYS_MODULE_VERIFY, mmap, relocate, SYS_MODULE_MAP_X
#           + init) and times xz_dec over XZTEST.XZ;
#   Linux   the pinned tree, same .config (`run.sh linux`): /init times
#           init_module of the same xz_dec.ko bytes, lxbench.ko times the
#           same decode in kernel.
# Rebuilds the riscv64/aarch64 kernels in target/ with bench-minimal: run a
# normal build afterwards before booting anything else. Exit 3 = SKIP.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"; cd "$root"
out="$root/build/lx/compare"; mkdir -p "$out"
export TOPOLOGY_PUBKEY_PATH="${TOPOLOGY_PUBKEY_PATH:-$root/tools/keys/test_pub.bin}"
bash "$here/run.sh" check || exit $?
[ -f build/lx/kbuild/SHA256SUMS ] || bash "$here/run.sh" build build/lx/kbuild
bash "$here/run.sh" linux build/lx/kbuild-linux >/dev/null
make -s lx-modules build/image_hashes.rs build/image_hashes_aarch64.rs >/dev/null
KCONFIG_CONFIG="$root/target/primary/qemu.config" cargo build -q --release --features qemu,lx-server,bench-minimal
env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$root/target/primary-aarch64/qemu-aarch64.config" \
    cargo build -q --release --target aarch64-unknown-none-softfloat -p azos_kernel \
    --features qemu,lx-server,bench-minimal --config 'build.rustflags=["-C","link-arg=-Tkernel/linker-aarch64.ld"]'
make -s build/disk-lxbench.img build/disk-aarch64-lxbench.img >/dev/null
oc="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
cp target/riscv64imac-unknown-none-elf/release/kernel "$out/kos-rv.kernel"
"$oc" -O binary target/aarch64-unknown-none-softfloat/release/kernel "$out/kos-arm.img"
cp build/disk-lxbench.img "$out/kos-rv.disk"; cp build/disk-aarch64-lxbench.img "$out/kos-arm.disk"
for i in riscv64 aarch64; do
    cp "build/lx/kbuild-linux/$i/Image" "$out/lin-$i.Image"; cp "build/lx/kbuild-linux/$i/initramfs.cpio" "$out/lin-$i.cpio"
done
ic="-icount shift=0,sleep=off"
boot() { # <log> <done-regex> <qemu...>: one QEMU at a time, never more than 4 host-wide
    local log="$1" re="$2"; shift 2; rm -f "$log"
    while [ $(( $(pgrep -x qemu-system-riscv64 | wc -l) + $(pgrep -x qemu-system-aarch64 | wc -l) )) -ge 4 ]; do sleep 2; done
    "$@" > "$log" 2>&1 &
    local pid=$! end=$(( $(date +%s) + 240 ))
    while [ "$(date +%s)" -lt "$end" ] && ! grep -aqE "$re" "$log"; do sleep 2; done
    sleep 1; kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
}
boot "$out/kos-rv.log" '\[LXSRV\] (idle|.*FAIL)|panic' qemu-system-riscv64 -machine virt -nographic -bios default -smp 1 $ic \
    -kernel "$out/kos-rv.kernel" -global virtio-mmio.force-legacy=false \
    -drive file="$out/kos-rv.disk",if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0
boot "$out/lin-rv.log" 'lxbench: done|Kernel panic' qemu-system-riscv64 -machine virt -nographic -bios default -smp 1 -m 256M $ic \
    -kernel "$out/lin-riscv64.Image" -initrd "$out/lin-riscv64.cpio" -append "console=ttyS0 rdinit=/init"
boot "$out/kos-arm.log" '\[LXSRV\] (idle|.*FAIL)|panic' qemu-system-aarch64 -M virt,gic-version=3 -cpu max,pauth=on -smp 1 $ic \
    -nographic -kernel "$out/kos-arm.img" -global virtio-mmio.force-legacy=false \
    -drive file="$out/kos-arm.disk",if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0
boot "$out/lin-arm.log" 'lxbench: done|Kernel panic' qemu-system-aarch64 -M virt,gic-version=3 -cpu max,pauth=on -smp 1 -m 256M $ic \
    -nographic -kernel "$out/lin-aarch64.Image" -initrd "$out/lin-aarch64.cpio" -append "console=ttyAMA0 rdinit=/init"
python3 - "$out" <<'PY'
import re, sys
out = sys.argv[1]
def grab(path, pat):
    t = open(path, "rb").read().decode("utf-8", "replace").replace("\r", "")
    m = re.search(pat, t)
    if not m:
        sys.exit(f"lx-compare: {path}: no match for {pat!r}")
    return [int(x) for x in m.groups()]
print(f"{'instructions (-icount)':34s}{'riscv64':>22s}{'aarch64':>22s}")
rows = {}
for isa in ("rv", "arm"):
    k, l = f"{out}/kos-{isa}.log", f"{out}/lin-{isa}.log"
    kc = 8_000_000 / grab(k, r"8M-instruction loop (\d+) ticks")[0]
    lc = 8_000_000 / grab(l, r"8M-instruction loop ticks (\d+)")[0]
    pa, ve, mm, ft, rl, mx, tot = grab(k, r"timing XZ_DEC\.KO: parse\+admit (\d+), verify (\d+), mmap (\d+), first touch (\d+), place\+relocate (\d+), map_x\+init (\d+), total (\d+)")
    base = grab(k, r"timing LXBASE\.KO: .*total (\d+) ticks")[0]
    cold, warm, kcrc, sysk = grab(k, r"xz decode \(init\+run\+end\) cold (\d+), warm (\d+) ticks; crc32_le 48K (\d+) ticks; uptime syscall x1000 (\d+)")
    lcrc = grab(l, r"crc32_le 48K ticks (\d+)")[0]
    lins = grab(l, r"init_module xz_dec\.ko bytes \d+ rc 0 ticks (\d+)")[0]
    ld = grab(l, r"xz decode 1: \d+ -> 49152 bytes, ret 1, ticks (\d+)")[0]
    lsys = grab(l, r"getppid x1000 ticks (\d+)")[0]
    K = lambda v: round(v * kc); L = lambda v: round(v * lc)
    rows[isa] = [
        ("load xz_dec.ko: AzOS total", K(tot)), ("  parse+admit", K(pa)), ("  verify (kernel SHA-256)", K(ve)),
        ("  mmap", K(mm)), ("  place+relocate", K(rl)), ("  map_x+init", K(mx)),
        ("  AzOS without verify", K(tot - ve)), ("load xz_dec.ko: Linux init_module", L(lins)),
        ("load lxbase.ko (AzOS only)", K(base)),
        ("decode XZTEST.XZ: AzOS (warm)", K(warm)), ("decode XZTEST.XZ: Linux in kernel", L(ld)),
        ("  of which crc32_le 48K: AzOS", K(kcrc)), ("  of which crc32_le 48K: Linux", L(lcrc)),
        ("null syscall: AzOS uptime", K(sysk) // 1000), ("null syscall: Linux getppid", L(lsys) // 1000),
    ]
for isa in ("rv", "arm"):
    t = open(f"{out}/kos-{isa}.log", "rb").read().decode("utf-8", "replace").replace("\r", "")
    picks = [m.group(0) for m in re.finditer(r"\[VDSO\] hwcap=\S+[^\n]*|\[CRYPTO\] sha256 blocks: \S+|lxbase crc32_le: [^\n]*", t)]
    print(f"AzOS {isa}: " + "; ".join(picks))
for i, (name, _) in enumerate(rows["rv"]):
    print(f"{name:34s}{rows['rv'][i][1]:>22,}{rows['arm'][i][1]:>22,}")
PY
