#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Build relibc (Redox's libc, MIT) for the native ABI, and C programs against it.
#
#   tools/relibc_build.sh prepare              the patched tree (from the pinned checkout)
#   tools/relibc_build.sh headers              C headers -> build/relibc/include
#   tools/relibc_build.sh libs  <isa>          libc.a -> build/relibc/<isa>/lib
#   tools/relibc_build.sh cc    <isa> OUT SRC..   compile and link C sources into the ELF OUT
#   tools/relibc_build.sh diff                 print the patch the work tree's edits amount to
#
# <isa> is riscv64, aarch64 or x86_64. The source is the checkout of the
# gitlink third_party/relibc (tools/third_party_fetch.sh relibc); it is never
# written: it is copied to a work tree, patched with userspace/lib/relibc-azos/patches
# and overlaid with userspace/lib/relibc-azos/overlay (our `azos` platform
# module). The Rust target is the ISA's native spec (sdk/targets), and a C
# program is linked with that spec's layout (tools/user_link_args.py --driver:
# a static executable at the same image base and entry): no linker script. Nothing in the checkout is run
# except through cargo, as relibc's own build would.
#
# Environment:
#   RELIBC_SRC    the checkout                    (default <repo>/third_party/relibc)
#   RELIBC_WORK   the patched work tree           (default <AZOS_OUT>/build/relibc-work: a tree of
#                 its own per output directory, since the patch bakes in this repository's path)
#   RELIBC_OUT    outputs                         (default <repo>/build/relibc)
#   RELIBC_ZIG    zig, the C compiler and linker  (default zig)
#   RELIBC_CBINDGEN  cbindgen                     (default ~/azos-tools/cbindgen/bin/cbindgen,
#                 else cbindgen on PATH; `cargo install cbindgen --version =0.29.2 --locked`)
#   RELIBC_RUSTFLAGS_TOML  the Kconfig codegen flags for <isa> as a TOML array body
#                 (kconfig_to_cargo.py --user-rustflags --toml), set by the Makefile
#   AZOS_PAGE_SIZE   aarch64 granule (4096, 16384, 65536); AZOS_USER_STACK_BYTES the
#                 kernel's user stack (Kconfig USER_STACK_SIZE_KB), for x86_64's second thread
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
AZOS_OUT="${AZOS_OUT:-$(python3 "$root/tools/out_dir.py")}"
src="${RELIBC_SRC:-$root/third_party/relibc}"
work="${RELIBC_WORK:-$AZOS_OUT/build/relibc-work}"
out="${RELIBC_OUT:-$AZOS_OUT/build/relibc}"
zig="${RELIBC_ZIG:-zig}"
lib="$root/userspace/lib/relibc-azos"
cbindgen="${RELIBC_CBINDGEN:-$HOME/azos-tools/cbindgen/bin/cbindgen}"
[ -x "$cbindgen" ] || cbindgen="$(command -v cbindgen || true)"

# The one compiler the repository pins; relibc's own rust-toolchain.toml is newer.
export RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
host="$(rustc -vV | sed -n 's/^host: //p')"
llvm="$(rustc --print sysroot)/lib/rustlib/$host/bin"

die() { echo "relibc_build: $*" >&2; exit 1; }
isa_ok() {
    case "$1" in riscv64|aarch64|x86_64) ;; *) die "ISA must be riscv64, aarch64 or x86_64, not '$1'" ;; esac
}

# zig's freestanding target and CPU for an ISA, the C side of the Rust targets in
# sdk/targets (same baseline: rv64imac, Armv8 with NEON and strict alignment,
# x86-64 with SSE2).
zig_target() {
    case "$1" in
        riscv64) echo "riscv64-freestanding -mcpu=generic_rv64+m+a+c" ;;
        aarch64) echo "aarch64-freestanding -mstrict-align" ;;
        x86_64)  echo "x86_64-freestanding" ;;
    esac
}

# The native target spec of an ISA (sdk/targets/<name>.json).
spec_name() {
    case "$1" in
        riscv64) echo riscv64imac-unknown-azos ;;
        aarch64) echo aarch64-unknown-azos ;;
        x86_64)  echo x86_64-unknown-azos ;;
    esac
}

prepare() {
    [ -e "$src/.git" ] || die "no checkout at $src: run tools/third_party_fetch.sh relibc"
    local commit; commit="$(git -C "$root" ls-files -s third_party/relibc | awk '$1 == "160000" { print $2 }')"
    [ -n "$commit" ] || die "third_party/relibc is not a gitlink"
    [ "$(git -C "$src" rev-parse HEAD)" = "$commit" ] || die "$src is not at the pin ($commit): run tools/third_party_fetch.sh relibc"
    # What the work tree is made of: the pin, the patches and the overlay.
    local key
    key="$( (echo "$commit"; echo "$root"; cd "$lib" && find patches overlay -type f | LC_ALL=C sort | xargs shasum -a 256) | shasum -a 256 | cut -d' ' -f1)"
    if [ -f "$work/.azos-prepared" ] && [ "$(cat "$work/.azos-prepared")" = "$key" ]; then
        return
    fi
    rm -rf "$work"
    mkdir -p "$work"
    rsync -a --exclude .git "$src/" "$work/"
    git -C "$work" init -q
    git -C "$work" -c user.name=relibc -c user.email=relibc@invalid add -A
    git -C "$work" -c user.name=relibc -c user.email=relibc@invalid commit -q -m "relibc $commit"
    local p
    for p in "$lib"/patches/*.patch; do
        git -C "$work" apply --whitespace=nowarn "$p"
    done
    sed -i.bak "s|@AZOS_ROOT@|$root|g" "$work/Cargo.toml" && rm -f "$work/Cargo.toml.bak"
    cp -R "$lib/overlay/src/." "$work/src/"
    echo "$key" > "$work/.azos-prepared"
}

# The patch the edits to upstream files amount to (new files are overlay, not patch).
diff_patch() {
    [ -d "$work/.git" ] || die "no work tree: run prepare"
    git -C "$work" diff | sed "s|$root|@AZOS_ROOT@|g"
}

headers() {
    prepare
    [ -n "$cbindgen" ] || die "no cbindgen: cargo install cbindgen --version =0.29.2 --locked --root ~/azos-tools/cbindgen"
    local inc="$out/include"
    rm -rf "$inc"; mkdir -p "$inc"
    cp -R "$work/include/." "$inc/"
    local d name o
    for d in "$work"/src/header/*/; do
        name="$(basename "$d")"
        case "$name" in _*) continue ;; esac
        [ -f "$d/cbindgen.toml" ] || continue
        o="$inc/$(echo "$name" | sed 's/_/\//g').h"
        mkdir -p "$(dirname "$o")"
        cat "$d/cbindgen.toml" "$work/cbindgen.globdefs.toml" | "$cbindgen" "$d/mod.rs" --config=/dev/stdin --output "$o" 2>/dev/null \
            || die "cbindgen failed on $name"
    done
    echo "[RELIBC] headers: $inc ($(find "$inc" -name '*.h' | wc -l | tr -d ' ') files)"
}

libs() {
    local isa="$1"; isa_ok "$isa"
    prepare
    local t tdir="$work/target-$isa" dst="$out/$isa/lib"
    t="$(spec_name "$isa")"
    # `azos_std`: the entry is relibc's own `_azos_entry` (overlay start.rs),
    # not libsys's, as in a `std` program.
    local flags=(--config "target.$t.rustflags=[\"--cfg=azos_std\"${RELIBC_RUSTFLAGS_TOML:+,$RELIBC_RUSTFLAGS_TOML}]")
    mkdir -p "$dst"
    (
        cd "$work"
        export CARGO_TARGET_DIR="$tdir"
        export AZOS_ISA="$isa"
        export "CC_${t//-/_}=$root/tools/relibc_cc.sh"
        export "AR_${t//-/_}=$llvm/llvm-ar"
        export RELIBC_ZIG="$zig"
        [ "$isa" != aarch64 ] || export AZOS_PAGE_SIZE="${AZOS_PAGE_SIZE:-4096}"
        cargo rustc --release -Zjson-target-spec -Zbuild-std=core,alloc,compiler_builtins \
            --target "$root/sdk/targets/$t.json" --features math_libm --no-default-features \
            ${flags[@]+"${flags[@]}"} -- --emit "link=$dst/librelibc.a"
    )
    # relibc's own post-processing: the Rust runtime's global symbols become
    # private (`__relibc_*`) so a C program's compiler runtime wins, and the
    # libm names rustc's core exports are dropped (rust-lang/rust#142119).
    export NM="$llvm/llvm-nm" OBJCOPY="$llvm/llvm-objcopy"
    (cd "$work" && ./renamesyms.sh "$dst/librelibc.a" "$tdir/$t/release/deps/" && ./stripcore.sh "$dst/librelibc.a")
    mv "$dst/librelibc.a" "$dst/libc.a"
    # The libraries a C link line names; everything lives in libc.a.
    local l
    for l in m dl pthread rt; do
        rm -f "$dst/lib$l.a"
        "$llvm/llvm-ar" rcs "$dst/lib$l.a"
    done
    echo "[RELIBC] $isa: $dst/libc.a ($(wc -c < "$dst/libc.a" | tr -d ' ') bytes)"
}

cc_link() {
    local isa="$1" elf="$2"; shift 2
    isa_ok "$isa"
    [ -f "$out/$isa/lib/libc.a" ] || die "no libc.a for $isa: run libs $isa"
    [ -d "$out/include" ] || die "no headers: run headers"
    local page=4096
    [ "$isa" != aarch64 ] || page="${AZOS_PAGE_SIZE:-4096}"
    # shellcheck disable=SC2046
    "$zig" cc -target $(zig_target "$isa") -std=c11 -O2 -Wall -Wextra -Werror \
        -D__azos__=1 -nostdinc -isystem "$out/include" -ffreestanding -fno-stack-protector -fno-pic -fno-pie -fno-builtin \
        -nostdlib -static \
        $(python3 "$root/tools/user_link_args.py" --driver "$isa") -Wl,-z,max-page-size="$page" -Wl,-s \
        -o "$elf" "$@" "$out/$isa/lib/libc.a"
}

cmd="${1:-}"; [ $# -eq 0 ] || shift
case "$cmd" in
    prepare) prepare ;;
    headers) headers ;;
    libs)    [ $# -eq 1 ] || die "usage: libs <isa>"; libs "$1" ;;
    cc)      [ $# -ge 3 ] || die "usage: cc <isa> OUT SRC.."; cc_link "$@" ;;
    diff)    diff_patch ;;
    *) die "usage: relibc_build.sh prepare|headers|libs <isa>|cc <isa> OUT SRC..|diff" ;;
esac
