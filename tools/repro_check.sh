#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# tools/repro_check.sh — RFC-0012: local, hand-run reproducible-build check.
#
# Builds the kernel release image and every ring-3 userspace ELF TWICE,
# each time from a clean cargo target directory under a fresh temp root,
# then compares sha256 of every artefact pair. Exits 1 if any artefact
# differs between the two builds.
#
# Run A builds from this checkout. Run B builds from a COPY of it under its
# own temp root, so the two runs differ in the source directory as well as in
# the target directory. A result that depends on where the tree is checked out
# is a DIFFER here. (Until 2026-09-14 both runs built from this checkout, and
# the script could not see that class: userspace ELF bytes depended on the
# checkout path, and gate 40 refused a brain_client rebuilt in its snapshot.)
#
# This is a hand-run tool, not a CI job — the project runs no CI
# automation by owner decision; RFC-0012 records the scope. Two clean
# CARGO_TARGET_DIRs are used (instead of the shared target/ tree) so
# this can run alongside other work on the main tree without racing it
# or reusing a warm/dirty cache that would hide non-determinism.
#
# Determinism knobs:
#   - SOURCE_DATE_EPOCH: fixed (overridable), so any embedded build time
#     is stable across the two runs.
#   - --remap-path-prefix for each run's source root and $HOME/.cargo, so
#     absolute source paths baked into debug info (profile.release has
#     debug=true) don't depend on where each copy or cargo home sit.
#   - --remap-path-prefix for EACH run's own CARGO_TARGET_DIR, mapped to
#     the SAME placeholder in both runs. This matters here specifically:
#     crates/core/limits/src/lib.rs, crates/core/ota/src/secure_boot.rs and
#     crates/drivers/sys/src/wcet.rs each do
#     `include!(concat!(env!("OUT_DIR"), "/...")))`, and OUT_DIR lives
#     under CARGO_TARGET_DIR — which is deliberately DIFFERENT between
#     run A and run B. Without this remap, the two ELFs would always
#     differ in their debug info for those three files alone, regardless
#     of any real non-determinism.
#   - Userspace crates are built as the Makefile's USPACE_BUILD builds them:
#     under that source root's userspace/rustc_stable_metadata.py as
#     RUSTC_WRAPPER, with the wrapper's digest as a `--cfg`. The wrapper
#     replaces the `-C metadata` cargo derives from the absolute path of
#     crates/core/libsys; without it the two runs' userspace ELFs differ.
#
# The existing target rustflags in .cargo/config.toml (and in each
# userspace crate's own .cargo/config.toml) are read and preserved: this
# script does NOT set a plain RUSTFLAGS, because RUSTFLAGS/
# CARGO_ENCODED_RUSTFLAGS take precedence over — rather than merge with —
# a config file's target.<triple>.rustflags. Instead it reads the existing
# array and re-emits it, with the remap flags appended, as
# CARGO_ENCODED_RUSTFLAGS.
#
# Usage:
#   tools/repro_check.sh [--dry-run] [--keep]
#
#   --dry-run   Print every command this script would run, for both
#               build A and build B, without building anything. Also
#               validates argument parsing.
#   --keep      Don't delete the temp build roots on exit (for
#               inspecting a DIFFER by hand). Default: cleaned up.
#
# Target: riscv64imac-unknown-none-elf.
#
# A real run copies the source tree once and does two full release builds of
# the kernel plus eleven userspace ELFs (nightly, build-std). Do not start it
# while a timing measurement or a gate run is in progress: it competes for CPU
# and disk. The kernel `include!`s build/image_hashes.rs: run
# `make build/image_hashes.rs` first.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="${CARGO:-cargo}"
RISCV_AS="${RISCV_AS:-riscv64-unknown-elf-as}"
RISCV_LD="${RISCV_LD:-riscv64-unknown-elf-ld}"
TARGET_TRIPLE="riscv64imac-unknown-none-elf"

# Fixed, not derived from the clock or from git — the point is that the
# SAME value is used for both runs. Override with an env var if a
# specific release date needs to be reproduced.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}" # 2025-01-01T00:00:00Z

DRY_RUN=0
KEEP=0

usage() {
    echo "Usage: $0 [--dry-run] [--keep]" >&2
}

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --keep) KEEP=1 ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "repro_check.sh: unknown argument: $arg" >&2
            usage
            exit 2
            ;;
    esac
done

log() { echo "[repro_check] $*"; }

if [[ "$DRY_RUN" -eq 0 ]] && [[ ! -f "$REPO_ROOT/build/image_hashes.rs" ]]; then
    echo "repro_check.sh: build/image_hashes.rs is missing; run make build/image_hashes.rs first" >&2
    exit 2
fi

# ---------------------------------------------------------------------
# Read a target's rustflags array out of a .cargo/config.toml, in
# repo-config order. This is a narrow, purpose-built reader (not a
# general TOML parser): it looks for
#   [target.<triple>]
#   rustflags = [ "...", "...", ... ]
# possibly spanning multiple lines, and prints one flag per line. It is
# used instead of hardcoding the flags here so this script tracks the
# config file instead of silently drifting from it.
# ---------------------------------------------------------------------
read_target_rustflags() {
    local config_toml="$1"
    local triple="$2"
    python3 - "$config_toml" "$triple" <<'PYEOF'
import re
import sys

config_path, triple = sys.argv[1], sys.argv[2]
with open(config_path, "r", encoding="utf-8") as f:
    text = f.read()

section_re = re.compile(
    r"^\[target\." + re.escape(triple) + r"\]\s*$(.*?)(?=^\[|\Z)",
    re.MULTILINE | re.DOTALL,
)
m = section_re.search(text)
if not m:
    sys.exit(f"repro_check.sh: no [target.{triple}] section in {config_path}")

section = m.group(1)
rf_re = re.compile(r"rustflags\s*=\s*\[(.*?)\]", re.DOTALL)
rf_m = rf_re.search(section)
if not rf_m:
    sys.exit(f"repro_check.sh: no rustflags array under [target.{triple}] in {config_path}")

for flag in re.findall(r'"([^"]*)"', rf_m.group(1)):
    print(flag)
PYEOF
}

# Build one CARGO_ENCODED_RUSTFLAGS value (unit-separator joined) from
# the flags passed as positional args. (Portability note: this avoids
# `local -n` namerefs and associative arrays on purpose — macOS ships
# bash 3.2 at /bin/bash, and this repo's mandated PATH resolves plain
# `bash` there, not to a Homebrew bash4+.)
encode_rustflags() {
    local joined=""
    local first=1
    for f in "$@"; do
        if [[ $first -eq 1 ]]; then
            joined="$f"
            first=0
        else
            joined="$joined"$'\x1f'"$f"
        fi
    done
    printf '%s' "$joined"
}

# The first 12 hex digits of a file's SHA-256: the Makefile's
# USPACE_METADATA_TAG for the wrapper.
short_digest() {
    python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:12])' "$1"
}

# ---------------------------------------------------------------------
# Artefact table. Each row:
#   name  kind(cargo|asm)  build_dir(relative to the source root)  config_toml(relative to build_dir)  rel_bin(under CARGO_TARGET_DIR)  extra_cargo_args  nightly(0|1)
# Matches Makefile's `userspace:` target and its $(KERNEL_ELF) build.
# ---------------------------------------------------------------------
ARTIFACTS=(
    "kernel|cargo|.|.cargo/config.toml|${TARGET_TRIPLE}/release/kernel|--features qemu|0"
    "uhello|cargo|userspace/tests/uhello|.cargo/config.toml|${TARGET_TRIPLE}/release/uhello||1"
    "reflex|cargo|userspace/services/reflex|.cargo/config.toml|${TARGET_TRIPLE}/release/reflex||1"
    "brain_client|cargo|userspace/services/brain_client|.cargo/config.toml|${TARGET_TRIPLE}/release/brain_client||1"
    "captest|cargo|userspace/tests/captest|.cargo/config.toml|${TARGET_TRIPLE}/release/captest||1"
    "latbench|cargo|userspace/bench/latbench|.cargo/config.toml|${TARGET_TRIPLE}/release/latbench||1"
    "abitest|cargo|userspace/tests/abitest|.cargo/config.toml|${TARGET_TRIPLE}/release/abitest||1"
    "ipctest|cargo|userspace/tests/ipctest|.cargo/config.toml|${TARGET_TRIPLE}/release/ipctest||1"
    "vsbench|cargo|userspace/bench/vsbench|.cargo/config.toml|${TARGET_TRIPLE}/release/vsbench|--features azos|1"
    "gpio_drv|cargo|userspace/drivers/gpio_drv|.cargo/config.toml|${TARGET_TRIPLE}/release/gpio_drv||1"
    "mlsrv|cargo|userspace/services/mlsrv|.cargo/config.toml|${TARGET_TRIPLE}/release/mlsrv||1"
    "buzz_drv|cargo|userspace/drivers/buzz_drv|.cargo/config.toml|${TARGET_TRIPLE}/release/buzz_drv||1"
    "ina_drv|cargo|userspace/drivers/ina_drv|.cargo/config.toml|${TARGET_TRIPLE}/release/ina_drv||1"
    "hello|asm|userspace/tests/hello|-|-|-|-"
    "syscall_test|asm|userspace/tests/syscall_test|-|-|-|-"
)

# ---------------------------------------------------------------------
# Build one cargo-based artefact from $src_root into $run_target_dir,
# remapping the source root, $HOME/.cargo, and this run's OWN target dir
# to shared placeholders so the two runs' outputs are comparable.
#
# Prints the argv it would run when DRY_RUN=1; otherwise runs it.
# ---------------------------------------------------------------------
build_cargo_artifact() {
    local src_root="$1" build_dir="$2" config_toml="$3" extra_args="$4" nightly="$5" run_target_dir="$6"

    # In a dry run build B's copy does not exist yet; its files are this
    # checkout's, byte for byte, so they are read from here instead.
    local read_root="$src_root"
    if [[ "$DRY_RUN" -eq 1 ]] && [[ ! -d "$src_root" ]]; then
        read_root="$REPO_ROOT"
    fi

    local -a base_flags=()
    while IFS= read -r line; do
        base_flags+=("$line")
    done < <(read_target_rustflags "$read_root/$build_dir/$config_toml" "$TARGET_TRIPLE")

    local -a flags=(
        "${base_flags[@]}"
        "--remap-path-prefix=$src_root=/azos-src"
        "--remap-path-prefix=$HOME/.cargo=/cargo-home"
        "--remap-path-prefix=$run_target_dir=/azos-build"
    )
    # Userspace ELFs are built as the Makefile's USPACE_BUILD builds them.
    local wrapper=""
    if [[ "$nightly" == "1" ]]; then
        wrapper="$src_root/userspace/rustc_stable_metadata.py"
        flags+=("--cfg=azos_stable_metadata_$(short_digest "$read_root/userspace/rustc_stable_metadata.py")")
    fi
    local encoded
    encoded="$(encode_rustflags "${flags[@]}")"

    local -a cmd=("$CARGO")
    [[ "$nightly" == "1" ]] && cmd+=("+nightly")
    cmd+=(build --release --target "$TARGET_TRIPLE")
    # shellcheck disable=SC2206 # extra_args is a small, fixed, space-safe set
    [[ -n "$extra_args" ]] && cmd+=($extra_args)

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '  (cd %q && CARGO_TARGET_DIR=%q SOURCE_DATE_EPOCH=%q RUSTC_WRAPPER=%q CARGO_ENCODED_RUSTFLAGS=<%d flags, see below> %s)\n' \
            "$src_root/$build_dir" "$run_target_dir" "$SOURCE_DATE_EPOCH" "$wrapper" "${#flags[@]}" "${cmd[*]}"
        printf '    rustflags:\n'
        for f in "${flags[@]}"; do
            printf '      %s\n' "$f"
        done
        return 0
    fi

    (
        cd "$src_root/$build_dir"
        export CARGO_TARGET_DIR="$run_target_dir"
        export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
        export CARGO_ENCODED_RUSTFLAGS="$encoded"
        if [[ -n "$wrapper" ]]; then
            export RUSTC_WRAPPER="$wrapper"
        fi
        "${cmd[@]}"
    )
}

build_asm_artifact() {
    local dir="$1" src="$2" ld_script="$3" obj_out="$4" elf_out="$5"

    local -a as_cmd=("$RISCV_AS" -march=rv64imac -mabi=lp64 -o "$obj_out" "$dir/$src")
    local -a ld_cmd=("$RISCV_LD" -T "$ld_script" -o "$elf_out" "$obj_out")

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '  %s\n' "${as_cmd[*]}"
        printf '  %s\n' "${ld_cmd[*]}"
        return 0
    fi

    mkdir -p "$(dirname "$obj_out")"
    "${as_cmd[@]}"
    "${ld_cmd[@]}"
}

# Copy the source tree to $1 for run B. Excluded: VCS and agent state, every
# cargo target/ directory, and the top-level build/ and "build 2" (in a checkout
# build/ may be a symlink to a directory shared with other checkouts). The one
# file the builds need from build/, image_hashes.rs, is copied on its own.
copy_source_tree() {
    local dst="$1"
    local -a cmd=(rsync -a
        --exclude '/.git' --exclude '/.claude' --exclude '/.codex'
        --exclude '/build' --exclude '/build 2'
        --exclude 'target/' --exclude 'target 2/'
        "$REPO_ROOT/" "$dst/")
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '  %s\n' "${cmd[*]}"
        printf '  mkdir -p %q && cp %q %q\n' "$dst/build" "$REPO_ROOT/build/image_hashes.rs" "$dst/build/image_hashes.rs"
        return 0
    fi
    mkdir -p "$dst"
    "${cmd[@]}"
    mkdir -p "$dst/build"
    cp "$REPO_ROOT/build/image_hashes.rs" "$dst/build/image_hashes.rs"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---------------------------------------------------------------------
# Set up two clean roots, and run B's own copy of the sources.
# ---------------------------------------------------------------------
# A template path, not `-t`: BSD mktemp appends its own suffix to a `-t`
# prefix, which left a literal `XXXXXX` in the directory name.
TMPROOT="$(mktemp -d "${TMPDIR:-/tmp}/azos-repro.XXXXXX")"
# Canonical form (`pwd -P`): on macOS $TMPDIR is under /var, a symlink to
# /private/var, and rustc records the resolved path. A remap keyed on the
# /var spelling then misses run B's source root, and the kernel's debug
# sections differ between the runs while every loaded section matches.
TMPROOT="$(cd "$TMPROOT" && pwd -P)"
ROOT_A="$TMPROOT/a"
ROOT_B="$TMPROOT/b"
mkdir -p "$ROOT_A" "$ROOT_B"
SRC_A="$REPO_ROOT"
SRC_B="$ROOT_B/src"

cleanup() {
    if [[ "$KEEP" -eq 1 ]]; then
        log "kept build roots: $TMPROOT"
    else
        rm -rf "$TMPROOT"
    fi
}
trap cleanup EXIT

log "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
log "build root A: $ROOT_A (sources: $SRC_A)"
log "build root B: $ROOT_B (sources: $SRC_B, a copy)"
[[ "$DRY_RUN" -eq 1 ]] && log "DRY RUN — no build will be executed"

log "=== copying the sources for build B ==="
copy_source_tree "$SRC_B"

# Portability note: parallel indexed arrays instead of `declare -A`,
# for the same bash-3.2-on-macOS reason as encode_rustflags above.
# Populated in the same order as ARTIFACTS, so index i in ARTIFACTS
# lines up with index i in ELF_A / ELF_B.
ELF_A=()
ELF_B=()

for row in "${ARTIFACTS[@]}"; do
    IFS='|' read -r name kind build_dir config_toml rel_bin extra_args nightly <<< "$row"

    if [[ "$kind" == "cargo" ]]; then
        target_dir_a="$ROOT_A/target-$name"
        target_dir_b="$ROOT_B/target-$name"

        log "=== $name (cargo) — build A ==="
        build_cargo_artifact "$SRC_A" "$build_dir" "$config_toml" "$extra_args" "$nightly" "$target_dir_a"
        log "=== $name (cargo) — build B ==="
        build_cargo_artifact "$SRC_B" "$build_dir" "$config_toml" "$extra_args" "$nightly" "$target_dir_b"

        ELF_A+=("$target_dir_a/$rel_bin")
        ELF_B+=("$target_dir_b/$rel_bin")

    elif [[ "$kind" == "asm" ]]; then
        # hello and syscall_test are plain riscv64-unknown-elf-as/ld
        # builds (no cargo, no debug info requested) — mirrors the
        # $(HELLO_ELF)/$(SYSTEST_ELF) rules in the Makefile.
        if [[ "$name" == "hello" ]]; then
            src="hello.S"
        else
            src="test.S"
        fi
        obj_a="$ROOT_A/asm-out/$name.o"
        obj_b="$ROOT_B/asm-out/$name.o"
        elf_a="$ROOT_A/asm-out/$name.elf"
        elf_b="$ROOT_B/asm-out/$name.elf"

        log "=== $name (asm) — build A ==="
        mkdir -p "$ROOT_A/asm-out" "$ROOT_B/asm-out"
        build_asm_artifact "$SRC_A/$build_dir" "$src" "$SRC_A/userspace/tests/hello/user.ld" "$obj_a" "$elf_a"
        log "=== $name (asm) — build B ==="
        build_asm_artifact "$SRC_B/$build_dir" "$src" "$SRC_B/userspace/tests/hello/user.ld" "$obj_b" "$elf_b"

        ELF_A+=("$elf_a")
        ELF_B+=("$elf_b")
    fi
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "dry run complete — no artefacts were built or compared"
    exit 0
fi

# ---------------------------------------------------------------------
# Compare.
# ---------------------------------------------------------------------
printf '\n%-16s %-10s %s\n' "ARTEFACT" "RESULT" "SHA256 (A / B)"
FAIL=0
for i in "${!ARTIFACTS[@]}"; do
    IFS='|' read -r name _ _ _ _ _ _ <<< "${ARTIFACTS[$i]}"
    a="${ELF_A[$i]}"
    b="${ELF_B[$i]}"

    if [[ ! -f "$a" ]] || [[ ! -f "$b" ]]; then
        printf '%-16s %-10s missing: %s\n' "$name" "ERROR" "$([[ -f "$a" ]] || echo "$a")$([[ -f "$b" ]] || echo " $b")"
        FAIL=1
        continue
    fi

    sha_a="$(sha256_of "$a")"
    sha_b="$(sha256_of "$b")"
    if [[ "$sha_a" == "$sha_b" ]]; then
        printf '%-16s %-10s %s\n' "$name" "MATCH" "$sha_a"
    else
        printf '%-16s %-10s %s / %s\n' "$name" "DIFFER" "$sha_a" "$sha_b"
        FAIL=1
    fi
done

exit "$FAIL"
