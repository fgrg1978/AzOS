#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Coverage-guided fuzzing of the host-buildable parsers (cargo-fuzz/libFuzzer).
#
# Each target lives in `tests/fuzz/<name>-fuzz/` (its own cargo workspace) with two
# checked-in input sets per target:
#   corpus/<target>/       seeds and a minimised coverage corpus
#   regressions/<target>/  every input that once crashed, kept after the fix
#
# Usage:
#   tools/fuzz.sh list                    targets, one `<crate>:<target>` per line
#   tools/fuzz.sh check <crate>:<target>  gate row: build, replay corpus +
#                                         regressions, then a bounded run of
#                                         FUZZ_SECS (default 30) seconds
#   tools/fuzz.sh run <crate>:<target> <secs>
#                                         long local run; the corpus it grows
#                                         persists in $FUZZ_WORK/corpus/<target>
#   tools/fuzz.sh cmin <crate>:<target>   merge the grown corpus into the
#                                         checked-in one, keeping only inputs
#                                         that add coverage
#
# Build notes. The repository's `.cargo/config.toml` sets
# `[unstable] build-std = ["core", "alloc"]` for the kernel. cargo merges config
# arrays, so a nightly host build anywhere under the tree inherits it and then
# links a second `core` beside the one `std` carries (E0152) — the reason every
# `*-tests` crate pins stable. cargo-fuzz needs nightly (sanitizers), so it is
# built with `--build-std`: cargo then builds core, alloc AND std from source,
# with the sanitizer, and there is only one `core`. All targets share one target
# dir, `target/fuzz`, so std is built once.
#
# Environment:
#   FUZZ_SECS     bounded-run length for `check` (default 30)
#   FUZZ_TIMEOUT  per-input timeout in seconds; a hang that reproduces is a
#                 failure (default 25)
#   FUZZ_RSS_MB   per-process memory limit (default 2048)
#   FUZZ_WORK     scratch dir for grown corpora, artifacts, logs
#                 (default target/fuzz-work)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="${CARGO:-cargo}"
FUZZ_SECS="${FUZZ_SECS:-30}"
FUZZ_TIMEOUT="${FUZZ_TIMEOUT:-25}"
FUZZ_RSS_MB="${FUZZ_RSS_MB:-2048}"
FUZZ_WORK="${FUZZ_WORK:-${REPO_ROOT}/target/fuzz-work}"
TARGET_DIR="${REPO_ROOT}/target/fuzz"

# Every target the gate runs. Order: cheapest first.
TARGETS="
dtb:dtb_parse
config:config_ini
gguf:gguf_parse
elf:elf_load
topology:topology_toml
encrypt-link:link_frames
fs:fat32_image
net:eth_frame
net:dhcp_dns
sh:sh_line
"

die() { echo "fuzz.sh: $*" >&2; exit 2; }

split_spec() { # <crate>:<target> -> CRATE_DIR, TGT
    local spec="$1"
    case "$spec" in *:*) ;; *) die "expected <crate>:<target>, got '$spec'" ;; esac
    CRATE_DIR="${REPO_ROOT}/tests/fuzz/${spec%%:*}-fuzz"
    TGT="${spec#*:}"
    [ -f "${CRATE_DIR}/Cargo.toml" ] || die "no fuzz crate at ${CRATE_DIR}"
    [ -f "${CRATE_DIR}/fuzz_targets/${TGT}.rs" ] || die "no target ${TGT} in ${CRATE_DIR}"
}

host_triple() { rustc -vV | sed -n 's/^host: //p'; }

build() { # -> BIN; prints cargo errors on failure
    local log="${FUZZ_WORK}/logs/${TGT}.build.log"
    mkdir -p "${FUZZ_WORK}/logs"
    if ! (cd "${REPO_ROOT}" && "$CARGO" fuzz build --build-std --fuzz-dir "${CRATE_DIR}" \
            --target-dir "${TARGET_DIR}" "${TGT}") >"$log" 2>&1; then
        echo "      build failed (log: $log):"
        grep -E "^error" -A4 "$log" | sed -n 1,12p | sed 's/^/        /'
        return 1
    fi
    if grep -qE "^warning:" "$log"; then
        echo "      build warned (log: $log):"
        grep -E "^warning:" -A3 "$log" | sed -n 1,8p | sed 's/^/        /'
        return 1
    fi
    BIN="${TARGET_DIR}/$(host_triple)/release/${TGT}"
    [ -x "$BIN" ] || { echo "      no binary at $BIN after a clean build"; return 1; }
}

# Print what a failed libFuzzer run said, from the lines only failure prints.
explain() { # <log>
    grep -aE "SUMMARY: |panicked at|ERROR: libFuzzer|ERROR: AddressSanitizer|Test unit written|ALARM: working on the last Unit" "$1" \
        | sed -n 1,8p | sed 's/^/        /'
}

# Replay every checked-in input once. Each file must print its own
# `Executed <file>` line: a replay that silently ran nothing is not a pass.
replay() {
    local files=() f
    for f in "${CRATE_DIR}/corpus/${TGT}"/* "${CRATE_DIR}/regressions/${TGT}"/*; do
        [ -f "$f" ] && files+=("$f")
    done
    if [ "${#files[@]}" -eq 0 ]; then
        echo "      no checked-in inputs under corpus/${TGT} or regressions/${TGT}"
        return 1
    fi
    local log="${FUZZ_WORK}/logs/${TGT}.replay.log"
    "$BIN" -timeout="${FUZZ_TIMEOUT}" -rss_limit_mb="${FUZZ_RSS_MB}" "${files[@]}" >"$log" 2>&1
    local rc=$? ran
    ran=$(grep -ac "^Executed " "$log")
    if [ "$rc" -ne 0 ]; then
        echo "      replay of a checked-in input failed (rc=$rc, log: $log):"
        explain "$log"
        return 1
    fi
    if [ "$ran" -ne "${#files[@]}" ]; then
        echo "      replay executed $ran of ${#files[@]} inputs (log: $log)"
        return 1
    fi
    REPLAYED="${#files[@]}"
}

# libFuzzer with the grown corpus first (new inputs are written there, never
# into the checked-in directories) and the checked-in sets as read-only seeds.
fuzz_for() { # <secs> <fresh: 1|0>
    local secs="$1" fresh="$2"
    local work="${FUZZ_WORK}/corpus/${TGT}" art="${FUZZ_WORK}/artifacts/${TGT}/"
    [ "$fresh" = "1" ] && rm -rf "$work"
    mkdir -p "$work" "$art"
    local log="${FUZZ_WORK}/logs/${TGT}.fuzz.log"
    # Only the checked-in sets that exist: git keeps no empty directory, so a
    # target that never crashed has no regressions/<target>, and libFuzzer
    # exits on a missing corpus directory.
    local seeds=() d
    for d in "${CRATE_DIR}/corpus/${TGT}" "${CRATE_DIR}/regressions/${TGT}"; do
        [ -d "$d" ] && seeds+=("$d")
    done
    "$BIN" "$work" "${seeds[@]}" \
        -max_total_time="$secs" -timeout="${FUZZ_TIMEOUT}" -rss_limit_mb="${FUZZ_RSS_MB}" \
        -artifact_prefix="$art" -print_final_stats=1 >"$log" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ] && grep -aq "SUMMARY: libFuzzer: timeout" "$log"; then
        # A timeout must reproduce to count. Under host load (or a sleeping
        # laptop) libFuzzer's wall-clock alarm fires on inputs that run in a
        # millisecond; a real hang hangs again. Re-run the input alone.
        local unit
        unit="$(grep -aoE "Test unit written to [^ ]*timeout-[0-9a-f]+" "$log" | sed -n '$s/^Test unit written to //p')"
        if [ -n "$unit" ] && "$BIN" -timeout="${FUZZ_TIMEOUT}" "$unit" >"${log}.retry" 2>&1; then
            echo "      note: timeout on $(basename "$unit") did not reproduce alone (host stall); run counted"
            rc=0
        fi
    fi
    if [ "$rc" -ne 0 ]; then
        echo "      fuzzing found a failing input (rc=$rc, log: $log):"
        explain "$log"
        return 1
    fi
    if grep -aq "SUMMARY: libFuzzer: timeout" "$log"; then
        STATS="(stopped early by a non-reproducing timeout)"
        return 0
    fi
    # Positive anchor: libFuzzer's own end-of-run line.
    if ! grep -aqE "^Done [0-9]+ runs in" "$log"; then
        echo "      libFuzzer exited 0 without its 'Done N runs' line (log: $log)"
        return 1
    fi
    STATS="$(grep -aE "^#[0-9]+[[:space:]]+DONE" "$log" | sed -n '$p')"
}

cmd="${1:-}"
case "$cmd" in
    list)
        for s in $TARGETS; do echo "$s"; done ;;
    check)
        [ $# -eq 2 ] || die "usage: $0 check <crate>:<target>"
        "$CARGO" fuzz --version >/dev/null 2>&1 || { echo "      cargo-fuzz not installed (cargo install cargo-fuzz)"; exit 1; }
        split_spec "$2"
        build || exit 1
        replay || exit 1
        fuzz_for "$FUZZ_SECS" 1 || exit 1
        echo "      ${TGT}: replayed ${REPLAYED}, ${FUZZ_SECS}s: ${STATS}" >>"${FUZZ_WORK}/logs/summary.log"
        ;;
    run)
        [ $# -eq 3 ] || die "usage: $0 run <crate>:<target> <secs>"
        split_spec "$2"
        build || exit 1
        replay || exit 1
        fuzz_for "$3" 0 || exit 1
        echo "${TGT}: ${STATS}"
        ;;
    cmin)
        [ $# -eq 2 ] || die "usage: $0 cmin <crate>:<target>"
        split_spec "$2"
        build || exit 1
        new="${FUZZ_WORK}/cmin/${TGT}"
        rm -rf "$new"; mkdir -p "$new"
        "$BIN" -merge=1 -timeout="${FUZZ_TIMEOUT}" -rss_limit_mb="${FUZZ_RSS_MB}" "$new" \
            "${CRATE_DIR}/corpus/${TGT}" "${FUZZ_WORK}/corpus/${TGT}" \
            >"${FUZZ_WORK}/logs/${TGT}.cmin.log" 2>&1 || die "merge failed"
        rm -f "${CRATE_DIR}/corpus/${TGT}"/*
        cp "$new"/* "${CRATE_DIR}/corpus/${TGT}/"
        echo "${TGT}: corpus now $(ls "${CRATE_DIR}/corpus/${TGT}" | wc -l | tr -d ' ') inputs"
        ;;
    *)
        sed -n '2,20p' "$0"; exit 2 ;;
esac
