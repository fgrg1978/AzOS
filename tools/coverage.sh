#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Real region coverage for the host test suites.
#
# **Why this exists.** The gate counts tests, and a test count says nothing
# about what fraction of the code is ever executed. Asked "do we have full
# coverage?", the only honest answer without this is "we have 717 tests" --
# which answers a different question.
#
# **What it cannot measure**, stated up front so the number is not read as more
# than it is: only what the HOST suites reach. Code that exists solely on the
# RV64 target -- every driver MMIO path, the trap entry, the boot assembly, the
# protocol conformance block -- is invisible here. The QEMU scenarios DO
# execute that block on every boot, but executing is not asserting: only its
# failure line is matched anywhere in the gate (`QEMU_FAIL_RE` in
# `ci_check.sh`), and nothing greps for the success line, so a crate reading
# 0% may be thoroughly exercised end-to-end with no gate confirming the
# outcome; a crate reading 90% may have no QEMU scenario at all. The two
# numbers answer different questions and neither replaces the other.
#
# Needs the llvm-tools rustup component.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT="${OUT:-$(mktemp -d)}"
mkdir -p "$OUT/prof" "$OUT/json" || { echo "cannot create $OUT" >&2; exit 1; }

TC="$(ls -d "$HOME"/.rustup/toolchains/*/lib/rustlib/aarch64-apple-darwin/bin 2>/dev/null | head -1)"
if [ -z "$TC" ] || [ ! -x "$TC/llvm-cov" ]; then
    echo "llvm-tools not found:  rustup component add llvm-tools" >&2
    exit 1
fi

# `AZOS_UBENCH_NO_CEILING` (set on the cargo invocation below) tells
# regression-tests' host microbenchmarks to measure and print but not to
# enforce their nanosecond ceilings. `-C instrument-coverage` adds a counter
# increment per region, so it inflates every sample -- the three ceilings
# failed here for that reason alone, which took the whole suite, and therefore
# all of its regions, out of this report. The gate still enforces them.

# The same list the gate runs, so this describes the suites that actually gate
# the tree rather than whatever happens to be on disk.
SUITES="regression-tests ota-tests sched-policy-tests msc-tests
        tftp-tests topology-tests config-tests dfu-tests crypto-tests
        flight-math-tests flight-tests abi-tests arch-api-tests gguf-tests efi-tests
        multi-stream-tests drv-api-tests encrypt-link-tests
        cam-ring-tests dtb-tests aead-link-tests cap-tests
        ipc-fast-tests ipc-lease-tests ipc-chan-tests sched-wake-tests
        fs-tests arch-tests drivers-tests mm-tests libsys-tests behavior-tests
        net-tests seccomp-tests syscall-tests sync-tests world-state-tests"

echo "=== instrumenting host suites ==="
for c in $SUITES; do
    [ -d "tests/host/$c" ] || { echo "  skip $c (absent)"; continue; }
    printf "  %-24s" "$c"
    out=$( cd "tests/host/$c" && \
        LLVM_PROFILE_FILE="$OUT/prof/$c-%p-%m.profraw" \
        RUSTFLAGS="-C instrument-coverage" \
        CARGO_TARGET_DIR="$OUT/tgt-$c" \
        AZOS_UBENCH_NO_CEILING=1 \
        cargo test --release 2>&1 )
    if echo "$out" | grep -q "test result: FAILED\|^error"; then
        echo "FAILED"; echo "$out" | grep -m3 -E "^error|FAILED" | sed 's/^/      /'
        continue
    fi
    # $4, not $5: `grep -oE` yields only the matched span, so the fields are
    # test/result:/ok./N. Getting this wrong printed "0 tests" for every suite.
    n=$(echo "$out" | grep -oE "^test result: ok\. [0-9]+" | awk '{s+=$4} END {print s+0}')
    echo "ok ($n tests)"

    # **One profile per suite, never merged across suites.** Several test
    # crates pull kernel modules in with `#[path]`, so the same function is
    # compiled into more than one test binary with different counter layouts.
    # Merging those profiles makes llvm-cov report "N functions have mismatched
    # data" and then SILENTLY DROP the affected files -- in this tree that is
    # exactly ipc, sched, ota and behavior, the ones worth measuring. A first
    # version of this script did that and produced a confident 73% over a file
    # set that contained none of them.
    prof="$OUT/$c.profdata"
    "$TC/llvm-profdata" merge -sparse "$OUT/prof/$c-"*.profraw -o "$prof" 2>/dev/null || continue
    objs=()
    while IFS= read -r b; do objs+=(-object "$b"); done < <(
        find "$OUT/tgt-$c" -type f -perm -111 -path '*/deps/*' 2>/dev/null \
        | grep -vE "\.(d|rlib|rmeta)$" )
    [ ${#objs[@]} -eq 0 ] && continue
    "$TC/llvm-cov" export "${objs[@]}" -instr-profile="$prof" \
        -format=text -summary-only > "$OUT/json/$c.json" 2>/dev/null
done

echo
python3 - "$OUT" <<'PYEOF'
import json, glob, os, sys, collections, posixpath
OUT = sys.argv[1]
best = {}
for j in glob.glob(OUT + "/json/*.json"):
    try: d = json.load(open(j))
    except Exception: continue
    for f in d['data'][0]['files']:
        p = f['filename']
        if any(x in p for x in ('/registry/', '/rustlib/', '/rustc/')): continue
        if 'azos/' not in p: continue
        # **normpath is load-bearing.** A `#[path]`-included module is recorded
        # as `tests/host/ipc-fast-tests/src/../../ipc/src/fast_ipc.rs`, which
        # contains "-tests/" -- so a naive filter meant to drop the suites' own
        # code drops the production code they exist to cover. Resolve the
        # `../..` first, then exclude only what is genuinely inside a suite.
        rel = posixpath.normpath(p.split('azos/')[1])
        if any(s in rel for s in ('-tests/src', '-tests/shims', '-tests/tests')):
            continue
        r = f['summary']['regions']
        if r['count'] == 0: continue
        # Best any suite achieves: one suite's miss is not another's evidence.
        if rel not in best or r['percent'] > best[rel][1]:
            best[rel] = (r['count'], r['percent'])

crate = collections.defaultdict(lambda: [0, 0.0])
for rel, (n, pct) in best.items():
    parts = rel.split('/')
    c = parts[2] if parts[0] in ('crates', 'domains') else parts[0]
    crate[c][0] += n
    crate[c][1] += n * pct / 100.0

print(f"{'CRATE':<16}{'REGIONS':>10}{'COVER':>8}")
print("-" * 34)
tot = cov = 0
for c, (n, cv) in sorted(crate.items(), key=lambda x: -x[1][0]):
    print(f"{c:<16}{n:>10}{100*cv/n:>7.1f}%")
    tot += n; cov += cv
print("-" * 34)
print(f"{'TOTAL':<16}{tot:>10}{100*cov/tot:>7.1f}%")
print()
print("Crates with NO host coverage at all are absent from this table by")
print("construction -- see docs, and `ls crates/` for the full set.")
PYEOF

echo
echo "report dir: $OUT"
