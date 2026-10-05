#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Build the TFTP smoke fixture. Single source of truth for BOTH callers:
# the `qemu-tftp-smoke` Makefile target and `tools/ci_check.sh`.
#
# The two used to generate it independently, and had drifted: the Makefile
# wrote /dev/urandom, ci_check.sh wrote /dev/zero, and neither the kernel nor
# the gate ever checked a byte. Contents nobody verifies are contents that
# cannot fail.
#
# The pattern is byte i = i % 251, recomputed by the kernel rather than shipped
# to it (`kernel/src/main.rs`, tftp-smoke block). 251 is the largest prime
# below 256, so the period shares no factor with the 512-byte TFTP block size:
# a block that arrives at the wrong offset, twice, or not at all cannot happen
# to match.
#
# The size spans two full DATA blocks plus a short final one. A fixture of one
# short block — which is what 256 bytes was — never puts a full block on the
# wire, and a full block is precisely what a short receive ring truncated.
set -euo pipefail

out="${1:?usage: make_tftp_fixture.sh <path> [bytes]}"
bytes="${2:-1100}"

mkdir -p "$(dirname "$out")"
# Rewritten every run, never reused. A fixture left over from an earlier run
# measures the history of the working tree instead of this build.
rm -f "$out"
python3 -c "
import sys
n = int(sys.argv[1])
sys.stdout.buffer.write(bytes((i % 251) for i in range(n)))
" "$bytes" > "$out"

actual=$(wc -c < "$out" | tr -d ' ')
if [ "$actual" != "$bytes" ]; then
    echo "[TFTP] fixture is $actual bytes, expected $bytes" >&2
    exit 1
fi
echo "[TFTP] fixture $out ($actual bytes, i%251 pattern)"
