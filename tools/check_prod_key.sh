#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# check_prod_key.sh — Validate that the production Ed25519 public key file
# is present, correctly sized, and NOT the all-zero dev key.
#
# Usage: ./tools/check_prod_key.sh [path/to/prod_pub.bin]
# Default path: tools/keys/prod_pub.bin (relative to repo root)
#
# Exit 0 on success, non-zero with an error message on stderr on failure.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
KEY_PATH="${1:-tools/keys/prod_pub.bin}"
EXPECTED_SIZE=32  # Ed25519 public key length in bytes

# ---------------------------------------------------------------------------
# Check 1: File must exist
# ---------------------------------------------------------------------------
if [ ! -f "$KEY_PATH" ]; then
    echo "ERROR: production key not found: $KEY_PATH" >&2
    echo "       Generate it with: xxd -p -c 256 tools/keys/prod_pub.bin" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Check 2: File must be exactly EXPECTED_SIZE bytes
# ---------------------------------------------------------------------------
actual_size="$(wc -c < "$KEY_PATH" | tr -d ' ')"
if [ "$actual_size" -ne "$EXPECTED_SIZE" ]; then
    echo "ERROR: $KEY_PATH is $actual_size bytes; expected $EXPECTED_SIZE bytes (Ed25519 pubkey)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Check 3: File must NOT be all-zero bytes (dev key)
# ---------------------------------------------------------------------------
hex_nonzero="$(xxd -p -c 256 "$KEY_PATH" | tr -d '0')"
if [ -z "$hex_nonzero" ]; then
    echo "ERROR: $KEY_PATH contains the all-zero dev key — refusing release build" >&2
    echo "       Provision the real production key from the secure key store." >&2
    exit 1
fi

echo "OK: $KEY_PATH is a valid $EXPECTED_SIZE-byte non-zero Ed25519 public key"
