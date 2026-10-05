#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# tools/sbom.sh — RFC-0012: local, offline CycloneDX 1.5 SBOM.
#
# Generates a Software Bill of Materials for the AzOS Rust workspace
# (every workspace member plus every resolved third-party crate) and,
# when the sibling ../AzOSRobotBrain repo is present, for its Python
# dependencies too. Fully offline: `cargo metadata --offline --locked`
# reads Cargo.lock without touching the network, and no crate is built.
#
# This is a hand-run tool, not a CI job — the project runs no CI
# automation by owner decision; RFC-0012 records the scope. Run it
# whenever a dependency change should be reflected in the SBOM.
#
# Usage:
#   tools/sbom.sh [output-path]
#
# Default output-path: build/sbom.cdx.json
#
# Exit status: non-zero if `cargo metadata` fails (e.g. Cargo.lock is
# out of date and --locked refuses to update it) or if the Python step
# cannot produce valid JSON.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRAIN_DIR="$REPO_ROOT/../AzOSRobotBrain"
OUT_PATH="${1:-build/sbom.cdx.json}"

# Resolve OUT_PATH relative to the repo root when it isn't absolute, so
# the tool behaves the same whether invoked from the repo root or from
# tools/.
case "$OUT_PATH" in
    /*) : ;;
    *) OUT_PATH="$REPO_ROOT/$OUT_PATH" ;;
esac

mkdir -p "$(dirname "$OUT_PATH")"

CARGO="${CARGO:-cargo}"

echo "[sbom] running cargo metadata --offline --locked ..."
cd "$REPO_ROOT"
METADATA_JSON="$(mktemp -t azos-sbom-metadata.XXXXXX)"
METADATA_ERR="$(mktemp -t azos-sbom-metadata-err.XXXXXX)"
trap 'rm -f "$METADATA_JSON" "$METADATA_ERR"' EXIT

if ! "$CARGO" metadata --offline --locked --format-version 1 > "$METADATA_JSON" 2>"$METADATA_ERR"; then
    echo "[sbom] ERROR: cargo metadata --offline --locked failed:" >&2
    cat "$METADATA_ERR" >&2
    exit 1
fi

echo "[sbom] building CycloneDX document ..."
python3 - "$METADATA_JSON" "$BRAIN_DIR" "$OUT_PATH" "$REPO_ROOT" <<'PYEOF'
import json
import re
import sys
import uuid
from datetime import datetime, timezone

metadata_path, brain_dir, out_path, repo_root = sys.argv[1:5]

with open(metadata_path, "r", encoding="utf-8") as f:
    meta = json.load(f)

components = []
seen = set()


def add_component(bom_ref, name, version, purl, license_expr, comp_type, description=None):
    if bom_ref in seen:
        return
    seen.add(bom_ref)
    comp = {
        "type": comp_type,
        "bom-ref": bom_ref,
        "name": name,
        "version": version,
        "purl": purl,
    }
    if description:
        comp["description"] = description
    if license_expr:
        comp["licenses"] = [{"expression": license_expr}]
    components.append(comp)


# --- Rust workspace + resolved third-party crates -------------------
for pkg in meta.get("packages", []):
    name = pkg["name"]
    version = pkg["version"]
    purl = f"pkg:cargo/{name}@{version}"
    license_expr = pkg.get("license") or None
    is_local = pkg.get("source") is None

    kinds = set()
    for t in pkg.get("targets", []):
        kinds.update(t.get("kind", []))
    if "bin" in kinds:
        comp_type = "application"
    else:
        comp_type = "library"

    bom_ref = f"cargo:{name}:{version}"
    add_component(
        bom_ref,
        name,
        version,
        purl,
        license_expr,
        comp_type,
        description="AzOS workspace crate" if is_local else None,
    )

rust_component_count = len(components)

# --- Python (AzOSRobotBrain) dependencies -------------------------------
# RFC-0012 scope: AzOSRobotBrain has no lockfile (no requirements.lock,
# poetry.lock, Pipfile.lock or uv.lock) as of 2026-09-13 — only an
# unpinned requirements.txt with >= constraints. Record each declared
# dependency with an "unknown" resolved version rather than guessing
# one; do not fabricate a purl version qualifier for an unpinned dep.
import os

LOCKFILE_CANDIDATES = [
    "requirements.lock",
    "requirements-lock.txt",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
]

brain_lockfile = None
for candidate in LOCKFILE_CANDIDATES:
    candidate_path = os.path.join(brain_dir, candidate)
    if os.path.isfile(candidate_path):
        brain_lockfile = candidate_path
        break

NAME_VERSION_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==)\s*([A-Za-z0-9._+!-]+)"
)
REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")

if brain_lockfile is not None:
    # Pinned lockfile present: parse "name==version" pairs (requirements.lock
    # style; poetry.lock/Pipfile.lock/uv.lock are TOML/JSON and would need a
    # format-specific parse not exercised in this repo state).
    with open(brain_lockfile, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = NAME_VERSION_RE.match(line)
            if not m:
                continue
            name, _, version = m.groups()
            purl = f"pkg:pypi/{name.lower()}@{version}"
            add_component(
                f"pypi:{name}:{version}",
                name,
                version,
                purl,
                None,
                "library",
                description=f"AzOSRobotBrain dependency, pinned in {os.path.basename(brain_lockfile)}",
            )
elif os.path.isfile(os.path.join(brain_dir, "requirements.txt")):
    req_path = os.path.join(brain_dir, "requirements.txt")
    with open(req_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = REQ_NAME_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            purl = f"pkg:pypi/{name.lower()}"
            add_component(
                f"pypi:{name}:unknown",
                name,
                "unknown",
                purl,
                None,
                "library",
                description="AzOSRobotBrain dependency, version unpinned in requirements.txt",
            )

python_component_count = len(components) - rust_component_count

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": [
            {
                "vendor": "AzOS project",
                "name": "tools/sbom.sh",
                "version": "1.0.0",
            }
        ],
        "component": {
            "type": "application",
            "bom-ref": "azos-workspace",
            "name": "azos",
            "version": "0.0.0",
        },
    },
    "components": components,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(bom, f, indent=2)
    f.write("\n")

print(f"[sbom] wrote {out_path}")
print(f"[sbom] components: {len(components)} (rust: {rust_component_count}, python: {python_component_count})")
PYEOF

echo "[sbom] done: $OUT_PATH"
