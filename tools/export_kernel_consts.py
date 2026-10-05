#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Export kernel-side Kconfig constants to a Python file the brain consumes.

The brain repo (`AzOSRobotBrain/`) is Python; it doesn't see the Rust
`crates/core/limits/src/generated.rs` directly.  Without coordination the two
sides drift (TCP_MAX_CONNS, MAX_SOCKETS, MTU, etc.) and bugs only surface
at deployment.

This script reads the kernel's active `.config` and writes a Python
companion module `AzOSRobotBrain/protocol_consts.py` with the subset of
options the brain side cares about — TCP/network sizing, AEAD wire
constants, profile flags, architecture flags.

Run after every Kconfig change:

    cd azos
    make defconfig-edge          # or any defconfig
    python3 tools/export_kernel_consts.py

Or wire into the Makefile as a post-defconfig hook.

The output file is regenerated; manual edits are lost.  Brain code that
needs a value imports it:

    from protocol_consts import KERNEL_TCP_MAX_CONNS

Drift detection: the brain's pytest includes a smoke test that loads
`protocol_consts.py` and checks key invariants (e.g. its
`KERNEL_TCP_MAX_CONNS` matches what the brain assumes for connection
pool sizing).  If the kernel-side value changes without a brain update,
the smoke fails.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

# ── The brain-relevant subset of Kconfig options ─────────────────────────
#
# Each entry: (kconfig_name, python_name, type)
# type ∈ {"int", "bool", "str"}.
#
# Keep this list tight — exporting EVERY Kconfig option would couple the
# brain to internal kernel decisions that don't affect cross-side
# behaviour.  The criterion for inclusion is: "does the brain need to
# reason about this number / flag to talk to the kernel correctly?"
EXPORTED: list[tuple[str, str, str]] = [
    # ── Architecture / board (informational; brain may key behaviour on these)
    ("ARCH_RISCV64",         "KERNEL_ARCH_RISCV64",         "bool"),
    ("ARCH_AARCH64",         "KERNEL_ARCH_AARCH64",         "bool"),
    ("ARCH_X86_64",          "KERNEL_ARCH_X86_64",          "bool"),
    ("BOARD_QEMU",           "KERNEL_BOARD_QEMU",           "bool"),
    ("BOARD_VF2",            "KERNEL_BOARD_VF2",            "bool"),
    ("BOARD_K1",             "KERNEL_BOARD_K1",             "bool"),

    # ── Profile (drives brain-side capacity decisions: connection pool,
    #    metric histogram buckets, etc.)
    ("PROFILE_EMBEDDED",     "KERNEL_PROFILE_EMBEDDED",     "bool"),
    ("PROFILE_EDGE",         "KERNEL_PROFILE_EDGE",         "bool"),
    ("PROFILE_FLEET",        "KERNEL_PROFILE_FLEET",        "bool"),

    # ── Connection / socket caps (brain MUST stay under these)
    ("TCP_MAX_CONNS",        "KERNEL_TCP_MAX_CONNS",        "int"),
    ("MAX_SOCKETS",          "KERNEL_MAX_SOCKETS",          "int"),

    # ── Network framing (brain TCP buffer sizing matches kernel)
    ("ETH_MTU",              "KERNEL_ETH_MTU",              "int"),
    ("TCP_MSS",              "KERNEL_TCP_MSS",              "int"),
    ("TCP_BUF_SIZE",         "KERNEL_TCP_BUF_SIZE",         "int"),
    ("TCP_WINDOW_SIZE",      "KERNEL_TCP_WINDOW_SIZE",      "int"),

    # ── Brain-link defaults (brain uses these as fall-back if env vars unset)
    ("BRAIN_SERVER_IP_DEFAULT",   "KERNEL_BRAIN_SERVER_IP_DEFAULT",   "str"),
    ("BRAIN_SERVER_PORT_DEFAULT", "KERNEL_BRAIN_SERVER_PORT_DEFAULT", "int"),
    ("AUTO_RECONNECT",            "KERNEL_AUTO_RECONNECT",            "bool"),

    # ── Subsumption layers (brain mirrors which layers the kernel accepts)
    ("BRAIN_L1_ENABLED",     "KERNEL_BRAIN_L1_ENABLED",     "bool"),
    ("BRAIN_L2_ENABLED",     "KERNEL_BRAIN_L2_ENABLED",     "bool"),
    ("BRAIN_L3_ENABLED",     "KERNEL_BRAIN_L3_ENABLED",     "bool"),

    # ── Security (brain must know if AEAD is expected by default)
    ("LINK_AEAD_DEFAULT_ON", "KERNEL_LINK_AEAD_DEFAULT_ON", "bool"),
    ("LINK_PSK_PATH",        "KERNEL_LINK_PSK_PATH",        "str"),
    ("SECURE_BOOT_ENFORCED", "KERNEL_SECURE_BOOT_ENFORCED", "bool"),

    # ── OTA (brain's fleet-OTA endpoint validates max image size)
    ("OTA_MAX_IMAGE_SIZE_MB", "KERNEL_OTA_MAX_IMAGE_SIZE_MB", "int"),
    ("OTA_SIG_MANDATORY",     "KERNEL_OTA_SIG_MANDATORY",     "bool"),

    # ── Task / resource ceilings (brain capacity planner uses these)
    ("MAX_TASKS",            "KERNEL_MAX_TASKS",            "int"),
    ("MAX_TOPICS",           "KERNEL_MAX_TOPICS",           "int"),
    ("MAX_SERVICES",         "KERNEL_MAX_SERVICES",         "int"),
]


# ── Bool semantics in Kconfig .config files ──────────────────────────────
#
# `CONFIG_FOO=y`              → True
# `# CONFIG_FOO is not set`   → False
# absent                       → False (Kconfig invariant: unset implies default)
def parse_config(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        raise FileNotFoundError(f"{path} not found — run `make defconfig-<name>` first")
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Disabled bool form: `# CONFIG_FOO is not set`
        if line.startswith("#") and " is not set" in line:
            tok = line.split()[1]  # CONFIG_FOO
            if tok.startswith("CONFIG_"):
                out[tok[len("CONFIG_"):]] = "n"
            continue
        if line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        if not k.startswith("CONFIG_"):
            continue
        key = k[len("CONFIG_"):]
        v = v.strip()
        # String values are quoted in .config — strip the quotes.
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[key] = v
    return out


def render_python(cfg: dict[str, str], sha12: Optional[str]) -> str:
    """Emit the brain-side Python module."""
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    lines: list[str] = [
        '"""GENERATED — kernel ↔ brain compile-time constant bridge.',
        "",
        "Run `python3 tools/export_kernel_consts.py` from the azos repo",
        "to regenerate.  Manual edits are lost.  See RFC-0026 §brain-side",
        "mirror.",
        "",
        f"Source: azos/.config",
    ]
    if sha12:
        lines.append(f"Config SHA-256 prefix: {sha12}")
    lines += [
        f"Generated: {now}",
        '"""',
        "from __future__ import annotations",
        "",
    ]

    for kconfig_name, py_name, kind in EXPORTED:
        raw = cfg.get(kconfig_name)
        # `raw == "n"` means explicitly disabled, missing means default-off.
        if kind == "bool":
            val = "True" if raw == "y" else "False"
            lines.append(f"{py_name}: bool = {val}")
        elif kind == "int":
            if raw is None or raw in ("y", "n"):
                # Missing → emit a None sentinel so downstream gets a clear
                # error instead of a silent zero.  Kconfig should always
                # produce a value for `int` options at their default.
                lines.append(f"{py_name}: int | None = None  # MISSING in .config")
            else:
                try:
                    v = int(raw, 0)  # accepts decimal + 0x-hex
                    lines.append(f"{py_name}: int = {v}")
                except ValueError:
                    lines.append(f"{py_name}: int | None = None  # UNPARSEABLE: {raw!r}")
        elif kind == "str":
            v = raw if raw is not None else ""
            lines.append(f'{py_name}: str = {v!r}')
        else:
            lines.append(f"# unknown kind {kind!r} for {kconfig_name}")

    lines += [
        "",
        "",
        "# ── Bookkeeping helpers ─────────────────────────────────────────────",
        "",
        "def selected_profile() -> str:",
        '    """Return the active PROFILE_* as a short string."""',
        "    if KERNEL_PROFILE_FLEET:    return 'fleet'",
        "    if KERNEL_PROFILE_EMBEDDED: return 'embedded'",
        "    return 'edge'",
        "",
        "def selected_board() -> str:",
        '    """Return the active BOARD_* as a short string."""',
        "    if KERNEL_BOARD_QEMU:    return 'qemu'",
        "    if KERNEL_BOARD_VF2:     return 'vf2'",
        "    if KERNEL_BOARD_K1:      return 'k1'",
        "    return 'generic'",
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Export kernel Kconfig → brain Python")
    p.add_argument(
        "--config",
        default=".config",
        help="Path to the kernel-side .config (default: .config in CWD)",
    )
    p.add_argument(
        "--out",
        default="../AzOSRobotBrain/protocol_consts.py",
        help="Destination Python file (default: ../AzOSRobotBrain/protocol_consts.py)",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Don't write; exit 1 if the destination would differ from current.",
    )
    args = p.parse_args()

    config_path = Path(args.config).resolve()
    cfg = parse_config(config_path)

    sha12: Optional[str] = None
    try:
        import hashlib
        sha12 = hashlib.sha256(config_path.read_bytes()).hexdigest()[:12]
    except Exception:
        pass

    text = render_python(cfg, sha12)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = (Path(args.config).resolve().parent / args.out).resolve()

    if args.check:
        if not out_path.exists():
            print(f"[CHECK] {out_path} does not exist — would create.", file=sys.stderr)
            return 1
        if out_path.read_text() != text:
            print(f"[CHECK] {out_path} is out-of-date.  Run without --check to regen.", file=sys.stderr)
            return 1
        print(f"[CHECK] {out_path} is up-to-date.")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    n = sum(1 for k, _, _ in EXPORTED if k in cfg or any(line.startswith(f"# CONFIG_{k} is not set") for line in config_path.read_text().splitlines()))
    print(f"[EXPORT] wrote {out_path} ({len(EXPORTED)} consts, {n} found in .config)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
