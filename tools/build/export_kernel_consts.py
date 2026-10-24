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
    make defconfig-generic-sbc-riscv64-dev          # or any defconfig
    python3 tools/build/export_kernel_consts.py

The output file is regenerated; manual edits are lost.  Brain code that
needs a value imports it:

    from protocol_consts import KERNEL_TCP_MAX_CONNS

Drift detection, both sides:
  * `--check` (the protocol-sync step of tools/gate/ci_full.sh, `make ci-full`)
    exits 1 when the brain's file holds other values than this `.config`
    gives (its header, which names the source, is not compared), or when an
    EXPORTED symbol is not declared in the Kconfig tree any more;
  * the brain's pytest loads `protocol_consts.py` and checks the invariants
    the brain relies on (e.g. `KERNEL_TCP_MAX_CONNS` against its connection
    pool sizing).
`--self-test` runs the check against a planted drift.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

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
    #    metric histogram buckets, etc.): the limits tier of the HWCLASS axis.
    #    A `|` list is true when any of its symbols is.
    ("HWCLASS_EMBEDDED",     "KERNEL_PROFILE_EMBEDDED",     "bool"),
    ("HWCLASS_SBC|HWCLASS_DESKTOP", "KERNEL_PROFILE_EDGE",  "bool"),
    ("HWCLASS_SERVER",       "KERNEL_PROFILE_FLEET",        "bool"),

    # ── Connection / socket caps (brain MUST stay under these)
    ("TCP_MAX_CONNS",        "KERNEL_TCP_MAX_CONNS",        "int"),
    ("MAX_SOCKETS",          "KERNEL_MAX_SOCKETS",          "int"),

    # ── Network buffers (brain TCP buffer sizing matches kernel)
    ("TCP_BUF_SIZE",         "KERNEL_TCP_BUF_SIZE",         "int"),

    # ── Security (the brain mirrors the kernel boot policy)
    ("SECURE_BOOT_ENFORCED", "KERNEL_SECURE_BOOT_ENFORCED", "bool"),

    # ── OTA (brain's fleet-OTA endpoint validates max image size)
    ("OTA_MAX_IMAGE_SIZE_MB", "KERNEL_OTA_MAX_IMAGE_SIZE_MB", "int"),
    ("OTA_SIG_MANDATORY",     "KERNEL_OTA_SIG_MANDATORY",     "bool"),

    # ── Task / resource ceilings (brain capacity planner uses these)
    ("MAX_TASKS",            "KERNEL_MAX_TASKS",            "int"),
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
    lines: list[str] = [
        '"""GENERATED — kernel ↔ brain compile-time constant bridge.',
        "",
        "Run `python3 tools/build/export_kernel_consts.py` from the azos repo",
        "to regenerate.  Manual edits are lost.  This is the brain-side",
        "mirror.",
        "",
        f"Source: azos/.config",
    ]
    if sha12:
        lines.append(f"Config SHA-256 prefix: {sha12}")
    lines += [
        '"""',
        "from __future__ import annotations",
        "",
    ]

    for kconfig_name, py_name, kind in EXPORTED:
        raw = cfg.get(kconfig_name)
        # `raw == "n"` means explicitly disabled, missing means default-off.
        if kind == "bool":
            val = "True" if any(cfg.get(n) == "y" for n in kconfig_name.split("|")) else "False"
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
        '    """Return the active limits tier (HWCLASS) as a short string."""',
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


def body(text: str) -> str:
    """The module without its docstring header (source path, config SHA)."""
    head, sep, rest = text.partition('\n"""\n')
    return rest if sep else text


def undeclared() -> list[str]:
    """EXPORTED symbols the Kconfig tree does not declare."""
    import kconfiglib
    old = os.getcwd()
    os.chdir(azos_tools.ROOT)
    try:
        kconf = kconfiglib.Kconfig("Kconfig", warn=False)
    finally:
        os.chdir(old)
    return [n for k, _, _ in EXPORTED for n in k.split("|")
            if n not in kconf.syms or not kconf.syms[n].nodes]


def check(out_path: Path, text: str) -> int:
    gone = undeclared()
    if gone:
        print(f"[CHECK] EXPORTED names symbols Kconfig no longer declares: {' '.join(gone)}", file=sys.stderr)
        return 1
    if not out_path.exists():
        print(f"[CHECK] {out_path} does not exist — would create.", file=sys.stderr)
        return 1
    have = {l for l in body(out_path.read_text()).splitlines() if l.startswith("KERNEL_")}
    want = {l for l in body(text).splitlines() if l.startswith("KERNEL_")}
    if body(out_path.read_text()) != body(text):
        print(f"[CHECK] {out_path} is out-of-date.  Run without --check to regen.", file=sys.stderr)
        for l in sorted(want - have):
            print(f"  kernel: {l}", file=sys.stderr)
        for l in sorted(have - want):
            print(f"  brain:  {l}", file=sys.stderr)
        return 1
    print(f"[CHECK] {out_path} is up-to-date.")
    return 0


def self_test() -> int:
    fails = []
    gone = undeclared()
    if gone:
        fails.append(f"EXPORTED names undeclared symbols: {gone}")
    cfg = {"ARCH_RISCV64": "y", "BOARD_QEMU": "y", "HWCLASS_SBC": "y", "TCP_MAX_CONNS": "8", "MAX_SOCKETS": "16",
           "TCP_BUF_SIZE": "4096", "OTA_MAX_IMAGE_SIZE_MB": "8", "MAX_TASKS": "64"}
    text = render_python(cfg, "000000000000")
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "protocol_consts.py"
        old, sys.stderr = sys.stderr, open(os.devnull, "w")
        old_out, sys.stdout = sys.stdout, sys.stderr
        try:
            cases = []
            cases.append(("absent", check(out, text), 1))
            out.write_text(text)
            cases.append(("same", check(out, text), 0))
            out.write_text(render_python(cfg, "111111111111").replace("Source: azos/.config", "Source: x"))
            cases.append(("only the header differs", check(out, text), 0))
            out.write_text(render_python(dict(cfg, TCP_MAX_CONNS="16"), "000000000000"))
            cases.append(("a value drifted", check(out, text), 1))
            out.write_text(text.replace("KERNEL_MAX_TASKS: int = 64\n", ""))
            cases.append(("a constant missing", check(out, text), 1))
        finally:
            sys.stderr.close()
            sys.stderr, sys.stdout = old, old_out
    for name, got, want in cases:
        if got != want:
            fails.append(f"{name}: check exit {got}, want {want}")
    if fails:
        print("export_kernel_consts self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("export_kernel_consts self-test ok")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
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
        return check(out_path, text)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    n = sum(1 for k, _, _ in EXPORTED if k in cfg or any(line.startswith(f"# CONFIG_{k} is not set") for line in config_path.read_text().splitlines()))
    print(f"[EXPORT] wrote {out_path} ({len(EXPORTED)} consts, {n} found in .config)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
