#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The porting checklist, produced by the compiler.

`cargo check`s every crate that depends on `azos_arch` for
`x86_64-unknown-none` (through `-Zbuild-std`, no installed target needed),
where the facade selects the x86_64 port skeleton (crates/core/arch-x86_64):
`azos_arch` then exports the arch contract (arch-api's traits, `ARCH`,
`PAGE_SIZE`) plus the port's ISA-private modules (`features`, `fpu`,
`cpu`, `gdt`, `idt`, `fork_regs`, `hw`), none standing in for another ISA's. Every error is a place that reaches past the contract, i.e.
something a new ISA would have to provide by hand. Grouped by the missing
`azos_arch::<module>` (or by error kind otherwise), with the sites.

What this cannot see: a `cfg(target_arch)` branch with no else simply
vanishes on the new ISA and compiles. tools/arch_cfg_lint.py lists those.

Usage:
    python3 tools/arch_stub_check.py [--md FILE] [--target-dir DIR] [CRATE ...]
"""

import collections
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = "x86_64-unknown-none"
# Leaf-first: a crate's errors are only reported once its deps compile.
CRATES = [
    "azos_sync", "azos_mm", "azos_ipc", "azos_ml", "azos_drv_sys", "azos_drv_irqchip",
    "azos_drv_base", "azos_drv_virtio", "azos_camera", "azos_display",
    "azos_sched", "azos_actuation", "azos_shell", "azos_syscall", "azos_safety_core",
    "azos_libsys", "azos_kernel",
]


def check(crate, target_dir, config):
    env = dict(os.environ)
    env.setdefault("KCONFIG_CONFIG", config)
    env.pop("RUSTFLAGS", None)
    env.pop("CARGO_BUILD_RUSTFLAGS", None)
    cmd = ["cargo", "check", "--target", TARGET, "--message-format", "short",
           "--target-dir", target_dir, "-p", crate]
    p = subprocess.run(cmd, cwd=REPO, env=env, capture_output=True, text=True)
    return p.returncode, p.stderr


def main(argv):
    md = argv[argv.index("--md") + 1] if "--md" in argv else None
    td = argv[argv.index("--target-dir") + 1] if "--target-dir" in argv else os.path.join(REPO, "target", "arch-stub-check")
    # The x86_64 expansion `make ARCH=x86_64 check` writes, else the riscv64
    # QEMU one (only the Kconfig values crates read at build time matter).
    config = os.path.join(REPO, "build", "check-x86_64.config")
    if not os.path.exists(config):
        config = os.path.join(REPO, "target", "primary", "qemu.config")
    picked = [a for a in argv if not a.startswith("--") and a not in (md, td)] or CRATES
    by_key = collections.defaultdict(set)
    per_crate = {}
    blocked = {}
    seen = set()
    for crate in picked:
        rc, err = check(crate, td, config)
        errs = [l for l in err.splitlines() if re.match(r"^\S+:\d+:\d+: error", l)]
        mine = []
        for l in errs:
            if l in seen:
                continue
            seen.add(l)
            mine.append(l)
            m = re.match(r"^(\S+?):(\d+):\d+: error(\[\w+\])?: (.*)$", l)
            where, msg = f"{m.group(1)}:{m.group(2)}", m.group(4)
            mod = re.search(r"`azos_arch::(\w+)`|in `azos_arch`|could not find `(\w+)` in `azos_arch`|no `(\w+)` in the root", msg)
            name = re.search(r"could not find `(\w+)` in `azos_arch`|unresolved import `azos_arch::(\w+)", msg)
            if name:
                key = "azos_arch::" + (name.group(1) or name.group(2))
            elif "azos_arch" in msg:
                key = "azos_arch: " + re.sub(r"`[^`]*`", "`_`", msg)[:80]
            else:
                key = "other: " + re.sub(r"`[^`]*`", "`_`", msg)[:80]
            _ = mod
            by_key[key].add(where)
        per_crate[crate] = (rc, len(mine))
        if rc != 0 and not mine:
            # Its own errors only show once its dependencies compile.
            blocked[crate] = sorted({m.group(1) for m in re.finditer(r"could not compile `(\w+)`", err)})
    total = sum(len(v) for v in by_key.values())
    print(f"crates checked: {len(picked)}; distinct error sites: {total}; groups: {len(by_key)}")
    for c, (rc, n) in per_crate.items():
        print(f"  {c}: {'ok' if rc == 0 else ('blocked by ' + ', '.join(blocked[c]) if c in blocked else 'errors')} ({n} new)")
    if md:
        w = ["# Porting checklist (tools/arch_stub_check.py)\n",
             f"`cargo check --target {TARGET}` of each `azos_arch` consumer against the x86_64 skeleton: "
             "the facade exports only the arch contract, so each error is coupling a new ISA must "
             "provide. Plus: every method of every arch-api trait (see crates/core/arch-x86_64), and "
             "every uncovered site of tools/arch_cfg_lint.py.\n",
             f"- crates checked: {len(picked)}; distinct error sites: **{total}** in **{len(by_key)}** groups\n",
             "| crate | result | new error sites |", "|---|---|---|"]
        for c, (rc, n) in per_crate.items():
            res = "type-checks" if rc == 0 else ("blocked by " + ", ".join(blocked[c]) if c in blocked else "errors")
            w.append(f"| {c} | {res} | {n} |")
        w.append("\n## Groups (most sites first)\n")
        for key, sites in sorted(by_key.items(), key=lambda kv: -len(kv[1])):
            s = sorted(sites)
            more = f" (+{len(s) - 6} more)" if len(s) > 6 else ""
            w.append(f"- **{key}** — {len(s)}: " + ", ".join(s[:6]) + more)
        with open(md, "w", encoding="utf-8") as f:
            f.write("\n".join(w) + "\n")
        print(f"wrote {md}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
