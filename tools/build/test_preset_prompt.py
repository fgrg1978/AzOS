#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host test of the recovery console's prompt: for each preset, the `azos_limits`
that a defconfig of the preset builds carries PRESET_PROMPT = "<preset>> ", and the
regular expression the gate's rows wait for and forbid (RECOVERY_PROMPT_RE in
tools/gate/ci_check.sh) matches that prompt, so a row of any cell still sees it.

    python3 tools/build/test_preset_prompt.py      (exit 0 = all pass)
"""

import glob
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
import gen_defconfigs  # noqa: E402
import out_dir  # noqa: E402

REPO = azos_tools.ROOT
FAILS = []


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


def gate_regex():
    line = next(l for l in open(os.path.join(REPO, "tools/gate/ci_check.sh"), encoding="utf-8")
                if l.startswith("RECOVERY_PROMPT_RE="))
    r = subprocess.run(["bash", "-c", f'REPO_ROOT="{REPO}"; {line}\nprintf %s "$RECOVERY_PROMPT_RE"'],
                       capture_output=True, text=True, check=True)
    return re.compile(r.stdout)


def prompt_of(preset, tmp, target):
    name = f"{preset}-sbc-riscv64-dev+qemu"
    cfg = os.path.join(tmp, preset + ".config")
    with open(cfg, "w") as f:
        f.write(gen_defconfigs.assemble(name))
    env = dict(os.environ, KCONFIG_CONFIG=cfg, CARGO_TARGET_DIR=target)
    subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=REPO, env=env, check=True, capture_output=True)
    subprocess.run(["cargo", "build", "-q", "-p", "azos_limits"], cwd=REPO, env=env, check=True)
    gen = max(glob.glob(os.path.join(target, "*/debug/build/azos_limits-*/out/generated.rs")), key=os.path.getmtime)
    m = re.search(r'pub const PRESET_PROMPT: &str = "([^"]*)";', open(gen).read())
    return m.group(1) if m else None


def main():
    rx = gate_regex()
    target = os.path.join(out_dir.out_root(), "target-prompt-test")
    with tempfile.TemporaryDirectory() as tmp:
        for p in gen_defconfigs.axis_values("presets"):
            got = prompt_of(p, tmp, target)
            check(got == f"{p}> ", f"{p}: the recovery console prompts {got!r}")
            check(got is not None and rx.search(got + "help") is not None,
                  f"{p}: the gate's RECOVERY_PROMPT_RE matches {got!r}")
    check(rx.search("azos$ ") is None, "the shell's prompt is not the recovery prompt")
    for f in FAILS:
        print("FAIL:", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
