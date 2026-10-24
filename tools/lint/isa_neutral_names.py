#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""isa_neutral_names.py — the generic idle seam is not named after one ISA's instruction.

`wfi` is riscv64's and aarch64's mnemonic; x86_64 waits with `hlt`. The
shared code names what the seam does (owner, 2026-10-21):

    Cpu::wfi                 -> Cpu::wait_for_interrupt   (crates/core/arch-api, each ISA's impl, callers)
    IdleChoice::Wfi          -> IdleChoice::Shallow       (crates/core/energy)
    IdleGovernor::WfiOnly    -> IdleGovernor::ShallowOnly

The mnemonic stays where it is the instruction: each ISA crate's own
`cpu::wfi()` free function and asm, a guest's trapped `wfi` (crates/core/hv,
tests/host/hv-tests `Step::Wfi`), and prose about an ISA. Console text and
gate row names never said these identifiers, so no row changes.

  isa_neutral_names.py              check: exit 1 on any old name (the lint, `make check0`)
  isa_neutral_names.py --fix        rewrite the tree in place (the replayable rename:
                                    re-run it on a newer tree instead of resolving
                                    conflicts)
  isa_neutral_names.py --self-test  the canaries
"""

import os
import re
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
EXTS = (".rs", ".md", ".sh", ".py", ".toml", ".txt")
SKIP = ("rfcs/", "third_party/", "CHANGELOG.md")

# (old name pattern, new name, only in this file or None): each old name is
# what the lint refuses afterwards.
RULES = [
    (r"\bfn wfi\(&self\)", "fn wait_for_interrupt(&self)", None),
    # A method call (`ARCH.wfi()`, `self.wfi()`), not an ISA crate's free
    # function (`crate::cpu::wfi()`).
    (r"(?<=[\w)\]])\.wfi\(\)", ".wait_for_interrupt()", None),
    (r"\b(Self|Cpu)::wfi\b", r"\1::wait_for_interrupt", None),
    (r"\bWfiOnly\b", "ShallowOnly", None),
    (r"\bwfi_only_", "shallow_only_", None),
    (r"\bIdleChoice::Wfi\b", "IdleChoice::Shallow", None),
    (r"\bWfi\b", "Shallow", "crates/core/energy/src/seams.rs"),
]

# Prose that named the generic seam by the mnemonic: exact text, per file.
# Applied once by --fix (a line that no longer reads so is left alone).
PROSE = [
    ("crates/core/arch-api/src/lib.rs",
     "    /// Wait For Interrupt — low-power idle. Returns when any\n"
     "    /// pending interrupt is delivered to this hart.\n",
     "    /// Wait for an interrupt (riscv64 and aarch64 `wfi`, x86_64 `hlt`):\n"
     "    /// low-power idle. Returns when any pending interrupt is delivered to\n"
     "    /// this hart.\n"),
    ("crates/core/arch-api/src/lib.rs",
     "depth. Like `wfi`, it returns when any interrupt is pending.",
     "depth. Like [`Self::wait_for_interrupt`], it returns when any interrupt is pending."),
    ("crates/core/energy/src/seams.rs",
     "`wfi` in the idle task (depth 0 of the arch idle seam)",
     "`wait_for_interrupt` in the idle task (depth 0 of the arch idle seam)"),
    ("crates/core/energy/src/seams.rs",
     "    /// Today: always `wfi`.\n",
     "    /// Today: always the shallow wait (`Cpu::wait_for_interrupt`).\n"),
    ("kernel/src/tasks/system.rs",
     "so this folds to the bare `wfi` the\n",
     "so this folds to the bare wait the\n"),
    ("tests/host/energy-tests/src/lib.rs",
     "answers `wfi` without computing its inputs",
     "answers `Shallow` without computing its inputs"),
    ("tests/host/energy-tests/src/lib.rs",
     "image's code is the bare `wfi` only because neither is called.",
     "image's code is the bare wait only because neither is called."),
    ("Documentation/hal.md", "`hart_id`, `wfi`, `cpu_idle(depth)`", "`hart_id`, `wait_for_interrupt`, `cpu_idle(depth)`"),
    ("Documentation/hal.md", "Depth 0 is `wfi`;", "Depth 0 is `wait_for_interrupt`;"),
    ("Documentation/energy.md", "`ShallowOnly`: `wfi` (depth 0)", "`ShallowOnly`: `wait_for_interrupt` (depth 0)"),
]


def files(root=ROOT):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    me = os.path.relpath(os.path.abspath(__file__), root)
    return [p for p in out.decode().split("\0")
            if p.endswith(EXTS) and not p.startswith(SKIP) and p != me and " " not in p]


def apply_rules(path, text):
    for pat, new, only in RULES:
        if only is None or only == path:
            text = re.sub(pat, new, text)
    return text


def findings(path, text):
    out = []
    for no, line in enumerate(text.split("\n"), 1):
        for pat, _, only in RULES:
            if (only is None or only == path) and re.search(pat, line):
                out.append((no, line.strip()))
                break
    return out


def fix(root=ROOT):
    changed = 0
    for rel in files(root):
        p = os.path.join(root, rel)
        try:
            text = open(p, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        new = apply_rules(rel, text)
        for f, old, rep in PROSE:
            if f == rel:
                new = new.replace(old, rep)
        if new != text:
            open(p, "w", encoding="utf-8").write(new)
            changed += 1
    return changed


def check(root=ROOT):
    bad = []
    for rel in files(root):
        try:
            text = open(os.path.join(root, rel), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        bad += [(rel, no, l) for no, l in findings(rel, text)]
    return bad


def self_test():
    src = ("pub trait Cpu { fn wfi(&self); }\n"
           "fn f() { ARCH.wfi(); crate::cpu::wfi(); }\n"
           "/// [`Self::wfi`] and `IdleGovernor::WfiOnly`\n"
           "match c { IdleChoice::Wfi => 0, Step::Wfi => 1 }\n")
    got = apply_rules("x.rs", src)
    want = ("pub trait Cpu { fn wait_for_interrupt(&self); }\n"
            "fn f() { ARCH.wait_for_interrupt(); crate::cpu::wfi(); }\n"
            "/// [`Self::wait_for_interrupt`] and `IdleGovernor::ShallowOnly`\n"
            "match c { IdleChoice::Shallow => 0, Step::Wfi => 1 }\n")
    if got != want:
        print("isa_neutral_names self-test FAILED: the rename gave\n" + got)
        return 1
    if [n for n, _ in findings("x.rs", src)] != [1, 2, 3, 4] or findings("x.rs", got):
        print("isa_neutral_names self-test FAILED: the check does not tell the old names from the new")
        return 1
    print("isa_neutral_names self-test ok")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if "--fix" in argv:
        print(f"isa_neutral_names --fix: {fix()} files rewritten")
    bad = check()
    for rel, no, l in bad:
        print(f"{rel}:{no}: the generic idle seam named after an ISA's instruction "
              f"(Cpu::wait_for_interrupt, IdleChoice::Shallow, IdleGovernor::ShallowOnly): {l}")
    if bad:
        return 1
    print("isa_neutral_names: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
