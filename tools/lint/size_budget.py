#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Size budget: the kernel image's .text, .rodata, .data and .bss against a
committed baseline, a ratchet that only moves in a reviewed commit.

Each group is the sum of the ELF's output sections whose name starts with it
(`.text` holds .text.boot, .text and .text.patch_pool; `.data` holds
.data.ro_after_init and .data), plus riscv's small-data twins (.srodata,
.sdata, .sbss), as `llvm-size -A` reports them. The ELF is a build of a
pinned configuration (`make size-check` builds the robot gate cell
config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config,
never the developer's .config), so the number does not depend on who runs it.

tools/lint/size_budget.tsv: `label<TAB>group<TAB>bytes` lines and one
`label<TAB>reason<TAB>text` line per label (why the baseline last moved). A
group more than TOLERANCE above its baseline FAILS: the commit that grows the
image updates the baseline (`--update --reason ".."`), which puts the growth
and its reason in the diff. A group more than TOLERANCE below fails too, as
stale: the gain is locked in by updating, so it cannot silently come back.

  size_budget.py LABEL=ELF ...                       check (the gate row)
  size_budget.py --update --reason TEXT LABEL=ELF ...  rewrite those labels
  size_budget.py --report LABEL=ELF ...              current sizes and deltas
  size_budget.py --self-test                         the tool's own canaries

Environment: LLVM_BIN, the directory holding llvm-size (default: the active
rustup toolchain's llvm-tools, as tools/bench/size_report.sh finds it).
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = azos_tools.ROOT
BASELINE = "tools/lint/size_budget.tsv"
GROUPS = (".text", ".rodata", ".data", ".bss")
# riscv's small-data sections count with their group.
SMALL = {".srodata": ".rodata", ".sdata": ".data", ".sbss": ".bss"}
# Allowed drift either way before the check fails: 0.25% of the baseline, and
# never less than 512 bytes (alignment padding moves small groups by that much).
TOL_PER_10K = 25
TOL_MIN = 512


def tolerance(base):
    return max(TOL_MIN, base * TOL_PER_10K // 10000)


def group_of(section):
    for g in GROUPS:
        if section == g or section.startswith(g + "."):
            return g
    for s, g in SMALL.items():
        if section == s or section.startswith(s + "."):
            return g
    return None


def llvm_size():
    d = os.environ.get("LLVM_BIN")
    if not d:
        try:
            sysroot = subprocess.run(["rustc", "--print", "sysroot"], check=True,
                                     capture_output=True, text=True, cwd=ROOT).stdout.strip()
            host = [l.split(": ", 1)[1] for l in subprocess.run(
                ["rustc", "-vV"], check=True, capture_output=True, text=True, cwd=ROOT).stdout.splitlines()
                if l.startswith("host: ")][0]
        except (OSError, IndexError, subprocess.CalledProcessError) as e:
            raise SystemExit(f"size_budget: cannot find the toolchain's llvm-tools: {e}")
        d = os.path.join(sysroot, "lib", "rustlib", host, "bin")
    tool = os.path.join(d, "llvm-size")
    if not os.access(tool, os.X_OK):
        raise SystemExit(f"size_budget: no llvm-size in {d} (rustup component add llvm-tools-preview, or set LLVM_BIN)")
    return tool


def parse_size_a(text):
    """`llvm-size -A` output -> {group: bytes}."""
    sizes = dict.fromkeys(GROUPS, 0)
    for line in text.splitlines():
        cols = line.split()
        if len(cols) >= 2 and cols[0].startswith(".") and cols[1].isdigit():
            g = group_of(cols[0])
            if g:
                sizes[g] += int(cols[1])
    return sizes


def measure(elf):
    if not os.path.isfile(elf):
        raise SystemExit(f"size_budget: no ELF at {elf} (make size-kernel builds it)")
    try:
        out = subprocess.run([llvm_size(), "-A", elf], check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"size_budget: llvm-size -A {elf} failed: {e.stderr.strip()}")
    return parse_size_a(out)


def read_baseline(path):
    """-> {label: {"sizes": {group: bytes}, "reason": text}}."""
    base = {}
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) == 3 and cols[1] == "reason" and cols[2].strip():
                ent = base.setdefault(cols[0], {"sizes": {}, "reason": None})
                if ent["reason"] is not None:
                    raise SystemExit(f"{path}:{no}: second reason for {cols[0]}")
                ent["reason"] = cols[2]
            elif len(cols) == 3 and cols[1] in GROUPS and cols[2].isdigit():
                ent = base.setdefault(cols[0], {"sizes": {}, "reason": None})
                if cols[1] in ent["sizes"]:
                    raise SystemExit(f"{path}:{no}: duplicate {cols[0]} {cols[1]}")
                ent["sizes"][cols[1]] = int(cols[2])
            else:
                raise SystemExit(f"{path}:{no}: want label<TAB>group<TAB>bytes or label<TAB>reason<TAB>text, got {line!r}")
    for label, ent in base.items():
        missing = [g for g in GROUPS if g not in ent["sizes"]]
        if missing or not ent["reason"]:
            raise SystemExit(f"{path}: {label} lacks " + ", ".join(missing + ([] if ent["reason"] else ["a reason"])))
    return base


HEADER = (
    "# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only\n"
    "# SPDX-FileCopyrightText: 2026 Fernando Rodriguez\n"
    "# Size budget baseline (tools/lint/size_budget.py): bytes of each section group of\n"
    "# the kernel ELF per build label, and why the label last moved. The gate fails\n"
    "# when a group drifts from its line by more than the tolerance (0.25%, at least\n"
    "# 512 B): a commit that grows the image updates this file with a reason,\n"
    "# make size-update REASON=\"..\" (one that shrinks it, to lock the gain in).\n"
    "# label\tgroup\tbytes   |   label\treason\ttext\n"
)


def write_baseline(path, base):
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER)
        for label in sorted(base):
            for g in GROUPS:
                f.write(f"{label}\t{g}\t{base[label]['sizes'][g]}\n")
            f.write(f"{label}\treason\t{base[label]['reason']}\n")


def compare(base, label, cur):
    """-> (grew, stale) messages for one label's current sizes."""
    if label not in base:
        return [f"{label}: not in {BASELINE} (make size-update REASON=..)"], []
    grew, stale = [], []
    for g in GROUPS:
        b, c = base[label]["sizes"][g], cur[g]
        if abs(c - b) > tolerance(b):
            (grew if c > b else stale).append(
                f"{label} {g}: {b} -> {c} B ({c - b:+d}, tolerance {tolerance(b)})")
    return grew, stale


def parse_args(args):
    """-> (mode, reason, [(label, elf)])."""
    mode, reason, pairs = "check", None, []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--update", "--report"):
            mode = a[2:]
        elif a == "--reason" and i + 1 < len(args):
            reason = " ".join(args[i + 1].split())
            i += 1
        elif "=" in a and not a.startswith("-"):
            pairs.append(tuple(a.split("=", 1)))
        else:
            raise SystemExit(__doc__)
        i += 1
    if not pairs:
        raise SystemExit(__doc__)
    if mode == "update" and not reason:
        raise SystemExit("size_budget: --update needs --reason TEXT (why the image moved)")
    return mode, reason, pairs


def run(root, args, measure_fn=measure):
    mode, reason, pairs = parse_args(args)
    path = os.path.join(root, BASELINE)
    base = read_baseline(path) if os.path.isfile(path) else {}
    cur = {label: measure_fn(elf) for label, elf in pairs}
    if mode == "update":
        for label, sizes in cur.items():
            base[label] = {"sizes": sizes, "reason": reason}
        write_baseline(path, base)
        return 0
    if mode == "report":
        for label, sizes in cur.items():
            for g in GROUPS:
                b = base.get(label, {}).get("sizes", {}).get(g)
                print(f"{label:20s} {g:8s} {sizes[g]:10d} B" + ("" if b is None else f"  ({sizes[g] - b:+d} vs baseline)"))
        return 0
    fail = 0
    for label, sizes in cur.items():
        grew, stale = compare(base, label, sizes)
        for m in grew:
            print("FAIL (image grew beyond the baseline): " + m)
        for m in stale:
            print("FAIL (baseline stale, the image shrank): " + m)
        if grew or stale:
            fail = 1
        else:
            print(f"size budget ok: {label} " + " ".join(f"{g} {sizes[g]}" for g in GROUPS))
    if fail:
        print("update the baseline in the same commit, with the reason: make size-update REASON=\"..\"")
    return fail


# ---- self-test -------------------------------------------------------------

def self_test():
    fails = []

    def eq(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    sample = ("kernel  :\nsection              size         addr\n.text.boot           4096   2149580800\n"
              ".text             1200000   2149584896\n.text.patch_pool     4096   0\n.rodata            300000   0\n"
              ".srodata               16   0\n.azos_patch            64   0\n.data.ro_after_init  4096   0\n"
              ".data               20000   0\n.bss               900000   0\n.stack              65536   0\n"
              ".debug_info      99999999   0\n.comment              153   0\nTotal            100000000\n")
    eq("groups", parse_size_a(sample), {".text": 1208192, ".rodata": 300016, ".data": 24096, ".bss": 900000})
    eq("tolerance floor", tolerance(1000), 512)
    eq("tolerance share", tolerance(1200000), 3000)

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.dirname(os.path.join(root, BASELINE)))
        sizes = {"k": {".text": 1200000, ".rodata": 300000, ".data": 20000, ".bss": 900000}}

        def go(args):
            old = sys.stdout
            sys.stdout = open(os.devnull, "w")
            try:
                return run(root, args, lambda elf: dict(sizes[elf]))
            except SystemExit:
                return "exit"
            finally:
                sys.stdout.close()
                sys.stdout = old
        eq("no baseline fails", go(["q=k"]), 1)
        eq("update needs a reason", go(["--update", "q=k"]), "exit")
        eq("update", go(["--update", "--reason", "initial baseline", "q=k"]), 0)
        eq("equal passes", go(["q=k"]), 0)
        eq("reason recorded", read_baseline(os.path.join(root, BASELINE))["q"]["reason"], "initial baseline")
        sizes["k"][".text"] += 3000
        eq("growth within tolerance passes", go(["q=k"]), 0)
        # canary: .text grown past the tolerance fails until the baseline moves
        sizes["k"][".text"] += 1
        eq("growth fails", go(["q=k"]), 1)
        eq("growth message", compare(read_baseline(os.path.join(root, BASELINE)), "q", sizes["k"])[0],
           ["q .text: 1200000 -> 1203001 B (+3001, tolerance 3000)"])
        eq("update with reason", go(["--update", "--reason", "new driver", "q=k"]), 0)
        eq("updated passes", go(["q=k"]), 0)
        sizes["k"][".bss"] -= 4096
        eq("shrink is stale", go(["q=k"]), 1)
        eq("shrink is not growth", compare(read_baseline(os.path.join(root, BASELINE)), "q", sizes["k"])[0], [])
        eq("unknown label fails", go(["other=k"]), 1)
        for bad in ("q\t.text\tx\n", "q\t.text\t1\n", "q\t.heap\t1\n"):
            with open(os.path.join(root, BASELINE), "w") as f:
                f.write(bad)
            try:
                read_baseline(os.path.join(root, BASELINE))
                fails.append(f"malformed baseline accepted: {bad!r}")
            except SystemExit:
                pass
    if fails:
        print("size_budget self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("size_budget self-test ok")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    return run(ROOT, sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
