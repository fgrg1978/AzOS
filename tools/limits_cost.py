#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""tools/limits_cost.py -- what one unit of a sizing option costs in RAM.

The sizing options of config/Kconfig.*  (MAX_TASKS, TCP_MAX_CONNS, ...) each
size one or more static tables.  Which tables, and how many bytes per unit,
is read here from the linker's own output instead of being estimated:

    1. build the kernel from a base config (the QEMU edge defaults),
    2. build it again with ONE option changed (a small and a large step),
    3. compare `llvm-nm -S` symbol sizes and `llvm-size -A` section sizes.

The difference divided by the step is the cost of one unit.  A symbol that
does not move linearly (a table rounded up to a power of two, an alignment
step) shows as a "small step" figure that disagrees with the "large step"
one; both are printed so the reader sees it.  A build the validator or a
compile-time assertion refuses is reported with the message: that is a hard
ceiling of the option, and the text is worth copying into its help.

Usage (from the repository root):

    python3 tools/limits_cost.py sweep  [--arch riscv64|aarch64] [SYMBOL ...]
    python3 tools/limits_cost.py compare [--arch A] SYM=VALUE [SYM=VALUE ...]
    python3 tools/limits_cost.py build [--arch A] [--linker LD] CONFIG
    python3 tools/limits_cost.py report RESULT.json [RESULT.json ...]

`compare` builds the base and the base with all the given options changed at
once, and prints what moved (used to check a model of several options against
the linker's own numbers).  `sweep` writes RESULT.json (default target/limits_cost/<arch>.json) and
prints a table.  With no SYMBOL it runs every option listed in STEPS.
`--base CONFIG` overrides the base .config; the defaults are
target/primary/qemu.config (riscv64) and
target/primary-aarch64/qemu-aarch64.config (aarch64), both the edge profile.
Set CARGO_TARGET_DIR to keep the two architectures' builds apart so they can
run side by side.

Byte figures are of the release ELF.  "RAM" is the sum of the changed
.data/.bss symbols (the linker places both in RAM; .data is also in the image
file); rodata and text symbol deltas are reported apart.  Per-unit figures come
from symbol sizes, not from section sizes: a section total can absorb a step
in alignment padding (aarch64's .bss did, for +1 task).  An
option that sizes frames taken from the PMM or the kernel heap at run time
(KERNEL_HEAP_SIZE, USER_STACK_SIZE_KB, the RING3_* budgets) moves nothing in
the image; the sweep shows a zero for it, and its help text says what it
costs at run time.
"""
import argparse
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SYMBOL -> (small step value, large step value).  A value is the NEW value of
# the option; the base value comes from the base config.  None skips a step
# (a power-of-two option has no +1).  Every value is accepted by the build.rs
# validator at the edge defaults, so a refusal reported by the sweep is news.
STEPS = {
    "MAX_TASKS":               (65, 128),
    "TCP_MAX_CONNS":           (9, 12),
    "MAX_SOCKETS":             (17, 32),
    "MAX_FDS_PER_PROC":        (17, 32),
    "MAX_FDS_TOTAL":           (2049, 4096),
    "MAX_CHANNELS":            (17, 32),
    "MAX_PIPES":               (33, 64),
    "MAX_PORTS":               (33, 64),
    "MAX_PORT_SOURCES":        (17, 32),
    "MAX_LEASES":              (17, 32),
    "MAX_SERVICES":            (33, 64),
    "MAX_TOPICS":              (33, 64),
    "MAX_SUBS_PER_TOPIC":      (9, 16),
    "MAX_CAPS_TOTAL":          (1025, 2048),
    "MAX_CAPS_PER_TASK":       (257, 512),
    "KERNEL_HEAP_SIZE":        (32769, 65536),
    "RING3_MEM_PAGES_DEFAULT": (1025, 2048),
    "AUTORUN_MEM_PAGES":       (2049, 4096),
    "MEM_KERNEL_RESERVE_KB":   (2049, 4096),
    "DMA_POOL_FLOOR_KB":       (2049, 4096),
    "USER_STACK_SIZE_KB":      (20, 32),
    "KERNEL_STACK_SIZE_KB":    (36, 64),
    "INTERRUPT_STACK_SIZE_KB": (9, 16),
    "WCET_MAX_POINTS":         (129, 256),
    "MAX_IO_RINGS":            (17, 32),
    "VFS_MAX_FILES":           (129, 256),
    "VFS_MAX_MOUNTS":          (5, 8),
    "FS_BLOCK_CACHE_KB":       (1024, 2048),
    "TMPFS_MAX_FILES":         (65, 128),
    "TMPFS_MAX_KB":            (2049, 4096),
    "TCP_BUF_SIZE":            (None, 262144),
    "ARP_CACHE_SIZE":          (17, 32),
    "ARP_PENDING_SIZE":        (9, 16),
    "DNS_CACHE_SIZE":          (5, 8),
    "UDP_RX_SLOTS":            (None, 8),
    "CONSOLE_TX_RING_BYTES":   (4097, 8192),
    "CONSOLE_DEFER_BYTES":     (8193, 16384),
    "RAM_SIZE":                (257, 512),
    "OTA_MAX_IMAGE_SIZE_MB":   (9, 16),
    "PSTORE_SIZE_KB":          (5, 16),
}

BASE_CONFIG = {
    "riscv64": "target/primary/qemu.config",
    "aarch64": "target/primary-aarch64/qemu-aarch64.config",
}
SECTIONS = (".text", ".rodata", ".data", ".bss")
HASH_RE = re.compile(r"::h[0-9a-f]{16}$")
LLVM_RE = re.compile(r"\s*\(?\.llvm\.\d+\)?$")


def tool(name):
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    out = subprocess.check_output(["rustc", "-vV"], text=True)
    host = re.search(r"^host: (.*)$", out, re.M).group(1)
    return os.path.join(sysroot, "lib", "rustlib", host, "bin", name)


def read_config(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def config_value(text, sym):
    m = re.search(r"^CONFIG_%s=(.*)$" % re.escape(sym), text, re.M)
    return m.group(1) if m else None


def with_value(text, sym, value):
    pat = re.compile(r"^CONFIG_%s=.*$" % re.escape(sym), re.M)
    if not pat.search(text):
        raise SystemExit(f"limits_cost: CONFIG_{sym} is not set in the base config")
    return pat.sub(f"CONFIG_{sym}={value}", text, count=1)


def target_dir():
    return os.environ.get("CARGO_TARGET_DIR", os.path.join(REPO, "target"))


def big_linker(arch):
    """Linker script with a RAM region big enough for a fleet-sized image.

    riscv64 has kernel/linker-fleet.ld (1022 MiB).  aarch64 has none: a copy of
    its script with the two 128 MiB regions widened is written under target/.
    """
    if arch == "riscv64":
        return os.path.join(REPO, "kernel", "linker-fleet.ld")
    src = read_config(os.path.join(REPO, "kernel", "linker-aarch64.ld"))
    dst = os.path.join(REPO, "target", "limits_cost", "linker-aarch64-1022M.ld")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(src.replace("LENGTH = 128M - 512K", "LENGTH = 1022M"))
    return dst


def build(arch, cfg_path, linker=None):
    """Build the kernel for ARCH from CFG_PATH; return (elf path | None, error text)."""
    env = dict(os.environ)
    env["KCONFIG_CONFIG"] = cfg_path
    if arch == "riscv64":
        cmd = ["cargo", "build", "--release", "--features", "qemu"]
        if linker:
            env["RUSTFLAGS"] = (f"-C link-arg=-T{linker} -C code-model=medium "
                                "-C target-feature=+zaamo,+zalrsc")
        elf = os.path.join(target_dir(), "riscv64imac-unknown-none-elf", "release", "kernel")
    else:
        env.pop("RUSTFLAGS", None)
        env.pop("CARGO_BUILD_RUSTFLAGS", None)
        cmd = ["cargo", "build", "--release", "--target", "aarch64-unknown-none-softfloat",
               "-p", "azos_kernel", "--features", "qemu",
               "--config",
               'build.rustflags=["-C","link-arg=-T%s"]' % (linker or "kernel/linker-aarch64.ld")]
        elf = os.path.join(target_dir(), "aarch64-unknown-none-softfloat", "release", "kernel")
    if os.path.exists(elf):
        os.remove(elf)  # never read a stale ELF after a failed build
    p = subprocess.run(cmd, cwd=REPO, env=env, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    # The gate (tools/ci_check.sh) excludes cargo's `warning: <pkg>@<version>: ...`
    # shape: build scripts announcing things (crates/core/ota names the key it embeds).
    warns = [l for l in p.stdout.splitlines()
             if l.startswith("warning:") and "future version of Rust" not in l
             and not re.match(r"^warning: [A-Za-z0-9_-]+@[0-9]", l)]
    if p.returncode != 0 or not os.path.exists(elf):
        lines = [l for l in p.stdout.splitlines()
                 if "validation FAIL" in l or l.startswith("error") or "panicked" in l
                 or "evaluation of constant" in l or "assertion" in l]
        return None, " | ".join(lines[:4]) or p.stdout[-400:], warns
    return elf, "", warns


def klass(t):
    """nm type letter -> ram (.data/.bss), ro (.rodata) or text."""
    t = t.lower()
    if t in ("b", "d", "s", "g", "c"):
        return "ram"
    if t in ("r", "n"):
        return "ro"
    return "text"


def measure(elf):
    """Symbol sizes keyed (demangled name without hash, class), and section sizes."""
    nm = subprocess.check_output([tool("llvm-nm"), "-S", "-C", "--defined-only", elf], text=True)
    syms = {}
    for line in nm.splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4:
            continue
        try:
            size = int(parts[1], 16)
        except ValueError:
            continue
        name = LLVM_RE.sub("", HASH_RE.sub("", LLVM_RE.sub("", parts[3])))
        k = klass(parts[2])
        if name.startswith(".L") or name.startswith("anon."):
            # `.L_MergedGlobals` is a blob of statics that also carry symbols
            # of their own (counting both would count a table twice); `.Lanon`
            # and `anon.` labels have a hash that differs between builds.
            continue
        key = name + "\t" + k
        syms[key] = syms.get(key, 0) + size
    sz = subprocess.check_output([tool("llvm-size"), "-A", elf], text=True)
    secs = {}
    for line in sz.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in SECTIONS:
            secs[parts[0]] = int(parts[1])
    return {"syms": syms, "secs": secs}


def diff(base, var, delta_units):
    changed = []
    tot = {"ram": 0, "ro": 0, "text": 0}
    for key in set(base["syms"]) | set(var["syms"]):
        d = var["syms"].get(key, 0) - base["syms"].get(key, 0)
        if d:
            name, k = key.split("\t")
            tot[k] += d
            changed.append((name, k, d, d / delta_units))
    changed.sort(key=lambda r: (r[1] == "text", -abs(r[2])))
    secs = {s: var["secs"].get(s, 0) - base["secs"].get(s, 0) for s in SECTIONS}
    return {"symbols": [{"name": n, "class": k, "delta": d, "per_unit": pu}
                        for n, k, d, pu in changed],
            "sections": secs, "image_delta": sum(secs.values()),
            "ram_delta": tot["ram"], "ro_delta": tot["ro"], "text_delta": tot["text"],
            "section_ram_delta": secs[".data"] + secs[".bss"]}


def sweep(args):
    arch = args.arch
    base_cfg = args.base or os.path.join(REPO, BASE_CONFIG[arch])
    text = read_config(base_cfg)
    work = os.path.join(REPO, "target", "limits_cost", arch)
    os.makedirs(work, exist_ok=True)
    args.steps = args.steps.split(",")
    names = args.symbols or list(STEPS)
    bad = [n for n in names if n not in STEPS]
    if bad:
        raise SystemExit("limits_cost: not in STEPS: " + ", ".join(bad))

    def run(label, sym=None, value=None):
        t = text if sym is None else with_value(text, sym, value)
        path = os.path.join(work, label + ".config")
        with open(path, "w", encoding="utf-8") as f:
            f.write(t)
        elf, err, warns = build(arch, path)
        if elf is None:
            return None, err, warns
        return measure(elf), "", warns

    base, err, warns = run("base")
    if base is None:
        raise SystemExit("limits_cost: the base build fails: " + err)
    out = {"arch": arch, "base_config": os.path.relpath(base_cfg, REPO),
           "base_image": sum(base["secs"].values()), "base_secs": base["secs"],
           "base_warnings": warns, "options": {},
           "base_ram_symbols": {k.split("\t")[0]: v for k, v in sorted(
               base["syms"].items(), key=lambda kv: -kv[1])
               if k.endswith("\tram") and v >= 1024}}
    for sym in names:
        b = config_value(text, sym)
        entry = {"base": b, "steps": {}}
        for tag, v in zip(("small", "large"), STEPS[sym]):
            if v is None or tag not in args.steps:
                continue
            m, err, warns = run(f"{sym}-{v}", sym, v)
            if m is None:
                entry["steps"][tag] = {"value": v, "refused": err}
            else:
                r = diff(base, m, v - int(b))
                r["value"] = v
                r["warnings"] = warns
                entry["steps"][tag] = r
        out["options"][sym] = entry
        print_option(sym, entry, out["base_image"])
        sys.stdout.flush()
    dest = args.out or os.path.join(REPO, "target", "limits_cost", arch + ".json")
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print("wrote", dest)


def compare(args):
    """Build the base config and the base with several options changed at once."""
    arch = args.arch
    linker = big_linker(arch) if args.big_image else None
    base_cfg = args.base or os.path.join(REPO, BASE_CONFIG[arch])
    text = read_config(base_cfg)
    changes = {}
    for item in args.changes:
        sym, _, val = item.partition("=")
        changes[sym] = val
    var = text
    for sym, val in changes.items():
        var = with_value(var, sym, val)
    work = os.path.join(REPO, "target", "limits_cost", arch)
    os.makedirs(work, exist_ok=True)
    res = []
    for label, t in (("base", text), ("compare", var)):
        path = os.path.join(work, label + ".config")
        with open(path, "w", encoding="utf-8") as f:
            f.write(t)
        elf, err, warns = build(arch, path, linker)
        if elf is None:
            raise SystemExit(f"limits_cost: the {label} build fails: {err}")
        if warns:
            print(f"{label}: {len(warns)} warning(s): {warns[0]}")
        res.append(measure(elf))
    d = diff(res[0], res[1], 1)
    print(f"== {arch}: " + " ".join(f"{k}={config_value(text, k)}->{v}" for k, v in changes.items()))
    print(f"   RAM symbols {d['ram_delta']:+d} B, rodata {d['ro_delta']:+d} B, "
          f"text {d['text_delta']:+d} B; sections {d['sections']}")
    for s in [x for x in d["symbols"] if x["class"] != "text"][:args.top]:
        print(f"   {s['delta']:+12d}  {s['name']}")


def one_build(args):
    """Build one config (optionally with another linker script) and list the biggest tables."""
    cfg = os.path.abspath(args.config)
    linker = args.linker
    if args.big_image and not linker:
        linker = big_linker(args.arch)
    elf, err, warns = build(args.arch, cfg, linker)
    if elf is None:
        raise SystemExit("limits_cost: the build fails: " + err)
    m = measure(elf)
    total = sum(m["secs"].values())
    print(f"== {args.arch} {os.path.relpath(cfg, REPO)}: image {total} B "
          f"({total / 1048576:.2f} MiB) {m['secs']}; {len(warns)} warning(s)")
    ram = sorted(((k.split("\t")[0], v) for k, v in m["syms"].items() if k.endswith("\tram")),
                 key=lambda kv: -kv[1])
    for name, size in ram[:args.top]:
        print(f"   {size:>12,}  {name}")


def print_option(sym, entry, base_image, top=6):
    print(f"== {sym} (base {entry['base']})")
    for tag, r in entry["steps"].items():
        if "refused" in r:
            print(f"   {tag} step -> {r['value']}: REFUSED: {r['refused']}")
            continue
        n = int(r["value"]) - int(entry["base"])
        print(f"   {tag} step -> {r['value']}: RAM symbols {r['ram_delta']:+d} B "
              f"({r['ram_delta'] / n:+.2f} B/unit), rodata {r['ro_delta']:+d}, "
              f"text {r['text_delta']:+d}; sections .data+.bss {r['section_ram_delta']:+d}")
        for s in [x for x in r["symbols"] if x["class"] != "text"][:top]:
            print(f"      {s['delta']:+10d}  {s['per_unit']:+12.2f}/unit  {s['name']}")
        more = len([x for x in r["symbols"] if x["class"] != "text"]) - top
        if more > 0:
            print(f"      ... {more} more changed data symbols")


def report(args):
    for p in args.files:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        print(f"# {d['arch']} base {d['base_config']} image {d['base_image']} B")
        for sym, e in d["options"].items():
            print_option(sym, e, d["base_image"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sweep")
    s.add_argument("--arch", choices=("riscv64", "aarch64"), default="riscv64")
    s.add_argument("--base")
    s.add_argument("--out")
    s.add_argument("--steps", default="small,large",
                   help="which steps to build: small, large or small,large (default)")
    s.add_argument("symbols", nargs="*")
    s.set_defaults(fn=sweep)
    c = sub.add_parser("compare", help="build the base and the base with SYM=VALUE changes")
    c.add_argument("--arch", choices=("riscv64", "aarch64"), default="riscv64")
    c.add_argument("--base")
    c.add_argument("--top", type=int, default=30)
    c.add_argument("--big-image", action="store_true",
                   help="link with a 1022 MiB RAM region (fleet-sized images)")
    c.add_argument("changes", nargs="+", metavar="SYM=VALUE")
    c.set_defaults(fn=compare)
    b = sub.add_parser("build", help="build one config and list its largest tables")
    b.add_argument("--arch", choices=("riscv64", "aarch64"), default="riscv64")
    b.add_argument("--linker", help="linker script (default: the build's own)")
    b.add_argument("--big-image", action="store_true",
                   help="link with a 1022 MiB RAM region (fleet-sized images)")
    b.add_argument("--top", type=int, default=25)
    b.add_argument("config")
    b.set_defaults(fn=one_build)
    r = sub.add_parser("report")
    r.add_argument("files", nargs="+")
    r.set_defaults(fn=report)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
