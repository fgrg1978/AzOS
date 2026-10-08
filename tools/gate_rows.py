#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Inventory of the gate's rows (tools/ci_check.sh), read from the script.

Every `par` / `par_row` call is a row: its key, flags, the function it runs,
the call's line, the function body's line range, and what the body shows:
the kernel features it builds, the QEMU options it passes, and the hazards
that keep it out of a shared boot (a peer or fixed host port, a disk, a
network, fault injection, wall-clock judgement, more than one boot).

  gate_rows.py --write   regenerate tools/gate_rows.tsv (tier + deps per row),
                         keeping the tier and deps of rows already listed
  gate_rows.py --check   the manifest names exactly the gate's row keys
  gate_rows.py --groups  the boot-group table: rows that only grep one boot,
                         grouped by (ISA, features, QEMU options)
  gate_rows.py --icount  rows that boot under -icount (load-independent
                         candidates for GATE_JOBS above 4)
  gate_rows.py --needs   read row keys on stdin, print them and, after them,
                         every row they need (tools/gate_needs.tsv), transitively
  gate_rows.py --selfbuild rv|arm
                         rows whose own function builds that ISA's kernel
                         (kbuild/kq, a64_kbuild): under CI_TIER=rows the gate
                         does not build a deferred top-level kernel for them

The manifest is tools/gate_rows.tsv: `key<TAB>tier<TAB>deps`, where tier is
n1 (may run in `make check1` when the diff maps to it) or n2 (full gate only),
and deps is a space-separated list of path globs (tools/rows_for_diff.py).
"""

import os
import re
import shlex
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "tools", "ci_check.sh")
MANIFEST = os.path.join(ROOT, "tools", "gate_rows.tsv")
NEEDS = os.path.join(ROOT, "tools", "gate_needs.tsv")

PAR_RE = re.compile(r'^\s*((?:[A-Z_][A-Z0-9_]*=(?:"[^"]*"|\S*)\s+)*)(par|par_row|host_job)\s+(.*)$')
FN_RE = re.compile(r'^(\s*)([a-zA-Z_][a-zA-Z_0-9]*)\(\)\s*\{')

# Subsystem -> (key/function/feature regex, path globs). A row depends on the
# paths of every subsystem its key, function or features name.
SUBSYS = [
    ("net", r"network|dhcp|tcp|udp|\barp\b|link|nic\b|\bnet\b|net-|slirp|brain|tftp|rfc-0019",
     "crates/net/** crates/drivers/net/** crates/drivers/virtio/**"),
    ("fs", r"\bfs\b|fat|crash log|pstore|boot count|storage|mmc|disk|volume|journal|procfs|seed",
     "crates/fs/** crates/drivers/block/** crates/drivers/msc/** kernel/src/pstore.rs"),
    ("sched", r"sched|rt7|edf|cbs|pifast|portwait|lease|preempt|timer|tick|idle|smp|deadline|\bpi\b|pi-|nr_cpus|nrcpus|percpu|cpuid",
     "crates/core/sched/** crates/core/percpu/** crates/core/sync/** kernel/src/tasks/** kernel/src/rt_smoke.rs"),
    ("ipc", r"ipc|port|lease|ring|stream|pubsub|channel|census",
     "crates/core/ipc/** crates/core/channel/** crates/core/pubsub/** crates/core/spsc/** crates/core/service/**"),
    ("mm", r"\bmm\b|mem|tlb|cow|w\^x|wx|mprot|guard|granule|huge|quota|fork|heap|slab|oom",
     "crates/core/mm/** crates/core/percpu/**"),
    ("user", r"userspace|abitest|ipctest|captest|\bsh\b|sh:|shell|busybox|seccomp|threads|orphan|zombie|exit|natfork|proc|abi|syscall|futex",
     "userspace/** crates/core/abi/** crates/core/syscall/** crates/core/libsys/** crates/core/shell/**"),
    ("drivers", r"driver|ina219|buzzer|gpio|i2c|uart|console|pci|rng|entropy|sensor|camera|virtio|ramfb|hdmi|irq|pl011|restart|supervis|placed",
     "crates/drivers/** kernel/src/drv_supervisor.rs kernel/src/console_mode.rs"),
    ("security", r"secure boot|secboot|topology|\bota\b|ota:|config|signed|seccomp|\bcap|toposign|key|tamper|crypto|spectre",
     "crates/core/topology/** crates/core/ota/** crates/core/crypto/** crates/core/config/** crates/core/azos-config/**"),
    ("safety", r"safety|e-stop|estop|watchdog|wdt|envelope|reflex|geofence|actuation|behavior|panic|safe mode",
     "crates/core/actuation/** domains/robot/** kernel/src/panic.rs kernel/src/behavior_*.rs"),
    ("lx", r"\blx\b|lx:|linux", "lx/** crates/core/lx-loader/** crates/core/linux-abi/**"),
    ("trace", r"trace|flight recorder", "crates/core/trace/** kernel/src/lat_trace.rs"),
    ("energy", r"energy|power", "crates/core/energy/** crates/drivers/power/**"),
    ("ml", r"\bml\b|ml |ml-|gguf|mlsrv|npu", "crates/core/ml/** crates/drivers/npu/** kernel/src/mlsf_bench.rs"),
]
ARCH_DEPS = {
    "rv": "crates/core/arch-riscv64/** kernel/linker.ld kernel/src/entry/**",
    "arm": "crates/core/arch-aarch64/** kernel/linker-aarch64.ld kernel/src/entry/**",
}
# Classes that keep a row out of a shared boot, and the evidence for each.
HAZARDS = [
    ("peer", r"fake_brain|hostfwd|guestfwd|9000|peer|socket,|-s\b|gdb|ota_server|serve"),
    # A stock image (file=build/<x>.img, a private copy per boot) is part of
    # the group key, not a hazard; an image the row makes or edits is.
    ("disk", r"fresh_disk|make_disk|mcopy|mtools|dd if=|truncate|mkfs"),
    ("net", r"-netdev|virtio-net|-nic\b"),
    ("fault", r"canary|inject|panic|crash|kill|fault|reboot|reset|tamper|corrupt|watchdog|wdt|exhaust|storm"),
    ("wallclock", r"date \+%s|SECONDS|wall.?clock|-rtc|latbench|per second|/s\b"),
    ("stdin", r"fifo|exec 9>|printf .*>&9"),
]
QEMU_RE = re.compile(r'"\$QEMU"|qemu-system-|qemu_run|a64_qemu_run|entseed_boot|kq ')


def joined_lines(text):
    """(start line, logical line) with backslash continuations joined."""
    out, buf, start = [], "", None
    for i, line in enumerate(text.splitlines(), 1):
        if start is None:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append((start, buf + line))
        buf, start = "", None
    return out


def functions(text):
    """name -> (first line, last line, body)."""
    lines = text.splitlines()
    fns, i = {}, 0
    while i < len(lines):
        m = FN_RE.match(lines[i])
        if m and not lines[i].rstrip().endswith("}"):
            end = m.group(1) + "}"
            j = i + 1
            while j < len(lines) and not lines[j].startswith(end):
                j += 1
            fns[m.group(2)] = (i + 1, j + 1, "\n".join(lines[i:j + 1]))
        i += 1
    return fns


GENERIC = {"qemu_run", "a64_qemu_run", "kq"}
KB_RE = re.compile(r'^\s*(a64_kbuild|kbuild)\s+"([^"$]*)"')


def rows(text=None):
    text = text if text is not None else open(GATE).read()
    fns = functions(text)
    current = {"rv": "qemu", "arm": "qemu"}  # the kernel a top-level row boots
    in_fn = set()
    for a, b, _ in fns.values():
        in_fn.update(range(a, b + 1))
    out = []
    for ln, line in joined_lines(text):
        k = KB_RE.match(line)
        if k:
            current["arm" if k.group(1) == "a64_kbuild" else "rv"] = k.group(2) or "default"
        m = PAR_RE.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        env, verb, rest = m.group(1), m.group(2), m.group(3)
        try:
            toks = shlex.split(rest.split(" #", 1)[0])
        except ValueError:
            continue
        flags = []
        if verb == "host_job":
            if len(toks) < 2:
                continue
            key, fn, args, flags = toks[1], toks[0], toks[1:], ["-a", "-h"]
        else:
            while toks and toks[0].startswith("-") and len(toks[0]) == 2:
                f = toks.pop(0)
                if f == "-n" and toks:
                    f += " " + toks.pop(0)
                flags.append(f)
            if len(toks) < 2:
                continue
            if verb == "par_row":
                fn, key, args = toks[0], toks[1], toks[1:]
            else:
                key, fn, args = toks[0], toks[1], toks[2:]
        if "$" in key:
            continue  # a key built at run time (loop rows): not in the manifest
        body = fns.get(fn, (0, 0, "")) if fn not in GENERIC else (0, 0, "")
        if fn == "kq" and args:
            prior = args[0]
        else:
            prior = current["arm" if fn == "a64_qemu_run" else "rv"]
        out.append({
            "prior": prior if fn in GENERIC else None,
            "key": key, "line": ln, "flags": flags, "fn": fn, "args": args,
            "env": env.strip(), "body": body[2], "range": (body[0], body[1]),
            "in_fn": ln in in_fn,
        })
    return out


def isa_of(r):
    s = " ".join([r["key"], r["fn"]] + r["args"])
    if re.search(r"aarch64|\barm\b|\ba64\b|\(arm\)", s):
        return "arm"
    return "rv"


def features_of(r):
    feats = [a for a in r["args"] if re.fullmatch(r"[a-z0-9][a-z0-9,_-]*", a) and
             ("qemu" in a or "," in a or a.endswith(("-smoke", "-canary")))]
    if r["prior"]:
        feats.append(r["prior"])
    for m in re.finditer(r'(?:a64_kbuild|kbuild|kq)\s+"([^"$]*)"', r["body"]):
        feats.append(m.group(1))
    for m in re.finditer(r'--features\s+"?([a-z0-9,_-]+)', r["body"]):
        feats.append(m.group(1))
    return sorted(set(feats)) or ["qemu"]


def qemu_opts(r):
    s = " ".join(r["args"]) + "\n" + r["body"]
    opts = []
    for pat in (r"-smp\s+\"?(\d+)", r"-cpu\s+\"?([\w,=-]+)", r"-icount\s+\"?([\w,=-]+)",
                r"-m\s+\"?(\d+\w?)", r"virtualization=on", r"gic-version=\d"):
        m = re.search(pat, s)
        if m:
            opts.append(m.group(0).replace('"', ""))
    return " ".join(opts)


def disks_of(r):
    s = " ".join(r["args"]) + "\n" + r["body"]
    return " ".join(sorted(set(re.findall(r"file=(build/[\w./-]+?)(?:,|\"|\s|$)", s)))) or "-"


def hazards(r):
    head = " ".join([r["key"], r["fn"], r["env"]] + r["args"])
    s = head + "\n" + r["body"]
    # Fault injection is named by the row (its key, features, arguments); a
    # body's own panic/kill handling is how every row stops QEMU.
    hz = [name for name, pat in HAZARDS if re.search(pat, head if name == "fault" else s)]
    if any(f in ("-s", "-w") or f.startswith("-n") for f in r["flags"]):
        hz.append("serial")
    if len(QEMU_RE.findall(r["body"])) > 1:
        hz.append("multiboot")
    return hz


def deps_of(r):
    s = " ".join([r["key"], r["fn"]] + r["args"] + features_of(r)).lower()
    globs = []
    for _, pat, g in SUBSYS:
        if re.search(pat, s):
            globs += g.split()
    if not r["flags"] or "-a" not in r["flags"]:
        globs += ARCH_DEPS[isa_of(r)].split()
    return " ".join(dict.fromkeys(globs))


def tier_of(r):
    hz = hazards(r)
    if "serial" in hz or "peer" in hz or "wallclock" in hz:
        return "n2"
    return "n1"


def read_manifest():
    m = {}
    if os.path.exists(MANIFEST):
        for line in open(MANIFEST):
            if line.startswith("#") or not line.strip():
                continue
            p = line.rstrip("\n").split("\t")
            m[p[0]] = (p[1] if len(p) > 1 else "n2", p[2] if len(p) > 2 else "")
    return m


HEADER = """# Gate rows: key, tier, deps (tools/gate_rows.py --write keeps listed rows).
# tier n1: `make check1` may run the row when the diff touches one of its deps.
# tier n2: only the full gate (`make ci`) runs it. deps: space-separated globs.
"""


def write_manifest():
    old = read_manifest()
    seen, lines = set(), []
    for r in rows():
        if r["key"] in seen:
            continue
        seen.add(r["key"])
        tier, deps = old.get(r["key"], (tier_of(r), deps_of(r)))
        lines.append("%s\t%s\t%s\n" % (r["key"], tier, deps))
    with open(MANIFEST, "w") as f:
        f.write(HEADER)
        f.writelines(lines)
    return len(lines)


def check_manifest():
    keys = {r["key"] for r in rows()}
    man = read_manifest()
    missing = sorted(keys - set(man))
    stale = sorted(set(man) - keys)
    for k in missing:
        print("gate_rows: no manifest line for row '%s' (run tools/gate_rows.py --write)" % k)
    for k in stale:
        print("gate_rows: manifest names '%s', which no row uses" % k)
    bad = [k for k, (t, _) in man.items() if t not in ("n1", "n2")]
    for k in bad:
        print("gate_rows: row '%s' has tier '%s' (n1 or n2)" % (k, man[k][0]))
    return 1 if (missing or stale or bad) else 0


def read_needs():
    """tools/gate_needs.tsv: row key -> the keys it needs, in file order."""
    out = {}
    if os.path.exists(NEEDS):
        for line in open(NEEDS):
            if line.startswith("#") or not line.strip():
                continue
            key, _, rest = line.rstrip("\n").partition("\t")
            out.setdefault(key, []).extend(k.strip() for k in rest.split(";") if k.strip())
    return out


def needs_closure(keys):
    needs, out, seen = read_needs(), [], set()
    todo = list(keys)
    while todo:
        k = todo.pop(0)
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
        todo.extend(needs.get(k, []))
    return out


def check_needs(text=None):
    """Every key gate_needs.tsv names is a label the gate prints or keys."""
    text = text if text is not None else open(GATE).read()
    bad = 0
    for key, deps in read_needs().items():
        for k in [key] + deps:
            if ('"%s' % k) not in text:
                print("gate_rows: gate_needs.tsv names '%s', which tools/ci_check.sh never prints" % k)
                bad = 1
    return bad


def selfbuild(isa):
    pat = r"\b(kbuild|kq)\b" if isa == "rv" else r"\ba64_kbuild(_out)?\b"
    out = []
    for r in rows():
        if (isa == "rv" and r["fn"] == "kq") or re.search(pat, r["body"] or ""):
            if r["key"] not in out:
                out.append(r["key"])
    return out


def groups():
    table = {}
    total = 0
    for r in rows():
        if any(f == "-h" for f in r["flags"]):
            continue
        total += 1
        hz = hazards(r)
        if hz:
            continue
        g = (isa_of(r), ",".join(features_of(r)), (qemu_opts(r) or "-") + " " + disks_of(r))
        table.setdefault(g, []).append(r["key"])
    shared = {g: ks for g, ks in table.items() if len(ks) > 1}
    saved = sum(len(ks) - 1 for ks in shared.values())
    alone = sum(len(ks) for ks in table.values())
    print("# boot groups: rows with no hazard, same (isa, features, qemu options)")
    print("# QEMU rows %d, hazard-free %d, in groups of 2+ %d, boots saved %d (%d -> %d)"
          % (total, alone, sum(len(k) for k in shared.values()), saved, total, total - saved))
    for g, ks in sorted(shared.items(), key=lambda x: -len(x[1])):
        print("%s\t%s\t%s\t%d\t%s" % (g[0], g[1], g[2] or "-", len(ks), " | ".join(ks)))


def icount_rows():
    for r in rows():
        s = " ".join(r["args"]) + r["body"]
        if "icount" in s:
            print("%s\t%s" % (r["key"], ",".join(hazards(r)) or "-"))


def main(argv):
    if "--write" in argv:
        print("gate_rows: %d rows written to %s" % (write_manifest(), MANIFEST))
        return 0
    if "--check" in argv:
        return check_manifest() | check_needs()
    if "--selfbuild" in argv:
        for k in selfbuild(argv[argv.index("--selfbuild") + 1]):
            print(k)
        return 0
    if "--needs" in argv:
        keys = [l.rstrip("\n") for l in sys.stdin if l.strip()]
        for k in needs_closure(keys):
            print(k)
        return 0
    if "--groups" in argv:
        groups()
        return 0
    if "--icount" in argv:
        icount_rows()
        return 0
    for r in rows():
        print("%d\t%s\t%s\t%s\t%s" % (r["line"], r["key"], " ".join(r["flags"]) or "-",
                                      r["fn"], ",".join(hazards(r)) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
