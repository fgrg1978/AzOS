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
  gate_rows.py --ktap [LOG]
                         the gate's log (LOG or stdin) as a KTAP result stream
  gate_rows.py --dry-run [--tier n1|n2] [--match REGEX]
                         the rows the gate would run, as a KTAP plan; runs
                         nothing and starts no QEMU
  gate_rows.py --self-test
                         canaries for the two modes above

Result protocol (KTAP, as the Linux kernel's kselftest prints it): a
`KTAP version 1` line, the plan `1..N`, then one line per row,
  ok N - name                  the row passed
  not ok N - name # reason     the row failed; reason is the first detail line
  ok N - name # SKIP reason    the row was not run (tier, missing tool)
and a closing `# Totals: pass:P fail:F skip:S`. The exit status of --ktap is 1
when any row failed or the log holds no row. The gate prints
`  <label>...  ok|FAIL|skipped (..)|SKIP (..)` and `bash tools/ci_check.sh | tee
LOG; gate_rows.py --ktap LOG` converts it; the gate's own output is unchanged.

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

PAR_RE = re.compile(r"^\s*((?:[A-Z_][A-Z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)*)(par|par_row|host_job)\s+(.*)$")
FOR_RE = re.compile(r'^(\s*)for\s+(\w+)\s+in\s+([^;$`()]+?)\s*;\s*do\s*$')
ASSIGN_RE = re.compile(r'^\s*(\w+)=(?:"([^"$`]*)"|([\w.-]+))\s*$')
# `name=a; [ "$loopvar" = x ] && name=b`: a name derived from a loop variable.
DERIVE_RE = re.compile(r'^\s*(\w+)=([\w.-]+);\s*\[\s+"\$(\w+)"\s+=\s+([\w.-]+)\s+\]\s*&&\s*\1=([\w.-]+)\s*$')
IF_RE = re.compile(r'^(\s*)if\s+\[\s+"\$(\w+)"\s+(=|!=)\s+"?([\w.-]+)"?\s+\]\s*;\s*then\s*$')
VAR_RE = re.compile(r'\$\{(\w+)\}|\$(\w+)')
FN_RE = re.compile(r'^(\s*)([a-zA-Z_][a-zA-Z_0-9]*)\(\)\s*\{')

# Subsystem -> (key/function/feature regex, path globs). A row depends on the
# paths of every subsystem its key, function or features name.
SUBSYS = [
    ("net", r"network|dhcp|tcp|udp|\barp\b|link|nic\b|\bnet\b|net-|slirp|brain|tftp",
     "crates/net/** crates/drivers/net/** crates/drivers/virtio/**"),
    ("fs", r"\bfs\b|fat|crash log|pstore|boot count|storage|mmc|disk|volume|journal|seed",
     "crates/fs/** crates/drivers/block/** kernel/src/pstore.rs"),
    ("sched", r"sched|rt7|edf|cbs|pifast|portwait|preempt|timer|tick|idle|smp|deadline|\bpi\b|pi-|nr_cpus|nrcpus|percpu|cpuid",
     "crates/core/sched/** crates/core/percpu/** crates/core/sync/** kernel/src/tasks/** kernel/src/rt_smoke.rs"),
    ("ipc", r"ipc|port|ring|stream|channel|census",
     "crates/core/ipc/** crates/core/channel/** crates/core/rings/**"),
    ("mm", r"\bmm\b|mem|tlb|cow|w\^x|wx|mprot|guard|granule|huge|quota|fork|heap|slab|oom",
     "crates/core/mm/** crates/core/percpu/**"),
    ("user", r"userspace|abitest|ipctest|captest|\bsh\b|sh:|shell|busybox|seccomp|threads|orphan|zombie|exit|natfork|proc|abi|syscall|futex",
     "userspace/** crates/core/abi/** crates/core/syscall/** crates/core/libsys/** crates/core/shell/** sdk/targets/**"),
    ("drivers", r"driver|ina219|buzzer|gpio|i2c|uart|console|pci|rng|entropy|sensor|camera|virtio|ramfb|hdmi|irq|pl011|restart|supervis|placed",
     "crates/drivers/** kernel/src/drv_supervisor.rs kernel/src/console_mode.rs kernel/src/boot/launch.rs"),
    ("security", r"secure boot|secboot|topology|\bota\b|ota:|config|signed|seccomp|\bcap|toposign|key|tamper|crypto|spectre",
     "crates/core/topology/** crates/core/ota/** crates/core/crypto/** crates/core/config/** crates/core/azos-config/**"),
    ("safety", r"safety|e-stop|estop|watchdog|wdt|envelope|reflex|geofence|actuation|behavior|panic|safe mode",
     "crates/core/actuation/** domains/robot/** kernel/src/panic.rs kernel/src/behavior_*.rs"),
    ("lx", r"\blx\b|lx:|linux",
     "lx/** crates/core/lx-loader/** crates/core/linux-abi/** userspace/tests/lx* "
     "crates/core/syscall/src/linux.rs"),
    ("trace", r"trace|flight recorder", "crates/core/trace/** crates/core/rings/** kernel/src/lat_trace.rs"),
    ("energy", r"energy|power", "crates/core/energy/** crates/drivers/power/**"),
    ("ml", r"\bml\b|ml |ml-|gguf|mlsrv|infsrv|npu", "userspace/lib/ml/** userspace/services/infsrv/** crates/drivers/npu/**"),
    ("inspect", r"inspect|views",
     "crates/core/inspect/** userspace/lib/inspect/** kernel/src/boot/inspect*.rs crates/core/ipc/src/inspect_region.rs "
     "userspace/** crates/core/abi/** crates/core/libsys/** crates/core/topology/**"),
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


def split_tolerant(text):
    """shlex.split, keeping the words before a quote left open at the end of
    the line (a row's script argument is a multi-line string)."""
    lex = shlex.shlex(text, posix=True)
    lex.whitespace_split = True
    lex.commenters = ""
    toks = []
    while True:
        try:
            t = lex.get_token()
        except ValueError:
            return toks
        if t is None:
            return toks
        toks.append(t)


def _vars_in(*texts):
    return {a or b for t in texts for a, b in VAR_RE.findall(t)}


def _subst(text, env):
    return VAR_RE.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), text)


def _expansions(loops, derived, consts, used):
    """Every {var: value} binding of the loop variables (and the names derived
    from them) in `used`, one per iteration combination."""
    need = set(used)
    for v in list(need):
        if v in derived:
            need.add(derived[v][0])
    combos = [dict()]
    for v, vals in loops:
        if v in need:
            combos = [dict(c, **{v: x}) for c in combos for x in vals]
    for c in combos:
        for name, (src, table, default) in derived.items():
            if name in used and src in c:
                c[name] = table.get(c[src], default)
        for name, val in consts.items():
            c.setdefault(name, val)
    return combos


def called_bodies(body, fns):
    """The bodies of the gate functions `body` calls, transitively: a row
    whose function only calls the functions that boot QEMU (a group such as
    `aarch64_captest_group`) boots it all the same."""
    seen, todo, out = set(), [body], []
    while todo:
        text = todo.pop()
        for name in re.findall(r"^\s*([A-Za-z_]\w*)\b", text, re.M):
            if name in fns and name not in seen:
                seen.add(name)
                out.append(fns[name][2])
                todo.append(fns[name][2])
    return "\n".join(out)


def rows(text=None):
    """The gate's rows. A key built from a literal `for v in a b; do` loop
    variable (or a name derived from one) is expanded once per iteration, so
    the manifest names every label the gate prints; a key with any other
    shell variable is left out, as it cannot be known statically."""
    text = text if text is not None else open(GATE).read()
    fns = functions(text)
    current = {"rv": "qemu", "arm": "qemu"}  # the kernel a top-level row boots
    in_fn = set()
    for a, b, _ in fns.values():
        in_fn.update(range(a, b + 1))
    out = []
    loops, derived, consts = [], {}, {}  # loops: (indent, var, [values])
    conds = []  # open `if [ "$v" = x ]` blocks on a loop variable: [indent, v, op, x]
    for ln, line in joined_lines(text):
        f = FOR_RE.match(line)
        if f:
            loops.append((f.group(1), f.group(2), [w.strip("\"'") for w in f.group(3).split()]))
            continue
        im = IF_RE.match(line)
        if im and im.group(2) in {lp[1] for lp in loops} | set(derived):
            conds.append([im.group(1), im.group(2), im.group(3), im.group(4)])
            continue
        cm = re.match(r"^(\s*)(else|fi)\b", line)
        if cm and conds and conds[-1][0] == cm.group(1):
            if cm.group(2) == "fi":
                conds.pop()
            else:
                conds[-1][2] = "!=" if conds[-1][2] == "=" else "="
            continue
        d = re.match(r"^(\s*)done\b", line)
        if d:
            ind = d.group(1)
            while loops and len(loops[-1][0]) >= len(ind):
                loops.pop()
            while conds and len(conds[-1][0]) >= len(ind):
                conds.pop()
            continue
        dm = DERIVE_RE.match(line)
        if dm and any(lp[1] == dm.group(3) for lp in loops):
            prev = derived.get(dm.group(1))
            table = dict(prev[1]) if prev and prev[0] == dm.group(3) else {}
            table[dm.group(4)] = dm.group(5)
            derived[dm.group(1)] = (dm.group(3), table, dm.group(2))
            continue
        am = ASSIGN_RE.match(line)
        if am and not line.lstrip().startswith("#"):
            consts[am.group(1)] = am.group(2) if am.group(2) is not None else am.group(3)
            continue
        k = KB_RE.match(line)
        if k:
            current["arm" if k.group(1) == "a64_kbuild" else "rv"] = k.group(2) or "default"
        m = PAR_RE.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        env, verb, rest = m.group(1), m.group(2), m.group(3)
        toks = split_tolerant(rest.split(" #", 1)[0])
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
            used = _vars_in(key) | _vars_in(*args) | {c[1] for c in conds}
            variants, seen_keys = [], set()
            for env_v in _expansions([(v, vals) for _, v, vals in loops], derived, consts, used):
                k2 = _subst(key, env_v)
                if any((env_v.get(c[1]) == c[3]) != (c[2] == "=") for c in conds):
                    continue  # inside an `if` this iteration does not take
                if "$" not in k2 and k2 not in seen_keys:
                    seen_keys.add(k2)
                    variants.append((k2, [_subst(a, env_v) for a in args]))
        else:
            variants = [(key, args)]
        body = fns.get(fn, (0, 0, "")) if fn not in GENERIC else (0, 0, "")
        for key_i, args_i in variants:
            if fn == "kq" and args_i:
                prior = args_i[0]
            else:
                prior = current["arm" if fn == "a64_qemu_run" else "rv"]
            out.append({
                "prior": prior if fn in GENERIC else None,
                "key": key_i, "line": ln, "flags": flags, "fn": fn, "args": args_i,
                "env": env.strip(), "body": body[2], "range": (body[0], body[1]),
                "boots": called_bodies(body[2], fns),
                "in_fn": ln in in_fn,
                "template": key if key_i != key else None,
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
    # The gate spells the image `file=$AZOS_OUT/build/<name>`; the column shows `<name>`'s path under the root.
    return " ".join(sorted(set(re.findall(r"file=(?:\$AZOS_OUT/)?(build/[\w./-]+?)(?:,|\"|\s|$)", s)))) or "-"  # out-dir-lint: ok


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
    # A Linux-personality row drives one private boot through ushell_row's
    # fifo and gives it a wall-clock limit: those are the helper's mechanics
    # (its body is what the hazard patterns see), not the row's own hazards,
    # so such a row may run in `make check1` when the diff maps to it.
    if r["fn"] == "ushell_row" and r["key"].startswith("linux:"):
        own = hazards(dict(r, body=""))
        if not {"serial", "peer", "wallclock"} & set(own):
            return "n1"
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
    text = open(GATE).read()
    keys = {r["key"] for r in rows()}
    bad_label = 0
    for r in rows():
        # An expanded label is real only if the gate text holds the template
        # it came from (a literal one: the label itself).
        if ('"%s' % (r["template"] or r["key"])) not in text:
            print("gate_rows: row '%s' is not printed by tools/ci_check.sh" % r["key"])
            bad_label = 1
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
    return 1 if (missing or stale or bad or bad_label) else 0


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
    known = {r["key"] for r in rows(text)}
    for key, deps in read_needs().items():
        for k in [key] + deps:
            if k not in known and ('"%s' % k) not in text:
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


# ── KTAP result protocol ─────────────────────────────────────────────────────
#
# A row line of the gate's log: two spaces, the label, `...`, the verdict. The
# label is padded to 26 columns, so a longer one runs into the verdict. A
# failed row's detail lines are indented further (6 spaces).
VERDICT_RE = re.compile(r"^  (\S.*?)\.\.\.\s*(ok|FAIL|(?:skipped|SKIP)\b.*)$")
RESULTS_RE = re.compile(r"\[4/4\] Results: (\d+) passed, (\d+) failed(?:, (\d+) skipped)?")


def parse_gate_log(text):
    """[(status, name, reason)] in log order; status is ok, fail or skip.
    Also returns the gate's own (passed, failed, skipped) or None."""
    res, last, gate = [], None, None
    for line in text.splitlines():
        m = VERDICT_RE.match(line)
        if m:
            name, v = m.group(1), m.group(2)
            if v == "ok":
                last = ["ok", name, ""]
            elif v == "FAIL":
                last = ["fail", name, ""]
            else:
                why = v.split(None, 1)[1] if " " in v else ""
                last = ["skip", name, why.strip("()")]
            res.append(last)
            continue
        g = RESULTS_RE.search(line)
        if g:
            gate = (int(g.group(1)), int(g.group(2)), int(g.group(3) or 0))
        elif last and last[0] == "fail" and not last[2] and line.startswith("    ") and line.strip():
            last[2] = line.strip()
    return [tuple(r) for r in res], gate


def _one_line(s):
    return " ".join(s.split())


def ktap_lines(results, extra=()):
    """KTAP for [(status, name, reason)]; `extra` are diagnostic lines."""
    out = ["KTAP version 1", "1..%d" % len(results)]
    counts = {"ok": 0, "fail": 0, "skip": 0}
    for i, (st, name, why) in enumerate(results, 1):
        counts[st] += 1
        name, why = _one_line(name).replace("#", "\\#"), _one_line(why)
        if st == "ok":
            out.append("ok %d - %s" % (i, name))
        elif st == "fail":
            out.append("not ok %d - %s # %s" % (i, name, why or "no detail printed"))
        else:
            out.append("ok %d - %s # SKIP %s" % (i, name, why))
    out += list(extra)
    out.append("# Totals: pass:%d fail:%d skip:%d" % (counts["ok"], counts["fail"], counts["skip"]))
    return out


def ktap_check(lines):
    """Validate a KTAP stream: [] when well formed, else the problems."""
    bad = []
    if not lines or lines[0] != "KTAP version 1":
        bad.append("no 'KTAP version 1' header")
    plan = [l for l in lines if re.fullmatch(r"1\.\.\d+", l)]
    res = [l for l in lines if re.match(r"(not )?ok \d+ - ", l)]
    if len(plan) != 1:
        bad.append("%d plan lines" % len(plan))
    elif int(plan[0][3:]) != len(res):
        bad.append("plan %s but %d results" % (plan[0], len(res)))
    for i, l in enumerate(res, 1):
        if int(l.split()[2 if l.startswith("not") else 1]) != i:
            bad.append("result %d is numbered wrongly: %s" % (i, l))
            break
    tot = [l for l in lines if l.startswith("# Totals:")]
    if len(tot) != 1:
        bad.append("%d totals lines" % len(tot))
    else:
        nf = sum(l.startswith("not ok") for l in res)
        ns = sum("# SKIP" in l for l in res if l.startswith("ok"))
        if tot[0] != "# Totals: pass:%d fail:%d skip:%d" % (len(res) - nf - ns, nf, ns):
            bad.append("totals line disagrees with the results: %s" % tot[0])
    return bad


def ktap_from_log(text):
    results, gate = parse_gate_log(text)
    extra = []
    if gate:
        mine = (sum(r[0] == "ok" for r in results), sum(r[0] == "fail" for r in results),
                sum(r[0] == "skip" for r in results))
        note = "" if mine == gate else " (log rows: %d/%d/%d)" % mine
        extra.append("# gate says passed:%d failed:%d skipped:%d%s" % (gate + (note,)))
    return results, ktap_lines(results, extra)


def is_qemu_row(r):
    return r["fn"] in GENERIC or bool(QEMU_RE.search((r["body"] or "") + (r["boots"] or ""))) and "-h" not in r["flags"]


def dry_run(tier=None, match=None):
    """KTAP plan of the rows the gate would run: one result per distinct key
    (a skip: nothing runs), the reason naming the row's tier, ISA and kind."""
    man, seen, res, qemu = read_manifest(), set(), [], 0
    for r in rows():
        k = r["key"]
        if k in seen or (match and not re.search(match, k)):
            continue
        t = man.get(k, ("n2", ""))[0]
        if tier and t != tier:
            continue
        seen.add(k)
        q = is_qemu_row(r)
        qemu += q
        res.append(("skip", k, "dry-run: %s %s %s" % (t, isa_of(r), "qemu" if q else "host")))
    return res, ktap_lines(res, ["# would boot QEMU in %d of %d rows (this run boots none)" % (qemu, len(res))])


def self_test():
    bad = []

    def expect(what, ok):
        if not ok:
            bad.append(what)

    log = "\n".join([
        "  plain row...              ok",
        "  a label longer than twenty-six cols (x)...ok",
        "  broken: row...            FAIL",
        "      expected X, saw Y",
        "      second detail",
        "  tier row...               skipped (CI_TIER=rows)",
        "  no farm...                SKIP (cargo kani not installed: nothing was verified)",
        "  hash # in name...         ok",
        "[4/4] Results: 3 passed, 1 failed, 2 skipped (CI_TIER=rows; each is marked above)",
    ])
    res, lines = ktap_from_log(log)
    want = ["KTAP version 1", "1..6",
            "ok 1 - plain row",
            "ok 2 - a label longer than twenty-six cols (x)",
            "not ok 3 - broken: row # expected X, saw Y",
            "ok 4 - tier row # SKIP CI_TIER=rows",
            "ok 5 - no farm # SKIP cargo kani not installed: nothing was verified",
            "ok 6 - hash \\# in name",
            "# gate says passed:3 failed:1 skipped:2",
            "# Totals: pass:3 fail:1 skip:2"]
    expect("log -> KTAP lines: %r" % lines, lines == want)
    expect("well-formed stream rejected: %r" % ktap_check(lines), ktap_check(lines) == [])
    # Canaries: the validator and the parser must discriminate.
    expect("canary: truncated stream accepted", ktap_check(lines[:5]) != [])
    expect("canary: wrong plan accepted", ktap_check([lines[0], "1..9"] + lines[2:]) != [])
    expect("canary: renumbered result accepted",
           ktap_check([l.replace("ok 2 -", "ok 7 -") for l in lines]) != [])
    expect("canary: a FAIL parsed as ok", sum(r[0] == "fail" for r in res) == 1)
    expect("canary: empty log has rows", parse_gate_log("nothing here\n")[0] == [])

    # Every real label survives log -> KTAP, the Linux-personality ones included.
    keys = [r["key"] for r in rows()]
    uniq = list(dict.fromkeys(keys))
    lx = [k for k in uniq if re.search(r"\blx\b|lx:|linux", k)]
    expect("no lx/linux rows found", len(lx) > 0)
    synth = "\n".join("  %-26s%s" % (k + "...", "ok") for k in uniq)
    got = [r[1] for r in parse_gate_log(synth)[0]]
    expect("labels lost or mangled in the round trip: %r" % [k for k in uniq if k not in got][:5],
           got == [_one_line(k) for k in uniq])
    expect("lx rows not all parsed", all(k in got for k in lx))

    # The dry run lists every distinct key once and is a valid stream.
    res, lines = dry_run()
    expect("dry-run stream invalid: %r" % ktap_check(lines), ktap_check(lines) == [])
    expect("dry-run row count %d != distinct keys %d" % (len(res), len(uniq)), len(res) == len(uniq))
    expect("dry-run misses an lx row", all(any(k == r[1] for r in res) for k in lx))
    expect("canary: dry-run starts no row", all(r[0] == "skip" for r in res))
    t1, _ = dry_run(tier="n1")
    t2, _ = dry_run(tier="n2")
    expect("tier filters do not partition the rows", len(t1) + len(t2) == len(res) and len(t1) > 0 and len(t2) > 0)
    expect("canary: --match filters nothing", len(dry_run(match=r"\blx\b|lx:")[0]) < len(res))
    for b in bad:
        print("gate_rows self-test: FAIL " + b)
    if not bad:
        print("gate_rows self-test: ok (log parser, KTAP validator, %d rows dry-run, %d lx rows)" % (len(res), len(lx)))
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if "--ktap" in argv:
        i = argv.index("--ktap")
        src = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("--") else None
        results, lines = ktap_from_log(open(src, errors="replace").read() if src else sys.stdin.read())
        print("\n".join(lines))
        return 1 if not results or any(r[0] == "fail" for r in results) else 0
    if "--dry-run" in argv:
        opt = lambda f: argv[argv.index(f) + 1] if f in argv and argv.index(f) + 1 < len(argv) else None
        tier = opt("--tier")
        if tier not in (None, "n1", "n2"):
            print("gate_rows: --tier takes n1 or n2")
            return 2
        print("\n".join(dry_run(tier, opt("--match"))[1]))
        return 0
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
