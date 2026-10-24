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
                         keeping the tier and deps of rows already listed and
                         adding the sources each row demonstrably reads
                         (required_deps: its suite, scripts, fixtures, image,
                         features, markers)
  gate_rows.py --check   the manifest names exactly the gate's row keys,
                         every QEMU row whose deps name the robot domain
                         builds a robot kernel (its features close over
                         `use-robot`), and every row's deps cover what it
                         demonstrably reads (--check-deps)
  gate_rows.py --check-deps
                         that last check alone: one line per row and source
                         its deps miss, with the rule that found it
  gate_rows.py --robot-features
                         the kernel features whose closure in kernel/Cargo.toml
                         names `use-robot`: the gate builds a kernel that asks
                         for one from the robot cell, every other from the
                         generic one (tools/ci_check.sh, ci_robot_feats)
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
                         canaries for the two modes above and for each
                         required-deps rule

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
    ("ml", r"\bml\b|ml |ml-|gguf|mlsrv|infsrv", "userspace/lib/ml/** userspace/services/infsrv/**"),
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


HEADER = """# Gate rows: key, tier, deps (tools/gate_rows.py --write keeps listed rows, and
# adds the sources a row demonstrably reads: gate_rows.py required_deps).
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
        # A listed row keeps its globs, hand-written ones included; what the
        # row demonstrably reads and they miss is added after them (and its
        # markers' files, see required_deps).
        globs = deps.split()
        globs += sorted(g for g, (cause, _) in required_deps(r).items()
                        if g not in globs and (cause == "marker" or not glob_covered(g, globs)))
        lines.append("%s\t%s\t%s\n" % (r["key"], tier, " ".join(globs)))
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


CARGO_TOML = os.path.join(ROOT, "kernel", "Cargo.toml")
# A row that depends on the robot domain (its deps name these): the gate runs
# it on the robot cell, so its kernel features must close over `use-robot`.
ROBOT_DEPS = ("domains/robot/", "config/domains/Kconfig.robot", "config/domains/Kconfig.brain")


def cargo_features(path):
    """The [features] table of a Cargo.toml: name -> list of entries. tomllib
    where the Python has it (3.11+); else the table's own shape, `name = [
    "a", "b" ]` over one or more lines, which is all kernel/Cargo.toml writes
    there (the gate's python3 may be the system 3.9)."""
    try:
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)["features"]
    except ImportError:
        pass
    features, cur, buf, inside = {}, None, "", False
    for line in open(path, encoding="utf-8"):
        s = line.split("#", 1)[0].strip()
        if cur is None and s.startswith("[") and s.endswith("]"):
            inside = s == "[features]"
            continue
        if not inside or not s:
            continue
        if cur is None:
            m = re.match(r'^"?([A-Za-z0-9_.-]+)"?\s*=\s*(.*)$', s)
            if not m:
                continue
            cur, buf = m.group(1), m.group(2)
        else:
            buf += " " + s
        if "]" in buf:
            features[cur] = re.findall(r'"([^"]*)"', buf)
            cur, buf = None, ""
    return features


def robot_features(features=None):
    """The kernel features whose closure (kernel/Cargo.toml [features], through
    the kernel's own features only) contains `use-robot`."""
    if features is None:
        features = cargo_features(CARGO_TOML)
    memo = {}

    def robot(f, seen=()):
        if f in memo:
            return memo[f]
        if f == "use-robot":
            return True
        if f not in features or f in seen:
            return False
        r = any(robot(x, seen + (f,)) for x in features[f] if "/" not in x and not x.startswith("dep:"))
        memo[f] = r
        return r
    return sorted(f for f in features if robot(f))


FEATS_STR_RE = re.compile(r'"([a-z0-9_/,-]*[a-z0-9]),?(?:\$\w+|\$\{\w+\})?"')


def row_features(r):
    """Every feature a row's build may name: what features_of reads, the quoted
    feature lists in its body and arguments (a `feats=` local, an argument passed
    on), and the gate's KTEST_FEATS* lists where the body names them."""
    out = {f for fs in features_of(r) for f in fs.split(",")}
    text = r["body"] + " " + " ".join(r["args"])
    for m in FEATS_STR_RE.finditer(text):
        out |= set(m.group(1).split(","))
    gate = _gate_text()
    for v in set(re.findall(r"\$\{?(KTEST_FEATS\w*)", text)):
        for m in re.finditer(r"^\s*%s=\"([a-z0-9_/,-]+)\"" % v, gate, re.M):
            out |= set(m.group(1).split(","))
    return {f for f in out if f}


_GATE_TEXT = None


def _gate_text():
    global _GATE_TEXT
    if _GATE_TEXT is None:
        _GATE_TEXT = open(GATE).read()
    return _GATE_TEXT


def check_robot_rows(rs=None, man=None, robot=None):
    """Every QEMU row whose deps name the robot domain builds with a feature
    that closes over `use-robot`, so the gate runs it on the robot cell."""
    rs = rs if rs is not None else rows()
    man = man if man is not None else read_manifest()
    robot = set(robot if robot is not None else robot_features())
    bad = []
    seen = set()
    for r in rs:
        if r["key"] in seen or not is_qemu_row(r):
            continue
        seen.add(r["key"])
        deps = man.get(r["key"], ("", ""))[1]
        if not any(d in deps for d in ROBOT_DEPS):
            continue
        if not row_features(r) & robot:
            bad.append(r["key"])
    for k in bad:
        print("gate_rows: row '%s' depends on the robot domain but builds no robot kernel "
              "(add `use-robot` to its features)" % k)
    return 1 if bad else 0


# ── Required deps: the sources a row demonstrably reads ──────────────────────
#
# The SUBSYS tags above are a guess from a row's name. These rules are read
# from what the row runs, and `--check` fails when a row's manifest deps miss
# one (`--write` adds them, and keeps every hand-written glob):
#   crate    a host suite the row runs (host_canary_row's suite, a crate dir
#            the row names): the suite and every crate it reaches through
#            `path =` and `workspace = true` dependencies, and the files its
#            sources pull in with `#[path]` / `include!`;
#   script   a tools/ file the row runs, and the tools/ modules a Python one
#            imports;
#   fixture  any other repository path the row names;
#   image    the disk image the row boots: the ring-3 programs the image's own
#            rule adds (its autorun ELF, the ELFs it lists, those of the image
#            it copies), with their userspace/ libraries. Not their kernel-side
#            crates (abi, libsys, rings): every boot reads those, and the
#            subsystem tags already name them;
#   feature  a kernel feature the row builds, beyond the base (`qemu`) every
#            gate kernel builds: the optional crates it turns on (`dep:x`, or
#            `x/f` for an optional `x`) and, for a test hook (a feature named
#            `*-smoke`, `*-canary`, `*-test` or `ktest`), the files whose cfg
#            names it, but not a registry (a main.rs, mod.rs or lib.rs whose
#            cfg names HUB_FEATURES hooks or more: kernel/src/main.rs and
#            kernel/src/smokes/mod.rs dispatch the smokes, the code is
#            elsewhere). A canary's plant in shared code (fat32.rs, 40 hooks)
#            is the canary, and counts;
#   marker   a quoted string the row waits for or greps (in its call, or in
#            the body of a function at most MARKER_FN_ROWS rows run), printed
#            by at most MARKER_MAX_SOURCES source files: those files. `--write`
#            names them even under a dir glob that already covers them:
#            tools/rows_for_diff.py ranks a row by its most specific glob, so
#            the row that reads a file's output outranks the rows that only
#            build its crate (the bench row and domains/robot/bench).
# A path the row only names as the prefix of a shell expansion
# (`config/defconfigs/$cell.config`) is no dependency. Comment lines are not
# read. A function at least SHARED_FN_ROWS rows reach (kbuild, make_disk, ...)
# is the gate's infrastructure, not one row's: its paths are not counted.
SHARED_FN_ROWS = 100
MARKER_FN_ROWS = 3
MARKER_MAX_SOURCES = 3
HUB_FEATURES = 8
REGISTRY_FILES = ("main.rs", "mod.rs", "lib.rs")
TEST_HOOK_RE = re.compile(r"(-smoke|-canary|-test)$|^ktest$")
SRC_ROOTS = ("kernel/", "crates/", "domains/", "userspace/", "lx/", "micro/", "sdk/")
PATH_RE = re.compile(r"(?<![\w.$/-])(?:\$\{?REPO_ROOT\}?/)?((?:tools|tests|userspace|crates|domains|kernel|config|lx"
                     r"|sdk|micro|formal|Documentation)/[\w.+-]+(?:/[\w.+-]+)*)")
IMG_RE = re.compile(r"\b(disk[\w-]*)\.img\b")
STR_RE = re.compile(r'"((?:[^"\\$`]|\\.)*)"|\'([^\']*)\'')
WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
DEP_SEC_RE = re.compile(r"^\[(?:target\.[^\]]*\.)?(?:dev-|build-)?dependencies(?:\.([\w-]+))?\]$")
INCLUDE_RE = re.compile(r'#\[path\s*=\s*"([^"]+)"\]|include(?:_str|_bytes)?!\(\s*"([^"]+)"')

_REPO = {}


def _cached(name, build):
    if name not in _REPO:
        _REPO[name] = build()
    return _REPO[name]


def _read(rel):
    try:
        with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def repo_files():
    """Tracked and untracked (not ignored) files, third_party/ left out."""
    def build():
        import subprocess
        out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT,
                             capture_output=True, text=True).stdout.splitlines()
        if not out:
            for d, subs, fs in os.walk(ROOT):
                subs[:] = [s for s in subs if not s.startswith(".") and s not in ("target", "third_party")]
                out += [os.path.relpath(os.path.join(d, f), ROOT) for f in fs]
        files = sorted(f for f in out if f and not f.startswith("third_party/"))
        dirs = set()
        for f in files:
            d = os.path.dirname(f)
            while d and d not in dirs:
                dirs.add(d)
                d = os.path.dirname(d)
        crates = {os.path.dirname(f) for f in files if os.path.basename(f) == "Cargo.toml"} - {""}
        return files, set(files), dirs, crates
    return _cached("files", build)


def owning_crate(path):
    crates = repo_files()[3]
    d = os.path.dirname(path)
    while d and d not in crates:
        d = os.path.dirname(d)
    return d or None


def toml_deps(path):
    """[name, path or None, workspace?, optional?] per dependency of a
    Cargo.toml, every dependency table included (dev, build, target)."""
    out, sec, table = [], False, None
    for line in _read(path).splitlines():
        s = line.split("#", 1)[0].strip()
        if s.startswith("["):
            m = DEP_SEC_RE.match(s)
            sec, table = bool(m), (m.group(1) if m else None)
            if table:
                out.append([table, None, False, False])
            continue
        if not sec or not s:
            continue
        if table:
            p = re.match(r'path\s*=\s*"([^"]+)"', s)
            if p:
                out[-1][1] = p.group(1)
            out[-1][2] |= bool(re.match(r"workspace\s*=\s*true", s))
            out[-1][3] |= bool(re.match(r"optional\s*=\s*true", s))
            continue
        m = re.match(r'^"?([\w-]+)"?(\.workspace)?\s*=\s*(.*)$', s)
        if m:
            rest = m.group(3)
            p = re.search(r'path\s*=\s*"([^"]+)"', rest)
            out.append([m.group(1), p.group(1) if p else None,
                        bool(m.group(2)) or bool(re.search(r"workspace\s*=\s*true", rest)),
                        bool(re.search(r"optional\s*=\s*true", rest))])
    return out


def _workspace_paths():
    def build():
        t, sec = {}, False
        for line in _read("Cargo.toml").splitlines():
            s = line.split("#", 1)[0].strip()
            if s.startswith("["):
                sec = s == "[workspace.dependencies]"
            elif sec:
                m = re.match(r'^"?([\w-]+)"?\s*=\s*\{.*\bpath\s*=\s*"([^"]+)"', s)
                if m:
                    t[m.group(1)] = os.path.normpath(m.group(2))
        return t
    return _cached("ws", build)


def dep_dir(crate, name, path, ws):
    """The repository dir of one dependency of `crate`, or None (crates.io,
    vendored, outside the tree)."""
    if path:
        q = os.path.normpath(os.path.join(crate, path))
    elif ws:
        q = _workspace_paths().get(name)
    else:
        return None
    if not q or q.startswith("..") or q.startswith("third_party"):
        return None
    return q


def crate_graph():
    """crate dir -> the crate dirs it depends on, and `file:<path>` for a
    file its sources pull in from outside it (`#[path]`, `include!`)."""
    def build():
        files, fileset, _, crates = repo_files()
        by_crate = {}
        for f in files:
            if f.endswith(".rs"):
                by_crate.setdefault(owning_crate(f), []).append(f)
        graph = {}
        for c in sorted(crates):
            deps = {d for d in (dep_dir(c, n, p, w) for n, p, w, _ in toml_deps(c + "/Cargo.toml")) if d}
            for f in by_crate.get(c, ()):
                for m in INCLUDE_RE.finditer(_read(f)):
                    q = os.path.normpath(os.path.join(os.path.dirname(f), m.group(1) or m.group(2)))
                    if q in fileset and not q.startswith(c + "/"):
                        deps.add("file:" + q)
            graph[c] = deps
        return graph
    return _cached("graph", build)


def crate_closure(crate):
    return _cached("closure:" + crate, lambda: _closure(crate))


def _closure(crate):
    graph, out, todo = crate_graph(), set(), [crate]
    while todo:
        x = todo.pop()
        if x not in out:
            out.add(x)
            if not x.startswith("file:"):
                todo.extend(graph.get(x, ()))
    return out


def _closure_globs(crate, only=None):
    return [x[5:] if x.startswith("file:") else x + "/**" for x in sorted(crate_closure(crate))
            if only is None or x.replace("file:", "").startswith(only)]


def image_programs():
    """disk image stem (`disk-uhello`) -> the ring-3 program dirs its own
    rule in mk/images.mk adds, and the image stems it is copied from."""
    def build():
        images = _read("mk/images.mk").replace("$(AARCH64_PG_SUFFIX)", "")
        dirs = dict(re.findall(r"^(\w+)_DIR\s*:=\s*(\S+)", _read("mk/vars.mk"), re.M))
        on_disk = {}
        for v, name in re.findall(r"\$\((\w+?)_ELF(?:_AARCH64|_X86_64|_BOARD)?\)\s+::(\w+)\.ELF", images):
            on_disk.setdefault(name, v)

        def var_dir(v):
            return dirs.get(re.sub(r"_ELFS?(?:_AARCH64|_X86_64|_BOARD|_RISCV64)?$", "", v))
        progs, bases = {}, {}
        for stem, elf in re.findall(r"^\$\(OUT_BUILD\)/(disk[\w-]*)\.img:\s+AUTORUN_ELF\w*\s*:=\s*/fat/(\w+)\.ELF",
                                    images, re.M):
            d = var_dir(on_disk[elf]) if elf in on_disk else None
            if d:
                progs.setdefault(stem, set()).add(d)
        for _, line in joined_lines(images):
            m = re.match(r"^\$\(OUT_BUILD\)/(disk[\w-]*)\.img:([^=]*)$", line)
            if m:
                for v in re.findall(r"\$\((\w+_ELFS?(?:_AARCH64|_X86_64)?)\)", m.group(2)):
                    if var_dir(v):
                        progs.setdefault(m.group(1), set()).add(var_dir(v))
                bases.setdefault(m.group(1), set()).update(
                    re.findall(r"\$\(OUT_BUILD\)/(disk[\w-]*)\.img", m.group(2)))
        return progs, bases
    return _cached("images", build)


def image_dirs(stem, seen=()):
    progs, bases = image_programs()
    out = set(progs.get(stem, ()))
    for b in bases.get(stem, ()):
        if b not in seen and b != stem:
            out |= image_dirs(b, seen + (stem,))
    return out


def _sources():
    """Product sources (path -> text) and a word index over them, for markers
    and cfg(feature) lookups."""
    def build():
        src = {}
        for f in repo_files()[0]:
            if f.startswith(SRC_ROOTS) and f.endswith((".rs", ".c", ".h", ".S")):
                src[f] = _read(f)
        index = {}
        for f, t in src.items():
            for w in set(WORD_RE.findall(t)):
                index.setdefault(w, set()).add(f)
        feat_files = {}
        for f, t in src.items():
            if 'feature' in t:
                c = owning_crate(f)
                for feat in set(re.findall(r'feature\s*=\s*"([\w-]+)"', t)):
                    feat_files.setdefault((c, feat), set()).add(f)
        return src, index, feat_files
    return _cached("src", build)


def producers(marker):
    """The source files that hold a marker's longest literal run (10 chars or
    more; a regex's specials, digits and shell expansions split it), or
    None when more than MARKER_MAX_SOURCES do (a common string marks no
    one source)."""
    frag = max(re.split(r"\$\{[^}]*\}|\$\w+|\\.|[\[\](){}|*+?^$.0-9\"']", marker), key=len, default="").strip()
    return _cached("marker:" + frag, lambda: _producers(frag)), frag


def _producers(frag):
    words = WORD_RE.findall(frag)
    if len(frag) < 10 or not words:
        return []
    src, index, _ = _sources()
    cand = None
    for w in sorted(words, key=lambda w: len(index.get(w, ()))):
        cand = index.get(w, set()) if cand is None else cand & index.get(w, set())
        if len(cand) <= 2 * MARKER_MAX_SOURCES:
            break
    hits = []
    for f in sorted(cand):
        if frag in src[f]:
            hits.append(f)
            if len(hits) > MARKER_MAX_SOURCES:
                return None
    return hits


def _kernel():
    def build():
        feats = cargo_features(CARGO_TOML)
        deps, optional = {}, set()
        for n, p, w, opt in toml_deps("kernel/Cargo.toml"):
            d = dep_dir("kernel", n, p, w)
            if d:
                deps[n] = d
                if opt:
                    optional.add(n)
        base, todo = set(), ["qemu"]
        while todo:
            f = todo.pop()
            if f in feats and f not in base:
                base.add(f)
                todo += [e for e in feats[f] if "/" not in e and not e.startswith("dep:")]
        return feats, deps, optional, base
    return _cached("kernel", build)


def feature_deps(features):
    """{glob: why} for the kernel features a row builds (see above)."""
    feats, deps, optional, base = _kernel()
    feat_files = _sources()[2]

    def count_hooks():
        n = {}
        for (_, f), files in feat_files.items():
            if TEST_HOOK_RE.search(f):
                for x in files:
                    n[x] = n.get(x, 0) + 1
        return n
    hooks_of = _cached("hooks", count_hooks)
    out, seen = {}, set()

    def hook_files(crate, f, why):
        if TEST_HOOK_RE.search(f):
            for x in sorted(feat_files.get((crate, f), ())):
                if hooks_of.get(x, 0) < HUB_FEATURES or os.path.basename(x) not in REGISTRY_FILES:
                    out.setdefault(x, why)

    todo = [f for f in features if f in feats and f not in base]
    while todo:
        f = todo.pop(0)
        if f in seen:
            continue
        seen.add(f)
        hook_files("kernel", f, "feature " + f)
        for e in feats[f]:
            if e.startswith("dep:"):
                if e[4:] in deps:
                    out.setdefault(deps[e[4:]] + "/**", "feature %s turns on %s" % (f, e[4:]))
            elif "/" in e:
                name, sub = e.split("/", 1)
                weak = name.endswith("?")
                name = name.rstrip("?")
                if name not in deps:
                    continue
                if name in optional and not weak:
                    out.setdefault(deps[name] + "/**", "feature %s turns on %s" % (f, name))
                hook_files(deps[name], sub, "feature %s (%s)" % (f, e))
            elif e in feats:
                if e not in base:
                    todo.append(e)
            elif e in optional:  # an optional dependency's implicit feature
                out.setdefault(deps[e] + "/**", "feature %s turns on %s" % (f, e))
    return out


def _fn_fan():
    """gate function -> how many rows reach it (their own function included)."""
    def build():
        text = _gate_text()
        fns = functions(text)
        reach = {}
        call_re = re.compile(r"(?:^|[;&|(]|\bthen|\bdo|\belse)\s*([A-Za-z_]\w*)\b", re.M)
        for name, (_, _, body) in fns.items():
            seen, todo = [], [name]
            while todo:
                for c in call_re.findall(_code(fns[todo.pop()][2])):
                    if c in fns and c not in seen and c != name:
                        seen.append(c)
                        todo.append(c)
            reach[name] = seen
        fan = {}
        for r in rows(text):
            for f in set(reach.get(r["fn"], [])) | {r["fn"]}:
                fan[f] = fan.get(f, 0) + 1
        return fns, reach, fan
    return _cached("fan", build)


def _strip_comment(line):
    """A shell line without its comment (a `#` that starts a word outside
    quotes)."""
    quote, prev = None, " "
    for i, ch in enumerate(line):
        if quote:
            if ch == quote and (quote == "'" or prev != "\\"):
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and prev in " \t;":
            return line[:i]
        prev = ch
    return line


def _code(text):
    return "\n".join(_strip_comment(l) for l in text.splitlines() if not l.lstrip().startswith("#"))


def call_text(line):
    """The whole `par`/`par_row` call that starts at gate line `line`, its
    multi-line quoted arguments (a shell script, markers) included."""
    lines = _cached("gate_lines", lambda: _gate_text().splitlines())
    buf = ""
    for i in range(line - 1, min(line + 400, len(lines))):
        buf += lines[i] + "\n"
        if lines[i].endswith("\\"):
            continue
        try:
            shlex.split(buf.replace("\\\n", " "))
            return _code(buf)
        except ValueError:
            continue
    return lines[line - 1]


def _script_imports(path):
    out = []
    for m in re.finditer(r"^\s*(?:from\s+(\w+)\s+import|import\s+(\w+))", _read(path), re.M):
        mod = "tools/%s.py" % (m.group(1) or m.group(2))
        if mod in repo_files()[1] and mod != path:
            out.append(mod)
    return out


def _path_globs(p):
    """The globs a repository path the row names stands for: a crate, its
    closure; a Python tool, itself and the tools/ modules it imports."""
    _, fileset, dirs, crates = repo_files()
    if p in crates:
        return _closure_globs(p)
    if p in fileset:
        return [p] + (_script_imports(p) if p.startswith("tools/") and p.endswith(".py") else [])
    if p in dirs:
        return [p + "/**"]
    return []


def required_deps(r):
    """{glob: (cause, why)}: the sources the row demonstrably reads (the rules
    above), whatever its manifest line says."""
    fns, reach, fan = _fn_fan()
    call = r["call"] if "call" in r else call_text(r["line"])
    own = _code(r["body"] or "")
    called = "\n".join(_code(fns[f][2]) for f in reach.get(r["fn"], [])
                       if f in fns and fan.get(f, 0) < SHARED_FN_ROWS)
    text = "\n".join((call, own, called))
    req = {}

    def add(globs, cause, why):
        for x in globs:
            req.setdefault(x, (cause, why))
    if r["fn"] == "host_canary_row" and len(r["args"]) > 1:
        suite = r["args"][1] if "/" in r["args"][1] else "tests/host/" + r["args"][1]
        add(_path_globs(suite), "crate", "suite " + suite)
    for m in PATH_RE.finditer(text):
        p, nxt = m.group(1), text[m.end():m.end() + 2]
        if nxt[:1] in ("$", "{") or nxt == "/$":
            continue  # the prefix of a shell expansion
        p = p.rstrip(".")
        cause = "crate" if p in repo_files()[3] else "script" if p.startswith("tools/") else "fixture"
        add(_path_globs(p), cause, p)
    for stem in IMG_RE.findall(text):
        for d in sorted(image_dirs(stem)):
            add(_closure_globs(d, only="userspace/"), "image", stem + ".img")
    for x, why in feature_deps(sorted(row_features(r))).items():
        add([x], "feature", why)
    lits = [a or b for a, b in STR_RE.findall(call)]
    if r["fn"] in fns and fan.get(r["fn"], 0) <= MARKER_FN_ROWS:
        lits += [a or b for a, b in STR_RE.findall(own)]
    for s in lits:
        hits, frag = producers(s)
        if hits:
            add(hits, "marker", "'%s'" % frag)
    return req


def glob_covered(glob, deps):
    """A required glob is covered when a manifest glob matches it: a dir glob
    (`a/b/**`) by itself or a dir glob above it, a file by any glob that
    matches the file (tools/rows_for_diff.py's rule)."""
    if glob.endswith("/**"):
        d = glob[:-3]
        return any(x.endswith("/**") and (d == x[:-3] or d.startswith(x[:-3] + "/")) for x in deps)
    import fnmatch
    return any(fnmatch.fnmatch(glob, x) or (x.endswith("/**") and glob.startswith(x[:-2])) for x in deps)


def missing_deps(r, deps):
    return {g: v for g, v in required_deps(r).items() if not glob_covered(g, deps)}


def check_deps(rs=None, man=None, quiet=False):
    """Every row's manifest deps cover the sources it demonstrably reads."""
    rs = rs if rs is not None else rows()
    man = man if man is not None else read_manifest()
    bad, seen = 0, set()
    for r in rs:
        if r["key"] in seen:
            continue
        seen.add(r["key"])
        miss = missing_deps(r, man.get(r["key"], ("n2", ""))[1].split())
        for g, (cause, why) in sorted(miss.items()):
            if not quiet:
                print("gate_rows: row '%s' reads %s (%s: %s), not in its deps "
                      "(tools/gate_rows.py --write adds it)" % (r["key"], g, cause, why))
        bad |= bool(miss)
    return 1 if bad else 0


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


def tier_lints_check(text=None):
    """tools/gate_tier.sh's lints (`make check0`, and so the full gate's "n0
    lints" row) run this tool's --check after its --self-test."""
    text = _read("tools/gate_tier.sh") if text is None else text
    units = re.findall(r'^\[ "\$lints" = 1 \] &&.*$|^if \[ "\$lints" = 1 \]; then\n(?:.*\n)*?fi$', text, re.M)
    return any(re.search(r"gate_rows\.py --self-test.*gate_rows\.py --check\b", u, re.S) for u in units)


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
    # Robot rows: the closure follows features through features, and the
    # invariant flags a robot-domain row whose kernel would be generic.
    toy = {"use-robot": [], "a": ["use-robot"], "b": ["a"], "c": ["azos_x/use-robot"], "d": []}
    expect("robot closure %r" % robot_features(toy), robot_features(toy) == ["a", "b", "use-robot"])
    row = dict(key="r", fn="f", args=[], body='kbuild "qemu,d"', prior=None, flags=[], boots="qemu-system-riscv64")
    man = {"r": ("n2", "domains/robot/**")}
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        expect("canary: a robot-domain row with a generic kernel passes",
               check_robot_rows([row], man, ["a", "use-robot"]) == 1)
        expect("a robot-domain row with a robot kernel fails",
               check_robot_rows([dict(row, body='kbuild "qemu,a"')], man, ["a", "use-robot"]) == 0)
    # Required deps: one synthetic row per rule. A row whose manifest line
    # misses what it reads fails the check; with the globs written, it passes.
    syn = dict(key="syn", fn="syn_row", args=["syn"], body="", prior=None, flags=[], boots="", call="")
    fixture = "tests/host/dtb-tests/fixtures/qemu-raspi3b.dtb"
    cases = [
        ("fixture", dict(syn, body='dtb="${REPO_ROOT}/%s"' % fixture), fixture),
        ("script", dict(syn, body="python3 tools/fake_brain.py --serve"), "tools/fake_brain.py"),
        ("suite", dict(syn, fn="host_canary_row", args=["syn", "tls-tests", "canary-no-pin", "t"]),
         "tests/host/tls-tests/**"),
        ("suite closure", dict(syn, fn="host_canary_row", args=["syn", "tls-tests", "canary-no-pin", "t"]),
         "userspace/lib/tls/**"),
        ("image", dict(syn, body="fresh_disk $AZOS_OUT/build/disk-uhello.img"), "userspace/tests/uhello/**"),
        ("feature dep", dict(syn, body='kbuild "qemu,use-robot"'), "domains/robot/bench/**"),
        ("marker", dict(syn, call='par_row qemu_run "syn" "run_all done emitted=49" 180'),
         "domains/robot/bench/src/lib.rs"),
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        for what, r, want in cases:
            req = required_deps(r)
            expect("%s rule: %s not required (got %r)" % (what, want, sorted(req)[:6]), want in req)
            expect("canary: a %s row missing %s passes the check" % (what, want),
                   check_deps([r], {"syn": ("n1", " ".join(g for g in req if g != want))}) == 1)
            expect("a %s row with its deps fails the check" % what,
                   check_deps([r], {"syn": ("n1", " ".join(req))}) == 0)
        expect("a dir glob above the required ones does not cover them",
               check_deps([cases[2][1]], {"syn": ("n1", "tests/** crates/** userspace/**")}) == 0)
        prefix = dict(syn, body='cp "${REPO_ROOT}/config/defconfigs/$cell.config" x; d=tests/host/${suite}')
        expect("canary: the prefix of a shell expansion is a dep: %r" % sorted(required_deps(prefix)),
               not required_deps(prefix))
        expect("canary: a commented path is a dep",
               not required_deps(dict(syn, body="  # python3 tools/fake_brain.py\n  true # tools/fake_brain.py")))
    # The lints tier runs --check: without it `make check0` passed a manifest
    # whose deps miss what a row reads.
    tier = _read("tools/gate_tier.sh")
    expect("tools/gate_tier.sh lints does not run gate_rows.py --check", tier_lints_check(tier))
    expect("canary: a lints tier without the gate rows line passes",
           not tier_lints_check("\n".join(l for l in tier.splitlines() if "gate_rows.py --check" not in l)))
    expect("canary: --check under the n0 tier alone counts as a lint",
           not tier_lints_check('if [ "$tier" = n0 ]; then\n  python3 tools/gate_rows.py --self-test'
                                ' && python3 tools/gate_rows.py --check\nfi'))
    expect("an if-block lint is not read",
           tier_lints_check('if [ "$lints" = 1 ]; then\n  python3 tools/gate_rows.py --self-test\n'
                            '  python3 tools/gate_rows.py --check\nfi'))
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
    if "--check-deps" in argv:
        return check_deps()
    if "--check" in argv:
        return check_manifest() | check_needs() | check_robot_rows() | check_deps()
    if "--robot-features" in argv:
        print("\n".join(robot_features()))
        return 0
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
