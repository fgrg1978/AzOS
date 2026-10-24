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
  size_budget.py --memory [LABEL=ELF[,CONFIG] ...]   static memory report (below)
  size_budget.py --self-test                         the tool's own canaries

--memory: static memory of kernel ELFs: sections, image end, per-subsystem
(crate) totals, the large static buffers, and what is left of a 16 / 64 MiB
board once the image and the kernel heap are placed. CONFIG is the expanded
.config the ELF was built from: the report looks for the `azos_limits`
generated.rs next to the ELF whose SHA-256 prefix matches it and reads the
constants (heap, RAM_SIZE, tasks, TCP) from THAT file, so a report never pairs
an ELF with a config it was not built from. With no LABEL=ELF, the builds
under $AZOS_OUT/target where they exist (default, fleet, embedded; see
memory_defaults). Figures are what the linker placed: symbol sizes from
`llvm-nm -S`, section sizes from `llvm-size -A`. Heap, page tables and task
frames are not in the image; the heap size comes from the config, the rest is
reported as what is left for the PMM. Environment: TOP (rows in the crate
table, 25), BIG_KIB (smallest buffer listed, 64).

Environment: LLVM_BIN, the directory holding llvm-size and llvm-nm (default:
the active rustup toolchain's llvm-tools).
"""
import glob
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
from out_dir import out_root  # noqa: E402

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


def llvm_tool(name):
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
    tool = os.path.join(d, name)
    if not os.access(tool, os.X_OK):
        raise SystemExit(f"size_budget: no {name} in {d} (rustup component add llvm-tools-preview, or set LLVM_BIN)")
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
        out = subprocess.run([llvm_tool("llvm-size"), "-A", elf], check=True, capture_output=True, text=True).stdout
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


# ---- --memory: the static memory report -----------------------------------

# Firmware window below the kernel on every rv64 layout here.
OPENSBI_KIB = 2048
# Sections the report leaves out: debug info and the ELF's own tables.
NOT_LOADED = re.compile(r"^\.(debug|riscv\.attributes|comment|symtab|strtab|shstrtab)")
LLVM_SUFFIX = re.compile(r" \(\.llvm\.[0-9]+\)$")
# Named buffers the budget discussion refers to: absent means not linked.
NAMED_BUFFERS = (
    ("secure_boot_verify_image_detailed::IMG_BUF", "secure boot image buffer (IMG_BUF)"),
    ("azos_net::tcp::TCP", "TCP connection table (TCP)"),
    ("scheduler::TASK_STACKS", "task kernel stacks (TASK_STACKS)"),
    ("scheduler::TASKS", "task slots (TASKS)"),
    ("scheduler::PER_CPU", "per-CPU scheduler state (PER_CPU)"),
    ("azos_mm::pmm::PCP", "per-hart frame caches (PCP)"),
    ("cap_store::CAP_TABLES", "capability tables (CAP_TABLES)"),
    ("cmd_exec::ELF_BUF", "shell exec buffer (ELF_BUF)"),
    ("handlers::EXEC_BOUNCE", "exec bounce buffer (EXEC_BOUNCE)"),
)
HWCLASSES = ("EMBEDDED", "SBC", "DESKTOP", "SERVER")


def memory_defaults():
    out = out_root()
    rel = "riscv64imac-unknown-none-elf/release/kernel"
    return [f"default={out}/target/{rel},{os.environ.get('KCONFIG_CONFIG', '.config')}",
            f"fleet={out}/target/fleet/{rel},{out}/target/fleet/fleet.config",
            f"embedded={out}/target/embedded/{rel},{out}/target/embedded/embedded.config"]


def kib(b):
    return f"{b / 1024:.1f}"


def nm_hex(h):
    """awk's hex read of an nm size column (a non-hex digit counts -1)."""
    v = 0
    for ch in h.lower():
        v = v * 16 + "0123456789abcdef".find(ch)
    return v


def nm_rows(text):
    """`llvm-nm -S -C` lines -> [(size column, type, demangled name)]."""
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4:
            rows.append((f[1], f[2], " ".join(f[3:])))
    return rows


def crate_lines(rows, top):
    """The per-subsystem table: a symbol's crate is the first path segment of
    its demangled name; `<T as Trait>` impls count toward T's crate. Local
    labels and names that do not demangle to a path are "(unattributed)"."""
    acc, total = {}, 0
    for size, t, name in rows:
        if len(size) < 8 or not re.fullmatch(r"[tTrRdDbBsSgG]", t):
            continue
        n = re.sub(r"^<(&mut |&)?", "", name, count=1)
        k = n.find("::")
        crate = n[:k] if k > 0 else "(unattributed)"
        if re.search(r"[ .$]", crate) or crate.startswith("_R"):
            crate = "(unattributed)"
        col = 0 if t in "tT" else 1 if t in "rR" else 2 if t in "dDgG" else 3
        e = acc.setdefault(crate, [0, 0, 0, 0])
        e[col] += nm_hex(size)
        total += nm_hex(size)
    # sort -k1,1nr: by total, ties by the whole line
    order = sorted(acc.items(), key=lambda kv: (-sum(kv[1]), f"{sum(kv[1])} {kv[0]} " + " ".join(map(str, kv[1]))))
    out, rest, others = [], [0, 0, 0, 0, 0], 0
    for i, (crate, c) in enumerate(order):
        if i < top:
            out.append("  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f" % ((crate,) + tuple(x / 1024 for x in c + [sum(c)])))
        else:
            rest = [a + b for a, b in zip(rest, c + [sum(c)])]
            others += 1
    if others:
        out.append("  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f" % ((f"({others} more)",) + tuple(x / 1024 for x in rest)))
    out.append("  %-32s %59.1f" % ("symbols, all crates", total / 1024))
    return out


def data_rows(rows):
    """(bytes, name) of the data and bss symbols, the LLVM suffix dropped."""
    return [(nm_hex(size), LLVM_SUFFIX.sub("", name)) for size, t, name in rows
            if re.fullmatch(r"[dDbBsSgG]", t)]


def big_lines(rows, min_bytes):
    big = [(s, n) for s, n in data_rows(rows) if s >= min_bytes]
    big.sort(key=lambda x: (-x[0], f"{x[0]}\t{x[1]}"))
    return ["  %-68s %11d %11.1f" % (n, s, s / 1024) for s, n in big]


def named_lines(rows):
    d = data_rows(rows)
    out = []
    for pat, what in NAMED_BUFFERS:
        hits = [s for s, n in d if n.endswith(pat)]
        if hits:
            out.append("  %-50s %11d %11.1f" % (what, sum(hits), sum(hits) / 1024))
        else:
            out.append("  %-50s %23s" % (what, "absent (not linked)"))
    return out


def gen_const(text, name):
    m = re.search(r"^pub const %s: [a-z0-9]* = (.*);$" % re.escape(name), text, re.M)
    return m.group(1) if m else ""


def memory_report(label, elf, cfg, top, big_kib):
    p = print
    p("==================================================================")
    p(f"== {label}")
    p("==================================================================")
    if not os.path.isfile(elf):
        p(f"  not built: {elf}")
        p("")
        return
    p(f"  elf:    {elf} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(elf)))})")

    # The config the ELF was compiled from.
    gen = None
    if cfg and os.path.isfile(cfg):
        with open(cfg, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()[:12]
        for g in sorted(glob.glob(os.path.join(os.path.dirname(elf), "build/azos_limits-*/out/generated.rs"))):
            with open(g, encoding="utf-8", errors="replace") as f:
                text = f.read()
            if f"Config SHA-256 prefix: {sha} " in text:
                gen = text
                break
        if gen is not None:
            p(f"  config: {cfg} ({sha}, compiled in)")
        else:
            p(f"  config: {cfg} ({sha}) is NOT the one compiled into this ELF:")
            p(f"          no generated.rs under {os.path.dirname(elf)}/build carries it")
    else:
        p("  config: none given")
    heap = ram_mib = None
    if gen is not None:
        hw = [c for c in HWCLASSES if gen_const(gen, "HWCLASS_" + c) == "true"]
        ram_mib, heap = gen_const(gen, "RAM_SIZE"), gen_const(gen, "KERNEL_HEAP_SIZE_BYTES")
        p(f"  consts: HWCLASS_{hw[-1] if hw else '?'} RAM_SIZE={ram_mib} MiB "
          f"KERNEL_HEAP={kib(int(heap or 0))} KiB MAX_TASKS={gen_const(gen, 'MAX_TASKS')} "
          f"KERNEL_STACK={gen_const(gen, 'KERNEL_STACK_SIZE_BYTES')} B "
          f"TCP={gen_const(gen, 'TCP_MAX_CONNS')}x{gen_const(gen, 'TCP_BUF_SIZE')} B")

    # Sections.
    p("")
    p("  section                      bytes         KiB")
    for line in subprocess.run([llvm_tool("llvm-size"), "-A", elf], capture_output=True, text=True).stdout.splitlines():
        c = line.split()
        if len(c) >= 2 and c[0].startswith(".") and not NOT_LOADED.match(c[0]) and c[1].isdigit():
            p("  %-20s %13d %11.1f" % (c[0], int(c[1]), int(c[1]) / 1024))

    # Image bounds.
    syms = {}
    for line in subprocess.run([llvm_tool("llvm-nm"), elf], capture_output=True, text=True).stdout.splitlines():
        f = line.split()
        if len(f) >= 3:
            syms.setdefault(f[2], f[0])
    text_start, kernel_end = syms.get("_text_start", ""), syms.get("_kernel_end", "")
    stack_start, stack_end, bss_end = syms.get("_stack_start", ""), syms.get("_stack_end", ""), syms.get("_bss_end", "")
    image = int(kernel_end or "0", 16) - int(text_start or "0", 16)
    p("")
    p(f"  _text_start  0x{text_start}")
    p(f"  _bss_end     0x{bss_end}")
    p(f"  _stack_start 0x{stack_start}   _stack_end 0x{stack_end}")
    p(f"  _kernel_end  0x{kernel_end}")
    p(f"  image [_text_start, _kernel_end): {image} B = {kib(image)} KiB")
    if not stack_end or int(stack_end, 16) > int(kernel_end or "0", 16):
        p("  WARNING: boot stack is not inside the image: this ELF was linked with a")
        p("           script older than the in-image .stack section; rebuild it.")

    # Per subsystem, the large static buffers, the named ones. Symbol sizes
    # exclude alignment padding, so the sum is compared with the sections'.
    rows = nm_rows(subprocess.run([llvm_tool("llvm-nm"), "-S", "-C", "--defined-only", elf],
                                  capture_output=True, text=True).stdout)
    p("")
    p("  subsystem (crate)                       text      rodata        data         bss       total (KiB)")
    for line in crate_lines(rows, top):
        p(line)
    p("")
    p(f"  static objects >= {big_kib} KiB (data and bss)                            bytes         KiB")
    for line in big_lines(rows, big_kib * 1024):
        p(line)
    p("")
    p("  named buffers                                         bytes         KiB")
    for line in named_lines(rows):
        p(line)

    # What is left on a board. RAM starts one firmware window below the link
    # address (every rv64 script here links the kernel 2 MiB above RAM; the
    # ELF, not RAM_BASE, is the authority: the qemu build of an edge/VF2
    # .config links at 0x80200000). The heap is reserved right after
    # _kernel_end (kernel/src/entry/{riscv64,aarch64}/boot_hooks.rs). What
    # remains is the PMM's for page tables, task frames and user memory. The
    # device tree QEMU passes also sits in the top megabytes of RAM.
    if heap and text_start:
        p("")
        p("  board RAM   image + heap (KiB)   left for PMM frames (KiB)")
        rb, heap_b, seen = int(text_start, 16) - OPENSBI_KIB * 1024, int(heap), set()
        for mib in [16, 64] + ([int(ram_mib)] if ram_mib else []):
            left = rb + mib * 1024 * 1024 - int(kernel_end, 16) - heap_b
            line = "  %4d MiB    %18s   %24s%s" % (mib, kib(image + heap_b), kib(left),
                                                  "   DOES NOT FIT" if left < 0 else "")
            if line not in seen:
                seen.add(line)
                p(line)
    p("")


def memory(args):
    top, big_kib = int(os.environ.get("TOP", "25")), int(os.environ.get("BIG_KIB", "64"))
    llvm_tool("llvm-nm")
    llvm_tool("llvm-size")
    for a in args or memory_defaults():
        label, rest = a.split("=", 1)
        elf, _, cfg = rest.partition(",")
        memory_report(label, elf, cfg, top, big_kib)
    return 0


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
    # --memory: crate attribution, the big-object floor, the named buffers.
    nm = nm_rows("80200000 0000000000001000 T azos_net::tcp::send\n"
                 "80300000 0000000000002000 b azos_net::tcp::TCP (.llvm.123)\n"
                 "80400000 0000000000000800 T <azos_mm::pmm::Pmm as core::fmt::Debug>::fmt\n"
                 "80500000 0000000000000400 r .Lanon.7\n"
                 "80600000 00000010 t short\n")
    eq("crate table", crate_lines(nm, 25), [
        "  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f" % ("azos_net", 4.0, 0.0, 0.0, 8.0, 12.0),
        "  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f" % ("azos_mm", 2.0, 0.0, 0.0, 0.0, 2.0),
        "  %-32s %11.1f %11.1f %11.1f %11.1f %11.1f" % ("(unattributed)", 0.0, 1.0, 0.0, 0.0, 1.0),
        "  %-32s %59.1f" % ("symbols, all crates", 15.0)])
    eq("crate table, top 1", crate_lines(nm, 1)[1].split()[:2], ["(2", "more)"])
    eq("big objects", big_lines(nm, 8192), ["  %-68s %11d %11.1f" % ("azos_net::tcp::TCP", 8192, 8.0)])
    eq("big objects floor", big_lines(nm, 8193), [])
    eq("named TCP", named_lines(nm)[1].split()[-2:], ["8192", "8.0"])
    eq("named absent", named_lines(nm)[0].endswith("absent (not linked)"), True)
    eq("named by suffix", named_lines(nm_rows("1 0000000000001000 b azos_sched::scheduler::TASK_STACKS\n"))[2].split()[-2:],
       ["4096", "4.0"])
    eq("gen const", gen_const("pub const RAM_SIZE: usize = 256;\n", "RAM_SIZE"), "256")

    if fails:
        print("size_budget self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("size_budget self-test ok")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:2] == ["--memory"]:
        return memory(sys.argv[2:])
    return run(ROOT, sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
