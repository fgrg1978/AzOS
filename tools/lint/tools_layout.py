#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The layout of tools/: one directory per role, and the move that made it.

  tools_layout.py              check the layout (the lint; exit 1 on a finding)
  tools_layout.py --apply      move every tool still at tools/<name> into its role
                               directory and rewrite every reference to it
  tools_layout.py --rewrite F...  rewrite the old paths in files outside git
                               (a checkout's untracked notes, skills, scripts)
  tools_layout.py --callers    print each tool and what calls it
  tools_layout.py --self-test  canaries for the rewrite rules and the checks

ROLES below is the layout (INCOMING places what other branches are adding): every file under tools/ belongs to one entry of one
role (an entry is a file, or a directory moved whole). tools/keys/ is not part
of it: it holds the key files, outside git, at a path other checkouts and the
owner use.

--apply is replayable: run on a newer tree it moves what is still flat and
rewrites what was added since (references by the old path, in any tracked
file but third_party/). It refuses to start while tools/ holds a top-level
file or directory ROLES does not place. The rewrite rules:
  * `tools/<old>` -> `tools/<role>/<old>` in every tracked text file, matched
    on the exact entry name, so `famtools/`, `azos-tools/build` or a JSON-RPC
    method `tools/list` are left alone (also after `$CI_CHECK_DIR/`, the gate's
    name for tools/);
  * in a moved shell script, `$(dirname "$0")` with the path after it: the
    path is resolved from the script's old directory and spelled again from
    the new one (`$(dirname "$0")/..` becomes `$(dirname "$0")/../..`);
  * in a moved Python file, the same for
    `os.path.join(os.path.dirname(os.path.abspath(__file__)), "<path>")`
    (the azos_tools bootstrap, tools/lib/azos_tools.py, is one); a file
    written before azos_tools gets its own-directory sys.path entry turned
    into that bootstrap and its dirname(dirname(__file__)) root into that form
    first (what other branches add keeps working once moved);
  * in a moved Rust file, `include!`/`include_str!`/`include_bytes!` and
    `#[path = ..]` literals, and `path = ".."` in a moved Cargo.toml.

The check: every file is where ROLES says; no tracked file names a tool by
its old path; Python module names are unique across tools/ and shadow no
standard module; every `$(dirname "$0")` and `__file__` path resolves; no
Python tool finds the checkout or a sibling another way; every entry has a
caller (Makefile, mk/, Kconfig, a build script, a host test, the gate or
another tool) or is listed in NO_CALLER, which is the owner's list to decide.
"""

import ast
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
SELF = "tools/lint/tools_layout.py"

# role -> entries (a trailing "/" marks a directory moved whole). The role
# directories, and what starts each role:
#   build  what make runs while it builds (mk/*.mk, the build scripts): `make`
#   gate   the gate, its tiers and its row helpers: `make check0|check1|ci`
#   lint   checks of the tree and of built images: `make lint`
#   image  disk images, packages, bundles and their checks: mk/images.mk targets
#   sign   keys, signatures and provisioning records: mk/images.mk targets
#   bench  benchmarks against Linux: tools/bench/vsbench_compare.sh
#   dev    run, flash, serve and debug by hand: the `make qemu*`/board targets
#   lib    modules the other tools import (out_dir, azos_tools)
ROLES = {
    "build": [
        "busybox_cc.sh", "defconfig_menu.py", "export_kernel_consts.py", "gen_config_index.py", "gen_feature_matrix.py",
        "gen_userspace_kconfig.py", "kconfig_to_cargo.py", "lx_device_table.py", "lx_kbuild/",
        "make_help.txt", "micro_topology.py", "module_hashes.py", "prune_build.py", "relibc_build.sh",
        "relibc_cc.sh", "sdk_cargo.py", "sdk_std.py", "syscall_defs.py", "test_gen_userspace_kconfig.py",
        "test_kconfig_to_cargo.py", "test_preset_prompt.py", "test_user_isa.py", "third_party_fetch.sh", "user_link_args.py",
    ],
    "gate": [
        "check_fast.py", "check_fast.sh", "ci_cargo.py", "ci_check.sh", "ci_full.sh",
        "console_splice_count.sh", "coverage.sh", "fake_brain.py", "fuzz.sh", "gate_needs.tsv",
        "gate_pgroup.sh", "gate_pgroup_selftest.sh", "gate_rows.py", "gate_rows.tsv", "linux_off.baseline", "gate_tier.sh",
        "image_header.py", "ipv6_tcp_row.sh", "kaslr_boot_row.sh", "link_peer.py", "net_pair_smoke.sh",
        "netboot/", "nvme_dma_mask_row.sh", "preset_boot_green.tsv", "qemu_sendkeys.py", "repro_check.sh", "rows_for_diff.py",
        "sbom.sh", "text_equiv.py", "vmmd_withhold_row.sh",
    ],
    "lint": [
        "aarch64_fp_free_check.sh", "arch_cfg_lint.baseline", "arch_cfg_lint.py",
        "arch_layout_lint.py", "boot_seq_lint.baseline", "boot_seq_lint.py",
        "check_livepatch_layout.py", "check_make_help.sh", "check_neverallow.py", "check_presets.py",
        "chip_source_check.py", "claims_check.sh", "doc_lint.py", "elf_page_perms.py", "kconfig_lint.py",
        "lx_license_lint.py", "out_dir_lint.py", "req_trace.py", "size_budget.py", "size_budget.tsv",
        "spdx_headers.py", "stack_chain.py", "stack_frames.py", "tcb_check.sh", "tools_layout.py",
        "trap_lint.py", "unsafe_budget.py", "unsafe_budget.tsv", "user_entry_lint.py", "user_stacks.py",
    ],
    "image": [
        "azpkg.py", "azpkg_licences.txt", "blklog_crash_image.py", "boot.cmd", "check_board_disk.py",
        "gen_board_manifest.py", "kaslr_image.sh", "make_gguf.py", "make_mbl.py", "make_parted_disk.py",
        "mkazvol.py", "ota_delta.py", "test_board_manifest.py",
    ],
    "sign": [
        "check_board_keys.py", "check_prod_key.sh", "corrupt_sig.py", "device_provision.py",
        "gen_config_sig.py", "gen_dev_key.py", "gen_prod_key.py", "gen_test_key.py", "link_key_provision.py",
        "seed_provision.py", "sigalg.py", "sign_ota.py",
    ],
    "bench": [
        "lat_linux/", "limits_cost.py", "linux_seccomp_launch/",
        "vsbench_aarch64.sh", "vsbench_compare.sh", "vsbench_cost.sh", "vsbench_linux.conf",
        "vsbench_tcp_pcap.py", "vsbench_tcp_peer.py", "vsbench_x86_64.sh",
    ],
    "dev": [
        "dev_dfu_recovery.sh", "dev_uart.py", "esp32_bridge/", "farm/",
        "ota_send.py", "perfetto_export.py", "qemu.sh", "run_guest.sh",
        "test_farm.py", "tftp_serve.py", "worktree_seed.py",
    ],
    "lib": ["azos_tools.py", "out_dir.py"],
}

# Entries in flight on other branches (2026-10-23): placed here so that --apply
# on a tree where they have landed moves them too. An absent one is no finding.
INCOMING = {
    "build": ["gen_defconfigs.py", "kconfig_to_cargo.golden"],
    "gate": ["azos_sim/", "ipv6_fw_row.sh"],
    "lint": ["compile_time_hooks.tsv", "dead_code_lint.py", "feature_source_lint.py", "isa_neutral_names.py",
             "task_place_lint.baseline", "task_place_lint.py"],
    "image": ["azos_records.py", "fat_damage_image.py", "mk_ucode.py"],
}

# The tools a person runs by hand, on purpose: nothing in the tree calls them,
# and each line says why it stays manual (owner batch IV, 2026-10-24; the other
# tools that had no caller were wired, merged, moved out or deleted).
NO_CALLER = {
    "check_prod_key.sh": "checks the production public key before a release build: only on the machine that holds it",
    "coverage.sh": "host-suite region coverage: an occasional measurement, minutes of instrumented builds",
    "dev_dfu_recovery.sh": "USB DFU recovery of a VF2/K1 held in its boot ROM: needs the board (kept until it)",
    "dev_uart.py": "relays a board's serial console to a person: needs the board (kept until it)",
    "esp32_bridge/": "ESP32 sketch, flashed with the Arduino tools: needs the board (kept until it)",
    "gen_prod_key.py": "generates the production signing key: never automated, on purpose",
    "text_equiv.py": "compares two kernels' .text: an A/B a person picks the two builds for",
    "qemu.sh": "interactive QEMU launcher (console, gdb): a person at the terminal",
    "limits_cost.py": "RAM cost of a sizing option: two builds per option a person chooses to price",
}

# Files that are data or a self-contained unit's own parts: called through the
# entry that reads them (checked as part of their directory entry).
SKIP_TEXT = ("third_party/",)


def entries(incoming=True):
    """[(old, new, is_dir)] repository-relative, no trailing slash."""
    out = []
    for role in ROLES:
        for n in ROLES[role] + (INCOMING.get(role, []) if incoming else []):
            d = n.endswith("/")
            n = n.rstrip("/")
            out.append(("tools/" + n, "tools/%s/%s" % (role, n), d))
    return out


def git(*args, cwd=None):
    return subprocess.run(["git"] + list(args), cwd=cwd or ROOT, capture_output=True, text=True,
                          check=True).stdout


def tracked(cwd=None):
    return [p for p in git("ls-files", "-z", cwd=cwd).split("\0") if p]


def read_text(path):
    try:
        with open(path, "rb") as f:
            b = f.read()
    except (IsADirectoryError, FileNotFoundError, PermissionError):
        return None
    if b"\0" in b[:8192]:
        return None
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ── the rewrite rules ────────────────────────────────────────────────────────

def ref_regex(ents):
    """One regex for every old path; group 1 is the entry name."""
    names = sorted((o[len("tools/"):] for o, _, _ in ents), key=len, reverse=True)
    alts = "|".join(re.escape(n) for n in names)
    return re.compile(r"(?<![\w.-])(tools/|\$CI_CHECK_DIR/|\$\{CI_CHECK_DIR\}/)(" + alts + r")(?![\w-])")


def rewrite_refs(text, ents, rx=None):
    rx = rx or ref_regex(ents)
    new = {o[len("tools/"):]: n[len("tools/"):] for o, n, _ in ents}
    return rx.sub(lambda m: m.group(1) + new[m.group(2)], text)


def map_path(p, ents):
    """The new repository path of old path `p` (a file, a directory, or inside one)."""
    for o, n, d in ents:
        if p == o:
            return n
        if d and p.startswith(o + "/"):
            return n + p[len(o):]
    return p


def respell(rel, old_dir, new_dir, ents):
    """`rel`, written from `old_dir`, spelled from `new_dir` once the move is done."""
    target = os.path.normpath(os.path.join(old_dir, rel) if rel else old_dir)
    target = map_path(target, ents)
    out = os.path.relpath(target, new_dir)
    return "" if out == "." else out


SH_ANCHOR = re.compile(r'\$\(dirname "\$0"\)((?:/[\w.-]+)*)')
PY_ANCHOR = re.compile(r'os\.path\.join\(os\.path\.dirname\(os\.path\.abspath\(__file__\)\), "([\w./-]*)"\)')
RS_LITERAL = re.compile(r'((?:include|include_str|include_bytes)!\(\s*"|#\[path\s*=\s*")(\.\.?/[^"]*)"')
TOML_PATH = re.compile(r'(\bpath\s*=\s*")(\.\.?/[^"]*)"')


LEGACY_SYSPATH = re.compile(r"^([ \t]*)sys\.path\.insert\(0, (?:os\.path\.dirname\(os\.path\.abspath\(__file__\)\)"
                            r"|str\(Path\(__file__\)\.parent\))\)[ \t]*$", re.M)
LEGACY_ROOT = re.compile(r"os\.path\.dirname\(os\.path\.dirname\(os\.path\.(abs|real)path\(__file__\)\)\)")


def legacy_py(text, od):
    """A moved Python file written before azos_tools: its two common __file__
    idioms, put in the forms the anchor rule respells."""
    lib = os.path.relpath("tools/lib", od)

    def boot(m):
        out = '%ssys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "%s"))\n' % (m.group(1), lib)
        return out + "%simport azos_tools  # noqa: E402,F401  (every tools/ module directory on sys.path)" % m.group(1)
    text, n = LEGACY_SYSPATH.subn(boot, text)
    if n and not re.search(r"^import os\b|^import .*\bos\b", text, re.M):
        text = "import os  # noqa: E402 (tools_layout.py)\n" + text if not text.startswith("#!") else \
            text.replace("\n", "\nimport os  # noqa: E402 (tools_layout.py)\n", 1)

    def root(m):
        r = 'os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))'
        return r if m.group(1) == "abs" else "os.path.realpath(%s)" % r
    return LEGACY_ROOT.sub(root, text)


def rewrite_anchors(text, path, old, new, ents):
    """Rules 2-4 for one moved file: `path` its new repository path, `old` its old one."""
    od, nd = os.path.dirname(old), os.path.dirname(new)
    if path.endswith(".py"):
        text = legacy_py(text, od)
    if path.endswith(".sh") or text.startswith("#!/usr/bin/env bash") or text.startswith("#!/bin/sh"):
        text = SH_ANCHOR.sub(
            lambda m: '$(dirname "$0")' + ("/" + r if (r := respell(m.group(1).lstrip("/"), od, nd, ents)) else ""),
            text)
    if path.endswith(".py"):
        text = PY_ANCHOR.sub(
            lambda m: 'os.path.join(os.path.dirname(os.path.abspath(__file__)), "%s")'
                      % (respell(m.group(1), od, nd, ents) or "."),
            text)
    if path.endswith(".rs"):
        text = RS_LITERAL.sub(lambda m: m.group(1) + (respell(m.group(2), od, nd, ents) or ".") + '"', text)
    if os.path.basename(path) == "Cargo.toml":
        text = TOML_PATH.sub(lambda m: m.group(1) + (respell(m.group(2), od, nd, ents) or ".") + '"', text)
    return text


def unplaced(root=ROOT):
    """Top-level names under tools/ that ROLES does not place."""
    known = {o[len("tools/"):] for o, _, _ in entries()} | set(ROLES) | {"keys"}
    out = []
    for p in tracked(root):
        if p.startswith("tools/"):
            top = p.split("/")[1]
            if top not in known:
                out.append(p)
    return sorted(set(out))


def apply(root=ROOT):
    ents = entries()
    bad = unplaced(root)
    if bad:
        print("tools_layout: ROLES places none of these; add them first:", file=sys.stderr)
        for p in bad:
            print("  " + p, file=sys.stderr)
        return 1
    moved = []
    for o, n, d in ents:
        if os.path.lexists(os.path.join(root, o)):
            if os.path.lexists(os.path.join(root, n)):
                print("tools_layout: both %s and %s exist; merge them by hand" % (o, n), file=sys.stderr)
                return 1
            os.makedirs(os.path.dirname(os.path.join(root, n)), exist_ok=True)
            subprocess.run(["git", "mv", o, n], cwd=root, check=True)
            moved.append((o, n, d))
    rx = ref_regex(ents)
    files = tracked(root)
    changed = 0
    for p in files:
        if p == SELF or p.startswith(SKIP_TEXT):
            continue
        full = os.path.join(root, p)
        text = read_text(full)
        if text is None:
            continue
        out = text
        for o, n, d in moved:
            if p == n or (d and p.startswith(n + "/")):
                out = rewrite_anchors(out, p, o + p[len(n):], p, ents)
        out = rewrite_refs(out, ents, rx)
        if out != text:
            with open(full, "w", encoding="utf-8", newline="") as f:
                f.write(out)
            changed += 1
    print("tools_layout: moved %d entries, rewrote %d files" % (len(moved), changed))
    return 0


def rewrite_files(paths):
    ents = entries()
    rx = ref_regex(ents)
    for p in paths:
        text = read_text(p)
        if text is None:
            continue
        out = rewrite_refs(text, ents, rx)
        if out != text:
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(out)
            print("rewrote " + p)
    return 0


# ── the check ────────────────────────────────────────────────────────────────

FORBIDDEN_PY = [
    (re.compile(r"os\.path\.dirname\(os\.path\.dirname\(os\.path\.(abs|real)path\(__file__\)\)\)"),
     "finds the checkout by counting directories: use azos_tools.ROOT"),
    (re.compile(r"Path\(__file__\)(\.resolve\(\))?\.parent"), "Path(__file__).parent: use azos_tools"),
    (re.compile(r"sys\.path\.insert\(\d, os\.path\.dirname\(os\.path\.abspath\(__file__\)\)\)"),
     "imports a sibling by its own directory: use the azos_tools bootstrap"),
    (re.compile(r"os\.path\.join\(os\.path\.dirname\(__file__\)"), "use the canonical __file__ form"),
    (re.compile(r'sys\.path\.insert\(\d, os\.path\.join\(\w+, "tools"\)\)'),
     "puts tools/ itself on sys.path, where no module lives: use the azos_tools bootstrap"),
    (re.compile(r'os\.path\.join\([^)]*"tools", "'),
     'names a tool by path parts, which the move cannot rewrite: write "tools/<role>/<name>"'),
]

# Where a caller can be: what make, a build script, a host test or a tool runs.
# A kernel crate's own source cannot run a host tool (its messages and
# comments name some), and Kconfig only runs one through $(shell,...).
CALLER_FILES = re.compile(r"(^Makefile$|^mk/.*\.mk$|^Kconfig$|^config/Kconfig\.|(^|/)build\.rs$|^tests/.*\.rs$|"
                          r"\.sh$|\.py$|Cargo\.toml$)")


def code_strings_py(text):
    """The string constants of a Python file that are not docstrings."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            b = getattr(node, "body", [])
            if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant):
                docs.add(id(b[0].value))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            out.append(node.value)
        elif isinstance(node, ast.Import):
            out += ["import:" + a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.append("import:" + node.module)
    return "\n".join(out)


def code_text(path, text):
    """What of a caller file can call: no comments, no Python docstrings."""
    if path.endswith(".py"):
        return code_strings_py(text)
    if path.endswith(".rs"):
        return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))
    if path == "Kconfig" or path.startswith("config/Kconfig."):
        return "\n".join(l for l in text.splitlines() if "$(shell" in l)
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def callers(root=ROOT):
    """{entry new path: sorted caller files}."""
    ents = entries()
    texts = {}
    for p in tracked(root):
        if p == SELF or p.startswith(SKIP_TEXT) or not CALLER_FILES.search(p):
            continue
        t = read_text(os.path.join(root, p))
        if t is not None:
            texts[p] = code_text(p, t)
    out = {}
    for o, n, d in ents:
        name = os.path.basename(n)
        stem = name[:-3] if name.endswith(".py") else None
        who = set()
        for p, t in texts.items():
            if p == n or (d and p.startswith(n + "/")):
                continue
            if n in t or (stem and p.startswith("tools/") and "import:" + stem in t.split()):
                who.add(p)
            elif p.startswith("tools/") and os.path.dirname(p) == os.path.dirname(n) and name in t:
                who.add(p)       # a sibling named from its own directory ($(dirname "$0")/name)
        out[n] = sorted(who)
    return out


def check(root=ROOT):
    ents = entries()
    errs = []
    for p in unplaced(root):
        errs.append("%s: ROLES places no such entry" % p)
    for p in tracked(root):
        parts = p.split("/")
        if len(parts) > 2 and parts[0] == "tools" and parts[1] in ROLES:
            if not ({parts[2], parts[2] + "/"} & set(ROLES[parts[1]] + INCOMING.get(parts[1], []))):
                errs.append("%s: not an entry of ROLES[%r]" % (p, parts[1]))
    optional = {"tools/%s/%s" % (r, x.rstrip("/")) for r, xs in INCOMING.items() for x in xs}
    for o, n, d in ents:
        if not os.path.lexists(os.path.join(root, n)) and n not in optional:
            errs.append("%s: listed in ROLES, missing" % n)
        if os.path.lexists(os.path.join(root, o)):
            errs.append("%s: still at its old place (tools_layout.py --apply)" % o)
    rx = ref_regex(ents)
    mods = {}
    for p in tracked(root):
        if p == SELF or p.startswith(SKIP_TEXT):
            continue
        text = read_text(os.path.join(root, p))
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = rx.search(line)
            if m:
                errs.append("%s:%d: old path %s" % (p, i, m.group(0)))
        if not p.startswith("tools/"):
            continue
        base = os.path.dirname(p)
        if p.endswith(".py"):
            mods.setdefault(os.path.basename(p)[:-3], []).append(p)
            for rx2, why in FORBIDDEN_PY:
                for i, line in enumerate(text.splitlines(), 1):
                    # a self-test's fixture text is a string line, not the tool's code
                    if rx2.search(line) and p != SELF and line.lstrip()[:1] not in "'\"":
                        errs.append("%s:%d: %s" % (p, i, why))
            for m in PY_ANCHOR.finditer(text):
                t = os.path.normpath(os.path.join(base, m.group(1)))
                if not t.startswith("..") and not os.path.lexists(os.path.join(root, t)):
                    errs.append("%s: __file__ path %r resolves to %s, which does not exist" % (p, m.group(1), t))
        if p.endswith(".sh") or text.startswith("#!/usr/bin/env bash"):
            for m in SH_ANCHOR.finditer(text):
                t = os.path.normpath(os.path.join(base, m.group(1).lstrip("/")) if m.group(1) else base)
                if not t.startswith("..") and not os.path.lexists(os.path.join(root, t)):
                    errs.append('%s: $(dirname "$0")%s resolves to %s, which does not exist' % (p, m.group(1), t))
    std = set(getattr(sys, "stdlib_module_names", ()))
    for m, ps in sorted(mods.items()):
        if len(ps) > 1:
            errs.append("python module %s defined twice: %s" % (m, " ".join(ps)))
        if m in std:
            errs.append("%s shadows the standard module %s" % (ps[0], m))
    nocall = {"tools/%s/%s" % (r, n.rstrip("/")) for r, ns in ROLES.items() for n in ns if n in NO_CALLER}
    nested = {k for k in NO_CALLER if "/" in k.rstrip("/")}
    for n, who in callers(root).items():
        if n in optional and not os.path.lexists(os.path.join(root, n)):
            continue
        if not who and n not in nocall:
            errs.append("%s: nothing calls it (add a caller, or list it in NO_CALLER)" % n)
        if who and n in nocall:
            errs.append("%s: listed in NO_CALLER but called by %s" % (n, " ".join(who[:3])))
    for k in nested:
        if not any(os.path.lexists(os.path.join(root, "tools", r, k)) for r in ROLES):
            errs.append("NO_CALLER names %s, which is not in tools/" % k)
    for e in errs:
        print(e)
    print("tools_layout: %s" % ("ok" if not errs else "%d finding(s)" % len(errs)), file=sys.stderr)
    return 1 if errs else 0


# ── self-test ────────────────────────────────────────────────────────────────

def self_test():
    ents = [("tools/a.py", "tools/build/a.py", False), ("tools/out_dir.py", "tools/lib/out_dir.py", False),
            ("tools/farm", "tools/dev/farm", True), ("tools/gate_rows.py", "tools/gate/gate_rows.py", False),
            ("tools/gate_rows.tsv", "tools/gate/gate_rows.tsv", False), ("tools/list.sh", "tools/gate/list.sh", False)]
    fails = 0

    def eq(name, got, want):
        nonlocal fails
        if got != want:
            fails += 1
            print("FAIL %s:\n  got  %r\n  want %r" % (name, got, want))

    eq("plain", rewrite_refs("python3 tools/a.py x", ents), "python3 tools/build/a.py x")
    eq("longest name", rewrite_refs("tools/gate_rows.tsv tools/gate_rows.py.", ents),
       "tools/gate/gate_rows.tsv tools/gate/gate_rows.py.")
    eq("dir prefix", rewrite_refs("tools/farm/farm.py and tools/farm", ents),
       "tools/dev/farm/farm.py and tools/dev/farm")
    eq("left alone", rewrite_refs('famtools/a.py azos-tools/a.py "tools/list" tools/a.pyc', ents),
       'famtools/a.py azos-tools/a.py "tools/list" tools/a.pyc')
    eq("idempotent", rewrite_refs(rewrite_refs("tools/a.py", ents), ents), "tools/build/a.py")
    eq("gate alias", rewrite_refs('CARGO="$CI_CHECK_DIR/a.py"; ${CI_CHECK_DIR}/a.py', ents),
       'CARGO="$CI_CHECK_DIR/build/a.py"; ${CI_CHECK_DIR}/build/a.py')
    sh = 'cd "$(dirname "$0")/.." && python3 "$(dirname "$0")/out_dir.py"; d="$(cd "$(dirname "$0")" && pwd)"'
    eq("shell anchors", rewrite_anchors(sh, "tools/build/a.sh", "tools/a.sh", "tools/build/a.sh", ents),
       'cd "$(dirname "$0")/../.." && python3 "$(dirname "$0")/../lib/out_dir.py"; '
       'd="$(cd "$(dirname "$0")/.." && pwd)"')
    eq("shell anchor in a moved dir",
       rewrite_anchors('x="$(dirname "$0")/../out_dir.py"; y="$(dirname "$0")/farm.py"', "tools/dev/farm/r.sh",
                       "tools/farm/r.sh", "tools/dev/farm/r.sh", ents),
       'x="$(dirname "$0")/../../lib/out_dir.py"; y="$(dirname "$0")/farm.py"')
    py = 'sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))'
    eq("python bootstrap", rewrite_anchors(py, "tools/build/a.py", "tools/a.py", "tools/build/a.py", ents),
       py.replace('"lib"', '"../lib"'))
    eq("python bootstrap in lib", rewrite_anchors(py, "tools/lib/out_dir.py", "tools/out_dir.py",
                                                  "tools/lib/out_dir.py", ents), py.replace('"lib"', '"."'))
    eq("python outside the repo",
       rewrite_anchors('os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../Brain")', "tools/build/a.py",
                       "tools/a.py", "tools/build/a.py", ents),
       'os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../Brain")')
    leg = ('import os, sys\nsys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n'
           'ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n')
    eq("legacy python", rewrite_anchors(leg, "tools/build/a.py", "tools/a.py", "tools/build/a.py", ents),
       'import os, sys\nsys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))\n'
       'import azos_tools  # noqa: E402,F401  (every tools/ module directory on sys.path)\n'
       'ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))\n')
    eq("legacy Path import", rewrite_anchors("import sys\nsys.path.insert(0, str(Path(__file__).parent))\n",
                                             "tools/build/a.py", "tools/a.py", "tools/build/a.py", ents),
       'import os  # noqa: E402 (tools_layout.py)\nimport sys\n'
       'sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))\n'
       'import azos_tools  # noqa: E402,F401  (every tools/ module directory on sys.path)\n')
    eq("rust include", rewrite_anchors('include_str!("../../../x/y.rs") include!("src/z.rs")',
                                       "tools/dev/farm/t/src/lib.rs", "tools/farm/t/src/lib.rs",
                                       "tools/dev/farm/t/src/lib.rs", ents),
       'include_str!("../../../../x/y.rs") include!("src/z.rs")')
    eq("cargo path", rewrite_anchors('a = { path = "../../crates/c" }', "tools/dev/farm/Cargo.toml",
                                     "tools/farm/Cargo.toml", "tools/dev/farm/Cargo.toml", ents),
       'a = { path = "../../../crates/c" }')

    # The tree-level rules on a scratch repository: apply, then check.
    with tempfile.TemporaryDirectory() as d:
        def w(p, s):
            os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True)
            with open(os.path.join(d, p), "w") as f:
                f.write(s)
        subprocess.run(["git", "init", "-q", d], check=True)
        w("Makefile", "x:\n\tpython3 tools/kconfig_to_cargo.py\n")
        w("tools/kconfig_to_cargo.py", 'import os\nR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")\n')
        w("tools/stray.py", "")
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        eq("unplaced", unplaced(d), ["tools/stray.py"])
        os.remove(os.path.join(d, "tools/stray.py"))
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        sys_stdout, sys.stdout = sys.stdout, open(os.devnull, "w")
        try:
            apply(d)
        finally:
            sys.stdout.close()
            sys.stdout = sys_stdout
        eq("make rewritten", read_text(os.path.join(d, "Makefile")), "x:\n\tpython3 tools/build/kconfig_to_cargo.py\n")
        eq("anchor rewritten", read_text(os.path.join(d, "tools/build/kconfig_to_cargo.py")),
           'import os\nR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../..")\n')
    print("tools_layout self-test: %s" % ("ok" if not fails else "%d FAILED" % fails))
    return 1 if fails else 0


def main(argv):
    if len(argv) > 1 and argv[1] == "--self-test":
        return self_test()
    if len(argv) > 1 and argv[1] == "--apply":
        return apply()
    if len(argv) > 1 and argv[1] == "--rewrite":
        return rewrite_files(argv[2:])
    if len(argv) > 1 and argv[1] == "--callers":
        for n, who in callers().items():
            print("%s\t%s" % (n, " ".join(who) or "-"))
        return 0
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
