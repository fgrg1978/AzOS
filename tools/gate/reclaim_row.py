#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""reclaim_row.py — the gate's `reclaim:` rows: real pressure on a real kernel.

    reclaim_row.py <riscv64|aarch64|x86_64> <scenario>   (AZOS_OUT set; CI_LOG_DIR optional)
    reclaim_row.py --self-test                           the judge on made-up consoles

What the owner types, in the gate's output directory: `make
defconfig-generic-sbc-<isa>-dev+qemu+reclaim`, `make build`, `make qemu`. The
overlay (config/fragments/overlays/reclaim.frag) turns on compression and swap
to a file, starts MEMPRESS.ELF (userspace/tests/mempress) and prints the decision
ring. This script reads that console and the swap file left on the volume the
boot wrote, and holds both to the properties in CHECKS.

A scenario is a kernel selection, a command line and the checks that must go
red with them; `pass` is the row with none. A canary row passes only when its
checks are red and the program got as far as they matter, so a boot that died
early does not read as a canary doing its job.
"""
import math
import os
import re
import signal
import subprocess
import sys
import time

CHECKS = ("attach", "past-ram", "contents", "verdicts", "swap-out", "purge", "pressure", "limit", "at-rest")

# name: (kernel selection, command line, checks that must be red)
SCENARIOS = {
    "pass": ("", "", ()),
    # The content check: a restored page has one bit changed.
    "content-canary": ("restore-flip-canary", "", ("contents",)),
    # The at-rest check: segments leave the kernel unencrypted.
    "at-rest-canary": ("swap-plain-canary", "", ("at-rest",)),
    # The medium changed behind the kernel's back: the tag refuses it, the task dies.
    "medium-canary": ("", "canary=swap-read-flip", ("contents",)),
    "pressure-canary": ("", "canary=reclaim-pressure-skip", ("pressure",)),
    "purge-canary": ("", "canary=reclaim-purge-skip", ("purge",)),
    "verdicts-canary": ("", "canary=decision-skip", ("verdicts",)),
    "break-canary": ("mmap-break-only-canary", "", ("past-ram",)),
    # The one memory kill a budgeted Domain can reach: restores with no back-off
    # outrun the storms and empty the allocator. Its pressure was told first.
    "kill-order": ("", "canary=reclaim-restore-no-wait", ()),
    "kill-order-canary": ("", "canary=reclaim-restore-no-wait,reclaim-pressure-skip", ("kill-order",)),
    # The pinned rows: every Domain counts as a `mem = "locked"` one, to the storm
    # or to swap. What must hold is the refusal (pinned-*), and their own canaries
    # take the gate away, so the refusal's check goes red.
    "pinned-storm": ("", "canary=reclaim-pin-storm", ()),
    "pinned-storm-canary": ("storm-ignore-locked-canary", "canary=reclaim-pin-storm", ("pinned-storm",)),
    "pinned-swap": ("", "canary=reclaim-pin-swap", ()),
    "pinned-swap-canary": ("swap-pinned-canary", "canary=reclaim-pin-swap", ("pinned-swap",)),
}

SEGMENT = 16 * 4096
PROGRAM_ENDED = re.compile(r"\[compmgr\] exit MEMPRESS\.ELF")


def lines_of(console):
    return console.replace("\r", "").replace("\0", "").splitlines()


def decisions(lines):
    """(rule, verdict, subject, n) of every `[DECISION]` line, in order."""
    out = []
    for line in lines:
        m = re.search(r"\[DECISION\] (\S+) (\S+) subject=(\d+) n=(\d+),(\d+),(\d+)", line)
        if m:
            out.append((m.group(1), m.group(2), int(m.group(3)), tuple(int(m.group(i)) for i in (4, 5, 6))))
    return out


def has(lines, text):
    return any(text in line for line in lines)


def first(lines, text):
    return next((i for i, line in enumerate(lines) if text in line), None)


def number(lines, text, key):
    for line in lines:
        if text in line:
            m = re.search(r"\b%s=(\d+)" % key, line)
            if m:
                return int(m.group(1))
    return None


def at_rest(data, swapped):
    """Why the swap file does not look encrypted, or None. Every segment that holds
    anything must be indistinguishable from random: a segment's tail is zeros and
    its headers are plain until the swap layer seals it. Blobs are ciphertext under
    the pool's key already, so looking for the program's bytes could not tell."""
    written = [data[i:i + SEGMENT] for i in range(0, len(data), SEGMENT) if any(data[i:i + SEGMENT])]
    if swapped and not written:
        return "%d swap-outs and no segment on the medium" % swapped
    for k, seg in enumerate(written):
        counts = [0] * 256
        for b in seg:
            counts[b] += 1
        bits = -sum(c / len(seg) * math.log2(c / len(seg)) for c in counts if c)
        if bits < 7.9 or b"\0" * 16 in seg:
            return "segment %d of %d: %.3f bits a byte, zero run: %s" % (k, len(written), bits, b"\0" * 16 in seg)
    return None


def judge(console, ram_mib, swap_file):
    """{check: why} for what the console and the medium do not show."""
    ls = lines_of(console)
    recs = decisions(ls)
    red = {}
    if not has(ls, "[SWAP] file "):
        red["attach"] = "swap never attached (no `[SWAP] file` line)"
    page = number(ls, "[MEMPRESS] start", "page") or 4096
    past = number(ls, "past RAM PASS", "pages")
    if past is None or past * page <= ram_mib * 1024 * 1024:
        red["past-ram"] = "no fill past %d MiB: %s pages" % (ram_mib, past)
    elif number(ls, "[MEMPRESS] filled", "untold") != 0:
        red["past-ram"] = "a program holding back was left waiting: %s" % number(ls, "[MEMPRESS] filled", "untold")
    if not has(ls, "[MEMPRESS] contents PASS") or has(ls, "contents FAIL"):
        red["contents"] = "no `contents PASS`" + (" (contents FAIL)" if has(ls, "contents FAIL") else "")
    stored = sum(n[0] for r, v, _, n in recs if r == "compress" and v == "admit")
    refused = sum(1 for r, v, _, _ in recs if r == "compress" and v == "refuse")
    if stored == 0 or refused == 0:
        red["verdicts"] = "Rule::Compress: %d pages admitted, %d refusals" % (stored, refused)
    out = [n for r, v, _, n in recs if r == "swap-out" and v == "admit"]
    if not out or sum(n[2] for n in out) == 0:
        red["swap-out"] = "no Rule::SwapOut admit with bytes written"
    if not has(ls, "[MEMPRESS] purge control PASS") or not has(ls, "[MEMPRESS] purge PASS") or not any(
        r == "purge" and v == "admit" and s != 0 for r, v, s, _ in recs
    ):
        red["purge"] = "no purge round trip, or no Rule::Purge of the program's object"
    told, kill = first(ls, "[MEMPRESS] event level=1"), first(ls, "Killing user task")
    if told is None or not has(ls, "pressure told at the limit") or not any(r == "mem-pressure" for r, *_ in recs):
        red["pressure"] = "the program was not told its pressure"
    if kill is not None:
        red["limit"] = "a task was killed at line %d" % kill
    elif not has(ls, "[MEMPRESS] limit PASS"):
        red["limit"] = "no `limit PASS`"
    if swap_file is None:
        red["at-rest"] = "no swap file on the volume"
    else:
        why = at_rest(swap_file, len(out))
        if why:
            red["at-rest"] = why
    return red


def judge_pinned(which, console):
    """Why the pinned rows' refusal did not hold, or None. No page of a pinned Domain
    is compressed, or no segment with one written, and a record says it was refused."""
    ls = lines_of(console)
    recs = decisions(ls)
    stored = sum(n[0] for r, v, _, n in recs if r == "compress" and v == "admit")
    refused = sum(1 for r, v, _, _ in recs if r == "compress" and v == "refuse")
    out = sum(n[0] for r, v, _, n in recs if r == "swap-out" and v == "admit")
    swap_refused = sum(1 for r, v, _, _ in recs if r == "swap-out" and v == "refuse")
    if not has(ls, "contents of the partial fill PASS"):
        return "the program did not end with its pages intact"
    if which == "pinned-storm":
        if stored or not refused:
            return "%d pages compressed, %d refusals" % (stored, refused)
    elif not stored or out or not swap_refused:
        return "%d pages compressed, %d segments out, %d refusals" % (stored, out, swap_refused)
    return None


def judge_kill_order(console):
    """Why the first memory kill was not preceded by its pressure, or None."""
    ls = lines_of(console)
    told, kill = first(ls, "[MEMPRESS] event level=1"), first(ls, "Killing user task")
    if kill is None:
        return "no kill: the restores did not outrun the storms"
    if told is None or told > kill:
        return "killed at line %d, told at line %s" % (kill, told)
    return None


def boot(repo, env, cmdline, accel, log, limit):
    """`make qemu` until the program ended, in a process group of its own. Its console."""
    args = ["make", "-C", repo, "qemu", "QEMU_ACCEL=%s" % accel]
    if cmdline:
        args.append("QEMU_CMDLINE=%s" % cmdline)
    with open(log, "wb") as out:
        p = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    marker = os.path.join(os.environ.get("GATE_PGROUP_DIR", ""), str(p.pid)) if os.environ.get("GATE_PGROUP_DIR") else None
    if marker:
        open(marker, "w").close()
    end = time.monotonic() + limit
    try:
        while time.monotonic() < end and p.poll() is None:
            with open(log, "rb") as f:
                text = f.read().decode("utf-8", "replace")
            if PROGRAM_ENDED.search(text):
                # The console task prints the ring every 50 ms: its last records.
                time.sleep(1)
                break
            time.sleep(0.5)
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        if marker:
            os.unlink(marker)
    with open(log, "rb") as f:
        return f.read().decode("utf-8", "replace")


def run(isa, scenario):
    select, cmdline, want_red = SCENARIOS[scenario]
    repo = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
    out_root = os.environ["AZOS_OUT"]
    logs = os.environ.get("CI_LOG_DIR") or os.path.join(out_root, "build")
    os.makedirs(os.path.join(out_root, "build"), exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    cfg = os.path.join(out_root, "build", "reclaim-%s.config" % isa)
    log = os.path.join(logs, "reclaim-%s-%s.log" % (isa, scenario))
    env = dict(os.environ, AZOS_OUT=out_root, KCONFIG_CONFIG=cfg)
    defconfig = "generic-sbc-%s-dev+qemu+reclaim" % isa
    sel = {"riscv64": "RISCV64_SELECT", "aarch64": "AARCH64_SELECT", "x86_64": "X86_64_SELECT"}[isa]
    for goal in (["defconfig-" + defconfig], ["build", "%s=%s" % (sel, select)]):
        with open(log + ".make", "wb") as out:
            r = subprocess.run(["make", "-C", repo] + goal, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
        if r.returncode:
            print("make %s failed; log kept: %s.make" % (goal[0], log))
            return 1
    with open(cfg) as f:
        ram = int(re.search(r"^CONFIG_RAM_SIZE=(\d+)$", f.read(), re.M).group(1))
    accel = "tcg"
    if isa == "aarch64" and subprocess.run([os.path.join(repo, "tools/dev/qemu_hvf.sh")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        accel = "hvf"
    console = boot(repo, env, cmdline, accel, log, int(os.environ.get("RECLAIM_ROW_LIMIT", "600")))
    if scenario.startswith(("pinned-", "kill-order")):
        which = scenario.replace("-canary", "")
        why = judge_kill_order(console) if which == "kill-order" else judge_pinned(which, console)
        if (why is None) == (not want_red):
            print("ok: %s" % (why or "refused, and the pages intact"))
            return 0
        print("%s; log kept: %s" % (why or "a canary that should have gone red did not", log))
        return 1
    volume = os.path.join(out_root, "build", "qemu-%s.img" % isa)
    swap_out = log + ".swap"
    got = subprocess.run(["mcopy", "-n", "-i", volume, "::SWAP.AZS", swap_out], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    data = None
    if got.returncode == 0:
        with open(swap_out, "rb") as f:
            data = f.read()
        os.unlink(swap_out)
    red = judge(console, ram, data)
    missing = [c for c in want_red if c not in red]
    extra = [c for c in red if c not in want_red and not (want_red and c in ("limit", "purge", "pressure", "contents", "verdicts", "swap-out", "past-ram"))]
    for c in sorted(red):
        print("%s: %s" % (c, red[c]))
    if missing or extra:
        print("expected red: %s; missing: %s; unexpected: %s; log kept: %s" % (list(want_red), missing, extra, log))
        return 1
    print("ok: pages=%s swap-outs=%d" % (number(lines_of(console), "past RAM PASS", "pages"),
                                         sum(1 for r, v, *_ in decisions(lines_of(console)) if r == "swap-out" and v == "admit")))
    return 0


GOOD = """[SWAP] file /fat/SWAP.AZS: 8 segment slots to start
[MEMPRESS] start free=100 target=200 chunk=8 page=4096
[MEMPRESS] purge control PASS
[MEMPRESS] event level=1 told=1
[DECISION] mem-pressure admit subject=5 n=1,10,1
[DECISION] purge admit subject=5 n=2,4096,0
[DECISION] compress admit subject=5 n=9,36864,1000
[DECISION] compress refuse subject=5 n=0,0,0
[DECISION] swap-out admit subject=0 n=1,65360,65360
[MEMPRESS] filled pages=70000 target=70000 refused=0 untold=0
[MEMPRESS] past RAM PASS pages=70000 free_at_start=100
[MEMPRESS] contents PASS pages=70000 free_now=9
[MEMPRESS] purge PASS rc=219 waited_ms=0
[MEMPRESS] pressure told at the limit told=4
[MEMPRESS] limit PASS refused=4
"""


def self_test():
    rnd = bytearray()
    x = 88172645463325252
    while len(rnd) < SEGMENT:
        x ^= (x << 13) & (2**64 - 1)
        x ^= x >> 7
        x ^= (x << 17) & (2**64 - 1)
        rnd += x.to_bytes(8, "little")
    rnd = bytes(rnd[:SEGMENT])
    fails = []

    def expect(name, red, console, swap=rnd, ram=128):
        got = set(judge(console, ram, swap))
        if got != set(red):
            fails.append("%s: red %s, expected %s" % (name, sorted(got), sorted(red)))

    expect("a good boot", [], GOOD)
    expect("a tiny fill", ["past-ram"], GOOD, ram=1024)
    expect("a client left waiting", ["past-ram"], GOOD.replace("untold=0", "untold=3"))
    expect("a wrong page", ["contents"], GOOD.replace("contents PASS", "contents FAIL"))
    expect("no refuse verdict", ["verdicts"], GOOD.replace("compress refuse", "compress admit"))
    expect("no swap", ["swap-out"], GOOD.replace("swap-out admit", "swap-out refuse"))
    expect("no purge of the program's", ["purge"], GOOD.replace("purge admit subject=5", "purge admit subject=0"))
    expect("no events", ["pressure"], GOOD.replace("pressure told at the limit", "x"))
    expect("a kill", ["limit"], GOOD + "[PAGE FAULT] Killing user task\n")
    expect("no limit", ["limit"], GOOD.replace("limit PASS", "x"))
    if judge_kill_order(GOOD + "[PAGE FAULT] Killing user task\n"):
        fails.append("a kill after the pressure did not pass")
    if not judge_kill_order("[PAGE FAULT] Killing user task\n" + GOOD):
        fails.append("a kill before the pressure passed")
    if not judge_kill_order(GOOD):
        fails.append("no kill passed")
    expect("no file", ["at-rest"], GOOD, None)
    expect("plain tail", ["at-rest"], GOOD, rnd[:-64] + bytes(64))
    expect("low entropy", ["at-rest"], GOOD, bytes(range(1, 129)) * 512)
    expect("segments and nothing on the medium", ["at-rest"], GOOD, bytes(SEGMENT))
    expect("every segment is looked at", ["at-rest"], GOOD, rnd + rnd[:-64] + bytes(64))
    expect("zero slots are not segments", [], GOOD, rnd + bytes(SEGMENT))
    pin = "[MEMPRESS] contents of the partial fill PASS pages=9\n"
    if judge_pinned("pinned-storm", pin + "[DECISION] compress refuse subject=5 n=0,0,0\n"):
        fails.append("a refused storm did not pass")
    if not judge_pinned("pinned-storm", pin + "[DECISION] compress admit subject=5 n=9,9,9\n[DECISION] compress refuse subject=5 n=0,0,0\n"):
        fails.append("a compressed pinned page passed")
    if judge_pinned("pinned-swap", pin + "[DECISION] compress admit subject=5 n=9,9,9\n[DECISION] swap-out refuse subject=0 n=0,0,0\n"):
        fails.append("a refused swap-out did not pass")
    if not judge_pinned("pinned-swap", pin + "[DECISION] compress admit subject=5 n=9,9,9\n[DECISION] swap-out admit subject=0 n=1,9,9\n"):
        fails.append("a swapped pinned page passed")
    if not judge_pinned("pinned-swap", "[DECISION] compress admit subject=5 n=9,9,9\n[DECISION] swap-out refuse subject=0 n=0,0,0\n"):
        fails.append("a program that did not finish passed")
    for f in fails:
        print("FAIL: " + f)
    print("reclaim_row self-test: %s" % ("FAILED" if fails else "ok"))
    return 1 if fails else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 3 or sys.argv[1] not in ("riscv64", "aarch64", "x86_64") or sys.argv[2] not in SCENARIOS:
        print(__doc__)
        return 2
    return run(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
