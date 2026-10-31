#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""stall_attach.py — attach to a silent AzOS boot and dump what the kernel is doing.

    stall_attach.py args  --isa ISA --dir DIR            QEMU arguments: gdbstub and monitor sockets in DIR
    stall_attach.py watch --isa ISA --elf ELF --log LOG --pid PID --dir DIR --marker ERE --out PREFIX
    stall_attach.py run   --isa ISA --elf ELF --marker ERE --out-dir DIR [--limit S] -- QEMU COMMAND...

A stall is SILENCE_S seconds without a byte on the console while the expected
marker has not been printed. A boot that goes quiet and then reaches the marker
is healthy and never a stall (`stalled`). On a stall the watcher attaches before
anything stops QEMU: it pauses the machine through the monitor socket, dumps,
resumes, waits GAP_S seconds and dumps again. Two dumps tell a hart that spins
from one that idles with work queued.

Each dump holds, per hart: pc, sp, link register, interrupt mask, the symbol
and line of the pc, a stack scan for return addresses, and the task the hart
runs; then the task table, the ready queues, every lock word that is not zero
and the interrupt controller. Addresses and member offsets come from the
kernel ELF (symbol table and DWARF); a KASLR slide comes from the console's
`[KASLR] image slid to` line.

Limits, stated in every dump: the kernel has no frame pointers, so a backtrace
is a scan of the stack for words that point into the kernel text (approximate,
it can list stale return addresses and miss frames of leaf calls); the state
bits of a task are read with the mask of `sched_word` (STATE_MASK below); the
interrupt controllers are read at the bases QEMU reports (`info mtree`).

The gdbstub is started with the monitor so that a person can attach too; the
dumps use the monitor alone (the same commands on every ISA, no gdb for
aarch64 and x86_64 needed). The gdbstub under HVF on arm is not exercised by
the soak rows (they run TCG); see the findings in tools/dev/test_stall_attach.py.
"""
import argparse
import bisect
import concurrent.futures
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401

import symbolize_bt  # noqa: E402

SILENCE_S = 20
GAP_S = 10
STATE_MASK = 7
STATES = {0: "Ready", 1: "Running", 2: "Blocked", 3: "Zombie", 4: "Invalid"}
WAITS = {0: "None", 1: "Ring", 2: "Timer", 3: "Port", 4: "WaitQueue", 5: "FastIpcServer", 6: "FastIpcClient"}
LLVM_BIN = ["/opt/homebrew/opt/llvm/bin"]
SCAN_BYTES = 16384
SCAN_KEEP = 20
LOCK_CAP = 600
MON_PROMPT = b"(qemu)"


def stalled(now, last_output, marker_seen, silence=SILENCE_S):
    return (not marker_seen) and now - last_output >= silence


def never_stalled(now, last_output, marker_seen, silence=SILENCE_S):
    return False


class Silence:
    """Feeds `decide` with what the console showed: bytes reset the clock, the marker disarms it."""

    def __init__(self, now, marker, silence=SILENCE_S, decide=stalled):
        self.marker = re.compile(marker, re.M)
        self.silence, self.decide = silence, decide
        self.last, self.seen, self.tail = now, False, ""

    def feed(self, now, text):
        if text:
            self.last = now
            if not self.seen:
                joined = self.tail + text.replace("\r", "")
                self.seen = self.marker.search(joined) is not None
                self.tail = joined[joined.rfind("\n") + 1:]
        return self.decide(now, self.last, self.seen, self.silence)


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def find_tool(names):
    for n in names:
        p = shutil.which(n) or next((os.path.join(d, n) for d in LLVM_BIN if os.access(os.path.join(d, n), os.X_OK)), None)
        if p:
            return p
    return None


# ---- the kernel ELF -------------------------------------------------------------------------

NM_LINE = re.compile(r"^([0-9a-fA-F]+) (?:([0-9a-fA-F]+) )?([A-Za-z?]) (.*)$")


class Elf:
    def __init__(self, path):
        self.path = path
        nm = find_tool(["llvm-nm"])
        if nm is None:
            raise RuntimeError("no llvm-nm (looked on PATH and in %s)" % " ".join(LLVM_BIN))
        out = subprocess.run([nm, "-C", "-S", "--defined-only", path], capture_output=True, text=True).stdout
        self.data, text = {}, []
        for line in out.splitlines():
            m = NM_LINE.match(line)
            if not m:
                continue
            addr, size, kind, name = int(m.group(1), 16), int(m.group(2) or "0", 16), m.group(3), m.group(4)
            name = re.sub(r"::h[0-9a-f]{16}$", "", name)
            if kind in "TtWw":
                if not name.startswith((".", "$")):
                    text.append((addr, name))
            elif kind in "DdBbRr":
                self.data[name] = (addr, size)
        text.sort()
        self.text_addrs = [a for a, _ in text]
        self.text_names = [n for _, n in text]
        self.text_start = symbolize_bt.elf_symbol(path, "_text_start")

    def static(self, suffix):
        """(address, size) of the data symbol whose path is `suffix` (`scheduler::TASKS`), or None."""
        for name, v in self.data.items():
            if name == suffix or name.endswith("::" + suffix):
                return v
        return None

    def statics(self):
        return self.data

    def symbol(self, addr, slide):
        u = addr - slide
        i = bisect.bisect_right(self.text_addrs, u) - 1
        if i < 0:
            return None
        return self.text_names[i], u - self.text_addrs[i]

    def in_text(self, addr, slide):
        u = addr - slide
        return bool(self.text_addrs) and self.text_addrs[0] <= u < self.text_addrs[-1] + 0x1000


def short(sym):
    if not sym:
        return "?"
    name = sym[0]
    parts = name.split("::")
    return "%s+%#x" % ("::".join(parts[-3:]) if len(parts) > 3 else name, sym[1])


DIE = re.compile(r"^(0x[0-9a-f]+):( *)(DW_TAG_\w+)")
ATTR = re.compile(r"^\s+(DW_AT_\w+)\s+\((.*)\)$")


def struct_layouts(elf, names=(), regex=None):
    """[{name, size, members: {name: offset}}] for the structures called `names`, or whose name matches `regex` (DWARF).
    A name lookup uses the index and takes a second; a regex scans every entry and takes ten."""
    dd = find_tool(["llvm-dwarfdump"])
    if dd is None:
        return []
    flags = ["--name=" + n for n in names] if names else ["--name=" + regex, "--regex"]
    out = subprocess.run([dd, *flags, "--show-children", elf], capture_output=True, text=True).stdout
    found, cur, member = [], None, None
    for line in out.splitlines():
        m = DIE.match(line)
        if m:
            tag, depth = m.group(3), len(m.group(2))
            member = None
            if tag == "DW_TAG_structure_type":
                cur = {"name": None, "size": 0, "members": {}, "depth": depth}
                found.append(cur)
            elif tag == "DW_TAG_member" and cur is not None and depth > cur["depth"]:
                member = {"name": None}
            elif cur is not None and depth <= cur["depth"]:
                cur = None
            continue
        a = ATTR.match(line)
        if not a or cur is None:
            continue
        key, val = a.groups()
        if member is not None:
            if key == "DW_AT_name":
                member["name"] = val.strip('"')
            elif key == "DW_AT_data_member_location" and member["name"]:
                cur["members"][member["name"]] = int(val, 0)
        elif key == "DW_AT_name" and cur["name"] is None:
            cur["name"] = val.strip('"')
        elif key == "DW_AT_byte_size":
            cur["size"] = int(val, 0)
    return [s for s in found if s["name"]]


def layout(elf, name, needs):
    for s in struct_layouts(elf.path, [name]):
        if all(n in s["members"] for n in needs):
            return s
    return None


# ---- the machine, through the monitor ---------------------------------------------------------

class Monitor:
    def __init__(self, path, scratch, timeout=10.0):
        self.s = socket.socket(socket.AF_UNIX)
        self.s.settimeout(timeout)
        self.s.connect(path)
        self.scratch = scratch
        self.cpu = 0
        self.ncpu = 1
        self._read(b"")

    def _read(self, echo):
        buf = b""
        try:
            while True:
                d = self.s.recv(65536)
                if not d:
                    break
                buf += d
                plain = re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", buf).replace(b"\r", b"")
                if plain.rstrip().endswith(MON_PROMPT) and (not echo or plain.count(b"\n") >= 1):
                    break
        except socket.timeout:
            pass
        return re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", buf).replace(b"\r", b"").decode(errors="replace")

    def cmd(self, c):
        self.s.sendall(c.encode() + b"\n")
        text = self._read(c.encode())
        lines = [l for l in text.split("\n") if not l.startswith("(qemu)") and not self._echo(l, c)]
        return "\n".join(lines)

    @staticmethod
    def _echo(line, c):
        return line.endswith(c) and len(line) >= len(c) and line.lstrip().startswith(c[:1])

    def select(self, cpu):
        if cpu != self.cpu:
            self.cmd("cpu %d" % cpu)
            self.cpu = cpu

    def read(self, addr, n):
        f = os.path.join(self.scratch, "mem.bin")
        for cpu in [self.cpu] + [c for c in range(self.ncpu) if c != self.cpu]:
            if cpu != self.cpu:
                self.select(cpu)
            if os.path.exists(f):
                os.unlink(f)
            self.cmd('memsave %#x %d "%s"' % (addr, n, f))
            if os.path.exists(f):
                with open(f, "rb") as fh:
                    data = fh.read()
                os.unlink(f)
                if len(data) == n:
                    return data
        return None


def words(text, width=8):
    return [int(w, 16) for w in re.findall(r"\b0x([0-9a-f]{%d})\b" % width, text)]


# ---- per ISA: registers, interrupt mask, interrupt controller ---------------------------------

def parse_aarch64(block):
    g = lambda r: int((re.search(r"\b%s=([0-9a-f]+)" % r, block) or [0, "0"])[1], 16)
    ps = re.search(r"PSTATE=([0-9a-f]+) (\S+) (EL\w+)", block)
    pstate = int(ps.group(1), 16) if ps else 0
    masked = "".join(c for c, bit in (("D", 9), ("A", 8), ("I", 7), ("F", 6)) if pstate >> bit & 1)
    return {"pc": g("PC"), "sp": g("SP"), "lr": g("X30"),
            "mode": "%s, masked: %s" % (ps.group(3) if ps else "?", masked or "none"),
            "kernel": bool(ps and ps.group(3).startswith("EL1")), "halted": None}


def parse_riscv64(block):
    regs = {m.group(1): int(m.group(2), 16) for m in re.finditer(r"(?:x\d+/)?(\w+)\s+([0-9a-f]{16})\b", block)}
    s = regs.get("sstatus", 0)
    return {"pc": regs.get("pc", 0), "sp": regs.get("sp", 0), "lr": regs.get("ra", 0),
            "mode": "SIE=%d sie=%#x sip=%#x scause=%#x satp=%#x" % (s >> 1 & 1, regs.get("sie", 0), regs.get("sip", 0),
                                                                    regs.get("scause", 0), regs.get("satp", 0)),
            "kernel": True, "halted": None}


def parse_x86_64(block):
    g = lambda r: int((re.search(r"\b%s=([0-9a-f]+)" % r, block) or [0, "0"])[1], 16)
    hlt = re.search(r"HLT=(\d)", block)
    efl = g("RFL") or g("EFL")
    cpl = re.search(r"CPL=(\d)", block)
    return {"pc": g("RIP") or g("EIP"), "sp": g("RSP") or g("ESP"), "lr": 0,
            "mode": "CPL=%s IF=%d" % (cpl.group(1) if cpl else "?", efl >> 9 & 1),
            "kernel": not cpl or cpl.group(1) == "0", "halted": bool(hlt and hlt.group(1) == "1")}


PARSERS = {"aarch64": parse_aarch64, "riscv64": parse_riscv64, "x86_64": parse_x86_64}


def region(mtree, name):
    m = re.search(r"([0-9a-f]+)-([0-9a-f]+) \(prio \d+, \S+\): %s" % re.escape(name), mtree)
    return (int(m.group(1), 16), int(m.group(2), 16) + 1) if m else None


def irq_aarch64(mon, ncpu):
    mt = mon.cmd("info mtree -f")
    d, r = region(mt, "gicv3_dist"), region(mt, "gicv3_redist_region[0]")
    if not d:
        return ["GIC: no gicv3_dist region in `info mtree` (not a GICv3 machine)"]
    out = ["GICD at %#x: ISENABLER/ISPENDR/ISACTIVER (irq 0..255)" % d[0]]
    for label, off in (("ISENABLER", 0x100), ("ISPENDR", 0x200), ("ISACTIVER", 0x300)):
        out.append("  %-9s %s" % (label, " ".join("%08x" % w for w in words(mon.cmd("xp /8wx %#x" % (d[0] + off))))))
    if r:
        out.append("GICR at %#x: SGI frame ISENABLER0/ISPENDR0/ISACTIVER0 per hart" % r[0])
        for c in range(ncpu):
            base = r[0] + c * 0x20000 + 0x10000
            v = [words(mon.cmd("xp /1wx %#x" % (base + off)))[:1] for off in (0x100, 0x200, 0x300)]
            out.append("  hart %d: %s" % (c, " ".join("%08x" % x[0] if x else "?" for x in v)))
    return out


def irq_riscv64(mon, ncpu):
    p = region(mon.cmd("info mtree -f"), "riscv.sifive.plic")
    if not p:
        return ["PLIC: no riscv.sifive.plic region in `info mtree` (an AIA machine: not dumped)"]
    out = ["PLIC at %#x: pending, then per hart S-mode context enable and threshold" % p[0]]
    out.append("  pending   %s" % " ".join("%08x" % w for w in words(mon.cmd("xp /3wx %#x" % (p[0] + 0x1000)))))
    for h in range(ncpu):
        ctx = 2 * h + 1
        en = words(mon.cmd("xp /3wx %#x" % (p[0] + 0x2000 + ctx * 0x80)))
        th = words(mon.cmd("xp /1wx %#x" % (p[0] + 0x200000 + ctx * 0x1000)))
        out.append("  hart %d: enable %s threshold %s" % (h, " ".join("%08x" % w for w in en), "%08x" % th[0] if th else "?"))
    return out


def irq_x86_64(mon, ncpu):
    out = []
    for c in range(ncpu):
        mon.select(c)
        t = mon.cmd("info lapic")
        keep = [l for l in t.split("\n") if re.match(r"(SPIV|ISR|IRR|LVTT|Timer|APR|dumping)", l)]
        out.append("LAPIC cpu %d: " % c + " | ".join(l.strip() for l in keep))
    mon.select(0)
    out.append("PIC/IOAPIC: " + " ".join(mon.cmd("info pic").split()))
    return out


IRQ = {"aarch64": irq_aarch64, "riscv64": irq_riscv64, "x86_64": irq_x86_64}


# ---- the dump ---------------------------------------------------------------------------------

class Dumper:
    def __init__(self, isa, elf, mon, slide, addr2line=None):
        self.isa, self.elf, self.mon, self.slide = isa, elf, mon, slide
        self.addr2line = addr2line
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            remote = pool.submit(struct_layouts, elf.path, (), r"^PerCpuRemote<.*ReadyList.*>$")
            found = struct_layouts(elf.path, ("Task", "WaitCell", "PerCpuSched", "ReadyList")) + remote.result()

        def pick(name, needs):
            return next((x for x in found if (x["name"] == name or name.endswith("<") and x["name"].startswith(name))
                         and all(n in x["members"] for n in needs)), None)

        self.task = pick("Task", ("tid", "state_word", "name", "wait_reason", "priority", "cpu_affinity"))
        self.wait = pick("WaitCell", ("tag", "payload"))
        self.percpu = pick("PerCpuSched", ("current_idx",))
        self.ready = pick("ReadyList", ("head", "tail", "count"))
        self.remote = pick("PerCpuRemote<", ("ptrs",))

    def line(self, addr):
        if not self.addr2line:
            return ""
        fr = symbolize_bt.lookup(self.addr2line, self.elf.path, addr - self.slide)
        return " at %s" % fr[0][1].rsplit("/", 1)[-1] if fr and not symbolize_bt.unresolved(fr[0][1]) else ""

    def sym(self, addr):
        return short(self.elf.symbol(addr, self.slide))

    def stack_scan(self, sp):
        data = b""
        while len(data) < SCAN_BYTES:
            room = 4096 - ((sp + len(data)) & 4095)
            chunk = self.mon.read(sp + len(data), room)
            if chunk is None:
                break
            data += chunk
        found = []
        for o in range(0, len(data) - 7, 8):
            v = int.from_bytes(data[o:o + 8], "little")
            if self.elf.in_text(v, self.slide):
                found.append(v)
        return found[:SCAN_KEEP], len(data)

    def tasks(self):
        t = self.task
        sym = self.elf.static("scheduler::TASKS")
        if not (t and sym):
            return None, []
        n = sym[1] // t["size"]
        raw = self.mon.read(sym[0], n * t["size"])
        if raw is None:
            return None, []
        out = {}
        for i in range(n):
            b = raw[i * t["size"]:(i + 1) * t["size"]]
            o = t["members"]["name"]
            name = b[o:o + 32].split(b"\0")[0].decode(errors="replace")
            if not name:
                continue
            u32 = lambda off: int.from_bytes(b[off:off + 4], "little")
            wo = t["members"]["wait_reason"]
            out[i] = {"tid": u32(t["members"]["tid"]), "name": name, "word": u32(t["members"]["state_word"]),
                      "prio": u32(t["members"]["priority"]),
                      "aff": int.from_bytes(b[t["members"]["cpu_affinity"]:t["members"]["cpu_affinity"] + 1], "little", signed=True),
                      "wtag": u32(wo + self.wait["members"]["tag"]) if self.wait else 0,
                      "wval": int.from_bytes(b[wo + self.wait["members"]["payload"]:wo + self.wait["members"]["payload"] + 8], "little") if self.wait else 0}
        return n, out

    def describe(self, t):
        st = t["word"] & STATE_MASK
        return "%s tid=%d %s pr=%d aff=%d wait=%s(%#x)" % (
            t["name"], t["tid"], STATES.get(st, "state?%d" % st), t["prio"], t["aff"], WAITS.get(t["wtag"], "tag?%d" % t["wtag"]), t["wval"])

    def hart_blocks(self):
        text = self.mon.cmd("info registers -a")
        parts = re.split(r"CPU#(\d+)", text)[1:]
        blocks = [(int(h), b) for h, b in zip(parts[0::2], parts[1::2])]
        self.mon.ncpu = max(1, len(blocks))
        return blocks

    def dump(self, tag, extra=""):
        o = []
        P = o.append
        P("==== %s  %s  isa %s  slide %#x  %s" % (tag, time.strftime("%H:%M:%S"), self.isa, self.slide, extra))
        P("elf %s" % self.elf.path)
        P("approximate: this build has no frame pointers, so the stack lines are scans for kernel text addresses, not a backtrace")
        harts = self.hart_blocks()
        ntasks, tasks = self.tasks()
        cur = {}
        ps = self.elf.static("scheduler::PER_CPU")
        if ps and self.percpu:
            stride = self.percpu["size"]
            raw = self.mon.read(ps[0], stride * len(harts))
            for h in range(len(harts)):
                if raw:
                    cur[h] = int.from_bytes(raw[h * stride + self.percpu["members"]["current_idx"]:][:8], "little")
        for h, block in harts:
            r = PARSERS[self.isa](block)
            where = "%s%s" % (self.sym(r["pc"]), self.line(r["pc"])) if self.elf.in_text(r["pc"], self.slide) else "not in the kernel image"
            P("hart %d: pc=%#x %s  sp=%#x%s  [%s]%s" % (h, r["pc"], where, r["sp"],
              "  lr=%#x %s" % (r["lr"], self.sym(r["lr"])) if r["lr"] else "", r["mode"],
              " HALTED" if r["halted"] else ""))
            if r["kernel"] and self.elf.in_text(r["pc"], self.slide):
                scan, got = self.stack_scan(r["sp"])
                P("  stack scan (approximate, %d bytes read): %s" % (got, " < ".join(self.sym(v) for v in scan) or "(nothing)"))
            t = tasks.get(cur.get(h))
            P("  current task: %s" % (("idx %d " % cur[h] + self.describe(t)) if t else "idx %s (not in the table)" % cur.get(h, "?")))
        if ntasks is None:
            P("task table: not decoded (%s)" % ("no TASKS symbol in the ELF" if not self.elf.static("scheduler::TASKS")
              else "no DWARF layout of Task, or the read failed"))
        else:
            P("task table (%d slots, %d in use):" % (ntasks, len(tasks)))
            for i, t in sorted(tasks.items()):
                P("  %3d %s%s" % (i, self.describe(t), "  STAMP" if t["word"] & ~STATE_MASK & 8 else ""))
        self.queues(o, len(harts))
        self.locks(o)
        P("interrupt controller:")
        for l in IRQ[self.isa](self.mon, len(harts)):
            P("  " + l)
        return "\n".join(o) + "\n"

    def queues(self, o, ncpu):
        q = self.elf.static("scheduler::PER_CPU_QUEUES")
        if not (q and self.remote and self.ready):
            o.append("ready queues: not decoded (no PER_CPU_QUEUES symbol or no DWARF layout)")
            return
        n = int(re.search(r"; (\d+)\]", self.remote["name"]).group(1))
        size = self.ready["size"]
        o.append("ready queues (per hart, priorities with a task):")
        for c in range(ncpu):
            p = self.mon.read(q[0] + self.remote["members"]["ptrs"] + 8 * c, 8)
            ptr = int.from_bytes(p, "little") if p else 0
            raw = self.mon.read(ptr, n * size) if ptr else None
            if raw is None:
                o.append("  hart %d: area pointer %#x unreadable" % (c, ptr))
                continue
            busy = []
            for k in range(n):
                b = raw[k * size:(k + 1) * size]
                cnt = int.from_bytes(b[self.ready["members"]["count"]:][:4], "little")
                if cnt:
                    busy.append("prio %d count %d head %d" % (k, cnt, int.from_bytes(b[self.ready["members"]["head"]:][:4], "little", signed=True)))
            o.append("  hart %d: %s" % (c, "; ".join(busy) or "empty"))
        ps = self.elf.static("scheduler::PER_CPU")
        if ps and self.percpu and "ready_bitmap" in self.percpu["members"]:
            raw = self.mon.read(ps[0], self.percpu["size"] * ncpu)
            if raw:
                o.append("  ready_bitmap per hart: " + " ".join("%#x" % int.from_bytes(
                    raw[h * self.percpu["size"] + self.percpu["members"]["ready_bitmap"]:][:4], "little") for h in range(ncpu)))

    def locks(self, o):
        held, zero, seen = [], 0, 0
        for name, (addr, size) in sorted(self.elf.statics().items()):
            last = re.sub(r" \(.*\)$", "", name.split("::")[-1])
            if not re.search(r"(^|_)LOCKS?$", last) or not 0 < size <= 256:
                continue
            seen += 1
            if seen > LOCK_CAP:
                break
            b = self.mon.read(addr, size)
            if b is None:
                held.append("%s unreadable" % name)
            elif any(b):
                held.append("%s @%#x = %s%s" % (name, addr + self.slide, b[:48].hex(), " ... (%d bytes)" % size if size > 48 else ""))
            else:
                zero += 1
        o.append("lock words (statics named *_LOCK or *_LOCKS, up to 256 B): %d zero, %d not zero%s" % (zero, len(held), ":" if held else ""))
        o.extend("  " + h for h in held)
        if not self.elf.static("PI_HELD_ADDR"):
            o.append("PI_HELD_ADDR: not in this ELF (the table is compiled out of this build)")


# ---- the watcher ------------------------------------------------------------------------------

def slide_from(log_text, elf):
    m = None
    for m in re.finditer(r"\[KASLR\] image slid to (0x[0-9a-fA-F]+)", log_text):
        pass
    if m is None or elf.text_start is None:
        return 0, "no KASLR line in the console: slide 0"
    return int(m.group(1), 16) - elf.text_start, "slide from the console's KASLR line"


def attach_args(isa, d):
    return ["-monitor", "unix:%s,server=on,wait=off" % os.path.join(d, "m"),
            "-gdb", "unix:%s,server=on,wait=off" % os.path.join(d, "g")]


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        return os.waitpid(pid, os.WNOHANG) == (0, 0)
    except ChildProcessError:
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        return bool(state) and not state.startswith("Z")


def take_dumps(isa, elf_path, d, log, prefix, tag_prefix=""):
    scratch = os.path.join(d, "scratch")
    os.makedirs(scratch, exist_ok=True)
    mon = Monitor(os.path.join(d, "m"), scratch)
    elf = Elf(elf_path)
    with open(log, errors="replace") as f:
        slide, how = slide_from(f.read(), elf)
    d2l = symbolize_bt.find_addr2line(symbolize_bt.ADDR2LINE)
    dumper = Dumper(isa, elf, mon, slide, d2l)
    paths = []
    try:
        for k, name in enumerate(("a", "b")):
            if k:
                time.sleep(GAP_S)
            mon.cmd("stop")
            try:
                text = dumper.dump(tag_prefix + "dump " + name, how)
            finally:
                mon.cmd("cont")
            path = "%s.stall-%s.txt" % (prefix, name)
            write(path, text)
            paths.append(path)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return paths


def watch(isa, elf_path, d, log, pid, marker, prefix, silence=SILENCE_S, decide=stalled, limit=None, poll=0.5):
    """Returns ("stalled", dumps), ("marker", []) or ("exited", []). The verdict is also written to PREFIX.stall-verdict."""
    clock = Silence(time.time(), marker, silence, decide)
    pos, dumps, t0 = 0, [], time.time()
    verdict = "exited"
    while alive(pid):
        try:
            with open(log, "rb") as f:
                f.seek(pos)
                new = f.read()
        except OSError:
            new = b""
        pos += len(new)
        now = time.time()
        hit = clock.feed(now, new.decode(errors="replace"))
        if hit and not dumps:
            write(prefix + ".stall-busy", "")
            try:
                dumps = take_dumps(isa, elf_path, d, log, prefix)
            except Exception as e:  # a watcher that dies leaves the row without its dumps: the error is the dump
                write(prefix + ".stall-error.txt", "attach failed: %s\n" % e)
                dumps = [prefix + ".stall-error.txt"]
            finally:
                os.unlink(prefix + ".stall-busy")
            clock.last = time.time()
        if limit and now - t0 > limit:
            break
        time.sleep(poll)
    if dumps and clock.seen:
        for p in dumps:
            os.unlink(p)
        dumps = []
        verdict = "marker"
    elif dumps:
        verdict = "stalled"
    elif clock.seen:
        verdict = "marker"
    write(prefix + ".stall-verdict", verdict + "\n")
    return verdict, dumps


def cmd_run(a, qemu):
    os.makedirs(a.out_dir, exist_ok=True)
    d = a.out_dir
    for n in ("m", "g"):
        if os.path.exists(os.path.join(d, n)):
            os.unlink(os.path.join(d, n))
    log = os.path.join(d, "console.log")
    with open(log, "wb") as lf:
        p = subprocess.Popen(qemu + attach_args(a.isa, d), stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT,
                             start_new_session=True)
    try:
        verdict, dumps = watch(a.isa, a.elf, d, log, p.pid, a.marker, os.path.join(d, "run"),
                               decide=never_stalled if a.canary_never_stall else stalled, limit=a.limit)
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
    print("stall_attach: %s; console %s" % (verdict, log))
    for x in dumps:
        print("stall_attach: dump %s" % x)
    return 1 if verdict == "stalled" else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("args", "watch", "run"):
        s = sub.add_parser(name)
        s.add_argument("--isa", required=True, choices=sorted(PARSERS))
        if name == "args":
            s.add_argument("--dir", required=True)
            continue
        s.add_argument("--elf", required=True)
        s.add_argument("--marker", required=True)
        s.add_argument("--canary-never-stall", action="store_true", help="gate canary: the stall decision never fires")
        if name == "watch":
            s.add_argument("--dir", required=True)
            s.add_argument("--log", required=True)
            s.add_argument("--pid", type=int, required=True)
            s.add_argument("--out", required=True)
            s.add_argument("--limit", type=float)
        else:
            s.add_argument("--out-dir", required=True)
            s.add_argument("--limit", type=float, default=300)
    a, rest = ap.parse_known_args(argv)
    if a.mode == "args":
        print(" ".join(attach_args(a.isa, a.dir)))
        return 0
    if a.mode == "run":
        return cmd_run(a, [r for r in rest if r != "--"])
    verdict, dumps = watch(a.isa, a.elf, a.dir, a.log, a.pid, a.marker, a.out,
                           decide=never_stalled if a.canary_never_stall else stalled, limit=a.limit)
    print("%s %s" % (verdict, " ".join(dumps)))
    return 1 if verdict == "stalled" else 0


if __name__ == "__main__":
    sys.exit(main())
