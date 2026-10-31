#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_stall_attach.py — host tests of tools/dev/stall_attach.py.

The stall decision (silence with no marker is a stall; silence after the
marker is not; output before the limit resets the clock), the watcher's
verdicts around it, and a dump of a small aarch64 ELF with the scheduler's
type and symbol names against a monitor that serves memory from a dictionary.
No QEMU: the gate's `stall attach` rows attach to real kernels.

Findings on the gdbstub under HVF (aarch64 macOS host, QEMU 11): see the commit
message of the change that added this file.

Run with:
    python3 tools/dev/test_stall_attach.py
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401

import stall_attach  # noqa: E402
import symbolize_bt  # noqa: E402
import test_debug  # noqa: E402

SOURCE = """\
struct WaitCell { unsigned tag; unsigned long long payload; };
struct Task {
    unsigned long context[3];
    unsigned tid;
    unsigned state_word;
    unsigned priority;
    unsigned base_priority;
    signed char cpu_affinity;
    char name[32];
    struct WaitCell wait_reason;
};
struct PerCpuSched { unsigned long current_idx; unsigned ready_bitmap; };
struct Task TASKS[4] __asm__("azos_sched::scheduler::TASKS");
struct PerCpuSched PER_CPU[2] __asm__("azos_sched::scheduler::PER_CPU");
unsigned CPU_LOCKS[2] __asm__("azos_sched::scheduler::CPU_LOCKS");
unsigned POOL_LOCK __asm__("azos_sched::scheduler::POOL_LOCK");
unsigned long CLOCK_NOW __asm__("azos_decision::CLOCK_NOW") = 5;
unsigned BLOCK_FN __asm__("azos_sync::BLOCK_FN") = 7;
void idle(void) { for (;;) {} }
void work(void) { idle(); }
void _start(void) { work(); }
"""
LINK = test_debug.LINK


def build_elf(tmp):
    src, obj, elf = (os.path.join(tmp, n) for n in ("k.c", "k.o", "k.elf"))
    test_debug.write(src, SOURCE)
    subprocess.run(["clang", "--target=aarch64-none-elf", "-g", "-O0", "-ffreestanding", "-fno-pic", "-c", src, "-o", obj],
                   check=True, capture_output=True)
    subprocess.run([test_debug.rust_lld(), "-flavor", "gnu", "-Ttext=0x%x" % LINK, "--defsym=_text_start=0x%x" % LINK,
                    "-e", "_start", "-o", elf, obj], check=True, capture_output=True)
    return elf


class FakeMonitor:
    def __init__(self, regs, mem):
        self.regs, self.mem, self.ncpu, self.log = regs, mem, 2, []

    def cmd(self, c):
        self.log.append(c)
        if c == "info registers -a":
            return self.regs
        if c.startswith("info mtree"):
            return "  0000000008000000-000000000800ffff (prio 0, i/o): gicv3_dist\n"
        if c.startswith("xp /"):
            return "0000000008000100: 0x0000000a 0x00000000 0x00000000 0x00000000\n"
        return ""

    def select(self, cpu):
        self.log.append("cpu %d" % cpu)

    def read(self, addr, n):
        for base, data in self.mem.items():
            if base <= addr and addr + n <= base + len(data):
                return bytes(data[addr - base:addr - base + n])
        return None


def aarch64_regs(pc0, sp0, pc1, sp1):
    def block(h, pc, sp):
        return ("\nCPU#%d\n PC=%016x X00=0000000000000000\nX29=0000000000000000 X30=%016x  SP=%016x\n"
                "PSTATE=00000000600003c5 -ZC- EL1h  SVCR=00000000 --\n" % (h, pc, pc, sp))
    return block(0, pc0, sp0) + block(1, pc1, sp1) + "(qemu)"


@unittest.skipUnless(shutil.which("clang") and test_debug.rust_lld() and stall_attach.find_tool(["llvm-nm"])
                     and stall_attach.find_tool(["llvm-dwarfdump"]),
                     "needs clang, rust-lld, llvm-nm and llvm-dwarfdump")
class Dump(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.elf = build_elf(cls.tmp)
        cls.E = stall_attach.Elf(cls.elf)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def addr(self, name):
        return symbolize_bt.elf_symbol(self.elf, name)

    def machine(self, slide=0, lock=0):
        t = stall_attach.layout(self.E, "Task", ("tid", "name"))
        tasks = bytearray(4 * t["size"])

        def put(i, tid, name, st, wtag, wval):
            b = bytearray(t["size"])
            m = t["members"]
            struct.pack_into("<I", b, m["tid"], tid)
            struct.pack_into("<I", b, m["state_word"], st)
            struct.pack_into("<I", b, m["priority"], 7)
            struct.pack_into("<b", b, m["cpu_affinity"], -1)
            b[m["name"]:m["name"] + len(name)] = name
            struct.pack_into("<I", b, m["wait_reason"], wtag)
            struct.pack_into("<Q", b, m["wait_reason"] + 8, wval)
            tasks[i * t["size"]:(i + 1) * t["size"]] = b

        put(0, 1, b"idle0", 1, 0, 0)
        put(2, 5, b"shell", 2, 1, 0x30)
        pc = self.addr("idle") + 4 + slide
        mem = {self.addr("azos_sched::scheduler::TASKS"): tasks,
               self.addr("azos_sched::scheduler::PER_CPU"): bytearray(16 * 2),
               self.addr("azos_sched::scheduler::CPU_LOCKS"): bytearray(8),
               self.addr("azos_sched::scheduler::POOL_LOCK"): bytearray(struct.pack("<I", lock)),
               0xffff0000: bytearray(struct.pack("<QQQQ", 0x1234, self.addr("work") + 8 + slide, 0, self.addr("_start") + 4 + slide)).ljust(4096, b"\0")}
        pcs = self.E.statics()
        per = stall_attach.layout(self.E, "PerCpuSched", ("current_idx",))
        struct.pack_into("<Q", mem[self.addr("azos_sched::scheduler::PER_CPU")], per["members"]["current_idx"], 0)
        struct.pack_into("<Q", mem[self.addr("azos_sched::scheduler::PER_CPU")], per["size"] + per["members"]["current_idx"], 2)
        self.assertIn("azos_sched::scheduler::TASKS", pcs)
        return FakeMonitor(aarch64_regs(pc, 0xffff0000, pc, 0xffff0000), mem)

    def dump(self, mon, slide=0):
        return stall_attach.Dumper("aarch64", self.E, mon, slide, symbolize_bt.find_addr2line()).dump("dump a")

    def test_harts_are_symbolized_with_the_pc_function_and_the_stack_scan(self):
        out = self.dump(self.machine())
        self.assertRegex(out, r"hart 0: pc=0x[0-9a-f]+ idle\+0x4 at .*k\.c:\d+")
        self.assertIn("stack scan (approximate", out)
        self.assertRegex(out, r"stack scan[^\n]*work\+0x8 < _start\+0x4")
        self.assertIn("approximate: this build has no frame pointers", out)

    def test_task_table_and_current_task_come_from_the_dwarf_layout(self):
        out = self.dump(self.machine())
        self.assertIn("current task: idx 0 idle0 tid=1 Running", out)
        self.assertIn("current task: idx 2 shell tid=5 Blocked pr=7 aff=-1 wait=Ring(0x30)", out)
        self.assertIn("task table (4 slots, 2 in use)", out)

    def test_a_slid_kernel_is_symbolized_at_the_slide(self):
        out = self.dump(self.machine(slide=0x200000), slide=0x200000)
        self.assertRegex(out, r"hart 0: pc=0x[0-9a-f]+ idle\+0x4")
        out = self.dump(self.machine(slide=0x200000), slide=0)
        self.assertIn("not in the kernel image", out)

    def test_only_lock_words_that_are_not_zero_are_listed(self):
        clean = self.dump(self.machine())
        self.assertIn("lock words (statics named *_LOCK or *_LOCKS, up to 256 B): 2 zero, 0 not zero", clean)
        held = self.dump(self.machine(lock=0x80000002))
        self.assertIn("1 zero, 1 not zero", held)
        self.assertRegex(held, r"POOL_LOCK @0x[0-9a-f]+ = 02000080")

    def test_clock_and_block_names_are_not_lock_words(self):
        out = self.dump(self.machine(lock=1))
        self.assertNotIn("CLOCK_NOW", out)
        self.assertNotIn("BLOCK_FN", out)

    def test_a_missing_table_is_said_not_guessed(self):
        out = self.dump(self.machine())
        self.assertIn("PI_HELD_ADDR: not in this ELF", out)
        self.assertIn("ready queues: not decoded", out)

    def test_the_interrupt_controller_is_read_where_qemu_reports_it(self):
        out = self.dump(self.machine())
        self.assertIn("GICD at 0x8000000", out)
        self.assertIn("ISENABLER 0000000a", out)


class Decision(unittest.TestCase):
    def test_silence_with_no_marker_is_a_stall(self):
        c = stall_attach.Silence(0, r"^MARK$")
        self.assertFalse(c.feed(19.9, ""))
        self.assertTrue(c.feed(20, ""))

    def test_silence_after_the_marker_is_not_a_stall(self):
        c = stall_attach.Silence(0, r"^MARK$")
        self.assertFalse(c.feed(5, "boot\nMARK\n"))
        self.assertFalse(c.feed(500, ""))

    def test_output_before_the_limit_resets_the_clock(self):
        c = stall_attach.Silence(0, r"^MARK$")
        self.assertFalse(c.feed(19, "x"))
        self.assertFalse(c.feed(38.9, ""))
        self.assertTrue(c.feed(39, ""))

    def test_a_marker_split_over_two_reads_is_seen(self):
        c = stall_attach.Silence(0, r"^# ktest: [0-9]+ tests")
        c.feed(1, "boot\n# kte")
        c.feed(2, "st: 12 tests\n")
        self.assertFalse(c.feed(100, ""))

    def test_a_marker_in_the_middle_of_a_line_does_not_match_a_line_anchor(self):
        c = stall_attach.Silence(0, r"^MARK$")
        c.feed(1, "xxMARK\r\n")
        self.assertTrue(c.feed(30, ""))

    def test_the_broken_decision_never_fires(self):
        c = stall_attach.Silence(0, r"^MARK$", decide=stall_attach.never_stalled)
        self.assertFalse(c.feed(10000, ""))

    def test_the_decision_function_alone(self):
        self.assertTrue(stall_attach.stalled(30, 0, False))
        self.assertFalse(stall_attach.stalled(30, 0, True))
        self.assertFalse(stall_attach.stalled(30, 15, False))


class Watch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "console.log")
        self.prefix = os.path.join(self.tmp, "row")
        test_debug.write(self.log, "")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def fake_dumps(self, *a, **k):
        self.taken = getattr(self, "taken", 0) + 1
        paths = []
        for n in ("a", "b"):
            p = "%s.stall-%s.txt" % (self.prefix, n)
            test_debug.write(p, "dump\n")
            paths.append(p)
        return paths

    def run_watch(self, script, **kw):
        p = subprocess.Popen(["sh", "-c", script])
        try:
            with mock.patch.object(stall_attach, "take_dumps", self.fake_dumps):
                return stall_attach.watch("aarch64", "elf", self.tmp, self.log, p.pid, r"^MARK$", self.prefix,
                                          silence=1, poll=0.05, **kw)
        finally:
            p.wait()

    def test_a_silent_boot_that_ends_without_the_marker_keeps_two_dumps(self):
        verdict, dumps = self.run_watch("sleep 2.5")
        self.assertEqual(verdict, "stalled")
        self.assertEqual(len(dumps), 2)
        self.assertTrue(all(os.path.exists(d) for d in dumps))
        self.assertEqual(test_debug.read(self.prefix + ".stall-verdict").strip(), "stalled")

    def test_a_boot_that_reaches_the_marker_after_a_long_quiet_keeps_nothing(self):
        script = "sleep 1.5; echo MARK >> '%s'; sleep 1" % self.log
        verdict, dumps = self.run_watch(script)
        self.assertEqual((verdict, dumps), ("marker", []))
        self.assertFalse(os.path.exists(self.prefix + ".stall-a.txt"))

    def test_quiet_after_the_marker_takes_no_dump(self):
        script = "echo MARK >> '%s'; sleep 2.5" % self.log
        verdict, dumps = self.run_watch(script)
        self.assertEqual((verdict, dumps), ("marker", []))
        self.assertEqual(getattr(self, "taken", 0), 0)

    def test_output_inside_the_limit_is_not_a_stall(self):
        script = "for i in 1 2 3 4 5; do echo x >> '%s'; sleep 0.5; done" % self.log
        verdict, dumps = self.run_watch(script)
        self.assertEqual(getattr(self, "taken", 0), 0)
        self.assertEqual(dumps, [])

    def test_the_broken_decision_takes_no_dump_on_a_silent_boot(self):
        verdict, dumps = self.run_watch("sleep 2.5", decide=stall_attach.never_stalled)
        self.assertEqual((verdict, dumps, getattr(self, "taken", 0)), ("exited", [], 0))


class Args(unittest.TestCase):
    def test_attach_arguments_name_a_monitor_and_a_gdbstub_in_the_directory(self):
        a = stall_attach.attach_args("aarch64", "/x/d")
        self.assertEqual(a, ["-monitor", "unix:/x/d/m,server=on,wait=off", "-gdb", "unix:/x/d/g,server=on,wait=off"])


if __name__ == "__main__":
    unittest.main()
