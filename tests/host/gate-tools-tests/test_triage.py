# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host tests of tools/gate/triage.py.  Run: python3 tests/host/gate-tools-tests/test_triage.py"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.."))
sys.path.insert(0, os.path.join(ROOT, "tools/gate"))
import triage  # noqa: E402

GATE_LOG = """  lint one...               ok
  ktest hotplug (arm)...    FAIL
      not ok: [hotplug_a], expected []
      not ok 70 - hotplug_a # task pinned to the CPU
      log kept: {log}
      kernel kept: {elf}
  other row...              ok
  aarch64 abitest...        FAIL
      a teardown found its root still live:
        [MM] page-table root 0x47f62000 still live on hart mask 0x1
"""

CONSOLE = "\n".join(["boot line %d" % i for i in range(30)] + [
    "# ktest 70 hotplug_a", "# reserve", "kernel reserve = 15440 of 19799 free pages",
    "[PANIC] backtrace: 0x1000 0x2000", "KERNEL PANIC at x.rs:1", "not ok 70 - hotplug_a # task pinned to the CPU", "tail"])


class Triage(unittest.TestCase):
    def test_red_rows_are_the_fail_blocks_only(self):
        rows = triage.red_rows(GATE_LOG.format(log="/x", elf="/y"))
        self.assertEqual([r[0] for r in rows], ["ktest hotplug (arm)", "aarch64 abitest"])
        self.assertIn("log kept: /x", rows[0][1])
        self.assertEqual(len(rows[1][1]), 2)

    def test_first_assertion_tail_memory_rerun(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "k.log")
            with open(log, "w") as fh:
                fh.write(CONSOLE)
            out = triage.triage_row("ktest hotplug (arm)", [], log, None)
        text = "\n".join(out)
        self.assertEqual(out[0], "== ktest hotplug (arm) ==")
        self.assertIn("first failure: [PANIC] backtrace: 0x1000 0x2000", text)
        self.assertIn("memory admission: kernel reserve = 15440 of 19799 free pages", text)
        self.assertIn('rerun: CI_TIER=rows CI_ROWS="ktest hotplug (arm)" CI_JOBS=1 bash tools/gate/ci_check.sh', text)
        before = [l for l in out if l.startswith("  | ")]
        self.assertEqual(len(before), triage.TAIL)
        self.assertTrue(before[-1].endswith("kernel reserve = 15440 of 19799 free pages"), before[-1])
        self.assertIn("(no kernel ELF kept: the backtrace stays as numbers)", text)
        self.assertLessEqual(len(out), triage.MAX_LINES)

    def test_a_missing_row_log_is_said_once_and_the_gate_detail_is_used(self):
        rows = triage.red_rows(GATE_LOG.format(log="/nowhere/k.log", elf="/nowhere/k.elf"))
        out = triage.triage_row(rows[0][0], rows[0][1], "/nowhere/k.log", "/nowhere/k.elf")
        self.assertEqual(sum("row log not found" in l for l in out), 1)
        self.assertTrue(out[2].startswith("first failure: not ok 70 - hotplug_a"), out)

    def test_symbolizer_is_given_the_kept_elf(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "sym.py")
            with open(fake, "w") as fh:
                fh.write("import sys\nprint('frame in', sys.argv[1])\n")
            elf = os.path.join(d, "k.elf")
            with open(elf, "w") as fh:
                fh.write("x")
            old, triage.SYMBOLIZE = triage.SYMBOLIZE, fake
            try:
                got = triage.symbolize(elf, CONSOLE.split("\n"))
            finally:
                triage.SYMBOLIZE = old
        self.assertEqual(got, ["frame in " + elf])

    def test_never_more_than_forty_lines(self):
        det = ["not ok %d - t%d # why" % (i, i) for i in range(200)]
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "k.log")
            with open(log, "w") as fh:
                fh.write("\n".join(["x"] * 500 + ["Bail out! boom"]))
            out = triage.triage_row("r", det, log, None)
        self.assertLessEqual(len(out), triage.MAX_LINES)
        self.assertTrue(out[-1].startswith("rerun:"))

    def test_a_green_log_has_no_red_row(self):
        out = triage.triage_text("  a...   ok\n  b...   ok\n", "g.log")
        self.assertIn("no red row", "\n".join(out[0]))


if __name__ == "__main__":
    unittest.main()
