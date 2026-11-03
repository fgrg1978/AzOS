# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host test of tools/gate/land_bisect.sh in a scratch repository.  Run: python3 tests/host/gate-tools-tests/test_land_bisect.py"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.."))
SCRIPT = os.path.join(ROOT, "tools/gate/land_bisect.sh")
ID = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]


def git(d, *a):
    return subprocess.run(["git"] + ID + list(a), cwd=d, check=True, capture_output=True, text=True).stdout.strip()


class LandBisect(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "tools/gate"))
        shutil.copy(SCRIPT, os.path.join(self.d, "tools/gate/land_bisect.sh"))
        git(self.d, "init", "-q", "-b", "main")
        self.write("state", "ok")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", "base")
        self.base = git(self.d, "rev-parse", "HEAD")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, name, text):
        with open(os.path.join(self.d, name), "w") as fh:
            fh.write(text)

    def landing(self, n, state="ok", broken=False):
        """A side branch of two commits merged with --no-ff: a landing; the commits inside it are not candidates."""
        git(self.d, "checkout", "-q", "-b", "f%d" % n)
        self.write("side%d" % n, "x")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", "inner a %d" % n)
        self.write("mark%d" % n, "y")
        self.write("state", state)
        self.write("nobuild", "1" if broken else "0")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", "inner b %d" % n)
        git(self.d, "checkout", "-q", "main")
        git(self.d, "merge", "-q", "--no-ff", "-m", "land %d" % n, "f%d" % n)

    def run_bisect(self, good, bad, cmd):
        env = dict(os.environ, LAND_BISECT_CMD=cmd, AZOS_OUT=tempfile.mkdtemp(),
                   LAND_BISECT_WT=os.path.join(tempfile.mkdtemp(), "wt"))
        return subprocess.run(["bash", os.path.join(self.d, "tools/gate/land_bisect.sh"), good, bad, "row"],
                              cwd=self.d, env=env, capture_output=True, text=True)

    CMD = 'if [ "$(cat nobuild)" = 1 ]; then echo "the kernel did NOT build"; exit 1; fi; [ "$(cat state)" = ok ]'

    def test_finds_the_first_bad_landing_and_skips_one_that_does_not_build(self):
        for n in range(1, 8):
            self.landing(n, state="bad" if n >= 5 else "ok", broken=(n == 3))
        r = self.run_bisect(self.base, "main", self.CMD)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("first bad landing:", r.stdout)
        self.assertIn("land 5", r.stdout, r.stdout + r.stderr)
        self.assertNotIn("inner", r.stdout)
        self.assertEqual(git(self.d, "worktree", "list").count("\n"), 0, "the worktree is removed")

    def test_the_callers_checkout_is_untouched(self):
        for n in range(1, 4):
            self.landing(n, state="bad" if n >= 2 else "ok")
        head = git(self.d, "rev-parse", "HEAD")
        self.run_bisect(self.base, "main", self.CMD)
        self.assertEqual(git(self.d, "rev-parse", "HEAD"), head)
        self.assertEqual(git(self.d, "status", "--porcelain"), "")

    def test_when_the_neighbours_do_not_build_the_candidates_are_listed(self):
        for n in range(1, 5):
            self.landing(n, state="ok" if n == 1 else "bad", broken=(n in (2, 3)))
        r = self.run_bisect(self.base, "main", self.CMD)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        for n in (2, 3, 4):
            self.assertIn("land %d" % n, r.stdout)
        self.assertNotIn("land 1", r.stdout)


if __name__ == "__main__":
    unittest.main()
