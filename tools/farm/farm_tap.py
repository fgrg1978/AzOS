# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The ktest runner's TAP (kernel/src/ktest.rs), read off a board's console.

The same judgement as the gate's `ktest_row` (tools/ci_check.sh), minus what a
board cannot give: there is no machine exit status (the runner powers a real
board off through SBI, which carries none), so the verdict is the TAP alone and
the deadline stands in for the power-off.

  * the plan is the FIRST `1..N` line; a second one means the board restarted
    during the run (a watchdog reset, a panic-reboot), which is a failure;
  * test k must report `ok k - name` or `not ok k - name` exactly once;
  * a `Bail out!` line fails the run (a panicking test cannot be resumed; the
    runner also prints one right AFTER the summary for lockdep violations
    outside any test);
  * the run is complete at the summary line `# ktest: N tests, P passed, F
    failed`, which must agree with the plan and the results.

Every pattern is anchored: U-Boot, OpenSBI and the kernel's own log lines come
before and between the TAP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

PLAN = re.compile(r"^1\.\.(\d+)$")
RESULT = re.compile(r"^(not )?ok (\d+) - (\S+)(?: # (.*))?$")
STARTED = re.compile(r"^# ktest (\d+) (\S+)$")
SUMMARY = re.compile(r"^# ktest: (\d+) tests, (\d+) passed, (\d+) failed")
BAIL = re.compile(r"^Bail out!")

# What the first hardware pass reads off a board: the ISA line (which
# extensions the probes claimed), the ASID width the hardware really has, the
# ktest phases. Extracted from the log and shown, never asserted.
FACTS = (
    ("isa", re.compile(r"^\[ISA\] .*")),
    ("asid", re.compile(r"^\[MM\] ASID: hw .*")),
    ("phase", re.compile(r"^# ktest phase .*")),
)


@dataclass
class Verdict:
    ok: bool
    why: str = ""


@dataclass
class Tap:
    plan: Optional[int] = None
    plans_seen: int = 0
    results: Dict[int, List[Tuple[bool, str, str]]] = field(default_factory=dict)
    bail: Optional[str] = None
    summary: Optional[Tuple[int, int, int]] = None
    started: Optional[Tuple[int, str]] = None   # the last `# ktest k name`: the test running
    facts: Dict[str, List[str]] = field(default_factory=dict)

    def feed(self, line: str) -> bool:
        """Take one console line. True once nothing more can change the verdict:
        a bail out. The summary is NOT the end: the runner may print a `Bail
        out!` (lockdep violations outside any test) right after it, so the
        caller keeps reading for a moment after `summary` is set."""
        m = PLAN.match(line)
        if m:
            self.plans_seen += 1
            if self.plan is None:
                self.plan = int(m.group(1))
            return False
        m = RESULT.match(line)
        if m:
            k = int(m.group(2))
            self.results.setdefault(k, []).append((m.group(1) is None, m.group(3), m.group(4) or ""))
            return False
        m = STARTED.match(line)
        if m:
            self.started = (int(m.group(1)), m.group(2))
            return False
        m = SUMMARY.match(line)
        if m:
            self.summary = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return False
        if BAIL.match(line):
            self.bail = line
            return True
        for key, pat in FACTS:
            if pat.match(line):
                self.facts.setdefault(key, []).append(line)
        return False

    def verdict(self, expected_plan: Optional[int] = None) -> Verdict:
        """The judgement of what was read so far. `expected_plan`: the number of
        tests the image holds (the registry in its ELF), when known."""
        if self.plan is None:
            return Verdict(False, "no TAP plan line (1..N)")
        if self.plans_seen > 1:
            return Verdict(False, f"the plan was printed {self.plans_seen} times: the board restarted during the run")
        if expected_plan is not None and self.plan != expected_plan:
            return Verdict(False, f"plan 1..{self.plan}, the image holds {expected_plan} tests")
        not_ok = sorted(
            f"{r[1]}" for rs in self.results.values() for r in rs if not r[0])
        if not_ok:
            return Verdict(False, "not ok: " + " ".join(not_ok))
        if self.bail:
            return Verdict(False, f"the run bailed out: {self.bail}")
        for k in range(1, self.plan + 1):
            n = len(self.results.get(k, []))
            if n != 1:
                return Verdict(False, f"test {k} reported {n} times" + self._running())
        stray = sorted(k for k in self.results if not 1 <= k <= self.plan)
        if stray:
            return Verdict(False, f"results outside the plan: {stray}")
        if self.summary is None:
            return Verdict(False, "no summary line")
        if self.summary != (self.plan, self.plan, 0):
            return Verdict(False, f"summary {self.summary} disagrees with the plan {self.plan}")
        return Verdict(True)

    def _running(self) -> str:
        if self.started is None:
            return ""
        return f" (the last test started: {self.started[0]} {self.started[1]})"
