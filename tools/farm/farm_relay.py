# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Power control of the board: a relay in its supply, behind a backend.

  dry-run  records the actions and touches nothing: the tests' backend, and a
           way to rehearse a farm run with no relay wired (boards.ini
           `relay = dry-run`).
  exec     two commands from boards.ini (`relay_on`, `relay_off`), run without
           a shell: `usbrelay HW348_1=1`, `uhubctl -a on -p 2`, a smart-plug
           CLI, anything that exits 0 when it did it.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from typing import Callable, List, Optional

EXEC_TIMEOUT_S = 15


class RelayError(Exception):
    pass


class Relay:
    def on(self) -> None:
        raise NotImplementedError

    def off(self) -> None:
        raise NotImplementedError

    def cycle(self, off_s: float, sleep: Callable[[float], None] = time.sleep) -> None:
        """Cut the power, keep it off for `off_s`, restore it."""
        self.off()
        sleep(off_s)
        self.on()


class DryRunRelay(Relay):
    """Records `on` / `off` in `events`; `on_event(name)` is called after each
    (a test's fake board boots from the `on`)."""

    def __init__(self, on_event: Optional[Callable[[str], None]] = None):
        self.events: List[str] = []
        self.on_event = on_event

    def _do(self, name: str) -> None:
        self.events.append(name)
        if self.on_event:
            self.on_event(name)

    def on(self) -> None:
        self._do("on")

    def off(self) -> None:
        self._do("off")


class ExecRelay(Relay):
    def __init__(self, cmd_on: str, cmd_off: str, runner=subprocess.run):
        self.argv = {"on": shlex.split(cmd_on), "off": shlex.split(cmd_off)}
        self.runner = runner

    def _run(self, which: str) -> None:
        argv = self.argv[which]
        try:
            r = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=EXEC_TIMEOUT_S)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RelayError(f"relay {which}: {argv[0]}: {e}") from None
        if r.returncode != 0:
            out = r.stdout.decode(errors="replace").strip()
            raise RelayError(f"relay {which}: {' '.join(argv)} exited {r.returncode}: {out}")

    def on(self) -> None:
        self._run("on")

    def off(self) -> None:
        self._run("off")


def make_relay(board) -> Relay:
    if board.relay == "dry-run":
        return DryRunRelay()
    return ExecRelay(board.relay_on, board.relay_off)
