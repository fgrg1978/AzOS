# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Serial capture of a board's console: raw 8N1, a timestamped copy on disk,
lines handed to an observer, a deadline.

termios and select only (pyserial is not a dependency of this tree). The port
may disappear while the board's supply is cut (a USB-serial adapter on a hub
the relay switches): a read error reopens it until the deadline.
"""

from __future__ import annotations

import os
import select
import termios
import time
from typing import Callable, Optional

REOPEN_EVERY_S = 0.5
READ_CHUNK = 4096
POLL_S = 0.2

BAUDS = {rate: getattr(termios, "B%d" % rate)
         for rate in (9600, 19200, 38400, 57600, 115200, 230400)
         if hasattr(termios, "B%d" % rate)}


class SerialError(Exception):
    pass


class Deadline:
    """An absolute time on the capture's clock; a line handler may move it."""

    def __init__(self, at: float) -> None:
        self.at = at


def open_raw(path: str, baud: int) -> int:
    """Open `path` non-blocking, raw, 8N1, no flow control, at `baud`."""
    if baud not in BAUDS:
        raise SerialError(f"baud {baud} is not one of {sorted(BAUDS)}")
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as e:
        raise SerialError(f"{path}: {e.strerror}") from None
    try:
        attrs = termios.tcgetattr(fd)
        attrs[0] = 0                                    # iflag: no translation, no flow control
        attrs[1] = 0                                    # oflag
        attrs[2] = (attrs[2] & ~(termios.CSIZE | termios.PARENB | termios.CSTOPB)) \
            | termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] = 0                                    # lflag: no echo, no line discipline
        attrs[4] = attrs[5] = BAUDS[baud]
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        termios.tcflush(fd, termios.TCIOFLUSH)
    except (termios.error, OSError) as e:
        os.close(fd)
        raise SerialError(f"{path}: cannot configure: {e}") from None
    return fd


class Lines:
    """Bytes in, whole lines out: `\\r` dropped, undecodable bytes replaced."""

    def __init__(self) -> None:
        self.buf = b""

    def feed(self, data: bytes):
        self.buf += data
        *done, self.buf = self.buf.split(b"\n")
        for raw in done:
            yield raw.replace(b"\r", b"").decode("utf-8", "replace")

    def rest(self) -> str:
        """The unterminated tail (a console that ended without a newline)."""
        return self.buf.replace(b"\r", b"").decode("utf-8", "replace")


def capture(path: str, baud: int, deadline: Deadline, on_line: Callable[[str], bool],
            log=None, clock: Callable[[], float] = time.monotonic,
            opened: Optional[Callable[[], None]] = None) -> str:
    """Read the console until `on_line(line)` returns True (-> "done"), the
    `deadline` (in `clock` time) passes (-> "deadline").

    Every byte goes to `log` (a binary file) as it arrives. `opened()` is
    called once the port is open for the first time: the caller powers the
    board only after that, so no early output is lost.
    """
    fd = None
    lines = Lines()
    first = True
    try:
        while True:
            if clock() >= deadline.at:
                return "deadline"
            if fd is None:
                try:
                    fd = open_raw(path, baud)
                except SerialError:
                    if first:
                        raise
                    time.sleep(REOPEN_EVERY_S)
                    continue
                if first:
                    first = False
                    if opened:
                        opened()
            ready, _, _ = select.select([fd], [], [], min(POLL_S, max(0.0, deadline.at - clock())))
            if not ready:
                continue
            try:
                data = os.read(fd, READ_CHUNK)
            except OSError:
                os.close(fd)
                fd = None
                continue
            if not data:
                time.sleep(POLL_S)      # an adapter that went away reads EOF, readable forever
                continue
            if log is not None:
                log.write(data)
                log.flush()
            for line in lines.feed(data):
                if on_line(line):
                    return "done"
    finally:
        if fd is not None:
            os.close(fd)
