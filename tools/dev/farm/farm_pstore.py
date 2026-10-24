# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The pstore boot counter, over serial: the gate's `pstore: valid record`
row (tools/gate/ci_check.sh `pstore_row`) read off a board.

A kernel built with `pstore-smoke` panics once, with the VFS lock held, on a
boot that found no record in the reserved RAM region; the panic is recorded
there, the machine resets warm, and the next boot must find the record. The
console of that one capture shows both boots, and the boot counter is the
number of `[PSTORE] region reserved` lines: exactly two (boot 1 and the warm
reboot), one panic banner, boot 1's record written, boot 2 recovering it.

This needs /fat mounted (the smoke runs after it, `recover` appends to
/fat/CRASH.LOG): on a board whose storage does not work yet it stays red, and
the log says so (no `[FS] FAT32 mounted` line).
"""

from __future__ import annotations

from typing import List, Optional

from farm_tap import Verdict

REGION = "[PSTORE] region reserved: "
PANIC = "!!! KERNEL PANIC !!!"
FOUND = "[PSTORE-SMOKE] record found this boot ("
BOOT_1 = (
    "[PSTORE] no record from the previous boot",
    "[PSTORE-SMOKE] panicking with the VFS FS lock held",
    "pstore-smoke: deliberate panic with the VFS FS lock held",
    "[PANIC] pstore record written: ",
)
BOOT_2 = (
    "[PSTORE] recovered previous panic into /fat/CRASH.LOG: ",
    "[PSTORE-SMOKE] record found this boot (valid)",
)
FAT = "[FS] FAT32 mounted at /fat"


class Pstore:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def feed(self, line: str) -> bool:
        """True when boot 2 has reported what it found, or a second panic ends it."""
        self.lines.append(line)
        return line.startswith(FOUND) or self.count(PANIC) >= 2

    def count(self, text: str) -> int:
        return sum(1 for ln in self.lines if text in ln)

    def has(self, text: str) -> bool:
        return self.count(text) > 0

    def boots(self) -> int:
        """The boot counter: how many boots reserved the region."""
        return self.count(REGION)

    def verdict(self) -> Verdict:
        if not self.has(FAT):
            return Verdict(False, "no /fat: the smoke and the recovery run after it mounts "
                                  "(the board's storage does not work yet?)")
        missing = [t for t in BOOT_1 if not self.has(t)]
        if missing:
            return Verdict(False, "boot 1 did not print: " + missing[0])
        if self.count(PANIC) != 1:
            return Verdict(False, f"{self.count(PANIC)} panic banners over both boots, want 1")
        if self.boots() != 2:
            return Verdict(False, f"boot counter {self.boots()}: want 2 '[PSTORE] region reserved' lines "
                                  "(boot 1 and the warm reboot)")
        missing = [t for t in BOOT_2 if not self.has(t)]
        if missing:
            return Verdict(False, "boot 2 did not print: " + missing[0])
        return Verdict(True)

    def last_lines(self, n: int = 5) -> List[str]:
        return self.lines[-n:]
