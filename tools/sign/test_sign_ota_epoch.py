#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""test_sign_ota_epoch.py: a bundle whose epoch the TPM floor cannot hold is not signed.

    python3 tools/sign/test_sign_ota_epoch.py [--canary]      (exit 0 = all pass)

With OTA_FLOOR_TPM_NV the floor is a 64-bit field (FLOOR_MAX in
crates/drivers/tpm/src/tpm.rs), so a device cannot confirm epoch FLOOR_MAX + 1.
`sign_ota.py bundle` refuses it at signing; with the BOOTMETA floor it signs.
The limit is read from the driver: the test takes it from there too, and the
kernel side of the same refusal is `floor_raise_from_unwritten_index_and_above_the_field`
(tpm-tests) and `a_failed_raise_leaves_the_floor_where_it_was_...` (ota-tests).

--canary runs the cases on a copy of the tool without the refusal: the case
that wants it must then fail (exit 0 means the canary was caught).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = Path(azos_tools.ROOT)
DRIVER = "crates/drivers/tpm/src/tpm.rs"


def driver_limit():
    return int(re.search(r"^pub const FLOOR_MAX: u32 = (\d+);", (ROOT / DRIVER).read_text(), re.M).group(1))


def tool_copy(td, canary):
    """tools/sign + tools/lib + the driver in `td`, so the copy reads its own tree."""
    for rel in ("tools/sign/sign_ota.py", "tools/sign/sigalg.py", "tools/lib/azos_tools.py", DRIVER):
        dst = Path(td) / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    tool = Path(td) / "tools/sign/sign_ota.py"
    if canary:
        text = tool.read_text()
        text = text.replace("if floor_in_tpm(a.kconfig) and a.epoch > floor_max():", "if False:")
        assert "if False:" in text
        tool.write_text(text)
    return tool


def bundle(tool, td, epoch, kconfig_lines):
    cfg = Path(td) / "kconfig"
    cfg.write_text("".join(f"{ln}\n" for ln in kconfig_lines))
    for n in ("kern", "caps", "capsig", "sched", "conf"):
        (Path(td) / n).write_bytes(b"x" * 16)
    out = Path(td) / f"out-{epoch}-{len(kconfig_lines)}.azu"
    r = subprocess.run([sys.executable, str(tool), "bundle", str(out), "--epoch", str(epoch), "--fw-version", "1",
                        "--kernel", f"{td}/kern", "--caps", f"{td}/caps", "--caps-sig", f"{td}/capsig",
                        "--sched", f"{td}/sched", "--config", f"{td}/conf",
                        "--priv", str(ROOT / "tools/keys/test_priv.bin"), "--kconfig", str(cfg)],
                       capture_output=True, text=True)
    return r, out


def main(argv):
    canary = "--canary" in argv
    top = driver_limit()
    tpm = ["CONFIG_OTA_FLOOR_TPM_NV=y"]
    boot = ["CONFIG_OTA_FLOOR_BOOTMETA=y"]
    failures = []
    with tempfile.TemporaryDirectory() as td:
        tool = tool_copy(td, canary)
        cases = [
            (f"TPM floor, epoch {top} (the last bit) signs", top, tpm, True),
            (f"TPM floor, epoch {top + 1} is refused and nothing is written", top + 1, tpm, False),
            (f"TPM floor, epoch {top + 1} is refused whatever the jump", 2**32 - 1, tpm, False),
            (f"BOOTMETA floor, epoch {top + 1} signs", top + 1, boot, True),
        ]
        for what, epoch, lines, signs in cases:
            r, out = bundle(tool, td, epoch, lines)
            ok = (r.returncode == 0 and out.exists()) if signs else (r.returncode == 1 and not out.exists()
                                                                    and str(top) in r.stderr)
            if not ok:
                failures.append(f"{what}: rc={r.returncode}, written={out.exists()}, {r.stderr.strip()[:100]}")
    for f in failures:
        print(f"    {'canary caught: ' if canary else 'FAIL '}{f}")
    if canary:
        return 0 if failures else 1
    if not failures:
        print(f"test_sign_ota_epoch: ok (limit {top}, read from {DRIVER})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
