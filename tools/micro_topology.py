#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""micro_topology.py — the signed topology the micro kernel embeds.

Reads micro/topology/{CAPS.in,SCHED.TOM} and writes <out>/{CAPS.TOM,
CAPS.SIG,SCHED.TOM}: CAPS.TOM is CAPS.in under the header the topology
loader requires (`format = 5` and `sched_sha256`, the SHA-256 of SCHED.TOM
that binds the two files), and CAPS.SIG is the `DSIG` sidecar holding the
signature over it (tools/gen_config_sig.py), made with the TEST key unless
--priv names another. The micro image carries these three files
(`include_bytes!`) and verifies them at boot, as the main kernel verifies
the files on its volume.

Usage: tools/micro_topology.py <out dir> [--priv KEY]
"""

import argparse
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "micro", "topology")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--priv", default=os.path.join(ROOT, "tools", "keys", "test_priv.bin"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    sched = open(os.path.join(SRC, "SCHED.TOM"), "rb").read()
    body = open(os.path.join(SRC, "CAPS.in"), "rb").read()
    digest = hashlib.sha256(sched).hexdigest()
    caps = b'# CAPS.TOML of the micro kernel image.\nformat = 5\nsched_sha256 = "%s"\n\n' % digest.encode() + body
    caps_path = os.path.join(args.out, "CAPS.TOM")
    open(caps_path, "wb").write(caps)
    open(os.path.join(args.out, "SCHED.TOM"), "wb").write(sched)
    subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "gen_config_sig.py"), caps_path,
         "--priv", args.priv, "--out", os.path.join(args.out, "CAPS.SIG")],
        check=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
