#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""NET_TX_BATCH_MAX's default fits the smallest TX ring of the NICs in the build.

crates/core/limits/build.rs fails a build whose batch bound exceeds the frames
the smallest TX ring holds, so a preset must never default to such a value. This
expands, as `olddefconfig` does, every config/defconfigs/*.config and each of
them switched to the server class with the Intel NICs on (the value a class
default would otherwise get wrong), and checks the resolved bound against the
rings: virtio-net holds NET_VIRTIO_TXQ_SIZE / 2 frames, e1000e / igc / dwmac one
fewer than their descriptors. Scratch goes under $AZOS_OUT.

    python3 tools/lint/net_batch_bound_check.py
"""
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def resolve(text, work):
    path = os.path.join(work, "bound.config")
    with open(path, "w") as f:
        f.write(text)
    subprocess.run([sys.executable, "-m", "olddefconfig"], cwd=ROOT, env={**os.environ, "KCONFIG_CONFIG": path},
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    cfg = {}
    for line in open(path):
        m = re.match(r"CONFIG_(\w+)=(.*)", line.strip())
        if m:
            cfg[m.group(1)] = m.group(2)
    return cfg


def rings(cfg):
    out = {}
    num = lambda k: int(cfg[k]) if cfg.get(k, "").isdigit() else None
    if num("NET_VIRTIO_TXQ_SIZE"):
        out["virtio"] = num("NET_VIRTIO_TXQ_SIZE") // 2
    for sym, who in (("DRV_E1000E", "e1000e"), ("DRV_IGC", "igc"), ("BOARD_VF2", "dwmac")):
        key = {"e1000e": "E1000E_TX_DESCS", "igc": "IGC_TX_DESCS", "dwmac": "DWMAC_TX_DESCS"}[who]
        if cfg.get(sym) == "y" and num(key):
            out[who] = num(key) - 1
    return out


def main():
    base = os.environ.get("AZOS_OUT")
    if not base:
        print("net_batch_bound_check: AZOS_OUT is not set", file=sys.stderr)
        return 2
    work = os.path.join(base, "net-batch-bound")
    os.makedirs(work, exist_ok=True)
    bad = 0
    cells = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "config/defconfigs/*.config"))):
        text = open(path).read()
        server = "".join(l for l in text.splitlines(True) if not l.startswith(("CONFIG_HWCLASS_", "# CONFIG_HWCLASS_")))
        server += "CONFIG_HWCLASS_SERVER=y\nCONFIG_DRV_PCI=y\nCONFIG_DRV_E1000E=y\nCONFIG_DRV_IGC=y\n"
        for label, body in (("as shipped", text), ("server class with e1000e and igc", server)):
            cfg = resolve(body, work)
            batch, limits = int(cfg["NET_TX_BATCH_MAX"]), rings(cfg)
            cells += 1
            over = {k: v for k, v in limits.items() if batch > v}
            if over:
                bad += 1
                print(f"net_batch_bound_check: {os.path.basename(path)} ({label}): batch {batch} over {over}", file=sys.stderr)
    print(f"net_batch_bound_check: {'FAIL' if bad else 'ok'}: {cells} cells")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
