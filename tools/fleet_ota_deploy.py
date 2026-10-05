#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""DEV04 — fleet-wide OTA deployment.

Sends a signed firmware image to N robots in parallel, with staged
rollout (canary → batch → all) and automatic rollback if any canary
fails health-check after install.

Usage:
    python3 tools/fleet_ota_deploy.py kernel.bin --inventory fleet.csv \\
        --canary 1 --batch 5 --health-port 9100

`fleet.csv` format (one robot per line):
    robot_id,ip,port,group
    drone-01,10.0.0.11,8080,prod
    rover-02,10.0.0.12,8080,prod

Stages:
    1. Send to `--canary` random robots, wait `--health-wait` seconds.
       If any canary fails health check, ABORT (no further robots).
    2. Send to `--batch` more robots in parallel; wait health-wait.
    3. Repeat batches until all robots updated.

Health check:
    GET http://<ip>:<health-port>/healthz → 200 means OK.
    Plain HTTP, no auth — assumes a private control plane network.
"""

from __future__ import annotations
import argparse
import csv
import random
import socket
import struct
import subprocess
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.error import URLError
from urllib.request import urlopen


OTA_MAGIC          = b"ROTA"
OTA_HEADER_VERSION = 1
OTA_HEADER_SIZE    = 24
PLATFORMS          = {"qemu": 0, "vf2": 1, "k1": 2}


@dataclass
class Robot:
    robot_id: str
    ip:       str
    port:     int
    group:    str

    def __str__(self) -> str:
        return f"{self.robot_id}@{self.ip}:{self.port}"


def parse_inventory(path: Path) -> list[Robot]:
    out: list[Robot] = []
    with path.open() as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            out.append(Robot(
                robot_id=row["robot_id"],
                ip      =row["ip"],
                port    =int(row["port"]),
                group   =row.get("group", "prod"),
            ))
    return out


def build_header(image_size: int, image_crc32: int, fw_version: int,
                 platform_id: int) -> bytes:
    return struct.pack(
        "<4sIIIIBBH",
        OTA_MAGIC, OTA_HEADER_VERSION,
        image_size, image_crc32, fw_version,
        platform_id, 0, 0,
    )


def send_to_robot(robot: Robot, header: bytes, payload: bytes,
                  timeout_s: int = 120) -> tuple[Robot, bool, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            s.connect((robot.ip, robot.port))
            s.sendall(header)
            s.sendall(payload)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            # Drain any final bytes.
            try:
                while s.recv(4096):
                    pass
            except (OSError, socket.timeout):
                pass
        return (robot, True, "sent")
    except Exception as e:
        return (robot, False, repr(e))


def health_check(robot: Robot, port: int, timeout: int = 5) -> bool:
    url = f"http://{robot.ip}:{port}/healthz"
    try:
        with urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except (URLError, OSError):
        return False


def chunks(seq: list, size: int) -> Iterator[list]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def deploy(args: argparse.Namespace) -> int:
    payload = Path(args.firmware).read_bytes()
    crc     = zlib.crc32(payload) & 0xFFFFFFFF
    plat_id = PLATFORMS[args.platform]
    header  = build_header(len(payload), crc, args.version, plat_id)

    inventory = parse_inventory(Path(args.inventory))
    if args.group:
        inventory = [r for r in inventory if r.group == args.group]
    if not inventory:
        print("Empty inventory after filter — nothing to do.")
        return 0

    print(f"Deploying {len(payload)} bytes (crc={crc:#010x}, "
          f"v{args.version}, {args.platform}) to {len(inventory)} robots")

    random.seed(args.seed)
    random.shuffle(inventory)

    canary, rest = inventory[:args.canary], inventory[args.canary:]
    stages: list[tuple[str, list[Robot]]] = [("canary", canary)]
    for i, batch in enumerate(chunks(rest, args.batch), start=1):
        stages.append((f"batch-{i}", batch))

    sent_total = 0
    for stage_name, robots in stages:
        if not robots:
            continue
        print(f"\n=== Stage {stage_name}: {len(robots)} robots ===")
        with ThreadPoolExecutor(max_workers=min(args.parallel, len(robots))) as ex:
            futures = {ex.submit(send_to_robot, r, header, payload): r for r in robots}
            results = []
            for f in as_completed(futures):
                results.append(f.result())
                r, ok, msg = results[-1]
                marker = "✓" if ok else "✗"
                print(f"  {marker} {r}: {msg}")

        send_failures = [r for r, ok, _ in results if not ok]
        if send_failures:
            print(f"!! {len(send_failures)} send failures — aborting deploy.")
            return 1
        sent_total += len(robots)

        print(f"Waiting {args.health_wait}s for health-check window…")
        time.sleep(args.health_wait)
        unhealthy = [r for r in robots
                     if not health_check(r, args.health_port)]
        if unhealthy:
            print(f"!! {len(unhealthy)} unhealthy after {stage_name}: " +
                  ", ".join(r.robot_id for r in unhealthy))
            print("ABORT — fleet kept on previous slot via boot-loop rollback.")
            return 2
        print(f"  ✓ all {len(robots)} healthy")

    print(f"\n=== DEPLOY OK: {sent_total} robots updated ===")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Fleet OTA deploy")
    p.add_argument("firmware",       help="Path to kernel binary (raw .BIN)")
    p.add_argument("--inventory",    required=True, help="CSV: robot_id,ip,port,group")
    p.add_argument("--platform",     default="qemu", choices=PLATFORMS)
    p.add_argument("--version",      type=int, default=1)
    p.add_argument("--group",        default="", help="Filter by group column")
    p.add_argument("--canary",       type=int, default=1)
    p.add_argument("--batch",        type=int, default=5)
    p.add_argument("--parallel",     type=int, default=5)
    p.add_argument("--health-port",  type=int, default=9100)
    p.add_argument("--health-wait",  type=int, default=30)
    p.add_argument("--seed",         type=int, default=0)
    args = p.parse_args()
    return deploy(args)


if __name__ == "__main__":
    sys.exit(main())
