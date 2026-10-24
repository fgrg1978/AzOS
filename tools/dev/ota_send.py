#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""
AzOS — OTA firmware sender.

Reads a kernel binary, wraps it in an OTA header (24 bytes), and sends
it to the robot over TCP.

Usage:
    python3 tools/dev/ota_send.py <kernel.bin> <robot-ip> [--port 8080] [--platform qemu] [--version 1]
    python3 tools/dev/ota_send.py <kernel.bin> --inventory fleet.csv [--canary 1] [--batch 5] \
        [--parallel 5] [--group G] [--health-port 9100] [--health-wait 30] [--seed 0]
    python3 tools/dev/ota_send.py <new.bundle> --delta-from <running.bundle> --out <new.azd>
    python3 tools/dev/ota_send.py --self-test

The robot must be running `ota recv <port>` in the shell.

`--inventory` sends the same image to a fleet, one CSV line per robot
(`robot_id,ip,port,group`), in stages: `--canary` robots picked at random
(`--seed`), then `--batch` at a time, `--parallel` connections at once. After
each stage it waits `--health-wait` seconds and asks every robot of the stage
`GET http://<ip>:<health-port>/healthz` (plain HTTP, no auth: a private
control-plane network); one that does not answer 200 stops the rollout (exit
2) and the robots not yet sent keep their slot. A failed send stops it too
(exit 1). `--group` keeps only the robots of that group column.

This installs a KERNEL on its own. A device is a kernel plus the userspace
images, the topology and the configuration that go with it; to update those
together, atomically and under one anti-rollback epoch, build a bundle with
`tools/sign/sign_ota.py bundle` and stage it with `pkg update` (see
`crates/core/ota/src/update.rs`).

`--delta-from` is the second form of that update: instead of the whole new
bundle, a patch against the bundle the device is running (the one it was staged
from), made by `tools/image/ota_delta.py`. The device applies it by reading the running
slot's set (`SetBase` and `DeltaSource`, `crates/core/ota/src/pure.rs`) and
staging the result through the same atomic path. The installer recognises a patch
by its magic, so the file is given to `pkg update` like a whole bundle
(`userspace/lib/packages/src/service.rs`); the `ota recv` socket takes kernels
only, so this mode writes the patch to a file and does not connect.
"""

import argparse
import csv
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError
from urllib.request import urlopen

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
import ota_delta  # noqa: E402

# Must match crates/core/ota/src/lib.rs
OTA_MAGIC = b"ROTA"
OTA_HEADER_VERSION = 1
OTA_HEADER_SIZE = 24


def _read_ota_max_image_size() -> int:
    """OTA_MAX_IMAGE_SIZE_MB from Kconfig, so this sender's ceiling cannot
    drift from the receiver's (`crates/core/ota/src/lib.rs::OTA_MAX_IMAGE_SIZE`,
    which reads the identical symbol via `azos_limits`).

    U12-4 (2026-09-25 audit): this used to hardcode `2 * 1024 * 1024` —
    `secure_boot.rs`'s OLD, separate `.bss`-buffer ceiling — while Kconfig's
    range was 1-64 MiB, default 8. That second ceiling is gone (2026-09-26,
    U09-14: OTA verification streams the hash instead of buffering a whole
    image), so `OTA_MAX_IMAGE_SIZE_MB` is now the ONLY size limit in the OTA
    path and this must track it, not the number that used to live beside it.

    Reads `$KCONFIG_CONFIG` if set (matches what a `make defconfig-<x>` or
    the CI gate expanded), else the workspace `.config`, else falls back to
    the Kconfig default (8 MiB) — never to the removed 2 MiB figure.
    """
    cfg_path = os.environ.get(
        "KCONFIG_CONFIG",
        os.path.join(azos_tools.ROOT, ".config"),
    )
    try:
        with open(cfg_path) as f:
            for line in f:
                if line.startswith("CONFIG_OTA_MAX_IMAGE_SIZE_MB="):
                    return int(line.strip().split("=", 1)[1]) * 1024 * 1024
    except (OSError, ValueError):
        pass
    return 8 * 1024 * 1024  # Kconfig default (config/subsys/Kconfig.ota: OTA_MAX_IMAGE_SIZE_MB default 8)


OTA_MAX_IMAGE_SIZE = _read_ota_max_image_size()

PLATFORMS = {
    "qemu":    0,
    "vf2":     1,
    "k1":      2,
}


def crc32(data: bytes) -> int:
    """IEEE 802.3 CRC-32 (same as zlib.crc32 but we compute manually for clarity)."""
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def build_header(image_size: int, image_crc32: int, fw_version: int,
                 platform_id: int) -> bytes:
    """Build a 24-byte OTA header."""
    return struct.pack(
        "<4sIIIIBBH",
        OTA_MAGIC,
        OTA_HEADER_VERSION,
        image_size,
        image_crc32,
        fw_version,
        platform_id,
        0,  # flags
        0,  # reserved
    )


def load_image(path: str, version: int, platform: str):
    """-> (header, payload, crc) of one OTA image; exits on an image the
    receiver would refuse for its size."""
    with open(path, "rb") as f:
        payload = f.read()
    if len(payload) > OTA_MAX_IMAGE_SIZE:
        print(f"ERROR: Kernel too large ({len(payload)} > {OTA_MAX_IMAGE_SIZE})")
        sys.exit(1)
    crc = crc32(payload)
    header = build_header(len(payload), crc, version, PLATFORMS[platform])
    assert len(header) == OTA_HEADER_SIZE
    return header, payload, crc


def send_image(host: str, port: int, header: bytes, payload: bytes, timeout_s: int = 120, connected=None):
    """One transfer: header, payload, then a half-close and a drain. Raises on
    a connect or send error; `connected()` runs once the connection is up.

    Half-close: signal end-of-stream to the kernel without dropping the
    connection. The kernel keeps draining its rx buffer until the OTA task
    reads everything; only then is it safe for us to close. Without SHUT_WR +
    a final read, the kernel hits FIN with data still in flight and reports
    INCOMPLETE."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_s)
        sock.connect((host, port))
        if connected:
            connected()
        sock.sendall(header)
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        # Drain any final bytes the kernel might send back (it doesn't, but
        # this also blocks until the kernel closes its side gracefully).
        sock.settimeout(60)
        try:
            while sock.recv(4096):
                pass
        except (OSError, socket.timeout):
            pass


def send_one(args):
    header, payload, image_crc = load_image(args.kernel, args.version, args.platform)
    print(f"[OTA] Kernel: {args.kernel}")
    print(f"[OTA] Size:   {len(payload)} bytes")
    print(f"[OTA] CRC-32: {image_crc:#010x}")
    print(f"[OTA] FW ver: {args.version}")
    print(f"[OTA] Target: {args.platform} (id={PLATFORMS[args.platform]})")
    print(f"[OTA] Connecting to {args.host}:{args.port}...")
    try:
        send_image(args.host, args.port, header, payload,
                   connected=lambda: print("[OTA] Connected — sending header + payload..."))
        print(f"[OTA] Sent {OTA_HEADER_SIZE + len(payload)} bytes total")
        print("[OTA] Done. Run 'ota status' on the robot to verify.")
    except Exception as e:
        print(f"[OTA] ERROR: {e}")
        sys.exit(1)


# ── Fleet rollout (--inventory) ──────────────────────────────────────────────

def parse_inventory(path: str):
    """-> [(robot_id, ip, port, group)] from a `robot_id,ip,port,group` CSV."""
    with open(path, newline="") as f:
        return [(r["robot_id"], r["ip"], int(r["port"]), r.get("group") or "prod")
                for r in csv.DictReader(f)]


def health_check(ip: str, port: int, timeout: int = 5) -> bool:
    try:
        with urlopen(f"http://{ip}:{port}/healthz", timeout=timeout) as r:
            return r.status == 200
    except (URLError, OSError):
        return False


def deploy(args) -> int:
    header, payload, crc = load_image(args.kernel, args.version, args.platform)
    inventory = parse_inventory(args.inventory)
    if args.group:
        inventory = [r for r in inventory if r[3] == args.group]
    if not inventory:
        print("Empty inventory after filter — nothing to do.")
        return 0
    print(f"Deploying {len(payload)} bytes (crc={crc:#010x}, "
          f"v{args.version}, {args.platform}) to {len(inventory)} robots")
    random.seed(args.seed)
    random.shuffle(inventory)
    canary, rest = inventory[:args.canary], inventory[args.canary:]
    stages = [("canary", canary)] + [(f"batch-{i // args.batch + 1}", rest[i:i + args.batch])
                                     for i in range(0, len(rest), args.batch)]

    def send(robot):
        try:
            send_image(robot[1], robot[2], header, payload)
            return robot, True, "sent"
        except Exception as e:
            return robot, False, repr(e)

    sent_total = 0
    for stage, robots in stages:
        if not robots:
            continue
        print(f"\n=== Stage {stage}: {len(robots)} robots ===")
        results = []
        with ThreadPoolExecutor(max_workers=min(args.parallel, len(robots))) as ex:
            for fut in as_completed([ex.submit(send, r) for r in robots]):
                results.append(fut.result())
                r, ok, msg = results[-1]
                print(f"  {'✓' if ok else '✗'} {r[0]}@{r[1]}:{r[2]}: {msg}")
        failed = [r for r, ok, _ in results if not ok]
        if failed:
            print(f"!! {len(failed)} send failures — aborting deploy.")
            return 1
        sent_total += len(robots)
        print(f"Waiting {args.health_wait}s for health-check window…")
        time.sleep(args.health_wait)
        unhealthy = [r for r in robots if not health_check(r[1], args.health_port)]
        if unhealthy:
            print(f"!! {len(unhealthy)} unhealthy after {stage}: " + ", ".join(r[0] for r in unhealthy))
            print("ABORT — fleet kept on previous slot via boot-loop rollback.")
            return 2
        print(f"  ✓ all {len(robots)} healthy")
    print(f"\n=== DEPLOY OK: {sent_total} robots updated ===")
    return 0


# ── --self-test: a localhost receiver and health endpoint ────────────────────

def self_test() -> int:
    fails = []

    def receiver(n):
        """A listening socket that keeps what n connections send."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(n)
        got = []

        def loop():
            for _ in range(n):
                c, _ = srv.accept()
                data = b""
                while True:
                    b = c.recv(65536)
                    if not b:
                        break
                    data += b
                got.append(data)
                c.close()
            srv.close()
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return srv.getsockname()[1], got, t

    def health(code):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(code if self.path == "/healthz" else 404)
                self.end_headers()

            def log_message(self, *a):
                pass
        h = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=h.serve_forever, daemon=True).start()
        return h

    def quiet(fn, *a):
        old, sys.stdout = sys.stdout, open(os.devnull, "w")
        try:
            return fn(*a)
        finally:
            sys.stdout.close()
            sys.stdout = old

    payload = bytes(range(256)) * 9
    want = build_header(len(payload), crc32(payload), 7, PLATFORMS["vf2"]) + payload
    if want[:4] != OTA_MAGIC or len(want) != OTA_HEADER_SIZE + len(payload):
        fails.append("header: wrong magic or size")
    if struct.unpack_from("<IIII", want, 4) != (OTA_HEADER_VERSION, len(payload), crc32(payload), 7):
        fails.append("header: version, size, crc or fw version out of place")
    with tempfile.TemporaryDirectory() as d:
        img = os.path.join(d, "k.bin")
        with open(img, "wb") as f:
            f.write(payload)
        ns = argparse.Namespace(kernel=img, version=7, platform="vf2", group="", canary=1, batch=1,
                                parallel=2, health_wait=0, seed=0)

        # One robot: what arrives is the header and the image, byte for byte.
        port, got, t = receiver(1)
        quiet(send_one, argparse.Namespace(**vars(ns), host="127.0.0.1", port=port))
        t.join(10)
        if got != [want]:
            fails.append("single send: the receiver did not get header + image")

        # A fleet of three, healthy: canary then two batches, every robot served.
        port, got, t = receiver(3)
        h = health(200)
        inv = os.path.join(d, "fleet.csv")
        with open(inv, "w") as f:
            f.write("robot_id,ip,port,group\n" + "".join(f"r{i},127.0.0.1,{port},prod\n" for i in range(3)))
        rc = quiet(deploy, argparse.Namespace(**vars(ns), inventory=inv, health_port=h.server_address[1]))
        t.join(10)
        h.shutdown()
        if rc != 0 or got != [want] * 3:
            fails.append(f"fleet, healthy: rc {rc}, {len(got)} of 3 robots got the image")

        # CANARY: an unhealthy canary stops the rollout before the batches.
        port, got, t = receiver(1)
        h = health(503)
        with open(inv, "w") as f:
            f.write("robot_id,ip,port,group\n" + "".join(f"r{i},127.0.0.1,{port},prod\n" for i in range(3)))
        rc = quiet(deploy, argparse.Namespace(**vars(ns), inventory=inv, health_port=h.server_address[1]))
        t.join(10)
        h.shutdown()
        if rc != 2 or len(got) != 1:
            fails.append(f"fleet, sick canary: rc {rc} (want 2), {len(got)} robots sent (want 1)")
    if fails:
        print("ota_send self-test FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("ota_send self-test ok")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    parser = argparse.ArgumentParser(description="AzOS OTA firmware sender")
    parser.add_argument("kernel", help="Path to kernel binary (with --delta-from: the new bundle)")
    parser.add_argument("host", nargs="?", help="Robot IP address (not with --delta-from or --inventory)")
    parser.add_argument("--port", type=int, default=8080, help="TCP port (default: 8080)")
    parser.add_argument("--platform", default="qemu",
                        choices=PLATFORMS.keys(), help="Target platform")
    parser.add_argument("--version", type=int, default=1,
                        help="Firmware version number (default: 1)")
    parser.add_argument("--delta-from", metavar="RUNNING_BUNDLE",
                        help="send the new bundle as a patch against the bundle the device runs")
    parser.add_argument("--out", help="with --delta-from: where to write the patch")
    fleet = parser.add_argument_group("fleet rollout (--inventory)")
    fleet.add_argument("--inventory", metavar="CSV", help="robot_id,ip,port,group: send to every robot")
    fleet.add_argument("--group", default="", help="only the robots of this group column")
    fleet.add_argument("--canary", type=int, default=1)
    fleet.add_argument("--batch", type=int, default=5)
    fleet.add_argument("--parallel", type=int, default=5)
    fleet.add_argument("--health-port", type=int, default=9100)
    fleet.add_argument("--health-wait", type=int, default=30)
    fleet.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    if args.delta_from:
        if args.host or args.inventory or not args.out:
            parser.error("--delta-from writes a patch file: give --out and no robot-ip")
        with open(args.delta_from, "rb") as f:
            old = f.read()
        with open(args.kernel, "rb") as f:
            new = f.read()
        try:
            delta = ota_delta.make(old, new)
        except (ValueError, AssertionError) as e:
            print(f"[OTA] ERROR: {e}")
            sys.exit(1)
        with open(args.out, "wb") as f:
            f.write(delta)
        print(f"[OTA] Delta: {args.out} ({len(delta)} bytes for a {len(new)}-byte bundle, "
              f"{100 * len(delta) / len(new):.1f}%)")
        return
    if args.inventory:
        if args.host:
            parser.error("--inventory takes the robots from the CSV: give no robot-ip")
        sys.exit(deploy(args))
    if not args.host:
        parser.error("robot-ip is required")
    send_one(args)


if __name__ == "__main__":
    main()
