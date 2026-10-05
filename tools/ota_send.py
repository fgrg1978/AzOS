#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""
AzOS — OTA firmware sender.

Reads a kernel binary, wraps it in an OTA header (24 bytes), and sends
it to the robot over TCP.

Usage:
    python3 tools/ota_send.py <kernel.bin> <robot-ip> [--port 8080] [--platform qemu] [--version 1]

The robot must be running `ota recv <port>` in the shell.
"""

import argparse
import os
import socket
import struct
import sys

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
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".config"),
    )
    try:
        with open(cfg_path) as f:
            for line in f:
                if line.startswith("CONFIG_OTA_MAX_IMAGE_SIZE_MB="):
                    return int(line.strip().split("=", 1)[1]) * 1024 * 1024
    except (OSError, ValueError):
        pass
    return 8 * 1024 * 1024  # Kconfig default (config/Kconfig.ota: OTA_MAX_IMAGE_SIZE_MB default 8)


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


def main():
    parser = argparse.ArgumentParser(description="AzOS OTA firmware sender")
    parser.add_argument("kernel", help="Path to kernel binary")
    parser.add_argument("host", help="Robot IP address")
    parser.add_argument("--port", type=int, default=8080, help="TCP port (default: 8080)")
    parser.add_argument("--platform", default="qemu",
                        choices=PLATFORMS.keys(), help="Target platform")
    parser.add_argument("--version", type=int, default=1,
                        help="Firmware version number (default: 1)")
    args = parser.parse_args()

    # Read kernel binary
    with open(args.kernel, "rb") as f:
        payload = f.read()

    if len(payload) > OTA_MAX_IMAGE_SIZE:
        print(f"ERROR: Kernel too large ({len(payload)} > {OTA_MAX_IMAGE_SIZE})")
        sys.exit(1)

    image_crc = crc32(payload)
    platform_id = PLATFORMS[args.platform]

    header = build_header(len(payload), image_crc, args.version, platform_id)
    assert len(header) == OTA_HEADER_SIZE

    print(f"[OTA] Kernel: {args.kernel}")
    print(f"[OTA] Size:   {len(payload)} bytes")
    print(f"[OTA] CRC-32: {image_crc:#010x}")
    print(f"[OTA] FW ver: {args.version}")
    print(f"[OTA] Target: {args.platform} (id={platform_id})")
    print(f"[OTA] Connecting to {args.host}:{args.port}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(120)
        sock.connect((args.host, args.port))
        print("[OTA] Connected — sending header + payload...")

        sock.sendall(header)
        sock.sendall(payload)
        print(f"[OTA] Sent {OTA_HEADER_SIZE + len(payload)} bytes total")

        # Half-close: signal end-of-stream to the kernel without dropping the
        # connection. The kernel keeps draining its rx buffer until the OTA
        # task reads everything; only then is it safe for us to close. Without
        # SHUT_WR + a final read, the kernel hits FIN with data still in flight
        # and reports INCOMPLETE.
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
        sock.close()
        print("[OTA] Done. Run 'ota status' on the robot to verify.")
    except Exception as e:
        print(f"[OTA] ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
