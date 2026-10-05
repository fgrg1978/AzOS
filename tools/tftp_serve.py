#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""DEV01 — minimal TFTP server (RFC 1350, octet mode, read-only).

Serves files from a directory over the standard port 69 (or any
caller-supplied port) so a board (or QEMU netboot) can pull the
freshly-built kernel binary without an SD-card cycle.

Scope kept tight on purpose — this is a dev tool, not production:

  * Octet (binary) mode only. ASCII / mail rejected.
  * No RFC 2347 OACK / block-size negotiation; we always send the
    default 512-byte blocks.
  * Single transfer at a time: each RRQ spawns a thread that owns
    the response socket until completion or error.
  * No directory escape — `filename` is restricted to one path
    component and resolved inside the served dir.

Run with:

    python3 tools/tftp_serve.py build/kernel-ota.bin
    python3 tools/tftp_serve.py --dir build --port 6969
"""

# PEP 563 — postpone evaluation of annotations so `str | None` and
# similar PEP 604 union syntax works on the macOS system Python 3.9.
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import threading
import time

# RFC 1350 wire constants.
TFTP_OPCODE_RRQ = 1
TFTP_OPCODE_DATA = 3
TFTP_OPCODE_ACK = 4
TFTP_OPCODE_ERROR = 5

TFTP_BLOCK_SIZE = 512
TFTP_HEADER_SIZE = 4  # opcode (2) + block / err_code (2)
TFTP_MAX_REQ_BYTES = 600  # RRQ rarely exceeds this; cap defensively.

# RFC 1350 §5 error codes.
TFTP_ERR_NOT_DEFINED = 0
TFTP_ERR_FILE_NOT_FOUND = 1
TFTP_ERR_ACCESS_VIOLATION = 2
TFTP_ERR_ILLEGAL_OP = 4

# Server tunables — no magic numbers in the protocol path.
TFTP_DEFAULT_PORT = 69
TFTP_DEFAULT_DIR = "build"
TFTP_DEFAULT_FILENAME = "kernel-ota.bin"
TFTP_PER_BLOCK_TIMEOUT_S = 1.0
TFTP_PER_BLOCK_RETRIES = 5


def build_error(code: int, msg: str) -> bytes:
    """Pack a TFTP ERROR packet: [opcode][code][msg][0]."""
    msg_b = msg.encode("ascii", "replace")[:128]
    return struct.pack("!HH", TFTP_OPCODE_ERROR, code) + msg_b + b"\x00"


def parse_rrq(pkt: bytes):
    """Parse a Read Request — returns `(filename, mode)` or None."""
    if len(pkt) < 4:
        return None
    opcode = struct.unpack_from("!H", pkt, 0)[0]
    if opcode != TFTP_OPCODE_RRQ:
        return None
    parts = pkt[2:].split(b"\x00")
    if len(parts) < 2 or not parts[0]:
        return None
    try:
        return parts[0].decode("ascii"), parts[1].decode("ascii").lower()
    except UnicodeDecodeError:
        return None


def safe_resolve(base_dir: str, filename: str) -> str | None:
    """Reject filenames with separators or `..` segments."""
    if not filename or filename in (".", ".."):
        return None
    if "/" in filename or "\\" in filename or "\x00" in filename:
        return None
    full = os.path.join(base_dir, filename)
    real = os.path.realpath(full)
    base_real = os.path.realpath(base_dir)
    if not real.startswith(base_real + os.sep) and real != base_real:
        return None
    return real


def handle_transfer(client_addr, filename, mode, base_dir):
    """Serve one file to one client. Runs in its own socket+thread."""
    log_prefix = f"[TFTP→{client_addr[0]}:{client_addr[1]}]"

    if mode != "octet":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(build_error(TFTP_ERR_ILLEGAL_OP, "octet only"), client_addr)
        sock.close()
        print(f"{log_prefix} rejected non-octet mode '{mode}'")
        return

    resolved = safe_resolve(base_dir, filename)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))  # ephemeral TID per RFC 1350 §4
    sock.settimeout(TFTP_PER_BLOCK_TIMEOUT_S)

    if resolved is None:
        sock.sendto(
            build_error(TFTP_ERR_ACCESS_VIOLATION, "bad filename"),
            client_addr,
        )
        sock.close()
        print(f"{log_prefix} rejected unsafe filename '{filename}'")
        return

    try:
        with open(resolved, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        sock.sendto(
            build_error(TFTP_ERR_FILE_NOT_FOUND, "no such file"),
            client_addr,
        )
        sock.close()
        print(f"{log_prefix} file not found: {filename}")
        return

    total = len(data)
    print(f"{log_prefix} serving '{filename}' ({total} B) from {resolved}")

    block_num = 1
    offset = 0
    # RFC 1350: a file whose size is an exact multiple of 512 ends
    # with one empty DATA block. The loop terminates after sending
    # AND acking that empty block.
    while True:
        chunk = data[offset : offset + TFTP_BLOCK_SIZE]
        pkt = (
            struct.pack("!HH", TFTP_OPCODE_DATA, block_num & 0xFFFF) + chunk
        )

        # Send + wait for ACK (with bounded retries).
        for attempt in range(TFTP_PER_BLOCK_RETRIES):
            sock.sendto(pkt, client_addr)
            try:
                reply, _ = sock.recvfrom(TFTP_HEADER_SIZE)
            except socket.timeout:
                continue
            if len(reply) < 4:
                continue
            op, ack_block = struct.unpack("!HH", reply[:4])
            if op == TFTP_OPCODE_ACK and ack_block == (block_num & 0xFFFF):
                break
        else:
            print(f"{log_prefix} no ACK for block {block_num} after retries")
            sock.close()
            return

        offset += len(chunk)
        if len(chunk) < TFTP_BLOCK_SIZE:
            break
        # RFC 1350 §1: u16 block number wraps after 65535.
        block_num = (block_num + 1) & 0xFFFF

    sock.close()
    print(f"{log_prefix} done — {offset} bytes in {block_num} blocks")


def serve(port: int, base_dir: str):
    """Bind to port and dispatch each RRQ into its own thread."""
    base_real = os.path.realpath(base_dir)
    if not os.path.isdir(base_real):
        print(f"error: serve dir not found: {base_dir}", file=sys.stderr)
        sys.exit(2)

    listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen.bind(("", port))
    except PermissionError:
        print(
            f"error: port {port} requires elevated privileges (try --port 6969)",
            file=sys.stderr,
        )
        sys.exit(2)

    print(f"[TFTP] listening on udp/{port}, serving {base_real}")
    print(f"[TFTP] Ctrl-C to stop")

    while True:
        try:
            pkt, addr = listen.recvfrom(TFTP_MAX_REQ_BYTES)
        except KeyboardInterrupt:
            print()
            print("[TFTP] shutting down")
            return
        parsed = parse_rrq(pkt)
        if parsed is None:
            print(f"[TFTP] ignored non-RRQ from {addr}")
            continue
        filename, mode = parsed
        threading.Thread(
            target=handle_transfer,
            args=(addr, filename, mode, base_real),
            daemon=True,
        ).start()


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "filename",
        nargs="?",
        help="single file to publish (mutually exclusive with --dir)",
    )
    parser.add_argument(
        "--dir",
        default=None,
        help=f"directory to serve (default: {TFTP_DEFAULT_DIR})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=TFTP_DEFAULT_PORT,
        help="UDP port to listen on (default: %(default)s; use >=1024 unprivileged)",
    )
    args = parser.parse_args(argv)

    if args.filename and args.dir:
        parser.error("specify a positional filename OR --dir, not both")

    if args.filename:
        # The single-file form lets the user point us straight at
        # build/kernel-ota.bin; we serve from that file's parent
        # dir and the client must request the basename.
        target = os.path.realpath(args.filename)
        if not os.path.isfile(target):
            print(f"error: file not found: {args.filename}", file=sys.stderr)
            sys.exit(2)
        base_dir = os.path.dirname(target)
        print(f"[TFTP] single-file mode — request '{os.path.basename(target)}'")
    else:
        base_dir = args.dir or TFTP_DEFAULT_DIR

    serve(args.port, base_dir)


if __name__ == "__main__":
    main(sys.argv[1:])
