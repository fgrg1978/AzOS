#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Host peer of vsbench's TCP bulk lanes (`tcp-bulk-tx`, `tcp-bulk-rx`).

`tools/vsbench_compare.sh` starts it before each boot of its TCP pass. It
listens on 127.0.0.1 at a port the OS picks, writes that port to
`--port-file`, and serves one connection at a time until it is killed. The
guest reaches it as 10.0.2.2 through QEMU user networking (`-netdev user`).

Protocol (`userspace/bench/vsbench/src/bench_core.rs`, `TCP_CMD_*`): the
guest sends one command byte and the byte count as a big-endian u32.
  S  the guest sends: read exactly that many bytes, then answer one `K`.
  R  the guest receives: send that many bytes, then wait for the guest to
     close.

One line per connection goes to `--log`, with the HOST's wall clock:
  dir=tx|rx bytes=<n> wall_us=<us> bytes_per_s=<n>
tx is timed from the first data byte read to the last; rx from the request
to the guest's close (it closes right after its last byte). Wall time, so it
moves with host load; the guest-side numbers are the reproducible ones.
"""
import argparse
import os
import socket
import struct
import sys
import time

CHUNK = 64 * 1024


def read_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        got = conn.recv(n - len(buf))
        if not got:
            return None
        buf += got
    return bytes(buf)


def serve(conn, log):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    head = read_exact(conn, 5)
    if head is None:
        log.write("dir=? error=closed-before-request\n")
        return
    cmd, n = head[:1], struct.unpack(">I", head[1:])[0]
    if cmd == b"S":
        got, t0 = 0, None
        while got < n:
            data = conn.recv(min(CHUNK, n - got))
            if not data:
                break
            if t0 is None:
                t0 = time.monotonic()
            got += len(data)
        t1 = time.monotonic()
        if got != n:
            log.write("dir=tx error=short bytes=%d of %d\n" % (got, n))
            return
        conn.sendall(b"K")
        direction = "tx"
    elif cmd == b"R":
        t0 = time.monotonic()
        block = b"\xa5" * CHUNK
        sent = 0
        while sent < n:
            k = min(CHUNK, n - sent)
            conn.sendall(block[:k])
            sent += k
        # The guest closes once it has the last byte.
        conn.settimeout(120)
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass
        t1 = time.monotonic()
        got = sent
        direction = "rx"
    else:
        log.write("dir=? error=bad-command %r\n" % cmd)
        return
    us = max(1, int((t1 - t0) * 1e6))
    log.write("dir=%s bytes=%d wall_us=%d bytes_per_s=%d\n"
              % (direction, got, us, got * 1000000 // us))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    with open(a.log, "a", buffering=1) as log:
        with open(a.port_file + ".tmp", "w") as f:
            f.write("%d\n" % srv.getsockname()[1])
        # Renamed into place: the reader never sees a half-written port.
        os.replace(a.port_file + ".tmp", a.port_file)
        while True:
            conn, _ = srv.accept()
            try:
                serve(conn, log)
            except OSError as e:
                log.write("dir=? error=%s\n" % e)
            finally:
                conn.close()


if __name__ == "__main__":
    sys.exit(main())
