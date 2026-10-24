#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A one-directory, read-only HTTP server for the UEFI HTTP Boot rows.

    http_serve.py <root> --port-file <file> --log <file> [--port N]

Binds 127.0.0.1 on a free port (or N), writes the port number to --port-file
once it is listening, and appends one line per request to --log:

    <METHOD> <path> <status> <bytes>

The row reads that log to prove the firmware really fetched the image over
HTTP (a file the firmware found anywhere else would not appear in it). The
guest reaches this server as 10.0.2.2:<port> (QEMU user networking forwards
the gateway address to the host's loopback).

Stops on SIGTERM. Serves only regular files below <root>; a path that leaves it
is a 404. UEFI HTTP Boot sends a HEAD first to learn the length, then a GET:
both are answered with Content-Length and a keep-alive connection.
"""
import argparse
import http.server
import os
import signal
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log_path = ""

    def translate_path(self, path):
        # Only files below the root: the base class already maps there, this
        # refuses what resolves outside it (symlinks, "..").
        p = super().translate_path(path)
        real = os.path.realpath(p)
        root = os.path.realpath(self.directory)
        if real != root and not real.startswith(root + os.sep):
            return os.path.join(root, "\0denied")
        return p

    def list_directory(self, path):
        self.send_error(404, "no listing")
        return None

    length = "-"

    def send_header(self, keyword, value):
        if keyword.lower() == "content-length":
            self.length = value
        super().send_header(keyword, value)

    def log_request(self, code="-", size="-"):
        with open(self.log_path, "a") as f:
            f.write("%s %s %d %s\n" % (self.command, self.path, int(code), self.length))
        self.length = "-"

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()

    Handler.log_path = a.log
    open(a.log, "w").close()
    handler = lambda *args, **kw: Handler(*args, directory=a.root, **kw)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), handler)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    with open(a.port_file + ".tmp", "w") as f:
        f.write("%d\n" % srv.server_address[1])
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
