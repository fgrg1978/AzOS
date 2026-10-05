# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A brain-server stand-in that ACCEPTS AND KEEPS READING.

Written 2026-09-08 while booting `build/disk-braincli.img` for the first time,
and its shape is the whole point — the first version of this file produced a
false bug report.

THE TRAP. That version accepted, then read with a 1 s timeout and, on timeout,
stopped reading that connection while holding it open. The peer's receive
window then filled, TCP applied backpressure, and ring 3's `brain_client`
logged "Send failed, disconnecting" — which reads exactly like a kernel
transport bug. It was the test peer refusing to drain.

So: non-blocking, and every open connection is drained on every pass.

WHAT THIS CANNOT TELL YOU. Two dialers target 10.0.2.2:9000 — the kernel's own
brain link (`kernel/src/tasks/brain_link.rs`) and ring 3's `brain_client` — and under
QEMU's SLIRP user networking the source port seen here is SLIRP's translated
port, not the guest's. An earlier version printed a "kernel vs ring3" verdict
from that port; it was meaningless. Tell them apart from the GUEST log
(`[brain_client]` lines) or by giving them different destination ports.

Usage:  python3 tools/hold_peer.py [seconds]
"""
import socket, sys, time

PORT = 9000
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 55.0

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT))
srv.listen(8)
srv.settimeout(1.0)

conns = []
accepts = 0
total_bytes = 0
t0 = time.time()
while time.time() - t0 < DURATION:
    try:
        c, a = srv.accept()
        c.setblocking(False)
        conns.append((a, c))
        accepts += 1
        print(f"[hold] accept #{accepts} (translated src :{a[1]})", flush=True)
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[hold] accept error {e}", flush=True)
    for a, c in list(conns):
        try:
            d = c.recv(4096)
            if not d:
                print(f"[hold] :{a[1]} closed by peer", flush=True)
                conns.remove((a, c))
            else:
                total_bytes += len(d)
                print(f"[hold] :{a[1]} got {len(d)} B", flush=True)
        except BlockingIOError:
            pass
        except Exception as e:
            print(f"[hold] :{a[1]} {e}", flush=True)
            conns.remove((a, c))

print(f"[hold] DONE accepts={accepts} bytes={total_bytes} still_open={len(conns)}",
      flush=True)
