#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The encrypted brain link, end to end, against a booted kernel.

`link auth accepts valid key` shows the key loads. This peer runs what follows
it on the kernel's own brain link: a handshake, sealed frames both ways, a
rekey in each direction, and a tampered frame the kernel must close on. The crypto is AzOSRobotBrain's
`secure_channel.py`, imported from the sibling repo — nothing here restates it
— and the brain-protocol framing is `fake_brain.py`'s, which its `--selftest`
pins against `brain_protocol.rs`.

Listens where the kernel dials (CONFIG.INI `behavior_server_ip:port`, which the
standard image sets to 10.0.2.2:9000 — SLIRP maps that to this host), accepts,
and runs the brain-side (responder) handshake: the kernel dials and speaks
first. Noise_XX with the keys derived from the link key, or Noise_IK when
`--noise-sk` gives the private half of the key the kernel's signed topology
pins (`noise_pk` of its `[peer.brain]` row; the image must carry that row).
Every message is one brain-protocol frame: the session is the only layer.
The PSK is read out of the image
the kernel boots (`::LINK.KEY`, with mtools): the Makefile draws that key from
/dev/urandom and keeps no other copy, so the image is the only source.

Phases, each ending in a `[link-peer] phase N done` line for
`tools/gate/ci_check.sh` (`link: encrypted end to end`):

  1. open a sealed SensorPacket from the kernel;
  2. send sealed ActuatorCmd drive frames, which the kernel applies to both
     wheels (`[ACTSMOKE] kernel motor id=N duty=60` under `actuation-smoke`);
  3. force a brain-side rekey — the next seal starts with a rekey frame — seal
     PKT_ESTOP behind it, then keep driving. As with `fake_brain.py
     --kernel-estop`, the drive frames after the stop are what the gate asserts
     on: a latch is visible from outside only as later commands that move no
     wheel, and every one of them is sealed under the new generation;
  4. keep opening kernel frames after the brain's REKEY, and after at least
     one kernel REKEY (a `link-rekey-smoke` kernel rekeys every few seconds);
  5. send one frame with a flipped ciphertext bit; the kernel must close (there
     is no REJECT frame), dial again, and complete a second handshake whose
     session id differs from the first.

The robot sends its camera frames on this same connection (the engine's
`PKT_CAMERA`, at most one per `BRAIN_CAMERA_PERIOD_MS`), so phase 4 also waits
for a sealed camera frame among the control frames.

Any failure prints `[link-peer] FAIL <what>` and exits non-zero; a complete
script ends with `[link-peer] PASS`.
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402
# The optional brain repo, found by tools/lib/azos_tools.py (AZOS_BRAIN_DIR, then the siblings).
BRAIN_DIR = azos_tools.brain_dir()
if BRAIN_DIR is None:
    print("[link-peer] FAIL import — no AzOSRobotBrain (set AZOS_BRAIN_DIR)", flush=True)
    sys.exit(4)

sys.path.insert(1, BRAIN_DIR)

import fake_brain  # noqa: E402

try:
    import protocol as brain_protocol  # noqa: E402
    import secure_channel as sc_mod  # noqa: E402
except ImportError as e:
    print(f"[link-peer] FAIL import — AzOSRobotBrain is not importable from {BRAIN_DIR}: {e}",
          flush=True)
    sys.exit(4)

SC = sc_mod.SecureChannel
# ActuatorCmd both wheels at 60 %, the frame `fake_brain.py --kernel-estop` drives with.
DRIVE = fake_brain.actuator_payload(60, 60)


def say(msg: str) -> None:
    print(f"[link-peer] {msg}", flush=True)


class PeerFailure(Exception):
    """A step the kernel did not complete; the message names it."""


def load_psk(image: str) -> bytes:
    """The key the kernel reads as /fat/LINK.KEY, out of the image it boots."""
    try:
        out = subprocess.run(
            ["mcopy", "-n", "-i", image, "::LINK.KEY", "-"],
            check=True, capture_output=True, timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise PeerFailure(f"key — cannot read ::LINK.KEY from {image}: {e}") from None
    if len(out) != sc_mod.KEY_BYTES:
        raise PeerFailure(
            f"key — ::LINK.KEY in {image} is {len(out)} bytes, want {sc_mod.KEY_BYTES}")
    return out


class Link:
    """One TCP connection to the kernel and the encrypted-link session on it."""

    def __init__(self, conn, psk: bytes, static_key=None) -> None:
        self.conn = conn
        # The kernel dials, so this side is the Noise responder.
        self.sc = SC(psk, is_initiator=False, static_key=static_key)
        self._buf = bytearray()
        self.eof = False
        self.kernel_rekeys = 0
        self.messages = 0
        self.sensors = 0
        self.since_kernel_rekey = 0
        self.since_brain_rekey = -1  # counts from the brain's REKEY
        self.dropped = 0
        self.types: dict = {}

    # ── Handshake ──────────────────────────────────────────────────────

    def _recv_exact(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            try:
                chunk = self.conn.recv(n - len(out))
            except OSError as e:
                raise PeerFailure(f"handshake — receive failed: {e}") from None
            if not chunk:
                raise PeerFailure("handshake — kernel closed the connection")
            out += chunk
        return bytes(out)

    def handshake(self, timeout: float) -> str:
        """Brain-side (responder) handshake; returns the session id as hex."""
        self.conn.settimeout(timeout)
        try:
            self.sc.begin(self._recv_exact(1)[0])
            while not self.sc.is_established:
                head = self._recv_exact(sc_mod.FRAME_HEAD)
                try:
                    total = sc_mod.handshake_frame_size(head)
                except ValueError as e:
                    raise PeerFailure(f"handshake — kernel frame refused ({e})") from None
                reply = self.sc.handle_handshake(head + self._recv_exact(total - sc_mod.FRAME_HEAD))
                if reply:
                    self.conn.sendall(reply)
        except sc_mod.LinkViolation as e:
            raise PeerFailure(f"handshake — kernel handshake refused ({e})") from None
        except OSError as e:
            raise PeerFailure(f"handshake — send failed: {e}") from None
        self.conn.settimeout(10.0)
        return self.sc.session_id.hex()

    # ── Receive ────────────────────────────────────────────────────────

    def feed(self, data: bytes) -> None:
        """Open every whole frame in the stream so far."""
        self._buf += data
        head = sc_mod.FRAME_HEAD
        while len(self._buf) >= head:
            try:
                size = self.sc.frame_size(bytes(self._buf[:head]))
            except sc_mod.LinkViolation as e:
                raise PeerFailure(f"kernel frame header refused: {e}") from None
            if len(self._buf) < size:
                return
            frame = bytes(self._buf[:size])
            del self._buf[:size]
            try:
                kind, payload = self.sc.open_frame(frame)
            except sc_mod.LinkViolation as e:
                raise PeerFailure(f"kernel frame refused: {e}") from None
            if kind == SC.RECORD_REKEY:
                self.kernel_rekeys += 1
                self.since_kernel_rekey = 0
                continue
            self._message(payload)

    def _message(self, frame: bytes) -> None:
        parsed = brain_protocol.parse_packet(frame)
        if parsed is None:
            self.dropped += 1
            return
        ptype, payload = parsed
        if ptype == brain_protocol.SENSOR_PACKET:
            try:
                brain_protocol.SensorPacket.from_bytes(payload)
            except ValueError as e:
                raise PeerFailure(f"SensorPacket refused by the brain's parser: {e}") from None
            self.sensors += 1
        self.types[ptype] = self.types.get(ptype, 0) + 1
        self.messages += 1
        self.since_kernel_rekey += 1
        if self.since_brain_rekey >= 0:
            self.since_brain_rekey += 1

    def pump(self, seconds: float) -> None:
        """Read and open what the kernel sends for up to `seconds`."""
        deadline = time.monotonic() + seconds
        while not self.eof:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            ready, _, _ = select.select([self.conn], [], [], left)
            if not ready:
                return
            try:
                data = self.conn.recv(65536)
            except OSError:
                data = b""
            if not data:
                self.eof = True
                return
            self.feed(data)

    def wait_for(self, cond, timeout: float, what, *, end_ok: bool = False) -> None:
        """Pump until `cond()`; the session ending first is a failure unless
        `end_ok`. `what` names the wait, or is a callable that names it at the
        moment of failure (for counts)."""
        deadline = time.monotonic() + timeout
        while not cond():
            label = what() if callable(what) else what
            if not end_ok and self.eof:
                raise PeerFailure(f"{label} — kernel closed the connection")
            if time.monotonic() >= deadline:
                raise PeerFailure(f"{label} — not within {timeout:.0f}s")
            self.pump(min(0.25, max(0.0, deadline - time.monotonic())))

    # ── Send ───────────────────────────────────────────────────────────

    def send(self, ptype: int, payload: bytes, *, rekey: bool = False,
             tamper: bool = False) -> None:
        if rekey:
            self.sc.request_rekey()
        generation = self.sc.tx_generation
        wire = self.sc.seal_message(fake_brain.build_packet(ptype, payload))
        if rekey:
            # The seal starts with an empty-message frame: a bare tag.
            if (len(wire) < 2 * sc_mod.FRAME_OVERHEAD
                    or wire[:sc_mod.FRAME_HEAD] != sc_mod.TAG_LEN.to_bytes(sc_mod.FRAME_HEAD, "big")
                    or self.sc.tx_generation != generation + 1):
                raise PeerFailure("brain REKEY — the seal did not start with a rekey frame")
            self.since_brain_rekey = 0
        if tamper:
            flipped = bytearray(wire)
            flipped[-1 - sc_mod.TAG_LEN] ^= 0x01  # a ciphertext byte of the last frame
            wire = bytes(flipped)
        try:
            self.conn.sendall(wire)
        except OSError as e:
            raise PeerFailure(f"send failed: {e}") from None

    def drive(self, seconds: float, gap: float, what: str) -> int:
        """Drive frames every `gap` for `seconds`, opening kernel records in
        between. Never stop reading: an undrained socket backs TCP up, and
        that looks exactly like a kernel transport fault."""
        sent = 0
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.send(fake_brain.PKT_ACTUATOR, DRIVE)
            sent += 1
            self.pump(gap)
            if self.eof:
                raise PeerFailure(f"{what} — kernel closed the connection after {sent} frames")
        return sent


def accept(srv, n: int, wait: float, psk: bytes, timeout: float, static_key=None):
    srv.settimeout(wait)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        if n == 1:
            raise PeerFailure(f"no-robot — nothing connected within {wait:.0f}s") from None
        raise PeerFailure(
            f"phase 5 — no second connection within {wait:.0f}s after the close") from None
    say(f"robot connected from {addr[0]} (connection {n})")
    link = Link(conn, psk, static_key)
    sid = link.handshake(timeout)
    say(f"session {n} established sid={sid}")
    return link, sid


def non_camera_types(link) -> list:
    """Packet types other than CAMERA_FRAME that `link` opened."""
    return sorted(t for t in link.types if t != brain_protocol.CAMERA_FRAME)


def run(args) -> None:
    psk = load_psk(args.image)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(2)
    static_key = bytes.fromhex(args.noise_sk) if args.noise_sk else None
    say(f"listening on {args.host}:{srv.getsockname()[1]} (LINK.KEY from {args.image})")

    link, sid1 = accept(srv, 1, args.wait, psk, args.phase_timeout, static_key)

    # Phase 1 — the kernel's first records open under the session keys.
    link.wait_for(lambda: link.sensors >= 1, args.phase_timeout, "phase 1: SensorPacket")
    say(f"phase 1 done: SensorPacket opened ({link.messages} kernel messages)")

    # Phase 2 — commands the kernel acts on.
    sent = link.drive(args.drive_s, args.gap, "phase 2")
    say(f"phase 2 done: {sent} sealed ActuatorCmd drive frames")

    # Phase 3 — brain REKEY, PKT_ESTOP behind it, then keep asking.
    link.send(fake_brain.PKT_ESTOP, bytes([0]), rekey=True)
    say(f"brain REKEY sent: tx generation {link.sc.tx_generation}, PKT_ESTOP sealed after it")
    after = link.drive(args.after_s, args.gap, "phase 3")
    say(f"phase 3 done: {after} drive frames after the e-stop, "
        f"tx generation {link.sc.tx_generation}")

    # Phase 4 — the kernel→brain direction across both rekeys.
    link.wait_for(
        lambda: link.kernel_rekeys >= 1 and link.since_kernel_rekey >= 1
        and link.since_brain_rekey >= 1,
        args.phase_timeout,
        lambda: (f"phase 4: a kernel REKEY followed by an opened record (kernel_rekeys="
                 f"{link.kernel_rekeys}, after_kernel_rekey={link.since_kernel_rekey}, "
                 f"after_brain_rekey={link.since_brain_rekey})"),
    )
    say(f"phase 4 done: kernel_rekeys={link.kernel_rekeys} "
        f"rx_generation={link.sc.rx_generation} "
        f"after_kernel_rekey={link.since_kernel_rekey} "
        f"after_brain_rekey={link.since_brain_rekey}")
    link.wait_for(lambda: link.types.get(brain_protocol.CAMERA_FRAME, 0) >= 1,
                  args.phase_timeout, "phase 4: a sealed camera frame on the control connection")
    say(f"camera frames on the control connection: {link.types[brain_protocol.CAMERA_FRAME]}")

    # Phase 5 — a tampered frame ends the session; a new one replaces it.
    link.send(fake_brain.PKT_ACTUATOR, DRIVE, tamper=True)
    say("tampered frame sent (one ciphertext bit flipped)")
    link.wait_for(lambda: link.eof, args.phase_timeout,
                  "phase 5: close after the tampered frame", end_ok=True)
    say("kernel closed the connection (no REJECT frame exists: a violation just closes)")
    link.conn.close()

    link2, sid2 = accept(srv, 2, args.reconnect_wait, psk, args.phase_timeout, static_key)
    if sid2 == sid1:
        raise PeerFailure(f"phase 5 — second session reused session id {sid1}")
    link2.wait_for(lambda: link2.sensors >= 1, args.phase_timeout,
                   "phase 5: SensorPacket on the second session")
    say(f"phase 5 done: close, second session sid={sid2} differs from sid={sid1}")
    link2.pump(2.0)  # let the kernel log what it received before teardown
    link2.conn.close()
    srv.close()
    say("PASS")


# ── Selftest ───────────────────────────────────────────────────────────────


class _Wire:
    """A connection stand-in that records what `Link` writes."""

    def __init__(self) -> None:
        self.sent: list = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def settimeout(self, _t) -> None:
        pass


def _open_all(chan, data: bytes) -> list:
    """The kernel's view: every frame in `data`, opened in order."""
    out, off = [], 0
    while off < len(data):
        size = chan.frame_size(data[off:off + sc_mod.FRAME_HEAD])
        out.append(chan.open_frame(data[off:off + size]))
        off += size
    return out


def selftest() -> int:
    """Every `Link` code path the phases use, against AzOSRobotBrain's
    initiator side (the kernel's role), in memory. A broken import, a moved
    attribute or a framing change fails here instead of as a QEMU boot that
    reads like a kernel fault."""
    fake_brain.selftest()
    where = os.path.realpath(os.path.dirname(os.path.abspath(sc_mod.__file__)))
    if where != BRAIN_DIR:
        raise PeerFailure(f"selftest — secure_channel imported from {where}, not {BRAIN_DIR}")
    psk = os.urandom(sc_mod.KEY_BYTES)
    kernel = SC(psk, is_initiator=True)
    wire = _Wire()
    link = Link(wire, psk)
    # The kernel speaks first: feed its pattern byte and frames to the peer.
    first = kernel.start_handshake()
    link.sc.begin(first[0])
    reply = link.sc.handle_handshake(first[1:])
    out = kernel.handle_handshake(reply)
    while out is not None:
        reply = link.sc.handle_handshake(out)
        if reply is None:
            break
        out = kernel.handle_handshake(reply)
    assert link.sc.is_established and kernel.is_established
    assert link.sc.session_id == kernel.session_id and len(link.sc.session_id) == 16

    def kernel_sends(ptype: int, payload: bytes, rekey: bool = False) -> bytes:
        if rekey:
            kernel.request_rekey()
        return kernel.seal_message(brain_protocol.build_packet(ptype, payload))

    sensor = brain_protocol.SensorPacket(1, 7400, (0, 0, 1000), (0, 0, 0), 0, 0, 0, 0, 0, 0)
    # A kernel REKEY, then a SensorPacket, fed one byte at a time.
    for b in kernel_sends(brain_protocol.SENSOR_PACKET, sensor.to_bytes(), rekey=True):
        link.feed(bytes([b]))
    assert (link.kernel_rekeys, link.sensors, link.since_kernel_rekey) == (1, 1, 1), vars(link)
    # A camera-sized message: one frame.
    link.feed(kernel_sends(brain_protocol.CAMERA_FRAME, bytes(5000)))
    assert link.types.get(brain_protocol.CAMERA_FRAME) == 1 and link.dropped == 0
    assert non_camera_types(link) == [brain_protocol.SENSOR_PACKET], link.types

    # Brain REKEY + PKT_ESTOP, as phase 3 seals it.
    link.send(fake_brain.PKT_ESTOP, bytes([0]), rekey=True)
    opened = _open_all(kernel, wire.sent[-1])
    assert [k for k, _ in opened] == [SC.RECORD_REKEY, SC.RECORD_DATA], opened
    parsed = brain_protocol.parse_packet(opened[1][1])
    assert parsed == (fake_brain.PKT_ESTOP, bytes([0])), parsed
    link.feed(kernel_sends(brain_protocol.SENSOR_PACKET, sensor.to_bytes()))
    assert link.since_brain_rekey == 1

    # Phase 5: the tampered frame is refused and ends the session.
    link.send(fake_brain.PKT_ACTUATOR, DRIVE, tamper=True)
    try:
        _open_all(kernel, wire.sent[-1])
        raise PeerFailure("selftest — the tampered frame opened")
    except sc_mod.LinkViolation:
        pass
    assert not kernel.is_established
    say(f"selftest ok — AzOSRobotBrain secure_channel from {where}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000,
                    help="0: any free port; the bound one is printed on the 'listening on' line")
    ap.add_argument("--image", help="disk image the kernel boots; LINK.KEY is read from it")
    ap.add_argument("--wait", type=float, default=180.0,
                    help="seconds to wait for the kernel's first connection")
    ap.add_argument("--gap", type=float, default=0.25, help="seconds between drive frames")
    ap.add_argument("--drive-s", type=float, default=12.0, help="phase 2 length")
    ap.add_argument("--after-s", type=float, default=20.0, help="phase 3 driving after the e-stop")
    ap.add_argument("--phase-timeout", type=float, default=30.0,
                    help="ceiling for each wait on the kernel inside a phase")
    ap.add_argument("--reconnect-wait", type=float, default=60.0,
                    help="seconds to wait for the kernel to dial again after the close")
    ap.add_argument("--noise-sk", default="",
                    help="hex of the brain's static private key, for a kernel whose signed "
                         "topology pins its public half ([peer.brain] noise_pk, Noise_IK); "
                         "empty: Noise_XX")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    try:
        if args.selftest:
            return selftest()
        if not args.image:
            ap.error("--image is required")
        run(args)
        return 0
    except PeerFailure as e:
        say(f"FAIL {e}")
        return 1
    except AssertionError as e:
        say(f"FAIL selftest assertion: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
