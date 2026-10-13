#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The RFC-0019 encrypted brain link, end to end, against a booted kernel.

`link auth accepts valid key` shows the key loads. This peer runs what follows
it on the kernel's own brain link: a handshake, sealed records both ways, a
rekey in each direction, and an in-session REJECT. The crypto is AzOSRobotBrain's
`secure_channel.py`, imported from the sibling repo — nothing here restates it
— and the brain-protocol framing is `fake_brain.py`'s, which its `--selftest`
pins against `brain_protocol.rs`.

Listens where the kernel dials (CONFIG.INI `behavior_server_ip:port`, which the
standard image sets to 10.0.2.2:9000 — SLIRP maps that to this host), accepts,
and runs the brain-side (initiator) handshake. The PSK is read out of the image
the kernel boots (`::LINK.KEY`, with mtools): the Makefile draws that key from
/dev/urandom and keeps no other copy, so the image is the only source.

Phases, each ending in a `[link-peer] phase N done` line for
`tools/ci_check.sh` (`link: rfc-0019 end to end`):

  1. open a sealed SensorPacket from the kernel;
  2. send sealed ActuatorCmd drive frames, which the kernel applies to both
     wheels (`[ACTSMOKE] kernel motor id=N duty=60` under `actuation-smoke`);
  3. force a brain-side rekey — the next seal starts with a REKEY record — seal
     PKT_ESTOP behind it, then keep driving. As with `fake_brain.py
     --kernel-estop`, the drive frames after the stop are what the gate asserts
     on: a latch is visible from outside only as later commands that move no
     wheel, and every one of them is sealed under the new generation;
  4. keep opening kernel records after the brain's REKEY, and after at least
     one kernel REKEY (a `link-rekey-smoke` kernel rekeys every few seconds);
  5. send one record with a flipped ciphertext bit; the kernel must answer with
     a REJECT record and close, dial again, and complete a second handshake
     whose session id differs from the first.

With `--camera-port` (CONFIG.INI `behavior_camera_port`), the peer also listens
where the kernel's camera task dials, as AzOSRobotBrain's `camera_link.py` does: a
handshake per camera connection, then records it only reads. On top of the
phases above, each step ending in a `[link-peer] camera ... done` line: the
first camera connection carries sealed camera frames and a kernel REKEY; it
closes when phase 5 ends the control session; the control session that
replaces it gets a new camera connection; the four session ids differ; no
camera frame travels on a control connection, and nothing else on a camera one.

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

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
# The sibling repo, located the way tools/ci_full.sh does ($OS_DIR/../AzOSRobotBrain).
BRAIN_DIR = os.path.realpath(
    os.environ.get("AZOS_BRAIN_DIR") or os.path.join(TOOLS_DIR, "..", "..", "AzOSRobotBrain")
)

sys.path.insert(0, TOOLS_DIR)
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
    """One TCP connection to the kernel and the RFC-0019 session on it."""

    def __init__(self, conn, psk: bytes, sender) -> None:
        self.conn = conn
        self.sc = SC(psk, is_initiator=True)
        # One Sender for the whole run: the kernel's envelope replay mark
        # survives reconnects, so the envelope nonce must keep rising.
        self.sender = sender
        # A fresh Receiver per session, as `protocol.perform_handshake` does.
        self.receiver = sc_mod.Receiver(psk)
        self._buf = bytearray()
        self._msg = bytearray()
        self.eof = False
        self.rejected = False
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
        """Brain-side handshake; returns the session id as hex."""
        self.conn.settimeout(timeout)
        try:
            self.conn.sendall(self.sc.start_handshake())
        except OSError as e:
            raise PeerFailure(f"handshake — send failed: {e}") from None
        head = self._recv_exact(sc_mod.REJECT_BYTES)
        if head == sc_mod.REJECT_FRAME:
            reply = head
        else:
            # The brain's own reply size (`protocol._read_handshake_reply`).
            reply = head + self._recv_exact(
                brain_protocol._HELLO_REPLY_BYTES - sc_mod.REJECT_BYTES)
        try:
            confirm = self.sc.handle_peer_hello(reply)
        except sc_mod.PeerRejected:
            raise PeerFailure("handshake — kernel sent REJECT in place of its HELLO") from None
        except (ValueError, PermissionError) as e:
            self.conn.sendall(sc_mod.REJECT_FRAME)
            raise PeerFailure(f"handshake — kernel HELLO refused ({e}); REJECT sent") from None
        self.conn.sendall(confirm)
        self.conn.settimeout(10.0)
        return self.sc.session_id.hex()

    # ── Receive ────────────────────────────────────────────────────────

    def feed(self, data: bytes) -> None:
        """Open every whole record in the stream so far."""
        if self.rejected:
            return  # the session is over; the bytes before the close are noise
        self._buf += data
        hs = sc_mod.AEAD_HEADER_SIZE
        while len(self._buf) >= hs:
            try:
                size = self.sc.record_size(bytes(self._buf[:hs]))
            except sc_mod.LinkViolation as e:
                raise PeerFailure(f"kernel record header refused: {e}") from None
            if len(self._buf) < size:
                return
            record = bytes(self._buf[:size])
            del self._buf[:size]
            try:
                kind, payload = self.sc.open_record(record)
            except sc_mod.PeerRejected:
                self.rejected = True
                self._buf.clear()
                return
            except sc_mod.LinkViolation as e:
                raise PeerFailure(f"kernel record refused: {e}") from None
            if kind == SC.RECORD_REKEY:
                self.kernel_rekeys += 1
                self.since_kernel_rekey = 0
                continue
            self._msg += payload
            if kind == SC.RECORD_DATA:
                self._message(bytes(self._msg))
                self._msg = bytearray()

    def _message(self, envelope: bytes) -> None:
        inner = self.receiver.unwrap(envelope)
        parsed = brain_protocol.parse_packet(inner) if inner is not None else None
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
            if not end_ok and self.rejected:
                raise PeerFailure(f"{label} — kernel sent a REJECT record")
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
        wire = self.sc.seal_message(self.sender.wrap(fake_brain.build_packet(ptype, payload)))
        if rekey:
            flags, _ = sc_mod.parse_record_header(wire[:sc_mod.AEAD_HEADER_SIZE])
            if flags != sc_mod.RECORD_FLAG_REKEY or self.sc.tx_generation != generation + 1:
                raise PeerFailure("brain REKEY — the seal did not start with a REKEY record")
            self.since_brain_rekey = 0
        if tamper:
            flipped = bytearray(wire)
            flipped[sc_mod.AEAD_HEADER_SIZE] ^= 0x01  # first ciphertext byte
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
            if self.rejected:
                raise PeerFailure(f"{what} — kernel sent a REJECT record after {sent} frames")
            if self.eof:
                raise PeerFailure(f"{what} — kernel closed the connection after {sent} frames")
        return sent


def accept(srv, n: int, wait: float, psk: bytes, sender, timeout: float):
    srv.settimeout(wait)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        if n == 1:
            raise PeerFailure(f"no-robot — nothing connected within {wait:.0f}s") from None
        raise PeerFailure(
            f"phase 5 — no second connection within {wait:.0f}s after the REJECT") from None
    say(f"robot connected from {addr[0]} (connection {n})")
    link = Link(conn, psk, sender)
    sid = link.handshake(timeout)
    say(f"session {n} established sid={sid}")
    return link, sid


def non_camera_types(link) -> list:
    """Packet types other than CAMERA_FRAME that `link` opened."""
    return sorted(t for t in link.types if t != brain_protocol.CAMERA_FRAME)


class CameraSide:
    """AzOSRobotBrain's camera listener (`camera_link.py`) for `--camera-port`:
    accepts the kernel's camera connections one at a time on a thread of its
    own, runs the brain-side handshake on each, and opens every record the
    kernel sends. It never writes after the handshake."""

    def __init__(self, host: str, port: int, psk: bytes, sender, timeout: float) -> None:
        self.psk, self.sender, self.timeout = psk, sender, timeout
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, max(port, 0)))  # -1: any free port
        self.srv.listen(2)
        self.srv.settimeout(0.5)
        self._sessions: list = []  # (sid, Link) in accept order
        self.failure = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        self.srv.close()

    def count(self) -> int:
        return len(self._sessions)

    def sid(self, n: int) -> str:
        return self._sessions[n][0]

    def link(self, n: int):
        return self._sessions[n][1]

    def frames(self, n: int) -> int:
        if n >= len(self._sessions):
            return 0
        return self._sessions[n][1].types.get(brain_protocol.CAMERA_FRAME, 0)

    def _serve(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = self.srv.accept()
                except socket.timeout:
                    continue
                n = len(self._sessions) + 1
                say(f"camera connection {n} from {addr[0]}")
                link = Link(conn, self.psk, self.sender)
                sid = link.handshake(self.timeout)
                self._sessions.append((sid, link))
                say(f"camera session {n} established sid={sid}")
                while not (link.eof or link.rejected or self._stop.is_set()):
                    link.pump(0.25)
                say(f"camera connection {n} ended: {self.frames(n - 1)} camera frames, "
                    f"kernel_rekeys={link.kernel_rekeys} eof={link.eof} "
                    f"rejected={link.rejected}")
                conn.close()
        except (PeerFailure, OSError) as e:
            self.failure = str(e)
            say(f"camera side stopped: {e}")


def wait_camera(cam: CameraSide, link, cond, timeout: float, what: str) -> None:
    """Wait for `cond()` on the camera side, reading the control `link` (when
    there is one) meanwhile: an undrained control socket backs TCP up."""
    deadline = time.monotonic() + timeout
    while not cond():
        if cam.failure:
            raise PeerFailure(f"{what} — {cam.failure}")
        if link is not None and (link.eof or link.rejected):
            raise PeerFailure(f"{what} — the control connection ended first")
        if time.monotonic() >= deadline:
            raise PeerFailure(f"{what} — not within {timeout:.0f}s")
        if link is not None:
            link.pump(0.1)
        else:
            time.sleep(0.1)


def run(args) -> None:
    psk = load_psk(args.image)
    sender = sc_mod.Sender(psk)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(2)
    cam = None
    if args.camera_port:
        cam = CameraSide(args.host, args.camera_port, psk, sender, args.phase_timeout)
        cam.start()
        say(f"camera listener on {args.host}:{cam.srv.getsockname()[1]}")
    say(f"listening on {args.host}:{srv.getsockname()[1]} (LINK.KEY from {args.image})")

    link, sid1 = accept(srv, 1, args.wait, psk, sender, args.phase_timeout)

    # Phase 1 — the kernel's first records open under the session keys.
    link.wait_for(lambda: link.sensors >= 1, args.phase_timeout, "phase 1: SensorPacket")
    say(f"phase 1 done: SensorPacket opened ({link.messages} kernel messages)")
    if cam:
        wait_camera(cam, link, lambda: cam.frames(0) >= 1, args.phase_timeout,
                    "camera phase 1: a sealed camera frame on the first camera connection")
        say(f"camera phase 1 done: camera session 1 sid={cam.sid(0)}, "
            f"{cam.frames(0)} camera frames")

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
    if not cam:
        # No camera connection: camera frames travel inline, sealed as
        # multi-record messages among the control records.
        link.wait_for(lambda: link.types.get(brain_protocol.CAMERA_FRAME, 0) >= 1,
                      args.phase_timeout, "phase 4: a sealed camera frame on the control connection")
        say(f"inline camera frames on the control connection: "
            f"{link.types[brain_protocol.CAMERA_FRAME]}")
    if cam:
        wait_camera(cam, link, lambda: cam.link(0).kernel_rekeys >= 1, args.phase_timeout,
                    "camera phase 4: a kernel REKEY on the first camera connection")
        if cam.count() != 1 or cam.link(0).eof:
            raise PeerFailure("camera phase 4 — the first camera connection ended while its "
                              "control session was up")
        say(f"camera phase 4 done: {cam.frames(0)} camera frames, "
            f"kernel_rekeys={cam.link(0).kernel_rekeys}")

    # Phase 5 — a tampered record ends the session; a new one replaces it.
    link.send(fake_brain.PKT_ACTUATOR, DRIVE, tamper=True)
    say("tampered record sent (one ciphertext bit flipped)")
    link.wait_for(lambda: link.rejected or link.eof, args.phase_timeout,
                  "phase 5: REJECT record or close after the tampered record", end_ok=True)
    if not link.rejected:
        raise PeerFailure("phase 5 — kernel closed without sending a REJECT record")
    say("kernel answered the tampered record with a REJECT record")
    link.wait_for(lambda: link.eof, args.phase_timeout,
                  "phase 5: close after the REJECT record", end_ok=True)
    say("kernel closed the connection")
    link.conn.close()
    if cam:
        wait_camera(cam, None, lambda: cam.link(0).eof, args.phase_timeout,
                    "camera phase 5: the first camera connection closing with its control session")
        say("camera connection 1 closed with its control session")

    link2, sid2 = accept(srv, 2, args.reconnect_wait, psk, sender, args.phase_timeout)
    if sid2 == sid1:
        raise PeerFailure(f"phase 5 — second session reused session id {sid1}")
    link2.wait_for(lambda: link2.sensors >= 1, args.phase_timeout,
                   "phase 5: SensorPacket on the second session")
    say(f"phase 5 done: REJECT, close, second session sid={sid2} differs from sid={sid1}")
    if cam:
        wait_camera(cam, link2, lambda: cam.frames(1) >= 1, args.reconnect_wait,
                    "camera phase 5: a camera frame on a second camera connection")
        sids = {sid1, sid2, cam.sid(0), cam.sid(1)}
        if len(sids) != 4:
            raise PeerFailure(f"camera phase 5 — session ids repeat: control {sid1} {sid2}, "
                              f"camera {cam.sid(0)} {cam.sid(1)}")
        for n, ctl in enumerate((link, link2), 1):
            if ctl.types.get(brain_protocol.CAMERA_FRAME, 0):
                raise PeerFailure(f"camera — {ctl.types[brain_protocol.CAMERA_FRAME]} camera "
                                  f"frames on control connection {n}")
        for n in range(cam.count()):
            other = non_camera_types(cam.link(n))
            if other:
                raise PeerFailure(f"camera — packet types {other} on camera connection {n + 1}")
        say(f"camera phase 5 done: camera session 2 sid={cam.sid(1)}, {cam.frames(1)} camera "
            f"frames; four distinct session ids; no camera frame on a control connection")
    link2.pump(2.0)  # let the kernel log what it received before teardown
    link2.conn.close()
    if cam:
        cam.stop()
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
    """The kernel's view: every record in `data`, opened in order."""
    out, off = [], 0
    while off < len(data):
        size = chan.record_size(data[off:off + sc_mod.AEAD_HEADER_SIZE])
        out.append(chan.open_record(data[off:off + size]))
        off += size
    return out


def selftest() -> int:
    """Every `Link` code path the phases use, against AzOSRobotBrain's responder
    side, in memory. A broken import, a moved attribute or a framing change
    fails here instead of as a QEMU boot that reads like a kernel fault."""
    fake_brain.selftest()
    where = os.path.realpath(os.path.dirname(os.path.abspath(sc_mod.__file__)))
    if where != BRAIN_DIR:
        raise PeerFailure(f"selftest — secure_channel imported from {where}, not {BRAIN_DIR}")
    psk = os.urandom(sc_mod.KEY_BYTES)
    kernel = SC(psk, is_initiator=False)
    k_send = sc_mod.Sender(psk, direction=sc_mod.DIR_S2C)
    k_recv = sc_mod.Receiver(psk, direction=sc_mod.DIR_C2S)
    wire = _Wire()
    link = Link(wire, psk, sc_mod.Sender(psk))
    confirm = link.sc.handle_peer_hello(kernel.handle_initiator_hello(link.sc.start_handshake()))
    kernel.handle_initiator_confirm(confirm)
    assert link.sc.session_id == kernel.session_id and len(link.sc.session_id) == 16

    def kernel_sends(ptype: int, payload: bytes, rekey: bool = False) -> bytes:
        if rekey:
            kernel.request_rekey()
        return kernel.seal_message(k_send.wrap(brain_protocol.build_packet(ptype, payload)))

    sensor = brain_protocol.SensorPacket(1, 7400, (0, 0, 1000), (0, 0, 0), 0, 0, 0, 0, 0, 0)
    # A kernel REKEY, then a SensorPacket, fed one byte at a time.
    for b in kernel_sends(brain_protocol.SENSOR_PACKET, sensor.to_bytes(), rekey=True):
        link.feed(bytes([b]))
    assert (link.kernel_rekeys, link.sensors, link.since_kernel_rekey) == (1, 1, 1), vars(link)
    # A camera-sized message: MORE records, opened as one.
    link.feed(kernel_sends(brain_protocol.CAMERA_FRAME, bytes(5000)))
    assert link.types.get(brain_protocol.CAMERA_FRAME) == 1 and link.dropped == 0
    assert non_camera_types(link) == [brain_protocol.SENSOR_PACKET], link.types

    # Brain REKEY + PKT_ESTOP, as phase 3 seals it.
    link.send(fake_brain.PKT_ESTOP, bytes([0]), rekey=True)
    opened = _open_all(kernel, wire.sent[-1])
    assert [k for k, _ in opened] == [SC.RECORD_REKEY, SC.RECORD_DATA], opened
    parsed = brain_protocol.parse_packet(k_recv.unwrap(opened[1][1]))
    assert parsed == (fake_brain.PKT_ESTOP, bytes([0])), parsed
    link.feed(kernel_sends(brain_protocol.SENSOR_PACKET, sensor.to_bytes()))
    assert link.since_brain_rekey == 1

    # Phase 5: the tampered record is refused, the REJECT ends the session.
    link.send(fake_brain.PKT_ACTUATOR, DRIVE, tamper=True)
    try:
        _open_all(kernel, wire.sent[-1])
        raise PeerFailure("selftest — the tampered record opened")
    except sc_mod.LinkViolation:
        pass
    link.feed(kernel.seal_reject())
    assert link.rejected and not link.sc.is_established
    say(f"selftest ok — AzOSRobotBrain secure_channel from {where}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000,
                    help="0: any free port; the bound one is printed on the 'listening on' line")
    ap.add_argument("--camera-port", type=int, default=0,
                    help="also accept the kernel's camera connections here (C1); -1: any "
                         "free port, printed on the 'camera listener on' line; 0: none")
    ap.add_argument("--image", help="disk image the kernel boots; LINK.KEY is read from it")
    ap.add_argument("--wait", type=float, default=180.0,
                    help="seconds to wait for the kernel's first connection")
    ap.add_argument("--gap", type=float, default=0.25, help="seconds between drive frames")
    ap.add_argument("--drive-s", type=float, default=12.0, help="phase 2 length")
    ap.add_argument("--after-s", type=float, default=20.0, help="phase 3 driving after the e-stop")
    ap.add_argument("--phase-timeout", type=float, default=30.0,
                    help="ceiling for each wait on the kernel inside a phase")
    ap.add_argument("--reconnect-wait", type=float, default=60.0,
                    help="seconds to wait for the kernel to dial again after the REJECT")
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
