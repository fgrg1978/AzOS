#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""A brain that lies, for the QEMU scenarios of RFC-0035 step 6.

Listens where the kernel dials (`behavior_server_ip:behavior_server_port` from
CONFIG.INI, which the standard disk image sets to 10.0.2.2:9000 — QEMU's SLIRP
maps 10.0.2.2 to the host, so this process is the peer) and sends frames that
are **structurally valid and semantically wrong**.

Why that shape and not a corrupt one: a bit-garbled frame is dropped by
`parse_packet`'s CRC check before it ever reaches the dispatch, which tests the
parser rather than the safety layer. What has never been exercised is a frame
that passes every structural check and carries content the kernel must refuse.
That is the "brain lies" failure mode the product thesis names, and RFC-0037
records that nothing sends one:

    "No QEMU scenario sends a PKT_SEMANTIC_LEVEL to a booted kernel. The
     fail-closed unwrap_or(CONTAINED) on a truncated packet is the single most
     safety-relevant line in the design and has no runtime coverage at all."

This is the sender for that.

Not a stand-in for `../AzOSRobotBrain`. It speaks the wire format and nothing
else — no perception, no planning, no handshake — because the point is to be a
peer the kernel cannot distinguish from a real one at the frame level.
"""

import argparse
import hashlib
import hmac as hmac_mod
import socket
import struct
import sys
import time

MAGIC = b"BR"

# From domains/robot/behavior/src/brain_protocol.rs. Restated rather than generated
# because this file must be able to send a type the kernel does NOT know, which
# a generated mirror could not express.
PKT_SEMANTIC_LEVEL = 0x8B
PKT_DEGRADE = 0x8A
PKT_ESTOP = 0x88
PKT_UNKNOWN_PROBE = 0x7F  # deliberately not a type the kernel handles
# The one frame this file SENDS BACK rather than at: ring 3's `brain_client`
# turns it into motor commands, and so does the kernel's own brain link.
PKT_ACTUATOR = 0x80

# `PKT_MODE` / `MODE_ID_ESTOP_RESET`: the only rearm path in the tree (see
# `domains/robot/behavior/src/brain_protocol.rs`). Added 2026-09-25, alongside the
# owner decision that this frame — sent BARE, exactly as below — is now a
# REQUEST the kernel records but never acts on by itself. See
# `kernel_estop_release` for the frame that DOES clear the latch: the same
# `mode_id`, with an operator-signed proof appended.
PKT_MODE = 0x81
MODE_ID_ESTOP_RESET = 0xFF

# `safety::RELEASE_CONTEXT` in `domains/robot/behavior/src/safety.rs` — restated
# rather than imported for the same reason as the packet types above: this
# file has to be able to send bytes the kernel's Rust never constructs for
# it (a FORGED proof, for the negative scenario), which a generated mirror
# could not express.
RELEASE_CONTEXT = b"AZOS-ESTOP-RELEASE-v1"

DEGRADE_LEVEL_CONTAINED = 3

# ActuatorCmd payload, transcribed from `apply_actuator_cmd` in
# `userspace/services/brain_client/src/main.rs`:
#
#   [0] act_type    -- READ AND IGNORED by the client (`let _act_type`)
#   [1] n_channels  -- must be >= 2 or the client applies NOTHING, silently
#   [2] flags       -- bit 0 = emergency: motor_stop() and return
#   [3..] channels  -- i16 LITTLE-endian each; ch0 = left, ch1 = right
#
# Minimum 7 payload bytes. A frame that misses any of those conditions is
# dropped without a word, which is precisely how a serving peer produces a
# green scenario that proves nothing.
ACT_FLAG_EMERGENCY = 0x01

# V1.9 (coordinator decision, 2026-09-26): the HMAC envelope
# `domains/robot/behavior/src/auth_envelope_core.rs` verifies, restated here in
# Python for the same reason every other wire constant above is restated
# rather than imported. `DIR_RX` is the direction label a RECEIVER (the
# kernel, or now `brain_client`) verifies incoming frames under — this file
# plays the brain/sender role, so every wrapped frame it sends here is
# signed under `DIR_RX`, matching what a real receiver checks.
ENVELOPE_DIR_RX = b"C2S"
ENVELOPE_NONCE_BYTES = 8
ENVELOPE_HMAC_BYTES = 16
ENVELOPE_LEN_BYTES = 2


def wrap_envelope(key: bytes, nonce: int, inner: bytes) -> bytes:
    """`nonce(8 BE) | HMAC-SHA-256(dir || nonce || len || inner)[:16] | len(2 LE) | inner`."""
    nonce_b = nonce.to_bytes(ENVELOPE_NONCE_BYTES, "big")
    len_b = len(inner).to_bytes(ENVELOPE_LEN_BYTES, "little")
    mac = hmac_mod.new(key, ENVELOPE_DIR_RX + nonce_b + len_b + inner,
                       hashlib.sha256).digest()[:ENVELOPE_HMAC_BYTES]
    return nonce_b + mac + len_b + inner


# RFC-0019 encrypted mode (wave 9, P3): `brain_client` no longer accepts the
# HMAC envelope on its own — it runs the encrypted link, the envelope inside
# sealed records, exactly as the kernel's own link does. The crypto is
# AzOSRobotBrain's `secure_channel.py`, imported from the sibling repo the way
# `tools/link_peer.py` imports it (and honouring the same `AZOS_BRAIN_DIR`),
# so nothing here restates it. Imported only when `--encrypt` asks for it:
# every other mode of this file stays free of the sibling repo.
def load_secure_channel():
    import os
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    brain_dir = os.path.realpath(
        os.environ.get("AZOS_BRAIN_DIR") or os.path.join(tools_dir, "..", "..", "AzOSRobotBrain"))
    if brain_dir not in sys.path:
        sys.path.insert(0, brain_dir)
    try:
        import secure_channel  # noqa: E402
    except ImportError as e:
        print(f"[fake-brain] FAIL import — AzOSRobotBrain is not importable from {brain_dir}: {e}",
              flush=True)
        sys.exit(4)
    return secure_channel


class EncPeer:
    """One accepted connection in `--encrypt` mode: the brain-side (initiator)
    handshake, then sealed records both ways.

    States: `await` (HELLO sent, waiting for the responder's reply), `est`
    (session established), `plain` (the connection answered HELLO with bytes
    that are not a handshake reply — the kernel's own HMAC-only brain link,
    which dials the same port; it is drained and never answered), `dead`.
    """

    def __init__(self, sc_mod, psk: bytes):
        self.sc_mod = sc_mod
        self.sc = sc_mod.SecureChannel(psk, is_initiator=True)
        self.sender = sc_mod.Sender(psk)
        self.receiver = sc_mod.Receiver(psk)
        self.state = "await"
        self.buf = bytearray()
        self.msg = bytearray()
        self.sensors = 0
        self.client_rekeys = 0
        # A client REKEY whose completion (a record opened under the new key)
        # has not been seen yet: its number, 0 when none.
        self.rekey_pending = 0
        self.rejected = False

    def hello(self) -> bytes:
        return self.sc.start_handshake()

    def feed(self, data: bytes):
        """Consume inbound bytes. Returns the CONFIRM to send once the reply
        completes the handshake, else None. Raises on a refused session."""
        self.buf += data
        m = self.sc_mod
        if self.state == "await":
            if len(self.buf) < m.REJECT_BYTES:
                return None
            head = bytes(self.buf[:m.REJECT_BYTES])
            if head == m.REJECT_FRAME:
                self.state = "dead"
                raise RuntimeError("client sent REJECT in place of its HELLO")
            if head != bytes([0x02, 0x48]):
                self.state = "plain"
                self.buf.clear()
                return None
            want = 2 + 32 + 32
            if len(self.buf) < want:
                return None
            reply = bytes(self.buf[:want])
            del self.buf[:want]
            confirm = self.sc.handle_peer_hello(reply)
            self.state = "est"
            self._records()
            return confirm
        if self.state == "est":
            self._records()
        else:
            self.buf.clear()
        return None

    def _records(self) -> None:
        m = self.sc_mod
        hs = m.AEAD_HEADER_SIZE
        while len(self.buf) >= hs:
            size = self.sc.record_size(bytes(self.buf[:hs]))
            if len(self.buf) < size:
                return
            record = bytes(self.buf[:size])
            del self.buf[:size]
            try:
                kind, payload = self.sc.open_record(record)
            except m.PeerRejected:
                self.rejected = True
                self.state = "dead"
                return
            if kind == self.sc_mod.SecureChannel.RECORD_REKEY:
                self.client_rekeys += 1
                self.rekey_pending = self.client_rekeys
                print(f"[fake-brain] client REKEY #{self.client_rekeys} opened", flush=True)
                continue
            self.msg += payload
            if kind == self.sc_mod.SecureChannel.RECORD_DATA:
                inner = self.receiver.unwrap(bytes(self.msg))
                self.msg = bytearray()
                if inner is not None and len(inner) > 2 and inner[2] == 0x01:
                    self.sensors += 1
                    if self.sensors == 1:
                        print("[fake-brain] opened a sealed SensorPacket from the client "
                              "(first of this session)", flush=True)
                    # The REKEY record only announces the ratchet; the rekey
                    # is COMPLETE once a message sealed under the new key
                    # opens and its envelope verifies. Printed only here.
                    if self.rekey_pending:
                        print(f"[fake-brain] client REKEY #{self.rekey_pending} completed: "
                              "a SensorPacket opened under the new key", flush=True)
                        self.rekey_pending = 0

    def seal(self, frame: bytes, *, wrap: bool = True, rekey: bool = False) -> bytes:
        if rekey:
            self.sc.request_rekey()
        return self.sc.seal_message(self.sender.wrap(frame) if wrap else frame)


def crc8(data: bytes) -> int:
    """CRC-8/MAXIM, polynomial 0x31 — transcribed from `brain_protocol.rs`.

    Transcribed rather than imported: the kernel's copy is Rust in a `no_std`
    crate, and a Python reimplementation that disagreed would make every frame
    below get dropped by the CRC check instead of reaching the dispatch — which
    would look exactly like the kernel ignoring them. The `--selftest` flag
    exists to make that failure loud instead of silent.
    """
    crc = 0x00
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x31) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def build_packet(pkt_type: int, payload: bytes) -> bytes:
    """`MAGIC | type | len u16 LE | payload | crc8(header+payload)`."""
    header = MAGIC + bytes([pkt_type, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
    body = header + payload
    return body + bytes([crc8(body)])


def actuator_payload(left: int, right: int, flags: int = 0,
                     act_type: int = 0, n_channels: int = 2) -> bytes:
    """Build an ActuatorCmd payload. `left`/`right` are signed i16."""
    return bytes([act_type, n_channels & 0xFF, flags]) + struct.pack("<hh", left, right)


def announce_port(host: str, srv) -> int:
    """Print the port actually bound and return it. `--port 0` asks the OS for
    a free one; the gate row reads it back from this line and points the
    image's CONFIG.INI at it (ci_check.sh `run_brain_peer_boot`), so no other
    guest on the host -- they all dial 9000 -- can reach this peer."""
    port = srv.getsockname()[1]
    print(f"[fake-brain] listening on {host}:{port}", flush=True)
    return port


def kernel_estop(host: str, port: int, duration: float, gap: float,
                 send_estop: bool = True) -> int:
    """Drive the KERNEL's own brain link, then `PKT_ESTOP`, then keep driving.

    A different target from `--serve`. That mode answers ring 3's
    `brain_client`; this one talks to the kernel's `behavior_task` brain link,
    which is the only thing that handles `PKT_ESTOP` over TCP. The two never
    run in the same image: the link comes up only where `link_encrypt=0`, and
    the ring-3 client image has no LINK.KEY, so its kernel link closes on the
    handshake ("no plaintext fallback"). Measured, not assumed.

    **The script is drive / stop / DRIVE AGAIN, and the third phase is the
    assertion.** `PKT_ESTOP` latches, so what follows it is the only way to see
    the latch from outside: every command after it must reach the wheels as
    duty 0. Asserting on the `[BRAIN] ESTOP received` console line instead
    would be a false green — measured on the ring-3 path, where a handler that
    skipped the latch still printed "envelope latched" and the robot drove 20
    more times.

    Pushes on a timer rather than answering inbound traffic: the kernel link's
    own send cadence is not this test's business, and a peer that only replies
    would sit silent if the kernel went quiet for its own reasons.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    port = announce_port(host, srv)
    srv.settimeout(duration)
    print(f"[fake-brain] kernel-estop mode on {host}:{port}", flush=True)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print("[fake-brain] FAIL no-robot — nothing connected", flush=True)
        return 2
    print(f"[fake-brain] robot connected from {addr[0]}", flush=True)

    drive = build_packet(PKT_ACTUATOR, actuator_payload(60, 60))
    # One reason byte, matching `EStopCmd` in ../AzOSRobotBrain/protocol.py:
    # 0 = ESTOP_REASON_OPERATOR.
    estop = build_packet(PKT_ESTOP, bytes([0]))

    def drain(c):
        # Never stop reading. A peer that holds a connection open without
        # draining creates TCP backpressure that looks exactly like a kernel
        # transport bug -- it was reported as one on 2026-09-08.
        try:
            c.setblocking(False)
            while c.recv(4096):
                pass
        except (BlockingIOError, OSError):
            pass
        finally:
            try:
                c.setblocking(True)
            except OSError:
                pass

    sent = 0
    with conn:
        conn.settimeout(5.0)
        try:
            # Phase 1 — get the wheels moving.
            for _ in range(int(max(1.0, duration * 0.3) / gap)):
                conn.sendall(drive); sent += 1; drain(conn); time.sleep(gap)
            print(f"[fake-brain] phase 1 done: {sent} drive frames", flush=True)

            # Phase 2 — the e-stop, unless the stop is coming from somewhere
            # else. `--kernel-drive` is this same script with the frame
            # withheld: the GPIO kill-switch scenario needs a peer that only
            # ever asks the robot to move, so that anything which stops it can
            # only have been the switch.
            if send_estop:
                conn.sendall(estop)
                print("[fake-brain] sent PKT_ESTOP", flush=True)
            else:
                print("[fake-brain] withholding PKT_ESTOP (drive-only)", flush=True)
            time.sleep(gap)
            drain(conn)

            # Phase 3 — keep asking. THIS is what the scenario asserts on.
            after = 0
            for _ in range(int(max(1.0, duration * 0.5) / gap)):
                conn.sendall(drive); after += 1; drain(conn); time.sleep(gap)
            print(f"[fake-brain] phase 3 done: {after} drive frames "
                  f"after the e-stop", flush=True)
        except OSError as e:
            print(f"[fake-brain] link error {e}", flush=True)
            return 3
    print(f"[fake-brain] PASS kernel-estop script complete", flush=True)
    return 0


def mode_request_payload(mode_id: int = MODE_ID_ESTOP_RESET) -> bytes:
    """The historical, unchanged 1-byte `PKT_MODE` payload — a bare REQUEST
    (or, for any other `mode_id`, an ordinary mode change). Never clears the
    latch on its own after the 2026-09-25 owner decision."""
    return bytes([mode_id])


def mode_release_payload(priv_key_path, nonce: int,
                         mode_id: int = MODE_ID_ESTOP_RESET) -> bytes:
    """The LONGER `PKT_MODE` payload that carries an operator-signed release
    proof: `mode_id (1) || nonce (8, big-endian) || Ed25519 signature (64)`,
    matching `safety::RELEASE_PROOF_BYTES` in `domains/robot/behavior/src/safety.rs`.
    Signs `RELEASE_CONTEXT || nonce_be`, exactly `safety::release_message`'s
    contract (restated from the `pub` constants, not imported — this process
    has no Rust to import from).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("error: install the 'cryptography' package: pip install cryptography",
              file=sys.stderr)
        raise
    priv_raw = open(priv_key_path, "rb").read()
    if len(priv_raw) != 32:
        raise ValueError(f"operator private key must be 32 bytes, got {len(priv_raw)}")
    priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
    nonce_be = nonce.to_bytes(8, "big")
    sig = priv.sign(RELEASE_CONTEXT + nonce_be)
    assert len(sig) == 64, sig
    return bytes([mode_id]) + nonce_be + sig


def kernel_estop_release(host: str, port: int, duration: float, gap: float,
                         operator_priv) -> int:
    """Drive / latch / REQUEST (must not clear) / RELEASE (must clear).

    Proves the 2026-09-25 owner decision end to end over the same TCP brain
    link `--kernel-estop` uses: `PKT_ESTOP` latches, a bare `PKT_MODE`
    `MODE_ID_ESTOP_RESET` (phase 3) is recorded but changes nothing — the
    wheels must stay at duty 0 through phase 4 — and only the operator-signed
    `PKT_MODE` (phase 5, longer payload, same `mode_id`) actually clears it,
    which phase 6 (driving again) must show.

    Four phases turned into six for the same reason `kernel_estop`'s docstring
    gives for its own three: the assertion is a BEFORE and an AFTER around
    each state change, on the kernel's own `[ACTSMOKE] kernel motor` writes,
    never on a console line that only says a handler ran.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    port = announce_port(host, srv)
    srv.settimeout(duration)
    print(f"[fake-brain] kernel-estop-release mode on {host}:{port}", flush=True)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print("[fake-brain] FAIL no-robot — nothing connected", flush=True)
        return 2
    print(f"[fake-brain] robot connected from {addr[0]}", flush=True)

    drive = build_packet(PKT_ACTUATOR, actuator_payload(60, 60))
    estop = build_packet(PKT_ESTOP, bytes([0]))
    request = build_packet(PKT_MODE, mode_request_payload())
    try:
        release = build_packet(PKT_MODE, mode_release_payload(operator_priv, nonce=1))
    except (OSError, ValueError) as e:
        print(f"[fake-brain] FAIL could not build the release proof: {e}", flush=True)
        return 4

    def drain(c):
        try:
            c.setblocking(False)
            while c.recv(4096):
                pass
        except (BlockingIOError, OSError):
            pass
        finally:
            try:
                c.setblocking(True)
            except OSError:
                pass

    n_each = int(max(1.0, duration * 0.2) / gap)
    with conn:
        conn.settimeout(5.0)
        try:
            for _ in range(n_each):
                conn.sendall(drive); drain(conn); time.sleep(gap)
            print("[fake-brain] phase 1 done: driving", flush=True)

            conn.sendall(estop); drain(conn); time.sleep(gap)
            print("[fake-brain] sent PKT_ESTOP", flush=True)

            conn.sendall(request); drain(conn); time.sleep(gap)
            print("[fake-brain] sent bare ESTOP_RESET (request only)", flush=True)

            # THE FIRST ASSERTION WINDOW: must stay at duty 0.
            for _ in range(n_each):
                conn.sendall(drive); drain(conn); time.sleep(gap)
            print("[fake-brain] phase 3 done: request must not have cleared", flush=True)

            conn.sendall(release); drain(conn); time.sleep(gap)
            print("[fake-brain] sent signed ESTOP_RESET (operator release)", flush=True)

            # THE SECOND ASSERTION WINDOW: must drive again.
            for _ in range(n_each):
                conn.sendall(drive); drain(conn); time.sleep(gap)
            print("[fake-brain] phase 5 done: release must have cleared", flush=True)
        except OSError as e:
            print(f"[fake-brain] link error {e}", flush=True)
            return 3
    print("[fake-brain] PASS kernel-estop-release script complete", flush=True)
    return 0


def selftest() -> int:
    """Prove the framing agrees with the kernel's before trusting a run.

    A wrong CRC produces a scenario that fails for the wrong reason: the kernel
    drops the frame at `parse_packet` and the log looks identical to a kernel
    that received nothing. These vectors are small enough to check by hand
    against `brain_protocol.rs`.
    """
    # An empty-payload SEMANTIC_LEVEL: the exact frame the fail-closed branch
    # is written for.
    # The e-stop frame the kernel-estop mode sends. One reason byte, so a
    # zero-length payload here would mean the mode was sending a frame this
    # check never looked at.
    e = build_packet(PKT_ESTOP, bytes([0]))
    assert e[:2] == MAGIC and e[2] == PKT_ESTOP, e
    assert e[3] == 1 and e[4] == 0, e
    assert e[5] == 0, e
    assert e[-1] == crc8(e[:-1]), e

    f = build_packet(PKT_SEMANTIC_LEVEL, b"")
    assert f[:2] == MAGIC, f
    assert f[2] == PKT_SEMANTIC_LEVEL
    assert f[3] == 0 and f[4] == 0, "length must be 0, little-endian"
    assert len(f) == 6, f"empty frame must be 6 bytes, got {len(f)}"
    assert f[5] == crc8(f[:5])
    # And a one-byte one, so the length field is exercised as non-zero.
    g = build_packet(PKT_SEMANTIC_LEVEL, bytes([200]))
    assert len(g) == 7 and g[3] == 1 and g[5] == 200
    assert g[6] == crc8(g[:6])
    # And the ActuatorCmd the --serve mode sends. Checked here for the same
    # reason as the frames above: a wrong CRC or a wrong field order is
    # dropped silently by the client, and the log then looks exactly like a
    # client that received nothing and did nothing.
    pay = actuator_payload(-2, 400)
    assert len(pay) == 7, f"minimum payload is 7 bytes, got {len(pay)}"
    assert pay[1] >= 2, "n_channels < 2 makes the client apply nothing"
    assert pay[2] == 0, "flags must be clear or the client emergency-stops"
    # i16 LITTLE-endian, and the sign must survive. -2 is 0xFFFE LE = FE FF.
    assert pay[3] == 0xFE and pay[4] == 0xFF, f"left channel wrong: {pay[3:5].hex()}"
    assert struct.unpack("<h", pay[3:5])[0] == -2
    assert struct.unpack("<h", pay[5:7])[0] == 400
    h = build_packet(PKT_ACTUATOR, pay)
    assert h[2] == PKT_ACTUATOR and h[3] == 7 and h[4] == 0
    assert h[-1] == crc8(h[:-1])

    # The bare ESTOP_RESET request: still exactly 1 byte, unchanged by the
    # 2026-09-25 decision — that is the whole point ("keep the wire format").
    req = mode_request_payload()
    assert req == bytes([0xFF]), req
    m = build_packet(PKT_MODE, req)
    assert m[2] == PKT_MODE and m[3] == 1 and m[4] == 0 and m[5] == 0xFF
    assert m[-1] == crc8(m[:-1])

    # The signed release: mode_id unchanged, 72 bytes longer. Signs with a
    # throwaway key (selftest only checks framing, not that any particular
    # kernel accepts it) and verifies the signature independently with the
    # SAME library that produced it, so a selftest that only checked its own
    # length would not catch a byte-order or concatenation-order mistake.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        import tempfile, os as _os
        seed = bytes(range(32))
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(seed)
            priv_path = tf.name
        try:
            rel = mode_release_payload(priv_path, nonce=0x1122334455667788)
        finally:
            _os.unlink(priv_path)
        assert len(rel) == 1 + 8 + 64, f"release payload must be 73 bytes, got {len(rel)}"
        assert rel[0] == 0xFF, "mode_id must be unchanged inside the longer payload"
        assert rel[1:9] == (0x1122334455667788).to_bytes(8, "big"), "nonce must be big-endian"
        pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        pub.verify(rel[9:], RELEASE_CONTEXT + rel[1:9])  # raises if wrong
        rm = build_packet(PKT_MODE, rel)
        assert rm[2] == PKT_MODE and rm[3] == 73 and rm[4] == 0
        assert rm[-1] == crc8(rm[:-1])
    except ImportError:
        print("[fake-brain] selftest: 'cryptography' not installed, skipping "
              "the release-proof framing check", file=sys.stderr)

    print("[fake-brain] selftest ok — framing matches brain_protocol.rs")
    return 0


# Each entry: (label, frame, what the kernel is expected to do).
def script_lies() -> list:
    """The 'brain lies' sequence: valid frames, refusable content."""
    return [
        ("semantic-level truncated (no payload byte)",
         build_packet(PKT_SEMANTIC_LEVEL, b""),
         "clamp to CONTAINED and record SAFETY_SEMANTIC_MALFORMED"),
        ("semantic-level out of range (200)",
         build_packet(PKT_SEMANTIC_LEVEL, bytes([200])),
         "clamp to CONTAINED"),
        ("degrade with no reason byte",
         build_packet(PKT_DEGRADE, b""),
         "ARM containment — it used to clear it"),
        ("a packet type this build does not act on",
         build_packet(PKT_UNKNOWN_PROBE, b"\x01\x02"),
         "record SAFETY_UNKNOWN_PKT instead of dropping in silence"),
    ]


def serve(host: str, port: int, duration: float, emergency: bool,
          link_key: bytes = None, enc_key: bytes = None) -> int:
    """Accept, DRAIN, and answer with ActuatorCmd frames.

    **Why draining is not optional.** An earlier stand-in accepted, read with a
    1 s timeout and then stopped reading while holding the connection open. The
    peer's receive window filled, TCP applied backpressure, and ring 3's
    `brain_client` logged "Send failed, disconnecting" — which reads exactly
    like a kernel transport bug and was reported as one. A test peer that does
    not consume is a false-bug generator, and the symptom shows up on the side
    that works. So: non-blocking, every open connection drained every pass.

    **Why it answers every connection.** Two dialers reach this port — the
    kernel's own brain link and ring 3's `brain_client` — and under QEMU's
    SLIRP the source port seen here is the translated one, so they cannot be
    told apart from this side. They are separated where it is unambiguous
    instead: `sys_motor_speed_typed` is reachable only by `ecall`, so a marker
    inside it fires for ring 3 and never for the kernel's own path, which
    publishes through a channel.

    **Why the order of commands is fixed.** Forward first: a positive speed
    goes through `SYS_MOTOR_SPEED_TYPED` (560), and `apply_motor_cmd` sends
    reverse down `SYS_MOTOR_DIRECTION_TYPED` (576), the typed form of the
    retired `SYS_MOTOR_ENABLE`. Reverse second, because it is the branch a real regression already
    hit once — `-50` sign-extended and the robot drove full speed FORWARD on a
    back-up command.

    Emergency is off by default, and when it IS enabled a plain drive command
    follows it — deliberately, and that command is the whole assertion. The
    e-stop is designed to STICK, so what follows it is not noise to be avoided:
    it is the only way to observe the latch from outside. The script's last
    entry repeats for the rest of the run, so the peer keeps asking for 60%
    against a latched machine. `duty=0` on every one of those is the proof;
    `duty=60` would mean the emergency did not hold.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    port = announce_port(host, srv)
    srv.settimeout(0.2)

    script = [("forward", actuator_payload(60, 60)),
              ("reverse", actuator_payload(-40, -40))]
    if emergency:
        script.append(("emergency", actuator_payload(0, 0, ACT_FLAG_EMERGENCY)))
        # Repeats to the end of the run — see the docstring: this is the
        # assertion, not an afterthought.
        script.append(("post-estop drive", actuator_payload(60, 60)))

    print(f"[fake-brain] serving on {host}:{port} for {duration:.0f}s; "
          f"script = {[n for n, _ in script]}", flush=True)

    conns = {}          # sock -> [addr, step, bytes_in, nonce, probed]
    enc = {}            # sock -> EncPeer (--encrypt only)
    sc_mod = load_secure_channel() if enc_key is not None else None
    retired = []        # EncPeers of closed connections, for the summary
    accepts = 0
    sent = 0
    refused_probe_sent = 0
    brain_rekeys = 0
    t0 = time.time()
    while time.time() - t0 < duration:
        try:
            c, a = srv.accept()
            c.setblocking(False)
            conns[c] = [a, 0, 0, 1, False]
            accepts += 1
            print(f"[fake-brain] accept #{accepts}", flush=True)
            if sc_mod is not None:
                # The brain speaks first (RFC-0019: crypto initiator = TCP
                # server). Small enough for one non-blocking send.
                ep = EncPeer(sc_mod, enc_key)
                enc[c] = ep
                c.sendall(ep.hello())
        except socket.timeout:
            pass
        except OSError as e:
            print(f"[fake-brain] accept error {e}", flush=True)

        for c in list(conns):
            a, step, got, nonce, probed = conns[c]
            try:
                d = c.recv(4096)
            except BlockingIOError:
                continue
            except OSError as e:
                print(f"[fake-brain] conn error {e}", flush=True)
                conns.pop(c, None)
                if c in enc:
                    retired.append(enc.pop(c))
                continue
            if not d:
                print(f"[fake-brain] a peer closed after {got} B", flush=True)
                conns.pop(c, None)
                if c in enc:
                    retired.append(enc.pop(c))
                continue
            got += len(d)
            if c in enc:
                ep = enc[c]
                was = ep.state
                try:
                    confirm = ep.feed(d)
                except Exception as e:  # noqa: BLE001 — any refusal ends it
                    print(f"[fake-brain] encrypted session refused: {e}", flush=True)
                    try:
                        c.sendall(sc_mod.REJECT_FRAME)
                    except OSError:
                        pass
                    c.close()
                    conns.pop(c, None)
                    retired.append(enc.pop(c))
                    continue
                if confirm is not None:
                    c.setblocking(True)
                    c.sendall(confirm)
                    c.setblocking(False)
                    print(f"[fake-brain] encrypted session established "
                          f"sid={ep.sc.session_id.hex()}", flush=True)
                if ep.state == "plain" and was == "await":
                    print("[fake-brain] a peer answered HELLO with non-handshake bytes "
                          "(the kernel's HMAC-only link) — draining it, never answering",
                          flush=True)
                if ep.state != "est" or confirm is not None:
                    # Nothing to answer yet: the handshake just finished, or
                    # this connection is not an encrypted session at all.
                    conns[c] = [a, step, got, nonce, probed]
                    continue
            # Answer once per inbound read, walking the script and then
            # repeating its last entry — the client applies a command per loop
            # iteration and holding it steady is what keeps the motors driven.
            name, payload = script[min(step, len(script) - 1)]
            frame = build_packet(PKT_ACTUATOR, payload)
            try:
                if c in enc:
                    ep = enc[c]
                    if not probed:
                        # V1.9's unwrapped probe, one layer in: a record the
                        # session seals correctly whose inner bytes carry no
                        # HMAC envelope. The AEAD layer accepts it (it is
                        # this session's record); the envelope check inside
                        # it must still refuse — `brain_client` prints
                        # "REFUSED unwrapped frame". Alone, as before.
                        wire = ep.seal(frame, wrap=False)
                        c.setblocking(True)
                        c.sendall(wire)
                        c.setblocking(False)
                        probed = True
                        refused_probe_sent += 1
                        print("[fake-brain] sent sealed UNWRAPPED probe (must be refused)",
                              flush=True)
                        conns[c] = [a, step, got, nonce, probed]
                        continue
                    # Once per session, on the third command: a brain-side
                    # REKEY, so the client's receive ratchet is exercised.
                    rekey = step == 2
                    wire = ep.seal(frame, rekey=rekey)
                    c.setblocking(True)
                    c.sendall(wire)
                    c.setblocking(False)
                    if rekey:
                        brain_rekeys += 1
                        print(f"[fake-brain] sent brain REKEY (tx generation "
                              f"{ep.sc.tx_generation})", flush=True)
                    sent += 1
                    if step < len(script):
                        print(f"[fake-brain] sent ActuatorCmd '{name}' (sealed)", flush=True)
                    conns[c] = [a, step + 1, got, nonce, probed]
                    continue
                if link_key is not None and not probed:
                    # One deliberately UNWRAPPED probe first — proves the
                    # peer actually refuses rather than merely never being
                    # sent anything to refuse. It goes ALONE, as this read's
                    # whole answer: the client refuses the entire TCP read
                    # on a bad envelope, so a wrapped frame sent right behind
                    # the probe arrived in the same read and was thrown away
                    # with it (gate 182e, 2026-09-26: the first 'forward' was
                    # never applied; the script then repeated 'reverse').
                    # `step` is not advanced — the next inbound read gets the
                    # first script entry, wrapped.
                    c.sendall(frame)
                    probed = True
                    refused_probe_sent += 1
                    print("[fake-brain] sent UNWRAPPED probe (must be refused)", flush=True)
                    conns[c] = [a, step, got, nonce, probed]
                    continue
                if link_key is not None:
                    c.sendall(wrap_envelope(link_key, nonce, frame))
                    nonce += 1
                else:
                    c.sendall(frame)
                sent += 1
                if step < len(script):
                    print(f"[fake-brain] sent ActuatorCmd '{name}'"
                          f"{' (wrapped)' if link_key is not None else ''}", flush=True)
            except OSError as e:
                print(f"[fake-brain] send error {e}", flush=True)
                conns.pop(c, None)
                continue
            conns[c] = [a, step + 1, got, nonce, probed]

    if link_key is not None or enc_key is not None:
        print(f"[fake-brain] unwrapped probes sent={refused_probe_sent}", flush=True)
    if enc_key is not None:
        peers = retired + list(enc.values())
        est = [p for p in peers if p.state in ("est", "dead") and p.sc.session_id]
        print(f"[fake-brain] encrypted sessions={len(est)} "
              f"sealed_sensor_packets_opened={sum(p.sensors for p in peers)} "
              f"client_rekeys={sum(p.client_rekeys for p in peers)} "
              f"brain_rekeys={brain_rekeys} "
              f"plain_peers={sum(1 for p in peers if p.state == 'plain')}", flush=True)

    if accepts == 0:
        # Never treat silence as success.
        print("[fake-brain] FAIL no-robot — nothing connected", flush=True)
        return 2
    print(f"[fake-brain] PASS accepts={accepts} actuator_frames_sent={sent}",
          flush=True)
    return 0


def reconnect(host: str, port: int, duration: float, enc_key: bytes = None) -> int:
    """Accept, read one burst, and reset the connection — for the whole run.

    The ring-3 client must give its socket back every time a connection ends.
    A client that closes the file descriptor without releasing the socket, or
    releases nothing, keeps working for exactly `MAX_SOCKETS_PER_TASK` dials and
    then can no longer create one. The only way to see that from outside is to
    make it dial more often than that, so this peer ends every connection it
    accepts: it waits for the first bytes (the client's SensorPacket), then
    closes with SO_LINGER 0 so the client's next send fails at once rather than
    after a FIN it may not notice.

    Both dialers get the same treatment — the kernel's own brain link reaches
    this port too, and SLIRP hides which is which. The count that matters is
    therefore taken from the kernel log, not from `accepts` here.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    port = announce_port(host, srv)
    srv.settimeout(0.2)
    sc_mod = load_secure_channel() if enc_key is not None else None
    print(f"[fake-brain] resetting every connection on {host}:{port} "
          f"for {duration:.0f}s", flush=True)

    accepts = 0
    t0 = time.time()
    while time.time() - t0 < duration:
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            print(f"[fake-brain] accept error {e}", flush=True)
            continue
        accepts += 1
        c.settimeout(1.5)
        if enc_key is not None:
            # The encrypted client sends nothing until it has a HELLO to
            # answer, so "its first bytes" are its handshake reply.
            try:
                c.sendall(EncPeer(sc_mod, enc_key).hello())
            except OSError:
                pass
        try:
            got = len(c.recv(4096))
        except OSError:
            got = 0
        # A client that already closed (or reset) the connection makes this
        # setsockopt fail with EINVAL on macOS: the reset is then moot, and
        # the peer must keep accepting. Unhandled, it killed the peer
        # mid-row (wave-15 integration: `ring-3 reconnects` red after 51
        # resets, every later dial refused).
        try:
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        c.close()
        print(f"[fake-brain] reset #{accepts} after {got} B", flush=True)

    if accepts == 0:
        print("[fake-brain] FAIL no-robot — nothing connected", flush=True)
        return 2
    print(f"[fake-brain] reconnect done accepts={accepts}", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--wait", type=float, default=120.0,
                    help="seconds to wait for the robot to dial in")
    ap.add_argument("--gap", type=float, default=0.5,
                    help="seconds between frames, so each lands in its own "
                         "behaviour tick (the loop runs at 10 Hz)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--serve", action="store_true",
                    help="answer SensorPackets with ActuatorCmd frames instead "
                         "of sending the lying script")
    ap.add_argument("--duration", type=float, default=30.0,
                    help="--serve only: seconds to keep serving")
    ap.add_argument("--kernel-drive", action="store_true",
                    help="the kernel-estop script with the PKT_ESTOP withheld: "
                         "drive throughout, so whatever stops the robot was "
                         "not this peer")
    ap.add_argument("--kernel-estop", action="store_true",
                    help="drive the KERNEL brain link, send PKT_ESTOP, then "
                         "keep driving -- the third phase is the assertion")
    ap.add_argument("--kernel-estop-release", action="store_true",
                    help="drive / latch / bare ESTOP_RESET (must NOT clear) / "
                         "operator-signed ESTOP_RESET (must clear) -- the "
                         "2026-09-25 owner decision, end to end")
    ap.add_argument("--operator-priv", type=str, default=None,
                    help="--kernel-estop-release only: path to the 32-byte "
                         "raw Ed25519 seed of the operator authority's "
                         "PRIVATE key (the matching public half is what the "
                         "kernel loads from /fat/OPERATOR.PUB)")
    ap.add_argument("--emergency", action="store_true",
                    help="--serve only: append an emergency-stop command. Off "
                         "by default because in the kernel it is designed to "
                         "STICK, so it poisons anything asserted after it")
    ap.add_argument("--wrap", type=str, default=None, metavar="LINK_KEY_PATH",
                    help="--serve only: wrap every sent ActuatorCmd in the "
                         "HMAC envelope (V1.9), keyed from the 32 raw bytes "
                         "at this path (the SAME /fat/LINK.KEY the robot "
                         "image carries) -- and send one deliberately "
                         "UNWRAPPED probe first, which the peer must refuse")
    ap.add_argument("--encrypt", type=str, default=None, metavar="LINK_KEY_PATH",
                    help="--serve/--reconnect: run the RFC-0019 encrypted link "
                         "(brain side, AzOSRobotBrain's secure_channel) keyed from "
                         "the 32 raw bytes at this path, the envelope inside "
                         "sealed records; one sealed UNWRAPPED probe first, "
                         "which the client must refuse, and one brain-side "
                         "REKEY per session")
    ap.add_argument("--reconnect", action="store_true",
                    help="reset every connection after its first bytes, for "
                         "--duration seconds, so the client has to dial again")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    enc_key = None
    if args.encrypt:
        with open(args.encrypt, "rb") as f:
            enc_key = f.read()
        if len(enc_key) != 32:
            print(f"error: --encrypt key at {args.encrypt} is {len(enc_key)} "
                  f"bytes, need exactly 32", file=sys.stderr)
            return 1
    if args.reconnect:
        return reconnect(args.host, args.port, args.duration, enc_key)
    if args.serve:
        link_key = None
        if args.wrap:
            with open(args.wrap, "rb") as f:
                link_key = f.read()
            if len(link_key) != 32:
                print(f"error: --wrap key at {args.wrap} is {len(link_key)} "
                      f"bytes, need exactly 32", file=sys.stderr)
                return 1
        return serve(args.host, args.port, args.duration, args.emergency, link_key,
                     enc_key)
    if args.kernel_estop:
        return kernel_estop(args.host, args.port, args.duration, args.gap)
    if args.kernel_drive:
        return kernel_estop(args.host, args.port, args.duration, args.gap,
                            send_estop=False)
    if args.kernel_estop_release:
        if not args.operator_priv:
            print("error: --kernel-estop-release requires --operator-priv PATH",
                  file=sys.stderr)
            return 1
        return kernel_estop_release(args.host, args.port, args.duration,
                                    args.gap, args.operator_priv)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(1)
    srv.settimeout(args.wait)
    print(f"[fake-brain] listening on {args.host}:{srv.getsockname()[1]}", flush=True)

    try:
        conn, addr = srv.accept()
    except socket.timeout:
        # Never treat silence as success: a robot that never dialled is a
        # failure of the scenario, not a pass with nothing to assert.
        print(f"[fake-brain] FAIL no-robot — nothing connected within "
              f"{args.wait:.0f}s", flush=True)
        return 2

    print(f"[fake-brain] robot connected from {addr[0]}", flush=True)
    with conn:
        conn.settimeout(5.0)
        for label, frame, expect in script_lies():
            conn.sendall(frame)
            print(f"[fake-brain] sent {label} "
                  f"({len(frame)} B) — expect: {expect}", flush=True)
            time.sleep(args.gap)
        # Hold the connection open briefly. Closing immediately would make the
        # kernel take its clean-disconnect path (`offline_activate`), which is a
        # DIFFERENT failure mode — scenario 1, not this one — and would muddle
        # which behaviour the log is showing.
        time.sleep(2.0)
    print("[fake-brain] PASS sent 4 frames", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
