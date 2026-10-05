#!/usr/bin/env python3.12
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""DEV01.D — UART relay daemon with timestamped persistent logs.

Captures the board's serial console (typically /dev/cu.usbserial-*),
prints lines to stdout with a [HH:MM:SS.mmm] prefix, and persists every
line to a rotating log file under build/dev_log/.

Why not just `screen` or `picocom`?
  - We want deterministic, machine-parseable timestamps in the log file
    (so e2e tests, CI, and grep work cleanly).
  - We want logs to survive when the terminal is closed.
  - We want non-blocking auto-detect of UART device + auto-reconnect
    after a board reset that bounces the device.

Usage:
  ./tools/dev_uart.py
  ./tools/dev_uart.py --device /dev/cu.usbserial-A50285BI
  ./tools/dev_uart.py --baud 115200
  ./tools/dev_uart.py --quiet            # log to file only, no stdout
  ./tools/dev_uart.py --no-log           # stdout only, no file

Output:
  build/dev_log/uart_YYYYMMDD_HHMMSS.log    one file per session
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import os
import pathlib
import sys
import time

# ── Constants ──────────────────────────────────────────────────────────────
DEFAULT_UART_GLOB = "/dev/cu.usbserial-*"
DEFAULT_BAUD = 115200
LOG_DIR = pathlib.Path(__file__).resolve().parent.parent / "build" / "dev_log"
RECONNECT_BACKOFF_S = 0.5
RECONNECT_MAX_BACKOFF_S = 5.0
READ_TIMEOUT_S = 0.5
LINE_BUFFER_MAX_BYTES = 8192


def _now_stamp() -> str:
    """High-resolution wall-clock timestamp for line prefix."""
    return _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _session_log_path() -> pathlib.Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fname = "uart_" + _dt.datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
    return LOG_DIR / fname


def _autodetect_device() -> str | None:
    matches = sorted(glob.glob(DEFAULT_UART_GLOB))
    return matches[0] if matches else None


def _open_serial(device: str, baud: int):
    """Open the serial port. Imports pyserial lazily so --help works without it."""
    try:
        import serial  # type: ignore
    except ImportError:
        print(
            "error: pyserial not installed. run: pip3 install pyserial",
            file=sys.stderr,
        )
        sys.exit(2)
    return serial.Serial(device, baud, timeout=READ_TIMEOUT_S)


def _emit(line: bytes, *, fp_log, to_stdout: bool) -> None:
    """Print a line to stdout (timestamped) and append it to the log file."""
    text = line.decode("utf-8", errors="replace").rstrip("\r\n")
    if not text:
        return
    stamp = _now_stamp()
    formatted = f"[{stamp}] {text}\n"
    if to_stdout:
        sys.stdout.write(formatted)
        sys.stdout.flush()
    if fp_log is not None:
        fp_log.write(formatted)
        fp_log.flush()


def _run_session(device: str, baud: int, *, to_stdout: bool, log_path: pathlib.Path | None):
    fp_log = log_path.open("a", buffering=1) if log_path else None
    if to_stdout:
        sys.stdout.write(
            f"[{_now_stamp()}] dev_uart: connected {device} @ {baud}\n"
        )
        sys.stdout.flush()
    if fp_log:
        fp_log.write(f"[{_now_stamp()}] === session start: {device} @ {baud} ===\n")

    backoff = RECONNECT_BACKOFF_S
    try:
        while True:
            try:
                ser = _open_serial(device, baud)
                backoff = RECONNECT_BACKOFF_S
                buf = bytearray()
                while True:
                    chunk = ser.read(1024)
                    if chunk:
                        buf.extend(chunk)
                        # Split on either CR or LF, emit complete lines only.
                        while True:
                            nl = -1
                            for i, b in enumerate(buf):
                                if b in (0x0A, 0x0D):
                                    nl = i
                                    break
                            if nl < 0:
                                break
                            line = bytes(buf[:nl])
                            del buf[: nl + 1]
                            _emit(line, fp_log=fp_log, to_stdout=to_stdout)
                        # Defensive: prevent unbounded buffer growth on a
                        # device that never emits a newline.
                        if len(buf) > LINE_BUFFER_MAX_BYTES:
                            _emit(bytes(buf), fp_log=fp_log, to_stdout=to_stdout)
                            buf.clear()
            except KeyboardInterrupt:
                raise
            except Exception as e:  # noqa: BLE001 — broad on purpose for reconnect
                msg = f"[{_now_stamp()}] dev_uart: disconnected ({e!r}), retry in {backoff:.1f}s\n"
                if to_stdout:
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                if fp_log:
                    fp_log.write(msg)
                time.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX_BACKOFF_S)
    except KeyboardInterrupt:
        if to_stdout:
            sys.stdout.write(f"\n[{_now_stamp()}] dev_uart: stopped by user\n")
        if fp_log:
            fp_log.write(f"[{_now_stamp()}] === session end ===\n")
            fp_log.close()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="UART relay with timestamped persistent logs."
    )
    p.add_argument(
        "--device",
        default=None,
        help=f"UART device (default: auto-detect first match for {DEFAULT_UART_GLOB})",
    )
    p.add_argument("--baud", type=int, default=DEFAULT_BAUD, help="baud rate")
    p.add_argument(
        "--quiet", action="store_true", help="suppress stdout, log to file only"
    )
    p.add_argument(
        "--no-log",
        action="store_true",
        help="don't write to build/dev_log/, stdout only",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    device = args.device or _autodetect_device()
    if not device:
        print(
            f"error: no UART device found matching {DEFAULT_UART_GLOB}",
            file=sys.stderr,
        )
        print("       plug in FTDI cable or pass --device", file=sys.stderr)
        return 1
    if not os.path.exists(device):
        print(f"error: device does not exist: {device}", file=sys.stderr)
        return 1
    log_path = None if args.no_log else _session_log_path()
    _run_session(
        device,
        args.baud,
        to_stdout=not args.quiet,
        log_path=log_path,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
