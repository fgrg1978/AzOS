#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The board farm: one board, a relay in its supply, its console on a serial line.

  farm.py check                    is a board configured? (exit 3 when not)
  farm.py net-config [--out FILE]  the dnsmasq configuration serving the board
  farm.py power on|off|cycle       drive the relay
  farm.py run ktest  --kernel K [--elf E]
                                   stage K for the board's TFTP boot, power-cycle
                                   it, read the ktest TAP off its console under a
                                   deadline, power it off; exit by the verdict
  farm.py run pstore --kernel K    the pstore boot counter (farm_pstore.py)

`make vf2-ktest` / `make vf2-pstore` build the image first, then run this.
Setup: tools/dev/farm/README.md. The board's entry: tools/dev/farm/boards.ini.

Exit codes: 0 pass, 1 red verdict, 2 the farm itself (a bad entry, a relay or
TFTP that does not answer, a board that never reached the kernel's TAP),
3 no board configured on this host (a gate row SKIPs).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Callable, Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../lib"))
import azos_tools  # noqa: E402,F401

import farm_config
import farm_elf
import farm_net
import farm_pstore
import farm_relay
import farm_serial
import farm_tap

EXIT_OK, EXIT_RED, EXIT_FARM, EXIT_NO_BOARD = 0, 1, 2, 3
SUMMARY_GRACE_S = 2.0       # the runner may print a `Bail out!` right after its summary
DEFAULT_BOARD = "vf2"


def say(msg: str) -> None:
    print(f"[farm] {msg}", flush=True)


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def run_scenario(board, scenario: str, kernel: str, relay: farm_relay.Relay, expected_plan: Optional[int],
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> int:
    """Stage, capture, judge. `relay` is cycled once the console is open."""
    try:
        dst = farm_net.stage(board, kernel)
        say(f"{board.name} {scenario}: staged {kernel} as {dst} ({os.path.getsize(dst)} bytes)")
        if board.verify_tftp:
            farm_net.verify(board)
            say(f"tftp {board.server_ip}:{board.tftp_port} serves it")
    except (OSError, farm_config.ConfigError) as e:
        say(f"{board.name} {scenario}: {e}")
        return EXIT_FARM

    os.makedirs(board.log_dir, exist_ok=True)
    log_path = os.path.join(board.log_dir, f"{board.name}-{scenario}-{stamp()}.log")
    start = clock()
    if scenario == "ktest":
        tap = farm_tap.Tap()
        deadline = farm_serial.Deadline(start + board.boot_deadline_s)

        def on_line(line: str) -> bool:
            was_planned = tap.plan is not None
            was_summed = tap.summary is not None
            done = tap.feed(line)
            if tap.plan is not None and not was_planned:       # the kernel is up: the run's own budget
                deadline.at = clock() + board.ktest_deadline_s
            if tap.summary is not None and not was_summed:
                deadline.at = min(deadline.at, clock() + SUMMARY_GRACE_S)
            return done
    else:
        pstore = farm_pstore.Pstore()
        deadline = farm_serial.Deadline(start + board.pstore_deadline_s)

        def on_line(line: str) -> bool:
            return pstore.feed(line)

    def cycle() -> None:
        say(f"power cycle ({board.relay}, {board.power_off_s:g} s off)")
        relay.cycle(board.power_off_s, sleep)

    try:
        with open(log_path, "wb") as log:
            how = farm_serial.capture(board.serial, board.baud, deadline, on_line, log,
                                      clock=clock, opened=cycle)
    except (farm_serial.SerialError, farm_relay.RelayError) as e:
        say(f"{board.name} {scenario}: {e}")
        _power_off(relay)
        return EXIT_FARM
    _power_off(relay)

    if scenario == "ktest":
        rc = _judge_ktest(board, tap, how, expected_plan, log_path)
    else:
        rc = _judge_pstore(board, pstore, how, log_path)
    return rc


def _power_off(relay: farm_relay.Relay) -> None:
    try:
        relay.off()
    except farm_relay.RelayError as e:
        say(f"warning: could not power the board off: {e}")


def _judge_ktest(board, tap: farm_tap.Tap, how: str, expected_plan: Optional[int], log_path: str) -> int:
    for lines in tap.facts.values():
        say(f"board: {lines[0]}")
    if tap.plan is None:
        say(f"FARM {board.name} ktest: the board printed no TAP plan within {board.boot_deadline_s:g} s "
            f"(did U-Boot fetch the kernel? log: {log_path})")
        return EXIT_FARM
    v = tap.verdict(expected_plan)
    if how == "deadline" and tap.summary is None and v.ok is False:
        v = farm_tap.Verdict(False, f"{v.why}; no summary within {board.ktest_deadline_s:g} s")
    if v.ok:
        say(f"PASS {board.name} ktest: {tap.plan} tests (log: {log_path})")
        return EXIT_OK
    say(f"FAIL {board.name} ktest: {v.why} (log: {log_path})")
    return EXIT_RED


def _judge_pstore(board, pstore: farm_pstore.Pstore, how: str, log_path: str) -> int:
    v = pstore.verdict()
    say(f"boot counter: {pstore.boots()}")
    if v.ok:
        say(f"PASS {board.name} pstore: {pstore.boots()} boots, the record survived the warm reboot (log: {log_path})")
        return EXIT_OK
    suffix = f"; deadline {board.pstore_deadline_s:g} s passed" if how == "deadline" else ""
    say(f"FAIL {board.name} pstore: {v.why}{suffix} (log: {log_path})")
    return EXIT_RED


def load_board(args) -> farm_config.Board:
    return farm_config.load(args.board, args.config)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--board", default=DEFAULT_BOARD)
    ap.add_argument("--config", default=None, help=f"default: ${farm_config.ENV_PATH} or tools/dev/farm/boards.ini")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    nc = sub.add_parser("net-config")
    nc.add_argument("--out", default=None)
    pw = sub.add_parser("power")
    pw.add_argument("state", choices=("on", "off", "cycle"))
    rn = sub.add_parser("run")
    rn.add_argument("scenario", choices=("ktest", "pstore"))
    rn.add_argument("--kernel", required=True, help="flat kernel binary to boot")
    rn.add_argument("--elf", default=None, help="the kernel ELF: its ktest registry is the plan to expect")
    args = ap.parse_args(argv)

    try:
        board = load_board(args)
    except farm_config.NoBoard as e:
        say(f"no board configured: {e}")
        return EXIT_NO_BOARD
    except farm_config.ConfigError as e:
        say(str(e))
        return EXIT_FARM

    if args.cmd == "check":
        say(f"{board.name}: console {board.serial} @ {board.baud}, relay {board.relay}, tftp {board.server_ip}")
        return EXIT_OK
    if args.cmd == "net-config":
        try:
            text = farm_net.dnsmasq_conf(board)
        except farm_config.ConfigError as e:
            say(str(e))
            return EXIT_FARM
        if args.out:
            with open(args.out, "w") as f:
                f.write(text)
            say(f"wrote {args.out}")
        else:
            sys.stdout.write(text)
        return EXIT_OK
    relay = farm_relay.make_relay(board)
    if args.cmd == "power":
        try:
            if args.state == "cycle":
                relay.cycle(board.power_off_s)
            else:
                getattr(relay, args.state)()
        except farm_relay.RelayError as e:
            say(str(e))
            return EXIT_FARM
        return EXIT_OK
    expected = None
    if args.scenario == "ktest" and args.elf:
        try:
            expected = farm_elf.registry_count(args.elf)
        except (OSError, farm_elf.ElfError) as e:
            say(str(e))
            return EXIT_FARM
        say(f"{args.elf} holds {expected} tests")
    return run_scenario(board, args.scenario, args.kernel, relay, expected)


if __name__ == "__main__":
    sys.exit(main())
