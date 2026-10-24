# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The farm's board entries: tools/dev/farm/boards.ini (see boards.ini.example).

The file is per host (a serial device, a MAC, a relay) and is not tracked. No
file, or no section for the board, is "no board configured": the farm and its
gate row then SKIP instead of failing. A section that is there but wrong is a
configuration error.
"""

from __future__ import annotations

import configparser
import os
import sys
from dataclasses import dataclass
from typing import Optional

FARM_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../lib"))
import azos_tools  # noqa: E402
REPO = azos_tools.ROOT
from out_dir import out_root  # noqa: E402
DEFAULT_PATH = os.path.join(FARM_DIR, "boards.ini")
ENV_PATH = "AZOS_FARM_CONFIG"

RELAY_BACKENDS = ("dry-run", "exec")


class NoBoard(Exception):
    """No entry for the board on this host."""


class ConfigError(Exception):
    """An entry that cannot be used."""


@dataclass(frozen=True)
class Board:
    name: str
    isa: str
    serial: str
    baud: int
    relay: str
    relay_on: str
    relay_off: str
    power_off_s: float
    mac: str
    board_ip: str
    server_ip: str
    netmask: str
    interface: str
    tftp_root: str
    tftp_port: int
    kernel_name: str
    verify_tftp: bool
    boot_deadline_s: float
    ktest_deadline_s: float
    pstore_deadline_s: float
    log_dir: str


def config_path(env: Optional[dict] = None) -> str:
    env = os.environ if env is None else env
    return env.get(ENV_PATH) or DEFAULT_PATH


def load(name: str, path: Optional[str] = None) -> Board:
    path = path or config_path()
    parser = configparser.ConfigParser(interpolation=None)
    if not parser.read(path) or not parser.has_section(name):
        raise NoBoard(f"no [{name}] section in {path}")
    sec = parser[name]

    def need(key: str) -> str:
        value = sec.get(key, "").strip()
        if not value:
            raise ConfigError(f"{path}: [{name}] needs {key}")
        return value

    def number(key: str, default: str, cast):
        text = sec.get(key, default).strip()
        try:
            value = cast(text)
        except ValueError:
            raise ConfigError(f"{path}: [{name}] {key} = {text!r} is not a number") from None
        if value <= 0:
            raise ConfigError(f"{path}: [{name}] {key} must be positive")
        return value

    relay = need("relay")
    if relay not in RELAY_BACKENDS:
        raise ConfigError(f"{path}: [{name}] relay = {relay!r}, one of {', '.join(RELAY_BACKENDS)}")
    relay_on = sec.get("relay_on", "").strip()
    relay_off = sec.get("relay_off", "").strip()
    if relay == "exec" and not (relay_on and relay_off):
        raise ConfigError(f"{path}: [{name}] relay = exec needs relay_on and relay_off")
    return Board(
        name=name,
        isa=sec.get("isa", "riscv64").strip(),
        serial=need("serial"),
        baud=number("baud", "115200", int),
        relay=relay,
        relay_on=relay_on,
        relay_off=relay_off,
        power_off_s=number("power_off_s", "3", float),
        mac=need("mac").lower(),
        board_ip=need("board_ip"),
        server_ip=need("server_ip"),
        netmask=sec.get("netmask", "255.255.255.0").strip(),
        interface=sec.get("interface", "").strip(),
        tftp_root=os.path.expanduser(need("tftp_root")),
        tftp_port=number("tftp_port", "69", int),
        kernel_name=sec.get("kernel_name", "kernel.bin").strip(),
        verify_tftp=sec.getboolean("verify_tftp", fallback=True),
        boot_deadline_s=number("boot_deadline_s", "180", float),
        ktest_deadline_s=number("ktest_deadline_s", "600", float),
        pstore_deadline_s=number("pstore_deadline_s", "300", float),
        log_dir=os.path.expanduser(sec.get("log_dir", os.path.join(out_root(), "build", "farm")).strip()),
    )
