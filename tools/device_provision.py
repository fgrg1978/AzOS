#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""device_provision.py — write or read the device record on a disk image.

The kernel binds a signed CONFIG.INI to ONE device and refuses an older one
(CONFIG.SIG format v2, `crates/core/topology/src/verify.rs`). Both facts live
in a reserved sector past the end of the FAT32 volume
(`kernel/src/msc_gadget.rs`: the last MSC_RESERVED_TAIL_SECTORS = 8 sectors of
the medium; `RESERVED_SECTOR_DEVICE` = 2 is the sector this tool touches),
which the USB mass-storage export cannot address:

    tools/device_provision.py build/disk.img                     # random id, floor 0
    tools/device_provision.py build/disk.img --device-id <32 hex>
    tools/device_provision.py --show build/disk.img              # print the record

`--show` prints `device <32 hex> floor <n>` or `absent`. `--id-only` with
`--show` prints just the 32 hex digits (what `gen_config_sig.py --device-id`
takes). `--topo-floor` with `--show` prints the signed topology's counter
floor instead (wave 15: the "KTPF" record the kernel keeps in tail sector
`--topo-sector`, Kconfig TOPOLOGY_FLOOR_SECTOR, default 3): `topo-floor <n>`,
or `absent` (which the kernel reads as 0).

Record format (one sector; see `crates/core/topology/src/device_record.rs`):
    0   4   magic "KDEV"
    4   1   version 1
    5  16   device id
    21  8   config counter floor, u64 little-endian (0: no signed CONFIG.INI
            accepted yet on this device)
    29  4   first 4 bytes of SHA-256(bytes 0..29)

Provisioning writes floor 0. The kernel raises the floor each time it accepts
a CONFIG.INI whose signed counter is above it. Re-provisioning a device
(a new record, floor 0) is the operator's way back from a lost config key; it
needs the card, not the USB port.

Only an image FILE is handled (the size comes from the file), and only one
whose FAT32 volume stops short of the tail, as `seed_provision.py` requires.
"""
import argparse
import hashlib
import os
import struct
import sys

SECTOR = 512
TAIL_SECTORS = 8
DEVICE_SECTOR = 2
MAGIC = b"KDEV"
VERSION = 1
ID_BYTES = 16
RECORD_BYTES = 4 + 1 + ID_BYTES + 8 + 4


def record(device_id: bytes, floor: int) -> bytes:
    assert len(device_id) == ID_BYTES
    body = MAGIC + bytes([VERSION]) + device_id + struct.pack("<Q", floor)
    return body + hashlib.sha256(body).digest()[:4]


def decode(sector: bytes):
    if len(sector) < RECORD_BYTES or sector[:4] != MAGIC or sector[4] != VERSION:
        return None
    body = sector[:RECORD_BYTES - 4]
    if sector[RECORD_BYTES - 4:RECORD_BYTES] != hashlib.sha256(body).digest()[:4]:
        return None
    return body[5:5 + ID_BYTES], struct.unpack_from("<Q", body, 5 + ID_BYTES)[0]


def tail_offset(image: str):
    size = os.path.getsize(image)
    if size % SECTOR or size // SECTOR <= TAIL_SECTORS:
        raise SystemExit(f"{image}: size {size} is not a whole number of sectors past the tail")
    tail_start = size // SECTOR - TAIL_SECTORS
    return tail_start, (tail_start + DEVICE_SECTOR) * SECTOR


def read_record(image: str):
    """The `(device_id, floor)` on `image`, or None. For gen_config_sig.py."""
    _, off = tail_offset(image)
    with open(image, "rb") as f:
        f.seek(off)
        return decode(f.read(SECTOR))


TOPO_MAGIC = b"KTPF"
TOPO_RECORD_BYTES = 4 + 1 + 8 + 4


def read_topo_floor(image: str, sector: int = 3):
    """The topology counter floor on `image` (`device_record.rs`
    `topo_floor_decode`), or None for no valid record."""
    tail_start, _ = tail_offset(image)
    with open(image, "rb") as f:
        f.seek((tail_start + sector) * SECTOR)
        s = f.read(SECTOR)
    if len(s) < TOPO_RECORD_BYTES or s[:4] != TOPO_MAGIC or s[4] != 1:
        return None
    body = s[:TOPO_RECORD_BYTES - 4]
    if s[TOPO_RECORD_BYTES - 4:TOPO_RECORD_BYTES] != hashlib.sha256(body).digest()[:4]:
        return None
    return struct.unpack_from("<Q", body, 5)[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image")
    ap.add_argument("--show", action="store_true", help="read, do not write")
    ap.add_argument("--id-only", action="store_true", help="with --show: print only the id")
    ap.add_argument("--device-id", help="32 hex digits (default: random)")
    ap.add_argument("--topo-floor", action="store_true", help="with --show: the topology counter floor")
    ap.add_argument("--topo-sector", type=int, default=3, help="its tail sector (Kconfig TOPOLOGY_FLOOR_SECTOR)")
    a = ap.parse_args()

    tail_start, off = tail_offset(a.image)
    if a.show and a.topo_floor:
        f = read_topo_floor(a.image, a.topo_sector)
        print("absent" if f is None else f"topo-floor {f}")
        return 0
    if a.show:
        r = read_record(a.image)
        if r is None:
            print("absent")
        elif a.id_only:
            print(r[0].hex())
        else:
            print(f"device {r[0].hex()} floor {r[1]}")
        return 0

    if a.device_id is None:
        dev = os.urandom(ID_BYTES)
    else:
        try:
            dev = bytes.fromhex(a.device_id)
        except ValueError:
            dev = b""
        if len(dev) != ID_BYTES:
            print(f"--device-id must be {2 * ID_BYTES} hex digits", file=sys.stderr)
            return 2
    with open(a.image, "r+b") as f:
        f.seek(0)
        s0 = f.read(SECTOR)
        if s0[510:512] != b"\x55\xaa" or struct.unpack_from("<H", s0, 19)[0] != 0:
            print("sector 0 is not a FAT32 boot sector: cannot tell where the filesystem ends", file=sys.stderr)
            return 2
        tot32 = struct.unpack_from("<I", s0, 32)[0]
        if tot32 > tail_start:
            print(f"the FAT32 volume ({tot32} sectors) reaches the tail (starts at {tail_start}); "
                  "build the image with headroom first", file=sys.stderr)
            return 2
        f.seek(off)
        f.write(record(dev, 0).ljust(SECTOR, b"\0"))
    print(f"{a.image}: device {dev.hex()} provisioned at sector {tail_start + DEVICE_SECTOR} (floor 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
