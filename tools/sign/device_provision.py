#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""device_provision.py — write or read the device record on a disk image.

The kernel binds a signed CONFIG.INI to ONE device and refuses an older one
(CONFIG.SIG format v2, `crates/core/topology/src/verify.rs`). Both facts live
in a reserved sector past the end of the FAT32 volume
(`kernel/src/reserved_tail.rs`: the last TAIL_SECTORS = 8 sectors of
the medium, or the AzOS records partition of a GPT medium,
`tools/image/azos_records.py`; `DEVICE` = 2 is the sector this tool touches),
which the USB mass-storage export cannot address:

    tools/sign/device_provision.py $AZOS_OUT/build/disk.img                     # random id, floor 0
    tools/sign/device_provision.py $AZOS_OUT/build/disk.img --device-id <32 hex>
    tools/sign/device_provision.py --show $AZOS_OUT/build/disk.img              # print the record

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

Provisioning writes floor 0 and an empty, valid bank of the repository index
marks (the "KPIX" records the kernel keeps in the last 2 x
PKG_INDEX_MARK_SECTORS tail sectors, `crates/core/pkg/src/index.rs`
`MarkTable::encode_bank`, generation 1, the other bank zero): a provisioned
device whose marks then read all zero has had them erased, and the kernel says
so instead of starting afresh. `--clear-index-marks` writes the same empty bank.

The kernel raises the floor each time it accepts
a CONFIG.INI whose signed counter is above it. Re-provisioning a device
(a new record, floor 0) is the operator's way back from a lost config key; it
needs the card, not the USB port.

Only an image FILE is handled (the size comes from the file), and only a GPT
one with a records partition or one whose FAT32 volume stops short of the
tail, as `seed_provision.py` requires.
"""
import argparse
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402,F401  (every tools/ module directory on sys.path)
from azos_records import SECTOR, records_start  # noqa: E402

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


def read_record(image: str):
    """The `(device_id, floor)` on `image`, or None. For gen_config_sig.py."""
    with open(image, "rb") as f:
        f.seek((records_start(image) + DEVICE_SECTOR) * SECTOR)
        return decode(f.read(SECTOR))


TAIL_SECTORS = 8
MARKS_MAGIC = b"KPIX"
MARKS_VERSION = 3
MARKS_DIGEST = 8
MARKS_TAG = 4


def marks_bank(sectors: int, gen: int = 1) -> bytes:
    """An empty bank of the repository index marks of `sectors` sectors at
    generation `gen`: what `MarkTable::encode_bank` writes for no entries."""
    digest = hashlib.sha256(struct.pack("<I", gen) + bytes([sectors, 0])).digest()[:MARKS_DIGEST]
    out = b""
    for i in range(sectors):
        sec = bytearray(SECTOR)
        sec[0:4] = MARKS_MAGIC
        sec[4] = MARKS_VERSION
        sec[5:9] = struct.pack("<I", gen)
        sec[9], sec[10], sec[11] = i, sectors, 0
        sec[SECTOR - MARKS_TAG - MARKS_DIGEST:SECTOR - MARKS_TAG] = digest
        sec[SECTOR - MARKS_TAG:] = hashlib.sha256(bytes(sec[:SECTOR - MARKS_TAG])).digest()[:MARKS_TAG]
        out += bytes(sec)
    return out


def marks_first(index_sectors: int, topo_sector: int):
    """The first tail sector of the marks, or None when the banks would reach
    the device record or the topology floor."""
    first = TAIL_SECTORS - 2 * index_sectors
    if not 1 <= index_sectors <= 2 or first <= max(DEVICE_SECTOR, topo_sector):
        return None
    return first


def write_empty_marks(f, start: int, first: int, index_sectors: int) -> None:
    """Bank 0 an empty valid bank, bank 1 zero."""
    f.seek((start + first) * SECTOR)
    f.write(marks_bank(index_sectors) + b"\0" * (SECTOR * index_sectors))


TOPO_MAGIC = b"KTPF"
TOPO_RECORD_BYTES = 4 + 1 + 8 + 4


def read_topo_floor(image: str, sector: int = 3):
    """The topology counter floor on `image` (`device_record.rs`
    `topo_floor_decode`), or None for no valid record."""
    with open(image, "rb") as f:
        f.seek((records_start(image) + sector) * SECTOR)
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
    ap.add_argument("--clear-index-marks", action="store_true",
                    help="forget the repository index marks and floors the kernel keeps (an empty valid bank "
                         "over the last 2 x PKG_INDEX_MARK_SECTORS tail sectors): the way back from an index "
                         "the source can no longer serve")
    ap.add_argument("--index-sectors", type=int, default=2, help="Kconfig PKG_INDEX_MARK_SECTORS (sectors per bank, 1 or 2)")
    a = ap.parse_args()

    # Never the link key, the entropy seed, the device record or the topology floor.
    first = marks_first(a.index_sectors, a.topo_sector)
    if first is None and not a.show:
        print(f"--index-sectors {a.index_sectors} would reach tail sector {max(DEVICE_SECTOR, a.topo_sector)} "
              f"(the device record or the topology floor): refused", file=sys.stderr)
        return 2
    if a.clear_index_marks:
        start = records_start(a.image, check_fat=True)
        with open(a.image, "r+b") as f:
            write_empty_marks(f, start, first, a.index_sectors)
        print(f"{a.image}: repository index marks cleared (tail sectors {first}..{TAIL_SECTORS - 1})")
        return 0
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
    start = records_start(a.image, check_fat=True)
    lba = start + DEVICE_SECTOR
    with open(a.image, "r+b") as f:
        f.seek(lba * SECTOR)
        f.write(record(dev, 0).ljust(SECTOR, b"\0"))
        write_empty_marks(f, start, first, a.index_sectors)
    print(f"{a.image}: device {dev.hex()} provisioned at sector {lba} (floor 0, empty index marks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
