#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""lx_device_table.py -- the Linux half of the hwbus match tables.

Reads the Linux leaf drivers listed in lx/DEVICE_SOURCES, finds their
MODULE_DEVICE_TABLE(pci|of|virtio, ...) arrays in the pinned tree
(third_party/linux) and prints one line per id:

    <class> <selector> module=<name>

where <selector> is the hwbus selector text (crates/drivers/hwbus/src/pattern.rs):
pci:VVVV:DDDD, pciclass:CCCCCC:MMMMMM, dt:<compatible>, virtio:<id>. The
output is read by crates/drivers/hwbus/build.rs, which refuses an id that a
native driver also declares.

lx/DEVICE_SOURCES: one `<class> <path under third_party/linux>` per line, `#`
comments. No file or an empty list prints nothing; so does a tree that is not
checked out (tools/third_party_fetch.sh linux fetches it): the table is then empty and
no Linux class server is ever wanted. A listed file that is missing from a
checked-out tree, or an id this reader cannot resolve, is an error: a dropped
id would let the native/Linux collision check pass on an incomplete table.

Usage: lx_device_table.py [REPO_ROOT]
       lx_device_table.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PCI_ANY = "*"


class TableError(Exception):
    pass


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


def defines(text: str, prefix: str) -> dict[str, int]:
    out = {}
    for m in re.finditer(rf"^\s*#\s*define\s+({prefix}\w+)\s+(0[xX][0-9a-fA-F]+|\d+)\b", text, re.M):
        out[m.group(1)] = int(m.group(2), 0)
    return out


class Headers:
    """The constants the id macros name, read from the pinned tree."""

    def __init__(self, tree: Path | None):
        self.pci_vendor: dict[str, int] = {}
        self.virtio_id: dict[str, int] = {}
        self.pci_class: dict[str, int] = {}
        if tree is None:
            return
        pci_ids = tree / "include/linux/pci_ids.h"
        if pci_ids.is_file():
            t = pci_ids.read_text(errors="replace")
            self.pci_vendor = defines(t, "PCI_VENDOR_ID_")
        pci = tree / "include/linux/pci.h"
        cls = tree / "include/linux/pci_ids.h"
        for f in (cls, pci):
            if f.is_file():
                self.pci_class.update(defines(f.read_text(errors="replace"), "PCI_CLASS_"))
        vids = tree / "include/uapi/linux/virtio_ids.h"
        if vids.is_file():
            self.virtio_id = defines(vids.read_text(errors="replace"), "VIRTIO_ID_")


def split_entries(body: str) -> list[str]:
    """The top-level `{ ... }` initialisers of an array body."""
    out, depth, start = [], 0, None
    for i, ch in enumerate(body):
        if ch == "{":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                out.append(body[start:i].strip())
                start = None
    return out


def split_args(s: str) -> list[str]:
    args, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


def num(tok: str, table: dict[str, int], what: str) -> int | str:
    tok = tok.strip()
    if tok in ("PCI_ANY_ID", "VIRTIO_DEV_ANY_ID", "~0", "(~0)"):
        return PCI_ANY
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", tok):
        return int(tok, 0)
    if tok in table:
        return table[tok]
    raise TableError(f"cannot resolve {what} {tok!r}")


def hexf(v: int | str) -> str:
    return PCI_ANY if v == PCI_ANY else f"{v:x}"


def pci_entry(e: str, h: Headers) -> str | None:
    if e.strip().rstrip(',').strip() in ('', '0'):
        return None  # the sentinel
    m = re.match(r"(PCI_DEVICE|PCI_VDEVICE|PCI_DEVICE_CLASS)\s*\((.*)\)\s*(,.*)?$", e, re.S)
    if m:
        macro, args = m.group(1), split_args(m.group(2))
        if macro == "PCI_DEVICE" and len(args) == 2:
            v, d = num(args[0], h.pci_vendor, "vendor"), num(args[1], {}, "device")
            return f"pci:{hexf(v)}:{hexf(d)}"
        if macro == "PCI_VDEVICE" and len(args) == 2:
            v = num("PCI_VENDOR_ID_" + args[0].strip(), h.pci_vendor, "vendor")
            return f"pci:{hexf(v)}:{hexf(num(args[1], {}, 'device'))}"
        if macro == "PCI_DEVICE_CLASS" and len(args) == 2:
            c = num(args[0], h.pci_class, "class")
            mk = num(args[1], {}, "class mask")
            mk = 0xFFFFFF if mk == PCI_ANY else mk
            return f"pciclass:{c:06x}:{mk:06x}"
        raise TableError(f"unhandled {macro}({m.group(2)})")
    # Raw form: { vendor, device, subvendor, subdevice, class, class_mask, ... }.
    args = split_args(e)
    if len(args) >= 2 and not e.lstrip().startswith("."):
        return f"pci:{hexf(num(args[0], h.pci_vendor, 'vendor'))}:{hexf(num(args[1], {}, 'device'))}"
    raise TableError(f"unhandled pci_device_id initialiser {e!r}")


def of_entry(e: str, _h: Headers) -> str | None:
    m = re.search(r'\.compatible\s*=\s*"([^"]+)"', e)
    if m:
        return f"dt:{m.group(1)}"
    if e.strip() == "":
        return None  # the sentinel
    raise TableError(f"of_device_id without .compatible: {e!r}")


def virtio_entry(e: str, h: Headers) -> str | None:
    args = split_args(e)
    if not args or args[0] == "0":
        return None
    v = num(args[0], h.virtio_id, "virtio id")
    if v == PCI_ANY:
        raise TableError("virtio_device_id with a wildcard device id")
    return f"virtio:{v}"


KINDS = {
    "pci": ("pci_device_id", pci_entry),
    "of": ("of_device_id", of_entry),
    "virtio": ("virtio_device_id", virtio_entry),
}


def ids_of_source(src: str, h: Headers) -> list[str]:
    src = strip_comments(src)
    out = []
    for m in re.finditer(r"MODULE_DEVICE_TABLE\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", src):
        kind, name = m.group(1), m.group(2)
        if kind not in KINDS:
            continue  # usb, i2c, platform ...: not a hwbus bus kind yet
        ctype, fn = KINDS[kind]
        arr = re.search(rf"(?:struct\s+{ctype}|{ctype})\s+{re.escape(name)}\s*\[\s*\]\s*=\s*\{{(.*?)\n?\}}\s*;", src, re.S)
        if not arr:
            raise TableError(f"MODULE_DEVICE_TABLE({kind}, {name}) without its array")
        for e in split_entries(arr.group(1)):
            sel = fn(e, h)
            if sel is not None:
                out.append(sel)
    return out


def read_sources(root: Path) -> list[tuple[str, str]]:
    lst = root / "lx/DEVICE_SOURCES"
    if not lst.is_file():
        return []
    rows = []
    for n, line in enumerate(lst.read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            raise TableError(f"lx/DEVICE_SOURCES:{n}: want `<class> <path>`")
        rows.append((parts[0], parts[1]))
    return rows


def generate(root: Path) -> list[str]:
    rows = read_sources(root)
    tree = root / "third_party/linux"
    if not rows or not (tree / "Makefile").is_file():
        return []
    h = Headers(tree)
    lines = []
    for cls, rel in rows:
        f = tree / rel
        if not f.is_file():
            # A tree fetched before the file joined the sparse set: the blob is
            # already in its pack, so a re-run checks it out without a download.
            raise TableError(f"lx/DEVICE_SOURCES names {rel}, not in third_party/linux "
                             "(re-run tools/third_party_fetch.sh linux to apply the sparse set)")
        module = f.stem
        for sel in ids_of_source(f.read_text(errors="replace"), h):
            lines.append(f"{cls} {sel} module={module}")
    return lines


def self_test() -> None:
    h = Headers(None)
    h.pci_vendor["PCI_VENDOR_ID_INTEL"] = 0x8086
    h.virtio_id["VIRTIO_ID_NET"] = 1
    h.pci_class["PCI_CLASS_SERIAL_USB_XHCI"] = 0x0c0330
    src = r'''
    /* a comment with MODULE_DEVICE_TABLE(pci, bogus) */
    static const struct pci_device_id ids[] = {
        { PCI_DEVICE(0x1b36, 0x000d) },
        { PCI_VDEVICE(INTEL, 0x1234) },
        { PCI_DEVICE_CLASS(PCI_CLASS_SERIAL_USB_XHCI, ~0) },
        { PCI_VENDOR_ID_INTEL, 0x5678, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
        { 0, }
    };
    MODULE_DEVICE_TABLE(pci, ids);
    static const struct of_device_id of_ids[] = {
        { .compatible = "vendor,chip-a", .data = &x },
        { .compatible = "vendor,chip-b" },
        { /* sentinel */ }
    };
    MODULE_DEVICE_TABLE(of, of_ids);
    static const struct virtio_device_id vids[] = { { VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID }, { 0 }, };
    MODULE_DEVICE_TABLE(virtio, vids);
    MODULE_DEVICE_TABLE(usb, usbids);
    '''
    got = ids_of_source(src, h)
    assert got[0] == "pci:1b36:d", got
    assert got[1] == "pci:8086:1234", got
    assert got[2] == "pciclass:0c0330:ffffff", got
    assert got[3] == "pci:8086:5678", got
    assert got[4:] == ["dt:vendor,chip-a", "dt:vendor,chip-b", "virtio:1"], got
    # An id that cannot be resolved is an error, never a dropped line.
    try:
        ids_of_source("static const struct pci_device_id t[] = { { PCI_VDEVICE(NOPE, 1) }, };"
                      "MODULE_DEVICE_TABLE(pci, t);", h)
    except TableError:
        pass
    else:
        raise AssertionError("an unresolvable vendor was dropped")
    try:
        ids_of_source("MODULE_DEVICE_TABLE(of, missing);", h)
    except TableError:
        pass
    else:
        raise AssertionError("a table without its array was accepted")
    print("lx_device_table: self-test ok")


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        self_test()
        return 0
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    try:
        for line in generate(root):
            print(line)
    except TableError as e:
        print(f"lx_device_table: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
