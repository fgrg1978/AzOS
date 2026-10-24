#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""mkazvol: build and read back azvol volume images (the AzOS native volume).

  mkazvol.py create IMAGE --size 16M [--root DIR] [--label NAME]
                          [--uuid HEX32] [--time-ns N] [--verity]
  mkazvol.py verify IMAGE [--verity-root HEX64]
                                 check every checksum, list the tree
  mkazvol.py sha256              sha256 of stdin (helper for the host tests)

`create` writes a complete volume at generation 1 holding the files under
--root (like `mke2fs -d`): each file is one contiguous extent, directories are
packed record blocks, and the output is deterministic (names sorted, no
clocks: the time is --time-ns, default $SOURCE_DATE_EPOCH or 0, and the
uuid derives from the label and the size unless given).

--verity appends a SHA-256 hash tree after the volume (header, then the
levels, see crates/fs/fs/src/azvol/verity.rs) and prints `verity_root HEX` on
stdout: the value of the topology row's `verity_root`. --size stays the size
of the volume; the image file is longer by the tree, and the partition it goes
to must hold both. `verify --verity-root` recomputes the tree from the volume
blocks and checks the stored one and the root against it.

The format is described in crates/fs/fs/src/azvol/mod.rs. This file is the
second, independent implementation of it: the host suite
(tests/host/fs-tests/src/azvol_format.rs) mounts what `create` writes with
the Rust engine and has `verify` read what the Rust engine wrote, so a layout
drift in either shows up as a test failure, not as an unreadable disk.
"""

import argparse
import hashlib
import os
import stat
import struct
import sys

BLOCK = 4096
MAGIC = b"AZVOLUME"
VERSION = 1
SB_SLOTS = (0, 64)
RESERVED = 128
BITMAP_PAYLOAD = BLOCK - 4
BITS_PER_BITMAP_BLOCK = BITMAP_PAYLOAD * 8
CSUMS_PER_BLOCK = BLOCK // 4
INODE_SIZE = 256
INODES_PER_BLOCK = BLOCK // INODE_SIZE
INLINE_CAP = 6
ENTRY = 32
NODE_HDR = 32
NODE_CAP = (BLOCK - NODE_HDR) // ENTRY
NODE_MAGIC = 0x4E585A41
MIN_DATA_BLOCKS = 16
MAX_NAME = 255
ROOT_INO = 1
KIND_FREE, KIND_FILE, KIND_DIR, KIND_TABLE = 0, 1, 2, 3
VERITY_MAGIC = b"AZVERITY"
VERITY_VERSION = 1
VERITY_ALG_SHA256 = 1
HASH_LEN = 32
FANOUT = BLOCK // HASH_LEN
VERITY_MAX_LEVELS = 6


class VolError(Exception):
    pass


# ---- crc32c (Castagnoli, reflected) ---------------------------------------

def _make_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_TABLE = _make_table()


def crc32c(data, crc=0):
    c = crc ^ 0xFFFFFFFF
    for b in data:
        c = _TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


assert crc32c(b"123456789") == 0xE3069283, "crc32c self-check"


# ---- geometry ---------------------------------------------------------------

def div_ceil(a, b):
    return -(-a // b)


class Geo:
    def __init__(self, n):
        self.block_count = n
        self.bitmap_start = RESERVED
        self.bitmap_blocks = div_ceil(n, BITS_PER_BITMAP_BLOCK)
        self.csum_start = self.bitmap_start + self.bitmap_blocks
        self.csum_blocks = div_ceil(n, CSUMS_PER_BLOCK)
        self.data_start = self.csum_start + self.csum_blocks
        if n < self.data_start + MIN_DATA_BLOCKS:
            raise VolError("volume too small: %d blocks" % n)


# ---- on-disk records ---------------------------------------------------------

def inode_record(ino, kind, size, gen, ctime, mtime, link, igen, mode, extents):
    """256-byte inode record; `extents` (at most INLINE_CAP) stay inline."""
    assert len(extents) <= INLINE_CAP
    b = bytearray(INODE_SIZE)
    struct.pack_into("<QQQQQQ", b, 0, ino, size, gen, ctime, mtime, link)
    struct.pack_into("<IBBHHH", b, 48, igen, kind, 0, len(extents), mode, 0)
    for i, e in enumerate(extents):
        b[64 + i * ENTRY:64 + (i + 1) * ENTRY] = extent_entry(*e)
    return bytes(b)


def extent_entry(file_blk, disk_blk, nblocks, gen, flags=0):
    return struct.pack("<QQIIQ", file_blk, disk_blk, nblocks, flags, gen)


def sb_crc(b):
    """crc32c of the block with its own crc field read as zero."""
    return crc32c(bytes(b[:16]) + b"\0\0\0\0" + bytes(b[20:BLOCK]))


def superblock(geo, generation, uuid, label, free_head, inode_slots, used, created, itable_rec):
    b = bytearray(BLOCK)
    b[0:8] = MAGIC
    struct.pack_into("<III", b, 8, VERSION, 12, 0)          # version, log2, crc
    struct.pack_into("<I", b, 20, 0)                         # incompat
    struct.pack_into("<QQ", b, 24, generation, geo.block_count)
    b[40:56] = uuid
    b[56:88] = label.ljust(32, b"\0")[:32]
    struct.pack_into("<QQQ", b, 88, free_head, inode_slots, used)
    struct.pack_into("<QQQQQ", b, 112, geo.bitmap_start, geo.bitmap_blocks, geo.csum_start,
                     geo.csum_blocks, geo.data_start)
    struct.pack_into("<QQ", b, 152, ROOT_INO, created)
    b[256:512] = itable_rec
    struct.pack_into("<I", b, 16, sb_crc(b))
    return bytes(b)


def dir_blocks(entries):
    """Pack (name, ino, kind) records into directory blocks."""
    if not entries:
        return []
    blocks, cur, off = [], bytearray(BLOCK), 0
    for name, ino, kind in entries:
        need = (16 + len(name) + 7) & ~7
        if off + need > BLOCK:
            blocks.append(bytes(cur))
            cur, off = bytearray(BLOCK), 0
        struct.pack_into("<QHBB", cur, off, ino, need, len(name), kind)
        cur[off + 16:off + 16 + len(name)] = name
        off += need
    blocks.append(bytes(cur))
    return blocks


def check_name(name):
    if not 1 <= len(name) <= MAX_NAME or b"\0" in name or b"/" in name or name in (b".", b".."):
        raise VolError("unusable file name: %r" % name)


# ---- create ---------------------------------------------------------------------

class Node:
    def __init__(self, ino, kind, mode, parent):
        self.ino, self.kind, self.mode, self.parent = ino, kind, mode, parent
        self.children = []      # (name, Node) for directories
        self.path = None        # host path for files
        self.size = 0


def scan(root):
    """Number the tree depth-first in sorted name order."""
    nodes = []

    def visit(path, ino_parent, mode):
        n = Node(len(nodes) + 1, KIND_DIR, mode, ino_parent)
        nodes.append(n)
        for name in sorted(os.listdir(path), key=os.fsencode):
            bname = os.fsencode(name)
            check_name(bname)
            full = os.path.join(path, name)
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                child = visit(full, n.ino, stat.S_IMODE(st.st_mode))
            elif stat.S_ISREG(st.st_mode):
                child = Node(len(nodes) + 1, KIND_FILE, stat.S_IMODE(st.st_mode), 0)
                child.path, child.size = full, st.st_size
                nodes.append(child)
            else:
                raise VolError("%s: only regular files and directories can go in an image" % full)
            n.children.append((bname, child))
        return n

    mode = stat.S_IMODE(os.stat(root).st_mode) if root else 0o755
    if root:
        visit(root, ROOT_INO, mode)
    else:
        nodes.append(Node(ROOT_INO, KIND_DIR, 0o755, ROOT_INO))
    nodes[0].parent = ROOT_INO
    return nodes


def create(image, size, root, label, uuid, time_ns, verity=False):
    if size % BLOCK or size <= 0:
        raise VolError("size must be a multiple of %d" % BLOCK)
    geo = Geo(size // BLOCK)
    nodes = scan(root)
    slots = len(nodes) + 1
    itable_blocks = div_ceil(slots * INODE_SIZE, BLOCK)
    out = open(image, "wb")
    out.truncate(size)
    csum = {}
    bitmap = bytearray(geo.bitmap_blocks * BITMAP_PAYLOAD)

    def setbit(b):
        bitmap[b // 8] |= 1 << (b % 8)

    for b in range(geo.data_start):
        setbit(b)
    nxt = [geo.data_start]

    def alloc(n):
        if n == 0:
            return 0
        s = nxt[0]
        if s + n > geo.block_count:
            raise VolError("image too small for the tree")
        nxt[0] += n
        for b in range(s, s + n):
            setbit(b)
        return s

    def put(first, data):
        assert len(data) % BLOCK == 0
        out.seek(first * BLOCK)
        out.write(data)
        for i in range(len(data) // BLOCK):
            csum[first + i] = crc32c(data[i * BLOCK:(i + 1) * BLOCK])

    it_start = alloc(itable_blocks)
    records = {}
    for n in nodes:
        if n.kind == KIND_DIR:
            ents = [(name, c.ino, c.kind) for name, c in n.children]
            blocks = dir_blocks(ents)
            start = alloc(len(blocks))
            if blocks:
                put(start, b"".join(blocks))
            nb, fsize = len(blocks), len(blocks) * BLOCK
        else:
            nb = div_ceil(n.size, BLOCK)
            start = alloc(nb)
            if nb:
                with open(n.path, "rb") as f:
                    data = f.read()
                if len(data) != n.size:
                    raise VolError("%s changed while it was read" % n.path)
                put(start, data.ljust(nb * BLOCK, b"\0"))
            fsize = n.size
        exts = [(0, start, nb, 1)] if nb else []
        records[n.ino] = inode_record(n.ino, n.kind, fsize, 1, time_ns, time_ns,
                                      n.parent if n.kind == KIND_DIR else 0, 1, n.mode, exts)
    table = bytearray(itable_blocks * BLOCK)
    for ino, rec in records.items():
        table[ino * INODE_SIZE:(ino + 1) * INODE_SIZE] = rec
    put(it_start, bytes(table))
    itable_rec = inode_record(0, KIND_TABLE, slots * INODE_SIZE, 1, 0, 0, 0, 0, 0,
                              [(0, it_start, itable_blocks, 1)])
    # checksum table and bitmap
    ct = bytearray(geo.csum_blocks * BLOCK)
    for b, c in csum.items():
        struct.pack_into("<I", ct, b * 4, c)
    out.seek(geo.csum_start * BLOCK)
    out.write(ct)
    for i in range(geo.bitmap_blocks):
        payload = bytes(bitmap[i * BITMAP_PAYLOAD:(i + 1) * BITMAP_PAYLOAD])
        out.seek((geo.bitmap_start + i) * BLOCK)
        out.write(payload + struct.pack("<I", crc32c(payload)))
    used = sum(bin(x).count("1") for x in bitmap)
    sb = superblock(geo, 1, uuid, label, 0, slots, used, time_ns, itable_rec)
    for s in SB_SLOTS:
        out.seek(s * BLOCK)
        out.write(sb)
    out.close()
    return verity_append(image, geo.block_count) if verity else None


# ---- verity ------------------------------------------------------------------------

def verity_tree(volume_hashes):
    """The hash tree of an n-block volume, given the SHA-256 of each block.

    Returns (levels, header): `levels` is the list of levels, bottom first,
    each a list of 4096-byte hash blocks, laid out from block n+1 on; `header`
    is the block at n. The layout is `Shape::new` in verity.rs."""
    n = len(volume_hashes)
    if not 0 < n <= 1 << 40:
        raise VolError("no hash tree for a volume of %d blocks" % n)
    levels, below = [], volume_hashes
    while True:
        blocks = []
        for i in range(0, len(below), FANOUT):
            blocks.append(b"".join(below[i:i + FANOUT]).ljust(BLOCK, b"\0"))
        levels.append(blocks)
        if len(levels) > VERITY_MAX_LEVELS:
            raise VolError("hash tree deeper than %d levels" % VERITY_MAX_LEVELS)
        if len(blocks) == 1:
            break
        below = [hashlib.sha256(b).digest() for b in blocks]
    top = hashlib.sha256(levels[-1][0]).digest()
    header = bytearray(BLOCK)
    header[0:8] = VERITY_MAGIC
    struct.pack_into("<IIQII", header, 8, VERITY_VERSION, VERITY_ALG_SHA256, n, len(levels), 0)
    header[32:32 + HASH_LEN] = top
    return levels, bytes(header)


def volume_block_hashes(f, n):
    f.seek(0)
    out = []
    for blk in range(n):
        b = f.read(BLOCK)
        if len(b) != BLOCK:
            raise VolError("block %d is beyond the image" % blk)
        out.append(hashlib.sha256(b).digest())
    return out


def verity_append(image, n):
    """Write the header and the tree after the first n blocks of `image`;
    returns the verity root (the SHA-256 of the header), as hex."""
    with open(image, "r+b") as f:
        levels, header = verity_tree(volume_block_hashes(f, n))
        f.seek(n * BLOCK)
        f.write(header)
        for blocks in levels:
            f.write(b"".join(blocks))
        f.truncate()
    return hashlib.sha256(header).hexdigest()


def verity_check(image, n, root_hex):
    """The tree stored after the first n blocks is the one the volume yields,
    and its root is `root_hex`."""
    with open(image, "rb") as f:
        levels, header = verity_tree(volume_block_hashes(f, n))
        want = header + b"".join(b"".join(blocks) for blocks in levels)
        f.seek(n * BLOCK)
        have = f.read(len(want))
    if have != want:
        raise VolError("the stored hash tree does not match the volume")
    root = hashlib.sha256(header).hexdigest()
    if root != root_hex.lower():
        raise VolError("verity root is %s, not %s" % (root, root_hex.lower()))
    print("verity ok, root %s" % root)


# ---- verify ------------------------------------------------------------------------

class Image:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(0, os.SEEK_END)
        self.blocks = self.f.tell() // BLOCK
        self.sb = self.pick_superblock()
        self.geo = Geo(self.sb["block_count"])
        self.csum_cache = {}

    def raw(self, blk, n=1):
        self.f.seek(blk * BLOCK)
        data = self.f.read(n * BLOCK)
        if len(data) != n * BLOCK:
            raise VolError("block %d is beyond the image" % blk)
        return data

    def pick_superblock(self):
        best = None
        for slot in SB_SLOTS:
            if slot >= self.blocks:
                continue
            b = self.raw(slot)
            if b[:8] != MAGIC:
                continue
            if struct.unpack_from("<I", b, 16)[0] != sb_crc(b):
                continue
            version, log2, _ = struct.unpack_from("<III", b, 8)
            incompat, = struct.unpack_from("<I", b, 20)
            if version != VERSION or log2 != 12 or incompat:
                raise VolError("unsupported volume (version %d, log2 %d, incompat %#x)"
                               % (version, log2, incompat))
            gen, count = struct.unpack_from("<QQ", b, 24)
            free_head, slots, used = struct.unpack_from("<QQQ", b, 88)
            key_alg, = struct.unpack_from("<I", b, 192)
            if key_alg:
                raise VolError("encrypted volumes are not supported")
            sb = dict(generation=gen, block_count=count, uuid=b[40:56],
                      label=b[56:88].rstrip(b"\0"), free_head=free_head,
                      inode_slots=slots, used=used, itable=b[256:512])
            if best is None or gen >= best["generation"]:
                best = sb
        if best is None:
            raise VolError("no valid superblock")
        return best

    def csum_of(self, blk):
        idx = blk // CSUMS_PER_BLOCK
        if idx not in self.csum_cache:
            self.csum_cache[idx] = self.raw(self.geo.csum_start + idx)
        return struct.unpack_from("<I", self.csum_cache[idx], (blk % CSUMS_PER_BLOCK) * 4)[0]

    def block(self, blk):
        if blk < self.geo.data_start or blk >= self.geo.block_count:
            raise VolError("block %d is outside the data area" % blk)
        b = self.raw(blk)
        if crc32c(b) != self.csum_of(blk):
            raise VolError("block %d fails its checksum" % blk)
        return b

    def extents(self, rec, owner, used):
        """All extents of an inode record, walking its tree."""
        level, count = rec[53], struct.unpack_from("<H", rec, 54)[0]
        if level > 3 or count > INLINE_CAP:
            raise VolError("bad extent root in inode %d" % owner)
        out = []

        def walk(entries, lvl):
            for i in range(entries[1]):
                raw = entries[0][i * ENTRY:(i + 1) * ENTRY]
                if lvl == 0:
                    f, d, n, flags, g = struct.unpack("<QQIIQ", raw)
                    if flags or n == 0:
                        raise VolError("unsupported extent in inode %d" % owner)
                    out.append((f, d, n))
                    for b in range(d, d + n):
                        used.add(b)
                else:
                    _, child, cgen, _ = struct.unpack("<QQQQ", raw)
                    node = self.block(child)
                    magic, nlevel, ncount, selfblk, ngen, nowner = struct.unpack_from("<IHHQQQ", node, 0)
                    if (magic != NODE_MAGIC or nlevel != lvl - 1 or not 0 < ncount <= NODE_CAP
                            or selfblk != child or ngen != cgen or nowner != owner):
                        raise VolError("bad tree node %d of inode %d" % (child, owner))
                    used.add(child)
                    walk((node[NODE_HDR:], ncount), lvl - 1)

        walk((rec[64:64 + INLINE_CAP * ENTRY], count), level)
        return out

    def read_file(self, exts, size):
        data = bytearray()
        blocks = {}
        for f, d, n in exts:
            for i in range(n):
                blocks[f + i] = d + i
        for fb in range(div_ceil(size, BLOCK)):
            data += self.block(blocks[fb]) if fb in blocks else bytes(BLOCK)
        return bytes(data[:size])


def verify(image, verity_root=None):
    img = Image(image)
    sb = img.sb
    used = set(range(img.geo.data_start))
    itable = sb["itable"]
    if itable[52] != KIND_TABLE:
        raise VolError("inode table record is not a table")
    size = struct.unpack_from("<Q", itable, 8)[0]
    if size != sb["inode_slots"] * INODE_SIZE:
        raise VolError("inode table size disagrees with the slot count")
    texts = img.extents(itable, 0, used)
    table = img.read_file(texts, size)
    recs = {}
    for ino in range(1, sb["inode_slots"]):
        rec = table[ino * INODE_SIZE:(ino + 1) * INODE_SIZE]
        if struct.unpack_from("<Q", rec, 0)[0] != ino:
            raise VolError("inode %d: record carries another number" % ino)
        if rec[52] != KIND_FREE:
            recs[ino] = rec
    listing = {}

    def load(ino):
        rec = recs[ino]
        fsize = struct.unpack_from("<Q", rec, 8)[0]
        exts = img.extents(rec, ino, used)
        return rec, fsize, img.read_file(exts, fsize)

    def walk(ino, prefix):
        rec, fsize, data = load(ino)
        for off in range(0, len(data), BLOCK):
            blk = data[off:off + BLOCK]
            pos = 0
            while pos + 16 <= BLOCK:
                child, rec_len, name_len, kind = struct.unpack_from("<QHBB", blk, pos)
                if rec_len == 0:
                    break
                if rec_len % 8 or rec_len < 24 or pos + rec_len > BLOCK:
                    raise VolError("directory %d: bad record length" % ino)
                if child:
                    name = blk[pos + 16:pos + 16 + name_len]
                    path = prefix + "/" + os.fsdecode(name)
                    if child not in recs or recs[child][52] != kind:
                        raise VolError("%s names a missing or mistyped inode" % path)
                    if kind == KIND_DIR:
                        listing[path] = ("dir", "-")
                        walk(child, path)
                    else:
                        _, csize, cdata = load(child)
                        listing[path] = (str(csize), hashlib.sha256(cdata).hexdigest())
                pos += rec_len

    if ROOT_INO not in recs or recs[ROOT_INO][52] != KIND_DIR:
        raise VolError("the root is not a directory")
    walk(ROOT_INO, "")
    for path in sorted(listing):
        print("%s\t%s\t%s" % ((path,) + listing[path]))
    stored = 0
    for i in range(img.geo.bitmap_blocks):
        b = img.raw(img.geo.bitmap_start + i)
        if crc32c(b[:BITMAP_PAYLOAD]) == struct.unpack_from("<I", b, BITMAP_PAYLOAD)[0]:
            stored += sum(bin(x).count("1") for x in b[:BITMAP_PAYLOAD])
        else:
            stored = -1
            break
    print("ok generation %d, %d inodes, %d blocks used, bitmap %s" % (
        sb["generation"], len(recs), len(used),
        "matches the trees" if stored == len(used) else "needs a rebuild"))
    if verity_root is not None:
        verity_check(image, img.geo.block_count, verity_root)


# ---- command line ------------------------------------------------------------------

def parse_size(s):
    mult = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
    if s[-1].lower() in mult:
        return int(s[:-1]) * mult[s[-1].lower()]
    return int(s)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("image")
    c.add_argument("--size", required=True, help="bytes, or N[KMG]; a multiple of 4096")
    c.add_argument("--root", help="directory whose contents become the volume")
    c.add_argument("--label", default="azvol")
    c.add_argument("--uuid", help="32 hex digits (default: derived from label and size)")
    c.add_argument("--time-ns", type=int,
                   default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")) * 10 ** 9)
    c.add_argument("--verity", action="store_true",
                   help="append a SHA-256 hash tree and print `verity_root HEX`")
    v = sub.add_parser("verify")
    v.add_argument("image")
    v.add_argument("--verity-root", help="64 hex digits: also check the hash tree after the volume")
    sub.add_parser("sha256")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "create":
            size = parse_size(a.size)
            label = a.label.encode()
            if len(label) > 32:
                raise VolError("label longer than 32 bytes")
            uuid = bytes.fromhex(a.uuid) if a.uuid else \
                hashlib.sha256(label + str(size).encode()).digest()[:16]
            if len(uuid) != 16:
                raise VolError("--uuid must be 32 hex digits")
            root = create(a.image, size, a.root, label, uuid, a.time_ns, a.verity)
            if root:
                print("verity_root %s" % root)
        elif a.cmd == "verify":
            if a.verity_root is not None and len(bytes.fromhex(a.verity_root)) != HASH_LEN:
                raise VolError("--verity-root must be 64 hex digits")
            verify(a.image, a.verity_root)
        else:
            print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
    except (VolError, OSError) as e:
        print("mkazvol: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
