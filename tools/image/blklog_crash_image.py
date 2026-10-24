#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Build the disk a power cut would leave, from a QEMU `blklogwrites` log.

usage: blklog_crash_image.py <pristine.img> <write.log> <out.img>
       blklog_crash_image.py --cuts <pristine.img> <write.log>
       blklog_crash_image.py --cut <epoch> <classes> <pristine.img> <write.log> <out.img>

`blklogwrites` (a QEMU block filter) records every write and every flush the
guest's disk receives, in order, in the dm-log-writes format: a superblock in
sector 0, then one entry sector per request (sector, nr_sectors, flags,
data_len; flags bit 0 = FLUSH, bit 1 = FUA), each followed by its data.

With the device's write cache on, only writes followed by a flush are
durable. This replays onto a copy of the image the guest booted from every
write up to the LAST flush (and any FUA write), and drops the rest: the most
pessimistic state a power cut right after the guest stopped can leave,
assuming the device does not reorder writes that a flush separates.

Prints one summary line. A log with no flush at all yields the pristine
image plus FUA writes only. Exits non-zero only if the log is unreadable.

`--cuts` / `--cut`: power cuts INSIDE an operation, with the device free to
persist the writes a flush has not yet covered in any order. The flushes
split the log into epochs; a cut in epoch k leaves every write before it
plus any subset of epoch k's writes. The writes are grouped by what they
touch on a FAT32 volume (from the pristine image's BPB): `j` the journal
sector (LBA 8), `f` a FAT sector, `d` the root directory cluster, `c` file
data. `--cuts` lists one `<epoch> <classes>` line per distinct image over
every subset of the classes present in each epoch, from the first epoch that
writes a PENDING journal record onward (the operations under test; earlier
epochs are boot and mount traffic). `--cut` builds one of them. A prefix cut
(`<out.img>` mode) never reorders; these do, at class granularity.
"""
import shutil
import struct
import sys

LOG_MAGIC = 0x6A736677736872
FLUSH, FUA = 1, 2


def entries(log):
    magic, version, nr, ss = struct.unpack_from('<QQQI', log, 0)
    if magic != LOG_MAGIC or ss not in (512, 4096):
        sys.exit("blklog_crash_image: not a blklogwrites log (magic %#x, sector %d)" % (magic, ss))
    off = ss
    # `nr` in the superblock can lag the entries when the guest is killed;
    # walk until an all-zero entry instead of trusting it.
    while off + 32 <= len(log):
        sector, nsec, flags, _dlen = struct.unpack_from('<QQQQ', log, off)
        if sector == 0 and nsec == 0 and flags == 0:
            return
        data = log[off + ss: off + ss + nsec * ss]
        yield sector, nsec, flags, data, ss
        off += ss + nsec * ss


JOURNAL_SECTOR = 8


def classifier(pristine):
    img = open(pristine, 'rb').read()
    bpb = img[:512]
    spc = bpb[13]
    rsvd, = struct.unpack_from('<H', bpb, 14)
    nfats = bpb[16]
    fatsz, = struct.unpack_from('<I', bpb, 36)
    root, = struct.unpack_from('<I', bpb, 44)
    data_start = rsvd + nfats * fatsz
    # Every cluster of the root directory's chain, from the pristine FAT
    # (a populated image's root spans several clusters).
    root_sectors, c, seen = set(), root, 0
    while 2 <= c < 0x0FFFFFF8 and seen < 4096:
        first = data_start + (c - 2) * spc
        root_sectors.update(range(first, first + spc))
        c, = struct.unpack_from('<I', img, rsvd * 512 + c * 4)
        c &= 0x0FFFFFFF
        seen += 1

    def cls(sector):
        if sector == JOURNAL_SECTOR:
            return 'j'
        if rsvd <= sector < data_start:
            return 'f'
        if sector in root_sectors:
            return 'd'
        return 'c'
    return cls


def epochs(ents, cls):
    """[(writes, flushed)] from the first PENDING journal record on; each
    write is (sector, bytes, class), one per sector."""
    out, cur, started = [], [], False
    for sector, nsec, flags, data, ss in ents:
        for i in range(nsec):
            chunk = data[i * ss:(i + 1) * ss]
            s = sector + i
            if s == JOURNAL_SECTOR and chunk[0:4] == b'JRNL' and chunk[4] == 1:
                started = True
            cur.append((s, chunk, cls(s)))
        if flags & FLUSH:
            out.append((cur, True))
            cur = []
    out.append((cur, False))
    # Drop everything before the epoch holding the first PENDING record,
    # but keep its writes as the base the cuts start from.
    first = None
    for k, (ws, _) in enumerate(out):
        if any(s == JOURNAL_SECTOR and b[0:4] == b'JRNL' and b[4] == 1 for s, b, _ in ws):
            first = k
            break
    return out, (first if started else None)


def cut_overlay(eps, k, classes):
    ov = {}
    for ws, _ in eps[:k]:
        for s, b, _ in ws:
            ov[s] = b
    for s, b, c in eps[k][0]:
        if c in classes:
            ov[s] = b
    return ov


def load(pristine, log_path):
    log = open(log_path, 'rb').read()
    ents = list(entries(log))
    return ents, classifier(pristine)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--cuts':
        ents, cls = load(sys.argv[2], sys.argv[3])
        eps, first = epochs(ents, cls)
        if first is None:
            sys.exit("blklog_crash_image: no PENDING journal record in the log")
        seen = set()
        flushes = sum(1 for _, f in eps[first:] if f)
        n = 0
        for k in range(first, len(eps)):
            present = sorted({c for _, _, c in eps[k][0]})
            for mask in range(1 << len(present)):
                classes = ''.join(c for i, c in enumerate(present) if mask & (1 << i)) or '-'
                ov = cut_overlay(eps, k, classes)
                key = tuple(sorted((s, hash(b)) for s, b in ov.items()))
                if key in seen:
                    continue
                seen.add(key)
                print("%d %s" % (k, classes))
                n += 1
        print("# %d cut images over epochs %d..%d, %d flushes in that window"
              % (n, first, len(eps) - 1, flushes), file=sys.stderr)
        return
    if len(sys.argv) == 7 and sys.argv[1] == '--cut':
        k, classes, pristine, log_path, out = int(sys.argv[2]), sys.argv[3], *sys.argv[4:]
        ents, cls = load(pristine, log_path)
        eps, _ = epochs(ents, cls)
        shutil.copyfile(pristine, out)
        with open(out, 'r+b') as img:
            for s, b in cut_overlay(eps, k, classes).items():
                img.seek(s * 512)
                img.write(b)
        return
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    pristine, log_path, out = sys.argv[1:]
    log = open(log_path, 'rb').read()
    ents = list(entries(log))
    last_flush = max((i for i, e in enumerate(ents) if e[2] & FLUSH), default=-1)
    shutil.copyfile(pristine, out)
    kept = dropped = 0
    with open(out, 'r+b') as img:
        for i, (sector, nsec, flags, data, ss) in enumerate(ents):
            if nsec == 0:
                continue
            if i < last_flush or flags & FUA:
                img.seek(sector * ss)
                img.write(data)
                kept += 1
            else:
                dropped += 1
    flushes = sum(1 for e in ents if e[2] & FLUSH)
    print("blklog_crash_image: %d entries, %d flushes, %d writes kept, %d dropped"
          % (len(ents), flushes, kept, dropped))


if __name__ == '__main__':
    main()
