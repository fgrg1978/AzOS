#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""ACKs per data segment of vsbench's TCP bulk lanes, from a QEMU pcap.

`tools/vsbench_compare.sh`'s TCP pass records every frame of the guest's NIC
with `-object filter-dump` (Ethernet, possibly truncated by `maxlen`: only
the headers are read). Both kernels are counted by the same code, from the
wire, so neither side's own counters are trusted for this number.

Per TCP connection with the guest (10.0.2.15), the side that sent more
payload bytes is the data sender. Printed, one line per connection:

  <lane> data_segs=<n> payload_per_seg=<n> pure_acks=<n> acks_per_seg=<x.xxx>
         retx=<n> fin=<s>/<r> rst=<s>/<r>

`tcp-bulk-tx` is the connection the guest sent on (its ACKs are slirp's);
`tcp-bulk-rx` the one it received on (its ACKs are the guest kernel's).
`pure_acks`: segments from the receiver with no payload and only ACK set
(window updates included; SYN, FIN and RST excluded). `retx`: data
segments from the sender that end at or before a byte it had already sent.
`fin`/`rst`: segments carrying that flag, from the sender / the receiver.
"""
import struct
import sys

GUEST = bytes([10, 0, 2, 15])


def frames(path):
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return
        magic = struct.unpack("<I", head[:4])[0]
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            _, _, incl, _ = struct.unpack(endian + "IIII", rec)
            yield f.read(incl)


def main(path):
    flows = {}   # guest port -> stats, in order of first sight
    for fr in frames(path):
        if len(fr) < 14 + 20 or fr[12:14] != b"\x08\x00":
            continue
        ip = fr[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        total = struct.unpack(">H", ip[2:4])[0]
        src, dst = ip[12:16], ip[16:20]
        tcp = ip[ihl:]
        sport, dport = struct.unpack(">HH", tcp[:4])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        payload = total - ihl - doff
        if src == GUEST:
            key, from_guest = sport, True
        elif dst == GUEST:
            key, from_guest = dport, False
        else:
            continue
        st = flows.setdefault(key, {True: [0, 0, 0, 0, 0, 0, None],
                                    False: [0, 0, 0, 0, 0, 0, None]})
        # [payload bytes, payload segments, pure ACKs, retx, FIN, RST, top]
        s = st[from_guest]
        seq = struct.unpack(">I", tcp[4:8])[0]
        if payload > 0:
            s[0] += payload
            s[1] += 1
            end = (seq + payload) & 0xFFFFFFFF
            if s[6] is not None and ((end - s[6]) & 0xFFFFFFFF) >= 0x80000000 or end == s[6]:
                s[3] += 1
            else:
                s[6] = end
        elif flags & 0x17 == 0x10:   # ACK, and none of SYN/FIN/RST
            s[2] += 1
        if flags & 0x01:
            s[4] += 1
        if flags & 0x04:
            s[5] += 1
    for st in flows.values():
        guest_sends = st[True][0] >= st[False][0]
        snd, rcv = st[guest_sends], st[not guest_sends]
        if snd[1] == 0:
            continue
        lane = "tcp-bulk-tx" if guest_sends else "tcp-bulk-rx"
        print("%s data_segs=%d payload_per_seg=%d pure_acks=%d acks_per_seg=%.3f"
              " retx=%d fin=%d/%d rst=%d/%d"
              % (lane, snd[1], snd[0] // snd[1], rcv[2], rcv[2] / snd[1],
                 snd[3], snd[4], rcv[4], snd[5], rcv[5]))


if __name__ == "__main__":
    main(sys.argv[1])
