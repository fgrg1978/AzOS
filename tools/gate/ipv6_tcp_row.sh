#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Gate row for TCP over IPv6 and SLAAC (crates/net/net: ipv6.rs, tcp.rs,
# socket.rs): the "network: IPv6 SLAAC on the wire" row of tools/gate/ci_check.sh.
# What slirp does was read off this row's frame capture (QEMU 11.0, libslirp
# 4.9.1): the places that are still from memory are marked UNVERIFIED.
#
# What it does: boots the kernel on a virtio-net NIC behind QEMU's user-mode
# (slirp) network with IPv6 on, records every frame the NIC sees
# (`filter-dump`), and judges the recording on the host:
#
#   rs     the guest sent a Router Solicitation: ICMPv6 type 133 to FF02::2,
#          hop limit 255, from its fe80:: address, with a valid checksum.
#   ra     slirp answered with a Router Advertisement (type 134): within a
#          millisecond of the solicitation, from fe80::2 to ff02::1, carrying
#          the prefix fec0::/64 (`ipv6-net=`) with the L and A flags, valid
#          86400 s and preferred 14400 s, the router's MAC and an RDNSS option
#          (tests/host/net-tests, ipv6_tcp.rs, holds it byte for byte).
#   dad    the guest probed for the address it formed from that prefix
#          (Duplicate Address Detection, RFC 4862 §5.4.2): a Neighbour
#          Solicitation from ::, hop limit 255, to the solicited-node group of
#          a target that is the prefix and the guest's interface id, with no
#          option. The address formed, read from the wire.
#   slaac  the guest used that address as the source of an IPv6 packet
#          afterwards -- the SLAAC address in use, read from the wire and not
#          from a console line -- and not before RetransTimer (1 s: slirp's
#          advertisement leaves it unspecified) had passed since the probe: a
#          tentative address is no source. Slirp itself never addresses the
#          guest, so what is seen is the Neighbour Advertisement the guest sends
#          the routers when the address is assigned (RFC 9131), or the TCP leg.
#   tcp6   when TCP6_PEER is set (an IPv6 address slirp can reach, e.g. the
#          host's `fec0::2`, UNVERIFIED) and the guest has something that
#          dials it: a SYN from the guest to TCP6_PEER:TCP6_PORT, with a valid
#          pseudo-header checksum, MSS option 1440, and -- if slirp's host
#          side answered -- a SYN-ACK back to the guest, then data. Without
#          TCP6_PEER the row stops after `slaac`.
#
# The guest-side user of tcp6 is not wired yet: no kernel code dials an IPv6
# peer today (the syscall layer has no AF_INET6 yet), so `tcp6` is a check the
# row can only pass once something does. The host tests (tests/host/net-tests,
# ipv6_tcp.rs) carry the protocol; this row is for the real NIC path.
#
# Usage: tools/gate/ipv6_tcp_row.sh [kernel-elf]
#   kernel-elf  riscv64 ELF built with `--features qemu` (default:
#               $AZOS_OUT/target/riscv64imac-unknown-none-elf/release/kernel).
# Needs qemu-system-riscv64 and python3. Exit 0 when every enabled check holds.
set -u
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/../lib/out_dir.py")}"; export AZOS_OUT
KERNEL="${1:-$AZOS_OUT/target/riscv64imac-unknown-none-elf/release/kernel}"
QEMU="${QEMU:-qemu-system-riscv64}"
WAIT_SECS="${WAIT_SECS:-40}"
TCP6_PEER="${TCP6_PEER:-}"
TCP6_PORT="${TCP6_PORT:-7}"
OUT="${OUT:-$AZOS_OUT/build/ipv6-tcp-row}"
mkdir -p "$OUT"
LOG="$OUT/console.log"; PCAP="$OUT/net.pcap"
rm -f "$LOG" "$PCAP"
[ -f "$KERNEL" ] || { echo "ipv6 tcp row: no kernel at $KERNEL"; exit 2; }

# `ipv6-net` names the prefix slirp advertises (fec0::/64 on the capture);
# `ipv6=on` is said explicitly.
"$QEMU" -M virt -bios default -smp 1 -m 256M -nographic \
    -netdev user,id=net0,ipv6=on,ipv6-net=fec0::/64 \
    -device virtio-net-device,netdev=net0 \
    -object filter-dump,id=dump0,netdev=net0,file="$PCAP" \
    -kernel "$KERNEL" > "$LOG" 2>&1 &
qpid=$!
trap 'kill "$qpid" 2>/dev/null' EXIT
# Give the guest time to boot, send its solicitation and hear the answer.
for _ in $(seq 1 "$WAIT_SECS"); do
    kill -0 "$qpid" 2>/dev/null || break
    sleep 1
done
kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null

python3 -I - "$PCAP" "$TCP6_PEER" "$TCP6_PORT" <<'PY'
import socket, struct, sys

pcap, peer, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

def frames(path):
    d = open(path, "rb").read()
    magic = d[:4]
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    e = "<" if le else ">"
    i = 24
    while i + 16 <= len(d):
        _, _, incl, _ = struct.unpack(e + "IIII", d[i:i + 16])
        sec, usec = struct.unpack(e + "II", d[i:i + 8])
        yield sec + usec / 1e6, d[i + 16:i + 16 + incl]
        i += 16 + incl

def csum_ok(src, dst, proto, body):
    pseudo = src + dst + struct.pack(">I", len(body)) + bytes([0, 0, 0, proto]) + body
    if len(pseudo) % 2:
        pseudo += b"\0"
    s = sum(struct.unpack(">%dH" % (len(pseudo) // 2), pseudo))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF

rs = ra = slaac = False
prefix = None
syn = synack = False
guest_ll = None
fails = []
dad_at = None
for t, f in frames(pcap):
    if len(f) < 54 or f[12:14] != b"\x86\xdd":
        continue
    nxt, hop, src, dst, body = f[20], f[21], f[22:38], f[38:54], f[54:]
    if nxt == 58 and body and body[0] == 133 and dst == bytes.fromhex("ff020000000000000000000000000002"):
        if hop != 255 or src[:2] != b"\xfe\x80" or not csum_ok(src, dst, 58, body):
            fails.append("rs malformed (hop %d)" % hop)
        rs, guest_ll = True, src
    if nxt == 58 and body and body[0] == 134 and not ra:
        # options start at 16: look for a prefix information option (type 3)
        i = 16
        while i + 2 <= len(body) and body[i + 1]:
            if body[i] == 3 and body[i + 1] == 4 and i + 32 <= len(body):
                prefix = body[i + 16:i + 24]
                ra = True
            i += body[i + 1] * 8
    iid = (guest_ll or b"\0" * 16)[8:]
    if prefix and nxt == 58 and body[:1] == b"\x87" and src == b"\0" * 16 \
            and body[8:16] == prefix and body[16:24] == iid and dad_at is None:
        target = body[8:24]
        group = bytes.fromhex("ff0200000000000000000001ff") + target[13:16]
        if hop != 255 or dst != group or len(body) != 24 or not csum_ok(src, dst, 58, body):
            fails.append("dad probe malformed (hop %d, %d octets)" % (hop, len(body)))
        dad_at = t
    if prefix and src[:8] == prefix and src[8:] == iid and not slaac:
        if dad_at is None or t - dad_at < 0.9:
            fails.append("the address was a source " + ("with no probe before it" if dad_at is None
                         else "%.3f s after its probe, inside RetransTimer" % (t - dad_at)))
        slaac = True
    if peer and nxt == 6 and len(body) >= 20:
        p = socket.inet_pton(socket.AF_INET6, peer)
        sport, dport = struct.unpack(">HH", body[:4])
        flags = body[13]
        if dst == p and dport == port and flags & 0x12 == 0x02:
            ok = csum_ok(src, dst, 6, body)
            mss = None
            opts = body[20:(body[12] >> 4) * 4]
            j = 0
            while j + 1 < len(opts):
                if opts[j] == 0: break
                if opts[j] == 1: j += 1; continue
                if opts[j] == 2 and opts[j + 1] == 4: mss = struct.unpack(">H", opts[j + 2:j + 4])[0]
                j += max(opts[j + 1], 2)
            if not ok or mss != 1440:
                fails.append("tcp6 SYN: checksum %s, mss %s" % (ok, mss))
            syn = True
        if src == p and sport == port and flags & 0x12 == 0x12:
            synack = True

checks = [("rs", rs), ("ra", ra), ("dad", dad_at is not None), ("slaac", slaac)]
if peer:
    checks += [("tcp6 syn", syn), ("tcp6 synack", synack)]
for name, ok in checks:
    print("ipv6 tcp row: %-12s %s" % (name, "ok" if ok else "MISSING"))
for f in fails:
    print("ipv6 tcp row: FAIL", f)
sys.exit(0 if all(ok for _, ok in checks) and not fails else 1)
PY
