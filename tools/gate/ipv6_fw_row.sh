#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Gate row for the packet filter on the IPv6 path (crates/net/stack: filter.rs,
# ipv6.rs): the "network: IPv6 firewall refuses" row of tools/gate/ci_check.sh and
# its control, "network: IPv6 firewall control".
#
# The guest's NIC is a QEMU `dgram` netdev whose other end is the Python peer
# below: one UDP datagram is one Ethernet frame, so the peer writes the IPv6
# frames itself and reads every frame the guest sends. No slirp, no host
# network stack in between.
#
#   rs      the guest sent a Router Solicitation (its IPv6 path is up).
#   fw      the console's `[FW]` line: with EXPECT=refuse it must say "inbound
#           default drop" and "installed", with EXPECT=answer "accept".
#   slaac   the peer advertises a /64 (Router Advertisement, hop limit 255)
#           and solicits the guest's SLAAC address in it (Neighbour
#           Solicitation): a Neighbour Advertisement for that address comes
#           back. Proves the guest is alive on IPv6 and that the ND and RA
#           messages SLAAC needs pass the policy: the positive control of the
#           silence below.
#   echo    an ICMPv6 echo request to that address. EXPECT=refuse: no reply
#           (the inbound default drops it). EXPECT=answer: an echo reply.
#   tcp     a TCP SYN to a port with no listener. EXPECT=refuse: nothing back.
#           EXPECT=answer: the RST a closed port sends.
#   fence   one more solicitation after the probes, answered: the guest takes
#           frames in order, so by then every probe has been handled and its
#           answer, if any, read. Silence is judged by ordering, not a timer.
#
# The refuse row boots a kernel built with FIREWALL_INBOUND_DROP=y; the
# control boots the default qemu kernel (no firewall installed) with the same
# probes and must see the answers: silence in the first row is the filter's,
# not a deaf guest's or a probe that could never be answered.
#
# Usage: tools/gate/ipv6_fw_row.sh <kernel-elf>
#   EXPECT=refuse|answer (default refuse), QEMU (default qemu-system-riscv64,
#   or qemu-system-aarch64), WAIT_SECS (boot budget, default 90).
# Needs python3. Exit 0 when every check holds.
set -u
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/../lib/out_dir.py")}"; export AZOS_OUT
KERNEL="${1:?usage: ipv6_fw_row.sh <kernel-elf>}"
QEMU="${QEMU:-qemu-system-riscv64}"
EXPECT="${EXPECT:-refuse}"
WAIT_SECS="${WAIT_SECS:-90}"
OUT="${OUT:-$AZOS_OUT/build/ipv6-fw-row}"
# Unique per run: two runs of the row must not share the link's ports.
GUEST_PORT="${GUEST_PORT:-$((21000 + ($$ % 2000) * 2))}"
PEER_PORT=$((GUEST_PORT + 1))
mkdir -p "$OUT"
LOG="$OUT/console-$EXPECT.log"
rm -f "$LOG"
[ -f "$KERNEL" ] || { echo "ipv6 fw row: no kernel at $KERNEL"; exit 2; }
case "$QEMU" in
    *aarch64*) MACH=(-M virt,gic-version=3 -cpu max) ;;
    *) MACH=(-M virt -bios default) ;;
esac

"$QEMU" "${MACH[@]}" -smp 1 -m 256M -nographic \
    -netdev "dgram,id=net0,local.type=inet,local.host=127.0.0.1,local.port=$GUEST_PORT,remote.type=inet,remote.host=127.0.0.1,remote.port=$PEER_PORT" \
    -device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
    -kernel "$KERNEL" </dev/null > "$LOG" 2>&1 &
qpid=$!
trap 'kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null' EXIT

python3 -I - "$LOG" "$GUEST_PORT" "$PEER_PORT" "$EXPECT" "$WAIT_SECS" "$qpid" <<'PY'
import os, socket, struct, sys, time

log, gport, pport, expect, wait_s, qpid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), int(sys.argv[6])

GUEST_MAC = bytes.fromhex("525400123456")
PEER_MAC = bytes.fromhex("02aabbccddee")
PEER_LL = bytes.fromhex("fe800000000000000000000000000001")
PREFIX = bytes.fromhex("20010db800010002")
IID = bytes([GUEST_MAC[0] ^ 2]) + GUEST_MAC[1:3] + b"\xff\xfe" + GUEST_MAC[3:6]
GUEST_GLOBAL = PREFIX + IID
SOLICITED = bytes.fromhex("ff0200000000000000000001ff") + IID[5:8]

def csum(src, dst, proto, body):
    p = src + dst + struct.pack(">I", len(body)) + bytes([0, 0, 0, proto]) + body
    if len(p) % 2:
        p += b"\0"
    s = sum(struct.unpack(">%dH" % (len(p) // 2), p))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def frame(dst_mac, src, dst, proto, hop, body, csum_at):
    body = bytearray(body)
    body[csum_at:csum_at + 2] = b"\0\0"
    body[csum_at:csum_at + 2] = struct.pack(">H", csum(src, dst, proto, bytes(body)))
    ip = struct.pack(">IHBB", 6 << 28, len(body), proto, hop) + src + dst
    return dst_mac + PEER_MAC + b"\x86\xdd" + ip + bytes(body)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", pport))
guest = ("127.0.0.1", gport)

def frames(timeout):
    """Every IPv6 frame the guest sends within `timeout` seconds."""
    end = time.time() + timeout
    while True:
        left = end - time.time()
        if left <= 0:
            return
        s.settimeout(left)
        try:
            f, _ = s.recvfrom(2048)
        except socket.timeout:
            return
        if len(f) >= 54 and f[12:14] == b"\x86\xdd":
            yield f[20], f[21], f[22:38], f[38:54], f[54:]

def console(word):
    try:
        return [l for l in open(log, errors="replace") if word in l]
    except OSError:
        return []

def alive():
    try:
        os.kill(qpid, 0)
        return True
    except OSError:
        return False

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print("ipv6 fw row: %-6s %s%s" % (name, "ok" if ok else "FAIL", (" (" + detail + ")") if detail else ""))

# Boot: the Router Solicitation, then the firewall's line (installed after it).
rs = False
end = time.time() + wait_s
while time.time() < end and alive() and not (rs and console("[FW]")):
    for nxt, hop, src, dst, body in frames(1):
        if nxt == 58 and body[:1] == b"\x85" and hop == 255:
            rs = True
check("rs", rs)
fw = console("[FW]")
if expect == "refuse":
    check("fw", bool(fw) and "inbound default drop" in fw[-1] and "installed" in fw[-1], fw[-1].strip() if fw else "no [FW] line")
else:
    check("fw", bool(fw) and "inbound default accept" in fw[-1], fw[-1].strip() if fw else "no [FW] line")

# SLAAC: advertise the prefix, then solicit the address it gives the guest.
ra = bytes([134, 0, 0, 0, 64, 0]) + struct.pack(">H", 1800) + bytes(8)
ra += bytes([1, 1]) + PEER_MAC
ra += bytes([3, 4, 64, 0xC0]) + struct.pack(">II", 3600, 1800) + bytes(4) + PREFIX + bytes(8)
ns = bytes([135, 0, 0, 0, 0, 0, 0, 0]) + GUEST_GLOBAL + bytes([1, 1]) + PEER_MAC
na = False
# The guest's address is tentative for its Duplicate Address Detection wait
# (1 s): the first solicitations draw nothing, so they are repeated.
for _ in range(10):
    s.sendto(frame(b"\x33\x33\x00\x00\x00\x01", PEER_LL, bytes.fromhex("ff020000000000000000000000000001"), 58, 255, ra, 2), guest)
    s.sendto(frame(b"\x33\x33\xff" + IID[5:8], PEER_LL, SOLICITED, 58, 255, ns, 2), guest)
    for nxt, hop, src, dst, body in frames(1):
        if nxt == 58 and body[:1] == b"\x88" and body[8:24] == GUEST_GLOBAL and src == GUEST_GLOBAL:
            na = True
    if na:
        break
check("slaac", na, "" if na else "no Neighbour Advertisement for the SLAAC address")

# The probes: an echo request and a SYN to a closed port, each sent three times.
echo = bytes([128, 0, 0, 0, 0x12, 0x34, 0, 1]) + b"fw6"
syn = struct.pack(">HHIIBBHHH", 40000, 23, 1000, 0, 5 << 4, 0x02, 8192, 0, 0)
# Then a fence: one more solicitation. The guest takes its frames in order, so
# once its advertisement is back every probe before it has been handled, and
# any answer a probe drew has been read: the verdict does not hang on a timer.
reply = rst = fence = False
for _ in range(3):
    s.sendto(frame(GUEST_MAC, PEER_LL, GUEST_GLOBAL, 58, 64, echo, 2), guest)
    s.sendto(frame(GUEST_MAC, PEER_LL, GUEST_GLOBAL, 6, 64, syn, 16), guest)
s.sendto(frame(b"\x33\x33\xff" + IID[5:8], PEER_LL, SOLICITED, 58, 255, ns, 2), guest)
end = time.time() + wait_s
while time.time() < end and not fence:
    for nxt, hop, src, dst, body in frames(1):
        if dst != PEER_LL:
            continue
        if nxt == 58 and body[:1] == b"\x81":
            reply = True
        if nxt == 6 and len(body) >= 20 and body[13] & 0x04:
            rst = True
        if nxt == 58 and body[:1] == b"\x88" and body[8:24] == GUEST_GLOBAL:
            fence = True
            break
check("fence", fence, "" if fence else "no advertisement after the probes")
if expect == "refuse":
    check("echo", not reply, "an echo reply came back" if reply else "")
    check("tcp", not rst, "a RST came back" if rst else "")
else:
    check("echo", reply, "" if reply else "no echo reply")
    check("tcp", rst, "" if rst else "no RST")
sys.exit(0 if results and all(results) else 1)
PY
