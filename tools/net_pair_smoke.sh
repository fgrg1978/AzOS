#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Two-node network smoke: boots two kernel instances wired together by QEMU's
# `socket` net backend and asserts that a 256-byte payload round-trips intact
# and that both ends negotiated Window Scale and SACK-Permitted.
#
# Why two guests instead of QEMU user-mode networking: SLIRP only carries
# host<->guest traffic, and the host side is not our code. Here BOTH ends are
# this kernel, so the run exercises our TX path against our RX path — ARP, the
# IPv4 header checksum, the TCP handshake, and RX checksum validation in both
# directions. The TFTP smoke covers none of that (UDP, one direction, and the
# peer is QEMU's built-in server).
#
# Identity comes from the MAC QEMU assigns, so one kernel image serves both
# roles: last octet 01 => server 10.0.0.1, 02 => client 10.0.0.2.
#
# Exit: 0 only on an explicit client-side PASS with both `opts` lines. Any FAIL,
# a missing or different `opts` line, a panic, or a timeout is
# non-zero — silence is never treated as success.
set -u

QEMU="${QEMU:-qemu-system-riscv64}"
KERNEL="${KERNEL:-target/riscv64imac-unknown-none-elf/release/kernel}"
# Unique per run. Consecutive runs on a fixed port race: the previous server
# QEMU can still be dying on it when the next one starts, so the new client
# connects to the OLD server, the new server never sees a peer, and both guests
# report plausible-looking kernel failures ("no-client" / "FAIL arp") for what
# is purely a harness collision.
LINK_PORT="${LINK_PORT:-$((17000 + ($$ % 1500)))}"
OUT="${OUT:-build/net-pair}"
WAIT_SECS="${WAIT_SECS:-150}"

mkdir -p "$OUT"
SRV_LOG="$OUT/server.log"
CLI_LOG="$OUT/client.log"
rm -f "$SRV_LOG" "$CLI_LOG"

if [ ! -f "$KERNEL" ]; then
    echo "[net-pair] kernel not found: $KERNEL" >&2
    echo "[net-pair] build it first: cargo build --release --features qemu,net-smoke" >&2
    exit 4
fi

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    # Block until they are really gone. Returning while a QEMU still holds the
    # link port is what makes back-to-back runs collide.
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# Pure-bash matching. This host's non-interactive PATH has neither `grep` nor
# `rg` nor `seq`, so any detection built on them silently finds nothing and the
# harness reports a timeout while the test underneath is actually passing.
has() { # has <substring> <file>...
    local pat="$1"; shift
    local f line
    for f in "$@"; do
        [ -r "$f" ] || continue
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in *"$pat"*) return 0 ;; esac
        done < "$f"
    done
    return 1
}

show() { # show <file> — echo the lines worth seeing
    local f="$1" line
    [ -r "$f" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *NETSMOKE*|*"[NET]"*|*panic*|*PANIC*) printf '%s\n' "$line" ;;
        esac
    done < "$f"
}

boot() { # $1=log  $2=mac-octet  $3=netdev-spec
    "$QEMU" -machine virt -nographic -bios default \
        -kernel "$KERNEL" \
        -netdev "$3" \
        -device "virtio-net-device,netdev=net0,mac=52:54:00:00:00:0$2" \
        > "$1" 2>&1 &
}

# A point-to-point TCP link, not multicast: `socket,mcast=` needs a multicast
# route, and on this host sendto() to a multicast group returns EHOSTUNREACH, so
# ZERO frames are delivered and the test can only ever time out. An earlier
# version used mcast to dodge TCP backpressure freezing a guest mid-send — that
# concern died with the unbounded TX completion spin it came from; send() is
# asynchronous now.
#
# The listener must be up before the peer dials in.
echo "[net-pair] starting server node (10.0.0.1) on link port $LINK_PORT"
boot "$SRV_LOG" 1 "socket,id=net0,listen=127.0.0.1:$LINK_PORT"
SRV_PID=$!

# Wait for the server QEMU to actually be up before dialling in. A fixed sleep
# is a race: `connect=` fails outright if the listening socket is not bound yet,
# the client QEMU exits instantly with an empty log, and the server reports
# "no-client" — which reads like a kernel bug rather than a harness one. Any
# output at all proves the process is alive and past socket setup.
#
# We do NOT wait for the guest to reach its listen() call: QEMU binds the link
# socket before the guest boots, so no frame can be lost, and starting both
# together means they reach the smoke within a second of each other instead of
# the server burning its polling budget while the client boots.
i=0
while [ $i -lt 60 ]; do
    [ -s "$SRV_LOG" ] && break
    kill -0 "$SRV_PID" 2>/dev/null || { echo "[net-pair] server died on startup" >&2; exit 5; }
    i=$((i + 1)); sleep 0.25
done

echo "[net-pair] starting client node (10.0.0.2)"
# Started exactly once, deliberately. `socket,listen=` accepts ONE connection:
# killing a client and starting another consumes the server's only accept and
# leaves the link permanently dead, which then looks like an ARP failure in the
# guest. If the client cannot start, fail loudly instead of retrying.
boot "$CLI_LOG" 2 "socket,id=net0,connect=127.0.0.1:$LINK_PORT"
CLI_PID=$!

i=0
while [ $i -lt 20 ]; do
    [ -s "$CLI_LOG" ] && break
    kill -0 "$CLI_PID" 2>/dev/null || {
        echo "[net-pair] client QEMU exited immediately — link port $LINK_PORT" >&2
        echo "[net-pair] probably not bound yet, or already in use." >&2
        exit 6
    }
    i=$((i + 1)); sleep 0.25
done

# Poll for a verdict. Checked in severity order so a panic is never masked by a
# later PASS line, and vice versa.
verdict=""
i=0; while [ $i -lt $((WAIT_SECS * 4)) ]; do
    if has "panic" "$CLI_LOG" "$SRV_LOG"; then
        verdict="panic"; break
    fi
    if has "NETSMOKE] FAIL" "$CLI_LOG" "$SRV_LOG"; then
        verdict="fail"; break
    fi
    if has "NETSMOKE] PASS" "$CLI_LOG"; then
        verdict="pass"; break
    fi
    i=$((i + 1)); sleep 0.25
done

# The handshake options. Only here are both ends this stack: slirp parses the
# MSS and nothing else, so every other boot runs without Window Scale and SACK
# and a round trip passes either way. Each side prints what its connection
# agreed. Shift 1 is `RCV_WSCALE` for the 128 KiB receive ring
# (`crates/net/net/src/tcp.rs`); the value is pinned, not just the option's presence.
OPTS="NETSMOKE] opts wscale=1/1 sack=1"
if [ "$verdict" = "pass" ]; then
    i=0; while [ $i -lt 20 ]; do
        has "$OPTS" "$SRV_LOG" && has "$OPTS" "$CLI_LOG" && break
        i=$((i + 1)); sleep 0.25
    done
    if ! has "$OPTS" "$SRV_LOG" || ! has "$OPTS" "$CLI_LOG"; then verdict="opts"; fi
fi

echo
echo "─── server (10.0.0.1) ───"
show "$SRV_LOG" | tail -12
echo "─── client (10.0.0.2) ───"
show "$CLI_LOG" | tail -12
echo

case "$verdict" in
    pass)
        echo "[net-pair] PASS — payload round-tripped intact, Window Scale and SACK negotiated"
        exit 0 ;;
    opts)
        echo "[net-pair] FAIL — round trip passed, but a side did not report 'opts wscale=1/1 sack=1'" >&2
        exit 7 ;;
    fail)
        echo "[net-pair] FAIL — see the verdict line above" >&2
        exit 1 ;;
    panic)
        echo "[net-pair] FAIL — kernel panic" >&2
        show "$CLI_LOG" >&2; show "$SRV_LOG" >&2
        exit 2 ;;
    *)
        echo "[net-pair] FAIL — no verdict within ${WAIT_SECS}s (hang or lost link)" >&2
        exit 3 ;;
esac
