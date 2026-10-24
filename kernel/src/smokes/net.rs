// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The DHCP smoke and the two-node TCP smoke.

use crate::*;

/// Boot-time DHCP smoke (opt-in via `--features dhcp-smoke`).
///
/// QEMU's user-mode backend runs a DHCP server on the gateway, so
/// `-netdev user,...` is all the infrastructure this needs. Asserts we
/// actually reach the Bound state and end up with a non-zero address in the
/// 10.0.2.x pool SLIRP hands out — not merely that `dhcp_start()` returned.
///
/// Must run after [`install_net`]/`net_init()` (needs a live transport) and
/// before the scheduler starts preempting (it busy-polls synchronously, not
/// through a task).
///
/// Shared between both `kernel_main`s: the body is pure `crates/net/net` API
/// (`dhcp::dhcp_start`, `net_poll`, `net_set_ip`, `net_get_ip`/
/// `net_get_gateway`), none of it RISC-V-specific — riscv64 had this
/// inlined directly in its own body; aarch64 gets the identical scenario
/// through the same call rather than a second copy.
///
/// `#[inline(always)]`: same codegen-preservation rule as `install_net`
/// above, applied even though this only affects the opt-in `dhcp-smoke`
/// build, not the default gate build.
#[cfg(feature = "dhcp-smoke")]
#[inline(always)]
pub(crate) fn run_dhcp_smoke() {
    // `dhcp_start` takes a `fn()` it calls once per receive attempt, and
    // only polls once itself per iteration. Pre-scheduler there is nothing
    // to yield TO, so the hook does the waiting instead: 200 attempts x 20k
    // polls is ~1.7s per phase at this placement, which is ample for a
    // server on the same host and still bounded.
    fn dhcp_smoke_wait() {
        for _ in 0..20_000 { azos_net::net_poll(); }
    }

    // Start from a deliberately wrong address so a PASS cannot be the
    // CONFIG.INI value surviving untouched.
    azos_net::net_set_ip([0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]);
    // virtio-pci IRQ mode: the NIC's per-vector MSI counts around the
    // exchange (RX is read only after an RX MSI there).
    azos_drv_virtio::virtio::net::print_msi_counts("before dhcp");

    if !azos_net::dhcp::dhcp_start(dhcp_smoke_wait) {
        kprintln!("[DHCPSMOKE] FAIL no-lease");
    } else {
        let ip = azos_net::net_get_ip();
        let gw = azos_net::net_get_gateway();
        if ip == [0, 0, 0, 0] {
            kprintln!("[DHCPSMOKE] FAIL bound-but-no-address");
        } else if ip[0] != 10 || ip[1] != 0 || ip[2] != 2 {
            // Not fatal in principle, but on QEMU user-mode it means we
            // parsed something other than the lease we were offered.
            kprintln!("[DHCPSMOKE] FAIL unexpected-subnet {}.{}.{}.{}",
                      ip[0], ip[1], ip[2], ip[3]);
        } else {
            kprintln!("[DHCPSMOKE] PASS ip={}.{}.{}.{} gw={}.{}.{}.{}",
                      ip[0], ip[1], ip[2], ip[3], gw[0], gw[1], gw[2], gw[3]);
        }
    }
    azos_drv_virtio::virtio::net::print_msi_counts("after dhcp");
}

/// DEV01.5's two-node TCP smoke over a QEMU `socket` link (opt-in via
/// `--features net-smoke`): the client sends a 256-byte pattern, the server
/// echoes it and the client compares every byte, with one verdict line,
/// `[NETSMOKE] PASS` or `[NETSMOKE] FAIL <reason>`. Its call site, in the
/// network bring-up, says why it runs there. Inlined, as every boot phase
/// (see `boot`'s module doc).
#[cfg(feature = "net-smoke")]
#[inline(always)]
pub(crate) fn net_pair_smoke() {
    const PORT:     u16   = 9100;
    const LEN:      usize = 256;
    const SERVER:   [u8; 4] = [10, 0, 0, 1];
    /// Patience budget, in POLLS — not in seconds. MUST be recomputed
    /// whenever this block moves, because the poll rate here varies by two
    /// orders of magnitude: after `sched::start()` the polling context is
    /// starved to ~20k polls/s, while here — before the scheduler preempts
    /// — it runs at ~2.4M/s. The previous 600_000 was sized for the starved
    /// regime (~30 s) and silently became ~0.25 s when the block moved, so
    /// the server gave up before a loaded machine could boot its peer.
    /// ~100M ≈ 40 s at the current placement.
    const POLLS:    u32   = 100_000_000;

    /// Deterministic, position-dependent and non-repeating within a
    /// byte: a length error, a duplicated segment or a reordered one
    /// all change the bytes, unlike a constant fill.
    fn pat(i: usize) -> u8 { (i as u8).wrapping_mul(31).wrapping_add(7) }

    /// One line per side stating what the handshake negotiated, asserted
    /// by `tools/gate/net_pair_smoke.sh`. A 256-byte round trip passes whether
    /// or not Window Scale, SACK-Permitted, Timestamps and ECN were agreed, so
    /// without this line the negotiation has no QEMU coverage at all.
    fn report_opts(fd: i32) {
        match azos_net::socket_tcp_conn(fd) {
            Some(h) => {
                let n = h.negotiated();
                match n.wscale {
                    Some((snd, rcv)) => kprintln!("[NETSMOKE] opts wscale={}/{} sack={} ts={} ecn={}",
                                                  snd, rcv, n.sack as u8, n.ts as u8, n.ecn as u8),
                    None => kprintln!("[NETSMOKE] opts wscale=none sack={} ts={} ecn={}",
                                      n.sack as u8, n.ts as u8, n.ecn as u8),
                }
            }
            None => kprintln!("[NETSMOKE] opts no-connection"),
        }
    }

    let mac  = azos_drv_virtio::virtio::net::get_mac();
    let is_server = mac[5] == 1;

    if is_server {
        let fd = azos_net::socket_create(
            azos_net::AF_INET, azos_net::SOCK_STREAM, 0);
        let mut a = azos_net::SockAddr::new();
        a.family = azos_net::AF_INET as u16;
        a.port   = PORT;
        if fd < 0
            || azos_net::socket_bind(fd, &a) < 0
            || azos_net::socket_listen_bound(fd) < 0
        {
            kprintln!("[NETSMOKE] FAIL server-bind");
        } else {
            kprintln!("[NETSMOKE] server listening on {}", PORT);
            let mut cfd = -1;
            for _ in 0..POLLS {
                azos_net::net_poll();
                let r = azos_net::socket_accept(fd);
                if r >= 0 { cfd = r; break; }
            }
            if cfd < 0 {
                kprintln!("[NETSMOKE] FAIL no-client");
            } else {
                report_opts(cfd);
                // Echo until we have bounced LEN bytes back.
                let mut buf  = [0u8; LEN];
                let mut seen = 0usize;
                for _ in 0..POLLS {
                    azos_net::net_poll();
                    let n = azos_net::socket_recv(cfd, &mut buf[..LEN - seen]);
                    if n > 0 {
                        let n = n as usize;
                        if azos_net::socket_send(cfd, &buf[..n]) < 0 {
                            kprintln!("[NETSMOKE] FAIL server-send");
                            break;
                        }
                        seen += n;
                        if seen >= LEN { break; }
                    }
                }
                kprintln!("[NETSMOKE] server echoed {} bytes", seen);
                azos_net::socket_close(cfd);
            }
            azos_net::socket_close(fd);
        }
    } else {
        let fd = azos_net::socket_create(
            azos_net::AF_INET, azos_net::SOCK_STREAM, 0);
        let mut a = azos_net::SockAddr::new();
        a.family = azos_net::AF_INET as u16;
        a.port   = PORT;
        a.addr   = SERVER;
        // Resolve ARP first. `tcp::connect` does no address resolution:
        // on a cache miss the SYN is simply dropped and never retried,
        // so connecting cold would hang in SynSent forever. Pinging
        // until it succeeds both primes the cache and gives the peer
        // time to finish booting — and exercises ARP + ICMP on the way.
        let mut arp_ok = false;
        // Same rate caveat as POLLS: 3000 x 20k is ~25 s at this
        // placement, where the old 300 x 1k was ~0.12 s.
        for _ in 0..3_000 {
            if azos_net::net_ping(SERVER) == 0 { arp_ok = true; break; }
            for _ in 0..20_000 { azos_net::net_poll(); }
        }
        if arp_ok { kprintln!("[NETSMOKE] arp resolved, connecting"); }
        if !arp_ok {
            kprintln!("[NETSMOKE] FAIL arp");
        } else if azos_net::socket_connect(fd, &a, 40000) < 0 {
            // Only reports failure to *start* connecting (no free slot);
            // the handshake itself completes asynchronously below.
            kprintln!("[NETSMOKE] FAIL connect-start");
        } else {
            let mut tx = [0u8; LEN];
            for i in 0..LEN { tx[i] = pat(i); }
            // `socket_send` refuses until the connection is established,
            // so retrying it while polling is how we wait out the
            // three-way handshake without a state-query API.
            let mut sent = false;
            // Also a poll count, also rate-dependent — see POLLS.
            for _ in 0..20_000_000 {
                azos_net::net_poll();
                if azos_net::socket_send(fd, &tx) >= 0 { sent = true; break; }
            }
            if sent { kprintln!("[NETSMOKE] sent {} bytes, awaiting echo", LEN); }
            if sent { report_opts(fd); }
            if !sent {
                kprintln!("[NETSMOKE] FAIL client-send");
            } else {
                let mut rx  = [0u8; LEN];
                let mut got = 0usize;
                for _ in 0..POLLS {
                    azos_net::net_poll();
                    let n = azos_net::socket_recv(fd, &mut rx[got..]);
                    if n > 0 { got += n as usize; }
                    if got >= LEN { break; }
                }
                if got != LEN {
                    kprintln!("[NETSMOKE] FAIL short-echo got={} want={}", got, LEN);
                } else {
                    let mut bad = usize::MAX;
                    for i in 0..LEN {
                        if rx[i] != pat(i) { bad = i; break; }
                    }
                    if bad == usize::MAX {
                        kprintln!("[NETSMOKE] PASS {} bytes round-tripped", LEN);
                    } else {
                        kprintln!("[NETSMOKE] FAIL mismatch at {} got={} want={}",
                                  bad, rx[bad], pat(bad));
                    }
                }
            }
        }
        azos_net::socket_close(fd);
    }
}
